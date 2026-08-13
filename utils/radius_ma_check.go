// radius_ma_check.go — RADIUS Message-Authenticator field validator
//
// Standalone tool for field analysis of captured RADIUS packets.
// Detects Message-Authenticator (attr 80) and validates HMAC-MD5.
//
// NOTE: For Access-Accept HMAC validation, substitute the Request-Authenticator
// into bytes [4:20] before computing HMAC-MD5 (this tool validates Access-Request
// only; Access-Accept requires --req-auth <hex> flag — see TODO below).
//
// Usage:
//   go run radius_ma_check.go <radius_packet.bin> <shared_secret>
//
// To check RFC 5080 §2.2 compliance (pair of packets):
//   go run radius_ma_check.go --rfc5080 <request.bin> <response.bin> <secret>

package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
)

var radiusCodeNames = map[byte]string{
	1:  "Access-Request",
	2:  "Access-Accept",
	3:  "Access-Reject",
	11: "Access-Challenge",
}

var radiusAttrNames = map[byte]string{
	1:  "User-Name",
	2:  "User-Password",
	4:  "NAS-IP-Address",
	25: "Class",
	80: "Message-Authenticator",
}

type RadiusAttr struct {
	Type   byte
	Length int
	Value  []byte
	Offset int // offset within attribute bytes (packet[20:])
}

func parseAttrs(attrs []byte) []RadiusAttr {
	var parsed []RadiusAttr
	i := 0
	for i < len(attrs) {
		if i+2 > len(attrs) {
			break
		}
		t := attrs[i]
		l := int(attrs[i+1])
		if l < 2 || i+l > len(attrs) {
			break
		}
		parsed = append(parsed, RadiusAttr{
			Type:   t,
			Length: l,
			Value:  attrs[i+2 : i+l],
			Offset: i,
		})
		i += l
	}
	return parsed
}

func findMessageAuthenticator(attrs []RadiusAttr) *RadiusAttr {
	for i := range attrs {
		if attrs[i].Type == 80 && attrs[i].Length == 18 {
			return &attrs[i]
		}
	}
	return nil
}

// validateMA validates Message-Authenticator HMAC-MD5.
// For Access-Accept packets, caller must pass requestAuth (16 bytes from the
// original Access-Request Authenticator field); pass nil for Access-Request.
func validateMA(packet []byte, sharedSecret string, requestAuth []byte) (bool, error) {
	if len(packet) < 20 {
		return false, fmt.Errorf("packet too short (%d bytes)", len(packet))
	}
	length := binary.BigEndian.Uint16(packet[2:4])
	if int(length) > len(packet) {
		return false, fmt.Errorf("invalid length field %d > packet size %d", length, len(packet))
	}

	attrs := parseAttrs(packet[20:length])
	ma := findMessageAuthenticator(attrs)
	if ma == nil {
		return false, nil
	}

	packetForHMAC := make([]byte, len(packet))
	copy(packetForHMAC, packet)

	// Zero Message-Authenticator value in the copy
	maFieldOffset := 20 + ma.Offset + 2
	for i := 0; i < 16; i++ {
		packetForHMAC[maFieldOffset+i] = 0
	}

	// Access-Accept/Reject/Challenge: substitute Request-Authenticator (RFC 2104 + RFC 5080)
	if requestAuth != nil && len(requestAuth) == 16 {
		copy(packetForHMAC[4:20], requestAuth)
	}

	mac := hmac.New(md5.New, []byte(sharedSecret))
	mac.Write(packetForHMAC)
	calculated := mac.Sum(nil)

	fmt.Printf("  Calculated HMAC-MD5: %x\n", calculated)
	fmt.Printf("  Packet MA value:     %x\n", ma.Value)

	return hmac.Equal(calculated, ma.Value), nil
}

func printPacketInfo(packet []byte, label string) []RadiusAttr {
	if len(packet) < 20 {
		fmt.Printf("%s: packet too short\n", label)
		return nil
	}
	code := packet[0]
	id := packet[1]
	length := binary.BigEndian.Uint16(packet[2:4])
	codeName := radiusCodeNames[code]
	if codeName == "" {
		codeName = fmt.Sprintf("Unknown(%d)", code)
	}
	fmt.Printf("%s: %s (id=%d, len=%d)\n", label, codeName, id, length)

	attrs := parseAttrs(packet[20:length])
	for _, a := range attrs {
		name := radiusAttrNames[a.Type]
		if name == "" {
			name = fmt.Sprintf("Attr-%d", a.Type)
		}
		if a.Type == 1 || a.Type == 25 {
			fmt.Printf("  %-25s (type %3d, len %2d): %s\n", name, a.Type, a.Length, string(a.Value))
		} else {
			fmt.Printf("  %-25s (type %3d, len %2d): %x\n", name, a.Type, a.Length, a.Value)
		}
	}
	return attrs
}

func checkRFC5080(requestPkt, responsePkt []byte, sharedSecret string) {
	fmt.Println("=== RFC 5080 §2.2 Compliance Check ===")

	reqAttrs := printPacketInfo(requestPkt, "Access-Request")
	fmt.Println()
	printPacketInfo(responsePkt, "Access-Accept/Response")
	fmt.Println()

	reqMA := findMessageAuthenticator(reqAttrs)
	respAttrs := parseAttrs(responsePkt[20:binary.BigEndian.Uint16(responsePkt[2:4])])
	respMA := findMessageAuthenticator(respAttrs)

	fmt.Printf("Request  has Message-Authenticator: %v\n", reqMA != nil)
	fmt.Printf("Response has Message-Authenticator: %v\n", respMA != nil)

	if reqMA != nil && respMA == nil {
		fmt.Println("RESULT: RFC 5080 §2.2 VIOLATION — response MUST include Message-Authenticator")
	} else if reqMA != nil && respMA != nil {
		requestAuth := requestPkt[4:20]
		valid, err := validateMA(responsePkt, sharedSecret, requestAuth)
		if err != nil {
			fmt.Println("RESULT: validation error:", err)
		} else if valid {
			fmt.Println("RESULT: RFC 5080 §2.2 COMPLIANT — Message-Authenticator present and valid")
		} else {
			fmt.Println("RESULT: INVALID Message-Authenticator in response (HMAC mismatch)")
		}
	} else {
		fmt.Println("RESULT: RFC 5080 §2.2 N/A — Access-Request has no Message-Authenticator")
	}
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--rfc5080" {
		if len(os.Args) < 5 {
			fmt.Println("Usage: go run radius_ma_check.go --rfc5080 <request.bin> <response.bin> <secret>")
			os.Exit(1)
		}
		req, err1 := ioutil.ReadFile(os.Args[2])
		resp, err2 := ioutil.ReadFile(os.Args[3])
		if err1 != nil || err2 != nil {
			fmt.Println("Error reading files:", err1, err2)
			os.Exit(1)
		}
		checkRFC5080(req, resp, os.Args[4])
		return
	}

	if len(os.Args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  go run radius_ma_check.go <packet.bin> <secret>")
		fmt.Println("  go run radius_ma_check.go --rfc5080 <request.bin> <response.bin> <secret>")
		os.Exit(1)
	}

	packet, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}
	secret := os.Args[2]

	printPacketInfo(packet, os.Args[1])
	fmt.Println()

	ma := findMessageAuthenticator(parseAttrs(packet[20:binary.BigEndian.Uint16(packet[2:4])]))
	if ma == nil {
		fmt.Println("Message-Authenticator: NOT PRESENT")
		return
	}

	fmt.Println("Message-Authenticator: PRESENT — validating...")
	valid, err := validateMA(packet, secret, nil)
	if err != nil {
		fmt.Println("Validation error:", err)
		return
	}
	if valid {
		fmt.Println("Message-Authenticator: VALID")
	} else {
		fmt.Println("Message-Authenticator: INVALID (HMAC mismatch or Access-Accept needs --rfc5080 mode)")
	}
}
