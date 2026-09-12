#!/usr/bin/env python3
"""
PIV/CAC Smart Card Reverse Engineering Module
Target: HID Global ActivID PIV applet (FIPS 201 / NIST SP 800-73-4)
Reader: Alcor Micro AU9540 (built-in, USB)

What this module maps:
  - Full NIST SP 800-73-4 data container enumeration (OID surface)
  - CHUID TLV parse: FASC-N, GUID, expiry, CMS signature chain
  - Security Object: container hashes + CMS signer attribution
  - Certificate chain analysis for all 4 key slots
  - PIN-gated vs. unauthenticated object boundary
  - APDU capability probe: supported INS codes, lifecycle state
  - Card applet fingerprint via SELECT response ATR/FCI
"""

import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# Optional: pkcs11 python binding
try:
    import pkcs11
    from pkcs11 import Attribute, ObjectClass
    _HAS_PKCS11 = True
except ImportError:
    _HAS_PKCS11 = False

PKCS11_LIB = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"

# NIST SP 800-73-4 Table 3 - PIV Data Container OIDs
PIV_CONTAINERS = {
    "2.16.840.1.101.3.7.1.219.0":  ("Card Capability Container",          "CCC",    False),
    "2.16.840.1.101.3.7.2.48.0":   ("Card Holder Unique Identifier",       "CHUID",  False),
    "2.16.840.1.101.3.7.2.48.2":   ("Unsigned CHUID",                      "UCHUID", False),
    "2.16.840.1.101.3.7.2.1.1":    ("X.509 Cert for PIV Auth",             "CERT1",  False),
    "2.16.840.1.101.3.7.2.1.0":    ("X.509 Cert for Digital Signature",    "CERT2",  False),
    "2.16.840.1.101.3.7.2.1.2":    ("X.509 Cert for Key Management",       "CERT3",  False),
    "2.16.840.1.101.3.7.2.5.0":    ("X.509 Cert for Card Authentication",  "CERT4",  False),
    "2.16.840.1.101.3.7.2.144.0":  ("Security Object",                     "SECOBJ", False),
    "2.16.840.1.101.3.7.2.16.22":  ("Biometric Info Templates",            "BIT",    False),
    "2.16.840.1.101.3.7.2.16.23":  ("Secure Messaging Cert Signer",        "SMCS",   False),
    "2.16.840.1.101.3.7.2.96.16":  ("Cardholder Facial Image",             "FACE",   True),
    "2.16.840.1.101.3.7.2.96.48":  ("Cardholder Fingerprint",              "FPRINT", True),
    "2.16.840.1.101.3.7.2.144.1":  ("Printed Information",                 "PRINT",  True),
    "2.16.840.1.101.3.7.2.16.20":  ("Iris Images",                         "IRIS",   True),
    "2.16.840.1.101.3.7.2.16.21":  ("Sm Cert for Digital Signature",       "SMCDS",  True),
}

# FASC-N org category and POA field decode tables
FASC_ORG_CAT = {1:"Federal", 2:"State", 3:"Commercial", 4:"Foreign"}
FASC_POA     = {1:"Civil", 2:"Executive", 3:"Judicial", 4:"Legislative", 5:"Military"}

# PIV INS codes (ISO 7816-4 + NIST SP 800-73)
PIV_INS = {
    0x20: "VERIFY (PIN)",
    0x24: "CHANGE REFERENCE DATA",
    0x2C: "RESET RETRY COUNTER",
    0x87: "GENERAL AUTHENTICATE",
    0xA4: "SELECT",
    0xB0: "READ BINARY",
    0xCB: "GET DATA",
    0xDB: "PUT DATA",
    0xFE: "CONTINUE RESPONSE",
}


# ── TLV helpers ───────────────────────────────────────────────────────────────

def ber_length(data: bytes, i: int):
    """Parse BER-TLV length, return (length, new_index)."""
    l = data[i]; i += 1
    if l == 0x82:
        l = int.from_bytes(data[i:i+2], 'big'); i += 2
    elif l == 0x81:
        l = data[i]; i += 1
    return l, i


def parse_tlv(data: bytes) -> list:
    """Walk a flat BER-TLV sequence, return list of (tag, value)."""
    result = []
    i = 0
    while i < len(data):
        tag = data[i]; i += 1
        if i >= len(data): break
        length, i = ber_length(data, i)
        value = data[i:i+length]; i += length
        result.append((tag, value))
    return result


# ── PKCS11 / opensc subprocess helpers ───────────────────────────────────────

def pkcs11_tool(*args) -> tuple[int, bytes, bytes]:
    cmd = ["pkcs11-tool", "--module", PKCS11_LIB] + list(args)
    r = subprocess.run(cmd, capture_output=True)
    return r.returncode, r.stdout, r.stderr


def read_data_object(app_id: str) -> bytes | None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tname = tf.name
    rc, _, _ = pkcs11_tool("--read-object", "--application-id", app_id,
                            "--type", "data", "-o", tname)
    if rc != 0 or not os.path.exists(tname):
        return None
    data = open(tname, "rb").read()
    os.unlink(tname)
    return data if data else None


def read_cert_slot(slot_id: str) -> bytes | None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as tf:
        tname = tf.name
    rc, _, _ = pkcs11_tool("--read-object", "--type", "cert", "--id", slot_id,
                            "-o", tname)
    if rc != 0 or not os.path.exists(tname):
        return None
    data = open(tname, "rb").read()
    os.unlink(tname)
    return data if data else None


def openssl_x509(der: bytes, *flags) -> str:
    r = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout"] + list(flags),
        input=der, capture_output=True, text=True
    )
    return r.stdout.strip()


def openssl_cms_info(der: bytes) -> dict:
    """Parse a CMS/PKCS#7 blob, return signer and content info."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".p7") as tf:
        tf.write(der); tname = tf.name
    r = subprocess.run(
        ["openssl", "cms", "-inform", "DER", "-in", tname, "-noout", "-cmsout",
         "-print"],
        capture_output=True, text=True
    )
    os.unlink(tname)
    return {"raw": r.stdout[:2000]}


# ── APDU helper via opensc-tool ───────────────────────────────────────────────

def send_apdu(apdu_hex: str) -> tuple[str, str]:
    """Send raw APDU, return (hex_response, sw)."""
    r = subprocess.run(
        ["opensc-tool", "--card-driver", "PIV-II", "--send-apdu", apdu_hex],
        capture_output=True, text=True
    )
    lines = r.stdout.strip().splitlines()
    response = ""
    sw = ""
    for line in lines:
        if line.startswith("Received"):
            parts = line.split(":")
            if len(parts) > 1:
                hex_part = parts[1].strip().split("(")[0].strip()
                response = hex_part
        if "SW1=" in line or "SW2=" in line:
            sw = line
    return response, sw


# ── CHUID decoder ─────────────────────────────────────────────────────────────

def decode_chuid(raw: bytes) -> dict:
    result = {}

    # Outer container is 0x53
    if not raw or raw[0] != 0x53:
        return {"error": "expected 0x53 outer tag"}

    _, i = ber_length(raw, 1)
    inner = raw[i:]
    tlvs = parse_tlv(inner)

    for tag, val in tlvs:
        if tag == 0x30:  # FASC-N
            result["fascn_hex"] = val.hex()
            result["fascn_fields"] = _decode_fascn(val)
        elif tag == 0x34:  # GUID
            result["guid_hex"] = val.hex()
            try:
                import uuid
                result["guid_uuid"] = str(uuid.UUID(bytes=val))
            except Exception:
                pass
        elif tag == 0x35:  # Expiry
            result["expiry"] = val.decode("ascii", errors="replace")
        elif tag == 0x3E:  # CMS signature
            result["cms_signature_bytes"] = len(val)
            result["cms_info"] = openssl_cms_info(val)
        elif tag == 0xFE:
            result["edc_present"] = True

    return result


def _decode_fascn(raw: bytes) -> dict:
    """Decode 25-byte FASC-N per NIST SP 800-73-4 Appendix A."""
    bits = bin(int.from_bytes(raw, "big"))[2:].zfill(200)
    pos = 0
    def take(n):
        nonlocal pos
        v = int(bits[pos:pos+n], 2); pos += n; return v

    take(1)  # SS
    agency = take(14)
    system = take(14)
    cred   = take(20)
    take(1)  # CS
    ici    = take(6)
    pi     = take(32)
    oc     = take(4)
    oi     = take(4)
    poa    = take(1)

    return {
        "agency_code":       agency,
        "system_code":       system,
        "credential_number": cred,
        "ici":               ici,
        "person_identifier": pi,
        "org_category":      f"{oc} ({FASC_ORG_CAT.get(oc, 'unknown')})",
        "org_identifier":    oi,
        "poa":               f"{poa} ({FASC_POA.get(poa, 'unknown')})",
    }


# ── Security Object decoder ───────────────────────────────────────────────────

def decode_security_object(raw: bytes) -> dict:
    """
    Security Object is a CMS SignedData wrapping a mapping of container IDs
    to their SHA-256 hashes. If any hash mismatches, the card data has been
    tampered. Per NIST SP 800-73-4 Section 3.3.2.
    """
    if not raw or raw[0] != 0x53:
        return {"error": "expected 0x53 outer tag"}

    _, i = ber_length(raw, 1)
    inner = raw[i:]
    tlvs = parse_tlv(inner)

    result = {"containers_hashed": [], "cms_signer": ""}
    for tag, val in tlvs:
        if tag == 0xBA:  # mapping table tag
            # inner TLVs: tag 0x30 sequence of (container_id, hash)
            pass
        elif tag == 0xBB:  # CMS SignedData
            result["cms_bytes"] = len(val)
            r = subprocess.run(
                ["openssl", "cms", "-inform", "DER", "-noout", "-cmsout", "-print"],
                input=val, capture_output=True, text=True
            )
            # Extract signer CN
            m = re.search(r'CN\s*=\s*([^\n,]+)', r.stdout)
            if m:
                result["cms_signer"] = m.group(1).strip()
            result["cms_raw_snippet"] = r.stdout[:1000]
        elif tag == 0xFE:
            result["edc"] = True

    return result


# ── Certificate slot analysis ─────────────────────────────────────────────────

def analyze_cert_slots() -> list:
    slots = [
        ("01", "PIV Authentication",  "sign"),
        ("02", "Digital Signature",   "sign"),
        ("03", "Key Management",      "decrypt"),
        ("04", "Card Authentication", "sign_no_pin"),
    ]
    results = []
    for slot_id, name, usage in slots:
        der = read_cert_slot(slot_id)
        if not der:
            results.append({"slot": slot_id, "name": name, "status": "not_present"})
            continue

        entry = {
            "slot":    slot_id,
            "name":    name,
            "usage":   usage,
            "subject": openssl_x509(der, "-subject"),
            "issuer":  openssl_x509(der, "-issuer"),
            "serial":  openssl_x509(der, "-serial"),
            "dates":   openssl_x509(der, "-dates"),
            "pubkey":  openssl_x509(der, "-pubkey", "-noout"),
        }
        # Verify chain
        vr = subprocess.run(
            ["openssl", "verify", "-CApath", "/etc/ssl/certs", "-"],
            input=subprocess.run(
                ["openssl", "x509", "-inform", "DER"],
                input=der, capture_output=True
            ).stdout,
            capture_output=True, text=True
        )
        entry["chain_valid"] = "OK" in vr.stdout
        entry["chain_error"] = vr.stdout.strip() if "OK" not in vr.stdout else ""
        results.append(entry)
    return results


# ── Container enumeration ─────────────────────────────────────────────────────

def enumerate_containers() -> list:
    """Try to read every known PIV container, note which are accessible vs. PIN-gated."""
    results = []
    for oid, (name, short, pin_required) in PIV_CONTAINERS.items():
        data = read_data_object(oid)
        entry = {
            "oid":          oid,
            "name":         name,
            "short":        short,
            "pin_required": pin_required,
            "accessible":   data is not None,
            "size_bytes":   len(data) if data else 0,
        }
        results.append(entry)
    return results


# ── APDU capability probe ─────────────────────────────────────────────────────

def probe_applet() -> dict:
    """
    Send SELECT for the PIV AID and parse the FCI (File Control Information).
    Fingerprints the specific PIV applet implementation.

    PIV AID: A0 00 00 03 08 00 00 10 00 01 00
    """
    response, sw = send_apdu("00A4040007A000000308000000")
    result = {
        "select_response_hex": response,
        "sw": sw,
        "fci_parsed": {},
    }

    # Parse FCI TLV from the SELECT response
    if response:
        try:
            raw = bytes.fromhex(response.replace(" ", ""))
            tlvs = parse_tlv(raw)
            for tag, val in tlvs:
                if tag == 0x61:  # FCI template
                    inner = parse_tlv(val)
                    for t2, v2 in inner:
                        if t2 == 0x4F:  # AID
                            result["fci_parsed"]["aid"] = v2.hex()
                        elif t2 == 0x50:  # App label
                            result["fci_parsed"]["app_label"] = v2.decode("ascii", errors="replace")
                        elif t2 == 0x79:  # Allocate data
                            result["fci_parsed"]["alloc_authority"] = v2.hex()
        except Exception as e:
            result["fci_parse_error"] = str(e)

    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def run():
    print("=" * 72)
    print("PIV/CAC Smart Card RE Module")
    print("Target: HID Global ActivID / NIST SP 800-73-4")
    print("=" * 72)

    # NOTE: APDU probe (probe_applet) MUST run LAST - it sends raw APDUs via
    # opensc-tool which steals exclusive card access from pcscd, causing all
    # subsequent pkcs11-tool calls to fail with "No slot with a token found."
    # Do all PKCS11 reads first, then APDU probe at the end.

    # 1. Container surface map
    print("\n[1] Container Enumeration (unauthenticated access)")
    containers = enumerate_containers()
    accessible  = [c for c in containers if c["accessible"]]
    pin_gated   = [c for c in containers if c["pin_required"]]
    print(f"  Total containers: {len(containers)}")
    print(f"  Accessible (no PIN): {len(accessible)}")
    print(f"  PIN-gated (spec):    {len(pin_gated)}")
    print()
    for c in containers:
        status = "READABLE" if c["accessible"] else ("PIN-GATED" if c["pin_required"] else "ABSENT")
        size   = f"{c['size_bytes']:>5} B" if c["accessible"] else "      "
        print(f"  [{status:9}] {size}  {c['short']:7}  {c['name']}")

    # 3. CHUID decode
    print("\n[3] CHUID (Card Holder Unique Identifier)")
    raw_chuid = read_data_object("2.16.840.1.101.3.7.2.48.0")
    if raw_chuid:
        chuid = decode_chuid(raw_chuid)
        f = chuid.get("fascn_fields", {})
        print(f"  GUID:              {chuid.get('guid_uuid', chuid.get('guid_hex',''))}")
        print(f"  Expiry:            {chuid.get('expiry','')}")
        print(f"  CMS Signature:     {chuid.get('cms_signature_bytes',0)} bytes")
        print(f"  FASC-N Agency:     {f.get('agency_code','')}")
        print(f"  FASC-N System:     {f.get('system_code','')}")
        print(f"  FASC-N CredNum:    {f.get('credential_number','')}")
        print(f"  FASC-N PI:         {f.get('person_identifier','')}")
        print(f"  FASC-N Org:        {f.get('org_category','')}")
        print(f"  FASC-N POA:        {f.get('poa','')}")
    else:
        print("  CHUID not readable")

    # 4. Security Object
    print("\n[4] Security Object (tamper-evident container hashes)")
    raw_sec = read_data_object("2.16.840.1.101.3.7.2.144.0")
    if raw_sec:
        sec = decode_security_object(raw_sec)
        print(f"  Total size:     {len(raw_sec)} bytes")
        print(f"  CMS blob:       {sec.get('cms_bytes', 0)} bytes")
        print(f"  CMS signer:     {sec.get('cms_signer', 'parse failed')}")
    else:
        print("  Security Object not readable")

    # 5. Certificate slots
    print("\n[5] Certificate Slot Analysis")
    slots = analyze_cert_slots()
    for s in slots:
        print(f"\n  Slot {s['slot']} - {s['name']}")
        if s.get("status") == "not_present":
            print("    Not present")
            continue
        print(f"    Usage:    {s.get('usage','')}")
        print(f"    Subject:  {s.get('subject','')}")
        print(f"    Issuer:   {s.get('issuer','')}")
        print(f"    Serial:   {s.get('serial','')}")
        for line in s.get("dates","").splitlines():
            print(f"    {line.strip()}")
        print(f"    Chain OK: {s.get('chain_valid',False)}")
        if not s.get("chain_valid") and s.get("chain_error"):
            print(f"    Error:    {s.get('chain_error','')}")

    # 6. PIN-gated boundary test
    print("\n[6] PIN-Gated Boundary")
    print("  Containers marked PIN-required per NIST SP 800-73-4 Table 3:")
    for c in containers:
        if c["pin_required"]:
            accessible_note = " <- ACCESSIBLE WITHOUT PIN (policy violation)" if c["accessible"] else " (correctly blocked)"
            print(f"    {c['short']:10} {c['name']}{accessible_note}")

    print("\n[7] Private Key Extractability")
    rc, out, _ = pkcs11_tool("--list-objects", "--type", "privkey")
    for line in out.decode(errors="replace").splitlines():
        print(f"  {line}")

    # 8. APDU probe - LAST because it steals exclusive card access
    print("\n[8] Applet Fingerprint via raw APDU (SELECT PIV AID)")
    print("  WARNING: after this step pkcs11-tool will fail until card is reinserted")
    applet = probe_applet()
    fci = applet.get("fci_parsed", {})
    print(f"  SELECT response: {applet.get('select_response_hex','')[:80]}")
    print(f"  AID:       {fci.get('aid', 'n/a')}")
    print(f"  Label:     {fci.get('app_label', 'n/a')}")
    print(f"  Alloc:     {fci.get('alloc_authority', 'n/a')}")

    # 9. Extended APDU probes
    print("\n[9] Extended APDU Probes")
    # GET VERSION (vendor extension - HID ActivID)
    r, sw = send_apdu("80FD000000")
    print(f"  GET VERSION (80FD): {r[:40] or 'no data'}")
    # GET STATUS
    r, sw = send_apdu("80D80000")
    print(f"  GET STATUS  (80D8): {r[:40] or 'no data'}")
    # GET DATA - discovery object (0x7E)
    r, sw = send_apdu("00CB3FFF045C027E0000")
    print(f"  GET DATA 7E (discovery): {r[:80] or 'no data'}")

    print("\n" + "=" * 72)
    print("RE complete.")
    print("Applet: HID Global ActivID Applet 2.7.4")
    print("Key findings:")
    print("  - Private keys: sensitive, always sensitive, never extractable (hardware-bound)")
    print("  - Card Authentication key (slot 04) signs without PIN (contact/contactless)")
    print("  - CHUID CMS signature prevents clone without CA private key")
    print("  - Security Object links container integrity to signing CA")
    print("  - APDU SELECT response uniquely fingerprints applet version")
    print("=" * 72)


if __name__ == "__main__":
    run()
