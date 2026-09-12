#!/usr/bin/env python3
"""
CAC/PIV Direct CCID Reader - libusb bypass of pcscd
Target: Alcor Micro AU9540 (VID:058f PID:9540) - generic CCID class device

Eliminates pcscd entirely: one USB session, no exclusive-access drops,
nanosecond APDU timing for side-channel prep, raw CCID frame logging,
systematic INS fuzzer, ATR decode.

Run with: sudo python3 cac_direct_re.py
(needs root or udev rule for libusb device access)

Requires: pip install pyusb
"""

import struct
import sys
import time
import re
from typing import Optional

try:
    import usb.core
    import usb.util
except ImportError:
    sys.exit("pip install pyusb")

# ── Hardware constants ────────────────────────────────────────────────────────
ALCOR_VID  = 0x058F
ALCOR_PID  = 0x9540
EP_OUT     = 0x02   # Bulk OUT  PC → Reader
EP_IN      = 0x83   # Bulk IN   Reader → PC
EP_INT     = 0x81   # Interrupt IN (card insert/remove events)
TIMEOUT_MS = 5000
READ_BUF   = 65535  # max read - libusb accumulates packets

# ── CCID message types ────────────────────────────────────────────────────────
PC_TO_RDR_ICCPOWERON    = 0x62
PC_TO_RDR_ICCPOWEROFF   = 0x63
PC_TO_RDR_GETSLOTSTATUS = 0x65
PC_TO_RDR_XFRBLOCK      = 0x6F
RDR_TO_PC_DATABLOCK     = 0x80
RDR_TO_PC_SLOTSTATUS    = 0x81

# ── PIV container map ─────────────────────────────────────────────────────────
# tag bytes (3-byte form used in GET DATA), name, PIN required
PIV_CONTAINERS = [
    (bytes.fromhex("5FC107"), "Card Capability Container",         False),
    (bytes.fromhex("5FC102"), "CHUID",                            False),
    (bytes.fromhex("5FC105"), "Cert PIV Authentication",          False),
    (bytes.fromhex("5FC101"), "Cert Digital Signature",           False),
    (bytes.fromhex("5FC10B"), "Cert Key Management",              False),
    (bytes.fromhex("5FC10A"), "Cert Card Authentication",         False),
    (bytes.fromhex("5FC106"), "Security Object",                  False),
    (bytes.fromhex("7E"),     "Discovery Object",                 False),
    (bytes.fromhex("5FC10D"), "Printed Information",              True),
    (bytes.fromhex("5FC103"), "Cardholder Fingerprints",          True),
    (bytes.fromhex("5FC108"), "Cardholder Facial Image",          True),
    (bytes.fromhex("5FC109"), "Printed Information (alt)",        True),
    (bytes.fromhex("5FC10E"), "Iris Images",                      True),
    (bytes.fromhex("5FC10F"), "Biometric Info Templates",         False),
    (bytes.fromhex("5FC110"), "SM Cert Signer",                   False),
    (bytes.fromhex("5FC111"), "Pairing Code Reference Data",      True),
]


# ── CCID frame builder ────────────────────────────────────────────────────────

def _ccid_header(msg_type: int, data_len: int, slot: int, seq: int,
                 b3: int = 0, w_level: int = 0) -> bytes:
    """10-byte CCID bulk-message header."""
    return struct.pack('<BIBBH', msg_type, data_len, slot, seq, b3) + \
           struct.pack('<H', w_level)[:2]


# ── Core reader class ─────────────────────────────────────────────────────────

class CCIDReader:
    """
    Direct libusb CCID driver for Alcor AU9540.
    Persistent USB session - no pcscd, no exclusive-access drops.
    """

    def __init__(self, vid: int = ALCOR_VID, pid: int = ALCOR_PID,
                 verbose: bool = False):
        self.verbose   = verbose
        self.seq       = 0
        self.slot      = 0
        self.atr: Optional[bytes] = None
        self.log: list  = []   # (direction, msg_type, data, elapsed_ns)
        self._connect(vid, pid)

    def _connect(self, vid: int, pid: int):
        dev = usb.core.find(idVendor=vid, idProduct=pid)
        if dev is None:
            raise RuntimeError(f"USB device {vid:04x}:{pid:04x} not found. "
                               "Is the card reader plugged in?")
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
        dev.set_configuration()
        self.dev = dev
        if self.verbose:
            print(f"[usb] connected {vid:04x}:{pid:04x}")

    def _seq(self) -> int:
        s = self.seq; self.seq = (self.seq + 1) & 0xFF; return s

    def _write(self, frame: bytes):
        self.dev.write(EP_OUT, frame, TIMEOUT_MS)
        if self.verbose:
            print(f"[out] {frame.hex()}")

    def _read(self) -> bytes:
        raw = bytes(self.dev.read(EP_IN, READ_BUF, TIMEOUT_MS))
        if self.verbose:
            print(f"[in ] {raw.hex()}")
        return raw

    def _parse_rdr_response(self, raw: bytes) -> tuple:
        """Parse RDR_to_PC header. Returns (msg_type, data, bStatus, bError)."""
        if len(raw) < 10:
            raise RuntimeError(f"Short CCID response ({len(raw)}B): {raw.hex()}")
        msg_type = raw[0]
        length   = struct.unpack('<I', raw[1:5])[0]
        bstatus  = raw[7]
        berror   = raw[8]
        data     = raw[10:10 + length]
        return msg_type, data, bstatus, berror

    # ── Card power ────────────────────────────────────────────────────────────

    def power_on(self) -> bytes:
        """Power on card, return ATR bytes."""
        seq = self._seq()
        # bPowerSelect = 0 (auto-detect voltage)
        frame = struct.pack('<BIBBB', PC_TO_RDR_ICCPOWERON, 0,
                            self.slot, seq, 0) + b'\x00\x00'
        # Pad to 10 bytes total
        frame = bytes([PC_TO_RDR_ICCPOWERON]) + struct.pack('<I', 0) + \
                bytes([self.slot, seq, 0, 0, 0])
        self._write(frame)
        raw = self._read()
        _, data, status, error = self._parse_rdr_response(raw)
        if status & 0x40:
            raise RuntimeError(f"Power-on failed: status=0x{status:02x} error=0x{error:02x}")
        self.atr = data
        return data

    def power_off(self):
        seq = self._seq()
        frame = bytes([PC_TO_RDR_ICCPOWEROFF]) + struct.pack('<I', 0) + \
                bytes([self.slot, seq, 0, 0, 0])
        self._write(frame)
        self._read()

    def get_slot_status(self) -> tuple:
        seq = self._seq()
        frame = bytes([PC_TO_RDR_GETSLOTSTATUS]) + struct.pack('<I', 0) + \
                bytes([self.slot, seq, 0, 0, 0])
        self._write(frame)
        raw = self._read()
        _, _, status, error = self._parse_rdr_response(raw)
        return status, error

    # ── APDU exchange ─────────────────────────────────────────────────────────

    def apdu(self, apdu_bytes: bytes) -> tuple:
        """
        Send APDU, return (response_data, SW1, SW2, elapsed_us).
        Handles SW1=0x61 GET RESPONSE chaining (T=0).
        Logs timing at nanosecond resolution.
        """
        seq   = self._seq()
        hdr   = bytes([PC_TO_RDR_XFRBLOCK]) + struct.pack('<I', len(apdu_bytes)) + \
                bytes([self.slot, seq, 0, 0, 0])
        frame = hdr + apdu_bytes

        t0 = time.perf_counter_ns()
        self._write(frame)
        raw = self._read()
        t1 = time.perf_counter_ns()
        elapsed_us = (t1 - t0) // 1000

        _, resp, status, error = self._parse_rdr_response(raw)
        if status & 0x40:
            raise RuntimeError(f"APDU error: status=0x{status:02x} error=0x{error:02x} "
                               f"apdu={apdu_bytes.hex()}")
        if len(resp) < 2:
            raise RuntimeError(f"Response too short ({len(resp)}B): {resp.hex()}")

        sw1, sw2 = resp[-2], resp[-1]
        data     = resp[:-2]

        # T=0 GET RESPONSE chaining
        acc = data
        while sw1 == 0x61:
            get_resp = bytes([0x00, 0xC0, 0x00, 0x00, sw2])
            seq2     = self._seq()
            hdr2     = bytes([PC_TO_RDR_XFRBLOCK]) + struct.pack('<I', len(get_resp)) + \
                       bytes([self.slot, seq2, 0, 0, 0])
            self._write(hdr2 + get_resp)
            raw2         = self._read()
            _, resp2, _, _ = self._parse_rdr_response(raw2)
            sw1, sw2  = resp2[-2], resp2[-1]
            acc       = acc + resp2[:-2]

        # Log entry
        self.log.append({
            "apdu":    apdu_bytes.hex(),
            "resp":    acc.hex(),
            "sw":      f"{sw1:02X}{sw2:02X}",
            "us":      elapsed_us,
        })

        return acc, sw1, sw2, elapsed_us

    def apdu_hex(self, hex_str: str) -> tuple:
        return self.apdu(bytes.fromhex(hex_str.replace(" ", "")))

    # ── PIV helpers ───────────────────────────────────────────────────────────

    def select_piv(self) -> bytes:
        """SELECT PIV AID, return FCI."""
        data, sw1, sw2, _ = self.apdu(bytes.fromhex("00A4040007A000000308000000"))
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError(f"PIV SELECT failed: {sw1:02X}{sw2:02X}")
        return data

    def get_data(self, tag: bytes) -> tuple:
        """
        PIV GET DATA for a container.
        tag: 1 or 3 byte tag (e.g. b'\x7e' or b'\x5f\xc1\x02')
        Returns (data, sw1, sw2, elapsed_us).
        """
        if len(tag) == 1:
            body = bytes([0x5C, 0x01]) + tag
        else:
            body = bytes([0x5C, len(tag)]) + tag
        apdu_bytes = bytes([0x00, 0xCB, 0x3F, 0xFF, len(body)]) + body + bytes([0x00])
        return self.apdu(apdu_bytes)

    def verify_pin_counter(self) -> int:
        """VERIFY with no PIN data - returns retry counter (0-15) or -1 if blocked."""
        _, sw1, sw2, _ = self.apdu(bytes.fromhex("0020008000"))
        if sw1 == 0x63:
            return sw2 & 0x0F
        if (sw1, sw2) == (0x69, 0x83):
            return 0  # blocked
        return -1

    def close(self):
        try:
            usb.util.release_interface(self.dev, 0)
            self.dev.attach_kernel_driver(0)
        except Exception:
            pass


# ── ATR decoder ───────────────────────────────────────────────────────────────

def decode_atr(atr: bytes) -> dict:
    """Decode ISO 7816-3 ATR."""
    result = {"raw": atr.hex(), "protocols": [], "historical": b""}
    if not atr or atr[0] not in (0x3B, 0x3F):
        return result
    result["convention"] = "direct" if atr[0] == 0x3B else "inverse"
    i = 1
    t0 = atr[i]; i += 1
    k = t0 & 0x0F          # historical byte count
    y = (t0 >> 4) & 0x0F   # interface byte flags

    td_prev_t = 0
    while i < len(atr):
        if y & 0x1:  # TAi
            result[f"TA"] = atr[i]; i += 1
        if y & 0x2:  # TBi
            result[f"TB"] = atr[i]; i += 1
        if y & 0x4:  # TCi
            result[f"TC"] = atr[i]; i += 1
        if y & 0x8:  # TDi
            tdi = atr[i]; i += 1
            td_prev_t = tdi & 0x0F
            result["protocols"].append(f"T={td_prev_t}")
            y = (tdi >> 4) & 0x0F
        else:
            break

    # Historical bytes
    result["historical"] = atr[i:i+k]
    result["historical_hex"] = atr[i:i+k].hex()
    # Try ASCII decode
    try:
        result["historical_ascii"] = atr[i:i+k].decode("ascii", errors="replace")
    except Exception:
        pass
    return result


# ── TLV parser ────────────────────────────────────────────────────────────────

def ber_len(data: bytes, i: int) -> tuple:
    l = data[i]; i += 1
    if l == 0x82: l = int.from_bytes(data[i:i+2], 'big'); i += 2
    elif l == 0x81: l = data[i]; i += 1
    return l, i

def parse_tlv(data: bytes) -> list:
    result = []; i = 0
    while i < len(data):
        tag = data[i]; i += 1
        if i >= len(data): break
        l, i = ber_len(data, i)
        result.append((tag, data[i:i+l])); i += l
    return result


# ── APDU fuzzer ───────────────────────────────────────────────────────────────

def fuzz_ins(reader: CCIDReader, cls: int = 0x00,
             ins_range: range = range(0x00, 0x100, 4)) -> list:
    """
    Probe every INS code in the given range.
    Returns list of (INS, SW1, SW2, elapsed_us) for non-6D/6E responses.
    """
    hits = []
    for ins in ins_range:
        try:
            _, sw1, sw2, us = reader.apdu(bytes([cls, ins, 0x00, 0x00]))
            if sw1 not in (0x6D, 0x6E):  # not "INS not supported / class not supported"
                hits.append((ins, sw1, sw2, us))
                print(f"  INS 0x{ins:02X}: SW={sw1:02X}{sw2:02X} ({us}us)")
        except Exception as e:
            print(f"  INS 0x{ins:02X}: ERROR {e}")
            # Reader may need a reset after errors
            try:
                reader.power_off()
                time.sleep(0.1)
                reader.power_on()
                reader.select_piv()
            except Exception:
                pass
    return hits


# ── Main RE run ───────────────────────────────────────────────────────────────

def run(verbose: bool = False):
    import subprocess

    print("=" * 72)
    print("CAC DIRECT CCID RE - libusb bypass")
    print("=" * 72)

    # Stop pcscd to release the USB device
    print("\n[*] Stopping pcscd to release USB device...")
    subprocess.run(["sudo", "systemctl", "stop", "pcscd"], capture_output=True)
    time.sleep(0.3)

    reader = CCIDReader(verbose=verbose)
    print(f"[+] USB connected: Alcor Micro AU9540")

    # ── ATR ───────────────────────────────────────────────────────────────────
    print("\n[1] POWER ON / ATR")
    atr = reader.power_on()
    atr_info = decode_atr(atr)
    print(f"  ATR:         {atr.hex(':')}")
    print(f"  Convention:  {atr_info.get('convention','?')}")
    print(f"  Protocols:   {', '.join(atr_info.get('protocols', ['T=0'])) or 'T=0 (default)'}")
    print(f"  Historical:  {atr_info.get('historical_hex','')}")
    print(f"               {atr_info.get('historical_ascii','')}")

    # ── SELECT PIV ────────────────────────────────────────────────────────────
    print("\n[2] SELECT PIV AID")
    try:
        fci = reader.select_piv()
        print(f"  FCI ({len(fci)}B): {fci.hex()}")
        # Parse FCI TLV
        for tag, val in parse_tlv(fci):
            if tag == 0x61:
                for t2, v2 in parse_tlv(val):
                    if t2 == 0x4F:
                        print(f"  AID:          {v2.hex()}")
                    elif t2 == 0x50:
                        print(f"  Label:        {v2.decode('ascii', errors='replace')}")
    except Exception as e:
        print(f"  SELECT failed: {e}")

    # ── Slot status ───────────────────────────────────────────────────────────
    print("\n[3] SLOT STATUS")
    status, error = reader.get_slot_status()
    icc_status = status & 0x03
    status_str = {0: "ICC present active", 1: "ICC present inactive",
                  2: "No ICC present", 3: "RFU"}.get(icc_status, "?")
    print(f"  bStatus: 0x{status:02X}  bError: 0x{error:02X}")
    print(f"  ICC:     {status_str}")

    # ── PIN retry counter ─────────────────────────────────────────────────────
    print("\n[4] PIN RETRY COUNTER (VERIFY with no PIN)")
    retries = reader.verify_pin_counter()
    print(f"  Retries remaining: {retries}")

    # ── Full container dump ───────────────────────────────────────────────────
    print("\n[5] PIV CONTAINER DUMP (all in one session, no pcscd drops)")
    containers = {}
    for tag_bytes, name, pin_req in PIV_CONTAINERS:
        try:
            data, sw1, sw2, us = reader.get_data(tag_bytes)
            sw = f"{sw1:02X}{sw2:02X}"
            if sw == "9000":
                containers[name] = data
                fname = f"/tmp/cac_direct_{name.replace(' ','_')}.bin"
                open(fname, "wb").write(data)
                print(f"  [OK    ] {us:>6}us  {len(data):>5}B  {name}")
            elif sw == "6982":
                print(f"  [PIN   ]          {'':>5}   {name}")
            elif sw == "6A82":
                print(f"  [ABSENT]          {'':>5}   {name}")
            else:
                print(f"  [SW{sw}]          {'':>5}   {name}")
        except Exception as e:
            print(f"  [ERR   ]          {'':>5}   {name}: {e}")

    # ── SAN extraction from certs ─────────────────────────────────────────────
    print("\n[6] CERTIFICATE SANs (UPN / email / UUID from raw DER)")
    import subprocess as sp
    for tag_bytes, name, _ in PIV_CONTAINERS:
        if "Cert" not in name: continue
        fname = f"/tmp/cac_direct_{name.replace(' ','_')}.bin"
        try:
            raw = open(fname, "rb").read()
            # Strip PKCS15 wrapper (outer 0x53 > 0x70)
            if raw[0] == 0x53:
                _, i = ber_len(raw, 1)
                inner = raw[i:]
                if inner[0] == 0x70:
                    _, j = ber_len(inner, 1)
                    cert_der = inner[j:]
                else:
                    cert_der = inner
            else:
                cert_der = raw
            r = sp.run(["openssl", "x509", "-inform", "DER", "-noout",
                        "-text", "-in", "-"],
                       input=cert_der, capture_output=True, text=True)
            # Extract SAN
            in_san = False
            for line in r.stdout.splitlines():
                if "Subject Alternative Name" in line:
                    in_san = True; continue
                if in_san:
                    print(f"  {name}: {line.strip()}")
                    in_san = False
        except Exception:
            pass

    # ── APDU timing analysis ──────────────────────────────────────────────────
    print("\n[7] APDU TIMING LOG")
    print(f"  {'APDU':40s}  {'SW':4s}  {'us':>8s}")
    print(f"  {'-'*40}  {'----':4s}  {'--------':>8s}")
    for entry in reader.log:
        apdu_disp = entry["apdu"][:40]
        print(f"  {apdu_disp:40s}  {entry['sw']:4s}  {entry['us']:>8d}")

    # ── INS fuzzer - HID vendor class ─────────────────────────────────────────
    print("\n[8] INS FUZZ - Class 0x80 (vendor/HID specific)")
    print("  Looking for undocumented HID ActivID commands...")
    hits_80 = fuzz_ins(reader, cls=0x80, ins_range=range(0x00, 0x100, 8))

    print("\n[9] INS FUZZ - Class 0x00 extended range")
    # Skip known PIV INS codes (0x20, 0x24, 0x2C, 0x87, 0xA4, 0xB0, 0xCB, 0xDB, 0xFE)
    known = {0x20, 0x24, 0x2C, 0x87, 0xA4, 0xB0, 0xCB, 0xDB, 0xFE}
    candidates = [i for i in range(0x00, 0x100, 4) if i not in known]
    hits_00 = fuzz_ins(reader, cls=0x00, ins_range=candidates)

    # ── HID-specific SELECT probes ────────────────────────────────────────────
    print("\n[10] HID APPLET SELECT PROBES")
    hid_aids = {
        "HID ActivClient":     "A0000001160130003000000000000000",
        "HID ActivID v1":      "A0000001160160103000000000000000",
        "HID ActivID v3":      "A0000001160160303000000000000000",
        "HID ActivID v9":      "A0000001160190003000000000000000",
        "HID iCLASS":          "A0000001160405000500000000000000",
        "HID Management":      "A00000011604A001A001000000000000",
        "CAC Data Model v1":   "A0000000790112011201000000000000",
        "CAC Data Model v2":   "A0000000790112021201000000000000",
        "PIV Applet (full)":   "A0000003080000",
    }
    for name, aid_hex in hid_aids.items():
        aid = bytes.fromhex(aid_hex)
        apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
        _, sw1, sw2, us = reader.apdu(apdu)
        status = "ACTIVE" if (sw1, sw2) == (0x90, 0x00) else \
                 "WARN"   if sw1 == 0x62 else \
                 f"SW={sw1:02X}{sw2:02X}"
        print(f"  {name:25s}: {status} ({us}us)")
        if (sw1, sw2) == (0x90, 0x00):
            # Try to read some data from the activated applet
            try:
                d2, s1, s2, _ = reader.apdu_hex("00CB3FFF035C017E00")
                if s1 == 0x90:
                    print(f"    Discovery Object: {d2.hex()}")
            except Exception:
                pass

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("FINDINGS SUMMARY")
    print("=" * 72)
    print(f"  Containers readable (no PIN): "
          f"{sum(1 for n,d in containers.items() if d)}")
    print(f"  APDU transactions logged:     {len(reader.log)}")
    if hits_80:
        print(f"  HID vendor (0x80) hits:       {len(hits_80)}")
        for ins, sw1, sw2, us in hits_80:
            print(f"    INS 0x{ins:02X}: SW={sw1:02X}{sw2:02X} ({us}us)")
    if hits_00:
        print(f"  Class 0x00 undocumented hits: {len(hits_00)}")
        for ins, sw1, sw2, us in hits_00:
            print(f"    INS 0x{ins:02X}: SW={sw1:02X}{sw2:02X} ({us}us)")
    print(f"  PIN retries remaining:        {retries}")
    print()
    print("  Saved container blobs: /tmp/cac_direct_*.bin")
    print("  Full APDU log:         reader.log  (in-memory)")
    print()
    print("  Next surface:")
    print("  - ChipWhisperer power trace on GENERAL AUTHENTICATE (side-channel)")
    print("  - ACR122U contactless probe (HID AIDs may respond on contactless)")
    print("  - T=0 vs T=1 timing differential on signature ops")

    reader.close()

    # Restart pcscd
    subprocess.run(["sudo", "systemctl", "start", "pcscd"], capture_output=True)
    print("\n[*] pcscd restarted")


if __name__ == "__main__":
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    run(verbose=verbose)
