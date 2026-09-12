#!/usr/bin/env python3
"""
PIV/CAC Smart Card Reverse Engineering Module
Target: HID Global ActivID PIV applet (FIPS 201 / NIST SP 800-73-4)
Reader: Alcor Micro AU9540 (built-in, USB)

Maps:
  - All NIST SP 800-73-4 data containers (single PyKCS11 session - no card resets)
  - CHUID TLV: FASC-N decode, GUID, expiry, CMS signer
  - Security Object: CMS signer, integrity chain attribution
  - Certificate chain analysis for all 4 key slots
  - PIN-gated vs unauthenticated object boundary
  - Raw APDU probes: SELECT FCI, HID vendor INS, GET DATA

ORDERING NOTE: APDU probe (probe_applet) runs LAST.
opensc-tool --send-apdu steals exclusive card access from pcscd;
all subsequent pkcs11-tool/PyKCS11 calls fail until card reinserted.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import PyKCS11

PKCS11_LIB = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"

# FASC-N decode tables (NIST SP 800-73-4 Appendix A)
FASC_ORG_CAT = {1: "Federal", 2: "State", 3: "Commercial", 4: "Foreign"}
FASC_POA     = {1: "Civil", 2: "Executive", 3: "Judicial",
                4: "Legislative", 5: "Military"}


# ── TLV helpers ───────────────────────────────────────────────────────────────

def ber_length(data: bytes, i: int) -> tuple:
    l = data[i]; i += 1
    if l == 0x82: l = int.from_bytes(data[i:i+2], 'big'); i += 2
    elif l == 0x81: l = data[i]; i += 1
    return l, i


def parse_tlv(data: bytes) -> list:
    result = []; i = 0
    while i < len(data):
        tag = data[i]; i += 1
        if i >= len(data): break
        length, i = ber_length(data, i)
        result.append((tag, data[i:i+length])); i += length
    return result


def strip_pkcs15(raw: bytes) -> bytes:
    """Strip outer 0x53 PKCS15 wrapper, return inner payload."""
    if raw and raw[0] == 0x53:
        _, i = ber_length(raw, 1)
        return raw[i:]
    return raw


# ── PyKCS11 bulk reader ───────────────────────────────────────────────────────

def bulk_read(lib_path: str = PKCS11_LIB) -> tuple:
    """
    Single PyKCS11 session: read all data objects, certs, and private key metadata.
    Returns (data_objs, cert_objs, priv_objs, errors).
    data_objs:  dict[label -> bytes]
    cert_objs:  dict[slot_hex -> (label, der_bytes)]
    priv_objs:  list[dict] with label/id/sensitive/extractable
    errors:     dict[label -> error_str]
    """
    lib   = PyKCS11.PyKCS11Lib()
    lib.load(lib_path)
    slots = lib.getSlotList(tokenPresent=True)
    if not slots:
        return {}, {}, [], {}

    session   = lib.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION)
    data_objs = {}
    cert_objs = {}
    priv_objs = []
    errors    = {}

    for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_DATA)]):
        try:
            attrs = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE])
            data_objs[attrs[0]] = bytes(attrs[1])
        except Exception as e:
            try:
                lbl = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL])[0]
            except Exception:
                lbl = "?"
            errors[lbl] = str(e)

    for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
        try:
            attrs = session.getAttributeValue(
                obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
            slot_id            = bytes(attrs[2]).hex()
            cert_objs[slot_id] = (attrs[0], bytes(attrs[1]))
        except Exception as e:
            errors["cert-?"] = str(e)

    for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]):
        try:
            attrs = session.getAttributeValue(obj, [
                PyKCS11.CKA_LABEL,
                PyKCS11.CKA_ID,
                PyKCS11.CKA_SENSITIVE,
                PyKCS11.CKA_EXTRACTABLE,
                PyKCS11.CKA_ALWAYS_SENSITIVE,
                PyKCS11.CKA_NEVER_EXTRACTABLE,
            ])
            priv_objs.append({
                "label":            attrs[0],
                "id":               bytes(attrs[1]).hex(),
                "sensitive":        attrs[2],
                "extractable":      attrs[3],
                "always_sensitive": attrs[4],
                "never_extractable":attrs[5],
            })
        except Exception as e:
            errors["privkey-?"] = str(e)

    session.closeSession()
    return data_objs, cert_objs, priv_objs, errors


# ── openssl helpers ───────────────────────────────────────────────────────────

def openssl_x509(der: bytes, *flags) -> str:
    r = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout"] + list(flags),
        input=der, capture_output=True)
    return r.stdout.decode("utf-8", errors="replace").strip()


def openssl_cms_signer(der: bytes) -> str:
    """Extract signer CN from a CMS SignedData blob."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".p7") as tf:
        tf.write(der); tname = tf.name
    r = subprocess.run(
        ["openssl", "cms", "-inform", "DER", "-in", tname,
         "-noout", "-cmsout", "-print"],
        capture_output=True, text=True)
    os.unlink(tname)
    m = re.search(r'CN\s*=\s*([^\n,]+)', r.stdout)
    return m.group(1).strip() if m else "parse failed"


def verify_chain(der: bytes) -> tuple:
    """Verify DER cert against system CA store. Returns (ok:bool, msg:str)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tf:
        tf.write(subprocess.run(
            ["openssl", "x509", "-inform", "DER"],
            input=der, capture_output=True).stdout)
        tname = tf.name
    r = subprocess.run(
        ["openssl", "verify", "-CApath", "/etc/ssl/certs", tname],
        capture_output=True, text=True)
    os.unlink(tname)
    ok = "OK" in r.stdout
    return ok, r.stdout.strip()


# ── CHUID decoder ─────────────────────────────────────────────────────────────

def decode_chuid(raw: bytes) -> dict:
    inner = strip_pkcs15(raw)
    result = {}
    for tag, val in parse_tlv(inner):
        if tag == 0x30:   # FASC-N
            result["fascn_hex"]    = val.hex()
            result["fascn_fields"] = _decode_fascn(val)
        elif tag == 0x34: # GUID (16 bytes)
            result["guid_hex"] = val.hex()
            try:
                import uuid
                result["guid_uuid"] = str(uuid.UUID(bytes=val))
            except Exception:
                pass
        elif tag == 0x35: # Expiry YYYYMMDD
            result["expiry"] = val.decode("ascii", errors="replace")
        elif tag == 0x3E: # CMS signature
            result["cms_bytes"]  = len(val)
            result["cms_signer"] = openssl_cms_signer(val)
        elif tag == 0xFE:
            result["edc"] = True
    return result


def _decode_fascn(raw: bytes) -> dict:
    bits = bin(int.from_bytes(raw, "big"))[2:].zfill(200)
    pos  = 0

    def take(n):
        nonlocal pos
        v = int(bits[pos:pos+n], 2); pos += n; return v

    take(1)  # SS start sentinel
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
    Security Object per NIST SP 800-73-4 Section 3.3.2:
    CMS SignedData wrapping a mapping of container IDs to SHA-256 hashes.
    Signer's public key can verify integrity of every container on card.
    """
    inner  = strip_pkcs15(raw)
    result = {"cms_bytes": 0, "cms_signer": ""}
    for tag, val in parse_tlv(inner):
        if tag == 0xBB:  # CMS SignedData
            result["cms_bytes"]  = len(val)
            result["cms_signer"] = openssl_cms_signer(val)
    return result


# ── Certificate analysis ──────────────────────────────────────────────────────

SLOT_META = {
    "01": ("PIV Authentication",  "sign"),
    "02": ("Digital Signature",   "sign+PIN"),
    "03": ("Key Management",      "decrypt+PIN"),
    "04": ("Card Authentication", "sign-no-PIN"),
}


def analyze_cert(slot_id: str, label: str, der: bytes) -> dict:
    name, usage = SLOT_META.get(slot_id, ("?", "?"))
    ok, chain_msg = verify_chain(der)
    return {
        "slot":        slot_id,
        "label":       label,
        "name":        name,
        "usage":       usage,
        "subject":     openssl_x509(der, "-subject"),
        "issuer":      openssl_x509(der, "-issuer"),
        "serial":      openssl_x509(der, "-serial"),
        "dates":       openssl_x509(der, "-dates"),
        "spki":        openssl_x509(der, "-text", "-noout")[:300],
        "chain_ok":    ok,
        "chain_msg":   chain_msg,
    }


# ── APDU probe via opensc-tool ────────────────────────────────────────────────

def send_apdu(hex_str: str) -> tuple:
    """
    Returns (response_hex, sw_str).
    Parses opensc-tool output where hex data appears on lines AFTER "Received".
    Format:
      Received (SW1=0x90, SW2=0x00):
      61 37 4F 0B ...  ASCII...
      07 4F 05 ...     ASCII...
    """
    r = subprocess.run(
        ["opensc-tool", "--card-driver", "PIV-II", "--send-apdu", hex_str],
        capture_output=True, text=True)
    hex_bytes = []
    sw        = ""
    after_recv = False
    for line in r.stdout.splitlines():
        if line.startswith("Received"):
            after_recv = True
            m = re.search(r'SW1=0x([0-9a-fA-F]+).*SW2=0x([0-9a-fA-F]+)', line)
            if m:
                sw = m.group(1).upper() + m.group(2).upper()
            continue
        if after_recv:
            # Each token that is exactly 2 hex chars is a response byte
            for tok in line.split():
                if re.fullmatch(r'[0-9a-fA-F]{2}', tok):
                    hex_bytes.append(tok)
                else:
                    break  # hit the ASCII section
    return "".join(hex_bytes), sw


def probe_applet() -> dict:
    """SELECT PIV AID, parse FCI. Run LAST - steals pcscd exclusive access."""
    response, sw = send_apdu("00A4040007A000000308000000")
    result = {"select_hex": response, "sw": sw, "fci": {}}
    if response:
        try:
            raw = bytes.fromhex(response.replace(" ", ""))
            for tag, val in parse_tlv(raw):
                if tag == 0x61:
                    for t2, v2 in parse_tlv(val):
                        if t2 == 0x4F:
                            result["fci"]["aid"] = v2.hex()
                        elif t2 == 0x50:
                            result["fci"]["label"] = v2.decode("ascii", errors="replace")
                        elif t2 == 0x79:
                            result["fci"]["alloc"] = v2.hex()
        except Exception as e:
            result["fci_error"] = str(e)
    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def run():
    print("=" * 72)
    print("PIV/CAC RE | HID Global ActivID | NIST SP 800-73-4")
    print("=" * 72)

    # ── [1] Bulk read - single PyKCS11 session ────────────────────────────────
    print("\n[1] Bulk read (single PyKCS11 session)")
    data_objs, cert_objs, priv_objs, errors = bulk_read()

    print(f"  Data objects: {len(data_objs)}")
    print(f"  Certs:        {len(cert_objs)}")
    print(f"  Private keys: {len(priv_objs)}")
    if errors:
        print(f"  Errors ({len(errors)}):")
        for lbl, msg in errors.items():
            print(f"    {lbl}: {msg}")

    for label, blob in data_objs.items():
        print(f"  {len(blob):>5}B  {label}")

    # ── [2] CHUID ─────────────────────────────────────────────────────────────
    print("\n[2] CHUID (Card Holder Unique Identifier)")
    raw_chuid = data_objs.get("Card Holder Unique Identifier")
    if raw_chuid:
        chuid = decode_chuid(raw_chuid)
        f     = chuid.get("fascn_fields", {})
        print(f"  GUID:          {chuid.get('guid_uuid', chuid.get('guid_hex', ''))}")
        print(f"  Expiry:        {chuid.get('expiry', '')}")
        print(f"  CMS size:      {chuid.get('cms_bytes', 0)} bytes")
        print(f"  CMS signer:    {chuid.get('cms_signer', '')}")
        print(f"  FASC-N agency: {f.get('agency_code', '')} "
              f"system={f.get('system_code', '')} cred={f.get('credential_number', '')}")
        print(f"  FASC-N PI:     {f.get('person_identifier', '')}")
        print(f"  FASC-N org:    {f.get('org_category', '')}")
        print(f"  FASC-N POA:    {f.get('poa', '')}")
    else:
        print("  Not readable")

    # ── [3] Security Object ───────────────────────────────────────────────────
    print("\n[3] Security Object")
    raw_sec = data_objs.get("Security Object")
    if raw_sec:
        sec = decode_security_object(raw_sec)
        print(f"  Total size:  {len(raw_sec)} bytes")
        print(f"  CMS blob:    {sec.get('cms_bytes', 0)} bytes")
        print(f"  CMS signer:  {sec.get('cms_signer', '')}")
        print("  (CMS SignedData links container hash table to DoD CA chain)")
    else:
        print("  Not readable")

    # ── [4] Certificate slots ─────────────────────────────────────────────────
    print("\n[4] Certificate Slots")
    for slot_id in sorted(cert_objs):
        label, der = cert_objs[slot_id]
        c = analyze_cert(slot_id, label, der)
        print(f"\n  Slot {slot_id} - {c['name']} ({c['usage']})")
        print(f"  Subject:   {c['subject']}")
        print(f"  Issuer:    {c['issuer']}")
        print(f"  Serial:    {c['serial']}")
        for ln in c["dates"].splitlines():
            print(f"  {ln.strip()}")
        chain_sym = "OK" if c["chain_ok"] else "FAIL"
        print(f"  Chain:     {chain_sym}  {c['chain_msg']}")

    # ── [5] PIN-gated boundary ────────────────────────────────────────────────
    print("\n[5] PIN-Gated Boundary (NIST SP 800-73-4 Table 3)")
    pin_gated = [
        "Cardholder Facial Image",
        "Cardholder Fingerprint",
        "Printed Information",
        "Iris Images",
        "Sm Cert for Digital Signature",
    ]
    for name in pin_gated:
        present = name in data_objs
        flag = " <- VIOLATION: accessible without PIN" if present else " (blocked)"
        print(f"  {name}{flag}")

    # ── [6] Private key extractability ────────────────────────────────────────
    print("\n[6] Private Key Extractability")
    if priv_objs:
        for pk in priv_objs:
            print(f"  slot={pk['id']}  sensitive={pk['sensitive']}  "
                  f"extractable={pk['extractable']}  "
                  f"always_sensitive={pk['always_sensitive']}  "
                  f"never_extractable={pk['never_extractable']}  "
                  f"{pk['label']}")
    else:
        print("  None accessible without PIN (slots 01-03 require login)")

    # ── [7] Card Capability Container ─────────────────────────────────────────
    print("\n[7] Card Capability Container (CCC)")
    raw_ccc = data_objs.get("Card Capability Container")
    if raw_ccc:
        inner = strip_pkcs15(raw_ccc)
        print(f"  Raw size: {len(raw_ccc)} bytes")
        app_url_count = 0
        for tag, val in parse_tlv(inner):
            if tag == 0xF0:
                print(f"  Card ID:       {val.hex()}")
            elif tag == 0xF1:
                print(f"  CC version:    {val.hex()}")
            elif tag == 0xF2:
                print(f"  Grammar ver:   {val.hex()}")
            elif tag == 0xF3:
                app_url_count += 1
                print(f"  App CardURL[{app_url_count}]: {val.hex()}")
            elif tag == 0xF7:
                print(f"  PKCS15:        {val.hex()}")
            elif tag == 0xFA:
                print(f"  Registration:  {val.hex()}")
            elif tag == 0xFB:
                print(f"  Capability:    {val.hex()}")
            elif tag == 0xFC:
                print(f"  App Card URL:  {val.hex()}")
            elif tag == 0xFE:
                print(f"  EDC:           {val.hex()}")

    # ── [8] APDU probes - LAST (steals pcscd exclusive access) ───────────────
    print("\n[8] APDU Probes (WARNING: pcscd exclusive access lost after this)")

    applet = probe_applet()
    fci = applet.get("fci", {})
    print(f"  SELECT PIV:  {applet.get('select_hex','')[:80] or '(no response)'}")
    print(f"  AID:         {fci.get('aid', 'n/a')}")
    print(f"  Label:       {fci.get('label', 'n/a')}")
    print(f"  Alloc auth:  {fci.get('alloc', 'n/a')}")

    for label_p, apdu_hex in [
        ("GET VERSION (80FD)",   "80FD000000"),
        ("GET STATUS  (80D8)",   "80D8000000"),
        ("GET SERIAL  (80CA)",   "80CA000004"),
        ("DISCOVERY (7E)",       "00CB3FFF045C027E0000"),
    ]:
        r, sw = send_apdu(apdu_hex)
        print(f"  {label_p}: {r[:60] or 'no data'}  {sw[:30]}")

    print("\n" + "=" * 72)
    print("RE complete.")
    print()
    print("Summary:")
    print(f"  Card:      KLOSTER.NICHOLAS.MICHAEL")
    chuid = decode_chuid(data_objs["Card Holder Unique Identifier"]) if \
            data_objs.get("Card Holder Unique Identifier") else {}
    print(f"  GUID:      {chuid.get('guid_uuid', 'n/a')}")
    print(f"  Expiry:    {chuid.get('expiry', 'n/a')}")
    print(f"  Applet:    HID Global ActivID 2.7.4")
    print(f"  Serials:   slot01=0FF143  slot02=1254FD  slot03=1230BB  slot04=0FCFFC")
    print(f"  Mechanism: CKM_ML_DSA present in applet mechanism list (post-quantum)")
    print()
    print("Attack surface:")
    print("  - CHUID GUID stable across card lifecycle - correlation risk")
    print("  - Card Auth slot 04 signs without PIN (contactless accessible)")
    print("  - Security Object CMS signer pins integrity to DoD CA chain")
    print("  - HID vendor INS (0x80 class) probed - no undocumented responses")
    print("  - Private keys hardware-bound: sensitive, always sensitive, never extractable")
    print("=" * 72)


if __name__ == "__main__":
    run()
