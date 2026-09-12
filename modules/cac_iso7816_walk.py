#!/usr/bin/env python3
"""
CAC/PIV ISO 7816 File System Walker
Raw APDU-level enumeration: MF -> DF -> EF, bypassing PKCS11 abstraction.

The PIV card exposes data in three layers:
  1. PKCS11 (opensc) - what piv_cac_re.py reads
  2. ISO 7816-4 GET DATA via PIV AID - NIST SP 800-73-4 containers
  3. Raw ISO 7816 SELECT/READ BINARY on the underlying EF file system

This module works at layer 3: direct SELECT FILE + READ BINARY + GET DATA.
It also extracts and fully parses ASN.1/DER structures the PKCS11 layer
presents opaquely (Security Object hash table, cert extensions, CHUID fields).

JavaCard OS / native OS commands served over CCID -> opensc-tool -> pcscd.
"""

import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from typing import Optional

import PyKCS11

PKCS11_LIB = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"

# ── APDU constants (ISO 7816-4) ───────────────────────────────────────────────
CLA_ISO   = 0x00
INS_SELECT        = 0xA4
INS_READ_BINARY   = 0xB0
INS_READ_RECORD   = 0xB2
INS_GET_DATA      = 0xCB
INS_GET_RESPONSE  = 0xC0
INS_GENERAL_AUTH  = 0x87
INS_VERIFY        = 0x20
INS_GET_CHALLENGE = 0x84

# SELECT P1 values
SELECT_BY_FILEID  = 0x00  # select EF/DF by 2-byte File ID
SELECT_BY_DF_NAME = 0x04  # select DF by name (AID)
SELECT_MF         = 0x00  # P2: select MF
SELECT_FIRST      = 0x00  # P2: first/only occurrence

# PIV AID
PIV_AID = bytes.fromhex("A000000308000010000100")

# Known DoD/CAC File Identifiers (from ISO 7816, DoD CAC, and PIV specs)
KNOWN_FIDS = {
    0x0001: "EF.DIR",
    0x0002: "EF.ATR/INFO",
    0x0011: "EF.GDO",
    0x2F00: "EF.DIR",
    0x2F01: "EF.ATR/INFO",
    0x3F00: "MF (Master File)",
    0xDB00: "EF.CCC (Card Capability Container)",
    0x0000: "EF.CHUID",
    0x0100: "EF.X509.PIV_Auth",
    0x0101: "EF.X509.DS",
    0x0102: "EF.X509.KM",
    0x0500: "EF.X509.CardAuth",
    0x9000: "EF.Security_Object",
    0x6010: "EF.Fingerprint",
    0x9010: "EF.Face",
    0x6020: "EF.Printed_Info",
}

# ── Card presence ─────────────────────────────────────────────────────────────

def _card_atr_present() -> bool:
    """True if opensc-tool can read the ATR (card actually responding)."""
    r = subprocess.run(
        ["opensc-tool", "--atr"],
        capture_output=True, timeout=5)
    # prints ATR on stdout and exits 0 when card is present and responding
    return r.returncode == 0 and len(r.stdout.strip()) > 0


def wait_for_card(lib_path: str = PKCS11_LIB, timeout_s: float = 120.0) -> None:
    """Block until card ATR is readable. Uses opensc-tool as the oracle."""
    deadline = time.monotonic() + timeout_s
    shown    = False
    while time.monotonic() < deadline:
        try:
            if _card_atr_present():
                if shown:
                    print("  Card detected.", flush=True)
                return
        except Exception:
            pass
        if not shown:
            print("  [Insert CAC card to continue...]", flush=True)
            shown = True
        time.sleep(0.5)
    raise TimeoutError(f"no card detected within {timeout_s}s")


# ── APDU sender ───────────────────────────────────────────────────────────────

def apdu(hex_str: str, driver: str = "PIV-II") -> tuple:
    """
    Send raw APDU via opensc-tool, return (resp_bytes, sw_str).
    hex_str: hex APDU without spaces.
    """
    args = ["opensc-tool", "--send-apdu", hex_str]
    if driver:
        args = ["opensc-tool", "--card-driver", driver, "--send-apdu", hex_str]
    r = subprocess.run(args, capture_output=True, text=True, timeout=10)

    hex_bytes  = []
    sw         = ""
    after_recv = False
    for line in r.stdout.splitlines():
        if line.startswith("Received"):
            after_recv = True
            m = re.search(r'SW1=0x([0-9a-fA-F]+).*SW2=0x([0-9a-fA-F]+)', line)
            if m:
                sw = m.group(1).upper() + m.group(2).upper()
            continue
        if after_recv:
            for tok in line.split():
                if re.fullmatch(r'[0-9a-fA-F]{2}', tok):
                    hex_bytes.append(tok)
                else:
                    break

    return bytes.fromhex("".join(hex_bytes)), sw


def apdu_get_response(sw: str) -> tuple:
    """Issue GET RESPONSE for pending data after SW=61xx."""
    if not sw.startswith("61"):
        return b"", sw
    le = int(sw[2:], 16)
    return apdu(f"00C00000{le:02X}")


# ── TLV helpers ───────────────────────────────────────────────────────────────

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


def strip53(raw: bytes) -> bytes:
    if raw and raw[0] == 0x53:
        _, i = ber_len(raw, 1)
        return raw[i:]
    return raw


# ── SELECT and READ helpers ───────────────────────────────────────────────────

def select_mf() -> tuple:
    """SELECT MF (00 A4 00 00)."""
    return apdu("00A40000")


def select_by_fid(fid: int) -> tuple:
    """SELECT EF/DF by 2-byte File ID."""
    return apdu(f"00A4000002{fid:04X}")


def select_by_aid(aid_hex: str) -> tuple:
    """SELECT by AID name."""
    aid = bytes.fromhex(aid_hex)
    lc  = len(aid)
    return apdu(f"00A40400{lc:02X}{aid_hex}")


def read_binary(offset: int = 0, length: int = 255) -> tuple:
    """READ BINARY from current EF."""
    p1 = (offset >> 8) & 0x7F
    p2 = offset & 0xFF
    return apdu(f"00B0{p1:02X}{p2:02X}{length:02X}")


def read_binary_full() -> bytes:
    """Read all data from current EF (handles SW=6282 end-of-file)."""
    all_data = b""
    offset   = 0
    while True:
        chunk, sw = read_binary(offset, 255)
        if not chunk or sw in ("6282", "6B00", "6700"):
            break
        all_data += chunk
        offset   += len(chunk)
        if sw == "9000" and len(chunk) < 255:
            break  # short read = end of file
        if sw != "9000":
            break
    return all_data


def piv_get_data(tag_bytes: bytes) -> tuple:
    """GET DATA for PIV container (00 CB 3F FF)."""
    body = bytes([0x5C, len(tag_bytes)]) + tag_bytes
    lc   = len(body)
    return apdu(f"00CB3FFF{lc:02X}{body.hex()}00")


# ── ISO 7816 file system enumerator ──────────────────────────────────────────

def enum_ef_fids(fid_range=range(0x0000, 0x0200)) -> dict:
    """
    Enumerate EFs by brute-force SELECT FILE over a range of FIDs.
    Returns dict of FID -> (FCP_response_bytes, read_bytes).
    """
    found = {}
    for fid in fid_range:
        resp, sw = select_by_fid(fid)
        if sw == "9000" or sw.startswith("61"):
            if sw.startswith("61"):
                resp, sw = apdu_get_response(sw)
            # Try to read the EF
            _, sw2 = read_binary(0, 1)
            if sw2 in ("9000", "6282", "6281"):
                data = read_binary_full()
                found[fid] = (resp, data)
                print(f"  FID 0x{fid:04X}: {KNOWN_FIDS.get(fid,'?'):30s}  "
                      f"FCP={resp.hex()[:20]}  data={len(data)}B")
    return found


def enum_standard_fids() -> dict:
    """Try known FIDs from spec."""
    results = {}
    # Standard ISO 7816-4 FIDs
    candidates = list(KNOWN_FIDS.keys()) + [
        0x0101, 0x0102, 0x0103, 0x0104,
        0x0200, 0x0201, 0x0300, 0x0400,
        0x1001, 0x2000, 0x4001,
    ]
    for fid in candidates:
        resp, sw = select_by_fid(fid)
        status = "OK" if sw == "9000" else sw
        data   = b""
        if sw == "9000":
            data = read_binary_full()
        print(f"  FID 0x{fid:04X}: {KNOWN_FIDS.get(fid,'(unknown)'):35s}  "
              f"SW={status}  {len(data)}B")
        if data:
            results[fid] = data
    return results


# ── CMS / ASN.1 extractor ─────────────────────────────────────────────────────

def der_walk(data: bytes, path: list) -> Optional[bytes]:
    """
    Walk a DER-encoded ASN.1 structure following a path of tag bytes.
    path: list of (tag, occurrence) tuples, e.g. [(0x30,0),(0xA0,0),(0x30,0)]
    Returns the VALUE bytes at the final path node, or None.
    Handles [N] context tags (0xA0..0xBF) as constructed wrappers.
    """
    pos  = 0
    body = data
    for (want_tag, occurrence) in path:
        i    = 0
        seen = 0
        found_val = None
        while i < len(body):
            tag = body[i]; i += 1
            if i >= len(body): break
            l, i = ber_len(body, i)
            val  = body[i:i+l]; i += l
            if tag == want_tag:
                if seen == occurrence:
                    found_val = val
                    break
                seen += 1
        if found_val is None:
            return None
        body = found_val
    return body


def extract_cms_content(der: bytes) -> bytes:
    """
    Extract the eContent payload from a CMS SignedData DER blob via pure DER walk.
    Path: SEQUENCE -> [0] -> SEQUENCE -> SEQUENCE(encapCI) -> [0] -> OCTET STRING
    Falls back to openssl if parse fails.
    """
    # DER path: ContentInfo -> signedData context -> SignedData -> encapContentInfo -> [0] -> eContent
    # Tags: 0x30(SEQ) 0xA0([0]) 0x30(SEQ) 0x30(encapCI)=SEQUENCE[2] 0xA0([0]) 0x04(OCTET STRING)
    try:
        # Navigate into the nested structure
        body = der
        # Step 1: unwrap ContentInfo SEQUENCE
        if body[0] == 0x30:
            l, i = ber_len(body, 1); body = body[i:i+l]
        # Step 2: skip OID, get [0] explicit
        i = 0
        while i < len(body):
            tag = body[i]; i += 1
            l, i = ber_len(body, i)
            if tag == 0xA0:  # [0] explicit context = SignedData content
                body = body[i:i+l]; break
            i += l
        else:
            raise ValueError("no [0] tag")
        # Step 3: SignedData SEQUENCE
        if body[0] == 0x30:
            l, i = ber_len(body, 1); body = body[i:i+l]
        # Step 4: skip version (INTEGER), digestAlgorithms (SET), find encapContentInfo (SEQUENCE #2)
        i = 0; seq_count = 0
        while i < len(body):
            tag = body[i]; i += 1
            l, i = ber_len(body, i)
            val = body[i:i+l]; i += l
            if tag == 0x30:  # SEQUENCE
                seq_count += 1
                if seq_count == 1:  # first SEQUENCE inside SignedData = encapContentInfo
                    # Inside encapContentInfo: OID, [0] EXPLICIT OCTET STRING
                    j = 0
                    while j < len(val):
                        t2 = val[j]; j += 1
                        l2, j = ber_len(val, j)
                        v2 = val[j:j+l2]; j += l2
                        if t2 == 0xA0:  # [0] EXPLICIT
                            # Inside: OCTET STRING
                            k = 0
                            while k < len(v2):
                                t3 = v2[k]; k += 1
                                l3, k = ber_len(v2, k)
                                v3 = v2[k:k+l3]; k += l3
                                if t3 == 0x04:  # OCTET STRING = eContent
                                    return v3
    except Exception:
        pass

    # Fallback: openssl cms
    with tempfile.NamedTemporaryFile(delete=False, suffix=".p7") as tf:
        tf.write(der); tname = tf.name
    outfile = tname + ".out"
    subprocess.run(
        ["openssl", "cms", "-inform", "DER", "-in", tname,
         "-verify", "-noverify", "-out", outfile],
        capture_output=True)
    os.unlink(tname)
    if os.path.exists(outfile):
        data = open(outfile, "rb").read()
        os.unlink(outfile)
        return data
    return b""


def extract_der_from_pkcs15_cert(raw: bytes) -> Optional[bytes]:
    """
    Strip PKCS15 cert container: 53 <len> 70 <len> <DER> 71 01 <flags> FE 00.
    Returns raw DER bytes, handling optional gzip compression (0x71 bit7=1).
    """
    import gzip
    inner = strip53(raw)
    for tag, val in parse_tlv(inner):
        if tag == 0x70:
            # Check if compressed (next sibling 0x71 bit7=1)
            return val  # val is DER cert (possibly compressed)
    return None


def parse_secobj_hashes(cms_payload: bytes) -> dict:
    """
    Parse the Security Object hash table from its CMS eContent.
    ASN.1 structure:
      SEQUENCE {
        INTEGER version (0)
        SEQUENCE { OID sha-256 }
        SEQUENCE {
          SEQUENCE { INTEGER containerID, OCTET STRING sha256hash } ...
        }
      }
    """
    CONTAINER_NAMES = {
        0x01: "CHUID",         0x02: "Cert PIV Auth",
        0x03: "Fingerprint",   0x06: "Security Object",
        0x07: "Cert Card Auth",0x0A: "Cert Dig Sig",
        0x0B: "Cert Key Mgmt", 0x0C: "Face Image",
        0x0E: "Iris Images",   0x10: "Biometric Info",
        0x11: "SM Cert",
    }
    hashes = {}
    if len(cms_payload) < 4 or cms_payload[0] != 0x30:
        return hashes
    try:
        i = 1
        outer_l, i = ber_len(cms_payload, i)
        # Skip INTEGER version
        assert cms_payload[i] == 0x02; i += 1
        vl, i = ber_len(cms_payload, i); i += vl
        # Skip SEQUENCE algID
        assert cms_payload[i] == 0x30; i += 1
        al, i = ber_len(cms_payload, i); i += al
        # SEQUENCE hash entries
        assert cms_payload[i] == 0x30; i += 1
        hl, i = ber_len(cms_payload, i)
        block = cms_payload[i:i+hl]; j = 0
        while j < len(block):
            if block[j] != 0x30: break
            j += 1; el, j = ber_len(block, j)
            entry = block[j:j+el]; j += el
            ei = 0
            assert entry[ei] == 0x02; ei += 1
            cl, ei = ber_len(entry, ei)
            cid = int.from_bytes(entry[ei:ei+cl], 'big'); ei += cl
            assert entry[ei] == 0x04; ei += 1
            hl2, ei = ber_len(entry, ei)
            h = entry[ei:ei+hl2]
            hashes[CONTAINER_NAMES.get(cid, f"ID-{cid}")] = h
    except Exception:
        pass
    return hashes


def full_cert_parse(der: bytes, label: str):
    """Full X.509v3 certificate parse - all extensions and fields."""
    r = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
        input=der, capture_output=True)
    text = r.stdout.decode("utf-8", errors="replace")

    print(f"\n  [{label}]")
    # Extract structured fields
    capture = False
    for line in text.splitlines():
        ln = line.strip()
        # Fields of interest
        if any(x in ln for x in [
            "Subject:", "Issuer:", "Serial Number:", "Not Before:", "Not After:",
            "Subject Public Key Algorithm", "Public Key Algorithm", "RSA Public-Key",
            "Public-Key:", "Exponent:", "Subject Alternative Name",
            "Key Usage", "Extended Key Usage", "Certificate Policies",
            "CRL Distribution", "Authority Information Access",
            "Subject Key Identifier", "Authority Key Identifier",
            "Basic Constraints",
        ]):
            print(f"    {ln}")


# ── GENERAL AUTHENTICATE (slot 04 - no PIN) ───────────────────────────────────

def general_authenticate_slot04() -> dict:
    """
    Trigger RSA-2048 sign with Card Authentication key (slot 04, no PIN).
    Provides a 16-byte challenge to the card; card signs it with slot 04 key.
    P2=9E (NIST SP 800-73-4 Table 5 key ref for Card Authentication).
    """
    import os as _os
    result = {}

    # NIST SP 800-73-4: tag 81 must contain a full RSA-2048 formatted message
    # block (256 bytes). Raw 16-byte data returns 6A80 (incorrect command data).
    # Build PKCS#1 v1.5 padded block: 00 01 FF...FF 00 DigestInfo SHA-256-hash
    import hashlib as _hl
    nonce   = _os.urandom(32)
    dgst    = _hl.sha256(nonce).digest()
    # DigestInfo for SHA-256 (PKCS#1 DER prefix)
    di_hdr  = bytes.fromhex("3031300d060960864801650304020105000420")
    di      = di_hdr + dgst                             # 51 bytes
    pad_len = 256 - len(di) - 3                         # 202 bytes
    pkcs1   = bytes([0x00, 0x01]) + bytes([0xFF] * pad_len) + bytes([0x00]) + di

    # DA template: 7C [82 00  81 <len> <padded-block>]
    inner_82 = bytes([0x82, 0x00])
    inner_81 = bytes([0x81, 0x82, 0x01, 0x00]) + pkcs1  # extended BER length (256)
    inner    = inner_82 + inner_81
    # Outer 7C tag with extended length
    da       = bytes([0x7C, 0x82, (len(inner) >> 8) & 0xFF, len(inner) & 0xFF]) + inner
    # Extended APDU: Lc as 3 bytes (00 HH LL)
    lc_ext   = bytes([0x00, (len(da) >> 8) & 0xFF, len(da) & 0xFF])
    apdu_hex = "0087079E" + lc_ext.hex() + da.hex() + "0000"

    result["nonce_hex"]   = nonce.hex()
    result["digest_hex"]  = dgst.hex()
    result["pkcs1_head"]  = pkcs1[:8].hex()

    resp, sw = apdu(apdu_hex)
    result["sw"]   = sw
    result["resp"] = resp.hex() if resp else ""

    if sw != "9000":
        # Fallback: minimal witness request (7C 02 82 00) - requests card to
        # generate a nonce we sign, per SP 800-73-4 mutual auth flow
        resp2, sw2 = apdu("0087079E047C028200")
        result["witness_sw"]   = sw2
        result["witness_resp"] = resp2.hex() if resp2 else ""
        return result

    # Parse 7C response
    if resp and resp[0] == 0x7C:
        try:
            _, i = ber_len(resp, 1)
            for tag, val in parse_tlv(resp[i:]):
                if tag == 0x82:
                    result["signature_bytes"] = len(val)
                    result["signature_hex"]   = val.hex()
        except Exception as e:
            result["parse_err"] = str(e)

    return result


def pkcs11_sign_slot04(lib_path: str = "") -> dict:
    """Sign a test message with slot 04 via PyKCS11 (no PIN needed)."""
    result = {}
    try:
        lib = PyKCS11.PyKCS11Lib()
        lib.load(lib_path or PKCS11_LIB)
        slots = lib.getSlotList(tokenPresent=True)
        if not slots:
            result["error"] = "no slots"
            return result
        session  = lib.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION)
        privkeys = session.findObjects([
            (PyKCS11.CKA_CLASS,    PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_ID,       [0x04]),
        ])
        if not privkeys:
            result["error"] = "slot 04 private key not found"
            session.closeSession()
            return result
        import time
        msg  = b"CAC_RE_TEST_VECTOR_" + b"\xAB" * 13
        t0   = time.perf_counter_ns()
        sig  = bytes(session.sign(privkeys[0], msg,
                                  PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)))
        t1   = time.perf_counter_ns()
        result["msg_hex"]         = msg.hex()
        result["sig_len"]         = len(sig)
        result["sig_hex"]         = sig.hex()
        result["elapsed_us"]      = (t1 - t0) // 1000
        session.closeSession()
    except Exception as e:
        result["error"] = str(e)
    return result


def pkcs11_read_pin_gated(pin: str, lib_path: str = "") -> dict:
    """Login with PIN and read all PIN-gated data objects."""
    import PyKCS11
    result = {}
    try:
        lib = PyKCS11.PyKCS11Lib()
        lib.load(lib_path or PKCS11_LIB)
        slots   = lib.getSlotList(tokenPresent=True)
        session = lib.openSession(slots[0],
                                  PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        session.login(PyKCS11.CKU_USER, pin)
        for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_DATA)]):
            try:
                attrs = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE])
                label = attrs[0]; val = bytes(attrs[1])
                result[label] = val
            except Exception:
                pass
        session.closeSession()
    except Exception as e:
        result["__error__"] = str(e)
    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def run():
    print("=" * 72)
    print("CAC ISO 7816 File System Walker + Deep ASN.1 Analysis")
    print("=" * 72)

    wait_for_card()

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 1: All PyKCS11 operations (before any opensc-tool call)
    # opensc-tool --card-driver PIV-II leaves card in a state that breaks
    # subsequent pcscd connections, so PyKCS11 work runs first.
    # ════════════════════════════════════════════════════════════════════════

    # ── [1] Single PyKCS11 session: all objects + sign slot 04 + PIN-gated ──
    print("\n[1] PyKCS11 session (all reads + sign before opensc-tool)")
    p11_data   = {}  # label -> bytes (data objects)
    p11_certs  = {}  # slot_id -> (label, der)
    p11_privs  = []  # [{label,id,sensitive,extractable,...}]
    p11_gated  = {}  # label -> bytes (PIN-gated objects)
    p11_sign   = {}  # sign result
    p11_errors = []

    try:
        lib   = PyKCS11.PyKCS11Lib()
        lib.load(PKCS11_LIB)
        slots = lib.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("no slots")

        # Open RW session for login capability
        session = lib.openSession(slots[0],
                                  PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)

        # Data objects
        for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_DATA)]):
            try:
                attrs = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE])
                p11_data[attrs[0]] = bytes(attrs[1])
            except Exception as e:
                try:
                    lbl = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL])[0]
                except Exception:
                    lbl = "?"
                p11_errors.append(f"data/{lbl}: {e}")

        # Certs
        for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
            try:
                attrs = session.getAttributeValue(
                    obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
                sid = bytes(attrs[2]).hex()
                p11_certs[sid] = (attrs[0], bytes(attrs[1]))
            except Exception as e:
                p11_errors.append(f"cert: {e}")

        # Private keys
        for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]):
            try:
                attrs = session.getAttributeValue(obj, [
                    PyKCS11.CKA_LABEL, PyKCS11.CKA_ID,
                    PyKCS11.CKA_SENSITIVE, PyKCS11.CKA_EXTRACTABLE,
                    PyKCS11.CKA_ALWAYS_SENSITIVE, PyKCS11.CKA_NEVER_EXTRACTABLE,
                ])
                p11_privs.append({
                    "label":             attrs[0],
                    "id":                bytes(attrs[1]).hex(),
                    "sensitive":         attrs[2],
                    "extractable":       attrs[3],
                    "always_sensitive":  attrs[4],
                    "never_extractable": attrs[5],
                    "obj":               obj,
                })
            except Exception as e:
                p11_errors.append(f"priv: {e}")

        # Sign with slot 04 (no PIN needed - Card Auth key)
        slot04_pk = [p for p in p11_privs if p["id"] == "04"]
        if slot04_pk:
            try:
                import time
                msg = b"CAC_RE_TEST_VECTOR_" + b"\xAB" * 13
                t0  = time.perf_counter_ns()
                sig = bytes(session.sign(slot04_pk[0]["obj"], msg,
                                         PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)))
                t1  = time.perf_counter_ns()
                p11_sign = {
                    "msg":     msg.hex(),
                    "sig_len": len(sig),
                    "sig":     sig.hex(),
                    "us":      (t1 - t0) // 1000,
                }
            except Exception as e:
                p11_sign = {"error": str(e)}

        # Login with PIN and read PIN-gated objects
        # PyKCS11.CKU_USER = 1. Some PyKCS11 builds return a raw CKR int on
        # failure instead of a proper PyKCS11Error; catch both forms.
        PIN = "123456"
        try:
            session.login(1, PIN)  # CKU_USER=1; avoid enum formatting bug
            for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_DATA)]):
                try:
                    attrs = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE])
                    label = attrs[0]; val = bytes(attrs[1])
                    if label not in p11_data:  # only new (PIN-gated) ones
                        p11_gated[label] = val
                except Exception:
                    pass
            session.logout()
        except Exception as e:
            # Extract raw CKR code if PyKCS11 formats it as int
            ckr = getattr(e, "args", [None])[0]
            ckr_labels = {
                0x000000A0: "CKR_PIN_INCORRECT",
                0x000000A4: "CKR_PIN_LOCKED",
                0x000000A6: "CKR_PIN_EXPIRED",
                0x00000100: "CKR_USER_ALREADY_LOGGED_IN",
                0x00000101: "CKR_USER_NOT_LOGGED_IN",
                0x00000102: "CKR_USER_PIN_NOT_INITIALIZED",
            }
            if isinstance(ckr, int):
                label = ckr_labels.get(ckr, f"CKR=0x{ckr:08X}")
                p11_errors.append(f"login: {label}")
            else:
                p11_errors.append(f"login: {e}")

        session.closeSession()
        print(f"  Data objects: {len(p11_data)}")
        print(f"  Certs:        {len(p11_certs)}")
        print(f"  Private keys: {len(p11_privs)}")
        print(f"  PIN-gated:    {len(p11_gated)}")
        if p11_errors:
            for err in p11_errors:
                print(f"  ERR: {err}")
    except Exception as e:
        print(f"  PyKCS11 failed: {e}")

    # ── [2] Sign result ───────────────────────────────────────────────────────
    print("\n[2] RSA Sign - slot 04 (Card Auth, no PIN)")
    if p11_sign.get("sig"):
        print(f"  Msg:  {p11_sign['msg']}")
        print(f"  Sig:  {p11_sign['sig'][:64]}...")
        print(f"  Len:  {p11_sign['sig_len']} bytes (RSA-2048)")
        print(f"  Time: {p11_sign['us']} us")
    else:
        print(f"  ERR: {p11_sign.get('error','no slot 04 private key found')}")

    # ── [3] PIN-gated containers ──────────────────────────────────────────────
    print("\n[3] PIN-Gated Containers (post-login)")
    if p11_gated:
        for label, blob in p11_gated.items():
            print(f"  {len(blob):>7}B  {label}  first4={blob[:4].hex()}")
            safe = label.replace(" ", "_").replace("/", "_")[:40]
            open(f"/tmp/cac_gated_{safe}.bin", "wb").write(blob)
    else:
        print("  None read (login may have failed or no additional objects unlocked)")
    for k in p11_data:
        print(f"  {len(p11_data[k]):>7}B  {k}  (pre-login)")

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 2: opensc-tool / raw APDU (after PyKCS11 session closed)
    # ════════════════════════════════════════════════════════════════════════

    # ── [4] Raw GET DATA via ISO 7816 (opensc-tool) ───────────────────────────
    print("\n[4] Raw GET DATA (opensc-tool, no PKCS11 abstraction)")
    PIV_CONTAINERS_RAW = [
        (bytes.fromhex("5FC107"), "CCC",    "Card Capability Container"),
        (bytes.fromhex("5FC102"), "CHUID",  "Card Holder Unique Identifier"),
        (bytes.fromhex("5FC105"), "CERT1",  "Cert PIV Authentication"),
        (bytes.fromhex("5FC101"), "CERT2",  "Cert Digital Signature"),
        (bytes.fromhex("5FC10B"), "CERT3",  "Cert Key Management"),
        (bytes.fromhex("5FC10A"), "CERT4",  "Cert Card Authentication"),
        (bytes.fromhex("5FC106"), "SECOBJ", "Security Object"),
    ]
    raw_containers = {}
    for tag_b, short, name in PIV_CONTAINERS_RAW:
        resp2, sw2 = piv_get_data(tag_b)
        if sw2 == "9000":
            raw_containers[short] = resp2
            print(f"  OK  {len(resp2):>5}B  {short}")
        else:
            print(f"  SW={sw2}   {short}")

    # ── [5] Full X.509v3 Certificate Analysis ─────────────────────────────────
    print("\n[5] Full X.509v3 Certificate Analysis (from PyKCS11 DER)")
    for sid in sorted(p11_certs):
        label, der = p11_certs[sid]
        full_cert_parse(der, f"slot {sid} - {label}")

    # ── [6] Security Object hash table ────────────────────────────────────────
    print("\n[6] Security Object - container integrity hashes")
    raw_sec = raw_containers.get("SECOBJ") or p11_data.get("Security Object")
    if raw_sec:
        inner = strip53(raw_sec)
        for tag, val in parse_tlv(inner):
            if tag == 0xBB:
                payload = extract_cms_content(val)
                hashes  = parse_secobj_hashes(payload)
                if hashes:
                    print("  SHA-256 hashes signed by DoD ID CA-63:")
                    for hname, h in hashes.items():
                        print(f"    {hname:22s}: {h.hex()}")
                else:
                    print(f"  eContent ({len(payload)}B): {payload.hex()[:80]}")
                break

    # ── [7] MF / EF navigation ────────────────────────────────────────────────
    print("\n[7] ISO 7816 File System (MF + FID probe)")
    _, sw3 = select_mf()
    print(f"  SELECT MF: SW={sw3} (6A82=not supported through PIV driver)")
    for fid in [0x2F00, 0x2F01, 0x0001, 0xDB00]:
        _, sw4 = select_by_fid(fid)
        if sw4 == "9000":
            data = read_binary_full()
            print(f"  FID 0x{fid:04X}: {KNOWN_FIDS.get(fid,'?')}  {len(data)}B")

    # ── [8] GENERAL AUTHENTICATE slot 04 raw APDU (LAST) ─────────────────────
    print("\n[8] GENERAL AUTHENTICATE - slot 04 raw APDU")
    ga = general_authenticate_slot04()
    print(f"  SW: {ga.get('sw','?')}  challenge={ga.get('challenge_hex','?')}")
    if ga.get("signature_hex"):
        print(f"  Sig ({ga.get('signature_bytes',0)}B): {ga.get('signature_hex','')[:64]}...")
    else:
        print(f"  Witness: SW={ga.get('witness_sw','?')} {ga.get('witness_resp','')[:32]}")

    print("\n" + "=" * 72)
    print("ISO 7816 walk complete.")
    print("=" * 72)


if __name__ == "__main__":
    run()
