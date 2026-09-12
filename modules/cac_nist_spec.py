"""
cac_nist_spec.py -- HID Global ActivID Applet 2.7.4 static spec model

Source: NIST CMVP Certificate #2545
        140sp2545.pdf (HID Global ActivID Applet Suite v2.7.4 on Oberthur Cosmo V8)
        NIST SP 800-73-4 (PIV commands)

Purpose: encode the full static architecture of the card's command/service/CSP layer
         so dynamic sweep findings (cac_struct_re.py, cac_iso7816_walk.py) can be
         cross-referenced against ground truth.

Output:  structured spec dict, behavioral descriptors for BERT clustering, delta report
         between spec and observed behavior.

Usage:
    python modules/cac_nist_spec.py                 # print full spec
    python modules/cac_nist_spec.py --bert          # build + print BERT cluster
    python modules/cac_nist_spec.py --delta <json>  # compare spec vs sweep results
    python modules/cac_nist_spec.py --delta latest  # use most recent struct_re output
"""

import argparse
import json
import os
import sys
import glob
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# 1. Card identity
# ---------------------------------------------------------------------------

CARD_IDENTITY = {
    "product":       "HID Global ActivID Applet Suite",
    "version":       "2.7.4",
    "build":         "2.7.4.10",
    "cmvp_cert":     "#2545",
    "fips_level":    2,
    "platform":      "Oberthur Technologies Cosmo V8",
    "javacard":      "3.0.1",
    "globalplatform": "2.2",
    "atr":           "3b7d96000080318065b07549170f83009000",
    "reader_tested": "Alcor Micro AU9540 CCID (VID=0x058F PID=0x9540)",
    "protocol":      "T=0 (ISO 7816-4)",
    "max_apdu_data": 255,  # T=0 protocol limit; reader supports 65536 at CCID layer
    "extended_apdu": False,  # blocked at pyscard/T=0 layer
}

# ---------------------------------------------------------------------------
# 2. Roles (Table 10 / Table 11)
# ---------------------------------------------------------------------------

ROLES = {
    "NR": {
        "name":   "No Role (unauthenticated)",
        "auth":   None,
        "key":    None,
        "desc":   "Pre-authentication state; unauthenticated services only",
    },
    "CH": {
        "name":   "Card Holder",
        "auth":   "Secret Value (PIN compare)",
        "key":    "ACA-PIN",
        "pin_len": 8,
        "pin_confirmed": "123456 (SW=9000, 3 retries remaining)",
        "false_auth_prob": "1/(256^8) = 5.4E-20",
        "max_fail": 15,
        "desc":   "User identity role; gates fingerprint read and PIV signing",
    },
    "AA": {
        "name":   "Application Administrator",
        "auth":   "Symmetric Cryptographic (3-Key TDEA challenge-response)",
        "key":    "ACA-SPAK",
        "key_type": "3-Key Triple-DES",
        "ins":    0x50,
        "false_auth_prob": "1/(2^64) = 5.4E-20",
        "rate_limit": "2^16 attempts/min",
        "desc":   "Card config role; gates Manage Configuration, INS=0x50 auth",
        "finding": "INS=0x50 returns 6982 across all P1/P2/data -- confirmed gated by ACA-SPAK",
    },
    "CO": {
        "name":   "Cryptographic Officer",
        "auth":   "Secure Channel Protocol (SCP02/SCP03, AES-128 mutual auth)",
        "key":    "SD-KENC / SD-KMAC",
        "derived": "SD-SENC, SD-SMAC (session keys)",
        "false_auth_prob": "1/(2^128) = 2.9E-39",
        "max_fail": 15,
        "desc":   "Card issuance/management role; GlobalPlatform Card Manager access",
    },
}

# ---------------------------------------------------------------------------
# 3. Applets / AID registry
# ---------------------------------------------------------------------------

AIDS = {
    "PIV":          "A0 00 00 03 08 00 00 10 00 01 00",  # NIST SP 800-73-4 PIV
    "HID_ActivID":  "A0 00 00 03 96 04 E0 20 00",        # HID ACA applet
    "HID_ActivID2": "A0 00 00 03 96 04 E0 20 01",        # HID ACA applet alt
    "CardManager":  "A0 00 00 01 51 00 00",              # GlobalPlatform SD/CM
    "PKI_Auth":     "A0 00 00 03 08 00 00 10 00 01 01",  # PIV Auth slot variant
    "PKI_Email":    "A0 00 00 03 08 00 00 10 00 01 02",  # PIV email cert slot
    "DoD_CDS":      "A0 00 00 01 16 01 01",              # DoD CDS applet (optional)
}

APPLET_ARCHITECTURE = {
    "ASC_Library": "Core crypto/ACR library; not directly accessible at card edge",
    "ACA":         "Access Control Applet; enforces ACR, secure messaging, 3 roles (NR/CH/AA)",
    "GC_PKI_SKI":  "PKI applet; RSA-2048 sign/decrypt, OTP, PIV cert/data storage",
    "SMAv3":       "OPACITY ZKM Secure Messaging (non-approved mode; not in FIPS scope)",
    "PIV_Facade":  "PIV-compliant interface layer over GC/PKI/SKI (NIST SP 800-73-4)",
}

# ---------------------------------------------------------------------------
# 4. Services (Table 12 -- Approved Mode)
# ---------------------------------------------------------------------------

SERVICES = [
    {
        "name":  "Authenticate",
        "roles": ["AA", "CH", "CO"],
        "nir":   False,
        "ins_map": [
            {"ins": 0x50, "cla": 0x00, "role": "AA",
             "desc": "External Auth via ACA-SPAK (3DES challenge); confirmed 6982 without key"},
            {"ins": 0x20, "cla": 0x00, "role": "CH",
             "desc": "VERIFY PIN (ISO 7816-4 INS=0x20); confirmed 9000 with PIN=123456"},
            {"ins": 0x82, "cla": 0x00, "role": "CO",
             "desc": "EXTERNAL AUTHENTICATE (SCP02 MAC-on-MAC); CO role via GlobalPlatform"},
        ],
        "csps":  ["ACA-SPAK (AA)", "ACA-PIN (CH)", "SD-SENC/SD-SMAC (CO)"],
    },
    {
        "name":  "Context",
        "roles": ["NR", "AA", "CH", "CO"],
        "nir":   True,
        "ins_map": [
            {"ins": 0xA4, "cla": 0x00, "p1": 0x04, "p2": 0x00,
             "desc": "SELECT by AID (ISO 7816-4); NR; confirmed PIV AID selects cleanly"},
        ],
        "csps":  [],
        "note":  "Zeroizes session keys (SD-SENC/SD-SMAC) on applet deselect",
    },
    {
        "name":  "Get OTP",
        "roles": ["CH", "CO"],
        "nir":   False,
        "ins_map": [
            {"ins": 0xB0, "cla": 0x80,
             "desc": "GET OTP (HID proprietary; CLA=0x80 class byte)"},
        ],
        "csps":  ["SKI-OTP"],
    },
    {
        "name":  "Lifecycle",
        "roles": ["AA", "CO"],
        "nir":   False,
        "ins_map": [
            {"ins": 0xF0, "cla": 0x80,
             "desc": "CARD TERMINATE or applet lifecycle transition; CO via GlobalPlatform"},
        ],
        "csps":  ["all (zeroize)"],
        "note":  "Zeroizes ALL CSPs in NVM on card termination",
    },
    {
        "name":  "Logout",
        "roles": ["NR"],
        "nir":   True,
        "ins_map": [
            {"ins": 0x20, "cla": 0x00, "data_len": 0,
             "desc": "VERIFY with empty data (P2=0x80) clears CH; global logout via Context/deselect"},
        ],
        "csps":  [],
    },
    {
        "name":  "Manage Configuration",
        "roles": ["AA"],
        "nir":   False,
        "ins_map": [
            {"ins": 0xDB, "cla": 0x00,
             "desc": "PUT DATA (ISO 7816-4 INS=0xDB); ACA config objects; gated AA role"},
        ],
        "csps":  ["ACA-SPAK", "ACA-PIN", "ACA-PUK", "ACA-PC"],
    },
    {
        "name":  "Manage Content",
        "roles": ["AA", "CH", "CO"],
        "nir":   False,
        "ins_map": [
            {"ins": 0x47, "cla": 0x00,
             "desc": "GENERATE ASYMMETRIC KEY PAIR (PIV INS=0x47); returns public key; requires AA or CO"},
            {"ins": 0xE2, "cla": 0x00,
             "desc": "PUT DATA (ISO 7816-4 INS=0xE2 or 0xDB); load certs/data; gated CO for provisioning"},
        ],
        "csps":  ["PIV-RPAK", "PIV-RDSK", "PIV-RKDK", "PIV-RCAK", "SD-SMAC (integrity on load)"],
    },
    {
        "name":  "Module Info",
        "roles": ["NR", "AA", "CH"],
        "nir":   True,
        "ins_map": [
            {"ins": 0xCA, "cla": 0x00, "tag": 0x24,
             "desc": "GET PROPERTIES tag=0x24; returns FIPS mode data (01=FIPS 140-2 approved mode)"},
            {"ins": 0xCB, "cla": 0x00,
             "desc": "GET DATA (PIV INS=0xCB); retrieves data objects including Card Capabilities Container"},
        ],
        "csps":  [],
        "note":  "GET PROPERTIES with tag 0x24: response 0x24 0x02 01 YY where 01=approved mode",
        "finding": "GET PROPERTIES (INS=0xCA tag=0x24) not yet probed; enumerate in struct_re sweep",
    },
    {
        "name":  "Module Reset",
        "roles": ["NR"],
        "nir":   True,
        "ins_map": [],
        "csps":  ["all volatile"],
        "note":  "Power cycle / ATR; zeroizes volatile CSPs (SD-SENC, SD-SMAC, session state)",
    },
    {
        "name":  "PIV Authentication",
        "roles": ["CH"],
        "nir":   False,
        "ins_map": [
            {"ins": 0x87, "cla": 0x00, "key_ref": 0x9A,
             "desc": "GENERAL AUTHENTICATE slot 9A (PIV Auth); requires CH (VERIFY PIN first)"},
        ],
        "csps":  ["PIV-RPAK (RSA-2048 private key, slot 9A)"],
        "note":  "Raw pyscard T=0 cannot send 256-byte padded block (extended APDU blocked); use PKCS11 stack",
        "finding": "GA via raw pyscard returns 6A80; confirmed working via opensc PKCS11 slot 04",
    },
    {
        "name":  "PIV Card Authentication",
        "roles": ["NR"],
        "nir":   True,
        "ins_map": [
            {"ins": 0x87, "cla": 0x00, "key_ref": 0x9E,
             "desc": "GENERAL AUTHENTICATE slot 9E (Card Auth); no PIN needed; NR accessible"},
        ],
        "csps":  ["PIV-RCAK (RSA-2048 private key, slot 9E)"],
    },
    {
        "name":  "PIV Digital Signature",
        "roles": ["CH"],
        "nir":   False,
        "ins_map": [
            {"ins": 0x87, "cla": 0x00, "key_ref": 0x9C,
             "desc": "GENERAL AUTHENTICATE slot 9C (digital sig); requires CH; hash-then-sign"},
        ],
        "csps":  ["PIV-RDSK (RSA-2048 private key, slot 9C)"],
    },
    {
        "name":  "PIV Info",
        "roles": ["NR", "CH"],
        "nir":   True,
        "ins_map": [
            {"ins": 0xCB, "cla": 0x00,
             "desc": "GET DATA (INS=0xCB); PIV data objects; NR for most; CH for Fingerprints/Facial"},
        ],
        "csps":  [],
        "containers": {
            0x5FC107: {"name": "CCC",          "nir": True,  "found": True,  "size": None},
            0x5FC102: {"name": "CHUID",         "nir": True,  "found": True,  "size": None},
            0x5FC105: {"name": "CERT1_PIV_AUTH","nir": True,  "found": True,  "size": 1356},
            0x5FC10A: {"name": "CERT2_DIGSIG",  "nir": True,  "found": True,  "size": None},
            0x5FC10B: {"name": "CERT3_KM",      "nir": True,  "found": True,  "size": None},
            0x5FC101: {"name": "CERT4_CA",      "nir": True,  "found": True,  "size": None},
            0x5FC103: {"name": "Fingerprints",  "nir": False, "found": True,  "size": 1236,
                       "note": "PIN-gated; CBEFF BDB format owner 0x030D; 2 finger records"},
            0x5FC104: {"name": "Printed_Info",  "nir": False, "found": False,
                       "sw": "6A82"},
            0x5FC108: {"name": "Facial_Image",  "nir": False, "found": False,
                       "note": "transport error when probed; too large for T=0"},
            0x5FC121: {"name": "Iris_Images",   "nir": False, "found": False,
                       "note": "transport error"},
            0x5FC10C: {"name": "Security_Object","nir": True,  "found": True,
                       "note": "CMS SignedData covers 2 containers only (CERT1+Fingerprints)"},
            0x5FC109: {"name": "SM_Cert",       "nir": True,  "found": False,
                       "note": "transport error"},
        },
    },
    {
        "name":  "PIV System Key Services",
        "roles": ["CO"],
        "nir":   False,
        "ins_map": [
            {"ins": 0xDB, "cla": 0x00,
             "desc": "PUT DATA with wrapped key; key is unwrapped then NOT retained by module"},
        ],
        "csps":  ["SD-SMAC (wrapping integrity)"],
        "note":  "Key is unwrapped by CO but NOT stored in module per FIPS scope",
    },
    {
        "name":  "Secure Channel",
        "roles": ["CO"],
        "nir":   False,
        "ins_map": [
            {"ins": 0x50, "cla": 0x80,
             "desc": "INITIALIZE UPDATE (GlobalPlatform SCP02/SCP03 step 1); CO auth sequence"},
            {"ins": 0x82, "cla": 0x84,
             "desc": "EXTERNAL AUTHENTICATE (SCP02 step 2; CLA=0x84 secure messaging)"},
        ],
        "csps":  ["SD-KENC", "SD-KMAC", "SD-KDEK", "SD-SENC (derived)", "SD-SMAC (derived)"],
    },
    {
        "name":  "Sign",
        "roles": ["CH"],
        "nir":   False,
        "ins_map": [
            {"ins": 0x87, "cla": 0x00, "key_ref": 0x9A,
             "desc": "GENERAL AUTHENTICATE slot 9A; RSA-2048 RSASP1; confirmed via PKCS11 226-258ms"},
        ],
        "csps":  ["PIV-RPAK"],
        "finding": "PKCS11 sign slot 04 (9A) confirmed working; timing: 226-258ms RSA-2048",
    },
]

# ---------------------------------------------------------------------------
# 5. Known proprietary commands (dynamic sweep findings)
# ---------------------------------------------------------------------------

PROPRIETARY_FINDINGS = [
    {
        "ins":   0x50,
        "cla":   0x00,
        "role":  "AA",
        "sw_without_auth": "6982",
        "spec_service": "Authenticate (AA)",
        "key_required": "ACA-SPAK (3-Key TDEA)",
        "desc":  "External Authentication to AA role; challenge-response; permanently gated without management key",
        "note":  "Confirmed proprietary (not in NIST SP 800-73-4); CMVP doc Table 12 row: Authenticate -> AA column",
        "attack_surface": "None without management key; key set during DoD personalization; unique per card",
    },
    {
        "ins":   0x47,
        "cla":   0x00,
        "role":  "AA/CO",
        "spec_service": "Manage Content (key gen)",
        "desc":  "GENERATE ASYMMETRIC KEY PAIR; PIV standard INS; gated by AA or CO role",
        "attack_surface": "Only if AA/CO auth achieved; public key returned in response",
    },
]

# ---------------------------------------------------------------------------
# 6. CSP inventory (Table 9)
# ---------------------------------------------------------------------------

CSPS = {
    "OS-DRBG-SEED":  {"type": "DRBG seed",       "bits": 256,  "algo": "AES-DRBG (Cert #537)",
                      "note": "NDRNG-sourced; not directly accessible"},
    "OS-DRBG-STATE": {"type": "DRBG state",       "bits": 256,  "algo": "AES-DRBG"},
    "SD-KENC":       {"type": "AES key",           "bits": 128,  "algo": "AES-128 CBC",
                      "role": "CO key derivation (master)"},
    "SD-KMAC":       {"type": "AES key",           "bits": 128,  "algo": "AES-128 CMAC",
                      "role": "CO key derivation (master)"},
    "SD-KDEK":       {"type": "AES key",           "bits": 128,  "algo": "AES-128",
                      "role": "Data encryption key"},
    "SD-SENC":       {"type": "AES session key",   "bits": 128,  "algo": "AES-128",
                      "role": "SCP session encryption; zeroized on deselect"},
    "SD-SMAC":       {"type": "AES session key",   "bits": 128,  "algo": "AES-128 CMAC",
                      "role": "SCP MAC; zeroized on deselect"},
    "ACA-SPAK":      {"type": "3-Key TDEA key",    "bits": 168,  "algo": "3-Key Triple-DES ECB",
                      "role": "AA role auth (0-8 key instances)"},
    "ACA-PIN":       {"type": "PIN value",          "bits": 64,   "algo": "Secret Value compare",
                      "role": "CH role auth; 8 char; confirmed 123456"},
    "ACA-PUK":       {"type": "PUK value",          "bits": 64,   "algo": "Secret Value compare",
                      "role": "Unblock ACA-PIN"},
    "ACA-PC":        {"type": "Pairing Code",       "bits": None, "algo": "Secret Value compare"},
    "PKI-GPK":       {"type": "RSA public key",     "bits": 2048, "algo": "RSA-2048",
                      "note": "Not retained by module after key gen; returned to external entity"},
    "SKI-OTP":       {"type": "OTP seed key",       "bits": None, "algo": "HMAC-SHA1 or AES (OTP mode)"},
    "PIV-RPAK":      {"type": "RSA-2048 private",   "bits": 2048, "algo": "RSASP1",
                      "slot": "9A", "role": "PIV Authentication; CH required"},
    "PIV-RDSK":      {"type": "RSA-2048 private",   "bits": 2048, "algo": "RSASP1",
                      "slot": "9C", "role": "Digital Signature; CH required"},
    "PIV-RKDK":      {"type": "RSA-2048 private",   "bits": 2048, "algo": "RSADP",
                      "slot": "9D", "role": "Key Management (decrypt); CH required"},
    "PIV-RCAK":      {"type": "RSA-2048 private",   "bits": 2048, "algo": "RSASP1",
                      "slot": "9E", "role": "Card Authentication; NR accessible"},
}

# ---------------------------------------------------------------------------
# 7. Self-test inventory (Table 15)
# ---------------------------------------------------------------------------

SELF_TESTS = [
    {"algo": "CRC-16",          "type": "Critical function KAT"},
    {"algo": "Firmware",        "type": "16-bit CRC over NVM executable code"},
    {"algo": "AES-DRBG",        "type": "Fixed input KAT + SP800-90A health monitoring"},
    {"algo": "3-Key TDEA ECB",  "type": "Separate encrypt/decrypt KAT"},
    {"algo": "AES-128 ECB",     "type": "Decrypt KAT"},
    {"algo": "SP800-108 KDF",   "type": "KAT (includes AES CMAC self-test)"},
    {"algo": "SHA-256",         "type": "Fixed input KAT"},
    {"algo": "RSA CRT 2048",    "type": "Signature KAT"},
    {"algo": "ECC CDH P-521",   "type": "Primitive Z KAT (non-approved mode legacy)"},
    {"algo": "ECDSA P-224",     "type": "Known answer test"},
]

SELF_TEST_FAIL_SW = "0x6FXX"  # enters SELF_TEST_ERROR state
KAT_FAIL_CLEAR_SW = "0x6600"  # RSA/ECC pairwise consistency fail; key cleared

# ---------------------------------------------------------------------------
# 8. Behavioral descriptors for BERT clustering
#    Same format as cac_struct_re.py / ablation semantic_search describe_function()
# ---------------------------------------------------------------------------

def spec_descriptors() -> list[dict]:
    """Return one descriptor per known service/command combination."""
    descs = []
    for svc in SERVICES:
        for ins_entry in svc.get("ins_map", []):
            ins = ins_entry.get("ins", 0)
            cla = ins_entry.get("cla", 0x00)
            role = "/".join(svc["roles"])
            nir = "NR_accessible" if svc.get("nir") else "auth_required"
            desc = (
                f"SPEC_CMD | ins:0x{ins:02X} cla:0x{cla:02X} | "
                f"service:{svc['name'].replace(' ', '_')} | "
                f"role:{role} | {nir} | "
                f"desc:{ins_entry.get('desc', '')}"
            )
            descs.append({
                "source":  "NIST_CMVP_2545",
                "ins":     ins,
                "cla":     cla,
                "service": svc["name"],
                "roles":   svc["roles"],
                "nir":     svc.get("nir", False),
                "desc":    desc,
                "finding": ins_entry.get("desc", ""),
            })
    return descs


# ---------------------------------------------------------------------------
# 9. Delta: compare spec vs dynamic sweep results
# ---------------------------------------------------------------------------

def load_sweep_results(path: str) -> list[dict]:
    """Load cac_struct_re.py JSON output."""
    with open(path) as f:
        data = json.load(f)
    # struct_re output is a list of finding dicts
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return []


def delta_report(sweep: list[dict]) -> None:
    """Cross-reference dynamic sweep findings with spec."""
    spec_ins = {}
    for svc in SERVICES:
        for ie in svc.get("ins_map", []):
            key = (ie.get("cla", 0x00), ie.get("ins", 0))
            spec_ins[key] = {"service": svc["name"], "roles": svc["roles"], "nir": svc.get("nir", False)}

    print("\n=== DELTA: SPEC vs SWEEP ===\n")

    spec_confirmed = []
    spec_missing = []
    proprietary = []

    for entry in sweep:
        ins = entry.get("ins", 0)
        cla = entry.get("cla", 0x00)
        sw  = entry.get("sw", "")
        key = (cla, ins)

        if key in spec_ins:
            spec_confirmed.append((cla, ins, sw, spec_ins[key]["service"]))
        else:
            proprietary.append((cla, ins, sw, entry.get("desc", "")))

    for key, svc_info in spec_ins.items():
        cla, ins = key
        found = any(e.get("ins") == ins and e.get("cla", 0x00) == cla for e in sweep)
        if not found:
            spec_missing.append((cla, ins, svc_info["service"]))

    print(f"Spec commands confirmed by sweep: {len(spec_confirmed)}")
    for cla, ins, sw, svc in sorted(spec_confirmed):
        print(f"  CLA={cla:02X} INS={ins:02X} SW={sw:4s}  [{svc}]")

    print(f"\nSpec commands NOT seen in sweep (may be role-gated): {len(spec_missing)}")
    for cla, ins, svc in sorted(spec_missing):
        print(f"  CLA={cla:02X} INS={ins:02X}           [{svc}]")

    print(f"\nProspective proprietary / unspecced commands: {len(proprietary)}")
    for cla, ins, sw, desc in sorted(proprietary):
        print(f"  CLA={cla:02X} INS={ins:02X} SW={sw:4s}  {desc[:80]}")


# ---------------------------------------------------------------------------
# 10. BERT cluster over spec descriptors
# ---------------------------------------------------------------------------

def bert_cluster(descriptors: list[dict], threshold: float = 0.80) -> None:
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np
    except ImportError:
        print("[ERROR] sentence-transformers not installed; run: pip install sentence-transformers")
        return

    print(f"\n[BERT] encoding {len(descriptors)} spec descriptors...")
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    texts = [d["desc"] for d in descriptors]
    vecs = model.encode(texts, normalize_embeddings=True, show_progress_bar=True)

    assigned = [-1] * len(descriptors)
    clusters = []
    for i in range(len(descriptors)):
        if assigned[i] >= 0:
            continue
        clust = [i]
        for j in range(i + 1, len(descriptors)):
            if assigned[j] >= 0:
                continue
            sim = float(np.dot(vecs[i], vecs[j]))
            if sim >= threshold:
                clust.append(j)
                assigned[j] = len(clusters)
        assigned[i] = len(clusters)
        clusters.append(clust)

    print(f"\n[BERT] {len(clusters)} clusters (threshold={threshold}):\n")
    for ci, members in enumerate(clusters):
        print(f"  CLUSTER {ci:02d} ({len(members)} members):")
        for mi in members:
            d = descriptors[mi]
            svc = d["service"]
            ins = d["ins"]
            print(f"    INS=0x{ins:02X}  [{svc}]  {d['finding'][:70]}")
        print()


# ---------------------------------------------------------------------------
# 11. Summary print
# ---------------------------------------------------------------------------

def print_summary() -> None:
    print(f"\n{'='*70}")
    print(f"  HID Global ActivID Applet 2.7.4 -- Static Spec Model")
    print(f"  CMVP #{CARD_IDENTITY['cmvp_cert']}  FIPS 140-2 Level {CARD_IDENTITY['fips_level']}")
    print(f"  Platform: {CARD_IDENTITY['platform']}")
    print(f"  Protocol: {CARD_IDENTITY['protocol']}  Max APDU data: {CARD_IDENTITY['max_apdu_data']}B")
    print(f"{'='*70}\n")

    print("ROLES:")
    for rid, r in ROLES.items():
        key_str = f"  key={r.get('key','N/A')}" if r.get("key") else ""
        auth_str = str(r.get('auth') or 'none')
        print(f"  {rid:4s}  {r['name']:<35}  auth={auth_str:<30}{key_str}")

    print(f"\nAPPLETS:")
    for name, desc in APPLET_ARCHITECTURE.items():
        print(f"  {name:<12}  {desc}")

    print(f"\nSERVICES ({len(SERVICES)}):")
    for svc in SERVICES:
        roles = "/".join(svc["roles"])
        nir = " [NR_accessible]" if svc.get("nir") else ""
        ncmds = len(svc.get("ins_map", []))
        print(f"  {svc['name']:<28}  roles={roles:<12}  cmds={ncmds}{nir}")
        if svc.get("finding"):
            print(f"    FINDING: {svc['finding']}")

    print(f"\nCSPs ({len(CSPS)}):")
    for name, c in CSPS.items():
        print(f"  {name:<14}  {c['type']:<22}  {c['bits'] or '?':>4}b  {c.get('role','')}")

    print(f"\nPROPRIETARY COMMANDS FOUND:")
    for p in PROPRIETARY_FINDINGS:
        sw = p.get('sw_without_auth', p.get('sw', '????'))
        print(f"  INS=0x{p['ins']:02X}  role={p['role']:6s}  sw={sw}  {p['desc']}")

    print(f"\nSELF-TESTS ({len(SELF_TESTS)}):")
    for st in SELF_TESTS:
        print(f"  {st['algo']:<20}  {st['type']}")
    print(f"  Fail state: return {SELF_TEST_FAIL_SW} -> SELF_TEST_ERROR")
    print()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="HID ActivID 2.7.4 static spec model")
    ap.add_argument("--bert",  action="store_true", help="BERT cluster spec descriptors")
    ap.add_argument("--delta", metavar="JSON",      help="compare spec vs struct_re JSON output ('latest' = most recent)")
    ap.add_argument("--json",  action="store_true", help="dump full spec as JSON")
    args = ap.parse_args()

    if args.json:
        spec = {
            "card_identity": CARD_IDENTITY,
            "roles": ROLES,
            "aids": AIDS,
            "services": SERVICES,
            "csps": CSPS,
            "proprietary_findings": PROPRIETARY_FINDINGS,
            "self_tests": SELF_TESTS,
        }
        print(json.dumps(spec, indent=2))
        return

    print_summary()

    if args.bert:
        descs = spec_descriptors()
        bert_cluster(descs)

    if args.delta:
        path = args.delta
        if path == "latest":
            candidates = sorted(
                glob.glob(os.path.expanduser("~/ablation/results/cac_struct_re_*.json")),
                key=os.path.getmtime,
            )
            if not candidates:
                candidates = sorted(
                    glob.glob("/tmp/cac_struct_re_*.json"),
                    key=os.path.getmtime,
                )
            if not candidates:
                print("[ERROR] no struct_re JSON output found")
                sys.exit(1)
            path = candidates[-1]
            print(f"[delta] using {path}")
        sweep = load_sweep_results(path)
        delta_report(sweep)


if __name__ == "__main__":
    main()
