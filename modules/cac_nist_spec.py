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
# 5b. Confirmed dynamic behavior findings (empirical, this card)
# ---------------------------------------------------------------------------

BEHAVIORAL_FINDINGS = [
    {
        "id":    "F-GA-9E",
        "title": "GA slot 9E (Card Auth) NR signing confirmed via PKCS11",
        "ins":   0x87,
        "p2":    0x9E,
        "role":  "NR",
        "sw":    "9000",
        "path":  "PKCS11 (opensc-pkcs11.so)",
        "timing_ms": 228,
        "sig_len":   256,
        "always_auth": False,
        "desc":  "RSA-2048 sign with Card Auth key (slot 9E) without PIN; NR accessible as per PIV spec",
        "note":  "Raw pyscard T=0 returns 6A80 for ALL GA templates due to extended-APDU barrier; PKCS11 only path",
        "surface": "NR-accessible signing oracle; attacker with card can sign arbitrary data without PIN",
    },
    {
        "id":    "F-GA-9A",
        "title": "GA slot 9A (PIV Auth) confirmed working via PKCS11 with PIN",
        "ins":   0x87,
        "p2":    0x9A,
        "role":  "CH",
        "sw":    "9000",
        "path":  "PKCS11 (opensc-pkcs11.so) + PIN login",
        "timing_ms": 237,
        "sig_len":   256,
        "desc":  "RSA-2048 sign with PIV Auth key (slot 9A); requires CH (VERIFY PIN first)",
    },
    {
        "id":    "F-GETCHAL",
        "title": "INS=0x84 GET CHALLENGE causes card hardware reset",
        "ins":   0x84,
        "cla":   0x00,
        "sw":    "CARD_RESET",
        "desc":  "GET CHALLENGE (ISO 7816-4 INS=0x84) does not return 6D00; causes T=0 transaction failure that drops pcscd connection and forces card reinsertion",
        "note":  "Behavior: pcscard returns 'Transaction failed' then subsequent fresh_conn() throws NoCardException -- card has reset or entered unresponsive state",
        "finding_class": "Structural JavaCard implementation bug; GET CHALLENGE handler not implemented in PIV facade; causes state machine error at T=0 layer",
    },
    {
        "id":    "F-VERIFY-P2",
        "title": "VERIFY PIN reference: P2=0x80 only",
        "ins":   0x20,
        "cla":   0x00,
        "sw":    "9000",
        "desc":  "VERIFY with P2=0x80 (global PIN ref) and 8-byte data [PIN + 0xFF padding] returns 9000; P2=0x00 returns 6A88 (reference data not found)",
        "retry_query": "VERIFY P2=0x80 no data = SW 63Cx where x=retry count remaining; confirmed 63C3 (3 retries = max)",
    },
    {
        "id":    "F-CRD",
        "title": "CHANGE REFERENCE DATA (INS=0x24 P2=0x80) confirmed working",
        "ins":   0x24,
        "cla":   0x00,
        "sw":    "9000",
        "desc":  "INS=0x24 P2=0x80 with old_pin(8B) + new_pin(8B) returns 9000; validated same-value change",
        "note":  "PIV spec command, not proprietary; absent from struct_re bare sweep because bare transmit returns 6A88 (P2 ref not set without P2=0x80)",
    },
    {
        "id":    "F-ACA-AID",
        "title": "ACA applet not card-edge addressable",
        "desc":  "All ACA AID variants (A000000396*) return 6A82 (file not found); ACA is an internal applet only -- only PIV facade (A000000308000010000100) is exposed",
        "note":  "Prior XXXX transport errors on AID SELECT were connection-state artifacts; fresh-conn shows clean 6A82",
    },
    {
        "id":    "F-MODULE-INFO",
        "title": "GET PROPERTIES (INS=0xCA) not exposed in PIV context",
        "ins":   0xCA,
        "cla":   0x00,
        "sw":    "6D00",
        "desc":  "ACA Module Info service GET PROPERTIES (CMVP #2545 Table 12) returns 6D00 in PIV AID context; service only accessible via ACA internal interface (not card-edge)",
    },
    {
        "id":    "F-CLA80",
        "title": "CLA=0x80 sweep: zero responses in PIV context",
        "desc":  "All 256 INS codes under CLA=0x80 return 6D00/6E00/SKIP in PIV AID; HID proprietary class byte not active via PIV facade",
    },
    {
        "id":    "F-EXT-AUTH",
        "title": "EXTERNAL AUTHENTICATE (INS=0x82) reachable without prior challenge",
        "ins":   0x82,
        "cla":   0x00,
        "sw":    "6A86",
        "desc":  "INS=0x82 P1=0x00 P2=0x00 returns 6A86 (incorrect P1/P2); command is reachable and parsed; requires correct P1/P2 and prior GET CHALLENGE sequence",
    },
    {
        "id":    "F-SECOBJ-TAG",
        "title": "Security Object at non-standard tag 0x5FC106 (not 0x5FC10C)",
        "tag":   "5FC106",
        "sw":    "9000",
        "size":  1024,
        "desc":  "HID ActivID stores CMS SignedData Security Object at tag 0x5FC106 (HID proprietary), not at NIST standard 0x5FC10C which returns 6A82",
        "inner_tag": "0xBB (HID ActivID proprietary wrapper)",
        "cms_oid": "1.3.27.1.1.1 (DoD SDN security object content type)",
        "note":  "Contains SHA-256 hash table: IDref=2 CHUID, IDref=3 CERT_PIV_AUTH; signed by DoD PKI CA",
    },
    {
        "id":    "F-SECOBJ-MISMATCH",
        "title": "Security Object integrity verification FAILS -- stale hashes",
        "severity": "HIGH",
        "desc":  "SHA-256 hashes in Security Object (IDref=2 CHUID, IDref=3 CERT_PIV_AUTH) do not match SHA-256 of current container content in ANY representation (full raw, strip-53, inner DER, subset). Card content was modified after Security Object was last signed.",
        "impact": "PIV integrity mechanism non-functional. Security Object CMS signature covers stale data; current CHUID and CERT_PIV_AUTH are not integrity-protected.",
        "likely_cause": "CHUID or CERT_PIV_AUTH renewed/re-issued without re-signing Security Object; Security Object is from earlier in card lifecycle.",
        "h_idref2_chuid":     "d861591293da59ee25e596d08cbf8b19b7e041bfd6d149eb50ae968843c9b864",
        "h_idref3_cert_auth": "b59bc5d8f207af509c43c9bcd97af1199853e420c5ac0e72fd849e515c0d3eb1",
        "computed_chuid":     "348eb82909fab9cba3d4aa43101dd8153f378ac597eeaea8f53e92e0be9a9026",
        "computed_cert":      "0d5382facbc894b3f6b792a214de59aef96e0fefd0e05c1c3f034cdf1363b379",
    },
    {
        "id":    "F-CHUID-EXPIRED",
        "title": "CHUID expiry confirmed: 2024-12-16",
        "desc":  "CHUID tag 0x35 (Expiry Date) = '20241216' in ASCII. Card expired December 16, 2024.",
        "note":  "Card is being reverse-engineered post-expiry; no operational use",
    },
    {
        "id":    "F-CHUID-ISSUER-SIG",
        "title": "CHUID CMS signer: DSS17.dmdc.osd.mil (DMDC/OSD) via DOD ID CA-63",
        "desc":  "CHUID tag 0x3E = CMS SignedData (1818B). Signer cert: CN=DSS17.dmdc.osd.mil, OU=OSD, issued by CN=DOD ID CA-63 (serial #07), valid 2021-04-27 through 2027-04-07. Content OID: 2.16.840.1.101.3.6.1. Signing entity: DMDC (Defense Manpower Data Center). Cert still valid at time of analysis. Card expired 2024-12-16; signing infrastructure valid through 2027.",
        "note":  "Signature not cryptographically verified (DoD PKI root cert not downloaded); structural parse only via openssl asn1parse. BIT STRING parse error at RSA public key offset prevents full DER extraction.",
    },
    {
        "id":    "F-SECOBJ-CMS-SELF-CONSISTENT",
        "title": "Security Object CMS message digest internally consistent",
        "desc":  "SHA-256 of Security Object encapsulated content (96B hash table) = 73ADB543B3EC0C7763FD1321B26BB0AFF223FAE3755BCB06C6E6D8F437B1D3AA, matches the messageDigest signed attribute in the CMS exactly. Security Object CMS is self-consistent; it was validly constructed at signing time. Mismatch (F-SECOBJ-MISMATCH) is between the hash table values and current container content, not an internal CMS integrity failure.",
        "note":  "The CMS is structurally valid. The security failure is the stale hash table, not a corrupted signature structure.",
    },
    {
        "id":    "F-SIGNER-CHAIN",
        "title": "Both CMS structures share signer: DOD ID CA-63 serial #07 / DMDC",
        "desc":  "Security Object CMS: signerInfo references issuer CN=DOD ID CA-63, serial #07 (no embedded cert). CHUID CMS: signerInfo references same issuer/serial, embeds cert for CN=DSS17.dmdc.osd.mil. Both structures signed by the same DMDC card-issuance infrastructure. DOD ID CA-63 is a DISA-managed intermediate CA in the DoD PKI hierarchy.",
        "note":  "Confirmed via openssl asn1parse of both CMS DER files. DOD ID CA-63 root cert publicly available from DISA PKI but not downloaded for chain verification.",
    },
    {
        "id":    "F-FASC-N-5BIT",
        "title": "FASC-N 5-bit INCITS 287 decode: AC=8011, CN=000054, PI=0515939123, POA=4 (contractor)",
        "desc":  "25B FASC-N (hex: d22010da0168ad084215258360da150d733c845382201093fa) decoded via INCITS 287 5-bit BCD with odd parity. Fields: SS | Agency=8011 | FS | System=01[0x0D]2 | FS | Credential=000054 | FS | CS=1 | FS | ICI=1 | FS | PI=0515939123 | OC=0 | OI=8011 | POA=4 | ES | LRC. POA=4 = non-federal employee (contractor). PI = cardholder EDIPI. Non-standard code 0x0D (01101 binary) at System Code digit 3: not a valid BCD digit (BCD 1101=13) and not a standard INCITS 287 sentinel; likely HID ActivID proprietary encoding or card-manufacturing artifact.",
        "note":  "Prior nibble-based decode (Agency=2201, PI=5836015073) disagrees with 5-bit decode. 5-bit INCITS 287 decode is authoritative per NIST SP 800-73-4. Non-standard code at system code position is anomalous.",
    },
    {
        "id":    "F-PIV-AUTH-CERT",
        "title": "PIV Auth cert (5FC105): KLOSTER.NICHOLAS.MICHAEL.1505393089 / DOD ID CA-64",
        "desc":  "X.509 cert (1343B DER) at container tag 0x70. Subject CN=KLOSTER.NICHOLAS.MICHAEL.1505393089 (C=US, O=U.S. Government, OU=DoD, OU=PKI, OU=USA). Issuer: CN=DOD ID CA-64 (under DoD Root CA 3, valid through 2027-06-02), serial 0x0FF143. Validity: 2023-02-13 to 2024-12-16. RSA-2048 public key. keyUsage=[digitalSignature] (critical). EKU: smartcardLogon (1.3.6.1.4.1.311.20.2.2), clientAuth (1.3.6.1.5.5.7.3.2). certPolicies: 2.16.840.1.101.2.1.11.42 (id-piv-auth), 2.16.840.1.101.3.2.1.3.13. subjectDirectoryAttributes: countryOfCitizenship=US. SAN: otherName OID 2.16.840.1.101.3.6.6 (id-FASC-N) = d22010da... (matches CHUID exactly). CRL: http://crl.disa.mil/crl/DODIDCA_64.crl. AIA: http://crl.disa.mil/sign/DODIDCA_64.cer + OCSP http://ocsp.disa.mil. Non-standard: stray 0x01 at DER offset 580 before extensions block + tag 0xFD wrapper around AIA extension (both DoD encoding artifacts preventing standard x509 parsing).",
        "note":  "CA-64 cert downloaded from DISA. Signature verification blocked by stray-byte DER artifact. EKU confirms Windows smart card logon + TLS client auth use cases.",
    },
    {
        "id":    "F-DIGSIG-CERT",
        "title": "Digital Signature cert (5FC10A): DOD EMAIL CA-62, emailProtection+documentSigning",
        "desc":  "X.509 cert (1243B DER). Subject CN=KLOSTER.NICHOLAS.MICHAEL.1505393089 (OU=USA). Issuer: CN=DOD EMAIL CA-62, serial 0x1254FD. Validity: 2023-02-13 to 2024-12-16. RSA-2048. keyUsage=[digitalSignature, nonRepudiation]. EKU=[emailProtection, szOID_KP_DOCUMENT_SIGNING (1.3.6.1.4.1.311.10.3.12)]. Purpose: S/MIME email signing and document signing.",
        "note":  "DOD EMAIL CA-62 (not CA-64) -- the email signing infrastructure uses a separate CA chain from PIV auth.",
    },
    {
        "id":    "F-KEYMGMT-CERT",
        "title": "Key Management cert (5FC10B): DOD EMAIL CA-64, keyEncipherment",
        "desc":  "X.509 cert (1210B DER). Subject CN=KLOSTER.NICHOLAS.MICHAEL.1505393089 (OU=USA). Issuer: CN=DOD EMAIL CA-64, serial 0x1230BB. Validity: 2023-02-13 to 2024-12-16. RSA-2048. keyUsage=[keyEncipherment]. Purpose: S/MIME email encryption (key transport).",
        "note":  "Three distinct CA chains: DOD ID CA-64 (PIV auth), DOD EMAIL CA-62 (signing), DOD EMAIL CA-64 (encryption). All three key pairs on same card for different cryptographic purposes.",
    },
    {
        "id":    "F-CA-MISMATCH",
        "title": "CA version mismatch: Security Object=CA-63, PIV Auth cert=CA-64",
        "desc":  "Security Object (tag 0x5FC106) CMS signed by DOD ID CA-63 (serial #07); PIV Auth cert (tag 0x5FC105) issued by DOD ID CA-64 (serial 0x0FF143). The card was re-issued or the cert was renewed under CA-64 after the Security Object was signed. Security Object was not re-signed to reflect the new cert. This directly causes F-SECOBJ-MISMATCH: the hash table covers the old cert content from CA-63 era, but current 0x5FC105 contains a CA-64 cert with a different hash.",
        "severity": "HIGH",
        "note":  "Root cause of F-SECOBJ-MISMATCH: card management failure -- cert renewal without Security Object re-issuance.",
    },
    {
        "id":    "F-CHUID-GUID",
        "title": "CHUID GUID (tag 0x34): cad783c7-0cf4-4251-97f5-de5e375a182b",
        "desc":  "CHUID tag 0x34 = 16 bytes = UUID cad783c7-0cf4-4251-97f5-de5e375a182b (RFC 4122 format). Used as the card's globally unique identifier for contactless card authentication (NIST SP 800-73-4 GUID field).",
    },
    {
        "id":    "F-FINGERPRINTS",
        "title": "Fingerprint BDB: 1236B CBEFF retrieved PIN-gated (FF-padded verify); RAPIDS/ANSI-378",
        "desc":  "GET DATA 5FC103 returned 1236B after VERIFY 9000 (PIN '123456' + 0xFF padding). Container: outer 0x53 (1232B) -> inner 0xBC CBEFF BDB (1226B) + 0xFE EDC. CBEFF BDB: Format Owner 0x030D (DoD/RAPIDS), 'US DOD RAPIDS' origin string at BDB offset 41. FASC-N bound in BDB at offset ~67 (d22010da... = exact match to CHUID FASC-N). FMR magic 'FMR\\0 20\\0' (ANSI INCITS 378-2004) at BDB offset 88 -- this is the finger minutiae template. BDB length field: 1226B total.",
        "note":  "PIN padding: right-padded with 0xFF to 8 bytes (not 0x00). 6982 (access denied) clears after any successful VERIFY 9000 in CH role.",
    },
    {
        "id":    "F-MANAGE-CHANNEL",
        "title": "INS=0x70 MANAGE CHANNEL: OS opens ch1 (returns 0x01); PIV applet rejects ch1 (6881)",
        "desc":  "INS=0x70 P1=00 P2=00 Le=01 returns 9000 data=01 -- logical channel 1 opened at OS layer. All PIV APDUs with CLA=0x01 (channel 1) return 6881 'Logical channel not supported'. MANAGE CHANNEL close returns 6200 (warning). Oberthur Cosmo V8 JavaCard OS supports logical channels; HID ActivID PIV applet binds exclusively to basic channel (CLA=0x00).",
        "note":  "No expanded command surface on channel 1. Confirms PIV applet single-channel design.",
    },
    {
        "id":    "F-TIMING-CLEAN",
        "title": "RSA-2048 timing: TVLA clean, Hamming clean, constant-time confirmed",
        "slot":  "9E (Card Auth, NR)",
        "baseline_ms":  225.2,
        "stddev_ms":    0.87,
        "tvla_t":       1.35,
        "tvla_verdict": "CLEAN (|t|<2.0)",
        "hamming_range_ms": 1.5,
        "hamming_verdict":  "No data-dependent correlation",
        "desc":  "Software TVLA (n=80/class fixed vs random) and Hamming weight sweep (HW 0-256, n=20/point) both clean. RSA-2048 on Oberthur Cosmo V8 is constant-time at PC/SC measurement layer. Consistent with FIPS 140-2 Level 2 requirement.",
        "note":  "Hardware-level timing (ChipWhisperer) would require physical card modification. Software TVLA provides upper bound only.",
    },
    {
        "id":    "F-CONTAINER-MAP",
        "title": "Full container accessibility map confirmed by GET DATA sweep",
        "desc":  "Accessible NR: CCC/CHUID/CERT1-4/5FC106(SecObj). PIN-gated (6982): Fingerprints/Facial. Not present (6A82): Printed_Info/SM_Cert/Security_Object(5FC10C)/Iris/BitGroup/SM_Cert_Signer/Pairing_Code. Proprietary NR: 5FC106 (Security Object, 1024B).",
        "tag_sweep": "5FC0xx-5FCFxx range tested; only 5FC106 responds outside spec list",
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


def _int_or_hex(val, default: int = 0) -> int:
    """Coerce a value that may be int or hex string like '00'/'0x00' to int."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val = val.strip()
        try:
            return int(val, 16)
        except ValueError:
            return default
    return default


def delta_report(sweep: list[dict]) -> None:
    """Cross-reference dynamic sweep findings with spec."""
    spec_ins = {}
    for svc in SERVICES:
        for ie in svc.get("ins_map", []):
            key = (_int_or_hex(ie.get("cla", 0x00)), _int_or_hex(ie.get("ins", 0)))
            spec_ins[key] = {"service": svc["name"], "roles": svc["roles"], "nir": svc.get("nir", False)}

    print("\n=== DELTA: SPEC vs SWEEP ===\n")

    spec_confirmed = []
    spec_missing = []
    proprietary = []

    for entry in sweep:
        ins = _int_or_hex(entry.get("ins", 0))
        cla = _int_or_hex(entry.get("cla", 0x00))
        sw  = str(entry.get("sw", ""))
        key = (cla, ins)

        if key in spec_ins:
            spec_confirmed.append((cla, ins, sw, spec_ins[key]["service"]))
        else:
            proprietary.append((cla, ins, sw, str(entry.get("desc", ""))))

    for key, svc_info in spec_ins.items():
        cla, ins = key
        found = any(
            _int_or_hex(e.get("ins", 0)) == ins and _int_or_hex(e.get("cla", 0x00)) == cla
            for e in sweep
        )
        if not found:
            spec_missing.append((cla, ins, svc_info["service"]))

    print(f"Spec commands confirmed by sweep: {len(spec_confirmed)}")
    for cla, ins, sw, svc in sorted(spec_confirmed):
        print(f"  CLA={cla:02X} INS={ins:02X} SW={sw:<6}  [{svc}]")

    print(f"\nSpec commands NOT seen in sweep (may be role-gated or need data): {len(spec_missing)}")
    for cla, ins, svc in sorted(spec_missing):
        print(f"  CLA={cla:02X} INS={ins:02X}           [{svc}]")

    print(f"\nProspective proprietary / unspecced commands: {len(proprietary)}")
    for cla, ins, sw, desc in sorted(proprietary):
        print(f"  CLA={cla:02X} INS={ins:02X} SW={sw:<6}  {desc[:80]}")


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

    print(f"\nBEHAVIORAL FINDINGS ({len(BEHAVIORAL_FINDINGS)}):")
    for f in BEHAVIORAL_FINDINGS:
        ins_str = f"INS=0x{f['ins']:02X}  " if "ins" in f else "              "
        print(f"  [{f['id']:12s}]  {ins_str}{f['desc'][:80]}")

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
            "behavioral_findings": BEHAVIORAL_FINDINGS,
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
