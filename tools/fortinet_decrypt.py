#!/usr/bin/env python3
"""
Fortinet Universal Decryption Tool
Targets:
  FortiClient EMS 7.2.9 (Go PE32+): ecsocksrv.exe, regworker.exe, ...
  FortiSOAR 7.2.x-7.6.x (Cython .so): workflow secrets + connector credentials

EMS Schemes:
  SCHEME-1  XOR passphrase: defaultCertPassEnc XOR defaultCertPassKey -> AES-256-CBC PEM passphrase
  SCHEME-2  AES-128-CBC passphrase decrypt: AES128CBC(k1, IV=zeros, serverKeyPwd) -> DES passphrase
  SCHEME-3  AES-128-CBC blob decrypt: AES128CBC(k1, IV=zeros, serverKeyEnc) -> DES-EDE3-CBC PEM
  SCHEME-4  HMAC-512 key extraction: raw ASCII from global (no decryption needed)
  SCHEME-5  JWT signing keys: same as SCHEME-4

FortiSOAR Schemes:
  SCHEME-FSR1  Fernet/AES-128-CBC: hardcoded key in encrypt_decrypt_util.so (FSR-F39)
               Encrypts: workflow secrets, env vars, playbook sensitive params (PostgreSQL)
  SCHEME-FSR2  AES-128-CFB: hardcoded keys in PasswordModule.so (FSR-F40)
               Encrypts: connector credentials (API keys, OAuth, SMTP, cloud creds)

Usage:
  # FortiClient EMS binary analysis
  python3 fortinet_decrypt.py <binary.exe> [--dump-all] [--out-dir /tmp/out]

  # FortiSOAR decrypt single blob (auto-detect Fernet vs AES-CFB)
  python3 fortinet_decrypt.py --fortisoar --blob <base64_ciphertext>

  # FortiSOAR decrypt file of blobs (one per line, optionally label:blob format)
  python3 fortinet_decrypt.py --fortisoar --blob-file blobs.txt

  # FortiSOAR try all keys against a blob
  python3 fortinet_decrypt.py --fortisoar --blob <base64_ciphertext> --try-all
"""

import struct, sys, os, hashlib, subprocess, argparse, json, base64
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[!] cryptography not installed -- decryption disabled (pip install cryptography)")

try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False

try:
    from Crypto.Cipher import AES as PyCryptoAES
    HAS_PYCRYPTO = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES as PyCryptoAES
        HAS_PYCRYPTO = True
    except ImportError:
        HAS_PYCRYPTO = False


# ================================================================ FortiSOAR keys
# FSR-F39: Fernet key from encrypt_decrypt_util.so module init
# Used by: workflow secrets, environment variables, playbook sensitive params
FSR_FERNET_KEY = b'PGh7aJYw8gPK0HT9W2x7ThTOyTurZShP7HmnQGQFyKA='

# FSR-F40: AES-128-CFB keys from PasswordModule.so
# Used by: connector credentials stored in cyops_db
FSR_AES_CFB_KEYS = {
    'PasswordModule_default': b'jp3mci29fq7f2kc7',
    'PasswordModule_alt':     b'I3dmcn23@KlS2#!c',  # 16 bytes (truncated from I3dmcn23@KlS2#!ck)
    'PasswordModule_cli':     b'jQp3(7@jod#j38d1',
}

# Suffix appended by PasswordModule.encrypt, stripped in decrypt
# BSS ref: __pyx_kp_s_Password -> endswith check
FSR_PWD_SUFFIX = b'Password'


# ============================================================= FortiSOAR decrypt

def fsr_fernet_decrypt(token_b64: str) -> bytes | None:
    """Decrypt a FortiSOAR Fernet token (FSR-F39 hardcoded key)."""
    if not HAS_FERNET:
        print("[!] cryptography.fernet not available")
        return None
    try:
        if isinstance(token_b64, str):
            token_b64 = token_b64.encode()
        f = Fernet(FSR_FERNET_KEY)
        return f.decrypt(token_b64)
    except InvalidToken:
        return None
    except Exception as e:
        return None


def fsr_aes_cfb_decrypt(ciphertext_b64: str, key: bytes) -> bytes | None:
    """
    Decrypt a FortiSOAR PasswordModule AES-128-CFB blob (FSR-F40).
    Format: base64(IV[16] + ciphertext) with optional 'Password' suffix stripped.
    """
    if not HAS_PYCRYPTO:
        print("[!] pycryptodome not available (pip install pycryptodome)")
        return None
    try:
        raw = base64.b64decode(ciphertext_b64)
        if len(raw) < 17:
            return None
        iv = raw[:16]
        ct = raw[16:]
        if ct.endswith(FSR_PWD_SUFFIX):
            ct = ct[:-len(FSR_PWD_SUFFIX)]
        cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_CFB, iv)
        pt = cipher.decrypt(ct)
        if pt.endswith(FSR_PWD_SUFFIX):
            pt = pt[:-len(FSR_PWD_SUFFIX)]
        return pt
    except Exception:
        return None


def fsr_is_fernet_token(blob: str) -> bool:
    """Fernet tokens are URL-safe base64 and start with gAAAAA (version byte 0x80)."""
    try:
        b = base64.urlsafe_b64decode(blob.strip() + '==')
        return b[0] == 0x80
    except Exception:
        return False


def fsr_decrypt_blob(blob: str, try_all: bool = False) -> dict:
    """
    Auto-detect scheme and decrypt a FortiSOAR ciphertext blob.
    Returns dict with: scheme, key_used, plaintext (hex+str), raw
    """
    blob = blob.strip()
    result = {'input': blob[:40] + ('...' if len(blob) > 40 else ''), 'scheme': None,
              'key_used': None, 'plaintext': None, 'plaintext_str': None, 'success': False}

    # Try Fernet first (FSR-F39)
    if fsr_is_fernet_token(blob) or try_all:
        pt = fsr_fernet_decrypt(blob)
        if pt is not None:
            result.update({
                'scheme': 'SCHEME-FSR1 (Fernet/AES-128-CBC)',
                'key_used': 'FSR_FERNET_KEY (PGh7aJYw8gPK0HT9W2x7ThTOyTurZShP7HmnQGQFyKA=)',
                'plaintext': pt.hex(),
                'plaintext_str': pt.decode('utf-8', errors='replace'),
                'success': True,
            })
            return result

    # Try AES-128-CFB keys (FSR-F40)
    for key_name, key in FSR_AES_CFB_KEYS.items():
        pt = fsr_aes_cfb_decrypt(blob, key)
        if pt and _looks_printable(pt):
            result.update({
                'scheme': 'SCHEME-FSR2 (AES-128-CFB)',
                'key_used': f'{key_name} ({key.decode()})',
                'plaintext': pt.hex(),
                'plaintext_str': pt.decode('utf-8', errors='replace'),
                'success': True,
            })
            return result

    if try_all:
        # Report best attempt even if not clearly printable
        for key_name, key in FSR_AES_CFB_KEYS.items():
            pt = fsr_aes_cfb_decrypt(blob, key)
            if pt:
                result.update({
                    'scheme': 'SCHEME-FSR2 (AES-128-CFB, uncertain)',
                    'key_used': f'{key_name} ({key.decode()})',
                    'plaintext': pt.hex(),
                    'plaintext_str': pt.decode('utf-8', errors='replace'),
                    'success': False,
                })
                break

    return result


def _looks_printable(b: bytes) -> bool:
    """Heuristic: >80% printable ASCII -> likely plaintext."""
    if not b:
        return False
    printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return printable / len(b) > 0.80


def fsr_decrypt_main(args):
    """Entry point for --fortisoar mode."""
    if not HAS_FERNET and not HAS_PYCRYPTO:
        print("[!] Install dependencies: pip install cryptography pycryptodome")
        sys.exit(1)

    blobs = []
    if args.blob:
        blobs.append(('cmdline', args.blob))
    if args.blob_file:
        for line in Path(args.blob_file).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line and len(line.split(':', 1)[0]) < 40:
                label, blob = line.split(':', 1)
                blobs.append((label.strip(), blob.strip()))
            else:
                blobs.append((f'blob_{len(blobs)+1}', line))

    if not blobs:
        print("[!] Provide --blob <token> or --blob-file <file>")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("FortiSOAR Universal Decryption")
    print(f"  FSR-F39 Fernet key: {FSR_FERNET_KEY.decode()}")
    print(f"  FSR-F40 AES-CFB keys: {', '.join(FSR_AES_CFB_KEYS)}")
    print(f"{'='*60}\n")

    report = []
    for label, blob in blobs:
        r = fsr_decrypt_blob(blob, try_all=args.try_all)
        r['label'] = label
        report.append(r)
        status = '[OK]' if r['success'] else '[FAIL]'
        print(f"{status} {label}")
        if r['success'] or args.try_all:
            print(f"  scheme    : {r['scheme']}")
            print(f"  key       : {r['key_used']}")
            print(f"  plaintext : {r['plaintext_str']!r}")
            print(f"  hex       : {r['plaintext']}")
        else:
            print(f"  no scheme matched -- unknown key or format")
        print()

    if args.out_dir:
        Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        rpath = os.path.join(args.out_dir, 'fortisoar_decrypt.json')
        Path(rpath).write_text(json.dumps(report, indent=2))
        print(f"[*] Report -> {rpath}")

    return report


IMAGE_BASE = 0x400000


# ------------------------------------------------------------------ PE parsing
def parse_pe(raw):
    pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
    machine = struct.unpack_from('<H', raw, pe_off + 4)[0]
    num_sec = struct.unpack_from('<H', raw, pe_off + 6)[0]
    opt_sz  = struct.unpack_from('<H', raw, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_sz

    if machine == 0x8664:  # PE32+
        img_base = struct.unpack_from('<Q', raw, pe_off + 24 + 24)[0]
    else:
        img_base = struct.unpack_from('<I', raw, pe_off + 24 + 28)[0]

    sections = {}
    for i in range(num_sec):
        o = sec_off + i * 40
        name = raw[o:o+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', raw, o + 8)
        sections[name] = {'va': va, 'ro': ro, 'vsz': vsz, 'rsz': rsz}

    sym_ptr = struct.unpack_from('<I', raw, pe_off + 12)[0]  # PointerToSymbolTable
    sym_cnt = struct.unpack_from('<I', raw, pe_off + 16)[0]  # NumberOfSymbols
    return img_base, sections, sym_ptr, sym_cnt


def rva_to_file(sections, rva):
    for s in sections.values():
        if s['va'] <= rva < s['va'] + s['vsz']:
            return s['ro'] + (rva - s['va'])
    return None


def va_to_file(img_base, sections, va):
    return rva_to_file(sections, va - img_base)


# ---------------------------------------------------------------- COFF symbols
def scan_coff(raw, sym_ptr, sym_cnt, strtab_off=None):
    """Return dict: symbol_name -> (section_relative_val, section_num)"""
    if sym_ptr == 0 or sym_cnt == 0:
        return {}
    if strtab_off is None:
        strtab_off = sym_ptr + sym_cnt * 18
    results = {}

    for i in range(sym_cnt):
        off = sym_ptr + i * 18
        nb = raw[off:off+8]
        if nb[:4] == b'\x00\x00\x00\x00':
            idx = struct.unpack_from('<I', nb, 4)[0]
            try:
                end = raw.index(b'\x00', strtab_off + idx)
                name = raw[strtab_off + idx:end].decode('utf-8', errors='replace')
            except Exception:
                continue
        else:
            name = nb.rstrip(b'\x00').decode('utf-8', errors='replace')
        val = struct.unpack_from('<I', raw, off + 8)[0]
        sec = struct.unpack_from('<H', raw, off + 12)[0]
        results[name] = (val, sec)

    return results


def resolve_coff_symbols(raw, img_base, sections, sym_ptr, sym_cnt, targets):
    """
    targets: list of (partial_name, human_label)
    Returns dict: human_label -> file_offset (of Go string header in .data)
    """
    strtab_off = sym_ptr + sym_cnt * 18
    coff = scan_coff(raw, sym_ptr, sym_cnt, strtab_off)
    sec_list = list(sections.values())

    def sec_rawoff(sec_num):
        if 1 <= sec_num <= len(sec_list):
            return sec_list[sec_num - 1]['ro'], sec_list[sec_num - 1]['va']
        return None, None

    found = {}
    for partial, label in targets:
        for name, (val, sec) in coff.items():
            if partial in name:
                ro, va = sec_rawoff(sec)
                if ro is not None:
                    file_off = ro + val
                    found[label] = file_off
                    break
    return found


def read_go_string(raw, img_base, sections, hdr_file_off):
    """Read Go string header {ptr uint64, len uint64} and return blob bytes."""
    ptr    = struct.unpack_from('<Q', raw, hdr_file_off)[0]
    length = struct.unpack_from('<Q', raw, hdr_file_off + 8)[0]
    rva    = ptr - img_base
    foff   = rva_to_file(sections, rva)
    if foff and 0 < length < 500_000:
        return raw[foff:foff + length]
    return None


# --------------------------------------------------------------- AES-128-CBC
def aes128_cbc_decrypt(key16, ct, iv=None):
    if not HAS_CRYPTO:
        return None
    if iv is None:
        iv = b'\x00' * 16
    if len(ct) % 16 != 0:
        return None
    cipher = Cipher(algorithms.AES(key16), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        return pt[:-pad]
    return pt


def aes256_cbc_decrypt(key32, ct, iv=None):
    if not HAS_CRYPTO:
        return None
    if iv is None:
        iv = b'\x00' * 16
    if len(ct) % 16 != 0:
        return None
    cipher = Cipher(algorithms.AES(key32), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ------------------------------------------------------ OpenSSL PEM passphrase
def openssl_decrypt_pem(pem_bytes, passphrase_str, out_path):
    """Write pem_bytes to temp file, run openssl rsa, save plaintext key."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as tf:
        tf.write(pem_bytes)
        tmp = tf.name
    try:
        r = subprocess.run(
            ['openssl', 'rsa', '-in', tmp, '-passin', f'pass:{passphrase_str}',
             '-out', out_path],
            capture_output=True, text=True
        )
        return r.returncode == 0, r.stderr.strip()
    finally:
        os.unlink(tmp)


# -------------------------------------------------------------------- main RE
def analyse(path, out_dir, dump_all):
    print(f"[*] Target: {path}")
    raw = Path(path).read_bytes()
    print(f"[*] Size: {len(raw):,} bytes")

    img_base, sections, sym_ptr, sym_cnt = parse_pe(raw)
    strtab_off = sym_ptr + sym_cnt * 18
    print(f"[*] ImageBase=0x{img_base:X}  Sections={len(sections)}")
    print(f"[*] COFF: sym_ptr=0x{sym_ptr:X}  sym_cnt={sym_cnt}  strtab=0x{strtab_off:X}")

    targets = [
        # (partial COFF name,                               human label)
        ('manager.k1',                                      'k1'),
        ('manager.serverKeyEnc',                            'serverKeyEnc'),
        ('manager.serverCrtEnc',                            'serverCrtEnc'),
        ('manager.serverKeyPwd',                            'serverKeyPwd'),
        ('manager.dasSalt',                                 'dasSalt'),
        ('manager.dasCryptKey',                             'dasCryptKey'),
        ('manager.dasEncryptOne',                           'dasEncryptOne'),
        ('update._emsWhiteListHMAC512_Key2',                 'hmac_key2'),
        ('update._emsWhiteListHMAC512_Key3',                 'hmac_key3'),
        ('/common.defaultCertPassEnc',                      'defaultCertPassEnc'),
        ('/common.defaultCertPassKey',                      'defaultCertPassKey'),
        ('/common.defaultKey',                              'defaultKey'),
        ('/common.defaultCert',                             'defaultCert'),
        ('/common.defaultCertPassEnc',                      'defaultCertPassEnc'),
    ]

    print("\n[*] Scanning COFF symbol table...")
    sym_map = resolve_coff_symbols(raw, img_base, sections, sym_ptr, sym_cnt, targets)

    results = {}
    for label, hdr_off in sym_map.items():
        blob = read_go_string(raw, img_base, sections, hdr_off)
        if blob is not None:
            results[label] = blob
            print(f"  {label:30s}  hdr=0x{hdr_off:X}  len={len(blob):5d}  first8={blob[:8].hex()}")
        else:
            print(f"  {label:30s}  hdr=0x{hdr_off:X}  INVALID (Go header ptr out of range)")

    print()
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    report = {}

    # SCHEME-1: XOR passphrase for defaultKey
    if 'defaultCertPassEnc' in results and 'defaultCertPassKey' in results:
        enc = results['defaultCertPassEnc']
        key = results['defaultCertPassKey']
        length = min(len(enc), len(key))
        passphrase = xor_bytes(enc[:length], key[:length])
        passphrase_str = passphrase.decode('utf-8', errors='replace')
        print(f"[SCHEME-1] XOR passphrase for defaultKey: {passphrase_str!r}")
        report['scheme1_xor_passphrase'] = passphrase.hex()
        report['scheme1_passphrase_ascii'] = passphrase_str

        if 'defaultKey' in results:
            pem_bytes = results['defaultKey']
            out_key = os.path.join(out_dir, 'defaultKey_decrypted.pem')
            ok, err = openssl_decrypt_pem(pem_bytes, passphrase_str, out_key)
            print(f"  defaultKey decrypt: {'OK -> ' + out_key if ok else 'FAIL: ' + err}")
            report['scheme1_defaultKey_decrypted'] = out_key if ok else None

    # SCHEME-2+3: k1 AES-128-CBC decryption chain
    k1 = results.get('k1')
    if k1 and len(k1) == 16:
        print(f"\n[SCHEME-2] k1 AES-128 key: {k1.hex()}")
        report['k1'] = k1.hex()

        # Decrypt serverKeyPwd to get DES passphrase
        if 'serverKeyPwd' in results:
            skpwd = results['serverKeyPwd']
            passphrase_bytes = aes128_cbc_decrypt(k1, skpwd)
            if passphrase_bytes:
                passphrase_str = passphrase_bytes.decode('utf-8', errors='replace').rstrip('\x00')
                print(f"[SCHEME-2] serverKeyPwd decrypted passphrase: {passphrase_str!r}")
                report['scheme2_server_key_passphrase'] = passphrase_str
            else:
                passphrase_str = None
                print("[SCHEME-2] serverKeyPwd decryption failed")

            # Decrypt serverKeyEnc (outer AES-128-CBC layer)
            if 'serverKeyEnc' in results:
                outer_pem = aes128_cbc_decrypt(k1, results['serverKeyEnc'])
                if outer_pem and b'-----BEGIN' in outer_pem[:30]:
                    out_pem = os.path.join(out_dir, 'serverKeyEnc_outer.pem')
                    Path(out_pem).write_bytes(outer_pem)
                    print(f"[SCHEME-3] serverKeyEnc outer layer decrypted -> {out_pem}")
                    report['scheme3_outer_pem'] = out_pem

                    if passphrase_str:
                        out_key = os.path.join(out_dir, 'serverKeyEnc_decrypted.key')
                        ok, err = openssl_decrypt_pem(outer_pem, passphrase_str, out_key)
                        print(f"  inner DES-EDE3-CBC decrypt: {'OK -> ' + out_key if ok else 'FAIL: ' + err}")
                        report['scheme3_decrypted_key'] = out_key if ok else None

        # Decrypt serverCrtEnc (certificate text)
        if 'serverCrtEnc' in results:
            crt_text = aes128_cbc_decrypt(k1, results['serverCrtEnc'])
            if crt_text and b'Certificate' in crt_text[:30]:
                out_crt = os.path.join(out_dir, 'serverCrtEnc_decrypted.txt')
                Path(out_crt).write_bytes(crt_text)
                print(f"[SCHEME-3] serverCrtEnc decrypted (cert text) -> {out_crt}")
                report['scheme3_cert_text'] = out_crt

    # SCHEME-4: HMAC-512 hardcoded keys (raw ASCII, no decryption)
    for key_label in ['hmac_key2', 'hmac_key3']:
        if key_label in results:
            blob = results[key_label]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in blob)
            print(f"[SCHEME-4] {key_label} ({len(blob)} bytes): {printable!r}")
            report[key_label] = blob.decode('utf-8', errors='replace')

    # SCHEME-5: dasSalt (for DAS channel key derivation context)
    if 'dasSalt' in results:
        print(f"[SCHEME-5] dasSalt ({len(results['dasSalt'])} bytes): {results['dasSalt'].hex()}")
        report['dasSalt'] = results['dasSalt'].hex()

    # Dump all raw blobs if requested
    if dump_all:
        for label, blob in results.items():
            out_blob = os.path.join(out_dir, f'raw_{label}.bin')
            Path(out_blob).write_bytes(blob)
            print(f"[DUMP] {label} -> {out_blob}")

    # Write JSON report
    report_path = os.path.join(out_dir, 'report.json')
    Path(report_path).write_text(json.dumps(report, indent=2))
    print(f"\n[*] Report -> {report_path}")
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Fortinet universal decryption tool (EMS + FortiSOAR)')
    ap.add_argument('binary', nargs='?', help='Path to FortiClient EMS Go binary (e.g. ecsocksrv.exe)')
    ap.add_argument('--out-dir', default='/tmp/fortinet_decrypt_out', help='Output directory')
    ap.add_argument('--dump-all', action='store_true', help='Dump all raw blobs to out-dir (EMS mode)')

    # FortiSOAR mode
    ap.add_argument('--fortisoar', action='store_true',
                    help='FortiSOAR decrypt mode (FSR-F39 Fernet + FSR-F40 AES-CFB)')
    ap.add_argument('--blob', metavar='B64',
                    help='Single base64 ciphertext blob to decrypt (FortiSOAR)')
    ap.add_argument('--blob-file', metavar='FILE',
                    help='File of blobs to decrypt, one per line or label:blob format')
    ap.add_argument('--try-all', action='store_true',
                    help='Try all known keys even if auto-detect fails')
    ap.add_argument('--keys', action='store_true',
                    help='Print all known FortiSOAR hardcoded keys and exit')

    args = ap.parse_args()

    if args.keys:
        print(f"FSR-F39 Fernet key (encrypt_decrypt_util.so, workflow secrets):")
        print(f"  {FSR_FERNET_KEY.decode()}")
        print(f"\nFSR-F40 AES-128-CFB keys (PasswordModule.so, connector credentials):")
        for name, key in FSR_AES_CFB_KEYS.items():
            print(f"  {name}: {key.decode()}")
        sys.exit(0)

    if args.fortisoar or args.blob or args.blob_file:
        fsr_decrypt_main(args)
    elif args.binary:
        analyse(args.binary, args.out_dir, args.dump_all)
    else:
        ap.print_help()
