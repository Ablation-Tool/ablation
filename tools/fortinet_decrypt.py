#!/usr/bin/env python3
"""
Fortinet Go PE32+ Universal Decryption Tool
Target: FortiClient EMS 7.2.9 and related binaries (ecsocksrv.exe, regworker.exe, ...)
Method: COFF symbol table scan + Go string header parsing + multi-scheme decryption

Schemes implemented:
  SCHEME-1  XOR passphrase: defaultCertPassEnc XOR defaultCertPassKey -> AES-256-CBC PEM passphrase
  SCHEME-2  AES-128-CBC passphrase decrypt: AES128CBC(k1, IV=zeros, serverKeyPwd) -> DES passphrase
  SCHEME-3  AES-128-CBC blob decrypt: AES128CBC(k1, IV=zeros, serverKeyEnc) -> DES-EDE3-CBC PEM
  SCHEME-4  HMAC-512 key extraction: raw ASCII from global (no decryption needed)
  SCHEME-5  JWT signing keys: same as SCHEME-4

Usage:
  python3 fortinet_decrypt.py <binary.exe> [--dump-all] [--out-dir /tmp/out]
"""

import struct, sys, os, hashlib, subprocess, argparse, json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[!] cryptography not installed -- decryption disabled (pip install cryptography)")


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
    ap = argparse.ArgumentParser(description='Fortinet Go PE32+ universal decryption tool')
    ap.add_argument('binary', help='Path to Fortinet Go binary (e.g. ecsocksrv.exe)')
    ap.add_argument('--out-dir', default='/tmp/fortinet_decrypt_out', help='Output directory')
    ap.add_argument('--dump-all', action='store_true', help='Dump all raw blobs to out-dir')
    args = ap.parse_args()
    analyse(args.binary, args.out_dir, args.dump_all)
