#!/usr/bin/env python3
"""
Firmware Analyzer Module
Synthesized from: Practical IoT Hacking (Ch. 9 Firmware Hacking, Ch. 7 UART/JTAG Exploitation)

Static analysis for embedded firmware images: filesystem signature scanning,
hardcoded credential extraction, entropy-based section classification, and
supply chain component version detection. Pure stdlib — no external dependencies.
"""

import re
import math
import struct
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Magic byte registry -> filesystem / compression type
# Ordered longest-match first to avoid prefix collisions.
# ---------------------------------------------------------------------------
FIRMWARE_MAGIC: dict[bytes, str] = {
    # Filesystem types
    b'\x73\x71\x73\x68': 'SquashFS_LE',       # sqsh LE v4
    b'\x68\x73\x71\x73': 'SquashFS_BE',       # hsqs BE v4
    b'\x71\x73\x71\x73': 'SquashFS_LEv3',     # qsqs LE v3
    b'\x73\x71\x73\x68': 'SquashFS_LE',       # duplicate guard
    b'\x55\x42\x49\x23': 'UBI',               # UBI volume image
    b'\x31\x18\x00\x00': 'JFFS2_LE',          # JFFS2 little-endian
    b'\x00\x00\x18\x31': 'JFFS2_BE',          # JFFS2 big-endian
    b'\x19\x85':         'JFFS2',             # generic JFFS2 marker
    b'070701':           'CPIO_newc',          # CPIO new ASCII (newc)
    b'070707':           'CPIO_odc',           # CPIO old ASCII
    b'070702':           'CPIO_newcCRC',       # CPIO newc with CRC
    # Archive / compression types
    b'PK\x03\x04':       'ZIP/APK',
    b'\x1f\x8b':         'gzip',
    b'BZh':              'bzip2',
    b'\xfd7zXZ\x00':     'xz',
    b'\xfd7zXZ':         'xz',
    b'\xd7\xc3\xab\x1e': 'LZMA_alone',        # raw LZMA (alone format)
    b'\x5d\x00\x00':     'LZMA',              # LZMA properties byte
    b'\x04\x22\x4d\x18': 'LZ4',
    b'\x28\xb5\x2f\xfd': 'zstd',
    # Executable / OS formats relevant inside firmware
    b'\x7fELF':          'ELF',
    b'uImage':           'uboot_legacy',       # U-Boot legacy image header
    b'\x27\x05\x19\x56': 'uboot_image',        # U-Boot magic
    b'\xd0\x0d\xfe\xed': 'FDT/DTB',           # Flattened Device Tree blob
    b'ANDROID!':         'Android_boot',
    b'\x41\x4e\x44\x52\x4f\x49\x44\x21': 'Android_boot',
}

# Filesystem types that mean "filesystem found = extractable content"
_EXTRACTABLE_FS = frozenset({
    'SquashFS_LE', 'SquashFS_BE', 'SquashFS_LEv3',
    'JFFS2', 'JFFS2_LE', 'JFFS2_BE',
    'UBI',
    'CPIO_newc', 'CPIO_odc', 'CPIO_newcCRC',
})

# Pre-sorted by descending key length for greedy match
_MAGIC_SORTED = sorted(FIRMWARE_MAGIC.items(), key=lambda kv: len(kv[0]), reverse=True)
_MAX_KEY_LEN = max(len(k) for k in FIRMWARE_MAGIC)


# ---------------------------------------------------------------------------
# 1. Signature scanning
# ---------------------------------------------------------------------------

def scan_firmware_signatures(data: bytes) -> list:
    """
    Walk every byte offset, match against FIRMWARE_MAGIC.

    Returns list of dicts, max 100 hits, sorted by offset:
        {'offset': int, 'type': str, 'severity': 'HIGH'|'LOW'}

    Severity HIGH: extractable filesystem (SquashFS, CPIO, JFFS2, UBI)
    Severity LOW: compression wrappers, executables, misc
    """
    hits = []
    seen_offsets: set[int] = set()
    limit = len(data)

    for offset in range(limit):
        if offset in seen_offsets:
            continue
        window = data[offset:offset + _MAX_KEY_LEN]
        for magic, fs_type in _MAGIC_SORTED:
            mlen = len(magic)
            if window[:mlen] == magic:
                severity = 'HIGH' if fs_type in _EXTRACTABLE_FS else 'LOW'
                hits.append({
                    'offset': offset,
                    'type': fs_type,
                    'severity': severity,
                })
                # skip past this match to reduce redundant hits at same region
                for skip in range(offset, min(offset + mlen, limit)):
                    seen_offsets.add(skip)
                break  # longest-match wins; don't double-report same offset

        if len(hits) >= 100:
            break

    return hits


# ---------------------------------------------------------------------------
# 2. String and credential extraction
# ---------------------------------------------------------------------------

# Compiled patterns — all bytes-level where applied against raw data slices
_RE_PASSWORD   = re.compile(rb'(?i)password\s*[=:]\s*(\S+)')
_RE_API_LINE   = re.compile(rb'(?i)(?:token|key|secret|api)[^\n]{0,80}')
_RE_TOKEN_VAL  = re.compile(rb'[A-Za-z0-9_\-]{32,64}')
_RE_IP         = re.compile(rb'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_RE_URL        = re.compile(rb'https?://[^\s<>\'"]{8,200}')
_RE_PASSWD_ENT = re.compile(rb'[a-z_][a-z0-9_\-]{0,30}:[^:\n]{0,60}:\d+:\d+:')
_RE_BUSYBOX    = re.compile(rb'BusyBox v(\d+\.\d+[\.\d]*)')
_RE_OPENSSL    = re.compile(rb'OpenSSL (\d+\.\d+[\.\w]+)')
_RE_KERNEL     = re.compile(rb'Linux version (\d+\.\d+[\.\d\-\w]+)')
_RE_TELNET_MSG = re.compile(rb'(?i)telnet[d]?\b')
_RE_BACKDOOR   = re.compile(rb'(?i)(?:bind.?shell|backdoor|nc\s+-l|netcat\s+-l)')

_PEM_MARKERS = [
    b'-----BEGIN RSA PRIVATE KEY-----',
    b'-----BEGIN PRIVATE KEY-----',
    b'-----BEGIN EC PRIVATE KEY-----',
    b'-----BEGIN DSA PRIVATE KEY-----',
    b'-----BEGIN OPENSSH PRIVATE KEY-----',
]


def _extract_printable_strings(data: bytes, min_length: int) -> list[bytes]:
    """Extract contiguous printable ASCII runs of at least min_length bytes."""
    strings: list[bytes] = []
    buf: list[int] = []
    for b in data:
        if 0x20 <= b <= 0x7e:
            buf.append(b)
        else:
            if len(buf) >= min_length:
                strings.append(bytes(buf))
            buf = []
    if len(buf) >= min_length:
        strings.append(bytes(buf))
    return strings


def extract_firmware_strings(data: bytes, min_length: int = 8) -> dict:
    """
    Extract security-relevant strings from raw firmware bytes.

    Returns:
        {
          'passwords':      [str, ...],   # password=value occurrences
          'private_keys':   [str, ...],   # PEM private key markers
          'api_tokens':     [str, ...],   # 32-64 char tokens near key/secret/api
          'ips':            [str, ...],   # IPv4 addresses
          'urls':           [str, ...],   # http/https URLs
          'passwd_entries': [str, ...],   # /etc/passwd-format lines
          'supply_chain':   dict,         # component versions
          'debug_strings':  [str, ...],   # telnet / backdoor indicators
        }
    """
    passwords: list[str] = []
    private_keys: list[str] = []
    api_tokens: list[str] = []
    ips: list[str] = []
    urls: list[str] = []
    passwd_entries: list[str] = []
    supply_chain: dict[str, list[str]] = {
        'busybox': [],
        'openssl': [],
        'kernel': [],
    }
    debug_strings: list[str] = []

    # PEM private key scan (full data)
    for marker in _PEM_MARKERS:
        idx = 0
        while True:
            pos = data.find(marker, idx)
            if pos == -1:
                break
            private_keys.append(f'offset=0x{pos:08x} marker={marker.decode(errors="replace")}')
            idx = pos + len(marker)

    # Supply chain version strings
    for m in _RE_BUSYBOX.finditer(data):
        ver = m.group(1).decode(errors='replace')
        if ver not in supply_chain['busybox']:
            supply_chain['busybox'].append(ver)

    for m in _RE_OPENSSL.finditer(data):
        ver = m.group(1).decode(errors='replace')
        if ver not in supply_chain['openssl']:
            supply_chain['openssl'].append(ver)

    for m in _RE_KERNEL.finditer(data):
        ver = m.group(1).decode(errors='replace')
        if ver not in supply_chain['kernel']:
            supply_chain['kernel'].append(ver)

    # Debug / backdoor indicators
    for m in _RE_TELNET_MSG.finditer(data):
        ctx_start = max(0, m.start() - 20)
        ctx = data[ctx_start:m.end() + 40].decode(errors='replace').replace('\n', ' ')
        debug_strings.append(f'telnet_ref offset=0x{m.start():08x} ctx={ctx!r}')

    for m in _RE_BACKDOOR.finditer(data):
        ctx_start = max(0, m.start() - 10)
        ctx = data[ctx_start:m.end() + 30].decode(errors='replace').replace('\n', ' ')
        debug_strings.append(f'backdoor_ref offset=0x{m.start():08x} ctx={ctx!r}')

    # Pattern scan over printable strings
    printable = _extract_printable_strings(data, min_length)
    seen_ips: set[str] = set()
    seen_urls: set[str] = set()
    seen_passwd: set[str] = set()

    for s in printable:
        # Passwords
        for m in _RE_PASSWORD.finditer(s):
            val = m.group(0).decode(errors='replace')
            if val not in passwords:
                passwords.append(val)

        # API tokens
        for m in _RE_API_LINE.finditer(s):
            line = m.group(0)
            for tm in _RE_TOKEN_VAL.finditer(line):
                token = tm.group(0).decode(errors='replace')
                if token not in api_tokens:
                    api_tokens.append(token)

        # /etc/passwd entries
        for m in _RE_PASSWD_ENT.finditer(s):
            entry = m.group(0).decode(errors='replace')
            if entry not in seen_passwd:
                seen_passwd.add(entry)
                passwd_entries.append(entry)

    # IP addresses — scan full data (also binary context)
    for m in _RE_IP.finditer(data):
        ip = m.group(1).decode()
        if ip not in seen_ips and not ip.startswith('0.') and ip != '255.255.255.255':
            # Validate octets
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                seen_ips.add(ip)
                ips.append(ip)

    # URLs — scan full data
    for m in _RE_URL.finditer(data):
        url = m.group(0).decode(errors='replace')
        if url not in seen_urls:
            seen_urls.add(url)
            urls.append(url)

    return {
        'passwords':      passwords,
        'private_keys':   private_keys,
        'api_tokens':     api_tokens,
        'ips':            ips,
        'urls':           urls,
        'passwd_entries': passwd_entries,
        'supply_chain':   supply_chain,
        'debug_strings':  debug_strings,
    }


# ---------------------------------------------------------------------------
# 3. Entropy analysis
# ---------------------------------------------------------------------------

def _shannon_entropy(block: bytes) -> float:
    """Shannon entropy (bits per byte) of a byte sequence."""
    if not block:
        return 0.0
    counts: dict[int, int] = {}
    for b in block:
        counts[b] = counts.get(b, 0) + 1
    length = len(block)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _entropy_type(entropy: float) -> str:
    if entropy > 7.0:
        return 'compressed/encrypted'
    elif entropy >= 5.0:
        return 'data'
    else:
        return 'code/text'


def analyze_firmware_entropy(data: bytes, block_size: int = 1024) -> list:
    """
    Compute Shannon entropy per block, return only section-boundary blocks.

    A block is returned when its entropy differs from its neighbor by > 1.0
    (indicating a transition between regions of different content type).

    Returns list of dicts:
        {'offset': int, 'entropy': float, 'type': str}

    Types: 'compressed/encrypted' (>7.0), 'data' (5.0-7.0), 'code/text' (<5.0)
    """
    if not data:
        return []

    total = len(data)
    block_count = (total + block_size - 1) // block_size

    entropies: list[tuple[int, float]] = []
    for i in range(block_count):
        offset = i * block_size
        block = data[offset:offset + block_size]
        h = _shannon_entropy(block)
        entropies.append((offset, h))

    if len(entropies) == 0:
        return []

    result = []

    # Always include first block
    offset0, h0 = entropies[0]
    result.append({'offset': offset0, 'entropy': round(h0, 4), 'type': _entropy_type(h0)})

    for i in range(1, len(entropies)):
        prev_offset, prev_h = entropies[i - 1]
        curr_offset, curr_h = entropies[i]
        if abs(curr_h - prev_h) > 1.0:
            result.append({
                'offset': curr_offset,
                'entropy': round(curr_h, 4),
                'type': _entropy_type(curr_h),
            })

    # Always include last block if not already included
    last_offset, last_h = entropies[-1]
    if not result or result[-1]['offset'] != last_offset:
        result.append({'offset': last_offset, 'entropy': round(last_h, 4), 'type': _entropy_type(last_h)})

    return result


# ---------------------------------------------------------------------------
# 4. Backdoor account detection
# ---------------------------------------------------------------------------

def _detect_backdoor_accounts(passwd_entries: list[str]) -> list[str]:
    """
    Flag passwd entries with uid=0 but username != 'root' (hidden root).
    Pattern: username:hash:0:0:...
    """
    backdoors = []
    re_uid0 = re.compile(r'^([^:]+):[^:]*:0:0:')
    for entry in passwd_entries:
        m = re_uid0.match(entry)
        if m:
            username = m.group(1)
            if username != 'root':
                backdoors.append(f'uid=0 non-root account: {entry.strip()}')
    return backdoors


# ---------------------------------------------------------------------------
# 5. Top-level file scanner
# ---------------------------------------------------------------------------

def scan_firmware_file(filepath: str) -> dict:
    """
    Read a firmware image, run all analysis stages.

    Returns:
        {
          'filepath':        str,
          'size':            int,
          'signatures':      list,   # from scan_firmware_signatures
          'strings':         dict,   # from extract_firmware_strings
          'entropy_sections': list,  # from analyze_firmware_entropy
          'findings':        list,   # consolidated CRITICAL/HIGH findings
        }

    Finding severity:
        CRITICAL: private key PEM marker found
        HIGH: hardcoded password found
        HIGH: extractable filesystem (SquashFS/CPIO/JFFS2/UBI) found
        HIGH: backdoor account (uid=0, username != root)
        MEDIUM: known vulnerable component version string
        LOW: telnetd reference / bind-shell debug string
    """
    fp = Path(filepath)
    if not fp.exists():
        raise FileNotFoundError(f'firmware not found: {filepath}')

    with open(fp, 'rb') as fh:
        data = fh.read()

    size = len(data)

    signatures   = scan_firmware_signatures(data)
    strings      = extract_firmware_strings(data)
    entropy_secs = analyze_firmware_entropy(data)

    findings: list[dict] = []

    # CRITICAL: PEM private keys
    for pk in strings['private_keys']:
        findings.append({
            'severity': 'CRITICAL',
            'category': 'private_key',
            'detail':   pk,
        })

    # HIGH: hardcoded passwords
    for pw in strings['passwords']:
        findings.append({
            'severity': 'HIGH',
            'category': 'hardcoded_password',
            'detail':   pw,
        })

    # HIGH: extractable filesystems
    fs_found: set[str] = set()
    for sig in signatures:
        if sig['severity'] == 'HIGH' and sig['type'] not in fs_found:
            fs_found.add(sig['type'])
            findings.append({
                'severity': 'HIGH',
                'category': 'extractable_filesystem',
                'detail':   f'{sig["type"]} at offset 0x{sig["offset"]:08x}',
            })

    # HIGH: backdoor accounts (uid=0, non-root)
    backdoors = _detect_backdoor_accounts(strings['passwd_entries'])
    for bd in backdoors:
        findings.append({
            'severity': 'HIGH',
            'category': 'backdoor_account',
            'detail':   bd,
        })

    # MEDIUM: supply chain component versions (flagged as informational/medium)
    sc = strings['supply_chain']
    for component, versions in sc.items():
        for ver in versions:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'supply_chain_component',
                'detail':   f'{component} version {ver}',
            })

    # LOW: debug / telnet / backdoor string references
    for ds in strings['debug_strings']:
        findings.append({
            'severity': 'LOW',
            'category': 'debug_string',
            'detail':   ds,
        })

    return {
        'filepath':         str(fp.resolve()),
        'size':             size,
        'signatures':       signatures,
        'strings':          strings,
        'entropy_sections': entropy_secs,
        'findings':         findings,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 2:
        print('Usage: firmware_analyzer.py <firmware_file> [--json]')
        sys.exit(1)

    target = sys.argv[1]
    as_json = '--json' in sys.argv

    try:
        result = scan_firmware_file(target)
    except FileNotFoundError as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print(f'File:  {result["filepath"]}')
        print(f'Size:  {result["size"]:,} bytes')
        print(f'\nSignatures ({len(result["signatures"])} hits):')
        for sig in result['signatures'][:20]:
            print(f'  0x{sig["offset"]:08x}  [{sig["severity"]:4s}]  {sig["type"]}')
        if len(result['signatures']) > 20:
            print(f'  ... and {len(result["signatures"]) - 20} more')

        print(f'\nEntropy sections ({len(result["entropy_sections"])} transitions):')
        for es in result['entropy_sections'][:10]:
            bar = '#' * int(es['entropy'])
            print(f'  0x{es["offset"]:08x}  H={es["entropy"]:.4f}  [{es["type"]}]  {bar}')

        print(f'\nFindings ({len(result["findings"])} total):')
        for finding in result['findings']:
            print(f'  [{finding["severity"]:8s}] {finding["category"]}: {finding["detail"][:100]}')
