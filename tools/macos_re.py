#!/usr/bin/env python3
"""
macos_re.py — macOS Mach-O binary RE tool
Mach-O analysis using LIEF + capstone. Targets: NE framework, VPN daemons, LINA connection search.
Usage: python3 macos_re.py <binary_path> [--json] [--lina] [--objc] [--disasm ADDR:N]
"""

import sys, json, struct, os, re, argparse
from pathlib import Path

try:
    import lief
except ImportError:
    sys.exit("pip install lief")
try:
    import capstone
except ImportError:
    sys.exit("pip install capstone")

# ─── LINA signatures to hunt for (from ASA 9.22.2.32 RE) ────────────────────
LINA_SIGS = {
    'jwt_key':         b'\x9c\x42\xf9\xfd\x11\xa9\xfc\xfc\x26\xb5\xbc\x53\x25\xfd\x51\xc5',
    'cstp_magic':      b'\x53\x54\x46\x01',          # STF\x01 — CSTP header
    'x_dtls_hdr':      b'X-DTLS-Master-Secret',
    'x_cstp_hdr':      b'X-CSTP-',
    'cisco_ssl':       b'CiscoSSL',
    'cstrap':          b'CStrapMgr',
    'ac_strap':        b'ac_strap.dat',
    'hpke_decrypt':    b'decryptHPKEMessage',
    'msg_auth':        b'Message-Authenticator',
    'dtls1_get_rec':   b'dtls1_get_record',
    'ssl3_read_bytes': b'ssl3_read_bytes',
    'aes_cbc_cipher':  b'AES-128-CBC',
    'hmac_sha1':       b'HMAC-SHA1',
}

# ─── Cisco co-design artifacts (from NE framework binary RE) ─────────────────
CISCO_ARTIFACTS = {
    'team_id':       b'DE8Y96K9QP',
    'bundle_ne':     b'com.cisco.anyconnect.macosext.networkextension',
    'bundle_kext':   b'com.cisco.kext.acsock',
    'bundle_sysext': b'com.cisco.anyconnect.macos.acsockext',
    'bundle_plugin': b'com.cisco.anyconnect.applevpn.plugin',
    'bug_cscvq':     b'CSCvq',
}

# ─── Protocol overlap patterns (CSTP / IKE / LINA) ──────────────────────────
PROTO_OVERLAP = {
    'xauth_name':    b'XAuthName',
    'xauth_pass':    b'XAuthPassword',
    'securid':       b'securID',
    'cryptocard':    b'cryptocard',
    'mobike':        b'MOBIKE',
    'modp768':       b'MODP768',
    'chacha20':      b'ChaCha20Poly1305',
    'racoon':        b'racoon',
    'pppd':          b'pppd',
    'rsasecurid':    b'RSASecurID',
    'rsa_dhparams':  b'RSASecurID_DHParams',
    'var_ace':       b'/var/ace',
}


def parse_macho(path):
    """Full LIEF parse of a Mach-O binary."""
    binary = lief.parse(str(path))
    if binary is None:
        return None
    return binary


def section_bytes(binary, segname, sectname):
    """Return raw bytes of a named section."""
    for s in binary.sections:
        if s.segment_name.strip('\x00') == segname and s.name.strip('\x00') == sectname:
            return bytes(s.content)
    return b''


def hunt_patterns(raw, patterns, label):
    """Search raw bytes for all patterns in dict. Returns findings list."""
    findings = []
    for name, pat in patterns.items():
        off = 0
        while True:
            idx = raw.find(pat, off)
            if idx < 0:
                break
            context = raw[max(0,idx-16):idx+len(pat)+32]
            findings.append({
                'pattern': name,
                'offset': hex(idx),
                'context_hex': context.hex(),
                'context_str': context.decode('ascii', errors='replace'),
            })
            off = idx + 1
    return findings


def objc_classes(binary):
    """Extract ObjC class names and method lists from __objc_classlist."""
    classes = []
    methnames_raw = section_bytes(binary, '__TEXT', '__objc_methname')
    classnames_raw = section_bytes(binary, '__TEXT', '__objc_classname')

    # Extract class names from classname section
    cnames = [n.decode('ascii', 'replace') for n in classnames_raw.split(b'\x00') if n]
    # Extract method names from methname section
    mnames = [n.decode('ascii', 'replace') for n in methnames_raw.split(b'\x00') if n]

    return {
        'class_names': cnames,
        'class_count': len(cnames),
        'method_names': mnames,
        'method_count': len(mnames),
    }


def symbol_dump(binary, filter_re=None):
    """All defined symbols, optionally filtered."""
    syms = []
    for s in binary.symbols:
        if s.value == 0:
            continue
        name = s.name
        if filter_re and not re.search(filter_re, name, re.IGNORECASE):
            continue
        syms.append({'addr': hex(s.value), 'name': name})
    return syms


def imports(binary):
    """Undefined (imported) symbols — what this binary calls."""
    return [s.name for s in binary.symbols if s.value == 0 and s.name]


def sections_summary(binary):
    """Section map with sizes."""
    return [
        {'seg': s.segment_name.strip('\x00'), 'name': s.name.strip('\x00'),
         'offset': hex(s.offset), 'size': s.size}
        for s in binary.sections if s.size > 0
    ]


def disassemble(binary, vaddr, count=50, raw=None):
    """Disassemble `count` instructions at virtual address `vaddr`.

    Pass raw=<file bytes> for correct results on high-VA addresses.
    Fallback to LIEF segment content works for addresses < first segment file_offset limit.
    """
    file_bytes = b''
    for seg in binary.segments:
        if seg.virtual_address <= vaddr < seg.virtual_address + seg.virtual_size:
            rel_off = vaddr - seg.virtual_address
            if raw is not None:
                # Direct file read via file_offset: correct for all addresses in segment
                file_off = seg.file_offset + rel_off
                file_bytes = raw[file_off:]
            else:
                seg_data = bytes(seg.content)
                file_bytes = seg_data[rel_off:]
            break
    if not file_bytes:
        return [{'error': f'vaddr {hex(vaddr)} not found in any segment'}]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    results = []
    for insn in md.disasm(file_bytes, vaddr):
        results.append({
            'addr': hex(insn.address),
            'mnemonic': insn.mnemonic,
            'op_str': insn.op_str,
        })
        if len(results) >= count:
            break
    return results


def strings_section(binary, min_len=8):
    """Extract printable strings from __cstring and __oslogstring sections."""
    out = []
    for sectname in ('__cstring', '__oslogstring'):
        raw = section_bytes(binary, '__TEXT', sectname)
        for s in raw.split(b'\x00'):
            if len(s) >= min_len:
                try:
                    out.append(s.decode('ascii'))
                except Exception:
                    pass
    return out


def cfstrings(binary):
    """Parse __DATA,__cfstring to get CFStringRef literals with their offsets."""
    raw = section_bytes(binary, '__DATA', '__cfstring')
    if not raw:
        return []
    results = []
    # CFStringRef: isa(8), flags(8), data_ptr(8), len(8)
    entry_size = 32
    # Get __cstring base for pointer math
    cstring_off = 0
    cstring_raw = b''
    for s in binary.sections:
        if s.segment_name.strip('\x00') == '__TEXT' and s.name.strip('\x00') == '__cstring':
            cstring_off = s.virtual_address
            cstring_raw = bytes(s.content)
            break

    cfstring_va = 0
    for s in binary.sections:
        if s.segment_name.strip('\x00') == '__DATA' and s.name.strip('\x00') == '__cfstring':
            cfstring_va = s.virtual_address
            break

    for i in range(0, len(raw) - entry_size + 1, entry_size):
        entry = raw[i:i+entry_size]
        isa, flags, data_ptr, length = struct.unpack('<QQQQ', entry)
        if cstring_off and data_ptr >= cstring_off:
            str_off = data_ptr - cstring_off
            if str_off < len(cstring_raw):
                s = cstring_raw[str_off:str_off+length]
                try:
                    results.append({
                        'va': hex(cfstring_va + i),
                        'str': s.decode('ascii', 'replace'),
                    })
                except Exception:
                    pass
    return results


def analyze(path, args):
    raw = Path(path).read_bytes()
    binary = parse_macho(path)
    if not binary:
        return {'error': f'LIEF could not parse {path}'}

    result = {
        'path': str(path),
        'size': len(raw),
        'format': str(binary.format),
        'cpu': str(binary.header.cpu_type),
    }

    # Sections
    result['sections'] = sections_summary(binary)

    # Imports (what it calls)
    imp = imports(binary)
    result['imports_count'] = len(imp)
    result['imports_sample'] = imp[:40]

    # Symbol stats
    all_syms = symbol_dump(binary)
    result['symbols_defined'] = len(all_syms)
    result['symbols_sample'] = all_syms[:20]

    # ObjC introspection
    if args.objc or args.all:
        oc = objc_classes(binary)
        result['objc'] = oc
        # Flag interesting classes
        interesting = [c for c in oc['class_names']
                       if any(kw in c.lower() for kw in
                              ('ike', 'ipsec', 'vpn', 'tunnel', 'packet', 'session',
                               'cisco', 'plugin', 'extension', 'agent', 'filter',
                               'auth', 'cert', 'key', 'credential'))]
        result['objc_interesting_classes'] = interesting

    # LINA signature hunt
    lina_hits = hunt_patterns(raw, LINA_SIGS, 'LINA')
    result['lina_hits'] = lina_hits
    result['lina_verdict'] = 'HIT' if lina_hits else 'CLEAN'

    # Cisco co-design artifacts
    cisco_hits = hunt_patterns(raw, CISCO_ARTIFACTS, 'Cisco')
    result['cisco_artifacts'] = cisco_hits

    # Protocol overlap (XAUTH, SecurID, MOBIKE, etc.)
    proto_hits = hunt_patterns(raw, PROTO_OVERLAP, 'Proto')
    result['protocol_overlap'] = proto_hits

    # Strings
    if args.strings or args.all:
        strs = strings_section(binary)
        result['strings_count'] = len(strs)
        # Categorized
        result['strings_vpn'] = [s for s in strs if any(kw in s.lower() for kw in
            ('vpn', 'tunnel', 'cstp', 'dtls', 'ike', 'ipsec', 'cisco'))]
        result['strings_crypto'] = [s for s in strs if any(kw in s.lower() for kw in
            ('aes', 'hmac', 'sha', 'rsa', 'ecdh', 'dh-group', 'modp', 'chacha',
             'nonce', 'iv ', 'salt', 'cipher', 'key '))]
        result['strings_auth'] = [s for s in strs if any(kw in s.lower() for kw in
            ('password', 'credential', 'keychain', 'certificate', 'xauth',
             'securid', 'radius', 'eap', 'token'))]

    # CFStrings (faster than full string scan for ObjC binaries)
    if args.cfstrings or args.all:
        cf = cfstrings(binary)
        result['cfstrings_count'] = len(cf)
        result['cfstrings_sample'] = cf[:30]

    # Disassembly — pass raw bytes for correct VA→file-offset mapping on all addresses
    if args.disasm:
        parts = args.disasm.split(':')
        vaddr = int(parts[0], 16)
        count = int(parts[1]) if len(parts) > 1 else 50
        result['disasm'] = disassemble(binary, vaddr, count, raw=raw)

    # Symbol filter
    if args.sym_filter:
        result['sym_filter_results'] = symbol_dump(binary, args.sym_filter)

    return result


def format_text(result):
    """Human-readable output."""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"BINARY: {result.get('path')}")
    lines.append(f"  Size: {result.get('size',0):,} bytes")
    lines.append(f"  CPU:  {result.get('cpu')}")
    lines.append(f"  Symbols defined: {result.get('symbols_defined',0)}")

    lina = result.get('lina_hits', [])
    lines.append(f"\n  LINA VERDICT: {result.get('lina_verdict')} ({len(lina)} hits)")
    for h in lina:
        lines.append(f"    [{h['pattern']}] @ {h['offset']}  {h['context_str'][:60]}")

    cisco = result.get('cisco_artifacts', [])
    lines.append(f"\n  Cisco artifacts: {len(cisco)}")
    for h in cisco[:10]:
        lines.append(f"    [{h['pattern']}] @ {h['offset']}  {h['context_str'][:60]}")

    proto = result.get('protocol_overlap', [])
    lines.append(f"\n  Protocol overlaps: {len(proto)}")
    for h in proto[:15]:
        lines.append(f"    [{h['pattern']}] @ {h['offset']}  {h['context_str'][:60]}")

    oc = result.get('objc', {})
    if oc:
        lines.append(f"\n  ObjC classes: {oc.get('class_count',0)}, methods: {oc.get('method_count',0)}")
        ic = result.get('objc_interesting_classes', [])
        lines.append(f"  Security-relevant classes ({len(ic)}):")
        for c in ic[:30]:
            lines.append(f"    {c}")

    syms = result.get('sym_filter_results', [])
    if syms:
        lines.append(f"\n  Filtered symbols ({len(syms)}):")
        for s in syms[:40]:
            lines.append(f"    {s['addr']}  {s['name']}")

    disasm = result.get('disasm', [])
    if disasm:
        lines.append(f"\n  Disassembly:")
        for insn in disasm:
            if 'error' in insn:
                lines.append(f"    ERROR: {insn['error']}")
            else:
                lines.append(f"    {insn['addr']:22}  {insn['mnemonic']:8} {insn['op_str']}")

    strs_vpn = result.get('strings_vpn', [])
    if strs_vpn:
        lines.append(f"\n  VPN strings ({len(strs_vpn)}):")
        for s in strs_vpn[:20]:
            lines.append(f"    {s}")

    strs_auth = result.get('strings_auth', [])
    if strs_auth:
        lines.append(f"\n  Auth strings ({len(strs_auth)}):")
        for s in strs_auth[:20]:
            lines.append(f"    {s}")

    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser(description='macos_re — Mach-O RE tool (LIEF+capstone)')
    ap.add_argument('binary', help='Path to Mach-O binary')
    ap.add_argument('--json', action='store_true', help='JSON output')
    ap.add_argument('--lina', action='store_true', help='LINA signature hunt only')
    ap.add_argument('--objc', action='store_true', help='ObjC class/method dump')
    ap.add_argument('--strings', action='store_true', help='String extraction')
    ap.add_argument('--cfstrings', action='store_true', help='CFString literals')
    ap.add_argument('--disasm', metavar='ADDR[:N]', help='Disassemble N insns at hex ADDR')
    ap.add_argument('--sym-filter', dest='sym_filter', metavar='REGEX', help='Filter symbols by regex')
    ap.add_argument('--all', action='store_true', help='All analysis passes')
    ap.add_argument('--out', metavar='FILE', help='Write JSON output to file')
    args = ap.parse_args()

    result = analyze(args.binary, args)

    if args.json or args.out:
        out = json.dumps(result, indent=2, default=str)
        if args.out:
            Path(args.out).write_text(out)
            print(f"Written to {args.out}")
        else:
            print(out)
    else:
        print(format_text(result))


if __name__ == '__main__':
    main()
