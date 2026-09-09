"""
axis_os_firmware_re — AXIS OS firmware binary RE module (ARM32 Thumb)

Targets: P3245-V_11_11_220.bin extracted rootfs (ARTPEC-7, armhf)
Binaries: actionengined, ws-datastreamingd, parhand
Plugins: libhttp_smtp_notify.so, libtcpnotify.so

Architecture: ARM32 Thumb-2 PIE stripped ELFs.
Prologue detection: Thumb PUSH-with-LR (0x?? 0xB5) and Thumb-2 wide
PUSH.W (0x2D 0xE9) — covers ~95% of non-leaf function entries.
PLT resolution: .plt_base + 20 + n * 12 (ARM PLT format, 12-byte stubs).

Findings:
  F-AXACTION-01: SSRF via HTTP notification action recipient (libhttp_smtp_notify.so)
                 URL → curl_easy_setopt with no RFC-1918/loopback filter
  F-AXACTION-02: Arbitrary TCP SSRF via TCP notify action (libtcpnotify.so)
                 getaddrinfo+connect to arbitrary host:port from action rule config

Standalone:
    cd ~/ablation
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin actionengined
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin ws-datastreamingd
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin libhttp_smtp_notify.so
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin libtcpnotify.so
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --all --out findings.json
"""

import os
import sys
import json
import struct
import argparse
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).parent))
from semantic_search import describe_function, normalize_asm
from sentence_transformers import SentenceTransformer
import numpy as np


# ---------------------------------------------------------------------------
# ELF parsing helpers
# ---------------------------------------------------------------------------

def _read_elf_sections(path: str) -> dict:
    """
    Parse ELF32 section headers. Returns dict of name → (addr, offset, size).
    Handles little-endian ARM32.
    """
    with open(path, 'rb') as f:
        data = f.read()

    # ELF header
    if data[:4] != b'\x7fELF':
        return {}
    e_shoff  = struct.unpack_from('<I', data, 0x20)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x2e)[0]
    e_shnum  = struct.unpack_from('<H', data, 0x30)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x32)[0]

    # String table
    sh = e_shoff + e_shstrndx * e_shentsize
    strtab_off  = struct.unpack_from('<I', data, sh + 0x10)[0]
    strtab_size = struct.unpack_from('<I', data, sh + 0x14)[0]
    strtab = data[strtab_off: strtab_off + strtab_size]

    sections = {}
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        name_off = struct.unpack_from('<I', data, sh)[0]
        sh_type  = struct.unpack_from('<I', data, sh + 0x04)[0]
        addr     = struct.unpack_from('<I', data, sh + 0x0c)[0]
        offset   = struct.unpack_from('<I', data, sh + 0x10)[0]
        size     = struct.unpack_from('<I', data, sh + 0x14)[0]

        end = strtab.find(b'\x00', name_off)
        name = strtab[name_off:end].decode('latin-1')
        sections[name] = {'addr': addr, 'off': offset, 'size': size, 'type': sh_type}

    return sections


def _build_plt_map(path: str, sections: dict) -> dict:
    """
    Build PLT address → symbol name map from .rel.plt entries.
    ARM32 PLT layout: 20-byte header + 12-byte stubs.
    Returns {plt_addr: symbol_name}.
    """
    plt_info  = sections.get('.plt', {})
    relplt    = sections.get('.rel.plt', {})
    dynsym    = sections.get('.dynsym', {})
    dynstr    = sections.get('.dynstr', {})

    if not all([plt_info, relplt, dynsym, dynstr]):
        return {}

    with open(path, 'rb') as f:
        data = f.read()

    # Read dynstr
    ds_off  = dynstr['off']
    ds_size = dynstr['size']
    dynstr_data = data[ds_off: ds_off + ds_size]

    # Read dynsym entries (ELF32 Sym: name(4) value(4) size(4) info(1) other(1) shndx(2))
    sym_off  = dynsym['off']
    sym_size = 16  # ELF32 Sym entry size
    syms = {}
    for i in range(dynsym['size'] // sym_size):
        s = sym_off + i * sym_size
        name_off = struct.unpack_from('<I', data, s)[0]
        end = dynstr_data.find(b'\x00', name_off)
        name = dynstr_data[name_off:end].decode('latin-1')
        syms[i] = name

    # Read .rel.plt entries (ELF32 Rel: offset(4) info(4))
    rel_off  = relplt['off']
    rel_size = relplt['size']
    entries = []
    for i in range(rel_size // 8):
        r = rel_off + i * 8
        r_offset = struct.unpack_from('<I', data, r)[0]
        r_info   = struct.unpack_from('<I', data, r + 4)[0]
        sym_idx  = r_info >> 8
        entries.append((r_offset, sym_idx))

    # Sort by GOT offset to get canonical PLT order (matches stub index)
    entries.sort(key=lambda x: x[0])

    plt_base = plt_info['addr']
    plt_header = 20  # ARM PLT header
    stub_size  = 12  # ARM PLT stub (ldr pc,[pc,#x]; nop; .word)

    result = {}
    for n, (_, sym_idx) in enumerate(entries):
        plt_addr = plt_base + plt_header + n * stub_size
        sym_name = syms.get(sym_idx, f'sym_{sym_idx}')
        result[plt_addr] = sym_name
        # Also add +1 for Thumb interworking (BLX to odd address)
        result[plt_addr + 1] = sym_name

    return result


def _get_strings_map(path: str, sections: dict, min_len: int = 4) -> dict:
    """
    Extract strings from .rodata → {vaddr: string}. Used for context.
    """
    rodata = sections.get('.rodata', {})
    if not rodata:
        return {}
    with open(path, 'rb') as f:
        f.seek(rodata['off'])
        raw = f.read(rodata['size'])

    result = {}
    i = 0
    base = rodata['addr']
    while i < len(raw):
        j = raw.find(b'\x00', i)
        if j < 0:
            break
        s = raw[i:j]
        if len(s) >= min_len and s.isascii():
            result[base + i] = s.decode('ascii', errors='replace')
        i = j + 1
    return result


def _find_prologues_thumb(text_data: bytes, text_va: int) -> list:
    """
    Find ARM32 Thumb function prologues.
    Pattern 1: ?? B5 — Thumb 16-bit PUSH {registers, lr}  (byte[1] == 0xB5)
    Pattern 2: 2D E9 ?? ?? — Thumb-2 32-bit PUSH.W {registers} including LR
    Returns list of (va, 'thumb16'|'thumb32').
    """
    starts = []
    i = 0
    dlen = len(text_data)
    while i < dlen - 4:
        # Thumb-2 wide PUSH first (4 bytes)
        if text_data[i] == 0x2D and text_data[i+1] == 0xE9:
            reg_mask = struct.unpack_from('<H', text_data, i+2)[0]
            if reg_mask & 0x4000:  # LR bit in wide PUSH.W
                starts.append((text_va + i, 'thumb32'))
            i += 4
            continue
        # Thumb 16-bit PUSH with LR
        if i + 1 < dlen and text_data[i+1] == 0xB5:
            starts.append((text_va + i, 'thumb16'))
            i += 2
            continue
        i += 2  # Thumb instructions are 2-byte aligned
    return starts


def _disasm_thumb(data: bytes, va: int, max_insns: int = 80) -> list:
    """Disassemble Thumb-2 code starting at va. Returns list of (mnemonic, op_str)."""
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = False
    insns = []
    for ins in md.disasm(data, va):
        insns.append((ins.mnemonic, ins.op_str, ins.address))
        if len(insns) >= max_insns:
            break
    return insns


def _resolve_strings_near(va: int, insns: list, strings_map: dict, window: int = 0x200) -> list:
    """Find string constants near va in strings_map (within window bytes)."""
    found = []
    for s_va, s_str in strings_map.items():
        if abs(s_va - va) < window:
            found.append(s_str[:60])
    return found[:6]


# ---------------------------------------------------------------------------
# Semantic sweep engine
# ---------------------------------------------------------------------------

THUMB_CALL_MNEMONICS = {'bl', 'blx'}

def _semantic_sweep(bin_path: str, plt_map: dict, model, queries: dict,
                    strings_map: dict = None) -> dict:
    """
    Run BERT sweep over all Thumb prologues in bin_path.
    Returns {query_name: [top_5_hits]}.
    """
    sections = _read_elf_sections(bin_path)
    text = sections.get('.text', {})
    if not text:
        return {'error': f'No .text in {bin_path}'}

    with open(bin_path, 'rb') as f:
        raw = f.read()

    text_data = raw[text['off']: text['off'] + text['size']]
    text_va   = text['addr']

    prologues = _find_prologues_thumb(text_data, text_va)
    if not prologues:
        return {'error': 'No Thumb prologues found'}

    funcs = []
    for (va, kind) in prologues:
        file_off = va - text_va + text['off']
        chunk    = raw[file_off: file_off + 512]
        insns    = _disasm_thumb(chunk, va)

        if len(insns) < 4:
            continue  # skip tiny leaf stubs

        asm_lines = [f'{m} {o}'.strip() for m, o, _ in insns[:64]]

        # Resolve call targets
        calls = []
        for m, op, _ in insns:
            if m in THUMB_CALL_MNEMONICS:
                # op is like '#0x3d30' or 'r3'
                raw_op = op.lstrip('#').strip()
                try:
                    target = int(raw_op, 16)
                    # check both even and odd (Thumb interworking)
                    sym = plt_map.get(target) or plt_map.get(target & ~1) or plt_map.get(target | 1)
                    if sym:
                        calls.append(sym)
                except ValueError:
                    pass  # register-indirect call

        # Find nearby strings for context
        strs = []
        if strings_map:
            strs = _resolve_strings_near(va, insns, strings_map)

        name = f'func_{va:08x}'
        desc = describe_function(
            name=name,
            role='unknown',
            call_targets=calls,
            strings=strs,
            vuln_notes='',
            asm_lines=asm_lines,
        )
        funcs.append({'va': va, 'name': name, 'calls': calls, 'strs': strs, 'desc': desc})

    if not funcs:
        return {'error': 'No functions after filtering'}

    print(f'  {len(funcs)} functions encoded from {Path(bin_path).name}', flush=True)
    corpus_vecs = model.encode([f['desc'] for f in funcs], normalize_embeddings=True)

    results = {}
    for qname, qtext in queries.items():
        qvec = model.encode(qtext, normalize_embeddings=True)
        scores = corpus_vecs @ qvec
        top_idx = np.argsort(scores)[::-1][:5]
        results[qname] = [
            {
                'va':    hex(funcs[i]['va']),
                'name':  funcs[i]['name'],
                'calls': funcs[i]['calls'][:8],
                'strs':  funcs[i]['strs'][:4],
                'score': round(float(scores[i]), 4),
            }
            for i in top_idx
        ]

    return results


# ---------------------------------------------------------------------------
# Binary-specific analyzers
# ---------------------------------------------------------------------------

QUERIES = {
    'cmd_injection': (
        'ACTIONENGINED | calls: system popen g_spawn_command_line_async | '
        'vuln: command string assembled from config or event data passed to shell executor without sanitization'
    ),
    'url_ssrf': (
        'ACTIONENGINED | calls: soup_session_send g_file_read curl | '
        'vuln: URL from action rule config or event trigger passed directly to HTTP client — SSRF'
    ),
    'format_string': (
        'ACTIONENGINED | calls: g_sprintf snprintf printf g_log | '
        'vuln: format string constructed from user-controlled config value'
    ),
    'json_injection': (
        'WS_STREAM | calls: json_loads json_object json_pack json_string_value | '
        'vuln: JSON parsed from WebSocket message without length or type validation'
    ),
    'websocket_overflow': (
        'WS_STREAM | calls: soup_websocket_connection_send_message soup_server_add_websocket_handler memcpy | '
        'vuln: WebSocket message length not bounded before copy into fixed buffer'
    ),
    'xml_injection': (
        'PARSER | calls: xmlnode_parse_string xmlParseDoc | '
        'vuln: XML input from action condition or event filter passed directly to parser'
    ),
    'path_traversal': (
        'FILEOP | calls: open g_file_new_for_path g_file_test rename | '
        'vuln: file path derived from action rule name or param without canonicalization'
    ),
    'auth_bypass': (
        'AUTH | calls: g_strcmp0 memcmp g_hash_table_lookup | '
        'vuln: credential or token compared with timing-unsafe string compare'
    ),
    'buffer_size_ext': (
        'NETREAD | calls: g_input_stream_read recv read memcpy | '
        'vuln: buffer size determined from untrusted network input, no upper bound check'
    ),
}


def analyze_actionengined(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/bin/actionengined')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'actionengined: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, QUERIES, strs_map)


def analyze_ws_datastreamingd(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/bin/ws-datastreamingd')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'ws-datastreamingd: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    # ws-datastreamingd is C++ — focus on WebSocket/JSON queries
    ws_queries = {k: v for k, v in QUERIES.items()
                  if k in ('json_injection', 'websocket_overflow', 'buffer_size_ext',
                           'auth_bypass', 'format_string', 'path_traversal')}
    return _semantic_sweep(path, plt_map, model, ws_queries, strs_map)


PLUGIN_SSRF_QUERIES = {
    'ssrf_url': (
        'HTTP_NOTIFY | calls: curl_easy_setopt xmlnode_find_tag | '
        'vuln: URL from action rule XML passed to CURLOPT_URL without RFC-1918 or loopback filtering — SSRF'
    ),
    'smtp_inject': (
        'SMTP_NOTIFY | calls: set_mail_url setsockopt formatname_init | '
        'vuln: SMTP URL constructed from action rule config; email recipient injected via formatstring USER_STRING'
    ),
    'curl_opts': (
        'CURL | calls: curl_easy_setopt curl_easy_escape curl_slist_append | '
        'vuln: CURLOPT_URL or CURLOPT_POSTFIELDS set from unvalidated action rule XML parameter'
    ),
    'format_injection': (
        'FORMAT | calls: formatstring formatname_init strtok __snprintf_chk | '
        'vuln: FORMATNAME_USER_STRING value from event metadata embedded in HTTP body or TCP payload'
    ),
}

TCP_SSRF_QUERIES = {
    'tcp_ssrf': (
        'TCP_NOTIFY | calls: getaddrinfo connect send formatstring | '
        'vuln: host and port from action rule XML used in raw TCP connection to arbitrary dest — blind SSRF'
    ),
    'payload_inject': (
        'TCP | calls: formatstring xmlnode_find_tag send g_strdup_printf | '
        'vuln: FORMATNAME_USER_STRING value embedded in TCP payload sent to arbitrary host:port'
    ),
}


def analyze_libhttp_smtp_notify(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/lib/actionengine_plugins/libhttp_smtp_notify.so')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'libhttp_smtp_notify.so: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, PLUGIN_SSRF_QUERIES, strs_map)


def analyze_libtcpnotify(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/lib/actionengine_plugins/libtcpnotify.so')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'libtcpnotify.so: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, TCP_SSRF_QUERIES, strs_map)


def analyze_parhand(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/bin/parhand')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'parhand: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    param_queries = {
        'param_injection': (
            'PARHAND | calls: fopen fwrite rename | '
            'vuln: parameter value written to conf file without escaping quotes or newlines'
        ),
        'cmd_exec': (
            'PARHAND | calls: system popen g_spawn | '
            'vuln: dbus callback field value passed to shell executor'
        ),
        'format_string': (
            'PARHAND | calls: sprintf printf g_log snprintf | '
            'vuln: parameter name or value used as format string argument'
        ),
        'path_traversal': (
            'PARHAND | calls: open fopen snprintf | '
            'vuln: parameter group name used in file path without sanitization — /etc/dynamic/param/<group>/<name>.conf'
        ),
    }
    return _semantic_sweep(path, plt_map, model, param_queries, strs_map)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ANALYZERS = {
    'actionengined':           analyze_actionengined,
    'ws-datastreamingd':       analyze_ws_datastreamingd,
    'parhand':                 analyze_parhand,
    'libhttp_smtp_notify.so':  analyze_libhttp_smtp_notify,
    'libtcpnotify.so':         analyze_libtcpnotify,
}


def _print_results(binary: str, results: dict):
    if 'error' in results:
        print(f'\n[{binary}] ERROR: {results["error"]}')
        return
    print(f'\n{"="*60}')
    print(f'  {binary.upper()} — BERT SWEEP RESULTS')
    print(f'{"="*60}')
    for qname, hits in results.items():
        print(f'\n  [{qname}]')
        for h in hits:
            calls_str = ', '.join(h["calls"][:5]) if h["calls"] else '(none)'
            strs_str  = ' | '.join(h["strs"][:2]) if h["strs"] else ''
            print(f'    {h["va"]}  score={h["score"]:.4f}  calls=[{calls_str}]')
            if strs_str:
                print(f'           strings: {strs_str}')


def main():
    parser = argparse.ArgumentParser(description='ARM32 Thumb firmware RE via BERT sweep')
    parser.add_argument('rootfs', help='Path to extracted firmware rootfs')
    parser.add_argument('--bin', choices=list(ANALYZERS.keys()), metavar='BIN',
                        help=f'Analyze one target: {list(ANALYZERS.keys())}')
    parser.add_argument('--all', action='store_true', help='Analyze all binaries')
    parser.add_argument('--out', help='Write results JSON to file')
    args = parser.parse_args()

    if not args.bin and not args.all:
        parser.error('Specify --bin NAME or --all')

    print('Loading BERT model (all-MiniLM-L6-v2)...', flush=True)
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')

    targets = list(ANALYZERS.keys()) if args.all else [args.bin]
    all_results = {}

    for binary in targets:
        print(f'\nAnalyzing {binary}...', flush=True)
        results = ANALYZERS[binary](args.rootfs, model)
        all_results[binary] = results
        _print_results(binary, results)

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(all_results, f, indent=2)
        print(f'\nResults written to {args.out}')


if __name__ == '__main__':
    main()
