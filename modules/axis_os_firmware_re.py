"""
axis_os_firmware_re — AXIS OS firmware binary RE module (ARM32 Thumb)

Targets: P3245-V_11_11_220.bin extracted rootfs (ARTPEC-7, armhf)
Binaries: actionengined, ws-datastreamingd, parhand, sipd, monolith, netd, firewall-confd
Plugins: libhttp_smtp_notify.so, libtcpnotify.so
Apache: libwssecurity_url_access.so, mod_authz_axisgroupfile.so, mod_trax.so

Architecture: ARM32 Thumb-2 PIE stripped ELFs.
Prologue detection: Thumb PUSH-with-LR (0x?? 0xB5) and Thumb-2 wide
PUSH.W (0x2D 0xE9) — covers ~95% of non-leaf function entries.
PLT resolution: .plt_base + 20 + n * 12 (ARM PLT format, 12-byte stubs).

Findings:
  F-AXACTION-01: SSRF via HTTP notification action recipient (libhttp_smtp_notify.so)
                 URL → curl_easy_setopt with no RFC-1918/loopback filter
  F-AXACTION-02: Arbitrary TCP SSRF via TCP notify action (libtcpnotify.so)
                 getaddrinfo+connect to arbitrary host:port from action rule config
  F-AXDEVCONF-01: InstallAPI YAML file write via D-Bus (dev-conf-service)
  F-AXDEVCONF-02: setfacl spawn with potentially attacker-controlled UDS path (dev-conf-service)
  F-AXMONO-01: 1028-byte stack frame + auth bypass path in monolith RTSP HTTP auth checker

Standalone:
    cd ~/ablation
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin actionengined
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin libwssecurity_url_access.so
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin mod_authz_axisgroupfile.so
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin mod_trax.so
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin netd
    python3 modules/axis_os_firmware_re.py ~/VDT/axis-os-re/extracted/rootfs --bin firewall-confd
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


def _arm32_imm12(imm12: int) -> int:
    """Decode ARM32 data-processing 12-bit immediate: ROR(imm8, rot*2)."""
    rot  = ((imm12 >> 8) & 0xf) * 2
    imm8 = imm12 & 0xff
    if rot == 0:
        return imm8
    return ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xffffffff


def _decode_plt_stub(data: bytes, stub_va: int) -> int | None:
    """
    Decode ARM32 3-instruction PLT stub at stub_va:
      add ip, pc, #K1   (E28FC???)
      add ip, ip, #K2   (E28CC???)
      ldr pc, [ip,#K3]! (E5BCF???)
    Returns GOT VA or None if pattern doesn't match.
    PC during first add = stub_va + 8 (ARM pipeline).
    """
    w0 = struct.unpack_from('<I', data, stub_va)[0]
    w1 = struct.unpack_from('<I', data, stub_va + 4)[0]
    w2 = struct.unpack_from('<I', data, stub_va + 8)[0]
    if ((w0 & 0xfffff000) == 0xE28FC000 and
            (w1 & 0xfffff000) == 0xE28CC000 and
            (w2 & 0xfffff000) == 0xE5BCF000):
        k1 = _arm32_imm12(w0 & 0xfff)
        k2 = _arm32_imm12(w1 & 0xfff)
        k3 = w2 & 0xfff
        return (stub_va + 8 + k1 + k2 + k3) & 0xffffffff
    return None


def _build_plt_map(path: str, sections: dict) -> dict:
    """
    Build PLT address → symbol name map by decoding actual ARM32 PLT stubs.
    Handles both 12-byte (3-instruction) and 16-byte (4-word) stubs correctly.
    Uses GOT VA decoded from each stub's add/add/ldr instruction sequence,
    cross-referenced against .rel.plt entries — avoids the n*12 formula
    that breaks whenever a 16-byte stub shifts subsequent entries.
    Returns {plt_addr: symbol_name, plt_addr+1: symbol_name}.
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
    dynstr_data = data[dynstr['off']: dynstr['off'] + dynstr['size']]

    # Read dynsym entries (ELF32 Sym: name(4) value(4) size(4) info(1) other(1) shndx(2))
    sym_size = 16
    syms = {}
    for i in range(dynsym['size'] // sym_size):
        s = dynsym['off'] + i * sym_size
        name_off = struct.unpack_from('<I', data, s)[0]
        end = dynstr_data.find(b'\x00', name_off)
        syms[i] = dynstr_data[name_off:end].decode('latin-1')

    # Build GOT VA → symbol name from .rel.plt
    got_to_sym: dict[int, str] = {}
    for i in range(relplt['size'] // 8):
        r = relplt['off'] + i * 8
        r_offset = struct.unpack_from('<I', data, r)[0]
        sym_idx  = struct.unpack_from('<I', data, r + 4)[0] >> 8
        got_to_sym[r_offset] = syms.get(sym_idx, f'sym_{sym_idx}')

    # Walk PLT stubs by decoding instructions (not by formula).
    # Skip 20-byte PLT header; advance 12 or 16 bytes per stub.
    plt_base = plt_info['addr']
    plt_end  = plt_base + plt_info['size']
    stub_va  = plt_base + 20

    result: dict[int, str] = {}
    while stub_va + 12 <= plt_end:
        got_va = _decode_plt_stub(data, stub_va)
        if got_va is not None:
            sym = got_to_sym.get(got_va)
            if sym is not None:
                result[stub_va]     = sym
                result[stub_va + 1] = sym
            stub_va += 12
            continue

        # 16-byte stub: leading word before the 3-instruction block.
        # PC during the add at (stub_va+4) = (stub_va+4)+8 = stub_va+12.
        if stub_va + 16 <= plt_end:
            w0b = struct.unpack_from('<I', data, stub_va + 4)[0]
            w1b = struct.unpack_from('<I', data, stub_va + 8)[0]
            w2b = struct.unpack_from('<I', data, stub_va + 12)[0]
            if ((w0b & 0xfffff000) == 0xE28FC000 and
                    (w1b & 0xfffff000) == 0xE28CC000 and
                    (w2b & 0xfffff000) == 0xE5BCF000):
                k1 = _arm32_imm12(w0b & 0xfff)
                k2 = _arm32_imm12(w1b & 0xfff)
                k3 = w2b & 0xfff
                got_va = (stub_va + 12 + k1 + k2 + k3) & 0xffffffff
                sym = got_to_sym.get(got_va)
                if sym is not None:
                    result[stub_va]     = sym
                    result[stub_va + 1] = sym
                stub_va += 16
                continue

        # Unrecognised; advance 4 bytes and retry.
        stub_va += 4

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


SIP_QUERIES = {
    'sip_overflow': (
        'SIP | calls: recv read sscanf sscanf g_strsplit | '
        'vuln: SIP message header or URI parsed into fixed buffer without length check'
    ),
    'sip_format': (
        'SIP | calls: sprintf printf snprintf g_strdup_printf | '
        'vuln: SIP header field value used as format string or in unbounded sprintf'
    ),
    'sip_uri_inject': (
        'SIP_URI | calls: strncpy strncat strcpy g_strlcpy | '
        'vuln: SIP URI or Contact header copied to fixed-size buffer — off-by-one or no-null-terminator'
    ),
    'sip_auth': (
        'SIP_AUTH | calls: strcmp memcmp strncmp g_ascii_strncasecmp | '
        'vuln: authentication digest compared with timing-unsafe function; nonce validation bypass'
    ),
    'sip_realloc': (
        'SIP_BUF | calls: realloc malloc memcpy | '
        'vuln: SIP message body length from Content-Length header used as realloc size without validation'
    ),
}

MONOLITH_QUERIES = {
    'rtsp_overflow': (
        'RTSP | calls: g_strdup_printf snprintf strncpy memcpy | '
        'vuln: RTSP request line or header copied to fixed buffer; URL length unchecked'
    ),
    'rtsp_auth_bypass': (
        'RTSP_AUTH | calls: g_strcmp0 g_ascii_strncasecmp memcmp strcmp | '
        'vuln: Authorization header value compared with timing-unsafe function or constant-time bypass'
    ),
    'http_inject': (
        'HTTP | calls: g_strdup_printf snprintf g_strsplit | '
        'vuln: CGI parameter value reflected into HTTP response without escaping — XSS or header injection'
    ),
    'media_factory': (
        'MEDIA | calls: g_object_new g_object_ref gst_element_factory_make | '
        'vuln: GStreamer pipeline created from user-controlled URI without validating element names'
    ),
    'stream_auth': (
        'STREAM_AUTH | calls: strcmp g_strcmp0 g_hash_table_lookup | '
        'vuln: stream authentication check uses constant-time-unsafe compare; viewer bypass possible'
    ),
}


def analyze_sipd(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/bin/sipd')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'sipd: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, SIP_QUERIES, strs_map)


def analyze_monolith(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/bin/monolith')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'monolith: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, MONOLITH_QUERIES, strs_map)


# ---------------------------------------------------------------------------
# Apache module + auth library analyzers
# ---------------------------------------------------------------------------

# mod_authz_urlaccess.so → libwssecurity_url_access.so
# URL ACL policy: g_str_has_prefix prefix matching against /var/run/wsd/url_policy
# Reload: stat + gettimeofday + g_mutex (TOCTOU candidate on policy file)
URLACCESS_QUERIES = {
    'url_prefix_bypass': (
        'URL_ACL | calls: g_str_has_prefix g_hash_table_lookup g_strsplit | '
        'vuln: URL path checked with prefix-only match; unnormalized paths like //onvif/ or '
        '/./onvif/ may bypass the ACL before Apache normalizes the request URI'
    ),
    'policy_toctou': (
        'POLICY_RELOAD | calls: stat gettimeofday g_mutex_lock g_key_file_load_from_file | '
        'vuln: policy file stat-then-load TOCTOU; attacker who can write /var/run/wsd/url_policy '
        'between stat() and load wins the race and injects allow-all policy'
    ),
    'keyfile_inject': (
        'KEYFILE_PARSE | calls: g_key_file_get_string_list g_key_file_get_groups keyfile_encode | '
        'vuln: URL policy key-file fields parsed without escaping; if any user-controlled value '
        'reaches url_policy content, group/user injection possible'
    ),
    'anon_access': (
        'ANON_AUTH | calls: g_strcmp0 g_str_equal g_hash_table_lookup | '
        'vuln: anonymous user token compared; bypass if empty string or NULL passes comparison'
    ),
}


def analyze_libwssecurity_url_access(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/lib/libwssecurity_url_access.so')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'libwssecurity_url_access.so: {len(plt_map)//2} PLT entries, {len(strs_map)} strings',
          flush=True)
    return _semantic_sweep(path, plt_map, model, URLACCESS_QUERIES, strs_map)


# mod_authz_axisgroupfile.so
# VAPIX group-based authorization: PTZ_FLAG/VIEW_FLAG/OPER_FLAG/ADMIN_FLAG
# Group file parsed with apr_strtok; strstr for membership; timing-unsafe comparisons
AXISGROUPFILE_QUERIES = {
    'group_timing_bypass': (
        'GROUP_AUTH | calls: strcmp strncmp strcasecmp ap_cstr_casecmp strstr | '
        'vuln: group name or username compared with timing-unsafe function; '
        'timing side channel leaks valid group names; constant-time compare absent'
    ),
    'groupfile_overflow': (
        'GROUPFILE_PARSE | calls: ap_varbuf_cfg_getline apr_file_gets apr_strtok __sprintf_chk | '
        'vuln: group file line read into variable buffer; if varbuf expands from attacker-controlled '
        'group file content, heap corruption or OOB read possible'
    ),
    'vapix_flag_logic': (
        'VAPIX_FLAGS | calls: axisgroupfile_authz_group_mapping axisgroupfile_authz_handle_group_access | '
        'vuln: ADMIN_FLAG/OPER_FLAG/PTZ_FLAG/VIEW_FLAG assignment logic; incorrect OR/AND of flags '
        'could grant elevated VAPIX privilege (admin) to operator-only group'
    ),
    'groupfile_toctou': (
        'GROUPFILE_RELOAD | calls: apr_stat gettimeofday apr_thread_mutex_lock apr_file_open | '
        'vuln: group file stat-then-open TOCTOU; race window between stat() and open() '
        'could let attacker swap group file to grant unauthorized group membership'
    ),
    'ssl_header_bypass': (
        'SSL_BYPASS | calls: ap_ssl_conn_is_ssl apr_table_get ap_note_auth_failure | '
        'vuln: authorization decision differs for SSL vs non-SSL connections; '
        'Proxy-Authorization header accepted on plain-text connection may bypass cert requirement'
    ),
}


def analyze_mod_authz_axisgroupfile(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/lib/apache2/modules/mod_authz_axisgroupfile.so')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'mod_authz_axisgroupfile.so: {len(plt_map)//2} PLT entries, {len(strs_map)} strings',
          flush=True)
    return _semantic_sweep(path, plt_map, model, AXISGROUPFILE_QUERIES, strs_map)


# mod_trax.so — Apache proxy/relay module for VAPIX to backend FDIP daemon
# PCRE URL routing; CGI_encode for parameter encoding; fdipc_send for IPC
TRAX_QUERIES = {
    'pcre_route_bypass': (
        'TRAX_ROUTE | calls: pcre_exec pcre_compile strcmp strstr | '
        'vuln: URL routed via pcre_exec regex; regex bypass (catastrophic backtrack or '
        'incomplete anchoring) allows unauthorized backend service access through TRAX proxy'
    ),
    'cgi_encode_bypass': (
        'CGI_ENCODE | calls: CGI_encode apr_pstrcat apr_pstrdup __snprintf_chk | '
        'vuln: CGI_encode applied to HTTP query params before IPC forwarding; '
        'encoding bypass (double-encode, null byte, percent-literal) injects raw chars into FDIP message'
    ),
    'fdipc_inject': (
        'FDIP_IPC | calls: fdipc_send fdipc_client_socket apr_table_get apr_socket_connect | '
        'vuln: HTTP header or query param value forwarded via fdipc_send to backend daemon; '
        'if IPC protocol lacks framing, injected newlines or length fields corrupt IPC stream'
    ),
    'proxy_header_inject': (
        'PROXY_FORWARD | calls: apr_table_addn apr_table_set apr_table_get add_transfer_proxy | '
        'vuln: hop-by-hop or X-Forwarded-* headers forwarded to backend without stripping; '
        'backend may trust attacker-supplied X-Forwarded-For or Proxy-Authorization'
    ),
    'socket_timeout_race': (
        'TRAX_SOCKET | calls: set_transfer_timeout apr_socket_timeout_set apr_pollset_poll | '
        'vuln: timeout configured per-request; very short timeout causes connection abort '
        'mid-transfer leaving partial data in FDIP buffer — potential desync or smuggling'
    ),
}


CGIPARSER_QUERIES = {
    'strcpy_overflow': (
        'CGI_PARAM | calls: strcpy malloc strlen CGI_split_namval | '
        'vuln: CGI parameter name or value copied with strcpy into fixed-size or malloc-sized buffer; '
        'URL-decoded length may exceed original encoded length'
    ),
    'sscanf_fmt_overflow': (
        'CGI_SCAN | calls: __isoc99_sscanf strtol CGI_decode | '
        'vuln: CGI parameter value parsed with sscanf using %s format specifier into fixed buffer; '
        'no field width limit on %s → stack overflow from query string value'
    ),
    'decode_overflow': (
        'CGI_DECODE | calls: CGI_decode memcpy strncpy | '
        'vuln: URL-decoded CGI parameter value written into fixed-size buffer; '
        'URL encoding expands (e.g., %XX = 3 chars → 1 char after decode) but decode output '
        'can still exceed dest if dest is sized by encoded length rather than decoded max'
    ),
    'fgets_injection': (
        'CGI_BODY | calls: fgets fread CGI_get_name_value_pair | '
        'vuln: POST body read from stdin into fixed buffer; Content-Length from header not '
        'validated against fgets buffer size → overflow or injection in multipart body'
    ),
}


def analyze_libcgiparser(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/lib/libcgiparser.so')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'libcgiparser.so: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, CGIPARSER_QUERIES, strs_map)


def analyze_mod_trax(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/lib/apache2/modules/mod_trax.so')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'mod_trax.so: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, TRAX_QUERIES, strs_map)


# ---------------------------------------------------------------------------
# netd — Network configuration daemon
# D-Bus interface: com.axis.Net.IPFilter (SetIPFilterInputConfig: policy + addresses[])
# WPA supplicant control via wpa_ctrl_request (EAP identity, PSK, cert paths)
# IP filter config: %srule filter ip %s policy %s → /etc/netd/ipfilter.conf
# firewall-confd reads config, applies iptables rules via /run/iptables/*.rules
# ---------------------------------------------------------------------------

NETD_QUERIES = {
    'ipfilter_cidr_inject': (
        'IPFILTER_CONFIG | calls: g_string_append_printf g_string_new fopen fwrite confutils | '
        'vuln: CIDR address string from SetIPFilterInputConfig D-Bus call formatted into '
        '%srule filter ip %s policy %s without newline or special-char validation; '
        'attacker-controlled address field containing \\n injects iptables-restore syntax '
        'into /run/iptables/iptables.rules via firewall-confd — arbitrary firewall rule injection'
    ),
    'wpa_ctrl_identity_inject': (
        'WPA_CTRL | calls: wpa_ctrl_request snprintf g_strdup_printf | '
        'vuln: EAP identity or PSK string from VAPIX config used as argument in wpa_supplicant '
        'control-socket command (SET_NETWORK N identity "...") without escaping quote or newline; '
        'injected newline appends second wpa_supplicant command — DISABLE_NETWORK or SAVE_CONFIG'
    ),
    'wpa_psk_passphrase': (
        'WPA_PSK | calls: wpa_ctrl_request strncpy g_strdup | '
        'vuln: WPA personal passphrase (netd_device_auth_config_set_wpa_personal_key) passed '
        'unescaped to SET_NETWORK N psk command; PSK is 8-63 printable chars — space/quote/newline valid'
    ),
    'popen_system_exec': (
        'NETD_EXEC | calls: system popen g_spawn_sync g_spawn_async | '
        'vuln: shell command or argv element derived from user-controlled network config; '
        'popen/system call with network interface name, service name, or DHCP option value'
    ),
    'policykit_service_inject': (
        'POLICYKIT_SVC | calls: policykit_system_restart_service policykit_system_start_service | '
        'vuln: service name argument to policykit_system_restart_service derived from D-Bus param; '
        'if caller can supply arbitrary service name, attacker restarts arbitrary systemd unit'
    ),
    'dbus_addr_parse': (
        'DBUS_IPFILTER | calls: g_variant_get g_variant_iter_loop g_variant_get_string | '
        'vuln: D-Bus addresses array (as) iterated without length or content validation; '
        'each address string passed directly to config writer — no CIDR regex enforcement at parse stage'
    ),
}


def analyze_netd(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/sbin/netd')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'netd: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, NETD_QUERIES, strs_map)


# ---------------------------------------------------------------------------
# firewall-confd — Iptables rule applicator
# Reads /etc/firewall-confd/firewall-confd.conf; writes iptables-restore format
# to /run/iptables/iptables.rules; applies via iptables/ip6tables CLI
# Rule format: -A INPUT %s -j DROP/ACCEPT where %s is CIDR address filter clause
# ---------------------------------------------------------------------------

FIREWALLCONFD_QUERIES = {
    'iptables_rule_format': (
        'IPTABLES_FORMAT | calls: g_string_append_printf g_string_new snprintf | '
        'vuln: config-supplied address written into -A INPUT %s -j ACCEPT/DROP rule string; '
        'if address contains newline, injected line is appended inside *filter block '
        'and iptables-restore accepts it as valid iptables rule — arbitrary INPUT chain rule injection'
    ),
    'config_parse_inject': (
        'CONF_PARSE | calls: g_file_get_contents g_key_file_load_from_data g_key_file_get_string | '
        'vuln: /etc/firewall-confd/firewall-confd.conf value read without escaping; '
        'if config group or key value contains stanza break (e.g., \\n[new_group]\\n), '
        'key-file parser misattributes attacker data to different config section'
    ),
    'iptables_cli_exec': (
        'IPTABLES_EXEC | calls: g_spawn_sync g_spawn_async system popen | '
        'vuln: iptables or iptables-restore invoked with address or rule file path from config; '
        'if path or argv element is attacker-controlled, injection into iptables argv or shell command'
    ),
    'addr_cidr_validate': (
        'CIDR_VALIDATE | calls: inet_pton inet_addr inet_ntop g_regex_match | '
        'vuln: absence of inet_pton validation for config addresses allows non-CIDR content '
        'to reach -A INPUT %s — network address must be validated to RFC-4632 CIDR before format'
    ),
    'rules_file_write': (
        'RULES_WRITE | calls: fopen fwrite rename confutils_set_file_contents_with_sync_mode | '
        'vuln: /run/iptables/iptables.rules written with config-derived content; '
        'if write is not atomic (no tmpfile+rename), concurrent read by iptables-restore sees partial file'
    ),
}


def analyze_firewall_confd(rootfs_dir: str, model) -> dict:
    path = os.path.join(rootfs_dir, 'usr/libexec/firewall-confd')
    sections = _read_elf_sections(path)
    plt_map  = _build_plt_map(path, sections)
    strs_map = _get_strings_map(path, sections)
    print(f'firewall-confd: {len(plt_map)//2} PLT entries, {len(strs_map)} strings', flush=True)
    return _semantic_sweep(path, plt_map, model, FIREWALLCONFD_QUERIES, strs_map)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ANALYZERS = {
    'actionengined':                   analyze_actionengined,
    'ws-datastreamingd':               analyze_ws_datastreamingd,
    'parhand':                         analyze_parhand,
    'libhttp_smtp_notify.so':          analyze_libhttp_smtp_notify,
    'libtcpnotify.so':                 analyze_libtcpnotify,
    'sipd':                            analyze_sipd,
    'monolith':                        analyze_monolith,
    'libwssecurity_url_access.so':     analyze_libwssecurity_url_access,
    'mod_authz_axisgroupfile.so':      analyze_mod_authz_axisgroupfile,
    'mod_trax.so':                     analyze_mod_trax,
    'libcgiparser.so':                 analyze_libcgiparser,
    'netd':                            analyze_netd,
    'firewall-confd':                  analyze_firewall_confd,
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
