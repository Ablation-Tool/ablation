#!/usr/bin/env python3
"""
Swift Binary Reverse Engineering Module
Synthesized from: Mastering Swift 6 (9781836203698), Swift in Depth (9781617295188),
                  Hands-On Server-Side Web Dev with Swift (9781789341171),
                  Swift Game Development 3rd Ed, iOS Developer's Guide to SwiftUI

Target: com.macstadium.orka-engine.server — Swift/NIO/gRPC ARM64 macOS binary

Key Swift ABI facts encoded here:
  - Name mangling: $s prefix; module+type+identifier+signature encoding
  - Protocol witness tables: __swift5_proto, __swift5_protos sections
  - Type descriptors: __swift5_types section (class/struct/enum metadata)
  - Field descriptors: __swift5_fieldmd (property names/types via reflection)
  - ARC: swift_retain / swift_release / objc_retain patterns
  - Error register: X21 = error result on ARM64 (CBZ X21 = success check)
  - Vapor/NIO routes: HTTP method + path string pairs in __cstring
  - gRPC-Swift: service descriptor strings, method names
  - Codable: synthesized encode/decode functions match _$s...(CodingKeys)

v2 additions (book-grounded):
  - Vapor middleware stack detection (auth guard, CORS, rate-limit, session)
  - Vapor route group prefix extraction
  - SwiftNIO ChannelHandler pipeline analysis
  - Swift Codable/Content struct extraction via symbol patterns
  - async/await continuation detection in ARM64 disassembly
  - Protocol conformance record parsing (__swift5_proto)
  - Type metadata extraction (__swift5_types, __swift5_reflstr)
  - gRPC method descriptor improved extraction
  - Swift Package Manager dependency URL extraction
  - LicenseSpring SDK deep credential analysis
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

# ── Mach-O constants ──────────────────────────────────────────────────────────
MH_MAGIC_64        = 0xFEEDFACF
MH_CIGAM_64        = 0xCFFAEDFE   # LE on disk (arm64)
CPU_TYPE_ARM64     = 0x0100000C

LC_SEGMENT_64      = 0x19
LC_SYMTAB          = 0x02
LC_DYSYMTAB        = 0x0B
LC_LOAD_DYLIB      = 0x0C
LC_UUID            = 0x1B

# nlist_64 layout (24 bytes)
NLIST_64_FMT = '<IBBHQ'  # n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(8)
NLIST_64_SZ  = struct.calcsize(NLIST_64_FMT)

# Segment64 header after cmd+cmdsize (64 bytes payload)
SEG64_HDR_FMT = '<16sQQQQIIII'
# Section64 (80 bytes)
SECT64_FMT = '<16s16sQQIIIIIII'

# ── Security-relevant string patterns ────────────────────────────────────────
SEC_STRING_PATTERNS = [
    (re.compile(rb'password', re.I),            'credential'),
    (re.compile(rb'secret', re.I),              'credential'),
    (re.compile(rb'api[_-]?key', re.I),         'api_key'),
    (re.compile(rb'Bearer', re.I),              'auth_header'),
    (re.compile(rb'Authorization', re.I),       'auth_header'),
    (re.compile(rb'-----BEGIN', re.I),          'pem_key'),
    (re.compile(rb'license', re.I),             'license'),
    (re.compile(rb'LicenseSpring', re.I),       'license_sdk'),
    (re.compile(rb'90ECE379', re.I),            'hardcoded_api_key'),
    (re.compile(rb'8ad72323', re.I),            'hardcoded_product_code'),
    (re.compile(rb'C8J7gHUr', re.I),            'hardcoded_shared_key'),
    (re.compile(rb'api\.macstadium', re.I),     'macstadium_url'),
    (re.compile(rb'orka-engine', re.I),         'orka_service'),
    (re.compile(rb'idp\.macstadium', re.I),     'idp_url'),
    (re.compile(rb'token', re.I),               'token_ref'),
    (re.compile(rb'private_key|privateKey', re.I), 'private_key'),
    (re.compile(rb'/var/run/orka', re.I),       'orka_socket'),
    (re.compile(rb'ORKA_', re.I),              'orka_env_var'),
]

# Vapor/NIO HTTP method strings
VAPOR_HTTP_METHODS = [b'GET', b'POST', b'PUT', b'DELETE', b'PATCH', b'HEAD', b'OPTIONS']

# Known Orka gRPC service names (from prior RE)
KNOWN_GRPC_SERVICES = [
    b'VirtualMachineService',
    b'ImageService',
    b'SystemService',
    b'VirtualMachineRegistrationService',
]

# ARC function names to look for in dylib imports
ARC_FUNCTIONS = [
    b'swift_retain',
    b'swift_release',
    b'swift_unknownObjectRetain',
    b'swift_unknownObjectRelease',
    b'swift_bridgeObjectRetain',
    b'swift_bridgeObjectRelease',
    b'swift_weakRetain',
    b'swift_weakRelease',
    b'objc_retain',
    b'objc_release',
    b'objc_autorelease',
]


# ── Mach-O parsing helpers ────────────────────────────────────────────────────

def _read32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def _read64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


def is_macho(data):
    if len(data) < 4:
        return False
    magic = struct.unpack_from('<I', data, 0)[0]
    return magic in (MH_MAGIC_64, MH_CIGAM_64)


def parse_macho_header(data):
    """Parse Mach-O 64-bit header.

    Returns: dict with magic, cputype, filetype, ncmds, sizeofcmds
    """
    if len(data) < 32:
        return None
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _ = \
        struct.unpack_from('<IIIIIIII', data, 0)
    return {
        'magic':       hex(magic),
        'cputype':     hex(cputype),
        'is_arm64':    cputype == CPU_TYPE_ARM64,
        'filetype':    filetype,
        'ncmds':       ncmds,
        'sizeofcmds':  sizeofcmds,
    }


def iter_load_commands(data):
    """Yield (cmd_type, cmd_offset, cmd_size, cmd_data) for each load command."""
    hdr_size = 32  # Mach-O 64-bit header
    off = hdr_size
    hdr = parse_macho_header(data)
    if not hdr:
        return

    for _ in range(hdr['ncmds']):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        yield cmd, off, cmdsize, data[off:off + cmdsize]
        off += cmdsize


def parse_segments_and_sections(data):
    """Parse all segments and their sections.

    Returns: dict mapping section_name -> {offset, size, addr, seg}
    """
    sections = {}

    for cmd, off, cmdsize, cmd_data in iter_load_commands(data):
        if cmd != LC_SEGMENT_64:
            continue

        if len(cmd_data) < 72:
            continue

        seg_name_raw = cmd_data[8:24]
        seg_name     = seg_name_raw.rstrip(b'\x00').decode('utf-8', errors='replace')
        nsects       = struct.unpack_from('<I', cmd_data, 64)[0]

        sect_off = 72  # offset into cmd_data where sections start
        for _ in range(nsects):
            if sect_off + 80 > len(cmd_data):
                break
            sect_data = cmd_data[sect_off:sect_off + 80]
            sect_name_raw = sect_data[0:16].rstrip(b'\x00').decode('utf-8', errors='replace')
            addr          = struct.unpack_from('<Q', sect_data, 32)[0]
            size          = struct.unpack_from('<Q', sect_data, 40)[0]
            file_off      = struct.unpack_from('<I', sect_data, 48)[0]
            full_name     = f'{seg_name},{sect_name_raw}'
            sections[full_name] = {
                'segment':   seg_name,
                'name':      sect_name_raw,
                'addr':      addr,
                'size':      size,
                'file_off':  file_off,
            }
            sect_off += 80

    return sections


def parse_symtab(data):
    """Parse LC_SYMTAB to extract all symbol names and their values.

    Returns: list of {name, value, type, sect}
    """
    for cmd, off, cmdsize, cmd_data in iter_load_commands(data):
        if cmd != LC_SYMTAB or len(cmd_data) < 24:
            continue

        symoff  = struct.unpack_from('<I', cmd_data, 8)[0]
        nsyms   = struct.unpack_from('<I', cmd_data, 12)[0]
        stroff  = struct.unpack_from('<I', cmd_data, 16)[0]

        symbols = []
        for i in range(nsyms):
            nlist_start = symoff + i * NLIST_64_SZ
            if nlist_start + NLIST_64_SZ > len(data):
                break
            n_strx, n_type, n_sect, n_desc, n_value = \
                struct.unpack_from(NLIST_64_FMT, data, nlist_start)

            str_start = stroff + n_strx
            str_end   = data.find(b'\x00', str_start)
            if str_end == -1:
                str_end = str_start + 256
            name = data[str_start:str_end].decode('utf-8', errors='replace')

            symbols.append({
                'name':   name,
                'value':  n_value,
                'type':   n_type,
                'sect':   n_sect,
            })
        return symbols

    return []


def parse_dylib_imports(data):
    """Extract imported dylib names from LC_LOAD_DYLIB commands."""
    libs = []
    for cmd, off, cmdsize, cmd_data in iter_load_commands(data):
        if cmd != LC_LOAD_DYLIB or len(cmd_data) < 24:
            continue
        name_off = struct.unpack_from('<I', cmd_data, 8)[0]
        raw = cmd_data[name_off:].split(b'\x00', 1)[0]
        libs.append(raw.decode('utf-8', errors='replace'))
    return libs


# ── Swift name demangling ─────────────────────────────────────────────────────

def demangle_swift_symbol(mangled):
    """Demangle a Swift mangled name.

    Tries swift-demangle CLI first, then falls back to partial regex decode.
    Returns: dict with mangled, demangled, module, type_kind, name
    """
    result = {
        'mangled':    mangled,
        'demangled':  None,
        'module':     None,
        'type_kind':  None,
        'name':       None,
    }

    # Clean leading underscore
    clean = mangled.lstrip('_')
    if not clean.startswith('$s'):
        result['demangled'] = mangled
        return result

    # Try swift-demangle CLI
    try:
        proc = subprocess.run(
            ['swift-demangle', '--compact', clean],
            capture_output=True, text=True, timeout=3
        )
        if proc.returncode == 0 and proc.stdout.strip():
            demangled = proc.stdout.strip()
            result['demangled'] = demangled
            # Extract module: first identifier before dot
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\.(.+)', demangled)
            if m:
                result['module'] = m.group(1)
                rest = m.group(2)
                # type_kind from last character pattern
                m2 = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\.(.*)', rest)
                if m2:
                    result['name'] = m2.group(1)
            return result
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    # Partial decode: parse length-prefixed identifiers after $s
    body  = clean[2:]  # strip $s
    parts = _parse_swift_name_parts(body)
    if parts:
        result['demangled'] = '$s' + '.'.join(parts)
        if len(parts) >= 1:
            result['module'] = parts[0]
        if len(parts) >= 2:
            result['name'] = parts[-1]

    return result


def _parse_swift_name_parts(body):
    """Partially decode Swift mangled name identifiers."""
    parts = []
    i = 0
    while i < len(body):
        if body[i].isdigit():
            j = i
            while j < len(body) and body[j].isdigit():
                j += 1
            length = int(body[i:j])
            name   = body[j:j + length]
            if name and all(c.isalnum() or c == '_' for c in name):
                parts.append(name)
            i = j + length
        else:
            break
    return parts


def extract_swift_symbols(data):
    """Find all $s-prefixed Swift symbols in the binary symbol table.

    Returns: list of {offset, mangled, demangled, type_kind}
    """
    symbols = parse_symtab(data)
    swift_syms = []

    for sym in symbols:
        name = sym['name']
        if name.startswith('$s') or name.startswith('_$s'):
            info = demangle_swift_symbol(name)
            swift_syms.append({
                'offset':     sym['value'],
                'mangled':    name,
                'demangled':  info['demangled'],
                'module':     info['module'],
                'name':       info['name'],
            })

    return swift_syms


# ── Swift section parsing ─────────────────────────────────────────────────────

SWIFT_SECTIONS = [
    '__TEXT,__swift5_proto',       # protocol conformance records
    '__TEXT,__swift5_protos',      # protocol descriptors
    '__TEXT,__swift5_types',       # type descriptors
    '__TEXT,__swift5_fieldmd',     # field descriptor records
    '__TEXT,__swift5_reflstr',     # reflection strings
    '__TEXT,__swift5_assocty',     # associated type records
    '__DATA,__swift5_proto',
    '__DATA,__swift5_types',
]


def extract_swift_sections(data):
    """Locate Swift metadata sections in Mach-O.

    Returns: dict of section_name -> {offset, size, addr, record_count}
    """
    all_sections = parse_segments_and_sections(data)
    result = {}

    for name in SWIFT_SECTIONS:
        if name in all_sections:
            sec = all_sections[name]
            result[name] = {
                'file_off': sec['file_off'],
                'size':     sec['size'],
                'addr':     sec['addr'],
                # Relative pointer entries are 4 bytes each
                'record_count': sec['size'] // 4 if sec['size'] > 0 else 0,
            }

    return result


# ── ARC pattern detection ─────────────────────────────────────────────────────

def find_arc_functions_in_imports(data):
    """Check if ARC runtime functions are imported from dylibs.

    Returns: list of ARC function names present in the binary
    """
    symbols = parse_symtab(data)
    found   = []

    sym_names = {s['name'].lstrip('_').encode() for s in symbols}
    for arc_fn in ARC_FUNCTIONS:
        if arc_fn in sym_names or (b'_' + arc_fn) in {s['name'].encode() for s in symbols}:
            found.append(arc_fn.decode())

    return found


def find_arc_patterns_in_text(data):
    """Scan __TEXT,__text section for ARC call patterns (no capstone).

    Looks for BL instructions whose computed target lands on an ARC function stub.
    Returns: count of ARC-pattern instructions (heuristic)
    """
    sections  = parse_segments_and_sections(data)
    text_sec  = sections.get('__TEXT,__text')
    if not text_sec:
        return 0

    off  = text_sec['file_off']
    size = text_sec['size']
    code = data[off:off + size]

    arc_count = 0
    # BL encoding: [31:26] = 0b100101, [25:0] = imm26 (signed, *4 from PC)
    BL_MASK  = 0xFC000000
    BL_VALUE = 0x94000000

    for i in range(0, len(code) - 4, 4):
        word = struct.unpack_from('<I', code, i)[0]
        if (word & BL_MASK) == BL_VALUE:
            arc_count += 1  # heuristic: count all BL calls as potential ARC candidates

    return arc_count


# ── Swift error handling patterns ─────────────────────────────────────────────

def find_error_handlers(data):
    """Find X21 error check patterns (CBZ/CBNZ X21).

    ARM64 Swift error check: after BL, check X21 == 0 (no error)
      CBZ  X21, #offset  — jump if no error
      CBNZ X21, #offset  — jump if error

    Returns: list of {addr, mnemonic, offset}
    """
    sections = parse_segments_and_sections(data)
    text_sec = sections.get('__TEXT,__text')
    if not text_sec:
        return []

    off  = text_sec['file_off']
    size = text_sec['size']
    code = data[off:off + size]
    base = text_sec['addr']

    handlers = []

    # CBZ X21: [31]=0, [30]=1, [24]=0, [4:0]=X21=21=0x15
    # Encoding: 0b1011010_imm19_00_reg5 → top 7 bits for CBZ Xn:
    # CBZ  64-bit: b7:b6:b5 = 1:0:1 → mask = 0x7E000000, val = 0xB4000000
    # CBNZ 64-bit: b7:b6:b5 = 1:0:1, b24=1 → 0xB5000000
    # Reg = bits [4:0]
    CBZ_MASK  = 0xFF00001F
    CBZ_VAL   = 0xB4000015   # CBZ X21
    CBNZ_VAL  = 0xB5000015   # CBNZ X21

    for i in range(0, len(code) - 4, 4):
        word = struct.unpack_from('<I', code, i)[0]
        if (word & CBZ_MASK) == CBZ_VAL:
            imm19     = (word >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 |= ~0x7FFFF  # sign extend
            target    = base + i * 4 + imm19 * 4  # approximate
            handlers.append({
                'addr':     base + i,
                'mnemonic': 'CBZ X21 (no-error branch)',
                'target':   target,
            })
        elif (word & CBZ_MASK) == CBNZ_VAL:
            imm19     = (word >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 |= ~0x7FFFF
            target    = base + i * 4 + imm19 * 4
            handlers.append({
                'addr':     base + i,
                'mnemonic': 'CBNZ X21 (error-present branch)',
                'target':   target,
            })

    return handlers


# ── String extraction ─────────────────────────────────────────────────────────

def extract_cstrings(data, sections=None):
    """Extract null-terminated strings from __TEXT,__cstring.

    Returns: list of (offset, string_bytes)
    """
    if sections is None:
        sections = parse_segments_and_sections(data)

    cstr_sec = sections.get('__TEXT,__cstring')
    if not cstr_sec:
        # Fallback: scan entire binary for printable strings >= 6 chars
        strings = []
        buf     = b''
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7E:
                buf += bytes([b])
            else:
                if len(buf) >= 6:
                    strings.append((i - len(buf), buf))
                buf = b''
        return strings

    off  = cstr_sec['file_off']
    size = cstr_sec['size']
    raw  = data[off:off + size]

    strings = []
    start   = 0
    while start < len(raw):
        end = raw.find(b'\x00', start)
        if end == -1:
            end = len(raw)
        s = raw[start:end]
        if len(s) >= 4:
            strings.append((off + start, s))
        start = end + 1

    return strings


def find_security_strings(data):
    """Scan __TEXT,__cstring for security-relevant strings.

    Returns: list of {string, offset, pattern_type, context}
    """
    sections = parse_segments_and_sections(data)
    cstrings = extract_cstrings(data, sections)
    results  = []

    for file_off, s in cstrings:
        for pattern, ptype in SEC_STRING_PATTERNS:
            if pattern.search(s):
                ctx_start = max(0, file_off - 16)
                ctx_end   = min(len(data), file_off + len(s) + 16)
                results.append({
                    'string':       s.decode('utf-8', errors='replace'),
                    'offset':       hex(file_off),
                    'pattern_type': ptype,
                    'context':      data[ctx_start:ctx_end].hex(),
                })
                break  # one match per string

    return results


# ── Vapor/NIO route extraction ────────────────────────────────────────────────

def find_vapor_routes(data):
    """Find Vapor route path strings in the binary.

    Looks for path strings starting with '/' followed by API-path patterns.
    Tries to find adjacent HTTP method strings.

    Returns: list of {path, offset, method_hint}
    """
    sections = parse_segments_and_sections(data)
    cstrings = extract_cstrings(data, sections)
    routes   = []
    seen     = set()

    for file_off, s in cstrings:
        if not s.startswith(b'/'):
            continue
        try:
            path = s.decode('utf-8')
        except Exception:
            continue

        # Filter: looks like an API path
        if len(path) < 2 or len(path) > 128:
            continue
        if not re.match(r'^/[a-zA-Z0-9_\-/.:{}*]+$', path):
            continue
        if path in seen:
            continue
        seen.add(path)

        # Look for adjacent HTTP method string (within 64 bytes before/after)
        method_hint = None
        for method in VAPOR_HTTP_METHODS:
            search_start = max(0, file_off - 64)
            search_end   = min(len(data), file_off + len(s) + 64)
            if method in data[search_start:search_end]:
                method_hint = method.decode()
                break

        routes.append({
            'path':        path,
            'offset':      hex(file_off),
            'method_hint': method_hint,
        })

    return routes


# ── gRPC service detection ────────────────────────────────────────────────────

def find_grpc_services(data):
    """Find gRPC service descriptor strings.

    Returns: list of {service_name, offset, methods_found}
    """
    services = []
    seen     = set()

    # Search in raw binary for known and pattern-matched service names
    for known in KNOWN_GRPC_SERVICES:
        idx = 0
        while True:
            pos = data.find(known, idx)
            if pos == -1:
                break
            if known not in seen:
                seen.add(known)
                # Look for method names nearby (within 512 bytes)
                nearby = data[max(0, pos - 256):min(len(data), pos + 512)]
                methods = re.findall(rb'[A-Z][a-zA-Z]{3,30}(?:VM|Machine|Image|Node|Network)', nearby)
                services.append({
                    'service_name': known.decode(),
                    'offset':       hex(pos),
                    'methods_found': [m.decode('utf-8', errors='replace') for m in methods[:10]],
                })
            idx = pos + 1

    # Also scan for gRPC package prefix patterns
    grpc_pkg_re = re.compile(rb'\x12[\x01-\x1F]([A-Za-z][A-Za-z0-9_]{2,30}Service)')
    for m in grpc_pkg_re.finditer(data):
        svc = m.group(1).decode('utf-8', errors='replace')
        if svc not in seen:
            seen.add(svc.encode())
            services.append({
                'service_name': svc,
                'offset':       hex(m.start()),
                'methods_found': [],
                'source':       'proto_wire_scan',
            })

    return services


# ── Vapor middleware stack detection ─────────────────────────────────────────

# Middleware class names as they appear in Swift symbol tables and strings
VAPOR_MIDDLEWARE_PATTERNS = [
    # Auth/Session
    (re.compile(rb'UserAuthenticator|BearerAuthenticator|BasicAuthenticator', re.I), 'auth_bearer_or_basic'),
    (re.compile(rb'SessionAuthenticator|RedirectMiddleware',                   re.I), 'session_auth'),
    (re.compile(rb'JWTMiddleware|JWTAuthenticator',                            re.I), 'jwt_auth'),
    (re.compile(rb'TokenAuthenticator|APIKeyMiddleware',                       re.I), 'token_auth'),
    (re.compile(rb'EnsureAuthenticatedMiddleware|EnsureAuthenticated',         re.I), 'auth_guard'),
    (re.compile(rb'GuardMiddleware|UserGuardMiddleware',                       re.I), 'auth_guard'),
    # CORS / Security headers
    (re.compile(rb'CORSMiddleware|cors(?:configuration)?',                     re.I), 'cors'),
    (re.compile(rb'SecurityHeadersMiddleware|SecurityHeaders',                 re.I), 'security_headers'),
    # Rate limiting
    (re.compile(rb'RateLimitMiddleware|RateLimit|rateLimiter',                 re.I), 'rate_limit'),
    # Logging / metrics
    (re.compile(rb'LoggingMiddleware|AccessLogMiddleware',                     re.I), 'access_log'),
    (re.compile(rb'MetricsMiddleware|PrometheusMiddleware',                    re.I), 'metrics'),
    # Error handling
    (re.compile(rb'ErrorMiddleware|AbortMiddleware',                           re.I), 'error_handler'),
    # Body / file handling
    (re.compile(rb'FileMiddleware|StaticFileMiddleware',                       re.I), 'static_files'),
    (re.compile(rb'CompressMiddleware|GzipMiddleware',                        re.I), 'compression'),
]


def find_vapor_middleware_stack(data):
    """Scan binary strings for Vapor middleware class names.

    Vapor middleware is registered in configure.swift via
    app.middleware.use(...). Their type names appear in the binary as
    Swift mangled symbols and in __cstring for dynamic dispatch.

    Returns: list of {middleware_type, pattern_type, offset, context}
    """
    sections = parse_segments_and_sections(data)
    cstrings = extract_cstrings(data, sections)
    symbols  = parse_symtab(data)

    found   = []
    seen    = set()

    # Scan cstrings
    for file_off, s in cstrings:
        for pattern, mtype in VAPOR_MIDDLEWARE_PATTERNS:
            if pattern.search(s):
                key = (mtype, s[:60])
                if key not in seen:
                    seen.add(key)
                    found.append({
                        'middleware_type': s.decode('utf-8', errors='replace'),
                        'pattern_type':   mtype,
                        'offset':         hex(file_off),
                        'source':         'cstring',
                    })
                break

    # Also scan symbol table mangled names for middleware types
    for sym in symbols:
        name = sym['name'].encode('utf-8', errors='replace')
        for pattern, mtype in VAPOR_MIDDLEWARE_PATTERNS:
            if pattern.search(name):
                key = (mtype, name[:40])
                if key not in seen:
                    seen.add(key)
                    found.append({
                        'middleware_type': sym['name'][:80],
                        'pattern_type':   mtype,
                        'offset':         hex(sym['value']),
                        'source':         'symbol_table',
                    })
                break

    return found


def find_vapor_route_groups(data):
    """Extract Vapor route group prefixes.

    In Vapor, route groups are declared as:
      app.grouped("api", "v1").get("users") { ... }
      router.grouped("journal", Int.parameter) ...

    The group prefix strings end up as contiguous null-terminated strings
    in __cstring with common API-naming patterns.

    Returns: list of {prefix, offset, group_type}
    """
    sections = parse_segments_and_sections(data)
    cstrings = extract_cstrings(data, sections)
    groups   = []
    seen     = set()

    # Route group prefix pattern: alphanumeric path component, not a full path
    # Usually short (1-30 chars), no leading slash
    prefix_re  = re.compile(r'^[a-zA-Z][a-zA-Z0-9_\-]{1,29}$')
    version_re = re.compile(r'^v\d+$|^api$|^v\d+\.\d+$')

    for file_off, s in cstrings:
        if s.startswith(b'/'):
            continue
        try:
            text = s.decode('utf-8')
        except Exception:
            continue
        if len(text) < 2 or len(text) > 30:
            continue
        if not prefix_re.match(text):
            continue
        if text in seen:
            continue
        seen.add(text)

        gtype = 'api_version' if version_re.match(text) else 'path_prefix'
        groups.append({
            'prefix':     text,
            'offset':     hex(file_off),
            'group_type': gtype,
        })

    return groups


# ── SwiftNIO channel pipeline analysis ───────────────────────────────────────

# Known SwiftNIO and gRPC-swift ChannelHandler class names.
# These appear in __cstring and Swift mangled symbols.
# Source: swift-nio, grpc-swift, swift-nio-ssl, swift-nio-http2 source trees.
NIO_HANDLER_PATTERNS = [
    # TLS/SSL
    (re.compile(rb'NIOSSLClientHandler|NIOSSLServerHandler|TLSConfiguration', re.I), 'tls'),
    (re.compile(rb'NIOSSLHandler',                                             re.I), 'tls'),
    # HTTP/1.1
    (re.compile(rb'HTTP(?:Server|Client)(?:Codec|CODEC|Handler|Protocol)',     re.I), 'http1'),
    (re.compile(rb'ByteToMessage(?:Handler|Decoder)',                          re.I), 'framing'),
    (re.compile(rb'MessageToByte(?:Handler|Encoder)',                          re.I), 'framing'),
    # HTTP/2
    (re.compile(rb'HTTP2StreamMultiplexer|NIOHTTP2Handler|HTTP2Handler',       re.I), 'http2'),
    (re.compile(rb'HTTP2ToHTTP1ClientCodec|HTTP2ToHTTP1ServerCodec',           re.I), 'http2_upgrade'),
    # gRPC
    (re.compile(rb'GRPCServerCodecHandler|GRPCClientCodecHandler',             re.I), 'grpc_codec'),
    (re.compile(rb'GRPCIdleHandler|GRPCServerHandler|GRPCClientHandler',      re.I), 'grpc_handler'),
    (re.compile(rb'LengthPrefixedMessageReader|LengthPrefixedMessageWriter',   re.I), 'grpc_framing'),
    # WebSocket
    (re.compile(rb'WebSocketFrameDecoder|WebSocketFrameEncoder',               re.I), 'websocket'),
    # Idle / keepalive
    (re.compile(rb'IdleStateHandler|KeepaliveHandler|PingHandler',             re.I), 'keepalive'),
    # Channel pipeline internals
    (re.compile(rb'ChannelPipeline|DefaultChannelPipeline',                    re.I), 'pipeline_core'),
    (re.compile(rb'EventLoopGroup|MultiThreadedEventLoopGroup|NIOEventLoop',   re.I), 'event_loop'),
    # Flow control
    (re.compile(rb'BackPressureHandler|FlowControlHandler',                    re.I), 'flow_control'),
]


def find_nio_channel_handlers(data):
    """Identify SwiftNIO ChannelHandler types installed in the pipeline.

    The set of handlers installed determines what protocols the server
    speaks: TLS, HTTP/1.1, HTTP/2, gRPC framing, WebSocket, etc.

    Returns: list of {handler_name, protocol_type, offset, source}
    """
    sections = parse_segments_and_sections(data)
    cstrings = extract_cstrings(data, sections)
    symbols  = parse_symtab(data)
    found    = []
    seen     = set()

    for file_off, s in cstrings:
        for pattern, ptype in NIO_HANDLER_PATTERNS:
            if pattern.search(s):
                key = s[:60]
                if key not in seen:
                    seen.add(key)
                    found.append({
                        'handler_name':  s.decode('utf-8', errors='replace')[:80],
                        'protocol_type': ptype,
                        'offset':        hex(file_off),
                        'source':        'cstring',
                    })
                break

    for sym in symbols:
        name = sym['name'].encode('utf-8', errors='replace')
        for pattern, ptype in NIO_HANDLER_PATTERNS:
            if pattern.search(name):
                key = name[:60]
                if key not in seen:
                    seen.add(key)
                    found.append({
                        'handler_name':  sym['name'][:80],
                        'protocol_type': ptype,
                        'offset':        hex(sym['value']),
                        'source':        'symbol_table',
                    })
                break

    return found


# ── Swift Codable struct extraction ───────────────────────────────────────────

# Symbol patterns for synthesized Codable encode/decode methods.
# Swift synthesizes these for any type conforming to Codable:
#   init(from:)       → mangling ends in 4from ...
#   encode(to:)       → mangling ends in 6encode2to ...
#   CodingKeys enum   → mangling contains 10CodingKeys
#
# In the binary these become:
#   $s<Module><N><TypeName>V4from...  (struct init from decoder)
#   $s<Module><N><TypeName>C4from...  (class init from decoder)
#   $s<Module><N><TypeName>V6encode2to...
CODABLE_DECODE_RE  = re.compile(r'\$s\w+(?:4from|6decode|4init).*(?:7Decoder|8Decoding)', re.I)
CODABLE_ENCODE_RE  = re.compile(r'\$s\w+6encode2to.*(?:7Encoder|8Encoding)', re.I)
CODINGKEYS_RE      = re.compile(r'\$s(\w+)10CodingKeys')
CONTENT_CONFORM_RE = re.compile(rb'Content\s*\{|: Content\b|Vapor\.Content')

# Vapor Content protocol (superset of Codable for HTTP body)
VAPOR_CONTENT_RE   = re.compile(rb'(?:struct|class)\s+(\w+)\s*:.*Content')


def find_codable_structs(data):
    """Find types conforming to Codable/Content by analyzing symbol patterns.

    Codable conformance in Swift generates synthesized symbols:
      - init(from decoder: Decoder)  — decodes JSON/Protobuf into the struct
      - encode(to encoder: Encoder)  — encodes the struct to JSON/Protobuf
      - CodingKeys enum              — maps property names to JSON keys

    These are the API data-model types. In a gRPC+Vapor binary they represent
    both the REST API payloads (Vapor Content) and the Protobuf message types.

    Returns: list of {type_name, mangled, kind, offset, codable_ops}
    """
    symbols = parse_symtab(data)
    found   = {}

    for sym in symbols:
        name = sym['name']
        if not (name.startswith('$s') or name.startswith('_$s')):
            continue

        # CodingKeys enum — type uses Codable
        m = CODINGKEYS_RE.search(name)
        if m:
            type_segment = m.group(1)
            # Extract readable type name from mangled segment
            parts = re.findall(r'\d+([A-Za-z][A-Za-z0-9_]+)', type_segment)
            type_name = parts[-1] if parts else type_segment[:30]
            if type_name not in found:
                found[type_name] = {
                    'type_name':   type_name,
                    'mangled':     name,
                    'kind':        'unknown',
                    'offset':      hex(sym['value']),
                    'codable_ops': set(),
                }
            found[type_name]['codable_ops'].add('CodingKeys')
            continue

        if CODABLE_DECODE_RE.search(name):
            # Extract type name from mangled symbol
            parts = re.findall(r'\d+([A-Za-z][A-Za-z0-9_]+)', name[2:])
            if len(parts) >= 2:
                type_name = parts[1]  # parts[0]=module, parts[1]=type
                kind      = 'struct' if 'V4from' in name or 'V6decode' in name else 'class'
                if type_name not in found:
                    found[type_name] = {
                        'type_name':   type_name,
                        'mangled':     name,
                        'kind':        kind,
                        'offset':      hex(sym['value']),
                        'codable_ops': set(),
                    }
                found[type_name]['codable_ops'].add('init(from:)')

        if CODABLE_ENCODE_RE.search(name):
            parts = re.findall(r'\d+([A-Za-z][A-Za-z0-9_]+)', name[2:])
            if len(parts) >= 2:
                type_name = parts[1]
                if type_name not in found:
                    found[type_name] = {
                        'type_name':   type_name,
                        'mangled':     name,
                        'kind':        'unknown',
                        'offset':      hex(sym['value']),
                        'codable_ops': set(),
                    }
                found[type_name]['codable_ops'].add('encode(to:)')

    # Convert sets to lists for JSON serialisation
    result = []
    for entry in found.values():
        entry['codable_ops'] = sorted(entry['codable_ops'])
        result.append(entry)

    return result


# ── Swift async/await continuation detection ──────────────────────────────────
#
# In ARM64, Swift async functions use a distinct calling convention:
#   - async function pointer stored in a AsyncFunctionPointer record
#   - Task context passed in a dedicated register (X22 on macOS ARM64)
#   - withCheckedContinuation / withCheckedThrowingContinuation create a
#     CheckedContinuation<T,E> value and call resume(returning:) or
#     resume(throwing:) to unblock the await point
#
# In the binary, these appear as:
#   1. Symbol names containing "CheckedContinuation", "withChecked", "resume"
#   2. String literals: "Fatal error: SWIFT TASK CONTINUATION MISUSE"
#   3. Task group strings: "withTaskGroup", "withThrowingTaskGroup"
#   4. Actor isolation strings: "actor", "MainActor", "nonisolated"

ASYNC_SYMBOL_PATTERNS = [
    re.compile(r'withChecked(?:Throwing)?Continuation',        re.I),
    re.compile(r'withUnsafe(?:Throwing)?Continuation',         re.I),
    re.compile(r'CheckedContinuation',                         re.I),
    re.compile(r'UnsafeContinuation',                          re.I),
    re.compile(r'swift_task_create|swift_task_enqueue',        re.I),
    re.compile(r'swift_continuation_init|swift_continuation_', re.I),
    re.compile(r'AsyncStream|AsyncSequence|AsyncIterator',     re.I),
    re.compile(r'withTaskGroup|withThrowingTaskGroup',         re.I),
    re.compile(r'TaskGroup\b',                                 re.I),
    re.compile(r'MainActor\.run|MainActor\.shared',            re.I),
    re.compile(r'GlobalActor\b|nonisolated\b',                 re.I),
]

ASYNC_STRING_PATTERNS = [
    (re.compile(rb'SWIFT TASK CONTINUATION MISUSE',        re.I), 'continuation_misuse_fatal'),
    (re.compile(rb'continuation.*resum',                   re.I), 'continuation_resume'),
    (re.compile(rb'async.*let\b',                          re.I), 'async_let'),
    (re.compile(rb'Task\.sleep|TaskSleepError',            re.I), 'task_sleep'),
    (re.compile(rb'CancellationError|Task\.isCancelled',   re.I), 'task_cancellation'),
    (re.compile(rb'@MainActor',                            re.I), 'main_actor_attr'),
]


def find_async_patterns(data):
    """Detect Swift async/await and structured concurrency patterns.

    Looks for:
      - withCheckedContinuation / withUnsafeContinuation bridging
      - Swift Task and TaskGroup usage
      - Actor declarations and MainActor isolation
      - Fatal error strings from misused continuations (a runtime crash path
        that can be triggered by double-resume or non-resume)

    Returns: {
        'continuation_types': list of symbol names,
        'async_string_hits':  list of {string, offset, async_type},
        'actor_symbols':      list of symbol names containing 'Actor',
        'task_count_hint':    int (number of swift_task_* imports),
    }
    """
    symbols  = parse_symtab(data)
    sections = parse_segments_and_sections(data)
    cstrings = extract_cstrings(data, sections)

    continuation_syms = []
    actor_syms        = []
    task_imports      = 0

    for sym in symbols:
        name = sym['name']
        for pat in ASYNC_SYMBOL_PATTERNS:
            if pat.search(name):
                if 'Actor' in name and 'actor' not in name.lower()[:10]:
                    actor_syms.append(name[:100])
                elif 'swift_task' in name.lower():
                    task_imports += 1
                else:
                    continuation_syms.append(name[:100])
                break

    async_strings = []
    for file_off, s in cstrings:
        for pattern, atype in ASYNC_STRING_PATTERNS:
            if pattern.search(s):
                async_strings.append({
                    'string':     s.decode('utf-8', errors='replace')[:80],
                    'offset':     hex(file_off),
                    'async_type': atype,
                })
                break

    return {
        'continuation_types': list(dict.fromkeys(continuation_syms)),  # dedup preserve order
        'async_string_hits':  async_strings,
        'actor_symbols':      list(dict.fromkeys(actor_syms)),
        'task_count_hint':    task_imports,
    }


# ── Protocol conformance record parsing ───────────────────────────────────────
#
# __TEXT,__swift5_proto contains 4-byte relative pointers.
# Each pointer points to a ProtocolConformanceDescriptor:
#   Offset  Size  Field
#   0       4     protocol (relative pointer to ProtocolDescriptor)
#   4       4     type (relative pointer to TypeDescriptor or indirect)
#   8       4     witness table pattern (relative pointer)
#   12      4     conformance flags
#
# Flags bits [3:0] = type reference kind:
#   0 = direct type reference
#   1 = indirect type reference (pointer-to-pointer)
#   2-7 = reserved
#
# We read the section raw, resolve as many names as we can from
# string cross-references, and report which types conform to which protocols.

def parse_protocol_conformances(data):
    """Parse __TEXT,__swift5_proto protocol conformance records.

    Each 4-byte entry is a relative pointer to a ProtocolConformanceDescriptor.
    We extract the descriptor addresses and cross-reference them against
    the symbol table and string sections to name the types and protocols.

    Returns: list of {
        'record_offset': hex str,  # file offset of the relative pointer
        'descriptor_addr': hex str, # computed VM address of descriptor
        'type_hint': str,          # best-guess type name from symtab
        'protocol_hint': str,      # best-guess protocol name
    }
    """
    all_sections = parse_segments_and_sections(data)
    proto_sec    = (all_sections.get('__TEXT,__swift5_proto')
                    or all_sections.get('__DATA,__swift5_proto'))
    if not proto_sec:
        return []

    file_off  = proto_sec['file_off']
    size      = proto_sec['size']
    base_addr = proto_sec['addr']
    section   = data[file_off:file_off + size]
    n_records = size // 4

    # Build a quick symbol lookup: vm_addr -> demangled name
    symbols   = parse_symtab(data)
    sym_by_addr = {}
    for sym in symbols:
        if sym['value']:
            sym_by_addr[sym['value']] = sym['name']

    records = []
    for i in range(n_records):
        rel_ptr_file = file_off + i * 4
        if rel_ptr_file + 4 > len(data):
            break

        # Relative pointer: target = (address of field) + (int32 value of field)
        field_addr  = base_addr + i * 4
        raw_val     = struct.unpack_from('<i', section, i * 4)[0]  # signed 32-bit
        desc_addr   = (field_addr + raw_val) & 0xFFFFFFFFFFFFFFFF

        # Attempt to name the descriptor from nearby symbols
        type_hint     = sym_by_addr.get(desc_addr, '')
        protocol_hint = ''

        # Check +8 from descriptor for protocol pointer (heuristic)
        proto_field_addr = desc_addr
        if proto_field_addr in sym_by_addr:
            protocol_hint = sym_by_addr[proto_field_addr]

        records.append({
            'record_offset':  hex(rel_ptr_file),
            'descriptor_addr': hex(desc_addr),
            'type_hint':       type_hint[:80] if type_hint else '',
            'protocol_hint':   protocol_hint[:80] if protocol_hint else '',
        })

    return records


# ── Type metadata extraction ───────────────────────────────────────────────────
#
# __TEXT,__swift5_reflstr contains UTF-8 reflection strings (type and field names).
# These are referenced by field descriptors in __swift5_fieldmd.
# Scanning this section gives us property names of all Codable/reflected types.
#
# __TEXT,__swift5_types contains TypeContextDescriptor relative pointers.
# Each descriptor has a name field at offset +8 (relative pointer to a string).

def extract_reflection_strings(data):
    """Extract type and property names from __swift5_reflstr.

    These strings name every type and field that participates in
    Swift's runtime reflection (Mirror API, Codable, etc.).

    Returns: list of strings
    """
    all_sections = parse_segments_and_sections(data)
    sec = all_sections.get('__TEXT,__swift5_reflstr')
    if not sec:
        return []

    raw = data[sec['file_off']:sec['file_off'] + sec['size']]

    strings = []
    start   = 0
    while start < len(raw):
        end = raw.find(b'\x00', start)
        if end == -1:
            end = len(raw)
        s = raw[start:end]
        if s and len(s) >= 2:
            try:
                strings.append(s.decode('utf-8', errors='replace'))
            except Exception:
                pass
        start = end + 1

    return strings


def extract_type_names_from_reflstr(data):
    """Return only reflection strings that look like Swift type or property names.

    Filters to alphanumeric identifiers, discarding generic noise.
    """
    raw_strings = extract_reflection_strings(data)
    type_re     = re.compile(r'^[A-Z][A-Za-z0-9_]{1,60}$')   # CamelCase type names
    prop_re     = re.compile(r'^[a-z][A-Za-z0-9_]{1,60}$')   # camelCase property names

    types = []
    props = []
    for s in raw_strings:
        if type_re.match(s):
            types.append(s)
        elif prop_re.match(s):
            props.append(s)

    return {'types': types, 'properties': props}


# ── gRPC method descriptor improved extraction ────────────────────────────────
#
# gRPC-Swift generates service descriptors containing:
#   - Service name (e.g. "VirtualMachineService")
#   - Per-method descriptor structs with:
#       name: "CreateVM", "ListVMs", etc.
#       type: unary | clientStreaming | serverStreaming | bidiStreaming
#
# In the binary these appear as:
#   1. Proto wire format: \x0a (field 1 tag) + length + method name
#   2. Swift string literals directly in __cstring
#   3. Mangled symbols: $sXxx<ServiceName>...3RPC...

GRPC_METHOD_PATTERNS = [
    # Full RPC path format: /package.ServiceName/MethodName
    re.compile(rb'/[A-Za-z][A-Za-z0-9_.]+/[A-Z][A-Za-z0-9]+'),
    # Proto field-1 string encoding: 0x0a + 1-byte-len + name
    re.compile(rb'\x0a([\x01-\x3f])([A-Z][a-zA-Z0-9]{2,40})'),
    # gRPC method type markers
    re.compile(rb'(?:unary|serverStreaming|clientStreaming|bidirectionalStreaming)Method'),
]

# Orka-specific known method names derived from prior RE of the binary
ORKA_RPC_METHODS = [
    b'CreateVM', b'DeleteVM', b'StartVM', b'StopVM', b'SuspendVM',
    b'ResumeVM', b'ListVMs', b'GetVM', b'UpdateVM',
    b'PullImage', b'DeleteImage', b'ListImages', b'GetImage',
    b'GetSystemInfo', b'GetSystemStatus', b'GetClusterStatus',
    b'RegisterVM', b'DeregisterVM',
    b'CreateNode', b'DeleteNode', b'ListNodes', b'GetNode',
    b'CreateVMConfig', b'GetVMConfig', b'ListVMConfigs',
]


def find_grpc_methods_extended(data):
    """Deep gRPC method extraction with full path and streaming type.

    Extends find_grpc_services() with:
      - Full /package/Service/Method path extraction
      - Streaming type classification (unary/server/client/bidi)
      - Known Orka RPC method name scan
      - Proto field-1 encoded method name heuristic

    Returns: list of {
        'method_path': str,      # /pkg.Svc/Method or just Method
        'streaming_type': str,   # unary|server_streaming|client_streaming|bidi
        'offset': hex str,
        'source': str,
    }
    """
    methods = []
    seen    = set()

    # 1. Full gRPC path scan: /package.Service/Method
    for m in GRPC_METHOD_PATTERNS[0].finditer(data):
        path = m.group(0).decode('utf-8', errors='replace')
        if path not in seen:
            seen.add(path)
            methods.append({
                'method_path':     path,
                'streaming_type':  'unknown',
                'offset':          hex(m.start()),
                'source':          'full_path',
            })

    # 2. Proto wire-encoded field-1 string (tag 0x0a = field 1, type 2)
    for m in GRPC_METHOD_PATTERNS[1].finditer(data):
        length = m.group(1)[0]
        name   = m.group(2)
        if len(name) >= length:
            name_str = name[:length].decode('utf-8', errors='replace')
            if name_str not in seen:
                seen.add(name_str)
                methods.append({
                    'method_path':     name_str,
                    'streaming_type':  'unknown',
                    'offset':          hex(m.start()),
                    'source':          'proto_wire',
                })

    # 3. Known Orka RPC method scan
    for method_name in ORKA_RPC_METHODS:
        pos = 0
        while True:
            idx = data.find(method_name, pos)
            if idx == -1:
                break
            # Confirm it's null-terminated or preceded by a length
            surrounding = data[max(0, idx - 2):idx + len(method_name) + 2]
            name_str = method_name.decode()
            key = f'orka:{name_str}'
            if key not in seen:
                seen.add(key)
                # Check for streaming type marker nearby
                window = data[idx:idx + len(method_name) + 64]
                stype  = 'unary'
                if b'serverStreaming' in window or b'ServerStreaming' in window:
                    stype = 'server_streaming'
                elif b'clientStreaming' in window or b'ClientStreaming' in window:
                    stype = 'client_streaming'
                elif b'bidi' in window.lower() or b'Bidirectional' in window:
                    stype = 'bidi_streaming'
                methods.append({
                    'method_path':     name_str,
                    'streaming_type':  stype,
                    'offset':          hex(idx),
                    'source':          'known_orka_method',
                })
            pos = idx + 1

    return methods


# ── Swift Package Manager dependency extraction ───────────────────────────────
#
# SPM embeds package URLs in the binary at multiple points:
#   1. __cstring: github.com/... package URL strings from Package.swift
#   2. Symbol table: module names from dependencies (e.g. NIO, GRPC, Vapor)
#   3. Dylib paths: /path/to/checkouts/<package-name>/...
#
# Known Orka-engine dependencies (deduced from dylib paths + string scan):
#   - grpc-swift (github.com/grpc/grpc-swift)
#   - swift-nio (github.com/apple/swift-nio)
#   - swift-nio-ssl (github.com/apple/swift-nio-ssl)
#   - swift-nio-http2 (github.com/apple/swift-nio-http2)
#   - vapor (github.com/vapor/vapor)
#   - LicenseSpring (private/commercial SDK)

SPM_URL_RE    = re.compile(rb'https?://(?:www\.)?github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+')
SPM_GIT_RE    = re.compile(rb'git@github\.com:[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+\.git')
CHECKOUTS_RE  = re.compile(rb'/checkouts/([A-Za-z0-9_.\-]+)/')

KNOWN_SPM_PACKAGES = {
    b'grpc-swift':          'grpc_swift',
    b'swift-nio':           'nio_core',
    b'swift-nio-ssl':       'nio_tls',
    b'swift-nio-http2':     'nio_http2',
    b'vapor':               'vapor_framework',
    b'swift-log':           'logging',
    b'swift-metrics':       'metrics',
    b'swift-protobuf':      'protobuf',
    b'LicenseSpring':       'license_sdk',
    b'licensespring':       'license_sdk',
    b'Leaf':                'vapor_templating',
    b'Fluent':              'vapor_orm',
    b'jwt-kit':             'jwt',
}


def find_spm_dependencies(data):
    """Extract Swift Package Manager dependency information from the binary.

    SPM package URLs, git references, and checkout paths all appear as
    string literals in the binary. Cross-reference against known packages
    to classify the dependency type.

    Returns: {
        'package_urls': list of str,
        'git_refs':     list of str,
        'checkout_names': list of str,
        'classified':   list of {name, dep_type},
    }
    """
    package_urls   = []
    git_refs       = []
    checkout_names = []
    seen_urls      = set()

    for m in SPM_URL_RE.finditer(data):
        url = m.group(0).decode('utf-8', errors='replace')
        if url not in seen_urls:
            seen_urls.add(url)
            package_urls.append(url)

    for m in SPM_GIT_RE.finditer(data):
        ref = m.group(0).decode('utf-8', errors='replace')
        git_refs.append(ref)

    seen_chk = set()
    for m in CHECKOUTS_RE.finditer(data):
        name = m.group(1).decode('utf-8', errors='replace')
        if name not in seen_chk:
            seen_chk.add(name)
            checkout_names.append(name)

    # Classify against known packages
    classified = []
    all_names  = checkout_names[:]
    for url in package_urls:
        pkg_name = url.rstrip('/').split('/')[-1].replace('.git', '')
        if pkg_name not in all_names:
            all_names.append(pkg_name)

    for name in all_names:
        dep_type = 'unknown'
        for pkg_bytes, dtype in KNOWN_SPM_PACKAGES.items():
            if pkg_bytes.lower() in name.lower().encode():
                dep_type = dtype
                break
        classified.append({'name': name, 'dep_type': dep_type})

    return {
        'package_urls':   package_urls,
        'git_refs':       git_refs,
        'checkout_names': checkout_names,
        'classified':     classified,
    }


# ── LicenseSpring SDK deep credential analysis ────────────────────────────────
#
# LicenseSpring SDK uses three hardcoded identifiers per integration:
#   1. API key     (UUID-like hex string, e.g. 90ECE379-...)
#   2. Shared key  (Base64-ish string, e.g. C8J7gHUr...)
#   3. Product code (short alpha string, e.g. 8ad72323-...)
#
# These are passed to LicenseSpring SDK init:
#   LicenseSpringConfiguration(apiKey: "90ECE379-...", sharedKey: "C8J7gHUr...", ...)
#
# The SDK also embeds:
#   - LicenseSpring API endpoint: api.licensespring.com
#   - License validation endpoint
#   - Activation/deactivation paths

LS_KEY_PATTERNS = [
    (re.compile(rb'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', re.I),
     'uuid_api_key'),
    (re.compile(rb'[A-Za-z0-9+/]{20,64}={0,2}'),
     'base64_key_candidate'),
    (re.compile(rb'api\.licensespring\.com', re.I),
     'licensespring_endpoint'),
    (re.compile(rb'/api/v\d+/(?:license|activate|deactivate|check)',  re.I),
     'licensespring_api_path'),
    (re.compile(rb'LicenseSpringConfiguration|LicenseManager|LicenseHandler', re.I),
     'licensespring_class'),
    (re.compile(rb'productCode|apiKey|sharedKey|licenseKey', re.I),
     'licensespring_field'),
    (re.compile(rb'90ECE379', re.I), 'orka_ls_api_key_fragment'),
    (re.compile(rb'8ad72323', re.I), 'orka_ls_product_code_fragment'),
    (re.compile(rb'C8J7gHUr', re.I), 'orka_ls_shared_key_fragment'),
    (re.compile(rb'licensespring', re.I), 'licensespring_ref'),
]

# Minimum length for a base64 key candidate to avoid false positives
LS_B64_MIN_LEN = 24


def find_licensespring_credentials(data):
    """Deep scan for LicenseSpring SDK hardcoded credentials.

    Returns: list of {
        'value': str,     # the extracted credential or endpoint
        'type': str,      # credential type
        'offset': hex str,
        'context': str,   # surrounding bytes (hex)
        'confidence': str # high / medium / low
    }
    """
    sections = parse_segments_and_sections(data)
    cstrings = extract_cstrings(data, sections)
    found    = []
    seen     = set()

    for file_off, s in cstrings:
        for pattern, ctype in LS_KEY_PATTERNS:
            if pattern.search(s):
                # Skip short base64 candidates that are likely not keys
                if ctype == 'base64_key_candidate' and len(s) < LS_B64_MIN_LEN:
                    continue
                key = s[:80]
                if key in seen:
                    continue
                seen.add(key)

                ctx_start = max(0, file_off - 24)
                ctx_end   = min(len(data), file_off + len(s) + 24)

                # Confidence heuristic
                if ctype in ('orka_ls_api_key_fragment', 'orka_ls_product_code_fragment',
                             'orka_ls_shared_key_fragment'):
                    confidence = 'high'
                elif ctype in ('licensespring_endpoint', 'licensespring_api_path',
                               'licensespring_class'):
                    confidence = 'high'
                elif ctype == 'uuid_api_key':
                    # High confidence if near LicenseSpring string
                    nearby = data[max(0, file_off - 128):file_off + 128]
                    confidence = 'high' if b'licensespring' in nearby.lower() else 'medium'
                else:
                    confidence = 'low'

                found.append({
                    'value':      s.decode('utf-8', errors='replace')[:120],
                    'type':       ctype,
                    'offset':     hex(file_off),
                    'context':    data[ctx_start:ctx_end].hex(),
                    'confidence': confidence,
                })
                break

    return found


# ── ARM64 / PAC / runtime analysis ───────────────────────────────────────────

def detect_arm64_pac_bypass(binary_data: bytes) -> list:
    """Detect ARM64 Pointer Authentication Code (PAC) bypass patterns.

    Searches for:
      RETAA/RETAB  — PAC-authenticated return (INFO: protection present)
      XPACLRI      — PAC strip instruction (MEDIUM)
      BRAA/BRAB without preceding AUTIA/AUTIB (HIGH: unauthenticated branch)
      PACIZA/PACIA1716 in code sections (HIGH: signing gadget)

    ARM64 encodings (little-endian):
      RETAA     0xD65F0BFF  -> FF 0B 5F D6
      RETAB     0xD65F0FFF  -> FF 0F 5F D6
      XPACLRI   0xD50320FF  -> FF 20 03 D5
      PACIA1716 0xD503211F  -> 1F 21 03 D5
      BRAA Xn,Xm: word & 0xFFBFFC00 == 0xD71F0800
      AUTIA Xd,Xn: word & 0xFFFFFC00 == 0xDAC11000
      AUTIB Xd,Xn: word & 0xFFFFFC00 == 0xDAC11400
      AUTIZA Xd:   word & 0xFFFFFFE0 == 0xDAC133E0
      AUTIZB Xd:   word & 0xFFFFFFE0 == 0xDAC137E0
      PACIZA Xd:   word & 0xFFFFFFE0 == 0xDAC123E0
      PACIZB Xd:   word & 0xFFFFFFE0 == 0xDAC127E0

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    data = binary_data

    # -- Fixed-encoding patterns --
    RETAA     = b'\xFF\x0B\x5F\xD6'
    RETAB     = b'\xFF\x0F\x5F\xD6'
    XPACLRI   = b'\xFF\x20\x03\xD5'
    PACIA1716 = b'\x1F\x21\x03\xD5'

    # RETAA/RETAB: PAC return authentication present (INFO)
    ret_offsets = []
    for pat in (RETAA, RETAB):
        off = 0
        while True:
            pos = data.find(pat, off)
            if pos == -1:
                break
            ret_offsets.append(hex(pos))
            off = pos + 4
    if ret_offsets:
        findings.append({
            'severity': 'INFO',
            'title':    'PAC_RETURN_AUTH_PRESENT',
            'detail':   f'RETAA/RETAB at {", ".join(ret_offsets[:8])}',
            'host':     'localhost',
            'port':     0,
        })

    # XPACLRI: PAC pointer stripped (MEDIUM)
    strip_offsets = []
    off = 0
    while True:
        pos = data.find(XPACLRI, off)
        if pos == -1:
            break
        strip_offsets.append(hex(pos))
        off = pos + 4
    if strip_offsets:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'PAC_STRIP_INSTRUCTION',
            'detail':   f'XPACLRI at {", ".join(strip_offsets[:8])} — PAC pointer stripped',
            'host':     'localhost',
            'port':     0,
        })

    # BRAA/BRAB without preceding AUTIA/AUTIB in 32-byte window (HIGH)
    BRAA_MASK  = 0xFFBFFC00   # masks bit-22 (A/B key) and bits 9:0 (Rn+Rm)
    BRAA_VAL   = 0xD71F0800
    AUTH_MASK  = 0xFFFFFC00   # masks bits 9:0 (Xn+Xd)
    AUTIA_VAL  = 0xDAC11000
    AUTIB_VAL  = 0xDAC11400
    AUTIZA_MSK = 0xFFFFFFE0   # masks Xd (bits 4:0)
    AUTIZA_VAL = 0xDAC133E0
    AUTIZB_VAL = 0xDAC137E0

    unauth_br = []
    n = len(data)
    for off in range(0, n - 3, 4):
        word = struct.unpack_from('<I', data, off)[0]
        if word & BRAA_MASK != BRAA_VAL:
            continue
        # Search preceding 32 bytes for any AUT* instruction
        has_auth = False
        win_start = max(0, off - 32)
        for woff in range(win_start, off, 4):
            prev = struct.unpack_from('<I', data, woff)[0]
            if (prev & AUTH_MASK == AUTIA_VAL or
                    prev & AUTH_MASK == AUTIB_VAL or
                    prev & AUTIZA_MSK == AUTIZA_VAL or
                    prev & AUTIZA_MSK == AUTIZB_VAL):
                has_auth = True
                break
        if not has_auth:
            unauth_br.append(hex(off))
    if unauth_br:
        findings.append({
            'severity': 'HIGH',
            'title':    'UNAUTHENTICATED_BRANCH_PAC',
            'detail':   (f'BRAA/BRAB without preceding AUTIA/AUTIB '
                         f'at {", ".join(unauth_br[:8])} — PAC bypass'),
            'host':     'localhost',
            'port':     0,
        })

    # PACIZA/PACIZB/PACIA1716 signing gadgets (HIGH)
    PACIZA_MSK = 0xFFFFFFE0
    PACIZA_VAL = 0xDAC123E0
    PACIZB_VAL = 0xDAC127E0
    PACIA1716_WORD = 0xD503211F

    sign_offsets = []
    for off in range(0, n - 3, 4):
        word = struct.unpack_from('<I', data, off)[0]
        if (word & PACIZA_MSK in (PACIZA_VAL, PACIZB_VAL) or
                word == PACIA1716_WORD):
            sign_offsets.append(hex(off))
    if sign_offsets:
        findings.append({
            'severity': 'HIGH',
            'title':    'PAC_SIGNING_GADGET',
            'detail':   (f'PACIZA/PACIZB/PACIA1716 at '
                         f'{", ".join(sign_offsets[:8])}'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_arm64_shellcode_patterns(binary_data: bytes) -> list:
    """Detect ARM64 shellcode and ROP indicators.

    Patterns:
      NOP sled  4+ consecutive 0x1F200 3D5 (ARM64 NOP = HINT #0) -> HIGH
      SVC #0    0x01 0x00 0x00 0xD4 -> CRITICAL  (raw syscall)
      BRK #0    0x00 0x00 0x20 0xD4 -> MEDIUM    (embedded breakpoint)
      MOVZ+MOVK+BLR sequence building 64-bit constant -> HIGH  (ROP chain)

    ARM64 little-endian encodings:
      NOP  = HINT #0 = 0xD503201F -> 1F 20 03 D5
      SVC #0 = 0xD4000001 -> 01 00 00 D4
      BRK #0 = 0xD4200000 -> 00 00 20 D4
      MOVZ Xd (64-bit): byte[3]==0xD2, byte[2]&0x80==0x80
      MOVK Xd (64-bit): byte[3]==0xF2, byte[2]&0x80==0x80
      BLR  Xn:          byte[3]==0xD6, byte[2]==0x3F

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    data = binary_data

    ARM64_NOP = b'\x1F\x20\x03\xD5'
    SVC_0     = b'\x01\x00\x00\xD4'
    BRK_0     = b'\x00\x00\x20\xD4'

    # NOP sled: 4+ consecutive ARM64 NOPs
    nop_sled = ARM64_NOP * 4  # 16 bytes minimum
    sled_offsets = []
    off = 0
    while True:
        pos = data.find(nop_sled, off)
        if pos == -1:
            break
        sled_offsets.append(hex(pos))
        off = pos + 4
    if sled_offsets:
        findings.append({
            'severity': 'HIGH',
            'title':    'ARM64_NOP_SLED',
            'detail':   f'4+ consecutive NOPs at {", ".join(sled_offsets[:8])}',
            'host':     'localhost',
            'port':     0,
        })

    # SVC #0: raw syscall (shellcode indicator)
    svc_offsets = []
    off = 0
    while True:
        pos = data.find(SVC_0, off)
        if pos == -1:
            break
        svc_offsets.append(hex(pos))
        off = pos + 4
    if svc_offsets:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ARM64_SYSCALL_INSTRUCTION',
            'detail':   (f'SVC #0 at {", ".join(svc_offsets[:8])} '
                         f'— shellcode syscall'),
            'host':     'localhost',
            'port':     0,
        })

    # BRK #0: embedded breakpoint
    brk_offsets = []
    off = 0
    while True:
        pos = data.find(BRK_0, off)
        if pos == -1:
            break
        brk_offsets.append(hex(pos))
        off = pos + 4
    if brk_offsets:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'ARM64_BREAKPOINT_INSTRUCTION',
            'detail':   f'BRK #0 at {", ".join(brk_offsets[:8])}',
            'host':     'localhost',
            'port':     0,
        })

    # MOVZ + MOVK + BLR: ROP gadget building 64-bit constant then calling it
    rop_offsets = []
    n = len(data)
    off = 0
    while off < n - 3 and len(rop_offsets) < 10:
        b3 = data[off + 3]
        b2 = data[off + 2]
        if b3 == 0xD2 and (b2 & 0x80):        # MOVZ Xd (64-bit)
            has_movk = False
            limit = min(off + 36, n - 3)       # look ahead up to 8 instructions
            for j in range(off + 4, limit, 4):
                jb3 = data[j + 3]
                jb2 = data[j + 2]
                if jb3 == 0xF2 and (jb2 & 0x80):   # MOVK Xd (64-bit)
                    has_movk = True
                elif has_movk and jb3 == 0xD6 and jb2 == 0x3F:  # BLR Xn
                    rop_offsets.append(hex(off))
                    break
        off += 4
    if rop_offsets:
        findings.append({
            'severity': 'HIGH',
            'title':    'ARM64_ROP_GADGET_CHAIN',
            'detail':   (f'MOVZ/MOVK+BLR 64-bit constant-load+call at '
                         f'{", ".join(rop_offsets[:8])}'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_swift_runtime_patterns(binary_data: bytes) -> list:
    """Detect Swift runtime linkage and access-control patterns.

    Patterns:
      swift_retain / swift_release          -> INFO  (ARC runtime linked)
      _swift_beginAccess absent              -> MEDIUM (exclusive access off)
      swift_dynamicCast                     -> MEDIUM (type confusion surface)
      __swift_instantiateConcreteTypeFromMangledName -> HIGH (type confusion via mangled name)

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    data = binary_data

    # swift_retain / swift_release: ARC runtime linked
    if b'swift_retain' in data or b'swift_release' in data:
        findings.append({
            'severity': 'INFO',
            'title':    'SWIFT_RUNTIME_LINKED',
            'detail':   'swift_retain/swift_release present — Swift ARC runtime linked',
            'host':     'localhost',
            'port':     0,
        })

    # _swift_beginAccess absent: exclusive access enforcement may be disabled
    # (compiled with -Ounchecked or -enforce-exclusivity=none)
    if (b'_swift_beginAccess' not in data and
            b'swift_beginAccess' not in data):
        findings.append({
            'severity': 'MEDIUM',
            'title':    'SWIFT_EXCLUSIVE_ACCESS_DISABLED',
            'detail':   ('_swift_beginAccess not found — '
                         'Swift exclusive access enforcement absent'),
            'host':     'localhost',
            'port':     0,
        })

    # swift_dynamicCast: runtime type cast, type confusion surface
    if b'swift_dynamicCast' in data:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'SWIFT_DYNAMIC_CAST',
            'detail':   'swift_dynamicCast reference — type confusion risk',
            'host':     'localhost',
            'port':     0,
        })

    # __swift_instantiateConcreteTypeFromMangledName: attacker-controlled
    # mangled name can instantiate arbitrary types
    if (b'__swift_instantiateConcreteTypeFromMangledName' in data or
            b'_swift_instantiateConcreteTypeFromMangledName' in data):
        findings.append({
            'severity': 'HIGH',
            'title':    'SWIFT_TYPE_INSTANTIATION',
            'detail':   ('__swift_instantiateConcreteTypeFromMangledName found '
                         '— potential type confusion via controlled mangled name'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_objc_runtime_abuse(binary_data: bytes) -> list:
    """Detect Objective-C runtime misuse patterns (swizzling, reflection, hooking).

    Patterns:
      objc_msgSend_stret              -> MEDIUM (ABI variation, struct return)
      method_setImplementation        -> HIGH   (runtime method swizzle)
      class_replaceMethod             -> HIGH   (class-level method replacement)
      objc_getClass + "NSObject"      -> INFO   (ObjC runtime reflection)
      NSInvocation / NSMethodSignature -> HIGH  (arbitrary selector invocation)

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    data = binary_data

    # objc_msgSend_stret: struct-return ABI variant
    if b'objc_msgSend_stret' in data:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'OBJC_STRUCT_RETURN',
            'detail':   ('objc_msgSend_stret reference — '
                         'ABI variation for struct return values'),
            'host':     'localhost',
            'port':     0,
        })

    # method_setImplementation: direct IMP swap — classic swizzle primitive
    if b'method_setImplementation' in data:
        findings.append({
            'severity': 'HIGH',
            'title':    'OBJC_METHOD_SWIZZLING',
            'detail':   'method_setImplementation reference — runtime method hook',
            'host':     'localhost',
            'port':     0,
        })

    # class_replaceMethod: replaces method IMP at class level
    if b'class_replaceMethod' in data:
        findings.append({
            'severity': 'HIGH',
            'title':    'OBJC_CLASS_REPLACEMENT',
            'detail':   'class_replaceMethod reference — method hooking via class replacement',
            'host':     'localhost',
            'port':     0,
        })

    # objc_getClass + "NSObject": runtime class lookup by name
    if b'objc_getClass' in data and b'NSObject' in data:
        findings.append({
            'severity': 'INFO',
            'title':    'OBJC_RUNTIME_REFLECTION',
            'detail':   'objc_getClass + "NSObject" string — ObjC runtime reflection',
            'host':     'localhost',
            'port':     0,
        })

    # NSInvocation / NSMethodSignature: arbitrary selector invocation
    if b'NSInvocation' in data or b'NSMethodSignature' in data:
        findings.append({
            'severity': 'HIGH',
            'title':    'OBJC_INVOCATION_REFLECTION',
            'detail':   ('NSInvocation/NSMethodSignature reference — '
                         'arbitrary selector invocation'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_swift_unsafe_memory_patterns(binary_data: bytes) -> list:
    """Detect unsafe Swift memory access patterns that bypass type safety.

    Sources: Swift in Depth — ARC, retain cycles, UnsafePointer, withUnsafeBytes,
    Unmanaged, assumingMemoryBound, bindMemory.
    """
    import re
    findings = []

    # UnsafeRawPointer / UnsafeMutableRawPointer — type-safety bypass
    if b'UnsafeRawPointer' in binary_data or b'UnsafeMutableRawPointer' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'UNSAFE_RAW_POINTER',
            'detail':   ('UnsafeRawPointer/UnsafeMutableRawPointer reference — '
                         'type-safety bypass; raw memory accessed without type guarantees'),
            'host':     'localhost',
            'port':     0,
        })

    # UnsafePointer + load(as:) — potential type confusion
    if b'UnsafePointer' in binary_data and b'load(as:)' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'UNSAFE_TYPED_LOAD',
            'detail':   ('UnsafePointer with load(as:) — typed load from raw pointer; '
                         'type confusion possible if layout assumptions are wrong'),
            'host':     'localhost',
            'port':     0,
        })

    # withUnsafeBytes + bindMemory — undefined behaviour surface
    if b'withUnsafeBytes' in binary_data and b'bindMemory' in binary_data:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'BIND_MEMORY_REINTERPRET',
            'detail':   ('withUnsafeBytes + bindMemory(to:) — reinterpret-cast of byte '
                         'buffer into typed pointer; undefined behaviour if alignment or '
                         'type invariants violated'),
            'host':     'localhost',
            'port':     0,
        })

    # assumingMemoryBound(to:) — unsafe cast
    if b'assumingMemoryBound(to:)' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'ASSUME_MEMORY_BOUND',
            'detail':   ('assumingMemoryBound(to:) reference — asserts type binding '
                         'without compiler verification; unsafe cast, potential '
                         'exploitation if caller controls pointer source'),
            'host':     'localhost',
            'port':     0,
        })

    # Unmanaged.passRetained / Unmanaged.passUnretained — manual retain/release
    if b'Unmanaged.passRetained' in binary_data or b'Unmanaged.passUnretained' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'UNMANAGED_REFERENCE',
            'detail':   ('Unmanaged.passRetained/passUnretained — manual retain/release '
                         'outside ARC; memory safety bypass; use-after-free or leak '
                         'if takeRetainedValue/takeUnretainedValue mismatched'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def detect_swift_actor_isolation_bypass(binary_data: bytes) -> list:
    """Detect Swift concurrency isolation bypasses and unsafe task patterns.

    Sources: Swift in Depth — actors, async/await, Sendable, Task.detached,
    withoutActuallyEscaping, nonisolated(unsafe), _Concurrency internals.
    """
    import re
    findings = []

    # nonisolated(unsafe) — data race surface
    if b'nonisolated(unsafe)' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'NONISOLATED_UNSAFE',
            'detail':   ('nonisolated(unsafe) declaration — suppresses actor isolation '
                         'enforcement; shared mutable state accessible from any thread '
                         'without synchronisation; data race surface'),
            'host':     'localhost',
            'port':     0,
        })

    # withoutActuallyEscaping — closure lifetime bypass
    if b'withoutActuallyEscaping' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'WITHOUT_ACTUALLY_ESCAPING',
            'detail':   ('withoutActuallyEscaping reference — presents a non-escaping '
                         'closure as escaping; closure lifetime bypass; use-after-free '
                         'if the closure outlives the withoutActuallyEscaping block'),
            'host':     'localhost',
            'port':     0,
        })

    # @unchecked Sendable — concurrency safety disabled
    if b'@unchecked Sendable' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'UNCHECKED_SENDABLE',
            'detail':   ('@unchecked Sendable conformance — opts out of compiler-enforced '
                         'concurrency safety; programmer asserts thread-safety without '
                         'compiler verification; data race if assertion is wrong'),
            'host':     'localhost',
            'port':     0,
        })

    # _Concurrency + unsafeCurrentTask — task context manipulation
    if b'_Concurrency' in binary_data and b'unsafeCurrentTask' in binary_data:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'UNSAFE_CURRENT_TASK',
            'detail':   ('_Concurrency + unsafeCurrentTask reference — direct access to '
                         'the current Task from outside a Swift concurrency context; '
                         'task context manipulation, potential priority/cancellation '
                         'state corruption'),
            'host':     'localhost',
            'port':     0,
        })

    # Task.detached without withTaskCancellationHandler — unbound task lifetime
    if b'Task.detached' in binary_data and b'withTaskCancellationHandler' not in binary_data:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'DETACHED_TASK_NO_CANCELLATION',
            'detail':   ('Task.detached present without withTaskCancellationHandler — '
                         'detached task runs outside structured concurrency tree with '
                         'no cancellation propagation; resource leak or orphaned work '
                         'on shutdown'),
            'host':     'localhost',
            'port':     0,
        })

    return findings


def probe_swift_ios_app_transport_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    import ssl
    import socket
    import struct
    import urllib.request

    findings = []

    http_ports = [80, 8080, 8008, 2368, 4567]
    for p in http_ports:
        try:
            req = urllib.request.Request(
                f'http://{host}:{p}/',
                headers={'User-Agent': 'CFNetwork/1410.0.3 Darwin/22.6.0'},
            )
            ctx = urllib.request.build_opener()
            resp = ctx.open(req, timeout=timeout)
            body = resp.read(512)
            srv = resp.headers.get('Server', '')
            findings.append({
                'severity': 'HIGH',
                'title':    'ATS_HTTP_PLAINTEXT_ACCEPTED',
                'detail':   (
                    f'HTTP accepted on port {p}; iOS ATS exception required; '
                    f'server={srv!r}; body_prefix={body[:64].hex()}'
                ),
                'host': host,
                'port': p,
            })
        except Exception:
            pass

    for udp_port, proto_label in ((500, 'IKEv1'), (4500, 'IKEv2-NAT-T')):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            if udp_port == 500:
                probe = (
                    b'\x00' * 8 +
                    b'\x00' * 8 +
                    b'\x01\x10\x02\x00' +
                    b'\x00' * 4 +
                    b'\x00\x00\x00\x1c' +
                    b'\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x01' +
                    b'\x00\x00\x00\x00'
                )
            else:
                probe = b'\x00' * 4 + b'\x00' * 8 + b'\x00' * 8 + b'\x21\x20\x22\x08' + b'\x00' * 16
            sock.sendto(probe, (host, udp_port))
            data, _ = sock.recvfrom(512)
            sock.close()
            if data:
                findings.append({
                    'severity': 'MEDIUM',
                    'title':    f'UDP_{proto_label}_BANNER',
                    'detail':   (
                        f'{proto_label} UDP port {udp_port} responded; '
                        f'game-server UDP pattern overlap; response_hex={data[:32].hex()}'
                    ),
                    'host': host,
                    'port': udp_port,
                })
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    relay_port = 53443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, relay_port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.sendall(
                    b'GET / HTTP/1.1\r\n'
                    b'Host: ' + host.encode() + b'\r\n'
                    b'Upgrade: websocket\r\n'
                    b'Connection: Upgrade\r\n'
                    b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
                    b'Sec-WebSocket-Version: 13\r\n\r\n'
                )
                resp = s.recv(512)
                if resp:
                    code = resp[:12]
                    findings.append({
                        'severity': 'MEDIUM',
                        'title':    'GAMEKIT_RELAY_PORT_OPEN',
                        'detail':   (
                            f'Port {relay_port} (GameKit/GKRelay) responded; '
                            f'status_prefix={code!r}'
                        ),
                        'host': host,
                        'port': relay_port,
                    })
    except Exception:
        pass

    ws_paths = ['/ws', '/websocket', '/socket.io/', '/socket.io/?EIO=4&transport=websocket']
    for p in [port, 80, 8080]:
        scheme = 'https' if p in (443, 8443) else 'http'
        for path in ws_paths:
            try:
                import base64
                key = base64.b64encode(b'\xde\xad\xbe\xef' * 4).decode()
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, p), timeout=timeout) as raw2:
                    conn = ctx2.wrap_socket(raw2, server_hostname=host) if p in (443, 8443) else raw2
                    conn.sendall(
                        f'GET {path} HTTP/1.1\r\n'
                        f'Host: {host}\r\n'
                        f'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                        f'Sec-WebSocket-Key: {key}\r\n'
                        f'Sec-WebSocket-Version: 13\r\n\r\n'.encode()
                    )
                    hdr = conn.recv(256)
                    if b'101' in hdr[:20]:
                        findings.append({
                            'severity': 'HIGH',
                            'title':    'WEBSOCKET_UPGRADE_ACCEPTED',
                            'detail':   (
                                f'WebSocket upgrade succeeded on {scheme}://{host}:{p}{path}; '
                                f'MCSession-compatible framing surface; '
                                f'status={hdr[:40]!r}'
                            ),
                            'host': host,
                            'port': p,
                        })
                    elif hdr:
                        first_line = hdr.split(b'\r\n')[0]
                        findings.append({
                            'severity': 'INFO',
                            'title':    'WEBSOCKET_PATH_PRESENT',
                            'detail':   (
                                f'Path {path} responded on port {p}: {first_line!r}'
                            ),
                            'host': host,
                            'port': p,
                        })
                    try:
                        conn.close()
                    except Exception:
                        pass
            except Exception:
                pass

    return findings


def probe_swift_binary_protocol_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    import ssl
    import socket
    import struct
    import urllib.request
    import json

    findings = []

    def _tls_ctx():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    probe_ports = [
        (830,   'NETCONF',  False),
        (57500, 'gRPC-IOS', False),
        (443,   'TLS',      True),
        (port,  'TARGET',   port in (443, 8443)),
    ]

    frame_probe = struct.pack('>I', 5) + b'\x00\x00\x00\x00\x00'

    http2_preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

    netconf_hello = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        b'<capabilities><capability>urn:ietf:params:netconf:base:1.0</capability>'
        b'</capabilities></hello>]]>]]>'
    )

    seen_ports = set()
    for (p, label, use_tls) in probe_ports:
        if p in seen_ports:
            continue
        seen_ports.add(p)
        try:
            raw = socket.create_connection((host, p), timeout=timeout)
        except Exception:
            continue

        try:
            if use_tls:
                conn = _tls_ctx().wrap_socket(raw, server_hostname=host)
            else:
                conn = raw

            if p == 830:
                conn.sendall(netconf_hello)
            elif p in (57500,):
                conn.sendall(http2_preface)
            else:
                conn.sendall(frame_probe)

            resp = conn.recv(1024)
            conn.close()

            if not resp:
                continue

            if p == 830 and b'hello' in resp.lower():
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'NETCONF_UNAUTH_HELLO',
                    'detail':   (
                        f'NETCONF port 830 returned hello without authentication; '
                        f'full device config read/write; '
                        f'resp_prefix={resp[:80].hex()}'
                    ),
                    'host': host,
                    'port': 830,
                })
            elif p == 830 and resp:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'NETCONF_PORT_OPEN',
                    'detail':   f'NETCONF tcp/830 responded; resp_hex={resp[:32].hex()}',
                    'host': host,
                    'port': 830,
                })

            if p in (57500,) and (b'HTTP/2' in resp or resp[:3] in (b'PRI', b'\x00\x00\x00')):
                findings.append({
                    'severity': 'HIGH',
                    'title':    'GRPC_IOS_PORT_OPEN',
                    'detail':   (
                        f'gRPC port {p} ({label}) accepted HTTP/2 preface; '
                        f'Cisco IOS-XR gRPC telemetry surface; '
                        f'resp_hex={resp[:32].hex()}'
                    ),
                    'host': host,
                    'port': p,
                })

            if len(resp) >= 4:
                declared_len = struct.unpack('>I', resp[:4])[0]
                remaining = len(resp) - 4
                if 0 < declared_len <= 65536 and abs(declared_len - remaining) <= 4:
                    findings.append({
                        'severity': 'HIGH',
                        'title':    'LENGTH_PREFIXED_FRAME_DETECTED',
                        'detail':   (
                            f'Port {p} ({label}): 4-byte big-endian length prefix '
                            f'declared_len={declared_len} remaining={remaining}; '
                            f'binary framing protocol (game-net / Cisco mgmt overlap); '
                            f'frame_hex={resp[:min(48, len(resp))].hex()}'
                        ),
                        'host': host,
                        'port': p,
                    })
        except Exception:
            try:
                raw.close()
            except Exception:
                pass

    msgpack_paths = [
        '/api/v1/config',
        '/restconf/data',
        '/api/v1/data',
        '/mgmt/tm/sys',
        '/api/model',
    ]
    cbor_magic = b'\xd9\xd9\xf7'
    msgpack_magic_prefixes = (b'\x80', b'\x81', b'\x82', b'\x83', b'\x84',
                               b'\x85', b'\x86', b'\x87', b'\x90', b'\x91',
                               b'\x92', b'\x93', b'\xde', b'\xdf', b'\xdc', b'\xdd')

    for path in msgpack_paths:
        for req_port in [port, 443, 830]:
            scheme = 'https' if req_port in (443, 8443) else 'http'
            try:
                ctx3 = _tls_ctx()
                req = urllib.request.Request(
                    f'{scheme}://{host}:{req_port}{path}',
                    headers={
                        'Accept': 'application/msgpack, application/cbor, application/json',
                        'User-Agent': 'CFNetwork/1410.0.3 Darwin/22.6.0',
                    },
                )
                hndlr = urllib.request.HTTPSHandler(context=ctx3) if scheme == 'https' else urllib.request.HTTPHandler()
                opener = urllib.request.build_opener(hndlr)
                resp2 = opener.open(req, timeout=timeout)
                body = resp2.read(256)
                ct = resp2.headers.get('Content-Type', '')
                if b'msgpack' in ct.encode() or (body and body[:1] in msgpack_magic_prefixes):
                    findings.append({
                        'severity': 'HIGH',
                        'title':    'MSGPACK_API_ENDPOINT',
                        'detail':   (
                            f'msgpack-framed response at {scheme}://{host}:{req_port}{path}; '
                            f'content-type={ct!r}; '
                            f'body_hex={body[:32].hex()}'
                        ),
                        'host': host,
                        'port': req_port,
                    })
                elif body and body[:3] == cbor_magic:
                    findings.append({
                        'severity': 'HIGH',
                        'title':    'CBOR_API_ENDPOINT',
                        'detail':   (
                            f'CBOR-framed response at {scheme}://{host}:{req_port}{path}; '
                            f'body_hex={body[:32].hex()}'
                        ),
                        'host': host,
                        'port': req_port,
                    })
                elif resp2.status == 200:
                    findings.append({
                        'severity': 'MEDIUM',
                        'title':    'MGMT_API_PATH_OPEN',
                        'detail':   (
                            f'Management API path {path} returned HTTP 200 on port {req_port}; '
                            f'content-type={ct!r}'
                        ),
                        'host': host,
                        'port': req_port,
                    })
            except Exception:
                pass

    return findings


# ── Main analyzer class ───────────────────────────────────────────────────────

class SwiftREAnalyzer:
    """Swift binary reverse engineering for Ablation."""

    def __init__(self, binary_path=None):
        self.binary_path = binary_path
        self.findings    = []
        self._data       = None

    def _load(self, path=None):
        p = path or self.binary_path
        if p is None:
            raise ValueError('No binary path set')
        self._data = Path(p).read_bytes()
        return self._data

    def analyze(self, binary_path=None):
        """Run full Swift RE analysis on a file.

        Returns: findings dict
        """
        try:
            data = self._load(binary_path or self.binary_path)
        except (OSError, ValueError) as e:
            return {'error': str(e), 'is_swift': False, 'findings': []}
        return self.analyze_bytes(data)

    def analyze_bytes(self, data):
        """Analyze Swift binary from bytes.

        Returns: findings dict
        """
        self._data = data
        result = {
            'is_macho':              is_macho(data),
            'header':                None,
            'dylibs':                [],
            'swift_sections':        {},
            'swift_symbols':         [],
            'security_strings':      [],
            'vapor_routes':          [],
            'vapor_middleware':      [],
            'vapor_route_groups':    [],
            'grpc_services':         [],
            'grpc_methods':          [],
            'nio_handlers':          [],
            'codable_structs':       [],
            'async_patterns':        {},
            'proto_conformances':    [],
            'reflection_strings':    {},
            'spm_dependencies':      {},
            'licensespring_creds':   [],
            'error_handlers':        [],
            'arc_functions':         [],
            'findings':              [],
        }

        if not result['is_macho']:
            result['findings'].append({
                'type':     'NOT_MACHO',
                'severity': 'INFO',
                'detail':   f'First 4 bytes: {data[:4].hex()}',
            })
            return result

        result['header'] = parse_macho_header(data)

        # Dylib imports
        result['dylibs'] = parse_dylib_imports(data)

        # Swift metadata sections
        result['swift_sections'] = extract_swift_sections(data)

        # Swift symbols (symbol table)
        try:
            syms = extract_swift_symbols(data)
            result['swift_symbols'] = syms[:100]  # cap at 100
            result['swift_symbol_count'] = len(syms)
        except Exception as e:
            result['swift_symbol_error'] = str(e)

        # Security-relevant strings
        try:
            result['security_strings'] = find_security_strings(data)
        except Exception as e:
            result['security_string_error'] = str(e)

        # Vapor routes
        try:
            result['vapor_routes'] = find_vapor_routes(data)
        except Exception as e:
            result['vapor_route_error'] = str(e)

        # Vapor middleware stack
        try:
            result['vapor_middleware'] = find_vapor_middleware_stack(data)
        except Exception as e:
            result['vapor_middleware_error'] = str(e)

        # Vapor route groups
        try:
            result['vapor_route_groups'] = find_vapor_route_groups(data)
        except Exception as e:
            result['vapor_route_groups_error'] = str(e)

        # gRPC services (original)
        try:
            result['grpc_services'] = find_grpc_services(data)
        except Exception as e:
            result['grpc_service_error'] = str(e)

        # gRPC methods (extended)
        try:
            result['grpc_methods'] = find_grpc_methods_extended(data)
        except Exception as e:
            result['grpc_methods_error'] = str(e)

        # SwiftNIO channel handlers
        try:
            result['nio_handlers'] = find_nio_channel_handlers(data)
        except Exception as e:
            result['nio_handlers_error'] = str(e)

        # Codable struct extraction
        try:
            result['codable_structs'] = find_codable_structs(data)
        except Exception as e:
            result['codable_structs_error'] = str(e)

        # Async/await patterns
        try:
            result['async_patterns'] = find_async_patterns(data)
        except Exception as e:
            result['async_patterns_error'] = str(e)

        # Protocol conformance records
        try:
            conformances = parse_protocol_conformances(data)
            result['proto_conformances'] = conformances[:200]   # cap — can be huge
            result['proto_conformance_count'] = len(conformances)
        except Exception as e:
            result['proto_conformances_error'] = str(e)

        # Reflection strings
        try:
            result['reflection_strings'] = extract_type_names_from_reflstr(data)
        except Exception as e:
            result['reflection_strings_error'] = str(e)

        # SPM dependencies
        try:
            result['spm_dependencies'] = find_spm_dependencies(data)
        except Exception as e:
            result['spm_dependencies_error'] = str(e)

        # LicenseSpring credentials
        try:
            result['licensespring_creds'] = find_licensespring_credentials(data)
        except Exception as e:
            result['licensespring_creds_error'] = str(e)

        # Error handler patterns
        try:
            handlers = find_error_handlers(data)
            result['error_handlers'] = handlers[:50]
            result['error_handler_count'] = len(handlers)
        except Exception as e:
            result['error_handler_error'] = str(e)

        # ARC import check
        try:
            result['arc_functions'] = find_arc_functions_in_imports(data)
        except Exception as e:
            result['arc_error'] = str(e)

        # Generate findings from results
        self._synthesize_findings(result)
        result['findings'] = self.findings
        return result

    def _synthesize_findings(self, result):
        """Synthesize high-value findings from analysis results."""

        # Hardcoded credentials
        sec_strings = result.get('security_strings', [])
        cred_types  = {'credential', 'api_key', 'hardcoded_api_key',
                       'hardcoded_product_code', 'hardcoded_shared_key',
                       'private_key', 'pem_key'}
        for s in sec_strings:
            if s['pattern_type'] in cred_types:
                self.findings.append({
                    'type':        'HARDCODED_CREDENTIAL',
                    'severity':    'CRITICAL',
                    'description': f'Hardcoded {s["pattern_type"]}: {s["string"][:60]}',
                    'detail':      f'File offset: {s["offset"]} | Context: {s["context"][:40]}',
                    'exploit':     f'Extract and replay credential against MacStadium APIs',
                })

        # Orka socket path
        for s in sec_strings:
            if s['pattern_type'] == 'orka_socket':
                self.findings.append({
                    'type':        'ORKA_GRPC_SOCKET',
                    'severity':    'HIGH',
                    'description': f'Orka gRPC Unix socket path: {s["string"]}',
                    'detail':      f'Socket path at offset {s["offset"]}',
                    'exploit':     (
                        f'echo -ne "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n" '
                        f'| socat - UNIX-CONNECT:{s["string"]}'
                    ),
                })

        # gRPC services
        for svc in result.get('grpc_services', []):
            self.findings.append({
                'type':        'GRPC_SERVICE_FOUND',
                'severity':    'MEDIUM',
                'description': f'gRPC service descriptor: {svc["service_name"]}',
                'detail': (
                    f'Offset: {svc["offset"]} | '
                    f'Methods: {", ".join(svc["methods_found"][:5]) or "unknown"}'
                ),
                'exploit':     f'Probe with grpcurl or custom gRPC client against service {svc["service_name"]}',
            })

        # Vapor routes — high value API surface
        routes = result.get('vapor_routes', [])
        if routes:
            api_routes = [r for r in routes if '/api/' in r['path'] or '/orka/' in r['path']]
            if api_routes:
                self.findings.append({
                    'type':        'VAPOR_API_ROUTES',
                    'severity':    'HIGH',
                    'description': f'{len(api_routes)} API route paths extracted from binary strings',
                    'detail':      '\n'.join(f'  {r["method_hint"] or "?"} {r["path"]}' for r in api_routes[:15]),
                    'exploit':     'Map extracted routes against authenticated API session',
                })

        # Swift metadata sections present → demangleable symbols
        swift_secs = result.get('swift_sections', {})
        if swift_secs:
            self.findings.append({
                'type':        'SWIFT_METADATA_SECTIONS',
                'severity':    'INFO',
                'description': f'{len(swift_secs)} Swift metadata sections found',
                'detail':      '\n'.join(
                    f'  {n}: {s["record_count"]} records @ {hex(s["addr"])}'
                    for n, s in swift_secs.items()
                ),
                'exploit':     'Use swift-demangle + section dump for full type reflection',
            })

        # Error handlers — maps error propagation paths
        h_count = result.get('error_handler_count', 0)
        if h_count > 0:
            self.findings.append({
                'type':        'SWIFT_ERROR_HANDLERS',
                'severity':    'INFO',
                'description': f'{h_count} Swift X21 error check patterns found in __TEXT,__text',
                'detail':      'CBZ/CBNZ X21 sequences map error propagation paths',
                'exploit':     'Patch CBZ X21 → NOP at error check to skip error handling (requires code injection)',
            })

        # LicenseSpring high-confidence credentials
        ls_creds = result.get('licensespring_creds', [])
        high_ls  = [c for c in ls_creds if c['confidence'] == 'high'
                    and c['type'] not in ('licensespring_ref', 'licensespring_field')]
        if high_ls:
            self.findings.append({
                'type':        'LICENSESPRING_HARDCODED_CREDS',
                'severity':    'CRITICAL',
                'description': f'{len(high_ls)} high-confidence LicenseSpring SDK credentials found',
                'detail':      '\n'.join(
                    f'  [{c["type"]}] {c["value"][:60]} @ {c["offset"]}'
                    for c in high_ls[:10]
                ),
                'exploit': (
                    'Use extracted API key + shared key to call api.licensespring.com '
                    'directly and enumerate/clone license state, or bypass license checks '
                    'by replaying valid activation responses.'
                ),
            })

        # NIO handler pipeline — tells us what protocols the server speaks
        nio_handlers = result.get('nio_handlers', [])
        if nio_handlers:
            has_tls    = any(h['protocol_type'] == 'tls'   for h in nio_handlers)
            has_http2  = any(h['protocol_type'] == 'http2' for h in nio_handlers)
            has_grpc   = any('grpc' in h['protocol_type']  for h in nio_handlers)
            has_ws     = any(h['protocol_type'] == 'websocket' for h in nio_handlers)

            protocols  = []
            if has_tls:   protocols.append('TLS')
            if has_http2: protocols.append('HTTP/2')
            if has_grpc:  protocols.append('gRPC')
            if has_ws:    protocols.append('WebSocket')

            self.findings.append({
                'type':        'NIO_CHANNEL_PIPELINE',
                'severity':    'INFO',
                'description': (
                    f'SwiftNIO pipeline: {", ".join(protocols) or "unknown"} '
                    f'({len(nio_handlers)} handler types)'
                ),
                'detail':      '\n'.join(
                    f'  [{h["protocol_type"]}] {h["handler_name"][:60]}'
                    for h in nio_handlers[:15]
                ),
                'exploit': (
                    'Pipeline analysis maps the exact protocol stack. '
                    'No TLS handler = plaintext gRPC. '
                    'Intercept with: mitmproxy --mode transparent --ssl-insecure'
                    if not has_tls else
                    'TLS present. Dump cert with: openssl s_client -connect <host>:<port>'
                ),
            })

        # Vapor middleware — auth guards map the protected surface
        middleware = result.get('vapor_middleware', [])
        auth_mw    = [m for m in middleware
                      if m['pattern_type'] in ('auth_bearer_or_basic', 'session_auth',
                                               'jwt_auth', 'token_auth', 'auth_guard')]
        if auth_mw:
            self.findings.append({
                'type':        'VAPOR_AUTH_MIDDLEWARE',
                'severity':    'MEDIUM',
                'description': f'{len(auth_mw)} Vapor auth middleware types detected',
                'detail':      '\n'.join(
                    f'  [{m["pattern_type"]}] {m["middleware_type"][:60]}'
                    for m in auth_mw[:10]
                ),
                'exploit': (
                    'Identify which route groups are protected by auth middleware '
                    'by correlating middleware types with route group prefixes. '
                    'Unguarded routes are unauthenticated API surface.'
                ),
            })

        # Codable struct map — API data model
        codable = result.get('codable_structs', [])
        if codable:
            full_codable = [c for c in codable if len(c['codable_ops']) >= 2]
            self.findings.append({
                'type':        'CODABLE_API_MODEL',
                'severity':    'INFO',
                'description': (
                    f'{len(codable)} Codable types found '
                    f'({len(full_codable)} with full encode+decode)'
                ),
                'detail':      '\n'.join(
                    f'  {c["type_name"]} ({c["kind"]}) ops={",".join(c["codable_ops"])}'
                    for c in full_codable[:20]
                ),
                'exploit': (
                    'These are the API payload types. Use field names from reflection '
                    'strings to craft exact JSON payloads for each endpoint.'
                ),
            })

        # Async continuation misuse fatal — crash path reachability
        async_info = result.get('async_patterns', {})
        cont_misuse = [s for s in async_info.get('async_string_hits', [])
                       if s['async_type'] == 'continuation_misuse_fatal']
        if cont_misuse:
            self.findings.append({
                'type':        'ASYNC_CONTINUATION_MISUSE_PATH',
                'severity':    'LOW',
                'description': 'Swift continuation misuse fatal error strings present',
                'detail': (
                    f'  Crash path at {cont_misuse[0]["offset"]}: '
                    f'{cont_misuse[0]["string"][:60]}\n'
                    '  Double-resume or never-resume of a CheckedContinuation causes '
                    'runtime abort. Fuzzing concurrent code paths may trigger this.'
                ),
                'exploit': (
                    'Send concurrent or timed-out requests to force continuation '
                    'double-resume: rapid parallel POST to async endpoints, then '
                    'observe crash via logs or connection drop.'
                ),
            })

        # SPM dependencies — maps attack surface to known CVE-bearing packages
        spm = result.get('spm_dependencies', {})
        classified = spm.get('classified', [])
        if classified:
            self.findings.append({
                'type':        'SPM_DEPENDENCY_MAP',
                'severity':    'INFO',
                'description': f'{len(classified)} Swift Package Manager dependencies identified',
                'detail':      '\n'.join(
                    f'  {c["name"]} [{c["dep_type"]}]'
                    for c in classified[:20]
                ),
                'exploit': (
                    'Cross-reference package names against known CVE databases. '
                    'grpc-swift < 1.8.0: CVE-2023-32731 (flow control bypass). '
                    'swift-nio-ssl: check for expired/weak cipher config. '
                    'vapor: check for CSRF bypass in session handling.'
                ),
            })

        # gRPC methods extended — full call surface
        grpc_methods = result.get('grpc_methods', [])
        if grpc_methods:
            full_paths = [m for m in grpc_methods if m['source'] == 'full_path']
            known_methods = [m for m in grpc_methods if m['source'] == 'known_orka_method']
            self.findings.append({
                'type':        'GRPC_METHOD_SURFACE',
                'severity':    'HIGH',
                'description': (
                    f'{len(grpc_methods)} gRPC method references '
                    f'({len(full_paths)} full paths, {len(known_methods)} known Orka methods)'
                ),
                'detail':      '\n'.join(
                    f'  [{m["streaming_type"]}] {m["method_path"]} @ {m["offset"]}'
                    for m in (full_paths + known_methods)[:20]
                ),
                'exploit': (
                    'Probe each extracted method with grpcurl:\n'
                    '  grpcurl -plaintext -proto orka.proto <host>:<port> <Service/Method>\n'
                    'For unary methods, send empty request first to check auth requirement.'
                ),
            })

    def report(self):
        lines = ['=' * 60, 'SWIFT BINARY RE ANALYSIS', '=' * 60]

        if self._data:
            lines.append(f'Binary size: {len(self._data):,} bytes')

        if not self.findings:
            lines.append('No findings.')
            return '\n'.join(lines)

        crit  = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high  = [f for f in self.findings if f['severity'] == 'HIGH']
        other = [f for f in self.findings if f['severity'] not in ('CRITICAL', 'HIGH')]

        lines.append(
            f'\nFindings: {len(self.findings)} '
            f'({len(crit)} CRITICAL, {len(high)} HIGH, {len(other)} other)'
        )

        for f in crit + high + other:
            lines.append(f'\n[{f["severity"]}] {f["type"]}')
            lines.append(f'  {f["description"]}')
            if f.get('detail'):
                for dl in f['detail'].splitlines():
                    lines.append(f'    {dl}')
            if f.get('exploit'):
                lines.append(f'  EXPLOIT: {f["exploit"][:120]}')

        return '\n'.join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import json

    if len(sys.argv) < 2:
        print("Usage: swift_re.py <binary_path> [--json]")
        sys.exit(0)

    path    = sys.argv[1]
    as_json = '--json' in sys.argv

    ana    = SwiftREAnalyzer(path)
    result = ana.analyze()

    if as_json:
        # Serialize: convert bytes to hex strings
        def _default(o):
            if isinstance(o, bytes):
                return o.hex()
            raise TypeError
        print(json.dumps(result, indent=2, default=_default))
    else:
        print(ana.report())

        if result.get('vapor_routes'):
            print('\nVapor Routes:')
            for r in result['vapor_routes'][:20]:
                print(f'  {r["method_hint"] or "?"} {r["path"]}')

        if result.get('grpc_services'):
            print('\ngRPC Services:')
            for s in result['grpc_services']:
                print(f'  {s["service_name"]} @ {s["offset"]}')
                for m in s['methods_found']:
                    print(f'    .{m}')

        if result.get('security_strings'):
            print(f'\nSecurity Strings ({len(result["security_strings"])}):')
            for s in result['security_strings'][:20]:
                print(f'  [{s["pattern_type"]}] {s["string"][:80]} @ {s["offset"]}')

        if result.get('vapor_middleware'):
            print(f'\nVapor Middleware ({len(result["vapor_middleware"])}):')
            for m in result['vapor_middleware'][:15]:
                print(f'  [{m["pattern_type"]}] {m["middleware_type"][:60]}')

        if result.get('nio_handlers'):
            print(f'\nNIO Channel Handlers ({len(result["nio_handlers"])}):')
            for h in result['nio_handlers'][:15]:
                print(f'  [{h["protocol_type"]}] {h["handler_name"][:60]}')

        if result.get('codable_structs'):
            print(f'\nCodable Structs ({len(result["codable_structs"])}):')
            for c in result['codable_structs'][:20]:
                print(f'  {c["type_name"]} ({c["kind"]}) [{",".join(c["codable_ops"])}]')

        if result.get('grpc_methods'):
            print(f'\ngRPC Methods ({len(result["grpc_methods"])}):')
            for m in result['grpc_methods'][:25]:
                print(f'  [{m["streaming_type"]}] {m["method_path"]} ({m["source"]})')

        if result.get('licensespring_creds'):
            hi = [c for c in result['licensespring_creds'] if c['confidence'] == 'high']
            print(f'\nLicenseSpring Credentials ({len(result["licensespring_creds"])} total, {len(hi)} high-conf):')
            for c in hi[:10]:
                print(f'  [{c["type"]}] {c["value"][:60]} @ {c["offset"]}')

        async_p = result.get('async_patterns', {})
        if async_p.get('continuation_types') or async_p.get('actor_symbols'):
            print(f'\nAsync/Await Patterns:')
            print(f'  Continuation types: {len(async_p.get("continuation_types", []))}')
            print(f'  Actor symbols:      {len(async_p.get("actor_symbols", []))}')
            print(f'  Task imports hint:  {async_p.get("task_count_hint", 0)}')
            for s in async_p.get('async_string_hits', [])[:5]:
                print(f'  [{s["async_type"]}] {s["string"][:60]}')

        spm = result.get('spm_dependencies', {})
        if spm.get('classified'):
            print(f'\nSPM Dependencies ({len(spm["classified"])}):')
            for c in spm['classified'][:15]:
                print(f'  {c["name"]} [{c["dep_type"]}]')

        refl = result.get('reflection_strings', {})
        if refl.get('types'):
            print(f'\nReflection Type Names ({len(refl["types"])}):')
            for t in refl['types'][:20]:
                print(f'  {t}')
        if refl.get('properties'):
            print(f'Reflected Properties ({len(refl["properties"])}):')
            for p in refl['properties'][:20]:
                print(f'  .{p}')
