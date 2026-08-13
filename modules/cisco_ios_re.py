"""
cisco_ios_re.py — Cisco IOS/IOS-XE firmware binary reverse engineering module.
Stdlib only: struct, os, re, json, base64, hashlib, binascii.

Classes:
    CiscoIOSImage    — ELF/packed firmware parser, string/gadget/cred extraction
    IOSCrashDumpRE   — Crash dump parser + image-base recovery via ADRP analysis
    CiscoConfigRE    — Running/startup config parser for security findings

Top-level:
    analyze_ios_firmware(path) — detect artifact type, dispatch, return unified findings
"""

import struct
import os
import re
import json
import base64
import hashlib
import binascii

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ELF_MAGIC = b'\x7fELF'

# e_machine values
EM_MIPS   = 8
EM_386    = 3
EM_X86_64 = 0x3e
EM_AARCH64 = 0xb7  # ARM64

ARCH_MAP = {
    EM_MIPS:    'mips',
    EM_386:     'x86',
    EM_X86_64:  'x86_64',
    EM_AARCH64: 'arm64',
}

PT_LOAD = 1

# ARM64 gadget byte patterns (little-endian)
ARM64_RET        = b'\xc0\x03\x5f\xd6'
ARM64_BR_MASK    = 0xFFFFFC1F
ARM64_BR_VALUE   = 0xD61F0000   # br xN  — bits [9:5] = register
ARM64_BLR_MASK   = 0xFFFFFC1F
ARM64_BLR_VALUE  = 0xD63F0000   # blr xN
ARM64_LDP_FP_LR  = b'\xfd\x7b\xc1\xa8'   # ldp x29, x30, [sp], #16 (epilogue)

# MIPS gadgets (big-endian encoded)
MIPS_JR_RA  = b'\x03\xe0\x00\x08'   # jr ra
MIPS_JALR   = b'\x00\x00\xf8\x09'   # jalr ra, ... (common form)

CRED_PATTERNS = [
    (r'enable\s+(?:secret|password)\s+\S+',          'ENABLE_SECRET'),
    (r'username\s+\S+\s+(?:secret|password)\s+\S+',  'LOCAL_USER_CRED'),
    (r'snmp-server\s+community\s+\S+',               'SNMP_COMMUNITY'),
    (r'(?:password|passwd|secret|key)\s*[=:]\s*\S{4,}', 'GENERIC_CRED'),
    (r'jdbc:[a-z]+://[^\s]+',                         'JDBC_URL'),
    (r'ldaps?://[^\s]+',                              'LDAP_URL'),
    (r'tacacs-server\s+key\s+\S+',                   'TACACS_KEY'),
    (r'radius-server\s+key\s+\S+',                   'RADIUS_KEY'),
]

_CRED_RE = [(re.compile(p, re.IGNORECASE), label) for p, label in CRED_PATTERNS]

# String classification patterns
STRING_FLAGS = [
    (re.compile(r'(password|secret|enable|snmpv3|tacacs|radius|key\s+chain)', re.I), 'credential'),
    (re.compile(r'jdbc:|oracle:|mysql://|postgres://',                          re.I), 'jdbc_db'),
    (re.compile(r'(?:^|\s)(10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d',   re.I), 'rfc1918_ip'),
    (re.compile(r'BEGIN\s+(?:RSA|CERTIFICATE|PRIVATE)',                         re.I), 'crypto_material'),
    (re.compile(r'Version\s+\d|IOS-XE|Cisco IOS|Compiled',                     re.I), 'version_info'),
]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _read_file(path: str) -> bytes:
    with open(path, 'rb') as fh:
        return fh.read()


def _u16le(data: bytes, off: int) -> int:
    return struct.unpack_from('<H', data, off)[0]

def _u16be(data: bytes, off: int) -> int:
    return struct.unpack_from('>H', data, off)[0]

def _u32le(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]

def _u32be(data: bytes, off: int) -> int:
    return struct.unpack_from('>I', data, off)[0]

def _u64le(data: bytes, off: int) -> int:
    return struct.unpack_from('<Q', data, off)[0]

def _u64be(data: bytes, off: int) -> int:
    return struct.unpack_from('>Q', data, off)[0]


def _classify_string(s: str) -> list:
    tags = []
    for pattern, label in STRING_FLAGS:
        if pattern.search(s):
            tags.append(label)
    return tags


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# CiscoIOSImage
# ---------------------------------------------------------------------------

class CiscoIOSImage:
    """
    Parser for Cisco IOS/IOS-XE firmware images.

    Handles:
    - ELF binaries (ARM64 on Cavium/Marvell, x86_64 on ISR4k, MIPS on older platforms)
    - Raw/packed binaries (non-ELF; best-effort string/gadget extraction)

    Usage:
        img = CiscoIOSImage('/path/to/firmware.bin')
        if img.load():
            result = img.analyze()
            print(img.report())
    """

    def __init__(self, path: str):
        self.path = path
        self.data: bytes = b''
        self.arch: str = 'unknown'
        self.image_base = None          # lowest PT_LOAD p_vaddr for ELF
        self.sections: list = []        # [{name, offset, size, vaddr, flags}]
        self.strings: list = []         # [{string, offset, tags}]
        self.symbols: list = []         # [{name, vaddr, size, type}]
        self.gadgets: list = []         # [{vaddr, encoding_hex, mnemonic, offset_in_segment}]
        self.credentials: list = []     # [{pattern_type, value, offset}]
        self.build_info: dict = {}
        self._is_elf: bool = False
        self._ei_class: int = 0         # 1=32bit 2=64bit
        self._ei_data: int = 0          # 1=LE 2=BE
        self._elf_info: dict = {}

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def load(self) -> bool:
        """Read file into self.data. Returns True on success."""
        try:
            self.data = _read_file(self.path)
        except OSError as exc:
            return False
        if len(self.data) < 4:
            return False
        self._is_elf = self.data[:4] == ELF_MAGIC
        return True

    # ------------------------------------------------------------------
    # Architecture detection
    # ------------------------------------------------------------------

    def detect_arch(self) -> str:
        """
        Determine CPU architecture. For ELF reads e_machine.
        For raw binaries uses heuristic byte-pattern scanning.
        Sets self.arch and returns it.
        """
        if self._is_elf and len(self.data) >= 20:
            self._ei_class = self.data[4]
            self._ei_data  = self.data[5]
            is_le = (self._ei_data == 1)
            u16 = _u16le if is_le else _u16be
            e_machine = u16(self.data, 18)
            self.arch = ARCH_MAP.get(e_machine, 'unknown')
        else:
            # Heuristic: count ARM64 ret opcodes vs MIPS jr ra
            arm64_hits = self.data.count(ARM64_RET)
            mips_hits  = self.data.count(MIPS_JR_RA)
            if arm64_hits > mips_hits and arm64_hits > 4:
                self.arch = 'arm64'
            elif mips_hits > 4:
                self.arch = 'mips'
            else:
                self.arch = 'unknown'
        return self.arch

    # ------------------------------------------------------------------
    # ELF parsing
    # ------------------------------------------------------------------

    def parse_elf(self) -> dict:
        """
        Parse ELF header and program headers.
        Populates self.sections (from PT_LOAD segments) and self.image_base.
        Returns a dict with the key ELF header fields.
        """
        if not self._is_elf:
            return {}

        d = self.data
        is_64 = (self._ei_class == 2)
        is_le = (self._ei_data == 1)
        u16 = _u16le if is_le else _u16be
        u32 = _u32le if is_le else _u32be
        u64 = _u64le if is_le else _u64be

        info: dict = {}

        if is_64:
            # 64-bit ELF header layout
            if len(d) < 64:
                return {}
            info['ei_class']   = '64bit'
            info['ei_data']    = 'LE' if is_le else 'BE'
            info['e_type']     = u16(d, 16)
            info['e_machine']  = u16(d, 18)
            info['e_version']  = u32(d, 20)
            info['e_entry']    = u64(d, 24)
            info['e_phoff']    = u64(d, 32)
            info['e_shoff']    = u64(d, 40)
            info['e_flags']    = u32(d, 48)
            info['e_ehsize']   = u16(d, 52)
            info['e_phentsize']= u16(d, 54)
            info['e_phnum']    = u16(d, 56)
            info['e_shentsize']= u16(d, 58)
            info['e_shnum']    = u16(d, 60)
            info['e_shstrndx'] = u16(d, 62)
            phoff    = info['e_phoff']
            phentsize= info['e_phentsize']
            phnum    = info['e_phnum']
        else:
            # 32-bit ELF header layout
            if len(d) < 52:
                return {}
            info['ei_class']   = '32bit'
            info['ei_data']    = 'LE' if is_le else 'BE'
            info['e_type']     = u16(d, 16)
            info['e_machine']  = u16(d, 18)
            info['e_version']  = u32(d, 20)
            info['e_entry']    = u32(d, 24)
            info['e_phoff']    = u32(d, 28)
            info['e_shoff']    = u32(d, 32)
            info['e_flags']    = u32(d, 36)
            info['e_ehsize']   = u16(d, 40)
            info['e_phentsize']= u16(d, 42)
            info['e_phnum']    = u16(d, 44)
            info['e_shentsize']= u16(d, 46)
            info['e_shnum']    = u16(d, 48)
            info['e_shstrndx'] = u16(d, 50)
            phoff    = info['e_phoff']
            phentsize= info['e_phentsize']
            phnum    = info['e_phnum']

        # Program headers -> sections
        load_vaddrs = []
        for i in range(phnum):
            ph_off = phoff + i * phentsize
            if ph_off + phentsize > len(d):
                break

            if is_64:
                p_type   = u32(d, ph_off)
                p_flags  = u32(d, ph_off + 4)
                p_offset = u64(d, ph_off + 8)
                p_vaddr  = u64(d, ph_off + 16)
                p_filesz = u64(d, ph_off + 32)
                p_memsz  = u64(d, ph_off + 40)
            else:
                p_type   = u32(d, ph_off)
                p_offset = u32(d, ph_off + 4)
                p_vaddr  = u32(d, ph_off + 8)
                p_filesz = u32(d, ph_off + 16)
                p_memsz  = u32(d, ph_off + 20)
                p_flags  = u32(d, ph_off + 24)

            if p_type == PT_LOAD and p_filesz > 0:
                load_vaddrs.append(p_vaddr)
                flags_str = ''
                if p_flags & 4: flags_str += 'R'
                if p_flags & 2: flags_str += 'W'
                if p_flags & 1: flags_str += 'X'
                seg_name = 'LOAD_{:d}'.format(len(self.sections))
                self.sections.append({
                    'name':   seg_name,
                    'offset': p_offset,
                    'size':   p_filesz,
                    'vaddr':  p_vaddr,
                    'flags':  flags_str,
                })

        if load_vaddrs:
            self.image_base = min(load_vaddrs)

        info['image_base'] = self.image_base
        info['segment_count'] = len(self.sections)
        self._elf_info = info
        return info

    # ------------------------------------------------------------------
    # String extraction
    # ------------------------------------------------------------------

    def extract_strings(self, min_len: int = 6) -> list:
        """
        Scan self.data for printable ASCII sequences >= min_len.
        Populates and returns self.strings as list of dicts:
            {string, offset, tags}
        """
        results = []
        data = self.data
        n = len(data)
        i = 0
        while i < n:
            if 0x20 <= data[i] <= 0x7e:
                j = i
                while j < n and 0x20 <= data[j] <= 0x7e:
                    j += 1
                if j - i >= min_len:
                    s = data[i:j].decode('ascii', errors='replace')
                    tags = _classify_string(s)
                    results.append({'string': s, 'offset': i, 'tags': tags})
                i = j
            else:
                i += 1
        self.strings = results
        return results

    # ------------------------------------------------------------------
    # ROP gadget finder
    # ------------------------------------------------------------------

    def find_gadgets(self) -> list:
        """
        Scan executable segments (or whole image if no sections parsed) for
        ARM64 and MIPS ROP gadgets.

        ARM64 patterns:
          ret           — 0xd65f03c0 LE: c0 03 5f d6
          br xN         — 0xd61f0000 + (N<<5)
          blr xN        — 0xd63f0000 + (N<<5)
          ldp x29, x30  — fd 7b c1 a8
        MIPS patterns:
          jr ra         — 03 e0 00 08
          jalr          — 00 00 f8 09

        Returns list of {vaddr, encoding_hex, mnemonic, offset_in_segment}.
        """
        gadgets = []

        # Determine segments to scan (executable only)
        exec_segs = [s for s in self.sections if 'X' in s.get('flags', '')]
        if not exec_segs:
            # Fallback: treat whole image as one segment at offset 0, vaddr 0
            exec_segs = [{'offset': 0, 'size': len(self.data),
                          'vaddr': self.image_base or 0, 'flags': 'RX'}]

        data = self.data

        for seg in exec_segs:
            seg_off   = seg['offset']
            seg_size  = seg['size']
            seg_vaddr = seg['vaddr']
            seg_end   = seg_off + seg_size

            if seg_off >= len(data):
                continue
            seg_end = min(seg_end, len(data))

            if self.arch in ('arm64', 'unknown'):
                # ARM64: 4-byte aligned scan
                pos = seg_off
                while pos + 4 <= seg_end:
                    chunk = data[pos:pos+4]
                    vaddr = seg_vaddr + (pos - seg_off)
                    hex_enc = binascii.hexlify(chunk).decode()

                    if chunk == ARM64_RET:
                        gadgets.append({
                            'vaddr': vaddr,
                            'encoding_hex': hex_enc,
                            'mnemonic': 'ret',
                            'offset_in_segment': pos - seg_off,
                        })
                    elif chunk == ARM64_LDP_FP_LR:
                        gadgets.append({
                            'vaddr': vaddr,
                            'encoding_hex': hex_enc,
                            'mnemonic': 'ldp x29, x30, [sp], #16',
                            'offset_in_segment': pos - seg_off,
                        })
                    else:
                        # Decode as u32 LE and check br/blr
                        word = struct.unpack_from('<I', chunk)[0]
                        if (word & ARM64_BR_MASK) == ARM64_BR_VALUE:
                            reg = (word >> 5) & 0x1f
                            gadgets.append({
                                'vaddr': vaddr,
                                'encoding_hex': hex_enc,
                                'mnemonic': 'br x{:d}'.format(reg),
                                'offset_in_segment': pos - seg_off,
                            })
                        elif (word & ARM64_BLR_MASK) == ARM64_BLR_VALUE:
                            reg = (word >> 5) & 0x1f
                            gadgets.append({
                                'vaddr': vaddr,
                                'encoding_hex': hex_enc,
                                'mnemonic': 'blr x{:d}'.format(reg),
                                'offset_in_segment': pos - seg_off,
                            })
                    pos += 4

            if self.arch in ('mips', 'unknown'):
                # MIPS: 4-byte aligned scan
                pos = seg_off
                while pos + 4 <= seg_end:
                    chunk = data[pos:pos+4]
                    vaddr = seg_vaddr + (pos - seg_off)
                    hex_enc = binascii.hexlify(chunk).decode()
                    if chunk == MIPS_JR_RA:
                        gadgets.append({
                            'vaddr': vaddr,
                            'encoding_hex': hex_enc,
                            'mnemonic': 'jr ra',
                            'offset_in_segment': pos - seg_off,
                        })
                    elif chunk == MIPS_JALR:
                        gadgets.append({
                            'vaddr': vaddr,
                            'encoding_hex': hex_enc,
                            'mnemonic': 'jalr ra',
                            'offset_in_segment': pos - seg_off,
                        })
                    pos += 4

        self.gadgets = gadgets
        return gadgets

    # ------------------------------------------------------------------
    # Credential hunter
    # ------------------------------------------------------------------

    def hunt_credentials(self) -> list:
        """
        Apply CRED_PATTERNS against extracted strings.
        Populates and returns self.credentials as list of
        {pattern_type, value, offset, context}.
        """
        if not self.strings:
            self.extract_strings()

        found = []
        for entry in self.strings:
            s = entry['string']
            off = entry['offset']
            for pattern_re, label in _CRED_RE:
                m = pattern_re.search(s)
                if m:
                    found.append({
                        'pattern_type': label,
                        'value': m.group(0),
                        'offset': off,
                        'context': s[:120],
                    })
        self.credentials = found
        return found

    # ------------------------------------------------------------------
    # Build info extraction
    # ------------------------------------------------------------------

    def extract_build_info(self) -> dict:
        """
        Extract version strings, build timestamps, platform identifiers
        from self.strings. Returns and stores self.build_info.
        """
        if not self.strings:
            self.extract_strings()

        version_re   = re.compile(r'(?:Version\s+[\d.()A-Za-z]+)', re.I)
        iosxe_re     = re.compile(r'IOS[- ]XE\s+Software[^\n]{0,80}', re.I)
        ios_re       = re.compile(r'Cisco\s+IOS\s+Software[^\n]{0,80}', re.I)
        compiled_re  = re.compile(r'Compiled\s+\w+\s+\d+-\w+-\d+\s+\d+:\d+[^\n]{0,60}', re.I)
        platform_re  = re.compile(r'(?:ISR|ASR|CSR|Catalyst|Nexus|NCS|CRS)\d[\dA-Za-z\-]*', re.I)

        info = {
            'versions': [],
            'build_timestamps': [],
            'platforms': [],
            'raw_version_strings': [],
        }

        for entry in self.strings:
            s = entry['string']
            for m in version_re.finditer(s):
                v = m.group(0).strip()
                if v not in info['versions']:
                    info['versions'].append(v)
            for m in iosxe_re.finditer(s):
                v = m.group(0).strip()
                if v not in info['raw_version_strings']:
                    info['raw_version_strings'].append(v)
            for m in ios_re.finditer(s):
                v = m.group(0).strip()
                if v not in info['raw_version_strings']:
                    info['raw_version_strings'].append(v)
            for m in compiled_re.finditer(s):
                ts = m.group(0).strip()
                if ts not in info['build_timestamps']:
                    info['build_timestamps'].append(ts)
            for m in platform_re.finditer(s):
                plat = m.group(0)
                if plat not in info['platforms']:
                    info['platforms'].append(plat)

        self.build_info = info
        return info

    # ------------------------------------------------------------------
    # Top-level analysis
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """
        Run all analysis stages. Returns unified findings dict.
        """
        if not self.data:
            self.load()

        self.detect_arch()

        elf_info = {}
        if self._is_elf:
            elf_info = self.parse_elf()

        strings  = self.extract_strings()
        gadgets  = self.find_gadgets()
        creds    = self.hunt_credentials()
        build    = self.extract_build_info()

        # Flag interesting strings for summary
        flagged = [s for s in strings if s['tags']]

        return {
            'path': self.path,
            'size': len(self.data),
            'sha256': _sha256_hex(self.data),
            'is_elf': self._is_elf,
            'arch': self.arch,
            'image_base': self.image_base,
            'elf_info': elf_info,
            'sections': self.sections,
            'string_count': len(strings),
            'flagged_strings': flagged[:200],  # cap for JSON sanity
            'gadget_count': len(gadgets),
            'gadgets_sample': gadgets[:50],
            'credentials': creds,
            'build_info': build,
        }

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def report(self) -> str:
        """Return a plain-text summary of analysis results."""
        lines = []
        lines.append('=== CiscoIOSImage Report ===')
        lines.append('Path     : {}'.format(self.path))
        lines.append('Size     : {:,} bytes'.format(len(self.data)))
        lines.append('SHA256   : {}'.format(_sha256_hex(self.data)))
        lines.append('Type     : {}'.format('ELF' if self._is_elf else 'raw/packed'))
        lines.append('Arch     : {}'.format(self.arch))
        lines.append('ImageBase: {}'.format(
            '0x{:x}'.format(self.image_base) if self.image_base is not None else 'N/A'))

        lines.append('')
        lines.append('--- Build Info ---')
        for k, v in self.build_info.items():
            if v:
                lines.append('  {} : {}'.format(k, v))

        lines.append('')
        lines.append('--- Segments ({}) ---'.format(len(self.sections)))
        for s in self.sections:
            lines.append('  {:20s}  vaddr=0x{:x}  size={:,}  flags={}'.format(
                s['name'], s['vaddr'], s['size'], s['flags']))

        lines.append('')
        lines.append('--- Strings ---')
        lines.append('  Total: {:,}'.format(len(self.strings)))
        flagged = [s for s in self.strings if s['tags']]
        lines.append('  Flagged: {:,}'.format(len(flagged)))
        for s in flagged[:30]:
            lines.append('    [{}] offset=0x{:x}  {!r}'.format(
                ','.join(s['tags']), s['offset'], s['string'][:80]))

        lines.append('')
        lines.append('--- ROP Gadgets ({}) ---'.format(len(self.gadgets)))
        mnemonic_counts: dict = {}
        for g in self.gadgets:
            mnemonic_counts[g['mnemonic']] = mnemonic_counts.get(g['mnemonic'], 0) + 1
        for mnem, cnt in sorted(mnemonic_counts.items(), key=lambda x: -x[1]):
            lines.append('  {:30s}  {:6,} occurrences'.format(mnem, cnt))

        lines.append('')
        lines.append('--- Credentials ({}) ---'.format(len(self.credentials)))
        for c in self.credentials:
            lines.append('  [{}] offset=0x{:x}  {!r}'.format(
                c['pattern_type'], c['offset'], c['value'][:80]))

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# IOSCrashDumpRE
# ---------------------------------------------------------------------------

class IOSCrashDumpRE:
    """
    Parses Cisco IOS crash dump files (text format) and recovers the firmware
    image base address using ARM64 ADRP-page math.

    Usage:
        cr = IOSCrashDumpRE('/var/crashinfo/dump.txt')
        data = cr.analyze()
        print(data)
    """

    # Regex patterns for crash dump fields
    _PC_RE   = re.compile(r'\bPC\s*[=:]\s*(0x[0-9a-fA-F]+)', re.I)
    _LR_RE   = re.compile(r'\bLR\s*[=:]\s*(0x[0-9a-fA-F]+)', re.I)
    _SP_RE   = re.compile(r'\bSP\s*[=:]\s*(0x[0-9a-fA-F]+)', re.I)
    _CPSR_RE = re.compile(r'\bCPSR\s*[=:]\s*(0x[0-9a-fA-F]+)', re.I)
    _REG_RE  = re.compile(r'\b(x\d{1,2})\s*[=:]\s*(0x[0-9a-fA-F]+)', re.I)
    _FAULT_INSN_RE = re.compile(r'Faulting\s+instruction\s*:\s*(0x[0-9a-fA-F]+)', re.I)
    _EXCEPT_CLASS_RE = re.compile(r'Exception\s+class\s*=\s*(\S+)', re.I)

    # Backtrace: GDB-style: #N  0xADDR in symbol ()
    _BT_RE   = re.compile(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+(?:in\s+)?(\S+)', re.I)
    # Alternative: plain hex+symbol
    _BT_ALT  = re.compile(r'\b(0x[0-9a-fA-F]{8,16})\s+<([^>]+)>', re.I)
    # Cisco IOS native backtrace format: "0: 0x..." or "  n:  ADDR (symbol+offset)"
    _BT_IOS  = re.compile(r'^\s*(\d+):\s+(0x[0-9a-fA-F]+)', re.I | re.M)

    def __init__(self, path_or_text: str, is_file: bool = True):
        self.is_file = is_file
        if is_file:
            self.path = path_or_text
            self.text = ''
        else:
            self.path = '<inline>'
            self.text = path_or_text

        self.pc    = None
        self.lr    = None
        self.sp    = None
        self.cpsr  = None
        self.registers: dict = {}
        self.stack_frames: list = []
        self.adrp_candidates: list = []
        self.exception_class = None
        self.faulting_insn   = None

    def _load_text(self):
        if self.is_file and not self.text:
            try:
                with open(self.path, 'r', errors='replace') as fh:
                    self.text = fh.read()
            except OSError:
                self.text = ''

    # ------------------------------------------------------------------
    # parse
    # ------------------------------------------------------------------

    def parse(self) -> dict:
        """
        Extract PC, LR, SP, CPSR, x0-x30 registers, stack frames,
        exception class, and faulting instruction from the crash dump text.
        """
        self._load_text()
        text = self.text

        def _hex(s: str) -> int:
            try:
                return int(s, 16)
            except (ValueError, TypeError):
                return 0

        m = self._PC_RE.search(text)
        if m:
            self.pc = _hex(m.group(1))

        m = self._LR_RE.search(text)
        if m:
            self.lr = _hex(m.group(1))

        m = self._SP_RE.search(text)
        if m:
            self.sp = _hex(m.group(1))

        m = self._CPSR_RE.search(text)
        if m:
            self.cpsr = _hex(m.group(1))

        for m in self._REG_RE.finditer(text):
            reg_name = m.group(1).lower()
            self.registers[reg_name] = _hex(m.group(2))

        m = self._EXCEPT_CLASS_RE.search(text)
        if m:
            self.exception_class = m.group(1)

        m = self._FAULT_INSN_RE.search(text)
        if m:
            self.faulting_insn = _hex(m.group(1))

        # Backtrace
        frames = []
        for m in self._BT_RE.finditer(text):
            frames.append({
                'frame': int(m.group(1)),
                'addr':  _hex(m.group(2)),
                'symbol': m.group(3),
            })
        if not frames:
            for m in self._BT_IOS.finditer(text):
                frames.append({
                    'frame': int(m.group(1)),
                    'addr':  _hex(m.group(2)),
                    'symbol': None,
                })
        if not frames:
            for m in self._BT_ALT.finditer(text):
                frames.append({
                    'frame': len(frames),
                    'addr':  _hex(m.group(1)),
                    'symbol': m.group(2),
                })
        self.stack_frames = sorted(frames, key=lambda f: f['frame'])

        return {
            'pc':              self.pc,
            'lr':              self.lr,
            'sp':              self.sp,
            'cpsr':            self.cpsr,
            'exception_class': self.exception_class,
            'faulting_insn':   self.faulting_insn,
            'registers':       dict(self.registers),
            'stack_frames':    self.stack_frames,
            'adrp_candidates': self.adrp_candidates,
        }

    # ------------------------------------------------------------------
    # recover_image_base
    # ------------------------------------------------------------------

    def recover_image_base(self, known_symbol_offset: int = None) -> dict:
        """
        Estimate the firmware image base from the crash PC.

        Method:
          1. pc_page = PC & ~0xfff   (4K ARM64 page alignment)
          2. If known_symbol_offset provided:
               image_base = pc_page - known_symbol_offset
               confidence = 'high'
          3. Else:
               Scan stack frames for the lowest plausible kernel/text address,
               align it, use as lower bound.
               confidence = 'low'

        Returns {image_base_estimate, confidence, method, pc, pc_page}
        """
        result = {
            'image_base_estimate': None,
            'confidence':          'none',
            'method':              None,
            'pc':                  self.pc,
            'pc_page':             None,
        }

        if self.pc is None:
            return result

        pc_page = self.pc & ~0xfff
        result['pc_page'] = pc_page

        if known_symbol_offset is not None:
            image_base = pc_page - known_symbol_offset
            result['image_base_estimate'] = image_base
            result['confidence']          = 'high'
            result['method']              = 'pc_page_minus_known_offset'
            self.adrp_candidates.append({
                'type':            'pc_adrp',
                'pc':              self.pc,
                'pc_page':         pc_page,
                'known_offset':    known_symbol_offset,
                'image_base':      image_base,
            })
            return result

        # Without a known symbol offset, use pc_page as the lower bound.
        # Try to narrow it further using the lowest stack-frame address.
        candidate_addrs = [f['addr'] for f in self.stack_frames if f['addr'] > 0]
        if self.lr:
            candidate_addrs.append(self.lr)

        # Filter out obvious stack/data addresses (heuristic: text segment
        # typically in low half of 64-bit address space, or kernel mapping)
        text_candidates = [a for a in candidate_addrs if 0 < a <= 0xffffffffffffffff]

        if text_candidates:
            min_addr = min(text_candidates)
            min_page = min_addr & ~0xfff
            # image_base is at or below the lowest observed text address
            result['image_base_estimate'] = min_page
            result['confidence']          = 'medium'
            result['method']              = 'lowest_frame_addr_page'
        else:
            result['image_base_estimate'] = pc_page
            result['confidence']          = 'low'
            result['method']              = 'pc_page_lower_bound'

        self.adrp_candidates.append({
            'type':       'pc_page_bound',
            'pc':         self.pc,
            'pc_page':    pc_page,
            'estimate':   result['image_base_estimate'],
            'confidence': result['confidence'],
        })

        return result

    # ------------------------------------------------------------------
    # decode_backtrace
    # ------------------------------------------------------------------

    def decode_backtrace(self) -> list:
        """
        Return parsed stack frames (populated by parse()).
        Each frame: {frame, addr, symbol}
        """
        return list(self.stack_frames)

    # ------------------------------------------------------------------
    # analyze
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """Run parse + recover_image_base. Returns unified findings dict."""
        parsed = self.parse()
        base   = self.recover_image_base()
        bt     = self.decode_backtrace()
        return {
            'source':             self.path,
            'parsed':             parsed,
            'image_base_recovery': base,
            'backtrace':          bt,
        }


# ---------------------------------------------------------------------------
# CiscoConfigRE
# ---------------------------------------------------------------------------

class CiscoConfigRE:
    """
    Parses Cisco IOS/IOS-XE running or startup configuration text for
    security-relevant findings.

    Usage:
        with open('running-config.txt') as fh:
            cfg = CiscoConfigRE(fh.read())
        result = cfg.analyze()
        print(cfg.report())
    """

    # Weak configuration patterns: (regex, severity, description)
    WEAK_CONFIG_PATTERNS = [
        (re.compile(r'^no\s+service\s+password-encryption', re.M | re.I),
         'HIGH', 'Passwords stored in plaintext (no service password-encryption)'),
        (re.compile(r'^no\s+aaa\s+new-model', re.M | re.I),
         'MEDIUM', 'AAA not enabled (no aaa new-model)'),
        (re.compile(r'^snmp-server\s+community\s+(?:public|private)\b', re.M | re.I),
         'CRITICAL', 'Default SNMP community string in use'),
        (re.compile(r'^no\s+ip\s+ssh\s+version', re.M | re.I),
         'MEDIUM', 'SSH version not explicitly set to 2'),
        (re.compile(r'^\s*transport\s+input\s+(?:all|telnet)', re.M | re.I),
         'HIGH', 'Telnet transport allowed on VTY/console'),
        (re.compile(r'^ip\s+http\s+server\b', re.M | re.I),
         'HIGH', 'Unencrypted HTTP server enabled'),
        (re.compile(r'^\s*exec-timeout\s+0\s+0', re.M | re.I),
         'MEDIUM', 'Session exec-timeout set to never (0 0)'),
        (re.compile(r'^no\s+exec-timeout', re.M | re.I),
         'MEDIUM', 'exec-timeout disabled (no exec-timeout)'),
        (re.compile(r'^\s*config-register\s+0x2142\b', re.M | re.I),
         'CRITICAL', 'config-register 0x2142 set — ROMMON password bypass possible'),
        (re.compile(r'^\s*service\s+telnet', re.M | re.I),
         'HIGH', 'Telnet service explicitly enabled'),
        (re.compile(r'^no\s+ip\s+domain.lookup', re.M | re.I),
         'INFO', 'DNS lookup disabled (no ip domain-lookup)'),
        (re.compile(r'^\s*logging\s+on\b', re.M | re.I),
         'INFO', 'Logging enabled'),
        (re.compile(r'^\s*cdp\s+run\b|^cdp\s+enable\b', re.M | re.I),
         'LOW', 'CDP running (layer 2 recon vector)'),
        (re.compile(r'^\s*ip\s+proxy-arp\b', re.M | re.I),
         'LOW', 'Proxy ARP enabled'),
        (re.compile(r'^no\s+ip\s+source-route', re.M | re.I),
         'INFO', 'IP source routing disabled (good)'),
        (re.compile(r'^ip\s+source-route\b', re.M | re.I),
         'MEDIUM', 'IP source routing enabled'),
    ]

    # Topology extraction patterns
    _IFACE_RE   = re.compile(r'^interface\s+(\S+)', re.M | re.I)
    _IP_ADDR_RE = re.compile(r'^\s+ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', re.M | re.I)
    _BGP_PEER_RE = re.compile(r'^\s*neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remote-as\s+(\d+)', re.M | re.I)
    _OSPF_RE    = re.compile(r'^router\s+ospf\s+(\d+)', re.M | re.I)
    _EIGRP_RE   = re.compile(r'^router\s+eigrp\s+(\d+)', re.M | re.I)
    _BGP_AS_RE  = re.compile(r'^router\s+bgp\s+(\d+)', re.M | re.I)
    _VRF_RE     = re.compile(r'^(?:ip\s+)?vrf\s+(?:definition\s+)?(\S+)', re.M | re.I)
    _VLAN_RE    = re.compile(r'^vlan\s+(\d+)', re.M | re.I)
    _HOSTNAME_RE = re.compile(r'^hostname\s+(\S+)', re.M | re.I)

    def __init__(self, config_text: str):
        self.text = config_text
        self._credentials: list = []
        self._weak_configs: list = []
        self._topology: dict = {}

    # ------------------------------------------------------------------
    # extract_credentials
    # ------------------------------------------------------------------

    def extract_credentials(self) -> list:
        """
        Extract credential-like entries from config text.
        Returns list of {type, value, line_no, raw_line}.
        """
        found = []
        lines = self.text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            for pattern_re, label in _CRED_RE:
                m = pattern_re.search(stripped)
                if m:
                    found.append({
                        'type':     label,
                        'value':    m.group(0),
                        'line_no':  lineno,
                        'raw_line': stripped[:200],
                    })
                    break  # one label per line

        # Extra: crypto key names, VPN PSK
        vpn_psk_re  = re.compile(r'^\s*pre-shared-key\s+\S+', re.M | re.I)
        crypto_re   = re.compile(r'^\s*crypto\s+key\s+\S+\s+\S+', re.M | re.I)
        ntp_key_re  = re.compile(r'^\s*ntp\s+authentication-key\s+\d+\s+\S+\s+\S+', re.M | re.I)

        for m in vpn_psk_re.finditer(self.text):
            s = m.group(0).strip()
            found.append({'type': 'VPN_PSK', 'value': s, 'line_no': None, 'raw_line': s[:200]})
        for m in crypto_re.finditer(self.text):
            s = m.group(0).strip()
            found.append({'type': 'CRYPTO_KEY', 'value': s, 'line_no': None, 'raw_line': s[:200]})
        for m in ntp_key_re.finditer(self.text):
            s = m.group(0).strip()
            found.append({'type': 'NTP_AUTH_KEY', 'value': s, 'line_no': None, 'raw_line': s[:200]})

        self._credentials = found
        return found

    # ------------------------------------------------------------------
    # find_weak_config
    # ------------------------------------------------------------------

    def find_weak_config(self) -> list:
        """
        Check config text against WEAK_CONFIG_PATTERNS.
        Returns list of {severity, description, match, line_no}.
        """
        findings = []
        for pattern_re, severity, description in self.WEAK_CONFIG_PATTERNS:
            for m in pattern_re.finditer(self.text):
                # Determine line number
                line_no = self.text[:m.start()].count('\n') + 1
                findings.append({
                    'severity':    severity,
                    'description': description,
                    'match':       m.group(0).strip()[:200],
                    'line_no':     line_no,
                })
        self._weak_configs = findings
        return findings

    # ------------------------------------------------------------------
    # map_network_topology
    # ------------------------------------------------------------------

    def map_network_topology(self) -> dict:
        """
        Extract: interfaces + IPs, routing protocols, BGP peers, VRFs, VLANs,
        hostname.
        Returns topology dict.
        """
        text = self.text

        # Hostname
        hostname = None
        m = self._HOSTNAME_RE.search(text)
        if m:
            hostname = m.group(1)

        # Interfaces
        interfaces = []
        # Split config by 'interface' blocks
        iface_blocks = re.split(r'^(?=interface\s)', text, flags=re.M | re.I)
        for block in iface_blocks:
            iface_m = self._IFACE_RE.match(block)
            if not iface_m:
                continue
            iface_name = iface_m.group(1)
            ip_entries = []
            for ip_m in self._IP_ADDR_RE.finditer(block):
                ip_entries.append({
                    'address': ip_m.group(1),
                    'mask':    ip_m.group(2),
                })
            shutdown = bool(re.search(r'^\s*shutdown\b', block, re.M | re.I))
            desc_m = re.search(r'^\s*description\s+(.+)', block, re.M | re.I)
            interfaces.append({
                'name':        iface_name,
                'ip_addresses': ip_entries,
                'shutdown':    shutdown,
                'description': desc_m.group(1).strip() if desc_m else None,
            })

        # Routing protocols
        routing = []
        for m in self._OSPF_RE.finditer(text):
            routing.append({'protocol': 'OSPF', 'process': m.group(1)})
        for m in self._EIGRP_RE.finditer(text):
            routing.append({'protocol': 'EIGRP', 'as': m.group(1)})
        for m in self._BGP_AS_RE.finditer(text):
            routing.append({'protocol': 'BGP', 'local_as': m.group(1)})

        # BGP peers
        bgp_peers = []
        for m in self._BGP_PEER_RE.finditer(text):
            bgp_peers.append({'neighbor': m.group(1), 'remote_as': m.group(2)})

        # VRFs
        vrfs = list({m.group(1) for m in self._VRF_RE.finditer(text)})

        # VLANs
        vlans = list({m.group(1) for m in self._VLAN_RE.finditer(text)})

        topo = {
            'hostname':   hostname,
            'interfaces': interfaces,
            'routing':    routing,
            'bgp_peers':  bgp_peers,
            'vrfs':       vrfs,
            'vlans':      vlans,
        }
        self._topology = topo
        return topo

    # ------------------------------------------------------------------
    # analyze
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """Run all extractions. Returns unified findings dict."""
        creds    = self.extract_credentials()
        weak     = self.find_weak_config()
        topology = self.map_network_topology()

        # Severity summary
        sev_counts: dict = {}
        for w in weak:
            sev_counts[w['severity']] = sev_counts.get(w['severity'], 0) + 1

        return {
            'source':          '<config_text>',
            'credentials':     creds,
            'weak_configs':    weak,
            'severity_summary': sev_counts,
            'topology':        topology,
        }

    # ------------------------------------------------------------------
    # report
    # ------------------------------------------------------------------

    def report(self) -> str:
        """Return plain-text security summary."""
        lines = []
        lines.append('=== CiscoConfigRE Report ===')

        hostname = self._topology.get('hostname') if self._topology else None
        lines.append('Hostname : {}'.format(hostname or 'unknown'))

        lines.append('')
        lines.append('--- Weak Configurations ({}) ---'.format(len(self._weak_configs)))
        # Sort by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_weak = sorted(self._weak_configs,
                             key=lambda w: sev_order.get(w['severity'], 99))
        for w in sorted_weak:
            lines.append('  [{}] line {:5}  {}'.format(
                w['severity'], w['line_no'] or '?', w['description']))
            lines.append('         > {}'.format(w['match'][:100]))

        lines.append('')
        lines.append('--- Credentials ({}) ---'.format(len(self._credentials)))
        for c in self._credentials:
            lines.append('  [{}] line {:5}  {}'.format(
                c['type'], c['line_no'] or '?', c['raw_line'][:80]))

        lines.append('')
        lines.append('--- Topology ---')
        topo = self._topology
        if topo:
            lines.append('  Interfaces : {}'.format(len(topo.get('interfaces', []))))
            lines.append('  VRFs       : {}'.format(topo.get('vrfs', [])))
            lines.append('  VLANs      : {}'.format(topo.get('vlans', [])))
            lines.append('  Routing    : {}'.format(topo.get('routing', [])))
            lines.append('  BGP Peers  : {}'.format(topo.get('bgp_peers', [])))

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# analyze_ios_firmware — top-level dispatcher
# ---------------------------------------------------------------------------

def analyze_ios_firmware(path: str) -> dict:
    """
    Detect artifact type and dispatch to the appropriate analyzer.

    Detection order:
      1. ELF magic -> CiscoIOSImage
      2. Text file heuristics:
         - Crash dump signatures (PC=, LR=, Exception class=) -> IOSCrashDumpRE
         - Config signatures (interface, ip address, hostname) -> CiscoConfigRE
      3. Fallback -> CiscoIOSImage (raw binary)

    Returns unified findings dict with 'artifact_type' key.
    """
    try:
        raw = _read_file(path)
    except OSError as exc:
        return {'error': str(exc), 'path': path}

    # Determine if this looks like text
    def _is_text(data: bytes) -> bool:
        sample = data[:4096]
        try:
            sample.decode('utf-8')
            printable = sum(1 for b in sample if 0x09 <= b <= 0x0d or 0x20 <= b <= 0x7e)
            return printable / max(len(sample), 1) > 0.85
        except UnicodeDecodeError:
            return False

    artifact_type = 'unknown'
    result = {}

    if raw[:4] == ELF_MAGIC:
        artifact_type = 'elf_firmware'
        img = CiscoIOSImage(path)
        img.load()
        result = img.analyze()

    elif _is_text(raw):
        text = raw.decode('utf-8', errors='replace')

        # Crash dump detection
        crash_score = 0
        for sig in ('PC=', 'PC :', 'LR=', 'LR :', 'Exception class', 'Faulting instruction',
                    'Stack trace', 'Backtrace', 'SIGABRT', 'SIGSEGV', 'Signal'):
            if sig in text:
                crash_score += 1

        # Config detection
        config_score = 0
        for sig in ('interface ', 'ip address ', 'hostname ', 'router ', 'no shutdown',
                    'line vty', 'aaa ', 'service password'):
            if sig in text:
                config_score += 1

        if crash_score >= 2 and crash_score > config_score:
            artifact_type = 'crash_dump'
            cr = IOSCrashDumpRE(path, is_file=True)
            result = cr.analyze()

        elif config_score >= 3:
            artifact_type = 'ios_config'
            cfg = CiscoConfigRE(text)
            result = cfg.analyze()
            result['source'] = path

        else:
            # Ambiguous text — try config parser
            artifact_type = 'ios_config'
            cfg = CiscoConfigRE(text)
            result = cfg.analyze()
            result['source'] = path

    else:
        # Raw/packed binary
        artifact_type = 'raw_firmware'
        img = CiscoIOSImage(path)
        img.load()
        result = img.analyze()

    result['artifact_type'] = artifact_type
    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: cisco_ios_re.py <firmware.bin|crash.txt|running-config.txt>")
        sys.exit(1)

    result = analyze_ios_firmware(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))
