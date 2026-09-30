"""
library_inventory.py — Batch triage of native ELF libraries in a directory.

Produces a per-library summary table:
    size_kb / arch / exports / internal_funcs / jni_count /
    has_jni_on_load / security_score / security_strings_sample

Designed for Android IoT targets where a single APK ships 20-80 native .so
files. Running the inventory at session start replaces the repeated ad-hoc
BL-target enumeration scripts written per-engagement.

Usage:
    from ablation.analyzers.library_inventory import LibraryInventory

    # Whole directory
    inv = LibraryInventory.from_dir('/tmp/target/lib/arm64-v8a/')
    entries = inv.scan()
    print(LibraryInventory.report(entries))

    # Filter to security-relevant only (score >= 3)
    for e in LibraryInventory.security_entries(entries):
        print(e.path, e.security_strings[:3])

    # Single library
    entry = LibraryInventory.scan_one('/tmp/target/lib/arm64-v8a/libfoo.so')
    print(entry)

Security score (0-10):
    +3  credential-field format strings found (sk=%s, password=%s, token=%s …)
    +2  credential-field name alone, or exec/command sink strings found
    +1  crypto-primitive strings found (AES, HMAC, SHA256, RSA …)
    +2  JNI count >= 50 (large attack surface)
    +1  JNI count >= 10
    +1  internal function count >= 200
    +1  internal function count >= 1000 (extra)

Strings are matched against two corpora:
    CRED_PATTERNS   — credential field names followed by = or : or %
    CRYPTO_PATTERNS — crypto primitive names (whole-word where practical)
    EXEC_PATTERNS   — command execution sinks

Known false-positive contexts are filtered before scoring.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Security string corpora
# ---------------------------------------------------------------------------

# Credential field patterns — field name followed by = : or a printf specifier.
# Match against the full string, case-insensitive.
_CRED_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r'\bsk[=:%]',                  # sk=val  sk:%s  sk%s
        r'\bak[=:%]',                  # ak=val  ak:%s
        r'\bpassword\s*[=:%]',
        r'\bpasswd\s*[=:%]',
        r'\bpwd\s*[=:%]',
        r'\btoken\s*[=:%]',
        r'\bsecret\s*[=:%]',
        r'\bapikey\s*[=:%]',
        r'\bapi_key\s*[=:%]',
        r'\bauthkey\s*[=:%]',
        r'\bsecretkey\s*[=:%]',
        r'\bsecret_key\s*[=:%]',
        r'\baccesskey\s*[=:%]',
        r'\baccess_key\s*[=:%]',
        r'\bcredential\s*[=:%]',
        r'OSSAccessKeyId',
        r'X-Amz-Security-Token',
        r'security-token\s*=',
        r'\bprivateKey\s*[=:%]',
        r'\bprivate_key\s*[=:%]',
        r'BEGIN (RSA |EC |PRIVATE )',     # PEM headers
    ]
]

# Crypto-primitive names (whole-word or short enough to be unambiguous)
_CRYPTO_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r'\bAES[-_]?(?:128|256|192|ECB|CBC|CTR|GCM)\b',
        r'\bAES\b',
        r'\bHMAC[-_]?SHA',
        r'\bHMAC\b',
        r'\bSHA-?256\b',
        r'\bSHA-?1\b',
        r'\bSHA512\b',
        r'\bRSA\b',
        r'\bECDH\b',
        r'\bECC\b',
        r'\bsecp256k1\b',
        r'\bXTEA\b',
        r'\bmbedtls_',
        r'\bopenssl\b',
        r'armv8 AES',
        r'\bDTLS\b',
        r'\bSTUN\b',
        r'\bPPCS\b',                    # PPCS P2P auth (IoT cameras)
        r'(?:HMAC|MD5|SHA)\s*=',        # hash value assignment
    ]
]

# PLT import names that indicate high-risk behavior regardless of rodata strings.
# Checked against the library's dynamic symbol names (value == 0 imports).
_PLT_CRITICAL_IMPORTS: List[tuple] = [
    # (name_substring, score_delta, label)
    ('SSL_CTX_set_keylog_callback', 3, '[TLS-KEYLOG]'),  # TLS session key export
    ('bytehook_hook_all',           2, '[PLT-HOOK]'),    # process-wide PLT interception
    ('bytehook_hook_single',        2, '[PLT-HOOK]'),    # targeted PLT interception
    ('shadowhook_hook_sym_name',    2, '[PLT-HOOK]'),    # ShadowHook variant
    ('ssl_log_secret',              2, '[TLS-KEYLOG]'),  # OpenSSL internal key logger
    ('ssl_log_rsa_client_key_exchange', 2, '[TLS-KEYLOG]'),  # RSA premaster secret
]

# Command/exec sink patterns
_EXEC_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r'\bsystem\s*\(',
        r'\bpopen\s*\(',
        r'\bexecv[pe]?\s*\(',
        r'\bexecl[pe]?\s*\(',
        r'\bfork\s*\(',
        r'\bsh\s+-c\b',
        r'\/bin\/sh',
        r'\/bin\/bash',
    ]
]

# Known-false-positive string fragments — if a string contains any of these
# it is excluded from scoring regardless of other matches.
_KNOWN_FP: List[str] = [
    'noise shaping',        # LAME psychoacoustic
    'object key',           # JSON object accessor
    'unknown token',        # parser diagnostics
    'token list',
    'key-value',
    'key=value',            # documentation
    'log key',
    'asymmetric key',       # crypto library docs
    'key length',           # crypto API docs
    'key size',
    'key type',
    'key exchange',         # informational
    'shared key',           # informational
    'public key',           # informational (no credential leak)
    'private key type',     # informational
    'no key',
    'invalid key',
    'key not found',
    'aes encryption key',   # audit/description (not a log credential)
    'substep_shaping',      # LAME encoder internal
    'allocator',            # STL allocator keyword contains 'secret' substring? No, just safety
    'keystore',             # Android keystore API (not a raw key)
    'keychain',
]

_KNOWN_FP_LOWER = [s.lower() for s in _KNOWN_FP]


def _is_fp(s: str) -> bool:
    sl = s.lower()
    return any(fp in sl for fp in _KNOWN_FP_LOWER)


def _classify_string(s: str) -> tuple:
    """Return (score, tag) where tag is one of [CRED+FMT]/[CRED]/[EXEC]/[CRYPTO]/''."""
    if _is_fp(s):
        return 0, ''
    for pat in _CRED_PATTERNS:
        if pat.search(s):
            if re.search(r'[=:%]\s*%[sd]', s, re.IGNORECASE):
                return 3, '[CRED+FMT]'
            return 2, '[CRED]'
    for pat in _EXEC_PATTERNS:
        if pat.search(s):
            return 2, '[EXEC]'
    for pat in _CRYPTO_PATTERNS:
        if pat.search(s):
            return 1, '[CRYPTO]'
    return 0, ''


def _score_string(s: str) -> int:
    """Return 0 (no match), 1 (crypto), 2 (credential/exec), or 3 (cred+format specifier)."""
    return _classify_string(s)[0]


# ---------------------------------------------------------------------------
# ELF architecture names
# ---------------------------------------------------------------------------

_EMACHINE_TO_ARCH: Dict[int, str] = {
    3:   'x86',
    40:  'arm32',
    62:  'x86_64',
    183: 'arm64',
    8:   'mips32',
    10:  'mips64',
    20:  'ppc32',
    21:  'ppc64',
    243: 'riscv',
}


def _elf_arch(data: bytes) -> str:
    if len(data) < 20 or data[:4] != b'\x7fELF':
        return 'unknown'
    e_machine = struct.unpack_from('<H', data, 18)[0]
    return _EMACHINE_TO_ARCH.get(e_machine, f'e_machine={e_machine}')


# ---------------------------------------------------------------------------
# Internal function counter (ARM64 only — BL-target enumeration)
# ---------------------------------------------------------------------------

def _count_internal_arm64(data: bytes, binary=None) -> int:
    """Count ARM64 BL targets inside .text that are not in the export set."""
    if not _LIEF_OK:
        return -1
    try:
        b = binary if binary is not None else _lief.parse(data)
    except Exception:
        return -1
    if not b or not isinstance(b, _lief.ELF.Binary):
        return -1
    text = b.get_section('.text')
    if not text:
        return -1
    tv0 = text.virtual_address
    traw = bytes(text.content)
    n = len(traw) // 4
    exports = {s.value for s in b.dynamic_symbols if s.value != 0}
    targets: set = set()
    for i in range(n):
        w = struct.unpack_from('<I', traw, i * 4)[0]
        if (w >> 26) == 0x25:       # BL instruction
            off = w & 0x3FFFFFF
            if off & (1 << 25):
                off -= (1 << 26)
            tgt = tv0 + i * 4 + off * 4
            if tv0 <= tgt < tv0 + text.size:
                targets.add(tgt)
    return len(targets - exports)


# ---------------------------------------------------------------------------
# Rodata string extractor
# ---------------------------------------------------------------------------

def _extract_strings(data: bytes, min_len: int = 6, binary=None) -> List[str]:
    """Extract printable ASCII strings from .rodata (and .data.rel.ro)."""
    if not _LIEF_OK:
        # Fallback: scan whole file for printable runs
        result = []
        i = 0
        while i < len(data):
            start = i
            while i < len(data) and 0x20 <= data[i] < 0x7f:
                i += 1
            length = i - start
            if length >= min_len:
                result.append(data[start:i].decode('ascii', errors='replace'))
            else:
                i = start + 1
        return result
    try:
        b = binary if binary is not None else _lief.parse(data)
    except Exception:
        return []
    if not b or not isinstance(b, _lief.ELF.Binary):
        return []
    result = []
    for sec_name in ('.rodata', '.data.rel.ro', '.data'):
        try:
            sec = b.get_section(sec_name)
        except Exception:
            sec = None
        if not sec:
            continue
        raw = bytes(sec.content)
        i = 0
        while i < len(raw):
            start = i
            while i < len(raw) and 0x20 <= raw[i] < 0x7f:
                i += 1
            length = i - start
            if length >= min_len:
                result.append(raw[start:i].decode('ascii', errors='replace'))
            else:
                i = start + 1
    return result


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class LibInventoryEntry:
    """Per-library inventory result."""

    path: str                               # absolute path
    filename: str                           # basename
    size_kb: int
    arch: str
    exports: int                            # total dynamic symbols with value != 0
    internal: int                           # BL-target internal count (-1 = unsupported arch)
    jni: int                                # Java_* export count
    has_jni_on_load: bool
    security_score: int                     # 0-10
    security_strings: List[str] = field(default_factory=list)
    plt_hooks: List[str] = field(default_factory=list)  # critical PLT import labels found

    def __repr__(self) -> str:
        return (
            f"LibInventoryEntry({self.filename}, arch={self.arch}, "
            f"exports={self.exports}, internal={self.internal}, jni={self.jni}, "
            f"score={self.security_score})"
        )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class LibraryInventory:
    """
    Batch triage scanner for directories of native ELF libraries.

    Construction:
        inv = LibraryInventory.from_dir('/tmp/target/lib/arm64-v8a/')
        entries = inv.scan()

    Single file:
        entry = LibraryInventory.scan_one('/tmp/lib/libfoo.so')
    """

    def __init__(self, paths: List[str]) -> None:
        self._paths = paths

    @classmethod
    def from_dir(cls, dir_path: str, pattern: str = '*.so') -> 'LibraryInventory':
        """Collect all .so files (non-recursive) matching pattern."""
        p = Path(dir_path)
        if not p.is_dir():
            raise ValueError(f"Not a directory: {dir_path}")
        paths = sorted(str(f) for f in p.glob(pattern) if f.is_file())
        return cls(paths)

    @classmethod
    def from_paths(cls, paths: List[str]) -> 'LibraryInventory':
        """Explicit list of ELF paths."""
        return cls(list(paths))

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------

    @staticmethod
    def scan_one(elf_path: str) -> LibInventoryEntry:
        """Triage a single ELF and return its LibInventoryEntry."""
        p = Path(elf_path)
        size_kb = p.stat().st_size // 1024
        data = p.read_bytes()
        arch = _elf_arch(data)

        # Parse once; share across all three uses below
        _binary = None
        if _LIEF_OK:
            try:
                _binary = _lief.parse(data)
                if not isinstance(_binary, _lief.ELF.Binary):
                    _binary = None
            except Exception:
                pass

        # Exports, JNI counts, and critical PLT imports
        exports = 0
        jni = 0
        has_jni_on_load = False
        plt_hooks: List[str] = []
        if _binary is not None:
            try:
                syms = [s for s in _binary.dynamic_symbols if s.value != 0]
                exports = len(syms)
                for s in syms:
                    if s.name.startswith('Java_'):
                        jni += 1
                    if s.name == 'JNI_OnLoad':
                        has_jni_on_load = True
                # Check PLT imports (value == 0) and exported symbols for critical patterns.
                # Imports: dynamically linked in from another library.
                # Exports: statically linked OpenSSL re-exports the function itself.
                all_syms = [s.name for s in _binary.dynamic_symbols if s.name]
                for sym_name in all_syms:
                    for needle, _delta, label in _PLT_CRITICAL_IMPORTS:
                        if needle in sym_name and label not in plt_hooks:
                            plt_hooks.append(label)
            except Exception:
                pass

        # Internal function count (ARM64 only)
        internal = _count_internal_arm64(data, binary=_binary) if arch == 'arm64' else -1

        # Security strings
        all_strings = _extract_strings(data, binary=_binary)
        scored: List[tuple] = []
        for s in all_strings:
            sc = _score_string(s)
            if sc > 0:
                scored.append((sc, s))

        # Deduplicate, keep highest-scored version of similar strings
        scored.sort(key=lambda x: -x[0])
        sec_strings = [s for _, s in scored[:20]]  # cap at 20

        # Compute security score
        score = 0
        max_str_score = scored[0][0] if scored else 0
        if max_str_score >= 3:
            score += 3   # credential + format specifier
        elif max_str_score >= 2:
            score += 2   # credential or exec pattern
        if any(sc == 1 for sc, _ in scored):
            score += 1   # crypto primitives
        if jni >= 50:
            score += 2
        elif jni >= 10:
            score += 1
        if internal >= 200:
            score += 1
        if internal >= 1000:
            score += 1   # extra for very large
        # PLT critical import bonus
        for imp_label in plt_hooks:
            for _needle, delta, label in _PLT_CRITICAL_IMPORTS:
                if label == imp_label:
                    score += delta
                    break
        # Cap at 10
        score = min(score, 10)

        return LibInventoryEntry(
            path=str(p.resolve()),
            filename=p.name,
            size_kb=size_kb,
            arch=arch,
            exports=exports,
            internal=internal,
            jni=jni,
            has_jni_on_load=has_jni_on_load,
            security_score=score,
            security_strings=sec_strings,
            plt_hooks=plt_hooks,
        )

    def scan(self) -> List[LibInventoryEntry]:
        """Scan all paths, return entries sorted by security_score descending."""
        entries = []
        for path in self._paths:
            try:
                entries.append(self.scan_one(path))
            except Exception as exc:
                entries.append(LibInventoryEntry(
                    path=path,
                    filename=os.path.basename(path),
                    size_kb=0,
                    arch='error',
                    exports=0,
                    internal=-1,
                    jni=0,
                    has_jni_on_load=False,
                    security_score=0,
                    security_strings=[f'ERROR: {exc}'],
                ))
        entries.sort(key=lambda e: (-e.security_score, -e.internal, e.filename))
        return entries

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    @staticmethod
    def security_entries(
        entries: List[LibInventoryEntry],
        min_score: int = 3,
    ) -> List[LibInventoryEntry]:
        """Return only entries with security_score >= min_score."""
        return [e for e in entries if e.security_score >= min_score]

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def report(entries: List[LibInventoryEntry], show_strings: bool = True) -> str:
        """
        Format a concise triage table.

        Columns: filename | size | arch | exports | internal | jni | score | strings
        """
        if not entries:
            return "(no entries)"

        # Header
        lines = [
            "Library Inventory",
            "=" * 100,
            f"{'Library':<45} {'KB':>5} {'arch':>6} {'exp':>5} {'int':>5} {'jni':>4} {'score':>5}  Security strings",
            "-" * 100,
        ]

        for e in entries:
            internal_str = str(e.internal) if e.internal >= 0 else '?'
            score_str = f"{e.security_score}/10"
            # Show up to 2 highest-scored strings inline, truncated
            str_preview = ""
            if show_strings and e.security_strings:
                previews = [s[:60] for s in e.security_strings[:2]]
                str_preview = "  " + " | ".join(f'"{p}"' for p in previews)
            hook_str = ""
            if e.plt_hooks:
                hook_str = "  " + " ".join(e.plt_hooks)
            lines.append(
                f"{e.filename:<45} {e.size_kb:>5} {e.arch:>6} {e.exports:>5}"
                f" {internal_str:>5} {e.jni:>4} {score_str:>5}{hook_str}{str_preview}"
            )

        lines.append("-" * 100)
        total_internal = sum(e.internal for e in entries if e.internal >= 0)
        total_exports = sum(e.exports for e in entries)
        total_jni = sum(e.jni for e in entries)
        lines.append(
            f"{'TOTAL':<45} {sum(e.size_kb for e in entries):>5}"
            f"       {total_exports:>5} {total_internal:>5} {total_jni:>4}"
        )
        lines.append(f"\n{len(entries)} libraries scanned")
        high_risk = [e for e in entries if e.security_score >= 5]
        if high_risk:
            lines.append(f"\nHigh-risk libraries (score >= 5):")
            for e in high_risk:
                hooks = f"  hooks={e.plt_hooks}" if e.plt_hooks else ""
                lines.append(f"  {e.filename}  score={e.security_score}/10  jni={e.jni}{hooks}")
        return "\n".join(lines)

    @staticmethod
    def report_strings(entry: LibInventoryEntry) -> str:
        """Full security strings dump for one library."""
        if not entry.security_strings:
            return f"{entry.filename}: no security strings found"
        lines = [f"{entry.filename} security strings ({entry.security_score}/10):"]
        for s in entry.security_strings:
            _sc, tag = _classify_string(s)
            if not tag:
                tag = '[?]'
            lines.append(f"  {tag:12}  {s[:100]}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal function taxonomy (ARM64)
    # ------------------------------------------------------------------

    @staticmethod
    def classify_internals(elf_path: str) -> Dict[str, List[int]]:
        """
        Classify ARM64 internal functions by PLT call signature.

        Returns a dict mapping subsystem label to list of function VAs.
        Labels are derived from the first 6 distinct PLT symbols called
        within each function, joined with '+'. Functions with no PLT calls
        are grouped under '(pure-internal)'.

        Requires LIEF. Returns {} if arch is not ARM64 or LIEF is absent.

        Example:
            clusters = LibraryInventory.classify_internals('/tmp/lib/libfoo.so')
            for label, vas in sorted(clusters.items(), key=lambda x: -len(x[1])):
                print(f"[{len(vas):3d}] {label}")
        """
        if not _LIEF_OK:
            return {}
        try:
            import capstone as _cs
        except ImportError:
            return {}

        data = Path(elf_path).read_bytes()
        if _elf_arch(data) != 'arm64':
            return {}

        try:
            b = _lief.parse(data)
        except Exception:
            return {}
        if not b or not isinstance(b, _lief.ELF.Binary):
            return {}

        text = b.get_section('.text')
        if not text:
            return {}
        tv0 = text.virtual_address
        traw = bytes(text.content)
        text_end = tv0 + text.size

        # Build PLT map
        got_to_sym: Dict[int, str] = {}
        rela_plt = b.get_section('.rela.plt')
        if rela_plt:
            rd = bytes(rela_plt.content)
            for off in range(0, len(rd), 24):
                if off + 24 > len(rd):
                    break
                r_offset, r_info = struct.unpack_from('<QQ', rd, off)
                sym_idx = r_info >> 32
                try:
                    got_to_sym[r_offset] = b.dynamic_symbols[sym_idx].name
                except Exception:
                    pass

        plt_sec = b.get_section('.plt')
        plt_map: Dict[int, str] = {}
        if plt_sec:
            pd = bytes(plt_sec.content)
            pv0 = plt_sec.virtual_address
            for i in range(1, len(pd) // 16):
                wo = i * 16
                stub_va = pv0 + wo
                w0, w1, w2, w3 = struct.unpack_from('<IIII', pd, wo)
                if (w0 & 0x9f00001f) != 0x90000010:
                    continue
                if (w1 & 0xFFC003FF) != 0xF9400211:
                    continue
                if w3 != 0xD61F0220:
                    continue
                immlo = (w0 >> 29) & 0x3
                immhi = (w0 >> 5) & 0x7ffff
                imm21 = (immhi << 2) | immlo
                if imm21 & (1 << 20):
                    imm21 -= (1 << 21)
                page = (stub_va & ~0xfff) + (imm21 << 12)
                imm12 = (w1 >> 10) & 0xfff
                got_va = page + imm12 * 8
                if got_va in got_to_sym:
                    plt_map[stub_va] = got_to_sym[got_va]

        dynsym_vas = {s.value for s in b.dynamic_symbols if s.value != 0}

        # Enumerate internal BL targets
        internals: set = set()
        for wo in range(0, len(traw), 4):
            w = struct.unpack_from('<I', traw, wo)[0]
            if (w >> 26) == 0x25:
                imm26 = w & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= (1 << 26)
                tgt = (tv0 + wo) + imm26 * 4
                if tv0 <= tgt < text_end and tgt not in dynsym_vas and tgt not in plt_map:
                    internals.add(tgt)

        md = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM)

        def _plt_calls(va: int) -> tuple:
            wo = va - tv0
            if wo < 0 or wo >= len(traw):
                return ()
            chunk = traw[wo:min(wo + 200 * 4, len(traw))]
            calls: List[str] = []
            for insn in md.disasm(chunk, va):
                if insn.mnemonic == 'bl':
                    try:
                        tgt = int(insn.op_str.strip().lstrip('#'), 16)
                        if tgt in plt_map:
                            name = plt_map[tgt]
                            if name not in calls:
                                calls.append(name)
                    except ValueError:
                        pass
                elif insn.mnemonic == 'ret':
                    break
            return tuple(calls[:6])

        from collections import defaultdict
        clusters: Dict[str, List[int]] = defaultdict(list)
        for va in sorted(internals):
            sig = _plt_calls(va)
            label = '+'.join(sig) if sig else '(pure-internal)'
            clusters[label].append(va)

        return dict(clusters)
