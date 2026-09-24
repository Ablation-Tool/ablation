"""
version_delta.py — Cross-version function tracking for ablation.

Tracks how a specific function
evolves across binary versions. Identifies homologs via a three-stage pipeline:

  Stage 1  Structural pre-filter   basic block count ±2, edge count ±30%
  Stage 2  Mnemonic 4-gram Jaccard sequence similarity, keeps top-10 candidates
  Stage 3  Semantic tiebreaker     SemanticSearcher when top-2 within 0.05

Patch localization via difflib.SequenceMatcher on normalized instruction lines
reveals the specific instructions that changed between versions.

Primary use case: track a specific function across firmware patch releases
to confirm CVE-2022-0778 / RADIUS overflow remediation.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Layer 0 — structural anchor scan (implementation-variant classification)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AnchorScanResult:
    """Result for one anchor pattern against one binary."""
    anchor_name: str
    era:         int
    hit_offset:  int    # file offset of first hit; -1 if not found
    description: str

    @property
    def found(self) -> bool:
        return self.hit_offset >= 0


def _masked_find(data: bytes, pattern: bytes, mask: bytes, start: int, end: int) -> int:
    """Find first masked pattern match. Uses bytes.find() on the fixed prefix for speed."""
    plen = len(pattern)
    # Find the longest fully-masked prefix to use as a fast filter
    prefix_len = next((i for i, m in enumerate(mask) if m != 0xff), plen)
    prefix = pattern[:prefix_len] if prefix_len > 0 else pattern[:1]
    i = start
    while i <= end - plen:
        idx = data.find(prefix, i, end - plen + len(prefix))
        if idx == -1:
            break
        if all((data[idx + j] & mask[j]) == (pattern[j] & mask[j]) for j in range(plen)):
            return idx
        i = idx + 1
    return -1


# Anchor format: name → (pattern, mask, impl_variant, description)
#
# pattern and mask are equal-length bytes. mask 0xFF = must match, 0x00 = wildcard.
# impl_variant is an integer classifying the IMPLEMENTATION of the function, not
# the patched/unpatched state of the system. The patch (MA validation) is upstream
# and not visible from attr_list_add_impl itself — all variants below are present
# in both patched and unpatched binaries.
#
# Corpus validation (28 binary versions):
#   impl_v1:  ALL ELF32 builds (9.2.4, 9.4.4, 9.17.x-k8...) — 32-bit calling conv
#             also: ELF64 binaries do NOT hit this anchor ✓
#   impl_v2a: ELF64 9.5.2–9.14.x, 9.20.3    | misses v1 builds, 9.15.x, 9.16.x, 9.17.x+ELF64 ✓
#   impl_v2b: ELF64 9.15.x, 9.16.x           | misses v1, v2a, v2c ✓
#   impl_v2c: ELF64 9.17.x, 9.22.x           | misses all prior ✓
#             r14 first at 9.17.2.3; 9.20.x reverts to v2a (maintenance branch, forked before 9.15)
ERA_DISCRIMINATOR_ANCHORS: dict[str, tuple[bytes, bytes, int, str]] = {
    # v1: 32-bit i386 calling convention — jne + lea eax,[ebp-0x10] after match
    # Covers a range of ELF32 binary versions including legacy hardware builds
    # The lea eax,[rbp-0x10] encoding is identical for 32-bit [ebp-0x10]
    'attr_list_add_impl_v1': (
        b'\x66\x3d\x19\x10\x75\x00\x8d\x45\xf0',
        b'\xff\xff\xff\xff\xff\x00\xff\xff\xff',
        1,
        'v1: 32-bit calling conv; cmp ax,0x1019 / jne / lea eax,[ebp-0x10]; '
        'all ELF32 builds (9.2.4, 9.4.4, 9.17.x-k8...); '
        'ELF64 transition at 9.5.2 yields v2a',
    ),
    # v2a: jne + xor esi,esi + mov rdx,r13 after match (r13=context ptr)
    'attr_list_add_impl_v2a': (
        b'\x66\x3d\x19\x10\x75\x00\x31\xf6\x4c\x89\xea',
        b'\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff',
        2,
        'v2a: cmp ax,0x1019 / jne / xor esi / mov rdx,r13; confirmed 9.5.2–9.14.x, '
        '9.20.3; boundary 9.4.4→9.5.2',
    ),
    # v2b: loop refactored — je(match) + add rbx,0x10 as fall-through
    # Two sub-forms: short je (74 XX, 6-byte pattern) and long je (0f 84 XX XX XX XX, 10-byte)
    # Use long-je form as anchor; short-je (9.15.x) caught by separate entry
    'attr_list_add_impl_v2b_short': (
        b'\x66\x3d\x19\x10\x74\x00\x48\x83\xc3\x10',
        b'\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff',
        2,
        'v2b-short: cmp ax,0x1019 / je(short) / add rbx,0x10; confirmed 9.15.x',
    ),
    'attr_list_add_impl_v2b_long': (
        b'\x66\x3d\x19\x10\x0f\x84\x00\x00\x00\x00\x48\x83\xc3\x10',
        b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff',
        2,
        'v2b-long: cmp ax,0x1019 / je(long) / add rbx,0x10; confirmed 9.16.x',
    ),
    # v2c: same structure as v2a but r14 instead of r13 (register allocation shifted)
    'attr_list_add_impl_v2c': (
        b'\x66\x3d\x19\x10\x75\x00\x31\xf6\x4c\x89\xf2',
        b'\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff',
        2,
        'v2c: cmp ax,0x1019 / jne / xor esi / mov rdx,r14; confirmed 9.17.2.3, 9.22.x; '
        'r14 first appears at 9.17; 9.20.x reverts to v2a (maintenance branch)',
    ),
}


def structural_anchor_scan(
    data:     bytes,
    anchors:  dict | None = None,
    text_end: int = 0,
) -> list[AnchorScanResult]:
    """
    Scan binary bytes for known implementation-variant anchor sequences.

    O(n) per anchor using masked pattern matching. A HIT definitively classifies
    the implementation variant. A MISS is inconclusive — fall through to Jaccard.

    The "patched vs unpatched" state is NOT visible from these anchors: all variants
    represent the attr_list_add_impl function, which exists in both patched (MA
    validation upstream) and unpatched binaries. Use VisorPlus/aimap for vuln state.

    Args:
        data:     raw binary bytes
        anchors:  anchor library; defaults to ERA_DISCRIMINATOR_ANCHORS
        text_end: scan limit; 0 = full binary

    Returns:
        one AnchorScanResult per anchor, in anchor-dict order
    """
    if anchors is None:
        anchors = ERA_DISCRIMINATOR_ANCHORS
    # ELF32 (i386) binaries — both the old pre-9.5.2 builds AND the legacy-HW k8 builds
    # from 9.17.x onward — use the 32-bit calling convention.  The v1 anchor correctly
    # identifies attr_list_add_impl in all of them.  No architecture gate here; the
    # anchor handles it naturally.
    limit = text_end if text_end > 0 else len(data)
    results = []
    for name, entry in anchors.items():
        if len(entry) == 4:
            pattern, mask, impl_variant, desc = entry
            hit = _masked_find(data, pattern, mask, 0, limit)
        else:
            # Legacy 3-tuple: exact match
            pattern, impl_variant, desc = entry
            hit = data.find(pattern, 0, limit)
        results.append(AnchorScanResult(
            anchor_name=name,
            era=impl_variant,
            hit_offset=hit,
            description=desc,
        ))
    return results


@dataclass
class BinaryClassification:
    """Top-level classification of a binary's parser implementation variant."""
    variant:    str    # 'v1' | 'v2a' | 'v2b' | 'v2c' | 'unknown'
    confidence: str    # 'anchor' (deterministic) | 'unknown' (no hit)
    hit_offset: int    # file offset of anchor match; -1 if none
    anchor_name: str   # which anchor fired; '' if none
    elf_class:  int    # 1=ELF32/i386  2=ELF64/x86_64  0=unknown

    @property
    def is_elf32(self) -> bool:
        return self.elf_class == 1


# anchor name → short variant label
_ANCHOR_VARIANT: dict[str, str] = {
    'attr_list_add_impl_v1':        'v1',
    'attr_list_add_impl_v2a':       'v2a',
    'attr_list_add_impl_v2b_short': 'v2b',
    'attr_list_add_impl_v2b_long':  'v2b',
    'attr_list_add_impl_v2c':       'v2c',
}


def classify_binary(
    source:  'bytes | str | Path',
    anchors: dict | None = None,
) -> BinaryClassification:
    """
    Classify a binary's parser implementation variant.

    Layer 0 only — structural anchor scan.  Deterministic, <1ms per binary.
    Returns variant='unknown' with confidence='unknown' on anchor miss; caller
    should cascade to Layer 2 (mnemonic Jaccard) for novel/unrecognized builds.

    Args:
        source:  raw bytes, file path string, or pathlib.Path
        anchors: override anchor library; defaults to ERA_DISCRIMINATOR_ANCHORS

    Returns:
        BinaryClassification with variant, confidence tier, and hit metadata
    """
    if isinstance(source, (str, Path)):
        data = Path(source).read_bytes()
    else:
        data = source

    elf_class = data[4] if len(data) > 5 and data[:4] == b'\x7fELF' else 0
    results   = structural_anchor_scan(data, anchors=anchors)
    hits      = [r for r in results if r.found]

    if not hits:
        return BinaryClassification(
            variant='unknown', confidence='unknown',
            hit_offset=-1, anchor_name='', elf_class=elf_class,
        )

    # Multiple anchors should never fire on one binary — each variant is mutually
    # exclusive.  If they do (novel build or anchor regression), take the first hit.
    r = hits[0]
    return BinaryClassification(
        variant=_ANCHOR_VARIANT.get(r.anchor_name, 'unknown'),
        confidence='anchor',
        hit_offset=r.hit_offset,
        anchor_name=r.anchor_name,
        elf_class=elf_class,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────

_MNEMONIC_RE = re.compile(r'^\s*([a-z][a-z0-9_]{0,15})', re.IGNORECASE)
_ADDR_RE     = re.compile(r'\b0x[0-9a-fA-F]{4,}\b')
_IMM_RE      = re.compile(r'\b\d{4,}\b')
_REG_RE      = re.compile(
    r'\b('
    r'r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5])[lhwd]?|'
    r'e(?:ax|bx|cx|dx|si|di|bp|sp)|'
    r'[abcd][lhx]|sil|dil|bpl|spl|'
    r'[xyz]mm\d{1,2}|mm\d|st\d|'
    r'[xwb](?:\d{1,2}|zr|sp|lr|fp|pc)|'
    r'v\d{1,2}\.[248]?[BHSDQ]?|'
    r'r\d{1,2}'
    r')\b',
    re.IGNORECASE,
)


def _normalize_line(line: str) -> str:
    """Normalize one instruction line to a build-invariant form."""
    line = re.sub(r'^[0-9a-f]+:\s*(?:[0-9a-f]{2}\s+)*', '', line, flags=re.IGNORECASE)
    line = re.sub(r'[;#].*$', '', line)
    line = _ADDR_RE.sub('<A>', line)
    line = _IMM_RE.sub('<I>', line)
    line = _REG_RE.sub('<R>', line)
    return line.strip()


def _mnemonic(line: str) -> Optional[str]:
    m = _MNEMONIC_RE.match(line)
    return m.group(1).lower() if m else None


def _ngrams(seq: list[str], n: int = 4) -> frozenset[str]:
    return frozenset(' '.join(seq[i:i+n]) for i in range(len(seq) - n + 1))


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


@dataclass
class FuncFeatures:
    va:           int
    name:         str
    n_blocks:     int
    n_edges:      int
    n_instrs:     int
    mnemonics:    list[str]        # per-instruction, in order
    ngrams_4:     frozenset[str]
    norm_lines:   list[str]        # normalized instruction lines
    callees:      list[str]
    string_xrefs: list[str]

    @classmethod
    def from_angr(cls, proj, cfg, va: int, name: str = '') -> Optional['FuncFeatures']:
        """Extract features for the function at *va* using an already-built CFGFast."""
        try:
            func = cfg.kb.functions.get(va)
            if func is None:
                return None

            blocks     = list(func.blocks)
            n_blocks   = len(blocks)
            n_edges    = sum(len(list(func.graph.successors(b))) for b in blocks)
            mnemonics: list[str] = []
            norm_lines: list[str] = []

            for block in sorted(blocks, key=lambda b: b.addr):
                cs = block.disassembly
                if cs is None:
                    continue
                for insn in cs.insns:
                    raw  = f"{insn.mnemonic} {insn.op_str}".strip()
                    mn   = insn.mnemonic.lower()
                    mnemonics.append(mn)
                    norm = _normalize_line(raw)
                    if norm:
                        norm_lines.append(norm)

            callees = [
                categorize_callee(
                    cfg.kb.functions.get(c.addr).name
                    if cfg.kb.functions.get(c.addr) else hex(c.addr)
                )
                for c in func.callees
            ]
            string_xrefs: list[str] = []
            if hasattr(cfg, 'memory_data'):
                for ref in cfg.memory_data.values():
                    if ref.sort == 'string' and ref.content:
                        val = ref.content.decode(errors='replace').strip()
                        if val:
                            string_xrefs.append(val[:80])

            return cls(
                va=va,
                name=name or func.name or hex(va),
                n_blocks=n_blocks,
                n_edges=n_edges,
                n_instrs=len(mnemonics),
                mnemonics=mnemonics,
                ngrams_4=_ngrams(mnemonics, 4),
                norm_lines=norm_lines,
                callees=callees,
                string_xrefs=string_xrefs,
            )
        except Exception:
            return None

    @classmethod
    def from_disasm_lines(
        cls,
        va: int,
        name: str,
        asm_lines: list[str],
        callees: Optional[list[str]] = None,
        string_xrefs: Optional[list[str]] = None,
    ) -> 'FuncFeatures':
        """Build from raw disassembly text (e.g., capstone output)."""
        mnemonics  = [m for line in asm_lines if (m := _mnemonic(line))]
        norm_lines = [n for line in asm_lines if (n := _normalize_line(line))]
        return cls(
            va=va,
            name=name,
            n_blocks=0,
            n_edges=0,
            n_instrs=len(mnemonics),
            mnemonics=mnemonics,
            ngrams_4=_ngrams(mnemonics, 4),
            norm_lines=norm_lines,
            callees=callees or [],
            string_xrefs=string_xrefs or [],
        )


# ─────────────────────────────────────────────────────────────────────────────
# Seed enrichment — callee resolution + string xref extraction
# ─────────────────────────────────────────────────────────────────────────────

_RIP_REL_RE = re.compile(
    r'\[rip \+? ?(0x[0-9a-fA-F]+|-?0x[0-9a-fA-F]+|-\d+|\d+)\]',
    re.IGNORECASE,
)
_MIN_STR_LEN = 4
_MAX_STR_LEN = 120


_CALLEE_CATEGORIES: dict[str, str] = {}

def _build_callee_categories() -> dict[str, str]:
    m: dict[str, str] = {}
    allocators   = ['malloc', 'calloc', 'realloc', 'xmalloc', 'xcalloc', 'zmalloc',
                    'malloc_wrapper', 'mem_alloc', 'xalloc', 'safe_malloc',
                    'attr_alloc', 'radius_alloc', 'chunk_alloc', 'pool_alloc']
    deallocators = ['free', 'xfree', 'zfree', 'mem_free', 'safe_free', 'vfree',
                    'attr_free', 'radius_free', 'chunk_free']
    str_copy     = ['strcpy', 'strncpy', 'strlcpy', 'memcpy', 'memmove',
                    'bcopy', 'strdup', 'strndup', 'g_strdup']
    str_compare  = ['strcmp', 'strncmp', 'strcasecmp', 'strncasecmp', 'memcmp', 'bcmp']
    str_length   = ['strlen', 'strnlen']
    str_format   = ['sprintf', 'snprintf', 'vsprintf', 'vsnprintf', 'asprintf']
    io_ops       = ['read', 'write', 'send', 'recv', 'sendto', 'recvfrom',
                    'fread', 'fwrite', 'fgets', 'fputs']
    crypto_ops   = ['EVP_EncryptUpdate', 'EVP_DecryptUpdate', 'SHA256', 'SHA1',
                    'MD5', 'HMAC', 'AES_encrypt', 'AES_decrypt',
                    'RSA_public_encrypt', 'RSA_private_decrypt']
    log_ops      = ['syslog', 'fprintf', 'printf', 'vprintf', 'log_message',
                    'cisco_log', 'err_log', 'debug_log']
    for name in allocators:   m[name.lower()] = 'ALLOCATOR'
    for name in deallocators: m[name.lower()] = 'DEALLOCATOR'
    for name in str_copy:     m[name.lower()] = 'STRING_COPY'
    for name in str_compare:  m[name.lower()] = 'STRING_CMP'
    for name in str_length:   m[name.lower()] = 'STRING_LEN'
    for name in str_format:   m[name.lower()] = 'STRING_FORMAT'
    for name in io_ops:       m[name.lower()] = 'IO_OP'
    for name in crypto_ops:   m[name.lower()] = 'CRYPTO_OP'
    for name in log_ops:      m[name.lower()] = 'LOG_OP'
    return m

_CALLEE_CATEGORIES = _build_callee_categories()


def categorize_callee(name: str) -> str:
    """Map a callee name to a behavioral category, or return the name unchanged."""
    return _CALLEE_CATEGORIES.get(name.lower(), name)


def resolve_callees(
    callee_vas: list[str],
    db_path: str,
    binary_sha256: str = '',
) -> list[str]:
    """Replace hex callee VAs with func_id_db names where known.

    Falls back to the hex string for unknowns so the description degrades
    gracefully rather than losing information.
    """
    import sqlite3

    try:
        con = sqlite3.connect(Path(db_path).expanduser())
        out = []
        for va_str in callee_vas:
            try:
                va = int(va_str, 16) if va_str.startswith('0x') else int(va_str)
            except ValueError:
                out.append(va_str)
                continue
            if binary_sha256:
                row = con.execute(
                    'SELECT name FROM functions WHERE va=? AND binary_sha256=?',
                    (va, binary_sha256),
                ).fetchone()
            else:
                row = con.execute(
                    'SELECT name FROM functions WHERE va=?', (va,)
                ).fetchone()
            out.append(row[0] if row else va_str)
        con.close()
        return out
    except Exception:
        return callee_vas


def extract_string_xrefs(
    binary_data: bytes,
    asm_lines: list[str],
    insn_vas: list[int],
    binary_base: int = 0,
) -> list[str]:
    """Follow RIP-relative data references to ASCII strings in the binary.

    For each instruction of the form `lea/mov reg, [rip ± disp]`, compute
    the target VA, read up to _MAX_STR_LEN bytes from the binary, and keep
    it if it looks like printable ASCII.  Requires per-instruction VAs
    (parallel list to asm_lines) so the RIP offset can be resolved correctly.
    """
    strings: list[str] = []
    seen: set[int] = set()

    for i, (line, va) in enumerate(zip(asm_lines, insn_vas)):
        m = _RIP_REL_RE.search(line)
        if not m:
            continue

        # RIP points to the START of the NEXT instruction
        next_va = insn_vas[i + 1] if i + 1 < len(insn_vas) else va + 7

        raw_disp = m.group(1)
        try:
            disp = int(raw_disp, 16) if '0x' in raw_disp else int(raw_disp)
        except ValueError:
            continue

        target_va = next_va + disp
        file_off  = target_va - binary_base
        if file_off < 0 or file_off + _MIN_STR_LEN >= len(binary_data):
            continue
        if file_off in seen:
            continue
        seen.add(file_off)

        chunk = binary_data[file_off: file_off + _MAX_STR_LEN]
        null  = chunk.find(b'\x00')
        if null < _MIN_STR_LEN:
            continue
        candidate = chunk[:null]
        if all(0x20 <= b < 0x7f for b in candidate):
            strings.append(candidate.decode('ascii'))

    return strings


# ─────────────────────────────────────────────────────────────────────────────
# Patch localization
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PatchDelta:
    added:   list[str]
    removed: list[str]
    context: list[str]    # unchanged lines surrounding changes
    ratio:   float        # SequenceMatcher similarity (0–1, higher = more similar)

    @property
    def is_patched(self) -> bool:
        return bool(self.added or self.removed)

    def unified_diff(self, version_a: str = 'v_a', version_b: str = 'v_b') -> str:
        return '\n'.join(difflib.unified_diff(
            self.removed, self.added,
            fromfile=version_a, tofile=version_b,
            lineterm='',
        ))


def compute_patch_delta(features_a: FuncFeatures, features_b: FuncFeatures) -> PatchDelta:
    """Diff normalized instruction sequences to localize the patch."""
    sm = difflib.SequenceMatcher(None, features_a.norm_lines, features_b.norm_lines, autojunk=False)
    added   = []
    removed = []
    context = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            context.extend(features_a.norm_lines[i1:i2])
        elif tag in ('replace', 'delete'):
            removed.extend(features_a.norm_lines[i1:i2])
            if tag == 'replace':
                added.extend(features_b.norm_lines[j1:j2])
        elif tag == 'insert':
            added.extend(features_b.norm_lines[j1:j2])
    return PatchDelta(added=added, removed=removed, context=context, ratio=sm.ratio())


# ─────────────────────────────────────────────────────────────────────────────
# Homolog matching result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HomologMatch:
    va:             int
    name:           str
    jaccard:        float
    semantic_score: float
    confidence:     str          # 'HIGH' | 'MEDIUM' | 'LOW'
    delta:          PatchDelta
    new_callees:    list[str]
    removed_callees: list[str]

    @property
    def callee_changed(self) -> bool:
        return bool(self.new_callees or self.removed_callees)


@dataclass
class DeltaReport:
    seed_binary:    str
    seed_va:        int
    seed_name:      str
    target_binary:  str
    target_version: str
    match:          Optional[HomologMatch]
    anchor_results: list[AnchorScanResult] = field(default_factory=list)

    @property
    def era_confirmed(self) -> Optional[int]:
        """Return confirmed era number if any anchor hit; None if inconclusive."""
        for r in self.anchor_results:
            if r.found:
                return r.era
        return None

    def summary(self) -> str:
        era_tag = f" [era{self.era_confirmed}:anchor]" if self.era_confirmed else ""
        if self.match is None:
            return f"{self.target_version}: NO MATCH{era_tag}"
        m = self.match
        patch = 'PATCHED' if m.delta.is_patched else 'UNCHANGED'
        callee = ''
        if m.new_callees:
            callee += f" +callees:{','.join(m.new_callees)}"
        if m.removed_callees:
            callee += f" -callees:{','.join(m.removed_callees)}"
        return (
            f"{self.target_version}: {m.name} @ {hex(m.va)}"
            f" jaccard={m.jaccard:.3f} sem={m.semantic_score:.3f}"
            f" [{m.confidence}] {patch}{callee}{era_tag}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Three-stage matching engine
# ─────────────────────────────────────────────────────────────────────────────

class FuncMatcher:
    """Match a seed function against a target binary's function set."""

    _BLOCK_TOLERANCE = 2       # ±N basic blocks for structural pre-filter
    _EDGE_RATIO_MAX  = 0.35    # max fractional edge-count difference
    _TOP_K           = 10      # candidates to keep after Jaccard ranking
    _SEM_TIE_THRESH  = 0.05    # Jaccard gap below which semantic is tiebreaker
    _SEM_JACCARD_MIN = 0.15    # Jaccard below this → semantic becomes primary signal
    _WHITEN_MIN_N    = 50      # minimum candidates to fit whitening transform
    _WHITEN_SAMPLE_N = 1000   # max candidates sampled to fit transform (performance)

    def __init__(self, semantic_searcher=None):
        self._sem = semantic_searcher
        self._whitening = None   # fitted WhiteningTransform, built per find_homolog call

    def _structural_candidates(
        self, seed: FuncFeatures, candidates: list[FuncFeatures]
    ) -> list[FuncFeatures]:
        """Stage 1: filter by basic-block and edge counts."""
        if seed.n_blocks == 0:
            return candidates  # no CFG data — skip filter
        out = []
        for c in candidates:
            if c.n_blocks == 0:
                out.append(c)
                continue
            block_ok = abs(c.n_blocks - seed.n_blocks) <= self._BLOCK_TOLERANCE
            if seed.n_edges > 0:
                edge_ratio = abs(c.n_edges - seed.n_edges) / max(seed.n_edges, 1)
                edge_ok = edge_ratio <= self._EDGE_RATIO_MAX
            else:
                edge_ok = True
            if block_ok and edge_ok:
                out.append(c)
        return out

    def _jaccard_rank(
        self, seed: FuncFeatures, candidates: list[FuncFeatures]
    ) -> list[tuple[float, FuncFeatures]]:
        """Stage 2: rank by mnemonic 4-gram Jaccard, return top-k."""
        scored = [(jaccard(seed.ngrams_4, c.ngrams_4), c) for c in candidates]
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:self._TOP_K]

    def _build_whitening(self, candidates: list[FuncFeatures]) -> None:
        """Fit WhiteningTransform on candidate embeddings if enough exist.

        Called once per find_homolog() on the full candidate set before
        Stage 2 ranking, so the transform is calibrated to the target
        binary's embedding distribution rather than a generic prior.
        """
        if self._sem is None or len(candidates) < self._WHITEN_MIN_N:
            self._whitening = None
            return
        try:
            import random
            import numpy as np
            from .semantic_search import WhiteningTransform, describe_function
            model = self._sem._get_model()
            # Sample for efficiency — distribution estimate is stable at 1k samples
            sample = candidates
            if len(candidates) > self._WHITEN_SAMPLE_N:
                sample = random.sample(candidates, self._WHITEN_SAMPLE_N)
            descs = [
                describe_function(
                    c.name, 'UNKNOWN', c.callees, c.string_xrefs,
                    asm_lines=c.norm_lines[:30],
                )
                for c in sample
            ]
            vecs = model.encode(
                descs, normalize_embeddings=True,
                show_progress_bar=False, batch_size=128,
            ).astype(np.float32)
            wt = WhiteningTransform()
            wt.fit(vecs)
            # Only cache vectors for the sampled functions; TOP_K candidates
            # not in cache are encoded on demand in _semantic_score.
            self._whitening = (wt, {id(c): v for c, v in zip(sample, vecs)})
        except Exception:
            self._whitening = None

    def _semantic_score(self, seed: FuncFeatures, candidate: FuncFeatures) -> float:
        """Stage 3: cosine similarity with optional whitening correction.

        Encodes seed and candidate on the fly. If a WhiteningTransform was
        fitted in _build_whitening(), applies it before computing similarity
        to correct BERT embedding anisotropy (Su et al. 2021).
        """
        if self._sem is None:
            return 0.0
        try:
            import numpy as np
            from .semantic_search import describe_function
            model = self._sem._get_model()
            seed_desc = describe_function(
                seed.name, 'UNKNOWN',
                seed.callees, seed.string_xrefs,
                asm_lines=seed.norm_lines[:30],
            )
            seed_vec = model.encode(
                seed_desc, normalize_embeddings=True,
                show_progress_bar=False,
            ).astype(np.float32)

            # Reuse pre-computed candidate vector if available
            if self._whitening is not None:
                wt, vec_cache = self._whitening
                if id(candidate) in vec_cache:
                    cand_vec = vec_cache[id(candidate)].astype(np.float32)
                else:
                    cand_desc = describe_function(
                        candidate.name, 'UNKNOWN',
                        candidate.callees, candidate.string_xrefs,
                        asm_lines=candidate.norm_lines[:30],
                    )
                    cand_vec = model.encode(
                        cand_desc, normalize_embeddings=True,
                        show_progress_bar=False,
                    ).astype(np.float32)
                # Apply whitening to both
                seed_vec = wt.transform(seed_vec.reshape(1, -1))[0]
                cand_vec = wt.transform(cand_vec.reshape(1, -1))[0]
            else:
                cand_desc = describe_function(
                    candidate.name, 'UNKNOWN',
                    candidate.callees, candidate.string_xrefs,
                    asm_lines=candidate.norm_lines[:30],
                )
                cand_vec = model.encode(
                    cand_desc, normalize_embeddings=True,
                    show_progress_bar=False,
                ).astype(np.float32)

            # Cosine similarity (both already L2-normalized after whitening)
            norm_s = np.linalg.norm(seed_vec)
            norm_c = np.linalg.norm(cand_vec)
            if norm_s < 1e-9 or norm_c < 1e-9:
                return 0.0
            return float((seed_vec / norm_s) @ (cand_vec / norm_c))
        except Exception:
            return 0.0

    def find_homolog(
        self, seed: FuncFeatures, target_functions: list[FuncFeatures]
    ) -> Optional[HomologMatch]:
        """Three-stage pipeline: structural → Jaccard → semantic."""
        if not target_functions:
            return None

        # Stage 1
        struct_pass = self._structural_candidates(seed, target_functions)
        if not struct_pass:
            struct_pass = target_functions  # fallback to full set

        # Whitening disabled: cross-corpus mean subtraction collapses scores for
        # functions that are "typical" of the target binary, destroying the TP signal.
        # Jaccard floor (>= 0.15) is the load-bearing FP suppressor; raw MPNet cosine
        # similarity is the semantic tiebreaker.
        self._whitening = None

        # Stage 2
        ranked = self._jaccard_rank(seed, struct_pass)
        if not ranked:
            return None

        best_score, best_func = ranked[0]

        # Stage 3 — semantic kicks in under two conditions:
        #   (a) tiebreak: top-2 Jaccard within _SEM_TIE_THRESH
        #   (b) primary:  best Jaccard below _SEM_JACCARD_MIN (cross-version divergence)
        sem_score = 0.0
        low_jaccard = best_score < self._SEM_JACCARD_MIN

        if self._sem is not None and (
            low_jaccard or
            (len(ranked) >= 2 and ranked[0][0] - ranked[1][0] < self._SEM_TIE_THRESH)
        ):
            if low_jaccard:
                # Score all top-K candidates; pick highest semantic match
                scored_sem = [
                    (self._semantic_score(seed, f), jac, f)
                    for jac, f in ranked
                ]
                scored_sem.sort(key=lambda x: x[0], reverse=True)
                sem_score, best_score, best_func = scored_sem[0]
            else:
                sem_a = self._semantic_score(seed, ranked[0][1])
                sem_b = self._semantic_score(seed, ranked[1][1])
                if sem_b > sem_a:
                    best_score, best_func = ranked[1]
                    sem_score = sem_b
                else:
                    sem_score = sem_a

        # Jaccard floor: semantic alone is insufficient for HIGH — too many generic
        # C patterns (alloc+copy+return) score 0.9+ cross-binary with no structural
        # overlap. Require _SEM_JACCARD_MIN structural corroboration for HIGH.
        jaccard_ok = best_score >= self._SEM_JACCARD_MIN
        confidence = (
            'HIGH'   if jaccard_ok and (sem_score >= 0.75 or best_score >= 0.70) else
            'MEDIUM' if sem_score >= 0.55 or best_score >= 0.45 else
            'LOW'
        )

        delta = compute_patch_delta(seed, best_func)
        new_callees     = [c for c in best_func.callees if c not in set(seed.callees)]
        removed_callees = [c for c in seed.callees     if c not in set(best_func.callees)]

        return HomologMatch(
            va=best_func.va,
            name=best_func.name,
            jaccard=best_score,
            semantic_score=sem_score,
            confidence=confidence,
            delta=delta,
            new_callees=new_callees,
            removed_callees=removed_callees,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Version tracker — orchestrates across a list of binaries
# ─────────────────────────────────────────────────────────────────────────────

class VersionTracker:
    """
    Track a seed function across multiple binary versions.

    Usage:
        tracker = VersionTracker(binaries={'v1.0': '/path/fw-v1.0', ...})
        reports = tracker.track(seed_binary='9.14', seed_va=0x4a1234)
        for r in reports:
            print(r.summary())
    """

    def __init__(
        self,
        binaries: dict[str, str],
        semantic_searcher=None,
        angr_load_options: Optional[dict] = None,
    ):
        self._binaries   = binaries          # {version_str: binary_path}
        self._matcher    = FuncMatcher(semantic_searcher)
        self._load_opts  = angr_load_options or {'auto_load_libs': False}
        self._cfg_cache: dict[str, object] = {}

    def _load_cfg(self, binary_path: str):
        """Load angr project and CFGFast, cached by path."""
        if binary_path in self._cfg_cache:
            return self._cfg_cache[binary_path]
        import angr
        proj = angr.Project(binary_path, load_options=self._load_opts, auto_load_libs=False)
        cfg  = proj.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            collect_data_references=True,
        )
        self._cfg_cache[binary_path] = (proj, cfg)
        return proj, cfg

    def _all_features(self, binary_path: str) -> list[FuncFeatures]:
        """Extract FuncFeatures for every function in a binary."""
        proj, cfg = self._load_cfg(binary_path)
        feats = []
        for va, func in cfg.kb.functions.items():
            if func.is_plt or func.is_simprocedure:
                continue
            f = FuncFeatures.from_angr(proj, cfg, va, func.name)
            if f and f.n_instrs >= 4:   # skip stub-size functions
                feats.append(f)
        return feats

    def _seed_features(self, seed_binary: str, seed_va: int, seed_name: str = '') -> Optional[FuncFeatures]:
        proj, cfg = self._load_cfg(seed_binary)
        func = cfg.kb.functions.get(seed_va)
        if func is None:
            # VA may be inside a function whose entry angr placed elsewhere —
            # use floor_func to find the nearest function whose start <= seed_va
            try:
                func = cfg.kb.functions.floor_func(seed_va)
            except Exception:
                pass
        if func is None:
            return None
        return FuncFeatures.from_angr(proj, cfg, func.addr, seed_name or func.name)

    def track(
        self,
        seed_binary:    str,
        seed_va:        int,
        seed_name:      str = '',
        skip_versions:  Optional[list[str]] = None,
        era_only:       bool = False,
        anchors:        dict[str, tuple[bytes, int, str]] | None = None,
    ) -> list[DeltaReport]:
        """
        Find homologs of seed_va across all registered binaries.

        Layer 0 (anchor scan) runs first on every target binary — O(n) bytes scan,
        no CFG load required. Results populate DeltaReport.anchor_results.

        Args:
            era_only: if True and an anchor confirms the era, skip CFG analysis and
                      homolog finding for that binary. DeltaReport.match will be None
                      but DeltaReport.era_confirmed will be set. Use when you only need
                      to know which era a binary belongs to, not the specific homolog VA.
            anchors:  override anchor library; defaults to ERA_DISCRIMINATOR_ANCHORS.

        Returns:
            one DeltaReport per version, in version-registration order.
        """
        skip = set(skip_versions or [])
        seed_path = self._binaries.get(seed_binary)
        if seed_path is None:
            raise ValueError(f"seed binary '{seed_binary}' not in tracker")

        seed_feat = self._seed_features(seed_path, seed_va, seed_name)
        if seed_feat is None:
            raise ValueError(f"Function {hex(seed_va)} not found in {seed_path}")

        reports: list[DeltaReport] = []

        for version, binary_path in self._binaries.items():
            if version == seed_binary or version in skip:
                continue

            # Layer 0: anchor scan — microseconds, no CFG required
            anchor_results: list[AnchorScanResult] = []
            try:
                binary_data = Path(binary_path).read_bytes()
                anchor_results = structural_anchor_scan(binary_data, anchors)
            except Exception:
                pass

            era_hit = any(r.found for r in anchor_results)

            if era_only and era_hit:
                # Anchor confirmed era; skip expensive CFG + homolog finding
                reports.append(DeltaReport(
                    seed_binary=seed_binary,
                    seed_va=seed_va,
                    seed_name=seed_feat.name,
                    target_binary=binary_path,
                    target_version=version,
                    match=None,
                    anchor_results=anchor_results,
                ))
                continue

            # Layers 1-3: CFG + structural pre-filter + Jaccard + semantic
            target_feats = self._all_features(binary_path)
            match = self._matcher.find_homolog(seed_feat, target_feats)
            reports.append(DeltaReport(
                seed_binary=seed_binary,
                seed_va=seed_va,
                seed_name=seed_feat.name,
                target_binary=binary_path,
                target_version=version,
                match=match,
                anchor_results=anchor_results,
            ))

        return reports


# ─────────────────────────────────────────────────────────────────────────────
# Standalone delta: compare two specific functions without a tracker
# ─────────────────────────────────────────────────────────────────────────────

def diff_functions(
    asm_a: list[str],
    name_a: str,
    asm_b: list[str],
    name_b: str,
    callees_a: Optional[list[str]] = None,
    callees_b: Optional[list[str]] = None,
    version_a: str = 'v_a',
    version_b: str = 'v_b',
) -> PatchDelta:
    """
    Quick diff between two functions given their disassembly text.

    No angr required — works on pre-extracted asm_lines from any disassembler.
    """
    fa = FuncFeatures.from_disasm_lines(0, name_a, asm_a, callees_a)
    fb = FuncFeatures.from_disasm_lines(0, name_b, asm_b, callees_b)
    return compute_patch_delta(fa, fb)


def jaccard_similarity(asm_a: list[str], asm_b: list[str]) -> float:
    """4-gram Jaccard similarity between two functions' mnemonic sequences."""
    mnemonics_a = [m for line in asm_a if (m := _mnemonic(line))]
    mnemonics_b = [m for line in asm_b if (m := _mnemonic(line))]
    return jaccard(_ngrams(mnemonics_a, 4), _ngrams(mnemonics_b, 4))
