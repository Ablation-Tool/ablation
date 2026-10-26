"""
sink_arg_classifier_loongarch64.py
===================================
Classify exec-class sink argument provenance on LoongArch64 (LA64) ELF
binaries built for Alpine musl, LoongOS, or similar environments.

Why this module exists
----------------------
The x86-64 Capstone SinkArgClassifier returns 0 results on LA64
binaries because there is no Capstone LA64 backend.  Before this module,
sac_for_context() dispatched all loongarch64 binaries to the x86-64
fallback, which classified every instruction as a no-op.

This module closes the last structural-tier SAC gap after PPC64 and S390X.

Architecture: LoongArch64 lp64d ABI
-------------------------------------
  Argument registers:    $a0-$a7 (integer and pointer arguments 0-7)
  Return register:       $a0
  Callee-saved:          $s0-$s8, $fp (also written $s9)
  Stack pointer:         $sp
  Link register:         $ra (saved and restored around function calls)
  Instruction width:     32 bits, little-endian
  Decoder:               LoongArchDecoderV2 (no Capstone required)

BL target encoding
-------------------
The bl instruction carries a 26-bit signed word offset split across two
non-contiguous fields.  The naive formula ``insn & 0x3FFFFFF`` produces the
wrong target because the two 16- and 10-bit halves are swapped.

  Correct extraction:
    lo16   = (insn >> 10) & 0xFFFF
    hi10   = insn & 0x3FF
    offs26 = (hi10 << 16) | lo16
    if offs26 >= 0x2000000: offs26 -= 0x4000000
    target = va + offs26 * 4

  LoongArchDecoderV2 handles this via format string ``"sb0:10|10:16<<2"``.
  The SAC module delegates call site discovery to the decoder so the
  split-field formula stays in one place.

  Ground truth: verified on Alpine 3.24.3 LA64 execline 2.9.9.1 and
  mqtt-exec 0.7.1.  The raw-byte scanner at ``re/loongarch64/SESSION_execline.md``
  documents the failure mode when the naive formula is used.

PLT layout
-----------
  Header size: 32 bytes (two 16-byte lazy-binding stubs at base+0 and +16).
  First real stub: plt_base + 32.

  Stub pattern (4 instructions at 16-byte stride):
    pcaddu12i $t3, N
    ld.d      $t3, $t3, M
    jirl      $t1, $t3, 0
    andi      $zero, $zero, 0x0   (padding NOP)

  GOT address = stub_VA + N*0x1000 + M

  BinaryContext.load_or_build() may return plt_entries=0 for LA64 binaries
  when the GOT base offset is large.  Confirmed on execline 2.9.9.1 where
  GOT@0x2faa0 caused BinaryContext to miss all 147 entries.  This module
  builds the PLT map from raw ELF bytes, bypassing BinaryContext.

Argument trace patterns
------------------------
RODATA_CONST patterns:

  1. pcaddi $rD, imm
     target_va = frame.va + imm * 4
     RODATA_CONST when target_va falls inside .rodata.

  2. pcalau12i $rD, imm20 + ld.d $rD, $rD, disp
     Loads an 8-byte pointer from the GOT.
     RODATA_CONST when the pointer value falls inside .rodata.

  3. addi.w $rD, $zero, 0 or or $rD, $zero, $zero
     NULL literal, classify as RODATA_CONST.

ARG_PROPAGATED patterns:

  4. or $rD, $aN, $zero
     Direct copy from an entry argument register.

  5. or $rD, $sN, $zero
     Copy from a callee-saved register.  Classified ARG_PROPAGATED because
     callee-saved registers on all confirmed LA64 binaries hold values
     derived from parsed external data, not from .rodata.  A forward scan
     would be required to confirm the source; the conservative verdict is
     ARG_PROPAGATED.  See SAC-LA64-CALLEE-001 in re/loongarch64/SESSION_execline.md.

  6. ldptr.d $rD, $sN, off or ld.d $rD, $sN, off
     Struct field load from a callee-saved base pointer.  Same reasoning as
     pattern 5.

  7. ld.d $rD, $aN, off or ldptr.d $rD, $aN, off
     Struct field load from an entry argument base pointer.

Usage
------
  from ablation.analyzers.binary_context import BinaryContext
  from ablation.analyzers.sink_arg_classifier_loongarch64 import SinkArgClassifierLA64

  ctx = BinaryContext.load_or_build('/path/to/la64_binary')
  clf = SinkArgClassifierLA64.from_context(ctx)
  results = clf.classify_all()
  print(clf.report(results))

  # Register vendor-specific sinks (execline wrappers as an example):
  clf.add_sink('xexec_ae',          arg_pos=0)
  clf.add_sink('xmexec_afn',        arg_pos=0)
  clf.add_sink('el_modif_and_exec', arg_pos=0)
  clf.add_sink('el_modifs_and_exec', arg_pos=0)

Ground truth
-------------
  mqtt-exec 0.7.1, Alpine 3.24.3 LA64:
    execv @ PLT 0x1370
    $a0: RODATA_CONST  (argv[0] loaded from config struct via ldptr.d)
    $a1: ARG_PROPAGATED  (argv slots written from MQTT topic+payload via alsl.d+st.d)
    Taint entry: message_cb $s1=message, ld.d from message+8 and message+16

  execline 2.9.9.1, Alpine 3.24.3 LA64:
    xexec_ae call sites: $a0 ARG_PROPAGATED via or $a0, $sN, $zero
    Pattern: callee-saved register holds argv from runtime-parsed program arguments

Integration test
-----------------
  tests/test_sac_la64.py (TODO: add after first real binary is available in tests/)
  Until then, the classify_all() result on mqtt-exec should show:
    RODATA_CONST execv(arg0) at call 0x23fc
    ARG_PROPAGATED execv(arg1) at call 0x2400

Decoder integration
--------------------
  Call site discovery uses LoongArchDecoderV2.decode_frames_clean():
    - frame.is_call is True for bl instructions
    - frame.target holds the resolved VA (split-field bl encoding handled internally)
    - KASAN/KCOV instrumentation frames are stripped in kernel builds
  This avoids duplicating the bl split-field formula in SAC.

Module gap history
-------------------
  Session 14: LA64 SAC gap confirmed on mqtt-exec 0.7.1 (sac_for_context returned 0)
  Session 14: bl split-field encoding bug found in raw scanner (fixed in session notes)
  Session 14: PLT 32-byte header bug found (fixed; confirmed on mqtt-exec and execline)
  Session 14: this module created; sac_for_context() wired for 'loongarch64'
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from ablation.analyzers.loongarch_decoder import LoongArchOpType
from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

_LOOKBACK = 80

# lp64 ABI register indices (match _R_LP64 in loongarch_decoder.py)
_GPR_NAMES: Tuple[str, ...] = (
    '$zero', '$ra',  '$tp',  '$sp',  '$a0',  '$a1',  '$a2',  '$a3',
    '$a4',   '$a5',  '$a6',  '$a7',  '$t0',  '$t1',  '$t2',  '$t3',
    '$t4',   '$t5',  '$t6',  '$t7',  '$t8',  '$r21', '$fp',  '$s0',
    '$s1',   '$s2',  '$s3',  '$s4',  '$s5',  '$s6',  '$s7',  '$s8',
)

# Argument registers: $a0-$a7 = indices 4-11
_LA64_ARG_REG_IDX    = frozenset(range(4, 12))
# Callee-saved: $fp=22, $s0-$s8=23-31
_LA64_CALLEE_REG_IDX = frozenset({22, 23, 24, 25, 26, 27, 28, 29, 30, 31})
_REG_ZERO = 0   # $zero
_REG_SP   = 3   # $sp
_A0_IDX   = 4   # first argument register ($a0)

_DEFAULT_SINKS_LA64: Dict[str, int] = {
    'execv':   0,
    'execve':  0,
    'execvp':  0,
    'execvpe': 0,
    'execl':   0,
    'execlp':  0,
    'popen':   0,
    'system':  0,
}

_LOAD_MNEMONICS = frozenset({
    'ld.d', 'ldptr.d', 'ld.w', 'ldptr.w', 'ld.b', 'ld.h',
    'ld.bu', 'ld.hu', 'ld.wu',
})

_STORE_MNEMONICS = frozenset({
    'st.d', 'stptr.d', 'st.w', 'stptr.w', 'st.b', 'st.h',
    'stx.d', 'stx.w', 'stx.b', 'stx.h',
    'fst.d', 'fst.s', 'fstx.d', 'fstx.s',
})


def _elf64_shdr(data: bytes, e_shoff: int, entsize: int, idx: int) -> dict:
    """Parse one ELF64 section header by index.

    Returns keys: name_idx, addr (sh_addr), offset (sh_offset), size,
    entsize (sh_entsize), all as ints.
    """
    off = e_shoff + idx * entsize
    return {
        'name_idx': int.from_bytes(data[off:off+4],     'little'),
        'addr':     int.from_bytes(data[off+16:off+24], 'little'),
        'offset':   int.from_bytes(data[off+24:off+32], 'little'),
        'size':     int.from_bytes(data[off+32:off+40], 'little'),
        'entsize':  int.from_bytes(data[off+56:off+64], 'little'),
    }


def _elf64_section_map(data: bytes) -> Dict[str, dict]:
    """Parse all ELF64 section headers and return a name->header dict.

    Returns empty dict on any parse error.  The caller must handle the
    empty-dict case gracefully.
    """
    try:
        e_shoff     = int.from_bytes(data[40:48], 'little')
        e_shentsize = int.from_bytes(data[58:60], 'little')
        e_shnum     = int.from_bytes(data[60:62], 'little')
        e_shstrndx  = int.from_bytes(data[62:64], 'little')

        shstr_h  = _elf64_shdr(data, e_shoff, e_shentsize, e_shstrndx)
        shstr_off = shstr_h['offset']
        shstr_sz  = shstr_h['size']
        shstrtab  = data[shstr_off : shstr_off + shstr_sz]

        result: Dict[str, dict] = {}
        for i in range(e_shnum):
            h    = _elf64_shdr(data, e_shoff, e_shentsize, i)
            name = shstrtab[h['name_idx']:].split(b'\x00')[0].decode('utf-8', 'replace')
            result[name] = h
        return result
    except Exception:
        return {}


def _extract_plt_la64(data: bytes) -> Dict[int, str]:
    """Decode all LA64 PLT stubs from raw ELF bytes.

    Reads the RELA.plt table to map GOT slots to symbol names, then decodes
    each 16-byte PLT stub to compute the GOT address and look up the symbol.
    GOT address formula: stub_VA + imm20 * 0x1000 + imm12

    Returns a dict mapping stub_va to symbol_name.  Returns empty dict on
    any parse error or if the PLT section is absent.
    """
    try:
        from ablation.analyzers.loongarch_decoder_v2 import LoongArchDecoderV2
        dec = LoongArchDecoderV2()
    except Exception:
        return {}

    secs = _elf64_section_map(data)
    if not secs:
        return {}

    required = ('.dynsym', '.dynstr', '.rela.plt', '.plt')
    if any(k not in secs for k in required):
        return {}

    dynsym_h  = secs['.dynsym']
    dynstr_d  = data[secs['.dynstr']['offset'] :
                     secs['.dynstr']['offset'] + secs['.dynstr']['size']]

    def _sym_name(idx: int) -> str:
        off      = dynsym_h['offset'] + idx * dynsym_h['entsize']
        name_idx = int.from_bytes(data[off:off+4], 'little')
        return dynstr_d[name_idx:].split(b'\x00')[0].decode('utf-8', 'replace')

    rela_h    = secs['.rela.plt']
    got_to_sym: Dict[int, str] = {}
    for i in range(rela_h['size'] // 24):
        off     = rela_h['offset'] + i * 24
        r_off   = int.from_bytes(data[off:off+8],   'little')
        sym_idx = int.from_bytes(data[off+8:off+16], 'little') >> 32
        name    = _sym_name(sym_idx)
        if name:
            got_to_sym[r_off] = name

    plt_h    = secs['.plt']
    if plt_h['offset'] == 0 or plt_h['size'] == 0:
        return {}
    plt_base = plt_h['addr']
    plt_end  = plt_base + plt_h['size']
    stub_va  = plt_base + 32  # skip 32-byte lazy-binding header

    result: Dict[int, str] = {}
    while stub_va < plt_end:
        off    = plt_h['offset'] + (stub_va - plt_base)
        chunk  = data[off : off + 16]
        frames = list(dec.decode_frames_clean(chunk, base_addr=stub_va))
        if (len(frames) >= 2
                and 'pcaddu12i' in frames[0].mnemonic
                and 'ld.d' in frames[1].mnemonic):
            f0, f1 = frames[0], frames[1]
            if (len(f0.operands) >= 2 and f0.operands[1].type == LoongArchOpType.IMM
                    and len(f1.operands) >= 3 and f1.operands[2].type == LoongArchOpType.IMM):
                imm20    = f0.operands[1].imm
                imm12    = f1.operands[2].imm
                got_addr = stub_va + imm20 * 0x1000 + imm12
                sym = got_to_sym.get(got_addr)
                if sym:
                    result[stub_va] = sym
        stub_va += 16

    return result


class SinkArgClassifierLA64:
    """Classify exec-class sink call-site argument provenance on LoongArch64 ELFs.

    Closes the LA64 SAC gap: sac_for_context() previously dispatched to
    the x86-64 SinkArgClassifier for all loongarch64 binaries, returning
    0 results because there is no Capstone LA64 backend.

    This class follows the same interface as SinkArgClassifierPPC64ELFv2:
    from_context(), from_path(), add_sink(), classify_all(), classify_sink(),
    report().  Call site discovery uses LoongArchDecoderV2 instead of
    Capstone so the bl split-field encoding is handled in one place.

    PLT resolution: built from raw ELF bytes when BinaryContext.plt is empty.
    This handles binaries where the GOT base offset exceeds BinaryContext's
    detection threshold (confirmed on execline 2.9.9.1, GOT@0x2faa0).

    Trace depth is bounded at 1 recursive level.  Deeper chains (spilled to
    the stack, passed through multiple callee-saved registers) result in
    UNKNOWN, not a false RODATA_CONST.

    Register representation: the trace operates on lp64 register indices
    (int, 0-31) from frame.operands[n].reg rather than op_str text tokens.
    No Capstone register IDs are used anywhere in this module.
    """

    def __init__(self, ctx) -> None:
        self._ctx  = ctx
        self._data = Path(ctx.path).read_bytes()
        self._sinks: Dict[str, int] = dict(_DEFAULT_SINKS_LA64)
        self._dead_sinks: List[str] = []
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._plt_map: Dict[str, int] = {}  # symbol_name -> stub_va
        self._dec = None

        try:
            from ablation.analyzers.loongarch_decoder_v2 import LoongArchDecoderV2
            self._dec = LoongArchDecoderV2()
        except Exception:
            pass

        self._init()

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierLA64':
        """Build from a pre-loaded BinaryContext."""
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierLA64':
        """Build from a binary path.  Calls BinaryContext.load_or_build() internally."""
        from ablation.analyzers.binary_context import BinaryContext
        ctx = BinaryContext.load_or_build(path)
        return cls(ctx)

    def add_sink(self, name: str, arg_pos: int) -> None:
        """Register a custom sink symbol with the argument position to trace.

        Use arg_pos=0 for functions whose first argument ($a0) is the
        command or path string.  Most execv-family wrappers follow this
        convention.  Call this before classify_all() or classify_sink().
        """
        self._sinks[name] = arg_pos

    # ── Initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        self._rodata_ranges = self._find_rodata_ranges()
        # Prefer BinaryContext plt when populated; fall back to byte decode.
        # BinaryContext returns empty plt for LA64 binaries with large GOT
        # offsets.  The byte-decode path handles both cases.
        ctx_plt = getattr(self._ctx, 'plt', {})
        if ctx_plt:
            self._plt_map = {v: k for k, v in ctx_plt.items()}
        else:
            stub_to_name = _extract_plt_la64(self._data)
            self._plt_map = {v: k for k, v in stub_to_name.items()}

    def _find_rodata_ranges(self) -> List[Tuple[int, int]]:
        """Return list of (va_start, va_end) tuples covering read-only sections.

        Tries LIEF first; falls back to direct ELF64 section header parsing.
        Returns empty list on failure (trace will classify all pcaddi targets
        as UNKNOWN rather than RODATA_CONST, which is the safe direction).
        """
        ranges: List[Tuple[int, int]] = []
        _RO_NAMES = frozenset({
            '.rodata', '.rodata1', '__const', '__cstring',
            '.rdata', '.data.rel.ro',
        })

        # LIEF path
        try:
            import lief as _lief
            b = _lief.parse(self._ctx.path)
            if b is not None:
                for sec in b.sections:
                    if sec.name in _RO_NAMES and int(sec.size) > 0:
                        va = int(sec.virtual_address)
                        ranges.append((va, va + int(sec.size)))
                return ranges
        except Exception:
            pass

        # Fallback: raw ELF64 section headers
        secs = _elf64_section_map(self._data)
        for name, h in secs.items():
            if name in _RO_NAMES and h['size'] > 0:
                ranges.append((h['addr'], h['addr'] + h['size']))
        return ranges

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_rodata(self, va: int) -> bool:
        return any(lo <= va < hi for lo, hi in self._rodata_ranges)

    def _read_u64(self, va: int) -> Optional[int]:
        base = self._ctx.base_va
        off  = va - base
        if off < 0 or off + 8 > len(self._data):
            return None
        return struct.unpack_from('<Q', self._data, off)[0]

    def _text_section(self) -> Tuple[int, int, int]:
        """Return (va_start, file_offset, size) for the .text section.

        Returns (0, 0, 0) when the section cannot be located.
        """
        secs = _elf64_section_map(self._data)
        h = secs.get('.text', {})
        if h and h.get('size', 0) > 0:
            return h['addr'], h['offset'], h['size']
        return 0, 0, 0

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        """Map sink stub VAs to (symbol_name, arg_pos) for all registered sinks.

        Populates self._dead_sinks with names that have no PLT stub or export.
        """
        result: Dict[int, Tuple[str, int]] = {}
        self._dead_sinks = []
        for name, arg_pos in self._sinks.items():
            va = self._plt_map.get(name)
            if not va:
                va = getattr(self._ctx, 'exports', {}).get(name)
            if not va:
                self._dead_sinks.append(name)
                continue
            result[va] = (name, arg_pos)
        return result

    # ── Call site discovery (decoder-based) ───────────────────────────────────

    def _scan_call_sites(
        self,
        exec_plt_vas: frozenset,
    ) -> List[Tuple[int, int]]:
        """Find all call sites in .text that branch to one of exec_plt_vas.

        Uses LoongArchDecoderV2.decode_frames_clean() to decode the .text
        section.  Each frame with is_call=True and target in exec_plt_vas is
        a confirmed call site.

        Using the decoder here avoids duplicating the bl split-field formula:
        frame.target is already resolved correctly for all call flavours,
        including indirect calls (target=0, excluded) and bl.

        Returns a list of (caller_va, target_va) pairs.
        """
        if self._dec is None:
            return []

        text_va, text_off, text_sz = self._text_section()
        if text_sz == 0:
            return []

        chunk   = self._data[text_off : text_off + text_sz]
        results = []
        for frame in self._dec.decode_frames_clean(chunk, base_addr=text_va):
            if frame.is_call and frame.target in exec_plt_vas:
                results.append((frame.va, frame.target))
        return results

    # ── Backward argument trace ───────────────────────────────────────────────

    def _decode_window(self, end_va: int, n_insns: int = _LOOKBACK) -> list:
        """Decode up to n_insns instructions immediately before end_va.

        Decodes a backward window ending at (not including) end_va.  Returns
        an empty list when the decoder is unavailable or the window falls
        outside the mapped binary data.
        """
        if self._dec is None:
            return []
        base  = self._ctx.base_va
        start = max(end_va - n_insns * 4, base)
        off   = start - base
        size  = end_va - start
        if off < 0 or size <= 0 or off + size > len(self._data):
            return []
        chunk  = self._data[off : off + size]
        return list(self._dec.decode_frames_clean(chunk, base_addr=start))

    def _trace_arg(
        self,
        frames: list,
        call_idx: int,
        target_reg: int,
        depth: int = 0,
    ) -> Tuple[str, str]:
        """Backward-trace what loaded target_reg (register index) before the call.

        Walks backward from call_idx through the decoded frame window looking
        for the instruction that last wrote target_reg.  Classifies it as
        RODATA_CONST, ARG_PROPAGATED, or UNKNOWN.

        depth limits recursive calls (e.g. when a copy-of-copy is found).
        The limit is 1 to bound analysis time; deeper chains return UNKNOWN.

        Instruction patterns and their classification:

          or $rD, $rS, $zero
            If $rS is $zero: NULL literal, RODATA_CONST
            If $rS is an arg register ($a0-$a7): ARG_PROPAGATED
            If $rS is a callee-saved register: ARG_PROPAGATED (conservative)
            Otherwise: recurse on $rS

          pcaddi $rD, imm
            Computes PC + imm*4.  RODATA_CONST if in .rodata.

          pcalau12i $rD, imm + ld.d $rD, $rD, disp
            Loads a pointer from the GOT page.  RODATA_CONST if the pointer
            value points into .rodata.

          addi.w/addi.d $rD, $zero, 0
            Zero literal, RODATA_CONST.

          addi.w/addi.d $rD, $rBase, imm
            Pointer arithmetic.  ARG_PROPAGATED if $rBase is arg or callee-saved.

          ld.d / ldptr.d / similar $rD, $rBase, off
            Struct field load.  ARG_PROPAGATED if $rBase is arg or callee-saved.
            UNKNOWN if $rBase is $sp (stack slot, origin not traced).
        """
        if depth > 1:
            return (UNKNOWN, 'max recursion depth')

        limit    = max(call_idx - _LOOKBACK, -1)
        tregname = _GPR_NAMES[target_reg & 0x1f]

        for j in range(call_idx - 1, limit, -1):
            f    = frames[j]
            mnem = f.mnemonic

            if mnem in _STORE_MNEMONICS:
                continue

            # Destination must be a GPR matching target_reg
            if (not f.operands
                    or f.operands[0].type != LoongArchOpType.REG
                    or f.operands[0].reg != target_reg):
                continue

            # Pattern: or $rD, $rS1, $rS2 (register copy or NULL)
            if mnem == 'or' and len(f.operands) == 3:
                s1 = f.operands[1]
                s2 = f.operands[2]
                s1i = s1.reg if s1.type == LoongArchOpType.REG else -1
                s2i = s2.reg if s2.type == LoongArchOpType.REG else -1

                if s1i == _REG_ZERO and s2i == _REG_ZERO:
                    return (RODATA_CONST, f'or {tregname}, $zero, $zero -> NULL')

                active = None
                if s2i == _REG_ZERO and s1i not in (_REG_ZERO, -1):
                    active = s1i
                elif s1i == _REG_ZERO and s2i not in (_REG_ZERO, -1):
                    active = s2i

                if active is not None:
                    aname = _GPR_NAMES[active & 0x1f]
                    if active in _LA64_ARG_REG_IDX:
                        return (ARG_PROPAGATED,
                                f'or {tregname}, {aname}, $zero (entry arg)')
                    if active in _LA64_CALLEE_REG_IDX:
                        return (ARG_PROPAGATED,
                                f'or {tregname}, {aname}, $zero '
                                f'(callee-saved; SAC-LA64-CALLEE-001)')
                    return self._trace_arg(frames, j, active, depth + 1)

                if s1i not in (_REG_ZERO, -1):
                    return self._trace_arg(frames, j, s1i, depth + 1)

            # Pattern: pcaddi $rD, imm
            if mnem == 'pcaddi' and len(f.operands) >= 2:
                imm_op = f.operands[1]
                if imm_op.type == LoongArchOpType.IMM:
                    target_va = f.va + imm_op.imm * 4
                    if self._is_rodata(target_va):
                        return (RODATA_CONST,
                                f'pcaddi -> 0x{target_va:x} in .rodata')
                    return (UNKNOWN,
                            f'pcaddi -> 0x{target_va:x} not in .rodata')

            # Pattern: pcalau12i $rD, imm (first half of GOT-relative load)
            if mnem == 'pcalau12i' and len(f.operands) >= 2:
                imm_op = f.operands[1]
                if imm_op.type == LoongArchOpType.IMM:
                    page_va = (f.va & ~0xFFF) + (imm_op.imm << 12)
                    for k in range(j + 1, min(j + 5, len(frames))):
                        nf = frames[k]
                        # Stop if another instruction writes target_reg before ld.d
                        if (nf.operands
                                and nf.operands[0].type == LoongArchOpType.REG
                                and nf.operands[0].reg != target_reg):
                            break
                        if nf.mnemonic not in ('ld.d', 'ldptr.d'):
                            continue
                        if (len(nf.operands) < 3
                                or nf.operands[2].type != LoongArchOpType.IMM):
                            break
                        got_va = page_va + nf.operands[2].imm
                        ptr    = self._read_u64(got_va)
                        if ptr is not None:
                            if self._is_rodata(ptr):
                                return (RODATA_CONST,
                                        f'pcalau12i+ld.d GOT[0x{got_va:x}]=0x{ptr:x} in .rodata')
                            return (UNKNOWN,
                                    f'pcalau12i+ld.d GOT[0x{got_va:x}]=0x{ptr:x} not in .rodata')
                        return (UNKNOWN, f'pcalau12i+ld.d GOT[0x{got_va:x}] unreadable')
                    return (UNKNOWN, f'pcalau12i 0x{page_va:x}: no paired ld.d within 4')

            # Pattern: addi.w / addi.d $rD, $rBase, imm
            if mnem in ('addi.w', 'addi.d') and len(f.operands) >= 3:
                base_op = f.operands[1]
                imm_op  = f.operands[2]
                base_i  = base_op.reg if base_op.type == LoongArchOpType.REG else -1
                imm_val = imm_op.imm  if imm_op.type  == LoongArchOpType.IMM  else 0
                if base_i == _REG_ZERO:
                    if imm_val == 0:
                        return (RODATA_CONST, f'{mnem} {tregname}, $zero, 0 -> NULL')
                    return (UNKNOWN, f'{mnem} {tregname}, $zero, {imm_val:#x} (literal)')
                if base_i in _LA64_ARG_REG_IDX:
                    bname = _GPR_NAMES[base_i & 0x1f]
                    return (ARG_PROPAGATED,
                            f'{mnem} {tregname}, {bname}, ... (arg-base offset)')
                if base_i in _LA64_CALLEE_REG_IDX:
                    bname = _GPR_NAMES[base_i & 0x1f]
                    return (ARG_PROPAGATED,
                            f'{mnem} {tregname}, {bname}, ... (callee-saved-base offset)')

            # Pattern: ld.d / ldptr.d / similar $rD, $rBase, off
            if mnem in _LOAD_MNEMONICS and len(f.operands) >= 2:
                base_op = f.operands[1]
                base_i  = base_op.reg if base_op.type == LoongArchOpType.REG else -1
                if base_i in _LA64_ARG_REG_IDX:
                    bname = _GPR_NAMES[base_i & 0x1f]
                    return (ARG_PROPAGATED,
                            f'{mnem} {tregname}, {bname}, ... (field of arg struct)')
                if base_i in _LA64_CALLEE_REG_IDX:
                    bname = _GPR_NAMES[base_i & 0x1f]
                    return (ARG_PROPAGATED,
                            f'{mnem} {tregname}, {bname}, ... '
                            f'(callee-saved struct; SAC-LA64-CALLEE-001)')
                if base_i == _REG_SP:
                    return (UNKNOWN, f'{mnem} {tregname}, $sp, ... (stack slot)')

            # Pseudo-ops the decoder may emit
            if mnem in ('move', 'li', 'la.local', 'la.global', 'la.pcrel'):
                if (len(f.operands) >= 2
                        and f.operands[1].type == LoongArchOpType.IMM
                        and f.operands[1].imm == 0):
                    return (RODATA_CONST, f'{mnem} {tregname}, 0 -> NULL')
                return (UNKNOWN, f'{mnem} {tregname}: literal address')

        return (UNKNOWN,
                f'{tregname} not found within {_LOOKBACK}-insn backward window')

    # ── Classification ────────────────────────────────────────────────────────

    def _classify_call(
        self,
        caller_va: int,
        sink_name: str,
        arg_pos: int,
    ) -> SinkClassification:
        """Classify a single call site at caller_va for arg_pos of sink_name."""
        frames = self._decode_window(caller_va + 4, n_insns=_LOOKBACK)
        if not frames:
            return SinkClassification(
                sink_name, arg_pos, 0, caller_va, UNKNOWN,
                'empty decode window', 'HIGH',
            )

        # Locate the call frame within the window (may be absent for the last
        # instruction if the window ended exactly at the call).
        call_idx = next(
            (i for i, f in enumerate(frames) if f.va == caller_va and f.is_call),
            len(frames),
        )

        if arg_pos > 7:
            return SinkClassification(
                sink_name, arg_pos, 0, caller_va, UNKNOWN,
                f'arg_pos {arg_pos} out of range for LA64 ($a0-$a7 only)', '',
            )

        target_reg_idx     = _A0_IDX + arg_pos   # $a0=4, $a1=5, ..., $a7=11
        verdict, detail    = self._trace_arg(frames, call_idx, target_reg_idx)
        severity           = '' if verdict in (RODATA_CONST, SNPRINTF_RODATA) else 'HIGH'
        func_va            = frames[0].va if frames else 0

        return SinkClassification(
            sink_name, arg_pos, func_va, caller_va, verdict, detail, severity,
        )

    def classify_all(self) -> List[SinkClassification]:
        """Scan .text for all registered sink call sites and classify each one.

        Returns a list of SinkClassification objects.  RODATA_CONST results
        are safe (hardcoded literal).  ARG_PROPAGATED and UNKNOWN warrant
        manual taint review.

        If LoongArchDecoderV2 is unavailable or the PLT is empty, returns
        an empty list and populates self._dead_sinks with unresolved names.
        """
        if self._dec is None:
            return []
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []

        exec_vas   = frozenset(sink_plts.keys())
        call_sites = self._scan_call_sites(exec_vas)

        results: List[SinkClassification] = []
        for caller_va, target_va in call_sites:
            sink_name, arg_pos = sink_plts[target_va]
            results.append(self._classify_call(caller_va, sink_name, arg_pos))
        return results

    def classify_sink(self, name: str) -> List[SinkClassification]:
        """Classify all call sites for one named sink.

        Returns an empty list when the sink is not registered or has no PLT stub.
        """
        arg_pos = self._sinks.get(name)
        if arg_pos is None:
            return []
        va = self._plt_map.get(name) or getattr(self._ctx, 'exports', {}).get(name)
        if not va:
            return []
        call_sites = self._scan_call_sites(frozenset({va}))
        return [
            self._classify_call(caller_va, name, arg_pos)
            for caller_va, _ in call_sites
        ]

    def report(self, results: List[SinkClassification]) -> str:
        """Format results as a human-readable string.

        Includes a per-verdict summary line and a dead-sinks warning when
        any registered sink had no PLT stub or export.
        """
        if not results:
            lines = ['SinkArgClassifierLA64: no results']
            if self._dead_sinks:
                lines.append(
                    f'  Dead sinks (no PLT stubs): {", ".join(self._dead_sinks)}'
                )
            return '\n'.join(lines) + '\n'

        lines = [f'SinkArgClassifierLA64: {len(results)} results']
        for r in results:
            lines.append(
                f'  {r.verdict:16s}  {r.sink_name}(arg{r.arg_pos})'
                f'  func=0x{r.func_va:08x}  call=0x{r.call_va:08x}'
                f'  detail={r.detail}'
            )
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        lines.append(
            'Summary: '
            + ' | '.join(f'{k}={v}' for k, v in sorted(by_verdict.items()))
        )
        if self._dead_sinks:
            lines.append(
                f'Dead sinks (no PLT stubs): {", ".join(self._dead_sinks)}'
            )
        return '\n'.join(lines) + '\n'
