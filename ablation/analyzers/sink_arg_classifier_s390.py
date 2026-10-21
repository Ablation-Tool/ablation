"""
sink_arg_classifier_s390.py: classify exec-class sink argument provenance on
s390 (31-bit) and s390x (64-bit) BE ELFs.

Gap this fills (S390-GAP-001):
  BinaryContext detects ELF e_machine 0x0016 (EM_S390) and falls through to its
  x86_64 PLT parser, which returns plt=0 (parse failure) — masking any exec-class
  dynamic imports.  Ablation SinkArgClassifier therefore cannot run.  This module
  uses LIEF directly for DYNSYM enumeration and Capstone CS_ARCH_SYSZ for
  disassembly, completely bypassing BinaryContext's broken s390x path.

Evidence for this gap: IBM ClearCase linux_390 (cleartool, 20516 bytes), IBM
Rational BuildForge 7.1.1.3 bfagent (s390x), IBM XL C/C++ Compiler 1.2.0 for
s390x — all returned BinaryContext.arch='x86_64' with plt=0.

Four verdicts (consistent with all other SinkArgClassifier variants):
  RODATA_CONST     — argument is a .rodata address or literal immediate.
  SNPRINTF_RODATA  — stack buffer filled by snprintf with a .rodata format string.
  ARG_PROPAGATED   — argument traces back to an entry-point register (r2–r6).
  UNKNOWN          — provenance not resolved within the look-back window.

s390x System V ABI (both 31-bit s390 and 64-bit s390x):
  Argument 0 → r2    Argument 1 → r3    Argument 2 → r4
  Argument 3 → r5    Argument 4 → r6

s390x string-address load patterns handled:
  1. larl  %rX, addr        PC-relative address load.
                            If addr in .rodata → RODATA_CONST.
  2. lghi  %rX, imm         16-bit sign-extended immediate → RODATA_CONST (NULL/literal).
     lhi   %rX, imm
  3. lgfi  %rX, imm         32-bit sign-extended immediate → RODATA_CONST.
  4. lgr   %rX, %rY  /      Register copy.  Recurse on source register.
     lr    %rX, %rY
  5. la    %rX, N(%r15)     Address of stack slot; trigger snprintf back-track.
     lay   %rX, N(%r15)
  6. lgrl  %rX, addr        64-bit load from PC-relative address.
                            If target in .rodata → RODATA_CONST.
  7. lg    %rX, N(%rY)      64-bit load from memory.
     l     %rX, N(%rY)      If rY is an entry-arg register (r2–r6) → ARG_PROPAGATED.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_s390 import SinkArgClassifierS390X

    ctx = BinaryContext.load_or_build('/path/to/bfagent')
    clf = SinkArgClassifierS390X.from_path(ctx.path)  # bypass BinaryContext PLT gap

    results = clf.classify_all()
    print(clf.report(results))
"""

from __future__ import annotations

import bisect
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
    from capstone.sysz_const import (
        SYSZ_OP_REG, SYSZ_OP_MEM, SYSZ_OP_IMM,
        SYSZ_REG_0,  SYSZ_REG_1,  SYSZ_REG_2,  SYSZ_REG_3,
        SYSZ_REG_4,  SYSZ_REG_5,  SYSZ_REG_6,  SYSZ_REG_7,
        SYSZ_REG_14, SYSZ_REG_15,
        SYSZ_INS_LARL,  SYSZ_INS_LA,    SYSZ_INS_LAY,
        SYSZ_INS_LGHI,  SYSZ_INS_LHI,   SYSZ_INS_LGFI,
        SYSZ_INS_LGR,   SYSZ_INS_LR,
        SYSZ_INS_LGRL,  SYSZ_INS_LGF,
    )
    _CS_OK = True
except ImportError:
    # Stubs so the module can be imported without Capstone
    (SYSZ_OP_REG, SYSZ_OP_MEM, SYSZ_OP_IMM) = (1, 3, 2)
    (SYSZ_REG_0,  SYSZ_REG_1,  SYSZ_REG_2,  SYSZ_REG_3,
     SYSZ_REG_4,  SYSZ_REG_5,  SYSZ_REG_6,  SYSZ_REG_7) = range(1, 9)
    (SYSZ_REG_14, SYSZ_REG_15) = (15, 16)
    (SYSZ_INS_LARL, SYSZ_INS_LA,   SYSZ_INS_LAY,
     SYSZ_INS_LGHI, SYSZ_INS_LHI,  SYSZ_INS_LGFI,
     SYSZ_INS_LGR,  SYSZ_INS_LR,
     SYSZ_INS_LGRL, SYSZ_INS_LGF)  = (410, 401, 413, 448, 455, 444, 451, 493, 452, 443)

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# Re-use shared verdict constants
from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── s390x argument registers (r2 = arg0 … r6 = arg4) ─────────────────────────
# Capstone SYSZ_REG_N values: SYSZ_REG_2=3, SYSZ_REG_3=4, …
_S390_ARG_REGS: List[int] = [
    SYSZ_REG_2, SYSZ_REG_3, SYSZ_REG_4, SYSZ_REG_5, SYSZ_REG_6,
]
_S390_ENTRY_ARG_SET = frozenset(_S390_ARG_REGS)
_S390_SP_REG = SYSZ_REG_15

_S390_REG_NAMES: Dict[int, str] = {
    SYSZ_REG_0: 'r0', SYSZ_REG_1: 'r1', SYSZ_REG_2: 'r2', SYSZ_REG_3: 'r3',
    SYSZ_REG_4: 'r4', SYSZ_REG_5: 'r5', SYSZ_REG_6: 'r6', SYSZ_REG_7: 'r7',
    SYSZ_REG_14: 'r14', SYSZ_REG_15: 'r15',
}

# ── Default exec-class sinks ──────────────────────────────────────────────────
_DEFAULT_SINKS_S390: Dict[str, int] = {
    'system':   0,
    'popen':    0,
    'execve':   0,
    'execvp':   0,
    'execl':    0,
    'execlp':   0,
    'execle':   0,
    'execvpe':  0,
}

# snprintf-family: fmt arg position (0-indexed, r2=pos0)
_SNPRINTF_FMT_POS_S390: Dict[str, int] = {
    'snprintf':       2,   # r2=buf, r3=size, r4=fmt
    'vsnprintf':      2,
    'sprintf':        1,   # r2=buf, r3=fmt
    '__sprintf_chk':  3,
    '__snprintf_chk': 3,
}

_LOOKBACK        = 80
_SNPRINTF_WINDOW = 140
_MAX_FUNC_BYTES  = 65536


def _rname(reg_id: int) -> str:
    return _S390_REG_NAMES.get(reg_id, f'r{reg_id}')


def _sign16(v: int) -> int:
    return v if v < 0x8000 else v - 0x10000


def _sign32(v: int) -> int:
    return v if v < 0x80000000 else v - 0x100000000


class SinkArgClassifierS390X:
    """
    Classify exec-class sink call-site argument provenance on s390/s390x BE ELFs.

    Fills S390-GAP-001: BinaryContext returns plt=0 for s390/s390x (e_machine=0x0016)
    due to architecture detection mismatch.  Use from_path() instead of from_context()
    to bypass BinaryContext's broken s390 PLT path.
    """

    def __init__(self, path: str) -> None:
        self._path                              = path
        self._data: bytes                       = Path(path).read_bytes()
        self._sinks: Dict[str, int]             = dict(_DEFAULT_SINKS_S390)
        self._snprintf_plts: Dict[int, int]     = {}   # PLT VA → fmt arg position
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._dead_sinks: List[str]             = []
        self._func_starts: List[int]            = []
        self._bin                               = None
        self._cs: Optional[Cs]                 = None
        self._is_64bit: bool                    = False
        if _CS_OK:
            self._cs = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.ELF.parse(path)
        self._init()

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierS390X':
        """Construct directly from file path, bypassing BinaryContext's s390 gap."""
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierS390X':
        """Accept a BinaryContext for API consistency; uses ctx.path internally."""
        return cls(ctx.path)

    def add_sink(self, name: str, arg_pos: int) -> None:
        """Register a vendor-specific exec-class sink."""
        self._sinks[name] = arg_pos

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        # Detect word size
        self._is_64bit = (self._bin.header.identity_class == _lief.ELF.Header.CLASS.ELF64)
        # Collect .rodata ranges for string-address checking
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring',
                            '.rdata', '.data.rel.ro'):
                self._rodata_ranges.append(
                    (int(sec.virtual_address),
                     int(sec.virtual_address) + int(sec.size))
                )
        # Snprintf PLT stubs
        for sym_name, fmt_pos in _SNPRINTF_FMT_POS_S390.items():
            va = self._get_plt_va(sym_name)
            if va:
                self._snprintf_plts[va] = fmt_pos
        # Function starts from ELF symbol table
        self._func_starts = sorted(
            int(s.value)
            for s in self._bin.symbols
            if s.value and s.type == _lief.ELF.Symbol.TYPE.FUNC
        ) if _LIEF_OK and self._bin else []

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata_ranges)

    def _get_plt_va(self, sym_name: str) -> Optional[int]:
        """
        Return the PLT stub VA for sym_name, or None.
        s390x PLT layout: stub[0]=resolver (32 bytes), stub[N]=plt_base+32*(N+1).
        R_390_JMP_SLOT relocations in .rela.plt are ordered; their 0-indexed rank
        gives stub N.
        """
        if not _LIEF_OK or self._bin is None:
            return None
        plt_sec = self._bin.get_section('.plt')
        if plt_sec is None:
            return None
        plt_base = int(plt_sec.virtual_address)
        # s390x PLT stub size: 32 bytes (both 31-bit and 64-bit)
        PLT_STUB_SIZE = 32
        for idx, rel in enumerate(self._bin.pltgot_relocations):
            if rel.symbol and rel.symbol.name == sym_name:
                # Stub 0 is resolver; first imported symbol is stub 1
                return plt_base + PLT_STUB_SIZE * (idx + 1)
        return None

    def _va_to_file_offset(self, va: int) -> int:
        if self._bin is None:
            return va
        try:
            return int(self._bin.virtual_address_to_offset(va))
        except Exception:
            return -1

    def _read_va(self, va: int, size: int) -> bytes:
        off = self._va_to_file_offset(va)
        if off < 0 or off >= len(self._data):
            return b''
        return self._data[off:off + size]

    def _writes_reg(self, insn, reg_id: int) -> bool:
        if not insn.operands:
            return False
        op = insn.operands[0]
        return op.type == SYSZ_OP_REG and op.reg == reg_id

    def _next_func_va(self, func_va: int) -> Optional[int]:
        if not self._func_starts:
            return None
        idx = bisect.bisect_right(self._func_starts, func_va)
        return self._func_starts[idx] if idx < len(self._func_starts) else None

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        result: Dict[int, Tuple[str, int]] = {}
        self._dead_sinks = []
        for name, arg_pos in self._sinks.items():
            va = self._get_plt_va(name)
            if not va:
                self._dead_sinks.append(name)
                continue
            result[va] = (name, arg_pos)
        return result

    # ── lookback classifier ───────────────────────────────────────────────────

    def _classify_reg(
        self,
        insns: List,
        call_idx: int,
        target_reg: int,
        depth: int = 0,
    ) -> str:
        """Walk backwards from call_idx to determine argument register provenance."""
        if depth > 12:
            return UNKNOWN
        lo = max(0, call_idx - _LOOKBACK)
        for i in range(call_idx - 1, lo - 1, -1):
            insn = insns[i]
            if not self._writes_reg(insn, target_reg):
                continue
            id_ = insn.id

            # larl %rX, addr  — PC-relative address load
            if id_ == SYSZ_INS_LARL and len(insn.operands) >= 2:
                op1 = insn.operands[1]
                if op1.type == SYSZ_OP_IMM:
                    addr = op1.imm & 0xFFFFFFFFFFFFFFFF
                    return RODATA_CONST if self._is_rodata(addr) else UNKNOWN

            # lghi / lhi / lgfi — immediate load
            if id_ in (SYSZ_INS_LGHI, SYSZ_INS_LHI, SYSZ_INS_LGFI):
                return RODATA_CONST  # literal constant (NULL or flag)

            # lgr / lr — register copy
            if id_ in (SYSZ_INS_LGR, SYSZ_INS_LR) and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == SYSZ_OP_REG:
                    if src.reg in _S390_ENTRY_ARG_SET:
                        return ARG_PROPAGATED
                    return self._classify_reg(insns, i, src.reg, depth + 1)

            # lgrl %rX, addr — 64-bit load from PC-relative address
            if id_ == SYSZ_INS_LGRL and len(insn.operands) >= 2:
                op1 = insn.operands[1]
                if op1.type == SYSZ_OP_IMM:
                    ptr_va = op1.imm & 0xFFFFFFFFFFFFFFFF
                    raw = self._read_va(ptr_va, 8)
                    if len(raw) == 8:
                        tgt = struct.unpack_from('>Q', raw)[0]
                        return RODATA_CONST if self._is_rodata(tgt) else UNKNOWN
                return UNKNOWN

            # la / lay %rX, N(%r15) — stack-slot address
            if id_ in (SYSZ_INS_LA, SYSZ_INS_LAY) and len(insn.operands) >= 2:
                op1 = insn.operands[1]
                if op1.type == SYSZ_OP_MEM and op1.mem.base == _S390_SP_REG:
                    verdict = self._check_snprintf_fill(insns, i, target_reg)
                    if verdict:
                        return verdict
                    return UNKNOWN
                return UNKNOWN

            # lg / l %rX, N(%rY) — memory load
            if id_ in (SYSZ_INS_LGF, 494) and len(insn.operands) >= 2:  # 494=LG in SYSZ
                op1 = insn.operands[1]
                if op1.type == SYSZ_OP_MEM:
                    base_reg = op1.mem.base
                    if base_reg in _S390_ENTRY_ARG_SET:
                        return ARG_PROPAGATED
                return UNKNOWN

            return UNKNOWN

        return UNKNOWN

    def _check_snprintf_fill(
        self,
        insns: List,
        stack_addr_idx: int,
        target_reg: int,
    ) -> Optional[str]:
        """
        Return SNPRINTF_RODATA if the stack slot was filled by snprintf with a
        .rodata format string within _SNPRINTF_WINDOW instructions before the call.
        """
        lo = max(0, stack_addr_idx - _SNPRINTF_WINDOW)
        for i in range(stack_addr_idx - 1, lo - 1, -1):
            insn = insns[i]
            # Identify BRASL/BAS calls to snprintf PLT stubs by checking the
            # branch target VA in the operand, not insn.id (which is a small
            # Capstone enum constant, never a PLT VA).
            target_va: Optional[int] = None
            for op in insn.operands:
                if op.type == SYSZ_OP_IMM:
                    target_va = op.imm & 0xFFFFFFFFFFFFFFFF
                    break
            if target_va is None or target_va not in self._snprintf_plts:
                continue
            fmt_pos = self._snprintf_plts[target_va]
            fmt_reg = _S390_ARG_REGS[fmt_pos] if fmt_pos < len(_S390_ARG_REGS) else None
            if fmt_reg is None:
                continue
            fmt_verdict = self._classify_reg(insns, i, fmt_reg, depth=0)
            if fmt_verdict == RODATA_CONST:
                return SNPRINTF_RODATA
        return None

    # ── classify_all ─────────────────────────────────────────────────────────

    def _raw_brasl_scan(
        self,
        sink_plts: Dict[int, Tuple[str, int]],
        text_va: int,
        text_data: bytes,
    ) -> List[SinkClassification]:
        """
        Byte-sweep a raw code segment for BRASL instructions whose target is a
        PLT sink.  Used for stripped binaries where ELF FUNC symbols do not cover
        the actual code.

        s390x BRASL encoding: 0xC0 0xE5 <i32 half-word offset> (6 bytes).
        target = call_va + 2 * sign_extend_32(offset)
        We verify each hit with Capstone before running the argument trace.
        """
        results: List[SinkClassification] = []
        data = text_data
        n = len(data)
        # Lookback window: _LOOKBACK instructions at max 6 bytes each, plus a
        # 16-byte alignment pad so we don't start mid-instruction.
        _WIN_BYTES = _LOOKBACK * 6 + 16
        for i in range(0, n - 5):
            if data[i] != 0xC0 or data[i + 1] != 0xE5:
                continue
            call_va = text_va + i
            raw_off = struct.unpack('>i', data[i + 2:i + 6])[0]
            target_va = (call_va + 2 * raw_off) & 0xFFFFFFFFFFFFFFFF
            if target_va not in sink_plts:
                continue
            sink_name, arg_pos = sink_plts[target_va]
            if arg_pos >= len(_S390_ARG_REGS):
                continue
            # Disassemble a tight lookback window ending at the call.  Using
            # _MAX_FUNC_BYTES causes Capstone to fail on long s390x sections
            # that contain undecodable bytes before the call; using a short
            # window avoids this but may start mid-instruction if the computed
            # start lands on a data byte.  Walk forward 2 bytes at a time
            # (s390x minimum instruction size) until Capstone can decode past
            # the call.
            window_start = max(0, i - _WIN_BYTES)
            insns: list = []
            call_idx: Optional[int] = None
            for _adj in range(0, min(16, i - window_start + 1), 2):
                ws = window_start + _adj
                window_va = text_va + ws
                code = data[ws:i + 6]
                try:
                    insns = list(self._cs.disasm(code, window_va))
                except Exception:
                    insns = []
                call_idx = next(
                    (j for j, ins in enumerate(insns) if ins.address == call_va),
                    None,
                )
                if call_idx is not None:
                    break
            if call_idx is None:
                continue
            arg_reg = _S390_ARG_REGS[arg_pos]
            verdict = self._classify_reg(insns, call_idx, arg_reg)
            # func_va approximation: first instruction in the disassembled window
            func_va_approx = insns[0].address if insns else call_va
            results.append(SinkClassification(
                func_va=func_va_approx,
                call_va=call_va,
                sink_name=sink_name,
                arg_pos=arg_pos,
                verdict=verdict,
                detail=f's390x arg_pos={arg_pos} (text-sweep)',
            ))
        return results

    def classify_all(self) -> List[SinkClassification]:
        """
        Find all exec-class sink call sites in this binary and classify each.
        Returns a list of SinkClassification named tuples.

        For non-stripped binaries the ELF FUNC symbols cover all functions.
        For stripped binaries (no .symtab) the symbol set covers only exported
        entries (typically OpenSSL/libc glue) and misses the actual application
        code.  In that case a raw BRASL byte-sweep over the .text section is used
        to locate call sites, bypassing the need for function-boundary symbols.
        """
        if not _LIEF_OK or self._bin is None or not _CS_OK or self._cs is None:
            return []

        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []

        results: List[SinkClassification] = []
        seen_call_vas: set = set()
        seen_funcs: set = set()

        for func_sym in self._bin.symbols:
            if func_sym.type != _lief.ELF.Symbol.TYPE.FUNC:
                continue
            func_va = int(func_sym.value)
            if not func_va or func_va in seen_funcs:
                continue
            seen_funcs.add(func_va)

            # Determine function bounds
            next_va = self._next_func_va(func_va)
            off = self._va_to_file_offset(func_va)
            if off < 0 or off >= len(self._data):
                continue
            if next_va:
                size = min(int(next_va) - func_va, _MAX_FUNC_BYTES)
            else:
                size = _MAX_FUNC_BYTES
            size = max(0, min(size, len(self._data) - off))
            if size < 4:
                continue

            code = self._data[off:off + size]
            try:
                insns = list(self._cs.disasm(code, func_va))
            except Exception:
                continue

            for idx, insn in enumerate(insns):
                # s390x calls use BRASL %r14, target (or BRAS/BASRL in 31-bit)
                if insn.mnemonic not in ('brasl', 'bras', 'bas', 'basr'):
                    continue
                if not insn.operands:
                    continue
                # Get call target VA
                target_va: Optional[int] = None
                for op in insn.operands:
                    if op.type == SYSZ_OP_IMM:
                        target_va = op.imm & 0xFFFFFFFFFFFFFFFF
                        break
                if target_va is None or target_va not in sink_plts:
                    continue

                sink_name, arg_pos = sink_plts[target_va]
                if arg_pos >= len(_S390_ARG_REGS):
                    continue
                arg_reg = _S390_ARG_REGS[arg_pos]

                call_va = insn.address
                if call_va in seen_call_vas:
                    continue
                seen_call_vas.add(call_va)

                classification = self._classify_reg(insns, idx, arg_reg)
                results.append(SinkClassification(
                    func_va=func_va,
                    call_va=call_va,
                    sink_name=sink_name,
                    arg_pos=arg_pos,
                    verdict=classification,
                    detail=f's390x arg_pos={arg_pos}',
                ))

        # Stripped-binary fallback: sweep the .text section directly for BRASL
        # instructions targeting PLT sinks.  Skip call sites already found above.
        text_sec = self._bin.get_section('.text')
        if text_sec is not None:
            text_va  = int(text_sec.virtual_address)
            text_off = self._va_to_file_offset(text_va)
            if 0 <= text_off < len(self._data):
                text_data = self._data[text_off:text_off + int(text_sec.size)]
                for r in self._raw_brasl_scan(sink_plts, text_va, text_data):
                    if r.call_va not in seen_call_vas:
                        seen_call_vas.add(r.call_va)
                        results.append(r)

        return results

    # ── reporting ─────────────────────────────────────────────────────────────

    def report(self, results: List[SinkClassification]) -> str:
        if not results:
            return f'SinkArgClassifierS390({Path(self._path).name}): no exec-class sinks found.'
        lines = [f'SinkArgClassifierS390({Path(self._path).name}): {len(results)} call sites']
        counts: Dict[str, int] = {}
        for r in results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1
        lines.append(f'  verdicts: {counts}')
        for r in results:
            lines.append(
                f'  {r.verdict} func={hex(r.func_va)} call={hex(r.call_va)} '
                f'sink={r.sink_name} detail={r.detail!r}'
            )
        return '\n'.join(lines)

    # ── static helper ─────────────────────────────────────────────────────────

    @staticmethod
    def is_s390(path: str) -> bool:
        """Return True if the file is an s390 or s390x ELF (e_machine == 0x0016)."""
        try:
            with open(path, 'rb') as f:
                h = f.read(20)
            if h[:4] != b'\x7fELF':
                return False
            end = h[5]
            e_machine = struct.unpack_from('>H', h[18:20])[0] if end == 2 else struct.unpack_from('<H', h[18:20])[0]
            return e_machine == 0x0016
        except Exception:
            return False


# Backward-compat alias: the class was previously named SinkArgClassifierS390.
# sac_for_path() and callers should use SinkArgClassifierS390X (the canonical name).
SinkArgClassifierS390 = SinkArgClassifierS390X
