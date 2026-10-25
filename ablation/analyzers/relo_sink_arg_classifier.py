"""
relo_sink_arg_classifier.py: classify exec-class sink argument provenance
in ELF32 relocatable object files.

Why this exists:
  SinkArgClassifierPPC32BE requires a linked ELF: it uses PLT virtual addresses
  to detect call sites (bl <plt_va>) and LIEF section ranges to detect .rodata
  references (_is_rodata checks absolute VAs).
  Relocatable objects (.o) have neither: all calls are bctrl through a register
  loaded via lis+addi with RELA annotations, and all section references are
  section-relative with zero-valued reloc fields.
  Gap IDs: RELO-GAP-002 (solidDB VxWorks PPC440 solidac.a analysis).

Architecture of the difference:
  Linked ELF:                 Relocatable .o:
    bl <plt_va>                 lis  rX, 0  [HA→strcpy]
                                addi rX, rX, 0  [LO→strcpy]
                                mtctr rX
                                bctrl
  _is_rodata checks abs VA    rela_map[lis_offset].is_rodata

The backward register trace (_trace_arg) is identical between the two:
  PPC32 ABI arguments are always in r3-r10 regardless of link state.
  This classifier re-implements that trace with the two substitutions above.

Usage:
    from ablation.analyzers.relo_object_context import ReloObjectContext
    from ablation.analyzers.relo_sink_arg_classifier import ReloSinkArgClassifier

    roc = ReloObjectContext.from_path('rpc0http.o')
    clf = ReloSinkArgClassifier.from_context(roc)
    clf.add_sink('SsQmemAlloc', arg_pos=0)

    results = clf.classify_fn('rpc_http_svc_get')
    print(clf.report(results))

    flagged = [r for r in results if r.verdict not in ('RODATA_CONST', 'SNPRINTF_RODATA')]
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
    from capstone.ppc_const import (
        PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM,
        PPC_REG_R1,
        PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
        PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10,
        PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_LI,
        PPC_INS_LWZ, PPC_INS_STW,
        PPC_INS_OR, PPC_INS_MR,
        PPC_INS_LBZ, PPC_INS_LHZ,
    )
    _CS_OK = True
except ImportError:
    (PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM) = (1, 3, 2)
    PPC_REG_R1  = 88
    (PPC_REG_R3, PPC_REG_R4, PPC_REG_R5,  PPC_REG_R6,
     PPC_REG_R7, PPC_REG_R8, PPC_REG_R9,  PPC_REG_R10) = range(90, 98)
    (PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_LI, PPC_INS_LWZ,
     PPC_INS_STW, PPC_INS_OR, PPC_INS_MR,
     PPC_INS_LBZ, PPC_INS_LHZ) = (632, 4, 631, 651, 1066, 843, 759, 594, 626)

from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── PPC32 ABI registers ────────────────────────────────────────────────────────

_PPC32_ARG_REGS: List[int] = [
    PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
    PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10,
]
_PPC32_ENTRY_ARG_SET = frozenset(_PPC32_ARG_REGS)

_PPC32_REG_NAMES: Dict[int, str] = {
    88: 'r1', 89: 'r2',
    **{90 + i: f'r{3 + i}' for i in range(8)},
}

# ── Default exec-class sinks ──────────────────────────────────────────────────

_DEFAULT_SINKS: Dict[str, int] = {
    'system':   0,
    'popen':    0,
    'execve':   0,
    'execvp':   0,
    'execl':    0,
    'execlp':   0,
    'strcpy':   0,
    'strcat':   0,
    'sprintf':  0,
}

_SNPRINTF_FMT_POS: Dict[str, int] = {
    'snprintf':       2,
    'vsnprintf':      2,
    'sprintf':        1,
    '__sprintf_chk':  3,
    '__snprintf_chk': 3,
}

_LOOKBACK        = 80
_SNPRINTF_WINDOW = 140
_BCTRL_LOOKBACK  = 8    # lis → bctrl window for indirect call setup


def _rname(reg_id: int) -> str:
    return _PPC32_REG_NAMES.get(reg_id, f'r{reg_id}')


def _sign16(v: int) -> int:
    return v if v < 0x8000 else v - 0x10000


# ── Main class ─────────────────────────────────────────────────────────────────

class ReloSinkArgClassifier:
    """
    Classify exec-class sink argument provenance in ELF32 relocatable .o files.

    Uses ReloObjectContext for section-relative disassembly and RELA-based
    symbol annotation.  The backward register trace is identical to
    SinkArgClassifierPPC32BE; only call-site detection and rodata identification
    use the rela_map instead of PLT VAs and LIEF section ranges.
    """

    def __init__(self, roc) -> None:
        self._roc = roc
        self._rela_map: Dict[int, Tuple[str, bool]] = roc.rela_map()
        self._sinks: Dict[str, int] = dict(_DEFAULT_SINKS)
        self._snprintf_names: frozenset = frozenset(_SNPRINTF_FMT_POS)
        self._cs: Optional[object] = None
        if _CS_OK:
            self._cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
            self._cs.detail = True

    @classmethod
    def from_context(cls, roc) -> 'ReloSinkArgClassifier':
        return cls(roc)

    def add_sink(self, name: str, arg_pos: int) -> None:
        self._sinks[name] = arg_pos

    # ── instruction stream ────────────────────────────────────────────────────

    def _get_insns(self, fn_name: str) -> list:
        if self._cs is None:
            return []
        try:
            raw, base = self._roc.text_bytes(fn_name)
        except KeyError:
            return []
        if not raw:
            return []
        return list(self._cs.disasm(raw, base))

    # ── rodata detection via rela_map ─────────────────────────────────────────

    def _is_rodata_rela(self, insn_offset: int) -> bool:
        """
        True if the instruction at insn_offset has a HA RELA annotation targeting
        a .rodata* section.  Replaces the VA-range _is_rodata() check used in
        SinkArgClassifierPPC32BE.
        """
        entry = self._rela_map.get(insn_offset)
        return entry is not None and entry[1]

    def _sym_at(self, insn_offset: int) -> str:
        entry = self._rela_map.get(insn_offset)
        return entry[0] if entry else ''

    # ── call-site detection for bctrl pattern ────────────────────────────────

    def _find_call_sites(self, insns: list, sink_name: str) -> List[int]:
        """
        Return indices into insns of bctrl instructions that call sink_name.

        Detection: scan forward from each 'lis rX' that has a RELA annotation
        for sink_name.  Find 'mtctr rX' (same rX) within _BCTRL_LOOKBACK
        instructions; the bctrl following mtctr is the call site.

          lis   rX, 0    [HA→sink_name]   ← annotation anchor
          addi  rX, rX, 0
          [... arg setup may be interleaved ...]
          mtctr rX
          bctrl                           ← call site index returned
        """
        sites: List[int] = []
        seen_bctrl: set = set()
        for i, insn in enumerate(insns):
            if insn.id != PPC_INS_LIS:
                continue
            if self._sym_at(insn.address) != sink_name:
                continue
            if not insn.operands:
                continue
            lis_reg = insn.operands[0].reg
            # Walk forward for mtctr lis_reg, then bctrl
            end = min(i + _BCTRL_LOOKBACK, len(insns))
            for k in range(i + 1, end):
                nxt = insns[k]
                if nxt.mnemonic == 'mtctr':
                    # capstone represents mtctr rX as: op[0] = rX
                    if nxt.operands and nxt.operands[0].reg == lis_reg:
                        # bctrl may be several instructions after mtctr due to
                        # compiler argument-setup scheduling; scan until bctrl
                        # or another mtctr (which would mean a different call)
                        for m in range(k + 1, min(k + 12, len(insns))):
                            mn = insns[m].mnemonic
                            if mn == 'bctrl' and m not in seen_bctrl:
                                sites.append(m)
                                seen_bctrl.add(m)
                                break
                            if mn == 'mtctr':
                                break
                        break
        return sites

    # ── helpers ───────────────────────────────────────────────────────────────

    def _writes_reg(self, insn, reg_id: int) -> bool:
        if not insn.operands:
            return False
        op = insn.operands[0]
        return op.type == PPC_OP_REG and op.reg == reg_id

    # ── backward argument trace ───────────────────────────────────────────────

    def _find_preceding_lis(
        self,
        insns: list,
        from_j: int,
        reg_id: int,
    ) -> Optional[bool]:
        """
        Scan backward from from_j - 1 for a 'lis reg_id' instruction.
        Returns True if the lis has a .rodata RELA annotation (RODATA_CONST),
        False if it has a non-rodata annotation, None if no lis found.
        Stops if any other instruction writes reg_id.
        """
        for k in range(from_j - 1, max(from_j - 6, -1), -1):
            insn = insns[k]
            if insn.id == PPC_INS_LIS and self._writes_reg(insn, reg_id):
                return self._is_rodata_rela(insn.address)
            if self._writes_reg(insn, reg_id):
                return None
        return None

    def _trace_arg(
        self,
        insns: list,
        from_idx: int,
        arg_reg: int,
        depth: int = 0,
    ) -> Tuple[str, str]:
        """
        Trace the source of arg_reg backward from from_idx.

        Identical in structure to SinkArgClassifierPPC32BE._trace_arg() with
        two substitutions:
          1. lis+addi/lwz rodata check: uses _is_rodata_rela(lis.address) instead
             of _is_rodata(computed_va).
          2. No pointer dereference path: in .o files the linker-patched words are
             zero, so we cannot dereference lis+lwz to read a rodata pointer.
        """
        if depth > 1:
            return (UNKNOWN, 'max recursion depth')

        limit = max(from_idx - _LOOKBACK, -1)

        for j in range(from_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, arg_reg):
                continue

            # ── li rX, imm ────────────────────────────────────────────────────
            if insn.id == PPC_INS_LI:
                return (RODATA_CONST,
                        f'li {_rname(arg_reg)}, #{insn.operands[1].imm:#x}')

            # ── lis rX — scan forward for paired addi ────────────────────────
            if insn.id == PPC_INS_LIS:
                is_ro = self._is_rodata_rela(insn.address)
                if is_ro:
                    sym = self._sym_at(insn.address)
                    return (RODATA_CONST,
                            f'lis+addi {_rname(arg_reg)} → .rodata ref {sym!r}')
                # Not rodata — check what symbol this is
                sym = self._sym_at(insn.address)
                if sym:
                    return (UNKNOWN, f'lis+addi → external sym {sym!r} (not .rodata)')
                # No annotation at all — could be a literal constant or unresolved
                # Scan forward for paired addi within 5 instructions
                for k in range(j + 1, min(j + 6, len(insns))):
                    nxt = insns[k]
                    if nxt.id == PPC_INS_ADDI and self._writes_reg(nxt, arg_reg):
                        ops = nxt.operands
                        if len(ops) >= 3 and ops[1].reg == arg_reg:
                            lo = ops[2].imm
                            # If the addi also has a LO rodata rela, it's rodata
                            # (LO rela shares the same sym as HA — check sym)
                            return (UNKNOWN,
                                    f'lis+addi {_rname(arg_reg)} no rela annotation')
                    if self._writes_reg(nxt, arg_reg) and nxt.id not in (
                            PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_LWZ):
                        break
                return (UNKNOWN, f'lis {_rname(arg_reg)}: no rela, no paired addi')

            # ── mr rD, rA (PPC_INS_MR or OR with rA==rB) ─────────────────────
            if insn.id == PPC_INS_MR:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_REG:
                    src_reg = ops[1].reg
                    if src_reg in _PPC32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'mr {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                    return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'mr {_rname(arg_reg)}: unknown src')

            if insn.id == PPC_INS_OR:
                ops = insn.operands
                if (len(ops) == 3
                        and ops[1].type == PPC_OP_REG
                        and ops[2].type == PPC_OP_REG
                        and ops[1].reg == ops[2].reg):
                    src_reg = ops[1].reg
                    if src_reg in _PPC32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'mr {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                    return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'or {_rname(arg_reg)}: non-mr pattern')

            # ── addi rX, r1, N — stack slot address ──────────────────────────
            if insn.id == PPC_INS_ADDI:
                ops = insn.operands
                if len(ops) >= 3 and ops[1].type == PPC_OP_REG:
                    base_r = ops[1].reg
                    lo_val = ops[2].imm

                    if base_r == PPC_REG_R1:
                        disp = lo_val
                        snp = self._trace_snprintf_buf(insns, from_idx, PPC_REG_R1, disp, depth)
                        if snp is not None:
                            return snp
                        if self._is_entry_arg_save(insns, PPC_REG_R1, disp):
                            return (ARG_PROPAGATED, f'entry arg at r1+{disp:#x}')
                        return (UNKNOWN, f'addi {_rname(arg_reg)}, r1, {disp:#x}')

                    if base_r == arg_reg:
                        is_ro = self._find_preceding_lis(insns, j, arg_reg)
                        if is_ro is True:
                            sym = self._sym_at(insns[j].address)
                            return (RODATA_CONST, f'lis+addi → .rodata {sym!r}')
                        if is_ro is False:
                            sym = self._sym_at(insns[j].address)
                            return (UNKNOWN, f'lis+addi → external {sym!r}')

                    if base_r in _PPC32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'addi {_rname(arg_reg)}, {_rname(base_r)}: entry+imm')

                return (UNKNOWN,
                        f'addi {_rname(arg_reg)}: unknown base @ {insn.address:#010x}')

            # ── lwz rX, N(rY) ─────────────────────────────────────────────────
            if insn.id == PPC_INS_LWZ:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_MEM:
                    base_reg = ops[1].mem.base
                    disp     = ops[1].mem.disp

                    if base_reg == PPC_REG_R1:
                        snp = self._trace_snprintf_buf(insns, from_idx, PPC_REG_R1, disp, depth)
                        if snp is not None:
                            return snp
                        if self._is_entry_arg_save(insns, PPC_REG_R1, disp):
                            return (ARG_PROPAGATED, f'entry arg saved at r1+{disp:#x}')
                        return (UNKNOWN, f'lwz {_rname(arg_reg)}, {disp:#x}(r1)')

                    if base_reg == arg_reg:
                        is_ro = self._find_preceding_lis(insns, j, arg_reg)
                        if is_ro is True:
                            sym = self._sym_at(insns[j].address)
                            return (RODATA_CONST, f'lis+lwz → .rodata {sym!r}')

                    if base_reg in _PPC32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'lwz {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})'
                                f' struct field of entry arg')
                    return (UNKNOWN,
                            f'lwz {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})')

            # ── lbz/lhz — byte/halfword load → UNKNOWN ───────────────────────
            if insn.id in (PPC_INS_LBZ, PPC_INS_LHZ):
                return (UNKNOWN, f'{insn.mnemonic} {_rname(arg_reg)} @ {insn.address:#010x}')

            # ── any other writer ──────────────────────────────────────────────
            ops = insn.operands
            if (len(ops) >= 2
                    and ops[1].type == PPC_OP_REG
                    and ops[1].reg in _PPC32_ENTRY_ARG_SET):
                return (ARG_PROPAGATED,
                        f'{insn.mnemonic}: src {_rname(ops[1].reg)} is entry arg')
            return (UNKNOWN,
                    f'{insn.mnemonic} writes {_rname(arg_reg)} @ {insn.address:#010x}')

        if arg_reg in _PPC32_ENTRY_ARG_SET:
            return (ARG_PROPAGATED,
                    f'{_rname(arg_reg)} unmodified in {_LOOKBACK}-insn window: entry arg')
        return (UNKNOWN, f'{_rname(arg_reg)} write not found in {_LOOKBACK}-insn window')

    # ── snprintf buffer backtrack ─────────────────────────────────────────────

    def _trace_snprintf_buf(
        self,
        insns: list,
        sink_idx: int,
        base_reg: int,
        disp: int,
        depth: int,
    ) -> Optional[Tuple[str, str]]:
        """
        Search backward for snprintf/vsnprintf bctrl that wrote to stack at (base_reg, disp).
        Uses rela-based bctrl detection instead of PLT VA comparison.
        """
        limit = max(sink_idx - _SNPRINTF_WINDOW, -1)
        for i in range(sink_idx - 1, limit, -1):
            insn = insns[i]
            if insn.mnemonic != 'bctrl':
                continue
            # Check if this bctrl was a snprintf-family call
            snp_name = ''
            start = max(i - _BCTRL_LOOKBACK, 0)
            for k in range(i - 1, start - 1, -1):
                sym = self._sym_at(insns[k].address)
                if sym in self._snprintf_names:
                    snp_name = sym
                    break
            if not snp_name:
                continue
            if not self._r3_is_slot(insns, i, base_reg, disp):
                continue
            fmt_pos = _SNPRINTF_FMT_POS.get(snp_name, 2)
            if fmt_pos >= len(_PPC32_ARG_REGS):
                continue
            fmt_reg = _PPC32_ARG_REGS[fmt_pos]
            verdict, detail = self._trace_arg(insns, i, fmt_reg, depth + 1)
            if verdict == RODATA_CONST:
                return (SNPRINTF_RODATA, f'{snp_name}(r1+{disp:#x}) fmt={detail}')
            return (verdict, f'{snp_name}(r1+{disp:#x}) fmt={detail}')
        return None

    def _r3_is_slot(
        self,
        insns: list,
        bl_idx: int,
        base_reg: int,
        disp: int,
    ) -> bool:
        limit = max(bl_idx - _LOOKBACK, -1)
        for j in range(bl_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, PPC_REG_R3):
                continue
            if insn.id == PPC_INS_ADDI:
                ops = insn.operands
                if (len(ops) >= 3
                        and ops[1].type == PPC_OP_REG
                        and ops[1].reg == base_reg
                        and ops[2].type == PPC_OP_IMM
                        and ops[2].imm == disp):
                    return True
            return False
        return False

    def _is_entry_arg_save(
        self,
        insns: list,
        base_reg: int,
        disp: int,
    ) -> bool:
        for insn in insns:
            if insn.id != PPC_INS_STW:
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if ops[0].type == PPC_OP_REG and ops[0].reg in _PPC32_ENTRY_ARG_SET:
                if (ops[1].type == PPC_OP_MEM
                        and ops[1].mem.base == base_reg
                        and ops[1].mem.disp == disp):
                    return True
        return False

    # ── per-function classification ───────────────────────────────────────────

    def classify_fn(self, fn_name: str) -> List[SinkClassification]:
        """Classify all sink call sites within a named function."""
        insns = self._get_insns(fn_name)
        if not insns:
            return []
        fn = self._roc._func_by_name.get(fn_name)
        fn_offset = fn.offset if fn else 0

        results: List[SinkClassification] = []
        for sink_name, arg_pos in self._sinks.items():
            for call_idx in self._find_call_sites(insns, sink_name):
                if arg_pos >= len(_PPC32_ARG_REGS):
                    continue
                arg_reg = _PPC32_ARG_REGS[arg_pos]
                verdict, detail = self._trace_arg(insns, call_idx, arg_reg)
                severity = '' if verdict in (RODATA_CONST, SNPRINTF_RODATA) else 'HIGH'
                results.append(SinkClassification(
                    sink_name=sink_name,
                    arg_pos=arg_pos,
                    func_va=fn_offset,
                    call_va=insns[call_idx].address,
                    verdict=verdict,
                    detail=detail,
                    severity=severity,
                ))
        return results

    def classify_all(self) -> List[SinkClassification]:
        """Classify all sink call sites across all functions in the object."""
        results: List[SinkClassification] = []
        for fn in self._roc.functions():
            results.extend(self.classify_fn(fn.name))
        return results

    def report(self, results: List[SinkClassification]) -> str:
        if not results:
            return 'ReloSinkArgClassifier: no results\n'
        lines = [f'ReloSinkArgClassifier: {len(results)} results']
        for r in results:
            lines.append(
                f'  {r.verdict:16s} {r.sink_name}(arg{r.arg_pos})'
                f' func=+{r.func_va:#010x} call=+{r.call_va:#010x}'
                f' detail={r.detail}'
            )
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        lines.append('Summary: ' + ' | '.join(f'{k}={v}' for k, v in sorted(by_verdict.items())))
        return '\n'.join(lines) + '\n'
