"""
ppc64_be_sink_classifier.py — PPC64 big-endian ELFv1 sink argument classifier.

Fills the gap left by SinkArgClassifier (x86-only) for PPC64 BE targets.
SinkArgClassifier scans for x86 `call` instructions; PPC64 uses `bl` (branch-link)
with a different stub layout (glink stubs, OPD descriptors) and different argument
registers (r3/r4/r5 vs rdi/rsi/rdx).

Gaps this module fills:

1. **SinkArgClassifier cannot classify PPC64 BE call sites.**  SinkArgClassifier
   uses `insn.mnemonic.lower() == 'call'` to find call sites, which never fires on
   PPC64.  For any IBM POWER Linux binary the result is zero classifications — every
   strcpyx/sprintf call site goes unclassified.  LL-008/010/011/012 were found by
   manual disassembly precisely because no automated classifier existed.

2. **IBM "string allocator" false-positive pattern is endemic.**  IBM LoadLeveler
   C++ code calls `strcpyx(ibm_str_obj, int_size)` as a string allocator with no
   source argument (r4 = 0 or not set).  Without automation, every strcpyx call site
   must be manually inspected to distinguish allocator from copy sink.

3. **IBM string object pattern (mr r3, rX) masks dangerous sinks.**  When r3 is set
   via `mr r3, rX` before a strcpyx call, the destination is an IBM string object
   (not a raw stack buffer).  Distinguishing `rX = stack buffer address` from
   `rX = IBM string object` requires a backward register trace.

Classification output (mirrors SinkArgClassifier taxonomy):
  RODATA_TOC       r4 = ld N(r2)  — static global string via TOC. SAFE.
  IMM_SIZE         r3 = li rX, N  (N < 0x2000) — IBM string allocator. SAFE.
  STACK_DEST       r3 = addi r1, N — stack buffer as destination. INTERESTING.
  ARG_PROPAGATED   r4 from function argument via deref (ld rx, 0(param_reg)).
                   DANGEROUS when combined with STACK_DEST.
  IBM_OBJECT       r3 via mr from a non-stack saved register (IBM string object
                   pass — r4 may come from anywhere). Context-dependent.
  UNKNOWN          Cannot determine within the 12-instruction lookback window.

Usage::

    from ablation.analyzers.ppc64_be_sink_classifier import Ppc64BeSinkClassifier

    clf = Ppc64BeSinkClassifier.from_path('/path/to/ppc64be.elf')
    results = clf.classify_all()
    print(clf.report(results))

    # Filter to dangerous candidates only:
    dangerous = [r for r in results
                 if r.dest_class == 'STACK_DEST' and r.src_class == 'ARG_PROPAGATED']

    # With an existing BinaryContext (avoids ELF re-parse):
    clf = Ppc64BeSinkClassifier.from_context(ctx)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import capstone
    from capstone.ppc import *
    _CS_OK = True
except ImportError:
    _CS_OK = False

from .ppc64_elfv1_resolver import Ppc64ElfV1Resolver, Ppc64ElfV1Info

# ── constants ─────────────────────────────────────────────────────────────────

# Sinks monitored by default: (name, arg_positions_to_classify)
# arg_pos 1 = r3 (dest), arg_pos 2 = r4 (src/fmt), arg_pos 3 = r5
_DEFAULT_SINKS: Dict[str, Tuple[int, int]] = {
    'strcpyx':  (1, 2),   # strcpyx(dest, src)
    'strcatx':  (1, 2),   # strcatx(dest, src)
    'strlenx':  (1, 0),   # strlenx(src) — r3 only
    'strdupx':  (1, 0),   # strdupx(src) — r3 only
    'sprintf':  (1, 2),   # sprintf(dest, fmt, ...)
    'snprintf': (1, 2),   # snprintf(dest, n, fmt, ...)
    'strcpy':   (1, 2),
    'strcat':   (1, 2),
    'memcpy':   (1, 2),
}

# PPC64 argument registers (r3-r10)
_ARG_REGS = {3, 4, 5, 6, 7, 8, 9, 10}

# Registers typically used for saved non-volatiles in PPC64 ELFv1
# r14-r31 are callee-saved non-volatile
_NONVOL_REGS = set(range(14, 32))

# Lookback window (instructions before the BL)
_WINDOW = 12

# IBM string allocator size threshold: li r3, N where N < 0x2000 and r4 not set
_IBM_ALLOC_MAX_SIZE = 0x2000


# ── result types ──────────────────────────────────────────────────────────────

@dataclass
class Ppc64SinkSite:
    """Classification of one PPC64 BE BL-to-sink call site."""
    va: int                        # VA of the BL instruction
    sink_name: str                 # e.g. 'strcpyx'
    stub_va: int                   # VA of the glink PLT stub
    dest_class: str                # r3 classification (STACK_DEST / IMM_SIZE / IBM_OBJECT / UNKNOWN / …)
    src_class: str                 # r4 classification (RODATA_TOC / ARG_PROPAGATED / IMM / UNKNOWN / …)
    dest_detail: str = ''          # human-readable r3 context (e.g. 'sp+0x70')
    src_detail: str = ''           # human-readable r4 context (e.g. 'ld 0(r25) [arg r3]')
    interesting: bool = False      # True if dest=STACK_DEST and src=ARG_PROPAGATED


# ── classifier ────────────────────────────────────────────────────────────────

class Ppc64BeSinkClassifier:
    """
    Classify PPC64 big-endian ELFv1 BL-to-sink call sites.

    Finds all BL callers of each registered sink stub, disassembles the
    preceding 12 instructions, and classifies r3 (dest) and r4 (src) to
    distinguish safe allocator/global calls from dangerous argv-propagated
    stack copies.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._data = open(path, 'rb').read()
        self._info: Optional[Ppc64ElfV1Info] = None
        self._res: Optional[Ppc64ElfV1Resolver] = None
        self._sinks: Dict[str, Tuple[int, int]] = dict(_DEFAULT_SINKS)
        self._md: Optional['capstone.Cs'] = None

    @classmethod
    def from_path(cls, path: str) -> 'Ppc64BeSinkClassifier':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'Ppc64BeSinkClassifier':
        obj = cls(ctx.path)
        return obj

    def add_sink(self, name: str, dest_pos: int = 1, src_pos: int = 2) -> None:
        """Register an additional sink name."""
        self._sinks[name] = (dest_pos, src_pos)

    # ── lazy-init ────────────────────────────────────────────────────────────

    def _ensure(self) -> bool:
        if not _CS_OK:
            return False
        if self._res is None:
            self._res = Ppc64ElfV1Resolver.from_path(self._path)
            self._info = self._res.resolve()
        if self._md is None:
            self._md = capstone.Cs(
                capstone.CS_ARCH_PPC,
                capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN,
            )
            self._md.detail = True
        return True

    # ── classification ───────────────────────────────────────────────────────

    def classify_all(self) -> List[Ppc64SinkSite]:
        """Classify all call sites for all registered sinks."""
        if not self._ensure():
            return []
        # Build stub_va → (sink_name, dest_pos, src_pos)
        sink_stubs: Dict[int, Tuple[str, int, int]] = {}
        for name, (dp, sp) in self._sinks.items():
            for stub_va, sym in self._info.stub_map.items():
                if sym == name:
                    sink_stubs[stub_va] = (name, dp, sp)

        if not sink_stubs:
            return []

        all_callers = self._res.find_all_bl_callers()
        results: List[Ppc64SinkSite] = []

        for stub_va, (name, _dp, _sp) in sink_stubs.items():
            for bl_va in all_callers.get(name, []):
                site = self._classify_site(bl_va, name, stub_va)
                results.append(site)

        results.sort(key=lambda s: s.va)
        return results

    def classify_sink(self, sink_name: str) -> List[Ppc64SinkSite]:
        """Classify call sites for a single named sink."""
        if not self._ensure():
            return []
        all_results = self.classify_all()
        return [r for r in all_results if r.sink_name == sink_name]

    def _classify_site(
        self,
        bl_va: int,
        sink_name: str,
        stub_va: int,
    ) -> Ppc64SinkSite:
        """Classify one BL call site: inspect r3/r4 in the lookback window."""
        base = self._info.text_va - (self._info.text_va % 0x10000000) * 0 + 0x10000000
        # Compute the actual base VA of the binary (assume 0x10000000 for IBM)
        # More robust: resolve from first OPD entry or text_va rounding
        file_base = 0x10000000  # standard IBM PPC64 ELF base

        start_va = bl_va - _WINDOW * 4
        if start_va < file_base:
            start_va = file_base
        off = start_va - file_base
        n_insns = (bl_va - start_va) // 4 + 1
        raw = self._data[off: off + n_insns * 4]
        insns = list(self._md.disasm(raw, start_va))

        dest_class, dest_detail = 'UNKNOWN', ''
        src_class, src_detail = 'UNKNOWN', ''

        # Build pre-BL instruction list for two-pass lookup
        pre_bl = [i for i in insns if i.address < bl_va]

        def _last_setter(target_va: int, reg: int) -> Optional[object]:
            """Return the last instruction before target_va that writes to reg."""
            for ins in reversed(pre_bl):
                if ins.address >= target_va:
                    continue
                if _dest_reg(ins) == reg:
                    return ins
            return None

        # Build an extended prologue window: scan backward up to 512 instructions
        # from the BL to find the function's stdu and prologue mr-from-arg instructions.
        # The 12-insn lookback window is too small to reach prologues of large functions.
        _PROLOGUE_SCAN = 512
        prologue_start_va = max(bl_va - _PROLOGUE_SCAN * 4, file_base)
        _pro_off = prologue_start_va - file_base
        _pro_raw = self._data[_pro_off: _pro_off + (bl_va - prologue_start_va)]
        _pro_insns = list(self._md.disasm(_pro_raw, prologue_start_va))

        # Find the LAST stdu before the BL (= closest function prologue boundary)
        prologue_end_va = prologue_start_va
        for _ins in _pro_insns:
            if _ins.mnemonic.lower() == 'stdu' and 'r1' in _ins.op_str:
                prologue_end_va = _ins.address

        def _nonvol_from_arg_in_prologue(reg: int) -> bool:
            """True if reg was set by 'mr reg, rARG' BEFORE the stdu (in function prologue)."""
            for ins in _pro_insns:
                if ins.address >= prologue_end_va:
                    break
                if _dest_reg(ins) != reg:
                    continue
                m = ins.mnemonic.lower()
                if m not in ('mr', 'mr.'):
                    continue
                parts = [p.strip() for p in ins.op_str.split(',')]
                if len(parts) >= 2:
                    try:
                        src = int(parts[1].lstrip('r'))
                        if src in _ARG_REGS:
                            return True
                    except ValueError:
                        pass
            return False

        def _classify_with_base_trace(setter_ins) -> Tuple[str, str]:
            """Classify register source with one-level base-register origin check.

            Demotions applied when the initial classification is ARG_PROPAGATED:
            - base_reg was loaded from TOC → RODATA_TOC (static global, not argv)
            - base_reg's last setter is a load from a non-volatile that was NOT
              initialized from an arg in the prologue → UNKNOWN (exception object /
              internal struct, not confirmed argv)
            """
            m = setter_ins.mnemonic.lower()
            op = setter_ins.op_str
            result = _classify_reg_set(setter_ins, file_base, m, op, _ARG_REGS)
            if result is None:
                return ('UNKNOWN', '')
            cls, detail = result
            if cls == 'MR_FROM':
                # mr rD, rS — trace rS one level
                try:
                    src_reg = int(op.split(',')[1].strip().lstrip('r'))
                    src_setter = _last_setter(setter_ins.address, src_reg)
                    if src_setter:
                        return _classify_reg_set(src_setter, file_base,
                                                 src_setter.mnemonic.lower(),
                                                 src_setter.op_str, _ARG_REGS) or ('UNKNOWN', '')
                except (ValueError, IndexError):
                    pass
                return ('UNKNOWN', detail)
            if cls == 'ARG_PROPAGATED':
                # ld rD, N(rX) where rX ∈ arg_regs. Check rX's actual origin.
                try:
                    parts = [p.strip() for p in op.split(',')]
                    src_part = parts[1] if len(parts) >= 2 else ''
                    base_reg = int(src_part.split('(')[1].rstrip(')').lstrip('r'))
                    base_setter = _last_setter(setter_ins.address, base_reg)
                    if base_setter is not None:
                        bm = base_setter.mnemonic.lower()
                        bop = base_setter.op_str
                        if bm in ('ld', 'lwz', 'lhz', 'lbz'):
                            bparts = [p.strip() for p in bop.split(',')]
                            bsrc = bparts[1] if len(bparts) >= 2 else ''
                            # Direct TOC load → RODATA_TOC
                            if '(r2)' in bsrc or '(2)' in bsrc:
                                return ('RODATA_TOC', f'{m} {src_part} [via r{base_reg}←TOC]')
                            # Load via a non-volatile base register
                            try:
                                bb_str = bsrc.split('(')[1].rstrip(')').lstrip('r')
                                bb_reg = int(bb_str)
                                if bb_reg in _NONVOL_REGS:
                                    # Only UNKNOWN if that non-vol was NOT a prologue-saved arg
                                    if not _nonvol_from_arg_in_prologue(bb_reg):
                                        return ('UNKNOWN', f'{m} {src_part} [via r{base_reg}←nonvol r{bb_reg}]')
                            except (ValueError, IndexError):
                                pass
                except (ValueError, IndexError):
                    pass
            return (cls, detail)

        # Classify r3 (dest) and r4 (src)
        r3_src: Optional[Tuple[str, str]] = None
        r4_src: Optional[Tuple[str, str]] = None

        setter3 = _last_setter(bl_va, 3)
        if setter3:
            r3_src = _classify_with_base_trace(setter3)

        setter4 = _last_setter(bl_va, 4)
        if setter4:
            r4_src = _classify_with_base_trace(setter4)

        if r3_src:
            dest_class, dest_detail = r3_src[0], (r3_src[1] or '')
        if r4_src:
            src_class, src_detail = r4_src[0], (r4_src[1] or '')

        interesting = (dest_class == 'STACK_DEST' and src_class == 'ARG_PROPAGATED')
        return Ppc64SinkSite(
            va=bl_va,
            sink_name=sink_name,
            stub_va=stub_va,
            dest_class=dest_class,
            src_class=src_class,
            dest_detail=dest_detail,
            src_detail=src_detail,
            interesting=interesting,
        )

    # ── reporting ────────────────────────────────────────────────────────────

    @staticmethod
    def report(results: List[Ppc64SinkSite]) -> str:
        lines = ['Ppc64BeSinkClassifier results:',
                 f'  {len(results)} call sites classified']
        interesting = [r for r in results if r.interesting]
        if interesting:
            lines.append(f'  {len(interesting)} INTERESTING (STACK_DEST + ARG_PROPAGATED):')
            for r in interesting:
                lines.append(
                    f'    0x{r.va:x}  {r.sink_name:<12}  '
                    f'dest={r.dest_detail or r.dest_class}  '
                    f'src={r.src_detail or r.src_class}'
                )
        lines.append('')
        lines.append('  All results:')
        for r in results:
            flag = ' ***' if r.interesting else ''
            lines.append(
                f'    0x{r.va:x}  {r.sink_name:<12}  '
                f'{r.dest_class:<16} {r.src_class:<18}{flag}'
            )
        return '\n'.join(lines)


# ── instruction helpers ───────────────────────────────────────────────────────

def _dest_reg(ins) -> Optional[int]:
    """Return the destination GPR number (0-31), or None."""
    if not ins.operands:
        return None
    op0 = ins.operands[0]
    if op0.type != capstone.ppc.PPC_OP_REG:
        return None
    name = str(ins.reg_name(op0.reg))
    if not name.startswith('r'):
        return None
    try:
        return int(name[1:])
    except ValueError:
        return None


def _mr_src_reg(op_str: str) -> Optional[int]:
    """Extract source register number from 'mr rD, rS' operand string."""
    parts = op_str.split(',')
    if len(parts) < 2:
        return None
    s = parts[1].strip().lstrip('r')
    try:
        return int(s)
    except ValueError:
        return None


def _reg_origin_class(reg: int, insns_before: list, arg_regs: set) -> str:
    """
    Quick one-level origin check for a register seen as a base in a load instruction.

    Returns: 'TOC' if reg was set from r2 (TOC), 'NONVOL' if from r14-r31,
             'ARG' if from an arg register or load of arg-reg, 'UNKNOWN' otherwise.

    Only scans the already-reversed insns_before list (closest-first).
    """
    for ins in insns_before:
        m = ins.mnemonic.lower()
        op = ins.op_str
        parts = [p.strip() for p in op.split(',')]
        if not parts:
            continue
        dest = parts[0].lstrip('r')
        try:
            dest_reg = int(dest)
        except ValueError:
            continue
        if dest_reg != reg:
            continue
        # Found instruction that sets reg
        # ld reg, N(r2) → TOC
        if m in ('ld', 'lwz', 'lhz', 'lbz') and len(parts) >= 2:
            src = parts[1]
            if '(r2)' in src or '(2)' in src:
                return 'TOC'
            # ld reg, N(rX) — check rX
            try:
                base_str = src.split('(')[1].rstrip(')').lstrip('r')
                base = int(base_str)
                if base == 2:
                    return 'TOC'
                if base in _NONVOL_REGS:
                    return 'NONVOL'
                if base in arg_regs:
                    return 'ARG'
            except (ValueError, IndexError):
                pass
        # mr reg, rS
        if m in ('mr', 'mr.') and len(parts) >= 2:
            try:
                src_reg = int(parts[1].lstrip('r'))
                if src_reg in _NONVOL_REGS:
                    return 'NONVOL'
                if src_reg in arg_regs:
                    return 'ARG'
            except ValueError:
                pass
        # addi reg, r1, N → stack address
        if m == 'addi' and len(parts) >= 3:
            try:
                if int(parts[1].lstrip('r')) == 1:
                    return 'STACK'
            except ValueError:
                pass
        return 'UNKNOWN'
    return 'UNKNOWN'


def _classify_reg_set(
    ins,
    file_base: int,
    mnemonic: str,
    op_str: str,
    arg_regs: set,
    insns_before: Optional[list] = None,
) -> Optional[Tuple[str, str]]:
    """
    Classify how a register is set by this instruction.

    Returns (class_str, detail_str) or None if this instruction doesn't
    set a register in a classifiable way.

    insns_before: reversed list of instructions already seen in lookback (closest first).
    Used to resolve the origin of base registers in load instructions.
    """
    parts = [p.strip() for p in op_str.split(',')]
    if not parts:
        return None

    # addi rD, r1, N  → STACK_DEST (rD = sp + N)
    if mnemonic == 'addi' and len(parts) >= 3:
        base_reg_str = parts[1].lstrip('r')
        try:
            base_reg = int(base_reg_str)
            imm_str = parts[2]
            imm = int(imm_str, 0) if '0x' in imm_str else int(imm_str)
            if base_reg == 1:  # r1 = stack pointer
                return ('STACK_DEST', f'sp+0x{imm & 0xffff:x}' if imm >= 0 else f'sp-0x{-imm:x}')
        except (ValueError, IndexError):
            pass

    # li rD, N  → IMM or IMM_SIZE
    if mnemonic in ('li', 'li.') and len(parts) >= 2:
        val_str = parts[1]
        try:
            val = int(val_str, 0) if '0x' in val_str else int(val_str)
            if 0 < val < _IBM_ALLOC_MAX_SIZE:
                return ('IMM_SIZE', f'li 0x{val:x}')
            return ('IMM', f'li 0x{val:x}')
        except ValueError:
            pass

    # ld rD, N(r2)  → RODATA_TOC (TOC-relative load from r2 = TOC pointer)
    if mnemonic in ('ld', 'lwz', 'lhz', 'lbz') and len(parts) >= 2:
        src_part = parts[1]
        if '(r2)' in src_part or '(2)' in src_part:
            return ('RODATA_TOC', f'{mnemonic} {src_part}')
        # ld rD, 0(rX) or ld rD, N(rX)
        # For a direct arg register deref (rX ∈ r3-r10), classify ARG_PROPAGATED
        # UNLESS that arg register itself was loaded from TOC or a non-volatile —
        # in which case the source is not user-controlled.
        try:
            off_str = src_part.split('(')[0]
            reg_str = src_part.split('(')[1].rstrip(')').lstrip('r')
            base_reg = int(reg_str)
        except (ValueError, IndexError):
            base_reg = None

        if base_reg is not None and base_reg in arg_regs:
            # Check base register's origin in the lookback window
            base_origin = _reg_origin_class(base_reg, insns_before or [], arg_regs)
            if base_origin == 'TOC':
                # base was loaded from TOC → source is a TOC-derived pointer, not raw argv
                return ('RODATA_TOC', f'{mnemonic} {src_part} [via r{base_reg}←TOC]')
            elif base_origin == 'NONVOL':
                # base was loaded from a non-volatile → caller-defined, not confirmed argv
                return ('UNKNOWN', f'{mnemonic} {src_part} [via r{base_reg}←nonvol]')
            elif base_origin == 'STACK':
                return ('STACK_DEST', f'{mnemonic} {src_part} [via r{base_reg}←sp]')
            else:
                # ARG or UNKNOWN: treat as ARG_PROPAGATED
                offset_str = off_str if off_str else '0'
                return ('ARG_PROPAGATED', f'{mnemonic} {offset_str}(r{base_reg}) [arg reg]' if offset_str == '0'
                        else f'{mnemonic} {offset_str}(r{base_reg}) [arg reg field]')

    # mr rD, rS  → pass-through (mark for further tracing)
    if mnemonic in ('mr', 'mr.') and len(parts) >= 2:
        return ('MR_FROM', parts[1].strip())

    # ori rD, rS, 0 (nop form of mr on PPC)
    if mnemonic == 'ori' and len(parts) >= 3 and parts[2].strip() == '0':
        return ('MR_FROM', parts[1].strip())

    return None
