"""
taint_tracker_riscv64.py: RISC-V 64-bit network-to-sink taint analysis.

Architecture: RV64GC (RV64I + M + A + F + D + C compressed).
ABI: RISC-V Linux lp64 / lp64d calling convention:
     a0-a7 (x10-x17) argument registers (8 integer args), a0 (x10) return value.
     Caller-saved: ra (x1), t0-t6 (x5-x7, x28-x31), a0-a7 (x10-x17).
     Callee-saved: s0/fp-s11 (x8-x9, x18-x27), sp (x2), gp (x3), tp (x4).
     No branch delay slots.

Prologue: addi sp, sp, -N   [allocate stack frame]
          sd   ra, N-8(sp)  [save return address; sd = doubleword on RV64]
Return:   ret               [= jalr zero, 0(ra)]
          c.jr ra           [RVC compact return]
Call:     jal  ra, target   [direct call, PC-relative 21-bit offset]
          c.jal target      [RVC compact direct call -- RV32C only, not valid in RV64GC]
          jalr ra, rs1, 0   [indirect call via register]
          c.jalr rs1        [RVC compact indirect call]

RV64-specific additions over RV32:
  ld/sd (doubleword load/store), addiw (word add+sign-extend),
  addw/subw/mulw/divw/divuw/remw/remuw (32-bit operations sign-extended to 64),
  sllw/srlw/sraw, slliw/srliw/sraiw, c.ld/c.ldsp/c.sd/c.sdsp, c.addiw/c.addw/c.subw.

Sources: recv/recvfrom/read/fgets/gets/fread -- return value in a0.
Sinks  : system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf.

Targets: StarFive VisionFive 2 (JH7110), SiFive HiFive Unmatched (FU740),
         Milk-V Pioneer (SG2042), SpacemiT K1 (X60), Canaan K510/K230,
         SOPHON BM1684 (64-bit RISC-V cores), OpenWrt RISC-V 64,
         PLCT RISC-V Linux servers, custom RV64GC embedded Linux.

Usage:
    from ablation.analyzers.taint_tracker_riscv64 import RISCV64TaintTracker
    tracker = RISCV64TaintTracker.from_path('rv64_elf')
    findings = tracker.run()
    chains   = tracker.run_interprocedural(depth=4)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import capstone
    from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False

try:
    import lief as _lief
    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    _HAS_PYELF = True
except ImportError:
    _HAS_PYELF = False


# ---------------------------------------------------------------------------
# RISC-V lp64 ABI register model (identical to ilp32 -- same names, wider)
# ---------------------------------------------------------------------------

_ARG_REGS: List[str] = ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7']

_CALLER_SAVED: frozenset = frozenset([
    'ra',
    't0', 't1', 't2', 't3', 't4', 't5', 't6',
    'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7',
])

_CALLEE_SAVED: frozenset = frozenset([
    'sp', 'gp', 'tp',
    's0', 's1', 's2', 's3', 's4', 's5', 's6',
    's7', 's8', 's9', 's10', 's11',
])

# Direct-call mnemonics (jal with rd=ra)
_CALL_MNEMS: frozenset = frozenset({'jal'})
# Indirect-call mnemonics (jalr with rd=ra or RVC c.jalr)
_ICALL_MNEMS: frozenset = frozenset({'jalr', 'c.jalr'})
# Return mnemonics
_RET_MNEMS: frozenset = frozenset({'ret'})

_SOURCES: Set[str] = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'pread',
    'fread', 'fgets', 'gets', 'getenv',
    'recv@plt', 'read@plt', 'fgets@plt', 'recvfrom@plt',
}

_DEFAULT_SINKS: Dict[str, List[int]] = {
    'system':    [0],
    'execv':     [0],
    'execvp':    [0],
    'execve':    [0],
    'popen':     [0],
    'strcpy':    [1],
    'strcat':    [1],
    'sprintf':   [1],
    'snprintf':  [2],
    'memcpy':    [2],
    'memmove':   [2],
    'malloc':    [0],
    'calloc':    [0, 1],
    'realloc':   [1],
}

MAX_FUNC_BYTES = 0x8000

# Data-propagating mnemonics for RV64GC (ISA spec §5 RV64I + §16 RVC, superset of RV32GC).
# Contract: canonical pseudo-instructions and direct data-movement ops only.
# Membership means _exec_insn may propagate taint from source registers to rd.
# *w arithmetic (addw/subw/mulw etc.) sign-extends to 64 bits -- not a bitwise copy,
# but taint propagation is conservative (attacker-controlled 32-bit value is still
# attacker-controlled after sign extension).
# sext.w (addiw rd,rs,0 alias) handled separately in _exec_insn mv-branch.
_COPY_MNEMS: frozenset = frozenset({
    # Pseudoinstructions
    'mv', 'li', 'la',
    # RV64I base integer
    'add', 'addi', 'sub',
    'addw', 'addiw', 'subw',
    'and', 'andi',
    'or', 'ori',
    'xor', 'xori',
    'sll', 'slli', 'srl', 'srli', 'sra', 'srai',
    'sllw', 'slliw', 'srlw', 'srliw', 'sraw', 'sraiw',
    'slt', 'sltu', 'slti', 'sltiu',
    'auipc', 'lui',
    # RV64M multiply/divide
    'mul', 'mulh', 'mulhsu', 'mulhu', 'mulw',
    'div', 'divu', 'rem', 'remu',
    'divw', 'divuw', 'remw', 'remuw',
    # Loads (clear taint -- memory not tracked)
    'lw', 'lh', 'lb', 'lhu', 'lbu', 'lwu',
    'ld',
    # RVC compressed variants (RV64C)
    'c.mv', 'c.li', 'c.addi', 'c.addi4spn',  # c.addi16sp intentionally absent (modifies sp)
    'c.addiw', 'c.add', 'c.addw', 'c.sub', 'c.subw',
    'c.and', 'c.or', 'c.xor',
    'c.slli', 'c.srli', 'c.srai',
    'c.lw', 'c.lwsp',
    'c.ld', 'c.ldsp',
})


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingRISCV64:
    binary: str
    func_va: int
    func_name: str
    sink_va: int
    sink_name: str
    tainted_args: List[int]
    source_name: str

    def __str__(self) -> str:
        args_str = ', '.join(f'a{i}' for i in self.tainted_args)
        return (f'[RISCV64-TAINT] {self.func_name} (0x{self.func_va:x})'
                f' -> {self.sink_name}({args_str}) @ 0x{self.sink_va:x}'
                f'  [src: {self.source_name}]')


# ---------------------------------------------------------------------------
# RISCV64TaintTracker
# ---------------------------------------------------------------------------

class RISCV64TaintTracker:
    """
    Source-to-sink static taint tracker for RISC-V 64-bit ELF binaries.

    ABI: RISC-V Linux lp64. a0-a7 args, a0 return.
    Requires capstone with CS_ARCH_RISCV (capstone 5.x+).

    Usage:
        tracker = RISCV64TaintTracker.from_path('rv64_elf')
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)

    Custom sinks:
        tracker = RISCV64TaintTracker.from_path('fw', custom_sinks={'riscv_exec': [0]})

    From BinaryContext:
        tracker = RISCV64TaintTracker.from_context(ctx)
    """

    def __init__(
        self,
        binary_path: str,
        ctx=None,
        custom_sinks: Optional[Dict[str, List[int]]] = None,
    ):
        self.binary_path = binary_path
        self._ctx = ctx
        self._sinks = dict(_DEFAULT_SINKS)
        if custom_sinks:
            self._sinks.update(custom_sinks)

        self._data = Path(binary_path).read_bytes()
        self._md = None
        if _HAS_CAPSTONE:
            self._md = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
            self._md.detail = False

        self._plt: Dict[int, str] = {}
        self._plt_by_name: Dict[str, int] = {}
        self._func_starts: List[int] = []
        self._text_va: int = 0
        self._text_off: int = 0
        self._text_size: int = 0

        self._load_elf()

    @classmethod
    def from_path(cls, path: str, **kwargs) -> 'RISCV64TaintTracker':
        return cls(path, **kwargs)

    @classmethod
    def from_context(cls, ctx, **kwargs) -> 'RISCV64TaintTracker':
        return cls(ctx.binary_path, ctx=ctx, **kwargs)

    # ------------------------------------------------------------------
    # ELF loading
    # ------------------------------------------------------------------

    def _load_elf(self) -> None:
        if _HAS_LIEF:
            self._load_lief()
        elif _HAS_PYELF:
            self._load_pyelf()

    def _load_lief(self) -> None:
        try:
            binary = _lief.parse(self.binary_path)
            if not binary:
                return
            for sym in binary.pltgot_relocations:
                if sym.symbol and sym.symbol.name:
                    self._plt[sym.address] = sym.symbol.name
                    self._plt_by_name[sym.symbol.name] = sym.address
            for sym in binary.plt_relocations:
                if sym.symbol and sym.symbol.name:
                    self._plt[sym.address] = sym.symbol.name
                    self._plt_by_name[sym.symbol.name] = sym.address
            starts: Set[int] = set()
            for sym in binary.static_symbols:
                if sym.type == _lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                    starts.add(sym.value)
            for sym in binary.dynamic_symbols:
                if sym.type == _lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                    starts.add(sym.value)
            self._func_starts = sorted(starts)
            for seg in binary.segments:
                if seg.type == _lief.ELF.SEGMENT_TYPES.LOAD and seg.flags & 0x1:
                    self._text_va   = seg.virtual_address
                    self._text_off  = seg.file_offset
                    self._text_size = seg.physical_size
                    break
        except Exception:
            pass

    def _load_pyelf(self) -> None:
        try:
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                text = elf.get_section_by_name('.text')
                if text:
                    self._text_va   = text['sh_addr']
                    self._text_off  = text['sh_offset']
                    self._text_size = text['sh_size']
                dynsym = elf.get_section_by_name('.dynsym')
                if dynsym:
                    plt_sec = elf.get_section_by_name('.plt')
                    plt_va  = plt_sec['sh_addr'] if plt_sec else 0
                    for relname in ('.rela.plt', '.rel.plt'):
                        rsec = elf.get_section_by_name(relname)
                        if not rsec:
                            continue
                        for idx, rel in enumerate(rsec.iter_relocations()):
                            sym = dynsym.get_symbol(rel['r_info_sym'])
                            if sym and plt_va:
                                # RISC-V 64 PLT stubs are typically 16 bytes
                                entry_va = plt_va + 16 * (idx + 1)
                                self._plt[entry_va] = sym.name
                                self._plt_by_name[sym.name] = entry_va
                for sname in ('.symtab', '.dynsym'):
                    sec = elf.get_section_by_name(sname)
                    if not isinstance(sec, SymbolTableSection):
                        continue
                    for sym in sec.iter_symbols():
                        if (sym['st_info']['type'] == 'STT_FUNC'
                                and sym['st_value'] and sym['st_size'] > 0):
                            self._func_starts.append(sym['st_value'])
                self._func_starts = sorted(set(self._func_starts))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_func_starts(self) -> List[int]:
        if self._ctx is not None:
            return self._ctx.func_starts
        if self._func_starts:
            return self._func_starts
        starts: List[int] = []
        if not self._md:
            return starts
        text = self._data[self._text_off: self._text_off + self._text_size]
        prev_ret = True
        for address, size, mnemonic, op_str in self._md.disasm_lite(text, self._text_va):
            if prev_ret and mnemonic == 'addi' and 'sp, sp, -' in op_str:
                starts.append(address)
            is_ret = (mnemonic == 'ret' or
                      (mnemonic in ('c.jr', 'jr') and op_str.strip() == 'ra'))
            prev_ret = is_ret
        return sorted(set(starts))

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        if not self._text_va:
            return None
        off = self._text_off + (va - self._text_va)
        if off < 0 or off + size > len(self._data):
            return None
        return self._data[off: off + size]

    def _func_name(self, va: int) -> str:
        if self._ctx is not None:
            return self._ctx.name(va)
        return self._plt.get(va, f'0x{va:x}')

    def _plt_name_for_target(self, target_va: int) -> str:
        name = self._plt.get(target_va, '')
        if name:
            return name
        for plt_va, plt_name in self._plt.items():
            if abs(target_va - plt_va) <= 16:
                return plt_name
        return ''

    @staticmethod
    def _jal_target(address: int, op_str: str) -> int:
        try:
            return address + int(op_str.strip(), 0)
        except ValueError:
            return 0

    @staticmethod
    def _parse_rd(op_str: str) -> str:
        return op_str.split(',')[0].strip()

    @staticmethod
    def _parse_rs(op_str: str, idx: int = 1) -> str:
        parts = op_str.split(',')
        if len(parts) > idx:
            return parts[idx].strip()
        return ''

    def _exec_insn(self, mnemonic: str, op_str: str, tainted: Dict[str, bool]) -> None:
        if mnemonic not in _COPY_MNEMS:
            return

        rd = self._parse_rd(op_str)
        if not rd or rd in ('zero', 'x0', 'sp'):
            return

        rs1 = self._parse_rs(op_str, 1)
        rs2 = self._parse_rs(op_str, 2) if ',' in op_str[op_str.find(',')+1:] else ''

        if mnemonic in ('mv', 'c.mv',
                        'sext.w'):  # addiw rd,rs,0 alias -- narrowing but taint-conservative
            tainted[rd] = bool(tainted.get(rs1))
            return
        if mnemonic in ('li', 'la', 'lui', 'auipc', 'c.li'):
            tainted[rd] = False
            return
        if mnemonic in ('lw', 'lh', 'lb', 'lhu', 'lbu', 'lwu', 'ld',
                        'c.lw', 'c.lwsp', 'c.ld', 'c.ldsp'):
            tainted[rd] = False
            return
        # For 2-operand C-ext forms (c.addi rd, imm / c.addiw rd, imm), capstone emits
        # op_str='rd, imm'; rs1 parses as the immediate string -- source register is rd.
        if mnemonic in ('addi', 'addiw', 'ori', 'xori', 'slti', 'sltiu',
                        'slli', 'srli', 'srai', 'slliw', 'srliw', 'sraiw',
                        'c.addi', 'c.addiw', 'c.slli', 'c.srli', 'c.srai'):
            src = rs1 if rs1 and rs1[0].isalpha() else rd
            tainted[rd] = bool(tainted.get(src))
            return
        if mnemonic in ('andi', 'c.and'):
            tainted[rd] = False
            return

        tainted[rd] = bool(tainted.get(rs1)) or bool(tainted.get(rs2))

    # ------------------------------------------------------------------
    # Taint analysis
    # ------------------------------------------------------------------

    def _analyze_function(
        self,
        func_va: int,
        func_end_va: int,
        func_bytes: bytes,
        seed_arg_indices: List[int],
    ) -> List[TaintFindingRISCV64]:
        tainted: Dict[str, bool] = {}
        for i in seed_arg_indices:
            if i < len(_ARG_REGS):
                tainted[_ARG_REGS[i]] = True

        findings: List[TaintFindingRISCV64] = []
        func_name = self._func_name(func_va)

        if not self._md:
            return findings

        for address, size, mnemonic, op_str in self._md.disasm_lite(func_bytes, func_va):
            if mnemonic in _CALL_MNEMS:
                target_va = self._jal_target(address, op_str)
                target_name = self._plt_name_for_target(target_va) if target_va else ''

                if target_name in _SOURCES:
                    tainted['a0'] = True
                elif target_name in self._sinks:
                    hit_args = [
                        ai for ai in self._sinks.get(target_name, [])
                        if tainted.get(_ARG_REGS[ai])
                    ]
                    if hit_args:
                        findings.append(TaintFindingRISCV64(
                            binary=self.binary_path,
                            func_va=func_va,
                            func_name=func_name,
                            sink_va=address,
                            sink_name=target_name,
                            tainted_args=hit_args,
                            source_name='recv/arg',
                        ))
                for r in _CALLER_SAVED - {'a0'}:
                    tainted[r] = False
                if target_name not in _SOURCES:
                    tainted['a0'] = False

            elif mnemonic in _ICALL_MNEMS:
                for r in _CALLER_SAVED:
                    tainted[r] = False

            elif mnemonic == 'ret':
                break
            elif mnemonic in ('c.jr', 'jr') and op_str.strip() == 'ra':
                break
            elif mnemonic == 'jr' and op_str.strip() != 'ra':
                # tail call via register (tail pseudo: auipc + jalr zero,reg,0)
                for r in _CALLER_SAVED:
                    tainted[r] = False
                break

            else:
                self._exec_insn(mnemonic, op_str, tainted)

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_on_function(self, func_va: int, func_end_va: int = 0) -> List[TaintFindingRISCV64]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 4:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, [])

    def run_on_function_seeded(
        self, func_va: int, seed_arg_indices: List[int], func_end_va: int = 0
    ) -> List[TaintFindingRISCV64]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 4:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, seed_arg_indices)

    def run(self) -> List[TaintFindingRISCV64]:
        func_starts = self._get_func_starts()
        findings: List[TaintFindingRISCV64] = []
        func_end_map = {
            fva: (func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES)
            for i, fva in enumerate(func_starts)
        }
        for fva, fend in func_end_map.items():
            size = min(fend - fva, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(fva, size)
            if not func_bytes or len(func_bytes) < 4:
                continue
            try:
                findings.extend(self._analyze_function(fva, fend, func_bytes, []))
            except Exception:
                continue
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[TaintFindingRISCV64]:
        func_starts = self._get_func_starts()
        if not func_starts or not self._md:
            return []

        func_start_set = set(func_starts)
        func_end_map: Dict[int, int] = {
            fva: (func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES)
            for i, fva in enumerate(func_starts)
        }

        seed_funcs: Dict[int, str] = {}
        for fva in func_starts:
            fend = func_end_map[fva]
            func_bytes = self._va_to_slice(fva, min(fend - fva, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 4:
                continue
            try:
                for address, size, mnemonic, op_str in self._md.disasm_lite(func_bytes, fva):
                    if mnemonic in _CALL_MNEMS:
                        target_va = self._jal_target(address, op_str)
                        if target_va:
                            name = self._plt_name_for_target(target_va)
                            if name in _SOURCES:
                                seed_funcs[fva] = name
                                break
            except Exception:
                continue

        results: List[TaintFindingRISCV64] = []
        queue: deque = deque()
        visited: Set[tuple] = set()

        for fva, src_name in seed_funcs.items():
            key = (fva, frozenset())
            if key not in visited:
                visited.add(key)
                queue.append((fva, [], 0, src_name))

        while queue:
            func_va, seed_arg_indices, depth_cur, source_name = queue.popleft()
            if depth_cur > depth:
                continue

            fend = func_end_map.get(func_va, func_va + MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(func_va, min(fend - func_va, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 4:
                continue

            try:
                findings = self._analyze_function(func_va, fend, func_bytes, seed_arg_indices)
            except Exception:
                continue

            results.extend(findings)

            try:
                tainted: Dict[str, bool] = {_ARG_REGS[i]: True for i in seed_arg_indices
                                             if i < len(_ARG_REGS)}
                for address, size, mnemonic, op_str in self._md.disasm_lite(func_bytes, func_va):
                    if mnemonic in _CALL_MNEMS:
                        target_va = self._jal_target(address, op_str)
                        if target_va and target_va in func_start_set:
                            tainted_passed = [
                                ai for ai, ar in enumerate(_ARG_REGS)
                                if tainted.get(ar)
                            ]
                            if tainted_passed:
                                key = (target_va, frozenset(tainted_passed))
                                if key not in visited:
                                    visited.add(key)
                                    queue.append((target_va, tainted_passed,
                                                  depth_cur + 1, source_name))
                        for r in _CALLER_SAVED:
                            tainted[r] = False
                    elif mnemonic == 'ret':
                        break
                    elif mnemonic in ('c.jr', 'jr') and op_str.strip() == 'ra':
                        break
                    elif mnemonic == 'jr' and op_str.strip() != 'ra':
                        for r in _CALLER_SAVED:
                            tainted[r] = False
                        break
                    else:
                        self._exec_insn(mnemonic, op_str, tainted)
            except Exception:
                pass

        return results

    def report(self, findings: List[TaintFindingRISCV64]) -> str:
        if not findings:
            return f'[riscv64_taint] No findings in {self.binary_path}'
        lines = [f'[riscv64_taint] {self.binary_path}: {len(findings)} finding(s)']
        for f in findings:
            lines.append(f'  {f}')
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='RISC-V 64 taint tracker')
    ap.add_argument('binary')
    ap.add_argument('--interprocedural', action='store_true')
    ap.add_argument('--depth', type=int, default=4)
    args = ap.parse_args()

    tracker = RISCV64TaintTracker.from_path(args.binary)
    if args.interprocedural:
        results = tracker.run_interprocedural(depth=args.depth)
    else:
        results = tracker.run()
    print(tracker.report(results))


if __name__ == '__main__':
    _cli()
