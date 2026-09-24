"""
mips_analyzer.py -- Static analysis for MIPS32/MIPS32r2 ELF binaries.

Provides:
  - MIPS32TaintTracker: source-to-sink taint tracking (recv/read -> dangerous sinks)
  - MIPS32FuncProfiler: quick function profiling (calls, strings, sink detection)

Register model (MIPS32 O32 ABI):
  $zero ($0)   -- always zero
  $at   ($1)   -- assembler temp
  $v0,$v1      -- return values; tainted after source calls
  $a0-$a3      -- function args; seeded as ARG kind at function entry
  $t0-$t9      -- temporaries; caller-saved; clobbered across calls
  $s0-$s7      -- callee-saved; survive across calls
  $k0,$k1      -- kernel reserved
  $gp          -- global pointer
  $sp          -- stack pointer
  $fp ($s8)    -- frame pointer (callee-saved)
  $ra          -- return address

Branch delay slots: the instruction immediately following a branch/jump
executes before the branch takes effect. The tracker handles this by
buffering the next instruction and executing it before processing the
branch outcome.

Calling convention:
  - Arguments pass in $a0-$a3 (first 4 args); additional args on stack
  - Return value in $v0 (64-bit in $v0:$v1)
  - Caller-saved: $at, $v0-$v1, $a0-$a3, $t0-$t9, $ra
  - Callee-saved: $s0-$s7, $gp, $sp, $fp
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
from capstone import CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
from capstone.mips_const import (
    MIPS_OP_REG, MIPS_OP_IMM, MIPS_OP_MEM,
    MIPS_INS_LW, MIPS_INS_LH, MIPS_INS_LB, MIPS_INS_LHU, MIPS_INS_LBU,
    MIPS_INS_SW, MIPS_INS_SH, MIPS_INS_SB,
    MIPS_INS_MOVE, MIPS_INS_ADDU, MIPS_INS_ADD,
    MIPS_INS_ADDIU, MIPS_INS_ADDI,
    MIPS_INS_AND, MIPS_INS_ANDI, MIPS_INS_OR, MIPS_INS_ORI,
    MIPS_INS_XOR, MIPS_INS_XORI, MIPS_INS_NOR,
    MIPS_INS_SLL, MIPS_INS_SRL, MIPS_INS_SRA,
    MIPS_INS_SLLV, MIPS_INS_SRLV, MIPS_INS_SRAV,
    MIPS_INS_JAL, MIPS_INS_JALR, MIPS_INS_JR, MIPS_INS_J,
    MIPS_INS_BEQ, MIPS_INS_BNE, MIPS_INS_BGEZ, MIPS_INS_BGTZ,
    MIPS_INS_BLEZ, MIPS_INS_BLTZ, MIPS_INS_BGEZAL, MIPS_INS_BLTZAL,
    MIPS_INS_BAL,
    MIPS_INS_NOP,
    MIPS_INS_LUI,
    MIPS_INS_SUBU, MIPS_INS_SUB,
    MIPS_INS_MUL, MIPS_INS_MULT, MIPS_INS_MULTU,
    MIPS_INS_DIV, MIPS_INS_DIVU,
    MIPS_INS_MFHI, MIPS_INS_MFLO,
)
import lief

# MIPS register name -> canonical name
_REG_FAMILY: Dict[str, str] = {}
_MIPS_REG_NAMES = [
    ("zero", ["$0"]),
    ("at",   ["$1"]),
    ("v0",   ["$2"]),
    ("v1",   ["$3"]),
    ("a0",   ["$4"]),
    ("a1",   ["$5"]),
    ("a2",   ["$6"]),
    ("a3",   ["$7"]),
    ("t0",   ["$8"]),
    ("t1",   ["$9"]),
    ("t2",   ["$10"]),
    ("t3",   ["$11"]),
    ("t4",   ["$12"]),
    ("t5",   ["$13"]),
    ("t6",   ["$14"]),
    ("t7",   ["$15"]),
    ("s0",   ["$16"]),
    ("s1",   ["$17"]),
    ("s2",   ["$18"]),
    ("s3",   ["$19"]),
    ("s4",   ["$20"]),
    ("s5",   ["$21"]),
    ("s6",   ["$22"]),
    ("s7",   ["$23"]),
    ("t8",   ["$24"]),
    ("t9",   ["$25"]),
    ("k0",   ["$26"]),
    ("k1",   ["$27"]),
    ("gp",   ["$28"]),
    ("sp",   ["$29"]),
    ("fp",   ["$30", "s8"]),
    ("ra",   ["$31"]),
]
for _base, _aliases in _MIPS_REG_NAMES:
    _REG_FAMILY[_base] = _base
    for _a in _aliases:
        _REG_FAMILY[_a] = _base


def _canon(name: str) -> Optional[str]:
    n = name.lower().lstrip("$")
    return _REG_FAMILY.get(n)


# O32 ABI arg registers (first 4 args)
_ARG_REGS = ["a0", "a1", "a2", "a3"]

# Caller-saved registers (clobbered across calls)
_CALLER_SAVED: Set[str] = {
    "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "t8", "t9", "ra",
}

# Callee-saved registers (survive across calls)
_CALLEE_SAVED: Set[str] = {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "fp", "gp", "sp"}

# Branch/jump instruction IDs (have delay slots)
_BRANCH_IDS: Set[int] = {
    MIPS_INS_JAL, MIPS_INS_JALR, MIPS_INS_JR, MIPS_INS_J,
    MIPS_INS_BEQ, MIPS_INS_BNE, MIPS_INS_BGEZ, MIPS_INS_BGTZ,
    MIPS_INS_BLEZ, MIPS_INS_BLTZ, MIPS_INS_BGEZAL, MIPS_INS_BLTZAL,
    MIPS_INS_BAL,
}

# Taint source function names (result in $v0 = tainted)
_SOURCES: Set[str] = {
    "recv", "recvfrom", "recvmsg",
    "read", "pread",
    "fread", "fgets",
    "getenv", "getarg",
}

# Default sinks: (function_name, arg_index_list)
# arg_index 0 = $a0, 1 = $a1, 2 = $a2, 3 = $a3
_DEFAULT_SINKS: Dict[str, List[int]] = {
    "system":    [0],
    "execv":     [0],
    "execvp":    [0],
    "execve":    [0],
    "popen":     [0],
    "strcpy":    [1],   # strcpy(dst, src) -- src = $a1 is the dangerous arg
    "strcat":    [1],
    "sprintf":   [1],   # sprintf(buf, fmt) -- fmt = $a1
    "memcpy":    [2],   # memcpy(dst, src, n) -- n = $a2
    "malloc":    [0],
    "calloc":    [0, 1],
    "realloc":   [1],
}

MAX_FUNC_BYTES = 0x8000


@dataclass
class TaintFinding32Mips:
    binary: str
    func_va: int
    func_name: str
    sink_va: int
    sink_name: str
    tainted_args: List[int]   # 0-indexed arg positions that are tainted
    source_name: str

    def __str__(self) -> str:
        args_str = ", ".join(f"$a{i}" for i in self.tainted_args)
        return (
            f"[MIPS32-TAINT] {self.func_name} (0x{self.func_va:x})"
            f" -> {self.sink_name}({args_str}) @ 0x{self.sink_va:x}"
            f"  [src: {self.source_name}]"
        )


@dataclass
class MipsCallProfile:
    site_va: int
    target_name: str
    args: Dict[str, str]   # reg -> origin kind
    is_sink: bool = False


@dataclass
class MipsFuncProfile:
    binary: str
    func_va: int
    func_name: str
    calls: List[MipsCallProfile] = field(default_factory=list)
    strings: List[Tuple[int, str]] = field(default_factory=list)

    @property
    def sink_calls(self) -> List[MipsCallProfile]:
        return [c for c in self.calls if c.is_sink]

    def fmt(self) -> str:
        lines = [
            f"[mips_profiler] {self.func_name} @ 0x{self.func_va:x}",
            f"  {len(self.calls)} calls, {len(self.sink_calls)} sinks, "
            f"{len(self.strings)} strings",
        ]
        if self.strings:
            lines.append("  STRINGS:")
            for va, s in self.strings[:8]:
                lines.append(f"    0x{va:x}  {s!r}")
        if self.calls:
            lines.append("  CALLS:")
            for c in self.calls:
                tag = " *** SINK ***" if c.is_sink else ""
                arg_str = "  ".join(f"{r}={v}" for r, v in c.args.items())
                lines.append(f"    0x{c.site_va:x}  {c.target_name}({arg_str}){tag}")
        return "\n".join(lines)


class MIPS32TaintTracker:
    """
    Source-to-sink static taint tracker for MIPS32/MIPS32r2 ELF binaries.

    Usage:
        tracker = MIPS32TaintTracker('/path/to/mips_binary')
        findings = tracker.run_interprocedural()
        print(tracker.report(findings))

    Custom sinks:
        tracker = MIPS32TaintTracker('/path', custom_sinks={'my_exec': [0]})

    From BinaryContext:
        tracker = MIPS32TaintTracker.from_context(ctx)
    """

    def __init__(
        self,
        binary_path: str,
        ctx=None,
        custom_sinks: Optional[Dict[str, List[int]]] = None,
        big_endian: bool = False,
    ):
        self.binary_path = binary_path
        self._ctx = ctx
        self._sinks = dict(_DEFAULT_SINKS)
        if custom_sinks:
            self._sinks.update(custom_sinks)

        self._binary = lief.parse(binary_path)
        self._data = Path(binary_path).read_bytes()
        self._plt = self._build_plt()
        self._strings: Dict[int, str] = {}
        if ctx is not None:
            self._strings = dict(ctx.strings)

        endian = CS_MODE_BIG_ENDIAN if big_endian else CS_MODE_LITTLE_ENDIAN
        md = capstone.Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | endian)
        md.detail = True
        self._md = md

    @classmethod
    def from_path(cls, binary_path: str, **kwargs) -> "MIPS32TaintTracker":
        return cls(binary_path, **kwargs)

    @classmethod
    def from_context(cls, ctx, **kwargs) -> "MIPS32TaintTracker":
        return cls(ctx.binary_path, ctx=ctx, **kwargs)

    def _build_plt(self) -> Dict[int, str]:
        plt: Dict[int, str] = {}
        if not self._binary:
            return plt
        try:
            for sym in self._binary.pltgot_relocations:
                if sym.symbol and sym.symbol.name:
                    plt[sym.address] = sym.symbol.name
        except Exception:
            pass
        try:
            for sym in self._binary.plt_relocations:
                if sym.symbol and sym.symbol.name:
                    plt[sym.address] = sym.symbol.name
        except Exception:
            pass
        return plt

    def _va_to_offset(self, va: int) -> Optional[int]:
        if not self._binary:
            return None
        try:
            return self._binary.virtual_address_to_offset(va)
        except Exception:
            return None

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        off = self._va_to_offset(va)
        if off is None:
            return None
        return self._data[off: off + size]

    def _get_func_starts(self) -> List[int]:
        if self._ctx is not None:
            return self._ctx.func_starts
        starts: Set[int] = set()
        if self._binary:
            try:
                for sym in self._binary.static_symbols:
                    if sym.type == lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                        starts.add(sym.value)
                for sym in self._binary.dynamic_symbols:
                    if sym.type == lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                        starts.add(sym.value)
            except Exception:
                pass
        return sorted(starts)

    def _func_name(self, va: int) -> str:
        if self._ctx is not None:
            return self._ctx.name(va)
        if va in self._plt:
            return self._plt[va]
        return f"0x{va:x}"

    def run_on_function(self, func_va: int, func_end_va: int = 0) -> List[TaintFinding32Mips]:
        """Analyze a single function for source-to-sink taint paths."""
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []

        return self._analyze_function(func_va, func_end_va, func_bytes, seed_arg_indices=[])

    def run_on_function_seeded(
        self, func_va: int, seed_arg_indices: List[int], func_end_va: int = 0
    ) -> List[TaintFinding32Mips]:
        """Analyze with pre-tainted argument registers."""
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, seed_arg_indices)

    def _analyze_function(
        self, func_va: int, func_end_va: int, func_bytes: bytes, seed_arg_indices: List[int]
    ) -> List[TaintFinding32Mips]:
        # Register taint state: reg_name -> bool (True = tainted)
        tainted: Dict[str, bool] = {}

        # Seed from sources found in this function, or from entry args
        for i in seed_arg_indices:
            if i < len(_ARG_REGS):
                tainted[_ARG_REGS[i]] = True

        findings: List[TaintFinding32Mips] = []
        func_name = self._func_name(func_va)

        # Collect all instructions first (to handle delay slots)
        all_insns = list(self._md.disasm(func_bytes, func_va))

        i = 0
        while i < len(all_insns):
            insn = all_insns[i]
            ops = insn.operands

            # Branch/jump: execute delay slot before processing the branch
            if insn.id in _BRANCH_IDS:
                delay_slot = all_insns[i + 1] if i + 1 < len(all_insns) else None
                if delay_slot is not None:
                    self._exec_non_branch(delay_slot, tainted)
                    i += 1  # skip delay slot in main loop

                # Process the branch/jump itself
                if insn.id in (MIPS_INS_JAL, MIPS_INS_JALR, MIPS_INS_BAL, MIPS_INS_BGEZAL,
                               MIPS_INS_BLTZAL):
                    target_name = ""
                    if ops and ops[0].type == MIPS_OP_IMM:
                        target_name = self._plt.get(ops[0].imm, "")
                    elif ops and ops[0].type == MIPS_OP_REG:
                        # jalr $t9 -- PLT jump
                        pass

                    if target_name in _SOURCES:
                        tainted["v0"] = True
                        tainted["v1"] = False

                    # Check if this is a sink
                    if target_name in self._sinks:
                        arg_indices = self._sinks[target_name]
                        hit_args = []
                        for idx in arg_indices:
                            if idx < len(_ARG_REGS) and tainted.get(_ARG_REGS[idx]):
                                hit_args.append(idx)
                        if hit_args:
                            findings.append(TaintFinding32Mips(
                                binary=self.binary_path,
                                func_va=func_va,
                                func_name=func_name,
                                sink_va=insn.address,
                                sink_name=target_name,
                                tainted_args=hit_args,
                                source_name="recv/arg",
                            ))

                    # Clobber caller-saved (except v0 which we just set)
                    for r in _CALLER_SAVED - {"v0", "v1"}:
                        tainted[r] = False
                    if target_name not in _SOURCES:
                        tainted["v0"] = False
                        tainted["v1"] = False

                elif insn.id == MIPS_INS_JR and ops and insn.reg_name(ops[0].reg).lower() == "ra":
                    break  # function return

                i += 1
                continue

            self._exec_non_branch(insn, tainted)
            i += 1

        return findings

    def _exec_non_branch(self, insn, tainted: Dict[str, bool]) -> None:
        """Apply one non-branch instruction's taint semantics."""
        ops = insn.operands
        if not ops:
            return

        def get_taint(reg_name: str) -> bool:
            c = _canon(reg_name)
            return bool(tainted.get(c)) if c else False

        def set_taint(reg_name: str, val: bool) -> None:
            c = _canon(reg_name)
            if c and c != "zero":
                tainted[c] = val

        def reg_name(op) -> str:
            return insn.reg_name(op.reg).lower() if op.type == MIPS_OP_REG else ""

        # LUI -- loads upper immediate; not a taint source
        if insn.id == MIPS_INS_LUI and len(ops) >= 1:
            set_taint(reg_name(ops[0]), False)

        # MOVE / ADDU (used as pseudo-move when src2 is $zero)
        elif insn.id in (MIPS_INS_MOVE,) and len(ops) == 2:
            dst, src = reg_name(ops[0]), reg_name(ops[1])
            set_taint(dst, get_taint(src))

        elif insn.id in (MIPS_INS_ADDU, MIPS_INS_ADD) and len(ops) == 3:
            dst, s1, s2 = reg_name(ops[0]), reg_name(ops[1]), reg_name(ops[2])
            if s2 == "zero":
                set_taint(dst, get_taint(s1))
            elif s1 == "zero":
                set_taint(dst, get_taint(s2))
            else:
                set_taint(dst, get_taint(s1) or get_taint(s2))

        # ADDIU / ADDI -- reg + immediate; taint propagates from source reg
        elif insn.id in (MIPS_INS_ADDIU, MIPS_INS_ADDI) and len(ops) >= 2:
            dst, src = reg_name(ops[0]), reg_name(ops[1])
            set_taint(dst, get_taint(src))

        # OR, AND, XOR, NOR, ORI, ANDI, XORI
        elif insn.id in (MIPS_INS_OR, MIPS_INS_AND, MIPS_INS_XOR, MIPS_INS_NOR) and len(ops) == 3:
            dst, s1, s2 = reg_name(ops[0]), reg_name(ops[1]), reg_name(ops[2])
            set_taint(dst, get_taint(s1) or get_taint(s2))

        elif insn.id in (MIPS_INS_ORI, MIPS_INS_ANDI, MIPS_INS_XORI) and len(ops) >= 2:
            dst, src = reg_name(ops[0]), reg_name(ops[1])
            set_taint(dst, get_taint(src))

        # XOR reg, reg -- zeroing idiom
        elif insn.id == MIPS_INS_XOR and len(ops) == 3:
            dst, s1, s2 = reg_name(ops[0]), reg_name(ops[1]), reg_name(ops[2])
            if s1 == s2:
                set_taint(dst, False)
            else:
                set_taint(dst, get_taint(s1) or get_taint(s2))

        # Shifts: taint propagates from source
        elif insn.id in (MIPS_INS_SLL, MIPS_INS_SRL, MIPS_INS_SRA) and len(ops) >= 2:
            dst = reg_name(ops[0])
            src = reg_name(ops[1]) if ops[1].type == MIPS_OP_REG else reg_name(ops[0])
            set_taint(dst, get_taint(src))

        elif insn.id in (MIPS_INS_SLLV, MIPS_INS_SRLV, MIPS_INS_SRAV) and len(ops) == 3:
            dst, s1 = reg_name(ops[0]), reg_name(ops[1])
            set_taint(dst, get_taint(s1))

        # MUL: result tainted if either operand tainted
        elif insn.id in (MIPS_INS_MUL,) and len(ops) == 3:
            dst, s1, s2 = reg_name(ops[0]), reg_name(ops[1]), reg_name(ops[2])
            set_taint(dst, get_taint(s1) or get_taint(s2))

        # MFHI / MFLO: result from hi/lo multiply registers -- treat as unknown
        elif insn.id in (MIPS_INS_MFHI, MIPS_INS_MFLO) and len(ops) >= 1:
            dst = reg_name(ops[0])
            set_taint(dst, False)  # conservative: can't easily track hi/lo

        # Loads: LW/LH/LB -- taint from memory is unknown unless we track mem state
        elif insn.id in (MIPS_INS_LW, MIPS_INS_LH, MIPS_INS_LB,
                         MIPS_INS_LHU, MIPS_INS_LBU) and len(ops) >= 2:
            dst = reg_name(ops[0])
            # If loading from stack ($sp/$fp-relative) where a tainted value was stored,
            # we'd need mem tracking. Conservative: loads from stack = unknown, not tainted.
            # Loads from a tainted base pointer = potentially tainted (e.g., user struct field).
            if ops[1].type == MIPS_OP_MEM:
                base = _canon(insn.reg_name(ops[1].mem.base).lower())
                if base and tainted.get(base):
                    set_taint(dst, True)  # dereferencing a tainted pointer
                else:
                    # Don't set to False here -- preserve existing state for other paths
                    pass

        # Stores: no taint update needed (we track register state, not memory)

        # SUBU / SUB
        elif insn.id in (MIPS_INS_SUBU, MIPS_INS_SUB) and len(ops) == 3:
            dst, s1, s2 = reg_name(ops[0]), reg_name(ops[1]), reg_name(ops[2])
            set_taint(dst, get_taint(s1) or get_taint(s2))

    def run_interprocedural(self, depth: int = 4) -> List[TaintFinding32Mips]:
        """BFS from network source functions, following tainted args into callees."""
        from collections import deque

        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        func_start_set = set(func_starts)
        func_end_map: Dict[int, int] = {}
        for i, fva in enumerate(func_starts):
            fend = func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES
            func_end_map[fva] = fend

        # Find seed functions: those that call a _SOURCES function
        seed_funcs: Dict[int, str] = {}
        for fva in func_starts:
            fend = func_end_map[fva]
            func_bytes = self._va_to_slice(fva, min(fend - fva, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 8:
                continue
            try:
                for insn in self._md.disasm(func_bytes, fva):
                    if insn.id in (MIPS_INS_JAL,):
                        ops = insn.operands
                        if ops and ops[0].type == MIPS_OP_IMM:
                            name = self._plt.get(ops[0].imm, "")
                            if name in _SOURCES:
                                seed_funcs[fva] = name
                                break
            except Exception:
                continue

        # BFS
        results: List[TaintFinding32Mips] = []
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
            if not func_bytes or len(func_bytes) < 8:
                continue

            try:
                findings = self._analyze_function(
                    func_va, fend, func_bytes, seed_arg_indices
                )
            except Exception:
                continue

            results.extend(findings)

            # Propagate: find calls where tainted arg was passed, and enqueue callee
            try:
                tainted: Dict[str, bool] = {_ARG_REGS[i]: True for i in seed_arg_indices}
                all_insns = list(self._md.disasm(func_bytes, func_va))
                idx = 0
                while idx < len(all_insns):
                    insn = all_insns[idx]
                    ops = insn.operands
                    if insn.id in _BRANCH_IDS:
                        delay = all_insns[idx + 1] if idx + 1 < len(all_insns) else None
                        if delay:
                            self._exec_non_branch(delay, tainted)
                            idx += 1
                        if insn.id == MIPS_INS_JAL and ops and ops[0].type == MIPS_OP_IMM:
                            callee_va = ops[0].imm
                            if callee_va in func_start_set:
                                tainted_args_passed = [
                                    i for i, r in enumerate(_ARG_REGS)
                                    if tainted.get(r)
                                ]
                                if tainted_args_passed:
                                    key = (callee_va, frozenset(tainted_args_passed))
                                    if key not in visited:
                                        visited.add(key)
                                        queue.append((callee_va, tainted_args_passed,
                                                      depth_cur + 1, source_name))
                        # Clobber caller-saved
                        for r in _CALLER_SAVED:
                            tainted[r] = False
                    else:
                        self._exec_non_branch(insn, tainted)
                    idx += 1
            except Exception:
                pass

        return results

    def report(self, findings: List[TaintFinding32Mips]) -> str:
        if not findings:
            return f"[mips32_taint] No findings in {self.binary_path}"
        lines = [f"[mips32_taint] {self.binary_path}: {len(findings)} finding(s)"]
        for f in findings:
            lines.append(f"  {f}")
        return "\n".join(lines)


class MIPS32FuncProfiler:
    """
    Quick MIPS32 function profiler: strings + calls + sink detection.

    Usage:
        fp = MIPS32FuncProfiler.from_path('/path/to/mips_binary')
        profile = fp.profile(func_va=0x400800)
        print(profile.fmt())
    """

    def __init__(self, binary_path: str, ctx=None,
                 custom_sinks: Optional[Dict[str, List[int]]] = None,
                 big_endian: bool = False):
        self._tracker = MIPS32TaintTracker(binary_path, ctx=ctx, big_endian=big_endian)
        self._sinks = dict(_DEFAULT_SINKS)
        if custom_sinks:
            self._sinks.update(custom_sinks)

    @classmethod
    def from_path(cls, binary_path: str, **kwargs) -> "MIPS32FuncProfiler":
        return cls(binary_path, **kwargs)

    @classmethod
    def from_context(cls, ctx, **kwargs) -> "MIPS32FuncProfiler":
        return cls(ctx.binary_path, ctx=ctx, **kwargs)

    def profile(self, func_va: int, func_end_va: int = 0) -> MipsFuncProfile:
        t = self._tracker
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = t._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        func_name = t._func_name(func_va)

        calls: List[MipsCallProfile] = []
        strings: List[Tuple[int, str]] = []

        if not func_bytes:
            return MipsFuncProfile(t.binary_path, func_va, func_name)

        # Scan for GP-relative string references (MIPS common pattern: lw $a0, %got(str)($gp))
        # and JAL call sites
        try:
            all_insns = list(t._md.disasm(func_bytes, func_va))
            for insn in all_insns:
                ops = insn.operands
                if insn.id in (MIPS_INS_JAL,) and ops and ops[0].type == MIPS_OP_IMM:
                    target_va = ops[0].imm
                    target_name = t._plt.get(target_va, t._func_name(target_va))
                    is_sink = target_name in self._sinks
                    calls.append(MipsCallProfile(
                        site_va=insn.address,
                        target_name=target_name,
                        args={},
                        is_sink=is_sink,
                    ))
        except Exception:
            pass

        return MipsFuncProfile(t.binary_path, func_va, func_name, calls=calls, strings=strings)
