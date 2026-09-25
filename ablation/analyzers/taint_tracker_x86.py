"""
taint_tracker_x86.py: Static intraprocedural x86-64 taint analysis.

Finds data-flow paths from network receive taint sources to dangerous sinks.
Implements the libdft taint policy (Andriesse, "Practical Binary Analysis", ch.11)
adapted for static analysis:

  XFER (mov/movsx/movzx):   dst_taint = src_taint
  ALU  (add/sub/and/or/xor/shl/shr/imul): dst_taint |= operand taints
  CLR  (xor rX,rX; sub rX,rX):  dst_taint = {}
  SPEC (lea):               dst_taint = union(base_reg, index_reg taints)
  CALL (source):            rax tainted; buffer arg tracked if on stack
  CALL (sink):              alert if relevant arg register is tainted
  CALL (other):             caller-saved regs cleared (rax/rcx/rdx/rsi/rdi/r8-r11)

Stack model: tracks rbp-relative and rsp-relative (with delta tracking) slots.

Usage:
    from ablation.analyzers.taint_tracker_x86 import TaintTracker, TaintFinding
    from ablation.analyzers.xref_graph import XRefGraph

    xg = XRefGraph.from_path(binary_path)
    xg.build()

    tracker = TaintTracker(binary_path, xref=xg)
    findings = tracker.run()
    for f in findings:
        print(f)
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
from capstone.x86_const import (
    X86_OP_REG, X86_OP_IMM, X86_OP_MEM,
    X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX, X86_INS_MOVSXD,
    X86_INS_MOVSS, X86_INS_MOVSD, X86_INS_MOVAPS, X86_INS_MOVDQA,
    X86_INS_MOVQ, X86_INS_MOVD,
    X86_INS_LEA,
    X86_INS_ADD, X86_INS_SUB, X86_INS_AND, X86_INS_OR, X86_INS_XOR,
    X86_INS_IMUL, X86_INS_MUL, X86_INS_DIV, X86_INS_IDIV,
    X86_INS_NOT, X86_INS_NEG,
    X86_INS_SHL, X86_INS_SHR, X86_INS_SAR, X86_INS_SAL, X86_INS_ROL, X86_INS_ROR,
    X86_INS_PUSH, X86_INS_POP,
    X86_INS_CALL, X86_INS_JMP, X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ,
    X86_INS_CMOVNE, X86_INS_CMOVE, X86_INS_CMOVA, X86_INS_CMOVB,
    X86_INS_CMOVG, X86_INS_CMOVL, X86_INS_CMOVGE, X86_INS_CMOVLE,
    X86_INS_CMOVNS, X86_INS_CMOVS,
    X86_INS_XCHG, X86_INS_CMPXCHG,
    X86_INS_TEST, X86_INS_CMP,
    X86_INS_NOP, X86_INS_HLT,
    X86_INS_CDQE, X86_INS_CDQ, X86_INS_CQO, X86_INS_CBW,
)
import lief

# ── canonical register names ──────────────────────────────────────────────────

_REG_FAMILY: Dict[str, str] = {}
for _base, _aliases in [
    ("rax", ["eax", "ax", "al", "ah"]),
    ("rbx", ["ebx", "bx", "bl", "bh"]),
    ("rcx", ["ecx", "cx", "cl", "ch"]),
    ("rdx", ["edx", "dx", "dl", "dh"]),
    ("rsi", ["esi", "si", "sil"]),
    ("rdi", ["edi", "di", "dil"]),
    ("rsp", ["esp", "sp", "spl"]),
    ("rbp", ["ebp", "bp", "bpl"]),
    ("r8",  ["r8d", "r8w", "r8b"]),
    ("r9",  ["r9d", "r9w", "r9b"]),
    ("r10", ["r10d", "r10w", "r10b"]),
    ("r11", ["r11d", "r11w", "r11b"]),
    ("r12", ["r12d", "r12w", "r12b"]),
    ("r13", ["r13d", "r13w", "r13b"]),
    ("r14", ["r14d", "r14w", "r14b"]),
    ("r15", ["r15d", "r15w", "r15b"]),
]:
    _REG_FAMILY[_base] = _base
    for _a in _aliases:
        _REG_FAMILY[_a] = _base

# Caller-saved (volatile) registers under x86-64 System V ABI
_CALLER_SAVED = frozenset(["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"])

# x86-64 argument registers (arg0..arg5)
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

def _canon(name: str) -> Optional[str]:
    """Return canonical 64-bit register name, or None if not a GP register."""
    return _REG_FAMILY.get(name.lower())

# ── taint sources and sinks ───────────────────────────────────────────────────

# Taint-forwarding functions: if any listed arg index is tainted before the call,
# rax (return value) is marked tainted after the call. Models "allocator-wrapper"
# patterns where a function wraps tainted data in a new allocation and returns a
# pointer to it: the pointer itself becomes a taint carrier.
#
# Example: strdup(tainted_str) -> rax = new allocation containing tainted bytes.
# Example: cli_nscript_get(interp, tainted_script, ...) -> rax = nscript struct
#   where nscript->script_body = tainted_script; [rax+8] then propagates taint.
_TAINT_FORWARDING: Dict[str, List[int]] = {
    "strdup":          [0],
    "strndup":         [0],
    "g_strdup":        [0],
    "xstrdup":         [0],
    "strdup_printf":   [0],
}

# After call to these: rax tainted (return value = bytes received/read)
# arg1 (rsi) = buffer: after call, track that stack slot as tainted
_SOURCES: Set[str] = {
    "recv", "recvfrom", "recvmsg", "read", "fread",
    "fgets", "gets", "getline", "getdelim",
    "scanf", "fscanf", "sscanf",
    "readv", "pread", "pread64",
}

# Sink -> list of argument indices (0-indexed) to check for taint
_SINKS: Dict[str, List[int]] = {
    # Command injection
    "system":   [0],
    "popen":    [0],
    "execve":   [0, 1, 2],
    "execl":    [0],
    "execvp":   [0, 1],
    "execv":    [0, 1],
    "execlp":   [0],
    "execle":   [0],
    "posix_spawn": [1],
    "_system":  [0],
    # Format string injection
    "printf":   [0],
    "fprintf":  [1],
    "sprintf":  [2],
    "snprintf": [2],
    "vprintf":  [0],
    "vsprintf": [2],
    "vsnprintf":[2],
    "vfprintf": [1],
    "syslog":   [1],
    # Memory corruption
    "memcpy":        [2],   # size argument
    "__memcpy_chk":  [2],   # gcc hardened version: __memcpy_chk(dst, src, len, dstlen)
    "memmove":       [2],
    "__memmove_chk": [2],
    "memset":        [2],
    "__memset_chk":  [2],
    "strcpy":   [1],
    "strcat":   [1],
    "strncpy":  [2],
    "strncat":  [2],
    "mempcpy":  [2],
    "bcopy":    [2],
    # Allocation with attacker-controlled size
    "malloc":   [0],
    "calloc":   [0, 1],
    "realloc":  [1],
    "alloca":   [0],
    # File operations with attacker-controlled path
    "open":     [0],
    "fopen":    [0],
    "unlink":   [0],
    "chmod":    [0],
    "chown":    [0],
    "rename":   [0, 1],
    "remove":   [0],
    "dlopen":   [0],
    "symlink":  [1],
    # Tcl interpreter execution (interp=arg0, script=arg1)
    "Tcl_Eval":            [1],
    "Tcl_EvalEx":          [1],
    "Tcl_GlobalEval":      [1],
    "Tcl_EvalFile":        [1],
    "Tcl_EvalObj":         [1],
    "Tcl_EvalObjEx":       [1],
    "Tcl_GlobalEvalObj":   [1],
    "Tcl_OpenCommandChannel": [1],
    # Lua interpreter execution (L=arg0, script=arg1 or chunk=arg1)
    "lua_dostring":        [1],
    "lua_loadstring":      [1],
    "luaL_dostring":       [1],
    "luaL_loadstring":     [1],
    "luaL_loadbuffer":     [1],
    # Python interpreter execution
    "PyRun_SimpleString":  [0],
    "PyRun_String":        [0],
    "PyEval_EvalCode":     [0],
    # eval-like libc
    "wordexp":             [0],
}

# ── taint state ───────────────────────────────────────────────────────────────

@dataclass
class TaintState:
    """Per-instruction taint state: which registers and stack slots are tainted."""
    regs: Dict[str, bool] = field(default_factory=dict)
    # rbp-relative slots (disp as signed int -> tainted)
    rbp_slots: Dict[int, bool] = field(default_factory=dict)
    # rsp-relative slots (rsp_delta-adjusted disp -> tainted)
    rsp_slots: Dict[int, bool] = field(default_factory=dict)
    # running rsp offset from function entry (sub rsp,N -> delta decreases)
    rsp_delta: int = 0

    def is_tainted_reg(self, name: str) -> bool:
        c = _canon(name)
        return bool(c and self.regs.get(c))

    def taint_reg(self, name: str):
        c = _canon(name)
        if c:
            self.regs[c] = True

    def clear_reg(self, name: str):
        c = _canon(name)
        if c:
            self.regs[c] = False

    def is_tainted_rbp_slot(self, disp: int) -> bool:
        return bool(self.rbp_slots.get(disp))

    def taint_rbp_slot(self, disp: int):
        self.rbp_slots[disp] = True

    def clear_rbp_slot(self, disp: int):
        self.rbp_slots[disp] = False

    def is_tainted_rsp_slot(self, disp: int) -> bool:
        normalized = disp + self.rsp_delta
        return bool(self.rsp_slots.get(normalized))

    def taint_rsp_slot(self, disp: int):
        normalized = disp + self.rsp_delta
        self.rsp_slots[normalized] = True

    def clear_rsp_slot(self, disp: int):
        normalized = disp + self.rsp_delta
        self.rsp_slots[normalized] = False

    def clear_caller_saved(self):
        for r in _CALLER_SAVED:
            self.regs[r] = False

    def any_tainted(self) -> bool:
        return any(self.regs.values()) or any(self.rbp_slots.values()) or any(self.rsp_slots.values())

    def copy(self) -> "TaintState":
        return TaintState(
            regs=dict(self.regs),
            rbp_slots=dict(self.rbp_slots),
            rsp_slots=dict(self.rsp_slots),
            rsp_delta=self.rsp_delta,
        )

    def join(self, other: "TaintState") -> "TaintState":
        """Conservative join (union): result is tainted if EITHER input is tainted."""
        result = self.copy()
        for reg, tainted in other.regs.items():
            if tainted:
                result.regs[reg] = True
        for slot, tainted in other.rbp_slots.items():
            if tainted:
                result.rbp_slots[slot] = True
        for slot, tainted in other.rsp_slots.items():
            if tainted:
                result.rsp_slots[slot] = True
        # rsp_delta: take the most negative (deepest stack) for safety
        result.rsp_delta = min(self.rsp_delta, other.rsp_delta)
        return result

    def __eq__(self, other) -> bool:
        if not isinstance(other, TaintState):
            return False
        return (self.regs == other.regs and
                self.rbp_slots == other.rbp_slots and
                self.rsp_slots == other.rsp_slots)


# ── finding ───────────────────────────────────────────────────────────────────

@dataclass
class TaintFinding:
    func_va: int       # VA of the function where found
    sink_va: int       # VA of the sink call instruction
    sink_name: str     # name of the sink (e.g. "system")
    tainted_args: List[int]   # which argument positions are tainted
    tainted_regs: List[str]   # which canonical registers carried taint
    source_calls: List[str]   # source functions that introduced taint

    def __str__(self) -> str:
        args = [f"arg{i}" for i in self.tainted_args]
        return (f"[TAINT] func={self.func_va:#x} sink={self.sink_va:#x} "
                f"{self.sink_name}({', '.join(args)}) "
                f"regs={self.tainted_regs} sources={self.source_calls}")


# ── instruction-level propagation ────────────────────────────────────────────

def _taint_from_mem_op(op, state: TaintState) -> bool:
    """Return whether a MEM operand's referenced address is tainted."""
    base = None
    index = None

    # Get register names from capstone
    if hasattr(op, 'mem'):
        m = op.mem
        if m.base:
            # We need the capstone handle to get reg_name: handled outside
            # This function receives pre-resolved names via keyword params
            pass

    return False  # caller handles this with pre-resolved names


def _is_self_op(insn, md) -> bool:
    """True if instruction is a CLR (xor rX,rX or sub rX,rX)."""
    if len(insn.operands) != 2:
        return False
    op0, op1 = insn.operands[0], insn.operands[1]
    if op0.type == X86_OP_REG and op1.type == X86_OP_REG:
        return md.reg_name(op0.reg) == md.reg_name(op1.reg)
    return False


def _propagate(insn, md, state: TaintState, plt: Dict[int, str],
               findings: List[TaintFinding], func_va: int,
               source_calls: List[str],
               extra_sinks: Optional[Dict[str, List[int]]] = None) -> Optional[str]:
    """
    Apply taint propagation for one instruction. Returns sink name if hit.
    Mutates state in place.

    extra_sinks: additional {symbol_name: [arg_indices]} merged with _SINKS.
                 Use for target-specific sinks (e.g. exec_handler, custom wrappers).
    """
    iid = insn.id
    ops = insn.operands
    mnem = insn.mnemonic

    _eff = {**_SINKS, **extra_sinks} if extra_sinks else _SINKS

    # ── CALL ─────────────────────────────────────────────────────────────
    if iid == X86_INS_CALL:
        target = None
        if ops and ops[0].type == X86_OP_IMM:
            target = ops[0].imm
        elif ops and ops[0].type == X86_OP_REG:
            # indirect call: we don't know the target statically
            state.clear_caller_saved()
            return None

        target_name = plt.get(target, "") if target else ""

        if target_name in _SOURCES:
            # Mark rax as tainted (return value = bytes count)
            state.clear_caller_saved()
            state.taint_reg("rax")
            # The buffer argument (rsi before call) is now tainted on the stack
            # Try to track: if rsi pointed to [rbp-N], mark that slot
            # (We can't know the pointer target here without memory model;
            # we mark rsi itself as tainted so subsequent loads propagate)
            state.taint_reg("rsi")
            return None

        if target_name in _eff:
            expected_args = _eff[target_name]
            tainted_args = []
            tainted_regs = []
            for arg_idx in expected_args:
                if arg_idx < len(_ARG_REGS):
                    reg = _ARG_REGS[arg_idx]
                    if state.is_tainted_reg(reg):
                        tainted_args.append(arg_idx)
                        tainted_regs.append(reg)
            if tainted_args:
                findings.append(TaintFinding(
                    func_va=func_va,
                    sink_va=insn.address,
                    sink_name=target_name,
                    tainted_args=tainted_args,
                    tainted_regs=tainted_regs,
                    source_calls=list(source_calls),
                ))
            state.clear_caller_saved()
            return target_name if tainted_args else None

        # Unknown call: clear caller-saved
        state.clear_caller_saved()
        return None

    # ── TAIL CALL: unconditional jmp to a PLT stub ───────────────────────
    # Compiler emits `jmp PLT_stub` instead of `call PLT_stub; ret` when the
    # callee's return value is also the caller's: same ABI, all arg regs live.
    if iid == X86_INS_JMP:
        target = None
        if ops and ops[0].type == X86_OP_IMM:
            target = ops[0].imm
        if target:
            target_name = plt.get(target, "")
            if target_name in _eff:
                expected_args = _eff[target_name]
                tainted_args = []
                tainted_regs = []
                for arg_idx in expected_args:
                    if arg_idx < len(_ARG_REGS):
                        reg = _ARG_REGS[arg_idx]
                        if state.is_tainted_reg(reg):
                            tainted_args.append(arg_idx)
                            tainted_regs.append(reg)
                if tainted_args:
                    findings.append(TaintFinding(
                        func_va=func_va,
                        sink_va=insn.address,
                        sink_name=target_name,
                        tainted_args=tainted_args,
                        tainted_regs=tainted_regs,
                        source_calls=list(source_calls),
                    ))
                return target_name if tainted_args else None
        return None

    # ── RET ──────────────────────────────────────────────────────────────
    if iid in (X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ):
        return None

    # ── NOP/TEST/CMP (no taint effect) ───────────────────────────────────
    if iid in (X86_INS_NOP, X86_INS_HLT, X86_INS_TEST, X86_INS_CMP):
        return None

    # ── PUSH ──────────────────────────────────────────────────────────────
    if iid == X86_INS_PUSH:
        state.rsp_delta -= 8
        if ops and ops[0].type == X86_OP_REG:
            reg_name = md.reg_name(ops[0].reg)
            tainted = state.is_tainted_reg(reg_name)
            state.taint_rsp_slot(0) if tainted else state.clear_rsp_slot(0)
        return None

    # ── POP ───────────────────────────────────────────────────────────────
    if iid == X86_INS_POP:
        tainted = state.is_tainted_rsp_slot(0)
        state.rsp_delta += 8
        if ops and ops[0].type == X86_OP_REG:
            reg_name = md.reg_name(ops[0].reg)
            if tainted:
                state.taint_reg(reg_name)
            else:
                state.clear_reg(reg_name)
        return None

    # ── rsp delta tracking ────────────────────────────────────────────────
    # sub rsp, N / add rsp, N adjust the delta
    if iid in (X86_INS_SUB, X86_INS_ADD) and len(ops) >= 2:
        op0, op1 = ops[0], ops[1]
        if op0.type == X86_OP_REG and md.reg_name(op0.reg) == "rsp":
            if op1.type == X86_OP_IMM:
                delta = op1.imm
                if iid == X86_INS_SUB:
                    state.rsp_delta -= delta
                else:
                    state.rsp_delta += delta
                return None

    # ── XFER class: MOV variants ──────────────────────────────────────────
    _XFER_IDS = (X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX, X86_INS_MOVSXD,
                 X86_INS_MOVSS, X86_INS_MOVSD, X86_INS_MOVAPS, X86_INS_MOVDQA,
                 X86_INS_MOVQ, X86_INS_MOVD,
                 X86_INS_CMOVNE, X86_INS_CMOVE, X86_INS_CMOVA, X86_INS_CMOVB,
                 X86_INS_CMOVG, X86_INS_CMOVL, X86_INS_CMOVGE, X86_INS_CMOVLE,
                 X86_INS_CMOVNS, X86_INS_CMOVS)

    if iid in _XFER_IDS and len(ops) == 2:
        dst_op, src_op = ops[0], ops[1]
        src_tainted = _op_is_tainted(src_op, md, state)
        _apply_dst(dst_op, md, state, src_tainted)
        return None

    # ── CLR: xor rX,rX / sub rX,rX ──────────────────────────────────────
    if iid in (X86_INS_XOR, X86_INS_SUB) and _is_self_op(insn, md):
        if ops[0].type == X86_OP_REG:
            state.clear_reg(md.reg_name(ops[0].reg))
        return None

    # ── SPEC: LEA ────────────────────────────────────────────────────────
    if iid == X86_INS_LEA and len(ops) == 2:
        dst_op, src_op = ops[0], ops[1]
        # src_op is MEM: taint = union(base_reg, index_reg)
        src_tainted = False
        if src_op.type == X86_OP_MEM:
            m = src_op.mem
            if m.base and md.reg_name(m.base) not in ("rip", "rsp", "rbp"):
                src_tainted |= state.is_tainted_reg(md.reg_name(m.base))
            if m.index and md.reg_name(m.index) not in ("rip",):
                src_tainted |= state.is_tainted_reg(md.reg_name(m.index))
            # Special: if base is rbp/rsp and the slot is tainted, dst is tainted
            if m.base:
                bname = md.reg_name(m.base)
                if bname == "rbp":
                    src_tainted |= state.is_tainted_rbp_slot(m.disp)
                elif bname == "rsp":
                    src_tainted |= state.is_tainted_rsp_slot(m.disp)
        if dst_op.type == X86_OP_REG:
            if src_tainted:
                state.taint_reg(md.reg_name(dst_op.reg))
            else:
                state.clear_reg(md.reg_name(dst_op.reg))
        return None

    # ── ALU class: add/and/or/xor/shl/shr/sar/imul etc. ─────────────────
    _ALU_IDS = (X86_INS_ADD, X86_INS_AND, X86_INS_OR, X86_INS_XOR,
                X86_INS_IMUL, X86_INS_MUL,
                X86_INS_SHL, X86_INS_SHR, X86_INS_SAR, X86_INS_SAL,
                X86_INS_ROL, X86_INS_ROR)

    if iid in _ALU_IDS and len(ops) >= 2:
        dst_op = ops[0]
        # dst is read AND written; src_taints = union of all operand taints
        combined = False
        for op in ops:
            combined |= _op_is_tainted(op, md, state)
        # Apply: dst_taint |= combined (but only if not CLR: handled above)
        if dst_op.type == X86_OP_REG:
            if combined:
                state.taint_reg(md.reg_name(dst_op.reg))
            # (never clear dst for ALU: taint is additive)
        return None

    # ── SUB (non-self) ALU ────────────────────────────────────────────────
    if iid == X86_INS_SUB and len(ops) >= 2:
        dst_op, src_op = ops[0], ops[1]
        src_tainted = _op_is_tainted(src_op, md, state)
        dst_tainted = _op_is_tainted(dst_op, md, state)
        combined = src_tainted or dst_tainted
        if dst_op.type == X86_OP_REG:
            if combined:
                state.taint_reg(md.reg_name(dst_op.reg))
        return None

    # ── XCHG ─────────────────────────────────────────────────────────────
    if iid == X86_INS_XCHG and len(ops) == 2:
        t0 = _op_is_tainted(ops[0], md, state)
        t1 = _op_is_tainted(ops[1], md, state)
        _apply_dst(ops[0], md, state, t1)
        _apply_dst(ops[1], md, state, t0)
        return None

    # ── NEG / NOT (unary) ────────────────────────────────────────────────
    if iid in (X86_INS_NEG, X86_INS_NOT) and len(ops) == 1:
        # Taint preserved
        return None

    # ── CDQ / CQO (sign-extend rax into rdx:rax) ─────────────────────────
    if iid in (X86_INS_CDQ, X86_INS_CQO, X86_INS_CDQE, X86_INS_CBW):
        if state.is_tainted_reg("rax"):
            state.taint_reg("rdx")
        else:
            state.clear_reg("rdx")
        return None

    return None


def _op_is_tainted(op, md, state: TaintState) -> bool:
    """Check if a capstone operand carries taint."""
    if op.type == X86_OP_IMM:
        return False   # immediates are never tainted
    if op.type == X86_OP_REG:
        return state.is_tainted_reg(md.reg_name(op.reg))
    if op.type == X86_OP_MEM:
        m = op.mem
        # Check if memory operand reads from a tainted slot
        if m.base:
            bname = md.reg_name(m.base)
            if bname == "rbp":
                return state.is_tainted_rbp_slot(m.disp)
            if bname == "rsp":
                return state.is_tainted_rsp_slot(m.disp)
            # Otherwise: if the base register is tainted, the load is tainted
            return state.is_tainted_reg(bname)
    return False


def _apply_dst(dst_op, md, state: TaintState, tainted: bool):
    """Set taint on a destination operand (register or stack slot)."""
    if dst_op.type == X86_OP_REG:
        if tainted:
            state.taint_reg(md.reg_name(dst_op.reg))
        else:
            state.clear_reg(md.reg_name(dst_op.reg))
    elif dst_op.type == X86_OP_MEM:
        m = dst_op.mem
        if m.base:
            bname = md.reg_name(m.base)
            if bname == "rbp":
                if tainted:
                    state.taint_rbp_slot(m.disp)
                else:
                    state.clear_rbp_slot(m.disp)
            elif bname == "rsp":
                if tainted:
                    state.taint_rsp_slot(m.disp)
                else:
                    state.clear_rsp_slot(m.disp)


# ── per-function analysis ─────────────────────────────────────────────────────

MAX_FUNC_BYTES = 8192   # cap to avoid runaway analysis


def analyze_function(data: bytes, func_va: int, func_end_va: int,
                     plt: Dict[int, str],
                     md: capstone.Cs,
                     extra_sinks: Optional[Dict[str, List[int]]] = None) -> List[TaintFinding]:
    """
    Run linear taint analysis on one function. Returns list of TaintFindings.

    data:       full binary bytes
    func_va:    start VA of the function in the binary
    func_end_va: end VA (exclusive): we stop at min(func_end_va, func_va+MAX_FUNC_BYTES)
    plt:        {va: name} for PLT entries
    md:         configured capstone Cs instance (detail=True)
    """
    findings: List[TaintFinding] = []
    source_calls: List[str] = []

    # Determine byte offset in data
    # Assume virtual base = data start (caller adjusts func_va appropriately)
    # The caller should pass file-offset-based func_va or handle the VA-to-offset mapping
    # Here we rely on the XRefGraph/sweep pattern where data is read from file and VA
    # matches file offset for .text (not always true; caller must slice data correctly)

    # We accept a pre-sliced bytes buffer starting at func_va's offset
    func_bytes = data
    end_bytes = min(len(func_bytes), MAX_FUNC_BYTES)
    if func_end_va > func_va:
        end_bytes = min(end_bytes, func_end_va - func_va)

    state = TaintState()

    # Check if this function is a source itself (unlikely but possible)
    func_name = plt.get(func_va, "")

    prev_was_source = False

    for insn in md.disasm(func_bytes[:end_bytes], func_va):
        # Track which sources introduced taint
        if insn.id == X86_INS_CALL:
            ops = insn.operands
            if ops and ops[0].type == X86_OP_IMM:
                target = ops[0].imm
                target_name = plt.get(target, "")
                if target_name in _SOURCES and target_name not in source_calls:
                    source_calls.append(target_name)

        _propagate(insn, md, state, plt, findings, func_va, source_calls, extra_sinks)

        # Early exit: if no taint and we've passed any source call, no point continuing
        # (optimization: skip only if we've never had taint)
        if insn.id in (X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ):
            break

    return findings


# ── interprocedural path ─────────────────────────────────────────────────────

@dataclass
class InterproceduralPath:
    """Multi-hop taint path from a network source through function calls to a sink."""
    func_chain: List[int]    # ordered list of function VAs traversed
    sink_va: int
    sink_name: str
    tainted_args: List[int]
    source_name: str         # which source function introduced taint

    def __str__(self) -> str:
        chain = " -> ".join(f"0x{va:x}" for va in self.func_chain)
        args = [f"arg{i}" for i in self.tainted_args]
        return (f"[TAINT-CHAIN] {chain} -> {self.sink_name}({', '.join(args)}) "
                f"source={self.source_name}")


def analyze_function_seeded(
    data: bytes,
    func_va: int,
    func_end_va: int,
    plt: Dict[int, str],
    md: capstone.Cs,
    seed_arg_indices: List[int],
    source_calls: Optional[List[str]] = None,
    taint_forwarding: Optional[Dict[str, List[int]]] = None,
    extra_sinks: Optional[Dict[str, List[int]]] = None,
) -> Tuple[List[TaintFinding], List[Tuple[int, List[int]]]]:
    """
    Taint analysis with pre-tainted argument registers (for interprocedural propagation).

    seed_arg_indices: argument positions (0-indexed) that arrive tainted.
    Returns (findings, propagations) where propagations is a list of
    (callee_va, tainted_arg_indices) for internal calls that received tainted args.
    """
    findings: List[TaintFinding] = []
    propagations: List[Tuple[int, List[int]]] = []
    if source_calls is None:
        source_calls = []

    func_bytes = data
    end_bytes = min(len(func_bytes), MAX_FUNC_BYTES)
    if func_end_va > func_va:
        end_bytes = min(end_bytes, func_end_va - func_va)

    state = TaintState()
    _eff = {**_SINKS, **extra_sinks} if extra_sinks else _SINKS
    # Pre-taint seed argument registers
    for arg_idx in seed_arg_indices:
        if arg_idx < len(_ARG_REGS):
            state.taint_reg(_ARG_REGS[arg_idx])

    for insn in md.disasm(func_bytes[:end_bytes], func_va):
        # At each internal CALL: capture which arg regs are tainted before clearing
        if insn.id == X86_INS_CALL:
            ops = insn.operands
            if ops and ops[0].type == X86_OP_IMM:
                target = ops[0].imm
                target_name = plt.get(target, "")

                if target_name in _SOURCES:
                    if target_name not in source_calls:
                        source_calls = list(source_calls) + [target_name]
                    state.clear_caller_saved()
                    state.taint_reg("rax")
                    state.taint_reg("rsi")
                    continue

                if target_name in _eff:
                    expected_args = _eff[target_name]
                    tainted_args = []
                    tainted_regs = []
                    for arg_idx in expected_args:
                        if arg_idx < len(_ARG_REGS):
                            reg = _ARG_REGS[arg_idx]
                            if state.is_tainted_reg(reg):
                                tainted_args.append(arg_idx)
                                tainted_regs.append(reg)
                    if tainted_args:
                        findings.append(TaintFinding(
                            func_va=func_va,
                            sink_va=insn.address,
                            sink_name=target_name,
                            tainted_args=tainted_args,
                            tainted_regs=tainted_regs,
                            source_calls=list(source_calls),
                        ))
                    state.clear_caller_saved()
                    continue

                # Internal call (not PLT source/sink): record propagation
                if target_name == "":
                    tainted_args_out = []
                    for arg_idx, reg in enumerate(_ARG_REGS):
                        if state.is_tainted_reg(reg):
                            tainted_args_out.append(arg_idx)
                    if tainted_args_out:
                        propagations.append((target, tainted_args_out))

                # Forwarding: if any trigger arg is tainted, mark rax tainted
                # after the call instead of clearing it. Handles "allocator-wrapper"
                # patterns: f(tainted_ptr, ...) -> rax = struct containing tainted data.
                merged_forwarding = dict(_TAINT_FORWARDING)
                if taint_forwarding:
                    merged_forwarding.update(taint_forwarding)
                forwarded = False
                if target_name in merged_forwarding:
                    trigger_args = merged_forwarding[target_name]
                    if any(state.is_tainted_reg(_ARG_REGS[a])
                           for a in trigger_args if a < len(_ARG_REGS)):
                        forwarded = True

                state.clear_caller_saved()
                if forwarded:
                    state.taint_reg("rax")
                continue

            # Indirect call: clear caller-saved only
            if ops and ops[0].type == X86_OP_REG:
                state.clear_caller_saved()
                continue

        # Tail-call: unconditional jmp to a PLT sink or internal callee
        if insn.id == X86_INS_JMP:
            ops = insn.operands
            if ops and ops[0].type == X86_OP_IMM:
                target = ops[0].imm
                target_name = plt.get(target, "")
                if target_name in _eff:
                    expected_args = _eff[target_name]
                    tainted_args = []
                    tainted_regs = []
                    for arg_idx in expected_args:
                        if arg_idx < len(_ARG_REGS):
                            reg = _ARG_REGS[arg_idx]
                            if state.is_tainted_reg(reg):
                                tainted_args.append(arg_idx)
                                tainted_regs.append(reg)
                    if tainted_args:
                        findings.append(TaintFinding(
                            func_va=func_va,
                            sink_va=insn.address,
                            sink_name=target_name,
                            tainted_args=tainted_args,
                            tainted_regs=tainted_regs,
                            source_calls=list(source_calls),
                        ))
                elif target_name == "":
                    # Internal tail-call: record propagation
                    tainted_args_out = []
                    for arg_idx, reg in enumerate(_ARG_REGS):
                        if state.is_tainted_reg(reg):
                            tainted_args_out.append(arg_idx)
                    if tainted_args_out:
                        propagations.append((target, tainted_args_out))
            continue

        _propagate(insn, md, state, plt, findings, func_va, source_calls, extra_sinks)

        if insn.id in (X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ):
            break

    return findings, propagations


# ── flow-sensitive taint (MFP worklist over CFG) ─────────────────────────────

def analyze_function_flow_sensitive(
    data: bytes,
    func_va: int,
    func_end_va: int,
    plt: Dict[int, str],
    md: capstone.Cs,
    cfg,
    seed_args: Optional[List[int]] = None,
    source_calls: Optional[List[str]] = None,
    taint_forwarding: Optional[Dict[str, List[int]]] = None,
    extra_sinks: Optional[Dict[str, List[int]]] = None,
) -> Tuple[List[TaintFinding], List[Tuple[int, List[int]]]]:
    """
    Flow-sensitive taint analysis using CFG-based MFP worklist algorithm.

    Processes each basic block once per taint-state change at its entry.
    Join at merge points: conservative union (tainted on ANY predecessor path).
    Fixpoint: iterate until no block's exit taint changes.

    Returns (findings, propagations) matching analyze_function_seeded interface.

    cfg: CFG object from cfg_builder.CFGBuilder.build_function()
    seed_args: argument indices to pre-taint at function entry (interprocedural use)
    """
    from collections import deque

    if source_calls is None:
        source_calls = []

    findings: List[TaintFinding] = []
    propagations: List[Tuple[int, List[int]]] = []

    if not cfg or not cfg.blocks:
        return findings, propagations

    # VA -> file offset helper using known section bounds embedded in data param
    # data here is a pre-sliced bytes starting at func_va's file offset
    def read_block(bb_start: int, bb_end_inclusive: int) -> Optional[bytes]:
        rel_start = bb_start - func_va
        rel_end = bb_end_inclusive - func_va + 15  # +15 for max insn size
        if rel_start < 0:
            return None
        end = min(rel_end, len(data))
        return data[rel_start:end]

    # Taint state at entry of each basic block
    taint_in: Dict[int, TaintState] = {}
    taint_out: Dict[int, TaintState] = {}

    # Initialize entry block
    entry_state = TaintState()
    if seed_args:
        for arg_idx in seed_args:
            if arg_idx < len(_ARG_REGS):
                entry_state.taint_reg(_ARG_REGS[arg_idx])
    taint_in[func_va] = entry_state

    worklist: deque = deque([func_va])
    visited_with_state: Dict[int, TaintState] = {}

    # Per-block accumulated source calls (grows monotonically; propagated to successors)
    # Separate from taint state so fixpoint convergence is unaffected.
    accumulated_sources: Dict[int, Set[str]] = {func_va: set(source_calls)}

    # Build predecessor map
    preds: Dict[int, List[int]] = {bb_va: [] for bb_va in cfg.blocks}
    for bb_va, bb in cfg.blocks.items():
        for succ in bb.succs:
            if succ in preds:
                preds[succ].append(bb_va)

    iterations = 0
    max_iterations = len(cfg.blocks) * 4  # convergence bound

    while worklist and iterations < max_iterations:
        iterations += 1
        bb_va = worklist.popleft()
        bb = cfg.blocks.get(bb_va)
        if bb is None:
            continue

        # Compute taint-in = join of all predecessor taint-outs
        pred_outs = [taint_out[p] for p in preds.get(bb_va, []) if p in taint_out]
        if pred_outs:
            state_in = pred_outs[0].copy()
            for ps in pred_outs[1:]:
                state_in = state_in.join(ps)
        else:
            state_in = taint_in.get(bb_va, TaintState()).copy()

        # Check fixpoint: skip if state_in unchanged from last visit
        prev = visited_with_state.get(bb_va)
        if prev is not None and state_in == prev:
            continue
        visited_with_state[bb_va] = state_in.copy()

        # Propagate taint through this basic block's instructions
        state = state_in.copy()
        # Source calls accumulated from all predecessor paths into this block
        block_src_set: Set[str] = set(accumulated_sources.get(bb_va, set()))

        chunk = read_block(bb.start, bb.end)
        if chunk:
            for insn in md.disasm(chunk, bb.start):
                if insn.address > bb.end:
                    break
                if insn.address >= func_end_va:
                    break

                # Track sources introduced in this block; capture forwarding state before call
                _fwd_taint_rax = False
                if insn.id == X86_INS_CALL:
                    ops = insn.operands
                    if ops and ops[0].type == X86_OP_IMM:
                        target_name = plt.get(ops[0].imm, "")
                        if target_name in _SOURCES:
                            block_src_set.add(target_name)

                        # For propagation tracking (interprocedural): capture tainted args before call clears them
                        if target_name == "":
                            callee_va = ops[0].imm
                            tainted_out = []
                            for ai, reg in enumerate(_ARG_REGS):
                                if state.is_tainted_reg(reg):
                                    tainted_out.append(ai)
                            if tainted_out:
                                propagations.append((callee_va, tainted_out))

                        # Check forwarding: capture pre-call arg taint before _propagate clears it
                        _merged_fwd = dict(_TAINT_FORWARDING)
                        if taint_forwarding:
                            _merged_fwd.update(taint_forwarding)
                        if target_name in _merged_fwd:
                            _trigger = _merged_fwd[target_name]
                            if any(state.is_tainted_reg(_ARG_REGS[a])
                                   for a in _trigger if a < len(_ARG_REGS)):
                                _fwd_taint_rax = True

                _propagate(insn, md, state, plt, findings, func_va, list(block_src_set), extra_sinks)
                if _fwd_taint_rax:
                    state.taint_reg("rax")

        # Save accumulated sources for this block
        accumulated_sources[bb_va] = block_src_set

        state_out = state
        old_out = taint_out.get(bb_va)
        if old_out is None or state_out != old_out:
            taint_out[bb_va] = state_out.copy()
            # Update successors' taint_in and propagate accumulated sources
            for succ_va in bb.succs:
                if succ_va not in cfg.blocks:
                    continue
                succ_preds_outs = [taint_out[p] for p in preds.get(succ_va, []) if p in taint_out]
                if succ_preds_outs:
                    new_succ_in = succ_preds_outs[0].copy()
                    for ps in succ_preds_outs[1:]:
                        new_succ_in = new_succ_in.join(ps)
                    taint_in[succ_va] = new_succ_in
                # Propagate sources forward to successor
                accumulated_sources.setdefault(succ_va, set()).update(block_src_set)
                worklist.append(succ_va)

    return findings, propagations


# ── main tracker class ────────────────────────────────────────────────────────

class TaintTracker:
    """
    Static x86-64 intraprocedural taint tracker.

    Iterates all functions detected in the binary (via XRefGraph prologue scan
    or supplied func_starts), applies linear taint analysis to each, collects
    all sink hits.
    """

    def __init__(self, binary_path: str, xref=None, func_starts=None,
                 custom_sinks: Optional[Dict[str, List[int]]] = None,
                 custom_sink_vas: Optional[Dict[int, tuple]] = None):
        """
        binary_path:     path to ELF binary
        xref:            XRefGraph instance (already built): provides PLT + func boundaries
        func_starts:     optional explicit set of function start VAs
        custom_sinks:    {symbol_name: [arg_indices]} added to the sink table.
                         Use for target-specific functions not in the default list.
                         Example: {"exec_handler": [2], "custom_eval": [1]}
        custom_sink_vas: {va: (name, [arg_indices])} for sinks referenced by VA.
                         Entries are injected into the PLT map AND the sink table.
                         Example: {0x595c0: ("exec_handler", [2])}
        """
        self.path = binary_path
        self.data = Path(binary_path).read_bytes()
        self.xref = xref
        self._func_starts = func_starts

        # Build extra_sinks: merge custom_sinks + custom_sink_vas names
        self._extra_sinks: Optional[Dict[str, List[int]]] = None
        merged: Dict[str, List[int]] = {}
        if custom_sinks:
            merged.update(custom_sinks)
        if custom_sink_vas:
            for va, (name, args) in custom_sink_vas.items():
                merged[name] = args
        if merged:
            self._extra_sinks = merged

        # Load LIEF binary for section VA->offset mapping
        try:
            self._lief = lief.parse(binary_path)
        except Exception:
            self._lief = None

        # Build VA-to-file-offset map from LIEF sections
        self._sections: List[Tuple[int, int, int, bytes]] = []  # (vaddr, size, offset, data)
        if self._lief:
            try:
                for sect in self._lief.sections:
                    va = sect.virtual_address
                    sz = int(sect.size)
                    off = int(sect.offset)
                    if sz > 0 and va > 0:
                        self._sections.append((va, sz, off, None))  # data loaded lazily
            except Exception:
                pass

        # Configure capstone
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._md.detail = True

        # Build PLT map
        self._plt: Dict[int, str] = {}
        if xref is not None:
            self._plt = dict(xref._plt)
        # Inject custom VA sinks into PLT map so they resolve by name
        if custom_sink_vas:
            for va, (name, _args) in custom_sink_vas.items():
                self._plt[va] = name

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        """Return bytes from file at virtual address va with given size."""
        for svaddr, ssz, soff, _ in self._sections:
            if svaddr <= va < svaddr + ssz:
                rel = va - svaddr
                end = rel + size
                if end <= ssz:
                    return self.data[soff + rel: soff + rel + size]
                return self.data[soff + rel: soff + ssz]
        # Fallback: no section map, treat data as a flat file
        if va < len(self.data):
            return self.data[va: va + size]
        return None

    def _get_func_starts(self) -> List[int]:
        if self._func_starts:
            return sorted(self._func_starts)
        if self.xref is not None and self.xref._func_starts:
            return sorted(self.xref._func_starts)
        # Fallback: prologue scan
        starts = []
        for i in range(len(self.data) - 3):
            if self.data[i] == 0x55 and self.data[i + 1:i + 3] == b'\x48\x89':
                starts.append(i)  # raw file offset as VA (imprecise without LIEF)
        return starts

    def run(self, min_func_size: int = 20) -> List[TaintFinding]:
        """
        Analyze all functions. Return all TaintFindings sorted by func_va.
        """
        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        all_findings: List[TaintFinding] = []

        # Build function end VA map: each function ends where next starts
        for i, fva in enumerate(func_starts):
            fend = func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES

            # Get bytes for this function
            func_bytes = self._va_to_slice(fva, min(fend - fva, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < min_func_size:
                continue

            try:
                findings = analyze_function(
                    data=func_bytes,
                    func_va=fva,
                    func_end_va=fend,
                    plt=self._plt,
                    md=self._md,
                    extra_sinks=self._extra_sinks,
                )
                all_findings.extend(findings)
            except Exception:
                continue

        all_findings.sort(key=lambda f: f.func_va)
        return all_findings

    def run_interprocedural(self, depth: int = 4, min_func_size: int = 20) -> List["InterproceduralPath"]:
        """
        Multi-hop taint tracking across function call boundaries.

        BFS from functions that call network sources, following tainted arguments
        into callee functions up to `depth` hops. Reports full chains:
          recv_func -> parse_packet -> exec_cmd -> system()

        depth: max hops from seed function (default 4)
        """
        from collections import deque

        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        # Build function boundary map
        func_end_map: Dict[int, int] = {}
        for i, fva in enumerate(func_starts):
            fend = func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES
            func_end_map[fva] = fend

        func_start_set = set(func_starts)

        # Step 1: identify seed functions (directly call a network source)
        # Use CFGBuilder so calls in non-first basic blocks are not missed.
        from ablation.analyzers.cfg_builder import CFGBuilder
        try:
            cfg_builder = CFGBuilder(self.path, xref=self.xref)
        except Exception:
            cfg_builder = None

        seed_funcs: Dict[int, List[str]] = {}
        for fva in func_starts:
            fend = func_end_map[fva]
            func_bytes = self._va_to_slice(fva, min(fend - fva, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < min_func_size:
                continue
            if cfg_builder is not None:
                # Walk all basic blocks -- catches source calls anywhere in the function
                try:
                    cfg = cfg_builder.build_function(fva, fend)
                    for bb in cfg.blocks.values():
                        for va, mnem, op_str in bb.insns:
                            if mnem != "call":
                                continue
                            # Re-disassemble the single instruction to get the
                            # operand integer directly (avoids op_str string parsing)
                            raw = self._va_to_slice(va, 15)
                            if not raw:
                                continue
                            for insn in self._md.disasm(raw, va):
                                if insn.id == X86_INS_CALL:
                                    ops = insn.operands
                                    if ops and ops[0].type == X86_OP_IMM:
                                        target_name = self._plt.get(ops[0].imm, "")
                                        if target_name in _SOURCES:
                                            seed_funcs.setdefault(fva, []).append(target_name)
                                break
                    continue
                except Exception:
                    pass
            # Fallback: linear scan when CFGBuilder unavailable
            try:
                for insn in self._md.disasm(func_bytes, fva):
                    if insn.id == X86_INS_CALL:
                        ops = insn.operands
                        if ops and ops[0].type == X86_OP_IMM:
                            target_name = self._plt.get(ops[0].imm, "")
                            if target_name in _SOURCES:
                                seed_funcs.setdefault(fva, []).append(target_name)
                    if insn.id in (X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ):
                        break
            except Exception:
                continue

        # Step 2: BFS: (func_va, seed_arg_indices, path, source_name, depth)
        results: List[InterproceduralPath] = []
        queue: deque = deque()
        visited: Set[tuple] = set()

        for fva, sources in seed_funcs.items():
            key = (fva, frozenset())
            if key not in visited:
                visited.add(key)
                queue.append((fva, [], [fva], sources[0], 0))

        while queue:
            func_va, seed_args, path, source_name, d = queue.popleft()
            if d > depth:
                continue

            fend = func_end_map.get(func_va, func_va + MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(func_va, min(fend - func_va, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < min_func_size:
                continue

            try:
                cfg = cfg_builder.build_function(func_va, fend) if cfg_builder else None
                if cfg and cfg.blocks:
                    findings, propagations = analyze_function_flow_sensitive(
                        data=func_bytes, func_va=func_va, func_end_va=fend,
                        plt=self._plt, md=self._md, cfg=cfg,
                        seed_args=seed_args or None,
                        source_calls=[source_name],
                        extra_sinks=self._extra_sinks,
                    )
                else:
                    findings, propagations = analyze_function_seeded(
                        data=func_bytes, func_va=func_va, func_end_va=fend,
                        plt=self._plt, md=self._md, seed_arg_indices=seed_args,
                        source_calls=[source_name],
                        extra_sinks=self._extra_sinks,
                    )
            except Exception:
                continue

            for f in findings:
                results.append(InterproceduralPath(
                    func_chain=list(path),
                    sink_va=f.sink_va,
                    sink_name=f.sink_name,
                    tainted_args=f.tainted_args,
                    source_name=source_name,
                ))

            # Propagate to callees that received tainted args
            for callee_va, tainted_arg_indices in propagations:
                if callee_va not in func_start_set:
                    continue
                key = (callee_va, frozenset(tainted_arg_indices))
                if key not in visited:
                    visited.add(key)
                    queue.append((callee_va, tainted_arg_indices,
                                  path + [callee_va], source_name, d + 1))

        return results

    def run_on_function(self, func_va: int, func_end_va: int = 0) -> List[TaintFinding]:
        """Analyze a single function."""
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes:
            return []
        return analyze_function(
            data=func_bytes, func_va=func_va, func_end_va=func_end_va,
            plt=self._plt, md=self._md,
            extra_sinks=self._extra_sinks,
        )

    def run_on_function_seeded(
        self,
        func_va: int,
        seed_arg_indices: List[int],
        func_end_va: int = 0,
        source_calls: Optional[List[str]] = None,
    ) -> List[TaintFinding]:
        """
        Analyze a function with pre-tainted argument registers.

        Use when taint originates from the function's caller (entry arguments)
        rather than from a network source call within the function.

        seed_arg_indices: argument positions (0-indexed) that arrive tainted.
          0 = rdi, 1 = rsi, 2 = rdx, 3 = rcx, 4 = r8, 5 = r9
          Example: seed_arg_indices=[1] to taint rsi (argv in a handler function)

        Returns TaintFinding list; findings include custom_sinks if registered.
        """
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes:
            return []
        findings, _ = analyze_function_seeded(
            data=func_bytes,
            func_va=func_va,
            func_end_va=func_end_va,
            plt=self._plt,
            md=self._md,
            seed_arg_indices=seed_arg_indices,
            source_calls=source_calls,
            extra_sinks=self._extra_sinks,
        )
        return findings

    def run_flow_sensitive(self, min_func_size: int = 20) -> Tuple[List[TaintFinding], List["InterproceduralPath"]]:
        """
        Flow-sensitive taint analysis over all functions using CFG-based MFP worklist.

        Builds a CFG per function and applies the fixpoint algorithm instead of
        linear scan. Eliminates false positives from infeasible paths and handles
        loops correctly (linear analysis may miss taint introduced in loop bodies).

        Returns (intraprocedural_findings, interprocedural_chains).
        """
        from ablation.analyzers.cfg_builder import CFGBuilder
        from collections import deque

        func_starts = self._get_func_starts()
        if not func_starts:
            return [], []

        func_end_map: Dict[int, int] = {}
        for i, fva in enumerate(func_starts):
            fend = func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES
            func_end_map[fva] = fend

        func_start_set = set(func_starts)

        builder = CFGBuilder(self.path, xref=self.xref)

        all_findings: List[TaintFinding] = []

        # Phase 1: intraprocedural flow-sensitive analysis on all functions
        seed_funcs: Dict[int, List[str]] = {}
        for fva in func_starts:
            fend = func_end_map[fva]
            func_bytes = self._va_to_slice(fva, min(fend - fva, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < min_func_size:
                continue
            try:
                cfg = builder.build_function(fva, fend)
                if not cfg.blocks:
                    continue
                findings, _ = analyze_function_flow_sensitive(
                    data=func_bytes, func_va=fva, func_end_va=fend,
                    plt=self._plt, md=self._md, cfg=cfg,
                    extra_sinks=self._extra_sinks,
                )
                all_findings.extend(findings)
                # Track seed functions (directly call a network source)
                for insn in self._md.disasm(func_bytes, fva):
                    if insn.id == X86_INS_CALL:
                        ops = insn.operands
                        if ops and ops[0].type == X86_OP_IMM:
                            tname = self._plt.get(ops[0].imm, "")
                            if tname in _SOURCES:
                                seed_funcs.setdefault(fva, []).append(tname)
                    if insn.id in (X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ):
                        break
            except Exception:
                continue

        all_findings.sort(key=lambda f: f.func_va)

        # Phase 2: interprocedural BFS using flow-sensitive analysis per hop
        chains: List[InterproceduralPath] = []
        queue: deque = deque()
        visited: Set[tuple] = set()

        for fva, sources in seed_funcs.items():
            key = (fva, frozenset())
            if key not in visited:
                visited.add(key)
                queue.append((fva, [], [fva], sources[0], 0))

        while queue:
            func_va, seed_args, path, source_name, d = queue.popleft()
            if d > 4:
                continue
            fend = func_end_map.get(func_va, func_va + MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(func_va, min(fend - func_va, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < min_func_size:
                continue
            try:
                cfg = builder.build_function(func_va, fend)
                findings, propagations = analyze_function_flow_sensitive(
                    data=func_bytes, func_va=func_va, func_end_va=fend,
                    plt=self._plt, md=self._md, cfg=cfg,
                    seed_args=seed_args if seed_args else None,
                    source_calls=[source_name],
                    extra_sinks=self._extra_sinks,
                )
            except Exception:
                continue

            for f in findings:
                chains.append(InterproceduralPath(
                    func_chain=list(path),
                    sink_va=f.sink_va,
                    sink_name=f.sink_name,
                    tainted_args=f.tainted_args,
                    source_name=source_name,
                ))

            for callee_va, tainted_arg_indices in propagations:
                if callee_va not in func_start_set:
                    continue
                key = (callee_va, frozenset(tainted_arg_indices))
                if key not in visited:
                    visited.add(key)
                    queue.append((callee_va, tainted_arg_indices,
                                  path + [callee_va], source_name, d + 1))

        return all_findings, chains


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse, sys

    ap = argparse.ArgumentParser(description="Static x86-64 taint analysis: sources -> sinks")
    ap.add_argument("binary", help="Stripped x86-64 ELF binary")
    ap.add_argument("--func", help="Analyze single function at VA (hex)", default=None)
    ap.add_argument("--min-size", type=int, default=20, help="Min function byte size to analyze")
    ap.add_argument("--use-xref", action="store_true", help="Build XRefGraph for better function detection")
    ap.add_argument("--interprocedural", action="store_true", help="Run cross-function BFS taint tracking")
    ap.add_argument("--depth", type=int, default=4, help="Max hop depth for interprocedural analysis")
    ap.add_argument("--flow-sensitive", action="store_true", help="CFG-based MFP worklist analysis (more precise)")
    args = ap.parse_args()

    xref = None
    if args.use_xref:
        from ablation.analyzers.xref_graph import XRefGraph
        print(f"[*] Building XRefGraph for {args.binary} ...")
        xref = XRefGraph.from_path(args.binary)
        xref.build()
        xs = xref.stats()
        print(f"[*] XRef: {xs['functions']} functions, {xs['plt_entries']} PLT entries")

    tracker = TaintTracker(args.binary, xref=xref)

    if args.func:
        va = int(args.func, 16)
        findings = tracker.run_on_function(va)
        if not findings:
            print("[*] No taint paths found.")
        else:
            print(f"\n[!] {len(findings)} taint path(s) found:\n")
            for f in findings:
                print(str(f))
                print(f"    sources: {f.source_calls}")
                print()
    elif args.interprocedural:
        print(f"[*] Running interprocedural taint analysis (depth={args.depth}) ...")
        chains = tracker.run_interprocedural(depth=args.depth, min_func_size=args.min_size)
        if not chains:
            print("[*] No cross-function taint chains found.")
        else:
            print(f"\n[!] {len(chains)} interprocedural taint chain(s):\n")
            for c in chains:
                print(str(c))
                print()
        sys.exit(0 if not chains else 1)
    elif getattr(args, 'flow_sensitive', False):
        print(f"[*] Running flow-sensitive CFG taint analysis ...")
        findings, chains = tracker.run_flow_sensitive(min_func_size=args.min_size)
        if findings:
            print(f"\n[!] {len(findings)} intraprocedural finding(s):\n")
            for f in findings:
                print(str(f))
                print(f"    sources: {f.source_calls}")
                print()
        if chains:
            print(f"\n[!] {len(chains)} interprocedural chain(s):\n")
            for c in chains:
                print(str(c))
                print()
        if not findings and not chains:
            print("[*] No taint paths found.")
        sys.exit(0 if (not findings and not chains) else 1)
    else:
        print(f"[*] Running taint analysis on all functions ...")
        findings = tracker.run(min_func_size=args.min_size)

        if not findings:
            print("[*] No taint paths found.")
        else:
            print(f"\n[!] {len(findings)} taint path(s) found:\n")
            for f in findings:
                print(str(f))
                print(f"    sources: {f.source_calls}")
                print()
        sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    _cli()
