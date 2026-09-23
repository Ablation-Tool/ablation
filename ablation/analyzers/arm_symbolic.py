#!/usr/bin/env python3
"""
arm_symbolic.py — Lightweight Symbolic Execution for ARM32

Path-insensitive symbolic execution for tracking args → protocol fields.
No SMT solver, summary-based inter-procedural analysis.

Architecture
────────────
Symbolic Domain:
  Arg(index)     — function argument (r0-r3)
  InputBuf(id)   — protocol buffer pointer
  Add(base, off) — pointer arithmetic (flattened)
  Unknown        — merge points, complex operations

Transfer Functions:
  MOV, ADD, SUB, LDR, STR, BL, BLX

Function Summaries:
  arg_field_writes: [(arg_idx, offset)]  — which args write to which offsets
  inputbuf_reads:   [offset]             — offsets read from input buffer
  const_stores:     {offset: value}      — constant values written

Vtable Dispatch Strategy:
  Slot-specific semantic patterning (Approach C from SESSION.md)
  - Build slot → implementations map
  - Classify slots by pattern (sendto, session writes, RTP headers)
  - Union summaries per slot
  - Model vcall as named operation

Usage:
  analyzer = ARMSymbolicAnalyzer(binary_data, base_addr=0)
  summary = analyzer.analyze_function(0x2511c, max_insns=200)

  print(f"Arg field writes: {summary.arg_field_writes}")
  print(f"Input reads: {summary.inputbuf_reads}")

Author: NuClide Research (2026-08-16)
License: Internal research use only
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set, Union
from pathlib import Path
import struct

# Import our custom ARM disassembler
from arm_disasm import ARMDisassembler, ARMInstruction


# ============================================================================
# Symbolic Domain
# ============================================================================

@dataclass(frozen=True)
class Arg:
    """Function argument (r0-r3 on ARM32)"""
    index: int  # 0-3 for r0-r3

    def __str__(self):
        return f"Arg({self.index})"


@dataclass(frozen=True)
class InputBuf:
    """Input buffer pointer (marked explicitly)"""
    id: str  # e.g., "sendto_buf"

    def __str__(self):
        return f"InputBuf({self.id})"


@dataclass(frozen=True)
class Add:
    """Pointer arithmetic (flattened: Add(Add(x,k1),k2) → Add(x,k1+k2))"""
    base: 'SymVal'
    offset: int

    def __str__(self):
        return f"({self.base} + {self.offset:#x})"


@dataclass(frozen=True)
class Unknown:
    """Unknown value (merge points, complex ops, external calls)"""
    reason: str = "unknown"

    def __str__(self):
        return f"Unknown({self.reason})"


# Union type for all symbolic values
SymVal = Union[Arg, InputBuf, Add, Unknown]


# ============================================================================
# Function Summary
# ============================================================================

@dataclass
class FuncSummary:
    """Summary of a function's symbolic effects"""
    addr: int
    name: str = ""

    # Symbolic writes: arg[idx] written to offset
    arg_field_writes: List[Tuple[int, int]] = field(default_factory=list)

    # Offsets read from input buffer
    inputbuf_reads: List[int] = field(default_factory=list)

    # Constant values stored at offsets
    const_stores: Dict[int, int] = field(default_factory=dict)

    # Calls to other functions (address, arg mapping)
    calls: List[Tuple[int, List[SymVal]]] = field(default_factory=list)

    # Vtable calls (slot index if known)
    vcalls: List[Optional[int]] = field(default_factory=list)

    def __str__(self):
        lines = [f"FuncSummary @ 0x{self.addr:x}"]
        if self.arg_field_writes:
            lines.append(f"  arg_field_writes: {self.arg_field_writes}")
        if self.inputbuf_reads:
            lines.append(f"  inputbuf_reads: {[f'0x{x:x}' for x in self.inputbuf_reads]}")
        if self.const_stores:
            lines.append(f"  const_stores: {{{', '.join(f'0x{k:x}: {v}' for k, v in self.const_stores.items())}}}")
        if self.calls:
            lines.append(f"  calls: {len(self.calls)} direct calls")
        if self.vcalls:
            lines.append(f"  vcalls: {len(self.vcalls)} vtable calls")
        return '\n'.join(lines)


# ============================================================================
# Symbolic Execution Engine
# ============================================================================

class ARMSymbolicAnalyzer:
    """Lightweight symbolic execution for ARM32 binaries"""

    def __init__(self, data: bytes, base_addr: int = 0):
        self.data = data
        self.base_addr = base_addr
        self.disasm = ARMDisassembler(data, base_addr)

        # Function summaries cache
        self.summaries: Dict[int, FuncSummary] = {}

        # Vtable slot mapping (slot_idx → [function_addrs])
        self.vtable_slots: Dict[int, List[int]] = {}

    def analyze_function(self, addr: int, max_insns: int = 200,
                        mark_inputbuf: Optional[int] = None) -> FuncSummary:
        """
        Analyze a function and generate summary.

        Args:
            addr: Function start address
            max_insns: Maximum instructions to analyze
            mark_inputbuf: Arg index to mark as InputBuf (e.g., 0 for r0)
        """
        # Check cache
        if addr in self.summaries:
            return self.summaries[addr]

        summary = FuncSummary(addr=addr)

        # Disassemble
        insns = self.disasm.disassemble(addr, max_insns)

        # Initialize symbolic state
        state = self._init_state(mark_inputbuf)

        # Execute symbolically
        for insn in insns:
            # Check for function end (BX LR, POP {..., PC})
            if self._is_return(insn):
                break

            # Execute transfer function
            self._execute_insn(insn, state, summary)

        # Cache and return
        self.summaries[addr] = summary
        return summary

    def _init_state(self, mark_inputbuf: Optional[int] = None) -> Dict[str, SymVal]:
        """Initialize symbolic state with arguments"""
        state = {}

        # ARM calling convention: r0-r3 are args
        for i in range(4):
            reg = f'r{i}'
            if mark_inputbuf is not None and i == mark_inputbuf:
                state[reg] = InputBuf(f"arg{i}")
            else:
                state[reg] = Arg(i)

        # Other registers start as unknown
        for i in range(4, 13):
            state[f'r{i}'] = Unknown("initial")

        state['sp'] = Unknown("stack")
        state['lr'] = Unknown("link")
        state['pc'] = Unknown("pc")

        return state

    def _is_return(self, insn: ARMInstruction) -> bool:
        """Check if instruction is a function return"""
        # BX LR
        if insn.mnemonic.startswith('bx') and 'lr' in insn.operands.lower():
            return True

        # POP {..., PC}
        if insn.mnemonic.startswith('pop') and 'pc' in insn.operands.lower():
            return True

        return False

    def _execute_insn(self, insn: ARMInstruction,
                     state: Dict[str, SymVal],
                     summary: FuncSummary):
        """Execute single instruction symbolically"""
        mnem = insn.mnemonic.lower().rstrip('s')  # Strip condition suffix

        # MOV: rd = rs
        if mnem.startswith('mov'):
            self._exec_mov(insn, state)

        # ADD/SUB: rd = rn + operand2
        elif mnem.startswith('add') or mnem.startswith('sub'):
            self._exec_add_sub(insn, state)

        # LDR: rd = [rn + offset]
        elif mnem.startswith('ldr'):
            self._exec_ldr(insn, state, summary)

        # STR: [rd + offset] = rs
        elif mnem.startswith('str'):
            self._exec_str(insn, state, summary)

        # BL: direct call
        elif mnem.startswith('bl') and not mnem.startswith('blx'):
            self._exec_bl(insn, state, summary)

        # BLX: indirect call (vtable dispatch)
        elif mnem.startswith('blx'):
            self._exec_blx(insn, state, summary)

        # CMP, TST: comparison (don't modify registers, but important for context)
        elif mnem.startswith('cmp') or mnem.startswith('tst'):
            pass  # Path-insensitive: ignore conditionals

        # Other instructions: conservatively mark affected regs as Unknown
        else:
            self._exec_default(insn, state)

    def _exec_mov(self, insn: ARMInstruction, state: Dict[str, SymVal]):
        """MOV rd, rs / MOV rd, #imm"""
        parts = [p.strip() for p in insn.operands.split(',')]
        if len(parts) < 2:
            return

        rd = parts[0].lower()
        src = parts[1].lower()

        # MOV rd, rs
        if src in state:
            state[rd] = state[src]
        # MOV rd, #imm
        elif src.startswith('#'):
            # Immediate → Unknown (we care about pointers, not constants)
            state[rd] = Unknown("immediate")
        else:
            state[rd] = Unknown("mov")

    def _exec_add_sub(self, insn: ARMInstruction, state: Dict[str, SymVal]):
        """ADD/SUB rd, rn, operand2"""
        parts = [p.strip() for p in insn.operands.split(',')]
        if len(parts) < 3:
            return

        rd = parts[0].lower()
        rn = parts[1].lower()
        op2 = parts[2].lower()

        # Only track ADD with immediate offset (pointer arithmetic)
        if op2.startswith('#'):
            try:
                # Parse immediate
                imm_str = op2.lstrip('#')
                if imm_str.startswith('0x'):
                    offset = int(imm_str, 16)
                else:
                    offset = int(imm_str)

                # Negate for SUB
                if insn.mnemonic.lower().startswith('sub'):
                    offset = -offset

                # Flatten nested Adds
                base_val = state.get(rn, Unknown("unknown"))
                if isinstance(base_val, Add):
                    state[rd] = Add(base_val.base, base_val.offset + offset)
                elif isinstance(base_val, (Arg, InputBuf)):
                    state[rd] = Add(base_val, offset)
                else:
                    state[rd] = Unknown("add")
            except:
                state[rd] = Unknown("add_imm_parse_fail")
        else:
            # Register operand → Unknown
            state[rd] = Unknown("add_reg")

    def _exec_ldr(self, insn: ARMInstruction, state: Dict[str, SymVal], summary: FuncSummary):
        """LDR rd, [rn, #offset]"""
        parts = insn.operands.split(',')
        if len(parts) < 2:
            return

        rd = parts[0].strip().lower()

        # Parse address: [rn, #offset] or [rn]
        addr_part = ','.join(parts[1:]).strip()
        if '[' in addr_part:
            addr_part = addr_part.lstrip('[').rstrip(']')
            addr_parts = [p.strip() for p in addr_part.split(',')]
            rn = addr_parts[0].lower()

            # Extract offset if present
            offset = 0
            if len(addr_parts) > 1:
                off_str = addr_parts[1]
                if off_str.startswith('#') or off_str.startswith('+#'):
                    try:
                        off_str = off_str.lstrip('+#')
                        offset = int(off_str, 16) if off_str.startswith('0x') else int(off_str)
                    except:
                        pass

            # Log read from symbolic pointer
            base_val = state.get(rn, Unknown("unknown"))
            if isinstance(base_val, InputBuf):
                summary.inputbuf_reads.append(offset)
            elif isinstance(base_val, Add):
                if isinstance(base_val.base, InputBuf):
                    summary.inputbuf_reads.append(base_val.offset + offset)

            # Result is Unknown (we don't track memory contents)
            state[rd] = Unknown("loaded")
        else:
            state[rd] = Unknown("ldr")

    def _exec_str(self, insn: ARMInstruction, state: Dict[str, SymVal], summary: FuncSummary):
        """STR rs, [rd, #offset]"""
        parts = insn.operands.split(',')
        if len(parts) < 2:
            return

        rs = parts[0].strip().lower()

        # Parse destination: [rd, #offset] or [rd]
        addr_part = ','.join(parts[1:]).strip()
        if '[' in addr_part:
            addr_part = addr_part.lstrip('[').rstrip(']')
            addr_parts = [p.strip() for p in addr_part.split(',')]
            rd = addr_parts[0].lower()

            # Extract offset
            offset = 0
            if len(addr_parts) > 1:
                off_str = addr_parts[1]
                if off_str.startswith('#') or off_str.startswith('+#'):
                    try:
                        off_str = off_str.lstrip('+#')
                        offset = int(off_str, 16) if off_str.startswith('0x') else int(off_str)
                    except:
                        pass

            # Log symbolic writes
            src_val = state.get(rs, Unknown("unknown"))
            dest_val = state.get(rd, Unknown("unknown"))

            # Arg writes
            if isinstance(src_val, Arg):
                if isinstance(dest_val, Add) and isinstance(dest_val.base, Arg):
                    summary.arg_field_writes.append((src_val.index, dest_val.offset + offset))
                elif isinstance(dest_val, Arg):
                    summary.arg_field_writes.append((src_val.index, offset))

    def _exec_bl(self, insn: ARMInstruction, state: Dict[str, SymVal], summary: FuncSummary):
        """BL target — direct call"""
        # Parse target address
        target_str = insn.operands.strip()
        try:
            if target_str.startswith('0x'):
                target = int(target_str, 16)
            else:
                target = int(target_str)

            # Record call with current args (r0-r3)
            args = [state.get(f'r{i}', Unknown("arg")) for i in range(4)]
            summary.calls.append((target, args))

            # Return value in r0 is Unknown
            state['r0'] = Unknown("call_return")
        except:
            state['r0'] = Unknown("bl_parse_fail")

    def _exec_blx(self, insn: ARMInstruction, state: Dict[str, SymVal], summary: FuncSummary):
        """BLX reg — indirect call (vtable dispatch)"""
        # Extract register
        reg = insn.operands.strip().lower()

        # Try to infer vtable slot if possible
        # (For now, just record that a vcall happened)
        summary.vcalls.append(None)  # Slot index unknown in this simple version

        # Return value in r0 is Unknown
        state['r0'] = Unknown("vcall_return")

    def _exec_default(self, insn: ARMInstruction, state: Dict[str, SymVal]):
        """Default handler: mark destination as Unknown"""
        # Try to extract destination register
        if ',' in insn.operands:
            parts = insn.operands.split(',')
            rd = parts[0].strip().lower()
            if rd in state:
                state[rd] = Unknown(f"{insn.mnemonic}")


# ============================================================================
# Vtable Slot Analyzer
# ============================================================================

class VtableSlotAnalyzer:
    """Analyzes vtable dispatch patterns and builds slot summaries"""

    def __init__(self, analyzer: ARMSymbolicAnalyzer):
        self.analyzer = analyzer
        self.slot_summaries: Dict[int, FuncSummary] = {}

    def scan_vtables(self, start: int, end: int) -> Dict[int, List[int]]:
        """
        Scan .rodata for vtables (arrays of function pointers).

        Returns: {slot_index: [implementation_addrs]}
        """
        # Simplified: look for aligned sequences of code pointers
        # Real implementation would use heuristics + section info

        vtables = {}
        # Placeholder for now
        return vtables

    def classify_slot(self, slot_idx: int, implementations: List[int]) -> str:
        """
        Classify slot by analyzing all implementations.

        Returns semantic label: "SendSignaling", "UpdateSession", etc.
        """
        # Analyze all implementations
        summaries = []
        for addr in implementations:
            summary = self.analyzer.analyze_function(addr)
            summaries.append(summary)

        # Classify by pattern
        # - Calls sendto? → I/O operation
        # - Writes to session struct? → State update
        # - Builds RTP headers? → Media operation

        # Placeholder heuristic
        if any('sendto' in str(s.calls) for s in summaries):
            return "SendSignaling"
        elif any(s.arg_field_writes for s in summaries):
            return "UpdateSession"
        else:
            return f"VcallSlot{slot_idx}"

    def union_summaries(self, slot_idx: int, implementations: List[int]) -> FuncSummary:
        """Union summaries across all implementations of a slot"""
        if slot_idx in self.slot_summaries:
            return self.slot_summaries[slot_idx]

        # Analyze all implementations
        summaries = [self.analyzer.analyze_function(addr) for addr in implementations]

        # Union all effects
        union = FuncSummary(addr=slot_idx, name=f"VcallSlot{slot_idx}")

        for s in summaries:
            union.arg_field_writes.extend(s.arg_field_writes)
            union.inputbuf_reads.extend(s.inputbuf_reads)
            union.const_stores.update(s.const_stores)

        # Deduplicate
        union.arg_field_writes = list(set(union.arg_field_writes))
        union.inputbuf_reads = list(set(union.inputbuf_reads))

        self.slot_summaries[slot_idx] = union
        return union


# ============================================================================
# Example Usage
# ============================================================================

def main():
    """Example: analyze SendSignaling function from libhijoyptt.so"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: arm_symbolic.py <libhijoyptt.so> [function_addr]")
        sys.exit(1)

    lib_path = Path(sys.argv[1])
    func_addr = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x2511c

    # Load binary
    with open(lib_path, 'rb') as f:
        data = f.read()

    # Create analyzer
    analyzer = ARMSymbolicAnalyzer(data, base_addr=0)

    # Analyze function (mark r0 as InputBuf for protocol analysis)
    print(f"Analyzing function at 0x{func_addr:x}...\n")
    summary = analyzer.analyze_function(func_addr, max_insns=200, mark_inputbuf=0)

    # Print results
    print(summary)
    print()

    # Protocol field mapping
    if summary.inputbuf_reads:
        print("Protocol Buffer Field Accesses:")
        for offset in sorted(set(summary.inputbuf_reads)):
            print(f"  InputBuf[0x{offset:x}]")
        print()

    if summary.arg_field_writes:
        print("Argument Field Writes:")
        for arg_idx, offset in sorted(set(summary.arg_field_writes)):
            print(f"  Arg({arg_idx}) → [base + 0x{offset:x}]")
        print()


if __name__ == '__main__':
    main()
