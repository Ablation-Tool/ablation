"""
cpp_struct_field_tracker.py: trace std::string field propagation between C++ structs
in x86-64 stripped PIE ELF binaries via c_str()/assign() call pairs.

The question this answers:
  "Which struct field (at base_reg+offset) was read to populate another
   struct field (at base_reg+offset), without sanitization?"

This resolves the core manual step in C++ RCE taint chains: tracking how a
network-supplied value stored in one struct's std::string field gets propagated
to a downstream struct that eventually reaches a shell sink.

Pattern detected:

  [READ]  lea rdi, [src_reg + src_off]     ; &src_struct.field
          call c_str_va                    ; rax = char*
          mov  carrier_reg, rax            ; save ptr (often rax→rsi or rax→rdX→rsi)

  [WRITE] lea rdi, [dst_reg + dst_off]     ; &dst_struct.field
          mov  rsi, carrier_reg            ; source char*
          call assign_va                   ; std::string::assign writes ptr

Gap this fills:
  1. No existing ablation tool traces C++ object field-to-field propagation.
     TaintTracker traces argument registers but does not model std::string
     method call chains. Manual capstone traces of c_str/assign pairs took
     hours per function in the PaloAlto GlobalProtect Session 4 investigation.

  2. SAC classifies a popen arg as ARG_PROPAGATED but cannot answer which
     upstream struct field supplied it.  CppStructFieldTracker answers that
     question systematically across the whole binary.

  3. DirecFlow feeds PathSolver: once you have the src_struct_offset →
     dst_struct_offset chain, PathSolver can confirm reachability from
     attacker-controlled input to the dst field.

Usage:
    from ablation.analyzers.cpp_struct_field_tracker import CppStructFieldTracker

    tracker = CppStructFieldTracker.from_context(ctx)

    # Auto-detect c_str and assign PLT stubs; finds all flows
    flows = tracker.find_flows()
    print(tracker.report(flows))

    # Restrict to flows that write into a known sink field offset
    dangerous = tracker.flows_to_offset(0xd8)   # e.g. HipCheckConfig.gateway_name

    # Restrict to flows that read from a known source field offset
    portal_sourced = tracker.flows_from_offset(0x102d0)

    # Supply explicit stub VAs when auto-detection fails (stripped / inlined)
    tracker2 = CppStructFieldTracker.from_context(ctx, c_str_va=0x83e90, assign_va=0x838c0)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_OP_REG, X86_OP_MEM, X86_OP_IMM,
        X86_REG_RDI, X86_REG_RSI, X86_REG_RAX,
    )
    _CS_OK = True
except ImportError:
    pass


# ── Register family canonicalisation ─────────────────────────────────────────

_REG_ALIASES: Dict[str, str] = {}

def _build_reg_aliases() -> Dict[str, str]:
    families = {
        'rax': ['rax', 'eax', 'ax', 'al', 'ah'],
        'rbx': ['rbx', 'ebx', 'bx', 'bl', 'bh'],
        'rcx': ['rcx', 'ecx', 'cx', 'cl', 'ch'],
        'rdx': ['rdx', 'edx', 'dx', 'dl', 'dh'],
        'rsi': ['rsi', 'esi', 'si', 'sil'],
        'rdi': ['rdi', 'edi', 'di', 'dil'],
        'rbp': ['rbp', 'ebp', 'bp', 'bpl'],
        'rsp': ['rsp', 'esp', 'sp', 'spl'],
        **{f'r{n}': [f'r{n}', f'r{n}d', f'r{n}w', f'r{n}b']
           for n in range(8, 16)},
    }
    m: Dict[str, str] = {}
    for canon, aliases in families.items():
        for a in aliases:
            m[a] = canon
    return m

_REG_ALIASES = _build_reg_aliases()


def _canon(reg_name: str) -> str:
    """Return canonical 64-bit register name (e.g. 'eax' → 'rax')."""
    return _REG_ALIASES.get(reg_name.lower(), reg_name.lower())


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class FieldFlow:
    """One confirmed c_str → assign propagation between two struct fields."""
    fn_va: int            # owning function VA

    # READ side: c_str() call that extracted the source char*
    src_call_va: int      # VA of the call c_str instruction
    src_base_reg: str     # base register in [base_reg + src_offset]
    src_offset: int       # displacement into source struct

    # Carrier: register that transported the char* from c_str to assign
    carrier_reg: str      # e.g. 'rax', 'rdx', 'rsi'

    # WRITE side: assign() call that stored the char* into the destination field
    dst_call_va: int      # VA of the call assign instruction
    dst_base_reg: str     # base register in [base_reg + dst_offset]
    dst_offset: int       # displacement into destination struct

    def fmt(self) -> str:
        src = f'{self.src_base_reg}+{hex(self.src_offset)}'
        dst = f'{self.dst_base_reg}+{hex(self.dst_offset)}'
        return (
            f'  fn@{hex(self.fn_va):12s}  [{src}] →({self.carrier_reg})→ [{dst}]'
            f'  (c_str@{hex(self.src_call_va)} assign@{hex(self.dst_call_va)})'
        )


# ── Core tracker ─────────────────────────────────────────────────────────────

# PLT name fragments that identify c_str / data() / _M_data() methods
_CSTR_MARKERS = ('c_str', '_M_data', 'basic_string', '_M_local_data')
# PLT name fragments for assign(const char*) — must also exclude operator==(...)
_ASSIGN_MARKERS = ('assign', 'operator=')


class CppStructFieldTracker:
    """
    Trace std::string field-to-field propagation via c_str()/assign() in
    x86-64 stripped C++ ELF binaries.

    Instantiate with from_context(ctx) or from_context(ctx, c_str_va=X, assign_va=Y).
    Call find_flows() to get all FieldFlow objects across the whole binary.
    """

    def __init__(
        self,
        data: bytes,
        func_starts: List[int],
        c_str_vas: Set[int],
        assign_vas: Set[int],
    ) -> None:
        self._data = data
        self._func_starts = sorted(func_starts)
        self._c_str_vas = c_str_vas
        self._assign_vas = assign_vas
        self._md: Optional[object] = None
        if _CS_OK:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_context(
        cls,
        ctx,
        c_str_va: Optional[int] = None,
        assign_va: Optional[int] = None,
    ) -> 'CppStructFieldTracker':
        """
        Build a tracker from a BinaryContext.

        If c_str_va / assign_va are not given, auto-detect from ctx.plt using
        PLT symbol name heuristics.  Pass explicit VAs when the binary is
        stripped of PLT symbol names or uses inlined std::string methods.
        """
        data = open(ctx.path, 'rb').read()
        func_starts = list(ctx.func_starts)
        plt: Dict[int, str] = ctx.plt  # {va: name}

        c_str_vas: Set[int] = set()
        assign_vas: Set[int] = set()

        if c_str_va is not None:
            c_str_vas.add(c_str_va)
        if assign_va is not None:
            assign_vas.add(assign_va)

        # Auto-detect from PLT when not overridden
        for va, name in plt.items():
            low = name.lower()
            if not c_str_vas:
                if any(m in low for m in _CSTR_MARKERS):
                    c_str_vas.add(va)
            if not assign_vas:
                if any(m in low for m in _ASSIGN_MARKERS):
                    assign_vas.add(va)

        return cls(data, func_starts, c_str_vas, assign_vas)

    # ── Public API ────────────────────────────────────────────────────────────

    def find_flows(self) -> List[FieldFlow]:
        """
        Scan all assign() call sites across the binary and return FieldFlow
        objects for those whose rsi source traces back to a c_str() call on
        a struct field.
        """
        if not _CS_OK or self._md is None:
            return []
        if not self._assign_vas:
            return []

        # Build a set of assign() call-site VAs: scan for E8 disp32 call instructions
        # targeting any assign_va across the full binary.
        assign_sites = self._find_call_sites(self._assign_vas)
        flows: List[FieldFlow] = []
        for call_va in assign_sites:
            flow = self._analyze_assign_site(call_va)
            if flow is not None:
                flows.append(flow)
        return flows

    def flows_from_offset(self, offset: int) -> List[FieldFlow]:
        """Return flows where the source struct field is at src_offset == offset."""
        return [f for f in self.find_flows() if f.src_offset == offset]

    def flows_to_offset(self, offset: int) -> List[FieldFlow]:
        """Return flows where the destination struct field is at dst_offset == offset."""
        return [f for f in self.find_flows() if f.dst_offset == offset]

    def report(self, flows: List[FieldFlow]) -> str:
        if not flows:
            return '[cpp_struct_field_tracker] no c_str→assign field flows found\n'
        lines = [f'[cpp_struct_field_tracker] {len(flows)} flow(s)\n']
        for f in flows:
            lines.append(f.fmt())
        return '\n'.join(lines) + '\n'

    # ── Internal: call site discovery ────────────────────────────────────────

    def _find_call_sites(self, target_vas: Set[int]) -> List[int]:
        """
        Scan the binary for E8 disp32 (near CALL) instructions targeting
        any VA in target_vas.  Returns sorted list of call instruction VAs.
        """
        data = self._data
        size = len(data)
        sites: List[int] = []
        for off in range(0, size - 5):
            if data[off] != 0xE8:
                continue
            import struct
            disp = struct.unpack_from('<i', data, off + 1)[0]
            target = off + 5 + disp
            if target in target_vas:
                sites.append(off)
        return sorted(sites)

    # ── Internal: per-call-site analysis ─────────────────────────────────────

    def _owning_fn(self, va: int) -> int:
        """Return the function start that contains va (lower-bound lookup)."""
        fs = self._func_starts
        lo, hi = 0, len(fs)
        while lo < hi:
            mid = (lo + hi) // 2
            if fs[mid] <= va:
                lo = mid + 1
            else:
                hi = mid
        return fs[lo - 1] if lo > 0 else va

    def _disasm_range(self, start: int, end: int):
        """Disassemble [start, end) and return list of capstone instructions."""
        if end <= start or start >= len(self._data):
            return []
        chunk = self._data[start:min(end, len(self._data))]
        return list(self._md.disasm(chunk, start))

    def _analyze_assign_site(self, call_va: int) -> Optional[FieldFlow]:
        """
        Given an assign() call site, walk backward to:
          1. Find dst field: lea rdi, [base + disp] → dst_base_reg, dst_offset
          2. Find rsi source: mov rsi, <reg> — trace <reg> to a prior c_str call
          3. For that c_str call, find src field: lea rdi, [base + disp]

        Returns a FieldFlow if the full chain resolves; None otherwise.
        """
        fn_va = self._owning_fn(call_va)

        # Disassemble from fn_va to just past the assign call
        insns = self._disasm_range(fn_va, call_va + 6)
        # Keep only instructions up to and including the assign call
        insns = [i for i in insns if i.address <= call_va]
        if not insns:
            return None

        # Reverse list for backward walk (index 0 = assign call, last = fn start)
        rev = list(reversed(insns))

        # ── Step 1: find dst rdi source (lea rdi, [base + disp]) ──────────────
        dst_base, dst_off = self._find_lea_rdi(rev, start=1, stop_at_call=True)
        if dst_base is None or dst_off <= 0:
            return None

        # ── Step 2: find what register was moved into rsi before the call ──────
        rsi_src_reg = self._find_rsi_source(rev, start=1)
        if rsi_src_reg is None:
            return None
        # rsi_src_reg is the canonical register that was in rsi at call time

        # ── Step 3: find the c_str call that set rsi_src_reg ──────────────────
        cstr_call_va = self._find_cstr_setting(rev, rsi_src_reg, start=1)
        if cstr_call_va is None:
            return None

        # ── Step 4: find src rdi before the c_str call ─────────────────────────
        cstr_idx = next(
            (i for i, insn in enumerate(rev) if insn.address == cstr_call_va), None
        )
        if cstr_idx is None:
            return None
        src_base, src_off = self._find_lea_rdi(rev, start=cstr_idx + 1, stop_at_call=True)
        if src_base is None or src_off <= 0:
            return None

        fn_va_actual = self._owning_fn(call_va)
        return FieldFlow(
            fn_va=fn_va_actual,
            src_call_va=cstr_call_va,
            src_base_reg=src_base,
            src_offset=src_off,
            carrier_reg=rsi_src_reg,
            dst_call_va=call_va,
            dst_base_reg=dst_base,
            dst_offset=dst_off,
        )

    # ── Backward-walk helpers ────────────────────────────────────────────────

    def _find_lea_rdi(
        self,
        rev_insns,
        start: int = 0,
        stop_at_call: bool = True,
        window: int = 40,
    ) -> Tuple[Optional[str], int]:
        """
        Walk rev_insns[start:start+window] backward (already reversed) looking
        for the most recent `lea rdi, [base + disp]` where disp > 0.

        stop_at_call=True: stop searching if we cross a CALL (rdi is caller-saved,
        so a call between the lea and our target call would have clobbered it).

        Returns (base_reg_canonical, displacement) or (None, 0).
        """
        for insn in rev_insns[start: start + window]:
            if stop_at_call and insn.mnemonic == 'call':
                break
            if insn.mnemonic != 'lea':
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if ops[0].type != X86_OP_REG:
                continue
            reg_name = self._md.reg_name(ops[0].reg)
            if _canon(reg_name) != 'rdi':
                continue
            if ops[1].type != X86_OP_MEM:
                continue
            mem = ops[1].mem
            # Reject rip-relative (rodata string literals) and negative offsets
            base_reg = self._md.reg_name(mem.base) if mem.base else ''
            if _canon(base_reg) == 'rip':
                continue
            if mem.disp <= 0:
                continue
            return _canon(base_reg), mem.disp
        return None, 0

    def _find_rsi_source(self, rev_insns, start: int = 0, window: int = 40) -> Optional[str]:
        """
        Walk backward looking for the instruction that set rsi just before the
        assign() call.  Returns the canonical source register (e.g. 'rax', 'rdx').

        Handles:
          mov rsi, rax        → returns 'rax'
          mov rsi, rdx        → returns 'rdx'
          mov rsi, r15        → returns 'r15'

        Returns None if rsi was set by a non-register source (immediate, memory)
        or not found within the window.
        """
        for insn in rev_insns[start: start + window]:
            if insn.mnemonic not in ('mov', 'movq', 'movl'):
                # A call clobbers rsi (caller-saved); stop searching past it
                if insn.mnemonic == 'call':
                    break
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if ops[0].type != X86_OP_REG:
                continue
            dst_reg = _canon(self._md.reg_name(ops[0].reg))
            if dst_reg != 'rsi':
                continue
            if ops[1].type == X86_OP_REG:
                return _canon(self._md.reg_name(ops[1].reg))
            return None  # rsi set from imm or mem — not a c_str chain
        return None

    def _find_cstr_setting(
        self, rev_insns, target_reg: str, start: int = 0, window: int = 60
    ) -> Optional[int]:
        """
        Walk backward from start looking for the call c_str instruction that
        set target_reg (via rax, possibly with one intermediate mov).

        Handles:
          call c_str_va  → rax; mov target_reg, rax      (direct)
          call c_str_va  → rax; mov rX, rax; ...; mov target_reg, rX  (one hop)

        Returns the VA of the `call c_str_va` instruction, or None.
        """
        # Phase 1: if target_reg == 'rax', look directly for call c_str in the window
        if target_reg == 'rax':
            for insn in rev_insns[start: start + window]:
                if insn.mnemonic == 'call':
                    ops = insn.operands
                    if ops and ops[0].type == X86_OP_IMM:
                        if ops[0].imm in self._c_str_vas:
                            return insn.address
                    break  # any other call means rax was clobbered
            return None

        # Phase 2: target_reg was set by `mov target_reg, rax` after a call.
        # Walk backward to find `mov target_reg, rax` then the preceding call c_str.
        found_mov = False
        for insn in rev_insns[start: start + window]:
            if not found_mov:
                # Looking for: mov target_reg, rax
                if insn.mnemonic in ('mov', 'movq', 'movl'):
                    ops = insn.operands
                    if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                        dst = _canon(self._md.reg_name(ops[0].reg))
                        src = _canon(self._md.reg_name(ops[1].reg))
                        if dst == target_reg and src == 'rax':
                            found_mov = True
                            continue
                if insn.mnemonic == 'call':
                    break  # rax clobbered by a different call — give up
            else:
                # found_mov: now looking for call c_str
                if insn.mnemonic == 'call':
                    ops = insn.operands
                    if ops and ops[0].type == X86_OP_IMM:
                        if ops[0].imm in self._c_str_vas:
                            return insn.address
                    # A different call — rax was clobbered before target_reg was set
                    break
        return None


# ── Module-level CLI ──────────────────────────────────────────────────────────

def _main() -> None:  # pragma: no cover
    import sys
    if len(sys.argv) < 2:
        print('Usage: python3 -m ablation.analyzers.cpp_struct_field_tracker <elf> [c_str_va] [assign_va]')
        sys.exit(1)
    path = sys.argv[1]
    c_str_va = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    assign_va = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(path)
    t = CppStructFieldTracker.from_context(ctx, c_str_va=c_str_va, assign_va=assign_va)
    flows = t.find_flows()
    print(t.report(flows))


if __name__ == '__main__':
    _main()
