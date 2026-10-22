"""
Forward taint tracker for x86-32 (i386) stripped ELF binaries.

Addresses the gap in TaintTracker (x86-64 only): i386 cdecl passes all
arguments on the stack ([ebp+8]=arg1, [ebp+c]=arg2, ...).  The initial
taint source is a set of EBP-relative offsets (e.g. {0x2c} = arg10),
not a set of register names.

Usage:
    from ablation.analyzers.taint_tracker_i386 import TaintTrackerI386
    tt = TaintTrackerI386('/path/to/i386.elf')
    sinks = tt.trace_function(
        func_va=0x839c14f,
        tainted_ebp_offsets={0x2c},   # [ebp+0x2c] = arg10 tainted at entry
        max_insns=2000,
    )
    for sink in sinks: print(sink)

Why this exists:
    TaintTracker uses CS_MODE_64 and SysV x86-64 register ARG_REGS.
    i386 cdecl has no register-passed args; all arguments are EBP-relative
    stack slots.  Tracking whether a specific stack argument flows to a call
    sink requires a different initial-taint model and a push-tracking model.

Limitation vs x86-64 tracker:
    - No inter-procedural analysis (stays within the traced function)
    - Conservative (union across all paths, no path sensitivity)
    - Handles push/pop taint propagation for i386 call convention
"""

import capstone
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


def _elf_load_base(data: bytes) -> int:
    """
    Return the lowest PT_LOAD p_vaddr for a 32-bit ELF, or 0 for PIE/unknown.
    Used to convert VA → file offset: file_off = va - load_base + p_offset.
    For common non-PIE i386 binaries (base=0x8048000, p_offset=0), this
    gives file_off = va - 0x8048000.  For PIE (base=0), file_off = va.
    """
    try:
        if data[4] != 1:   # EI_CLASS must be ELFCLASS32
            return 0
        e_phoff = struct.unpack_from('<I', data, 0x1c)[0]
        e_phnum = struct.unpack_from('<H', data, 0x2c)[0]
        lowest = None
        for i in range(e_phnum):
            ph = e_phoff + i * 0x20
            p_type   = struct.unpack_from('<I', data, ph)[0]
            p_offset = struct.unpack_from('<I', data, ph + 0x04)[0]
            p_vaddr  = struct.unpack_from('<I', data, ph + 0x08)[0]
            if p_type == 1 and p_vaddr != 0:   # PT_LOAD, not the null segment
                if lowest is None or p_vaddr < lowest:
                    lowest = p_vaddr - p_offset   # base = vaddr - file_offset
        return lowest if lowest is not None else 0
    except Exception:
        return 0

# ---------------------------------------------------------------------------
# Register canonicalization (maps 8/16/32-bit aliases to 32-bit name)
# ---------------------------------------------------------------------------

_CANON32: Dict[str, str] = {}
for _r in ('eax','ecx','edx','ebx','esp','ebp','esi','edi'):
    _CANON32[_r] = _r
for _r16, _r32 in [('ax','eax'),('cx','ecx'),('dx','edx'),('bx','ebx'),
                    ('sp','esp'),('bp','ebp'),('si','esi'),('di','edi')]:
    _CANON32[_r16] = _r32
for _r8, _r32 in [('al','eax'),('cl','ecx'),('dl','edx'),('bl','ebx'),
                   ('ah','eax'),('ch','ecx'),('dh','edx'),('bh','ebx')]:
    _CANON32[_r8] = _r32


def _canon(reg: str) -> Optional[str]:
    return _CANON32.get(reg.lower())


def _regs_in(expr: str) -> List[str]:
    """Return canonical register names that appear in a memory expression."""
    out = []
    for r, c in _CANON32.items():
        if r in expr.lower():
            if c not in out:
                out.append(c)
    return out


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class TaintSink32:
    address:          int
    sink_type:        str   # call_arg | mem_write | branch_cond | copy_len
    instruction:      str
    tainted_operand:  str
    push_depth:       int = 0   # how many pushes before the call (arg position, 1=last)
    note:             str = ''

    def __str__(self) -> str:
        return (
            f'0x{self.address:x}  [{self.sink_type}]  {self.instruction}'
            f'  (tainted: {self.tainted_operand})'
            + (f' [push_depth={self.push_depth}]' if self.push_depth else '')
            + (f': {self.note}' if self.note else '')
        )


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class TaintTrackerI386:
    """
    Forward taint tracker for i386 stripped ELF binaries.

    Taint sources are EBP-relative stack offsets (function arguments in
    cdecl calling convention) specified as a set of positive integers.
    Example: {0x2c} taints [ebp+0x2c] = arg10.
    """

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.data = open(binary_path, 'rb').read()
        self.load_base = _elf_load_base(self.data)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        self._plt: Dict[int, str] = {}
        self._load_plt()

    def _load_plt(self) -> None:
        try:
            from ablation.analyzers.binary_context import BinaryContext
            bc = BinaryContext.load_or_build(self.binary_path)
            self._plt = {va: name for va, name in bc.plt.items()}
        except Exception:
            pass

    def _plt_name(self, va: int) -> str:
        return self._plt.get(va, '')

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def trace_function(
        self,
        func_va: int,
        tainted_ebp_offsets: Set[int],
        max_insns: int = 2000,
        max_func_size: int = 0x4000,
    ) -> List[TaintSink32]:
        """
        Trace tainted EBP-relative stack slots forward through the function.

        tainted_ebp_offsets: set of positive offsets from EBP that are
            tainted at function entry.  E.g. {0x2c} = arg10 in a cdecl
            function where arg1=[ebp+8].

        Returns list of TaintSink32 where tainted data reaches a sink.
        """
        sinks: List[TaintSink32] = []

        # Primary taint state: set of canonical 32-bit register names
        taint_regs: Set[str] = set()
        # Tainted EBP offsets that remain tainted throughout the function
        taint_ebp: Set[int] = set(tainted_ebp_offsets)
        # Tainted ESP-relative slots (stack[offset]) written by push
        taint_stack: Dict[int, bool] = {}   # esp_offset -> tainted
        # Approximate ESP delta from entry (starts at 0; decremented by push/sub)
        esp_delta: int = 0
        # Pending tainted pushes before the next CALL (arg stack simulation)
        push_taint_stack: List[bool] = []   # True=tainted, bottom=first pushed

        file_off = func_va - self.load_base
        chunk = self.data[file_off:file_off + max_func_size]
        insn_count = 0

        for insn in self.md.disasm(chunk, func_va):
            if insn_count >= max_insns:
                break
            insn_count += 1
            va    = insn.address
            mnem  = insn.mnemonic.lower()
            ops   = insn.op_str
            parts = [p.strip() for p in ops.split(',')]
            dst   = parts[0] if parts else ''
            src   = parts[1] if len(parts) > 1 else ''

            dst_c = _canon(dst)
            src_c = _canon(src)

            full_insn = f'{mnem} {ops}'

            # ---------------------------------------------------------------
            # Helper: is a value tainted?
            # ---------------------------------------------------------------

            def _reg_tainted(r: str) -> bool:
                c = _canon(r)
                return bool(c and c in taint_regs)

            def _mem_expr_tainted(expr: str) -> bool:
                """Return True if the memory expression reads tainted data."""
                if '[' not in expr:
                    return False
                inner = expr[expr.index('[')+1:expr.rindex(']')]
                # Check [ebp + offset] with offset in taint_ebp
                if 'ebp' in inner.lower():
                    offset = _extract_ebp_offset(inner)
                    if offset is not None and offset in taint_ebp:
                        return True
                # Check if any register in the expr is tainted
                return any(_reg_tainted(r) for r in _regs_in(inner))

            # ---------------------------------------------------------------
            # CALL instruction
            # ---------------------------------------------------------------

            if mnem == 'call':
                target_va = None
                try:
                    target_va = int(ops.strip(), 16)
                except ValueError:
                    pass

                plt_name = self._plt_name(target_va) if target_va else ''

                # Report any tainted push in the pre-call argument stack
                for depth, is_tainted in enumerate(reversed(push_taint_stack), 1):
                    if is_tainted:
                        sinks.append(TaintSink32(
                            address=va,
                            sink_type='call_arg',
                            instruction=full_insn,
                            tainted_operand=f'pushed_arg_{depth}',
                            push_depth=depth,
                            note=(
                                f'tainted arg{depth} at call to '
                                f'{plt_name if plt_name else hex(target_va) if target_va else "indirect"}'
                            ),
                        ))

                # Also check registers (for non-cdecl patterns or indirects)
                for r in ('eax', 'ecx', 'edx'):
                    if r in taint_regs:
                        sinks.append(TaintSink32(
                            address=va,
                            sink_type='call_arg',
                            instruction=full_insn,
                            tainted_operand=r,
                            note=f'tainted {r} at call',
                        ))

                # Clear argument push stack and caller-saved regs after call
                push_taint_stack.clear()
                for kill in ('eax', 'ecx', 'edx'):
                    taint_regs.discard(kill)
                continue

            # ---------------------------------------------------------------
            # PUSH instruction — models the cdecl argument passing
            # ---------------------------------------------------------------

            if mnem == 'push':
                is_tainted_push = False
                if dst_c and _reg_tainted(dst):
                    is_tainted_push = True
                elif '[' in dst and _mem_expr_tainted(dst):
                    is_tainted_push = True
                push_taint_stack.append(is_tainted_push)
                esp_delta -= 4
                continue

            # ---------------------------------------------------------------
            # POP instruction
            # ---------------------------------------------------------------

            if mnem == 'pop':
                if push_taint_stack:
                    was_tainted = push_taint_stack.pop()
                    if dst_c:
                        if was_tainted:
                            taint_regs.add(dst_c)
                        else:
                            taint_regs.discard(dst_c)
                else:
                    if dst_c:
                        taint_regs.discard(dst_c)
                esp_delta += 4
                continue

            # ---------------------------------------------------------------
            # SUB/ADD esp — stack pointer adjustment (not argument passing)
            # ---------------------------------------------------------------

            if mnem in ('sub', 'add') and dst.lower() == 'esp':
                try:
                    imm = int(src.replace('0x', ''), 16)
                    esp_delta += (-imm if mnem == 'sub' else imm)
                except ValueError:
                    pass
                # sub esp doesn't push call args — reset arg tracking
                push_taint_stack.clear()
                continue

            # ---------------------------------------------------------------
            # MOV propagation
            # ---------------------------------------------------------------

            if mnem in ('mov', 'movzx', 'movsx', 'movzxd'):
                src_tainted = False
                if src_c and src_c in taint_regs:
                    src_tainted = True
                elif '[' in src and _mem_expr_tainted(src):
                    src_tainted = True
                elif src_c is None and not src.startswith('0x') and src.lstrip('-').isdigit():
                    src_tainted = False  # immediate constant: never tainted

                if dst_c:
                    if src_tainted:
                        taint_regs.add(dst_c)
                    else:
                        taint_regs.discard(dst_c)
                elif '[' in dst:
                    # Write to memory — check if writing tainted data
                    if src_tainted:
                        sinks.append(TaintSink32(
                            address=va, sink_type='mem_write',
                            instruction=full_insn, tainted_operand=src,
                        ))
                continue

            # ---------------------------------------------------------------
            # LEA
            # ---------------------------------------------------------------

            if mnem == 'lea':
                if dst_c:
                    any_t = any(_reg_tainted(r) for r in _regs_in(src))
                    if any_t:
                        taint_regs.add(dst_c)
                    else:
                        taint_regs.discard(dst_c)
                continue

            # ---------------------------------------------------------------
            # Arithmetic (add/sub/xor/or/and/shl/shr/etc.)
            # ---------------------------------------------------------------

            if mnem in ('add', 'sub', 'xor', 'or', 'and',
                        'shl', 'shr', 'sar', 'neg', 'not',
                        'imul', 'mul', 'inc', 'dec'):
                if mnem == 'xor' and dst == src and dst_c:
                    taint_regs.discard(dst_c)
                    continue
                src_t = (src_c in taint_regs) if src_c else False
                src_t = src_t or (('[' in src) and _mem_expr_tainted(src))
                if dst_c:
                    if src_t or (dst_c in taint_regs):
                        taint_regs.add(dst_c)
                continue

            # ---------------------------------------------------------------
            # CMP / TEST — branch condition on tainted value
            # ---------------------------------------------------------------

            if mnem in ('cmp', 'test'):
                op_a = dst_c and dst_c in taint_regs
                op_b = (src_c and src_c in taint_regs) or (
                    '[' in src and _mem_expr_tainted(src)
                ) or ('[' in dst and _mem_expr_tainted(dst))
                if op_a or op_b:
                    sinks.append(TaintSink32(
                        address=va, sink_type='branch_cond',
                        instruction=full_insn,
                        tainted_operand=dst if op_a else src,
                    ))
                continue

        return sinks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_ebp_offset(inner: str) -> Optional[int]:
    """
    Parse an EBP-relative memory expression and return the signed offset.
    Examples:
        'ebp + 0x2c'  → 0x2c
        'ebp - 0x8'   → -0x8 (not positive, so ignored for arg tracking)
        'ebp'         → 0
    Returns None if parsing fails.
    """
    s = inner.lower().replace(' ', '').replace('ebp', '')
    if not s:
        return 0
    try:
        if s.startswith('+'):
            return int(s[1:], 16)
        elif s.startswith('-'):
            return -int(s[1:], 16)
        else:
            return int(s, 16)
    except ValueError:
        return None
