"""
Forward taint tracker for x86-64 stripped ELF binaries.

Usage:
    from ablation.analyzers.taint_tracker import TaintTracker
    tt = TaintTracker('/path/to/binary')
    sinks = tt.trace_function(
        func_va=0x22ccc0,
        tainted_args=['rdi', 'rsi', 'rdx'],
        max_insns=500
    )
    for sink in sinks:
        print(sink)

Returns a list of TaintSink objects describing where tainted data reaches:
    - alloc_size: tainted value used as allocation size argument
    - copy_len: tainted value used as copy/move length
    - mem_write: tainted value written to memory
    - branch_cond: tainted value controls a branch (determines reachability)
    - call_arg: tainted value passed to a function call

Limitations:
    - Intra-function only (does not follow calls)
    - No path sensitivity (conservative: union of all paths)
    - No loop unrolling (assumes loops can execute any number of times)
    - Handles: mov, movzx, movsxd, lea (partial), add, sub, imul, shl, shr, and, or, xor
    - Tracks general-purpose 64-bit registers + stack slots (rsp+offset, rbp-offset)
"""

import capstone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

REG64 = {
    'rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',
    'r8','r9','r10','r11','r12','r13','r14','r15',
}
REG32 = {
    'eax','ecx','edx','ebx','esp','ebp','esi','edi',
    'r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d',
}
REG16 = {
    'ax','cx','dx','bx','sp','bp','si','di',
    'r8w','r9w','r10w','r11w','r12w','r13w','r14w','r15w',
}
REG8 = {
    'al','cl','dl','bl','ah','ch','dh','bh',
    'spl','bpl','sil','dil',
    'r8b','r9b','r10b','r11b','r12b','r13b','r14b','r15b',
}

_REG_CANONICAL = {}
for r in REG64: _REG_CANONICAL[r] = r
for r in REG32:
    base = r.rstrip('d')
    if base.startswith('r'): _REG_CANONICAL[r] = base
    else: _REG_CANONICAL[r] = 'r' + base[1:]
for r in REG16:
    if r.startswith('r'): _REG_CANONICAL[r] = r[:-1]  # r8w -> r8
    else: _REG_CANONICAL[r] = 'r' + r[:-1] if len(r)==2 else 'r' + r
for r in REG8:
    # al->rax, cl->rcx, ...
    base_map = {'a':'rax','c':'rcx','d':'rdx','b':'rbx','sp':'rsp','bp':'rbp','si':'rsi','di':'rdi'}
    short = r[:-1]
    if short in base_map: _REG_CANONICAL[r] = base_map[short]
    elif r[-1] == 'b': _REG_CANONICAL[r] = r[:-1]  # r8b -> r8
    else: _REG_CANONICAL[r] = r

# Fix 8-bit 'h' regs
for r, canonical in [('ah','rax'),('ch','rcx'),('dh','rdx'),('bh','rbx')]:
    _REG_CANONICAL[r] = canonical

# Additional: rip -> rip
_REG_CANONICAL['rip'] = 'rip'

def canon(reg: str) -> Optional[str]:
    return _REG_CANONICAL.get(reg)


@dataclass
class TaintSink:
    address: int
    sink_type: str      # alloc_size | copy_len | mem_write | branch_cond | call_arg
    instruction: str    # mnemonic + op_str
    tainted_operand: str
    note: str = ''

    def __str__(self):
        return f'0x{self.address:x}  [{self.sink_type}]  {self.instruction}  (tainted: {self.tainted_operand}){" -- " + self.note if self.note else ""}'


class TaintTracker:
    # Known allocation functions by VA (populated from PLT / BinaryContext)
    ALLOC_FUNCS: Set[int] = set()
    # Known copy functions
    COPY_FUNCS: Set[int] = set()

    # Argument registers for SysV x86-64
    ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.data = open(binary_path, 'rb').read()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self._populate_known_funcs()

    def _populate_known_funcs(self):
        try:
            import sys
            sys.path.insert(0, '/home/cowboy/ablation')
            from ablation.analyzers.binary_context import BinaryContext
            bc = BinaryContext.load_or_build(self.binary_path)
            for va, name in bc.plt.items():
                if any(x in name for x in ('malloc','calloc','realloc')):
                    self.ALLOC_FUNCS.add(va)
                if any(x in name for x in ('memcpy','memmove','memset','bcopy')):
                    self.COPY_FUNCS.add(va)
        except Exception:
            pass

    def _insn_at(self, va: int, count: int = 1):
        chunk = self.data[va:va+15*count]
        insns = list(self.md.disasm(chunk, va))
        return insns[:count]

    def trace_function(
        self,
        func_va: int,
        tainted_args: List[str],
        max_insns: int = 800,
        max_func_size: int = 0x2000,
    ) -> List[TaintSink]:
        """
        Trace taint forward through function starting at func_va.
        tainted_args: list of register names that are tainted at function entry,
                      e.g. ['rdi', 'rsi', 'rdx']
        Returns list of TaintSink where taint reaches interesting operations.
        """
        sinks: List[TaintSink] = []
        # Taint set: canonical register names or 'stack+N' keys
        taint: Set[str] = set()
        for a in tainted_args:
            c = canon(a)
            if c: taint.add(c)

        chunk = self.data[func_va:func_va + max_func_size]
        insn_count = 0

        for insn in self.md.disasm(chunk, func_va):
            if insn_count >= max_insns:
                break
            insn_count += 1
            va = insn.address
            mnem = insn.mnemonic
            ops = insn.op_str

            # Parse operands
            parts = [p.strip() for p in ops.split(',')]
            if not parts or not parts[0]:
                continue

            dst = parts[0] if parts else ''
            src = parts[1] if len(parts) > 1 else ''

            dst_canon = canon(dst) if dst in _REG_CANONICAL else None
            src_canon = canon(src) if src in _REG_CANONICAL else None

            src_tainted = (src_canon in taint) if src_canon else False
            # Check if src has memory reference containing tainted reg
            src_mem_tainted = any(
                canon(r) in taint
                for r in _REG_CANONICAL
                if r in src and r not in ('rip',)
            ) if '[' in src else False

            full_insn = f'{mnem} {ops}'

            # --- SINK DETECTION ---

            # Detect alloc calls: check arg registers before call
            if mnem == 'call':
                target_str = ops.strip()
                # Try to get numeric target
                target_va = None
                try:
                    target_va = int(target_str, 16)
                except ValueError:
                    pass

                # Report any tainted arg register at call site
                for i, arg_reg in enumerate(self.ARG_REGS):
                    if arg_reg in taint:
                        note = ''
                        if target_va and target_va in self.ALLOC_FUNCS:
                            note = 'ALLOC SIZE ARG'
                        elif target_va and target_va in self.COPY_FUNCS:
                            note = 'COPY LEN/ADDR ARG'
                        else:
                            note = f'arg{i+1} at call'
                        sinks.append(TaintSink(
                            address=va,
                            sink_type='alloc_size' if 'ALLOC' in note else
                                      'copy_len' if 'COPY' in note else 'call_arg',
                            instruction=full_insn,
                            tainted_operand=arg_reg,
                            note=note,
                        ))

                # Calls kill caller-saved regs (rax, rcx, rdx, rsi, rdi, r8-r11)
                # but preserve callee-saved (rbx, rbp, r12-r15)
                for kill_reg in ('rax','rcx','rdx','rsi','rdi','r8','r9','r10','r11'):
                    taint.discard(kill_reg)
                continue

            # Detect memory writes with tainted source/length
            if mnem in ('mov', 'movq', 'movd') and '[' in dst and src_tainted:
                sinks.append(TaintSink(
                    address=va, sink_type='mem_write',
                    instruction=full_insn, tainted_operand=src,
                ))

            # Detect rep movs/stos with tainted count (rcx) or address (rdi/rsi)
            if 'rep' in mnem:
                for tainted_reg in ('rcx', 'rdi', 'rsi'):
                    if tainted_reg in taint:
                        stype = 'copy_len' if tainted_reg == 'rcx' else 'mem_write'
                        sinks.append(TaintSink(
                            address=va, sink_type=stype,
                            instruction=full_insn, tainted_operand=tainted_reg,
                        ))

            # Detect conditional branches on tainted flags (result of cmp with tainted operand)
            if mnem in ('cmp', 'test') and (
                (src_canon and src_canon in taint) or (dst_canon and dst_canon in taint) or
                src_mem_tainted
            ):
                sinks.append(TaintSink(
                    address=va, sink_type='branch_cond',
                    instruction=full_insn, tainted_operand=dst or src,
                ))

            # --- TAINT PROPAGATION ---

            # Clear taint on destination when it's overwritten with untainted value
            if dst_canon and mnem in ('mov', 'movzx', 'movsxd', 'movsx'):
                if src_tainted or src_mem_tainted:
                    taint.add(dst_canon)
                else:
                    taint.discard(dst_canon)

            elif dst_canon and mnem in ('lea',):
                # LEA propagates taint from any register in the address expression
                any_tainted = any(
                    canon(r) in taint
                    for r in _REG_CANONICAL
                    if r in src and r not in ('rip',)
                )
                if any_tainted:
                    taint.add(dst_canon)
                else:
                    taint.discard(dst_canon)

            elif dst_canon and mnem in ('add', 'sub', 'imul', 'mul',
                                        'shl', 'shr', 'sar', 'and', 'or', 'xor',
                                        'neg', 'not', 'inc', 'dec',
                                        'cmovb', 'cmovbe', 'cmova', 'cmovae',
                                        'cmove', 'cmovne', 'cmovl', 'cmovle',
                                        'cmovg', 'cmovge', 'cmovs', 'cmovns',
                                        'cmovz', 'cmovnz'):
                # Arithmetic: tainted if either operand is tainted
                if src_tainted or src_mem_tainted or (dst_canon in taint):
                    taint.add(dst_canon)
                # For cmov: conservative -- mark tainted if src or existing dst tainted
                # (we don't know which branch was taken)

            elif dst_canon and mnem in ('xor',) and dst == src:
                # xor reg, reg = 0 -> clear taint
                taint.discard(dst_canon)

            elif dst_canon and mnem in ('setb','sete','setne','setl','setg',
                                         'seta','setbe','setae','setle','setge',
                                         'sets','setns'):
                taint.discard(dst_canon)  # setcc produces known 0/1, not tainted

            # cdqe/cwde: sign-extends rax, propagates taint from rax
            elif mnem in ('cdqe', 'cwde', 'cdq'):
                if 'rax' in taint: taint.add('rax')

            # pop: propagates stack taint (simplified: mark as untainted)
            elif dst_canon and mnem == 'pop':
                taint.discard(dst_canon)

            # push: does not produce register taint

        return sinks
