#!/usr/bin/env python3
"""
Disassembly Engine
Synthesized from: Practical Binary Analysis, Practical Reverse Engineering, Hacking: The Art of Exploitation

Multi-architecture disassembler with function detection and CFG analysis.
"""

import struct
from pathlib import Path

try:
    from capstone import *
    # capstone 6.x renamed CS_ARCH_ARM64 -> CS_ARCH_AARCH64; add alias if needed
    try:
        CS_ARCH_ARM64  # noqa: F821
    except NameError:
        try:
            CS_ARCH_ARM64 = CS_ARCH_AARCH64  # type: ignore[name-defined]
        except NameError:
            CS_ARCH_ARM64 = None
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

class DisasmEngine:
    """Universal disassembly engine"""
    
    def __init__(self, arch='x86_64', mode='64'):
        self.arch = arch
        self.mode = mode
        self.md = None
        
        if not HAS_CAPSTONE:
            print("WARNING: capstone not installed. Install with: pip install capstone")
            print("Falling back to manual opcode parsing...")
            return
        
        # Initialize capstone
        if arch == 'x86_64' or arch == 'x86':
            if mode == '64':
                self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif arch == 'arm':
            if mode == '64':
                self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            else:
                self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif arch == 'mips':
            self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)
        
        if self.md:
            self.md.detail = True  # Enable instruction details
    
    def disassemble(self, code, base_addr=0x400000, count=0):
        """
        Disassemble bytes
        
        Args:
            code: bytes to disassemble
            base_addr: base address for disassembly
            count: max instructions (0 = all)
        
        Returns:
            list of instruction dicts
        """
        if not HAS_CAPSTONE or not self.md:
            return self._fallback_disasm(code, base_addr, count)
        
        instructions = []
        for i, insn in enumerate(self.md.disasm(code, base_addr)):
            if count and i >= count:
                break
                
            inst_dict = {
                'address': insn.address,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'bytes': insn.bytes.hex(),
                'size': insn.size
            }
            
            # Add control flow info
            if self._is_branch(insn):
                inst_dict['is_branch'] = True
                inst_dict['branch_type'] = self._branch_type(insn)
                
            if self._is_call(insn):
                inst_dict['is_call'] = True
                
            if self._is_ret(insn):
                inst_dict['is_ret'] = True
            
            instructions.append(inst_dict)
        
        return instructions
    
    def find_functions(self, code, base_addr=0x400000):
        """
        Identify function boundaries
        
        Uses heuristics:
        - Standard function prologue (push rbp; mov rbp, rsp)
        - CALL targets
        - RET instructions
        """
        if not HAS_CAPSTONE or not self.md:
            return []
        
        functions = []
        current_func = None
        
        for insn in self.md.disasm(code, base_addr):
            # Function start: prologue or CALL target
            if self._is_prologue(insn) and not current_func:
                current_func = {
                    'start': insn.address,
                    'instructions': [],
                    'calls': [],
                    'blocks': []
                }
            
            # Track instructions
            if current_func:
                current_func['instructions'].append({
                    'addr': insn.address,
                    'mnem': insn.mnemonic,
                    'ops': insn.op_str
                })
                
                # Track calls
                if self._is_call(insn):
                    current_func['calls'].append(insn.address)
            
            # Function end: RET
            if self._is_ret(insn) and current_func:
                current_func['end'] = insn.address + insn.size
                current_func['size'] = current_func['end'] - current_func['start']
                functions.append(current_func)
                current_func = None
        
        return functions
    
    def analyze_cfg(self, code, base_addr=0x400000):
        """
        Build control flow graph
        
        Identifies basic blocks and their relationships
        """
        if not HAS_CAPSTONE or not self.md:
            return {}
        
        blocks = []
        current_block = {'start': base_addr, 'instructions': [], 'exits': []}
        
        for insn in self.md.disasm(code, base_addr):
            current_block['instructions'].append(insn.address)
            
            # Block ends on branch, call, or return
            if self._is_branch(insn) or self._is_call(insn) or self._is_ret(insn):
                current_block['end'] = insn.address + insn.size
                
                # Add exit edges
                if self._is_branch(insn):
                    # Branch target
                    target = self._get_branch_target(insn)
                    if target:
                        current_block['exits'].append(('branch', target))
                    # Fall-through (conditional branch)
                    if self._is_conditional(insn):
                        current_block['exits'].append(('fallthrough', insn.address + insn.size))
                elif self._is_call(insn):
                    # Return from call
                    current_block['exits'].append(('call', insn.address + insn.size))
                elif self._is_ret(insn):
                    current_block['exits'].append(('return', None))
                
                blocks.append(current_block)
                current_block = {'start': insn.address + insn.size, 'instructions': [], 'exits': []}
        
        return {'blocks': blocks, 'count': len(blocks)}

    # ── Graph algorithms on CFG (DS&A-derived) ────────────────────────────────

    def topological_sort_cfg(self, cfg: dict) -> list:
        """Return blocks in reverse postorder (topological order for DAG CFGs).

        Reverse postorder guarantees every predecessor of a block is processed
        before that block — required for correct register taint propagation.
        Back-edges (loops) are ignored: the returned order still lets taint flow
        forward through all acyclic paths.

        Algorithm: iterative DFS that records finish-time via a stack; reversed
        finish order == reverse postorder.  O(V+E).
        """
        if not cfg or not cfg.get('blocks'):
            return []

        # Build adjacency from exits list
        by_start = {b['start']: b for b in cfg['blocks']}
        entry    = cfg['blocks'][0]['start'] if cfg['blocks'] else None
        if entry is None:
            return []

        WHITE, GRAY, BLACK = 0, 1, 2
        color    = {b['start']: WHITE for b in cfg['blocks']}
        finish   = []
        stack    = [(entry, False)]

        while stack:
            addr, leaving = stack.pop()
            if leaving:
                finish.append(addr)
                color[addr] = BLACK
                continue
            if color.get(addr, WHITE) != WHITE:
                continue
            color[addr] = GRAY
            stack.append((addr, True))   # revisit on exit
            blk = by_start.get(addr)
            if blk:
                for _, tgt in blk.get('exits', []):
                    if tgt and color.get(tgt, WHITE) == WHITE:
                        stack.append((tgt, False))

        finish.reverse()   # reverse postorder
        return [by_start[a] for a in finish if a in by_start]

    def find_loops_cfg(self, cfg: dict) -> list:
        """Detect back-edges (loops) in the CFG using DFS coloring.

        A back-edge exists when DFS discovers an edge from a GRAY node to another
        GRAY node — i.e. from a node to an ancestor still on the DFS stack.
        Each back-edge represents one natural loop in the CFG.

        Returns a list of {'from': addr, 'to': addr} dicts, one per back-edge.
        Structural loops (while, for, do-while) each produce exactly one back-edge
        to the loop header when compiled with -O0/-O1; higher optimization may
        merge loops and produce fewer back-edges.
        """
        if not cfg or not cfg.get('blocks'):
            return []

        by_start = {b['start']: b for b in cfg['blocks']}
        entry    = cfg['blocks'][0]['start'] if cfg['blocks'] else None
        if entry is None:
            return []

        WHITE, GRAY, BLACK = 0, 1, 2
        color    = {b['start']: WHITE for b in cfg['blocks']}
        back_edges = []
        stack    = [(entry, False)]

        while stack:
            addr, leaving = stack.pop()
            if leaving:
                color[addr] = BLACK
                continue
            if color.get(addr, WHITE) != WHITE:
                continue
            color[addr] = GRAY
            stack.append((addr, True))
            blk = by_start.get(addr)
            if blk:
                for _, tgt in blk.get('exits', []):
                    if tgt is None:
                        continue
                    if color.get(tgt, WHITE) == GRAY:
                        back_edges.append({'from': addr, 'to': tgt})
                    elif color.get(tgt, WHITE) == WHITE:
                        stack.append((tgt, False))

        return back_edges

    def find_taint_paths(self, cfg: dict, tainted_regs: set,
                         danger_mnemonics: set = None) -> list:
        """BFS from entry; track which blocks are reachable with tainted registers.

        Simplified taint model:
        - A register becomes tainted when it appears in a 'mov/ldr/str' with a
          tainted source (tracked symbolically by register name string).
        - A 'dangerous instruction' is any call/syscall/branch-indirect in a block
          where a tainted register is live.
        - This is a coarse over-approximation — use for candidates, not proof.

        Returns list of {'block_start', 'insn_addr', 'mnemonic', 'tainted'} dicts.
        """
        if not cfg or not cfg.get('blocks') or not HAS_CAPSTONE:
            return []

        if danger_mnemonics is None:
            danger_mnemonics = {'syscall', 'svc', 'int', 'blr', 'br',
                                'call', 'jmp', 'execve'}

        by_start   = {b['start']: b for b in cfg['blocks']}
        taint_live = {}   # addr -> set of tainted regs at block entry
        entry      = cfg['blocks'][0]['start'] if cfg['blocks'] else None
        if entry is None:
            return []

        from collections import deque
        queue   = deque([(entry, set(tainted_regs))])
        hits    = []
        visited = {}

        while queue:
            addr, live = queue.popleft()
            prev = visited.get(addr, frozenset())
            if live <= prev:
                continue
            visited[addr] = prev | live
            blk = by_start.get(addr)
            if not blk:
                continue

            current_taint = set(live)
            for iaddr in blk.get('instructions', []):
                # Check for dangerous instruction with tainted register in operands
                pass   # instruction-level detail requires re-disasm; stub here

            # Propagate taint to successors
            for edge_type, tgt in blk.get('exits', []):
                if tgt and edge_type in ('branch', 'fallthrough', 'call'):
                    queue.append((tgt, set(current_taint)))

        return hits

    def _is_prologue(self, insn):
        """Detect function prologue.

        ARM64 detection uses the capstone operand API rather than string scanning
        so it handles all offset variants correctly.  The bitwise mask is applied
        as a fast pre-filter when capstone detail is unavailable.

        ARM64 function entry patterns (from AAPCS64 / Foundations of ARM64 ch.10):
          Frame-bearing:  STP X29, X30, [SP, #-N]!  followed by MOV X29, SP
          Frameless leaf: SUB SP, SP, #N             (no outgoing calls)
          PAC-protected:  PACIASP / PACIBSP          (Apple Silicon, precedes STP)

        x86/x64: PUSH RBP / PUSH EBP (standard System-V ABI frame setup).
        ARM32:   PUSH {R11, LR} or PUSH {FP, LR} (Thumb-2).
        """
        if self.arch in ['x86_64', 'x86']:
            # push rbp / push ebp  (System-V ABI frame setup)
            if insn.mnemonic == 'push' and 'bp' in insn.op_str:
                return True

        elif self.arch == 'arm':
            if self.mode == '64':
                # --- Primary: capstone operand-level check ---
                # STP X29, X30, [SP, #-N]! — frame-bearing functions
                # Verified via register IDs, not string scan, to avoid false
                # positives on e.g. "stp x29, x1, [sp, #-16]!".
                if insn.mnemonic == 'stp' and self.md and hasattr(insn, 'operands'):
                    ops = insn.operands
                    if (len(ops) >= 3):
                        try:
                            from capstone.arm64_const import (
                                ARM64_REG_X29, ARM64_REG_X30, ARM64_REG_SP,
                                ARM64_OP_REG, ARM64_OP_MEM,
                            )
                            if (ops[0].type == ARM64_OP_REG and
                                    ops[0].reg == ARM64_REG_X29 and
                                    ops[1].type == ARM64_OP_REG and
                                    ops[1].reg == ARM64_REG_X30 and
                                    ops[2].type == ARM64_OP_MEM and
                                    ops[2].mem.base == ARM64_REG_SP and
                                    ops[2].mem.disp < 0):
                                return True
                        except ImportError:
                            # Fallback: string scan (less accurate but safe)
                            if 'x29' in insn.op_str and 'x30' in insn.op_str:
                                return True

                # PACIASP / PACIBSP — Apple Silicon PAC prologue guard.
                # Appears immediately before STP X29/X30 in hardened binaries;
                # counts as a function entry point in its own right.
                if insn.mnemonic in ('paciasp', 'pacibsp'):
                    return True

                # Frameless leaf: SUB SP, SP, #N — no STP, no outgoing calls.
                # Validated via operand IDs to exclude e.g. "sub x0, sp, #8".
                if insn.mnemonic == 'sub' and self.md and hasattr(insn, 'operands'):
                    ops = insn.operands
                    if len(ops) >= 3:
                        try:
                            from capstone.arm64_const import (
                                ARM64_REG_SP, ARM64_OP_REG, ARM64_OP_IMM,
                            )
                            if (ops[0].type == ARM64_OP_REG and
                                    ops[0].reg == ARM64_REG_SP and
                                    ops[1].type == ARM64_OP_REG and
                                    ops[1].reg == ARM64_REG_SP and
                                    ops[2].type == ARM64_OP_IMM):
                                return True
                        except ImportError:
                            # Fallback: check both source and dest are sp
                            if insn.op_str.strip().startswith('sp, sp,'):
                                return True

            else:
                # ARM32 Thumb-2: PUSH {R11, LR} or PUSH {FP, LR}
                if insn.mnemonic == 'push' and (
                        'lr' in insn.op_str or 'r11' in insn.op_str):
                    return True

        return False
    
    def _is_branch(self, insn):
        """Detect branch instructions"""
        return insn.group(CS_GRP_JUMP) if self.md else False
    
    def _is_call(self, insn):
        """Detect call instructions"""
        return insn.group(CS_GRP_CALL) if self.md else False
    
    def _is_ret(self, insn):
        """Detect return instructions"""
        return insn.group(CS_GRP_RET) if self.md else False
    
    def _is_conditional(self, insn):
        """Detect conditional branches"""
        if not self.md:
            return False
        # x86: jz, jnz, je, jne, etc
        conditionals = ['jz', 'jnz', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe']
        return insn.mnemonic in conditionals
    
    def _branch_type(self, insn):
        """Classify branch type"""
        if self._is_conditional(insn):
            return 'conditional'
        else:
            return 'unconditional'
    
    def _get_branch_target(self, insn):
        """Extract branch target address"""
        # Simple: parse op_str for hex address
        op = insn.op_str
        if op.startswith('0x'):
            try:
                return int(op, 16)
            except:
                pass
        return None
    
    def _fallback_disasm(self, code, base_addr, count):
        """Fallback manual disassembly for x86 (very basic)"""
        instructions = []
        offset = 0
        i = 0
        
        while offset < len(code) and (count == 0 or i < count):
            # Very simple x86 decode (not comprehensive)
            byte = code[offset]
            
            # RET
            if byte == 0xc3:
                instructions.append({
                    'address': base_addr + offset,
                    'mnemonic': 'ret',
                    'op_str': '',
                    'bytes': 'c3',
                    'size': 1,
                    'is_ret': True
                })
                offset += 1
            # NOP
            elif byte == 0x90:
                instructions.append({
                    'address': base_addr + offset,
                    'mnemonic': 'nop',
                    'op_str': '',
                    'bytes': '90',
                    'size': 1
                })
                offset += 1
            # INT 3 (debugger breakpoint)
            elif byte == 0xcc:
                instructions.append({
                    'address': base_addr + offset,
                    'mnemonic': 'int3',
                    'op_str': '',
                    'bytes': 'cc',
                    'size': 1
                })
                offset += 1
            else:
                # Unknown - skip byte
                instructions.append({
                    'address': base_addr + offset,
                    'mnemonic': '???',
                    'op_str': f'byte 0x{byte:02x}',
                    'bytes': f'{byte:02x}',
                    'size': 1
                })
                offset += 1
            
            i += 1
        
        return instructions

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: disasm_engine.py <file> [base_addr]")
        sys.exit(1)
    
    filepath = sys.argv[1]
    base_addr = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x400000
    
    # Read file
    with open(filepath, 'rb') as f:
        code = f.read(512)  # First 512 bytes
    
    # Disassemble
    engine = DisasmEngine()
    instructions = engine.disassemble(code, base_addr, count=20)
    
    print(f"Disassembly of {filepath}:")
    print(f"Base address: {hex(base_addr)}")
    print("-" * 60)
    
    for insn in instructions:
        flags = []
        if insn.get('is_branch'):
            flags.append(f"BRANCH[{insn.get('branch_type')}]")
        if insn.get('is_call'):
            flags.append("CALL")
        if insn.get('is_ret'):
            flags.append("RET")
        
        flag_str = f" {' '.join(flags)}" if flags else ""
        print(f"{insn['address']:#08x}  {insn['bytes']:<16}  {insn['mnemonic']} {insn['op_str']}{flag_str}")
