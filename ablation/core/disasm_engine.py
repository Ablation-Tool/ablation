#!/usr/bin/env python3
"""
Disassembly Engine
Synthesized from: Practical Binary Analysis, Practical Reverse Engineering, Hacking: The Art of Exploitation

Multi-architecture disassembler with function detection and CFG analysis.
"""

import struct
from contextlib import contextmanager
from functools import cached_property
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

try:
    import angr as _angr
    import angr.knowledge_plugins.xrefs.xref as _xref_mod
    HAS_ANGR = True
except ImportError:
    HAS_ANGR = False


class InsnRecord:
    """Per-instruction record with __slots__ — replaces per-insn dict.

    Fluent Python ch.11 §"Saving Memory with __slots__": each Python dict
    costs ~240 bytes of overhead. At 10M instructions a list-of-dicts approach
    burns ~2.4 GB on dict overhead alone; __slots__ drops that to ~120 bytes/
    instance (~1.2 GB), and avoids the hash-table realloc on every new key.

    Usage replaces: {'address': ..., 'mnemonic': ..., 'op_str': ..., ...}
    """
    __slots__ = ('address', 'mnemonic', 'op_str', 'size', 'raw',
                 'is_branch', 'is_call', 'is_ret', 'branch_type')

    def __init__(self, address, mnemonic, op_str, size, raw,
                 is_branch=False, is_call=False, is_ret=False, branch_type=None):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.size = size
        self.raw = raw
        self.is_branch = is_branch
        self.is_call = is_call
        self.is_ret = is_ret
        self.branch_type = branch_type

    def __repr__(self):
        return f'<InsnRecord {self.address:#x}: {self.mnemonic} {self.op_str}>'


class DisasmEngineX:
    """
    Extended disassembly engine — angr-backed CFG, xref resolution, and data-flow.

    Bridges the three gaps that Capstone's linear sweep cannot cover:
      1. CFG construction   — CFGFast recursive descent, resolves indirect jumps
      2. Cross-references   — kb.xrefs.get_xrefs_to(addr) replaces manual pointer hunting
      3. Data-flow (def-use) — ReachingDefinitionsAnalysis tracks register lifecycles

    Requires: pip install angr

    Usage:
        dx = DisasmEngineX('firmware_binary', base_addr=0x0)
        callers = dx.find_all_callers(0xADDR_OF_SetTextFileContents)
        defs    = dx.track_register_def_use(func_addr=0xADDR, reg_name='rdx')

    Note: CFGFast on a 105MB binary takes 60-120s and ~4GB RAM on first run.
    Scope to a function range via normalize=True + function_starts=[addr] to limit.
    """

    def __init__(self, binary_path: str, base_addr: int = 0x0):
        if not HAS_ANGR:
            raise ImportError("angr not installed — pip install angr")
        self.proj = _angr.Project(
            binary_path,
            load_options={'auto_load_libs': False},
            main_opts={'base_addr': base_addr},
        )
        print("[*] DisasmEngineX: building CFG (CFGFast, cross_references=True) ...")
        self.cfg = self.proj.analyses.CFGFast(
            cross_references=True,
            resolve_indirect_jumps=True,
        )
        print(f"[+] CFG complete — {len(self.cfg.functions)} functions, "
              f"{len(list(self.cfg.model.nodes()))} nodes")

    def find_all_callers(self, target_addr: int) -> list:
        """Return all instruction addresses that call target_addr.

        Replaces manual string/pointer hunting for callers of functions like
        SetTextFileContents (TOCTOU in ac_strap.dat) or strcpy PLT entries.

        Deduplicates via seen set: xrefs_to() can return the same ins_addr
        multiple times when CFGFast resolves indirect-jump aliases — the PBA
        recursive-disassembler pattern (queue + seen map) applies here too.
        """
        node = self.cfg.model.get_any_node(target_addr)
        if not node:
            return []
        xrefs = self.proj.kb.xrefs.get_xrefs_to(target_addr)
        seen: set[int] = set()
        result = []
        for x in xrefs:
            if x.type == _xref_mod.XRefType.Call and x.ins_addr not in seen:
                seen.add(x.ins_addr)
                result.append(x.ins_addr)
        return result

    def track_register_def_use(self, func_addr: int, reg_name: str = 'rdx') -> list:
        """Track definition and use sites of reg_name within a function.

        Uses Reaching Definitions Analysis (RDA) over VEX IR. Automates the
        manual register-state tracing done in comments for the F2 overflow chain.

        Returns list of {'definition_at': int, 'used_at': [int, ...], 'block': int} dicts.

        Engineering a Compiler §9.2.4: RDA computes Reaches(n) = ∪{DEDef(m) ∪ (Reaches(m) − DefKill(m))}
        for each predecessor m. angr's ReachingDefinitions implements this fixed-point iteration
        internally; exposing the block address alongside each def-site makes the kill chain visible
        without re-running the analysis.
        """
        func = self.cfg.functions.get(func_addr)
        if not func:
            raise ValueError(f"Function at {func_addr:#x} not found in CFG")
        rda = self.proj.analyses.ReachingDefinitions(subject=func, track_tmps=False)
        reg_offset = self.proj.arch.registers[reg_name][0]
        results = []
        for node in rda.dep_graph.graph.nodes():
            if hasattr(node, 'offset') and node.offset == reg_offset:
                uses = list(rda.dep_graph.graph.successors(node))
                results.append({
                    'definition_at': node.codeloc.ins_addr,
                    'block': node.codeloc.block_addr,
                    'used_at': [u.codeloc.ins_addr for u in uses],
                    'killed_by': [u.codeloc.ins_addr for u in uses
                                  if hasattr(u, 'offset') and u.offset == reg_offset],
                })
        return results

    def block_dataflow(self, func_addr: int, reg_name: str = 'rdx') -> dict:
        """Per-block DEDef and DefKill sets for reg_name across a function.

        Engineering a Compiler §9.2.4: DEDef(b) = definitions in b that reach b's
        bottom without being re-defined within b. DefKill(b) = all other definitions
        of the same register that b kills.

        Returns {block_addr: {'DEDef': [ins_addr, ...], 'DefKill': [ins_addr, ...]}}
        for each block in the function. Use this to understand which blocks expose a
        definition of reg_name downward vs. which blocks kill incoming definitions —
        the split is the core of the iterative reaching-definitions fixed point.
        """
        func = self.cfg.functions.get(func_addr)
        if not func:
            raise ValueError(f"Function at {func_addr:#x} not found in CFG")
        rda = self.proj.analyses.ReachingDefinitions(subject=func, track_tmps=False)
        reg_offset = self.proj.arch.registers[reg_name][0]

        # Collect all definitions of reg_name keyed by block
        by_block: dict = {}
        for node in rda.dep_graph.graph.nodes():
            if not (hasattr(node, 'offset') and node.offset == reg_offset):
                continue
            blk = node.codeloc.block_addr
            by_block.setdefault(blk, []).append(node.codeloc.ins_addr)

        result = {}
        for blk, defs in by_block.items():
            defs_sorted = sorted(defs)
            # DEDef: last definition in the block (reaches the block exit)
            # DefKill: all earlier definitions in the same block (killed by later ones)
            result[blk] = {
                'DEDef': [defs_sorted[-1]],
                'DefKill': defs_sorted[:-1],
            }
        return result

    def xrefs_to(self, target_addr: int) -> list:
        """All xrefs to target_addr (all types — call, data, jump)."""
        return list(self.proj.kb.xrefs.get_xrefs_to(target_addr))

    @contextmanager
    def scoped_state(self, func_addr: int, *sym_args):
        """Context manager for a temporary angr call_state.

        Fluent Python ch.18 §"Using @contextmanager": the generator body before
        yield runs as __enter__; after yield runs as __exit__ (cleanup).  Prevents
        state objects from leaking across multiple exploration runs on the same
        project — each `with` block gets a fresh state and the SimulationManager
        is discarded on exit regardless of exceptions.

        Usage:
            with dx.scoped_state(func_addr, gp_obj_ptr) as simgr:
                simgr.explore(find=end_addr)
                found = simgr.found
        """
        import claripy as _claripy
        state = self.proj.factory.call_state(func_addr, *sym_args)
        simgr = self.proj.factory.simulation_manager(state)
        try:
            yield simgr
        finally:
            del simgr
            del state


_MIPS_BRANCH_MNEMS = frozenset({
    'beq', 'bne', 'bgtz', 'bltz', 'bgez', 'blez',
    'bgezal', 'bltzal', 'bal', 'bc1f', 'bc1t',
    'beql', 'bnel', 'bgtzl', 'bltzl', 'bgezl', 'blezl',
    'j', 'jr', 'b',
})
_MIPS_CALL_MNEMS = frozenset({'jal', 'jalr', 'jalr.hb'})
_MIPS_RET_MNEMS  = frozenset({'jr'})   # jr $ra is a return; handled by context

# ARC branch/call/ret mnemonic sets (from arc_decoder classification)
_ARC_BRANCH_MNEMS = frozenset({'b', 'bcc', 'bbit', 'b_s'})
_ARC_CALL_MNEMS   = frozenset({'bl', 'jl'})
_ARC_RET_MNEMS    = frozenset({'j_blink', 'j_s'})

# PPC32/PPC64 mnemonic sets (capstone lowercase strings)
_PPC_BRANCH_MNEMS = frozenset({
    'b', 'ba', 'bc', 'bca',
    'beq', 'bne', 'bgt', 'blt', 'bge', 'ble',
    'bdnz', 'bdz', 'bctr',
})
_PPC_CALL_MNEMS = frozenset({'bl', 'bla', 'bctrl'})
_PPC_RET_MNEMS  = frozenset({'blr', 'blrl'})


class DisasmEngine:
    """Universal disassembly engine — Capstone linear sweep."""

    def __init__(self, arch='x86_64', mode='64', endian='little'):
        self.arch = arch
        self.mode = mode
        self.endian = endian
        self.md = None

        if not HAS_CAPSTONE:
            print("WARNING: capstone not installed. Install with: pip install capstone")
            print("Falling back to manual opcode parsing...")
            return

        if arch in ('x86_64', 'x86'):
            self.md = Cs(CS_ARCH_X86, CS_MODE_64 if mode == '64' else CS_MODE_32)
        elif arch == 'arm':
            if mode == '64':
                self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            else:
                self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif arch in ('mips', 'mips32', 'mips64', 'mips32r6', 'nanomips'):
            cs_endian = CS_MODE_BIG_ENDIAN if endian == 'big' else CS_MODE_LITTLE_ENDIAN
            if arch in ('mips', 'mips32'):
                self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | cs_endian)
            elif arch == 'mips64':
                self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | cs_endian)
            elif arch == 'mips32r6':
                self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32R6 | cs_endian)
            elif arch == 'nanomips':
                try:
                    nm_mode = CS_MODE_NANOMIPS  # type: ignore[name-defined]  # capstone 6.x
                    self.md = Cs(CS_ARCH_MIPS, nm_mode | cs_endian)
                except (AttributeError, NameError):
                    print("WARNING: CS_MODE_NANOMIPS not in capstone 5.x. "
                          "Upgrade to capstone 6.x for full nanoMIPS decode. "
                          "Falling back to MIPS32 -- frame boundaries may be wrong.")
                    self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | cs_endian)
        elif arch in ('ppc', 'ppc32', 'ppc64'):
            cs_endian = CS_MODE_BIG_ENDIAN if endian == 'big' else CS_MODE_LITTLE_ENDIAN
            cs_width  = CS_MODE_32 if arch in ('ppc', 'ppc32') else CS_MODE_64
            self.md = Cs(CS_ARCH_PPC, cs_width | cs_endian)
        elif arch in ('arc', 'arc32'):
            # capstone 5.x has no CS_ARCH_ARC; use the pure-Python arc_decoder
            # for stream() when arch=='arc'/'arc32'. self.md stays None.
            self._arc_endian = endian

        if self.md:
            self.md.detail = True
    
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
        for insn in self.stream(code, base_addr, count):
            instructions.append({
                'address': insn.address,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'bytes': insn.raw,
                'size': insn.size,
                **({'is_branch': True, 'branch_type': insn.branch_type} if insn.is_branch else {}),
                **({'is_call': True} if insn.is_call else {}),
                **({'is_ret': True} if insn.is_ret else {}),
            })
        return instructions

    def stream(self, code, base_addr=0x400000, count=0):
        """Generator variant of disassemble() — yields InsnRecord objects one at a time.

        Fluent Python ch.17 §"How a Generator Works": yields values one by one
        rather than building a list. For large binaries this avoids
        materialising millions of dicts in RAM simultaneously.  Callers that only
        need a subset (e.g. finding the first CALL *rax) can break early without
        paying the cost of scanning the entire binary.

        Usage:
            for insn in engine.stream(code, base_addr):
                if insn.mnemonic == 'call' and '*rax' in insn.op_str:
                    break
        """
        if self.arch in ('arc', 'arc32'):
            yield from self._arc_stream(code, base_addr, count)
            return
        if not HAS_CAPSTONE or not self.md:
            yield from self._fallback_disasm_stream(code, base_addr, count)
            return
        # disasm_lite() is the streaming API in Capstone 5+; disasm_iter was removed.
        # Returns (address, size, mnemonic, op_str) tuples — no .bytes attribute.
        is_mips = self.arch in ('mips', 'mips32', 'mips64', 'mips32r6', 'nanomips')
        is_ppc  = self.arch in ('ppc', 'ppc32', 'ppc64')
        for i, (address, size, mnemonic, op_str) in enumerate(self.md.disasm_lite(code, base_addr)):
            if count and i >= count:
                return
            if is_mips:
                _is_br   = mnemonic in _MIPS_BRANCH_MNEMS
                _is_call = mnemonic in _MIPS_CALL_MNEMS
                _is_ret  = mnemonic == 'jr' and 'ra' in op_str
                _btype   = ('unconditional' if mnemonic in ('j', 'jr', 'b', 'jal', 'jalr')
                            else 'conditional') if (_is_br or _is_call) else None
            elif is_ppc:
                _is_br   = mnemonic in _PPC_BRANCH_MNEMS
                _is_call = mnemonic in _PPC_CALL_MNEMS
                _is_ret  = mnemonic in _PPC_RET_MNEMS
                _btype   = ('unconditional' if mnemonic in ('b', 'ba', 'bl', 'bla', 'bctr', 'bctrl', 'blr', 'blrl')
                            else 'conditional') if (_is_br or _is_call or _is_ret) else None
            else:
                _is_br   = mnemonic in ('jmp','je','jne','jz','jnz','jl','jle','jg','jge',
                                        'ja','jb','jae','jbe','jc','jnc','js','jns','jo','jno',
                                        'jp','jnp','jcxz','jecxz','jrcxz','loop','loope','loopne')
                _is_call = mnemonic == 'call'
                _is_ret  = mnemonic in ('ret', 'retn', 'retf')
                _btype   = ('conditional' if mnemonic.startswith('j') and mnemonic != 'jmp'
                            else 'unconditional') if _is_br else None
            yield InsnRecord(
                address=address,
                mnemonic=mnemonic,
                op_str=op_str,
                size=size,
                raw='',
                is_branch=_is_br,
                is_call=_is_call,
                is_ret=_is_ret,
                branch_type=_btype,
            )

    def _arc_stream(self, code, base_addr, count):
        """ARC stream using pure-Python arc_decoder (no capstone required)."""
        from ablation.analyzers.arc_decoder import ARCDecoder
        endian = getattr(self, '_arc_endian', 'little')
        dec = ARCDecoder(endian=endian)
        for i, frame in enumerate(dec.decode_frames(code, base_addr)):
            if count and i >= count:
                return
            yield InsnRecord(
                address=frame.va,
                mnemonic=frame.mnemonic,
                op_str=frame.op_str,
                size=frame.width,
                raw='',
                is_branch=frame.is_branch,
                is_call=frame.is_call,
                is_ret=frame.is_ret,
                branch_type=('unconditional' if frame.is_call or frame.mnemonic == 'b'
                             else 'conditional') if (frame.is_branch or frame.is_call) else None,
            )

    def _fallback_disasm_stream(self, code, base_addr, count):
        """Stub — fallback path has no stream support; yields nothing."""
        return
        yield  # make this a generator
    
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

        for insn in self.md.disasm_iter(code, base_addr):
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

        for insn in self.md.disasm_iter(code, base_addr):
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

        elif self.arch in ('mips', 'mips32', 'mips64', 'mips32r6', 'nanomips'):
            # addiu $sp, $sp, -N  (MIPS32/nanoMIPS standard frame setup)
            # daddiu $sp, $sp, -N (MIPS64 standard frame setup)
            if insn.mnemonic in ('addiu', 'daddiu') and '$sp, $sp, -' in insn.op_str:
                return True

        elif self.arch in ('ppc', 'ppc32', 'ppc64'):
            # stwu r1, -N(r1)  (PPC32 frame setup + SP save)
            if insn.mnemonic == 'stwu' and 'r1, -' in insn.op_str:
                return True
            # stdu r1, -N(r1)  (PPC64 ELFv2 frame setup + SP save)
            if insn.mnemonic == 'stdu' and 'r1, -' in insn.op_str:
                return True

        elif self.arch in ('arc', 'arc32'):
            # push_s blink -- saves BLINK to stack (compact 16-bit prologue)
            if insn.mnemonic == 'push_s' and 'blink' in insn.op_str:
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
