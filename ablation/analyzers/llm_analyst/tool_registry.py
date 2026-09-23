"""
tool_registry.py — Tool definitions and dispatch for the LLM analyst.

Tools are the API surface Claude uses during a ReAct analysis loop.
Each tool returns a plain string — either formatted text or JSON —
because all results go directly into the LLM context window.

Design rules:
  - Orthogonal: one concern per tool, no overlap
  - Lazy: angr Project and CFGFast are built only when first needed
  - Safe: every tool catches exceptions and returns an error string
  - Token-aware: output is trimmed to prevent context blowout
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

# ─────────────────────────────────────────────────────────────────────────────
# Tool schema — fed directly to anthropic.messages.create(tools=TOOL_SCHEMAS)
# ─────────────────────────────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        'name': 'get_disassembly',
        'description': (
            'Disassemble instructions at a virtual address. '
            'Returns offset-relative mnemonics (no absolute VAs). '
            'Use this first to understand what a function does.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {
                'addr':    {'type': 'integer', 'description': 'Virtual address to start at'},
                'n_insns': {'type': 'integer', 'description': 'Instructions to show (default 30, max 80)'},
            },
            'required': ['addr'],
        },
    },
    {
        'name': 'get_cfg',
        'description': (
            'Get the control flow graph of a function: basic block addresses, '
            'instruction counts, and edges. '
            'Use to understand branching structure before reading full disassembly.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {
                'func_addr': {'type': 'integer', 'description': 'Function entry VA'},
            },
            'required': ['func_addr'],
        },
    },
    {
        'name': 'get_xrefs',
        'description': (
            'Get cross-references to or from an address. '
            '"to" = callers of this address; "from" = addresses this function calls.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {
                'addr':      {'type': 'integer'},
                'direction': {'type': 'string', 'enum': ['to', 'from'],
                              'description': '"to" = who calls this; "from" = what this calls'},
            },
            'required': ['addr', 'direction'],
        },
    },
    {
        'name': 'get_strings',
        'description': (
            'Get string literals referenced by a function. '
            'Returns the string content, not the virtual addresses. '
            'Strongest signal for function naming and role classification.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {
                'func_addr': {'type': 'integer'},
            },
            'required': ['func_addr'],
        },
    },
    {
        'name': 'get_imports',
        'description': (
            'Get external/PLT calls made by a function — libc, libssl, etc. '
            'Returns symbol names and addresses. '
            'Use to understand what library functions are involved.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {
                'func_addr': {'type': 'integer'},
            },
            'required': ['func_addr'],
        },
    },
    {
        'name': 'query_func_db',
        'description': (
            'Search the function identity database (func_id_db) for known functions. '
            'Searches by name or role. Returns confirmed RE findings from prior work. '
            'Use to check if this function or a similar one has been identified before.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {
                'name': {'type': 'string', 'description': 'Function name to search for'},
                'role': {'type': 'string',
                         'description': 'Role filter: RADIUS_ATTR_HANDLER, FILE_IO, CRYPTO_HPKE, etc.'},
                'k':    {'type': 'integer', 'description': 'Max results (default 5)'},
            },
        },
    },
    {
        'name': 'done',
        'description': (
            'Signal that analysis is complete. '
            'Call this when you have enough information to characterize the function. '
            'This is the only way to end the analysis loop.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {
                'name':       {'type': 'string',  'description': 'Proposed function name (snake_case)'},
                'role':       {'type': 'string',  'description': 'Role from ablation taxonomy'},
                'confidence': {'type': 'number',  'description': 'Confidence 0.0–1.0'},
                'rationale':  {'type': 'string',  'description': 'Why this name/role was chosen'},
                'vuln_notes': {'type': 'string',
                               'description': 'Vulnerability observations, if any (empty string if none)'},
            },
            'required': ['name', 'confidence', 'rationale'],
        },
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

class ToolRegistry:
    """
    Wraps ablation's binary analysis capabilities as callable tools.
    All public methods return strings for direct injection into LLM context.
    """

    # Maximum output length per tool call — prevents context blowout
    _MAX_DISASM_LINES = 80
    _MAX_RESULT_CHARS = 4000

    def __init__(self, binary_path: str, func_db=None):
        """
        binary_path: path to the ELF binary to analyze
        func_db: optional FuncDB instance for query_func_db tool
        """
        self._binary_path = str(Path(binary_path).expanduser())
        self._func_db = func_db
        self._proj   = None   # angr.Project — lazy
        self._cfg    = None   # CFGFast — lazy, expensive

    # ── lazy properties ──────────────────────────────────────────────────────

    @property
    def proj(self):
        if self._proj is None:
            import angr
            self._proj = angr.Project(
                self._binary_path,
                auto_load_libs=False,
                load_options={'main_opts': {'base_addr': 0}},
            )
        return self._proj

    @property
    def cfg(self):
        """Build CFGFast once; subsequent calls return the cached graph."""
        if self._cfg is None:
            self._cfg = self.proj.analyses.CFGFast(
                normalize=True,
                resolve_indirect_jumps=True,
                collect_data_references=True,
            )
        return self._cfg

    # ── dispatch ─────────────────────────────────────────────────────────────

    def dispatch(self, tool_name: str, args: dict) -> str:
        """
        Route a tool call from the agent loop to the correct handler.
        Returns a plain string for injection into the LLM message list.
        'done' is NOT handled here — the agent loop owns that terminal case.
        """
        handlers = {
            'get_disassembly': self._get_disassembly,
            'get_cfg':         self._get_cfg,
            'get_xrefs':       self._get_xrefs,
            'get_strings':     self._get_strings,
            'get_imports':     self._get_imports,
            'query_func_db':   self._query_func_db,
        }
        handler = handlers.get(tool_name)
        if handler is None:
            return json.dumps({'error': f'unknown tool: {tool_name}'})
        try:
            return handler(**args)
        except Exception as exc:
            return json.dumps({'error': str(exc), 'tool': tool_name})

    # ── tools ────────────────────────────────────────────────────────────────

    def _get_disassembly(self, addr: int, n_insns: int = 30) -> str:
        n_insns = min(n_insns, self._MAX_DISASM_LINES)
        try:
            block = self.proj.factory.block(addr, num_inst=n_insns)
            lines = []
            for insn in block.capstone.insns:
                rel = insn.address - addr
                lines.append(f'+{rel:04x}  {insn.mnemonic:<8} {insn.op_str}')
            return '\n'.join(lines) if lines else '(no instructions decoded at this address)'
        except Exception as exc:
            return f'disassembly error at {addr:#x}: {exc}'

    def _get_cfg(self, func_addr: int) -> str:
        func = self.cfg.kb.functions.get(func_addr)
        if func is None:
            return json.dumps({'error': f'no function at {func_addr:#x} in CFG'})

        blocks = []
        for bb in sorted(func.blocks, key=lambda b: b.addr):
            try:
                mnems = [f'{i.mnemonic} {i.op_str}'.strip()
                         for i in bb.capstone.insns]
            except Exception:
                mnems = []
            blocks.append({
                'addr':   f'{bb.addr:#x}',
                'n_insns': len(mnems),
                'mnemonics': mnems,
            })

        edges = [
            {'src': f'{s.addr:#x}', 'dst': f'{d.addr:#x}'}
            for s, d in func.graph.edges()
        ]

        result = {
            'func_addr': f'{func_addr:#x}',
            'name':      func.name,
            'n_blocks':  len(blocks),
            'n_edges':   len(edges),
            'cyclomatic': len(edges) - len(blocks) + 2,
            'blocks':    blocks,
            'edges':     edges,
        }
        return self._trim(json.dumps(result, indent=2))

    def _get_xrefs(self, addr: int, direction: str = 'to') -> str:
        node = self.cfg.get_any_node(addr, anyaddr=True)
        if node is None:
            return json.dumps({'error': f'no CFG node at {addr:#x}', 'results': []})

        if direction == 'to':
            neighbors = self.cfg.get_predecessors(node)
            label = 'callers'
        else:
            neighbors = self.cfg.get_successors(node)
            label = 'callees'

        addrs = [f'{n.addr:#x}' for n in neighbors]
        # Annotate with known function names where available
        annotated = []
        for n in neighbors:
            func = self.cfg.kb.functions.get(n.addr)
            name = func.name if func else ''
            annotated.append({'addr': f'{n.addr:#x}', 'name': name})

        return json.dumps({label: annotated})

    def _get_strings(self, func_addr: int) -> str:
        func = self.cfg.kb.functions.get(func_addr)
        if func is None:
            return json.dumps({'error': f'no function at {func_addr:#x}'})

        strings = []

        # angr collects data references during CFGFast(collect_data_references=True)
        # cfg.kb.memory_data maps VA -> MemoryData with .sort and .content
        func_block_addrs = {bb.addr for bb in func.blocks}

        for data_addr, mem_data in self.cfg.kb.memory_data.items():
            if getattr(mem_data, 'sort', None) != 'string':
                continue
            content = getattr(mem_data, 'content', None)
            if content is None:
                continue
            try:
                s = content.decode('utf-8', errors='replace').rstrip('\x00')
            except Exception:
                continue
            if len(s) < 3:
                continue

            # Check if any block in this function references this data address
            for bb_addr in func_block_addrs:
                node = self.cfg.get_any_node(bb_addr, anyaddr=True)
                if node is None:
                    continue
                refs = getattr(node, 'data_references', None) or []
                if data_addr in refs:
                    strings.append(s)
                    break

        # Fallback: scan immediates in disassembly for known string VAs
        if not strings:
            strings = self._scan_string_immediates(func)

        return json.dumps({'strings': list(dict.fromkeys(strings))})  # dedup, preserve order

    def _scan_string_immediates(self, func) -> list:
        """Fallback string extraction: scan instruction operands for data-section VAs."""
        # Build a VA -> string map from memory_data
        str_map = {}
        for data_addr, mem_data in self.cfg.kb.memory_data.items():
            if getattr(mem_data, 'sort', None) == 'string':
                content = getattr(mem_data, 'content', None)
                if content:
                    try:
                        str_map[data_addr] = content.decode('utf-8', errors='replace').rstrip('\x00')
                    except Exception:
                        pass

        found = []
        for bb in func.blocks:
            try:
                for insn in bb.capstone.insns:
                    op = insn.op_str
                    # Scan for hex immediates that match known string VAs
                    for va, s in str_map.items():
                        if f'{va:#x}' in op or f'0x{va:x}' in op:
                            if len(s) >= 3:
                                found.append(s)
            except Exception:
                pass
        return found

    def _get_imports(self, func_addr: int) -> str:
        func = self.cfg.kb.functions.get(func_addr)
        if func is None:
            return json.dumps({'error': f'no function at {func_addr:#x}'})

        imports = []
        for callee_addr in func.functions_called():
            callee = self.cfg.kb.functions.get(callee_addr)
            if callee is None:
                continue
            if callee.is_plt or callee.is_simprocedure:
                imports.append({
                    'addr': f'{callee_addr:#x}',
                    'name': callee.name,
                    'plt':  callee.is_plt,
                })

        return json.dumps({'imports': imports})

    def _query_func_db(self, name: str = '', role: str = '', k: int = 5) -> str:
        if self._func_db is None:
            return json.dumps({'error': 'no func_db configured'})

        if role:
            results = self._func_db.match_by_role(role)[:k]
        elif name:
            results = self._func_db.match_by_name(name)[:k]
        else:
            return json.dumps({'error': 'provide name or role'})

        # Trim to fields relevant for LLM context
        trimmed = [
            {
                'name':       r.get('name', ''),
                'role':       r.get('role', ''),
                'confidence': r.get('confidence', ''),
                'product':    r.get('product', ''),
                'version':    r.get('version', ''),
                'notes':      (r.get('notes', '') or '')[:200],
            }
            for r in results
        ]
        return json.dumps({'results': trimmed}, indent=2)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _trim(self, s: str) -> str:
        if len(s) <= self._MAX_RESULT_CHARS:
            return s
        return s[:self._MAX_RESULT_CHARS] + f'\n... [truncated at {self._MAX_RESULT_CHARS} chars]'
