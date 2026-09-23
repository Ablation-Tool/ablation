"""
tasks/struct_reconstructor.py — Infer struct layout from function memory access patterns.

Pre-processes disassembly before the LLM call:
  1. Scan instructions for [base_reg + offset] memory operands
  2. Classify access type (read / write / lea) and width (byte/word/dword/qword)
  3. Group by base register — each group is a candidate struct pointer
  4. Sort by offset — produces a candidate field list
  5. Feed the structured tuples to the LLM via AgentLoop

This is the "offset clustering" pattern from the O'Reilly RAG research:
feeding (offset, size, access_type) tuples beats raw asm for struct inference
because the model doesn't have to parse x86-64 addressing modes itself.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional


@dataclass
class FieldAccess:
    offset: int
    width:  int          # bytes: 1, 2, 4, 8
    kind:   str          # 'read', 'write', 'lea'
    reg:    str          # destination / source register
    insn:   str          # original instruction string


@dataclass
class CandidateStruct:
    base_reg: str
    fields:   list[FieldAccess]   # sorted by offset

    def to_prompt_block(self) -> str:
        lines = [f'base register: {self.base_reg}']
        for fa in self.fields:
            lines.append(
                f'  +{fa.offset:#06x}  {fa.kind:<6}  {fa.width}B  [{fa.insn.strip()}]'
            )
        return '\n'.join(lines)


# ── Capstone-based access scanner ─────────────────────────────────────────────

# Maps capstone size encoding to byte count
_SIZE_MAP = {
    'byte ptr':  1,
    'word ptr':  2,
    'dword ptr': 4,
    'qword ptr': 8,
}

# Regex to extract [reg + offset] or [reg - offset] patterns from op_str
_MEM_PATTERN = re.compile(
    r'(?P<size>byte ptr|word ptr|dword ptr|qword ptr)?\s*'
    r'\[(?P<base>[a-z0-9]+)\s*(?P<sign>[+-])\s*(?P<offset>0x[0-9a-f]+|\d+)\]',
    re.IGNORECASE
)


def scan_struct_accesses(
    disasm_text: str,
    min_offset:  int = 0,
    max_offset:  int = 0x2000,
) -> dict[str, list[FieldAccess]]:
    """
    Parse the output of get_disassembly() and extract memory access patterns.

    Returns: {base_register: [FieldAccess, ...]} sorted by offset.
    Filters out accesses to stack (rsp/rbp-relative) to focus on heap struct pointers.
    """
    accesses: dict[str, list[FieldAccess]] = defaultdict(list)

    for line in disasm_text.splitlines():
        # Strip leading offset prefix: '+0000  mnemonic  op_str'
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        mnemonic = parts[1].lower()
        op_str   = parts[2]

        # Classify access kind
        if mnemonic == 'lea':
            kind = 'lea'
        elif mnemonic.startswith('mov') and '[' in op_str:
            # Write if dest is memory, read if src is memory
            dest, _, src = op_str.partition(',')
            kind = 'write' if '[' in dest else 'read'
        elif mnemonic in ('cmp', 'test') and '[' in op_str:
            kind = 'read'
        elif mnemonic in ('add', 'sub', 'or', 'and', 'xor') and '[' in op_str:
            dest, _, _ = op_str.partition(',')
            kind = 'write' if '[' in dest else 'read'
        else:
            continue

        match = _MEM_PATTERN.search(op_str)
        if not match:
            continue

        base   = match.group('base').lower()
        sign   = match.group('sign')
        raw_off = match.group('offset')
        size_kw = (match.group('size') or '').lower()

        # Skip stack-relative accesses
        if base in ('rsp', 'rbp', 'esp', 'ebp'):
            continue

        try:
            offset = int(raw_off, 16) if raw_off.startswith('0x') else int(raw_off)
        except ValueError:
            continue

        if sign == '-':
            offset = -offset

        if not (min_offset <= offset <= max_offset):
            continue

        width = _SIZE_MAP.get(size_kw, 8)  # default qword for unlabeled

        # Get the destination register for the access
        dest_reg = op_str.split(',')[0].strip().split()[-1] if ',' in op_str else ''

        accesses[base].append(FieldAccess(
            offset=offset, width=width, kind=kind,
            reg=dest_reg, insn=f'{mnemonic} {op_str}'
        ))

    # Sort each register's accesses by offset and deduplicate
    result: dict[str, list[FieldAccess]] = {}
    for reg, fas in accesses.items():
        seen_offsets = set()
        deduped = []
        for fa in sorted(fas, key=lambda f: f.offset):
            if fa.offset not in seen_offsets:
                seen_offsets.add(fa.offset)
                deduped.append(fa)
        if len(deduped) >= 2:  # at least 2 accesses to be interesting
            result[reg] = deduped

    return result


def build_struct_prompt(
    func_addr:   int,
    disasm_text: str,
    func_name:   str = '',
) -> str:
    """
    Extract struct access patterns from disassembly and format a prompt block.
    Used by AgentLoop when running 'struct_reconstruct' task.
    """
    accesses = scan_struct_accesses(disasm_text)
    if not accesses:
        return (
            f'No struct-like memory access patterns found in function at {func_addr:#x}.\n'
            'The function may not use struct pointers, or the disassembly window is too small.'
        )

    lines = [
        f'[STRUCT ACCESS PATTERNS in function {func_name or hex(func_addr)}]',
        'Each line: +offset  kind  width  [instruction]',
        '',
    ]
    for base_reg, fas in sorted(accesses.items()):
        struct = CandidateStruct(base_reg=base_reg, fields=fas)
        lines.append(struct.to_prompt_block())
        lines.append('')

    lines.append(
        '[TASK]\n'
        'Based on the access patterns above, infer the struct layout for each base register.\n'
        'Output one struct per base register as: offset:width_bytes:field_name triples.\n'
        'Name fields based on their size and access pattern '
        '(e.g., ptr=8B write=next_ptr, 4B read at low offset=type_field).\n'
        'Call done() with the struct layout description in rationale.'
    )
    return '\n'.join(lines)


def run_struct_reconstruction(
    agent_loop,
    func_addr:   int,
    disasm_text: str,
    func_name:   str = '',
):
    """
    Convenience wrapper: pre-process disassembly and run struct reconstruction via AgentLoop.
    """
    from ..agent_loop import AnalysisResult

    prompt = build_struct_prompt(func_addr, disasm_text, func_name)
    if 'No struct-like' in prompt:
        # Short-circuit: no patterns found, don't waste a Claude call
        return AnalysisResult(
            func_addr=func_addr,
            name=func_name or f'sub_{func_addr:#x}',
            role='UNKNOWN',
            confidence=0.0,
            rationale='No struct access patterns found in disassembly window.',
            vuln_notes='',
            tool_calls=0,
            finished=False,
            model=agent_loop._model,
            task='struct_reconstruct',
        )

    # Inject the pre-processed prompt as the initial user message
    # then run the loop for struct-specific follow-up (deeper disasm if needed)
    return agent_loop.run(
        func_addr=func_addr,
        task='struct_reconstruct',
        size_hint=f'~{len(disasm_text.splitlines())} insns',
        cfg_summary=prompt,   # struct prompt replaces normal CFG summary
    )
