"""Seeded control-flow recovery and direct data xrefs for C166 firmware.

Only code reachable from caller-supplied entries and direct calls/branches is
decoded. Unreached bytes remain unclassified. Data references are limited to
proven absolute encodings; immediate constants and register-indirect accesses
are not misreported as direct memory xrefs.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Iterable, Optional

from .ecu_c166_decoder import C166Insn, EcuC166Decoder

MAX_FUNCTIONS = 4096
MAX_INSTRUCTIONS = 250_000
MAX_ISSUES = 16_384

_DIRECT_READ_OPS = frozenset({0x02, 0x22, 0x32, 0x42, 0x43, 0xA2, 0xB2, 0xC2, 0xD2, 0xF2, 0xF3})
_DIRECT_WRITE_OPS = frozenset({0xC5, 0xD5, 0xF6, 0xF7})
_DIRECT_READ_WRITE_OPS = frozenset({0x05, 0x25, 0x64, 0x65, 0x74})


@dataclass(frozen=True)
class C166ControlFlowIssue:
    function: int
    address: int
    reason: str
    target: Optional[int] = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            'function': f'0x{self.function:06X}',
            'address': f'0x{self.address:06X}',
            'reason': self.reason,
        }
        if self.target is not None:
            result['target'] = f'0x{self.target:06X}'
        return result


@dataclass(frozen=True)
class C166DataXref:
    instruction: int
    address: int
    access: str
    mnemonic: str
    opcode: int

    @property
    def dpp_index(self) -> int:
        return (self.address >> 14) & 0x3

    @property
    def page_offset(self) -> int:
        return self.address & 0x3FFF

    def physical_address(self, dpp_pages: dict[int, int]) -> Optional[int]:
        if self.dpp_index not in dpp_pages:
            return None
        page = dpp_pages[self.dpp_index]
        if not 0 <= page <= 0x3FF:
            raise ValueError(f'DPP page outside 10-bit range: {page:#x}')
        return (page << 14) | self.page_offset

    def to_dict(self) -> dict[str, object]:
        return {
            'instruction': f'0x{self.instruction:06X}',
            'address': f'0x{self.address:04X}',
            'access': self.access,
            'mnemonic': self.mnemonic,
            'opcode': f'0x{self.opcode:02X}',
            'dpp_index': self.dpp_index,
            'page_offset': f'0x{self.page_offset:04X}',
        }


@dataclass
class C166Block:
    start: int
    insns: list[C166Insn] = field(default_factory=list)
    succs: list[int] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        if not self.insns:
            return self.start
        return self.insns[-1].pa + len(self.insns[-1].raw)

    @property
    def terminator(self) -> Optional[C166Insn]:
        for insn in self.insns:
            if _flow(insn) != 'linear':
                return insn
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            'start': f'0x{self.start:06X}',
            'end': f'0x{self.end:06X}',
            'successors': [f'0x{value:06X}' for value in self.succs],
            'predecessors': [f'0x{value:06X}' for value in self.preds],
            'instructions': [
                {
                    'address': f'0x{insn.pa:06X}',
                    'raw': insn.raw.hex(' '),
                    'mnemonic': insn.mnemonic,
                    'type': insn.insn_type,
                }
                for insn in self.insns
            ],
        }


@dataclass
class C166Function:
    entry: int
    blocks: dict[int, C166Block]
    calls: dict[int, int]
    issues: list[C166ControlFlowIssue]

    @property
    def instructions(self) -> list[C166Insn]:
        return [insn for block in self for insn in block.insns]

    def __iter__(self):
        return iter(sorted(self.blocks.values(), key=lambda block: block.start))

    def to_dict(self) -> dict[str, object]:
        return {
            'entry': f'0x{self.entry:06X}',
            'calls': [
                {'site': f'0x{site:06X}', 'target': f'0x{target:06X}'}
                for site, target in sorted(self.calls.items())
            ],
            'issues': [issue.to_dict() for issue in self.issues],
            'blocks': [block.to_dict() for block in self],
        }


@dataclass
class C166Recovery:
    base_pa: int
    image_size: int
    functions: dict[int, C166Function]
    code: dict[int, C166Insn]
    issues: list[C166ControlFlowIssue]
    data_xrefs: tuple[C166DataXref, ...]

    @property
    def code_ranges(self) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for address in sorted(self.code):
            end = address + len(self.code[address].raw)
            if ranges and ranges[-1][1] == address:
                ranges[-1] = (ranges[-1][0], end)
            else:
                ranges.append((address, end))
        return ranges

    @property
    def unclassified_ranges(self) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        cursor = self.base_pa
        image_end = self.base_pa + self.image_size
        for start, end in self.code_ranges:
            if cursor < start:
                ranges.append((cursor, start))
            cursor = max(cursor, end)
        if cursor < image_end:
            ranges.append((cursor, image_end))
        return ranges

    def xrefs_to(self, address: int) -> tuple[C166DataXref, ...]:
        if not 0 <= address <= 0xFFFF:
            raise ValueError('C166 direct data address outside 16-bit range')
        return tuple(xref for xref in self.data_xrefs if xref.address == address)

    def to_dict(self) -> dict[str, object]:
        return {
            'schema': 'ablation.c166-recovery.v1',
            'image': {
                'base_pa': f'0x{self.base_pa:06X}',
                'size': self.image_size,
            },
            'coverage': {
                'functions': len(self.functions),
                'instructions': len(self.code),
                'code_ranges': [[f'0x{start:06X}', f'0x{end:06X}'] for start, end in self.code_ranges],
                'unclassified_ranges': [
                    [f'0x{start:06X}', f'0x{end:06X}']
                    for start, end in self.unclassified_ranges
                ],
            },
            'functions': [function.to_dict() for _, function in sorted(self.functions.items())],
            'data_xrefs': [xref.to_dict() for xref in self.data_xrefs],
            'issues': [issue.to_dict() for issue in self.issues],
        }


def _flow(insn: C166Insn) -> str:
    if insn.insn_type in ('RET', 'RETS'):
        return 'return'
    if insn.is_call:
        return 'call'
    if insn.insn_type in ('JMPS',):
        return 'jump'
    if insn.insn_type in ('JMPA', 'JMPR', 'JMPI'):
        return 'conditional'
    return 'linear'


def _unconditional(insn: C166Insn) -> bool:
    if insn.insn_type in ('CALLS', 'JMPS'):
        return True
    if insn.insn_type in ('CALLA', 'JMPA'):
        return (insn.raw[1] >> 4) == 0
    if insn.insn_type == 'JMPR':
        return (insn.raw[0] >> 4) == 0
    if insn.insn_type == 'JMPI':
        return (insn.raw[1] >> 4) == 0
    return False


def _terminates(insn: C166Insn) -> bool:
    return _flow(insn) != 'linear'


def direct_data_xref(insn: C166Insn) -> Optional[C166DataXref]:
    """Classify a proven absolute-memory encoding, or return ``None``."""
    opcode = insn.raw[0]
    if opcode in _DIRECT_READ_OPS:
        access = 'read'
    elif opcode in _DIRECT_WRITE_OPS:
        access = 'write'
    elif opcode in _DIRECT_READ_WRITE_OPS:
        access = 'read_write'
    else:
        return None
    address = int.from_bytes(insn.raw[2:4], 'little')
    return C166DataXref(insn.pa, address, access, insn.mnemonic, opcode)


class C166CFGBuilder:
    def __init__(
        self,
        decoder: EcuC166Decoder,
        *,
        max_functions: int = MAX_FUNCTIONS,
        max_instructions: int = MAX_INSTRUCTIONS,
        max_issues: int = MAX_ISSUES,
    ) -> None:
        if max_functions < 1 or max_instructions < 1 or max_issues < 1:
            raise ValueError('C166 recovery limits must be positive')
        self.decoder = decoder
        self.max_functions = max_functions
        self.max_instructions = max_instructions
        self.max_issues = max_issues
        self.code: dict[int, C166Insn] = {}
        self.owners: dict[int, int] = {}
        self.issues: list[C166ControlFlowIssue] = []

    def recover(self, entries: Optional[Iterable[int]] = None) -> C166Recovery:
        seeds = []
        for address in [self.decoder.base_pa] if entries is None else entries:
            if len(seeds) >= self.max_functions:
                raise ValueError('too many initial C166 entry addresses')
            seeds.append(address)
        if not seeds:
            raise ValueError('at least one C166 entry address is required')

        pending = deque((address, self.decoder.base_pa) for address in seeds)
        queued = set(seeds)
        functions: dict[int, C166Function] = {}
        while pending:
            entry, caller = pending.popleft()
            owner = self.owners.get(entry)
            if owner is not None:
                if owner != entry:
                    self._issue(caller, entry, 'entry overlaps another function')
                continue
            if not self.decoder.contains_pa(entry):
                self._issue(caller, entry, 'entry outside image')
                continue
            if len(functions) >= self.max_functions:
                raise ValueError(f'C166 recovery exceeds {self.max_functions} functions')
            function, callees = self._recover_function(entry)
            functions[entry] = function
            for site, target in sorted(callees.items()):
                if not self.decoder.contains_pa(target):
                    self._issue(entry, site, 'call target outside image', target)
                elif target not in queued:
                    queued.add(target)
                    pending.append((target, entry))

        xrefs = tuple(
            xref
            for _, insn in sorted(self.code.items())
            for xref in [direct_data_xref(insn)]
            if xref is not None
        )
        return C166Recovery(
            self.decoder.base_pa,
            self.decoder.image_size,
            functions,
            self.code,
            self.issues,
            xrefs,
        )

    def _issue(self, function: int, address: int, reason: str, target: Optional[int] = None) -> None:
        if len(self.issues) >= self.max_issues:
            raise ValueError(f'C166 recovery exceeds {self.max_issues} issues')
        self.issues.append(C166ControlFlowIssue(function, address, reason, target))

    def _recover_function(self, entry: int) -> tuple[C166Function, dict[int, int]]:
        local: dict[int, C166Insn] = {}
        states: set[int] = set()
        branches: dict[int, tuple[int, ...]] = {}
        calls: dict[int, int] = {}
        local_issues: list[C166ControlFlowIssue] = []
        issue_start = len(self.issues)
        work = deque([entry])

        while work:
            address = work.popleft()
            if address in states:
                continue
            if not self.decoder.contains_pa(address):
                self._issue(entry, address, 'instruction outside image')
                continue
            owner = self.owners.get(address)
            if owner is not None:
                if owner != entry:
                    self._issue(entry, address, 'instruction owned by another function')
                continue
            states.add(address)
            insn = self.decoder.decode_one(address - self.decoder.base_pa)
            if insn is None:
                self._issue(entry, address, 'truncated instruction')
                continue
            local[address] = insn
            if len(self.code) + len(local) > self.max_instructions:
                raise ValueError(f'C166 recovery exceeds {self.max_instructions} instructions')
            if insn.insn_type in ('UNKNOWN_2B', 'UNKNOWN_4B'):
                self._issue(entry, address, 'unknown instruction encoding; linear decoding retained')

            next_address = address + len(insn.raw)
            flow = _flow(insn)
            if flow == 'linear':
                work.append(next_address)
                continue
            if flow == 'return':
                continue

            targets = (insn.target,) if insn.target is not None else ()
            if targets:
                branches[address] = targets
            unconditional = _unconditional(insn)
            if flow == 'call':
                if insn.target is None:
                    self._issue(entry, address, 'unresolved indirect call')
                else:
                    calls[address] = insn.target
                work.append(next_address)
                continue

            if insn.target is None:
                reason = 'unresolved indirect jump' if unconditional else 'unresolved conditional branch'
                self._issue(entry, address, reason)
            for target in targets:
                if self.decoder.contains_pa(target):
                    work.append(target)
                else:
                    self._issue(entry, address, 'branch target outside image', target)
            if not unconditional:
                work.append(next_address)

        blocks = self._build_blocks(entry, local, branches)
        local_issues = self.issues[issue_start:]
        function = C166Function(entry, blocks, calls, local_issues)
        for address, insn in local.items():
            self.code[address] = insn
            self.owners[address] = entry
        return function, calls

    @staticmethod
    def _build_blocks(
        entry: int,
        local: dict[int, C166Insn],
        branches: dict[int, tuple[int, ...]],
    ) -> dict[int, C166Block]:
        leaders = {entry}
        for insn in local.values():
            if not _terminates(insn):
                continue
            leaders.update(target for target in branches.get(insn.pa, ()) if target in local)
            following = insn.pa + len(insn.raw)
            if following in local and (_flow(insn) == 'call' or not _unconditional(insn)):
                leaders.add(following)

        blocks: dict[int, C166Block] = {}
        consumed: set[int] = set()
        for leader in sorted(leaders):
            if leader not in local or leader in consumed:
                continue
            block = C166Block(leader)
            address = leader
            while address in local and address not in consumed:
                if address != leader and address in leaders:
                    break
                insn = local[address]
                block.insns.append(insn)
                consumed.add(address)
                if _terminates(insn):
                    break
                address += len(insn.raw)
            blocks[leader] = block

        for block in blocks.values():
            terminator = block.terminator
            if terminator is None:
                if block.end in blocks:
                    block.succs.append(block.end)
                continue
            if _flow(terminator) in ('jump', 'conditional'):
                block.succs.extend(
                    target for target in branches.get(terminator.pa, ()) if target in blocks
                )
            following = terminator.pa + len(terminator.raw)
            if (
                _flow(terminator) == 'call' or not _unconditional(terminator)
            ) and following in blocks:
                block.succs.append(following)
        for block in blocks.values():
            for successor in block.succs:
                blocks[successor].preds.append(block.start)
        return blocks


def recover_c166_cfg(
    decoder: EcuC166Decoder,
    entries: Optional[Iterable[int]] = None,
    *,
    max_functions: int = MAX_FUNCTIONS,
    max_instructions: int = MAX_INSTRUCTIONS,
    max_issues: int = MAX_ISSUES,
) -> C166Recovery:
    """Recover bounded C166 functions, blocks, calls, issues, and direct xrefs."""
    return C166CFGBuilder(
        decoder,
        max_functions=max_functions,
        max_instructions=max_instructions,
        max_issues=max_issues,
    ).recover(entries)


def _cli(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('entries', nargs='+', type=lambda value: int(value, 0))
    parser.add_argument('--base', type=lambda value: int(value, 0), default=0)
    parser.add_argument('--xref', action='append', type=lambda value: int(value, 0), default=[])
    parser.add_argument('--max-functions', type=int, default=MAX_FUNCTIONS)
    parser.add_argument('--max-instructions', type=int, default=MAX_INSTRUCTIONS)
    parser.add_argument('--max-issues', type=int, default=MAX_ISSUES)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    recovery = recover_c166_cfg(
        EcuC166Decoder(args.image, args.base),
        args.entries,
        max_functions=args.max_functions,
        max_instructions=args.max_instructions,
        max_issues=args.max_issues,
    )
    payload = recovery.to_dict()
    if args.xref:
        payload['selected_xrefs'] = {
            f'0x{address:04X}': [xref.to_dict() for xref in recovery.xrefs_to(address)]
            for address in args.xref
        }
    text = json.dumps(payload, indent=2) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        print(text, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(_cli())
