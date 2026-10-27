"""Recursive-descent control-flow recovery for raw MicroBlaze images.

Only reachable words are decoded. Direct calls discover additional functions;
unreached bytes remain unclassified rather than being assumed to be data.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .microblaze_decoder import MicroBlazeDecoder, MicroBlazeInsn


MAX_FUNCTIONS = 4096
MAX_INSTRUCTIONS = 1_000_000


@dataclass(frozen=True)
class ControlFlowIssue:
    function: int
    address: int
    reason: str
    target: Optional[int] = None


@dataclass
class MicroBlazeBlock:
    start: int
    insns: list[MicroBlazeInsn] = field(default_factory=list)
    succs: list[int] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.insns[-1].address + self.insns[-1].size if self.insns else self.start

    @property
    def terminator(self) -> Optional[MicroBlazeInsn]:
        for insn in self.insns:
            if insn.flow != "linear":
                return insn
        return None


@dataclass
class MicroBlazeFunction:
    entry: int
    blocks: dict[int, MicroBlazeBlock]
    calls: dict[int, int]
    issues: list[ControlFlowIssue]

    @property
    def instructions(self) -> list[MicroBlazeInsn]:
        return [insn for block in self for insn in block.insns]

    def __iter__(self):
        return iter(sorted(self.blocks.values(), key=lambda block: block.start))


@dataclass
class MicroBlazeRecovery:
    base_va: int
    image_size: int
    functions: dict[int, MicroBlazeFunction]
    code: dict[int, MicroBlazeInsn]
    issues: list[ControlFlowIssue]

    @staticmethod
    def _ranges(addresses: Iterable[int]) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for address in sorted(set(addresses)):
            if ranges and ranges[-1][1] == address:
                ranges[-1] = (ranges[-1][0], address + 4)
            else:
                ranges.append((address, address + 4))
        return ranges

    @property
    def code_ranges(self) -> list[tuple[int, int]]:
        return self._ranges(self.code)

    @property
    def unclassified_ranges(self) -> list[tuple[int, int]]:
        end = self.base_va + self.image_size
        cursor = self.base_va
        ranges: list[tuple[int, int]] = []
        for start, code_end in self.code_ranges:
            if cursor < start:
                ranges.append((cursor, start))
            cursor = max(cursor, code_end)
        if cursor < end:
            ranges.append((cursor, end))
        return ranges


@dataclass(frozen=True)
class JumpTableSpec:
    table_address: int
    entry_count: int
    target_delta: int = 0


def resolve_jump_tables(
    decoder: MicroBlazeDecoder,
    recovery: MicroBlazeRecovery,
    specs: dict[int, JumpTableSpec],
) -> dict[int, tuple[int, ...]]:
    """Resolve bounded tables after validating their five-instruction site pattern."""
    if len(specs) > 4096:
        raise ValueError("too many jump-table specifications")
    resolved: dict[int, tuple[int, ...]] = {}
    for branch_address, spec in sorted(specs.items()):
        if not 1 <= spec.entry_count <= 4096:
            raise ValueError("jump-table entry count must be between 1 and 4096")
        branch = recovery.code.get(branch_address)
        pattern = [recovery.code.get(branch_address - delta) for delta in (16, 12, 8, 4)]
        if branch is None or branch.flow != "jump" or branch.target is not None or any(
            insn is None for insn in pattern
        ):
            raise ValueError(f"invalid indirect-branch site: {branch_address:#x}")
        shift, imm, address_calc, load = pattern
        register = branch.rb
        if not (
            shift.mnemonic == "bslli" and shift.imm == 2
            and shift.rd == register and shift.ra is not None
            and imm.mnemonic == "imm"
            and address_calc.mnemonic in ("addi", "addik")
            and address_calc.rd == register and address_calc.ra == register
            and address_calc.extended_imm
            and load.mnemonic == "lwi" and load.rd == register
            and load.ra == register and load.imm == 0
        ):
            raise ValueError(f"unrecognized jump-table pattern: {branch_address:#x}")
        table_offset = spec.table_address - decoder.base_va
        table_size = spec.entry_count * 4
        if table_offset < 0 or table_offset % 4 or table_offset + table_size > decoder.image_size:
            raise ValueError(f"jump table outside image: {spec.table_address:#x}")
        targets = []
        for index in range(spec.entry_count):
            word = decoder.decode_one(table_offset + index * 4)
            if word is None:
                raise ValueError("truncated jump table")
            target = (word.word + spec.target_delta) & 0xFFFFFFFF
            target_offset = target - decoder.base_va
            if target_offset < 0 or target_offset % 4 or target_offset + 4 > decoder.image_size:
                raise ValueError(f"jump-table target outside image: {target:#x}")
            targets.append(target)
        resolved[branch_address] = tuple(targets)
    return resolved


class MicroBlazeCFGBuilder:
    def __init__(
        self,
        decoder: MicroBlazeDecoder,
        *,
        jump_table_targets: Optional[dict[int, Iterable[int]]] = None,
        no_return: Optional[Iterable[int]] = None,
        max_functions: int = MAX_FUNCTIONS,
        max_instructions: int = MAX_INSTRUCTIONS,
    ) -> None:
        if max_functions < 1 or max_instructions < 1:
            raise ValueError("recovery limits must be positive")
        self.decoder = decoder
        self.no_return: set[int] = set()
        for address in no_return or ():
            if len(self.no_return) >= max_functions:
                raise ValueError("too many no-return addresses")
            self.no_return.add(address)
        supplied_tables = jump_table_targets or {}
        if len(supplied_tables) > 4096:
            raise ValueError("too many jump-table targets")
        self.jump_table_targets: dict[int, tuple[int, ...]] = {}
        for address, targets in supplied_tables.items():
            values = []
            for target in targets:
                if len(values) >= 4096:
                    raise ValueError("too many targets in jump table")
                values.append(target)
            self.jump_table_targets[address] = tuple(values)
        self.max_functions = max_functions
        self.max_instructions = max_instructions
        self.code: dict[int, MicroBlazeInsn] = {}
        self.owners: dict[int, int] = {}
        self.issues: list[ControlFlowIssue] = []

    def recover(self, entries: Optional[Iterable[int]] = None) -> MicroBlazeRecovery:
        base = self.decoder.base_va
        seeds = []
        for address in [base] if entries is None else entries:
            if len(seeds) >= self.max_functions:
                raise ValueError("too many initial entry addresses")
            seeds.append(address)
        if not seeds:
            raise ValueError("at least one entry address is required")
        pending = deque((address, base) for address in seeds)
        queued = set(seeds)
        functions: dict[int, MicroBlazeFunction] = {}

        while pending:
            entry, caller = pending.popleft()
            owner = self.owners.get(entry)
            if owner is not None:
                if owner != entry and entry not in self.no_return:
                    self.issues.append(ControlFlowIssue(caller, entry, "entry overlaps another function"))
                continue
            if not self._contains(entry):
                self.issues.append(ControlFlowIssue(caller, entry, "entry outside image"))
                continue
            if len(functions) >= self.max_functions:
                raise ValueError(f"MicroBlaze recovery exceeds {self.max_functions} functions")
            function, callees = self._recover_function(entry)
            functions[entry] = function
            for address, target in sorted(callees.items(), key=lambda item: item[0]):
                if not self._contains(target):
                    self.issues.append(ControlFlowIssue(entry, address, "call target outside image", target))
                elif target not in queued:
                    queued.add(target)
                    pending.append((target, entry))

        return MicroBlazeRecovery(base, self.decoder.image_size, functions, self.code, self.issues)

    def _contains(self, address: int) -> bool:
        offset = address - self.decoder.base_va
        return offset >= 0 and offset % 4 == 0 and offset + 4 <= self.decoder.image_size

    def _recover_function(self, entry: int) -> tuple[MicroBlazeFunction, dict[int, int]]:
        local: dict[int, MicroBlazeInsn] = {}
        states: dict[int, Optional[int]] = {}
        delay_slots: dict[int, int] = {}
        branches: dict[int, tuple[int, ...]] = {}
        calls: dict[int, int] = {}
        issues: list[ControlFlowIssue] = []
        work = deque([(entry, None)])

        def issue(address: int, reason: str, target: Optional[int] = None) -> None:
            issues.append(ControlFlowIssue(entry, address, reason, target))

        def decode(address: int, imm_high: Optional[int]) -> Optional[MicroBlazeInsn]:
            if not self._contains(address):
                issue(address, "instruction outside image")
                return None
            owner = self.owners.get(address)
            if owner is not None:
                if owner != entry:
                    issue(address, "instruction owned by another function")
                return None
            previous = states.get(address)
            if address in states:
                if previous != imm_high:
                    issue(address, "conflicting IMM context")
                return None
            states[address] = imm_high
            insn = self.decoder.decode_one(address - self.decoder.base_va, imm_high)
            if insn is None or not insn.valid:
                issue(address, "invalid instruction")
                return None
            local[address] = insn
            if len(self.code) + len(local) > self.max_instructions:
                raise ValueError(f"MicroBlaze recovery exceeds {self.max_instructions} instructions")
            return insn

        while work:
            address, imm_high = work.popleft()
            insn = decode(address, imm_high)
            if insn is None:
                continue
            next_address = address + 4
            if insn.mnemonic == "imm":
                work.append((next_address, insn.word & 0xFFFF))
                continue
            if insn.flow == "linear":
                work.append((next_address, None))
                continue

            post = next_address
            if insn.delay_slot:
                slot = decode(next_address, None)
                if slot is None:
                    issue(next_address, "missing delay slot")
                    continue
                delay_slots[next_address] = address
                post += 4
                if slot.mnemonic == "imm" or slot.flow != "linear":
                    issue(next_address, "control transfer or IMM in delay slot")
                    continue

            targets = (insn.target,) if insn.target is not None else self.jump_table_targets.get(address, ())
            if targets:
                branches[address] = targets
            if insn.flow == "call":
                if insn.target is not None:
                    calls[address] = insn.target
                else:
                    issue(address, "unresolved indirect call")
                if insn.target not in self.no_return:
                    work.append((post, None))
            elif insn.flow == "conditional":
                if not targets:
                    issue(address, "unresolved conditional branch")
                for target in targets:
                    work.append((target, None))
                work.append((post, None))
            elif insn.flow == "jump":
                if not targets:
                    issue(address, "unresolved indirect jump")
                for target in targets:
                    work.append((target, None))
            elif insn.flow not in ("return", "trap"):
                issue(address, f"unsupported control flow: {insn.flow}")

        blocks = self._build_blocks(entry, local, delay_slots, branches, self.no_return, issues)
        self.issues.extend(issues)
        for address, insn in local.items():
            self.code[address] = insn
            self.owners[address] = entry
        return MicroBlazeFunction(entry, blocks, calls, issues), calls

    @staticmethod
    def _build_blocks(
        entry: int,
        local: dict[int, MicroBlazeInsn],
        delay_slots: dict[int, int],
        branches: dict[int, tuple[int, ...]],
        no_return: set[int],
        issues: list[ControlFlowIssue],
    ) -> dict[int, MicroBlazeBlock]:
        leaders = {entry}
        for insn in local.values():
            if insn.flow != "linear":
                leaders.update(target for target in branches.get(insn.address, ()) if target in local)
                post = insn.address + 8 if insn.delay_slot else insn.address + 4
                if post in local and insn.flow in ("conditional", "call"):
                    leaders.add(post)
        for slot in delay_slots:
            if slot in leaders:
                issues.append(ControlFlowIssue(entry, slot, "branch target enters delay slot"))
                leaders.remove(slot)

        blocks: dict[int, MicroBlazeBlock] = {}
        consumed: set[int] = set()
        for leader in sorted(leaders):
            if leader not in local or leader in consumed:
                continue
            block = MicroBlazeBlock(leader)
            address = leader
            while address in local and address not in consumed:
                if address != leader and address in leaders:
                    break
                insn = local[address]
                block.insns.append(insn)
                consumed.add(address)
                if insn.flow != "linear":
                    if insn.delay_slot and address + 4 in local:
                        slot_address = address + 4
                        block.insns.append(local[slot_address])
                        consumed.add(slot_address)
                    break
                address += 4
            blocks[leader] = block

        for block in blocks.values():
            term = block.terminator
            if term is None:
                if block.end in blocks:
                    block.succs.append(block.end)
                continue
            if term.flow in ("jump", "conditional"):
                block.succs.extend(target for target in branches.get(term.address, ()) if target in blocks)
            post = term.address + 8 if term.delay_slot else term.address + 4
            if (
                term.flow == "conditional"
                or (term.flow == "call" and term.target not in no_return)
            ) and post in blocks:
                block.succs.append(post)
        for block in blocks.values():
            for successor in block.succs:
                blocks[successor].preds.append(block.start)
        return blocks


def _self_loop_addresses(function: MicroBlazeFunction) -> set[int]:
    if any(insn.flow == "return" for insn in function.instructions):
        return set()
    result: set[int] = set()
    loops = [
        block for block in function
        if block.succs == [block.start]
        and block.terminator is not None
        and block.terminator.flow == "jump"
        and block.terminator.target == block.terminator.address
    ]
    for loop in loops:
        reachable = {loop.start}
        pending = [loop.start]
        while pending:
            current = pending.pop()
            for predecessor in function.blocks[current].preds:
                if predecessor not in reachable:
                    reachable.add(predecessor)
                    pending.append(predecessor)
        if reachable == set(function.blocks):
            result.add(loop.terminator.address)
    return result


def no_return_addresses(recovery: MicroBlazeRecovery) -> set[int]:
    """Return direct self-loop addresses proven to have no returning path."""
    result: set[int] = set()
    for function in recovery.functions.values():
        result.update(_self_loop_addresses(function))
    return result


def no_return_functions(recovery: MicroBlazeRecovery) -> set[int]:
    """Return entries of standalone functions containing only a proven infinite loop."""
    return {
        entry for entry, function in recovery.functions.items()
        if entry in _self_loop_addresses(function)
    }


def recover_cfg(
    decoder: MicroBlazeDecoder,
    entries: Optional[Iterable[int]] = None,
    *,
    jump_table_targets: Optional[dict[int, Iterable[int]]] = None,
    no_return: Optional[Iterable[int]] = None,
    max_functions: int = MAX_FUNCTIONS,
    max_instructions: int = MAX_INSTRUCTIONS,
) -> MicroBlazeRecovery:
    return MicroBlazeCFGBuilder(
        decoder, jump_table_targets=jump_table_targets, no_return=no_return,
        max_functions=max_functions, max_instructions=max_instructions,
    ).recover(entries)
