"""Bounded, path-sensitive MIPS pointer ownership analysis.

The analyzer reports evidence and candidates. It does not claim that a static
candidate is dynamically reachable or exploitable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .cfg_mips import build_cfg
from .insn_mips import Imm, Insn, Mem, Reg
from .isa_mips import CALL_DIRECT, CALL_INDIRECT, LOAD, STORE
from .mips_function import MipsFunction, load_mips_function


@dataclass(frozen=True)
class Value:
    object_id: str | None = None
    const: int | None = None
    root: int | None = None
    expression: str = ""


@dataclass
class OwnershipState:
    regs: dict[str, Value] = field(default_factory=dict)
    memory: dict[str, Value] = field(default_factory=dict)
    freed: dict[str, int] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    visits: dict[int, int] = field(default_factory=dict)

    def clone(self) -> "OwnershipState":
        return OwnershipState(
            dict(self.regs), dict(self.memory), dict(self.freed),
            list(self.events), list(self.findings), dict(self.visits),
        )


def _event(state: OwnershipState, kind: str, insn: Insn, **values) -> None:
    state.events.append({"kind": kind, "va": hex(insn.address), **values})


def _finding(state: OwnershipState, kind: str, insn: Insn, object_id: str, **values) -> None:
    state.findings.append({
        "kind": kind, "va": hex(insn.address), "object": object_id,
        "status": "static-candidate", **values,
    })


def _object_root(object_id: str) -> int | None:
    if object_id.startswith("global:"):
        return int(object_id.split(":", 1)[1], 16)
    return None


def _memory_key(value: Value) -> str | None:
    if value.const is not None:
        return f"absolute:{value.const:#x}"
    if value.root is not None:
        return f"global:{value.root:#x}"
    if value.object_id:
        return f"object:{value.object_id}"
    if value.expression:
        return f"expr:{value.expression}"
    return None


def _binary_value(insn: Insn, state: OwnershipState) -> Value:
    left = state.regs.get(insn.reg(1), Value())
    right = state.regs.get(insn.reg(2), Value())
    if insn.mnemonic == "addu":
        if left.const is not None and right.const is not None:
            return Value(const=(left.const + right.const) & 0xFFFFFFFF)
        left_address = left.root is not None or (left.const is not None and left.const >= 0x10000)
        right_address = right.root is not None or (right.const is not None and right.const >= 0x10000)
        address, other = (left, right) if left_address else (right, left)
        root = address.root if address.root is not None else address.const
        if (left_address or right_address) and root is not None:
            expression = other.expression or (hex(other.const) if other.const is not None else "?")
            return Value(root=root, expression=expression)
        if left.object_id and (right.const is not None or right.expression):
            return left
        if right.object_id and (left.const is not None or left.expression):
            return right
        return Value(expression="+".join(item for item in (left.expression, right.expression) if item))
    if insn.mnemonic == "sll" and isinstance(insn.ops[2], Imm):
        amount = insn.ops[2].value
        if left.const is not None:
            return Value(const=(left.const << amount) & 0xFFFFFFFF)
        return Value(expression=f"({left.expression or '?'}<<{amount})")
    return Value()


def _call_target(insn: Insn, state: OwnershipState, function: MipsFunction) -> tuple[int | None, str | None]:
    if insn.mnemonic in CALL_DIRECT:
        target = insn.imm(-1)
        return target, function.symbols.get(target) if target is not None else None
    if insn.mnemonic in CALL_INDIRECT:
        register = insn.reg(-1)
        value = state.regs.get(register, Value())
        if value.const is not None:
            return value.const, function.symbols.get(value.const)
    return None, None


def _process_insn(
    insn: Insn,
    state: OwnershipState,
    function: MipsFunction,
    frees: set[int],
    free_names: set[str],
    allocators: set[int],
    allocator_names: set[str],
    function_calls: dict[int, str],
) -> None:
    mnemonic = insn.mnemonic
    if mnemonic == "move" and insn.reg(0) and insn.reg(1):
        state.regs[insn.reg(0)] = state.regs.get(insn.reg(1), Value())
    elif mnemonic == "lui" and insn.reg(0) and insn.imm(1) is not None:
        state.regs[insn.reg(0)] = Value(const=(insn.imm(1) << 16) & 0xFFFFFFFF)
    elif mnemonic in ("addiu", "daddiu", "ori") and insn.reg(0):
        source = state.regs.get(insn.reg(1), Value())
        immediate = insn.imm(2)
        if source.const is not None and immediate is not None:
            value = source.const | immediate if mnemonic == "ori" else source.const + immediate
            state.regs[insn.reg(0)] = Value(const=value & 0xFFFFFFFF)
        elif source.root is not None and immediate is not None:
            state.regs[insn.reg(0)] = Value(root=source.root + immediate, expression="")
        elif source.object_id:
            state.regs[insn.reg(0)] = source
        elif immediate is not None:
            state.regs[insn.reg(0)] = Value(expression=f"({source.expression or '?'}{immediate:+#x})")
    elif mnemonic in ("addu", "sll"):
        if insn.reg(0):
            state.regs[insn.reg(0)] = _binary_value(insn, state)
    elif mnemonic in LOAD and insn.reg(0) and insn.mem(1):
        address = state.regs.get(insn.mem(1).base, Value())
        if address.root is None and address.const is not None and address.const >= 0x10000:
            address = Value(root=address.const)
        object_id = address.object_id
        if object_id:
            if object_id.startswith("global:"):
                _event(state, "global_deref", insn, object=object_id)
            if object_id in state.freed:
                _finding(state, "use_after_free", insn, object_id, first_free_va=hex(state.freed[object_id]), access="read")
        key = _memory_key(address)
        if address.root is not None:
            value = Value(object_id=f"global:{address.root:#x}")
        elif key in state.memory:
            value = state.memory[key]
        else:
            value = Value(expression=key or "?")
        state.regs[insn.reg(0)] = value
    elif mnemonic in STORE and insn.reg(0) and insn.mem(1):
        address = state.regs.get(insn.mem(1).base, Value())
        if address.root is None and address.const is not None and address.const >= 0x10000:
            address = Value(root=address.const)
        object_id = address.object_id
        if object_id:
            if object_id.startswith("global:"):
                _event(state, "global_deref", insn, object=object_id)
            if object_id in state.freed:
                _finding(state, "use_after_free", insn, object_id, first_free_va=hex(state.freed[object_id]), access="write")
        key = _memory_key(address)
        source = state.regs.get(insn.reg(0), Value())
        if address.root is not None and source.const == 0:
            _event(state, "pointer_clear", insn, root=hex(address.root))
        if key:
            state.memory[key] = source
    elif mnemonic in CALL_DIRECT | CALL_INDIRECT:
        target, name = _call_target(insn, state, function)
        argument = state.regs.get("$4", Value())
        is_free = target in frees or name in free_names
        if is_free and argument.object_id:
            object_id = argument.object_id
            if object_id in state.freed:
                _finding(state, "double_free", insn, object_id, first_free_va=hex(state.freed[object_id]))
            else:
                state.freed[object_id] = insn.address
            _event(state, "free", insn, object=object_id, callee=name or hex(target) if target is not None else "indirect")
            prior_may_free = next((event for event in reversed(state.events) if event["kind"] == "callee_may_free" and event["object"] == object_id), None)
            if prior_may_free:
                _finding(state, "double_free_after_callee", insn, object_id, callee_free_va=prior_may_free["va"])
        elif target in function_calls and argument.object_id:
            _event(state, "callee_may_free", insn, object=argument.object_id, callee=function_calls[target])
        if target in allocators or name in allocator_names:
            state.regs["$2"] = Value(object_id=f"alloc:{insn.address:#x}")
            _event(state, "allocate", insn, object=state.regs["$2"].object_id, callee=name or hex(target))
        elif not is_free:
            state.regs["$2"] = Value()
        for register in ("$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25"):
            state.regs.pop(register, None)


def analyze_function(
    function: MipsFunction,
    free_functions: set[int] | None = None,
    free_names: set[str] | None = None,
    allocator_functions: set[int] | None = None,
    allocator_names: set[str] | None = None,
    callees_may_free: set[int] | None = None,
    max_paths: int = 256,
    max_steps: int = 20000,
) -> dict[str, object]:
    cfg = build_cfg(function.instructions, function.va)
    calls = {va: name for va, name in function.symbols.items() if va in (callees_may_free or set())}
    initial = OwnershipState(regs={
        "$4": Value(object_id="arg0"), "$5": Value(object_id="arg1"),
        "$6": Value(object_id="arg2"), "$7": Value(object_id="arg3"),
        "$0": Value(const=0),
    })
    worklist = [(cfg.entry, initial)]
    terminals = []
    steps = 0
    truncated = False
    while worklist and steps < max_steps:
        address, state = worklist.pop()
        if address not in cfg.blocks:
            continue
        state.visits[address] = state.visits.get(address, 0) + 1
        if state.visits[address] > 2:
            continue
        block = cfg.blocks[address]
        for insn in block.insns:
            _process_insn(
                insn, state, function,
                free_functions or set(), free_names or {"free", "mod_free"},
                allocator_functions or set(), allocator_names or {"malloc", "calloc", "mod_kzalloc"},
                calls,
            )
            steps += 1
            if steps >= max_steps:
                truncated = True
                break
        if not block.succs:
            terminals.append(state)
        elif len(worklist) + len(terminals) >= max_paths:
            truncated = True
            break
        else:
            for successor in reversed(block.succs):
                worklist.append((successor, state.clone()))
    if worklist:
        truncated = True
    findings = []
    events = []
    for state in terminals:
        events.extend(state.events)
        findings.extend(state.findings)
        for index, event in enumerate(state.events):
            if event["kind"] != "free" or not event["object"].startswith("global:"):
                continue
            root = event["object"].split(":", 1)[1]
            cleared = any(
                later["kind"] == "pointer_clear" and later["root"] == root
                for later in state.events[index + 1:]
            )
            if not cleared:
                findings.append({
                    "kind": "dangling_global_pointer",
                    "va": event["va"],
                    "object": event["object"],
                    "status": "static-candidate",
                    "reason": "No zero store to the same global root was found after this free on the analyzed path.",
                })
    unique_findings = list({str(item): item for item in findings}.values())
    unique_events = list({str(item): item for item in events}.values())
    return {
        "name": function.name,
        "va": hex(function.va),
        "size": function.size,
        "paths_completed": len(terminals),
        "truncated": truncated,
        "steps": steps,
        "events": unique_events,
        "findings": unique_findings,
    }


def analyze_ownership(
    binary: str | Path,
    functions: list[dict],
    free_functions: set[int] | None = None,
    free_names: set[str] | None = None,
    allocator_functions: set[int] | None = None,
    allocator_names: set[str] | None = None,
    max_paths: int = 256,
    max_steps: int = 20000,
) -> dict[str, object]:
    loaded = [load_mips_function(binary, int(item["va"]), item.get("size")) for item in functions]
    may_free = set()
    for function, spec in zip(loaded, functions):
        if spec.get("may_free_arg0"):
            may_free.add(function.va)
    reports = [
        analyze_function(
            function,
            free_functions=free_functions,
            free_names=free_names,
            allocator_functions=allocator_functions,
            allocator_names=allocator_names,
            callees_may_free=may_free,
            max_paths=max_paths,
            max_steps=max_steps,
        )
        for function in loaded
    ]
    for report, spec in zip(reports, functions):
        report["name"] = spec.get("name", report["name"])
    cross_function = []
    for owner, owner_spec in zip(reports, functions):
        freed_roots = {
            event["object"]
            for event in owner["events"]
            if event["kind"] == "free" and event["object"].startswith("global:")
        }
        for callback, callback_spec in zip(reports, functions):
            if callback["name"] == owner["name"] or callback_spec.get("role") != "deferred_callback":
                continue
            uses = [event for event in callback["events"] if event["kind"] == "global_deref" and event["object"] in freed_roots]
            for use in uses:
                cross_function.append({
                    "kind": "deferred_use_after_free",
                    "status": "static-candidate",
                    "object": use["object"],
                    "owner": owner["name"],
                    "callback": callback["name"],
                    "callback_va": use["va"],
                })
    findings = [finding for report in reports for finding in report["findings"]] + cross_function
    return {
        "schema_version": 1,
        "analysis": "bounded-mips-ownership",
        "binary": str(binary),
        "functions": reports,
        "findings": findings,
        "summary": {
            "functions": len(reports),
            "findings": len(findings),
            "truncated_functions": sum(bool(report["truncated"]) for report in reports),
        },
        "caveat": "Findings are static candidates. Global table entries are collapsed by root, indirect calls and runtime reachability require manual review.",
    }
