"""Evidence-preserving producer, transport, authorization, and consumer graphs."""
from __future__ import annotations

from collections import deque
from pathlib import Path

from .isa_mips import CALL_DIRECT, CALL_INDIRECT
from .mips_function import load_mips_function


def _integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def _paths(nodes: list[dict], edges: list[dict], limit: int = 64) -> list[list[str]]:
    producers = {node["id"] for node in nodes if node.get("role") == "producer"}
    consumers = {node["id"] for node in nodes if node.get("role") == "consumer"}
    adjacency = {}
    for edge in edges:
        if edge["verification"]["status"] != "failed":
            adjacency.setdefault(edge["source"], []).append(edge["target"])
    paths = []
    queue = deque((producer, [producer]) for producer in sorted(producers))
    while queue and len(paths) < limit:
        current, path = queue.popleft()
        if current in consumers:
            paths.append(path)
            continue
        for target in adjacency.get(current, []):
            if target not in path:
                queue.append((target, path + [target]))
    return paths


def build_provenance_graph(root: str | Path, spec: dict) -> dict[str, object]:
    base = Path(root)
    nodes = []
    node_by_id = {}
    loaded = {}
    for item in spec.get("nodes", []):
        if not item.get("id") or item["id"] in node_by_id:
            raise ValueError("Provenance node IDs must be present and unique")
        node = dict(item)
        node["va"] = _integer(node["va"])
        if isinstance(node.get("size"), str):
            node["size"] = _integer(node["size"])
        binary = Path(node["binary"])
        if not binary.is_absolute():
            binary = base / binary
        node["binary"] = str(binary)
        try:
            function = load_mips_function(binary, node["va"], node.get("size"))
            loaded[node["id"]] = function
            node["verification"] = {"status": "loaded", "instructions": len(function.instructions)}
            node["function_name"] = function.name
        except (OSError, ValueError) as exc:
            node["verification"] = {"status": "failed", "reason": str(exc)}
        nodes.append(node)
        node_by_id[node["id"]] = node

    edges = []
    for item in spec.get("edges", []):
        edge = dict(item)
        source = edge.get("source")
        target = edge.get("target")
        if source not in node_by_id or target not in node_by_id:
            raise ValueError(f"Edge references an unknown node: {source} -> {target}")
        if edge.get("kind") == "direct_call":
            try:
                function = loaded[source]
                call_va = _integer(edge["call_va"])
                expected = _integer(edge.get("target_va", node_by_id[target]["va"]))
                instruction = next((insn for insn in function.instructions if insn.address == call_va), None)
                actual = instruction.imm(-1) if instruction is not None and instruction.mnemonic in CALL_DIRECT else None
                verified = actual == expected
                edge["verification"] = {
                    "status": "verified" if verified else "failed",
                    "call_va": hex(call_va),
                    "expected_target": hex(expected),
                    "actual_target": hex(actual) if actual is not None else None,
                }
            except (KeyError, TypeError, ValueError) as exc:
                edge["verification"] = {"status": "failed", "reason": str(exc)}
        elif edge.get("kind") == "indirect_call":
            try:
                function = loaded[source]
                call_va = _integer(edge["call_va"])
                instruction = next((insn for insn in function.instructions if insn.address == call_va), None)
                verified = instruction is not None and instruction.mnemonic in CALL_INDIRECT
                edge["verification"] = {
                    "status": "call_site_verified" if verified else "failed",
                    "call_va": hex(call_va),
                    "target": "declared; indirect PIC target not resolved by this checker",
                    "actual_mnemonic": instruction.mnemonic if instruction is not None else None,
                }
            except (KeyError, TypeError, ValueError) as exc:
                edge["verification"] = {"status": "failed", "reason": str(exc)}
        else:
            edge["verification"] = {
                "status": "declared",
                "reason": "Non-call edge retained as supplied static evidence; not independently verified by the call checker.",
            }
        edges.append(edge)

    verified = sum(edge["verification"]["status"] == "verified" for edge in edges)
    failed = sum(edge["verification"]["status"] == "failed" for edge in edges)
    return {
        "schema_version": 1,
        "analysis": "gencfg-provenance-graph",
        "root": str(base),
        "nodes": nodes,
        "edges": edges,
        "producer_consumer_paths": _paths(nodes, edges),
        "authorization": spec.get("authorization", []),
        "transport": spec.get("transport", {}),
        "reachability": spec.get("reachability", {}),
        "runtime_unknowns": spec.get("runtime_unknowns", []),
        "summary": {
            "nodes": len(nodes),
            "nodes_failed": sum(node["verification"]["status"] == "failed" for node in nodes),
            "edges": len(edges),
            "direct_calls_verified": verified,
            "edges_failed": failed,
            "declared_edges": sum(edge["verification"]["status"] == "declared" for edge in edges),
        },
        "caveat": "A graph describes static evidence and declared transport policy. It does not enumerate runtime credentials or prove attacker reachability.",
    }
