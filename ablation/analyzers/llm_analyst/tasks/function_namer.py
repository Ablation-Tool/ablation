"""
tasks/function_namer.py — Propose function names for unknown binary functions.

For each function, pre-fetches callee names, string xrefs, and RAG prior findings
before launching the agent loop — so the model has strong signals without tool calls.
This keeps the typical case at 1-2 tool calls (usually just done()).
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class NamingCandidate:
    func_addr:  int
    name:       str
    role:       str
    confidence: float
    rationale:  str
    tool_calls: int
    source:     str   # 'llm_inferred', 'func_db_exact', 'llm_low_conf'


def name_function(
    agent_loop,
    func_addr:  int,
    pre_fetch:  bool = True,
) -> NamingCandidate:
    """
    Name a single function at func_addr.

    pre_fetch=True (default): calls get_strings and get_imports before the LLM,
    injecting those results directly into context to reduce tool call count.
    """
    callees = []
    strings = []

    if pre_fetch:
        reg = agent_loop._registry
        try:
            imports_json = reg._get_imports(func_addr)
            imports = json.loads(imports_json).get('imports', [])
            callees = [imp['name'] for imp in imports]
        except Exception:
            pass

        try:
            strings_json = reg._get_strings(func_addr)
            strings = json.loads(strings_json).get('strings', [])
        except Exception:
            pass

    result = agent_loop.run(
        func_addr=func_addr,
        task='name_function',
        callees=callees or None,
        strings=strings or None,
    )

    source = (
        'llm_inferred' if result.finished and result.confidence >= 0.6 else
        'llm_low_conf'
    )

    return NamingCandidate(
        func_addr=func_addr,
        name=result.name,
        role=result.role,
        confidence=result.confidence,
        rationale=result.rationale,
        tool_calls=result.tool_calls,
        source=source,
    )


def name_batch(
    agent_loop,
    func_addrs:         list[int],
    confidence_threshold: float = 0.6,
    binary_sha256:      str = '',
    persist:            bool = True,
) -> list[NamingCandidate]:
    """
    Name a batch of functions, persisting high-confidence results to func_id_db.
    Skips functions already in func_id_db with CONFIRMED confidence.
    """
    results = []
    already_confirmed = _fetch_confirmed_set(agent_loop._func_db, binary_sha256)

    for addr in func_addrs:
        if addr in already_confirmed:
            continue

        candidate = name_function(agent_loop, addr)
        results.append(candidate)

        if persist and candidate.confidence >= confidence_threshold:
            agent_loop.persist_result(
                agent_loop._build_result(
                    addr, 'name_function',
                    {
                        'name': candidate.name,
                        'role': candidate.role,
                        'confidence': candidate.confidence,
                        'rationale': candidate.rationale,
                    },
                    candidate.tool_calls,
                    True,
                ),
                binary_sha256=binary_sha256,
            )

    return results


def _fetch_confirmed_set(func_db, binary_sha256: str) -> set[int]:
    """Return VA set of CONFIRMED functions already in func_id_db for this binary."""
    if func_db is None or not binary_sha256:
        return set()
    try:
        rows = func_db._con.execute(
            "SELECT f.va FROM functions f"
            " JOIN binaries b ON f.binary_id=b.id"
            " WHERE b.sha256=? AND f.confidence='CONFIRMED'",
            (binary_sha256,)
        ).fetchall()
        return {r['va'] for r in rows}
    except Exception:
        return set()
