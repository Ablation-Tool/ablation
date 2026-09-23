"""
tasks/vuln_hypothesis.py — Identify vulnerability potential in binary functions.

Focuses on signals the O'Reilly taint analysis research identified as high-value:
  - strcpy / memcpy / sprintf callees without preceding bound checks
  - Integer arithmetic on externally-controlled values before allocation
  - Use-after-free patterns (free followed by dereference of same pointer)
  - Unchecked return values from malloc / calloc

Pre-screens before sending to LLM: checks callee names for known dangerous functions.
If no dangerous callees are found, returns LOW confidence without a Claude call.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


# Callees that warrant vuln hypothesis analysis
_DANGEROUS_IMPORTS = frozenset({
    'strcpy', 'strncpy', 'sprintf', 'vsprintf', 'gets',
    'memcpy', 'memmove', 'memset',
    'malloc', 'calloc', 'realloc', 'free',
    'strcat', 'strncat', 'strtol', 'strtoul', 'atoi', 'atol',
    'printf', 'fprintf', 'snprintf',
    'system', 'execve', 'popen',
})

_SAFE_COPY_REPLACEMENTS = frozenset({
    'strlcpy', 'strlcat', 'strncpy_s', 'memcpy_s',
})


@dataclass
class VulnHypothesis:
    func_addr:      int
    pre_screened:   bool          # True = dangerous callees found in pre-screen
    dangerous_sigs: list[str]     # callee names that triggered pre-screen
    vuln_notes:     str
    confidence:     float
    tool_calls:     int
    finished:       bool


def hypothesize(
    agent_loop,
    func_addr: int,
    binary_sha256: str = '',
) -> VulnHypothesis:
    """
    Run vulnerability hypothesis analysis on a function.
    Pre-screens callee names; skips Claude call if no dangerous callees found.
    """
    reg = agent_loop._registry
    dangerous = []
    callees = []
    strings = []

    # Pre-fetch imports and strings for pre-screening and context
    try:
        imports_json = reg._get_imports(func_addr)
        imports = json.loads(imports_json).get('imports', [])
        callees = [imp['name'] for imp in imports]
        dangerous = [
            name for name in callees
            if any(d in name.lower() for d in _DANGEROUS_IMPORTS)
            and not any(s in name.lower() for s in _SAFE_COPY_REPLACEMENTS)
        ]
    except Exception:
        pass

    try:
        strings_json = reg._get_strings(func_addr)
        strings = json.loads(strings_json).get('strings', [])
    except Exception:
        pass

    if not dangerous:
        # No dangerous callees — return low-confidence skip without a Claude call
        return VulnHypothesis(
            func_addr=func_addr,
            pre_screened=False,
            dangerous_sigs=[],
            vuln_notes='',
            confidence=0.0,
            tool_calls=0,
            finished=False,
        )

    # Dangerous callees found — run full LLM analysis
    result = agent_loop.run(
        func_addr=func_addr,
        task='vuln_hypothesis',
        callees=callees or None,
        strings=strings or None,
    )

    return VulnHypothesis(
        func_addr=func_addr,
        pre_screened=True,
        dangerous_sigs=dangerous,
        vuln_notes=result.vuln_notes or result.rationale,
        confidence=result.confidence,
        tool_calls=result.tool_calls,
        finished=result.finished,
    )


def scan_batch(
    agent_loop,
    func_addrs: list[int],
    binary_sha256: str = '',
    min_confidence: float = 0.5,
) -> list[VulnHypothesis]:
    """
    Scan a batch of functions for vulnerability potential.
    Only sends functions with dangerous callees to Claude.
    Returns findings with confidence >= min_confidence.
    """
    findings = []
    for addr in func_addrs:
        hyp = hypothesize(agent_loop, addr, binary_sha256)
        if hyp.pre_screened and hyp.confidence >= min_confidence:
            findings.append(hyp)
    findings.sort(key=lambda h: h.confidence, reverse=True)
    return findings
