# MCP Grammar Fuzzer

**File:** `modules/mcp_grammar_fuzzer.py`

## Why this exists

Atheris-based grammar fuzzer targeting prompt injection via poisoned MCP tool schemas. Attack surface: `description` fields rendered verbatim into LLM context, `name` fields used in routing, `inputSchema` property descriptions injected into tool-call reasoning, and cross-server exfiltration (Server A description reads Server B output). Transport: JSON-RPC 2.0 over stdio.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads. No HTTP reads. No lief.parse(). Subprocess usage is for launching the MCP target under test — uses `subprocess.Popen` with explicit argument list (no shell=True).
