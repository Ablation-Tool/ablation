# LLM Analyst llm_analyst

ReAct agent loop for LLM-assisted binary analysis. Seven modules under `ablation/analyzers/llm_analyst/`: `agent_loop.py`, `context_builder.py`, `rag_retriever.py`, `tool_registry.py`, and three task modules in `tasks/`: `vuln_hypothesis.py`, `function_namer.py`, `struct_reconstructor.py`.

---

## Why this exists

1. **Semantic gaps that pattern matching cannot close.** SemanticSearcher and SinkArgClassifier reach a ceiling: they can identify that a function calls `memcpy` with an argument from `recv`, but cannot assess whether an intervening `if len > MAX` actually prevents overflow. The LLM analyst closes this gap by reasoning over disassembly, callee names, and prior findings in a structured loop.

2. **Tool-calling loop prevents hallucination drift.** A single-shot LLM call with raw disassembly produces confident wrong answers. The ReAct loop forces the model to use tools `get_disassembly`, `get_strings`, and `get_imports` to retrieve specific evidence before committing. `done()` is the only exit: the model cannot stop without stating a name, role, and rationale.

3. **Pre-screening and RAG amortize the token cost.** `vuln_hypothesis.py` skips Claude calls entirely for functions with no dangerous callees. `rag_retriever.py` injects confirmed prior findings from `func_id_db`, so the model often needs only 1–2 tool calls (usually just `done()`).

---

## Architecture

```
AgentLoop (agent_loop.py)
  ├── ContextBuilder (context_builder.py)  — assembles system + user prompt
  ├── RAGRetriever (rag_retriever.py)      — prior findings from func_id_db
  └── ToolRegistry (tool_registry.py)      — dispatch table for tools

tasks/
  ├── function_namer.py     — name_function task entry point
  ├── vuln_hypothesis.py    — vulnerability hypothesis with pre-screening
  └── struct_reconstructor.py — struct layout inference from memory accesses
```

---

## Usage

```python
from ablation.analyzers.func_id_db import FuncDB
from ablation.analyzers.llm_analyst.tool_registry import ToolRegistry
from ablation.analyzers.llm_analyst.agent_loop import AgentLoop
from ablation.analyzers.llm_analyst.tasks.function_namer import name_batch

func_db = FuncDB.open('~/.ablation/func_id.db')
registry = ToolRegistry('/path/to/binary.so', func_db=func_db)
loop = AgentLoop(registry, func_db=func_db, product='my-target', version='1.0')

# Name a batch of unknown functions
binary_sha256 = func_db.sha256_of('/path/to/binary.so')
results = name_batch(loop, unknown_addrs, binary_sha256=binary_sha256)
for c in results:
    print(f'{c.func_addr:#x}: {c.name} ({c.confidence:.2f}) — {c.rationale[:80]}')
```

---

## agent_loop.py

**AgentLoop** drives a Claude ReAct loop. Key parameters:
- `max_tool_calls=10`: hard budget; loop exits whether or not `done()` is called
- Loop detector: identical `tool_name, args` pair injects `LOOP_DETECTED` error and blocks the call
- `persist_result()`: writes to `func_id_db` at `confidence >= 0.5`

`run_patchv1, v2, disasm_v1, disasm_v2`: single-shot patch analysis no tool loop needed; disasm already injected.

---

## context_builder.py

**ContextBuilder** assembles the hierarchical prompt. Context ordering (most signal first per O'Reilly "Prompt Engineering for LLMs"):
1. Prior findings from `func_id_db` capped at 5, notes trimmed to 150 chars
2. Callee names strongest semantic signal
3. String xrefs capped at 10, trimmed to 120 chars each
4. CFG summary
5. Raw disassembly last: token-expensive

---

## rag_retriever.py

**RAGRetriever** retrieves prior findings from `func_id_db` via four strategies in priority order:
1. Exact binary SHA256 + VA match
2. Callee-set overlap LIKE query, parameterized, no injection risk
3. Role-based match
4. Name fuzzy match

Results ranked by callee overlap score; capped at `_MAX_RESULTS=8`.

---

## tool_registry.py

**ToolRegistry** wraps binary analysis tools for the agent loop. Uses `angr.Project(binary_path, auto_load_libs=False)` (lazy: built on first `get_disassembly` call). Tool output trimmed to `_MAX_RESULT_CHARS=4000`. Available tools: `get_disassembly`, `get_cfg`, `get_xrefs`, `get_strings`, `get_imports`, `query_func_db`, `done`.

---

## tasks/vuln_hypothesis.py

Pre-screens PLT callee names against `_DANGEROUS_IMPORTS` strcpy, memcpy, malloc, free, exec … before sending to Claude. Functions with no dangerous callees return `confidence=0.0` without a Claude call. `scan_batch()` filters by `min_confidence=0.5`.

---

## tasks/function_namer.py

`name_function()` pre-fetches `get_imports` and `get_strings` before the loop, injecting them as context to reduce tool calls. Skips functions already `CONFIRMED` in `func_id_db` for the same binary. `name_batch()` writes high-confidence results back to `func_id_db`.

---

## tasks/struct_reconstructor.py

`scan_struct_accesses()` parses `get_disassembly()` output for `[reg+offset]` memory patterns using a named-group regex. Filters stack-relative (rsp/rbp) accesses. Offset range clamped to `max_offset=0x2000`. Groups by base register; requires ≥2 accesses per register before reporting. `run_struct_reconstruction()` builds the prompt and delegates to `AgentLoop`.

---

## See also

- [Taint Analysis](taint-analysis.md): lower-cost automated taint tracking before LLM analysis
- [Semantic Searcher](semantic-code-search.md): initial candidate identification before LLM analysis
- [Function Profiler](single-function-profiling.md): function characterization used alongside naming
