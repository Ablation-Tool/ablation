# AgentLoop

  - [What is the ReAct pattern?](#what-is-the-react-pattern)
  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [False positives](#false-positives)
  - [Pipeline position](#pipeline-position)
  - [Reading output](#reading-output)
  - [See also](#see-also)

**Files:** `ablation/analyzers/llm_analyst/agent_loop.py` · `ablation/analyzers/llm_analyst/tool_registry.py`

---

## What is the ReAct pattern? <sup>[↑](#agentloop)</sup>

ReAct (Reason + Act, Yao et al. 2022) is an agent architecture in which a language model interleaves reasoning traces and tool calls in a single conversation loop. At each step the model produces either a Thought (free-text reasoning about what it has observed so far and what to do next) or a tool invocation (a structured call to an external analysis function). The tool's output is fed back into the conversation as an Observation, and the model continues until it has enough information to produce a final Answer. The loop terminates when the model emits a stop signal or reaches a maximum step count.

The key advantage of ReAct over single-shot prompting for binary analysis is that the model can adaptively select which analysis tools to run based on what it learns at each step. A one-shot prompt cannot adjust its query after seeing that a function calls `malloc` and `memcpy`; the ReAct agent can follow up immediately by running `FuncProfiler` on the exact function identified in the previous step, then `TaintTracker` on the allocation candidate found by `FuncProfiler`. The tool calls are not scripted in advance: the model navigates the analysis space guided by what each tool returns.

`AgentLoop` implements the ReAct loop against the Anthropic Claude API. The `ToolRegistry` wraps Ablation analysis tools (semantic search, profiling, taint tracking, disassembly windowing) in the JSON schema format required by Claude's tool-use API. `ContextBuilder` assembles the initial system prompt from the `BinaryContext` summary, known function names, and the analysis objective. `AgentLoop.run()` sends the prompt, handles tool calls in a loop, and returns an `AnalysisResult` with the recovered function name, role, confidence score, and any vulnerability hypotheses the model reported.

## Why this exists <sup>[↑](#agentloop)</sup>

1. **Semantic search identifies function candidates by embedding similarity, but for functions whose role cannot be inferred from adjacent strings or callees alone, reasoning over the actual disassembly is required.** `AgentLoop.run()` gives Claude a set of RE tools: disassembly, CFG, cross-references, string lookup, import lookup, and function DB query; and a task ("name this function" or "find vulnerabilities") and lets it reason through the analysis in a bounded multi-turn loop. The result is a structured `AnalysisResult` with a proposed name, role, and confidence score.

2. **The `RAGRetriever` injects prior analysis results as context before the first tool call: if the same function VA has been analyzed before on any binary with the same SHA-256, the prior result is loaded.** This means the analyst loop does not re-analyze functions it has already confirmed, and can use prior naming to resolve callees. `persist_result()` saves results to the function database so they are available in future sessions.

3. **A budget governor `max_tool_calls`, default 10 and a loop detector identical tool+args terminates with a warning prevent unbounded token consumption.** Without these guards, an unconstrained agentic loop over a complex function would run until context is exhausted. The budget governor ensures that even if Claude does not call `done()` within budget, `run()` returns the best available `AnalysisResult` from the last tool call.

---

## How it works <sup>[↑](#agentloop)</sup>

```mermaid
flowchart TD
    A(["AgentLoop(registry, product, version, max_tool_calls=10)"]):::input --> B["ContextBuilder: system prompt with product/version/binary_hint\nRAGRetriever: load prior results for func_va from FuncDB"]:::primary
    B:::primary --> C["AgentLoop.run(func_addr, task='name_function', callees, callers, strings, cfg_summary)"]:::secondary
    C:::secondary --> D["Turn 1: user message with function context\n(addr, callees, callers, strings, size_hint, prior)"]:::tertiary
    D:::tertiary --> E["Claude responds with tool_use blocks\n↓ dispatch via ToolRegistry"]:::tertiary
    E:::tertiary --> F{"Tool called"}:::neutral
    F:::neutral --> G["get_disassembly(va) → capstone disasm text"]:::tertiary
    F:::neutral --> H["get_cfg(va) → basic-block structure summary"]:::tertiary
    F:::neutral --> I["get_xrefs(va) → callers + callees"]:::tertiary
    F:::neutral --> J["get_strings(va) → string refs in function body"]:::tertiary
    F:::neutral --> K["get_imports(va) → PLT imports used in function"]:::tertiary
    F:::neutral --> L["query_func_db(name) → prior analysis results for similar functions"]:::tertiary
    F:::neutral --> M["done(name, role, confidence, cve_hypothesis) → terminates loop"]:::tertiary
    G:::tertiary --> N["Inject tool_result as user message\nReturn to Claude"]:::tertiary
    H:::tertiary --> N:::tertiary
    I:::tertiary --> N:::tertiary
    J:::tertiary --> N:::tertiary
    K:::tertiary --> N:::tertiary
    L:::tertiary --> N:::tertiary
    M:::tertiary --> O(["AnalysisResult: func_addr, name, role, confidence, cve_hypothesis, tool_call_count"]):::output
    N:::tertiary --> E:::tertiary
    E:::tertiary --> P{"max_tool_calls reached?"}:::neutral
    P:::neutral -->|Yes| Q(["Return best AnalysisResult from last state"]):::output
    P:::neutral -->|No| E:::tertiary
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#546e7a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#6a1b9a,stroke-width:2px
    linkStyle 8 stroke:#6a1b9a,stroke-width:2px
    linkStyle 9 stroke:#6a1b9a,stroke-width:2px
    linkStyle 10 stroke:#6a1b9a,stroke-width:2px
    linkStyle 11 stroke:#6a1b9a,stroke-width:2px
    linkStyle 12 stroke:#6a1b9a,stroke-width:2px
    linkStyle 13 stroke:#6a1b9a,stroke-width:2px
    linkStyle 14 stroke:#6a1b9a,stroke-width:2px
    linkStyle 15 stroke:#6a1b9a,stroke-width:2px
    linkStyle 16 stroke:#6a1b9a,stroke-width:2px
    linkStyle 17 stroke:#6a1b9a,stroke-width:2px
    linkStyle 18 stroke:#2e7d32,stroke-width:3px
    linkStyle 19 stroke:#6a1b9a,stroke-width:2px
    linkStyle 20 stroke:#546e7a,stroke-width:2px
    linkStyle 21 stroke:#2e7d32,stroke-width:3px
    linkStyle 22 stroke:#6a1b9a,stroke-width:2px
```

### AnalysisResult fields <sup>[↑](#agentloop)</sup>

| Field | Type | Description |
|:---|:---|:---|
| `func_addr` | `int` | VA of the analyzed function |
| `name` | `str` | Proposed function name snake_case |
| `role` | `str` | Role description for example "network input handler" |
| `confidence` | `float` | 0.0–1.0 confidence in the naming/role |
| `cve_hypothesis` | `str` | Optional vulnerability hypothesis (populated by `run_patch()`) |

---

## Usage <sup>[↑](#agentloop)</sup>

```python
from ablation.analyzers.llm_analyst.agent_loop import AgentLoop
from ablation.analyzers.llm_analyst.tool_registry import ToolRegistry
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/target.elf')

# Build registry (provides tools to Claude)
registry = ToolRegistry('/path/to/target.elf', func_db=ctx._func_db)

# Create analyst loop
loop = AgentLoop(
    registry,
    func_db=ctx._func_db,
    product='my-appliance',
    version='1.x',
    binary_hint='FortiOS 7.4 management daemon',
    max_tool_calls=10,
)

# Name a single function
result = loop.run(
    func_addr=0x1fa00,
    task='name_function',
    callees=['recv', 'malloc', 'memcpy'],
    callers=['http_dispatch'],
    cfg_summary='12 blocks, 1 loop, 3 exits',
)
print(f"{result.func_addr:#x}: {result.name}  ({result.role})  conf={result.confidence:.2f}")

# Patch analysis — find what changed between two function versions
result_patch = loop.run_patch(
    old_func_addr=0x1fa00,
    new_func_addr=0x1fc80,
    task='find_vulnerability',
)
print(result_patch.cve_hypothesis)

# Persist to function DB for future sessions
loop.persist_result(result, binary_sha256='<sha256>')
```

---

## Example output <sup>[↑](#agentloop)</sup>

The following illustrates the `AnalysisResult` output format. Actual names and addresses are binary-specific.

```
<func-va>: parse_http_request  (HTTP request body parser — reads Content-Length then memcpy)
  role: network input handler
  confidence: 0.87
  tool_calls: 6

run_patch() cve_hypothesis:
  "Missing bounds check on Content-Length before memcpy at <va>: attacker-controlled
   length from recv() copied to fixed-size stack buffer without size validation."
```

---

## False positives <sup>[↑](#agentloop)</sup>

**`max_tool_calls=10` is a hard budget: functions that require more tool calls to analyze will have lower-confidence results.** Increase `max_tool_calls` for complex functions large CFGs, indirect dispatch, heavily-inlined code at the cost of more API tokens per function. The default of 10 is appropriate for 90% of handler-class functions.

**`query_func_db(name)` searches for prior results by name similarity: a query for "parse" may return unrelated functions that were named with "parse" in their description.** The RAG retriever uses embedding similarity, not exact match. Prior results are hints, not ground truth: Claude's `confidence` score accounts for prior result relevance.

---

## Pipeline position <sup>[↑](#agentloop)</sup>

Run `AgentLoop` as a targeted tool on `SemanticSearcher` top candidates that need human-quality naming and role analysis, not as a bulk pass over all functions token cost is per-function. Use `run()` for naming and `run_patch()` for diff-based vulnerability hypothesis generation after `VersionTracker.find_homolog()` identifies a changed function.

---

## Reading output <sup>[↑](#agentloop)</sup>

`AgentLoopctx, task.runfunc_addr` returns an `AnalysisResult`:

| Attribute | Content |
|:---|:---|
| `func_addr` | VA of the analyzed function |
| `name` | Inferred function name |
| `role` | Role tag for example `'network input handler'`, `'parser'` |
| `confidence` | Float 0.0–1.0 |
| `rationale` | Plain-language explanation of the naming/role evidence |
| `vuln_notes` | Vulnerability hypothesis notes, if requested |
| `tool_calls` | Count of tool calls made during the loop |
| `finished` | `True` if `done()` was called; `False` if the tool-call budget was exhausted |
| `model` | Claude model ID used |
| `task` | Task name for example `'name_function'`, `'vulnerability_hypothesis'` |

`AgentLoop.run_patchfunc_addr_v1, func_addr_v2` returns an `AnalysisResult` for patch diff analysis.

---

## See also <sup>[↑](#agentloop)</sup>

- [Assisted Function Naming](assisted-function-naming.md): higher-level interface wrapping `AgentLoop` for batch function naming
- [Assisted Vulnerability Hypotheses](assisted-vulnerability-hypotheses.md): `run_patch()` usage for patch-based CVE hypothesis
- [Semantic Search](semantic-search.md): identifies top candidates for `AgentLoop` deeper analysis
- [FuncProfiler](func-profiler.md): generates `callees`, `callers`, `cfg_summary` for the `run()` call
