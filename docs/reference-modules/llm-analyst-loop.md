<a id="agentloop"></a>
# AI-Guided Analysis

Use an LLM to propose a function name and role, reconstruct behavior, or compare two function versions from pre-fetched binary evidence and relevant prior results.

**Files:** `ablation/analyzers/llm_analyst/agent_loop.py` · `ablation/analyzers/llm_analyst/rag_retriever.py`

---

## What the current implementation does

`AgentLoop` retains its historical name, but the current implementation is **single-shot analysis**, not an iterative ReAct tool-calling loop.

For each `run()` call, Ablation:

1. Retrieves relevant prior function records when a function database is configured.
2. Pre-fetches disassembly, strings, imports, and a CFG summary through `ToolRegistry` when the caller does not supply them.
3. Builds one prompt containing the task, binary context, prior findings, and collected evidence.
4. Makes one LLM request through the Anthropic SDK or Claude CLI.
5. Parses the JSON response into an `AnalysisResult` and records execution metadata when supported by the database.

The model is explicitly instructed that no tools are available in the child session. `tool_calls` in the result counts local evidence pre-fetch operations; it does not count model-initiated tool rounds.

## When to use it

Use AI-guided analysis after static tools have identified a function worth reviewing. It is suited to targeted naming, role classification, and vulnerability or patch hypotheses—not an unattended bulk replacement for disassembly, taint tracking, or path validation.

Treat names, roles, and vulnerability notes as proposals. Confirm security findings with byte-level evidence and appropriate static or dynamic analysis before registering or disclosing them.

## Prerequisites

- A binary and a function virtual address.
- A `ToolRegistry` for the binary.
- Either the Anthropic Python package and an API key, or an authenticated `claude` CLI available on `PATH`.
- Optional: a `FuncDB` containing prior function records.

Install the SDK extra when using API transport:

```bash
pip install 'ablation-tool[llm]'
```

Set `ANTHROPIC_API_KEY` in the environment or pass `api_key=` explicitly. `ANTHROPIC_WORKSPACE_ID` is optional and is forwarded as an Anthropic workspace header. Without an API key, `AgentLoop` invokes `claude -p -` in an isolated temporary working directory with file, shell, web, and agent tools denied. CLI transport reports zero token counts.

## Model selection

An explicit `model=` overrides task-based routing. Otherwise, current defaults are:

| Task | Default model |
|:---|:---|
| `name_function`, `struct_reconstruct` | `claude-haiku-4-5` |
| `vuln_hypothesis`, `patch_analysis` | `claude-sonnet-4-6` |
| `exploit_chain` | `claude-opus-4-7` |
| Other task names | `claude-sonnet-4-6` |

Model availability and billing depend on the configured Anthropic account or Claude CLI subscription.

## Analyze a function

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.llm_analyst.agent_loop import AgentLoop
from ablation.analyzers.llm_analyst.tool_registry import ToolRegistry

ctx = BinaryContext.load_or_build('/path/to/target.elf')
func_db = ctx._func_db
registry = ToolRegistry('/path/to/target.elf', func_db=func_db)

loop = AgentLoop(
    registry,
    func_db=func_db,
    product='example-appliance',
    version='1.0',
    binary_hint='network management daemon',
    binary_sha256=ctx.sha256,
    verbose=True,
)

result = loop.run(
    func_addr=0x1FA00,
    task='name_function',
    callees=['recv', 'malloc', 'memcpy'],
    callers=['http_dispatch'],
    cfg_summary='12 blocks, 1 loop, 3 exits',
)

print(result.name, result.role, result.confidence)
print(result.rationale)
```

If `strings` or `cfg_summary` is omitted, the registry attempts to retrieve it. Disassembly and imports are also pre-fetched locally. Failures retrieving optional context degrade to empty or unavailable context; transport failures raise `RuntimeError` rather than silently creating a successful result.

`max_tool_calls` remains in the constructor for prompt/context compatibility, but it is not an iterative tool-loop budget in the current single-call implementation.

## Compare two function versions

`run_patch()` requires both disassembly strings and version labels; it does not accept a task argument or fetch the two versions automatically.

```python
patch_result = loop.run_patch(
    func_addr_v1=0x1FA00,
    func_addr_v2=0x1FC80,
    disasm_v1=old_disassembly,
    disasm_v2=new_disassembly,
    version_v1='1.0',
    version_v2='1.1',
)

print(patch_result.vuln_notes)
```

Use a verified homolog match before comparing functions. Similar-looking but unrelated functions can produce a convincing yet invalid patch narrative.

## Prior-result retrieval

`RAGRetriever` retrieves up to eight trimmed records from SQLite using these strategies:

1. Exact binary SHA-256 and function address.
2. Overlap with known callee names.
3. A matching role hint.
4. A fuzzy name hint.

Confirmed records sort before candidates. Each result includes `epistemic` and `retrieval_source` so the prompt can distinguish confirmed prior work from unverified candidates. This retrieval uses database queries, not the vector search implemented by `SemanticSearcher`.

## Persist a reviewed result

```python
loop.persist_result(result, binary_sha256=ctx.sha256)
```

Persistence is skipped when no function database is configured, confidence is below `0.5`, or the proposed name is empty. Stored records use `ANGR_INFERRED`, not `CONFIRMED`. Review the result before treating it as established analyst knowledge.

## AnalysisResult fields

| Field | Meaning |
|:---|:---|
| `func_addr` | Address supplied for the analyzed function. |
| `name` | Proposed snake-case name, or `unknown__parse_failed` after a response-parse failure. |
| `role` | Proposed role classification. |
| `confidence` | Model-reported score from 0.0 to 1.0; not calibrated proof of correctness. |
| `rationale` | Model's explanation for the proposal. |
| `vuln_notes` | Vulnerability or patch notes, if any. |
| `tool_calls` | Number of local evidence pre-fetch operations. |
| `finished` | `True` when the response parsed successfully; otherwise `False`. |
| `model` | Model selected for the task. |
| `task` | Task supplied to `run()` or `patch_analysis` for `run_patch()`. |

## Limitations

- Pre-fetched context can be incomplete or misleading, especially with incorrect function boundaries, unresolved indirect calls, or obfuscation.
- Prior results are evidence, not ground truth. Exact matches are strongest; callee, role, and name matches can associate unrelated functions.
- A high model confidence value does not validate a vulnerability. Confirm reachability, source control, sanitization, and byte evidence independently.
- The SDK has a 512-token response limit and the CLI has a 120-second subprocess timeout. Large functions may require narrower evidence or manual analysis.
- A parse failure returns `finished=False` with zero confidence. Transport errors are raised separately.

## See also

- [Semantic Code Search](semantic-code-search.md): finds candidate functions before targeted LLM analysis.
- [Function Identification & Naming](function-identity-database.md): stores prior function records and execution metadata.
- [Binary Diffing & Patch Tracking](../workflows/cross-version.md): finds corresponding functions before patch comparison.
- [Vulnerability Hypothesis Tracking](hypothesis-engine-2.md): tracks competing claims and evidence separately from a single LLM response.
