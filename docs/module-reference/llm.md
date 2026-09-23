# LLM Analyst

Claude as a first-class RE participant in a ReAct tool-calling loop.

---

## LlmAnalyst

**File:** `ablation/analyzers/llm_analyst/`

**Requires:** `pip install ablation[llm]` (adds `anthropic>=0.30.0`)

LlmAnalyst runs Claude (claude-sonnet-5 by default) in a ReAct (Reasoning + Acting) loop over
an Ablation-instrumented binary. Claude issues tool calls to query the binary context --
callers, callees, strings, disassembly -- and synthesizes the results into a function name,
confidence score, and vulnerability hypothesis.

RAGRetriever retrieves confirmed findings from `func_id.db` by embedding similarity and
injects them into the context window. This grounds Claude's analysis in concrete patterns from
prior engagements rather than pure inference.

### Components

| Module | Role |
|---|---|
| `AgentLoop` | ReAct loop orchestrator -- runs Claude, dispatches tool calls, collects results |
| `ToolRegistry` | Registers Ablation tools as Claude tool-use schemas; executes tool calls against the binary |
| `ContextBuilder` | Builds the initial context window: binary summary, named functions, relevant prior findings |
| `RAGRetriever` | Retrieves similar confirmed findings from `func_id.db` by embedding similarity |

### Quick start

```python
from ablation.analyzers.llm_analyst import AgentLoop, ToolRegistry
from ablation.analyzers.func_id_db import FuncDB

db = FuncDB.open('~/.ablation/func_id.db')
reg = ToolRegistry('/path/to/binary.so', func_db=db)
loop = AgentLoop(reg, func_db=db, product='libservice', version='1.0')

# Name a function automatically
result = loop.run(0x1000, task='name_function')
print(result.name)        # "proto_parse_message"
print(result.confidence)  # 0.92

# Generate a vulnerability hypothesis
result = loop.run(0x1000, task='vuln_hypothesis')
print(result.hypothesis)
# "Function advances AVP pointer by wire-supplied length without minimum size check.
#  If length=0, pointer never advances, infinite loop results."
```

### Tools available to Claude

| Tool | Description |
|---|---|
| `get_callees` | Get all functions called by the target function |
| `get_callers` | Get all callers of the target function |
| `get_strings` | Get all strings referenced by the target function |
| `disassemble` | Disassemble N instructions starting from a VA |
| `get_context` | Get BinaryContext summary for the binary |
| `get_prior_findings` | Retrieve similar confirmed findings from func_id.db |
| `get_cfg` | Get basic block structure for a function |
| `name_function` | Register a name in NameRegistry (write tool) |

### ReAct loop behavior

1. **Reason:** Claude analyzes the current information -- callers, callees, strings
2. **Act:** Claude issues a tool call to gather more information
3. **Observe:** The tool result is injected back into the conversation
4. **Repeat:** Claude reasons over the new information and issues another tool call if needed
5. **Conclude:** Claude outputs a final name, confidence score, and hypothesis

The loop runs until Claude issues no further tool calls, or until a 10-iteration safeguard
triggers to prevent runaway token consumption on ambiguous functions.

### RAG retrieval

RAGRetriever fetches the top-K most similar confirmed findings from `func_id.db` by BERT
embedding cosine similarity. These are prepended to Claude's context window:

```
[Prior finding: vendor-a, service_parse_record, confirmed buffer overflow]
[Prior finding: vendor-b, proto_decode_frame, confirmed infinite loop]
```

This grounding improves name accuracy on protocol parsers where function behavior (TLV
advance, length check, memcpy) is shared across vendors.

### When to use LlmAnalyst

LlmAnalyst performs best when:

- The function has clear callee structure (external calls that hint at its role)
- Prior similar findings exist in `func_id.db` (RAG gives Claude concrete anchors)
- You want a structured hypothesis before committing to a manual disassembly session

LlmAnalyst performs poorly when:

- The function is very small (fewer than 10 instructions) -- too little signal
- The function has only internal calls with no PLT symbols -- Claude cannot infer its role
- The binary has no string references at all (fully stripped data segments)

In those cases, fall back to manual FuncProfiler triage or a targeted SemanticSearcher query.

### Cost and rate limits

LlmAnalyst uses Claude Sonnet 5 by default. A typical `name_function` run consumes 3 to 8
API calls of roughly 2,000 tokens each. A `vuln_hypothesis` run on a complex function uses
up to 15 calls. At current Anthropic pricing, expect $0.01 to $0.05 per function analysis.

Use `claude-haiku-4-5-20251001` for cost-sensitive batch runs at reduced accuracy:

```python
loop = AgentLoop(reg, func_db=db, model='claude-haiku-4-5-20251001')
```
