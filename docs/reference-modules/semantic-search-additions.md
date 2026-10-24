# SemanticSearcher: KNOWN_QUERIES and KNOWN_PLT_PATTERNS

## Why these additions exist

Two gaps motivated this addition:

1. Each analyst who started a new engagement had to write semantic query strings from scratch for common vuln classes. Inconsistent query phrasing reduced recall across sessions.
2. PLT import pre-screening before semantic search was undocumented. Without a reference set, analysts ran full semantic queries on binaries that lacked the relevant imports entirely.

## KNOWN_QUERIES

A module-level dict mapping vuln class key to a natural-language semantic query string. Pass these directly to `searcher.query()`.

```python
from ablation.analyzers.semantic_search import SemanticSearcher, KNOWN_QUERIES

searcher = SemanticSearcher(ctx)
searcher.build_corpus()

results = searcher.query(KNOWN_QUERIES['sign_extension_packet'], top_k=5)
```

**Vuln classes covered:**

| Key | Description |
| --- | ----------- |
| `anti_analysis_apis` | Functions calling debugger/VM detection APIs |
| `sign_extension_packet` | Sign-extension from packet field used as length |
| `hallucinated_dependency` | AI-hallucinated package name references |
| `float_to_int_narrowing` | Float-to-int truncation used as allocation size |
| `auth_bypass_framing` | Prompt injection framing strings in system prompts |

## KNOWN_PLT_PATTERNS

A module-level dict mapping a subset of vuln class keys to frozensets of PLT import names. Use to pre-screen before running the full semantic query.

```python
from ablation.analyzers.semantic_search import KNOWN_PLT_PATTERNS

plt_names = frozenset(n.split('@')[0].lstrip('_') for _, n in ctx.plt.items())
if plt_names & KNOWN_PLT_PATTERNS['anti_analysis_apis']:
    results = searcher.query(KNOWN_QUERIES['anti_analysis_apis'])
```

**PLT patterns available:** `anti_analysis_apis` (12 import names), `float_to_int_narrowing` (8 import names).

`sign_extension_packet`, `hallucinated_dependency`, and `auth_bypass_framing` have no PLT pattern sets. Run their semantic queries unconditionally on candidate binaries.

## Severity and triage

`KNOWN_QUERIES` and `KNOWN_PLT_PATTERNS` do not produce findings directly. Feed `searcher.query()` results into `FuncProfiler` and `TaintTracker` per the standard tool-selection workflow.
