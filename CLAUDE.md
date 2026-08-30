# Ablation — Project Context

## What this tool is

Ablation is a binary reverse engineering tool built around semantic BERT embeddings. Its core capability: read a stripped firmware binary with no symbols, no source, no debug info — encode what every function *does* — then either (1) find functions matching a vulnerability pattern query, or (2) track a specific function across firmware versions even when its address, name, and instruction sequence have all changed.

**This is the main feature of the tool.** Everything else (cross-version diffing, patch epoch attribution, Jaccard similarity) is built on top of the same semantic encoding pipeline.

---

## Semantic RE capability (proven working, load this first)

**Module:** `modules/semantic_search.py`  
**Validation test:** `tests/test_bert_cross_version.py`

### How it works

1. Disassemble function with capstone from prologue
2. Normalize instructions through BinFuse 11-category opcode abstraction (`mov`/`ldr`/`lw` → `DATA_TRANSFER_OP` etc.) + Markov transitions — makes the representation architecture-agnostic
3. Build a behavioral description string: `"<name> | role: <role> | calls: <c1>, <c2> | asm: OP OP OP | vuln: <pattern>"`
4. Encode with `sentence-transformers/all-MiniLM-L6-v2` (sweep) or `all-mpnet-base-v2` (corpus)
5. Cosine similarity query — returns ranked candidates

### Vulnerability sweep pattern

```python
from modules.semantic_search import describe_function
from sentence_transformers import SentenceTransformer
import numpy as np

model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')

# Build corpus: encode every function in the binary
corpus_vecs = model.encode([f['desc'] for f in funcs], normalize_embeddings=True)

# Query: describe what dangerous code looks like
query = 'DHCP_DAEMON | calls: memcpy | vuln: memcpy called with length derived from packet option byte without upper-bound check'
qvec = model.encode(query, normalize_embeddings=True)

scores = corpus_vecs @ qvec
top = np.argsort(scores)[::-1][:8]
```

885 functions in an 11MB binary encodes in ~35 seconds on CPU.

### Cross-version homolog tracking

Give it a function from version A. It finds the equivalent in version B even if:
- Address moved (28 MB in the lina 9.14→9.22 case)
- Function was renamed (`attr_list_add_impl` → `class_attr_parse_fn`)
- Code was recompiled with different optimization flags

**Proven result:** lina 9.14 vs 9.22 — homolog similarity 0.82, separation from unrelated function 5.9x. Both assertions pass.

---

## Architecture

```
modules/
├── semantic_search.py     SemanticSearcher, describe_function, normalize_asm, WhiteningTransform
├── func_id_db.py          SQLite function identity store
├── llm_analyst/           Claude ReAct loop for active RE
└── cisco_*.py             Cisco-specific RE modules
tests/
└── test_bert_cross_version.py   lina 9.14 vs 9.22 validation
```

---

## Active RE work

**Current target:** Junos EVO 23.4R2.14 — pre-auth memory corruption hunt in jdhcpd  
**Binary:** `/tmp/.../scratchpad/evo-re64/usr/sbin/jdhcpd` (11.6MB, PIE, no canary, no RELRO)  
**BERT sweep complete:** 885 functions encoded, 7 query profiles run  
**Pending manual verification:** `0x294ef0`, `0x294f30`, `0x3a9c00` (appeared in 5+ query profiles)

Confirmed findings in sshpie/ablation git history (see `git log --oneline`).

---

## Hard rules

- Active GitHub account: `sshpie`. ALL repo ops via `gh` CLI as sshpie.
- Push to GitHub after every ablation commit.
- Ablation edits: main session only, never fork/delegate.
- When doing RE: reach for `modules/semantic_search.py` first — do not write manual capstone loops from scratch when the semantic sweep can triage the binary in 35 seconds.
