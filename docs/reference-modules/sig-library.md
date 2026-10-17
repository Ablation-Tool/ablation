# SigLibrary -- Function Signature Matching

Identifies standard library functions in stripped binaries by comparing behavioral
descriptions against a library of 40 known-function signatures using the same BERT
model already loaded for semantic search.

---

## Why it exists

Two things were not possible before in Ablation:

**1. Identifying standard library functions without reading disassembly.**
Stripped firmware routinely contains hundreds of functions named `fn_0x1d700`. Most
are inlined wrappers for `memcpy`, `strlen`, `recv`, or other libc functions. Without
this module, identifying them meant reading each function's disassembly and recognizing
the pattern by hand. On a 500-function binary that could mean hours of work before
reaching the first interesting function.

**2. Cleaning the semantic search corpus before analysis.**
`SemanticSearcher` builds embeddings from function descriptions. When hundreds of those
functions are still named `fn_0x*`, their descriptions pollute every downstream query
because libc call patterns appear as noise across the embedding space. Running
`auto_name()` before building the corpus removes that noise. Semantic queries then
return results from actual logic, not from `memcpy` wrappers that happen to match the
description.

`SigLibrary.auto_name()` does both: it renames placeholder functions in the corpus DB
so every subsequent analysis tool sees clean names.

---

## Quick start

```python
from ablation.analyzers.sig_library import SigLibrary

lib = SigLibrary()
lib.load_model()  # loads sentence-transformers/all-mpnet-base-v2

# Match a description string directly
match = lib.match_description("copies bytes from src to dst buffer; no length check")
if match:
    print(f"{match.label()}  score={match.score:.3f}  cwe={match.cwe_risk}")
    # likely:memcpy  score=0.81  cwe=CWE-120

# Auto-name all fn_0x* functions in a corpus DB
n = lib.auto_name('/tmp/my_corpus.db')
print(f"Renamed {n} functions")
```

CLI equivalent:

```bash
# Build corpus and auto-name in one step
ablation corpus firmware.so --sigs

# Auto-name an existing corpus without rebuilding
ablation sigs firmware.so

# Preview names without writing to DB
ablation sigs firmware.so --dry-run
```

---

## Shipped signatures

40 signatures across 6 categories:

| Category | Functions |
|---|---|
| Memory ops | `memcpy`, `memmove`, `memset`, `memcmp` |
| String ops | `strlen`, `strcpy`, `strncpy`, `strcat`, `strcmp`, `strncmp`, `sprintf`, `snprintf`, `sscanf`, `strtol` |
| Heap | `malloc`, `calloc`, `realloc`, `free` |
| Network | `recv`, `send`, `accept`, `connect` |
| System | `getenv`, `system`, `execve`, `fopen`, `fread`, `fwrite` |
| Crypto/TLS | `SSL_read`, `SSL_write`, `SSL_connect`, `EVP_EncryptUpdate`, `SHA256_Update`, `RAND_bytes` |
| Format/parse | `printf`, `json_parse`, `xml_parse`, `base64_decode`, `url_decode` |
| Threading | `pthread_mutex_lock` |

---

## How matching works

1. On first call, `load_model()` encodes all 40 signature descriptions into a 768-dim
 embedding matrix. This is cached to `~/.ablation/sig_cache/` -- subsequent loads
 take ~2ms.
2. Each incoming description is encoded as a single vector, then cosine similarity is
 computed against the matrix (one matrix multiply: ~1ms for 40 sigs).
3. The best match is returned if its score exceeds `threshold` (default 0.62).
4. `auto_name()` iterates over all `ANGR_INFERRED` functions in the corpus DB that
 still have placeholder names (`fn_0x*`), builds a description from call targets and
 string references, and renames matches.

---

## API reference

### `SigLibrary(sigs_path=None, threshold=0.62)`

| Parameter | Default | Description |
|---|---|---|
| `sigs_path` | bundled `data/sigs.json` | Path to a custom signatures JSON file |
| `threshold` | `0.62` | Minimum cosine similarity to accept a match |

### `load_model()`

Loads the sentence-transformers model and builds or loads the cached embedding matrix.
Must be called before `match_description()` or `auto_name()`.

### `match_description(description: str) -> SigMatch | None`

Match a free-form function description string. Returns `None` if no signature exceeds
threshold. Does not skip already-named functions -- use this for ad-hoc matching.

### `match_function(name, call_targets, string_xrefs, notes) -> SigMatch | None`

Higher-level matcher used by `auto_name()`. Skips functions that already have real
names (i.e., not matching `fn_0x*`). Returns `None` for functions with no signal
(empty call targets and string xrefs).

### `auto_name(db_path: str, dry_run=False) -> int`

Iterates over all `ANGR_INFERRED` placeholder functions in the corpus DB and renames
matches. Returns the count of functions renamed. With `dry_run=True`, prints proposed
names without writing.

### `known_signatures() -> list[dict]`

Returns the raw list of signature dicts from `sigs.json`. Each dict has `name`,
`description`, `aliases`, `category`, and `cwe_risk` fields.

---

## Extending the signature library

`sigs.json` ships with the package at `ablation/data/sigs.json`. To add signatures,
either edit that file directly or pass a custom path:

```python
lib = SigLibrary(sigs_path='/path/to/my_sigs.json')
```

The JSON format:

```json
{
  "signatures": [
    {
      "name": "my_parser",
      "description": "reads a length-prefixed TLV field and advances a pointer",
      "aliases": ["parse_tlv", "tlv_read"],
      "category": "parser",
      "cwe_risk": "CWE-125"
    }
  ]
}
```

Good descriptions are behavioral, not structural. "copies N bytes using a loop" is
worse than "copies N bytes from src to dst; caller controls N; no upper bound check".

---

## How it works

`load_model()` loads the sentence-transformers model and encodes the 40 signature descriptions into a 768-dim embedding matrix, caching the result to `~/.ablation/sig_cache/`. On subsequent loads the matrix is deserialized from disk in ~2 ms instead of being recomputed. `match_description()` encodes the input description as a single 768-dim vector, computes cosine similarity against the matrix (one NumPy matmul), and returns the best match if it exceeds `threshold`. `auto_name()` iterates over every `ANGR_INFERRED` placeholder function in the corpus DB, builds a behavioral description from the `call_targets` JSON column and `string_xrefs` text, calls `match_description()`, and writes back the matched `name` for every hit above threshold.

---

## Usage

```python
from ablation.analyzers.sig_library import SigLibrary

lib = SigLibrary()
# match_function takes name, call_targets (JSON str), string_xrefs (str)
match = lib.match_function(
    name='fn_401000',
    call_targets='["strcpy","malloc"]',
    string_xrefs='buffer overflow detected',
)
if match:
    print(f"  {match.sig_name}  score={match.score:.2f}")
```

---

## Example output

```
$ ablation sigs firmware.so --dry-run
SigLibrary  firmware.so  (2847 fn_0x* candidates)
  fn_0x1d700  →  likely:memcpy     score=0.89  cwe=CWE-120
  fn_0x1e200  →  likely:strlen     score=0.84  cwe=None
  fn_0x1f100  →  likely:strcpy     score=0.81  cwe=CWE-120
  fn_0x21400  →  likely:malloc     score=0.78  cwe=None
  fn_0x22800  →  likely:recv       score=0.72  cwe=None
  ... (47 total matches above threshold=0.62)
Dry run: 47 functions would be renamed (no DB write)
```

---

## False positives

**High similarity score for a function that only calls the matched function.** A thin wrapper around `memcpy` (3–5 instructions: `MOV rdi, …`, `MOV rsi, …`, `CALL memcpy`, `RET`) has the same behavioral description as `memcpy` itself and will score above threshold. Use `--dry-run` to inspect proposed renames and filter out functions where the description is dominated by a single call target rather than a broader pattern.

---

## Pipeline position

**Before this module:** `CorpusBuilder.build()` to build the function corpus DB. `auto_name()` reads from and writes to the corpus DB, so the corpus must exist before running it.

**After this module:** `SemanticSearcher.build_corpus()` re-encodes the renamed functions so semantic queries no longer match `memcpy` wrappers. Standard pipeline: `BinaryContext.load_or_build()` → `CorpusBuilder.build()` → `SigLibrary.auto_name()` → `SemanticSearcher.build_corpus()`.

---

## Reading output

`SigLibrary().match_function(name, call_targets, string_xrefs, notes='')` returns `Optional[SigMatch]` — `None` if no signature matches with sufficient confidence:

| Attribute | Content |
|:---|:---|
| `name` | Standard library function name (e.g., `'memcpy'`, `'SSL_read'`) |
| `aliases` | `List[str]` — alternate names this function is known by |
| `category` | Category string: `'Memory ops'` / `'String ops'` / `'Heap'` / `'Network'` / etc. |
| `cwe_risk` | CWE risk identifier if the matched function is security-sensitive, or `None` |
| `score` | Float — cosine similarity score of the match (0.0–1.0) |

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
