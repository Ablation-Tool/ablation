# SigLibrary -- Function Signature Matching

Identifies standard library functions in stripped binaries by comparing behavioral
descriptions against a library of 40 known-function signatures using the same BERT
model already loaded for semantic search.

---

## Why it exists

Stripped firmware routinely contains hundreds of functions named `fn_0x1d700`. Most
are wrappers for `memcpy`, `strlen`, `recv`, or other libc functions inlined by the
compiler. Manually identifying them is tedious. SigLibrary does it automatically:
a match above 0.62 cosine similarity renames the function to `likely:memcpy` in the
corpus DB.

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
