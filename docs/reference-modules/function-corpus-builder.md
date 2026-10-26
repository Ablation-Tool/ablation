# Function Corpus Builder

Populate `func_id.db` with `ANGR_INFERRED` function records for binaries with no prior RE coverage: enabling `SemanticSearcher.build_corpus()` to index new firmware libraries and include them in semantic queries without requiring manual RE work on each function.

---

## Why this exists

1. **`SemanticSearcher` requires a populated `func_id.db` corpus to perform semantic search: a binary with zero corpus entries returns no results regardless of how many functions it contains.** For freshly-encountered firmware shared libraries such as a new version of a vendor's `libcrypto_hw.so` with no prior RE coverage, `CorpusBuilder.build()` generates the initial corpus entries automatically by heuristically inferring role and call targets from the binary's PLT and string cross-references.

2. **`ANGR_INFERRED` is a distinct confidence level from `CONFIRMED`, it signals that the function record was machine-generated and has not been validated by a human analyst.** `SemanticSearcher.build_corpus()` accepts `confidence_filter=['CONFIRMED', 'ANGR_INFERRED']` to include inferred records, while sensitive operations for example formal disclosure query `CONFIRMED` only. This separation prevents polluting the confirmed corpus with noisy inferred data while still making the inferred corpus useful for initial triage.

3. **For each function discovered via `eh_frame` FDE entries, `CorpusBuilder` extracts three features that `SemanticSearcher` can match against: PLT callee names call targets, RIP-relative string literal cross-references string xrefs, and a heuristic role description.** These three features encode most of what an analyst would manually write in a `CONFIRMED` record, at roughly 100x the speed. `SigLibrary.auto_name()` renames `ANGR_INFERRED` records when a semantic match above a confidence threshold is found.

---

## How it works

```mermaid
flowchart TD
    A(["CorpusBuilder(db_path='~/.ablation/func_id.db')"]):::input --> B["build(binary_path, product, version) → int\n  ELF parsing: discover functions via eh_frame FDE entries\n  (strips without symbols still have unwind tables if compiled with -fexceptions)"]:::primary
    B:::primary --> C["For each function:\n  1. name: 'fn_0x<va>' (stripped; no symbols)\n  2. call_targets: PLT names for resolved calls,\n     '0x<va>' hex strings for unresolved\n  3. string_xrefs: string CONTENTS from RIP-relative LEA\n  4. role: heuristic from callee PLT names\n     (recv/send → network, open/read → file_io, etc.)\n  5. notes: short role description for vuln_notes field"]:::secondary
    C:::secondary --> D["Insert row into func_id.db:\n  confidence = ANGR_INFERRED\n  product, version, binary, func_va, name, role,\n  call_targets, string_xrefs, notes"]:::tertiary
    D:::tertiary --> E["Returns: count of rows inserted\n  Skips: functions already present at same (binary, func_va)"]:::tertiary
    E:::tertiary --> F(["SemanticSearcher.build_corpus() picks up ANGR_INFERRED rows\n  all-mpnet-base-v2 encodes role + call_targets + string_xrefs\n  → corpus now queryable for this binary"]):::output

    G(["build_multi(binary_paths, product, version) → Dict[str,int]\n  Builds corpus for N binaries in sequence\n  Returns per-path insertion counts"]):::input
    H(["status() → Dict[str, int]\n  Counts by confidence level in func_id.db\n  {'CONFIRMED': N, 'ANGR_INFERRED': M}"]):::input
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
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.analyzers.corpus_builder import CorpusBuilder

cb = CorpusBuilder('~/.ablation/func_id.db')

# Build corpus for a single newly-encountered library
count = cb.build(
    '/path/to/firmware.so',
    product='my-target',
    version='1.0'
)
print(f"Inserted {count} ANGR_INFERRED records")

# Build corpus for all shared libraries extracted from a firmware image
binary_paths = ['/tmp/fw/lib/libssl.so', '/tmp/fw/lib/libcrypto.so']
counts = cb.build_multi(binary_paths, product='target-fw', version='7.4.1')
for path, n in counts.items():
    print(f"  {path}: {n} records")

# Check corpus state
status = cb.status()
print(f"Confirmed: {status['CONFIRMED']}  Inferred: {status['ANGR_INFERRED']}")
```

---

## Example output

The following illustrates the build output format. Actual counts are binary-specific.

```
CorpusBuilder: /path/to/firmware.so
  Functions found (via eh_frame): <N>
  Inserted: <M> ANGR_INFERRED records
  Skipped (already present): <K>

status():
  CONFIRMED: <N>
  ANGR_INFERRED: <M>
```

---

## False positives

**`eh_frame` FDE discovery misses functions in binaries compiled with `-fno-exceptions` and without `.eh_frame` section.** For these binaries, combine `CorpusBuilder` with `ARM32FunctionScanner` prologue scan or `GoStringResolver.scan_function()` Go binaries to supplement function discovery before building the corpus.

**`ANGR_INFERRED` role assignments are heuristic: a function that calls `recv()` then `strncpy()` will be labeled `network` when it might be a dispatcher that calls both.** Review inferred roles for high-priority functions before promoting their records to `CONFIRMED`.

---

## Pipeline position

Run `CorpusBuilder.build()` immediately after the first `BinaryContext.load_or_build()` on a previously-unseen binary: before `SemanticSearcher.query()`, since querying against an empty corpus returns nothing. See the RE workflow in `CLAUDE.md`: step 3 ("CorpusBuilder.build() if no prior coverage") precedes step 4 ("SemanticSearcher.query()").

---

## Reading output

`CorpusBuilder.build(binary_path, product='', version='', arch='x86-64')` returns `int`: the number of function records inserted into `func_id.db`. The build also persists all semantic embeddings and role labels to the database; the integer count is the only direct return value.

---

## See also

- [Bundled Finding Signature Seeds](bundled-finding-signature-seeds.md): `SigLibrary.auto_name()` promotes `ANGR_INFERRED` → named when semantic match found
- [DTW Function Homolog Matching](dtw-function-homolog-matching.md): uses corpus to find cross-version homologs
- [SAX Approximate Indexing](sax-approximate-indexing.md): complementary pre-filter index
