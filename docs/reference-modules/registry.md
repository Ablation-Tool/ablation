# Registry Modules

Persistent cross-session storage for function names and confirmed findings.

---

## NameRegistry

**File:** `ablation/analyzers/name_registry.py`

Every confirmed function name registers here and auto-loads in future sessions. Names appear
automatically in all BinaryContext output: callee lists, caller lists, string xref output, and
the summary table. The registry is keyed by binary SHA256 so names track the exact binary,
not just the filename.

### Storage

`~/.ablation/function_names.json` -- user-local, not committed to git.

Key structure:

```json
{
  "fdfaceccdc740d82": {
    "0x1000": {
      "name": "proto_parse_message",
      "source": "confirmed",
      "ts": "2026-09-23T09:00:00"
    }
  }
}
```

### Sources

| Source | Meaning |
|---|---|
| `manual` | Analyst assigned the name based on code inspection |
| `string` | Name inferred from a nearby string (automated) |
| `confirmed` | Name tied to a confirmed, disclosed vulnerability |

The `confirmed` source carries the highest priority. It means you completed the full triage,
trace, and confirmation workflow for this function.

### Usage via BinaryContext (preferred)

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Register a name
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Look up a name
ctx.name(0x1000)       # "proto_parse_message"

# All names for this binary
ctx.names_table()        # formatted table
ctx.names_map()          # {va: name} dict
ctx.names_count()        # int
ctx.delete_name(0x1000)
```

`set_name()` writes to disk immediately. Thread-safe via file locking.

### Usage direct

```python
from ablation.analyzers.name_registry import NameRegistry

reg = NameRegistry()  # loads from ~/.ablation/function_names.json

reg.set_name(binary_sha256, 0x1000, 'proto_parse_message', source='confirmed')
reg.get_name(binary_sha256, 0x1000)   # "proto_parse_message"
reg.all_names(binary_sha256)            # [(va, name, source), ...] sorted by VA
reg.names_map(binary_sha256)            # {va: name}
reg.count(binary_sha256)                # int
reg.delete_name(binary_sha256, 0x1000)
reg.save()
```

### Cross-binary name sharing

Names are keyed by SHA256 of the specific binary. A name for `libservice.so` from firmware version 1.0 does not apply to the same filename from
version 1.1 -- the SHA256 differs. Use VersionDelta to find the function's new VA in the
updated binary, then register the name under the new SHA256.

---

## FindingRegistry

**File:** `ablation/analyzers/finding_registry.py`

Cross-target confirmed finding store backed by SQLite. A confirmed finding in one vendor's
binary registers as a BERT seed that surfaces as a hit when sweeping other vendors' binaries,
even when the function descriptions use different protocol terminology.

### Storage

`~/.ablation/findings.db` -- SQLite, user-local, not committed to git.
`ablation/data/seed_corpus.json` -- ships pre-loaded with patterns from published CVEs.

### Register a confirmed finding

```python
from ablation.analyzers.finding_registry import FindingRegistry

reg = FindingRegistry()

reg.register(
    vendor='my-vendor',
    product='my-product',
    version='1.0',
    binary='libservice.so',
    title='TLV zero-length infinite loop',
    description='PROTOCOL_PARSER | role=tlv_advance | calls: memcpy | '
                'vuln: zero-length field causes infinite pointer advance loop',
    cwe_class='CWE-835',
    severity='HIGH',
    func_addr=0x1000,
    embedding=func_embedding_vector,   # optional: numpy float32 array
)
```

### Find similar findings

```python
hits = reg.find_similar(func_embedding, top_k=8)
for h in hits:
    print(f"  {h.vendor}/{h.product} {h.version} -- {h.title} ({h.severity})")

print(reg.stats())
reg.list_findings(vendor='my-vendor')
```

### CLI

```bash
python -m ablation.analyzers.finding_registry stats
python -m ablation.analyzers.finding_registry list
python -m ablation.analyzers.finding_registry list --vendor my-vendor
python -m ablation.analyzers.finding_registry register --interactive

# Shortcuts
ablation-search my-vendor
ablation-commit
```

### Export patterns for PatternLibrary (flywheel)

`export_patterns()` returns all confirmed findings as `{'query': str, 'tag': str}` dicts,
one per unique (title, description) pair, tagged by CWE class. Unlike `prior_queries()` which
returns one entry per CWE class, `export_patterns()` returns every confirmed finding so the
full history feeds future sweeps.

Pass the result directly to `PatternLibrary.ingest_from_registry()` to wire the loop:

```python
from ablation.analyzers.finding_registry import FindingRegistry
from ablation.analyzers.pattern_library import PatternLibrary

reg = FindingRegistry()
pl  = PatternLibrary()

n = pl.ingest_from_registry(reg)
print(f"{n} new patterns added from confirmed findings")
# Call pl.sweep(searcher): confirmed findings from all past engagements now run automatically
```

`ingest_from_registry()` is idempotent: calling it again adds only findings registered since
the last call. Save is automatic when new patterns are added.

### How it seeds future sweeps

When findings carry BERT embeddings, SemanticSearcher uses them as additional query vectors
during a sweep. This pulls in cross-vendor patterns that pure-text queries miss. A TLV loop
vulnerability confirmed in one vendor's binary surfaces as a seed hit when sweeping another
vendor's binary, even when the function description uses different protocol-specific
terminology.

---

## Why this exists

Prior to this module, registry modules required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works

**NameRegistry** writes function names keyed by `(binary_sha256, va)` to `~/.ablation/function_names.json` on every `set_name()` call. `BinaryContext.load_or_build()` calls `NameRegistry.all_names()` at load time and caches the result so that `ctx.name(va)` is a pure in-memory lookup during analysis. The SHA-256 key means names track the exact binary file, not just its filename — version bumps with the same filename do not inherit incorrect names.

**FindingRegistry** is backed by a user-local SQLite file (`~/.ablation/findings.db`). `register()` inserts a row and returns the row ID as an integer. When an `embedding` is provided, it is L2-normalized before storage as a binary blob. `find_similar(embedding, top_k)` runs cosine similarity over stored embeddings in Python and returns the top-k result rows as dicts. The pre-loaded `ablation/data/seed_corpus.json` populates the DB at first run with patterns from published CVEs, so cross-vendor similarity queries work immediately without any prior registrations.

---

## Usage

```python
from ablation.analyzers.name_registry import NameRegistry
from ablation.analyzers.finding_registry import FindingRegistry
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary')

# NameRegistry: persist confirmed function names across sessions
names = NameRegistry()
names.set_name(ctx.sha256, 0x1234, 'parse_http_request', source='confirmed')

# Retrieve names in a later session
ctx2 = BinaryContext.load_or_build('/path/to/binary')
print(ctx2.name(0x1234))  # 'parse_http_request'

# FindingRegistry: store and replay confirmed security findings
reg = FindingRegistry()
reg.register(
    vendor='acme', product='firmware', version='1.0',
    binary='libservice.so', func_addr=0x1234,
    cwe_class='CWE-121', severity='HIGH',
    title='Stack overflow in HTTP parser',
    description='Length field flows unvalidated to memcpy.',
)

# List findings by vendor (no model required)
findings = reg.list_findings(vendor='acme')
for h in findings:
    print(h['title'], h['severity'], h['product'])
```

---

## Example output

```
$ python -m ablation.analyzers.finding_registry stats
FindingRegistry  ~/.ablation/findings.db
  total findings  : 47  (23 confirmed)
  vendors         : cisco (12), juniper (9), fortinet (11), custom (15)
  cwe classes     : CWE-787 (8), CWE-121 (6), CWE-119 (11), CWE-120 (7), other (15)
  with embeddings : 31

$ python -m ablation.analyzers.finding_registry list --vendor cisco
vendor    product     title                                cwe_class  severity
------    -------     -----                                ---------  --------
cisco     fmc_server  TLV zero-length infinite loop        CWE-835    HIGH
cisco     asa_fw      SIP parser heap overflow             CWE-787    CRITICAL
cisco     ios_xe      CLI command injection via snmp trap  CWE-78     HIGH
```

---

## False positives

Core infrastructure modules do not emit security findings directly. False positives in downstream scanners are addressed at the scanner level, not here.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to build the analysis session.

**After this module:** Results feed directly into the analysis pipeline: `SemanticSearcher`, `TaintTracker`, or output modules depending on the task.

---

## Reading output

`NameRegistry.get_name(sha256, va)` returns `Optional[str]` — the stored function name for the given binary SHA-256 and VA, or `None` if not registered.

`FindingRegistry.register(vendor, product, title, description, cwe_class, severity)` returns an `int` — the new row ID in the findings SQLite table. Rows include `vendor`, `product`, `version`, `binary`, `func_addr`, `cwe_class`, `severity`, `title`, `description`, `source`, and `confirmed` (1/0 boolean).

`FindingRegistry.find_similar(embedding, top_k)` returns a list of row dicts from the findings table, ranked by embedding cosine similarity.

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
