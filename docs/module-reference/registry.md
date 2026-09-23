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
    "0x17b660": {
      "name": "ips_diameter_parse_message",
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
ctx.set_name(0x17b660, 'ips_diameter_parse_message', source='confirmed')

# Look up a name
ctx.name(0x17b660)       # "ips_diameter_parse_message"

# All names for this binary
ctx.names_table()        # formatted table
ctx.names_map()          # {va: name} dict
ctx.names_count()        # int
ctx.delete_name(0x17b660)
```

`set_name()` writes to disk immediately. Thread-safe via file locking.

### Usage direct

```python
from ablation.analyzers.name_registry import NameRegistry

reg = NameRegistry()  # loads from ~/.ablation/function_names.json

reg.set_name(binary_sha256, 0x17b660, 'ips_diameter_parse_message', source='confirmed')
reg.get_name(binary_sha256, 0x17b660)   # "ips_diameter_parse_message"
reg.all_names(binary_sha256)            # [(va, name, source), ...] sorted by VA
reg.names_map(binary_sha256)            # {va: name}
reg.count(binary_sha256)                # int
reg.delete_name(binary_sha256, 0x17b660)
reg.save()
```

### Cross-binary name sharing

Names are keyed by SHA256 of the specific binary. A name for `libips.so.new` from
FortiOS 8.0.0 does not apply to `libips.so.new` from FortiOS 8.0.1 -- the SHA256 differs.
Use VersionDelta to find the function's new VA in the updated binary, then register the name
under the new SHA256.

---

## FindingRegistry

**File:** `ablation/analyzers/finding_registry.py`

Cross-target confirmed finding store backed by SQLite. A confirmed Cisco LINA overflow
registers as a BERT seed that surfaces as a hit when sweeping FortiGate, even when the
function descriptions use different protocol terminology.

### Storage

`~/.ablation/findings.db` -- SQLite, user-local, not committed to git.
`ablation/data/seed_corpus.json` -- ships pre-loaded with patterns from published CVEs.

### Register a confirmed finding

```python
from ablation.analyzers.finding_registry import FindingRegistry

reg = FindingRegistry()

reg.register(
    vendor='fortinet',
    product='fortigate-7000f',
    version='8.0.0',
    binary='libips.so.new',
    title='Diameter AVP zero-length infinite loop',
    description='PROTOCOL_PARSER | role=tlv_advance | calls: memcpy | '
                'vuln: AVP length=0 causes infinite pointer advance loop',
    cwe_class='CWE-835',
    severity='HIGH',
    func_addr=0x17b660,
    embedding=func_embedding_vector,   # optional: numpy float32 array
)
```

### Find similar findings

```python
hits = reg.find_similar(func_embedding, top_k=8)
for h in hits:
    print(f"  {h.vendor}/{h.product} {h.version} -- {h.title} ({h.severity})")

print(reg.stats())
reg.list_findings(vendor='fortinet')
```

### CLI

```bash
python -m ablation.analyzers.finding_registry stats
python -m ablation.analyzers.finding_registry list
python -m ablation.analyzers.finding_registry list --vendor fortinet
python -m ablation.analyzers.finding_registry register --interactive

# Shortcuts
ablation-search fortinet
ablation-commit
```

### How it seeds future sweeps

When findings carry BERT embeddings, SemanticSearcher uses them as additional query vectors
during a sweep. This pulls in cross-vendor patterns that pure-text queries miss. A TLV loop
vulnerability confirmed in Cisco ASA surfaces as a seed hit when sweeping FortiGate even when
the function description uses different protocol-specific terminology.
