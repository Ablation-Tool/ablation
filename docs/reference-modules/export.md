# Export Formats -- SARIF and JSON

Ablation sweep results and confirmed findings export to SARIF 2.1.0 or flat JSON.

---

## SARIF 2.1.0

[SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) is the OASIS standard for
static analysis results. GitHub Code Scanning, VS Code, and most modern SAST platforms
consume it natively -- meaning sweep results can appear as PR annotations without any
custom integration.

### CLI

```bash
# Sweep and write SARIF in one step
ablation sweep firmware.so --sarif results.sarif

# Export confirmed findings from the findings DB
ablation findings --sarif findings.sarif

# Both flags work together
ablation sweep firmware.so --sarif sweep.sarif --json sweep.json
```

### Python API

```python
from ablation.analyzers.pattern_library import PatternLibrary
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.export.sarif import sweep_to_sarif, findings_to_sarif
from ablation.export.json_export import write_sarif, write_json

# Run sweep
pl = PatternLibrary()
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()
results = pl.sweep(searcher)

# Export
sarif = sweep_to_sarif(results, binary_path='firmware.so', min_score=0.30)
write_sarif(sarif, 'results.sarif')
```

### Upload to GitHub Code Scanning

```bash
ablation sweep firmware.so --sarif results.sarif

gh api repos/<owner>/<repo>/code-scanning/sarifs \
    -f commit_sha=$(git rev-parse HEAD) \
    -f ref=refs/heads/main \
    -f sarif=$(gzip -c results.sarif | base64 -w0) \
    -f tool_name=ablation
```

Results appear as annotations on open PRs and in the Security tab.

### SARIF structure

Each sweep hit becomes a SARIF `result` with:

| Field | Value |
|---|---|
| `ruleId` | `<tag>/<query-slug>` e.g. `buffer-overflow/strcpy-no-length-check` |
| `level` | `warning` for sweep hits; `error` for critical/high findings |
| `physicalLocation.address.absoluteAddress` | Virtual address (integer) |
| `properties.score` | Cosine similarity score |
| `properties.va` | VA as hex string e.g. `0x1fa00` |

---

## JSON export

Flat JSON for scripting, dashboards, or feeding into other tools.

### CLI

```bash
ablation sweep   firmware.so --json sweep.json
ablation findings            --json findings.json
```

### Python API

```python
from ablation.export.json_export import sweep_to_json, findings_to_json, write_json

doc = sweep_to_json(results, binary_path='firmware.so', min_score=0.30)
write_json(doc, 'sweep.json')
```

### JSON structure

```json
{
  "binary": "firmware.so",
  "total_hits": 14,
  "min_score": 0.3,
  "findings": [
    {
      "pattern": "strcpy with user-controlled src, no length check",
      "tag": "buffer-overflow",
      "hits": [
        {"va": "0x1fa00", "score": 0.71},
        {"va": "0x2200c", "score": 0.63}
      ]
    }
  ]
}
```

Patterns with zero hits above `min_score` are omitted from `findings`.

---

## API reference

### `sweep_to_sarif(sweep_results, binary_path, min_score=0.0)`

Convert `PatternLibrary.sweep()` output to a SARIF 2.1.0 dict.

### `findings_to_sarif(findings, binary_path=None)`

Convert `FindingRegistry.list_findings()` output to SARIF 2.1.0.

### `sweep_to_json(sweep_results, binary_path, min_score=0.0)`

Convert sweep results to a flat JSON-serializable dict.

### `findings_to_json(findings)`

Convert findings list to a JSON-serializable dict.

### `write_sarif(doc, path)`

Write a SARIF dict to a file.

### `write_json(doc, path)`

Write a JSON dict to a file.

---

## Why this exists

Prior to this module, export formats -- sarif and json required manual work outside the Ablation pipeline. This module integrates the capability directly so findings feed the shared `PatternLibrary` and `FindingRegistry` without a separate toolchain.

---

## How it works

`sweep_to_sarif()` and `sweep_to_json()` iterate the `PatternLibrary.sweep()` result list and filter hits by `min_score`. Each passing hit becomes one SARIF `result` entry or one JSON `hit` dict. SARIF results carry the rule ID from the pattern's `tag`, the virtual address in `physicalLocation.address.absoluteAddress`, and the cosine similarity score in `properties.score`. `findings_to_sarif()` and `findings_to_json()` do the same for rows from `FindingRegistry.list_findings()`, using the CWE class as the SARIF rule ID. `write_sarif()` and `write_json()` serialize to disk; both set `"$schema"` to the SARIF 2.1.0 schema URI.

---

## Usage

```python
from ablation.export.sarif import findings_to_sarif
import json

# findings: list of FindingRecord objects from FindingRegistry
sarif_doc = findings_to_sarif(findings, binary_path='/path/to/target.elf')
print(json.dumps(sarif_doc, indent=2))
```

---

## Example output

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "ablation", "version": "2.57.0", "rules": [
      {"id": "buffer-overflow/strcpy-no-length-check", "shortDescription": {"text": "buffer-overflow"}}
    ]}},
    "results": [{
      "ruleId": "buffer-overflow/strcpy-no-length-check",
      "level": "warning",
      "message": {"text": "strcpy with user-controlled src, no length check (score=0.71)"},
      "locations": [{"physicalLocation": {"address": {"absoluteAddress": 130560}}}],
      "properties": {"score": 0.71, "va": "0x1fa00"}
    }]
  }]
}
```

---

## False positives

The export module does not emit security findings. A SARIF output that contains no results (`"results": []`) is valid and expected when `findings` is empty — not a false positive from the tool. If `sweep_to_sarif` produces no results, verify that `PatternLibrary.sweep()` returned hits and that the hit objects have non-null `func_addr` fields before calling the exporter.

---

## Pipeline position

**Before this module:** `PatternLibrary.sweep()` to generate sweep hits, or `FindingRegistry.list_findings()` to retrieve confirmed findings. Both produce the input lists these functions consume.

**After this module:** Upload to GitHub Code Scanning via `gh api repos/.../code-scanning/sarifs`, import into a SAST dashboard, or feed into downstream tooling. No further Ablation modules depend on export output.

---

## Reading output

All export functions are module-level (no class instantiation). They return structured dicts or write files:

| Function | Returns |
|:---|:---|
| `sweep_to_sarif(sweep_results, binary_path, min_score=0.0)` | `dict` — SARIF 2.1.0 document from `PatternLibrary.sweep()` output |
| `findings_to_sarif(findings, binary_path=None)` | `dict` — SARIF 2.1.0 document from `FindingRegistry.list_findings()` output |
| `sweep_to_json(sweep_results, binary_path, min_score=0.0)` | `dict` — flat JSON with `binary`, `findings`, `total_hits` keys |
| `findings_to_json(findings)` | `dict` — flat JSON with `findings` and `total` keys |
| `write_sarif(data, path)` | Writes SARIF file; returns `None` |
| `write_json(data, path)` | Writes JSON file; returns `None` |

See [JSON and SARIF Export](json-and-sarif-export.md) for the full SARIF schema and field reference.

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
