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
