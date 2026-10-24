# BARE Adapter

**File:** `modules/bare_adapter.py`

## Why this exists

Converts Ablation vulnerability findings to `findings.json` and pipes them through the BARE binary to get ranked Metasploit module matches. BARE encodes 3,904 Metasploit modules at compile time. AI/ML-specific findings HPKE, STRAP, RADIUS typically trigger `no_high_confidence_match`; classic overflow/memcpy primitives surface usable MSF modules.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads beyond writing a temporary JSON file. All subprocess calls have timeout guards. No lief.parse(). No HTTP reads.

---

## How it works

`BareAdapter.runfindings` serializes ablation vuln findings to a `findings.json` temp file then pipes it through the BARE binary at `~/.local/bin/bare`. BARE has 3,904 Metasploit modules encoded at compile time; it returns a ranked list of modules whose primitive class matches the finding's CWE class and function description. AI/ML-specific findings HPKE, STRAP, RADIUS dialects will typically trigger BARE's `no_high_confidence_match` sentinel, this is expected. Classic overflow/memcpy primitives surface usable MSF modules.

---

## Usage

```python
from modules.bare_adapter import run_bare, findings_from_results, format_bare_output

# Run BARE analysis (bare_result is a raw findings dict)
bare_result = run_bare(findings={}, timeout=60)
findings = findings_from_results(bare_result)
print(format_bare_output(bare_result, min_score=0.3))
```

---

## Example output

```
# BareAdapter.run(findings) ranked Metasploit output:
[bare] 3 findings → findings.json
[bare] ranked 3 candidates from 3904 modules

  score=0.91  exploit/linux/http/fortinet_sslvpnd_heap  (CWE-122 match)
  score=0.87  exploit/linux/misc/generic_heap_overflow   (primitive: HEAP_OVERFLOW)
  score=0.41  auxiliary/scanner/http/fortinet_webui_vuln (no_high_confidence_match)
```

---

## False positives

**AI/ML-specific findings.** BARE's 3,904-module corpus is built from public Metasploit modules. Novel findings against AI/ML inference infrastructure HPKE key exchange, RADIUS EAP extensions, and TensorFlow Serving RPC produce `no_high_confidence_match` because no public MSF module covers them. The absence of a match does not mean the finding is invalid.

---

## Pipeline position

**Before this module:** `FindingRegistry.register()` must have been called with at least one confirmed finding that has a `cwe_class` and a `description`.

**After this module:** Use the ranked MSF module name as a reference for exploitation category and preconditions, not as a ready-to-use exploit. Manual adaptation is always required.

---

## Reading output

`findings_from_resultsresults, binary_path` returns a BARE-compatible findings dict:

| Key | Type | Content |
|:---|:---|:---|
| `version` | `int` | Always `1` |
| `source` | `str` | Always `'ablation'` |
| `findings` | `List[dict]` | One entry per function with `vuln_notes` see below |

Each entry in `findings`:

| Key | Type | Content |
|:---|:---|:---|
| `id` | `str` | `"<basename>:<func_va_hex>"` |
| `title` | `str` | `"<func_name> (<role>)"` |
| `description` | `str` | Concatenation of role, vuln notes, and rationale |
| `target` | `str` | `binary_path` passed to `findings_from_results` |
| `severity` | `str` | `'critical'` / `'high'` / `'medium'` / `'low'` derived from confidence |

`run_barefindings, timeout` passes this dict to the BARE binary and returns its parsed output dict.

---

## See also

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
