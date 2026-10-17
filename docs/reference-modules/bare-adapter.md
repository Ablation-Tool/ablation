# BARE Adapter

**File:** `modules/bare_adapter.py`

## Why this exists

Converts Ablation vulnerability findings to `findings.json` and pipes them through the BARE binary to get ranked Metasploit module matches. BARE encodes 3,904 Metasploit modules at compile time. AI/ML-specific findings (HPKE, STRAP, RADIUS) typically trigger `no_high_confidence_match`; classic overflow/memcpy primitives surface usable MSF modules.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads beyond writing a temporary JSON file. All subprocess calls have timeout guards. No lief.parse(). No HTTP reads.

---

## How it works

Reads the binary image and resolves the target-specific data structures (PLT, GOT, `.eh_frame`, symbol tables) to build a function and import index. Architecture-specific calling conventions and instruction encodings are applied to recover call edges, argument registers, and return value locations. Results are stored in the session `BinaryContext` so downstream tools can use resolved names and edges.

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
Resolved 847 PLT entries
Recovered 312 function starts from .eh_frame
Named 28 functions from DWARF remnants

va=0x401200  name=verify_admin_token  confidence=HIGH
va=0x4015C0  name=process_http_request  confidence=HIGH
va=0x403A00  name=''  confidence=MEDIUM  (stripped)
```

---

## False positives

Symbol resolution errors produce phantom function boundaries. Verify any candidate VA against `ctx.func_starts` before analysis. Compiler-synthesized stubs (PLT entries, thunks) appear as functions in some loaders — `BinaryContext` filters known stub patterns but custom thunks may slip through.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for symbol and import resolution. For stripped binaries, run `SemanticSearcher` first to identify candidate function VAs.

**After this module:** Pass resolved call edges and function VAs to `TaintTracker` or `SinkArgClassifier`.

---

## Reading output

`findings_from_results(results, binary_path)` returns a BARE-compatible findings dict:

| Key | Type | Content |
|:---|:---|:---|
| `version` | `int` | Always `1` |
| `source` | `str` | Always `'ablation'` |
| `findings` | `List[dict]` | One entry per function with `vuln_notes` (see below) |

Each entry in `findings`:

| Key | Type | Content |
|:---|:---|:---|
| `id` | `str` | `"<basename>:<func_va_hex>"` |
| `title` | `str` | `"<func_name> (<role>)"` |
| `description` | `str` | Concatenation of role, vuln notes, and rationale |
| `target` | `str` | `binary_path` passed to `findings_from_results` |
| `severity` | `str` | `'critical'` / `'high'` / `'medium'` / `'low'` (derived from confidence) |

`run_bare(findings, timeout)` passes this dict to the BARE binary and returns its parsed output dict.

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
