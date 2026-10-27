<a id="forge"></a>
# Module Security Quality Gate

FORGE is the production gate for every Python module in Ablation. Before any new or changed `.py` file gets a `git add`, FORGE checks a cache for a prior SAFE CODE audit result. On a cache miss it raises `ForgeAuditRequired`, which tells you to read the file and do the 10-section review inline in your Claude Code session. On a cache hit it returns the cached `ForgeReport` instantly. It blocks the commit if the report contains a HIGH or CRITICAL finding.

---

## Why this exists

Three things were not possible before FORGE:

1. **Modules shipped without an independent review.** A module could pass syntax checks and smoke tests and still carry a silent failure mode, a data-integrity risk, or an unbounded blocking call. FORGE runs the full Ablation-SAFE CODE.md S.O.P. against the actual source before any commit.

2. **Every re-audit was a full LLM round-trip.** Running `FORGE.audit_module()` on a module that had not changed still blocked for two minutes. A cache keyed on the system prompt hash and file hash now returns the previous result instantly on cache hit.

3. **Audit calls required a subprocess.** The old implementation called `claude --print` in a subprocess, which backgrounded unpredictably in Claude Code sessions. FORGE now raises `ForgeAuditRequired` on cache miss. The audit happens inline in the Claude Code session; no subprocess, no backgrounding, no Anthropic API key.

---

## Usage

```python
from ablation.analyzers.forge import FORGE, ForgeAuditRequired

# Before committing: check cache or raise ForgeAuditRequired
try:
    report = FORGE.audit_module('ablation/analyzers/my_module.py')
except ForgeAuditRequired as e:
    # Read the file. Do the 10-section SAFE CODE audit inline.
    # Then store the result:
    report = FORGE.record_result(
        'ablation/analyzers/my_module.py',
        findings=[...],   # list[ForgeFinding] or list[dict]
        summary='...',
    )

print(report.report())
if not report.gate_passed:
    raise SystemExit("FORGE BLOCKED: fix HIGH/CRITICAL findings before committing")

# Source security audit (no LLM, any codebase)
report = FORGE.audit_source('/tmp/target-repo')
print(report.report())

# Validate and register a local module
report = FORGE.register('~/my_work/my_scanner.py')
```

CLI:

```
python3 -m ablation.analyzers.forge module ablation/analyzers/my_module.py
python3 -m ablation.analyzers.forge source /tmp/target-repo
python3 -m ablation.analyzers.forge register ~/my_work/my_scanner.py
python3 -m ablation.analyzers.forge list
```

---

## How the audit works

`FORGE.audit_module(path)` does this:

1. Loads the SAFE CODE system prompt from `ablation/data/forge_system.md` external drive fallback.
2. Checks `~/.ablation/forge_cache.json` for a prior result keyed on `sha256system_prompt[:16] + ":" + sha256file_bytes[:16]`. If found, returns the cached `ForgeReport` immediately.
3. On cache miss, raises `ForgeAuditRequired` with the file path and instructions.

The audit itself runs inline: read the file in Claude Code, apply the 10-section SAFE CODE review, then call `FORGE.record_result()` to cache the result. Future calls return instantly from cache.

`gate_passed` is `True` when no finding has severity `CRITICAL` or `HIGH`.

---

## Detection stage

Every `ForgeFinding` carries a `detection_stage` field. It answers one question: at what point in the pipeline would this bug surface without this audit?

Four values: `develop`, `debug`, `test`, `deploy`. A `develop` finding is one that `mypy` or a basic arity check catches immediately. A `deploy` finding only surfaces in production under specific conditions. The default is `deploy` because that is the worst case, and a finding should earn a lower stage explicitly.

`ForgeReport.report()` prints a stage-risk summary for every HIGH or CRITICAL finding and a cost marker next to each stage: free for DEVELOP, $ for DEBUG, $$ for TEST, $$$ for DEPLOY. The multiples come from software defect cost-of-change research: a DEPLOY-stage bug costs roughly 18 times as much to fix as the same bug caught at DEVELOP.

The FORGE audit plan Section F of the DEV & TEST ORCHESTRATION PLAN requires a stage classification for every HIGH and CRITICAL finding. A finding with no stage is treated as DEPLOY.

---

## record_result()

`FORGE.record_resultpath, findings, summary, raw_text` stores an inline audit result in the cache. `findings` can be a list of `ForgeFinding` objects or a list of dicts with keys `severity`, `category`, `title`, `location`, `description`, `recommendation`, `source`, `cwe`, `detection_stage`.

```python
report = FORGE.record_result(
    '/absolute/path/to/module.py',
    findings=[
        {'severity': 'CRITICAL', 'category': 'wiring', 'title': '...', 'location': '...',
         'description': '...', 'recommendation': '...', 'source': 'module_audit',
         'cwe': '', 'detection_stage': 'develop'},
    ],
    summary='gate_passed=False. 1 CRITICAL: ...'
)
```

---

## Result cache

The cache lives at `~/.ablation/forge_cache.json`. It loads lazily on first use and writes atomically via a `.tmp` file.

The key is:

```
sha256(system_prompt)[:16] + ":" + sha256(file_bytes)[:16]
```

Any change to the SOP file or the module source invalidates the entry for that module. Changing the SOP invalidates every entry. `raw_text` is not cached; findings, summary, path, and mode are.

---

## ForgeReport

```python
report.gate_passed     # bool: False if any CRITICAL or HIGH finding
report.findings        # list[ForgeFinding]
report.highs()         # findings with severity CRITICAL or HIGH
report.summary         # text summary
report.raw_text        # full audit text (not cached)
report.report()        # formatted human-readable summary
```

`ForgeFinding` fields: `severity`, `category`, `title`, `location`, `description`, `recommendation`, `source`, `cwe`, `detection_stage`.

---

## Local module store

`FORGE.register(path)` checks the cache for a passed audit, then copies the file to `~/.ablation/local_modules/`. Modules there load automatically via `FORGE.load_local_modules()`. They are separate from native Ablation modules and are never overwritten by Ablation updates.

```python
FORGE.load_local_modules()    # call once at session start
FORGE.list_local_modules()    # list registered modules
```

---

## Hard rules

- Run `FORGE.audit_module()` on every new or modified `.py` file before `git add`. This is required by Ablation-SAFE CODE.md.
- On a cache miss, do the audit inline in the Claude Code session. Do not call `claude --print` in a subprocess or background task.
- Fix every HIGH and CRITICAL finding before committing. The gate exists to block commits, not to document known problems.

---

## How it works

`FORGE.audit_module(path)` computes a two-part cache key: `sha256system_prompt[:16] + ":" + sha256file_bytes[:16]`. A hit returns the cached `ForgeReport` in under a millisecond with no LLM call. A miss raises `ForgeAuditRequired`, this is the signal to read the file in the current Claude Code session, apply the 10-section SAFE CODE review, and call `FORGE.record_result()` to write the result to `~/.ablation/forge_cache.json`. Changing either the SOP file or the module source invalidates the cache entry for that module only; changing the SOP invalidates all entries. `gate_passed` is the property checked before `git add`.

---

## Example output

```
FORGE [MODULE]  ablation/analyzers/my_scanner.py
Gate: PASSED   Findings: 3  (0 CRITICAL  0 HIGH  1 MEDIUM  2 LOW  0 INFO)

  [MEDIUM]  path-traversal  unchecked user-supplied path  my_scanner.py:42
    Path passed to open() without normalization or prefix check.
    Recommendation: use pathlib.Path(p).resolve() and verify prefix before open()
    CWE-22  stage: test ($$)

  [LOW]  broad-exception  bare except: at top-level  my_scanner.py:88
    Swallows all exceptions including KeyboardInterrupt and SystemExit.
    Recommendation: except (ValueError, OSError) or log and re-raise

  [LOW]  naming  ambiguous variable name 'l' at line 104  my_scanner.py:104
    Single-letter variable in 30-line function reduces readability under review.
    Recommendation: rename to 'length' or 'limit'

Gate: PASSED — no CRITICAL or HIGH findings.
```

---

## False positives

**`MEDIUM` finding on path normalization**: FORGE flags any `open()`, `os.path.join()`, or `pathlib.Path()` call that takes an argument not validated against a known prefix. This is correct for user-supplied paths, but a false positive when the path is constructed internally from a package data directory or a hardcoded `~/.ablation/` prefix. Add an explicit comment in `record_result()` noting the internal-only path if a finding of this type is downgraded from MEDIUM.

**`FORGE.audit_module()` raises `ForgeAuditRequired` on every call**, this means the cache has no prior result for this module. It is not a false positive; it is the signal to run the audit inline. Run the SAFE CODE review and call `record_result()` to cache the result so future calls return instantly.

---

## Pipeline position

**Before this module:** Called before every `git add` on a new or changed `.py` file. Read the module source in Claude Code, apply the 10-section SAFE CODE review, then call `FORGE.record_result()` to cache the result.

**After this module:** When `gate_passed=True`, proceed with `git add` and `git commit`. When `gate_passed=False`, fix every HIGH and CRITICAL finding and re-run `FORGE.audit_module()` to update the cache before committing.

---

## Reading findings

`FORGE.audit_module(path)` returns a `ForgeReport`:

| Attribute | Content |
|:---|:---|
| `path` | Path to the audited module |
| `mode` | `'module'` LLM audit or `'source'` static compressor audit |
| `findings` | `list[ForgeFinding]`: individual findings sorted by severity |
| `summary` | Short summary string |
| `gate_passed` | Property: `True` if no CRITICAL or HIGH findings |

Each `ForgeFinding`:

| Attribute | Content |
|:---|:---|
| `severity` | `'CRITICAL'` / `'HIGH'` / `'MEDIUM'` / `'LOW'` / `'INFO'` |
| `category` | Section name or sink category that triggered the finding |
| `title` | Short finding title |
| `location` | `file:line` or function name |
| `description` | Detailed explanation |
| `recommendation` | Remediation guidance |
| `source` | `'module_audit'` or `'source_audit'` |
| `cwe` | CWE identifier string, or empty |
| `detection_stage` | Effort tier: `'develop'` / `'debug'` / `'test'` / `'deploy'` |

---

## See also

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
