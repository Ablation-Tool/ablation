# FORGE

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

1. Loads the SAFE CODE system prompt from `ablation/data/forge_system.md` (external drive fallback).
2. Checks `~/.ablation/forge_cache.json` for a prior result keyed on `sha256(system_prompt)[:16] + ":" + sha256(file_bytes)[:16]`. If found, returns the cached `ForgeReport` immediately.
3. On cache miss, raises `ForgeAuditRequired` with the file path and instructions.

The audit itself runs inline: read the file in Claude Code, apply the 10-section SAFE CODE review, then call `FORGE.record_result()` to cache the result. Future calls return instantly from cache.

`gate_passed` is `True` when no finding has severity `CRITICAL` or `HIGH`.

---

## result_result()

`FORGE.record_result(path, findings, summary, raw_text)` stores an inline audit result in the cache. `findings` can be a list of `ForgeFinding` objects or a list of dicts with keys `severity`, `category`, `title`, `location`, `description`, `recommendation`, `source`, `cwe`.

```python
report = FORGE.record_result(
    '/absolute/path/to/module.py',
    findings=[
        {'severity': 'LOW', 'category': 'reliability', 'title': '...', 'location': '...',
         'description': '...', 'recommendation': '...', 'source': 'module_audit', 'cwe': ''},
    ],
    summary='gate_passed=True. 1 LOW: ...'
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

`ForgeFinding` fields: `severity`, `category`, `title`, `location`, `description`, `recommendation`, `source`, `cwe`.

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
