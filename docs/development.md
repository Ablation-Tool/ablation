# Development

How to extend Ablation and run its test suite.

---

## Project structure

```
ablation/
  core/          # Low-level parsers and platform detection. Not for direct use.
  analyzers/     # All analysis tools. New modules go here.
  profiles/      # Vendor-specific YAML: sink lists, safe patterns.
sweeps/          # Standalone sweep scripts; thin drivers over analyzers/.
docs/            # Documentation.
  module-reference/   # One file per module: constructor patterns, API, output format.
  workflows/          # Step-by-step guides for common research tasks.
  known-anomalies/    # Per-ISA taint tracker false-negative conditions.
tests/           # Test suite.
re/              # LOCAL ONLY — per-target findings and session state. Never committed.
```

---

## Build and test

Install in editable mode:

```bash
pip install -e ~/ablation/
```

Run the full test suite:

```bash
cd ~/ablation
python -m pytest tests/ -x -q
```

Run tests for a specific module:

```bash
python -m pytest tests/test_taint_tracker_arm64.py -x -q
```

Check that the package imports cleanly:

```bash
python -c "import ablation; print(ablation.__version__)"
```

---

## Custom scanner workflow

Follow this process when adding a new scanner to Ablation:

1. **Confirm SemanticSearcher has no existing pattern.** Run a query over the target binary first. If a pattern exists, replay it rather than writing a new scanner.

2. **Create `ablation/analyzers/<scanner_name>.py`.** Use `length_underflow.py` as a template. Wire three entry points:
   - `from_context(ctx)` — classmethod constructor
   - `scan()` → list of findings
   - `report(findings)` → formatted string

3. **Run on a known-positive binary.** Analyze false positives: cross-BB register clobber? Trusted source? Callee reads the register before the sink?

4. **Add to `docs/guide-tool-selection.md`** under the appropriate category.

5. **Write `docs/reference-modules/<module>.md`** — open with "Why this exists" as a numbered list of gaps the module fills.

6. **Run FORGE before committing.** See [FORGE gate](#forge-gate) below.

---

## FORGE gate

Every new `ablation/analyzers/*.py` must pass `FORGE.audit_module()` before any git commit.

```python
from ablation.analyzers.forge import FORGE
FORGE.audit_module('/path/to/new_module.py')
```

If the module has not been audited, `FORGE` raises `ForgeAuditRequired`. Perform the 10-section audit inline in the Claude Code session, then call `FORGE.record_result()` to cache the result. The gate blocks on any HIGH or CRITICAL finding.

Audit results are cached at `~/.ablation/forge_cache.json`, keyed by module source hash. A cached pass is instant on subsequent runs.

See [FORGE module reference](reference-modules/forge.md) for full details.

---

## Commit and push

After every commit:

```bash
env HOME=/home/cowboy GIT_LFS_SKIP_SMUDGE=1 git push origin main
```

---

## Adding a new ISA backend

New ISA backends go into `ablation/analyzers/binary_lifter.py` as a new `_<ISA>State` class and a corresponding dispatch branch in `BinaryLifter._lift_structural()`.

Follow the existing pattern:
- `_regs: dict[str, NativeVal]` — per-register state
- `_written: set[str]` — registers written this function
- `_declared: set[str]` — variable names emitted
- `_alloc()` — counter for fresh variable names
- `emit(insn)` — dispatch on mnemonic; emit C expression or `// comment`

Seed `_regs` with the ISA's calling convention argument registers and return register. Use `_walk_ablation_cfg()` as the shared BFS walker.

If the new ISA requires structured control flow (loops, if/else), pass the CFG through `Structurizer` before emission. See `binary_lifter_sh2a.md` for an example.

---

## Hard rules

- `~/ablation/` is never deleted, moved, or destructively modified.
- All ablation edits run in the main session only. Never fork or delegate.
- No findings in the repo: reports, disclosures, and write-ups go into `re/<vendor>/<target>_re.py` only.
- No Ghidra. Ever.
- FORGE gate must pass before any new `.py` is committed.
