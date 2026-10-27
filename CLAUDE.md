# Ablation: Claude Operational Reference

## What this tool is

Binary RE toolkit for stripped firmware. No symbols. No source.

**Version:** 2.88.0. Install: `pip install -e ~/ablation/`
**GitHub:** `Ablation-Tool/ablation`. All repo ops via `gh` CLI. `mcp__github` is BANNED.

---

## Package layout

```
ablation/
  core/          # parsers + platform detection (not for direct use)
  analyzers/     # all analysis tools — the RE surface
  profiles/      # vendor-specific YAML sinks/safe patterns
sweeps/          # standalone sweep scripts
re/              # LOCAL ONLY — per-target findings + session state
docs/            # module reference + tool selection guide
tests/
```

**Read `SESSION.md` (root) before any work.** Per-target state: `re/<vendor>/SESSION_<target>.md`.

---

## Session start

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/target.so')
print(ctx.summary())
if ctx.names_count():
    print(ctx.names_table())
# ctx.name(va) everywhere. ctx.set_name(0xVA, "name", source="confirmed")
```

---

## Which tool?

See `docs/guide-tool-selection.md` for the full task→tool lookup table.

**Ordering:** BinaryContext → SemanticSearcher (new binary/vuln class) → FuncProfiler (candidate) → **SinkArgClassifier** (eliminate RODATA_CONST first) → TaintedStringTracker → SnprintfVariableFilter → **NetworkSinkFinder** (networked binaries only) → TaintTracker (ARG_PROPAGATED/UNKNOWN sinks only) → PathSolver (confirm feasibility). Manual capstone only when TaintTracker has no configured sink.

---

## Module quick-reference

See `docs/reference-modules/` for per-module constructor patterns and key methods. Also `docs/INDEX.md`.

---

## RE workflow

**New binary, initial triage:**

1. Read `SESSION.md` (root) + `re/<vendor>/SESSION_<target>.md`
2. `BinaryContext.load_or_build()` + `ctx.summary()` + `ctx.names_table()`
3. `CorpusBuilder.build()` if no prior coverage
4. `SemanticSearcher.query()`: sweep ALL vuln classes before touching disasm
5. `PatternLibrary.sweep()`: replay confirmed patterns from prior engagements
6. `FuncProfiler.profile()` on top candidates
6.5. `SinkArgClassifier.from_context(ctx).classify_all()`: classify ALL shell sink call sites as RODATA_CONST / SNPRINTF_RODATA / ARG_PROPAGATED / UNKNOWN. Eliminate RODATA_CONST and parameterless SNPRINTF_RODATA before TaintTracker runs. Use `from_context(ctx)`, not `from_path()`: `from_path()` returns ~22 func_starts on stripped binaries.
6.6. `TaintedStringTracker.from_context(ctx).upgrade_snprintf_rodata(sac_results)`: upgrade SNPRINTF_RODATA where snprintf format args are tainted (SAC-FORMAT-001). Skipping this caused the pam_hsc.so false-negative (session 2026-10-22).
6.7. `SnprintfVariableFilter.from_context(ctx).apply(sac_results)`: re-classify SNPRINTF_RODATA as injectable when format string contains `%s`. Run on all SNPRINTF_RODATA results before closing them as safe.
6.8. `NetworkSinkFinder.from_context(ctx).find(depth=3)`: for any binary with network PLT imports, filter SAC results to network-reachable sinks only. Skip for local-only binaries (no recv/accept/read in PLT). Returns {} immediately if no network sources found.
7. `TaintTracker` on ARG_PROPAGATED / UNKNOWN sinks only (not the raw SAC set)
8. `IPRegAnnotator` for cross-library call chains
9. `WindowAnalyzer.dump_text()` for manual disasm only when automated tools don't have the sink

**Confirming a finding:**

0. **Byte-verify every VA.** `data = open(binary,'rb').read(); off = va - base; assert data[off:off+n] == expected_bytes`. No exceptions. C16 was carried as CONFIRMED HIGH for six sessions on pattern-match alone. The bytes were wrong.
1. `PathSolver.solve_path()` for feasibility
2. `ctx.set_name(va, name, source="confirmed")`
3. `PatternLibrary.record_hit(confirmed=True)`
4. `FindingRegistry.register()`
5. Write finding to `re/<vendor>/<target>_re.py` (NOT into ablation itself)
6. Update `re/<vendor>/SESSION_<target>.md`

**Custom scanner workflow:**

1. Confirm SemanticSearcher has no existing pattern (run a query first)
2. Create `ablation/analyzers/<scanner_name>.py`; follow `length_underflow.py` as template
3. Wire: `from_context(ctx)` classmethod, `scan()` → findings list, `report(findings)` → str
4. Run on a known-positive binary first; analyze FPs (cross-BB clobber? trusted source? callee reads register?)
5. Add to `docs/guide-tool-selection.md`
6. Write `docs/reference-modules/<module>.md`. Open with "Why this exists" as numbered gaps.

**Cross-version patch analysis:**

1. `DTWMatcher.score_functions()`: same era?
2. `MatrixProfileDiff.diff_functions()`: what changed?
3. `VersionTracker.find_homolog()`: where did it move?

---

## Hard rules

- **GitHub:** active account is `Ablation-Tool`. ALL repo ops via `gh` CLI. `mcp__github` is BANNED.
- **Push:** after every commit: `env HOME=/home/cowboy GIT_LFS_SKIP_SMUDGE=1 git push origin main`
- **Edits:** main session only. Never fork or delegate ablation work.
- **Repo integrity:** `~/ablation/` is never deleted, moved, or destructively modified.
- **No findings in repo:** reports, disclosures, and write-ups never go into the ablation repo.
- **No Ghidra:** ever.
- **Semantic sweep first:** before ANY manual disasm on a new binary or new vuln class.
- **FORGE gate:** run `FORGE.audit_module()` on every new `.py` before any `git commit`. Gate must pass.
- **Gaps become modules:** every missing sink, scanner pattern, or analysis gap → new ablation module. Never a workaround script.
- **Findings go in RE modules:** `re/<vendor>/<target>_re.py`. Nowhere else. NOT `modules/`.
- **Name everything:** `ctx.set_name()` the moment a function is confirmed. `ctx.name(va)` everywhere.
- **Session files:** update `re/<vendor>/SESSION_<target>.md` at end of each session. Update root `SESSION.md` if active target changes.
