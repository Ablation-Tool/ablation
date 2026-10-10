# FORGE Audit: compiler_security_gate.py

> Auditor: FORGE.audit_module (claude --print fallback, no API key required)
> Date: 2026-10-05

---

I have all the information needed to produce the full audit. Here is the complete report.

---

## 1. Scope & Assumptions

**Code reviewed:** `ablation/analyzers/compiler_security_gate.py`, a single Python module (~440 lines) implementing a post-linker binary security gate for the Ablation RE toolkit.

**Language / execution model:** Python 3, used both as an importable library (`CompilerSecurityGate` class) and as a CLI batch tool (`python -m ablation.analyzers.compiler_security_gate <binary>`). Invoked synchronously as a CI gate step after the linker produces its output binary.

**Intended behavior:** After linking, the gate runs Ablation's taint trackers (multi-arch), format string scanner, heap scanner, and length underflow scanner on the binary. It normalizes all results into `GateFinding` objects, builds a `SemanticBlock` DAG per taint path, produces a human-readable report, and returns exit code 0 (CLEAN) or 1 (findings present) for CI integration.

**Assumptions:**
- `Assumption:` `BinaryContext.load_or_build()` (confirmed at line 154: `self.path`) is the intended arch-detection mechanism and is expected to succeed on any valid ELF/PE binary the gate is applied to.
- `Assumption:` The taint tracker module for MIPS32 is `taint_tracker_mips.py` (file confirmed on disk); the CLAUDE.md entry naming it `taint_tracker_mips32` is a doc discrepancy, not a code error.
- `Assumption:` `encoding_dag.SemanticBlock.dag_nodes()` raises `ValueError` on cyclic edge sets (confirmed by code reading and live test).
- `Assumption:` The gate is a hard CI gate; exit 0 means "safe to ship," making false negatives (CLEAN on failure) the most severe failure mode.
- `Assumption:` The `encoding_dag` module (`SemanticBlock`, `DataflowEdge`, `SemanticOp`) is stable and already tested separately.
- `Assumption:` `FormatStringScanner`, `HeapVulnScanner`, and `LengthUnderflowScanner` all expose both `from_context(ctx)` and `from_path(path)` constructors (confirmed by reading their source files).

**Important unknowns:**
- The exact attribute schema guaranteed by each arch taint tracker; the duck-typing in `_normalize_taint` is not validated by any contract.
- Whether the `_run_taint` bare `except Exception: pass` has ever masked a real failure in production use of this gate.
- Typical binary sizes and `run_interprocedural()` wall-clock times in the CI environments this gate targets.

---

## 2. Functional Correctness Assessment

**Finding 2-1: `from_path()` accepts non-existent paths without validation**
- **Type:** Issue
- **Location:** `CompilerSecurityGate.from_path()` (line 256) and `_main()` (line 431)
- **Description:** `from_path(path)` constructs the gate object with no file existence check. All downstream scanners fail silently (see Section 3). Live-tested: `CompilerSecurityGate.from_path('/nonexistent/binary.elf').check()` returns `0` (CLEAN) after printing "Failed to open" to stderr. A typo in the Makefile variable or a build artifact that wasn't produced passes the gate.
- **Recommendation:** Add `if not os.path.isfile(path): raise FileNotFoundError(f"Gate target not found: {path}")` at the top of `from_path()` and in `_main()` before constructing the gate.

---

**Finding 2-2: `_arch()` silently falls back to `x86_64` when BinaryContext build fails**
- **Type:** Issue
- **Location:** `_arch()` (lines 275–279), `_ctx_or_build()` (lines 265–273)
- **Description:** If `BinaryContext.load_or_build()` raises for any reason (unsupported binary format, missing dependency, corrupted ELF), `_ctx_or_build()` catches the exception and returns `None`. `_arch()` then returns `"x86_64"` unconditionally. For a cross-compilation CI workflow (ARM64 firmware, MIPS router binary, RISC-V embedded binary), the wrong taint tracker runs and finds nothing. The gate exits 0.
- **Recommendation:** When `ctx` is `None`, emit a warning and either refuse to run (`raise RuntimeError("Cannot detect arch; BinaryContext failed")`) or require the caller to supply the arch explicitly via an `arch=` parameter.

---

**Finding 2-3: `_normalize_taint` silently drops malformed findings**
- **Type:** Issue
- **Location:** `_normalize_taint()` (lines 207–235)
- **Description:** The entire normalization body is wrapped in `except Exception: return None`. Any tracker that returns objects with different attribute names (e.g., `call_va` instead of `sink_va`, `target` instead of `sink_name`) produces zero `GateFinding` objects with no diagnostic. The comment "Handle duck typing" describes the intent, but provides no visibility into mismatches.
- **Recommendation:** Log a warning on exception before returning `None`. At minimum, count dropped findings and surface the count in `report()`. Consider a `_validate_raw_finding(raw)` pre-check that warns on missing canonical attributes.

---

**Finding 2-4: `_normalize_taint` defaults `sink_name` to `"?"`; always produces HIGH, never CRITICAL**
- **Type:** Risk
- **Location:** `_normalize_taint()` (line 216), `_taint_severity()` (lines 201–204)
- **Description:** `getattr(raw, "sink_name", getattr(raw, "sink", "?"))`. If neither attribute is present, `sink_name = "?"`. `"?"` is not in `_CRITICAL_SINKS`, so `_taint_severity` returns `"HIGH"`. A taint path reaching `system()` in a tracker that exposes the sink as, say, `target_name` instead of `sink_name` would be misclassified as HIGH instead of CRITICAL, potentially masking command injection from strict-mode blocking logic.
- **Recommendation:** Log a warning when `sink_name == "?"` and treat it as CRITICAL-candidate (or UNKNOWN severity with explicit escalation comment) rather than silently downgrading.

---

**Finding 2-5: DAG node ID collision on duplicate register names**
- **Type:** Risk
- **Location:** `_taint_dag()` (lines 118–130)
- **Description:** `nid = f"carry_{reg}"` is constructed from the register name. If `tainted_regs` contains the same register name twice (e.g., `["rdi", "rdi"]` from a tracker that emits duplicates), two `add_op` calls with the same `node_id` are made. `dag_nodes()` builds `by_id` as a dict; the second op silently overwrites the first. This corrupts the taint chain display without error.
- **Recommendation:** Deduplicate `tainted_regs` before the loop, or use a counter suffix (`f"carry_{reg}_{i}"`).

---

**Finding 2-6: `report()` produces double-blank-line output**
- **Type:** Risk (minor cosmetic / parsing)
- **Location:** `report()` (lines 392–397)
- **Description:** `lines` contains strings that already end with `\n` (the `header`, the summary line, and each `f.fmt()`). `"\n".join(lines)` inserts an additional `\n` between each element, producing blank lines before the result summary and between every finding. Downstream tooling that parses the report by double-newline delimiters would misparse it.
- **Recommendation:** Either strip trailing newlines from each element before joining, or use `"".join(lines)` instead of `"\n".join(lines)`.

---

**Finding 2-7: `check()` re-runs `scan()` independently**
- **Type:** Issue (correctness + efficiency)
- **Location:** `check()` (line 406), `_main()` (lines 432–435)
- **Description:** `check()` calls `self.scan()` unconditionally. In `_main()`, `findings = gate.scan()` is called at line 432, then `gate.check()` at line 435 invokes `scan()` again. Live-tested: `scan()` is called exactly 2× in the CLI path. This is not merely a performance issue; if any scanner is non-deterministic (e.g., depends on ordering of dict iteration in an interpreter with random seed), the two scans could return different results, and the report and exit code would be based on different data.
- **Recommendation:** Add `check(self, findings=None)` that accepts pre-computed findings: `if findings is None: findings = self.scan()`. Update `_main()` to pass `findings` to `check()`.

---

**Finding 2-8: Positive: clean `dataclass`-based `GateFinding` with optional DAG field**
- **Type:** Positive
- **Location:** `GateFinding` (lines 65–93)
- **Description:** Using `@dataclass` with a typed optional `taint_dag` field keeps the finding schema explicit and IDE-navigable. The separation of the DAG annotation from the core finding fields is clean.

---

## 3. Operational Safety & Failure Modes

**Finding 3-1: All scanner runners swallow `Exception` silently; gate always reports CLEAN on total failure**
- **Severity:** HIGH
- **Location:** `_run_taint()` (lines 152–198), `_run_format_string()` (lines 283–304), `_run_heap()` (lines 306–325), `_run_length_underflow()` (lines 327–349)
- **Description:** Every scanner runner wraps its body in `except Exception: pass/return []`. An `ImportError` (module not installed), a runtime crash in a taint tracker, an `OSError` during binary loading; all produce `[]` findings. From the gate's perspective these are indistinguishable from "analysis completed, no vulnerabilities." In a CI environment, a broken Ablation install silently passes every binary.
- **Recommendation:** Change the pattern to: catch the exception, emit a stderr warning with the scanner name and exception message, set a `scan_errors: List[str]` attribute on the gate, and surface errors in `report()`. Exit code 1 when any scanner error occurs (unless a `--allow-scan-errors` flag is passed explicitly).

---

**Finding 3-2: No binary file existence or readability check before analysis**
- **Severity:** HIGH
- **Location:** `from_path()` (line 256), `_main()` (lines 431–435)
- **Description:** Confirmed by live test: passing a non-existent path produces `scan() = []`, `check() = 0`. The "Failed to open" messages printed by the scanners go to stderr, which is typically not checked by Makefile `$(shell ...)` invocations. A CI system relying on exit code alone will treat a missing build artifact as a passing gate.
- **Recommendation:** Validate `os.path.isfile(path)` and `os.access(path, os.R_OK)` in `from_path()` before constructing the gate. Raise `FileNotFoundError` immediately rather than deferring failure.

---

**Finding 3-3: `GateFinding.fmt()` propagates unguarded `ValueError` from `dag_nodes()`**
- **Severity:** MEDIUM
- **Location:** `GateFinding.fmt()` (lines 79–85), `SemanticBlock.dag_nodes()` (encoding_dag.py line 314)
- **Description:** `dag_nodes()` raises `ValueError` when a cycle is detected in the DAG. The current `_taint_dag()` construction is acyclic (source→carry→sink topology), but the `ValueError` is confirmed to propagate. If taint tracker raw findings ever carry pre-built DAG-like objects that are passed through, or if future changes to `_taint_dag` introduce a cycle (e.g., when `source_calls` and `tainted_regs` happen to share the same string), `fmt()` raises. This crashes `report()` inside a `print()` call in `_main()` with an unhandled exception traceback. The exit code from an unhandled exception is system-dependent but is typically 1, so the gate technically blocks; the diagnostic is a Python traceback, not a finding report.
- **Recommendation:** Wrap `list(self.taint_dag.dag_nodes())` in `try/except ValueError` inside `fmt()`, falling back to insertion-order iteration. Separately, add cycle detection or assertion to `_taint_dag()` itself.

---

**Finding 3-4: No timeout on taint tracker `run_interprocedural()`**
- **Severity:** MEDIUM
- **Location:** `_run_taint()` (lines 150–198), all `run_interprocedural()` call sites
- **Description:** Inter-procedural taint analysis on a large binary can take arbitrarily long. There is no timeout, watchdog, or cancellation mechanism. A heavily inlined binary or an adversarially crafted binary with deep call graphs can hang the CI job indefinitely.
- **Recommendation:** Run each scanner in a subprocess or thread with a configurable timeout (`ABLATION_GATE_TIMEOUT_SECS` env var, default 300s). On timeout, record a `SCAN_TIMEOUT` error and proceed.

---

**Finding 3-5: Positive: `_SEV_ORDER.keys()` in strict mode is functionally correct**
- **Severity:** N/A (Positive)
- **Location:** `check()` (line 409)
- **Description:** Using `_SEV_ORDER.keys()` as the blocking set in strict mode works correctly: `dict_keys` supports O(1) `in` membership testing and enumerates all defined severity strings. Not a bug.

---

## 4. Reliability & Resilience Issues

**Finding 4-1: Repeated expensive retries on `BinaryContext` build failure**
- **Severity:** MEDIUM
- **Location:** `_ctx_or_build()` (lines 265–273)
- **Description:** When `BinaryContext.load_or_build()` raises, `self._ctx` remains `None`. Every subsequent call to `_arch()`, `_run_format_string()`, `_run_heap()`, and `_run_length_underflow()` calls `_ctx_or_build()`, which retries the expensive context build. On a binary that consistently fails to parse, the context build runs N+1 times (once per scanner call) rather than once.
- **Recommendation:** On first failure, set `self._ctx` to a sentinel value (e.g., a private `_CTX_FAILED` singleton or `False`) so subsequent calls skip the retry: `if self._ctx is _CTX_FAILED: return None`.

---

**Finding 4-2: No error accumulation or partial-results reporting**
- **Severity:** MEDIUM
- **Location:** `scan()` (lines 353–376), `report()` (lines 378–397)
- **Description:** When one or more scanners fail, `scan()` returns only the findings from scanners that succeeded. `report()` presents this as the complete result with no indication that some analysis was skipped. A user reviewing the report has no way to know whether the HEAP category was skipped because there are no heap vulnerabilities, or because `HeapVulnScanner` crashed.
- **Recommendation:** Add `self._scan_errors: List[str]` to track scanner names and exception messages. Include them in `report()` under a `SCAN ERRORS` section. Add `has_scan_errors: bool` to the gate API for programmatic checks.

---

**Finding 4-3: `from_context()` assumes `ctx.path` attribute exists without guard**
- **Severity:** LOW
- **Location:** `from_context()` (lines 259–261)
- **Description:** `return cls(binary_path=ctx.path, ctx=ctx)`. Confirmed that `BinaryContext` uses `self.path`, but any other context-like object passed here that lacks `.path` raises `AttributeError` with no informative message.
- **Recommendation:** Add `if not hasattr(ctx, 'path'): raise TypeError(f"ctx must have a .path attribute; got {type(ctx)}")`.

---

**Finding 4-4: Positive: lazy BinaryContext construction via `_ctx_or_build()`**
- **Severity:** N/A (Positive)
- **Location:** `_ctx_or_build()` (lines 265–273)
- **Description:** Delaying BinaryContext construction until first use means `from_path()` is cheap and the gate can be instantiated in environments where context building is not always needed (e.g., `check()` with an already-cached context).

---

## 5. Performance & Resource Use Considerations

**Finding 5-1: Full analysis runs twice in CLI invocation**
- **Impact:** HIGH
- **Location:** `_main()` (lines 432–435), `check()` (line 406)
- **Description:** `_main()` calls `gate.scan()` (line 432) to get findings for `report()`, then calls `gate.check()` (line 435) which calls `self.scan()` again unconditionally. Live-tested and confirmed: `scan()` is invoked exactly 2× per CLI run. On a large binary where each scan takes minutes, this doubles build time.
- **Recommendation:** Pass pre-computed findings to `check()`: modify `check(self, findings=None)` and update `_main()` to `gate.check(findings=findings, strict=args.strict)`.

---

**Finding 5-2: No result caching between `scan()` calls**
- **Impact:** MEDIUM
- **Location:** `scan()` (lines 353–376)
- **Description:** Each call to `scan()` re-runs all trackers from scratch. Library users calling `scan()` for reporting and `check()` for gating run the full analysis at least twice. There is no memoization or cached-findings store on the gate instance.
- **Recommendation:** Optionally cache findings internally: `self._cached_findings: Optional[List[GateFinding]] = None`. `scan()` returns cached findings on second call. Add a `rescan=False` parameter to force a fresh run.

---

**Finding 5-3: x86_64 XRefGraph rebuild on every invocation**
- **Impact:** MEDIUM
- **Location:** `_run_taint()` (lines 154–158), x86_64 path
- **Description:** `XRefGraph.from_path(path); xg.build()` is called inside `_run_taint()` on every scan. If `BinaryContext` was already built externally (e.g., via `from_context(ctx)`), the XRefGraph is rebuilt from scratch rather than derived from the existing context.
- **Recommendation:** When `self._ctx` is available for x86_64, check if `ctx` exposes an `xref_graph` or similar; pass it directly rather than rebuilding.

---

## 6. Maintainability & Operability Observations

**Finding 6-1: Silent exception swallowing makes CI debugging impossible**
- **Type:** Operability
- **Description:** All five scanner runners (`_run_taint`, `_run_format_string`, `_run_heap`, `_run_length_underflow`, `_ctx_or_build`) silently discard exceptions. In a CI environment where logs are the only diagnostic surface, a broken install, a missing dependency, or a scanner regression produces no logged output. The gate "passes" and the team has no signal.
- **Suggestion:** Replace all bare `except Exception: pass` / `return []` with at minimum `import warnings; warnings.warn(f"[CompilerSecurityGate] {scanner_name} failed: {e}", RuntimeWarning)` and collect into `self._scan_errors`.

---

**Finding 6-2: `_run_taint` architecture dispatch via long if-chain**
- **Type:** Maintainability / Complexity
- **Description:** Ten consecutive `if arch == "..."` branches each containing an import and a function call is hard to extend. Adding a new architecture (e.g., `xtensa`, `s390x`) requires editing the middle of the function body and remembering to stay inside the outer `try/except`.
- **Suggestion:** Replace with a dispatch dict: `_TAINT_DISPATCH: Dict[str, Callable[[str], List[Any]]] = {"x86_64": _run_taint_x86, ...}`. Each arch gets a small private function. `_run_taint` becomes a single lookup + call.

---

**Finding 6-3: Module docstring claims `mips32` support but CLAUDE.md names the module `taint_tracker_mips32`**
- **Type:** Maintainability / Readability
- **Description:** The module docstring correctly lists `mips32` in "Architecture support." The file on disk is `taint_tracker_mips.py` (not `taint_tracker_mips32.py`). The CLAUDE.md entry names it `taint_tracker_mips32`; the documentation is wrong, not the code, but this creates confusion for future developers trying to locate the MIPS32 tracker from the docs.
- **Suggestion:** Update the CLAUDE.md table entry to reflect the actual filename `taint_tracker_mips`.

---

**Finding 6-4: No `--verbose` / `--debug` flag for scanner-level diagnostics**
- **Type:** Operability
- **Description:** The CLI offers only `--strict` and `--quiet`. There is no flag to surface scanner timing, the number of raw taint findings before normalization, dropped findings, or which scanners ran. Diagnosing false-negative reports requires modifying source code.
- **Suggestion:** Add `--verbose` to print per-scanner result counts and any suppressed exceptions to stderr.

---

**Finding 6-5: `field` is imported but unused**
- **Type:** Maintainability / Readability
- **Location:** Line 45: `from dataclasses import dataclass, field`
- **Description:** `field` is imported but never used in this file (`GateFinding` has no `field(default_factory=...)` annotations). Stale import.
- **Suggestion:** Remove `field` from the import.

---

## 7. Data Integrity & Consistency Risks

**Finding 7-1: No deduplication; same vulnerability site can appear from multiple scanners**
- **Severity:** LOW
- **Location:** `scan()` (lines 353–376)
- **Description:** A format-string vulnerability that also matches a taint path (e.g., tainted input flowing to `printf` with a non-literal format) would appear once from `TaintTracker` (category `TAINT_FLOW`) and once from `FormatStringScanner` (category `FORMAT_STRING`) with no cross-reference. A reviewer counting findings would double-count the severity.
- **Recommendation:** After aggregating all findings, deduplicate on `(func_va, site_va, sink/fmt-function)` and annotate the finding with all detector names that flagged it.

---

**Finding 7-2: `_normalize_taint` drops findings silently; gate may report fewer HIGH findings than actually exist**
- **Severity:** HIGH
- **Location:** `_normalize_taint()` (lines 207–235), `scan()` (lines 364–367)
- **Description:** The `if gf is not None` filter at line 366 silently excludes any taint finding that failed normalization. If a new arch taint tracker uses slightly different attribute names (e.g., `call_site` instead of `sink_va`), all of its findings are dropped. The gate reports CLEAN. This is not a theoretical concern; it is the exact failure mode that would occur when integrating a new tracker without updating `_normalize_taint`.
- **Recommendation:** Count the number of raw findings vs. normalized findings. If `len(normalized) < len(raw_taint)`, include a `NORMALIZATION_WARNINGS: N finding(s) dropped` line in the report and return exit code 1 if any were dropped (or add a `--strict-normalization` flag).

---

**Finding 7-3: Severity downgrade from unknown sink name**
- **Severity:** MEDIUM
- **Location:** `_normalize_taint()` (line 216), `_taint_severity()` (lines 201–204)
- **Description:** As described in 2-4: sink name defaults to `"?"` → severity always `"HIGH"` → CRITICAL sinks in unrecognized trackers are misclassified. In non-strict mode this doesn't change the blocking behavior (both CRITICAL and HIGH block), but in strict mode only, MEDIUM and LOW are also blocking; the severity misclassification corrupts the audit trail and could mislead triage.
- **Recommendation:** Treat `sink_name == "?"` as UNKNOWN severity with explicit logging rather than silently mapping to HIGH.

---

## 8. Testing & Verification Suggestions

**Unit tests:**
- `CompilerSecurityGate.from_path('/nonexistent')`: assert `FileNotFoundError` is raised (after the fix from 2-1).
- `_normalize_taint(raw)` with a mock object missing `sink_name` and `sink`: assert warning is emitted and return value reflects the unknown-sink case.
- `_normalize_taint(raw)` with `sink_name="system"`: assert `severity == "CRITICAL"`.
- `_normalize_taint(raw)` with every required attribute present and correct: assert a valid `GateFinding` is returned with populated `taint_dag`.
- `_taint_dag([], [], "system", 0x1234, [])`: assert the resulting `SemanticBlock` has a source node with label `<unknown>` and a sink node `system`.
- `_taint_dag(["recv"], ["rdi", "rdi"], "system", 0x1234, [0])`: assert no duplicate node IDs (regression for Finding 2-5).
- `GateFinding.fmt()` with a cyclic DAG: assert `ValueError` is caught and a fallback string is returned (after guarding).
- `check(findings=pre_computed)`: assert `scan()` is not called when findings are provided (regression for Finding 2-7 double-scan fix).
- `scan()` called twice on the same gate instance: assert the second call does not re-run analysis if caching is implemented.
- `report()` output: assert no double blank lines (regression for Finding 2-6).
- `_arch()` when `BinaryContext` raises: assert behavior matches documented contract (raises or returns a clearly-labeled fallback, not silent `x86_64`).

**Integration / end-to-end tests:**
- Provide a small known-vulnerable x86_64 ELF (taint path from `recv` to `system`): assert gate returns exit 1, report contains CRITICAL/HIGH finding, `taint_dag` is populated.
- Provide a clean x86_64 ELF with no taint paths: assert gate returns exit 0, report contains "CLEAN."
- Simulate `FormatStringScanner` import failure (patch `__import__` to raise `ImportError`): assert gate does NOT exit 0 silently after fix; assert error is surfaced in report.
- Run gate on an ARM64 binary with a known taint path: assert `ARM64TaintTracker.from_path_full` was called (not `TaintTracker`).
- CLI `--strict` mode on a binary with MEDIUM-only findings: assert exit code is 1.
- CLI `--quiet` mode: assert no stdout output, exit code still correct.
- `gate.scan()` then `gate.check(findings=findings)`: assert `scan()` is called exactly once (regression test for double-scan fix).

**Non-functional tests:**
- **Load/soak:** Run gate on a large production binary (e.g., stripped 50MB ELF). Record wall time per scanner. Establish baselines; alert if > 5× baseline in CI.
- **Timeout behavior:** Provide a synthetic binary or mock tracker that sleeps 600s in `run_interprocedural()`. Assert gate times out gracefully after the configured limit and reports `SCAN_TIMEOUT` rather than hanging.
- **Memory:** Run gate on a series of 20 consecutive binaries without process restart. Assert no unbounded memory growth (BinaryContext cache should bound memory use).

**Tooling (generic):**
- **Static type checker** (e.g., mypy): catches the `_run_taint` return type inconsistency (returns `List[Any]` but callers iterate and duck-type), the untyped `ctx=` parameter in `__init__`, and the unguarded `Optional` returns.
- **Linter with unused-import detection**: would flag `field` import (Finding 6-5) immediately.
- **Coverage tool**: measuring coverage on `_run_taint` reveals that many architecture branches are untested in the unit suite, showing which arch-specific failure modes are invisible.
- **Mutation tester**: would confirm that the `gf is not None` guard in `scan()` is actually tested; a mutation removing that guard should fail at least one test.

---

## 9. Prioritized Production Readiness Checklist

1. **Add file existence and readability validation in `from_path()` and `_main()`**: raises `FileNotFoundError` immediately on missing binary. Effort: Low. (Refs: 2-1, 3-2)

2. **Replace all silent `except Exception: pass/return []` with error accumulation and surfacing**: collect scanner name + exception in `self._scan_errors`; include in `report()`; exit 1 when any scanner error occurred. Effort: Medium. (Refs: 3-1, 4-2, 6-1)

3. **Fix double-scan in CLI and `check()` method**: add `check(self, findings=None, strict=False)` accepting pre-computed findings; update `_main()` to pass findings. Effort: Low. (Refs: 2-7, 5-1)

4. **Guard `_arch()` against silent `x86_64` fallback**: when BinaryContext fails, either raise or require explicit `arch=` argument; never silently mismatch architecture. Effort: Low. (Refs: 2-2)

5. **Add normalization-failure accounting in `_normalize_taint` / `scan()`**: count dropped findings; emit a warning and optionally block. Effort: Low. (Refs: 2-3, 7-2)

6. **Treat `sink_name == "?"` as UNKNOWN / CRITICAL-candidate, not silent HIGH**: emit a warning; do not silently downgrade potentially-CRITICAL findings. Effort: Low. (Refs: 2-4, 7-3)

7. **Guard `GateFinding.fmt()` against `ValueError` from `dag_nodes()`**: wrap in `try/except ValueError`, fall back to insertion-order iteration. Effort: Low. (Refs: 3-3)

8. **Deduplicate `tainted_regs` in `_taint_dag()` to prevent node ID collision**: `tainted_regs = list(dict.fromkeys(tainted_regs))` before the carry loop. Effort: Low. (Refs: 2-5)

9. **Add scanner timeout mechanism**: configurable via env var; run each tracker with a timeout; record `SCAN_TIMEOUT` errors. Effort: High. (Refs: 3-4)

10. **Fix `report()` newline handling**: change `"\n".join(lines)` to `"".join(lines)` since each element already ends with `\n`. Effort: Low. (Refs: 2-6)

11. **Add result caching to `scan()`**: memoize findings on first call; expose `rescan=False` parameter. Effort: Low. (Refs: 5-2)

12. **Replace `_run_taint` if-chain with dispatch dict**: each arch in its own private function; the `try/except` can be per-arch for more precise error attribution. Effort: Low. (Refs: 6-2)

13. **Remove unused `field` import**: trivial cleanup. Effort: Low. (Refs: 6-5)

14. **Add `--verbose` CLI flag** for per-scanner diagnostics. Effort: Low. (Refs: 6-4)

15. **Add `from_context()` guard for missing `.path` attribute**. Effort: Low. (Refs: 4-3)

---

## 10. Residual Risk & Limitations

This assessment is based solely on the provided source file and the related files read during review (`encoding_dag.py`, `binary_context.py`, `length_underflow.py`, `format_string_scanner.py`, `heap_vuln_scanner.py`). The following limitations apply:

- **Taint tracker schemas are unverified**: The duck-typing in `_normalize_taint` is correct in intent but impossible to validate without reading every arch taint tracker. If any tracker has returned findings with different attribute names and this gate was silently dropping them, that would not be visible without instrumentation.
- **Downstream scanner behavior on large binaries is unknown**: `run_interprocedural()` behavior, memory use, and wall time at scale are outside scope of this review.
- **`encoding_dag` cycle behavior**: The current `_taint_dag()` construction is acyclic, but future changes that add back-edges (e.g., annotating recursive taint paths) would silently crash `report()` without the fix to Finding 3-3.
- **Arch coverage in tests**: No test suite was reviewed. It is unknown whether any non-x86_64 arch has integration test coverage in CI. The most likely undetected failure mode is the silent arch mismatch (Finding 2-2) on cross-compilation workflows.
- **Next steps to reduce residual risk**: (1) Instrument the gate with `--verbose` and run it against a real cross-arch binary to confirm arch detection works. (2) Inject a `ImportError` for each scanner module and assert the error is surfaced after implementing Finding 3-1 fix. (3) Review all arch taint tracker `__init__` and `run_interprocedural` return types against `_normalize_taint`'s expected attribute set. (4) Add a `test_gate_on_nonexistent_path` test immediately, before any other change.

---

---

# DEV & TEST ORCHESTRATION PLAN (ADDITIVE)

---

## A. Dev Work Items by Category

### A.1 Functional Corrections

- **Validate binary file existence and readability in `from_path()` and `_main()` before constructing the gate.**
  Add `if not os.path.isfile(path) or not os.access(path, os.R_OK): raise FileNotFoundError(...)` as the first statement in `from_path()` and as an argument check in `_main()` before `CompilerSecurityGate.from_path(args.binary)`.
  Source Finding(s): Section 2 – Finding 2-1, Section 3 – Finding 3-2.
  Scope Hint: `CompilerSecurityGate.from_path()` (line 256), `_main()` (line 431).

- **Eliminate the silent `x86_64` fallback in `_arch()` when `BinaryContext` fails.**
  When `_ctx_or_build()` returns `None`, either raise `RuntimeError("Cannot determine binary architecture; BinaryContext failed. Use from_context(ctx) or supply arch= explicitly.")` or add an `arch: Optional[str] = None` parameter to `__init__`/`from_path()` for explicit override.
  Source Finding(s): Section 2 – Finding 2-2.
  Scope Hint: `_arch()` (line 275), `__init__()` (line 251), `from_path()` (line 256).

- **Add findings-drop accounting in `_normalize_taint()` and report it in `scan()`.**
  Before returning `None`, append to a module-level or gate-instance list: `(type(raw).__name__, repr(e))`. In `scan()`, if `len(raw_taint) > len(normalized)`, set `self._scan_errors` entry and include in `report()`.
  Source Finding(s): Section 2 – Finding 2-3, Section 7 – Finding 7-2.
  Scope Hint: `_normalize_taint()` (line 234), `scan()` (lines 364–367).

- **Treat `sink_name == "?"` as UNKNOWN/CRITICAL-candidate, not silent HIGH.**
  In `_normalize_taint()`, when `sink_name == "?"`, log a warning and assign severity `"CRITICAL"` with a note "sink name unresolvable; conservatively escalated."
  Source Finding(s): Section 2 – Finding 2-4, Section 7 – Finding 7-3.
  Scope Hint: `_normalize_taint()` (line 216), `_taint_severity()` (line 201).

- **Deduplicate `tainted_regs` before constructing carry nodes in `_taint_dag()`.**
  Add `tainted_regs = list(dict.fromkeys(tainted_regs))` before the `for reg in (tainted_regs or []):` loop to prevent duplicate `node_id` values.
  Source Finding(s): Section 2 – Finding 2-5.
  Scope Hint: `_taint_dag()` (line 119).

- **Fix `report()` double-newline output by using `"".join(lines)` instead of `"\n".join(lines)`.**
  Each element in `lines` already ends with `\n`; `"\n".join()` inserts a redundant separator.
  Source Finding(s): Section 2 – Finding 2-6.
  Scope Hint: `report()` (line 397).

- **Fix double-scan: add `findings` parameter to `check()` and update `_main()` to pass pre-computed findings.**
  Change `def check(self, strict=False)` to `def check(self, findings=None, strict=False)`. Inside: `if findings is None: findings = self.scan()`. In `_main()`, call `gate.check(findings=findings, strict=args.strict)`.
  Source Finding(s): Section 2 – Finding 2-7, Section 5 – Finding 5-1.
  Scope Hint: `check()` (line 399), `_main()` (line 435).

- **Remove unused `field` import.**
  `field` is imported from `dataclasses` at line 45 but never used. Remove it.
  Source Finding(s): Section 6 – Finding 6-5.
  Scope Hint: Line 45.

### A.2 Operational Safety Improvements

- **Replace all bare `except Exception: pass / return []` in scanner runners with error accumulation.**
  In each scanner runner (`_run_taint`, `_run_format_string`, `_run_heap`, `_run_length_underflow`, `_ctx_or_build`), catch the exception, record `(scanner_name, str(e))` in `self._scan_errors: List[Tuple[str, str]]`, and emit `warnings.warn(...)` or write to stderr. In `report()`, append a `SCAN ERRORS` section when `self._scan_errors` is non-empty. In `check()`, return exit code 1 if any scan error is present (or gate behind a `--allow-scan-errors` flag).
  Source Finding(s): Section 3 – Finding 3-1, Section 4 – Finding 4-2, Section 6 – Finding 6-1.
  Scope Hint: Lines 152–198, 283–349, 265–273.

- **Guard `GateFinding.fmt()` against `ValueError` from `dag_nodes()`.**
  Wrap `list(self.taint_dag.dag_nodes())` in `try/except ValueError`, falling back to `list(self.taint_dag.ops)` (insertion order).
  Source Finding(s): Section 3 – Finding 3-3.
  Scope Hint: `GateFinding.fmt()` (lines 79–85).

- **Add `from_context()` guard for missing `.path` attribute.**
  Add `if not hasattr(ctx, 'path'): raise TypeError(...)` at the top of `from_context()`.
  Source Finding(s): Section 4 – Finding 4-3.
  Scope Hint: `from_context()` (line 259).

### A.3 Reliability & Resilience Enhancements

- **Prevent repeated BinaryContext rebuild on repeated failure.**
  Introduce a sentinel `_CTX_FAILED = object()`. In `_ctx_or_build()`, on exception set `self._ctx = _CTX_FAILED`. At the top of `_ctx_or_build()`, add `if self._ctx is _CTX_FAILED: return None`.
  Source Finding(s): Section 4 – Finding 4-1.
  Scope Hint: `_ctx_or_build()` (lines 265–273).

- **Implement configurable timeout for `run_interprocedural()` calls.**
  Run each taint tracker call in a `concurrent.futures.ThreadPoolExecutor` with a `timeout` parameter, configurable via `ABLATION_GATE_TIMEOUT_SECS` env var (default 300). On `TimeoutError`, record a `SCAN_TIMEOUT` error in `self._scan_errors` and return `[]` for that arch.
  Source Finding(s): Section 3 – Finding 3-4.
  Scope Hint: `_run_taint()` (line 150), scanner runner methods.

- **Add result caching inside `scan()`.**
  Add `self._cached_findings: Optional[List[GateFinding]] = None` in `__init__`. In `scan()`: if `self._cached_findings is not None: return self._cached_findings`. Set `self._cached_findings = findings` before returning. Add `rescan: bool = False` parameter to force a fresh run.
  Source Finding(s): Section 5 – Finding 5-2.
  Scope Hint: `scan()` (line 353), `__init__()` (line 251).

### A.4 Performance & Resource Tuning

- **Eliminate the redundant XRefGraph build on x86_64 when a context is available.**
  In the x86_64 branch of `_run_taint()`, check if `self._ctx` (passed via a `ctx=` parameter or accessed via closure) exposes an existing XRefGraph. If so, pass it directly to `TaintTracker(path, xref=existing_xg)` rather than calling `XRefGraph.from_path(path); xg.build()`.
  Source Finding(s): Section 5 – Finding 5-3.
  Scope Hint: `_run_taint()` (lines 154–158). Requires refactoring `_run_taint` to accept a `ctx` argument.

### A.5 Maintainability & Operability Refactors

- **Replace the 10-branch `if arch == "..."` chain in `_run_taint()` with a dispatch dict.**
  Extract each arch branch into a small private function (e.g., `_run_taint_arm64(path)`). Build `_TAINT_DISPATCH: Dict[str, Callable[[str], List[Any]]]`. `_run_taint()` becomes a single lookup and call. Per-arch errors can be caught in each small function independently.
  Source Finding(s): Section 6 – Finding 6-2.
  Scope Hint: `_run_taint()` (lines 150–198).

- **Add `self._scan_errors` attribute and expose it in `report()` and via a public property.**
  Initialize `self._scan_errors: List[Tuple[str, str]] = []` in `__init__`. Surface in `report()` as a `SCAN ERRORS (N)` section. Expose `gate.scan_errors` as a read-only property.
  Source Finding(s): Section 4 – Finding 4-2, Section 6 – Finding 6-1.
  Scope Hint: `__init__()`, `report()`, all scanner runners.

- **Add `--verbose` CLI flag for scanner-level diagnostics.**
  When `--verbose` is set, print to stderr: which scanner ran, raw finding count, normalized finding count, and any scan errors. Does not affect stdout or exit code.
  Source Finding(s): Section 6 – Finding 6-4.
  Scope Hint: `_main()` (lines 418–435), `argparse` setup.

- **Add post-scan deduplication on `(func_va, site_va)` with multi-detector annotation.**
  After collecting all findings in `scan()`, group by `(func_va, site_va)` and merge entries that share both addresses into a single `GateFinding` whose `detector` field is comma-separated (e.g., `"TaintTracker, FormatStringScanner"`). Keep the highest severity among merged findings.
  Source Finding(s): Section 7 – Finding 7-1.
  Scope Hint: `scan()` (lines 353–376).

---

## B. Test Plan by Level

### B.1 Unit Tests

- **Target:** `CompilerSecurityGate.from_path()`
  - Scenarios: Non-existent path; path that exists but is not readable; valid path to a real ELF.
  - Expected Behavior: `FileNotFoundError` on missing path; `PermissionError` on unreadable path; gate instance returned on valid path. (After A.1 fix.)

- **Target:** `_normalize_taint(raw)`
  - Scenarios: Raw object with all canonical attrs (`func_va`, `sink_va`, `sink_name`, `tainted_args`, `tainted_regs`, `source_calls`); raw object missing `sink_name` and `sink`; raw object missing `sink_va` and `site_va`; object that raises `AttributeError` on any access.
  - Expected Behavior: Full `GateFinding` for canonical case; CRITICAL severity escalation and warning log for `sink_name="?"`; `func_va=0` for missing VA; warning emitted and `None` returned on `AttributeError`.

- **Target:** `_taint_severity(sink_name)`
  - Scenarios: Each name in `_CRITICAL_SINKS`; `"memcpy"`; `"?"`.
  - Expected Behavior: `"CRITICAL"` for all names in the frozenset; `"HIGH"` for others.

- **Target:** `_taint_dag(source_calls, tainted_regs, sink_name, sink_va, tainted_args)`
  - Scenarios: Empty `source_calls` and empty `tainted_regs`; single source, single reg, single arg; duplicate register names in `tainted_regs` (regression for Finding 2-5); empty `tainted_args`.
  - Expected Behavior: Single `<unknown>` source node when `source_calls=[]`; no duplicate `node_id` values after deduplication fix; `dag_nodes()` does not raise `ValueError`.

- **Target:** `GateFinding.fmt()`
  - Scenarios: `taint_dag=None`; `taint_dag` with a valid acyclic graph; `taint_dag` with a cyclic graph (regression for Finding 3-3).
  - Expected Behavior: No `dag_note` section when `taint_dag=None`; chain rendered correctly for acyclic graph; no `ValueError` raised for cyclic graph; fallback output returned.

- **Target:** `CompilerSecurityGate.check()`
  - Scenarios: No findings; CRITICAL finding, non-strict; HIGH finding, non-strict; MEDIUM finding, non-strict; MEDIUM finding, strict; pre-computed `findings` passed (after A.1 fix; assert `scan()` not called).
  - Expected Behavior: Exit 0 for no findings; exit 1 for CRITICAL/HIGH in non-strict; exit 0 for MEDIUM in non-strict; exit 1 for MEDIUM in strict; `scan()` called 0 additional times when findings passed.

- **Target:** `report()` output format
  - Scenarios: Zero findings; one CRITICAL finding with DAG; multiple findings of mixed severity.
  - Expected Behavior: No double blank lines; `CLEAN` message on zero findings; summary shows counts by severity in correct order.

- **Target:** `_arch()` fallback behavior
  - Scenarios: `_ctx_or_build()` raises; `ctx.arch` attribute missing; `ctx.arch == "arm64"`.
  - Expected Behavior: After fix, raises `RuntimeError` (not silently returns `x86_64`); returns `"arm64"` when attribute is set.

- **Target:** `_ctx_or_build()` sentinel after failure
  - Scenarios: `BinaryContext.load_or_build()` raises on first call; call `_ctx_or_build()` a second time.
  - Expected Behavior: After fix, `BinaryContext.load_or_build()` called exactly once (not twice).

### B.2 Integration Tests

- **Interaction:** `CompilerSecurityGate` + real x86_64 ELF containing a known `recv`→`system` taint path
  - Happy Path: `gate.scan()` returns ≥1 `GateFinding` with `severity="CRITICAL"`, `category="TAINT_FLOW"`, `taint_dag` populated.
  - Failure Scenario: `TaintTracker` module not installed (`ImportError`); after fix, gate returns scan error in `report()` and exits 1.
  - Expected Behavior: CRITICAL finding confirmed; error surfaced and gate does not silently return CLEAN.

- **Interaction:** `CompilerSecurityGate` + real ARM64 ELF
  - Happy Path: `_arch()` returns `"arm64"`; `ARM64TaintTracker.from_path_full()` is invoked (not x86_64 tracker).
  - Failure Scenario: `BinaryContext.load_or_build()` raises; after fix, gate raises or uses explicit arch override.
  - Expected Behavior: Correct tracker dispatched; no silent arch fallback.

- **Interaction:** `CompilerSecurityGate` + `FormatStringScanner` on ELF with non-literal printf call
  - Happy Path: `FORMAT_STRING` finding returned; `detector == "FormatStringScanner"`.
  - Failure Scenario: `FormatStringScanner` import raises; after fix, scan error recorded, gate exits 1.

- **Interaction:** `CompilerSecurityGate` + `LengthUnderflowScanner` on ELF with header-subtraction pattern
  - Happy Path: `LENGTH_UNDERFLOW` finding with correct `sub_const` and `call_label` values.
  - Failure Scenario: Binary has no underflow pattern; assert scanner runs and returns empty list without error.

- **Interaction:** CLI invocation via `_main()` on a known-vulnerable binary
  - Happy Path: Exit code 1, stdout contains finding report.
  - Failure Scenario: Binary path does not exist; after fix, `FileNotFoundError` printed to stderr, exit 2 (distinct from "found findings").

### B.3 End-to-End (E2E) / System Tests

- **Flow Name:** Full CI gate pass: clean binary
  - Steps: (1) Compile a minimal C binary with no taint paths. (2) Run `python -m ablation.analyzers.compiler_security_gate ./clean_binary`. (3) Capture exit code and stdout.
  - Success Criteria: Exit code 0; stdout contains "CLEAN — no findings"; `scan()` called exactly once.
  - Failure/Edge Variant: Provide a binary that fails to open (wrong ELF magic); after fix, exit code is non-zero with a diagnostic message, not 0.

- **Flow Name:** Full CI gate fail: vulnerable binary
  - Steps: (1) Compile a minimal C binary with a `recv`→`system` path. (2) Run `python -m ablation.analyzers.compiler_security_gate ./vuln_binary`. (3) Capture exit code and stdout.
  - Success Criteria: Exit code 1; stdout contains at least one `CRITICAL` GateFinding with a DAG chain; DAG chain includes source and sink nodes.
  - Failure/Edge Variant: Run with `--quiet`; assert stdout is empty and exit code is still 1.

- **Flow Name:** Strict mode: MEDIUM-severity binary
  - Steps: (1) Compile a binary triggering only format string scanner (MEDIUM severity). (2) Run gate with `--strict`. (3) Capture exit code.
  - Success Criteria: Exit code 1 in strict mode; exit code 0 in non-strict mode for the same binary.
  - Failure/Edge Variant: Ensure `scan()` is called exactly once in both modes after the double-scan fix.

- **Flow Name:** API usage with pre-supplied `BinaryContext`
  - Steps: (1) Build `ctx = BinaryContext.load_or_build(path)`. (2) `gate = CompilerSecurityGate.from_context(ctx)`. (3) `findings = gate.scan()`. (4) `gate.check(findings=findings)`.
  - Success Criteria: `BinaryContext.load_or_build()` called exactly once; `scan()` called exactly once; exit code is consistent between `report()` and `check()`.
  - Failure/Edge Variant: Pass a mock context with no `.path` attribute; assert `TypeError` is raised by `from_context()`.

### B.4 Non-Functional Tests

- **Test Type:** Load / stress
  - Target: `scan()` on large stripped ELF binaries (e.g., 20MB–100MB firmware binaries).
  - Load/Condition Description: Run gate on 10 consecutive large binaries without process restart, measuring peak RSS and wall time per scan.
  - Metrics of Interest: Wall time per scan (p50, p99), peak RSS, absence of memory leaks between scans (BinaryContext cache should bound growth).
  - Pass Criteria: Wall time < 10× baseline for 50MB binary; RSS does not grow unboundedly across 10 runs.

- **Test Type:** Timeout / hanging tracker
  - Target: `_run_taint()` with a mock `run_interprocedural()` that blocks for 600s.
  - Load/Condition Description: Mock tracker injected; gate invoked with `ABLATION_GATE_TIMEOUT_SECS=10`.
  - Metrics of Interest: Wall time to gate exit; scan error count in `self._scan_errors`.
  - Pass Criteria: Gate exits in ≤15 seconds; `scan_errors` contains `"SCAN_TIMEOUT"` entry; exit code is 1 (error present).

- **Test Type:** Soak
  - Target: CLI invocation in a Makefile loop: 100 consecutive builds on the same binary.
  - Load/Condition Description: Simulate a fast-iteration build loop invoking the gate on every compile cycle.
  - Metrics of Interest: CPU time per invocation, total wall time for 100 runs, absence of subprocess/fd leaks.
  - Pass Criteria: No fd leaks; 100-run total wall time < 100× single-run baseline (no superlinear accumulation).

### B.5 Tooling Support (Generic)

- **Tool Category:** Static type checker (e.g., mypy)
  - Purpose: Catches untyped `ctx` parameter in `__init__` and `from_context()`; catches `Optional[List[GateFinding]]` return being iterated without None-guard; catches the `_SEV_ORDER.keys()` vs `Set[str]` type difference. Directly surfaces the unguarded `ctx.path` access in `from_context()` (Finding 4-3) and the untyped `raw: Any` duck-typing surface in `_normalize_taint()` (Finding 2-3).

- **Tool Category:** Linter with unused-import detection
  - Purpose: Immediately surfaces the unused `field` import (Finding 6-5); enforces consistent exception handling style (bare `except Exception` patterns flagged by most linters as `broad-exception-caught`).

- **Tool Category:** Coverage tool
  - Purpose: Reveals that all non-x86_64 architecture branches in `_run_taint()` have zero test coverage; shows that `_normalize_taint`'s `except Exception` branch is uncovered, meaning no test currently exercises the normalization-failure path (Finding 2-3, 7-2).

- **Tool Category:** Mutation tester
  - Purpose: Validates that the `gf is not None` guard in `scan()` is exercised by tests; confirms that severity branching in `_taint_severity()` is tested for both CRITICAL and HIGH paths; confirms that `check()`'s strict vs. non-strict branching is exercised.

- **Tool Category:** Profiler / benchmark harness
  - Purpose: Quantifies the double-scan overhead (Finding 5-1) and the XRefGraph rebuild cost (Finding 5-3) on real binaries before and after fixes; provides a performance regression baseline for CI.

---

## C. Implementation Order & Dependencies

### C.1 Suggested Implementation Order

1. **Add file existence validation in `from_path()` and `_main()`.**
   Covers A.1 (existence check), B.1 (unit test for missing path), B.3 (E2E edge variant for missing binary).
   Rationale: Smallest change; eliminates the most dangerous silent false-negative in CI immediately; all subsequent tests become meaningful only if the gate can reliably error on bad input.

2. **Replace all bare exception swallowing with `self._scan_errors` accumulation; expose in `report()` and `check()`.**
   Covers A.2 (error accumulation), A.5 (scan_errors property), B.1 (unit test for scanner ImportError), B.2 (scanner failure integration test).
   Rationale: Without this, test results in steps 3–N are ambiguous; a scanner crash is indistinguishable from "no findings."

3. **Fix double-scan: add `findings` parameter to `check()`; update `_main()` to pass pre-computed findings.**
   Covers A.1 (double-scan fix), B.1 (unit: check() not calling scan() when findings supplied), B.3 (E2E: scan() called once).
   Rationale: Low-effort correctness fix that also enables accurate mocking in all subsequent tests; a test that patches `scan()` will now work correctly.

4. **Add BinaryContext failure sentinel in `_ctx_or_build()` and harden `_arch()` against silent x86_64 fallback.**
   Covers A.3 (sentinel), A.1 (arch hardening), B.1 (unit: arch fallback behavior, ctx_or_build retry prevention).
   Rationale: Must precede integration tests for non-x86_64 arches; tests can only confirm correct arch dispatch once the failure path is surfaced rather than silently defaulted.

5. **Add normalization-drop accounting in `_normalize_taint()` and fix `sink_name == "?"` to CRITICAL-candidate.**
   Covers A.1 (normalization accounting, sink severity fix), B.1 (unit: normalize with missing attrs, severity for "?"), B.2 (integration: tracker with wrong schema).
   Rationale: After steps 1–4, finding counts are now visible; this step makes quality of normalization visible and testable.

6. **Deduplicate `tainted_regs` in `_taint_dag()`; guard `GateFinding.fmt()` against `ValueError`.**
   Covers A.1 (reg deduplication), A.2 (fmt ValueError guard), B.1 (unit: duplicate regs, cyclic dag).
   Rationale: Correctness fixes to the DAG builder; must be done before non-functional tests exercise the DAG rendering path at scale.

7. **Refactor `_run_taint()` if-chain into dispatch dict with per-arch private functions.**
   Covers A.5 (dispatch dict), B.1 (unit: each arch branch in isolation via mock), B.2 (integration: ARM64 dispatch).
   Rationale: Once the error-accumulation framework (step 2) and arch-detection hardening (step 4) are in place, the refactor can use those mechanisms cleanly in each per-arch function.

8. **Implement result caching in `scan()` and BinaryContext-based XRefGraph reuse for x86_64.**
   Covers A.3 (caching), A.4 (xref reuse), B.1 (unit: scan() called once with caching), B.4 (load/soak test baseline).
   Rationale: Performance work is only meaningful after correctness is established; soak tests in step 10 use the cached path.

9. **Add configurable timeout for `run_interprocedural()` calls.**
   Covers A.3 (timeout), B.4 (timeout non-functional test).
   Rationale: Requires a stable dispatch architecture (step 7) before wrapping individual tracker calls in futures.

10. **Add `--verbose` CLI flag; add post-scan deduplication; fix `report()` newlines; remove unused `field` import.**
    Covers A.5 (verbose, dedup, report formatting, unused import), B.1 (unit: report no double newlines), B.3 (E2E: verbose flag output).
    Rationale: Polish and operability improvements; all correctness-critical work is done.

### C.2 Key Dependencies / Pre-Conditions

- **Step 2 (error accumulation) must precede steps 3–10**: Without `self._scan_errors`, tests in later steps cannot distinguish "scanner ran cleanly" from "scanner crashed silently."
- **Step 4 (arch hardening) must precede step 7 (dispatch dict refactor)**: The per-arch private functions in the dispatch dict need to use the error accumulation and arch-detection mechanisms established in steps 2 and 4.
- **Step 7 (dispatch dict) must precede step 9 (timeouts)**: Wrapping individual arch tracker calls in `concurrent.futures` timeouts is much cleaner when each arch has its own private function rather than being an inline branch.
- **Step 3 (double-scan fix) must precede any performance benchmarking in B.4**: Soak test baselines measured before the fix count double scans; baselines taken after reflect true single-scan cost.
- Steps 1, 5, 6, 8, and 10 have no strict technical dependencies on each other beyond completing step 2 first; they can be parallelized as resources allow.

---

## D. Minimal "Safe-to-Run" Gate

### D.1 Critical DEV Changes Required Before Running

- **Validate binary file existence in `from_path()` before constructing the gate.**
  The gate currently returns exit 0 (CLEAN) for non-existent binaries. Until this is fixed, the gate cannot be trusted in any CI context. Source: Section 2 – Finding 2-1, Section 3 – Finding 3-2.

- **Replace silent `except Exception: pass / return []` in all scanner runners with at minimum a stderr warning.**
  Until this change is in place, any scanner crash is invisible; the gate certifies binaries as clean when analysis was never performed. Source: Section 3 – Finding 3-1.

- **Fix double-scan in CLI (`check()` must accept pre-computed findings).**
  In a CI environment with determinism requirements, running the same analysis twice introduces risk of inconsistency between the displayed report and the actual exit code if any scanner output is non-deterministic. Source: Section 2 – Finding 2-7.

### D.2 Critical Tests That Must Exist and Pass

- **Unit / Target: `from_path()` on non-existent path**
  Validates that the gate raises `FileNotFoundError` rather than returning CLEAN. Reason: prevents the silent false-negative on missing build artifact (Section 3 – Finding 3-2).

- **Unit / Target: `_normalize_taint()` drop accounting**
  Passes a raw finding missing canonical attributes; asserts a warning is emitted and the drop is counted in `self._scan_errors`. Reason: validates that normalization failures are not invisible (Section 7 – Finding 7-2).

- **Integration / Target: Scanner `ImportError` handling**
  Patches one scanner's import to raise `ImportError`; asserts `report()` contains a SCAN ERROR section and `check()` returns 1. Reason: confirms silent-failure mode is eliminated (Section 3 – Finding 3-1).

- **Integration / Target: Known-vulnerable x86_64 binary**
  Runs gate on a small ELF with a confirmed `recv`→`system` taint path; asserts at least one `CRITICAL` `GateFinding` is returned and `check()` returns 1. Reason: validates the core gate function works end-to-end.

- **E2E / Target: CLI on non-existent binary path**
  Runs `_main()` with a path that does not exist; asserts exit code is non-zero and stdout/stderr contains a clear diagnostic. Reason: Makefile integration relies on exit codes; this test confirms the CI integration is not silently broken.

---

## E. Ongoing DEV/TEST Guardrails

### E.1 Coding Practices to Maintain

- **Unified `GateFinding` dataclass as the single findings schema**: All scanners produce raw objects that are normalized into `GateFinding` via a single function. This single normalization point is the correct pattern; maintain it as the exclusive path. Do not let individual scanner runners return `GateFinding` objects directly, which would bypass normalization accounting.
  Benefit: Keeps audit trail consistent; makes normalization-drop accounting (A.1) effective.

- **`from_context()` / `from_path()` dual construction pattern**: The dual constructor pattern correctly separates "I have an existing context" from "start fresh." Preserve this distinction; do not collapse them into a single constructor that accepts `Union[str, BinaryContext]`.
  Benefit: Allows callers to avoid redundant BinaryContext builds without coupling the gate to a specific context type.

- **Severity constants centralized in `_SEV_ORDER` and `_CRITICAL_SINKS`**: All severity logic is defined at module level as immutable `frozenset` / `dict`. Preserve this; do not hardcode severity strings inside individual scanner runners.
  Benefit: A single place to update when new critical sinks are identified (e.g., vendor sinks from `VendorProfile`).

### E.2 Regression Risks to Watch

- **Any new arch taint tracker added to `_run_taint()`**: The new branch must be tested with an actual binary for that arch, not just import-tested. The risk pattern is "tracker is imported and runs but returns objects with different attribute names"; `_normalize_taint` silently drops them. Mitigation: For every new arch, add a `_normalize_taint(real_finding_from_that_arch)` unit test using a fixture captured from the tracker's own test suite.

- **Changes to `_normalize_taint` attribute fallback chain**: The `getattr(raw, "sink_va", getattr(raw, "site_va", 0))` pattern is fragile. Any change to the fallback attribute names (e.g., adding `"call_va"` as a third fallback) must be accompanied by a unit test for every combination. Mitigation: Require a test for each `getattr` fallback pair before merging.

- **Changes to `_taint_dag()` that introduce back-edges**: Any modification to the DAG builder that adds an edge where `consumer_id` equals a previously-defined `producer_id` (e.g., to represent recursive taint paths) will trigger `ValueError` in `dag_nodes()`. Mitigation: Add a cycle-detection assertion in `_taint_dag()` as a development-time invariant check.

- **Changes to `check()` that re-introduce unconditional `self.scan()` call**: After the double-scan fix, future refactors that restructure `check()` may inadvertently remove the `findings=None` parameter and reintroduce the double-scan. Mitigation: The unit test "check() does not call scan() when findings are provided" should be part of the permanent test suite.

- **Scanner runner bare `except Exception` re-introduction**: After replacing silent swallowing with error accumulation, code review must enforce that no new scanner runner uses `except Exception: return []`. Mitigation: Add a linter rule / pre-commit hook flagging bare `except Exception` in this file.

### E.3 Automation Hooks

- **Run unit tests for `compiler_security_gate.py` on every commit that touches any file in `ablation/analyzers/`.**
  Trigger: pre-push or PR CI check.
  Risk addressed: Regressions in normalization, severity classification, DAG construction, or CLI behavior from unrelated analyzer changes.

- **Run integration test "gate on known-vulnerable binary exits 1" before merging any change to `compiler_security_gate.py` or any taint tracker.**
  Trigger: PR CI check, scoped to changes in `compiler_security_gate.py`, `taint_tracker_*.py`.
  Risk addressed: Silent taint tracker API changes that break `_normalize_taint`'s duck-typing (Section 7 – Finding 7-2).

- **Lint for bare `except Exception: pass` and `except Exception: return []` patterns in this file.**
  Trigger: pre-commit hook or per-commit CI lint step.
  Risk addressed: Re-introduction of silent scanner failure mode (Section 3 – Finding 3-1).

- **Run static type checking (mypy) on `compiler_security_gate.py` after each change.**
  Trigger: pre-commit or PR CI.
  Risk addressed: Untyped `ctx=` parameters, unguarded `Optional` returns, and `Any`-typed duck-typing surfaces that static analysis can catch before runtime.

- **Run the soak test (100-binary loop) nightly on the CI build machine, not on every commit.**
  Trigger: Nightly scheduled job.
  Risk addressed: Gradual fd leaks or cache unbounded growth (Section 5 – Findings 5-2, 5-3) that are invisible on single-run tests.

---

FORGE_JSON: [{"severity": "HIGH", "category": "functional_correctness", "title": "from_path() accepts non-existent binary path without validation", "location": "CompilerSecurityGate.from_path() line 256; _main() line 431", "description": "No file existence check before constructing the gate. All scanners fail silently with exceptions swallowed. scan() returns 0 findings and check() returns exit 0 (CLEAN). Confirmed by live test: CompilerSecurityGate.from_path('/nonexistent').check() == 0.", "recommendation": "Add os.path.isfile(path) and os.access(path, os.R_OK) validation in from_path() and _main(); raise FileNotFoundError immediately on failure.", "cwe": "CWE-20"}, {"severity": "HIGH", "category": "functional_correctness", "title": "_arch() silently defaults to x86_64 when BinaryContext build fails", "location": "_arch() lines 275-279; _ctx_or_build() lines 265-273", "description": "If BinaryContext.load_or_build() raises for any reason, _ctx_or_build() returns None and _arch() returns 'x86_64'. For ARM64/MIPS/RISC-V cross-compilation CI workflows, the wrong taint tracker runs and finds nothing; gate exits 0.", "recommendation": "When ctx is None after build attempt, raise RuntimeError('Cannot determine arch; BinaryContext failed') or require an explicit arch= parameter. Do not silently default.", "cwe": "CWE-20"}, {"severity": "HIGH", "category": "functional_correctness", "title": "All scanner runners swallow Exception silently, making gate report CLEAN on total analysis failure", "location": "_run_taint() lines 196-198; _run_format_string() lines 303-304; _run_heap() lines 324-325; _run_length_underflow() lines 348-349", "description": "Every scanner runner wraps its entire body in except Exception: pass/return []. ImportError, runtime crashes, and OSError all produce [] findings. Gate exits 0 (CLEAN) when all scanners have failed. A broken Ablation install passes every binary.", "recommendation": "Replace bare exception swallowing with self._scan_errors accumulation. Emit a stderr warning per failed scanner. In check(), return exit code 1 when any scan error is present.", "cwe": "CWE-390"}, {"severity": "HIGH", "category": "functional_correctness", "title": "_normalize_taint silently drops malformed taint findings with no diagnostic", "location": "_normalize_taint() lines 213-235; scan() lines 364-367", "description": "The entire normalization body is wrapped in except Exception: return None. Any taint tracker with different attribute names (e.g., call_va instead of sink_va) produces zero GateFinding objects. The gate cannot distinguish dropped-findings from no-findings.", "recommendation": "Count raw vs. normalized findings. Emit a warning and add a NORMALIZATION_WARNINGS entry in report() when any raw finding is dropped. Return exit code 1 if findings are dropped.", "cwe": "CWE-390"}, {"severity": "MEDIUM", "category": "functional_correctness", "title": "check() calls scan() unconditionally, causing double analysis in CLI path", "location": "check() line 406; _main() lines 432-435", "description": "gate.scan() is called at line 432 for reporting, then gate.check() calls self.scan() again at line 406. Confirmed by live test: scan() invoked exactly 2x per CLI run. If any scanner is non-deterministic, the report and exit code may reflect different analysis runs.", "recommendation": "Change check(self, strict=False) to check(self, findings=None, strict=False). If findings is None, call self.scan(). Update _main() to pass pre-computed findings.", "cwe": "CWE-1041"}, {"severity": "MEDIUM", "category": "functional_correctness", "title": "sink_name defaulting to '?' always produces HIGH severity, silently downgrading CRITICAL sinks", "location": "_normalize_taint() line 216; _taint_severity() lines 201-204", "description": "When neither sink_name nor sink attribute is present on a raw finding, sink defaults to '?'. '?' is not in _CRITICAL_SINKS, so _taint_severity returns 'HIGH'. A tracker exposing the sink as 'target_name' instead of 'sink_name' would have system/execve findings misclassified as HIGH not CRITICAL.", "recommendation": "Treat sink_name == '?' as CRITICAL-candidate: assign severity CRITICAL with a note 'sink name unresolvable — conservatively escalated' and log a warning.", "cwe": "CWE-693"}, {"severity": "MEDIUM", "category": "functional_correctness", "title": "DAG node ID collision on duplicate register names in _taint_dag()", "location": "_taint_dag() lines 118-130", "description": "nid = f'carry_{reg}' is built from the register name. If tainted_regs contains duplicates (e.g., ['rdi', 'rdi']), two add_op() calls use the same node_id. dag_nodes() builds by_id as a dict, so the second op silently overwrites the first, corrupting the taint chain display.", "recommendation": "Deduplicate tainted_regs before the loop: tainted_regs = list(dict.fromkeys(tainted_regs)).", "cwe": "CWE-672"}, {"severity": "MEDIUM", "category": "functional_correctness", "title": "GateFinding.fmt() propagates unguarded ValueError from dag_nodes() on cyclic DAG", "location": "GateFinding.fmt() lines 79-85; SemanticBlock.dag_nodes() encoding_dag.py line 314", "description": "dag_nodes() raises ValueError when a cycle is detected. fmt() calls list(self.taint_dag.dag_nodes()) with no exception guard. This crashes report() via an unhandled exception traceback in _main() rather than producing a structured finding.", "recommendation": "Wrap list(self.taint_dag.dag_nodes()) in try/except ValueError inside fmt(), falling back to list(self.taint_dag.ops) for insertion-order rendering.", "cwe": "CWE-755"}, {"severity": "MEDIUM", "category": "functional_correctness", "title": "No deduplication: same vulnerability site can appear from multiple scanners", "location": "scan() lines 353-376", "description": "A taint path to printf with a non-literal format string produces one TAINT_FLOW finding from TaintTracker and one FORMAT_STRING finding from FormatStringScanner for the same site. No correlation or deduplication logic exists; severity counts in report() are inflated.", "recommendation": "After aggregating findings in scan(), group by (func_va, site_va) and merge entries sharing both addresses into a single GateFinding with combined detector names and highest severity.", "cwe": "CWE-1041"}]
