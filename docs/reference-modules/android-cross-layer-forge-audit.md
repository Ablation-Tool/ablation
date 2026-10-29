# Android Cross-Layer FORGE Audit

**Date:** 2026-10-29
**Mode:** Inline SAFE CODE production review with `FORGE.record_result()`
**Final gate:** PASS for all eleven touched Python files; zero unresolved findings

## 1. Scope & Assumptions

Reviewed the Android implementation and integration changes in:

- `ablation/core/android_package.py`
- `ablation/core/apk_parser.py`
- `ablation/analyzers/dex_decompiler.py`
- `ablation/analyzers/dex_disasm.py`
- `ablation/analyzers/dex_lifter.py`
- `ablation/analyzers/elf_disassembler.py`
- `ablation/analyzers/apk_jni_mapper.py`
- `ablation/analyzers/cross_layer_taint.py`
- `ablation/analyzers/__init__.py`
- `ablation/cli.py`
- `tests/test_android_re_tools.py`

The code is a local CLI/library static-analysis workflow for potentially untrusted APK/XAPK, DEX, AXML, and ELF inputs. It does not execute target applications or contact target services.

- Assumption: callers require deterministic local analysis and explicit errors for unsupported inputs.
- Assumption: the existing Capstone and pyelftools dependencies declared by the project are available.
- Assumption: analytical paths are review evidence, not proof of exploitability.
- Unknown: runtime Android behavior, all vendor-specific API wrappers, and indirect native dispatch targets.

## 2. Functional Correctness Assessment

| ID | Type | Finding | Resolution |
|---|---|---|---|
| F-01 | Issue, initially HIGH | DEX method indices are shard-local; combining multi-DEX indices could bind a Java call to the wrong native method. | `APKJNIMapper` now rejects more than one DEX with an explicit error. |
| F-03 | Issue, initially MEDIUM | Repeated `APKJNIMapper.analyze()` calls appended duplicate state. | Analysis now resets all derived state before rebuilding; repeatability regression added. |
| F-04 | Risk, initially MEDIUM | Duplicate canonical `Java_*` candidates selected the first library arbitrarily. | Multiple candidates now produce an ambiguous-registration record and no arbitrary binding. |
| Positive | — | Overload-aware methods, exact native signatures, dynamic-table Thumb addresses, and mapped direct-call targets are preserved. | Synthetic DEX, native ARM/Thumb, and B-Unit integration checks pass. |

## 3. Operational Safety & Failure Modes

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| F-02 | Initially MEDIUM | APK/XAPK members were read into memory without size limits, allowing oversized or compressed members to exhaust memory. | Added a 256 MiB default member limit and a 1 MiB XAPK manifest limit, with caller-configurable APK limits. |
| F-05 | Initially MEDIUM | ULEB128 and AXML string counts could cause excessive parsing work on malformed data. | ULEB128 is bounded to five bytes; AXML string-pool chunk and count bounds are validated. |
| F-06 | Initially LOW | Exceptions during `AndroidPackage.from_path()` initialization could leave the ZIP handle open. | Initialization now closes the handle on every exception path. |

Malformed, oversized, and unsupported inputs now fail explicitly instead of silently producing partial security conclusions.

## 4. Reliability & Resilience Issues

F-02, F-03, F-04, and F-06 also affected reliable behavior. Their fixes provide bounded reads, deterministic repeat analysis, explicit ambiguity, and deterministic resource cleanup. No additional reliability defect remains open based on the visible code. Target-side dynamic behavior is outside this audit.

## 5. Performance & Resource Use Considerations

The DEX fixed point and native recursive analysis remain intentionally bounded by configurable iterations/depth, and native function reads have size caps. Member limits apply per file, not to an entire package or total analysis runtime. These are documented operational limits rather than hidden behavior. The real B-Unit workflow completed and the 16-iteration trace converged without warnings.

## 6. Maintainability & Operability Observations

The workflow is separated into container, DEX, ELF, JNI mapping, and taint layers. CLI commands expose each stage independently and return structured JSON. Precision limits are documented in `android-cross-layer.md` and `reference-anomalies/cross-layer-taint.md`. Capability placement is in README **Multi-Architecture Analysis Matrix**, with cross-links in **VMs & Runtimes** and **Security Research**.

## 7. Data Integrity & Consistency Risks

F-01 was the principal data-integrity risk: a valid-looking but incorrect JNI graph could redirect subsequent taint analysis. Explicit multi-DEX rejection removes that silent failure. F-03 and F-04 could also duplicate or misattribute evidence; both are fixed and covered by tests. JSON remains derived output and does not mutate the target package.

## 8. Testing & Verification Suggestions

Completed checks:

- Synthetic DEX native declaration, decompilation, call-edge, and `InputStream.read → native([B)` taint tests.
- Member-size, overlong-ULEB128, multi-DEX rejection, mapper repeatability, and CLI mapper-scoping regressions.
- Byte-backed ELF disassembly and real ARM/Thumb PLT/direct-call checks.
- B-Unit XAPK inventory, AXML network text, all 25 JNI bindings, and final 16-iteration trace.
- Focused Android, CLI, and release tests: 17 passed. Python compilation and `git diff --check` pass.
- Full project suite: 2,669 passed and 92 skipped; two IBM z/OS golden tests fail in concurrent `ablation/ibm_zos/relocation.py` work (`truncated full RLD entry`). Those files are outside this Android change and were not modified for this audit.

No additional mandatory test remains open from F-01 through F-06. Future changes must retain these regressions and add fixtures for any newly supported format or dispatch mode.

## 9. Exhaustive Production Readiness Checklist

- [x] **F-01:** Reject shard-local multi-DEX indices rather than misattributing JNI methods. Effort: Medium.
- [x] **F-02:** Enforce APK/XAPK member and outer-manifest size limits. Effort: Low.
- [x] **F-03:** Reset mapper state on every analysis and test repeatability. Effort: Low.
- [x] **F-04:** Report duplicate canonical exports as ambiguous. Effort: Low.
- [x] **F-05:** Bound ULEB128 and validate AXML string-pool counts/chunks. Effort: Low.
- [x] **F-06:** Close package initialization handles on exceptions. Effort: Low.

**Open items: zero.**

## 10. Residual Risk & Limitations

This assessment covers the visible implementation and test evidence, not every possible malformed artifact or Android runtime behavior. Multi-DEX is explicitly unsupported for JNI mapping/cross-layer analysis. Native indirect calls, complex aliasing, stack-passed arguments, non-ARM native taint, and obfuscated/custom DEX APIs can cause false negatives. DEX register propagation and registration-table heuristics can create candidates requiring manual verification. Java-like output is not recompilable source. These limitations are documented rather than treated as proof of safety.

## DEV & TEST ORCHESTRATION PLAN (ADDITIVE)

### A. Dev Work Items by Category

**A.1 Functional Corrections**

- [x] Reject multi-DEX input and report duplicate canonical JNI candidates. Source: F-01/F-04.
- [x] Reset mapper state before rebuilding. Source: F-03.

**A.2 Operational Safety Improvements**

- [x] Add member/manifest limits and AXML/ULEB128 bounds. Source: F-02/F-05.
- [x] Close initialization handles on exceptions. Source: F-06.

**A.3 Reliability & Resilience Enhancements**

- [x] Make unsupported and ambiguous inputs explicit in errors/output. Source: F-01/F-02/F-04/F-06.

**A.4 Performance & Resource Tuning**

- [x] Bound member reads and retain configurable taint/native traversal limits. Source: F-02/F-05.

**A.5 Maintainability & Operability Refactors**

- [x] Publish capability, anomaly, validation, and CLI documentation in the capability indexes. Source: all findings.

### B. Test Plan by Level

**B.1 Unit Tests**

- [x] Oversized member and overlong ULEB128 inputs raise explicit errors.
- [x] Multi-DEX is rejected and repeated mapper calls do not duplicate results.
- [x] Synthetic source-to-native propagation remains intact.

**B.2 Integration Tests**

- [x] XAPK base/split parsing, binary XML text, JNI bindings, and CLI JSON exports work on the real B-Unit package.

**B.3 End-to-End (E2E) / System Tests**

- [x] Inventory → decompile → JNI graph → converged cross-layer trace completes through the public CLI.

**B.4 Non-Functional Tests**

- [x] Member-limit and bounded-traversal behavior is exercised; full-project regression suite completes.

**B.5 Tooling Support (Generic)**

- [x] Python compilation, pytest, FORGE inline review, and whitespace validation run on the changed files.

### C. Implementation Order & Dependencies

**C.1 Suggested Implementation Order**

1. [x] Correct attribution and state handling, then add unit regressions. Covers A.1/B.1.
2. [x] Add resource bounds and cleanup, then malformed-input tests. Covers A.2/A.3/A.4/B.1/B.4.
3. [x] Re-run real target integration and converged trace. Covers B.2/B.3.
4. [x] Publish capability and anomaly documentation after behavior stabilizes. Covers A.5.

**C.2 Key Dependencies / Pre-Conditions**

Correct multi-DEX behavior was required before trusting JNI or taint integration results. Documentation was finalized after those semantics and tests were stable.

### D. Minimal “Safe-to-Run” Gate

**D.1 Critical DEV Changes Required Before Running**

- [x] F-01 through F-06 are all implemented. No unresolved critical change remains.

**D.2 Critical Tests That Must Exist and Pass**

- [x] Multi-DEX rejection, repeatability, member limits, synthetic cross-layer flow, and B-Unit integration pass.

### E. Ongoing DEV/TEST Guardrails

**E.1 Coding Practices to Maintain**

- Keep format-specific indices scoped to their shard/format.
- Preserve explicit ambiguity, bounded reads, and deterministic cleanup.
- Keep structural, analytical, confirmed, and runtime evidence labels separate.

**E.2 Regression Risks to Watch**

- Adding multi-DEX support requires composite method identities, not removal of the guard.
- New native call types must state Thumb/direct/indirect coverage and argument limitations.
- New archive readers must inherit member limits rather than calling unbounded ZIP reads.

**E.3 Automation Hooks**

- Run `tests/test_android_re_tools.py` for every Android change.
- Run B-Unit integration and a converged trace before changing JNI/taint semantics.
- Re-run FORGE after every Python source change; content hashes invalidate stale cached results.

### F. Detection Stage Risk Analysis

| Finding | Stage | Cost | Reason |
|---|---|---|---|
| F-01 multi-DEX JNI misattribution | TEST | $$ | Requires a multi-DEX fixture with colliding indices; ordinary single-DEX smoke tests do not expose it. |

**F.2 Highest-Cost Exposure**

F-01 was the only HIGH finding and the highest-cost exposure. Without the audit, detecting it in production would require an analyst to notice an implausible native binding and compare shard-local method tables manually. The new regression rejects the condition before any graph or taint result is emitted.

## Final FORGE cache results

| File | Gate | Findings |
|---|---|---|
| `ablation/core/android_package.py` | PASS | 0 |
| `ablation/core/apk_parser.py` | PASS | 0 |
| `ablation/analyzers/dex_decompiler.py` | PASS | 0 |
| `ablation/analyzers/dex_disasm.py` | PASS | 0 |
| `ablation/analyzers/dex_lifter.py` | PASS | 0 |
| `ablation/analyzers/elf_disassembler.py` | PASS | 0 |
| `ablation/analyzers/apk_jni_mapper.py` | PASS | 0 |
| `ablation/analyzers/cross_layer_taint.py` | PASS | 0 |
| `ablation/analyzers/__init__.py` | PASS | 0 |
| `ablation/cli.py` | PASS | 0 |
| `tests/test_android_re_tools.py` | PASS | 0 |
