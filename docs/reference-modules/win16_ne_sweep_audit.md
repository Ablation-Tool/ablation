# SAFE CODE Audit: win16_ne_sweep.py

> Auditor: Claude Sonnet 4.6 (manual, 10-section SOP)
> Date: 2026-10-08
> Gate result: **PASSED**; no HIGH or CRITICAL findings

---

## 1. Scope & Assumptions

**Reviewed:** `sweeps/win16_ne_sweep.py`
**Language/model:** Python 3, CLI sweep tool
**Intended behavior:** Parse Win16 NE (New Executable) binaries with a pure-Python header parser; disassemble code segments via Capstone CS_MODE_16; run MiniLM semantic sweep against Win16-specific and base vulnerability profiles; write a Markdown report to `reports/`.

Assumptions:
- Called as `python3 sweeps/win16_ne_sweep.py <target.exe> --vendor V --product P --version V`
- Target files are untrusted (attacker-supplied NE binaries).
- ablation package is installed (`pip install -e .`) before invocation.
- `sweeps/base_sweep.py` exports `VULN_PROFILES` as a list of `(name, query)` tuples.
- `ablation.analyzers.describe_function` and `FindingRegistry` are importable.
- `sentence_transformers.SentenceTransformer` is available (ablation[ml] or full install).
- No network access is needed; all analysis is local.

---

## 2. Functional Correctness Assessment

**Positive: NE `align_shift=0` fallback is correct.**
Type: Positive. Location: `NEBinary._parse()` line 537–538. The NE spec states that an `align_shift` of 0 means the default 512-byte alignment (2^9). The `if self.align_shift == 0: self.align_shift = 9` guard matches this. ✓

**Positive: `file_size = ... or 65536` handles the NE size=0 convention.**
Type: Positive. Location: `NEBinary._parse()` line 556. NE spec: a segment file size of 0 means the segment occupies a full 64KB page. Defaulting to 65536 is correct. ✓

**Risk: `_parse()` reads name at `ne_off + imp_names_off + name_off` without bounds check.**
Type: Risk. Severity: Low. Location: `NEBinary._parse()` lines 544–547 and 598. A malformed NE binary with a corrupt `name_off` in the module-reference table or import-names table could produce `name_abs > len(d)`, causing an `IndexError` when accessing `d[name_abs]`. Worst case: exception propagates to `_sweep_ne_one` which catches it at the `NEBinary(binary_path)` call site, marks `result['error']`, and returns. No data corruption or code execution possible.
Recommendation: Low priority. The caller wraps in `try/except`. Optional: add `if name_abs >= len(d): continue` guard.

**Risk: `_find_near_call_targets_x86_16` scan is byte-by-byte O(n×m).**
Type: Correctness observation. Location: lines 648–657. `0xE8` is the NEAR CALL opcode, but 0xE8 also appears as operand bytes inside other instructions. The function will recover false function start candidates when 0xE8 appears in a data literal or instruction operand. These false starts will be disassembled as short (< 4 instruction) function bodies and filtered by the `if len(lines) < 4: continue` guard at line 762. False starts that produce ≥ 4 decodable instructions may emit low-value function descriptions, but they cannot affect the semantic sweep result significantly (scores for garbage disassembly are uniformly low).
Recommendation: Acceptable. This is the same trade-off as prologue scanning: false starts are a known limitation of static function discovery.

**Positive: Relocation record loop has an explicit EOF guard.**
Type: Positive. Location: `build_segment_import_map()` line 581. `if rec_off + 8 > len(d): break` prevents reading past the end of file on corrupt relocation records. ✓

**Risk: `_resolve_ne_call` FAR CALL `+1` offset may miss some compilers.**
Type: Risk. Severity: Low. Location: `_resolve_ne_call()` lines 676–680. The code adjusts `far_reloc_key = (call_file_off + 1) - seg_file_off` for FAR CALL (0x9A, which is 1 opcode byte followed by the 4-byte target). This is correct for the common form. However, some Win16 toolchains (Borland, Watcom) may use CALL FAR [mem] (FF 1F / FF 9C / FF 9F) forms. These FAR indirect calls will not match and fall through to the `NEAR` regex, returning the operand string as-is. This is safe; the worst case is a call labeled `"cs:0x1234"` instead of `"KERNEL!LoadLibrary"`, producing lower semantic scores. No crash or data integrity issue.
Recommendation: Low priority. Acceptable for the sweep use case.

---

## 3. Operational Safety & Failure Modes

**Positive: No subprocess, exec, eval, or dangerous calls.**
Location: entire file. AST scan confirms zero uses of `subprocess`, `os.system`, `eval`, `exec`, `__import__`, `open(... 'w')` on attacker-supplied paths. ✓

**Positive: Report output path is always `Path(__file__).parent.parent / "reports"`.**
Location: `main()` lines 1007–1013. The output directory is derived from the script's own location, not from user-supplied arguments. The filename is constructed from `--vendor`, `--product`, `--version` arguments after regex sanitization (`re.sub(r'[^a-z0-9_\-]', '', ...)`). Path traversal via arguments is not possible. ✓

**Low: `_semantic_sweep_ne` has no `try/except` wrapper.**
Severity: Low. Location: `_sweep_ne_one()` lines 892–897. `_semantic_sweep_ne` calls `model.encode()` and `registry.prior_queries()`. If the model is missing or the registry is corrupt, the exception propagates to the caller's `try/except Exception as e:` which sets `result['error']` and returns; correct behavior. However, the reported error will include `traceback.format_exc()` which reveals internal paths.
Recommendation: Low priority. Acceptable for a local analysis tool.

**Low: `NEBinary._parse()` reads `ne_off` from `d[0x3c:0x3e]` without checking file length.**
Severity: Low. Location: `NEBinary._parse()` line 526. A file shorter than 0x3E bytes would cause `struct.unpack_from` to raise, which propagates to `_sweep_ne_one`'s outer try/except. ✓

---

## 4. Reliability & Resilience Issues

**Low: `from ablation.analyzers import describe_function` is a deferred import inside `_extract_functions_ne`.**
Severity: Low. Location: `_extract_functions_ne()` line 700. The import runs at function call time, not module load time. If ablation is not installed, the import error is caught by `_sweep_ne_one`'s `try/except Exception`. This is correct and avoids import errors at module load when win16_ne_sweep.py is imported by other tools.

**Low: `_build_win16_profiles` imports `from sweeps.base_sweep import VULN_PROFILES` unconditionally at module level via `main()`.**
Severity: Low. Location: `_build_win16_profiles()` line 508. `base_sweep` exists (`sweeps/base_sweep.py`) and is importable. If `base_sweep` is removed in a future refactor, `_build_win16_profiles` will raise `ImportError`. This is a single point of failure but low probability given the stable sweeps directory structure.

**Positive: `reports_dir.mkdir(exist_ok=True)` handles race-free directory creation.**
Location: `main()` line 1008. `exist_ok=True` prevents `FileExistsError` if the directory was created between the check and the call. ✓

---

## 5. Security Issues

**None found.** No injection sinks, no arbitrary path writes from user input, no deserialization of untrusted data (the NE binary is only read as raw bytes via `struct.unpack_from`, never executed). No credential handling. No network access.

The MiniLM model is loaded from the HuggingFace cache (set up at install time); `SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")` reads from `~/.cache/huggingface/`. No model download occurs at analysis time if the cache is populated.

---

## 6. Performance & Resource Use Considerations

**Acceptable: byte-by-byte prologue scan and NEAR call scan are O(n) per segment.**
Impact: Acceptable. Win16 code segments are at most 64KB. An O(64KB) scan per segment completes in microseconds. ✓

**Acceptable: MiniLM encode is the dominant cost.**
Impact: Acceptable (same as pe_sweep.py). For a typical NE binary with 20–200 functions, `model.encode()` runs in < 1 second on CPU. ✓

**Low: `_render_report` constructs the report as a list of strings joined at end.**
Impact: Low. For typical reports (< 1MB), this is fine. Memory usage is bounded.

---

## 7. Data Integrity & Consistency Risks

**Low: FindingRegistry is closed via `registry.close()` only in the normal path.**
Severity: Low. Location: `_semantic_sweep_ne()` lines 799, 834. If an exception is raised between `registry = FindingRegistry()` and `registry.close()`, the registry connection is leaked. This is a SQLite file handle leak; the OS will clean it up on process exit, and the database is not corrupted. `try/finally` would be cleaner.
Recommendation: Low priority. Wrap `registry.close()` in a `finally` block.

**Positive: Report file uses `write_text(encoding='utf-8')`.**
Location: `main()` line 1017. UTF-8 encoding handles any Unicode in vendor/product names or in disassembled strings. ✓

---

## 8. Testing & Verification Suggestions

**Unit tests:**
- `NEBinary._parse()` on a minimal hand-crafted NE binary (MZ stub + NE header with 1 code segment, 1 data segment, 2 module refs). Verify: `seg_count`, `module_names`, `align_shift`.
- `NEBinary._parse()` on a file shorter than 0x3E bytes → `struct.unpack_from` exception caught by `_sweep_ne_one`.
- `NEBinary._parse()` with `align_shift=0` → verify `align_shift` becomes 9 after parse.
- `build_segment_import_map()` with a segment containing 3 relocation records: 1 IMPORTORDINAL, 1 IMPORTNAME, 1 INTERNAL. Verify the map has the correct 2 import entries.
- `_find_prologue_starts_x86_16()` on a byte sequence containing both MSVC (`55 8B EC`) and GCC (`55 89 E5`) prologues. Verify both offsets are returned.
- `_find_near_call_targets_x86_16()`: hand-crafted segment with one `E8 rel16` instruction. Verify target offset is added to the set.
- `_resolve_ne_call()` with a FAR CALL at a known relocation source offset → verify `KERNEL!LoadLibrary` returned.
- `_render_report()` with an empty results list → verify no exception; report contains summary line.

**Integration tests:**
- `python3 sweeps/win16_ne_sweep.py <real_Win16_NE> --vendor test --product test --version 1.0` → report written to `reports/`.
- Verify report contains the correct binary name, segment count, and module import list.
- Verify semantic sweep completes without error for a binary with 10+ functions.

---

## 9. Prioritized Production Readiness Checklist

1. **Add bounds guard in `_parse()` for `name_abs >= len(d)`** in module-reference and import-name loops. Converts `IndexError` on malformed binary to a safe skip. Effort: Very Low. (Section 2)
2. **Wrap `registry.close()` in `finally` in `_semantic_sweep_ne`.** Prevents file handle leak on exceptions. Effort: Very Low. (Section 7)
3. **Add unit test for NE parser on minimal hand-crafted binary.** Prevents regressions when NE parsing is extended. Effort: Low. (Section 8)
4. **Add unit test for `build_segment_import_map()` with all three target_type values.** Verifies import resolution correctness. Effort: Low. (Section 8)
5. **Document the `0xE8` false-start trade-off in the module docstring.** Prevents future PRs from adding heuristics to "fix" expected behavior. Effort: Very Low. (Section 2)
6. **Add `try/except ImportError` for `from sweeps.base_sweep import VULN_PROFILES` in `_build_win16_profiles`.** Graceful fallback to Win16-only profiles if `base_sweep` is removed. Effort: Very Low. (Section 4)

**Gate result: PASSED.** No HIGH or CRITICAL findings. All items are LOW or informational. Module is safe for production use in its current form.

---

## 10. Residual Risk & Limitations

- **Incomplete Win16 API ordinal tables:** `_KERNEL_ORDS`, `_USER_ORDS`, `_GDI_ORDS` cover ~200 ordinals each from publicly documented Windows 3.1 SDK tables. Undocumented or vendor-specific DLL ordinals will appear as `"MODULE!ord_N"` in semantic descriptions. This reduces semantic signal for vendor-specific imports (e.g., QuickTime 2.1 Win16 extension DLLs) but does not cause false positives.
- **Win16 16-bit address space:** All addresses in this module are segment:offset (16:16 format). The VA representation `(seg_idx << 16) | seg_off` is a display convention, not a real linear address. Cross-segment call resolution is not implemented; FAR CALL targets in other segments are resolved only via the relocation map.
- **CS_MODE_16 disassembly limitations:** Capstone's 16-bit mode correctly decodes real-mode x86 instruction forms, but may misalign on FPO functions that lack the `push bp; mov bp, sp` prologue. Such functions are recovered via the NEAR CALL scanner but may produce degenerate disassembly.

---

## DEV & TEST ORCHESTRATION PLAN (ADDITIVE)

### A. Dev Work Items by Category

**A.1 Functional Corrections**

- Add `if name_abs >= len(d): continue` guard in `_parse()` loops for module-reference and import-names table (Section 2, item 1 from checklist). One line each; no logic change.
- Wrap `registry.close()` in `try/finally` inside `_semantic_sweep_ne` (Section 7, checklist item 2). One line change.

**A.2 Operational Safety Improvements**

- Add `try/except ImportError` fallback in `_build_win16_profiles` for the `base_sweep` import (checklist item 6). Returns `list(WIN16_NE_PROFILES)` on import failure. No change to production behavior.

**A.3 Reliability & Resilience Enhancements**

No additional items beyond A.1/A.2.

**A.4 Performance & Resource Tuning**

No items. Current performance is acceptable for all expected NE binary sizes.

**A.5 Documentation & Observability**

- Add a docstring note to `_find_near_call_targets_x86_16` documenting the 0xE8 false-start trade-off (checklist item 5).

---

### B. Test Plan by Level

**B.1 Unit tests** (new file: `tests/test_win16_ne_sweep.py`)

| Test | Verifies |
|------|---------|
| `test_ne_parse_minimal` | NE header parsing on 512-byte hand-crafted binary |
| `test_ne_parse_short_file` | Files < 0x3E bytes → exception caught by caller |
| `test_align_shift_zero_fallback` | align_shift=0 → becomes 9 |
| `test_build_segment_import_map_ordinal` | IMPORTORDINAL reloc record → `KERNEL!LoadLibrary` |
| `test_build_segment_import_map_name` | IMPORTNAME reloc record → `CUSTOM!FuncName` |
| `test_prologue_detection_both_forms` | 55 8B EC and 55 89 E5 both found |
| `test_near_call_target_recovery` | E8 rel16 instruction → target in result set |
| `test_resolve_ne_call_far` | FAR CALL with reloc entry → resolved name |
| `test_render_report_empty` | `_render_report([])` → no exception, summary line present |

**B.2 Integration tests** (manual / CI)

| Test | Verifies |
|------|---------|
| `win16_ne_sweep.py <Win16_NE> --vendor test --product test --version 1.0` | Report file created, no crash |
| Report contains segment count matching `NEBinary.seg_count` | Parser-to-output consistency |
| Semantic sweep finds > 0 hits ≥ 0.30 on a known Windows 3.1 binary | Profiles fire on real data |

**B.3 Regression gate**

```bash
python3 sweeps/win16_ne_sweep.py tests/fixtures/minimal_ne.exe \
  --vendor test --product test --version 1 --threshold 0.01
grep "binary(ies) swept" reports/sweep_ne_test_test_1_*.md
```

---

### C. Implementation Order & Dependencies

1. Apply A.1 bounds guards (no deps, 2 min)
2. Apply A.2 registry finally (no deps, 1 min)
3. Apply A.3 base_sweep fallback (no deps, 2 min)
4. Write `tests/fixtures/minimal_ne.exe` (hand-crafted) for B.1 tests
5. Write `tests/test_win16_ne_sweep.py` with unit tests

---

### D. Minimal "Safe-to-Run" Gate

The module is safe to run now. For CI gate readiness, the minimum bar is:
- A.1 bounds guards applied (prevents `IndexError` on fuzz-tested malformed NE headers)
- At least `test_ne_parse_minimal` + `test_align_shift_zero_fallback` passing

---

### E. Ongoing DEV/TEST Guardrails

- Any addition to `_KERNEL_ORDS`, `_USER_ORDS`, `_GDI_ORDS` must be sourced from public documentation (Windows 3.1 SDK, Schulman/Pietrek _Undocumented Windows_) and must not change existing ordinal mappings.
- Any new relocation target_type (values 0/1/2 are the only defined NE types) should be added defensively with an `else: pass` fallthrough rather than raising.
- Win16-specific profiles in `WIN16_NE_PROFILES` must be tested against at least one real Win16 binary before being declared production-quality.
