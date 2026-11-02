# CERN Toolchain FORGE Audit

Audit model: inline ten-section SAFE CODE review followed by `FORGE.record_result()` and a second `FORGE.audit_module()` cache verification for every changed source file. This document records the completed review; it is not a claim that model-level tools prove deployed hardware behavior.

## 1. Scope & Assumptions

Reviewed Python modules:

- `ablation/analyzers/ecu_c166_decoder.py`
- `ablation/analyzers/c166_cfg.py`
- `ablation/analyzers/c166_execution.py`
- `ablation/analyzers/xilinx_wdb.py`
- `ablation/analyzers/__init__.py`
- `ablation/__init__.py`
- `tests/test_c166_cfg.py`
- `tests/test_c166_execution.py`
- `tests/test_xilinx_wdb.py`
- `analysis/specs-protocol/run_rtl_boundaries.py`
- `analysis/mixed-hdl/run_mixed_bridge.py`
- `analysis/endeavour/run_focused_sim.py`
- `analysis/edms-firmware/analyze_service.py`

Reviewed native sources:

- `analysis/mixed-hdl/ablation_vpi_bridge.c`
- `analysis/mixed-hdl/vhdl_side.vhd`
- `analysis/mixed-hdl/verilog_side.sv`
- `analysis/specs-protocol/rtl_boundary_tb.sv`
- `analysis/endeavour/focused_tb.sv`

Assumptions:

- Original CERN artifacts are read-only evidence; generated analysis outputs are derived material.
- C166 execution is a bounded model, not full-chip or timing-accurate emulation.
- Mixed simulation validates the VPI bridge, not the complete Endeavour OCB host.
- Legacy WDB event records have no trustworthy signal-name mapping.
- No commit or push is implied by this audit.

## 2. Functional Correctness Assessment

Positive findings:

- Seeded C166 CFG follows only reachable direct control flow, preserves unknowns, and separates direct reads, writes, and read-modify-write operations from immediate constants and indirect pointers.
- The interpreter models the semantics required by the real update path: move flags, zero-extension flag preservation, DPP mappings, `ZEROS`, `ONES`, protected spans, and ten-copy loop indices.
- SPECS exercises all 256 counts with 1,280 assertions rather than relying only on a codec or archived 129/130 vectors.
- The mixed bridge uses settled callbacks, per-timestamp immutable files, hierarchical lookup at simulation start, and independent assertions on both sides.
- WDB rejects unsupported layouts, cycles, invalid pointers, malformed records, empty event tables, and incomplete zlib streams.

Corrected findings:

- WDB decompression initially allowed `flush()` to bypass the intended output cap. Both decompression calls are now capped and a regression test proves failure is enforced.
- Focused Endeavour subprocesses initially lacked timeouts. Version, compile, and simulation calls are now bounded at 30, 60, and 120 seconds respectively.
- A1396 checksum behavior was refined dynamically: invalid arming skips the arming store; a valid arm followed by an invalid trigger still reaches `SRST`.
- Stale statements that the WDB was undecoded were corrected throughout the reports.

No open functional HIGH or CRITICAL finding remains.

## 3. Operational Safety & Failure Modes

Controls reviewed and verified:

- Explicit function, instruction, issue, step, call-depth, page, stream, event, payload, file-size, export, subprocess, and simulator-time limits.
- Protected firmware spans reject writes while intended RAM and message-object writes remain possible.
- Unsupported instructions, indirect jumps without a target model, empty modeled returns, invalid DPP pages, and protected-memory writes fail explicitly.
- Mixed runner terminates only child processes it started and uses bounded waits and kill fallback.
- Normal mixed-simulator completion creates `.done`, preventing false timeout errors; a genuinely missing peer creates `.error`.
- WDB and runner file handles close through context management or deterministic temporary-directory cleanup.

No unresolved crash, hang, or uncontrolled side-effect finding remains.

## 4. Reliability & Resilience Issues

- Atomic temporary-file replacement protects WDB JSONL from success-looking partial exports.
- Mixed values use immutable per-timestamp files so a faster simulator cannot erase the value a peer is waiting for.
- C166 recovery preserves issues for indirect flow, ownership conflicts, outside-image targets, and unknown encodings instead of silently presenting complete coverage.
- WDB page-chain cycle detection and bounded continuation stop hostile or malformed loops.
- Tool bundles are copied to executable temporary filesystems and source/package hashes are pinned.

Residual dependency boundaries are documented: local compiler and simulator packages, their versions, and optional system-tool selection must be reviewed when changed.

## 5. Performance & Resource Use Considerations

- C166 memory uses sparse 4 KiB pages and bounded execution traces.
- CFG recovery has independent function, instruction, and issue caps.
- WDB uses memory mapping and streams one event at a time instead of retaining 10.76 million event objects.
- Decompression is limited to 64 MiB per chunk, event payloads to 1 MiB, and JSONL previews to a caller-bounded length.
- Summary structures are capped by stream and payload-shape counts; top-stream output is bounded.
- Full WDB integration remains I/O and zlib CPU intensive and is separated from short synthetic tests.

No unbounded resource-growth finding remains open.

## 6. Maintainability & Operability Observations

Positive patterns:

- Public dataclasses and JSON schemas separate evidence from presentation.
- Package exports provide a small documented API without new third-party runtime dependencies.
- C166 decoder metadata is exposed read-only instead of using private fields.
- Runners preserve logs, source hashes, tool versions, native binaries, and structured findings.
- Per-module references, known anomalies, a CERN workflow, and this audit explain both operation and evidence limits.

The code intentionally leaves full-chip emulation, complete OCB integration, and modern WDB naming as separate tasks rather than hiding them behind broad names.

## 7. Data Integrity & Consistency Risks

Controls verified:

- Original archive, HDL, firmware, and selected-source hashes are checked before analysis or simulation.
- Compatibility source transformations are build-only and behavior-preserving; original files remain unchanged.
- Direct xrefs retain instruction addresses and access classes so flag-producer searches are reproducible.
- A1396 valid-arm/invalid-trigger and invalid-arm cases are separate, preventing the former overbroad checksum conclusion.
- Legacy WDB streams remain unnamed, avoiding false signal/type assignment.
- Evidence JSON distinguishes `complete_within_limit` from successful decoding and from complete simulation success.

No unresolved data-corruption or unsupported-evidence finding remains.

## 8. Testing & Verification Suggestions

Implemented and passing:

- 141 C166 decoder/CFG/execution tests.
- Seven WDB tests, including decompression-bypass, empty-table, and full 10.76-million-event integration.
- 158 focused tests across C166, WDB, SPECS, and release metadata.
- 2,749 full-project tests with 92 skips and 37 subtests.
- SPECS: 256 cases, 1,280 checks, zero checksum errors.
- Endeavour: 23 checks, 14 replies, 352 serial reply bits.
- Mixed HDL: both native assertion streams and a bounded missing-peer test.
- Documentation links and package API import smoke checks.

Further work should retain these tests whenever semantics, supported profiles, simulator versions, or resource limits change. Performance tests should compare resource usage before increasing WDB limits.

## 9. Exhaustive Production Readiness Checklist

All audit recommendations are implemented and verified:

- [x] Bound zlib initial decompression and flush, with a bypass regression test.
- [x] Reject empty event tables.
- [x] Add subprocess timeouts to the focused Endeavour runner.
- [x] Preserve bounded execution and explicit errors for unsupported behavior.
- [x] Keep direct and DPP-indirect memory forms separate.
- [x] Protect exact firmware spans without blocking intended RAM writes.
- [x] Validate CAN field widths, payload type/length, object indices, and checksum behavior.
- [x] Use seeded CFG coverage and explicit indirect-flow limitations.
- [x] Add synthetic, original-artifact, negative, integration, and full-project tests.
- [x] Synchronize mixed-HDL callbacks and timestamps without delta loops.
- [x] Distinguish normal peer completion from a genuine missing peer.
- [x] Preserve atomic evidence output and immutable timestamp exchange.
- [x] Document all remaining limitations and corrected interpretations.
- [x] Record and verify FORGE results for all 18 changed source files.

Open checklist items: **0**.

## 10. Residual Risk & Limitations

This review is based on source, tests, and characterized artifacts; it does not establish hardware equivalence or production deployment safety.

Residual evidence limits:

- Seeded CFG is not whole-image proof and indirect tables require target evidence.
- The C166 instruction subset and memory model are not a complete ISA or reset-state specification.
- `SRST` is a modeled stop, not a hardware reset or bootloader verdict.
- Mixed HDL is scalar and synchronized; it is not the complete OCB host or an arbitrary asynchronous channel.
- Legacy WDB root/storage IDs lack name/type mapping and cannot prove transaction success.
- Original hardware, CAN arbitration, timing closure, electrical behavior, and bootloader authenticity remain outside the validated scope.

These are documented evidence boundaries, not unresolved HIGH or CRITICAL source defects.

# DEV & TEST ORCHESTRATION PLAN (ADDITIVE)

## A. Dev Work Items by Category

### A.1 Functional Corrections

- Implemented direct C166 dispatch/xref recovery and bounded execution with real-image tests.
- Implemented legacy WDB event decoding with no invented name mapping.
- Corrected checksum-arming interpretation and report text.

### A.2 Operational Safety Improvements

- Added zlib output caps, empty-table rejection, subprocess timeouts, protected spans, and simulator completion handling.
- Added fail-closed behavior for unsupported instructions, malformed structures, and limit violations.

### A.3 Reliability & Resilience Enhancements

- Added atomic export, immutable timestamp files, source hashes, page-cycle detection, and deterministic cleanup.
- Added separate valid-arm/invalid-trigger and invalid-arm evidence.

### A.4 Performance & Resource Tuning

- Added sparse memory, bounded traces, streaming WDB events, and bounded summary/export structures.

### A.5 Maintainability & Operability Refactors

- Exposed decoder metadata read-only and added package exports, JSON schemas, workflow documentation, known anomalies, and this audit.

## B. Test Plan by Level

### B.1 Unit Tests

- C166 arithmetic, branches, calls, memory protection, direct xrefs, CAN objects, invalid fields, and limits.
- WDB sections, zlib, cycles, empty events, payload/export limits, and atomic output.

### B.2 Integration Tests

- A1396 dispatcher/arming/trigger and exact handoff.
- Full legacy WDB summary and bounded event export.
- Mixed GHDL/Icarus exchange and missing-peer timeout.

### B.3 End-to-End (E2E) / System Tests

- All 256 SPECS counts and four explicit boundary records.
- C166 decoder/CFG/execution plus full-project pytest.
- Documentation links and package API import smoke checks.

### B.4 Non-Functional Tests

- Full 10.76-million-event WDB decode validates streaming operation and limit handling.
- Full-project suite validates cross-module regression behavior.

### B.5 Tooling Support (Generic)

- Pytest, strict C compiler warnings, GHDL, Icarus, static FORGE source review, inline FORGE module review, and cache verification are used for their respective failure classes.

## C. Implementation Order & Dependencies

1. Established source/container integrity and original-artifact evidence.
2. Implemented bounded decoders and focused tests.
3. Added CFG/execution models and real A1396 paths.
4. Added exhaustive RTL and mixed-HDL verification.
5. Added streaming WDB and large-file integration.
6. Completed documentation, full-project tests, FORGE reviews, and cache verification.

Pre-conditions completed: original sources remained available and hash-pinned; local simulator packages were provisioned before dynamic tests; safety fixes preceded final FORGE cache records.

## D. Minimal “Safe-to-Run” Gate

### D.1 Critical DEV Changes Required Before Running

Completed: bounded zlib flush, bounded subprocesses, explicit memory protection, failure on unsupported behavior, and correct simulator lifecycle.

### D.2 Critical Tests That Must Exist and Pass

Passed: focused regression suites, original A1396 paths, exhaustive SPECS, mixed two-way/timeout, full legacy WDB, full-project pytest, and all FORGE cache checks.

## E. Ongoing DEV/TEST Guardrails

### E.1 Coding Practices to Maintain

- Preserve explicit bounds, read-only originals, fail-closed unknowns, source hashes, and evidence-level language.
- Keep atomic output and deterministic cleanup.

### E.2 Regression Risks to Watch

- New C166 opcodes or DPP behavior must add semantic and real-image tests.
- New WDB profiles must add structural and decompression-limit tests without inventing names.
- New VPI transports must preserve timestamp scheduling and completion semantics.
- Any limit increase must be justified by resource measurements.

### E.3 Automation Hooks

- Run focused tests for every affected module and full-project tests before commit.
- Run SPECS/mixed runners for simulator or HDL changes.
- Run full WDB integration for decoder/profile changes.
- Require `FORGE.audit_module()` cache hits with `gate_passed=True` for every changed source file before `git add`.

## F. Detection Stage Risk Analysis

No HIGH or CRITICAL findings remain open. The pre-audit resource and timeout issues were corrected and covered by tests before cache records were written. There is no residual HIGH/CRITICAL exposure requiring a stage table.
