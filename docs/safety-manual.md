# Ablation Safety Manual

**Version:** 1.0.0 — 2026-10-10  
**Standard:** ISO 26262 Part 8 Clause 11 (TCL3 tool qualification requirement)  
**Scope:** All taint trackers and all scanners that produce CRITICAL findings

This document is the standalone safety manual required by ISO 26262 Part 8 Clause 11 for TCL3-qualified tools. It describes when each qualified module can be trusted, when it cannot, and what the user must do when confidence is insufficient.

For full qualification context see `docs/ABLATION-STANDARDS.md`. For known anomaly detail see `docs/known-anomalies/<module>.md`.

---

## 1. Scope of Qualification

TCL3 applies to modules where a false negative (missed finding) could propagate into a safety case or PSIRT disclosure without detection. The following modules are in TCL3 qualification scope:

| Module | File | Capability |
|---|---|---|
| ARM32TaintTracker | `ablation/analyzers/taint_tracker_arm32.py` | ARM32/Thumb interprocedural taint |
| ARM64TaintTracker | `ablation/analyzers/taint_tracker_arm64.py` | ARM64 interprocedural taint |
| MIPS32TaintTracker | `ablation/analyzers/taint_tracker_mips32.py` | MIPS32 BE/LE interprocedural taint |
| MIPS64TaintTracker | `ablation/analyzers/taint_tracker_mips64.py` | MIPS64 BE/LE interprocedural taint |
| PPC32TaintTracker | `ablation/analyzers/taint_tracker_ppc32.py` | PPC32 interprocedural taint |
| PPC64TaintTracker | `ablation/analyzers/taint_tracker_ppc64.py` | PPC64 interprocedural taint |
| RH850TaintTracker | `ablation/analyzers/taint_tracker_rh850.py` | RH850 GHS/IAR ABI taint |
| TriCoreTaintTracker | `ablation/analyzers/taint_tracker_tricore.py` | TriCore AURIX EABI taint |
| V850TaintTracker | `ablation/analyzers/taint_tracker_v850.py` | V850 interprocedural taint |
| X86TaintTracker | `ablation/analyzers/taint_tracker_x86.py` | x86-64 interprocedural taint |
| X86_32TaintTracker | `ablation/analyzers/taint_tracker_x86_32.py` | x86-32 CDECL interprocedural taint |
| RISCV32TaintTracker | `ablation/analyzers/taint_tracker_riscv32.py` | RISC-V 32 interprocedural taint |
| RISCV64TaintTracker | `ablation/analyzers/taint_tracker_riscv64.py` | RISC-V 64 interprocedural taint |
| LoongArch64TaintTracker | `ablation/analyzers/taint_tracker_loongarch64.py` | LoongArch64 interprocedural taint |
| LA64MaxNotMinScanner | `ablation/analyzers/loongarch64_max_not_min_scanner.py` | GCC max-not-min bug (CRITICAL) |
| WindowsPoolTaintTracker | `ablation/analyzers/windows_pool_taint_tracker.py` | Windows kernel pool taint |

Other Ablation modules (`BinaryContext`, `SemanticSearcher`, utility parsers) are not TCL3 scope and do not require safety manual coverage.

---

## 2. Intended Use

Each taint tracker performs static data-flow analysis on a single binary ELF file or flat ROM image. The tracker identifies instruction sequences where attacker-controlled data from a network source function reaches a dangerous sink function. A finding means the path exists in the static call graph. It does not mean the path is reachable at runtime under all inputs.

Ablation is a security research tool. It accelerates human analysis. A CONFIRMED finding requires human verification of the call trace before disclosure or safety-case use. An ELIMINATED finding is not a guarantee that the path does not exist.

---

## 3. Prerequisites for Reliable Results

The following constraints must be satisfied before a taint tracker result is treated as reliable for a safety case or PSIRT disclosure.

| Constraint | Requirement |
|---|---|
| **Binary format** | ELF with valid section headers, or flat ROM with caller-supplied function boundaries |
| **Architecture** | One of the 16 supported architectures listed in Section 1 above |
| **Endian** | Pass `endian='big'` or `endian='little'` explicitly; do not rely on defaults for cross-endian targets |
| **Stripped binaries** | Use `from_path_full()` for ARM64 and LoongArch64; use `from_path()` only when symbols exist |
| **Known anomalies** | Consult `docs/known-anomalies/<tracker>.md` before treating a zero-findings result as clean |
| **Loop bodies** | Manually inspect loop bodies for copy/fill patterns in functions with high SemanticSearcher match scores |
| **Indirect calls** | Findings for indirect call targets require `VtableResolver` or manual callee resolution |
| **Stack buffers** | If the tracker returns no findings, run `SinkArgClassifier` to check for stack-buffered flows |
| **Byte verification** | Every confirmed finding: verify the VA exists and the bytes match before reporting |

---

## 4. Known False Negative Categories

These categories of false negatives are shared across all trackers. They are documented in the known-anomaly files for each tracker and summarised here for cross-reference.

1. **Loop fixpoint** — taint accumulated on the second and subsequent loop iterations is not propagated (all trackers)
2. **Indirect calls** — callee not entered when the callee address is in a register at the call site (all trackers)
3. **Stack taint** — data routed through a local stack buffer before the sink is not tracked (all trackers except LoongArch64 which uses `mem_taint`)
4. **Vector registers** — NEON (ARM32/ARM64), LSX/LASX (LoongArch64), VFP, SIMD — taint through vector registers is lost
5. **Architecture-specific opcode gaps** — unrecognised opcodes fall to conservative fallback; may miss taint at those instructions

---

## 5. When Not to Use Ablation as the Sole Evidence

Do not cite a taint tracker zero-findings result as sole evidence that a function is safe in the following situations:

- The function contains a loop body whose exit value is used in a subsequent sink call
- The function dispatches to an indirect callee whose address is loaded from a function pointer table
- The binary uses a vector ISA extension (NEON, LSX, LASX, VFP) for data movement
- The tracker's known-anomaly file lists a triggering condition that matches the binary

In these situations, supplement with `SemanticSearcher`, `SinkArgClassifier`, and manual trace using `WindowAnalyzer.dump_text()` before concluding no finding exists.

---

## 6. Tool Qualification Evidence Chain

| Claim | Evidence |
|---|---|
| Register model matches ABI spec | ABI conformance tests in `tests/conformance/`; ABI spec citations in module docs |
| Coverage gate met for qualified modules | `pytest --cov` run on labeled engine modules; see `pyproject.toml [tool.coverage]` |
| No critical security defects in tool code | FORGE audit `gate_passed=True` for all modules; SAFE CODE 10-section residual risk documented |
| Known anomalies tracked | `docs/known-anomalies/` per-module files; per-anomaly regression tests in `tests/conformance/` |
| Byte-verification enforced | Hard rule in `CLAUDE.md`; per-finding byte check documented in session files |

---

## 7. Contact and Maintenance

This safety manual is maintained alongside the Ablation codebase. It is updated when:
- A new taint tracker is added to TCL3 scope
- A new known anomaly category is discovered
- The ABI conformance test suite changes
- A constraint in Section 3 is resolved or a new one is added

**Source document:** `docs/ABLATION-STANDARDS.md` §2.5 (the section this file extracts)  
**Known anomalies:** `docs/known-anomalies/`  
**Qualification plan:** `docs/ABLATION-STANDARDS.md` §10 compliance matrix
