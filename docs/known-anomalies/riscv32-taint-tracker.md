# Known Anomalies — RISCV32TaintTracker

**Module:** `ablation/analyzers/taint_tracker_riscv32.py`  
**Tracker version:** v2.57.0  
**Format:** ISO 26262 Part 8 / TASKING qualification kit (see `ABLATION-STANDARDS.md` §2.3)

An anomaly is a condition under which `RISCV32TaintTracker` is known to produce an incorrect
result. Each entry documents the triggering condition, the impact, and the recommended
workaround.

---

## RISCV32-KA-001 — Capstone 5.x required; silent decode failure on older versions

**Description:**  
`RISCV32TaintTracker` requires Capstone with `CS_ARCH_RISCV`. Capstone 4.x does not include
RISC-V support. If the tracker is imported in an environment with Capstone 4.x, the
`Cs(CS_ARCH_RISCV, ...)` call raises `CsError`. The anomaly is listed here because older
environments may suppress this error and return empty findings that are misread as a clean
binary.

**Triggering conditions:**  
- Capstone pinned to 4.x before the RISC-V tracker was added
- CI environments that install the system capstone package

**Impact:** Analysis abort. No findings produced. Hard error, not a silent miss, but
error suppression in batch runners can convert it to a false clean result.

**Workaround:**  
Verify `import capstone; print(capstone.__version__)` returns 5.0+. The pinned version in
`requirements.txt` covers standard installs. The risk is only in non-standard environments.

**Resolved in version:** Mitigated by `requirements.txt` pin.

---

## RISCV32-KA-002 — HiSilicon custom opcodes require ext_decoder; missed without it

**Description:**  
HiSilicon WS63/Hi3863/BS21 RISC-V SoC firmware uses six custom opcode spaces (0x0b, 0x1b,
0x1f, 0x3b, 0x5b, 0x7b) plus two 16-bit extensions (`uxtb`/`uxth`). Without
`HiSiliconRV32ExtDecoder` passed as `ext_decoder`, those instructions fall through to
Capstone, which returns empty decode results for custom opcodes. Taint stops propagating
at the first unrecognised HiSilicon instruction.

**Triggering conditions:**  
- WS63/Hi3863/BS21 firmware analysed without `ext_decoder=HiSiliconRV32ExtDecoder`
- Any HiSilicon riscv31 binary

**Impact:** False negative. The first custom instruction breaks the taint chain. All
findings that require propagation through custom opcodes are missed.

**Workaround:**  
Always pass `ext_decoder=HiSiliconRV32ExtDecoder` for HiSilicon RISC-V targets:

```python
from ablation.analyzers.hisi_rv32_ext import HiSiliconRV32ExtDecoder
tracker = RISCV32TaintTracker.from_path(elf, ext_decoder=HiSiliconRV32ExtDecoder)
```

Use `HiSiliconRV32ExtDecoder.scan_all_custom(code, base_va)` to confirm a binary has
HiSilicon custom opcodes before running.

**Resolved in version:** Mitigated by `ext_decoder` parameter.

---

## RISCV32-KA-003 — RVC compressed instructions supported but ldmia/stmia multi-reg not tracked through memory

**Description:**  
HiSilicon `ldmia` (opcode 0x0b) is a multi-register load-from-memory instruction. The
`HiSiliconRV32ExtDecoder` handles `ldmia` by clearing taint on all destination registers
because memory is not tracked at the register level. Data that was tainted in memory and
then reloaded by `ldmia` enters a register as untainted.

**Triggering conditions:**  
- Any HiSilicon firmware where tainted data passes through a `ldmia` instruction
- Network buffer reads followed by multi-register loads

**Impact:** False negative. Taint that passed through memory and is reloaded by `ldmia` is
not propagated.

**Workaround:**  
Identify `ldmia` call sites in candidate functions using
`HiSiliconRV32ExtDecoder.scan_all_custom()`. For each `ldmia` that loads from a potentially
tainted memory region, manually confirm whether the loaded registers are passed to sinks.

**Resolved in version:** Open. Memory taint tracking is a long-term tracker gap.

---

## RISCV32-KA-004 — Indirect JALR calls not followed interprocedurally

**Description:**  
Direct `JAL ra, target` and `c.jal target` calls are resolved interprocedurally. Indirect
calls via `JALR ra, rs1, 0` or `c.jalr rs1` are treated as unknown calls when the target
is not a PLT stub.

**Triggering conditions:**  
- Function pointer dispatch and callback tables in RISC-V 32 firmware

**Impact:** False negative. Taint flowing into an indirect internal callee is lost.

**Workaround:**  
Resolve the callee VA manually and add it as a custom sink, or trace it with
`scan_function()`.

**Resolved in version:** Open

---

## RISCV32-KA-005 — Loop fixpoint not computed; second-iteration taint not propagated

**Description:**  
`RISCV32TaintTracker` performs a linear forward trace without loop fixpoint computation.
Taint accumulated after the second and subsequent loop iterations is not propagated. This is
the same shared limitation as the other Ablation taint trackers.

**Triggering conditions:**  
- Any function containing a loop that processes tainted data

**Impact:** False negative.

**Workaround:**  
Inspect loop bodies manually for functions flagged by `SemanticSearcher` as copy or parse
patterns.

**Resolved in version:** Open. Shared limitation with all Ablation taint trackers.
