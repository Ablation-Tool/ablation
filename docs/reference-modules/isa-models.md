# ISA and ABI Models

Per-architecture ISA constant tables and ABI models used internally by instruction parsers, taint trackers, and CFG builders. Four modules: `isa_arc.py`, `isa_arm32.py`, `isa_arm64.py`, `isa_ppc.py`.

---

## Why this exists <sup>[↑](#isa-and-abi-models)</sup>

1. **Every taint tracker and CFG builder needs the same ABI facts.** Register names, argument registers, return registers, stack pointer, frame pointer, and calling convention conventions differ by architecture and by mode within an architecture. Duplicating these tables across 14 arch-specific modules would make them drift. The ISA model files are the single source of truth.

2. **`canon_reg()` is the shared contract.** Across all arch ISA files, the central function is `canon_reg(name) -> canonical_name`. Callers that receive a register from a disassembler in any variant form such as `w5`, `x5`, `r5d`, and `r5` get back the canonical name that the taint tracker uses as its key. Without this contract, each tool would independently parse register aliases and they would diverge.

3. **Mode-aware facts avoid silent wrong behavior.** ARM32 has A32 and Thumb modes; PPC has 32/64 with ELFv1/ELFv2 ABIs; ARC has EM and HS cores. Width-specific facts `bits`, `ptr_bytes`, and `arg_regs` are gated by an explicit `Mode` query so callers cannot accidentally apply 64-bit facts to 32-bit binaries.

---

## Modules <sup>[↑](#isa-and-abi-models)</sup>

| Module | Arch | Modes | ABI |
|:---|:---|:---|:---|
| `isa_arc.py` | Synopsys DesignWare ARC EM / ARC HS | `Mode.EM`, `Mode.HS` | ARC GNU 32-bit |
| `isa_arm32.py` | ARM A32 + Thumb-2 (T32) | `Mode.ARM`, `Mode.THUMB` | AAPCS32 |
| `isa_arm64.py` | AArch64 |: | AAPCS64 |
| `isa_ppc.py` | PowerPC 32-bit + 64-bit | `Mode.PPC32`, `Mode.PPC64` | SysV32, ELFv1, ELFv2 |

---

## Common interface <sup>[↑](#isa-and-abi-models)</sup>

Every ISA module provides at minimum:

```python
canon_reg(name: str) -> Optional[str | Tuple[str, int]]
```

Returns the canonical register name and access width for AArch64. Returns `None` for unknown names. Used by taint trackers to normalize Capstone output.

```python
ARG_REGS: Tuple[str, ...]   # argument registers in calling-convention order
RET_REG: str                # primary return value register
SP: str                     # stack pointer canonical name
```

---

## Usage <sup>[↑](#isa-and-abi-models)</sup>

These modules are not called directly from user code. They are imported by:

- **Taint trackers**: `taint_tracker_arc_labeled.py`, `taint_tracker_arm64.py`, `taint_tracker_x86.py`, etc.
- **Instruction parsers**: `insn_arc.py`, `insn_x86.py`, `insn_arm32.py`, etc.
- **CFG builders**: `cfg_arc.py`, `cfg_builder.py`, etc.
- **Analysis engines**: `analysis_arc.py`, `analysis_x86.py`, `analysis_ppc.py`

```python
# Example: ARC ISA model used by taint tracker
from ablation.analyzers.isa_arc import Mode, canon_reg, ARG_REGS
mode = Mode.HS
print(ARG_REGS)     # ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7')
print(canon_reg("blink"))  # 'r31'

# Example: AArch64 ISA model
from ablation.analyzers.isa_arm64 import canon_reg as arm64_canon
print(arm64_canon("w5"))   # ('x5', 32) — W-form, zero-extends
print(arm64_canon("lr"))   # ('x30', 64)
```

---

## ARM32 `Mode.pc_value()` <sup>[↑](#isa-and-abi-models)</sup>

ARM32 has a non-trivial PC-relative behavior that affects literal pool loads and `adr`:

```
ARM state (A32): PC reads as instruction_address + 8 (ARM ARM A2.3.1)
Thumb state (T32): PC reads as instruction_address + 4; literal loads use Align(PC, 4)
```

`Mode.pc_valueaddress, size, align` encodes this so instruction parsers and taint trackers compute the correct target address without duplicating the ARM ARM rule.

---

## Sources <sup>[↑](#isa-and-abi-models)</sup>

| Module | Primary source |
|:---|:---|
| `isa_arc.py` | ARCv2 ISA Programmer's Reference Manual; ARC GNU/Linux ABI |
| `isa_arm32.py` | ARM Architecture Reference Manual ARMv7-A/R; AAPCS32 |
| `isa_arm64.py` | Arm Architecture Reference Manual A-profile; AAPCS64 |
| `isa_ppc.py` | Power ISA v2.07/v3.0; 32-bit SysV PPC supplement; 64-bit ELFv1/ELFv2 ABI |

---

## See also <sup>[↑](#isa-and-abi-models)</sup>

- [Insn Models](insn-models.md): instruction representation layer that imports these ISA models
- [Analysis Engine](analysis-engine.md): CFG dataflow engine that uses these ABI constants
- [Taint Analysis](taint-analysis.md): taint trackers built on top of these models
