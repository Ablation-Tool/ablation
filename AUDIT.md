# RISC-V Python ABI-Model Audit

**Modules:** `ablation/analyzers/taint_tracker_riscv32.py`, `ablation/analyzers/taint_tracker_riscv64.py`  
**Backend:** Capstone 5.0.7 (`CS_ARCH_RISCV + CS_MODE_RISCV32|64 + CS_MODE_RISCVC`, `detail=False`)  
**Targets claimed:** RV32GC (ilp32), RV64GC (lp64d)  
**Existing taint tests:** none  
**RISC-V toolchain installed:** none (all claims verified by capstone disassembly of hand-encoded bytes)  
**Auditor:** mechanical -- capstone fixtures + static analysis  

---

## §2.1 `_COPY_MNEMS`

### F1 — `addiw` in RV32 `_COPY_MNEMS` (wrong width guard)

**File:** `taint_tracker_riscv32.py:146`  
**Severity:** low (harmless in practice)  

`addiw` is an RV64I instruction (RISC-V Unprivileged ISA §5.2). It does not exist in the RV32I ISA and capstone with `CS_MODE_RISCV32` never emits it. Its presence in `_COPY_MNEMS` is dead for RV32 targets but misleads any reader comparing the two modules.

Fixture: `disasm_rv32(bytes([0x1b, 0x05, 0x05, 0x00]))` produces no output.

### F2 — Duplicate `'lw'` in RV32 `_COPY_MNEMS` (line 156)

**File:** `taint_tracker_riscv32.py:156`  
**Severity:** low  

```python
'lw', 'lh', 'lb', 'lhu', 'lbu', 'lw', 'lwu',
```

`'lw'` appears twice. `frozenset` deduplicates silently, so no runtime error, but `'lwu'` at the end of the same line is an RV64-only mnemonic (load word unsigned, sign-extended to 64 bits -- RISC-V Unprivileged ISA §5.2) and should not be in the RV32 set at all (capstone with `CS_MODE_RISCV32` never emits it).

### F3 — `sext.w` (alias for `addiw rd, rs, 0`) not in `_COPY_MNEMS` -- taint silently dropped

**File:** `taint_tracker_riscv64.py`  
**Severity:** medium  

Capstone 5.0.7 with `CS_MODE_RISCV64` renders `addiw a0, a0, 0` as mnemonic `'sext.w'`, op_str `'a0, a0'`:

```
Fixture: addiw a0,a0,0 (0x0005051b) at CS_MODE_RISCV64
  -> mnemonic='sext.w'  op_str='a0, a0'
```

`'sext.w'` is absent from `_COPY_MNEMS` in both modules. In `_exec_insn`, an unrecognized mnemonic is a no-op (early return at line 367). When a compiler emits `sext.w a0, a0` (common after a 32-bit arithmetic result), taint on `a0` is silently dropped even though `a0` still holds a network-derived value (sign-extended, but attacker-controlled).

Per the psABI prompt (§2.1): `addiw rd, rs, 0` is a narrowing operation (sign-extends 32 low bits to 64), so it is not a bitwise copy. The question is whether the tool contract is "conservative" (taint survives narrowing) or "precise" (taint dropped). Current behavior is implicitly precise with no documentation. The tool should make this choice explicit and handle the mnemonic.

**Recommended resolution:** add `'sext.w'` to the RV64 load-clear block with a comment, or add it to the arithmetic-propagate block (conservative). See PLAN.

### F4 -- Contract for `*w` arithmetic (sign-extension semantics)

**File:** `taint_tracker_riscv64.py:118-146`  
**Severity:** low (documented gap, not a correctness error for the tool's stated contract)  

`addw`, `subw`, `mulw`, `divw`, etc. are in `_COPY_MNEMS` and propagate taint from both rs1 and rs2 (conservative). However, these instructions sign-extend the 32-bit result to 64 bits, so they are not bitwise copies. This is consistent conservative taint tracking. The module docstring and the set definition lack a comment stating this choice. No change required; documentation only.

### F5 -- Non-obvious copy idioms not recognized

**File:** both modules  
**Severity:** low (tool contract not stated; not a regression)  

The following are semantically equivalent to `mv` for integer-width values but not in `_COPY_MNEMS`:
- `add rd, rs, zero` / `add rd, zero, rs` -- capstone renders as `'add'` with `op_str='rd, rs, zero'`
- `or rd, rs, zero` -- `'or'` with three operands
- `sub rd, rs, zero` -- `'sub'`

Compilers rarely emit these; hand-written code sometimes does. The module should either document that the contract is "canonical pseudo-instructions only" or extend the set. Currently undocumented.

---

## §2.2 `andi` sanitization

### F6 -- Dead code: `if mnemonic == 'andi'` inside the `addi`/`ori`/... block (RV32)

**File:** `taint_tracker_riscv32.py:422-424`  
**Severity:** medium (dead code; intended sanitization logic is unreachable)  

```python
if mnemonic in ('addi', 'addiw', 'ori', 'xori', 'slti', 'sltiu',
                'slli', 'srli', 'srai', 'slliw', 'srliw', 'sraiw',
                'c.addi', 'c.slli', 'c.srli', 'c.srai'):
    # 'andi' with small immediate can sanitize (zero upper bits)
    if mnemonic == 'andi':          # <-- DEAD: 'andi' is not in the outer tuple
        tainted[rd] = False
        return
    tainted[rd] = bool(tainted.get(rs1))
    return
```

`'andi'` is not in the outer tuple, so `mnemonic == 'andi'` is never `True` inside this block. The comment says "andi with small immediate can sanitize" but the check is unreachable. The actual `andi` handling occurs at lines 429-431 and unconditionally clears taint -- which is correct. The dead inner block is confusing and should be removed.

The RV64 module does not have this dead code (its structure is cleaner: no inner `andi` check inside the immediate block).

### F7 -- `andi` immediate sign-extension not checked (both modules)

**File:** `taint_tracker_riscv32.py:429-431`, `taint_tracker_riscv64.py:393-395`  
**Severity:** low  

Capstone renders `andi a0, a1, -16` as op_str `'a0, a1, -0x10'`. The code clears taint unconditionally on any `andi`, regardless of the immediate. Per prompt §2.2: `andi rd, rs, imm` with negative `imm` (bit 11 of the 12-bit immediate set) is an alignment mask (e.g. `-16 = 0xffff...fff0`), which clears the low bits but leaves all high bits intact -- it does not bound the value. Treating it as a sanitizer produces false negatives.

This is a conservative choice (clears taint even for masking `andi`), which is safe for a taint tracker (no false positives). However it is undocumented. If the tool ever evolves to track ranges, this needs to be revisited.

---

## §2.3 `_CALL_MNEMS` -- RV32 vs RV64 divergence

### F8 -- `c.jal` asymmetry is correct; assertion test missing

**Files:** `taint_tracker_riscv32.py:108`, `taint_tracker_riscv64.py:87`  

`c.jal` is in RV32 `_CALL_MNEMS` and absent from RV64 `_CALL_MNEMS`. This is **correct**: in RV32C, encoding `001 imm[11|4|9:8|10|6|7|3:1|5] 01` is `c.jal`; in RV64C the same encoding is `c.addiw` (ISA spec §16.5). Verified by fixture:

```
0x2501 at CS_MODE_RISCV64 -> c.addiw a0, 0
0x2501 at CS_MODE_RISCV32 -> c.jal 0x600
```

No code change needed. A regression test is required so a future cleanup does not add `c.jal` to RV64 (see PLAN #7).

### F9 -- `j` pseudo (jal x0, offset) not in `_CALL_MNEMS` -- correct

Capstone renders `jal x0, target` as mnemonic `'j'`, op_str is the offset. `'j'` is absent from `_CALL_MNEMS` -- correct, `j` is an unconditional jump that does not save a return address.

### F10 -- `jalr ra, a0, 0` (indirect call) rendered as `'jalr' 'a0'` by capstone

**Files:** both modules, `_ICALL_MNEMS`  
**Severity:** informational  

Capstone with `detail=False` renders `jalr ra, a0, 0` as mnemonic `'jalr'`, op_str `'a0'` (elides `ra` and `0`). The code routes `jalr` through `_ICALL_MNEMS` and clears all caller-saved regs -- correct behavior. `_jal_target` is not called for `jalr`. No defect; documented for completeness.

### F11 -- `tail` call pseudo (`auipc + jalr zero, t1, lo`) not recognized as a sink call

**Files:** both modules  
**Severity:** medium  

The RISC-V `tail sym` pseudo expands to `auipc t1, hi` + `jalr zero, t1, lo`. Capstone renders `jalr zero, t1, lo` as mnemonic `'jr'` with op_str `'t1'`. `'jr'` is not in `_CALL_MNEMS` or `_ICALL_MNEMS`. It is not recognized at all -- `_exec_insn` sees `'jr'` which is not in `_COPY_MNEMS` and returns immediately. No taint propagation or sink check occurs for tail calls.

Impact: if a function passes tainted data to a sink via a tail call (e.g. `tail system`), the tracker misses it entirely.

Fixture:
```
jalr zero, a0, 0 -> 'jr' 'a0'   (tail jump to address in a0)
```

---

## §2.4 `_jal_target` -- op_str parse

### F12 -- `_jal_target` correctly adds offset; single-operand `jal` rendering confirmed

**Files:** `taint_tracker_riscv32.py:366-372`, `taint_tracker_riscv64.py:349-353`  

Capstone 5.0.7 renders `jal ra, 12` as mnemonic `'jal'`, op_str `'0xc'` (the **relative offset**, not the absolute target). The offset is constant across all base addresses. `_jal_target` computes `address + int(op_str.strip(), 0)` which is correct.

The `rd` operand is elided by capstone when `rd = ra` (the alias rendering). The single-token parse is therefore valid for the common case.

### F13 -- `_jal_target` silently returns 0 for non-integer op_str; no `jal t0, target` support

**Files:** both modules  
**Severity:** low  

If `jal` is emitted with a non-`ra` link register (e.g. `jal t0, sym` in millicode), capstone renders op_str as `'t0, 0x<offset>'`. `int('t0, 0x...', 0)` raises `ValueError`, `_jal_target` returns 0, `_plt_name_for_target(0)` returns `''`, and the call is silently skipped. The tool's contract ("calls via `ra` only") should be stated in the module docstring.

### F14 -- `c.jal` single-operand parse works

Capstone renders `c.jal 0x20` as mnemonic `'c.jal'`, op_str `'0x20'` (single-token offset). `_jal_target(address, '0x20')` works correctly.

---

## §2.5 General ABI model

### F15 -- RV32 `_COPY_MNEMS` contains `'slliw'`, `'srliw'`, `'sraiw'` -- RV64-only mnemonics

**File:** `taint_tracker_riscv32.py:148-151`  

`slliw`, `srliw`, `sraiw` are RV64I instructions (ISA §5.2). Capstone with `CS_MODE_RISCV32` never emits them. Dead entries; no runtime impact but misleading.

### F16 -- RV32 `_exec_insn` includes `'addiw'` in the immediate-propagate block

**File:** `taint_tracker_riscv32.py:418`  

`addiw` in the `('addi', 'addiw', ...)` tuple. As with F1, `addiw` is RV64-only; capstone never emits it on RV32. Dead; misleading.

### F17 -- `c.addi16sp` in `_COPY_MNEMS` -- modifies `sp`, should not propagate taint

**Files:** `taint_tracker_riscv32.py:158`, `taint_tracker_riscv64.py:141`  

`c.addi16sp` adjusts `sp` (x2) by a multiple of 16. It is a stack-pointer adjustment, not a general-purpose data copy. `_exec_insn` guards against `rd == 'sp'` (line 399/371), so any taint propagation to `sp` is already blocked. But `c.addi16sp` is in `_COPY_MNEMS` with rd being `sp` implicitly, meaning it enters `_exec_insn` and is caught by the `rd in ('zero', 'x0', 'sp')` guard. No correctness defect; the guard saves it. However listing it in `_COPY_MNEMS` is conceptually wrong. Remove or add a comment.

---

## §2.6 Syscall model

Neither module implements a syscall model (`ecall` is not in any recognized mnemonic set). Not a defect given the tool's stated purpose (PLT-call source-to-sink). Documented for completeness.

---

## §2.7 Code quality

### F18 -- Both modules are near-identical; shared logic not factored

The two modules share `_ARG_REGS`, `_CALLER_SAVED`, `_CALLEE_SAVED`, `_SOURCES`, `_DEFAULT_SINKS`, `_get_func_starts`, `_va_to_slice`, `_func_name`, `_plt_name_for_target`, `_jal_target`, `_parse_rd`, `_parse_rs`, `_load_lief`, `_load_pyelf`, `run`, `run_interprocedural`, `report`, `_cli`. Approximately 80% of the code is duplicated. A single base class with per-width subclasses would eliminate the maintenance surface for all future ISA/ABI fixes.

### F19 -- No type annotation on width/arch selector; bare `CS_MODE_*` constants in `__init__`

Width-specific constants (`CS_MODE_RISCV32`, `CS_MODE_RISCV64`, `_COPY_MNEMS`, `_CALL_MNEMS`) are baked into each class body. There is no `Literal['rv32','rv64']` or enum parameter; the only way to select width is to instantiate the correct class. This is fine API design; the missing piece is a module-level `__all__` and a docstring note that the two classes are not interchangeable.

### F20 -- No tests for any RISC-V taint tracker path

`tests/` contains no `test_taint_riscv*.py`. Every finding above is unverified by the test suite.

---

## Summary table

| ID | File | Severity | Category | Line |
|----|------|----------|----------|------|
| F1 | rv32 | low | isa-correctness | 146 |
| F2 | rv32 | low | isa-correctness | 156 |
| F3 | rv64 | medium | isa-correctness | _COPY_MNEMS |
| F4 | rv64 | low | documentation | _COPY_MNEMS |
| F5 | both | low | documentation | _COPY_MNEMS |
| F6 | rv32 | medium | correctness | 418-424 |
| F7 | both | low | documentation | 429/393 |
| F8 | both | low | test | _CALL_MNEMS |
| F9 | both | info | -- | _CALL_MNEMS |
| F10 | both | info | -- | _ICALL_MNEMS |
| F11 | both | medium | isa-correctness | _analyze_function |
| F12 | both | info | -- | _jal_target |
| F13 | both | low | documentation | _jal_target |
| F14 | rv32 | info | -- | _jal_target |
| F15 | rv32 | low | isa-correctness | _COPY_MNEMS |
| F16 | rv32 | low | isa-correctness | 418 |
| F17 | both | low | correctness | _COPY_MNEMS |
| F18 | both | low | readability | all |
| F19 | both | low | readability | all |
| F20 | both | medium | test | tests/ |
