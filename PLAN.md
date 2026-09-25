# RISC-V Python ABI-Model -- Refactor Plan

Ordered: ISA/ABI correctness -> parser robustness -> tests -> readability.  
Each item references the AUDIT.md finding(s) it resolves.

---

## ISA / ABI Correctness

### #1 -- Remove `addiw`, `slliw`, `srliw`, `sraiw`, `lwu` from RV32 `_COPY_MNEMS`
**Category:** isa-correctness  
**Audit:** F1, F2, F15  
**File:** `taint_tracker_riscv32.py`  
**Before:**
```python
'lw', 'lh', 'lb', 'lhu', 'lbu', 'lw', 'lwu',
...
'sll', 'slli', 'srl', 'srli', 'sra', 'srai',
'sll', 'slli', 'sllw', 'slliw',
'srl', 'srli', 'srlw', 'srliw',
'sra', 'srai', 'sraw', 'sraiw',
```
**After:** Remove `addiw`, `slliw`, `srliw`, `sraiw`, `lwu`. Remove duplicate `'lw'`.  
**Spec:** RV32I has no `*w` arithmetic or `lwu` (ISA spec §2 RV32I base).  
**Behavioral impact:** none (capstone never emits these mnemonics on RV32).  
**Risk:** low. Verify by confirming capstone `CS_MODE_RISCV32` never outputs these.

---

### #2 -- Remove `addiw` from RV32 `_exec_insn` immediate-propagate block
**Category:** isa-correctness  
**Audit:** F16  
**File:** `taint_tracker_riscv32.py:418`  
**Before:** `'addiw'` in the `('addi', 'addiw', 'ori', ...)` tuple  
**After:** Remove `'addiw'` from the tuple.  
**Behavioral impact:** none.  
**Risk:** low.

---

### #3 -- Add `'sext.w'` to RV64 `_COPY_MNEMS` as a propagating entry
**Category:** isa-correctness  
**Audit:** F3  
**File:** `taint_tracker_riscv64.py`  
**Rationale:** Capstone 5.0.7 renders `addiw rd, rs, 0` as `'sext.w'`. This is a narrowing copy (sign-extends low 32 bits). For a conservative taint tracker, taint should propagate through `sext.w` (attacker-controlled input remains attacker-controlled after sign extension). Clearing taint silently is an undercount.  
**Before:** `'sext.w'` absent from `_COPY_MNEMS` and `_exec_insn`.  
**After:** Add `'sext.w'` to the `mv`/`c.mv` branch in `_exec_insn` (it has 2 operands `rd, rs`, same as `mv`). Add a comment: `# addiw rd, rs, 0 alias -- narrowing but taint-conservative`.  
**Behavioral impact:** taint propagates through `addiw rd, rs, 0` on RV64 targets (previously dropped).  
**Risk:** medium. Verify by constructing a test case where `addiw a0, a0, 0` appears between a source call and a sink call.

---

### #4 -- Handle `'jr'` as a recognized tail-call instruction
**Category:** isa-correctness  
**Audit:** F11  
**File:** both modules, `_analyze_function`  
**Rationale:** `tail sym` expands to `auipc t1, hi` + `jalr zero, t1, lo`, rendered by capstone as `'jr' 'reg'`. Currently `'jr'` is only recognized as a return-from-function when `op_str == 'ra'`; `'jr' 'a0'` (tail call via a register) falls through to `_exec_insn` and is ignored.  
**Before:** No sink check or caller-saved clear for `jr reg` (non-ra).  
**After:** In `_analyze_function`, add a branch:
```python
elif mnemonic == 'jr' and op_str.strip() != 'ra':
    # Tail call via register -- treat as indirect call: clear caller-saved, stop
    for r in _CALLER_SAVED:
        tainted[r] = False
    break
```
This conservatively treats any `jr non-ra` as a function exit via tail call. It does not attempt sink detection (target is unknown). If PLT resolution via the preceding `auipc` is needed, that is a separate enhancement.  
**Behavioral impact:** tail-call paths now terminate taint analysis cleanly instead of falling through.  
**Risk:** low. Verify with a fixture: call `recv`, then tail-call `system` via `jr`.

---

### #5 -- Remove `c.addi16sp` from `_COPY_MNEMS` (both modules)
**Category:** isa-correctness  
**Audit:** F17  
**Before:** `'c.addi16sp'` in `_COPY_MNEMS`.  
**After:** Remove it. `c.addi16sp` modifies `sp`, which is already guarded in `_exec_insn` (`rd in ('zero', 'x0', 'sp')`), but listing a stack-pointer instruction in a data-copy set is conceptually wrong.  
**Behavioral impact:** none (guard in `_exec_insn` already blocked propagation to `sp`).  
**Risk:** low.

---

## Dead Code / Parser Robustness

### #6 -- Remove dead `if mnemonic == 'andi'` inside RV32 `_exec_insn` immediate block
**Category:** correctness (dead code removal)  
**Audit:** F6  
**File:** `taint_tracker_riscv32.py:422-424`  
**Before:**
```python
if mnemonic in ('addi', 'addiw', 'ori', ...):
    # 'andi' with small immediate can sanitize (zero upper bits)
    if mnemonic == 'andi':          # dead
        tainted[rd] = False
        return
    tainted[rd] = bool(tainted.get(rs1))
    return
```
**After:** Remove the inner `if mnemonic == 'andi'` block and its comment. The outer-level `andi`/`c.and` handler at lines 429-431 is the live path and is correct.  
**Behavioral impact:** none.  
**Risk:** low.

---

## Tests

### #7 -- Add `test_riscv_call_mnem_sets.py`: assert `c.jal` asymmetry
**Category:** test  
**Audit:** F8  
**File:** `tests/test_riscv_call_mnem_sets.py` (new)  
**Content:** Assert `'c.jal' not in RISCV64_CALL_MNEMS` and `'c.jal' in RISCV32_CALL_MNEMS` with spec citation in comment. Prevents future "cleanup" from breaking the correct asymmetry.

---

### #8 -- Add `tests/test_taint_riscv32.py` and `tests/test_taint_riscv64.py`
**Category:** test  
**Audit:** F20  
**Coverage:**
- Source call (`recv`) taints `a0`
- `mv` propagates taint
- `sext.w` propagates taint (RV64, after #3)
- `andi` clears taint
- `li` / `la` clear taint
- Sink call with tainted arg produces a finding
- `jr ra` terminates analysis
- `jr non-ra` terminates analysis (after #4)
- `c.jal` recognized as call (RV32 only)
- `'c.jal'` not triggering on RV64

All expected values derived from capstone output, not hand-typed. Use synthetic byte sequences directly rather than requiring a RISC-V toolchain.

---

## Readability / Documentation

### #9 -- Add docstring to `_COPY_MNEMS` stating the contract
**Category:** readability  
**Audit:** F4, F5  
**Both modules.** Add a block comment above `_COPY_MNEMS` stating: "Mnemonics whose result register (`rd`) receives a copy or arithmetic combination of source registers. Membership means `_exec_insn` may propagate taint from sources to `rd`. Contract: canonical pseudo-instructions and direct data-movement ops only; non-canonical copy idioms (`add rd, rs, zero` etc.) are not listed. Width-specific entries noted inline with ISA spec citation."

---

### #10 -- Add `# RV64-only` / `# RV32-only` comments to all width-specific entries
**Category:** readability  
**Audit:** F1, F15, F8  
**Both modules.** Every mnemonic that exists only on one width gets an inline comment: `# RV64I only`, `# RV32C only`, etc., with the ISA spec section.

---

## Open Questions (ordered by risk)

1. **`sext.w` taint propagation (#3):** Should `addiw rd, rs, 0` propagate taint? The conservative (recommended) answer is yes -- attacker-controlled 32-bit value sign-extended to 64 bits is still attacker-controlled. If a future range-tracking mode is added, narrowing must be modeled precisely.

2. **Tail-call sink detection (#4):** `jr reg` after `auipc reg, hi` could be resolved to a PLT entry by pairing with the preceding `auipc`. This is a two-instruction window that the current single-pass model doesn't support. Recommendation: defer; the current fix (treat as function exit) is safe and conservative.

3. **`jal t0, offset` millicode calls (#13):** Should calls via non-`ra` link registers be recognized? Currently silently skipped. Recommendation: document the "ra-only" contract; add a counter for skipped non-ra jal calls in a debug mode.

4. **Shared base class refactor (#18):** Worth doing but high churn. Recommendation: defer until the test suite (#8) is green; then refactor with tests as the regression harness.
