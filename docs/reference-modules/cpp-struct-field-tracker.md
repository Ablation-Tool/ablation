# CppStructFieldTracker

Traces `std::string` field propagation between C++ structs in x86-64 stripped PIE ELF binaries via `c_str()` / `assign()` call pairs.

---

## Why this exists

1. **No existing tool traced C++ object field-to-field propagation.** `TaintTracker` traces argument registers but does not model `std::string` method call chains. Manually tracing `c_str`/`assign` pairs in PanGPS Session 4 required hours of capstone work to establish that a portal-supplied gateway name reached a popen sink through two intermediate structs.

2. **SAC classifies a sink arg as ARG_PROPAGATED but cannot name the source field.** `CppStructFieldTracker` answers the follow-up question: which upstream struct field supplied the tainted char*, and at what offset.

3. **The pattern recurs across any C++ firmware binary.** Fortinet, Palo Alto, Cisco ASA, and similar targets share the same GCC `std::string` ABI. Once the c_str/assign PLT stubs are identified, the tracker works without modification.

---

## How it works

For each `assign()` call site in the binary:

```
E8 disp32  →  target ∈ assign_vas
```

the tracker forward-disassembles the owning function (for correct alignment on stripped binaries), then walks backward through the collected instruction list:

```
[Step 1] Find lea rdi, [base + disp>0]  →  dst struct field offset
[Step 2] Find mov rsi, rX               →  carrier register
[Step 3] Find call c_str_va before rX   →  source of char*
[Step 4] Find lea rdi, [base + disp>0]  →  src struct field offset
```

Handles direct chains (`rax → rsi`) and one-hop chains (`rax → rdX → rsi`). Stops backward search at any intervening CALL (which clobbers rax/rsi as caller-saved registers).

---

## CppStructFieldTracker

```python
from ablation.analyzers.cpp_struct_field_tracker import CppStructFieldTracker

tracker = CppStructFieldTracker.from_context(ctx)
```

### Constructor

```python
CppStructFieldTracker.from_context(ctx, c_str_va=None, assign_va=None)
```

| Parameter | Description |
|:----------|:-----------|
| `ctx` | `BinaryContext` for the target binary |
| `c_str_va` | PLT stub VA for `c_str()` / `data()`. Auto-detected from `ctx.plt` when omitted. |
| `assign_va` | PLT stub VA for `std::string::assign()`. Auto-detected from `ctx.plt` when omitted. |

Auto-detection matches PLT symbol names containing `c_str`, `_M_data`, or `basic_string` (for c_str) and `assign` or `operator=` (for assign). Pass explicit VAs when PLT symbols are stripped or the binary uses inlined string methods.

### Key methods

| Method | Returns |
|:-------|:--------|
| `find_flows()` | `List[FieldFlow]` — all c_str→assign chains in the binary |
| `flows_from_offset(offset)` | Flows where `src_offset == offset` |
| `flows_to_offset(offset)` | Flows where `dst_offset == offset` |
| `report(flows)` | Formatted string listing all flows |

### FieldFlow fields

| Field | Content |
|:------|:--------|
| `fn_va` | Owning function VA |
| `src_call_va` | VA of the `call c_str` instruction |
| `src_base_reg` | Base register in `[base_reg + src_offset]` before c_str |
| `src_offset` | Displacement into source struct |
| `carrier_reg` | Register that carried the char* to assign's rsi |
| `dst_call_va` | VA of the `call assign` instruction |
| `dst_base_reg` | Base register in `[base_reg + dst_offset]` before assign |
| `dst_offset` | Displacement into destination struct |

---

## Usage

```python
# Auto-detect PLT stubs
tracker = CppStructFieldTracker.from_context(ctx)
flows = tracker.find_flows()
print(tracker.report(flows))

# Explicit PLT VAs (stripped binary or PLT names absent)
tracker = CppStructFieldTracker.from_context(ctx, c_str_va=0x83e90, assign_va=0x838c0)

# Find all flows feeding a known sink struct field
hip_name_flows = tracker.flows_to_offset(0xd8)   # HipCheckConfig.gateway_name

# Find all flows sourced from a known network-controlled struct field
portal_flows = tracker.flows_from_offset(0x102d0)  # CPanMSServiceLinux.gateway_name
```

---

## Example output

```
[cpp_struct_field_tracker] 3 flow(s)

  fn@0xe9850       [rbx+0xd78] →(rax)→ [r14+0xbb8]  (c_str@0xe9bde assign@0xe9bed)
  fn@0xe9850       [rbx+0xd38] →(rax)→ [r14+0xbb8]  (c_str@0xe9df1 assign@0xe9e00)
  fn@0xe9850       [rbx+0xd58] →(rax)→ [r14+0xbb8]  (c_str@0xea00e assign@0xea01d)
```

Three c_str→assign chains in `RecvFromSocket` (PanGPS 6.3.3-c42), all copying different string fields from one struct into `r14+0xbb8` on another. Verified with byte-check: all c_str calls reach `0x83e90` and all assign calls reach `0x838c0`.

---

## False positives

**rsi set from a function argument, not c_str** — When `rsi` for the assign() call comes from a function argument register (e.g. `mov rsi, rdx` where rdx = arg3), the tracker correctly skips the site (no c_str call found setting rdx). The `PanPortalCfgCriteria` function in PanGPS is this exact pattern: its `assign()` call receives the gateway name as an argument, not via intra-function c_str. This is expected behavior — use inter-procedural analysis (TaintTracker) for argument chains.

**std::string copy constructor or operator=** — Some assign-class PLT stubs take `(this, const std::string&)` rather than `(this, const char*)`. These have a different argument type (pointer to another std::string, not a raw char*). If the PLT auto-detection picks them up, their rsi arg won't trace back to a c_str call and will produce no flow (they are silently skipped). No false positives, only missed flows.

**Inlined string methods** — If c_str or assign are inlined (no PLT call), the tracker produces no output for those sites. Supply explicit stub VAs and check that the stubs exist in the PLT; if they don't, the binary needs manual disassembly.

---

## Pipeline position

**Before this module:** Run `SinkArgClassifier` and identify ARG_PROPAGATED sinks. When a sink arg traces back to a struct field, use this module to find where that field was populated.

**After this module:** Feed confirmed `src_offset` values to `PathSolver` or `TaintTracker` to confirm reachability from network input to the source struct field.

---

## See also

- [SinkArgClassifier](sink-arg-classifier.md): classify what kind of argument reaches a shell sink
- [TaintTracker](taint-analysis.md): full inter-procedural taint from network recv to sink
- [PathSolver](path-solver.md): confirm a code path is feasible given constraints
