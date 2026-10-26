# SinkArgClassifierI386

Forward register-state exec-sink classifier for i386 ELF binaries.

---

## Why this exists

1. Gap RMC-GAP-002 / COMMSVR-GAP-004 / HACMP-GAP-001: The main `SinkArgClassifier` hardcodes x86-64 registers `rdi`, `rsi`, and `rdx`. i386 cdecl passes all arguments on the stack (`push` or `sub esp; mov [esp+N]`). This module is the canonical i386-aware variant.

2. Forward-state vs backward-scan: `sink_arg_classifier_x86_32.py` uses a backward push-count scan with a fixed lookback window. When the exec argument register is loaded far before the call beyond the window and aliased through several `mov reg, reg2` instructions, the backward scan returns UNKNOWN. This module uses a forward register-state pass, no lookback limit.

3. Register alias tracking: When the forward pass sees `mov eax, [ebp+8]`, it records `reg_state[eax] = ARG_PROPAGATED`. A subsequent `mov edi, eax` then sets `reg_state[edi] = ARG_PROPAGATED`. This chain persists for the entire function lifetime.

---

## Algorithm

```
for each function in func_starts:
  reg_state = {}        # reg_id → verdict
  call_args = {}        # slot_idx → verdict (built by push / mov[esp+N])
  stack = {}            # ebp_neg_offset → verdict (for local slot fills)

  for insn in forward_disasm(func_start, func_end):
    if insn == CALL:
      if callee in exec_sinks:
        verdict = call_args.get(arg_pos, UNKNOWN)
        emit SinkClassification
      call_args.clear()          # arg build-up resets after any call
      reg_state[EAX] = UNKNOWN   # return value unknown
      continue

    # Update reg_state from insn:
    mov reg, [ebp+N]  (N>0)  → reg_state[reg] = ARG_PROPAGATED
    mov reg, [ebp-N]          → reg_state[reg] = stack.get(N, UNKNOWN)
    mov reg, imm              → reg_state[reg] = RODATA_CONST
    mov reg1, reg2            → reg_state[reg1] = reg_state[reg2]
    mov reg, [abs_va](.rodata)→ reg_state[reg] = RODATA_CONST
    mov reg, [ARG_PROP+disp]  → reg_state[reg] = ARG_PROPAGATED  (deref propagation)
    arithmetic on ARG_PROP reg → reg_state[reg] = UNKNOWN
    xor reg, reg              → reg_state[reg] = RODATA_CONST (zero)
    push val                  → call_args shifts; call_args[0] = classify(val)
    mov [esp+N], val          → call_args[N//4] = classify(val)
```

**Key ordering**: exec-sink results are recorded BEFORE `call_args.clear()`: the verdict is captured from the accumulated push/mov state, then cleared for the next call.

---

## Constructor patterns

```python
from ablation.analyzers.sink_arg_classifier_i386 import SinkArgClassifierI386

# From path
clf = SinkArgClassifierI386.from_path('/path/to/ccm_eng_inf')

# From BinaryContext (avoids double parse)
clf = SinkArgClassifierI386.from_context(ctx)

# Custom sink
clf.add_sink('my_exec_wrapper', arg_pos=0)

results = clf.classify_all()
print(clf.report(results))
```

---

## Verdicts

Same as SinkArgClassifier: `RODATA_CONST` / `SNPRINTF_RODATA` / `ARG_PROPAGATED` / `UNKNOWN`.

---

## Confirmed results

| Binary | Sites | ARG_PROPAGATED | RODATA_CONST | UNKNOWN |
|--------|-------|----------------|--------------|---------|
| ccm_eng_inf Synergy 7.0 | 18 | 4 0x80cf3c8 ✓, 0x80cf5a2 ✓, and 0x80d427a ✓ | 10 | 4 |
| ccm_eng_ora Synergy 7.0 | 17 | 4 0x80dcb74 ✓, 0x80dcd4e ✓, and 0x80e1a26 ✓ | 10 | 3 |

All ARG_PROPAGATED findings byte-verified against known synergy_re.py entries.

---

## Comparison with sink_arg_classifier_x86_32.py

| Capability | x86_32 backward | i386 (forward) |
|------------|-------------------|----------------|
| i386 cdecl stack args | ✓ | ✓ |
| push convention | ✓ | ✓ |
| sub-esp/mov[esp+N] | ✓ | ✓ |
| [reg+deref] propagation | ✓ session 20 | ✓ |
| strcpy-family backtrack | ✓ session 20 |: no stack-slot fill tracking |
| Long-range register persistence | limited lookback window | ✓ full function |
| Register alias chains | limited | ✓ reg_state propagation |

Use x86_32 when strcpy/snprintf stack-slot patterns need classification. Use i386 this module when the exec arg register is set far before the call.

---

## Gap IDs

- `RMC-GAP-002`: i386 cdecl ABI mismatch in main SinkArgClassifier
- `COMMSVR-GAP-004`: same
- `HACMP-GAP-001`: same
