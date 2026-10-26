# I386CallChainResolver

Multi-level call chain resolver for i386 ELF binaries. Extends `CallerArgResolver` with automatic multi-level ascent and struct pointer origin tracing.

---

## Why this exists

1. Gap SYNERGY-GAP-004: `CallerArgResolver` resolves ONE level of callers and returns `UNKNOWN` when a caller passes `push mem [dword ptr [reg]]`: a struct field dereference. Tracing the struct pointer origin (is `reg` a function argument? a network recv return value? a global?) requires a separate pass that `CallerArgResolver` does not perform.

2. Manual multi-level iteration was impractical: Upgrading a `CANDIDATE` finding to `CONFIRMED` network-injectable requires traversing multiple levels of the call graph. Calling `CallerArgResolver` manually at each level, handling `ARG_PROPAGATED` recursion, detecting `NO_CALLERS`, and stopping at static ceilings is repetitive work that belongs in a module.

3. Network source detection: `CallerArgResolver` classifies call site arguments but does not check whether any callee in the chain is a network input function `recv`, `recvfrom`, `read`, and `accept`, and so on. This module does, enabling `CANDIDATE → CONFIRMED` upgrades.

---

## How it works

```
resolve_chain(func_va, func_arg_pos) →
  worklist = [(func_va, arg_pos, depth=0)]
  while worklist:
    CallerArgResolver.resolve(callee_va, arg_pos) for each entry
    ARG_PROPAGATED  → add caller to worklist at depth+1
    UNKNOWN         → _resolve_deref_origin():
                        trace reg backward in caller:
                          [ebp+N]      → ARG_PROPAGATED: add to worklist
                          call F; eax  → if F ∈ NETWORK_SOURCES → CONFIRMED
                          [global]     → STATIC_CEILING
                          imm          → SAFE
    RODATA_CONST    → SAFE leaf
    NO_CALLERS      → STATIC_CEILING leaf (function pointer dispatch)
  all leaves SAFE → SAFE
  any non-safe    → STATIC_CEILING
  network found   → CONFIRMED (returns immediately)
```

---

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `CONFIRMED` | A network source function (`recv`/`recvfrom`/`read`/`accept`/etc.) feeds the exec argument. Finding is confirmed exploitable via network input. |
| `SAFE` | All call chain leaves trace to RODATA constants or compile-time immediates. |
| `STATIC_CEILING` | Max depth reached, or struct pointer origin is a global or internal function that cannot be traced further without dynamic analysis. |

---

## Constructor patterns

```python
from ablation.analyzers.i386_call_chain_resolver import I386CallChainResolver

# From BinaryContext (preferred — avoids double parse)
ccr = I386CallChainResolver.from_context(ctx)

# From path (builds BinaryContext internally)
ccr = I386CallChainResolver.from_path('/path/to/ccm_eng_inf')

# Trace an ARG_PROPAGATED dispatch function
result = ccr.resolve_chain(func_va=0x80cf362, func_arg_pos=0, max_depth=8)
print(result.report())
# → I386CallChainResolver: 0x80cf362 arg_pos=0 → STATIC_CEILING (depth=2)
#     0x80cf362 ← caller 0x80d20df (site=0x80d2162): ARG_PROPAGATED — [ebp+0x14]=func_arg_3
#     0x80d20df ← caller 0x0 (site=0x0): STATIC_CEILING — NO_CALLERS
```

---

## Confirmed results

| Binary | Func VA | Result | Detail |
|--------|---------|--------|--------|
| ccm_eng_inf Synergy 7.0 | 0x80cf362 execvp dispatch | STATIC_CEILING depth=2 | Struct ptr → [ebp+0x14]=func_arg_3 at 0x80d20df; 0x80d20df has NO_CALLERS func pointer |
| ccm_eng_inf | 0x80d4263 system dispatch | STATIC_CEILING depth=0 | NO_CALLERS: function pointer dispatch |
| ccm_eng_ora | 0x80dcb0e execvp-A | STATIC_CEILING depth=1 | func pointer at 0x80df88b |
| ccm_eng_ora | 0x80dcbe1 execvp-B | STATIC_CEILING depth=3 | 3 ARG_PROPAGATED callers, all terminate at func pointer |
| ccm_eng_ora | 0x80e1a0d (system) | STATIC_CEILING depth=1 | func pointer at 0x80e1e87 |

All Synergy 7.0 exec dispatch paths are STATIC_CEILING. Dynamic analysis required to confirm whether function pointer dispatch chains receive network input.

---

## Network sources detected

`recv recvfrom recvmsg recvmmsg read pread pread64 fread accept accept4 gets fgets fgetc getchar scanf fscanf sscanf vscanf vfscanf __isoc99_sscanf __isoc99_fscanf __isoc99_scanf getline getdelim msgrcv mq_receive mq_timedreceive`

---

## Gap IDs

- `SYNERGY-GAP-004`: static ceiling confirmed for SYNERGY-001 / SYNERGY-002 Synergy 7.0 ccm_eng_inf/ora
