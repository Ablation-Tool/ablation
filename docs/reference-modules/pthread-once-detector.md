# PthreadOnceDetector

Identifies `pthread_once(3)` lazy-init wrappers in stripped x86-64 ELFs that are structurally indistinguishable from authentication checks.

---

## Why this exists

1. **Manual disassembly is required to distinguish auth from lazy-init.** A two-instruction wrapper (`call pthread_once; xor eax,eax; ret`) looks identical to a gating function until you verify the PLT target and the return path.
2. **SemanticSearcher returns "authentication" for both real auth and lazy-init wrappers.** Embedding similarity cannot distinguish control structure from purpose.
3. **`callers_of()` identifies the call sites but not the verdict.** Without a classifier, every caller of a pthread_once wrapper must be manually inspected.

Concrete gap (session 12, IBM Storage Defender Sentinel dispatch): `func@0x7781ac` was initially classified as an auth barrier by Q-shell session init `func@0xce3be2`. Full disassembly showed it calls `pthread_once()` and always returns 0 — LAZY_INIT, not auth.

---

## How it works

1. Parse ELF64 section headers; collect all `SHF_EXECINSTR` sections into `_exec_regions`.
2. Locate `pthread_once` PLT stub via `.rela.plt` relocations: walk RELA entries, resolve symbol name from `.dynsym`/`.dynstr`, compute PLT stub VA as `plt_va + (j+1) × 16`.
3. Scan all exec regions for `E8 rel32` CALL instructions whose target equals `_plt_va`.
4. For each call site, estimate the enclosing function start by scanning **nearest-first backward** (max 256 bytes), recognizing:
   - `endbr64` (`f3 0f 1e fa`) — CET-enabled prologue.
   - `push rbp` (`55`) — frame-pointer prologue.
   - `sub rsp, N` (`48 83 ec XX`) preceded by a boundary byte (ret/nop/int3/zero-fill) — frameless leaf prologue.
5. Disassemble the function body (max 512 bytes) with Capstone; count CALL instructions; detect `xor eax,eax; ret` pattern (stack-cleanup instructions pass through without clearing the zero-return flag).
6. Verdict:
   - `LAZY_INIT`: ≤1 call + unconditional zero return.
   - `POSSIBLE_AUTH`: ≥2 calls.
   - `UNKNOWN`: capstone unavailable or disassembly inconclusive.

---

## PthreadOnceDetector

```python
from ablation.analyzers.pthread_once_detector import (
    PthreadOnceDetector, LAZY_INIT, POSSIBLE_AUTH, UNKNOWN
)

det     = PthreadOnceDetector.from_context(ctx)  # preferred
results = det.detect()
print(PthreadOnceDetector.report(results))

# Filter safe-to-eliminate auth barriers:
lazy = [r for r in results if r.verdict == LAZY_INIT]
```

### PthreadOnceResult fields

| Field | Type | Description |
|---|---|---|
| `call_va` | int | VA of the `call pthread_once` instruction |
| `func_va` | int | Estimated function start VA |
| `verdict` | str | `LAZY_INIT` / `POSSIBLE_AUTH` / `UNKNOWN` |
| `returns_zero` | bool | True if function unconditionally returns 0 |
| `call_count` | int | Total CALL instructions in function body |
| `caller_vas` | list[int] | VAs of functions that call this wrapper |
| `detail` | str | Human-readable classification rationale |

---

## Known-positive

IBM Storage Defender Sentinel 2.3.2 dispatch binary:
- `func@0x7781ac` → `LAZY_INIT`, `returns_zero=True`, `call_count=1`.
- Prologue: `sub rsp, 8` (frameless leaf, preceded by `ret` byte = 0xc3 from prior function).
- Called from `func@0xce3be2` (Q-shell session init) as a gating call — correctly classified as non-auth.

---

## Limitations

- Handles `E8 rel32` CALL encoding only; `FF /2` indirect calls to PLT are not detected.
- PLT slot formula (`plt_va + (j+1) × 16`) is correct for standard x86-64 PLT but may be incorrect for `.plt.sec` IBT PLT entries in `-fcf-protection`-compiled binaries.
- `last_was_zero` is cleared by any instruction not in the stack-cleanup allowlist (`ADD`, `POP`, `LEAVE`, `MOV`); unusual epilog patterns may produce `UNKNOWN` instead of `LAZY_INIT`.
