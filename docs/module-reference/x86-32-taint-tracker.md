# X86_32TaintTracker

**File:** `ablation/analyzers/taint_tracker_x86_32.py`

Intraprocedural taint analysis for stripped i386 ELF binaries (32-bit x86, SysV ABI, CDECL32 calling convention). Traces network-sourced data from read/recv/fgets/getenv sources to command-execution sinks (system, popen, execv, execvp) and memory-corruption sinks (strcpy, sprintf, snprintf, memcpy).

First deployed on Acronis True Image 2018 build 15560 rescue environment (`asamba` and `product.bin`, both i386 ELF).

Confirmed findings that drove this module:
- **ATI-KRB-001**: `asamba_mount_cifs_krb5` (0x804ec40) — `snprintf` injects five Kerberos credential fields into `/bin/mount.cifs` command string → `system()`. toupper-only sanitizer at 0x804de18 does not strip shell metacharacters. CWE-78 HIGH.
- **ATI-KRB-002**: `asamba_kerberos_domain_prep` (0x804e986) — `snprintf` injects SMB server hostname into `/bin/net time set -S %s` → `system()`. CWE-78 HIGH.

---

## Usage

```python
from ablation.analyzers.taint_tracker_x86_32 import X86_32TaintTracker

# From file path (auto-detects function starts via ebp-frame prologue scan)
tracker = X86_32TaintTracker.from_path('/path/to/asamba')
for finding in tracker.run_interprocedural():
    print(finding)

# From BinaryContext (inherits pre-computed func_starts)
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/asamba')
tracker = X86_32TaintTracker.from_context(ctx)
findings = tracker.run_interprocedural()

# With custom sinks — {name: {arg_index: min_len}}
tracker = X86_32TaintTracker.from_path(
    path,
    custom_sinks={'asamba_system_wrapper': {0: 0}}
)
```

---

## ABI model — CDECL32 (i386 SysV)

| Register | Role |
|---|---|
| eax | Return value; caller-saved; tainted by source calls |
| ecx | Caller-saved; cleared on every unknown call |
| edx | Caller-saved; cleared on every unknown call |
| ebx | Callee-saved; **GOT base** in PIC binaries (set by PIC thunk) |
| esi | Callee-saved |
| edi | Callee-saved |
| ebp | Frame base pointer; never tainted |
| esp | Stack pointer; never tainted |

### Call convention

Arguments are pushed right-to-left before the `call` instruction:

```
push arg2     ; last arg pushed first in right-to-left order
push arg1
push arg0     ; arg0 is last pushed (closest to call site)
call system
add esp, 12   ; caller cleans stack
```

The tracker models this via `esp_stack`: a dict keyed by `esp_delta` (bytes pushed since function entry). At a sink `call`, it maps `arg_idx → esp_stack[esp_delta - arg_idx * 4]`.

---

## PLT resolution

Handles both i386 PLT stub variants:

| Variant | Encoding | When |
|---|---|---|
| Non-PIC executable | `ff 25 <abs32>` (`jmp *[abs32]`) | Static binaries, `-no-pie` executables |
| PIC shared library | `ff a3 <disp32>` (`jmp *[ebx+disp32]`) | `-fpic` shared libs, PIE executables |

Each PLT stub is 16 bytes. Stubs start at `.plt` base + 0x10 (skip the resolver stub). The resolver maps: for each `JUMP_SLOT` relocation at `got_va`, resolve `disp32 = got_va - got_plt_base` (PIC) or `abs32 = got_va` (non-PIC).

---

## Stack frame model

```
[ebp + 8]    arg0     (first argument)
[ebp + 12]   arg1
[ebp + N]    argN-1
[ebp + 4]    return address
[ebp + 0]    saved ebp
[ebp - 4]    local0
[ebp - N]    localN-1
```

The tracker indexes `stack: Dict[int, FrozenSet[str]]` on the signed ebp-relative offset. Positive offsets → incoming arguments (tainted at function entry if passed from sources); negative offsets → locals (tainted when a source-derived value is stored).

---

## GOT-relative string detection

In PIC i386 binaries, strings are accessed as `ebx + disp32` where `ebx` is the GOT base (set by the PIC thunk: `call __x86.get_pc_thunk.bx; add $offset, %ebx`). The tracker does not perform GOT-base emulation — format-string references in sink arg analysis are resolved by `_build_plt_map()` using lief's relocation table.

For full format-string constant detection on i386, pass the result of `SinkArgClassifier.from_path(elf).classify_all()` separately.

---

## Known limitations

1. **Intraprocedural only.** Does not follow taint across call boundaries. For interprocedural taint, combine with `XRefGraph.callers_of(sink_plt_va)` to identify entry functions.
2. **Function start detection via prologue scan.** Finds `55 89 e5` (push ebp; mov ebp,esp) prologues. FPO (frame-pointer-omitted) functions are not found unless a `BinaryContext` with full `func_starts` is passed via `from_context(ctx)`.
3. **GOT-base not emulated.** PIC thunk initialization is not tracked; `ebx` is treated as untainted throughout. This is correct for taint purposes since GOT addresses are constant.
4. **No loop analysis.** Single linear pass, no fixed-point iteration. Loops with back-edges may miss taint propagation across iterations.
5. **esp arithmetic.** `sub esp,N` for frame allocation does not adjust `esp_delta`; only explicit `push` / `pop` / `add esp,N` (call cleanup) do. This is correct for the intended use case (call-arg tracking), but stack-based copy loops are not modeled.

---

## Ablation gap this module closes

Prior to this module, `taint_tracker_x86.py` was hardcoded to `CS_MODE_64`, making i386 binaries invisible to the taint analysis pipeline. The `isa_x86.py` infrastructure had `Mode.X86 = "x86"` (IA-32) and `Abi.CDECL32` already defined — this module provides the corresponding runtime tracker.

Add to `CompilerSecurityGate` dispatch table when i386 ELF support is needed there.
