# WindowAnalyzer alignment methods

## Why this exists

Backward scanning from an arbitrary call site VA produces misaligned instruction decode in stripped binaries. The `dump()` method starts disassembly from whatever VA the caller provides. If that VA does not land on an instruction boundary, capstone decodes garbage for the first several instructions and the context before the CALL is unreadable.

The sim_ppc-power9 reader binary exposed this: a 100-byte backward window from the execvp call site at `0x42c93b` produced `sub cl, byte ptr [rax - 0x77]` and other meaningless output. The fix was to search backward for ENDBR64, which is always placed at instruction boundaries by the compiler. This module bakes that fix into reusable methods.

Gap ID: **IBM-WIN-GAP-001**.

## Usage

```python
from ablation.analyzers.window_analyzer import WindowAnalyzer

wa = WindowAnalyzer.from_path('/tmp/extract/usr/bin/reader')

# Find the function start before a call site
start_va = wa.align_to_func_start(0x42c93b)
print(f"Function starts at 0x{start_va:x}")

# Disassemble the function from its prologue to the call
lines = wa.dump_caller_context(0x42c93b)   # max_insns defaults to 30
for line in lines:
    print(line)
```

## Methods

### `align_to_func_start`

Accepts a call site VA and an optional search window in bytes (default 512). Searches backward for ENDBR64 first because ENDBR64 is always placed at a guaranteed instruction boundary by CET-enabled compilers. Falls back to `push rbp` if ENDBR64 is not found. Returns the VA of the nearest match. Returns `call_site_va - search_back` if neither pattern is found.

### `dump_caller_context`

Accepts a call site VA, an optional search window in bytes, and an optional `max_insns` count (default 30). Calls `align_to_func_start()`, then disassembles forward from the function prologue to the call instruction. Returns the last `max_insns` annotated lines for a clean view of register state at the call site.

## Notes

ENDBR64 bytes are `f3 0f 1e fa`. The search uses `bytes.rfind()` so it finds the nearest match before the call site, not the first match in the window.

The `_load_va()` helper computes the ELF load bias from the first PT_LOAD segment. For PIE ELFs with multiple PT_LOAD segments, the returned VA may be slightly off but the disassembly bytes remain valid.
