# Vulnerability Scanners

Targeted scanners for specific vulnerability classes in x86-64 ELF binaries.
Both scanners accept either a binary path or an existing `BinaryContext`. Reuse
the context when running multiple scanners on the same binary.

---

## FormatStringScanner

**File:** `ablation/analyzers/format_string_scanner.py`

Detects format string vulnerabilities in x86-64 ELF binaries. A format argument
is safe only when it is a string literal (RIP-relative load from `.rodata`). Any
any other provenance is a finding: a function argument, a stack variable, or a
register populated from `recv`/`read`.

Covers the full `printf` family, `syslog`, `err`/`warn`, and common custom
`debug_printf`/`log_printf` variants.

### Detection algorithm

Per call site to a format function:
1. Identify the fmt register for the callee (`RDI` for `printf`, `RSI` for `fprintf`, `RDX` for `snprintf`, etc.)
2. Walk backwards up to 20 instructions to find the last definition of that register
3. If the definition is `LEA` from `.rodata` → string literal → **safe**
4. Otherwise → finding
5. Severity **HIGH** if fmt comes from a function entry argument register (`rdi/rsi/rdx/rcx`); **MEDIUM** if provenance is unclear (stack load, cross-call result)

### Covered functions

| Function family | fmt register |
|---|---|
| `printf`, `vprintf` | RDI (arg0) |
| `fprintf`, `sprintf`, `asprintf`, `dprintf`, `syslog`, `err`, `warn` | RSI (arg1) |
| `snprintf`, `vsnprintf` | RDX (arg2) |
| `log_printf`, `debug_printf`, `trace_printf` | RDI / RSI |

### Usage

```python
from ablation.analyzers.format_string_scanner import FormatStringScanner

# From binary path
scanner = FormatStringScanner.from_path('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))

# Reusing an existing BinaryContext (avoids LIEF rebuild)
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = FormatStringScanner.from_context(ctx)
findings = scanner.scan()

# High severity only
highs = [f for f in findings if f.severity == 'HIGH']
```

### Finding fields

| Field | Description |
|---|---|
| `func_va` | VA of the enclosing function |
| `call_va` | VA of the format function call site |
| `fmt_func` | Name of the format function called |
| `fmt_reg` | Register that held the format argument |
| `provenance` | How the register was defined: `RODATA` / `ENTRY_ARG` / `STACK_LOAD` / `UNKNOWN` |
| `severity` | `HIGH` (entry arg) or `MEDIUM` (unclear provenance) |

---

## HeapVulnScanner

**File:** `ablation/analyzers/heap_vuln_scanner.py`

Detects four heap memory corruption vulnerability classes in x86-64 ELF binaries,
grounded in TAOSSA chapters 5 and 6.

### Vulnerability classes

**`INT_OVERFLOW_BEFORE_ALLOC`**

`IMUL`/`MUL`/`SHL` on a register, result passed to an allocator (`malloc`, `calloc`,
`kmalloc`, `ExAllocatePool`, etc.) in `RDI`/`RSI`/`RDX` without an intervening
overflow flag check. Classic TAOSSA L6-2 `width * height` pattern.

**`USE_AFTER_FREE`**

`free(ptr)` followed by a dereference or re-use of the same register in the same
function without an intervening store. Covers `[reg+off]` memory reads and passing
the freed register as a call argument.

**`DOUBLE_FREE`**

The same register freed twice in the same function without reassignment between
the two `free()` calls. Detects the TAOSSA Listing 5-4 strcpy-then-free corruption
pattern.

**`OFF_BY_ONE_ALLOC`**

Allocation size computed as `strlen(buf)` without `+1` for the NUL terminator,
followed by `strcpy`/`memcpy` into the allocation.

### Usage

```python
from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner

# From binary path
scanner = HeapVulnScanner.from_path('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))

# Reusing an existing BinaryContext
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = HeapVulnScanner.from_context(ctx)
findings = scanner.scan()

unguarded = [f for f in findings if f.severity == 'HIGH']
```

### Finding fields

| Field | Type | Description |
|---|---|---|
| `kind` | str | `int_overflow_before_alloc` / `uaf` / `double_free` / `off_by_one_alloc` |
| `func_va` | int | VA of the enclosing function |
| `site_va` | int | VA of the specific instruction |
| `description` | str | Human-readable summary of the pattern found |
| `severity` | str | `HIGH` (direct path) or `MEDIUM` (conditional/unclear) |
| `alloc_sym` | str | Allocator name, when applicable |
| `freed_at` | int | VA of the prior `free()` call, for UAF/double-free findings |

### Allocator coverage

User-space: `malloc`, `calloc`, `realloc`, `xmalloc`, `xcalloc`, `asprintf` variants, `g_malloc`, `BUF_MEM_grow` (OpenSSL).  
Kernel: `kmalloc`, `kzalloc`, `kcalloc`, `vmalloc`, `kvmalloc`.  
Windows: `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExAllocatePool2`, `HeapAlloc`, `LocalAlloc`.

---

## Running both scanners together

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.format_string_scanner import FormatStringScanner
from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner

ctx = BinaryContext.load_or_build('/path/to/binary')

fmt_findings = FormatStringScanner.from_context(ctx).scan()
heap_findings = HeapVulnScanner.from_context(ctx).scan()

all_highs = (
    [f for f in fmt_findings if f.severity == 'HIGH'] +
    [f for f in heap_findings if f.severity == 'HIGH']
)
print(f"{len(all_highs)} HIGH findings across format string and heap classes")
```
