# Vulnerability Scanners

Targeted scanners for specific vulnerability classes in x86-64 ELF binaries.
Both scanners accept either a binary path or an existing `BinaryContext`. Reuse
the context when running multiple scanners on the same binary.

---

## FormatStringScanner

**File:** `ablation/analyzers/format_string_scanner.py`

Detects format string vulnerabilities in x86-64 ELF binaries. A format argument
is safe only when it is a string literal (RIP-relative load from `.rodata`). Any
other provenance is a finding: a function argument, a stack variable, or a
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
| `callee` | Name of the format function called (e.g. `printf`, `syslog`) |
| `fmt_reg` | Register that held the format argument |
| `provenance` | How the register was defined: `rodata` / `arg_passthrough` / `stack_load` / `register` / `unknown` |
| `severity` | `HIGH` (entry arg passthrough) or `MEDIUM` (unclear provenance) |
| `description` | Human-readable summary of the finding |

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

## SqlSinkScanner

**File:** `ablation/analyzers/sql_sink_scanner.py`

Detects raw SQL injection in C/C++ binaries that call the MySQL C API or SQLite3
directly, without a prepared-statement layer. The classic pattern:

```c
snprintf(buf, sizeof(buf), "SELECT ... WHERE login='%s'", username);
mysql_query(conn, buf);              // username flows unsanitized into SQL
```

`FormatStringScanner` cannot catch this because `snprintf` is safe by itself —
the danger is in what the formatted buffer is *then used for*. `SqlSinkScanner`
specifically follows the data flow from format-string builder to SQL execution sink.

### Detection algorithm

For each call site to a SQL sink (`mysql_query`, `mysql_real_query`, `sqlite3_exec`,
`sqlite3_prepare_v2`, `sqlite3_prepare`):

1. Identify the SQL string register for the callee (`RSI` for `mysql_query`/`mysql_real_query`,
   `RDX` for `sqlite3_exec`/`sqlite3_prepare_v2`).
2. Walk backward up to 40 instructions looking for how that register was populated:
   - **`LEA reg, [rip+off]`** pointing to `.rodata` → `RODATA_CONST`.  
     Inspect the literal for `%s`: if present, mark `INJECTABLE_LITERAL` (rare but real).
   - **`MOV reg, rbp/rsp+N`** (stack-local buffer): look further back for the
     `snprintf`/`sprintf` that filled it. Inspect *its* format string for `%s`.
   - **`MOV reg, rax`** after a call: consider the call's return value as the SQL
     string — mark `RETURN_VALUE` (requires caller trace; verdict = `UNKNOWN`).
   - **Entry register** (`rdi/rsi/rdx/rcx/r8/r9` unchanged since function entry):
     mark `ARG_PROPAGATED`.
3. For `snprintf`/`sprintf`-built buffers: extract the format string (should be a
   `LEA`/`MOVQ` from `.rodata`). Scan for `%s` (string interpolation). A `%s`
   specifier with a non-RODATA argument → `INJECTABLE`.
4. `%d`, `%u`, `%ld`, `%llu`, `%x` etc. → numeric only → `SAFE_NUMERIC`.

### Verdict values

| Verdict | Meaning |
|---|---|
| `INJECTABLE` | Format string has `%s`; arg is not RODATA. High-confidence SQL injection candidate. |
| `INJECTABLE_LITERAL` | SQL literal in RODATA already contains `%s`. Should not happen in safe code. |
| `RODATA_CONST` | SQL string is a RODATA literal with no `%s`. Safe. |
| `SAFE_NUMERIC` | Format string has only `%d`/`%u`/`%x` — no string interpolation. Safe. |
| `ARG_PROPAGATED` | SQL string arrived from an entry-argument register. Caller controls it; needs caller trace. |
| `UNKNOWN` | Provenance not resolved within look-back window. |

### Covered sinks

| Function | SQL arg | Arg position |
|---|---|---|
| `mysql_query(conn, sql)` | `RSI` | arg1 |
| `mysql_real_query(conn, sql, len)` | `RSI` | arg1 |
| `sqlite3_exec(db, sql, ...)` | `RSI` | arg1 |
| `sqlite3_prepare_v2(db, sql, ...)` | `RSI` | arg1 |
| `sqlite3_prepare(db, sql, ...)` | `RSI` | arg1 |

### Usage

```python
from ablation.analyzers.sql_sink_scanner import SqlSinkScanner

scanner = SqlSinkScanner.from_path('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))

# Reusing an existing BinaryContext
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = SqlSinkScanner.from_context(ctx)
findings = scanner.scan()

# INJECTABLE only
injections = [f for f in findings if f.verdict == 'INJECTABLE']
```

### Finding fields

| Field | Description |
|---|---|
| `sink_name` | PLT symbol called (`mysql_query`, `sqlite3_exec`, etc.) |
| `call_va` | VA of the sink call instruction |
| `func_va` | VA of the enclosing function |
| `verdict` | `INJECTABLE` / `INJECTABLE_LITERAL` / `RODATA_CONST` / `SAFE_NUMERIC` / `ARG_PROPAGATED` / `UNKNOWN` |
| `fmt_string` | Format string literal if resolved (e.g. `"SELECT ... WHERE x='%s'"`) |
| `fmt_va` | VA of the format string in RODATA (if resolved) |
| `description` | Human-readable summary |

---

## Running all scanners together

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

---

## LA64MaxNotMinScanner

**File:** `ablation/analyzers/loongarch64_max_not_min_scanner.py`

Detects the GCC 12.3.1.7-1.tl4 LoongArch64 code-generation bug where branchless
`min(a, b)` emits `max(a, b)` instead, and confirms that the wrong value flows
into a memory-sizing sink.

The compiler uses four instructions for branchless min/max:

```
sltu   Rcond, Ra, Rb       # Rcond = (Ra < Rb) unsigned
masknez Rtmp1, Rb, Rcond   # Rtmp1 = Rcond ? Rb : 0
maskeqz Rtmp2, Ra, Rcond   # Rtmp2 = !Rcond ? Ra : 0
or     Rout, Rtmp2, Rtmp1  # Rout = Rtmp1 | Rtmp2
```

That sequence is `max(Ra, Rb)`. Correct `min(Ra, Rb)` swaps the masknez/maskeqz
order. GCC 12.3.1.7-1.tl4 on TencentOS Server 4.6 emits the wrong order for
every branchless min in the corpus, affecting libstd, swtpm, and 608 other ELF
files. When the wrong value is a memcpy count or malloc size the result is a heap
overflow (CWE-122).

### Detection algorithm

1. Slide a four-word window over `.text` looking for the exact opcode sequence
   that matches the MAX pattern (sltu, then masknez with the same cond register,
   then maskeqz with the same cond register, then or combining the two mask outputs).
2. Track the `or` result register through register-move instructions for up to 20
   instructions ahead of the pattern.
3. Flag the finding when the tracked register reaches a memory-sizing sink argument
   before being clobbered.

No capstone dependency. Uses pure 32-bit integer matching against the binutils 2.41
opcode table. Handles the LoongArch64 PLT two-slot (32-byte) header automatically.

### Sink coverage

| Sink | Argument |
|---|---|
| `memcpy`, `memmove`, `memset` | count (arg2) |
| `read`, `pread`, `pread64` | nbytes (arg2) |
| `fread` | nmemb (arg2) |
| `recv`, `recvfrom` | len (arg2) |
| `fgets` | size (arg1) |
| `malloc`, `calloc`, `kmalloc`, `vmalloc`, `kzalloc` | size (arg0) |
| `realloc`, `posix_memalign` | size (arg1/arg2) |

### Usage

```python
from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner

scanner = LA64MaxNotMinScanner.from_path('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))

# Sink-proximate findings only (already filtered by scan())
for f in findings:
    print(f"0x{f.pattern_va:x}  {f.result_name} -> {f.sink_name}({f.sink_arg})@0x{f.sink_va:x}")
```

### Finding fields

| Field | Description |
|---|---|
| `pattern_va` | VA of the `sltu` instruction that starts the four-instruction sequence |
| `result_reg` | Integer register number of the `or` result (0-31) |
| `result_name` | ABI name of the result register (e.g. `$a2`) |
| `sink_va` | VA of the `bl` instruction that calls the sink |
| `sink_name` | PLT symbol name (e.g. `memcpy`) |
| `sink_arg` | Human label for the dangerous argument (`count`, `size`, etc.) |
| `context` | Space-separated hex words of the four-instruction sequence |

### Known false positives

The Rust Vec-append pattern uses a `bltu remaining_cap, read_result, error` guard
immediately before the memcpy call. The scanner does not detect branch-based guards,
so these appear as candidates and require manual verification. In the TencentOS
libstd corpus, four Vec-grow functions (around 0x1a3b4, 0x1a974, 0x1af48, 0x1b554)
hit this false-positive class.
```
