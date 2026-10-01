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

### PE32+ mode (UEFI DXE modules)

```python
from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner

data = open('/path/to/TlsDxe.efi', 'rb').read()
scanner = LA64MaxNotMinScanner.from_pe32plus(data, image_base=0)
findings = scanner.scan()
print(scanner.report(findings))
```

PE32+ (UEFI DXE/PEIM) binaries have no PLT/GOT — external functions such as
`AllocatePool` and `CopyMem` are called via EFI Boot Services Table pointers
through `jirl $ra, rj, 0` indirect calls.  The scanner cannot resolve sink names
automatically.  Instead, in PE32+ mode the scanner flags any `bl` or `jirl` call
where the max-not-min result is live in an argument register (`$a0`–`$a7`) at
call time.  Findings use `sink_name="<direct>"` or `"<indirect>"` with
`sink_arg` set to the register name; confirm manually whether the callee is
`AllocatePool`, `CopyMem`, or another sizing sink.

The VA/file-offset mapping is handled automatically: the parser reads the PE32+
optional header and code section table, then sets a bias so the standard
`_words_at()` path resolves VAs to the correct file offsets without copying
the section into a new buffer.

Validation corpus: TencentOS Server 4.6 EDK2 UEFI (QEMU_EFI.fd, LoongArch64).
87 DXE modules, 63 sink-proximate findings, 26 affected modules.
Highest-risk module: TlsDxe (GUID 3aceb0c0-3c72-11e4-9a56-74d435052646, 13
findings) — network-reachable in PXE/HTTP-boot context, no ASLR.

### Known false positives

The Rust Vec-append pattern uses a `bltu remaining_cap, read_result, error` guard
immediately before the memcpy call. The scanner does not detect branch-based guards,
so these appear as candidates and require manual verification. In the TencentOS
libstd corpus, four Vec-grow functions (around 0x1a3b4, 0x1a974, 0x1af48, 0x1b554)
hit this false-positive class.

---

## LA64HeapVulnScanner

**File:** `ablation/analyzers/la64_heap_vuln_scanner.py`

Detects integer overflow before heap allocation on LoongArch64 (CWE-190 → CWE-122).
Finds overflow-prone arithmetic — `mul.w`, `sll.w`, `add.w`, `addi.w` — whose
result flows into an allocation sink without an intervening bounds check.

The critical class is `mul.w`: LoongArch64 `mul.w rd, rj, rk` computes the low 32
bits of `rj * rk` and sign-extends the result to 64 bits. If an attacker controls
one multiplicand and drives the product past 2^31, the 64-bit size argument fed to
`malloc` is far smaller than the caller intends.

No capstone dependency. Uses the same pure-Python 32-bit opcode matching as
`LA64MaxNotMinScanner`. Supports ET_DYN, ET_EXEC, and ET_REL (kernel modules).

### Detection algorithm

1. Scan `.text` for `BL` to an allocation sink (resolved via `.plt`/`.rela.plt` for
   shared objects, or `.rela.text` R_LARCH_B26 for kernel modules).
2. Identify the size argument register (`$a0` for malloc/kmalloc, `$a1` for realloc,
   `$a2` for posix_memalign, etc.).
3. Trace backward up to 32 instructions from the `BL`, following register-move
   instructions (`or rd, rj, r0`).
4. Find the instruction that last defined the size register.
5. **Filter:** if that instruction is `addi.w rd, r0, const` (constant load) or any
   arithmetic with a zero-register operand, skip — not overflow.
6. **Filter:** if any `BLT/BGE/BLTU/BGEU/BEQ/BNE` between the definer and the `BL`
   uses the size register, skip — bounds check present.
7. Surviving candidates are findings.

### Severity

| Opcode | Severity | Rationale |
|---|---|---|
| `mul.w` | HIGH | 32-bit multiply, product wraps silently |
| `sll.w` | HIGH | 32-bit left shift, wraps silently |
| `add.w` | MEDIUM | 32-bit add, signed wrap then zero-extend |
| `addi.w` | MEDIUM | 32-bit add-immediate with user-controlled base |
| `mul.d` | MEDIUM | 64-bit multiply, harder to overflow but possible |
| `sll.d` | MEDIUM | 64-bit shift |

### Sink coverage

| Sink | Size argument |
|---|---|
| `malloc`, `kmalloc`, `kzalloc`, `vmalloc`, `vzalloc`, `__kmalloc` | arg0 |
| `calloc` | arg0 (nmemb) and arg1 (size) checked independently |
| `realloc`, `krealloc`, `devm_kmalloc` | arg1 |
| `posix_memalign`, `aligned_alloc` | arg1/arg2 |
| `mmap` | arg1 (length) |

### Usage

```python
from ablation.analyzers.la64_heap_vuln_scanner import LA64HeapVulnScanner

scanner = LA64HeapVulnScanner.from_path('/path/to/binary')
findings = scanner.scan()
print(LA64HeapVulnScanner.report(findings))

for f in findings:
    print(f"[{f.severity}] {f.overflow_op} overflow@0x{f.overflow_va:x} → {f.sink_name}@0x{f.sink_va:x}")
```

### Finding fields

| Field | Description |
|---|---|
| `overflow_va` | VA of the overflow arithmetic instruction |
| `overflow_op` | Mnemonic: `mul.w`, `sll.w`, `add.w`, `addi.w`, `mul.d`, `sll.d` |
| `overflow_reg` | Register number of the potentially-wrapped size value (0–31) |
| `sink_va` | VA of the `bl` to the allocation sink |
| `sink_name` | PLT symbol name (`malloc`, `calloc`, `kmalloc`, …) |
| `size_arg` | Argument label (`size`, `nmemb`, `newsize`, `length`) |
| `severity` | `HIGH` (32-bit wrap) or `MEDIUM` (64-bit or add-imm) |

### Known false-positive classes

**Constant addi.w via r0**: `addi.w $rd, $r0, const` is a constant load, not overflow.
Filtered automatically (`rj == 0` check).

**Zero-operand arithmetic**: `mul.w rd, r0, rx` always produces 0. Filtered.

**Count+1 for null terminator**: `addi.w $a0, $s0, 1; bl malloc` where `$s0` is a
string length. If `$s0` is bounded upstream this is safe. The scanner emits MEDIUM;
byte-verify the upstream bounds check before promoting to CONFIRMED.

**Struct-size add**: `addi.w $a0, $t0, sizeof(hdr)` where `t0` is a user-provided
payload size. Genuine vulnerability if payload size is unbounded — confirms as HIGH
after source-level verification.
```
