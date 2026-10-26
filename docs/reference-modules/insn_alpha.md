# AlphaEcoffScanner

Scans DEC Alpha AXP ECOFF (OSF/1) binaries for exec-class sink calls in stripped
executables where BinaryContext returns `arch=x86_64, func_starts=0`.

---

## Why this exists

1. **BinaryContext cannot parse OSF/1 Alpha ECOFF.** LIEF and capstone identify
   the magic as unknown and fall back to x86_64 with zero function starts.
   A 6MB DataExplorer binary with 47 886 BSR and 11 435 JSR call sites produced
   no BinaryContext candidates before this module.

2. **Standard COFF parsers misparse the file header.** OSF/1 Alpha ECOFF uses a
   24-byte FILHDR with a 64-bit `symptr` field (not the standard 32-bit COFF
   layout), which shifts section header parsing by 4 bytes and corrupts all
   section VAs and raw offsets.

3. **Exec-class functions are statically linked.** In OSF/1 Alpha executables
   libc is linked in; system/popen/execve appear in `.dynsym` as *exported*
   symbols, not imports. Existing import-based scan logic finds nothing.
   `AlphaEcoffScanner` locates each exported exec-class function via `GOT[N]`
   (dynsym entry N → GOT offset N×8) and scans for BSR call sites directly.

---

## How it works

```
Parse ECOFF headers  →  locate .dynsym / .dynstr / .got / .text
       ↓
Elf64_Sym scan (24-byte entries) — match exec-class symbol names
       ↓
Read GOT[N] for each match  →  callee VA within .text
       ↓
BSR sweep over .text  →  filter by target VA ∈ exec-class set
       ↓
AlphaExecFinding per confirmed call site
```

**Key design decisions:**

- **24-byte Elf64_Sym** for `.dynsym` entries (not the 16-byte Elf32_Sym).
  Verified by `.hash` nchain = 3103 and `.dynsym.size` = 0x122f0 = 3103 × 24.
- **GOT[N] = dynsym[N]** index mapping confirmed on OSF/1 3.11-4 dxexec.
  The GOT entry at byte offset `N × 8` from the GOT section start holds the
  function's actual VA in `.text` for exported symbols.
- **BSR scan only** (opcode 0x34). Internal callers in OSF/1 Alpha executables
  use direct BSR (PC-relative, ±4MB). JSR-through-GOT is not emitted for
  internal calls in the Alpha ABI.
- **24-byte FILHDR** with 8-byte `symptr` at offset 8. Section headers at byte
  `_FILHDR_SIZE + opthdr_size` = 24 + 80 = 104 for a standard ZMAGIC executable.
  Each section header is 64 bytes with 64-bit paddr/vaddr/size.

---

## AlphaEcoffScanner

```python
from ablation.analyzers.insn_alpha import AlphaEcoffScanner
```

**Constructor:**

```python
AlphaEcoffScanner(binary_path: str, ctx=None)
```

**Class methods:**

```python
AlphaEcoffScanner.from_context(ctx)   # ctx.path used; ctx otherwise ignored
AlphaEcoffScanner.from_path(path)     # direct path construction
```

**Instance methods:**

| Method | Returns | Notes |
|:---|:---|:---|
| `scan()` | `List[AlphaExecFinding]` | Full scan; reads binary once |
| `scan_summary()` | `Dict[str, int]` | `{sink_name: count}` — quick triage |
| `report(findings)` | `str` | Human-readable text output |

---

## Usage

```python
from ablation.analyzers.insn_alpha import AlphaEcoffScanner

# Minimal
scanner = AlphaEcoffScanner('/path/to/osf1-alpha-binary')
findings = scanner.scan()
print(scanner.report(findings))

# Quick count
summary = scanner.scan_summary()
# {'system': 1, 'execve': 3, 'execlp': 1}

# From BinaryContext (path forwarded; ctx not used)
scanner = AlphaEcoffScanner.from_context(ctx)
```

---

## Example output

```
AlphaEcoffScanner: 5 exec-class call site(s)

  execlp [callee 0x0000000120321860]: 1 call site(s)
    BSR 0x000000012032180c
  execve [callee 0x000000012031f810]: 3 call site(s)
    BSR 0x000000012031e128
    BSR 0x000000012031ec2c
    BSR 0x000000012031fa5c
  system [callee 0x00000001202e9550]: 1 call site(s)
    BSR 0x000000012028d76c
```

---

## AlphaExecFinding fields

| Field | Content |
|:---|:---|
| `caller_va` | VA of the BSR instruction (call site) |
| `callee_va` | VA of the exec-class function implementation in `.text` |
| `sink_name` | Dynamic symbol name: `system`, `popen`, `execve`, … |
| `dynsym_idx` | Index in `.dynsym` for this exported symbol |

---

## False positives

**Exec-class function implementations calling each other** — `execl`, `execle`,
`execv`, `execlp` are typically thin wrappers that chain-call `execve`.
These show as `execve` callers at VAs adjacent to the exec-family block.
Filter by checking the distance between `caller_va` and `callee_va`: callers
within ~8KB of `callee_va` are almost always libc chain-calls, not application
code.

**popen with zero callers** — if `popen` is exported but has no BSR callers,
it is exported for other shared modules to call.  This is not a false positive;
it means popen is unused within the executable itself.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` — run first to confirm
`arch=x86_64, func_starts=0` (the Alpha ECOFF detection failure) before switching
to `AlphaEcoffScanner`.

**After this module:** `FindingRegistry.register()` for any CONFIRMED callers.
Manual `WindowAnalyzer.dump_text()` on `caller_va` ± 32 instructions to trace
argument construction (what is passed as the `cmd` argument to `system()`).

---

## See also

- [insn_sh4.md](insn_sh4.md): same architecture-gap pattern for SH4 binaries
- [length_underflow.md](length_underflow.md): template used for this module's structure
