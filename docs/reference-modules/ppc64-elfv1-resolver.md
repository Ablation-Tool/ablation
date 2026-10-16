# Ppc64ElfV1Resolver

## Why this exists

3 gaps that blocked analysis of any PPC64 big-endian ELFv1 binary (IBM POWER Linux, LoadLeveler):

1. **BinaryContext.plt is empty for PPC64 BE binaries.** `BinaryContext._extract_plt` checks for `ELFDATA2LSB` and calls the ELFv2 path; big-endian PPC64 falls through to a generic JUMP_SLOT loop that maps GOT slot VAs, not stub VAs. `SinkArgClassifier` needs stub VA → symbol_name; the generic path produces the wrong keys. Result: `plt_entries=0` on every IBM Linux POWER binary.

2. **ctx.func_starts contains OPD entry VAs, not code VAs.** On ELFv1, `nm`/`readelf` report symbol values as the address of the 24-byte OPD descriptor (`code_ptr, TOC_ptr, env_ptr`), not the code address. Disassembling at an OPD VA produces 8 bytes of a pointer, not a function prologue. Every symbol VA must be resolved through the OPD table before disassembling.

3. **BL target decoding on PPC64 requires a sign-extended 24-bit LI.** BL word layout: `opcode(6) | LI(24) | AA(1) | LK(1)`. LI is the number of *words* (not bytes) from the instruction. Correct formula: `li24 = (word>>2)&0xFFFFFF; if li24&0x800000: li24-=0x1000000; target=src_va+li24*4`. Several off-by-one errors arise if the shift/sign-extension is applied to the wrong field width.

---

## What it does

`Ppc64ElfV1Resolver` parses a PPC64 big-endian ELFv1 binary and resolves all three gaps in a single `resolve()` call:

- Parses `.opd` → `opd_to_code` dict (OPD entry VA → code VA)
- Parses `.rela.plt` JMP_SLOT relocations → glink stub map (`stub_N = text_va + N*28`, sorted by GOT VA) → name
- Exposes `bl_target()` for correct big-endian BL decoding
- `patch_context(ctx)` rewrites `ctx.plt` and `ctx.func_starts` in-place so all downstream tools work correctly

---

## Architecture notes

**OPD section (ELFv1 only):** Each OPD entry is 24 bytes, `(code_va, TOC_ptr, env_ptr)`. `nm`/`readelf -s` report the OPD entry VA as the function address; the actual executable code is at `code_va`. OPD entries are fixed-size, so `opd_to_code[sym_va] = struct.unpack_from('>Q', opd_data, sym_va - opd_base)[0]`.

**Glink stubs (ELFv1):** 28 bytes each (ELFv1; ELFv2 uses 16). Stubs are at `.text` start: `stub_N = text_va + N*28`. Stub index N corresponds to the Nth entry in `.rela.plt` sorted by GOT slot VA (ascending). The relocation type `R_PPC64_JMP_SLOT = 21` identifies PLT entries.

**BL encoding:** `word = struct.unpack_from('>I', data, offset)[0]`. `li24 = (word >> 2) & 0xFFFFFF`. Sign-extend: `if li24 & 0x800000: li24 -= 0x1000000`. Target: `src_va + li24 * 4`.

---

## Usage

```python
from ablation.analyzers.ppc64_elfv1_resolver import Ppc64ElfV1Resolver

res = Ppc64ElfV1Resolver.from_path('/path/to/ppc64be.elf')
info = res.resolve()

# Stub map: stub VA -> import name
print(info.stub_map)            # {0x10005874: 'sprintf', ...}
print(info.n_stubs)             # e.g. 76
print(f"TOC=0x{info.toc:x}")   # module TOC pointer

# OPD resolution
code_va = info.opd_to_code.get(sym_va)   # OPD entry VA -> code VA
code_va = info.code_va_for(sym_va)       # same, returns None if not found

# BL target decoding
data = open('/path/to/bin', 'rb').read()
target = info.bl_target(src_va, data)    # returns None if not a BL

# Find all callers of an imported symbol (by stub VA)
callers = res.find_bl_callers(stub_va=0x10005874)  # -> [0x1000a200, ...]

# Find callers of ALL imported symbols at once
all_callers = res.find_all_bl_callers()  # -> {'sprintf': [...], 'strcpyx': [...], ...}

# Patch BinaryContext so plt and func_starts are correct
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/ppc64be.elf')
res.patch_context(ctx)
# ctx.plt now: stub_VA -> name (not GOT slot VA)
# ctx.func_starts now: code VAs (not OPD entry VAs)
```

### Via BinaryContext

```python
res = Ppc64ElfV1Resolver.from_context(ctx)
info = res.resolve()
res.patch_context(ctx)
```

### Detection

```python
Ppc64ElfV1Resolver.is_ppc64_elfv1('/path/to/bin')  # -> bool
```

---

## Key fields of `Ppc64ElfV1Info`

| Field | Type | Description |
|---|---|---|
| `opd_va` | `int` | VA of `.opd` section |
| `opd_file_off` | `int` | File offset of `.opd` |
| `opd_size` | `int` | Size of `.opd` in bytes |
| `toc` | `int` | Module TOC pointer (from first OPD entry's TOC field) |
| `text_va` | `int` | VA of `.text` (glink stubs start here) |
| `opd_to_code` | `Dict[int, int]` | OPD entry VA → code VA |
| `opd_to_toc` | `Dict[int, int]` | OPD entry VA → TOC pointer |
| `stub_map` | `Dict[int, str]` | Glink stub VA → import name |
| `jmp_slots` | `List[Tuple[int, str]]` | (GOT VA, name) pairs sorted by GOT VA |
| `n_stubs` | `int` | Number of glink stubs |

---

## When to use

- Any binary identified as `ELF 64-bit MSB PowerPC64` (big-endian). IBM LoadLeveler, IBM GPFS, AIX POWER Linux binaries.
- Before running `SinkArgClassifier`, `TaintTracker`, or `FuncProfiler` on a PPC64 BE binary: call `res.patch_context(ctx)` first.
- When `BinaryContext.summary()` shows `plt_entries: 0` on a PPC64 BE binary: that is this gap.
- When disassembly at a symbol VA produces garbage (8 bytes of a pointer): the VA is an OPD entry, not code.
