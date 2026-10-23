# RelDynPc32Scanner

Scan the `.rel.dyn` section of i386 ELF shared objects for `R_386_PC32` relocations targeting exec-class or network-class sinks: covering the import mechanism that `BinaryContext` and `SinkArgClassifier` miss entirely on PIC i386 shared objects.

---

## Why this exists

1. **`BinaryContext` only reads `.rel.plt` for import extraction.** `BinaryContext._build_plt()` scans `.rel.plt` (type `R_386_JUMP_SLOT`) to populate the PLT map. Some i386 PIC shared objects use `R_386_PC32` direct-call fixups in `.rel.dyn` instead of PLT stubs. Those binaries report `plt=0` and `SAC` returns 0 results, not because the binary is safe, but because the import mechanism is different.

2. **The gap is a real source of missed findings.** Four IBM RSCT/CSM shared objects confirmed this: `libevfbpv.so` imports `system` via `R_386_PC32` at offset `0x3ac87e`; `liblinux.so` imports `fork` and `socket` the same way. All four returned SAC=0 before this module existed.

3. **The scanner works standalone on raw ELF bytes.** It parses ELF32 section headers and `.rel.dyn` using only `struct`, without LIEF or BinaryContext. This is intentional, it exists specifically to cover the case where normal BinaryContext import extraction fails.

---

## How it works

```
from_path('/path/to/libevfbpv.so')
         │
         ▼
    _parse_elf()
    ├── Verify ELF magic, ELFCLASS32 (e_class=1), ELFDATA2LSB (ei_data=1)
    ├── Read section header table (e_shoff, e_shentsize, e_shnum)
    ├── Locate section name string table (e_shstrndx)
    └── Walk section headers:
        ├── SHT_REL (type=9) named ".rel.dyn" → record (offset, size)
        ├── SHT_DYNSYM (type=11) → record (offset, entsize, count)
        └── SHT_STRTAB (type=3) named ".dynstr" → record (offset, size)
         │
         ▼
    scan()
    ├── Iterate .rel.dyn entries (8 bytes each: r_offset, r_info)
    ├── r_type = r_info & 0xFF → skip if ≠ R_386_PC32 (2)
    ├── r_sym  = r_info >> 8  → look up in .dynsym
    ├── Strip @GLIBC versioning suffix from symbol name
    └── Check against EXEC_SINKS / NET_SINKS sets
        └── → Pc32Hit(r_offset, sym_name, family, load_bias)
```

The `.rel.dyn` format for i386 is the simplest possible relocation record: 4 bytes for the offset where the fixup is applied, 4 bytes encoding both the symbol index (top 24 bits) and the relocation type (low 8 bits). No addend.

---

## Usage

```python
from ablation.analyzers.rel_dyn_pc32_scanner import RelDynPc32Scanner

scanner = RelDynPc32Scanner.from_path('/path/to/libevfbpv.so')
hits = scanner.scan()
print(scanner.report(hits))

# Filter and hand off to manual trace
exec_hits = [h for h in hits if h.family == 'EXEC']
for h in exec_hits:
    print(f'{h.sym_name} call site VA: 0x{h.call_va:x}')
```

**Typical output on libevfbpv.so:**
```
RelDynPc32Scanner: /path/to/libevfbpv.so
  3 R_386_PC32 hits: 2 EXEC, 1 NET
  EXEC sinks:
    [EXEC] system via R_386_PC32 at offset 0x3ac87e (call VA 0x3ac87e)
    [EXEC] popen via R_386_PC32 at offset 0x3b1042 (call VA 0x3b1042)
  NET sinks:
    [NET] socket via R_386_PC32 at offset 0x3a9c10 (call VA 0x3a9c10)
```

**Integration with SAC pipeline:**
```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.rel_dyn_pc32_scanner import RelDynPc32Scanner
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier

ctx = BinaryContext.load_or_build('/path/to/libevfbpv.so')

# Check for the R_386_PC32 gap first
scanner = RelDynPc32Scanner.from_context(ctx)
hits = scanner.scan()
if hits:
    print(scanner.report(hits))
    # For EXEC hits: trace arg at call_va manually with WindowAnalyzer
    # or patch into SAC pipeline by adding call_va as a known sink site

# SAC handles PLT-based imports
sac = SinkArgClassifier.from_context(ctx)
sac_results = sac.classify_all()
```

---

## Hit fields

| Field | Type | Content |
|:---|:---|:---|
| `r_offset` | `int` | File offset of the relocation (= call site offset for `.text` R_386_PC32) |
| `sym_name` | `str` | Symbol name with `@GLIBC` version suffix stripped |
| `family` | `str` | `'EXEC'` or `'NET'` |
| `load_bias` | `int` | Added to `r_offset` to produce `call_va`; 0 for shared objects |
| `call_va` | property `int` | `r_offset + load_bias` |

---

## Sink families

| Family | Functions covered |
|:---|:---|
| EXEC | `system`, `popen`, `fork`, `vfork`, `execve`, `execvp`, `execl`, `execle`, `execvpe`, `execveat`, `posix_spawn`, `posix_spawnp` |
| NET | `socket`, `bind`, `listen`, `accept`, `accept4`, `connect`, `recv`, `recvfrom`, `recvmsg`, `send`, `sendto`, `sendmsg`, `gethostbyname`, `getaddrinfo` |

---

## Limitations

**Only LE i386 is supported.** `_parse_elf()` returns False on `EI_DATA=2` (big-endian) or ELFCLASS64. The scanner returns an empty hit list silently, it does not raise. Always verify the binary is i386 LE before assuming a 0-hit result means the binary is clean.

**`exec_names` and `net_names` properties re-scan.** Both properties call `scan()` independently. If you access both in sequence the relocation table is walked twice. Call `scan()` once and filter the returned list instead.

**Only `R_386_PC32` (type 2) is covered.** Other i386 relocation types (`R_386_GOT32X`, `R_386_PLT32`) that could also represent import calls are not matched.

---

## Pipeline position

**Before:** Check that `ctx.plt` is empty or unexpectedly sparse. Run this scanner when `SinkArgClassifier.from_context(ctx).classify_all()` returns 0 results on an i386 shared object that visibly links against libc.

**After:** For each EXEC hit, trace the call site with `WindowAnalyzer.dump_text(call_va)` or `SinkArgClassifier` manual override to classify the argument at that specific call VA.

---

## See also

- [Sink Arg Classifier](sink-arg-classifier.md): primary SAC for PLT-based imports
- [Window Analyzer](window-analyzer.md): disassemble the call site returned by `call_va`
- [StaticLinkSinkScanner](static-link-sink-scanner.md): for statically linked binaries with no PLT at all
