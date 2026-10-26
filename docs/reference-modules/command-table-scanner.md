# CommandTableScanner

Finds `(name_ptr, fn_ptr, ...)` dispatch-table structures in ELF data segments — the Q-shell command table pattern used by IBM Storage Defender Sentinel and similar server firmware.

---

## Why this exists

1. **SemanticSearcher cannot locate un-named dispatch tables.** A Q-shell jump table with 35 entries is invisible to text embedding search because the entries have no symbol names — they're arrays of pointers in `.data`.
2. **Manual segment walking is slow and error-prone.** The dispatch binary has a 177MB rodata segment and a 4.7MB data segment; hand-navigating pointer arrays at an unknown stride produces high false-positive rates.
3. **BinaryContext `callers_of()` requires PLT or symbol metadata.** For internal dispatch tables with no external symbol, there is nothing to call `callers_of()` against.

---

## How it works

1. Parse ELF64 program headers; classify PT_LOAD segments as text (PF_X), data (PF_W), or rodata (PF_R only). Fall back to section headers if no R-only segment exists.
2. For each data segment, scan 8-byte-aligned positions trying all 15 `(stride, fn_word_idx, name_word_idx)` layouts for strides 2, 3, 4.
3. An entry is valid when:
   - `fn_word` VA falls in a text range.
   - `name_word` VA falls in a rodata range and the bytes there are printable ASCII, null-terminated, ≤128 chars.
   - All other words in the entry are in text, rodata, or null.
4. Consecutive valid entries with the same layout and stride ≥ `_MIN_RUN = 3` form a `CommandTable`.
5. Inside a confirmed run, advance by `entry_size = stride × 8`; outside a run, slide by 8 bytes to catch mis-aligned starts.

---

## CommandTableScanner

```python
from ablation.analyzers.command_table_scanner import CommandTableScanner

scanner = CommandTableScanner.from_context(ctx)  # preferred — reuses loaded BinaryContext
# or
scanner = CommandTableScanner.from_path('/path/to/binary')

tables = scanner.scan()
print(CommandTableScanner.report(tables))
```

### Key dataclasses

```python
@dataclass
class CommandEntry:
    table_offset: int   # byte offset into the file where this entry starts
    entry_va:     int   # VA of the entry in the loaded binary
    name:         str   # null-terminated ASCII name string
    name_va:      int   # VA of the name string in rodata
    handler_va:   int   # VA of the handler function in text
    stride:       int   # words per entry (2, 3, or 4)

@dataclass
class CommandTable:
    start_va:     int
    start_offset: int
    stride:       int
    entries:      List[CommandEntry]
```

### Utility

```python
scanner._in_text(va)    # True if va is within any text range
scanner._in_rodata(va)  # True if va is within any rodata range
```

---

## Known-positive

IBM Storage Defender Sentinel 2.3.2 dispatch binary (183MB, 18584 funcs, non-PIE ET_EXEC):
- Q-shell table at VA `0xbadca80`, stride=3, 35 commands.
- Layout: `(help_ptr, name_ptr, fn_ptr)` — `fn_word_idx=2`, `name_word_idx=1`.
- Confirmed by `source` handler at `0xce6da0` (in text ✓).

---

## Pipeline position

```
BinaryContext.load_or_build()
    → SemanticSearcher.query()
    → CommandTableScanner.from_context(ctx).scan()   ← here (step 4.5)
    → FuncProfiler.profile() on handler_va results
    → SinkArgClassifier → [post-SAC filters] → TaintTracker
```

Run after `SemanticSearcher` (step 4.5) for any dispatch-table target: firmware with a Q-shell layer, IBM Sentinel, or any binary where SemanticSearcher returns few results despite a large function count. Pass `handler_va` values from each `CommandTable` entry directly to `FuncProfiler` and `SinkArgClassifier` as the taint entry points.

---

## Notes

- Only scans `_data_ranges` (PF_W segments). Rodata is used for pointer validation only, never scanned as a table source — this prevents false positives from the 177MB rodata segment in the dispatch binary.
- For non-PIE ET_EXEC (like dispatch), pointers are absolute 8-byte VAs. PIE `.so` files use the same absolute encoding after the loader applies relocations; pre-relocation scanning will produce zero results on position-dependent fields.
