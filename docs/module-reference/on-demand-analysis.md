# On-Demand Analysis

Ablation analyzes only the code being examined. The first run on any binary takes 0.5 to 5 seconds to build an index. Every subsequent session reloads that index in under 200 milliseconds. Ghidra and IDA Pro parse the entire file upfront and block for minutes before any analysis can begin.

---

## Why this exists

Two things were not possible before BinaryContext:

**1. Sub-second analysis startup on large binaries.**
IDA Pro's autoanalysis on a 50 MB firmware binary runs for 5 to 20 minutes before the UI is interactive. Ghidra's analysis pipeline is similar. Every session restart pays that cost again. BinaryContext builds a lightweight index once, serializes it to JSON keyed on the binary's SHA-256 hash, and reloads in under 200 ms from cache. The second session on any binary is instant. The cache is stale the moment any byte in the binary changes, so analysis always reflects the current file.

**2. Caller/callee/string queries without a running GUI.**
Getting "which functions call `strcpy`?" in IDA requires the GUI to be open and fully indexed. BinaryContext answers `ctx.callers_of('strcpy')` from the command line, in a script, or inside a taint tracker — with no GUI dependency and no license requirement.

---

## How it works

### Build phase (runs once per binary)

```
  ELF / PE / Mach-O binary
          |
          v
  ┌────────────────────────────────────────────────────────────┐
  │  lief.parse(binary)                                        │
  │                                                            │
  │  PLT entries:                                              │
  │    ELF:  .plt section + .rela.plt relocations             │
  │          → {stub_VA: import_name} for all imports         │
  │    PE:   IAT entries + import table                        │
  │          → {thunk_VA: 'module!function'} for all imports  │
  │                                                            │
  │  Exported symbols:                                         │
  │    ELF:  .dynsym + .symtab FUNC entries                   │
  │    PE:   export directory → {name: VA} for all exports    │
  │                                                            │
  │  .rodata strings:                                          │
  │    scan all readable non-executable sections               │
  │    keep printable runs of >= 4 chars                       │
  │    → {string_VA: content} for all matching strings         │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              v
  ┌────────────────────────────────────────────────────────────┐
  │  Function start recovery (two-pass)                        │
  │                                                            │
  │  Pass 1 — unwind tables:                                   │
  │    ELF:  .eh_frame FDE records → entry VAs                 │
  │          .ARM.exidx → ARM32 function starts                │
  │    PE:   .pdata RUNTIME_FUNCTION → x64 function starts     │
  │                                                            │
  │  Pass 2 — callee augmentation:                             │
  │    for every call target in the disassembly:               │
  │      if target_VA not in func_starts: add it               │
  │    catches functions missing from unwind tables            │
  │    (common in stripped hand-written assembly)              │
  │                                                            │
  │  result: sorted list of function entry VAs                 │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              v
  ┌────────────────────────────────────────────────────────────┐
  │  Call graph construction                                   │
  │                                                            │
  │  for each function entry VA:                               │
  │    Capstone linear disassembly from entry to next entry    │
  │    extract all CALL / BL / BLR / JAL / BALC targets        │
  │    → call_edges: [(from_va, to_va, label)]                 │
  │                                                            │
  │  label = import_name if to_va in plt else hex(to_va)       │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              v
  ┌────────────────────────────────────────────────────────────┐
  │  Serialization                                             │
  │                                                            │
  │  cache key: SHA-256 of entire binary file                  │
  │  cache path: ~/.ablation/cache/<sha256[:16]>_<basename>.json │
  │                                                            │
  │  JSON schema:                                              │
  │    {                                                       │
  │      "plt":        {VA: name, ...},                        │
  │      "exports":    {name: VA, ...},                        │
  │      "strings":    {VA: content, ...},                     │
  │      "func_starts": [VA, VA, ...],                         │
  │      "call_edges":  [[from, to, label], ...]               │
  │    }                                                       │
  └────────────────────────────────────────────────────────────┘
```

### Reload phase (every subsequent session)

```
  BinaryContext.load_or_build(path)
          |
          +-- compute SHA-256 of binary
          |
          +-- cache file exists AND sha256 matches?
          |     YES → load JSON directly: < 200ms
          |     NO  → run build phase: 0.5 to 5s, write cache
```

The SHA-256 key means stale caches are impossible: any change to the binary produces a different hash and triggers a rebuild. The cache file name embeds the first 16 hex digits of the hash so multiple versions of the same binary can coexist in the cache directory without collision.

### What is indexed

| Attribute | Content | Example query |
|---|---|---|
| `ctx.plt` | `{VA: import_name}` for all PLT stubs | `ctx.plt[0x3000]` → `'strcpy'` |
| `ctx.exports` | `{name: VA}` for exported symbols | `ctx.exports['init_handler']` → `0x4000` |
| `ctx.strings` | `{VA: content}` for .rodata printables | `ctx.strings_near(0x4137f, radius=64)` |
| `ctx.func_starts` | sorted list of function entry VAs | `len(ctx.func_starts)` → `19432` |
| `ctx.call_edges` | `[(from_va, to_va, label)]` flat call graph | callers / callees queries |

### Name overlay

`ctx.name(va)` returns a human-readable name for any VA. It draws from three sources in priority order:

```
  Priority 1: NameRegistry (confirmed names from prior sessions)
              set via ctx.set_name(va, name, source='confirmed')

  Priority 2: exports dict (ELF/PE symbol table)
              always present in non-stripped binaries

  Priority 3: PLT dict (import names for PLT stub VAs)
              always present if the binary has dynamic imports

  Priority 4: hex fallback
              "0x{va:x}" — used for stripped internal functions
```

`ctx.set_name(va, name, source='confirmed')` writes into the NameRegistry (a separate SQLite table at `~/.ablation/names.db`) so confirmed function names persist across sessions. Every function name confirmed in any engagement on this binary reappears automatically in future sessions, building up a progressive symbol table independent of the binary's own symbol section.

### callers_of and callees_of

Both methods walk `ctx.call_edges` in memory. The call graph is flat: a list of `(from_va, to_va, label)` triples. `callers_of` filters for rows where `to_va` matches (or where `label` matches an import name string). `callees_of` filters for rows where `from_va` matches.

```
  ctx.callers_of('strcpy')
    → [(va, label), ...] for every call site that calls the strcpy PLT stub

  ctx.callees_of(0x4000)
    → [(va, label), ...] for every function called from the function at 0x4000
```

Both return `(va, label)` pairs where `va` is the call site address and `label` is the callee name (import name if resolved, hex otherwise).

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext

# First run: builds and caches (0.5-5s)
ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())

# All callers of strcpy
for (va, label) in ctx.callers_of('strcpy'):
    print(f"  0x{va:x}  {label}")

# All callees of a function at 0x4000
for (va, label) in ctx.callees_of(0x4000):
    print(f"  -> 0x{va:x}  {label}")

# Strings referenced near a VA
for (sva, content) in ctx.strings_near(0x4137f, radius=64):
    print(f"  0x{sva:x}  {content!r}")

# Name a confirmed function
ctx.set_name(0x4000, 'parse_radius_packet', source='confirmed')
print(ctx.name(0x4000))   # -> 'parse_radius_packet'
```

---

## Comparison with commercial tools

```
                  IDA Pro / Ghidra         BinaryContext
  ─────────────────────────────────────────────────────────────
  Startup time    5-20 min (autoanalysis)  0.5s first / <200ms cached
  GUI required    Yes (for scripting)      No — Python API only
  License         $$$                      Open source
  Architectures   Good x86/ARM coverage    14 arch taint trackers
  Decompiler      Hex-Rays / Ghidra IR     Structural pseudo-C (BinaryLifter)
  Cross-session   Project file             JSON cache + NameRegistry
  Call graph      Full (with analysis)     PLT-resolved (no decompiler needed)
```

BinaryContext does not replace a full decompiler for deep manual RE. It covers the analysis surface needed for automated vulnerability scanning: PLT imports, exported functions, string xrefs, and the call graph. That surface is enough for taint analysis, semantic search, and pattern matching — the three tools that find most vulnerabilities in stripped firmware without human-in-the-loop disassembly.
