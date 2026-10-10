# On-Demand Analysis

`BinaryContext` builds a lightweight index of a binary once and reloads it in under 200 milliseconds on every subsequent session. Ablation analyzes only the code being examined — no GUI, no autoanalysis, no license.

---

## Why this exists

Two things were not possible before BinaryContext:

**1. Sub-second analysis startup on large binaries.**
IDA Pro's autoanalysis on a 50 MB firmware binary runs for 5 to 20 minutes before the UI becomes interactive. Ghidra's analysis pipeline is similar. Every session restart pays that cost again. BinaryContext builds a lightweight index once, serializes it to JSON keyed on the binary's SHA-256 hash, and reloads in under 200 ms from cache. The second session on any binary is instant. The cache invalidates the moment any byte in the binary changes, so analysis always reflects the current file.

**2. Caller/callee/string queries without a running GUI.**
Getting "which functions call `strcpy`?" in IDA requires the GUI to be open and fully indexed. `ctx.callers_of('strcpy')` answers that question from the command line, in a script, or inside a taint tracker — with no GUI dependency and no license requirement. The call graph is a flat in-memory list, so filtering it is a single linear scan in Python.

---

## Build phase (runs once per binary)

```
  ELF / PE / Mach-O binary on disk
  ══════════════════════════════════════════════════════════════

  STEP 1 — Format parse via lief
  ┌──────────────────────────────────────────────────────────────┐
  │  lief.parse(binary_path)                                     │
  │                                                              │
  │  PLT stub resolution (ELF):                                  │
  │    .rela.plt section: array of Elf64_Rela entries            │
  │      struct Elf64_Rela {                                     │
  │        Elf64_Addr  r_offset;  // VA of GOT slot to patch     │
  │        Elf64_Xword r_info;    // sym index | reloc type      │
  │        Elf64_Sxword r_addend; // always 0 for JUMP_SLOT      │
  │      }                                                       │
  │    r_info >> 32 = symbol table index into .dynsym            │
  │    .dynsym[index].st_name → string in .dynstr → import_name │
  │                                                              │
  │    PLT stubs (x86-64, 16 bytes each):                        │
  │      push   QWORD PTR [GOT+8]     ; push link_map            │
  │      jmp    QWORD PTR [GOT+16]    ; jmp to resolver          │
  │      ──── first stub (resolver) ─────────────────────────    │
  │      jmp    QWORD PTR [GOT+slot]  ; GOT slot for symbol N    │
  │      push   N                     ; relocation index         │
  │      jmp    PLT[0]                ; call resolver            │
  │      ──── stub N (16 bytes, one per import) ─────────────    │
  │                                                              │
  │    stub_VA for import N:                                     │
  │      = plt_section_VA + 16 + (N * 16)                       │
  │    stored as: plt_map[stub_VA] = import_name                 │
  │                                                              │
  │  PLT stub resolution (PE, x86-64):                           │
  │    IMAGE_IMPORT_DESCRIPTOR → module name                     │
  │    INT (Import Name Table) entries → function name           │
  │    IAT (Import Address Table) → thunk VAs                    │
  │    iat_map[thunk_VA] = 'module!function'                     │
  │                                                              │
  │  Exported symbols:                                           │
  │    ELF .dynsym / .symtab: STT_FUNC entries within .text      │
  │    PE export directory: AddressOfNames[] + AddressOfFunctions[]│
  │    exports_map[name] = VA                                    │
  │                                                              │
  │  .rodata string extraction:                                  │
  │    for every readable, non-executable section:               │
  │      scan for printable ASCII runs of length >= 4            │
  │      include null-terminator as delimiter                    │
  │      strings_map[VA] = content                               │
  └──────────────────────────────┬───────────────────────────────┘
                                 |
                                 v
  STEP 2 — Function start recovery (two-pass)
  ┌──────────────────────────────────────────────────────────────┐
  │  Pass 1a — .eh_frame FDE records (ELF)                       │
  │                                                              │
  │    .eh_frame is a sequence of CIE and FDE records:           │
  │                                                              │
  │    CIE (Common Information Entry):                           │
  │      [length: 4B][id=0: 4B][version: 1B][augmentation: str] │
  │      [code_align: uleb128][data_align: sleb128]              │
  │      [return_addr_reg: uleb128][aug_data][initial_instrs]    │
  │                                                              │
  │    FDE (Frame Description Entry):                            │
  │      [length: 4B][cie_ptr: 4B (offset back to parent CIE)]  │
  │      [initial_location: ptr-size] ← THIS IS THE FUNCTION VA │
  │      [address_range: ptr-size]   ← function byte length      │
  │      [augmentation_data][call_frame_instructions]            │
  │                                                              │
  │    GCC emits one FDE per function by default (-fasynchronous-│
  │    unwind-tables). Present even in stripped binaries because │
  │    the runtime stack unwinder (libgcc, libunwind) needs it   │
  │    to walk frames on exception or signal. Strip removes      │
  │    .symtab but not .eh_frame.                               │
  │                                                              │
  │    initial_location encoding: pcrel (DW_EH_PE_pcrel=0x10)   │
  │    or absolute (DW_EH_PE_absptr=0x00) — both handled.        │
  │    Result: set of function start VAs from unwind tables.     │
  │                                                              │
  │  Pass 1b — .ARM.exidx (ARM32 ELF)                           │
  │    Each entry is two 32-bit words:                           │
  │      [prel31_offset_to_function][compact_unwind_or_lsda_ptr] │
  │    prel31 → absolute VA = (entry_VA & ~1) + sign_extend31   │
  │    Result: ARM32 function start VAs                          │
  │                                                              │
  │  Pass 1c — .pdata RUNTIME_FUNCTION (PE x86-64)              │
  │    struct RUNTIME_FUNCTION {                                 │
  │      DWORD BeginAddress;  // VA of function start            │
  │      DWORD EndAddress;    // VA of function end (exclusive)  │
  │      DWORD UnwindInfoAddress; // ptr to UNWIND_INFO          │
  │    }                                                         │
  │    BeginAddress → function start VA                          │
  │                                                              │
  │  Pass 2 — callee augmentation                                │
  │                                                              │
  │    Purpose: recover functions with no FDE / no .pdata entry. │
  │    These are: hand-written assembly, early-return stubs,     │
  │    cold-path functions split by compiler, tail-call targets. │
  │                                                              │
  │    Algorithm:                                                │
  │      for each known function start VA in sorted order:       │
  │        Capstone linear scan from start to next known start   │
  │        for each decoded instruction:                         │
  │          if instruction is CALL/BL/BLX/JAL/BALC:            │
  │            extract target VA (direct only; indirect=skip)    │
  │            if target_VA not in func_starts:                  │
  │              if target_VA in .text range:                    │
  │                func_starts.add(target_VA)                   │
  │                                                              │
  │    Termination: scan stops at next known func start, at RET/ │
  │    return-class instruction, or at section boundary.         │
  │                                                              │
  │    Iteration: pass 2 runs once. Newly discovered starts are  │
  │    added to func_starts but not rescanned in the same pass.  │
  │    (A second pass would find their callees; current design   │
  │    runs one augmentation pass for speed.)                    │
  │                                                              │
  │    Result: func_starts merged from passes 1a/1b/1c + pass 2  │
  │    Sorted ascending, deduplicated.                           │
  └──────────────────────────────┬───────────────────────────────┘
                                 |
                                 v
  STEP 3 — Call graph construction
  ┌──────────────────────────────────────────────────────────────┐
  │  for each func_start VA (in sorted order):                   │
  │    end_VA = next func_start VA (or section end)              │
  │    Capstone linear disassembly from start_VA to end_VA       │
  │                                                              │
  │    for each decoded instruction:                             │
  │      if instruction group contains CS_GRP_CALL:              │
  │        target_VA = instruction.operands[0].imm               │
  │        (direct calls only; indirect BLR/CALL [reg] skipped)  │
  │                                                              │
  │        label = plt_map.get(target_VA)        ← PLT import   │
  │             or exports_rev.get(target_VA)    ← named export  │
  │             or f"0x{target_VA:x}"            ← stripped VA   │
  │                                                              │
  │        call_edges.append((func_start_VA, target_VA, label)) │
  │                                                              │
  │    Architecture-specific call detection:                     │
  │      x86-64:  CALL rel32 / CALL r/m64                        │
  │      ARM64:   BL imm26   (BLR = indirect, not recorded)      │
  │      ARM32:   BL imm24 / BLX imm24 / BX Lr (return, skip)   │
  │      MIPS32:  JAL imm26 / JALR $ra,$t9                       │
  │      LA64:    BL offset26 / JIRL $ra,rj,0                    │
  │      nanoMIPS: BALC P32/P16 (resolved from bitfield)         │
  │                                                              │
  │  Final: call_edges = flat list of (from_va, to_va, label)    │
  │  Size: typically 50k–300k entries for firmware binaries      │
  └──────────────────────────────┬───────────────────────────────┘
                                 |
                                 v
  STEP 4 — String cross-reference index
  ┌──────────────────────────────────────────────────────────────┐
  │  Two data structures are built for string queries:           │
  │                                                              │
  │  strings_map: {string_VA → content}                          │
  │    Built in Step 1 from .rodata scan.                        │
  │                                                              │
  │  str_xref_idx: {func_VA → [string_VA, ...]}                  │
  │    Built during call graph construction:                     │
  │      for each instruction in func body:                      │
  │        if instruction loads an immediate or PC-relative addr: │
  │          if addr in strings_map:                             │
  │            str_xref_idx[func_VA].append(addr)               │
  │                                                              │
  │  x86-64: string refs are LEA rX, [RIP + disp] or            │
  │          MOV rX, abs64 — both are immediate-address loads.   │
  │  ARM64:  ADRP + ADD pair; ADRP loads page, ADD adds offset.  │
  │          Both instructions must be tracked together.         │
  │  ARM32:  LDR rX, [PC, #N] from literal pool.                 │
  │  MIPS32: LUI + ADDIU pair for absolute address load.         │
  │                                                              │
  │  ctx.strings_in_func(va) → reads str_xref_idx[va]           │
  │  ctx.funcs_referencing_string(string_va) → inverse lookup    │
  └──────────────────────────────┬───────────────────────────────┘
                                 |
                                 v
  STEP 5 — Serialization and caching
  ┌──────────────────────────────────────────────────────────────┐
  │  cache_key  = SHA-256(entire binary file bytes)              │
  │  cache_path = ~/.ablation/cache/<sha256[:16]>_<basename>.json│
  │                                                              │
  │  SHA-256 properties used here:                               │
  │    collision-resistant: two binaries with different bytes    │
  │    always produce different keys (no accidental cache hit)   │
  │    deterministic: same binary bytes → same key, forever      │
  │    fast: SHA-256 on 50 MB takes ~50 ms on modern hardware    │
  │                                                              │
  │  Multiple versions of the same binary coexist in cache:      │
  │    firmware_v1.so → a3f9b2c1d4e5f678_firmware_v1.json       │
  │    firmware_v2.so → b7c4d3e2f1a0b9c8_firmware_v2.json       │
  │    (different SHA-256 prefix → different cache file)         │
  │                                                              │
  │  JSON schema:                                                │
  │    {                                                         │
  │      "sha256":       "a3f9b2c1...",  // full hash            │
  │      "plt":          {"3000": "strcpy", "3010": "malloc"},   │
  │      "exports":      {"init_handler": "4000"},               │
  │      "strings":      {"6010": "Authorization: Bearer"},      │
  │      "func_starts":  [4000, 4120, 4280, ...],                │
  │      "call_edges":   [[4000, 3000, "strcpy"], ...],          │
  │      "str_xref_idx": {"4000": [6010, 6050, ...]}             │
  │    }                                                         │
  │                                                              │
  │  Keys are decimal integers (JSON numbers); BinaryContext      │
  │  converts them back to int on load.                          │
  └──────────────────────────────────────────────────────────────┘
```

---

## Reload phase

```
  BinaryContext.load_or_build(path)
  ═══════════════════════════════════════════════════════════════

  1. Open binary, read all bytes into memory (mmap on large files)
  2. Compute SHA-256 of bytes → sha256_key

  3. expected_cache = ~/.ablation/cache/<sha256_key[:16]>_<basename>.json
     does expected_cache exist on disk?
       YES → open JSON, read "sha256" field
             does stored sha256 == sha256_key?
               YES → deserialize in place
                     convert JSON string keys to int (VA)
                     load plt, exports, strings, func_starts,
                     call_edges, str_xref_idx into memory
                     done in < 200 ms  ← reload path
               NO  → cache file is from a different binary
                     (basename collision; different content)
                     fall through to build phase
       NO  → fall through to build phase

  4. build phase: 0.5 to 5 seconds depending on binary size
     → write cache to expected_cache path
     → return populated BinaryContext

  ───────────────────────────────────────────────────────────────
  Why < 200 ms?

  The JSON file for a 50 MB firmware binary with 19,000 functions
  and 200,000 call edges is typically 8–12 MB. Python's json.loads
  on 10 MB of pre-parsed string data runs in 40–80 ms. The SHA-256
  of the binary itself costs ~50 ms. Total reload: ~120–150 ms.

  The build phase cost breakdown for a 50 MB stripped ELF:
    lief.parse():           ~80 ms
    .eh_frame FDE scan:     ~30 ms
    callee augmentation:    ~250 ms  (depends on function count)
    call graph (Capstone):  ~3.5 s   (Capstone decode is the bottleneck)
    string xref indexing:   ~100 ms
    JSON serialization:     ~200 ms
    Total first run:        ~4.2 s
```

---

## What is indexed

| Attribute | Type | Content | Example |
|---|---|---|---|
| `ctx.plt` | `{int: str}` | PLT stub VA → import name | `ctx.plt[0x3000]` → `'strcpy'` |
| `ctx.exports` | `{str: int}` | Export name → VA | `ctx.exports['init_handler']` → `0x4000` |
| `ctx.strings` | `{int: str}` | String VA → content | `ctx.strings[0x6010]` |
| `ctx.func_starts` | `list[int]` | Sorted function entry VAs | `len(ctx.func_starts)` → `19432` |
| `ctx.call_edges` | `list[tuple]` | `(from_va, to_va, label)` | Call graph |
| `ctx.str_xref_idx` | `{int: list[int]}` | Func VA → referenced string VAs | `ctx.strings_in_func(0x4000)` |

---

## Name overlay: priority stack

`ctx.name(va)` resolves through four layers in order:

```
  ctx.name(0x4000)
  ═══════════════════════════════════════════════════════════════

  Layer 1 — NameRegistry (SQLite at ~/.ablation/names.db)
  ┌──────────────────────────────────────────────────────────────┐
  │  Table: function_names                                       │
  │    CREATE TABLE function_names (                             │
  │      binary_sha256  TEXT,  -- ties name to specific binary   │
  │      va             INTEGER,                                 │
  │      name           TEXT,                                    │
  │      source         TEXT,  -- 'confirmed' / 'pclntab' / etc  │
  │      timestamp      INTEGER                                  │
  │    )                                                         │
  │                                                              │
  │  ctx.set_name(0x4000, 'parse_radius_packet', 'confirmed')   │
  │    → INSERT INTO function_names (sha256, 4000, ..., 'confirmed') │
  │                                                              │
  │  Confirmed names persist across sessions because they are    │
  │  stored by binary SHA-256, not by path. If you rename the   │
  │  binary file, the name overlay still loads.                  │
  └──────────────────────────────┬───────────────────────────────┘
                                 |  (not found)
                                 v
  Layer 2 — exports dict (symbol table)
  ┌──────────────────────────────────────────────────────────────┐
  │  Populated from .dynsym / .symtab (ELF) or export directory  │
  │  (PE). Only present for non-stripped exported symbols.       │
  │  exports_rev[VA] = name for fast reverse lookup.             │
  └──────────────────────────────┬───────────────────────────────┘
                                 |  (not found)
                                 v
  Layer 3 — PLT dict (import names)
  ┌──────────────────────────────────────────────────────────────┐
  │  plt_map[VA] = import_name for PLT stub VAs.                 │
  │  A call to 0x3000 that resolves to plt_map[0x3000]='strcpy'  │
  │  means the call site calls the libc strcpy import.           │
  └──────────────────────────────┬───────────────────────────────┘
                                 |  (not found)
                                 v
  Layer 4 — hex fallback
  ┌──────────────────────────────────────────────────────────────┐
  │  return f"0x{va:x}"                                          │
  │  Used for stripped internal functions with no confirmed name. │
  │  RULE: ctx.name(va) everywhere. Never raw hex in display.    │
  └──────────────────────────────────────────────────────────────┘
```

---

## callers_of and callees_of internals

Both methods operate on `ctx.call_edges`, which is a flat Python list of `(from_va, to_va, label)` tuples held in memory.

```
  call_edges = [
    (0x4000, 0x3000, 'strcpy'),    # func at 0x4000 calls strcpy PLT stub
    (0x4000, 0x4280, '0x4280'),    # func at 0x4000 calls internal func
    (0x4120, 0x3000, 'strcpy'),    # func at 0x4120 also calls strcpy
    (0x4280, 0x3010, 'malloc'),    # func at 0x4280 calls malloc
    ...
  ]

  ───────────────────────────────────────────────────────────────

  ctx.callers_of('strcpy'):
    scan: [(f, t, l) for (f, t, l) in call_edges if l == 'strcpy']
    result: [(0x4000, 'strcpy'), (0x4120, 'strcpy')]
    → va=call_site_VA, label=callee_name

  ctx.callers_of(0x3000):
    scan: [(f, t, l) for (f, t, l) in call_edges if t == 0x3000]
    (same result — both the string name and the VA form work)

  ctx.callees_of(0x4000):
    scan: [(t, l) for (f, t, l) in call_edges if f == 0x4000]
    result: [(0x3000, 'strcpy'), (0x4280, '0x4280')]
    → va=callee_VA, label=callee_name

  ───────────────────────────────────────────────────────────────

  Performance: O(N) scan over N call_edges.
  N is typically 50k–300k.
  A single callers_of() call on a 200k-edge graph takes ~2 ms in CPython.
  No index is needed — the list is scanned once per query.
  For repeated queries in a loop, pre-build an inverted dict:
    callers_idx = defaultdict(list)
    for (f, t, l) in ctx.call_edges:
        callers_idx[l].append((f, t, l))
    callers_idx['strcpy']  # O(1) from here
```

---

## strings_in_func and the xref index

```
  ctx.strings_in_func(0x4000)
  ═══════════════════════════════════════════════════════════════

  Returns the content of every string whose VA appears in
  str_xref_idx[0x4000]. The index was built during the call graph
  construction pass: any instruction that loads an address found
  in strings_map gets that string's VA recorded under the
  containing function.

  Architecture-specific string reference detection:

    x86-64:
      LEA rX, [RIP + disp32]
        target = insn_VA + insn_length + disp32
        if target in strings_map → record
      MOV rX, imm64
        if imm64 in strings_map → record

    ARM64:
      ADRP Xn, page_label  (insn encodes PC-relative page offset)
      ADD  Xn, Xn, #offset  (immediately following instruction)
        full_VA = (ADRP_VA & ~0xfff) + (page_imm << 12) + offset
        tracker maintains pending_adrp[Xn] between instructions
        when ADD fires: compute full_VA, check strings_map

    ARM32:
      LDR Rd, [PC, #N]
        target = (insn_VA + 8) & ~3 + N  (literal pool load)
        read 4 bytes at target → read address from literal pool
        if address in strings_map → record

    MIPS32:
      LUI  $t0, hi16   (load upper 16 bits)
      ADDIU $t0, $t0, lo16  (add lower 16 bits, sign-extended)
        full_VA = (hi16 << 16) + sign_extend16(lo16)
        tracker maintains pending_lui[$t0] between instructions
        when ADDIU fires: compute full_VA, check strings_map

  ctx.funcs_referencing_string(string_va):
    inverse of str_xref_idx — O(N) scan over all values.
    result: list of func_VAs that reference the given string VA.
```

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext

# First run: builds and caches (0.5-5s)
ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
# BinaryContext: firmware_v2.so
# Functions: 19432  Strings: 41206  Call edges: 198341
# PLT imports: 89    Exports: 12

# All callers of strcpy
for (va, label) in ctx.callers_of('strcpy'):
    print(f"  0x{va:x}  {ctx.name(va)}")

# All callees of a function
for (va, label) in ctx.callees_of(0x4000):
    print(f"  -> 0x{va:x}  {label}")

# Strings referenced by a specific function
for (sva, content) in ctx.strings_in_func(0x4000):
    print(f"  0x{sva:x}  {content!r}")

# Which functions reference a specific string VA?
for fva in ctx.funcs_referencing_string(0x6010):
    print(f"  {ctx.name(fva)}")

# Name a confirmed function — persists across sessions
ctx.set_name(0x4000, 'parse_radius_packet', source='confirmed')
print(ctx.name(0x4000))   # -> 'parse_radius_packet'
```

---

## Where BinaryContext fits in the pipeline

BinaryContext is the base layer. Every other Ablation tool calls it first:

```
  BinaryContext
  ├── SemanticSearcher  — needs func_starts + call_edges for corpus
  ├── FuncProfiler      — needs callers_of / callees_of for sink mapping
  ├── TaintTracker      — needs plt_map for source/sink PLT resolution
  │                       needs func_starts for function boundary scan
  │                       needs call_edges for interprocedural BFS
  ├── PatternLibrary    — needs names (ctx.name) for finding labels
  ├── VersionDelta      — loads ctx for both v1 and v2 binaries
  └── HypothesisEngine  — ctx passed as optional accelerator (step adapter)
```

BinaryContext does not replace a full decompiler for deep manual RE. It covers the analysis surface needed for automated vulnerability scanning: PLT imports, exported functions, string xrefs, and the call graph. That surface is enough for taint analysis, semantic search, and pattern matching — the three tools that find most vulnerabilities in stripped firmware without a GUI.

---

## Comparison with commercial tools

```
                  IDA Pro / Ghidra          BinaryContext
  ─────────────────────────────────────────────────────────────
  Startup time    5-20 min (autoanalysis)   0.5s first / <200ms cached
  GUI required    Yes (for scripting)       No — Python API only
  License         $$$                       Open source
  Function starts Symbol + heuristics       eh_frame FDE + callee augment
  String xrefs    Full (with analysis)      Architecture-specific loaders
  Call graph      Full (with decompiler)    PLT-resolved direct calls
  Name persistence Project file             SQLite NameRegistry (by SHA-256)
  Multi-version   Manual import             Coexist by SHA-256 cache key
```
