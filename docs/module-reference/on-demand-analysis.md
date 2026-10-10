# On-Demand Analysis

Every session with a binary starts by loading `BinaryContext`. It builds a lightweight index of the binary once and reloads that index in under 200 milliseconds on every subsequent session. The cost of analyzing a new binary falls to a few seconds the first time and becomes nearly instant after that.

---

## Why this exists

### The startup time problem

IDA Pro's autoanalysis on a 50 MB firmware binary runs for 5 to 20 minutes before the UI is interactive. Ghidra's analysis pipeline is similar. Every session restart pays that full cost again. If you are iterating on a taint tracker or testing a new semantic query, that 10-minute wait becomes a serious obstacle to experimentation.

BinaryContext solves this by separating the expensive work from the repeatable work. The expensive part — parsing the binary, recovering function starts, building the call graph — runs once. The result is serialized to a JSON file keyed on the binary's SHA-256 hash. Every subsequent session deserializes that file directly. Python's JSON parser reads 10 MB of pre-parsed data in about 80 milliseconds. Add 50 milliseconds to compute the SHA-256, and the total reload time is roughly 130 milliseconds. The second session on any binary is instant.

The SHA-256 key ensures the cache never goes stale. Any change to the binary produces a different hash and triggers a full rebuild. This is a deliberately simple design. There is no version tag, no timestamp, no partial invalidation. The binary itself is the truth, and the hash is the gate.

### The GUI dependency problem

Getting "which functions call `strcpy`?" in IDA requires the GUI to be open and fully analyzed. That means a license seat, a running process, and the 10-minute wait. `ctx.callers_of('strcpy')` answers the same question from the command line, in a script, or inside a taint tracker. No GUI. No license. The call graph lives in memory as a flat Python list.

This matters most in automated pipelines. A taint tracker calling `callers_of` on 200 different sinks in sequence would be unusable against an IDA backend. Against an in-memory list, it runs in milliseconds.

---

## Build phase (runs once per binary)

The build phase has five steps. Understanding each step helps you understand what the index can and cannot tell you.

### Step 1 — Format parse and symbol extraction

The first step uses `lief` to parse the binary format and extract three symbol tables.

**PLT imports (ELF)**

The PLT (Procedure Linkage Table) is ELF's mechanism for lazy binding of shared library calls. When you compile C code that calls `strcpy`, the compiler generates a call to a PLT stub rather than the actual `strcpy` address. The PLT stub is a small trampoline: on the first call, it invokes the dynamic linker to resolve the symbol and patch the GOT entry. On subsequent calls, the GOT entry already holds the resolved address, so the stub jumps directly to it.

For reverse engineering, the PLT stub is the important artifact. The stub has a fixed VA in the binary. Every call to `strcpy` goes through the same stub VA. If you know that PLT stub at 0x3000 corresponds to `strcpy`, you can find every `strcpy` caller by scanning for calls to 0x3000.

The ELF linker records the PLT-to-symbol mapping in `.rela.plt`. Each entry is a `Elf64_Rela` struct:

```
  struct Elf64_Rela {
      Elf64_Addr   r_offset;   // VA of the GOT slot that will hold the resolved address
      Elf64_Xword  r_info;     // upper 32 bits: .dynsym index; lower 32 bits: reloc type
      Elf64_Sxword r_addend;   // always 0 for R_X86_64_JUMP_SLOT
  };

  To resolve a PLT entry:
    sym_index   = r_info >> 32
    sym_name    = dynsym[sym_index].st_name       // index into .dynstr
    import_name = .dynstr[sym_name]               // null-terminated string
    stub_va     = plt_section_va + 16 + (N * 16)  // N = entry position

  The first 16 bytes of .plt are the resolver stub (PLT[0]).
  Each subsequent import gets its own 16-byte stub:

  PLT stub layout (x86-64, 16 bytes):
  ┌──────────────────────────────────────────────────────────────┐
  │  offset  0: FF 25 XX XX XX XX   JMP  QWORD PTR [RIP + disp] │
  │                                 → jumps into GOT slot        │
  │  offset  6: 68 NN 00 00 00      PUSH N     (reloc index)     │
  │  offset 11: E9 XX XX XX XX      JMP  PLT[0] (resolver)       │
  │  (total: 16 bytes per import)                                │
  └──────────────────────────────────────────────────────────────┘

  After dynamic linking resolves the symbol, GOT[slot] holds the
  real function address. The JMP at offset 0 now jumps directly
  to the resolved function, bypassing the PUSH+JMP tail.
```

BinaryContext records `plt_map[stub_va] = import_name` for every PLT entry.

**PLT imports (PE/COFF)**

PE binaries use the IAT (Import Address Table) instead of a GOT. The mechanism is the same — a table of function pointers patched at load time — but the layout differs. BinaryContext reads the import directory's INT (Import Name Table) and IAT to build `iat_map[thunk_va] = 'module!function'`.

**Exported symbols and string extraction**

Exported symbols from `.dynsym`/`.symtab` (ELF) or the export directory (PE) populate `exports_map[name] = va`. The string extractor scans all readable, non-executable sections for printable ASCII runs of at least 4 characters and stores them in `strings_map[va] = content`.

```
  ┌──────────────────────────────────────────────────────────────┐
  │  STEP 1 — Format parse and symbol extraction                 │
  │                                                              │
  │  lief.parse(binary_path)                                     │
  │     │                                                        │
  │     ├── .rela.plt + .dynsym → plt_map  {stub_va: name}      │
  │     │   (ELF) or IAT + INT  → iat_map  {thunk_va: name}     │
  │     │                                                        │
  │     ├── .dynsym/.symtab (ELF) or export dir (PE)            │
  │     │          → exports_map  {name: va}                     │
  │     │                                                        │
  │     └── readable non-exec sections: scan for printable runs  │
  │                → strings_map  {va: content}                  │
  └──────────────────────────────────────────────────────────────┘
```

### Step 2 — Function start recovery

Recovering function starts in a stripped binary is a two-pass process. The first pass reads the binary's own unwind data. The second pass fills in the gaps.

**Why unwind tables contain function starts**

C++ exception handling and signal delivery both need to unwind the call stack. To unwind a frame, the runtime needs to know which function owns a given PC value and what that function does to the stack. Compilers solve this by emitting one Frame Description Entry (FDE) per function in `.eh_frame`. The FDE records the function's start VA and byte length, along with instructions for restoring the previous frame.

The critical insight for RE is that `strip(1)` cannot remove `.eh_frame`. The runtime linker reads it at program startup to register unwind information with the OS. Remove it and exception handling breaks. So in any binary compiled with GCC or Clang at default settings, `.eh_frame` contains the complete function start list, even when the symbol table is gone.

```
  .eh_frame record types:

  CIE (Common Information Entry) — one per compilation unit:
  ┌──────────────────────────────────────────────────────────────┐
  │  length         4 bytes  total CIE size minus length field   │
  │  CIE_id         4 bytes  always 0 (distinguishes CIE vs FDE) │
  │  version        1 byte   always 1 (DWARF 2) or 3 (DWARF 3)  │
  │  augmentation   string   "zR" common; encodes pointer format │
  │  code_align     uleb128  instruction size quantum (1 for x86)│
  │  data_align     sleb128  stack slot size factor (-8 for x64) │
  │  return_addr_reg uleb128 register number of return address   │
  │  aug_data       variable pointer encoding (pcrel, abs, etc.) │
  │  initial_insns  variable CFA baseline rules (push rbp, etc.) │
  └──────────────────────────────────────────────────────────────┘

  FDE (Frame Description Entry) — one per function:
  ┌──────────────────────────────────────────────────────────────┐
  │  length          4 bytes  total FDE size minus length field  │
  │  CIE_ptr         4 bytes  byte offset back to parent CIE     │
  │  initial_location ptr     ← FUNCTION START VA                │
  │  address_range   ptr      ← function byte length             │
  │  aug_data_len    uleb128  length of augmentation data        │
  │  aug_data        variable LSDA pointer for C++ (if any)      │
  │  call_frame_insns variable how to unwind registers per offset │
  └──────────────────────────────────────────────────────────────┘

  The initial_location encoding varies by CIE augmentation:
    DW_EH_PE_pcrel (0x10):  value = FDE_field_VA + encoded_value
    DW_EH_PE_absptr (0x00): value = encoded_value directly
  BinaryContext handles both encodings.
```

ARM32 binaries use `.ARM.exidx` instead of `.eh_frame`. Each entry is two 32-bit words. The first word encodes the function start as a prel31 offset: `abs_va = (entry_field_va & ~1) + sign_extend(value, 31)`. PE x86-64 binaries use `.pdata`, an array of `RUNTIME_FUNCTION` structs with `BeginAddress` fields pointing to function starts.

**Callee augmentation: recovering what unwind tables miss**

Unwind tables are comprehensive but not complete. Hand-written assembly functions, early-exit stubs, compiler-generated cold paths, and tail-call targets sometimes have no FDE. They do, however, get called from known functions. The callee augmentation pass recovers them.

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Callee augmentation algorithm                               │
  │                                                              │
  │  Input:  func_starts (from unwind tables, pass 1)           │
  │  Output: func_starts augmented with discovered callees       │
  │                                                              │
  │  for each known function start VA (sorted ascending):        │
  │    end_va = next known func start  (or section end)          │
  │    Capstone linear disassembly from start_va to end_va:      │
  │      for each decoded instruction:                           │
  │        if instruction.group has CS_GRP_CALL:                 │
  │          target_va = instruction.operands[0].imm             │
  │          (skip indirect calls: operands[0].type != IMM)      │
  │          if target_va in .text range:                        │
  │            if target_va not in func_starts:                  │
  │              func_starts.add(target_va)   ← new discovery   │
  │                                                              │
  │  Termination conditions (stop scanning current function):    │
  │    1. Reached end_va (next known function start)             │
  │    2. Encountered RET / RETN / BX LR / JR $ra               │
  │    3. Reached section boundary                               │
  │                                                              │
  │  One pass only. Newly discovered callees are not rescanned.  │
  │  A second pass would recover their callees too. The design   │
  │  accepts this limitation for build speed.                    │
  └──────────────────────────────────────────────────────────────┘
```

What callee augmentation recovers in practice: functions whose body starts with a `push rbp` that the compiler inserted without a corresponding unwind entry (common in `-fno-unwind-tables` builds), trampolines and wrappers called from multiple sites, and inline assembly blocks that the compiler treats as a separate function boundary.

After both passes, `func_starts` is a sorted, deduplicated list of all function entry VAs the index knows about.

### Step 3 — Call graph construction

With a function boundary list in hand, BinaryContext disassembles each function and extracts every direct call it makes. The result is a flat list of edges: `(caller_va, callee_va, label)`.

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Call graph construction                                     │
  │                                                              │
  │  for each func_start VA (in sorted order):                   │
  │    end_va = next func_start  (or section end)                │
  │    Capstone linear disassembly from start_va to end_va:      │
  │                                                              │
  │    for each decoded instruction:                             │
  │      if CS_GRP_CALL in instruction.groups:                   │
  │        if operands[0].type == CS_OP_IMM:    ← direct only   │
  │          target_va = operands[0].imm                         │
  │                                                              │
  │          label resolution (priority order):                  │
  │            plt_map.get(target_va)           ← PLT import    │
  │         or exports_rev.get(target_va)       ← named export  │
  │         or f"0x{target_va:x}"               ← stripped VA   │
  │                                                              │
  │          call_edges.append(                                  │
  │            (func_start_va, target_va, label)                 │
  │          )                                                   │
  │                                                              │
  │  Architecture-specific call instructions detected:           │
  │    x86-64:  CALL rel32 / CALL r/m64                          │
  │    ARM64:   BL imm26   (BLR = indirect, label skipped)       │
  │    ARM32:   BL imm24 / BLX imm24                             │
  │    MIPS32:  JAL imm26 / JALR $ra,$t9                         │
  │    LA64:    BL offset26 / JIRL $ra,rj,0                      │
  │    nanoMIPS: BALC P32/P16 (resolved from bitfield)           │
  │                                                              │
  │  Indirect calls (BLR, CALL [rax], JALR $t9) are skipped.    │
  │  The callee address is not known statically without CFG      │
  │  analysis. VtableResolver handles C++ virtual dispatch.      │
  └──────────────────────────────────────────────────────────────┘
```

The final `call_edges` list for a large firmware binary typically holds 50,000 to 300,000 entries. It is loaded entirely into memory. There is no index structure because a linear scan over 200,000 entries takes about 2 milliseconds in CPython, which is fast enough for every query pattern Ablation uses.

### Step 4 — String cross-reference index

Strings in `.rodata` are inert until something loads their address. The cross-reference index connects function bodies to the strings they reference. This is what makes `ctx.strings_in_func(va)` possible without re-disassembling on every call.

The architecture-specific challenge is that "loading a string address" looks different on every ISA. On x86-64, the compiler emits `LEA rX, [RIP + disp32]` because the binary is position-independent and the displacement is relative to the next instruction's PC. On ARM64, the same operation takes two instructions: `ADRP Xn, page_label` loads the page address of the target, and `ADD Xn, Xn, #offset` adds the within-page offset to get the final address. The indexer must track these two-instruction sequences across instruction boundaries.

```
  ┌──────────────────────────────────────────────────────────────┐
  │  String cross-reference indexer                              │
  │                                                              │
  │  Two data structures:                                        │
  │    strings_map:    {string_va → content}   (from Step 1)    │
  │    str_xref_idx:   {func_va → [string_va, ...]}  (built now) │
  │                                                              │
  │  Built during call graph construction — same Capstone pass.  │
  │  For each instruction in each function body:                 │
  │                                                              │
  │  x86-64: RIP-relative load                                   │
  │    LEA rX, [RIP + disp32]                                    │
  │      target = insn_va + insn_length + sign_extend32(disp)    │
  │      if target in strings_map → record(func_va, target)      │
  │    MOV rX, imm64                                             │
  │      if imm64 in strings_map → record(func_va, imm64)        │
  │                                                              │
  │  ARM64: two-instruction ADRP+ADD pair                        │
  │    ADRP Xn, label                                            │
  │      page_va = (insn_va & ~0xFFF) + (imm21 << 12)           │
  │      pending_adrp[Xn] = page_va   ← held until next insn     │
  │    ADD Xn, Xn, #offset  (immediately follows ADRP)           │
  │      if Xn in pending_adrp:                                  │
  │        full_va = pending_adrp[Xn] + offset                   │
  │        if full_va in strings_map → record(func_va, full_va)  │
  │        del pending_adrp[Xn]                                  │
  │                                                              │
  │  ARM32: literal pool load                                     │
  │    LDR Rd, [PC, #N]                                          │
  │      pool_va = (insn_va + 8) & ~3 + N                        │
  │      addr = read_u32(binary, pool_va - load_addr)            │
  │      if addr in strings_map → record(func_va, addr)          │
  │                                                              │
  │  MIPS32: LUI+ADDIU pair                                      │
  │    LUI $t0, hi16                                             │
  │      pending_lui[$t0] = hi16 << 16  ← held until ADDIU      │
  │    ADDIU $t0, $t0, lo16                                       │
  │      if $t0 in pending_lui:                                   │
  │        full_va = pending_lui[$t0] + sign_extend16(lo16)      │
  │        if full_va in strings_map → record(func_va, full_va)  │
  │        del pending_lui[$t0]                                   │
  └──────────────────────────────────────────────────────────────┘
```

`ctx.funcs_referencing_string(string_va)` is the inverse: it scans `str_xref_idx.values()` for the given string VA. This answers "which functions reference this error message?" across the entire binary in one pass.

### Step 5 — Serialization and the cache key

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Cache key construction                                      │
  │                                                              │
  │  sha256_key  = SHA-256(entire binary file, all bytes)        │
  │  cache_path  = ~/.ablation/cache/<sha256_key[:16]>_<name>.json│
  │                                                              │
  │  Two builds of the same firmware with different content:     │
  │    firmware_v1.so → a3f9b2c1d4e5f678_firmware_v1.json       │
  │    firmware_v2.so → b7c4d3e2f1a0b9c8_firmware_v2.json       │
  │    (different hash prefix → different file → no collision)   │
  │                                                              │
  │  JSON schema:                                                │
  │  {                                                           │
  │    "sha256":       "a3f9b2c1d4e5f678...",   // full 64 hex  │
  │    "plt":          {"12288": "strcpy", ...},  // VA as str   │
  │    "exports":      {"init_handler": "16384"},                │
  │    "strings":      {"24592": "Authorization: Bearer"},       │
  │    "func_starts":  [16384, 16672, 16896, ...],               │
  │    "call_edges":   [[16384, 12288, "strcpy"], ...],          │
  │    "str_xref_idx": {"16384": [24592, 24632]}                 │
  │  }                                                           │
  │                                                              │
  │  JSON uses decimal integers for VAs (not "0x..." strings).   │
  │  BinaryContext converts them back to int on load.            │
  │                                                              │
  │  Timing for a 50 MB stripped ELF (19,000 functions):        │
  │    lief parse:               ~80 ms                          │
  │    .eh_frame FDE scan:       ~30 ms                          │
  │    callee augmentation:      ~250 ms                         │
  │    call graph (Capstone):    ~3.5 s   ← bottleneck           │
  │    string xref indexing:     ~100 ms                         │
  │    JSON serialize + write:   ~200 ms                         │
  │    ────────────────────────────────                          │
  │    First run total:          ~4.2 s                          │
  │                                                              │
  │    Reload (SHA-256 + JSON parse):  ~130 ms                   │
  └──────────────────────────────────────────────────────────────┘
```

---

## Reload phase

Every session after the first follows this path:

```
  BinaryContext.load_or_build(path)
  ═══════════════════════════════════════════════════════════════

  1. Read binary bytes into memory
  2. Compute SHA-256 of bytes → sha256_key
  3. expected_cache = ~/.ablation/cache/<sha256_key[:16]>_<name>.json

  does expected_cache exist?
  │
  ├── YES: open JSON, read stored "sha256" field
  │     does stored sha256 match sha256_key?
  │     │
  │     ├── YES: deserialize into BinaryContext
  │     │         convert string-keyed JSON dicts back to int
  │     │         load plt, exports, strings, func_starts,
  │     │         call_edges, str_xref_idx into memory
  │     │         done in ~130 ms  ← normal reload path
  │     │
  │     └── NO:  basename collision, different content
  │               fall through to build phase
  │
  └── NO: build phase (4-5 s), write cache, return
```

A basename collision happens when two different binaries have the same filename — for example, two versions of `libssl.so`. The SHA-256 prefix in the cache filename prevents them from colliding because the prefixes differ, so both caches can coexist. The check inside the cache file catches the rare case where two files share the first 16 hex digits of their SHA-256, which is probabilistically negligible but handled correctly.

---

## What is indexed

| Attribute | Type | Content |
|---|---|---|
| `ctx.plt` | `{int: str}` | PLT stub VA to import name |
| `ctx.exports` | `{str: int}` | Export name to VA |
| `ctx.strings` | `{int: str}` | String VA to content |
| `ctx.func_starts` | `list[int]` | Sorted function entry VAs |
| `ctx.call_edges` | `list[tuple]` | `(caller_va, callee_va, label)` |
| `ctx.str_xref_idx` | `{int: list[int]}` | Func VA to referenced string VAs |

---

## The name overlay

`ctx.name(va)` returns a human-readable name for any VA. This is the single most important rule in Ablation: always call `ctx.name(va)` rather than printing raw hex. The reason is that function names accumulate over time. A VA that is an opaque hex address in session one might have a confirmed name by session three. Using `ctx.name(va)` consistently means that improvement shows up everywhere automatically.

The name resolution priority stack works like this:

```
  ctx.name(0x4000)
  ═══════════════════════════════════════════════════════════════

  Layer 1 — NameRegistry
  ┌──────────────────────────────────────────────────────────────┐
  │  SQLite database at ~/.ablation/names.db                     │
  │                                                              │
  │  CREATE TABLE function_names (                               │
  │    binary_sha256  TEXT NOT NULL,   -- ties name to binary    │
  │    va             INTEGER NOT NULL,                          │
  │    name           TEXT NOT NULL,                             │
  │    source         TEXT,    -- 'confirmed' / 'pclntab' / etc  │
  │    timestamp      INTEGER                                    │
  │  );                                                          │
  │                                                              │
  │  Names are keyed on (binary_sha256, va), not on filename.    │
  │  Renaming the binary file does not lose the name overlay.    │
  │  Moving the binary between machines loses it only because    │
  │  the SQLite file is local.                                   │
  └──────────────────────────────┬───────────────────────────────┘
                                 │ not found
                                 ▼
  Layer 2 — exports dict
  ┌──────────────────────────────────────────────────────────────┐
  │  Populated from .dynsym / .symtab (ELF) or PE export dir.   │
  │  Present only for non-stripped exported symbols.             │
  └──────────────────────────────┬───────────────────────────────┘
                                 │ not found
                                 ▼
  Layer 3 — PLT dict
  ┌──────────────────────────────────────────────────────────────┐
  │  plt_map[VA] = import_name for PLT stub VAs.                 │
  │  Answers "this VA is the PLT stub for strcpy."               │
  └──────────────────────────────┬───────────────────────────────┘
                                 │ not found
                                 ▼
  Layer 4 — hex fallback
  ┌──────────────────────────────────────────────────────────────┐
  │  return f"0x{va:x}"                                          │
  └──────────────────────────────────────────────────────────────┘
```

`ctx.set_name(va, name, source='confirmed')` inserts into the NameRegistry at Layer 1. Do this the moment you confirm a function's purpose. The name will appear in every future session, in every tool that calls `ctx.name(va)`, without any further action.

---

## callers_of and callees_of

Both methods walk `call_edges` in memory. The graph is a flat Python list, not a dict. This is intentional: the list is fast to serialize and fast to scan, and the query patterns Ablation needs — "all callers of X" and "all callees of function at VA" — are both linear scans.

```
  call_edges = [
    (0x4000, 0x3000, 'strcpy'),   # func 0x4000 calls strcpy PLT stub
    (0x4000, 0x4280, '0x4280'),   # func 0x4000 calls internal func
    (0x4120, 0x3000, 'strcpy'),   # func 0x4120 also calls strcpy
    (0x4280, 0x3010, 'malloc'),   # func 0x4280 calls malloc
    ...
  ]

  ctx.callers_of('strcpy'):
    → [(f, l) for (f, t, l) in call_edges if l == 'strcpy']
    → [(0x4000, 'strcpy'), (0x4120, 'strcpy')]

  ctx.callers_of(0x3000):
    → [(f, l) for (f, t, l) in call_edges if t == 0x3000]
    same result — label form and VA form both work

  ctx.callees_of(0x4000):
    → [(t, l) for (f, t, l) in call_edges if f == 0x4000]
    → [(0x3000, 'strcpy'), (0x4280, '0x4280')]

  Performance: O(N) scan over N entries.
  N is typically 50,000 to 300,000.
  Single callers_of() on a 200,000-edge graph: ~2 ms in CPython.

  For repeated queries over the same graph, build an inverted dict:
    from collections import defaultdict
    callers_idx = defaultdict(list)
    for (f, t, l) in ctx.call_edges:
        callers_idx[l].append((f, l))
        callers_idx[t].append((f, l))
    callers_idx['strcpy']   # O(1) after setup
```

---

## Where BinaryContext fits in the pipeline

Every other Ablation tool calls `BinaryContext` first. Understanding what it provides — and what it does not — tells you when you need to reach for a heavier tool.

```
  BinaryContext provides:
    func_starts    → taint trackers use this to find function boundaries
    call_edges     → taint trackers use this for interprocedural BFS
    plt_map        → taint trackers use this to identify sources and sinks
    str_xref_idx   → FuncProfiler uses this to find format strings
    name(va)       → every tool uses this for display

  BinaryContext does NOT provide:
    register-level data flow  → use TaintTracker
    control flow graph        → CFG built per-function by each tool
    decompiled pseudocode     → use BinaryLifter
    dynamic behavior          → use DynamicSandbox (Phase 3)
    C++ vtable dispatch       → use VtableResolver
    cross-version tracking    → use VersionDelta

  Tool dependency graph:
    BinaryContext
    ├── SemanticSearcher   needs func_starts + call_edges for corpus
    ├── FuncProfiler       needs callers_of / callees_of for sink mapping
    ├── TaintTracker       needs plt_map + func_starts + call_edges
    ├── PatternLibrary     needs ctx.name for finding labels
    ├── VersionDelta       loads ctx for v1 and v2 binaries
    └── HypothesisEngine   ctx passed as accelerator for probe adapters
```

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext

# First run: 0.5-5 s depending on binary size
ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
# BinaryContext: firmware_v2.so
# Functions: 19432  Strings: 41206  Call edges: 198341
# PLT imports: 89   Exports: 12

# Callers of strcpy (all call sites across the binary)
for (va, label) in ctx.callers_of('strcpy'):
    print(f"  0x{va:x}  {ctx.name(va)}")

# Callees of a specific function
for (va, label) in ctx.callees_of(0x4000):
    print(f"  -> 0x{va:x}  {label}")

# Strings referenced by a function
for (sva, content) in ctx.strings_in_func(0x4000):
    print(f"  0x{sva:x}  {content!r}")

# Which functions reference a specific string?
for fva in ctx.funcs_referencing_string(0x6010):
    print(f"  {ctx.name(fva)}")

# Confirm a function name — persists across all future sessions
ctx.set_name(0x4000, 'parse_radius_packet', source='confirmed')
print(ctx.name(0x4000))   # 'parse_radius_packet'
```
