<a id="binarycontext"></a>
# Analysis Context & Caching

  - [What is BinaryContext?](#what-is-binarycontext)
  - [Why this exists](#why-this-exists)
    - [The startup time problem](#the-startup-time-problem)
    - [The GUI dependency problem](#the-gui-dependency-problem)
  - [Build phase](#build-phase)
    - [Step 1: Format parse and symbol extraction](#step-1-format-parse-and-symbol-extraction)
    - [Step 2: Function start recovery](#step-2-function-start-recovery)
    - [Step 3: Call graph construction](#step-3-call-graph-construction)
    - [Step 4: String cross-reference index](#step-4-string-cross-reference-index)
    - [Step 5: Serialization](#step-5-serialization)
  - [Reload phase](#reload-phase)
  - [What is indexed](#what-is-indexed)
  - [The name overlay](#the-name-overlay)
  - [callers_of and callees_of](#callers_of-and-callees_of)
  - [Pipeline position](#pipeline-position)
  - [Usage](#usage)
  - [How it works](#how-it-works)
  - [Example output](#example-output)
  - [False positives](#false-positives)
  - [Reading output](#reading-output)
  - [See also](#see-also)

---

## What is BinaryContext? <sup>[↑](#binarycontext)</sup>

`BinaryContext` is Ablation's session cache and binary index. It parses a binary once, builds a function-start list, call graph, import table, and string cross-reference index, then serializes the result keyed on the binary's SHA-256 hash. Every subsequent session deserializes that index in about 130 milliseconds rather than repeating the full parse.

Every Ablation analysis tool accepts a `BinaryContext` as its primary input. `TaintTracker`, `SemanticSearcher`, `SinkArgClassifier`, and `FuncProfiler` all query it for function starts, call graph data, and import names. The object holds no mutable state after the build phase: every analysis tool reads it as a read-only index.

The session cache eliminates the binary analysis startup cost that makes iterative RE workflows impractical in GUI-based tools. IDA Pro and Ghidra each require 5 to 20 minutes of autoanalysis before a 50 MB firmware binary is interactive. `BinaryContext` pays that cost once, serializes the result, and reloads in 130 milliseconds on every subsequent session.

---

## Why this exists <sup>[↑](#binarycontext)</sup>

### The startup time problem <sup>[↑](#binarycontext)</sup>

IDA Pro's autoanalysis on a 50 MB firmware binary runs for 5 to 20 minutes before the UI is interactive. Ghidra's analysis pipeline is similar. Every session restart pays that full cost again. If you are iterating on a taint tracker or testing a new semantic query, that wait becomes a serious obstacle to experimentation.

BinaryContext solves this by separating the expensive work from the repeatable work. The expensive part runs once: parse the binary, recover function starts, build the call graph. The result is serialized to a JSON file keyed on the binary's SHA-256 hash. Every subsequent session deserializes that file directly. Python's JSON parser reads 10 MB of pre-parsed data in about 80 milliseconds. Add 50 milliseconds to compute the SHA-256, and the total reload time is roughly 130 milliseconds.

The SHA-256 key ensures the cache never goes stale. Any change to the binary produces a different hash and triggers a full rebuild. There is no version tag, no timestamp, no partial invalidation. The binary itself is the truth, and the hash is the gate.

### The GUI dependency problem <sup>[↑](#binarycontext)</sup>

Getting "which functions call `strcpy`?" in IDA requires the GUI to be open, analyzed, and holding a license seat. `ctx.callers_of('strcpy')` answers the same question from the command line, in a script, or inside a taint tracker. No GUI. No license. The call graph lives in memory as a flat Python list, so filtering it is a single linear scan in Python.

---

## Build phase <sup>[↑](#binarycontext)</sup>

The build phase runs once per binary. Understanding each of the five steps tells you what the index can and cannot give you.

```mermaid
flowchart TD
    A(["Binary file on disk"]):::input --> B["Step 1 · lief.parse\nPLT stubs · exports · strings"]:::primary
    B:::primary --> F["Step 2 · Function start recovery\nPass 1: unwind tables\nPass 2: callee augmentation"]:::secondary
    F:::secondary --> J["Step 3 · Call graph construction\nCapstone per function body"]:::tertiary
    J:::tertiary --> K["Step 4 · String xref indexing\narch-specific load detection"]:::tertiary
    K:::tertiary --> L(["Step 5 · Serialize to JSON cache\nkey = SHA-256 of binary bytes"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

---

### Step 1: Format parse and symbol extraction <sup>[↑](#binarycontext)</sup>

The first step uses `lief` to parse the binary format and extract three symbol tables: PLT imports, exported symbols, and `.rodata` strings.

**Understanding the PLT**

The PLT Procedure Linkage Table is ELF's mechanism for lazy symbol binding. When you compile C code that calls `strcpy`, the compiler generates a call to a PLT stub. On the first call, the stub invokes the dynamic linker, which resolves the symbol and patches the GOT entry. On subsequent calls, the GOT entry already holds the real address, so the stub jumps directly there.

Every call to `strcpy` goes through the same stub VA. If you know that PLT stub at `0x3000` maps to `strcpy`, you find every caller by scanning for calls to `0x3000`. BinaryContext builds this mapping from `.rela.plt`.

The ELF linker records PLT-to-symbol mappings in `.rela.plt`. Each entry is an `Elf64_Rela` struct:

| Field | Size | Description |
|---|---|---|
| `r_offset` | 8 bytes | VA of the GOT slot to be patched at runtime |
| `r_info` | 8 bytes | Upper 32 bits: `.dynsym` index. Lower 32 bits: reloc type (7 = `JUMP_SLOT`) |
| `r_addend` | 8 bytes | Always 0 for PLT entries |

Resolution chain: `sym_index = r_info >> 32` → `dynsym[sym_index].st_name` → index into `.dynstr` → `import_name`.

The x86-64 PLT stub is 16 bytes per import:

| Offset | Bytes | Instruction | Purpose |
|---|---|---|---|
| 0 | `FF 25 XX XX XX XX` | `JMP [RIP+disp]` | Jump through GOT slot |
| 6 | `68 NN 00 00 00` | `PUSH N` | Push relocation index |
| 11 | `E9 XX XX XX XX` | `JMP PLT[0]` | Call the dynamic linker resolver |

After the dynamic linker runs, the GOT slot holds the real function address. The `JMP` at offset 0 goes directly there on every subsequent call, bypassing the `PUSH + JMP` tail entirely.

PE binaries use the IAT Import Address Table with the same concept: a table of function pointers patched at load time. BinaryContext reads the import directory's INT and IAT to build `iat_map[thunk_va] = 'module!function'`.

---

### Step 2: Function start recovery <sup>[↑](#binarycontext)</sup>

Recovering function starts in a stripped binary is a two-pass process. The first pass reads the binary's own unwind data. The second pass fills the gaps.

**Why unwind tables survive strip(1)**

C++ exception handling and signal delivery both need to unwind the call stack. GCC solves this by emitting one Frame Description Entry (FDE) per function in `.eh_frame`. The FDE records the function's start VA and byte length. `strip(1)` cannot remove `.eh_frame` because the runtime linker reads it at startup to register unwind information with the OS. Remove it and exception handling breaks. In any binary compiled with GCC or Clang at default settings, `.eh_frame` contains a complete function start list even when the symbol table is gone. This is a design feature of the C++ ABI that becomes a gift for reverse engineering.

**CIE Common Information Entry**: one per compilation unit:

| Field | Type | Description |
|---|---|---|
| `length` | 4 bytes | Total CIE size minus the length field itself |
| `CIE_id` | 4 bytes | Always 0 distinguishes CIE from FDE |
| `version` | 1 byte | 1 = DWARF 2, 3 = DWARF 3 |
| `augmentation` | string | `"zR"` = pointer format encoded in aug_data |
| `code_align` | uleb128 | Instruction size quantum 1 for x86 |
| `data_align` | sleb128 | Stack slot size factor −8 for x86-64 |
| `return_addr_reg` | uleb128 | Register number of return address |
| `aug_data` | variable | Pointer encoding byte pcrel / absolute |
| `initial_insns` | variable | CFA baseline rules for example `push rbp` |

**FDE Frame Description Entry**: one per function, contains the function start VA:

| Field | Type | Description |
|---|---|---|
| `length` | 4 bytes | Total FDE size minus the length field |
| `CIE_ptr` | 4 bytes | Byte offset back to the parent CIE |
| `initial_location` | ptr | **Function start VA** |
| `address_range` | ptr | Function byte length |
| `aug_data_len` | uleb128 | Length of augmentation data |
| `aug_data` | variable | LSDA pointer for C++ exceptions (if any) |
| `call_frame_insns` | variable | How to restore registers at each PC offset |

The `initial_location` encoding depends on the CIE's augmentation byte:
- `DW_EH_PE_pcrel (0x10)`: `abs_va = FDE_field_va + encoded_value`
- `DW_EH_PE_absptr (0x00)`: `abs_va = encoded_value` directly

ARM32 binaries use `.ARM.exidx` instead. Each entry is two 32-bit words. The first encodes the function start as a prel31 value: `abs_va = field_va & ~1 + sign_extendvalue, 31`. PE x86-64 binaries use `.pdata`, which is an array of `RUNTIME_FUNCTION { BeginAddress, EndAddress, UnwindInfoAddress }` structs.

**Pass 2: Callee augmentation**

Unwind tables are but not complete. Hand-written assembly, early-exit stubs, and tail-call targets sometimes have no FDE. They do get called from known functions, so BinaryContext discovers them by scanning call targets.

```mermaid
flowchart TD
    A(["Known func_starts\nfrom unwind tables"]):::input --> B["For each function,\nCapstone scan to next start"]:::primary
    B:::primary --> C{"Instruction is\ndirect CALL/BL?"}:::neutral
    C:::neutral -->|No| B:::primary
    C:::neutral -->|Yes| D{"target_va already\nin func_starts?"}:::neutral
    D:::neutral -->|Yes| B:::primary
    D:::neutral -->|No| E{"target_va\nin .text range?"}:::neutral
    E:::neutral -->|No| B:::primary
    E:::neutral -->|Yes| F["Add target_va\nto func_starts"]:::secondary
    F:::secondary --> B:::primary
    B:::primary --> G(["Augmented func_starts\nsorted + deduplicated"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#546e7a,stroke-width:2px
    linkStyle 2 stroke:#bf360c,stroke-width:2px
    linkStyle 3 stroke:#546e7a,stroke-width:2px
    linkStyle 4 stroke:#bf360c,stroke-width:2px
    linkStyle 5 stroke:#546e7a,stroke-width:2px
    linkStyle 6 stroke:#bf360c,stroke-width:2px
    linkStyle 7 stroke:#00695c,stroke-width:2px
    linkStyle 8 stroke:#bf360c,stroke-width:2px
    linkStyle 9 stroke:#2e7d32,stroke-width:3px
```

The pass runs once. Newly discovered callees are added to `func_starts` but their own bodies are not rescanned in the same pass.

---

### Step 3: Call graph construction <sup>[↑](#binarycontext)</sup>

With function boundaries established, BinaryContext disassembles each function body and extracts every direct call it makes. The result is a flat list of `caller_va, callee_va, label` tuples. Indirect calls are skipped because the callee address is not statically determinable. VtableResolver handles C++ virtual dispatch separately.

| Architecture | Direct call instructions detected |
|---|---|
| x86-64 | `CALL rel32` / `CALL r/m64` |
| ARM64 | `BL imm26` (`BLR` is indirect; skipped) |
| ARM32 | `BL imm24` / `BLX imm24` |
| MIPS32 | `JAL imm26` / `JALR $ra,$t9` |
| LA64 | `BL offset26` / `JIRL $ra,rj,0` |
| nanoMIPS | `BALC` P32/P16 bitfield resolved |

---

### Step 4: String cross-reference index <sup>[↑](#binarycontext)</sup>

Strings in `.rodata` are inert until something loads their address. The cross-reference index connects function bodies to the strings they reference, so `ctx.strings_in_func(va)` is a simple dict lookup rather than a full rescan.

"Load a string address" looks different on every ISA. BinaryContext tracks arch-specific patterns across instruction boundaries:

```python
# x86-64: RIP-relative load
# LEA rX, [RIP + disp32]
target = insn_va + insn_length + sign_extend32(disp)

# ARM64: two-instruction ADRP + ADD pair
# ADRP Xn, label  →  pending_adrp[Xn] = (insn_va & ~0xFFF) + (imm21 << 12)
# ADD  Xn, Xn, #offset  →  full_va = pending_adrp[Xn] + offset

# ARM32: literal pool
# LDR Rd, [PC, #N]  →  pool_va = (insn_va + 8) & ~3 + N
#                       addr = read_u32(binary, pool_va - load_addr)

# MIPS32: LUI + ADDIU pair
# LUI   $t0, hi16   →  pending_lui[$t0] = hi16 << 16
# ADDIU $t0, $t0, lo16  →  full_va = pending_lui[$t0] + sign_extend16(lo16)
```

If the resolved address falls in `strings_map`, it is recorded as `str_xref_idx[func_va].appendstring_va`.

---

### Step 5: Serialization <sup>[↑](#binarycontext)</sup>

| Field | JSON type | Content |
|---|---|---|
| `sha256` | string | Full 64-character hex hash |
| `plt` | object | `{"stub_va": "import_name"}` |
| `exports` | object | `{"name": va}` |
| `strings` | object | `{"va": "content"}` |
| `func_starts` | array | Sorted integer VAs |
| `call_edges` | array | `[caller_va, callee_va, label]` triples |
| `str_xref_idx` | object | `{"func_va": [string_va,...]}` |

Cache path: `~/.ablation/cache/<sha256[:16]>_<basename>.json`. Multiple versions of the same binary coexist because different content produces a different SHA-256 prefix.

Build timing for a 50 MB stripped ELF with 19,000 functions:

| Step | Time |
|---|---|
| `lief.parse` | ~80 ms |
| `.eh_frame` FDE scan | ~30 ms |
| Callee augmentation | ~250 ms |
| Call graph Capstone | ~3.5 s |
| String xref indexing | ~100 ms |
| JSON serialize + write | ~200 ms |
| **First run total** | **~4.2 s** |
| **Reload SHA-256 + JSON parse** | **~130 ms** |

---

## Reload phase <sup>[↑](#binarycontext)</sup>

```mermaid
flowchart TD
    A(["load_or_build(path)"]):::input --> B["Compute SHA-256\nof binary bytes"]:::primary
    B:::primary --> C{"Cache file\nexists?"}:::neutral
    C:::neutral -->|No| E["Run full build phase\n~4 s"]:::secondary
    C:::neutral -->|Yes| D{"Stored sha256\nmatches?"}:::neutral
    D:::neutral -->|Yes| F["Deserialize JSON\n~130 ms"]:::tertiary
    D:::neutral -->|No| E:::secondary
    E:::secondary --> G["Write cache file"]:::tertiary
    G:::tertiary --> H(["Return BinaryContext"]):::output
    F:::tertiary --> H:::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#546e7a,stroke-width:2px
    linkStyle 2 stroke:#00695c,stroke-width:2px
    linkStyle 3 stroke:#546e7a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#00695c,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
    linkStyle 8 stroke:#2e7d32,stroke-width:3px
```

A "stored sha256 doesn't match" case happens when two different binaries share a filename and their first 16 SHA-256 hex digits collide. The inner check forces a rebuild so stale data is never returned.

---

## What is indexed <sup>[↑](#binarycontext)</sup>

| Attribute | Type | Content |
|---|---|---|
| `ctx.plt` | `{int: str}` | PLT stub VA to import name |
| `ctx.exports` | `{str: int}` | Export name to VA |
| `ctx.strings` | `{int: str}` | String VA to content |
| `ctx.func_starts` | `list[int]` | Sorted function entry VAs |
| `ctx.call_edges` | `list[tuple]` | `caller_va, callee_va, label` |
| `ctx.str_xref_idx` | `{int: list[int]}` | Func VA to referenced string VAs |

---

## The name overlay <sup>[↑](#binarycontext)</sup>

`ctx.name(va)` returns a human-readable name for any VA. Always use it rather than printing raw hex. Function names accumulate over time, so using `ctx.name(va)` consistently means every confirmed name propagates everywhere automatically.

```mermaid
flowchart TD
    A(["ctx.name(va)"]):::input --> B{"NameRegistry\nSQLite · keyed by\nbinary_sha256 + va"}:::neutral
    B:::neutral -->|Found| Z(["Return confirmed name"]):::output
    B:::neutral -->|"Not found"| C{"exports dict\n.dynsym / .symtab"}:::neutral
    C:::neutral -->|Found| Z:::output
    C:::neutral -->|"Not found"| D{"PLT map\nstub VAs only"}:::neutral
    D:::neutral -->|Found| Z:::output
    D:::neutral -->|"Not found"| E(["Return 0x{va:x}"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#546e7a,stroke-width:2px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#546e7a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#546e7a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
```

The NameRegistry stores names in a SQLite database at `~/.ablation/names.db`:

```sql
CREATE TABLE function_names (
    binary_sha256  TEXT NOT NULL,
    va             INTEGER NOT NULL,
    name           TEXT NOT NULL,
    source         TEXT,   -- 'confirmed' / 'pclntab' / 'pdb' / etc.
    timestamp      INTEGER,
    PRIMARY KEY (binary_sha256, va)
);
```

Renaming or moving the binary does not lose the overlay because names are keyed on the SHA-256 hash, not the filename. `ctx.set_name(0x4000, 'parse_radius_packet', source='confirmed')` writes here. Call it the moment you confirm a function's purpose.

---

## callers_of and callees_of <sup>[↑](#binarycontext)</sup>

Both methods walk `call_edges` in memory. The graph is a flat Python list because the query patterns Ablation needs are both linear scans, and 200,000 entries cost about 2 ms in CPython.

```python
call_edges = [
    (0x4000, 0x3000, 'strcpy'),   # 0x4000 calls strcpy PLT stub
    (0x4000, 0x4280, '0x4280'),   # 0x4000 calls internal func
    (0x4120, 0x3000, 'strcpy'),   # 0x4120 also calls strcpy
    (0x4280, 0x3010, 'malloc'),
]

ctx.callers_of('strcpy')    # → [(0x4000, 'strcpy'), (0x4120, 'strcpy')]
ctx.callers_of(0x3000)      # same result: VA form also works
ctx.callees_of(0x4000)      # → [(0x3000, 'strcpy'), (0x4280, '0x4280')]
```

For repeated queries in a hot loop, build an inverted index once:

```python
from collections import defaultdict
callers_idx = defaultdict(list)
for (f, t, l) in ctx.call_edges:
    callers_idx[l].append((f, l))
    callers_idx[t].append((f, l))
callers_idx['strcpy']   # O(1) lookup
```

---

## Pipeline position <sup>[↑](#binarycontext)</sup>

BinaryContext is the foundation every other Ablation tool builds on.

```mermaid
flowchart TD
    BC(["BinaryContext\nfunc_starts · call_edges\nplt_map · str_xref_idx · name()"]):::input

    BC:::input --> SS(["SemanticSearcher\nfunc_starts + call_edges\n→ BERT corpus"]):::output
    BC:::input --> FP(["FuncProfiler\ncallers_of / callees_of\n→ sink mapping"]):::output
    BC:::input --> TT(["TaintTracker\nplt_map + func_starts + call_edges\n→ interprocedural BFS"]):::output
    BC:::input --> PL(["PatternLibrary\nctx.name() for finding labels"]):::output
    BC:::input --> VD(["VersionDelta\nctx for v1 and v2 binaries"]):::output
    BC:::input --> HE(["HypothesisEngine\nctx as probe accelerator"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#2e7d32,stroke-width:3px
    linkStyle 1 stroke:#2e7d32,stroke-width:3px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

---

## Usage <sup>[↑](#binarycontext)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext

# First run builds and caches (0.5-5 s). Every run after: ~130 ms.
ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())

# All callers of strcpy across the entire binary
for (va, label) in ctx.callers_of('strcpy'):
    print(f"  0x{va:x}  {ctx.name(va)}")

# All callees of a specific function
for (va, label) in ctx.callees_of(0x4000):
    print(f"  -> 0x{va:x}  {label}")

# Strings referenced by a function
for (sva, content) in ctx.strings_in_func(0x4000):
    print(f"  0x{sva:x}  {content!r}")

# Which functions reference a given string?
for fva in ctx.funcs_referencing_string(0x6010):
    print(f"  {ctx.name(fva)}")

# Confirm a name: persists across all future sessions
ctx.set_name(0x4000, 'parse_radius_packet', source='confirmed')
```

---

## How it works <sup>[↑](#binarycontext)</sup>

`load_or_build(path)` hashes the binary with SHA-256, checks `~/.ablation/cache/<sha256[:16]>_<basename>.json`, and returns the deserialized `BinaryContext` in ~130 ms on a hit. On a miss it runs the five-step build pipeline described in the sections above: format parse, FDE unwind scan, callee augmentation, call graph construction, string xref indexing: then serializes to the cache file. The SHA-256 key guarantees cache correctness: any byte change in the binary produces a different hash and forces a rebuild. No version tag, no timestamp. See **Build phase** above for the full step-by-step description.

---

## Example output <sup>[↑](#binarycontext)</sup>

```
BinaryContext: libservice.so
  sha256     : fdfaceccdc740d82...
  arch       : arm64
  base_va    : 0x0
  func_starts: 19842
  exports    : 0
  plt entries: 314
  strings    : 8821
  call_edges : 84763
  str_xrefs  : 22104 pairs indexed
  named funcs: 47 (overlay)

  Top PLT imports (callers):
    strcpy           called by 12 functions
    malloc           called by 31 functions
    memcpy           called by 44 functions
    ...
```

---

## False positives <sup>[↑](#binarycontext)</sup>

`BinaryContext.load_or_build()` does not emit security findings. The most common failure mode is a cache hit returning a stale context after the binary has been modified: the SHA-256 key prevents this for the binary itself, but the NameRegistry overlay is separate. If a function name registered in a prior session has since been determined incorrect, call `ctx.delete_name(va)` and `ctx.set_name(va, corrected_name, source='confirmed')` to update both the in-memory overlay and the persistent `NameRegistry`.

---

## Reading output <sup>[↑](#binarycontext)</sup>

`BinaryContext.load_or_build(path)` returns a `BinaryContext`: the session object that all analysis modules operate on. It has no findings output; it is the input handle. See [BinaryContext](binary-context.md) for the full method reference.

For PLT resolution specifically: `ctx.imports()` returns `Dict[str, int]`: import name → GOT VA.

---

## See also <sup>[↑](#binarycontext)</sup>

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
