# BinaryContext

## Why this exists

Three things were not possible before this module:

1. **No per-session symbol resolution.** Before `BinaryContext`, every analysis tool had to re-parse the ELF, rebuild the PLT map, re-extract strings, and re-compute the call graph from scratch. On a 15MB firmware binary that overhead ran 4–6 seconds per session. `BinaryContext` builds once (~2–5 seconds), serializes to `~/.ablation/cache/`, and reloads in under 100ms on every subsequent session.

2. **No cross-tool caller/callee queries.** Individual tools like `TaintTracker` and `SemanticSearcher` operated in isolation. There was no shared index for "what calls this symbol" or "what does this function call." `BinaryContext` builds `_callers_idx` and `_callees_idx` once and exposes them via `callers_of()` and `callees_of()`, making cross-tool queries O(1) lookups instead of per-session linear scans.

3. **No Windows PE support in the context layer.** All of Ablation's analysis tools (`SemanticSearcher`, `TaintTracker`, `WindowAnalyzer`, `FuncProfiler`) depend on `BinaryContext`. Before v2.45.0, loading a Windows PE or `.sys` driver silently returned an empty context, meaning every search and taint trace returned nothing. The v2.45.0 PE path populates all the same slots (IAT as PLT, exports, strings, func_starts, call_edges) so every tool works on PE files with no changes to calling code.

---

## What it does

`BinaryContext` is the pre-computed working context for a stripped binary. One build populates:

- `plt` (`{va: symbol_name}`): PLT stubs (ELF) or IAT entries (PE)
- `exports` (`{symbol_name: va}`): all globally exported functions
- `strings` (`{va: content}`): printable ASCII sequences ≥ 4 chars from read-only sections
- `func_starts`: sorted list of function entry VAs (DWARF `.eh_frame` for ELF; export VAs + prologue scan for PE)
- `call_edges` (`[(from_va, to_va, label)]`): flat call graph, vectorized numpy scan

Named function VAs are tracked in the overlay (`ctx.set_name(va, name)`) and persisted via `NameRegistry` across sessions.

---

## Supported formats

| Format | Arch support | func_starts source |
|---|---|---|
| ELF | x86_64, x86_32, arm64, arm32, ppc64, ppc32, mips64, mips32, riscv64, riscv32, loongarch64 | DWARF `.eh_frame` + exports + dynamic symbols |
| Windows PE / `.sys` | x86_64, x86_32 (arm64/arm32 no-op, safe) | Exports + prologue scan |

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext

# Works on both ELF and PE (load path auto-detects format)
ctx = BinaryContext.load_or_build('/path/to/target.exe')

print(ctx.summary())

# Caller/callee queries (ELF and PE)
ctx.callers_of('RpcServerRegisterIfEx')   # -> [(from_va, fn_name), ...]
ctx.callees_of(0x140001234)               # -> [(to_va, label), ...]

# String xrefs (ELF and PE x86_64)
ctx.strings_in_func(0x140001234)          # -> [(va, content), ...]
ctx.funcs_referencing_string(0x14000a000) # -> [va, ...]

# Name overlay (persisted across sessions)
ctx.set_name(0x140001234, 'parse_request', source='confirmed')
```

### PE-specific: combining with the Windows PE analyzers

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.rpc_server_analyzer import RPCServerAnalyzer

ctx = BinaryContext.load_or_build('/path/to/rpcss.dll')

# SemanticSearcher, TaintTracker, WindowAnalyzer, FuncProfiler all work now
from ablation.analyzers.semantic_searcher import SemanticSearcher
results = SemanticSearcher(ctx).query("unauthenticated RPC registration")

# Then hand off to the PE-specific analyzer for deep inspection
rpc = RPCServerAnalyzer.from_path('/path/to/rpcss.dll')
findings = rpc.scan()
```

---

## Cache

Cache lives at `~/.ablation/cache/<sha256[:16]>_<basename>.json`. Invalidated on SHA256 mismatch. Force rebuild with `force_rebuild=True`.

```python
ctx = BinaryContext.load_or_build(path, force_rebuild=True)
```

To load without the original binary (e.g. `/tmp` was cleared):

```python
ctx = BinaryContext.load_from_cache_file('~/.ablation/cache/abc123_target.json')
```

Cache predating ARM64 gap fixes (AARCH64-GAP-001/002) will have empty `str_xref_idx`. On next
`load_or_build()` the lazy-rebuild path in `_load_json()` detects the missing index and runs
`_build_string_xref_index()` automatically if the original binary is accessible.

---

## ARM64 / AArch64 support gaps fixed

Two gaps prevented ARM64 binary analysis. Both are now resolved.

### AARCH64-GAP-001 — Call graph (fixed 2026-10-15)

**Symptom:** `ctx.call_edges` contained ~1 edge on ARM64 ELFs.

**Root cause:** `_build_call_graph()` fell through to the x86 `0xe8` opcode scanner
for `arch='arm64'`. ARM64 has no `0xe8` call instruction.

**Fix:** `_build_call_graph_arm64()` — vectorized NumPy scan for BL instructions.

AArch64 BL encoding (little-endian):

```
bits 31:26 = 100101  →  byte[3] ∈ {0x94, 0x95, 0x96, 0x97}
imm26 = word[25:0]
target = insn_va + SignExtend(imm26, 26) × 4
```

No +8 pipeline adjustment (ARM32 adds +8; ARM64 does not). All instructions are
4-byte aligned — only word-aligned positions are scanned.

Validated on emsworkers_linux_arm64 v8.0.0 (78 MB Go binary): **1 → 69,344 call edges**.

### AARCH64-GAP-002 — String xref index (fixed 2026-10-15)

**Symptom:** `ctx.string_xrefs(va)` always returned `[]` on ARM64 binaries.

**Root cause:** `_build_string_xref_index()` docstring claimed "x86_64/arm64" but the
implementation applied the x86-64 RIP-relative 32-bit displacement formula to ARM64 code,
which uses a completely different addressing mode.

**Fix:** `_build_string_xref_index_arm64()` — vectorized NumPy scan for ADRP+ADD pairs.

ARM64 materialises PC-relative string addresses as a two-instruction sequence:

```
ADRP X_d, #page_imm    — byte[3] & 0x9F == 0x90; loads 4KB-aligned base page.
ADD  X_d, X_d, #off12  — bits[31:22] == 0x244 (64-bit, shift=0); adds 12-bit offset.
```

Page address computation: `page_base = (insn_va & ~0xFFF) + SignExtend(imm21, 21) << 12`

Full address: `page_base + imm12`

Only consecutive (i, i+1) pairs where `ADD.Rn == ADRP.Rd` (same register) are matched.

Validated on emsworkers_linux_arm64 v8.0.0 (78 MB Go binary): **0 → 13,962 string xref pairs**.

---

## MIPS32/64 support gap fixed

One gap prevented MIPS32 firmware analysis. Now resolved.

### MIPS-GAP-001 — Call graph: JAL-only scanner missed all PLT calls (fixed 2026-10-15)

**Symptom:** `ctx.call_edges` was empty on MIPS32 ET_EXEC firmware binaries.

**Root cause:** `_build_call_graph_mips()` scanned only for JAL (opcode=3, bits 31:26). The
O32 ABI PIC calling convention used by ET_EXEC firmware (e.g., FortiAP cwWtpd) routes all
PLT and cross-function calls through `LW $t9, N($gp)` + `JALR $t9` — zero JAL instructions.

**Fix:** `_build_call_graph_mips()` now handles both patterns:

1. **JAL** (unchanged): `bits 31:26 == 3`, target = `(DS_PC & 0xF0000000) | (imm26 << 2)`.

2. **LW $t9, N($gp) + JALR $t9** (new):
   - Encoding: bits 31:16 = `0x8F99` (opcode=LW=0x23, rs=$gp=28, rt=$t9=25).
   - `$gp` is fixed for ET_EXEC binaries; read from `.reginfo` section at offset 20.
   - GOT entry at `($gp + sign_ext(imm16))` holds the callee VA.
   - GOT contents read from `.got` section; entries matched against `plt` and `func_starts`.

```
# BE: LW $t9, N($gp) opcode breakdown
# bits 31:26 = LW = 0x23 = 0b100011
# bits 25:21 = rs = $gp = 28 = 0x1C
# bits 20:16 = rt = $t9 = 25 = 0x19
# → upper halfword = (0x23<<10)|(0x1C<<5)|0x19 = 0x8F99
```

`$gp` is from `.reginfo` layout:
```
ri_gprmask   (4 bytes, offset  0)
ri_cprmask   (16 bytes, offset 4)
ri_gp_value  (4 bytes, offset 20)  ← gp
```

Validated on FortiAP cwWtpd (MIPS32 BE, 3.3MB, 1,170 exports): **0 → 23,617 call edges**.
`callers_of('system')` and `callers_of('popen')` became functional, directly identifying
CAPWAP VSP shell injection (FAP-CWMIPS-1, see `re/fortinet/fortiap_re.py`).

### MIPS-GAP-002 — SinkArgClassifier / TaintTracker: MIPS32 not supported (open)

**Symptom:** `SinkArgClassifier.classify_all()` returns 0 results on MIPS32 ELFs.

**Root cause:** Both tools hardcode x86-64 register names (`rdi`, `rsi`, `rdx`) and x86-64
calling convention for argument tracking. MIPS32 uses `a0`–`a3` for the first four
arguments, with no register file equivalent.

**Workaround:** Manual capstone disassembly for sink classification and taint tracing on
MIPS32 targets. Annotate GOT offsets to resolve `LW $t9, N($gp)` call targets manually.

**Future fix:** Add MIPS calling convention path to both analyzers (MIPS registers a0–a3
map to argument positions 0–3; stack slots used for arguments 5+).
