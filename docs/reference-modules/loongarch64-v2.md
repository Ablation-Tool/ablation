# LoongArch64 KASAN/KCOV V2 Decoder

KASAN/KCOV-aware LoongArch64 instruction decoder that tags and strips instrumentation ghost calls from debug kernel binaries so taint analysis sees only real program logic.

---

## Why this exists

1. **A TencentOS 4.6 kernel built with `CONFIG_KASAN=y` / `CONFIG_KCOV=y` injects a 4–6 instruction shadow-check preamble before virtually every memory access.** The sequence is `srli.d` / `lu12i.w` / `addi.d` / `ld.b` / conditional branch / `bl __asan_load8`, and it is pure instrumentation overhead. Running the V1 decoder or `LoongArch64TaintTracker` directly against such a binary produces thousands of false call edges into `__asan_load8_noabort`, `__sanitizer_cov_trace_pc`, and similar KASAN/KCOV stubs. Roughly 40% of instructions in `kvm_eiointc_write` and similar hot functions are ghosts.

2. **`LoongArchDecoderV2` runs a two-pass semantic layer on top of the V1 fixed-width decode.** Pass 1 tags every `bl` targeting a known KASAN or KCOV VA as `is_instrumentation=True`. Pass 2 walks backward from each tagged `bl` and tags the shadow-address preamble instructions with `idiom="kasan_shadow"`. `decode_frames_clean()` then skips all tagged frames, leaving only real program instructions for the taint tracker.

3. **`from_system_map()` provides authoritative KASAN/KCOV VA discovery without guessing symbol patterns at runtime.** The kernel `System.map` file lists every symbol VA; V2 parses it for all `__asan_*`, `__kasan_*`, and `__sanitizer_cov_*` entries and pre-populates the instrumentation VA set before decode begins.
4. **KASAN/KCOV V2 is listed as a LoongArch64 *decompiler variant*, not a separate ISA, because the instrumentation is ISA-specific in its encoding.** On x86 and ARM, decompilers have handled KASAN/KCOV patterns for years and absorb them silently. LoongArch's Linux kernel support only landed in 5.19 (2022), so the sanitizer patterns — the `srli.d`/`lu12i.w`/`addi.d`/`ld.b` shadow-check sequence and the `dbar`-guarded KCOV counter stores — are recent and LoongArch-specific in their encoding. A decompiler without explicit handling of this variant treats them as opaque inline sequences, producing functionally useless output on any KASAN/KCOV debug kernel build. The variant designation signals that this decoder lifts those sequences correctly, collapsing them out of the IR rather than emitting them as unknown control flow.

---

## How it works

```mermaid
flowchart TD
    A(["LoongArchDecoderV2.from_system_map(System.map)"]):::input --> B["Parse System.map\n  Match __asan_* / __kasan_* / __sanitizer_cov_*\n  Build instrumentation_vas: FrozenSet[int]"]:::primary

    B:::primary --> C["decode_frames_v2(data, base_addr)\n  Step 1: V1 fixed-width decode of 32-bit LE stream\n    → List[LoongArchFrameV2] (is_instrumentation=False)"]:::secondary

    C:::secondary --> D["Pass 1: _tag_instrumentation(frames)\n  For each frame: if is_call and target in instrumentation_vas\n    → is_instrumentation=True, idiom='kasan'"]:::tertiary

    D:::tertiary --> E["Pass 2: _tag_kasan_preamble(frames)\n  For each tagged BL, walk back up to max_preamble=6 insns\n  Tag srli.d / lu12i.w / addi.d / ld.b / andi / add.d\n    → is_instrumentation=True, idiom='kasan_shadow'\n  Stop at: call / ret / branch / store / start of list"]:::tertiary

    E:::tertiary --> F["decode_frames_clean(data, base_addr)\n  Yields frames where is_instrumentation=False\n  Only real program logic remains"]:::tertiary

    F:::tertiary --> G(["LoongArch64TaintTracker consumes clean frames\n  No false edges into __asan_load8 / sanitizer_cov_trace_pc\n  ~40% instruction reduction on debug kernels"]):::output
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
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

---

## Class: LoongArchDecoderV2

Extends `LoongArchDecoder` (V1). Constructor and key methods:

```python
from ablation.analyzers.loongarch_decoder_v2 import LoongArchDecoderV2

# Primary path: load instrumentation VAs from System.map
dec = LoongArchDecoderV2.from_system_map("/path/to/System.map")

# Manual path: supply VA set from PLT resolution or external source
dec = LoongArchDecoderV2(instrumentation_vas={0x876f10, 0x8773d0})

# Decode with full tagging
frames = dec.decode_frames_v2(section_bytes, base_addr)

# Decode with instrumentation stripped
for frame in dec.decode_frames_clean(section_bytes, base_addr):
    print(frame)

# Coverage stats
stats = dec.count_instrumentation(section_bytes, base_addr)
```

### Constructor

`LoongArchDecoderV2(instrumentation_vas=None, max_preamble=6)`

| Parameter | Type | Default | Description |
|:---|:---|:---|:---|
| `instrumentation_vas` | `Set[int]` or `None` | `None` | VAs of KASAN/KCOV functions. Empty set disables tagging (V1 behavior). |
| `max_preamble` | `int` | `6` | Max instructions to walk back from a tagged BL when scanning for preamble. 6 covers the full TencentOS KASAN idiom. |

### Class methods

`from_system_map(map_path, max_preamble=6)` → `LoongArchDecoderV2`

Parses a kernel `System.map` file (`<hex_va> <type> <symbol>` per line). Extracts all VAs whose symbol name starts with any prefix in `KASAN_SYMBOL_PREFIXES` or `KCOV_SYMBOL_PREFIXES`.

### Instance methods

| Method | Returns | Description |
|:---|:---|:---|
| `decode_frames_v2(data, base_addr)` | `List[LoongArchFrameV2]` | Full decode with both tagging passes applied. Returns a list, not an iterator, because pass 2 needs random access. |
| `decode_frames_clean(data, base_addr)` | `Iterator[LoongArchFrameV2]` | Yields only frames where `is_instrumentation=False`. |
| `count_instrumentation(data, base_addr)` | `dict` | Returns `{total, instrumentation, real, pct_instrumentation}`. |

---

## LoongArchFrameV2

Extends `LoongArchFrame` (V1) with two fields:

| Field | Type | Description |
|:---|:---|:---|
| `is_instrumentation` | `bool` | `True` if this instruction is a KASAN/KCOV ghost call or part of its shadow-address preamble. |
| `idiom` | `str` | Named semantic pattern. `""` for real instructions; `"kasan"` for the ghost BL itself; `"kasan_shadow"` for the preamble sequence. |

`str(frame)` appends ` [kasan]` or ` [kasan_shadow]` to the standard V1 repr when `is_instrumentation` is set.

---

## Usage

```python
from ablation.analyzers.loongarch_decoder_v2 import LoongArchDecoderV2

# Standard: strip KASAN/KCOV from a debug vmlinuz before taint analysis
dec = LoongArchDecoderV2.from_system_map("/path/to/System.map")

with open("/path/to/vmlinuz.elf", "rb") as f:
    section_bytes = f.read()   # .text section bytes
base_addr = 0x9000000001000000  # from ELF section header

# See tagged output (debugging)
for frame in dec.decode_frames_v2(section_bytes, base_addr):
    if frame.is_instrumentation:
        print(f"  [ghost {frame.idiom}] {frame.va:#x}  {frame.mnemonic} {frame.op_str}")

# Clean output: feed into taint tracker
clean_frames = list(dec.decode_frames_clean(section_bytes, base_addr))

# Measure overhead
stats = dec.count_instrumentation(section_bytes, base_addr)
print(stats)
# {"total": 208, "instrumentation": 84, "real": 124, "pct_instrumentation": 40.4}
```

### Integrating with analysis modules

`LoongArch64TaintTracker.from_path_full()` does not accept a decoder parameter. Run V2 stripping as a separate inspection step to identify which VAs are real program logic, then run the taint tracker against the same binary with the System.map-sourced findings as context. The `decode_frames_clean()` output is the authoritative list of real instruction VAs for manual boundary checks and for feeding lower-level CFG APIs directly:

```python
from ablation.analyzers.loongarch_decoder_v2 import LoongArchDecoderV2

# Pre-inspect: confirm real instruction density before taint run
dec = LoongArchDecoderV2.from_system_map("/path/to/System.map")
stats = dec.count_instrumentation(section_bytes, base_addr)
print(stats)  # Verify pct_instrumentation ~40% on a KASAN debug build

# Then run the standard taint tracker on the same binary
from ablation.analyzers.taint_tracker_loongarch64 import LoongArch64TaintTracker
tt = LoongArch64TaintTracker.from_path_full("/path/to/vmlinuz.elf")
findings = tt.run_interprocedural()
print(tt.report(findings))
```

---

## Example output

```
# decode_frames_v2 with is_instrumentation visible:
0x9000000001234a10  srli.d   $t0, $a0, 3           [kasan_shadow]
0x9000000001234a14  lu12i.w  $t1, 0x11800           [kasan_shadow]
0x9000000001234a18  addi.d   $t0, $t0, -0x400       [kasan_shadow]
0x9000000001234a1c  ld.b     $t0, $t0, 0            [kasan_shadow]
0x9000000001234a20  bne      $t0, $zero, 0x1234b80   (branch — not tagged)
0x9000000001234a24  bl       __asan_load8_noabort    [kasan]
0x9000000001234a28  ld.d     $a0, $sp, 8             ← real instruction

# count_instrumentation output:
{"total": 208, "instrumentation": 84, "real": 124, "pct_instrumentation": 40.4}
```

---

## False positives

**Shadow-check preamble sequences that precede a non-instrumentation branch are not tagged.** The backward walk stops at any branch instruction to prevent mis-tagging control flow that belongs to real program logic. A KASAN sequence that contains an internal conditional branch will be partially tagged: the `bl` is marked but some preamble instructions before the branch remain real. This is the safe side because under-stripping produces no false positives, only retained noise.

**An incorrect `max_preamble` value can leave preamble instructions untagged.** The default of 6 covers the full TencentOS 4.6 KASAN idiom. Kernels compiled with `CONFIG_KASAN_GENERIC` may emit longer preambles. If `count_instrumentation()` shows unexpectedly low `pct_instrumentation` on a known KASAN build, try `max_preamble=10`.

**A missing or wrong `System.map` produces zero tagging.** If `from_system_map()` is given a path to the wrong kernel's map, none of the instrumentation VAs will match and all frames will be returned as real. Verify that `dec._instr_vas` is non-empty after construction.

---

## Pipeline position

**Before this module:** confirm `e_machine == 0x102` (LoongArch) in the ELF header. Obtain `System.map` from the matching kernel-debug-core RPM or build directory.

**After this module:** feed `decode_frames_clean()` output into `LoongArch64TaintTracker` or `cfg_loongarch64` CFG builder. For one-off investigation, use `decode_frames_v2()` to see which addresses are instrumentation before committing to the clean path.

---

## Reading findings

`count_instrumentation()` return value:

| Key | Type | Content |
|:---|:---|:---|
| `total` | `int` | Total instructions decoded in the section |
| `instrumentation` | `int` | Instructions tagged `is_instrumentation=True` |
| `real` | `int` | Instructions that are real program logic |
| `pct_instrumentation` | `float` | Percentage overhead, rounded to one decimal place |

`LoongArchFrameV2` idiom values:

| `idiom` | Meaning |
|:---|:---|
| `""` | Real program instruction |
| `"kasan"` | `bl` to a KASAN reporter: `__asan_load*` or `__kasan_*` |
| `"kasan_shadow"` | Shadow-address preamble: `srli.d`, `lu12i.w`, `addi.d`, `ld.b` |
| `"kcov"` | `bl` to a KCOV tracer (`__sanitizer_cov_*`) |

---

## See also

- [LoongArch64 Analysis Stack](loongarch64.md): full taint tracker and CFG builder that consumes clean V2 frames
- [LoongArch64 Compiler Bug Detection](loongarch64-2.md): `LA64MaxNotMinScanner` for GCC 12.3.1.7 min/max inversion on LoongArch64
- [LoongArch Syscall Labeling](loongarch-syscall-labeling.md): syscall classification used alongside taint results
