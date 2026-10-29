# Relocation-Aware bFLT BinaryContext

`BfltBinaryContext` turns a parsed bFLT v4 executable into the familiar `BinaryContext` interface: function candidates, direct calls, strings, literal references, and caller/callee indexes. It also exposes every relocation outcome instead of hiding them inside a loader.

Use it after [bFLT parsing](bflt.md), when the question is no longer just “where are the bytes?” but “what do they mean at a selected load base?”

---

## Why this exists

An executable file and its loaded form are not necessarily identical. A bFLT image can store relocation entries that adjust pointers for a runtime base. Treating file pointers as final addresses can connect a call site to the wrong string or function.

The earlier `BfltArm32` reader deliberately stopped at link-time literal recovery. `BfltBinaryContext` is the larger missing component: it applies supported relocations, creates zero-filled BSS, and builds the shared analysis context that other tools understand.

The work separates into three small systems:

1. `BfltImage` validates the file layout and compressed payload.
2. `relocate_bflt()` maps each relocation slot and stored value, applying it when the mapping is known.
3. `BfltBinaryContext` recovers instruction-level context and exposes relocation evidence alongside it.

Keeping those steps separate makes a wrong address assumption easier to see and test.

---

## The relocation model

For a contiguous RAM layout, let `base_va` be the address of the 64-byte bFLT header in the chosen runtime model. A valid image-relative value `r` maps to:

```text
runtime_address = base_va + 0x40 + r
```

The valid relative range is `0 .. bss_end - 0x40`. This follows the Linux bFLT loader's text/data mapping after simplifying it for a contiguous RAM image. It is not interchangeable with simply adding a base to every file offset.

Each table entry requires two steps:

```text
entry offset → mapped relocation slot → stored pointer value → relocated value
```

For example, the first `tinyws` relocation entry has offset `0x34`. At base zero it addresses slot `0x74`, whose stored value is `0x17B3C`. The relocated value is `0x17B7C`. The slot and the value have different meanings, and both must be mapped.

A second example shows why this matters to analysis. In `jenet`, the literal slot at `0x1938` stores `0x3D204`. Relocation entry 109 changes that value to `0x3D244`. A link-time reader sees `WS_CMD`; the relocated image instead points at `CLMR`. This is evidence of address transformation, not proof of a new vulnerability or a different deployed configuration.

Zero-valued pointers remain zero. Out-of-range slots fail even when unresolved values are allowed. Relocated pointers in this ARM32 model are written in little-endian runtime order, independently of their stored file order.

The implementation follows the [Linux bFLT loader](https://github.com/torvalds/linux/blob/master/fs/binfmt_flat.c) and the [elf2flt producer](https://github.com/uclinux-dev/elf2flt). It does not execute the program or claim to emulate an operating system, stack, or complete process.

---

## Compressed layouts

The parser now uses the standard v4 flags:

| Flag | Meaning | Current handling |
|---|---|---|
| `RAM` (`0x01`) | Contiguous RAM load | Supported |
| `GOTPIC` (`0x02`) | Position-independent GOT layout | Rejected explicitly |
| `GZIP` (`0x04`) | Everything after the header is compressed, including relocation data | Supported |
| `GZDATA` (`0x08`) | Header and text are stored; data and relocation data are compressed | Supported |
| `KTRACE` (`0x10`) | Loader tracing request | Preserved as metadata; no execution or tracing |

`GZIP` expands the stream after the 64-byte header and then reads the relocation data from the expanded bytes. `GZDATA` preserves header and text, then expands data and relocation data. For both, `reloc_start` is a logical uncompressed offset, not an offset into a compressed file. It must equal `data_end`.

Simultaneous compression modes, GOT-PIC, malformed streams, incoherent offsets, and excessive allocation requests raise `BfltError`. Parser input and memory limits remain in force.

---

## Strict relocation and explicit unresolved results

The default is strict. An unmapped stored value raises `BfltRelocationError` with its entry index and slot. This prevents a plausible-looking but incorrect runtime image from silently driving later analysis.

Sometimes an investigator needs a partial model for review. `allow_unresolved=True` preserves unresolved words and records why they were not changed:

- `UNRESOLVED_OUT_OF_RANGE`: no main-image mapping exists.
- `UNRESOLVED_SHARED_LIBRARY`: the value has a nonzero library identifier, but no library mapping was supplied.

`relocation_complete` is then false, and `unresolved_relocations` contains every such record. **A partial model is not a guaranteed runtime image.** The flag makes uncertainty inspectable; it does not prove that the unresolved values are valid or meaningless.

All six recovered C111C executables complete strict relocation with zero unresolved entries, so the permissive mode is not needed for them.

---

## Usage

```python
from ablation.analyzers.bflt_context import BfltBinaryContext

ctx = BfltBinaryContext.from_path(
    '/path/to/program',
    base_va=0,
    pointer_byteorder='big',
    allow_unresolved=False,
)

print(ctx.summary())
print(ctx.metadata())
for record in ctx.relocations[:4]:
    print(record)
```

`from_bytes()` accepts a complete stored file. `from_image()` accepts a `BfltImage` recovered through another parser, such as a JFFS2 file. When the complete original bytes are available, their SHA-256 identifies the context. `from_image()` otherwise hashes the parsed image and relocation table rather than pretending to hash the original file.

The following interfaces are available:

- `memory_image`: relocated header, text, initialized data, and zero-filled BSS.
- `relocations` and `unresolved_relocations`: immutable evidence records with entry index, offset, slot, stored value, relocated value, and status.
- `relocation_complete`: whether every entry was applied.
- `read_memory(address, size)`: bounded reads in the selected address model.
- `func_starts`: entry, direct-call targets, and ARM prologue candidates.
- `call_edges`: direct `BL`/`BLX` edges inside text.
- `strings`: printable strings in initialized data.
- `literal_references(target)`: supported PC-relative references to a relocated pointer.
- `string_xrefs()`, `strings_in_func()`, `funcs_referencing_string()`, `callers_of()`, and `callees_of()`: normal `BinaryContext` queries.

A `BfltBinaryContext` is a `BinaryContext` subclass. It does not need an ELF parser or a fabricated ELF section table.

---

## Window analysis

`WindowAnalyzer.from_bflt(ctx)` uses the relocated image and its text bounds. It does not try to parse bFLT as ELF.

```python
from ablation.analyzers.window_analyzer import WindowAnalyzer

wa = WindowAnalyzer.from_bflt(ctx)
print(wa.dump_text(0x1518, window=256))
print(wa.calls_in_window(0x1518, window=0x300))
```

For the C111C `jenet` image, `literal_references(0x3D244)` identifies the load at `0x1780`, and `calls_in_window()` includes the direct comparison call at `0x1788`. The strings shown in a window come from the relocated model, not blindly from the stored file.

---

## What this provides the user

This is the connector between a flat executable and Ablation's broader analysis workflow. It saves the manual work of applying relocation entries, assigning function candidates, linking calls to owners, and joining string literals to functions. It is more than a tiny parser, but it is not a decompiler.

Its narrow role also makes future change easier. A richer bFLT analyzer can reuse the relocation records and context rather than implementing another loader. A future GOT-PIC or shared-library implementation must add its own mappings instead of weakening these checks.

---

## Limitations

- Only little-endian ARM state is analyzed. Thumb, big-endian ARM, and other ISAs require separate evidence and support.
- Function entries and prologues are candidates, not a complete function-boundary proof or CFG. Conditional and indirect calls are not resolved automatically.
- bFLT has no dynamic symbol table in this model. Empty `plt` and `exports` do not prove that a program has no library calls.
- GOT-PIC is rejected. Shared-library values cannot be resolved without the corresponding library images and mappings.
- `allow_unresolved=True` produces an explicitly partial model, not a complete runtime guarantee.
- The adapter does not provide an operating system, stack, device emulation, or proof of actual runtime behavior.
- Existing analyzers that reparse `ctx.path` as ELF need a bFLT-specific path such as `WindowAnalyzer.from_bflt()`; subclassing `BinaryContext` does not make ELF-only parsers understand bFLT.
- Valid code and relocated pointers still do not establish service reachability, authentication, or a vulnerability.

## See also

- [bFLT v4 Executables](bflt.md)
- [bFLT ARM32 Link-Time References](bflt-arm32.md)
- [BinaryContext](binary-context.md)
- [WindowAnalyzer](window-analyzer.md)
- [JFFS2 Filesystem Reader](jffs2.md)
