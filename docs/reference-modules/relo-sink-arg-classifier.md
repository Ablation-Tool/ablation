# ReloSinkArgClassifier

Classify exec-class sink argument provenance in ELF32 relocatable object files using RELA-based call-site detection.

---

## Why this exists

1. **SinkArgClassifierPPC32BE requires a linked ELF.** It uses PLT virtual addresses (`bl <plt_va>`) to find call sites and LIEF section ranges to detect `.rodata` references. Neither exists in a `.o` file.
2. **In .o files, all calls are `bctrl` through a loaded register.** The pattern is `lis rX / addi rX / mtctr rX / bctrl`, with `R_PPC_ADDR16_HA` RELA at `lis+2` naming the target symbol.
3. **RELA annotations replace PLT VA lookup.** Instead of scanning for `bl <plt_va>`, scan for `lis` instructions whose RELA annotation names the sink, then walk forward to the corresponding `bctrl`.
4. **`.rodata` detection must be RELA-based.** All `lis` instruction bytes are zero (patched by the linker). The HA RELA's symbol section index tells us whether the reference is to a `.rodata*` section.

Gap ID: RELO-GAP-002 (solidDB VxWorks PPC440 solidac.a analysis).

---

## How it works

**Call-site detection (replaces `_find_call_sites()`):**
1. Scan all instructions for `lis rX` where `rela_map[insn.address] == (sink_name, _)`.
2. Walk forward from that `lis` for `mtctr rX` (same register rX).
3. Scan forward from `mtctr` for the `bctrl`; stop at another `mtctr`.

This is robust against compiler scheduling that interleaves argument setup between `mtctr` and `bctrl`.

**Rodata detection (replaces `_is_rodata(va)`):**
- `_is_rodata_rela(insn_offset)`: returns `True` if `rela_map[insn_offset][1]` (the `is_rodata` flag).
- `is_rodata` is set during RELA parsing when the reloc's symbol section index is a `.rodata*` section.

**Backward argument trace:** identical to `SinkArgClassifierPPC32BE._trace_arg()` — PPC32 ABI (r3-r10) is unchanged regardless of link state.

---

## ReloSinkArgClassifier

```python
from ablation.analyzers.relo_object_context import ReloObjectContext
from ablation.analyzers.relo_sink_arg_classifier import ReloSinkArgClassifier

roc = ReloObjectContext.from_path('rpc0http.o')
clf = ReloSinkArgClassifier.from_context(roc)
```

### Key methods

| Method | Returns | Description |
|:---|:---|:---|
| `classify_fn(fn_name)` | `List[SinkClassification]` | All sink call sites within a named function |
| `classify_all()` | `List[SinkClassification]` | All sink call sites across all functions |
| `add_sink(name, arg_pos)` | `None` | Register a vendor-specific sink |
| `report(results)` | `str` | Human-readable summary |

---

## Usage

```python
from ablation.analyzers.relo_object_context import ReloObjectContext
from ablation.analyzers.relo_sink_arg_classifier import ReloSinkArgClassifier
from ablation.analyzers.sink_arg_classifier import ARG_PROPAGATED, RODATA_CONST

roc = ReloObjectContext.from_path('rpc0http.o')
clf = ReloSinkArgClassifier.from_context(roc)

# Add vendor-specific sinks if needed
clf.add_sink('SsQmemStrdup', arg_pos=0)

# Classify all sinks across all functions
results = clf.classify_all()
print(clf.report(results))

# Flag non-safe findings
flagged = [r for r in results if r.verdict not in (RODATA_CONST, 'SNPRINTF_RODATA')]
for r in flagged:
    print(f'{r.sink_name}(arg{r.arg_pos}) @ +{r.call_va:#x}: {r.verdict}')

# Check a specific function and argument position
clf2 = ReloSinkArgClassifier.from_context(roc)
clf2._sinks['strcpy'] = 1  # check source (arg1) instead of dest (arg0)
results = clf2.classify_fn('rpc_http_svc_get')
```

---

## Example output

```
ReloSinkArgClassifier: 1 results
  ARG_PROPAGATED   strcpy(arg0) func=+0x00000070 call=+0x0000016c detail=mr r117, r3 (entry arg)
Summary: ARG_PROPAGATED=1
```

For strcpy(arg1=source):
```
ReloSinkArgClassifier: 1 results
  RODATA_CONST     strcpy(arg1) func=+0x00000070 call=+0x0000016c detail=lis+addi → .rodata ''
Summary: RODATA_CONST=1
```

---

## Known limitations

**Post-call r3 treated as ARG_PROPAGATED**: After any `bctrl`/`blrl`, r3 holds a return value (e.g., from `SsQmemAlloc`). The backward trace cannot distinguish return-value r3 from entry-arg r3; both yield `ARG_PROPAGATED`. This is identical to the limitation in `SinkArgClassifierPPC32BE`.

**`lis` without RELA yields UNKNOWN**: If a `lis` has no RELA annotation (rare in .o files), the trace returns UNKNOWN. The classification is conservative — it will never produce a false RODATA_CONST.

---

## Pipeline position

**Before:** Build `ReloObjectContext` first. Optionally pre-filter with `ctx.has_import(sink_name)`.

**After:** Filter results by verdict (`ARG_PROPAGATED`, `UNKNOWN`) for manual `TaintTracker` follow-up.

---

## See also

- [ReloObjectContext](relo-object-context.md): the parser that provides disassembly and RELA annotations
- [ArchiveContext](archive-context.md): run across all members of a .a archive
- [sac-ppc32-be](sac-ppc32-be.md): the linked-ELF equivalent for PPC32
