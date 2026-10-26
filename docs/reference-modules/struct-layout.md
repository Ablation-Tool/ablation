# StructLayoutAnalyzer

## Why this exists

1. `PseudoCEmitter` without struct recovery emits raw pointer dereferences:
   `*(r1 + 0x18)`. When the same base register appears at multiple offsets
   across a function, naming the struct and fields makes the output readable.

2. For exec-class taint analysis, knowing a `system()` argument came from
   `cmd_ctx->command` (offset 0x18) is more actionable than `*(r1 + 0x18)`.

3. IBM POWER and Alpha AXP codebases are heavily struct-driven — large C
   programs with deep struct hierarchies, no RTTI, no debug info in stripped
   firmware.

## Constructor

```python
StructLayoutAnalyzer(
    irig:  IRIG,
    names: Optional[Dict[Tuple[str, int], str]] = None,
)
```

- `irig`: any `IRIG` from `AlphaIRLifter.lift_cfg()` or `X86_64IRLifter.lift_cfg()`.
- `names`: optional override dict `{(base_reg, offset): field_name}`.

## `analyze() → List[StructDef]`

Scans every `IRLoad` and `IRStore` in the IRIG. When the address expression
is of the form `IRBinop('+', IRReg(base), IRConst(offset))`, records the
`(base, offset, width)` triple.

Any base register with **≥2 distinct offsets** is considered a struct candidate.

Filter parameters (module-level constants):
- `_MIN_FIELDS = 2` — minimum distinct offsets to classify as struct
- `_MAX_STRUCT_SIZE = 0x10000` — ignore accesses with offset ≥ 64 KB

## `StructDef`

```python
@dataclass
class StructDef:
    base_reg: str
    fields:   Dict[int, FieldDef]   # offset → FieldDef

struct_def.report()          # C-style struct definition with access stats
struct_def.annotate(0x18, 'command')  # attach a field name
```

Output from `report()`:
```
struct_from_r1 {
  /* +0x00 */ u64 field_0;   // 3 accesses (3R 0W)
  /* +0x08 */ u64 field_8;   // 1 accesses (1R 0W)
  /* +0x18 */ u64 field_18;  // 2 accesses (1R 1W)
};
```

## `FieldDef`

```python
@dataclass
class FieldDef:
    offset:   int
    width:    int           # bits (dominant access width)
    accesses: List[FieldAccess]
    name:     str           # empty until annotated

field.field_name()   # 'field_18' or the annotated name
```

## Integration with PseudoCEmitter

```python
from ablation.analyzers.ir import AlphaIRLifter, PseudoCEmitter
from ablation.analyzers.struct_layout import StructLayoutAnalyzer

lifter  = AlphaIRLifter(data, sections, gp)
irig    = lifter.lift_cfg(cfg)
structs = StructLayoutAnalyzer(irig).analyze()

# Annotate known fields manually (from prior RE work)
for s in structs:
    if s.base_reg == 'r1':
        s.annotate(0x18, 'command')

print(PseudoCEmitter(irig, structs=structs).emit())
# Output: r0 = r1->command;  system(r0);
```

## Known limitations

- Only tracks base register identity, not SSA version. If `r1` is reused
  for two different struct pointers across the function, their fields will
  be merged into one `StructDef`. Use `SSABuilder` output and annotate with
  `SSAName` strings (e.g. `base_reg='r1_2'`) if you need per-version structs.
- Array indexing (e.g. `r1 + r2*8`) is not detected; only constant offsets.
- Field width is the mode of observed access widths — a u32 field accessed
  once as u64 will still be reported as u32.
