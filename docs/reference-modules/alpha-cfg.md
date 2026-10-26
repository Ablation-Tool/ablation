# AlphaCFGBuilder

## Why this exists

1. `AlphaEcoffScanner.trace_arg()` stops with `BSR_RETVAL` when the target register
   was set by a prior call's return value. Resolving that requires entering the callee
   and tracing its `r0` return path — which requires knowing the callee's basic block
   structure so the backward scan stays within a single basic block.

2. Alpha's fixed 32-bit instruction width makes CFG construction clean: no length
   prefix decoding, no variable-width edge cases. Every branch target is computed as
   `(PC+4) + sign_extend(disp21) * 4`.

3. The module closes the gap between `trace_arg()` reporting CANDIDATE MEDIUM and
   actually knowing whether a `system()` argument is data-dependent or a constant.

## Constructor

```python
AlphaCFGBuilder(
    data:      bytes,              # raw binary bytes (ELF or ECOFF)
    sections:  Dict[str, _Section],# from AlphaEcoffScanner._load()[2]
    gp_value:  Optional[int],      # global pointer value from same _load()
)
```

Get these from the scanner's `_load()` method:

```python
from ablation.analyzers.insn_alpha import AlphaEcoffScanner
from ablation.analyzers.alpha_cfg import AlphaCFGBuilder

scanner = AlphaEcoffScanner('/path/to/binary')
data, gp_value, sections = scanner._load()
builder = AlphaCFGBuilder(data, sections, gp_value)
```

## `build(func_va, max_insns=4096)`

BFS from `func_va`. Splits blocks at:
- `RET` (opcode 0x1A, hint=2) → `BasicBlock.is_ret = True`
- `JMP` (opcode 0x1A, hint=0) → `BasicBlock.is_jmp = True` (target unknown)
- `BR` (opcode 0x30) → one successor
- Conditional branches (0x38–0x3F, 0x31–0x37) → two successors (taken, fall-through)

BSR (0x34) and JSR (0x1A hint=1) are treated as fall-through (not CFG edges).

Returns `Dict[int, BasicBlock]` mapping `start_va → BasicBlock`. Predecessor lists
are back-filled after all blocks are discovered.

## `trace_return_value(cfg, ret_reg=0, window=32)`

For each RET block in `cfg`, scans backward through the block's instructions to find
what value is in `ret_reg` (default `r0` / `$v0`, the Alpha return value register).

Returns `List[ReturnTrace]`, one per RET block:

```python
@dataclass
class ReturnTrace:
    ret_va:    int    # VA of the RET instruction
    reg:       int    # register traced
    insn_type: str    # 'LDA_CONST' | 'LDA_GP' | 'LDAH_GP' | 'LDQ_GP' | 'BIS_MOV' | 'BSR_RETVAL' | 'UNKNOWN'
    value:     int    # literal constant or address; 0 if unknown
    interp:    str    # human-readable description
```

Instruction types and what they mean for taint:

| `insn_type`  | Meaning | Taint conclusion |
|:---|:---|:---|
| `LDA_CONST`  | `lda r0, N($zero)` — literal integer | SAFE (constant) |
| `LDA_GP`     | `lda r0, N($gp)` — address in .rodata/.data | Check string content; likely SAFE if ASCII literal |
| `LDAH_GP`    | `ldah r0, N($gp)<<16` — address high half | Same as LDA_GP |
| `LDQ_GP`     | `ldq r0, N($gp)` — GOT dereference | Data-dependent; may be CANDIDATE |
| `BSR_RETVAL` | BSR encountered before finding reg — return value from another call | CANDIDATE (recurse one more level) |
| `UNKNOWN`    | Not found within window | CANDIDATE (deferred) |

## `report(cfg)`

Returns a human-readable CFG summary: block count, RET/JMP exit count, total
instruction count, and a per-block listing of start VA, end VA, insn count, and
successor type.

## Typical usage for DX-001 class findings

```python
from ablation.analyzers.insn_alpha import AlphaEcoffScanner
from ablation.analyzers.alpha_cfg import AlphaCFGBuilder

scanner = AlphaEcoffScanner('/path/to/binary')
findings = scanner.scan()
data, gp, sections = scanner._load()
builder = AlphaCFGBuilder(data, sections, gp)

for f in findings:
    if f.sink_name == 'system':
        t = scanner.trace_arg(f.caller_va)
        print(t)
        if t.insn_type == 'BSR_RETVAL':
            # Trace the callee's return value
            cfg = builder.build(t.value)        # t.value = callee VA
            ret_traces = builder.trace_return_value(cfg)
            for rt in ret_traces:
                print('  callee RET:', rt)
```

## Known limitations

- Indirect JMP targets are not resolved (no value-range analysis for the target register).
  Blocks that exit via JMP are marked `is_jmp = True` and have no successors.
- `trace_return_value()` does only a per-block backward linear scan — it does not
  merge traces from multiple predecessor blocks (no phi nodes). For most compiler-generated
  code this is sufficient: each exit block tends to have a single assignment to `r0`.
- `BSR_RETVAL` in `trace_return_value()` terminates the trace at one more call boundary.
  Recursive application is possible but not automated.
