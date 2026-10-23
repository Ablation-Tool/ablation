# SinkArgClassifierMIPS

**File:** `ablation/analyzers/sink_arg_classifier_mips.py`

Classifies what argument is passed to exec-class sinks (`system`, `popen`, `execve`, `execl`,
`execvp`) on MIPS32 O32 ABI firmware and assigns a provenance verdict: the argument is either a
hardcoded `.rodata` literal, an snprintf output built from a `.rodata` format string, a propagated
function argument, or an unresolved unknown.

---

## Why this exists

Two gaps prevented MIPS32 firmware analysis. Both are now resolved.

1. **MIPS-GAP-001: Call graph silent.** `BinaryContext._build_call_graph_mips()` scanned only for
 JAL opcode 3. ET_EXEC O32 PIC firmware uses zero JAL instructions. All calls go through
   `LW $t9, N($gp)` + `JALR $t9`. `callers_of('system')` returned `[]` on every MIPS32 target.
 Fixed in `BinaryContext` v2.55 commit bad68e8. See `binary-context.md` MIPS-GAP-001.

2. **MIPS-GAP-002: No MIPS32 argument classifier.** `SinkArgClassifier.classify_all()` traces
 x86-64 argument registers `rdi`, `rsi`, `rdx`. MIPS32 O32 ABI uses `$a0`–`$a3` for the first
 four arguments. There was no equivalent register path. Every MIPS32 sink call site returned 0
 results. Fixed here.

 Manual analysis of `cwWtpd` (FortiAP MIPS32 Gen1, `/sbin/cwWtpd`) required tracing CAPWAP
 message dispatch tables by hand to confirm FAP-CWMIPS-1. That work identified the specific
 trace pattern: `LW $vX, N($gp)` to load section base from the GOT, followed by
   `ADDIU $aY, $vX, M` to add an offset. Without this module, every shell sink call site on every
 MIPS32 Fortinet firmware image required that level of manual effort.

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.sink_arg_classifier_mips import SinkArgClassifierMIPS

ctx = BinaryContext.load_or_build('/path/to/cwWtpd')
clf = SinkArgClassifierMIPS.from_context(ctx)

# Add vendor-specific sinks (O32 ABI arg_pos maps to $a0=0, $a1=1, $a2=2, $a3=3)
clf.add_sink('cwSysCmdRun', arg_pos=0)   # format string
clf.add_sink('cwSysCmdRun', arg_pos=1)   # first variadic arg (check for %s injection)

results = clf.classify_all()
for r in results:
    print(r.fmt())

# Print summary report
print(clf.report(results))
```

---

## Verdicts

`RODATA_CONST` means the sink argument is a pointer directly into `.rodata`. The argument is
either a direct `LW $aX, N($gp)` where the GOT entry falls in a `.rodata` range, or an ADDIU
to a zero-immediate null pointer, or an `ADDIU $aX, $vY, M` where `GOT[N]+M` lands in `.rodata`.
No injection is possible regardless of caller context.

`SNPRINTF_RODATA` means the sink argument is a stack buffer filled by snprintf or vsnprintf with a
`.rodata` format string. Injection requires controlling a `%s` argument in that format string.
Integer-only formats (`%d`, `%u`, `%x`) are safe.

`ARG_PROPAGATED` means the argument arrived in an entry register (`$a0`–`$a3`) saved to the stack
at function entry via the O32 arg-save pattern (`SW $aX, disp($fp)` in the first 20 instructions).
The caller controls it. Move up one level.

`UNKNOWN` means provenance was not resolved in the look-back window. Treat the same as
`ARG_PROPAGATED` for severity purposes.

---

## MIPS32 O32 ABI calling convention

All calls in ET_EXEC O32 PIC firmware follow this two-instruction pattern:

```
LW $t9, N($gp)    # load callee VA from GOT slot at $gp+N
JALR $t9          # call; delay slot sets return address in $ra
```

`$gp` is a fixed register for ET_EXEC binaries. Its value is loaded from `.reginfo` at offset 20
(`ri_gp_value`). `SinkArgClassifierMIPS._init()` reads it once and holds it in `_gp`.

Arguments are passed in `$a0` (arg 0) through `$a3` (arg 3). Stack arguments begin at `$sp+0`.
Callee-saved argument registers follow the O32 arg-save pattern: `SW $aX, disp($fp)` in the
first 20 instructions of the callee.

---

## String address load pattern

MIPS32 O32 PIC materialises a `.rodata` string address as a two-instruction sequence:

```
LW  $vX, N($gp)       # loads section base from GOT: GOT[$gp+N]
ADDIU $aY, $vX, M     # adds offset: GOT[$gp+N] + M
```

`SinkArgClassifierMIPS` resolves this pattern in `_trace_arg_addiu`. It walks backward from the
ADDIU to find the LW that loaded the base register from the GOT, then computes the final VA.

A direct GOT pointer is also handled:

```
LW $aX, N($gp)        # GOT[$gp+N] points directly into .rodata
```

---

## $gp source

```
.reginfo section layout (MIPS32 BE):
  ri_gprmask    4 bytes @ offset  0
  ri_cprmask   16 bytes @ offset  4
  ri_gp_value   4 bytes @ offset 20   <- this is $gp
```

`SinkArgClassifierMIPS._init()` uses lief to read the `.reginfo` section and unpack
`ri_gp_value` at byte offset 20.

---

## snprintf backtrack

When a sink receives a stack buffer (`ADDIU $aX, $fp, N` or `ADDIU $aX, $sp, N`),
`_trace_snprintf_buf` searches backward for an `snprintf` or `vsnprintf` call with `$a0` matching
the same slot. If found, it traces the format argument (`$a2` for snprintf, `$a2` for vsnprintf)
to a `.rodata` pointer. A match returns `SNPRINTF_RODATA`.

---

## Adding vendor sinks

```python
# Any function that calls system() or popen() internally with its first argument
clf.add_sink('cwSysCmdRun', arg_pos=0)   # format string position
clf.add_sink('fadcSystemCall', arg_pos=1)
```

`add_sink` registers both the name and the argument position. `_find_sink_plts` resolves the
function VA from `ctx.exports` or `ctx.plt`, then indexes call sites via `ctx.callers_of(name)`.

---

## Known limitations

Argument classification requires the sink call to follow a `LW $t9, N($gp)` + `JALR $t9` pattern
within `_LOOKBACK = 80` instructions of the call site. Calls more than 80 instructions from the
GOT load will resolve as `UNKNOWN`.

Cross-basic-block argument clobbers are not detected. If `$a0` is written after the ADDIU but
before the JALR in a different branch, the verdict will be wrong.

`TaintTracker` is the correct tool for `UNKNOWN` and `ARG_PROPAGATED` sites. See
`docs/reference-modules/taint-tracker-mips.md`.

---

## How it works

`SinkArgClassifierMIPS.from_context(ctx).classify_all()` iterates `ctx.func_starts` MIPS32 binary and disassembles each function with Capstone. For each call to a configured exec-class sink (`system`, `execve`, `popen`, etc.), it traces the first argument register (`a0`) backward in the instruction stream using MIPS register conventions. Resolves to `RODATA_CONST` if the argument traces to a `.rodata` address; `ARG_PROPAGATED` if traced to a parameter; `UNKNOWN` if unresolved. Accounts for MIPS delay slot: the instruction after each branch/call is part of the branch semantics.

---

## Example output

```
SinkClassification  system  call_va=0x00801f44  func=run_cmd (0x00801f00)
  verdict: ARG_PROPAGATED  severity: HIGH
  detail: a0 traced to parameter at 0x00801f08 (delay slot: lw a0,4(sp))

SinkClassification  system  call_va=0x00802310  func=init_service (0x008022c0)
  verdict: RODATA_CONST  severity: LOW
  detail: a0 resolved to "start-service" at .rodata:0x00810a00
```

---

## False positives

Delay-slot misattribution: a load in the delay slot of a branch may be incorrectly attributed as the argument source when it's actually part of the branch cleanup. Verify the a0 trace manually for `ARG_PROPAGATED` sites where `delay slot` appears in the detail.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` on a MIPS32 ELF with `ctx.func_starts` populated. Confirm target is MIPS with `ctx.arch`.

**After this module:** Pass `ARG_PROPAGATED` and `UNKNOWN` sites to `TaintTrackerMIPS`. Exclude `RODATA_CONST` sites from taint analysis.

---

## Reading findings

`SinkArgClassifierMIPS.from_path(path).classify_all()` returns `List[SinkClassification]`:

| Attribute | Content |
|:---|:---|
| `sink_name` | Name of the exec-class sink function (e.g., `'system'`, `'popen'`) |
| `arg_pos` | 0-indexed argument position analyzed (0 = `$a0`, 1 = `$a1`, etc.) |
| `func_va` | VA of the calling function |
| `call_va` | VA of the `jal` / `jalr` instruction |
| `verdict` | `'RODATA_CONST'`: hardcoded constant; `'SNPRINTF_RODATA'`: buffer from fixed-format snprintf; `'ARG_PROPAGATED'`: traces to entry-point `$a0`–`$a3`; `'UNKNOWN'`: provenance unresolved |
| `detail` | Human-readable trace description |
| `severity` | Derived from verdict: `'LOW'` RODATA_CONST / `'MEDIUM'` SNPRINTF_RODATA/UNKNOWN / `'HIGH'` ARG_PROPAGATED |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
