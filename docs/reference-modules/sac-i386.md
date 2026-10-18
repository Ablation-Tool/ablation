# SinkArgClassifierX86_32: i386 cdecl exec-sink classifier

## Why this exists

i386 cdecl passes all arguments on the stack, pushed right-to-left. The main `SinkArgClassifier` tracks x86-64 registers `rdi`, `rsi`, and `rdx`. It returns SAC=0 for every i386 binary because no argument register write is visible in the i386 instruction stream.

Gap IDs resolved: **RMC-GAP-002**, **COMMSVR-GAP-004**, **HACMP-GAP-001**, **DOORS-i386-001**.

Affected products in the IBM-RE collection: DOORS, TestMate, Tau Mainsoft layer, RationalRoseRT, BTT, RMC, CommServer.

## Usage

```python
# Via factory (recommended):
from ablation.analyzers.sink_arg_classifier import sac_for_path
clf = sac_for_path('/tmp/extract/bin/doorsd')

# Direct:
from ablation.analyzers.sink_arg_classifier_x86_32 import SinkArgClassifierX86_32
clf = SinkArgClassifierX86_32.from_path('/tmp/extract/bin/doorsd')

for r in clf.classify_all():
    print(f"{r.sink_name}@0x{r.call_va:x}: {r.verdict}")
```

## How it works

The classifier walks backward from each `call <plt_stub>` instruction and tracks the last `push` before the CALL as arg0.

| Pattern | Verdict |
|---|---|
| `push imm` where imm falls in `.rodata` | `RODATA_CONST` |
| `lea eax, [ebx +/- N]; push eax` where ebx is the GOT base | `RODATA_CONST` |
| `mov eax, [ebp + N]` then `push eax`, N positive | `ARG_PROPAGATED` |
| `mov eax, [ebp - N]` then `push eax`, snprintf backtrack finds rodata fmt | `SNPRINTF_RODATA` |
| anything else | `UNKNOWN` |

## Verdicts

| Verdict | Meaning |
|---|---|
| `RODATA_CONST` | Compile-time constant. Not injectable. |
| `SNPRINTF_RODATA` | Built by snprintf from a rodata format string. Not injectable. |
| `ARG_PROPAGATED` | Argument comes from a function parameter. Trace callers. |
| `UNKNOWN` | Provenance not resolved in the look-back window. |
