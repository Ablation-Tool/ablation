<a id="nanomipstainttracker"></a>
# nanoMIPS Decoding & Taint Analysis

Decode variable-width nanoMIPS instructions, lift functions to structural pseudo-C, and trace source-to-sink data flows. `NanoMIPSTaintTracker` uses Capstone's nanoMIPS mode when available and otherwise falls back to Ablation's pure-Python frame decoder with more conservative analysis.

## Capability levels

| API | Purpose | Output |
|---|---|---|
| `NanoMIPSDecoder` | Decode 16-, 32-, and 48-bit instruction frames | Decoded instruction frames |
| `BinaryLifter(arch='nanomips')` | Read one function | Structural pseudo-C |
| `NanoMIPSTaintTracker` | Analyze calls and register taint | Findings or interprocedural paths |

nanoMIPS is not MIPS16 or microMIPS. Its variable-width encoding and lack of classic MIPS delay slots require a separate backend.

## Structural lifting

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/nanomips.elf', arch='nanomips')
print(lifter.lift_function(0x400A00))
```

The lifter resolves direct calls where possible and leaves unmodeled instructions as comments. It does not provide full C semantics.

## Taint analysis

```python
from ablation.analyzers.taint_tracker_nanomips import NanoMIPSTaintTracker

tracker = NanoMIPSTaintTracker.from_path(
    '/path/to/nanomips.elf', endian='little'
)
print(f'Full decode: {tracker.has_full_decode}')

findings = tracker.run()
paths = tracker.run_interprocedural(depth=4)
print(tracker.report(findings))
```

`from_path()` accepts only `path` and `endian`; it does not expose `custom_sinks` or `from_context()`. `run()` returns `NanoMIPSTaintFinding` objects, while `run_interprocedural()` returns `NanoMIPSInterproceduralPath` objects. Findings include `full_decode` so fallback results can be distinguished during triage.

The internal `_extra_sinks` table is not a stable public configuration API. Analyze vendor wrappers explicitly rather than relying on undocumented constructor arguments shown in older examples.

## Decode path and requirements

Full decoding requires a Capstone build that provides `CS_MODE_NANOMIPS` and the necessary MIPS operand constants. A Capstone version string alone does not guarantee that the installed binding exposes these features. Check `tracker.has_full_decode` at runtime.

The fallback uses `NanoMIPSDecoder` and manually resolves BALC call targets. It is intentionally more conservative and can over-approximate argument taint. Do not describe fallback findings as precise register-level proof.

ELF parsing uses `pyelftools` when installed. The loader reads `.text`, dynamic symbols, relocations, and function symbols. PLT stubs are assumed to be 12 bytes in this integration; unusual linker layouts can prevent name resolution. Inspect `tracker._plt` only as a diagnostic implementation detail, not as a stable public interface.

## Limitations

- `from_path()` defaults to little-endian. Select `endian='big'` when required by the target.
- Missing symbols or function boundaries reduce coverage; the fallback prologue scan is heuristic.
- A decoded instruction stream is not a decompiled program, and a taint finding is not proof of exploitability.
- Unknown instructions, indirect calls, PLT-layout differences, and conservative fallback propagation can create false positives or missed paths.
- Validate a candidate sink against the original instruction bytes and the actual source buffer flow before reporting it.

## Related workflows

- [MIPS Decompilation & Taint Analysis](mips.md)
- [Native Binary Lifting](binary-lifter.md)
