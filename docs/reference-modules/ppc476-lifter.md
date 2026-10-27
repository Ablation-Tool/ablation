<a id="ppc476lifter"></a>
# IBM PPC476 Pseudo-C Lifting

`Ppc32Lifter` lifts 32-bit big-endian PowerPC functions to linear, register-tracked pseudo-C. It is intended for IBM PPC476-style ELF firmware and resolves imported calls through `BinaryContext`, annotating call arguments with recovered register expressions.

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.ppc32_lifter import Ppc32Lifter

ctx = BinaryContext.load_or_build('/path/to/ppc476-binary')
lifter = Ppc32Lifter.from_context(ctx)
print(lifter.lift(0x10002754, n_insn=80))
```

The public class is `Ppc32Lifter`; “PPC476” describes its target profile, not the class name. `from_context()` reopens and parses the binary to obtain `.text`, so the original file must still exist at the context path. `lift()` starts at a code virtual address and returns a string with instruction addresses attached to emitted statements.

## What the lifter models

The register state tracks constants, arguments, stack expressions, symbols, memory expressions, and unknown values. Common `lis`/`addi` address construction, moves, loads/stores, update forms, calls, `mtctr`/`bctr`, and `blr` are translated. Direct calls use `BinaryContext.plt` and export names when available. After a call, `r3` represents the result and caller-saved registers are invalidated according to the lifter's ABI model.

PPC476 Book E privileged and cache instructions that have no modeled general-register effect remain comments. Unsupported operations also remain visible rather than being silently removed.

## Output and limitations

The output is a linear walk, not CFG-structured C. Conditional branches become comments or labels, and complex paths must be checked against disassembly. `n_insn` bounds the walk; the first modeled return ends it.

- This backend is for PPC32 big-endian ELF, not AIX XCOFF32, PowerPC VLE, or PPC64.
- PLT argument quality depends on the context's extraction results. Empty or stale context metadata leaves calls as numeric addresses.
- TOC, GOT, stack, and memory expressions are approximations, not proof of the runtime value.
- Floating-point, vector, and unmodeled instruction state can interrupt a value trace.
- Use the pseudo-C to guide review, then verify security-relevant arguments in the original instructions.

## Related workflows

- [PowerPC Decompilation & Taint Analysis](ppc32-taint-tracker.md)
- [AIX XCOFF32 Decompilation](xcoff32-decompiler.md)
- [Native Binary Lifting](binary-lifter.md)
