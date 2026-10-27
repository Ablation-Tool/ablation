<a id="xcoff32decompiler"></a>
# AIX XCOFF32 Decompilation

`Xcoff32Decompiler` converts AIX PPC32 big-endian XCOFF functions to C-like pseudocode. It understands function descriptors, TOC-relative data references, imports, glue call sequences, and names recovered from an XCOFF-aware `BinaryContext`.

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.xcoff32_decompiler import Xcoff32Decompiler

ctx = BinaryContext.load_or_build('/path/to/aix-binary')
decompiler = Xcoff32Decompiler.from_context(ctx)

code_va = decompiler.va_for_name('automount')
if code_va is not None:
    print(decompiler.decompile(code_va, n_insn=200))
```

`decompile()` requires a code virtual address. Do not pass the address of a function descriptor in `.data`: the descriptor contains the code entry, TOC base, and environment pointer, but it is not executable code. `va_for_name()` resolves a known function name to its code VA.

`from_context()` reads the XCOFF file directly and uses `ctx._xcoff_binary` when available. It accepts the XCOFF magics recognized by the implementation (`0x01df` and `0x01f7`) and raises `ValueError` for other formats. The decompiler logic targets PPC32; do not infer XCOFF64 instruction support from acceptance of a container magic.

## What it emits

The decompiler tracks general-purpose register expressions, stack-frame adjustments, direct and descriptor-based calls, comparisons, branches, and returns. TOC-relative loads are named when a symbol can be resolved. The output includes `auto`-style parameters and `r3` return expressions; these are analysis annotations, not recovered C declarations.

Supported instruction handling includes common integer loads/stores, arithmetic, logic, shifts, branches, selected floating-point operations, special-register moves, and syscall instructions. Unhandled instructions remain comments. Floating-point register dataflow is not propagated like GPR dataflow.

## Limitations

- Decompilation is a bounded linear walk, not full CFG recovery or structured C generation. Increase `n_insn` only to inspect more of a function, then verify branches manually.
- TOC naming requires a usable descriptor and TOC base. Otherwise output retains symbolic TOC offsets.
- Callee-save suppression and stack-local naming are heuristics and can hide or mislabel meaningful operations.
- XCOFF parsing and function naming depend on the available context metadata; stripped local functions may be unnamed.
- Pseudo-C is not proof of runtime behavior. Confirm security-relevant calls and arguments against the PPC32 instructions.

## Related workflows

- [PowerPC Decompilation & Taint Analysis](ppc32-taint-tracker.md)
- [IBM PPC476 Pseudo-C Lifting](ppc476-lifter.md)
