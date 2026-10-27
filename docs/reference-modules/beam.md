<a id="beamcontext"></a>
# Erlang BEAM Analysis & Lifting

Inspect Erlang/Elixir `.beam` modules with `BeamContext`, sweep OTP releases for dangerous imports, summarize a module through `BinaryLifter`, or decode the Code chunk into partial pseudo-IR with `BEAMLifter`.

## Inspect a module

```python
from ablation.analyzers.beam_context import BeamContext

ctx = BeamContext.from_path('/path/to/module.beam')
print(ctx.summary())
print(ctx.search_atoms('open_port'))
print(ctx.search_literals('https://'))

for item in ctx.dangerous_imports(min_severity='MEDIUM'):
    print(item)
```

The parser reads the IFF chunks for atoms, exports, imports, literals, optional debug AST metadata, and obfuscation indicators. Imports are resolved to `module:function/arity` names. `dangerous_imports()` classifies execution, dynamic-code, and other security-relevant imports; an import is an attack-surface signal, not a vulnerability by itself.

`BeamContext.from_bytes(data, path='<bytes>')` supports in-memory input. `sweep_beam_dir()` scans a release directory, `fmt_sweep()` formats results, and `sweep_beam_diff()` compares dangerous-import inventories between releases.

## Module summary through BinaryLifter

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/module.beam', arch='beam')
print(lifter.lift_function(0))
```

The BEAM backend has no native virtual-address function space. `va=0` selects a module-level summary containing exports, dangerous imports, and atoms; it is not pseudo-C for one BEAM function.

## Function-level pseudo-IR

```python
from pathlib import Path
from ablation.analyzers.beam_context import BeamContext, BEAMLifter, _split_chunks

path = '/path/to/module.beam'
ctx = BeamContext.from_path(path)
code_chunk = _split_chunks(Path(path).read_bytes()).get('Code', b'')
lifter = BEAMLifter.from_context(ctx, code_chunk)
print(lifter.lift())
```

`BEAMLifter` decodes known opcodes in the Code chunk and groups output by recovered function labels. `_split_chunks` is currently an internal helper, so this low-level integration is less stable than `BeamContext` and may change; a future public chunk accessor should replace it.

Unknown opcodes stop decoding and mark the output as partial. Remaining known operations without concise IR are emitted as comments. This is useful pseudo-IR, not original Erlang or Elixir source.

## Limitations

- Missing debug information does not by itself prove malicious obfuscation.
- Atoms and literals can contain examples or unreachable values; dangerous imports require call-site review.
- The generic `BinaryLifter` BEAM path is a summary, while `BEAMLifter` is the function-level decoder; their outputs are different.
- Native Implemented Functions (NIFs) reside in native libraries and require native analysis.
- Verify security-relevant pseudo-IR against module imports, exports, and instructions before reporting behavior.

## Related workflows

- [Native Binary Lifting](binary-lifter.md)
- [HarmonyOS Ark Bytecode Decompilation](harmonyos.md)
- [MicroPython .mpy v6 Lifting](micropython.md)
