<a id="abcdecompiler"></a>
# HarmonyOS Ark Bytecode Decompilation

Parse Ark Bytecode (ABC), disassemble ARK instructions, and decompile methods to JavaScript-like pseudocode. The stack is `ABCParser` for the container, `ARKDisasm` for instructions, and `ABCDecompiler` for method- and class-level output.

## Why the stack has three layers

A HAP/ABC container must be mapped before method code can be decoded, and decoded instructions must be understood before expressions can be reconstructed. Combining those steps into one opaque decompiler would make version-specific parsing failures look like instruction failures. The separate layers let users inspect exactly where an assumption changes.

Container metadata resolves classes and methods, instruction decoding preserves the underlying evidence, and partial expression propagation produces a more readable review form. Users can choose the level needed for inventory, manual verification, or broader pseudocode review. Future version or opcode support can extend the appropriate layer without requiring every consumer to change. The output is not original ArkTS, and native libraries still require native analysis.

## Decompile ABC

Extract the `.abc` payload from a HAP package first, then pass that file to the decompiler:

```python
from ablation.analyzers.abc_decompiler import ABCDecompiler

decompiler = ABCDecompiler.from_path('/path/to/modules.abc')
for pseudocode in decompiler.decompile_all():
    print(pseudocode)
```

For a targeted review:

```python
for method in decompiler.parser.iter_methods():
    code = decompiler.parser.get_code(method)
    if code is not None:
        print(decompiler.decompile_method(method, code))

print(decompiler.decompile_class('ListChatContent'))
```

`decompile_method()` returns JavaScript-like text for one `MethodInfo`. `decompile_class()` selects methods whose class name contains the supplied substring. `decompile_all()` yields one string per method with code.

## Inspect the container and instructions

```python
from ablation.analyzers.abc_parser import ABCParser
from ablation.analyzers.abc_disasm import ARKDisasm

parser = ABCParser.from_path('/path/to/modules.abc')
print(parser.summary())

disassembler = ARKDisasm(parser)
for method in parser.iter_methods():
    code = parser.get_code(method)
    if code is not None:
        print(disassembler.disasm_method(method))
```

The parser exposes class names, method metadata, code items, string/entity resolution, and security-oriented queries. The disassembler resolves instruction formats and references; the decompiler adds accumulator/register expression propagation and partial control-flow structuring.

ABC has version-specific layout rules, including the literal-array header boundary used by the parser. ArkTS is the source language in modern HarmonyOS applications, while ABC is the compiled runtime artifact. Dynamic-dialect method flags and native-bridge identification should be interpreted using the parser's dedicated helpers rather than JNI assumptions.

## Limitations

- `ABCDecompiler.from_path()` expects an ABC file, not an unextracted HAP ZIP.
- Pseudocode is not original ArkTS or JavaScript. Types, function boundaries, conditions, and exception behavior remain approximate.
- Complex control flow and unmodeled opcodes can degrade structuring; compare important expressions with ARK disassembly.
- Version-specific or malformed layout can limit parsing. Do not infer support for every future ABC version from a version-range label.
- Native `.so` libraries in a HAP require native analysis; they are not decompiled by the ABC backend.

## Related workflows

- [Android DEX Disassembly, Lifting & Scanning](dex.md)
- [Java Class / JAR Security Analysis](java-class-jar-parsing.md)
- [Erlang BEAM Analysis & Lifting](beam.md)
