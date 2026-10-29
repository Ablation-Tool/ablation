# DEX Disassembly & Pseudo-Java Lifting

`DEXDisasm` decodes DEX code items into smali-style text with resolved references. `DEXLifter` translates those instructions into readable pseudo-Java, preserving annotated pseudo-smali where higher-level recovery is incomplete.

## Method-level usage

```python
from ablation.analyzers.dex_disasm import DEXDisasm
from ablation.analyzers.dex_lifter import DEXLifter

class_name = 'Lcom/example/Foo;'

disassembler = DEXDisasm.from_path('/path/to/app.apk', dex_index=0)
print(disassembler.list_methods(class_name))
print(disassembler.disasm_method(class_name, 'processInput'))
print(disassembler.disasm_class(class_name))

lifter = DEXLifter.from_apk('/path/to/app.apk', dex_index=0)
print(lifter.lift_method(class_name, 'processInput'))
print(lifter.lift_class(class_name))
```

Class names use DEX descriptors such as `Lcom/example/Foo;`. Method selection uses the method name. `dex_index=0` selects `classes.dex`; increment it for additional shards.

`DEXDecompiler` adds an overload-aware class model and selects methods by `method_idx`, avoiding first-name matches for overloaded methods. It also emits native declarations and exact call edges. Switch and array payloads are skipped as data rather than linear-swept as instructions.

## Output

`disasm_method()` returns a string containing a method signature and decoded instructions. `decode_code_item()` is the lower-level route that yields `DEXInstruction` objects with code-unit offset, opcode, mnemonic, format, registers, reference index, literal, and branch metadata. `disasm_method()` itself does not return that object list.

`lift_method()` and `lift_class()` return strings. The lifter tracks common constants, moves, field accesses, invocations, constructor sequences, conditions, and backward branches. It resolves method, field, type, and string references through the DEX tables.

Unsupported or complex structures remain annotated pseudo-smali. Switch tables and exception-heavy methods should not be expected to become structured Java. Register names and inferred expressions are analysis output, not recovered source declarations.

## Limitations

- APK/DEX parsing and method-level lifting are supported; compiled ART OAT/VDEX code is outside this backend.
- Correct disassembly does not restore identifiers removed by obfuscation.
- Pseudo-Java is partial and must be checked against smali for security decisions.
- Multidex callers must select the shard containing the target class.

## Related workflows

- [Android DEX Disassembly, Lifting & Scanning](dex.md)
- [Java Class / JAR Security Analysis](java-class-jar-parsing.md)
