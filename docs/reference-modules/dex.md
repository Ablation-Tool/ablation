<a id="dexanalyzer"></a>
# Android DEX Disassembly, Lifting & Scanning

Analyze Dalvik Executable (DEX) bytecode at three levels: smali-style disassembly with `DEXDisasm`, pseudo-Java with `DEXLifter`, and APK-wide security screening with `DexAnalyzer`. These tools read `.dex` inside APKs; they do not decompile ART's compiled `.oat` or `.vdex` artifacts.

## Disassemble or lift a method

```python
from ablation.analyzers.dex_disasm import DEXDisasm
from ablation.analyzers.dex_lifter import DEXLifter

class_name = 'Lcom/example/NetworkClient;'

disassembler = DEXDisasm.from_path('/path/to/app.apk')
print(disassembler.list_methods(class_name))
print(disassembler.disasm_method(class_name, 'sendRequest'))

lifter = DEXLifter.from_apk('/path/to/app.apk')
print(lifter.lift_method(class_name, 'sendRequest'))
```

Both constructors accept `dex_index=` for multidex APKs. `disasm_class()` and `lift_class()` process the methods in one class. See [DEX Disassembly & Pseudo-Java Lifting](dex-disassembly-and-lifting.md) for output and fallback details.

## Scan an APK

```python
from ablation.analyzers.dex_analyzer import DexAnalyzer

analyzer = DexAnalyzer.from_path('/path/to/app.apk')
findings = analyzer.scan()
print(analyzer.report(findings))
```

`DexAnalyzer` parses the binary Android manifest and every `classes*.dex` shard. It reports exported components, dangerous permission combinations, cleartext settings and URLs, hardcoded-secret candidates, weak cryptographic strings, and security-sensitive method references. Results are `DexFinding` objects with severity, category, title, detail, source, and evidence.

A method reference proves that a DEX table names an API, not that a particular call is reachable or attacker-controlled. String-table findings likewise require context. Use method disassembly or lifting to inspect the candidate before reporting a vulnerability.

## DEX and ART

Dalvik and ART both consume DEX application bytecode, but ART can compile it to native code in OAT-related artifacts. This implementation analyzes DEX headers, tables, class data, and code items. “ART support” in a runtime description does not mean this tool lifts compiled OAT machine code.

DEX uses a register-based instruction set and flat string/type/prototype/field/method tables. Resolving those references is what lets disassembly show names rather than numeric indices. Obfuscation can reduce name quality without changing the underlying bytecode layout.

## Limitations

- `.apk` and `.dex` are supported inputs for the documented constructors; standalone OAT/VDEX decompilation is not implemented.
- Pseudo-Java is partial IR. Switches, exception regions, and complex control flow can fall back to annotated pseudo-smali.
- Manifest exposure depends on Android defaults and target SDK behavior; scanner results still need platform-aware review.
- Secret and weak-crypto patterns are heuristic and may include examples, dead constants, or benign uses.
- Native `.so` libraries require a native analysis workflow rather than DEX lifting.

## Related workflows

- [DEX Disassembly & Pseudo-Java Lifting](dex-disassembly-and-lifting.md)
- [Java Class / JAR Security Analysis](java-class-jar-parsing.md)
- [Android Analysis](android.md)
