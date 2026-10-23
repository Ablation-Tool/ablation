# DEX Disassembly and Lifting

Decode Android DEX bytecode to annotated smali output (`DEXDisasm`) and lift DEX instruction streams to readable pseudo-Java IR (`DEXLifter`): handling all 17 DEX instruction formats with full method/field/type/string reference resolution from the DEX flat tables.

---

## Why this exists

1. **Android APKs contain compiled `.dex` bytecode rather than source Java: static analysis of APK security requires disassembling the DEX bytecode to smali and then lifting it to pseudo-Java for comprehension.** `DEXDisasm` decodes all 17 DEX instruction formats and renders smali-style output with full reference resolution (method descriptors, field names, type names, string constants from the DEX flat tables). Without reference resolution, smali output shows numeric indices (`method@0023`) rather than `Lcom/example/Foo;->bar(Ljava/lang/String;)V`.

2. **`DEXLifter` lifts the decoded instruction stream to pseudo-Java IR without external dependencies**: handling the 90% of real Android methods that use field get/put, invoke-virtual/direct/static, const-string, if-* conditionals, and backward goto (loop) patterns. The result is readable pseudo-Java like `this.apiKey = getString(R.string.api_key)` rather than raw register-based smali operations. Complex methods (switch tables, try/catch blocks) fall back to annotated pseudo-smali that is still more readable than raw smali because all references are resolved.

3. **`DEXDisasm` and `DEXLifter` are consumed by `DexAnalyzer`**: the security scanner described in [DEX Analysis](dex.md), but they are also available as standalone disassembly and lifting tools for targeted method-level analysis without running the full security scan. This allows analysts to disassemble a specific class or lift a specific method without the overhead of APK-wide scanning.

---

## How it works

```mermaid
flowchart TD
    A["DEXDisasm.from_path(apk_path)"] --> B["APKParser: unzip APK → iterate .dex files\n  DEX header: magic, checksum, string/type/proto/field/method/class offsets\n  Build flat tables: string_ids, type_ids, method_ids, field_ids"]
    B --> C["disasm_method(class_name, method_name) → str\n  Locate method's code_item in class_data_item\n  Decode all instructions using 17-format dispatch:\n  Render smali with resolved references:\n  'invoke-virtual {v0, v1}, Ljava/net/URL;->openConnection()'\n  'const-string v2, \"https://api.example.com/\"'"]
    C --> D["disasm_class(class_name) → str\n  Disassemble all non-native methods in class\n  Annotate: class, method signatures, access flags"]
    B --> E["list_methods(class_name) → List[str]\n  All method names in class (including native)"]

    F["DEXLifter.from_apk(apk_path)"] --> G["lift_method(class_name, method_name) → str\n  DEXDisasm decodes instructions\n  Type propagation: move-result, iget, sget, check-cast\n  Single-use const folding\n  invoke-* → method call expression\n  new-instance + <init> → constructor call\n  if-* → labeled conditional\n  backward goto → 'loop:' marker\n  Complex: switch/try-catch → annotated pseudo-smali"]
    F --> H["list_methods(class_name) → List[str]\n  Same as DEXDisasm"]
```

---

## Usage

```python
from ablation.analyzers.dex_disasm import DEXDisasm
from ablation.analyzers.dex_lifter import DEXLifter

# ── Smali disassembly ─────────────────────────────────────────────────────────
dd = DEXDisasm.from_path('/path/to/app.apk')

# List methods in a class
methods = dd.list_methods('Lcom/example/MainActivity;')
print(methods)

# Disassemble one method
smali = dd.disasm_method('Lcom/example/Foo;', 'processInput')
print(smali)

# Disassemble entire class
smali_class = dd.disasm_class('Lcom/example/NetworkClient;')
print(smali_class)

# ── Pseudo-Java lifting ───────────────────────────────────────────────────────
lifter = DEXLifter.from_apk('/path/to/app.apk')

pseudo_java = lifter.lift_method('Lcom/example/NetworkClient;', 'sendRequest')
print(pseudo_java)
```

---

## Example output

The following illustrates the disassembly and lifting output format. Actual class and method names are APK-specific.

```
# DEXDisasm output (smali):
.method public processInput(Ljava/lang/String;)V
    const-string v0, "https://<api-endpoint>/"
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {p0, v0}, Lcom/example/NetworkClient;->sendRequest(Ljava/lang/String;)Z

# DEXLifter output (pseudo-Java):
void processInput(String p1) {
    String v0 = "https://<api-endpoint>/";
    v0 = v0.append(p1);
    sendRequest(v0);
}
```

---

## False positives

**`disasm_method()` disassembles the bytecode as-is: obfuscated DEX (ProGuard/R8 with identifier scrambling) will produce correct disassembly with scrambled names (`a.b.c.A.a()`).** The instruction decoding is correct regardless of obfuscation; only the human-readable names are affected by obfuscation.

**`DEXLifter` falls back to annotated pseudo-smali for try/catch blocks and switch tables.** These patterns are common in complex methods. The fallback output is still annotated with resolved references but uses register names (v0, v1) rather than inferred type names. Pseudo-Java quality degrades gracefully on complex methods rather than failing.

---

## Pipeline position

`DEXDisasm` and `DEXLifter` are typically consumed through `DexAnalyzer.scan()` (see [DEX Analysis](dex.md)) rather than called directly. Use them directly when you need to inspect a specific method found during `DexAnalyzer` scanning: for example, to read the code of a `HARDCODED_SECRET` method or a `DYNAMIC_CODE_LOAD` site.

---

## Reading output

`DEXDisasm.disasm_method(class_name, method_name)` returns a list of `DEXInstruction` objects:

| Attribute | Content |
|:---|:---|
| `cu_offset` | Offset in code units from start of `insns[]` |
| `opcode` | DEX opcode integer |
| `mnemonic` | DEX mnemonic string (e.g., `'invoke-virtual'`, `'iget-object'`) |
| `fmt` | DEX format code string (e.g., `'35c'`) |
| `regs` | `List[int]`: register indices |
| `ref_idx` | Reference table index, or `-1` if not applicable |
| `literal` | Literal value (signed integer), or `0` |
| `branch` | Branch offset in code units (signed, relative to this instruction), or `0` |

`DEXLifter.lift_method(class_name, method_name)` returns a pseudocode string (pseudo-Java with register annotations).

---

## See also

- [DEX Analysis](dex.md): full `DexAnalyzer` security scanner: secret detection, dangerous APIs, crypto misuse
- [Java Class/JAR Parsing](java-class-jar-parsing.md): JVM bytecode parsing for library and server-side code
- [Firmware Extraction](firmware-extraction.md): APK extraction from firmware images
