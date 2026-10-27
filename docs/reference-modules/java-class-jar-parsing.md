<a id="javareanalyzer"></a>
<a id="javaReanalyzer"></a>
# Java Class / JAR Security Analysis

Parse JVM `.class` files and JAR archives to recover class metadata, constants, method references, dependencies, and security-relevant patterns. Despite the legacy filename `modules/java_decompiler.py`, these modules do not reconstruct Java source or provide a full bytecode-to-source decompiler.

## Parse a class

```python
from pathlib import Path
from modules.java_re import parse_class_file

result = parse_class_file(Path('/path/to/Target.class').read_bytes())
print(result)
```

`modules.java_re` exposes constant-pool scanning, class parsing, JAR analysis, dependency inventory, and finding synthesis. `modules.java_decompiler.ClassFile` provides another class parser with method/field metadata and human-readable descriptors; its `JavaAnalyzer` performs security analysis rather than source emission.

## Analyze a JAR

```python
from modules.java_re import analyze_jar, synthesize_findings

result = analyze_jar('/path/to/application.jar')
findings = synthesize_findings([result])
for finding in findings:
    print(finding)
```

Use `scan_java_artifacts()` for a filesystem sweep and `scan_constant_pool_strings()` for a focused constant-pool check. The lower-level `modules.java_decompiler.scan_jar_for_vulnerabilities()` exposes additional pattern checks. Review each function's return schema before combining results; these are independent legacy APIs, not one uniform finding dataclass.

## What the analysis can establish

The JVM constant pool preserves class, method, field, descriptor, and string references. Parsing it can identify execution APIs, reflection, class loading, deserialization-related types, JNDI or XML parser usage, suspicious literals, and Spring-related annotations/configuration signals.

JAR analysis adds archive and dependency context, including nested libraries where supported. These observations help prioritize review, but a constant-pool reference is not proof of a call path, missing global authorization, exploitability, or attacker-controlled input.

`modules.java_decompiler.py` also contains live HTTP probe functions. They are not needed for offline class/JAR analysis and should only be used against systems you are authorized to test. No network probe is part of the examples on this page.

## Limitations

- No supported API here emits decompiled Java methods. Use `javap` or a dedicated Java decompiler when source-like output is required.
- Constant-pool co-presence does not prove two operations occur in the same method or on one execution path.
- Spring endpoint exposure cannot be decided from a missing method annotation alone; global security configuration and routing matter.
- Archive nesting, malformed classes, new constant-pool forms, and obfuscation can reduce coverage.
- Dependency-version and gadget-pattern findings need reachability and runtime-configuration review.

## Related workflows

- [Android DEX Disassembly, Lifting & Scanning](dex.md)
- [HarmonyOS Ark Bytecode Decompilation](harmonyos.md)
- [Pre-Authentication Exposure](preauth-exposure.md)
