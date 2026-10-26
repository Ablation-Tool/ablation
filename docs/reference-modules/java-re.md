# JavaREAnalyzer

**File:** `modules/java_re.py`

## Why this exists <sup>[↑](#javareanalyzer)</sup>

Java.class/.jar reverse engineering: constant pool analysis, method signature extraction, field access mapping, and cross-reference building. Provides the Java-tier analysis complement to native ARM64/x86 RE for mixed Java+JNI targets.

## Key constants <sup>[↑](#javareanalyzer)</sup>

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_FILE_BYTES` | 64 MB |.class/.jar file read cap |
| `_MAX_ENTRY_BYTES` | 16 MB | ZIP entry read cap |

## FORGE audit <sup>[↑](#javareanalyzer)</sup>

Gate: **PASSED**. No HIGH or CRITICAL findings. ZIP entry sizes checked via `zf.getinfo(cname).file_size > _MAX_ENTRY_BYTES` before extraction. `_MAX_FILE_BYTES=64MB`. No lief.parse(). No HTTP reads.

---

## How it works <sup>[↑](#javareanalyzer)</sup>

Parses the runtime-specific binary format APK, DEX, `.mpy`, BEAM, and Go ELF to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage <sup>[↑](#javareanalyzer)</sup>

```python
from modules.java_re import JavaREAnalyzer

analyzer = JavaREAnalyzer('/path/to/target.jar')
findings = analyzer.analyze()
for f in findings:
    print(f)
```

---

## Example output <sup>[↑](#javareanalyzer)</sup>

```
[HIGH] DANGEROUS_CALL   Runtime.exec() in com.example.CommandHandler:42
  detail: argument constructed from user-supplied intent extra
  evidence: exec(getIntent().getStringExtra("cmd"))

[MEDIUM] UNTRUSTED_INPUT   eval() in main.js:118
  detail: JSON.parse result passed directly to eval
```

---

## False positives <sup>[↑](#javareanalyzer)</sup>

Standard library calls that resemble dangerous patterns such as `exec` used for shell completions and `eval` used for template rendering with static input are not findings. Confirm that the argument reaching the dangerous call is user-controlled before escalating. Obfuscated code Garble-compiled Go and ProGuard-stripped Android produces incomplete call graphs: findings from incomplete graphs carry lower confidence.

---

## Pipeline position <sup>[↑](#javareanalyzer)</sup>

**Before this module:** Confirm the target binary format APK, `.mpy`, BEAM, and Go ELF before loading. `BinaryContext` is not required for all runtime analyzers.

**After this module:** Feed dangerous call findings to `TaintTracker` or `FindingRegistry` for confirmed findings.

---

## Reading output <sup>[↑](#javareanalyzer)</sup>

`analyze_jarjar_path` returns a dict:

| Key | Content |
|:---|:---|
| `jar_path` | Path string of the analyzed JAR/WAR/EAR |
| `class_count` | Number of `.class` files processed |
| `frameworks` | `Set[str]`: detected framework names such as `'Spring'` and `'Jakarta EE'` |
| `dangerous_calls` | `List[dict]`: each with `method`, `class`, and call site |
| `security_strings` | `List[str]`: security-relevant string literals found |
| `manifest` | Dict of MANIFEST.MF entries `Main-Class` and `Class-Path`, and so on |
| `maven_deps` | `List[dict]`: bundled Maven dependency metadata |
| `jndi_patterns` | `List[str]`: JNDI lookup strings found Log4Shell detection |
| `findings` | `List[dict]`: structured findings with `severity`, `title`, `description` |

---

## See also <sup>[↑](#javareanalyzer)</sup>

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
