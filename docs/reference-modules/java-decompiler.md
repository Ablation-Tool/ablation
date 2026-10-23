# Java Bytecode Analysis

**File:** `modules/java_decompiler.py`

## Why this exists

Java bytecode analysis for.class and.jar files: decompiles bytecode to readable form, identifies dangerous API calls (Runtime.exec, ProcessBuilder, URLClassLoader, reflection-based deserialization), and maps injection points in servlet and REST endpoint handlers.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_CLASS_BYTES` | 64 MB |.class/.jar file read cap |
| `_MAX_ENTRY_BYTES` | 16 MB | ZIP entry read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; ZIP entry sizes checked against `_MAX_ENTRY_BYTES` before extraction. `_MAX_CLASS_BYTES=64MB`. No lief.parse(). No HTTP reads.

---

## How it works

Parses the runtime-specific binary format (APK, DEX, `.mpy`, BEAM, Go ELF) to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage

```python
from modules.java_re import JavaREAnalyzer

analyzer = JavaREAnalyzer('/path/to/target.jar')
findings = analyzer.analyze()
for f in findings:
    print(f)
```

---

## Example output

```
[HIGH] DANGEROUS_CALL   Runtime.exec() in com.example.CommandHandler:42
  detail: argument constructed from user-supplied intent extra
  evidence: exec(getIntent().getStringExtra("cmd"))

[MEDIUM] UNTRUSTED_INPUT   eval() in main.js:118
  detail: JSON.parse result passed directly to eval
```

---

## False positives

Standard library calls that resemble dangerous patterns (e.g., `exec` used for shell completions, `eval` used for template rendering with static input) are not findings. Confirm that the argument reaching the dangerous call is user-controlled before escalating. Obfuscated code (Garble-compiled Go, ProGuard-stripped Android) produces incomplete call graphs: findings from incomplete graphs carry lower confidence.

---

## Pipeline position

**Before this module:** Confirm the target binary format (APK, `.mpy`, BEAM, Go ELF) before loading. `BinaryContext` is not required for all runtime analyzers.

**After this module:** Feed dangerous call findings to `TaintTracker` or `FindingRegistry` for confirmed findings.

---

## Reading output

`JavaDecompiler(path).analyze()` returns a dict:

| Key | Content |
|:---|:---|
| `path` | Absolute path to the analyzed `.class` / `.jar` file |
| `classes` | `List[dict]`: per-class analysis with `name`, `methods`, `fields` |
| `security` | Security audit result string summarizing all findings |
| `findings` | `List[dict]`: individual findings, each with `severity`, `title`, `description` |

---

## See also

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
