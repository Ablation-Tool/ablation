# JavaJarScanner

`ablation/analyzers/java_jar_scanner.py`

## Why this exists

Three gaps in existing Ablation coverage:

1. **BinaryContext silently fails on Java .class files.** `BinaryContext.load_or_build()` returns `arch=x86_64` fallback with `func_starts=0` for `.class` inputs. `SinkArgClassifier` produces 0 results. Java components inside BFF archives or ZIP distributions were treated as analyzed when they were not.

2. **Enterprise packages contain Java exec-class components that prior analysis missed.** Enterprise distributions ship Java `.jar` files inside `.bff` archives or ZIP distributions. A `.jar` that imports `Runtime.exec()` is invisible to `BinaryContext` and `SinkArgClassifier`. Both required constant-pool scanning, not native analysis.

3. **Common method names produce false positives without co-occurrence checks.** Names like `exec`, `start`, `load` appear in thousands of unrelated Java classes. A correct scanner requires both the exec-class class name (`java/lang/Runtime`) and method name (`exec`) to co-occur in the same class file's constant pool.

## Exec-class categories

| Category | APIs detected |
|---|---|
| `RUNTIME_EXEC` | `Runtime.exec()`: requires `java/lang/Runtime` + `exec` co-occurrence |
| `PROCESS_BUILDER` | `ProcessBuilder.start()`: requires `java/lang/ProcessBuilder` or `java/lang/Process` + `start` |
| `NATIVE_LOAD` | `System.load()`, `System.loadLibrary()`, `System.mapLibraryName()`: requires `java/lang/System` + method |
| `REFLECTIVE_EXEC` | `Class.forName()` + `invoke`/`getMethod`: reflective invocation pattern |

## Usage

```python
from ablation.analyzers.java_jar_scanner import JavaJarScanner

# JAR on disk
result = JavaJarScanner.scan_jar('/path/to/app.jar')
print(result.report())

# JAR extracted from BFF archive (bytes in memory)
result = JavaJarScanner.scan_bytes(jar_bytes, label='derdebug.jar')
print(result.summary())

# Already-open ZipFile (JAR inside another archive)
import zipfile
with zipfile.ZipFile('/path/to/outer.zip') as zf:
    with zipfile.ZipFile.__new__(zipfile.ZipFile) as inner:
        inner_data = zf.read('nested.jar')
result = JavaJarScanner.scan_bytes(inner_data, label='nested.jar')
```

## Example output

```
./usr/idebug/extras/390/lib/derdebug.jar: 350 classes, 1 exec-class hits — RUNTIME_EXEC
  [RUNTIME_EXEC] j.class: Runtime.exec() (java/lang/Runtime + exec)

/path/to/src.jar: 819 classes, 0 exec-class APIs
```

## Limitations

- Detects constant-pool references, not reachability. A class that references `Runtime.exec()` but never calls it at runtime will still be reported.
- Obfuscated code that renames `exec` to `e()` will not be detected.
- Inner classes (`$`) and anonymous classes are scanned individually; a finding in `Foo$Bar.class` is a finding in the outer class `Foo`.
- Does not parse bytecode (instructions). Cannot determine argument provenance or whether exec is reachable from a network-reachable entry point.

## Pipeline position

Run after `BinaryContext.load_or_build()` when the target includes `.jar` files or BFF archives with Java content. Output is per-JAR summary; pass findings to manual analysis or `TaintTracker` (if a JVM-aware taint tool is available) for reachability verification.
