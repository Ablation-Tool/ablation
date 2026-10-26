# PycBytecodeScanner

**File:** `ablation/analyzers/pyc_bytecode_scanner.py`

## Why this exists <sup>[↑](#pycbytecodescanner)</sup>

FortiSwitch v7 management plane ships only `.pyc` bytecode, no `.py` source files. Three gaps existed before this module:

1. Python's `marshal.loads()` is version-locked. It cannot unmarshal a `.pyc` compiled by Python 3.10 when the host runs Python 3.8. Decompilation tools like `uncompyle6` have the same limitation for older bytecode formats.

2. Full decompilation is not required to detect dangerous patterns. Every Python code object stores `co_names`, the list of all attribute and global names referenced by `LOAD_ATTR`, `LOAD_GLOBAL`, and `STORE_ATTR` opcodes. If a module calls `os.system()`, the strings `"system"` and `"os"` appear in `co_names` without decompilation.

3. `xdis` handles cross-version marshal parsing for Python 3.4–3.12+. It is already installed as an `uncompyle6` dependency, so no new requirements are added.

Gap closed: 2026-10-16. FortiSwitch v7 Python layer confirmed CLEAN.

---

## Key constants <sup>[↑](#pycbytecodescanner)</sup>

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PYC_BYTES` | 1 MB | `scan_file()`: `.pyc` file size cap before `read_bytes()` |
| `_MAX_RAW_HITS` | 4096 | `scan_raw()`: max embedded pyc entries per firmware image scan |

## Confidence classification <sup>[↑](#pycbytecodescanner)</sup>

| `danger_hits` | `os_module_present` | `confidence` |
|---|---|---|
| empty |: | `clean` |
| non-empty | True | `HIGH` |
| non-empty | False | `LOW` |

`"system"` alone may come from a logging module; `"system"` + `"os"` in `co_names` is reliable shell execution signal.

## Key API <sup>[↑](#pycbytecodescanner)</sup>

```python
from ablation.analyzers.pyc_bytecode_scanner import PycBytecodeScanner, PYC_MAGICS

scanner = PycBytecodeScanner()

# PycBytecodeScanner
result = scanner.scan_file('/tmp/fortiswitch_web/views/main.pyc')
print(result.confidence)       # "clean" / "LOW" / "HIGH"
print(result.danger_hits)      # frozenset of matched dangerous names
print(result.python_version)   # e.g. "3.6"
print(result.co_names)         # frozenset of all names referenced by the module

# PycBytecodeScanner
results = scanner.scan_dir('/tmp/fortisandbox_web_pyc/')
dangerous = [r for r in results if r.danger_hits]
print(scanner.report(dangerous))

# PycBytecodeScanner
with open('firmware.bin', 'rb') as f:
    raw = f.read()
results = scanner.scan_raw(raw, magic=PYC_MAGICS['3.4'])
print(scanner.report([r for r in results if r.danger_hits]))

# PycBytecodeScanner
custom = PycBytecodeScanner(dangerous_names=frozenset({"marshal", "pickle"}))
```

## Supported Python versions <sup>[↑](#pycbytecodescanner)</sup>

| Key | Magic bytes | Notes |
|---|---|---|
| `"3.4"` | `\xee\x0c\x0d\x0a` | 12-byte header |
| `"3.6"` | `\xb0\x0b\x0d\x0a` | 12-byte header |
| `"3.8"` | `\x55\x0d\x0d\x0a` | 16-byte header PEP 552 flags field |
| `"3.10"` | `\x6f\x0d\x0d\x0a` | 16-byte header |
| `"3.11"` | `\xa7\x0d\x0d\x0a` | 16-byte header |
| `"3.12"` | `\xcb\x0d\x0d\x0a` | 16-byte header |

Header size determined by magic_int threshold: `magic_int >= 0x0d55` Python 3.8+ → 16 bytes, otherwise 12 bytes.

## FORGE audit <sup>[↑](#pycbytecodescanner)</sup>

Gate: **PASSED**. No HIGH or CRITICAL findings. Two CWE-770 fixes applied:
- `scan_file()`: `Path.stat().st_size > _MAX_PYC_BYTES` guard before `read_bytes()`: returns error `PycScanResult` if file exceeds 1 MB
- `scan_raw()`: `offsets = offsets[:_MAX_RAW_HITS]` cap limits firmware image scan to 4096 embedded pyc entries

No subprocess. No shell=True. No lief.parse(). No bare `except:`. `_extract_names_recursive()` uses Python's built-in recursion limit as an implicit depth bound.

---

## How it works <sup>[↑](#pycbytecodescanner)</sup>

Parses the runtime-specific binary format APK, DEX, `.mpy`, BEAM, and Go ELF to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage <sup>[↑](#pycbytecodescanner)</sup>

```python
from ablation.analyzers.pyc_bytecode_scanner import PycBytecodeScanner

scanner = PycBytecodeScanner()
results = scanner.scan_dir('/path/to/extracted_firmware/', recursive=True)
print(scanner.report(results))
```

---

## Example output <sup>[↑](#pycbytecodescanner)</sup>

```
[HIGH] DANGEROUS_CALL   Runtime.exec() in com.example.CommandHandler:42
  detail: argument constructed from user-supplied intent extra
  evidence: exec(getIntent().getStringExtra("cmd"))

[MEDIUM] UNTRUSTED_INPUT   eval() in main.js:118
  detail: JSON.parse result passed directly to eval
```

---

## False positives <sup>[↑](#pycbytecodescanner)</sup>

Standard library calls that resemble dangerous patterns such as `exec` used for shell completions and `eval` used for template rendering with static input are not findings. Confirm that the argument reaching the dangerous call is user-controlled before escalating. Obfuscated code Garble-compiled Go and ProGuard-stripped Android produces incomplete call graphs: findings from incomplete graphs carry lower confidence.

---

## Pipeline position <sup>[↑](#pycbytecodescanner)</sup>

**Before this module:** Confirm the target binary format APK, `.mpy`, BEAM, and Go ELF before loading. `BinaryContext` is not required for all runtime analyzers.

**After this module:** Feed dangerous call findings to `TaintTracker` or `FindingRegistry` for confirmed findings.

---

## Reading output <sup>[↑](#pycbytecodescanner)</sup>

`PycBytecodeScannerdangerous_names.scan_file(path)` returns a `PycScanResult`:

| Attribute | Content |
|:---|:---|
| `path` | Path to the `.pyc` file |
| `filename` | `co_filename` string from the top-level code object (the original `.py` source path) |
| `python_version` | Version string such as `'3.4'` and `'3.11'` |
| `co_names` | `FrozenSet[str]`: all name references in the bytecode |
| `danger_hits` | `FrozenSet[str]`: intersection of `co_names` with `dangerous_names` |
| `os_module_present` | `True` if `'os'` appears in `co_names` |
| `error` | `None` on success, error string if the file could not be parsed |
| `is_clean` | Property: `True` if `danger_hits` is empty and no error |
| `confidence` | Property: `'clean'` / `'HIGH'` os module + danger hits / `'LOW'` danger hits only |

---

## See also <sup>[↑](#pycbytecodescanner)</sup>

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
