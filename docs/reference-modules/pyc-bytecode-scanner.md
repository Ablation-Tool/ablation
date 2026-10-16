# PYC Bytecode Scanner

**File:** `ablation/analyzers/pyc_bytecode_scanner.py`

## Why this exists

FortiSwitch v7 management plane ships only `.pyc` bytecode, no `.py` source files. Three gaps existed before this module:

1. **Python's `marshal.loads()` is version-locked.** It cannot unmarshal a `.pyc` compiled by Python 3.10 when the host runs Python 3.8. Decompilation tools like `uncompyle6` have the same limitation for older bytecode formats.

2. **Full decompilation is not required to detect dangerous patterns.** Every Python code object stores `co_names`, the list of all attribute and global names referenced by `LOAD_ATTR`, `LOAD_GLOBAL`, and `STORE_ATTR` opcodes. If a module calls `os.system()`, the strings `"system"` and `"os"` appear in `co_names` without decompilation.

3. **`xdis` handles cross-version marshal parsing (Python 3.4–3.12+).** Already installed as an `uncompyle6` dependency, no new requirements.

Gap closed: 2026-10-16. FortiSwitch v7 Python layer confirmed CLEAN.

---

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PYC_BYTES` | 1 MB | `scan_file()`: `.pyc` file size cap before `read_bytes()` |
| `_MAX_RAW_HITS` | 4096 | `scan_raw()`: max embedded pyc entries per firmware image scan |

## Confidence classification

| `danger_hits` | `os_module_present` | `confidence` |
|---|---|---|
| empty |: | `clean` |
| non-empty | True | `HIGH` |
| non-empty | False | `LOW` |

`"system"` alone may come from a logging module; `"system"` + `"os"` in `co_names` is reliable shell execution signal.

## Key API

```python
from ablation.analyzers.pyc_bytecode_scanner import PycBytecodeScanner, PYC_MAGICS

scanner = PycBytecodeScanner()

# Single file
result = scanner.scan_file('/tmp/fortiswitch_web/views/main.pyc')
print(result.confidence)       # "clean" / "LOW" / "HIGH"
print(result.danger_hits)      # frozenset of matched dangerous names
print(result.python_version)   # e.g. "3.6"
print(result.co_names)         # frozenset of all names referenced by the module

# Directory tree
results = scanner.scan_dir('/tmp/fortisandbox_web_pyc/')
dangerous = [r for r in results if r.danger_hits]
print(scanner.report(dangerous))

# Raw firmware image (finds pyc by magic byte search)
with open('firmware.bin', 'rb') as f:
    raw = f.read()
results = scanner.scan_raw(raw, magic=PYC_MAGICS['3.4'])
print(scanner.report([r for r in results if r.danger_hits]))

# Custom dangerous name set (override defaults)
custom = PycBytecodeScanner(dangerous_names=frozenset({"marshal", "pickle"}))
```

## Supported Python versions

| Key | Magic bytes | Notes |
|---|---|---|
| `"3.4"` | `\xee\x0c\x0d\x0a` | 12-byte header |
| `"3.6"` | `\xb0\x0b\x0d\x0a` | 12-byte header |
| `"3.8"` | `\x55\x0d\x0d\x0a` | 16-byte header (PEP 552 flags field) |
| `"3.10"` | `\x6f\x0d\x0d\x0a` | 16-byte header |
| `"3.11"` | `\xa7\x0d\x0d\x0a` | 16-byte header |
| `"3.12"` | `\xcb\x0d\x0d\x0a` | 16-byte header |

Header size determined by magic_int threshold: `magic_int >= 0x0d55` (Python 3.8+) → 16 bytes, otherwise 12 bytes.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. Two CWE-770 fixes applied:
- `scan_file()`: `Path.stat().st_size > _MAX_PYC_BYTES` guard before `read_bytes()`: returns error `PycScanResult` if file exceeds 1 MB
- `scan_raw()`: `offsets = offsets[:_MAX_RAW_HITS]` cap limits firmware image scan to 4096 embedded pyc entries

No subprocess. No shell=True. No lief.parse(). No bare `except:`. `_extract_names_recursive()` uses Python's built-in recursion limit as an implicit depth bound.
