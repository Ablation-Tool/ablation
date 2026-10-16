# PycBytecodeScanner

## Why this exists

1. **FSW-PYC-GAP**: FortiSwitch firmware ships only compiled `.pyc` bytecode — no `.py` source files. SourceEntryClassifier and SourceSinkScanner cannot run without source. Binary taint trackers cannot run on Python bytecode. No Ablation module existed to bridge this gap.

2. **Decompiler brittleness**: `uncompyle6` and its `xdis` dependency crash on certain FortiSwitch Python 3.4 `.pyc` files with `ValueError: could not convert string to float` (xdis unmarshal encounters `TYPE_COMPLEX = 0x78` and fails to read the float string). Full decompilation is unreliable for firmware-embedded `.pyc` files.

3. **Name-extraction sufficiency**: Detecting dangerous function calls does not require full decompilation. Every Python code object stores `co_names` — the complete set of LOAD_GLOBAL / LOAD_ATTR / STORE_ATTR name operands. If `os.system()` is called, both `"os"` and `"system"` appear in `co_names`. This is reliable without decompiling instruction sequences.

## What it does

Scans Python `.pyc` bytecode for dangerous function-call patterns by parsing code object trees with `xdis` and extracting `co_names`. Works across Python 3.4 through 3.12+.

Supports:
- Single `.pyc` file
- Directory tree of `.pyc` files
- Raw firmware image bytes (magic-byte search + structural validation)

## Usage

```python
from ablation.analyzers.pyc_bytecode_scanner import PycBytecodeScanner, PYC_MAGICS

scanner = PycBytecodeScanner()

# Firmware image — finds all embedded pyc files by magic bytes
import gzip, io
with open('/path/to/firmware.bin', 'rb') as f:
    f.seek(0x410000)
    raw = gzip.open(io.BytesIO(f.read())).read()

results = scanner.scan_raw(raw, magic=PYC_MAGICS["3.4"])
print(scanner.report(results))

# Directory of extracted pyc files
results = scanner.scan_dir('/tmp/extracted_pyc/')
dangerous = [r for r in results if r.danger_hits]
print(scanner.report(dangerous))
```

## Output

```
PycBytecodeScanner
  Total scanned : 1364
  Errors        : 177
  Dangerous     : 19
  Clean         : 1168

Dangerous modules:
  [HIGH] :/Chroot_Build/.../python3.4/mailcap.py
    hits: ['popen', 'system']
    os_context: ['os']
```

`confidence` field:
- `HIGH` — dangerous name + OS module name both present in `co_names` (e.g. `system` + `os`)
- `LOW` — dangerous name present but no OS module (e.g. `eval` in a template engine)
- `clean` — no dangerous names found

## Interpreting results

Dangerous hits from `python3.4/` or standard library paths are expected and benign. Filter on `co_filename` to isolate target-specific code:

```python
mgmt_hits = [
    r for r in results
    if r.danger_hits and "python3.4" not in (r.filename or r.path)
]
```

## FortiSwitch v7 result

Scanned 1364 `.pyc` files from `FSW_108E_FPOE-v7-build0022-FORTINET-7.0.0.out`:
- 19 files with dangerous patterns — all Python 3.4 stdlib (`mailcap`, `distutils`, `multiprocessing`, etc.)
- 0 management-plane (`fortiproc`) files with dangerous patterns
- Gap FSW-PYC-GAP closed: Python management layer confirmed CLEAN

## Known limitations

- `xdis` silences unknown type warnings but returns partial code objects when encountering unknown marshal types (e.g., `TYPE_COMPLEX`). Parse errors are returned as `PycScanResult.error` strings.
- `co_names` reports names of all globals and attributes accessed. A name like `"run"` may come from a Django HTTP response method, not `subprocess.run`. Use `os_module_present` to filter.
- Python 3.4 firmware pyc files have `source_size = 0` (Fortinet does not write source size). The `max_source_size` filter in `scan_raw()` uses the timestamp field position, not source_size, for structural validation.

## Tool selection

Use `PycBytecodeScanner` when:
- Target management plane is Python but only `.pyc` files are present in firmware
- `SourceEntryClassifier` / `SourceSinkScanner` unavailable (no source)
- Quick danger-pattern triage needed before committing to full decompilation

Use `SourceSinkScanner` instead when:
- Python `.py` source files are available (FortiSandbox, FortiManager web layer)
