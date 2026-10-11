# TI COFF Loader — FORGE Audit + DEV & TEST ORCHESTRATION PLAN

**Module:** `ablation/analyzers/ti_coff_loader.py`  
**Version:** v2.70.0  
**Date:** 2026-10-10  
**Auditor:** Claude Sonnet 4.6  

---

## SAFE CODE 10-Section Audit

### §1 Input Validation
- `from_path(path)`: accepts `str | Path`, wraps `Path.read_bytes()` in try/except in the
  caller (`TiNNCScanner.scan()`). The loader itself raises on missing files; the scanner
  catches it. **PASS**
- `_parse_ar()`: validates `end_magic == b'\x60\n'` before processing each member; breaks
  on bad magic rather than continuing. **PASS**
- `_parse_coff_object()`: bounds-checks `base + 22 > len(data)` before unpacking. **PASS**
- `_parse_symbols()`: bounds-checks `off + 18 > len(data)` for every symbol entry. **PASS**
- `_read_strtab()`: validates `strtab_off`, `offset < 4`, and `strtab_off + offset >= len(data)`
  before indexing. **PASS**
- `member_size = int(file_size_raw)`: wrapped in `try/except ValueError` — bad AR size
  field breaks the loop rather than crashing. **PASS**

### §2 Command Injection
No subprocess, os.system, Popen, eval, or exec calls in the module. **PASS**

### §3 Path Traversal
Path is passed only to `Path.read_bytes()`. No `open()` calls on user-supplied paths
beyond the initial read. No path construction from parsed COFF content. **PASS**

### §4 Secret/Credential Exposure
No credentials, API keys, or secrets. **PASS**

### §5 Integer Overflow / Underflow
- `i += 1 + numaux`: `numaux` is a `uint8` (0–255); `i` advances by at most 256 per
  iteration. Loop bound is `hdr.n_syms` (uint32). No overflow possible in Python. **PASS**
- `sym_off + i * 18`: Python integers are unbounded; no overflow. The `off + 18 > len(data)`
  guard prevents out-of-bounds access. **PASS**
- `offset += member_size`: `member_size` is parsed from a 10-byte decimal string in the AR
  header (max 9999999999); at most ~10 GB, which exceeds any realistic `.a` file but will
  simply advance `offset` past `len(data)`, terminating the loop. **PASS**

### §6 Memory Safety
Pure Python. No ctypes, no C extensions, no mmap. `struct.unpack_from()` raises
`struct.error` on out-of-bounds access — caught at the call sites via `try/except
struct.error`. **PASS**

### §7 Error Handling
- `struct.error` from `_FH_STRUCT.unpack_from()` and `_SYM_STRUCT.unpack_from()` caught
  inside `_parse_coff_object()` and `_parse_symbols()` respectively. **PASS**
- `ValueError` from `int(file_size_raw)` caught in `_parse_ar()`. **PASS**
- `_parse_ar()` and `_parse_symbols()` use `break` (not `raise`) on format errors, so
  partial archives produce partial results rather than exceptions. **PASS**
- `from_path()` re-raises `FileNotFoundError`, `PermissionError`, and `OSError` — the
  caller (`TiNNCScanner.scan()`) is responsible for catching these. Documented behavior,
  not a gap. **PASS**

### §8 Data Leakage
No network calls, no file writes, no logging statements. **PASS**

### §9 Dependencies
- `struct`, `dataclasses`, `pathlib`, `typing` — stdlib only. No new dependencies
  introduced. **PASS**

### §10 Logic Correctness
- AR member name parsing: strips trailing spaces and `/`, then skips names starting with
  `/` (the AR symbol table). This is correct for standard Unix AR (GNU variant). Handles
  BSD-style AR (`#1/<len>` names) by skipping them — they start with `#`, not `/`. BSD AR
  is not used by TI toolchain, so no gap. **PASS**
- String table offset: `offset < 4` guard avoids reading the 4-byte size field as a name.
  The COFF spec stores string table size in the first 4 bytes of the string table. **PASS**
- `numaux` skip: auxiliary symbol entries are skipped via `i += 1 + numaux`. This is
  correct per SPRAAO8 §6.5 — aux entries immediately follow the primary entry and must
  be skipped as a unit. **PASS**
- Symbol filter: skips names starting with `.` (section names) or `$` (TI compiler
  internal labels). This prevents false-positive norm-symbol matches on section symbols. **PASS**
- `is_coff()` / `is_ar()` operate on `self._data` (in-memory bytes) — they return False
  for an empty `TiCoffLoader(b'', '')` instance, so the scanner's magic check correctly
  falls through to the ELF path. **PASS**

**gate_passed: True** — 0 HIGH, 0 CRITICAL findings.

---

## DEV & TEST ORCHESTRATION PLAN

### Test 1 — Import smoke test
```python
from ablation.analyzers.ti_coff_loader import (
    TiCoffLoader, CoffSymbol, C_EXT, C_UEXT, C_STAT, C_EXTREF,
    TI_TARGET_C2800,
)
```
Expected: no ImportError.

### Test 2 — is_ar() / is_coff() on empty instance
```python
loader = TiCoffLoader(b'', '')
assert not loader.is_ar()
assert not loader.is_coff()
assert list(loader.symbols()) == []
```
Expected: empty, no exception.

### Test 3 — is_ar() on AR magic bytes
```python
loader = TiCoffLoader(b'!<arch>\n', '')
assert loader.is_ar()
assert not loader.is_coff()
```
Expected: AR detected, no COFF.

### Test 4 — is_coff() on COFF2 magic bytes
```python
import struct
header = struct.pack('<H', 0x00C2) + b'\x00' * 20
loader = TiCoffLoader(header, '')
assert loader.is_coff()
assert not loader.is_ar()
```
Expected: COFF detected.

### Test 5 — from_path() on missing file raises
```python
try:
    TiCoffLoader.from_path('/nonexistent.bin')
    assert False, 'expected FileNotFoundError'
except FileNotFoundError:
    pass  # correct
```
Expected: FileNotFoundError raised (caller is responsible for catching).

### Test 6 — symbols() on minimal valid COFF2 object
Construct a minimal TI COFF2 object in memory with:
- File header: magic=0x00C2, n_scns=0, symptr=22, nsyms=1, opthdr=0, flags=0,
  target_id=0x009D
- One symbol entry: name=b'tvmgen_default_run\x00\x00\x00\x00\x00' (8 bytes padded),
  value=0x100, scnum=1, type=0, sclass=C_EXT (2), numaux=0
- String table: size=4 (just the size field, no strings)

Expected: one CoffSymbol with name='tvmgen_default_run', storage_class=2 (C_EXT),
is_weak=False, is_global=True.

### Test 7 — C_UEXT symbol detected as weak
Construct COFF2 object (as Test 6) but with sclass=C_UEXT (19).
Expected: CoffSymbol.is_weak == True, storage_class_name == 'C_UEXT'.

### Test 8 — AR archive with one COFF2 member
Wrap a minimal COFF2 object (Test 6) in a Unix AR archive header.
Expected: loader.is_ar() == True, symbols() yields the symbol from the inner object,
CoffSymbol.member_name set to the member filename.

### Test 9 — TiNNCScanner on C28x AR archive (end-to-end)
Construct an AR archive containing a COFF2 object with:
- `tvmgen_default_run` (C_EXT)
- `tvmgen_default_bias_data` (C_UEXT)
- `tvmgen_default_scale_data` (C_UEXT)

Expected:
- result.modules has one entry: name='default', execution_mode='npu_soft'
- result.findings has TINCC-001 × 2 (bias_data, scale_data)
- result.findings has TINCC-004 × 1 (skip-normalize)

### Test 10 — Corrupt AR member size field
AR archive with a member whose file_size field contains non-numeric bytes.
Expected: _parse_ar() catches ValueError, yields no objects, no exception.
