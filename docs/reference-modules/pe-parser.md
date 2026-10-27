# PEParser (core)

Low-level Windows PE file parser in `ablation/core/pe_parser.py`. Foundation layer consumed by `pe_analyzer.py` and `kernel_driver_analyzer.py`. Takes `data: bytes` directly: callers load the file.

---

## Why this exists

1. **`pe_analyzer.py` and `kernel_driver_analyzer.py` need a shared PE parsing substrate.** Without `PEParser`, each analyzer would duplicate DOS/COFF/optional-header parsing, and diverge on edge cases like PE32 vs PE32+ magic, or short optional headers in embedded firmware.

2. **No dependency on LIEF or pefile for Windows targets.** LIEF's PE support is solid but returns objects tuned for binary instrumentation, not forensic field access. `PEParser` exposes raw field values and section tables with the exact offsets needed for IOCTL code extraction and pool-tag byte-pattern scans.

3. **Static analysis of kernel drivers requires struct-level access to COFF fields.** `KernelDriverAnalyzer` reads `IMAGE_FILE_MACHINE`, `MajorOperatingSystemVersion`, the debug directory RSDS → PDB path, and the import table for kernel API surface audit. These all require direct field offsets that a high-level abstraction hides.

---

## Usage

```python
from ablation.core.pe_parser import PEParser

with open('/path/to/driver.sys', 'rb') as f:
    data = f.read()

pe = PEParser(data)
if not pe.valid:
    print('Not a valid PE')
else:
    print(f'Machine: {pe.machine:#x}')
    for sec in pe.sections:
        print(sec['name'], hex(sec['va']), sec['size'])
    for imp in pe.imports:
        print(imp['dll'], imp['name'])
```

---

## Key API

| Attribute/Method | Returns | Notes |
|:---|:---|:---|
| `valid` | `bool` | True if MZ + PE signatures verified |
| `machine` | `int` | IMAGE_FILE_MACHINE value 0x014c=i386 and 0x8664=AMD64 |
| `sections` | `list[dict]` | `{name, va, offset, size, characteristics}` |
| `imports` | `list[dict]` | `{dll, name, ordinal, va}` |
| `exports` | `list[dict]` | `{name, va, ordinal}` |
| `pe_offset` | `int` | File offset of PE header from DOS stub e_lfanew |
| `is_64bit` | `bool` | True for PE32+ IMAGE_NT_OPTIONAL_HDR64_MAGIC |

---

## Architecture notes

- Constructor takes `data: bytes`; no file I/O. The CLI wrapper at line 901 (`open(path, 'rb').read()`) is the only file-reading path.
- DOS stub validated at `data[0:2] == b'MZ'`; PE signature at `data[pe_offset:pe_offset+4] == b'PE\x00\x00'`.
- Import/export table parsing traverses RVA-linked lists; bounds-checked per entry.

---

## See also

- [PE Analyzer](binary-format-and-platform-identification.md): higher-level analysis built on this parser
- [Kernel Driver Analyzer](kernel-drivers.md): extends PEParser for Windows kernel drivers
