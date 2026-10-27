# MachoAnalyzer

Deep static analysis of macOS Mach-O binaries: load commands, segments, dynamic libraries, code signing, and malware indicators.

---

## Why this exists

1. **macOS targets require Mach-O parsing** that goes beyond LIEF's default load-command enumeration. `MachoAnalyzer` extracts dylib names, code signing status, and entropy per segment: indicators not returned by `BinaryContext` on macOS binaries.

2. **Entropy mapping per segment.** Packed or encrypted Mach-O payloads dylib injection and MalwareBytes case studies exhibit abnormal per-segment entropy. `MachoAnalyzer.entropy_map()` returns segment-level entropy without requiring LIEF.

3. **Code signing presence check.** `has_code_signature()` locates `LC_CODE_SIGNATURE` in load commands: the minimum gate check before deeper malware analysis.

---

## Usage

```python
from ablation.core.macho_analyzer import MachoAnalyzer

data = open('/path/to/binary', 'rb').read()
mac = MachoAnalyzer(data)

if not mac.valid:
    print('Not a valid Mach-O')
else:
    print(f'64-bit: {mac.is_64bit}')
    print(f'Dylibs: {mac.dylibs()}')
    print(f'Code signed: {mac.has_code_signature()}')
    for seg, entropy in mac.entropy_map().items():
        print(f'  {seg}: {entropy:.2f} bits/byte')
```

---

## Key methods

| Method | Return | Notes |
|:---|:---|:---|
| `dylibs()` | `list[str]` | Dylib install names from LC_LOAD_DYLIB commands |
| `has_code_signature()` | `bool` | True if LC_CODE_SIGNATURE load command is present |
| `entropy_map()` | `dict[str, float]` | Per-segment Shannon entropy bits/byte |
| `sections()` | `list[dict]` | Section names, offsets, sizes per segment |

---

## Architecture

Supports both 32-bit (`MH_MAGIC = 0xfeedface`) and 64-bit (`MH_MAGIC_64 = 0xfeedfacf`) Mach-O, including byte-swapped CIGAM variants. `MachoAnalyzer.valid` is False for non-Mach-O input.

---

## Limitations

**No FAT/universal binary support.** Passes the first architecture slice only. For universal binaries, slice with `lipo` before analysis.

**No ObjC runtime decoding.** Method selectors, class lists, and `__objc_methnames` sections are not parsed. Use LIEF or class-dump for ObjC analysis.

---

## Pipeline position

**When to use:** macOS targets, iOS frameworks (`.dylib` in IPA), and any binary whose magic is `0xfeedface` / `0xfeedfacf`.

**After:** Pass dylib names to `SinkArgClassifier` for PLT-based analysis, or load via `BinaryContext.load_or_build()` for full pipeline access.

---

## See also

- [PE Analyzer](binary-format-and-platform-identification.md): Windows PE equivalent
- [ELF Parser](elf-internals-and-hardening.md): Linux ELF equivalent
