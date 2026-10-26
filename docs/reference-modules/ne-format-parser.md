# NEFormatParser

Parse NE/LE/LX New Executable format OS/2 and Windows 3.x binaries and check for exec-class API imports.

---

## Why this exists

1. Gap IBM-OS2-001: IBM-RE contains OS/2-era software CM2, NFS-OS2, NOV, IBM4690, OS2-CM2, and ImagePlus whose NE/LX format binaries were classified "no Linux ELFs" without exec-class verification. NOV/noteinet.exe, CM2/alert.exe, OS2-CM2/COMMAC.SYS all required manual hex to identify format and confirm no DosExecPgm/DosStartSession.

2. OS/2 ≠ ELF: SinkArgClassifier and all other Ablation analyzers require ELF input. NE/LX is a completely different binary format DOS stub + New Executable header. There was no path from an NE binary to an exec-class verdict.

3. DosExecPgm is the OS/2 exec: OS/2 programs spawn subprocesses via `DOSCALLS.DLL:DosExecPgm` ordinal 237 and `DosStartSession` ordinal 214, not via Linux exec* syscalls. Without a parser that reads the NE import table, there was no way to check for these.

---

## How it works

```
file bytes → check MZ magic → read 0x3c for extended header offset
          → read sig at ext_off: 'NE'/'LE'/'LX'/'PE\0\0'
          → NE path: parse module reference table → resolve imported names
                   → scan imported names table for DOSEXECPGM/DOSSTARTSESSION/WINEXEC
          → LX path: read import module table + import procedure name table
                   → scan procedure names for exec-class functions
```

NE header offsets all relative to NE header start, 16-bit:
- `+0x28`: module reference table → array of uint16 offsets into imported names
- `+0x2a`: imported names table base
- `+0x2c`: nonresident names table 32-bit, file-absolute
- `+0x36`: target OS 1=OS/2-1.x and 2=Windows-3.x

---

## NEFormatParser

```python
from ablation.analyzers.ne_format_parser import NEFormatParser, NEFormatResult

p = NEFormatParser.from_path('/path/to/noteinet.exe')
r = p.parse()          # → NEFormatResult
print(r.fmt())
print(r.exec_imports)  # [] if safe
```

`NEFormatResult` fields:
- `format`: `'NE'`, `'LE'`, `'LX'`, `'PE'`, `'MZ-only'`, `'NOT-MZ'`
- `target_os`: `'OS/2-1.x'`, `'Windows-3.x'`, `'OS/2-2.x'`, etc.
- `imported_modules`: list of DLL/module names from module reference table
- `exec_imports`: list of exec-class function names found `DOSEXECPGM`, and so on
- `nonresident_names`: first entries from non-resident name table
- `segment_count`, `module_ref_count`

---

## Usage

```python
# Scan a single file
p = NEFormatParser.from_path('/media/cowboy/research/IBM-RE/NOV/noteinet.exe')
r = p.parse()
# r.format='NE', r.target_os='OS/2-1.x', r.imported_modules=['DOSCALLS'],
# r.exec_imports=[], r.segment_count=6

# Bulk scan a directory
import os
for root, _, files in os.walk('/media/cowboy/research/IBM-RE/CM2'):
    for fname in files:
        fpath = os.path.join(root, fname)
        try:
            with open(fpath, 'rb') as f:
                magic = f.read(2)
            if magic != b'MZ': continue
            r = NEFormatParser.from_path(fpath).parse()
            if r.exec_imports:
                print('EXEC-CLASS:', fpath, r.exec_imports)
        except Exception:
            pass
```

---

## Example output

```
NE format=NE target_os=OS/2-1.x modules=['DOSCALLS', 'MSG'] exec_imports=[] segments=3 nonresident=[] verdict=SAFE-NO-EXEC-IMPORT
```

IBM 4690 retail OS utilities 6 NE files: all `DOSCALLS`-only, no `DOSEXECPGM`.
CM2 alert.exe LX OS/2-2.x: `DOSCALLS, NLS, MSG`, no exec-class.

---

## False positives

None typical. The module only flags when exec-class names appear verbatim in the import table. NE import tables are explicit name references, not pattern-matched.

**Note on NFS-OS2**: Files with magic `4e4e40d7` are IBM CSD PTF packages (`.1TS`/`.1TC`/`.1UC`), not NE/MZ executables. They will return `format='NOT-MZ'` and should be excluded from scans.

---

## Pipeline position

**This module is standalone**, it does not feed into SinkArgClassifier or TaintTracker. OS/2 binaries have no ELF exec surface. The verdict is import-table-only.

**Before:** Check magic bytes to confirm MZ header before calling.

**After:** Record verdict in `PER_DIR_COVERAGE` for IBM-RE completeness tracking.

---

## See also

- [ArArchiveScanner](ar-archive-scanner.md): for `.a` static library archives containing ELF members
- [sink-arg-classifier](sink-arg-classifier.md): for ELF binaries after format identification
