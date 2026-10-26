# ArArchiveScanner

Scan Unix ar (.a) static library archives for exec-class sinks by dispatching SinkArgClassifier on each ELF object member.

---

## Why this exists

1. Gap IBM-ARCH-002: Static libraries (`.a` files) contain pre-compiled `.o` object files that must be checked for exec-class surface. `nested_archive_scanner.py` handles tar/RPM/zip/deb but does NOT handle ar format. MASS/Linux/`libmass_64.a` required manual extraction before SAC could run.

2. ar ≠ tar: The ar format uses an 8-byte magic `!<arch>\n` and 60-byte member headers: completely different from tar. Python's `tarfile` module does not read ar archives.

3. Architecture dispatch: ELF objects inside `.a` files may be any architecture: ppc64 BE, i386, x86_64, ARM. The scanner reads `e_machine` from each member's ELF header and dispatches `SinkArgClassifierI386` for i386 cdecl and `SinkArgClassifier` for all others, matching the correct ABI.

---

## How it works

```
.a bytes → verify !<arch>\n magic
         → iterate 60-byte member headers
         → skip GNU symbol table (/) and long-name table (//)
         → resolve GNU long names (/N offset) if present
         → for each member: check ELF magic, read e_machine
         → write member to temp file
         → dispatch SinkArgClassifier (x86_64) or SinkArgClassifierI386 (i386)
         → collect exec-class hits, delete temp file
         → report aggregate results
```

ar member header layout 60 bytes:
- `[0:16]`: member name space-padded, `/` suffix stripped for GNU format
- `[48:58]`: member size decimal ASCII
- `[58:60]`: end marker `0x60 0x0a`

---

## ArArchiveScanner

```python
from ablation.analyzers.ar_archive_scanner import ArArchiveScanner

scanner = ArArchiveScanner.from_path('/path/to/lib.a')
results = scanner.scan_exec_class()   # → List[ArMemberResult]
print(scanner.report(results))
```

`ArMemberResult` fields:
- `member_name`: filename inside the archive
- `size`: member data size in bytes
- `elf_format`: e.g. `'ELF64-BE-ppc64'`, `'ELF32-LE-x86'`
- `exec_hits`: count of exec-class sink hits
- `verdicts`: list of `sink_name, verdict` tuples from SAC
- `error`: SAC error string if analysis failed

---

## Usage

```python
# Quick one-liner
ArArchiveScanner.quick_check('/media/cowboy/research/IBM-RE/MASS/lib64/libmass_64.a')

# Full analysis
import subprocess
data = subprocess.run(['tar', '-xzO', '-f', 'MASS_4.4_rhel5.tar.gz',
                       'mass/4.4/rhel5/lib64/libmass_64.a'],
                     capture_output=True).stdout
scanner = ArArchiveScanner(data)
results = scanner.scan_exec_class()
exec_members = [r for r in results if r.exec_hits > 0]
```

---

## Example output

```
ArArchiveScanner: 55 ELF members, 0 with exec-class hits
  [safe] atan_p4.s64.o (3008B ELF64-BE-ppc64) hits=0 []
  [safe] atan2_p4.s64.o (2928B ELF64-BE-ppc64) hits=0 []
  [safe] sincos.s64.o (3472B ELF64-BE-ppc64) hits=0 []
  ...
```

MASS libmass_64.a: 55 ELF64-BE-ppc64 math function objects, 0 exec-class: pure math library IBM MASS 4.4.

---

## False positives

None expected for pure math libraries. For application `.a` files, SAC may return `UNKNOWN` classification for indirect exec calls: same as for ELF binaries; treat identically.

**BSD extended names** (`#1/<len>` format): member names are not resolved but members are still analyzed. Only the name string will be wrong; the exec-class scan is unaffected.

---

## Pipeline position

**Before:** Extract `.a` from tar/RPM if necessary. Verify archive magic is `!<arch>\n`.

**After:** Findings feed into TaintTracker for any `ARG_PROPAGATED` or `UNKNOWN` sinks found. Record aggregate verdict in `PER_DIR_COVERAGE`.

---

## See also

- [NEFormatParser](ne-format-parser.md): for OS/2 NE/LX format binaries
- [nested-archive-scanner](nested-archive-scanner.md): for tar/RPM/zip/deb nesting
- [sink-arg-classifier](sink-arg-classifier.md): the underlying per-ELF analyzer
