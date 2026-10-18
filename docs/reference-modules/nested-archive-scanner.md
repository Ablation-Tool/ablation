# NestedArchiveScanner: recursive archive extraction for ELF analysis

## Why this exists

IBM product analysis hit multi-level archive chains three separate times in session 9. HACMP packages contain RPMs inside tar.gz. Tau contains a tgz nested inside a plain tar. DOORS contains a tar nested inside a zip. Each time, the session wrote its own ad-hoc subprocess script to extract ELFs. This module replaces all three.

Gap ID: **IBM-ARCH-001**.

## Usage

```python
from ablation.analyzers.nested_archive_scanner import NestedArchiveScanner

# Scan a directory, yielding one path per ELF
for real_path, virtual_path in NestedArchiveScanner('/path/to/HACMP/').scan():
    print(virtual_path)

# Scan a single archive
for real_path, virtual_path in NestedArchiveScanner.scan_archive('/path/to/hacmp.base.rpm'):
    print(virtual_path)

# Collect up to 30 ELFs into memory (max_elfs limits how many are read into RAM)
elfs = NestedArchiveScanner.collect_elfs(
    '/path/to/tau-4201-lin.tar', max_elfs=30
)
for vpath, data in elfs:
    print(vpath)
```

## Supported archive formats

| Format | Extraction method |
|---|---|
| `.rpm` | `rpm2cpio` piped to `cpio -idm` |
| `.zip` | `zipfile.ZipFile.extractall()` |
| `.tar.gz` or `.tgz` | `tarfile.open('r:gz')` |
| `.tar` | `tarfile.open('r:')` |
| `.tar.Z` | `uncompress -c` piped to `tarfile` |

The scanner descends up to four levels deep. AIX BFF archives are detected by magic bytes `\x09\x00\x6b\xea` and skipped because they contain no Linux ELF content.

## Notes

`scan()` returns an iterator. The real file paths inside the iterator point to temporary directories. Read the file bytes before the iterator finishes or use `collect_elfs()` to load everything into memory first.

`shlex.quote()` is applied to archive paths before passing them to subprocess calls.

## Pipeline position

**Before this module:** Identify the target directory or archive path. No BinaryContext needed.

**After this module:** Pass the extracted ELF paths to `sac_for_path()` or `BinaryContext.load_or_build()` for analysis.
