# ScanResultVersionCache

## Why this exists

Two things were not possible before in Ablation:

1. **Stale scanner results were undetectable.** When `LA64MaxNotMinScanner` gained the sltui variant and OR commutativity fix across sessions S28-S32, previously cached JSON sweep results became silently wrong. Nothing in the result said which scanner version produced it. In S35, re-discovering 23 kernel modules that the original sweep missed cost an entire session because there was no signal that the results were stale.

2. **Every scanner sweep was stateless.** Running a scanner across 1096 `.ko` files with no caching meant re-scanning unchanged files on every session, even when the scanner had not changed. There was no standard pattern that said "scan if the scanner or file changed, return the old result otherwise."

`ScanResultVersionCache` wraps any scanner and stores results on disk. It checks whether the scanner source changed and whether the target file changed before deciding to rescan. A full cache hit on 1096 `.ko` files costs only 1096 stat calls, not 1096 file reads.

## Usage

```python
from ablation.analyzers.scan_result_version_cache import ScanResultVersionCache
from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner

cache = ScanResultVersionCache.for_scanner(LA64MaxNotMinScanner)

# Single file. Returns list[dict] (findings as dicts).
findings = cache.get_or_scan('/path/to/file.ko')

# Batch. Returns dict[abspath, list[dict]].
ko_files = list(Path('/lib/modules/.../kernel/').rglob('*.ko'))
results = cache.scan_batch([str(p) for p in ko_files])
cache.save()   # writes to ~/.ablation/cache/scan_results/LA64MaxNotMinScanner.json

# Force a rescan regardless of cache state.
findings = cache.get_or_scan('/path/to/file.ko', force=True)

# Check cache state.
print(ScanResultVersionCache.report(cache.cache_stats()))
```

## How the cache key works

```
<scanner_version_hash>|<abspath>|<mtime_ns>|<size_bytes>|<sha256_prefix_16>
```

- `scanner_version_hash`: SHA-256 of `inspect.getsource(scanner_class)` truncated to 16 chars. Changes whenever the scanner source changes. No manual version bumping required.
- `mtime_ns`, `size_bytes`, `sha256_prefix_16`: these identify the file. The SHA-256 prefix catches same-size content changes that preserve mtime.

The fast path uses mtime_ns and size only (a stat call, no file read). Only when the fast path misses does the code read the file to compute the SHA-256. A batch of 1096 cached files costs 1096 stat calls.

## Cache file

Lives at `~/.ablation/cache/scan_results/<ClassName>.json`. Safe to delete; rebuilds on next use. Writes are atomic via a `.tmp` rename.

## Serialization

Findings come back as `list[dict]` via `dataclasses.asdict()`. If a caller needs the original dataclass type:

```python
from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinFinding
findings = [LA64MaxNotMinFinding(**d) for d in cache.get_or_scan(path)]
```

## Works with any scanner that follows the standard interface

```python
from ablation.analyzers.la64_heap_vuln_scanner import LA64HeapVulnScanner
cache = ScanResultVersionCache.for_scanner(LA64HeapVulnScanner)
results = cache.scan_batch(ko_files)
cache.save()
```

---

## How it works

`for_scanner(scanner_class)` builds a cache key from the scanner class's source file SHA-256 and stores it alongside the results. `get_or_scan(file_path)` computes the SHA-256 of the target file, checks whether both the scanner source and the file hash match the cached values, and returns the cached `list[dict]` on a hit. On a miss it runs the scanner's standard interface (`from_pe32plus(data)` or `scan_binary(path)`) and stores the result as `dataclasses.asdict()` output. `scan_batch()` runs `get_or_scan()` concurrently across a list of files and returns `dict[abspath, list[dict]]`. `save()` flushes all in-memory results to `~/.ablation/cache/scan_results/<ScannerClassName>.json`.

---

## Example output

```
ScanResultVersionCache  LA64MaxNotMinScanner
  cache: ~/.ablation/cache/scan_results/LA64MaxNotMinScanner.json
  scanner hash: 3f8a1c9d...  (source SHA-256 prefix)
  scan_batch /lib/modules/5.10.0/kernel/  1096 files
    cache hits : 1049  (no rescan)
    rescanned  : 47    (scanner or file changed)
    total time : 3.2 s (vs ~94 s without cache)
  findings    : 23 across 18 files
```

---

## False positives

The cache does not introduce false positives, it returns the wrapped scanner's results verbatim. If a scanner's findings change after a bug fix, call `get_or_scan(path, force=True)` or delete `~/.ablation/cache/scan_results/<ScannerClassName>.json` to force a full rescan. The scanner source hash invalidation catches this automatically when the scanner's `.py` file changes.

---

## Pipeline position

**Before this module:** The target files must exist on disk. No other Ablation setup required: `ScanResultVersionCache` wraps any scanner that follows the standard interface (`from_pe32plus(data)` or `scan_binary(path)` returning a findings list).

**After this module:** Pass results to downstream analysis or write to `~/VDT/VULNERABILITIES-<ip>.md`. The cache automatically invalidates on scanner source changes, so there is no manual cache management needed between sessions.

---

## Reading output

`ScanResultVersionCache(db_path, scanner_class).get_or_scan(file_path, force)` returns `List[dict]`: finding dicts converted from the scanner's dataclass findings via `dataclasses.asdict()`. The schema matches the wrapped scanner's finding class. Pass `force=True` to bypass the cache and always re-scan.

---

## See also

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
