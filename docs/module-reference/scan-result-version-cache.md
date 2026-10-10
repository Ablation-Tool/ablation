# ScanResultVersionCache

## Why this exists

2 things that weren't possible before in Ablation:

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
