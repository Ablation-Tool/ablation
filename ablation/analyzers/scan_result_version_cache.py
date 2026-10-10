"""
scan_result_version_cache.py: version-aware persistent cache for any ablation scanner.

Invalidates automatically when the scanner source changes or the target file changes.
Results are stored as lists of dicts (JSON-serializable).  On a cache hit the caller
gets the same dict list back; on a miss the scanner is invoked and the results are
stored.

Usage:
    from ablation.analyzers.scan_result_version_cache import ScanResultVersionCache
    from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner
    import dataclasses

    cache = ScanResultVersionCache.for_scanner(LA64MaxNotMinScanner)
    findings = cache.get_or_scan('/path/to/file.ko')   # list[dict] on cache hit
    cache.save()

    # To force a re-scan regardless of cache:
    findings = cache.get_or_scan('/path/to/file.ko', force=True)

    # To scan a batch efficiently:
    results = cache.scan_batch([path1, path2, ...])   # dict[str, list[dict]]
    cache.save()

The cache file lives at ~/.ablation/cache/scan_results/<ClassName>.json and is safe to
delete — it will be rebuilt on next use.
"""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import os
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

_CACHE_ROOT = Path.home() / ".ablation" / "cache" / "scan_results"


def _scanner_version_hash(scanner_class: type) -> str:
    """SHA-256 of the scanner class source code, truncated to 16 hex chars."""
    try:
        src = inspect.getsource(scanner_class)
    except (OSError, TypeError):
        src = scanner_class.__name__
    return hashlib.sha256(src.encode()).hexdigest()[:16]


def _fast_stat(path: str) -> Optional[tuple]:
    """(mtime_ns, size_bytes) using stat only — no file read."""
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _file_fingerprint(path: str) -> Optional[tuple]:
    """(mtime_ns, size_bytes, sha256_prefix_16) or None if file unreadable."""
    try:
        st = os.stat(path)
        with open(path, "rb") as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()[:16]
        return (st.st_mtime_ns, st.st_size, sha)
    except OSError:
        return None


def _make_cache_key(scanner_version: str, file_path: str, fingerprint: tuple) -> str:
    mtime_ns, size, sha_prefix = fingerprint
    return f"{scanner_version}|{os.path.abspath(file_path)}|{mtime_ns}|{size}|{sha_prefix}"


def _key_prefix_for_fast_stat(scanner_version: str, abs_path: str, stat: tuple) -> str:
    mtime_ns, size = stat
    return f"{scanner_version}|{abs_path}|{mtime_ns}|{size}|"


def _serialize_finding(obj: Any) -> Any:
    """Convert a dataclass finding (or any object) to a JSON-safe value."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_serialize_finding(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _serialize_finding(v) for k, v in obj.items()}
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)


class ScanResultVersionCache:
    """Version-aware persistent cache for ablation scanner results.

    The cache key is (scanner_source_hash, file_abspath, file_mtime_ns, file_size,
    file_sha256_prefix).  Any change to the scanner source or the target file
    invalidates the entry and triggers a fresh scan.
    """

    def __init__(self, scanner_class: type, cache_path: Optional[Path] = None):
        self._scanner_class = scanner_class
        self._version_hash = _scanner_version_hash(scanner_class)
        if cache_path is None:
            _CACHE_ROOT.mkdir(parents=True, exist_ok=True)
            cache_path = _CACHE_ROOT / f"{scanner_class.__name__}.json"
        self._cache_path = Path(cache_path)
        self._cache: Dict[str, Any] = self._load()
        # prefix_index maps key-without-sha_suffix → full key for O(1) fast-path lookup.
        # Key format: {scanner_version}|{abspath}|{mtime_ns}|{size}|{sha_prefix}
        # Prefix = everything up to and including the 4th "|", i.e. rsplit("|",1)[0]+"|".
        self._prefix_index: Dict[str, str] = {
            k.rsplit('|', 1)[0] + '|': k for k in self._cache
        }
        self._dirty = False

    @classmethod
    def for_scanner(
        cls,
        scanner_class: type,
        cache_path: Optional[Path] = None,
    ) -> "ScanResultVersionCache":
        return cls(scanner_class, cache_path=cache_path)

    def _load(self) -> Dict[str, Any]:
        try:
            with open(self._cache_path, "r") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except (OSError, json.JSONDecodeError):
            pass
        return {}

    def save(self) -> None:
        if not self._dirty:
            return
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._cache_path.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            json.dump(self._cache, fh, indent=2)
        tmp.replace(self._cache_path)
        self._dirty = False

    def get_or_scan(self, file_path: str, force: bool = False, **scanner_kwargs) -> List[dict]:
        """Return cached results if valid; otherwise scan and cache.

        Returns a list of dicts (findings converted via dataclasses.asdict).
        ``force=True`` skips the cache and always re-scans.
        ``scanner_kwargs`` are forwarded to ``scanner_class.from_path()``.

        Fast path: uses stat (mtime_ns + size) only for the cache lookup.
        Only reads the file for SHA-256 when the fast path misses, ensuring
        a full cache hit for 1000+ files costs only stat calls, not file reads.
        """
        file_path = str(file_path)
        abs_path = os.path.abspath(file_path)

        if not force:
            # Fast path: stat only, no file read — O(1) via prefix index
            stat = _fast_stat(file_path)
            if stat is not None:
                prefix = _key_prefix_for_fast_stat(self._version_hash, abs_path, stat)
                full_key = self._prefix_index.get(prefix)
                if full_key is not None:
                    cached = self._cache.get(full_key)
                    if cached is not None:
                        return cached

        # Slow path: compute full fingerprint (reads file for SHA-256)
        fingerprint = _file_fingerprint(file_path)
        if fingerprint is None:
            return []

        cache_key = _make_cache_key(self._version_hash, file_path, fingerprint)

        if not force:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            scanner = self._scanner_class.from_path(file_path, **scanner_kwargs)
            raw_findings = scanner.scan()
        except Exception as e:
            warnings.warn(
                f"ScanResultVersionCache: {self._scanner_class.__name__} raised on "
                f"{file_path}: {e}",
                stacklevel=2,
            )
            return []

        serialized = [_serialize_finding(f) for f in raw_findings]
        self._cache[cache_key] = serialized
        self._prefix_index[cache_key.rsplit('|', 1)[0] + '|'] = cache_key
        self._dirty = True
        return serialized

    def scan_batch(
        self,
        file_paths: List[str],
        force: bool = False,
        **scanner_kwargs,
    ) -> Dict[str, List[dict]]:
        """Scan multiple files, using cache where valid.

        Returns {abspath: [finding_dict, ...]} for every path.
        Call ``save()`` after to persist results.
        """
        results: Dict[str, List[dict]] = {}
        for path in file_paths:
            results[os.path.abspath(str(path))] = self.get_or_scan(
                path, force=force, **scanner_kwargs
            )
        return results

    def is_cached(self, file_path: str) -> bool:
        """Return True if a valid (non-stale) cache entry exists for this file."""
        abs_path = os.path.abspath(str(file_path))
        stat = _fast_stat(str(file_path))
        if stat is None:
            return False
        prefix = _key_prefix_for_fast_stat(self._version_hash, abs_path, stat)
        return prefix in self._prefix_index

    def evict(self, file_path: str) -> bool:
        """Remove all cache entries for this file path. Returns True if anything was removed."""
        abs_path = os.path.abspath(str(file_path))
        # scanner_version is always 16 hex chars with no pipes, so split at the first "|"
        # gives (scanner_version, rest). rest starts with abs_path + "|" for matching entries.
        needle = abs_path + '|'
        evicted = [k for k in self._cache if k.split('|', 1)[1].startswith(needle)]
        for k in evicted:
            del self._cache[k]
            self._prefix_index.pop(k.rsplit('|', 1)[0] + '|', None)
        if evicted:
            self._dirty = True
        return bool(evicted)

    def cache_stats(self) -> dict:
        """Return a summary dict for diagnostics."""
        return {
            "scanner": self._scanner_class.__name__,
            "scanner_version_hash": self._version_hash,
            "cache_path": str(self._cache_path),
            "entries": len(self._cache),
            "cache_exists": self._cache_path.exists(),
        }

    @staticmethod
    def report(cache_stats: dict) -> str:
        lines = [
            f"ScanResultVersionCache: {cache_stats['scanner']}",
            f"  version hash : {cache_stats['scanner_version_hash']}",
            f"  cache file   : {cache_stats['cache_path']}",
            f"  entries      : {cache_stats['entries']}",
        ]
        return "\n".join(lines)
