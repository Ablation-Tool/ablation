"""
fortigate_cert_key_scanner.py — FortiGateCertKeyScanner

Batch-extracts and fingerprints cert keys from FortiGate firmware OVF/VMware packages.
Compares each extracted key MD5 against the known Fortinet shared key family table and
flags any unrecognised key variant as a potential new finding.

Three things that were not possible before this module:
  1. A single call to sweep a directory of FortiGate OVF ZIPs and report which known key
     families each version ships — previously required 5 manual steps per image.
  2. Automatic detection of an unrecognised key MD5 in a new firmware release, which
     would represent a new entry in the Fortinet shared-key corpus without manual comparison.
  3. Consistent, cache-aware batch processing: VMDK conversion takes ~30 seconds per image;
     cached results mean a sweep of 20+ versions runs in seconds after the first pass.

Supports FGT_VM64 OVF format (VMware/ESXi) and compatible formats that use the same
extraction pipeline: outer ZIP -> inner .out.ovf.zip -> fortios.vmdk -> qemu-img -> ext4 P1 ->
datafs.tar.gz -> cert key files.

Requirements: qemu-img, debugfs (e2fsprogs). Both must be on PATH.

Usage:
    from ablation.analyzers.fortigate_cert_key_scanner import FortiGateCertKeyScanner

    # Single image
    result = FortiGateCertKeyScanner.from_path('/path/to/FGT_VM64-v7.4.12.M.out.zip')
    print(FortiGateCertKeyScanner.report([result]))

    # Batch -- all OVF ZIPs in a directory
    results = FortiGateCertKeyScanner.batch_scan('/media/research/Fortinet/FortiGate/Firmware/Virtual/FGT_VM64/')
    print(FortiGateCertKeyScanner.report(results))

    # Check for unknown key variants (trigger: any result has keys with family='UNKNOWN')
    unknowns = [r for r in results if any(k.family == 'UNKNOWN' for k in r.keys.values())]

    # Force re-scan of a previously cached image (e.g. after a transient failure)
    result = FortiGateCertKeyScanner.from_path('/path/to/firmware.zip', force_rescan=True)
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# ─── Known key family fingerprints ───────────────────────────────────────────
# MD5 -> (family_name, severity, description)
# MD5 is used for family identification only, not integrity verification.
# Each KeyEntry also carries a sha256 field for cross-validation.
# Source: Fortinet firmware corpus RE sessions 1-21

KNOWN_KEY_FAMILIES: Dict[str, tuple] = {
    "1158fa1e43c915520a051fe4bebf90d6": (
        "fgt_512.key Gen1", "CRITICAL",
        "512-bit RSA, factorable in <1s; shared across FGT/FFW/FEXT/FWF families"
    ),
    "12b045d81de1c16c531e2a43e17f0332": (
        "fgt_512.key Gen2", "CRITICAL",
        "512-bit RSA, factorable in <1s; ARM64 v8.0.0 variant"
    ),
    "c8eaa255efceab1512356f46f90b57b5": (
        "fgt2.key", "CRITICAL",
        "2048-bit RSA, plaintext; cross-platform FGT/FFW; FortiRecorder MitM chain"
    ),
    "4e447a814e6ea1e8b9ac8581ffd4c600": (
        "fgt.key", "HIGH",
        "2048-bit RSA, plaintext; FGT VM64 + FortiWiFi JFFS2; FortiRecorder MitM chain"
    ),
    "c0ab56309ab9647b28529d412d44b676": (
        "fsw_512.key", "CRITICAL",
        "512-bit RSA, factorable in <1s; FortiSwitch v7 shared key"
    ),
}

# Key paths within datafs.tar.gz -- checked in order, first hit wins per name
_DATAFS_KEY_PATHS = [
    ("fgt_512.key", ["etc/fgt_512.key", "./etc/fgt_512.key"]),
    ("fgt2.key",    ["etc/fgt2.key",    "./etc/fgt2.key"]),
    ("fgt.key",     ["etc/fgt.key",     "./etc/fgt.key"]),
]

# P1 partition parameters (all FortiGate VM64 OVF images tested)
_P1_LBA_START = 2048
_P1_LBA_COUNT = 524288  # 256 MiB

# Input size limits to prevent resource exhaustion on corrupt/unexpected input
_MAX_OUTER_ZIP_SIZE = 4 * 1024 * 1024 * 1024   # 4 GiB
_MAX_VMDK_SIZE = 2 * 1024 * 1024 * 1024        # 2 GiB
_MAX_KEY_FILE_SIZE = 65536                       # RSA keys are < 4 KiB; guard against crafted archives

# Minimum datafs.tar.gz size to accept (zero or near-zero = debugfs failure)
_MIN_DATAFS_SIZE = 1024

# Cache file for previously scanned results
_CACHE_PATH = Path.home() / ".ablation" / "cache" / "fortigate_cert_key_scanner.json"
_CACHE_LOCK_PATH = _CACHE_PATH.with_suffix(".lock")


# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class KeyEntry:
    name: str           # e.g. "fgt_512.key"
    md5: str            # hexdigest (identification only -- not integrity; see sha256)
    sha256: str         # hexdigest (cross-validation)
    family: str         # family name or "UNKNOWN"
    severity: str       # "CRITICAL" / "HIGH" / "UNKNOWN"
    description: str    # human-readable note


@dataclass
class CertKeyScanResult:
    path: str                          # source firmware zip path
    version: str                       # parsed from filename or "unknown"
    keys: Dict[str, KeyEntry] = field(default_factory=dict)
    error: Optional[str] = None
    scan_time_s: float = 0.0
    from_cache: bool = False

    def has_unknown_keys(self) -> bool:
        return any(k.family == "UNKNOWN" for k in self.keys.values())

    def critical_count(self) -> int:
        return sum(1 for k in self.keys.values() if k.severity == "CRITICAL")


# ─── Scanner ─────────────────────────────────────────────────────────────────

class FortiGateCertKeyScanner:
    """
    Extracts and fingerprints cert keys from FortiGate OVF firmware packages.
    Identifies key families and flags unknown variants as potential new findings.
    """

    @staticmethod
    def from_path(ovf_zip_path: str, force_rescan: bool = False) -> CertKeyScanResult:
        """Scan a single FortiGate OVF zip file.

        force_rescan: bypass cache and re-run the full pipeline. Use after a
        transient failure (disk full, missing qemu-img) has been resolved.
        Error results are never cached, so force_rescan is only needed when
        a previous successful scan produced stale data.
        """
        path = str(ovf_zip_path)
        version = _parse_version(path)

        if not force_rescan:
            cached = _load_from_cache(path)
            if cached is not None:
                return cached

        t0 = time.time()
        result = CertKeyScanResult(path=path, version=version)
        try:
            with tempfile.TemporaryDirectory(prefix="fgt_cert_scan_") as tmp:
                datafs_path = _extract_datafs(path, tmp)
                if datafs_path is None:
                    result.error = "datafs.tar.gz not found in firmware"
                    return result
                keys = _extract_keys(datafs_path)
                for name, (md5hex, sha256hex) in keys.items():
                    family, severity, desc = KNOWN_KEY_FAMILIES.get(
                        md5hex,
                        ("UNKNOWN", "UNKNOWN", "Key not in known family table -- potential new finding")
                    )
                    result.keys[name] = KeyEntry(
                        name=name, md5=md5hex, sha256=sha256hex,
                        family=family, severity=severity, description=desc
                    )
        except Exception as exc:
            result.error = str(exc)
        result.scan_time_s = time.time() - t0
        if result.error is None:
            _save_to_cache(path, result)
        return result

    @staticmethod
    def batch_scan(
        source: str,
        glob_pattern: str = "**/*.zip",
        force_rescan: bool = False,
    ) -> List[CertKeyScanResult]:
        """
        Scan all matching OVF zip files under a directory.
        Returns results sorted by version string.
        """
        p = Path(source)
        if p.is_file():
            return [FortiGateCertKeyScanner.from_path(str(p), force_rescan=force_rescan)]
        zips = sorted(p.glob(glob_pattern))
        results = []
        for zp in zips:
            results.append(FortiGateCertKeyScanner.from_path(str(zp), force_rescan=force_rescan))
        return results

    @staticmethod
    def report(results: List[CertKeyScanResult]) -> str:
        lines = [
            "FortiGateCertKeyScanner",
            "=" * 70,
        ]
        for r in results:
            status = "ERROR" if r.error else ("UNKNOWN_KEY" if r.has_unknown_keys() else "OK")
            cache_tag = " [cached]" if r.from_cache else f" [{r.scan_time_s:.1f}s]"
            lines.append(f"\n{r.version}  {status}{cache_tag}")
            lines.append(f"  path: {r.path}")
            if r.error:
                lines.append(f"  ERROR: {r.error}")
                continue
            for name, ke in r.keys.items():
                sev_tag = f"[{ke.severity}]"
                lines.append(f"  {ke.name:<18} {ke.md5}  {sev_tag:<10} {ke.family}")
        lines.append("\n" + "=" * 70)
        total = len(results)
        errors = sum(1 for r in results if r.error)
        unknowns = sum(1 for r in results if r.has_unknown_keys())
        lines.append(
            f"Scanned {total} images | {errors} errors | {unknowns} unknown-key variants"
        )
        return "\n".join(lines)


# ─── Internal pipeline ────────────────────────────────────────────────────────

def _parse_version(path: str) -> str:
    """Extract version string from firmware filename."""
    name = Path(path).name
    import re
    m = re.search(r"-(v\d+\.\d+\.\d+\.[A-Z]?(?:-build\d+)?)", name)
    if m:
        return m.group(1)
    return name.split(".")[0]


def _extract_datafs(ovf_zip_path: str, workdir: str) -> Optional[str]:
    """
    Full extraction pipeline: outer ZIP -> inner OVF ZIP -> VMDK -> raw -> P1 ext4 -> datafs.tar.gz.
    Returns path to extracted datafs.tar.gz, or None on failure.
    """
    _check_tools()

    # Guard against oversized input before extracting anything
    zip_size = os.path.getsize(ovf_zip_path)
    if zip_size > _MAX_OUTER_ZIP_SIZE:
        raise ValueError(f"Outer ZIP too large: {zip_size} bytes (max {_MAX_OUTER_ZIP_SIZE})")

    inner_ovf_path = os.path.join(workdir, "inner.ovf.zip")
    vmdk_path = os.path.join(workdir, "fortios.vmdk")
    raw_path = os.path.join(workdir, "fortios.raw")
    p1_path = os.path.join(workdir, "p1.ext4")
    datafs_path = os.path.join(workdir, "datafs.tar.gz")

    with zipfile.ZipFile(ovf_zip_path, "r") as outer:
        names = outer.namelist()
        inner_candidates = [n for n in names if n.endswith(".ovf.zip")]
        if inner_candidates:
            outer.extract(inner_candidates[0], workdir)
            os.rename(os.path.join(workdir, inner_candidates[0]), inner_ovf_path)
            with zipfile.ZipFile(inner_ovf_path, "r") as inner:
                vmdk_names = [n for n in inner.namelist() if n.endswith(".vmdk") and "fortios" in n.lower()]
                if not vmdk_names:
                    vmdk_names = [n for n in inner.namelist() if n.endswith(".vmdk")]
                if not vmdk_names:
                    return None
                inner.extract(vmdk_names[0], workdir)
                os.rename(os.path.join(workdir, vmdk_names[0]), vmdk_path)
        else:
            out_candidates = [n for n in names if n.endswith(".out")]
            if not out_candidates:
                return None
            # Hardware .out format -- inner partitions encrypted; use FirmwareContainerKeyExtractor
            return None

    # Guard against oversized VMDK before invoking qemu-img
    vmdk_size = os.path.getsize(vmdk_path)
    if vmdk_size > _MAX_VMDK_SIZE:
        os.unlink(vmdk_path)
        raise ValueError(f"VMDK too large: {vmdk_size} bytes (max {_MAX_VMDK_SIZE})")

    subprocess.run(
        ["qemu-img", "convert", "-f", "vmdk", "-O", "raw", vmdk_path, raw_path],
        check=True, capture_output=True
    )
    os.unlink(vmdk_path)

    _dd_extract(raw_path, p1_path, skip=_P1_LBA_START, count=_P1_LBA_COUNT)
    os.unlink(raw_path)

    with open(p1_path, "rb") as f:
        header = f.read(2048)
    if header[1080:1082] != b"\x53\xef":
        os.unlink(p1_path)
        raise ValueError(f"P1 superblock magic check failed (expected 53ef, got {header[1080:1082].hex()})")

    # Find datafs.tar.gz inode via debugfs
    ls_proc = subprocess.run(
        ["debugfs", "-R", "ls -l /", p1_path],
        capture_output=True, text=True
    )
    inode = None
    for line in ls_proc.stdout.splitlines():
        if "datafs.tar.gz" in line and ".bak" not in line:
            parts = line.split()
            if parts:
                try:
                    inode = int(parts[0])
                    break
                except ValueError:
                    pass

    # Quote the destination path to handle spaces in TMPDIR
    if inode is not None:
        dump_cmd = f'dump <{inode}> "{datafs_path}"'
    else:
        dump_cmd = f'dump /datafs.tar.gz "{datafs_path}"'

    dump_proc = subprocess.run(
        ["debugfs", "-R", dump_cmd, p1_path],
        capture_output=True
    )
    os.unlink(p1_path)

    if dump_proc.returncode != 0:
        stderr = dump_proc.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"debugfs dump failed (rc={dump_proc.returncode}): {stderr}")

    if not os.path.exists(datafs_path) or os.path.getsize(datafs_path) < _MIN_DATAFS_SIZE:
        raise RuntimeError(
            f"debugfs dump produced no output or undersized file "
            f"(size={os.path.getsize(datafs_path) if os.path.exists(datafs_path) else 0})"
        )
    return datafs_path


def _extract_keys(datafs_path: str) -> Dict[str, tuple]:
    """Extract (MD5, SHA-256) fingerprints for each known cert key from datafs.tar.gz."""
    keys: Dict[str, tuple] = {}
    with tarfile.open(datafs_path, "r:gz") as tar:
        for key_name, candidate_paths in _DATAFS_KEY_PATHS:
            for cpath in candidate_paths:
                try:
                    member = tar.getmember(cpath)
                    if member.size > _MAX_KEY_FILE_SIZE:
                        raise ValueError(
                            f"Key file {cpath} unexpectedly large: {member.size} bytes "
                            f"(max {_MAX_KEY_FILE_SIZE}) -- possible corrupt or crafted archive"
                        )
                    fobj = tar.extractfile(member)
                    if fobj is None:
                        continue
                    data = fobj.read()
                    if data:
                        md5hex = hashlib.md5(data).hexdigest()
                        sha256hex = hashlib.sha256(data).hexdigest()
                        keys[key_name] = (md5hex, sha256hex)
                        break
                except KeyError:
                    continue
    return keys


def _dd_extract(src: str, dst: str, skip: int, count: int, bs: int = 512) -> None:
    """Extract a byte range from src to dst using seek/read (no external dd needed)."""
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fin.seek(skip * bs)
        remaining = count * bs
        chunk = 65536
        while remaining > 0:
            data = fin.read(min(chunk, remaining))
            if not data:
                break
            fout.write(data)
            remaining -= len(data)


def _check_tools() -> None:
    """Raise RuntimeError if required external tools are missing."""
    missing = []
    for tool in ("qemu-img", "debugfs"):
        if shutil.which(tool) is None:
            missing.append(tool)
    if missing:
        raise RuntimeError(
            f"Required tools not found on PATH: {', '.join(missing)}. "
            "Install qemu-utils and e2fsprogs."
        )


# ─── Cache helpers ────────────────────────────────────────────────────────────

def _cache_key(path: str) -> str:
    stat = os.stat(path)
    # Use nanosecond mtime to avoid false cache hits on files modified in the same second
    return f"{path}:{stat.st_size}:{stat.st_mtime_ns}"


def _load_from_cache(path: str) -> Optional[CertKeyScanResult]:
    try:
        if not _CACHE_PATH.exists():
            return None
        with open(_CACHE_PATH) as f:
            cache = json.load(f)
        key = _cache_key(path)
        if key not in cache:
            return None
        entry = cache[key]
        result = CertKeyScanResult(
            path=entry["path"],
            version=entry["version"],
            error=entry.get("error"),
            scan_time_s=entry.get("scan_time_s", 0.0),
            from_cache=True,
        )
        for name, ke_dict in entry.get("keys", {}).items():
            # sha256 may be absent in older cache entries written before this field was added
            ke_dict.setdefault("sha256", "")
            result.keys[name] = KeyEntry(**ke_dict)
        return result
    except Exception:
        return None


def _save_to_cache(path: str, result: CertKeyScanResult) -> None:
    """Write scan result to cache with exclusive file lock and atomic write."""
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_CACHE_LOCK_PATH, "w") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                cache: dict = {}
                if _CACHE_PATH.exists():
                    try:
                        with open(_CACHE_PATH) as f:
                            cache = json.load(f)
                    except Exception:
                        cache = {}
                key = _cache_key(path)
                cache[key] = {
                    "path": result.path,
                    "version": result.version,
                    "error": result.error,
                    "scan_time_s": result.scan_time_s,
                    "keys": {
                        name: {
                            "name": ke.name, "md5": ke.md5, "sha256": ke.sha256,
                            "family": ke.family, "severity": ke.severity,
                            "description": ke.description,
                        }
                        for name, ke in result.keys.items()
                    },
                }
                tmp_path = _CACHE_PATH.with_suffix(".tmp")
                with open(tmp_path, "w") as f:
                    json.dump(cache, f, indent=2)
                os.replace(tmp_path, _CACHE_PATH)
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)
    except Exception:
        pass  # Cache failure never blocks scan results
