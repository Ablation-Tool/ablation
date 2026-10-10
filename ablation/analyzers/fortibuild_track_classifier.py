"""
fortibuild_track_classifier.py — FortiBuildTrackClassifier

Parses Fortinet firmware filenames and returns the build track (M/F), expected
cert key set, version, and product family — without any disk I/O.

Two things that were not possible before this module:

  1. No programmatic way to predict whether a firmware image ships one or three
     cert keys before running a full VMDK conversion and debugfs extraction.
     The M/F track distinction appears in the filename and deterministically
     predicts the key set, validated across every virtual format in the corpus:
     VMware OVF, Hyper-V VHD/VHDX, KVM QCOW2, ARM64 KVM.

  2. No way to detect anomalies in a batch scan: a M-build that unexpectedly
     ships only one key, or an F-build with three keys, would go unnoticed in
     raw FortiGateCertKeyScanner output. FortiBuildTrackClassifier produces
     a structured expected_keys prediction that callers can compare against
     scanner results to flag discrepancies as new findings.

Version determines the key generation:
  v6.x, v7.x  M-build: fgt_512.key (Gen1) + fgt2.key + fgt.key
  v8.0+        M-build: fgt_512.key (Gen2) + fgt2.key  (fgt.key dropped in v8.0)
  Any version  F-build: fgt_512.key only (Gen1 pre-v8, Gen2 v8+)

Filename pattern: <PRODUCT>-v<MAJOR>.<MINOR>.<PATCH>.<TRACK>-build<NUM>-FORTINET.<EXT>
Example: FGT_VM64_HV-v7.4.12.M-build2902-FORTINET.out.zip

Requirements: none (pure Python, no external tools).

Usage:
    from ablation.analyzers.fortibuild_track_classifier import FortiBuildTrackClassifier

    result = FortiBuildTrackClassifier.classify('FGT_VM64-v7.4.12.M-build2902-FORTINET.out.zip')
    print(result.build_track)        # 'M'
    print(result.expected_keys)      # ['fgt_512.key', 'fgt2.key', 'fgt.key']
    print(result.key_generation)     # 'Gen1'

    results = FortiBuildTrackClassifier.batch_classify([
        'FGT_VM64-v7.4.12.M-build2902-FORTINET.out.zip',
        'FGT_VM64_HV-v8.0.0.F-build0167-FORTINET.out.zip',
    ])
    print(FortiBuildTrackClassifier.report(results))

    # Cross-validate against FortiGateCertKeyScanner results
    scan_result = FortiGateCertKeyScanner.from_path(path)
    track_result = FortiBuildTrackClassifier.classify(path)
    actual_keys = set(scan_result.keys.keys())
    expected_keys = set(track_result.expected_keys)
    if actual_keys != expected_keys:
        print(f"Key set mismatch: expected {expected_keys}, got {actual_keys}")
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Fortinet firmware filename pattern
# Captures: product, major, minor, patch, track (M/F), build number
_FILENAME_RE = re.compile(
    r"(?P<product>[A-Z][A-Z0-9_]+)"
    r"-v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"\.(?P<track>[MF])"
    r"-build(?P<build>\d+)"
    r"-FORTINET"
)


@dataclass
class BuildTrackResult:
    filename: str                    # input filename (basename)
    product: str                     # e.g. "FGT_VM64", "FGT_VM64_HV", "FOS_VM64_KVM"
    version: str                     # e.g. "7.4.12"
    build_number: int                # e.g. 2902
    build_track: str                 # "M" or "F"
    expected_keys: List[str] = field(default_factory=list)
    key_generation: str = ""         # "Gen1" or "Gen2"
    error: Optional[str] = None

    def matches_scan(self, actual_keys: set) -> bool:
        """True if the actual key set from a scan matches expected_keys."""
        return set(self.expected_keys) == actual_keys

    def discrepancy(self, actual_keys: set) -> Optional[str]:
        """Return a human-readable discrepancy string, or None if keys match."""
        expected = set(self.expected_keys)
        if expected == actual_keys:
            return None
        missing = expected - actual_keys
        extra = actual_keys - expected
        parts = []
        if missing:
            parts.append(f"missing: {sorted(missing)}")
        if extra:
            parts.append(f"unexpected: {sorted(extra)}")
        return "; ".join(parts)


class FortiBuildTrackClassifier:
    """Parses Fortinet firmware filenames and predicts cert key sets."""

    @staticmethod
    def classify(filename: str) -> BuildTrackResult:
        """Parse a Fortinet firmware filename and return build track information.

        Accepts a full path or a bare filename. The result is derived entirely
        from the filename; no file I/O is performed.
        """
        name = os.path.basename(filename)
        m = _FILENAME_RE.search(name)
        if m is None:
            return BuildTrackResult(
                filename=name,
                product="",
                version="",
                build_number=0,
                build_track="",
                error=f"Filename does not match Fortinet pattern: {name!r}",
            )

        product = m.group("product")
        major = int(m.group("major"))
        minor = int(m.group("minor"))
        patch = m.group("patch")
        track = m.group("track")
        build = int(m.group("build"))
        version = f"{major}.{minor}.{patch}"

        expected_keys, key_gen = _predict_keys(track, major)

        return BuildTrackResult(
            filename=name,
            product=product,
            version=version,
            build_number=build,
            build_track=track,
            expected_keys=expected_keys,
            key_generation=key_gen,
        )

    @staticmethod
    def batch_classify(filenames: List[str]) -> List[BuildTrackResult]:
        """Classify a list of firmware filenames."""
        return [FortiBuildTrackClassifier.classify(f) for f in filenames]

    @staticmethod
    def report(results: List[BuildTrackResult]) -> str:
        lines = [
            "FortiBuildTrackClassifier",
            "=" * 72,
            f"{'Filename':<55} {'Track':<6} {'Gen':<5} {'Keys'}",
            "-" * 72,
        ]
        for r in results:
            if r.error:
                lines.append(f"{r.filename:<55} ERROR  {r.error}")
                continue
            keys_str = ", ".join(r.expected_keys) if r.expected_keys else "(none)"
            lines.append(
                f"{r.filename:<55} {r.build_track:<6} {r.key_generation:<5} {keys_str}"
            )
        lines.append("=" * 72)
        return "\n".join(lines)


# ─── Prediction logic ─────────────────────────────────────────────────────────

def _predict_keys(track: str, major_version: int) -> tuple:
    """Return (expected_keys list, key_generation string) given track and major version."""
    if track == "F":
        gen = "Gen2" if major_version >= 8 else "Gen1"
        return (["fgt_512.key"], gen)
    # M-build
    if major_version >= 8:
        return (["fgt_512.key", "fgt2.key"], "Gen2")
    return (["fgt_512.key", "fgt2.key", "fgt.key"], "Gen1")
