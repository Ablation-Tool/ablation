"""
firmware_container_key_extractor.py — FirmwareContainerKeyExtractor

Recovers encryption keys embedded in Fortinet hardware firmware containers and decrypts
the inner partitions (rootfs.gz, datafs.tar.gz, signature) that remain encrypted after
the outer XOR layer is removed by FortiOSHardwareExtractor.

Four things that were not possible before this module:
  1. Hardware FortiGate cert keys (fgt_512.key etc.) were INACCESSIBLE from static
     analysis — FortiOSHardwareExtractor decrypts the outer XOR layer but the inner
     gzip partitions have a second encryption flag set (FENCRYPT / custom stream cipher).
     This module adds an RC4 KPA stage that recovers the inner key from known-plaintext
     at the gzip partition headers.
  2. PKCS#1 v1.5 block scanning: Fortinet embeds per-container encryption keys in the
     PKCS#1 v1.5 padding of the firmware's RSA signature block (FGT7K-2 finding).
     This scanner locates those blocks in the decrypted outer container and extracts
     candidate keys without needing the Fortinet RSA private key.
  3. RC4 known-plaintext key recovery: given candidate key bytes, tests RC4 decryption
     of each inner partition using the known gzip magic (0x1f 0x8b 0x08) as crib, and
     confirms which key produces valid gzip output.
  4. Manual key override: for cases where the key is known from prior analysis (e.g.
     hardware teardown, or PKCS#1 structure decryption via RSA key), supplies it directly
     to decrypt all inner partitions without the scan stage.

Supported inner encryption types:
  - RC4 stream cipher (FGT7K-2 class: 32-byte key embedded in PKCS#1 v1.5 padding)
  - XOR-stream cipher (same 64-byte key as outer layer — attempted as fallback)
  Not supported (requires further RE): gzip FENCRYPT (PKZIP DES-based), AES-CBC

Output lifetime: all paths in ExtractionResult point into result.workdir, a tempdir
created by from_path(). The caller must call result.cleanup() when done with the files.
Alternatively, pass output_dir= to from_path() to use a caller-managed directory
(cleanup is then the caller's responsibility; result.cleanup() is a no-op).

Usage:
    from ablation.analyzers.firmware_container_key_extractor import FirmwareContainerKeyExtractor

    # Full automatic extraction (KPA key recovery + decryption)
    result = FirmwareContainerKeyExtractor.from_path('/path/to/FGT_60F-v7.2.13.out')
    try:
        print(result.report())
        if result.datafs_path:
            import tarfile
            with tarfile.open(result.datafs_path, 'r:gz') as tar:
                fobj = tar.extractfile('etc/fgt_512.key')
                key_bytes = fobj.read()
    finally:
        result.cleanup()

    # Manual key override (key already known), caller-managed output dir
    result = FirmwareContainerKeyExtractor.from_path(
        '/path/to/firmware.out',
        override_key=bytes.fromhex('deadbeef...'),
        override_cipher='xor',
        output_dir='/tmp/my_analysis/'
    )
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import outer-layer extractor
from ablation.analyzers.fortios_firmware_extractor import FortiOSHardwareExtractor

# Known gzip magic and header constants for KPA crib
_GZIP_MAGIC = b"\x1f\x8b\x08"
_GZIP_CM_DEFLATE = 0x08

# PKCS#1 v1.5 signature structure constants
_PKCS1_HEADER = b"\x00\x01"         # Block type 01 (signature)
_PKCS1_PAD_BYTE = 0xFF
_PKCS1_SEP = 0x00                   # Separator between PS and DigestInfo

# RC4 key candidates extracted from PKCS#1 blocks are 16–64 bytes
_RC4_KEY_MIN = 16
_RC4_KEY_MAX = 64

# Minimum fraction of 0xFF bytes required in a PKCS#1 PS region to treat it as real padding
_PKCS1_FF_MIN_RATIO = 0.80

# Streaming chunk size for partition decryption (avoids loading full partition into memory)
_DECRYPT_CHUNK = 4 * 1024 * 1024   # 4 MiB


# ─── Gzip validation ─────────────────────────────────────────────────────────

def _gzip_valid_header(data: bytes) -> bool:
    """True if data starts with a valid 10-byte gzip header."""
    if len(data) < 10:
        return False
    if data[:3] != _GZIP_MAGIC:
        return False
    if data[3] != _GZIP_CM_DEFLATE:
        return False
    flg = data[4]
    if flg & 0b11100000:  # reserved bits 5-7 must be 0
        return False
    return True


# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class PartitionResult:
    kind: str                   # "gzip", "unknown"
    offset: int                 # offset in decrypted_full.bin
    encrypted_path: str         # raw encrypted partition bytes file
    decrypted_path: Optional[str] = None    # decrypted partition, if recovered
    key_used: Optional[bytes] = None        # encryption key that worked
    cipher: Optional[str] = None            # "rc4", "xor", "none"
    valid_gzip: bool = False


@dataclass
class ExtractionResult:
    fw_path: str
    outer_key: Optional[bytes] = None
    outer_key_confidence: float = 0.0
    pkcs1_candidates: List[bytes] = field(default_factory=list)
    partitions: List[PartitionResult] = field(default_factory=list)
    datafs_path: Optional[str] = None
    workdir: Optional[str] = None   # temp dir created by from_path(); caller must cleanup()
    error: Optional[str] = None

    def cleanup(self) -> None:
        """Remove the working directory created by from_path(), if any."""
        if self.workdir and os.path.isdir(self.workdir):
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.workdir = None

    def report(self) -> str:
        lines = [f"FirmwareContainerKeyExtractor: {self.fw_path}"]
        if self.error:
            lines.append(f"  ERROR: {self.error}")
            return "\n".join(lines)
        lines.append(f"  Outer XOR key confidence: {self.outer_key_confidence:.3f}")
        lines.append(f"  PKCS#1 candidate keys found: {len(self.pkcs1_candidates)}")
        for i, cand in enumerate(self.pkcs1_candidates):
            lines.append(f"    Candidate {i}: {cand.hex()} ({len(cand)} bytes)")
        lines.append(f"  Inner partitions: {len(self.partitions)}")
        for p in self.partitions:
            dec = "DECRYPTED" if p.decrypted_path else "ENCRYPTED"
            lines.append(
                f"    offset=0x{p.offset:08x} kind={p.kind} {dec} "
                f"cipher={p.cipher or 'unknown'}"
            )
        if self.datafs_path:
            lines.append(f"  datafs.tar.gz: {self.datafs_path}")
        else:
            lines.append("  datafs.tar.gz: NOT RECOVERED (key not found or wrong cipher type)")
        return "\n".join(lines)


# ─── Main class ───────────────────────────────────────────────────────────────

class FirmwareContainerKeyExtractor:
    """
    Recovers inner partition encryption keys from FortiOS hardware firmware containers.
    Combines outer XOR decryption (FortiOSHardwareExtractor) with PKCS#1 block scanning
    and RC4 known-plaintext key recovery.
    """

    def __init__(
        self,
        fw_path: str,
        override_key: Optional[bytes] = None,
        override_cipher: str = "rc4",
        output_dir: Optional[str] = None,
    ):
        self._fw_path = fw_path
        self._override_key = override_key
        self._override_cipher = override_cipher
        self._output_dir = output_dir
        self._decrypted_path: Optional[str] = None

    @classmethod
    def from_path(
        cls,
        fw_path: str,
        override_key: Optional[bytes] = None,
        override_cipher: str = "rc4",
        output_dir: Optional[str] = None,
    ) -> ExtractionResult:
        """
        Run the full extraction pipeline on a FortiOS hardware .out firmware file.

        output_dir: if given, all output files are written there and the caller is
        responsible for cleanup. If omitted, a temp dir is created and stored in
        result.workdir; caller must call result.cleanup() when done.
        """
        extractor = cls(fw_path, override_key, override_cipher, output_dir)
        return extractor._run()

    def _run(self) -> ExtractionResult:
        result = ExtractionResult(fw_path=self._fw_path)

        if self._output_dir:
            workdir = self._output_dir
            os.makedirs(workdir, exist_ok=True)
            caller_owns = True
        else:
            workdir = tempfile.mkdtemp(prefix="fce_")
            caller_owns = False

        try:
            result.workdir = workdir if not caller_owns else None
            self._extract_outer(result, workdir)
            if result.error:
                if not caller_owns and result.workdir:
                    shutil.rmtree(workdir, ignore_errors=True)
                    result.workdir = None
                return result
            self._scan_pkcs1_blocks(result)
            self._attempt_inner_decryption(result, workdir)
            self._identify_datafs(result)
        except Exception as exc:
            result.error = str(exc)
            if not caller_owns and result.workdir:
                shutil.rmtree(workdir, ignore_errors=True)
                result.workdir = None
        return result

    def _extract_outer(self, result: ExtractionResult, workdir: str) -> None:
        """Run FortiOSHardwareExtractor for outer XOR decryption."""
        outer_dir = os.path.join(workdir, "outer")
        hw_result = FortiOSHardwareExtractor.from_path(self._fw_path).extract_to(outer_dir)
        result.outer_key = hw_result.key
        result.outer_key_confidence = hw_result.key_confidence

        if result.outer_key_confidence < 0.5:
            result.error = (
                f"Outer XOR key confidence {result.outer_key_confidence:.3f} < 0.5; "
                "firmware may not be FortiOS format or key derivation failed"
            )
            return

        # Store path to decrypted full binary for PKCS#1 scanning
        decrypted_paths = [p for p in hw_result.extracted_paths if "decrypted_full" in p]
        if not decrypted_paths:
            result.error = "FortiOSHardwareExtractor did not produce decrypted_full.bin"
            return
        self._decrypted_path = decrypted_paths[0]

        # Record inner partition locations from HW extractor
        for ph in hw_result.partitions:
            pr = PartitionResult(
                kind=ph.kind,
                offset=ph.offset,
                encrypted_path=self._get_partition_path(hw_result, ph.offset),
            )
            result.partitions.append(pr)

    def _get_partition_path(self, hw_result, offset: int) -> str:
        """Find the extracted partition file matching a given offset."""
        for path in hw_result.extracted_paths:
            if f"0x{offset:010x}" in path or f"{offset:x}" in path:
                return path
        return ""

    def _scan_pkcs1_blocks(self, result: ExtractionResult) -> None:
        """
        Scan the outer-decrypted binary for PKCS#1 v1.5 signature blocks.
        Extracts non-0xFF bytes from the padding string as candidate encryption keys.
        Requires >= 80% of PS region to be 0xFF (real padding characteristic) to
        avoid false positives from arbitrary 0x00 0x01 byte sequences.
        """
        if not self._decrypted_path or not os.path.exists(self._decrypted_path):
            return

        with open(self._decrypted_path, "rb") as f:
            data = f.read()

        candidates = []
        pos = 0
        while pos < len(data) - 256:
            idx = data.find(_PKCS1_HEADER, pos, len(data) - 256)
            if idx == -1:
                break
            pos = idx + 1

            if idx + 2 >= len(data):
                continue

            # Find the 0x00 separator ending the PS region (within 256 bytes)
            ps_start = idx + 2
            ps_end = data.find(b"\x00", ps_start, ps_start + 256)
            if ps_end == -1 or (ps_end - ps_start) < 8:
                continue

            ps_bytes = data[ps_start:ps_end]

            # Require >= 80% 0xFF to treat this as a real PKCS#1 padding block
            ff_count = sum(1 for b in ps_bytes if b == 0xFF)
            if ff_count / len(ps_bytes) < _PKCS1_FF_MIN_RATIO:
                continue

            non_ff = bytes(b for b in ps_bytes if b != 0xFF)
            if _RC4_KEY_MIN <= len(non_ff) <= _RC4_KEY_MAX:
                candidates.append(non_ff)

            # Also try: full PS if it contains no 0xFF bytes at all
            if _RC4_KEY_MIN <= len(ps_bytes) <= _RC4_KEY_MAX and all(
                b != 0xFF for b in ps_bytes
            ):
                if ps_bytes not in candidates:
                    candidates.append(ps_bytes)

        # Deduplicate while preserving order
        seen: set = set()
        unique_candidates = []
        for c in candidates:
            ch = c.hex()
            if ch not in seen:
                seen.add(ch)
                unique_candidates.append(c)

        result.pkcs1_candidates = unique_candidates

    def _attempt_inner_decryption(self, result: ExtractionResult, workdir: str) -> None:
        """
        Try to decrypt each inner partition. Probes first 32 bytes per key
        (10-byte gzip header validation) before streaming the full partition.
        Keys tried in order:
          1. override_key dispatched to override_cipher
          2. PKCS#1 candidate keys via RC4
          3. Outer XOR key (fallback — same key, different position)
        """
        keys_to_try: List[Tuple[bytes, str]] = []
        if self._override_key:
            if len(self._override_key) == 0:
                pass  # empty override silently dropped
            else:
                keys_to_try.append((self._override_key, self._override_cipher))
        for cand in result.pkcs1_candidates:
            if len(cand) > 0:
                keys_to_try.append((cand, "rc4"))
        if result.outer_key and len(result.outer_key) > 0:
            keys_to_try.append((result.outer_key, "xor"))

        for i, pr in enumerate(result.partitions):
            if not os.path.exists(pr.encrypted_path):
                continue

            # Phase 1: probe first 32 bytes for each key candidate
            with open(pr.encrypted_path, "rb") as f:
                probe = f.read(32)

            if len(probe) < 10:
                continue

            for key_bytes, cipher_name in keys_to_try:
                if cipher_name in ("rc4", "override"):
                    probe_dec = _rc4_decrypt(probe, key_bytes)
                elif cipher_name == "xor":
                    probe_dec = _xor_decrypt(probe, key_bytes)
                else:
                    continue

                if not _gzip_valid_header(probe_dec):
                    continue

                # Phase 2: key confirmed — stream-decrypt the full partition
                out_path = os.path.join(workdir, f"partition_{i}_decrypted.bin")
                if cipher_name in ("rc4", "override"):
                    _stream_rc4_file(pr.encrypted_path, out_path, key_bytes)
                else:
                    _stream_xor_file(pr.encrypted_path, out_path, key_bytes)

                pr.decrypted_path = out_path
                pr.key_used = key_bytes
                pr.cipher = cipher_name
                pr.valid_gzip = True
                break

    def _identify_datafs(self, result: ExtractionResult) -> None:
        """
        Among decrypted partitions, find the one containing etc/fgt_512.key
        (the datafs.tar.gz). Store its path in result.datafs_path.
        """
        import tarfile
        for pr in result.partitions:
            if not pr.decrypted_path or not pr.valid_gzip:
                continue
            try:
                with tarfile.open(pr.decrypted_path, "r:gz") as tf:
                    names = tf.getnames()
                    if any("fgt_512.key" in n or "fgt.key" in n or "fgt2.key" in n for n in names):
                        result.datafs_path = pr.decrypted_path
                        return
            except Exception:
                continue


# ─── Cipher primitives ────────────────────────────────────────────────────────

def _rc4_decrypt(data: bytes, key: bytes) -> bytes:
    """RC4 stream cipher decryption for short buffers (probe/confirm only)."""
    if not key:
        raise ValueError("Cipher key must be non-empty")
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for idx, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[idx] = byte ^ S[(S[i] + S[j]) % 256]
    return bytes(out)


def _xor_decrypt(data: bytes, key: bytes) -> bytes:
    """Repeating XOR decryption for short buffers (probe/confirm only)."""
    if not key:
        raise ValueError("Cipher key must be non-empty")
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def _stream_rc4_file(src: str, dst: str, key: bytes) -> None:
    """Stream-decrypt src → dst with RC4, processing _DECRYPT_CHUNK bytes at a time."""
    if not key:
        raise ValueError("Cipher key must be non-empty")
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) % 256
        S[i], S[j] = S[j], S[i]
    ci = cj = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(_DECRYPT_CHUNK)
            if not chunk:
                break
            out = bytearray(len(chunk))
            for idx, byte in enumerate(chunk):
                ci = (ci + 1) % 256
                cj = (cj + S[ci]) % 256
                S[ci], S[cj] = S[cj], S[ci]
                out[idx] = byte ^ S[(S[ci] + S[cj]) % 256]
            fout.write(out)


def _stream_xor_file(src: str, dst: str, key: bytes) -> None:
    """Stream-decrypt src → dst with repeating XOR, processing _DECRYPT_CHUNK at a time."""
    if not key:
        raise ValueError("Cipher key must be non-empty")
    klen = len(key)
    byte_pos = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(_DECRYPT_CHUNK)
            if not chunk:
                break
            out = bytes(b ^ key[(byte_pos + i) % klen] for i, b in enumerate(chunk))
            fout.write(out)
            byte_pos += len(chunk)
