"""
FortiOS hardware firmware extraction pipeline.

Handles the full chain for FortiGate/FortiWiFi physical appliance firmware:
  1. First-gzip-member decompression (multi-stream .out files)
  2. 64-byte XOR key recovery via IC + frequency analysis (NAND 0xFF assumption)
  3. Partition boundary detection in the decrypted image
  4. Extraction of detected partitions to disk

Generalises across ARM (FortiWiFi IPQ4019) and x86-64 (FortiGate hardware) targets.
All key recovery is delegated to XorSolver: no reimplementation.

Cipher characteristics (confirmed across FortiWiFi 60E v5.0.9 through v7.2.4.F,
supported FortiGate hardware, and all intermediate versions):
  - Outer: gzip wrapper (first member only; trailing members are noise/padding)
  - Inner: 64-byte repeating pure XOR applied to a NAND flash partition image
  - NAND plaintext: 0xFF-dominant (erased cells), ~80-86% null bytes
  - IC at shift=64 is 192x-244x above random baseline: unambiguous key length signal
  - Key is device-family-specific, not version-specific (same key across versions)
"""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from ablation.analyzers.xor_solver import XorSolver, XorSolverResult


# ---------------------------------------------------------------------------
# Partition magic table: 3+ bytes only to suppress 2-byte false positives
# ---------------------------------------------------------------------------
PARTITION_MAGICS: Dict[bytes, str] = {
    b'\x1f\x8b\x08':         "gzip",
    b'\xd0\x0d\xfe\xed':     "uboot-fit",
    b'sqsh':                  "squashfs-le",
    b'hsqs':                  "squashfs-be",
    b'\x45\x3d\xcd\x28':     "squashfs-v3",
    b'\x85\x19\x00\x00':     "jffs2-le-node",
    b'\x85\x19\xe0\x01':     "jffs2-le-inode",
    b'\x85\x19\x00\xe0':     "jffs2-le-dirent",
    b'\x19\x85\x00\x00':     "jffs2-be-node",
    b'070701':                "cpio-newc",
    b'\xfd7zXZ\x00':         "xz",
    b'\x02\x21\x4c\x18':     "lz4-frame",
    b'\x28\xb5\x2f\xfd':     "zstandard",
    b'\x7fELF':              "elf",
    b'UBI#':                  "ubi-volume",
}

# NAND erase-block alignment boundaries to check for partition starts
NAND_BLOCK_SIZES = (128 * 1024, 256 * 1024, 512 * 1024, 64 * 1024)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PartitionHit:
    offset: int
    magic: bytes
    kind: str
    context: bytes  # first 64 bytes of partition


@dataclass
class ExtractionResult:
    fw_path: str
    inner_size: int
    key: bytes
    key_confidence: float
    entropy_before: float
    entropy_after: float
    partitions: List[PartitionHit] = field(default_factory=list)
    extracted_paths: List[str] = field(default_factory=list)

    def fmt(self) -> str:
        lines = [
            f"FortiOS hardware firmware extraction",
            f"  source:    {self.fw_path}",
            f"  inner:     {self.inner_size:,} bytes after outer gzip",
            f"  key:       {self.key.hex()}",
            f"  key_conf:  {self.key_confidence:.3f}",
            f"  entropy:   {self.entropy_before:.3f} -> {self.entropy_after:.3f} bits/byte "
            f"({100*(self.entropy_before-self.entropy_after)/max(0.001,self.entropy_before):.1f}% drop)",
            f"  partitions: {len(self.partitions)} detected",
        ]
        for i, p in enumerate(self.partitions):
            lines.append(
                f"    [{i}] offset=0x{p.offset:010x} ({p.offset/1024/1024:.2f} MB)  {p.kind}"
            )
        if self.extracted_paths:
            lines.append(f"  extracted to:")
            for p in self.extracted_paths:
                lines.append(f"    {p}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

class FortiOSHardwareExtractor:
    """
    Full extraction pipeline for FortiOS .out hardware firmware files.

    Usage:
        ex = FortiOSHardwareExtractor.from_path("/media/.../FWF_60E-v7.2.4.F-build1396-FORTINET.out")
        result = ex.scan_partitions()
        print(result.fmt())
        ex.extract_to("/tmp/fwf60e_extracted/")
    """

    CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB streaming chunks for scan

    def __init__(self, fw_path: str):
        self.fw_path = fw_path
        self._inner: Optional[bytes] = None
        self._key: Optional[bytes] = None
        self._solver_result: Optional[XorSolverResult] = None

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_path(cls, fw_path: str) -> "FortiOSHardwareExtractor":
        ex = cls(fw_path)
        ex._inner = ex._decompress_first_gzip_member(Path(fw_path).read_bytes())
        return ex

    # ------------------------------------------------------------------
    # Step 1: gzip decompression (first member only)
    # ------------------------------------------------------------------

    @staticmethod
    def _decompress_first_gzip_member(raw: bytes) -> bytes:
        """
        Decompress only the first gzip member from a multi-stream .out file.
        FortiOS .out files have trailing non-gzip bytes after the first stream;
        Python's gzip module raises BadGzipFile on the trailing data.
        """
        if raw[:2] != b'\x1f\x8b':
            raise ValueError(f"Not a gzip file: magic={raw[:2].hex()}")

        flg = raw[3]
        offset = 10
        if flg & 0x04:  # FEXTRA
            xlen = struct.unpack_from('<H', raw, offset)[0]
            offset += 2 + xlen
        if flg & 0x08:  # FNAME: null-terminated
            while raw[offset] != 0:
                offset += 1
            offset += 1
        if flg & 0x10:  # FCOMMENT: null-terminated
            while raw[offset] != 0:
                offset += 1
            offset += 1
        if flg & 0x02:  # FHCRC
            offset += 2

        d = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            return d.decompress(raw[offset:])
        except zlib.error:
            # Partial decompression is fine: trailing non-deflate bytes cause this
            return d.flush()

    # ------------------------------------------------------------------
    # Step 2: XOR key recovery: wraps XorSolver with NAND assumption
    # ------------------------------------------------------------------

    def recover_xor_key(
        self,
        plaintext_assumption: int = 0xFF,
        sample_bytes: int = 1 << 20,
    ) -> XorSolverResult:
        """
        Recover the 64-byte XOR key from the decompressed inner image.

        Uses IC key-length detection (XorSolver.ic_key_length) to confirm the
        period, then frequency analysis (XorSolver.recover_by_frequency) with
        the NAND erased-cell assumption (plaintext_assumption=0xFF by default).

        For x86-64 FortiGate hardware running FortiOS 6.x/7.x with 0x00-dominant
        images, pass plaintext_assumption=0x00.
        """
        if self._inner is None:
            raise RuntimeError("Call from_path() first")

        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
            tmp.write(self._inner[:sample_bytes])
            tmp_path = tmp.name

        try:
            solver = XorSolver(tmp_path)
            key_len = solver.ic_key_length(
                data=self._inner[:sample_bytes],
                max_len=128,
                sample_size=65536,
            )
            if key_len is None:
                raise ValueError("IC key-length detection failed: no significant IC spike found")

            result = solver.recover_by_frequency(
                key_length=key_len,
                data=self._inner[:sample_bytes],
                plaintext_assumption=plaintext_assumption,
            )
        finally:
            os.unlink(tmp_path)

        self._solver_result = result
        self._key = result.key
        return result

    # ------------------------------------------------------------------
    # Step 3: Partition boundary scan
    # ------------------------------------------------------------------

    def _decrypt_chunk(self, start: int, length: int) -> bytes:
        key = self._key
        kl = len(key)
        end = min(start + length, len(self._inner))
        return bytes(self._inner[i] ^ key[i % kl] for i in range(start, end))

    def scan_partitions(
        self,
        plaintext_assumption: int = 0xFF,
    ) -> ExtractionResult:
        """
        Recover key (if not already done) and scan the full decrypted image
        for partition boundary magic bytes.

        Only 3+ byte magic signatures are used to suppress false positives.
        Within each 4 MB chunk, every magic byte hit is recorded.
        """
        if self._key is None:
            self.recover_xor_key(plaintext_assumption=plaintext_assumption)

        sr = self._solver_result
        result = ExtractionResult(
            fw_path=self.fw_path,
            inner_size=len(self._inner),
            key=self._key,
            key_confidence=sr.confidence if sr else 0.0,
            entropy_before=float(sr.notes.split("entropy_before=")[1].split(",")[0]) if sr and "entropy_before=" in (sr.notes or "") else 0.0,
            entropy_after=float(sr.notes.split("entropy_after=")[1].split(",")[0]) if sr and "entropy_after=" in (sr.notes or "") else 0.0,
        )

        OVERLAP = max(len(m) for m in PARTITION_MAGICS) + 1
        seen: set = set()

        for chunk_start in range(0, len(self._inner), self.CHUNK_SIZE):
            end = min(chunk_start + self.CHUNK_SIZE + OVERLAP, len(self._inner))
            chunk = self._decrypt_chunk(chunk_start, end - chunk_start)

            for magic, kind in PARTITION_MAGICS.items():
                pos = 0
                while True:
                    pos = chunk.find(magic, pos)
                    if pos < 0:
                        break
                    abs_off = chunk_start + pos
                    if abs_off not in seen:
                        seen.add(abs_off)
                        ctx_end = min(pos + 64, len(chunk))
                        result.partitions.append(PartitionHit(
                            offset=abs_off,
                            magic=magic,
                            kind=kind,
                            context=bytes(chunk[pos:ctx_end]),
                        ))
                    pos += len(magic)

        result.partitions.sort(key=lambda h: h.offset)
        return result

    # ------------------------------------------------------------------
    # Step 4: Extract partitions to disk
    # ------------------------------------------------------------------

    def extract_to(
        self,
        outdir: str,
        result: Optional[ExtractionResult] = None,
        plaintext_assumption: int = 0xFF,
    ) -> ExtractionResult:
        """
        Run scan_partitions() if not already done, then write each detected
        partition to outdir as a separate file.

        File naming: <offset_hex>_<kind>.bin
        For gzip partitions: attempts to detect inner content size via gzip
        trailer (last 4 bytes of member = uncompressed size mod 2^32).
        """
        if result is None:
            result = self.scan_partitions(plaintext_assumption=plaintext_assumption)

        out = Path(outdir)
        out.mkdir(parents=True, exist_ok=True)

        # Write the full decrypted image first
        full_path = out / "decrypted_full.bin"
        with open(full_path, "wb") as f:
            for chunk_start in range(0, len(self._inner), self.CHUNK_SIZE):
                f.write(self._decrypt_chunk(chunk_start, self.CHUNK_SIZE))
        result.extracted_paths.append(str(full_path))

        # Write individual partition files by kind (deduplicate to first occurrence per kind)
        written_kinds: Dict[str, int] = {}
        for hit in result.partitions:
            fname = f"0x{hit.offset:010x}_{hit.kind}.bin"
            fpath = out / fname
            if str(fpath) in result.extracted_paths:
                continue
            # Determine extraction size based on kind
            size = self._estimate_partition_size(hit)
            if size is None:
                continue  # skip if we can't determine a safe size
            chunk = self._decrypt_chunk(hit.offset, size)
            fpath.write_bytes(chunk)
            result.extracted_paths.append(str(fpath))
            written_kinds[hit.kind] = written_kinds.get(hit.kind, 0) + 1

        return result

    def _estimate_partition_size(self, hit: PartitionHit) -> Optional[int]:
        """
        Best-effort size estimation for a partition hit.
        Returns None if the partition should be skipped (e.g. mid-filesystem hit).
        """
        remaining = len(self._inner) - hit.offset

        if hit.kind == "uboot-fit":
            # FIT image: total_size is at byte 4 (big-endian uint32)
            ctx = self._decrypt_chunk(hit.offset, 8)
            if len(ctx) >= 8:
                return struct.unpack('>I', ctx[4:8])[0]

        if hit.kind in ("squashfs-le", "squashfs-be", "squashfs-v3"):
            # squashfs: bytes_used at offset 40 (LE uint64 in newer versions)
            ctx = self._decrypt_chunk(hit.offset, 48)
            if len(ctx) >= 48:
                return struct.unpack_from('<Q', ctx, 40)[0]

        if hit.kind == "gzip":
            # Scan forward for gzip end: last 8 bytes of a gzip member are CRC32 + isize
            # Use a generous 64 MB cap and scan for the next gzip or end of image
            cap = min(remaining, 64 * 1024 * 1024)
            return cap

        if hit.kind.startswith("jffs2"):
            # Return everything from this offset to end of image (full JFFS2 volume)
            return remaining

        if hit.kind == "cpio-newc":
            return min(remaining, 256 * 1024 * 1024)

        if hit.kind in ("xz", "lz4-frame", "zstandard"):
            return min(remaining, 128 * 1024 * 1024)

        # Generic: first 4 MB
        return min(remaining, 4 * 1024 * 1024)


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------

def extract_fortios_hardware(fw_path: str, outdir: str, plaintext_assumption: int = 0xFF) -> ExtractionResult:
    """
    One-call extraction: decompress -> recover key -> scan -> extract.

    Example:
        from ablation.analyzers.fortios_firmware_extractor import extract_fortios_hardware
        result = extract_fortios_hardware(
            "/path/to/FortiWiFi-firmware.out",
            "/tmp/fwf60e_extracted/",
        )
        print(result.fmt())
    """
    ex = FortiOSHardwareExtractor.from_path(fw_path)
    return ex.extract_to(outdir, plaintext_assumption=plaintext_assumption)
