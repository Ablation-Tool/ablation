"""
fortimail_vmdk_extractor.py — FortiMailVmdkExtractor

Extracts private key material from FortiMail VM firmware images distributed
as VMware OVF/VMDK packages. FortiMail stores its PKI keys
(fgt_512.key, fgt_2048.key) inside datafs.tar.gz on the P2 ext4 partition of
its virtual disk — a layout not handled by FortiOSHardwareExtractor (which
targets NAND flash XOR images).

Four things this module adds:
  1. OVF zip extraction: unwraps FortiMail .zip → finds the embedded VMDK.
  2. VMDK → raw conversion: calls qemu-img convert to produce a flat raw image
     so MBR partition tables and ext4 filesystems are byte-addressable.
  3. Root-free ext4 access: uses dd to extract the P2 partition as a flat
     image, then runs debugfs on that image to dump datafs.tar.gz without
     needing a loop mount or root privileges.
  4. Key blob extraction: reads etc/fgt_512.key, etc/fgt_2048.key (and the
     matching .crt files) from datafs.tar.gz, returning them as ExtractedKey
     objects with metadata for downstream PEM/DER analysis.

Confirmed targets (byte-verified):
  FortiMail VM64 v6.4.3 build0437 through v8.0.0 build0183 (9 versions).
  P2 partition: LBA 12289, size ~600 MB, ext4, contains datafs.tar.gz.

Usage:
    from ablation.analyzers.fortimail_vmdk_extractor import FortiMailVmdkExtractor

    # From an OVF zip (the usual distribution format)
    result = FortiMailVmdkExtractor.from_zip('/path/to/FML_VM-64-v761.F-build0729-FORTINET.zip')
    for key in result.keys:
        print(f'{key.name}: {key.md5} ({key.bit_size}-bit RSA, valid={key.rsa_valid})')
    result.cleanup()

    # From a bare VMDK (already extracted)
    result = FortiMailVmdkExtractor.from_vmdk('/path/to/fortimail-vm-disk1.vmdk')
    if result.datafs_path:
        import tarfile
        with tarfile.open(result.datafs_path, 'r:gz') as tar:
            key_bytes = tar.extractfile('etc/fgt_2048.key').read()
    result.cleanup()

    # With a caller-managed output directory (no auto-cleanup)
    result = FortiMailVmdkExtractor.from_zip(zip_path, output_dir='/tmp/fml_analysis/')
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ─── MBR constants ────────────────────────────────────────────────────────────

_MBR_SIZE = 512
_MBR_SIGNATURE = b"\x55\xaa"
_MBR_PART_OFFSET = 446        # offset of 4× 16-byte partition entries
_MBR_PART_ENTRY_SIZE = 16
_MBR_PART_COUNT = 4

# Byte offsets within a 16-byte MBR partition entry (little-endian)
_PART_STATUS = 0              # 1 byte: 0x80 = bootable, 0x00 = not
_PART_TYPE = 4                # 1 byte: partition type
_PART_LBA_START = 8           # 4 bytes: LBA of first sector
_PART_LBA_SIZE = 12           # 4 bytes: sector count

_SECTOR_SIZE = 512

# ext4 partition type codes (Linux)
_EXT_TYPES = {0x83, 0x0E}     # 0x83 = Linux, 0x0E = FAT16 LBA (occasional mistype in VMs)

# FortiMail-specific: P2 is the 2nd partition entry, LBA ~12289
# We parse the MBR dynamically rather than hardcoding this.

# Files we extract from datafs.tar.gz
_KEY_FILES = [
    "etc/fgt_512.key",
    "etc/fgt_2048.key",
    "etc/fgt_512.crt",
    "etc/fgt_2048.crt",
    "etc/fgt.key",
    "etc/fgt.crt",
]


# ─── Result dataclasses ───────────────────────────────────────────────────────

@dataclass
class PartitionInfo:
    index: int            # 0-based partition table index
    type_code: int        # MBR partition type byte
    lba_start: int        # LBA of first sector
    lba_size: int         # sector count
    byte_offset: int      # lba_start * 512
    byte_size: int        # lba_size * 512


@dataclass
class ExtractedKey:
    name: str             # e.g. "etc/fgt_512.key"
    path: str             # absolute path in workdir
    md5: str
    sha256: str
    bit_size: int         # RSA key size in bits (0 if not RSA PEM)
    rsa_valid: bool       # openssl rsa -check succeeded
    cert_path: Optional[str] = None     # path to matching .crt if present
    cert_md5: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_not_before: Optional[str] = None


@dataclass
class VmdkExtractionResult:
    vmdk_path: str                     # source VMDK
    raw_path: Optional[str] = None    # converted raw image (in workdir)
    partitions: List[PartitionInfo] = field(default_factory=list)
    datafs_path: Optional[str] = None # extracted datafs.tar.gz
    keys: List[ExtractedKey] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    _workdir: Optional[str] = None    # managed temp dir (None = caller-managed)

    def cleanup(self) -> None:
        if self._workdir and os.path.isdir(self._workdir):
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None

    def report(self) -> str:
        lines = [
            f"FortiMailVmdkExtractor — {os.path.basename(self.vmdk_path)}",
            f"  Partitions found: {len(self.partitions)}",
        ]
        for p in self.partitions:
            lines.append(
                f"    P{p.index+1}: type=0x{p.type_code:02x} "
                f"LBA_start={p.lba_start} LBA_size={p.lba_size} "
                f"offset=0x{p.byte_offset:x}"
            )
        if self.datafs_path:
            lines.append(f"  datafs.tar.gz: {self.datafs_path}")
        if self.keys:
            lines.append(f"  Keys extracted: {len(self.keys)}")
            for k in self.keys:
                valid = "RSA key ok" if k.rsa_valid else "NOT valid RSA"
                lines.append(
                    f"    {k.name}: MD5={k.md5} {k.bit_size}-bit {valid}"
                )
                if k.cert_subject:
                    lines.append(f"      cert subject: {k.cert_subject}")
                if k.cert_not_before:
                    lines.append(f"      cert not_before: {k.cert_not_before}")
        if self.errors:
            lines.append(f"  Errors ({len(self.errors)}):")
            for e in self.errors:
                lines.append(f"    {e}")
        return "\n".join(lines)


# ─── Main class ───────────────────────────────────────────────────────────────

class FortiMailVmdkExtractor:
    """
    Extracts PKI keys from FortiMail VM firmware (OVF zip or bare VMDK).

    Pipeline: OVF zip → VMDK → raw image → MBR parse → P2 offset →
              dd P2 → debugfs dump datafs.tar.gz → extract key/cert files.

    Does not require root privileges (uses qemu-img + dd + debugfs).
    """

    # ── Public entry points ──────────────────────────────────────────────────

    @classmethod
    def from_zip(
        cls,
        zip_path: str,
        output_dir: Optional[str] = None,
    ) -> VmdkExtractionResult:
        """
        Extract keys from a FortiMail OVF distribution zip.
        The zip contains an OVF descriptor + one or more .vmdk files.
        """
        workdir, managed = cls._make_workdir(output_dir)
        result = VmdkExtractionResult(vmdk_path=zip_path, _workdir=workdir if managed else None)

        try:
            vmdk_path = cls._extract_vmdk_from_zip(zip_path, workdir, result)
            if vmdk_path is None:
                return result
            result.vmdk_path = vmdk_path
            cls._run_pipeline(vmdk_path, workdir, result)
        except Exception as exc:
            result.errors.append(f"from_zip unhandled exception: {exc}")
        return result

    @classmethod
    def from_vmdk(
        cls,
        vmdk_path: str,
        output_dir: Optional[str] = None,
    ) -> VmdkExtractionResult:
        """Extract keys from a bare .vmdk file (streamOptimized or monolithic)."""
        workdir, managed = cls._make_workdir(output_dir)
        result = VmdkExtractionResult(vmdk_path=vmdk_path, _workdir=workdir if managed else None)
        try:
            cls._run_pipeline(vmdk_path, workdir, result)
        except Exception as exc:
            result.errors.append(f"from_vmdk unhandled exception: {exc}")
        return result

    # ── Internal pipeline ────────────────────────────────────────────────────

    @classmethod
    def _run_pipeline(
        cls,
        vmdk_path: str,
        workdir: str,
        result: VmdkExtractionResult,
    ) -> None:
        """VMDK → raw → MBR → debugfs dump → key extraction."""
        raw_path = cls._convert_to_raw(vmdk_path, workdir, result)
        if raw_path is None:
            return
        result.raw_path = raw_path

        partitions = cls._parse_mbr(raw_path, result)
        result.partitions = partitions

        p2 = cls._find_p2(partitions, result)
        if p2 is None:
            return

        datafs_path = cls._dump_datafs(raw_path, p2.byte_offset, workdir, result)
        if datafs_path is None:
            return
        result.datafs_path = datafs_path

        result.keys = cls._extract_keys(datafs_path, workdir, result)

    @classmethod
    def _make_workdir(cls, output_dir: Optional[str]) -> tuple[str, bool]:
        """Return (workdir_path, is_managed). Managed means we created it."""
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            return output_dir, False
        return tempfile.mkdtemp(prefix="fml_vmdk_"), True

    # ── OVF zip extraction ───────────────────────────────────────────────────

    @classmethod
    def _extract_vmdk_from_zip(
        cls,
        zip_path: str,
        workdir: str,
        result: VmdkExtractionResult,
    ) -> Optional[str]:
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                vmdk_names = [n for n in zf.namelist() if n.lower().endswith(".vmdk")]
                if not vmdk_names:
                    result.errors.append("No .vmdk found in zip")
                    return None
                # Prefer the disk image file (not descriptor .vmdk which is ~1KB)
                target = cls._pick_disk_vmdk(zf, vmdk_names)
                out_path = os.path.join(workdir, os.path.basename(target))
                with zf.open(target) as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                return out_path
        except Exception as exc:
            result.errors.append(f"zip extraction failed: {exc}")
            return None

    @classmethod
    def _pick_disk_vmdk(cls, zf: zipfile.ZipFile, vmdk_names: list) -> str:
        """Pick the largest .vmdk — the disk image, not the OVF descriptor."""
        if len(vmdk_names) == 1:
            return vmdk_names[0]
        sizes = [(zf.getinfo(n).file_size, n) for n in vmdk_names]
        sizes.sort(reverse=True)
        return sizes[0][1]

    # ── VMDK → raw conversion ─────────────────────────────────────────────────

    @classmethod
    def _convert_to_raw(
        cls,
        vmdk_path: str,
        workdir: str,
        result: VmdkExtractionResult,
    ) -> Optional[str]:
        qemu_img = shutil.which("qemu-img")
        if qemu_img is None:
            result.errors.append("qemu-img not found in PATH")
            return None
        raw_path = os.path.join(workdir, "disk.raw")
        try:
            proc = subprocess.run(
                [qemu_img, "convert", "-f", "vmdk", "-O", "raw", vmdk_path, raw_path],
                capture_output=True, timeout=600,
            )
            if proc.returncode != 0:
                result.errors.append(
                    f"qemu-img convert failed (rc={proc.returncode}): "
                    f"{proc.stderr.decode(errors='replace')[:200]}"
                )
                return None
        except subprocess.TimeoutExpired:
            result.errors.append("qemu-img convert timed out (>600s)")
            return None
        return raw_path

    # ── MBR parsing ───────────────────────────────────────────────────────────

    @classmethod
    def _parse_mbr(
        cls,
        raw_path: str,
        result: VmdkExtractionResult,
    ) -> List[PartitionInfo]:
        partitions: List[PartitionInfo] = []
        try:
            with open(raw_path, "rb") as f:
                mbr = f.read(_MBR_SIZE)
        except OSError as exc:
            result.errors.append(f"MBR read failed: {exc}")
            return partitions

        if len(mbr) < _MBR_SIZE or mbr[510:512] != _MBR_SIGNATURE:
            result.errors.append(
                f"MBR signature invalid: {mbr[510:512].hex() if len(mbr) >= 512 else 'too short'}"
            )
            return partitions

        for i in range(_MBR_PART_COUNT):
            off = _MBR_PART_OFFSET + i * _MBR_PART_ENTRY_SIZE
            entry = mbr[off:off + _MBR_PART_ENTRY_SIZE]
            if len(entry) < _MBR_PART_ENTRY_SIZE:
                break
            ptype = entry[_PART_TYPE]
            lba_start = struct.unpack_from("<I", entry, _PART_LBA_START)[0]
            lba_size = struct.unpack_from("<I", entry, _PART_LBA_SIZE)[0]
            if lba_start == 0 and lba_size == 0:
                continue
            partitions.append(PartitionInfo(
                index=i,
                type_code=ptype,
                lba_start=lba_start,
                lba_size=lba_size,
                byte_offset=lba_start * _SECTOR_SIZE,
                byte_size=lba_size * _SECTOR_SIZE,
            ))
        return partitions

    @classmethod
    def _find_p2(
        cls,
        partitions: List[PartitionInfo],
        result: VmdkExtractionResult,
    ) -> Optional[PartitionInfo]:
        """
        Return the P2 candidate — the second non-boot partition with a Linux
        ext type code. FortiMail consistently puts datafs.tar.gz on P2.
        Falls back to the second largest partition if type codes are non-standard.
        """
        ext_parts = [p for p in partitions if p.type_code in _EXT_TYPES]
        if len(ext_parts) >= 2:
            # P2 is the second ext partition (P1 = boot/rootfs, P2 = data)
            return ext_parts[1]
        if len(ext_parts) == 1:
            return ext_parts[0]
        # Fallback: second partition by index
        if len(partitions) >= 2:
            result.errors.append(
                "No Linux ext partition type found; trying partition index 1 as P2 fallback"
            )
            return partitions[1]
        result.errors.append(f"Cannot identify P2: only {len(partitions)} partition(s) found")
        return None

    # ── debugfs extraction ────────────────────────────────────────────────────

    @classmethod
    def _dump_datafs(
        cls,
        raw_path: str,
        p2_byte_offset: int,
        workdir: str,
        result: VmdkExtractionResult,
    ) -> Optional[str]:
        """
        Dump /datafs.tar.gz from the P2 ext4 filesystem using debugfs.

        Strategy: extract the P2 partition to a separate file via dd (so the
        partition boundary is at offset 0), then run debugfs on the extracted
        partition image.  The debugfs -o offset= flag was removed in 1.47.x;
        using dd + plain debugfs works on all installed versions.
        """
        debugfs = shutil.which("debugfs")
        if debugfs is None:
            result.errors.append(
                "debugfs not found in PATH (install e2fsprogs)"
            )
            return None

        # Step 1: extract P2 partition with dd
        p2_img = os.path.join(workdir, "p2.img")
        lba_start = p2_byte_offset // _SECTOR_SIZE
        try:
            proc = subprocess.run(
                ["dd", f"if={raw_path}", f"of={p2_img}",
                 f"bs={_SECTOR_SIZE}", f"skip={lba_start}", "status=none"],
                capture_output=True, timeout=300,
            )
            if proc.returncode != 0 or not os.path.isfile(p2_img):
                result.errors.append(
                    f"dd P2 extraction failed (rc={proc.returncode}): "
                    f"{proc.stderr.decode(errors='replace')[:200]}"
                )
                return None
        except subprocess.TimeoutExpired:
            result.errors.append("dd P2 extraction timed out (>300s)")
            return None

        # Step 2: dump datafs.tar.gz from the extracted P2 image
        out_path = os.path.join(workdir, "datafs.tar.gz")
        return cls._debugfs_dump(debugfs, p2_img, out_path, workdir, result)

    @classmethod
    def _debugfs_dump(
        cls,
        debugfs: str,
        p2_img: str,
        out_path: str,
        workdir: str,
        result: VmdkExtractionResult,
    ) -> Optional[str]:
        """Run debugfs dump on the already-extracted P2 image."""
        try:
            proc = subprocess.run(
                [debugfs, p2_img, "-R", f"dump /datafs.tar.gz {out_path}"],
                capture_output=True, timeout=120,
            )
            if os.path.isfile(out_path) and os.path.getsize(out_path) >= 512:
                return out_path
            result.errors.append(
                f"debugfs dump /datafs.tar.gz produced no output "
                f"(rc={proc.returncode}, stderr={proc.stderr.decode(errors='replace')[:200]})"
            )
        except subprocess.TimeoutExpired:
            result.errors.append("debugfs timed out (>120s)")
            return None

        # Try alternate names used by some FortiMail builds
        candidates = ["datafs.tar", "datafs.tgz"]
        for name in candidates:
            candidate_out = os.path.join(workdir, f"datafs_alt_{name}")
            subprocess.run(
                [debugfs, p2_img, "-R", f"dump /{name} {candidate_out}"],
                capture_output=True, timeout=120,
            )
            if os.path.isfile(candidate_out) and os.path.getsize(candidate_out) >= 512:
                result.errors.append(f"Note: datafs found at /{name} (not /datafs.tar.gz)")
                return candidate_out

        result.errors.append("datafs not found under any known path on P2")
        return None

    # ── Key extraction ────────────────────────────────────────────────────────

    @classmethod
    def _extract_keys(
        cls,
        datafs_path: str,
        workdir: str,
        result: VmdkExtractionResult,
    ) -> List[ExtractedKey]:
        keys: List[ExtractedKey] = []
        try:
            tf = tarfile.open(datafs_path, "r:gz")
        except Exception as exc:
            result.errors.append(f"tarfile open failed on datafs: {exc}")
            return keys

        with tf:
            present = {m.name for m in tf.getmembers()}
            for name in _KEY_FILES:
                if name not in present:
                    continue
                try:
                    extracted = cls._dump_tarfile_member(tf, name, workdir)
                    if extracted is None:
                        continue
                    # Is this a key (.key) or cert (.crt)?
                    if name.endswith(".key"):
                        key_info = cls._analyze_key_file(name, extracted)
                        # Match cert
                        cert_name = name.replace(".key", ".crt")
                        cert_extracted = None
                        if cert_name in present:
                            cert_extracted = cls._dump_tarfile_member(tf, cert_name, workdir)
                        if cert_extracted:
                            cls._attach_cert_info(key_info, cert_name, cert_extracted)
                        keys.append(key_info)
                except Exception as exc:
                    result.errors.append(f"key extraction failed for {name}: {exc}")
        return keys

    @classmethod
    def _dump_tarfile_member(
        cls,
        tf: tarfile.TarFile,
        name: str,
        workdir: str,
    ) -> Optional[str]:
        member = tf.getmember(name)
        out_path = os.path.join(workdir, name.replace("/", "_"))
        with tf.extractfile(member) as src:
            data = src.read()
        with open(out_path, "wb") as dst:
            dst.write(data)
        return out_path

    @classmethod
    def _analyze_key_file(cls, name: str, path: str) -> ExtractedKey:
        data = open(path, "rb").read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        bit_size, rsa_valid = cls._check_rsa_key(path)
        return ExtractedKey(
            name=name, path=path,
            md5=md5, sha256=sha256,
            bit_size=bit_size, rsa_valid=rsa_valid,
        )

    @classmethod
    def _check_rsa_key(cls, path: str) -> tuple[int, bool]:
        """Run openssl rsa -check -text; return (bit_size, is_valid)."""
        openssl = shutil.which("openssl")
        if openssl is None:
            return 0, False
        proc = subprocess.run(
            [openssl, "rsa", "-check", "-text", "-noout", "-in", path],
            capture_output=True, timeout=10,
        )
        valid = b"RSA key ok" in proc.stdout + proc.stderr
        # Extract bit count from "Private-Key: (N bit)" line
        bit_size = 0
        for line in (proc.stdout + proc.stderr).splitlines():
            if b"Private-Key:" in line or b"bit" in line.lower():
                import re
                m = re.search(rb"(\d+) bit", line)
                if m:
                    bit_size = int(m.group(1))
                    break
        return bit_size, valid

    @classmethod
    def _attach_cert_info(
        cls,
        key: ExtractedKey,
        cert_name: str,
        cert_path: str,
    ) -> None:
        data = open(cert_path, "rb").read()
        key.cert_path = cert_path
        key.cert_md5 = hashlib.md5(data).hexdigest()
        openssl = shutil.which("openssl")
        if openssl is None:
            return
        proc = subprocess.run(
            [openssl, "x509", "-text", "-noout", "-in", cert_path],
            capture_output=True, timeout=10,
        )
        out = (proc.stdout + proc.stderr).decode(errors="replace")
        import re
        m = re.search(r"Subject:\s*(.+)", out)
        if m:
            key.cert_subject = m.group(1).strip()
        m = re.search(r"Not Before\s*:\s*(.+)", out)
        if m:
            key.cert_not_before = m.group(1).strip()
