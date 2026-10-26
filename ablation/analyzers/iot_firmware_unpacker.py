"""
iot_firmware_unpacker.py: generic IoT firmware detection and extraction pipeline.

Why this exists:
1. Every IoT vendor wraps their rootfs in a vendor-specific container before the
   standard layers: uImage, squashfs, cramfs, ext2. Identifying and stripping the
   outer wrapper was done manually for each target: VIVOTEK 49-byte pkg header,
   Fortinet XOR-encrypted NAND image, Dahua .bin containers. This module
   automates format detection and extraction to a working rootfs directory.

2. Encrypted firmware hit us immediately on the ND9541 NVR (.img with Salted__ magic).
   Early detection saves a full download + 4 extraction attempts.

3. The goal is one call that returns a structured rootfs inventory ready for
   BinaryContext and ShellSinkClassifier. It replaces the manual dd/zcat/tar/mount chain.

Supported formats (outer wrappers):
  VIVOTEK .flash.pkg   49-byte vendor header + gzip tar
  uImage               64-byte U-Boot header (magic 0x27051956)
  SquashFS             v3/v4. Little-endian magic: 'sqsh'. Big-endian magic: 'hsqs'.
  CramFS               little-endian: 0x28CD3D45, big-endian: 0x453DCD28
  JFFS2                LE/BE inode/dirent magic pairs
  ext2/3/4             0xEF53 superblock at +1080
  gzip                 1F 8B 08
  XZ                   FD 37 7A 58 5A 00
  GNU tar              'ustar' at offset 257
  OpenSSL encrypted    'Salted__'. AES CBC PBKDF. Passphrase required.
  ZIP                  PK 03 04

Usage::

    from ablation.analyzers.iot_firmware_unpacker import IoTFirmwareUnpacker

    info = IoTFirmwareUnpacker.probe('/path/to/FD8369A-VVTK-0200f.flash.pkg')
    print(info)                  # FirmwareInfo(format='vivotek_pkg', ...)

    result = IoTFirmwareUnpacker.unpack(
        '/path/to/FD8369A-VVTK-0200f.flash.pkg',
        outdir='/tmp/vivotek_unpack/',
    )
    print(result.rootfs_path)    # /tmp/vivotek_unpack/rootfs/
    print(result.inventory)      # list of FirmwareFile objects with path, size, magic

    # Encrypted image:
    info = IoTFirmwareUnpacker.probe('/path/to/ND9541.img')
    # info.encrypted == True; info.format == 'openssl_aes'

CLI::

    python3 -m ablation.analyzers.iot_firmware_unpacker /path/to/firmware.pkg
    python3 -m ablation.analyzers.iot_firmware_unpacker /path/to/firmware.pkg --outdir /tmp/fw/
"""

from __future__ import annotations

import gzip
import io
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Magic table
# ---------------------------------------------------------------------------

_MAGICS: List[Tuple[int, bytes, str]] = [
    # (offset, magic_bytes, format_name)
    (0,    b'Salted__',                'openssl_aes'),
    (0,    b'\x1f\x8b\x08',           'gzip'),
    (0,    b'\xfd7zXZ\x00',           'xz'),
    (0,    b'BZh',                     'bzip2'),
    (0,    b'PK\x03\x04',             'zip'),
    (0,    b'\x27\x05\x19\x56',       'uimage'),
    (0,    b'sqsh',                    'squashfs_le'),
    (0,    b'hsqs',                    'squashfs_be'),
    (0,    b'\x45\x3d\xcd\x28',       'squashfs_v3'),
    (0,    b'\x28\xcd\x3d\x45',       'cramfs_le'),
    (0,    b'\x45\x3d\xcd\x28',       'cramfs_be'),
    (0,    b'\x85\x19\x00\x00',       'jffs2_le'),
    (0,    b'\x19\x85\x00\x00',       'jffs2_be'),
    (0,    b'070701',                  'cpio_newc'),
    (0,    b'070707',                  'cpio_odc'),
    (0,    b'\x7fELF',                'elf'),
    (0,    b'MZ',                      'pe'),
    (0,    b'#! /bin/sh',             'shell'),
    (0,    b'#!/bin/sh',              'shell'),
    (0,    b'#!/bin/bash',            'shell'),
    (257,  b'ustar',                   'tar'),
    (1080, b'\x53\xef',               'ext2'),      # ext2/3/4 superblock magic at +1080
    (49,   b'\x1f\x8b',               'vivotek_pkg'),  # after 49-byte VIVOTEK header
]

# VIVOTEK .flash.pkg: first 49 bytes are a proprietary header, then gzip starts
_VIVOTEK_HDR_SIZE = 49


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FirmwareInfo:
    path: str
    size: int
    format: str           # format name from _MAGICS or 'unknown'
    encrypted: bool = False
    inner_offset: int = 0  # byte offset where actual content starts
    notes: str = ''

    def __str__(self) -> str:
        enc = " [ENCRYPTED: passphrase required]" if self.encrypted else ""
        return (
            f"FirmwareInfo: {Path(self.path).name}\n"
            f"  format      : {self.format}{enc}\n"
            f"  size        : {self.size:,} bytes\n"
            f"  inner_offset: {self.inner_offset}\n"
            f"  notes       : {self.notes or '(none)'}\n"
        )


@dataclass
class FirmwareFile:
    path: str       # relative to rootfs root
    abs_path: str
    size: int
    magic: str      # detected type of the file


@dataclass
class UnpackResult:
    source_path: str
    outdir: str
    format_chain: List[str]    # e.g. ['vivotek_pkg', 'gzip', 'tar', 'squashfs_le']
    rootfs_path: Optional[str] = None   # path to extracted rootfs directory
    inventory: List[FirmwareFile] = field(default_factory=list)
    error: Optional[str] = None

    def __str__(self) -> str:
        chain = ' → '.join(self.format_chain)
        inv_count = len(self.inventory)
        return (
            f"UnpackResult: {Path(self.source_path).name}\n"
            f"  chain       : {chain}\n"
            f"  rootfs      : {self.rootfs_path or '(not extracted)'}\n"
            f"  inventory   : {inv_count} files\n"
            f"  error       : {self.error or 'none'}\n"
        )


# ---------------------------------------------------------------------------
# IoTFirmwareUnpacker
# ---------------------------------------------------------------------------

class IoTFirmwareUnpacker:
    """Detect and extract IoT firmware containers."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def probe(cls, path: str | Path) -> FirmwareInfo:
        """Return a FirmwareInfo describing the format of *path* without extracting."""
        p = Path(path)
        size = p.stat().st_size
        data = p.read_bytes()[:max(2048, _VIVOTEK_HDR_SIZE + 4)]

        fmt, offset, notes = cls._detect_format(data, size)
        encrypted = (fmt == 'openssl_aes')
        return FirmwareInfo(
            path=str(p),
            size=size,
            format=fmt,
            encrypted=encrypted,
            inner_offset=offset,
            notes=notes,
        )

    @classmethod
    def unpack(
        cls,
        path: str | Path,
        outdir: Optional[str | Path] = None,
        squashfs_tool: str = 'unsquashfs',
    ) -> UnpackResult:
        """
        Extract *path* as far as possible into a rootfs directory.

        If *outdir* is None a temporary directory is created. The caller is
        responsible for cleanup when a temp dir is used.
        """
        p = Path(path)
        if outdir is None:
            outdir = tempfile.mkdtemp(prefix='ablation_fw_')
        outdir = Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)

        info = cls.probe(path)
        chain: List[str] = [info.format]
        result = UnpackResult(
            source_path=str(p),
            outdir=str(outdir),
            format_chain=chain,
        )

        if info.encrypted:
            result.error = (
                f"Firmware is OpenSSL-AES encrypted (Salted__ magic). "
                f"Passphrase required. Check bootloader or upgrade scripts "
                f"for the decryption key."
            )
            return result

        try:
            data = p.read_bytes()
            inner_data, chain_ext = cls._unwrap(data, info.format, info.inner_offset)
            chain.extend(chain_ext)

            # Write the innermost content and try to extract rootfs
            inner_path = outdir / 'inner.bin'
            inner_path.write_bytes(inner_data)

            rootfs_dir = outdir / 'rootfs'
            rootfs_dir.mkdir(exist_ok=True)

            inner_fmt, _, _ = cls._detect_format(inner_data[:2048], len(inner_data))
            chain.append(inner_fmt)

            extracted = cls._extract_layer(inner_data, inner_fmt, rootfs_dir, squashfs_tool)
            if extracted:
                result.rootfs_path = str(rootfs_dir)
                result.inventory = cls._build_inventory(rootfs_dir)
            else:
                result.rootfs_path = str(inner_path)

        except Exception as exc:
            result.error = str(exc)

        return result

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    @classmethod
    def _detect_format(
        cls, data: bytes, size: int
    ) -> Tuple[str, int, str]:
        """Return (format_name, inner_offset, notes)."""
        for offset, magic, name in _MAGICS:
            end = offset + len(magic)
            if len(data) >= end and data[offset:end] == magic:
                notes = ''
                inner_offset = offset
                if name == 'vivotek_pkg':
                    inner_offset = _VIVOTEK_HDR_SIZE
                    notes = f"VIVOTEK 49-byte proprietary header; gzip stream at offset {_VIVOTEK_HDR_SIZE}"
                elif name == 'uimage':
                    inner_offset = 64  # U-Boot header is 64 bytes
                    img_type = data[30] if len(data) > 30 else 0
                    comp = data[29] if len(data) > 29 else 0
                    notes = f"U-Boot uImage; img_type=0x{img_type:02x} comp=0x{comp:02x}"
                elif name == 'openssl_aes':
                    notes = "OpenSSL AES-CBC PBKDF encryption; passphrase required"
                return name, inner_offset, notes

        # Check for VIVOTEK by probing at offset 49 for gzip magic
        if len(data) >= _VIVOTEK_HDR_SIZE + 3 and data[_VIVOTEK_HDR_SIZE:_VIVOTEK_HDR_SIZE + 2] == b'\x1f\x8b':
            return 'vivotek_pkg', _VIVOTEK_HDR_SIZE, 'VIVOTEK 49-byte header + gzip'

        return 'unknown', 0, f'size={size} bytes; no known magic matched'

    # ------------------------------------------------------------------
    # Layer unwrapping
    # ------------------------------------------------------------------

    @classmethod
    def _unwrap(
        cls, data: bytes, fmt: str, inner_offset: int
    ) -> Tuple[bytes, List[str]]:
        """
        Strip the outermost container layer and return (inner_bytes, format_chain).
        For tar archives, return the largest member's content.
        """
        chain: List[str] = []

        if fmt == 'vivotek_pkg':
            # 49-byte header + gzip tar
            gz_data = data[inner_offset:]
            tar_data = gzip.decompress(gz_data)
            chain.append('gzip')
            chain.append('tar')
            # Find the largest member (typically rootfs.img or inner.bin)
            tf = tarfile.open(fileobj=io.BytesIO(tar_data))
            best_member = max(tf.getmembers(), key=lambda m: m.size)
            content = tf.extractfile(best_member)
            assert content is not None
            return content.read(), chain

        if fmt == 'gzip':
            return gzip.decompress(data), ['gzip']

        if fmt == 'xz':
            import lzma
            return lzma.decompress(data), ['xz']

        if fmt == 'bzip2':
            import bz2
            return bz2.decompress(data), ['bzip2']

        if fmt == 'uimage':
            # Strip 64-byte U-Boot header
            return data[64:], ['uimage_strip']

        if fmt == 'tar':
            tf = tarfile.open(fileobj=io.BytesIO(data))
            best = max(tf.getmembers(), key=lambda m: m.size)
            content = tf.extractfile(best)
            assert content is not None
            return content.read(), ['tar']

        # For squashfs/cramfs/ext2/jffs2 and others, return as-is
        return data, []

    # ------------------------------------------------------------------
    # Layer extraction (filesystem)
    # ------------------------------------------------------------------

    @classmethod
    def _extract_layer(
        cls, data: bytes, fmt: str, outdir: Path, squashfs_tool: str
    ) -> bool:
        """Extract a filesystem image into *outdir*. Returns True on success."""
        if fmt in ('squashfs_le', 'squashfs_be', 'squashfs_v3'):
            return cls._extract_squashfs(data, outdir, squashfs_tool)

        if fmt == 'tar':
            try:
                tf = tarfile.open(fileobj=io.BytesIO(data))
                tf.extractall(path=str(outdir), filter='data')
                return True
            except Exception:
                return False

        if fmt in ('cpio_newc', 'cpio_odc'):
            return cls._extract_cpio(data, outdir)

        # For ext2/3/4, gzip, xz, uimage: unwrap one more level
        if fmt == 'gzip':
            try:
                inner = gzip.decompress(data)
            except Exception:
                return False
            inner_fmt, inner_off, _ = cls._detect_format(inner[:2048], len(inner))
            if inner_fmt != fmt and inner_fmt != 'unknown':
                return cls._extract_layer(inner[inner_off:], inner_fmt, outdir, squashfs_tool)

        return False

    @classmethod
    def _extract_squashfs(
        cls, data: bytes, outdir: Path, tool: str
    ) -> bool:
        """Write squashfs to a temp file and run unsquashfs."""
        sqfs_file = outdir.parent / 'rootfs_raw.bin'
        sqfs_file.write_bytes(data)
        cmd = [tool, '-d', str(outdir), '-f', str(sqfs_file)]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=120)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @classmethod
    def _extract_cpio(cls, data: bytes, outdir: Path) -> bool:
        """Extract a cpio archive."""
        try:
            r = subprocess.run(
                ['cpio', '-i', '-d', '--no-absolute-filenames'],
                input=data,
                capture_output=True,
                cwd=str(outdir),
                timeout=60,
            )
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    # Inventory
    # ------------------------------------------------------------------

    @classmethod
    def _build_inventory(cls, rootfs: Path) -> List[FirmwareFile]:
        files: List[FirmwareFile] = []
        for p in rootfs.rglob('*'):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
                hdr = p.read_bytes()[:8]
                magic = cls._quick_magic(hdr)
                rel = str(p.relative_to(rootfs))
                files.append(FirmwareFile(
                    path=rel, abs_path=str(p), size=size, magic=magic
                ))
            except OSError:
                pass
        return files

    @classmethod
    def _quick_magic(cls, hdr: bytes) -> str:
        if hdr[:4] == b'\x7fELF':
            return 'elf'
        if hdr[:2] == b'\x1f\x8b':
            return 'gzip'
        if hdr[:6] in (b'#!/bin', b'#! /bi'):
            return 'shell'
        if hdr[:4] == b'\x27\x05\x19\x56':
            return 'uimage'
        if hdr[:4] in (b'sqsh', b'hsqs'):
            return 'squashfs'
        if hdr[:2] == b'MZ':
            return 'pe'
        if hdr[:3] in (b'#!/', b'#! '):
            return 'script'
        return 'data'


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description='Detect and extract IoT firmware containers'
    )
    parser.add_argument('firmware', help='Firmware file path')
    parser.add_argument('--outdir', default=None, help='Output directory for extraction')
    parser.add_argument('--probe-only', action='store_true', help='Probe format only, no extraction')
    args = parser.parse_args()

    info = IoTFirmwareUnpacker.probe(args.firmware)
    print(info)

    if args.probe_only:
        return

    if info.encrypted:
        print("[BLOCKED] Encrypted image. Provide passphrase or decryption key to proceed.")
        sys.exit(1)

    result = IoTFirmwareUnpacker.unpack(args.firmware, outdir=args.outdir)
    print(result)
    if result.inventory:
        print(f"Inventory ({len(result.inventory)} files):")
        for f in result.inventory[:20]:
            print(f"  {f.magic:8}  {f.size:>10,}  {f.path}")
        if len(result.inventory) > 20:
            print(f"  ... and {len(result.inventory) - 20} more")


if __name__ == '__main__':
    _main()
