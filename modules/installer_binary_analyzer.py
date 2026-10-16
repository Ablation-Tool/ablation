"""
InstallerBinaryAnalyzer — extract and enumerate binaries from self-extracting installers.

Supported formats:
  BitRock/Bitnami InstallBuilder  (bitrock-lzma-4.0): LZMA-compressed payload
  NSIS (Nullsoft)                 (.nsis, 7z-block)
  Inno Setup                      (ISArc)

BitRock LZMA-4.0 format (confirmed on TI CC3xxx RadioTool v1.0.3.19, v1.2; RTI SDK v2.00.01.15):
  1. PE sections end at max_raw (computed from section table).
  2. Overlay at max_raw:
       [4-byte LE record_size]  e.g. 0x0e = 14
       [record_size - 4 bytes]  section name: '.eh_frame\0' (10 bytes)
       [1 byte]                 compression type: 0xFF = LZMA
       [LZMA_ALONE stream]      starts at overlay[record_size + 1]
  3. Payload is followed by 'bitrock-lzma-4.0' marker + PKCS7 digital signature.
  4. Decompressed payload: BitRock file catalog containing embedded PE/DLL/source files.
  5. PE files are locatable by carving MZ+valid PE header from the decompressed data.

UPX note: RTI SDK wraps the BitRock PE stub with UPX. Detect by section names
          UPX0/UPX1 and call `upx -d` before processing.
"""

import lzma
import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Format detection
# ──────────────────────────────────────────────────────────────────────────────

BITROCK_MARKER  = b'bitrock-lzma-4.0'
NSIS_MAGIC      = b'\xEF\xBE\xAD\xDE'        # NSIS block magic
INNO_MAGIC      = b'Inno Setup Setup Data'
SEVENZIP_MAGIC  = b'7z\xBC\xAF\x27\x1C'


def _pe_sections(data: bytes) -> List[Tuple[int, int, str]]:
    """Return list of (raw_offset, raw_size, name) for all PE sections."""
    if data[0:2] != b'MZ':
        return []
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        return []
    num_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_sz  = struct.unpack_from('<H', data, pe_off + 0x14)[0]
    sections = []
    for i in range(num_sec):
        s = pe_off + 0x18 + opt_sz + i * 0x28
        name     = data[s:s+8].rstrip(b'\x00').decode('latin-1', errors='replace')
        raw_size = struct.unpack_from('<I', data, s + 0x10)[0]
        raw_off  = struct.unpack_from('<I', data, s + 0x14)[0]
        sections.append((raw_off, raw_size, name))
    return sections


def _pe_end(data: bytes) -> int:
    """Return byte offset of end of last PE section (start of overlay)."""
    secs = _pe_sections(data)
    if not secs:
        return len(data)
    return max(off + sz for off, sz, _ in secs)


def _is_upx(data: bytes) -> bool:
    """True if PE has UPX section names (UPX0 / UPX1)."""
    return any(name.startswith('UPX') for _, _, name in _pe_sections(data))


def _is_bitrock(data: bytes) -> bool:
    return BITROCK_MARKER in data


def _is_nsis(data: bytes) -> bool:
    return NSIS_MAGIC in data[0:0x40000]


def _is_inno(data: bytes) -> bool:
    return INNO_MAGIC in data[0:0x40000]


# ──────────────────────────────────────────────────────────────────────────────
# UPX unpacking
# ──────────────────────────────────────────────────────────────────────────────

def _upx_unpack(data: bytes) -> Optional[bytes]:
    """
    Decompress a UPX-packed executable in memory.
    Returns unpacked bytes, or None if upx is not on PATH or fails.
    """
    try:
        subprocess.run(['upx', '--version'], capture_output=True, check=True, timeout=5)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp_in:
        tmp_in.write(data)
        tmp_in_path = tmp_in.name

    tmp_out_path = tmp_in_path + '_upx_out.exe'
    try:
        import shutil
        shutil.copy2(tmp_in_path, tmp_out_path)
        result = subprocess.run(
            ['upx', '-d', '-q', tmp_out_path],
            capture_output=True, timeout=60
        )
        if result.returncode == 0:
            return open(tmp_out_path, 'rb').read()
        return None
    except Exception:
        return None
    finally:
        for p in (tmp_in_path, tmp_out_path):
            try: os.unlink(p)
            except: pass


# ──────────────────────────────────────────────────────────────────────────────
# BitRock LZMA-4.0 extraction
# ──────────────────────────────────────────────────────────────────────────────

def _parse_bitrock_overlay(data: bytes) -> Optional[bytes]:
    """
    Parse the BitRock LZMA-4.0 overlay appended after a PE and return
    the decompressed payload bytes.

    Overlay layout:
      [4-byte LE]  record_size  (e.g. 0x0e = 14)
      [bytes]      section name  (record_size - 4 bytes, null-terminated)
      [1 byte]     compression type  (0xff = LZMA)
      [LZMA_ALONE stream]
    """
    overlay_start = _pe_end(data)
    overlay = data[overlay_start : data.rfind(BITROCK_MARKER)]
    if len(overlay) < 16:
        return None

    record_size = struct.unpack_from('<I', overlay, 0)[0]
    # compression type byte is at overlay[record_size]
    comp_type   = overlay[record_size] if record_size < len(overlay) else 0
    lzma_start  = record_size + 1

    if comp_type != 0xFF:
        # Unknown compression type — try brute-force LZMA_ALONE search
        for probe in range(4, min(64, len(overlay))):
            b = overlay[probe]
            lc = b % 9; rem = b // 9; lp = rem % 5; pb = rem // 5
            if pb <= 4 and lp <= 4 and lc <= 8 and probe + 5 <= len(overlay):
                dict_size = struct.unpack_from('<I', overlay, probe + 1)[0]
                if dict_size in (1<<16, 1<<17, 1<<18, 1<<20, 1<<22, 1<<24, 1<<26):
                    try:
                        result = lzma.decompress(overlay[probe:], format=lzma.FORMAT_ALONE)
                        return result
                    except lzma.LZMAError:
                        pass
        return None

    try:
        return lzma.decompress(overlay[lzma_start:], format=lzma.FORMAT_ALONE)
    except lzma.LZMAError:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# PE carving from decompressed payload
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CarvedBinary:
    offset:   int          # byte offset in decompressed payload
    arch:     str          # 'i386', 'x64', 'ARM', 'ARM64', etc.
    size:     int          # approximate size (last section raw end)
    data:     bytes        # raw bytes of the PE
    name_hint: str = ''    # nearby string context (best-effort filename)


def _carve_pe_files(dec: bytes) -> List[CarvedBinary]:
    """Find all valid MZ PE headers in decompressed data and return carved binaries."""
    ARCH_MAP = {0x14c: 'i386', 0x8664: 'x64', 0x1c0: 'ARM',
                0xaa64: 'ARM64', 0x1f0: 'PPC32'}
    results = []
    off = 0
    while True:
        off = dec.find(b'MZ', off)
        if off < 0:
            break
        try:
            e_lfanew = struct.unpack_from('<I', dec, off + 0x3c)[0]
            if e_lfanew >= len(dec) - off - 4:
                off += 2; continue
            if dec[off + e_lfanew : off + e_lfanew + 4] != b'PE\x00\x00':
                off += 2; continue

            machine  = struct.unpack_from('<H', dec, off + e_lfanew + 4)[0]
            num_sec  = struct.unpack_from('<H', dec, off + e_lfanew + 6)[0]
            opt_sz   = struct.unpack_from('<H', dec, off + e_lfanew + 0x14)[0]
            if num_sec > 96:
                off += 2; continue

            max_raw = 0
            valid = True
            for i in range(num_sec):
                s = off + e_lfanew + 0x18 + opt_sz + i * 0x28
                if s + 0x28 > len(dec):
                    valid = False; break
                raw_off  = struct.unpack_from('<I', dec, s + 0x14)[0]
                raw_size = struct.unpack_from('<I', dec, s + 0x10)[0]
                max_raw  = max(max_raw, raw_off + raw_size)
            if not valid or max_raw == 0:
                off += 2; continue

            arch = ARCH_MAP.get(machine, f'0x{machine:x}')
            pe_end = off + max_raw

            # Try to find a filename hint from nearby preceding bytes
            name_hint = ''
            look_back = dec[max(0, off - 200):off]
            for sep in (b'\x00', b'\n', b'\r'):
                idx = look_back.rfind(sep)
                if idx >= 0:
                    candidate = look_back[idx+1:].decode('latin-1', errors='replace').strip()
                    if 4 <= len(candidate) <= 80 and '.' in candidate:
                        name_hint = candidate[-60:]
                    break

            pe_bytes = dec[off:pe_end] if pe_end <= len(dec) else dec[off:]
            results.append(CarvedBinary(
                offset    = off,
                arch      = arch,
                size      = max_raw,
                data      = pe_bytes,
                name_hint = name_hint,
            ))
        except (struct.error, IndexError):
            pass
        off += 2

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class InstallerAnalysisResult:
    path:            str
    installer_type:  str                           # 'bitrock-lzma-4.0', 'nsis', 'inno', 'unknown'
    upx_unpacked:    bool
    payload_size:    int                           # decompressed payload bytes
    binaries:        List[CarvedBinary] = field(default_factory=list)
    extracted_paths: Dict[str, str]     = field(default_factory=dict)  # name → temp file path
    errors:          List[str]          = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────────
# Main analyzer
# ──────────────────────────────────────────────────────────────────────────────

class InstallerBinaryAnalyzer:
    """
    Detect, decompress, and enumerate binaries from self-extracting Windows installers.

    Usage::

        result = InstallerBinaryAnalyzer.from_path('/path/to/setup.exe').analyze()
        for binary in result.binaries:
            print(f"{binary.arch}  {binary.size:,} bytes  hint={binary.name_hint!r}")

        # Extract to files for ablation sweep
        paths = InstallerBinaryAnalyzer.extract_to_dir(result, '/tmp/extracted/')
    """

    def __init__(self, path: str):
        self.path = path
        self._data: Optional[bytes] = None

    @classmethod
    def from_path(cls, path: str) -> 'InstallerBinaryAnalyzer':
        return cls(path)

    def _load(self) -> bytes:
        if self._data is None:
            self._data = open(self.path, 'rb').read()
        return self._data

    def analyze(self) -> InstallerAnalysisResult:
        data = self._load()
        result = InstallerAnalysisResult(
            path           = self.path,
            installer_type = 'unknown',
            upx_unpacked   = False,
            payload_size   = 0,
        )

        # UPX layer: unpack first, then re-detect
        if _is_upx(data):
            unpacked = _upx_unpack(data)
            if unpacked is not None:
                data = unpacked
                result.upx_unpacked = True
            else:
                result.errors.append('UPX detected but upx binary not found on PATH')

        if _is_bitrock(data):
            result.installer_type = 'bitrock-lzma-4.0'
            dec = _parse_bitrock_overlay(data)
            if dec is None:
                result.errors.append('BitRock overlay parse failed')
            else:
                result.payload_size = len(dec)
                result.binaries     = _carve_pe_files(dec)
                # Store decompressed payload for further analysis
                result._dec = dec  # type: ignore[attr-defined]

        elif _is_nsis(data):
            result.installer_type = 'nsis'
            result.errors.append('NSIS extraction not yet implemented — use 7z e or innounp')

        elif _is_inno(data):
            result.installer_type = 'inno'
            result.errors.append('Inno Setup extraction not yet implemented — use innoextract')

        return result

    @staticmethod
    def extract_to_dir(result: InstallerAnalysisResult, out_dir: str) -> Dict[str, str]:
        """
        Write carved PE binaries to out_dir.
        Returns {filename: path} mapping.
        """
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        paths = {}
        for i, b in enumerate(result.binaries):
            if b.name_hint:
                stem = Path(b.name_hint.replace('\\', '/').replace(':', '')).name
            else:
                stem = f'binary_{i}'
            ext = '.exe' if b.size > 0x10000 else '.dll'
            if not stem.lower().endswith(('.exe', '.dll', '.sys', '.ocx')):
                stem = stem + ext
            out = os.path.join(out_dir, stem)
            # Avoid collisions
            if os.path.exists(out):
                stem_base = os.path.splitext(stem)[0]
                ext2      = os.path.splitext(stem)[1]
                out = os.path.join(out_dir, f'{stem_base}_{i}{ext2}')
            open(out, 'wb').write(b.data)
            paths[stem] = out
        result.extracted_paths = paths
        return paths

    @staticmethod
    def report(result: InstallerAnalysisResult) -> str:
        lines = [
            f"InstallerBinaryAnalyzer: {os.path.basename(result.path)}",
            f"  type:         {result.installer_type}",
            f"  upx_unpacked: {result.upx_unpacked}",
            f"  payload:      {result.payload_size:,} bytes decompressed",
            f"  pe_binaries:  {len(result.binaries)}",
        ]
        for b in result.binaries:
            lines.append(f"    [0x{b.offset:x}] arch={b.arch} size={b.size:,}"
                         + (f"  hint={b.name_hint!r}" if b.name_hint else ''))
        if result.errors:
            lines.append(f"  errors: {result.errors}")
        return '\n'.join(lines)
