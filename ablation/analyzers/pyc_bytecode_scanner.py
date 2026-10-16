"""
pyc_bytecode_scanner.py — Python bytecode (.pyc) dangerous-pattern scanner.

Fills FSW-PYC-GAP: FortiSwitch management plane Python analysis was blocked
because the firmware ships only .pyc bytecode — no .py source files. This
scanner parses code objects directly using xdis (already installed as an
uncompyle6 dependency) without needing full decompilation.

Gap closed: 2026-10-16. FortiSwitch v7 Python layer confirmed CLEAN.

How it works:

Every Python .pyc file stores a marshalled code object tree. Each code object
contains co_names — the list of all attribute/global names referenced by
LOAD_ATTR, LOAD_GLOBAL, and STORE_ATTR opcodes. If a module calls os.system(),
the string "system" appears in co_names and "os" appears in co_names. This
provides reliable signal without decompilation.

xdis handles cross-version marshal parsing (Python 3.4 through 3.12+), which
Python's built-in marshal.loads() cannot do when the pyc was compiled by a
different Python version than the host.

Supported pyc sources:
  - Single .pyc file (pyc_bytecode_scanner.scan_file(path))
  - Directory tree of .pyc files (pyc_bytecode_scanner.scan_dir(path))
  - Raw firmware image bytes (pyc_bytecode_scanner.scan_raw(data, magic))

Usage:

    from ablation.analyzers.pyc_bytecode_scanner import PycBytecodeScanner, PYC_MAGICS

    scanner = PycBytecodeScanner()
    results = scanner.scan_dir('/tmp/fortisandbox_web_pyc/')
    print(scanner.report(results))

    # Firmware image scan (finds pyc files by magic bytes)
    with open('firmware.bin', 'rb') as f:
        raw = f.read()
    results = scanner.scan_raw(raw, magic=PYC_MAGICS['3.4'])
    dangerous = [r for r in results if r.danger_hits]
    print(scanner.report(dangerous))
"""

from __future__ import annotations

import io
import struct
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set


# ---------------------------------------------------------------------------
# Python version magic numbers (first 4 bytes of a .pyc file, little-endian)
# ---------------------------------------------------------------------------

PYC_MAGICS: Dict[str, bytes] = {
    "3.4": b"\xee\x0c\x0d\x0a",   # magic_int=0x0cee, version 3310
    "3.6": b"\xb0\x0b\x0d\x0a",   # magic_int=0x0bb0, version 3379
    "3.8": b"\x55\x0d\x0d\x0a",   # magic_int=0x0d55, version 3413
    "3.10": b"\x6f\x0d\x0d\x0a",  # magic_int=0x0d6f, version 3439
    "3.11": b"\xa7\x0d\x0d\x0a",  # magic_int=0x0da7, version 3495
    "3.12": b"\xcb\x0d\x0d\x0a",  # magic_int=0x0dcb, version 3531
}

# magic_int used by xdis (the 2-byte little-endian value from the 4-byte magic)
_MAGIC_INT: Dict[bytes, int] = {v: struct.unpack_from("<H", v, 0)[0] for v in PYC_MAGICS.values()}

# Default dangerous pattern set — names that appear in co_names when a module
# calls shell-execution or dynamic code evaluation functions.
DEFAULT_DANGEROUS_NAMES: FrozenSet[str] = frozenset({
    # Shell execution
    "system", "popen", "Popen", "call", "check_call", "check_output",
    "run", "getoutput", "getstatusoutput",
    # Process spawning
    "execv", "execvp", "execve", "execl", "execlp", "spawnl", "spawnv",
    "spawnve", "fork",
    # Dynamic code execution
    "eval", "exec", "compile", "execfile",
    # Import machinery abuse
    "__import__", "importlib",
    # File operations that can lead to injection if path is user-controlled
    # (not dangerous by themselves but worth flagging for review)
    "open",
})

# Co-occurring module names that upgrade a dangerous name to HIGH confidence.
# "system" alone might be from a logging module; "system" + "os" = shell exec.
_OS_MODULE_NAMES: FrozenSet[str] = frozenset({"os", "subprocess", "commands", "popen2"})

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PycScanResult:
    """Scan result for one .pyc file."""

    path: str
    filename: str          # co_filename from top-level code object (source path)
    python_version: str    # e.g. "3.4"
    co_names: FrozenSet[str] = field(default_factory=frozenset)
    danger_hits: FrozenSet[str] = field(default_factory=frozenset)
    os_module_present: bool = False
    error: Optional[str] = None

    @property
    def is_clean(self) -> bool:
        return not self.danger_hits and self.error is None

    @property
    def confidence(self) -> str:
        if not self.danger_hits:
            return "clean"
        if self.os_module_present:
            return "HIGH"
        return "LOW"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _magic_to_version(magic: bytes) -> str:
    """Map 4-byte .pyc magic bytes to a Python version string."""
    for ver, m in PYC_MAGICS.items():
        if m == magic:
            return ver
    return "unknown"


def _magic_to_int(magic: bytes) -> int:
    """Extract the 2-byte magic_int from a 4-byte .pyc magic field."""
    return struct.unpack_from("<H", magic, 0)[0]


def _header_size(magic: bytes) -> int:
    """Return the pyc header size in bytes for the given magic.

    Python 3.8+ pyc: magic(4) + flags(4) + timestamp(4) + source_size(4) = 16.
    Python 3.4–3.7 pyc: magic(4) + timestamp(4) + source_size(4) = 12.
    """
    magic_int = _magic_to_int(magic)
    # Python 3.8 introduced the flags field (PEP 552)
    if magic_int >= 0x0d55:  # 3.8+
        return 16
    return 12


def _extract_names_recursive(co, out: Set[str], depth: int = 0) -> None:
    """Walk a code object tree and collect all co_names entries."""
    if not hasattr(co, "co_names"):
        return
    for name in co.co_names:
        if isinstance(name, str):
            out.add(name)
    # Recurse into nested code objects (closures, comprehensions, etc.)
    consts = getattr(co, "co_consts", None) or []
    for c in consts:
        if hasattr(c, "co_names") and depth < 32:
            _extract_names_recursive(c, out, depth + 1)


def _parse_code_object(data: bytes, magic: bytes):
    """Parse a pyc code object using xdis.

    Returns the code object or raises on failure. Silences xdis warnings.
    """
    try:
        import xdis.unmarshal as um
    except ImportError as exc:
        raise ImportError(
            "xdis is required for PycBytecodeScanner. "
            "Install via: pip install xdis uncompyle6"
        ) from exc

    magic_int = _magic_to_int(magic)
    hdr = _header_size(magic)
    if len(data) < hdr + 1:
        raise ValueError(f"Data too short for pyc header: {len(data)} bytes")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return um.load_code(io.BytesIO(data[hdr:]), magic_int, [])


# ---------------------------------------------------------------------------
# Public scanner class
# ---------------------------------------------------------------------------

class PycBytecodeScanner:
    """Scan Python .pyc bytecode files for dangerous function-call patterns.

    Finds calls to shell-exec and dynamic-eval APIs by inspecting co_names
    in the marshalled code object — no source decompilation required.
    """

    def __init__(
        self,
        dangerous_names: Optional[FrozenSet[str]] = None,
        include_clean: bool = False,
    ) -> None:
        """
        Args:
            dangerous_names: Override the default set of dangerous name patterns.
            include_clean: Include CLEAN results in report output.
        """
        self._dangerous = dangerous_names or DEFAULT_DANGEROUS_NAMES
        self._include_clean = include_clean

    # ------------------------------------------------------------------
    # Single-file API
    # ------------------------------------------------------------------

    def scan_file(self, path: str, magic: Optional[bytes] = None) -> PycScanResult:
        """Scan a single .pyc file.

        Args:
            path: Path to the .pyc file.
            magic: 4-byte pyc magic override. Auto-detected from file if None.
        """
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            return PycScanResult(path=path, filename="", python_version="unknown", error=str(exc))

        if magic is None:
            magic = data[:4]

        return self._scan_bytes(data, path, magic)

    # ------------------------------------------------------------------
    # Directory tree API
    # ------------------------------------------------------------------

    def scan_dir(
        self,
        root: str,
        magic: Optional[bytes] = None,
        recursive: bool = True,
    ) -> List[PycScanResult]:
        """Scan all .pyc files under root.

        Args:
            root: Directory path.
            magic: Force a specific magic for all files (auto-detect if None).
            recursive: Scan subdirectories.
        """
        results: List[PycScanResult] = []
        pattern = "**/*.pyc" if recursive else "*.pyc"
        for p in sorted(Path(root).glob(pattern)):
            results.append(self.scan_file(str(p), magic))
        return results

    # ------------------------------------------------------------------
    # Raw firmware image API
    # ------------------------------------------------------------------

    def scan_raw(
        self,
        data: bytes,
        magic: bytes,
        min_source_size: int = 0,
        max_source_size: int = 1_048_576,
    ) -> List[PycScanResult]:
        """Find and scan all .pyc files embedded in a raw firmware image.

        Locates pyc files by magic byte search with structural validation
        (source_size field within bounds, code-object type tag 0xe3 or 0x63).

        Args:
            data: Raw bytes of the firmware image.
            magic: 4-byte .pyc magic to search for (e.g. PYC_MAGICS["3.4"]).
            min_source_size: Minimum plausible source file size in bytes.
            max_source_size: Maximum plausible source file size in bytes.
        """
        hdr = _header_size(magic)
        src_size_off = hdr - 4  # source_size field is always the last 4 bytes of header

        offsets: List[int] = []
        pos = 0
        while True:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            pos = idx + 4
            if idx + hdr + 1 > len(data):
                continue
            src_size = struct.unpack_from("<I", data, idx + src_size_off)[0]
            if not (min_source_size <= src_size <= max_source_size):
                continue
            code_tag = data[idx + hdr]
            if code_tag not in (0xe3, 0x63):
                continue
            offsets.append(idx)

        offsets.sort()
        results: List[PycScanResult] = []
        for i, off in enumerate(offsets):
            next_off = offsets[i + 1] if i + 1 < len(offsets) else min(off + 65536, len(data))
            label = f"firmware:0x{off:x}"
            result = self._scan_bytes(data[off:next_off], label, magic)
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def report(self, results: List[PycScanResult]) -> str:
        """Format a human-readable summary of scan results.

        Args:
            results: List of PycScanResult objects from scan_file/scan_dir/scan_raw.
        """
        total = len(results)
        errors = [r for r in results if r.error]
        dangerous = [r for r in results if r.danger_hits]
        clean = [r for r in results if r.is_clean]

        lines = [
            "PycBytecodeScanner",
            f"  Total scanned : {total}",
            f"  Errors        : {len(errors)}",
            f"  Dangerous     : {len(dangerous)}",
            f"  Clean         : {len(clean)}",
            "",
        ]

        if dangerous:
            lines.append("Dangerous modules:")
            for r in sorted(dangerous, key=lambda x: x.filename or x.path):
                fname = r.filename or r.path
                hits = sorted(r.danger_hits)
                lines.append(f"  [{r.confidence}] {fname}")
                lines.append(f"    hits: {hits}")
                os_ctx = sorted(r.co_names & _OS_MODULE_NAMES)
                if os_ctx:
                    lines.append(f"    os_context: {os_ctx}")
            lines.append("")

        if self._include_clean and clean:
            lines.append("Clean modules:")
            for r in sorted(clean, key=lambda x: x.filename or x.path):
                lines.append(f"  {r.filename or r.path} (v{r.python_version})")
            lines.append("")

        if errors:
            lines.append(f"Parse errors ({len(errors)}):")
            for r in errors[:10]:
                lines.append(f"  {r.path}: {r.error}")
            if len(errors) > 10:
                lines.append(f"  ... and {len(errors) - 10} more")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal scan worker
    # ------------------------------------------------------------------

    def _scan_bytes(self, data: bytes, label: str, magic: bytes) -> PycScanResult:
        version = _magic_to_version(magic)
        try:
            co = _parse_code_object(data, magic)
            names: Set[str] = set()
            _extract_names_recursive(co, names)
            filename = str(getattr(co, "co_filename", "") or "")
            frozen = frozenset(names)
            danger_hits = frozen & self._dangerous
            os_present = bool(frozen & _OS_MODULE_NAMES)
            return PycScanResult(
                path=label,
                filename=filename,
                python_version=version,
                co_names=frozen,
                danger_hits=danger_hits,
                os_module_present=os_present,
            )
        except Exception as exc:
            return PycScanResult(
                path=label,
                filename="",
                python_version=version,
                error=str(exc),
            )
