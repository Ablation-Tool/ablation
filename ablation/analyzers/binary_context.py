"""
binary_context.py: Pre-computed binary context cache for LLM-assisted RE.

Eliminates per-session ELF parsing overhead. Build once (~2-5s), serialize to
~/.ablation/cache/, reload in <100ms on subsequent sessions.

Captures:
  plt         : {va: symbol_name} for all PLT stubs
  exports     : {symbol_name: va} for all globally exported functions
  strings     : {va: content} for .rodata printable sequences >= 4 chars
  func_starts : sorted list of function entry VAs (eh_frame + callee augmentation)
  call_edges  : [(from_va, to_va, label)] flat call graph

Usage:
    ctx = BinaryContext.load_or_build('/path/to/binary')

    ctx.plt[0x3000]                    # -> 'target_func'
    ctx.exports['init_handler'] # -> 0x4000
    ctx.callers_of('target_func')  # -> [(from_va, from_fn_name_or_hex), ...]
    ctx.callees_of(0x4000)             # -> [(to_va, label), ...]
    ctx.strings_near(0x4137f, radius=64)# -> [(va, content), ...]

    print(ctx.summary())                # compact session-start context block

Cache location: ~/.ablation/cache/<sha256[:16]>_<basename>.json
Invalidation: SHA256 mismatch triggers rebuild.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ablation.analyzers.name_registry import get_registry

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False

try:
    import numpy as np
    _NUMPY_OK = True
except ImportError:
    _NUMPY_OK = False

_CACHE_DIR = Path.home() / ".ablation" / "cache"
_MIN_STR_LEN = 4


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _va_to_i64(va: int) -> "np.int64":
    """Reinterpret an unsigned VA as a signed int64 without OverflowError.

    np.int64() raises OverflowError for kernel-space addresses (VA > 2^63-1).
    ctypes.c_int64 bit-casts the value the same way C's (int64_t) does.
    """
    return np.int64(ctypes.c_int64(va).value)


def _va_arr_to_i64(vas) -> "np.ndarray":
    """Create an int64 ndarray from a VA sequence without OverflowError.

    np.array([...], dtype=np.int64) also raises OverflowError on kernel-space
    addresses. Route through uint64 first, then view-cast the bits to int64.
    """
    return np.array(list(vas), dtype=np.uint64).view(np.int64)


def _cache_path(binary_sha256: str, binary_name: str) -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    slug = f"{binary_sha256[:16]}_{Path(binary_name).name}"
    return _CACHE_DIR / f"{slug}.json"


def _extract_strings_into(data: bytes, base_va: int, out: dict,
                          min_len: int = _MIN_STR_LEN) -> None:
    """Extract printable ASCII strings from data, writing {va: content} into out.

    Uses a numpy run-detection pass (O(N) with low constant) when available;
    falls back to a byte-by-byte Python loop otherwise.
    """
    if not data:
        return
    if _NUMPY_OK:
        buf     = np.frombuffer(data, dtype=np.uint8)
        printable = (buf >= 0x20) & (buf < 0x7F)
        padded  = np.empty(len(buf) + 2, dtype=bool)
        padded[0] = padded[-1] = False
        padded[1:-1] = printable
        starts = np.where(~padded[:-1] &  padded[1:])[0]
        ends   = np.where( padded[:-1] & ~padded[1:])[0]
        mask   = (ends - starts) >= min_len
        for s, e in zip(starts[mask].tolist(), ends[mask].tolist()):
            out[base_va + s] = data[s:e].decode("ascii", errors="replace")
    else:
        i    = 0
        dlen = len(data)
        while i < dlen:
            start = i
            while i < dlen and 0x20 <= data[i] < 0x7F:
                i += 1
            if i - start >= min_len:
                out[base_va + start] = data[start:i].decode("ascii", errors="replace")
            else:
                i = start + 1


def _detect_arch(binary) -> str:
    try:
        m = str(binary.header.machine_type)
        if 'X86_64' in m or 'AMD64' in m:
            return 'x86_64'
        if 'AARCH64' in m or 'ARM64' in m:
            return 'arm64'
        if 'RISCV' in m or 'RISC_V' in m:
            cls = str(binary.header.identity_class)
            return 'riscv64' if '64' in cls else 'riscv32'
        if 'ARM' in m:
            return 'arm32'
        if 'MIPS' in m:
            cls = str(binary.header.identity_class)
            return 'mips64' if '64' in cls else 'mips32'
        if 'LOONGARCH' in m or 'LARCH' in m:
            return 'loongarch64'
        if 'PPC' in m or 'POWERPC' in m:
            cls = str(binary.header.identity_class)
            return 'ppc64' if '64' in cls else 'ppc32'
        # EM_386 (i386/x86 32-bit): lief reports '386' or 'I386'
        if '386' in m or 'I386' in m:
            return 'x86_32'
    except Exception:
        pass
    return 'x86_64'


def _detect_arch_pe(binary) -> str:
    """Detect arch from PE MACHINE_TYPES header field."""
    try:
        m = binary.header.machine
        if m == lief.PE.MACHINE_TYPES.AMD64:
            return 'x86_64'
        if m == lief.PE.MACHINE_TYPES.I386:
            return 'x86_32'
        if m == lief.PE.MACHINE_TYPES.ARM64:
            return 'arm64'
        if m == lief.PE.MACHINE_TYPES.ARMNT:
            return 'arm32'
    except Exception:
        pass
    return 'x86_64'


class BinaryContext:
    """
    Pre-computed binary context. One object = complete working context for a
    stripped binary: symbols, strings, function starts, call graph.
    Supports ELF (x86_64, x86_32, arm64, arm32, loongarch64, mips32, mips64, ppc32, ppc64, riscv32, riscv64)
    and Windows PE / .sys (x86_64, x86_32).
    """

    def __init__(self):
        self.path: str = ""
        self.sha256: str = ""
        self.base_va: int = 0
        self.arch: str = "x86_64"
        self.plt: Dict[int, str] = {}
        self.exports: Dict[str, int] = {}
        self.strings: Dict[int, str] = {}
        self.func_starts: List[int] = []
        self.thumb_funcs: Set[int] = set()
        self.call_edges: List[Tuple[int, int, str]] = []
        self._callers_idx: Dict[str, List[Tuple[int, str]]] = {}
        self._callees_idx: Dict[int, List[Tuple[int, str]]] = {}
        self._str_xref_idx: Dict[int, List[int]] = {}
        self._func_str_idx: Dict[int, List[int]] = {}

    # ── public factory ────────────────────────────────────────────────────────

    @classmethod
    def load_or_build(cls, path: str, force_rebuild: bool = False) -> "BinaryContext":
        """
        Load from cache if valid, otherwise build from scratch and cache.

        Args:
            path         : path to ELF binary
            force_rebuild: ignore cache and rebuild
        """
        data = Path(path).read_bytes()

        # Detect non-ELF formats early so callers aren't silently misled by an
        # empty context.  Known magic bytes that are NOT ELF:
        _NON_ELF = {
            b'FOR1': 'Erlang BEAM bytecode',
            b'PK\x03\x04': 'ZIP/JAR/APK archive',
            b'\xca\xfe\xba\xbe': 'Mach-O fat binary',
            b'\xce\xfa\xed\xfe': 'Mach-O 32-bit',
            b'\xcf\xfa\xed\xfe': 'Mach-O 64-bit',
        }
        for magic, label in _NON_ELF.items():
            if data[:len(magic)] == magic:
                import warnings
                warnings.warn(
                    f"BinaryContext: {Path(path).name!r} appears to be {label}, "
                    f"not an ELF binary -- context will be empty. "
                    f"Use the appropriate format-specific analyzer instead.",
                    stacklevel=2,
                )
                break

        sha = _sha256(data)
        cache_file = _cache_path(sha, path)

        if not force_rebuild and cache_file.exists():
            try:
                ctx = cls._load_json(cache_file, path)
                if ctx.sha256 == sha:
                    return ctx
            except Exception:
                pass

        ctx = cls._build(data, path, sha)
        try:
            ctx._save_json(cache_file)
        except Exception:
            pass
        return ctx

    @classmethod
    def load_from_cache_file(cls, cache_file: str, orig_path: str = "") -> "BinaryContext":
        """
        Load directly from a cache JSON file without requiring the original binary.

        Use when the binary is unavailable (e.g., /tmp cleared) but the cache is intact.
        The SHA256 integrity check is skipped: caller guarantees the binary hasn't changed.
        """
        return cls._load_json(Path(cache_file), orig_path)

    @classmethod
    def build(cls, path: str) -> "BinaryContext":
        """Build without cache (always rebuilds)."""
        data = Path(path).read_bytes()
        sha = _sha256(data)
        return cls._build(data, path, sha)

    # ── query API ─────────────────────────────────────────────────────────────

    def callers_of(self, symbol_or_va) -> List[Tuple[int, str]]:
        """
        Return [(caller_va, caller_name_or_hex), ...] for all callers of a
        symbol name (string) or VA (int).

        If symbol: looks up by PLT name.
        If int: looks up by target VA directly.
        Caller names use the overlay when available.
        """
        if isinstance(symbol_or_va, str):
            raw = self._callers_idx.get(symbol_or_va, [])
        else:
            va = symbol_or_va
            sym = self.plt.get(va) or f"0x{va:x}"
            raw = self._callers_idx.get(sym, [])
        return [(cva, self.name(cva)) for cva, _ in raw]

    def callees_of(self, func_va: int) -> List[Tuple[int, str]]:
        """Return [(target_va, label), ...] for all calls from func_va.

        Labels use overlay names when available (hex fallback replaced by
        discovered name if one has been registered).
        """
        raw = self._callees_idx.get(func_va, [])
        return [(tva, self.name(tva)) for tva, _ in raw]

    def strings_near(self, va: int, radius: int = 128) -> List[Tuple[int, str]]:
        """Return (string_va, content) pairs within radius bytes of va."""
        lo, hi = va - radius, va + radius
        return [(sva, s) for sva, s in self.strings.items() if lo <= sva <= hi]

    def string_xrefs(self, string_va: int) -> List[int]:
        """Return code VAs (instruction-level) that RIP-relatively reference string_va.

        Uses the numpy displacement scan built during _build(). Empty if the index was
        not populated (old cache format): call build_xref_index(path) to populate.
        """
        return list(self._str_xref_idx.get(string_va, []))

    def funcs_referencing_string(self, string_va: int) -> List[int]:
        """Return function start VAs that contain a RIP-relative reference to string_va."""
        code_vas = self._str_xref_idx.get(string_va, [])
        funcs: Set[int] = set()
        for cva in code_vas:
            fva = self.func_containing(cva)
            if fva is not None:
                funcs.add(fva)
        return sorted(funcs)

    def strings_in_func(self, func_va: int) -> List[Tuple[int, str]]:
        """Return (string_va, content) for all strings RIP-relatively referenced by func_va."""
        svas = self._func_str_idx.get(func_va, [])
        return [(sva, self.strings[sva]) for sva in svas if sva in self.strings]

    def build_xref_index(self, binary_path: str) -> int:
        """Populate RIP-relative xref index from binary on disk.

        Call this after loading from an older cache that predates xref indexing.
        Returns number of (string_va, code_va) pairs indexed.
        """
        if self._str_xref_idx:
            return sum(len(v) for v in self._str_xref_idx.values())
        if not _LIEF_OK or not _NUMPY_OK:
            return 0
        data = Path(binary_path).read_bytes()
        try:
            binary = lief.parse(data)
        except Exception:
            return 0
        self._build_string_xref_index(data, binary)
        return sum(len(v) for v in self._str_xref_idx.values())

    def func_containing(self, va: int) -> Optional[int]:
        """
        Return the function start VA that most likely contains va.
        Uses largest start <= va heuristic.
        """
        starts = self.func_starts
        lo, hi = 0, len(starts) - 1
        result = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if starts[mid] <= va:
                result = starts[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return result

    def export_va(self, name: str) -> Optional[int]:
        """Return VA for an exported function by name, or None."""
        return self.exports.get(name)

    def plt_name(self, va: int) -> Optional[str]:
        return self.plt.get(va)

    # ── discovered-name overlay ───────────────────────────────────────────────

    def name(self, va: int) -> str:
        """Best available name for va: overlay > export > PLT > hex.

        This is the single call for "what is this function?": use it everywhere
        a hex address would otherwise appear.
        """
        reg = get_registry()
        discovered = reg.get_name(self.sha256, va)
        if discovered:
            return discovered
        for sym, eva in self.exports.items():
            if eva == va:
                return sym
        plt_sym = self.plt.get(va)
        if plt_sym:
            return plt_sym
        return f"0x{va:x}"

    def set_name(self, va: int, name: str, source: str = "manual") -> None:
        """Register a discovered name for va. Persists across sessions immediately."""
        get_registry().set_name(self.sha256, va, name, source=source)

    def delete_name(self, va: int) -> bool:
        """Remove a previously set name. Returns True if it existed."""
        return get_registry().delete_name(self.sha256, va)

    def names_map(self) -> Dict[int, str]:
        """Return {va: name} for all overlay-registered names for this binary."""
        return get_registry().names_map(self.sha256)

    def names_count(self) -> int:
        """Number of discovered names registered for this binary."""
        return get_registry().count(self.sha256)

    def names_table(self, limit: int = 0) -> str:
        """Formatted table of all discovered names sorted by VA.

        limit=0 means all. Pass limit=N to cap at N rows.
        """
        entries = get_registry().all_names(self.sha256)
        if limit:
            entries = entries[:limit]
        if not entries:
            return "(no discovered names registered for this binary)"
        lines = [f"  {'VA':<14}  {'Source':<10}  Name"]
        lines.append("  " + "-" * 60)
        for va, nm, src in entries:
            lines.append(f"  0x{va:<12x}  {src:<10}  {nm}")
        return "\n".join(lines)

    # ── summary ───────────────────────────────────────────────────────────────

    def summary(self, top_n: int = 20) -> str:
        """
        Compact session-start context block.

        Shows: binary metadata, export count, PLT count, selected exports,
        and import relationships (who is called from this binary).
        """
        lines = [
            f"BinaryContext: {Path(self.path).name}",
            f"  sha256     : {self.sha256[:16]}...",
            f"  arch       : {self.arch}",
            f"  base_va    : 0x{self.base_va:x}",
            f"  func_starts: {len(self.func_starts)}",
            f"  exports    : {len(self.exports)}",
            f"  plt entries: {len(self.plt)}",
            f"  strings    : {len(self.strings)}",
            f"  call_edges : {len(self.call_edges)}",
            f"  str_xrefs  : {sum(len(v) for v in self._str_xref_idx.values())} pairs indexed",
            f"  named funcs: {self.names_count()} (overlay)",
            "",
        ]

        if self.exports:
            lines.append(f"  exports (first {min(top_n, len(self.exports))}):")
            for name, va in sorted(self.exports.items())[:top_n]:
                lines.append(f"    0x{va:x}  {name}")
            lines.append("")

        if self.plt:
            lines.append(f"  imports via PLT (first {min(top_n, len(self.plt))}):")
            for va, name in sorted(self.plt.items())[:top_n]:
                lines.append(f"    0x{va:x}  {name}")

        return "\n".join(lines)

    # ── build internals ───────────────────────────────────────────────────────

    @classmethod
    def _build(cls, data: bytes, path: str, sha: str) -> "BinaryContext":
        ctx = cls()
        ctx.path = path
        ctx.sha256 = sha

        if not _LIEF_OK:
            return ctx

        try:
            binary = lief.parse(data)
        except Exception:
            return ctx
        if isinstance(binary, lief.PE.Binary):
            return cls._build_pe(data, path, sha, binary)
        if not isinstance(binary, lief.ELF.Binary):
            return ctx

        ctx.base_va = binary.imagebase
        ctx.arch = _detect_arch(binary)

        ctx._extract_plt(binary)
        ctx._extract_exports(binary)
        ctx._extract_strings(binary)
        ctx._extract_func_starts(path, binary)
        ctx._build_call_graph(data, binary)
        ctx._build_indices()
        ctx._build_string_xref_index(data, binary)

        return ctx

    def _extract_plt(self, binary) -> None:
        # ARM32: .rel.plt (8-byte entries, no addend), stubs at PLT+20+(n*12)
        if self.arch == 'arm32':
            self._extract_plt_arm32(binary)
            return

        # Build GOT -> symbol name from .rela.plt (x86_64 / arm64)
        got_to_sym: Dict[int, str] = {}
        try:
            rela_plt = binary.get_section(".rela.plt")
            if rela_plt:
                rela_data = bytes(rela_plt.content)
                for off in range(0, len(rela_data) - 23, 24):
                    r_offset, r_info = struct.unpack_from("<QQ", rela_data, off)
                    sym_idx = r_info >> 32
                    try:
                        sym = binary.dynamic_symbols[sym_idx]
                        if sym.name:
                            got_to_sym[r_offset] = sym.name
                    except Exception:
                        pass
        except Exception:
            pass

        if not got_to_sym:
            # Fallback: LIEF imported_functions
            try:
                for sym in binary.imported_functions:
                    if hasattr(sym, 'value') and sym.value and sym.name:
                        self.plt[sym.value] = sym.name
            except Exception:
                pass
            try:
                for rel in binary.relocations:
                    if not rel.has_symbol:
                        continue
                    rtype = str(getattr(rel, 'type', ''))
                    if 'JUMP_SLOT' in rtype and rel.symbol.name:
                        self.plt[rel.address] = rel.symbol.name
            except Exception:
                pass
            return

        import capstone
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        _ENDBR64 = bytes([0xf3, 0x0f, 0x1e, 0xfa])

        for sec_name in (".plt.sec", ".plt", ".plt.got"):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_data = bytes(sec.content)
            sec_va = sec.virtual_address
            entry_size = 16

            for off in range(0, len(sec_data), entry_size):
                stub_va = sec_va + off
                chunk = sec_data[off:off + entry_size]
                if len(chunk) < 6:
                    break
                start = 4 if chunk[:4] == _ENDBR64 else 0
                if len(chunk) < start + 6:
                    continue
                if chunk[start:start + 2] == b'\xff\x25':
                    disp = struct.unpack_from("<i", chunk, start + 2)[0]
                    got_va = stub_va + start + 6 + disp
                    if got_va in got_to_sym:
                        self.plt[stub_va] = got_to_sym[got_va]

    def _extract_plt_arm32(self, binary) -> None:
        # Parse .rel.plt (8-byte entries: r_offset:u32 + r_info:u32)
        sym_names: List[str] = []
        try:
            rel_plt = binary.get_section(".rel.plt")
            if rel_plt:
                rel_data = bytes(rel_plt.content)
                for off in range(0, len(rel_data) - 7, 8):
                    r_offset, r_info = struct.unpack_from("<II", rel_data, off)
                    sym_idx = r_info >> 8
                    try:
                        sym = binary.dynamic_symbols[sym_idx]
                        sym_names.append(sym.name if sym.name else "")
                    except Exception:
                        sym_names.append("")
        except Exception:
            pass

        if sym_names:
            plt_sec = binary.get_section(".plt")
            if plt_sec:
                plt_va = int(plt_sec.virtual_address)
                # PLT[0] is 20-byte resolver; each stub is 12 bytes
                for i, name in enumerate(sym_names):
                    if name:
                        stub_va = plt_va + 20 + i * 12
                        self.plt[stub_va] = name
                return

        # Fallback: JUMP_SLOT relocations give GOT addresses; use as plt entries
        try:
            for rel in binary.relocations:
                if not rel.has_symbol:
                    continue
                rtype = str(getattr(rel, 'type', ''))
                if 'JUMP_SLOT' in rtype and rel.symbol.name:
                    self.plt[rel.address] = rel.symbol.name
        except Exception:
            pass

    def _extract_exports(self, binary) -> None:
        try:
            for sym in binary.exported_functions:
                if sym.name and sym.value:
                    va = sym.value
                    if self.arch == 'arm32' and (va & 1):
                        va &= ~1
                    self.exports[sym.name] = va
        except Exception:
            pass
        if not self.exports:
            try:
                for sym in binary.dynamic_symbols:
                    if (sym.name and sym.value and
                            str(getattr(sym, 'binding', '')).endswith('GLOBAL') and
                            str(getattr(sym, 'type', '')).endswith('FUNC')):
                        va = sym.value
                        if self.arch == 'arm32' and (va & 1):
                            va &= ~1
                        self.exports[sym.name] = va
            except Exception:
                pass

    def _extract_strings(self, binary) -> None:
        for sec_name in (".rodata", ".data.rel.ro"):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            _extract_strings_into(bytes(sec.content), sec.virtual_address, self.strings)
        # Fallback: scan readable LOAD segments when section names are unavailable
        # (e.g. PS3 SELF→ELF where shstrtab is zeroed by scetool).
        if not self.strings and _LIEF_OK:
            try:
                for seg in binary.segments:
                    seg_type  = str(getattr(seg, 'type', ''))
                    seg_flags = str(getattr(seg, 'flags', ''))
                    if 'LOAD' not in seg_type:
                        continue
                    # On PPC64 Cell, rodata is combined with code in the X|R segment.
                    # Always scan all readable LOAD segments (including X|R) for strings.
                    if 'R' not in seg_flags:
                        continue
                    _extract_strings_into(
                        bytes(seg.content), int(seg.virtual_address), self.strings
                    )
            except Exception:
                pass

    def _extract_func_starts(self, path: str, binary) -> None:
        starts: Set[int] = set()
        thumb: Set[int] = set()
        if path:
            try:
                from elftools.elf.elffile import ELFFile
                from elftools.dwarf.callframe import FDE
                with open(path, "rb") as fh:
                    elf = ELFFile(fh)
                    if elf.has_dwarf_info():
                        di = elf.get_dwarf_info()
                        if di.has_EH_CFI():
                            for e in di.EH_CFI_entries():
                                if isinstance(e, FDE) and e["initial_location"] > 0:
                                    # pyelftools can return Python ints > 2^64 for PPC64
                                    # ELF V1 eh_frame pcrel entries; mask to 64 bits.
                                    va = int(e["initial_location"]) & 0xFFFFFFFFFFFFFFFF
                                    if self.arch == 'arm32' and (va & 1):
                                        va &= ~1
                                        thumb.add(va)
                                    starts.add(va)
            except Exception:
                pass
        # Augment from exports (already LSB-stripped)
        for va in self.exports.values():
            if va:
                starts.add(va)
        # ARM32: also scan dynamic_symbols for FUNC type to catch non-exported funcs
        if self.arch == 'arm32' and _LIEF_OK:
            try:
                for sym in binary.dynamic_symbols:
                    if sym.name and sym.value and str(getattr(sym, 'type', '')).endswith('FUNC'):
                        va = sym.value
                        if va & 1:
                            va &= ~1
                            thumb.add(va)
                        starts.add(va)
            except Exception:
                pass
        # PPC64: scan code segment for MFLR r0 (7C 08 02 A6, big-endian) function prologues.
        # Every non-leaf Cell PPU function opens with MFLR r0 to save the link register.
        # This is the single reliable prologue discriminator for stripped PPC64 Cell binaries.
        if self.arch in ('ppc64', 'ppc32') and not starts and path:
            try:
                import struct
                MFLR_R0 = b'\x7c\x08\x02\xa6'  # big-endian
                with open(path, 'rb') as fh:
                    raw = fh.read()
                # Find the executable LOAD segment via ELF program headers
                # ELF64 big-endian: e_phoff at 0x20 (NOT 0x28 which is e_shoff!)
                # e_phentsize at 0x36, e_phnum at 0x38
                e_phoff = struct.unpack_from('>Q', raw, 0x20)[0]
                e_phentsize = struct.unpack_from('>H', raw, 0x36)[0]
                e_phnum = struct.unpack_from('>H', raw, 0x38)[0]
                for i in range(e_phnum):
                    ph_off = e_phoff + i * e_phentsize
                    p_type = struct.unpack_from('>I', raw, ph_off)[0]
                    p_flags = struct.unpack_from('>I', raw, ph_off + 0x04)[0]
                    p_offset = struct.unpack_from('>Q', raw, ph_off + 0x08)[0]
                    p_vaddr = struct.unpack_from('>Q', raw, ph_off + 0x10)[0]
                    p_filesz = struct.unpack_from('>Q', raw, ph_off + 0x20)[0]
                    PT_LOAD = 1
                    PF_X = 0x1  # execute flag
                    if p_type == PT_LOAD and (p_flags & PF_X) and p_filesz > 0:
                        seg = raw[p_offset: p_offset + p_filesz]
                        pos = 0
                        while True:
                            idx = seg.find(MFLR_R0, pos)
                            if idx < 0:
                                break
                            # Must be 4-byte aligned
                            if idx % 4 == 0:
                                starts.add(p_vaddr + idx)
                            pos = idx + 4
            except Exception:
                pass
        # x86_32: scan for i386 function prologues (push ebp; mov ebp, esp)
        # when eh_frame and exports both produce zero starts (static stripped binaries).
        if self.arch == 'x86_32' and not starts and path:
            try:
                from ablation.analyzers.static_elf32_func_start_scanner import StaticELF32FuncStartScanner
                scanner = StaticELF32FuncStartScanner.from_path(path)
                for va in scanner.scan():
                    starts.add(va)
            except Exception:
                pass
        self.func_starts = sorted(starts)
        self.thumb_funcs = thumb

    def _build_call_graph(self, data: bytes, binary) -> None:
        """Build call graph via vectorized opcode scan (arch-aware).

        x86_64: scan .text for 0xe8 (CALL rel32); target = site+5+disp32.
        arm32:  scan .text for BL words (byte[3]==0xEB); target = site+8+imm24*4.
        Falls back to sequential capstone if NumPy is unavailable.
        """
        if self.arch == 'arm32':
            if _NUMPY_OK:
                self._build_call_graph_arm32(data, binary)
            else:
                self._build_call_graph_sequential(data, binary)
            return

        if not _NUMPY_OK:
            self._build_call_graph_sequential(data, binary)
            return

        text_sec = binary.get_section(".text")
        if not text_sec:
            return

        sec_data = bytes(text_sec.content)
        sec_va = int(text_sec.virtual_address)
        N = len(sec_data)
        if N < 5:
            return

        buf = np.frombuffer(sec_data, dtype=np.uint8)

        # All positions where 0xe8 appears with at least 4 bytes following
        cand_pos = np.where(buf[:-4] == 0xe8)[0]
        if len(cand_pos) == 0:
            self.call_edges = []
            return

        # Extract 4-byte LE displacements at cand_pos + [1,2,3,4]
        idx = cand_pos[:, None] + np.array([1, 2, 3, 4], dtype=np.intp)
        disp_bytes = buf[idx]                                              # (M, 4)
        disp_u32 = (disp_bytes[:, 0].astype(np.uint32)
                    | (disp_bytes[:, 1].astype(np.uint32) << 8)
                    | (disp_bytes[:, 2].astype(np.uint32) << 16)
                    | (disp_bytes[:, 3].astype(np.uint32) << 24))
        disp_i32 = disp_u32.view(np.int32)

        # target_va[i] = sec_va + cand_pos[i] + 5 + disp32[i]
        site_vas    = _va_to_i64(sec_va) + cand_pos.astype(np.int64)
        target_vas  = site_vas + np.int64(5) + disp_i32.astype(np.int64)

        # Filter: target must be a known PLT stub or function entry
        plt_arr  = _va_arr_to_i64(sorted(self.plt.keys())) if self.plt         else np.empty(0, np.int64)
        func_arr = _va_arr_to_i64(self.func_starts)         if self.func_starts else np.empty(0, np.int64)

        valid = np.zeros(len(target_vas), dtype=bool)
        if len(plt_arr):
            hi = np.searchsorted(plt_arr, target_vas)
            hi = np.minimum(hi, len(plt_arr) - 1)
            valid |= plt_arr[hi] == target_vas
        if len(func_arr):
            hi = np.searchsorted(func_arr, target_vas)
            hi = np.minimum(hi, len(func_arr) - 1)
            valid |= func_arr[hi] == target_vas

        site_vas   = site_vas[valid]
        target_vas = target_vas[valid]

        # Owning-function: largest func_start <= site_va (one searchsorted call)
        if len(func_arr) and len(site_vas):
            owner_idx = np.searchsorted(func_arr, site_vas, side='right') - 1
            owner_idx = np.maximum(owner_idx, 0)
            owner_vas = func_arr[owner_idx]
        else:
            owner_vas = site_vas

        # Label targets with PLT name or export name
        va_to_export: Dict[int, str] = {va: nm for nm, va in self.exports.items()}

        edges: List[Tuple[int, int, str]] = []
        for owner_va, target_va in zip(owner_vas.tolist(), target_vas.tolist()):
            label = self.plt.get(target_va, "") or va_to_export.get(target_va, "")
            edges.append((int(owner_va), int(target_va), label))

        self.call_edges = edges

    def _build_call_graph_arm32(self, data: bytes, binary) -> None:
        """ARM32 call graph via numpy BL scan.

        BL (condition=AL) encoding: byte[3] of 4-byte LE word == 0xEB.
        Target: insn_va + 8 + sign_extend(word[23:0], 24) * 4
        (ARM pipeline: PC = insn_addr + 8 during execution.)
        """
        text_sec = binary.get_section(".text")
        if not text_sec:
            return
        sec_data = bytes(text_sec.content)
        sec_va = int(text_sec.virtual_address)
        N = len(sec_data)
        if N < 4:
            return

        buf = np.frombuffer(sec_data, dtype=np.uint8)
        word_count = N // 4
        # MSByte of each 4-byte-aligned word (byte index 3, 7, 11, ...)
        msb = buf[3: word_count * 4: 4]
        # BL (cond=AL) = 0xEB; BLX label = 0xFA
        bl_word_idx = np.where((msb == 0xEB) | (msb == 0xFA))[0]
        if len(bl_word_idx) == 0:
            self.call_edges = []
            return

        byte_off = bl_word_idx * 4
        # Reconstruct 32-bit LE words
        b0 = buf[byte_off    ].astype(np.uint32)
        b1 = buf[byte_off + 1].astype(np.uint32)
        b2 = buf[byte_off + 2].astype(np.uint32)
        words = b0 | (b1 << 8) | (b2 << 16) | (msb[bl_word_idx].astype(np.uint32) << 24)

        imm24 = words & np.uint32(0xFFFFFF)
        # Sign-extend 24-bit to 32-bit signed
        sign_bit = np.uint32(0x800000)
        fill = np.uint32(0xFF000000)
        imm_i32 = np.where(imm24 & sign_bit, (imm24 | fill).view(np.int32), imm24.astype(np.int32))

        insn_vas = _va_to_i64(sec_va) + byte_off.astype(np.int64)
        target_vas = insn_vas + np.int64(8) + imm_i32.astype(np.int64) * 4

        plt_arr  = _va_arr_to_i64(sorted(self.plt.keys())) if self.plt         else np.empty(0, np.int64)
        func_arr = _va_arr_to_i64(self.func_starts)         if self.func_starts else np.empty(0, np.int64)

        valid = np.zeros(len(target_vas), dtype=bool)
        if len(plt_arr):
            hi = np.searchsorted(plt_arr, target_vas)
            hi = np.minimum(hi, len(plt_arr) - 1)
            valid |= plt_arr[hi] == target_vas
        if len(func_arr):
            hi = np.searchsorted(func_arr, target_vas)
            hi = np.minimum(hi, len(func_arr) - 1)
            valid |= func_arr[hi] == target_vas

        insn_vas   = insn_vas[valid]
        target_vas = target_vas[valid]

        if len(func_arr) and len(insn_vas):
            owner_idx = np.searchsorted(func_arr, insn_vas, side='right') - 1
            owner_idx = np.maximum(owner_idx, 0)
            owner_vas = func_arr[owner_idx]
        else:
            owner_vas = insn_vas

        va_to_export: Dict[int, str] = {va: nm for nm, va in self.exports.items()}
        edges: List[Tuple[int, int, str]] = []
        for owner_va, target_va in zip(owner_vas.tolist(), target_vas.tolist()):
            label = self.plt.get(target_va, "") or va_to_export.get(target_va, "")
            edges.append((int(owner_va), int(target_va), label))

        # Second pass: capstone scan for Thumb BL/BLX in Thumb functions
        if self.thumb_funcs:
            import capstone
            sorted_starts = self.func_starts
            for i, fva in enumerate(sorted_starts):
                if fva not in self.thumb_funcs:
                    continue
                end_va = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else sec_va + N
                func_size = min(end_va - fva, 4096)
                if func_size <= 0:
                    continue
                off = fva - sec_va
                if off < 0 or off + func_size > N:
                    continue
                chunk = sec_data[off: off + func_size]
                cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
                cs.detail = False
                cs.skipdata = True
                for insn in cs.disasm(chunk, fva):
                    mn = insn.mnemonic.lower()
                    if mn not in ('bl', 'blx'):
                        continue
                    try:
                        target = int(insn.op_str.strip().lstrip('#'), 16)
                        label = self.plt.get(target, "") or va_to_export.get(target, "")
                        edges.append((fva, target, label))
                    except ValueError:
                        pass

        self.call_edges = edges

    def _build_call_graph_sequential(self, data: bytes, binary) -> None:
        """Sequential capstone fallback for _build_call_graph (NumPy unavailable)."""
        import capstone

        text_sec = binary.get_section(".text")
        if not text_sec:
            return

        sec_data = bytes(text_sec.content)
        sec_va   = text_sec.virtual_address

        if self.arch == 'arm32':
            cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            call_mnems = {'bl', 'blx'}
        else:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            call_mnems = {'call'}
        cs.detail = False

        edges: List[Tuple[int, int, str]] = []
        va_to_export: Dict[int, str] = {va: nm for nm, va in self.exports.items()}

        for insn in cs.disasm(sec_data, sec_va):
            if insn.mnemonic.lower().split('.')[0] not in call_mnems:
                continue
            try:
                target = int(insn.op_str.strip().lstrip('#'), 16)
            except ValueError:
                continue
            label = self.plt.get(target, "") or va_to_export.get(target, "")
            owner = self.func_containing(insn.address) or insn.address
            edges.append((owner, target, label))

        self.call_edges = edges

    def _build_string_xref_index(self, data: bytes, binary) -> None:
        """Build string xref index.

        x86_64/arm64: vectorized RIP/PC-relative displacement scan.
        x86_32 (i386): vectorized absolute 4-byte LE immediate scan.
        arm32: capstone LDR [PC, #off] literal pool scan per function.
        """
        if self.arch == 'arm32':
            self._build_string_xref_index_arm32(data, binary)
            return
        if self.arch == 'x86_32':
            self._build_string_xref_index_x86_32()
            return
        if not _NUMPY_OK:
            return

        text_sec = binary.get_section(".text")
        if not text_sec and self.arch in ('ppc64', 'ppc32'):
            self._build_string_xref_index_ppc64(data, binary)
            return
        if not text_sec:
            return

        text_data = bytes(text_sec.content)
        text_va = int(text_sec.virtual_address)
        N = len(text_data)
        if N < 4 or not self.strings:
            return

        str_va_arr = _va_arr_to_i64(sorted(self.strings.keys()))

        # Build 4-byte LE windows at every byte offset using stride tricks
        from numpy.lib.stride_tricks import as_strided
        buf_u8 = np.frombuffer(text_data, dtype=np.uint8)
        end = N - 3
        windows = as_strided(buf_u8, shape=(end, 4), strides=(1, 1))

        # Combine bytes into uint32 LE, then reinterpret as signed int32
        disp_u32 = (windows[:, 0].astype(np.uint32)
                    | (windows[:, 1].astype(np.uint32) << 8)
                    | (windows[:, 2].astype(np.uint32) << 16)
                    | (windows[:, 3].astype(np.uint32) << 24))
        disp_i32 = disp_u32.view(np.int32)

        # target_va[p] = text_va + p + 4 + disp32[p]
        positions = np.arange(end, dtype=np.int64)
        target_vas = _va_to_i64(text_va) + positions + np.int64(4) + disp_i32.astype(np.int64)

        # Binary-search for string VA matches
        hits = np.searchsorted(str_va_arr, target_vas)
        clipped = np.minimum(hits, len(str_va_arr) - 1)
        valid = str_va_arr[clipped] == target_vas

        hit_pos = positions[valid].tolist()
        hit_svas = target_vas[valid].tolist()

        str_xref: Dict[int, List[int]] = {}
        func_str: Dict[int, List[int]] = {}

        for pos, sva in zip(hit_pos, hit_svas):
            code_va = text_va + int(pos)
            sva = int(sva)
            fva = self.func_containing(code_va)
            if fva is None:
                continue
            str_xref.setdefault(sva, []).append(code_va)
            func_str.setdefault(fva, []).append(sva)

        # Deduplicate per-func string lists
        self._str_xref_idx = str_xref
        self._func_str_idx = {k: list(dict.fromkeys(v)) for k, v in func_str.items()}

    def _build_string_xref_index_x86_32(self) -> None:
        """i386 absolute-address string xref via I386AbsoluteXrefScanner."""
        from ablation.analyzers.i386_absolute_xref_scanner import I386AbsoluteXrefScanner
        scanner = I386AbsoluteXrefScanner(self.path, ctx=self)
        scanner.inject(self)

    def _build_string_xref_index_arm32(self, data: bytes, binary) -> None:
        """ARM32 string xref via LDR Rd, [PC, #off] literal pool scan.

        ARM mode: pool_va = insn_va + 8 + disp  (pipeline prefetch offset)
        Thumb 16-bit: pool_va = ((insn_va + 4) & ~3) + disp  (word-aligned PC+4)
        Thumb 32-bit: pool_va = insn_va + 4 + disp
        The 4-byte word at pool_va is the string pointer.
        """
        import capstone
        from capstone import arm as C_ARM

        text_sec = binary.get_section('.text')
        if not text_sec or not self.strings:
            return

        text_data = bytes(text_sec.content)
        text_va = int(text_sec.virtual_address)
        str_va_set = set(self.strings.keys())

        # Build section map for dereferencing pool words
        sec_map: List[Tuple[int, int, bytes]] = []
        for sn in ('.text', '.rodata', '.data', '.data.rel.ro'):
            try:
                sec = binary.get_section(sn)
                if sec and sec.size > 0:
                    sc = bytes(sec.content)
                    sv = int(sec.virtual_address)
                    sec_map.append((sv, sv + len(sc), sc))
            except Exception:
                pass

        def _read_word(va: int) -> Optional[int]:
            for sv, ev, sc in sec_map:
                off = va - sv
                if 0 <= off <= len(sc) - 4:
                    return struct.unpack_from('<I', sc, off)[0]
            return None

        str_xref: Dict[int, List[int]] = {}
        func_str: Dict[int, List[int]] = {}

        sorted_starts = self.func_starts or [text_va]
        for i, fva in enumerate(sorted_starts):
            end_va = sorted_starts[i + 1] if i + 1 < len(sorted_starts) else text_va + len(text_data)
            is_thumb = fva in self.thumb_funcs
            func_size = min(end_va - fva, 4096)
            if func_size <= 0:
                continue
            off = fva - text_va
            if off < 0 or off + func_size > len(text_data):
                continue
            chunk = text_data[off: off + func_size]
            mode = capstone.CS_MODE_THUMB if is_thumb else capstone.CS_MODE_ARM
            cs = capstone.Cs(capstone.CS_ARCH_ARM, mode)
            cs.detail = True
            cs.skipdata = True
            for insn in cs.disasm(chunk, fva):
                if insn.mnemonic.lower() != 'ldr':
                    continue
                try:
                    ops = insn.operands
                    if len(ops) < 2:
                        continue
                    op1 = ops[1]
                    if op1.type != C_ARM.ARM_OP_MEM:
                        continue
                    if insn.reg_name(op1.mem.base).lower() != 'pc':
                        continue
                    disp = op1.mem.disp
                    if is_thumb and insn.size == 2:
                        pool_va = ((insn.address + 4) & ~3) + disp
                    elif is_thumb:
                        pool_va = insn.address + 4 + disp
                    else:
                        pool_va = insn.address + 8 + disp
                    ptr = _read_word(pool_va)
                    if ptr is not None and ptr in str_va_set:
                        str_xref.setdefault(ptr, []).append(insn.address)
                        func_str.setdefault(fva, []).append(ptr)
                except Exception:
                    continue

        self._str_xref_idx = str_xref
        self._func_str_idx = {k: list(dict.fromkeys(v)) for k, v in func_str.items()}

    def _build_string_xref_index_ppc64(self, data: bytes, binary) -> None:
        """PPC64 Cell PS3 string xref via TOC (r2-relative) addressing.

        Cell GCC stores string pointers in the TOC (Table of Contents).
        The code accesses them via:
          Far:  ADDIS rD, r2, ha16(N)  +  LWZ rD, lo16(N)(rD)
          Near: LWZ rD, N(r2)                [|N| < 32768]
        where N = toc_entry_va - r2 and mem[r2 + N] = string_va.

        r2 is read from the first .opd function descriptor (ELF e_entry in data seg:
        bytes[0:4] = code ptr, bytes[4:8] = TOC ptr == r2 runtime value).
        """
        if not _NUMPY_OK or not self.strings or not self.func_starts:
            return
        import struct
        from collections import defaultdict

        # Parse LOAD segments: find executable (X|R) code seg and writable (W) data seg.
        try:
            e_phoff     = struct.unpack_from('>Q', data, 0x20)[0]
            e_phentsize = struct.unpack_from('>H', data, 0x36)[0]
            e_phnum     = struct.unpack_from('>H', data, 0x38)[0]
        except Exception:
            return

        code_seg = None  # (file_off, vaddr, filesz)
        data_seg = None
        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            try:
                p_type  = struct.unpack_from('>I', data, ph)[0]
                p_flags = struct.unpack_from('>I', data, ph + 0x04)[0]
                p_off   = struct.unpack_from('>Q', data, ph + 0x08)[0]
                p_vaddr = struct.unpack_from('>Q', data, ph + 0x10)[0]
                p_fsz   = struct.unpack_from('>Q', data, ph + 0x20)[0]
            except Exception:
                continue
            if p_type != 1 or p_fsz == 0:
                continue
            if (p_flags & 0x1) and p_fsz > 0x100000 and code_seg is None:
                code_seg = (int(p_off), int(p_vaddr), int(p_fsz))
            elif not (p_flags & 0x1) and (p_flags & 0x2) and p_fsz > 0x1000 and data_seg is None:
                data_seg = (int(p_off), int(p_vaddr), int(p_fsz))

        if not code_seg or not data_seg:
            return

        code_off, code_va, code_fsz = code_seg
        ds_off,   ds_va,  ds_fsz   = data_seg
        code_data = data[code_off : code_off + code_fsz]
        ds_data   = data[ds_off   : ds_off  + ds_fsz]

        # Discover r2 (TOC pointer) from .opd function descriptor.
        # PS3 Cell uses 32-bit EA mode: each descriptor = [4B code_ptr][4B toc_ptr].
        # ELF e_entry points into the data segment at the first descriptor.
        e_entry = struct.unpack_from('>Q', data, 0x18)[0]
        r2 = 0
        if ds_va <= e_entry < ds_va + ds_fsz:
            opd_foff = ds_off + (e_entry - ds_va)
            try:
                cptr     = struct.unpack_from('>I', data, opd_foff)[0]
                toc_cand = struct.unpack_from('>I', data, opd_foff + 4)[0]
                if code_va <= cptr < code_va + code_fsz and ds_va <= toc_cand < ds_va + ds_fsz:
                    r2 = toc_cand
            except Exception:
                pass

        if not r2:
            return
        self._r2 = r2  # expose for _augment_xrefs_ppc64_arrays

        # Scan data segment for 4-byte values that are known string VAs.
        # Build two lookup tables keyed by TOC offset components:
        #   ha16_map[ha16] -> [(lo16, string_va)]   for ADDIS rD, r2, ha16 + LWZ rD, lo16(rD)
        #   near_map[lo16] -> [string_va]            for direct LWZ rD, N(r2) when |N|<32768
        str_vas = set(self.strings.keys())
        ha16_map: Dict[int, list] = defaultdict(list)
        near_map: Dict[int, list] = defaultdict(list)

        for i in range(0, len(ds_data) - 3, 4):
            val = struct.unpack_from('>I', ds_data, i)[0]
            if val not in str_vas:
                continue
            toc_va     = ds_va + i
            toc_offset = toc_va - r2            # signed Python int
            lo16 = toc_offset & 0xFFFF          # 16-bit displacement for LWZ
            ha16 = ((toc_offset + 0x8000) >> 16) & 0xFFFF  # high-adjusted for ADDIS
            ha16_map[ha16].append((lo16, val))
            if -32768 <= toc_offset <= 32767:
                near_map[lo16].append(val)

        if not ha16_map and not near_map:
            return

        buf = np.frombuffer(code_data, dtype=np.uint8)
        M   = len(buf)
        str_xref: Dict[int, List[int]] = {}
        func_str: Dict[int, List[int]] = {}
        func_arr = np.array(self.func_starts, dtype=np.int64)
        SCAN_AHEAD = 128

        def _record(str_va: int, site_off: int) -> None:
            idx = int(np.searchsorted(func_arr, code_va + site_off, side='right')) - 1
            if idx >= 0:
                fva = int(func_arr[idx])
                str_xref.setdefault(str_va, []).append(fva)
                func_str.setdefault(fva, []).append(str_va)

        # PPC64 instruction encoding:
        #   ADDIS rD, rA, SIMM16:  opcode=15; byte[0]=0x3C|(rD>>3); byte[1]=(rD&7)<<5|rA
        #   LWZ   rD, SIMM16(rA):  opcode=32; byte[0]=0x80|(rD>>3); byte[1]=(rD&7)<<5|rA
        # For ADDIS rD, r2, ha16: byte[1] & 0x1F == 2
        # For LWZ   rD, lo16(rD): byte[1] low5 == rD

        aligned = np.arange(0, M - 3, 4, dtype=np.int64)
        b0_arr = buf[aligned]
        b1_arr = buf[aligned + 1]

        # --- Pass 1: ADDIS rD, r2, ha16 + LWZ rD, lo16(rD) ---
        addis_mask = (b0_arr >= 0x3C) & (b0_arr <= 0x3F) & ((b1_arr & 0x1F) == 2)
        addis_pos  = aligned[addis_mask]

        if len(addis_pos) > 0:
            addis_rd   = ((buf[addis_pos].astype(np.uint32) & 0x03) << 3) | (buf[addis_pos + 1].astype(np.uint32) >> 5)
            addis_ha16 = (buf[addis_pos + 2].astype(np.uint32) << 8) | buf[addis_pos + 3].astype(np.uint32)

            for k in range(len(addis_pos)):
                ha16    = int(addis_ha16[k])
                entries = ha16_map.get(ha16)
                if not entries:
                    continue
                rD   = int(addis_rd[k])
                apos = int(addis_pos[k])
                end  = min(apos + SCAN_AHEAD, M - 4)
                for fwd in range(apos + 4, end, 4):
                    lb0 = int(buf[fwd])
                    if lb0 < 0x80 or lb0 > 0x83:
                        continue
                    lrD  = ((lb0 & 0x03) << 3) | (int(buf[fwd + 1]) >> 5)
                    lrA  = int(buf[fwd + 1]) & 0x1F
                    if lrD != rD or lrA != rD:
                        continue
                    l_lo16 = (int(buf[fwd + 2]) << 8) | int(buf[fwd + 3])
                    for (elo16, str_va) in entries:
                        if l_lo16 == elo16:
                            _record(str_va, apos)
                            break

        # --- Pass 2: direct LWZ rD, N(r2) for near TOC entries ---
        if near_map:
            lwz_mask = (b0_arr >= 0x80) & (b0_arr <= 0x83) & ((b1_arr & 0x1F) == 2)
            lwz_pos  = aligned[lwz_mask]
            if len(lwz_pos) > 0:
                lwz_lo16 = (buf[lwz_pos + 2].astype(np.uint32) << 8) | buf[lwz_pos + 3].astype(np.uint32)
                for k in range(len(lwz_pos)):
                    lo16    = int(lwz_lo16[k])
                    entries = near_map.get(lo16)
                    if not entries:
                        continue
                    lpos = int(lwz_pos[k])
                    for str_va in entries:
                        _record(str_va, lpos)

        # Pass 3: pre-call argument register trace (BL → backward LIS+ADDI/ORI scan)
        self._augment_xrefs_ppc64_precall(code_data, code_va, str_xref, func_str, func_arr)

        # Pass 4: string-pointer array detection (dense ptr blocks in data seg)
        self._augment_xrefs_ppc64_arrays(
            ds_data, ds_va, code_data, code_va, str_xref, func_str, func_arr
        )

        # Pass 5: near-TOC 2-hop string array xref detection (arrays in data seg)
        self._augment_xrefs_ppc64_twohop(
            ds_data, ds_va, code_data, code_va, str_xref, func_str, func_arr
        )

        # Pass 6: 2-hop detection for string arrays in the code/rodata segment.
        # Covers arrays like NanoSuit display strings that live in the X|R LOAD
        # segment rather than the writable data segment.
        self._augment_xrefs_ppc64_twohop(
            ds_data, ds_va, code_data, code_va, str_xref, func_str, func_arr,
            target_data=code_data, target_va=code_va,
        )

        self._str_xref_idx = {k: list(dict.fromkeys(v)) for k, v in str_xref.items()}
        self._func_str_idx = {k: list(dict.fromkeys(v)) for k, v in func_str.items()}

    def _augment_xrefs_ppc64_precall(
        self,
        code_data: bytes,
        code_va: int,
        str_xref: Dict,
        func_str: Dict,
        func_arr,
    ) -> None:
        """Pass 3 — pre-call argument register trace.

        For each BL (call) instruction, walk backward up to 32 instructions and
        simulate register state for argument registers r3-r6.  If a LIS+ADDI or
        LIS+ORI sequence reconstructs a known string VA, record that call site's
        containing function as a string reference.

        This catches the common Cell GCC pattern where absolute string addresses
        are loaded directly into argument registers before log/error calls, bypassing
        the TOC entirely.
        """
        buf = code_data
        M   = len(buf)
        str_vas   = set(self.strings.keys())
        ARG_REGS  = {3, 4, 5, 6}
        SCAN_BACK = 128  # bytes = 32 instructions

        for i in range(0, M - 3, 4):
            b0 = buf[i]; b3 = buf[i + 3]
            # BL: opcode 18, b0 in 0x48-0x4B, LK=1 AA=0 → b3 & 3 == 1
            if b0 < 0x48 or b0 > 0x4B or (b3 & 0x3) != 0x1:
                continue

            reg_hi: Dict[int, int]   = {}  # rD -> upper 16 bits from LIS
            reg_val: Dict[int, int]  = {}  # rD -> fully reconstructed 32-bit VA

            start = max(0, i - SCAN_BACK)
            for j in range(start, i, 4):
                jb0 = buf[j]; jb1 = buf[j + 1]; jb2 = buf[j + 2]; jb3 = buf[j + 3]
                rD  = ((jb0 & 0x03) << 3) | (jb1 >> 5)
                imm = (jb2 << 8) | jb3

                if 0x3C <= jb0 <= 0x3F and (jb1 & 0x1F) == 0:
                    # LIS rD, imm16  (ADDIS rD, r0, imm16)
                    if rD in ARG_REGS:
                        reg_hi[rD]  = imm
                        reg_val.pop(rD, None)
                elif 0x38 <= jb0 <= 0x3B:
                    # ADDI rD, rA, imm16
                    rA = jb1 & 0x1F
                    if rD in ARG_REGS and rA == rD and rD in reg_hi:
                        simm = imm if imm < 0x8000 else imm - 0x10000
                        reg_val[rD] = ((reg_hi[rD] << 16) + simm) & 0xFFFFFFFF
                    elif rD in ARG_REGS and rA != rD:
                        # Different source reg → clobbers our tracked state
                        reg_hi.pop(rD, None); reg_val.pop(rD, None)
                elif 0x60 <= jb0 <= 0x63:
                    # ORI rA, rS, imm16  (rS == rD in symmetric encoding)
                    rA = jb1 & 0x1F
                    if rA in ARG_REGS and rA == rD and rA in reg_hi:
                        reg_val[rA] = (reg_hi[rA] << 16) | imm

            site_va = code_va + i
            idx = int(np.searchsorted(func_arr, site_va, side='right')) - 1
            if idx < 0:
                continue
            fva = int(func_arr[idx])
            for val in reg_val.values():
                if val in str_vas:
                    str_xref.setdefault(val, []).append(fva)
                    func_str.setdefault(fva, []).append(val)

    def _augment_xrefs_ppc64_arrays(
        self,
        ds_data: bytes,
        ds_va: int,
        code_data: bytes,
        code_va: int,
        str_xref: Dict,
        func_str: Dict,
        func_arr,
    ) -> None:
        """Pass 4 — string-pointer array detection.

        Cell GCC sometimes groups all string pointers for a class into a contiguous
        array in the data segment, then accesses the array via a single base-pointer
        load.  This pass:
          1. Finds runs of ≥5 consecutive 4-byte values in the data segment that all
             point to known string VAs ('string-pointer arrays').
          2. Batch-indexes all arrays by their TOC key (near and far).
          3. Single O(M) scan for near-TOC arrays   — LWZ rX, lo16(r2).
          4. Single O(M×16) scan for far-TOC arrays — ADDIS rD, r2, ha16 + LWZ.

        Batched approach (step 2-4) replaces O(arrays × M) with O(M × 16).
        Critical for CryEngine PS3 which has ~1900 far-TOC string-pointer arrays.
        """
        import struct as _st

        str_vas  = set(self.strings.keys())
        r2       = getattr(self, '_r2', 0)
        if not r2:
            return

        # Step 1 — detect string-pointer arrays
        n_slots = len(ds_data) // 4
        arrays: List[Tuple[int, List[int]]] = []  # [(array_base_va, [str_va, ...])]
        i = 0
        while i < n_slots - 5:
            va = _st.unpack_from('>I', ds_data, i * 4)[0]
            if va not in str_vas:
                i += 1
                continue
            j = i
            run: List[int] = []
            while j < n_slots:
                vj = _st.unpack_from('>I', ds_data, j * 4)[0]
                if vj not in str_vas:
                    break
                run.append(vj)
                j += 1
            if len(run) >= 5:
                arrays.append((ds_va + i * 4, run))
                i = j
            else:
                i += 1

        if not arrays:
            return

        buf = code_data
        M   = len(buf)
        near_lo = r2 - 0x8000
        near_hi = r2 + 0x7FFF

        # Step 2 — batch-index all arrays by TOC key
        # near: {(lo_b2, lo_b3): [str_list, ...]}  — LWZ rX, lo16(r2)
        # far:  {(ha_b2, ha_b3, lo_b2, lo_b3): merged_str_list}  — ADDIS+LWZ
        near_idx: Dict[Tuple[int, int], List[List[int]]] = {}
        far_lo_idx: Dict[Tuple[int, int, int, int], List[int]] = {}

        for arr_va, str_list in arrays:
            if near_lo <= arr_va <= near_hi:
                toc_off = arr_va - r2
                lo16    = toc_off & 0xFFFF
                key     = ((lo16 >> 8) & 0xFF, lo16 & 0xFF)
                near_idx.setdefault(key, []).append(str_list)
            else:
                toc_off = (arr_va - r2) & 0xFFFFFFFF
                if toc_off > 0x7FFFFFFF:
                    toc_off -= 0x100000000
                ha16   = ((toc_off + 0x8000) >> 16) & 0xFFFF
                lo16   = toc_off & 0xFFFF
                full_k = (
                    (ha16 >> 8) & 0xFF, ha16 & 0xFF,
                    (lo16 >> 8) & 0xFF, lo16 & 0xFF,
                )
                far_lo_idx.setdefault(full_k, []).extend(str_list)

        # Step 3 — near-TOC: single O(M) scan for all near arrays
        if near_idx:
            for k in range(0, M - 3, 4):
                kb0 = buf[k]; kb1 = buf[k + 1]; kb2 = buf[k + 2]; kb3 = buf[k + 3]
                if kb0 < 0x80 or kb0 > 0x83:
                    continue
                if (kb1 & 0x1F) != 2:
                    continue
                entries = near_idx.get((kb2, kb3))
                if not entries:
                    continue
                site_va = code_va + k
                idx     = int(np.searchsorted(func_arr, site_va, side='right')) - 1
                if idx < 0:
                    continue
                fva = int(func_arr[idx])
                for sl in entries:
                    for sv in sl:
                        str_xref.setdefault(sv, []).append(fva)
                        func_str.setdefault(fva, []).append(sv)

        # Step 4 — far-TOC: single O(M×16) batched scan for all far arrays
        if far_lo_idx:
            ha_set = {(k[0], k[1]) for k in far_lo_idx}
            for k in range(0, M - 7, 4):
                kb0 = buf[k]; kb1 = buf[k + 1]; kb2 = buf[k + 2]; kb3 = buf[k + 3]
                if kb0 < 0x3C or kb0 > 0x3F:
                    continue
                if (kb1 & 0x1F) != 2:
                    continue
                if (kb2, kb3) not in ha_set:
                    continue
                rD    = ((kb0 & 0x03) << 3) | (kb1 >> 5)
                ha_b2 = kb2; ha_b3 = kb3
                for fwd in range(k + 4, min(k + 64, M - 4), 4):
                    fb0 = buf[fwd]; fb1 = buf[fwd + 1]; fb2 = buf[fwd + 2]; fb3 = buf[fwd + 3]
                    if fb0 < 0x80 or fb0 > 0x83:
                        continue
                    if (fb1 & 0x1F) != rD:
                        continue
                    sl = far_lo_idx.get((ha_b2, ha_b3, fb2, fb3))
                    if sl:
                        site_va = code_va + k
                        idx     = int(np.searchsorted(func_arr, site_va, side='right')) - 1
                        if idx >= 0:
                            fva = int(func_arr[idx])
                            for sv in sl:
                                str_xref.setdefault(sv, []).append(fva)
                                func_str.setdefault(fva, []).append(sv)

    def _augment_xrefs_ppc64_twohop(
        self,
        ds_data: bytes,
        ds_va: int,
        code_data: bytes,
        code_va: int,
        str_xref: Dict,
        func_str: Dict,
        func_arr,
        target_data: Optional[bytes] = None,
        target_va: Optional[int] = None,
    ) -> None:
        """Pass 5/6 — near-TOC 2-hop string array xref detection.

        CryEngine PS3 stores string pointer arrays far from r2 (beyond ±32KB), so
        direct near-TOC LWZ can't reach individual string VAs.  The actual pattern is:
            LWZ rX, near_off(r2)   # load array BASE ptr from near-TOC slot
            LWZ rY, N*4(rX)        # load individual string VA from the array

        This pass:
        1. Scans the near-TOC window (r2±32KB) in ds_data for 4-byte entries whose
           target is the start of a run of ≥3 consecutive string-pointer values in
           target_data (defaults to ds_data — Pass 5; set to code_data for Pass 6
           to cover string arrays that live in the code/rodata segment).
        2. Does a single linear pass over code looking for LWZ rX, off(r2) whose
           (b2,b3) displacement bytes match any discovered array-base TOC offset.
           Each hit attributes ALL strings in the pointed-to array to the
           enclosing function.

        Covers ~12K function xrefs for CryEngine PS3 in a ~60s scan.
        """
        import struct as _st

        r2 = getattr(self, '_r2', 0)
        if not r2:
            return

        # Target segment: where the string arrays live (default: data seg).
        tgt_data = target_data if target_data is not None else ds_data
        tgt_va   = target_va   if target_va   is not None else ds_va
        tgt_end  = tgt_va + len(tgt_data)

        near_lo = r2 - 0x8000
        near_hi = r2 + 0x7FFF
        str_vas = set(self.strings.keys())

        # Step 1: scan near-TOC window (always in ds_data — TOC is in data seg)
        # for entries pointing to dense string arrays in tgt_data.
        lo_off        = max(0, near_lo - ds_va)
        hi_off        = min(len(ds_data), near_hi - ds_va + 4)
        near_toc_data = ds_data[lo_off:hi_off]
        n             = len(near_toc_data) // 4

        imm_to_strs: Dict[Tuple[int, int], List[int]] = {}
        for i in range(n):
            v = _st.unpack_from('>I', near_toc_data, i * 4)[0]
            if not (tgt_va <= v < tgt_end):
                continue
            t_off    = v - tgt_va
            str_list: List[int] = []
            for j in range(200):
                if t_off + j * 4 + 3 >= len(tgt_data):
                    break
                kv = _st.unpack_from('>I', tgt_data, t_off + j * 4)[0]
                if kv in str_vas:
                    str_list.append(kv)
                elif j > 0:
                    break
            if len(str_list) >= 3:
                toc_va  = near_lo + i * 4
                toc_off = (toc_va - r2) & 0xFFFF
                key     = (toc_off >> 8, toc_off & 0xFF)
                if key in imm_to_strs:
                    imm_to_strs[key].extend(str_list)
                else:
                    imm_to_strs[key] = list(str_list)

        if not imm_to_strs:
            return

        # Step 2: single linear pass — LWZ rX, off(r2) matching array-base TOC keys
        buf = code_data
        M   = len(buf)
        for k in range(0, M - 3, 4):
            kb0 = buf[k]; kb1 = buf[k + 1]; kb2 = buf[k + 2]; kb3 = buf[k + 3]
            if not (0x80 <= kb0 <= 0x83):
                continue
            if (kb1 & 0x1F) != 2:
                continue
            key = (kb2, kb3)
            if key not in imm_to_strs:
                continue
            site_va = code_va + k
            idx     = int(np.searchsorted(func_arr, site_va, side='right')) - 1
            if idx < 0:
                continue
            fva = int(func_arr[idx])
            for sv in imm_to_strs[key]:
                str_xref.setdefault(sv, []).append(fva)
                func_str.setdefault(fva, []).append(sv)

    # ── PE support ────────────────────────────────────────────────────────────

    @classmethod
    def _build_pe(cls, data: bytes, path: str, sha: str, binary) -> "BinaryContext":
        ctx = cls()
        ctx.path = path
        ctx.sha256 = sha
        ctx.base_va = binary.optional_header.imagebase
        ctx.arch = _detect_arch_pe(binary)
        ctx._extract_plt_pe(binary)
        ctx._extract_exports_pe(binary)
        ctx._extract_strings_pe(binary)
        ctx._extract_func_starts_pe(binary)
        ctx._build_call_graph_pe(data, binary)
        ctx._build_indices()
        ctx._build_string_xref_index_pe(data, binary)
        return ctx

    def _extract_plt_pe(self, binary) -> None:
        """IAT map: {absolute_va: import_name}."""
        base = self.base_va
        try:
            for imp in binary.imports:
                for entry in imp.entries:
                    if entry.iat_address and entry.name:
                        self.plt[base + entry.iat_address] = entry.name
        except Exception:
            pass

    def _extract_exports_pe(self, binary) -> None:
        """Export map: {name: absolute_va}."""
        base = self.base_va
        try:
            exp = binary.get_export()
            if exp is None:
                return
            for entry in exp.entries:
                if entry.name and entry.address:
                    self.exports[entry.name] = base + entry.address
        except Exception:
            pass

    def _extract_strings_pe(self, binary) -> None:
        """Printable strings from .rdata and .data PE sections."""
        base = self.base_va
        for sec_name in (".rdata", ".data"):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            _extract_strings_into(bytes(sec.content), base + sec.virtual_address, self.strings)

    def _extract_func_starts_pe(self, binary) -> None:
        """Function starts: exported VAs + prologue scan on executable sections."""
        starts: Set[int] = set()
        base = self.base_va

        for va in self.exports.values():
            if va:
                starts.add(va)

        _PROLOGUES: Dict[str, List[bytes]] = {
            'x86_64': [
                b'\x48\x83\xec',       # sub rsp, N  (MSVC x64 stack reserve)
                b'\x48\x89\x5c\x24',   # mov [rsp+N], rbx  (callee-save opener)
                b'\x40\x53',           # push rbx
                b'\x55\x48\x89\xec',   # push rbp; mov rbp, rsp  (gcc -O0)
                b'\xf3\x0f\x1e\xfa',   # endbr64
            ],
            'x86_32': [
                b'\x55\x8b\xec',       # push ebp; mov ebp, esp  (MSVC)
                b'\x55\x89\xe5',       # push ebp; mov ebp, esp  (GCC)
            ],
        }

        patterns = _PROLOGUES.get(self.arch, [])
        if patterns:
            try:
                for sec in binary.sections:
                    if not (sec.characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
                        continue
                    sec_data = bytes(sec.content)
                    sec_va = base + sec.virtual_address
                    for pat in patterns:
                        pos = 0
                        while True:
                            idx = sec_data.find(pat, pos)
                            if idx < 0:
                                break
                            starts.add(sec_va + idx)
                            pos = idx + 1
            except Exception:
                pass

        self.func_starts = sorted(starts)

    def _build_call_graph_pe(self, data: bytes, binary) -> None:
        """Call graph for PE x86_64/x86_32: vectorized 0xe8 scan on executable sections."""
        if self.arch not in ('x86_64', 'x86_32'):
            return
        if not _NUMPY_OK:
            self._build_call_graph_pe_sequential(data, binary)
            return

        base = self.base_va
        plt_arr  = _va_arr_to_i64(sorted(self.plt.keys())) if self.plt else np.empty(0, np.int64)
        func_arr = _va_arr_to_i64(self.func_starts) if self.func_starts else np.empty(0, np.int64)
        va_to_export: Dict[int, str] = {va: nm for nm, va in self.exports.items()}
        edges: List[Tuple[int, int, str]] = []

        try:
            code_secs = [s for s in binary.sections if s.characteristics & 0x20000000]
        except Exception:
            code_secs = []

        for sec in code_secs:
            sec_data = bytes(sec.content)
            sec_va = base + int(sec.virtual_address)
            N = len(sec_data)
            if N < 5:
                continue

            buf = np.frombuffer(sec_data, dtype=np.uint8)
            cand_pos = np.where(buf[:-4] == 0xe8)[0]
            if len(cand_pos) == 0:
                continue

            idx = cand_pos[:, None] + np.array([1, 2, 3, 4], dtype=np.intp)
            disp_bytes = buf[idx]
            disp_u32 = (disp_bytes[:, 0].astype(np.uint32)
                        | (disp_bytes[:, 1].astype(np.uint32) << 8)
                        | (disp_bytes[:, 2].astype(np.uint32) << 16)
                        | (disp_bytes[:, 3].astype(np.uint32) << 24))
            disp_i32 = disp_u32.view(np.int32)

            site_vas   = _va_to_i64(sec_va) + cand_pos.astype(np.int64)
            target_vas = site_vas + np.int64(5) + disp_i32.astype(np.int64)

            valid = np.zeros(len(target_vas), dtype=bool)
            if len(plt_arr):
                hi = np.searchsorted(plt_arr, target_vas)
                hi = np.minimum(hi, len(plt_arr) - 1)
                valid |= plt_arr[hi] == target_vas
            if len(func_arr):
                hi = np.searchsorted(func_arr, target_vas)
                hi = np.minimum(hi, len(func_arr) - 1)
                valid |= func_arr[hi] == target_vas

            site_vas   = site_vas[valid]
            target_vas = target_vas[valid]

            if len(func_arr) and len(site_vas):
                owner_idx = np.searchsorted(func_arr, site_vas, side='right') - 1
                owner_idx = np.maximum(owner_idx, 0)
                owner_vas = func_arr[owner_idx]
            else:
                owner_vas = site_vas

            for owner_va, target_va in zip(owner_vas.tolist(), target_vas.tolist()):
                label = self.plt.get(target_va, "") or va_to_export.get(target_va, "")
                edges.append((int(owner_va), int(target_va), label))

        self.call_edges = edges

    def _build_call_graph_pe_sequential(self, data: bytes, binary) -> None:
        """Sequential Capstone fallback for PE call graph (NumPy unavailable)."""
        import capstone

        base = self.base_va
        cs_mode = capstone.CS_MODE_64 if self.arch == 'x86_64' else capstone.CS_MODE_32
        cs = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        cs.detail = False

        va_to_export: Dict[int, str] = {va: nm for nm, va in self.exports.items()}
        edges: List[Tuple[int, int, str]] = []

        try:
            for sec in binary.sections:
                if not (sec.characteristics & 0x20000000):
                    continue
                sec_data = bytes(sec.content)
                sec_va = base + int(sec.virtual_address)
                for insn in cs.disasm(sec_data, sec_va):
                    if insn.mnemonic.lower() != 'call':
                        continue
                    try:
                        target = int(insn.op_str.strip(), 16)
                    except ValueError:
                        continue
                    label = self.plt.get(target, "") or va_to_export.get(target, "")
                    owner = self.func_containing(insn.address) or insn.address
                    edges.append((owner, target, label))
        except Exception:
            pass

        self.call_edges = edges

    def _build_string_xref_index_pe(self, data: bytes, binary) -> None:
        """String xref for PE: RIP-relative scan (x86_64) or absolute scan (x86_32)."""
        if not self.strings:
            return
        if self.arch == 'x86_32':
            self._build_string_xref_index_pe_x86_32(data, binary)
            return
        if not _NUMPY_OK or self.arch != 'x86_64':
            return

        from numpy.lib.stride_tricks import as_strided

        base = self.base_va
        str_va_arr = _va_arr_to_i64(sorted(self.strings.keys()))
        str_xref: Dict[int, List[int]] = {}
        func_str: Dict[int, List[int]] = {}

        try:
            for sec in binary.sections:
                if not (sec.characteristics & 0x20000000):
                    continue
                sec_data = bytes(sec.content)
                sec_va = base + int(sec.virtual_address)
                N = len(sec_data)
                if N < 4:
                    continue

                buf_u8 = np.frombuffer(sec_data, dtype=np.uint8)
                end = N - 3
                windows = as_strided(buf_u8, shape=(end, 4), strides=(1, 1))
                disp_u32 = (windows[:, 0].astype(np.uint32)
                            | (windows[:, 1].astype(np.uint32) << 8)
                            | (windows[:, 2].astype(np.uint32) << 16)
                            | (windows[:, 3].astype(np.uint32) << 24))
                disp_i32 = disp_u32.view(np.int32)

                positions = np.arange(end, dtype=np.int64)
                target_vas = _va_to_i64(sec_va) + positions + np.int64(4) + disp_i32.astype(np.int64)

                hits = np.searchsorted(str_va_arr, target_vas)
                clipped = np.minimum(hits, len(str_va_arr) - 1)
                valid = str_va_arr[clipped] == target_vas

                for pos, sva in zip(positions[valid].tolist(), target_vas[valid].tolist()):
                    code_va = sec_va + int(pos)
                    sva = int(sva)
                    fva = self.func_containing(code_va)
                    if fva is None:
                        continue
                    str_xref.setdefault(sva, []).append(code_va)
                    func_str.setdefault(fva, []).append(sva)
        except Exception:
            pass

        self._str_xref_idx = str_xref
        self._func_str_idx = {k: list(dict.fromkeys(v)) for k, v in func_str.items()}

    def _build_string_xref_index_pe_x86_32(self, data: bytes, binary) -> None:
        """x86_32 PE string xref: scan code sections for 4-byte LE absolute addresses."""
        if not _NUMPY_OK:
            return
        from numpy.lib.stride_tricks import as_strided

        base = self.base_va
        str_va_arr = _va_arr_to_i64(sorted(self.strings.keys()))
        str_xref: Dict[int, List[int]] = {}
        func_str: Dict[int, List[int]] = {}

        try:
            for sec in binary.sections:
                if not (sec.characteristics & 0x20000000):
                    continue
                sec_data = bytes(sec.content)
                sec_va = base + int(sec.virtual_address)
                N = len(sec_data)
                if N < 4:
                    continue

                buf_u8 = np.frombuffer(sec_data, dtype=np.uint8)
                end = N - 3
                windows = as_strided(buf_u8, shape=(end, 4), strides=(1, 1))
                abs_u32 = (windows[:, 0].astype(np.uint32)
                           | (windows[:, 1].astype(np.uint32) << 8)
                           | (windows[:, 2].astype(np.uint32) << 16)
                           | (windows[:, 3].astype(np.uint32) << 24))

                positions = np.arange(end, dtype=np.int64)
                candidate_vas = abs_u32.astype(np.int64)

                hits = np.searchsorted(str_va_arr, candidate_vas)
                clipped = np.minimum(hits, len(str_va_arr) - 1)
                valid = str_va_arr[clipped] == candidate_vas

                for pos, sva in zip(positions[valid].tolist(), candidate_vas[valid].tolist()):
                    code_va = sec_va + int(pos)
                    sva = int(sva)
                    fva = self.func_containing(code_va)
                    if fva is None:
                        continue
                    str_xref.setdefault(sva, []).append(code_va)
                    func_str.setdefault(fva, []).append(sva)
        except Exception:
            pass

        self._str_xref_idx = str_xref
        self._func_str_idx = {k: list(dict.fromkeys(v)) for k, v in func_str.items()}

    # ── indices ────────────────────────────────────────────────────────────────

    def _build_indices(self) -> None:
        # Rebuild callers_idx: sym_name -> [(caller_va, label)]
        callers_idx: Dict[str, List[Tuple[int, str]]] = {}
        callees_idx: Dict[int, List[Tuple[int, str]]] = {}

        for from_va, to_va, label in self.call_edges:
            # Callers by symbol name
            sym = label or self.plt.get(to_va) or f"0x{to_va:x}"
            callers_idx.setdefault(sym, []).append((from_va, self._va_name(from_va)))
            # Callees by function VA
            callees_idx.setdefault(from_va, []).append((to_va, sym))

        self._callers_idx = callers_idx
        self._callees_idx = callees_idx

    def _va_name(self, va: int) -> str:
        # Overlay takes priority over exports in all display contexts.
        reg = get_registry()
        discovered = reg.get_name(self.sha256, va)
        if discovered:
            return discovered
        for name, eva in self.exports.items():
            if eva == va:
                return name
        return f"0x{va:x}"

    # ── serialization ─────────────────────────────────────────────────────────

    def _save_json(self, path: Path) -> None:
        payload = {
            "path": self.path,
            "sha256": self.sha256,
            "base_va": self.base_va,
            "arch": self.arch,
            "plt": {str(va): name for va, name in self.plt.items()},
            "exports": {name: va for name, va in self.exports.items()},
            "strings": {str(va): s for va, s in self.strings.items()},
            "func_starts": self.func_starts,
            "call_edges": [[f, t, l] for f, t, l in self.call_edges],
            "thumb_funcs": sorted(self.thumb_funcs),
            "str_xref_idx": {str(k): v for k, v in self._str_xref_idx.items()},
            "func_str_idx": {str(k): v for k, v in self._func_str_idx.items()},
        }
        path.write_text(json.dumps(payload, separators=(",", ":")))

    @classmethod
    def _load_json(cls, path: Path, orig_path: str) -> "BinaryContext":
        payload = json.loads(path.read_text())
        ctx = cls()
        ctx.path = orig_path or payload.get("path", "")
        ctx.sha256 = payload["sha256"]
        ctx.base_va = int(payload.get("base_va", 0))
        ctx.arch = payload.get("arch", "x86_64")
        ctx.plt = {int(k): v for k, v in payload.get("plt", {}).items()}
        ctx.exports = {k: int(v) for k, v in payload.get("exports", {}).items()}
        ctx.strings = {int(k): v for k, v in payload.get("strings", {}).items()}
        ctx.func_starts = [int(x) for x in payload.get("func_starts", [])]
        ctx.thumb_funcs = set(int(x) for x in payload.get("thumb_funcs", []))
        ctx.call_edges = [(int(f), int(t), l) for f, t, l in payload.get("call_edges", [])]
        ctx._build_indices()
        ctx._str_xref_idx = {int(k): v for k, v in payload.get("str_xref_idx", {}).items()}
        ctx._func_str_idx = {int(k): v for k, v in payload.get("func_str_idx", {}).items()}
        return ctx
