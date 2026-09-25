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


def _cache_path(binary_sha256: str, binary_name: str) -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    slug = f"{binary_sha256[:16]}_{Path(binary_name).name}"
    return _CACHE_DIR / f"{slug}.json"


def _detect_arch(binary) -> str:
    try:
        m = str(binary.header.machine_type)
        if 'X86_64' in m or 'AMD64' in m:
            return 'x86_64'
        if 'AARCH64' in m or 'ARM64' in m:
            return 'arm64'
        if 'ARM' in m:
            return 'arm32'
    except Exception:
        pass
    return 'x86_64'


class BinaryContext:
    """
    Pre-computed binary context. One object = complete working context for a
    stripped ELF binary: symbols, strings, function starts, call graph.
    Supports x86_64, arm64, and arm32 ELF binaries.
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
            b'MZ': 'PE/DOS executable',
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
            sec_data = bytes(sec.content)
            sec_va = sec.virtual_address
            i = 0
            while i < len(sec_data):
                start = i
                while i < len(sec_data) and 0x20 <= sec_data[i] < 0x7f:
                    i += 1
                if i - start >= _MIN_STR_LEN:
                    content = sec_data[start:i].decode("ascii", errors="replace")
                    self.strings[sec_va + start] = content
                else:
                    i = start + 1

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
                                    va = e["initial_location"]
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
        site_vas    = np.int64(sec_va) + cand_pos.astype(np.int64)
        target_vas  = site_vas + np.int64(5) + disp_i32.astype(np.int64)

        # Filter: target must be a known PLT stub or function entry
        plt_arr  = np.array(sorted(self.plt.keys()),   dtype=np.int64) if self.plt         else np.empty(0, np.int64)
        func_arr = np.array(self.func_starts,           dtype=np.int64) if self.func_starts else np.empty(0, np.int64)

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

        insn_vas = np.int64(sec_va) + byte_off.astype(np.int64)
        target_vas = insn_vas + np.int64(8) + imm_i32.astype(np.int64) * 4

        plt_arr  = np.array(sorted(self.plt.keys()),   dtype=np.int64) if self.plt         else np.empty(0, np.int64)
        func_arr = np.array(self.func_starts,           dtype=np.int64) if self.func_starts else np.empty(0, np.int64)

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
        arm32: capstone LDR [PC, #off] literal pool scan per function.
        """
        if self.arch == 'arm32':
            self._build_string_xref_index_arm32(data, binary)
            return
        if not _NUMPY_OK:
            return

        text_sec = binary.get_section(".text")
        if not text_sec:
            return

        text_data = bytes(text_sec.content)
        text_va = int(text_sec.virtual_address)
        N = len(text_data)
        if N < 4 or not self.strings:
            return

        str_va_arr = np.array(sorted(self.strings.keys()), dtype=np.int64)

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
        target_vas = np.int64(text_va) + positions + np.int64(4) + disp_i32.astype(np.int64)

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
