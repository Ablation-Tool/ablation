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
        return 'unknown'
    return 'unknown'


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
        # Use .value for newer machine types not yet in all LIEF builds.
        # LoongArch64: 0x6232 (UEFI PE32+ LA64 firmware modules)
        # RISC-V 64-bit: 0x5064
        _v = m.value if hasattr(m, 'value') else int(m)
        if _v == 0x6232:
            return 'loongarch64'
        if _v == 0x5064:
            return 'riscv64'
    except Exception:
        return 'unknown'
    return 'unknown'


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
            # IBM AIX installp package (BFF format). Contains AIX .a static libs and
            # XCOFF32/64 binaries for AIX, not Linux ELFs.  lief.parse() silently returns
            # None or logs parse errors on these. Magic: 0x09006bea (big-endian u32).
            b'\x09\x00\x6b\xea': 'AIX BFF (installp) package — no Linux ELF content',
            # IBM XCOFF32 object file (RS/6000, AIX). lief.parse() either silently returns
            # None or logs noise. Magic: 0x01df (big-endian u16 at offset 0).
            # Note: XCOFF64 uses 0x01f7; BinaryContext.build_xcoff() handles that path.
            b'\x01\xdf': 'XCOFF32 object file (AIX RS/6000) — use build_xcoff() instead',
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
            sym = self.plt.get(va) or self._va_name(va)
            raw = self._callers_idx.get(sym, [])
        return [(cva, self.name(cva)) for cva, _ in raw]

    def reachable_from(self, source_vas, depth: int = 3) -> Set[int]:
        """Return the set of function VAs reachable from *source_vas* within *depth* call steps.

        Uses BFS over ``callees_of``, so depth is exact (not a hop-count bound that
        DFS can exceed via backtracking).  PLT stubs are included in traversal so
        cross-library hops count toward the depth limit.

        Example::

            net_srcs = {va for va, _ in ctx.callers_of('recv')}
            reachable = ctx.reachable_from(net_srcs, depth=3)
            dangerous = ap_func_vas & reachable
        """
        frontier: Set[int] = set(source_vas)
        visited:  Set[int] = set(frontier)
        for _ in range(depth):
            next_frontier: Set[int] = set()
            for va in frontier:
                for callee_va, _ in self.callees_of(va):
                    if callee_va not in visited:
                        visited.add(callee_va)
                        next_frontier.add(callee_va)
            frontier = next_frontier
            if not frontier:
                break
        return visited

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
        if binary is None:
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

    def name(self, va) -> str:
        """Best available name for va: overlay > export > PLT > hex.

        This is the single call for "what is this function?": use it everywhere
        a hex address would otherwise appear.

        *va* may be a ``(va, name)`` tuple as returned by :meth:`callers_of` and
        :meth:`callees_of`; in that case the integer element is extracted
        automatically so callers do not need to unpack.
        """
        if isinstance(va, tuple):
            va = va[0]
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

    def save_cache(self) -> None:
        """Persist the current in-memory state (including func_starts) to the cache file.

        Call this after any in-memory update to func_starts or call_edges that
        should survive across sessions — for example, after patch_context() adds
        pclntab-recovered function starts to the binary context.
        """
        if not self.sha256 or not self.path:
            return
        cache_file = _cache_path(self.sha256, self.path)
        self._save_json(cache_file)

    def rebuild_call_graph(self) -> int:
        """Rebuild the call graph using the current func_starts and persist the result.

        Call after patch_context() has expanded func_starts with pclntab boundaries.
        The cached call graph was built from a smaller func_starts set; BL edges to
        pclntab-recovered functions are absent until this method runs.

        Returns the new call_edges count.
        """
        if not _LIEF_OK or not self.path:
            return len(self.call_edges)
        data = open(self.path, "rb").read()
        try:
            binary = lief.parse(data)
        except Exception:
            return len(self.call_edges)
        if not isinstance(binary, (lief.ELF.Binary, lief.PE.Binary)):
            return len(self.call_edges)
        self._build_call_graph(data, binary)
        self._build_indices()
        self.save_cache()
        return len(self.call_edges)

    def set_name(self, va: int, name: str, source: str = "manual") -> None:
        """Register a discovered name for va. Persists across sessions immediately."""
        get_registry().set_name(self.sha256, va, name, source=source)

    def set_names_bulk(self, names: Dict[int, Tuple[str, str]]) -> int:
        """Register many (va → name, source) pairs in one disk write.

        names: {va: (name, source)}
        Returns the number of new VAs added (existing VAs are updated silently).
        Use this instead of repeated set_name() when registering more than ~10 names
        at once — set_name() saves to disk on every call, making bulk use O(N²).
        """
        return get_registry().set_names_bulk(self.sha256, names)

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

    # ── analysis helpers ─────────────────────────────────────────────────────

    def plt_sparsity_warning(self, threshold: int = 6) -> str | None:
        """Return a warning string when PLT import count is below threshold.

        Canonical packer footprint: only VirtualAlloc / LoadLibrary /
        GetProcAddress (3-5 imports). Pairs with EntropyAnalyzer to gate
        pre-analysis packing detection. Returns None when not sparse.
        """
        n = len(self.plt)
        if n == 0:
            return None
        if n >= threshold:
            return None
        names = ', '.join(sorted(self.plt.values())[:threshold])
        return (f"[PLT_SPARSE] {n} import(s) below threshold {threshold} "
                f"— possible packer stub: {names}")

    def pushad_at_entry(self) -> bool:
        """Return True when PUSHAD/PUSHA appears within the first 32 bytes of the entry point.

        On x86 firmware, PUSHAD at entry is a strong packer signature: the
        packer saves all registers, unpacks to a new memory region, then POPAD
        and JMP to the original entry point. Requires lief for EP location.
        """
        if self.arch not in ('x86', 'i386', 'i686'):
            return False
        try:
            import lief
            import capstone
            data = open(self.path, 'rb').read()
            elf = lief.parse(self.path)
            if elf is None:
                return False
            ep = elf.header.entrypoint
            if ep == 0:
                return False
            off = ep - self.base_va
            if off < 0 or off + 32 > len(data):
                return False
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            for insn in md.disasm(data[off:off + 32], ep):
                if insn.mnemonic in ('pushad', 'pusha'):
                    return True
                # Stop at the first non-push instruction (packer must start with PUSHAD)
                if not insn.mnemonic.startswith('push'):
                    break
            return False
        except Exception:
            return False

    def ads_reference_vas(self) -> list[int]:
        """Return VAs of CreateFileA/NtCreateFile call sites whose filename includes ':'.

        Alternate Data Streams (ADS) are referenced by paths like 'file.txt:hidden'.
        NtCreateFile with such a path hides data from most directory listings.
        Only meaningful for PE binaries; returns [] for ELF.
        """
        ads_funcs = frozenset({'CreateFileA', 'CreateFileW', 'NtCreateFile',
                                'ZwCreateFile', 'CreateFile'})
        ads_call_vas: list[int] = []
        for va, name in self.plt.items():
            if name.split('@')[0].lstrip('_') not in ads_funcs:
                continue
            for xref_va in self.callers_of(va):
                # Check for a nearby string containing ':' in the strings table
                nearby = self.strings_near(xref_va, window=64)
                if any(':' in s for s in nearby):
                    ads_call_vas.append(xref_va)
        return ads_call_vas

    def cpuid_locations(self) -> list[int]:
        """Return VAs of CPUID instructions followed by a conditional branch.

        Used for VM-detection heuristic: CPUID + conditional branch is a
        classic anti-VM check pattern (e.g. checking hypervisor bit in ECX).
        Only meaningful on x86/x86_64 binaries.
        """
        if self.arch not in ('x86_64', 'x86', 'i386', 'i686'):
            return []
        try:
            import capstone
            data = open(self.path, 'rb').read()
            base = self.base_va
            md = capstone.Cs(capstone.CS_ARCH_X86,
                             capstone.CS_MODE_64 if self.arch == 'x86_64' else capstone.CS_MODE_32)
            md.detail = False
            results: list[int] = []
            insns = list(md.disasm(data, base))
            for i, insn in enumerate(insns):
                if insn.mnemonic != 'cpuid':
                    continue
                # Check if the next 5 instructions contain a conditional branch
                window = insns[i + 1:i + 6]
                for nxt in window:
                    if nxt.mnemonic.startswith('j') and nxt.mnemonic != 'jmp':
                        results.append(insn.address)
                        break
            return results
        except Exception:
            return []

    # ── build internals ───────────────────────────────────────────────────────

    @classmethod
    def _build(cls, data: bytes, path: str, sha: str) -> "BinaryContext":
        ctx = cls()
        ctx.path = path
        ctx.sha256 = sha

        if not _LIEF_OK:
            return ctx

        try:
            is_mips = (
                len(data) > 20 and data[:4] == b'\x7fELF'
                and int.from_bytes(data[18:20], 'big' if data[5] == 2 else 'little') == 8
            )
            if is_mips:
                with lief.logging.level_scope(lief.logging.LEVEL.CRITICAL):
                    binary = lief.parse(data)
            else:
                binary = lief.parse(data)
        except Exception:
            return ctx
        if isinstance(binary, lief.PE.Binary):
            return cls._build_pe(data, path, sha, binary)
        if not isinstance(binary, lief.ELF.Binary):
            # Attempt XCOFF detection before giving up
            if data[:2] in (b'\x01\xdf', b'\x01\xf7'):
                return cls._build_xcoff(data, path, sha)
            if data[:2] == b'\x01\x6d':
                return cls._build_m88k(data, path, sha)
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

        # i386: .rel.plt (8-byte REL, no addend), stubs in .plt with FF 25 [abs32]
        if self.arch == 'x86_32':
            self._extract_plt_x86_32(binary)
            return

        # PPC32 BE: .rela.plt (12-byte RELA, big-endian), glink stubs in .text (4 bytes each)
        if self.arch == 'ppc32':
            self._extract_plt_ppc32be(binary)
            return

        # PPC64: dispatch on endianness.
        # ELFv2 LE (ELFDATA2LSB=1): stubs inside .text — std r2,24(r1); ld r12,N(r2); mtctr r12; bctr
        # ELFv1 BE (ELFDATA2MSB=2): glink stubs inside .text — same instruction words, BE byte order
        if self.arch == 'ppc64':
            try:
                ei_data = binary.header.identity[5]
                if ei_data == 1:  # ELFDATA2LSB — ppc64le ELFv2
                    self._extract_plt_ppc64le(binary)
                    return
                elif ei_data == 2:  # ELFDATA2MSB — ppc64 BE ELFv1
                    self._extract_plt_ppc64be(binary)
                    return
            except Exception:
                pass

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

        if self.arch == 'arm64':
            self._extract_plt_arm64(binary, got_to_sym)
            return

        if not got_to_sym:
            # Fallback: LIEF imported_functions
            try:
                for sym in binary.imported_functions:
                    if hasattr(sym, 'value') and sym.value and sym.name:
                        # Strip ELF versioning suffix (system@GLIBC_2.0 → system).
                        # Downstream consumers use exact-match lookups; versioned names
                        # cause silent misses — or, if callers use `in` substring, false positives.
                        self.plt[sym.value] = sym.name.split('@')[0]
            except Exception:
                pass
            try:
                for rel in binary.relocations:
                    if not rel.has_symbol:
                        continue
                    rtype = str(getattr(rel, 'type', ''))
                    if 'JUMP_SLOT' in rtype and rel.symbol.name:
                        self.plt[rel.address] = rel.symbol.name.split('@')[0]
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
                # IBT .plt.sec stubs: endbr64 + bnd jmp *[rip+disp32] — skip the f2 BND prefix
                if start < len(chunk) and chunk[start] == 0xf2:
                    start += 1
                if len(chunk) < start + 6:
                    continue
                if chunk[start:start + 2] == b'\xff\x25':
                    disp = struct.unpack_from("<i", chunk, start + 2)[0]
                    got_va = stub_va + start + 6 + disp
                    if got_va in got_to_sym:
                        self.plt[stub_va] = got_to_sym[got_va]

    def _extract_plt_arm64(self, binary, got_to_sym: Dict[int, str]) -> None:
        """Resolve AArch64 ADRP-based PLT stubs to their dynamic symbols."""
        import capstone
        from capstone import arm64 as C_ARM64

        arm64_arch = (
            getattr(capstone, 'CS_ARCH_AARCH64', None)
            or getattr(capstone, 'CS_ARCH_ARM64', None)
        )
        if arm64_arch is None or not got_to_sym:
            return
        md = capstone.Cs(arm64_arch, capstone.CS_MODE_ARM)
        md.detail = True

        for section_name in ('.plt', '.plt.sec', '.plt.got'):
            try:
                plt_sec = binary.get_section(section_name)
            except Exception:
                plt_sec = None
            if not plt_sec:
                continue
            plt_data = bytes(plt_sec.content)
            plt_base = int(plt_sec.virtual_address)
            for offset in range(0, len(plt_data) - 15, 16):
                stub_va = plt_base + offset
                chunk = plt_data[offset:offset + 16]
                page = None
                page_reg = None
                got_off = None
                for insn in md.disasm(chunk, stub_va):
                    mnemonic = insn.mnemonic.lower()
                    operands = insn.operands
                    if (
                        mnemonic == 'adrp'
                        and len(operands) == 2
                        and operands[0].type == C_ARM64.ARM64_OP_REG
                        and operands[1].type == C_ARM64.ARM64_OP_IMM
                    ):
                        page = operands[1].imm
                        page_reg = operands[0].reg
                    elif (
                        mnemonic == 'add'
                        and len(operands) >= 3
                        and operands[0].type == C_ARM64.ARM64_OP_REG
                        and operands[1].type == C_ARM64.ARM64_OP_REG
                        and operands[2].type == C_ARM64.ARM64_OP_IMM
                        and operands[0].reg == page_reg
                        and operands[1].reg == page_reg
                    ):
                        got_off = operands[2].imm
                    elif (
                        mnemonic == 'ldr'
                        and len(operands) >= 2
                        and operands[1].type == C_ARM64.ARM64_OP_MEM
                        and operands[1].mem.base == page_reg
                        and got_off is None
                    ):
                        got_off = operands[1].mem.disp
                if page is None or got_off is None:
                    continue
                name = got_to_sym.get(page + got_off)
                if name:
                    self.plt[stub_va] = name.split('@')[0]

    def _extract_plt_x86_32(self, binary) -> None:
        """i386 ELF PLT extraction.

        ET_EXEC stubs (non-PIC):
          ff 25 XX XX XX XX  jmp dword ptr [abs_GOT_va]
          68 YY YY YY YY     push reloc_offset
          e9 ZZ ZZ ZZ ZZ     jmp PLT_resolver

        ET_DYN PIC stubs (EBX = GOT base at runtime):
          ff a3 XX XX XX XX  jmp dword ptr [ebx+disp32]
          68 YY YY YY YY     push reloc_offset
          e9 ZZ ZZ ZZ ZZ     jmp PLT_resolver
          got_va = got_base + disp32  (got_base = .got section VA)

        PLT[0] is the resolver stub — not a real call target.
        .rel.plt: 8-byte REL entries, r_offset=GOT_entry_va, r_info=(sym_idx<<8)|7
        """
        got_to_sym: Dict[int, str] = {}
        try:
            rel_plt = binary.get_section('.rel.plt')
            if rel_plt:
                rel_data = bytes(rel_plt.content)
                for off in range(0, len(rel_data) - 7, 8):
                    r_offset, r_info = struct.unpack_from('<II', rel_data, off)
                    sym_idx = r_info >> 8
                    try:
                        sym = binary.dynamic_symbols[sym_idx]
                        if sym.name:
                            got_to_sym[r_offset] = sym.name
                    except Exception:
                        pass
        except Exception:
            pass

        if not got_to_sym:
            return

        # For PIC SOs (ET_DYN), stubs use [ebx+disp32]. Resolve GOT base from .got section.
        got_base: int = 0
        for got_sec_name in ('.got', '.got.plt'):
            try:
                gs = binary.get_section(got_sec_name)
                if gs:
                    got_base = int(gs.virtual_address)
                    break
            except Exception:
                pass

        for sec_name in ('.plt', '.plt.got'):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_data = bytes(sec.content)
            sec_va = int(sec.virtual_address)
            for off in range(0, len(sec_data) - 5, 16):
                chunk = sec_data[off:off + 6]
                if len(chunk) < 6:
                    break
                if chunk[0:2] == b'\xff\x25':
                    # ET_EXEC: absolute GOT address
                    got_va = struct.unpack_from('<I', chunk, 2)[0]
                    if got_va in got_to_sym:
                        self.plt[sec_va + off] = got_to_sym[got_va]
                elif chunk[0:2] == b'\xff\xa3' and got_base:
                    # ET_DYN PIC: jmp [ebx+disp32], EBX=got_base at runtime
                    disp32 = struct.unpack_from('<I', chunk, 2)[0]
                    got_va = got_base + disp32
                    if got_va in got_to_sym:
                        self.plt[sec_va + off] = got_to_sym[got_va]

    def _extract_plt_ppc32be(self, binary) -> None:
        """PPC32 BE ELF PLT extraction.

        PPC32 uses .rela.plt (12-byte RELA entries, big-endian):
          r_offset:u32  — GOT slot VA that ld.so will patch
          r_info:u32    — (sym_idx << 8) | R_PPC_JMP_SLOT(21)
          r_addend:u32  — addend (unused)

        Callers use linker-inserted call stubs in .text with the pattern:
          lis  r11, HI        ; 0x3D60xxxx
          lwz  r11, LO(r11)   ; 0x816Bxxxx
          mtctr r11            ; 0x7D6903A6
          bctr                 ; 0x4E800420
        where HI:LO form the absolute GOT slot address.  Each 4-instruction
        stub corresponds to one external symbol.
        """
        got_to_sym: Dict[int, str] = {}
        try:
            rela_plt = binary.get_section('.rela.plt')
            if rela_plt:
                rela_data = bytes(rela_plt.content)
                for off in range(0, len(rela_data) - 11, 12):
                    r_offset, r_info, _r_addend = struct.unpack_from('>III', rela_data, off)
                    sym_idx = r_info >> 8  # ELF32: sym in upper 24 bits
                    try:
                        sym = binary.dynamic_symbols[sym_idx]
                        if sym.name:
                            got_to_sym[r_offset] = sym.name
                    except Exception:
                        pass
        except Exception:
            pass

        if not got_to_sym:
            return

        # Scan .text for 4-instruction call stub pattern:
        #   lis  r11, HI    (0x3D60xxxx)
        #   lwz  r11, LO(r11) (0x816Bxxxx)
        #   mtctr r11       (0x7D6903A6)
        #   bctr            (0x4E800420)
        _MTCTR_R11 = 0x7D6903A6
        _BCTR      = 0x4E800420
        _LIS_R11   = 0x3D600000
        _LIS_MASK  = 0xFFFF0000
        _LWZ_R11   = 0x816B0000
        _LWZ_MASK  = 0xFFFF0000
        try:
            text_sec = binary.get_section('.text')
            if not text_sec:
                return
            text_data = bytes(text_sec.content)
            text_va   = int(text_sec.virtual_address)
            for i in range(0, len(text_data) - 15, 4):
                w0 = struct.unpack_from('>I', text_data, i)[0]
                if (w0 & _LIS_MASK) != _LIS_R11:
                    continue
                w1 = struct.unpack_from('>I', text_data, i + 4)[0]
                if (w1 & _LWZ_MASK) != _LWZ_R11:
                    continue
                w2 = struct.unpack_from('>I', text_data, i + 8)[0]
                if w2 != _MTCTR_R11:
                    continue
                w3 = struct.unpack_from('>I', text_data, i + 12)[0]
                if w3 != _BCTR:
                    continue
                hi = w0 & 0xFFFF
                lo = w1 & 0xFFFF
                # Sign-extend 16-bit fields
                if hi >= 0x8000:
                    hi -= 0x10000
                if lo >= 0x8000:
                    lo -= 0x10000
                got_va = (hi << 16) + lo
                if got_va in got_to_sym:
                    stub_va = text_va + i
                    self.plt[stub_va] = got_to_sym[got_va]
        except Exception:
            pass

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

    def _extract_plt_ppc64le(self, binary) -> None:
        # PPC64le ELF V2: PLT stubs live in .text (not a separate .plt section).
        # Each stub is 16 bytes:
        #   std  r2, 24(r1)   0xF8410018  -- saves caller TOC
        #   ld   r12, N(r2)   0xE9820000|(N&0xFFFF)  -- loads GOT slot
        #   mtctr r12          0x7D8903A6
        #   bctr               0x4E800420
        # where GOT slot VA = r2 + sign_extend_16(N), and r2 is the ELF-wide TOC pointer.
        #
        # r2 is found from any function prologue: addis r2,r12,HI; addi r2,r2,LO
        # => r2 = prologue_VA + sign_extend_16(HI)*0x10000 + sign_extend_16(LO)

        got_to_sym: Dict[int, str] = {}
        rela_plt_ordered: List[Optional[str]] = []  # file-order names for .glink stub mapping
        try:
            rela_plt = binary.get_section('.rela.plt')
            if rela_plt:
                rela_data = bytes(rela_plt.content)
                for off in range(0, len(rela_data) - 23, 24):
                    r_offset, r_info = struct.unpack_from('<QQ', rela_data, off)
                    sym_idx = r_info >> 32
                    try:
                        sym = binary.dynamic_symbols[sym_idx]
                        if sym.name:
                            got_to_sym[r_offset] = sym.name
                            rela_plt_ordered.append(sym.name)
                        else:
                            rela_plt_ordered.append(None)
                    except Exception:
                        rela_plt_ordered.append(None)
        except Exception:
            pass

        if not got_to_sym:
            return

        # Find r2 from a function prologue.
        r2: Optional[int] = None
        for sec_name in ('.text', '.init'):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_bytes = bytes(sec.content)
            sec_va = int(sec.virtual_address)
            for off in range(0, len(sec_bytes) - 7, 4):
                w0 = struct.unpack_from('<I', sec_bytes, off)[0]
                w1 = struct.unpack_from('<I', sec_bytes, off + 4)[0]
                # addis r2, r12, HI  (opcode=15, rD=2, rA=12) — PIC/PIE form; TOC relative to entry VA
                # addi  r2, r2,  LO  (opcode=14, rD=2, rA=2)
                if (w0 & 0xFFFF0000) == 0x3C4C0000 and (w1 & 0xFFFF0000) == 0x38420000:
                    hi = w0 & 0xFFFF
                    lo = w1 & 0xFFFF
                    if hi & 0x8000:
                        hi -= 0x10000
                    if lo & 0x8000:
                        lo -= 0x10000
                    cand = (sec_va + off) + (hi << 16) + lo
                    # PIE DSO form: addis r2,r12,HI is encoding-unambiguous (rA=r12
                    # only in TOC prologues). When all PLT stubs use 5-word addis+ld
                    # the GOT may be >32KB from r2; widen the acceptance window to
                    # ±2GB so large DSOs with HI!=0 addis stubs are not rejected.
                    if any(-(1 << 31) <= (gva - cand) < (1 << 31) for gva in got_to_sym):
                        r2 = cand
                        break
                # lis r2, HI (= addis r2, r0, HI, rA=0) — absolute-address form used by position-dependent
                # IBM XLC-compiled binaries (non-PIE with fixed load address, e.g. base_va != 0).
                # addi r2, r2, LO  (opcode=14, rD=2, rA=2)
                # No proximity check needed: lis+addi into r2 is unambiguous (rA=0 makes it a
                # constant load, not a relative adjustment), so any match is the real TOC setup.
                # A tight ±32KB GOT check would falsely reject large binaries where PLT GOT slots
                # are >32KB from the TOC (addis+ld stubs used instead of plain ld).
                elif (w0 & 0xFFFF0000) == 0x3C400000 and (w1 & 0xFFFF0000) == 0x38420000:
                    hi = w0 & 0xFFFF
                    lo = w1 & 0xFFFF
                    if hi & 0x8000:
                        hi -= 0x10000
                    if lo & 0x8000:
                        lo -= 0x10000
                    r2 = (hi << 16) + lo
                    break
            if r2 is not None:
                break

        if r2 is None:
            # .glink lazy PLT fallback (ELFv2-GLINK-001): when r2 cannot be determined
            # (e.g. PIE DSOs where TOC is set dynamically at load time), the 4-word stub
            # scan cannot run, but .glink lazy stubs can still be mapped directly from
            # .rela.plt file order — no r2 needed.
            if rela_plt_ordered:
                try:
                    glink = binary.get_section('.glink')
                    if glink:
                        glink_va = int(glink.virtual_address)
                        glink_size = int(glink.size)
                        PLT0_SIZE = 0x40  # ELFv2: PLT0 resolver padded to 64-byte alignment
                        for i, sym_name in enumerate(rela_plt_ordered):
                            if not sym_name:
                                continue
                            stub_va = glink_va + PLT0_SIZE + i * 4
                            if stub_va + 4 > glink_va + glink_size:
                                break
                            self.plt[stub_va] = sym_name
                except Exception:
                    pass
            return

        # Decode stubs: scan .text and .init for 4-word and 5-word PLT stub patterns.
        #
        # 4-word form (small binary, GOT offset fits in signed 16 bits):
        #   std  r2, 0x18(r1)        0xF8410018
        #   ld   r12, N(r2)          0xE9820000|(N&0xFFFF)   direct TOC-relative
        #   mtctr r12                0x7D8903A6
        #   bctr                     0x4E800420
        #
        # 5-word form (large binary, GOT offset needs addis+ld pair, >32KB from TOC):
        #   std  r2, 0x18(r1)        0xF8410018
        #   addis r12, r2, HI        0x3D820000|(HI&0xFFFF)
        #   ld   r12, LO(r12)        0xE98C0000|(LO&0xFFFF)
        #   mtctr r12                0x7D8903A6
        #   bctr                     0x4E800420
        #   GOT slot VA = r2 + sign_extend_16(HI)<<16 + sign_extend_16(LO)
        _STD   = 0xF8410018
        _MTCTR = 0x7D8903A6
        _BCTR  = 0x4E800420

        for sec_name in ('.text', '.init'):
            try:
                sec = binary.get_section(sec_name)
            except Exception:
                sec = None
            if not sec:
                continue
            sec_bytes = bytes(sec.content)
            sec_va = int(sec.virtual_address)
            for off in range(0, len(sec_bytes) - 15, 4):
                w0 = struct.unpack_from('<I', sec_bytes, off)[0]
                if w0 != _STD:
                    continue
                w1 = struct.unpack_from('<I', sec_bytes, off + 4)[0]
                w2 = struct.unpack_from('<I', sec_bytes, off + 8)[0]
                w3 = struct.unpack_from('<I', sec_bytes, off + 12)[0]
                # 4-word: std; ld r12,N(r2); mtctr; bctr
                if (w1 & 0xFFFF0000) == 0xE9820000 and w2 == _MTCTR and w3 == _BCTR:
                    n = w1 & 0xFFFF
                    if n & 0x8000:
                        n -= 0x10000
                    sym = got_to_sym.get(r2 + n)
                    if sym:
                        self.plt[sec_va + off] = sym
                # 5-word: std; addis r12,r2,HI; ld r12,LO(r12); mtctr; bctr
                elif (off + 19 < len(sec_bytes) and
                      (w1 & 0xFFFF0000) == 0x3D820000 and
                      (w2 & 0xFFFF0000) == 0xE98C0000 and
                      w3 == _MTCTR):
                    w4 = struct.unpack_from('<I', sec_bytes, off + 16)[0]
                    if w4 == _BCTR:
                        hi = w1 & 0xFFFF
                        lo = w2 & 0xFFFF
                        if hi & 0x8000:
                            hi -= 0x10000
                        if lo & 0x8000:
                            lo -= 0x10000
                        sym = got_to_sym.get(r2 + (hi << 16) + lo)
                        if sym:
                            self.plt[sec_va + off] = sym

        # .glink lazy PLT fallback (ELFv2-GLINK-001): for binaries using lazy binding
        # (not -z now / BIND_NOW), stubs are 4-byte 'b glink_resolver' branches inside
        # .glink rather than the 4-word std r2/ld r12/mtctr/bctr pattern in .text.
        # PLT0 (the lazy resolver) occupies the first 64 bytes of .glink (ELFv2 fixed);
        # stubs follow in .rela.plt file order, 4 bytes each.
        if not self.plt and rela_plt_ordered:
            try:
                glink = binary.get_section('.glink')
                if glink:
                    glink_va = int(glink.virtual_address)
                    glink_size = int(glink.size)
                    PLT0_SIZE = 0x40  # ELFv2: PLT0 resolver padded to 64-byte alignment
                    for i, sym_name in enumerate(rela_plt_ordered):
                        if not sym_name:
                            continue
                        stub_va = glink_va + PLT0_SIZE + i * 4
                        if stub_va + 4 > glink_va + glink_size:
                            break
                        self.plt[stub_va] = sym_name
            except Exception:
                pass

    def _extract_plt_ppc64be(self, binary) -> None:
        # PPC64 BE ELFv1: PLT calls use inline 7-instruction call stubs in .text.
        # Each stub loads the PLT function descriptor via TOC-relative addressing:
        #
        #   addis r12, r2, HI    3D 82 xx xx  (opcode=15, RT=12, RA=2)
        #   std   r2, N(r1)      F8 41 xx xx  (save caller TOC)
        #   ld    r11, LO(r12)   E9 6C xx xx  (load entry_point from PLT descriptor)
        #   ld    r2, LO+8(r12)  E8 4C xx xx  (load callee TOC from PLT descriptor)
        #   mtctr r11             7D 69 03 A6
        #   ld    r11, LO+16(r12) E9 6C xx xx  (load env ptr; same upper-16 as w2)
        #   bctr                  4E 80 04 20
        #
        # PLT descriptor VA = r2 + (sign_extend(HI) << 16) + sign_extend(LO)
        # .rela.plt entries give us: descriptor_VA -> symbol_name

        got_to_sym: Dict[int, str] = {}
        try:
            rela_plt = binary.get_section('.rela.plt')
            if rela_plt:
                rela_data = bytes(rela_plt.content)
                for off in range(0, len(rela_data) - 23, 24):
                    r_offset, r_info = struct.unpack_from('>QQ', rela_data, off)
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
            return

        # Read TOC (r2) from .opd[0] — second 8-byte word of first function descriptor.
        r2: Optional[int] = None
        try:
            opd = binary.get_section('.opd')
            if opd and len(bytes(opd.content)) >= 16:
                r2 = struct.unpack_from('>Q', bytes(opd.content), 8)[0]
        except Exception:
            pass

        if r2 is None:
            return

        # Scan .text for the 7-word stub pattern.
        try:
            text = binary.get_section('.text')
            if not text:
                return
            text_data = bytes(text.content)
            text_va = int(text.virtual_address)
        except Exception:
            return

        for off in range(0, len(text_data) - 23, 4):
            w0 = struct.unpack_from('>I', text_data, off)[0]

            # ── 7-instruction stub: addis r12,r2,HI + std r2,N(r1) + ld r11,LO(r12) + … ──
            # Used when GOT offset from r2 does not fit in 16 bits.
            if (w0 & 0xFFFF0000) == 0x3D820000 and len(text_data) - off >= 28:
                w1 = struct.unpack_from('>I', text_data, off + 4)[0]
                if (w1 & 0xFFFF0000) == 0xF8410000:   # std r2, N(r1)
                    w2 = struct.unpack_from('>I', text_data, off + 8)[0]
                    if (w2 & 0xFFFF0000) == 0xE96C0000:  # ld r11, LO(r12)
                        w3 = struct.unpack_from('>I', text_data, off + 12)[0]
                        if (w3 & 0xFFFF0000) == 0xE84C0000:  # ld r2, LO+8(r12)
                            w4 = struct.unpack_from('>I', text_data, off + 16)[0]
                            if w4 == 0x7D6903A6:  # mtctr r11
                                w5 = struct.unpack_from('>I', text_data, off + 20)[0]
                                if (w5 & 0xFFFF0000) == 0xE96C0000:  # ld r11, LO+16(r12)
                                    w6 = struct.unpack_from('>I', text_data, off + 24)[0]
                                    if w6 == 0x4E800420:  # bctr
                                        hi = w0 & 0xFFFF
                                        lo = w2 & 0xFFFF
                                        if hi & 0x8000:
                                            hi -= 0x10000
                                        if lo & 0x8000:
                                            lo -= 0x10000
                                        desc_va = r2 + (hi << 16) + lo
                                        sym = got_to_sym.get(desc_va)
                                        if sym:
                                            self.plt[text_va + off] = sym
                                        continue

            # ── 6 / 5-instruction stubs: std r2,N(r1) prefix ──
            # Both forms start with std r2,N(r1) (0xF841xxxx), then differ by the target
            # register of the ld instruction that follows:
            #   r11 → 6-instruction form (0xE962):
            #     std r2,N(r1); ld r11,LO(r2); mtctr r11; ld r11,LO+16(r2); ld r2,LO+8(r2); bctr
            #   r12 → 5-instruction form (0xE982):
            #     std r2,N(r1); ld r12,LO(r2); mtctr r12; ld r2,LO+8(r2); bctr
            # Both: desc_va = r2 + sign_extend16(LO). Used when GOT offset fits in ±32KB.
            if (w0 & 0xFFFF0000) != 0xF8410000:   # std r2, N(r1)
                continue
            if len(text_data) - off < 20:
                continue
            w1 = struct.unpack_from('>I', text_data, off + 4)[0]
            w1_upper = w1 & 0xFFFF0000

            if w1_upper == 0xE9620000:             # ld r11, LO(r2)  → 6-instruction form
                if len(text_data) - off < 24:
                    continue
                w2 = struct.unpack_from('>I', text_data, off + 8)[0]
                if w2 != 0x7D6903A6:               # mtctr r11
                    continue
                w3 = struct.unpack_from('>I', text_data, off + 12)[0]
                if (w3 & 0xFFFF0000) != 0xE9620000:  # ld r11, LO+16(r2)
                    continue
                w4 = struct.unpack_from('>I', text_data, off + 16)[0]
                if (w4 & 0xFFFF0000) != 0xE8420000:  # ld r2, LO+8(r2)
                    continue
                w5 = struct.unpack_from('>I', text_data, off + 20)[0]
                if w5 != 0x4E800420:               # bctr
                    continue
            elif w1_upper == 0xE9820000:           # ld r12, LO(r2)  → 5-instruction form
                w2 = struct.unpack_from('>I', text_data, off + 8)[0]
                if w2 != 0x7D8903A6:               # mtctr r12
                    continue
                w3 = struct.unpack_from('>I', text_data, off + 12)[0]
                if (w3 & 0xFFFF0000) != 0xE8420000:  # ld r2, LO+8(r2)
                    continue
                w4 = struct.unpack_from('>I', text_data, off + 16)[0]
                if w4 != 0x4E800420:               # bctr
                    continue
            else:
                continue

            # GOT descriptor VA: r2 + sign_extend16(LO from first ld instruction)
            lo_s = w1 & 0xFFFF
            if lo_s & 0x8000:
                lo_s -= 0x10000
            desc_va = (r2 + lo_s) & 0xFFFFFFFFFFFFFFFF
            sym = got_to_sym.get(desc_va)
            if sym:
                self.plt[text_va + off] = sym

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
                                    # ELF32 (ppc32, x86_32): pyelftools computes pcrel
                                    # in full Python int arithmetic and can produce values
                                    # like 0x1000497c0 (correct 32-bit VA + 0x100000000)
                                    # for ppc32 BE binaries. Clamp to 32-bit address space.
                                    if self.arch in ('ppc32', 'x86_32'):
                                        va &= 0xFFFFFFFF
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
        # PPC64/PPC32: scan code segment for MFLR r0 function prologues.
        # Every non-leaf function opens with MFLR r0 to save the link register before calling out.
        # Runs as primary fallback (no starts) OR supplementary when starts<100 for ppc64le
        # binaries that use IBM .except instead of standard DWARF EH (IPA, large XLC binaries).
        if self.arch in ('ppc64', 'ppc32') and path and (not starts or len(starts) < 100):
            try:
                import struct
                with open(path, 'rb') as fh:
                    raw = fh.read()
                # EI_DATA at offset 5: 1=ELFDATA2LSB (LE), 2=ELFDATA2MSB (BE)
                _elf_le = len(raw) > 5 and raw[5] == 1
                _fmt = '<' if _elf_le else '>'
                # mflr r0 = 0x7C0802A6; stored LE as a6 02 08 7c, BE as 7c 08 02 a6
                MFLR_R0 = b'\xa6\x02\x08\x7c' if _elf_le else b'\x7c\x08\x02\xa6'
                # EI_CLASS at offset 4: 1=ELF32, 2=ELF64 — struct layouts differ completely
                _elf32 = len(raw) > 4 and raw[4] == 1
                if _elf32:
                    # ELF32 Ehdr: e_phoff(4B)@0x1C, e_phentsize(2B)@0x2A, e_phnum(2B)@0x2C
                    e_phoff = struct.unpack_from(_fmt + 'I', raw, 0x1C)[0]
                    e_phentsize = struct.unpack_from(_fmt + 'H', raw, 0x2A)[0]
                    e_phnum = struct.unpack_from(_fmt + 'H', raw, 0x2C)[0]
                else:
                    # ELF64 Ehdr: e_phoff(8B)@0x20, e_phentsize(2B)@0x36, e_phnum(2B)@0x38
                    e_phoff = struct.unpack_from(_fmt + 'Q', raw, 0x20)[0]
                    e_phentsize = struct.unpack_from(_fmt + 'H', raw, 0x36)[0]
                    e_phnum = struct.unpack_from(_fmt + 'H', raw, 0x38)[0]
                for i in range(e_phnum):
                    ph_off = e_phoff + i * e_phentsize
                    p_type = struct.unpack_from(_fmt + 'I', raw, ph_off)[0]
                    if _elf32:
                        # ELF32 Phdr layout: type(4) offset(4) vaddr(4) paddr(4)
                        #                    filesz(4) memsz(4) flags(4) align(4)
                        p_offset = struct.unpack_from(_fmt + 'I', raw, ph_off + 0x04)[0]
                        p_vaddr  = struct.unpack_from(_fmt + 'I', raw, ph_off + 0x08)[0]
                        p_filesz = struct.unpack_from(_fmt + 'I', raw, ph_off + 0x10)[0]
                        p_flags  = struct.unpack_from(_fmt + 'I', raw, ph_off + 0x18)[0]
                    else:
                        # ELF64 Phdr layout: type(4) flags(4) offset(8) vaddr(8)
                        #                    paddr(8) filesz(8) memsz(8) align(8)
                        p_flags  = struct.unpack_from(_fmt + 'I', raw, ph_off + 0x04)[0]
                        p_offset = struct.unpack_from(_fmt + 'Q', raw, ph_off + 0x08)[0]
                        p_vaddr  = struct.unpack_from(_fmt + 'Q', raw, ph_off + 0x10)[0]
                        p_filesz = struct.unpack_from(_fmt + 'Q', raw, ph_off + 0x20)[0]
                    PT_LOAD = 1
                    PF_X = 0x1
                    if p_type == PT_LOAD and (p_flags & PF_X) and p_filesz > 0:
                        seg = raw[p_offset: p_offset + p_filesz]
                        pos = 0
                        while True:
                            idx = seg.find(MFLR_R0, pos)
                            if idx < 0:
                                break
                            if idx % 4 == 0:
                                starts.add(p_vaddr + idx)
                            pos = idx + 4
            except Exception:
                pass
        # x86_32: strip PLT stub VAs from func_starts before the threshold check.
        # On i386 binaries built with -fasynchronous-unwind-tables, EH frame entries
        # include PLT stubs, which causes all .text call sites to be attributed to
        # the last PLT stub (the highest VA below any .text address). Removing PLT
        # VAs lets StaticELF32FuncStartScanner trigger normally. (X86-32-PLT-FUNCSTART)
        if self.arch == 'x86_32' and _LIEF_OK and binary:
            try:
                plt_sec = binary.get_section('.plt')
                if plt_sec:
                    plt_va  = int(plt_sec.virtual_address)
                    plt_end = plt_va + int(plt_sec.size)
                    starts  = {va for va in starts if not (plt_va <= va < plt_end)}
            except Exception:
                pass
        # x86_32: scan for i386 function prologues (push ebp; mov ebp, esp) and,
        # as a fallback for -fomit-frame-pointer binaries, call-target analysis.
        # Runs when eh_frame+exports produce fewer than 50 starts, matching the
        # ppc32/ppc64 threshold above (where < 100 triggers the MFLR scan).
        if self.arch == 'x86_32' and path and (not starts or len(starts) < 50):
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
        arm64:  scan .text for BL words (byte[3]∈{0x94..0x97}); target = site+sign_ext26*4.
        ppc32/ppc64: scan .text for BL words (opcode=18,AA=0,LK=1); target = site+sign_ext26.
        mips32/mips64: scan .text for JAL words (opcode==3); target=(DS_addr&0xF0000000)|imm26<<2.
        Falls back to sequential capstone if NumPy is unavailable.
        """
        if self.arch in ('ppc32', 'ppc64'):
            if _NUMPY_OK:
                self._build_call_graph_ppc(data, binary)
            return

        if self.arch in ('mips32', 'mips64'):
            if _NUMPY_OK:
                self._build_call_graph_mips(data, binary)
            return

        if self.arch == 'arm32':
            if _NUMPY_OK:
                self._build_call_graph_arm32(data, binary)
            else:
                self._build_call_graph_sequential(data, binary)
            return

        if self.arch == 'arm64':
            if _NUMPY_OK:
                self._build_call_graph_arm64(data, binary)
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

    def _build_call_graph_ppc(self, data: bytes, binary) -> None:
        """PPC32 BE / PPC64le call graph via numpy BL scan.

        BL encoding (both BE and LE): bits[31:26]=18, AA=0 (bit1), LK=1 (bit0).
        For ppc32 BE: words stored big-endian; use byteswap to decode.
        For ppc64le: words stored little-endian; '<u4' decodes directly.
        Target: insn_va + sign_extend_26(word & 0x03FFFFFC)
        """
        text_sec = binary.get_section(".text")
        if not text_sec:
            return
        sec_data = bytes(text_sec.content)
        sec_va = int(text_sec.virtual_address)
        N = len(sec_data)
        if N < 4:
            return

        word_count = N // 4
        if self.arch == 'ppc32':
            # Big-endian: each 4-byte chunk read as big-endian uint32
            words = np.frombuffer(sec_data[:word_count * 4], dtype=np.dtype('>u4')).astype(np.uint32)
        elif self.arch == 'ppc64':
            # ppc64 BE (ELFv1) stores words big-endian; ppc64le (ELFv2) stores little-endian.
            # Detect from the ELF header (byte 5: 1=LE, 2=BE).
            _ppc64_be = (hasattr(binary, 'header') and
                         getattr(binary.header, 'identity', None) is not None and
                         len(binary.header.identity) > 5 and
                         binary.header.identity[5] == 2)
            if _ppc64_be:
                words = np.frombuffer(sec_data[:word_count * 4], dtype=np.dtype('>u4')).astype(np.uint32)
            else:
                words = np.frombuffer(sec_data[:word_count * 4], dtype=np.dtype('<u4'))
        else:
            words = np.frombuffer(sec_data[:word_count * 4], dtype=np.dtype('<u4'))

        # ppc64le far-call stub detection (XLC-GAP-007).
        # The linker emits far-call stubs for calls whose TOC offset exceeds 16-bit range.
        # These stubs don't start with mflr so they're absent from func_starts, but BL
        # instructions target them. Two patterns — detect both, add their VAs to the
        # valid-target set so those BL edges aren't silently dropped.
        stub_vas: List[int] = []
        if self.arch == 'ppc64' and word_count >= 4:
            MTCTR_R12 = np.uint32(0x7D8903A6)
            BCTR      = np.uint32(0x4E800420)
            mtctr_pos = np.where(words == MTCTR_R12)[0]
            # Keep only mtctr positions where bctr follows immediately
            valid_bctr = (mtctr_pos + 1 < word_count) & (words[mtctr_pos + 1] == BCTR)
            bp = mtctr_pos[valid_bctr]  # bctr_pairs: indices where mtctr,bctr appear

            # Pattern A: addis r12,r2,HI | ld r12,LO(r12) | mtctr r12 | bctr
            #   addis r12,r2: opcode=15, RT=r12, RA=r2 → upper16=0x3D82
            #   ld r12,X(r12): opcode=58, RT=r12, RA=r12 → upper16=0xE98C
            a_sel = (bp >= 2) & \
                    ((words[bp - 2] & np.uint32(0xFFFF0000)) == np.uint32(0x3D820000)) & \
                    ((words[bp - 1] & np.uint32(0xFFFF0000)) == np.uint32(0xE98C0000))
            stub_a = bp[a_sel] - 2  # stub starts at addis instruction

            # Pattern B: addi r2,r2,X | addis r2,r2,X | ld r12,Y(r2) | addi/addic r3,r3,X | mtctr | bctr
            # C++ vtable thunks that also restore the caller's TOC and adjust `this` (r3).
            #   addi r2,r2: opcode=14, RT=r2, RA=r2 → upper16=0x3842
            #   addis r2,r2: opcode=15, RT=r2, RA=r2 → upper16=0x3C42
            #   ld r12,X(r2): opcode=58, RT=r12, RA=r2 → upper16=0xE982
            #   addi/addic r3,r3: upper16 in {0x3863, 0x3063}
            b_mask_addi_r3 = (
                ((words[np.maximum(bp - 1, 0)] & np.uint32(0xFFFF0000)) == np.uint32(0x38630000)) |
                ((words[np.maximum(bp - 1, 0)] & np.uint32(0xFFFF0000)) == np.uint32(0x30630000))
            )
            b_sel = (bp >= 4) & \
                    ((words[bp - 4] & np.uint32(0xFFFF0000)) == np.uint32(0x38420000)) & \
                    ((words[bp - 3] & np.uint32(0xFFFF0000)) == np.uint32(0x3C420000)) & \
                    ((words[bp - 2] & np.uint32(0xFFFF0000)) == np.uint32(0xE9820000)) & \
                    b_mask_addi_r3
            stub_b = bp[b_sel] - 4  # stub starts at addi r2 instruction

            # Collect all stub start VAs (deduplicated, sorted)
            if len(stub_a) or len(stub_b):
                all_stubs = np.unique(np.concatenate([stub_a, stub_b]) if len(stub_a) and len(stub_b)
                                      else (stub_a if len(stub_a) else stub_b))
                stub_vas = (_va_to_i64(sec_va) + all_stubs.astype(np.int64)).tolist()

        # BL: opcode=18 (bits 31:26), AA=0 (bit 1), LK=1 (bit 0)
        bl_idx = np.where(((words >> 26) == 18) & ((words & 3) == 1))[0]
        if len(bl_idx) == 0:
            self.call_edges = []
            return

        insn_vas = _va_to_i64(sec_va) + bl_idx.astype(np.int64) * 4

        # Extract 26-bit signed branch offset: bits [25:2] of instruction word
        # Sign-extend from bit 25: shift to bit 31 then arithmetic-right-shift back
        raw26 = (words[bl_idx] & np.uint32(0x03FFFFFC)).astype(np.int32)
        signed_offset = (raw26 << 6) >> 6

        target_vas = insn_vas + signed_offset.astype(np.int64)

        plt_arr  = _va_arr_to_i64(sorted(self.plt.keys())) if self.plt         else np.empty(0, np.int64)
        func_arr = _va_arr_to_i64(self.func_starts)         if self.func_starts else np.empty(0, np.int64)
        stub_arr = np.array(sorted(stub_vas), dtype=np.int64) if stub_vas else np.empty(0, np.int64)

        valid = np.zeros(len(target_vas), dtype=bool)
        if len(plt_arr):
            hi = np.searchsorted(plt_arr, target_vas)
            hi = np.minimum(hi, len(plt_arr) - 1)
            valid |= plt_arr[hi] == target_vas
        if len(func_arr):
            hi = np.searchsorted(func_arr, target_vas)
            hi = np.minimum(hi, len(func_arr) - 1)
            valid |= func_arr[hi] == target_vas
        if len(stub_arr):
            hi = np.searchsorted(stub_arr, target_vas)
            hi = np.minimum(hi, len(stub_arr) - 1)
            valid |= stub_arr[hi] == target_vas

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

    def _build_call_graph_arm64(self, data: bytes, binary) -> None:
        """AArch64 call graph via vectorized BL scan.

        BL encoding (AArch64, little-endian):
          bits 31:26 = 100101; byte[3] of 4-byte LE word ∈ {0x94, 0x95, 0x96, 0x97}.
          imm26 = word[25:0]; target = insn_va + sign_extend(imm26, 26) * 4.
          No pipeline PC adjustment (ARM32 uses +8; ARM64 does not).
        All instructions are 4-byte aligned — word boundaries only.
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
        # MSByte of each 4-byte-aligned word (index 3, 7, 11, ...)
        msb = buf[3: word_count * 4: 4]
        # BL top 6 bits = 100101 → byte[3] ∈ {0x94, 0x95, 0x96, 0x97}
        bl_word_idx = np.where(
            (msb == 0x94) | (msb == 0x95) | (msb == 0x96) | (msb == 0x97)
        )[0]
        if len(bl_word_idx) == 0:
            self.call_edges = []
            return

        byte_off = bl_word_idx * 4
        b0 = buf[byte_off    ].astype(np.uint32)
        b1 = buf[byte_off + 1].astype(np.uint32)
        b2 = buf[byte_off + 2].astype(np.uint32)
        words = b0 | (b1 << 8) | (b2 << 16) | (msb[bl_word_idx].astype(np.uint32) << 24)

        imm26 = words & np.uint32(0x3FFFFFF)
        # Sign-extend 26-bit to 32-bit signed
        sign_bit = np.uint32(0x2000000)
        fill = np.uint32(0xFC000000)
        imm_i32 = np.where(
            imm26 & sign_bit,
            (imm26 | fill).view(np.int32),
            imm26.astype(np.int32),
        )

        insn_vas = _va_to_i64(sec_va) + byte_off.astype(np.int64)
        # ARM64: target = insn_va + imm26_signed * 4 (no +8 pipeline adjustment)
        target_vas = insn_vas + imm_i32.astype(np.int64) * 4

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

        self.call_edges = edges

    def _build_call_graph_mips(self, data: bytes, binary) -> None:
        """MIPS32/64 call graph via JAL and LW-$t9/$gp + JALR-$t9 vectorized scan.

        Two calling conventions:

        1. JAL (opcode=3, bits 31:26): non-PIC direct call.
           target = (DS_PC & 0xF0000000) | (imm26 << 2).

        2. LW $t9, N($gp) + JALR $t9 (O32 ABI PIC, standard for ET_EXEC firmware):
           Encoding: bits 31:16 = 0x8F99 (BE) — opcode=LW, rs=$gp(28), rt=$t9(25).
           imm16 = signed offset from $gp; GOT entry at ($gp + imm16) holds callee VA.
           $gp fixed for ET_EXEC binaries; read from .reginfo offset 20.

        ELF identity byte 5 == 2 → big-endian (standard for MIPS32 firmware).

        Gap: MIPS-GAP-001. Prior implementation was JAL-only; ET_EXEC O32 PIC binaries
        use exclusively LW+JALR (0 JAL instructions), yielding 0 call edges.
        """
        text_sec = binary.get_section(".text")
        if not text_sec:
            return
        sec_data = bytes(text_sec.content)
        sec_va   = int(text_sec.virtual_address)
        N = len(sec_data)
        if N < 4:
            return

        big_endian = data[5] == 2 if len(data) > 5 else True
        buf        = np.frombuffer(sec_data, dtype=np.uint8)
        word_count = N // 4
        idx4       = np.arange(word_count, dtype=np.int64) * 4

        if big_endian:
            words = (buf[idx4    ].astype(np.uint32) << 24
                   | buf[idx4 + 1].astype(np.uint32) << 16
                   | buf[idx4 + 2].astype(np.uint32) << 8
                   | buf[idx4 + 3].astype(np.uint32))
        else:
            words = (buf[idx4    ].astype(np.uint32)
                   | buf[idx4 + 1].astype(np.uint32) << 8
                   | buf[idx4 + 2].astype(np.uint32) << 16
                   | buf[idx4 + 3].astype(np.uint32) << 24)

        plt_arr      = _va_arr_to_i64(sorted(self.plt.keys())) if self.plt         else np.empty(0, np.int64)
        func_arr     = _va_arr_to_i64(self.func_starts)         if self.func_starts else np.empty(0, np.int64)
        va_to_export: Dict[int, str] = {va: nm for nm, va in self.exports.items()}
        edges: List[Tuple[int, int, str]] = []

        def _valid_targets(tgt: np.ndarray) -> np.ndarray:
            mask = np.zeros(len(tgt), dtype=bool)
            if len(plt_arr):
                hi = np.minimum(np.searchsorted(plt_arr, tgt), len(plt_arr) - 1)
                mask |= plt_arr[hi] == tgt
            if len(func_arr):
                hi = np.minimum(np.searchsorted(func_arr, tgt), len(func_arr) - 1)
                mask |= func_arr[hi] == tgt
            return mask

        def _attr_edges(insn_v: np.ndarray, tgt_v: np.ndarray) -> None:
            if not len(insn_v):
                return
            if len(func_arr):
                oi = np.maximum(np.searchsorted(func_arr, insn_v, side='right') - 1, 0)
                owners = func_arr[oi]
            else:
                owners = insn_v
            for owner_va, target_va in zip(owners.tolist(), tgt_v.tolist()):
                label = self.plt.get(target_va, "") or va_to_export.get(target_va, "")
                edges.append((int(owner_va), int(target_va), label))

        # --- JAL scan ---
        jal_idx = np.where((words >> 26) == np.uint32(3))[0]
        if len(jal_idx):
            instr_index = words[jal_idx] & np.uint32(0x03FFFFFF)
            insn_v      = _va_to_i64(sec_va) + jal_idx.astype(np.int64) * 4
            ds_addr     = insn_v + np.int64(4)
            tgt_v       = (ds_addr & np.int64(0xF0000000)) | (instr_index.astype(np.int64) << 2)
            valid       = _valid_targets(tgt_v)
            _attr_edges(insn_v[valid], tgt_v[valid])

        # --- LW $t9, N($gp) scan (O32 ABI PIC and MIPS N32 IRIX) ---
        # LW $t9, N($gp): upper halfword bits 31:16 = (opcode=LW<<10)|(rs=$gp<<5)|(rt=$t9)
        # = (0x23<<10)|(0x1C<<5)|0x19 = 0x8C00|0x0380|0x0019 = 0x8F99
        got_sec  = binary.get_section(".got")
        reginfo  = binary.get_section(".reginfo")
        if got_sec and reginfo:
            ri_data = bytes(reginfo.content)
            if len(ri_data) >= 24:
                gp_val = int(struct.unpack_from('>I' if big_endian else '<I', ri_data, 20)[0])
            else:
                gp_val = 0
            if gp_val:
                got_data  = bytes(got_sec.content)
                got_va    = int(got_sec.virtual_address)
                got_count = len(got_data) // 4
                endian_ch = '>' if big_endian else '<'
                got_entries = np.array(
                    struct.unpack(endian_ch + 'I' * got_count, got_data[:got_count * 4]),
                    dtype=np.int64,
                )

                if big_endian:
                    # bytes 0,1 of each 4-byte word hold bits 31:16
                    hi16 = (buf[idx4].astype(np.uint16) << 8
                           | buf[idx4 + 1].astype(np.uint16))
                    raw_imm_u = (buf[idx4 + 2].astype(np.uint16) << 8
                                | buf[idx4 + 3].astype(np.uint16))
                else:
                    # bytes 3,2 hold bits 31:16; bytes 1,0 hold bits 15:0
                    hi16 = (buf[idx4 + 3].astype(np.uint16) << 8
                           | buf[idx4 + 2].astype(np.uint16))
                    raw_imm_u = (buf[idx4 + 1].astype(np.uint16) << 8
                                | buf[idx4    ].astype(np.uint16))

                lw_t9_idx = np.where(hi16 == np.uint16(0x8F99))[0]
                if len(lw_t9_idx):
                    imm_u     = raw_imm_u[lw_t9_idx]
                    # sign-extend uint16 → int64 via int16 view
                    imm16     = imm_u.view(np.int16).astype(np.int64)
                    got_e_vas = np.int64(gp_val) + imm16
                    got_idx_a = (got_e_vas - np.int64(got_va)) // 4
                    in_got    = (got_idx_a >= 0) & (got_idx_a < got_count)

                    if np.any(in_got):
                        sel       = np.where(in_got)[0]
                        tgt_v_lw  = got_entries[got_idx_a[sel]]
                        insn_v_lw = _va_to_i64(sec_va) + lw_t9_idx[sel].astype(np.int64) * 4
                        valid_lw  = _valid_targets(tgt_v_lw)
                        _attr_edges(insn_v_lw[valid_lw], tgt_v_lw[valid_lw])

                        # IRIX MIPS N32 fallback: static GOT holds RLD resolver stubs,
                        # not PLT VAs, so the GOT-value path above misses external calls.
                        # Run this for any LW instruction not matched by GOT value to
                        # cover both IRIX (all external calls missed) and Linux MIPS
                        # (internal-ptr calls found by GOT, external PLT calls missed).
                        if hasattr(binary, 'dynamic_entries'):
                            local_gotno_v = None
                            gotsym_v = None
                            for tag in binary.dynamic_entries:
                                ts = str(tag.tag)
                                if 'LOCAL_GOTNO' in ts:
                                    local_gotno_v = int(tag.value)
                                elif 'GOTSYM' in ts:
                                    gotsym_v = int(tag.value)
                            if local_gotno_v is not None and gotsym_v is not None:
                                plt_name_to_va: Dict[str, int] = {n: va for va, n in self.plt.items()}
                                gp_off_to_plt: Dict[int, int] = {}
                                if hasattr(binary, 'dynamic_symbols'):
                                    for sym_idx, sym in enumerate(binary.dynamic_symbols):
                                        if sym_idx < gotsym_v:
                                            continue
                                        nm = str(sym.name)
                                        plt_va = plt_name_to_va.get(nm)
                                        if plt_va is None:
                                            continue
                                        got_idx_d = local_gotno_v + (sym_idx - gotsym_v)
                                        entry_va = got_va + got_idx_d * 4
                                        gp_off = entry_va - gp_val
                                        if -0x8000 <= gp_off <= 0x7FFF:
                                            gp_off_to_plt[gp_off] = plt_va
                                if gp_off_to_plt:
                                    # Only emit edges for LW instructions not already
                                    # resolved via GOT value (avoid duplicates).
                                    already_resolved = set(zip(
                                        (insn_v_lw[valid_lw]).tolist(),
                                        (tgt_v_lw[valid_lw]).tolist(),
                                    ))
                                    imm16_list = imm16.tolist()
                                    insn_v_arr = _va_to_i64(sec_va) + lw_t9_idx.astype(np.int64) * 4
                                    insn_list  = insn_v_arr.tolist()
                                    for off, insn_va in zip(imm16_list, insn_list):
                                        plt_va = gp_off_to_plt.get(int(off))
                                        if plt_va is None:
                                            continue
                                        if (int(insn_va), plt_va) in already_resolved:
                                            continue
                                        label = self.plt.get(plt_va, "")
                                        if len(func_arr):
                                            oi = max(0, int(np.searchsorted(func_arr, insn_va, side='right')) - 1)
                                            owner = int(func_arr[oi])
                                        else:
                                            owner = int(insn_va)
                                        edges.append((owner, plt_va, label))

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
        elif self.arch == 'arm64':
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            call_mnems = {'bl'}
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

        x86_64: vectorized RIP-relative 32-bit displacement scan.
        arm64:  vectorized ADRP+ADD instruction-pair scan.
        x86_32 (i386): vectorized absolute 4-byte LE immediate scan.
        arm32: capstone LDR [PC, #off] literal pool scan per function.
        """
        if self.arch == 'arm32':
            self._build_string_xref_index_arm32(data, binary)
            return
        if self.arch == 'x86_32':
            self._build_string_xref_index_x86_32()
            return
        if self.arch == 'arm64':
            if _NUMPY_OK:
                self._build_string_xref_index_arm64(data, binary)
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

    def _build_string_xref_index_arm64(self, data: bytes, binary) -> None:
        """AArch64 string xref index via vectorized ADRP+ADD pair scan.

        ARM64 materialises PC-relative addresses as a two-instruction pair:
          ADRP X_d, #page_imm   — byte[3] & 0x9F == 0x90; loads 4KB-aligned page.
          ADD  X_d, X_d, #off12 — byte[3] == 0x91 (64-bit, shift=0); adds page offset.
        Combined: target = (PC & ~0xFFF) + sign_extend(imm21,21)<<12 + imm12.
        Only consecutive (i, i+1) pairs with matching Rd/Rn are matched.
        """
        text_sec = binary.get_section(".text")
        if not text_sec or not self.strings:
            return
        sec_data = bytes(text_sec.content)
        sec_va = int(text_sec.virtual_address)
        N = len(sec_data)
        if N < 8:
            return

        buf = np.frombuffer(sec_data, dtype=np.uint8)
        word_count = N // 4
        msb = buf[3: word_count * 4: 4]

        # ADRP: bits 31:29=100, bits 28:24=10000 → byte[3] & 0x9F == 0x90
        adrp_idx = np.where((msb & np.uint8(0x9F)) == np.uint8(0x90))[0]
        if len(adrp_idx) == 0:
            return

        # Guard: next word must be in bounds
        in_bounds = adrp_idx + 1 < word_count
        adrp_idx = adrp_idx[in_bounds]
        if len(adrp_idx) == 0:
            return

        byte_off = adrp_idx * 4
        b0 = buf[byte_off    ].astype(np.uint32)
        b1 = buf[byte_off + 1].astype(np.uint32)
        b2 = buf[byte_off + 2].astype(np.uint32)
        b3 = msb[adrp_idx].astype(np.uint32)
        words_adrp = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

        # Decode ADRP fields
        rd_adrp = words_adrp & np.uint32(0x1F)
        immlo   = (words_adrp >> 29) & np.uint32(0x3)
        immhi   = (words_adrp >> 5)  & np.uint32(0x7FFFF)
        imm21   = (immhi << 2) | immlo
        # Sign-extend 21-bit → int32
        sign21 = np.uint32(0x100000)
        fill21 = np.uint32(0xFFE00000)
        imm21_i32 = np.where(
            imm21 & sign21,
            (imm21 | fill21).view(np.int32),
            imm21.astype(np.int32),
        )

        insn_vas = _va_to_i64(sec_va) + byte_off.astype(np.int64)
        # page_base = (insn_va >> 12 + imm21_signed) << 12
        page_num  = (insn_vas >> 12) + imm21_i32.astype(np.int64)
        page_base = page_num << 12

        # Decode next instruction (potential ADD)
        nxt_byte_off = (adrp_idx + 1) * 4
        nb0 = buf[nxt_byte_off    ].astype(np.uint32)
        nb1 = buf[nxt_byte_off + 1].astype(np.uint32)
        nb2 = buf[nxt_byte_off + 2].astype(np.uint32)
        nb3 = buf[nxt_byte_off + 3].astype(np.uint32)
        next_words = nb0 | (nb1 << 8) | (nb2 << 16) | (nb3 << 24)

        # ADD (immediate, 64-bit, shift=0): bits 31:22 = 1001000100 = 0x244
        is_add    = ((next_words >> 22) & np.uint32(0x3FF)) == np.uint32(0x244)
        add_rn    = (next_words >> 5) & np.uint32(0x1F)
        imm12     = (next_words >> 10) & np.uint32(0xFFF)
        reg_match = add_rn == rd_adrp

        valid = is_add & reg_match
        if not np.any(valid):
            return

        target_vas   = page_base[valid] + imm12[valid].astype(np.int64)
        insn_vas_hit = insn_vas[valid]

        str_va_arr = _va_arr_to_i64(sorted(self.strings.keys()))
        hits    = np.searchsorted(str_va_arr, target_vas)
        clipped = np.minimum(hits, len(str_va_arr) - 1)
        str_valid = str_va_arr[clipped] == target_vas

        str_xref: Dict[int, List[int]] = {}
        func_str: Dict[int, List[int]] = {}
        for code_va, sva in zip(insn_vas_hit[str_valid].tolist(),
                                target_vas[str_valid].tolist()):
            code_va = int(code_va)
            sva     = int(sva)
            fva     = self.func_containing(code_va)
            if fva is None:
                continue
            str_xref.setdefault(sva, []).append(code_va)
            func_str.setdefault(fva, []).append(sva)

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

        r2 is read from the entry-point .opd descriptor (ELF e_entry in data seg).
        Statically-linked binaries embed multiple modules (e.g. game engine + Demonware
        BD SDK), each with its own TOC.  All distinct TOC values are discovered by
        counting toc_ptr frequency across every OPD entry in the data segment; the top
        candidates (min 10 OPD entries, max 4 values) are used so all modules' string
        xrefs are found — not just the entry-point module's.
        """
        if not _NUMPY_OK or not self.strings or not self.func_starts:
            return
        import struct
        from collections import defaultdict, Counter

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

        # Discover primary r2 (TOC pointer) from entry-point .opd descriptor.
        # PS3 Cell uses 32-bit EA mode: each descriptor = [4B code_ptr][4B toc_ptr].
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
        self._r2 = r2  # primary r2; backward compat for callers

        # Discover all distinct TOC values by counting toc_ptr frequency across
        # every 8-byte OPD entry in the data segment.  Statically-linked binaries
        # embed multiple modules (e.g. game engine + Demonware BD SDK) each with
        # its own r2; the entry-point r2 alone misses all other modules' xrefs.
        _toc_freq: Counter = Counter()
        for _i in range(0, ds_fsz - 7, 8):
            try:
                _cp = struct.unpack_from('>I', ds_data, _i)[0]
                _tc = struct.unpack_from('>I', ds_data, _i + 4)[0]
            except Exception:
                break
            if code_va <= _cp < code_va + code_fsz and ds_va <= _tc < ds_va + ds_fsz:
                _toc_freq[_tc] += 1

        _MIN_OPD = 10   # ignore TOC values with fewer OPD entries (noise threshold)
        _MAX_R2  = 4    # cap to avoid pathological binaries
        all_r2: List[int] = [r2]
        for _tv, _cnt in _toc_freq.most_common(_MAX_R2 + 1):
            if _tv == r2 or _cnt < _MIN_OPD:
                continue
            if len(all_r2) >= _MAX_R2:
                break
            all_r2.append(_tv)
        self._r2_all = all_r2  # all discovered TOC values; used by augment passes

        # Scan data segment for 4-byte values that are known string VAs.
        # Accumulate ha16/near maps across ALL r2 values so every module's
        # TOC-relative string references are captured in a single code scan.
        #   ha16_map[ha16] -> [(lo16, string_va)]   for ADDIS rD, r2, ha16 + LWZ rD, lo16(rD)
        #   near_map[lo16] -> [string_va]            for direct LWZ rD, N(r2) when |N|<32768
        str_vas = set(self.strings.keys())
        ha16_map: Dict[int, list] = defaultdict(list)
        near_map: Dict[int, list] = defaultdict(list)

        for r2_i in all_r2:
            for i in range(0, len(ds_data) - 3, 4):
                val = struct.unpack_from('>I', ds_data, i)[0]
                if val not in str_vas:
                    continue
                toc_va_i   = ds_va + i
                toc_offset = toc_va_i - r2_i        # signed Python int
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
        all_r2   = getattr(self, '_r2_all', None) or ([getattr(self, '_r2', 0)] if getattr(self, '_r2', 0) else [])
        if not all_r2:
            return

        # Step 1 — detect string-pointer arrays (r2-independent)
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

        # Steps 2-4 run once per r2 value so arrays near each module's TOC are found.
        for r2 in all_r2:
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

        all_r2 = getattr(self, '_r2_all', None) or ([getattr(self, '_r2', 0)] if getattr(self, '_r2', 0) else [])
        if not all_r2:
            return

        # Target segment: where the string arrays live (default: data seg).
        tgt_data = target_data if target_data is not None else ds_data
        tgt_va   = target_va   if target_va   is not None else ds_va
        tgt_end  = tgt_va + len(tgt_data)

        str_vas = set(self.strings.keys())
        buf = code_data
        M   = len(buf)

        for r2 in all_r2:
            near_lo = r2 - 0x8000
            near_hi = r2 + 0x7FFF

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
                continue

            # Step 2: single linear pass — LWZ rX, off(r2) matching array-base TOC keys
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

    # ── XCOFF support ─────────────────────────────────────────────────────────

    @classmethod
    def _build_xcoff(cls, data: bytes, path: str, sha: str) -> "BinaryContext":
        """Build BinaryContext from an XCOFF32 or XCOFF64 binary (IBM AIX PowerPC).

        Uses xcoff_parser to extract sections and loader-section symbols, then
        runs a BL scan on .text to discover function starts and call edges.
        XCOFF imports have no resolved VA (link-time patching), so ctx.plt is
        intentionally left empty; import names appear only in ctx.summary().
        """
        import bisect
        from ablation.core.xcoff_parser import parse as xcoff_parse

        ctx = cls()
        ctx.path = path
        ctx.sha256 = sha
        try:
            xb = xcoff_parse(path, data)
        except Exception:
            return ctx

        ctx.arch = xb.arch
        ctx.base_va = 0

        # Exports: code_va (descriptor-resolved) preferred; fall back to descriptor VA.
        # Kernel extension exports that are zero-filled (patched by kload at runtime)
        # end up with code_va=0 and va>0; we use the descriptor VA as the best proxy.
        # Symbol-table exports (.o files) use va=code_va=0 for the first function — accept
        # va=0 for non-imports (imports have lib set; exports have lib='').
        for sym in xb.exports:
            if not sym.name:
                continue
            va = sym.code_va if sym.code_va else sym.va
            # Accept VA=0 only for non-imports (symbol-table exports in .o files)
            if va or not sym.lib:
                ctx.exports[sym.name] = va

        # Strings from .data (XCOFF has no .rodata; constants live in .data)
        dsec = xb.data
        if dsec is not None and dsec.data:
            _extract_strings_into(dsec.data, dsec.vaddr, ctx.strings)

        # func_starts: export VAs + BL-target scan on .text
        starts: Set[int] = set(ctx.exports.values())
        tsec = xb.text
        if tsec is not None and tsec.data:
            text_data = tsec.data
            text_va   = tsec.vaddr
            n_words   = len(text_data) // 4
            for i in range(n_words):
                word = struct.unpack_from('>I', text_data, i * 4)[0]
                if (word & 0xFC000003) != 0x48000001:   # BL AA=0 LK=1
                    continue
                pc     = text_va + i * 4
                li24   = (word >> 2) & 0xFFFFFF
                disp26 = li24 << 2
                if disp26 & 0x2000000:
                    disp26 -= 0x4000000
                target = pc + disp26
                if tsec.contains_va(target):
                    starts.add(target)

        ctx.func_starts = sorted(starts)
        func_arr = ctx.func_starts

        # Call graph: second BL pass, now that func_arr is sorted for owner lookup
        va_to_export: Dict[int, str] = {va: nm for nm, va in ctx.exports.items()}
        edges: List[Tuple[int, int, str]] = []
        if tsec is not None and tsec.data:
            text_data = tsec.data
            text_va   = tsec.vaddr
            n_words   = len(text_data) // 4
            for i in range(n_words):
                word = struct.unpack_from('>I', text_data, i * 4)[0]
                if (word & 0xFC000003) != 0x48000001:
                    continue
                pc     = text_va + i * 4
                li24   = (word >> 2) & 0xFFFFFF
                disp26 = li24 << 2
                if disp26 & 0x2000000:
                    disp26 -= 0x4000000
                target = pc + disp26
                label  = va_to_export.get(target, "")
                owner  = pc
                if func_arr:
                    idx = bisect.bisect_right(func_arr, pc) - 1
                    if idx >= 0:
                        owner = func_arr[idx]
                edges.append((owner, target, label))

        ctx.call_edges = edges
        ctx._build_indices()
        return ctx

    # ── m88k BCS COFF support ─────────────────────────────────────────────────

    @classmethod
    def _build_m88k(cls, data: bytes, path: str, sha: str) -> "BinaryContext":
        """Build BinaryContext from an m88k BCS COFF binary (Motorola 88000).

        Uses coff_m88k_parser + M88kDecoder to extract sections, function
        starts (BSR/BSR.N scan → 126 unique entries on moto_gen), and call
        edges.  No symbol table in stripped binaries; exports left empty.
        Capstone has no m88k backend; M88kDecoder is the only Python decoder.
        """
        import bisect
        import tempfile, os
        from ablation.core.coff_m88k_parser import parse as m88k_parse
        from ablation.analyzers.insn_m88k import M88kDecoder

        ctx = cls()
        ctx.path = path
        ctx.sha256 = sha
        try:
            # coff_m88k_parser.parse() takes a path, not raw bytes; write to tmp
            tmp = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.coff') as f:
                    f.write(data)
                    tmp = f.name
                mb = m88k_parse(tmp)
            finally:
                if tmp and os.path.exists(tmp):
                    os.unlink(tmp)
        except Exception:
            return ctx

        ctx.arch = 'm88k'
        ctx.base_va = mb.text_start

        # Strings from .data section
        dsec = mb.data
        if dsec is not None and dsec.data:
            _extract_strings_into(dsec.data, dsec.vaddr, ctx.strings)

        # Function starts: BSR + BSR.N scan via M88kDecoder
        try:
            dec = M88kDecoder(mb)
            func_set = dec.function_starts()
        except Exception:
            func_set = set()
        ctx.func_starts = sorted(func_set)

        # Call graph: re-scan BSR/BSR.N, resolve owner and label
        tsec = mb.text
        if tsec is not None and tsec.data and ctx.func_starts:
            import bisect as _bisect
            func_arr = ctx.func_starts
            va_to_export: Dict[int, str] = {va: nm for nm, va in ctx.exports.items()}
            edges: List[Tuple[int, int, str]] = []
            text_data = tsec.data
            text_va = tsec.vaddr
            n_words = len(text_data) // 4
            for i in range(n_words):
                word = struct.unpack_from('>I', text_data, i * 4)[0]
                op = word >> 26
                if op not in (0x32, 0x33):   # BSR, BSR.N
                    continue
                pc = text_va + i * 4
                off26 = word & 0x3FFFFFF
                if off26 & (1 << 25):
                    off26 -= (1 << 26)
                target = pc + 4 + off26 * 4
                if not tsec.contains_va(target) or (target & 3) != 0:
                    continue
                label = va_to_export.get(target, "")
                owner = pc
                idx = _bisect.bisect_right(func_arr, pc) - 1
                if idx >= 0:
                    owner = func_arr[idx]
                edges.append((owner, target, label))
            ctx.call_edges = edges

        ctx._build_indices()
        return ctx

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
            # LoongArch64 UEFI (EDK2/GCC): function prologues open with
            #   addi.d $sp, $sp, -N  (encoding: 0x02C00063 | (((-N & 0xFFF) << 10)))
            # Patterns for N = 16..128 in 16-byte steps (most common UEFI frame sizes).
            # Extend this list with additional frame sizes as needed.
            'loongarch64': [
                b'\x63\xc0\xff\x02',   # addi.d $sp, $sp, -16
                b'\x63\x80\xff\x02',   # addi.d $sp, $sp, -32
                b'\x63\x40\xff\x02',   # addi.d $sp, $sp, -48
                b'\x63\x00\xff\x02',   # addi.d $sp, $sp, -64
                b'\x63\xc0\xfe\x02',   # addi.d $sp, $sp, -80
                b'\x63\x80\xfe\x02',   # addi.d $sp, $sp, -96
                b'\x63\x40\xfe\x02',   # addi.d $sp, $sp, -112
                b'\x63\x00\xfe\x02',   # addi.d $sp, $sp, -128
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
            # Non-x86 PE (e.g. LA64, arm64): no call graph built yet.
            # Future: wire a BL-opcode scan for loongarch64 / arm64 here.
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
            "cache_version": 3,
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
        if payload.get("cache_version", 1) < 3:
            raise ValueError("stale cache: cache_version < 3; rebuild required")
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
        # Rebuild string xref index if absent (e.g. cache predates arm64 support)
        if not ctx._str_xref_idx and ctx.strings and ctx.func_starts:
            orig = orig_path or ctx.path
            if orig and Path(orig).exists():
                try:
                    import lief as _lief
                    _data = Path(orig).read_bytes()
                    _bin  = _lief.parse(orig)
                    ctx._build_string_xref_index(_data, _bin)
                except Exception:
                    pass
        return ctx
