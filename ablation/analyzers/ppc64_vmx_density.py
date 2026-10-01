"""
ppc64_vmx_density.py — PowerPC64 VMX/AltiVec instruction density scanner.

Identifies functions with high concentrations of VMX (AltiVec) vector instructions.
On Cell PPU (PS3) and IBM POWER targets, math, physics, and renderer code is
heavily vectorized via VMX.  Functions above a density threshold are labeled
"vector_math" without needing any string cross-references, complementing the
string-xref system in BinaryContext.

Architecture: neutral PPC64/PPC32 BE module — works on Cell PPU, POWER5-9, G5.

VMX instructions occupy primary opcode 4 (0b000100).  In big-endian PPC64/PPC32
encoding, byte[0] of any word-aligned VMX instruction is one of {0x10..0x13}:
    primary_opcode = 4 = 0b000100
    byte[0] = (4 << 2) | bits[6:7]  →  0x10 | {0,1,2,3}  →  {0x10, 0x11, 0x12, 0x13}

Usage:
    from ablation.analyzers.ppc64_vmx_density import VMXDensityScanner

    scanner = VMXDensityScanner.from_context(ctx)  # BinaryContext (ppc64)
    results = scanner.scan(threshold=5)
    print(scanner.report(results))

    # High-density functions are candidates for math/physics/render labels
    for r in results:
        if r.density >= 0.15:
            ctx.set_name(r.va, f"vmx_{r.label}_{r.va:x}", source="vmx_density")
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import numpy as np
    _NUMPY_OK = True
except ImportError:
    _NUMPY_OK = False


# Primary opcode 4 encodes all VMX instructions.  Byte[0] range in BE encoding:
_VMX_B0_MIN = 0x10
_VMX_B0_MAX = 0x13

# Threshold labels for display
_DENSITY_LABELS = (
    (0.30, "vector_heavy"),   # ≥30% VMX: pure math kernel (dot product, matrix mul)
    (0.15, "vector_math"),    # ≥15% VMX: physics/render with significant vectorisation
    (0.05, "vector_light"),   # ≥ 5% VMX: some SIMD usage
    (0.00, "vector_trace"),   # any VMX instructions detected
)


@dataclass
class VMXFunctionResult:
    """VMX density analysis for a single function."""

    va: int
    total_insns: int
    vmx_count: int
    density: float          # vmx_count / total_insns

    @property
    def label(self) -> str:
        for threshold, lbl in _DENSITY_LABELS:
            if self.density >= threshold:
                return lbl
        return "vector_trace"

    def fmt(self, name_fn=None) -> str:
        name = name_fn(self.va) if name_fn else f"0x{self.va:x}"
        return (
            f"0x{self.va:010x}  insns={self.total_insns:5d}  "
            f"vmx={self.vmx_count:4d}  density={self.density:6.2%}  "
            f"[{self.label:<14}]  {name}"
        )


class VMXDensityScanner:
    """
    Scans a PPC64/PPC32 big-endian binary for functions with high VMX density.

    Identifies math-heavy functions (physics, renderer, animation, audio DSP)
    that use AltiVec/VMX without relying on string cross-references.  Complements
    the 5-pass xref system in BinaryContext for unlabeled residual functions.

    The scan runs in O(N log F) time via numpy vectorised operations where N is
    the number of instructions and F is the number of functions.
    """

    def __init__(
        self,
        func_starts: List[int],
        code_data: bytes,
        code_va: int,
    ) -> None:
        self._func_starts = sorted(func_starts)
        self._code_data   = code_data
        self._code_va     = code_va

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_context(cls, ctx) -> "VMXDensityScanner":
        """Build from a BinaryContext (must be ppc64 or ppc32 arch)."""
        if ctx.arch not in ("ppc64", "ppc32"):
            raise ValueError(
                f"VMXDensityScanner requires ppc64/ppc32 binary, got {ctx.arch!r}"
            )
        path = getattr(ctx, "path", None) or getattr(ctx, "_path", None)
        if not path:
            raise ValueError("BinaryContext has no path attribute")
        with open(path, "rb") as fh:
            raw = fh.read()
        code_data, code_va = _load_code_segment(raw)
        if not code_data:
            raise ValueError(f"Could not locate executable LOAD segment in {path}")
        return cls(list(ctx.func_starts), code_data, code_va)

    @classmethod
    def from_path(cls, elf_path: str) -> "VMXDensityScanner":
        """Build directly from an ELF file path without a BinaryContext."""
        with open(elf_path, "rb") as fh:
            raw = fh.read()
        code_data, code_va = _load_code_segment(raw)
        if not code_data:
            raise ValueError(f"Could not locate executable LOAD segment in {elf_path}")

        func_starts: List[int] = _extract_func_starts(raw)
        return cls(func_starts, code_data, code_va)

    # ── Scanning ─────────────────────────────────────────────────────────────

    def scan(
        self,
        threshold: int = 5,
        min_insns: int = 8,
        min_density: float = 0.0,
    ) -> List[VMXFunctionResult]:
        """
        Return functions with at least `threshold` VMX instructions.

        Args:
            threshold:   Minimum VMX instruction count (absolute) to include.
            min_insns:   Minimum total instruction count; filters tiny stubs.
            min_density: Optional minimum density ratio (0.0 = any count above threshold).

        Returns:
            List of VMXFunctionResult sorted by vmx_count descending.
        """
        if not self._func_starts or not self._code_data:
            return []

        if _NUMPY_OK:
            results = self._scan_numpy(threshold, min_insns, min_density)
        else:
            results = self._scan_python(threshold, min_insns, min_density)

        results.sort(key=lambda r: r.vmx_count, reverse=True)
        return results

    def _scan_numpy(
        self, threshold: int, min_insns: int, min_density: float
    ) -> List[VMXFunctionResult]:
        buf      = self._code_data
        buf_len  = len(buf)
        code_va  = self._code_va
        fa       = np.array(self._func_starts, dtype=np.int64)
        n_funcs  = len(fa)

        buf_np  = np.frombuffer(buf, dtype=np.uint8)
        aligned = np.arange(0, buf_len - 3, 4, dtype=np.int64)
        b0      = buf_np[aligned]

        is_vmx = (b0 >= _VMX_B0_MIN) & (b0 <= _VMX_B0_MAX)

        # Map every word-aligned position to its enclosing function index
        insn_vas  = code_va + aligned
        func_idxs = np.searchsorted(fa, insn_vas, side='right') - 1

        # Filter to positions inside a known function (idx >= 0)
        valid = func_idxs >= 0
        func_idxs_v = func_idxs[valid]
        is_vmx_v    = is_vmx[valid]

        total_counts = np.bincount(func_idxs_v, minlength=n_funcs)
        vmx_counts   = np.bincount(func_idxs_v[is_vmx_v], minlength=n_funcs)

        results: List[VMXFunctionResult] = []
        hit_idxs = np.where(vmx_counts >= threshold)[0]
        for fi in hit_idxs.tolist():
            vc = int(vmx_counts[fi])
            tc = int(total_counts[fi])
            if tc < min_insns:
                continue
            density = vc / tc
            if density < min_density:
                continue
            results.append(VMXFunctionResult(
                va=int(fa[fi]),
                total_insns=tc,
                vmx_count=vc,
                density=density,
            ))
        return results

    def _scan_python(
        self, threshold: int, min_insns: int, min_density: float
    ) -> List[VMXFunctionResult]:
        buf      = self._code_data
        buf_len  = len(buf)
        code_va  = self._code_va
        fa       = self._func_starts

        results: List[VMXFunctionResult] = []
        for fi, fva in enumerate(fa):
            f_end = fa[fi + 1] if fi + 1 < len(fa) else code_va + buf_len
            f_off = fva - code_va
            e_off = min(f_end - code_va, buf_len - 3)
            if f_off < 0 or f_off >= e_off:
                continue
            total = vmx = 0
            for off in range(f_off, e_off, 4):
                total += 1
                b0 = buf[off]
                if _VMX_B0_MIN <= b0 <= _VMX_B0_MAX:
                    vmx += 1
            if vmx < threshold or total < min_insns:
                continue
            density = vmx / total
            if density < min_density:
                continue
            results.append(VMXFunctionResult(
                va=fva, total_insns=total, vmx_count=vmx, density=density,
            ))
        return results

    # ── Reporting ─────────────────────────────────────────────────────────────

    def report(
        self,
        results: List[VMXFunctionResult],
        name_fn=None,
        top_n: int = 60,
    ) -> str:
        """Format results as a human-readable table.

        Args:
            results:  Output of scan().
            name_fn:  Optional callable (va -> str) for function names.
                      Pass ctx.name to use BinaryContext overlay names.
            top_n:    Maximum rows to print.
        """
        if not results:
            return "VMXDensityScanner: no functions above threshold"
        header = (
            f"VMX density scan — {len(results)} functions\n"
            f"{'VA':<14} {'insns':>6} {'vmx':>5} {'density':>8}  {'label':<16} name\n"
            + "-" * 72
        )
        rows = [r.fmt(name_fn) for r in results[:top_n]]
        if len(results) > top_n:
            rows.append(f"  ... {len(results) - top_n} more")
        return header + "\n" + "\n".join(rows)

    def density_histogram(self, results: List[VMXFunctionResult]) -> str:
        """Print a 10-bucket density histogram."""
        if not results:
            return "no results"
        buckets = [0] * 10
        for r in results:
            b = min(9, int(r.density * 10))
            buckets[b] += 1
        lines = ["VMX density histogram:"]
        for i, count in enumerate(buckets):
            lo = i * 10
            hi = lo + 9
            bar = "#" * min(40, count)
            lines.append(f"  {lo:2d}-{hi:2d}%  {bar} ({count})")
        return "\n".join(lines)


# ── ELF helpers ──────────────────────────────────────────────────────────────

def _load_code_segment(raw: bytes) -> Tuple[bytes, int]:
    """Return (code_bytes, code_va) for the executable LOAD segment of a BE PPC ELF."""
    try:
        if raw[:4] != b'\x7fELF':
            return b"", 0
        ei_class = raw[4]   # 1=32-bit, 2=64-bit
        ei_data  = raw[5]   # 2=big-endian
        if ei_data != 2:
            return b"", 0   # only big-endian PPC supported

        if ei_class == 2:   # ELFCLASS64 (Cell PPU)
            e_phoff     = struct.unpack_from('>Q', raw, 0x20)[0]
            e_phentsize = struct.unpack_from('>H', raw, 0x36)[0]
            e_phnum     = struct.unpack_from('>H', raw, 0x38)[0]
            _ptype = lambda ph: struct.unpack_from('>I', raw, ph)[0]
            _pflags= lambda ph: struct.unpack_from('>I', raw, ph + 4)[0]
            _poff  = lambda ph: struct.unpack_from('>Q', raw, ph + 8)[0]
            _pvaddr= lambda ph: struct.unpack_from('>Q', raw, ph + 16)[0]
            _pfsz  = lambda ph: struct.unpack_from('>Q', raw, ph + 32)[0]
        elif ei_class == 1: # ELFCLASS32 (PPC32, older Cell targets)
            e_phoff     = struct.unpack_from('>I', raw, 0x1C)[0]
            e_phentsize = struct.unpack_from('>H', raw, 0x2A)[0]
            e_phnum     = struct.unpack_from('>H', raw, 0x2C)[0]
            _ptype = lambda ph: struct.unpack_from('>I', raw, ph)[0]
            _pflags= lambda ph: struct.unpack_from('>I', raw, ph + 24)[0]
            _poff  = lambda ph: struct.unpack_from('>I', raw, ph + 4)[0]
            _pvaddr= lambda ph: struct.unpack_from('>I', raw, ph + 8)[0]
            _pfsz  = lambda ph: struct.unpack_from('>I', raw, ph + 16)[0]
        else:
            return b"", 0

        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            if _ptype(ph) != 1:     # PT_LOAD
                continue
            if not (_pflags(ph) & 0x1):  # must be executable (PF_X)
                continue
            fsz = int(_pfsz(ph))
            if fsz < 0x100000:      # skip tiny segments
                continue
            off   = int(_poff(ph))
            vaddr = int(_pvaddr(ph))
            return raw[off:off + fsz], vaddr
    except Exception:
        pass
    return b"", 0


def _extract_func_starts(raw: bytes) -> List[int]:
    """Best-effort extraction of function start VAs from eh_frame."""
    starts: List[int] = []
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.dwarf.callframe import FDE
        import io
        elf = ELFFile(io.BytesIO(raw))
        if elf.has_dwarf_info():
            di = elf.get_dwarf_info()
            if di.has_EH_CFI():
                for e in di.EH_CFI_entries():
                    if isinstance(e, FDE):
                        va = e["initial_location"]
                        if va > 0:
                            starts.append(va)
    except Exception:
        pass
    return sorted(set(starts))
