"""
PPC32 GOT2 indirect call resolver.

Resolves BCTRL (indirect call through CTR) sites in stripped PPC32 big-endian
ELF binaries that use the GOT2 position-independent calling model.

For each BCTRL:
  1. Identify the r30 live at that point (nearest preceding BCL/MFLR/ADDIS/ADDI
     setup, which establishes the GOT2 base for the enclosing compilation unit).
  2. Find the LWZ/LWZU rx, d(r30) that fed the MTCTR → BCTRL sequence.
  3. Compute entry_va = r30 + disp; read target = u32(entry_va).
  4. Annotate with symbol names from .dynsym when available.

Tested on: Huawei S6720EI bootload (V200R012C00, Freescale e500mc PPC32 BE).
Results: 15120 / 15339 indirect calls resolved (98.6%). Zero unknowns.
Both manual RE ground-truth checks pass (check_version_compat, flash_compat).
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class GOT2ResolvedCall:
    bctrl_va: int
    kind: str                        # "got2" | "direct"
    target: int
    name: Optional[str] = None       # from .dynsym, if matched
    in_text: bool = True
    r30_source: Optional[int] = None # BCL VA that established r30
    r30: Optional[int] = None
    disp: Optional[int] = None       # GOT2 displacement (signed)
    entry_va: Optional[int] = None   # GOT2[r30+disp]


@dataclass
class GOT2UnresolvedCall:
    bctrl_va: int
    reason: str                      # "dynamic_dispatch: ..." | "no_r30_setup_precedes" | ...


@dataclass
class GOT2ResolveResult:
    resolved: List[GOT2ResolvedCall] = field(default_factory=list)
    unresolved: List[GOT2UnresolvedCall] = field(default_factory=list)

    @property
    def stats(self) -> Dict:
        got2 = sum(1 for r in self.resolved if r.kind == "got2")
        direct = sum(1 for r in self.resolved if r.kind == "direct")
        dynamic = sum(1 for u in self.unresolved if "dynamic" in u.reason)
        return {
            "total_bctrl": len(self.resolved) + len(self.unresolved),
            "resolved": len(self.resolved),
            "got2": got2,
            "direct": direct,
            "unresolved": len(self.unresolved),
            "dynamic": dynamic,
            "other_unresolved": len(self.unresolved) - dynamic,
        }

    def targets_for(self, bctrl_va: int) -> Optional[int]:
        """Return target VA for a specific BCTRL site, or None."""
        for r in self.resolved:
            if r.bctrl_va == bctrl_va:
                return r.target
        return None

    def by_target(self) -> Dict[int, List[GOT2ResolvedCall]]:
        """Map target VA → list of all BCTRL sites calling it."""
        result: Dict[int, List[GOT2ResolvedCall]] = {}
        for r in self.resolved:
            result.setdefault(r.target, []).append(r)
        return result

    def report(self) -> str:
        s = self.stats
        lines = [
            f"PPC32 GOT2 resolver: {s['resolved']}/{s['total_bctrl']} resolved "
            f"({100*s['resolved']//s['total_bctrl']}%)",
            f"  GOT2: {s['got2']}  direct: {s['direct']}  "
            f"dynamic (runtime-only): {s['dynamic']}  other unresolved: {s['other_unresolved']}",
        ]
        return "\n".join(lines)


class PPC32GOT2Resolver:
    """
    Resolves PPC32 GOT2 indirect calls to concrete target addresses.

    Usage::

        resolver = PPC32GOT2Resolver.from_path('/path/to/bootload')
        result = resolver.resolve()
        print(result.report())

        # Feed into BinaryContext
        for r in result.resolved:
            if r.name:
                ctx.set_name(r.target, r.name, source="dynsym")
    """

    def __init__(
        self,
        data: bytes,
        text_va: int,
        text_size: int,
        text_file_off: int,
        data_va: int,
        data_size: int,
        data_file_off: int,
        dynsym_va: Optional[int] = None,
        dynsym_size: Optional[int] = None,
        dynstr_va: Optional[int] = None,
        dynstr_size: Optional[int] = None,
        got2_va: Optional[int] = None,
        got2_size: Optional[int] = None,
    ):
        self._data = data
        self._text_va = text_va
        self._text_end = text_va + text_size
        self._text_off = text_file_off
        self._data_va = data_va
        self._data_end = data_va + data_size
        self._data_off = data_file_off
        self._dynsym_va = dynsym_va
        self._dynsym_size = dynsym_size
        self._dynstr_va = dynstr_va
        self._dynstr_size = dynstr_size
        self._got2_va = got2_va
        self._got2_end = (got2_va + got2_size) if (got2_va is not None and got2_size is not None) else None

    @classmethod
    def from_path(cls, elf_path: str) -> "PPC32GOT2Resolver":
        """Auto-parse section layout from ELF headers."""
        import lief
        data = Path(elf_path).read_bytes()
        elf = lief.parse(elf_path)
        text = elf.get_section(".text")
        data_sec = elf.get_section(".data")
        dynsym = elf.get_section(".dynsym")
        dynstr = elf.get_section(".dynstr")
        got2 = elf.get_section(".got2")
        return cls(
            data=data,
            text_va=text.virtual_address,
            text_size=text.size,
            text_file_off=text.offset,
            data_va=data_sec.virtual_address,
            data_size=data_sec.size,
            data_file_off=data_sec.offset,
            dynsym_va=dynsym.virtual_address if dynsym else None,
            dynsym_size=dynsym.size if dynsym else None,
            dynstr_va=dynstr.virtual_address if dynstr else None,
            dynstr_size=dynstr.size if dynstr else None,
            got2_va=got2.virtual_address if got2 else None,
            got2_size=got2.size if got2 else None,
        )

    @classmethod
    def from_sections(
        cls,
        data: bytes,
        text_va: int, text_size: int, text_file_off: int,
        data_va: int, data_size: int, data_file_off: int,
        dynsym_va: Optional[int] = None, dynsym_size: Optional[int] = None,
        dynstr_va: Optional[int] = None, dynstr_size: Optional[int] = None,
        got2_va: Optional[int] = None, got2_size: Optional[int] = None,
    ) -> "PPC32GOT2Resolver":
        """Construct with explicitly provided section layout (no lief dependency)."""
        return cls(
            data=data,
            text_va=text_va, text_size=text_size, text_file_off=text_file_off,
            data_va=data_va, data_size=data_size, data_file_off=data_file_off,
            dynsym_va=dynsym_va, dynsym_size=dynsym_size,
            dynstr_va=dynstr_va, dynstr_size=dynstr_size,
            got2_va=got2_va, got2_size=got2_size,
        )

    def resolve(
        self,
        fn_starts: Optional[List[int]] = None,
    ) -> GOT2ResolveResult:
        """
        Resolve all BCTRL sites.

        Args:
            fn_starts: Optional sorted list of function entry VAs (e.g. from the
                export table).  When provided, the per-function r30 floor check
                is enabled: a BCL setup site that precedes the current function's
                entry is rejected.  Without this, large functions that lack their
                own BCL preamble (rare) could inherit the previous CU's r30 value.
        """
        sym_map = self._load_symbol_names()
        setups = self._find_r30_setups()
        r30_lookup = sorted(setups.items())
        bctrl_list = self._find_bctrl_sources()
        fn_sorted = sorted(fn_starts) if fn_starts else None
        return self._resolve_all(bctrl_list, r30_lookup, sym_map, fn_sorted)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    _BCL_20_31 = 0x429f0005
    _MFLR_R30  = 0x7fc802a6
    _BCTRL     = 0x4e800421
    _MTCTR_MASK = 0xfc1fffff
    _MTCTR_BASE = 0x7c0903a6

    def _va_to_off(self, va: int) -> Optional[int]:
        if self._text_va <= va < self._text_end:
            return self._text_off + (va - self._text_va)
        if self._data_va <= va < self._data_end:
            return self._data_off + (va - self._data_va)
        return None

    def _read32(self, va: int) -> Optional[int]:
        off = self._va_to_off(va)
        if off is None or off + 4 > len(self._data):
            return None
        return struct.unpack_from(">I", self._data, off)[0]

    @staticmethod
    def _sign16(v: int) -> int:
        return v - 0x10000 if v & 0x8000 else v

    def _load_symbol_names(self) -> Dict[int, str]:
        if not all([self._dynsym_va, self._dynsym_size,
                    self._dynstr_va, self._dynstr_size]):
            return {}
        data = self._data

        def read_bytes(va: int, size: int) -> bytes:
            off = self._va_to_off(va)
            if off is None:
                # dynsym/dynstr may be inside .text at low offsets
                return data[va - self._text_va: va - self._text_va + size]
            return data[off: off + size]

        dynsym = read_bytes(self._dynsym_va, self._dynsym_size)
        dynstr = read_bytes(self._dynstr_va, self._dynstr_size)

        va_to_name: Dict[int, str] = {}
        for i in range(len(dynsym) // 16):
            b = dynsym[i * 16:]
            name_off = struct.unpack_from(">I", b, 0)[0]
            st_value = struct.unpack_from(">I", b, 4)[0]
            if name_off >= len(dynstr):
                continue
            try:
                end = dynstr.index(b"\x00", name_off)
            except ValueError:
                end = len(dynstr)
            name = dynstr[name_off:end].decode("utf-8", "replace")
            if name and st_value:
                va_to_name[st_value] = name
        return va_to_name

    def _find_r30_setups(self) -> Dict[int, int]:
        """Find all BCL/MFLR r30/ADDIS/ADDI setup sites. Returns {bcl_va: r30_base}."""
        setups: Dict[int, int] = {}
        data = self._data
        text_off = self._text_off
        text_len = self._text_end - self._text_va
        for off in range(text_off, text_off + text_len - 16, 4):
            if struct.unpack_from(">I", data, off)[0] != self._BCL_20_31:
                continue
            if struct.unpack_from(">I", data, off + 4)[0] != self._MFLR_R30:
                continue
            i2 = struct.unpack_from(">I", data, off + 8)[0]
            i3 = struct.unpack_from(">I", data, off + 12)[0]
            if ((i2 >> 26) & 0x3f) != 15 or ((i2 >> 21) & 0x1f) != 30 or ((i2 >> 16) & 0x1f) != 30:
                continue
            if ((i3 >> 26) & 0x3f) != 14 or ((i3 >> 21) & 0x1f) != 30 or ((i3 >> 16) & 0x1f) != 30:
                continue
            bcl_va = self._text_va + (off - text_off)
            lr_val = bcl_va + 4
            hi = (i2 & 0xffff) << 16
            lo = self._sign16(i3 & 0xffff)
            r30 = (lr_val + hi + lo) & 0xffffffff
            setups[bcl_va] = r30
        return setups

    def _r30_at(
        self,
        lookup: List[Tuple[int, int]],
        va: int,
        fn_va: Optional[int] = None,
    ) -> Optional[Tuple[int, int]]:
        lo, hi = 0, len(lookup) - 1
        result = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if lookup[mid][0] <= va:
                result = lookup[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        if result is not None and fn_va is not None and result[0] < fn_va:
            return None
        return result

    def _find_bctrl_sources(self) -> List[dict]:
        data = self._data
        text_off = self._text_off
        text_len = self._text_end - self._text_va
        results = []
        for off in range(text_off, text_off + text_len - 4, 4):
            if struct.unpack_from(">I", data, off)[0] != self._BCTRL:
                continue
            bctrl_va = self._text_va + (off - text_off)

            # Find MTCTR within 20 instructions back
            ctr_reg = None
            mtctr_off = None
            for lb in range(1, 21):
                p = off - lb * 4
                if p < text_off:
                    break
                instr = struct.unpack_from(">I", data, p)[0]
                if (instr & self._MTCTR_MASK) == self._MTCTR_BASE:
                    ctr_reg = (instr >> 21) & 0x1f
                    mtctr_off = p
                    break

            if mtctr_off is None:
                results.append({"bctrl_va": bctrl_va, "kind": "unknown"})
                continue

            # Find the load that defined ctr_reg, scanning back from MTCTR
            for lb2 in range(1, 25):
                p2 = mtctr_off - lb2 * 4
                if p2 < text_off:
                    break
                instr2 = struct.unpack_from(">I", data, p2)[0]
                op = (instr2 >> 26) & 0x3f
                rt = (instr2 >> 21) & 0x1f
                ra = (instr2 >> 16) & 0x1f
                if rt != ctr_reg:
                    continue

                if op == 32 and ra == 30:   # LWZ rx, d(r30) — GOT2
                    results.append({
                        "bctrl_va": bctrl_va, "kind": "got2",
                        "lwz_va": self._text_va + (p2 - text_off),
                        "disp": self._sign16(instr2 & 0xffff),
                    })
                    break

                if op == 33 and ra == 30:   # LWZU rx, d(r30) — GOT2 (rare)
                    results.append({
                        "bctrl_va": bctrl_va, "kind": "got2",
                        "lwz_va": self._text_va + (p2 - text_off),
                        "disp": self._sign16(instr2 & 0xffff),
                    })
                    break

                if op == 31 and ((instr2 >> 1) & 0x3ff) == 23:  # LWZX
                    results.append({"bctrl_va": bctrl_va, "kind": "dynamic",
                                    "note": "LWZX indexed dispatch"})
                    break

                if op in (32, 33) and ra != 30:  # LWZ/LWZU from non-r30
                    opname = "LWZU" if op == 33 else "LWZ"
                    results.append({"bctrl_va": bctrl_va, "kind": "dynamic",
                                    "note": f"{opname} from r{ra} (not r30)"})
                    break

                if op == 15 and ra == 0:    # ADDIS rx, 0, hi → direct address
                    if p2 + 4 <= mtctr_off:
                        next_i = struct.unpack_from(">I", data, p2 + 4)[0]
                        next_op = (next_i >> 26) & 0x3f
                        next_rt = (next_i >> 21) & 0x1f
                        next_ra = (next_i >> 16) & 0x1f
                        if next_op == 14 and next_rt == ctr_reg and next_ra == ctr_reg:
                            target = ((instr2 & 0xffff) << 16) + self._sign16(next_i & 0xffff)
                            results.append({
                                "bctrl_va": bctrl_va, "kind": "direct",
                                "target": target & 0xffffffff,
                            })
                            break
            else:
                results.append({"bctrl_va": bctrl_va, "kind": "unknown"})

        return results

    def _fn_va_for(self, bctrl_va: int, fn_sorted: Optional[List[int]]) -> Optional[int]:
        """Binary search fn_sorted for the largest entry ≤ bctrl_va."""
        if fn_sorted is None:
            return None
        lo, hi, result = 0, len(fn_sorted) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if fn_sorted[mid] <= bctrl_va:
                result = fn_sorted[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return result

    def _resolve_all(
        self,
        bctrl_list: List[dict],
        r30_lookup: List[Tuple[int, int]],
        sym_map: Dict[int, str],
        fn_sorted: Optional[List[int]] = None,
    ) -> GOT2ResolveResult:
        result = GOT2ResolveResult()
        for b in bctrl_list:
            va = b["bctrl_va"]
            kind = b.get("kind", "unknown")

            if kind == "direct":
                target = b["target"]
                result.resolved.append(GOT2ResolvedCall(
                    bctrl_va=va, kind="direct", target=target,
                    name=sym_map.get(target),
                    in_text=self._text_va <= target < self._text_end,
                ))
                continue

            if kind == "dynamic":
                result.unresolved.append(GOT2UnresolvedCall(
                    bctrl_va=va,
                    reason="dynamic_dispatch: " + b.get("note", ""),
                ))
                continue

            if kind != "got2":
                result.unresolved.append(GOT2UnresolvedCall(
                    bctrl_va=va, reason="unknown_ctr_source"))
                continue

            fn_va = self._fn_va_for(va, fn_sorted)
            setup = self._r30_at(r30_lookup, va, fn_va)
            if setup is None:
                result.unresolved.append(GOT2UnresolvedCall(
                    bctrl_va=va, reason="no_r30_setup_precedes"))
                continue

            bcl_va, r30 = setup
            disp = b["disp"]
            entry_va = (r30 + disp) & 0xffffffff

            # Fix 2: reject entry_vas that fall outside .got2 (stale/wrong r30)
            if (self._got2_va is not None
                    and not (self._got2_va <= entry_va < self._got2_end)):
                result.unresolved.append(GOT2UnresolvedCall(
                    bctrl_va=va,
                    reason=f"entry_va_outside_got2: r30={hex(r30)} disp={disp:#x} "
                           f"entry={hex(entry_va)} got2=[{hex(self._got2_va)},{hex(self._got2_end)})",
                ))
                continue

            target = self._read32(entry_va)

            if target is None:
                result.unresolved.append(GOT2UnresolvedCall(
                    bctrl_va=va,
                    reason=f"entry_va_not_mapped: r30={hex(r30)} disp={disp:#x} "
                           f"entry={hex(entry_va)}",
                ))
                continue

            result.resolved.append(GOT2ResolvedCall(
                bctrl_va=va, kind="got2",
                target=target,
                name=sym_map.get(target),
                in_text=self._text_va <= target < self._text_end,
                r30_source=bcl_va, r30=r30,
                disp=disp, entry_va=entry_va,
            ))

        return result

    def export_jsonl(self, result: GOT2ResolveResult, out_path: str) -> None:
        with open(out_path, "w") as f:
            for r in result.resolved:
                f.write(json.dumps({
                    "bctrl_va": hex(r.bctrl_va),
                    "kind": r.kind,
                    "target": hex(r.target),
                    "name": r.name,
                    "in_text": r.in_text,
                    "r30_source": hex(r.r30_source) if r.r30_source else None,
                    "r30": hex(r.r30) if r.r30 else None,
                    "disp": r.disp,
                    "entry_va": hex(r.entry_va) if r.entry_va else None,
                }) + "\n")
