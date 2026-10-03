"""
PPC32 PLT import caller tracer for position-independent .so files.

Finds every BL call site that calls a named imported symbol in a PPC32 BE .so.
Uses the PLT-thunk calling model (LWZ rx,d(r30) + MTCTR + BCTR) and verifies
each caller's active r30 against the expected implied_r30 for the target symbol,
eliminating the false-positive class where multiple compilation units share a
thunk VA but route to different PLT slots depending on their r30.

See: docs/module-reference/ppc32-plt-tracer.md
"""
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
import lief

DANGEROUS_SINKS: Set[str] = {'system', 'popen', 'execl', 'execve', 'execvp', 'execvpe'}

_CS = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 + capstone.CS_MODE_BIG_ENDIAN)
_CS.detail = True

_BCL  = 0x429F0005
_MFLR = 0x7FC802A6


@dataclass
class PLTCallSite:
    """One confirmed call site where a BL instruction calls an imported symbol."""
    bl_va: int
    thunk_va: int
    caller_r30: int
    func_name: Optional[str] = None


class PPC32ELF:
    """
    Thin lief + capstone wrapper for a PPC32 BE ELF binary.

    Provides section access, disassembly, and import/export queries.
    This class is shared by both workspace scripts and PPC32PLTTracer.
    """

    def __init__(self, path: str):
        self.path = path
        self.data = Path(path).read_bytes()
        self.elf = lief.parse(path)
        self._sec_cache: Dict[str, lief.ELF.Section] = {
            s.name: s for s in self.elf.sections
        }

    @property
    def dangerous_imports(self) -> List[str]:
        return [s.name for s in self.elf.imported_symbols if s.name in DANGEROUS_SINKS]

    @property
    def all_imports(self) -> List[str]:
        return [s.name for s in self.elf.imported_symbols]

    @property
    def exports(self) -> Dict[str, int]:
        return {s.name: s.value for s in self.elf.exported_symbols if s.value}

    def plt_slot(self, sym_name: str) -> Optional[int]:
        for rel in self.elf.pltgot_relocations:
            if hasattr(rel, 'symbol') and rel.symbol and rel.symbol.name == sym_name:
                return rel.address
        return None

    def section(self, name: str) -> Optional[lief.ELF.Section]:
        return self._sec_cache.get(name)

    def section_at(self, va: int) -> Optional[lief.ELF.Section]:
        for sec in self.elf.sections:
            if sec.virtual_address <= va < sec.virtual_address + sec.size:
                return sec
        return None

    def read32(self, va: int) -> Optional[int]:
        sec = self.section_at(va)
        if sec is None:
            return None
        off = sec.offset + (va - sec.virtual_address)
        if off + 4 > len(self.data):
            return None
        return struct.unpack_from('>I', self.data, off)[0]

    def disasm(self, va: int, n: int = 20) -> List[capstone.CsInsn]:
        sec = self.section_at(va)
        if sec is None:
            return []
        off = sec.offset + (va - sec.virtual_address)
        return list(_CS.disasm(self.data[off: off + n * 4], va))

    def print_disasm(self, va: int, n: int = 20, mark: Optional[int] = None) -> None:
        for insn in self.disasm(va, n):
            arrow = '  <<<' if mark and insn.address == mark else ''
            print(f"  0x{insn.address:x}: {insn.mnemonic:<10} {insn.op_str}{arrow}")

    def find_bl_callers(self, target_va: int) -> List[int]:
        text = self.section('.text')
        if not text:
            return []
        callers = []
        for i in range(0, text.size - 3, 4):
            w = struct.unpack_from('>I', self.data, text.offset + i)[0]
            if (w & 0xFC000003) != 0x48000001:
                continue
            li = (w >> 2) & 0xFFFFFF
            if li >= 0x800000:
                li -= 0x1000000
            instr_va = text.virtual_address + i
            if instr_va + (li << 2) == target_va:
                callers.append(instr_va)
        return callers

    # kept for backward compatibility with ppc32_tools.py callers
    def find_import_callers(self, sym_name: str) -> Dict[int, List[int]]:
        """
        Unverified thunk-to-callers map. Prefer PPC32PLTTracer.find_callers()
        which applies the r30 cross-check and eliminates false positives.
        Returns {thunk_va: [bl_caller_vas]}.
        """
        slot_va = self.plt_slot(sym_name)
        if slot_va is None:
            return {}
        valid_r30s = self._valid_r30_values()
        thunks = self._find_thunks()
        result: Dict[int, List[int]] = {}
        for thunk_va, disp in thunks.items():
            implied_r30 = (slot_va - disp) & 0xFFFFFFFF
            if implied_r30 not in valid_r30s:
                continue
            callers = self.find_bl_callers(thunk_va)
            if callers:
                result[thunk_va] = callers
        return result

    def _find_thunks(self) -> Dict[int, int]:
        text = self.section('.text')
        if not text:
            return {}
        thunks = {}
        for i in range(0, text.size - 11, 4):
            w0 = struct.unpack_from('>I', self.data, text.offset + i)[0]
            w1 = struct.unpack_from('>I', self.data, text.offset + i + 4)[0]
            w2 = struct.unpack_from('>I', self.data, text.offset + i + 8)[0]
            if (w0 >> 26) & 0x3f != 32 or (w0 >> 16) & 0x1f != 30:
                continue
            rx = (w0 >> 21) & 0x1f
            disp = w0 & 0xffff
            if disp >= 0x8000:
                disp -= 0x10000
            if (w1 & 0xFC1FFFFF) != 0x7C0903A6 or (w1 >> 21) & 0x1f != rx:
                continue
            if w2 != 0x4E800420:
                continue
            thunks[text.virtual_address + i] = disp
        return thunks

    def _valid_r30_values(self) -> Set[int]:
        text = self.section('.text')
        if not text:
            return set()
        r30_values: Set[int] = set()
        d = self.data
        base = text.offset
        for i in range(0, text.size - 64, 4):
            if struct.unpack_from('>I', d, base + i)[0] != _BCL:
                continue
            mflr_i = None
            for j in range(1, 17):
                if struct.unpack_from('>I', d, base + i + j * 4)[0] == _MFLR:
                    mflr_i = j
                    break
            if mflr_i is None:
                continue
            addis_w = addi_w = None
            for k in range(1, 7):
                w = struct.unpack_from('>I', d, base + i + (mflr_i + k) * 4)[0]
                if (w >> 26) & 0x3f == 15 and (w >> 21) & 0x1f == 30 and (w >> 16) & 0x1f == 30:
                    addis_w = w
                    for m in range(1, 7):
                        w2 = struct.unpack_from('>I', d, base + i + (mflr_i + k + m) * 4)[0]
                        if (w2 >> 26) & 0x3f == 14 and (w2 >> 21) & 0x1f == 30 and (w2 >> 16) & 0x1f == 30:
                            addi_w = w2
                            break
                    break
            if addis_w is None or addi_w is None:
                continue
            bcl_va = text.virtual_address + i
            lr_val = bcl_va + 4
            hi = (addis_w & 0xFFFF) << 16
            lo = addi_w & 0xFFFF
            if lo >= 0x8000:
                lo -= 0x10000
            r30_values.add((lr_val + hi + lo) & 0xFFFFFFFF)
        return r30_values


class PPC32PLTTracer:
    """
    Verified import caller finder for PPC32 BE .so files.

    Identifies every BL instruction that calls a named imported symbol
    and verifies each caller's active r30 against the expected value for
    that PLT slot, eliminating cross-compilation-unit false positives.
    """

    def __init__(self, elf: PPC32ELF):
        self._elf = elf
        self._thunks: Optional[Dict[int, int]] = None
        self._valid_r30s: Optional[Set[int]] = None

    @classmethod
    def from_path(cls, path: str) -> 'PPC32PLTTracer':
        return cls(PPC32ELF(path))

    @property
    def elf(self) -> PPC32ELF:
        return self._elf

    def _thunk_map(self) -> Dict[int, int]:
        if self._thunks is None:
            self._thunks = self._elf._find_thunks()
        return self._thunks

    def _r30_set(self) -> Set[int]:
        if self._valid_r30s is None:
            self._valid_r30s = self._elf._valid_r30_values()
        return self._valid_r30s

    def _get_caller_r30(self, va: int, max_scan: int = 8192) -> Optional[int]:
        """Compute the r30 value active at a call site VA by scanning back for BCL preamble."""
        text = self._elf.section('.text')
        if not text:
            return None
        data = self._elf.data
        base = text.offset
        for back in range(4, min(max_scan, va - text.virtual_address) + 4, 4):
            check_va = va - back
            off = base + (check_va - text.virtual_address)
            if off < 0 or off + 4 > len(data):
                break
            if struct.unpack_from('>I', data, off)[0] != _BCL:
                continue
            bcl_va = check_va
            lr_val = bcl_va + 4
            mflr_i = None
            for j in range(1, 17):
                if struct.unpack_from('>I', data, off + j * 4)[0] == _MFLR:
                    mflr_i = j
                    break
            if mflr_i is None:
                continue
            addis_w = addi_w = None
            for k in range(1, 7):
                w = struct.unpack_from('>I', data, off + (mflr_i + k) * 4)[0]
                if (w >> 26) & 0x3f == 15 and (w >> 21) & 0x1f == 30 and (w >> 16) & 0x1f == 30:
                    addis_w = w
                    for m in range(1, 7):
                        w2 = struct.unpack_from('>I', data, off + (mflr_i + k + m) * 4)[0]
                        if (w2 >> 26) & 0x3f == 14 and (w2 >> 21) & 0x1f == 30 and (w2 >> 16) & 0x1f == 30:
                            addi_w = w2
                            break
                    break
            if addis_w is None or addi_w is None:
                continue
            hi = (addis_w & 0xFFFF) << 16
            lo = addi_w & 0xFFFF
            if lo >= 0x8000:
                lo -= 0x10000
            return (lr_val + hi + lo) & 0xFFFFFFFF
        return None

    def _nearest_export(self, va: int) -> Optional[str]:
        best = None
        best_dist = 0xFFFFFFFF
        for name, export_va in self._elf.exports.items():
            d = va - export_va
            if 0 <= d < best_dist:
                best_dist = d
                best = name
        return best

    def find_callers(self, sym_name: str) -> List[PLTCallSite]:
        """
        Return every BL site that definitively calls sym_name.

        For each candidate thunk (LWZ+MTCTR+BCTR pattern with displacement d
        matching plt_slot(sym_name) - d = implied_r30), enumerate all BL callers
        and keep only those whose active r30 equals the implied_r30.
        """
        slot_va = self._elf.plt_slot(sym_name)
        if slot_va is None:
            return []
        thunks = self._thunk_map()
        valid_r30s = self._r30_set()
        sites: List[PLTCallSite] = []

        for thunk_va, disp in thunks.items():
            implied_r30 = (slot_va - disp) & 0xFFFFFFFF
            if implied_r30 not in valid_r30s:
                continue
            for bl_va in self._elf.find_bl_callers(thunk_va):
                actual_r30 = self._get_caller_r30(bl_va)
                if actual_r30 != implied_r30:
                    continue
                sites.append(PLTCallSite(
                    bl_va=bl_va,
                    thunk_va=thunk_va,
                    caller_r30=actual_r30,
                    func_name=self._nearest_export(bl_va),
                ))
        return sorted(sites, key=lambda s: s.bl_va)

    def report(self, sites: List[PLTCallSite], sym_name: str = '') -> str:
        lines = [f"[{sym_name or '?'}] {len(sites)} confirmed call site(s):"]
        for s in sites:
            lines.append(f"  BL@{s.bl_va:#x}  thunk@{s.thunk_va:#x}  r30={s.caller_r30:#x}  in {s.func_name or '?'}")
        return '\n'.join(lines)


def batch_sweep(
    directory: str,
    sinks: Optional[Set[str]] = None,
) -> Dict[str, List[str]]:
    """
    Scan all ELFs in directory for dangerous imports.
    Returns {filename: [sink_names]} for files with hits only.
    Compatible with ppc32_tools.batch_sweep.
    """
    if sinks is None:
        sinks = DANGEROUS_SINKS
    hits = {}
    for p in sorted(Path(directory).iterdir()):
        if not p.is_file():
            continue
        try:
            if p.read_bytes()[:4] != b'\x7fELF':
                continue
        except OSError:
            continue
        try:
            e = PPC32ELF(str(p))
            found = [s for s in e.all_imports if s in sinks]
            if found:
                hits[p.name] = found
        except Exception:
            continue
    return hits


def batch_scan(
    directory: str,
    sinks: Optional[Set[str]] = None,
) -> Dict[str, Dict[str, List[PLTCallSite]]]:
    """
    Full verified scan: for each ELF in directory, run find_callers() on each
    dangerous import. Returns {filename: {sym: [PLTCallSite]}} for non-empty results.
    """
    if sinks is None:
        sinks = DANGEROUS_SINKS
    results: Dict[str, Dict[str, List[PLTCallSite]]] = {}
    for p in sorted(Path(directory).iterdir()):
        if not p.is_file():
            continue
        try:
            if p.read_bytes()[:4] != b'\x7fELF':
                continue
        except OSError:
            continue
        try:
            e = PPC32ELF(str(p))
            found_sinks = [s for s in e.all_imports if s in sinks]
            if not found_sinks:
                continue
            tracer = PPC32PLTTracer(e)
            file_hits: Dict[str, List[PLTCallSite]] = {}
            for sym in found_sinks:
                sites = tracer.find_callers(sym)
                if sites:
                    file_hits[sym] = sites
            if file_hits:
                results[p.name] = file_hits
        except Exception:
            continue
    return results
