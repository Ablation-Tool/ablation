"""
VtableDispatchScanner — finds call [reg+disp] dispatch sites in x86-64 ELF .text.

Determines which virtual function slots are actually dispatched (live) vs. never
called (dead). Covers all standard x86-64 indirect call encodings including
REX.B-extended registers (r8–r15) and disp8 / disp32 forms.

See docs/module-reference/vtable-x86-64.md for full documentation.
"""

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union


@dataclass
class DispatchSite:
    call_va: int
    register: str    # base register name (e.g. 'rax', 'r12')
    slot_offset: int
    encoding: str    # 'disp8' or 'disp32'


@dataclass
class DispatchReport:
    slot_offsets: Dict[str, List[DispatchSite]] = field(default_factory=dict)

    def dead(self) -> Dict[str, List[DispatchSite]]:
        return {k: v for k, v in self.slot_offsets.items() if not v}

    def live(self) -> Dict[str, List[DispatchSite]]:
        return {k: v for k, v in self.slot_offsets.items() if v}

    def is_dead(self, key: str) -> bool:
        return len(self.slot_offsets.get(key, [])) == 0

    def sites_for(self, key: str) -> List[DispatchSite]:
        return self.slot_offsets.get(key, [])


# x86-64 register names for ModRM rm field
_BASE_REGS = {0: 'rax', 1: 'rcx', 2: 'rdx', 3: 'rbx', 5: 'rbp', 6: 'rsi', 7: 'rdi'}
_REXB_REGS = {0: 'r8',  1: 'r9',  2: 'r10', 3: 'r11', 5: 'r13', 6: 'r14', 7: 'r15'}

# rm=4 with disp32 requires a SIB byte; handled separately
_SIB_RM = 4


class VtableDispatchScanner:
    """
    Searches executable sections of an x86-64 ELF for vtable dispatch patterns.

    Usage:
        scanner = VtableDispatchScanner.from_path('/path/to/lib.so')
        report  = scanner.scan({'method_a': 0x10, 'method_b': 0x4b0})

        # or pass a VtableMap from ELFVtableReconstructor
        report = scanner.scan(vtable_map)

        print(VtableDispatchScanner.report(report))
    """

    def __init__(self, elf_path: str):
        self.elf_path = elf_path
        with open(elf_path, 'rb') as f:
            self._data = f.read()
        self._exec_regions: List[Tuple[int, int, int]] = []  # (va_start, va_end, file_off)
        self._parse_exec_sections()

    @classmethod
    def from_path(cls, elf_path: str) -> 'VtableDispatchScanner':
        return cls(elf_path)

    @classmethod
    def from_context(cls, ctx) -> 'VtableDispatchScanner':
        return cls(ctx.binary_path)

    def _parse_exec_sections(self) -> None:
        data = self._data
        if len(data) < 64 or data[:4] != b'\x7fELF':
            return
        e_shoff    = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum    = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx = struct.unpack_from('<H', data, 62)[0]
        shstr_off  = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 24)[0]

        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            sh_flags = struct.unpack_from('<Q', data, sh + 8)[0]
            sh_addr  = struct.unpack_from('<Q', data, sh + 16)[0]
            sh_off   = struct.unpack_from('<Q', data, sh + 24)[0]
            sh_size  = struct.unpack_from('<Q', data, sh + 32)[0]
            if sh_flags & 0x4 and sh_size > 0:  # SHF_EXECINSTR
                self._exec_regions.append((sh_addr, sh_addr + sh_size, sh_off))

    def _file_offset_to_va(self, file_off: int) -> int:
        for va_start, va_end, f_off in self._exec_regions:
            size = va_end - va_start
            if f_off <= file_off < f_off + size:
                return va_start + (file_off - f_off)
        return file_off  # ET_DYN fallback: VA == file offset

    def _exec_data(self) -> Tuple[bytes, int]:
        """Return (contiguous_exec_bytes, file_start_offset) for scanning."""
        if not self._exec_regions:
            return self._data, 0
        f_start = min(r[2] for r in self._exec_regions)
        f_end   = max(r[2] + (r[1] - r[0]) for r in self._exec_regions)
        return self._data[f_start:f_end], f_start

    # ------------------------------------------------------------------
    # Pattern builders
    # ------------------------------------------------------------------

    @staticmethod
    def _patterns_disp32(disp: int):
        """
        Yield (prefix_bytes, modrm) for all call [reg+disp32] encodings.
        ModRM = 10_010_rrr where 10=mod (disp32), 010=reg (/2=CALL), rrr=rm.
        Skips rm=4 without SIB (handled by _patterns_sib_disp32).
        """
        disp_bytes = struct.pack('<i', disp)
        # REX prefix variants that affect the rm field (REX.B) or are no-ops (REX.W, none)
        prefixes_and_regs = [
            (b'',     _BASE_REGS),  # no REX
            (b'\x40', _BASE_REGS),  # REX (no-op extension, valid)
            (b'\x41', _REXB_REGS),  # REX.B: rm selects r8..r15
            (b'\x44', _BASE_REGS),  # REX.R (extends reg field, rm unchanged)
            (b'\x45', _REXB_REGS),  # REX.RB
            (b'\x48', _BASE_REGS),  # REX.W
            (b'\x49', _REXB_REGS),  # REX.WB
            (b'\x4c', _BASE_REGS),  # REX.WR
            (b'\x4d', _REXB_REGS),  # REX.WRB
        ]
        for prefix, reg_map in prefixes_and_regs:
            for rm, reg_name in reg_map.items():
                modrm = 0x90 | rm  # mod=10, reg=2, rm=rm
                yield prefix + bytes([0xff, modrm]) + disp_bytes, reg_name

    @staticmethod
    def _patterns_disp8(disp: int):
        """
        Yield (pattern, reg_name) for call [reg+disp8].
        Only valid for 0 <= disp <= 127 (positive disp8).
        ModRM = 01_010_rrr.
        """
        if not (0 <= disp <= 127):
            return
        for prefix, reg_map in [
            (b'',     _BASE_REGS),
            (b'\x41', _REXB_REGS),
            (b'\x48', _BASE_REGS),
            (b'\x49', _REXB_REGS),
        ]:
            for rm, reg_name in reg_map.items():
                modrm = 0x50 | rm  # mod=01, reg=2, rm=rm
                yield prefix + bytes([0xff, modrm, disp]), reg_name

    @staticmethod
    def _patterns_sib_disp32(disp: int):
        """
        Yield patterns for call [base+index*scale+disp32] forms where rm=4 (SIB byte).
        Covers common compiler-generated patterns: [r12+disp32] (REX.B, rm=4, SIB=0x24)
        and [rsp+disp32] (rm=4, SIB=0x24).
        """
        disp_bytes = struct.pack('<i', disp)
        # SIB=0x24: index=4 (no index), base=4 (rsp or r12 with REX.B), scale=0
        sib = bytes([0x24])
        # No REX: [rsp+disp32]
        yield b'\xff\x94' + sib + disp_bytes, 'rsp'
        # REX.B: [r12+disp32]
        yield b'\x41\xff\x94' + sib + disp_bytes, 'r12'
        yield b'\x49\xff\x94' + sib + disp_bytes, 'r12'

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_offset(self, slot_offset: int) -> List[DispatchSite]:
        """Find all call [reg+slot_offset] sites in executable sections."""
        exec_data, file_start = self._exec_data()
        sites: List[DispatchSite] = []
        seen_vas = set()

        def _search(patterns, encoding: str):
            for pattern, reg_name in patterns:
                pos = 0
                while True:
                    pos = exec_data.find(pattern, pos)
                    if pos == -1:
                        break
                    # call instruction VA: file_start + pos + len(prefix_before_0xff)
                    # We record the VA of the FF byte (start of call instruction proper)
                    prefix_len = len(pattern) - len(pattern.lstrip(bytes(range(0x40, 0x50))))
                    # Simpler: prefix = everything before 0xff byte
                    ff_pos = next(i for i, b in enumerate(pattern) if b == 0xff)
                    call_va = self._file_offset_to_va(file_start + pos + ff_pos)
                    if call_va not in seen_vas:
                        seen_vas.add(call_va)
                        sites.append(DispatchSite(
                            call_va=call_va,
                            register=reg_name,
                            slot_offset=slot_offset,
                            encoding=encoding,
                        ))
                    pos += 1

        _search(self._patterns_disp32(slot_offset), 'disp32')
        _search(self._patterns_sib_disp32(slot_offset), 'disp32')
        if 0 <= slot_offset <= 127:
            _search(self._patterns_disp8(slot_offset), 'disp8')

        return sorted(sites, key=lambda s: s.call_va)

    def scan(self, slot_map) -> DispatchReport:
        """
        Scan for dispatch sites for all slots in slot_map.

        slot_map accepts:
          - dict of {name: slot_offset}
          - VtableMap (ELFVtableReconstructor) — uses live_slots() automatically
          - list / tuple of slot_offset integers
        """
        if hasattr(slot_map, 'live_slots'):
            items = {s.function_name: s.slot_offset
                     for s in slot_map.live_slots().values()}
        elif isinstance(slot_map, dict):
            items = slot_map
        elif isinstance(slot_map, (list, tuple)):
            items = {f'offset_{off:#x}': off for off in slot_map}
        else:
            raise TypeError(f'Unsupported slot_map type: {type(slot_map).__name__}')

        results = {name: self.scan_offset(offset) for name, offset in items.items()}
        return DispatchReport(slot_offsets=results)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def report(dr: DispatchReport) -> str:
        live = dr.live()
        dead = dr.dead()
        lines = ['VtableDispatchScanner report:']

        if live:
            lines.append(f'  LIVE  ({len(live)} slots):')
            for name, sites in sorted(live.items()):
                lines.append(f'    {name}: {len(sites)} site(s)')
                for s in sites[:4]:
                    lines.append(
                        f'      {s.call_va:#010x}  [{s.register}+{s.slot_offset:#x}]  ({s.encoding})'
                    )

        if dead:
            lines.append(f'  DEAD  ({len(dead)} slots — no dispatch sites):')
            for name in sorted(dead.keys()):
                lines.append(f'    {name}')

        return '\n'.join(lines)
