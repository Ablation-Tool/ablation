"""VxWorks static archive strcpy-in-frame scanner.

Scans PPC (32-bit big-endian) VxWorks static archive (.a) files for strcpy
call sites inside functions with stack frame sizes in a given range. Designed
for solidDB 6.0 PPC440 and compatible VxWorks 6.x embedded targets.

Why this exists
---------------
1. VxWorks ships as a static library that is linked into a kernel image; there
   is no standalone binary to load with BinaryContext. Existing scanners
   operate on ELF or XCOFF executables and reject .a archives outright.
2. The PPC440 session scan of 666 objects required a one-off script that
   combined ELF section parsing with Capstone disassembly. That logic is
   now a reusable module covering PPC440, PPC603, and any PPC32 BE VxWorks .a.
3. VxWorks 6.x PPC targets have no ASLR and no stack canaries. A strcpy
   inside a medium-frame function (0x80--0x300 bytes) is exploitable without
   bypass gadgets; this range is therefore the primary triage filter.

Usage::

    from ablation.analyzers.vxworks_archive_scanner import VxWorksArchiveScanner

    results = VxWorksArchiveScanner('/path/to/solidac.a').scan_strcpy_in_frame()
    for r in results:
        print(f'{r.obj_file}:{r.func_name}  call_va={r.call_va:#010x}  '
              f'frame={r.frame_size:#x}  callee={r.callee_name!r}')
"""
from __future__ import annotations

import struct
import subprocess
from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import List, Optional

_MAX_ARCHIVE_BYTES = 128 * 1024 * 1024   # 128 MB cap for the .a archive itself
_MAX_MEMBER_BYTES  =  16 * 1024 * 1024   # 16 MB cap per extracted .o member


@dataclass
class ArchiveSite:
    """One strcpy (or similar unbounded copy) call site found in a .o member."""

    obj_file:    str            # member name inside the archive
    func_name:   str            # enclosing function symbol name (if known)
    func_va:     int            # function start offset in .text
    call_va:     int            # offset of the bl instruction
    frame_size:  int            # stack frame allocated by stwu at function entry
    callee_name: str            # target symbol name from .rela.text (or hex addr)


def _read_u32be(data: bytes, off: int) -> int:
    return struct.unpack_from('>I', data, off)[0]


def _read_u16be(data: bytes, off: int) -> int:
    return struct.unpack_from('>H', data, off)[0]


def _read_u16le(data: bytes, off: int) -> int:
    return struct.unpack_from('<H', data, off)[0]


def _parse_elf32_ppc(raw: bytes):
    """Parse ELF32 BE sections, symbols, and .rela.text from a .o member.

    Returns (text_data, text_off_in_raw, syms, relas) where:
      syms  = {symbol_index: {'name': str, 'value': int, 'size': int, 'shndx': int}}
      relas = {text_offset: callee_name}
    Returns None if the data is not a valid PPC ELF32.
    """
    if len(raw) < 52 or raw[:4] != b'\x7fELF':
        return None
    if raw[4] != 1:        # EI_CLASS != ELFCLASS32
        return None
    if raw[5] != 2:        # EI_DATA != ELFDATA2MSB
        return None
    if _read_u16be(raw, 18) != 20:    # e_machine != EM_PPC
        return None

    e_shoff     = _read_u32be(raw, 32)
    e_shentsize = _read_u16be(raw, 46)
    e_shnum     = _read_u16be(raw, 48)
    e_shstrndx  = _read_u16be(raw, 50)

    shstr_sh = e_shoff + e_shstrndx * e_shentsize
    shstr_off  = _read_u32be(raw, shstr_sh + 16)
    shstrtab = raw[shstr_off:shstr_off + 2048]

    def sh_name(i: int) -> str:
        sh = e_shoff + i * e_shentsize
        name_off = _read_u32be(raw, sh)
        try:
            end = shstrtab.index(b'\x00', name_off)
        except (ValueError, IndexError):
            return ''
        return shstrtab[name_off:end].decode('ascii', errors='replace')

    def sh_offset(i: int) -> int:
        return _read_u32be(raw, e_shoff + i * e_shentsize + 16)

    def sh_size(i: int) -> int:
        return _read_u32be(raw, e_shoff + i * e_shentsize + 20)

    text_data = b''
    text_file_off = 0
    sym_off = sym_size = str_off = str_size = 0
    rela_off = rela_size = 0

    for i in range(e_shnum):
        name = sh_name(i)
        off = sh_offset(i)
        sz = sh_size(i)
        if name == '.text':
            text_file_off = off
            text_data = raw[off:off + sz]
        elif name == '.symtab':
            sym_off, sym_size = off, sz
        elif name == '.strtab':
            str_off, str_size = off, sz
        elif name == '.rela.text':
            rela_off, rela_size = off, sz

    if not text_data or not sym_size:
        return None

    sym_data = raw[sym_off:sym_off + sym_size]
    str_data = raw[str_off:str_off + str_size]

    syms = {}
    for i in range(sym_size // 16):
        s = sym_data[i * 16:(i + 1) * 16]
        st_name, st_value, st_size, st_info, _st_other, st_shndx = struct.unpack_from('>IIIBBH', s)
        try:
            end = str_data.index(b'\x00', st_name)
            sname = str_data[st_name:end].decode('ascii', errors='replace')
        except (ValueError, IndexError):
            sname = ''
        syms[i] = {'name': sname, 'value': st_value, 'size': st_size, 'shndx': st_shndx}

    relas: dict[int, str] = {}
    if rela_off:
        for j in range(rela_size // 12):
            roff = rela_off + j * 12
            r_offset = _read_u32be(raw, roff)
            r_info   = _read_u32be(raw, roff + 4)
            sym_idx  = r_info >> 8
            sname = syms.get(sym_idx, {}).get('name', '')
            relas[r_offset] = sname

    return text_data, text_file_off, syms, relas


def _func_at(syms: dict, text_offset: int) -> tuple[str, int, int]:
    """Return (name, start, size) for the function containing text_offset."""
    best_name, best_va, best_sz = '', 0, 0
    for s in syms.values():
        # shndx==1 = .text section; type FUNC (st_info low nibble 2)
        if s['shndx'] != 1 or s['size'] == 0:
            continue
        va = s['value']
        sz = s['size']
        if va <= text_offset < va + sz:
            if sz < best_sz or best_sz == 0:
                best_name, best_va, best_sz = s['name'], va, sz
    return best_name, best_va, best_sz


def _find_frame_size(text_data: bytes, func_va: int) -> int:
    """Scan forward from func_va for stwu r1, -N(r1) to get frame size N."""
    scan = min(func_va + 64, len(text_data) - 4)
    for off in range(func_va, scan, 4):
        word = _read_u32be(text_data, off)
        # stwu r1, SIMM(r1): opcode=37, rS=r1, rA=r1
        # Encoding: (37<<26)|(1<<21)|(1<<16)|SIMM16
        # SIMM16 is negative for allocating: SIMM16 = 0x10000 - frame_size
        if (word >> 26) == 37 and ((word >> 21) & 0x1f) == 1 and ((word >> 16) & 0x1f) == 1:
            simm16 = word & 0xFFFF
            if simm16 >= 0x8000:        # negative (sign extend)
                return 0x10000 - simm16
    return 0


class VxWorksArchiveScanner:
    """Scans a PPC32 BE VxWorks static archive for strcpy calls in medium-size frames.

    Args:
        archive_path: Path to the .a archive.
        targets:      Set of callee names to flag as dangerous.
                      Defaults to the standard unbounded copy set.
    """

    _DEFAULT_TARGETS = frozenset({'strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf'})

    def __init__(
        self,
        archive_path: str | Path,
        targets: Optional[frozenset] = None,
    ):
        archive_path = str(archive_path)
        arc_size = os.path.getsize(archive_path)
        if arc_size > _MAX_ARCHIVE_BYTES:
            raise ValueError(
                f'{archive_path}: archive size {arc_size} exceeds {_MAX_ARCHIVE_BYTES} byte limit')
        self.archive_path = archive_path
        self._targets = targets if targets is not None else self._DEFAULT_TARGETS

    @classmethod
    def from_context(cls, ctx) -> 'VxWorksArchiveScanner':
        """Construct from a BinaryContext whose path is an archive."""
        return cls(ctx.path)

    def _list_members(self) -> List[str]:
        result = subprocess.run(
            ['ar', 't', self.archive_path],
            capture_output=True, text=True,
        )
        return [m.strip() for m in result.stdout.splitlines() if m.strip()]

    def _extract_member(self, name: str) -> bytes:
        result = subprocess.run(
            ['ar', 'p', self.archive_path, name],
            capture_output=True,
        )
        data = result.stdout
        if len(data) > _MAX_MEMBER_BYTES:
            return b''
        return data

    def scan_strcpy_in_frame(
        self,
        frame_min: int = 0x80,
        frame_max: int = 0x300,
    ) -> List[ArchiveSite]:
        """Scan all .o members for unbounded copy calls inside bounded frames.

        Args:
            frame_min: Minimum frame size to include (bytes).
            frame_max: Maximum frame size to include (bytes).

        Returns:
            List of ArchiveSite findings, sorted by frame size descending.
        """
        try:
            from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
        except ImportError:
            return []

        cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)

        findings: List[ArchiveSite] = []
        members = self._list_members()

        for obj_name in members:
            raw = self._extract_member(obj_name)
            parsed = _parse_elf32_ppc(raw)
            if parsed is None:
                continue
            text_data, _text_file_off, syms, relas = parsed

            for instr in cs.disasm(text_data, 0):
                if instr.mnemonic != 'bl':
                    continue
                call_va = instr.address
                callee = relas.get(call_va, '')
                if callee not in self._targets:
                    continue

                func_name, func_va, func_sz = _func_at(syms, call_va)
                if func_va == 0 and func_sz == 0:
                    continue

                frame = _find_frame_size(text_data, func_va)
                if frame_min <= frame <= frame_max:
                    findings.append(ArchiveSite(
                        obj_file=obj_name,
                        func_name=func_name,
                        func_va=func_va,
                        call_va=call_va,
                        frame_size=frame,
                        callee_name=callee,
                    ))

        findings.sort(key=lambda s: s.frame_size, reverse=True)
        return findings

    @staticmethod
    def report(findings: List[ArchiveSite]) -> str:
        """Format findings as a text summary."""
        if not findings:
            return 'VxWorksArchiveScanner: no strcpy-in-medium-frame sites found.\n'
        lines = [f'VxWorksArchiveScanner: {len(findings)} site(s)']
        for f in findings:
            lines.append(
                f'  {f.obj_file}:{f.func_name}'
                f'  func_va={f.func_va:#010x}'
                f'  call_va={f.call_va:#010x}'
                f'  frame={f.frame_size:#05x}'
                f'  callee={f.callee_name!r}'
            )
        return '\n'.join(lines) + '\n'
