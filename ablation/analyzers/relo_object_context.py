"""
relo_object_context.py: context for ELF32 relocatable object files (.o).

Why this exists:
  BinaryContext is designed for linked ELFs: it relies on PLT stubs, virtual
  address spaces, and LIEF for section mapping.  ELF32 relocatable objects
  (PPC32 VxWorks firmware, static library members) have none of these:
    - All addresses are section-relative, not absolute VAs.
    - External calls use bctrl + RELA annotations, not bl to PLT stubs.
    - BinaryContext.load_or_build() returns base_va=0xffffffffffffffff and
      zero func_starts for any relocatable (.o) input.
  Gap ID: RELO-GAP-001 (solidDB VxWorks PPC440 solidac.a analysis).

Usage:
    from ablation.analyzers.relo_object_context import ReloObjectContext

    ctx = ReloObjectContext.from_path('rpc0http.o')
    print(ctx.summary())
    for fn in ctx.functions():
        print(f'  {fn.name}  +0x{fn.offset:x}  size={fn.size}')
    print(ctx.disasm('rpc_http_svc_get'))
    for call in ctx.calls_in('rpc_http_svc_get'):
        print(f'  +0x{call.insn_offset:x}  → {call.sym_name}')
    print('imports:', ctx.imports())
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Capstone is optional; disasm() degrades gracefully without it
_CS_OK = False
try:
    import capstone
    _CS_OK = True
except ImportError:
    pass

# ── ELF constants ─────────────────────────────────────────────────────────────

_ELFMAG        = b'\x7fELF'
_ELFCLASS32    = 1
_ELFDATA2MSB   = 2    # big-endian
_ET_REL        = 1

_SHT_PROGBITS  = 1
_SHT_SYMTAB    = 2
_SHT_STRTAB    = 3
_SHT_RELA      = 4
_SHT_REL       = 9

_SHN_UNDEF     = 0
_SHN_ABS       = 0xfff1
_SHN_COMMON    = 0xfff2

_STB_LOCAL     = 0
_STB_GLOBAL    = 1
_STB_WEAK      = 2

_STT_NOTYPE    = 0
_STT_OBJECT    = 1
_STT_FUNC      = 2
_STT_SECTION   = 3
_STT_FILE      = 4

# PPC32 reloc types
_R_PPC_NONE        = 0
_R_PPC_ADDR32      = 1
_R_PPC_ADDR16_LO   = 4
_R_PPC_ADDR16_HA   = 6
_R_PPC_REL24       = 10   # bl to local symbol

# ELF32 struct sizes
_ELF32_EHDR_SIZE   = 52
_ELF32_SHDR_SIZE   = 40
_ELF32_SYM_SIZE    = 16
_ELF32_RELA_SIZE   = 12
_ELF32_REL_SIZE    = 8

# Architecture codes
_EM_PPC   = 0x14   # PowerPC 32-bit
_EM_ARM   = 0x28
_EM_MIPS  = 0x08


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ReloFunction:
    name: str
    offset: int   # section-relative byte offset within .text
    size: int
    binding: str  # 'global' | 'local' | 'weak'


@dataclass
class ReloCall:
    insn_offset: int   # section-relative offset of the lis/bl instruction
    sym_name: str      # target symbol name
    is_rodata: bool    # True if the symbol references .rodata* data
    reloc_type: int    # R_PPC_ADDR16_HA or R_PPC_REL24


# ── Internal ELF32 section descriptor ────────────────────────────────────────

@dataclass
class _Section:
    name: str
    sh_type: int
    offset: int   # file offset of section data
    size: int
    link: int
    info: int
    entsize: int
    idx: int      # section index


# ── Main class ────────────────────────────────────────────────────────────────

class ReloObjectContext:
    """
    Context for an ELF32 relocatable object file.

    Parses section table, symbol table, and RELA entries to provide:
      - function list with section-relative offsets
      - annotated capstone disassembly
      - per-function call list (external symbol names from RELA)
      - import / export enumeration
    """

    def __init__(self, data: bytes, path: str = '<buffer>') -> None:
        self.path = path
        self._data = data
        self._big_endian: bool = True
        self._fmt: str = '>'
        self._e_machine: int = 0

        # Filled by _parse()
        self._sections: List[_Section] = []
        self._sec_by_name: Dict[str, _Section] = {}
        self._sym_list: List[Tuple[str, int, int, int, int, int]] = []
        # (name, value, size, info, other, shndx)
        self._text_sec: Optional[_Section] = None
        self._rodata_sec_idxs: List[int] = []   # section indices for .rodata* sections
        self._rodata_ranges: List[Tuple[int, int]] = []  # (start, end) section-relative

        # Main products
        self._rela_map: Dict[int, Tuple[str, bool]] = {}
        # key: section-relative insn offset, value: (sym_name, is_rodata)
        self._func_list: List[ReloFunction] = []
        self._func_by_name: Dict[str, ReloFunction] = {}

        self._cs: Optional[object] = None
        self._parse()

    @classmethod
    def from_path(cls, path: str) -> 'ReloObjectContext':
        data = Path(path).read_bytes()
        return cls(data, path)

    # ── ELF parsing ───────────────────────────────────────────────────────────

    def _u16(self, off: int) -> int:
        return struct.unpack_from(self._fmt + 'H', self._data, off)[0]

    def _u32(self, off: int) -> int:
        return struct.unpack_from(self._fmt + 'I', self._data, off)[0]

    def _i32(self, off: int) -> int:
        return struct.unpack_from(self._fmt + 'i', self._data, off)[0]

    def _parse(self) -> None:
        data = self._data
        if len(data) < _ELF32_EHDR_SIZE:
            return
        if data[:4] != _ELFMAG:
            return
        if data[4] != _ELFCLASS32:
            return

        self._big_endian = (data[5] == _ELFDATA2MSB)
        self._fmt = '>' if self._big_endian else '<'

        e_type = self._u16(0x10)
        if e_type != _ET_REL:
            return   # not a relocatable object

        self._e_machine = self._u16(0x12)

        e_shoff     = self._u32(0x20)
        e_shentsize = self._u16(0x2e)
        e_shnum     = self._u16(0x30)
        e_shstrndx  = self._u16(0x32)

        if e_shoff == 0 or e_shnum == 0:
            return

        # Read all section headers
        raw_secs: List[Tuple] = []
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            if base + _ELF32_SHDR_SIZE > len(data):
                break
            sh_name    = self._u32(base + 0x00)
            sh_type    = self._u32(base + 0x04)
            sh_offset  = self._u32(base + 0x10)
            sh_size    = self._u32(base + 0x14)
            sh_link    = self._u32(base + 0x18)
            sh_info    = self._u32(base + 0x1c)
            sh_entsize = self._u32(base + 0x24)
            raw_secs.append((sh_name, sh_type, sh_offset, sh_size, sh_link, sh_info, sh_entsize))

        # Resolve section names via shstrtab
        if e_shstrndx < len(raw_secs):
            shstr_off  = raw_secs[e_shstrndx][2]
            shstr_size = raw_secs[e_shstrndx][3]
            shstrtab   = data[shstr_off:shstr_off + shstr_size]
        else:
            shstrtab = b''

        def sec_name(name_idx: int) -> str:
            end = shstrtab.find(b'\x00', name_idx)
            return shstrtab[name_idx:end].decode('utf-8', 'replace') if end >= 0 else ''

        for i, (sh_name_idx, sh_type, sh_offset, sh_size, sh_link, sh_info, sh_entsize) in enumerate(raw_secs):
            name = sec_name(sh_name_idx)
            sec = _Section(
                name=name,
                sh_type=sh_type,
                offset=sh_offset,
                size=sh_size,
                link=sh_link,
                info=sh_info,
                entsize=sh_entsize,
                idx=i,
            )
            self._sections.append(sec)
            # Keep last value if duplicate names exist (shouldn't happen, but be safe)
            self._sec_by_name[name] = sec

        # Identify .text section (prefer '.text', then first SHT_PROGBITS+SHF_EXECINSTR)
        for sec in self._sections:
            if sec.name == '.text' and sec.sh_type == _SHT_PROGBITS:
                self._text_sec = sec
                break
        if self._text_sec is None:
            for sec in self._sections:
                if sec.sh_type == _SHT_PROGBITS and sec.size > 0:
                    self._text_sec = sec
                    break

        # Identify .rodata sections
        for sec in self._sections:
            if sec.name.startswith('.rodata') or sec.name in ('__const', '.rdata', '.data.rel.ro'):
                self._rodata_sec_idxs.append(sec.idx)
                # rodata ranges are section-relative within THEIR section.
                # For argument classification we store them as (0, size) because
                # RELA-based detection is more reliable for relocatable objects.
                self._rodata_ranges.append((0, sec.size))

        # Parse symbol table
        self._parse_symbols()

        # Parse RELA sections targeting .text
        text_idx = self._text_sec.idx if self._text_sec else -1
        for sec in self._sections:
            if sec.sh_type == _SHT_RELA and sec.info == text_idx:
                self._parse_rela(sec)

        # Build function list
        self._build_func_list()

        # Set up capstone
        if _CS_OK:
            self._init_capstone()

    def _parse_symbols(self) -> None:
        symtab = self._sec_by_name.get('.symtab')
        if symtab is None:
            return
        strtab_sec = self._sections[symtab.link] if 0 < symtab.link < len(self._sections) else None
        if strtab_sec is None:
            return
        strtab = self._data[strtab_sec.offset:strtab_sec.offset + strtab_sec.size]
        esz = symtab.entsize if symtab.entsize else _ELF32_SYM_SIZE
        n = symtab.size // esz
        for i in range(n):
            base = symtab.offset + i * esz
            if base + _ELF32_SYM_SIZE > len(self._data):
                break
            st_name  = self._u32(base + 0x00)
            st_value = self._u32(base + 0x04)
            st_size  = self._u32(base + 0x08)
            st_info  = self._data[base + 0x0c]
            st_other = self._data[base + 0x0d]
            st_shndx = self._u16(base + 0x0e)
            # Resolve name
            end = strtab.find(b'\x00', st_name)
            name = strtab[st_name:end].decode('utf-8', 'replace') if end >= 0 else ''
            self._sym_list.append((name, st_value, st_size, st_info, st_other, st_shndx))

    def _parse_rela(self, sec: _Section) -> None:
        """Parse a RELA section, building _rela_map for .text annotations."""
        data = self._data
        esz = sec.entsize if sec.entsize else _ELF32_RELA_SIZE
        n = sec.size // esz
        symtab_sec = self._sections[sec.link] if 0 < sec.link < len(self._sections) else None

        for i in range(n):
            base = sec.offset + i * esz
            if base + _ELF32_RELA_SIZE > len(data):
                break
            r_offset = self._u32(base + 0x00)
            r_info   = self._u32(base + 0x04)
            # r_addend = self._i32(base + 0x08)  # reserved for future use

            r_sym  = r_info >> 8
            r_type = r_info & 0xff

            # Resolve symbol
            sym_name = ''
            sym_shndx = _SHN_UNDEF
            if r_sym < len(self._sym_list):
                sym_name, _, _, sym_info, _, sym_shndx = self._sym_list[r_sym]

            # Determine if symbol refers to .rodata
            is_rodata = sym_shndx in self._rodata_sec_idxs

            if r_type == _R_PPC_ADDR16_HA:
                # HA reloc: r_offset points to byte 2 of the lis instruction.
                # Instruction start = r_offset - 2.
                insn_offset = r_offset - 2
                # Only record if not already annotated (prefer first annotation per insn)
                if insn_offset not in self._rela_map:
                    self._rela_map[insn_offset] = (sym_name, is_rodata)

            elif r_type == _R_PPC_REL24:
                # REL24: r_offset is the instruction start (bl/blr to local symbol)
                insn_offset = r_offset
                if insn_offset not in self._rela_map:
                    self._rela_map[insn_offset] = (sym_name, is_rodata)

            elif r_type == _R_PPC_ADDR32:
                # Full 32-bit reloc; not an instruction annotation
                pass

    def _build_func_list(self) -> None:
        if self._text_sec is None:
            return
        text_idx = self._text_sec.idx
        text_size = self._text_sec.size
        funcs: List[ReloFunction] = []

        for name, st_value, st_size, st_info, _, st_shndx in self._sym_list:
            if st_shndx != text_idx:
                continue
            if not name:
                continue
            sym_type    = st_info & 0xf
            sym_binding = st_info >> 4
            # STT_FUNC always included; STT_NOTYPE only when size > 0 (labels have size=0)
            if sym_type == _STT_NOTYPE and st_size == 0:
                continue
            if sym_type not in (_STT_FUNC, _STT_NOTYPE):
                continue

            binding_str = {_STB_LOCAL: 'local', _STB_GLOBAL: 'global', _STB_WEAK: 'weak'}.get(
                sym_binding, 'local'
            )

            # Infer size if zero: use distance to next symbol
            size = st_size
            if size == 0:
                size = 4  # minimum guess; will be refined below

            funcs.append(ReloFunction(
                name=name,
                offset=st_value,
                size=size,
                binding=binding_str,
            ))

        # Sort by offset, then infer sizes for size=0/tiny entries
        funcs.sort(key=lambda f: f.offset)
        for i, fn in enumerate(funcs):
            if fn.size <= 4:
                if i + 1 < len(funcs):
                    inferred = funcs[i + 1].offset - fn.offset
                    if inferred > 0:
                        fn.size = inferred
                elif text_size > fn.offset:
                    fn.size = text_size - fn.offset

        self._func_list = funcs
        self._func_by_name = {f.name: f for f in funcs}

    def _init_capstone(self) -> None:
        if not _CS_OK:
            return
        if self._e_machine == _EM_PPC:
            mode = capstone.CS_MODE_32
            if self._big_endian:
                mode |= capstone.CS_MODE_BIG_ENDIAN
            self._cs = capstone.Cs(capstone.CS_ARCH_PPC, mode)
        elif self._e_machine == _EM_ARM:
            mode = capstone.CS_MODE_ARM
            if self._big_endian:
                mode |= capstone.CS_MODE_BIG_ENDIAN
            self._cs = capstone.Cs(capstone.CS_ARCH_ARM, mode)
        # Add more architectures here as needed

    # ── Public API ────────────────────────────────────────────────────────────

    def functions(self) -> List[ReloFunction]:
        """All functions defined in .text, sorted by offset."""
        return list(self._func_list)

    def function_names(self) -> List[str]:
        """Names of all defined functions."""
        return [f.name for f in self._func_list]

    def imports(self) -> List[str]:
        """All external symbol names referenced (SHN_UNDEF, non-empty name)."""
        seen = set()
        result = []
        for name, _, _, _, _, shndx in self._sym_list:
            if shndx == _SHN_UNDEF and name and name not in seen:
                seen.add(name)
                result.append(name)
        return sorted(result)

    def exports(self) -> List[str]:
        """All globally-defined symbol names (non-UNDEF, non-empty, STB_GLOBAL)."""
        seen = set()
        result = []
        for name, _, _, st_info, _, shndx in self._sym_list:
            if shndx not in (_SHN_UNDEF, _SHN_ABS, _SHN_COMMON) and name:
                binding = st_info >> 4
                if binding in (_STB_GLOBAL, _STB_WEAK) and name not in seen:
                    seen.add(name)
                    result.append(name)
        return sorted(result)

    def has_import(self, sym: str) -> bool:
        """True if the object references external symbol `sym`."""
        return any(
            name == sym and shndx == _SHN_UNDEF
            for name, _, _, _, _, shndx in self._sym_list
        )

    def calls_in(self, fn_name: str) -> List[ReloCall]:
        """
        All external/local calls within the named function, derived from RELA entries.
        Returns one ReloCall per HA reloc or REL24 reloc within the function's range.
        """
        fn = self._func_by_name.get(fn_name)
        if fn is None:
            return []
        fn_end = fn.offset + fn.size
        result = []
        for insn_off, (sym_name, is_rodata) in sorted(self._rela_map.items()):
            if fn.offset <= insn_off < fn_end:
                # Classify reloc type from the offset alignment:
                # REL24 entries are at instruction start; HA entries are at insn+2
                # We stored them all at the insn start, so we can't easily distinguish.
                # Use a heuristic: if sym_name is '' (section ref), it's not a function call.
                if sym_name or not is_rodata:
                    result.append(ReloCall(
                        insn_offset=insn_off,
                        sym_name=sym_name,
                        is_rodata=is_rodata,
                        reloc_type=_R_PPC_ADDR16_HA,
                    ))
        return result

    def functions_calling(self, sym: str) -> List[str]:
        """Names of functions in this object that reference external symbol `sym`."""
        result = []
        for fn in self._func_list:
            for call in self.calls_in(fn.name):
                if call.sym_name == sym:
                    result.append(fn.name)
                    break
        return result

    def rela_map(self) -> Dict[int, Tuple[str, bool]]:
        """
        Raw RELA annotation map: {section_relative_insn_offset: (sym_name, is_rodata)}.
        The is_rodata flag is True when the reloc references a .rodata* section.
        """
        return dict(self._rela_map)

    def text_bytes(self, fn_name: str) -> Tuple[bytes, int]:
        """
        Returns (raw_bytes, section_relative_offset) for the named function.
        Raises KeyError if function not found.
        """
        fn = self._func_by_name.get(fn_name)
        if fn is None:
            raise KeyError(f'function not found: {fn_name!r}')
        if self._text_sec is None:
            return b'', fn.offset
        raw = self._data[self._text_sec.offset + fn.offset:
                         self._text_sec.offset + fn.offset + fn.size]
        return raw, fn.offset

    def rodata_section_indices(self) -> List[int]:
        """Section indices of all .rodata* sections."""
        return list(self._rodata_sec_idxs)

    def read_section_data(self, sec_name: str) -> bytes:
        """Raw bytes of the named section, or b'' if not found."""
        sec = self._sec_by_name.get(sec_name)
        if sec is None:
            return b''
        return self._data[sec.offset:sec.offset + sec.size]

    def disasm(self, fn_name: str, annotated: bool = True) -> str:
        """
        Return a formatted disassembly string for the named function.
        With annotated=True, each lis instruction that has a RELA entry is
        annotated with the target symbol name.
        Requires capstone to be installed; returns a placeholder otherwise.
        """
        fn = self._func_by_name.get(fn_name)
        if fn is None:
            return f'; function not found: {fn_name!r}\n'
        raw, base_off = self.text_bytes(fn_name)
        if not raw:
            return f'; no text for {fn_name!r}\n'

        if self._cs is None:
            return f'; capstone not available for {fn_name!r}\n'

        lines = [f'; {fn_name}  +0x{fn.offset:06x}  size={fn.size}  [{fn.binding}]']
        for insn in self._cs.disasm(raw, base_off):
            ann = ''
            if annotated:
                entry = self._rela_map.get(insn.address)
                if entry:
                    sym_name, is_rodata = entry
                    tag = '.rodata' if is_rodata else sym_name or '??'
                    ann = f'  ← {tag}'
            lines.append(f'  {insn.address:06x}  {insn.mnemonic:<10} {insn.op_str:<36}{ann}')
        return '\n'.join(lines) + '\n'

    def summary(self) -> str:
        arch_names = {_EM_PPC: 'PPC32', _EM_ARM: 'ARM32', _EM_MIPS: 'MIPS32'}
        arch = arch_names.get(self._e_machine, f'EM0x{self._e_machine:x}')
        endian = 'BE' if self._big_endian else 'LE'
        text_size = self._text_sec.size if self._text_sec else 0
        return (
            f'ReloObjectContext({Path(self.path).name}): '
            f'{arch} {endian}, '
            f'{len(self._func_list)} functions, '
            f'{len(self.imports())} imports, '
            f'.text={text_size}B'
        )
