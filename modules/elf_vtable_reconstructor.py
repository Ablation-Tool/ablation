"""
ELFVtableReconstructor — static C++ vtable reconstruction for x86-64 ET_DYN ELFs.

Reconstructs the runtime vtable slot→function map from .rela.dyn without executing
the binary. Handles R_X86_64_RELATIVE (type 8, in-library functions) and R_X86_64_64
(type 1, exported symbol references).

See docs/module-reference/vtable-x86-64.md for full documentation.
"""

import struct
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class VtableSlot:
    slot_index: int
    slot_offset: int       # byte offset from vtable_ptr (= vtable_va + 0x10)
    abs_va: int            # absolute VA of this slot entry
    function_va: int       # resolved target function VA
    function_name: str     # demangled or sub_0x... fallback
    is_rtti: bool          # True for RTTI/typeinfo entries

    def is_live(self) -> bool:
        return self.function_va > 0x1000 and not self.is_rtti


class VtableMap:
    def __init__(self, vtable_va: int, vtable_ptr: int,
                 slots: Dict[int, VtableSlot], class_name: str = ""):
        self.vtable_va = vtable_va
        self.vtable_ptr = vtable_ptr
        self.slots = slots
        self.class_name = class_name

    def get_slot(self, offset: int) -> Optional[VtableSlot]:
        return self.slots.get(offset)

    def function_at(self, offset: int) -> Optional[str]:
        s = self.slots.get(offset)
        return s.function_name if s else None

    def va_at(self, offset: int) -> int:
        s = self.slots.get(offset)
        return s.function_va if s else 0

    def live_slots(self) -> Dict[int, VtableSlot]:
        return {off: s for off, s in self.slots.items() if s.is_live()}

    def slot_for_va(self, function_va: int) -> Optional[VtableSlot]:
        for s in self.slots.values():
            if s.function_va == function_va:
                return s
        return None

    def slot_offset_for_name(self, fragment: str) -> Optional[int]:
        """Return slot_offset for the first slot whose name contains fragment."""
        for off, s in self.slots.items():
            if fragment in s.function_name:
                return off
        return None


class ELFVtableReconstructor:
    """
    Reconstructs C++ vtables from .rela.dyn for x86-64 ET_DYN ELF files.

    Usage:
        rec = ELFVtableReconstructor.from_path('/path/to/lib.so')
        vtable = rec.reconstruct_class('MyClass')
        # or
        vtable = rec.reconstruct(vtable_va=0x92d540)
    """

    def __init__(self, elf_path: str):
        self.elf_path = elf_path
        with open(elf_path, 'rb') as f:
            self._data = f.read()
        self._sections: Dict[str, dict] = {}
        self._dynsym: List[dict] = []
        self._symtab: List[dict] = []
        self._text_ranges: List[Tuple[int, int]] = []
        self._parse_elf()

    @classmethod
    def from_path(cls, elf_path: str) -> 'ELFVtableReconstructor':
        return cls(elf_path)

    # ------------------------------------------------------------------
    # ELF parsing
    # ------------------------------------------------------------------

    def _parse_elf(self) -> None:
        data = self._data
        if data[:4] != b'\x7fELF':
            raise ValueError('Not an ELF file')
        if data[4] != 2:
            raise ValueError('Only ELF64 supported')

        e_shoff = struct.unpack_from('<Q', data, 40)[0]
        e_shentsize = struct.unpack_from('<H', data, 58)[0]
        e_shnum = struct.unpack_from('<H', data, 60)[0]
        e_shstrndx = struct.unpack_from('<H', data, 62)[0]
        shstr_off = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 24)[0]

        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            nameoff = struct.unpack_from('<I', data, sh)[0]
            end = data.index(b'\x00', shstr_off + nameoff)
            name = data[shstr_off + nameoff:end].decode('utf-8', errors='replace')

            self._sections[name] = {
                'type':    struct.unpack_from('<I', data, sh + 4)[0],
                'flags':   struct.unpack_from('<Q', data, sh + 8)[0],
                'addr':    struct.unpack_from('<Q', data, sh + 16)[0],
                'off':     struct.unpack_from('<Q', data, sh + 24)[0],
                'size':    struct.unpack_from('<Q', data, sh + 32)[0],
                'link':    struct.unpack_from('<I', data, sh + 40)[0],
                'entsize': struct.unpack_from('<Q', data, sh + 56)[0],
            }

        if '.dynsym' in self._sections and '.dynstr' in self._sections:
            self._dynsym = self._parse_symtab('.dynsym', '.dynstr')
        if '.symtab' in self._sections and '.strtab' in self._sections:
            self._symtab = self._parse_symtab('.symtab', '.strtab')

        # Collect executable section VA ranges
        for sec in self._sections.values():
            if sec['flags'] & 0x4 and sec['size'] > 0:  # SHF_EXECINSTR
                self._text_ranges.append((sec['addr'], sec['addr'] + sec['size']))

    def _parse_symtab(self, sym_sec_name: str, str_sec_name: str) -> List[dict]:
        data = self._data
        sym_sec = self._sections[sym_sec_name]
        str_sec = self._sections[str_sec_name]
        str_off = str_sec['off']
        entsize = sym_sec['entsize'] or 24
        symbols = []
        for j in range(0, sym_sec['size'], entsize):
            off = sym_sec['off'] + j
            nameoff = struct.unpack_from('<I', data, off)[0]
            end = data.index(b'\x00', str_off + nameoff)
            name = data[str_off + nameoff:end].decode('utf-8', errors='replace')
            symbols.append({
                'name':   name,
                'value':  struct.unpack_from('<Q', data, off + 8)[0],
                'size':   struct.unpack_from('<Q', data, off + 16)[0],
                'info':   data[off + 4],
                'shndx':  struct.unpack_from('<H', data, off + 6)[0],
            })
        return symbols

    # ------------------------------------------------------------------
    # Symbol helpers
    # ------------------------------------------------------------------

    def _name_for_va(self, va: int) -> str:
        for sym in self._symtab:
            if sym['value'] == va and sym['name']:
                return self._demangle(sym['name'])
        for sym in self._dynsym:
            if sym['value'] == va and sym['name']:
                return self._demangle(sym['name'])
        return f'sub_{va:#010x}'

    def _va_for_mangled(self, mangled: str) -> int:
        for sym in self._symtab + self._dynsym:
            if sym['name'] == mangled:
                return sym['value']
        return 0

    def _demangle(self, name: str) -> str:
        if not name.startswith('_Z'):
            return name
        try:
            r = subprocess.run(['c++filt', name], capture_output=True, text=True, timeout=2)
            return r.stdout.strip() or name
        except Exception:
            return name

    def _is_function_va(self, va: int) -> bool:
        for start, end in self._text_ranges:
            if start <= va < end:
                return True
        return False

    # ------------------------------------------------------------------
    # Reconstruction
    # ------------------------------------------------------------------

    def reconstruct(self, vtable_va: int, max_size: int = 0x10000) -> VtableMap:
        """
        Reconstruct the vtable at vtable_va.

        Scans .rela.dyn for entries in [vtable_va, vtable_va + max_size).
        vtable_ptr = vtable_va + 0x10 (skip offset-to-top and RTTI pointer).
        Slot offsets in the returned map are relative to vtable_ptr.
        """
        data = self._data
        vtable_ptr = vtable_va + 0x10
        vtable_end = vtable_va + max_size

        if '.rela.dyn' not in self._sections:
            return VtableMap(vtable_va, vtable_ptr, {})

        rela = self._sections['.rela.dyn']
        slots: Dict[int, VtableSlot] = {}

        for j in range(0, rela['size'], 24):
            r_offset = struct.unpack_from('<Q', data, rela['off'] + j)[0]
            if not (vtable_va <= r_offset < vtable_end):
                continue

            r_info   = struct.unpack_from('<Q', data, rela['off'] + j + 8)[0]
            r_addend = struct.unpack_from('<q', data, rela['off'] + j + 16)[0]
            r_type   = r_info & 0xffffffff
            r_sym    = r_info >> 32

            if r_type == 8:  # R_X86_64_RELATIVE: fn_va = base + addend (base=0 for analysis)
                fn_va   = r_addend
                fn_name = self._name_for_va(fn_va) if fn_va else ''
            elif r_type == 1:  # R_X86_64_64: fn_va = sym_value + addend
                if r_sym < len(self._dynsym):
                    sym    = self._dynsym[r_sym]
                    fn_va  = sym['value'] + r_addend
                    fn_name = (self._demangle(sym['name'])
                               if sym['name'] else self._name_for_va(fn_va))
                else:
                    fn_va   = r_addend
                    fn_name = self._name_for_va(fn_va)
            else:
                continue

            is_rtti   = not self._is_function_va(fn_va) if fn_va else True
            slot_off  = r_offset - vtable_ptr
            slot_idx  = slot_off // 8 if slot_off >= 0 else (slot_off // 8)

            slots[slot_off] = VtableSlot(
                slot_index=slot_idx,
                slot_offset=slot_off,
                abs_va=r_offset,
                function_va=fn_va,
                function_name=fn_name,
                is_rtti=is_rtti,
            )

        return VtableMap(vtable_va=vtable_va, vtable_ptr=vtable_ptr, slots=slots)

    def reconstruct_class(self, class_name: str, max_size: int = 0x10000) -> VtableMap:
        """
        Reconstruct the vtable for a C++ class.

        class_name may be:
          - A plain class name ('MyClass') — the mangled vtable symbol
            '_ZTV<len><name>' is looked up automatically.
          - A full mangled vtable symbol ('_ZTV7MyClass').
        """
        va = self._va_for_mangled(class_name)
        if not va:
            mangled = f'_ZTV{len(class_name)}{class_name}'
            va = self._va_for_mangled(mangled)
        if not va:
            raise ValueError(f'No vtable symbol for {class_name!r} in {self.elf_path}')

        m = self.reconstruct(va, max_size)
        m.class_name = class_name
        return m

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def report(vtable_map: VtableMap) -> str:
        live = sorted(
            [(off, s) for off, s in vtable_map.slots.items() if s.is_live()],
            key=lambda x: x[0],
        )
        rtti = sorted(
            [(off, s) for off, s in vtable_map.slots.items() if s.is_rtti],
            key=lambda x: x[0],
        )
        lines = [
            f'VtableMap  class={vtable_map.class_name!r}',
            f'  vtable_va={vtable_map.vtable_va:#010x}  '
            f'vtable_ptr={vtable_map.vtable_ptr:#010x}',
            f'  {len(live)} virtual functions, {len(rtti)} RTTI/meta entries',
            '',
            f'  Virtual functions:',
        ]
        for off, s in live:
            lines.append(
                f'    [{s.slot_index:4d}]  +{off:#06x}  '
                f'{s.function_va:#010x}  {s.function_name}'
            )
        if rtti:
            lines.append(f'\n  RTTI / meta entries (first 8):')
            for off, s in rtti[:8]:
                lines.append(
                    f'    +{off:+#06x}  va={s.function_va:#010x}  {s.function_name}'
                )
        return '\n'.join(lines)
