"""
ppc64_elfv1_resolver.py — PPC64 ELFv1 (big-endian) OPD and glink stub resolver.

Why this exists
---------------

1. **Gap: BinaryContext.plt is empty for PPC64 BE binaries.**
   BinaryContext._extract_plt checks for ELFDATA2LSB and calls the ELFv2 path;
   big-endian PPC64 falls through to the generic JUMP_SLOT loop which maps GOT
   slot VAs, not stub VAs. SinkArgClassifier needs stub VA → symbol_name; the
   generic path produces the wrong keys. Result: plt_entries=0 on every IBM
   Linux POWER binary.

2. **Gap: ctx.func_starts contains OPD entry VAs, not code VAs.**
   On ELFv1, nm/readelf report symbol values as the address of the 24-byte OPD
   descriptor (code_ptr, TOC_ptr, env_ptr), not the code address. Disassembling
   at an OPD VA produces 8 bytes of a pointer, not a function prologue.
   Callers must resolve every symbol VA through the OPD before disassembling.

3. **Gap: BL target decoding on PPC64 requires a sign-extended 24-bit LI.**
   BL word: opcode(6) | LI(24) | AA(1) | LK(1). LI is the number of *words*
   (not bytes) from the instruction. Correct: li24 = (word>>2)&0xFFFFFF; if
   li24&0x800000: li24-=0x1000000; target=src_va+li24*4. Several off-by-one
   errors arise if the shift/sign-extension is applied to the wrong field width.

This module resolves all three:
  • Parses .opd → opd_to_code dict (OPD entry VA → code VA)
  • Parses .rela.plt JMP_SLOTs → glink stub VAs (stub_N = text_va + N*28) → name
  • Provides bl_target() for correct big-endian BL decoding
  • patch_context(ctx) rewrites ctx.plt and ctx.func_starts in-place

Usage
-----
    from ablation.analyzers.ppc64_elfv1_resolver import Ppc64ElfV1Resolver

    res = Ppc64ElfV1Resolver.from_path('/path/to/ppc64be.elf')
    info = res.resolve()

    # Stub map: stub VA -> import name
    print(info.stub_map)
    # OPD resolution: resolve a symbol VA to its code VA
    code_va = info.opd_to_code.get(sym_va)
    # BL target: decode a BL instruction at src_va
    target = info.bl_target(src_va, file_data)

    # Or: patch an existing BinaryContext so PLT and func_starts are correct
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/ppc64be.elf')
    res.patch_context(ctx)
    # ctx.plt now maps stub_VA -> name; ctx.func_starts now lists code VAs

    # Classmethod variant via BinaryContext:
    res = Ppc64ElfV1Resolver.from_context(ctx)
    res.resolve()
    res.patch_context(ctx)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Ppc64ElfV1Info:
    """Resolved ELFv1 metadata for a PPC64 big-endian binary."""

    binary_path: str

    # OPD section bounds
    opd_va: int = 0
    opd_file_off: int = 0
    opd_size: int = 0

    # TOC pointer (read from entry-point OPD entry)
    toc: int = 0

    # .text bounds
    text_va: int = 0
    text_file_off: int = 0
    text_size: int = 0

    # OPD entry VA -> code VA (and TOC, env)
    opd_to_code: Dict[int, int] = field(default_factory=dict)
    opd_to_toc:  Dict[int, int] = field(default_factory=dict)

    # stub VA -> import name
    stub_map: Dict[int, str] = field(default_factory=dict)

    # JMP_SLOT entries: sorted list of (got_va, symbol_name)
    jmp_slots: List[Tuple[int, str]] = field(default_factory=list)

    # Number of glink stubs
    n_stubs: int = 0

    def code_va_for(self, sym_va: int) -> Optional[int]:
        """Resolve an OPD-style symbol VA to its code VA."""
        return self.opd_to_code.get(sym_va)

    def bl_target(self, src_va: int, data: bytes, file_off_base: int = 0) -> Optional[int]:
        """Decode a big-endian BL instruction at src_va and return the target VA.

        file_off_base: add to src_va to get the file offset of the instruction.
        If 0, assumes VA == file offset (valid for non-PIE with text at the same
        address as stored in the file).
        """
        file_off = src_va - self.text_va + self.text_file_off
        if file_off < 0 or file_off + 4 > len(data):
            return None
        word = struct.unpack_from('>I', data, file_off)[0]
        opcode = (word >> 26) & 0x3f
        if opcode != 18:
            return None
        if not (word & 1):  # LK bit must be set for BL
            return None
        li = (word >> 2) & 0xFFFFFF
        if li & 0x800000:
            li -= 0x1000000
        return src_va + li * 4

    def fmt(self) -> str:
        lines = [
            f"Ppc64ElfV1Info({self.binary_path})",
            f"  OPD:   VA={self.opd_va:#x}  off={self.opd_file_off:#x}  sz={self.opd_size:#x}  entries={self.opd_size//24}",
            f"  .text: VA={self.text_va:#x}  off={self.text_file_off:#x}  sz={self.text_size:#x}",
            f"  TOC:   {self.toc:#x}",
            f"  OPD->code entries: {len(self.opd_to_code)}",
            f"  glink stubs: {self.n_stubs}",
        ]
        for va, name in sorted(self.stub_map.items())[:10]:
            lines.append(f"    stub {va:#x} -> {name}")
        if len(self.stub_map) > 10:
            lines.append(f"    ... ({len(self.stub_map) - 10} more)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class Ppc64ElfV1Resolver:
    """Resolves OPD descriptors and glink stubs for PPC64 big-endian ELFv1 binaries.

    Handles IBM Linux POWER (RHEL/SLES ppc64) and AIX-style ELFv1 binaries
    where:
      - .opd section contains 24-byte function descriptors (code_va, TOC, env)
      - glink stubs are 28 bytes each at the start of .text
      - Symbols have OPD entry VAs, not code VAs
    """

    def __init__(self, path: str, data: bytes):
        self._path = path
        self._data = data
        self._info: Optional[Ppc64ElfV1Info] = None

    @classmethod
    def from_path(cls, path: str) -> 'Ppc64ElfV1Resolver':
        data = open(path, 'rb').read()
        return cls(path, data)

    @classmethod
    def from_context(cls, ctx) -> 'Ppc64ElfV1Resolver':
        """Construct from a BinaryContext (uses ctx.path)."""
        return cls.from_path(ctx.path)

    # ------------------------------------------------------------------
    # Core resolution
    # ------------------------------------------------------------------

    def resolve(self) -> Ppc64ElfV1Info:
        """Parse OPD, .text, and .rela.plt to build the full resolution."""
        if self._info is not None:
            return self._info

        data = self._data
        info = Ppc64ElfV1Info(binary_path=self._path)

        # Validate ELF header
        if data[:4] != b'\x7fELF':
            raise ValueError("Not an ELF file")
        ei_class = data[4]   # 2 = 64-bit
        ei_data  = data[5]   # 2 = big-endian
        if ei_class != 2 or ei_data != 2:
            raise ValueError(f"Expected 64-bit big-endian ELF; got class={ei_class} data={ei_data}")

        # ELF64 header fields (big-endian)
        e_shoff     = struct.unpack_from('>Q', data, 0x28)[0]
        e_shentsize = struct.unpack_from('>H', data, 0x3a)[0]
        e_shnum     = struct.unpack_from('>H', data, 0x3c)[0]
        e_shstrndx  = struct.unpack_from('>H', data, 0x3e)[0]

        # Load section name string table
        shstrtab_va = shstrtab_off = shstrtab_sz = 0
        if e_shstrndx and e_shstrndx < e_shnum:
            sh = e_shoff + e_shstrndx * e_shentsize
            shstrtab_off = struct.unpack_from('>Q', data, sh + 0x18)[0]
            shstrtab_sz  = struct.unpack_from('>Q', data, sh + 0x20)[0]

        def section_name(name_off: int) -> str:
            if not shstrtab_off or name_off >= shstrtab_sz:
                return ''
            end = data.index(b'\x00', shstrtab_off + name_off)
            return data[shstrtab_off + name_off:end].decode('ascii', errors='replace')

        # Scan section headers for .opd, .text, .rela.plt
        sections: Dict[str, tuple] = {}  # name -> (va, file_off, size)
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            if sh + e_shentsize > len(data):
                break
            sh_name = struct.unpack_from('>I', data, sh)[0]
            sh_type = struct.unpack_from('>I', data, sh + 4)[0]
            sh_addr = struct.unpack_from('>Q', data, sh + 0x10)[0]
            sh_off  = struct.unpack_from('>Q', data, sh + 0x18)[0]
            sh_size = struct.unpack_from('>Q', data, sh + 0x20)[0]
            name = section_name(sh_name)
            if name:
                sections[name] = (sh_addr, sh_off, sh_size, sh_type)

        # .text
        if '.text' in sections:
            va, off, sz, _ = sections['.text']
            info.text_va = va
            info.text_file_off = off
            info.text_size = sz

        # .opd — parse 24-byte ELFv1 function descriptors
        if '.opd' in sections:
            va, off, sz, _ = sections['.opd']
            info.opd_va = va
            info.opd_file_off = off
            info.opd_size = sz
            n_entries = sz // 24
            for i in range(n_entries):
                foff = off + i * 24
                if foff + 24 > len(data):
                    break
                code_va, toc_va, env_va = struct.unpack_from('>QQQ', data, foff)
                entry_va = va + i * 24
                info.opd_to_code[entry_va] = code_va
                info.opd_to_toc[entry_va]  = toc_va
            # TOC from first entry (typically the main/entry-point descriptor)
            if info.opd_to_toc:
                info.toc = next(iter(info.opd_to_toc.values()))

        # .rela.plt — JMP_SLOT entries give us GOT VA -> symbol name
        # Must parse the dynamic symbol table for names.
        # Parse .dynsym to build sym_idx -> name map.
        dynsym: Dict[int, str] = {}
        if '.dynsym' in sections:
            va, off, sz, _ = sections['.dynsym']
            # ELF64 Sym: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8) = 24 bytes
            n_syms = sz // 24
            # Need .dynstr
            dynstr_off = dynstr_sz = 0
            if '.dynstr' in sections:
                _, dynstr_off, dynstr_sz, _ = sections['.dynstr']
            for i in range(n_syms):
                foff = off + i * 24
                if foff + 4 > len(data):
                    break
                st_name = struct.unpack_from('>I', data, foff)[0]
                if dynstr_off and st_name < dynstr_sz:
                    end = data.index(b'\x00', dynstr_off + st_name)
                    name = data[dynstr_off + st_name:end].decode('ascii', errors='replace')
                    if name:
                        dynsym[i] = name

        # .rela.plt — ELF64 Rela: r_offset(8) r_info(8) r_addend(8) = 24 bytes
        jmp_slots: List[Tuple[int, str]] = []
        if '.rela.plt' in sections:
            va, off, sz, _ = sections['.rela.plt']
            n_relas = sz // 24
            for i in range(n_relas):
                foff = off + i * 24
                if foff + 16 > len(data):
                    break
                r_offset = struct.unpack_from('>Q', data, foff)[0]
                r_info   = struct.unpack_from('>Q', data, foff + 8)[0]
                sym_idx  = (r_info >> 32) & 0xFFFFFFFF
                r_type   = r_info & 0xFFFFFFFF
                # R_PPC64_JMP_SLOT = 21
                if r_type == 21 and sym_idx in dynsym:
                    jmp_slots.append((r_offset, dynsym[sym_idx]))

        jmp_slots.sort(key=lambda x: x[0])
        info.jmp_slots = jmp_slots
        info.n_stubs = len(jmp_slots)

        # Build glink stub map.
        # Each stub is 28 bytes. The third instruction (offset +8) is
        # 'ld r11, DELTA(r12)' where r12=TOC and TOC+DELTA = the GOT entry VA.
        # Decoding DELTA from the raw instruction gives the correct stub->name
        # mapping regardless of the order the linker placed stubs in .text.
        # This matters: at least one IBM LoadLeveler binary (llstepnotify) has
        # stubs in an order that differs from ascending GOT VA order, causing
        # the old index-equals-GOT-VA-rank assumption to misidentify every stub.
        GLINK_STUB_SIZE = 28
        if info.toc and jmp_slots and info.text_file_off:
            got_va_to_name = {gv: sn for gv, sn in jmp_slots}
            for idx in range(info.n_stubs):
                stub_va = info.text_va + idx * GLINK_STUB_SIZE
                ld_off = info.text_file_off + idx * GLINK_STUB_SIZE + 8
                if ld_off + 4 > len(data):
                    break
                word = struct.unpack_from('>I', data, ld_off)[0]
                # DS-form: bits[16:29] = DS (14-bit signed), bits[30:31] = XO.
                # displacement = sign_extend(DS) * 4  (= sign_extend(raw16 & 0xFFFC))
                raw16 = word & 0xFFFF
                ds_raw = (raw16 >> 2) & 0x3FFF
                if ds_raw & 0x2000:
                    ds_raw -= 0x4000
                got_va = info.toc + ds_raw * 4
                name = got_va_to_name.get(got_va)
                if name is not None:
                    info.stub_map[stub_va] = name
            # Fall back to index=GOT-VA-rank if TOC decoding found nothing
            # (e.g. TOC was wrong or the binary has no OPD section).
            if not info.stub_map:
                for idx, (got_va, sym_name) in enumerate(jmp_slots):
                    stub_va = info.text_va + idx * GLINK_STUB_SIZE
                    info.stub_map[stub_va] = sym_name
        else:
            for idx, (got_va, sym_name) in enumerate(jmp_slots):
                stub_va = info.text_va + idx * GLINK_STUB_SIZE
                info.stub_map[stub_va] = sym_name

        self._info = info
        return info

    # ------------------------------------------------------------------
    # BinaryContext patch
    # ------------------------------------------------------------------

    def patch_context(self, ctx) -> None:
        """Rewrite ctx.plt and ctx.func_starts for PPC64 ELFv1 correctness.

        After patching:
          - ctx.plt maps stub_VA -> import_name (correct for SinkArgClassifier)
          - ctx.func_starts lists code VAs (not OPD VAs)
        """
        info = self.resolve()

        # Replace plt with stub_map
        ctx.plt.clear()
        ctx.plt.update(info.stub_map)

        # Replace func_starts: resolve OPD entry VAs to code VAs
        resolved = []
        for va in ctx.func_starts:
            code_va = info.opd_to_code.get(va)
            if code_va is not None:
                resolved.append(code_va)
            else:
                # Already a code VA (e.g. anonymous function from eh_frame)
                resolved.append(va)
        resolved.sort()
        ctx.func_starts[:] = resolved

    # ------------------------------------------------------------------
    # Convenience: scan all BL calls to a specific stub
    # ------------------------------------------------------------------

    def find_bl_callers(self, stub_va: int) -> List[int]:
        """Return all VAs in .text that branch-and-link to stub_va."""
        info = self.resolve()
        if not info.text_va or not info.text_size:
            return []
        data = self._data
        text_off = info.text_file_off
        text_va  = info.text_va
        callers  = []
        for i in range(0, info.text_size - 4, 4):
            word = struct.unpack_from('>I', data, text_off + i)[0]
            opcode = (word >> 26) & 0x3f
            if opcode != 18 or not (word & 1):
                continue
            li = (word >> 2) & 0xFFFFFF
            if li & 0x800000:
                li -= 0x1000000
            src_va = text_va + i
            tgt = src_va + li * 4
            if tgt == stub_va:
                callers.append(src_va)
        return callers

    def find_all_bl_callers(self) -> Dict[str, List[int]]:
        """Return {symbol_name: [caller_va, ...]} for all stubs with callers."""
        info = self.resolve()
        result: Dict[str, List[int]] = {}
        for stub_va, name in info.stub_map.items():
            callers = self.find_bl_callers(stub_va)
            if callers:
                result[name] = callers
        return result

    # ------------------------------------------------------------------
    # Classmethod: detect whether a binary is PPC64 BE ELFv1
    # ------------------------------------------------------------------

    @staticmethod
    def is_ppc64_elfv1(path: str) -> bool:
        """Return True if path is a PPC64 big-endian ELFv1 ELF."""
        try:
            with open(path, 'rb') as f:
                hdr = f.read(16)
            return (
                hdr[:4] == b'\x7fELF'
                and hdr[4] == 2      # ELFCLASS64
                and hdr[5] == 2      # ELFDATA2MSB
            )
        except Exception:
            return False
