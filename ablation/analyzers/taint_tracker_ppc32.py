"""
taint_tracker_ppc32.py: PowerPC 32-bit network-to-sink taint analysis.

Architecture: PPC32 big-endian and little-endian (POWER LE Linux).
ABI: System V / EABI: r3-r10 args (8 integer regs), r3 return value,
     r13-r31 callee-saved, r0/r3-r12/lr caller-saved. No branch delay slots.

Prologue: stwu r1, -N(r1)  [allocate frame + save old SP]
          mflr r0           [save link register]
Return:   blr               [branch to link register]
Call:     bl  <target>      [direct call]
          bctrl             [indirect call via CTR, used for PLT]

Sources: recv/recvfrom/read/fgets/gets/fread -- return value in r3.
Sinks  : system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf.

Targets: Cisco 7200/3700 series IOS (big-endian), MikroTik RB600 (big-endian),
         VxWorks embedded (big-endian), POWER LE Linux userspace (little-endian),
         older Fortinet hardware (big-endian).

Usage:
    from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker
    tracker = PPC32TaintTracker.from_path('iosd')          # big-endian default
    findings = tracker.run()
    chains   = tracker.run_interprocedural(depth=4)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import capstone
    from capstone.ppc_const import (
        PPC_OP_REG, PPC_OP_IMM, PPC_OP_MEM,
        # Loads (word, halfword, byte -- Z=zero-extend, A=sign-extend)
        PPC_INS_LWZ,  PPC_INS_LWZU,
        PPC_INS_LBZ,  PPC_INS_LBZU,
        PPC_INS_LHZ,  PPC_INS_LHZU,
        PPC_INS_LHA,  PPC_INS_LHAU,
        # Stores
        PPC_INS_STW,  PPC_INS_STWU,
        PPC_INS_STB,  PPC_INS_STH,
        # Arithmetic
        PPC_INS_ADD,  PPC_INS_ADDI,  PPC_INS_ADDIS, PPC_INS_ADDIC,
        PPC_INS_ADDC, PPC_INS_ADDE,
        PPC_INS_SUBF, PPC_INS_SUBFIC, PPC_INS_NEG,
        PPC_INS_MULLW, PPC_INS_MULHW, PPC_INS_MULHWU,
        PPC_INS_DIVW,  PPC_INS_DIVWU,
        # Logic
        PPC_INS_AND,  PPC_INS_ANDI,  PPC_INS_ANDC,
        PPC_INS_OR,   PPC_INS_ORI,   PPC_INS_NOR,
        PPC_INS_XOR,  PPC_INS_XORI,
        PPC_INS_SLW,  PPC_INS_SRW,   PPC_INS_SRAWI,
        PPC_INS_RLWINM, PPC_INS_RLWIMI,
        # Pseudo / move
        PPC_INS_MR,   PPC_INS_LI,    PPC_INS_LIS,
        PPC_INS_NOP,
        # SPR
        PPC_INS_MFLR, PPC_INS_MTLR,  PPC_INS_MTCTR,
        # Branches / calls / returns
        PPC_INS_B,    PPC_INS_BC,
        PPC_INS_BL,   PPC_INS_BLA,
        PPC_INS_BLR,  PPC_INS_BLRL,
        PPC_INS_BCTR, PPC_INS_BCTRL,
        # Conditional branch aliases (capstone expands to these)
        PPC_INS_BEQ,  PPC_INS_BNE,
        PPC_INS_BGT,  PPC_INS_BLT,
        PPC_INS_BGE,  PPC_INS_BLE,
    )
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False

try:
    import lief as _lief
    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    _HAS_PYELF = True
except ImportError:
    _HAS_PYELF = False


# ---------------------------------------------------------------------------
# PPC32 System V / EABI register model
# ---------------------------------------------------------------------------
#
# r0        : volatile (used as scratch in prologue: mflr r0)
# r1        : stack pointer (never tainted)
# r2        : small data area / TOC (EABI/POWER)
# r3-r10    : integer argument registers + return value (r3)
# r11-r12   : volatile (used by PLT stubs / compiler)
# r13       : small data area pointer (callee-saved in EABI)
# r14-r31   : callee-saved
# lr        : link register (return address)
# ctr       : count register (used for indirect calls)
# ---------------------------------------------------------------------------

_ARG_REGS: List[str] = ['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10']

_CALLER_SAVED: frozenset = frozenset([
    'r0', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10',
    'r11', 'r12',
])

_CALLEE_SAVED: frozenset = frozenset([
    'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20',
    'r21', 'r22', 'r23', 'r24', 'r25', 'r26', 'r27', 'r28',
    'r29', 'r30', 'r31',
    'r1', 'r2',
])

_CALL_IDS: Set[int] = set()
_RET_IDS: Set[int] = set()
_BRANCH_IDS: Set[int] = set()

if _HAS_CAPSTONE:
    _CALL_IDS = {PPC_INS_BL, PPC_INS_BLA, PPC_INS_BCTRL}
    _RET_IDS  = {PPC_INS_BLR, PPC_INS_BLRL}
    _BRANCH_IDS = {
        PPC_INS_B, PPC_INS_BC,
        PPC_INS_BEQ, PPC_INS_BNE, PPC_INS_BGT, PPC_INS_BLT,
        PPC_INS_BGE, PPC_INS_BLE,
        PPC_INS_BCTR,
    } | _CALL_IDS | _RET_IDS

_SOURCES: Set[str] = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'pread',
    'fread', 'fgets', 'gets', 'getenv',
    'recv@plt', 'read@plt', 'fgets@plt', 'recvfrom@plt',
}

_DEFAULT_SINKS: Dict[str, List[int]] = {
    'system':      [0],   # arg index 0 = r3
    'execv':       [0],
    'execvp':      [0],
    'execve':      [0],
    'execl':       [0],   # execl(path, arg0, ...) -- path in r3
    'execle':      [0],
    'execlp':      [0],
    'popen':       [0],
    'strcpy':      [1],   # strcpy(dst, src): src = r4
    'strcpy_s':    [2],   # strcpy_s(dst, n, src): src = r5
    'strcat':      [1],
    'strcat_s':    [2],   # strcat_s(dst, n, src): src = r5
    'sprintf':     [1],   # format = r4
    'sprintf_s':   [2],   # sprintf_s(dst, n, fmt, ...) -- fmt = r5
    'snprintf':    [2],   # format = r5
    'snprintf_s':  [3],   # snprintf_s(dst, n, maxlen, fmt, ...) -- fmt = r6
    'memcpy':      [2],   # length = r5
    'memcpy_s':    [3],   # memcpy_s(dst, dsz, src, count): src = r6
    'memmove':     [2],
    'malloc':      [0],
    'calloc':      [0, 1],
    'realloc':     [1],
}

MAX_FUNC_BYTES = 0x8000


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingPPC32:
    binary: str
    func_va: int
    func_name: str
    sink_va: int
    sink_name: str
    tainted_args: List[int]
    source_name: str

    def __str__(self) -> str:
        args_str = ', '.join(f'r{i + 3}' for i in self.tainted_args)
        return (f'[PPC32-TAINT] {self.func_name} (0x{self.func_va:x})'
                f' -> {self.sink_name}({args_str}) @ 0x{self.sink_va:x}'
                f'  [src: {self.source_name}]')


# ---------------------------------------------------------------------------
# PPC32TaintTracker
# ---------------------------------------------------------------------------

class PPC32TaintTracker:
    """
    Source-to-sink static taint tracker for PPC32 ELF binaries.

    ABI: System V / EABI. No branch delay slots.

    Usage:
        tracker = PPC32TaintTracker.from_path('iosd')          # BE default
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)

    Custom sinks:
        tracker = PPC32TaintTracker.from_path('fw', custom_sinks={'vxExecCmd': [0]})

    From BinaryContext:
        tracker = PPC32TaintTracker.from_context(ctx)
    """

    def __init__(
        self,
        binary_path: str,
        ctx=None,
        custom_sinks: Optional[Dict[str, List[int]]] = None,
        endian: str = 'big',
    ):
        if not _HAS_CAPSTONE:
            raise RuntimeError('capstone not installed')

        self.binary_path = binary_path
        self._ctx = ctx
        self._sinks = dict(_DEFAULT_SINKS)
        if custom_sinks:
            self._sinks.update(custom_sinks)

        self._data = Path(binary_path).read_bytes()
        self._endian = endian
        self._plt: Dict[int, str] = {}
        self._func_starts: List[int] = []
        self._text_va: int = 0
        self._text_off: int = 0
        self._text_size: int = 0
        # GOT-indirect call support (PPC32 EABI secure-PLT / got2 ABI):
        #   calls use  lwz rX, N(r_got) + mtctr rX + bctrl
        #   where r_got = GOT_base + 0x8000 (signed 16-bit offset range)
        # _got_offset_to_name: signed-16-bit offset -> plt symbol name
        self._got_offset_to_name: Dict[int, str] = {}

        cs_endian = (capstone.CS_MODE_BIG_ENDIAN if endian == 'big'
                     else capstone.CS_MODE_LITTLE_ENDIAN)
        self._md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | cs_endian)
        self._md.detail = True
        self._md.skipdata = True

        # GOT2 PIC: per-function r30 map (func_va -> r30_value)
        # Populated by _build_got2_r30_map() for binaries using GOT2 ABI where
        # each compilation unit has its own r30 (LIEF sees 0 JUMP_SLOT relocations).
        self._func_r30: Dict[int, int] = {}
        # got2_va -> symbol_name (populated from raw dynsym when LIEF PLT is empty)
        self._got2_va_to_name: Dict[int, str] = {}

        self._load_elf()

    @classmethod
    def from_path(cls, path: str, endian: str = 'big', **kwargs) -> 'PPC32TaintTracker':
        return cls(path, endian=endian, **kwargs)

    @classmethod
    def from_context(cls, ctx, endian: str = 'big', **kwargs) -> 'PPC32TaintTracker':
        return cls(ctx.binary_path, ctx=ctx, endian=endian, **kwargs)

    # ------------------------------------------------------------------
    # ELF loading
    # ------------------------------------------------------------------

    def _load_elf(self) -> None:
        if _HAS_LIEF:
            self._load_lief()
        if not self._text_va and _HAS_PYELF:
            # Supplement: lief may populate PLT correctly but fail to set _text_va
            # (lief 1.0.0 changed SEGMENT_TYPES/SYMBOL_TYPES enum paths).
            # Only fill _text_va/_text_off/_text_size — never overwrite PLT already set by lief.
            self._fill_text_from_pyelf()
        elif not _HAS_LIEF and _HAS_PYELF:
            self._load_pyelf()
        # Always supplement _plt with raw dynsym SHN_UNDEF stub VAs.
        # LIEF on Huawei PPC32 (vendor reloc type 0x40000054) maps _plt to the
        # .plt section VAs (0x10150e6c...) instead of the actual PLT stub VAs
        # (0x1011f...) that appear as values inside .got2.  Running this
        # unconditionally adds the correct SHN_UNDEF entries alongside any LIEF
        # entries; the GOT2 scanner matches against stub VAs, not .plt VAs.
        self._load_plt_from_dynsym_raw()
        self._build_got_offset_table()
        # Always build the GOT2-aware resolver — it's cheap and handles PPC32
        # GOT2 PIC (Huawei, embedded Linux) where _build_got_offset_table builds
        # a wrong table from .plt stub VAs instead of actual GOT2 entry VAs.
        if self._plt:
            self._build_got2_resolver()

    def _load_lief(self) -> None:
        try:
            binary = _lief.parse(self.binary_path)
            if not binary:
                return
            for sym in binary.pltgot_relocations:
                if sym.symbol and sym.symbol.name:
                    self._plt[sym.address] = sym.symbol.name
            for sym in binary.plt_relocations:
                if sym.symbol and sym.symbol.name:
                    self._plt[sym.address] = sym.symbol.name
            starts: Set[int] = set()
            # lief 1.0.0+ moved enums: SYMBOL_TYPES -> Symbol.TYPE, SEGMENT_TYPES -> Segment.TYPE
            try:
                _sym_func = _lief.ELF.Symbol.TYPE.FUNC
            except AttributeError:
                _sym_func = _lief.ELF.SYMBOL_TYPES.FUNC
            try:
                _seg_load = _lief.ELF.Segment.TYPE.LOAD
            except AttributeError:
                _seg_load = _lief.ELF.SEGMENT_TYPES.LOAD
            for sym in binary.static_symbols:
                if sym.type == _sym_func and sym.value:
                    starts.add(sym.value)
            for sym in binary.dynamic_symbols:
                if sym.type == _sym_func and sym.value:
                    starts.add(sym.value)
            self._func_starts = sorted(starts)
            for seg in binary.segments:
                if seg.type == _seg_load and int(seg.flags) & 0x1:
                    self._text_va   = seg.virtual_address
                    self._text_off  = seg.file_offset
                    self._text_size = seg.physical_size
                    break
        except Exception:
            pass

    def _load_pyelf(self) -> None:
        try:
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                text = elf.get_section_by_name('.text')
                if text:
                    self._text_va   = text['sh_addr']
                    self._text_off  = text['sh_offset']
                    self._text_size = text['sh_size']
                dynsym = elf.get_section_by_name('.dynsym')
                if dynsym:
                    plt_sec = elf.get_section_by_name('.plt')
                    plt_va  = plt_sec['sh_addr'] if plt_sec else 0
                    for relname in ('.rel.plt', '.rela.plt'):
                        rsec = elf.get_section_by_name(relname)
                        if not rsec:
                            continue
                        for idx, rel in enumerate(rsec.iter_relocations()):
                            sym = dynsym.get_symbol(rel['r_info_sym'])
                            if sym and plt_va:
                                # PPC PLT stubs are typically 16 bytes
                                self._plt[plt_va + 16 * (idx + 1)] = sym.name
                for sname in ('.symtab', '.dynsym'):
                    sec = elf.get_section_by_name(sname)
                    if not isinstance(sec, SymbolTableSection):
                        continue
                    for sym in sec.iter_symbols():
                        if (sym['st_info']['type'] == 'STT_FUNC'
                                and sym['st_value'] and sym['st_size'] > 0):
                            self._func_starts.append(sym['st_value'])
                self._func_starts = sorted(set(self._func_starts))
        except Exception:
            pass

    def _fill_text_from_pyelf(self) -> None:
        """Set _text_va/_text_off/_text_size from .text section without touching PLT."""
        if not _HAS_PYELF:
            return
        try:
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                text = elf.get_section_by_name('.text')
                if text:
                    self._text_va   = text['sh_addr']
                    self._text_off  = text['sh_offset']
                    self._text_size = text['sh_size']
        except Exception:
            pass

    def _load_plt_from_dynsym_raw(self) -> None:
        """
        Fallback PLT loader for PPC32 GOT2 binaries where LIEF reports 0 JUMP_SLOT
        relocations (e.g. vendor-specific relocation type 0x40000054 in Huawei bootloaders).

        On PPC32 Linux with -mrelocatable / GOT2 ABI, dynamic symbols with non-zero
        st_value and SHN_UNDEF (st_shndx == 0) are PLT stub VAs.  Parse the raw ELF
        to recover them without relying on LIEF's relocation type table.
        """
        import struct as _struct
        try:
            data = self._data
            bo = '>' if self._endian == 'big' else '<'
            # ELF header: e_shoff [32], e_shnum [48], e_shstrndx [50]
            e_shoff   = _struct.unpack_from(bo + 'I', data, 32)[0]
            e_shnum   = _struct.unpack_from(bo + 'H', data, 48)[0]
            e_shstrndx= _struct.unpack_from(bo + 'H', data, 50)[0]
            # section header string table offset
            shstrtab_foff = _struct.unpack_from(bo + 'I', data, e_shoff + e_shstrndx*40 + 16)[0]

            def sh(i):
                off = e_shoff + i * 40
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link = \
                    _struct.unpack_from(bo + 'IIIIIII', data, off)
                name_end = data.index(b'\x00', shstrtab_foff + sh_name)
                sec_name = data[shstrtab_foff + sh_name:name_end].decode('ascii', errors='replace')
                return sec_name, sh_addr, sh_offset, sh_size, sh_link

            # find .dynsym and .dynstr
            dynsym_foff = dynsym_size = dynstr_foff = 0
            for i in range(e_shnum):
                sname, saddr, sfoff, ssize, slink = sh(i)
                if sname == '.dynsym':
                    dynsym_foff, dynsym_size = sfoff, ssize
                    _, _, dynstr_foff, _, _ = sh(slink)
                elif sname == '.dynstr' and not dynstr_foff:
                    dynstr_foff = sfoff

            if not dynsym_foff or not dynstr_foff:
                return

            sym_size = 16  # ELF32 Sym: name(4)+value(4)+size(4)+info(1)+other(1)+shndx(2)
            sym_count = dynsym_size // sym_size
            for i in range(sym_count):
                off = dynsym_foff + i * sym_size
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    _struct.unpack_from(bo + 'IIIBBH', data, off)
                # SHN_UNDEF (0) with non-zero st_value = PLT stub VA for external symbol.
                # Skip internal symbols (st_shndx != 0) to avoid polluting _plt.
                if st_shndx != 0 or not st_value:
                    continue
                ne = data.index(b'\x00', dynstr_foff + st_name)
                name = data[dynstr_foff + st_name:ne].decode('ascii', errors='replace')
                if name:
                    self._plt[st_value] = name
        except Exception:
            pass

    def _build_got2_resolver(self) -> None:
        """
        Build GOT2-VA → symbol name map for PPC32 GOT2 PIC binaries.

        In this ABI each compilation unit sets r30 = LR + addis_hi<<16 + addi_lo
        at function entry (PIC prologue).  Indirect calls are:
          lwz  rX, N(r30)   ; load ptr from GOT2
          mtctr rX
          bctrl

        Strategy:
        1. Build plt_va → name from self._plt (already populated).
        2. Scan the .got2 section (or all non-text writable data): for each 4-byte
           entry whose value is in plt_va_to_name, record got2_entry_va → name.
        3. At call-resolution time, compute got2_va = func_r30 + N and look up.
        4. Pre-compute r30 for every function by scanning the PIC prologue.
        """
        import struct as _struct
        bo = '>' if self._endian == 'big' else '<'
        data = self._data

        # Reverse-map: plt_stub_va → name (already in self._plt)
        plt_va_to_name = self._plt  # va → name

        # Find .got2 section via raw ELF headers
        try:
            e_shoff    = _struct.unpack_from(bo + 'I', data, 32)[0]
            e_shnum    = _struct.unpack_from(bo + 'H', data, 48)[0]
            e_shstrndx = _struct.unpack_from(bo + 'H', data, 50)[0]
            shstrtab_foff = _struct.unpack_from(bo + 'I', data,
                                                 e_shoff + e_shstrndx*40 + 16)[0]

            got2_foff = got2_addr = got2_size = 0
            for i in range(e_shnum):
                soff = e_shoff + i * 40
                sh_name_off = _struct.unpack_from(bo + 'I', data, soff)[0]
                ne = data.index(b'\x00', shstrtab_foff + sh_name_off)
                sname = data[shstrtab_foff + sh_name_off:ne].decode('ascii', errors='replace')
                if sname in ('.got2', '.got', '.got.plt'):
                    _, _, _, sh_addr, sh_foff, sh_size = \
                        _struct.unpack_from(bo + 'IIIIII', data, soff)[:6]
                    if sh_size > got2_size:  # prefer larger section
                        got2_addr, got2_foff, got2_size = sh_addr, sh_foff, sh_size

            if not got2_size:
                return

            # Scan every 4-byte word in .got2 for PLT pointers
            for i in range(0, got2_size - 3, 4):
                ptr = _struct.unpack_from(bo + 'I', data, got2_foff + i)[0]
                if ptr in plt_va_to_name:
                    entry_va = got2_addr + i
                    self._got2_va_to_name[entry_va] = plt_va_to_name[ptr]

        except Exception:
            return

        # Pre-compute r30 for each function by scanning PIC prologue.
        # Pattern: bdnzl/bcl $+4  [insn at N stores LR=N+4]
        #          mflr r30       [r30 = N+4]
        #          addis r30, r30, HI
        #          addi  r30, r30, LO
        # r30 = (N+4) + sign_ext(HI)*0x10000 + sign_ext(LO)
        if not self._text_va:
            return
        text_end = self._text_va + self._text_size
        for fva in self._get_func_starts():
            if fva < self._text_va or fva >= text_end:
                continue
            foff = self._text_off + (fva - self._text_va)
            if foff + 64 > len(data):
                continue
            # Read first 16 instructions (64 bytes) — PIC prologues on Huawei PPC32
            # reach instruction index 10+ before the addis/addi pair completes.
            chunk = data[foff:foff + 64]
            try:
                insns = list(self._md.disasm(chunk, fva))
            except Exception:
                continue
            # Look for mflr r30 followed by addis r30, r30, HI + addi r30, r30, LO
            for idx, ins in enumerate(insns):
                if ins.id != PPC_INS_MFLR:
                    continue
                ops = ins.operands
                if not ops or ins.reg_name(ops[0].reg).lower() != 'r30':
                    continue
                # bcl sets LR = bcl_addr + 4 = mflr_addr; so lr_val = mflr address.
                lr_val = ins.address
                # Find addis r30, r30, HI
                if idx + 2 >= len(insns):
                    break
                ins_addis = insns[idx + 1]
                ins_addi  = insns[idx + 2]
                if ins_addis.id != PPC_INS_ADDIS:
                    break
                aops = ins_addis.operands
                if len(aops) < 3:
                    break
                hi = aops[2].imm  # signed 16-bit
                if ins_addi.id not in (PPC_INS_ADDI, PPC_INS_ADDIC):
                    break
                bops = ins_addi.operands
                if len(bops) < 3:
                    break
                lo = bops[2].imm  # signed 16-bit
                r30 = (lr_val + hi * 0x10000 + lo) & 0xFFFFFFFF
                self._func_r30[fva] = r30
                break

    def _build_got_offset_table(self) -> None:
        """
        Build _got_offset_to_name for GOT-indirect bctrl dispatch.

        PPC32 EABI secure-PLT / got2 ABI calling convention:
          lwz  rX, N(r_got)   ; load function pointer from GOT
          mtctr rX
          bctrl               ; call via CTR

        r_got = GOT_base + 0x8000 (so signed 16-bit offsets cover the entire GOT).
        GOT_base = minimum address in self._plt (the .plt/.got.plt section start).
        """
        if not self._plt:
            return
        got_base = min(self._plt.keys())
        got_reg_value = got_base + 0x8000  # r2 or r30 value
        for got_va, name in self._plt.items():
            offset = got_va - got_reg_value  # signed 16-bit offset from r_got
            if -32768 <= offset <= 32767:
                self._got_offset_to_name[offset] = name

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_func_starts(self) -> List[int]:
        if self._ctx is not None:
            return self._ctx.func_starts
        # Only trust lief/pyelf symbol list when it's symbol-rich (>= 50 entries).
        # Stripped binaries yield 0-2 symbols; fall through to prologue scan in that case.
        if len(self._func_starts) >= 50:
            return self._func_starts
        # Prologue scan: stwu r1, -N(r1)
        # Encoding: opcode=37(0x25), rs=1, ra=1, d=negative
        # Word: [31:26]=37, [25:21]=1, [20:16]=1, [15:0]=negative imm
        starts: List[int] = []
        bo = 'big' if self._endian == 'big' else 'little'
        for off in range(0, len(self._data) - 3, 4):
            w = int.from_bytes(self._data[off:off+4], bo)
            opcode = (w >> 26) & 0x3f
            rs     = (w >> 21) & 0x1f
            ra     = (w >> 16) & 0x1f
            d      = w & 0xffff
            if opcode == 37 and rs == 1 and ra == 1 and (d & 0x8000):
                if self._text_va and self._text_off:
                    va = self._text_va + (off - self._text_off)
                    if self._text_va <= va < self._text_va + self._text_size:
                        starts.append(va)
        return sorted(set(starts))

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        if not self._text_va:
            return None
        off = self._text_off + (va - self._text_va)
        if off < 0 or off + size > len(self._data):
            return None
        return self._data[off: off + size]

    def _func_name(self, va: int) -> str:
        if self._ctx is not None:
            return self._ctx.name(va)
        return self._plt.get(va, f'0x{va:x}')

    def _resolve_bctrl_name(self, prev2, prev1, func_r30: int = 0, prev3=None) -> str:
        """
        Resolve a bctrl indirect call to a PLT name.

        Handles two ABI variants:
        - Secure-PLT / single-GOT: uses _got_offset_to_name keyed by signed disp.
        - GOT2 PIC (Huawei PPC32): uses _got2_va_to_name keyed by got2_va = r30 + disp.

        Expected pattern (2 instructions before bctrl):
          prev2: lwz  rX, N(rGOT)   -- GOT load; N is signed disp
          prev1: mtctr rX            -- load CTR from rX

        GCC PPC32 ABI also emits `crclr cr1eq` (or other CR insns) between
        mtctr and bctrl as a varargs indicator; when prev1 is such an insn,
        fall back to prev3=lwz / prev2=mtctr.

        Returns empty string if pattern not recognized.
        """
        if prev2 is None or prev1 is None:
            return ''
        if prev1.id != PPC_INS_MTCTR:
            # GCC PPC32 ABI: crclr inserted between mtctr and bctrl
            if prev2.id == PPC_INS_MTCTR and prev3 is not None and prev3.id == PPC_INS_LWZ:
                prev2, prev1 = prev3, prev2  # shift window to recover lwz+mtctr
            else:
                return ''
        if prev2.id != PPC_INS_LWZ:
            return ''
        ops = prev2.operands
        if len(ops) < 2:
            return ''
        if ops[1].type != PPC_OP_MEM:
            return ''
        disp = ops[1].mem.disp  # signed 16-bit displacement
        # Try GOT2 per-CU resolver first when func_r30 is known
        if func_r30 and self._got2_va_to_name:
            got2_va = (func_r30 + disp) & 0xFFFFFFFF
            name = self._got2_va_to_name.get(got2_va, '')
            if name:
                return name
        # Fall back to single-GOT offset table
        return self._got_offset_to_name.get(disp, '')

    # ------------------------------------------------------------------
    # Taint semantics
    # ------------------------------------------------------------------

    def _exec_insn(self, insn, tainted: Dict[str, bool]) -> None:
        """Apply one non-call instruction's taint semantics."""
        ops = insn.operands
        if not ops:
            return

        def get_t(reg: str) -> bool:
            return bool(tainted.get(reg.lower()))

        def set_t(reg: str, val: bool) -> None:
            r = reg.lower()
            if r not in ('r1', 'r2'):
                tainted[r] = val

        def rn(op) -> str:
            return insn.reg_name(op.reg).lower() if op.type == PPC_OP_REG else ''

        # LI/LIS: immediate load -- clears taint
        if insn.id in (PPC_INS_LI, PPC_INS_LIS) and ops:
            set_t(rn(ops[0]), False)

        # MR dst, src (move register)
        elif insn.id == PPC_INS_MR and len(ops) == 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # ADDI/ADDIS/ADDIC dst, src, imm -- taint from src
        elif insn.id in (PPC_INS_ADDI, PPC_INS_ADDIS, PPC_INS_ADDIC) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # ADD/ADDC/ADDE dst, src1, src2
        elif insn.id in (PPC_INS_ADD, PPC_INS_ADDC, PPC_INS_ADDE) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))

        # SUBF/NEG
        elif insn.id == PPC_INS_SUBF and len(ops) == 3:
            # SUBF dst, ra, rb = rb - ra
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))
        elif insn.id in (PPC_INS_SUBFIC,) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_NEG and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # AND/ANDC, OR/NOR, XOR (3-reg)
        elif insn.id in (PPC_INS_AND, PPC_INS_ANDC,
                         PPC_INS_OR, PPC_INS_NOR,
                         PPC_INS_XOR) and len(ops) == 3:
            dst, s1, s2 = rn(ops[0]), rn(ops[1]), rn(ops[2])
            if insn.id == PPC_INS_XOR and s1 == s2:
                set_t(dst, False)
            else:
                set_t(dst, get_t(s1) or get_t(s2))

        # ANDI/ORI/XORI (immediate)
        elif insn.id in (PPC_INS_ANDI, PPC_INS_ORI, PPC_INS_XORI) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # Shifts / rotates
        elif insn.id in (PPC_INS_SLW, PPC_INS_SRW) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_SRAWI and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_RLWINM and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_RLWIMI and len(ops) >= 2:
            # dst |= rotated src; taint if either source is tainted
            set_t(rn(ops[0]), get_t(rn(ops[0])) or get_t(rn(ops[1])))

        # MULLW/MULHW/MULHWU: result tainted if either operand tainted
        elif insn.id in (PPC_INS_MULLW, PPC_INS_MULHW, PPC_INS_MULHWU) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))

        # DIVW/DIVWU: result tainted if either operand tainted
        elif insn.id in (PPC_INS_DIVW, PPC_INS_DIVWU) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))

        # Loads: LWZ/LWZU/LBZ/LHZ etc: dst = mem[base+offset]
        elif insn.id in (PPC_INS_LWZ, PPC_INS_LWZU,
                         PPC_INS_LBZ, PPC_INS_LBZU,
                         PPC_INS_LHZ, PPC_INS_LHZU,
                         PPC_INS_LHA, PPC_INS_LHAU) and len(ops) >= 2:
            dst = rn(ops[0])
            if ops[1].type == PPC_OP_MEM:
                base = insn.reg_name(ops[1].mem.base).lower()
                if tainted.get(base):
                    set_t(dst, True)   # dereferencing tainted pointer
                else:
                    set_t(dst, False)  # load from untainted addr — overwrites dst, clears prior taint
                # LWZU also updates the base reg: base = base + offset
                if insn.id in (PPC_INS_LWZU, PPC_INS_LBZU,
                                PPC_INS_LHZU, PPC_INS_LHAU) and len(ops) >= 2:
                    pass  # base-reg writeback: conservative, don't taint base

        # MFLR: not a taint source
        elif insn.id == PPC_INS_MFLR and ops:
            set_t(rn(ops[0]), False)

        # Stores and compare instructions: no reg taint update

    def _analyze_function(
        self,
        func_va: int,
        func_end_va: int,
        func_bytes: bytes,
        seed_arg_indices: List[int],
    ) -> List[TaintFindingPPC32]:
        tainted: Dict[str, bool] = {}
        for i in seed_arg_indices:
            if i < len(_ARG_REGS):
                tainted[_ARG_REGS[i]] = True

        findings: List[TaintFindingPPC32] = []
        func_name = self._func_name(func_va)
        func_r30 = self._func_r30.get(func_va, 0)

        try:
            all_insns = list(self._md.disasm(func_bytes, func_va))
        except Exception:
            return findings

        prev3 = None
        prev2 = None
        prev1 = None
        for insn in all_insns:
            ops = insn.operands

            # -- Calls: bl/bla/bctrl --
            if insn.id in _CALL_IDS:
                target_name = ''
                if insn.id in (PPC_INS_BL, PPC_INS_BLA) and ops:
                    if ops[0].type == PPC_OP_IMM:
                        target_name = self._plt.get(ops[0].imm, '')
                elif insn.id == PPC_INS_BCTRL and (self._got_offset_to_name or self._got2_va_to_name):
                    target_name = self._resolve_bctrl_name(prev2, prev1, func_r30, prev3)

                if target_name in _SOURCES:
                    tainted['r3'] = True

                elif target_name in self._sinks:
                    hit_args = []
                    for ai, areg in enumerate(_ARG_REGS):
                        if ai in self._sinks.get(target_name, []) and tainted.get(areg):
                            hit_args.append(ai)
                    if hit_args:
                        findings.append(TaintFindingPPC32(
                            binary=self.binary_path,
                            func_va=func_va,
                            func_name=func_name,
                            sink_va=insn.address,
                            sink_name=target_name,
                            tainted_args=hit_args,
                            source_name='recv/arg',
                        ))

                # Clobber caller-saved after call
                for r in _CALLER_SAVED - {'r3'}:
                    tainted[r] = False
                if target_name not in _SOURCES:
                    tainted['r3'] = False

            # -- Return: blr/blrl --
            elif insn.id in _RET_IDS:
                break

            # -- Everything else: taint propagation --
            else:
                self._exec_insn(insn, tainted)

            prev3, prev2, prev1 = prev2, prev1, insn

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_on_function(self, func_va: int, func_end_va: int = 0) -> List[TaintFindingPPC32]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, [])

    def run_on_function_seeded(
        self, func_va: int, seed_arg_indices: List[int], func_end_va: int = 0
    ) -> List[TaintFindingPPC32]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, seed_arg_indices)

    def run(self) -> List[TaintFindingPPC32]:
        func_starts = self._get_func_starts()
        findings: List[TaintFindingPPC32] = []
        func_end_map = {
            fva: (func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES)
            for i, fva in enumerate(func_starts)
        }
        for fva, fend in func_end_map.items():
            size = min(fend - fva, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(fva, size)
            if not func_bytes or len(func_bytes) < 8:
                continue
            try:
                findings.extend(self._analyze_function(fva, fend, func_bytes, []))
            except Exception:
                continue
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[TaintFindingPPC32]:
        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        func_start_set = set(func_starts)
        func_end_map: Dict[int, int] = {
            fva: (func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES)
            for i, fva in enumerate(func_starts)
        }

        # Seed: functions that directly call a network source
        seed_funcs: Dict[int, str] = {}
        for fva in func_starts:
            fend = func_end_map[fva]
            func_bytes = self._va_to_slice(fva, min(fend - fva, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 8:
                continue
            try:
                prev3 = None
                prev2 = None
                prev1 = None
                for insn in self._md.disasm(func_bytes, fva):
                    if insn.id == PPC_INS_BL and insn.operands:
                        op = insn.operands[0]
                        if op.type == PPC_OP_IMM:
                            name = self._plt.get(op.imm, '')
                            if name in _SOURCES:
                                seed_funcs[fva] = name
                                break
                    elif insn.id == PPC_INS_BCTRL and (self._got_offset_to_name or self._got2_va_to_name):
                        cur_r30 = self._func_r30.get(fva, 0)
                        name = self._resolve_bctrl_name(prev2, prev1, cur_r30, prev3)
                        if name in _SOURCES:
                            seed_funcs[fva] = name
                            break
                    prev3, prev2, prev1 = prev2, prev1, insn
            except Exception:
                continue

        results: List[TaintFindingPPC32] = []
        queue: deque = deque()
        visited: Set[tuple] = set()

        for fva, src_name in seed_funcs.items():
            key = (fva, frozenset())
            if key not in visited:
                visited.add(key)
                queue.append((fva, [], 0, src_name))

        while queue:
            func_va, seed_arg_indices, depth_cur, source_name = queue.popleft()
            if depth_cur > depth:
                continue

            fend = func_end_map.get(func_va, func_va + MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(func_va, min(fend - func_va, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 8:
                continue

            try:
                findings = self._analyze_function(func_va, fend, func_bytes, seed_arg_indices)
            except Exception:
                continue

            results.extend(findings)

            # Propagate tainted args into callees
            try:
                tainted: Dict[str, bool] = {_ARG_REGS[i]: True for i in seed_arg_indices
                                             if i < len(_ARG_REGS)}
                for insn in self._md.disasm(func_bytes, func_va):
                    if insn.id in _CALL_IDS:
                        if insn.id == PPC_INS_BL and insn.operands:
                            op = insn.operands[0]
                            if op.type == PPC_OP_IMM:
                                callee_va = op.imm
                                if callee_va in func_start_set:
                                    tainted_passed = [
                                        ai for ai, ar in enumerate(_ARG_REGS)
                                        if tainted.get(ar)
                                    ]
                                    if tainted_passed:
                                        key = (callee_va, frozenset(tainted_passed))
                                        if key not in visited:
                                            visited.add(key)
                                            queue.append((callee_va, tainted_passed,
                                                          depth_cur + 1, source_name))
                        for r in _CALLER_SAVED:
                            tainted[r] = False
                    elif insn.id in _RET_IDS:
                        break
                    else:
                        self._exec_insn(insn, tainted)
            except Exception:
                pass

        return results

    def report(self, findings: List[TaintFindingPPC32]) -> str:
        if not findings:
            return f'[ppc32_taint] No findings in {self.binary_path}'
        lines = [f'[ppc32_taint] {self.binary_path}: {len(findings)} finding(s)']
        for f in findings:
            lines.append(f'  {f}')
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='PPC32 taint tracker')
    ap.add_argument('binary')
    ap.add_argument('--le', action='store_true', help='little-endian (default: big-endian)')
    ap.add_argument('--interprocedural', action='store_true')
    ap.add_argument('--depth', type=int, default=4)
    args = ap.parse_args()

    tracker = PPC32TaintTracker.from_path(args.binary, endian='little' if args.le else 'big')
    if args.interprocedural:
        results = tracker.run_interprocedural(depth=args.depth)
    else:
        results = tracker.run()
    print(tracker.report(results))


if __name__ == '__main__':
    _cli()
