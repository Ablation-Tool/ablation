"""
Infineon/Siemens C166/C167 ISA decoder for ECU firmware (AG-8).

The C166/C167 is a 16-bit CISC core produced by Siemens/Infineon, used in BMW
MS43 (M54 engine), Bosch KW1, Motronic M3.x, and various Daimler/VW ECUs.
Capstone has no C166 support; this module implements decoding in pure Python
from the Infineon C167CR V1.0 instruction-set reference.

Instruction width
-----------------
Instructions are 2 or 4 bytes. The opcode byte determines the length through
``_FOUR_BYTE_OPS``; an incomplete table misaligns every following instruction.

Address spaces
--------------
JMPS and CALLS encode an 8-bit code segment and a 16-bit code address, so code
segments are 64 KB. Data pointers use a separate DPP mapping with 16 KB pages.
``resolve_pa()`` preserves power-of-two ROM mirroring; non-power-of-two images
are accepted without applying a mirror mask.

Confirmed byte-verified patterns::

  E6 FC AE 96  MOV R12, #0x96AE
  66 F4 20 00  AND R4, #0x0020
  DA 02 D0 03  CALLS seg=0x02, 0x03D0
  EC FD        PUSH R13
  FC FD        POP R13
  DB 00        RETS
  F2 F0 24 F0  MOV R0, [0xF024]
  F6 F4 8E E1  MOV [0xE18E], R4

Usage::

    from ablation.analyzers.ecu_c166_decoder import EcuC166Decoder

    dec = EcuC166Decoder(rom_path)
    ivt = dec.parse_ivt()
    insns = dec.disassemble(0x01AB80, 0x01AE10)
    seed_refs = dec.scan_xram_loads(0x96AE)
    calls_targets = dec.function_starts()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Opcode tables
# ---------------------------------------------------------------------------

# C166 Family Instruction Set Manual, instruction overview and encodings.
_FOUR_BYTE_OPS: frozenset[int] = frozenset({
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0A, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x1A, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x2A, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x3A, 0x42, 0x43, 0x46, 0x47,
    0x4A, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x5A,
    0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x6A, 0x72,
    0x73, 0x74, 0x75, 0x76, 0x77, 0x7A, 0x82, 0x84,
    0x86, 0x87, 0x8A, 0x92, 0x94, 0x96, 0x97, 0x9A,
    0xA2, 0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xB2, 0xB4,
    0xB5, 0xB6, 0xB7, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6,
    0xCA, 0xD2, 0xD4, 0xD5, 0xD6, 0xD7, 0xDA, 0xE2,
    0xE4, 0xE6, 0xE7, 0xEA, 0xF2, 0xF3, 0xF4, 0xF6,
    0xF7, 0xFA,
})

# Instruction type tags
_MOV_IMM  = 'MOV_IMM'    # MOV Rwn, #data16
_MOV_IMM4 = 'MOV_IMM4'   # MOV Rwn, #data4
_CMP_IMM  = 'CMP_IMM'    # CMP reg, #data16
_CMP_IMM3 = 'CMP_IMM3'   # CMP Rwn, #data3
_CMP_REG  = 'CMP_REG'    # CMP Rwn, Rwm
_CMP_MEM  = 'CMP_MEM'    # CMP reg, mem or register-indirect memory
_CMPB_IMM = 'CMPB_IMM'   # CMPB reg, #data8 (low byte of data16)
_CMPB_IMM3 = 'CMPB_IMM3'  # CMPB Rbn, #data3
_CMPB_REG = 'CMPB_REG'   # CMPB Rbn, Rbm
_CMPB_MEM = 'CMPB_MEM'   # CMPB reg, mem or register-indirect memory
_CMPD     = 'CMPD'       # CMPD1/CMPD2 Rwn, mem
_AND_IMM  = 'AND_IMM'    # AND Rwn, #data16
_ADD_IMM  = 'ADD_IMM'    # ADD Rwn, #data16
_JMPS     = 'JMPS'       # JMPS seg, caddr
_CALLS    = 'CALLS'      # CALLS seg, caddr
_JMPA     = 'JMPA'       # JMPA cc, caddr
_JMPI     = 'JMPI'       # JMPI cc, [Rwn]; target is not statically resolved
_CALLA    = 'CALLA'      # CALLA cc, caddr
_MOV_LD   = 'MOV_LD'     # load from direct/indirect memory address
_MOV_ST   = 'MOV_ST'     # store to direct/indirect memory address
_MOV_REG  = 'MOV_REG'    # MOV Rwdst, Rwsrc — register-to-register (2-byte, F0)
_ADD_REG  = 'ADD_REG'   # ADD Rwn, Rwm — word add (2-byte, 00 nm); from PDF table col x0 row 0
_XOR_REG  = 'XOR_REG'   # XOR Rwn, Rwm — word XOR (2-byte, 50 nm); from PDF table col x0 row 5
_MOVBZ    = 'MOVBZ'     # MOVBZ Rwn, Rbm — byte zero-extend to word (2-byte, C0 nm); from PDF col x0 row C
_MOVBS    = 'MOVBS'     # MOVBS Rwn, Rbm — byte sign-extend to word (2-byte, D0 nm); from PDF col x0 row D
_MUL_REG  = 'MUL_REG'  # MUL Rwn, Rwm  — signed 16×16 multiply; result in MDL:MDH (2-byte, 0B nm); PDF row xB col 0
_MULU_REG = 'MULU_REG' # MULU Rwn, Rwm — unsigned 16×16 multiply; result in MDL:MDH (2-byte, 1B nm); PDF row xB col 1
_SHL_REG  = 'SHL_REG'  # SHL Rwn, Rwm  — logical shift left by register count (2-byte, 4C nm); PDF row xC col 4
_SHL_IMM  = 'SHL_IMM'  # SHL Rwn, #data4 — logical shift left by immediate 0–15 (2-byte, 5C nm); PDF row xC col 5
_SHR_REG  = 'SHR_REG'  # SHR Rwn, Rwm  — logical shift right by register count (2-byte, 6C nm); PDF row xC col 6
_SHR_IMM  = 'SHR_IMM'  # SHR Rwn, #data4 — logical shift right by immediate 0–15 (2-byte, 7C nm); PDF row xC col 7
_PUSH     = 'PUSH'       # PUSH reg — push register onto stack (2-byte, EC)
_POP      = 'POP'        # POP reg — pop register from stack (2-byte, FC)
_RET      = 'RET'        # RET — near return (2-byte, CB 00)
_RETS     = 'RETS'       # RETS — segmented return (2-byte, DB 00)
_JMPR     = 'JMPR'       # JMPR cc, rel8 — relative conditional branch (2-byte, nD rel)
_UNKNOWN2 = 'UNKNOWN_2B'
_UNKNOWN4 = 'UNKNOWN_4B'

# Condition codes from the C166 Family Instruction Set Manual, Table 4-4.
_JMPR_CC = (
    'UC', 'NET', 'Z', 'NZ', 'V', 'NV', 'N', 'NN',
    'C', 'NC', 'SGT', 'SLE', 'SLT', 'SGE', 'UGT', 'ULE',
)


def _byte_reg_name(reg: int) -> str:
    return f'R{"H" if reg & 1 else "L"}{reg >> 1}'


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class C166Insn:
    """A decoded C166/C167 instruction."""

    pa: int               # physical address (file offset for flat ROM)
    raw: bytes            # 2 or 4 raw bytes
    mnemonic: str         # decoded mnemonic string
    insn_type: str        # one of the _xxx constants above
    reg: Optional[int] = None    # dest/src register number (0–15), if applicable
    imm: Optional[int] = None    # immediate value or direct address
    target: Optional[int] = None # resolved target PA for branches/calls
    seg: Optional[int] = None    # segment byte for absolute branches/calls

    @property
    def is_branch(self) -> bool:
        return self.insn_type in (_JMPS, _JMPA, _JMPR, _JMPI)

    @property
    def is_call(self) -> bool:
        return self.insn_type in (_CALLS, _CALLA)

    @property
    def is_load(self) -> bool:
        return self.insn_type in (
            _MOV_IMM, _MOV_IMM4, _MOV_LD, _MOV_REG, _MOVBZ, _MOVBS,
            'MOVB_REG', 'MOVB_IMM',
        )

    @property
    def is_store(self) -> bool:
        return self.insn_type == _MOV_ST

    def __str__(self) -> str:
        raw_hex = self.raw.hex(' ')
        return (
            f'0x{self.pa:06X}  {raw_hex:<11}  {self.mnemonic}'
        )


@dataclass
class IVTEntry:
    """A parsed interrupt vector table entry (4-byte JMPS instruction)."""

    index: int            # vector index (0 = reset, 4 = NMI, …)
    pa: int               # PA of the IVT entry itself
    seg: int              # target code segment
    addr: int             # target code address
    target_pa: int        # resolved target physical address


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class EcuC166Decoder:
    """
    Decode C166/C167 instructions from a raw ROM binary.

    Parameters
    ----------
    data
        Raw bytes, ``str`` path, or ``pathlib.Path``. Images may have any
        nonzero size up to the C166 24-bit physical address space.
    base_pa
        Physical address of the first byte in ``data``. Almost always 0 for
        flat ECU ROM images (file offset == PA).

    Notes
    -----
    Instruction length is determined from ``_FOUR_BYTE_OPS``. Unknown
    operations remain explicit rather than stopping a linear walk.
    """

    def __init__(self, data: 'str | Path | bytes', base_pa: int = 0) -> None:
        if not 0 <= base_pa <= 0xFFFFFF:
            raise ValueError('EcuC166Decoder: base_pa outside 24-bit address space')
        if isinstance(data, (str, Path)):
            p = Path(data)
            if not p.exists():
                raise FileNotFoundError(f'EcuC166Decoder: {data!r} not found')
            if p.stat().st_size > 0x1000000:
                raise ValueError('EcuC166Decoder: image exceeds 24-bit address space')
            self._data = p.read_bytes()
        else:
            self._data = bytes(data)
        if not self._data:
            raise ValueError('EcuC166Decoder: empty ROM image')
        if len(self._data) > 0x1000000:
            raise ValueError('EcuC166Decoder: image exceeds 24-bit address space')
        if base_pa + len(self._data) > 0x1000000:
            raise ValueError('EcuC166Decoder: image extends beyond 24-bit address space')
        self._base_pa = base_pa
        self._rom_size = len(self._data)

    # ---- Constructors ----

    @classmethod
    def from_path(cls, path: 'str | Path', base_pa: int = 0) -> 'EcuC166Decoder':
        return cls(path, base_pa)

    @classmethod
    def from_bytes(cls, data: bytes, base_pa: int = 0) -> 'EcuC166Decoder':
        return cls(data, base_pa)

    # ---- Public API ----

    def insn_length(self, byte_off: int) -> int:
        """Return 2 or 4 — byte length of instruction at ``byte_off``."""
        if byte_off < 0 or byte_off >= len(self._data):
            return 0
        op = self._data[byte_off]
        return 4 if op in _FOUR_BYTE_OPS else 2

    def decode_one(self, byte_off: int) -> Optional[C166Insn]:
        """
        Decode a single instruction at ``byte_off`` (file offset).

        Returns ``None`` when the offset is past the end or there are not
        enough bytes for the instruction.
        """
        data = self._data
        if byte_off < 0 or byte_off >= len(data):
            return None
        op = data[byte_off]
        pa = self._base_pa + byte_off
        is4 = op in _FOUR_BYTE_OPS
        if is4 and byte_off + 4 > len(data):
            return None
        if not is4 and byte_off + 2 > len(data):
            return None

        if is4:
            raw = data[byte_off: byte_off + 4]
            return self._decode4(pa, raw)
        else:
            raw = data[byte_off: byte_off + 2]
            return self._decode2(pa, raw)

    def disassemble(
        self,
        start_pa: Optional[int] = None,
        end_pa: Optional[int] = None,
    ) -> list[C166Insn]:
        """
        Linearly disassemble instructions from ``start_pa`` to ``end_pa``.

        Unknown 2-byte opcodes are represented as UNKNOWN_2B entries and do
        not interrupt the walk.  If ``start_pa`` or ``end_pa`` are omitted,
        the full ROM is disassembled.
        """
        base = self._base_pa
        data = self._data
        size = len(data)
        s_off = (0 if start_pa is None else start_pa - base)
        e_off = (size if end_pa is None else end_pa - base)
        s_off = max(0, min(s_off, size))
        e_off = max(0, min(e_off, size))

        result: list[C166Insn] = []
        off = s_off
        while off < e_off:
            insn = self.decode_one(off)
            if insn is None:
                break
            result.append(insn)
            off += len(insn.raw)
        return result

    def function_starts(self) -> list[int]:
        """
        Return all CALLS target PAs found by scanning the full ROM.

        Targets are physical code addresses after applying the configured
        ROM-mirror behavior.
        """
        targets: list[int] = []
        data = self._data
        size = len(data)
        off = 0
        while off < size - 3:
            if data[off] == 0xDA:
                raw = data[off: off + 4]
                insn = self._decode4(self._base_pa + off, raw)
                if insn.target is not None:
                    targets.append(insn.target)
            off += 4 if data[off] in _FOUR_BYTE_OPS else 2
        return targets

    def scan_xram_loads(self, xram_addr: int) -> list[C166Insn]:
        """Return immediate and direct references to a 16-bit data offset."""
        if not 0 <= xram_addr <= 0xFFFF:
            raise ValueError('EcuC166Decoder: data offset outside 16-bit range')
        results: list[C166Insn] = []
        data = self._data
        size = len(data)
        lo = xram_addr & 0xFF
        hi = (xram_addr >> 8) & 0xFF
        for off in range(0, size - 3):
            if data[off + 2] == lo and data[off + 3] == hi:
                op = data[off]
                if op in _FOUR_BYTE_OPS:
                    insn = self._decode4(self._base_pa + off, data[off: off + 4])
                    if insn.insn_type in (_MOV_IMM, _CMP_IMM, _MOV_LD, _MOVBZ):
                        results.append(insn)
        return results

    def scan_dpp_loads(
        self, physical_addr: int, dpp: int, dpp_index: int,
    ) -> list[C166Insn]:
        """Return references using an explicit DPP register and page value."""
        return self.scan_xram_loads(self.dpp_offset(physical_addr, dpp, dpp_index))

    def scan_xram_stores(self, xram_addr: int) -> list[C166Insn]:
        """Return all MOV_ST instructions that store to ``xram_addr``."""
        if not 0 <= xram_addr <= 0xFFFF:
            raise ValueError('EcuC166Decoder: data offset outside 16-bit range')
        results: list[C166Insn] = []
        data = self._data
        size = len(data)
        lo = xram_addr & 0xFF
        hi = (xram_addr >> 8) & 0xFF
        for off in range(0, size - 3):
            op = data[off]
            if op in (0xF6, 0xF7, 0xC5, 0xD5) and data[off + 2] == lo and data[off + 3] == hi:
                results.append(
                    self._decode4(self._base_pa + off, data[off: off + 4])
                )
        return results

    def parse_ivt(
        self, num_vectors: int = 64, start_pa: Optional[int] = None,
    ) -> list[IVTEntry]:
        """Parse JMPS vector entries at ``start_pa`` or the image base."""
        if num_vectors < 0:
            raise ValueError('EcuC166Decoder: negative vector count')
        table_pa = self._base_pa if start_pa is None else start_pa
        table_off = table_pa - self._base_pa
        if table_off < 0:
            raise ValueError('EcuC166Decoder: IVT starts before image')
        entries: list[IVTEntry] = []
        data = self._data
        for i in range(num_vectors):
            off = table_off + i * 4
            if off + 4 > len(data):
                break
            b = data[off: off + 4]
            if b[0] != 0xFA:
                continue
            seg = b[1]
            addr = struct.unpack_from('<H', b, 2)[0]
            entries.append(IVTEntry(
                index=i,
                pa=table_pa + i * 4,
                seg=seg,
                addr=addr,
                target_pa=self.resolve_pa(seg, addr),
            ))
        return entries

    @staticmethod
    def code_pa(seg: int, addr: int) -> int:
        """Convert a code segment/address pair to a 24-bit physical address."""
        if not 0 <= seg <= 0xFF or not 0 <= addr <= 0xFFFF:
            raise ValueError('EcuC166Decoder: invalid code segment/address')
        return (seg << 16) | addr

    @staticmethod
    def dpp_pa(offset: int, dpp: int) -> int:
        """Convert a 16-bit data offset and DPP page to a physical address."""
        if not 0 <= offset <= 0xFFFF or not 0 <= dpp <= 0x3FF:
            raise ValueError('EcuC166Decoder: invalid DPP offset/page')
        return (dpp << 14) | (offset & 0x3FFF)

    @staticmethod
    def dpp_offset(physical_addr: int, dpp: int, dpp_index: int) -> int:
        """Recover a data offset using an explicit DPP register and page."""
        if not 0 <= physical_addr <= 0xFFFFFF or not 0 <= dpp_index <= 3:
            raise ValueError('EcuC166Decoder: invalid physical address/DPP register')
        offset = (dpp_index << 14) | (physical_addr & 0x3FFF)
        if EcuC166Decoder.dpp_pa(offset, dpp) != physical_addr:
            raise ValueError('EcuC166Decoder: physical address is outside DPP page')
        return offset

    def resolve_pa(self, seg: int, addr: int) -> int:
        """Resolve a code target, folding mirrors for power-of-two ROMs."""
        physical = self.code_pa(seg, addr)
        if self._rom_size & (self._rom_size - 1):
            return physical
        if self._base_pa <= physical < self._base_pa + self._rom_size:
            return physical
        return self._base_pa + (physical & (self._rom_size - 1))

    def is_c166_rom(self, start_pa: Optional[int] = None) -> bool:
        """Return whether at least 32 of 64 IVT slots contain JMPS opcodes."""
        table_pa = self._base_pa if start_pa is None else start_pa
        table_off = table_pa - self._base_pa
        if table_off < 0 or table_off + 256 > len(self._data):
            return False
        return sum(
            self._data[table_off + offset] == 0xFA
            for offset in range(0, 256, 4)
        ) >= 32

    # ---- Internal ----

    def _decode4(self, pa: int, raw: bytes) -> C166Insn:
        """Decode a known 4-byte instruction."""
        op = raw[0]
        b1 = raw[1]
        imm = struct.unpack_from('<H', raw, 2)[0]

        if op == 0xE6:
            reg = b1 & 0x0F
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MOV R{reg:X}, #{imm:#06x}',
                insn_type=_MOV_IMM,
                reg=reg, imm=imm,
            )

        if op in (0x46, 0x66):
            reg = b1 & 0x0F
            mnemonic = 'CMP' if op == 0x46 else 'AND'
            insn_type = _CMP_IMM if op == 0x46 else _AND_IMM
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} R{reg:X}, #{imm:#06x}',
                insn_type=insn_type,
                reg=reg, imm=imm,
            )

        if op in (0x42, 0x43):
            reg = b1 & 0x0F
            byte = op == 0x43
            operand = _byte_reg_name(reg) if byte else f'R{reg:X}'
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{"CMPB" if byte else "CMP"} {operand}, [{imm:#06x}]',
                insn_type=_CMPB_MEM if byte else _CMP_MEM,
                reg=reg, imm=imm,
            )

        if op in (0x07, 0x47, 0xE7):
            reg = b1 & 0x0F
            value = raw[2]
            mnemonic = {0x07: 'ADDB', 0x47: 'CMPB', 0xE7: 'MOVB'}[op]
            insn_type = {0x07: 'ADDB_IMM', 0x47: _CMPB_IMM, 0xE7: 'MOVB_IMM'}[op]
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} {_byte_reg_name(reg)}, #{value:#04x}',
                insn_type=insn_type,
                reg=reg, imm=value,
            )

        if op == 0x26:
            reg = b1 & 0x0F
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SUB R{reg:X}, #{imm:#06x}',
                insn_type='SUB_IMM',
                reg=reg, imm=imm,
            )

        if op == 0x06:
            reg = b1 & 0x0F
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'ADD R{reg:X}, #{imm:#06x}',
                insn_type=_ADD_IMM,
                reg=reg, imm=imm,
            )

        if op in (0xFA, 0xDA):
            seg = b1
            addr = imm
            tgt = self.resolve_pa(seg, addr)
            mn = 'JMPS' if op == 0xFA else 'CALLS'
            tp = _JMPS if op == 0xFA else _CALLS
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mn} seg={seg:#04x}, {addr:#06x}  -> PA {tgt:#08x}',
                insn_type=tp,
                seg=seg, imm=addr, target=tgt,
            )

        if op in (0xCA, 0xEA):
            target = (pa & 0xFF0000) | imm
            mnemonic = 'CALLA' if op == 0xCA else 'JMPA'
            insn_type = _CALLA if op == 0xCA else _JMPA
            condition = _JMPR_CC[(b1 >> 4) & 0xF]
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} {condition}, #{imm:#06x}  -> PA {target:#08x}',
                insn_type=insn_type,
                seg=pa >> 16, imm=imm, target=target,
            )

        if op in (0xF2, 0xF3):
            reg = b1 & 0x0F
            mnemonic = 'MOV' if op == 0xF2 else 'MOVB'
            operand = f'R{reg:X}' if op == 0xF2 else _byte_reg_name(reg)
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} {operand}, [{imm:#06x}]',
                insn_type=_MOV_LD,
                reg=reg, imm=imm,
            )

        if op in (0xC2, 0xD2):
            reg = b1 & 0x0F
            mnemonic = 'MOVBZ' if op == 0xC2 else 'MOVBS'
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} {_byte_reg_name(reg)}, [{imm:#06x}]',
                insn_type=_MOVBZ if op == 0xC2 else _MOVBS,
                reg=reg, imm=imm,
            )

        if op in (0xF6, 0xF7, 0xC5, 0xD5):
            reg = b1 & 0x0F
            mnemonics = {0xF6: 'MOV', 0xF7: 'MOVB', 0xC5: 'MOVBZ', 0xD5: 'MOVBS'}
            operand = f'R{reg:X}' if op == 0xF6 else _byte_reg_name(reg)
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonics[op]} [{imm:#06x}], {operand}',
                insn_type=_MOV_ST,
                reg=reg, imm=imm,
            )

        if op in (0xA2, 0xB2, 0xA6, 0xB6):
            reg = b1 & 0x0F
            mnemonic = 'CMPD1' if op in (0xA2, 0xA6) else 'CMPD2'
            operand = f'#{imm:#06x}' if op in (0xA6, 0xB6) else f'[{imm:#06x}]'
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} R{reg:X}, {operand}',
                insn_type=_CMPD,
                reg=reg, imm=imm,
            )

        if op in (0xD4, 0xF4):
            dst = (b1 >> 4) & 0x0F
            base = b1 & 0x0F
            mnemonic = 'MOV' if op == 0xD4 else 'MOVB'
            operand = f'R{dst:X}' if op == 0xD4 else _byte_reg_name(dst)
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} {operand}, [R{base:X}+#{imm:#06x}]',
                insn_type=_MOV_LD,
                reg=dst, imm=imm,
            )

        if op in (0xC4, 0xE4):
            src = (b1 >> 4) & 0x0F
            base = b1 & 0x0F
            mnemonic = 'MOV' if op == 0xC4 else 'MOVB'
            operand = f'R{src:X}' if op == 0xC4 else _byte_reg_name(src)
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} [R{base:X}+#{imm:#06x}], {operand}',
                insn_type=_MOV_ST,
                reg=src, imm=imm,
            )

        # Unknown 4-byte (should not reach here, but guard)
        return C166Insn(
            pa=pa, raw=raw,
            mnemonic=f'db {raw.hex(" ")}',
            insn_type=_UNKNOWN4,
        )

    def _decode2(self, pa: int, raw: bytes) -> C166Insn:
        """Decode a 2-byte instruction.

        Encodings are empirically confirmed from MS43 ROM analysis
        (prologue/epilogue mirroring, post-CMP branch target arithmetic).
        """
        op = raw[0]
        b1 = raw[1]

        if op == 0x29 and not (b1 & 0x08):
            dst = (b1 >> 4) & 0xF
            imm = b1 & 0x07
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SUBB {_byte_reg_name(dst)}, #{imm}',
                insn_type='SUBB_IMM',
                reg=dst,
                imm=imm,
            )

        if op in (0x28, 0x48, 0x49):
            dst = (b1 >> 4) & 0xF
            mnemonic = {0x28: 'SUB', 0x48: 'CMP', 0x49: 'CMPB'}[op]
            operand = f'R{dst:X}' if op != 0x49 else _byte_reg_name(dst)
            if b1 & 0x08:
                base = b1 & 0x03
                suffix = '+' if b1 & 0x04 else ''
                source = f'[R{base:X}{suffix}]'
                imm = None
                insn_type = {
                    0x28: 'SUB_MEM', 0x48: _CMP_MEM, 0x49: _CMPB_MEM,
                }[op]
            else:
                imm = b1 & 0x07
                source = f'#{imm}'
                insn_type = {
                    0x28: 'SUB_IMM3', 0x48: _CMP_IMM3, 0x49: _CMPB_IMM3,
                }[op]
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} {operand}, {source}',
                insn_type=insn_type,
                reg=dst, imm=imm,
            )

        if op in (0x40, 0x41):
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            byte = op == 0x41
            source = _byte_reg_name(src) if byte else f'R{src:X}'
            operand = _byte_reg_name(dst) if byte else f'R{dst:X}'
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{"CMPB" if byte else "CMP"} {operand}, {source}',
                insn_type=_CMPB_REG if byte else _CMP_REG,
                reg=dst,
            )

        # ADD Rwn, Rwm: opcode 0x00, byte1 = (dst<<4)|src.
        # From PDF opcode table: lower-nibble-0 col, upper-nibble-0 row = ADD.
        # Cross-check: 0x50 (XOR) and 0xF0 (MOV) are at rows 5 and F of the same column.
        if op == 0x00:
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'ADD R{dst:X}, R{src:X}',
                insn_type=_ADD_REG,
                reg=dst,
            )

        # XOR Rwn, Rwm: opcode 0x50, byte1 = (dst<<4)|src.
        # From PDF opcode table: lower-nibble-0 col, upper-nibble-5 row = XOR.
        # Corrects prior assumption that 0xC0 was XOR — 0xC0 is MOVBZ.
        if op == 0x50:
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'XOR R{dst:X}, R{src:X}',
                insn_type=_XOR_REG,
                reg=dst,
            )

        # MOVBZ/MOVBS Rwn, Rbm: high nibble is the word destination.
        if op in (0xC0, 0xD0):
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=(
                    f'{"MOVBZ" if op == 0xC0 else "MOVBS"} '
                    f'R{dst:X}, {_byte_reg_name(src)}'
                ),
                insn_type=_MOVBZ if op == 0xC0 else _MOVBS,
                reg=dst,
            )

        # MUL Rwn, Rwm: opcode 0x0B, byte1 = (n<<4)|m.
        # Signed 16x16 multiply; 32-bit result stored in MDL:MDH (SFR 0xFE0E:0xFE0C).
        # From PDF table row xB, position 0 (upper nibble 0, lower nibble B).
        # Seen as '0b 00' (MUL R0, R0) in MS43 LFSR step function inner loop.
        if op == 0x0B:
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MUL R{dst:X}, R{src:X}',
                insn_type=_MUL_REG,
                reg=dst,
            )

        # MULU Rwn, Rwm: opcode 0x1B, byte1 = (n<<4)|m.
        # Unsigned 16x16 multiply; 32-bit result stored in MDL:MDH.
        # From PDF table row xB, position 1 (upper nibble 1, lower nibble B).
        if op == 0x1B:
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MULU R{dst:X}, R{src:X}',
                insn_type=_MULU_REG,
                reg=dst,
            )

        # SHL Rwn, Rwm: opcode 0x4C, byte1 = (n<<4)|m.
        # Logical shift left of Rwn by shift count in Rwm (count mod 16).
        # From PDF table row xC, position 4 (upper nibble 4, lower nibble C).
        if op == 0x4C:
            dst = (b1 >> 4) & 0xF
            cnt = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SHL R{dst:X}, R{cnt:X}',
                insn_type=_SHL_REG,
                reg=dst,
            )

        # SHL Rwn, #data4: opcode 0x5C, byte1 = (count<<4)|n.
        # Seen as '5c 25' (SHL R5, #2) in the MS43 seed-key outer loop.
        if op == 0x5C:
            dst = b1 & 0xF
            cnt = (b1 >> 4) & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SHL R{dst:X}, #{cnt}',
                insn_type=_SHL_IMM,
                reg=dst,
                imm=cnt,
            )

        # SHR Rwn, Rwm: opcode 0x6C, byte1 = (n<<4)|m.
        if op == 0x6C:
            dst = (b1 >> 4) & 0xF
            cnt = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SHR R{dst:X}, R{cnt:X}',
                insn_type=_SHR_REG,
                reg=dst,
            )

        # SHR Rwn, #data4: opcode 0x7C, byte1 = (count<<4)|n.
        if op == 0x7C:
            dst = b1 & 0xF
            cnt = (b1 >> 4) & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SHR R{dst:X}, #{cnt}',
                insn_type=_SHR_IMM,
                reg=dst,
                imm=cnt,
            )

        if op in (0x88, 0x98, 0xA8, 0xB8):
            reg = (b1 >> 4) & 0xF
            base = b1 & 0xF
            if op == 0x88:
                mnemonic, insn_type = f'MOV [-R{base:X}], R{reg:X}', _MOV_ST
            elif op == 0xB8:
                mnemonic, insn_type = f'MOV [R{base:X}], R{reg:X}', _MOV_ST
            elif op == 0x98:
                mnemonic, insn_type = f'MOV R{reg:X}, [R{base:X}+]', _MOV_LD
            else:
                mnemonic, insn_type = f'MOV R{reg:X}, [R{base:X}]', _MOV_LD
            return C166Insn(pa=pa, raw=raw, mnemonic=mnemonic,
                            insn_type=insn_type, reg=reg)

        if op in (0x89, 0x99, 0xA9, 0xB9):
            reg = (b1 >> 4) & 0xF
            base = b1 & 0xF
            operand = _byte_reg_name(reg)
            if op == 0x89:
                mnemonic, insn_type = f'MOVB [-R{base:X}], {operand}', _MOV_ST
            elif op == 0xB9:
                mnemonic, insn_type = f'MOVB [R{base:X}], {operand}', _MOV_ST
            elif op == 0x99:
                mnemonic, insn_type = f'MOVB {operand}, [R{base:X}+]', _MOV_LD
            else:
                mnemonic, insn_type = f'MOVB {operand}, [R{base:X}]', _MOV_LD
            return C166Insn(pa=pa, raw=raw, mnemonic=mnemonic,
                            insn_type=insn_type, reg=reg)

        if op in (0xEC, 0xFC):
            reg = b1 & 0x0F
            mnemonic = 'PUSH' if op == 0xEC else 'POP'
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} R{reg:X}',
                insn_type=_PUSH if op == 0xEC else _POP,
                reg=reg,
            )

        if op in (0xCB, 0xDB) and b1 == 0x00:
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic='RET' if op == 0xCB else 'RETS',
                insn_type=_RET if op == 0xCB else _RETS,
            )

        # JMPR displacement is a signed count of two-byte words.
        if (op & 0x0F) == 0x0D:
            cc = (op >> 4) & 0xF
            rel = struct.unpack_from('b', raw, 1)[0]
            target = pa + 2 + rel * 2
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'JMPR {_JMPR_CC[cc]}, 0x{target:06X}',
                insn_type=_JMPR,
                target=target,
                imm=rel,
            )

        if op == 0x9C:
            reg = (b1 >> 4) & 0xF
            base = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'JMPI {_JMPR_CC[reg]}, [R{base:X}]',
                insn_type=_JMPI,
                reg=base,
            )

        if op in (0xF0, 0xF1):
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            byte = op == 0xF1
            destination = _byte_reg_name(dst) if byte else f'R{dst:X}'
            source = _byte_reg_name(src) if byte else f'R{src:X}'
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{"MOVB" if byte else "MOV"} {destination}, {source}',
                insn_type='MOVB_REG' if byte else _MOV_REG,
                reg=dst,
            )

        if op in (0xE0, 0xE1):
            reg = b1 & 0xF
            immediate = (b1 >> 4) & 0xF
            mnemonic = 'MOV' if op == 0xE0 else 'MOVB'
            operand = f'R{reg:X}' if op == 0xE0 else _byte_reg_name(reg)
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'{mnemonic} {operand}, #{immediate}',
                insn_type=_MOV_IMM4,
                reg=reg, imm=immediate,
            )

        return C166Insn(
            pa=pa, raw=raw,
            mnemonic=f'db {raw.hex(" ")}',
            insn_type=_UNKNOWN2,
        )
