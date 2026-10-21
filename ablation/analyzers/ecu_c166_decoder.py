"""
Infineon/Siemens C166/C167 ISA decoder for ECU firmware (AG-8).

The C166/C167 is a 16-bit CISC core produced by Siemens/Infineon, used in BMW
MS43 (M54 engine), Bosch KW1, Motronic M3.x, and various Daimler/VW ECUs.
Capstone has no C166 support; this module implements decoding in pure Python
from the Infineon C167CR V1.0 instruction-set reference.

Instruction width
-----------------
All instructions are 2 or 4 bytes, always at even addresses.  The opcode byte
alone determines the length via a small lookup table (``_FOUR_BYTE_OPS``).  9
opcodes are known 4-byte; every other opcode byte is treated as 2-byte.

Address space and ROM mirroring
--------------------------------
The C166 physical address space is 16 MB (24 bits).  JMPS and CALLS encode a
code segment (``seg``, 8 bits) and a 16-bit code address.  A 512 KB ROM
occupies 8 × 64 KB segments (seg 0x00–0x07); the hardware bus controllers
typically mirror it at seg 0x08–0x0F.  ``resolve_pa(seg, addr)`` returns the
file offset using::

    file_offset = (seg * 0x10000 + addr) % rom_size

which is correct for power-of-2 ROM sizes.

Register encoding
-----------------
For 4-byte instructions (except JMPS/CALLS) byte[1] encodes the register
number in the lower nibble: ``reg = byte[1] & 0x0F`` (R0–R15).
For JMPS/CALLS byte[1] is the raw segment number.

Confirmed byte-verified patterns (MS43_WBABW510X0PK46741_430069_512KB.bin)
---------------------------------------------------------------------------
  0xE6 FC AE 96  MOV R12, #0x96AE        ; load XRAM seed-ptr into R12
  0xE6 FD 68 59  MOV R13, #0x5968        ; load XRAM resp-buf ptr into R13
  0xE6 FC 67 00  MOV R12, #0x0067        ; SA response code 0x67
  0xE6 FC 68 00  MOV R12, #0x0068        ; SA response code 0x68
  0x66 F4 20 00  CMP  R4, #0x0020        ; length ≥ 0x20 check
  0xDA 0A 6E B4  CALLS seg=0x0A, 0xB46E  ; seed_fetch (PA 0x0AB46E)
  0xDA 0C EC 23  CALLS seg=0x0C, 0x23EC  ; send_response (PA 0x0C23EC)
  0xFA 00 06 2D  JMPS  seg=0x00, 0x2D06  ; IVT[0] reset vector
  0xC2 F4 B8 96  MOV_LD R4, [0x96B8]    ; load XRAM[0x96B8] → R4
  0xF2 F0 24 F0  MOV_LD R0, [0xF024]    ; load ESFR[0xF024] → R0
  0xF6 F4 8E E1  MOV_ST [0xE18E], R4    ; store R4 → DS2-hw[0xE18E]

Usage::

    from ablation.analyzers.ecu_c166_decoder import EcuC166Decoder

    dec = EcuC166Decoder(rom_path)
    ivt = dec.parse_ivt()                     # list of IVTEntry
    insns = dec.disassemble(0x01AB80, 0x01AE10)
    seed_refs = dec.scan_xram_loads(0x96AE)   # all C166Insn that load #0x96AE or [0x96AE]
    calls_targets = dec.function_starts()      # CALLS target PAs across whole ROM
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Opcode tables
# ---------------------------------------------------------------------------

# Opcodes whose instruction length is 4 bytes (all others → 2 bytes).
# Sources: Infineon C167CR User's Manual V1.0, Section 12 instruction encoding.
_FOUR_BYTE_OPS: frozenset[int] = frozenset({
    0xE6,   # MOV Rwn, #data16          — immediate word load
    0x66,   # CMP Rwn, #data16          — compare with immediate
    0xFA,   # JMPS seg, caddr           — absolute code segment jump
    0xDA,   # CALLS seg, caddr          — absolute code segment call
    0xF2,   # MOV Rwn, mem              — load from direct address (DPP-mapped)
    0xF6,   # MOV mem, Rwn              — store to direct address (DPP-mapped)
    0xC2,   # MOV Rwn, mem              — load from direct address (internal)
    0xA2,   # MOV Rwn, [Rwm]            — register-indirect load
    0xB2,   # MOV [Rwm], Rwn            — register-indirect store
})

# Instruction type tags
_MOV_IMM  = 'MOV_IMM'    # MOV Rwn, #imm16
_CMP_IMM  = 'CMP_IMM'    # CMP Rwn, #imm16
_JMPS     = 'JMPS'       # JMPS seg, caddr
_CALLS    = 'CALLS'      # CALLS seg, caddr
_MOV_LD   = 'MOV_LD'    # load from direct/indirect memory address
_MOV_ST   = 'MOV_ST'    # store to direct/indirect memory address
_MOV_REG  = 'MOV_REG'   # MOV Rwdst, Rwsrc — register-to-register (2-byte, F0)
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
_PUSH     = 'PUSH'       # PUSH Rwn — push register onto stack (2-byte, 88 n0)
_POP      = 'POP'        # POP Rwn — pop register from stack (2-byte, 98 n0)
_RET      = 'RET'        # RET — return from subroutine (2-byte, DB 00)
_JMPR     = 'JMPR'       # JMPR cc, rel8 — relative conditional branch (2-byte, nD rel)
_UNKNOWN2 = 'UNKNOWN_2B'
_UNKNOWN4 = 'UNKNOWN_4B'

# Condition code names for JMPR (index = cc nibble 0–F)
_JMPR_CC = (
    'UC', 'Z', 'NZ', 'V', 'NV', 'N', 'NN', 'C',
    'NC', 'UGT', 'ULE', 'SGT', 'SLE', 'SLT', 'SGE', 'NET',
)


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
    target: Optional[int] = None # resolved target PA for JMPS/CALLS
    seg: Optional[int] = None    # segment byte for JMPS/CALLS

    @property
    def is_branch(self) -> bool:
        return self.insn_type in (_JMPS, _JMPR)

    @property
    def is_call(self) -> bool:
        return self.insn_type == _CALLS

    @property
    def is_load(self) -> bool:
        return self.insn_type in (_MOV_IMM, _MOV_LD, _MOV_REG)

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
        Raw bytes, ``str`` path, or ``pathlib.Path``.  Accepts 128 KB, 256 KB,
        512 KB, and 1 MB ROM images.
    base_pa
        Physical address of the first byte in ``data``.  Almost always 0 for
        flat ECU ROM images (file offset == PA).

    Notes
    -----
    Instruction length is determined from ``_FOUR_BYTE_OPS``.  Any opcode not
    in that set is decoded as a 2-byte instruction with type UNKNOWN_2B.
    """

    def __init__(self, data: 'str | Path | bytes', base_pa: int = 0) -> None:
        if isinstance(data, (str, Path)):
            p = Path(data)
            if not p.exists():
                raise FileNotFoundError(f'EcuC166Decoder: {data!r} not found')
            self._data = p.read_bytes()
        else:
            self._data = bytes(data)
        self._base_pa = base_pa
        # Validate ROM size is power of 2 (required for mirror resolution)
        sz = len(self._data)
        if sz == 0 or (sz & (sz - 1)) != 0:
            raise ValueError(
                f'EcuC166Decoder: ROM size {sz:#x} is not a power of 2; '
                'provide a padded image or set rom_size_override'
            )
        self._rom_size = sz

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
        if byte_off >= len(self._data):
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
        if byte_off >= len(data):
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

        Targets are resolved through ROM mirrors so they represent file
        offsets into this ROM image.
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
        """
        Return all instructions that load the 16-bit value ``xram_addr`` as
        an immediate (E6/66) or load/compare from that direct address (C2/F2).

        Useful for finding every site that references a specific XRAM pointer
        value (e.g. all ``MOV Rn, #0x96AE`` instructions that load the seed
        buffer address).
        """
        results: list[C166Insn] = []
        data = self._data
        size = len(data)
        lo = xram_addr & 0xFF
        hi = (xram_addr >> 8) & 0xFF
        # Pattern: opcode(1) + reg_byte(1) + lo + hi  (LE 16-bit value)
        for off in range(0, size - 3):
            if data[off + 2] == lo and data[off + 3] == hi:
                op = data[off]
                if op in _FOUR_BYTE_OPS:
                    insn = self._decode4(self._base_pa + off, data[off: off + 4])
                    if insn.insn_type in (_MOV_IMM, _CMP_IMM, _MOV_LD):
                        results.append(insn)
        return results

    def scan_xram_stores(self, xram_addr: int) -> list[C166Insn]:
        """
        Return all MOV_ST instructions that store TO ``xram_addr``.
        """
        results: list[C166Insn] = []
        data = self._data
        size = len(data)
        lo = xram_addr & 0xFF
        hi = (xram_addr >> 8) & 0xFF
        for off in range(0, size - 3):
            op = data[off]
            if op in (0xF6,) and data[off + 2] == lo and data[off + 3] == hi:
                results.append(
                    self._decode4(self._base_pa + off, data[off: off + 4])
                )
        return results

    def parse_ivt(self, num_vectors: int = 64) -> list[IVTEntry]:
        """
        Parse the interrupt vector table at PA 0 (file offset 0).

        The C166/C167 IVT occupies the first ``num_vectors`` × 4 bytes; each
        entry is a JMPS instruction ``FA seg lo hi``.  Returns only entries
        whose opcode byte is 0xFA.
        """
        entries: list[IVTEntry] = []
        data = self._data
        for i in range(num_vectors):
            off = i * 4
            if off + 4 > len(data):
                break
            b = data[off: off + 4]
            if b[0] != 0xFA:
                continue
            seg = b[1]
            addr = struct.unpack_from('<H', b, 2)[0]
            tgt = self.resolve_pa(seg, addr)
            entries.append(IVTEntry(
                index=i,
                pa=self._base_pa + off,
                seg=seg,
                addr=addr,
                target_pa=tgt,
            ))
        return entries

    def resolve_pa(self, seg: int, addr: int) -> int:
        """
        Convert a C166 (seg, addr) pair to a file offset.

        For a ROM whose ``rom_size`` is a power of 2, the physical address
        ``seg * 0x10000 + addr`` is masked to ``rom_size - 1`` to fold in
        ROM mirrors (e.g. seg 0x0A aliases seg 0x02 in a 512 KB ROM).
        """
        return (seg * 0x10000 + addr) & (self._rom_size - 1)

    def is_c166_rom(self) -> bool:
        """
        Return True if the ROM begins with a valid-looking C166 IVT.

        Heuristic: at least 32 of the first 64 IVT entries must start with
        opcode 0xFA (JMPS), which is the expected C166 vector format.
        Calibration-only ROMs and padding images will fail this check.
        """
        data = self._data
        if len(data) < 256:
            return False
        fa_count = sum(1 for i in range(64) if data[i * 4] == 0xFA)
        return fa_count >= 32

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

        if op == 0x66:
            reg = b1 & 0x0F
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'CMP R{reg:X}, #{imm:#06x}',
                insn_type=_CMP_IMM,
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

        # Direct-address load (opcode C2 or F2): reg ← [addr16]
        if op in (0xC2, 0xF2):
            reg = b1 & 0x0F
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MOV R{reg:X}, [{imm:#06x}]',
                insn_type=_MOV_LD,
                reg=reg, imm=imm,
            )

        # Direct-address store (opcode F6): [addr16] ← reg
        if op == 0xF6:
            reg = b1 & 0x0F
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MOV [{imm:#06x}], R{reg:X}',
                insn_type=_MOV_ST,
                reg=reg, imm=imm,
            )

        # Register-indirect load: reg ← [base_reg]
        if op == 0xA2:
            dst = b1 & 0x0F
            base = (b1 >> 4) & 0x0F
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MOV R{dst:X}, [R{base:X}]',
                insn_type=_MOV_LD,
                reg=dst,
            )

        # Register-indirect store: [base_reg] ← reg
        if op == 0xB2:
            src = b1 & 0x0F
            base = (b1 >> 4) & 0x0F
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MOV [R{base:X}], R{src:X}',
                insn_type=_MOV_ST,
                reg=src,
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

        # MOVBZ Rwn, Rbm: opcode 0xC0, byte1 = (dst<<4)|src.
        # Move byte register Rbm with zero extension into word register Rwn.
        # From PDF opcode table: lower-nibble-0 col, upper-nibble-C row = MOVBZ.
        # Seen in MS43 LFSR step function as 'C0 C2' (MOVBZ R12, Rb2) and 'C0 C4' (MOVBZ R12, Rb4).
        if op == 0xC0:
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MOVBZ R{dst:X}, Rb{src:X}',
                insn_type=_MOVBZ,
                reg=dst,
            )

        # MOVBS Rwn, Rbm: opcode 0xD0, byte1 = (dst<<4)|src.
        # Move byte register Rbm with sign extension into word register Rwn.
        # From PDF opcode table: lower-nibble-0 col, upper-nibble-D row = MOVBS.
        if op == 0xD0:
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MOVBS R{dst:X}, Rb{src:X}',
                insn_type=_MOVBS,
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

        # SHL Rwn, #data4: opcode 0x5C, byte1 = (n<<4)|count.
        # Logical shift left of Rwn by immediate count 0–15.
        # From PDF table row xC, position 5 (upper nibble 5, lower nibble C).
        # Seen as '5c 25' (SHL R2, #5) in the MS43 seed-key outer loop.
        if op == 0x5C:
            dst = (b1 >> 4) & 0xF
            cnt = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SHL R{dst:X}, #{cnt}',
                insn_type=_SHL_IMM,
                reg=dst,
                imm=cnt,
            )

        # SHR Rwn, Rwm: opcode 0x6C, byte1 = (n<<4)|m.
        # Logical shift right of Rwn by shift count in Rwm (count mod 16).
        # From PDF table row xC, position 6 (upper nibble 6, lower nibble C).
        if op == 0x6C:
            dst = (b1 >> 4) & 0xF
            cnt = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SHR R{dst:X}, R{cnt:X}',
                insn_type=_SHR_REG,
                reg=dst,
            )

        # SHR Rwn, #data4: opcode 0x7C, byte1 = (n<<4)|count.
        # Logical shift right of Rwn by immediate count 0–15.
        # From PDF table row xC, position 7 (upper nibble 7, lower nibble C).
        if op == 0x7C:
            dst = (b1 >> 4) & 0xF
            cnt = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'SHR R{dst:X}, #{cnt}',
                insn_type=_SHR_IMM,
                reg=dst,
                imm=cnt,
            )

        # PUSH Rwn: opcode 0x88, register in high nibble of byte1, low nibble = 0.
        # Confirmed: 88 90/80/70/60/E0/D0/C0 = PUSH R9/R8/R7/R6/R14/R13/R12
        if op == 0x88 and (b1 & 0x0F) == 0x00:
            reg = (b1 >> 4) & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'PUSH R{reg:X}',
                insn_type=_PUSH,
                reg=reg,
            )

        # POP Rwn: opcode 0x98, register in high nibble of byte1, low nibble = 0.
        # Confirmed: 98 60/70/80/90 = POP R6/R7/R8/R9 (reverse PUSH order)
        if op == 0x98 and (b1 & 0x0F) == 0x00:
            reg = (b1 >> 4) & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'POP R{reg:X}',
                insn_type=_POP,
                reg=reg,
            )

        # RET: opcode 0xDB, operand 0x00.
        # Confirmed: DB 00 = RET (appears after POP epilogue in seed_fetch/init_ds2_sa_ctx)
        if op == 0xDB and b1 == 0x00:
            return C166Insn(pa=pa, raw=raw, mnemonic='RET', insn_type=_RET)

        # JMPR cc, rel8: low nibble of byte0 = 0xD, high nibble = condition code.
        # Confirmed: 0D 06 = JMPR UC +12, 2D 10 = JMPR NZ +32, 3D 61 = JMPR V +194
        # Displacement is signed 8-bit in words (2 bytes each).
        # Target = pa + 2 + rel*2
        if (op & 0x0F) == 0x0D:
            cc = (op >> 4) & 0xF
            rel = struct.unpack_from('b', raw, 1)[0]  # signed byte
            target = pa + 2 + rel * 2
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'JMPR {_JMPR_CC[cc]}, 0x{target:06X}',
                insn_type=_JMPR,
                target=target,
                imm=rel,
            )

        # MOV Rwdst, Rwsrc: opcode 0xF0, byte1 = (dst<<4)|src.
        # Confirmed: F0 8D = MOV R8,RD / F0 9C = MOV R9,RC (seed_fetch prologue arg-save)
        if op == 0xF0:
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            return C166Insn(
                pa=pa, raw=raw,
                mnemonic=f'MOV R{dst:X}, R{src:X}',
                insn_type=_MOV_REG,
                reg=dst,
            )

        return C166Insn(
            pa=pa, raw=raw,
            mnemonic=f'db {raw.hex(" ")}',
            insn_type=_UNKNOWN2,
        )
