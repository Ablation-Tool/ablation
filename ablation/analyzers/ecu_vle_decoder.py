"""
PowerPC VLE (Variable Length Encoding) decoder for e200-class ECU firmware.

VLE is a mixed-width ISA used by NXP e200z4/z6/z7 cores on GM E39, E39a,
E54, and E92 PCMs. Instructions are either 16-bit SE (Short Encoding) or
32-bit, distinguished by the first byte of each instruction:

    (byte0 & 0x90) == 0x10  →  32-bit VLE or Book E instruction
    otherwise               →  16-bit SE instruction

This module decodes the security-relevant subset of the VLE instruction set
and provides function_starts() for seeding taint-tracking pipelines against
flat ROM images that have no ELF headers or VLE section flags.

All encodings are sourced from binutils ppc-opc.c (GNU Binutils 2.40):
    SE instructions: SE_R, SE_RR, SE_IM5, IM7, SD4, BD8, BD8IO macros
    32-bit VLE: OP, OPVUP, BD24 macros
    Length discrimination: (byte0 & 0x90) == 0x10  [NXP e200 VLE Reference Manual]

Usage::

    from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder

    decoder = EcuVLEDecoder(rom_bytes, base_va=0x40000000)
    insns = decoder.disassemble()
    starts = decoder.function_starts()

    for start in starts[:10]:
        print(f"  function @ 0x{start:08X}")

    # Or use decode_one() for single-instruction inspection:
    insn = decoder.decode_one(0)
    print(insn)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class VLEInsn:
    """A decoded VLE instruction."""

    offset: int
    is_16bit: bool
    mnemonic: str
    insn_type: str
    raw: bytes
    target: Optional[int] = None
    rd: Optional[int] = None
    rs: Optional[int] = None
    ra: Optional[int] = None
    imm: Optional[int] = None

    def __str__(self) -> str:
        va = self.offset
        width = "SE16" if self.is_16bit else "VLE32"
        ops = []
        if self.rd is not None:
            ops.append(f"r{self.rd}")
        if self.rs is not None and self.rs != self.rd:
            ops.append(f"r{self.rs}")
        if self.ra is not None:
            ops.append(f"r{self.ra}")
        if self.imm is not None:
            ops.append(f"0x{self.imm:x}" if self.imm >= 0 else f"-0x{-self.imm:x}")
        op_str = ", ".join(ops) if ops else ""
        target_str = f"  -> 0x{self.target:08X}" if self.target is not None else ""
        return f"0x{va:08X}  [{width}]  {self.mnemonic:<16} {op_str}{target_str}"


class EcuVLEDecoder:
    """
    Decode PowerPC VLE instructions from a raw ROM buffer.

    Parameters
    ----------
    data
        Raw ROM bytes covering the VLE code region.
    base_va
        Virtual address of the first byte in ``data``.  Used for branch
        target computation and for the offset values returned by
        ``function_starts()``.
    """

    def __init__(self, data: "str | Path | bytes", base_va: int = 0):
        if isinstance(data, (str, Path)):
            try:
                self._data = open(data, "rb").read()
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"EcuVLEDecoder: {data!r} not found"
                ) from exc
        else:
            self._data = bytes(data)
        self._base_va = base_va

    @classmethod
    def from_path(cls, path: "str | Path", base_va: int = 0) -> "EcuVLEDecoder":
        return cls(path, base_va)

    @classmethod
    def from_bytes(cls, data: bytes, base_va: int = 0) -> "EcuVLEDecoder":
        return cls(data, base_va)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def insn_length(self, offset: int) -> int:
        """Return 2 or 4 — the length of the instruction at ``offset``."""
        if offset >= len(self._data):
            return 0
        b0 = self._data[offset]
        return 4 if (b0 & 0x90) == 0x10 else 2

    def decode_one(self, offset: int) -> Optional[VLEInsn]:
        """Decode a single instruction at ``offset``.  Returns None at EOF."""
        data = self._data
        n = len(data)
        if offset >= n:
            return None
        b0 = data[offset]
        if (b0 & 0x90) == 0x10:
            if offset + 4 > n:
                return None
            word = struct.unpack_from(">I", data, offset)[0]
            return self._decode_32(offset, word)
        else:
            if offset + 2 > n:
                return None
            hw = struct.unpack_from(">H", data, offset)[0]
            return self._decode_se16(offset, hw)

    def disassemble(
        self, start: int = 0, end: Optional[int] = None
    ) -> list[VLEInsn]:
        """
        Decode all instructions in the byte range ``[start, end)``.

        ``start`` and ``end`` are byte offsets within the data buffer.
        The default range is the entire buffer.
        """
        if end is None:
            end = len(self._data)
        end = min(end, len(self._data))
        results: list[VLEInsn] = []
        off = start
        while off < end:
            insn = self.decode_one(off)
            if insn is None:
                break
            results.append(insn)
            off += len(insn.raw)
        return results

    def function_starts(self) -> list[int]:
        """
        Return probable function-start VAs by scanning for VLE prologues.

        Two prologue forms are detected:

        *Frame-allocating functions* — begin with ``e_stwu r1, -N(r1)``,
        the 32-bit VLE store-with-update that allocates a stack frame.  This
        instruction pattern is unique enough to serve as a strong function
        boundary signal in ECU code.

        *Leaf functions* — begin with ``se_mflr r0`` (save LR without
        allocating a frame).  These are smaller helpers that never call out
        and have no stack frame.

        Returns virtual addresses (``base_va + offset``).  The list is
        sorted and deduplicated.
        """
        data = self._data
        n = len(data)
        starts: set[int] = set()

        for i in range(0, n - 3, 4):
            word = struct.unpack_from(">I", data, i)[0]
            if self._is_e_stwu_r1(word):
                starts.add(self._base_va + i)

        for i in range(0, n - 1, 2):
            hw = struct.unpack_from(">H", data, i)[0]
            if (hw & 0xFFF0) == 0x0080:
                va = self._base_va + i
                if va not in starts:
                    # Only accept se_mflr r0 if the immediately preceding
                    # instruction (at i-2) is not e_stwu (which would mean
                    # the se_mflr is the SECOND instruction of a non-leaf
                    # prologue, not a function start itself).
                    if i < 4:
                        starts.add(va)
                    else:
                        prev_word = struct.unpack_from(">I", data, i - 4)[0]
                        if not self._is_e_stwu_r1(prev_word):
                            starts.add(va)

        return sorted(starts)

    # ------------------------------------------------------------------
    # 32-bit VLE instruction decoder
    # ------------------------------------------------------------------

    def _decode_32(self, offset: int, word: int) -> VLEInsn:
        raw = struct.pack(">I", word)
        va = self._base_va + offset
        op6 = word >> 26

        # e_stwu rS, D8(rA)  — OPVUP(6,6) = 0x18000600
        if op6 == 6:
            vup = (word >> 8) & 0xFF
            rs = (word >> 21) & 0x1F
            ra = (word >> 16) & 0x1F
            d8_raw = word & 0xFF
            d8 = d8_raw if d8_raw < 0x80 else d8_raw - 0x100
            mnems = {
                6: "e_stwu",
                9: "e_stmw",
                8: "e_lmw",
                7: "e_lwzu",
            }
            mnem = mnems.get(vup, f"e_opvup6_{vup}")
            itype = "PROLOGUE" if (vup == 6 and rs == 1 and ra == 1 and d8 < 0) else "STORE"
            return VLEInsn(
                offset=va,
                is_16bit=False,
                mnemonic=mnem,
                insn_type=itype,
                raw=raw,
                rs=rs,
                ra=ra,
                imm=d8,
            )

        # e_add16i / e_la  — OP(7) = 0x1C000000
        if op6 == 7:
            rd = (word >> 21) & 0x1F
            ra = (word >> 16) & 0x1F
            si16 = word & 0xFFFF
            si = si16 if si16 < 0x8000 else si16 - 0x10000
            return VLEInsn(
                offset=va, is_16bit=False,
                mnemonic="e_add16i", insn_type="MISC",
                raw=raw, rd=rd, ra=ra, imm=si,
            )

        # e_lbz — OP(12)
        if op6 == 12:
            return self._decode_e_load_store(va, word, raw, "e_lbz", "LOAD")

        # e_stb — OP(13)
        if op6 == 13:
            return self._decode_e_load_store(va, word, raw, "e_stb", "STORE")

        # e_lha — OP(14)
        if op6 == 14:
            return self._decode_e_load_store(va, word, raw, "e_lha", "LOAD")

        # e_lwz — OP(20)
        if op6 == 20:
            return self._decode_e_load_store(va, word, raw, "e_lwz", "LOAD")

        # e_stw — OP(21)
        if op6 == 21:
            return self._decode_e_load_store(va, word, raw, "e_stw", "STORE")

        # e_lhz — OP(22)
        if op6 == 22:
            return self._decode_e_load_store(va, word, raw, "e_lhz", "LOAD")

        # e_li — LI20(28,0) = OP(28) | (0<<15) = 0x70000000
        if op6 == 28:
            rd = (word >> 21) & 0x1F
            li_xop = (word >> 15) & 1
            if li_xop == 0:
                # e_li: 20-bit immediate assembled from scattered bits
                imm20_hi = (word >> 16) & 0x1F
                imm20_lo = word & 0x7FFF
                imm20 = (imm20_hi << 15) | imm20_lo
                imm = imm20 if imm20 < 0x80000 else imm20 - 0x100000
                return VLEInsn(
                    offset=va, is_16bit=False,
                    mnemonic="e_li", insn_type="MISC",
                    raw=raw, rd=rd, imm=imm,
                )
            # Other I16L forms (e_lis, e_or2is, etc.)
            return VLEInsn(
                offset=va, is_16bit=False,
                mnemonic=f"e_i16l_xop{li_xop}", insn_type="MISC",
                raw=raw,
            )

        # e_b / e_bc family — BD24(30,0,0) = OP(30) = 0x78000000
        if op6 == 30:
            aa = (word >> 25) & 1
            lk = word & 1
            if aa == 0:
                # PC-relative: BD24 in bits[24:1]
                bd24_raw = word & 0x01FFFFFE
                if bd24_raw & 0x01000000:
                    bd24 = bd24_raw - 0x02000000
                else:
                    bd24 = bd24_raw
                target = va + bd24
                mnem = "e_bl" if lk else "e_b"
                itype = "CALL" if lk else "BRANCH"
            else:
                target = word & 0x01FFFFFE
                mnem = "e_bla" if lk else "e_ba"
                itype = "CALL" if lk else "BRANCH"
            return VLEInsn(
                offset=va, is_16bit=False,
                mnemonic=mnem, insn_type=itype,
                raw=raw, target=target,
            )

        # e_bc / e_bdnz / conditional branch family — opcode 30, but
        # EBD15 forms use a different bit layout inside op6=30. Handled
        # above via the aa/lk fields; fall through to generic.

        # SCI8 arithmetic (e_addi, e_ori, etc.) — OP(6) covered above;
        # other SCI8 use opcode 6. Already decoded via OPVUP above.

        # Generic fallback
        return VLEInsn(
            offset=va, is_16bit=False,
            mnemonic=f"vle32_op{op6}", insn_type="MISC",
            raw=raw,
        )

    def _decode_e_load_store(
        self, va: int, word: int, raw: bytes, mnem: str, itype: str
    ) -> VLEInsn:
        rd_rs = (word >> 21) & 0x1F
        ra = (word >> 16) & 0x1F
        disp = word & 0xFFFF
        disp_s = disp if disp < 0x8000 else disp - 0x10000
        if itype == "LOAD":
            return VLEInsn(
                offset=va, is_16bit=False, mnemonic=mnem, insn_type=itype,
                raw=raw, rd=rd_rs, ra=ra, imm=disp_s,
            )
        return VLEInsn(
            offset=va, is_16bit=False, mnemonic=mnem, insn_type=itype,
            raw=raw, rs=rd_rs, ra=ra, imm=disp_s,
        )

    # ------------------------------------------------------------------
    # 16-bit SE instruction decoder
    # ------------------------------------------------------------------

    def _decode_se16(self, offset: int, hw: int) -> VLEInsn:
        raw = struct.pack(">H", hw)
        va = self._base_va + offset

        # Special-form: low opcode byte = 0x00-0x0F
        if hw <= 0x000F:
            _SE_SPECIALS = {
                0x0000: ("se_illegal", "MISC"),
                0x0002: ("se_sc", "MISC"),
                0x0004: ("se_blr", "RETURN"),
                0x0005: ("se_blrl", "RETURN"),
                0x0006: ("se_bctr", "BRANCH"),
                0x0007: ("se_bctrl", "CALL"),
                0x0008: ("se_rfi", "MISC"),
                0x000A: ("se_rfci", "MISC"),
                0x000B: ("se_rfdi", "MISC"),
            }
            mnem, itype = _SE_SPECIALS.get(hw, (f"se_special_{hw:04x}", "MISC"))
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic=mnem, insn_type=itype, raw=raw,
            )

        # SE_R form: mask 0xFFF0, register in bits[3:0]
        base = hw & 0xFFF0
        rx = hw & 0xF
        _SE_R = {
            0x0020: ("se_not", "MISC"),
            0x0030: ("se_neg", "MISC"),
            0x0080: ("se_mflr", "LR_SAVE"),
            0x0090: ("se_mtlr", "LR_RESTORE"),
            0x00A0: ("se_mfctr", "MISC"),
            0x00B0: ("se_mtctr", "MISC"),
            0x00C0: ("se_extzb", "MISC"),
            0x00D0: ("se_extsb", "MISC"),
            0x00E0: ("se_extzh", "MISC"),
            0x00F0: ("se_extsh", "MISC"),
        }
        if base in _SE_R:
            mnem, itype = _SE_R[base]
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic=mnem, insn_type=itype,
                raw=raw, rd=rx,
            )

        # SE_RR form: mask 0xFF00, RX in bits[7:4], RY in bits[3:0]
        base_rr = hw & 0xFF00
        rx_rr = (hw >> 4) & 0xF
        ry_rr = hw & 0xF
        _SE_RR = {
            0x0400: ("se_add", "MISC"),
            0x0500: ("se_mullw", "MISC"),
            0x0600: ("se_sub", "MISC"),
            0x0700: ("se_subf", "MISC"),
            0x0C00: ("se_cmp", "MISC"),
            0x0D00: ("se_cmpl", "MISC"),
            0x0E00: ("se_cmph", "MISC"),
            0x0F00: ("se_cmphl", "MISC"),
            0x4000: ("se_srw", "MISC"),
            0x4100: ("se_sraw", "MISC"),
            0x4200: ("se_slw", "MISC"),
            0x4400: ("se_or", "MISC"),
            0x4500: ("se_andc", "MISC"),
            0x4600: ("se_and", "MISC"),
            0x4700: ("se_and.", "MISC"),
            0x0000: ("se_illegal", "MISC"),  # SE_RR(0,0)
            0x0100: ("se_mr", "MISC"),
            0x0200: ("se_mtar", "MISC"),
            0x0300: ("se_mfar", "MISC"),
        }
        if base_rr in _SE_RR:
            mnem, itype = _SE_RR[base_rr]
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic=mnem, insn_type=itype,
                raw=raw, rd=rx_rr, rs=ry_rr,
            )

        # SE_IM5 form: mask 0xFE00, 5-bit immediate in bits[4:0], RX in bits[7:5]
        base_im5 = hw & 0xFE00
        rx_im5 = (hw >> 5) & 0x7
        imm5 = hw & 0x1F
        _SE_IM5 = {
            0x2000: ("se_addi", "MISC"),
            0x2200: ("se_cmpli", "MISC"),
            0x2400: ("se_subi", "MISC"),
            0x2600: ("se_subi.", "MISC"),
            0x2A00: ("se_cmpi", "MISC"),
            0x2C00: ("se_bmaski", "MISC"),
            0x2E00: ("se_andi", "MISC"),
            0x6000: ("se_bclri", "MISC"),
            0x6200: ("se_bgeni", "MISC"),
            0x6400: ("se_bseti", "MISC"),
            0x6600: ("se_btsti", "MISC"),
            0x6800: ("se_srwi", "MISC"),
            0x6A00: ("se_srawi", "MISC"),
            0x6C00: ("se_slwi", "MISC"),
        }
        if base_im5 in _SE_IM5:
            mnem, itype = _SE_IM5[base_im5]
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic=mnem, insn_type=itype,
                raw=raw, rd=rx_im5, imm=imm5,
            )

        # se_li: IM7(9) = (9<<11) = 0x4800, mask 0xF800
        # Format: bits[10:7] = RX (4-bit compact register), bits[6:0] = UI7
        if (hw & 0xF800) == 0x4800:
            rx_li = self._compact_reg_4bit((hw >> 7) & 0xF)
            ui7 = hw & 0x7F
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic="se_li", insn_type="MISC",
                raw=raw, rd=rx_li, imm=ui7,
            )

        # SD4 load/store: mask 0xF000, top nibble = opcode
        # Format: bits[11:9] = RZ (3-bit), bits[8:5] = SE_SD (4-bit scaled disp),
        #         bits[4:2] = RX (3-bit), bits[1:0] = reserved
        top_nibble = hw >> 12
        _SD4 = {
            8: ("se_lbz", "LOAD", 1),
            9: ("se_stb", "STORE", 1),
            10: ("se_lhz", "LOAD", 2),
            11: ("se_sth", "STORE", 2),
            12: ("se_lwz", "LOAD", 4),
            13: ("se_stw", "STORE", 4),
        }
        if top_nibble in _SD4:
            mnem, itype, scale = _SD4[top_nibble]
            rz = (hw >> 9) & 0x7
            sd4 = (hw >> 5) & 0xF
            rx_sd4 = (hw >> 2) & 0x7
            disp = sd4 * scale
            if itype == "LOAD":
                return VLEInsn(
                    offset=va, is_16bit=True, mnemonic=mnem, insn_type=itype,
                    raw=raw, rd=rz, ra=rx_sd4, imm=disp,
                )
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic=mnem, insn_type=itype,
                raw=raw, rs=rz, ra=rx_sd4, imm=disp,
            )

        # Branch instructions
        # se_bc (conditional): BD8IO(28) = (28<<11) = 0xE000, mask 0xF800
        if (hw & 0xF800) == 0xE000:
            bo16 = (hw >> 10) & 1
            bi16 = (hw >> 8) & 3
            bd8_raw = hw & 0xFF
            bd8 = bd8_raw if bd8_raw < 0x80 else bd8_raw - 0x100
            # target = CIA + exts(BD8 || 0) per NXP VLE spec — CIA-relative, not NIA-relative
            target = va + bd8 * 2
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic="se_bc", insn_type="BRANCH",
                raw=raw, target=target, imm=bd8,
            )

        # se_b (unconditional): BD8(58,0,0) = 0xE800, mask 0xFF00
        # se_bl (with link):    BD8(58,0,1) = 0xE900, mask 0xFF00
        if (hw & 0xFF00) == 0xE800:
            bd8_raw = hw & 0xFF
            bd8 = bd8_raw if bd8_raw < 0x80 else bd8_raw - 0x100
            target = va + bd8 * 2
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic="se_b", insn_type="BRANCH",
                raw=raw, target=target, imm=bd8,
            )

        if (hw & 0xFF00) == 0xE900:
            bd8_raw = hw & 0xFF
            bd8 = bd8_raw if bd8_raw < 0x80 else bd8_raw - 0x100
            target = va + bd8 * 2
            return VLEInsn(
                offset=va, is_16bit=True, mnemonic="se_bl", insn_type="CALL",
                raw=raw, target=target, imm=bd8,
            )

        return VLEInsn(
            offset=va, is_16bit=True,
            mnemonic=f"se_unknown_{hw:04x}", insn_type="MISC",
            raw=raw,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compact_reg_4bit(raw: int) -> int:
        """Translate a 4-bit VLE compact register field to a GPR index.

        VLE SE instructions that use 4-bit compact register notation encode
        GPR0-GPR7 as fields 0-7 and GPR24-GPR31 as fields 8-15.  The
        translation is: field < 8 → field; field >= 8 → field + 16.

        Note: SE_R form instructions (se_mflr, se_mtlr, etc.) use a direct
        4-bit GPR field (0-15 = GPR0-GPR15) without compact remapping.  Apply
        this helper only to IM7 and SE_RR compact register fields; do NOT apply
        it to SE_R instructions.
        """
        return raw if raw < 8 else raw + 16

    @staticmethod
    def _is_e_stwu_r1(word: int) -> bool:
        """True if word is e_stwu r1, -N(r1) (any negative displacement)."""
        if (word >> 26) != 6:
            return False
        if ((word >> 8) & 0xFF) != 6:
            return False
        if ((word >> 21) & 0x1F) != 1:
            return False
        if ((word >> 16) & 0x1F) != 1:
            return False
        # D8 must be negative: bit 7 set
        return bool(word & 0x80)
