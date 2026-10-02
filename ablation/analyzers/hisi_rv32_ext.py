"""
hisi_rv32_ext.py: Correct-size decoder for all HiSilicon riscv31 ISA extensions.

HiSilicon WS63 / Hi3863 / BS21 (Hi2821) NearLink SoCs use a proprietary extended
RISC-V core named "riscv31" (fbb_ws63 SDK). Six custom opcode spaces:

  0x0b  custom-0  : ldmia / stmia — multi-register load/store, ascending addresses
  0x7b  custom-3  : R-type dispatch/context operations (~9000 hits in WS63-liteos-app)
  0x5b  custom-2  : muliadd (bits[13:12]=01)
  0x3b  OP-32     : beqi, bnei, bgei, blti, bgeui, bltui (branch-immediate)
  0x1b  OP-IMM-32 : addshf, orshf, andshf, xorshf, subshf (shift-fused ALU)
  0x1f  reserved  : l.li — 6-byte long load-immediate (CRITICAL: variable-length!)

  16-bit (RVC compressed-space reuse):
  uxtb/uxth  : insn & 0xFC5F == 0x9C01 — in-place zero-extend byte/half
  push/pop/popret, lbu/lhu, sb/sh — forwarded to Capstone (Quadrant-0/funct3 slots)

Capstone 5.x mishandles all five spaces:
  - 0x7b/0x5b/0x3b/0x1b: decoded as 4-byte raw, then next 2 bytes misinterpreted as RVC
  - 0x1f: decoded as 4-byte instruction; trailing 2 bytes cause 2-byte misalignment cascade

l.li encoding (6 bytes, LE):
  bytes[0:4] word  = { imm[15:0] :: funct3=0 :: rd[4:0] :: 0x1f }
  bytes[4:6] hword = imm[31:16]
  Example: l.li a0,0x12345678  →  1f 05 78 56 34 12
    word = 0x5678051F: bits[11:7]=10(a0), bits[31:16]=0x5678, hword=0x1234

muliadd encoding (4 bytes, custom-2 opcode 0x5b):
  bits[31:25]=uimm[7:1], bits[24:20]=rs2, bits[19:15]=rs1, bits[14:12]=funct3,
  bits[11:7]=rd, bits[6:0]=0x5b
  Semantics: rd = rs1 + (rs2 * zero_ext(uimm))   [array base + index*stride]

addshf encoding (4 bytes, opcode 0x1b):
  bits[31:25]=shamt, bits[24:20]=rs2, bits[19:15]=rs1, bits[14:12]=funct3(op),
  bits[11:7]=rd, bits[6:0]=0x1b
  funct3: 0=sll, 1=srl, 2=sra, 3=ror  (operation applied to rs1 before addition)
  Semantics: rd = rs2 + shift_op(rs1, shamt)

push/pop/popret (opcode 0x5b, identified by funct3):
  push   funct3=5: saves {ra,s0-sN} to stack, adjusts sp
  pop    funct3=6: restores {ra,s0-sN} from stack
  popret funct3=7: pop + ret

Source references:
  - fbb_ws63/src/drivers/chips/ws63/arch/riscv/riscv31/ (HiSilicon SDK)
  - riscv-code-size-reduction: existing_extensions/Huawei Custom Extension/riscv_muladd_extension.rst
  - CARRV 2020: Perotti et al., "HW/SW approaches for RISC-V code size reduction"
  - Empirical: tools_isa/poc_hisi_asm_map.py + HiSilicon-patched GCC 7.3.0 / binutils 2.38

See: docs/module-reference/hisi-rv32-ext.md
"""
from __future__ import annotations

import struct
from typing import Generator, Iterator, List, Optional, Tuple

try:
    import capstone
    from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


# ---------------------------------------------------------------------------
# ABI register names (RISC-V ilp32 psABI)
# ---------------------------------------------------------------------------

_ABI: List[str] = [
    'zero', 'ra',  'sp',  'gp',  'tp',
    't0',   't1',  't2',
    's0',   's1',
    'a0',   'a1',  'a2',  'a3',  'a4',  'a5',  'a6',  'a7',
    's2',   's3',  's4',  's5',  's6',  's7',  's8',  's9',  's10', 's11',
    't3',   't4',  't5',  't6',
]

_ARG_REGS = frozenset({'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'})

# Callee-saved registers for push/pop: ra + s0-s11
_CALLEE_SAVED = ['ra', 's0', 's1', 's2', 's3', 's4', 's5', 's6',
                 's7', 's8', 's9', 's10', 's11']

# Map funct3 values for 0x1b shift-fused ALU
_SHFALU_F3: List[str] = ['sll', 'srl', 'sra', 'ror', '?', '?', '?', '?']

# Map funct3 values for 0x3b branch-immediate
_BRANCHI_F3: List[str] = ['beqi', 'bnei', 'bgei', 'blti', 'bgeui', 'bltui', '?', '?']

# ---------------------------------------------------------------------------
# Decoded instruction result
# ---------------------------------------------------------------------------

class HisiInsn:
    """A decoded HiSilicon custom instruction (any opcode space)."""
    __slots__ = ('address', 'size', 'mnemonic', 'op_str',
                 'rd', 'rs1', 'rs2', 'funct3', 'funct7',
                 '_taint_srcs', '_taint_dst')

    def __init__(
        self,
        address: int,
        size: int,
        mnemonic: str,
        op_str: str,
        rd: int,
        rs1: int,
        rs2: int,
        funct3: int,
        funct7: int,
        taint_srcs: List[int],
        taint_dst: Optional[int],
    ) -> None:
        self.address   = address
        self.size      = size
        self.mnemonic  = mnemonic
        self.op_str    = op_str
        self.rd        = rd
        self.rs1       = rs1
        self.rs2       = rs2
        self.funct3    = funct3
        self.funct7    = funct7
        self._taint_srcs = taint_srcs
        self._taint_dst  = taint_dst

    @property
    def taint_sources(self) -> List[str]:
        """Registers that may carry taint into this instruction."""
        return [_ABI[r] for r in self._taint_srcs if 0 <= r < 32]

    @property
    def taint_dest(self) -> Optional[str]:
        """Register written by this instruction (None if none or rd == zero)."""
        if self._taint_dst is None or self._taint_dst == 0:
            return None
        r = self._taint_dst
        return _ABI[r] if r < 32 else f'x{r}'

    def as_tuple(self) -> Tuple[int, int, str, str]:
        """(address, size, mnemonic, op_str) — same layout as capstone.disasm_lite."""
        return (self.address, self.size, self.mnemonic, self.op_str)


def _reg(r: int) -> str:
    return _ABI[r] if r < 32 else f'x{r}'


def _make_custom3(word: int, address: int, conservative: bool) -> HisiInsn:
    """Decode 0x7b (custom-3) R-type."""
    rd     = (word >>  7) & 0x1f
    funct3 = (word >> 12) & 0x07
    rs1    = (word >> 15) & 0x1f
    rs2    = (word >> 20) & 0x1f
    funct7 = (word >> 25) & 0x7f
    mnem   = f'hisi.{funct3}.{funct7:02x}'
    ops    = f'{_reg(rd)}, {_reg(rs1)}, {_reg(rs2)}'
    srcs   = [rs1, rs2] if conservative else []
    return HisiInsn(address, 4, mnem, ops, rd, rs1, rs2, funct3, funct7, srcs, rd)


def _make_shfalu(word: int, address: int) -> HisiInsn:
    """Decode 0x1b (OP-IMM-32 reuse): addshf/subshf/orshf/xorshf/andshf.

    Encoding (R-type layout, riscv_preshifted_arithmetic.rst):
      bits[31:25] = {shift_type[1:0], shamt[4:0]}
        shift_type: 00=sll, 01=srl, 10=sra, 11=ror
      bits[24:20] = rs2 (base register)
      bits[19:15] = rs1 (register to be shifted)
      bits[14:12] = funct3 (base op: 0=add, 1=sub, 2=or, 3=xor, 4=and)
      bits[11:7]  = rd
      bits[6:0]   = 0x1b
    Semantics: rd = rs2 base_op shift_type(rs1, shamt)
    Verified: addshf a0,a1,a2,sll,3 → 0x06C5851B ✓ (rd=a0,rs1=a1,rs2=a2,shamt=3)
    """
    rd         = (word >>  7) & 0x1f
    funct3     = (word >> 12) & 0x07
    rs1        = (word >> 15) & 0x1f
    rs2        = (word >> 20) & 0x1f
    f7         = (word >> 25) & 0x7f
    shamt      = f7 & 0x1f
    shift_type = (f7 >> 5) & 0x03
    _OP   = ['addshf', 'subshf', 'orshf', 'xorshf', 'andshf']
    _SHFT = ['sll', 'srl', 'sra', 'ror']
    mnem  = _OP[funct3] if funct3 < 5 else f'hisi1b.{funct3}'
    stype = _SHFT[shift_type]
    ops   = f'{_reg(rd)}, {_reg(rs1)}, {_reg(rs2)}, {stype}, {shamt}'
    return HisiInsn(address, 4, mnem, ops, rd, rs1, rs2, funct3, f7, [rs1, rs2], rd)


def _make_lli(word: int, hword: int, address: int) -> HisiInsn:
    """Decode 0x1f l.li — 6-byte long load-immediate.

    Encoding:
      bytes[0:4] = { imm[15:0] :: funct3=0 :: rd[4:0] :: 0x1f }  (LE uint32)
      bytes[4:6] = imm[31:16]  (LE uint16)
    Semantics: rd = sign_ext(imm32) ... HiSilicon uses zero-ext for unsigned addresses
    """
    rd   = (word >>  7) & 0x1f
    imm_lo = (word >> 16) & 0xffff
    imm_hi = hword & 0xffff
    imm32  = (imm_hi << 16) | imm_lo
    mnem   = 'l.li'
    ops    = f'{_reg(rd)}, 0x{imm32:08x}'
    # l.li loads a constant — no register source, writes rd
    return HisiInsn(address, 6, mnem, ops, rd, 0, 0, 0, 0, [], rd)


def _make_custom2(word: int, address: int) -> HisiInsn:
    """Decode 0x5b (custom-2): muliadd.

    NOTE: push/pop/popret are NOT here — they are 16-bit RVC instructions
    (bits[15:13]=100, bits[1:0]=00). ldmia/stmia are at opcode 0x0b, not 0x5b.

    muliadd encoding (riscv_muladd_extension.rst):
      bits[31:25] = uimm[7:1]  (uimm[0]=0 always; unsigned 7-bit via bits[7:1])
      bits[24:20] = rs2         (register to multiply)
      bits[19:15] = rs1         (base register)
      bits[14:12] = funct3      (operand variant; typically 0)
      bits[11:7]  = rd
      bits[6:0]   = 0x5b
    Semantics: rd = rs1 + (rs2 * zero_ext(uimm))
    Verified: muliadd a0,a1,a2,4 → 0x04C5955B ✓ (rd=a0, rs1=a1, rs2=a2, uimm=4)
    """
    rd     = (word >>  7) & 0x1f
    funct3 = (word >> 12) & 0x07
    rs1    = (word >> 15) & 0x1f
    rs2    = (word >> 20) & 0x1f
    f7     = (word >> 25) & 0x7f
    uimm   = (f7 << 1) & 0xff  # uimm[7:1] → full uimm (bit0=0)
    mnem   = 'muliadd'
    ops    = f'{_reg(rd)}, {_reg(rs1)}, {_reg(rs2)}, {uimm}'
    return HisiInsn(address, 4, mnem, ops, rd, rs1, rs2, funct3, f7, [rs1, rs2], rd)


def _make_branchi(word: int, address: int) -> HisiInsn:
    """Decode 0x3b (OP-32 reuse): beqi/bnei/bgei/blti/bgeui/bltui.

    Encoding (riscv_condbr_imm_extension.rst, empirically opcode=0x3b not 0x0b):
      bits[31:24] = cmpimm[7:0]    (8-bit signed comparison immediate)
      bits[23:20] = offset[9:6]    (branch offset upper 4 bits)
      bits[19:15] = rs1            (register to compare)
      bits[14:12] = funct3         (0=beqi,1=bnei,2=bgei,3=blti,4=bgeui,5=bltui)
      bits[11:7]  = offset[5:1]    (branch offset lower 5 bits; bit0 always 0)
      bits[6:0]   = 0x3b
    Verified: beqi a0,7,. → 0x0705003B ✓ (cmpimm=7, rs1=a0, funct3=0, offset=0)

    No register write (branch affects PC only).
    """
    off_lo  = (word >>  7) & 0x1f
    funct3  = (word >> 12) & 0x07
    rs1     = (word >> 15) & 0x1f
    off_hi  = (word >> 20) & 0x0f
    cmpimm  = (word >> 24) & 0xff
    offset  = (off_hi << 6) | (off_lo << 1)  # PC-relative byte offset
    mnem    = _BRANCHI_F3[funct3]
    target  = address + offset
    ops     = f'{_reg(rs1)}, {cmpimm}, 0x{target:08x}'
    return HisiInsn(address, 4, mnem, ops, 0, rs1, 0, funct3, cmpimm, [rs1], None)


# ---------------------------------------------------------------------------
# ldmia / stmia — opcode 0x0b (custom-0)
# ---------------------------------------------------------------------------
#
# Encoding (verified against trans_xlinx.c.inc, hispark-rs/hisi-riscv-qemu):
#   bit12:    0 = ldmia (load-multiple), 1 = stmia (store-multiple)
#   bit31:    bank selector (0 = callee-saved {s0-s11, sp, ra};
#                            1 = caller-saved {t0-t6, a0-a7, ra})
#   bits[19:15]: base register (rs1); no writeback
#   register presence bitmap: 16 slots, each controlled by one instruction bit:
#     slot_bit[16] = {30,29,28,27,26,25,24,23,22,21,20,11,10,9,8,7}  (ascending-address order)
#   bank 0 register mapping per slot:
#     {s11,s10,s9,s8,s7,s6,s5,s4,s3,s2,a1,a0,s1,s0,sp,ra}
#   bank 1 register mapping per slot:
#     {t6,t5,t4,t3,a7,a6,a5,a4,a3,a2,a1,a0,t2,t1,t0,ra}
#
# Taint model: ldmia clears taint on all destination registers (memory not tracked).
#              stmia writes no registers; no taint update.

_LDMSTM_SLOT_BIT: List[int] = [30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 11, 10, 9, 8, 7]
_LDMSTM_SLOT_REG: List[List[int]] = [
    #        s11 s10  s9  s8  s7  s6  s5  s4  s3  s2  a1  a0  s1  s0  sp  ra
    [27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 11, 10,  9,  8,  2,  1],  # bank 0
    #        t6  t5   t4  t3  a7  a6  a5  a4  a3  a2  a1  a0  t2  t1  t0  ra
    [31, 30, 29, 28, 17, 16, 15, 14, 13, 12, 11, 10,  7,  6,  5,  1],  # bank 1
]


def _make_ldmstm_tuples(
    word: int,
    address: int,
) -> List[Tuple[int, int, str, str]]:
    """Return (address, size, mnemonic, op_str) tuples for an ldmia/stmia instruction.

    ldmia: one tuple per loaded register → disasm_lite yields each as a load.
    stmia: single tuple (no register writes).
    """
    is_store  = bool((word >> 12) & 0x1)
    bank      = (word >> 31) & 0x1
    base      = (word >> 15) & 0x1f
    mnem      = 'stmia' if is_store else 'ldmia'
    base_name = _reg(base)
    results: List[Tuple[int, int, str, str]] = []

    if is_store:
        regs = [
            _reg(_LDMSTM_SLOT_REG[bank][slot])
            for slot, bit in enumerate(_LDMSTM_SLOT_BIT)
            if word & (1 << bit)
        ]
        reg_list = '{' + ','.join(regs) + '}' if regs else '{}'
        results.append((address, 4, mnem, f'{reg_list}, ({base_name})'))
    else:
        for slot, bit in enumerate(_LDMSTM_SLOT_BIT):
            if not (word & (1 << bit)):
                continue
            reg = _LDMSTM_SLOT_REG[bank][slot]
            results.append((address, 4, mnem, f'{_reg(reg)}, 0({base_name})'))
        if not results:
            results.append((address, 4, mnem, f'0({base_name})'))

    return results


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

_HISI_OPCODES = frozenset({0x0b, 0x7b, 0x5b, 0x3b, 0x1b, 0x1f})


class HiSiliconRV32ExtDecoder:
    """
    Drop-in replacement for capstone.Cs that correctly handles all six
    HiSilicon riscv31 custom opcode spaces (WS63/Hi3863/BS21/Hi2821).

    0x0b  custom-0  : ldmia/stmia — multi-register load/store (4 bytes)
    0x7b  custom-3  : R-type generic dispatch (4 bytes)
    0x5b  custom-2  : muliadd (4 bytes)
    0x3b  OP-32     : beqi/bnei/bgei/blti/bgeui/bltui (4 bytes)
    0x1b  OP-IMM-32 : addshf/subshf/orshf/xorshf/andshf (4 bytes)
    0x1f  reserved  : l.li — 6-byte long load-immediate  ← MISALIGNMENT HAZARD

    16-bit (decoded natively, before Capstone):
    uxtb/uxth : insn & 0xFC5F == 0x9C01 — in-place zero-extend byte/half

    Capstone handles all other opcodes (push/pop/popret, lbu/lhu/sb/sh, etc.).

    Args:
        conservative: if True, treat custom-3 as propagating taint from rs1/rs2
            to rd. If False (default), treat custom-3 as opaque with no taint.
    """

    def __init__(self, conservative: bool = False) -> None:
        self._conservative = conservative
        self._cs: Optional['capstone.Cs'] = None
        if _HAS_CAPSTONE:
            self._cs = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
            self._cs.skipdata = True
            self._cs.detail   = False

    # ------------------------------------------------------------------
    # Core decode dispatch
    # ------------------------------------------------------------------

    def decode_word(self, word: int, address: int) -> HisiInsn:
        """Decode a single 32-bit HiSilicon custom word."""
        op = word & 0x7f
        if op == 0x7b:
            return _make_custom3(word, address, self._conservative)
        if op == 0x5b:
            return _make_custom2(word, address)
        if op == 0x3b:
            return _make_branchi(word, address)
        if op == 0x1b:
            return _make_shfalu(word, address)
        raise ValueError(f'decode_word: not a HiSilicon opcode: 0x{op:02x}')

    def decode_lli(self, word: int, hword: int, address: int) -> HisiInsn:
        """Decode a 6-byte l.li instruction."""
        return _make_lli(word, hword, address)

    # Backward-compat alias
    @staticmethod
    def decode_custom3(word: int, address: int, conservative: bool) -> HisiInsn:
        """Decode a 32-bit custom-3 word (bits[6:0] == 0x7b) as R-type."""
        return _make_custom3(word, address, conservative)

    # ------------------------------------------------------------------
    # disasm_lite: drop-in for capstone.Cs.disasm_lite
    # ------------------------------------------------------------------

    def disasm_lite(
        self,
        code: bytes,
        offset: int,
    ) -> Iterator[Tuple[int, int, str, str]]:
        """
        Yield (address, size, mnemonic, op_str) for each instruction.

        HiSilicon custom instructions (opcodes 0x0b/0x7b/0x5b/0x3b/0x1b/0x1f at
        2-byte aligned positions) are decoded natively. Critically, l.li (0x1f)
        consumes 6 bytes — without this decoder, every l.li causes a 2-byte
        misalignment cascade through the rest of the function.

        ldmia (0x0b) yields one tuple per loaded register; stmia yields one tuple.
        uxtb/uxth (16-bit, insn & 0xFC5F == 0x9C01) are intercepted before Capstone.
        All other bytes are forwarded to Capstone in contiguous chunks.
        """
        pos = 0
        length = len(code)

        while pos < length - 1:
            va  = offset + pos
            b0  = code[pos]
            op7 = b0 & 0x7f

            # l.li: 6-byte variable-length (must check before the 4-byte path)
            if op7 == 0x1f and (b0 & 0x80) == 0:
                if pos + 6 <= length:
                    word  = struct.unpack_from('<I', code, pos)[0]
                    hword = struct.unpack_from('<H', code, pos + 4)[0]
                    insn  = _make_lli(word, hword, va)
                    yield insn.as_tuple()
                    pos += 6
                    continue
                # Not enough bytes: fall through to capstone
                break

            # ldmia/stmia: opcode 0x0b (custom-0, 4 bytes)
            # NOTE: no (b0 & 0x80) guard here — bit7 is register bitmap, not rd lsb
            if op7 == 0x0b:
                if pos + 4 <= length:
                    word = struct.unpack_from('<I', code, pos)[0]
                    funct3 = (word >> 12) & 0x7
                    if funct3 >= 2:
                        # pref/prefd: cache prefetch hints, no architectural effect → NOP
                        yield (va, 4, 'prefd', '')
                    else:
                        yield from _make_ldmstm_tuples(word, va)
                    pos += 4
                    continue

            # 4-byte HiSilicon opcodes (bits[1:0] == 11 guaranteed)
            if op7 in (0x7b, 0x5b, 0x3b, 0x1b) and (b0 & 0x80) == 0:
                if pos + 4 <= length:
                    word = struct.unpack_from('<I', code, pos)[0]
                    insn = self.decode_word(word, va)
                    yield insn.as_tuple()
                    pos += 4
                    continue

            # Standard instruction: determine size (16 or 32 bit) from bits[1:0]
            insn_size = 4 if (b0 & 0x03) == 0x03 else 2

            # uxtb/uxth: 16-bit, intercept before building the Capstone run
            if insn_size == 2 and pos + 2 <= length:
                hw = struct.unpack_from('<H', code, pos)[0]
                if (hw & 0xFC5F) == 0x9C01:
                    rd = 8 + ((hw >> 7) & 0x7)
                    mnem = 'uxth' if (hw & 0x20) else 'uxtb'
                    yield (va, 2, mnem, _reg(rd))
                    pos += 2
                    continue

            # Build a contiguous run of non-HiSilicon bytes for Capstone
            run_start = pos
            run_pos   = pos + insn_size

            while run_pos < length - 1:
                nb0  = code[run_pos]
                nop7 = nb0 & 0x7f
                # 0x0b (ldmia/stmia) does not have (nb0 & 0x80) == 0 constraint
                # (bit7 is register bitmap, not rd lsb); check separately.
                if nop7 == 0x0b and (nb0 & 0x03) == 0x03:
                    break
                if (nb0 & 0x80) == 0 and nop7 in _HISI_OPCODES:
                    break
                nb_size = 4 if (nb0 & 0x03) == 0x03 else 2
                run_pos += nb_size

            run_end  = min(run_pos, length)
            chunk    = code[run_start:run_end]
            chunk_va = offset + run_start

            if self._cs is not None:
                yield from self._cs.disasm_lite(chunk, chunk_va)
            else:
                for i in range(0, len(chunk), 2):
                    b   = chunk[i]
                    sz  = 4 if (b & 0x03) == 0x03 else 2
                    sl  = chunk[i:i + sz]
                    if len(sl) == sz:
                        yield (chunk_va + i, sz, '.byte', ' '.join(f'0x{x:02x}' for x in sl))

            pos = run_end

        # Tail: pass remainder to Capstone
        if pos < length and self._cs is not None:
            yield from self._cs.disasm_lite(code[pos:], offset + pos)

    # ------------------------------------------------------------------
    # Scan helpers
    # ------------------------------------------------------------------

    def scan_custom3(
        self,
        code: bytes,
        base_va: int,
    ) -> List[HisiInsn]:
        """Return all custom-3 instructions found in the code region (4-byte stride)."""
        results: List[HisiInsn] = []
        for i in range(0, len(code) - 3, 4):
            b0 = code[i]
            if (b0 & 0x7f) == 0x7b and (b0 & 0x80) == 0:
                word = struct.unpack_from('<I', code, i)[0]
                results.append(_make_custom3(word, base_va + i, self._conservative))
        return results

    def scan_all_custom(
        self,
        code: bytes,
        base_va: int,
    ) -> List[HisiInsn]:
        """Return all HiSilicon custom instructions (all 6 opcode spaces, 4-byte stride).

        Note: l.li is 6 bytes but starts on a 4-byte boundary; stride=4 finds the
        start correctly. The trailing 2-byte extension is consumed as part of the
        instruction and not scanned separately.

        ldmia/stmia (0x0b) may generate multiple HisiInsn per instruction; all are
        included. For stmia the single emitted HisiInsn has taint_dst=None.
        """
        results: List[HisiInsn] = []
        i = 0
        while i < len(code) - 3:
            b0  = code[i]
            op7 = b0 & 0x7f
            if (b0 & 0x80) == 0 and op7 in _HISI_OPCODES:
                word = struct.unpack_from('<I', code, i)[0]
                if op7 == 0x1f and i + 6 <= len(code):
                    hword = struct.unpack_from('<H', code, i + 4)[0]
                    results.append(_make_lli(word, hword, base_va + i))
                    i += 6
                    continue
                elif op7 == 0x0b:
                    funct3 = (word >> 12) & 0x7
                    if funct3 < 2:
                        va = base_va + i
                        for tup in _make_ldmstm_tuples(word, va):
                            addr, sz, mnem, ops = tup
                            is_store = mnem == 'stmia'
                            base_reg = (word >> 15) & 0x1f
                            results.append(HisiInsn(addr, sz, mnem, ops, 0, base_reg, 0,
                                                     (word >> 12) & 0x7, 0,
                                                     [base_reg], None))
                elif op7 != 0x1f:
                    results.append(self.decode_word(word, base_va + i))
            i += 4
        return results

    # ------------------------------------------------------------------
    # Opcode frequency report
    # ------------------------------------------------------------------

    def opcode_report(self, code: bytes, base_va: int) -> str:
        """Frequency table for all HiSilicon custom instructions."""
        import collections
        counts: collections.Counter = collections.Counter()
        for insn in self.scan_all_custom(code, base_va):
            counts[insn.mnemonic] += 1
        total = sum(counts.values())
        lines = [f"HiSilicon custom opcode frequency ({total} total):"]
        for mnem, cnt in counts.most_common(30):
            lines.append(f"  {mnem:<20s}  x{cnt}")
        return '\n'.join(lines)
