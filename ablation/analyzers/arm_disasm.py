#!/usr/bin/env python3
"""
arm_disasm.py — Custom ARM32 disassembler for ablation suite

Pure Python ARM instruction decoder. No external disassembly libraries.
Decodes ARMv7 instructions from libhijoyptt.so (and other ARM32 binaries).

Architecture
────────────
Instruction formats (ARMv7):
  - Data Processing (AND, EOR, SUB, RSB, ADD, ADC, SBC, RSC, TST, TEQ, CMP, CMN, ORR, MOV, BIC, MVN)
  - Load/Store (LDR, STR, LDRB, STRB, LDRH, STRH)
  - Branch (B, BL, BX, BLX)
  - Multiply (MUL, MLA, UMULL, UMLAL, SMULL, SMLAL)
  - Status Register Access (MRS, MSR)

Encoding:
  [31:28] - Condition code
  [27:25] - Instruction class
  [24:0]  - Instruction-specific fields

Usage:
  from arm_disasm import ARMDisassembler

  disasm = ARMDisassembler(binary_data, base_addr=0x10000)
  for addr, insn, decoded in disasm.disassemble(start=0x10000, count=100):
      print(f"0x{addr:08x}: {insn:08x}  {decoded}")

Author: NuClide Research (2026-08-16)
License: Internal research use only
"""

import struct
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass

@dataclass
class ARMInstruction:
    """Decoded ARM instruction"""
    address: int
    encoding: int
    mnemonic: str
    operands: str

    def __str__(self):
        return f"{self.mnemonic:8s} {self.operands}"

class ARMDisassembler:
    """Pure Python ARM32 disassembler"""

    # Condition codes
    COND_MAP = {
        0x0: 'eq', 0x1: 'ne', 0x2: 'cs', 0x3: 'cc',
        0x4: 'mi', 0x5: 'pl', 0x6: 'vs', 0x7: 'vc',
        0x8: 'hi', 0x9: 'ls', 0xa: 'ge', 0xb: 'lt',
        0xc: 'gt', 0xd: 'le', 0xe: '', 0xf: 'nv'  # '' = always (omitted)
    }

    # Register names
    REGS = [f'r{i}' for i in range(13)] + ['sp', 'lr', 'pc']

    def __init__(self, data: bytes, base_addr: int = 0):
        self.data = data
        self.base_addr = base_addr

    def disassemble(self, start: int, count: int = 100) -> List[ARMInstruction]:
        """Disassemble count instructions starting from start address"""
        results = []
        offset = start - self.base_addr

        for i in range(count):
            if offset + 4 > len(self.data):
                break

            addr = start + (i * 4)
            insn_bytes = self.data[offset + i*4:offset + i*4 + 4]
            if len(insn_bytes) < 4:
                break

            insn = struct.unpack('<I', insn_bytes)[0]
            decoded = self.decode(insn, addr)
            results.append(decoded)

        return results

    def decode(self, insn: int, addr: int) -> ARMInstruction:
        """Decode single ARM instruction"""
        cond = (insn >> 28) & 0xF
        cond_str = self.COND_MAP.get(cond, '')

        # Instruction class (bits 27-25)
        insn_class = (insn >> 25) & 0x7

        if insn_class == 0b000:
            # Data processing or multiply
            if (insn & 0x0FC000F0) == 0x00000090:
                return self._decode_multiply(insn, addr, cond_str)
            else:
                return self._decode_data_processing(insn, addr, cond_str)

        elif insn_class == 0b001:
            # Data processing immediate / MOV immediate
            return self._decode_data_processing_imm(insn, addr, cond_str)

        elif insn_class in [0b010, 0b011]:
            # Load/Store
            return self._decode_load_store(insn, addr, cond_str)

        elif insn_class == 0b100:
            # Load/Store Multiple
            return self._decode_load_store_multiple(insn, addr, cond_str)

        elif insn_class == 0b101:
            # Branch
            return self._decode_branch(insn, addr, cond_str)

        elif insn_class == 0b111:
            # Software interrupt
            return ARMInstruction(addr, insn, f'swi{cond_str}', f'#{insn & 0xFFFFFF}')

        # Unknown
        return ARMInstruction(addr, insn, 'dcd', f'0x{insn:08x}')

    def _decode_data_processing(self, insn: int, addr: int, cond: str) -> ARMInstruction:
        """Decode data processing instruction"""
        opcode = (insn >> 21) & 0xF
        s = (insn >> 20) & 1
        rn = (insn >> 16) & 0xF
        rd = (insn >> 12) & 0xF

        opcodes = ['and', 'eor', 'sub', 'rsb', 'add', 'adc', 'sbc', 'rsc',
                   'tst', 'teq', 'cmp', 'cmn', 'orr', 'mov', 'bic', 'mvn']

        mnemonic = opcodes[opcode] + cond
        if s and opcode < 8:  # Don't add 's' to TST/TEQ/CMP/CMN (they're always S)
            mnemonic += 's'

        # Decode operand2
        i_bit = (insn >> 25) & 1
        if i_bit:
            # Immediate
            imm = insn & 0xFF
            rotate = ((insn >> 8) & 0xF) * 2
            operand2 = f'#{self._ror(imm, rotate)}'
        else:
            # Register
            rm = insn & 0xF
            shift_type = (insn >> 5) & 0x3
            shift_types = ['lsl', 'lsr', 'asr', 'ror']

            if (insn >> 4) & 1:
                # Register shift
                rs = (insn >> 8) & 0xF
                operand2 = f'{self.REGS[rm]}, {shift_types[shift_type]} {self.REGS[rs]}'
            else:
                # Immediate shift
                shift_imm = (insn >> 7) & 0x1F
                if shift_imm == 0 and shift_type == 0:
                    operand2 = self.REGS[rm]
                else:
                    operand2 = f'{self.REGS[rm]}, {shift_types[shift_type]} #{shift_imm}'

        # Format operands based on opcode
        if opcode in [8, 9, 10, 11]:  # TST, TEQ, CMP, CMN (no destination)
            operands = f'{self.REGS[rn]}, {operand2}'
        elif opcode in [13, 15]:  # MOV, MVN (no first operand)
            operands = f'{self.REGS[rd]}, {operand2}'
        else:
            operands = f'{self.REGS[rd]}, {self.REGS[rn]}, {operand2}'

        return ARMInstruction(addr, insn, mnemonic, operands)

    def _decode_data_processing_imm(self, insn: int, addr: int, cond: str) -> ARMInstruction:
        """Decode data processing with immediate"""
        return self._decode_data_processing(insn, addr, cond)

    def _decode_load_store(self, insn: int, addr: int, cond: str) -> ARMInstruction:
        """Decode load/store instruction"""
        p = (insn >> 24) & 1  # Pre/post index
        u = (insn >> 23) & 1  # Add/subtract
        b = (insn >> 22) & 1  # Byte/word
        w = (insn >> 21) & 1  # Writeback
        l = (insn >> 20) & 1  # Load/store
        rn = (insn >> 16) & 0xF
        rd = (insn >> 12) & 0xF

        mnemonic = ('ldr' if l else 'str') + ('b' if b else '') + cond

        # Decode offset
        if (insn >> 25) & 1:
            # Register offset
            rm = insn & 0xF
            shift_type = (insn >> 5) & 0x3
            shift_imm = (insn >> 7) & 0x1F
            shift_types = ['lsl', 'lsr', 'asr', 'ror']

            if shift_imm == 0:
                offset = self.REGS[rm]
            else:
                offset = f'{self.REGS[rm]}, {shift_types[shift_type]} #{shift_imm}'
        else:
            # Immediate offset
            offset_val = insn & 0xFFF
            offset = f'#{offset_val}' if offset_val else ''

        # Format addressing mode
        sign = '+' if u else '-'
        if p:  # Pre-indexed
            if offset:
                addr_mode = f'[{self.REGS[rn]}, {sign}{offset}]'
                if w:
                    addr_mode += '!'
            else:
                addr_mode = f'[{self.REGS[rn]}]'
        else:  # Post-indexed
            if offset:
                addr_mode = f'[{self.REGS[rn]}], {sign}{offset}'
            else:
                addr_mode = f'[{self.REGS[rn]}]'

        operands = f'{self.REGS[rd]}, {addr_mode}'
        return ARMInstruction(addr, insn, mnemonic, operands)

    def _decode_load_store_multiple(self, insn: int, addr: int, cond: str) -> ARMInstruction:
        """Decode LDM/STM"""
        p = (insn >> 24) & 1
        u = (insn >> 23) & 1
        s = (insn >> 22) & 1
        w = (insn >> 21) & 1
        l = (insn >> 20) & 1
        rn = (insn >> 16) & 0xF
        reg_list = insn & 0xFFFF

        # Addressing mode
        modes = {
            (0, 0): 'da', (0, 1): 'ia',
            (1, 0): 'db', (1, 1): 'ib'
        }
        mode = modes[(p, u)]

        mnemonic = ('ldm' if l else 'stm') + mode + cond

        # Register list
        regs = [self.REGS[i] for i in range(16) if reg_list & (1 << i)]
        reg_str = '{' + ', '.join(regs) + '}'

        base = self.REGS[rn] + ('!' if w else '')
        operands = f'{base}, {reg_str}'
        if s:
            operands += '^'

        return ARMInstruction(addr, insn, mnemonic, operands)

    def _decode_branch(self, insn: int, addr: int, cond: str) -> ARMInstruction:
        """Decode branch instruction"""
        l = (insn >> 24) & 1
        offset = insn & 0xFFFFFF

        # Sign extend
        if offset & 0x800000:
            offset |= 0xFF000000

        # Calculate target (PC + 8 + offset * 4)
        target = addr + 8 + (self._sign_extend(offset, 24) << 2)

        mnemonic = ('bl' if l else 'b') + cond
        operands = f'0x{target:x}'

        return ARMInstruction(addr, insn, mnemonic, operands)

    def _decode_multiply(self, insn: int, addr: int, cond: str) -> ARMInstruction:
        """Decode multiply instruction"""
        a = (insn >> 21) & 1
        s = (insn >> 20) & 1
        rd = (insn >> 16) & 0xF
        rn = (insn >> 12) & 0xF
        rs = (insn >> 8) & 0xF
        rm = insn & 0xF

        mnemonic = ('mla' if a else 'mul') + cond
        if s:
            mnemonic += 's'

        if a:
            operands = f'{self.REGS[rd]}, {self.REGS[rm]}, {self.REGS[rs]}, {self.REGS[rn]}'
        else:
            operands = f'{self.REGS[rd]}, {self.REGS[rm]}, {self.REGS[rs]}'

        return ARMInstruction(addr, insn, mnemonic, operands)

    @staticmethod
    def _ror(val: int, n: int) -> int:
        """Rotate right"""
        n = n % 32
        return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _sign_extend(val: int, bits: int) -> int:
        """Sign extend value"""
        sign_bit = 1 << (bits - 1)
        return (val & (sign_bit - 1)) - (val & sign_bit)


def main():
    """Example usage"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: arm_disasm.py <binary> [start_offset] [count]")
        sys.exit(1)

    binary_path = sys.argv[1]
    start_offset = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 100

    with open(binary_path, 'rb') as f:
        data = f.read()

    disasm = ARMDisassembler(data, base_addr=0)
    instructions = disasm.disassemble(start_offset, count)

    for insn in instructions:
        print(f"0x{insn.address:08x}: {insn.encoding:08x}  {insn}")

if __name__ == '__main__':
    main()
