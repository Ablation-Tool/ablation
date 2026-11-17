"""Dependency-free PA-RISC 1.0/1.1 instruction decoding."""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterator, Optional

from .pa_risc_opcodes import OPCODES

REG_NAMES = (
    "r0", "r1", "rp", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
    "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19",
    "r20", "r21", "r22", "r23", "r24", "r25", "r26", "dp", "ret0", "ret1",
    "sp", "r31",
)
FP_REG_NAMES = (
    "fpsr", "fpe2", "fpe4", "fpe6", "fr4", "fr5", "fr6", "fr7", "fr8",
    "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15", "fr16", "fr17",
    "fr18", "fr19", "fr20", "fr21", "fr22", "fr23", "fr24", "fr25", "fr26",
    "fr27", "fr28", "fr29", "fr30", "fr31",
)
CONTROL_REG = (
    "rctr", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",
    "pidr1", "pidr2", "ccr", "sar", "pidr3", "pidr4", "iva", "eiem",
    "itmr", "pcsq", "pcoq", "iir", "isr", "ior", "ipsw", "eirr", "tr0",
    "tr1", "tr2", "tr3", "tr4", "tr5", "tr6", "tr7",
)
COMPARE = ("", ",=", ",<", ",<=", ",<<", ",<<=", ",sv", ",od", ",tr", ",<>", ",>=", ",>", ",>>=", ",>>", ",nsv", ",ev")
COMPARE64 = ("", ",*=", ",*<", ",*<=", ",*<<", ",*<<=", ",*sv", ",*od", ",*tr", ",*<>", ",*>=", ",*>", ",*>>=", ",*>>", ",*nsv", ",*ev")
CMPIB64 = (",*<<", ",*=", ",*<", ",*<=", ",*>>=", ",*<>", ",*>=", ",*>")
ADD = ("", ",=", ",<", ",<=", ",nuv", ",znv", ",sv", ",od", ",tr", ",<>", ",>=", ",>", ",uv", ",vnz", ",nsv", ",ev")
ADD64 = ("", ",*=", ",*<", ",*<=", ",*nuv", ",*znv", ",*sv", ",*od", ",*tr", ",*<>", ",*>=", ",*>", ",*uv", ",*vnz", ",*nsv", ",*ev")
LOGICAL = ("", ",=", ",<", ",<=", "", "", "", ",od", ",tr", ",<>", ",>=", ",>", "", "", "", ",ev")
LOGICAL64 = ("", ",*=", ",*<", ",*<=", "", "", "", ",*od", ",*tr", ",*<>", ",*>=", ",*>", "", "", "", ",*ev")
UNIT = ("", ",swz", ",sbz", ",shz", ",sdc", ",swc", ",sbc", ",shc", ",tr", ",nwz", ",nbz", ",nhz", ",ndc", ",nwc", ",nbc", ",nhc")
UNIT64 = ("", ",*swz", ",*sbz", ",*shz", ",*sdc", ",*swc", ",*sbc", ",*shc", ",*tr", ",*nwz", ",*nbz", ",*nhz", ",*ndc", ",*nwc", ",*nbc", ",*nhc")
SHIFT = ("", ",=", ",<", ",od", ",tr", ",<>", ",>=", ",ev")
SHIFT64 = ("", ",*=", ",*<", ",*od", ",*tr", ",*<>", ",*>=", ",*ev")
BB64 = (",*<", ",*>=")
INDEX_COMP = ("", ",m", ",s", ",sm")
SHORT_LDST = ("", ",ma", "", ",mb")
SHORT_BYTES = ("", ",b,m", ",e", ",e,m")
FLOAT_FORMAT = (",sgl", ",dbl", "", ",quad")
FIXED = (",w", ",dw", "", ",qw")
UFIXED = (",uw", ",udw", "", ",uqw")
FLOAT_COMPARE = (
    ",false?", ",false", ",?", ",!<=>", ",=", ",=t", ",?=", ",!<>",
    ",!?>=", ",<", ",?<", ",!>=", ",!?>", ",<=", ",?<=", "!>",
    ",!?<=", ",>", ",?>", ",!<=", ",!?<", ",>=", ",?>=", ",!<",
    ",!?=", ",<>", ",!=", ",!=t", ",!?", ",<=>", ",true?", ",true",
)
SIGNED_UNSIGNED = (",u", ",s")
MIX_HALF = (",l", ",r")
SATURATION = (",us", ",ss", "", "")
READ_WRITE = (",r", ",w")
ADD_COMP = ("", "", ",l", ",tsv")


def field(word: int, first: int, last: int) -> int:
    return (word >> (31 - last)) & ((1 << (last - first + 1)) - 1)


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def low_sign_extend(value: int, bits: int) -> int:
    return (value >> 1) - ((value & 1) << (bits - 1))


def extract_21(word: int) -> int:
    value = (word & 0x1fffff) << 11
    result = field(value, 20, 20)
    result = (result << 11) | field(value, 9, 19)
    result = (result << 2) | field(value, 5, 6)
    result = (result << 5) | field(value, 0, 4)
    result = (result << 2) | field(value, 7, 8)
    return sign_extend(result, 21) << 11


def extract_12(word: int) -> int:
    value = field(word, 19, 28) | (field(word, 29, 29) << 10) | ((word & 1) << 11)
    return sign_extend(value, 12) << 2


def extract_17(word: int) -> int:
    value = field(word, 19, 28) | (field(word, 29, 29) << 10)
    value |= field(word, 11, 15) << 11 | (word & 1) << 16
    return sign_extend(value, 17) << 2


def extract_22(word: int) -> int:
    value = field(word, 19, 28) | (field(word, 29, 29) << 10)
    value |= field(word, 11, 15) << 11 | field(word, 6, 10) << 16 | (word & 1) << 21
    return sign_extend(value, 22) << 2


def extract_16(word: int) -> int:
    m0, m1, m15 = field(word, 16, 16), field(word, 17, 17), field(word, 31, 31)
    value = (word >> 1) & 0x1fff
    value |= (m15 << 15) | ((m15 ^ m0) << 14) | ((m15 ^ m1) << 13)
    return sign_extend(value, 16)


def const_text(value: int) -> str:
    return f"-{(-value):x}" if value < 0 else f"{value:x}"


def fp_reg(number: int) -> str:
    return FP_REG_NAMES[number]


def fp_reg_r(number: int) -> str:
    return f"fpe{number * 2 + 1}" if number < 4 else f"{fp_reg(number)}R"


@dataclass(frozen=True)
class Instruction:
    address: int
    word: int
    mnemonic: str
    operands: str = ""
    arch: str = ""
    branch_target: Optional[int] = None
    is_call: bool = False
    is_return: bool = False

    @property
    def known(self) -> bool:
        return self.mnemonic != ".word"

    def text(self) -> str:
        if not self.operands:
            suffix = ""
        elif self.operands.startswith((" ", ",")):
            suffix = self.operands
        else:
            suffix = f" {self.operands}"
        return f"0x{self.address:08x}: {self.word:08x}  {self.mnemonic}{suffix}"


class PaRiscDecoder:
    def decode(self, word: int, address: int) -> Instruction:
        for name, match, mask, args, arch, _strict in OPCODES:
            if word & mask != match:
                continue
            operands = self._operands(word, address, args)
            target = None
            if "W" in args:
                target = address + 8 + extract_17(word)
            elif "w" in args:
                target = address + 8 + extract_12(word)
            elif "X" in args:
                target = address + 8 + extract_22(word)
            is_call = name in {"bl", "ble"} or (name in {"b", "bve"} and ("L" in args or "cl" in args or "cp" in args))
            is_return = name == "bv" and field(word, 6, 10) == 2
            return Instruction(address, word, name, operands, arch, target, is_call, is_return)
        return Instruction(address, word, ".word", f"0x{word:08x}")

    def decode_bytes(self, data: bytes, address: int = 0) -> Iterator[Instruction]:
        if len(data) % 4:
            raise ValueError("PA-RISC input length must be a multiple of four")
        for offset in range(0, len(data), 4):
            word = struct.unpack_from(">I", data, offset)[0]
            yield self.decode(word, address + offset)

    def _operands(self, word: int, address: int, args: str) -> str:
        out = " " if args and args[0] not in "cfCY?-+nHNZFIuv{" else ""
        i = 0
        while i < len(args):
            ch = args[i]
            if ch == "x":
                out += REG_NAMES[field(word, 11, 15)]
            elif ch in "ab":
                out += REG_NAMES[field(word, 6, 10)]
            elif ch == "^":
                out += CONTROL_REG[field(word, 6, 10)]
            elif ch == "t":
                out += REG_NAMES[field(word, 27, 31)]
            elif ch == "f":
                i += 1
                if i >= len(args):
                    break
                sub = args[i]
                if sub == "t":
                    out += fp_reg(field(word, 27, 31))
                elif sub == "T":
                    number = field(word, 27, 31)
                    out += fp_reg_r(number) if field(word, 25, 25) else fp_reg(number)
                elif sub == "a":
                    number = field(word, 6, 10)
                    out += fp_reg_r(number) if field(word, 25, 25) else fp_reg(number)
                elif sub in "AX":
                    if sub == "X":
                        out += " "
                    number = field(word, 6, 10)
                    out += fp_reg_r(number) if field(word, 24, 24) else fp_reg(number)
                elif sub in "bB":
                    number = field(word, 11, 15)
                    bit = 25 if sub == "b" else 19
                    out += fp_reg_r(number) if field(word, bit, bit) else fp_reg(number)
                elif sub == "C":
                    number = field(word, 21, 22) | field(word, 16, 18) << 2
                    out += fp_reg_r(number) if field(word, 23, 23) else fp_reg(number)
                elif sub in "ijklm":
                    positions = {"i": (6, 10), "j": (11, 15), "k": (27, 31), "l": (21, 25), "m": (16, 20)}
                    first, last = positions[sub]
                    number = field(word, first, last) | field(word, 26, 26) << 4
                    out += fp_reg(number)
                elif sub in "eE":
                    if sub == "E":
                        out += " "
                    number = field(word, 11, 15)
                    out += fp_reg_r(number) if field(word, 30, 30) else fp_reg(number)
                elif sub == "x":
                    out += fp_reg(field(word, 11, 15))
            elif ch == "5":
                out += const_text(low_sign_extend(field(word, 11, 15), 5))
            elif ch == "s":
                space = field(word, 16, 17)
                if space:
                    out += f"sr{space}"
            elif ch == "S":
                out += f"sr{field(word, 18, 18) << 2 | field(word, 16, 17)}"
            elif ch == "c":
                i += 1
                if i >= len(args):
                    break
                sub = args[i]
                compl = field(word, 26, 26) | field(word, 18, 18) << 1
                if sub == "x":
                    out += INDEX_COMP[compl]
                elif sub == "X":
                    out += INDEX_COMP[compl] + " "
                elif sub == "m":
                    out += SHORT_LDST[compl]
                elif sub == "M":
                    out += SHORT_LDST[compl] + " "
                elif sub == "A":
                    out += SHORT_BYTES[compl] + " "
                elif sub == "s":
                    out += SHORT_BYTES[compl]
                elif sub in "cC":
                    out += {1: ",bc ", 2: ",sl "}.get(field(word, 20, 21), " ")
                elif sub == "d":
                    out += ",co " if field(word, 20, 21) == 1 else " "
                elif sub == "o":
                    out += ",o"
                elif sub == "g":
                    out += ",gate"
                elif sub == "p":
                    out += ",l,push"
                elif sub == "P":
                    out += ",pop"
                elif sub in "lL":
                    out += ",l"
                elif sub == "w":
                    out += READ_WRITE[field(word, 25, 25)] + " "
                elif sub == "W":
                    out += ",w "
                elif sub == "r":
                    if field(word, 23, 26) == 5:
                        out += ",r"
                elif sub == "Z":
                    out += ",m " if field(word, 26, 26) else " "
                elif sub == "i":
                    if field(word, 25, 25):
                        out += ",i"
                elif sub == "z":
                    if not field(word, 21, 21):
                        out += ",z"
                elif sub == "a":
                    out += ADD_COMP[field(word, 20, 21)]
                elif sub == "Y":
                    out += ",dc" + ADD_COMP[field(word, 20, 21)]
                elif sub == "y":
                    out += ",c" + ADD_COMP[field(word, 20, 21)]
                elif sub == "v":
                    if field(word, 20, 20):
                        out += ",tsv"
                elif sub == "t":
                    out += ",tc"
                    if field(word, 20, 20):
                        out += ",tsv"
                elif sub in "bB":
                    out += ",db" if sub == "B" else ",b"
                    if field(word, 20, 20):
                        out += ",tsv"
                elif sub == "T":
                    if field(word, 25, 25):
                        out += ",tc"
                elif sub == "S":
                    suffix = SIGNED_UNSIGNED[field(word, 21, 21)]
                    out += suffix if i + 1 < len(args) and args[i + 1] == "?" else suffix + " "
                elif sub == "h":
                    out += MIX_HALF[field(word, 17, 17)]
                elif sub == "H":
                    out += SATURATION[field(word, 24, 25)] + " "
                elif sub == "*":
                    out += f",{field(word, 17, 18)}{field(word, 20, 21)}{field(word, 22, 23)}{field(word, 24, 25)} "
                elif sub == "q":
                    m, a = field(word, 28, 28), field(word, 29, 29)
                    out += ",ma " if m and not a else ",mb " if m and a else " "
                elif sub == "J":
                    opc = field(word, 0, 5)
                    if opc in (0x16, 0x1e):
                        out += ",mb " if field(word, 29, 29) else ",ma "
                    else:
                        out += " "
                elif sub == "e":
                    opc = field(word, 0, 5)
                    if opc in (0x13, 0x1b):
                        out += ",mb " if field(word, 18, 18) else ",ma "
                    elif opc in (0x17, 0x1f):
                        out += ",ma " if field(word, 31, 31) else ",mb "
                    else:
                        out += " "
            elif ch == "?":
                i += 1
                if i >= len(args):
                    break
                sub = args[i]
                cond = field(word, 16, 18) + (8 if field(word, 19, 19) else 0)
                if sub == "f":
                    out += FLOAT_COMPARE[field(word, 27, 31)] + " "
                elif sub == "t":
                    out += COMPARE[field(word, 16, 18)]
                elif sub == "n":
                    out += COMPARE[field(word, 16, 18) + field(word, 4, 4) * 8]
                elif sub == "N":
                    out += COMPARE64[field(word, 16, 18) + field(word, 2, 2) * 8]
                elif sub == "Q":
                    out += CMPIB64[field(word, 16, 18)]
                elif sub == "@":
                    out += ADD[field(word, 16, 18) + field(word, 4, 4) * 8]
                elif sub == "s":
                    out += COMPARE[cond] + " "
                elif sub == "S":
                    out += COMPARE64[cond] + " "
                elif sub == "a":
                    out += ADD[cond] + " "
                elif sub == "A":
                    out += ADD64[cond] + " "
                elif sub == "d":
                    out += ADD[field(word, 16, 18)]
                elif sub == "W":
                    wide = ("", ",=", ",<", ",<=", ",nuv", ",*=", ",*<", ",*<=", ",tr", ",<>", ",>=", ",>", ",uv", ",*<>", ",*>=", ",*>")
                    out += wide[field(word, 16, 18) + field(word, 4, 4) * 8]
                elif sub == "l":
                    out += LOGICAL[cond] + " "
                elif sub == "L":
                    out += LOGICAL64[cond] + " "
                elif sub == "u":
                    out += UNIT[cond] + " "
                elif sub == "U":
                    out += UNIT64[cond] + " "
                elif sub in "yxb":
                    out += SHIFT[field(word, 16, 18)]
                    if i + 1 < len(args) and args[i + 1] != "n":
                        out += " "
                elif sub == "X":
                    out += SHIFT64[field(word, 16, 18)] + " "
                elif sub == "B":
                    out += BB64[field(word, 16, 16)]
                    if i + 1 < len(args) and args[i + 1] != "n":
                        out += " "
            elif ch == "V":
                out += const_text(low_sign_extend(word & 0x1f, 5))
            elif ch in "rRU":
                values = {"r": word & 0x1f, "R": field(word, 16, 20), "U": field(word, 16, 25)}
                out += const_text(values[ch])
            elif ch in "BQ":
                out += const_text(field(word, 21, 25))
            elif ch == "i":
                out += const_text(low_sign_extend(word & 0x7ff, 11))
            elif ch == "j":
                out += const_text(low_sign_extend(word & 0x3fff, 14))
            elif ch == "k":
                out += "L%" + const_text(extract_21(word))
            elif ch in "<l":
                out += const_text(extract_16(word))
            elif ch == "n":
                out += ",n " if word & 2 else " "
            elif ch == "N":
                if word & 0x20:
                    out += ",n " if i + 1 < len(args) else ",n"
                elif i + 1 < len(args):
                    out += " "
            elif ch == "w":
                out += f"0x{address + 8 + extract_12(word):x}"
            elif ch == "W":
                out += f"0x{address + 8 + extract_17(word):x}"
            elif ch == "z":
                out += const_text(extract_17(word))
            elif ch == "Z":
                out += "r1"
            elif ch == "Y":
                out += "sr0,r31"
            elif ch == "@":
                out += "0"
            elif ch == ".":
                out += str(field(word, 24, 25))
            elif ch == "*":
                out += str(field(word, 22, 25))
            elif ch == "!":
                out += "sar"
            elif ch == "p":
                out += str(31 - field(word, 22, 26))
            elif ch == "~":
                out += str(63 - ((field(word, 20, 20) << 5) | field(word, 22, 26)))
            elif ch == "P":
                out += str(field(word, 22, 26))
            elif ch == "q":
                out += str((field(word, 20, 20) << 5) | field(word, 22, 26))
            elif ch == "T":
                out += str(32 - field(word, 27, 31))
            elif ch == "%":
                out += str((field(word, 23, 23) + 1) * 32 - field(word, 27, 31))
            elif ch == "|":
                out += str((field(word, 19, 19) + 1) * 32 - field(word, 27, 31))
            elif ch == "$":
                out += const_text(field(word, 20, 28))
            elif ch == "A":
                out += const_text(field(word, 6, 18))
            elif ch == "D":
                out += const_text(field(word, 6, 31))
            elif ch in "vu":
                out += f",{field(word, 23, 25)}"
            elif ch == "O":
                out += const_text(field(word, 6, 20) << 5 | field(word, 27, 31))
            elif ch == "o":
                out += const_text(field(word, 6, 20))
            elif ch == "2":
                out += const_text(field(word, 6, 22) << 5 | field(word, 27, 31))
            elif ch == "1":
                out += const_text(field(word, 11, 20) << 5 | field(word, 27, 31))
            elif ch == "0":
                out += const_text(field(word, 16, 20) << 5 | field(word, 27, 31))
            elif ch in "FGHI":
                if ch == "F":
                    out += FLOAT_FORMAT[field(word, 19, 20)]
                    if i + 1 < len(args) and args[i + 1] not in "G?":
                        out += " "
                elif ch == "G":
                    out += FLOAT_FORMAT[field(word, 17, 18)] + " "
                elif ch == "H":
                    out += FLOAT_FORMAT[0 if field(word, 26, 26) else 1] + " "
                else:
                    out += FLOAT_FORMAT[field(word, 20, 20)]
                    if i + 1 >= len(args) or args[i + 1] != "?":
                        out += " "
            elif ch in "JKd#":
                if ch == "J":
                    out += const_text(low_sign_extend(word & 0x3fff, 14))
                elif ch == "#":
                    value = ((-1 << 10) | field(word, 18, 27)) if field(word, 31, 31) else field(word, 18, 27)
                    out += const_text(value << 3)
                else:
                    value = ((-1 << 11) | field(word, 18, 28)) if field(word, 31, 31) else field(word, 18, 28)
                    out += const_text(value << 2)
            elif ch in ">y&":
                value = extract_16(word)
                out += const_text(value & (~3 if ch in ">y" else ~7))
            elif ch == "_":
                pass
            elif ch == "{":
                sub, df, sf = field(word, 14, 16), field(word, 17, 18), field(word, 19, 20)
                if sub == 4:
                    out += ",UND "
                else:
                    source = FIXED if sub & 4 == 0 and sub & 1 else UFIXED if sub & 1 else FLOAT_FORMAT
                    dest = FIXED if sub & 4 == 0 and sub & 2 else UFIXED if sub & 2 else FLOAT_FORMAT
                    out += (",t" if sub & 3 == 3 else "") + source[sf] + dest[df] + " "
            elif ch == "m":
                value = field(word, 16, 18)
                if value != 1:
                    out += const_text((value ^ 1) - 1)
            elif ch == "h":
                value = field(word, 16, 18)
                if value:
                    out += f",{value - 1}"
            elif ch == "=":
                out += {0: " ", 1: "acc ", 2: "rej ", 5: "acc8 ", 6: "rej8 ", 9: "acc6 ", 13: "acc4 ", 17: "acc2 "}.get(field(word, 27, 31), "")
            elif ch == "X":
                out += f"0x{address + 8 + extract_22(word):x}"
            elif ch == "L":
                out += ",rp"
            else:
                out += ch
            i += 1
        return out
