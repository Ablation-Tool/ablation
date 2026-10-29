from dataclasses import dataclass


RR = {
    0x04: "spm", 0x05: "balr", 0x06: "bctr", 0x07: "bcr", 0x08: "ssk", 0x0A: "svc",
    0x0B: "bsm", 0x0C: "bassm", 0x0D: "basr", 0x0E: "mvcl", 0x0F: "clcl",
    0x10: "lpr", 0x11: "lnr", 0x12: "ltr", 0x13: "lcr", 0x14: "nr", 0x15: "clr",
    0x16: "or", 0x17: "xr", 0x18: "lr", 0x19: "cr", 0x1A: "ar", 0x1B: "sr",
    0x1C: "mr", 0x1D: "dr", 0x1E: "alr", 0x1F: "slr", 0x20: "lpdr", 0x21: "lndr",
    0x22: "ltdr", 0x23: "lcdr", 0x28: "ldr", 0x29: "cdr", 0x2A: "adr", 0x2B: "sdr",
    0x2C: "mdr", 0x2D: "ddr", 0x2E: "awr", 0x2F: "swr", 0x30: "lper", 0x31: "lner",
    0x32: "lter", 0x33: "lcer", 0x38: "ler", 0x39: "cer", 0x3A: "aer", 0x3B: "ser",
    0x3C: "mder", 0x3D: "der", 0x3E: "aur", 0x3F: "sur",
}
RX = {
    0x40: "sth", 0x41: "la", 0x42: "stc", 0x43: "ic", 0x44: "ex", 0x45: "bal",
    0x46: "bct", 0x47: "bc", 0x48: "lh", 0x49: "ch", 0x4A: "ah", 0x4B: "sh",
    0x4C: "mh", 0x4D: "ms", 0x4E: "cvd", 0x4F: "cvb", 0x50: "st", 0x54: "n",
    0x55: "cl", 0x56: "o", 0x57: "x", 0x58: "l", 0x59: "c", 0x5A: "a",
    0x5B: "s", 0x5C: "m", 0x5D: "d", 0x5E: "al", 0x5F: "sl", 0x60: "std",
    0x68: "ld", 0x69: "cd", 0x6A: "ad", 0x6B: "sd", 0x6C: "md", 0x6D: "dd",
    0x6E: "aw", 0x6F: "sw", 0x70: "ste", 0x78: "le", 0x79: "ce", 0x7A: "ae",
    0x7B: "se", 0x7C: "mde", 0x7D: "de", 0x7E: "au", 0x7F: "su",
}
RS = {
    0x80: "ssm", 0x82: "lpsw", 0x83: "diag", 0x84: "brxh", 0x85: "brxle",
    0x86: "bxh", 0x87: "bxle", 0x88: "srl", 0x89: "sll", 0x8A: "sra",
    0x8B: "sla", 0x8C: "srdl", 0x8D: "sldl", 0x8E: "srda", 0x8F: "slda",
    0x90: "stm", 0x98: "lm", 0x99: "trace", 0x9A: "lam", 0x9B: "stam",
    0xBD: "clm", 0xBF: "icm",
}
SI = {0x91: "tm", 0x92: "mvi", 0x93: "ts", 0x94: "ni", 0x95: "cli", 0x96: "oi", 0x97: "xi"}
SS = {
    0xD2: "mvc", 0xD3: "mvz", 0xD4: "nc", 0xD5: "clc", 0xD6: "oc", 0xD7: "xc",
    0xD9: "mvck", 0xDA: "mvcp", 0xDB: "mvcs", 0xDC: "tr", 0xDD: "trt",
    0xDE: "ed", 0xDF: "edmk", 0xF0: "srp", 0xF1: "mvo", 0xF2: "pack",
    0xF3: "unpk", 0xF8: "zap", 0xF9: "cp", 0xFA: "ap", 0xFB: "sp", 0xFC: "mp", 0xFD: "dp",
}
RRE = {
    0xB255: "mvst", 0xB25D: "clst", 0xB25E: "srst",
    0xB900: "lpgr", 0xB901: "lngr", 0xB902: "ltgr",
    0xB903: "lcgr", 0xB904: "lgr", 0xB988: "alcgr",
    0xB998: "alcr", 0xB9BE: "srstu",
}
RIL = {
    0xC0: {
        0x0: "larl", 0x1: "lgfi", 0x4: "brcl", 0x5: "brasl",
        0x6: "xihf", 0x7: "xilf", 0x8: "iihf", 0x9: "iilf",
        0xA: "nihf", 0xB: "nilf", 0xC: "oihf", 0xD: "oilf",
        0xE: "llihf", 0xF: "llilf",
    },
    0xC2: {
        0x0: "msgfi", 0x1: "msfi", 0x4: "slgfi", 0x5: "slfi",
        0x8: "agfi", 0x9: "afi", 0xA: "algfi", 0xB: "alfi",
        0xC: "cgfi", 0xD: "cfi", 0xE: "clgfi", 0xF: "clfi",
    },
    0xC4: {
        0x2: "llhrl", 0x4: "lghrl", 0x5: "lhrl", 0x6: "llghrl",
        0x7: "sthrl", 0x8: "lgrl", 0xB: "stgrl", 0xC: "lgfrl",
        0xD: "lrl", 0xE: "llgfrl", 0xF: "strl",
    },
    0xC6: {
        0x0: "exrl", 0x2: "pfdrl", 0x4: "cghrl", 0x5: "chrl",
        0x6: "clghrl", 0x7: "clhrl", 0x8: "cgrl", 0xA: "clgrl",
        0xC: "cgfrl", 0xD: "crl", 0xE: "clgfrl", 0xF: "clrl",
    },
    0xCC: {
        0x6: "brcth", 0x8: "aih", 0xA: "alsih", 0xB: "alsihn",
        0xD: "cih", 0xF: "clih",
    },
}
RIL_PC = {
    "larl", "llhrl", "lghrl", "lhrl", "llghrl", "sthrl", "lgrl", "stgrl",
    "lgfrl", "lrl", "llgfrl", "strl", "exrl", "pfdrl", "cghrl", "chrl",
    "clghrl", "clhrl", "cgrl", "clgrl", "cgfrl", "crl", "clgfrl", "clrl",
}
RIL_UNSIGNED = {
    "xihf", "xilf", "iihf", "iilf", "nihf", "nilf", "oihf", "oilf",
    "llihf", "llilf", "algfi", "alfi", "slgfi", "slfi", "clgfi", "clfi", "clih",
}
RI = {
    0x0: "tmlh", 0x1: "tmll", 0x2: "tmhh", 0x3: "tmhl",
    0x4: "brc", 0x5: "bras", 0x6: "brct", 0x7: "brctg", 0x8: "lhi",
    0x9: "lghi", 0xA: "ahi", 0xB: "aghi", 0xC: "mhi", 0xD: "mghi",
    0xE: "chi", 0xF: "cghi",
}
RI_A5 = {
    0x0: "iihh", 0x1: "iihl", 0x2: "iilh", 0x3: "iill",
    0x4: "nihh", 0x5: "nihl", 0x6: "nilh", 0x7: "nill",
    0x8: "oihh", 0x9: "oihl", 0xA: "oilh", 0xB: "oill",
    0xC: "llihh", 0xD: "llihl", 0xE: "llilh", 0xF: "llill",
}
RXE = {
    0x04: "lg", 0x14: "lgf", 0x15: "lgh", 0x16: "llgf",
    0x20: "cg", 0x21: "clg", 0x24: "stg", 0x30: "cgf", 0x31: "clgf",
    0x32: "ltgf", 0x34: "cgh", 0x47: "bic", 0x50: "sty",
    0x54: "ny", 0x55: "cly", 0x56: "oy", 0x57: "xy",
    0x58: "ly", 0x59: "cy", 0x5A: "ay", 0x5B: "sy", 0x5E: "aly",
    0x5F: "sly", 0x70: "stey", 0x71: "lay", 0x78: "ley", 0x79: "cey",
    0x7A: "aey", 0x7B: "sey", 0x7E: "auy", 0x7F: "suy", 0x91: "llgh",
}
RSE = {
    0x04: "lmg", 0x20: "clmh", 0x21: "clm", 0x24: "stmg",
    0x80: "icmh", 0x81: "icm",
}
CALLS = {"bal", "balr", "bas", "basr", "bassm", "bras", "brasl"}
CONDITIONAL = {"bct", "bctr", "brct", "brctg", "brcth", "bxh", "bxle", "brxh", "brxle"}


@dataclass
class Instruction:
    address: int
    data: bytes
    mnemonic: str
    operands: str
    format: str
    known: bool
    target: int | None = None
    flow: str = "next"
    mask: int | None = None

    @property
    def length(self):
        return len(self.data)

    @property
    def end(self):
        return self.address + self.length

    def text(self):
        return f"{self.address:08x}: {self.data.hex():<16} {self.mnemonic:<10} {self.operands}".rstrip()

    def to_dict(self):
        return {
            "address": self.address, "hex": self.data.hex(), "mnemonic": self.mnemonic,
            "operands": self.operands, "format": self.format, "known": self.known,
            "target": self.target, "flow": self.flow,
        }


def _reg(number):
    return f"%r{number}"


def _signed(data):
    return int.from_bytes(data, "big", signed=True)


def _memory(base, displacement, index=None):
    registers = []
    if index:
        registers.append(_reg(index))
    if base:
        registers.append(_reg(base))
    suffix = f"({','.join(registers)})" if registers else ""
    return f"{displacement:#x}{suffix}"


class S390Decoder:
    def decode(self, data, address=0):
        if address < 0 or address + 2 > len(data):
            raise ValueError("truncated S/390 instruction")
        first = data[address]
        length = (2, 4, 4, 6)[first >> 6]
        if address + length > len(data):
            raise ValueError("truncated S/390 instruction")
        raw = data[address:address + length]
        opcode2 = int.from_bytes(raw[:2], "big")
        mnemonic = "unknown"
        operands = raw.hex()
        fmt = "unknown"
        known = False
        target = None
        mask = None
        if first in RR and length == 2:
            mnemonic, fmt, known = RR[first], "RR", True
            operands = f"{_reg(raw[1] >> 4)}, {_reg(raw[1] & 15)}"
        elif first in RX and length == 4:
            mnemonic, fmt, known = RX[first], "RX", True
            r1, x2 = raw[1] >> 4, raw[1] & 15
            base, displacement = raw[2] >> 4, ((raw[2] & 15) << 8) | raw[3]
            operands = f"{_reg(r1)}, {_memory(base, displacement, x2)}"
            mask = r1
        elif first in RS and length == 4:
            mnemonic, fmt, known = RS[first], "RS", True
            r1, r3 = raw[1] >> 4, raw[1] & 15
            base, displacement = raw[2] >> 4, ((raw[2] & 15) << 8) | raw[3]
            second = f"{r3:#x}" if mnemonic in ("clm", "icm") else _reg(r3)
            operands = f"{_reg(r1)}, {second}, {_memory(base, displacement)}"
        elif first in SI and length == 4:
            mnemonic, fmt, known = SI[first], "SI", True
            base, displacement = raw[2] >> 4, ((raw[2] & 15) << 8) | raw[3]
            operands = f"{_memory(base, displacement)}, {raw[1]:#x}"
        elif first in SS and length == 6:
            mnemonic, fmt, known = SS[first], "SS", True
            b1, d1 = raw[2] >> 4, ((raw[2] & 15) << 8) | raw[3]
            b2, d2 = raw[4] >> 4, ((raw[4] & 15) << 8) | raw[5]
            operands = f"{_memory(b1, d1)}, {_memory(b2, d2)}, {raw[1]:#x}"
        elif first == 0xA5 and length == 4:
            mnemonic, fmt, known = RI_A5[raw[1] & 15], "RI", True
            register = raw[1] >> 4
            operands = f"{_reg(register)}, {int.from_bytes(raw[2:4], 'big'):#x}"
        elif first == 0xA7 and length == 4 and (raw[1] & 15) in RI:
            extension = raw[1] & 15
            mnemonic, fmt, known = RI[extension], "RI", True
            mask = raw[1] >> 4
            immediate = int.from_bytes(raw[2:4], "big") if extension < 4 else _signed(raw[2:4])
            if mnemonic in ("brc", "bras", "brct", "brctg"):
                target = address + immediate * 2
                operands = f"{mask:#x}, {target:#x}"
            else:
                operands = f"{_reg(mask)}, {immediate:#x}"
        elif first in RIL and length == 6 and (raw[1] & 15) in RIL[first]:
            extension = raw[1] & 15
            mnemonic, fmt, known = RIL[first][extension], "RIL", True
            mask = raw[1] >> 4
            immediate = int.from_bytes(raw[2:6], "big") if mnemonic in RIL_UNSIGNED else _signed(raw[2:6])
            if mnemonic in ("brcl", "brasl", "brcth"):
                target = address + immediate * 2
                first_operand = _reg(mask) if mnemonic == "brcth" else f"{mask:#x}"
                operands = f"{first_operand}, {target:#x}"
            elif mnemonic in RIL_PC:
                target = address + immediate * 2
                operands = f"{_reg(mask)}, {target:#x}"
            else:
                operands = f"{_reg(mask)}, {immediate:#x}"
        elif first == 0xE3 and length == 6 and raw[5] in RXE:
            mnemonic, fmt, known = RXE[raw[5]], "RXY", True
            r1, x2 = raw[1] >> 4, raw[1] & 15
            base = raw[2] >> 4
            displacement = (raw[4] << 12) | ((raw[2] & 15) << 8) | raw[3]
            if displacement & 0x80000:
                displacement -= 0x100000
            operands = f"{_reg(r1)}, {_memory(base, displacement, x2)}"
            mask = r1
        elif first == 0xEB and length == 6 and raw[5] in RSE:
            mnemonic, fmt, known = RSE[raw[5]], "RSE", True
            r1, r3 = raw[1] >> 4, raw[1] & 15
            base, displacement = raw[2] >> 4, ((raw[2] & 15) << 8) | raw[3]
            second = f"{r3:#x}" if mnemonic in ("clm", "clmh", "icm", "icmh") else _reg(r3)
            operands = f"{_reg(r1)}, {second}, {_memory(base, displacement)}"
        elif first in (0xB2, 0xB3, 0xB9) and length == 4 and opcode2 in RRE:
            mnemonic, fmt, known = RRE[opcode2], "RRE", True
            operands = f"{_reg(raw[2] >> 4)}, {_reg(raw[2] & 15)}"
        flow = "next"
        if mnemonic in ("balr", "basr") and raw[1] & 15 == 0:
            flow = "next"
        elif mnemonic == "balr" and raw[1] >> 4 != 14 and raw[1] & 15 == 14:
            flow = "return"
        elif mnemonic in CALLS:
            flow = "call"
        elif mnemonic in CONDITIONAL:
            flow = "conditional_jump"
        elif mnemonic == "bcr":
            condition = raw[1] >> 4
            register = raw[1] & 15
            mask = condition
            if condition == 0:
                flow = "next"
            elif condition == 15 and register == 14:
                flow = "return"
            elif condition == 15:
                flow = "jump"
            else:
                flow = "conditional_jump"
        elif mnemonic in ("bc", "brc", "brcl", "bic"):
            flow = "jump" if mask == 15 else "conditional_jump" if mask else "next"
        if mnemonic in ("bc", "bal", "bct", "bic") and x2 == 0 and base == 0:
            target = displacement
        elif mnemonic in ("brxh", "brxle") and base == 0:
            target = displacement
        return Instruction(address, raw, mnemonic, operands, fmt, known, target, flow, mask)

    def linear(self, data, start=0, end=None, maximum=100000):
        end = len(data) if end is None else min(end, len(data))
        address = start
        count = 0
        while address < end and count < maximum:
            instruction = self.decode(data, address)
            yield instruction
            address = instruction.end
            count += 1
