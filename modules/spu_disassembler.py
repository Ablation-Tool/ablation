"""
SPU (Synergistic Processing Unit) Disassembler — neutral ISA module.

Cell BE co-processor: 128 × 128-bit registers, 256KB local store, big-endian.
32-bit fixed-width instructions. Dual even/odd pipeline.

Opcode source: IBM SPU ISA v1.2 (SPU_ISA_v1.2_27Jan2007_pub.pdf), extracted from
the Cell SDK 3.0 documentation RPM.  All binary encodings match the PDF bit tables.

Format hierarchy (big-endian, IBM bit notation: bit 0 = MSB):
  RRR  4-bit op:  top nibble 0x8/0xB-0xF   → selb/shufb/mpya/fnms/fma/fms
  RI18 7-bit op:  (w>>25)&0x7F in RI18 set → hbra/hbrr/ila
  RI16 9-bit op:  (w>>23)&0x1FF in RI16 set→ br*/il/ilhu/iohl/lqr/stqr/stqa/lqa
  RI10 8-bit op:  (w>>24)&0xFF in RI10 set → ai/lqd/stqd/mpyi/ceqi/ori/...
  RR/RI7 11-bit:  remainder                → everything else

Field extraction (Python LSB=0 convention):
  rT  = w & 0x7F
  rA  = (w >> 7) & 0x7F
  rB  = (w >> 14) & 0x7F         (RR format)
  I7  = (w >> 14) & 0x7F         (RI7: rB field carries 7-bit immediate)
  I10 = signed((w >> 14) & 0x3FF, 10)
  I16 = signed((w >> 7) & 0xFFFF, 16)
  I18 = signed((w >> 7) & 0x3FFFF, 18)

csflt/cuflt/cflts/cfltu use a 10-bit opcode + 8-bit scale immediate (no rB).
Two consecutive op11 slots per instruction cover the two possible MSB values of I8.
"""

import struct
from collections import Counter
from typing import Optional

__all__ = [
    "SPUInstruction",
    "SPUDisassembler",
    "disassemble_spu_text",
    "decode_spu_word",
]


# ---------------------------------------------------------------------------
# Opcode tables
# ---------------------------------------------------------------------------

# RRR: 4-bit top nibble (bits 31-28), remaining bits encode rT/rA/rB/rC
# format: op4 (bits31-28), rT (27-23), rA (22-18), rB (17-13), rC (12-8) ... varies
# IBM ISA v1.2: selb=0x8, shufb=0xB, mpya=0xC, fnms=0xD, fma=0xE, fms=0xF
RRR_OPS = {
    0x8: "selb",   # conditional select: rT = (rC & rA) | (~rC & rB)
    0xB: "shufb",  # shuffle bytes: uses 4 operands
    0xC: "mpya",
    0xD: "fnms",   # float negative multiply-subtract
    0xE: "fma",    # float multiply-add
    0xF: "fms",    # float multiply-subtract
}

# RI18: 7-bit opcode (bits 31-25), I18 (bits 24-7), rT (bits 6-0)
RI18_OPS = {
    0x08: "hbra",  # hint for branch absolute
    0x09: "hbrr",  # hint for branch relative
    0x21: "ila",   # load immediate address (18-bit zero-extended)
}

# RI16: 9-bit opcode (bits 31-23), I16 (bits 22-7), rT (bits 6-0)
# All branch offsets are PC-relative word-addressed (target = PC + I16*4).
# Absolute branches (bra/brasl) use I16 as an absolute word address.
RI16_OPS = {
    0x040: "brz",    # branch if zero (word)
    0x041: "stqa",   # store quadword absolute
    0x042: "brnz",   # branch if not zero (word)
    0x044: "brhz",   # branch if zero (halfword)
    0x046: "brhnz",  # branch if not zero (halfword)
    0x047: "stqr",   # store quadword PC-relative
    0x060: "bra",    # branch absolute
    0x061: "lqa",    # load quadword absolute
    0x062: "brasl",  # branch absolute and set link
    0x064: "br",     # branch relative
    0x065: "fsmbi",  # form select mask for bytes immediate
    0x066: "brsl",   # branch relative and set link
    0x067: "lqr",    # load quadword PC-relative
    0x081: "il",     # load immediate signed 16-bit (all 4 word slots)
    0x082: "ilhu",   # load immediate halfword upper
    0x083: "ilh",    # load immediate halfword
    0x0C1: "iohl",   # OR immediate lower halfword
}

# RI10: 8-bit opcode (bits 31-24), I10 (bits 23-14 signed), rA (13-7), rT (6-0)
# stqa/lqa are RI16 (op9), NOT RI10.  All values below are from ISA v1.2 directly.
RI10_OPS = {
    0x04: "ori",    # OR immediate
    0x05: "orhi",   # OR halfword immediate
    0x06: "orbi",   # OR byte immediate
    0x0C: "sfi",    # subtract from immediate
    0x0D: "sfhi",   # subtract from halfword immediate
    0x14: "andi",   # AND immediate
    0x15: "andhi",  # AND halfword immediate
    0x16: "andbi",  # AND byte immediate
    0x1C: "ai",     # add immediate (signed 10-bit)
    0x1D: "ahi",    # add halfword immediate
    0x24: "stqd",   # store quadword d-form: mem[(rA + I10*16) & ~0xF] = rT
    0x34: "lqd",    # load quadword d-form: rT = mem[(rA + I10*16) & ~0xF]
    0x44: "xori",   # XOR immediate
    0x45: "xorhi",  # XOR halfword immediate
    0x46: "xorbi",  # XOR byte immediate
    0x4C: "cgti",   # compare greater than immediate (signed word)
    0x4D: "cgthi",  # compare greater than halfword immediate
    0x4E: "cgtbi",  # compare greater than byte immediate
    0x4F: "hgti",   # halt if greater than immediate
    0x5C: "clgti",  # compare logical greater than immediate (unsigned word)
    0x5D: "clgthi", # compare logical greater than halfword immediate
    0x5E: "clgtbi", # compare logical greater than byte immediate
    0x5F: "hlgti",  # halt if logical greater than immediate
    0x74: "mpyi",   # multiply immediate (signed lower 16)
    0x75: "mpyui",  # multiply immediate unsigned
    0x7C: "ceqi",   # compare equal immediate
    0x7D: "ceqhi",  # compare equal halfword immediate
    0x7E: "ceqbi",  # compare equal byte immediate
    0x7F: "heqi",   # halt if equal immediate
}

# RR / RI7: 11-bit opcode (bits 31-21)
# RI7 instructions use the rB field (bits 20-14) as a 7-bit immediate.
# RR instructions use rB as a register.
# All encodings from IBM SPU ISA v1.2 (SPU_ISA_v1.2_27Jan2007_pub.pdf).
RR_OPS = {
    # Special / control
    0x000: "stop",
    0x001: "lnop",    # odd-pipe NOP
    0x002: "sync",
    0x003: "dsync",
    0x00C: "mfspr",   # move from special-purpose register
    0x00D: "rdch",    # read channel
    0x00F: "rchcnt",  # read channel count
    0x10C: "mtspr",   # move to special-purpose register
    0x10D: "wrch",    # write channel (DMA, mailbox, event)
    0x140: "stopd",   # stop and signal with dependencies
    0x201: "nop",     # even-pipe NOP

    # Subtract / logical
    0x040: "sf",      # subtract from word
    0x041: "or",      # bitwise OR (or $rT, $rA, $rA = move)
    0x042: "bg",      # borrow generate
    0x048: "sfh",     # subtract from halfword
    0x049: "nor",     # bitwise NOR
    0x053: "absdb",   # absolute difference of bytes
    0x058: "rot",     # rotate word
    0x059: "rotm",    # rotate and mask word
    0x05A: "rotma",   # rotate and mask algebraic word
    0x05B: "shl",     # shift left word
    0x05C: "roth",    # rotate halfword
    0x05D: "rothm",   # rotate and mask halfword
    0x05E: "rotmah",  # rotate and mask algebraic halfword
    0x05F: "shlh",    # shift left halfword

    # RI7 immediate shift/rotate word/halfword
    0x078: "roti",    # rotate word immediate
    0x079: "rotmi",   # rotate and mask word immediate
    0x07A: "rotmai",  # rotate and mask algebraic word immediate
    0x07B: "shli",    # shift left word immediate
    0x07C: "rothi",   # rotate halfword immediate
    0x07D: "rothmi",  # rotate and mask halfword immediate
    0x07E: "rotmahi", # rotate and mask algebraic halfword immediate
    0x07F: "shlhi",   # shift left halfword immediate

    # Integer add / logical
    0x0C0: "a",       # add word
    0x0C1: "and",     # bitwise AND
    0x0C2: "cg",      # carry generate
    0x0C8: "ah",      # add halfword
    0x0C9: "nand",    # bitwise NAND
    0x0D3: "avgb",    # average bytes unsigned

    # Compare (signed/unsigned word/halfword/byte)
    0x240: "cgt",     # compare greater than word (signed)
    0x241: "xor",     # bitwise XOR
    0x248: "cgth",    # compare greater than halfword (signed)
    0x249: "eqv",     # bitwise equivalence
    0x250: "cgtb",    # compare greater than byte (signed)
    0x253: "sumb",    # sum bytes into halfwords
    0x258: "hgt",     # halt if greater than

    # Unary sign/leading-zero
    0x2A5: "clz",     # count leading zeros
    0x2A6: "xswd",    # extend sign doubleword to quadword (unary)
    0x2AE: "xshw",    # extend sign halfword to word (unary)
    0x2B4: "cntb",    # count bits in bytes (population count, unary)
    0x2B6: "xsbh",    # extend sign byte to halfword (unary)

    # Compare logical (unsigned) / float compare
    0x2C0: "clgt",    # compare logical greater than word
    0x2C1: "andc",    # AND with complement: rT = rA & ~rB
    0x2C2: "fcgt",    # float compare greater than
    0x2C3: "dfcgt",   # double float compare greater than
    0x2C4: "fa",      # float add
    0x2C5: "fs",      # float subtract
    0x2C6: "fm",      # float multiply
    0x2C8: "clgth",   # compare logical greater than halfword
    0x2C9: "orc",     # OR with complement: rT = rA | ~rB
    0x2CA: "fcmgt",   # float compare magnitude greater than
    0x2CB: "dfcmgt",  # double float compare magnitude greater than
    0x2CC: "dfa",     # double float add
    0x2CD: "dfs",     # double float subtract
    0x2CE: "dfm",     # double float multiply
    0x2D0: "clgtb",   # compare logical greater than byte
    0x2D8: "hlgt",    # halt if logical greater than

    # Extended integer (carry/borrow chains, multi-word arithmetic)
    0x340: "addx",    # add extended (with carry from prior cg)
    0x341: "sfx",     # subtract from extended
    0x342: "cgx",     # carry generate extended
    0x343: "bgx",     # borrow generate extended
    0x346: "mpyhha",  # multiply high halfwords and add
    0x34E: "mpyhhau", # multiply high halfwords and add unsigned

    # Double-float fused ops
    0x35C: "dfma",    # double float multiply-add
    0x35D: "dfms",    # double float multiply-subtract
    0x35E: "dfnms",   # double float negative multiply-subtract
    0x35F: "dfnma",   # double float negative multiply-add

    # Branch indirect
    0x128: "biz",     # branch indirect if zero
    0x129: "binz",    # branch indirect if not zero
    0x12A: "bihz",    # branch indirect if halfword zero
    0x12B: "bihnz",   # branch indirect if halfword not zero
    0x1A8: "bi",      # branch indirect
    0x1A9: "bisl",    # branch indirect and set link
    0x1AA: "iret",    # interrupt return
    0x1AB: "bisled",  # branch indirect and set link if event dispatch enabled
    0x1AC: "hbr",     # hint for indirect branch

    # Gather / form select mask (unary: rA → rT)
    0x1B0: "gb",      # gather bits from words
    0x1B1: "gbh",     # gather bits from halfwords
    0x1B2: "gbb",     # gather bits from bytes
    0x1B4: "fsm",     # form select mask for words
    0x1B5: "fsmh",    # form select mask for halfwords
    0x1B6: "fsmb",    # form select mask for bytes
    0x1B8: "frest",   # float reciprocal estimate (unary)
    0x1B9: "frsqest", # float reciprocal sqrt estimate (unary)

    # Memory indexed
    0x144: "stqx",    # store quadword indexed: mem[(rA+rB)&~0xF] = rT
    0x1C4: "lqx",     # load quadword indexed: rT = mem[(rA+rB)&~0xF]

    # Quadword shift/rotate by register count
    0x1CC: "rotqbybi",  # rotate quadword by bytes from bit count
    0x1CD: "rotqmbybi", # rotate and mask quadword by bytes from bit count
    0x1CF: "shlqbybi",  # shift left quadword by bytes from bit count
    0x1D4: "cbx",       # control for byte insertion x-form
    0x1D5: "chx",       # control for halfword insertion x-form
    0x1D6: "cwx",       # control for word insertion x-form
    0x1D7: "cdx",       # control for doubleword insertion x-form
    0x1D8: "rotqbi",    # rotate quadword by bits
    0x1D9: "rotqmbi",   # rotate and mask quadword by bits
    0x1DB: "shlqbi",    # shift left quadword by bits
    0x1DC: "rotqby",    # rotate quadword by bytes
    0x1DD: "rotqmby",   # rotate and mask quadword by bytes
    0x1DF: "shlqby",    # shift left quadword by bytes

    # RI7 immediate quadword shift/rotate and control-for-insertion d-forms
    0x1F0: "orx",     # OR across quadword (unary)
    0x1F4: "cbd",     # control for byte insertion d-form (RI7: I7 = byte offset)
    0x1F5: "chd",     # control for halfword insertion d-form
    0x1F6: "cwd",     # control for word insertion d-form
    0x1F7: "cdd",     # control for doubleword insertion d-form
    0x1F8: "rotqbii",  # rotate quadword by bits immediate (RI7)
    0x1F9: "rotqmbii", # rotate and mask quadword by bits immediate
    0x1FB: "shlqbii",  # shift left quadword by bits immediate
    0x1FC: "rotqbyi",  # rotate quadword by bytes immediate
    0x1FD: "rotqmbyi", # rotate and mask quadword by bytes immediate
    0x1FF: "shlqbyi",  # shift left quadword by bytes immediate

    # Compare equal
    0x3C0: "ceq",     # compare equal word
    0x3C2: "fceq",    # float compare equal
    0x3C3: "dfceq",   # double float compare equal
    0x3C4: "mpy",     # multiply even halfwords (signed)
    0x3C5: "mpyh",    # multiply high halfwords
    0x3C6: "mpyhh",   # multiply high halfwords signed
    0x3C7: "mpys",    # multiply and shift right
    0x3C8: "ceqh",    # compare equal halfword
    0x3CA: "fcmeq",   # float compare magnitude equal
    0x3CB: "dfcmeq",  # double float compare magnitude equal
    0x3CC: "mpyu",    # multiply even halfwords unsigned
    0x3CE: "mpyhhu",  # multiply high halfwords unsigned
    0x3D0: "ceqb",    # compare equal byte
    0x3D4: "fi",      # float interpolate
    0x3D8: "heq",     # halt if equal

    # Float status / precision
    0x398: "fscrrd",  # float status and control register read (unary)
    0x3B8: "fesd",    # float extend single to double (unary)
    0x3B9: "frds",    # float round double to single (unary)
    0x3BA: "fscrwr",  # float status and control register write (unary)
    0x3BF: "dftsv",   # double float test special value

    # Float conversion RI8-format: 10-bit fixed opcode, bit 10 = MSB of I8 scale
    # Two consecutive op11 entries per instruction (I8 MSB = 0 and 1).
    0x3B0: "cflts",  0x3B1: "cflts",  # convert float to signed fixed-point
    0x3B2: "cfltu",  0x3B3: "cfltu",  # convert float to unsigned fixed-point
    0x3B4: "csflt",  0x3B5: "csflt",  # convert signed fixed-point to float
    0x3B6: "cuflt",  0x3B7: "cuflt",  # convert unsigned fixed-point to float
}

# RI7 subset: these op11 values use the rB field as a 7-bit immediate instead of a register
RI7_OPS = {
    # Word/halfword shift/rotate immediates
    0x078, 0x079, 0x07A, 0x07B,
    0x07C, 0x07D, 0x07E, 0x07F,
    # Quadword shift/rotate immediates and control-for-insertion d-forms
    0x1F4, 0x1F5, 0x1F6, 0x1F7,
    0x1F8, 0x1F9, 0x1FB,
    0x1FC, 0x1FD, 0x1FF,
}


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class SPUInstruction:
    __slots__ = ("addr", "word", "mnemonic", "fmt",
                 "rT", "rA", "rB", "I7", "I10", "I16", "I18")

    def __init__(self, addr: int, word: int):
        self.addr = addr
        self.word = word
        self.mnemonic = "???"
        self.fmt = "unknown"
        self.rT = word & 0x7F
        self.rA = (word >> 7) & 0x7F
        self.rB = (word >> 14) & 0x7F
        i7 = (word >> 14) & 0x7F
        self.I7 = i7
        i10 = (word >> 14) & 0x3FF
        self.I10 = i10 - 0x400 if i10 >= 0x200 else i10
        i16 = (word >> 7) & 0xFFFF
        self.I16 = i16 - 0x10000 if i16 >= 0x8000 else i16
        i18 = (word >> 7) & 0x3FFFF
        self.I18 = i18 - 0x40000 if i18 >= 0x20000 else i18

    def __repr__(self) -> str:
        return f"<SPUInsn {self.addr:#010x} {self.word:#010x} {self.mnemonic}>"

    def asm(self) -> str:
        w = self.word
        m = self.mnemonic
        fmt = self.fmt
        rT, rA, rB = self.rT, self.rA, self.rB

        if fmt == "rrr":
            # RRR: 4-op — rD/rA/rB/rC packed differently per instruction
            # IBM: bits 6-10=rT, 11-15=rA, 16-20=rB, 21-25=rC (approximate)
            rC = (w >> 0) & 0x7F   # rough; actual IBM field layout varies
            return f"{m}\t${rT}, ${rA}, ${rB}, ${rC}"
        if fmt == "ri18":
            return f"{m}\t${rT}, {self.I18:#x}"
        if fmt == "ri16":
            if m in ("br", "brsl", "brz", "brhz", "brnz", "brhnz"):
                target = self.addr + (self.I16 << 2)
                return f"{m}\t${rT}, {target:#x}"
            if m in ("bra", "brasl"):
                target = self.I16 << 2
                return f"{m}\t${rT}, {target:#x}"
            if m in ("lqr", "stqr"):
                target = (self.addr + self.I16 * 4 + 4) & ~0xF
                return f"{m}\t${rT}, {target:#010x}"
            if m in ("stqa", "lqa"):
                return f"{m}\t${rT}, {self.I16 << 2:#x}"
            return f"{m}\t${rT}, {self.I16}"
        if fmt == "ri10":
            return f"{m}\t${rT}, {self.I10}(${rA})"
        if fmt == "ri7":
            return f"{m}\t${rT}, {self.I7}(${rA})"
        if fmt == "rr":
            return f"{m}\t${rT}, ${rA}, ${rB}"
        if fmt == "rr_unary":
            return f"{m}\t${rT}, ${rA}"
        if fmt == "nop":
            return f"{m}\t${rT}"
        if fmt == "data":
            return f".word\t{w:#010x}{_word_ascii_hint(w)}"
        return f"{m}\t${rT}, ${rA}, ${rB}  ; {w:#010x}"


# Unary RR instructions: output format is rT, rA only (rB unused)
_RR_UNARY = {
    0x1B0, 0x1B1, 0x1B2,         # gb, gbh, gbb
    0x1B4, 0x1B5, 0x1B6,         # fsm, fsmh, fsmb
    0x1B8, 0x1B9,                 # frest, frsqest
    0x1F0,                        # orx
    0x2A5, 0x2A6, 0x2AE, 0x2B4, 0x2B6,  # clz, xswd, xshw, cntb, xsbh
    0x398,                        # fscrrd
    0x3B8, 0x3B9, 0x3BA,          # fesd, frds, fscrwr
}

# Inline data annotation: branch categories and unconditional terminators
_RI16_REL_BRANCHES = frozenset({"br", "brsl", "brz", "brhz", "brnz", "brhnz"})
_RI16_ABS_BRANCHES = frozenset({"bra", "brasl"})
_TERMINATORS = frozenset({"stop", "stopd", "bra", "br"})


def _word_ascii_hint(w: int) -> str:
    chars = [(w >> s) & 0xFF for s in (24, 16, 8, 0)]
    if all(0x20 <= c <= 0x7E for c in chars):
        return '  # "' + "".join(chr(c) for c in chars) + '"'
    return ""


def decode_spu_word(addr: int, word: int) -> SPUInstruction:
    insn = SPUInstruction(addr, word)

    # RRR: top nibble 0xA-0xF
    top4 = (word >> 28) & 0xF
    if top4 in RRR_OPS:
        insn.mnemonic = RRR_OPS[top4]
        insn.fmt = "rrr"
        return insn

    # RI18: 7-bit opcode
    op7 = (word >> 25) & 0x7F
    if op7 in RI18_OPS:
        insn.mnemonic = RI18_OPS[op7]
        insn.fmt = "ri18"
        return insn

    # RI16: 9-bit opcode — MUST check before RI10
    op9 = (word >> 23) & 0x1FF
    if op9 in RI16_OPS:
        insn.mnemonic = RI16_OPS[op9]
        insn.fmt = "ri16"
        return insn

    # RI10: 8-bit opcode
    op8 = (word >> 24) & 0xFF
    if op8 in RI10_OPS:
        insn.mnemonic = RI10_OPS[op8]
        insn.fmt = "ri10"
        return insn

    # RR / RI7: 11-bit opcode
    op11 = (word >> 21) & 0x7FF
    if op11 in RR_OPS:
        insn.mnemonic = RR_OPS[op11]
        if op11 in RI7_OPS:
            insn.fmt = "ri7"
        elif op11 in _RR_UNARY:
            insn.fmt = "rr_unary"
        elif op11 in (0x001, 0x201):  # lnop / nop
            insn.fmt = "nop"
        else:
            insn.fmt = "rr"
        return insn

    # Unknown — record opcode for gap analysis
    insn.mnemonic = f"???_{op11:#05x}"
    insn.fmt = "unknown"
    return insn


# ---------------------------------------------------------------------------
# Disassembler entry point
# ---------------------------------------------------------------------------

def disassemble_spu_text(data: bytes, base_vaddr: int = 0, limit: Optional[int] = None):
    """
    Decode a raw SPU text section (big-endian 32-bit words).
    Yields SPUInstruction objects.

    Two-pass: first decodes all words, then annotates unknown words that follow
    unconditional terminators (stop/bra/br) and are not branch targets as
    fmt="data" / mnemonic=".word" (inline constant pools).
    """
    n = len(data) // 4
    if limit is not None:
        n = min(n, limit)

    # Pass 1: decode
    insns = []
    for i in range(n):
        addr = base_vaddr + i * 4
        word = struct.unpack_from(">I", data, i * 4)[0]
        insns.append(decode_spu_word(addr, word))

    # Build branch target set from RI16 control-flow instructions
    branch_targets = set()
    for insn in insns:
        if insn.fmt == "ri16":
            if insn.mnemonic in _RI16_REL_BRANCHES:
                branch_targets.add(insn.addr + (insn.I16 << 2))
            elif insn.mnemonic in _RI16_ABS_BRANCHES:
                branch_targets.add(insn.I16 << 2)

    # Pass 2: annotate unknown words after unconditional terminators
    for i, insn in enumerate(insns):
        if insn.mnemonic not in _TERMINATORS:
            continue
        j = i + 1
        while j < len(insns):
            nxt = insns[j]
            if nxt.addr in branch_targets:
                break
            if nxt.fmt != "unknown":
                break
            nxt.fmt = "data"
            nxt.mnemonic = ".word"
            j += 1

    yield from insns


def frequency_report(data: bytes, base_vaddr: int = 0) -> str:
    """Return a mnemonic frequency table for coverage analysis."""
    counts: Counter = Counter()
    unknowns: Counter = Counter()
    data_count = 0
    total = 0
    for insn in disassemble_spu_text(data, base_vaddr):
        total += 1
        if insn.fmt == "unknown":
            op11 = (insn.word >> 21) & 0x7FF
            op8  = (insn.word >> 24) & 0xFF
            unknowns[f"op11={op11:#05x}/op8={op8:#04x}"] += 1
        elif insn.fmt == "data":
            data_count += 1
        else:
            counts[insn.mnemonic] += 1
    known = total - sum(unknowns.values())
    pct = 100.0 * known / total if total else 0.0
    lines = [f"=== SPU mnemonic frequency (coverage {known}/{total} = {pct:.1f}%) ==="]
    for mnem, cnt in counts.most_common(40):
        lines.append(f"  {mnem:16s} {cnt:5d}")
    if data_count:
        lines.append(f"\n=== Inline data words: {data_count} (annotated as .word, excluded from unknown count) ===")
    if unknowns:
        lines.append("\n=== Unknown opcodes (coverage gaps) ===")
        for key, cnt in unknowns.most_common(20):
            lines.append(f"  {key:30s} {cnt:5d}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SPU ELF extraction helper
# ---------------------------------------------------------------------------

def extract_spu_text_from_elf(elf_data: bytes):
    """
    Given raw bytes of an SPU ELF (machine type 0x17), return
    (text_bytes, base_vaddr, entry_vaddr) or raise ValueError.
    """
    if elf_data[0:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    e_type = struct.unpack_from(">H", elf_data, 16)[0]
    e_machine = struct.unpack_from(">H", elf_data, 18)[0]
    if e_machine != 0x17:
        raise ValueError(f"not SPU ELF (machine={e_machine:#x})")

    e_entry   = struct.unpack_from(">I", elf_data, 24)[0]
    e_phoff   = struct.unpack_from(">I", elf_data, 28)[0]
    e_phnum   = struct.unpack_from(">H", elf_data, 44)[0]

    # Find PT_LOAD segment containing the text
    for i in range(e_phnum):
        off = e_phoff + i * 32
        p_type   = struct.unpack_from(">I", elf_data, off)[0]
        p_offset = struct.unpack_from(">I", elf_data, off + 4)[0]
        p_vaddr  = struct.unpack_from(">I", elf_data, off + 8)[0]
        p_filesz = struct.unpack_from(">I", elf_data, off + 16)[0]
        p_flags  = struct.unpack_from(">I", elf_data, off + 24)[0]
        if p_type == 1 and (p_flags & 0x1):  # PT_LOAD + PF_X
            text = elf_data[p_offset: p_offset + p_filesz]
            return text, p_vaddr, e_entry

    raise ValueError("no executable PT_LOAD segment found")


# ---------------------------------------------------------------------------
# Standalone disassembly
# ---------------------------------------------------------------------------

def dump_spu_elf(path: str, start_va: Optional[int] = None,
                 end_va: Optional[int] = None, limit: int = 256) -> str:
    """
    Disassemble an SPU ELF to a string.
    start_va / end_va filter to a VA range.
    limit caps the number of instructions printed.
    """
    with open(path, "rb") as f:
        data = f.read()
    text, base_vaddr, entry = extract_spu_text_from_elf(data)
    lines = [f"; SPU ELF {path}  entry={entry:#010x}  base={base_vaddr:#010x}"]
    printed = 0
    for insn in disassemble_spu_text(text, base_vaddr):
        if start_va is not None and insn.addr < start_va:
            continue
        if end_va is not None and insn.addr >= end_va:
            break
        lines.append(f"  {insn.addr:08x}: {insn.word:08x}  {insn.asm()}")
        printed += 1
        if printed >= limit:
            lines.append(f"  ... (truncated at {limit} instructions)")
            break
    return "\n".join(lines)
