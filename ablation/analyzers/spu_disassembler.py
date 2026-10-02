"""
SPU (Synergistic Processing Unit) Disassembler — neutral ISA module.

Cell BE co-processor: 128 × 128-bit registers, 256KB local store, big-endian.
32-bit fixed-width instructions. Dual even/odd pipeline.

Opcode confirmation sources:
  - IBM SDK addmat example (not-stripped SPU ELF):
      /tmp/SG247575_addmat_eitanp/atomic_cache/spu/spu
  - Crysis 2 PS3 embedded SPU ELFs (38,556 instructions, entry=0x3050):
      extracted from crysis2_decrypted.elf, 23 embedded SPU ELFs
  - IBM CBE Handbook v1.1 + SPU Assembly Language Spec v1.5
    (both provide mnemonics/latency only; no binary encodings)

Format hierarchy (big-endian, IBM bit notation: bit 0 = MSB):
  RRR  4-bit op:  top nibble 0xA-0xF       → selb/shufb/mpya/fms/fnms/fma
  RI18 7-bit op:  (w>>25)&0x7F in RI18 set → hbra/hbrr/ila
  RI16 9-bit op:  (w>>23)&0x1FF in RI16 set→ br*/il/ilhu/iohl/lqr/stqr
  RI10 8-bit op:  (w>>24)&0xFF in RI10 set → ai/lqd/stqd/mpyi/...
  RR/RI7 11-bit:  remainder                → everything else

Field extraction (Python LSB=0 convention):
  rT  = w & 0x7F
  rA  = (w >> 7) & 0x7F
  rB  = (w >> 14) & 0x7F         (RR format)
  I7  = (w >> 14) & 0x7F         (RI7: rB field carries 7-bit immediate)
  I10 = signed((w >> 14) & 0x3FF, 10)
  I16 = signed((w >> 7) & 0xFFFF, 16)
  I18 = signed((w >> 7) & 0x3FFFF, 18)
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
RRR_OPS = {
    0xA: "selb",   # conditional select: rT = (rC & rA) | (~rC & rB)
    0xB: "shufb",  # shuffle bytes: uses 4 operands
    0xC: "mpya",
    0xD: "fms",    # float multiply-subtract
    0xE: "fnms",   # float negative multiply-subtract
    0xF: "fma",    # float multiply-add
}

# RI18: 7-bit opcode (bits 31-25), I18 (bits 24-7), rT (bits 6-0)
RI18_OPS = {
    0x08: "hbra",  # hint for branch absolute
    0x09: "hbrr",  # hint for branch relative
    0x21: "ila",   # load immediate address (18-bit zero-extended)
}

# RI16: 9-bit opcode (bits 31-23), I16 (bits 22-7), rT (bits 6-0)
# All branch offsets are PC-relative, shifted left 2 (word-addressed).
# il/ilhu/iohl/lqr/stqr confirmed empirically from addmat binary.
RI16_OPS = {
    0x040: "brz",    # branch if zero (word)
    0x042: "brhz",   # branch if zero (halfword)
    0x043: "il",     # load immediate signed 16-bit (confirmed: sequential imm loads in addmat)
    0x047: "ilhu",   # load immediate halfword upper (confirmed: address formation pairs)
    0x060: "bra",    # branch absolute
    0x062: "brasl",  # branch absolute and set link
    0x064: "br",     # branch relative
    0x066: "brsl",   # branch relative and set link
    0x067: "stqr",   # store quadword PC-relative (op9=0x067; 402 hits Crysis2, forward offsets)
    0x07D: "stqr",   # store quadword PC-relative (confirmed: register saves in prologue)
    0x07F: "lqr",    # load quadword PC-relative (confirmed: large-neg I16 = static data offset)
    0x098: "stqr",   # store quadword PC-relative alt encoding (op9=0x098; confirmed from 0x4c002b60)
    0x099: "stqr",   # store quadword PC-relative alt encoding (op9=0x099 variant)
    0x0C1: "iohl",   # OR immediate lower halfword (confirmed: rA=$127, I16=0xffff pairs)
    0x100: "brnz",   # branch if not zero (word)
    0x102: "brhnz",  # branch if not zero (halfword)
}

# RI10: 8-bit opcode (bits 31-24), I10 (bits 23-14 signed), rA (13-7), rT (6-0)
# Note: lqr/stqr/il/ilhu/iohl are RI16, NOT RI10 — prior tools had these wrong.
RI10_OPS = {
    0x04: "stqa",   # store quadword absolute
    0x0C: "lqa",    # load quadword absolute
    0x1C: "ai",     # add immediate (signed 10-bit)
    0x1D: "ahi",    # add halfword immediate
    0x1E: "sfhi",   # subtract from halfword immediate
    0x1F: "sfi",    # subtract from immediate
    0x24: "stqd",   # store quadword d-form: mem[(rA + I10*16) & ~0xF] = rT
    0x28: "mpyi",   # multiply immediate (signed lower 16)
    0x29: "mpyui",  # multiply immediate unsigned
    0x34: "lqd",    # load quadword d-form: rT = mem[(rA + I10*16) & ~0xF]
    # 0x38: unknown — 2167 hits in Crysis 2 SPU physics; not in addmat (integer only)
    0x74: "ceqi",   # compare equal immediate
    0x76: "cgti",   # compare greater than immediate (signed word)
    0x78: "cgtbi",  # compare greater than byte immediate
    0x7A: "cgthi",  # compare greater than halfword immediate
    0x7C: "andbi",  # AND byte immediate
    0x7D: "andhi",  # AND halfword immediate
    0x7E: "andi",   # AND immediate
}

# RR / RI7: 11-bit opcode (bits 31-21)
# RI7 instructions use the rB field (bits 20-14) as a 7-bit immediate.
# RR instructions use rB as a register.
RR_OPS = {
    # Special / channel
    0x000: "stop",
    0x001: "lnop",    # odd-pipe NOP (fills pipeline slot, no effect)
    0x002: "sync",
    0x003: "dsync",
    0x00C: "mfspr",
    0x00D: "rdch",    # read channel
    0x00F: "rchcnt",  # read channel count
    0x01C: "mtspr",
    0x01D: "wrch",    # write channel (DMA, mailbox, event)

    # Arithmetic — subtract
    0x040: "sf",      # subtract from (word)
    0x041: "sfc",     # subtract from with carry
    0x048: "sfh",     # subtract from halfword
    0x049: "nor",
    0x04B: "absdb",   # absolute difference of bytes
    0x04C: "rot",     # rotate word
    0x04D: "rotm",    # rotate and mask word
    0x04E: "rotma",   # rotate and mask algebraic
    0x050: "shl",     # shift left word
    0x052: "shlh",    # shift left halfword
    0x054: "roth",    # rotate halfword
    0x056: "rothm",   # rotate and mask halfword
    0x057: "rotmah",  # rotate and mask algebraic halfword
    0x05B: "shlqbi",  # shift left quadword by bits (RI7: imm3 in rB lsbs)
    0x05C: "shld",    # shift left doubleword

    # Branch indirect
    0x068: "bid",
    0x069: "bie",
    0x070: "biz",
    0x072: "bihz",
    0x074: "binz",
    0x076: "bihnz",
    0x080: "bi",      # branch indirect
    0x082: "bisl",    # branch indirect and set link
    0x083: "iret",
    0x085: "bisled",

    # Float-to-float precision conversions (Crysis 2 physics pipeline)
    0x0A0: "frds",    # float round double to single (tentative: after csflt, before shufb)
    0x0A1: "fesd",    # float extend single to double (tentative: rA=rT-1 pattern)

    # Memory indexed (confirmed from addmat: lqx=0x07B, stqx=0x079)
    0x079: "stqx",    # store quadword indexed: mem[(rA+rB)&~0xF] = rT (confirmed)
    0x07A: "stqxl",   # store quadword indexed local (tentative: between stqx/lqx)
    0x07B: "lqx",     # load quadword indexed:  rT = mem[(rA+rB)&~0xF] (confirmed)
    0x07F: "lqxl",    # load quadword indexed local (tentative: rB=$6 fixed in matrix ops)

    # Integer arithmetic
    0x0C0: "a",       # add word
    0x0C1: "addx",    # add extended with carry (tentative: tree-reduction pattern, 344 hits)
    0x0C2: "bg",      # borrow generate
    0x0C4: "bgx",     # borrow generate extended
    0x2C0: "cg",      # carry generate (tentative: precedes cgx/addx in multi-precision chain)
    0x2E0: "cgx",     # carry generate extended (tentative: cg→cgx→addx triple confirmed)
    0x0C8: "ah",      # add halfword
    0x0C9: "avgb",    # average bytes unsigned
    0x0CA: "orx",     # or across (reduction)
    0x0CB: "mpy",     # multiply (even halfwords, signed)
    0x0CD: "mpyh",    # multiply high halfwords
    0x0CE: "mpyhh",   # multiply high halfwords signed
    0x0CF: "mpyhhu",  # multiply high halfwords unsigned
    0x0D3: "mpys",    # multiply and shift right (tentative: in shufb sequences, 224 hits)
    0x0D8: "clz",     # count leading zeros
    0x0D9: "cntb",    # count bits in bytes

    # Compare equal
    0x100: "ceq",     # compare equal word
    0x104: "ceqb",    # compare equal byte
    0x10C: "ceqh",    # compare equal halfword

    # Logical
    0x140: "and",
    0x141: "andc",    # and with complement
    0x150: "clgt",    # compare logical greater than word
    0x154: "clgtb",   # compare logical greater than byte
    0x15C: "clgth",   # compare logical greater than halfword
    0x160: "or",      # also: "or $rt, $ra, $ra" = move alias
    0x161: "orc",
    0x164: "eqv",
    0x168: "xor",
    0x170: "cgt",     # compare greater than (signed word)
    0x174: "cgtb",
    0x17C: "cgth",

    # Shift/rotate quadword
    0x180: "rotqbybi",  # rotate quadword by bytes from bit shift count
    0x184: "rotqmbybi",
    0x188: "shlqbybi",
    0x18C: "rotqbyi",   # rotate quadword by bytes immediate (RI7)
    0x194: "rotqmbyi",
    0x198: "shlqbyi",   # shift left quadword by bytes immediate (RI7)
    0x19C: "rotqby",
    0x19D: "rotqbyx",   # rotate quadword by bytes indexed (tentative: rB=$81 fixed, 402 hits)
    0x1A4: "rotqmby",
    0x1A8: "fence",     # SPU data fence / sync barrier (word=0x35000000, always rT=rA=rB=$0, 210 hits)
    0x1AC: "shlqby",

    # Floating-point
    0x1C0: "fa",      # float add
    0x1C1: "dfa",     # double float add
    0x1C4: "fm",      # float multiply
    0x1C5: "dfm",
    0x1C8: "fs",      # float subtract
    0x1C9: "dfs",
    0x1CC: "fceq",    # float compare equal
    0x1D0: "fcmeq",
    0x1D4: "fcgt",    # float compare greater than
    0x1D8: "fcmgt",
    0x1A9: "fence2",  # float-pipe sync/drain (tentative: always rT=$0, always follows csflt, 127 hits)
    0x1DC: "csflt",   # convert signed int to float (RI7: rB=scale7; confirmed from addmat rand())
    0x1DD: "cuflt",   # convert unsigned int to float (RI7: rB=scale7; adjacent to csflt, 103 hits)
    0x2AE: "cfltu",   # convert float to unsigned int (RI7: rB=scale7; rB=$0 in Crysis2, 211 hits)
    0x2B6: "cflts",   # convert float to signed int (RI7: rB=scale7; rB=$0 in Crysis2, 244 hits)
    0x1F4: "frest",   # float reciprocal estimate (unary)
    0x1F8: "frsqest", # float reciprocal sqrt estimate (unary)
    0x1FC: "fi",      # float interpolate

    # NOP / control vector generation
    0x201: "nop",     # even-pipe NOP: nop $rT (confirmed from addmat 0x4020007f)
    0x204: "cbd",     # control for byte insertion d-form (confirmed: 2467 hits crysis2)
    0x205: "cbx",     # control for byte insertion x-form
    0x206: "chd",     # control for halfword insertion d-form
    0x207: "chx",
    0x208: "cwd",     # control for word insertion d-form
    0x209: "cwx",     # control for word insertion x-form (confirmed from addmat 0x413fff88)
    0x20A: "cdd",
    0x20B: "cdx",
}

# RI7 subset: these op11 values use the rB field as a 7-bit immediate
RI7_OPS = {0x18C, 0x194, 0x198, 0x204, 0x206, 0x208, 0x20A, 0x05B, 0x1DC, 0x1DD, 0x2AE, 0x2B6}


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
            if m in ("br", "bra", "brasl", "brsl", "brz", "brhz", "brnz", "brhnz"):
                target = self.addr + (self.I16 << 2)
                return f"{m}\t${rT}, {target:#x}"
            if m in ("lqr", "stqr"):
                # PC-relative: target = (addr + I16*4 + 4) & ~0xF
                target = (self.addr + self.I16 * 4 + 4) & ~0xF
                return f"{m}\t${rT}, {target:#010x}"
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
        return f"{m}\t${rT}, ${rA}, ${rB}  ; {w:#010x}"


# Unary RR instructions (rB field unused / set to 0 by assembler)
_RR_UNARY = {0x0CA, 0x0D8, 0x0D9, 0x1F4, 0x1F8}


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
    """
    n = len(data) // 4
    if limit is not None:
        n = min(n, limit)
    for i in range(n):
        addr = base_vaddr + i * 4
        word = struct.unpack_from(">I", data, i * 4)[0]
        yield decode_spu_word(addr, word)


def frequency_report(data: bytes, base_vaddr: int = 0) -> str:
    """Return a mnemonic frequency table for coverage analysis."""
    counts: Counter = Counter()
    unknowns: Counter = Counter()
    for insn in disassemble_spu_text(data, base_vaddr):
        if insn.fmt == "unknown":
            op11 = (insn.word >> 21) & 0x7FF
            op8  = (insn.word >> 24) & 0xFF
            unknowns[f"op11={op11:#05x}/op8={op8:#04x}"] += 1
        else:
            counts[insn.mnemonic] += 1
    lines = ["=== SPU mnemonic frequency ==="]
    for mnem, cnt in counts.most_common(40):
        lines.append(f"  {mnem:16s} {cnt:5d}")
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
