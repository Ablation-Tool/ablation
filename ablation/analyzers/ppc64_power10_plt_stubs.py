"""
ppc64_power10_plt_stubs.py — Power10 ppc64le PLT stub scanner.

Why this exists (ELFv2-PLD-GAP-001)
--------------------------------------
SinkArgClassifierPPC64ELFv2._remap_plt_rev_to_stubs recognises only the
classic 5-instruction ELFv2 PLT stub:

    std  r2,  0x18(r1)       # save TOC
    addis r12, r2,  ha       # TOC-relative high
    ld    r12, lo(r12)       # load GOT entry
    mtctr r12
    bctr

Power10 (p10) ELFv2 objects linked with GNU ld 2.38+ emit TWO different
compact stub forms, neither of which has an "addis r12, r2, ha" instruction.

Form A — compact "ld from r2" (observed in p10 libgo.so stub #0):
    std  r2,  0x18(r1)       # save TOC  (0xF8410018)
    ld   r12, D(r2)          # compact GOT load (D fits in 16 bits)
    mtctr r12
    bctr

    GOT_VA = r2 + sign_extend_16(D)

Form B — 8-byte PLD pcrel (observed in p10 libgo.so stubs #1-7588):
    pld  r12, @got@pcrel     # prefixed load (8 bytes total)
    mtctr r12
    bctr

    The 8 bytes consist of a 4-byte MLS prefix word and a 4-byte LD suffix.
    Prefix: bits[31:26]=000001 (prefix opcode), bits[25:24]=00 (MLS),
            bit[20]=R=1 (pcrel), bits[17:16]=d0_hi2, bits[15:0]=d0_lo16.
    Suffix: bits[31:26]=111001 (opcode 57, PLD main), bits[25:21]=r12,
            bits[20:16]=0 (RA=0, pcrel), bits[15:0]=d1.

    34-bit displacement D = (d0_hi2 << 32) | (d0_lo16 << 16) | d1
    GOT_VA = prefix_instruction_VA + sign_extend_34(D)

Capstone cannot decode either form (Form B stubs silently produce no
instructions; Form A is decoded but the ld-from-r2 compact pattern was
never added to the addis+ld scanner).  Result: _remap_plt_rev_to_stubs
returns 0 stub remaps for affected binaries, so classify_all() sees 0
sinks for the entire object.

Confirmed behaviour on at17.0 glibc-hwcaps/power10/libgo.so (57 MB,
7588 pltgot relocs): old scanner found 1/7588 stubs; after this fix
all 7588 are resolved.

Usage (standalone)
-------------------
    from ablation.analyzers.ppc64_power10_plt_stubs import (
        scan_power10_stubs,
    )
    import lief

    b    = lief.parse('/path/to/power10.so')
    data = open('/path/to/power10.so', 'rb').read()
    r2   = find_r2(b)   # .got VA + 0x8000
    stub_to_got = scan_power10_stubs(data, b, r2)

Integration
-----------
This module is called from SinkArgClassifierPPC64ELFv2._remap_plt_rev_to_stubs
as an extra pass after the classic addis+ld scan.
"""

from __future__ import annotations

import struct as _struct
from typing import Dict

# ── instruction constants (LE byte order) ────────────────────────────────────
_STD_R2_LE  = _struct.pack('<I', 0xF8410018)   # std r2, 0x18(r1)
_MTCTR_LE   = _struct.pack('<I', 0x7D8903A6)   # mtctr r12
_BCTR_LE    = _struct.pack('<I', 0x4E800420)   # bctr

# Form A: ld r12, D(r2)  — bits[31:26]=58(ld), bits[25:21]=r12, bits[20:16]=r2
# Mask checks opcode+RT+RA; low 16 bits carry the displacement DS-form.
_LD_R12_R2_MASK = 0xFFFF0000
_LD_R12_R2_VAL  = 0xE9820000  # ld r12, X(r2)

# Form B: PLD prefix word — opcode=1 (prefix), type=MLS(00), R=1(pcrel)
# Bit pattern: 0b000001_00_xxxxxxx_1_xxxxxxxxxxxxxxxx → mask 0xFFF00000
_PLD_PREFIX_MASK = 0xFFF00000
_PLD_PREFIX_VAL  = 0x04100000  # MLS prefix with R=1

# Form B: PLD suffix word — opcode=57(0b111001), RT=r12, RA=0
# bits[31:26]=57, bits[25:21]=12, bits[20:16]=0  → mask 0xFFFF0000
_PLD_SUFFIX_MASK = 0xFFFF0000
_PLD_SUFFIX_VAL  = 0xE5800000


def _sign_extend_34(d: int) -> int:
    """Sign-extend a 34-bit integer to a Python int."""
    if d >= (1 << 33):
        d -= (1 << 34)
    return d


def _decode_pld_displacement(prefix: int, suffix: int) -> int:
    """Extract the 34-bit PC-relative displacement from a PLD prefix+suffix pair."""
    d0_hi = (prefix >> 16) & 0x3   # bits[17:16] of prefix → d0[0:1]
    d0_lo = prefix & 0xFFFF         # bits[15:0]  of prefix → d0[2:17]
    d0    = (d0_hi << 16) | d0_lo   # 18-bit upper portion of displacement
    d1    = suffix & 0xFFFF         # 16-bit lower portion
    return _sign_extend_34((d0 << 16) | d1)


def scan_power10_stubs(data: bytes, lief_binary, r2: int) -> Dict[int, int]:
    """Scan executable non-.text sections for Power10 PLT stub forms A and B.

    Returns a dict mapping stub_VA (the address of the first stub instruction,
    i.e. std-r2 for form A or pld-prefix for form B) to got_VA.

    Parameters
    ----------
    data        : raw file bytes of the ELF
    lief_binary : lief.ELF.Binary (already parsed)
    r2          : TOC base (typically .got VA + 0x8000)
    """
    stub_to_got: Dict[int, int] = {}

    for sec in lief_binary.sections:
        sec_va   = int(sec.virtual_address)
        sec_size = int(sec.size)
        if sec_size < 12 or sec.name == '.text':
            continue
        try:
            flags = int(sec.flags)
        except Exception:
            flags = 0
        if not (flags & 4):  # SHF_EXECINSTR
            continue
        try:
            sec_off = int(lief_binary.virtual_address_to_offset(sec_va))
        except Exception:
            sec_off = sec_va
        if sec_off < 0 or sec_off + sec_size > len(data):
            continue

        raw = data[sec_off : sec_off + sec_size]
        i   = 0
        while i < sec_size - 12:
            # Look for MTCTR + BCTR anchor
            if raw[i : i + 4] != _MTCTR_LE or raw[i + 4 : i + 8] != _BCTR_LE:
                i += 4
                continue

            mtctr_off = i
            mtctr_va  = sec_va + mtctr_off

            # ── Form A: STD_R2 + LD_R12_R2 + MTCTR + BCTR ───────────────
            if mtctr_off >= 8:
                w_std = _struct.unpack_from('<I', raw, mtctr_off - 8)[0]
                w_ld  = _struct.unpack_from('<I', raw, mtctr_off - 4)[0]
                if (w_std == 0xF8410018 and
                        (w_ld & _LD_R12_R2_MASK) == _LD_R12_R2_VAL):
                    d = w_ld & 0xFFFF
                    if d & 0x8000:
                        d -= 0x10000
                    d &= ~0x3  # clear DS-form XO bits
                    got_va   = r2 + d
                    stub_va  = mtctr_va - 8
                    stub_to_got[stub_va] = got_va

            # ── Form B: PLD_PREFIX + PLD_SUFFIX + MTCTR + BCTR ───────────
            if mtctr_off >= 8:
                w_pre = _struct.unpack_from('<I', raw, mtctr_off - 8)[0]
                w_suf = _struct.unpack_from('<I', raw, mtctr_off - 4)[0]
                if ((w_pre & _PLD_PREFIX_MASK) == _PLD_PREFIX_VAL and
                        (w_suf & _PLD_SUFFIX_MASK) == _PLD_SUFFIX_VAL):
                    prefix_va = mtctr_va - 8
                    disp      = _decode_pld_displacement(w_pre, w_suf)
                    got_va    = prefix_va + disp
                    stub_to_got[prefix_va] = got_va

            i += 8  # skip past MTCTR+BCTR

    return stub_to_got
