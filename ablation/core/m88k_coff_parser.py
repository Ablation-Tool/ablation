"""
m88k BCS COFF parser — Motorola 88000 Binary Compatibility Standard.

Format differences from standard COFF:
  - magic = 0x016d ("88K BCS")
  - Section headers are 44 bytes (nreloc and nlnno are 4 bytes each, not 2)
  - Big-endian throughout
  - No loader section; stripped binaries have nsyms=0

Function detection heuristic:
  op=0x09 (st), rd=r1, rs=r31 — save link register to stack frame.
  This is the canonical non-leaf function prologue on m88k BCS.
  (Caller pre-allocates callee frame per §3 of the BCS ABI, so there is
  no frame-pointer decrement at function entry to search for instead.)

Call instruction (BSR, op=0x32):
  [110010][rd:5][rs:5][disp16:16]
  target = PC + 4 + sign_extend(disp16) * 4
  (16-bit word offset, not 26-bit — empirically confirmed on moto_gen)

Usage::

    from ablation.core.m88k_coff_parser import parse
    mb = parse('/path/to/m88k_binary')
    print(mb.arch, mb.entry)
    for fn_va in mb.func_starts:
        print(hex(fn_va))
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional

M88K_BCS_MAGIC = 0x016d

# COFF file header: magic(2) nscns(2) timdat(4) symptr(4) nsyms(4) opthdr(2) flags(2)
_FILHDR_FMT = '>HHiiiHH'
_FILHDR_SIZE = 20

# Optional (a.out) header: magic(2) vstamp(2) tsize(4) dsize(4) bsize(4) entry(4) text_start(4) data_start(4)
_OPTHDR_FMT = '>HHiiiiii'
_OPTHDR_SIZE = 28

# 88K BCS section header: 44 bytes (nreloc/nlnno are 4-byte, not 2-byte)
_SCNHDR_FMT = '>8sIIIIIIIII'
_SCNHDR_SIZE = 44  # 8+4+4+4+4+4+4+4+4+4


@dataclass
class M88kSection:
    name:   str
    vaddr:  int
    size:   int
    scnptr: int
    flags:  int
    data:   bytes = field(repr=False)

    def contains_va(self, va: int) -> bool:
        return self.vaddr <= va < self.vaddr + self.size

    @property
    def vend(self) -> int:
        return self.vaddr + self.size


@dataclass
class M88kBinary:
    path:       str
    arch:       str           # always 'm88k'
    entry:      int
    text_start: int
    data_start: int
    sections:   List[M88kSection] = field(default_factory=list)
    func_starts: List[int]        = field(default_factory=list)

    @property
    def text(self) -> Optional[M88kSection]:
        for s in self.sections:
            if s.name == '.text':
                return s
        return None

    @property
    def data(self) -> Optional[M88kSection]:
        for s in self.sections:
            if s.name == '.data':
                return s
        return None


def _parse_sections(data: bytes, nscns: int, base_off: int) -> List[M88kSection]:
    sections: List[M88kSection] = []
    off = base_off
    for _ in range(nscns):
        if off + _SCNHDR_SIZE > len(data):
            break
        raw_name, paddr, vaddr, size, scnptr, relptr, lnnoptr, nreloc, nlnno, flags = \
            struct.unpack_from(_SCNHDR_FMT, data, off)
        name = raw_name.rstrip(b'\x00').decode('ascii', errors='replace')
        sec_data = b''
        if scnptr and size and scnptr + size <= len(data):
            sec_data = data[scnptr: scnptr + size]
        sections.append(M88kSection(name=name, vaddr=vaddr, size=size,
                                     scnptr=scnptr, flags=flags, data=sec_data))
        off += _SCNHDR_SIZE
    return sections


def _scan_func_starts(tsec: M88kSection) -> List[int]:
    """Scan text section for non-leaf function prologues.

    Pattern: op=0x09, rd=r1, rs=r31 — 'st r1, r31, imm16'
    This saves the return address (r1) to the caller-allocated stack frame,
    which is the first instruction of any non-leaf function in m88k BCS.

    The top 16 bits encode op/rd/rs: (9<<10)|(1<<5)|31 = 0x243F.
    """
    starts: List[int] = []
    text_data = tsec.data
    text_va = tsec.vaddr
    n_words = len(text_data) // 4
    for i in range(n_words):
        w = struct.unpack_from('>I', text_data, i * 4)[0]
        if (w >> 16) == 0x243F:
            starts.append(text_va + i * 4)
    return starts


def _scan_bsr_targets(tsec: M88kSection) -> List[int]:
    """Scan for BSR (op=0x32) call targets within the text section.

    Format: [110010][rd:5][rs:5][disp16:16]
    target = insn_va + 4 + sign_extend(disp16) * 4
    """
    targets: List[int] = []
    text_data = tsec.data
    text_va = tsec.vaddr
    n_words = len(text_data) // 4
    for i in range(n_words):
        w = struct.unpack_from('>I', text_data, i * 4)[0]
        if (w >> 26) != 0x32:
            continue
        disp = w & 0xFFFF
        if disp & 0x8000:
            disp -= 0x10000
        target = text_va + i * 4 + 4 + disp * 4
        if tsec.contains_va(target) and (target & 3) == 0:
            targets.append(target)
    return targets


def parse(path: str, data: Optional[bytes] = None) -> M88kBinary:
    """Parse an m88k BCS COFF binary.

    Raises ValueError if magic does not match M88K_BCS_MAGIC.
    """
    if data is None:
        with open(path, 'rb') as f:
            data = f.read()

    if len(data) < _FILHDR_SIZE:
        raise ValueError(f"File too small: {len(data)} bytes")

    magic, nscns, timdat, symptr, nsyms, opthdr_sz, flags = \
        struct.unpack_from(_FILHDR_FMT, data, 0)

    if magic != M88K_BCS_MAGIC:
        raise ValueError(f"Not an m88k BCS binary: magic={hex(magic)}")

    entry = 0
    text_start = 0
    data_start = 0
    if opthdr_sz >= _OPTHDR_SIZE:
        _, _, tsize, dsize, bsize, entry, text_start, data_start = \
            struct.unpack_from(_OPTHDR_FMT, data, _FILHDR_SIZE)

    sections_off = _FILHDR_SIZE + opthdr_sz
    sections = _parse_sections(data, nscns, sections_off)

    mb = M88kBinary(
        path=path,
        arch='m88k',
        entry=entry,
        text_start=text_start,
        data_start=data_start,
        sections=sections,
    )

    tsec = mb.text
    if tsec and tsec.data:
        prologue_starts = set(_scan_func_starts(tsec))
        bsr_targets = set(_scan_bsr_targets(tsec))
        # Union: non-leaf prologues + BSR targets not caught by prologue scan
        # (BSR targets without st-r1 prologues are leaf functions or tail-call sites)
        all_starts = prologue_starts | (bsr_targets - prologue_starts)
        mb.func_starts = sorted(all_starts)

    return mb
