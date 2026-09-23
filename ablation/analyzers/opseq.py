"""
opseq.py -- Shared opcode category sequence encoder.

Converts a function's disassembly to a List[int] where each integer is a
BinFuse category index (0-11). This is the common "time series" representation
used by MatrixProfileDiff, DTWMatcher, SAXIndex, and SubsequenceSearcher.

Category integers (CAT_INDEX):
  0  ARITHMETIC_OP     add/sub/mul/div/inc/dec/neg
  1  DATA_TRANSFER_OP  mov/lea/push/pop/xchg/ldr/str
  2  COMPARISON_OP     cmp/test/cmn/tst/fcmp
  3  LOGIC_OP          and/or/xor/not/eor/bic
  4  BIT_SHIFT_OP      shl/shr/sar/rol/ror/lsl/lsr
  5  UNCONDITIONAL_OP  jmp/call/ret/bl/br/blr
  6  CONDITIONAL_OP    je/jne/jz/beq/bne/cbz/cbnz
  7  MEMORY_MGMT_OP    rep/stosb/movsb/nop/prefetch
  8  PROCESSOR_STATE_OP pushf/cpuid/rdtsc/mrs/msr/svc
  9  SYNCHRONIZATION_OP lock/cmpxchg/stlr/ldar/dmb
 10  VECTOR_MGMT_OP    vpaddb/pshufb/ld1/fld/eor3
 11  OTHER_OP          anything not in above categories
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

# ── category integer map ───────────────────────────────────────────────────────

CAT_INDEX: Dict[str, int] = {
    'ARITHMETIC_OP': 0,
    'DATA_TRANSFER_OP': 1,
    'COMPARISON_OP': 2,
    'LOGIC_OP': 3,
    'BIT_SHIFT_OP': 4,
    'UNCONDITIONAL_OP': 5,
    'CONDITIONAL_OP': 6,
    'MEMORY_MGMT_OP': 7,
    'PROCESSOR_STATE_OP': 8,
    'SYNCHRONIZATION_OP': 9,
    'VECTOR_MGMT_OP': 10,
    'OTHER_OP': 11,
}
NUM_CATS = 12  # 0..11
CAT_NAMES = [k for k, v in sorted(CAT_INDEX.items(), key=lambda x: x[1])]

# Build mnemonic -> category integer table (shared with semantic_search but
# kept independent to avoid circular imports)
_MNEMONIC_TO_CAT: Dict[str, int] = {}

def _build_table() -> None:
    arithmetic = [
        'add','sub','mul','imul','div','idiv','inc','dec','neg','adc','sbb',
        'madd','msub','fadd','fsub','fmul','fdiv','fadds','fmuls','fmulx',
        'adds','subs','umull','smull','umull2','smull2','umlal','smlal',
        'udiv','sdiv','umulh','smulh','ucvtf','scvtf','fcvtzu','fcvtzs',
        'fnmadd','fnmsub','fnmul',
    ]
    data_transfer = [
        'mov','movq','movd','movdqu','movdqa','movaps','movups','movss','movsd',
        'vmovdqu','vmovdqa','vmovaps','vmovups',
        'lea','push','pop','xchg','bswap','cbw','cwde','cdqe','cwd','cdq','cqo',
        'ldr','str','ldp','stp','ldur','stur','ldrb','strb','ldrh','strh',
        'ldrsh','ldrsb','ldrsw','movz','movk','movn','adr','adrp',
        'stmfd','ldmfd','stmia','ldmia','stm','ldm','vpop','vpush',
        'fmov','ins','dup','ext','zip1','zip2','trn1','trn2',
        'movsx','movsxd','movzx',
    ]
    comparison = [
        'cmp','test','cmn','tst','fcmp','fccmp','ucomisd','ucomiss','comiss','comisd',
    ]
    logic = [
        'and','or','xor','not','andn','orn','eor','bic','eon','mvn','orr',
        'pand','por','pxor','pandn','vpand','vpor','vpxor','vpandn',
    ]
    bitshift = [
        'shl','shr','sar','sal','rol','ror','shld','shrd','rcl','rcr',
        'lsl','lsr','asr','rrx','lsls','lsrs','asrs','rors',
    ]
    unconditional = [
        'jmp','b','bl','call','ret','retn','bx','blx','br','blr',
        'jmpq','callq','retq','leave','enter','hlt',
    ]
    conditional = [
        'je','jne','jz','jnz','jl','jg','jle','jge','ja','jb','jae','jbe',
        'jns','js','jo','jno','jp','jnp','jpe','jpo','jcxz','jecxz','jrcxz',
        'beq','bne','blt','bgt','ble','bge','blo','bhi','bls','bhs','bpl','bmi','bvs','bvc',
        'cbnz','cbz','tbnz','tbz',
    ]
    memory_mgmt = [
        'rep','repe','repne','repz','repnz',
        'stosb','stosw','stosd','stosq','movsb','movsw','movsq',
        'lodsb','lodsw','lodsd','lodsq','scasb','scasw','scasd','scasq',
        'prefetch','prefetchnta','prefetcht0','prefetcht1','prefetcht2',
        'clflush','clflushopt','clwb','nop','nopl','nopw',
        'pause','mfence','sfence','lfence',
    ]
    processor_state = [
        'pushf','popf','pushfd','popfd','pushfq','popfq',
        'lahf','sahf','cpuid','rdtsc','rdtscp','rdmsr','wrmsr',
        'mrs','msr','svc','hvc','smc','cli','sti','cld','std','stc','clc','cmc',
    ]
    synchronization = [
        'lock','xadd','cmpxchg','cmpxchg8b','cmpxchg16b',
        'dmb','dsb','isb','stlr','ldar','stlrb','ldarb','stlrh','ldarh',
        'stlxr','ldaxr','stlxrb','ldaxrb','stlxrh','ldaxrh','prfm',
    ]
    vector = [
        'vpaddb','vpaddw','vpaddd','vpaddq','vpsubb','vpsubw','vpsubd','vpsubq',
        'paddq','psubq','paddb','psubb','paddw','psubw','paddd','psubd',
        'pmullw','pmulld','pmuludq','pmulhw','pmulhuw','vpmullw','vpmulld','vpmuludq',
        'punpcklbw','punpcklwd','punpckldq','punpcklqdq',
        'punpckhbw','punpckhwd','punpckhdq','punpckhqdq',
        'pshufb','pshufd','pshufhw','pshuflw','vpshufb','vpshufd',
        'vzeroupper','vzeroall','pmovmskb','vpmovmskb','movmskpd','movmskps',
        'pcmpeqb','pcmpeqw','pcmpeqd','pcmpeqq','vpcmpeqb','vpcmpeqw','vpcmpeqd',
        'fld','fst','fstp','fild','fist','fistp','fxch',
        'ld1','ld2','ld3','ld4','st1','st2','st3','st4','eor3','bcax','sm3','sm4',
    ]
    table = [
        ('ARITHMETIC_OP', arithmetic),
        ('DATA_TRANSFER_OP', data_transfer),
        ('COMPARISON_OP', comparison),
        ('LOGIC_OP', logic),
        ('BIT_SHIFT_OP', bitshift),
        ('UNCONDITIONAL_OP', unconditional),
        ('CONDITIONAL_OP', conditional),
        ('MEMORY_MGMT_OP', memory_mgmt),
        ('PROCESSOR_STATE_OP', processor_state),
        ('SYNCHRONIZATION_OP', synchronization),
        ('VECTOR_MGMT_OP', vector),
    ]
    for cat_name, mnemonics in table:
        cat_id = CAT_INDEX[cat_name]
        for mn in mnemonics:
            _MNEMONIC_TO_CAT[mn.lower()] = cat_id

_build_table()
OTHER_CAT = CAT_INDEX['OTHER_OP']


def mnemonic_to_cat(mn: str) -> int:
    """Map a mnemonic string to its category integer (11 = OTHER_OP)."""
    return _MNEMONIC_TO_CAT.get(mn.lower(), OTHER_CAT)


# ── ELF minimal helpers ────────────────────────────────────────────────────────

def _read_u64(data: bytes, off: int) -> int:
    return struct.unpack_from('<Q', data, off)[0]

def _read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]

def _read_i32(data: bytes, off: int) -> int:
    return struct.unpack_from('<i', data, off)[0]


def _text_section(data: bytes) -> Tuple[int, int, int]:
    """Returns (file_offset, va, size) of the first executable section."""
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return (0, 0, len(data))
    e_shoff = _read_u64(data, 0x28)
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    if e_shoff == 0 or e_shnum == 0:
        return (0, 0, len(data))

    strtab_sh = data[e_shoff + e_shstrndx * e_shentsize:
                     e_shoff + e_shstrndx * e_shentsize + e_shentsize]
    strtab_off = _read_u64(strtab_sh, 0x18)

    def sh_name(sh_data: bytes) -> str:
        name_off = _read_u32(sh_data, 0)
        try:
            end = data.index(b'\x00', strtab_off + name_off)
            return data[strtab_off + name_off:end].decode('ascii', errors='ignore')
        except ValueError:
            return ''

    for i in range(e_shnum):
        sh = data[e_shoff + i * e_shentsize: e_shoff + (i + 1) * e_shentsize]
        if len(sh) < 64:
            continue
        try:
            name = sh_name(sh)
        except Exception:
            continue
        if name == '.text':
            return (_read_u64(sh, 0x18), _read_u64(sh, 0x10), _read_u64(sh, 0x20))

    # Fallback: first PROGBITS + EXECINSTR
    for i in range(e_shnum):
        sh = data[e_shoff + i * e_shentsize: e_shoff + (i + 1) * e_shentsize]
        if len(sh) < 64:
            continue
        sh_type = _read_u32(sh, 4)
        sh_flags = _read_u64(sh, 8)
        if sh_type == 1 and (sh_flags & 4):
            return (_read_u64(sh, 0x18), _read_u64(sh, 0x10), _read_u64(sh, 0x20))

    return (0, 0, len(data))


# ── encoder ───────────────────────────────────────────────────────────────────

class OpSeqEncoder:
    """
    Converts a binary function to a List[int] opcode category sequence.

    The sequence is the "time series" representation used by all 4 TS analysis
    modules. Each integer is a BinFuse category index (0 = ARITHMETIC_OP, ...,
    11 = OTHER_OP).

    Usage:
        enc = OpSeqEncoder('/path/to/binary')
        seq = enc.encode_va(func_va=0x1000, end_va=0x1200)
        # -> [1, 1, 5, 2, 6, 1, 5, ...]  (DATA_TRANSFER, ..., COMPARISON, CONDITIONAL, ...)
    """

    def __init__(self, binary_path: str):
        self.path = binary_path
        self._data = Path(binary_path).read_bytes()
        self._md = Cs(CS_ARCH_X86, CS_MODE_64)
        self._text_off, self._text_va, self._text_size = _text_section(self._data)

    @classmethod
    def from_path(cls, binary_path: str) -> "OpSeqEncoder":
        return cls(binary_path)

    def encode_va(
        self,
        func_va: int,
        end_va: int = 0,
        max_insn: int = 512,
    ) -> List[int]:
        """
        Disassemble from func_va to end_va and return category integer sequence.

        end_va=0: use max_insn instructions as limit.
        """
        if end_va > func_va:
            size = min(end_va - func_va, max_insn * 16)
        else:
            size = max_insn * 8
        code = self._read_va(func_va, size)
        if not code:
            return []
        seq = []
        for insn in self._md.disasm(code, func_va):
            if end_va > 0 and insn.address >= end_va:
                break
            seq.append(mnemonic_to_cat(insn.mnemonic))
            if len(seq) >= max_insn:
                break
        return seq

    def encode_range(self, va: int, size: int) -> List[int]:
        """Encode exactly 'size' bytes starting at va."""
        code = self._read_va(va, size)
        if not code:
            return []
        return [mnemonic_to_cat(insn.mnemonic) for insn in self._md.disasm(code, va)]

    def _read_va(self, va: int, size: int) -> bytes:
        off = va - self._text_va + self._text_off
        if off < 0 or off + size > len(self._data):
            return b''
        return self._data[off:off + size]


def seq_to_str(seq: List[int]) -> str:
    """Compact human-readable sequence representation."""
    abbrev = {0:'A',1:'D',2:'C',3:'L',4:'S',5:'U',6:'J',7:'M',8:'P',9:'Y',10:'V',11:'?'}
    return ''.join(abbrev.get(c, '?') for c in seq)


def seq_histogram(seq: List[int]) -> List[float]:
    """Fraction of each category in sequence (length-normalized histogram)."""
    if not seq:
        return [0.0] * NUM_CATS
    counts = [0] * NUM_CATS
    for c in seq:
        if 0 <= c < NUM_CATS:
            counts[c] += 1
    n = len(seq)
    return [counts[i] / n for i in range(NUM_CATS)]
