"""ISA and ABI model for x86 / x86-64.

Every table encodes a fact from the Intel SDM or the relevant psABI (SysV
AMD64, Microsoft x64, i386 SysV/cdecl). Mode-specific facts are expressed as
a shared base plus explicit per-mode deltas.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Optional, Tuple


class Mode(str, Enum):
    X86 = "x86"    # IA-32, 32-bit
    X64 = "x64"    # x86-64 long mode

    @property
    def bits(self) -> int:
        return 32 if self is Mode.X86 else 64

    @property
    def ptr_bytes(self) -> int:
        return self.bits // 8

    @property
    def sp(self) -> str:
        return "esp" if self is Mode.X86 else "rsp"

    @property
    def bp(self) -> str:
        return "ebp" if self is Mode.X86 else "rbp"

    @property
    def ip(self) -> str:
        return "eip" if self is Mode.X86 else "rip"


class Abi(str, Enum):
    SYSV64 = "sysv64"    # Linux/BSD/macOS x86-64
    WIN64 = "win64"      # Microsoft x64
    CDECL32 = "cdecl32"  # i386 SysV / cdecl (args on stack)

    @staticmethod
    def default_for(mode: Mode) -> "Abi":
        return Abi.SYSV64 if mode is Mode.X64 else Abi.CDECL32


# --------------------------------------------------------------------------
# Register families and sub-register aliasing (SDM Vol.1 §3.4.1, §3.4.1.1)
# --------------------------------------------------------------------------
# name -> (family, low_bit, width_bits). The family is the widest register the
# name aliases (rax in 64-bit mode, eax in 32-bit mode). ah/bh/ch/dh sit at
# bit 8. In 64-bit mode a 32-bit write zero-extends to 64 (SDM Vol.1 §3.4.1.1);
# 8/16-bit writes preserve the untouched bits.

_GPR64: Dict[str, Tuple[str, int, int]] = {}
for _b in ("a", "b", "c", "d"):
    _GPR64[f"r{_b}x"] = (f"r{_b}x", 0, 64)
    _GPR64[f"e{_b}x"] = (f"r{_b}x", 0, 32)
    _GPR64[f"{_b}x"]  = (f"r{_b}x", 0, 16)
    _GPR64[f"{_b}l"]  = (f"r{_b}x", 0, 8)
    _GPR64[f"{_b}h"]  = (f"r{_b}x", 8, 8)
for _n in ("sp", "bp", "si", "di"):
    _GPR64[f"r{_n}"] = (f"r{_n}", 0, 64)
    _GPR64[f"e{_n}"] = (f"r{_n}", 0, 32)
    _GPR64[_n]        = (f"r{_n}", 0, 16)
    _GPR64[f"{_n}l"] = (f"r{_n}", 0, 8)
for _i in range(8, 16):
    _GPR64[f"r{_i}"]  = (f"r{_i}", 0, 64)
    _GPR64[f"r{_i}d"] = (f"r{_i}", 0, 32)
    _GPR64[f"r{_i}w"] = (f"r{_i}", 0, 16)
    _GPR64[f"r{_i}b"] = (f"r{_i}", 0, 8)
    _GPR64[f"r{_i}l"] = (f"r{_i}", 0, 8)
_GPR64["rip"] = ("rip", 0, 64)
_GPR64["eip"] = ("rip", 0, 32)

_GPR32: Dict[str, Tuple[str, int, int]] = {}
for _b in ("a", "b", "c", "d"):
    _GPR32[f"e{_b}x"] = (f"e{_b}x", 0, 32)
    _GPR32[f"{_b}x"]  = (f"e{_b}x", 0, 16)
    _GPR32[f"{_b}l"]  = (f"e{_b}x", 0, 8)
    _GPR32[f"{_b}h"]  = (f"e{_b}x", 8, 8)
for _n in ("sp", "bp", "si", "di"):
    _GPR32[f"e{_n}"] = (f"e{_n}", 0, 32)
    _GPR32[_n]        = (f"e{_n}", 0, 16)
_GPR32["eip"] = ("eip", 0, 32)

_VEC: Dict[str, Tuple[str, int, int]] = {}
for _i in range(32):
    _VEC[f"xmm{_i}"] = (f"xmm{_i}", 0, 128)
    _VEC[f"ymm{_i}"] = (f"xmm{_i}", 0, 256)
    _VEC[f"zmm{_i}"] = (f"xmm{_i}", 0, 512)
for _i in range(8):
    _VEC[f"mm{_i}"]    = (f"mm{_i}", 0, 64)
    _VEC[f"st{_i}"]    = (f"st{_i}", 0, 80)
    _VEC[f"st({_i})"]  = (f"st{_i}", 0, 80)
    _VEC[f"k{_i}"]     = (f"k{_i}", 0, 64)

SEGMENTS: FrozenSet[str] = frozenset({"cs", "ds", "es", "fs", "gs", "ss"})
FLAGS = "eflags"
_MISC = {FLAGS: (FLAGS, 0, 64), "rflags": (FLAGS, 0, 64), "flags": (FLAGS, 0, 16)}


@dataclass(frozen=True)
class RegInfo:
    name: str
    family: str
    low: int
    width: int

    @property
    def mask(self) -> int:
        return (1 << self.width) - 1


def reg_table(mode: Mode) -> Dict[str, Tuple[str, int, int]]:
    base = _GPR64 if mode is Mode.X64 else _GPR32
    return {**base, **_VEC, **_MISC, **{s: (s, 0, 16) for s in SEGMENTS}}


def reg_info(name: str, mode: Mode) -> Optional[RegInfo]:
    n = name.strip().lower()
    t = reg_table(mode).get(n)
    if t is None:
        return None
    return RegInfo(n, *t)


def is_reg(name: str, mode: Mode) -> bool:
    return reg_info(name, mode) is not None


# --------------------------------------------------------------------------
# Calling conventions
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class AbiModel:
    abi: Abi
    mode: Mode
    caller_saved: FrozenSet[str]
    callee_saved: FrozenSet[str]
    arg_regs: Tuple[str, ...]
    fp_arg_regs: Tuple[str, ...]
    ret_regs: Tuple[str, ...]
    fp_ret_regs: Tuple[str, ...]
    stack_args: bool
    shadow_space: int   # bytes caller reserves above return address (Win64 = 32)


_XMM_ALL = frozenset(f"xmm{i}" for i in range(16))

_ABIS = {
    # SysV AMD64 psABI §3.2.1 / §3.2.3
    Abi.SYSV64: AbiModel(
        Abi.SYSV64, Mode.X64,
        caller_saved=frozenset({"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}) | _XMM_ALL,
        callee_saved=frozenset({"rbx", "rbp", "r12", "r13", "r14", "r15", "rsp"}),
        arg_regs=("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
        fp_arg_regs=tuple(f"xmm{i}" for i in range(8)),
        ret_regs=("rax", "rdx"),
        fp_ret_regs=("xmm0", "xmm1"),
        stack_args=True, shadow_space=0,
    ),
    # Microsoft x64 calling convention
    Abi.WIN64: AbiModel(
        Abi.WIN64, Mode.X64,
        caller_saved=frozenset({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}) | frozenset(f"xmm{i}" for i in range(6)),
        callee_saved=frozenset({"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15", "rsp"}) | frozenset(f"xmm{i}" for i in range(6, 16)),
        arg_regs=("rcx", "rdx", "r8", "r9"),
        fp_arg_regs=("xmm0", "xmm1", "xmm2", "xmm3"),
        ret_regs=("rax",),
        fp_ret_regs=("xmm0",),
        stack_args=True, shadow_space=32,
    ),
    # i386 SysV psABI / cdecl
    Abi.CDECL32: AbiModel(
        Abi.CDECL32, Mode.X86,
        caller_saved=frozenset({"eax", "ecx", "edx"}) | frozenset(f"xmm{i}" for i in range(8)),
        callee_saved=frozenset({"ebx", "esi", "edi", "ebp", "esp"}),
        arg_regs=(),
        fp_arg_regs=(),
        ret_regs=("eax", "edx"),
        fp_ret_regs=("xmm0",),
        stack_args=True, shadow_space=0,
    ),
}


def abi_for(abi: Abi) -> AbiModel:
    return _ABIS[abi]


# --------------------------------------------------------------------------
# Linux system calls — numbers differ between i386 and x86-64
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SyscallModel:
    nr_reg: str
    arg_regs: Tuple[str, ...]
    ret_reg: str
    clobbered: FrozenSet[str]
    numbers: Dict[int, str]


# arch/x86/entry/syscalls/syscall_64.tbl
_SYS64 = SyscallModel(
    nr_reg="rax", arg_regs=("rdi", "rsi", "rdx", "r10", "r8", "r9"), ret_reg="rax",
    clobbered=frozenset({"rcx", "r11"}),
    numbers={0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 8: "lseek",
             9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction", 16: "ioctl",
             17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev", 32: "dup", 33: "dup2",
             39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
             49: "bind", 50: "listen", 56: "clone", 57: "fork", 59: "execve", 60: "exit", 62: "kill",
             72: "fcntl", 74: "fsync", 79: "getcwd", 89: "readlink", 231: "exit_group", 257: "openat",
             262: "newfstatat", 267: "readlinkat", 288: "accept4", 318: "getrandom"},
)
# arch/x86/entry/syscalls/syscall_32.tbl (int 0x80 / sysenter)
_SYS32 = SyscallModel(
    nr_reg="eax", arg_regs=("ebx", "ecx", "edx", "esi", "edi", "ebp"), ret_reg="eax",
    clobbered=frozenset(),
    numbers={1: "exit", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve", 19: "lseek",
             20: "getpid", 37: "kill", 41: "dup", 54: "ioctl", 55: "fcntl", 63: "dup2", 90: "mmap",
             91: "munmap", 102: "socketcall", 118: "fsync", 120: "clone", 125: "mprotect",
             145: "readv", 146: "writev", 180: "pread64", 181: "pwrite64", 183: "getcwd",
             192: "mmap2", 252: "exit_group", 295: "openat", 305: "readlinkat", 355: "getrandom",
             359: "socket", 362: "connect", 364: "accept4", 371: "recvfrom", 369: "bind"},
)


def syscall_model(mode: Mode) -> SyscallModel:
    return _SYS64 if mode is Mode.X64 else _SYS32


INPUT_SYSCALLS = {"read", "readv", "pread64", "recvfrom", "getcwd", "readlink", "readlinkat", "getrandom"}


# --------------------------------------------------------------------------
# Mnemonic normalization
# --------------------------------------------------------------------------

PREFIXES = frozenset({
    "rep", "repe", "repz", "repne", "repnz", "lock", "notrack", "bnd", "data16", "addr32",
    "xacquire", "xrelease", "cs", "ds", "es", "fs", "gs", "ss",
})

_CC_ALIAS = {
    "z": "e", "nz": "ne", "nbe": "a", "nb": "ae", "nc": "ae", "c": "b", "nae": "b", "na": "be",
    "nle": "g", "nl": "ge", "nge": "l", "ng": "le", "pe": "p", "po": "np",
}
_CC_ALL = frozenset({
    "e", "ne", "a", "ae", "b", "be", "g", "ge", "l", "le", "s", "ns", "o", "no", "p", "np",
    "z", "nz", "nbe", "nb", "nc", "c", "nae", "na", "nle", "nl", "nge", "ng", "pe", "po",
})

_ATT_MNEM = {
    "cltq": "cdqe", "cltd": "cdq", "cqto": "cqo", "cwtl": "cwde", "cbtw": "cbw", "cwtd": "cwd",
    "movslq": "movsxd", "movsbq": "movsx", "movswq": "movsx", "movsbl": "movsx", "movswl": "movsx",
    "movsbw": "movsx", "movzbq": "movzx", "movzwq": "movzx", "movzbl": "movzx", "movzwl": "movzx",
    "movzbw": "movzx", "retq": "ret", "retl": "ret", "callq": "call", "calll": "call",
    "leaveq": "leave", "pushq": "push", "pushl": "push", "popq": "pop", "popl": "pop",
    "iretq": "iret", "lretq": "retf", "jmpq": "jmp", "ljmp": "jmp", "lcall": "call",
}
_SUFFIXABLE = frozenset({
    "mov", "add", "sub", "and", "or", "xor", "cmp", "test", "lea", "inc", "dec", "neg", "not",
    "shl", "sal", "shr", "sar", "rol", "ror", "imul", "mul", "div", "idiv", "adc", "sbb",
    "push", "pop", "movs", "stos", "lods", "cmps", "scas", "xchg", "cmpxchg", "xadd", "bt", "bts",
    "btr", "btc", "bsf", "bsr", "popcnt", "lzcnt", "tzcnt", "cvtsi2sd", "cvtsi2ss", "movabs",
    "nop", "leave", "ret", "call", "jmp", "int", "sete", "setne",
})


def normalize_mnemonic(m: str) -> "tuple[tuple[str, ...], str]":
    """Return ``(prefixes, canonical_mnemonic)``."""
    parts = m.strip().lower().split()
    prefixes = tuple(p for p in parts[:-1] if p in PREFIXES)
    base = parts[-1] if parts else ""
    base = _ATT_MNEM.get(base, base)
    if base not in _KNOWN and base[:-1] in _SUFFIXABLE and base[-1] in "bwlq":
        base = base[:-1]
    for stem in ("j", "cmov", "set"):
        if base.startswith(stem) and base[len(stem):] in _CC_ALL:
            cc = base[len(stem):]
            return prefixes, stem + _CC_ALIAS.get(cc, cc)
    return prefixes, base


# --------------------------------------------------------------------------
# Mnemonic classes
# --------------------------------------------------------------------------

COPY = frozenset({
    "mov", "movabs", "movd", "movq", "movaps", "movups", "movapd", "movupd", "movdqa", "movdqu",
    "vmovaps", "vmovups", "vmovapd", "vmovupd", "vmovdqa", "vmovdqu", "vmovd", "vmovq",
    "movss", "movsd", "vmovss", "vmovsd", "lddqu", "movnti", "movntdq", "movntps", "kmovq", "kmovd",
})
ZEXT_COPY = frozenset({"movzx"})
SEXT_COPY = frozenset({"movsx", "movsxd"})
COND_COPY_STEM = "cmov"
SWAP = frozenset({"xchg"})
LEA = frozenset({"lea"})
PUSH = frozenset({"push"})
POP = frozenset({"pop"})
ZERO_IDIOM = frozenset({"xor", "sub", "pxor", "xorps", "xorpd", "vpxor", "vxorps", "vxorpd", "sbb"})

ALU2 = frozenset({
    "add", "adc", "sub", "sbb", "and", "or", "xor", "imul", "shl", "sal", "shr", "sar",
    "rol", "ror", "rcl", "rcr", "shld", "shrd", "bt", "bts", "btr", "btc", "xadd", "cmpxchg",
    "andn", "bextr", "bzhi", "pdep", "pext", "sarx", "shlx", "shrx", "rorx", "adcx", "adox",
    "paddd", "paddq", "psubd", "pand", "por", "pxor", "pshufd", "punpcklbw", "punpckldq",
    "addss", "addsd", "subss", "subsd", "mulss", "mulsd", "divss", "divsd", "sqrtsd", "sqrtss",
    "addps", "addpd", "mulps", "mulpd", "cvtsi2sd", "cvtsi2ss", "cvttsd2si", "cvttss2si",
    "cvtsd2si", "cvtss2si", "cvtsd2ss", "cvtss2sd", "pcmpeqb", "pmovmskb", "pminub", "pmaxub",
    "ucomisd", "ucomiss", "comisd", "comiss", "pshufb", "palignr", "pslldq", "psrldq",
    "vpaddd", "vpand", "vpor", "vpcmpeqb", "vpmovmskb", "vpshufb", "vpminub", "vptest",
    "andps", "andpd", "orps", "orpd", "andnps", "andnpd", "unpcklps", "unpcklpd", "shufps",
    "bsf", "bsr", "lzcnt", "tzcnt", "popcnt", "crc32", "bswap",
})
ALU1 = frozenset({"inc", "dec", "neg", "not", "bswap"})
SHIFT = frozenset({"shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr", "shlx", "shrx", "sarx", "rorx"})
FLAGS_ONLY = frozenset({"cmp", "test", "ucomisd", "ucomiss", "comisd", "comiss", "ptest", "vptest", "bt"})
WIDEN_RAX = frozenset({"cbw", "cwde", "cdqe"})
WIDEN_RDX = frozenset({"cwd", "cdq", "cqo"})
MUL_IMPLICIT = frozenset({"mul", "imul"})
DIV_IMPLICIT = frozenset({"div", "idiv"})
STRING = frozenset({
    "movsb", "movsw", "movsd", "movsq", "stosb", "stosw", "stosd", "stosq",
    "lodsb", "lodsw", "lodsd", "lodsq", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
    "scasb", "scasw", "scasd", "scasq", "movs", "stos", "lods", "cmps", "scas",
})
CALL = frozenset({"call"})
JMP = frozenset({"jmp"})
RET = frozenset({"ret", "retn", "retf", "iret", "iretd", "iretq"})
LOOP = frozenset({"loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz"})
SYSCALL = frozenset({"syscall", "sysenter", "int"})
CONST = frozenset({
    "rdtsc", "rdtscp", "cpuid", "rdrand", "rdseed", "lahf", "sahf",
    "pushf", "pushfq", "popf", "popfq",
})
NOP = frozenset({
    "nop", "endbr64", "endbr32", "hlt", "pause", "mfence", "lfence", "sfence", "clc", "stc",
    "cld", "std", "cmc", "ud2", "int3", "leave", "enter", "fwait", "wait", "vzeroupper", "vzeroall",
    "prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta", "clflush", "cwd", "emms",
})

_KNOWN = (
    COPY | ZEXT_COPY | SEXT_COPY | SWAP | LEA | PUSH | POP | ALU2 | ALU1 | FLAGS_ONLY |
    WIDEN_RAX | WIDEN_RDX | MUL_IMPLICIT | DIV_IMPLICIT | STRING | CALL | JMP | RET | LOOP |
    SYSCALL | CONST | NOP | frozenset({"movsx", "movzx", "movsxd", "sete", "setne"})
)


def imm_bound_after_and(imm: int, width_bits: int) -> Optional[int]:
    """``and r, imm``: sign-extended immediate (SDM Vol.2 AND).

    Non-negative immediate -> ``r <= imm``. Negative (alignment mask) -> None.
    """
    mask = (1 << width_bits) - 1
    v = imm & mask
    if v >> (width_bits - 1):
        return None
    return v
