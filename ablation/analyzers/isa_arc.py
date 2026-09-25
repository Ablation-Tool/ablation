"""ISA and ABI model for Synopsys DesignWare ARC EM / ARC HS (ARCv2, 32-bit).

Every table encodes a fact from the ARCv2 ISA Programmer's Reference Manual
(instruction semantics, condition codes, ENTER_S/LEAVE_S ordering) or the ARC
GNU/Linux ABI (register usage, TRAP_S syscall convention). EM and HS share one
instruction set; HS adds 64-bit multiply/ll-sc and dual-issue but no new ABI.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Optional, Tuple


class Mode(str, Enum):
    EM = "em"
    HS = "hs"

    @property
    def bits(self) -> int:
        return 32

    @property
    def ptr_bytes(self) -> int:
        return 4

    @property
    def mask(self) -> int:
        return 0xFFFFFFFF


class Abi(str, Enum):
    ARC32 = "arc32"      # GNU ARC 32-bit ABI (Linux and bare-metal share it)

    @staticmethod
    def default_for(mode: Mode) -> "Abi":
        return Abi.ARC32


# --------------------------------------------------------------------------
# Registers (ARCv2 PRM §"Core Register Set"). Canonical spelling is rN.
# --------------------------------------------------------------------------
SP, FP, GP, BLINK, ILINK, LP_COUNT, LIMM, PCL = "r28", "r27", "r26", "r31", "r29", "r60", "r62", "r63"
_ALIASES = {"gp": GP, "fp": FP, "sp": SP, "ilink": ILINK, "ilink1": ILINK, "ilink2": "r30", "blink": BLINK,
            "lp_count": LP_COUNT, "limm": LIMM, "pcl": PCL, "pc": "pc"}
FLAGS = "status32"    # Z N C V flags live in STATUS32


def canon_reg(name: str) -> Optional[str]:
    n = name.strip().lower()
    if n in _ALIASES:
        return _ALIASES[n]
    if n.startswith("r") and n[1:].isdigit():
        k = int(n[1:])
        return f"r{k}" if 0 <= k < 64 else None
    return None


def pretty(canon: str) -> str:
    inv = {v: k for k, v in _ALIASES.items() if k not in ("ilink1", "pc")}
    return inv.get(canon, canon)


def is_core(canon: str) -> bool:
    return canon.startswith("r") and canon[1:].isdigit()


# --------------------------------------------------------------------------
# ABI (ARC GNU ABI §"Register usage")
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class AbiModel:
    abi: Abi
    caller_saved: FrozenSet[str]
    callee_saved: FrozenSet[str]
    arg_regs: Tuple[str, ...]
    ret_regs: Tuple[str, ...]
    stack_arg_base: int


_ABI = AbiModel(
    Abi.ARC32,
    caller_saved=frozenset(f"r{i}" for i in range(0, 13)) | {BLINK, LP_COUNT, FLAGS},     # r0-r12, blink
    callee_saved=frozenset(f"r{i}" for i in range(13, 26)) | {GP, FP, SP},                # r13-r25, gp, fp, sp
    arg_regs=tuple(f"r{i}" for i in range(0, 8)),                                          # r0-r7
    ret_regs=("r0", "r1"),
    stack_arg_base=0,                                                                       # 9th+ argument at [sp]
)


def abi_for(abi: Abi) -> AbiModel:
    return _ABI


# --------------------------------------------------------------------------
# Linux syscalls: `trap_s 0`, number in r8, arguments r0-r5, result in r0
# (arch/arc/include/uapi/asm/unistd.h -> asm-generic table, plus ARC specifics)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SyscallModel:
    nr_reg: str
    arg_regs: Tuple[str, ...]
    ret_reg: str
    numbers: Dict[int, str]


_SYS = SyscallModel("r8", ("r0", "r1", "r2", "r3", "r4", "r5"), "r0", {
    17: "getcwd", 23: "dup", 24: "dup3", 25: "fcntl", 29: "ioctl", 56: "openat", 57: "close", 62: "lseek", 63: "read",
    64: "write", 65: "readv", 66: "writev", 67: "pread64", 68: "pwrite64", 78: "readlinkat", 79: "fstatat", 80: "fstat",
    82: "fsync", 93: "exit", 94: "exit_group", 129: "kill", 134: "rt_sigaction", 172: "getpid", 198: "socket",
    200: "bind", 201: "listen", 202: "accept", 203: "connect", 206: "sendto", 207: "recvfrom", 214: "brk", 215: "munmap",
    220: "clone", 221: "execve", 222: "mmap", 226: "mprotect", 242: "accept4", 244: "cacheflush", 245: "arc_settls",
    246: "arc_gettls", 248: "arc_usr_cmpxchg", 278: "getrandom",
})


def syscall_model(mode: Mode) -> SyscallModel:
    return _SYS


INPUT_SYSCALLS = {"read", "readv", "pread64", "recvfrom", "getcwd", "readlinkat", "getrandom"}


# --------------------------------------------------------------------------
# Mnemonic normalization: base[_s][.cc][.f][.d][.ab|.aw|.a|.as][.di][.x][.t|.nt]
# --------------------------------------------------------------------------
CONDS = {"al": None, "ra": None, "eq": "eq", "z": "eq", "ne": "ne", "nz": "ne", "pl": "pl", "p": "pl", "mi": "mi",
         "n": "mi", "cs": "cs", "c": "cs", "lo": "cs", "cc": "cc", "nc": "cc", "hs": "cc", "vs": "vs", "v": "vs",
         "vc": "vc", "nv": "vc", "gt": "gt", "ge": "ge", "lt": "lt", "le": "le", "hi": "hi", "ls": "ls", "pnz": "pnz",
         "ss": "ss", "sc": "sc"}
ADDR_MODES = ("ab", "aw", "a", "as", "di")
BR_CONDS = ("eq", "ne", "lt", "ge", "lo", "hs")           # brcc compare-and-branch family

LOAD = {"ld": 4, "ldw": 2, "ldh": 2, "ldb": 1, "ldd": 8}
STORE = {"st": 4, "stw": 2, "sth": 2, "stb": 1, "std": 8}
PUSH, POP, ENTER, LEAVE = frozenset({"push"}), frozenset({"pop"}), frozenset({"enter"}), frozenset({"leave"})
COPY = frozenset({"mov"})
ARITH = frozenset({"add", "sub", "rsub", "adc", "sbc", "add1", "add2", "add3", "sub1", "sub2", "sub3", "neg", "abs",
                   "max", "min", "adds", "subs", "addsdw", "subsdw", "sat16", "rnd16", "abssw", "abss", "negsw", "negs"})
MUL = frozenset({"mpy", "mpyu", "mpym", "mpymu", "mpyw", "mpyuw", "mpyd", "mpydu", "mulu64", "mul64", "div", "divu",
                 "rem", "remu", "mac", "macu", "macd", "macdu", "dmpyh", "dmpyhu", "vadd2", "vsub2", "vmpy2h"})
LOGIC = frozenset({"and", "or", "xor", "bic", "not"})
SHIFT = frozenset({"asl", "asr", "lsr", "ror", "rrc", "asls", "asrs", "lsl", "rol"})
BITOP = frozenset({"bset", "bclr", "bxor", "bmsk", "bmskn"})
EXT = {"extb": 0xFF, "exth": 0xFFFF}
SEXT = frozenset({"sexb", "sexh", "sexw"})
BITMISC = frozenset({"norm", "normw", "normh", "ffs", "fls", "swap", "swape", "xbfu", "seteq", "setne", "setlt", "setge",
                     "setlo", "sethi", "setls", "setle", "setgt", "setcc"})
CMP = frozenset({"cmp", "rcmp", "tst", "btst"})
BRANCH = frozenset({"b"})                 # b, bcc (conditional on flags)
CALL = frozenset({"bl"})
JUMP = frozenset({"j"})                   # j [reg] : return if blink, jump otherwise
JUMP_LINK = frozenset({"jl"})
BRANCH_INDEXED = frozenset({"bi", "bih"})
BRCC = frozenset({"breq", "brne", "brlt", "brge", "brlo", "brhs", "bbit0", "bbit1"})
JLI = frozenset({"jli"})
LOOP = frozenset({"lp"})
SYSCALL = frozenset({"trap"})
AUX_READ = frozenset({"lr", "aex"})
AUX_WRITE = frozenset({"sr"})
ATOMIC = frozenset({"ex", "llock", "scond", "llockd", "scondd"})
NOP = frozenset({"nop", "sync", "brk", "flag", "kflag", "sleep", "rtie", "swi", "seti", "clri", "unimp", "dsync", "dmb",
                 "prefetch", "prefetchw", "prealloc", "wevt", "wlfc", "ei", "ldi"})
KNOWN: FrozenSet[str] = (frozenset(LOAD) | frozenset(STORE) | PUSH | POP | ENTER | LEAVE | COPY | ARITH | MUL | LOGIC |
                         SHIFT | BITOP | frozenset(EXT) | SEXT | BITMISC | CMP | BRANCH | CALL | JUMP | JUMP_LINK |
                         BRANCH_INDEXED | BRCC | JLI | LOOP | SYSCALL | AUX_READ | AUX_WRITE | ATOMIC | NOP)


@dataclass(frozen=True)
class Decoded:
    base: str
    cond: Optional[str]      # canonical condition or None (always)
    flags: bool              # .f
    delay: bool              # .d : the next instruction executes before the transfer
    addr: Optional[str]      # ab / aw / as / di
    signed: bool             # .x on a load
    short: bool              # _s encoding


def normalize_mnemonic(m: str) -> Decoded:
    """``ldb.ab.x`` / ``mov_s.ne`` / ``add.f`` / ``bl.d`` / ``breq.nt`` / ``jeq`` / ``setlt`` -> Decoded.

    Condition codes folded into the base (``beq``, ``bleq``, ``jne``, ``jlcc``,
    ``lpne``) are peeled only when the remainder is a known base, so ``bl``
    is never ``b`` + ``l`` and ``breq`` stays the compare-and-branch family.
    """
    parts = m.strip().lower().split(".")
    base, sufs = parts[0], parts[1:]
    short = base.endswith("_s")
    if short:
        base = base[:-2]
    cond = None
    flags = delay = signed = False
    addr = None
    for s in sufs:
        if s == "f":
            flags = True
        elif s == "d":
            delay = True
        elif s in ADDR_MODES:
            addr = "aw" if s == "a" else s
        elif s == "x":
            signed = True
        elif s in ("t", "nt"):
            continue                                   # static branch-prediction hints
        elif s in CONDS:
            cond = CONDS[s]
    base = {"ldw": "ldh", "stw": "sth", "push_s": "push", "pop_s": "pop", "trap_s": "trap", "trap0": "trap"}.get(base, base)
    if base not in KNOWN:
        for stem in ("bl", "jl", "b", "j", "lp"):
            if base.startswith(stem) and base[len(stem):] in CONDS and base[len(stem):] not in ("", ):
                cond = CONDS[base[len(stem):]]
                base = stem
                break
    if base in CMP or base in BRCC:
        flags = flags or base in CMP
    return Decoded(base, cond, flags, delay, addr, signed, short)


def bmsk_bound(n: int) -> int:
    """``bmsk a,b,c``: a = b & ((2 << (c & 31)) - 1)  (ARCv2 PRM BMSK)."""
    return (2 << (n & 31)) - 1


def imm_bound(v: int) -> Optional[int]:
    """``and a,b,imm``: a non-negative 32-bit immediate bounds the result."""
    v &= 0xFFFFFFFF
    return None if v & 0x80000000 else v
