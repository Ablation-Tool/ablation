"""ISA and ABI model for MIPS32 and MIPS64 (MIPS32/64 Release 2, with the Release 6
compact branches recognized).

Every table encodes a fact from the MIPS Architecture for Programmers (Vol. II-A,
instruction set) or the o32 / n64 ABI documents. Width-specific facts are an
explicit :class:`Mode` query, never a shared table that silently applies to both.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Optional, Tuple


class Mode(str, Enum):
    MIPS32 = "mips32"   # o32 ABI
    MIPS64 = "mips64"   # n64 ABI

    @property
    def bits(self) -> int:
        return 32 if self is Mode.MIPS32 else 64

    @property
    def ptr_bytes(self) -> int:
        return self.bits // 8

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1


class Abi(str, Enum):
    O32 = "o32"
    N64 = "n64"

    @staticmethod
    def default_for(mode: Mode) -> "Abi":
        return Abi.O32 if mode is Mode.MIPS32 else Abi.N64


# --------------------------------------------------------------------------
# Registers. Canonical spelling is "$N" (0..31), "$fN", "hi", "lo", "fcc".
# ABI names for $8-$15 DIFFER between o32 (t0-t7) and n32/n64 (a4-a7, t0-t3):
# the o32 map is used for Capstone output in BOTH modes (capstone 5.0.7 prints
# o32 names when disassembling MIPS64), the n64 map only for n64 listings.
# --------------------------------------------------------------------------

SP, FP, GP, RA, ZERO, AT, T9 = "$29", "$30", "$28", "$31", "$0", "$1", "$25"
V0, V1, A0, A1, A2, A3 = "$2", "$3", "$4", "$5", "$6", "$7"

_COMMON = {"zero": 0, "at": 1, "v0": 2, "v1": 3, "a0": 4, "a1": 5, "a2": 6, "a3": 7,
           "s0": 16, "s1": 17, "s2": 18, "s3": 19, "s4": 20, "s5": 21, "s6": 22, "s7": 23,
           "t8": 24, "t9": 25, "k0": 26, "k1": 27, "kt0": 26, "kt1": 27, "gp": 28, "sp": 29, "fp": 30, "s8": 30, "ra": 31}
O32_NAMES = {**_COMMON, "t0": 8, "t1": 9, "t2": 10, "t3": 11, "t4": 12, "t5": 13, "t6": 14, "t7": 15}
N64_NAMES = {**_COMMON, "a4": 8, "a5": 9, "a6": 10, "a7": 11, "t0": 12, "t1": 13, "t2": 14, "t3": 15}


def canon_reg(name: str, abi: Abi = Abi.O32) -> Optional[str]:
    """``$t0`` / ``t0`` / ``$8`` / ``$f12`` / ``hi`` -> canonical, or None if not a register."""
    n = name.strip().lower()
    bare = n[1:] if n.startswith("$") else n
    if bare.isdigit():
        if not n.startswith("$"):
            return None                 # a bare number is a displacement / immediate, never a register
        k = int(bare)
        return f"${k}" if 0 <= k < 32 else None
    if bare.startswith("f") and bare[1:].isdigit():
        k = int(bare[1:])
        return f"$f{k}" if 0 <= k < 32 else None
    if bare.startswith("w") and bare[1:].isdigit():          # MSA vector registers
        k = int(bare[1:])
        return f"$w{k}" if 0 <= k < 32 else None
    if bare in ("hi", "lo", "fcc", "fcc0"):
        return {"fcc0": "fcc"}.get(bare, bare)
    names = N64_NAMES if abi is Abi.N64 else O32_NAMES
    if bare in names:
        return f"${names[bare]}"
    return None


def is_gpr(canon: str) -> bool:
    return canon.startswith("$") and canon[1:].isdigit()


def pretty(canon: str, abi: Abi = Abi.O32) -> str:
    """Canonical -> ABI name for messages."""
    if is_gpr(canon):
        names = N64_NAMES if abi is Abi.N64 else O32_NAMES
        inv = {v: k for k, v in names.items() if k not in ("kt0", "kt1", "s8")}
        return "$" + inv.get(int(canon[1:]), canon[1:])
    return canon


# --------------------------------------------------------------------------
# Calling conventions (o32: SYSV MIPS ABI supplement §3-18; n64: MIPSpro N64 ABI)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class AbiModel:
    abi: Abi
    caller_saved: FrozenSet[str]
    callee_saved: FrozenSet[str]
    arg_regs: Tuple[str, ...]
    fp_arg_regs: Tuple[str, ...]
    ret_regs: Tuple[str, ...]
    fp_ret_regs: Tuple[str, ...]
    stack_arg_base: int            # offset from sp of the first stack argument at entry (o32 reserves 16 bytes)


_TEMPS = frozenset(f"${i}" for i in list(range(1, 16)) + [24, 25, 31])      # at, v0-v1, a0-a3, t0-t7/a4-a7,t0-t3, t8, t9, ra
_SAVED = frozenset(f"${i}" for i in range(16, 24)) | {GP, SP, FP}            # s0-s7, gp, sp, fp/s8
_FP_TEMPS_O32 = frozenset(f"$f{i}" for i in range(0, 20))                   # f20-f31 callee-saved (even regs hold doubles)
_FP_TEMPS_N64 = frozenset(f"$f{i}" for i in range(0, 24))                   # f24-f31 callee-saved

_ABIS = {
    Abi.O32: AbiModel(Abi.O32, caller_saved=_TEMPS | _FP_TEMPS_O32 | {"hi", "lo", "fcc"},
                      callee_saved=_SAVED | frozenset(f"$f{i}" for i in range(20, 32)),
                      arg_regs=(A0, A1, A2, A3), fp_arg_regs=("$f12", "$f14"), ret_regs=(V0, V1), fp_ret_regs=("$f0", "$f2"),
                      stack_arg_base=16),
    Abi.N64: AbiModel(Abi.N64, caller_saved=_TEMPS | _FP_TEMPS_N64 | {"hi", "lo", "fcc"},
                      callee_saved=_SAVED | frozenset(f"$f{i}" for i in range(24, 32)),
                      arg_regs=tuple(f"${i}" for i in range(4, 12)), fp_arg_regs=tuple(f"$f{i}" for i in range(12, 20)),
                      ret_regs=(V0, V1), fp_ret_regs=("$f0", "$f2"), stack_arg_base=0),
}


def abi_for(abi: Abi) -> AbiModel:
    return _ABIS[abi]


# --------------------------------------------------------------------------
# Linux system calls (arch/mips/kernel/syscalls/syscall_o32.tbl / syscall_n64.tbl)
# `syscall`: number in v0, arguments a0-a3 (o32: 5th-8th at 16($sp)..28($sp);
# n64: a0-a5), result in v0, error flag in a3 (non-zero => v0 holds errno).
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SyscallModel:
    nr_reg: str
    arg_regs: Tuple[str, ...]
    ret_reg: str
    err_reg: str
    numbers: Dict[int, str]


_O32_NR = {1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve", 19: "lseek", 20: "getpid",
           37: "kill", 41: "dup", 45: "brk", 54: "ioctl", 55: "fcntl", 63: "dup2", 85: "readlink", 90: "mmap", 91: "munmap",
           118: "fsync", 120: "clone", 125: "mprotect", 145: "readv", 146: "writev", 168: "accept", 169: "bind", 170: "connect",
           174: "listen", 176: "recvfrom", 180: "sendto", 183: "socket", 200: "pread64", 201: "pwrite64", 203: "getcwd",
           210: "mmap2", 246: "exit_group", 288: "openat", 298: "readlinkat", 334: "accept4", 353: "getrandom"}
_N64_NR = {0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 8: "lseek", 9: "mmap", 10: "mprotect",
           11: "munmap", 12: "brk", 14: "ioctl", 16: "pread64", 17: "pwrite64", 18: "readv", 19: "writev", 31: "dup",
           32: "dup2", 38: "getpid", 40: "socket", 41: "connect", 42: "accept", 43: "sendto", 44: "recvfrom", 48: "bind",
           49: "listen", 55: "clone", 56: "fork", 57: "execve", 58: "exit", 60: "kill", 70: "fcntl", 72: "fsync",
           77: "getcwd", 87: "readlink", 205: "exit_group", 247: "openat", 257: "readlinkat", 293: "accept4", 313: "getrandom"}

_SYS = {
    Mode.MIPS32: SyscallModel(V0, (A0, A1, A2, A3), V0, A3, {4000 + k: v for k, v in _O32_NR.items()}),
    Mode.MIPS64: SyscallModel(V0, tuple(f"${i}" for i in range(4, 10)), V0, A3, {5000 + k: v for k, v in _N64_NR.items()}),
}


def syscall_model(mode: Mode) -> SyscallModel:
    return _SYS[mode]


INPUT_SYSCALLS = {"read", "readv", "pread64", "recvfrom", "getcwd", "readlink", "readlinkat", "getrandom"}


# --------------------------------------------------------------------------
# Mnemonic classes
# --------------------------------------------------------------------------
# 32-bit-result operations: in MIPS64 the result is sign-extended from bit 31
# (MIPS64 Vol. II-A, e.g. ADDU: "the 32-bit result is sign-extended"). A copy
# through one of these is NOT a copy of a 64-bit value.
NARROW32 = frozenset({"add", "addu", "addi", "addiu", "sub", "subu", "sll", "srl", "sra", "sllv", "srlv", "srav", "rotr",
                      "rotrv", "mul", "mulu", "muh", "muhu", "lui", "aui", "seb", "seh", "wsbh", "ext", "ins", "lw", "lh",
                      "lb", "lwl", "lwr", "ll", "clz", "clo", "addiupc", "lsa", "align", "bitswap"})

COPY_FULL = frozenset({"or", "daddu", "dadd", "move"})                    # rd = rs (| $zero)
ARITH = frozenset({"add", "addu", "addi", "addiu", "dadd", "daddu", "daddi", "daddiu", "sub", "subu", "dsub", "dsubu",
                   "aui", "daui", "dahi", "dati", "lsa", "dlsa", "addiupc"})
LOGIC = frozenset({"and", "andi", "or", "ori", "xor", "xori", "nor"})
SHIFT_IMM = frozenset({"sll", "srl", "sra", "dsll", "dsrl", "dsra", "dsll32", "dsrl32", "dsra32", "rotr", "drotr", "drotr32"})
SHIFT_VAR = frozenset({"sllv", "srlv", "srav", "dsllv", "dsrlv", "dsrav", "rotrv", "drotrv"})
SET = frozenset({"slt", "sltu", "slti", "sltiu"})
BITFIELD = frozenset({"ext", "dext", "dextm", "dextu", "ins", "dins", "dinsm", "dinsu"})
SIGNEXT = frozenset({"seb", "seh"})
MISC = frozenset({"wsbh", "dsbh", "dshd", "clz", "clo", "dclz", "dclo", "bitswap", "dbitswap", "align", "dalign"})
COND_MOVE = frozenset({"movz", "movn"})
SELECT = frozenset({"seleqz", "selnez"})
MUL_HILO = frozenset({"mult", "multu", "dmult", "dmultu", "madd", "maddu", "msub", "msubu", "div", "divu", "ddiv", "ddivu"})
MUL_RD = frozenset({"mul", "mulu", "muh", "muhu", "dmul", "dmulu", "dmuh", "dmuhu", "mod", "modu", "dmod", "dmodu"})
HILO_MOVE = frozenset({"mfhi", "mflo", "mthi", "mtlo"})
LUI = frozenset({"lui"})
LOAD = {"lb": (1, True), "lbu": (1, False), "lh": (2, True), "lhu": (2, False), "lw": (4, True), "lwu": (4, False),
        "ld": (8, False), "ll": (4, True), "lld": (8, False), "lwl": (4, True), "lwr": (4, True), "ldl": (8, False),
        "ldr": (8, False), "lwpc": (4, True), "ldpc": (8, False), "lbe": (1, True), "lbue": (1, False), "lhe": (2, True),
        "lhue": (2, False), "lwe": (4, True)}
LOAD_PARTIAL = frozenset({"lwl", "lwr", "ldl", "ldr"})
STORE = {"sb": 1, "sh": 2, "sw": 4, "sd": 8, "sc": 4, "scd": 8, "swl": 4, "swr": 4, "sdl": 8, "sdr": 8, "sbe": 1, "she": 2, "swe": 4}
STORE_COND = frozenset({"sc", "scd"})
FP_LOAD = frozenset({"lwc1", "ldc1", "lwxc1", "ldxc1", "luxc1"})
FP_STORE = frozenset({"swc1", "sdc1", "swxc1", "sdxc1", "suxc1"})
FP_MOVE_TO = frozenset({"mtc1", "dmtc1", "mthc1", "ctc1"})
FP_MOVE_FROM = frozenset({"mfc1", "dmfc1", "mfhc1", "cfc1"})
FP_CMP_PREFIX = "c."                                # c.eq.s etc. set fcc
FP_BRANCH = frozenset({"bc1t", "bc1f", "bc1tl", "bc1fl", "bc1eqz", "bc1nez"})

# control transfer with a branch delay slot (MIPS32 Vol. II-A: J, JAL, JR, JALR, B*)
JUMP = frozenset({"j"})
CALL_DIRECT = frozenset({"jal", "bal", "bgezal", "bltzal", "bgezall", "bltzall"})
CALL_INDIRECT = frozenset({"jalr", "jalr.hb"})
JUMP_REG = frozenset({"jr", "jr.hb"})
BRANCH_COND = frozenset({"beq", "bne", "blez", "bgtz", "bltz", "bgez", "beqz", "bnez", "beql", "bnel", "blezl", "bgtzl",
                         "bltzl", "bgezl", "b"})
BRANCH_LIKELY = frozenset({"beql", "bnel", "blezl", "bgtzl", "bltzl", "bgezl", "bgezall", "bltzall", "bc1tl", "bc1fl"})
# Release 6 compact branches: NO delay slot
COMPACT_JUMP = frozenset({"bc", "jic"})
COMPACT_CALL = frozenset({"balc", "jialc", "beqzalc", "bnezalc", "blezalc", "bgezalc", "bgtzalc", "bltzalc"})
COMPACT_COND = frozenset({"beqzc", "bnezc", "beqc", "bnec", "bltc", "blec", "bgec", "bgtc", "bltuc", "bgeuc", "blezc",
                          "bgezc", "bgtzc", "bltzc", "bovc", "bnvc", "bc1eqz", "bc1nez", "jrc"})
DELAY_SLOT = JUMP | CALL_DIRECT | CALL_INDIRECT | JUMP_REG | BRANCH_COND | FP_BRANCH - {"bc1eqz", "bc1nez"}
SYSCALL = frozenset({"syscall"})
CONST_WRITE = frozenset({"rdhwr", "rdpgpr"})
NOP = frozenset({"nop", "ssnop", "ehb", "sync", "synci", "pref", "prefe", "cache", "break", "teq", "tne", "tge", "tgeu",
                 "tlt", "tltu", "teqi", "tnei", "wait", "eret", "deret", "di", "ei", "pause", "sdbbp", "sigrie", "tlbwi",
                 "tlbwr", "tlbp", "tlbr", "ginvi", "ginvt"})
UNKNOWN_WRITE = frozenset({"mfc0", "dmfc0", "mfc2", "cfc2"})

_PSEUDO = {"jr.hb": "jr", "jalr.hb": "jalr", "beqzl": "beql", "bnezl": "bnel"}
# negu / dnegu / not / li / move / beqz / bnez / b keep their spelling here and are
# rewritten with explicit operands by insn.canonicalize.

KNOWN: FrozenSet[str] = (frozenset({"negu", "dnegu", "not", "li", "beqz", "bnez", "b"}) | NARROW32 | COPY_FULL | ARITH | LOGIC | SHIFT_IMM | SHIFT_VAR | SET | BITFIELD | SIGNEXT | MISC |
                         COND_MOVE | SELECT | MUL_HILO | MUL_RD | HILO_MOVE | LUI | frozenset(LOAD) | frozenset(STORE) |
                         FP_LOAD | FP_STORE | FP_MOVE_TO | FP_MOVE_FROM | FP_BRANCH | JUMP | CALL_DIRECT | CALL_INDIRECT |
                         JUMP_REG | BRANCH_COND | COMPACT_JUMP | COMPACT_CALL | COMPACT_COND | SYSCALL | CONST_WRITE | NOP |
                         UNKNOWN_WRITE)


@dataclass(frozen=True)
class Decoded:
    base: str
    fmt: Optional[str]     # FP format suffix: "s", "d", "w", "l", "ps"


def normalize_mnemonic(m: str) -> Decoded:
    """``c.eq.s`` -> (``c.eq``, ``s``); ``add.d`` -> (``add.fp``, ``d``); ``jr.hb`` -> ``jr``.

    FP arithmetic keeps a ``.fp`` marker so ``add.s`` is never confused with the
    integer ``add`` table (different narrowing and register file).
    """
    s = m.strip().lower()
    if s in _PSEUDO:
        return Decoded(_PSEUDO[s], None)
    if s in KNOWN:
        return Decoded(s, None)
    if s.startswith("c.") and s.count(".") == 2:            # c.<cond>.<fmt>
        return Decoded("c.cond", s.rsplit(".", 1)[1])
    if s.startswith("cmp.") and s.count(".") == 2:          # R6 cmp.<cond>.<fmt> fd, fs, ft
        return Decoded("cmp.cond", s.rsplit(".", 1)[1])
    if "." in s:
        base, fmt = s.rsplit(".", 1)
        if fmt in ("s", "d", "w", "l", "ps") or (base.startswith("cvt") or base.startswith(("round", "trunc", "ceil", "floor"))):
            return Decoded(base + ".fp", fmt)
    return Decoded(s, None)


def has_delay_slot(base: str) -> bool:
    return base in DELAY_SLOT or base in ("bc1t", "bc1f", "bc1tl", "bc1fl")


def imm16_signed(v: int) -> int:
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v
