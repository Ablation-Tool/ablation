"""RISC-V ISA / ABI utilities shared by the RV32 and RV64 taint trackers.

Facts are sourced from the RISC-V Unprivileged ISA spec and the psABI.
Each function documents the spec section it encodes.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Optional


# ---------------------------------------------------------------------------
# Width enum
# ---------------------------------------------------------------------------

class Width(str, Enum):
    RV32 = "rv32"
    RV64 = "rv64"

    @property
    def xlen(self) -> int:
        return 32 if self is Width.RV32 else 64

    @property
    def ptr_bytes(self) -> int:
        return self.xlen // 8

# ---------------------------------------------------------------------------
# Register name canonicalization (psABI §"Register Convention", ISA Ch. 2)
# ---------------------------------------------------------------------------

_ABI_INT = [
    "zero", "ra", "sp", "gp", "tp",
    "t0", "t1", "t2",
    "s0", "s1",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6",
]
_ABI_FP = [
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
    "fs0", "fs1",
    "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
    "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11",
    "ft8", "ft9", "ft10", "ft11",
]
_INT_SET = frozenset(_ABI_INT)
_FP_SET  = frozenset(_ABI_FP)
_X_TO_ABI = {f"x{i}": n for i, n in enumerate(_ABI_INT)}
_F_TO_ABI = {f"f{i}": n for i, n in enumerate(_ABI_FP)}
_ALIASES = {"fp": "s0", "s0": "s0"}

INT_REGS: FrozenSet[str] = _INT_SET
FP_REGS:  FrozenSet[str] = _FP_SET
ALL_REGS: FrozenSet[str] = _INT_SET | _FP_SET

# ABI register groups (psABI §"Register Convention")
CALLER_SAVED: FrozenSet[str] = frozenset(
    ["ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
     "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    + ["ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
       "ft8", "ft9", "ft10", "ft11",
       "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"]
)
CALLEE_SAVED: FrozenSet[str] = frozenset(
    ["sp", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11"]
    + ["fs0", "fs1", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11"]
)
NEVER_TOUCHED: FrozenSet[str] = frozenset(["zero", "gp", "tp"])
ARG_REGS      = ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7")
RET_REGS      = ("a0", "a1")
FP_ARG_REGS   = ("fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7")
FP_RET_REGS   = ("fa0", "fa1")
SYSCALL_ARG_REGS = ("a0", "a1", "a2", "a3", "a4", "a5", "a6")
SYSCALL_NR_REG   = "a7"
SYSCALL_RET_REG  = "a0"

# Linux syscall numbers (asm-generic/unistd.h -- same on RV32 and RV64)
SYSCALLS = {
    17: "getcwd", 23: "dup", 24: "dup3", 25: "fcntl", 29: "ioctl",
    56: "openat", 57: "close", 62: "lseek", 63: "read", 64: "write",
    65: "readv", 66: "writev", 78: "readlinkat", 79: "fstatat", 80: "fstat",
    82: "fsync", 93: "exit", 94: "exit_group", 129: "kill", 172: "getpid",
    198: "socket", 200: "bind", 201: "listen", 202: "accept", 203: "connect",
    206: "sendto", 207: "recvfrom", 214: "brk", 215: "munmap", 222: "mmap",
    226: "mprotect", 220: "clone", 221: "execve",
}
INPUT_SYSCALLS = {"read", "readv", "recvfrom", "getcwd", "readlinkat"}


def canon_reg(name: str) -> Optional[str]:
    """Return the canonical ABI name for any register spelling.

    Accepts ``x10``, ``a0``, ``fp``, ``f10``, ``fa0``. Returns ``None`` for
    immediates, memory expressions, or anything else that is not a register.
    ``fp`` canonicalizes to ``s0`` per the psABI.
    """
    n = name.strip().lower()
    if n in _ALIASES:
        return _ALIASES[n]
    if n in _INT_SET or n in _FP_SET:
        return n
    if n in _X_TO_ABI:
        return _X_TO_ABI[n]
    if n in _F_TO_ABI:
        return _F_TO_ABI[n]
    return None


def is_reg(name: str) -> bool:
    return canon_reg(name) is not None


# ---------------------------------------------------------------------------
# Immediate normalization (ISA §2.4 — I-type immediates are sign-extended)
# ---------------------------------------------------------------------------

def norm_imm12(raw: int, xlen: int = 64) -> int:
    """Normalize any rendered form of a 12-bit sign-extended immediate.

    Backends render ``andi a0, a0, -16`` as ``-16``, ``0xff0``, ``4080``, or
    the full sign-extended value ``0xfffffffffffffff0``. All encode the same
    12-bit field. Returns a signed integer in [-2048, 2047].
    """
    if -0x800 <= raw <= 0x7FF:
        return raw
    if 0x800 <= raw <= 0xFFF:          # raw unsigned 12-bit (e.g. 0xff0 = 4080)
        return raw - 0x1000
    mask = (1 << xlen) - 1
    v = raw & mask
    low12 = v & 0xFFF
    return low12 - 0x1000 if low12 >= 0x800 else low12


def andi_bound(imm12: int) -> Optional[int]:
    """Upper bound on ``rd`` established by ``andi rd, rs, imm``.

    A non-negative 12-bit immediate zeros every bit above it, bounding rd to
    at most ``imm``.  A negative immediate (bit 11 set) is an alignment mask
    with all high bits set; it bounds nothing, so returns ``None``.
    """
    return imm12 if imm12 >= 0 else None


def andi_propagates(imm_token: str, xlen: int = 64) -> bool:
    """True when an ``andi`` instruction does NOT sanitize taint.

    ``andi`` sanitizes only when the immediate is non-negative (a bounding
    mask). Negative immediates (alignment masks, e.g. -16 = ``sp & ~0xf``)
    have all high bits set and leave the value attacker-controlled.
    ``imm == -1`` is an identity (``rs & ~0 == rs``), so taint must propagate.

    ``imm_token`` is the raw string from the disassembler (``-0x10``, ``0xff0``,
    ``255``, etc.).
    """
    try:
        raw = int(imm_token.strip(), 0)
    except (ValueError, AttributeError):
        return False          # can't parse -> conservative: assume sanitizes
    return andi_bound(norm_imm12(raw, xlen)) is None


def parse_int(tok: str) -> int:
    """Parse ``-16``, ``0xff0``, ``4080`` with ``int(tok, 0)`` semantics."""
    return int(tok.strip(), 0)


# ---------------------------------------------------------------------------
# IsaModel and per-width mnemonic tables
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IsaModel:
    """Mnemonic classification for one target width. Build with :func:`isa_for`."""
    width: Width
    copy_mnems: FrozenSet[str]
    narrow_copy_mnems: FrozenSet[str]
    fp_copy_mnems: FrozenSet[str]
    call_mnems: FrozenSet[str]
    ret_mnems: FrozenSet[str]
    uncond_jump_mnems: FrozenSet[str]
    cond_branch_mnems: FrozenSet[str]
    load_mnems: FrozenSet[str]
    store_mnems: FrozenSet[str]
    const_mnems: FrozenSet[str]
    alu_rr_mnems: FrozenSet[str]
    alu_ri_mnems: FrozenSet[str]
    csr_mnems: FrozenSet[str]
    fp_arith_mnems: FrozenSet[str]

    @property
    def xlen(self) -> int:
        return self.width.xlen


_COPY_BASE = frozenset({
    "mv", "c.mv",
    "addi", "add", "or", "xor", "sub", "ori", "xori", "andi",
    "sll", "srl", "sra", "slli", "srli", "srai",
})
_NARROW_COPY_RV64 = frozenset({"sext.w", "addiw", "addw", "subw", "c.addiw"})
_FP_COPY = frozenset({
    "fmv.s", "fmv.d", "fsgnj.s", "fsgnj.d",
    "fmv.x.w", "fmv.w.x", "fmv.x.d", "fmv.d.x",
    "fmv.w.s", "fmv.s.w",
})
_FP_COPY_RV64_ONLY = frozenset({"fmv.x.d", "fmv.d.x"})
_CALL_BASE = frozenset({"jal", "jalr", "call", "c.jalr"})
_CALL_RV32_ONLY = frozenset({"c.jal"})
_RET = frozenset({"ret"})
_UNCOND_JUMP = frozenset({"j", "jr", "c.j", "c.jr", "tail"})
_COND_BRANCH = frozenset({
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "beqz", "bnez", "blez", "bgez", "bltz", "bgtz", "bgt", "ble", "bgtu", "bleu",
    "c.beqz", "c.bnez",
})
_LOAD_BASE = frozenset({
    "lb", "lh", "lw", "lbu", "lhu",
    "c.lw", "c.lwsp",
    "flw", "fld", "c.fld", "c.fldsp",
})
_LOAD_RV32_ONLY = frozenset({"c.flw", "c.flwsp"})
_LOAD_RV64_ONLY = frozenset({"ld", "lwu", "c.ld", "c.ldsp"})
_STORE_BASE = frozenset({
    "sb", "sh", "sw",
    "c.sw", "c.swsp",
    "fsw", "fsd", "c.fsd", "c.fsdsp",
})
_STORE_RV32_ONLY = frozenset({"c.fsw", "c.fswsp"})
_STORE_RV64_ONLY = frozenset({"sd", "c.sd", "c.sdsp"})
_CONST = frozenset({"li", "lui", "auipc", "c.li", "c.lui", "nop", "c.nop", "la", "lla"})
_ALU_RR_BASE = frozenset({
    "add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and",
    "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu",
    "c.add", "c.sub", "c.xor", "c.or", "c.and",
    "snez", "seqz", "sltz", "sgtz", "neg", "not",
    "andn", "orn", "xnor", "max", "maxu", "min", "minu", "rol", "ror",
    "sh1add", "sh2add", "sh3add", "bclr", "bext", "binv", "bset",
})
_ALU_RR_RV64_ONLY = frozenset({
    "addw", "subw", "sllw", "srlw", "sraw",
    "mulw", "divw", "divuw", "remw", "remuw",
    "c.addw", "c.subw", "negw", "rolw", "rorw",
    "add.uw", "sh1add.uw", "sh2add.uw", "sh3add.uw",
})
_ALU_RI_BASE = frozenset({
    "addi", "slti", "sltiu", "xori", "ori", "andi", "slli", "srli", "srai",
    "c.addi", "c.addi16sp", "c.addi4spn", "c.slli", "c.srli", "c.srai", "c.andi",
    "sext.b", "sext.h", "zext.b", "zext.h", "rori", "bclri", "bexti", "binvi", "bseti",
    "clz", "ctz", "cpop", "orc.b", "rev8",
})
_ALU_RI_RV64_ONLY = frozenset({
    "addiw", "slliw", "srliw", "sraiw", "c.addiw", "sext.w", "zext.w", "slli.uw",
    "clzw", "ctzw", "cpopw", "roriw",
})
_CSR = frozenset({
    "csrr", "csrw", "csrs", "csrc", "csrrw", "csrrs", "csrrc",
    "csrwi", "csrsi", "csrci", "csrrwi", "csrrsi", "csrrci",
    "rdcycle", "rdtime", "rdinstret", "frcsr", "frrm", "frflags",
})
_FP_ARITH = frozenset({
    "fadd.s", "fsub.s", "fmul.s", "fdiv.s", "fsqrt.s", "fmin.s", "fmax.s",
    "fmadd.s", "fmsub.s", "fnmadd.s", "fnmsub.s", "fsgnjn.s", "fsgnjx.s",
    "fneg.s", "fabs.s", "fcvt.w.s", "fcvt.wu.s", "fcvt.s.w", "fcvt.s.wu",
    "feq.s", "flt.s", "fle.s", "fclass.s",
    "fadd.d", "fsub.d", "fmul.d", "fdiv.d", "fsqrt.d", "fmin.d", "fmax.d",
    "fmadd.d", "fmsub.d", "fnmadd.d", "fnmsub.d", "fsgnjn.d", "fsgnjx.d",
    "fneg.d", "fabs.d", "fcvt.w.d", "fcvt.wu.d", "fcvt.d.w", "fcvt.d.wu",
    "fcvt.s.d", "fcvt.d.s", "feq.d", "flt.d", "fle.d", "fclass.d",
})
_FP_ARITH_RV64_ONLY = frozenset({
    "fcvt.l.s", "fcvt.lu.s", "fcvt.s.l", "fcvt.s.lu",
    "fcvt.l.d", "fcvt.lu.d", "fcvt.d.l", "fcvt.d.lu",
})


def isa_for(width: Width) -> IsaModel:
    """Build the :class:`IsaModel` for *width*."""
    rv64 = width is Width.RV64
    return IsaModel(
        width=width,
        copy_mnems=_COPY_BASE,
        narrow_copy_mnems=_NARROW_COPY_RV64 if rv64 else frozenset(),
        fp_copy_mnems=_FP_COPY if rv64 else (_FP_COPY - _FP_COPY_RV64_ONLY),
        call_mnems=_CALL_BASE if rv64 else (_CALL_BASE | _CALL_RV32_ONLY),
        ret_mnems=_RET,
        uncond_jump_mnems=_UNCOND_JUMP,
        cond_branch_mnems=_COND_BRANCH,
        load_mnems=(_LOAD_BASE | _LOAD_RV64_ONLY) if rv64 else (_LOAD_BASE | _LOAD_RV32_ONLY),
        store_mnems=(_STORE_BASE | _STORE_RV64_ONLY) if rv64 else (_STORE_BASE | _STORE_RV32_ONLY),
        const_mnems=_CONST,
        alu_rr_mnems=(_ALU_RR_BASE | _ALU_RR_RV64_ONLY) if rv64 else _ALU_RR_BASE,
        alu_ri_mnems=(_ALU_RI_BASE | _ALU_RI_RV64_ONLY) if rv64 else _ALU_RI_BASE,
        csr_mnems=_CSR,
        fp_arith_mnems=(_FP_ARITH | _FP_ARITH_RV64_ONLY) if rv64 else _FP_ARITH,
    )
