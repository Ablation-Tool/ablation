"""AArch64 ISA and AAPCS64 ABI model.

Sources: Arm Architecture Reference Manual (Arm ARM, A-profile);
Procedure Call Standard for the Arm 64-bit Architecture (AAPCS64).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

_GPR_RE = re.compile(r"^([xw])(\d{1,2})$")
_VEC_RE = re.compile(r"^(?:([bhsdq])(\d{1,2})|(v)(\d{1,2})(?:\.[0-9]*[bhsd])?(?:\[\d+\])?)$")

INT_REGS: FrozenSet[str] = frozenset([f"x{i}" for i in range(31)] + ["sp", "xzr"])
VEC_REGS: FrozenSet[str] = frozenset(f"v{i}" for i in range(32))
FLAGS = "nzcv"

_NAMED = {
    "lr": "x30", "fp": "x29", "xzr": "xzr", "wzr": "xzr",
    "sp": "sp", "wsp": "sp", "ip0": "x16", "ip1": "x17",
}


def canon_reg(tok: str) -> Optional[Tuple[str, int]]:
    """``(canonical_name, access_bits)`` or ``None``.

    ``w5`` -> ``("x5", 32)``; ``lr`` -> ``("x30", 64)``; ``d3`` -> ``("v3", 64)``.
    W-form writes zero-extend into the full X register (Arm ARM C1.2.4).
    """
    t = tok.strip().lower()
    if t in _NAMED:
        return _NAMED[t], (32 if t in ("wzr", "wsp") else 64)
    m = _GPR_RE.match(t)
    if m and int(m.group(2)) <= 30:
        return f"x{m.group(2)}", (64 if m.group(1) == "x" else 32)
    m = _VEC_RE.match(t)
    if m:
        kind, num = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        if int(num) <= 31:
            bits = {"b": 8, "h": 16, "s": 32, "d": 64, "q": 128, "v": 128}[kind]
            return f"v{num}", bits
    return None


# AAPCS64 §6.1
ARG_REGS      = tuple(f"x{i}" for i in range(8))
RET_REGS      = ("x0", "x1")
VEC_ARG_REGS  = tuple(f"v{i}" for i in range(8))
VEC_RET_REGS  = ("v0", "v1")
CALLER_SAVED: FrozenSet[str] = frozenset(
    [f"x{i}" for i in range(0, 18)] + ["x30"]
    + [f"v{i}" for i in range(0, 8)] + [f"v{i}" for i in range(16, 32)]
)
CALLEE_SAVED: FrozenSet[str] = frozenset(
    [f"x{i}" for i in range(19, 30)] + ["sp"]
    + [f"v{i}" for i in range(8, 16)]
)
LINK_REG  = "x30"
FRAME_REG = "x29"
FRAME_BASES = ("sp", FRAME_REG)
MASK64 = (1 << 64) - 1

# Linux arm64 syscall convention
SYSCALL_NR_REG   = "x8"
SYSCALL_ARG_REGS = ("x0", "x1", "x2", "x3", "x4", "x5")
SYSCALL_RET_REG  = "x0"
SYSCALLS = {
    63: "read", 64: "write", 65: "readv", 66: "writev",
    207: "recvfrom", 206: "sendto", 202: "accept", 221: "execve",
    56: "openat", 57: "close", 93: "exit", 94: "exit_group",
    222: "mmap", 215: "munmap", 214: "brk", 129: "kill",
}
INPUT_SYSCALLS = {"read", "readv", "recvfrom"}


# ---------------------------------------------------------------------------
# Bounds helpers
# ---------------------------------------------------------------------------

def and_bound(imm: int, bits: int) -> Optional[int]:
    """Bound from ``and rd, rn, #imm`` (AArch64 logical immediate, unsigned bitmask).

    A mask with the top bit set (e.g. alignment mask 0xfffffffffffffff0) leaves
    high bits intact -- not a useful bound. Returns ``None`` for those.
    """
    imm &= (1 << bits) - 1
    if imm >> (bits - 1):
        return None
    return imm


def w_cap(bound: Optional[int], bits: int) -> Optional[int]:
    """W-register write zero-extends: result is < 2**32 (Arm ARM C1.2.4)."""
    if bits == 32:
        return 0xFFFF_FFFF if bound is None else min(bound, 0xFFFF_FFFF)
    return bound


def ext_bound(kind: Optional[str], amount: int, bound: Optional[int], bits: int) -> Optional[int]:
    """Bound on a register source after its shift/extend modifier."""
    if bits == 32 and not kind:
        bound = 0xFFFF_FFFF if bound is None else min(bound, 0xFFFF_FFFF)
    if not kind:
        return bound
    if kind == "lsl":
        return None if bound is None or amount >= 32 else bound << amount
    if kind in ("lsr", "asr"):
        return None if bound is None else bound >> amount
    fixed = {"uxtb": 0xFF, "uxth": 0xFFFF, "uxtw": 0xFFFF_FFFF, "uxtx": None}
    if kind in fixed:
        b = fixed[kind]
        b = b if bound is None or b is None else min(b, bound)
        return None if b is None else (b << amount if amount < 32 else None)
    if kind in ("sxtb", "sxth", "sxtw", "sxtx"):
        limit = {"sxtb": 1 << 7, "sxth": 1 << 15, "sxtw": 1 << 31, "sxtx": None}[kind]
        if bound is not None and limit is not None and bound < limit:
            return bound << amount if amount < 32 else None
        return None
    return None


# ---------------------------------------------------------------------------
# Mnemonic tables
# ---------------------------------------------------------------------------

def parse_imm(tok: str) -> int:
    return int(tok.strip().lstrip("#"), 0)


@dataclass(frozen=True)
class IsaModel:
    copy_mnems: FrozenSet[str]
    ext_mnems: FrozenSet[str]
    const_mnems: FrozenSet[str]
    partial_write_mnems: FrozenSet[str]
    call_mnems: FrozenSet[str]
    ret_mnems: FrozenSet[str]
    indirect_jump_mnems: FrozenSet[str]
    uncond_branch_mnems: FrozenSet[str]
    cond_branch_mnems: FrozenSet[str]
    reg_branch_mnems: FrozenSet[str]
    load_mnems: FrozenSet[str]
    load_pair_mnems: FrozenSet[str]
    store_mnems: FrozenSet[str]
    store_pair_mnems: FrozenSet[str]
    atomic_rmw_mnems: FrozenSet[str]
    flag_setting_mnems: FrozenSet[str]
    cond_select_mnems: FrozenSet[str]
    alu_mnems: FrozenSet[str]
    fp_copy_mnems: FrozenSet[str]
    nop_mnems: FrozenSet[str]
    sys_mnems: FrozenSet[str]


_COPY    = frozenset({"mov", "orr", "add", "sub", "eor", "lsl", "lsr", "asr", "ror"})
_EXT     = frozenset({"uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw", "ubfx", "ubfiz", "sbfx", "sbfiz", "ubfm", "sbfm", "bfm"})
_CONST   = frozenset({"movz", "movn", "adr", "adrp"})
_PARTIAL = frozenset({"movk", "bfi", "bfxil", "ins"})
_CALL    = frozenset({"bl", "blr", "blraa", "blrab", "blraaz", "blrabz"})
_RET     = frozenset({"ret", "retaa", "retab", "eret"})
_IJUMP   = frozenset({"br", "braa", "brab", "braaz", "brabz"})
_UBRANCH = frozenset({"b"})
_CBRANCH = frozenset({f"b.{c}" for c in ("eq","ne","cs","hs","cc","lo","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv")})
_RBRANCH = frozenset({"cbz", "cbnz", "tbz", "tbnz"})

_LOAD = frozenset({
    "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw",
    "ldar", "ldarb", "ldarh", "ldxr", "ldxrb", "ldxrh", "ldaxr", "ldaxrb", "ldaxrh", "ldapr", "ldtr", "ldtrb", "ldtrh",
    "ldraa", "ldrab", "ld1", "ld1r",
})
_LOAD_PAIR  = frozenset({"ldp", "ldpsw", "ldnp", "ldxp", "ldaxp"})
_STORE      = frozenset({
    "str", "strb", "strh", "stur", "sturb", "sturh", "stlr", "stlrb", "stlrh",
    "stxr", "stxrb", "stxrh", "stlxr", "stlxrb", "stlxrh", "sttr", "sttrb", "sttrh", "st1",
})
_STORE_PAIR = frozenset({"stp", "stnp", "stxp", "stlxp"})
_ATOMIC     = frozenset({
    "ldadd", "ldadda", "ldaddl", "ldaddal", "ldclr", "ldclra", "ldclrl", "ldclral",
    "ldeor", "ldeora", "ldeorl", "ldeoral", "ldset", "ldseta", "ldsetl", "ldsetal",
    "ldsmax", "ldsmin", "ldumax", "ldumin", "swp", "swpa", "swpl", "swpal",
    "cas", "casa", "casl", "casal", "casb", "cash", "casp",
})
_FLAGS = frozenset({"cmp", "cmn", "tst", "adds", "subs", "ands", "bics", "adcs", "sbcs", "negs", "ngcs", "ccmp", "ccmn", "fcmp", "fcmpe", "fccmp"})
_CSEL  = frozenset({"csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg"})
_ALU   = frozenset({
    "add", "adc", "sub", "sbc", "neg", "ngc", "mul", "mneg", "madd", "msub", "smull", "umull", "smulh", "umulh",
    "smaddl", "smsubl", "umaddl", "umsubl", "sdiv", "udiv", "and", "orr", "eor", "eon", "orn", "bic", "mvn",
    "lsl", "lsr", "asr", "ror", "extr", "rbit", "rev", "rev16", "rev32", "rev64", "clz", "cls",
    "adds", "subs", "ands", "bics", "adcs", "sbcs", "negs", "ngcs",
    "crc32b", "crc32h", "crc32w", "crc32x", "crc32cb", "crc32ch", "crc32cw", "crc32cx",
    "fadd", "fsub", "fmul", "fdiv", "fneg", "fabs", "fsqrt", "fmadd", "fmsub", "fnmadd", "fnmsub", "fnmul",
    "fmax", "fmin", "fmaxnm", "fminnm", "fcvt", "fcvtzs", "fcvtzu", "fcvtas", "fcvtau", "fcvtms", "fcvtmu",
    "fcvtns", "fcvtnu", "fcvtps", "fcvtpu", "scvtf", "ucvtf",
    "frintn", "frintz", "frinta", "frintm", "frintp", "frintx", "frinti", "fcsel",
    "fabd", "fmla", "fmls", "dup", "ext", "zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2",
    "tbl", "tbx", "cnt", "addv", "uaddlv", "saddlv", "umov", "smov", "xtn", "uxtl", "sxtl",
    "shl", "ushr", "sshr", "cmeq", "cmgt", "cmge", "cmhi", "cmhs", "cmtst",
    "pmull", "pmull2", "aese", "aesd", "aesmc", "aesimc",
    "sha256h", "sha256h2", "sha256su0", "sha256su1",
})
_FP_COPY = frozenset({"fmov"})
_NOP = frozenset({
    "nop", "hint", "yield", "wfe", "wfi", "sev", "sevl", "dmb", "dsb", "isb", "clrex",
    "csdb", "esb", "paciasp", "pacibsp", "autiasp", "autibsp", "paciaz", "pacibz",
    "autiaz", "autibz", "xpaclri", "bti", "prfm", "prfum", "dc", "ic", "at", "tlbi",
    "sb", "pssbb", "ssbb",
})
_SYS = frozenset({"svc", "hvc", "smc", "brk", "hlt", "mrs", "msr", "sys", "sysl", "dcps1", "dcps2", "dcps3"})

LOAD_BYTES = {"b": 1, "h": 2, "sb": 1, "sh": 2, "sw": 4}


def access_bytes(mnemonic: str, dst_bits: int) -> Tuple[int, bool]:
    """``(bytes_accessed, is_signed)`` for a load mnemonic and its register width."""
    m = mnemonic
    if m in ("ldrsw", "ldursw", "ldpsw"):
        return 4, True
    for suf in ("sb", "sh", "b", "h"):
        if m.endswith(suf):
            return LOAD_BYTES[suf], suf.startswith("s")
    return dst_bits // 8, False


ISA = IsaModel(
    copy_mnems=_COPY, ext_mnems=_EXT, const_mnems=_CONST, partial_write_mnems=_PARTIAL,
    call_mnems=_CALL, ret_mnems=_RET, indirect_jump_mnems=_IJUMP, uncond_branch_mnems=_UBRANCH,
    cond_branch_mnems=_CBRANCH, reg_branch_mnems=_RBRANCH,
    load_mnems=_LOAD, load_pair_mnems=_LOAD_PAIR, store_mnems=_STORE, store_pair_mnems=_STORE_PAIR,
    atomic_rmw_mnems=_ATOMIC, flag_setting_mnems=_FLAGS, cond_select_mnems=_CSEL, alu_mnems=_ALU,
    fp_copy_mnems=_FP_COPY, nop_mnems=_NOP, sys_mnems=_SYS,
)
