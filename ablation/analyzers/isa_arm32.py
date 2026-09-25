"""ISA and ABI model for 32-bit ARM (A32) and Thumb-2 (T32).

Every table encodes a fact from the ARM Architecture Reference Manual (ARMv7-A/R,
"ARM ARM") or the Procedure Call Standard for the Arm Architecture (AAPCS32).
The two instruction sets share one register file and one ABI; where they
differ (pc-relative base, IT blocks, encodings) the difference is expressed as
an explicit :class:`Mode` query, never as a shared table that silently applies
to both.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Optional, Tuple


class Mode(str, Enum):
    ARM = "arm"        # A32: fixed 4-byte encodings
    THUMB = "thumb"    # T32: 2/4-byte encodings, IT blocks

    @property
    def bits(self) -> int:
        return 32

    @property
    def ptr_bytes(self) -> int:
        return 4

    @property
    def sp(self) -> str:
        return "sp"

    @property
    def lr(self) -> str:
        return "lr"

    @property
    def pc(self) -> str:
        return "pc"

    def pc_value(self, address: int, size: int, align: bool = False) -> int:
        """Value read from ``pc`` by an instruction at ``address``.

        ARM ARM A2.3.1 / A5.2: in ARM state the pc reads as the instruction
        address + 8; in Thumb state as address + 4. Loads from a literal pool
        (``ldr rX, [pc, #imm]``) and ``adr`` use ``Align(pc, 4)`` in Thumb
        state (A8.8.64 / A8.8.12); in ARM state the address is already aligned.
        """
        if self is Mode.ARM:
            return address + 8
        v = address + 4
        return v & ~3 if align else v


class Abi(str, Enum):
    AAPCS = "aapcs"          # soft-float / softfp: all arguments in core registers
    AAPCS_VFP = "aapcs-vfp"  # hard-float (gnueabihf): FP arguments in s/d registers

    @staticmethod
    def default_for(mode: Mode) -> "Abi":
        return Abi.AAPCS_VFP


# --------------------------------------------------------------------------
# Registers (ARM ARM A2.3; AAPCS32 §5.1.1 for the synonyms)
# --------------------------------------------------------------------------
# name -> (family, low_bit, width_bits). Core registers have no sub-registers.
# VFP/NEON: s2i and s2i+1 alias d_i (ARM ARM A2.6.2); d2i and d2i+1 alias q_i.
# The family is the q register (q0..q15), so a write to s3 is a partial write
# of q0 at bits 96..127, exactly like ah in x86.

_CORE: Dict[str, Tuple[str, int, int]] = {}
for _i in range(16):
    _CORE[f"r{_i}"] = (f"r{_i}", 0, 32)
_SYNONYMS = {"a1": "r0", "a2": "r1", "a3": "r2", "a4": "r3",
             "v1": "r4", "v2": "r5", "v3": "r6", "v4": "r7", "v5": "r8", "v6": "r9", "v7": "r10", "v8": "r11",
             "sb": "r9", "tr": "r9", "sl": "r10", "fp": "r11", "ip": "r12", "sp": "r13", "lr": "r14", "pc": "r15"}
for _n, _r in _SYNONYMS.items():
    _CORE[_n] = _CORE[_r]

# Canonical spelling used everywhere inside the tracker: r0..r12, sp, lr, pc.
CANON = {f"r{i}": f"r{i}" for i in range(13)}
CANON.update({"r13": "sp", "r14": "lr", "r15": "pc"})

_VFP: Dict[str, Tuple[str, int, int]] = {}
for _i in range(32):
    _VFP[f"s{_i}"] = (f"q{_i // 4}", 32 * (_i % 4), 32)
    _VFP[f"d{_i}"] = (f"q{_i // 2}", 64 * (_i % 2), 64)
for _i in range(16):
    _VFP[f"q{_i}"] = (f"q{_i}", 0, 128)

FLAGS = "cpsr"
_MISC = {FLAGS: (FLAGS, 0, 32), "apsr": (FLAGS, 0, 32), "apsr_nzcv": (FLAGS, 0, 32), "fpscr": ("fpscr", 0, 32)}


@dataclass(frozen=True)
class RegInfo:
    name: str          # canonical (sp/lr/pc, r0..r12, s/d/q)
    family: str
    low: int
    width: int

    @property
    def mask(self) -> int:
        return (1 << self.width) - 1

    @property
    def is_core(self) -> bool:
        return self.family.startswith("r") or self.family in ("sp", "lr", "pc")


def reg_info(name: str, mode: Mode = Mode.ARM) -> Optional[RegInfo]:
    n = name.strip().lower()
    if n in _CORE:
        fam, low, w = _CORE[n]
        c = CANON[fam]
        return RegInfo(c, c, low, w)
    t = _VFP.get(n) or _MISC.get(n)
    if t is None:
        return None
    return RegInfo(n, *t)


def is_reg(name: str, mode: Mode = Mode.ARM) -> bool:
    return reg_info(name, mode) is not None


def canon_reg(name: str) -> str:
    ri = reg_info(name)
    return ri.name if ri else name.lower()


# --------------------------------------------------------------------------
# Procedure call standard (AAPCS32 §5.1.1, §6.1.2)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class AbiModel:
    abi: Abi
    caller_saved: FrozenSet[str]   # clobbered by a call
    callee_saved: FrozenSet[str]
    arg_regs: Tuple[str, ...]
    fp_arg_regs: Tuple[str, ...]
    ret_regs: Tuple[str, ...]
    fp_ret_regs: Tuple[str, ...]
    stack_args: bool               # 5th and later arguments at [sp], [sp+4], ...


# r12 (ip) is the intra-procedure-call scratch register and may be clobbered by
# the call sequence itself (veneers, PLT). lr is overwritten by bl/blx. r9 is
# platform-reserved (sb/tr) and treated as callee-saved here.
_CORE_CALLER = frozenset({"r0", "r1", "r2", "r3", "r12", "lr"})
_CORE_CALLEE = frozenset({"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "sp"})
# VFP: d0-d7 (s0-s15) caller-saved, d8-d15 (s16-s31) callee-saved, d16-d31 caller-saved (AAPCS32 §5.1.2.1)
_VFP_CALLER = frozenset({f"q{i}" for i in range(4)} | {f"q{i}" for i in range(8, 16)})
_VFP_CALLEE = frozenset({f"q{i}" for i in range(4, 8)})

_ABIS = {
    Abi.AAPCS: AbiModel(
        Abi.AAPCS, caller_saved=_CORE_CALLER | _VFP_CALLER, callee_saved=_CORE_CALLEE | _VFP_CALLEE,
        arg_regs=("r0", "r1", "r2", "r3"), fp_arg_regs=(), ret_regs=("r0", "r1"), fp_ret_regs=(), stack_args=True,
    ),
    Abi.AAPCS_VFP: AbiModel(
        Abi.AAPCS_VFP, caller_saved=_CORE_CALLER | _VFP_CALLER, callee_saved=_CORE_CALLEE | _VFP_CALLEE,
        arg_regs=("r0", "r1", "r2", "r3"), fp_arg_regs=tuple(f"s{i}" for i in range(16)),
        ret_regs=("r0", "r1"), fp_ret_regs=("s0", "s1", "d0"), stack_args=True,
    ),
}


def abi_for(abi: Abi) -> AbiModel:
    return _ABIS[abi]


# --------------------------------------------------------------------------
# Linux system calls (arch/arm/tools/syscall.tbl, EABI)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SyscallModel:
    nr_reg: str
    arg_regs: Tuple[str, ...]
    ret_reg: str
    clobbered: FrozenSet[str]
    numbers: Dict[int, str]


# EABI: `svc #0`, number in r7, arguments r0-r6 (7 for some), result in r0.
# OABI (legacy): `swi #(0x900000 | nr)` — the number is in the instruction.
OABI_BASE = 0x900000
_SYS = SyscallModel(
    nr_reg="r7", arg_regs=("r0", "r1", "r2", "r3", "r4", "r5", "r6"), ret_reg="r0", clobbered=frozenset(),
    numbers={0: "restart_syscall", 1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve",
             19: "lseek", 20: "getpid", 37: "kill", 41: "dup", 45: "brk", 54: "ioctl", 55: "fcntl", 63: "dup2",
             85: "readlink", 91: "munmap", 118: "fsync", 120: "clone", 125: "mprotect", 145: "readv", 146: "writev",
             180: "pread64", 181: "pwrite64", 183: "getcwd", 192: "mmap2", 195: "stat64", 197: "fstat64",
             248: "exit_group", 281: "socket", 282: "bind", 283: "connect", 284: "listen", 285: "accept",
             290: "sendto", 292: "recvfrom", 322: "openat", 327: "fstatat64", 332: "readlinkat", 366: "accept4",
             384: "getrandom"},
)


def syscall_model(mode: Mode) -> SyscallModel:
    return _SYS


INPUT_SYSCALLS = {"read", "readv", "pread64", "recvfrom", "getcwd", "readlink", "readlinkat", "getrandom"}


# --------------------------------------------------------------------------
# Mnemonic normalization
# --------------------------------------------------------------------------
# UAL mnemonic = base [S] [cond] [.w|.n]. Because "teq", "bls", "smmls" etc. end
# in letters that are also condition codes, suffixes are only peeled when the
# remainder is a known base mnemonic.

CONDS = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al")
_COND_CANON = {"hs": "cs", "lo": "cc"}

# Capstone / ARM ARM stack-oriented aliases -> canonical addressing-mode forms
_LDM_STM_ALIAS = {
    "ldm": "ldmia", "ldmfd": "ldmia", "ldmea": "ldmdb", "ldmfa": "ldmda", "ldmed": "ldmib",
    "stm": "stmia", "stmea": "stmia", "stmfd": "stmdb", "stmfa": "stmib", "stmed": "stmda",
    "vldm": "vldmia", "vstm": "vstmia",
}
_MNEM_ALIAS = {**_LDM_STM_ALIAS, "addw": "add", "subw": "sub", "cpy": "mov", "neg": "rsb", "swi": "svc",
               "asl": "lsl", "vmov.f32": "vmov", "vmov.f64": "vmov", "vmov.32": "vmov", "vmov.i32": "vmov"}

COPY = frozenset({"mov", "movw"})
NOT_COPY = frozenset({"mvn"})
MOVT = frozenset({"movt"})
ZEXT = {"uxtb": 0xFF, "uxth": 0xFFFF}
SEXT = frozenset({"sxtb", "sxth"})
ZEXT_ADD = {"uxtab": 0xFF, "uxtah": 0xFFFF}     # rd = rn + zext(rm)
SEXT_ADD = frozenset({"sxtab", "sxtah"})
ARITH = frozenset({"add", "adc", "sub", "sbc", "rsb", "rsc"})
LOGIC = frozenset({"and", "orr", "eor", "bic", "orn"})
SHIFT = frozenset({"lsl", "lsr", "asr", "ror", "rrx"})
BITFIELD = frozenset({"ubfx", "sbfx", "bfi", "bfc"})
MISC_ALU = frozenset({"clz", "rev", "rev16", "revsh", "rbit", "usat", "ssat", "sel", "pkhbt", "pkhtb",
                      "qadd", "qsub", "uadd8", "usub8", "sadd8", "ssub8", "uqadd8", "uqsub8", "uhadd8"})
MUL = frozenset({"mul", "mla", "mls", "smull", "umull", "smlal", "umlal", "sdiv", "udiv", "smulbb", "smultb",
                 "smulbt", "smultt", "smulwb", "smulwt", "smlabb", "smlatb", "smlabt", "smlatt", "smmul", "smmla",
                 "smmls", "umaal", "smuad", "smusd", "smlad", "smlsd", "smlald", "smlsld"})
FLAGS_ONLY = frozenset({"cmp", "cmn", "tst", "teq"})
LOAD = frozenset({"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrt", "ldrbt", "ldrht", "ldrsbt", "ldrsht",
                  "ldrex", "ldrexb", "ldrexh", "lda", "ldab", "ldah", "ldaex", "ldaexb", "ldaexh"})
LOAD_WIDTH = {"ldr": 4, "ldrb": 1, "ldrh": 2, "ldrsb": 1, "ldrsh": 2, "ldrt": 4, "ldrbt": 1, "ldrht": 2,
              "ldrsbt": 1, "ldrsht": 2, "ldrex": 4, "ldrexb": 1, "ldrexh": 2, "lda": 4, "ldab": 1, "ldah": 2,
              "ldaex": 4, "ldaexb": 1, "ldaexh": 2, "ldrd": 8, "ldrexd": 8}
LOAD_SIGNED = frozenset({"ldrsb", "ldrsh", "ldrsbt", "ldrsht"})
LOAD_DUAL = frozenset({"ldrd", "ldrexd", "ldaexd"})
STORE = frozenset({"str", "strb", "strh", "strt", "strbt", "strht", "strex", "strexb", "strexh", "stl", "stlb",
                   "stlh", "stlex", "stlexb", "stlexh"})
STORE_DUAL = frozenset({"strd", "strexd", "stlexd"})
LDM = frozenset({"ldmia", "ldmib", "ldmda", "ldmdb"})
STM = frozenset({"stmia", "stmib", "stmda", "stmdb"})
PUSH = frozenset({"push"})
POP = frozenset({"pop"})
VPUSH = frozenset({"vpush"})
VPOP = frozenset({"vpop"})
VLDM = frozenset({"vldmia", "vldmdb"})
VSTM = frozenset({"vstmia", "vstmdb"})
VLOAD = frozenset({"vldr", "vld1", "vld2", "vld3", "vld4"})
VSTORE = frozenset({"vstr", "vst1", "vst2", "vst3", "vst4"})
VMOV = frozenset({"vmov"})
BRANCH = frozenset({"b"})
BRANCH_LINK = frozenset({"bl", "blx"})
BRANCH_EXCHANGE = frozenset({"bx", "bxj"})
CBZ = frozenset({"cbz", "cbnz"})
TABLE_BRANCH = frozenset({"tbb", "tbh"})
SYSCALL = frozenset({"svc"})
IT = frozenset({"it", "itt", "ite", "ittt", "itte", "itet", "itee", "itttt", "ittte", "ittet", "ittee",
                "itett", "itete", "iteet", "iteee"})
NOP = frozenset({"nop", "yield", "wfe", "wfi", "sev", "sevl", "dmb", "dsb", "isb", "pld", "pldw", "pli", "clrex",
                 "bkpt", "udf", "hlt", "cps", "cpsie", "cpsid", "setend", "dbg", "hint", "csdb", "esb"})
STATUS = frozenset({"mrs", "msr", "vmrs", "vmsr"})
ADR = frozenset({"adr"})

KNOWN: FrozenSet[str] = (COPY | NOT_COPY | MOVT | frozenset(ZEXT) | SEXT | frozenset(ZEXT_ADD) | SEXT_ADD | ARITH |
                         LOGIC | SHIFT | BITFIELD | MISC_ALU | MUL | FLAGS_ONLY | LOAD | LOAD_DUAL | STORE |
                         STORE_DUAL | LDM | STM | PUSH | POP | VPUSH | VPOP | VLDM | VSTM | VLOAD | VSTORE | VMOV |
                         BRANCH | BRANCH_LINK | BRANCH_EXCHANGE | CBZ | TABLE_BRANCH | SYSCALL | IT | NOP | STATUS |
                         ADR | frozenset(_MNEM_ALIAS) |
                         # VFP/NEON data-processing: treated generically (dest <- union of sources)
                         frozenset({"vadd", "vsub", "vmul", "vdiv", "vmla", "vmls", "vfma", "vfms", "vneg", "vabs",
                                    "vsqrt", "vcvt", "vcvtr", "vcmp", "vcmpe", "vand", "vorr", "veor", "vbic",
                                    "vorn", "vmax", "vmin", "vpadd", "vdup", "vext", "vshl", "vshr", "vqmovn",
                                    "vmovl", "vmovn", "vrev64", "vrev32", "vrev16", "vswp", "vtbl", "vtbx", "vzip",
                                    "vuzp", "vtrn", "vceq", "vcgt", "vcge", "vclt", "vcle", "vtst", "vmvn", "vsel",
                                    "vrinta", "vrintm", "vrintp", "vrintz", "vrintn", "vrintx", "vrintr", "vmaxnm",
                                    "vminnm", "vaddl", "vsubl", "vmull", "vpmax", "vpmin", "vsra", "vsli", "vsri",
                                    "vbsl", "vbit", "vbif", "vcnt", "vclz", "vcls", "vrecpe", "vrsqrte", "vabd"}))


@dataclass(frozen=True)
class Decoded:
    base: str                 # canonical base mnemonic ("ldmia", "add", "b")
    sets_flags: bool          # S suffix (or cmp/tst/... family, which always do)
    cond: Optional[str]       # canonical condition ("eq", "cs", ...) or None for always
    width: Optional[str]      # ".w" / ".n" if present (informational)


def _strip_dt(m: str) -> Tuple[str, Optional[str]]:
    """Split ``vcvt.f64.f32`` / ``vmov.i32`` / ``ldr.w`` into base and suffix chain."""
    if "." not in m:
        return m, None
    base, rest = m.split(".", 1)
    return base, rest


def normalize_mnemonic(m: str) -> Decoded:
    """Peel ``.w``/``.n``, condition and ``S`` suffixes from a UAL mnemonic.

    Suffixes are only removed when what remains is a known base mnemonic, so
    ``teq`` stays ``teq`` (not ``t`` + ``eq``), ``bls`` becomes ``b`` + ``ls``,
    ``lsls`` becomes ``lsl`` + S, ``ldmiane`` becomes ``ldmia`` + ``ne``, and
    Capstone's ``ldm`` maps onto objdump's ``ldmia``.
    """
    s = m.strip().lower()
    s, dt = _strip_dt(s)
    width = None
    if dt in ("w", "n"):
        width, dt = "." + dt, None
    elif dt and dt.split(".")[-1] in ("w", "n"):
        width = "." + dt.split(".")[-1]
        dt = ".".join(dt.split(".")[:-1]) or None

    def known(x: str) -> bool:
        return x in KNOWN or x in _MNEM_ALIAS

    cond: Optional[str] = None
    flags = False
    # IT-block mnemonics are their own family: "ite" is not "it" + cond "e".
    if s in IT:
        return Decoded(s, False, None, width)
    if not known(s):
        for c in CONDS:
            if s.endswith(c) and known(s[:-len(c)]):
                s, cond = s[:-len(c)], c
                break
    if not known(s) and s.endswith("s") and known(s[:-1]):
        s, flags = s[:-1], True
    elif not known(s):
        for c in CONDS:          # "addseq": S then cond
            if s.endswith(c) and s[:-len(c)].endswith("s") and known(s[:-len(c) - 1]):
                s, cond, flags = s[:-len(c) - 1], c, True
                break
    if cond == "al":
        cond = None
    if cond:
        cond = _COND_CANON.get(cond, cond)
    base = _MNEM_ALIAS.get(s, s)
    if dt and base == "vmov":
        pass
    if base in FLAGS_ONLY:
        flags = True
    return Decoded(base, flags, cond, width)


def modified_imm_bound(imm: int) -> Optional[int]:
    """``and rd, rn, #imm`` bounds rd by imm when imm is non-negative as a 32-bit value.

    ARM modified immediates (ARM ARM A5.2.4 / A6.3.2) are 8 bits rotated or
    byte-replicated and are frequently ``0xff000000``-shaped masks; those have
    bit 31 set, act as high-bit masks and bound nothing.
    """
    v = imm & 0xFFFFFFFF
    return None if v & 0x80000000 else v
