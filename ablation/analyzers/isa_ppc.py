"""ISA and ABI model for 32-bit and 64-bit PowerPC (Power ISA v2.07/v3.0 subset).

Every table encodes a fact from the Power ISA or the relevant ABI (32-bit SysV
PowerPC processor supplement; 64-bit ELF V1 / ELF V2 ABI). Width-specific facts
are an explicit :class:`Mode` query.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Tuple


class Mode(str, Enum):
    PPC32 = "ppc32"
    PPC64 = "ppc64"

    @property
    def bits(self) -> int:
        return 32 if self is Mode.PPC32 else 64

    @property
    def ptr_bytes(self) -> int:
        return self.bits // 8

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1


class Abi(str, Enum):
    SYSV32 = "sysv32"    # 32-bit SysV / EABI-like Linux ABI
    ELFV1 = "elfv1"      # 64-bit big-endian, function descriptors, TOC in r2
    ELFV2 = "elfv2"      # 64-bit (little-endian Linux), local/global entry points

    @staticmethod
    def default_for(mode: Mode, little: bool = False) -> "Abi":
        if mode is Mode.PPC32:
            return Abi.SYSV32
        return Abi.ELFV2 if little else Abi.ELFV1


# --------------------------------------------------------------------------
# Registers. Canonical: r0..r31, f0..f31, v0..v31, vs0..vs63, cr0..cr7, lr, ctr, xer, fpscr, vrsave.
# f_i is the low half of vs_i and v_i is vs_{32+i} (Power ISA v2.06 VSX register file).
# --------------------------------------------------------------------------
SP, TOC, RA_REG = "r1", "r2", "lr"


def canon_reg(name: str) -> Optional[str]:
    n = name.strip().lower()
    for pref, hi in (("vs", 64), ("cr", 8), ("r", 32), ("f", 32), ("v", 32)):
        if n.startswith(pref) and n[len(pref):].isdigit():
            k = int(n[len(pref):])
            return f"{pref}{k}" if k < hi else None
    if n in ("lr", "ctr", "xer", "fpscr", "vrsave", "sp"):
        return "r1" if n == "sp" else n
    if n.startswith("cr") and len(n) > 3 and n[2].isdigit() and n[3:] in ("lt", "gt", "eq", "so", "un"):
        return f"cr{n[2]}"                         # Capstone's "cr0eq" condition-bit register
    return None


def family(canon: str) -> str:
    if canon.startswith("f") and canon[1:].isdigit():
        return f"vs{int(canon[1:])}"
    if canon.startswith("v") and not canon.startswith("vs") and canon[1:].isdigit():
        return f"vs{32 + int(canon[1:])}"
    return canon


def is_gpr(canon: Optional[str]) -> bool:
    return bool(canon) and canon.startswith("r") and canon[1:].isdigit()


SPR = {1: "xer", 8: "lr", 9: "ctr", 256: "vrsave"}


def crbit_field(bit: int) -> str:
    return f"cr{bit // 4}"


# --------------------------------------------------------------------------
# Calling conventions
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
    lr_save: int              # offset from the caller's sp (sp at entry) of the LR save word
    stack_arg_base: int       # offset from sp at entry of the first stack-passed argument
    toc_save: Optional[int]   # where the caller keeps r2 across an indirect call (ELFv2: 24)


_VOL_GPR = frozenset({"r0"} | {f"r{i}" for i in range(3, 13)})
_NV_GPR = frozenset(f"r{i}" for i in range(14, 32)) | {"r1", "r2", "r13"}
_VOL_CR = frozenset({"cr0", "cr1", "cr5", "cr6", "cr7"})
_NV_CR = frozenset({"cr2", "cr3", "cr4"})
_VOL_FP = frozenset(f"vs{i}" for i in range(0, 14))          # f0-f13
_NV_FP = frozenset(f"vs{i}" for i in range(14, 32))          # f14-f31
_VOL_VR = frozenset(f"vs{32 + i}" for i in range(0, 20))     # v0-v19
_NV_VR = frozenset(f"vs{32 + i}" for i in range(20, 32))     # v20-v31
_SPECIAL = frozenset({"lr", "ctr", "xer"})

_ABIS = {
    # 32-bit SysV: back chain at 0(sp), LR save word at 4(sp), args from 8(sp)
    Abi.SYSV32: AbiModel(Abi.SYSV32, _VOL_GPR | _VOL_CR | _VOL_FP | _VOL_VR | _SPECIAL, _NV_GPR | _NV_CR | _NV_FP | _NV_VR,
                         tuple(f"r{i}" for i in range(3, 11)), tuple(f"f{i}" for i in range(1, 9)), ("r3", "r4"), ("f1",),
                         lr_save=4, stack_arg_base=8, toc_save=None),
    # ELF V1: back chain 0, CR save 8, LR save 16, compiler/linker dwords, TOC save 40, params 48
    Abi.ELFV1: AbiModel(Abi.ELFV1, _VOL_GPR | _VOL_CR | _VOL_FP | _VOL_VR | _SPECIAL, _NV_GPR | _NV_CR | _NV_FP | _NV_VR,
                        tuple(f"r{i}" for i in range(3, 11)), tuple(f"f{i}" for i in range(1, 14)), ("r3", "r4"), ("f1", "f2"),
                        lr_save=16, stack_arg_base=48, toc_save=40),
    # ELF V2: back chain 0, CR save 8, LR save 16, TOC save 24, params 32
    Abi.ELFV2: AbiModel(Abi.ELFV2, _VOL_GPR | _VOL_CR | _VOL_FP | _VOL_VR | _SPECIAL, _NV_GPR | _NV_CR | _NV_FP | _NV_VR,
                        tuple(f"r{i}" for i in range(3, 11)), tuple(f"f{i}" for i in range(1, 14)), ("r3", "r4"), ("f1", "f2"),
                        lr_save=16, stack_arg_base=32, toc_save=24),
}


def abi_for(abi: Abi) -> AbiModel:
    return _ABIS[abi]


# --------------------------------------------------------------------------
# Linux system calls (arch/powerpc/kernel/syscalls/syscall.tbl; shared by ppc32 and ppc64)
# `sc`: number in r0, arguments r3-r8, result in r3, error flagged in cr0.SO.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SyscallModel:
    nr_reg: str
    arg_regs: Tuple[str, ...]
    ret_reg: str
    numbers: Dict[int, str]


_SYS = SyscallModel("r0", ("r3", "r4", "r5", "r6", "r7", "r8"), "r3", {
    1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve", 19: "lseek", 20: "getpid", 37: "kill",
    41: "dup", 45: "brk", 54: "ioctl", 55: "fcntl", 63: "dup2", 85: "readlink", 90: "mmap", 91: "munmap", 118: "fsync",
    120: "clone", 125: "mprotect", 145: "readv", 146: "writev", 179: "pread64", 180: "pwrite64", 182: "getcwd", 192: "mmap2",
    234: "exit_group", 286: "openat", 296: "readlinkat", 326: "socket", 327: "bind", 328: "connect", 329: "listen",
    330: "accept", 335: "sendto", 337: "recvfrom", 344: "accept4", 359: "getrandom"})


def syscall_model(mode: Mode) -> SyscallModel:
    return _SYS


INPUT_SYSCALLS = {"read", "readv", "pread64", "recvfrom", "getcwd", "readlink", "readlinkat", "getrandom"}


# --------------------------------------------------------------------------
# Mnemonic classes (after canonicalization; see insn.canonicalize for the alias map)
# --------------------------------------------------------------------------
COPY = frozenset({"mr"})
LI = frozenset({"li", "lis"})
ARITH = frozenset({"add", "addc", "adde", "addo", "addco", "addeo", "addme", "addze", "addi", "addic", "addis", "subf",
                   "subfc", "subfe", "subfo", "subfme", "subfze", "subfic", "neg", "nego"})
MUL_DIV = frozenset({"mullw", "mullwo", "mulhw", "mulhwu", "mulld", "mulldo", "mulhd", "mulhdu", "mulli", "divw", "divwu",
                     "divd", "divdu", "divwe", "divweu", "divde", "divdeu", "modsw", "moduw", "modsd", "modud", "maddld",
                     "maddhd", "maddhdu"})
LOGIC = frozenset({"and", "andc", "or", "orc", "xor", "nand", "nor", "eqv", "andi", "andis", "ori", "oris", "xori", "xoris"})
SHIFT_VAR = frozenset({"slw", "srw", "sraw", "sld", "srd", "srad"})
SHIFT_SIGNED_IMM = frozenset({"srawi", "sradi"})
ROTATE_W = frozenset({"rlwinm", "rlwnm"})
INSERT = frozenset({"rlwimi", "rldimi"})
ROTATE_D = frozenset({"rldicl", "rldicr", "rldic", "rldcl", "rldcr"})
SIGNEXT = frozenset({"extsb", "extsh", "extsw"})
COUNT = {"cntlzw": 32, "cntlzd": 64, "cnttzw": 32, "cnttzd": 64, "popcntb": 64, "popcntw": 32, "popcntd": 64, "prtyw": 1, "prtyd": 1}
MISC = frozenset({"cmpb", "bpermd", "darn", "cmpeqb", "setb"})
ISEL = frozenset({"isel"})
CMP = frozenset({"cmpw", "cmpd", "cmplw", "cmpld", "cmpwi", "cmpdi", "cmplwi", "cmpldi", "cmp", "cmpl", "cmpi", "cmpli",
                 "fcmpu", "fcmpo", "cmprb"})
CR_LOGIC = frozenset({"crand", "cror", "crxor", "crnor", "creqv", "crandc", "crorc", "crnand", "crclr", "crset", "crmove", "crnot"})
CR_MOVE = frozenset({"mcrf", "mfcr", "mtcrf", "mfocrf", "mtocrf", "mcrxr", "mcrfs"})
SPR_MOVE = frozenset({"mflr", "mtlr", "mfctr", "mtctr", "mfxer", "mtxer", "mfspr", "mtspr", "mftb", "mftbu", "mfvrsave", "mtvrsave"})

# loads: mnemonic -> (width, signed, update)
LOAD: Dict[str, Tuple[int, bool, bool]] = {}
for _b, _w, _s in (("lbz", 1, False), ("lhz", 2, False), ("lha", 2, True), ("lwz", 4, False), ("lwa", 4, True), ("ld", 8, False)):
    LOAD[_b] = (_w, _s, False)
    LOAD[_b + "x"] = (_w, _s, False)
    if _b != "lwa":
        LOAD[_b + "u"] = (_w, _s, True)
        LOAD[_b + "ux"] = (_w, _s, True)
    else:
        LOAD["lwaux"] = (_w, _s, True)
LOAD.update({"lhbrx": (2, False, False), "lwbrx": (4, False, False), "ldbrx": (8, False, False), "lwarx": (4, False, False),
             "ldarx": (8, False, False), "lbarx": (1, False, False), "lharx": (2, False, False)})
LOAD_MULTI = frozenset({"lmw"})
STORE: Dict[str, Tuple[int, bool]] = {}
for _b, _w in (("stb", 1), ("sth", 2), ("stw", 4), ("std", 8)):
    STORE[_b] = (_w, False)
    STORE[_b + "x"] = (_w, False)
    STORE[_b + "u"] = (_w, True)
    STORE[_b + "ux"] = (_w, True)
STORE.update({"sthbrx": (2, False), "stwbrx": (4, False), "stdbrx": (8, False), "stwcx": (4, False), "stdcx": (8, False),
              "stbcx": (1, False), "sthcx": (2, False)})
STORE_MULTI = frozenset({"stmw"})
FP_LOAD = frozenset({"lfs", "lfsu", "lfsx", "lfsux", "lfd", "lfdu", "lfdx", "lfdux", "lfiwax", "lfiwzx", "lxsdx", "lxsspx",
                     "lxsiwax", "lxsiwzx", "lxsd", "lxssp", "lxvd2x", "lxvw4x", "lxvdsx", "lxvx", "lxv", "lxvb16x", "lxvh8x",
                     "lxvl", "lxvll", "lvx", "lvxl", "lvebx", "lvehx", "lvewx", "lvsl", "lvsr", "lxvwsx"})
FP_STORE = frozenset({"stfs", "stfsu", "stfsx", "stfsux", "stfd", "stfdu", "stfdx", "stfdux", "stfiwx", "stxsdx", "stxsspx",
                      "stxsiwx", "stxsd", "stxssp", "stxvd2x", "stxvw4x", "stxvx", "stxv", "stxvb16x", "stxvh8x", "stxvl",
                      "stxvll", "stvx", "stvxl", "stvebx", "stvehx", "stvewx"})
FP_MOVE_GPR = frozenset({"mtvsrd", "mtvsrwa", "mtvsrwz", "mtvsrdd", "mtvsrws", "mfvsrd", "mfvsrwz", "mfvsrld", "mtfprd",
                         "mtfprwa", "mtfprwz", "mffprd", "mffprwz", "mtvrd", "mfvrd", "mtvrwa", "mtvrwz", "mfvrwz"})

BRANCH = frozenset({"b", "ba"})
CALL = frozenset({"bl", "bla"})
RETURN = frozenset({"blr"})
CALL_LR = frozenset({"blrl"})
JUMP_CTR = frozenset({"bctr"})
CALL_CTR = frozenset({"bctrl"})
BCC = frozenset({"bcc"})                     # canonical conditional branch: [crN, target]
BCC_LR = frozenset({"bcclr"})                # conditional return
BCC_CTR = frozenset({"bccctr"})              # conditional jump via ctr
BCC_CTRL = frozenset({"bccctrl"})
BDNZ = frozenset({"bdnz", "bdz"})            # ctr-decrement branches: [target]
SYSCALL = frozenset({"sc"})
NOP = frozenset({"nop", "isync", "sync", "lwsync", "hwsync", "ptesync", "eieio", "msync", "trap", "tw", "twi", "td", "tdi",
                 "dcbt", "dcbtst", "dcbz", "dcbf", "dcbst", "dcbi", "icbi", "dcba", "dcbtt", "dcbtstt", "ori0", "xnop", "wait",
                 "rfi", "rfid", "hrfid", "attn", "dss", "dssall", "dst", "dstst", "mbar", "tbegin", "tend", "tabort", "tsr"})

# the alias families canonicalize resolves; listed so KNOWN admits them
ALIASES = frozenset({"slwi", "srwi", "clrlwi", "clrrwi", "rotlwi", "rotrwi", "extrwi", "extlwi", "clrlslwi", "inslwi", "insrwi",
                     "sldi", "srdi", "clrldi", "clrrdi", "rotldi", "rotrdi", "extrdi", "extldi", "clrlsldi", "insrdi", "sub", "subc",
                     "subi", "subis", "subic", "mtcr", "not", "la", "lwsync", "bt", "bf", "bdnzt", "bdnzf", "bdzt", "bdzf",
                     "bc", "bca", "bcl", "bcla", "bclr", "bclrl", "bcctr", "bcctrl", "rotlw", "rotld", "clrlwi."})

KNOWN: FrozenSet[str] = (COPY | LI | ARITH | MUL_DIV | LOGIC | SHIFT_VAR | SHIFT_SIGNED_IMM | ROTATE_W | INSERT | ROTATE_D |
                         SIGNEXT | frozenset(COUNT) | MISC | ISEL | CMP | CR_LOGIC | CR_MOVE | SPR_MOVE | frozenset(LOAD) |
                         LOAD_MULTI | frozenset(STORE) | STORE_MULTI | FP_LOAD | FP_STORE | FP_MOVE_GPR | BRANCH | CALL |
                         RETURN | CALL_LR | JUMP_CTR | CALL_CTR | BCC | BCC_LR | BCC_CTR | BCC_CTRL | BDNZ | SYSCALL | NOP | ALIASES)

# conditional-branch mnemonic stems (with cr field operand optional; cr0 implied)
BCC_CONDS = ("eq", "ne", "lt", "le", "gt", "ge", "so", "ns", "un", "nu", "nl", "ng", "t", "f")


@dataclass(frozen=True)
class Decoded:
    base: str
    record: bool        # "." suffix: also sets cr0
    hint: Optional[str]  # branch hint "+" / "-"


def normalize_mnemonic(m: str) -> Decoded:
    s = m.strip().lower()
    hint = None
    if s.endswith(("+", "-")) and s.startswith("b"):
        s, hint = s[:-1], s[-1]
    record = False
    if s.endswith(".") and s not in ("andi.", "andis.", "stwcx.", "stdcx.", "stbcx.", "sthcx."):
        s, record = s[:-1], True
    elif s in ("andi.", "andis."):
        s, record = s[:-1], True
    elif s in ("stwcx.", "stdcx.", "stbcx.", "sthcx."):
        s, record = s[:-1], True
    return Decoded(s, record, hint)


# --------------------------------------------------------------------------
# Operand signatures for numeric text (llvm-objdump prints registers as bare numbers)
# kinds: r gpr, a gpr-or-zero (rA base), f fpr, v vr, s vsr, c cr field, b cr bit, i immediate, m d(rA), t branch target
# --------------------------------------------------------------------------

_IMM_TAIL_1 = frozenset({"addi", "addis", "addic", "subfic", "mulli", "andi", "andis", "ori", "oris", "xori", "xoris", "srawi", "sradi",
                         "slwi", "srwi", "sldi", "srdi", "clrlwi", "clrrwi", "clrldi", "clrrdi", "rotlwi", "rotrwi", "rotldi", "rotrdi",
                         "subi", "subis", "subic", "rldcl", "rldcr", "cmpwi", "cmpdi", "cmplwi", "cmpldi", "li", "lis", "la"})
_IMM_TAIL_2 = frozenset({"extrwi", "extlwi", "extrdi", "extldi", "clrlslwi", "clrlsldi", "inslwi", "insrwi", "insrdi", "rldicl", "rldicr",
                         "rldic", "rldimi", "rlwnm"})
_IMM_TAIL_3 = frozenset({"rlwinm", "rlwimi"})
_VEC_IMM_TAIL = {"vspltisb": 1, "vspltish": 1, "vspltisw": 1, "vspltb": 1, "vsplth": 1, "vspltw": 1, "vsldoi": 1, "vcfsx": 1, "vcfux": 1,
                 "vctsxs": 1, "vctuxs": 1, "vextractub": 1, "vextractuh": 1, "vextractuw": 1, "vextractd": 1, "vinsertb": 1,
                 "vinserth": 1, "vinsertw": 1, "vinsertd": 1, "vshasigmaw": 2, "vshasigmad": 2, "vrlwmi": 0}
_VSX_IMM_TAIL = {"xxpermdi": 1, "xxsldwi": 1, "xxspltw": 1, "xxspltib": 1, "xxextractuw": 1, "xxinsertw": 1}


def operand_kinds(base: str, n: int) -> List[str]:
    """Kinds of the ``n`` operands of canonical-ish mnemonic ``base`` as printed by objdump."""
    b = base
    if b in ("b", "ba", "bl", "bla"):
        return ["t"]
    if b in ("blr", "bctr", "bctrl", "blrl", "sc", "nop", "isync", "sync", "lwsync", "eieio", "trap", "hwsync"):
        return ["i"] * n
    if b in ("bdnz", "bdz", "bdnza", "bdza", "bdnzl", "bdzl"):
        return ["t"]
    if b in ("bdnzlr", "bdzlr", "bdnzlrl", "bdzlrl"):
        return []
    if b in ("bt", "bf", "bdnzt", "bdnzf", "bdzt", "bdzf", "bta", "bfa", "btl", "bfl"):
        return ["b", "t"]
    if b in ("btlr", "bflr", "btctr", "bfctr", "btlrl", "bflrl", "btctrl", "bfctrl"):
        return ["b"]
    if b in ("bc", "bca", "bcl", "bcla"):
        return ["i", "b", "t"]
    if b in ("bclr", "bclrl", "bcctr", "bcctrl"):
        return ["i", "b"] + ["i"] * (n - 2)
    if _bcc_stem(b):
        # beq / bne / beqlr / bnectr / beqctrl …: optional cr field, target unless lr/ctr form
        stem = _bcc_stem(b) or ""
        tail = b[1 + len(stem):]
        if tail in ("lr", "lrl", "ctr", "ctrl"):
            return ["c"] * n
        return ["c", "t"] if n == 2 else ["t"]
    if b in ("crand", "cror", "crxor", "crnor", "creqv", "crandc", "crorc", "crnand"):
        return ["b", "b", "b"]
    if b in ("crclr", "crset", "crmove", "crnot"):
        return ["b"] * n
    if b == "mcrf":
        return ["c", "c"]
    if b in ("mfcr", "mflr", "mtlr", "mfctr", "mtctr", "mfxer", "mtxer", "mftb", "mftbu", "mfvrsave", "mtvrsave", "mtcr"):
        return ["r"]
    if b in ("mtcrf", "mtocrf", "mtspr", "mtdcr"):
        return ["i", "r"]
    if b in ("mfspr", "mfocrf", "mfdcr"):
        return ["r", "i"]
    if b == "mffs" or b == "mffsl":
        return ["f"]
    if b == "mtfsf":
        return ["i", "f"] + ["i"] * (n - 2)
    if b in ("mtfsb0", "mtfsb1"):
        return ["b"]
    if b == "mcrfs":
        return ["c", "c"]
    if b in ("fcmpu", "fcmpo"):
        return ["c", "f", "f"]
    if b in ("cmpw", "cmpd", "cmplw", "cmpld"):
        return ["c", "r", "r"] if n == 3 else ["r", "r"]
    if b in ("cmpwi", "cmpdi", "cmplwi", "cmpldi"):
        return ["c", "r", "i"] if n == 3 else ["r", "i"]
    if b in ("cmp", "cmpl"):
        return ["c", "i", "r", "r"]
    if b in ("cmpi", "cmpli"):
        return ["c", "i", "r", "i"]
    if b in ("cmprb", "cmpeqb"):
        return ["c", "i", "r", "r"][:n] if n == 4 else ["c", "r", "r"]
    if b in ("setb",):
        return ["r", "c"]
    if b in ("lmw", "stmw", "lq", "stq") or (b in LOAD and not b.endswith("x")) or (b in STORE and not b.endswith("x")):
        return ["r", "m"]
    if b in LOAD or b in STORE:
        return ["r", "a", "r"]
    if b in ("lfs", "lfsu", "lfd", "lfdu", "stfs", "stfsu", "stfd", "stfdu", "lxsd", "lxssp", "stxsd", "stxssp", "lxv", "stxv"):
        return [("s" if b in ("lxv", "stxv") else "f"), "m"]
    if b in FP_LOAD or b in FP_STORE:
        kind = "v" if b.startswith(("lv", "stv")) else ("s" if b.startswith(("lx", "stx")) else "f")
        return [kind, "a", "r"]
    if b in ("dcbt", "dcbtst", "dcbz", "dcbf", "dcbst", "dcbi", "icbi", "dcba"):
        return ["a", "r"] + ["i"] * (n - 2)
    if b in ("tw", "td"):
        return ["i", "r", "r"]
    if b in ("twi", "tdi"):
        return ["i", "r", "i"]
    if b.startswith(("tw", "td")):                   # tweqi r3, 0 / twlgt r3, r4
        return ["r", "i"] if b.endswith("i") else ["r", "r"]
    if b in FP_MOVE_GPR:
        if b.startswith("mt"):
            return [("s" if "vsr" in b else "f" if "fpr" in b else "v"), "r"] + ["r"] * (n - 2)
        return ["r", ("s" if "vsr" in b else "f" if "fpr" in b else "v")]
    if b == "isel":
        return ["r", "r", "r", "b"]
    if b.startswith("isel"):
        return ["r", "r", "r"]
    if b.startswith("xx") or b.startswith("xs") or b.startswith("xv"):
        k = _VSX_IMM_TAIL.get(b, 0)
        if b.startswith(("xscmp", "xvcmp")) and b.endswith("dp") and n == 3 and b.startswith("xscmpu"):
            return ["c", "s", "s"]
        return ["s"] * (n - k) + ["i"] * k
    if b.startswith("v") or b in ("mfvscr", "mtvscr"):          # VMX mnemonics start with v (VSX ones with x)
        k = _VEC_IMM_TAIL.get(b, 0)
        return ["v"] * (n - k) + ["i"] * k
    if b.startswith("f") and b not in ("fcmpu", "fcmpo"):
        return ["f"] * n
    if b in _IMM_TAIL_3:
        return ["r"] * (n - 3) + ["i"] * 3
    if b in _IMM_TAIL_2:
        return ["r"] * (n - 2) + ["i"] * 2
    if b in _IMM_TAIL_1:
        return ["r"] * (n - 1) + ["i"]
    return ["r"] * n


def _bcc_stem(b: str) -> Optional[str]:
    """'beqlr' -> 'eq', 'bne' -> 'ne', 'bdnz' -> None."""
    if not b.startswith("b") or b in ("b", "ba", "bl", "bla", "blr", "bctr", "bctrl", "blrl", "bt", "bf"):
        return None
    rest = b[1:]
    for tail in ("ctrl", "ctr", "lrl", "lr", "la", "l", "a", ""):
        if rest.endswith(tail):
            core = rest[: len(rest) - len(tail)] if tail else rest
            if core in BCC_CONDS and core not in ("t", "f"):
                return core
    return None


def mask32(mb: int, me: int) -> int:
    """Power ISA MASK(mb, me) for 32-bit rotates (bit 0 is the MSB). Wrapping when mb > me."""
    if mb <= me:
        return ((0xFFFFFFFF >> mb) & (0xFFFFFFFF << (31 - me))) & 0xFFFFFFFF
    return (~((0xFFFFFFFF >> (me + 1)) & (0xFFFFFFFF << (31 - (mb - 1))))) & 0xFFFFFFFF if mb - 1 >= me + 1 else 0xFFFFFFFF


def mask64(mb: int, me: int) -> int:
    if mb <= me:
        return ((0xFFFFFFFFFFFFFFFF >> mb) & (0xFFFFFFFFFFFFFFFF << (63 - me))) & 0xFFFFFFFFFFFFFFFF
    return (~mask64(me + 1, mb - 1)) & 0xFFFFFFFFFFFFFFFF if mb - 1 >= me + 1 else 0xFFFFFFFFFFFFFFFF
