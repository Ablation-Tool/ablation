"""ISA and ABI model for the Renesas V850 / V850E / V850E2 / RH850 (V850E3v5) family.

Sources: Renesas V850E2M Architecture Manual (R01US0001), RH850G3M Software Manual
(R01US0037), GCC / CC-RH ABI. Per-variant instruction deltas are noted with the
reason; verify against the specific core manual before relying on them.

V850 ISA facts that differ from most other architectures:
* Operand order is **destination last**: ``mov r6, r10`` writes r10;
  ``add r6, r10`` is ``r10 += r6``; ``ld.w 4[sp], r10``; ``st.w r10, 4[sp]``.
* ``andi/ori/xori imm16`` **zero-extend** the immediate; ``addi/movea`` sign-extend.
  Therefore ``andi`` ALWAYS bounds rd to [0, imm16], unlike RISC-V where negative
  imm is an alignment mask.
* ``r0`` reads as zero; ``disp[r0]`` is absolute addressing (MMIO peripheral access).
* Calls: ``jarl disp, lp`` (link in reg2, conventionally lp=r31). Return is
  ``jmp [lp]`` or ``dispose ..., [lp]``. ``jr`` is a plain jump.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Optional


class Variant(str, Enum):
    V850  = "v850"    # original core (NEC V850)
    V850E = "v850e"   # V850E / V850E1 / V850ES
    V850E2 = "v850e2" # V850E2 / V850E2M
    RH850 = "rh850"   # V850E3v5 (RH850 G3K/G3M/G3KH/G4MH)

    @property
    def rank(self) -> int:
        return ["v850", "v850e", "v850e2", "rh850"].index(self.value)


XLEN = 32
MASK32 = (1 << 32) - 1
ABS_BASE = "abs"


# ---------------------------------------------------------------------------
# Registers (GCC / CC-RH ABI)
# ---------------------------------------------------------------------------

_NUM_TO_ABI: Dict[int, str] = {0: "r0", 3: "sp", 4: "gp", 5: "tp", 30: "ep", 31: "lp"}
_ALIASES = {
    "zero": "r0", "hp": "r2",
    "r3": "sp", "r4": "gp", "r5": "tp", "r30": "ep", "r31": "lp",
}
_CANON = [_NUM_TO_ABI.get(i, f"r{i}") for i in range(32)]
ALL_REGS: FrozenSet[str] = frozenset(_CANON)


def canon_reg(name: str) -> Optional[str]:
    """Return the canonical ABI name for any V850 register spelling.

    Accepts ``r6``, ``lp``, ``sp``, ``zero``, ``hp``. Returns ``None`` for
    immediates, memory expressions, or anything else that is not a register.
    """
    n = name.strip().lower()
    if n in _ALIASES:
        return _ALIASES[n]
    if n in ALL_REGS:
        return n
    return None


def reg_num(canon: str) -> int:
    return _CANON.index(canon)


def reg_by_num(n: int) -> str:
    return _CANON[n]


# psABI register ownership.
#   r0   zero (hardwired)
#   r1   assembler temporary (clobbered by jr32, large movea, etc.)
#   r2   hp (handler stack pointer / reserved)
#   r3   sp    r4 gp    r5 tp   (compiler-managed)
#   r6-r9   arguments    r10-r11 return values    r12-r19 temporaries
#   r20-r29 callee-saved    r30 ep (reserved, preserved)    r31 lp (link, clobbered by jarl)
ARG_REGS = ("r6", "r7", "r8", "r9")
RET_REGS = ("r10", "r11")
CALLER_SAVED: FrozenSet[str] = frozenset([
    "r1", "r6", "r7", "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "lp",
])
CALLEE_SAVED: FrozenSet[str] = frozenset([
    "sp", "r20", "r21", "r22", "r23", "r24", "r25", "r26",
    "r27", "r28", "r29", "ep",
])
NEVER_TOUCHED: FrozenSet[str] = frozenset(["r0", "r2", "gp", "tp"])
LINK_REG = "lp"
FRAME_BASE = "sp"
EP_BASE = "ep"


# ---------------------------------------------------------------------------
# Mnemonic tables -- per-variant deltas
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IsaModel:
    variant: Variant
    call_mnems: FrozenSet[str]
    ret_mnems: FrozenSet[str]
    jump_mnems: FrozenSet[str]
    cond_branch_mnems: FrozenSet[str]
    load_mnems: FrozenSet[str]
    store_mnems: FrozenSet[str]
    stack_mnems: FrozenSet[str]
    alu_mnems: FrozenSet[str]
    twodest_mnems: FrozenSet[str]   # 3-op mul/div: write reg2 (lo) AND reg3 (hi)
    flag_only_mnems: FrozenSet[str]
    flag_read_mnems: FrozenSet[str]  # mnemonics that consume PSW flags
    bit_mem_mnems: FrozenSet[str]    # set1/clr1/not1/tst1
    sysreg_mnems: FrozenSet[str]     # ldsr/stsr
    nop_mnems: FrozenSet[str]
    available: FrozenSet[str]


_CALL_BASE = frozenset({"jarl"})
_CALL_E    = frozenset({"callt"})          # V850E: call via CTBP table
_RET_BASE  = frozenset({"reti"})
_RET_E     = frozenset({"ctret"})
_RET_E2    = frozenset({"eiret", "feret"})
_JUMP      = frozenset({"jr", "jmp"})
_BRANCH    = frozenset({
    "bv", "bl", "bz", "bnh", "bn", "br", "blt", "ble",
    "bnv", "bnl", "bnz", "bh", "bp", "bsa", "bge", "bgt",
    "bc", "bnc", "be", "bne", "bt", "bf",
})
_BRANCH_RH = frozenset({"loop"})           # RH850: reg1 -= 1; branch if != 0

_LOAD_BASE = frozenset({"ld.b", "ld.h", "ld.w", "sld.b", "sld.h", "sld.w"})
_LOAD_E    = frozenset({"ld.bu", "ld.hu", "sld.bu", "sld.hu"})
_LOAD_RH   = frozenset({"ld.dw", "ldl.w"})
_STORE_BASE = frozenset({"st.b", "st.h", "st.w", "sst.b", "sst.h", "sst.w"})
_STORE_RH  = frozenset({"st.dw", "stc.w"})

_STACK_E   = frozenset({"prepare", "dispose"})
_STACK_RH  = frozenset({"pushsp", "popsp"})

_ALU_BASE  = frozenset({
    "mov", "not", "add", "sub", "subr", "divh", "mulh",
    "and", "or", "xor", "shl", "shr", "sar",
    "addi", "movea", "movhi", "ori", "xori", "andi", "mulhi",
    "satadd", "satsub", "satsubr", "satsubi",
    "cmp", "tst",
})
_ALU_E     = frozenset({
    "zxb", "zxh", "sxb", "sxh", "bsh", "bsw", "hsw",
    "cmov", "mulu", "mul", "divhu", "div", "divu", "switch",
})
_ALU_E2    = frozenset({
    "adf", "sbf", "mac", "macu", "hsh",
    "sch0l", "sch0r", "sch1l", "sch1r", "rotl",
})
_ALU_RH    = frozenset({"bins", "binsu", "binsm", "caxi"})

_TWODEST   = frozenset({"mul", "mulu", "div", "divu", "divh", "divhu"})
_FLAG_ONLY = frozenset({"cmp", "tst"})
_NOP_BASE  = frozenset({"nop", "halt", "di", "ei", "rie"})
_NOP_E2    = frozenset({"synce", "syncm", "syncp", "snooze", "cll"})
_NOP_RH    = frozenset({"tlbai", "tlbr", "tlbs", "tlbw", "dbtrap", "dbret"})
_TRAP_BASE = frozenset({"trap", "fetrap"})
_TRAP_RH   = frozenset({"syscall"})
_BITMEM    = frozenset({"set1", "clr1", "not1", "tst1"})
_SYSREG    = frozenset({"ldsr", "stsr"})
_FLAG_READ = frozenset({"cmov", "setf", "sasf"})


def isa_for(variant: Variant) -> IsaModel:
    r = variant.rank
    e, e2, rh = r >= 1, r >= 2, r >= 3
    call   = _CALL_BASE | (_CALL_E if e else frozenset())
    ret    = _RET_BASE | (_RET_E if e else frozenset()) | (_RET_E2 if e2 else frozenset())
    branch = _BRANCH | (_BRANCH_RH if rh else frozenset())
    load   = _LOAD_BASE | (_LOAD_E if e else frozenset()) | (_LOAD_RH if rh else frozenset())
    store  = _STORE_BASE | (_STORE_RH if rh else frozenset())
    stack  = (_STACK_E if e else frozenset()) | (_STACK_RH if rh else frozenset())
    alu    = _ALU_BASE | (_ALU_E if e else frozenset()) | (_ALU_E2 if e2 else frozenset()) | (_ALU_RH if rh else frozenset())
    nop    = _NOP_BASE | (_NOP_E2 if e2 else frozenset()) | (_NOP_RH if rh else frozenset())
    trap   = _TRAP_BASE | (_TRAP_RH if rh else frozenset())
    twodest = _TWODEST & alu
    available = call | ret | _JUMP | branch | load | store | alu | stack | _SYSREG | nop | trap | _BITMEM | _FLAG_READ
    return IsaModel(
        variant=variant,
        call_mnems=call, ret_mnems=ret, jump_mnems=_JUMP,
        cond_branch_mnems=branch, load_mnems=load, store_mnems=store,
        stack_mnems=stack, alu_mnems=alu, twodest_mnems=twodest,
        flag_only_mnems=_FLAG_ONLY, flag_read_mnems=_FLAG_READ,
        bit_mem_mnems=_BITMEM, sysreg_mnems=_SYSREG,
        nop_mnems=nop, available=available,
    )

# ---------------------------------------------------------------------------
# Immediates
# ---------------------------------------------------------------------------

def norm_imm16_zext(value: int) -> int:
    """``andi/ori/xori`` immediates are zero-extended 16-bit fields.

    V850 ``andi`` always bounds rd to [0, imm16]: this is the opposite of
    RISC-V where a negative 12-bit imm is an alignment mask (no bound). Here
    even ``andi -1, r6, r10`` bounds rd to 0xFFFF.
    """
    return value & 0xFFFF


def norm_imm16_sext(value: int) -> int:
    """``addi/movea/mulhi/satsubi`` immediates are sign-extended 16-bit."""
    if -0x8000 <= value <= 0x7FFF:
        return value
    v = value & 0xFFFF
    return v - 0x10000 if v >= 0x8000 else v


def norm_imm5_sext(value: int) -> int:
    """Format II 5-bit signed immediate (``add imm5, reg2``)."""
    if -16 <= value <= 15:
        return value
    v = value & 0x1F
    return v - 0x20 if v >= 0x10 else v
