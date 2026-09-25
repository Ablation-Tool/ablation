"""Instruction representation and backends for MIPS32/MIPS64.

Capstone builds operands from structured detail; objdump / listing text goes
through :func:`make_insn`. Both keep the 4 encoding bytes so
:func:`canonicalize` can tell ``move`` = ``addu rd, rs, $zero`` (sign-extends in
MIPS64) from ``move`` = ``or`` / ``daddu`` (a true copy).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Union

from .isa_mips import Abi, Mode, O32_NAMES, canon_reg, normalize_mnemonic

_SYM = re.compile(r"\s*<[^>]*>")
_COMMENT = re.compile(r"\s*(?:#|//|;).*$")


@dataclass(frozen=True)
class Reg:
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Imm:
    value: int

    def __str__(self) -> str:
        return f"{self.value:#x}" if self.value >= 0 else f"-{-self.value:#x}"


@dataclass(frozen=True)
class Mem:
    base: str
    disp: int = 0
    index: Optional[str] = None

    def __str__(self) -> str:
        if self.index:
            return f"{self.index}({self.base})"
        return f"{self.disp}({self.base})" if self.disp else f"({self.base})"


@dataclass(frozen=True)
class Sym:
    text: str

    def __str__(self) -> str:
        return self.text


Operand = Union[Reg, Imm, Mem, Sym]


@dataclass
class Insn:
    address: int
    mnemonic: str
    ops: List[Operand] = field(default_factory=list)
    size: int = 4
    fmt: Optional[str] = None
    raw: str = ""
    code: bytes = b""
    little: bool = False

    @property
    def next_ip(self) -> int:
        return self.address + self.size

    @property
    def word(self) -> Optional[int]:
        if len(self.code) != 4:
            return None
        return int.from_bytes(self.code, "little" if self.little else "big")

    def reg(self, i: int) -> Optional[str]:
        return self.ops[i].name if i < len(self.ops) and isinstance(self.ops[i], Reg) else None

    def imm(self, i: int) -> Optional[int]:
        return self.ops[i].value if i < len(self.ops) and isinstance(self.ops[i], Imm) else None

    def mem(self, i: int) -> Optional[Mem]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], Mem) else None

    def __str__(self) -> str:
        m = self.mnemonic + (f".{self.fmt}" if self.fmt else "")
        return f"{self.address:#x}: {m} {', '.join(map(str, self.ops))}".rstrip()


# --------------------------------------------------------------------------
# text parsing
# --------------------------------------------------------------------------

def parse_int(tok: str) -> int:
    t = tok.strip().lower()
    neg = t.startswith("-")
    t = t.lstrip("+-")
    v = int(t, 0)
    return -v if neg else v


def split_operands(s: str) -> List[str]:
    s = _SYM.sub("", _COMMENT.sub("", s.strip()))
    return [o.strip() for o in s.split(",") if o.strip()] if s else []


_MEM_RE = re.compile(r"^(?P<disp>[^()]*)\((?P<base>[^()]+)\)$")


def parse_operand(tok: str, abi: Abi) -> Operand:
    t = tok.strip()
    r = canon_reg(t, abi)
    if r is not None:
        return Reg(r)
    m = _MEM_RE.match(t)
    if m:
        base = canon_reg(m.group("base"), abi)
        d = m.group("disp").strip()
        if base is not None:
            idx = canon_reg(d, abi) if d else None
            if idx is not None:
                return Mem(base, 0, idx)
            try:
                return Mem(base, parse_int(d) if d else 0)
            except ValueError:
                return Sym(t)
    try:
        return Imm(parse_int(t))
    except ValueError:
        return Sym(t)


_SIMM16 = frozenset({"addi", "addiu", "daddi", "daddiu", "slti", "sltiu", "lui", "teqi", "tnei"})
_BRANCH_TARGET = frozenset({"j", "jal", "b", "bal", "beq", "bne", "blez", "bgtz", "bltz", "bgez", "beqz", "bnez", "beql", "bnel",
                            "blezl", "bgtzl", "bltzl", "bgezl", "bgezal", "bltzal", "bc1t", "bc1f", "bc", "balc", "beqzc", "bnezc"})


def make_insn(address: int, mnemonic: str, op_str: str = "", mode: Mode = Mode.MIPS32, size: int = 4,
              code: bytes = b"", little: bool = False, abi: Optional[Abi] = None) -> Insn:
    d = normalize_mnemonic(mnemonic)
    abi = abi or Abi.default_for(mode)
    toks = split_operands(op_str)
    if d.base in _BRANCH_TARGET and toks and re.match(r"^[0-9a-fA-F]+$", toks[-1]) and not toks[-1].startswith("0x"):
        toks[-1] = "0x" + toks[-1]
    ops = [parse_operand(t, abi) for t in toks]
    if d.base in _SIMM16 and ops and isinstance(ops[-1], Imm) and 0x8000 <= ops[-1].value < 0x10000:
        ops[-1] = Imm(ops[-1].value - 0x10000)
    return canonicalize(Insn(address, d.base, ops, size, d.fmt, op_str, code, little), mode)


_FUNCT_ADDU, _FUNCT_OR, _FUNCT_DADDU, _FUNCT_SLL, _FUNCT_JALR, _FUNCT_JR = 0x21, 0x25, 0x2D, 0x00, 0x09, 0x08


def canonicalize(insn: Insn, mode: Mode) -> Insn:
    """One spelling per semantics, whichever backend produced it."""
    m, ops = insn.mnemonic, insn.ops
    if m == "move" and len(ops) == 2:
        w = insn.word
        if w is not None and (w >> 26) == 0:
            funct = w & 0x3F
            if funct == _FUNCT_ADDU and mode is Mode.MIPS64:
                insn.mnemonic, insn.ops = "addu", [ops[0], ops[1], Reg("$0")]
    elif m == "jalr" and len(ops) == 1:
        insn.ops = [Reg("$31"), ops[0]]
    elif m in ("beqz", "bnez") and len(ops) == 2:
        insn.mnemonic, insn.ops = ("beq" if m == "beqz" else "bne"), [ops[0], Reg("$0"), ops[1]]
    elif m == "b" and len(ops) == 1:
        insn.mnemonic, insn.ops = "beq", [Reg("$0"), Reg("$0"), ops[0]]
    elif m == "li" and len(ops) == 2 and isinstance(ops[1], Imm):
        v = ops[1].value
        insn.mnemonic, insn.ops = ("addiu" if -0x8000 <= v < 0x8000 else "li32"), [ops[0], Reg("$0"), ops[1]]
    elif m == "negu" and len(ops) == 2:
        insn.mnemonic, insn.ops = "subu", [ops[0], Reg("$0"), ops[1]]
    elif m == "dnegu" and len(ops) == 2:
        insn.mnemonic, insn.ops = "dsubu", [ops[0], Reg("$0"), ops[1]]
    elif m == "not" and len(ops) == 2:
        insn.mnemonic, insn.ops = "nor", [ops[0], ops[1], Reg("$0")]
    elif m in ("div", "divu", "ddiv", "ddivu") and len(ops) == 3 and ops[0] == Reg("$0"):
        insn.ops = ops[1:]
    elif m in ("sll", "dsll") and len(ops) == 3 and ops[0] == Reg("$0"):
        insn.mnemonic, insn.ops = "nop", []
    return insn


# --------------------------------------------------------------------------
# backends
# --------------------------------------------------------------------------

_ROW_RE = re.compile(r"^\s*(?P<addr>[0-9a-fA-F]+):(?P<rest>.*)$")
_HEXGROUP = re.compile(r"^[0-9a-fA-F]{2,8}$")
_LISTING_RE = re.compile(r"^\s*(?:(?P<addr>0x[0-9a-fA-F]+|[0-9a-fA-F]+):)?\s*(?P<text>[a-zA-Z].*?)\s*$")


def _split_mnem_ops(text: str) -> tuple:
    parts = text.strip().split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def from_listing(text: str, mode: Mode = Mode.MIPS32, base: int = 0x10000, abi: Optional[Abi] = None) -> Iterator[Insn]:
    """Hand-written listing, one instruction per line; ``#``/``;`` comments."""
    pc = base
    for line in text.splitlines():
        s = re.split(r"(?:#|//|;)", line, 1)[0].strip()
        if not s or re.match(r"^[A-Za-z_.$][\w.$]*:$", s) or s.startswith("."):
            continue
        m = _LISTING_RE.match(s)
        if not m:
            continue
        if m.group("addr"):
            pc = int(m.group("addr"), 16)
        mnem, ops = _split_mnem_ops(m.group("text"))
        yield make_insn(pc, mnem, ops, mode=mode, abi=abi)
        pc += 4


def _row(line: str) -> Optional[tuple]:
    m = _ROW_RE.match(line)
    if not m:
        return None
    fields = m.group("rest").split("\t")
    if len(fields) < 2:
        return None
    raw = fields[0].split()
    if not raw or not all(_HEXGROUP.match(t) for t in raw):
        return None
    text = " ".join(f.strip() for f in fields[1:] if f.strip())
    return int(m.group("addr"), 16), raw, text


def from_objdump(text: str, mode: Mode = Mode.MIPS32, little: bool = False, abi: Optional[Abi] = None) -> Iterator[Insn]:
    """Parse ``objdump -d`` / ``llvm-objdump -d``. Elided nop runs are re-inserted."""
    expected: Optional[int] = None
    pending: Optional[tuple] = None
    for line in text.splitlines():
        r = _row(line)
        if r is None:
            if pending is not None:
                t = line.strip()
                if t.startswith(".set"):
                    continue
                addr, raw, _ = pending
                pending = None
                r = (addr, raw, t)
            else:
                if re.match(r"^[0-9a-fA-F]+ <", line):
                    expected = None
                continue
        addr, raw, rest = r
        if rest.startswith(".set"):
            pending = (addr, raw, rest)
            continue
        if expected is not None and addr > expected and (addr - expected) % 4 == 0 and addr - expected <= 64:
            for a in range(expected, addr, 4):
                yield Insn(a, "nop", [], 4, None, "nop", b"\0\0\0\0", little)
        if len(raw) == 1 and len(raw[0]) == 8:
            code = int(raw[0], 16).to_bytes(4, "little" if little else "big")
        else:
            code = bytes(int(b, 16) for b in raw)
        rest = re.sub(r"\s*(?:#|;|//).*$", "", rest)
        if rest.startswith((".set", ".word", ".long", "<unknown>", ".short", ".byte")):
            expected = addr + len(code)
            continue
        mnem, ops = _split_mnem_ops(rest)
        yield make_insn(addr, mnem, ops, mode=mode, size=len(code), code=code, little=little, abi=abi)
        expected = addr + len(code)


def from_capstone(code: bytes, mode: Mode = Mode.MIPS32, base: int = 0x10000, little: bool = False) -> Iterator[Insn]:
    """Disassemble with Capstone. Register names are always mapped through the o32 table."""
    import capstone as cs
    from capstone import mips

    md = cs.Cs(cs.CS_ARCH_MIPS, (cs.CS_MODE_MIPS32 if mode is Mode.MIPS32 else cs.CS_MODE_MIPS64)
               | (cs.CS_MODE_LITTLE_ENDIAN if little else cs.CS_MODE_BIG_ENDIAN))
    md.detail = True
    for i in md.disasm(code, base):
        d = normalize_mnemonic(i.mnemonic)
        ops: List = []
        for o in i.operands:
            if o.type == mips.MIPS_OP_REG:
                ops.append(Reg(_cs_reg(i.reg_name(o.reg))))
            elif o.type == mips.MIPS_OP_IMM:
                ops.append(Imm(o.imm))
            elif o.type == mips.MIPS_OP_MEM:
                ops.append(Mem(_cs_reg(i.reg_name(o.mem.base)), o.mem.disp))
        yield canonicalize(Insn(i.address, d.base, ops, i.size, d.fmt, f"{i.mnemonic} {i.op_str}", bytes(i.bytes), little), mode)


def _cs_reg(name: str) -> str:
    n = name.lower().lstrip("$")
    if n in O32_NAMES:
        return f"${O32_NAMES[n]}"
    r = canon_reg(n, Abi.O32)
    return r if r is not None else n
