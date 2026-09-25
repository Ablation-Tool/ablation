"""Instruction representation, parsing, canonicalization, and backends for ARC EM/HS (ARCv2).

Merged from arctaint/insn.py + arctaint/backends.py.
Only text backends (GNU objdump / hand listing) -- no Capstone ARC backend exists.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Union

from .isa_arc import Decoded, canon_reg, normalize_mnemonic

_SYM = re.compile(r"\s*<[^>]*>")
_COMMENT = re.compile(r"\s*(?:;|#|//).*$")


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
            return f"[{self.base},{self.index}]"
        return f"[{self.base},{self.disp}]" if self.disp else f"[{self.base}]"


@dataclass(frozen=True)
class RegList:
    regs: tuple

    def __str__(self) -> str:
        return "{" + ",".join(self.regs) + "}"


@dataclass(frozen=True)
class Sym:
    text: str

    def __str__(self) -> str:
        return self.text


Operand = Union[Reg, Imm, Mem, RegList, Sym]


@dataclass
class Insn:
    address: int
    mnemonic: str
    ops: List[Operand] = field(default_factory=list)
    size: int = 4
    cond: Optional[str] = None
    flags: bool = False
    delay: bool = False
    addr: Optional[str] = None
    signed: bool = False
    raw: str = ""

    @property
    def next_ip(self) -> int:
        return self.address + self.size

    @property
    def pcl(self) -> int:
        return self.address & ~3

    def reg(self, i: int) -> Optional[str]:
        return self.ops[i].name if i < len(self.ops) and isinstance(self.ops[i], Reg) else None

    def imm(self, i: int) -> Optional[int]:
        return self.ops[i].value if i < len(self.ops) and isinstance(self.ops[i], Imm) else None

    def mem(self, i: int) -> Optional[Mem]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], Mem) else None

    def reglist(self, i: int) -> Optional[RegList]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], RegList) else None

    def __str__(self) -> str:
        m = self.mnemonic + (f".{self.cond}" if self.cond else "") + (".f" if self.flags else "") + (".d" if self.delay else "") \
            + (f".{self.addr}" if self.addr else "") + (".x" if self.signed else "")
        return f"{self.address:#x}: {m} {','.join(map(str, self.ops))}".rstrip()


def parse_int(tok: str) -> int:
    t = tok.strip().lower()
    neg = t.startswith("-")
    v = int(t.lstrip("+-"), 0)
    return -v if neg else v


def split_operands(s: str) -> List[str]:
    s = _SYM.sub("", _COMMENT.sub("", s.strip()))
    out, depth, cur = [], 0, []
    for ch in s:
        depth += ch in "[{"
        depth -= ch in "]}"
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return [o for o in out if o]


def parse_reglist(body: str) -> Optional[RegList]:
    regs: List[str] = []
    for part in body.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (canon_reg(p) for p in part.split("-", 1))
            if a is None or b is None:
                return None
            regs += [f"r{i}" for i in range(int(a[1:]), int(b[1:]) + 1)]
        else:
            r = canon_reg(part)
            if r is None:
                return None
            regs.append(r)
    return RegList(tuple(regs))


def parse_operand(tok: str, mnemonic: str = "") -> Operand:
    t = tok.strip()
    if t.startswith("{") and t.endswith("}"):
        rl = parse_reglist(t[1:-1])
        return rl if rl is not None else Sym(t)
    if t.startswith("[") and t.endswith("]"):
        body = t[1:-1]
        if mnemonic in ("lr", "sr", "aex"):
            return Sym(t)
        if mnemonic in ("enter", "leave"):
            rl = parse_reglist(body)
            if rl is not None:
                return rl
        parts = [p.strip() for p in body.split(",")]
        base = canon_reg(parts[0])
        if base is None:
            return Sym(t)
        if len(parts) == 1:
            return Mem(base)
        idx = canon_reg(parts[1])
        if idx is not None:
            return Mem(base, 0, idx)
        try:
            return Mem(base, parse_int(parts[1]))
        except ValueError:
            return Sym(t)
    r = canon_reg(t)
    if r is not None:
        return Reg(r)
    try:
        return Imm(parse_int(t))
    except ValueError:
        return Sym(t)


def make_insn(address: int, mnemonic: str, op_str: str = "", size: int = 4) -> Insn:
    d: Decoded = normalize_mnemonic(mnemonic)
    ops = [parse_operand(t, d.base) for t in split_operands(op_str)]
    return canonicalize(Insn(address, d.base, ops, size, d.cond, d.flags, d.delay, d.addr, d.signed, f"{mnemonic} {op_str}"))


def canonicalize(insn: Insn) -> Insn:
    m, ops = insn.mnemonic, insn.ops
    if m == "st" and len(ops) == 2 and isinstance(ops[1], Mem) and ops[1] == Mem("r28", -4) and insn.addr == "aw":
        insn.mnemonic, insn.ops, insn.addr = "push", [ops[0]], None
    elif m == "ld" and len(ops) == 2 and isinstance(ops[1], Mem) and ops[1] == Mem("r28", 4) and insn.addr == "ab":
        insn.mnemonic, insn.ops, insn.addr = "pop", [ops[0]], None
    elif m == "cmp" and len(ops) == 2:
        insn.mnemonic, insn.ops, insn.flags = "sub", [Imm(0), ops[0], ops[1]], True
    elif m == "rcmp" and len(ops) == 2:
        insn.mnemonic, insn.ops, insn.flags = "rsub", [Imm(0), ops[0], ops[1]], True
    elif m == "tst" and len(ops) == 2:
        insn.mnemonic, insn.ops, insn.flags = "and", [Imm(0), ops[0], ops[1]], True
    elif m == "sub" and len(ops) == 3 and ops[0] == Reg("r28") and ops[1] == Reg("r28") and isinstance(ops[2], Imm):
        insn.mnemonic, insn.ops = "add", [ops[0], ops[1], Imm(-ops[2].value)]
    elif m in ("add", "sub") and len(ops) == 3 and ops[1] == Reg("r28") and ops[0] == Reg("r28") and isinstance(ops[2], Imm):
        pass
    return insn


# --------------------------------------------------------------------------
# backends
# --------------------------------------------------------------------------

_ROW_RE = re.compile(r"^\s*(?P<addr>[0-9a-fA-F]+):(?P<rest>.*)$")
_HALFWORD = re.compile(r"^[0-9a-fA-F]{4}$")
_LISTING_RE = re.compile(r"^\s*(?:(?P<addr>0x[0-9a-fA-F]+|[0-9a-fA-F]+):)?\s*(?P<text>[a-zA-Z].*?)\s*$")


def _split_mnem_ops(text: str) -> tuple:
    parts = text.strip().split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def from_listing(text: str, base: int = 0x10000) -> Iterator[Insn]:
    """Hand-written GNU-syntax listing, one instruction per line; ;/# comments."""
    pc = base
    for line in text.splitlines():
        s = re.split(r"(?:;|#|//)", line, 1)[0].strip()
        if not s or re.match(r"^[A-Za-z_.$][\w.$]*:$", s) or s.startswith("."):
            continue
        m = _LISTING_RE.match(s)
        if not m:
            continue
        if m.group("addr"):
            pc = int(m.group("addr"), 16)
        mnem, ops = _split_mnem_ops(m.group("text"))
        size = 2 if mnem.split(".")[0].endswith("_s") else 4
        yield make_insn(pc, mnem, ops, size)
        pc += size


def from_objdump(text: str) -> Iterator[Insn]:
    """Parse arc-*-objdump -d output."""
    for line in text.splitlines():
        m = _ROW_RE.match(line)
        if not m:
            continue
        fields = [f for f in m.group("rest").split("\t") if f.strip()]
        if len(fields) < 2:
            continue
        raw = fields[0].split()
        if not raw or not all(_HALFWORD.match(t) for t in raw):
            continue
        rest = " ".join(f.strip() for f in fields[1:] if f.strip())
        rest = re.sub(r"\s*;.*$", "", rest)
        if not rest or rest.startswith((".word", ".long", ".short", "<unknown>")):
            continue
        mnem, ops = _split_mnem_ops(rest)
        yield make_insn(int(m.group("addr"), 16), mnem, ops, 2 * len(raw))
