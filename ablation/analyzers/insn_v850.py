"""Backend-neutral instruction model and operand parser for V850/RH850.

Operand grammar (GNU as / v850-elf-objdump / CC-RH renderings):
  registers      r6  r31  lp  sp  gp  tp  ep  zero  hp
  immediates     5   -16  0xff00
  memory         4[sp]  -8[r29]  0x100[r0]  [lp]
  register list  {r20 - r22, lp}  {r20-r22,lp}  (prepare/dispose)
  range          r20-r24                          (pushsp/popsp)
  symbolic       _foo  hi(_buf)  lo(_buf)  eipc   -> Sym

A trailing ``<symbol+off>`` from objdump is stripped before parsing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple, Union

from .isa_v850 import ALL_REGS, canon_reg, reg_by_num, reg_num

_SYM_TAIL   = re.compile(r"\s*<[^>]*>\s*$")
_ADDR_BFR   = re.compile(r"(?<![\w.$])([0-9a-fA-F]+)(\s*<[^>]*>)")
_MEM_RE     = re.compile(r"^\s*(?P<off>[-+]?(?:0x[0-9a-fA-F]+|\d+))?\s*\[(?P<base>[a-zA-Z0-9]+)\]\s*$")
_RANGE_RE   = re.compile(r"^\s*(?P<a>[a-zA-Z0-9]+)\s*-\s*(?P<b>[a-zA-Z0-9]+)\s*$")
_LABEL_RE   = re.compile(r"^[A-Za-z_.$][\w.$]*:$")
_LISTING_RE = re.compile(r"^\s*(?:(?P<addr>0x[0-9a-fA-F]+|[0-9a-fA-F]+):)?\s*(?P<mnem>[a-zA-Z][a-zA-Z0-9.]*)\s*(?P<ops>.*?)\s*$")
_OBJDUMP_RE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F]+):\s+(?P<bytes>(?:[0-9a-fA-F]{2}\s)+)\s*(?P<mnem>[a-zA-Z][a-zA-Z0-9.]*)\s*(?P<ops>.*)$"
)

# 16-bit mnemonics (for size inference in from_listing)
_SHORT = frozenset({
    "mov", "add", "sub", "subr", "mulh", "and", "or", "xor", "not", "cmp",
    "shl", "shr", "sar", "sld.b", "sld.h", "sld.w", "sst.b", "sst.h", "sst.w",
    "sld.bu", "sld.hu", "jmp", "nop", "satadd", "satsub", "satsubr",
    "zxb", "zxh", "sxb", "sxh", "callt", "switch", "divh",
    "bv", "bl", "bz", "bnh", "bn", "br", "blt", "ble",
    "bnv", "bnl", "bnz", "bh", "bp", "bsa", "bge", "bgt",
    "bc", "bnc", "be", "bne", "bt", "bf", "di", "ei",
})


# ---------------------------------------------------------------------------
# Operand types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Reg:
    name: str
    def __str__(self) -> str: return self.name


@dataclass(frozen=True)
class Imm:
    value: int
    def __str__(self) -> str: return str(self.value)


@dataclass(frozen=True)
class Mem:
    base: str
    offset: int
    def __str__(self) -> str: return f"{self.offset}[{self.base}]"


@dataclass(frozen=True)
class RegList:
    regs: Tuple[str, ...]
    def __str__(self) -> str: return "{" + ", ".join(self.regs) + "}"


@dataclass(frozen=True)
class Sym:
    text: str
    def __str__(self) -> str: return self.text


Operand = Union[Reg, Imm, Mem, RegList, Sym]


# ---------------------------------------------------------------------------
# Insn
# ---------------------------------------------------------------------------

@dataclass
class Insn:
    address: int
    mnemonic: str
    ops: List[Operand] = field(default_factory=list)
    size: int = 4
    raw: str = ""

    def reg(self, i: int) -> Optional[str]:
        return self.ops[i].name if i < len(self.ops) and isinstance(self.ops[i], Reg) else None

    def imm(self, i: int) -> Optional[int]:
        return self.ops[i].value if i < len(self.ops) and isinstance(self.ops[i], Imm) else None

    def mem(self, i: int) -> Optional[Mem]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], Mem) else None

    def reglist(self, i: int) -> Optional[RegList]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], RegList) else None

    def regs(self) -> List[str]:
        return [o.name for o in self.ops if isinstance(o, Reg)]

    @property
    def last(self) -> Optional[Operand]:
        return self.ops[-1] if self.ops else None

    def __str__(self) -> str:
        return f"{self.address:#x}: {self.mnemonic} {', '.join(map(str, self.ops))}".rstrip()


# ---------------------------------------------------------------------------
# Operand parsing
# ---------------------------------------------------------------------------

def _expand_range(a: str, b: str) -> List[str]:
    ra, rb = canon_reg(a), canon_reg(b)
    if ra is None or rb is None:
        raise ValueError(f"bad register range {a!r}-{b!r}")
    lo, hi = sorted((reg_num(ra), reg_num(rb)))
    return [reg_by_num(n) for n in range(lo, hi + 1)]


def parse_reglist(body: str) -> RegList:
    regs: List[str] = []
    for part in body.split(","):
        part = part.strip()
        if not part:
            continue
        m = _RANGE_RE.match(part)
        if m:
            regs += _expand_range(m.group("a"), m.group("b"))
        else:
            r = canon_reg(part)
            if r is None:
                raise ValueError(f"bad register in list: {part!r}")
            regs.append(r)
    return RegList(tuple(sorted(set(regs), key=reg_num)))


def split_operands(op_str: str) -> List[str]:
    """Split on commas outside ``[]{}``, strip objdump ``<symbol+off>`` tails."""
    s = _ADDR_BFR.sub(lambda m: "0x" + m.group(1) + m.group(2), op_str.strip())
    s = re.sub(r"\s*<[^>]*>", "", s)
    if not s:
        return []
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "[{(":   depth += 1
        elif ch in "]})": depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return [o for o in out if o]


def parse_operand(tok: str, mnemonic: str = "") -> Operand:
    tok = tok.strip()
    if tok.startswith("{") and tok.endswith("}"):
        return parse_reglist(tok[1:-1])
    r = canon_reg(tok)
    if r is not None:
        return Reg(r)
    m = _MEM_RE.match(tok)
    if m:
        base = canon_reg(m.group("base"))
        if base is not None:
            off_str = m.group("off")
            return Mem(base, int(off_str, 0) if off_str else 0)
    if mnemonic in ("pushsp", "popsp"):
        m = _RANGE_RE.match(tok)
        if m:
            return RegList(tuple(_expand_range(m.group("a"), m.group("b"))))
    try:
        return Imm(int(tok, 0))
    except (ValueError, TypeError):
        return Sym(tok)


def make_insn(address: int, mnemonic: str, op_str: str = "", size: int = 4) -> Insn:
    mn = mnemonic.strip().lower()
    toks = split_operands(op_str)
    return Insn(address, mn, [parse_operand(t, mn) for t in toks], size, op_str)


# ---------------------------------------------------------------------------
# jarl / jmp decoding helpers
# ---------------------------------------------------------------------------

def jarl_link_and_target(insn: Insn) -> Tuple[str, Optional[int], Optional[str]]:
    """``(link_register, absolute_target_or_None, indirect_base_or_None)`` for jarl forms.

    Indirect form ``jarl [r6], lp``: ibase="r6", target=None.
    Direct form ``jarl 0x2000, lp``: ibase=None, target=0x2000.
    """
    if len(insn.ops) >= 2:
        link = insn.reg(1) or "lp"
        src = insn.ops[0]
        if isinstance(src, Mem):
            return link, None, src.base
        return link, insn.imm(0), None
    return "lp", insn.imm(0), None


def jmp_base(insn: Insn) -> Optional[str]:
    """Base register for ``jmp [reg1]`` (or ``None``)."""
    m = insn.mem(0)
    return m.base if m is not None else insn.reg(0)


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

def from_objdump(text: str) -> Iterator[Insn]:
    """Yield ``Insn`` objects from ``v850-elf-objdump -d`` output."""
    for line in text.splitlines():
        m = _OBJDUMP_RE.match(line)
        if not m:
            continue
        size = len(m.group("bytes").split())
        ops  = m.group("ops")
        ops  = ops.split("\t")[0] if "\t" in ops else ops
        sz   = size if size in (2, 4, 6, 8) else 4
        yield make_insn(int(m.group("addr"), 16), m.group("mnem"), ops, sz)


def from_listing(text: str, base: int = 0x1000) -> Iterator[Insn]:
    """Yield ``Insn`` objects from a hand-written assembly listing.

    Lines may begin with ``0x<addr>:`` or just a mnemonic. ``--``, ``;``, and
    ``#`` start comments. Labels (``foo:``) are skipped.
    """
    pc = base
    for line in text.splitlines():
        s = re.split(r"--|;|#", line, 1)[0].strip()
        if not s or _LABEL_RE.match(s):
            continue
        m = _LISTING_RE.match(s)
        if not m:
            continue
        if m.group("addr"):
            pc = int(m.group("addr"), 16)
        mnem = m.group("mnem").lower()
        ops  = m.group("ops")
        # mov with imm32 is 48-bit; jarl/jr are 32-bit; short forms are 16-bit
        size = 2 if mnem in _SHORT else 4
        if mnem == "mov":
            first = ops.split(",")[0].strip()
            try:
                v = int(first, 0)
                size = 2 if -16 <= v <= 15 else 6
            except ValueError:
                pass
        yield make_insn(pc, mnem, ops, size)
        pc += size


def from_v850_frames(frames) -> Iterator[Insn]:
    """Yield ``Insn`` objects from a sequence of ``V850Frame`` objects.

    Frames with a recognised mnemonic are converted directly. Frames whose
    mnemonic is ``'???'`` are emitted with empty operands so the unknown
    handler in the tracker can handle them conservatively.
    """
    for f in frames:
        yield make_insn(f.va, f.mnemonic, f.op_str, f.width)
