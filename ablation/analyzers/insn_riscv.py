"""Backend-neutral RISC-V instruction representation and operand parsing.

Every backend (Capstone, objdump text, hand-written listing) produces
:class:`Insn` values through :func:`make_insn`, the single normalization
boundary for operand strings. Backends:
  from_listing()  -- hand-written assembly (addr optional, 0x10000 base)
  from_objdump()  -- riscv64-linux-gnu-objdump -d output
  from_capstone() -- capstone CS_ARCH_RISCV disassembly
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple, Union

from .isa_riscv import canon_reg, parse_int

_SYM_SUFFIX = re.compile(r"\s*<[^>]*>\s*$")
_MEM_RE = re.compile(r"^\s*(?P<off>[-+]?(?:0x[0-9a-fA-F]+|\d+))?\s*\(\s*(?P<base>[a-zA-Z0-9]+)\s*\)\s*$")
_OBJDUMP_RE = re.compile(r"^\s*(?P<addr>[0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{8}\s+){1,2}(?P<mnem>[a-zA-Z][a-zA-Z0-9._]*)\s*(?P<ops>.*)$")
_LISTING_RE = re.compile(r"^\s*(?:(?P<addr>0x[0-9a-fA-F]+|[0-9a-fA-F]+):)?\s*(?P<mnem>[a-zA-Z][a-zA-Z0-9._]*)\s*(?P<ops>.*?)\s*$")


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
    def __str__(self) -> str: return f"{self.offset}({self.base})"


@dataclass(frozen=True)
class Sym:
    text: str
    def __str__(self) -> str: return self.text


Operand = Union[Reg, Imm, Mem, Sym]


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

    def regs(self) -> List[str]:
        return [o.name for o in self.ops if isinstance(o, Reg)]

    def __str__(self) -> str:
        return f"{self.address:#x}: {self.mnemonic} {', '.join(map(str, self.ops))}".rstrip()


# ---------------------------------------------------------------------------
# Operand parsing
# ---------------------------------------------------------------------------

def split_operands(op_str: str) -> List[str]:
    s = _SYM_SUFFIX.sub("", op_str.strip())
    if not s:
        return []
    out, depth, cur = [], 0, []
    for ch in s:
        if ch == "(":  depth += 1
        elif ch == ")": depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return [o for o in out if o]


def parse_operand(tok: str) -> Operand:
    tok = tok.strip()
    r = canon_reg(tok)
    if r is not None:
        return Reg(r)
    m = _MEM_RE.match(tok)
    if m:
        base = canon_reg(m.group("base"))
        if base is not None:
            off = parse_int(m.group("off")) if m.group("off") else 0
            return Mem(base, off)
    try:
        return Imm(parse_int(tok))
    except ValueError:
        return Sym(tok)


def make_insn(address: int, mnemonic: str, op_str: str = "", size: int = 4) -> Insn:
    return Insn(
        address=address,
        mnemonic=mnemonic.strip().lower(),
        ops=[parse_operand(t) for t in split_operands(op_str)],
        size=size,
        raw=op_str,
    )


# ---------------------------------------------------------------------------
# Control-transfer decoding helpers
# ---------------------------------------------------------------------------

def jal_link_and_target(insn: Insn) -> Tuple[str, Optional[int]]:
    """``(link_register, absolute_target)`` for jal-family instructions."""
    m = insn.mnemonic
    if m in ("j", "c.j"):
        return "zero", insn.imm(0)
    if m == "c.jal":
        return "ra", insn.imm(0)
    if m == "jal":
        if len(insn.ops) == 1:
            return "ra", insn.imm(0)
        if len(insn.ops) >= 2:
            return insn.reg(0) or "ra", insn.imm(1)
    return "ra", None


def jalr_link_and_base(insn: Insn) -> Tuple[str, Optional[str], int]:
    """``(link_register, base_register, offset)`` for jalr-family instructions."""
    m = insn.mnemonic
    if m == "ret":
        return "zero", "ra", 0
    if m in ("jr", "c.jr"):
        return "zero", insn.reg(0), 0
    if m == "c.jalr":
        return "ra", insn.reg(0), 0
    if m == "jalr":
        n = len(insn.ops)
        if n == 1:
            return "ra", insn.reg(0), 0
        if n == 2:
            mem = insn.mem(1)
            if mem is not None:
                return insn.reg(0) or "ra", mem.base, mem.offset
            return insn.reg(0) or "ra", insn.reg(1), 0
        if n >= 3:
            return insn.reg(0) or "ra", insn.reg(1), insn.imm(2) or 0
    return "ra", None, 0


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

def from_listing(text: str, base: int = 0x10000) -> Iterator[Insn]:
    """Yield Insn from a hand-written listing. ``//`` and ``#`` start comments."""
    pc = base
    for line in text.splitlines():
        s = re.split(r"//|#", line, 1)[0].strip()
        if not s or re.match(r"^[A-Za-z_.$][\w.$]*:$", s):
            continue
        m = _LISTING_RE.match(s)
        if not m:
            continue
        if m.group("addr"):
            pc = int(m.group("addr"), 16)
        mnem = m.group("mnem").lower()
        size = 2 if mnem.startswith("c.") else 4
        yield make_insn(pc, mnem, m.group("ops"), size=size)
        pc += size


def from_objdump(text: str) -> Iterator[Insn]:
    """Yield Insn from ``riscv64-linux-gnu-objdump -d`` output."""
    for line in text.splitlines():
        m = _OBJDUMP_RE.match(line)
        if not m:
            continue
        mnem = m.group("mnem").lower()
        ops = re.sub(r"<[^>]*>", "", m.group("ops")).strip()
        size = 2 if mnem.startswith("c.") else 4
        yield make_insn(int(m.group("addr"), 16), mnem, ops, size=size)


def from_capstone(code: bytes, base: int, width_bits: int = 64) -> Iterator[Insn]:
    """Yield Insn from Capstone RISC-V disassembly."""
    import capstone as cs
    arch = cs.CS_ARCH_RISCV
    mode = cs.CS_MODE_RISCVC
    if width_bits == 32:
        mode |= cs.CS_MODE_RISCV32
    else:
        mode |= cs.CS_MODE_RISCV64
    md = cs.Cs(arch, mode)
    for i in md.disasm(code, base):
        yield make_insn(i.address, i.mnemonic, i.op_str, size=i.size)
