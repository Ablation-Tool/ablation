"""Backend-neutral AArch64 instruction model and operand parser.

Operand grammar:
  registers      x0, w1, xzr, sp, lr, d0, v1.4s, v2.d[1]
  immediates     #0x10, #-16, 0x10
  shifts/extends lsl #3 / lsr #2 / uxtw #2 / sxtw
  memory         [x0] / [x0, #0x10] / [x0, #-0x10]! / [x0], #0x10 / [x0, x1, lsl #3]
  conditions     eq, ne, hs, ...
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Union

from .isa_arm64 import canon_reg, parse_imm

_SYM_SUFFIX = re.compile(r"\s*<[^>]*>\s*$")
_SHIFT_RE   = re.compile(r"^(lsl|lsr|asr|ror|msl)\s*#?(\d+|0x[0-9a-fA-F]+)$")
_EXT_RE     = re.compile(r"^(uxtb|uxth|uxtw|uxtx|sxtb|sxth|sxtw|sxtx)(?:\s*#?(\d+))?$")
_IMM_RE     = re.compile(r"^#?-?(0x[0-9a-fA-F]+|\d+)$")
_OBJDUMP_RE = re.compile(r"^\s*(?P<addr>[0-9a-fA-F]+):\s+(?P<word>[0-9a-fA-F]{8})\s+(?P<mnem>[a-zA-Z][a-zA-Z0-9._]*)\s*(?P<ops>.*)$")
_LISTING_RE = re.compile(r"^\s*(?:(?P<addr>0x[0-9a-fA-F]+|[0-9a-fA-F]+):)?\s*(?P<mnem>[a-zA-Z][a-zA-Z0-9._]*)\s*(?P<ops>.*?)\s*$")
_BARE_HEX   = re.compile(r"^[0-9a-fA-F]+$")
_COND = frozenset({"eq","ne","cs","hs","cc","lo","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"})
_PC_REL = frozenset({"b","bl","cbz","cbnz","tbz","tbnz","adr","adrp","ldr","ldrsw","prfm"} | {f"b.{c}" for c in _COND})


# ---------------------------------------------------------------------------
# Operand types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Reg:
    name: str
    bits: int = 64
    shift: Optional[str] = None
    amount: int = 0

    def __str__(self) -> str:
        s = self.name
        if self.bits == 32 and self.name not in ("sp", "xzr") and not self.name.startswith("v"):
            s = "w" + self.name[1:]
        if self.shift:
            s += f", {self.shift} #{self.amount}"
        return s


@dataclass(frozen=True)
class Imm:
    value: int
    def __str__(self) -> str:
        return f"#{self.value:#x}" if abs(self.value) > 9 else f"#{self.value}"


@dataclass(frozen=True)
class Mem:
    base: str
    offset: int = 0
    index: Optional[Reg] = None
    writeback: Optional[str] = None   # "pre" | "post" | None
    wb_amount: int = 0

    def __str__(self) -> str:
        inner = self.base
        if self.index is not None:
            inner += f", {self.index}"
        elif self.offset:
            inner += f", #{self.offset:#x}"
        s = f"[{inner}]"
        if self.writeback == "pre":
            s += "!"
        elif self.writeback == "post":
            s += f", #{self.wb_amount:#x}"
        return s


@dataclass(frozen=True)
class Cond:
    code: str
    def __str__(self) -> str: return self.code


@dataclass(frozen=True)
class Sym:
    text: str
    def __str__(self) -> str: return self.text


Operand = Union[Reg, Imm, Mem, Cond, Sym]


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

    def reg(self, i: int) -> Optional[Reg]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], Reg) else None

    def imm(self, i: int) -> Optional[int]:
        return self.ops[i].value if i < len(self.ops) and isinstance(self.ops[i], Imm) else None

    def mem(self, i: int) -> Optional[Mem]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], Mem) else None

    def first_mem(self) -> Optional[Mem]:
        for o in self.ops:
            if isinstance(o, Mem):
                return o
        return None

    def regs(self) -> List[Reg]:
        return [o for o in self.ops if isinstance(o, Reg)]

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
        if ch in "[{":  depth += 1
        elif ch in "]}": depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return [o for o in out if o]


def _parse_reg_with_mod(tok: str, mod: Optional[str]) -> Optional[Reg]:
    r = canon_reg(tok)
    if r is None:
        return None
    name, bits = r
    if mod is None:
        return Reg(name, bits)
    m = _SHIFT_RE.match(mod)
    if m:
        return Reg(name, bits, m.group(1), int(m.group(2), 0))
    m = _EXT_RE.match(mod)
    if m:
        return Reg(name, bits, m.group(1), int(m.group(2) or 0))
    return Reg(name, bits)


def _parse_mem(tok: str) -> Optional[Mem]:
    t = tok.strip()
    if not t.startswith("["):
        return None
    pre = t.endswith("!")
    inner = t[1:].rstrip("!").rstrip()
    if not inner.endswith("]"):
        return None
    parts = [p.strip() for p in inner[:-1].split(",")]
    base = canon_reg(parts[0])
    if base is None:
        return None
    bname = base[0]
    if len(parts) == 1:
        return Mem(bname, 0, None, "pre" if pre else None, 0)
    second = parts[1]
    if _IMM_RE.match(second):
        off = parse_imm(second)
        return Mem(bname, off, None, "pre" if pre else None, off if pre else 0)
    idx = _parse_reg_with_mod(second, parts[2] if len(parts) > 2 else None)
    if idx is None:
        return None
    return Mem(bname, 0, idx, None, 0)


def parse_operands(op_str: str) -> List[Operand]:
    toks = split_operands(op_str)
    ops: List[Operand] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        mem = _parse_mem(t)
        if mem is not None:
            if nxt is not None and _IMM_RE.match(nxt) and mem.writeback is None and mem.index is None:
                mem = Mem(mem.base, 0, None, "post", parse_imm(nxt))
                i += 1
            ops.append(mem)
        elif canon_reg(t) is not None:
            mod = nxt if nxt is not None and (_SHIFT_RE.match(nxt) or _EXT_RE.match(nxt)) else None
            ops.append(_parse_reg_with_mod(t, mod))
            if mod is not None:
                i += 1
        elif t.lower() in _COND:
            ops.append(Cond(t.lower()))
        elif _IMM_RE.match(t):
            ops.append(Imm(parse_imm(t)))
        elif _SHIFT_RE.match(t) and ops and isinstance(ops[-1], Imm):
            m = _SHIFT_RE.match(t)
            ops[-1] = Imm(ops[-1].value << int(m.group(2), 0))
        else:
            ops.append(Sym(t))
        i += 1
    return ops


def make_insn(address: int, mnemonic: str, op_str: str = "", size: int = 4) -> Insn:
    m = mnemonic.strip().lower()
    return Insn(address=address, mnemonic=m, ops=parse_operands(op_str), size=size, raw=op_str)


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

def from_objdump(text: str) -> Iterator[Insn]:
    """Yield Insn from ``aarch64-linux-gnu-objdump -d`` output."""
    for line in text.splitlines():
        m = _OBJDUMP_RE.match(line)
        if not m:
            continue
        mnem = m.group("mnem").lower()
        ops = re.sub(r"<[^>]*>", "", m.group("ops")).strip()
        if mnem in _PC_REL:
            parts = [p.strip() for p in ops.split(",")]
            if parts and _BARE_HEX.match(parts[-1]) and not parts[-1].startswith("#"):
                parts[-1] = "#0x" + parts[-1]
            ops = ", ".join(parts)
        yield make_insn(int(m.group("addr"), 16), mnem, ops, size=4)


def from_listing(text: str, base: int = 0x400000) -> Iterator[Insn]:
    """Yield Insn from a hand-written assembly listing. ``//`` and ``;`` start comments."""
    pc = base
    for line in text.splitlines():
        s = re.split(r"//|;", line, 1)[0].strip()
        if not s or re.match(r"^[A-Za-z_.$][\w.$]*:$", s):
            continue
        m = _LISTING_RE.match(s)
        if not m:
            continue
        if m.group("addr"):
            pc = int(m.group("addr"), 16)
        yield make_insn(pc, m.group("mnem"), m.group("ops"), size=4)
        pc += 4


def from_capstone(code: bytes, base: int = 0x400000) -> Iterator[Insn]:
    """Yield Insn from Capstone ARM64 disassembly."""
    import capstone as cs
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    for i in md.disasm(code, base):
        yield make_insn(i.address, i.mnemonic, i.op_str, size=i.size)
