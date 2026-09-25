"""Instruction representation, backends, and canonicalization for 32-/64-bit PowerPC.

Merged from ppctaint/insn.py + ppctaint/backends.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Union

from .isa_ppc import Mode, SPR, canon_reg, crbit_field, normalize_mnemonic, operand_kinds

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
    base: Optional[str]          # None: literal zero base (rA = 0)
    disp: int = 0
    index: Optional[str] = None  # X-form: rA + rB

    def __str__(self) -> str:
        if self.index:
            return f"{self.base or 0}, {self.index}"
        return f"{self.disp}({self.base or 0})"


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
    record: bool = False        # Rc=1 (".") also sets cr0
    raw: str = ""

    @property
    def next_ip(self) -> int:
        return self.address + self.size

    def reg(self, i: int) -> Optional[str]:
        return self.ops[i].name if i < len(self.ops) and isinstance(self.ops[i], Reg) else None

    def imm(self, i: int) -> Optional[int]:
        return self.ops[i].value if i < len(self.ops) and isinstance(self.ops[i], Imm) else None

    def mem(self, i: int) -> Optional[Mem]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], Mem) else None

    def __str__(self) -> str:
        return f"{self.address:#x}: {self.mnemonic}{'.' if self.record else ''} {', '.join(map(str, self.ops))}".rstrip()


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


def _reg_of(tok: str, kind: str) -> Optional[str]:
    r = canon_reg(tok)
    if r is not None:
        return r
    if re.match(r"^-?\d+$", tok):
        k = int(tok)
        pref = {"r": "r", "a": "r", "f": "f", "v": "v", "s": "vs", "c": "cr"}.get(kind)
        if pref is not None and 0 <= k < (64 if pref == "vs" else 8 if pref == "cr" else 32):
            return f"{pref}{k}"
    return None


def parse_operand(tok: str, kind: str) -> Operand:
    t = tok.strip()
    m = _MEM_RE.match(t)
    if m and kind in ("m", "r", "a", "f", "s", "v"):
        base_tok = m.group("base").strip()
        base = _reg_of(base_tok, "r")
        if base_tok in ("0", "r0") and kind == "m":
            base = None
        d = m.group("disp").strip()
        try:
            return Mem(base, parse_int(d) if d else 0)
        except ValueError:
            return Sym(t)
    if kind == "b":
        if re.match(r"^\d+$", t):
            return Reg(crbit_field(int(t)))
        r = canon_reg(t)
        if r is not None:
            return Reg(r)
        m2 = re.match(r"^4\*cr(\d)\+(lt|gt|eq|so|un)$", t)
        if m2:
            return Reg(f"cr{m2.group(1)}")
    if kind in ("r", "a", "f", "v", "s", "c"):
        r = _reg_of(t, kind)
        if r is not None:
            if kind == "a" and r == "r0":
                return Reg("r0")
            return Reg(r)
    if kind in ("i", "t"):
        try:
            return Imm(parse_int(t))
        except ValueError:
            return Sym(t)
    r = canon_reg(t)
    if r is not None:
        return Reg(r)
    try:
        return Imm(parse_int(t))
    except ValueError:
        return Sym(t)


def make_insn(address: int, mnemonic: str, op_str: str = "", mode: Mode = Mode.PPC64, size: int = 4) -> Insn:
    d = normalize_mnemonic(mnemonic)
    toks = split_operands(op_str)
    kinds = operand_kinds(d.base, len(toks))
    if len(kinds) < len(toks):
        kinds = kinds + ["i"] * (len(toks) - len(kinds))
    ops = [parse_operand(t, k) for t, k in zip(toks, kinds)]
    if len(ops) == 3 and kinds[:3] == [kinds[0], "a", "r"] and isinstance(ops[1], (Reg, Imm)) and isinstance(ops[2], Reg) and kinds[0] in ("r", "f", "v", "s"):
        base = None if (isinstance(ops[1], Imm) or ops[1].name == "r0") else ops[1].name
        ops = [ops[0], Mem(base, 0, ops[2].name)]
    elif len(ops) == 2 and kinds[:2] == ["a", "r"]:
        ops = []
    return canonicalize(Insn(address, d.base, ops, size, d.record, f"{mnemonic} {op_str}".strip()), mode)


# --------------------------------------------------------------------------
# canonicalization
# --------------------------------------------------------------------------

_BCC_COND_OF_BIT = {0: "lt", 1: "gt", 2: "eq", 3: "so"}


def canonicalize(insn: Insn, mode: Mode) -> Insn:
    from .isa_ppc import _bcc_stem  # noqa: WPS450

    m, ops = insn.mnemonic, insn.ops
    n = len(ops)
    R, I = Reg, Imm

    def imm(i: int) -> int:
        return ops[i].value if isinstance(ops[i], Imm) else 0

    if n == 3 and m in ("slwi", "srwi", "clrlwi", "clrrwi", "rotlwi", "rotrwi"):
        k = imm(2)
        sh, mb, me = {"slwi": (k, 0, 31 - k), "srwi": (32 - k, k, 31), "clrlwi": (0, k, 31), "clrrwi": (0, 0, 31 - k),
                      "rotlwi": (k, 0, 31), "rotrwi": (32 - k, 0, 31)}[m]
        insn.mnemonic, insn.ops = "rlwinm", [ops[0], ops[1], I(sh % 32), I(mb), I(me)]
    elif n == 4 and m in ("extrwi", "extlwi", "clrlslwi", "inslwi", "insrwi"):
        a, b = imm(2), imm(3)
        if m == "extrwi":
            insn.mnemonic, insn.ops = "rlwinm", [ops[0], ops[1], I((b + a) % 32), I(32 - a), I(31)]
        elif m == "extlwi":
            insn.mnemonic, insn.ops = "rlwinm", [ops[0], ops[1], I(b), I(0), I(a - 1)]
        elif m == "clrlslwi":
            insn.mnemonic, insn.ops = "rlwinm", [ops[0], ops[1], I(b), I(a - b), I(31 - b)]
        elif m == "inslwi":
            insn.mnemonic, insn.ops = "rlwimi", [ops[0], ops[1], I((32 - b) % 32), I(b), I(b + a - 1)]
        else:
            insn.mnemonic, insn.ops = "rlwimi", [ops[0], ops[1], I((32 - (b + a)) % 32), I(b), I(b + a - 1)]
    elif n == 3 and m in ("sldi", "srdi", "clrldi", "clrrdi", "rotldi", "rotrdi"):
        k = imm(2)
        if m == "sldi":
            insn.mnemonic, insn.ops = "rldicr", [ops[0], ops[1], I(k), I(63 - k)]
        elif m == "srdi":
            insn.mnemonic, insn.ops = "rldicl", [ops[0], ops[1], I((64 - k) % 64), I(k)]
        elif m == "clrldi":
            insn.mnemonic, insn.ops = "rldicl", [ops[0], ops[1], I(0), I(k)]
        elif m == "clrrdi":
            insn.mnemonic, insn.ops = "rldicr", [ops[0], ops[1], I(0), I(63 - k)]
        elif m == "rotldi":
            insn.mnemonic, insn.ops = "rldicl", [ops[0], ops[1], I(k), I(0)]
        else:
            insn.mnemonic, insn.ops = "rldicl", [ops[0], ops[1], I((64 - k) % 64), I(0)]
    elif n == 4 and m in ("extrdi", "extldi", "clrlsldi", "insrdi"):
        a, b = imm(2), imm(3)
        if m == "extrdi":
            insn.mnemonic, insn.ops = "rldicl", [ops[0], ops[1], I((b + a) % 64), I(64 - a)]
        elif m == "extldi":
            insn.mnemonic, insn.ops = "rldicr", [ops[0], ops[1], I(b), I(a - 1)]
        elif m == "clrlsldi":
            insn.mnemonic, insn.ops = "rldic", [ops[0], ops[1], I(b), I(a - b)]
        else:
            insn.mnemonic, insn.ops = "rldimi", [ops[0], ops[1], I((64 - (b + a)) % 64), I(b)]
    elif m in ("rotlw", "rotld") and n == 3:
        insn.mnemonic, insn.ops = ("rlwnm", [ops[0], ops[1], ops[2], I(0), I(31)]) if m == "rotlw" else ("rldcl", [ops[0], ops[1], ops[2], I(0)])
    elif m == "sub" and n == 3:
        insn.mnemonic, insn.ops = "subf", [ops[0], ops[2], ops[1]]
    elif m == "subc" and n == 3:
        insn.mnemonic, insn.ops = "subfc", [ops[0], ops[2], ops[1]]
    elif m in ("subi", "subis", "subic") and n == 3 and isinstance(ops[2], Imm):
        insn.mnemonic, insn.ops = {"subi": "addi", "subis": "addis", "subic": "addic"}[m], [ops[0], ops[1], I(-ops[2].value)]
    elif m in ("addi", "addis") and n == 3 and isinstance(ops[1], Reg) and ops[1].name == "r0":
        insn.mnemonic, insn.ops = ("li" if m == "addi" else "lis"), [ops[0], ops[2]]
    elif m == "la" and n == 2 and isinstance(ops[1], Mem):
        insn.mnemonic, insn.ops = "addi", [ops[0], R(ops[1].base or "r0"), I(ops[1].disp)]
    elif m == "or" and n == 3 and isinstance(ops[1], Reg) and ops[1] == ops[2]:
        insn.mnemonic, insn.ops = "mr", [ops[0], ops[1]]
    elif m == "nor" and n == 3 and ops[1] == ops[2]:
        insn.mnemonic, insn.ops = "not", [ops[0], ops[1]]
    elif m == "not" and n == 2:
        insn.mnemonic, insn.ops = "nor", [ops[0], ops[1], ops[1]]
    elif m == "ori" and n == 3 and isinstance(ops[0], Reg) and ops[0].name == "r0" and ops == [R("r0"), R("r0"), I(0)]:
        insn.mnemonic, insn.ops = "nop", []
    elif m in ("bt", "bf") and n == 2 and isinstance(ops[0], Reg):
        insn.mnemonic, insn.ops = "bcc", [ops[0], ops[1]]
    elif m in ("bta", "bfa", "btl", "bfl") and n == 2:
        insn.mnemonic, insn.ops = ("bccl" if m.endswith("l") else "bcc"), [ops[0], ops[1]]
    elif m in ("btlr", "bflr", "btctr", "bfctr") and n == 1:
        insn.mnemonic = "bcclr" if "lr" in m else "bccctr"
    elif m in ("btlrl", "bflrl", "btctrl", "bfctrl") and n == 1:
        insn.mnemonic = "bcclrl" if "lr" in m else "bccctrl"
    elif m in ("bc", "bca", "bcl", "bcla") and n == 3:
        bo = imm(0)
        cr = ops[1] if isinstance(ops[1], Reg) else R(crbit_field(imm(1)))
        if bo & 0x10 and bo & 0x04:
            insn.mnemonic, insn.ops = ("bl" if m.endswith("l") else "b"), [ops[2]]
        elif bo & 0x10:
            insn.mnemonic, insn.ops = "bdnz", [ops[2]]
        else:
            insn.mnemonic, insn.ops = ("bccl" if m.endswith("l") else "bcc"), [cr, ops[2]]
    elif m in ("bclr", "bcctr", "bclrl", "bcctrl") and n >= 2:
        bo = imm(0)
        cr = ops[1] if isinstance(ops[1], Reg) else R(crbit_field(imm(1)))
        if bo & 0x10 and bo & 0x04:
            insn.mnemonic, insn.ops = {"bclr": "blr", "bcctr": "bctr", "bclrl": "blrl", "bcctrl": "bctrl"}[m], []
        else:
            insn.mnemonic, insn.ops = {"bclr": "bcclr", "bcctr": "bccctr", "bclrl": "bcclrl", "bcctrl": "bccctrl"}[m], [cr]
    elif _bcc_stem(m):
        stem = _bcc_stem(m)
        tail = m[1 + len(stem):]
        cr = next((o for o in ops if isinstance(o, Reg) and o.name.startswith("cr")), R("cr0"))
        tgt = [o for o in ops if isinstance(o, Imm)]
        if tail in ("lr", "lrl"):
            insn.mnemonic, insn.ops = ("bcclrl" if tail == "lrl" else "bcclr"), [cr]
        elif tail in ("ctr", "ctrl"):
            insn.mnemonic, insn.ops = ("bccctrl" if tail == "ctrl" else "bccctr"), [cr]
        else:
            insn.mnemonic, insn.ops = ("bccl" if tail in ("l", "la") else "bcc"), [cr] + tgt[:1]
    elif m in ("bdnz", "bdz", "bdnza", "bdza", "bdnzl", "bdzl", "bdnzt", "bdnzf", "bdzt", "bdzf"):
        insn.mnemonic, insn.ops = ("bdnz" if not m.endswith("l") else "bdnzl"), [o for o in ops if isinstance(o, Imm)][-1:]
    elif m in ("bdnzlr", "bdzlr"):
        insn.mnemonic, insn.ops = "bcclr", [R("cr0")]
    elif m == "isel" and n == 4:
        cr = ops[3]
        if isinstance(cr, Imm):
            cr = R(crbit_field(cr.value))
        insn.ops = [ops[0], ops[1], ops[2], cr]
    elif m.startswith("isel") and n == 3:
        insn.mnemonic, insn.ops = "isel", [ops[0], ops[1], ops[2], R("cr0")]
    elif m == "mtspr" and n == 2 and isinstance(ops[0], Imm) and ops[0].value in SPR:
        insn.mnemonic, insn.ops = "mt" + SPR[ops[0].value], [ops[1]]
    elif m == "mfspr" and n == 2 and isinstance(ops[1], Imm) and ops[1].value in SPR:
        insn.mnemonic, insn.ops = "mf" + SPR[ops[1].value], [ops[0]]
    elif m == "mtcr" and n == 1:
        insn.mnemonic, insn.ops = "mtcrf", [I(0xFF), ops[0]]
    elif m in ("crclr", "crset", "crmove", "crnot"):
        insn.mnemonic = "crlogic"
    elif m in ("crand", "cror", "crxor", "crnor", "creqv", "crandc", "crorc", "crnand"):
        insn.mnemonic = "crlogic"
    elif m.startswith(("tw", "td")) and m not in ("tw", "td"):
        insn.mnemonic, insn.ops = "trap", []
    insn.ops = [Mem(None, o.disp, o.index) if isinstance(o, Mem) and o.base == "r0" else o for o in insn.ops]
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


def from_listing(text: str, mode: Mode = Mode.PPC64, base: int = 0x10000) -> Iterator[Insn]:
    """Hand-written listing (symbolic r3/cr7 or numeric operands), #/; comments."""
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
        yield make_insn(pc, mnem, ops, mode=mode)
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
    return int(m.group("addr"), 16), sum(len(t) // 2 for t in raw), " ".join(f.strip() for f in fields[1:] if f.strip())


def from_objdump(text: str, mode: Mode = Mode.PPC64) -> Iterator[Insn]:
    """Parse objdump -d / llvm-objdump -d output."""
    for line in text.splitlines():
        r = _row(line)
        if r is None:
            continue
        addr, nbytes, rest = r
        rest = re.sub(r"\s*(?:#|;|//).*$", "", rest)
        if not rest or rest.startswith((".long", ".word", ".quad", "<unknown>", ".byte", ".short")):
            continue
        mnem, ops = _split_mnem_ops(rest)
        yield make_insn(addr, mnem, ops, mode=mode, size=nbytes)


def from_capstone(code: bytes, mode: Mode = Mode.PPC64, base: int = 0x10000, little: bool = False) -> Iterator[Insn]:
    """Disassemble with Capstone."""
    import capstone as cs
    from capstone import ppc

    from .isa_ppc import FP_LOAD, FP_STORE, LOAD, STORE

    _XFORM = frozenset(k for k in list(LOAD) + list(STORE) if k.endswith("x")) | \
             frozenset(k for k in FP_LOAD | FP_STORE if k.endswith("x") or k.startswith(("lv", "stv"))) | \
             frozenset({"lwarx", "ldarx", "stwcx", "stdcx", "lhbrx", "lwbrx", "ldbrx", "sthbrx", "stwbrx", "stdbrx"})
    _CACHE = frozenset({"dcbt", "dcbtst", "dcbz", "dcbf", "dcbst", "dcbi", "icbi", "dcba"})

    md = cs.Cs(cs.CS_ARCH_PPC, (cs.CS_MODE_32 if mode is Mode.PPC32 else cs.CS_MODE_64)
               | (cs.CS_MODE_LITTLE_ENDIAN if little else cs.CS_MODE_BIG_ENDIAN))
    md.detail = True
    md.skipdata = True
    for i in md.disasm(code, base):
        if i.id == 0:
            yield Insn(i.address, "nop", [], i.size, False, ".byte")
            continue
        d = normalize_mnemonic(i.mnemonic)
        ops: List = []
        for o in i.operands:
            if o.type == ppc.PPC_OP_REG:
                if o.reg == 0:
                    ops.append(Imm(0))
                else:
                    name = i.reg_name(o.reg) or ""
                    ops.append(Reg(canon_reg(name) or name))
            elif o.type == ppc.PPC_OP_IMM:
                ops.append(Imm(o.imm))
            elif o.type == ppc.PPC_OP_MEM:
                ops.append(Mem(canon_reg(i.reg_name(o.mem.base)) if o.mem.base else None, o.mem.disp))
            elif o.type == ppc.PPC_OP_CRX:
                ops.append(Reg(canon_reg(i.reg_name(o.crx.reg)) or "cr0"))
        if d.base in _XFORM and len(ops) == 3 and isinstance(ops[2], Reg):
            base_r = ops[1].name if isinstance(ops[1], Reg) else None
            ops = [ops[0], Mem(base_r, 0, ops[2].name)]
        elif d.base in _CACHE and len(ops) == 2:
            ops = []
        yield canonicalize(Insn(i.address, d.base, ops, i.size, d.record, f"{i.mnemonic} {i.op_str}"), mode)
