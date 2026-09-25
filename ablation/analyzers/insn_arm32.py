"""Instruction representation, UAL parser, and instruction-stream backends for ARM32/Thumb-2.

Merges armtaint/insn.py and armtaint/backends.py into one module following the
insn_x86.py pattern. Both instruction sets share one parser; the backends
(from_listing, from_objdump, from_capstone) use a ``mode`` parameter to
distinguish ARM state (A32) from Thumb state (T32).
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple, Union

from .isa_arm32 import Mode, canon_reg, normalize_mnemonic, reg_info

_SYM_SUFFIX = re.compile(r"\s*<[^>]*>\s*$")
_COMMENT = re.compile(r"\s*(?:@|//|;).*$")
SHIFT_TYPES = ("lsl", "lsr", "asr", "ror", "rrx")


@dataclass(frozen=True)
class Reg:
    name: str
    shift: Optional[str] = None
    shift_imm: Optional[int] = None
    shift_reg: Optional[str] = None
    subtracted: bool = False

    def __str__(self) -> str:
        s = ("-" if self.subtracted else "") + self.name
        if self.shift:
            s += f", {self.shift}" + (f" #{self.shift_imm}" if self.shift_imm is not None else f" {self.shift_reg}" if self.shift_reg else "")
        return s


@dataclass(frozen=True)
class Imm:
    value: int

    def __str__(self) -> str:
        return f"#{self.value:#x}" if self.value >= 0 else f"#-{-self.value:#x}"


@dataclass(frozen=True)
class Mem:
    base: Optional[str] = None
    index: Optional[str] = None
    disp: int = 0
    shift: Optional[str] = None
    shift_imm: int = 0
    subtracted: bool = False
    writeback: bool = False
    post: bool = False
    size: int = 0

    def __str__(self) -> str:
        inner = self.base or ""
        off = ""
        if self.index:
            off = ("-" if self.subtracted else "") + self.index + (f", {self.shift} #{self.shift_imm}" if self.shift else "")
        elif self.disp:
            off = f"#{self.disp:#x}" if self.disp >= 0 else f"#-{-self.disp:#x}"
        if self.post:
            return f"[{inner}], {off}" if off else f"[{inner}]"
        s = f"[{inner}, {off}]" if off else f"[{inner}]"
        return s + ("!" if self.writeback else "")


@dataclass(frozen=True)
class RegList:
    regs: Tuple[str, ...]

    def __str__(self) -> str:
        return "{" + ", ".join(self.regs) + "}"


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
    sets_flags: bool = False
    raw: str = ""
    literal: Optional[int] = None
    writeback: bool = False

    @property
    def next_ip(self) -> int:
        return self.address + self.size

    def reg(self, i: int) -> Optional[str]:
        return self.ops[i].name if i < len(self.ops) and isinstance(self.ops[i], Reg) else None

    def imm(self, i: int) -> Optional[int]:
        return self.ops[i].value if i < len(self.ops) and isinstance(self.ops[i], Imm) else None

    def mem(self, i: int) -> Optional[Mem]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], Mem) else None

    def reglist(self, i: int) -> Optional[RegList]:
        return self.ops[i] if i < len(self.ops) and isinstance(self.ops[i], RegList) else None

    @property
    def conditional(self) -> bool:
        return self.cond is not None

    def __str__(self) -> str:
        m = self.mnemonic + ("s" if self.sets_flags and self.mnemonic not in ("cmp", "cmn", "tst", "teq") else "") + (self.cond or "")
        return f"{self.address:#x}: {m} {', '.join(map(str, self.ops))}".rstrip()


# ---------------------------------------------------------------------------
# UAL text parsing
# ---------------------------------------------------------------------------

def parse_int(tok: str) -> int:
    t = tok.strip().lower().lstrip("#")
    neg = t.startswith("-")
    t = t.lstrip("+-")
    v = int(t, 0)
    return -v if neg else v


def split_operands(s: str) -> List[str]:
    s = _SYM_SUFFIX.sub("", _COMMENT.sub("", s.strip()))
    if not s:
        return []
    out, depth, cur = [], 0, []
    for ch in s:
        depth += ch in "[{("
        depth -= ch in "]})"
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return [o for o in out if o]


_REG_NUM = re.compile(r"^([a-z]+?)(\d+)$")


def _reg_index(canon: str) -> Tuple[str, int]:
    n = {"sp": "r13", "lr": "r14", "pc": "r15"}.get(canon, canon)
    m = _REG_NUM.match(n)
    return m.group(1), int(m.group(2))


def parse_reglist(tok: str) -> Optional[RegList]:
    t = tok.strip()
    if not (t.startswith("{") and t.endswith("}")):
        return None
    regs: List[str] = []
    for part in t[1:-1].split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (reg_info(p.strip()) for p in part.split("-", 1))
            if a is None or b is None:
                return None
            (pa, ia), (pb, ib) = _reg_index(a.name), _reg_index(b.name)
            if pa != pb or ib < ia:
                return None
            regs += [canon_reg(f"{pa}{i}") for i in range(ia, ib + 1)]
        else:
            ri = reg_info(part)
            if ri is None:
                return None
            regs.append(ri.name)
    return RegList(tuple(regs))


def parse_shift(tok: str) -> Optional[Tuple[str, Optional[int], Optional[str]]]:
    t = tok.strip().lower()
    m = re.match(r"^(lsl|lsr|asr|ror)\s+(#?-?(?:0x[0-9a-f]+|\d+)|[a-z]\w*)$", t)
    if m:
        amt = m.group(2)
        if amt.lstrip("#").lstrip("-").replace("0x", "").isalnum() and (amt.startswith("#") or amt[0].isdigit()):
            return m.group(1), parse_int(amt), None
        ri = reg_info(amt)
        return (m.group(1), None, ri.name) if ri else None
    if t == "rrx":
        return "rrx", None, None
    return None


_MEM_RE = re.compile(r"^\[(?P<body>[^\]]*)\](?P<wb>!)?$")


def parse_mem(tok: str, post_tok: Optional[str] = None, mode: Mode = Mode.ARM) -> Optional[Mem]:
    m = _MEM_RE.match(tok.strip())
    if not m:
        return None
    parts = [p.strip() for p in m.group("body").split(",")]
    base = reg_info(parts[0]) if parts and parts[0] else None
    if base is None:
        return None
    mem = Mem(base=base.name, writeback=bool(m.group("wb")))
    offs = parts[1:]
    post = False
    if post_tok is not None:
        offs = [p.strip() for p in post_tok.split(",")]
        post = True
    if not offs:
        return mem
    o = offs[0]
    if o.startswith("#") or re.match(r"^[-+]?(0x[0-9a-fA-F]+|\d+)$", o):
        return Mem(base.name, None, parse_int(o), None, 0, False, mem.writeback or post, post)
    sub = o.startswith("-")
    ri = reg_info(o.lstrip("+-"))
    if ri is None:
        return None
    sh, shimm = None, 0
    if len(offs) > 1:
        ps = parse_shift(offs[1])
        if ps is None or ps[1] is None:
            return None
        sh, shimm = ps[0], ps[1]
    return Mem(base.name, ri.name, 0, sh, shimm, sub, mem.writeback or post, post)


def parse_operands(tokens: List[str], mode: Mode = Mode.ARM) -> List[Operand]:
    ops: List[Operand] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        tl = t.lower()
        ps = parse_shift(tl)
        if ps is not None and ops and isinstance(ops[-1], Reg):
            r = ops[-1]
            ops[-1] = Reg(r.name, ps[0], ps[1], ps[2], r.subtracted)
            i += 1
            continue
        rl = parse_reglist(t)
        if rl is not None:
            ops.append(rl)
            i += 1
            continue
        if t.startswith("["):
            post = None
            if not t.rstrip().endswith("!") and i + 1 < len(tokens) and re.match(r"^(#|[-+]?(0x[0-9a-fA-F]+|\d+$)|[-+]?[a-z]\w*$)", tokens[i + 1].lower()) \
                    and not parse_shift(tokens[i + 1]) and parse_reglist(tokens[i + 1]) is None and not tokens[i + 1].startswith("["):
                nxt = tokens[i + 1]
                if i + 2 < len(tokens) and parse_shift(tokens[i + 2]):
                    nxt = nxt + ", " + tokens[i + 2]
                    i += 1
                post = nxt
                i += 1
            mem = parse_mem(t, post, mode)
            ops.append(mem if mem is not None else Sym(t))
            i += 1
            continue
        sub = tl.startswith("-") and reg_info(tl[1:]) is not None
        wb = tl.endswith("!")
        ri = reg_info(tl[1:] if sub else tl.rstrip("!"))
        if ri is not None:
            ops.append(Reg(ri.name, subtracted=sub))
            if wb:
                ops[-1] = Reg(ri.name, "!", None, None, sub)
        else:
            try:
                ops.append(Imm(parse_int(t)))
            except ValueError:
                ops.append(Sym(t))
        i += 1
    return ops


_BRANCHES = frozenset({"b", "bl", "blx", "cbz", "cbnz"})


def make_insn(address: int, mnemonic: str, op_str: str = "", mode: Mode = Mode.ARM, size: int = 0) -> Insn:
    d = normalize_mnemonic(mnemonic)
    if d.base in ("it",) or d.base.startswith("it"):
        return Insn(address, d.base, [], size or (2 if mode is Mode.THUMB else 4), None, False, op_str)
    tokens = split_operands(op_str)
    if d.base in _BRANCHES and tokens and re.match(r"^[0-9a-fA-F]+$", tokens[-1].strip()):
        tokens[-1] = "0x" + tokens[-1].strip()
    ops = parse_operands(tokens, mode)
    ops = [Imm(o.value - (1 << 32)) if isinstance(o, Imm) and 0x80000000 <= o.value < (1 << 32) else o for o in ops]
    wb = any(isinstance(o, Reg) and o.shift == "!" for o in ops)
    ops = [Reg(o.name, subtracted=o.subtracted) if isinstance(o, Reg) and o.shift == "!" else o for o in ops]
    if not size:
        size = 4 if mode is Mode.ARM else (2 if d.width == ".n" else 4)
    return canonicalize(Insn(address, d.base, ops, size, d.cond, d.sets_flags, op_str, writeback=wb))


def literal_address(insn: Insn, mem: Mem, mode: Mode) -> Optional[int]:
    if mem.base == "pc" and mem.index is None:
        return (mode.pc_value(insn.address, insn.size, align=True) + mem.disp) & 0xFFFFFFFF
    return None


def canonicalize(insn: Insn) -> Insn:
    m, ops = insn.mnemonic, insn.ops
    if m == "adr" and len(ops) == 2 and isinstance(ops[1], Imm):
        insn.mnemonic, insn.ops = "add", [ops[0], Reg("pc"), ops[1]]
    elif m == "ldr" and len(ops) == 2 and isinstance(ops[1], Mem) and ops[1].base == "sp" and ops[1].post \
            and ops[1].index is None and ops[1].disp == 4:
        insn.mnemonic, insn.ops = "pop", [RegList((ops[0].name,))]
    elif m == "str" and len(ops) == 2 and isinstance(ops[1], Mem) and ops[1].base == "sp" and ops[1].writeback \
            and not ops[1].post and ops[1].index is None and ops[1].disp == -4:
        insn.mnemonic, insn.ops = "push", [RegList((ops[0].name,))]
    elif m == "ldmia" and insn.writeback and len(ops) == 2 and isinstance(ops[0], Reg) and ops[0].name == "sp":
        insn.mnemonic, insn.ops, insn.writeback = "pop", [ops[1]], False
    elif m == "stmdb" and insn.writeback and len(ops) == 2 and isinstance(ops[0], Reg) and ops[0].name == "sp":
        insn.mnemonic, insn.ops, insn.writeback = "push", [ops[1]], False
    elif (m == "mov" or m in ("lsl", "lsr", "asr", "ror", "rrx")) and len(ops) == 2 and isinstance(ops[1], Reg) and ops[1].shift:
        src = ops[1]
        if src.shift == "rrx":
            insn.mnemonic, insn.ops = "rrx", [ops[0], Reg(src.name)]
        elif src.shift_reg is not None:
            insn.mnemonic, insn.ops = src.shift, [ops[0], Reg(src.name), Reg(src.shift_reg)]
        else:
            insn.mnemonic, insn.ops = src.shift, [ops[0], Reg(src.name), Imm(src.shift_imm or 0)]
    if not insn.mnemonic.startswith(("ldm", "stm", "vldm", "vstm")):
        insn.writeback = False
    return insn


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

_LISTING_RE = re.compile(r"^\s*(?:(?P<addr>0x[0-9a-fA-F]+|[0-9a-fA-F]+):)?\s*(?P<text>[a-zA-Z].*?)\s*$")


def _split_mnem_ops(text: str) -> Tuple[str, str]:
    parts = text.strip().split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def _attach_literal(insn: Insn, words: Optional[Dict[int, int]], mode: Mode) -> None:
    if not words or insn.mnemonic != "ldr":
        return
    mem = insn.mem(1)
    if mem is None:
        return
    a = literal_address(insn, mem, mode)
    if a is not None and a in words:
        insn.literal = words[a]


def from_listing(text: str, mode: Mode = Mode.ARM, base: int = 0x10000) -> Iterator[Insn]:
    """Hand-written UAL listing, one instruction per line."""
    pc = base
    for line in text.splitlines():
        s = re.split(r"(?:@|//|;)", line, 1)[0].strip()
        if not s or re.match(r"^[A-Za-z_.$][\w.$]*:$", s) or s.startswith("."):
            continue
        m = _LISTING_RE.match(s)
        if not m:
            continue
        if m.group("addr"):
            pc = int(m.group("addr"), 16)
        mnem, ops = _split_mnem_ops(m.group("text"))
        insn = make_insn(pc, mnem, ops, mode=mode)
        yield insn
        pc += insn.size


_ROW_RE = re.compile(r"^\s*(?P<addr>[0-9a-fA-F]+):(?P<rest>.*)$")
_HEXGROUP = re.compile(r"^[0-9a-fA-F]{2,8}$")


def _split_row(line: str) -> Optional[tuple]:
    m = _ROW_RE.match(line)
    if not m:
        return None
    fields = [f for f in m.group("rest").split("\t")]
    if len(fields) < 2:
        return None
    raw = fields[0].split()
    if not raw or not all(_HEXGROUP.match(t) for t in raw):
        return None
    text = " ".join(f.strip() for f in fields[1:] if f.strip())
    return int(m.group("addr"), 16), sum(len(t) // 2 for t in raw), raw, text


def from_objdump(text: str, mode: Mode = Mode.ARM) -> Iterator[Insn]:
    """Parse ``objdump -d`` / ``llvm-objdump -d`` output."""
    words: Dict[int, int] = {}
    rows: List[tuple] = []
    for line in text.splitlines():
        r = _split_row(line)
        if r is None:
            continue
        addr, nbytes, raw, rest = r
        if rest.startswith((".word", ".long")):
            words[addr] = int(rest.split()[1].rstrip(","), 0) & 0xFFFFFFFF
            continue
        if not rest or rest.startswith(("<unknown>", ".short", ".byte", ".inst")):
            if nbytes == 4 and len(raw) == 1:
                words[addr] = int(raw[0], 16)
            continue
        rows.append((addr, nbytes, rest))
    for addr, nbytes, rest in rows:
        rest = re.sub(r"\s*(?:@|;|//).*$", "", rest)
        mnem, ops_str = _split_mnem_ops(rest)
        insn = make_insn(addr, mnem, ops_str, mode=mode, size=nbytes)
        _attach_literal(insn, words, mode)
        yield insn


_CANON_NAMES = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12", "r13": "sp", "r14": "lr", "r15": "pc"}


def _canon(name: str) -> str:
    return _CANON_NAMES.get(name, name)


def from_capstone(code: bytes, mode: Mode = Mode.ARM, base: int = 0x10000) -> Iterator[Insn]:
    """Disassemble with Capstone, building operands from structured detail."""
    import capstone as cs
    from capstone import arm

    sft = {arm.ARM_SFT_LSL: "lsl", arm.ARM_SFT_LSR: "lsr", arm.ARM_SFT_ASR: "asr", arm.ARM_SFT_ROR: "ror",
           arm.ARM_SFT_RRX: "rrx", arm.ARM_SFT_LSL_REG: "lsl", arm.ARM_SFT_LSR_REG: "lsr",
           arm.ARM_SFT_ASR_REG: "asr", arm.ARM_SFT_ROR_REG: "ror", arm.ARM_SFT_RRX_REG: "rrx"}
    by_reg = {arm.ARM_SFT_LSL_REG, arm.ARM_SFT_LSR_REG, arm.ARM_SFT_ASR_REG, arm.ARM_SFT_ROR_REG, arm.ARM_SFT_RRX_REG}
    md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM if mode is Mode.ARM else cs.CS_MODE_THUMB)
    md.detail = True
    words = {base + i: struct.unpack_from("<I", code, i)[0] for i in range(0, len(code) - 3, 2)}

    for i in md.disasm(code, base):
        d = normalize_mnemonic(i.mnemonic)
        ops: List = []
        for o in i.operands:
            if o.type == arm.ARM_OP_REG:
                name = i.reg_name(o.reg)
                sh = sft.get(o.shift.type) if o.shift.type else None
                if sh and o.shift.type in by_reg:
                    ops.append(Reg(_canon(name), sh, None, _canon(i.reg_name(o.shift.value)), bool(o.subtracted)))
                else:
                    ops.append(Reg(_canon(name), sh, o.shift.value if sh and sh != "rrx" else None, None, bool(o.subtracted)))
            elif o.type == arm.ARM_OP_IMM:
                ops.append(Imm(-o.imm if o.subtracted else o.imm))
            elif o.type == arm.ARM_OP_MEM:
                sh = sft.get(o.shift.type) if o.shift.type else ("lsl" if o.mem.lshift else None)
                ops.append(Mem(
                    base=_canon(i.reg_name(o.mem.base)) if o.mem.base else None,
                    index=_canon(i.reg_name(o.mem.index)) if o.mem.index else None,
                    disp=o.mem.disp, shift=sh, shift_imm=(o.shift.value if o.shift.type else o.mem.lshift) or 0,
                    subtracted=bool(o.subtracted) or o.mem.scale == -1,
                    writeback=bool(i.writeback) and not i.post_index, post=bool(i.post_index),
                ))
        if i.post_index and len(ops) >= 2 and isinstance(ops[-2], Mem) and isinstance(ops[-1], (Imm, Reg)):
            m_op, off = ops[-2], ops[-1]
            if isinstance(off, Imm):
                ops[-2:] = [Mem(m_op.base, None, off.value, None, 0, False, True, True)]
            else:
                ops[-2:] = [Mem(m_op.base, off.name, 0, off.shift, off.shift_imm or 0, off.subtracted, True, True)]
        if d.base in ("push", "pop", "vpush", "vpop") and ops:
            ops = [RegList(tuple(r.name for r in ops if isinstance(r, Reg)))]
        elif d.base.startswith(("ldm", "stm", "vldm", "vstm")) and len(ops) >= 2:
            ops = [ops[0], RegList(tuple(r.name for r in ops[1:] if isinstance(r, Reg)))]
        insn = canonicalize(Insn(i.address, d.base, ops, i.size, d.cond, d.sets_flags, f"{i.mnemonic} {i.op_str}", writeback=bool(i.writeback)))
        _attach_literal(insn, words, mode)
        yield insn
