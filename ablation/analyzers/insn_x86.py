"""Instruction representation, operand parsing, and backends for x86 / x86-64.

Intel syntax is the canonical text form. AT&T (objdump default) is converted
to Intel in :func:`att_to_intel` before parsing. Capstone builds operands
from its structured detail and never goes through the string parser.

Backends
--------
* :func:`from_listing`  -- hand-written Intel listing, ``#``/``;`` comments
* :func:`from_objdump`  -- ``objdump -d`` in AT&T or ``-M intel``
* :func:`from_capstone` -- Capstone bytes; requires ``capstone`` installed
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple, Union

from .isa_x86 import PREFIXES, Mode, SEGMENTS, normalize_mnemonic, reg_info

_SIZE_WORDS: Dict[str, int] = {
    "byte": 1, "word": 2, "dword": 4, "qword": 8, "tbyte": 10,
    "xmmword": 16, "ymmword": 32, "zmmword": 64, "oword": 16, "fword": 6,
}
_SYM_SUFFIX = re.compile(r"\s*<[^>]*>\s*$")
_COMMENT = re.compile(r"\s*#.*$")


@dataclass(frozen=True)
class Reg:
    name: str        # as written (eax, al, r8d ...), lower-case
    size: int = 0    # bytes, 0 = unknown

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Imm:
    value: int
    size: int = 0

    def __str__(self) -> str:
        return hex(self.value) if self.value >= 0 else f"-{-self.value:#x}"


@dataclass(frozen=True)
class Mem:
    base: Optional[str] = None
    index: Optional[str] = None
    scale: int = 1
    disp: int = 0
    size: int = 0    # access width in bytes, 0 = unknown
    seg: Optional[str] = None

    def __str__(self) -> str:
        parts = []
        if self.base:
            parts.append(self.base)
        if self.index:
            parts.append(f"{self.index}*{self.scale}" if self.scale != 1 else self.index)
        s = " + ".join(parts)
        if self.disp or not parts:
            s += (f" + {self.disp:#x}" if self.disp >= 0 else f" - {-self.disp:#x}") if parts else f"{self.disp:#x}"
        seg = f"{self.seg}:" if self.seg else ""
        return f"[{seg}{s}]"


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
    size: int = 0
    prefixes: Tuple[str, ...] = ()
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

    @property
    def rep(self) -> bool:
        return any(p.startswith("rep") for p in self.prefixes)

    def __str__(self) -> str:
        p = " ".join(self.prefixes) + " " if self.prefixes else ""
        return f"{self.address:#x}: {p}{self.mnemonic} {', '.join(map(str, self.ops))}".rstrip()


# --------------------------------------------------------------------------
# Intel-syntax parsing
# --------------------------------------------------------------------------

def parse_int(tok: str) -> int:
    t = tok.strip().lower()
    if t.endswith("h") and re.match(r"^[0-9][0-9a-f]*h$", t):
        return int(t[:-1], 16)
    return int(t, 0)


def split_operands(s: str) -> List[str]:
    s = _COMMENT.sub("", _SYM_SUFFIX.sub("", s.strip()))
    if not s:
        return []
    out, depth, cur = [], 0, []
    for ch in s:
        depth += ch in "[("
        depth -= ch in "])"
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return [o for o in out if o]


_ZERO_INDEX = re.compile(r"^(?:eiz|riz)(?:\*\d+)?$", re.I)
_MEM_INTEL = re.compile(r"^(?:(?P<size>\w+)\s+ptr\s+)?(?:(?P<seg>[cdefgs]s):)?\[(?P<body>[^\]]*)\]$", re.I)
_MEM_ABS = re.compile(r"^(?:(?P<size>\w+)\s+ptr\s+)?(?P<seg>[cdefgs]s):(?P<disp>-?(?:0x[0-9a-f]+|\d+))$", re.I)


def parse_mem_body(body: str, mode: Mode) -> Optional[Mem]:
    body = body.replace(" ", "")
    if not body:
        return None
    terms = re.findall(r"[+-]?[^+-]+", body)
    base = index = None
    scale, disp = 1, 0
    for t in terms:
        sign = -1 if t.startswith("-") else 1
        t = t.lstrip("+-")
        if _ZERO_INDEX.match(t):
            continue
        if "*" in t:
            a, b = t.split("*", 1)
            if reg_info(a, mode) and b.isdigit():
                index, scale = a, int(b)
            elif reg_info(b, mode) and a.isdigit():
                index, scale = b, int(a)
            else:
                return None
        elif reg_info(t, mode):
            if base is None:
                base = t
            elif index is None:
                index = t
            else:
                return None
        else:
            try:
                disp += sign * parse_int(t)
            except ValueError:
                return None
    return Mem(base, index, scale, disp)


def parse_operand(tok: str, mode: Mode) -> Operand:
    t = tok.strip()
    tl = t.lower()
    ri = reg_info(tl, mode)
    if ri is not None:
        return Reg(ri.name, ri.width // 8)
    m = _MEM_INTEL.match(t)
    if m:
        mem = parse_mem_body(m.group("body"), mode)
        if mem is not None:
            size = _SIZE_WORDS.get((m.group("size") or "").lower(), 0)
            seg = (m.group("seg") or "").lower() or None
            return Mem(mem.base, mem.index, mem.scale, mem.disp, size, seg)
    m = _MEM_ABS.match(t)
    if m:
        return Mem(None, None, 1, parse_int(m.group("disp")),
                   _SIZE_WORDS.get((m.group("size") or "").lower(), 0), m.group("seg").lower())
    try:
        return Imm(parse_int(t))
    except ValueError:
        return Sym(t)


_STRING_BARE = {"movs", "stos", "lods", "cmps", "scas"}
_SIZE_MISMATCH_OK = {
    "lea", "movzx", "movsx", "movsxd", "movd", "movq", "cvtsi2sd", "cvtsi2ss", "cvttsd2si",
    "cvttss2si", "cvtsd2si", "cvtss2si", "pinsrb", "pinsrw", "pinsrd", "pextrb", "pextrw",
    "pextrd", "crc32", "vmovd", "vmovq", "pmovmskb", "vpmovmskb",
}
_STRING_SUFFIX = {1: "b", 2: "w", 4: "d", 8: "q"}


def _operand_width(ops: List[Operand]) -> int:
    w = 0
    for o in ops:
        if isinstance(o, (Reg, Mem)) and o.size:
            w = max(w, o.size)
    return w


def make_insn(address: int, mnemonic: str, op_str: str = "", mode: Mode = Mode.X64, size: int = 0) -> Insn:
    prefixes, canon = normalize_mnemonic(mnemonic)
    ops = [parse_operand(t, mode) for t in split_operands(op_str)]
    # Sign-extend unsigned-rendered immediates ("and rsp,0xfffffffffffffff0")
    w = _operand_width(ops)
    if w >= 4:
        bits = 8 * w
        ops = [
            Imm(o.value - (1 << bits), o.size)
            if isinstance(o, Imm) and (1 << (bits - 1)) <= o.value < (1 << bits)
            else o
            for o in ops
        ]
    # Propagate register width to adjacent unsized memory operand
    if canon not in _SIZE_MISMATCH_OK and len(ops) == 2:
        regw = next((o.size for o in ops if isinstance(o, Reg) and o.size), 0)
        if regw:
            ops = [
                Mem(o.base, o.index, o.scale, o.disp, regw, o.seg)
                if isinstance(o, Mem) and not o.size else o
                for o in ops
            ]
    # Fold string-op width suffix and drop explicit operands (they are implicit)
    if canon in _STRING_BARE:
        mw = next((o.size for o in ops if isinstance(o, Mem) and o.size), 0)
        if mw in _STRING_SUFFIX:
            canon += _STRING_SUFFIX[mw]
        ops = []
    elif canon in {b + sfx for b in _STRING_BARE for sfx in "bwdq"}:
        ops = []
    return Insn(address, canon, ops, size, prefixes, op_str)


# --------------------------------------------------------------------------
# AT&T -> Intel conversion (objdump default output)
# --------------------------------------------------------------------------

_ATT_MEM = re.compile(r"^(?P<seg>%[cdefgs]s:)?(?P<disp>[-+]?(?:0x[0-9a-fA-F]+|\d+))?\((?P<inner>[^)]*)\)$")
_ATT_SUFFIX_SIZE = {"b": "byte", "w": "word", "l": "dword", "q": "qword"}
_ATT_MOVX = re.compile(r"^mov[sz]([bwl])[wlq]$")

# local copies so att_to_intel doesn't need to import from isa_x86
from .isa_x86 import _ATT_MNEM, _SUFFIXABLE  # noqa: E402


def att_operand_to_intel(tok: str, mem_size: str = "") -> str:
    t = tok.strip()
    indirect = t.startswith("*")
    if indirect:
        t = t[1:]
    if t.startswith("$"):
        return t[1:]
    if t.startswith("%") and "(" not in t:
        return t[1:]
    m = _ATT_MEM.match(t)
    if m:
        inner = [x.strip().lstrip("%") for x in m.group("inner").split(",")]
        base  = inner[0] if inner and inner[0] else None
        index = inner[1] if len(inner) > 1 and inner[1] else None
        scale = inner[2] if len(inner) > 2 and inner[2] else "1"
        parts = []
        if base:
            parts.append(base)
        if index:
            parts.append(f"{index}*{scale}")
        disp = m.group("disp")
        body = "+".join(parts)
        if disp:
            body = body + ("+" if body and not disp.startswith(("-", "+")) else "") + disp if body else disp
        seg = (m.group("seg") or "").lstrip("%")
        size = f"{mem_size} ptr " if mem_size else ""
        return f"{size}{seg}[{body}]" if seg else f"{size}[{body}]"
    m2 = re.match(r"^(%[cdefgs]s):(-?(?:0x[0-9a-fA-F]+|\d+))$", t)
    if m2:
        return f"{m2.group(1)[1:]}:{m2.group(2)}"
    if re.match(r"^-?(0x[0-9a-fA-F]+|\d+)$", t) and not indirect:
        return t
    if indirect:
        return f"[{t}]"
    return t


def att_to_intel(mnemonic: str, op_str: str) -> Tuple[str, str]:
    parts = mnemonic.split()
    base = parts[-1]
    raw_ops = split_operands(op_str)
    vector = any(re.search(r"%(xmm|ymm|zmm|mm|st)", o) for o in raw_ops)
    mem_size = ""
    m2 = _ATT_MOVX.match(base)
    if m2:
        mem_size = _ATT_SUFFIX_SIZE[m2.group(1)]
        base = _ATT_MNEM[base]
    elif base in _ATT_MNEM:
        base = _ATT_MNEM[base]
    elif (len(base) > 2 and base[-1] in _ATT_SUFFIX_SIZE and base[:-1] in _SUFFIXABLE
          and not vector and base[:-1] not in _STRING_BARE):
        mem_size = _ATT_SUFFIX_SIZE[base[-1]]
        base = base[:-1]
    ops = [att_operand_to_intel(o, mem_size) for o in reversed(raw_ops)]
    return " ".join(parts[:-1] + [base]), ", ".join(ops)


def looks_like_att(op_str: str) -> bool:
    return "%" in op_str or op_str.strip().startswith("$")


# --------------------------------------------------------------------------
# Effective-address helpers
# --------------------------------------------------------------------------

def rip_relative_target(insn: Insn, mem: Mem, mode: Mode) -> Optional[int]:
    if mem.base == mode.ip and mem.index is None:
        return (insn.next_ip + mem.disp) & ((1 << mode.bits) - 1)
    return None


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------

_OBJDUMP_RE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F]+):\s+(?P<bytes>(?:[0-9a-fA-F]{2}\s)+)\s*(?P<rest>\S.*)?$"
)
_LISTING_RE = re.compile(r"^\s*(?:(?P<addr>0x[0-9a-fA-F]+|[0-9a-fA-F]+):)?\s*(?P<text>[a-zA-Z].*?)\s*$")
_TARGET_MNEMS = frozenset({"call", "jmp", "loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz"})


def _split_mnem_ops(text: str) -> Tuple[str, str]:
    parts = text.strip().split(None, 1)
    words = parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    toks = [words]
    while rest and toks[-1] in PREFIXES:
        nxt = rest.split(None, 1)
        toks.append(nxt[0])
        rest = nxt[1] if len(nxt) > 1 else ""
    return " ".join(toks), rest


def from_listing(text: str, mode: Mode = Mode.X64, base: int = 0x10000, size: int = 4) -> Iterator[Insn]:
    """Hand-written Intel-syntax listing, one instruction per line."""
    pc = base
    for line in text.splitlines():
        s = re.split(r"[#;]", line, 1)[0].strip()
        if not s or re.match(r"^[A-Za-z_.$][\w.$]*:$", s):
            continue
        m = _LISTING_RE.match(s)
        if not m:
            continue
        if m.group("addr"):
            pc = int(m.group("addr"), 16)
        mnem, ops = _split_mnem_ops(m.group("text"))
        if looks_like_att(ops):
            mnem, ops = att_to_intel(mnem, ops)
        yield make_insn(pc, mnem, ops, mode=mode, size=size)
        pc += size


def from_objdump(text: str, mode: Mode = Mode.X64) -> Iterator[Insn]:
    """Parse ``objdump -d`` output in AT&T or ``-M intel`` syntax."""
    for line in text.splitlines():
        m = _OBJDUMP_RE.match(line)
        if not m or not m.group("rest"):
            continue
        addr = int(m.group("addr"), 16)
        size = len(m.group("bytes").split())
        rest = m.group("rest").split("#", 1)[0]
        rest = re.sub(r"<[^>]*>", "", rest).strip()
        if not rest or rest.startswith("("):
            continue
        mnem, ops = _split_mnem_ops(rest)
        if looks_like_att(ops):
            mnem, ops = att_to_intel(mnem, ops)
        _, canon = normalize_mnemonic(mnem)
        if (canon in _TARGET_MNEMS or canon.startswith("j")) and ops and re.match(r"^[0-9a-fA-F]+$", ops.strip()):
            ops = "0x" + ops.strip()
        yield make_insn(addr, mnem, ops, mode=mode, size=size)


def from_capstone(code: bytes, mode: Mode = Mode.X64, base: int = 0x10000) -> Iterator[Insn]:
    """Disassemble bytes with Capstone, building operands from structured detail."""
    import capstone as cs
    from capstone import x86

    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if mode is Mode.X64 else cs.CS_MODE_32)
    md.detail = True
    _string_mnems = {
        "movsb", "movsw", "movsd", "movsq", "stosb", "stosw", "stosd", "stosq",
        "lodsb", "lodsw", "lodsd", "lodsq", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
        "scasb", "scasw", "scasd", "scasq",
    }
    for i in md.disasm(code, base):
        prefixes, canon = normalize_mnemonic(i.mnemonic)
        ops: List[Operand] = []
        for o in i.operands:
            if o.type == x86.X86_OP_REG:
                ops.append(Reg(i.reg_name(o.reg), o.size))
            elif o.type == x86.X86_OP_IMM:
                ops.append(Imm(o.imm, o.size))
            elif o.type == x86.X86_OP_MEM:
                ops.append(Mem(
                    base=i.reg_name(o.mem.base) if o.mem.base else None,
                    index=i.reg_name(o.mem.index) if o.mem.index else None,
                    scale=o.mem.scale or 1,
                    disp=o.mem.disp,
                    size=o.size,
                    seg=i.reg_name(o.mem.segment) if o.mem.segment else None,
                ))
        if canon in _string_mnems and all(isinstance(o, (Mem, Reg)) for o in ops):
            ops = []
        yield Insn(i.address, canon, ops, i.size, prefixes, f"{i.mnemonic} {i.op_str}")
