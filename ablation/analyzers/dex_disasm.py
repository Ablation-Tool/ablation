"""
dex_disasm.py -- DEX bytecode disassembler (smali output).

Decodes all 17 DEX instruction formats and renders smali-style output.
Annotates method/field/type/string references with full descriptors from
the DEX flat tables.

Usage:
    from ablation.analyzers.dex_disasm import DEXDisasm
    from ablation.core.apk_parser import APKParser

    with APKParser.from_path('/path/to/app.apk') as apk:
        for dex in apk.iter_dex():
            dd = DEXDisasm(dex)
            # Disassemble one method
            smali = dd.disasm_method('Lcom/example/Foo;', 'bar')
            print(smali)
            # Disassemble all non-native methods in a class
            smali = dd.disasm_class('Lcom/example/Foo;')
            print(smali)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

from ablation.core.apk_parser import DEXFile, _uleb128  # type: ignore[attr-defined]


# ── Instruction formats → code unit sizes ─────────────────────────────────────
#
# DEX instructions are arrays of 16-bit code units. The opcode occupies the low
# byte of the first code unit. The format name encodes the layout:
#
#   "10x" → 1 code unit, no args
#   "11x" → 1 code unit, one 8-bit register (AA field)
#   "12x" → 1 code unit, two 4-bit registers (A=bits 8-11, B=bits 12-15)
#   "11n" → 1 code unit, 4-bit reg (A) + 4-bit literal (B)
#   "10t" → 1 code unit, 8-bit branch offset
#   "20t" → 2 code units, 16-bit branch offset
#   "22x" → 2 code units, 8-bit dest + 16-bit src
#   "21t" → 2 code units, 8-bit reg + 16-bit branch offset
#   "21s" → 2 code units, 8-bit reg + 16-bit signed literal
#   "21h" → 2 code units, 8-bit reg + 16-bit high literal
#   "21c" → 2 code units, 8-bit reg + 16-bit reference index
#   "23x" → 2 code units, three 8-bit registers
#   "22b" → 2 code units, 8-bit dst + 8-bit src + 8-bit literal
#   "22t" → 2 code units, two 4-bit regs + 16-bit branch offset
#   "22s" → 2 code units, two 4-bit regs + 16-bit signed literal
#   "22c" → 2 code units, two 4-bit regs + 16-bit reference index
#   "30t" → 3 code units, 32-bit branch offset
#   "31i" → 3 code units, 8-bit reg + 32-bit literal
#   "31t" → 3 code units, 8-bit reg + 32-bit branch offset
#   "31c" → 3 code units, 8-bit reg + 32-bit reference index
#   "32x" → 3 code units, two 16-bit registers
#   "35c" → 3 code units, 4-bit count + 4-bit reg + 16-bit ref + regs in word 3
#   "3rc" → 3 code units, 8-bit count + 16-bit ref + 16-bit first reg
#   "45cc"→ 4 code units, invoke-polymorphic variant
#   "4rcc"→ 4 code units, invoke-polymorphic/range variant
#   "51l" → 5 code units, 8-bit reg + 64-bit literal

_FMT_SIZE = {
    "10x": 1, "10t": 1,
    "11x": 1, "11n": 1,
    "12x": 1,
    "20t": 2, "20bc": 2,
    "22x": 2, "21t": 2, "21s": 2, "21h": 2, "21c": 2,
    "23x": 2, "22b": 2, "22t": 2, "22s": 2, "22c": 2, "22cs": 2,
    "30t": 3, "31i": 3, "31t": 3, "31c": 3, "32x": 3,
    "35c": 3, "35ms": 3, "35mi": 3,
    "3rc": 3, "3rms": 3, "3rmi": 3,
    "45cc": 4, "4rcc": 4,
    "51l": 5,
}

# ── Complete opcode table (opcode → (mnemonic, format)) ───────────────────────

_OPCODES: dict[int, tuple[str, str]] = {
    0x00: ("nop",                    "10x"),
    0x01: ("move",                   "12x"),
    0x02: ("move/from16",            "22x"),
    0x03: ("move/16",                "32x"),
    0x04: ("move-wide",              "12x"),
    0x05: ("move-wide/from16",       "22x"),
    0x06: ("move-wide/16",           "32x"),
    0x07: ("move-object",            "12x"),
    0x08: ("move-object/from16",     "22x"),
    0x09: ("move-object/16",         "32x"),
    0x0a: ("move-result",            "11x"),
    0x0b: ("move-result-wide",       "11x"),
    0x0c: ("move-result-object",     "11x"),
    0x0d: ("move-exception",         "11x"),
    0x0e: ("return-void",            "10x"),
    0x0f: ("return",                 "11x"),
    0x10: ("return-wide",            "11x"),
    0x11: ("return-object",          "11x"),
    0x12: ("const/4",                "11n"),
    0x13: ("const/16",               "21s"),
    0x14: ("const",                  "31i"),
    0x15: ("const/high16",           "21h"),
    0x16: ("const-wide/16",          "21s"),
    0x17: ("const-wide/32",          "31i"),
    0x18: ("const-wide",             "51l"),
    0x19: ("const-wide/high16",      "21h"),
    0x1a: ("const-string",           "21c"),
    0x1b: ("const-string/jumbo",     "31c"),
    0x1c: ("const-class",            "21c"),
    0x1d: ("monitor-enter",          "11x"),
    0x1e: ("monitor-exit",           "11x"),
    0x1f: ("check-cast",             "21c"),
    0x20: ("instance-of",            "22c"),
    0x21: ("array-length",           "12x"),
    0x22: ("new-instance",           "21c"),
    0x23: ("new-array",              "22c"),
    0x24: ("filled-new-array",       "35c"),
    0x25: ("filled-new-array/range", "3rc"),
    0x26: ("fill-array-data",        "31t"),
    0x27: ("throw",                  "11x"),
    0x28: ("goto",                   "10t"),
    0x29: ("goto/16",                "20t"),
    0x2a: ("goto/32",                "30t"),
    0x2b: ("packed-switch",          "31t"),
    0x2c: ("sparse-switch",          "31t"),
    0x2d: ("cmpl-float",             "23x"),
    0x2e: ("cmpg-float",             "23x"),
    0x2f: ("cmpl-double",            "23x"),
    0x30: ("cmpg-double",            "23x"),
    0x31: ("cmp-long",               "23x"),
    0x32: ("if-eq",                  "22t"),
    0x33: ("if-ne",                  "22t"),
    0x34: ("if-lt",                  "22t"),
    0x35: ("if-ge",                  "22t"),
    0x36: ("if-gt",                  "22t"),
    0x37: ("if-le",                  "22t"),
    0x38: ("if-eqz",                 "21t"),
    0x39: ("if-nez",                 "21t"),
    0x3a: ("if-ltz",                 "21t"),
    0x3b: ("if-gez",                 "21t"),
    0x3c: ("if-gtz",                 "21t"),
    0x3d: ("if-lez",                 "21t"),
    # 0x3e-0x43 unused
    0x44: ("aget",                   "23x"),
    0x45: ("aget-wide",              "23x"),
    0x46: ("aget-object",            "23x"),
    0x47: ("aget-boolean",           "23x"),
    0x48: ("aget-byte",              "23x"),
    0x49: ("aget-char",              "23x"),
    0x4a: ("aget-short",             "23x"),
    0x4b: ("aput",                   "23x"),
    0x4c: ("aput-wide",              "23x"),
    0x4d: ("aput-object",            "23x"),
    0x4e: ("aput-boolean",           "23x"),
    0x4f: ("aput-byte",              "23x"),
    0x50: ("aput-char",              "23x"),
    0x51: ("aput-short",             "23x"),
    0x52: ("iget",                   "22c"),
    0x53: ("iget-wide",              "22c"),
    0x54: ("iget-object",            "22c"),
    0x55: ("iget-boolean",           "22c"),
    0x56: ("iget-byte",              "22c"),
    0x57: ("iget-char",              "22c"),
    0x58: ("iget-short",             "22c"),
    0x59: ("iput",                   "22c"),
    0x5a: ("iput-wide",              "22c"),
    0x5b: ("iput-object",            "22c"),
    0x5c: ("iput-boolean",           "22c"),
    0x5d: ("iput-byte",              "22c"),
    0x5e: ("iput-char",              "22c"),
    0x5f: ("iput-short",             "22c"),
    0x60: ("sget",                   "21c"),
    0x61: ("sget-wide",              "21c"),
    0x62: ("sget-object",            "21c"),
    0x63: ("sget-boolean",           "21c"),
    0x64: ("sget-byte",              "21c"),
    0x65: ("sget-char",              "21c"),
    0x66: ("sget-short",             "21c"),
    0x67: ("sput",                   "21c"),
    0x68: ("sput-wide",              "21c"),
    0x69: ("sput-object",            "21c"),
    0x6a: ("sput-boolean",           "21c"),
    0x6b: ("sput-byte",              "21c"),
    0x6c: ("sput-char",              "21c"),
    0x6d: ("sput-short",             "21c"),
    0x6e: ("invoke-virtual",         "35c"),
    0x6f: ("invoke-super",           "35c"),
    0x70: ("invoke-direct",          "35c"),
    0x71: ("invoke-static",          "35c"),
    0x72: ("invoke-interface",       "35c"),
    # 0x73 unused
    0x74: ("invoke-virtual/range",   "3rc"),
    0x75: ("invoke-super/range",     "3rc"),
    0x76: ("invoke-direct/range",    "3rc"),
    0x77: ("invoke-static/range",    "3rc"),
    0x78: ("invoke-interface/range", "3rc"),
    # 0x79-0x7a unused
    0x7b: ("neg-int",                "12x"),
    0x7c: ("not-int",                "12x"),
    0x7d: ("neg-long",               "12x"),
    0x7e: ("not-long",               "12x"),
    0x7f: ("neg-float",              "12x"),
    0x80: ("neg-double",             "12x"),
    0x81: ("int-to-long",            "12x"),
    0x82: ("int-to-float",           "12x"),
    0x83: ("int-to-double",          "12x"),
    0x84: ("long-to-int",            "12x"),
    0x85: ("long-to-float",          "12x"),
    0x86: ("long-to-double",         "12x"),
    0x87: ("float-to-int",           "12x"),
    0x88: ("float-to-long",          "12x"),
    0x89: ("float-to-double",        "12x"),
    0x8a: ("double-to-int",          "12x"),
    0x8b: ("double-to-long",         "12x"),
    0x8c: ("double-to-float",        "12x"),
    0x8d: ("int-to-byte",            "12x"),
    0x8e: ("int-to-char",            "12x"),
    0x8f: ("int-to-short",           "12x"),
    0x90: ("add-int",                "23x"),
    0x91: ("sub-int",                "23x"),
    0x92: ("mul-int",                "23x"),
    0x93: ("div-int",                "23x"),
    0x94: ("rem-int",                "23x"),
    0x95: ("and-int",                "23x"),
    0x96: ("or-int",                 "23x"),
    0x97: ("xor-int",                "23x"),
    0x98: ("shl-int",                "23x"),
    0x99: ("shr-int",                "23x"),
    0x9a: ("ushr-int",               "23x"),
    0x9b: ("add-long",               "23x"),
    0x9c: ("sub-long",               "23x"),
    0x9d: ("mul-long",               "23x"),
    0x9e: ("div-long",               "23x"),
    0x9f: ("rem-long",               "23x"),
    0xa0: ("and-long",               "23x"),
    0xa1: ("or-long",                "23x"),
    0xa2: ("xor-long",               "23x"),
    0xa3: ("shl-long",               "23x"),
    0xa4: ("shr-long",               "23x"),
    0xa5: ("ushr-long",              "23x"),
    0xa6: ("add-float",              "23x"),
    0xa7: ("sub-float",              "23x"),
    0xa8: ("mul-float",              "23x"),
    0xa9: ("div-float",              "23x"),
    0xaa: ("rem-float",              "23x"),
    0xab: ("add-double",             "23x"),
    0xac: ("sub-double",             "23x"),
    0xad: ("mul-double",             "23x"),
    0xae: ("div-double",             "23x"),
    0xaf: ("rem-double",             "23x"),
    0xb0: ("add-int/2addr",          "12x"),
    0xb1: ("sub-int/2addr",          "12x"),
    0xb2: ("mul-int/2addr",          "12x"),
    0xb3: ("div-int/2addr",          "12x"),
    0xb4: ("rem-int/2addr",          "12x"),
    0xb5: ("and-int/2addr",          "12x"),
    0xb6: ("or-int/2addr",           "12x"),
    0xb7: ("xor-int/2addr",          "12x"),
    0xb8: ("shl-int/2addr",          "12x"),
    0xb9: ("shr-int/2addr",          "12x"),
    0xba: ("ushr-int/2addr",         "12x"),
    0xbb: ("add-long/2addr",         "12x"),
    0xbc: ("sub-long/2addr",         "12x"),
    0xbd: ("mul-long/2addr",         "12x"),
    0xbe: ("div-long/2addr",         "12x"),
    0xbf: ("rem-long/2addr",         "12x"),
    0xc0: ("and-long/2addr",         "12x"),
    0xc1: ("or-long/2addr",          "12x"),
    0xc2: ("xor-long/2addr",         "12x"),
    0xc3: ("shl-long/2addr",         "12x"),
    0xc4: ("shr-long/2addr",         "12x"),
    0xc5: ("ushr-long/2addr",        "12x"),
    0xc6: ("add-float/2addr",        "12x"),
    0xc7: ("sub-float/2addr",        "12x"),
    0xc8: ("mul-float/2addr",        "12x"),
    0xc9: ("div-float/2addr",        "12x"),
    0xca: ("rem-float/2addr",        "12x"),
    0xcb: ("add-double/2addr",       "12x"),
    0xcc: ("sub-double/2addr",       "12x"),
    0xcd: ("mul-double/2addr",       "12x"),
    0xce: ("div-double/2addr",       "12x"),
    0xcf: ("rem-double/2addr",       "12x"),
    0xd0: ("add-int/lit16",          "22s"),
    0xd1: ("rsub-int",               "22s"),
    0xd2: ("mul-int/lit16",          "22s"),
    0xd3: ("div-int/lit16",          "22s"),
    0xd4: ("rem-int/lit16",          "22s"),
    0xd5: ("and-int/lit16",          "22s"),
    0xd6: ("or-int/lit16",           "22s"),
    0xd7: ("xor-int/lit16",          "22s"),
    0xd8: ("add-int/lit8",           "22b"),
    0xd9: ("rsub-int/lit8",          "22b"),
    0xda: ("mul-int/lit8",           "22b"),
    0xdb: ("div-int/lit8",           "22b"),
    0xdc: ("rem-int/lit8",           "22b"),
    0xdd: ("and-int/lit8",           "22b"),
    0xde: ("or-int/lit8",            "22b"),
    0xdf: ("xor-int/lit8",           "22b"),
    0xe0: ("shl-int/lit8",           "22b"),
    0xe1: ("shr-int/lit8",           "22b"),
    0xe2: ("ushr-int/lit8",          "22b"),
    # 0xe3-0xf9: unused/experimental
    0xfa: ("invoke-polymorphic",     "45cc"),
    0xfb: ("invoke-polymorphic/range","4rcc"),
    0xfc: ("invoke-custom",          "35c"),
    0xfd: ("invoke-custom/range",    "3rc"),
    0xfe: ("const-method-handle",    "21c"),
    0xff: ("const-method-type",      "21c"),
}

_REF_TYPE_METHOD = frozenset({
    0x6e, 0x6f, 0x70, 0x71, 0x72,      # invoke-*
    0x74, 0x75, 0x76, 0x77, 0x78,      # invoke-*/range
    0x24, 0x25,                         # filled-new-array
    0xfc, 0xfd,                         # invoke-custom
    0xfa, 0xfb,                         # invoke-polymorphic
})
_REF_TYPE_FIELD = frozenset({
    0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,   # iget-*
    0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,   # iput-*
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,   # sget-*
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,   # sput-*
    0x20, 0x23,                                   # instance-of, new-array
})
_REF_TYPE_TYPE  = frozenset({0x1c, 0x1f, 0x22})    # const-class, check-cast, new-instance
_REF_TYPE_STRING = frozenset({0x1a, 0x1b})          # const-string, const-string/jumbo
_REF_TYPE_PROTO  = frozenset({0xfa, 0xfb, 0xfe, 0xff})


# ── Decoded instruction ───────────────────────────────────────────────────────

@dataclass
class DEXInstruction:
    """A decoded DEX instruction."""
    cu_offset: int       # offset in code units from start of insns[]
    opcode:    int
    mnemonic:  str
    fmt:       str
    regs:      List[int] = field(default_factory=list)
    ref_idx:   int = -1   # reference table index, or -1
    literal:   int = 0    # literal value (signed)
    branch:    int = 0    # branch offset in code units (signed, relative to this insn)

    def size_cu(self) -> int:
        """Code unit count for this instruction."""
        return _FMT_SIZE.get(self.fmt, 1)

    def smali(
        self,
        dex: Optional[DEXFile] = None,
        cu_base: int = 0,
    ) -> str:
        """
        Render this instruction in smali notation.

        cu_base is the code-unit offset of insns[0] (for branch targets).
        """
        mn = self.mnemonic
        fmt = self.fmt

        def vreg(r: int) -> str:
            return f"v{r}"

        ref_str = ""
        if dex and self.ref_idx >= 0:
            ref_str = _resolve_ref(dex, self.opcode, self.ref_idx)

        # ── 10x / 10t ──────────────────────────────────────────────────────
        if fmt == "10x":
            return mn
        if fmt == "10t":
            target_cu = self.cu_offset + self.branch
            return f"{mn} :L{target_cu:04x}"

        # ── 11x ────────────────────────────────────────────────────────────
        if fmt == "11x":
            return f"{mn} {vreg(self.regs[0])}"

        # ── 11n ────────────────────────────────────────────────────────────
        if fmt == "11n":
            return f"{mn} {vreg(self.regs[0])}, #{self.literal}"

        # ── 12x ────────────────────────────────────────────────────────────
        if fmt == "12x":
            if len(self.regs) == 2:
                return f"{mn} {vreg(self.regs[0])}, {vreg(self.regs[1])}"
            return f"{mn} {vreg(self.regs[0])}"

        # ── 21s / 21h ──────────────────────────────────────────────────────
        if fmt in ("21s", "21h"):
            return f"{mn} {vreg(self.regs[0])}, #{self.literal:#x}"

        # ── 31i ────────────────────────────────────────────────────────────
        if fmt == "31i":
            return f"{mn} {vreg(self.regs[0])}, #{self.literal:#x}"

        # ── 51l ────────────────────────────────────────────────────────────
        if fmt == "51l":
            return f"{mn} {vreg(self.regs[0])}, #{self.literal:#x}"

        # ── 20t / 30t ──────────────────────────────────────────────────────
        if fmt in ("20t", "30t"):
            target_cu = self.cu_offset + self.branch
            return f"{mn} :L{target_cu:04x}"

        # ── 21t ────────────────────────────────────────────────────────────
        if fmt == "21t":
            target_cu = self.cu_offset + self.branch
            return f"{mn} {vreg(self.regs[0])}, :L{target_cu:04x}"

        # ── 22t ────────────────────────────────────────────────────────────
        if fmt == "22t":
            target_cu = self.cu_offset + self.branch
            return f"{mn} {vreg(self.regs[0])}, {vreg(self.regs[1])}, :L{target_cu:04x}"

        # ── 22x ────────────────────────────────────────────────────────────
        if fmt == "22x":
            return f"{mn} {vreg(self.regs[0])}, {vreg(self.regs[1])}"

        # ── 32x ────────────────────────────────────────────────────────────
        if fmt == "32x":
            return f"{mn} {vreg(self.regs[0])}, {vreg(self.regs[1])}"

        # ── 22s ────────────────────────────────────────────────────────────
        if fmt == "22s":
            return f"{mn} {vreg(self.regs[0])}, {vreg(self.regs[1])}, #{self.literal:#x}"

        # ── 22b ────────────────────────────────────────────────────────────
        if fmt == "22b":
            return f"{mn} {vreg(self.regs[0])}, {vreg(self.regs[1])}, #{self.literal:#x}"

        # ── 23x ────────────────────────────────────────────────────────────
        if fmt == "23x":
            return f"{mn} {vreg(self.regs[0])}, {vreg(self.regs[1])}, {vreg(self.regs[2])}"

        # ── 21c ────────────────────────────────────────────────────────────
        if fmt == "21c":
            return f"{mn} {vreg(self.regs[0])}, {ref_str}"

        # ── 22c ────────────────────────────────────────────────────────────
        if fmt == "22c":
            return f"{mn} {vreg(self.regs[0])}, {vreg(self.regs[1])}, {ref_str}"

        # ── 31c ────────────────────────────────────────────────────────────
        if fmt == "31c":
            return f"{mn} {vreg(self.regs[0])}, {ref_str}"

        # ── 31t ────────────────────────────────────────────────────────────
        if fmt == "31t":
            target_cu = self.cu_offset + self.branch
            return f"{mn} {vreg(self.regs[0])}, :L{target_cu:04x}"

        # ── 35c: invoke-kind {v1,v2,...,v5}, method@idx ────────────────────
        if fmt in ("35c", "35ms", "35mi"):
            reg_str = ", ".join(vreg(r) for r in self.regs)
            return f"{mn} {{{reg_str}}}, {ref_str}"

        # ── 3rc: invoke-kind/range {v1..vN}, method@idx ────────────────────
        if fmt in ("3rc", "3rms", "3rmi"):
            if self.regs:
                first, last = self.regs[0], self.regs[-1]
                if first == last:
                    reg_str = vreg(first)
                else:
                    reg_str = f"{vreg(first)} .. {vreg(last)}"
            else:
                reg_str = ""
            return f"{mn} {{{reg_str}}}, {ref_str}"

        # ── 45cc / 4rcc: invoke-polymorphic ────────────────────────────────
        if fmt in ("45cc", "4rcc"):
            reg_str = ", ".join(vreg(r) for r in self.regs)
            return f"{mn} {{{reg_str}}}, {ref_str}"

        return f"{mn} [fmt={fmt}]"


# ── Reference resolver ────────────────────────────────────────────────────────

def _resolve_ref(dex: DEXFile, opcode: int, idx: int) -> str:
    """Resolve a reference index to a human-readable smali string."""
    try:
        if opcode in _REF_TYPE_STRING:
            s = dex.string_at(idx)
            escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            return f'"{escaped}"'

        if opcode in _REF_TYPE_TYPE:
            return dex.type_name(idx)

        if opcode in _REF_TYPE_FIELD:
            if idx < len(dex._field_ids):
                class_idx, type_idx, name_idx = dex._field_ids[idx]
                cn = dex.type_name(class_idx)
                fn = dex.string_at(name_idx)
                ft = dex.type_name(type_idx)
                return f"{cn}->{fn}:{ft}"
            return f"field@{idx}"

        if opcode in _REF_TYPE_METHOD or opcode in (0x24, 0x25):
            if idx < len(dex._method_ids):
                class_idx, proto_idx, name_idx = dex._method_ids[idx]
                cn = dex.type_name(class_idx)
                mn = dex.string_at(name_idx)
                proto = _proto_str(dex, proto_idx)
                return f"{cn}->{mn}({proto[0]}){proto[1]}"
            return f"method@{idx}"

    except Exception:
        pass
    return f"ref@{idx}"


def _proto_str(dex: DEXFile, proto_idx: int) -> Tuple[str, str]:
    """Return (params_str, return_type) for a proto_idx."""
    if proto_idx >= len(dex._proto_ids):
        return ("", "V")
    shorty_idx, return_type_idx, params_off = dex._proto_ids[proto_idx]
    ret = dex.type_name(return_type_idx)
    if not params_off:
        return ("", ret)
    # params_off points to a type_list: u4 size, then size * u2 type_idx
    data = dex._data
    try:
        size = struct.unpack_from("<I", data, params_off)[0]
        params = []
        off = params_off + 4
        for _ in range(size):
            tidx = struct.unpack_from("<H", data, off)[0]
            params.append(dex.type_name(tidx))
            off += 2
        return ("".join(params), ret)
    except Exception:
        return ("", ret)


# ── code_item decoder ─────────────────────────────────────────────────────────

def decode_code_item(
    dex: DEXFile,
    code_off: int,
) -> Tuple[int, int, int, List[DEXInstruction]]:
    """
    Parse a code_item in the DEX data at code_off.

    Returns (registers_size, ins_size, outs_size, instructions).
    instructions is a list of DEXInstruction decoded from the insns[] array.
    """
    data = dex._data
    registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = \
        struct.unpack_from("<HHHHII", data, code_off)
    insns_start = code_off + 16   # 6 fields × 2 + 4 + 4 = 16 bytes header
    insns = []

    cu = 0   # current code unit offset within insns[]
    while cu < insns_size:
        raw_off = insns_start + cu * 2
        if raw_off + 2 > len(data):
            break
        word0 = struct.unpack_from("<H", data, raw_off)[0]
        opcode = word0 & 0xFF
        hi_byte = (word0 >> 8) & 0xFF

        entry = _OPCODES.get(opcode)
        if entry is None:
            # Unknown opcode — emit raw and advance 1 CU
            insns.append(DEXInstruction(cu_offset=cu, opcode=opcode,
                                        mnemonic=f"data-{opcode:02x}", fmt="10x"))
            cu += 1
            continue

        mnemonic, fmt = entry
        sz = _FMT_SIZE.get(fmt, 1)

        if raw_off + sz * 2 > len(data):
            break

        instr = _decode_fmt(data, raw_off, cu, opcode, mnemonic, fmt,
                            hi_byte, insns_size)
        insns.append(instr)
        cu += sz

    return registers_size, ins_size, outs_size, insns


def _read_s16(data: bytes, off: int) -> int:
    v = struct.unpack_from("<H", data, off)[0]
    return v if v < 0x8000 else v - 0x10000


def _read_s32(data: bytes, off: int) -> int:
    v = struct.unpack_from("<I", data, off)[0]
    return v if v < 0x80000000 else v - 0x100000000


def _decode_fmt(
    data: bytes,
    raw_off: int,
    cu: int,
    opcode: int,
    mnemonic: str,
    fmt: str,
    hi_byte: int,
    insns_size: int,
) -> DEXInstruction:
    """Decode a single instruction given its format and raw data offset."""
    w0 = struct.unpack_from("<H", data, raw_off)[0]

    def w(i: int) -> int:
        return struct.unpack_from("<H", data, raw_off + i * 2)[0]

    if fmt == "10x":
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic, fmt=fmt)

    if fmt == "10t":
        offset = hi_byte if hi_byte < 128 else hi_byte - 256
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, branch=offset)

    if fmt == "11x":
        vA = hi_byte
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vA])

    if fmt == "11n":
        vA = (hi_byte) & 0x0F
        lit = (hi_byte >> 4) & 0x0F
        if lit >= 8: lit -= 16
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vA], literal=lit)

    if fmt == "12x":
        vA = hi_byte & 0x0F
        vB = (hi_byte >> 4) & 0x0F
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vA, vB])

    if fmt == "20t":
        offset = _read_s16(data, raw_off + 2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, branch=offset)

    if fmt == "22x":
        vAA = hi_byte
        vBBBB = w(1)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA, vBBBB])

    if fmt == "21t":
        vAA = hi_byte
        offset = _read_s16(data, raw_off + 2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA], branch=offset)

    if fmt == "21s":
        vAA = hi_byte
        lit = _read_s16(data, raw_off + 2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA], literal=lit)

    if fmt == "21h":
        vAA = hi_byte
        val = w(1)
        # For const/high16 shift left 16; for const-wide/high16 shift left 48
        if opcode == 0x19:
            lit = val << 48
        else:
            lit = val << 16
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA], literal=lit)

    if fmt == "21c":
        vAA = hi_byte
        idx = w(1)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA], ref_idx=idx)

    if fmt == "23x":
        vAA = hi_byte
        w1 = w(1)
        vBB = w1 & 0xFF
        vCC = (w1 >> 8) & 0xFF
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA, vBB, vCC])

    if fmt == "22b":
        vAA = hi_byte
        w1 = w(1)
        vBB = w1 & 0xFF
        lit = (w1 >> 8) & 0xFF
        if lit >= 128: lit -= 256
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA, vBB], literal=lit)

    if fmt == "22t":
        vA = hi_byte & 0x0F
        vB = (hi_byte >> 4) & 0x0F
        offset = _read_s16(data, raw_off + 2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vA, vB], branch=offset)

    if fmt == "22s":
        vA = hi_byte & 0x0F
        vB = (hi_byte >> 4) & 0x0F
        lit = _read_s16(data, raw_off + 2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vA, vB], literal=lit)

    if fmt == "22c":
        vA = hi_byte & 0x0F
        vB = (hi_byte >> 4) & 0x0F
        idx = w(2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vA, vB], ref_idx=idx)

    if fmt == "30t":
        offset = _read_s32(data, raw_off + 2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, branch=offset)

    if fmt == "31i":
        vAA = hi_byte
        lit = _read_s32(data, raw_off + 2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA], literal=lit)

    if fmt == "31t":
        vAA = hi_byte
        offset = _read_s32(data, raw_off + 2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA], branch=offset)

    if fmt == "31c":
        vAA = hi_byte
        idx = struct.unpack_from("<I", data, raw_off + 2)[0]
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA], ref_idx=idx)

    if fmt == "32x":
        vAAAA = w(1)
        vBBBB = w(2)
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAAAA, vBBBB])

    if fmt in ("35c", "35ms", "35mi"):
        # word0: AA = count (bits 12-15) | G = reg (bits 8-11); opcode (bits 0-7)
        count = (hi_byte >> 4) & 0x0F   # A field
        vG    = hi_byte & 0x0F          # G field (5th reg)
        idx   = w(1)
        regs_word = w(2)
        vC = (regs_word)       & 0x0F
        vD = (regs_word >> 4)  & 0x0F
        vE = (regs_word >> 8)  & 0x0F
        vF = (regs_word >> 12) & 0x0F
        all_regs = [vC, vD, vE, vF, vG]
        used = all_regs[:count]
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=used, ref_idx=idx)

    if fmt in ("3rc", "3rms", "3rmi"):
        count = hi_byte
        idx   = w(1)
        first = w(2)
        regs  = list(range(first, first + count))
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=regs, ref_idx=idx)

    if fmt == "45cc":
        count = (hi_byte >> 4) & 0x0F
        vG    = hi_byte & 0x0F
        method_idx = w(1)
        regs_word  = w(2)
        # proto_idx  = w(3)  (ignored for now)
        vC = regs_word & 0x0F
        vD = (regs_word >> 4) & 0x0F
        vE = (regs_word >> 8) & 0x0F
        vF = (regs_word >> 12) & 0x0F
        all_regs = [vC, vD, vE, vF, vG]
        used = all_regs[:count]
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=used, ref_idx=method_idx)

    if fmt == "4rcc":
        count      = hi_byte
        method_idx = w(1)
        first      = w(2)
        regs       = list(range(first, first + count))
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=regs, ref_idx=method_idx)

    if fmt == "51l":
        vAA = hi_byte
        lo = struct.unpack_from("<I", data, raw_off + 2)[0]
        hi = struct.unpack_from("<I", data, raw_off + 6)[0]
        lit = (hi << 32) | lo
        return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic,
                              fmt=fmt, regs=[vAA], literal=lit)

    return DEXInstruction(cu_offset=cu, opcode=opcode, mnemonic=mnemonic, fmt=fmt)


# ── DEXDisasm ─────────────────────────────────────────────────────────────────

class DEXDisasm:
    """
    Smali disassembler for a single DEX file.

    Provides method-level and class-level disassembly with full reference
    annotation (method signatures, field descriptors, string literals).
    """

    def __init__(self, dex: DEXFile) -> None:
        self._dex = dex
        # Build code_off lookup: (class_name, method_name) → (code_off, access_flags)
        self._code_map: dict[Tuple[str, str], Tuple[int, int]] = {}
        self._build_code_map()

    def _build_code_map(self) -> None:
        dex = self._dex
        data = dex._data
        for row in dex._class_defs_raw:
            (class_idx, _cls_flags, _super_idx,
             _ifaces_off, _src_idx, _ann_off, data_off, _sv_off) = row
            if not data_off:
                continue
            class_name = dex.type_name(class_idx)
            off = data_off
            try:
                sf_size, off = _uleb128(data, off)
                if_size, off = _uleb128(data, off)
                dm_size, off = _uleb128(data, off)
                vm_size, off = _uleb128(data, off)
                for _ in range(sf_size + if_size):
                    _, off = _uleb128(data, off)
                    _, off = _uleb128(data, off)
                for dm_count in (dm_size, vm_size):
                    running_idx = 0
                    for _ in range(dm_count):
                        idx_diff, off = _uleb128(data, off)
                        flags, off    = _uleb128(data, off)
                        code_off, off = _uleb128(data, off)
                        running_idx += idx_diff
                        method_name, _ = dex._method_info(running_idx)
                        key = (class_name, method_name)
                        if key not in self._code_map and code_off:
                            self._code_map[key] = (code_off, flags)
            except Exception:
                continue

    @classmethod
    def from_path(cls, apk_path: str, dex_index: int = 0) -> "DEXDisasm":
        """
        Create a DEXDisasm from the nth DEX file in an APK (default: classes.dex).
        """
        from ablation.core.apk_parser import APKParser
        with APKParser.from_path(apk_path) as apk:
            dexes = list(apk.iter_dex())
        if dex_index >= len(dexes):
            raise IndexError(f"DEX index {dex_index} out of range (APK has {len(dexes)} DEX files)")
        return cls(dexes[dex_index])

    def list_methods(self, class_name: str) -> List[str]:
        """Return sorted method names with code for the given class."""
        if not class_name.startswith("L"):
            class_name = "L" + class_name.replace(".", "/") + ";"
        return sorted(m for (c, m) in self._code_map if c == class_name)

    def disasm_method(
        self,
        class_name: str,
        method_name: str,
        show_header: bool = True,
    ) -> str:
        """
        Return smali disassembly of a specific method.

        class_name accepts either descriptor form ('Lcom/foo/Bar;') or
        dotted Java form ('com.foo.Bar').
        """
        if not class_name.startswith("L"):
            class_name = "L" + class_name.replace(".", "/") + ";"

        key = (class_name, method_name)
        if key not in self._code_map:
            return f"# method not found: {class_name}->{method_name}"

        code_off, flags = self._code_map[key]
        try:
            reg_count, ins_size, outs_size, instrs = decode_code_item(self._dex, code_off)
        except Exception as e:
            return f"# decode error: {e}"

        lines: List[str] = []
        if show_header:
            lines.append(f".method {class_name}->{method_name}")
            lines.append(f"    .registers {reg_count}")
            lines.append("")

        for ins in instrs:
            smali_line = ins.smali(self._dex)
            lines.append(f"    {ins.cu_offset:04x}  {smali_line}")

        if show_header:
            lines.append(".end method")

        return "\n".join(lines)

    def disasm_class(self, class_name: str) -> str:
        """Return smali disassembly of all non-native methods in a class."""
        if not class_name.startswith("L"):
            class_name = "L" + class_name.replace(".", "/") + ";"
        methods = self.list_methods(class_name)
        if not methods:
            return f"# no methods with code for {class_name}"
        parts = [f"# class {class_name}  ({len(methods)} methods)"]
        for mn in methods:
            parts.append("")
            parts.append(self.disasm_method(class_name, mn))
        return "\n".join(parts)

    @staticmethod
    def report(dex: DEXFile, class_name: str, method_name: str) -> str:
        """Convenience: create disassembler and return method smali in one call."""
        return DEXDisasm(dex).disasm_method(class_name, method_name)
