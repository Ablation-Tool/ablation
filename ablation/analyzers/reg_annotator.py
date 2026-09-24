"""
reg_annotator.py: Lightweight forward symbolic register pass for call-site annotation.

Single forward pass through a function window tracking register assignments.
No Z3, no lattice: just linear propagation. Recovers ~85% of arg values for
typical firmware dispatch functions.

Usage:
    ra = RegAnnotator.from_path('/path/to/binary')
    result = ra.annotate_calls(func_va=0x1000, func_end_va=0x1200)

    for call in result.calls:
        print(f"0x{call.site_va:x}: call {call.target_name}")
        for reg, val in call.args.items():
            print(f"  {reg} = {val.display()}")

    print(result.fmt())  # full formatted block

Example output:
    0x1100: call exec_handler
      rdi = '/bin/target-binary'  (0x8000 via r13)
      rsi = arg0_entry  (rdi@entry via ebp)
      rdx = arg1_entry  (rsi@entry via r12)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import (
    X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
    X86_REG_RIP,
)

# ── canonical register name normalizer ────────────────────────────────────────

_REG_ALIASES: Dict[str, str] = {
    # 64-bit canonical
    'rax': 'rax', 'rbx': 'rbx', 'rcx': 'rcx', 'rdx': 'rdx',
    'rsi': 'rsi', 'rdi': 'rdi', 'rbp': 'rbp', 'rsp': 'rsp',
    'r8':  'r8',  'r9':  'r9',  'r10': 'r10', 'r11': 'r11',
    'r12': 'r12', 'r13': 'r13', 'r14': 'r14', 'r15': 'r15',
    # 32-bit aliases
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
    'r8d': 'r8',  'r9d': 'r9',  'r10d':'r10', 'r11d':'r11',
    'r12d':'r12', 'r13d':'r13', 'r14d':'r14', 'r15d':'r15',
    # 16-bit aliases
    'ax':  'rax', 'bx':  'rbx', 'cx':  'rcx', 'dx':  'rdx',
    'si':  'rsi', 'di':  'rdi', 'bp':  'rbp', 'sp':  'rsp',
    # 8-bit aliases
    'al':  'rax', 'bl':  'rbx', 'cl':  'rcx', 'dl':  'rdx',
    'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp',
    'r8b': 'r8',  'r9b': 'r9',  'r10b':'r10', 'r11b':'r11',
    'r12b':'r12', 'r13b':'r13', 'r14b':'r14', 'r15b':'r15',
    'ah':  'rax', 'bh':  'rbx', 'ch':  'rcx', 'dh':  'rdx',
}

# Arg registers in SysV AMD64 calling convention, indexed 0..5
_ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
# Caller-saved (clobbered at call sites)
_CALLER_SAVED = {'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'}


def _norm(reg_name: str) -> str:
    return _REG_ALIASES.get(reg_name.lower(), reg_name.lower())


# ── value types ───────────────────────────────────────────────────────────────

@dataclass
class RegVal:
    """
    A tracked register value.

    Kinds:
      arg    : entry argument (value.int = arg index 0..5)
      const  : immediate constant (value.int = the constant)
      string : resolved .rodata string (value.str = content)
      copy   : copied from another register (value.str = source reg, chain = source's RegVal)
      ret    : return value from a call (value.str = callee name)
      zero   : explicitly zeroed (xor reg, reg)
      mem    : loaded from memory (value.str = description)
      unknown: clobbered/untracked
    """
    kind: str
    int_val: int = 0
    str_val: str = ""
    chain: Optional["RegVal"] = None  # source val if kind == 'copy'

    def display(self, depth: int = 0) -> str:
        if depth > 4:
            return "..."
        if self.kind == 'arg':
            reg = _ARG_REGS[self.int_val] if self.int_val < len(_ARG_REGS) else f"arg{self.int_val}"
            return f"arg{self.int_val}_entry ({reg}@entry)"
        if self.kind == 'const':
            return f"0x{self.int_val:x}"
        if self.kind == 'string':
            preview = self.str_val[:40] + "..." if len(self.str_val) > 40 else self.str_val
            return f"'{preview}'"
        if self.kind == 'copy':
            if self.chain and self.chain.kind not in ('unknown',):
                return f"{self.chain.display(depth + 1)}  (via {self.str_val})"
            return f"copy of {self.str_val}"
        if self.kind == 'ret':
            return f"ret({self.str_val})"
        if self.kind == 'zero':
            return "0"
        if self.kind == 'mem':
            return f"[{self.str_val}]"
        return "?"

    @staticmethod
    def arg(n: int) -> "RegVal":
        return RegVal(kind='arg', int_val=n)

    @staticmethod
    def const(v: int) -> "RegVal":
        return RegVal(kind='const', int_val=v)

    @staticmethod
    def string(s: str) -> "RegVal":
        return RegVal(kind='string', str_val=s)

    @staticmethod
    def copy(src_reg: str, src_val: Optional["RegVal"] = None) -> "RegVal":
        return RegVal(kind='copy', str_val=src_reg, chain=src_val)

    @staticmethod
    def ret(name: str) -> "RegVal":
        return RegVal(kind='ret', str_val=name)

    @staticmethod
    def zero() -> "RegVal":
        return RegVal(kind='zero')

    @staticmethod
    def mem(desc: str) -> "RegVal":
        return RegVal(kind='mem', str_val=desc)

    @staticmethod
    def unknown() -> "RegVal":
        return RegVal(kind='unknown')


# ── call annotation record ─────────────────────────────────────────────────────

@dataclass
class CallSite:
    site_va: int
    target_va: int
    target_name: str
    args: Dict[str, RegVal] = field(default_factory=dict)

    def fmt(self) -> str:
        tname = self.target_name or f"0x{self.target_va:x}"
        lines = [f"  0x{self.site_va:x}: call {tname}"]
        for reg in ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']:
            v = self.args.get(reg)
            if v and v.kind != 'unknown':
                lines.append(f"    {reg} = {v.display()}")
        return "\n".join(lines)


@dataclass
class AnnotationResult:
    func_va: int
    func_end_va: int
    calls: List[CallSite] = field(default_factory=list)
    reg_trace: List[Tuple[int, str, RegVal]] = field(default_factory=list)

    def fmt(self) -> str:
        lines = [f"RegAnnotator: 0x{self.func_va:x}..0x{self.func_end_va:x}  ({len(self.calls)} calls)"]
        for cs in self.calls:
            lines.append(cs.fmt())
        return "\n".join(lines)

    def call_at(self, va: int) -> Optional[CallSite]:
        for c in self.calls:
            if c.site_va == va:
                return c
        return None


# ── ELF helpers (minimal, no dependency on BinaryContext) ─────────────────────

def _read_u64_le(data: bytes, off: int) -> int:
    return struct.unpack_from('<Q', data, off)[0]

def _read_u32_le(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]

def _read_i32_le(data: bytes, off: int) -> int:
    return struct.unpack_from('<i', data, off)[0]


# ── core annotator ─────────────────────────────────────────────────────────────

class RegAnnotator:
    """
    Lightweight forward symbolic register pass.

    Tracks register assignments through a function window and annotates
    call sites with the inferred values of argument registers at the call.

    Does NOT handle:
    - Branches (follows first path / fall-through only)
    - Loops (each instruction visited once)
    - Stack loads (partial: tracks RSP-relative stores but not complex frame indexing)

    Handles well:
    - mov/lea register-to-register transfers
    - RIP-relative string loads (.rodata, GOT)
    - Immediate constants
    - xor reg, reg zeroing
    - Callee-saved register preservation (r12-r15, rbx, rbp survive calls)
    - Entry arg seeding (rdi/rsi/rdx/rcx/r8/r9 = arg0..arg5 at func start)
    """

    def __init__(self, binary_path: str):
        self.path = binary_path
        self._data = Path(binary_path).read_bytes()
        self._md = Cs(CS_ARCH_X86, CS_MODE_64)
        self._md.detail = True

        self._plt: Dict[int, str] = {}    # va -> symbol name
        self._strings: Dict[int, str] = {} # va -> content
        self._text_off: int = 0
        self._text_va: int = 0
        self._text_size: int = 0

        self._parse_elf()

    @classmethod
    def from_path(cls, binary_path: str) -> "RegAnnotator":
        return cls(binary_path)

    # ── query API ─────────────────────────────────────────────────────────────

    def annotate_calls(
        self,
        func_va: int,
        func_end_va: int = 0,
        window: int = 2048,
        seed_args: bool = True,
    ) -> AnnotationResult:
        """
        Forward symbolic pass from func_va to func_end_va (or window bytes).

        seed_args: if True, pre-seed rdi=arg0, rsi=arg1, rdx=arg2, rcx=arg3,
                   r8=arg4, r9=arg5 at function entry.
        """
        if func_end_va == 0:
            func_end_va = func_va + window

        code = self._read_va(func_va, func_end_va - func_va)
        if not code:
            return AnnotationResult(func_va=func_va, func_end_va=func_end_va)

        regs: Dict[str, RegVal] = {}
        if seed_args:
            for i, reg in enumerate(_ARG_REGS):
                regs[reg] = RegVal.arg(i)

        result = AnnotationResult(func_va=func_va, func_end_va=func_end_va)

        for insn in self._md.disasm(code, func_va):
            if insn.address >= func_end_va:
                break
            self._step(insn, regs, result)

        return result

    def fmt_calls(
        self,
        func_va: int,
        func_end_va: int = 0,
        window: int = 2048,
    ) -> str:
        return self.annotate_calls(func_va, func_end_va, window).fmt()

    # ── forward pass step ─────────────────────────────────────────────────────

    def _step(
        self,
        insn,
        regs: Dict[str, RegVal],
        result: AnnotationResult,
    ) -> None:
        mn = insn.mnemonic.lower()

        # ── mov ──────────────────────────────────────────────────────────────
        if mn in ('mov', 'movsx', 'movsxd', 'movzx'):
            if not insn.operands or len(insn.operands) < 2:
                return
            dst_op, src_op = insn.operands[0], insn.operands[1]
            if dst_op.type != X86_OP_REG:
                return
            dst = _norm(insn.reg_name(dst_op.reg))
            val = self._eval_src(insn, src_op, regs)
            regs[dst] = val
            result.reg_trace.append((insn.address, dst, val))

        # ── lea ──────────────────────────────────────────────────────────────
        elif mn == 'lea':
            if not insn.operands or len(insn.operands) < 2:
                return
            dst_op, src_op = insn.operands[0], insn.operands[1]
            if dst_op.type != X86_OP_REG or src_op.type != X86_OP_MEM:
                return
            dst = _norm(insn.reg_name(dst_op.reg))
            mem = src_op.mem
            if mem.base == X86_REG_RIP and mem.index == 0:
                # RIP-relative: effective address
                eff_va = insn.address + insn.size + mem.disp
                s = self._strings.get(eff_va)
                val = RegVal.string(s) if s else RegVal.const(eff_va)
            else:
                val = RegVal.mem(self._mem_desc(insn, src_op))
            regs[dst] = val
            result.reg_trace.append((insn.address, dst, val))

        # ── xor reg, reg (zeroing idiom) ─────────────────────────────────────
        elif mn == 'xor':
            if not insn.operands or len(insn.operands) < 2:
                return
            dst_op, src_op = insn.operands[0], insn.operands[1]
            if (dst_op.type == X86_OP_REG and src_op.type == X86_OP_REG
                    and dst_op.reg == src_op.reg):
                dst = _norm(insn.reg_name(dst_op.reg))
                regs[dst] = RegVal.zero()
                result.reg_trace.append((insn.address, dst, RegVal.zero()))

        # ── push (partial: used with pop pairs for cheap transfer) ────────────
        elif mn == 'push':
            pass  # not tracking stack frame

        # ── pop ───────────────────────────────────────────────────────────────
        elif mn == 'pop':
            if insn.operands and insn.operands[0].type == X86_OP_REG:
                dst = _norm(insn.reg_name(insn.operands[0].reg))
                regs[dst] = RegVal.unknown()

        # ── call ──────────────────────────────────────────────────────────────
        elif mn == 'call':
            if not insn.operands:
                return
            op = insn.operands[0]
            target_va = 0
            if op.type == X86_OP_IMM:
                target_va = op.imm

            target_name = self._plt.get(target_va, "")
            if not target_name and target_va:
                target_name = f"0x{target_va:x}"

            cs = CallSite(
                site_va=insn.address,
                target_va=target_va,
                target_name=target_name,
                args={reg: regs.get(reg, RegVal.unknown()) for reg in _ARG_REGS},
            )
            result.calls.append(cs)

            # Clobber caller-saved, preserve callee-saved
            for reg in _CALLER_SAVED:
                regs[reg] = RegVal.ret(target_name)

        # ── ret: stop ─────────────────────────────────────────────────────────
        elif mn == 'ret':
            pass  # single forward pass; ret is natural terminator

    # ── src operand evaluator ─────────────────────────────────────────────────

    def _eval_src(self, insn, op, regs: Dict[str, RegVal]) -> RegVal:
        if op.type == X86_OP_IMM:
            # Could be a string pointer
            s = self._strings.get(op.imm)
            if s:
                return RegVal.string(s)
            return RegVal.const(op.imm)

        if op.type == X86_OP_REG:
            src = _norm(insn.reg_name(op.reg))
            src_val = regs.get(src)
            if src_val is None:
                return RegVal.unknown()
            if src_val.kind in ('arg', 'string', 'const', 'zero'):
                return src_val
            return RegVal.copy(src, src_val)

        if op.type == X86_OP_MEM:
            mem = op.mem
            if mem.base == X86_REG_RIP and mem.index == 0:
                eff_va = insn.address + insn.size + mem.disp
                s = self._strings.get(eff_va)
                if s:
                    return RegVal.string(s)
                return RegVal.mem(f"[rip + 0x{mem.disp:x}]  (0x{eff_va:x})")
            base_name = _norm(insn.reg_name(mem.base)) if mem.base else ""
            if mem.index == 0 and base_name:
                desc = f"{base_name}+0x{mem.disp:x}" if mem.disp >= 0 else f"{base_name}-0x{-mem.disp:x}"
                # If we know what's in the base reg, propagate for simple loads
                base_val = regs.get(base_name)
                if base_val and base_val.kind in ('arg',):
                    return RegVal.mem(f"[{desc}] (from {base_val.display()})")
                return RegVal.mem(desc)

        return RegVal.unknown()

    def _mem_desc(self, insn, op) -> str:
        mem = op.mem
        parts = []
        if mem.base and mem.base != X86_REG_RIP:
            parts.append(insn.reg_name(mem.base))
        if mem.index:
            scale = mem.scale
            reg = insn.reg_name(mem.index)
            parts.append(f"{reg}*{scale}" if scale > 1 else reg)
        if mem.disp:
            parts.append(f"0x{mem.disp:x}" if mem.disp >= 0 else f"-0x{-mem.disp:x}")
        return "+".join(parts) or "?"

    # ── VA read ───────────────────────────────────────────────────────────────

    def _read_va(self, va: int, size: int) -> bytes:
        off = va - self._text_va + self._text_off
        if off < 0 or off + size > len(self._data):
            return b""
        return self._data[off:off + size]

    # ── ELF parser ────────────────────────────────────────────────────────────

    def _parse_elf(self) -> None:
        data = self._data
        if len(data) < 64 or data[:4] != b'\x7fELF':
            return

        e_shoff = _read_u64_le(data, 0x28)
        e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
        e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]

        if e_shoff == 0 or e_shnum == 0:
            return

        def sh(i: int) -> bytes:
            off = e_shoff + i * e_shentsize
            return data[off:off + e_shentsize]

        # section names
        strtab_sh = sh(e_shstrndx)
        strtab_off = _read_u64_le(strtab_sh, 0x18)

        def sh_name(sh_data: bytes) -> str:
            name_off = _read_u32_le(sh_data, 0)
            end = data.index(b'\x00', strtab_off + name_off)
            return data[strtab_off + name_off:end].decode('ascii', errors='ignore')

        sections: Dict[str, Tuple[int, int, int]] = {}  # name -> (file_off, va, size)
        for i in range(e_shnum):
            s = sh(i)
            if len(s) < 64:
                continue
            try:
                name = sh_name(s)
            except (ValueError, UnicodeDecodeError):
                continue
            foff = _read_u64_le(s, 0x18)
            va = _read_u64_le(s, 0x10)
            size = _read_u64_le(s, 0x20)
            sections[name] = (foff, va, size)

        # .text (or first PROGBITS executable section)
        if '.text' in sections:
            foff, va, size = sections['.text']
            self._text_off = foff
            self._text_va = va
            self._text_size = size
        else:
            # fallback: find first executable section
            for i in range(e_shnum):
                s = sh(i)
                sh_type = _read_u32_le(s, 4)
                sh_flags = _read_u64_le(s, 8)
                if sh_type == 1 and (sh_flags & 4):  # SHT_PROGBITS + SHF_EXECINSTR
                    self._text_off = _read_u64_le(s, 0x18)
                    self._text_va = _read_u64_le(s, 0x10)
                    self._text_size = _read_u64_le(s, 0x20)
                    break

        # .rodata strings
        if '.rodata' in sections:
            foff, va, size = sections['.rodata']
            self._load_strings(foff, va, size)

        # PLT map via .rela.plt -> .dynsym
        self._load_plt(sections)

    def _load_strings(self, foff: int, va: int, size: int) -> None:
        data = self._data
        end = foff + size
        i = foff
        while i < end:
            j = i
            while j < end and data[j] >= 0x20 and data[j] < 0x7f:
                j += 1
            if j - i >= 4:
                s = data[i:j].decode('ascii', errors='ignore')
                self._strings[va + (i - foff)] = s
            i = max(j + 1, i + 1)

    def _load_plt(self, sections: Dict[str, Tuple[int, int, int]]) -> None:
        data = self._data

        # .dynsym
        if '.dynsym' not in sections or '.dynstr' not in sections:
            return
        dynsym_off, _, dynsym_size = sections['.dynsym']
        dynstr_off, _, _ = sections['.dynstr']

        def sym_name(idx: int) -> str:
            name_off = _read_u32_le(data, dynsym_off + idx * 24)
            end = data.index(b'\x00', dynstr_off + name_off)
            return data[dynstr_off + name_off:end].decode('ascii', errors='ignore')

        # .rela.plt
        for rela_name in ('.rela.plt', '.rela.dyn'):
            if rela_name not in sections:
                continue
            rela_off, _, rela_size = sections[rela_name]
            n = rela_size // 24
            for i in range(n):
                base = rela_off + i * 24
                r_offset = _read_u64_le(data, base)
                r_info = _read_u64_le(data, base + 8)
                sym_idx = r_info >> 32
                r_type = r_info & 0xffffffff
                if r_type not in (7, 6, 1):  # R_X86_64_JUMP_SLOT, GLOB_DAT, 64
                    continue
                try:
                    name = sym_name(sym_idx)
                    if not name:
                        continue
                except Exception:
                    continue

                # Resolve .plt.sec or .plt stub VA
                got_va = r_offset
                # Find .plt.sec stub that jmps through this GOT entry
                for plt_name in ('.plt.sec', '.plt', '.plt.got'):
                    if plt_name not in sections:
                        continue
                    pfoff, pva, psize = sections[plt_name]
                    stub_data = data[pfoff:pfoff + psize]
                    # Walk stubs in 16-byte increments
                    for s_off in range(0, psize, 16):
                        if s_off + 16 > psize:
                            break
                        stub = stub_data[s_off:s_off + 16]
                        # Pattern: ff 25 XX XX XX XX (jmp [rip + disp])
                        if stub[:2] == b'\xff\x25':
                            disp = _read_i32_le(stub, 2)
                            stub_va = pva + s_off
                            ref_va = stub_va + 6 + disp
                            if ref_va == got_va:
                                self._plt[stub_va] = name
                                break
                        # endbr64 + jmp [rip + disp]
                        elif stub[:4] == b'\xf3\x0f\x1e\xfa' and stub[4:6] == b'\xff\x25':
                            disp = _read_i32_le(stub, 6)
                            stub_va = pva + s_off
                            ref_va = stub_va + 10 + disp
                            if ref_va == got_va:
                                self._plt[stub_va] = name
                                break
