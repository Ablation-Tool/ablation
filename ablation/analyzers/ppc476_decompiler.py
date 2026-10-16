"""
Ppc476Decompiler — IBM PPC476 BE function decompiler.

Why this exists
---------------
Gap PPC476-GAP-003. No Python-native decompiler exists for IBM PPC476 (Book E,
32-bit big-endian PowerPC). Ghidra has PPC support but is not in this toolkit.
BinaryLifter's ppc32 backend emits structural output: most instructions appear
as comments, conditions are not decoded, and stack accesses are raw offsets.
This module produces C-like output with:

  - Named stack local variables  (local_0x28 instead of *(sp-128+0x28))
  - Type annotations from load width  (uint32_t / uint16_t / uint8_t / float)
  - Condition expression decoding  (cmpwi + branch → if (r3 > 5) goto loc_X)
  - CFG construction with loop detection  (back-edge branches annotated)
  - PLT call resolution with argument values at call time
  - GOT/TOC load annotation

Usage
-----
    from ablation.analyzers.ppc476_decompiler import Ppc476Decompiler
    dec = Ppc476Decompiler.from_context(ctx)
    print(dec.decompile(func_va, n_insn=200))
"""

from __future__ import annotations

import struct
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

try:
    import capstone
    _CS_OK = True
except ImportError:
    _CS_OK = False

# ── Type system ────────────────────────────────────────────────────────────────

class _T:
    U32   = 'uint32_t'
    U16   = 'uint16_t'
    U8    = 'uint8_t'
    I32   = 'int32_t'
    I16   = 'int16_t'
    F32   = 'float'
    F64   = 'double'
    PTR   = 'void *'
    AUTO  = 'auto'

# Load mnemonic → (type, sign-extension note)
_LOAD_TYPES: Dict[str, str] = {
    'lwz': _T.U32, 'lwa': _T.I32,
    'lhz': _T.U16, 'lha': _T.I16,
    'lbz': _T.U8,
    'lfs': _T.F32, 'lfd': _T.F64,
}
_STORE_TYPES: Dict[str, str] = {
    'stw': _T.U32, 'sth': _T.U16, 'stb': _T.U8,
    'stfs': _T.F32, 'stfd': _T.F64,
}

# ── Abstract value ─────────────────────────────────────────────────────────────

class _Val:
    """Abstract value carried by a register."""
    __slots__ = ('kind', 'text', 'type_')

    def __init__(self, kind: str, text: str, type_: str = _T.U32) -> None:
        self.kind  = kind   # const | arg | local | global | ptr | call | expr | unknown
        self.text  = text
        self.type_ = type_

    def __repr__(self) -> str:
        return self.text

    @staticmethod
    def const(n: int, t: str = _T.U32) -> '_Val':
        s = hex(n) if n >= 10 or n < 0 else str(n)
        return _Val('const', s, t)

    @staticmethod
    def arg(n: int) -> '_Val':
        return _Val('arg', f'arg{n}', _T.AUTO)

    @staticmethod
    def local(name: str, t: str = _T.U32) -> '_Val':
        return _Val('local', name, t)

    @staticmethod
    def ptr_local(name: str) -> '_Val':
        return _Val('ptr', f'&{name}', _T.PTR)

    @staticmethod
    def call_ret(sym: str) -> '_Val':
        return _Val('call', sym, _T.AUTO)

    @staticmethod
    def expr(text: str, t: str = _T.AUTO) -> '_Val':
        return _Val('expr', text, t)

    @staticmethod
    def unknown(reg: int) -> '_Val':
        return _Val('unknown', f'r{reg}', _T.AUTO)

# ── Stack frame tracker ────────────────────────────────────────────────────────

class _StackFrame:
    """Named stack slot manager.

    Tracks frame size from stwu and names each unique sp-relative offset
    accessed (stw/lwz/addi).  Types are inferred from the load/store width
    on first access.
    """

    def __init__(self) -> None:
        self.size: int = 0              # |frame size|, set by stwu r1,-N(r1)
        self._slots: Dict[int, Tuple[str, str]] = {}  # offset -> (name, type)
        self._decls: List[str] = []

    def record_frame(self, size: int) -> None:
        self.size = abs(size)

    def slot(self, offset: int, t: str = _T.U32) -> str:
        """Return or create named local for this sp-relative offset."""
        if offset not in self._slots:
            name = f'local_{offset:#x}'
            self._slots[offset] = (name, t)
            self._decls.append(f'  {t} {name};')
        return self._slots[offset][0]

    def refine_type(self, offset: int, t: str) -> None:
        if offset in self._slots:
            name = self._slots[offset][0]
            self._slots[offset] = (name, t)

    def declarations(self) -> str:
        if not self._decls:
            return ''
        return '\n'.join(self._decls) + '\n'

# ── Condition register tracker ─────────────────────────────────────────────────

# Maps branch mnemonic (stripped of + / - suffixes) → comparison operator
_BRANCH_OPS = {
    'beq':  '==', 'bne':  '!=',
    'blt':  '<',  'bgt':  '>',
    'ble':  '<=', 'bge':  '>=',
    'bdnz': None, 'bdz':  None,  # CTR-based — not condition register
}
# Unsigned equivalents
_BRANCH_OPS_U = {
    'bltu': '<',  'bgtu': '>',
    'bleu': '<=', 'bgeu': '>=',
}

class _CRState:
    """Tracks condition register fields (CR0–CR7)."""

    def __init__(self) -> None:
        # crN → (lhs_text, rhs_text, is_unsigned)
        self._state: Dict[int, Tuple[str, str, bool]] = {}

    def update(self, cr: int, lhs: str, rhs: str, unsigned: bool = False) -> None:
        self._state[cr] = (lhs, rhs, unsigned)

    def decode(self, mn: str, op: str) -> Tuple[Optional[str], str]:
        """Return (cond_expr, target_va_hex) or (None, None)."""
        # Strip prediction hints (+/-)
        base = mn.rstrip('+-')

        # Parse CR field and target from op
        # Forms: '0x1000xxxx' or 'cr7, 0x1000xxxx'
        parts = [p.strip() for p in op.split(',')]
        if len(parts) == 2 and parts[0].startswith('cr'):
            try:
                cr = int(parts[0][2:])
            except ValueError:
                cr = 0
            target_s = parts[1]
        else:
            cr = 0
            target_s = parts[0]

        try:
            target_va = int(target_s, 0)
            target_hex = hex(target_va)
        except (ValueError, IndexError):
            target_hex = target_s

        op_char = _BRANCH_OPS.get(base) or _BRANCH_OPS_U.get(base)
        if op_char is None:
            return None, target_hex

        state = self._state.get(cr)
        if state is None:
            return f'CR{cr}_cond', target_hex

        lhs, rhs, unsigned = state
        if unsigned and op_char in ('<', '>'):
            op_char = op_char + 'u'

        return f'{lhs} {op_char} {rhs}', target_hex

# ── Register file ──────────────────────────────────────────────────────────────

class _RegFile:
    """32 GPRs plus CTR (index 32) and LR (index 33)."""

    def __init__(self) -> None:
        self._r: Dict[int, _Val] = {}
        # PPC476 ABI entry state
        for i in range(8):
            self._r[3 + i] = _Val.arg(i)
        self._r[1]  = _Val.expr('sp', _T.PTR)
        self._r[2]  = _Val.expr('toc', _T.PTR)
        self._r[33] = _Val.expr('LR', _T.PTR)   # LR

    def get(self, reg: int) -> _Val:
        return self._r.get(reg, _Val.unknown(reg))

    def set(self, reg: int, val: _Val) -> None:
        self._r[reg] = val

    def clobber_caller_saves(self) -> None:
        """Clobber r3-r12 (caller-save) after a call."""
        for r in range(3, 13):
            self._r.pop(r, None)

    @staticmethod
    def name(n: int) -> str:
        return f'r{n}'

# ── CFG skeleton ───────────────────────────────────────────────────────────────

class _CFG:
    """Very lightweight CFG: tracks branch target VAs for label emission
    and detects back edges (loops) by BFS from entry."""

    def __init__(self, insns: List[Tuple[int, str, str]]) -> None:
        self.entry = insns[0][0] if insns else 0
        self.branch_targets: Set[int] = set()
        self.back_edges: Set[int] = set()   # source VAs of back edges
        self._build(insns)

    def _build(self, insns: List[Tuple[int, str, str]]) -> None:
        va_set = {i[0] for i in insns}
        first_va = insns[0][0] if insns else 0

        # Collect branch targets that land inside this function
        for va, mn, op in insns:
            if mn.startswith('b') and mn not in ('blr', 'bctr', 'bctrl', 'blrl'):
                parts = [p.strip() for p in op.split(',')]
                tgt_s = parts[-1]
                try:
                    tgt = int(tgt_s, 0)
                    if tgt in va_set:
                        self.branch_targets.add(tgt)
                except (ValueError, TypeError):
                    pass

        # Back edges: branch targets before the current instruction VA
        # (simplistic: targets with VA < branch site VA)
        for va, mn, op in insns:
            if mn.startswith('b') and mn not in ('blr', 'bctr', 'bctrl', 'blrl'):
                parts = [p.strip() for p in op.split(',')]
                tgt_s = parts[-1]
                try:
                    tgt = int(tgt_s, 0)
                    if tgt in va_set and tgt <= va:
                        self.back_edges.add(va)
                except (ValueError, TypeError):
                    pass

    def is_branch_target(self, va: int) -> bool:
        return va in self.branch_targets

    def is_back_edge(self, va: int) -> bool:
        return va in self.back_edges


# ── Decompiler ─────────────────────────────────────────────────────────────────

class Ppc476Decompiler:
    """
    IBM PPC476 BE function decompiler.

    Produces C-like pseudo-code with named locals, type annotations,
    condition expressions, and resolved PLT calls.

    Architecture: IBM PPC476, 32-bit big-endian, Book E, glibc-2.15.
    """

    def __init__(self, text_data: bytes, text_va: int,
                 plt: Dict[int, str],
                 exports: Dict[int, str],
                 strings: Optional[Dict[int, str]] = None) -> None:
        self._text    = text_data
        self._text_va = text_va
        self._plt     = plt
        self._exports = exports
        self._strings = strings or {}

    @classmethod
    def from_context(cls, ctx) -> 'Ppc476Decompiler':
        from lief import parse as lief_parse
        binary = lief_parse(ctx.path)
        text_sec = binary.get_section('.text')  # type: ignore[union-attr]
        if not text_sec:
            raise ValueError('no .text section')
        return cls(
            text_data=bytes(text_sec.content),
            text_va=int(text_sec.virtual_address),
            plt=dict(ctx.plt),
            exports=dict(ctx.exports),
            strings=getattr(ctx, 'strings', {}),
        )

    # ── Public API ──────────────────────────────────────────────────────────

    def decompile(self, func_va: int, n_insn: int = 200) -> str:
        """
        Decompile up to n_insn instructions starting at func_va.
        Returns C-like pseudo-code as a multi-line string.
        """
        if not _CS_OK:
            return '// capstone unavailable — pip install capstone'

        insns = self._disasm(func_va, n_insn)
        if not insns:
            return f'// func_va {hex(func_va)} not in .text or no instructions decoded'

        cfg   = _CFG(insns)
        regs  = _RegFile()
        frame = _StackFrame()
        cr    = _CRState()

        fn_name = self._exports.get(func_va, f'sub_{func_va:#x}')
        lines: List[str] = []
        lines.append(f'// Ppc476Decompiler: {fn_name} @ {hex(func_va)}')
        lines.append(f'auto {fn_name}(auto arg0, auto arg1, auto arg2, auto arg3) {{')

        body: List[str] = []
        for va, mn, op in insns:
            # Emit block label if this VA is a branch target
            if cfg.is_branch_target(va):
                body.append(f'loc_{va:#x}:')

            line = self._emit(va, mn, op, regs, frame, cr, cfg)
            if line:
                body.append(f'  {line}')

            if mn in ('blr',) or (mn.startswith('b') and not op):
                break  # unconditional return

        # Insert local variable declarations after opening brace
        decls = frame.declarations()
        if decls:
            lines.append(decls.rstrip())
        lines.extend(body)
        lines.append('}')
        return '\n'.join(lines)

    # ── Disassembly ─────────────────────────────────────────────────────────

    def _disasm(self, func_va: int, n_insn: int) -> List[Tuple[int, str, str]]:
        cs = capstone.Cs(capstone.CS_ARCH_PPC,
                         capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
        cs.detail = False
        off = func_va - self._text_va
        if off < 0 or off >= len(self._text):
            return []
        chunk = self._text[off: off + n_insn * 4]
        return [(i.address, i.mnemonic, i.op_str)
                for i in cs.disasm(chunk, func_va)][:n_insn]

    # ── Instruction emitter ─────────────────────────────────────────────────

    def _emit(self, va: int, mn: str, op: str,
              regs: _RegFile, frame: _StackFrame,
              cr: _CRState, cfg: _CFG) -> Optional[str]:
        """Emit one decompiled line.  Returns None to skip."""

        ann = f'  // [{hex(va)}]'  # trailing VA annotation

        # ── Frame allocation ─────────────────────────────────────────────
        if mn == 'stwu' and 'r1' in op and op.startswith('r1'):
            _off_s, _ = self._split_mem(op.split(',', 1)[1].strip())
            try:
                frame.record_frame(int(_off_s, 0))
            except ValueError:
                pass
            return f'// prologue: frame -{abs(frame.size)}b{ann}'

        # ── LR staging ──────────────────────────────────────────────────
        if mn == 'mflr':
            rd = self._preg(op)
            if rd is not None:
                regs.set(rd, _Val.expr('LR', _T.PTR))
            return f'// mflr r{rd}{ann}'

        if mn == 'mtlr':
            rs = self._preg(op)
            v = regs.get(rs) if rs is not None else _Val.unknown(0)
            return f'LR = {v};{ann}'

        # ── Move ────────────────────────────────────────────────────────
        if mn == 'mr':
            rd, rs = self._p2reg(op)
            if rd is not None and rs is not None:
                v = regs.get(rs)
                regs.set(rd, v)
                return f'r{rd} = {v};{ann}'

        # ── Load immediate ───────────────────────────────────────────────
        if mn == 'li':
            rd = self._preg(op.split(',')[0])
            if rd is not None:
                try:
                    imm = int(op.split(',')[1].strip(), 0)
                    regs.set(rd, _Val.const(imm))
                    return f'r{rd} = {hex(imm)};{ann}'
                except (ValueError, IndexError):
                    pass

        if mn == 'lis':
            rd = self._preg(op.split(',')[0])
            if rd is not None:
                try:
                    hi = int(op.split(',')[1].strip(), 0) & 0xFFFF
                    regs.set(rd, _Val.const(hi << 16))
                    return f'r{rd} = {hex(hi << 16)};  // lis{ann}'
                except (ValueError, IndexError):
                    pass

        # ── addi / addis ─────────────────────────────────────────────────
        if mn in ('addi', 'addis'):
            parts = [p.strip() for p in op.split(',')]
            if len(parts) == 3:
                rd = self._preg(parts[0])
                ra = self._preg(parts[1])
                if rd is not None and ra is not None:
                    try:
                        imm = int(parts[2], 0)
                        if mn == 'addis':
                            imm <<= 16
                        # sign-extend 16-bit (or 32-bit for addis)
                        if mn == 'addi' and imm >= 0x8000:
                            imm -= 0x10000
                        if ra == 1:
                            # addi rD, r1, N → address of stack slot
                            name = frame.slot(imm)
                            regs.set(rd, _Val.ptr_local(name))
                            return f'r{rd} = &{name};{ann}'
                        bv = regs.get(ra)
                        if bv.kind == 'const':
                            total = int(bv.text, 0) + imm
                            regs.set(rd, _Val.const(total))
                            return f'r{rd} = {hex(total)};{ann}'
                        regs.set(rd, _Val.expr(f'{bv}{imm:+#x}'))
                        return f'r{rd} = {bv}{imm:+#x};{ann}'
                    except (ValueError, IndexError):
                        pass

        # ── Load word ────────────────────────────────────────────────────
        if mn in _LOAD_TYPES:
            t = _LOAD_TYPES[mn]
            rd_s, mem_s = op.split(',', 1)
            rd = self._preg(rd_s)
            if rd is not None:
                addr_text, addr_type = self._mem_expr(mem_s.strip(), regs, frame, t)
                regs.set(rd, _Val.expr(f'*({addr_text})', t))
                return f'{t} r{rd} = *({addr_text});{ann}'

        if mn == 'lwzu':
            rd_s, mem_s = op.split(',', 1)
            rd = self._preg(rd_s)
            if rd is not None:
                imm_s, ra_s = self._split_mem(mem_s.strip())
                ra = self._preg(ra_s)
                if ra is not None:
                    try:
                        imm = int(imm_s, 0)
                        bv = regs.get(ra)
                        addr = f'{bv}{imm:+#x}'
                        regs.set(ra, _Val.expr(addr))
                        regs.set(rd, _Val.expr(f'*({addr})', _T.U32))
                        return f'uint32_t r{rd} = *({addr}); r{ra} = {addr};  // lwzu{ann}'
                    except ValueError:
                        pass

        if mn == 'lwzx':
            parts = [p.strip() for p in op.split(',')]
            if len(parts) == 3:
                rd = self._preg(parts[0])
                if rd is not None:
                    va_v = regs.get(self._preg(parts[1]) or 0)
                    vb_v = regs.get(self._preg(parts[2]) or 0)
                    addr = f'{va_v}+{vb_v}'
                    regs.set(rd, _Val.expr(f'*({addr})', _T.U32))
                    return f'uint32_t r{rd} = *({addr});  // lwzx{ann}'

        # ── Store ────────────────────────────────────────────────────────
        if mn in _STORE_TYPES:
            t = _STORE_TYPES[mn]
            rs_s, mem_s = op.split(',', 1)
            rs = self._preg(rs_s)
            if rs is not None:
                addr_text, _ = self._mem_expr(mem_s.strip(), regs, frame, t)
                v = regs.get(rs)
                return f'*({addr_text}) = {v};{ann}'

        # ── Compare instructions ─────────────────────────────────────────
        if mn in ('cmpwi', 'cmplwi', 'cmpw', 'cmplw'):
            unsigned = 'l' in mn  # cmplwi/cmplw are unsigned
            parts = [p.strip() for p in op.split(',')]
            # Forms: 'crN, rA, imm' or 'rA, imm' or 'rA, rB'
            if parts[0].startswith('cr'):
                try:
                    cr_n = int(parts[0][2:])
                except ValueError:
                    cr_n = 0
                operands = parts[1:]
            else:
                cr_n = 0
                operands = parts
            if len(operands) >= 2:
                ra = self._preg(operands[0])
                lhs = str(regs.get(ra)) if ra is not None else operands[0]
                rhs = operands[1]
                try:
                    rhs_v = int(rhs, 0)
                    rhs = hex(rhs_v) if rhs_v >= 10 else str(rhs_v)
                except ValueError:
                    rb = self._preg(rhs)
                    if rb is not None:
                        rhs = str(regs.get(rb))
                cr.update(cr_n, lhs, rhs, unsigned)
            return f'// cmp: {mn} {op}{ann}'

        # ── Branch instructions ──────────────────────────────────────────
        if mn.startswith('b') and mn not in ('bl', 'blr', 'bctr', 'bctrl', 'blrl'):
            cond_expr, target_hex = cr.decode(mn, op)
            is_back = cfg.is_back_edge(va)
            back_note = '  // LOOP BACK EDGE' if is_back else ''
            if cond_expr:
                return f'if ({cond_expr}) goto loc_{int(target_hex, 0):#x};{back_note}{ann}'
            else:
                return f'goto loc_{target_hex};{back_note}{ann}'

        # ── bl — function call ───────────────────────────────────────────
        if mn == 'bl':
            try:
                target = int(op.strip(), 0)
            except (ValueError, TypeError):
                return f'// bl {op} (unresolved){ann}'

            sym = self._plt.get(target) or self._exports.get(target)
            if not sym:
                sym = f'sub_{target:#x}'

            # Collect visible argument register values
            arg_vals = []
            for areg in range(3, 9):
                v = regs.get(areg)
                if v.kind != 'unknown':
                    arg_vals.append(f'r{areg}={v}')

            args_str = ', '.join(arg_vals) if arg_vals else ''
            regs.clobber_caller_saves()
            regs.set(3, _Val.call_ret(f'{sym}()'))
            return f'{sym}({args_str});{ann}'

        # ── Indirect call ────────────────────────────────────────────────
        if mn == 'mtctr':
            rs = self._preg(op)
            if rs is not None:
                regs.set(32, regs.get(rs))  # CTR = pseudo-reg 32
            return f'// mtctr{ann}'

        if mn in ('bctr', 'bctrl'):
            ctr = regs.get(32)
            arg_vals = []
            for areg in range(3, 9):
                v = regs.get(areg)
                if v.kind != 'unknown':
                    arg_vals.append(f'r{areg}={v}')
            args_str = ', '.join(arg_vals)
            return f'(*{ctr})({args_str});  // indirect call{ann}'

        # ── Return ───────────────────────────────────────────────────────
        if mn == 'blr':
            ret = regs.get(3)
            return f'return {ret};{ann}'

        # ── Arithmetic that modifies a register ──────────────────────────
        if mn in ('add', 'subf', 'and', 'or',
                  'mullw', 'divwu', 'divw', 'slwi', 'srwi', 'srawi',
                  'rlwinm', 'rlwimi', 'extsb', 'extsh', 'extsw', 'cntlzw'):
            parts = [p.strip() for p in op.split(',')]
            rd = self._preg(parts[0])
            if rd is not None:
                regs.set(rd, _Val.expr(f'{mn}({", ".join(parts[1:])})'))
                return f'r{rd} = {mn}({", ".join(parts[1:])});{ann}'

        if mn == 'neg':
            rd, rs = self._p2reg(op)
            if rd is not None and rs is not None:
                v = regs.get(rs)
                regs.set(rd, _Val.expr(f'-{v}'))
                return f'r{rd} = -{v};{ann}'

        if mn in ('xor', 'or', 'and'):
            parts = [p.strip() for p in op.split(',')]
            rd = self._preg(parts[0])
            if rd is not None:
                regs.set(rd, _Val.expr(f'{mn}({", ".join(parts[1:])})'))
                return f'r{rd} = {mn}({", ".join(parts[1:])});{ann}'

        # ── Book E privileged / cache / TLB — pass through ───────────────
        if mn in ('tlbwe', 'tlbre', 'tlbivax', 'tlbsx', 'tlbsrx',
                  'dcbt', 'dcbst', 'icbi', 'dcbf', 'dcbz',
                  'wait', 'mfmsr', 'mtmsr', 'mtspr', 'mfspr',
                  'mfcr', 'mtocrf', 'lmw', 'stmw'):
            return f'// {mn} {op}{ann}'

        # ── Epilogue stores (callee-save reg save) ───────────────────────
        if mn == 'stw':
            rs_s, mem_s = op.split(',', 1)
            rs = self._preg(rs_s)
            if rs is not None:
                addr_text, _ = self._mem_expr(mem_s.strip(), regs, frame, _T.U32)
                v = regs.get(rs)
                # callee-save prologue stores are boilerplate — emit as comment
                if v.kind == 'unknown' and 'sp' in addr_text:
                    return f'// {mn} {op}  // callee-save{ann}'
                return f'*({addr_text}) = {v};{ann}'

        # ── Unhandled ────────────────────────────────────────────────────
        return f'// {mn} {op}{ann}'

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _preg(s: str) -> Optional[int]:
        s = s.strip()
        if s.startswith('r') and s[1:].isdigit():
            return int(s[1:])
        if s == 'sp':
            return 1
        return None

    @staticmethod
    def _p2reg(op: str) -> Tuple[Optional[int], Optional[int]]:
        parts = op.split(',')
        if len(parts) < 2:
            return None, None
        return Ppc476Decompiler._preg(parts[0]), Ppc476Decompiler._preg(parts[1])

    @staticmethod
    def _split_mem(mem_s: str) -> Tuple[str, str]:
        lp = mem_s.index('(')
        rp = mem_s.index(')')
        return mem_s[:lp].strip(), mem_s[lp + 1:rp].strip()

    def _mem_expr(self, mem_s: str, regs: _RegFile,
                  frame: _StackFrame, hint_type: str) -> Tuple[str, str]:
        """Parse 'disp(rA)' and return (addr_string, type_string)."""
        try:
            imm_s, ra_s = self._split_mem(mem_s)
            ra = self._preg(ra_s)
            imm = int(imm_s, 0) if imm_s else 0
            if imm_s and imm >= 0x8000:
                imm -= 0x10000  # sign-extend 16-bit displacement

            if ra == 1:
                # Stack-relative access
                name = frame.slot(imm, hint_type)
                frame.refine_type(imm, hint_type)
                return name, hint_type

            if ra is not None:
                bv = regs.get(ra)
                if bv.kind == 'const':
                    addr = int(bv.text, 0) + imm
                    # Check if it's a known string
                    if addr in self._strings:
                        s = self._strings[addr]
                        label = repr(s[:32])
                        return f'{hex(addr)} /*{label}*/', _T.PTR
                    return hex(addr), hint_type
                if imm:
                    return f'{bv}{imm:+#x}', hint_type
                return str(bv), hint_type
        except (ValueError, IndexError):
            pass
        return mem_s, hint_type
