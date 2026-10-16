"""
Ppc32Lifter — PPC32 BE function pseudo-code lifter.

Why this exists
---------------
Gap PPC476-GAP-003: no Python-native PPC32 BE lifter exists in any open toolkit
(Ghidra has PPC support but is banned; IDA/BN are commercial). This module fills
the gap for the IBM PPC476 collection and any future PPC32 BE target.

Usage
-----
    from ablation.analyzers.ppc32_lifter import Ppc32Lifter
    lifter = Ppc32Lifter.from_context(ctx)
    pseudo = lifter.lift(func_va, n_insn=200)
    print(pseudo)

Output format
-------------
Lines of C-like pseudo-code, each tagged with VA:

    [0x10002754] r1 -= 0x80;           // frame alloc
    [0x10002760] r9 = r3;              // arg copy
    [0x100027a4] fork();               // PLT call
    [0x10002838] execv(r3, r4);        // PLT call

PPC32 ABI handled
-----------------
    r0   : scratch / LR staging (mflr/mtlr targets)
    r1   : stack pointer (stwu r1, -N(r1) = frame alloc)
    r2   : TOC (used as *(r2+off) in GOT loads)
    r3-r10: call arguments and return value
    r11-r12: scratch (call stubs use r11)
    r13   : small-data area (SDA) pointer
    r14-r31: callee-saved (prologue saves, epilogue restores)
    LR   : link register (bl stores return addr here)
    CTR  : count register (bctr for indirect calls)
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

try:
    import capstone
    _CS_OK = True
except ImportError:
    _CS_OK = False


# PPC32 register names
_REG_NAMES = {i: f'r{i}' for i in range(32)}
_REG_NAMES.update({
    0: 'r0',
    1: 'sp',
    2: 'r2_toc',
    3: 'r3',
})


class _Val:
    """Abstract value for a register: tracks origin for readable output."""
    __slots__ = ('kind', 'text')

    def __init__(self, kind: str, text: str) -> None:
        self.kind = kind   # 'const', 'arg', 'stack', 'mem', 'sym', 'expr', 'unknown'
        self.text = text   # human-readable string

    def __repr__(self) -> str:
        return self.text

    @staticmethod
    def const(n: int) -> '_Val':
        return _Val('const', hex(n) if abs(n) >= 10 else str(n))

    @staticmethod
    def arg(n: int) -> '_Val':
        return _Val('arg', f'arg{n}')   # entry arg: r3=arg0, r4=arg1, ...

    @staticmethod
    def unknown(reg: int) -> '_Val':
        return _Val('unknown', f'<r{reg}?>')

    @staticmethod
    def sym(name: str) -> '_Val':
        return _Val('sym', name)

    @staticmethod
    def mem(addr_text: str) -> '_Val':
        return _Val('mem', f'*({addr_text})')

    @staticmethod
    def expr(text: str) -> '_Val':
        return _Val('expr', text)


class Ppc32Lifter:
    """
    PPC32 BE pseudo-code lifter.

    Tracks register state across basic instruction sequences and emits C-like
    lines.  Does NOT do full data-flow analysis across branches — it lifts
    linearly and annotates branches with '// if/else' comments.

    Architecture: PPC32 BE (IBM PPC476, glibc 2.15).
    """

    def __init__(self, text_data: bytes, text_va: int,
                 plt: Dict[int, str],
                 exports: Dict[int, str]) -> None:
        self._text = text_data
        self._text_va = text_va
        self._plt = plt          # stub_va → sym_name
        self._exports = exports  # func_va → name

    @classmethod
    def from_context(cls, ctx) -> 'Ppc32Lifter':
        from lief import parse as lief_parse
        binary = lief_parse(ctx.path)
        text_sec = binary.get_section('.text')
        if not text_sec:
            raise ValueError('no .text section')
        return cls(
            text_data=bytes(text_sec.content),
            text_va=int(text_sec.virtual_address),
            plt=dict(ctx.plt),
            exports=dict(ctx.exports),
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def lift(self, func_va: int, n_insn: int = 150) -> str:
        """
        Lift up to n_insn instructions starting at func_va.
        Returns C-like pseudo-code as a multi-line string.
        """
        if not _CS_OK:
            return '# capstone not available — install: pip install capstone'

        cs = capstone.Cs(capstone.CS_ARCH_PPC,
                         capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
        cs.detail = False

        offset = func_va - self._text_va
        if offset < 0 or offset >= len(self._text):
            return f'# func_va {hex(func_va)} out of .text range'

        chunk = self._text[offset: offset + n_insn * 4]

        # Register state: reg index → _Val
        regs: Dict[int, _Val] = {}
        # Initialise entry args: r3=arg0 .. r10=arg7
        for i in range(8):
            regs[3 + i] = _Val.arg(i)
        regs[1] = _Val.expr('sp')
        regs[2] = _Val.expr('toc')

        lines: List[str] = []
        fn_name = self._exports.get(func_va, hex(func_va))
        lines.append(f'// PPC32 lift of {fn_name} @ {hex(func_va)}')
        lines.append('//')

        insn_count = 0
        for insn in cs.disasm(chunk, func_va):
            if insn_count >= n_insn:
                break
            insn_count += 1

            va = insn.address
            mn = insn.mnemonic
            op = insn.op_str

            line = self._lift_insn(va, mn, op, regs)
            if line:
                lines.append(f'  [{hex(va)}] {line}')

            # Stop at function return
            if mn in ('blr', 'bclr') and not op:
                lines.append(f'  [{hex(va)}] return r3;')
                break

        return '\n'.join(lines)

    # ── Instruction lifter ────────────────────────────────────────────────────

    def _lift_insn(self, va: int, mn: str, op: str,
                   regs: Dict[int, _Val]) -> Optional[str]:
        """
        Lift one instruction.  Updates `regs` in-place.
        Returns a string for the pseudo-code line, or None to skip.
        """

        # ── Stack frame allocation ──────────────────────────────────────────
        if mn == 'stwu' and 'r1' in op:
            # stwu r1, -N(r1)  → sp -= N
            try:
                parts = op.split(',')
                imm = int(parts[1].split('(')[0].strip(), 0)
                regs[1] = _Val.expr(f'sp{imm:+d}')
                return f'sp -= {-imm};  // frame alloc'
            except Exception:
                pass

        # ── LR staging (mflr / mtlr) ───────────────────────────────────────
        if mn == 'mflr':
            rd = self._parse_reg(op)
            if rd is not None:
                regs[rd] = _Val.sym('LR')
                return f'r{rd} = LR;'

        if mn == 'mtlr':
            rs = self._parse_reg(op)
            if rs is not None:
                v = regs.get(rs, _Val.unknown(rs))
                return f'LR = {v};'

        # ── Move ────────────────────────────────────────────────────────────
        if mn == 'mr':
            rd, rs = self._parse_2reg(op)
            if rd is not None and rs is not None:
                v = regs.get(rs, _Val.unknown(rs))
                regs[rd] = v
                return f'r{rd} = {v};'

        # ── Load immediate ──────────────────────────────────────────────────
        if mn == 'li':
            rd = self._parse_reg(op.split(',')[0])
            if rd is not None:
                try:
                    imm = int(op.split(',')[1].strip(), 0)
                    regs[rd] = _Val.const(imm)
                    return f'r{rd} = {hex(imm)};'
                except Exception:
                    pass

        if mn == 'lis':
            rd = self._parse_reg(op.split(',')[0])
            if rd is not None:
                try:
                    hi = int(op.split(',')[1].strip(), 0)
                    val = (hi & 0xFFFF) << 16
                    regs[rd] = _Val.const(val)
                    return f'r{rd} = {hex(val)};  // lis hi'
                except Exception:
                    pass

        # ── addi / addis ────────────────────────────────────────────────────
        if mn in ('addi', 'addis'):
            rd_s, rest = op.split(',', 1)
            rd = self._parse_reg(rd_s)
            parts = rest.split(',')
            if rd is not None and len(parts) == 2:
                ra = self._parse_reg(parts[0])
                try:
                    imm = int(parts[1].strip(), 0)
                    if mn == 'addis':
                        imm <<= 16
                    if ra is not None and ra != 0:
                        base = regs.get(ra, _Val.unknown(ra))
                        if base.kind == 'const':
                            total = int(base.text, 0) + imm
                            regs[rd] = _Val.const(total)
                            return f'r{rd} = {hex(total)};'
                        else:
                            regs[rd] = _Val.expr(f'{base}{imm:+#x}')
                            return f'r{rd} = {base}{imm:+#x};'
                    else:
                        # addi rD, 0, imm = li rD, imm
                        regs[rd] = _Val.const(imm)
                        return f'r{rd} = {hex(imm)};'
                except Exception:
                    pass

        # ── Load word ───────────────────────────────────────────────────────
        if mn == 'lwz':
            rd_s, mem_s = op.split(',', 1)
            rd = self._parse_reg(rd_s)
            if rd is not None:
                addr_text = self._parse_mem_addr(mem_s.strip(), regs)
                regs[rd] = _Val.mem(addr_text)
                return f'r{rd} = *({addr_text});'

        if mn == 'lwzu':
            # lwzu rD, d(rA) — load with update
            rd_s, mem_s = op.split(',', 1)
            rd = self._parse_reg(rd_s)
            if rd is not None:
                imm_s, ra_s = self._split_mem(mem_s.strip())
                ra = self._parse_reg(ra_s)
                if ra is not None:
                    try:
                        imm = int(imm_s, 0)
                        base = regs.get(ra, _Val.unknown(ra))
                        addr_text = f'{base}{imm:+#x}'
                        regs[ra] = _Val.expr(addr_text)  # update rA
                        regs[rd] = _Val.mem(addr_text)
                        return f'r{rd} = *({addr_text}); r{ra} = {addr_text};  // lwzu'
                    except Exception:
                        pass

        if mn == 'lwzx':
            # lwzx rD, rA, rB — rD = mem[rA+rB]
            parts = [p.strip() for p in op.split(',')]
            if len(parts) == 3:
                rd = self._parse_reg(parts[0])
                ra = self._parse_reg(parts[1])
                rb = self._parse_reg(parts[2])
                if rd is not None:
                    va_text = regs.get(ra, _Val.unknown(ra or 0))
                    vb_text = regs.get(rb, _Val.unknown(rb or 0))
                    addr = f'{va_text}+{vb_text}'
                    regs[rd] = _Val.mem(addr)
                    return f'r{rd} = *({addr});  // lwzx'

        # ── Store word ──────────────────────────────────────────────────────
        if mn in ('stw', 'stwu'):
            rs_s, mem_s = op.split(',', 1)
            rs = self._parse_reg(rs_s)
            if rs is not None:
                addr_text = self._parse_mem_addr(mem_s.strip(), regs)
                v = regs.get(rs, _Val.unknown(rs))
                return f'*({addr_text}) = {v};'

        # ── Branch and link (function call) ────────────────────────────────
        if mn == 'bl':
            try:
                target = int(op.strip(), 0)
            except Exception:
                return f'bl {op};  // indirect'

            sym = self._plt.get(target) or self._exports.get(target)
            if sym:
                # Show r3-r8 as arguments (those set before the call)
                arg_vals = []
                for areg in range(3, 9):
                    v = regs.get(areg)
                    if v and v.kind not in ('unknown',):
                        arg_vals.append(f'r{areg}={v}')
                args_str = ', '.join(arg_vals) if arg_vals else ''
                # After call: r3 = return value
                regs[3] = _Val.sym(f'{sym}()')
                # Clobber r4-r12 (caller-saves)
                for r in list(range(4, 13)):
                    regs.pop(r, None)
                return f'{sym}({args_str});  // PLT call'
            else:
                fn = self._exports.get(target, hex(target))
                regs[3] = _Val.sym(f'{fn}()')
                for r in list(range(4, 13)):
                    regs.pop(r, None)
                return f'{fn}();'

        # ── Indirect call ───────────────────────────────────────────────────
        if mn == 'mtctr':
            rs = self._parse_reg(op)
            if rs is not None:
                v = regs.get(rs, _Val.unknown(rs))
                regs[32] = v   # CTR "register" (use 32 as pseudo-index)
                return f'CTR = {v};'

        if mn == 'bctr':
            ctr_val = regs.get(32, _Val.unknown(32))
            return f'call *CTR;  // CTR={ctr_val}'

        # ── Comparisons / branches ─────────────────────────────────────────
        if mn.startswith('b') and mn not in ('bl', 'blr', 'bctr', 'bctrl'):
            return f'// branch: {mn} {op}'

        if mn in ('cmpwi', 'cmplwi', 'cmpw', 'cmplw'):
            return f'// cmp: {mn} {op}'

        # ── Arithmetic ops that affect register state ──────────────────────
        if mn in ('add', 'subf', 'mullw', 'divwu', 'slwi', 'srwi', 'srawi',
                  'and', 'or', 'xor', 'neg', 'not'):
            parts = [p.strip() for p in op.split(',')]
            if parts:
                rd = self._parse_reg(parts[0])
                if rd is not None:
                    regs[rd] = _Val.expr(f'{mn}({", ".join(parts[1:])})')
                    return f'r{rd} = {mn}({", ".join(parts[1:])});'

        # ── Return ─────────────────────────────────────────────────────────
        if mn in ('blr',):
            return None  # handled by caller

        # ── Skip prologue/epilogue boilerplate ─────────────────────────────
        if mn in ('mflr', 'mtlr', 'mtocrf', 'stmw', 'lmw'):
            return f'// {mn} {op}'

        # ── Unrecognised — pass through as comment ─────────────────────────
        return f'// {mn} {op}'

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_reg(s: str) -> Optional[int]:
        s = s.strip()
        if s.startswith('r') and s[1:].isdigit():
            return int(s[1:])
        if s == 'sp':
            return 1
        return None

    @staticmethod
    def _parse_2reg(op: str) -> Tuple[Optional[int], Optional[int]]:
        parts = op.split(',')
        if len(parts) < 2:
            return None, None
        rd = Ppc32Lifter._parse_reg(parts[0])
        rs = Ppc32Lifter._parse_reg(parts[1])
        return rd, rs

    @staticmethod
    def _split_mem(mem_s: str) -> Tuple[str, str]:
        """Parse 'offset(reg)' → ('offset', 'reg')."""
        lp = mem_s.index('(')
        rp = mem_s.index(')')
        return mem_s[:lp].strip(), mem_s[lp+1:rp].strip()

    def _parse_mem_addr(self, mem_s: str, regs: Dict[int, _Val]) -> str:
        """Parse 'disp(rA)' and return a descriptive address string."""
        try:
            imm_s, ra_s = self._split_mem(mem_s)
            ra = self._parse_reg(ra_s)
            imm = int(imm_s, 0) if imm_s else 0
            if ra is not None:
                base = regs.get(ra, _Val.unknown(ra))
                if base.kind == 'const':
                    return hex(int(base.text, 0) + imm)
                return f'{base}{imm:+#x}' if imm else str(base)
        except Exception:
            pass
        return mem_s
