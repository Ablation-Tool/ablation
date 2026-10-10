"""
MicroPython .mpy v6 bytecode lifter and security analyzer.

Lifts compiled MicroPython modules to readable pseudo-Python and identifies
dangerous call patterns (exec/eval, os.system, network access, direct hardware
writes via machine.mem32).

Supports .mpy v6.0 through v6.3 (MicroPython 1.19 through 1.23+).
CircuitPython uses the same v6 format and is fully supported.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, NamedTuple

# ── Format constants ──────────────────────────────────────────────────────────

MPY_MAGIC = ord('M')
MPY_VERSION = 6

KIND_BYTECODE = 0
KIND_NATIVE = 1
KIND_VIPER = 2

FMT_BYTE = 0
FMT_QSTR = 1
FMT_VINT = 2
FMT_JUMP = 3

# ── Opcode table ──────────────────────────────────────────────────────────────

_OP: dict[int, tuple[str, int]] = {
    # QSTR operand (vuint qstr-table index follows)
    0x10: ('LOAD_CONST_STRING',    FMT_QSTR),
    0x11: ('LOAD_NAME',            FMT_QSTR),
    0x12: ('LOAD_GLOBAL',          FMT_QSTR),
    0x13: ('LOAD_ATTR',            FMT_QSTR),
    0x14: ('LOAD_METHOD',          FMT_QSTR),
    0x15: ('LOAD_SUPER_METHOD',    FMT_QSTR),
    0x16: ('STORE_NAME',           FMT_QSTR),
    0x17: ('STORE_GLOBAL',         FMT_QSTR),
    0x18: ('STORE_ATTR',           FMT_QSTR),
    0x19: ('DELETE_NAME',          FMT_QSTR),
    0x1a: ('DELETE_GLOBAL',        FMT_QSTR),
    0x1b: ('IMPORT_NAME',          FMT_QSTR),
    0x1c: ('IMPORT_FROM',          FMT_QSTR),
    # VINT operand (vuint follows; signed for 0x22)
    0x20: ('MAKE_CLOSURE',         FMT_VINT),
    0x21: ('MAKE_CLOSURE_DEFARGS', FMT_VINT),
    0x22: ('LOAD_CONST_SMALL_INT', FMT_VINT),
    0x23: ('LOAD_CONST_OBJ',       FMT_VINT),
    0x24: ('LOAD_FAST_N',          FMT_VINT),
    0x25: ('LOAD_DEREF',           FMT_VINT),
    0x26: ('STORE_FAST_N',         FMT_VINT),
    0x27: ('STORE_DEREF',          FMT_VINT),
    0x28: ('DELETE_FAST',          FMT_VINT),
    0x29: ('DELETE_DEREF',         FMT_VINT),
    0x2a: ('BUILD_TUPLE',          FMT_VINT),
    0x2b: ('BUILD_LIST',           FMT_VINT),
    0x2c: ('BUILD_MAP',            FMT_VINT),
    0x2d: ('BUILD_SET',            FMT_VINT),
    0x2e: ('BUILD_SLICE',          FMT_VINT),
    0x2f: ('STORE_COMP',           FMT_VINT),
    # VINT operand (unsigned)
    0x30: ('UNPACK_SEQUENCE',      FMT_VINT),
    0x31: ('UNPACK_EX',            FMT_VINT),
    0x32: ('MAKE_FUNCTION',        FMT_VINT),
    0x33: ('MAKE_FUNCTION_DEFARGS',FMT_VINT),
    0x34: ('CALL_FUNCTION',        FMT_VINT),
    0x35: ('CALL_FUNCTION_VAR_KW', FMT_VINT),
    0x36: ('CALL_METHOD',          FMT_VINT),
    0x37: ('CALL_METHOD_VAR_KW',   FMT_VINT),
    # JUMP operand (signed 16-bit LE offset relative to byte after offset)
    0x40: ('UNWIND_JUMP',          FMT_JUMP),
    0x42: ('JUMP',                 FMT_JUMP),
    0x43: ('POP_JUMP_IF_TRUE',     FMT_JUMP),
    0x44: ('POP_JUMP_IF_FALSE',    FMT_JUMP),
    0x45: ('JUMP_IF_TRUE_OR_POP',  FMT_JUMP),
    0x46: ('JUMP_IF_FALSE_OR_POP', FMT_JUMP),
    0x47: ('SETUP_WITH',           FMT_JUMP),
    0x48: ('SETUP_EXCEPT',         FMT_JUMP),
    0x49: ('SETUP_FINALLY',        FMT_JUMP),
    0x4a: ('POP_EXCEPT_JUMP',      FMT_JUMP),
    0x4b: ('FOR_ITER',             FMT_JUMP),
    # BYTE (no operand)
    0x50: ('LOAD_CONST_FALSE',     FMT_BYTE),
    0x51: ('LOAD_CONST_NONE',      FMT_BYTE),
    0x52: ('LOAD_CONST_TRUE',      FMT_BYTE),
    0x53: ('LOAD_NULL',            FMT_BYTE),
    0x54: ('LOAD_BUILD_CLASS',     FMT_BYTE),
    0x55: ('LOAD_SUBSCR',          FMT_BYTE),
    0x56: ('STORE_SUBSCR',         FMT_BYTE),
    0x57: ('DUP_TOP',              FMT_BYTE),
    0x58: ('DUP_TOP_TWO',          FMT_BYTE),
    0x59: ('POP_TOP',              FMT_BYTE),
    0x5a: ('ROT_TWO',              FMT_BYTE),
    0x5b: ('ROT_THREE',            FMT_BYTE),
    0x5c: ('WITH_CLEANUP',         FMT_BYTE),
    0x5d: ('END_FINALLY',          FMT_BYTE),
    0x5e: ('GET_ITER',             FMT_BYTE),
    0x5f: ('GET_ITER_STACK',       FMT_BYTE),
    0x62: ('STORE_MAP',            FMT_BYTE),
    0x63: ('RETURN_VALUE',         FMT_BYTE),
    0x64: ('RAISE_LAST',           FMT_BYTE),
    0x65: ('RAISE_OBJ',            FMT_BYTE),
    0x66: ('RAISE_FROM',           FMT_BYTE),
    0x67: ('YIELD_VALUE',          FMT_BYTE),
    0x68: ('YIELD_FROM',           FMT_BYTE),
    0x69: ('IMPORT_STAR',          FMT_BYTE),
}

_UNARY_OPS = ('+', '-', '~', 'not ', 'bool()')
_BINARY_OPS = (
    'or', 'xor', '&', '<<', '>>', '+', '-', '*', '@', '//', '%',
    '**', '/', '<=', '<', '>=', '>', '==', '!=', 'in', 'not in',
    'is', 'is not', '[]', '[]=',
)

# Modules / names that expand attack surface
_DANGEROUS_IMPORTS = frozenset({
    'socket', 'network', 'ussl', 'ssl', 'uasyncio', 'asyncio',
    'uos', 'os', 'usocket', 'ubinascii', 'machine', 'uctypes',
    'io', 'uio', 'subprocess', 'uhashlib', 'ucryptography',
})
_DANGEROUS_NAMES = frozenset({'exec', 'eval', 'compile', '__import__', 'execfile', 'open'})
_DANGEROUS_ATTRS = frozenset({'system', 'popen', 'execv', 'execve', 'spawn', 'mem32', 'mem16', 'mem8'})

# ── Data types ────────────────────────────────────────────────────────────────


@dataclass
class MpyHeader:
    version_major: int
    feature_flags: int
    small_int_bits: int


class MpyInsn(NamedTuple):
    offset: int
    opcode: int
    mnemonic: str
    operand: int | None = None
    qstr_val: str | None = None


@dataclass
class MpyCodeObj:
    kind: int
    data: bytes
    children: list['MpyCodeObj'] = field(default_factory=list)
    name: str = '<module>'
    _qstrs: list[str] = field(default_factory=list, repr=False)
    _objs: list = field(default_factory=list, repr=False)


# ── Binary reader ─────────────────────────────────────────────────────────────


class _R:
    """Stateful binary reader."""

    def __init__(self, data: bytes) -> None:
        self._d = data
        self.pos = 0

    def byte(self) -> int:
        b = self._d[self.pos]
        self.pos += 1
        return b

    def read(self, n: int) -> bytes:
        b = self._d[self.pos: self.pos + n]
        self.pos += n
        return b

    def vuint(self) -> int:
        """MSB-first 7-bit-chunk variable-length unsigned int."""
        val = 0
        while True:
            b = self.byte()
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80):
                return val

    def qstr_entry(self) -> str:
        """One entry from the global qstr table."""
        raw = self.vuint()
        if raw & 1:
            return f'<qstr:{raw >> 1}>'
        length = raw >> 1
        return self.read(length).decode('utf-8', errors='replace')

    def obj_entry(self) -> object:
        """One entry from the global constant object table."""
        ch = chr(self.byte())
        if ch == 'N':
            return None
        if ch == 'T':
            return True
        if ch == 'F':
            return False
        if ch == 'i':
            length = self.vuint()
            return int(self.read(length).decode())
        if ch == 'f':
            length = self.vuint()
            return float(self.read(length).decode())
        if ch == 'c':
            length = self.vuint()
            return complex(self.read(length).decode())
        if ch in ('S', 's'):
            length = self.vuint()
            return self.read(length).decode('utf-8', errors='replace')
        if ch in ('B', 'b'):
            length = self.vuint()
            return self.read(length)
        if ch == '(':
            n = self.vuint()
            return tuple(self.obj_entry() for _ in range(n))
        length = self.vuint()
        self.read(length)
        return f'<obj:{ch}>'

    def raw_code(self, qstrs: list[str], objs: list) -> MpyCodeObj:
        kind_len = self.vuint()
        kind = kind_len & 3
        has_children = bool(kind_len & 4)
        data_len = kind_len >> 3
        data = self.read(data_len)
        children: list[MpyCodeObj] = []
        if has_children:
            n = self.vuint()
            children = [self.raw_code(qstrs, objs) for _ in range(n)]
        co = MpyCodeObj(kind=kind, data=data, children=children)
        co._qstrs = qstrs
        co._objs = objs
        return co


# ── Prelude parsing (py/bc.h MP_BC_PRELUDE_SIG/SIZE macros) ──────────────────


def _decode_prelude_sig(data: bytes, pos: int) -> tuple[int, int, int, int, int, int, int]:
    """Decode MP_BC_PRELUDE_SIG_DECODE_INTO.

    Returns (new_pos, n_state, n_exc_stack, scope_flags,
             n_pos_args, n_kwonly_args, n_def_pos_args).
    """
    z = data[pos]; pos += 1
    S = (z >> 3) & 0xf
    E = (z >> 2) & 0x1
    F = 0
    A = z & 0x3
    K = 0
    D = 0
    n = 0
    while z & 0x80:
        z = data[pos]; pos += 1
        S |= (z & 0x30) << (2 * n)
        E |= (z & 0x02) << n
        F |= ((z & 0x40) >> 6) << n
        A |= (z & 0x04) << n
        K |= ((z & 0x08) >> 3) << n
        D |= (z & 0x01) << n
        n += 1
    S += 1
    return pos, S, E, F, A, K, D


def _decode_prelude_size(data: bytes, pos: int) -> tuple[int, int, int]:
    """Decode MP_BC_PRELUDE_SIZE_DECODE_INTO.

    Returns (new_pos, n_info, n_cells).
    """
    C = I = n = 0
    while True:
        z = data[pos]; pos += 1
        C |= (z & 1) << n
        I |= ((z & 0x7e) >> 1) << (6 * n)
        n += 1
        if not (z & 0x80):
            break
    return pos, I, C


def _skip_prelude(data: bytes) -> int:
    """Return the byte offset where bytecode instructions begin."""
    pos, *_ = _decode_prelude_sig(data, 0)
    pos, n_info, n_cells = _decode_prelude_size(data, pos)
    return pos + n_info + n_cells


# ── Bytecode helpers ──────────────────────────────────────────────────────────


def _vuint_at(data: bytes, pos: int) -> tuple[int, int]:
    """Read a vuint at pos; return (value, new_pos)."""
    val = 0
    while True:
        b = data[pos]; pos += 1
        val = (val << 7) | (b & 0x7f)
        if not (b & 0x80):
            return val, pos


def _decode_bytecode(co: MpyCodeObj) -> Iterator[MpyInsn]:
    """Yield MpyInsn objects from a bytecode code object."""
    if co.kind != KIND_BYTECODE or not co.data:
        return
    try:
        insn_start = _skip_prelude(co.data)
    except Exception:
        insn_start = 0
    data = co.data
    pos = insn_start
    while pos < len(data):
        off = pos
        op = data[pos]; pos += 1
        # Compact multi-opcode ranges
        if 0x70 <= op <= 0x9f:
            yield MpyInsn(off, op, 'LOAD_CONST_SMALL_INT_MULTI', op - 0x70 - 16)
            continue
        if 0xb0 <= op <= 0xbf:
            yield MpyInsn(off, op, 'LOAD_FAST_MULTI', op - 0xb0)
            continue
        if 0xc0 <= op <= 0xcf:
            yield MpyInsn(off, op, 'STORE_FAST_MULTI', op - 0xc0)
            continue
        if 0xd0 <= op <= 0xd6:
            idx = op - 0xd0
            sym = _UNARY_OPS[idx] if idx < len(_UNARY_OPS) else f'op{idx}'
            yield MpyInsn(off, op, f'UNARY_OP({sym})')
            continue
        if 0xd7 <= op <= 0xff:
            idx = op - 0xd7
            sym = _BINARY_OPS[idx] if idx < len(_BINARY_OPS) else f'op{idx}'
            yield MpyInsn(off, op, f'BINARY_OP({sym})')
            continue
        entry = _OP.get(op)
        if entry is None:
            yield MpyInsn(off, op, f'UNKNOWN_{op:#04x}')
            continue
        mnem, fmt = entry
        if fmt == FMT_BYTE:
            yield MpyInsn(off, op, mnem)
        elif fmt == FMT_QSTR:
            qidx, pos = _vuint_at(data, pos)
            qval = co._qstrs[qidx] if qidx < len(co._qstrs) else f'<qstr:{qidx}>'
            yield MpyInsn(off, op, mnem, qidx, qval)
        elif fmt == FMT_VINT:
            raw, pos = _vuint_at(data, pos)
            if mnem == 'LOAD_CONST_SMALL_INT':
                # Sign-magnitude: odd raw = negative; raw=1 → -1, raw=3 → -2
                val = -(raw >> 1) - 1 if (raw & 1) else (raw >> 1)
            else:
                val = raw
            yield MpyInsn(off, op, mnem, val)
        elif fmt == FMT_JUMP:
            if pos + 2 > len(data):
                break
            raw = struct.unpack_from('<H', data, pos)[0]
            pos += 2
            signed = raw - 0x10000 if raw >= 0x8000 else raw
            yield MpyInsn(off, op, mnem, pos + signed)


# ── Lifter ────────────────────────────────────────────────────────────────────


class MpyLifter:
    """Lift a MicroPython .mpy v6 file to pseudo-Python.

    Construction:
        lifter = MpyLifter.from_path('/path/to/module.mpy')
        lifter = MpyLifter.from_bytes(data)

    Primary outputs:
        lifter.lift_module()        -> str   (full module pseudo-Python)
        lifter.imports()            -> list[str]   (imported module names)
        lifter.dangerous_calls()    -> list[dict]  (security findings)
        MpyLifter.report(findings)  -> str   (ASCII table)
    """

    def __init__(self, data: bytes) -> None:
        self._header, self._qstrs, self._objs, self._root = self._parse(data)

    @classmethod
    def from_path(cls, path: str) -> 'MpyLifter':
        return cls(open(path, 'rb').read())

    @classmethod
    def from_bytes(cls, data: bytes) -> 'MpyLifter':
        return cls(data)

    # ── Public API ────────────────────────────────────────────────────────────

    def lift_module(self) -> str:
        lines: list[str] = []
        self._lift_code(self._root, lines, 0)
        return '\n'.join(lines)

    def imports(self) -> list[str]:
        seen: list[str] = []
        for co in self._walk():
            for insn in _decode_bytecode(co):
                if insn.mnemonic == 'IMPORT_NAME' and insn.qstr_val:
                    name = insn.qstr_val
                    if name not in seen:
                        seen.append(name)
        return seen

    def dangerous_calls(self) -> list[dict]:
        findings: list[dict] = []
        for co in self._walk():
            insns = list(_decode_bytecode(co))
            for i, insn in enumerate(insns):
                m, q = insn.mnemonic, insn.qstr_val or ''
                if m == 'IMPORT_NAME' and q in _DANGEROUS_IMPORTS:
                    sev = 'HIGH' if q in {'os', 'uos', 'machine', 'uctypes'} else 'MEDIUM'
                    findings.append({
                        'type': 'DANGEROUS_IMPORT',
                        'detail': q,
                        'offset': insn.offset,
                        'function': co.name,
                        'severity': sev,
                    })
                if m in ('LOAD_NAME', 'LOAD_GLOBAL') and q in _DANGEROUS_NAMES:
                    findings.append({
                        'type': 'DANGEROUS_CALL',
                        'detail': q,
                        'offset': insn.offset,
                        'function': co.name,
                        'severity': 'HIGH',
                    })
                if m == 'LOAD_ATTR' and q in _DANGEROUS_ATTRS:
                    findings.append({
                        'type': 'DANGEROUS_ATTR',
                        'detail': q,
                        'offset': insn.offset,
                        'function': co.name,
                        'severity': 'HIGH' if q in {'mem32', 'mem16', 'mem8'} else 'HIGH',
                    })
        return findings

    @staticmethod
    def report(findings: list[dict]) -> str:
        if not findings:
            return 'No dangerous patterns found.'
        col = 22
        hdr = f'{"Type":<{col}} {"Sev":<6} {"Function":<28} Detail'
        rows = [hdr, '-' * 80]
        for f in findings:
            rows.append(
                f'{f["type"]:<{col}} {f["severity"]:<6} {f["function"]:<28} {f["detail"]}'
            )
        return '\n'.join(rows)

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _parse(data: bytes) -> tuple[MpyHeader, list[str], list, MpyCodeObj]:
        r = _R(data)
        if r.byte() != MPY_MAGIC:
            raise ValueError('not a .mpy file')
        ver = r.byte()
        if ver != MPY_VERSION:
            raise ValueError(f'.mpy version {ver} not supported (need {MPY_VERSION})')
        flags = r.byte()
        si_bits = r.byte()
        header = MpyHeader(version_major=ver, feature_flags=flags, small_int_bits=si_bits)
        n_qstr = r.vuint()
        n_obj = r.vuint()
        qstrs = [r.qstr_entry() for _ in range(n_qstr)]
        objs = [r.obj_entry() for _ in range(n_obj)]
        root = r.raw_code(qstrs, objs)
        return header, qstrs, objs, root

    def _walk(self) -> Iterator[MpyCodeObj]:
        def _rec(co: MpyCodeObj) -> Iterator[MpyCodeObj]:
            yield co
            for child in co.children:
                yield from _rec(child)
        yield from _rec(self._root)

    def _lift_code(self, co: MpyCodeObj, lines: list[str], depth: int) -> None:
        pad = '    ' * depth
        if co.kind != KIND_BYTECODE:
            lines.append(f'{pad}# <native/viper code — not lifted>')
            return
        stack: list[str] = []
        child_idx = 0

        def pop(n: int = 1) -> list[str]:
            if len(stack) >= n:
                items = stack[-n:]; del stack[-n:]
                return items
            have = list(stack); stack.clear()
            return have + ['<?>'] * (n - len(have))

        def push(v: str) -> None:
            stack.append(v)

        for insn in _decode_bytecode(co):
            m = insn.mnemonic
            q = insn.qstr_val or ''
            v = insn.operand

            if m == 'LOAD_CONST_FALSE':                      push('False')
            elif m == 'LOAD_CONST_NONE':                     push('None')
            elif m == 'LOAD_CONST_TRUE':                     push('True')
            elif m in ('LOAD_CONST_SMALL_INT',
                       'LOAD_CONST_SMALL_INT_MULTI'):        push(str(v))
            elif m == 'LOAD_CONST_STRING':                   push(repr(q))
            elif m == 'LOAD_CONST_OBJ':
                obj = co._objs[v] if isinstance(v, int) and v < len(co._objs) else '<?>'
                push(repr(obj))
            elif m in ('LOAD_NAME', 'LOAD_GLOBAL'):          push(q)
            elif m in ('LOAD_FAST_N', 'LOAD_FAST_MULTI'):    push(f'_v{v}')
            elif m == 'LOAD_DEREF':                          push(f'_free{v}')
            elif m == 'LOAD_ATTR':
                obj = pop(1)[0]; push(f'{obj}.{q}')
            elif m in ('LOAD_METHOD', 'LOAD_SUPER_METHOD'):
                obj = pop(1)[0]; push(obj); push(f'{obj}.{q}')
            elif m == 'LOAD_SUBSCR':
                idx_, obj_ = pop(2); push(f'{obj_}[{idx_}]')
            elif m in ('STORE_NAME', 'STORE_GLOBAL'):
                val = pop(1)[0]; lines.append(f'{pad}{q} = {val}')
            elif m in ('STORE_FAST_N', 'STORE_FAST_MULTI'):
                val = pop(1)[0]; lines.append(f'{pad}_v{v} = {val}')
            elif m == 'STORE_DEREF':
                val = pop(1)[0]; lines.append(f'{pad}_free{v} = {val}')
            elif m == 'STORE_ATTR':
                val, obj_ = pop(2); lines.append(f'{pad}{obj_}.{q} = {val}')
            elif m == 'STORE_SUBSCR':
                idx_, obj_, val = pop(3); lines.append(f'{pad}{obj_}[{idx_}] = {val}')
            elif m == 'IMPORT_NAME':
                pop(2); push(q); lines.append(f'{pad}import {q}')
            elif m == 'IMPORT_FROM':
                push(f'{stack[-1] if stack else "?"}.{q}')
            elif m == 'IMPORT_STAR':
                mod = pop(1)[0]; lines.append(f'{pad}from {mod} import *')
            elif m in ('CALL_FUNCTION', 'CALL_FUNCTION_VAR_KW'):
                n_pos = (v or 0) & 0xff
                n_kw  = ((v or 0) >> 8) & 0xff
                args = pop(n_pos + 2 * n_kw)
                func = pop(1)[0]
                pos_str = ', '.join(args[:n_pos])
                kw_str  = ', '.join(
                    f'{args[n_pos + i]}={args[n_pos + i + 1]}'
                    for i in range(0, 2 * n_kw, 2)
                )
                arg_str = ', '.join(filter(None, [pos_str, kw_str]))
                push(f'{func}({arg_str})')
            elif m in ('CALL_METHOD', 'CALL_METHOD_VAR_KW'):
                n_pos = (v or 0) & 0xff
                n_kw  = ((v or 0) >> 8) & 0xff
                args = pop(n_pos + 2 * n_kw)
                _, method = pop(2)
                arg_str = ', '.join(args[:n_pos])
                push(f'{method}({arg_str})')
            elif m == 'RETURN_VALUE':
                val = pop(1)[0] if stack else 'None'
                lines.append(f'{pad}return {val}')
            elif m == 'YIELD_VALUE':
                val = pop(1)[0] if stack else 'None'
                lines.append(f'{pad}yield {val}')
            elif m == 'POP_TOP':
                val = pop(1)[0]
                if '(' in val or '=' in val:
                    lines.append(f'{pad}{val}')
            elif m.startswith('BINARY_OP('):
                sym = m[10:-1]; b, a = pop(2); push(f'{a} {sym} {b}')
            elif m.startswith('UNARY_OP('):
                sym = m[9:-1]; a = pop(1)[0]; push(f'{sym}{a}')
            elif m == 'BUILD_TUPLE':
                items = pop(v or 0); push(f'({", ".join(items)},)')
            elif m == 'BUILD_LIST':
                items = pop(v or 0); push(f'[{", ".join(items)}]')
            elif m in ('BUILD_MAP', 'BUILD_SET'):
                push('{}')
            elif m == 'MAKE_FUNCTION':
                if child_idx < len(co.children):
                    child = co.children[child_idx]; child_idx += 1
                    child.name = q or f'<lambda_{child_idx}>'
                    lines.append(f'{pad}def {child.name}(...):')
                    self._lift_code(child, lines, depth + 1)
                    push(child.name)
                else:
                    push('<func>')
            elif m == 'POP_JUMP_IF_FALSE':
                cond = pop(1)[0]; lines.append(f'{pad}if not ({cond}):')
            elif m == 'POP_JUMP_IF_TRUE':
                cond = pop(1)[0]; lines.append(f'{pad}if {cond}:')
            elif m == 'FOR_ITER':
                lines.append(f'{pad}for ...:')
            elif m in ('SETUP_EXCEPT', 'SETUP_FINALLY'):
                lines.append(f'{pad}try:')
            elif m == 'DUP_TOP':
                if stack:
                    push(stack[-1])
            # Everything else: skip silently
