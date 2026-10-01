"""
abc_decompiler.py -- ARK Bytecode -> JavaScript-like pseudocode decompiler.

Lifts ARKInstruction streams (from ARKDisasm) into readable pseudocode using
a register-state machine with accumulator tracking and basic-block CFG.

Architecture (Durfina 2012, front-end -> IR -> back-end):
  Front-end:  ARKDisasm.iter_insns() yields ARKInstruction objects.
  IR lift:    _lift() translates each instruction to a pseudocode statement.
  Back-end:   Statements assembled into labelled blocks with if/goto control flow.

ABC-specific advantages over native decompilation:
  - Function boundaries are explicit (CodeItem metadata).
  - Argument count is explicit (parameter_count field, no ABI inference).
  - Register count is explicit (register_count field).

The ARK ISA centers on an accumulator register (_acc).  Most instructions read
from or write to _acc.  This lifter tracks _acc as a named slot alongside the
numbered virtual registers, enabling inline expression folding.

Usage:
    from ablation.analyzers.abc_decompiler import ABCDecompiler

    dec = ABCDecompiler.from_path('/path/to/modules.abc')
    for method in dec.parser.iter_methods():
        code = dec.parser.get_code(method)
        if code:
            print(dec.decompile_method(method, code))
"""

from __future__ import annotations

import re as _re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .abc_parser import ABCParser, MethodInfo, CodeItem
from .abc_disasm import ARKDisasm, ARKInstruction

# ── ARK ISA semantic tables ───────────────────────────────────────────────────

# Binary operations: mnemonic -> JS operator (first 'i' operand is IC slot, skip it)
_BIN_OPS: Dict[str, str] = {
    'add2': '+',   'sub2': '-',   'mul2': '*',   'div2': '/',
    'mod2': '%',   'exp': '**',
    'shl2': '<<',  'shr2': '>>',  'ashr2': '>>>',
    'and2': '&',   'or2': '|',    'xor2': '^',
    'eq': '==',    'noteq': '!=', 'stricteq': '===', 'strictnoteq': '!==',
    'less': '<',   'lesseq': '<=', 'greater': '>', 'greatereq': '>=',
    'isin': 'in',  'instanceof': 'instanceof',
}

# Unary operations on accumulator: mnemonic -> expression template (acc = <template>)
_UNARY_OPS: Dict[str, str] = {
    'neg':       '-acc',
    'not':       '!acc',
    'inc':       'acc + 1',
    'dec':       'acc - 1',
    'typeof':    'typeof acc',
    'tonumber':  'Number(acc)',
    'tonumeric': 'Number(acc)',
    'istrue':    '!!acc',
    'isfalse':   '!acc',
}

# Conditional branch conditions: mnemonic -> condition expression template
_COND_BRANCH: Dict[str, str] = {
    'jeqz':             'acc == 0',
    'jnez':             'acc != 0',
    'jstricteqz':       'acc === 0',
    'jnstricteqz':      'acc !== 0',
    'jeqnull':          'acc == null',
    'jnenull':          'acc != null',
    'jstricteqnull':    'acc === null',
    'jnstricteqnull':   'acc !== null',
    'jequndefined':     'acc == undefined',
    'jneundefined':     'acc != undefined',
    'jstrictequndefined': 'acc === undefined',
    'jnstrictequndefined': 'acc !== undefined',
}

# Two-operand conditional branches: (mnemonic, operator)
_REG_COND_BRANCH: Dict[str, str] = {
    'jeq': '==', 'jne': '!=', 'jstricteq': '===', 'jnstricteq': '!==',
}

# All call mnemonics in ARK (callarg*, callthis*, callrange, callthisrange,
# supercall*, callruntime.*)
_CALL_PREFIXES = ('callarg', 'callthis', 'callrange', 'supercall',
                  'callruntime', 'apply', 'newobjrange', 'newobjapply')

# Accumulator-load operations with direct values
_ACC_LITERALS: Dict[str, str] = {
    'ldundefined': 'undefined',
    'ldnull':      'null',
    'ldtrue':      'true',
    'ldfalse':     'false',
    'ldnan':       'NaN',
    'ldinfinity':  'Infinity',
    'ldthis':      'this',
    'ldglobal':    'globalThis',
    'ldnewtarget': 'new.target',
    'ldhole':      '<hole>',
    'ldsymbol':    'Symbol',
    'ldfunction':  '<function>',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sign_extend(val: int, bits: int) -> int:
    """Sign-extend an unsigned integer to a signed value."""
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)


_BINARY_OPS_RE = (' + ', ' - ', ' * ', ' / ', ' % ', ' ** ',
                   ' == ', ' != ', ' === ', ' !== ',
                   ' < ', ' > ', ' <= ', ' >= ',
                   ' && ', ' || ', ' in ', ' instanceof ')


def _paren(expr: str) -> str:
    """Wrap expr in parentheses when inlining would change precedence."""
    return f'({expr})' if any(op in expr for op in _BINARY_OPS_RE) else expr


def _rhs_of(stmt: str) -> str:
    """Return the right-hand side of a statement, stripping trailing comments."""
    s = stmt.split('//')[0]  # strip comment
    return s.split(' = ', 1)[1] if ' = ' in s else s


def _propagate_acc(lines: List[str]) -> List[str]:
    """Accumulator copy-propagation pass (Cifuentes §5.4.6, single-BB variant).

    For each `_acc = EXPR` statement:
    - If the next substantive line's rhs does not contain `_acc` at all:
      the assignment is dead (next line redefines or ignores acc) → drop it.
    - If the next substantive line's rhs contains `_acc` exactly once:
      substitute EXPR inline and drop the assignment.
    - If `_acc` appears multiple times in the rhs: keep (cannot safely inline).

    Labels and blank lines are treated as transparent for look-ahead purposes.
    This pass is sound within a single basic block; cross-block propagation
    requires full ud-chain / liveness analysis and is left for a future pass.
    """
    drop: Set[int] = set()
    lines = list(lines)  # work on a copy so mutations don't alias

    def _is_transparent(s: str) -> bool:
        t = s.strip()
        return not t or t.endswith(':') or t in ('{', '}') or t.startswith('//')

    for i, line in enumerate(lines):
        if i in drop:
            continue
        stripped = line.strip()
        if not stripped.startswith('_acc = '):
            continue
        expr = stripped[len('_acc = '):]

        # Find next substantive line
        j = i + 1
        while j < len(lines) and _is_transparent(lines[j]):
            j += 1
        if j >= len(lines):
            continue

        rhs = _rhs_of(lines[j].strip())
        cnt = rhs.count('_acc')

        if cnt == 0:
            drop.add(i)  # dead assignment
        elif cnt == 1:
            lines[j] = lines[j].replace('_acc', _paren(expr), 1)
            drop.add(i)
        # cnt > 1: leave both lines intact

    return [line for idx, line in enumerate(lines) if idx not in drop]


# ── v2.27.0: Control flow structuring (Cifuentes §6.6.1/§6.6.2) ──────────────

_LBL_RE  = _re.compile(r'^  (L_[0-9a-f]+):$')
_GOTO_RE = _re.compile(r'^    goto (L_[0-9a-f]+)$')
_COND_RE = _re.compile(r'^    if \((.+)\) goto (L_[0-9a-f]+)$')


@dataclass
class _BB:
    idx:       int
    label:     Optional[str]
    stmts:     List[str]       # body lines as-emitted (indented)
    term:      str             # terminal line as-emitted, or ""
    term_type: str             # "goto" | "cond" | "return" | "fall"
    goto_tgt:  Optional[str]
    cond_expr: Optional[str]


def _parse_blocks(body: List[str]) -> List[_BB]:
    """Split flat body lines into basic blocks at label and branch boundaries."""
    blocks:    List[_BB]     = []
    cur_label: Optional[str] = None
    cur_stmts: List[str]     = []

    def _flush(term: str = '', tt: str = 'fall',
               tgt: Optional[str] = None,
               cexpr: Optional[str] = None) -> None:
        nonlocal cur_label, cur_stmts
        b = _BB(len(blocks), cur_label, cur_stmts[:], term, tt, tgt, cexpr)
        if b.label or b.stmts or b.term:
            blocks.append(b)
        cur_label = None
        cur_stmts = []

    for line in body:
        lm = _LBL_RE.match(line)
        if lm:
            _flush()
            cur_label = lm.group(1)
            continue
        gm = _GOTO_RE.match(line)
        if gm:
            _flush(line, 'goto', gm.group(1))
            continue
        cm = _COND_RE.match(line)
        if cm:
            _flush(line, 'cond', cm.group(2), cm.group(1))
            continue
        if line.strip().startswith('return'):
            _flush(line, 'return')
            continue
        cur_stmts.append(line)

    _flush()
    for k, b in enumerate(blocks):
        b.idx = k
    return blocks


_OP_FLIP: Dict[str, str] = {
    '==': '!=',  '!=': '==',
    '===': '!==', '!==': '===',
    '<': '>=',   '>=': '<',
    '>': '<=',   '<=': '>',
}


def _negate(cond: str) -> str:
    for op, neg in _OP_FLIP.items():
        tok = f' {op} '
        if tok in cond:
            return cond.replace(tok, f' {neg} ', 1)
    return f'!({cond})'


def _structure_cfg(lines: List[str]) -> List[str]:
    """Control flow structuring pass (Cifuentes §6.6.1/§6.6.2).

    Recovers while loops (pre-tested), if/else, and simple if from the
    label+goto skeleton produced by the lift and propagation passes.
    Unrecognized patterns fall back to raw label+goto output unchanged.
    """
    if not lines or len(lines) < 4:
        return lines
    header, footer = lines[0], lines[-1]
    body = lines[1:-1]

    blocks = _parse_blocks(body)
    if len(blocks) <= 1:
        return lines

    lidx: Dict[str, int] = {b.label: b.idx for b in blocks if b.label}

    out: List[str] = [header]
    _cfg_emit(blocks, lidx, 0, len(blocks), out, '    ')
    out.append(footer)
    return out


def _cfg_emit(bls: List[_BB], lidx: Dict[str, int],
              start: int, end: int, out: List[str], pfx: str) -> None:
    i = start
    while i < end:
        n = _try_while(bls, lidx, i, end, out, pfx)
        if not n:
            n = _try_if(bls, lidx, i, end, out, pfx)
        if n:
            i += n
        else:
            _raw_bb(bls[i], out, pfx)
            i += 1


def _raw_bb(bb: _BB, out: List[str], pfx: str) -> None:
    if bb.label:
        lp = pfx[2:] if len(pfx) >= 2 else ''
        out.append(f'{lp}{bb.label}:')
    for s in bb.stmts:
        out.append(f'{pfx}{s.strip()}')
    if bb.term:
        out.append(f'{pfx}{bb.term.strip()}')


def _try_while(bls: List[_BB], lidx: Dict[str, int],
               i: int, end: int, out: List[str], pfx: str) -> int:
    """Detect pre-tested while loop (Cifuentes §6.6.1, Definition 59).

    Header (i):      L_head: [stmts] if (exit_cond) goto L_after
    Body (i+1..j-1): body blocks
    Latching (j):    [stmts] goto L_head  (back-edge)
    After (after_idx): L_after block

    Returns blocks consumed (i through after_idx-1 inclusive), or 0.
    """
    bb = bls[i]
    if not (bb.label and bb.term_type == 'cond'):
        return 0
    after_idx = lidx.get(bb.goto_tgt, -1)
    if not (i < after_idx <= end):
        return 0

    back_j = -1
    for j in range(i + 1, after_idx):
        if bls[j].term_type == 'goto' and bls[j].goto_tgt == bb.label:
            back_j = j  # take last back-edge (innermost continue stays raw)

    if back_j < 0:
        return 0

    body_pfx = pfx + '    '
    for s in bb.stmts:
        out.append(f'{pfx}{s.strip()}')
    out.append(f'{pfx}while ({_negate(bb.cond_expr)}) {{')
    _cfg_emit(bls, lidx, i + 1, back_j, out, body_pfx)
    lj = bls[back_j]
    if lj.label:
        out.append(f'{body_pfx[2:]}{lj.label}:')
    for s in lj.stmts:
        out.append(f'{body_pfx}{s.strip()}')
    out.append(f'{pfx}}}')
    return after_idx - i


def _try_if(bls: List[_BB], lidx: Dict[str, int],
            i: int, end: int, out: List[str], pfx: str) -> int:
    """Detect if/else and simple if (Cifuentes §6.6.2).

    Pattern A (if/else):
        if (cond) goto L_else; [then ending with goto L_end]; L_else: [else]; L_end:
    Pattern B (simple if):
        if (cond) goto L_skip; [then]; L_skip:

    In both cases the fall-through path is the then-branch, so the emitted
    condition is negated: if (!cond) { then }.

    Returns blocks consumed, or 0 if no pattern matches.
    """
    bb = bls[i]
    if bb.term_type != 'cond':
        return 0
    else_idx = lidx.get(bb.goto_tgt, -1)
    if not (i < else_idx <= end):
        return 0

    for s in bb.stmts:
        out.append(f'{pfx}{s.strip()}')

    body_pfx = pfx + '    '

    # Pattern A: last then-block ends with a forward goto (the join point)
    if else_idx > i + 1:
        lt = bls[else_idx - 1]
        if lt.term_type == 'goto':
            end_idx = lidx.get(lt.goto_tgt, -1)
            if else_idx <= end_idx <= end:
                out.append(f'{pfx}if ({_negate(bb.cond_expr)}) {{')
                _cfg_emit(bls, lidx, i + 1, else_idx - 1, out, body_pfx)
                if lt.label:
                    out.append(f'{body_pfx[2:]}{lt.label}:')
                for s in lt.stmts:
                    out.append(f'{body_pfx}{s.strip()}')
                out.append(f'{pfx}}} else {{')
                _cfg_emit(bls, lidx, else_idx, end_idx, out, body_pfx)
                out.append(f'{pfx}}}')
                return end_idx - i

    # Pattern B: simple if
    out.append(f'{pfx}if ({_negate(bb.cond_expr)}) {{')
    _cfg_emit(bls, lidx, i + 1, else_idx, out, body_pfx)
    out.append(f'{pfx}}}')
    return else_idx - i


# ─────────────────────────────────────────────────────────────────────────────

def _label(offset: int) -> str:
    return f'L_{offset:04x}'


def _rname(n: int) -> str:
    return f'v{n}'


_ACC = '_acc'


@dataclass
class _Reg:
    expr: str
    uses: int = 0

    def read(self) -> str:
        self.uses += 1
        return self.expr


# ── Register-state helpers ────────────────────────────────────────────────────

def _get(state: Dict[str, _Reg], name: str) -> str:
    r = state.get(name)
    if r is None:
        return name
    return r.read()


def _set(state: Dict[str, _Reg], name: str, expr: str) -> None:
    state[name] = _Reg(expr)


def _acc_val(state: Dict[str, _Reg]) -> str:
    return _get(state, _ACC)


def _set_acc(state: Dict[str, _Reg], expr: str) -> None:
    _set(state, _ACC, expr)


# ── Branch target extraction ──────────────────────────────────────────────────

def _branch_targets(insns: List[ARKInstruction]) -> Set[int]:
    """Return the set of bytecode offsets that are branch destinations."""
    targets: Set[int] = set()
    for insn in insns:
        m = insn.mnemonic
        if m in _COND_BRANCH or m in _REG_COND_BRANCH or m == 'jmp':
            # Get the offset operand (last 'i' kind)
            for kind, val in reversed(insn.operands):
                if kind == 'i':
                    signed = _sign_extend(val, _offset_bits(val))
                    targets.add(insn.offset + signed)
                    break
    return targets


def _offset_bits(val: int) -> int:
    """Infer signed bit width from raw unsigned value for branch offsets."""
    if val <= 0xFF:
        return 8
    if val <= 0xFFFF:
        return 16
    return 32


# ── Main decompiler class ─────────────────────────────────────────────────────

class ABCDecompiler:
    """
    Decompile ARK Bytecode (ABC) methods to JavaScript-like pseudocode.

    Wraps ABCParser and ARKDisasm.  Translates CodeItem instruction streams
    to readable pseudocode using register-state accumulator tracking.

    Security-relevant output: string loads, property accesses, object
    construction, function definitions, and exception handler counts are all
    surfaced inline.
    """

    def __init__(self, parser: ABCParser,
                 disasm: Optional[ARKDisasm] = None) -> None:
        self.parser = parser
        self._dis = disasm or ARKDisasm(parser)

    @classmethod
    def from_path(cls, path: str) -> 'ABCDecompiler':
        """Construct directly from an ABC file path."""
        return cls(ABCParser.from_path(path))

    def decompile_method(self, method: MethodInfo,
                         code: Optional[CodeItem] = None) -> str:
        """Return JS-like pseudocode for *method*."""
        if code is None:
            code = self.parser.get_code(method)
        if code is None:
            return f'// {method.fqn} — no code\n'

        insns = list(self._dis.iter_insns(code))
        branch_tgts = _branch_targets(insns)

        nparams = code.parameter_count
        # In ARK, argument registers are the last `parameter_count` vregs.
        args_start = code.register_count - nparams
        param_names = [f'a{i}' for i in range(nparams)]

        lines: List[str] = [
            f'function {method.method_name}({", ".join(param_names)}) {{',
            f'    // {method.class_name}',
        ]
        if code.exception_handler_count:
            lines.append(f'    // exc_handlers={code.exception_handler_count}')

        # Seed register state with parameter names
        state: Dict[str, _Reg] = {_ACC: _Reg('undefined')}
        for i in range(nparams):
            state[_rname(args_start + i)] = _Reg(f'a{i}')

        for insn in insns:
            if insn.offset in branch_tgts:
                lines.append(f'  {_label(insn.offset)}:')
            stmt = self._lift(insn, state)
            if stmt:
                lines.append(f'    {stmt}')

        lines.append('}')
        lines = _propagate_acc(lines)
        lines = _structure_cfg(lines)
        return '\n'.join(lines)

    def decompile_class(self, class_name: str) -> str:
        """Decompile all methods whose class name contains *class_name*."""
        parts: List[str] = []
        for method in self.parser.iter_methods():
            if class_name in method.class_name:
                code = self.parser.get_code(method)
                if code:
                    parts.append(self.decompile_method(method, code))
        return '\n\n'.join(parts)

    def decompile_all(self) -> Iterator[str]:
        """Yield pseudocode for every method with code in the file."""
        for method in self.parser.iter_methods():
            code = self.parser.get_code(method)
            if code:
                yield self.decompile_method(method, code)

    # ── Instruction lifting ───────────────────────────────────────────────────

    def _lift(self, insn: ARKInstruction, state: Dict[str, _Reg]) -> str:
        m = insn.mnemonic
        ops = insn.operands  # [(kind, val), ...]

        # ── Literal accumulator loads ──────────────────────────────────────────
        if m in _ACC_LITERALS:
            _set_acc(state, _ACC_LITERALS[m])
            return f'_acc = {_ACC_LITERALS[m]}'

        # ── lda (load register -> acc) ─────────────────────────────────────────
        if m == 'lda':
            reg = _rname(ops[0][1])
            _set_acc(state, _get(state, reg))
            return f'_acc = {reg}'

        # ── sta (acc -> register) ─────────────────────────────────────────────
        if m == 'sta':
            reg = _rname(ops[0][1])
            _set(state, reg, _acc_val(state))
            return f'{reg} = _acc'

        # ── mov ───────────────────────────────────────────────────────────────
        if m == 'mov':
            dst = _rname(ops[0][1])
            src = _rname(ops[1][1])
            _set(state, dst, _get(state, src))
            return f'{dst} = {src}'

        # ── lda.str / ldbigint ────────────────────────────────────────────────
        if m in ('lda.str', 'ldbigint'):
            idx = ops[0][1]
            s = self.parser.resolve_class_idx(idx)
            if s:
                expr = f'"{_esc(s)}"'
            else:
                expr = f'<str@{hex(idx)}>'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        # ── ldai / fldai (integer / float literal) ───────────────────────────
        if m == 'ldai':
            val = _sign_extend(ops[0][1], 32)
            _set_acc(state, str(val))
            return f'_acc = {val}'

        if m == 'fldai':
            _set_acc(state, f'<float {ops[0][1]}>')
            return f'_acc = <float {ops[0][1]}>'

        # ── Binary operations (acc op= reg) ──────────────────────────────────
        if m in _BIN_OPS:
            op = _BIN_OPS[m]
            # ops: [(i, slot), (r, reg_idx)]
            reg_idx = next((v for k, v in ops if k == 'r'), None)
            if reg_idx is not None:
                rhs = _rname(reg_idx)
                acc = _acc_val(state)
                expr = f'{acc} {op} {rhs}'
                _set_acc(state, expr)
                return f'_acc = {expr}'
            return f'// {insn}'

        # ── Unary operations (acc = op(acc)) ─────────────────────────────────
        if m in _UNARY_OPS:
            tmpl = _UNARY_OPS[m]
            acc = _acc_val(state)
            expr = tmpl.replace('acc', acc)
            _set_acc(state, expr)
            return f'_acc = {expr}'

        # ── Property load: ldobjbyname / ldthisbyname ─────────────────────────
        if m in ('ldobjbyname', 'ldobjbyvalue'):
            # ldobjbyname: (i=slot, d=prop_entity_id) — obj implied by context
            # ldobjbyvalue: (i=slot, r=obj_reg) — key is acc
            if m == 'ldobjbyname':
                prop = self._resolve_entity(ops)
                # There's no explicit object register in the short form.
                # The object is typically in the preceding lda/sta.
                acc = _acc_val(state)
                expr = f'{acc}.{prop}'
                _set_acc(state, expr)
                return f'_acc = {expr}'
            else:
                obj = _rname(next((v for k, v in ops if k == 'r'), 0))
                key = _acc_val(state)
                expr = f'{obj}[{key}]'
                _set_acc(state, expr)
                return f'_acc = {expr}'

        if m in ('ldthisbyname', 'ldsuperbyname'):
            prop = self._resolve_entity(ops)
            src = 'this' if 'this' in m else 'super'
            expr = f'{src}.{prop}'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        if m == 'ldthisbyvalue':
            key = _acc_val(state)
            expr = f'this[{key}]'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        # ── Property store: stobjbyname / stthisbyname ────────────────────────
        if m in ('stobjbyname', 'stownbyname', 'stownbynamewithnameset',
                 'definepropertybyname', 'definefieldbyname'):
            prop = self._resolve_entity(ops)
            obj_reg = next((v for k, v in ops if k == 'r'), None)
            obj = _rname(obj_reg) if obj_reg is not None else '???'
            acc = _acc_val(state)
            return f'{obj}.{prop} = {acc}'

        if m in ('stthisbyname', 'stsuperbyname', 'stconsttoglobalrecord',
                 'sttoglobalrecord'):
            prop = self._resolve_entity(ops)
            src = 'this' if 'this' in m else ('super' if 'super' in m else 'global')
            acc = _acc_val(state)
            return f'{src}.{prop} = {acc}'

        if m in ('stobjbyvalue', 'stownbyvalue', 'stownbyvaluewithnameset',
                 'stthisbyvalue', 'stsuperbyvalue'):
            regs = [v for k, v in ops if k == 'r']
            if m in ('stobjbyvalue', 'stownbyvalue', 'stownbyvaluewithnameset',
                     'stsuperbyvalue') and len(regs) >= 2:
                obj, key = _rname(regs[0]), _rname(regs[1])
                return f'{obj}[{key}] = _acc'
            elif m == 'stthisbyvalue' and regs:
                return f'this[{_rname(regs[0])}] = _acc'
            return f'// {insn}'

        if m == 'stobjbyindex':
            regs = [v for k, v in ops if k == 'r']
            imms = [v for k, v in ops if k == 'i']
            if regs and len(imms) >= 2:
                return f'{_rname(regs[0])}[{imms[1]}] = _acc'
            return f'// {insn}'

        if m == 'ldobjbyindex':
            imms = [v for k, v in ops if k == 'i']
            if len(imms) >= 2:
                expr = f'_acc[{imms[1]}]'
                _set_acc(state, expr)
                return f'_acc = {expr}'
            return f'// {insn}'

        # ── Global variable access ────────────────────────────────────────────
        if m in ('ldglobalvar', 'tryldglobalbyname'):
            name = self._resolve_entity(ops)
            _set_acc(state, name)
            return f'_acc = {name}  // global'

        if m in ('stglobalvar', 'trystglobalbyname'):
            name = self._resolve_entity(ops)
            acc = _acc_val(state)
            return f'{name} = {acc}  // global'

        # ── Lexical variable access ───────────────────────────────────────────
        if m in ('ldlexvar', 'callruntime.ldsendablevar'):
            lvl = ops[0][1]
            slot = ops[1][1] if len(ops) > 1 else 0
            expr = f'env[{lvl}][{slot}]'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        if m in ('stlexvar', 'callruntime.stsendablevar'):
            lvl = ops[0][1]
            slot = ops[1][1] if len(ops) > 1 else 0
            acc = _acc_val(state)
            return f'env[{lvl}][{slot}] = {acc}'

        # ── Module variable access ────────────────────────────────────────────
        if m == 'ldlocalmodulevar':
            slot = ops[0][1]
            expr = f'local_export[{slot}]'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        if m == 'ldexternalmodulevar':
            slot = ops[0][1]
            expr = f'import[{slot}]'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        if m == 'stmodulevar':
            slot = ops[0][1]
            return f'export[{slot}] = _acc'

        if m == 'getmodulenamespace':
            slot = ops[0][1]
            expr = f'namespace[{slot}]'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        # ── Call instructions ─────────────────────────────────────────────────
        if m == 'callarg0':
            func = _acc_val(state)
            _set_acc(state, f'{func}()')
            return f'_acc = {func}()'

        if m == 'callarg1':
            reg = next((v for k, v in ops if k == 'r'), None)
            arg = _rname(reg) if reg is not None else '???'
            func = _acc_val(state)
            _set_acc(state, f'{func}({arg})')
            return f'_acc = {func}({arg})'

        if m == 'callargs2':
            regs = [v for k, v in ops if k == 'r']
            args = ', '.join(_rname(r) for r in regs)
            func = _acc_val(state)
            _set_acc(state, f'{func}({args})')
            return f'_acc = {func}({args})'

        if m == 'callargs3':
            regs = [v for k, v in ops if k == 'r']
            args = ', '.join(_rname(r) for r in regs)
            func = _acc_val(state)
            _set_acc(state, f'{func}({args})')
            return f'_acc = {func}({args})'

        if m == 'callthis0':
            obj_reg = next((v for k, v in ops if k == 'r'), None)
            obj = _rname(obj_reg) if obj_reg is not None else 'this'
            func = _acc_val(state)
            _set_acc(state, f'{func}.call({obj})')
            return f'_acc = {func}.call({obj})'

        if m == 'callthis1':
            regs = [v for k, v in ops if k == 'r']
            obj = _rname(regs[0]) if regs else 'this'
            arg = _rname(regs[1]) if len(regs) > 1 else '???'
            func = _acc_val(state)
            _set_acc(state, f'{func}.call({obj}, {arg})')
            return f'_acc = {func}.call({obj}, {arg})'

        if m == 'callthis2':
            regs = [v for k, v in ops if k == 'r']
            obj = _rname(regs[0]) if regs else 'this'
            args = ', '.join(_rname(r) for r in regs[1:])
            func = _acc_val(state)
            _set_acc(state, f'{func}.call({obj}, {args})')
            return f'_acc = {func}.call({obj}, {args})'

        if m == 'callthis3':
            regs = [v for k, v in ops if k == 'r']
            obj = _rname(regs[0]) if regs else 'this'
            args = ', '.join(_rname(r) for r in regs[1:])
            func = _acc_val(state)
            _set_acc(state, f'{func}.call({obj}, {args})')
            return f'_acc = {func}.call({obj}, {args})'

        if m in ('callrange', 'callthisrange', 'supercallthisrange',
                 'supercallarrowrange'):
            # ops: (i=slot, i=nargs, r=first_arg)
            imms = [v for k, v in ops if k == 'i']
            regs = [v for k, v in ops if k == 'r']
            nargs = imms[1] if len(imms) > 1 else 0
            first = regs[0] if regs else 0
            args = ', '.join(_rname(first + i) for i in range(nargs))
            func = _acc_val(state)
            _set_acc(state, f'{func}({args})')
            return f'_acc = {func}({args})'

        if m == 'apply':
            regs = [v for k, v in ops if k == 'r']
            obj = _rname(regs[0]) if regs else 'null'
            arr = _rname(regs[1]) if len(regs) > 1 else '[]'
            func = _acc_val(state)
            _set_acc(state, f'{func}.apply({obj}, {arr})')
            return f'_acc = {func}.apply({obj}, {arr})'

        if m in ('newobjrange', 'newobjapply'):
            imms = [v for k, v in ops if k == 'i']
            regs = [v for k, v in ops if k == 'r']
            nargs = imms[1] if len(imms) > 1 else 0
            first = regs[0] if regs else 0
            args = ', '.join(_rname(first + i) for i in range(nargs))
            ctor = _acc_val(state)
            expr = f'new {ctor}({args})'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        # ── Object/array construction ─────────────────────────────────────────
        if m == 'createemptyobject':
            _set_acc(state, '{}')
            return '_acc = {}'

        if m == 'createemptyarray':
            _set_acc(state, '[]')
            return '_acc = []'

        if m in ('createarraywithbuffer', 'createobjectwithbuffer'):
            kind = 'array' if 'array' in m else 'object'
            _set_acc(state, f'<{kind}_literal>')
            return f'_acc = <{kind}_literal>'

        # ── Function / class definition ───────────────────────────────────────
        if m in ('definefunc', 'definemethod'):
            entity_id = next((v for k, v in ops if k == 'd'), None)
            name = self._lookup_func_name(entity_id)
            _set_acc(state, f'function {name}')
            return f'_acc = function {name}(...)  // entity {hex(entity_id) if entity_id is not None else "?"}'

        if m in ('defineclasswithbuffer', 'callruntime.definesendableclass'):
            entity_id = next((v for k, v in ops if k == 'd'), None)
            name = self._lookup_func_name(entity_id)
            _set_acc(state, f'class {name}')
            return f'_acc = class {name}  // entity {hex(entity_id) if entity_id is not None else "?"}'

        # ── Return instructions ───────────────────────────────────────────────
        if m == 'return':
            return 'return _acc'

        if m == 'returnundefined':
            return 'return undefined'

        # ── Unconditional jump ────────────────────────────────────────────────
        if m == 'jmp':
            tgt = self._branch_tgt(insn)
            return f'goto {_label(tgt)}' if tgt is not None else f'goto ??? // {insn}'

        # ── Conditional branches ──────────────────────────────────────────────
        if m in _COND_BRANCH:
            tgt = self._branch_tgt(insn)
            cond = _COND_BRANCH[m].replace('acc', _acc_val(state))
            lbl = _label(tgt) if tgt is not None else '???'
            return f'if ({cond}) goto {lbl}'

        if m in _REG_COND_BRANCH:
            op = _REG_COND_BRANCH[m]
            regs = [v for k, v in ops if k == 'r']
            rhs = _rname(regs[0]) if regs else '???'
            tgt = self._branch_tgt(insn)
            lbl = _label(tgt) if tgt is not None else '???'
            acc = _acc_val(state)
            return f'if ({acc} {op} {rhs}) goto {lbl}'

        # ── Throw ─────────────────────────────────────────────────────────────
        if m.startswith('throw'):
            acc = _acc_val(state)
            return f'throw {acc}'

        # ── Lexical scope management ──────────────────────────────────────────
        if m in ('newlexenv', 'newlexenvwithname'):
            n = ops[0][1]
            return f'// new_scope(vars={n})'

        if m == 'poplexenv':
            return '// pop_scope()'

        # ── Iterator / generator / async helpers ──────────────────────────────
        if m == 'getpropiterator':
            _set_acc(state, 'Object.keys(_acc)[Symbol.iterator]()')
            return '_acc = Object.keys(_acc)[Symbol.iterator]()'

        if m in ('getiterator', 'getasynciterator'):
            _set_acc(state, '_acc[Symbol.iterator]()')
            return f'_acc = _acc[Symbol.iterator]()'

        if m == 'getnextpropname':
            reg = ops[0][1]
            _set_acc(state, f'<next_prop({_rname(reg)})>')
            return f'_acc = <next_prop({_rname(reg)})>'

        if m in ('resumegenerator', 'getresumemode'):
            return f'// {m}'

        if m == 'suspendgenerator':
            reg = ops[0][1]
            return f'yield _acc  // generator={_rname(reg)}'

        if m == 'asyncfunctionenter':
            return '// async enter'

        if m in ('asyncfunctionresolve', 'asyncfunctionreject'):
            reg = ops[0][1]
            return f'// async_{m.split(".")[-1]}({_rname(reg)})'

        if m == 'asyncfunctionawaituncaught':
            reg = ops[0][1]
            return f'_acc = await _acc  // promise={_rname(reg)}'

        if m == 'dynamicimport':
            acc = _acc_val(state)
            expr = f'await import({acc})'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        if m == 'copyrestargs':
            slot = ops[0][1]
            _set_acc(state, f'...args[{slot}:]')
            return f'_acc = rest_args(from={slot})'

        if m == 'getunmappedargs':
            _set_acc(state, 'arguments')
            return '_acc = arguments'

        # ── Own-property definition (object literal helpers) ──────────────────
        if m in ('stownbyindex',):
            regs = [v for k, v in ops if k == 'r']
            imms = [v for k, v in ops if k == 'i']
            if regs and len(imms) >= 2:
                return f'{_rname(regs[0])}[{imms[1]}] = _acc'
            return f'// {insn}'

        if m == 'delobjprop':
            reg = ops[0][1]
            acc = _acc_val(state)
            return f'delete {_rname(reg)}[{acc}]'

        if m == 'copydataproperties':
            reg = ops[0][1]
            return f'Object.assign({_rname(reg)}, _acc)'

        if m == 'starrayspread':
            regs = [v for k, v in ops if k == 'r']
            dst = _rname(regs[0]) if regs else '???'
            idx = _rname(regs[1]) if len(regs) > 1 else '???'
            return f'{dst}[{idx}++] = ..._acc'

        if m == 'createiterresultobj':
            regs = [v for k, v in ops if k == 'r']
            val, done = (_rname(regs[0]), _rname(regs[1])) if len(regs) >= 2 else ('?', '?')
            expr = f'{{value: {val}, done: {done}}}'
            _set_acc(state, expr)
            return f'_acc = {expr}'

        # ── Misc ──────────────────────────────────────────────────────────────
        if m == 'nop':
            return ''

        if m == 'debugger':
            return 'debugger'

        if m == 'setobjectwithproto':
            reg = next((v for k, v in ops if k == 'r'), None)
            src = _rname(reg) if reg is not None else '???'
            return f'Object.setPrototypeOf(_acc, {src})'

        if m == 'getunmappedargs':
            _set_acc(state, 'arguments')
            return '_acc = arguments'

        if m == 'closeiterator':
            reg = next((v for k, v in ops if k == 'r'), None)
            return f'// close_iter({_rname(reg) if reg is not None else "?"})'

        if m.startswith('deprecated.'):
            return f'// {m}  /* deprecated */'

        if m.startswith('callruntime.'):
            return f'// {m}({", ".join(str(v) for _, v in ops)})'

        if m == '.data':
            return f'// .data {hex(ops[0][1])}'

        # Catch-all: emit as comment so nothing is silently dropped
        return f'// {insn}'

    # ── Entity resolution helpers ─────────────────────────────────────────────

    def _resolve_entity(self, ops: list) -> str:
        """Resolve the 'd'-kind operand to a property/global name string.

        Property-access and global-variable instructions encode their 'd' operand
        as an INDEX into IndexHeader.method_idx (not a raw file offset and not
        class_idx).  method_idx[N] → entity_id → string.
        """
        for kind, val in ops:
            if kind == 'd':
                s = self.parser.resolve_method_idx(val)
                return s if s else hex(val)
        return '???'

    def _lookup_func_name(self, entity_id: Optional[int]) -> str:
        """Look up a method name by entity_id (file offset of method item)."""
        if entity_id is None:
            return '???'
        for method in self.parser.iter_methods():
            if method.entity_id == entity_id:
                return method.method_name
        return hex(entity_id)

    def _branch_tgt(self, insn: ARKInstruction) -> Optional[int]:
        """Return absolute bytecode offset of branch target."""
        for kind, val in reversed(insn.operands):
            if kind == 'i':
                signed = _sign_extend(val, _offset_bits(val))
                return insn.offset + signed
        return None


# ── String escaping ───────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    """Minimal escaping for embedding a string in double-quoted JS output."""
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
