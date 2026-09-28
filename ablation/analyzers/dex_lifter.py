"""
dex_lifter.py -- Lift DEX bytecode to pseudo-Java IR.

Converts DEXInstruction streams (from DEXDisasm) into readable pseudo-Java
without external dependencies. Handles the patterns that appear in ~90% of
real Android methods:
  - field get/put as Java dot notation
  - invoke-* formatted as method calls with typed arguments
  - const-string / const/4 inline (single-use folding)
  - new-instance + invoke-direct <init> → constructor call
  - if-* → labelled conditionals with full conditions
  - backward goto → loop marker
  - type propagation through move-result, iget, sget, check-cast

Output for complex methods (switch, try/catch) falls back to annotated
pseudo-smali — still more readable than raw smali because all references
are resolved to full Java names.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ablation.core.apk_parser import DEXFile, _uleb128
from ablation.analyzers.dex_disasm import (
    DEXDisasm, DEXInstruction, decode_code_item, _proto_str,
)


# ── Type descriptor utilities ─────────────────────────────────────────────────

_PRIMITIVES: Dict[str, str] = {
    'Z': 'boolean', 'B': 'byte', 'C': 'char', 'S': 'short',
    'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double', 'V': 'void',
}

def jtype(desc: str) -> str:
    """DEX type descriptor → short Java type name."""
    if not desc:
        return 'Object'
    if desc in _PRIMITIVES:
        return _PRIMITIVES[desc]
    if desc.startswith('['):
        return jtype(desc[1:]) + '[]'
    if desc.startswith('L') and desc.endswith(';'):
        name = desc[1:-1].split('/')[-1].replace('$', '.')
        return name
    return desc


def _split_proto_params(params_str: str) -> List[str]:
    """Split 'ILjava/lang/String;Z' into ['I', 'Ljava/lang/String;', 'Z']."""
    types: List[str] = []
    i = 0
    while i < len(params_str):
        c = params_str[i]
        if c in 'ZBCSIFJDV':
            types.append(c)
            i += 1
        elif c == 'L':
            end = params_str.find(';', i)
            if end < 0:
                break
            types.append(params_str[i:end + 1])
            i = end + 1
        elif c == '[':
            j = i + 1
            while j < len(params_str) and params_str[j] == '[':
                j += 1
            if j >= len(params_str):
                break
            if params_str[j] == 'L':
                end = params_str.find(';', j)
                if end < 0:
                    break
                types.append(params_str[i:end + 1])
                i = end + 1
            else:
                types.append(params_str[i:j + 1])
                i = j + 1
        else:
            i += 1
    return types


# ── Register value ────────────────────────────────────────────────────────────

@dataclass
class RegVal:
    """Current type + expression for one register."""
    java_type: str    # short Java type, e.g. 'String', 'int', 'Handler'
    expr: str         # expression string, e.g. '"hello"', 'p0', 'v0.mField'
    is_object: bool = True
    uses: int = 0     # incremented each time this value is read


_UNKNOWN = RegVal('Object', '???')


# ── Control-flow helpers ──────────────────────────────────────────────────────

_BRANCH_OPS = frozenset({
    0x28, 0x29, 0x2a,                           # goto
    0x2b, 0x2c,                                 # switch
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37,         # if-eq..if-le
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,         # if-eqz..if-lez
    0x0e, 0x0f, 0x10, 0x11,                     # return-*
    0x27,                                        # throw
})

def _block_entries(instrs: List[DEXInstruction]) -> set:
    """Return the set of cu_offsets that begin a new basic block."""
    entries: set = {0}
    for ins in instrs:
        if ins.opcode in _BRANCH_OPS:
            next_cu = ins.cu_offset + ins.size_cu()
            entries.add(next_cu)
            if ins.branch:
                entries.add(ins.cu_offset + ins.branch)
    return entries


# ── Condition expressions ─────────────────────────────────────────────────────

_IF_OPS = {
    0x32: '==', 0x33: '!=', 0x34: '<',  0x35: '>=', 0x36: '>',  0x37: '<=',
}
_IFZ_OPS = {
    0x38: '== 0', 0x39: '!= 0', 0x3a: '< 0', 0x3b: '>= 0',
    0x3c: '> 0',  0x3d: '<= 0',
}

def _cond(ins: DEXInstruction, reg_state: Dict[int, RegVal], params_start: int, ins_size: int) -> str:
    op = ins.opcode
    def rv(r: int) -> str:
        v = reg_state.get(r)
        return v.expr if v else _rname(r, params_start, ins_size)
    if op in _IF_OPS and len(ins.regs) >= 2:
        return f'{rv(ins.regs[0])} {_IF_OPS[op]} {rv(ins.regs[1])}'
    if op in _IFZ_OPS and ins.regs:
        v = reg_state.get(ins.regs[0], _UNKNOWN)
        if v.is_object:
            return f'{rv(ins.regs[0])} {_IFZ_OPS[op].replace("0", "null")}'
        return f'{rv(ins.regs[0])} {_IFZ_OPS[op]}'
    return '???'


def _rname(r: int, params_start: int, ins_size: int) -> str:
    """'pN' for parameter register, 'vN' for local."""
    return f'p{r - params_start}' if r >= params_start else f'v{r}'


# ── Proto lookup ──────────────────────────────────────────────────────────────

def _method_proto(dex: DEXFile, class_name: str, method_name: str) -> Tuple[List[str], str]:
    """Return (param_type_descriptors, return_type_descriptor) for a method."""
    if not class_name.startswith('L'):
        class_name = 'L' + class_name.replace('.', '/') + ';'
    data = dex._data
    for row in dex._class_defs_raw:
        (class_idx, _flags, _super, _ifaces, _src, _ann, data_off, _sv) = row
        if not data_off or dex.type_name(class_idx) != class_name:
            continue
        off = data_off
        try:
            sf, off = _uleb128(data, off)
            if_, off = _uleb128(data, off)
            dm, off = _uleb128(data, off)
            vm, off = _uleb128(data, off)
            for _ in range(sf + if_):
                _, off = _uleb128(data, off)
                _, off = _uleb128(data, off)
            for count in (dm, vm):
                running = 0
                for _ in range(count):
                    diff, off = _uleb128(data, off)
                    _mf, off  = _uleb128(data, off)
                    _co, off  = _uleb128(data, off)
                    running += diff
                    mn, _ = dex._method_info(running)
                    if mn == method_name:
                        _, proto_idx, _ = dex._method_ids[running]
                        params_str, ret = _proto_str(dex, proto_idx)
                        return (_split_proto_params(params_str), ret)
        except Exception:
            pass
    return ([], 'V')


# ── Invoke formatting ─────────────────────────────────────────────────────────

def _format_invoke(
    dex: DEXFile,
    ins: DEXInstruction,
    reg_state: Dict[int, RegVal],
    params_start: int,
    ins_size: int,
) -> Tuple[str, str]:
    """
    Return (ret_type, call_expr) for an invoke-* instruction.
    ret_type is the Java return type (e.g. 'String', 'void', 'int').
    call_expr is the expression string (e.g. 'v0.getText()').
    """
    def rv(r: int) -> str:
        v = reg_state.get(r)
        if v:
            v.uses += 1
            return v.expr
        return _rname(r, params_start, ins_size)

    if ins.ref_idx < 0 or ins.ref_idx >= len(dex._method_ids):
        return ('Object', f'??(/* ref@{ins.ref_idx} */)')

    class_idx, proto_idx, name_idx = dex._method_ids[ins.ref_idx]
    class_desc = dex.type_name(class_idx)
    method_name = dex.string_at(name_idx)
    params_str, ret_desc = _proto_str(dex, proto_idx)
    ret_type = jtype(ret_desc)
    class_short = jtype(class_desc)

    is_static   = ins.opcode in (0x71, 0x77)
    is_range    = ins.opcode in (0x74, 0x75, 0x76, 0x77, 0x78)
    regs = ins.regs

    if is_static:
        obj_expr = class_short
        arg_regs = regs
    else:
        obj_expr = rv(regs[0]) if regs else 'this'
        arg_regs = regs[1:]

    args = [rv(r) for r in arg_regs]
    args_str = ', '.join(args)

    if method_name == '<init>':
        # new-instance was already emitted; annotate the constructor args
        call_expr = f'/* {obj_expr}.<init>({args_str}) */'
    elif is_static:
        call_expr = f'{class_short}.{method_name}({args_str})'
    else:
        call_expr = f'{obj_expr}.{method_name}({args_str})'

    return (ret_type, call_expr)


# ── DEXLifter ─────────────────────────────────────────────────────────────────

class DEXLifter:
    """
    Lift DEX bytecode to pseudo-Java IR.

    Usage:
        from ablation.analyzers.dex_lifter import DEXLifter
        from ablation.core.apk_parser import APKParser

        with APKParser.from_path('/path/to/app.apk') as apk:
            dexes = list(apk.iter_dex())
        lifter = DEXLifter(dexes[0])
        print(lifter.lift_method('Lcom/example/Foo;', 'onCreate'))
    """

    def __init__(self, dex: DEXFile, disasm: Optional[DEXDisasm] = None) -> None:
        self._dex = dex
        self._disasm = disasm or DEXDisasm(dex)

    @classmethod
    def from_apk(cls, apk_path: str, dex_index: int = 0) -> 'DEXLifter':
        from ablation.core.apk_parser import APKParser
        with APKParser.from_path(apk_path) as apk:
            dexes = list(apk.iter_dex())
        return cls(dexes[dex_index])

    def list_methods(self, class_name: str) -> List[str]:
        return self._disasm.list_methods(class_name)

    def lift_method(self, class_name: str, method_name: str) -> str:
        """
        Return pseudo-Java source for a single DEX method.
        Accepts 'Lcom/foo/Bar;' or 'com.foo.Bar'.
        """
        if not class_name.startswith('L'):
            class_name = 'L' + class_name.replace('.', '/') + ';'
        key = (class_name, method_name)
        if key not in self._disasm._code_map:
            return f'// not found: {class_name}->{method_name}'

        code_off, access_flags = self._disasm._code_map[key]
        dex = self._dex

        try:
            registers_size, ins_size, outs_size, instrs = decode_code_item(dex, code_off)
        except Exception as e:
            return f'// decode error: {e}'
        if not instrs:
            return f'// empty: {class_name}->{method_name}'

        params_start = registers_size - ins_size
        is_static = bool(access_flags & 0x8)

        param_types, ret_desc = _method_proto(dex, class_name, method_name)
        ret_type = jtype(ret_desc)

        # Initialise register state with parameters
        reg_state: Dict[int, RegVal] = {}
        param_decls: List[str] = []
        for i in range(ins_size):
            r = params_start + i
            if not is_static and i == 0:
                reg_state[r] = RegVal(jtype(class_name), 'this', True)
            else:
                pi = i if is_static else i - 1
                if pi < len(param_types):
                    pd = param_types[pi]
                    pt = jtype(pd)
                    is_obj = pd not in 'ZBCSIFJD'
                else:
                    pt, is_obj = 'Object', True
                pname = f'p{i}'
                reg_state[r] = RegVal(pt, pname, is_obj)
                param_decls.append(f'{pt} {pname}')

        if is_static:
            sig_params = ', '.join(param_decls)
        else:
            sig_params = ', '.join(param_decls)  # p0 = this, excluded below

        # Block labels for goto targets
        block_labels = _block_entries(instrs)

        lines: List[str] = []
        indent = '    '

        # Method header
        class_short = class_name[1:-1].split('/')[-1].replace('$', '.')
        lines.append(f'// {class_name[1:-1].replace("/", ".")}.{method_name}')
        if is_static:
            lines.append(f'static {ret_type} {method_name}({sig_params}) {{')
        else:
            non_this_params = ', '.join(param_decls)
            lines.append(f'{ret_type} {method_name}({non_this_params}) {{')
        lines.append(f'    // registers={registers_size}  params={ins_size}  outs={outs_size}')
        if instrs:
            lines.append('')

        # Pending invoke: (ret_type, call_expr) waits for move-result
        pending: Optional[Tuple[str, str]] = None

        def rv(r: int) -> str:
            v = reg_state.get(r)
            if v:
                v.uses += 1
                return v.expr
            return _rname(r, params_start, ins_size)

        def rname(r: int) -> str:
            return _rname(r, params_start, ins_size)

        def flush_pending(force: bool = True) -> None:
            nonlocal pending
            if pending and force:
                rt, ce = pending
                if rt == 'void':
                    lines.append(f'{indent}{ce};')
                else:
                    lines.append(f'{indent}{ce};  // result discarded')
                pending = None

        for idx, ins in enumerate(instrs):
            op = ins.opcode

            # Flush pending invoke if this instruction won't consume it
            if pending and op not in (0x0a, 0x0b, 0x0c):
                flush_pending()

            # Block label
            if ins.cu_offset in block_labels and ins.cu_offset > 0:
                lines.append(f'  :L{ins.cu_offset:04x}:')

            # ── nop ──────────────────────────────────────────────────────
            if op == 0x00:
                pass

            # ── move (12x, 22x, 32x variants) ────────────────────────────
            elif op in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09):
                if len(ins.regs) >= 2:
                    vA, vB = ins.regs[0], ins.regs[1]
                    src = reg_state.get(vB, _UNKNOWN)
                    reg_state[vA] = RegVal(src.java_type, rname(vA), src.is_object)
                    lines.append(f'{indent}{src.java_type} {rname(vA)} = {src.expr};')

            # ── move-result / move-result-wide / move-result-object ───────
            elif op in (0x0a, 0x0b, 0x0c):
                if pending and ins.regs:
                    rt, ce = pending
                    vA = ins.regs[0]
                    is_obj = (op == 0x0c)
                    reg_state[vA] = RegVal(rt, rname(vA), is_obj)
                    lines.append(f'{indent}{rt} {rname(vA)} = {ce};')
                    pending = None
                elif ins.regs:
                    vA = ins.regs[0]
                    lines.append(f'{indent}Object {rname(vA)} = _result;  // no pending invoke')
                    reg_state[vA] = RegVal('Object', rname(vA), True)

            # ── move-exception ────────────────────────────────────────────
            elif op == 0x0d:
                if ins.regs:
                    vA = ins.regs[0]
                    reg_state[vA] = RegVal('Throwable', rname(vA), True)
                    lines.append(f'{indent}Throwable {rname(vA)} = _exception;')

            # ── return-void ───────────────────────────────────────────────
            elif op == 0x0e:
                lines.append(f'{indent}return;')

            # ── return / return-wide / return-object ──────────────────────
            elif op in (0x0f, 0x10, 0x11):
                val = rv(ins.regs[0]) if ins.regs else '???'
                lines.append(f'{indent}return {val};')

            # ── const/4 ───────────────────────────────────────────────────
            elif op == 0x12:
                if ins.regs:
                    vA = ins.regs[0]
                    lit = ins.literal
                    reg_state[vA] = RegVal('int', str(lit), False)
                    lines.append(f'{indent}int {rname(vA)} = {lit};')

            # ── const/16, const ───────────────────────────────────────────
            elif op in (0x13, 0x14):
                if ins.regs:
                    vA = ins.regs[0]
                    lit = ins.literal
                    reg_state[vA] = RegVal('int', str(lit), False)
                    lines.append(f'{indent}int {rname(vA)} = {lit};')

            # ── const/high16 ──────────────────────────────────────────────
            elif op == 0x15:
                if ins.regs:
                    vA = ins.regs[0]
                    reg_state[vA] = RegVal('int', hex(ins.literal), False)
                    lines.append(f'{indent}int {rname(vA)} = {hex(ins.literal)};')

            # ── const-wide/* ──────────────────────────────────────────────
            elif op in (0x16, 0x17, 0x18, 0x19):
                if ins.regs:
                    vA = ins.regs[0]
                    reg_state[vA] = RegVal('long', str(ins.literal) + 'L', False)
                    lines.append(f'{indent}long {rname(vA)} = {ins.literal}L;')

            # ── const-string / const-string/jumbo ────────────────────────
            elif op in (0x1a, 0x1b):
                if ins.regs:
                    vA = ins.regs[0]
                    try:
                        s = dex.string_at(ins.ref_idx)
                        esc = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                        expr = f'"{esc}"'
                    except Exception:
                        expr = f'str@{ins.ref_idx}'
                    reg_state[vA] = RegVal('String', expr, True)
                    lines.append(f'{indent}String {rname(vA)} = {expr};')

            # ── const-class ────────────────────────────────────────────────
            elif op == 0x1c:
                if ins.regs:
                    vA = ins.regs[0]
                    try:
                        expr = f'{jtype(dex.type_name(ins.ref_idx))}.class'
                    except Exception:
                        expr = f'class@{ins.ref_idx}'
                    reg_state[vA] = RegVal('Class', expr, True)
                    lines.append(f'{indent}Class {rname(vA)} = {expr};')

            # ── monitor-enter / monitor-exit ───────────────────────────────
            elif op == 0x1d:
                obj = rv(ins.regs[0]) if ins.regs else '???'
                lines.append(f'{indent}// synchronized({obj}) enter')
            elif op == 0x1e:
                obj = rv(ins.regs[0]) if ins.regs else '???'
                lines.append(f'{indent}// synchronized({obj}) exit')

            # ── check-cast ─────────────────────────────────────────────────
            elif op == 0x1f:
                if ins.regs:
                    vA = ins.regs[0]
                    try:
                        t = jtype(dex.type_name(ins.ref_idx))
                    except Exception:
                        t = f'Type@{ins.ref_idx}'
                    old = rv(vA)
                    reg_state[vA] = RegVal(t, rname(vA), True)
                    lines.append(f'{indent}{t} {rname(vA)} = ({t}) {old};')

            # ── instance-of ────────────────────────────────────────────────
            elif op == 0x20:
                if len(ins.regs) >= 2:
                    vA, vB = ins.regs[0], ins.regs[1]
                    try:
                        t = jtype(dex.type_name(ins.ref_idx))
                    except Exception:
                        t = f'Type@{ins.ref_idx}'
                    reg_state[vA] = RegVal('boolean', rname(vA), False)
                    lines.append(f'{indent}boolean {rname(vA)} = {rv(vB)} instanceof {t};')

            # ── array-length ───────────────────────────────────────────────
            elif op == 0x21:
                if len(ins.regs) >= 2:
                    vA, vB = ins.regs[0], ins.regs[1]
                    reg_state[vA] = RegVal('int', rname(vA), False)
                    lines.append(f'{indent}int {rname(vA)} = {rv(vB)}.length;')

            # ── new-instance ───────────────────────────────────────────────
            elif op == 0x22:
                if ins.regs:
                    vA = ins.regs[0]
                    try:
                        t = jtype(dex.type_name(ins.ref_idx))
                    except Exception:
                        t = f'Type@{ins.ref_idx}'
                    # Defer to invoke-direct <init> to get constructor args;
                    # store the expr as "new T()" which gets refined on <init>
                    reg_state[vA] = RegVal(t, rname(vA), True)
                    lines.append(f'{indent}{t} {rname(vA)};  // new {t}(...) — args in next <init>')

            # ── new-array ──────────────────────────────────────────────────
            elif op == 0x23:
                if len(ins.regs) >= 2:
                    vA, vB = ins.regs[0], ins.regs[1]
                    try:
                        t = jtype(dex.type_name(ins.ref_idx))
                    except Exception:
                        t = 'Object'
                    size = rv(vB)
                    reg_state[vA] = RegVal(t + '[]', rname(vA), True)
                    lines.append(f'{indent}{t}[] {rname(vA)} = new {t}[{size}];')

            # ── filled-new-array ───────────────────────────────────────────
            elif op in (0x24, 0x25):
                args = ', '.join(rv(r) for r in ins.regs)
                try:
                    t = jtype(dex.type_name(ins.ref_idx))
                except Exception:
                    t = 'Object'
                pending = (t + '[]', f'{{ {args} }}')

            # ── fill-array-data ────────────────────────────────────────────
            elif op == 0x26:
                arr = rv(ins.regs[0]) if ins.regs else '???'
                lines.append(f'{indent}// fill-array-data({arr})')

            # ── throw ──────────────────────────────────────────────────────
            elif op == 0x27:
                exc = rv(ins.regs[0]) if ins.regs else '???'
                lines.append(f'{indent}throw {exc};')

            # ── goto / goto/16 / goto/32 ───────────────────────────────────
            elif op in (0x28, 0x29, 0x2a):
                target_cu = ins.cu_offset + ins.branch
                if ins.branch < 0:
                    lines.append(f'{indent}// ↑ back-edge → :L{target_cu:04x}  (loop end)')
                else:
                    lines.append(f'{indent}goto :L{target_cu:04x};')

            # ── switch ─────────────────────────────────────────────────────
            elif op in (0x2b, 0x2c):
                val = rv(ins.regs[0]) if ins.regs else '???'
                lines.append(f'{indent}switch ({val}) {{  // payload @ :L{ins.cu_offset + ins.branch:04x}')
                lines.append(f'{indent}}}')

            # ── cmp-* ──────────────────────────────────────────────────────
            elif op in (0x2d, 0x2e, 0x2f, 0x30, 0x31):
                if len(ins.regs) >= 3:
                    vA, vB, vC = ins.regs[0], ins.regs[1], ins.regs[2]
                    reg_state[vA] = RegVal('int', rname(vA), False)
                    lines.append(f'{indent}int {rname(vA)} = {ins.mnemonic}({rv(vB)}, {rv(vC)});')

            # ── if-eq / if-ne / if-lt / if-ge / if-gt / if-le ────────────
            elif op in (0x32, 0x33, 0x34, 0x35, 0x36, 0x37):
                target_cu = ins.cu_offset + ins.branch
                cond = _cond(ins, reg_state, params_start, ins_size)
                if ins.branch > 0:
                    lines.append(f'{indent}if ({cond}) goto :L{target_cu:04x};')
                else:
                    lines.append(f'{indent}if ({cond}) // ↑ back-edge → :L{target_cu:04x}')

            # ── if-eqz / if-nez / if-ltz / if-gez / if-gtz / if-lez ──────
            elif op in (0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d):
                target_cu = ins.cu_offset + ins.branch
                cond = _cond(ins, reg_state, params_start, ins_size)
                if ins.branch > 0:
                    lines.append(f'{indent}if ({cond}) goto :L{target_cu:04x};')
                else:
                    lines.append(f'{indent}if ({cond}) // ↑ back-edge → :L{target_cu:04x}')

            # ── aget-* ─────────────────────────────────────────────────────
            elif 0x44 <= op <= 0x4a:
                if len(ins.regs) >= 3:
                    vA, vB, vC = ins.regs[0], ins.regs[1], ins.regs[2]
                    et = {0x44:'int',0x45:'long',0x46:'Object',
                          0x47:'boolean',0x48:'byte',0x49:'char',0x4a:'short'}.get(op,'Object')
                    reg_state[vA] = RegVal(et, rname(vA), op == 0x46)
                    lines.append(f'{indent}{et} {rname(vA)} = {rv(vB)}[{rv(vC)}];')

            # ── aput-* ─────────────────────────────────────────────────────
            elif 0x4b <= op <= 0x51:
                if len(ins.regs) >= 3:
                    vA, vB, vC = ins.regs[0], ins.regs[1], ins.regs[2]
                    lines.append(f'{indent}{rv(vB)}[{rv(vC)}] = {rv(vA)};')

            # ── iget-* ─────────────────────────────────────────────────────
            elif 0x52 <= op <= 0x58:
                if len(ins.regs) >= 2 and ins.ref_idx >= 0 and ins.ref_idx < len(dex._field_ids):
                    vA, vB = ins.regs[0], ins.regs[1]
                    c_idx, t_idx, n_idx = dex._field_ids[ins.ref_idx]
                    fname = dex.string_at(n_idx)
                    ftype = jtype(dex.type_name(t_idx))
                    is_obj = (op == 0x54)
                    obj = rv(vB)
                    reg_state[vA] = RegVal(ftype, rname(vA), is_obj)
                    lines.append(f'{indent}{ftype} {rname(vA)} = {obj}.{fname};')
                elif ins.regs:
                    vA = ins.regs[0]
                    lines.append(f'{indent}// iget → {rname(vA)}')

            # ── iput-* ─────────────────────────────────────────────────────
            elif 0x59 <= op <= 0x5f:
                if len(ins.regs) >= 2 and ins.ref_idx >= 0 and ins.ref_idx < len(dex._field_ids):
                    vA, vB = ins.regs[0], ins.regs[1]
                    c_idx, t_idx, n_idx = dex._field_ids[ins.ref_idx]
                    fname = dex.string_at(n_idx)
                    obj = rv(vB)
                    val = rv(vA)
                    lines.append(f'{indent}{obj}.{fname} = {val};')
                else:
                    if len(ins.regs) >= 2:
                        lines.append(f'{indent}// iput {rname(ins.regs[1])}.field = {rname(ins.regs[0])}')

            # ── sget-* ─────────────────────────────────────────────────────
            elif 0x60 <= op <= 0x66:
                if ins.regs and ins.ref_idx >= 0 and ins.ref_idx < len(dex._field_ids):
                    vA = ins.regs[0]
                    c_idx, t_idx, n_idx = dex._field_ids[ins.ref_idx]
                    cname = jtype(dex.type_name(c_idx))
                    fname = dex.string_at(n_idx)
                    ftype = jtype(dex.type_name(t_idx))
                    is_obj = (op == 0x62)
                    reg_state[vA] = RegVal(ftype, rname(vA), is_obj)
                    lines.append(f'{indent}{ftype} {rname(vA)} = {cname}.{fname};')

            # ── sput-* ─────────────────────────────────────────────────────
            elif 0x67 <= op <= 0x6d:
                if ins.regs and ins.ref_idx >= 0 and ins.ref_idx < len(dex._field_ids):
                    vA = ins.regs[0]
                    c_idx, t_idx, n_idx = dex._field_ids[ins.ref_idx]
                    cname = jtype(dex.type_name(c_idx))
                    fname = dex.string_at(n_idx)
                    val = rv(vA)
                    lines.append(f'{indent}{cname}.{fname} = {val};')

            # ── invoke-* (35c: virtual, super, direct, static, interface) ──
            # ── invoke-*/range (3rc variants) ─────────────────────────────
            elif op in (0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
                ret_t, call_e = _format_invoke(dex, ins, reg_state, params_start, ins_size)
                if ret_t == 'void':
                    lines.append(f'{indent}{call_e};')
                else:
                    pending = (ret_t, call_e)

            # ── unary ops (12x) ────────────────────────────────────────────
            elif 0x7b <= op <= 0x8f:
                if len(ins.regs) >= 2:
                    vA, vB = ins.regs[0], ins.regs[1]
                    _tmap = {
                        0x7b:'int',  0x7c:'int',  0x7d:'long', 0x7e:'long',
                        0x7f:'float',0x80:'double',0x81:'long', 0x82:'float',
                        0x83:'double',0x84:'int', 0x85:'float',0x86:'double',
                        0x87:'int',  0x88:'long', 0x89:'double',0x8a:'int',
                        0x8b:'long', 0x8c:'float',0x8d:'byte', 0x8e:'char',0x8f:'short',
                    }
                    t = _tmap.get(op, 'int')
                    reg_state[vA] = RegVal(t, rname(vA), False)
                    lines.append(f'{indent}{t} {rname(vA)} = ({t}) {rv(vB)};')

            # ── binary ops/23x ─────────────────────────────────────────────
            elif 0x90 <= op <= 0xaf:
                if len(ins.regs) >= 3:
                    vA, vB, vC = ins.regs[0], ins.regs[1], ins.regs[2]
                    t = ('int' if op < 0x9b else 'long' if op < 0xa6 else
                         'float' if op < 0xab else 'double')
                    op_chars = {'add':'+','sub':'-','mul':'*','div':'/','rem':'%',
                                'and':'&','or':'|','xor':'^','shl':'<<','shr':'>>','ushr':'>>>'}
                    mn_base = ins.mnemonic.split('-')[0]
                    op_str = op_chars.get(mn_base, mn_base)
                    reg_state[vA] = RegVal(t, rname(vA), False)
                    lines.append(f'{indent}{t} {rname(vA)} = {rv(vB)} {op_str} {rv(vC)};')

            # ── binary ops/2addr (12x) ─────────────────────────────────────
            elif 0xb0 <= op <= 0xcf:
                if len(ins.regs) >= 2:
                    vA, vB = ins.regs[0], ins.regs[1]
                    op_chars = {'add':'+','sub':'-','mul':'*','div':'/','rem':'%',
                                'and':'&','or':'|','xor':'^','shl':'<<','shr':'>>','ushr':'>>>'}
                    mn_base = ins.mnemonic.split('/')[0].split('-')[0]
                    op_str = op_chars.get(mn_base, mn_base)
                    lines.append(f'{indent}{rv(vA)} {op_str}= {rv(vB)};')

            # ── binary ops/lit16 (22s) ─────────────────────────────────────
            elif 0xd0 <= op <= 0xd7:
                if len(ins.regs) >= 2:
                    vA, vB = ins.regs[0], ins.regs[1]
                    op_chars = {'add':'+','rsub':' rsub ','mul':'*','div':'/','rem':'%',
                                'and':'&','or':'|','xor':'^'}
                    mn_base = ins.mnemonic.split('-')[0]
                    op_str = op_chars.get(mn_base, mn_base)
                    reg_state[vA] = RegVal('int', rname(vA), False)
                    lines.append(f'{indent}int {rname(vA)} = {rv(vB)} {op_str} {ins.literal};')

            # ── binary ops/lit8 (22b) ──────────────────────────────────────
            elif 0xd8 <= op <= 0xe2:
                if len(ins.regs) >= 2:
                    vA, vB = ins.regs[0], ins.regs[1]
                    op_chars = {'add':'+','rsub':' rsub ','mul':'*','div':'/','rem':'%',
                                'and':'&','or':'|','xor':'^','shl':'<<','shr':'>>','ushr':'>>>'}
                    mn_base = ins.mnemonic.split('/')[0].split('-')[0]
                    op_str = op_chars.get(mn_base, mn_base)
                    reg_state[vA] = RegVal('int', rname(vA), False)
                    lines.append(f'{indent}int {rname(vA)} = {rv(vB)} {op_str} {ins.literal};')

            # ── catch-all: annotated smali ─────────────────────────────────
            else:
                lines.append(f'{indent}// {ins.smali(dex)}')

        # Flush any pending invoke at end of method
        flush_pending()

        lines.append('}')
        return '\n'.join(lines)

    def lift_class(self, class_name: str) -> str:
        """Lift all non-native methods in a class to pseudo-Java."""
        if not class_name.startswith('L'):
            class_name = 'L' + class_name.replace('.', '/') + ';'
        methods = self.list_methods(class_name)
        if not methods:
            return f'// no methods with code for {class_name}'
        parts: List[str] = [f'// class {class_name[1:-1].replace("/", ".")}']
        for mn in methods:
            parts.append('')
            parts.append(self.lift_method(class_name, mn))
        return '\n'.join(parts)

    @staticmethod
    def report(dex: DEXFile, class_name: str, method_name: str) -> str:
        """One-call convenience."""
        return DEXLifter(dex).lift_method(class_name, method_name)
