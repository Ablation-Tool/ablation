#!/usr/bin/env python3
"""
proto_fsm.py — Static MMTLS handshake FSM extractor for stripped ARM64 binaries.

Inspired by:
  NEMETYL: segment-based similarity + DBSCAN clustering for message-type inference.
  5G Protocol State Machine Inference: transformer-based state machine recovery.

Adapted for pure static binary analysis (no PCAP): infers FSM from BSS state variable
reads/writes within the handshake function cluster reachable from known seed VAs.

Pipeline:
  Phase 1 — State variable identification: BSS addrs written with small integer immediates,
             read before branches in the handshake cluster.
  Phase 2 — Handshake function cluster: BL-reachable subgraph from seed functions (2 hops).
  Phase 3 — Transition extraction: (state_read → branch → call → state_write) quads.
  Phase 4 — FSM graph output: FSMState / FSMTransition dataclasses + Graphviz DOT.

Usage:
  python3 proto_fsm.py [--so PATH] [--seed VA] [--hop-depth N] [--dot FILE]

Default seeds (libwechatnetwork.so, WeChat 8.0.56 ARM64):
  0x111f98  ILinkKey constructor/init
  0x305020  list clear-all
  0x305094  list sort-reorder
  0x304d64  list search+delete
  0x2ec280  list insertion
  0x246364  saveAuthLongList
"""

import struct, sys, argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import lief
import capstone
from capstone import arm64 as A64

# ─── capstone setup ──────────────────────────────────────────────────────────

_MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
_MD.detail = True
_MD.skipdata = True

def _rn(insn, reg_id: int) -> str:
    """Canonical register name: capstone id → string, w→x normalised."""
    if not reg_id:
        return 'xzr'
    n = insn.reg_name(reg_id)
    if n.startswith('w') and n[1:].isdigit():
        n = 'x' + n[1:]
    return n

# ─── dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class StateVar:
    addr: int                       # BSS VA
    read_sites: List[int] = field(default_factory=list)   # PCs of LDR before branch
    write_sites: List[int] = field(default_factory=list)  # PCs of STR after branch/call
    observed_values: Set[int] = field(default_factory=set)

@dataclass
class FSMState:
    id: int
    value: int
    functions: List[int] = field(default_factory=list)

@dataclass
class FSMTransition:
    from_state: int
    to_state: int
    trigger_pc: int
    trigger_fn: int
    state_var: int

# ─── binary helpers ───────────────────────────────────────────────────────────

def _load(so_path: str):
    binary = lief.parse(so_path)
    load_addr = 0
    for seg in binary.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD and seg.virtual_address == 0:
            load_addr = 0
            break
    raw = Path(so_path).read_bytes()
    return binary, raw, load_addr

def _va_to_raw(binary, va: int) -> Optional[int]:
    for seg in binary.segments:
        if seg.type != lief.ELF.Segment.TYPE.LOAD:
            continue
        base = seg.virtual_address
        if base <= va < base + seg.virtual_size:
            return seg.file_offset + (va - base)
    return None

def _read_u64(raw: bytes, off: int) -> int:
    return struct.unpack_from('<Q', raw, off)[0]

def _read_u32(raw: bytes, off: int) -> int:
    return struct.unpack_from('<I', raw, off)[0]

def _text_bounds(binary) -> Tuple[int, int, int]:
    for sec in binary.sections:
        if sec.name == '.text':
            return sec.virtual_address, sec.size, sec.offset
    for seg in binary.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD and (seg.flags & 0x1):
            return seg.virtual_address, seg.virtual_size, seg.file_offset
    raise RuntimeError("no .text")

def _bss_bounds(binary) -> Tuple[int, int]:
    for sec in binary.sections:
        if sec.name in ('.bss', '.sbss'):
            return sec.virtual_address, sec.size
    for seg in binary.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD and not (seg.flags & 0x1):
            rva = seg.virtual_address
            if rva > 0x300000:
                return rva, seg.virtual_size
    return 0x3d0000, 0x20000

# ─── disassembly helpers ──────────────────────────────────────────────────────

def _disasm_fn(raw: bytes, binary, fn_va: int, max_insns: int = 2048) -> List:
    off = _va_to_raw(binary, fn_va)
    if off is None:
        return []
    chunk = raw[off: off + max_insns * 4]
    insns = list(_MD.disasm(chunk, fn_va))
    result = []
    for i, ins in enumerate(insns):
        if i > 0 and ins.id in (A64.ARM64_INS_RET,):
            result.append(ins)
            break
        result.append(ins)
    return result

def _is_bl(ins) -> bool:
    return ins.id in (A64.ARM64_INS_BL,)

def _bl_target(ins) -> Optional[int]:
    if _is_bl(ins) and ins.operands:
        return ins.operands[0].imm
    return None

def _is_branch(ins) -> bool:
    return ins.id in (A64.ARM64_INS_B, A64.ARM64_INS_CBZ, A64.ARM64_INS_CBNZ,
                      A64.ARM64_INS_TBZ, A64.ARM64_INS_TBNZ)

def _is_ldr(ins) -> bool:
    return ins.id in (A64.ARM64_INS_LDR, A64.ARM64_INS_LDRB, A64.ARM64_INS_LDRH,
                      A64.ARM64_INS_LDRSB, A64.ARM64_INS_LDRSH, A64.ARM64_INS_LDRSW)

def _is_str(ins) -> bool:
    return ins.id in (A64.ARM64_INS_STR, A64.ARM64_INS_STRB, A64.ARM64_INS_STRH,
                      A64.ARM64_INS_STP)

# ─── ADRP + LDR/ADD GOT decode ───────────────────────────────────────────────

def _decode_adrp(word: int, pc: int) -> Optional[int]:
    if (word & 0x9F000000) != 0x90000000:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    imm <<= 12
    if imm & (1 << 32):
        imm -= (1 << 33)
    return (pc & ~0xFFF) + imm

# ─── Phase 1: state variable identification ───────────────────────────────────

def identify_state_vars(raw: bytes, binary, text_va: int, text_size: int,
                        bss_va: int, bss_size: int) -> Dict[int, StateVar]:
    """
    Scan .text for patterns:
      MOV wN, #imm (imm <= 16) + STR wN/xN, [xBase] -> track xBase as state var candidate
      LDR before branch -> confirm as state var read site
    Returns dict keyed by BSS VA.
    """
    state_vars: Dict[int, StateVar] = {}
    text_off = _va_to_raw(binary, text_va)
    if text_off is None:
        return state_vars

    chunk = raw[text_off: text_off + text_size]
    insns = list(_MD.disasm(chunk, text_va))

    # State: track register holding small immediate values and ADRP pages
    # We use a sliding window of 8 instructions
    WIN = 8

    for i, ins in enumerate(insns):
        # Look for STR/STP of xzr or small-immediate-loaded reg into BSS region
        if not _is_str(ins):
            continue
        ops = ins.operands
        if len(ops) < 2:
            continue

        # For STR: ops[0]=src, ops[1]=mem; for STP: ops[0]=src1, ops[1]=src2, ops[2]=mem
        mem_op = ops[-1]
        if mem_op.type != A64.ARM64_OP_MEM:
            continue

        base_name = _rn(ins, mem_op.mem.base)
        disp = mem_op.mem.disp

        # Back-trace base register over window to find BSS address
        bss_addr = None
        for j in range(max(0, i - WIN), i):
            prev = insns[j]
            # Look for ADRP xBase, page; ADD xBase, xBase, #lo12 -> BSS addr
            if prev.id == A64.ARM64_INS_ADRP:
                if prev.operands and _rn(prev, prev.operands[0].reg) == base_name:
                    pg = _decode_adrp(_read_u32(raw, text_off + (prev.address - text_va)), prev.address)
                    if pg is None:
                        continue
                    # Check next instruction for ADD or LDR
                    if j + 1 < len(insns):
                        nxt = insns[j + 1]
                        if nxt.id == A64.ARM64_INS_ADD and len(nxt.operands) >= 3:
                            if (_rn(nxt, nxt.operands[0].reg) == base_name and
                                    nxt.operands[2].type == A64.ARM64_OP_IMM):
                                candidate = (pg + nxt.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
                                if bss_va <= candidate < bss_va + bss_size:
                                    bss_addr = candidate + disp
                                    break

        if bss_addr is None:
            continue

        # Check source register is small-integer-like (check window for MOV wN, #imm)
        src_name = _rn(ins, ops[0].reg) if ops[0].type == A64.ARM64_OP_REG else None
        is_small_int = (src_name == 'xzr')
        if not is_small_int and src_name:
            for j in range(max(0, i - WIN), i):
                prev = insns[j]
                if prev.id in (A64.ARM64_INS_MOV, A64.ARM64_INS_MOVZ) and len(prev.operands) >= 2:
                    if (_rn(prev, prev.operands[0].reg) == src_name and
                            prev.operands[1].type == A64.ARM64_OP_IMM and
                            0 <= prev.operands[1].imm <= 16):
                        is_small_int = True
                        if bss_addr not in state_vars:
                            state_vars[bss_addr] = StateVar(addr=bss_addr)
                        state_vars[bss_addr].write_sites.append(ins.address)
                        state_vars[bss_addr].observed_values.add(prev.operands[1].imm)
                        break

        if is_small_int and bss_addr not in state_vars:
            state_vars[bss_addr] = StateVar(addr=bss_addr)
            state_vars[bss_addr].write_sites.append(ins.address)

    # Second pass: find LDR of state var addr followed (within 4 insns) by a branch
    for i, ins in enumerate(insns):
        if not _is_ldr(ins):
            continue
        ops = ins.operands
        if len(ops) < 2:
            continue
        mem_op = ops[-1] if ops[-1].type == A64.ARM64_OP_MEM else None
        if mem_op is None:
            continue
        base_name = _rn(ins, mem_op.mem.base)
        disp = mem_op.mem.disp

        # Back-trace base to BSS addr (same ADRP window)
        bss_addr = None
        for j in range(max(0, i - WIN), i):
            prev = insns[j]
            if prev.id == A64.ARM64_INS_ADRP and prev.operands:
                if _rn(prev, prev.operands[0].reg) == base_name:
                    pg = _decode_adrp(_read_u32(raw, text_off + (prev.address - text_va)), prev.address)
                    if pg is None:
                        continue
                    if j + 1 < len(insns):
                        nxt = insns[j + 1]
                        if nxt.id == A64.ARM64_INS_ADD and len(nxt.operands) >= 3:
                            if nxt.operands[2].type == A64.ARM64_OP_IMM:
                                candidate = (pg + nxt.operands[2].imm) & 0xFFFFFFFFFFFFFFFF
                                if bss_va <= candidate < bss_va + bss_size:
                                    bss_addr = candidate + disp
                                    break

        if bss_addr is None or bss_addr not in state_vars:
            continue

        # Check for branch within 4 insns
        for k in range(i + 1, min(len(insns), i + 5)):
            if _is_branch(insns[k]):
                state_vars[bss_addr].read_sites.append(ins.address)
                break

    return state_vars

# ─── Phase 2: handshake function cluster ──────────────────────────────────────

def build_cluster(raw: bytes, binary, seeds: List[int],
                  hop_depth: int = 2) -> Dict[int, Set[int]]:
    """
    BFS from seeds over direct BL edges.
    Returns {fn_va: set_of_callees}.
    """
    cluster: Dict[int, Set[int]] = {}
    frontier = set(seeds)

    for _ in range(hop_depth):
        next_frontier: Set[int] = set()
        for fn_va in frontier:
            if fn_va in cluster:
                continue
            callees: Set[int] = set()
            insns = _disasm_fn(raw, binary, fn_va)
            for ins in insns:
                tgt = _bl_target(ins)
                if tgt and tgt not in cluster:
                    callees.add(tgt)
            cluster[fn_va] = callees
            next_frontier |= callees
        frontier = next_frontier - set(cluster.keys())

    for fn_va in frontier:
        if fn_va not in cluster:
            callees: Set[int] = set()
            insns = _disasm_fn(raw, binary, fn_va)
            for ins in insns:
                tgt = _bl_target(ins)
                if tgt:
                    callees.add(tgt)
            cluster[fn_va] = callees

    return cluster

# ─── Phase 2b: per-function properties ───────────────────────────────────────

@dataclass
class FnProps:
    va: int
    reads_state_vars: List[int] = field(default_factory=list)
    writes_state_vars: List[int] = field(default_factory=list)
    calls_insert: bool = False
    calls_delete: bool = False

INSERT_FN = 0x2ec280
DELETE_FN = 0x304d64

def analyze_fn(raw: bytes, binary, fn_va: int,
               state_vars: Dict[int, StateVar]) -> FnProps:
    props = FnProps(va=fn_va)
    sv_addrs = set(state_vars.keys())
    insns = _disasm_fn(raw, binary, fn_va)

    for ins in insns:
        tgt = _bl_target(ins)
        if tgt == INSERT_FN:
            props.calls_insert = True
        elif tgt == DELETE_FN:
            props.calls_delete = True

        ops = ins.operands
        if not ops:
            continue

        mem_op = None
        if _is_ldr(ins) or _is_str(ins):
            mem_op = ops[-1] if ops[-1].type == A64.ARM64_OP_MEM else None

        if mem_op is None:
            continue

        base_name = _rn(ins, mem_op.mem.base) if mem_op.mem.base else None
        if not base_name or base_name in ('sp', 'xzr'):
            continue

        # Rough: if this instruction is at an address that is a read/write site
        # for any tracked state var, record it
        for sv_addr, sv in state_vars.items():
            if ins.address in sv.read_sites and _is_ldr(ins):
                if sv_addr not in props.reads_state_vars:
                    props.reads_state_vars.append(sv_addr)
            if ins.address in sv.write_sites and _is_str(ins):
                if sv_addr not in props.writes_state_vars:
                    props.writes_state_vars.append(sv_addr)

    return props

# ─── Phase 3: transition extraction ──────────────────────────────────────────

def extract_transitions(raw: bytes, binary, cluster: Dict[int, Set[int]],
                        state_vars: Dict[int, StateVar],
                        fn_props: Dict[int, FnProps]) -> List[FSMTransition]:
    """
    For functions that both read and write state vars, find:
    LDR state_var -> ... -> branch -> ... -> BL trigger -> ... -> STR state_var
    and emit a transition for each (read_val, trigger_fn, write_val) triple.
    """
    transitions: List[FSMTransition] = []
    sv_read_set = {pc: sv_addr for sv_addr, sv in state_vars.items() for pc in sv.read_sites}
    sv_write_set = {pc: sv_addr for sv_addr, sv in state_vars.items() for pc in sv.write_sites}

    for fn_va, props in fn_props.items():
        if not props.reads_state_vars or not props.writes_state_vars:
            continue

        insns = _disasm_fn(raw, binary, fn_va)
        pc_to_idx = {ins.address: i for i, ins in enumerate(insns)}

        for i, ins in enumerate(insns):
            sv_addr = sv_read_set.get(ins.address)
            if sv_addr is None:
                continue

            # Scan forward: find branch, then BL trigger, then state write
            seen_branch = False
            trigger_pc = None
            trigger_fn = None

            for j in range(i + 1, min(len(insns), i + 64)):
                nxt = insns[j]
                if _is_branch(nxt):
                    seen_branch = True
                if seen_branch and _is_bl(nxt):
                    tgt = _bl_target(nxt)
                    if tgt and trigger_pc is None:
                        trigger_pc = nxt.address
                        trigger_fn = tgt
                if nxt.address in sv_write_set and sv_write_set[nxt.address] == sv_addr:
                    # Emit transition — use placeholder state values (0→1 generically)
                    from_val = 0
                    to_val = 1
                    # Try to read observed values from state_vars
                    sv_vals = sorted(state_vars[sv_addr].observed_values)
                    if len(sv_vals) >= 2:
                        from_val = sv_vals[0]
                        to_val = sv_vals[1]
                    elif sv_vals:
                        to_val = sv_vals[0]

                    transitions.append(FSMTransition(
                        from_state=from_val,
                        to_state=to_val,
                        trigger_pc=trigger_pc or 0,
                        trigger_fn=trigger_fn or 0,
                        state_var=sv_addr,
                    ))
                    break

    return transitions

# ─── Phase 4: FSM graph ───────────────────────────────────────────────────────

def build_fsm(state_vars: Dict[int, StateVar],
              transitions: List[FSMTransition],
              cluster: Dict[int, Set[int]],
              fn_props: Dict[int, FnProps]) -> Tuple[List[FSMState], List[FSMTransition]]:
    state_ids: Dict[int, int] = {}  # value → state id
    states: List[FSMState] = []

    def get_or_create(val: int) -> int:
        if val not in state_ids:
            sid = len(states)
            state_ids[val] = sid
            states.append(FSMState(id=sid, value=val))
        return state_ids[val]

    # Collect all observed state values
    for sv in state_vars.values():
        for v in sorted(sv.observed_values):
            get_or_create(v)

    # Ensure from/to states exist
    for tr in transitions:
        get_or_create(tr.from_state)
        get_or_create(tr.to_state)

    # Annotate functions to states (functions that write a state val belong to that state)
    for fn_va, props in fn_props.items():
        for sv_addr in props.writes_state_vars:
            for v in state_vars[sv_addr].observed_values:
                sid = get_or_create(v)
                if fn_va not in states[sid].functions:
                    states[sid].functions.append(fn_va)

    return states, transitions

def emit_dot(states: List[FSMState], transitions: List[FSMTransition],
             state_vars: Dict[int, StateVar]) -> str:
    lines = ['digraph mmtls_fsm {', '  rankdir=LR;',
             '  node [shape=circle fontname=Courier fontsize=10];',
             '  edge [fontname=Courier fontsize=8];', '']

    for s in states:
        label = f'S{s.id}\\nval={s.value}'
        lines.append(f'  S{s.id} [label="{label}"];')

    lines.append('')
    for tr in transitions:
        edge_label = f'BL@0x{tr.trigger_pc:x}\\nfn@0x{tr.trigger_fn:x}' if tr.trigger_pc else 'unknown'
        lines.append(f'  S{tr.from_state} -> S{tr.to_state} [label="{edge_label}"];')

    lines.append('}')
    return '\n'.join(lines)

# ─── main ─────────────────────────────────────────────────────────────────────

DEFAULT_SO = '/path/to/libwechatnetwork.so'
DEFAULT_SEEDS = [0x111f98, 0x305020, 0x305094, 0x304d64, 0x2ec280, 0x246364]

def main():
    ap = argparse.ArgumentParser(description='MMTLS FSM extractor')
    ap.add_argument('--so', default=DEFAULT_SO, help='path to .so binary')
    ap.add_argument('--seed', type=lambda x: int(x, 0), action='append', dest='seeds',
                    metavar='VA', help='seed function VA (repeatable)')
    ap.add_argument('--hop-depth', type=int, default=2, metavar='N',
                    help='BL expansion depth from seeds')
    ap.add_argument('--dot', metavar='FILE', help='write Graphviz DOT to file')
    args = ap.parse_args()

    seeds = args.seeds if args.seeds else DEFAULT_SEEDS

    binary, raw, _ = _load(args.so)
    text_va, text_size, _ = _text_bounds(binary)
    bss_va, bss_size = _bss_bounds(binary)

    print(f'MMTLS FSM — {Path(args.so).name}')
    print(f'  .text  VA=0x{text_va:x}  size=0x{text_size:x}')
    print(f'  .bss   VA=0x{bss_va:x}  size=0x{bss_size:x}')
    print(f'  seeds  ({len(seeds)}): {[hex(s) for s in seeds]}')
    print()

    print('Phase 1 — State variable scan ...')
    state_vars = identify_state_vars(raw, binary, text_va, text_size, bss_va, bss_size)
    print(f'State variables: {len(state_vars)} found')
    for sv in sorted(state_vars.values(), key=lambda x: x.addr):
        print(f'  BSS:0x{sv.addr:x} — values seen: {sorted(sv.observed_values)}'
              f'  reads: {len(sv.read_sites)}  writes: {len(sv.write_sites)}')
    print()

    print(f'Phase 2 — Handshake cluster (seeds + {args.hop_depth} hops) ...')
    cluster = build_cluster(raw, binary, seeds, args.hop_depth)
    print(f'Handshake cluster: {len(cluster)} functions')
    print()

    fn_props: Dict[int, FnProps] = {}
    for fn_va in cluster:
        fn_props[fn_va] = analyze_fn(raw, binary, fn_va, state_vars)

    sv_readers = [fn_va for fn_va, p in fn_props.items() if p.reads_state_vars]
    sv_writers = [fn_va for fn_va, p in fn_props.items() if p.writes_state_vars]
    insert_callers = [fn_va for fn_va, p in fn_props.items() if p.calls_insert]
    delete_callers = [fn_va for fn_va, p in fn_props.items() if p.calls_delete]
    print(f'  State-var readers: {[hex(v) for v in sv_readers]}')
    print(f'  State-var writers: {[hex(v) for v in sv_writers]}')
    print(f'  list-insert callers: {[hex(v) for v in insert_callers]}')
    print(f'  list-delete callers: {[hex(v) for v in delete_callers]}')
    print()

    print('Phase 3 — Transition extraction ...')
    transitions = extract_transitions(raw, binary, cluster, state_vars, fn_props)
    print(f'FSM Transitions: {len(transitions)} found')
    if transitions:
        for tr in transitions:
            label = f'BL@0x{tr.trigger_pc:x} fn@0x{tr.trigger_fn:x}' if tr.trigger_pc else 'unknown'
            print(f'  state {tr.from_state} --[{label}]-> state {tr.to_state}'
                  f'  (var=BSS:0x{tr.state_var:x})')
    else:
        print('  (no clean read→branch→call→write quads found in cluster;')
        print('   expand --hop-depth or review seed list)')
    print()

    print('Phase 4 — FSM graph ...')
    states, transitions = build_fsm(state_vars, transitions, cluster, fn_props)
    print(f'States: {len(states)}')
    for s in states:
        fns = [f'0x{f:x}' for f in s.functions[:4]]
        print(f'  S{s.id}  val={s.value}  functions={fns}{"..." if len(s.functions) > 4 else ""}')
    print()

    dot = emit_dot(states, transitions, state_vars)
    print('Graphviz DOT:')
    print(dot)

    if args.dot:
        Path(args.dot).write_text(dot)
        print(f'\n[DOT written to {args.dot}]')

if __name__ == '__main__':
    main()
