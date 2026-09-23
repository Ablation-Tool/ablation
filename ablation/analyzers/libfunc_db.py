#!/usr/bin/env python3
"""
libfunc_db.py — PLT slot classifier for stripped ARM64 binaries.

Profiles each PLT stub via ABI-visible call-site behaviour (backward/forward
inspection of argument kinds and return usage), then scores against a hardcoded
LibFuncSummary database to classify common libc/libstdc++ functions without
needing symbol names.

Algorithm: PalmTree-style call-site profiling (Paper 24 / Epistasis).
  1. For each PLT stub, collect all BL call sites in .text.
  2. Backward-slice ~24 insns to classify x0–x3 (ptr/size/flags/int/mutex).
  3. Forward-inspect ~16 insns to classify return (void/ptr/int, null_check,
     neg_check, used_as_heap_base).
  4. Aggregate into ObservedSlotProfile.
  5. Score profile against LibFuncSummary DB; best match above threshold wins.

Usage:
  python3 libfunc_db.py [--so PATH] [--min-score 6] [--show-profiles] [--json]
"""

import argparse, json, sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import lief
import capstone
import capstone.aarch64 as _aarch64

# ─────────────────────────────────────────────────────────────────────────────
# LibFuncSummary database
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ArgRole:
    kind: str       # 'ptr','size','flags','int','fd','mutex'
    direction: str  # 'in','out','inout'

@dataclass(frozen=True)
class RetRole:
    kind: str           # 'ptr','int','void','bool'
    null_on_fail: bool
    neg_on_fail: bool

@dataclass(frozen=True)
class LibFuncSummary:
    name: str
    min_args: int
    max_args: int
    arg_roles: tuple    # ArgRole per position
    ret_role: RetRole
    effect: str         # 'alloc','dealloc','copy','compare','lock','unlock','zero','misc'

_P = ArgRole
_R = RetRole

LIB_DB: List[LibFuncSummary] = [
    LibFuncSummary('malloc',               1, 1,
        (_P('size','in'),),
        _R('ptr', True, False), 'alloc'),
    LibFuncSummary('operator_new',         1, 1,
        (_P('size','in'),),
        _R('ptr', False, False), 'alloc'),
    LibFuncSummary('calloc',               2, 2,
        (_P('size','in'), _P('size','in')),
        _R('ptr', True, False), 'alloc'),
    LibFuncSummary('realloc',              2, 2,
        (_P('ptr','inout'), _P('size','in')),
        _R('ptr', True, False), 'alloc'),
    LibFuncSummary('free',                 1, 1,
        (_P('ptr','in'),),
        _R('void', False, False), 'dealloc'),
    LibFuncSummary('operator_delete',      1, 1,
        (_P('ptr','in'),),
        _R('void', False, False), 'dealloc'),
    LibFuncSummary('memcpy',               3, 3,
        (_P('ptr','out'), _P('ptr','in'), _P('size','in')),
        _R('ptr', False, False), 'copy'),
    LibFuncSummary('memmove',              3, 3,
        (_P('ptr','out'), _P('ptr','in'), _P('size','in')),
        _R('ptr', False, False), 'copy'),
    LibFuncSummary('memset',               3, 3,
        (_P('ptr','out'), _P('int','in'), _P('size','in')),
        _R('ptr', False, False), 'zero'),
    LibFuncSummary('memcmp',               3, 3,
        (_P('ptr','in'), _P('ptr','in'), _P('size','in')),
        _R('int', False, False), 'compare'),
    LibFuncSummary('strcmp',               2, 2,
        (_P('ptr','in'), _P('ptr','in')),
        _R('int', False, False), 'compare'),
    LibFuncSummary('strncmp',              3, 3,
        (_P('ptr','in'), _P('ptr','in'), _P('size','in')),
        _R('int', False, False), 'compare'),
    LibFuncSummary('strlen',               1, 1,
        (_P('ptr','in'),),
        _R('int', False, False), 'misc'),
    LibFuncSummary('strdup',               1, 1,
        (_P('ptr','in'),),
        _R('ptr', True, False), 'alloc'),
    LibFuncSummary('pthread_mutex_lock',   1, 1,
        (_P('mutex','inout'),),
        _R('int', False, False), 'lock'),
    LibFuncSummary('pthread_mutex_unlock', 1, 1,
        (_P('mutex','inout'),),
        _R('int', False, False), 'unlock'),
    LibFuncSummary('pthread_mutex_init',   2, 2,
        (_P('mutex','out'), _P('ptr','in')),
        _R('int', False, False), 'misc'),
    LibFuncSummary('pthread_once',         2, 2,
        (_P('ptr','inout'), _P('ptr','in')),
        _R('int', False, False), 'misc'),
    LibFuncSummary('abort',                0, 0,
        (),
        _R('void', False, False), 'misc'),
    LibFuncSummary('exit',                 1, 1,
        (_P('int','in'),),
        _R('void', False, False), 'misc'),
]

# ─────────────────────────────────────────────────────────────────────────────
# Capstone helpers
# ─────────────────────────────────────────────────────────────────────────────

def _canon(name: str) -> str:
    if name.startswith('w') and name[1:].isdigit():
        return 'x' + name[1:]
    return name

def _rname(insn, reg_id: int) -> str:
    return _canon(insn.reg_name(reg_id))

# ─────────────────────────────────────────────────────────────────────────────
# Binary loading
# ─────────────────────────────────────────────────────────────────────────────

def _load(so_path: str):
    binary = lief.parse(so_path)
    text = binary.get_section('.text')
    text_data = bytes(text.content)
    text_va = text.virtual_address

    cs = capstone.Cs(capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
    cs.detail = True

    return binary, text_data, text_va, cs

def _text_bytes(binary) -> Tuple[int, bytes]:
    sec = binary.get_section('.text')
    return sec.virtual_address, bytes(sec.content)

def _rodata_range(binary) -> Tuple[int, int]:
    sec = binary.get_section('.rodata')
    if sec is None:
        return 0, 0
    return sec.virtual_address, sec.virtual_address + sec.size

def _va_to_offset(binary, va: int) -> Optional[int]:
    for seg in binary.segments:
        if seg.virtual_address <= va < seg.virtual_address + seg.virtual_size:
            return va - seg.virtual_address + seg.file_offset
    return None

def _read_u64(data: bytes, offset: int) -> int:
    if offset + 8 > len(data):
        return 0
    import struct
    return struct.unpack_from('<Q', data, offset)[0]

# ─────────────────────────────────────────────────────────────────────────────
# PLT stub discovery
# ─────────────────────────────────────────────────────────────────────────────

def _find_plt_stubs(binary) -> Dict[int, str]:
    """Return {stub_va: stub_name_or_empty}."""
    stubs: Dict[int, str] = {}
    plt = binary.get_section('.plt')
    if plt is None:
        plt = binary.get_section('.plt.got')
    if plt is None:
        return stubs

    plt_va = plt.virtual_address
    plt_data = bytes(plt.content)
    # Each PLT entry on AArch64 is typically 16 bytes (3 insns + pad or 4 insns).
    # We just treat every 16-byte block as a potential stub.
    for off in range(0, len(plt_data), 16):
        stubs[plt_va + off] = ''

    # Overlay names from dynamic relocations
    for rel in binary.pltgot_relocations:
        sym = rel.symbol
        if sym and sym.name:
            # The PLT stub for symbol at GOT slot rel.address is typically
            # found by scanning BL targets, but LIEF also surfaces stub_va via
            # rel.address for some formats. We record what we can.
            stubs[plt_va] = stubs.get(plt_va, '')  # placeholder

    # Better: use symbol table plt entries if available
    for sym in binary.dynamic_symbols:
        if sym.value != 0 and plt_va <= sym.value < plt_va + len(plt_data):
            stubs[sym.value] = sym.name

    return stubs

def _find_bl_targets(cs, text_data: bytes, text_va: int) -> Dict[int, List[int]]:
    """Return {target_va: [caller_pc, ...]} for all BL instructions."""
    result: Dict[int, List[int]] = {}
    for insn in cs.disasm(text_data, text_va):
        if insn.id == _aarch64.AARCH64_INS_BL:
            ops = insn.operands
            if ops and ops[0].type == _aarch64.AARCH64_OP_IMM:
                tgt = ops[0].imm
                result.setdefault(tgt, []).append(insn.address)
    return result

# ─────────────────────────────────────────────────────────────────────────────
# Call-site profiling helpers
# ─────────────────────────────────────────────────────────────────────────────

# Instruction IDs (capstone 6 uses CS_ARCH_AARCH64 + capstone.aarch64 module)
_ARM64 = _aarch64

_ALLOC_EFFECTS = {'alloc'}

def _is_load_from_got_or_global(insn) -> bool:
    """LDR/LDRB/LDRSW from a non-stack, non-sp base."""
    if insn.id not in (
        _ARM64.AARCH64_INS_LDR, _ARM64.AARCH64_INS_LDRB,
        _ARM64.AARCH64_INS_LDRSW, _ARM64.AARCH64_INS_LDRH,
    ):
        return False
    ops = insn.operands
    if len(ops) < 2:
        return False
    if ops[1].type != _ARM64.AARCH64_OP_MEM:
        return False
    base = _canon(insn.reg_name(ops[1].mem.base)) if ops[1].mem.base else ''
    return base not in ('sp', 'xzr', '')

def _classify_arg_at_callsite(insns_before: list, arg_reg: str) -> str:
    """
    Walk backward through insns_before (newest-first) looking for the
    last definition of arg_reg. Return 'ptr','size','flags','int','mutex'.
    """
    for insn in insns_before:
        ops = insn.operands
        # Which registers does this insn define?
        defs = set()
        if insn.id in (_ARM64.AARCH64_INS_MOV, _ARM64.AARCH64_INS_MOVZ,
                        _ARM64.AARCH64_INS_MOVK, _ARM64.AARCH64_INS_MOVN):
            if ops:
                defs.add(_rname(insn, ops[0].reg))
        elif insn.id in (_ARM64.AARCH64_INS_ADD, _ARM64.AARCH64_INS_SUB,
                          _ARM64.AARCH64_INS_LSL, _ARM64.AARCH64_INS_LSR,
                          _ARM64.AARCH64_INS_AND, _ARM64.AARCH64_INS_ORR,
                          _ARM64.AARCH64_INS_EOR):
            if ops:
                defs.add(_rname(insn, ops[0].reg))
        elif insn.id in (_ARM64.AARCH64_INS_LDR, _ARM64.AARCH64_INS_LDRB,
                          _ARM64.AARCH64_INS_LDRSW, _ARM64.AARCH64_INS_LDRH,
                          _ARM64.AARCH64_INS_LDUR):
            if ops:
                defs.add(_rname(insn, ops[0].reg))
        elif insn.id == _ARM64.AARCH64_INS_ADRP:
            if ops:
                defs.add(_rname(insn, ops[0].reg))

        if arg_reg not in defs:
            continue

        # We found the definition — classify it
        if insn.id == _ARM64.AARCH64_INS_ADRP:
            return 'ptr'
        if insn.id in (_ARM64.AARCH64_INS_ADD,):
            # ADD xD, sp, #off → stack ptr
            if len(ops) >= 2 and ops[1].type == _ARM64.AARCH64_OP_REG:
                base = _rname(insn, ops[1].reg)
                if base == 'sp':
                    return 'ptr'
        if insn.id in (_ARM64.AARCH64_INS_AND, _ARM64.AARCH64_INS_ORR,
                        _ARM64.AARCH64_INS_EOR):
            return 'flags'
        if insn.id in (_ARM64.AARCH64_INS_LSL, _ARM64.AARCH64_INS_LSR,
                        _ARM64.AARCH64_INS_SUB):
            return 'size'
        if insn.id in (_ARM64.AARCH64_INS_MOV, _ARM64.AARCH64_INS_MOVZ):
            if ops and ops[1].type == _ARM64.AARCH64_OP_IMM:
                v = ops[1].imm
                if 0 < v < 0x10000:
                    return 'size'
                return 'int'
        if _is_load_from_got_or_global(insn):
            return 'ptr'
        if insn.id in (_ARM64.AARCH64_INS_LDR, _ARM64.AARCH64_INS_LDRSW):
            return 'ptr'
        return 'int'

    return 'int'

def _profile_return(insns_after: list) -> Tuple[str, bool, bool, bool]:
    """
    Returns (ret_kind, null_on_fail, neg_on_fail, used_as_heap_base).
    """
    ret_kind = 'void'
    null_on_fail = False
    neg_on_fail = False
    used_as_heap_base = False
    prev_was_cmp = False

    for insn in insns_after:
        ops = insn.operands
        # Check if x0 is used as base for memory op → ptr
        if insn.id in (_ARM64.AARCH64_INS_STR, _ARM64.AARCH64_INS_STRB,
                        _ARM64.AARCH64_INS_STP, _ARM64.AARCH64_INS_LDR,
                        _ARM64.AARCH64_INS_LDRB):
            if len(ops) >= 2:
                mem_op = ops[-1] if ops[-1].type == _ARM64.AARCH64_OP_MEM else None
                if mem_op:
                    base = _canon(insn.reg_name(mem_op.mem.base)) if mem_op.mem.base else ''
                    if base == 'x0':
                        ret_kind = 'ptr'
                        used_as_heap_base = True

        if insn.id == _ARM64.AARCH64_INS_CBZ:
            if ops and ops[0].type == _ARM64.AARCH64_OP_REG:
                if _rname(insn, ops[0].reg) == 'x0':
                    null_on_fail = True
                    if ret_kind == 'void':
                        ret_kind = 'ptr'

        if insn.id == _ARM64.AARCH64_INS_CBNZ:
            if ops and ops[0].type == _ARM64.AARCH64_OP_REG:
                if _rname(insn, ops[0].reg) == 'x0':
                    if ret_kind == 'void':
                        ret_kind = 'ptr'

        if insn.mnemonic == 'cmp' or insn.id in (_ARM64.AARCH64_INS_SUBS, _ARM64.AARCH64_INS_ALIAS_SUBS):
            if ops and ops[0].type == _ARM64.AARCH64_OP_REG:
                r = _rname(insn, ops[0].reg)
                if r in ('x0', 'w0'):
                    prev_was_cmp = True
                    if len(ops) > 1 and ops[1].type == _ARM64.AARCH64_OP_IMM:
                        if ops[1].imm == 0:
                            if ret_kind == 'void':
                                ret_kind = 'int'
                            null_on_fail = True

        if prev_was_cmp and insn.mnemonic in ('b.lt', 'b.le', 'b.mi', 'b.lo', 'b.ls'):
            neg_on_fail = True
            prev_was_cmp = False

        # If x0 is used arithmetically → int
        if insn.id in (_ARM64.AARCH64_INS_ADD, _ARM64.AARCH64_INS_SUB) and len(ops) >= 2:
            if ops[1].type == _ARM64.AARCH64_OP_REG:
                if _rname(insn, ops[1].reg) == 'x0':
                    if ret_kind == 'void':
                        ret_kind = 'int'

    return ret_kind, null_on_fail, neg_on_fail, used_as_heap_base

# ─────────────────────────────────────────────────────────────────────────────
# ObservedSlotProfile
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ObservedSlotProfile:
    stub_va: int
    name_hint: str
    num_callsites: int
    arg_kinds: Dict[int, str]   # position → majority kind
    max_args: int
    ret_kind: str
    null_on_fail: bool
    neg_on_fail: bool
    used_as_heap_base: bool

def _disasm_window(cs, text_data: bytes, text_va: int,
                   start_va: int, count: int, forward: bool) -> list:
    """Disassemble up to `count` instructions starting at start_va (or before it)."""
    off = start_va - text_va
    if forward:
        chunk = text_data[off: off + count * 4]
        return list(cs.disasm(chunk, start_va))
    else:
        pre_off = max(0, off - count * 4)
        chunk = text_data[pre_off: off]
        insns = list(cs.disasm(chunk, text_va + pre_off))
        insns.reverse()
        return insns

def _build_profile(cs, text_data: bytes, text_va: int,
                   stub_va: int, name_hint: str,
                   callers: List[int]) -> ObservedSlotProfile:
    ARG_REGS = ['x0', 'x1', 'x2', 'x3']
    kind_votes: Dict[int, Dict[str, int]] = {i: {} for i in range(4)}
    ret_kinds: Dict[str, int] = {}
    null_votes = 0
    neg_votes = 0
    heap_votes = 0
    max_args_seen = 0

    for caller_pc in callers[:20]:  # cap at 20 call sites
        before = _disasm_window(cs, text_data, text_va, caller_pc, 24, forward=False)
        after_pc = caller_pc + 4
        after = _disasm_window(cs, text_data, text_va, after_pc, 16, forward=True)

        # Classify args
        args_present = 0
        for i, reg in enumerate(ARG_REGS):
            kind = _classify_arg_at_callsite(before, reg)
            if kind != 'int' or i == 0:
                args_present = i + 1
            kind_votes[i][kind] = kind_votes[i].get(kind, 0) + 1

        max_args_seen = max(max_args_seen, args_present)

        rk, nc, ng, hb = _profile_return(after)
        ret_kinds[rk] = ret_kinds.get(rk, 0) + 1
        if nc: null_votes += 1
        if ng: neg_votes += 1
        if hb: heap_votes += 1

    def majority(votes: dict, default: str) -> str:
        return max(votes, key=votes.get) if votes else default

    n = max(len(callers), 1)
    return ObservedSlotProfile(
        stub_va=stub_va,
        name_hint=name_hint,
        num_callsites=len(callers),
        arg_kinds={i: majority(kind_votes[i], 'int') for i in range(4)},
        max_args=max_args_seen,
        ret_kind=majority(ret_kinds, 'void'),
        null_on_fail=null_votes > n // 3,
        neg_on_fail=neg_votes > n // 3,
        used_as_heap_base=heap_votes > n // 3,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────

def _score(profile: ObservedSlotProfile, summary: LibFuncSummary) -> int:
    score = 0
    obs_argc = profile.max_args
    exp_min = summary.min_args
    exp_max = summary.max_args

    if exp_min <= obs_argc <= exp_max:
        score += 3
    elif abs(obs_argc - exp_min) <= 1 or abs(obs_argc - exp_max) <= 1:
        score += 1
    else:
        score -= 3

    for i, role in enumerate(summary.arg_roles[:3]):
        obs_kind = profile.arg_kinds.get(i, 'int')
        if obs_kind == role.kind:
            score += 2
        elif obs_kind == 'ptr' and role.kind in ('mutex',):
            score += 1

    if profile.ret_kind == summary.ret_role.kind:
        score += 2
    elif profile.ret_kind == 'int' and summary.ret_role.kind == 'bool':
        score += 1

    if profile.null_on_fail == summary.ret_role.null_on_fail:
        score += 2
    if profile.neg_on_fail == summary.ret_role.neg_on_fail:
        score += 1

    if summary.effect == 'alloc' and profile.used_as_heap_base:
        score += 2

    return score

def classify(profile: ObservedSlotProfile, min_score: int) -> Tuple[Optional[str], int, List[Tuple[str, int]]]:
    ranked = sorted(
        [(s.name, _score(profile, s)) for s in LIB_DB],
        key=lambda x: x[1], reverse=True
    )
    if ranked and ranked[0][1] >= min_score:
        return ranked[0][0], ranked[0][1], ranked[:3]
    return None, ranked[0][1] if ranked else 0, ranked[:3]

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def run(so_path: str, min_score: int, show_profiles: bool, as_json: bool):
    binary = lief.parse(so_path)
    text_va, text_data = _text_bytes(binary)

    cs = capstone.Cs(capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
    cs.detail = True

    print("Scanning BL targets...", file=sys.stderr)
    bl_map = _find_bl_targets(cs, text_data, text_va)

    # Identify PLT range
    plt = binary.get_section('.plt') or binary.get_section('.plt.got')
    plt_va = plt.virtual_address if plt else 0
    plt_end = (plt_va + plt.size) if plt else 0

    # Build name hints from dynamic symbols
    name_map: Dict[int, str] = {}
    for sym in binary.dynamic_symbols:
        if sym.name and plt_va <= sym.value < plt_end:
            name_map[sym.value] = sym.name

    # Collect stubs: PLT entries that have callers
    stubs = {va: callers for va, callers in bl_map.items()
             if plt_va <= va < plt_end}

    if not stubs:
        # Fallback: any BL target that looks like a short stub (≤ 3 insns before another BL)
        stubs = {va: callers for va, callers in bl_map.items()
                 if len(callers) >= 3}

    print(f"Found {len(stubs)} PLT stubs with callers", file=sys.stderr)

    results = []
    for stub_va in sorted(stubs):
        callers = stubs[stub_va]
        hint = name_map.get(stub_va, '')
        profile = _build_profile(cs, text_data, text_va, stub_va, hint, callers)
        best_name, best_score, top3 = classify(profile, min_score)
        results.append((stub_va, hint, profile, best_name, best_score, top3))

    if as_json:
        out = []
        for stub_va, hint, profile, best_name, best_score, top3 in results:
            out.append({
                'stub_addr': hex(stub_va),
                'name_hint': hint,
                'classified_as': best_name,
                'score': best_score,
                'top3': [(n, s) for n, s in top3],
                'profile': {
                    'num_callsites': profile.num_callsites,
                    'max_args': profile.max_args,
                    'arg_kinds': {str(k): v for k, v in profile.arg_kinds.items()},
                    'ret_kind': profile.ret_kind,
                    'null_on_fail': profile.null_on_fail,
                    'neg_on_fail': profile.neg_on_fail,
                    'used_as_heap_base': profile.used_as_heap_base,
                },
            })
        print(json.dumps(out, indent=2))
        return

    classified_count = sum(1 for _, _, _, n, _, _ in results if n is not None)
    print(f"\nPLT CLASSIFICATION — {Path(so_path).name}")
    print(f"Stubs: {len(results)}   Classified: {classified_count}\n")

    for stub_va, hint, profile, best_name, best_score, top3 in results:
        arg_str = ','.join(
            profile.arg_kinds.get(i, '?') for i in range(profile.max_args)
        ) or '(none)'
        hint_label = f' [{hint}]' if hint else ''

        if best_name:
            nc = ' null_check=yes' if profile.null_on_fail else ''
            ng = ' neg_check=yes' if profile.neg_on_fail else ''
            print(f"stub@0x{stub_va:x}{hint_label:20s}  →  {best_name:30s}"
                  f"(score={best_score:2d})  args={profile.max_args}[{arg_str}]"
                  f"  ret={profile.ret_kind}{nc}{ng}")
        else:
            alts = '  '.join(f"{n}:{s}" for n, s in top3[:2])
            print(f"stub@0x{stub_va:x}{hint_label:20s}  →  {'UNCLASSIFIED':30s}"
                  f"(top: {alts})")

        if show_profiles:
            print(f"       callsites={profile.num_callsites}  "
                  f"heap_base={profile.used_as_heap_base}")

    print()

def main():
    ap = argparse.ArgumentParser(description='PLT slot classifier for stripped ARM64 binaries')
    ap.add_argument('--so', default='/media/cowboy/research/wechat-re/native-libs/lib/arm64-v8a/libwechatnetwork.so')
    ap.add_argument('--min-score', type=int, default=6)
    ap.add_argument('--show-profiles', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()
    run(args.so, args.min_score, args.show_profiles, args.json)

if __name__ == '__main__':
    main()
