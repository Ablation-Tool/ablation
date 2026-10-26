"""
alpha_cfg.py — Control-flow graph builder for DEC Alpha AXP functions.

Builds per-function basic-block CFGs from raw Alpha ECOFF binary data.
Designed to extend insn_alpha.AlphaEcoffScanner.trace_arg() past BSR/JSR
call boundaries: build the callee's CFG, then trace r0 at each RET to
recover the return value that becomes the system() argument.

Why this exists:
  trace_arg() stops at BSR_RETVAL when the target register is set by a
  prior call's return value. Resolving that requires entering the callee,
  finding its exit paths (RET instructions), and tracing r0 backward from
  each RET. That requires knowing the callee's basic block structure — i.e.
  a CFG — so the backward scan stays within the correct basic block and
  doesn't cross branch boundaries that would make register assumptions wrong.

Usage:
    from ablation.analyzers.alpha_cfg import AlphaCFGBuilder
    from ablation.analyzers.insn_alpha import AlphaEcoffScanner

    scanner = AlphaEcoffScanner('/path/to/binary')
    data, gp_value, sections = scanner._load()
    builder = AlphaCFGBuilder(data, sections, gp_value)

    cfg = builder.build(func_va=0x120184f00)
    ret_traces = builder.trace_return_value(cfg, ret_reg=0)
    for trace in ret_traces:
        print(trace)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ── Alpha branch opcodes ──────────────────────────────────────────────────────

# Conditional branches — end a basic block with two successors (taken, fall-through)
_COND_BRANCH_OPS: frozenset = frozenset([
    0x38,  # BLBS  (branch if low bit set)
    0x39,  # BEQ
    0x3A,  # BLT
    0x3B,  # BLE
    0x3C,  # BLBC  (branch if low bit clear)
    0x3D,  # BNE
    0x3E,  # BGE
    0x3F,  # BGT
    0x31,  # FBEQ
    0x32,  # FBLT
    0x33,  # FBLE
    0x35,  # FBNE
    0x36,  # FBGE
    0x37,  # FBGT
])

_OP_BR  = 0x30   # unconditional branch (fall-through to taken target)
_OP_BSR = 0x34   # branch-and-store-return — CALL, not a CFG edge; falls through to next insn
_OP_JMP = 0x1A   # JMP / JSR / RET / JSR_COROUTINE (indirect; differentiated by hint field)

# Hint field for opcode 0x1A (bits [15:14] of low 16)
_HINT_JMP = 0    # JMP — indirect unconditional branch (exit block, target unknown)
_HINT_JSR = 1    # JSR — subroutine call (like BSR; falls through)
_HINT_RET = 2    # RET — return from subroutine (exit block)
_HINT_JSR_COROUTINE = 3


def _decode_alpha(insn: int) -> Tuple[int, int, int, int]:
    """Return (opcode, Ra, Rb, disp16) for a 32-bit Alpha instruction."""
    op   = (insn >> 26) & 0x3F
    ra   = (insn >> 21) & 0x1F
    rb   = (insn >> 16) & 0x1F
    d16  = insn & 0xFFFF
    if d16 >= 0x8000:
        d16 -= 0x10000
    return op, ra, rb, d16


def _branch_target(va: int, insn: int) -> int:
    """Compute the target VA of a direct branch (BR/BSR/Bcc) instruction."""
    disp21 = insn & 0x1FFFFF
    if disp21 >= (1 << 20):
        disp21 -= (1 << 21)
    return (va + 4) + disp21 * 4


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class BasicBlock:
    start_va:  int
    end_va:    int                    # VA of the LAST instruction
    insns:     List[Tuple[int, int]]  # [(va, insn_word), ...]
    succs:     List[int]              # successor BB start VAs
    preds:     List[int]              # predecessor BB start VAs (filled post-build)
    is_ret:    bool = False           # True if terminates with RET
    is_jmp:    bool = False           # True if terminates with indirect JMP (target unknown)


@dataclass
class ReturnTrace:
    ret_va:    int          # VA of the RET instruction
    reg:       int          # register traced (0 = r0 = return value)
    insn_type: str          # 'LDA_CONST' | 'LDA_GP' | 'LDQ_GP' | 'BIS_MOV' | 'BSR_RETVAL' | 'UNKNOWN'
    value:     int          # literal or address; 0 if unknown
    interp:    str          # human-readable description


# ── CFG builder ───────────────────────────────────────────────────────────────

class AlphaCFGBuilder:
    """
    Build a per-function basic-block CFG for an Alpha AXP function.

    Args:
        data:     Raw binary bytes of the ELF/ECOFF file.
        sections: Dict mapping section name → _Section (from insn_alpha._parse_ecoff).
        gp_value: Global pointer value (for GP-relative address resolution).
    """

    def __init__(self, data: bytes, sections: Dict, gp_value: Optional[int]) -> None:
        self._data     = data
        self._sections = sections
        self._gp       = gp_value

    def _va_to_off(self, va: int) -> Optional[int]:
        for sec in self._sections.values():
            if sec.vaddr and sec.vaddr <= va < sec.vaddr + sec.size:
                return sec.rawptr + (va - sec.vaddr)
        return None

    def _insn_at(self, va: int) -> Optional[int]:
        off = self._va_to_off(va)
        if off is None or off + 4 > len(self._data):
            return None
        return int.from_bytes(self._data[off:off+4], 'little')

    def build(
        self,
        func_va:   int,
        max_insns: int = 4096,
    ) -> Dict[int, BasicBlock]:
        """
        Build the CFG for the function starting at func_va.

        Uses a worklist BFS from func_va. Stops at RET, indirect JMP,
        or when the instruction count limit is reached.

        Returns a dict mapping BasicBlock.start_va → BasicBlock.
        Predecessor lists are filled after all blocks are discovered.
        """
        blocks: Dict[int, BasicBlock] = {}
        worklist: List[int] = [func_va]
        visited_starts: Set[int] = set()
        total_insns = 0

        while worklist:
            bb_start = worklist.pop()
            if bb_start in visited_starts:
                continue
            visited_starts.add(bb_start)

            insns: List[Tuple[int, int]] = []
            succs: List[int] = []
            is_ret = False
            is_jmp = False
            va = bb_start

            for _ in range(max_insns - total_insns):
                insn = self._insn_at(va)
                if insn is None:
                    break
                insns.append((va, insn))
                total_insns += 1

                op, ra, rb, _ = _decode_alpha(insn)

                # RET / JMP (indirect branches — end of block)
                if op == _OP_JMP:
                    hint = (insn >> 14) & 0x3
                    if hint in (_HINT_RET, _HINT_JMP):
                        is_ret = (hint == _HINT_RET)
                        is_jmp = (hint == _HINT_JMP)
                        va += 4
                        break
                    # JSR / JSR_COROUTINE — treat as fall-through (like BSR)
                    va += 4
                    continue

                # BSR — call; execution returns to va+4 (fall-through, not a CFG edge)
                if op == _OP_BSR:
                    va += 4
                    continue

                # Unconditional branch BR — one successor, end of block
                if op == _OP_BR:
                    target = _branch_target(va, insn)
                    succs.append(target)
                    va += 4
                    break

                # Conditional branches — two successors: taken target + fall-through
                if op in _COND_BRANCH_OPS:
                    target = _branch_target(va, insn)
                    fall   = va + 4
                    succs.extend([target, fall])
                    va += 4
                    break

                va += 4
            else:
                # Hit instruction limit without a terminator — treat as unknown exit
                pass

            if not insns:
                continue

            bb = BasicBlock(
                start_va=bb_start,
                end_va=insns[-1][0],
                insns=insns,
                succs=succs,
                preds=[],
                is_ret=is_ret,
                is_jmp=is_jmp,
            )
            blocks[bb_start] = bb

            for succ_va in succs:
                if succ_va not in visited_starts:
                    worklist.append(succ_va)

        # Fill predecessor lists
        for bb in blocks.values():
            for succ_va in bb.succs:
                if succ_va in blocks:
                    blocks[succ_va].preds.append(bb.start_va)

        return blocks

    def trace_return_value(
        self,
        cfg:    Dict[int, BasicBlock],
        ret_reg: int = 0,              # r0 = Alpha return value register
        window:  int = 32,
    ) -> List[ReturnTrace]:
        """
        For each RET block in cfg, trace backward to find what value is in
        ret_reg (default r0/$v0) at the RET instruction.

        Returns one ReturnTrace per RET block.
        """
        from ablation.analyzers.insn_alpha import (
            _OP_LDA, _OP_LDAH, _OP_LDQ, _OP_BIS, _BIS_FUNC,
            _REG_GP, _REG_ZERO,
        )

        ret_blocks = [bb for bb in cfg.values() if bb.is_ret]
        results: List[ReturnTrace] = []

        for bb in ret_blocks:
            # Scan backward through this block's instructions
            insns = bb.insns
            reg   = ret_reg
            found = ReturnTrace(
                ret_va=bb.end_va,
                reg=reg,
                insn_type='UNKNOWN',
                value=0,
                interp='Not found in exit block',
            )

            for va, insn in reversed(insns[-window:]):
                op, ra, rb, d16 = _decode_alpha(insn)

                # LDA Ra, disp(Rb) — loads address
                if op == _OP_LDA and ra == reg:
                    if rb == _REG_ZERO:
                        found = ReturnTrace(
                            ret_va=bb.end_va, reg=reg,
                            insn_type='LDA_CONST',
                            value=d16 & 0xFFFFFFFFFFFFFFFF,
                            interp=f'LDA r{reg}, {d16}($zero) → constant 0x{d16 & 0xFFFF:x}',
                        )
                    elif rb == _REG_GP and self._gp:
                        addr = self._gp + d16
                        s = self._try_read_string(addr)
                        found = ReturnTrace(
                            ret_va=bb.end_va, reg=reg,
                            insn_type='LDA_GP',
                            value=addr,
                            interp=f'LDA r{reg}, {d16}($gp) → 0x{addr:x}'
                                   + (f' = {s!r}' if s else ''),
                        )
                    else:
                        found = ReturnTrace(
                            ret_va=bb.end_va, reg=reg,
                            insn_type='LDA_REG',
                            value=0,
                            interp=f'LDA r{reg}, {d16}(r{rb}) — register-relative (not traced)',
                        )
                    break

                # LDAH Ra, disp(Rb) — load address high (disp << 16)
                if op == _OP_LDAH and ra == reg and rb == _REG_GP and self._gp:
                    addr = self._gp + (d16 << 16)
                    found = ReturnTrace(
                        ret_va=bb.end_va, reg=reg,
                        insn_type='LDAH_GP',
                        value=addr,
                        interp=f'LDAH r{reg}, {d16}($gp)<<16 → 0x{addr:x}',
                    )
                    break

                # LDQ Ra, disp(Rb) — load quadword (GOT dereference)
                if op == _OP_LDQ and ra == reg and rb == _REG_GP and self._gp:
                    got_addr = self._gp + d16
                    off = self._va_to_off(got_addr)
                    if off and off + 8 <= len(self._data):
                        val = int.from_bytes(self._data[off:off+8], 'little')
                        found = ReturnTrace(
                            ret_va=bb.end_va, reg=reg,
                            insn_type='LDQ_GP',
                            value=val,
                            interp=f'LDQ r{reg}, {d16}($gp) GOT[0x{got_addr:x}] = 0x{val:x}',
                        )
                    else:
                        found = ReturnTrace(
                            ret_va=bb.end_va, reg=reg,
                            insn_type='LDQ_GP',
                            value=got_addr,
                            interp=f'LDQ r{reg}, {d16}($gp) GOT addr 0x{got_addr:x} (unresolved)',
                        )
                    break

                # BIS Rc=reg with Ra==31 or Rb==31 (MOV pseudo-op)
                if op == _OP_BIS and (insn & 0x1FF) == _BIS_FUNC:
                    rc = insn & 0x1F
                    if rc == reg:
                        src = ra if ra != _REG_ZERO else rb
                        if src == _REG_ZERO:
                            found = ReturnTrace(
                                ret_va=bb.end_va, reg=reg,
                                insn_type='LDA_CONST',
                                value=0,
                                interp=f'BIS $zero,$zero,r{reg} — clears r{reg} (return 0)',
                            )
                            break
                        # Recurse one level: now trace src register
                        reg = src
                        continue

                # BSR encountered before finding reg — return value comes from a call
                if op == _OP_BSR:
                    target = _branch_target(va, insn)
                    found = ReturnTrace(
                        ret_va=bb.end_va, reg=ret_reg,
                        insn_type='BSR_RETVAL',
                        value=target,
                        interp=f'r{ret_reg} = return value of BSR→0x{target:x}',
                    )
                    break

            results.append(found)

        return results

    def try_read_string(self, addr: int, maxlen: int = 128) -> str:
        return self._try_read_string(addr, maxlen)

    def _try_read_string(self, addr: int, maxlen: int = 128) -> str:
        for sec in self._sections.values():
            if not sec.rawptr:
                continue
            if sec.vaddr <= addr < sec.vaddr + sec.size:
                off = sec.rawptr + (addr - sec.vaddr)
                end = self._data.find(b'\x00', off, off + maxlen)
                raw = self._data[off: end if end >= 0 else off + maxlen]
                if raw and all(0x20 <= b < 0x7F for b in raw):
                    return raw.decode('ascii', errors='replace')
                break
        return ''

    def report(self, cfg: Dict[int, BasicBlock]) -> str:
        """Return a human-readable CFG summary."""
        bbs = sorted(cfg.values(), key=lambda b: b.start_va)
        ret_bbs  = [b for b in bbs if b.is_ret]
        jmp_bbs  = [b for b in bbs if b.is_jmp]
        lines = [
            f'AlphaCFG: {len(bbs)} basic blocks',
            f'  RET exits : {len(ret_bbs)}',
            f'  JMP exits : {len(jmp_bbs)} (indirect, target unknown)',
            f'  total insns: {sum(len(b.insns) for b in bbs)}',
            '',
        ]
        for bb in bbs[:30]:
            term = 'RET' if bb.is_ret else ('JMP' if bb.is_jmp else f'→{[hex(s) for s in bb.succs]}')
            lines.append(
                f'  BB 0x{bb.start_va:x}–0x{bb.end_va:x} '
                f'({len(bb.insns)} insns) [{term}]'
            )
        if len(bbs) > 30:
            lines.append(f'  ... ({len(bbs) - 30} more blocks)')
        return '\n'.join(lines)
