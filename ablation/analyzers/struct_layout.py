"""
struct_layout.py — Struct field recovery from IRIG load/store patterns.

Why this exists:
  1. PseudoCEmitter emits raw pointer dereferences: *(r1 + 0x18). When the
     same base register is accessed at multiple offsets, it almost certainly
     holds a struct pointer. Naming the struct and its fields makes the
     pseudo-C output significantly more readable.
  2. For exec-class taint analysis, knowing that a `system()` argument came
     from `cmd_ctx->command` (offset 0x18) is more useful than `*(r1+0x18)`.
  3. IBM POWER and Alpha codebases are particularly struct-heavy — large C
     programs with deep struct hierarchies, no RTTI.

Algorithm:
  Walk every IRLoad and IRStore in the IRIG. When the address is of the form
  `IRBinop('+', IRReg(base), IRConst(offset))`, record the (base, offset,
  width) triple. Group by base register. Any base with two or more distinct
  offsets is a struct candidate.

  Field names default to `field_<hex_offset>`. The caller can supply a
  names dict to override (e.g. from debug info or manual annotation).

Integration with PseudoCEmitter:
  Pass the StructLayoutAnalyzer output to PseudoCEmitter as a `structs`
  argument; the emitter then replaces `*(r1 + 0x18)` with `r1->field_18`.

Usage:

    from ablation.analyzers.ir import AlphaIRLifter, PseudoCEmitter
    from ablation.analyzers.struct_layout import StructLayoutAnalyzer

    irig = AlphaIRLifter(data, sections, gp).lift_cfg(cfg)
    analyzer = StructLayoutAnalyzer(irig)
    structs = analyzer.analyze()

    for s in structs:
        print(s.report())

    # Annotated pseudo-C
    print(PseudoCEmitter(irig, structs=structs).emit())
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ablation.analyzers.ir import (
    IRIG, IRAssign, IRBinop, IRBlock, IRConst, IRLoad,
    IRNode, IRReg, IRStore,
)


# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class FieldAccess:
    """One load or store to a struct field."""
    insn_va:    int          # approximate (block start_va + index)
    is_store:   bool
    width:      int          # bits


@dataclass
class FieldDef:
    """A single struct field inferred from access patterns."""
    offset:   int
    width:    int            # bits (from first access seen)
    accesses: List[FieldAccess] = field(default_factory=list)
    name:     str = ''       # empty until annotated

    def field_name(self) -> str:
        if self.name:
            return self.name
        return f'field_{self.offset:x}'


@dataclass
class StructDef:
    """
    Inferred struct type for a single base register.

    base_reg: the register that holds the struct pointer.
    fields:   offset → FieldDef (sorted by offset).
    """
    base_reg: str
    fields:   Dict[int, FieldDef] = field(default_factory=dict)

    def report(self) -> str:
        lines = [f'struct_from_{self.base_reg} {{']
        for off in sorted(self.fields):
            fld = self.fields[off]
            acc_count = len(fld.accesses)
            loads  = sum(1 for a in fld.accesses if not a.is_store)
            stores = sum(1 for a in fld.accesses if a.is_store)
            lines.append(
                f'  /* +0x{off:02x} */ u{fld.width} {fld.field_name()};'
                f'  // {acc_count} accesses ({loads}R {stores}W)'
            )
        lines.append('};')
        return '\n'.join(lines)

    def annotate(self, offset: int, name: str) -> None:
        """Set a human-readable field name for the given offset."""
        if offset in self.fields:
            self.fields[offset].name = name


# ─── Analyzer ─────────────────────────────────────────────────────────────────

# Minimum number of distinct offsets required to call something a struct.
_MIN_FIELDS = 2

# Maximum plausible struct size (bytes). Accesses beyond this are probably
# not struct members (e.g. array accesses with large computed indices).
_MAX_STRUCT_SIZE = 0x10000


class StructLayoutAnalyzer:
    """
    Recover struct field layouts from IRIG memory access patterns.

    Args:
        irig:   IRIG produced by any IRLifter.
        names:  optional dict of {(base_reg, offset): field_name} overrides.
    """

    def __init__(self,
                 irig:  IRIG,
                 names: Optional[Dict[Tuple[str, int], str]] = None):
        self._irig  = irig
        self._names = names or {}

    def analyze(self) -> List[StructDef]:
        """
        Scan the IRIG for base+offset memory access patterns and return one
        StructDef per candidate base register.
        """
        # accesses[base_reg][offset] = list of FieldAccess
        accesses: Dict[str, Dict[int, List[FieldAccess]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for va, block in self._irig.blocks.items():
            self._scan_block(va, block, accesses)

        # Filter: keep only bases with at least MIN_FIELDS distinct offsets
        result: List[StructDef] = []
        for base_reg, offset_map in sorted(accesses.items()):
            if len(offset_map) < _MIN_FIELDS:
                continue
            struct_def = StructDef(base_reg=base_reg)
            for offset in sorted(offset_map):
                field_accesses = offset_map[offset]
                # Determine the dominant width (most common)
                width = max(
                    set(a.width for a in field_accesses),
                    key=lambda w: sum(1 for a in field_accesses if a.width == w),
                )
                fld = FieldDef(offset=offset, width=width, accesses=field_accesses)
                # Apply name override
                override = self._names.get((base_reg, offset))
                if override:
                    fld.name = override
                struct_def.fields[offset] = fld
            result.append(struct_def)
        return result

    def _scan_block(
        self,
        block_va: int,
        block:    IRBlock,
        accesses: Dict[str, Dict[int, List[FieldAccess]]],
    ) -> None:
        for idx, stmt in enumerate(block.stmts):
            approximate_va = block_va + idx * 4

            if isinstance(stmt, IRAssign) and isinstance(stmt.rhs, IRLoad):
                self._record_load(stmt.rhs, approximate_va, accesses)

            elif isinstance(stmt, IRStore):
                self._record_store(stmt, approximate_va, accesses)

            # Also look for nested loads in expressions
            elif isinstance(stmt, IRAssign):
                self._scan_node(stmt.rhs, approximate_va, False, accesses)

    def _scan_node(
        self,
        node:     IRNode,
        va:       int,
        is_store: bool,
        accesses: Dict[str, Dict[int, List[FieldAccess]]],
    ) -> None:
        if isinstance(node, IRLoad):
            self._record_load(node, va, accesses)
        elif isinstance(node, IRBinop):
            self._scan_node(node.lhs, va, is_store, accesses)
            self._scan_node(node.rhs, va, is_store, accesses)

    def _record_load(
        self,
        load:     IRLoad,
        va:       int,
        accesses: Dict[str, Dict[int, List[FieldAccess]]],
    ) -> None:
        base_reg, offset = self._extract_base_offset(load.addr)
        if base_reg is not None and 0 <= offset < _MAX_STRUCT_SIZE:
            accesses[base_reg][offset].append(
                FieldAccess(insn_va=va, is_store=False, width=load.width)
            )

    def _record_store(
        self,
        store:    IRStore,
        va:       int,
        accesses: Dict[str, Dict[int, List[FieldAccess]]],
    ) -> None:
        base_reg, offset = self._extract_base_offset(store.addr)
        if base_reg is not None and 0 <= offset < _MAX_STRUCT_SIZE:
            accesses[base_reg][offset].append(
                FieldAccess(insn_va=va, is_store=True, width=store.width)
            )

    @staticmethod
    def _extract_base_offset(addr: IRNode) -> Tuple[Optional[str], int]:
        """
        Extract (base_reg_name, offset) from an address expression.

        Recognises:
          IRReg(name)                    → (name, 0)
          IRBinop('+', IRReg, IRConst)   → (name, const)
          IRBinop('+', IRConst, IRReg)   → (name, const)
        """
        if isinstance(addr, IRReg):
            return addr.name, 0
        if isinstance(addr, IRBinop) and addr.op == '+':
            if isinstance(addr.lhs, IRReg) and isinstance(addr.rhs, IRConst):
                return addr.lhs.name, addr.rhs.value
            if isinstance(addr.lhs, IRConst) and isinstance(addr.rhs, IRReg):
                return addr.rhs.name, addr.lhs.value
        return None, 0
