"""
epilogue_share_scanner.py: Detect functions that share an epilogue via unconditional jump.

Some compilers merge the tail block (epilogue) of several functions into one shared
block and reach it with an unconditional jump rather than a call. When
run_interprocedural() encounters the shared block's address in ctx.func_starts it
may treat it as an independent function entry and follow a phantom taint path.

This scanner finds those entry-point impersonators, marks them in BinaryContext, and
lets the interprocedural loop skip them.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import List, Optional, Set

try:
    import capstone
    from capstone import tricore_const as _tc
    _HAS_CAPSTONE = True
    _CS_ARCH_TRICORE = capstone.CS_ARCH_TRICORE
    _CS_MODE_TC162   = capstone.CS_MODE_TRICORE_162
    _OP_IMM = _tc.CS_OP_IMM
except (ImportError, AttributeError):
    _HAS_CAPSTONE = False
    _OP_IMM = None

try:
    import lief as _lief
    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False


# Unconditional jump mnemonics in TriCore (the only supported arch for now)
_TRICORE_UNCOND_JUMP = frozenset({'j', 'ja', 'jl', 'jla'})


@dataclass(frozen=True)
class EpilogueShareHit:
    """One unconditional jump that lands inside another function's body."""
    from_func_va: int   # function that contains the jump
    jump_va: int        # VA of the jump instruction
    target_va: int      # VA the jump lands on
    host_func_va: int   # function whose body the target is inside


class EpilogueShareScanner:
    """
    Finds shared epilogue blocks in a TriCore binary.

    An unconditional jump whose target lands strictly inside another function's
    address range (not at its entry point) is an epilogue share: the compiler
    merged the two functions' closing block into one place.

    When injected into BinaryContext, those target VAs are added to
    ctx.shared_epilogues so run_interprocedural() can skip them.
    """

    def __init__(self, data: bytes, base_va: int, func_starts: List[int]) -> None:
        self._data = data
        self._base_va = base_va
        self._func_starts = sorted(func_starts)

    @classmethod
    def from_context(cls, ctx) -> "EpilogueShareScanner":
        """Build from a BinaryContext (uses ctx.binary_path + ctx.func_starts)."""
        if not _HAS_LIEF:
            raise ImportError("lief is required for EpilogueShareScanner.from_context()")
        with open(ctx.binary_path, "rb") as _f:
            data = _f.read()
        binary = _lief.parse(ctx.binary_path)
        if binary is None:
            raise ValueError(f"lief cannot parse {ctx.binary_path}")
        text = getattr(binary, "get_section", lambda _: None)(".text")
        base_va = text.virtual_address - text.offset if text else 0
        func_starts = list(getattr(ctx, "func_starts", None) or [])
        return cls(data, base_va, func_starts)

    @classmethod
    def from_bytes(
        cls, data: bytes, base_va: int, func_starts: List[int]
    ) -> "EpilogueShareScanner":
        """Build from a raw flat ROM blob (ECU firmware)."""
        return cls(data, base_va, func_starts)

    # -------------------------------------------------------------------------

    def scan(self) -> List[EpilogueShareHit]:
        if not _HAS_CAPSTONE:
            raise ImportError("capstone is required for EpilogueShareScanner.scan()")
        cs = capstone.Cs(_CS_ARCH_TRICORE, _CS_MODE_TC162)
        cs.detail = True

        starts = self._func_starts
        hits: List[EpilogueShareHit] = []

        for idx, func_va in enumerate(starts):
            func_end = starts[idx + 1] if idx + 1 < len(starts) else func_va + 0x200
            func_off = func_va - self._base_va
            func_size = func_end - func_va
            if func_off < 0 or func_off + func_size > len(self._data):
                continue
            chunk = self._data[func_off: func_off + func_size]

            for insn in cs.disasm(chunk, func_va):
                if insn.mnemonic not in _TRICORE_UNCOND_JUMP:
                    continue
                target = self._resolve_jump_target(insn)
                if target is None:
                    continue
                host = self._find_host_function(target, starts)
                if host is None or host == func_va:
                    continue
                # target lands strictly inside host's body (not at its entry point)
                if target != host:
                    hits.append(EpilogueShareHit(
                        from_func_va=func_va,
                        jump_va=insn.address,
                        target_va=target,
                        host_func_va=host,
                    ))
        return hits

    def inject(self, ctx) -> int:
        """
        Mark shared epilogue entry points in ctx.

        Adds target VAs to ctx.shared_epilogues (set[int]) and names them
        'shared_ep_<hex>' in BinaryContext. Returns the count of VAs added.
        """
        hits = self.scan()
        if not hasattr(ctx, "shared_epilogues") or ctx.shared_epilogues is None:
            ctx.shared_epilogues: Set[int] = set()
        added = 0
        for hit in hits:
            if hit.target_va not in ctx.shared_epilogues:
                ctx.shared_epilogues.add(hit.target_va)
                ctx.set_name(hit.target_va, f"shared_ep_{hit.target_va:x}")
                added += 1
        return added

    # -------------------------------------------------------------------------

    def _resolve_jump_target(self, insn: "capstone.CsInsn") -> Optional[int]:
        """Extract the immediate jump target from a J/JA/JL/JLA instruction."""
        if _OP_IMM is None:
            return None
        for op in insn.operands:
            if op.type == _OP_IMM:
                return op.imm
        return None

    def _find_host_function(
        self, target_va: int, starts: List[int]
    ) -> Optional[int]:
        """
        Return the VA of the function whose body contains target_va, or None.

        Uses bisect to find the largest func_start <= target_va.
        """
        idx = bisect.bisect_right(starts, target_va) - 1
        if idx < 0:
            return None
        host_start = starts[idx]
        host_end = starts[idx + 1] if idx + 1 < len(starts) else host_start + 0x200
        if host_start <= target_va < host_end:
            return host_start
        return None

    # -------------------------------------------------------------------------

    @staticmethod
    def report(hits: List[EpilogueShareHit]) -> str:
        if not hits:
            return "EpilogueShareScanner: 0 shared epilogue blocks found"
        lines = [f"EpilogueShareScanner: {len(hits)} shared epilogue block(s)"]
        for h in hits[:20]:
            lines.append(
                f"  0x{h.from_func_va:x}: j 0x{h.target_va:x}"
                f" (inside 0x{h.host_func_va:x})"
            )
        if len(hits) > 20:
            lines.append(f"  ... {len(hits) - 20} more")
        return "\n".join(lines)
