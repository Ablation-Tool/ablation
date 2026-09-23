"""
ipreg_annotator.py -- Interprocedural register annotator (N-hop forward symbolic pass).

Extends RegAnnotator to follow call chains across function boundaries.
At each callee, seeds entry registers with the actual RegVal objects from the
caller's register state at the call site -- so arg provenance traces back to the
root function's entry args.

Usage:
    from ablation.analyzers.ipreg_annotator import IPRegAnnotator
    from ablation.analyzers.binary_context import BinaryContext

    ctx = BinaryContext.load_or_build('/path/to/binary')
    ira = IPRegAnnotator.from_context(ctx)

    chain = ira.annotate_chain(entry_va=0x412f4, max_hops=2)
    print(chain.fmt())

Example output (libfmgsvrd.so -> conf_ctx_set_cli -> Tcl_Eval):
    CHAIN 0x412f4  libfmgsvrd.so:__conf_ctx_from_file  [hops=2]

    [0x412f4]  hop 0
      0x41339  conf_parse_devinfo(rdi=arg0_entry, rsi=0x...)
      0x41366  conf_ctx_set_cli(rdi=arg0_entry, rsi=?, rdx=?)
        [-> libfmgsvrd.so:0x5aee0  hop 1]
        0x5af12  Tcl_Eval(rdi=arg0_entry, rsi=?)  *** EXTERNAL ***
        0x5b023  __cdb_obj_ctx_init(rdi=arg0_entry)  *** EXTERNAL ***

    For cross-binary chains: pass lib_graph=LibGraph instance. IPRegAnnotator will
    look up PLT symbols in the LibGraph's loaded binaries and follow calls into
    other libraries by loading RegAnnotator for each callee binary on demand.

    ira = IPRegAnnotator.from_context(ctx, lib_graph=lg)
    chain = ira.annotate_chain(0x412f4, max_hops=3)
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .binary_context import BinaryContext
from .reg_annotator import RegAnnotator, RegVal, _ARG_REGS, _norm


@dataclass
class ChainCallSite:
    """One call site within the chain, with optional recursive callee chain."""
    site_va: int
    target_va: int
    target_name: str
    target_binary: str
    args: Dict[str, RegVal]
    callee_chain: Optional["ChainResult"] = None
    is_plt_leaf: bool = False  # True = external PLT call, not followed further

    def fmt(self, indent: int = 0) -> str:
        pad = "  " * indent
        parts = []
        for reg in _ARG_REGS:
            v = self.args.get(reg)
            if v and v.kind not in ('unknown',):
                parts.append(f"{reg}={v.display()}")
        args_str = ', '.join(parts)
        name = self.target_name or f"0x{self.target_va:x}"
        suffix = ""
        if self.is_plt_leaf:
            suffix = "  [PLT/external]"
        line = f"{pad}  0x{self.site_va:x}  {name}({args_str}){suffix}"
        lines = [line]
        if self.callee_chain:
            lines.append(self.callee_chain.fmt(indent=indent + 1))
        return "\n".join(lines)


@dataclass
class ChainResult:
    """Result for one function in the call chain."""
    func_va: int
    func_end_va: int
    binary: str
    hop: int
    calls: List[ChainCallSite] = field(default_factory=list)

    def fmt(self, indent: int = 0) -> str:
        pad = "  " * indent
        lines = [
            f"{pad}[0x{self.func_va:x}..0x{self.func_end_va:x}]  {self.binary}  hop {self.hop}"
        ]
        for cs in self.calls:
            lines.append(cs.fmt(indent=indent))
        return "\n".join(lines)

    def all_sinks(self, sink_names: Set[str]) -> List[Tuple[int, str, "ChainCallSite"]]:
        """Recursively find all calls to sink_names. Returns (func_va, binary, site)."""
        results = []
        for cs in self.calls:
            if cs.target_name in sink_names:
                results.append((self.func_va, self.binary, cs))
            if cs.callee_chain:
                results.extend(cs.callee_chain.all_sinks(sink_names))
        return results


@dataclass
class IPChain:
    """Top-level interprocedural chain result."""
    root_va: int
    root_binary: str
    max_hops: int
    root: ChainResult

    def fmt(self) -> str:
        name = Path(self.root_binary).name if self.root_binary else "?"
        lines = [
            f"CHAIN 0x{self.root_va:x}  {name}  [max_hops={self.max_hops}]",
            "",
        ]
        lines.append(self.root.fmt(indent=0))
        return "\n".join(lines)

    def all_sinks(self, sink_names: Set[str]) -> List[Tuple[int, str, ChainCallSite]]:
        return self.root.all_sinks(sink_names)

    def sink_report(self, sink_names: Set[str]) -> str:
        hits = self.all_sinks(sink_names)
        if not hits:
            return f"No calls to {sink_names} found in chain."
        lines = [f"SINK CALLS in chain from 0x{self.root_va:x}:"]
        for func_va, binary, cs in hits:
            b = Path(binary).name if binary else "?"
            args_parts = []
            for reg in _ARG_REGS:
                v = cs.args.get(reg)
                if v and v.kind != 'unknown':
                    args_parts.append(f"{reg}={v.display()}")
            lines.append(
                f"  {b}:0x{func_va:x} -> {cs.target_name}(0x{cs.site_va:x})"
                f"  [{', '.join(args_parts)}]"
            )
        return "\n".join(lines)


class IPRegAnnotator:
    """
    Interprocedural register annotator.

    Follows call chains N hops deep, carrying RegVal arg states across function
    boundaries. At each callee entry, seeds register state from the caller's
    register state at the call site rather than seeding with generic arg0/arg1.

    Cross-binary: if lib_graph is provided, PLT calls into other binaries are
    followed by loading a RegAnnotator for the callee binary on demand.
    """

    def __init__(
        self,
        binary_path: str,
        ctx: Optional[BinaryContext] = None,
        lib_graph=None,
    ):
        self.path = binary_path
        self._ctx = ctx or BinaryContext.load_or_build(binary_path)
        self._ra = RegAnnotator.from_path(binary_path)
        self._lib_graph = lib_graph

        # Cache of RegAnnotator + BinaryContext per binary path (for cross-binary)
        self._ra_cache: Dict[str, RegAnnotator] = {binary_path: self._ra}
        self._ctx_cache: Dict[str, BinaryContext] = {binary_path: self._ctx}

    @classmethod
    def from_context(
        cls,
        ctx: BinaryContext,
        lib_graph=None,
    ) -> "IPRegAnnotator":
        return cls(ctx.path, ctx=ctx, lib_graph=lib_graph)

    @classmethod
    def from_path(cls, binary_path: str, lib_graph=None) -> "IPRegAnnotator":
        return cls(binary_path, lib_graph=lib_graph)

    # ── query API ─────────────────────────────────────────────────────────────

    def annotate_chain(
        self,
        entry_va: int,
        entry_end_va: int = 0,
        max_hops: int = 2,
        max_callees_per_hop: int = 10,
        entry_binary: Optional[str] = None,
        seed_args: bool = True,
        visited: Optional[Set[Tuple[str, int]]] = None,
    ) -> IPChain:
        """
        Build interprocedural call chain from entry_va, max_hops deep.

        entry_va:       root function VA
        entry_end_va:   root function end VA (0 = auto from BinaryContext)
        max_hops:       maximum call depth to follow
        max_callees_per_hop: cap per function to avoid explosion in dense functions
        seed_args:      seed root entry with arg0/arg1/... placeholders
        """
        binary = entry_binary or self.path
        if visited is None:
            visited = set()

        root = self._annotate_one(
            va=entry_va,
            end_va=entry_end_va,
            binary=binary,
            hop=0,
            max_hops=max_hops,
            max_callees=max_callees_per_hop,
            entry_regs=None,  # root: use seed_args
            seed_args=seed_args,
            visited=visited,
        )

        return IPChain(
            root_va=entry_va,
            root_binary=binary,
            max_hops=max_hops,
            root=root,
        )

    # ── internal recursive pass ────────────────────────────────────────────────

    def _annotate_one(
        self,
        va: int,
        end_va: int,
        binary: str,
        hop: int,
        max_hops: int,
        max_callees: int,
        entry_regs: Optional[Dict[str, RegVal]],
        seed_args: bool,
        visited: Set[Tuple[str, int]],
    ) -> ChainResult:
        key = (binary, va)
        if key in visited:
            return ChainResult(func_va=va, func_end_va=va, binary=binary, hop=hop)
        visited.add(key)

        ra = self._get_ra(binary)
        ctx = self._get_ctx(binary)

        # Determine function end
        if end_va == 0:
            end_va = self._func_end(ctx, va)

        # Run the forward symbolic pass
        if entry_regs is not None:
            # Callee: seed from caller's register state at call site
            result = self._run_seeded(ra, va, end_va, entry_regs)
        else:
            # Root: seed with generic argN placeholders
            result = ra.annotate_calls(va, end_va, seed_args=seed_args)

        chain_result = ChainResult(
            func_va=va,
            func_end_va=end_va,
            binary=binary,
            hop=hop,
        )

        for call_site in result.calls[:max_callees]:
            target_va = call_site.target_va
            target_name = call_site.target_name
            target_binary = binary

            is_plt = target_va in ra._plt if target_va else False

            # Determine callee binary for cross-binary calls
            if is_plt and self._lib_graph:
                target_binary = self._resolve_callee_binary(target_name, binary)

            callee_chain = None
            is_leaf = False

            if hop < max_hops and target_va and not is_plt:
                # Internal call -- follow it
                callee_end = self._func_end(self._get_ctx(target_binary), target_va)
                callee_chain = self._annotate_one(
                    va=target_va,
                    end_va=callee_end,
                    binary=target_binary,
                    hop=hop + 1,
                    max_hops=max_hops,
                    max_callees=max_callees,
                    entry_regs=dict(call_site.args),
                    seed_args=False,
                    visited=visited,
                )
            elif hop < max_hops and is_plt and self._lib_graph and target_binary != binary:
                # Cross-binary PLT call -- try to follow into the other library
                export_va = self._get_ctx(target_binary).exports.get(target_name, 0)
                if export_va:
                    callee_end = self._func_end(self._get_ctx(target_binary), export_va)
                    callee_chain = self._annotate_one(
                        va=export_va,
                        end_va=callee_end,
                        binary=target_binary,
                        hop=hop + 1,
                        max_hops=max_hops,
                        max_callees=max_callees,
                        entry_regs=dict(call_site.args),
                        seed_args=False,
                        visited=visited,
                    )
                else:
                    is_leaf = True
            else:
                is_leaf = is_plt or (target_va == 0)

            chain_result.calls.append(ChainCallSite(
                site_va=call_site.site_va,
                target_va=target_va,
                target_name=target_name,
                target_binary=target_binary,
                args=dict(call_site.args),
                callee_chain=callee_chain,
                is_plt_leaf=is_leaf,
            ))

        return chain_result

    def _run_seeded(
        self,
        ra: RegAnnotator,
        va: int,
        end_va: int,
        entry_regs: Dict[str, RegVal],
    ):
        """
        Run RegAnnotator forward pass with a pre-set register state.

        Reuses RegAnnotator._step() machinery but injects the caller's
        register state instead of seeding with generic argN values.
        """
        from .reg_annotator import _CALLER_SAVED, AnnotationResult
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM

        md = ra._md
        code = ra._read_va(va, end_va - va)
        if not code:
            return AnnotationResult(func_va=va, func_end_va=end_va)

        # Seed: start with entry_regs (from caller's register state)
        # Normalize reg names
        regs: Dict[str, RegVal] = {_norm(k): v for k, v in entry_regs.items()}

        result = AnnotationResult(func_va=va, func_end_va=end_va)
        for insn in md.disasm(code, va):
            if insn.address >= end_va:
                break
            ra._step(insn, regs, result)

        return result

    # ── helpers ───────────────────────────────────────────────────────────────

    def _func_end(self, ctx: BinaryContext, va: int, max_window: int = 2048) -> int:
        starts = ctx.func_starts
        if not starts:
            return va + max_window
        idx = bisect.bisect_right(starts, va)
        if idx < len(starts):
            gap = starts[idx] - va
            if 8 <= gap <= max_window:
                return starts[idx]
        return va + max_window

    def _get_ra(self, binary: str) -> RegAnnotator:
        if binary not in self._ra_cache:
            self._ra_cache[binary] = RegAnnotator.from_path(binary)
        return self._ra_cache[binary]

    def _get_ctx(self, binary: str) -> BinaryContext:
        if binary not in self._ctx_cache:
            self._ctx_cache[binary] = BinaryContext.load_or_build(binary)
        return self._ctx_cache[binary]

    def _resolve_callee_binary(self, symbol_name: str, caller_binary: str) -> str:
        """Use LibGraph to find which binary exports this symbol."""
        if self._lib_graph is None:
            return caller_binary
        defined = self._lib_graph.defined_in(symbol_name)
        if not defined:
            return caller_binary
        # Prefer a binary that is loaded in the graph and is not the caller
        for bin_name, _ in defined:
            ctx = self._lib_graph.context(bin_name)
            if ctx and ctx.path != caller_binary:
                return ctx.path
        return caller_binary
