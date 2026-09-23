"""
lib_graph.py -- Cross-binary import/export matrix for a firmware library set.

Loads BinaryContext for every ELF in a directory (cache hit = ~110ms per binary),
builds a unified index of exports, callers, and import relationships across all
libraries at once.

Usage:
    lg = LibGraph.from_dir('/tmp/fmg800/rootfs/usr/lib/')
    lg = LibGraph.from_paths(['/path/to/libfoo.so', '/path/to/libbar.so'])

    lg.callers_of('conf_ctx_set_cli')
    # -> [LibCaller(binary='libfmgsvrd.so', caller_va=0x412f4, fn='0x412f4'),
    #     LibCaller(binary='libdmserver.so', caller_va=0x9951d, fn='svc_dmworker_diff_handler_')]

    lg.defined_in('conf_ctx_set_cli')
    # -> [('libdmapi.so', 0x5aee0)]

    lg.imports_of('libfmgsvrd.so')
    # -> ['conf_ctx_set_cli', 'conf_parse_devinfo', ...]

    lg.exports_of('libdmapi.so')
    # -> ['conf_ctx_set_cli', 'dm_devinfo2dvmdev', ...]

    lg.summary()
    # table: binary, exports, imports, outbound_calls

    print(lg.callers_of('Tcl_Eval'))
    # cross-binary: every library that calls Tcl_Eval anywhere
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .binary_context import BinaryContext

_ELF_MAGIC = b'\x7fELF'
_SO_SUFFIXES = {'.so'}


def _is_elf(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            return f.read(4) == _ELF_MAGIC
    except OSError:
        return False


def _is_shared_lib(path: str) -> bool:
    p = Path(path)
    if not p.is_file():
        return False
    name = p.name
    if '.so' in name:
        return True
    return False


@dataclass
class LibCaller:
    """One call site from one binary that calls a given symbol."""
    binary: str       # base name of the calling binary
    binary_path: str  # full path
    caller_va: int    # VA of the function that contains the call
    call_site_va: int # VA of the call instruction itself (= caller_va from call_edges; see note)
    fn_name: str      # export name of caller_va if known, else hex

    def __str__(self) -> str:
        fn = self.fn_name or f"0x{self.caller_va:x}"
        return f"{self.binary}:{fn} (0x{self.caller_va:x})"


class LibGraph:
    """
    Cross-binary call graph and import/export index.

    Built from BinaryContext objects. All BinaryContext caches are reused
    from ~/.ablation/cache/ so repeated LibGraph.from_dir() calls are fast.
    """

    def __init__(self):
        # binary_name -> BinaryContext
        self._contexts: Dict[str, BinaryContext] = {}
        # symbol_name -> [(binary_name, va)] -- where the symbol is DEFINED (exported)
        self._defined: Dict[str, List[Tuple[str, int]]] = {}
        # symbol_name -> [LibCaller] -- all call sites across all binaries
        self._callers: Dict[str, List[LibCaller]] = {}
        # binary_name -> [symbol_name] -- what each binary imports via PLT
        self._imports: Dict[str, List[str]] = {}
        # binary_name -> [symbol_name] -- what each binary exports
        self._exports: Dict[str, List[str]] = {}

    # ── factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_dir(
        cls,
        directory: str,
        pattern: str = "*.so*",
        max_binaries: int = 200,
        verbose: bool = False,
    ) -> "LibGraph":
        """
        Build LibGraph from all shared libraries in a directory.

        directory:    path to scan for .so files
        pattern:      glob pattern for files to include
        max_binaries: cap to avoid OOM on very large rootfs dirs
        verbose:      print progress per binary
        """
        paths = []
        for root, _, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                if _is_shared_lib(fpath) and _is_elf(fpath):
                    paths.append(fpath)
                    if len(paths) >= max_binaries:
                        break
            if len(paths) >= max_binaries:
                break

        return cls.from_paths(paths, verbose=verbose)

    @classmethod
    def from_paths(cls, paths: List[str], verbose: bool = False) -> "LibGraph":
        """Build LibGraph from an explicit list of binary paths."""
        lg = cls()
        for path in paths:
            try:
                ctx = BinaryContext.load_or_build(path)
                name = Path(path).name
                lg._contexts[name] = ctx
                if verbose:
                    print(f"  loaded {name}: {len(ctx.exports)} exports, {len(ctx.plt)} PLT, {len(ctx.call_edges)} edges")
            except Exception as e:
                if verbose:
                    print(f"  SKIP {path}: {e}")
        lg._build_indices()
        return lg

    # ── query API ─────────────────────────────────────────────────────────────

    def callers_of(self, symbol: str) -> List[LibCaller]:
        """
        Return all call sites across all loaded binaries that call `symbol`.

        `symbol` is matched against PLT-resolved call targets.
        """
        return self._callers.get(symbol, [])

    def defined_in(self, symbol: str) -> List[Tuple[str, int]]:
        """
        Return [(binary_name, va), ...] for all binaries that EXPORT `symbol`.
        Typically 1 entry; multiple = duplicate symbol or versioned .so.
        """
        return self._defined.get(symbol, [])

    def imports_of(self, binary_name: str) -> List[str]:
        """Return list of symbol names imported via PLT by binary_name."""
        return self._imports.get(binary_name, [])

    def exports_of(self, binary_name: str) -> List[str]:
        """Return list of symbol names exported by binary_name."""
        return self._exports.get(binary_name, [])

    def context(self, binary_name: str) -> Optional[BinaryContext]:
        """Return the BinaryContext for a given binary name."""
        return self._contexts.get(binary_name)

    def all_binaries(self) -> List[str]:
        """Return sorted list of all loaded binary names."""
        return sorted(self._contexts.keys())

    def call_chain(self, from_binary: str, to_symbol: str, max_depth: int = 4) -> List[List[str]]:
        """
        BFS: find shortest call chains from any function in from_binary to to_symbol.

        Returns list of chains, each chain = [from_binary:fn, ..., binary:to_symbol].
        Chains cross library boundaries by following exports -> callers.
        """
        results: List[List[str]] = []
        # Seed: all functions in from_binary that call to_symbol directly
        direct = [c for c in self.callers_of(to_symbol) if c.binary == from_binary]
        for c in direct:
            results.append([f"{from_binary}:{c.fn_name}", f"{c.binary}:{to_symbol}"])

        if results:
            return results

        # BFS one hop further: from_binary exports something that another binary calls
        # then that binary calls to_symbol
        visited: Set[str] = {from_binary}
        queue = [(from_binary, [from_binary])]
        while queue and len(results) < 10:
            current_bin, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            for sym in self.exports_of(current_bin):
                for c in self.callers_of(sym):
                    next_bin = c.binary
                    if next_bin in visited:
                        continue
                    new_path = path + [f"{next_bin}:{c.fn_name}"]
                    direct2 = [c2 for c2 in self.callers_of(to_symbol) if c2.binary == next_bin]
                    for d in direct2:
                        results.append(new_path + [f"{next_bin}:{to_symbol}"])
                    if next_bin not in visited:
                        visited.add(next_bin)
                        queue.append((next_bin, new_path))

        return results

    def summary(self, top_callers: int = 5) -> str:
        """Compact summary table: binary, exports, imports, unique outbound call targets."""
        lines = [
            f"LibGraph: {len(self._contexts)} binaries",
            f"  total exports  : {sum(len(v) for v in self._exports.values())}",
            f"  total PLT syms : {sum(len(v) for v in self._imports.values())}",
            f"  total call edges: {sum(len(ctx.call_edges) for ctx in self._contexts.values())}",
            "",
            f"  {'Binary':<35} {'Exports':>7} {'Imports':>7} {'Edges':>7}",
            f"  {'-'*35} {'-------':>7} {'-------':>7} {'-------':>7}",
        ]
        for name in sorted(self._contexts.keys()):
            ctx = self._contexts[name]
            lines.append(
                f"  {name:<35} {len(ctx.exports):>7} {len(ctx.plt):>7} {len(ctx.call_edges):>7}"
            )
        return "\n".join(lines)

    # ── index build ───────────────────────────────────────────────────────────

    def _build_indices(self) -> None:
        # Export index: symbol -> [(binary_name, va)]
        for name, ctx in self._contexts.items():
            self._exports[name] = sorted(ctx.exports.keys())
            for sym, va in ctx.exports.items():
                self._defined.setdefault(sym, []).append((name, va))

        # Import index: binary_name -> [symbol_name] (sorted unique PLT entries)
        for name, ctx in self._contexts.items():
            self._imports[name] = sorted(set(ctx.plt.values()))

        # Caller index: symbol -> [LibCaller]
        for bin_name, ctx in self._contexts.items():
            for from_va, to_va, label in ctx.call_edges:
                if not label:
                    label = ctx.plt.get(to_va, "")
                if not label:
                    continue
                fn_name = ctx._va_name(from_va)
                caller = LibCaller(
                    binary=bin_name,
                    binary_path=ctx.path,
                    caller_va=from_va,
                    call_site_va=from_va,
                    fn_name=fn_name,
                )
                self._callers.setdefault(label, []).append(caller)

        # Deduplicate callers per symbol (same function may appear multiple times
        # in call_edges if it calls the same symbol more than once)
        for sym in self._callers:
            seen: Set[Tuple[str, int]] = set()
            deduped = []
            for c in self._callers[sym]:
                key = (c.binary, c.caller_va)
                if key not in seen:
                    seen.add(key)
                    deduped.append(c)
            self._callers[sym] = deduped
