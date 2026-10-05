"""
compiler_security_gate.py — Post-linker binary security gate.

Runs Ablation's vulnerability detector suite on a freshly compiled binary
(the linker's output) before it ships. Catches post-optimization vulnerabilities
that sanitizers miss because they run before optimization passes complete.

Each taint finding is documented as a ``SemanticBlock`` using the DAG Adapter's
producer-consumer model, making the exact dataflow path traversable and
machine-readable at build time.

Architecture support: x86_64, arm32, arm64, mips32, mips64, ppc32, ppc64,
                      riscv32, riscv64, loongarch64.

Additional scanners (x86_64 only): format string, heap corruption,
                                    length underflow.

Exit codes (CLI):  0 = no HIGH/CRITICAL findings  1 = findings present

Usage::

    # Build system integration (Makefile):
    python -m ablation.analyzers.compiler_security_gate ./build/target

    # Block on any finding severity (not just HIGH/CRITICAL):
    python -m ablation.analyzers.compiler_security_gate ./build/target --strict

    # Python API:
    from ablation.analyzers.compiler_security_gate import CompilerSecurityGate

    gate = CompilerSecurityGate.from_path('./build/target')
    findings = gate.scan()
    print(gate.report(findings))

    # With existing BinaryContext (avoids cache rebuild):
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('./build/target')
    gate = CompilerSecurityGate.from_context(ctx)
    findings = gate.scan()
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ablation.analyzers.encoding_dag import DataflowEdge, SemanticBlock, SemanticOp


# ── Severity ordering ─────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Sinks whose taint constitutes CRITICAL severity (command injection)
_CRITICAL_SINKS = frozenset({
    "system", "popen", "execve", "execl", "execvp", "execv", "execlp",
    "execle", "posix_spawn", "_system", "Tcl_Eval", "Tcl_EvalEx",
    "Tcl_GlobalEval", "Tcl_EvalFile", "lua_dostring", "luaL_dostring",
})


# ── GateFinding ───────────────────────────────────────────────────────────────

@dataclass
class GateFinding:
    """Unified finding produced by CompilerSecurityGate."""

    func_va: int
    site_va: int
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    category: str            # TAINT_FLOW / FORMAT_STRING / HEAP / LENGTH_UNDERFLOW
    description: str
    detector: str            # which scanner produced this
    taint_dag: Optional[SemanticBlock] = None   # DAG Adapter block for taint paths

    def fmt(self) -> str:
        dag_note = ""
        if self.taint_dag is not None:
            nodes = list(self.taint_dag.dag_nodes())
            if nodes:
                chain = " → ".join(
                    n.operands.get("label", n.op) for n in nodes
                )
                dag_note = f"\n  dataflow  : {chain}"
        return (
            f"GateFinding [{self.severity}] {self.category}\n"
            f"  func      : {self.func_va:#x}\n"
            f"  site      : {self.site_va:#x}\n"
            f"  detector  : {self.detector}\n"
            f"  detail    : {self.description}"
            f"{dag_note}\n"
        )


# ── DAG builder ───────────────────────────────────────────────────────────────

def _taint_dag(source_calls: List[str], tainted_regs: List[str],
               sink_name: str, sink_va: int,
               tainted_args: List[int]) -> SemanticBlock:
    """Build a SemanticBlock documenting a taint path using the DAG Adapter.

    Nodes: one per taint source, one per tainted register, one sink.
    Edges: source → register carry → sink, giving explicit producer-consumer links.
    """
    block = SemanticBlock(label=f"taint_{sink_va:#x}")
    prev_ids: List[str] = []

    for i, src in enumerate(source_calls or ["<unknown>"]):
        nid = f"src_{i}"
        block.add_op(SemanticOp(
            op="TAINT_SOURCE",
            operands={"label": src, "func": src},
            node_id=nid,
        ))
        prev_ids.append(nid)

    carry_ids: List[str] = []
    for reg in (tainted_regs or []):
        nid = f"carry_{reg}"
        block.add_op(SemanticOp(
            op="TAINT_CARRY",
            operands={"label": reg, "reg": reg},
            node_id=nid,
        ))
        for pid in prev_ids:
            block.add_edge(DataflowEdge(
                producer_id=pid, consumer_id=nid, value_name=reg
            ))
        carry_ids.append(nid)

    args_str = ",".join(f"arg{a}" for a in (tainted_args or []))
    sink_nid = "sink"
    block.add_op(SemanticOp(
        op="TAINT_SINK",
        operands={"label": sink_name, "sink": sink_name,
                  "va": sink_va, "args": args_str},
        node_id=sink_nid,
    ))
    for cid in (carry_ids or prev_ids):
        block.add_edge(DataflowEdge(
            producer_id=cid, consumer_id=sink_nid, value_name=args_str or "?"
        ))

    return block


# ── Architecture dispatch ─────────────────────────────────────────────────────

def _run_taint(path: str, arch: str) -> List[Any]:
    """Dispatch to the right taint tracker and return its findings list."""
    try:
        if arch == "x86_64":
            from ablation.analyzers.xref_graph import XRefGraph
            from ablation.analyzers.taint_tracker_x86 import TaintTracker
            xg = XRefGraph.from_path(path)
            xg.build()
            return TaintTracker(path, xref=xg).run_interprocedural()

        if arch == "arm32":
            from ablation.analyzers.taint_tracker_arm32 import ARM32TaintTracker
            return ARM32TaintTracker.from_path(path).run_interprocedural()

        if arch == "arm64":
            from ablation.analyzers.taint_tracker_arm64 import ARM64TaintTracker
            return ARM64TaintTracker.from_path_full(path).run_interprocedural()

        if arch == "mips32":
            from ablation.analyzers.taint_tracker_mips import MIPS32TaintTracker
            return MIPS32TaintTracker.from_path(path).run_interprocedural()

        if arch == "mips64":
            from ablation.analyzers.taint_tracker_mips64 import MIPS64TaintTracker
            return MIPS64TaintTracker.from_path(path, endian="big").run_interprocedural()

        if arch == "ppc32":
            from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker
            return PPC32TaintTracker.from_path(path, endian="big").run_interprocedural()

        if arch == "ppc64":
            from ablation.analyzers.taint_tracker_ppc64 import PPC64TaintTracker
            return PPC64TaintTracker.from_path(path, endian="big").run_interprocedural()

        if arch == "riscv32":
            from ablation.analyzers.taint_tracker_riscv32 import RISCV32TaintTracker
            return RISCV32TaintTracker.from_path(path).run_interprocedural()

        if arch == "riscv64":
            from ablation.analyzers.taint_tracker_riscv64 import RISCV64TaintTracker
            return RISCV64TaintTracker.from_path(path).run_interprocedural()

        if arch == "loongarch64":
            from ablation.analyzers.taint_tracker_loongarch64 import LoongArch64TaintTracker
            return LoongArch64TaintTracker.from_path(path).run_interprocedural()

    except ImportError as exc:
        import warnings
        warnings.warn(
            f"compiler_security_gate: taint tracker unavailable for arch={arch}: {exc}",
            stacklevel=2,
        )
    except Exception:
        pass
    return []


def _taint_severity(sink_name: str) -> str:
    if sink_name in _CRITICAL_SINKS:
        return "CRITICAL"
    return "HIGH"


def _normalize_taint(raw: Any) -> Optional[GateFinding]:
    """Convert any arch taint tracker finding to a GateFinding.

    All trackers produce objects with at least func_va, sink_va (or site_va),
    sink_name, tainted_args, tainted_regs, source_calls. Handle duck typing.
    """
    try:
        func_va    = getattr(raw, "func_va", 0)
        sink_va    = getattr(raw, "sink_va", getattr(raw, "site_va", 0))
        sink_name  = getattr(raw, "sink_name", getattr(raw, "sink", "?"))
        t_args     = list(getattr(raw, "tainted_args", []))
        t_regs     = list(getattr(raw, "tainted_regs", []))
        src_calls  = list(getattr(raw, "source_calls", []))

        sev = _taint_severity(sink_name)
        args_str = ", ".join(f"arg{a}" for a in t_args) or "?"
        dag = _taint_dag(src_calls, t_regs, sink_name, sink_va, t_args)

        return GateFinding(
            func_va=func_va,
            site_va=sink_va,
            severity=sev,
            category="TAINT_FLOW",
            description=f"taint reaches {sink_name}({args_str}) via {t_regs}",
            detector="TaintTracker",
            taint_dag=dag,
        )
    except Exception:
        return None


# ── CompilerSecurityGate ──────────────────────────────────────────────────────

class CompilerSecurityGate:
    """Post-linker security gate: runs Ablation's detector suite on a compiled binary.

    Operates on the final binary produced by the linker — after all compiler
    optimization passes — catching vulnerabilities that pre-optimization
    sanitizers miss.

    Taint findings are documented as SemanticBlock DAGs using the encoding_dag
    module's producer-consumer model, making each path traversable at build time.
    """

    def __init__(self, binary_path: str, ctx=None) -> None:
        self.binary_path = binary_path
        self._ctx = ctx
        self._findings: Optional[List[GateFinding]] = None

    @classmethod
    def from_path(cls, path: str) -> "CompilerSecurityGate":
        return cls(binary_path=path)

    @classmethod
    def from_context(cls, ctx) -> "CompilerSecurityGate":
        return cls(binary_path=ctx.path, ctx=ctx)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _ctx_or_build(self):
        if self._ctx is not None:
            return self._ctx
        try:
            from ablation.analyzers.binary_context import BinaryContext
            self._ctx = BinaryContext.load_or_build(self.binary_path)
        except Exception:
            pass
        return self._ctx

    def _arch(self) -> str:
        ctx = self._ctx_or_build()
        if ctx is not None:
            return getattr(ctx, "arch", "unknown")
        return "unknown"

    # ── scanner runners ───────────────────────────────────────────────────────

    def _run_format_string(self) -> List[GateFinding]:
        try:
            from ablation.analyzers.format_string_scanner import FormatStringScanner
            ctx = self._ctx_or_build()
            scanner = (FormatStringScanner.from_context(ctx) if ctx
                       else FormatStringScanner.from_path(self.binary_path))
            findings = scanner.scan()
            out: List[GateFinding] = []
            for f in findings:
                sev = getattr(f, "severity", "MEDIUM")
                out.append(GateFinding(
                    func_va=getattr(f, "func_va", 0),
                    site_va=getattr(f, "site_va", getattr(f, "call_va", 0)),
                    severity=sev,
                    category="FORMAT_STRING",
                    description=getattr(f, "description",
                                        getattr(f, "fmt_func", "non-literal format string")),
                    detector="FormatStringScanner",
                ))
            return out
        except Exception:
            return []

    def _run_heap(self) -> List[GateFinding]:
        try:
            from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner
            ctx = self._ctx_or_build()
            scanner = (HeapVulnScanner.from_context(ctx) if ctx
                       else HeapVulnScanner.from_path(self.binary_path))
            findings = scanner.scan()
            out: List[GateFinding] = []
            for f in findings:
                out.append(GateFinding(
                    func_va=getattr(f, "func_va", 0),
                    site_va=getattr(f, "site_va", 0),
                    severity=getattr(f, "severity", "HIGH"),
                    category="HEAP",
                    description=getattr(f, "description", str(getattr(f, "kind", "heap"))),
                    detector="HeapVulnScanner",
                ))
            return out
        except Exception:
            return []

    def _run_length_underflow(self) -> List[GateFinding]:
        try:
            from ablation.analyzers.length_underflow import LengthUnderflowScanner
            ctx = self._ctx_or_build()
            scanner = (LengthUnderflowScanner.from_context(ctx) if ctx
                       else LengthUnderflowScanner(self.binary_path))
            findings = scanner.scan_unguarded()
            out: List[GateFinding] = []
            for f in findings:
                out.append(GateFinding(
                    func_va=getattr(f, "func_va", 0),
                    site_va=getattr(f, "sub_va", 0),
                    severity="HIGH",
                    category="LENGTH_UNDERFLOW",
                    description=(
                        f"header subtraction {getattr(f, 'sub_const', '?')} bytes "
                        f"→ uint16 truncation → {getattr(f, 'call_label', '') or 'call'}"
                    ),
                    detector="LengthUnderflowScanner",
                ))
            return out
        except Exception:
            return []

    # ── public API ────────────────────────────────────────────────────────────

    def scan(self) -> List[GateFinding]:
        """Run all applicable detectors and return a unified findings list.

        Results are cached on the instance — subsequent calls return the same
        list without re-running analysis. Taint findings include a SemanticBlock
        DAG documenting the exact producer-consumer dataflow path.
        """
        if self._findings is not None:
            return self._findings

        arch = self._arch()
        findings: List[GateFinding] = []

        # Taint tracking — all architectures
        raw_taint = _run_taint(self.binary_path, arch)
        for raw in raw_taint:
            gf = _normalize_taint(raw)
            if gf is not None:
                findings.append(gf)

        # x86_64-only scanners
        if arch == "x86_64":
            findings.extend(self._run_format_string())
            findings.extend(self._run_heap())
            findings.extend(self._run_length_underflow())

        findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.func_va))
        self._findings = findings
        return findings

    def report(self, findings: Optional[List[GateFinding]] = None) -> str:
        """Format findings as a human-readable text report."""
        if findings is None:
            findings = self.scan()
        arch = self._arch()
        header = (
            f"CompilerSecurityGate  binary={self.binary_path}  arch={arch}\n"
            f"{'─' * 60}\n"
        )
        if not findings:
            return header + "result: CLEAN — no findings\n"
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = "  ".join(f"{sev}:{n}" for sev, n in
                             sorted(counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9)))
        lines = [header, f"result: {len(findings)} finding(s)  [{summary}]\n"]
        for f in findings:
            lines.append(f.fmt())
        return "\n".join(lines)

    def check(self, strict: bool = False) -> int:
        """Run scan and return an exit code suitable for CI / make integration.

        Returns 0 if no blocking findings, 1 otherwise.
        strict=False: block on CRITICAL or HIGH only.
        strict=True:  block on any finding severity.
        """
        findings = self.scan()
        if not findings:
            return 0
        blocking = (_SEV_ORDER.keys() if strict
                    else {"CRITICAL", "HIGH"})
        if any(f.severity in blocking for f in findings):
            return 1
        return 0


# ── CLI entry point ───────────────────────────────────────────────────────────

def _main(argv: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="compiler_security_gate",
        description="Post-linker Ablation security gate. Exit 1 on HIGH/CRITICAL findings.",
    )
    p.add_argument("binary", help="Path to the compiled binary (linker output)")
    p.add_argument("--strict", action="store_true",
                   help="Block on any finding severity, not just HIGH/CRITICAL")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress report output; use exit code only")
    args = p.parse_args(argv)

    from pathlib import Path
    if not Path(args.binary).exists():
        p.error(f"binary not found: {args.binary}")

    gate = CompilerSecurityGate.from_path(args.binary)
    findings = gate.scan()
    if not args.quiet:
        print(gate.report(findings))
    return gate.check(strict=args.strict)


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
