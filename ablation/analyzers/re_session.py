"""
re_session.py — Automatic KnowledgeGraph write-back for Ablation RE tool runs.

Why this exists:
  1. KnowledgeGraph.add_run() must be called manually after every tool run.
     Manual calls are skipped or forgotten, starving get_gap_candidates() and
     breaking the self-evolution flywheel.
  2. fp_rate for SinkArgClassifier runs is computable from the result verdicts
     but only if someone does the math. Without it, gap detection never fires
     for the most important classifier in the pipeline.
  3. update_confirmed() closes the loop: once TaintTracker or PathSolver
     confirms findings from an earlier classify_all() run, the event record
     gains a real fp_rate rather than staying at 0.0.

Usage::

    from ablation.analyzers.re_session import RESession
    from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
    from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker
    from ablation.analyzers.semantic_search import SemanticSearcher

    with RESession(ctx, arch='ppc32', session_id='session://ibm-iplrom') as s:
        classifications = s.run(SinkArgClassifier)
        paths           = s.run(PPC32TaintTracker)
        hits            = s.run(SemanticSearcher,
                                description='stack overflow in recv', top_k=10)

        # After PathSolver confirms 3 of the TaintTracker paths:
        s.update_confirmed(s.last_event_id(), confirmed=3)
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

from ablation.analyzers.knowledge_graph import KnowledgeGraph

__all__ = ['RESession']

log = logging.getLogger(__name__)

# ── Result extractors ─────────────────────────────────────────────────────────
# Each returns (candidates: int, confirmed: int, fp_rate: float).
#
# For SinkArgClassifier: fp_rate is the fraction eliminated as RODATA_CONST or
# UNICODE_WRAPPER. This is a proxy — the true fp_rate is only known after
# TaintTracker confirmation — but it is the right signal for get_gap_candidates():
# a classifier that eliminates 90% of sinks on ppc32/XCOFF is likely
# misclassifying due to missing PLT resolution, which is a KnownGap candidate.
#
# For all other tools: fp_rate defaults to 0.0 at run time. Callers who later
# confirm findings should call session.update_confirmed() to refine the record.

_FP_VERDICTS = frozenset({'RODATA_CONST', 'UNICODE_WRAPPER'})


def _extract_sink_arg(result: list) -> tuple[int, int, float]:
    if not result:
        return 0, 0, 0.0
    total = len(result)
    fp_count = sum(1 for r in result if getattr(r, 'verdict', '') in _FP_VERDICTS)
    candidates = total - fp_count
    fp_rate = round(fp_count / total, 3)
    return candidates, 0, fp_rate


def _extract_list(result: Any) -> tuple[int, int, float]:
    try:
        return len(result), 0, 0.0
    except TypeError:
        return 1, 0, 0.0


# ── Canonical method + extractor registry ─────────────────────────────────────
# Keyed by class name string to avoid importing every analyzer into this module.

_SINK_ARG_NAMES = frozenset({
    'SinkArgClassifier',
    'SinkArgClassifierPPC32BE',
    'SinkArgClassifierI386',
    'SinkArgClassifierARM32',
    'SinkArgClassifierMIPS',
    'SinkArgClassifierS390X',
    'SinkArgClassifierX8632',
    'SinkArgClassifierPPC64',
    'SinkArgClassifierPPC64ELFv1',
    'SinkArgClassifierPPC64ELFv2',
})

_REGISTRY: dict[str, tuple[str, Callable]] = {
    **{name: ('classify_all', _extract_sink_arg) for name in _SINK_ARG_NAMES},
    'SemanticSearcher': ('query', _extract_list),
    'FuncProfiler': ('profile_many', _extract_list),
    'CorpusBuilder': ('build', _extract_list),
    'PatternLibrary': ('sweep', _extract_list),
}


def _resolve(cls_name: str, method_override: str | None) -> tuple[str, Callable]:
    if method_override:
        extractor = _extract_sink_arg if cls_name in _SINK_ARG_NAMES else _extract_list
        return method_override, extractor
    if cls_name in _REGISTRY:
        return _REGISTRY[cls_name]
    # TaintTracker* family: PPC32TaintTracker, TaintTrackerARM64, etc.
    if 'TaintTracker' in cls_name or cls_name.startswith('PPC32'):
        return 'run', _extract_list
    return 'run', _extract_list


def _instantiate(tool_cls: type, ctx: Any) -> Any:
    if hasattr(tool_cls, 'from_context'):
        return tool_cls.from_context(ctx)
    return tool_cls(ctx.path)


# ── RESession ─────────────────────────────────────────────────────────────────

class RESession:
    """Context manager that wraps tool calls and auto-records outcomes to KnowledgeGraph.

    Every session.run(ToolClass, **kwargs) call:
      1. Instantiates ToolClass via from_context(ctx).
      2. Calls the canonical method (or the method= override).
      3. Extracts candidates / confirmed / fp_rate from the result.
      4. Calls KnowledgeGraph.add_run() with those metrics.
      5. Returns the result unchanged.
    """

    def __init__(
        self,
        ctx: Any,
        arch: str,
        session_id: str,
        graph: KnowledgeGraph | None = None,
    ) -> None:
        self._ctx = ctx
        self._arch = arch
        self._session_id = session_id
        self._g = graph if graph is not None else KnowledgeGraph.open()
        # Each entry: {'event_id': str, 'candidates': int, 'cls_name': str}
        self._events: list[dict[str, Any]] = []

    # ── Primary API ──────────────────────────────────────────────────────────

    def run(
        self,
        tool_cls: type,
        method: str | None = None,
        root_cause: str = '',
        **method_kwargs: Any,
    ) -> Any:
        """Instantiate tool_cls, call method, record result to graph, return result.

        method: override the canonical method name for this tool class.
        root_cause: optional root cause string stored on the AnalysisEvent node.
        **method_kwargs: passed through to the method call.
        """
        cls_name = tool_cls.__name__
        method_name, extractor = _resolve(cls_name, method)

        instance = _instantiate(tool_cls, self._ctx)
        result = getattr(instance, method_name)(**method_kwargs)

        candidates, confirmed, fp_rate = extractor(result)
        binary_path = str(getattr(self._ctx, 'binary_path', getattr(self._ctx, 'path', '')))

        event_id = self._g.add_run(
            module_name=cls_name,
            binary_path=binary_path,
            arch=self._arch,
            results={
                'session_id': self._session_id,
                'candidates': candidates,
                'confirmed': confirmed,
                'fp_rate': fp_rate,
                'root_cause': root_cause,
            },
        )
        self._events.append({'event_id': event_id, 'candidates': candidates, 'cls_name': cls_name})
        log.debug(
            'RESession.run %s → %s  candidates=%d fp_rate=%.3f',
            cls_name, event_id, candidates, fp_rate,
        )
        return result

    def update_confirmed(self, event_id: str, confirmed: int) -> None:
        """Refine a previously recorded event with a confirmed finding count.

        Recomputes fp_rate from the stored candidate count and the new confirmed
        count, then overwrites the AnalysisEvent node. Call this after
        TaintTracker or PathSolver confirms findings from an earlier run().
        """
        entry = next((e for e in self._events if e['event_id'] == event_id), None)
        if entry is None:
            log.warning('RESession.update_confirmed: event %s not in this session', event_id)
            return
        candidates = entry['candidates']
        fp_rate = round((candidates - confirmed) / candidates, 3) if candidates > 0 else 0.0

        row = self._g._con.execute(
            "SELECT props FROM nodes WHERE id=?", (event_id,)
        ).fetchone()
        if not row:
            log.warning('RESession.update_confirmed: event %s not found in graph', event_id)
            return
        props = json.loads(row['props'])
        props['confirmed'] = confirmed
        props['fp_rate'] = fp_rate
        self._g.add_node('AnalysisEvent', event_id, props)

    def last_event_id(self) -> str | None:
        """Return the event_id from the most recent run() call, or None."""
        return self._events[-1]['event_id'] if self._events else None

    def event_ids(self) -> list[str]:
        """Return all event_ids recorded in this session, in call order."""
        return [e['event_id'] for e in self._events]

    def close_session(self, finding_ids: list[str] | None = None) -> str | None:
        """Create a SessionToolChain hyperedge linking session, arch, modules, and findings.

        Call once at session end, after all tool runs and update_confirmed() calls.
        finding_ids: list of Finding node IDs (e.g. ['finding://IBM-001']) confirmed
                     in this session. Defaults to empty.

        Returns the chain_id of the created hyperedge, or None if no tools were run.
        """
        if not self._events:
            return None

        seen: set[str] = set()
        module_ids: list[str] = []
        for e in self._events:
            mid = f"module://{e['cls_name']}"
            if mid not in seen:
                seen.add(mid)
                module_ids.append(mid)

        resolved_findings = finding_ids or []
        member_ids = (
            [self._session_id, f'arch://{self._arch}']
            + module_ids
            + resolved_findings
        )
        roles = (
            ['session', 'arch']
            + ['module'] * len(module_ids)
            + ['finding'] * len(resolved_findings)
        )

        chain_id = f"chain://{self._session_id.replace('session://', '')}"
        self._g.add_hyperedge(
            edge_type='SessionToolChain',
            edge_id=chain_id,
            member_ids=member_ids,
            roles=roles,
            props={
                'session_id': self._session_id,
                'arch': self._arch,
                'tool_count': len(module_ids),
                'confirmed_count': len(resolved_findings),
            },
        )
        log.debug('RESession.close_session → %s  tools=%d  confirmed=%d',
                  chain_id, len(module_ids), len(resolved_findings))
        return chain_id

    # ── Context manager ──────────────────────────────────────────────────────

    def close(self) -> None:
        self._g.close()

    def __enter__(self) -> 'RESession':
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ── FORGE gate ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    from pathlib import Path
    try:
        from ablation.analyzers.forge import FORGE, ForgeAuditRequired
    except ImportError:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from ablation.analyzers.forge import FORGE, ForgeAuditRequired  # type: ignore

    try:
        report = FORGE.audit_module(__file__)
    except ForgeAuditRequired as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)

    if not report.gate_passed:
        print(report.report())
        sys.exit(1)
