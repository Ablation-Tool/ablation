"""
knowledge_graph.py — SQLite-backed RE knowledge graph for Ablation.

Three gaps this closes:

1. Tool selection for a new binary requires reading 3-5 reference docs per session.
   KnowledgeGraph.get_context_for_binary() answers in one call, returning arch-matched
   modules, known gaps, and prior session verdicts.

2. High-fp_rate tool runs on specific architectures are silently discarded.
   AnalysisEvent nodes record every run outcome; get_gap_candidates() surfaces
   patterns that cross the MUSE threshold (fp_rate > 0.3, event_count >= 5).

3. Prior work on similar targets is not surfaced at session start.
   Session and Binary nodes link arch/format/vendor to confirmed findings
   without requiring a grep over re/**/*.py.

Usage::

    from ablation.analyzers.knowledge_graph import KnowledgeGraph

    g = KnowledgeGraph.open()

    # context for an LLM prompt at session start
    ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
    print(ctx)

    # ordered tool list for a task description
    rec = g.get_recommendations_for_task('find stack overflows', arch='ppc32')
    print(rec)

    # record a tool run after it finishes
    event_id = g.add_run('SinkArgClassifier', '/path/to/fw.bin', arch='ppc32',
                         results={'candidates': 5, 'confirmed': 0, 'fp_rate': 1.0,
                                  'root_cause': 'FCode_not_C_stack'})

    # check for gap candidates after several sessions
    gaps = g.get_gap_candidates(fp_threshold=0.3, min_events=5)
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

__all__ = ['KnowledgeGraph']

_DEFAULT_DB = Path.home() / '.ablation' / 'knowledge_graph.db'

# Canonical workflow stage ordering used for tool recommendation sorting.
_WORKFLOW_ORDER = [
    'triage', 'sweep', 'corpus', 'profile', 'classify', 'taint', 'confirm', 'analysis',
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id    TEXT PRIMARY KEY,
    type  TEXT NOT NULL,
    props TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS edges (
    src   TEXT NOT NULL,
    dst   TEXT NOT NULL,
    type  TEXT NOT NULL,
    props TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (src, dst, type)
);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
CREATE INDEX IF NOT EXISTS idx_edges_src  ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst  ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(type);
"""


class KnowledgeGraph:
    """SQLite-backed RE knowledge graph with structured write and query API.

    Storage: ~/.ablation/knowledge_graph.db (outside the repo; regenerable).
    No external dependencies beyond stdlib sqlite3.
    NetworkX can be imported by callers for in-session traversal; this class
    does not require it.
    """

    def __init__(self, con: sqlite3.Connection, db_path: str) -> None:
        self._con = con
        self.db_path = db_path

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def open(cls, db_path: str | None = None) -> 'KnowledgeGraph':
        """Open or create the graph DB. Default: ~/.ablation/knowledge_graph.db."""
        path = Path(db_path) if db_path else _DEFAULT_DB
        path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(str(path))
        con.row_factory = sqlite3.Row
        con.executescript(_SCHEMA)
        con.commit()
        return cls(con, str(path))

    # ── Write API ─────────────────────────────────────────────────────────────

    def add_node(self, node_type: str, node_id: str, props: dict[str, Any]) -> None:
        """Insert or replace a node. Idempotent on id."""
        self._con.execute(
            "INSERT OR REPLACE INTO nodes (id, type, props) VALUES (?, ?, ?)",
            (node_id, node_type, json.dumps(props)),
        )
        self._con.commit()

    def add_edge(
        self,
        src: str,
        dst: str,
        edge_type: str,
        props: dict[str, Any] | None = None,
    ) -> None:
        """Insert or replace an edge. Idempotent on (src, dst, type)."""
        self._con.execute(
            "INSERT OR REPLACE INTO edges (src, dst, type, props) VALUES (?, ?, ?, ?)",
            (src, dst, edge_type, json.dumps(props or {})),
        )
        self._con.commit()

    def add_analysis_event(
        self,
        session_id: str,
        module: str,
        arch: str,
        candidates: int,
        confirmed: int,
        fp_rate: float,
        root_cause: str = '',
    ) -> str:
        """Record one tool run as an AnalysisEvent node. Returns the event id."""
        event_id = f"event://{uuid.uuid4().hex[:12]}"
        props: dict[str, Any] = {
            'session_id': session_id,
            'module': module,
            'arch': arch,
            'candidates': candidates,
            'confirmed': confirmed,
            'fp_rate': fp_rate,
            'root_cause': root_cause,
        }
        self.add_node('AnalysisEvent', event_id, props)
        if session_id:
            self.add_edge(event_id, session_id, 'RECORDS')
        return event_id

    def record_finding(
        self,
        finding_id: str,
        cwe: str,
        va: int | str,
        status: str,
        byte_verified: bool,
        disclosure_status: str,
        session_id: str,
        access_level: str = 'public',
    ) -> None:
        """Record a finding and link it to its session.

        disclosure_status='pre-disclosure' findings are excluded from default
        get_context_for_binary() output (access_level='public' filter).
        """
        props: dict[str, Any] = {
            'cwe': cwe,
            'va': va,
            'status': status,
            'byte_verified': byte_verified,
            'disclosure_status': disclosure_status,
            'access_level': access_level,
        }
        self.add_node('Finding', finding_id, props)
        self.add_edge(finding_id, session_id, 'FOUND_IN')

    def add_run(
        self,
        module_name: str,
        binary_path: str,
        arch: str,
        results: dict[str, Any],
    ) -> str:
        """Record a tool run as an AnalysisEvent. Returns event_id.

        results keys: session_id, candidates, confirmed, fp_rate, root_cause.
        Only add_run() writes AnalysisEvent nodes during a live session;
        callers do not execute SQL directly.
        """
        return self.add_analysis_event(
            session_id=str(results.get('session_id', '')),
            module=module_name,
            arch=arch,
            candidates=int(results.get('candidates', 0)),
            confirmed=int(results.get('confirmed', 0)),
            fp_rate=float(results.get('fp_rate', 0.0)),
            root_cause=str(results.get('root_cause', '')),
        )

    # ── Query API ─────────────────────────────────────────────────────────────

    def get_context_for_binary(
        self,
        arch: str,
        fmt: str,
        vuln_class: str | None = None,
        access_level: str = 'public',
    ) -> str:
        """Return structured context for an LLM prompt given a binary's arch and format.

        Traverses:
          arch → Module nodes (SUPPORTS edges) → sorted by workflow_stage
          arch → KnownGap nodes (json_extract match)
          arch → Session nodes (most recent 5 verdicts)
          vuln_class → Module nodes (DETECTS edges, if provided)

        Finding nodes with disclosure_status='pre-disclosure' are excluded
        when access_level='public' (the default).
        """
        lines: list[str] = []

        modules = self._modules_for_arch(f"arch://{arch}")
        if modules:
            lines.append(f"[MODULES for arch={arch}]")
            for m in modules:
                p = _props(m)
                lines.append(f"  {p.get('name', m['id'])}  [{p.get('workflow_stage', '')}]")
                if p.get('entry_point'):
                    lines.append(f"    entry: {p['entry_point']}")
                if p.get('limitations'):
                    lines.append(f"    limits: {p['limitations']}")
            lines.append("")

        gaps = self._gaps_for_arch(arch)
        if gaps:
            lines.append(f"[KNOWN GAPS for arch={arch}]")
            for g in gaps:
                p = _props(g)
                desc = p.get('description', g['id'])
                lines.append(f"  {desc}")
                if p.get('workaround'):
                    lines.append(f"    workaround: {p['workaround']}")
                if p.get('module_needed'):
                    lines.append(f"    module_needed: {p['module_needed']}")
            lines.append("")

        sessions = self._sessions_for_arch(arch)
        if sessions:
            lines.append(f"[PRIOR SESSIONS for arch={arch}]")
            for s in sessions:
                p = _props(s)
                verdict = p.get('verdict', '?')
                tools = p.get('tool_sequence', [])
                date = p.get('date', '')
                lines.append(f"  {s['id']}  date={date}  verdict={verdict}  tools={tools}")
            lines.append("")

        if vuln_class:
            vc_modules = self._modules_for_vuln_class(f"vuln://{vuln_class}")
            if vc_modules:
                lines.append(f"[MODULES for vuln_class={vuln_class}]")
                for m in vc_modules:
                    p = _props(m)
                    lines.append(f"  {p.get('name', m['id'])}")
                lines.append("")

        if not lines:
            return f"[No graph context for arch={arch} fmt={fmt}]"
        return "\n".join(lines)

    def get_recommendations_for_task(
        self,
        task_description: str,
        arch: str | None = None,
    ) -> str:
        """Return an ordered tool sequence sorted by workflow_stage.

        If arch is provided, filters to modules that SUPPORTS that arch.
        Otherwise returns all Module nodes in workflow_stage order.
        The task_description is currently used as a label only; semantic
        filtering requires a vector index (Phase 4).
        """
        if arch:
            modules = self._modules_for_arch(f"arch://{arch}")
        else:
            rows = self._con.execute(
                "SELECT * FROM nodes WHERE type='Module' LIMIT 50"
            ).fetchall()
            modules = list(rows)

        modules = sorted(modules, key=_stage_sort_key)

        lines = [f"[RECOMMENDED TOOL SEQUENCE — {task_description}]"]
        for i, m in enumerate(modules, 1):
            p = _props(m)
            name = p.get('name', m['id'])
            stage = p.get('workflow_stage', '')
            entry = p.get('entry_point', '')
            lines.append(f"  {i}. {name}  [{stage}]")
            if entry:
                lines.append(f"     {entry}")
        return "\n".join(lines)

    def get_gap_candidates(
        self,
        fp_threshold: float = 0.3,
        min_events: int = 5,
    ) -> list[dict[str, Any]]:
        """Return modules whose avg fp_rate exceeds fp_threshold over >= min_events runs.

        These are MUSE candidates: modules that frequently fail on a specific
        architecture but have no KnownGap node yet. Callers should create a
        KnownGap node and HAS_GAP edge for each returned entry.
        """
        rows = self._con.execute(
            "SELECT props FROM nodes WHERE type='AnalysisEvent'"
        ).fetchall()

        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for r in rows:
            try:
                p = json.loads(r['props'])
            except (json.JSONDecodeError, TypeError):
                continue
            key = (str(p.get('module', '')), str(p.get('arch', '')))
            groups.setdefault(key, []).append(p)

        candidates: list[dict[str, Any]] = []
        for (module, arch), events in groups.items():
            if len(events) < min_events:
                continue
            avg_fp = sum(float(e.get('fp_rate', 0.0)) for e in events) / len(events)
            if avg_fp < fp_threshold:
                continue
            root_causes = sorted({
                str(e['root_cause'])
                for e in events
                if e.get('root_cause')
            })
            candidates.append({
                'module': module,
                'arch': arch,
                'event_count': len(events),
                'avg_fp_rate': round(avg_fp, 3),
                'root_causes': root_causes,
            })

        return sorted(candidates, key=lambda x: x['avg_fp_rate'], reverse=True)

    # ── Stats helpers ─────────────────────────────────────────────────────────

    def node_count(self, node_type: str | None = None) -> int:
        """Return total nodes, or nodes of a specific type."""
        if node_type:
            row = self._con.execute(
                "SELECT COUNT(*) FROM nodes WHERE type=?", (node_type,)
            ).fetchone()
        else:
            row = self._con.execute("SELECT COUNT(*) FROM nodes").fetchone()
        return int(row[0])

    def edge_count(self, edge_type: str | None = None) -> int:
        """Return total edges, or edges of a specific type."""
        if edge_type:
            row = self._con.execute(
                "SELECT COUNT(*) FROM edges WHERE type=?", (edge_type,)
            ).fetchone()
        else:
            row = self._con.execute("SELECT COUNT(*) FROM edges").fetchone()
        return int(row[0])

    # ── Private helpers ──────────────────────────────────────────────────────

    def _modules_for_arch(self, arch_id: str) -> list[sqlite3.Row]:
        rows = self._con.execute(
            """
            SELECT n.* FROM nodes n
            JOIN edges e ON e.src = n.id
            WHERE n.type = 'Module'
              AND e.type = 'SUPPORTS'
              AND e.dst = ?
            ORDER BY n.id
            """,
            (arch_id,),
        ).fetchall()
        return sorted(rows, key=_stage_sort_key)

    def _gaps_for_arch(self, arch: str) -> list[sqlite3.Row]:
        return self._con.execute(
            """
            SELECT * FROM nodes
            WHERE type = 'KnownGap'
              AND json_extract(props, '$.arch') = ?
            """,
            (arch,),
        ).fetchall()

    def _sessions_for_arch(self, arch: str, limit: int = 5) -> list[sqlite3.Row]:
        return self._con.execute(
            """
            SELECT * FROM nodes
            WHERE type = 'Session'
              AND json_extract(props, '$.arch') = ?
            ORDER BY json_extract(props, '$.date') DESC
            LIMIT ?
            """,
            (arch, limit),
        ).fetchall()

    def _modules_for_vuln_class(self, vc_id: str) -> list[sqlite3.Row]:
        return self._con.execute(
            """
            SELECT n.* FROM nodes n
            JOIN edges e ON e.src = n.id
            WHERE n.type = 'Module'
              AND e.type = 'DETECTS'
              AND e.dst = ?
            """,
            (vc_id,),
        ).fetchall()

    # ── Context manager ──────────────────────────────────────────────────────

    def close(self) -> None:
        self._con.close()

    def __enter__(self) -> 'KnowledgeGraph':
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ── Module-level helpers ──────────────────────────────────────────────────────

def _props(row: sqlite3.Row) -> dict[str, Any]:
    """Decode a node's props JSON, returning {} on any error."""
    try:
        return json.loads(row['props'])  # type: ignore[arg-type]
    except (json.JSONDecodeError, TypeError, KeyError):
        return {}


def _stage_sort_key(row: sqlite3.Row) -> int:
    """Sort key that maps workflow_stage string → integer position."""
    stage = _props(row).get('workflow_stage', '')
    try:
        return _WORKFLOW_ORDER.index(stage)
    except ValueError:
        return len(_WORKFLOW_ORDER)


# ── FORGE gate ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
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
