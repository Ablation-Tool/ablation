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

import dataclasses
import datetime
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

__all__ = ['KnowledgeGraph', 'GraphSession', 'ContextCoverage', 'SessionQuality', 'VALID_INTENTS']

# Valid intent values for get_context_for_binary() and RESession.
# sweep       — full initial binary sweep; all sections included (default).
# confirm     — confirming a known candidate; sessions filtered to those with a verdict.
# version_diff — cross-version patch comparison; gaps and sessions excluded.
VALID_INTENTS: frozenset[str] = frozenset({'sweep', 'confirm', 'version_diff'})

_DEFAULT_DB = Path.home() / '.ablation' / 'knowledge_graph.db'

# Canonical workflow stage ordering used for tool recommendation sorting.
_WORKFLOW_ORDER = [
    'triage', 'sweep', 'corpus', 'profile', 'classify', 'taint', 'confirm', 'analysis',
]

# Arch-family fallback table.  When a primary arch has no Module nodes, these
# candidates are tried in order.  Only the first candidate with modules is used.
_ARCH_FAMILIES: dict[str, list[str]] = {
    'ppc32':    ['ppc32be', 'powerpc', 'ppc'],
    'ppc32be':  ['ppc32', 'powerpc', 'ppc'],
    'ppc64':    ['ppc64be', 'ppc64le', 'powerpc64'],
    'ppc64be':  ['ppc64', 'ppc64le', 'powerpc64'],
    'ppc64le':  ['ppc64', 'ppc64be', 'powerpc64'],
    'powerpc':  ['ppc32', 'ppc32be', 'ppc'],
    'arm64':    ['aarch64', 'arm64be'],
    'aarch64':  ['arm64', 'arm64be'],
    'arm32':    ['armv7', 'armhf', 'armel', 'arm'],
    'armv7':    ['arm32', 'armhf', 'armel'],
    'mips32':   ['mips', 'mipsel', 'mipsbe'],
    'mips':     ['mips32', 'mipsel', 'mipsbe'],
    'mips64':   ['mips64el', 'mips64be'],
    'x86_64':   ['amd64', 'x64'],
    'amd64':    ['x86_64', 'x64'],
    'i386':     ['x86', 'x86_32', 'i686'],
    's390x':    ['s390', 'ibm390'],
}

# Module-level cache for embedding models (shared across KnowledgeGraph instances in the
# same process so the model loads only once per session).
_EMBED_MODEL_CACHE: dict[str, Any] = {}


@dataclasses.dataclass(frozen=True)
class ContextCoverage:
    """Coverage metadata returned alongside the context string from get_context_with_coverage().

    coverage_score: 0.0–1.0 composite.  Weights: modules 50%, sessions 30%, chains 20%.
    Gaps do not raise the score — knowing what is missing is metadata, not coverage.
    intent: the RE task type that shaped which sections were included.
    """

    arch: str
    arch_family_used: bool
    module_count: int
    gap_count: int
    session_count: int
    chain_count: int
    coverage_score: float
    intent: str = 'sweep'

    def sufficient(self, threshold: float = 0.3) -> bool:
        """True when coverage_score >= threshold.  Default 0.3 ≈ ~2 modules present."""
        return self.coverage_score >= threshold

    def __str__(self) -> str:
        flag = '  [arch-family fallback]' if self.arch_family_used else ''
        return (
            f"coverage={self.coverage_score:.2f}{flag}  intent={self.intent}  "
            f"modules={self.module_count}  gaps={self.gap_count}  "
            f"sessions={self.session_count}  chains={self.chain_count}"
        )


@dataclasses.dataclass(frozen=True)
class SessionQuality:
    """Per-session quality metrics derived from AnalysisEvent nodes.

    tool_efficiency maps module_name → confirmed / candidates for that module
    within this session (undefined / absent when candidates == 0).
    candidates_open = flagged - confirmed - eliminated.
    """

    session_id: str
    tools_run: int
    candidates_flagged: int
    candidates_confirmed: int
    candidates_eliminated: int
    tool_efficiency: dict[str, float]

    @property
    def candidates_open(self) -> int:
        return max(
            0, self.candidates_flagged - self.candidates_confirmed - self.candidates_eliminated
        )

    def __str__(self) -> str:
        eff_str = ', '.join(
            f"{m}={v:.2f}" for m, v in sorted(self.tool_efficiency.items())
        )
        return (
            f"SessionQuality({self.session_id}  "
            f"tools={self.tools_run}  flagged={self.candidates_flagged}  "
            f"confirmed={self.candidates_confirmed}  eliminated={self.candidates_eliminated}  "
            f"open={self.candidates_open}  efficiency={{{eff_str}}})"
        )


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
CREATE TABLE IF NOT EXISTS hyperedges (
    id    TEXT PRIMARY KEY,
    type  TEXT NOT NULL,
    props TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS hyperedge_members (
    hyperedge_id TEXT NOT NULL,
    node_id      TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (hyperedge_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_nodes_type          ON nodes(type);
CREATE INDEX IF NOT EXISTS idx_edges_src           ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst           ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_type          ON edges(type);
CREATE INDEX IF NOT EXISTS idx_hyperedges_type     ON hyperedges(type);
CREATE INDEX IF NOT EXISTS idx_hyperedge_members_node ON hyperedge_members(node_id);
CREATE TABLE IF NOT EXISTS embeddings (
    node_id TEXT PRIMARY KEY,
    model   TEXT NOT NULL,
    vec     BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_embeddings_model ON embeddings(model);
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
        intent: str = 'sweep',
        timestamp: str | None = None,
        parent_event_id: str | None = None,
    ) -> str:
        """Record one tool run as an AnalysisEvent node. Returns the event id.

        parent_event_id: the event that triggered this run (e.g. an SAC event whose
        candidates motivated a TaintTracker call). When provided, a CAUSED_BY edge is
        written from this event to its parent, forming the causal execution chain.
        """
        event_id = f"event://{uuid.uuid4().hex[:12]}"
        props: dict[str, Any] = {
            'session_id': session_id,
            'module': module,
            'arch': arch,
            'candidates': candidates,
            'confirmed': confirmed,
            'fp_rate': fp_rate,
            'root_cause': root_cause,
            'intent': intent,
            'timestamp': timestamp or datetime.datetime.utcnow().isoformat(),
        }
        self.add_node('AnalysisEvent', event_id, props)
        if session_id:
            self.add_edge(event_id, session_id, 'RECORDS')
        if parent_event_id:
            self.add_edge(event_id, parent_event_id, 'CAUSED_BY')
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
        triggering_module: str | None = None,
    ) -> None:
        """Record a finding and link it to its session.

        disclosure_status='pre-disclosure' findings are excluded from default
        get_context_for_binary() output (access_level='public' filter).

        triggering_module: the module name (not URI) that first flagged this
        finding (e.g. 'SinkArgClassifier'). When provided, module confidence for
        the session's arch is updated automatically — +0.10 for CONFIRMED/BYTE_VERIFIED,
        -0.05 for ELIMINATED/NOT_EXPLOITABLE — implementing a lightweight form of
        semantic backpropagation so future tool ranking reflects observed accuracy.
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

        if triggering_module:
            arch = self._arch_for_session(session_id)
            module_id = f'module://{triggering_module}'
            status_upper = status.upper()
            if status_upper in ('CONFIRMED', 'BYTE_VERIFIED', 'CONFIRMED_HIGH', 'CONFIRMED_MEDIUM'):
                self.update_module_confidence(module_id, arch, +0.10)
            elif status_upper in ('ELIMINATED', 'NOT_EXPLOITABLE', 'SAFE', 'INVALID'):
                self.update_module_confidence(module_id, arch, -0.05)

    def add_run(
        self,
        module_name: str,
        binary_path: str,
        arch: str,
        results: dict[str, Any],
        parent_event_id: str | None = None,
    ) -> str:
        """Record a tool run as an AnalysisEvent. Returns event_id.

        results keys: session_id, candidates, confirmed, fp_rate, root_cause, intent.
        parent_event_id: event whose output motivated this run; creates a CAUSED_BY
        edge so the full causal chain is queryable via get_execution_chain().
        Only add_run() writes AnalysisEvent nodes during a live session.
        """
        return self.add_analysis_event(
            session_id=str(results.get('session_id', '')),
            module=module_name,
            arch=arch,
            candidates=int(results.get('candidates', 0)),
            confirmed=int(results.get('confirmed', 0)),
            fp_rate=float(results.get('fp_rate', 0.0)),
            root_cause=str(results.get('root_cause', '')),
            intent=str(results.get('intent', 'sweep')),
            parent_event_id=parent_event_id,
        )

    # ── Query API ─────────────────────────────────────────────────────────────

    def get_context_for_binary(
        self,
        arch: str,
        fmt: str,
        vuln_class: str | None = None,
        access_level: str = 'public',
        intent: str = 'sweep',
    ) -> str:
        """Return structured context for an LLM prompt given a binary's arch and format.

        intent: RE task type — 'sweep' (default), 'confirm', or 'version_diff'.
          sweep       — all sections; full context for initial binary analysis.
          confirm     — sessions filtered to those with a non-empty verdict.
          version_diff — gaps and sessions omitted; only modules and tool chains.

        Traverses:
          arch → Module nodes (SUPPORTS edges) → sorted by workflow_stage
          arch → KnownGap nodes (json_extract match)  [omitted for version_diff]
          arch → Session nodes (most recent 5 verdicts)  [omitted for version_diff]
          vuln_class → Module nodes (DETECTS edges, if provided)
          arch → SessionToolChain hyperedges (most recent 5)

        If arch has no Module nodes, tries _ARCH_FAMILIES fallback candidates and
        notes the substitution in the returned string.  See get_context_with_coverage()
        for the full (context_str, ContextCoverage) form.
        """
        ctx, _ = self._build_context(arch, fmt, vuln_class, access_level, intent)
        return ctx

    def get_context_with_coverage(
        self,
        arch: str,
        fmt: str,
        vuln_class: str | None = None,
        access_level: str = 'public',
        intent: str = 'sweep',
    ) -> 'tuple[str, ContextCoverage]':
        """Return (context_str, ContextCoverage) for the given arch and format.

        ContextCoverage carries:
          coverage_score: 0.0–1.0 composite (modules 50%, sessions 30%, chains 20%)
          arch_family_used: True when the returned context is for a family arch
          intent: the RE task type that shaped which sections were included
          module_count, gap_count, session_count, chain_count: raw counts

        Use coverage.sufficient() to gate whether to proceed with graph-informed
        decisions or fall back to manual lookup:

            ctx, cov = g.get_context_with_coverage(arch='ppc32', fmt='xcoff32')
            if not cov.sufficient():
                # graph is thin; proceed manually
                ...
        """
        return self._build_context(arch, fmt, vuln_class, access_level, intent)

    def get_recommendations_for_task(
        self,
        task_description: str,
        arch: str | None = None,
    ) -> str:
        """Return an ordered tool sequence for the given task.

        When vector embeddings exist (built with embed_doc_nodes()), returns modules
        ranked by semantic similarity between task_description and their documentation
        chunks — the Phase 4 GraphRAG retrieval path.  Falls back to workflow_stage
        ordering when no embeddings are present or when fastembed/numpy are unavailable.

        If arch is provided, filters the result to modules that SUPPORTS that arch.
        """
        has_embeddings = bool(
            self._con.execute("SELECT 1 FROM embeddings LIMIT 1").fetchone()
        )
        if has_embeddings:
            return self._recommendations_semantic(task_description, arch)
        return self._recommendations_stage_sort(task_description, arch)

    def embed_doc_nodes(self, model_name: str = 'BAAI/bge-small-en-v1.5') -> int:
        """Embed all Doc nodes and store float32 vectors in the embeddings table.

        Requires fastembed: pip install fastembed.
        Idempotent: re-running replaces existing embeddings.
        Uses the same model as SemanticSearcher so cached model weights are shared.
        Returns the number of Doc nodes embedded.
        """
        try:
            import numpy as np
            from fastembed import TextEmbedding
        except ImportError as exc:
            raise ImportError(
                "fastembed and numpy are required for vector retrieval: "
                "pip install fastembed numpy"
            ) from exc

        rows = self._con.execute(
            "SELECT id, props FROM nodes WHERE type='Doc'"
        ).fetchall()

        texts: list[str] = []
        node_ids: list[str] = []
        for row in rows:
            text = _props(row).get('text', '')
            if text:
                texts.append(text)
                node_ids.append(row['id'])

        if not texts:
            return 0

        if model_name not in _EMBED_MODEL_CACHE:
            _EMBED_MODEL_CACHE[model_name] = TextEmbedding(model_name)
        model = _EMBED_MODEL_CACHE[model_name]

        vectors = [np.array(v, dtype='float32') for v in model.embed(texts)]

        self._con.executemany(
            "INSERT OR REPLACE INTO embeddings (node_id, model, vec) VALUES (?, ?, ?)",
            [(nid, model_name, vec.tobytes()) for nid, vec in zip(node_ids, vectors)],
        )
        self._con.commit()
        return len(node_ids)

    def get_gap_candidates(
        self,
        fp_threshold: float = 0.3,
        min_events: int = 5,
    ) -> list[dict[str, Any]]:
        """Return modules whose weighted avg fp_rate exceeds fp_threshold over >= min_events runs.

        Three filters remove already-documented gaps from the results:
          1. Events pointed to by a SUPERSEDES edge from any KnownGap node.
          2. Events whose root_cause matches a documented KnownGap root_cause for the same arch.
        Recency weighting: events older than 30 days receive 50% weight; older than
        90 days receive 10% weight.  Events without a timestamp receive full weight.

        These are MUSE candidates: modules that frequently fail on a specific
        architecture but have no KnownGap node yet. Callers should create a
        KnownGap node and HAS_GAP edge for each returned entry, or call add_gap_node().
        """
        now = datetime.datetime.utcnow()

        # Events explicitly superseded by a KnownGap via SUPERSEDES edge.
        superseded: set[str] = set()
        for row in self._con.execute(
            """
            SELECT e.dst FROM edges e
            JOIN nodes n ON n.id = e.src
            WHERE e.type = 'SUPERSEDES' AND n.type = 'KnownGap'
            """
        ).fetchall():
            superseded.add(row[0])

        # Root causes documented in KnownGap nodes, keyed by arch.
        documented: dict[str, set[str]] = {}
        for row in self._con.execute(
            "SELECT props FROM nodes WHERE type='KnownGap'"
        ).fetchall():
            try:
                p = json.loads(row['props'])
            except (json.JSONDecodeError, TypeError):
                continue
            a = str(p.get('arch', ''))
            rc = str(p.get('root_cause', ''))
            if a and rc:
                documented.setdefault(a, set()).add(rc)

        # Load AnalysisEvent nodes, applying both exclusion filters.
        rows = self._con.execute(
            "SELECT id, props FROM nodes WHERE type='AnalysisEvent'"
        ).fetchall()
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for r in rows:
            if r['id'] in superseded:
                continue
            try:
                p = json.loads(r['props'])
            except (json.JSONDecodeError, TypeError):
                continue
            a = str(p.get('arch', ''))
            rc = str(p.get('root_cause', ''))
            if rc and rc in documented.get(a, set()):
                continue
            key = (str(p.get('module', '')), a)
            groups.setdefault(key, []).append(p)

        candidates: list[dict[str, Any]] = []
        for (module, arch), events in groups.items():
            if len(events) < min_events:
                continue
            total_w = sum(_event_weight(e.get('timestamp', ''), now) for e in events)
            weighted_fp = sum(
                float(e.get('fp_rate', 0.0)) * _event_weight(e.get('timestamp', ''), now)
                for e in events
            )
            avg_fp = weighted_fp / total_w if total_w > 0 else 0.0
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

    def get_execution_chain(self, session_id: str) -> list[dict[str, Any]]:
        """Return the ordered causal chain of tool runs for a session.

        Each dict has: event_id, module, arch, candidates, confirmed, fp_rate,
        timestamp, parent_event_id (or None if the event was the first in the chain).

        Events are ordered by timestamp ascending. CAUSED_BY edges are resolved so
        callers can reconstruct the full DAG: which tool result motivated the next.
        """
        rows = self._con.execute(
            """
            SELECT id, props FROM nodes
            WHERE type = 'AnalysisEvent'
              AND json_extract(props, '$.session_id') = ?
            ORDER BY json_extract(props, '$.timestamp')
            """,
            (session_id,),
        ).fetchall()

        # Build parent lookup from CAUSED_BY edges.
        parent_map: dict[str, str] = {}
        for row in rows:
            parent_row = self._con.execute(
                "SELECT dst FROM edges WHERE src = ? AND type = 'CAUSED_BY' LIMIT 1",
                (row['id'],),
            ).fetchone()
            if parent_row:
                parent_map[row['id']] = parent_row['dst']

        chain = []
        for row in rows:
            try:
                p = json.loads(row['props'])
            except (json.JSONDecodeError, TypeError):
                p = {}
            chain.append({
                'event_id': row['id'],
                'module': p.get('module', ''),
                'arch': p.get('arch', ''),
                'candidates': p.get('candidates', 0),
                'confirmed': p.get('confirmed', 0),
                'fp_rate': p.get('fp_rate', 0.0),
                'timestamp': p.get('timestamp', ''),
                'parent_event_id': parent_map.get(row['id']),
            })
        return chain

    def get_execution_replay(self, finding_id: str) -> list[dict[str, Any]]:
        """Return the full tool chain that produced a given finding.

        Traverses: finding → FOUND_IN → Session → events for that session
        (via get_execution_chain). Returns an empty list if the finding has
        no FOUND_IN edge or its session has no recorded events.
        """
        row = self._con.execute(
            "SELECT dst FROM edges WHERE src = ? AND type = 'FOUND_IN' LIMIT 1",
            (finding_id,),
        ).fetchone()
        if not row:
            return []
        return self.get_execution_chain(row['dst'])

    def evaluate_session(self, session_id: str) -> 'SessionQuality':
        """Compute quality metrics for a session from its AnalysisEvent nodes.

        tool_efficiency[module] = confirmed / candidates when candidates > 0.
        Callers can pass the result to update_module_confidence() to propagate
        session-level accuracy back into the module graph.
        """
        rows = self._con.execute(
            """
            SELECT props FROM nodes
            WHERE type = 'AnalysisEvent'
              AND json_extract(props, '$.session_id') = ?
            """,
            (session_id,),
        ).fetchall()

        tools_run = len(rows)
        total_candidates = 0
        total_confirmed = 0
        per_module_cands: dict[str, int] = {}
        per_module_conf: dict[str, int] = {}

        for row in rows:
            try:
                p = json.loads(row['props'])
            except (json.JSONDecodeError, TypeError):
                continue
            mod = str(p.get('module', 'unknown'))
            cands = int(p.get('candidates', 0))
            conf = int(p.get('confirmed', 0))
            total_candidates += cands
            total_confirmed += conf
            per_module_cands[mod] = per_module_cands.get(mod, 0) + cands
            per_module_conf[mod] = per_module_conf.get(mod, 0) + conf

        # Count eliminated findings (status ELIMINATED / NOT_EXPLOITABLE).
        elim_rows = self._con.execute(
            """
            SELECT COUNT(*) FROM nodes n
            JOIN edges e ON e.src = n.id
            WHERE n.type = 'Finding'
              AND e.type = 'FOUND_IN'
              AND e.dst = ?
              AND (
                json_extract(n.props, '$.status') = 'ELIMINATED'
                OR json_extract(n.props, '$.status') = 'NOT_EXPLOITABLE'
                OR json_extract(n.props, '$.status') = 'SAFE'
                OR json_extract(n.props, '$.status') = 'INVALID'
              )
            """,
            (session_id,),
        ).fetchone()
        total_eliminated = int(elim_rows[0]) if elim_rows else 0

        efficiency: dict[str, float] = {}
        for mod, cands in per_module_cands.items():
            if cands > 0:
                efficiency[mod] = round(per_module_conf.get(mod, 0) / cands, 3)

        return SessionQuality(
            session_id=session_id,
            tools_run=tools_run,
            candidates_flagged=total_candidates,
            candidates_confirmed=total_confirmed,
            candidates_eliminated=total_eliminated,
            tool_efficiency=efficiency,
        )

    def update_module_confidence(
        self,
        module_id: str,
        arch: str,
        delta: float,
    ) -> float:
        """Adjust the confidence score on a Module→Arch SUPPORTS edge by delta.

        Confidence is stored as a float in the SUPPORTS edge props under key
        'confidence', clamped to [0.10, 1.00]. Returns the new confidence value.
        If the SUPPORTS edge does not exist, this is a no-op and returns 0.5.

        Positive delta (+0.10) when the module produced a CONFIRMED finding;
        negative delta (-0.05) when the module flagged a candidate that was
        subsequently ELIMINATED.  Over many sessions this shifts tool ranking so
        modules with demonstrated accuracy for a given arch surface first.
        """
        arch_id = f'arch://{arch}' if not arch.startswith('arch://') else arch
        row = self._con.execute(
            "SELECT props FROM edges WHERE src=? AND dst=? AND type='SUPPORTS'",
            (module_id, arch_id),
        ).fetchone()
        if not row:
            return 0.5

        try:
            props = json.loads(row['props'])
        except (json.JSONDecodeError, TypeError):
            props = {}

        current = float(props.get('confidence', 0.7))
        new_conf = round(max(0.10, min(1.00, current + delta)), 4)
        props['confidence'] = new_conf
        self._con.execute(
            "UPDATE edges SET props=? WHERE src=? AND dst=? AND type='SUPPORTS'",
            (json.dumps(props), module_id, arch_id),
        )
        self._con.commit()
        return new_conf

    def add_gap_node(
        self,
        gap_id: str,
        arch: str,
        description: str,
        root_cause: str = '',
        workaround: str = '',
        module_needed: str = '',
        supersedes_event_ids: list[str] | None = None,
    ) -> None:
        """Create a KnownGap node and optionally add SUPERSEDES edges to AnalysisEvents.

        gap_id: stable identifier, e.g. 'gap://ppc32/xcoff_no_plt'.
        supersedes_event_ids: AnalysisEvent IDs that this gap documents. SUPERSEDES
        edges are added from the gap node to each event so get_gap_candidates()
        excludes them from future gap scoring.
        """
        props: dict[str, Any] = {
            'arch': arch,
            'description': description,
            'root_cause': root_cause,
            'workaround': workaround,
            'module_needed': module_needed,
        }
        self.add_node('KnownGap', gap_id, props)
        for event_id in (supersedes_event_ids or []):
            self.add_edge(gap_id, event_id, 'SUPERSEDES')

    # ── Hyperedge API ─────────────────────────────────────────────────────────

    def add_hyperedge(
        self,
        edge_type: str,
        edge_id: str,
        member_ids: list[str],
        roles: list[str] | None = None,
        props: dict[str, Any] | None = None,
    ) -> None:
        """Insert or replace a hyperedge connecting multiple nodes.

        member_ids: ordered list of node IDs that participate in this edge.
        roles: parallel list of role labels (e.g. 'session', 'arch', 'module',
               'finding'). Defaults to 'member' for all if not provided.
        props: arbitrary metadata stored as JSON on the hyperedge node.
        """
        resolved_roles = roles if roles else ['member'] * len(member_ids)
        if len(resolved_roles) != len(member_ids):
            raise ValueError('roles and member_ids must have the same length')
        self._con.execute(
            "INSERT OR REPLACE INTO hyperedges (id, type, props) VALUES (?, ?, ?)",
            (edge_id, edge_type, json.dumps(props or {})),
        )
        for node_id, role in zip(member_ids, resolved_roles):
            self._con.execute(
                "INSERT OR REPLACE INTO hyperedge_members"
                " (hyperedge_id, node_id, role) VALUES (?, ?, ?)",
                (edge_id, node_id, role),
            )
        self._con.commit()

    def get_hyperedges_for_node(
        self,
        node_id: str,
        edge_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all hyperedges that contain node_id as a member.

        Each result dict has: id, type, props (decoded), members (list of
        {node_id, role} dicts).
        """
        if edge_type:
            rows = self._con.execute(
                """
                SELECT h.id, h.type, h.props FROM hyperedges h
                JOIN hyperedge_members hm ON hm.hyperedge_id = h.id
                WHERE hm.node_id = ? AND h.type = ?
                """,
                (node_id, edge_type),
            ).fetchall()
        else:
            rows = self._con.execute(
                """
                SELECT h.id, h.type, h.props FROM hyperedges h
                JOIN hyperedge_members hm ON hm.hyperedge_id = h.id
                WHERE hm.node_id = ?
                """,
                (node_id,),
            ).fetchall()
        result = []
        for row in rows:
            members = self.get_hyperedge_members(row['id'])
            try:
                p = json.loads(row['props'])
            except (json.JSONDecodeError, TypeError):
                p = {}
            result.append({'id': row['id'], 'type': row['type'], 'props': p, 'members': members})
        return result

    def get_hyperedge_members(self, edge_id: str) -> list[dict[str, str]]:
        """Return all members of a hyperedge as {node_id, role} dicts."""
        rows = self._con.execute(
            "SELECT node_id, role FROM hyperedge_members WHERE hyperedge_id = ?",
            (edge_id,),
        ).fetchall()
        return [{'node_id': r['node_id'], 'role': r['role']} for r in rows]

    def hyperedge_count(self, edge_type: str | None = None) -> int:
        """Return total hyperedges, or hyperedges of a specific type."""
        if edge_type:
            row = self._con.execute(
                "SELECT COUNT(*) FROM hyperedges WHERE type=?", (edge_type,)
            ).fetchone()
        else:
            row = self._con.execute("SELECT COUNT(*) FROM hyperedges").fetchone()
        return int(row[0])

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

    # ── Session factory ──────────────────────────────────────────────────────

    def session(
        self,
        session_id: str,
        arch: str,
        binary_path: str = '',
    ) -> 'GraphSession':
        """Return a GraphSession that pre-fills session_id/arch/binary_path for record() calls.

        Use at RE session start so each tool run only passes the results dict:

            gs = g.session('session://ibm-target', arch='ppc32', binary_path='/path/fw.bin')
            gs.record('SinkArgClassifier', {'candidates': 5, 'confirmed': 1, 'fp_rate': 0.8})
        """
        return GraphSession(kg=self, session_id=session_id, arch=arch, binary_path=binary_path)

    # ── Private helpers ──────────────────────────────────────────────────────

    def _recommendations_stage_sort(
        self, task_description: str, arch: str | None
    ) -> str:
        """Return modules ordered by workflow_stage. Used when no embeddings exist."""
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

    def _recommendations_semantic(
        self, task_description: str, arch: str | None, top_k: int = 15
    ) -> str:
        """Return modules ranked by cosine similarity of task_description to Doc embeddings.

        Traversal: task → embed → cosine-sim vs all Doc embeddings → top-k doc IDs →
        DOCUMENTED_BY edges (Module→Doc, reversed) → Module IDs → arch filter → ranked output.

        Falls back to _recommendations_stage_sort if fastembed/numpy are unavailable or
        no module scores survive the arch filter.
        """
        try:
            import numpy as np
            from fastembed import TextEmbedding
        except ImportError:
            return self._recommendations_stage_sort(task_description, arch)

        model_name = 'BAAI/bge-small-en-v1.5'
        if model_name not in _EMBED_MODEL_CACHE:
            _EMBED_MODEL_CACHE[model_name] = TextEmbedding(model_name)
        model = _EMBED_MODEL_CACHE[model_name]

        query_vec = np.array(next(model.embed([task_description])), dtype='float32')

        rows = self._con.execute("SELECT node_id, vec FROM embeddings").fetchall()
        if not rows:
            return self._recommendations_stage_sort(task_description, arch)

        doc_ids = [r['node_id'] for r in rows]
        dim = query_vec.shape[0]
        flat = b''.join(bytes(r['vec']) for r in rows)
        try:
            matrix = np.frombuffer(flat, dtype='float32').reshape(len(rows), dim)
        except ValueError:
            # Corrupt or mis-dimensioned BLOB in embeddings table; fall back to stage-sort.
            return self._recommendations_stage_sort(task_description, arch)

        # BGE vectors are L2-normalised; dot product equals cosine similarity.
        scores = matrix @ query_vec

        n_top = min(top_k * 4, len(doc_ids))
        top_idx = np.argsort(scores)[::-1][:n_top]

        # Follow DOCUMENTED_BY edges backward: edge src=Module, dst=Doc.
        module_score: dict[str, float] = {}
        for i in top_idx:
            doc_id = doc_ids[int(i)]
            score = float(scores[int(i)])
            for mr in self._con.execute(
                "SELECT src FROM edges WHERE dst=? AND type='DOCUMENTED_BY'",
                (doc_id,),
            ).fetchall():
                mid = mr['src']
                if mid not in module_score or score > module_score[mid]:
                    module_score[mid] = score

        arch_rows: list[Any] = []
        if arch:
            arch_rows = self._modules_for_arch(f'arch://{arch}')
            arch_set = {m['id'] for m in arch_rows}
            module_score = {k: v for k, v in module_score.items() if k in arch_set}

        if not module_score and not arch_rows:
            return self._recommendations_stage_sort(task_description, arch)

        # Semantic results: highest cosine score per module, descending.
        semantic_ranked = sorted(module_score.items(), key=lambda x: x[1], reverse=True)[:top_k]
        semantic_ids = {mid for mid, _ in semantic_ranked}

        # Stage-sorted fill: pad to top_k with arch modules absent from semantic pool.
        fill_rows: list[Any] = []
        if len(semantic_ranked) < top_k:
            if arch:
                candidates = arch_rows
            else:
                candidates = list(self._con.execute(
                    "SELECT * FROM nodes WHERE type='Module' LIMIT 50"
                ).fetchall())
            for row in sorted(candidates, key=_stage_sort_key):
                if len(semantic_ranked) + len(fill_rows) >= top_k:
                    break
                if row['id'] not in semantic_ids:
                    fill_rows.append(row)

        lines = [f"[RECOMMENDED TOOL SEQUENCE — {task_description}]"]
        idx = 1
        for mid, score in semantic_ranked:
            row = self._con.execute("SELECT * FROM nodes WHERE id=?", (mid,)).fetchone()
            if not row:
                continue
            p = _props(row)
            lines.append(
                f"  {idx}. {p.get('name', mid)}  [{p.get('workflow_stage','')}]  score={score:.3f}"
            )
            if p.get('entry_point'):
                lines.append(f"     {p['entry_point']}")
            idx += 1
        for row in fill_rows:
            p = _props(row)
            lines.append(f"  {idx}. {p.get('name', row['id'])}  [{p.get('workflow_stage','')}]")
            if p.get('entry_point'):
                lines.append(f"     {p['entry_point']}")
            idx += 1

        return "\n".join(lines) if len(lines) > 1 else self._recommendations_stage_sort(task_description, arch)

    def _build_context(
        self,
        arch: str,
        fmt: str,
        vuln_class: str | None,
        access_level: str,
        intent: str = 'sweep',
    ) -> 'tuple[str, ContextCoverage]':
        """Build context string and coverage metadata. Used by both public context methods.

        intent routing:
          sweep       — all sections (default).
          confirm     — sessions filtered to those with a non-empty verdict.
          version_diff — gaps and sessions omitted; only modules and tool chains returned.
        """
        if intent not in VALID_INTENTS:
            raise ValueError(
                f"intent must be one of {sorted(VALID_INTENTS)}, got {intent!r}"
            )

        effective_arch, family_used = self._resolve_arch_with_modules(arch)
        lines: list[str] = []

        if intent != 'sweep':
            lines.append(f"[INTENT: {intent}]")
            lines.append("")

        if family_used:
            lines.append(
                f"[NOTE: arch={arch} has no modules; using family arch={effective_arch}]"
            )
            lines.append("")

        modules = self._modules_for_arch(f"arch://{effective_arch}")
        if modules:
            lines.append(f"[MODULES for arch={effective_arch}]")
            for m in modules:
                p = _props(m)
                try:
                    ep = json.loads(m['edge_props'])  # type: ignore[index]
                    conf = ep.get('confidence')
                except (json.JSONDecodeError, TypeError, IndexError, KeyError):
                    conf = None
                conf_str = f"  conf={conf:.2f}" if conf is not None and conf != 0.7 else ''
                lines.append(
                    f"  {p.get('name', m['id'])}  [{p.get('workflow_stage', '')}]{conf_str}"
                )
                if p.get('entry_point'):
                    lines.append(f"    entry: {p['entry_point']}")
                if p.get('limitations'):
                    lines.append(f"    limits: {p['limitations']}")
            lines.append("")

        # Gaps: omitted for version_diff (cross-version diff doesn't need gap context).
        if intent == 'version_diff':
            gaps: list[sqlite3.Row] = []
        else:
            gaps = self._gaps_for_arch(effective_arch)
            if gaps:
                lines.append(f"[KNOWN GAPS for arch={effective_arch}]")
                for g in gaps:
                    p = _props(g)
                    desc = p.get('description', g['id'])
                    lines.append(f"  {desc}")
                    if p.get('workaround'):
                        lines.append(f"    workaround: {p['workaround']}")
                    if p.get('module_needed'):
                        lines.append(f"    module_needed: {p['module_needed']}")
                lines.append("")

        # Sessions: omitted for version_diff; confirm filters to sessions with a verdict.
        if intent == 'version_diff':
            sessions: list[sqlite3.Row] = []
        else:
            all_sessions = self._sessions_for_arch(effective_arch)
            if intent == 'confirm':
                sessions = [s for s in all_sessions if _props(s).get('verdict', '')]
            else:
                sessions = all_sessions
            if sessions:
                lines.append(f"[PRIOR SESSIONS for arch={effective_arch}]")
                now_for_sessions = datetime.datetime.utcnow()
                for s in sessions:
                    p = _props(s)
                    verdict = p.get('verdict', '?')
                    tools = p.get('tool_sequence', [])
                    date = p.get('date', '')
                    tier = _session_recency_tier(date, now_for_sessions)
                    lines.append(
                        f"  [{tier}] {s['id']}  date={date}  verdict={verdict}  tools={tools}"
                    )
                lines.append("")

        if vuln_class:
            vc_modules = self._modules_for_vuln_class(f"vuln://{vuln_class}")
            if vc_modules:
                lines.append(f"[MODULES for vuln_class={vuln_class}]")
                for m in vc_modules:
                    p = _props(m)
                    lines.append(f"  {p.get('name', m['id'])}")
                lines.append("")

        chains = self._chains_for_arch(effective_arch)
        if chains:
            lines.append(f"[TOOL CHAINS for arch={effective_arch}]")
            for chain in chains:
                chain_mods = [
                    mb['node_id'].replace('module://', '')
                    for mb in chain['members']
                    if mb['role'] == 'module'
                ]
                confirmed = sum(1 for mb in chain['members'] if mb['role'] == 'finding')
                session = chain['props'].get('session_id', chain['id'])
                lines.append(f"  {session}  tools={chain_mods}  confirmed={confirmed}")
            lines.append("")

        mc, gc, sc, cc = len(modules), len(gaps), len(sessions), len(chains)
        coverage_score = round(
            0.5 * min(mc / 3, 1.0) +
            0.3 * min(sc / 2, 1.0) +
            0.2 * min(cc / 2, 1.0),
            3,
        )
        coverage = ContextCoverage(
            arch=effective_arch,
            arch_family_used=family_used,
            module_count=mc,
            gap_count=gc,
            session_count=sc,
            chain_count=cc,
            coverage_score=coverage_score,
            intent=intent,
        )
        has_content = bool(modules or gaps or sessions or chains)
        context_str = (
            "\n".join(lines)
            if has_content
            else f"[No graph context for arch={arch} fmt={fmt}]"
        )
        return context_str, coverage

    def _resolve_arch_with_modules(self, arch: str) -> tuple[str, bool]:
        """Return (effective_arch, family_used).

        If arch has no Module nodes, iterates _ARCH_FAMILIES[arch] and returns
        the first candidate that has modules.  Returns (arch, False) if none found.
        """
        if self._modules_for_arch(f'arch://{arch}'):
            return arch, False
        for candidate in _ARCH_FAMILIES.get(arch, []):
            if self._modules_for_arch(f'arch://{candidate}'):
                return candidate, True
        return arch, False

    def _modules_for_arch(self, arch_id: str) -> list[sqlite3.Row]:
        rows = self._con.execute(
            """
            SELECT n.*, e.props as edge_props FROM nodes n
            JOIN edges e ON e.src = n.id
            WHERE n.type = 'Module'
              AND e.type = 'SUPPORTS'
              AND e.dst = ?
            ORDER BY n.id
            """,
            (arch_id,),
        ).fetchall()
        return sorted(rows, key=_confidence_stage_sort_key)

    def _arch_for_session(self, session_id: str) -> str:
        """Return the arch string for a Session node, or '' if not found."""
        row = self._con.execute(
            "SELECT props FROM nodes WHERE id=? AND type='Session'",
            (session_id,),
        ).fetchone()
        if not row:
            return ''
        try:
            return str(json.loads(row['props']).get('arch', ''))
        except (json.JSONDecodeError, TypeError):
            return ''

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

    def _chains_for_arch(self, arch: str, limit: int = 5) -> list[dict[str, Any]]:
        rows = self._con.execute(
            """
            SELECT h.id, h.props FROM hyperedges h
            JOIN hyperedge_members hm ON hm.hyperedge_id = h.id
            WHERE h.type = 'SessionToolChain'
              AND hm.node_id = ?
            ORDER BY json_extract(h.props, '$.date') DESC
            LIMIT ?
            """,
            (f'arch://{arch}', limit),
        ).fetchall()
        result = []
        for row in rows:
            members = self.get_hyperedge_members(row['id'])
            try:
                p = json.loads(row['props'])
            except (json.JSONDecodeError, TypeError):
                p = {}
            result.append({'id': row['id'], 'props': p, 'members': members})
        return result

    # ── Context manager ──────────────────────────────────────────────────────

    def close(self) -> None:
        self._con.close()

    def __enter__(self) -> 'KnowledgeGraph':
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ── GraphSession ──────────────────────────────────────────────────────────────

@dataclasses.dataclass
class GraphSession:
    """Live RE session handle that pre-fills session_id/arch/binary_path for write calls.

    Obtain via KnowledgeGraph.session():

        g = KnowledgeGraph.open()
        gs = g.session('session://ibm-target', arch='ppc32', binary_path='/path/fw.bin')
        ctx = gs.context('xcoff32')                         # get_context_for_binary shortcut
        # ... run BinaryContext, SinkArgClassifier, TaintTracker ...
        event1 = gs.record('SinkArgClassifier', {'candidates': 5, 'confirmed': 1, 'fp_rate': 0.8})
        gs.record('TaintTracker', {'candidates': 3, 'confirmed': 1, 'fp_rate': 0.67})
        # ↑ TaintTracker's event automatically gets a CAUSED_BY edge to event1.
        gs.record_finding('finding://IBM-001', 'CWE-78', 0x1234, 'CONFIRMED', True,
                          'pre-disclosure', triggering_module='SinkArgClassifier')

    Auto-chaining: each record() call stores the returned event_id and passes it as
    parent_event_id to the next call, building the causal chain automatically.
    """

    kg: KnowledgeGraph
    session_id: str
    arch: str
    binary_path: str = ''
    _last_event_id: str = dataclasses.field(default='', init=False, repr=False)

    def record(self, module_name: str, results: dict[str, Any]) -> str:
        """Record a tool run. session_id, arch, binary_path, and causal chain are pre-filled.

        Returns event_id. Automatically sets parent_event_id to the previous event
        in this session so the causal chain is built without any extra caller work.
        """
        event_id = self.kg.add_run(
            module_name,
            self.binary_path,
            self.arch,
            {'session_id': self.session_id, **results},
            parent_event_id=self._last_event_id or None,
        )
        self._last_event_id = event_id
        return event_id

    def record_finding(
        self,
        finding_id: str,
        cwe: str,
        va: int | str,
        status: str,
        byte_verified: bool,
        disclosure_status: str,
        triggering_module: str | None = None,
    ) -> None:
        """Record a finding. session_id is pre-filled.

        triggering_module: the module that first flagged this candidate. When
        provided, module confidence is updated automatically (backpropagation).
        """
        self.kg.record_finding(
            finding_id=finding_id,
            cwe=cwe,
            va=va,
            status=status,
            byte_verified=byte_verified,
            disclosure_status=disclosure_status,
            session_id=self.session_id,
            triggering_module=triggering_module,
        )

    def context(self, fmt: str, **kwargs: Any) -> str:
        """Shortcut for get_context_for_binary() with this session's arch pre-filled."""
        return self.kg.get_context_for_binary(self.arch, fmt, **kwargs)

    def quality(self) -> 'SessionQuality':
        """Return quality metrics for this session. Shortcut for evaluate_session()."""
        return self.kg.evaluate_session(self.session_id)

    def execution_chain(self) -> list[dict[str, Any]]:
        """Return the ordered causal tool chain for this session."""
        return self.kg.get_execution_chain(self.session_id)

    def __enter__(self) -> 'GraphSession':
        return self

    def __exit__(self, *_: object) -> None:
        pass


# ── Module-level helpers ──────────────────────────────────────────────────────

def _event_weight(timestamp_str: str, now: datetime.datetime) -> float:
    """Recency weight for a single AnalysisEvent.

    Events without a timestamp (written before this field existed) receive full
    weight to avoid penalizing existing data.  Age buckets:
      <30 days  → 1.0 (full)
      30–90 days → 0.5 (half)
      >90 days   → 0.1 (marginal)
    """
    if not timestamp_str:
        return 1.0
    try:
        ts = datetime.datetime.fromisoformat(timestamp_str)
        age_days = (now - ts).days
        if age_days < 30:
            return 1.0
        if age_days < 90:
            return 0.5
        return 0.1
    except (ValueError, TypeError):
        return 1.0


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


def _confidence_stage_sort_key(row: sqlite3.Row) -> tuple[int, float]:
    """Sort key: (workflow_stage_index, -confidence).

    Primary: workflow stage order (triage first).
    Secondary: higher confidence sorts first within the same stage.
    When no confidence is stored on the SUPPORTS edge, defaults to 0.7.
    """
    stage_idx = _stage_sort_key(row)
    try:
        edge_props = json.loads(row['edge_props'])  # type: ignore[index]
        confidence = float(edge_props.get('confidence', 0.7))
    except (json.JSONDecodeError, TypeError, IndexError, KeyError):
        confidence = 0.7
    return (stage_idx, -confidence)


def _session_recency_tier(date_str: str, now: datetime.datetime) -> str:
    """Return 'recent' (< 90 days) or 'prior' for a session date string."""
    if not date_str:
        return 'prior'
    try:
        ts = datetime.datetime.fromisoformat(date_str[:10])
        age_days = (now - ts).days
        return 'recent' if age_days < 90 else 'prior'
    except (ValueError, TypeError):
        return 'prior'


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
