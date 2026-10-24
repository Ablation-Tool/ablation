"""
build_ablation_graph.py — Bootstrap and sync the Ablation knowledge graph.

Two modes:
  --bootstrap   Full rebuild from capabilities.json. Wipes existing DB.
  --sync        Incremental: add new modules + new RE session/finding nodes.

Bootstrap steps:
  1. Load docs/capability-audit/capabilities.json (403 records)
  2. Module nodes from all records
  3. scope field → Architecture + BinaryFormat nodes + SUPPORTS/HANDLES edges
  4. workflow_stage → REQUIRES edges between sequential pipeline stages
  5. secondary_tags → VulnClass nodes + DETECTS edges (CWE/vuln-name tags only)
  6. docs/reference-modules/*.md → H2-chunked Doc nodes + DOCUMENTED_BY edges
  7. re/*/SESSION_*.md → Session + Binary nodes
  8. re/*/*.py FINDINGS dicts → Finding nodes + FOUND_IN edges
  9. Hand-crafted KnownGap nodes for documented gaps

Usage:
  python3 -I sweeps/build_ablation_graph.py --bootstrap
  python3 -I sweeps/build_ablation_graph.py --sync
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Always run from the repo root so relative paths work.
_REPO = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO))

from ablation.analyzers.knowledge_graph import KnowledgeGraph  # noqa: E402

_CAPS_JSON = _REPO / 'docs' / 'capability-audit' / 'capabilities.json'
_REF_DOCS = _REPO / 'docs' / 'reference-modules'
_RE_ROOT = _REPO / 're'

# Tags that indicate a VulnClass node should be created.
_VULN_PREFIXES = (
    'CWE-', 'stack_overflow', 'format_string', 'heap_overflow', 'use_after_free',
    'integer_overflow', 'command_injection', 'path_traversal', 'sql_injection',
    'buffer_overflow', 'race_condition', 'null_deref', 'type_confusion',
    'length_underflow', 'oob_read', 'oob_write', 'auth_bypass', 'uninitialized',
)

# Known ISA family patterns, longest-match first. Extracted from scope strings.
_ISA_PATTERNS = [
    # 4-letter or longer families first to avoid partial matches
    (r'loongarch64', 'loongarch64'),
    (r'aarch64', 'arm64'),
    (r'arm64', 'arm64'),
    (r'arm32', 'arm32'),
    (r'arm\b', 'arm32'),
    (r'thumb2', 'arm32'),
    (r'cortex[-_]m', 'arm32'),
    (r'ppc476', 'ppc32'),     # IBM PPC476 is a PPC32 variant
    (r'ppc32', 'ppc32'),
    (r'ppc64', 'ppc64'),
    (r'ppc\b', 'ppc32'),
    (r'powerpc64', 'ppc64'),
    (r'powerpc', 'ppc32'),
    (r'vle\b', 'ppc32'),      # VLE = PPC32 Variable Length Encoding variant
    (r'x86[_\-]64', 'x86_64'),
    (r'amd64', 'x86_64'),
    (r'x64\b', 'x86_64'),
    (r'x86[_\-]32', 'x86_32'),
    (r'i386', 'x86_32'),
    (r'x86\b', 'x86_32'),
    (r'ia[_\-]?64', 'ia64'),
    (r'mips64', 'mips64'),
    (r'mips32', 'mips32'),
    (r'mips\b', 'mips32'),
    (r'risc[-_]?v64', 'riscv64'),
    (r'risc[-_]?v32', 'riscv32'),
    (r'risc[-_]?v\b', 'riscv32'),
    (r'sh[-_]?2a', 'sh2a'),
    (r'sh[-_]?4', 'sh4'),
    (r'm88k', 'm88k'),
    (r'm88000', 'm88k'),
    (r'm68k', 'm68k'),
    (r'68000', 'm68k'),
    (r'tricore', 'tricore'),
    (r'sparc64', 'sparc64'),
    (r'sparc\b', 'sparc'),
    (r'alpha\b', 'alpha'),
    (r'sh2\b', 'sh2'),
    (r'm32r\b', 'm32r'),
    (r'c166\b', 'c166'),
    (r'avr\b', 'avr'),
]
_ISA_RE = [(re.compile(pat, re.I), canon) for pat, canon in _ISA_PATTERNS]

# Scope tokens that indicate a bare architecture vs a format.
_FORMAT_HINTS = ('no_sections', 'no_symbols', 'stripped', 'elf32', 'elf64', 'pe32',
                 'xcoff32', 'xcoff64', 'macho', 'coff', 'bff', 'dex', 'apk', 'ipa')

# Known gaps from CLAUDE.md hard rules + RE session history.
_KNOWN_GAPS = [
    {
        'id': 'gap://PPC32_PLT_resolution',
        'props': {
            'description': 'PPC32 binaries without PLT (XCOFF32, stripped PReP) — external call targets unresolvable via PLT scan',
            'arch': 'ppc32',
            'blocks_module': 'IPRegAnnotator',
            'workaround': 'BinaryContext exports (714 named) + WindowAnalyzer manual disasm',
            'module_needed': 'PPC32ExternalCallResolver',
        },
    },
    {
        'id': 'gap://stripped_Go_function_recovery',
        'props': {
            'description': 'Stripped Go binaries — standard func_starts heuristics miss Go prologue patterns',
            'arch': 'amd64',
            'blocks_module': 'SemanticSearcher',
            'workaround': 'PatternLibrary Go-prologue sweep',
            'module_needed': 'GoFuncDiscovery',
        },
    },
    {
        'id': 'gap://ARM64_pattern_coverage',
        'props': {
            'description': 'ARM64 stripped firmware — limited pattern library vs x86-64/PPC32 coverage',
            'arch': 'arm64',
            'blocks_module': 'PatternLibrary',
            'workaround': 'Manual capstone trace with WindowAnalyzer',
            'module_needed': 'ARM64PatternLibrary',
        },
    },
    {
        'id': 'gap://pyc_bytecode_analysis',
        'props': {
            'description': 'Python .pyc bytecode — no dedicated opcode-level taint analysis',
            'arch': 'python_bytecode',
            'blocks_module': 'TaintTracker',
            'workaround': 'dis module + manual inspection',
            'module_needed': 'PycTaintTracker',
        },
    },
]


# ── Scope tokenizer ───────────────────────────────────────────────────────────

def _parse_scope(scope: str) -> tuple[list[str], list[str]]:
    """Return (arch_ids, format_ids) extracted from a semicolon-delimited scope string.

    Uses regex ISA family matching to extract canonical arch names from compound
    tokens like "PPC32 BE/LE ELF; Cisco IOS/MikroTik" → ['ppc32'].
    Deduplicates results; preserves insertion order.
    """
    seen_archs: set[str] = set()
    archs: list[str] = []
    formats: list[str] = []

    text = re.sub(r'\(.*?\)', ' ', scope)   # drop parentheticals

    for pat, canon in _ISA_RE:
        if pat.search(text) and canon not in seen_archs:
            seen_archs.add(canon)
            archs.append(canon)

    return archs, formats


def _is_vuln_tag(tag: str) -> bool:
    tl = tag.lower().replace('-', '_')
    return any(tl.startswith(p.lower().replace('-', '_')) for p in _VULN_PREFIXES)


# ── Doc chunker ───────────────────────────────────────────────────────────────

def _chunk_ref_doc(path: Path) -> list[tuple[str, str]]:
    """Split a reference .md on H2 headings. Returns [(anchor, text)]."""
    text = path.read_text(encoding='utf-8', errors='replace')
    chunks: list[tuple[str, str]] = []
    current_anchor = 'intro'
    current_lines: list[str] = []

    for line in text.splitlines():
        m = re.match(r'^## (.+)', line)
        if m:
            if current_lines:
                chunks.append((current_anchor, '\n'.join(current_lines).strip()))
            current_anchor = re.sub(r'\s+', '-', m.group(1).lower().strip())
            current_anchor = re.sub(r'[^a-z0-9\-]', '', current_anchor)
            current_lines = [line]
        else:
            current_lines.append(line)

    if current_lines:
        chunks.append((current_anchor, '\n'.join(current_lines).strip()))

    return chunks


# ── Session parser ────────────────────────────────────────────────────────────

_SESSION_DATE_RE = re.compile(r'\*\*Date:\*\*\s*(\d{4}-\d{2}-\d{2})')
_SESSION_ARCH_RE = re.compile(r'(?:arch|Architecture)[:\s]+([a-zA-Z0-9_\-]+)', re.I)
_SESSION_VENDOR_RE = re.compile(r'\*\*Target:\*\*\s*[`"]?([^`"\n]+)[`"]?')
_SESSION_STATUS_RE = re.compile(r'\*\*Status:\*\*\s*([^\n]+)')


def _parse_session_md(path: Path) -> dict | None:
    """Extract minimal Session props from a SESSION_*.md file."""
    text = path.read_text(encoding='utf-8', errors='replace')

    date = ''
    m = _SESSION_DATE_RE.search(text)
    if m:
        date = m.group(1)

    arch = ''
    m = _SESSION_ARCH_RE.search(text)
    if m:
        raw = m.group(1).lower().strip()
        archs, _ = _parse_scope(raw)
        arch = archs[0] if archs else raw

    vendor = str(path.parent.name)

    status_match = _SESSION_STATUS_RE.search(text)
    verdict = ''
    if status_match:
        line = status_match.group(1).strip()
        if 'COMPLETE' in line.upper():
            verdict = 'COMPLETE'
        elif 'IN PROGRESS' in line.upper() or 'ACTIVE' in line.upper():
            verdict = 'IN_PROGRESS'

    # derive session id from filename
    stem = path.stem  # SESSION_prep_iplrom → prep_iplrom
    session_key = stem.replace('SESSION_', '')
    session_id = f"session://{vendor}-{session_key}"

    return {
        'id': session_id,
        'props': {
            'date': date,
            'arch': arch,
            'vendor': vendor,
            'verdict': verdict,
            'tool_sequence': [],
            'source_file': str(path.relative_to(_REPO)),
        },
    }


# ── Finding parser ────────────────────────────────────────────────────────────

# Matches: FINDINGS = { 'KEY': { ... } }  or  FINDINGS = {}
_FINDINGS_RE = re.compile(
    r'^FINDINGS\s*=\s*(\{.*?\})\s*(?=#|\Z)', re.DOTALL | re.MULTILINE
)
_FINDING_BLOCK_RE = re.compile(
    r"'([A-Z0-9\-]+)'\s*:\s*\{([^}]*)\}", re.DOTALL
)
_FIELD_RE = re.compile(r"'(\w+)'\s*:\s*(?:'([^']*)'|(\d+)|(True|False)|'(.*?)')")


def _parse_findings_py(path: Path) -> list[dict]:
    """Extract Finding records from a *_re.py FINDINGS dict.

    Returns list of {id, cwe, va, status, byte_verified, disclosure_status, session_id}.
    """
    text = path.read_text(encoding='utf-8', errors='replace')
    findings: list[dict] = []

    m = _FINDINGS_RE.search(text)
    if not m:
        return findings

    vendor = path.parent.name
    target = path.stem.replace('_re', '')

    for fm in _FINDING_BLOCK_RE.finditer(m.group(1)):
        fid_raw = fm.group(1)
        block = fm.group(2)
        props: dict = {}
        for field_m in re.finditer(
            r"['\"](\w+)['\"]\s*:\s*(?:['\"]([^'\"]*)['\"]|(\d+)|(True|False))",
            block,
        ):
            key = field_m.group(1)
            val = field_m.group(2) or field_m.group(3) or field_m.group(4)
            props[key] = val

        finding_id = f"finding://{vendor}-{target}-{fid_raw}"
        status = str(props.get('status', 'UNKNOWN'))
        disclosure = 'public' if status in ('CONFIRMED', 'ELIMINATED') else 'pre-disclosure'

        findings.append({
            'id': finding_id,
            'cwe': str(props.get('cwe', '')),
            'va': str(props.get('va', '')),
            'status': status,
            'byte_verified': str(props.get('byte_verified', 'False')) == 'True',
            'disclosure_status': disclosure,
            'session_id': f"session://{vendor}-{target}",
            'access_level': 'public',
        })

    return findings


# ── Bootstrap ─────────────────────────────────────────────────────────────────

def bootstrap(db_path: str | None = None) -> KnowledgeGraph:
    """Full rebuild. Wipes and recreates the DB from scratch."""
    from ablation.analyzers.knowledge_graph import _DEFAULT_DB
    path = Path(db_path) if db_path else _DEFAULT_DB
    if path.exists():
        path.unlink()
        print(f"[bootstrap] Removed existing DB: {path}")

    g = KnowledgeGraph.open(str(path))

    # ── Step 1-5: capabilities.json → Module + Arch + Format + VulnClass nodes ──
    if not _CAPS_JSON.exists():
        print(f"[bootstrap] WARNING: {_CAPS_JSON} not found — skipping module seed",
              file=sys.stderr)
    else:
        caps = json.loads(_CAPS_JSON.read_text(encoding='utf-8'))
        print(f"[bootstrap] Loaded {len(caps)} capability records")

        # Stage ordering for REQUIRES edges
        stage_modules: dict[str, list[str]] = {}

        # Batch into a single transaction for speed
        with g._con:
            for rec in caps:
                name = str(rec.get('name', ''))
                if not name:
                    continue

                module_id = f"module://{name}"
                props = {
                    'name': name,
                    'category': str(rec.get('category', '')),
                    'workflow_stage': str(rec.get('workflow_stage', 'analysis')),
                    'entry_point': str(rec.get('entry_point', '')),
                    'what_it_does': str(rec.get('what_it_does', '')),
                    'scope': str(rec.get('scope', '')),
                    'status': str(rec.get('status', '')),
                    'limitations': str(rec.get('limitations', '')),
                    'reference_docs': rec.get('reference_docs') or [],
                    'dependencies': [d for d in (rec.get('dependencies') or []) if d],
                    'secondary_tags': rec.get('secondary_tags') or [],
                }
                g._con.execute(
                    "INSERT OR REPLACE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                    (module_id, 'Module', json.dumps(props)),
                )

                # Stage → REQUIRES edges (recorded post-loop)
                stage = props['workflow_stage']
                stage_modules.setdefault(stage, []).append(module_id)

                # SUPPORTS (Architecture) + HANDLES (BinaryFormat) edges
                scope = str(rec.get('scope', ''))
                archs, formats = _parse_scope(scope)
                for arch in archs:
                    arch_id = f"arch://{arch}"
                    g._con.execute(
                        "INSERT OR IGNORE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                        (arch_id, 'Architecture', json.dumps({'name': arch})),
                    )
                    g._con.execute(
                        "INSERT OR IGNORE INTO edges (src, dst, type, props) VALUES (?, ?, ?, '{}')",
                        (module_id, arch_id, 'SUPPORTS'),
                    )
                for fmt in formats:
                    fmt_id = f"format://{fmt}"
                    g._con.execute(
                        "INSERT OR IGNORE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                        (fmt_id, 'BinaryFormat', json.dumps({'name': fmt})),
                    )
                    g._con.execute(
                        "INSERT OR IGNORE INTO edges (src, dst, type, props) VALUES (?, ?, ?, '{}')",
                        (module_id, fmt_id, 'HANDLES'),
                    )

                # DETECTS (VulnClass) edges from secondary_tags
                for tag in (rec.get('secondary_tags') or []):
                    if not _is_vuln_tag(str(tag)):
                        continue
                    vc_id = f"vuln://{tag.lower().replace(' ', '_').replace('-', '_')}"
                    g._con.execute(
                        "INSERT OR IGNORE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                        (vc_id, 'VulnClass', json.dumps({'name': tag})),
                    )
                    g._con.execute(
                        "INSERT OR IGNORE INTO edges (src, dst, type, props) VALUES (?, ?, ?, '{}')",
                        (module_id, vc_id, 'DETECTS'),
                    )

            # REQUIRES edges between consecutive stages in canonical ordering
            from ablation.analyzers.knowledge_graph import _WORKFLOW_ORDER
            for i in range(len(_WORKFLOW_ORDER) - 1):
                src_stage = _WORKFLOW_ORDER[i]
                dst_stage = _WORKFLOW_ORDER[i + 1]
                for src_mod in stage_modules.get(src_stage, []):
                    for dst_mod in stage_modules.get(dst_stage, []):
                        g._con.execute(
                            "INSERT OR IGNORE INTO edges (src, dst, type, props) VALUES (?, ?, ?, ?)",
                            (src_mod, dst_mod, 'REQUIRES', json.dumps({'order': i})),
                        )

        print(
            f"[bootstrap] Nodes: {g.node_count()}  "
            f"Modules: {g.node_count('Module')}  "
            f"Arch: {g.node_count('Architecture')}  "
            f"Format: {g.node_count('BinaryFormat')}  "
            f"VulnClass: {g.node_count('VulnClass')}  "
            f"Edges: {g.edge_count()}"
        )

    # ── Step 6: reference-modules/*.md → Doc nodes ────────────────────────────
    if _REF_DOCS.exists():
        doc_count = 0
        with g._con:
            for md_path in sorted(_REF_DOCS.glob('*.md')):
                chunks = _chunk_ref_doc(md_path)
                for anchor, text in chunks:
                    doc_id = f"doc://{md_path.name}#{anchor}"
                    # Find matching module by reference_docs path
                    rel = str(md_path.relative_to(_REPO))
                    rows = g._con.execute(
                        "SELECT id FROM nodes WHERE type='Module' AND props LIKE ?",
                        (f'%{md_path.name}%',),
                    ).fetchall()
                    module_id = rows[0]['id'] if rows else None

                    g._con.execute(
                        "INSERT OR REPLACE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                        (doc_id, 'Doc', json.dumps({
                            'module_id': module_id or '',
                            'section': anchor,
                            'text': text[:2000],  # cap at 2000 chars per chunk
                            'source_file': rel,
                        })),
                    )
                    if module_id:
                        g._con.execute(
                            "INSERT OR IGNORE INTO edges (src, dst, type, props) VALUES (?, ?, ?, '{}')",
                            (module_id, doc_id, 'DOCUMENTED_BY'),
                        )
                    doc_count += 1
        print(f"[bootstrap] Doc nodes: {doc_count}")
    else:
        print(f"[bootstrap] {_REF_DOCS} not found — skipping Doc nodes")

    # ── Step 7: re/*/SESSION_*.md → Session + Binary nodes ───────────────────
    _sync_sessions(g)

    # ── Step 8: re/*/*.py FINDINGS → Finding nodes ────────────────────────────
    _sync_findings(g)

    # ── Step 9: KnownGap nodes ────────────────────────────────────────────────
    with g._con:
        for gap in _KNOWN_GAPS:
            g._con.execute(
                "INSERT OR REPLACE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                (gap['id'], 'KnownGap', json.dumps(gap['props'])),
            )
            # Link gap to the module it blocks
            blocks = gap['props'].get('blocks_module', '')
            if blocks:
                blocker_id = f"module://{blocks}"
                g._con.execute(
                    "INSERT OR IGNORE INTO edges (src, dst, type, props) VALUES (?, ?, ?, '{}')",
                    (blocker_id, gap['id'], 'HAS_GAP'),
                )
    print(f"[bootstrap] KnownGap nodes: {len(_KNOWN_GAPS)}")

    print(
        f"\n[bootstrap] DONE — "
        f"total nodes: {g.node_count()}  total edges: {g.edge_count()}"
    )
    return g


# ── Sync ──────────────────────────────────────────────────────────────────────

def sync(db_path: str | None = None) -> KnowledgeGraph:
    """Incremental sync: add new modules and RE session/finding nodes."""
    g = KnowledgeGraph.open(db_path)
    existing = {
        r['id']
        for r in g._con.execute("SELECT id FROM nodes WHERE type='Module'").fetchall()
    }

    added = 0
    if _CAPS_JSON.exists():
        caps = json.loads(_CAPS_JSON.read_text(encoding='utf-8'))
        with g._con:
            for rec in caps:
                name = str(rec.get('name', ''))
                if not name:
                    continue
                module_id = f"module://{name}"
                if module_id not in existing:
                    g._con.execute(
                        "INSERT OR IGNORE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                        (module_id, 'Module', json.dumps({
                            'name': name,
                            'category': str(rec.get('category', '')),
                            'workflow_stage': str(rec.get('workflow_stage', 'analysis')),
                            'entry_point': str(rec.get('entry_point', '')),
                            'what_it_does': str(rec.get('what_it_does', '')),
                            'scope': str(rec.get('scope', '')),
                            'status': str(rec.get('status', '')),
                            'limitations': str(rec.get('limitations', '')),
                            'reference_docs': rec.get('reference_docs') or [],
                            'dependencies': [d for d in (rec.get('dependencies') or []) if d],
                            'secondary_tags': rec.get('secondary_tags') or [],
                        })),
                    )
                    added += 1

    print(f"[sync] New Module nodes added: {added}")

    _sync_sessions(g)
    _sync_findings(g)

    print(f"[sync] DONE — total nodes: {g.node_count()}  total edges: {g.edge_count()}")
    return g


# ── Shared session/finding sync helpers ──────────────────────────────────────

def _sync_sessions(g: KnowledgeGraph) -> None:
    if not _RE_ROOT.exists():
        return
    count = 0
    with g._con:
        for md_path in _RE_ROOT.rglob('SESSION_*.md'):
            parsed = _parse_session_md(md_path)
            if not parsed:
                continue
            sid = parsed['id']
            existing = g._con.execute(
                "SELECT id FROM nodes WHERE id=?", (sid,)
            ).fetchone()
            if existing:
                continue
            g._con.execute(
                "INSERT OR IGNORE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                (sid, 'Session', json.dumps(parsed['props'])),
            )
            count += 1
    print(f"[sessions] New Session nodes added: {count}")


def _sync_findings(g: KnowledgeGraph) -> None:
    if not _RE_ROOT.exists():
        return
    count = 0
    with g._con:
        for py_path in _RE_ROOT.rglob('*_re.py'):
            findings = _parse_findings_py(py_path)
            for f in findings:
                existing = g._con.execute(
                    "SELECT id FROM nodes WHERE id=?", (f['id'],)
                ).fetchone()
                if existing:
                    continue
                g._con.execute(
                    "INSERT OR IGNORE INTO nodes (id, type, props) VALUES (?, ?, ?)",
                    (f['id'], 'Finding', json.dumps({
                        'cwe': f['cwe'],
                        'va': f['va'],
                        'status': f['status'],
                        'byte_verified': f['byte_verified'],
                        'disclosure_status': f['disclosure_status'],
                        'access_level': f['access_level'],
                    })),
                )
                if f.get('session_id'):
                    g._con.execute(
                        "INSERT OR IGNORE INTO edges (src, dst, type, props) VALUES (?, ?, ?, '{}')",
                        (f['id'], f['session_id'], 'FOUND_IN'),
                    )
                count += 1
    print(f"[findings] New Finding nodes added: {count}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main() -> None:
    parser = argparse.ArgumentParser(
        description='Bootstrap or sync the Ablation knowledge graph'
    )
    parser.add_argument(
        '--bootstrap', action='store_true',
        help='Full rebuild from capabilities.json (wipes existing DB)',
    )
    parser.add_argument(
        '--sync', action='store_true',
        help='Incremental: add new modules + new RE session nodes',
    )
    parser.add_argument(
        '--db', default=None,
        help='Path to knowledge_graph.db (default: ~/.ablation/knowledge_graph.db)',
    )
    args = parser.parse_args()

    if not args.bootstrap and not args.sync:
        parser.print_help()
        sys.exit(1)

    os.chdir(_REPO)

    if args.bootstrap:
        bootstrap(args.db)
    elif args.sync:
        sync(args.db)


if __name__ == '__main__':
    _main()
