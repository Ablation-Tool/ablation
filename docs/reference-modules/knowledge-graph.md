# Knowledge Graph

Query the full Ablation capability set, known analysis gaps, and prior RE session history by architecture and format in one call, before reading any individual reference document.

---

## Why this exists

1. **Tool selection at session start required reading 3 to 5 reference files before picking the first tool.** `BinaryContext` tells you what the binary is. It says nothing about which Ablation tool to run next, which tools fail on that architecture, or whether a similar target has been analyzed before. The analyst had to reconstruct this context from memory or from a grep across the docs directory every session.

2. **High fp_rate tool runs on specific architectures were not recorded.** When `SinkArgClassifier` returned 100% false positives on a stripped PPC32 XCOFF binary because there was no C stack frame, that result was noted in a SESSION markdown file and forgotten. The next session on a similar target ran the same tool and reached the same dead end. `AnalysisEvent` nodes record every run outcome so `get_gap_candidates()` can surface the pattern before the tool runs again.

3. **Prior work on similar targets was invisible at session start.** Thirty-two IBM PReP sessions existed across `re/ibm/`. Knowing which arch variant produced confirmed findings and which tool sequence reached them required grepping `*_re.py` files manually. `Session` and `Finding` nodes make this retrievable in one call.

4. **The 334 capability records in `capabilities.json` had no graph structure.** Each record listed `workflow_stage` and `scope` as flat strings. There was no machine-readable ordering between tools, no SUPPORTS edges from modules to architectures, and no way to ask "which of the 67 vulnerability scanners cover PPC32" without reading each one. The bootstrap script converts those strings into graph edges once and answers the question in a SQL join.

---

## How it works

```mermaid
flowchart TD
    A["KnowledgeGraph.open()"] --> B[SQLite: nodes + edges tables]
    B --> C{query type}
    C -->|get_context_for_binary| D[SUPPORTS edges → Module nodes for arch]
    D --> E[json_extract → KnownGap nodes for arch]
    E --> F[json_extract → Session nodes for arch, most recent 5]
    F --> G[DETECTS edges → Module nodes for vuln_class]
    G --> H[Structured context string for LLM prompt]
    C -->|get_recommendations_for_task| I[Module nodes for arch or all]
    I --> J[Sort by _WORKFLOW_ORDER index]
    J --> K[Ordered tool list with entry_point]
    C -->|get_gap_candidates| L[All AnalysisEvent nodes]
    L --> M[Python-side grouping by module and arch]
    M --> N{event_count >= min_events?}
    N -->|yes| O{avg_fp_rate >= threshold?}
    O -->|yes| P[Gap candidate dict]
    C -->|add_run| Q[add_analysis_event → AnalysisEvent node]
    Q --> R[RECORDS edge to Session node]
```

### Node schema

| Type | ID pattern | Key props |
|---|---|---|
| `Module` | `module://BinaryContext` | name, category, workflow_stage, entry_point, scope, limitations, reference_docs |
| `Architecture` | `arch://ppc32` | name |
| `BinaryFormat` | `format://elf32_no_sections` | name |
| `VulnClass` | `vuln://stack_overflow` | name |
| `KnownGap` | `gap://PPC32_PLT_resolution` | description, arch, blocks_module, workaround, module_needed |
| `Binary` | `binary://sha256[:8]` | path, sha256, arch, vendor, format |
| `Session` | `session://ibm-iplrom` | date, arch, vendor, verdict, tool_sequence, source_file |
| `Finding` | `finding://IBM-IPLROM-001` | cwe, va, status, byte_verified, disclosure_status, access_level |
| `AnalysisEvent` | `event://uuid12` | session_id, module, arch, candidates, confirmed, fp_rate, root_cause |
| `Doc` | `doc://binary-context.md#usage` | module_id, section, text, source_file |

### Edge schema

| Edge | Meaning |
|---|---|
| `Module SUPPORTS Architecture` | This module supports that architecture |
| `Module HANDLES BinaryFormat` | This module handles that binary format |
| `Module DETECTS VulnClass` | This module detects that vulnerability class |
| `Module REQUIRES Module` | Workflow ordering between pipeline stages |
| `Module HAS_GAP KnownGap` | This module fails on this known gap |
| `KnownGap WORKAROUND_IS Module` | This module is the workaround for the gap |
| `Module DOCUMENTED_BY Doc` | This module is documented in this Doc chunk |
| `Binary HAS_ARCH Architecture` | This binary runs on that architecture |
| `Binary HAS_FORMAT BinaryFormat` | This binary has that file format |
| `Session ANALYZED Binary` | This session analyzed that binary |
| `Session USED Module` | This session ran that module |
| `Finding FOUND_IN Session` | This finding came from that session |
| `Finding EXPLOITS VulnClass` | This finding is an instance of that vuln class |
| `AnalysisEvent RECORDS Session` | This event belongs to that session |

### Workflow stage ordering

`get_recommendations_for_task()` sorts all returned modules by this sequence:

```
triage → sweep → corpus → profile → classify → taint → confirm → analysis
```

Modules with unknown `workflow_stage` sort last.

### Pre-disclosure security

`record_finding()` accepts a `disclosure_status` field. Findings with `disclosure_status='pre-disclosure'` are stored in the graph but are not returned by `get_context_for_binary()` when `access_level='public'` (the default). Pass `access_level='internal'` to retrieve pre-disclosure findings.

---

## KnowledgeGraph

```python
from ablation.analyzers.knowledge_graph import KnowledgeGraph

g = KnowledgeGraph.open()                     # default: ~/.ablation/knowledge_graph.db
g = KnowledgeGraph.open('/custom/path.db')    # explicit path
```

### Write API

```python
g.add_node(node_type, node_id, props)         # INSERT OR REPLACE on id
g.add_edge(src, dst, edge_type, props=None)   # INSERT OR REPLACE on (src, dst, type)
g.add_analysis_event(session_id, module, arch, candidates, confirmed, fp_rate, root_cause)
g.record_finding(finding_id, cwe, va, status, byte_verified, disclosure_status, session_id)
g.add_run(module_name, binary_path, arch, results)   # preferred write path in sessions
```

### Query API

```python
ctx  = g.get_context_for_binary(arch, fmt, vuln_class=None, access_level='public', intent='sweep')
ctx, cov = g.get_context_with_coverage(arch, fmt, vuln_class=None, access_level='public', intent='sweep')
rec  = g.get_recommendations_for_task(task_description, arch=None)
gaps = g.get_gap_candidates(fp_threshold=0.3, min_events=5)
```

`intent` controls which sections appear in the context string. Three values are accepted: `'sweep'` is the default and includes all sections; `'confirm'` filters sessions to those with a non-empty verdict; `'version_diff'` omits gaps and sessions. Any other value raises ValueError.

`get_context_with_coverage()` returns a `(context_str, ContextCoverage)` pair. `ContextCoverage` carries `coverage_score` (0.0-1.0), `arch_family_used`, `intent`, and raw counts. Call `cov.sufficient()` to gate graph-informed decisions.

### Gap documentation API

```python
g.add_gap_node(gap_id, arch, description, root_cause='', workaround='',
               module_needed='', supersedes_event_ids=None)
```

Creates a KnownGap node and optionally adds SUPERSEDES edges from the gap to specific AnalysisEvent IDs. Events that are superseded, or whose `root_cause` matches a documented KnownGap for the same arch, are excluded from `get_gap_candidates()` scoring. Use this when you have documented a gap and want prior failing events to stop appearing as candidates.

### Stats

```python
g.node_count()                    # total nodes
g.node_count('Module')            # nodes of specific type
g.edge_count('SUPPORTS')          # edges of specific type
```

---

## Usage

```python
from ablation.analyzers.knowledge_graph import KnowledgeGraph

# Session start: get arch context before picking the first tool
g = KnowledgeGraph.open()
ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
print(ctx)

# Session start: get ordered tool list for a specific task
rec = g.get_recommendations_for_task('find stack overflows', arch='ppc32')
print(rec)

# After each tool run: record the outcome
event_id = g.add_run(
    'SinkArgClassifier',
    '/media/cowboy/research/IBM-RE/IPLROM.image',
    arch='ppc32',
    results={
        'session_id': 'session://ibm-iplrom',
        'candidates': 53,
        'confirmed': 4,
        'fp_rate': 0.92,
        'root_cause': 'XCOFF_no_plt_49_rodata_const',
    },
)

# Record a confirmed finding
g.record_finding(
    finding_id='finding://IBM-IPLROM-NET-001',
    cwe='CWE-121',
    va=0x3208c,
    status='CONFIRMED',
    byte_verified=True,
    disclosure_status='public',
    session_id='session://ibm-iplrom',
)

# Check for gap candidates after several sessions
gaps = g.get_gap_candidates(fp_threshold=0.3, min_events=5)
for g_entry in gaps:
    print(g_entry['module'], g_entry['arch'], g_entry['avg_fp_rate'])
```

Bootstrap before the first session:

```bash
python3 -I sweeps/build_ablation_graph.py --bootstrap
# Adds new modules and sessions without wiping existing data:
python3 -I sweeps/build_ablation_graph.py --sync
```

---

## Example output

```
>>> ctx = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
>>> print(ctx)
[MODULES for arch=ppc32]
  BinaryContext  [triage]
    entry: BinaryContext.load_or_build(path)
  PPC32TaintTracker  [taint]
    entry: PPC32TaintTracker.from_context(ctx).run()
    limits: No PLT on stripped XCOFF32; external calls unresolved
  SinkArgClassifier (PPC32BE)  [classify]
    entry: SinkArgClassifier.from_context(ctx).classify_all()
  ...

[KNOWN GAPS for arch=ppc32]
  PPC32 binaries without PLT — external call targets unresolvable via PLT scan
    workaround: BinaryContext exports (714 named) + WindowAnalyzer manual disasm
    module_needed: PPC32ExternalCallResolver

[PRIOR SESSIONS for arch=ppc32]
  session://ibm-iplrom  date=2026-10-15  verdict=COMPLETE  tools=[]
```

```
>>> gaps = g.get_gap_candidates(fp_threshold=0.3, min_events=5)
>>> gaps
[{'module': 'SinkArgClassifier', 'arch': 'ppc32',
  'event_count': 7, 'avg_fp_rate': 0.88,
  'root_causes': ['XCOFF_no_plt', 'FCode_not_C_stack']}]
```

---

## False positives

**`get_context_for_binary` returns no modules for a valid arch.** This happens when the bootstrap has not been run or when the arch identifier passed by the caller does not match the canonical form in the graph. The canonical forms are: `ppc32`, `ppc64`, `arm64`, `arm32`, `x86_64`, `x86_32`, `mips32`, `mips64`, `riscv32`, `riscv64`, `m88k`, `m68k`, `sh2a`, `sh4`, `loongarch64`. Run `--bootstrap` first, then confirm the arch string matches one of these.

**`get_gap_candidates` returns no results despite known failures.** Results only appear after `add_run()` has been called enough times to cross `min_events`. The default is 5 events per module-arch pair. If you have 4 failing runs and want to surface the pattern earlier, pass `min_events=3`. Events whose `root_cause` matches a documented KnownGap for that arch are also excluded, as are events with SUPERSEDES edges from a KnownGap. If the gap is already documented but events keep disappearing, check that the KnownGap node's `root_cause` field matches the event's `root_cause` string exactly.

**Session nodes show `verdict=''` for sessions that completed.** The session parser reads `**Status:**` from SESSION markdown files. Sessions that record status on a line without that exact prefix will not parse the verdict field. Edit the SESSION file to match the format or call `add_node` directly to set the verdict.

---

## Pipeline position

**Before this module:** Run `build_ablation_graph.py --bootstrap` once to seed the graph from `capabilities.json`. Requires `docs/capability-audit/capabilities.json` and `docs/reference-modules/*.md` in the repo.

**After this module:** All analysis tools. Call `get_context_for_binary()` at session start, before `BinaryContext.load_or_build()`, to select the correct tool sequence. Call `add_run()` after each tool finishes. Call `get_gap_candidates()` at session end to identify modules that need KnownGap entries.

The canonical session start sequence with the graph:

```python
from ablation.analyzers.knowledge_graph import KnowledgeGraph
from ablation.analyzers.binary_context import BinaryContext

g = KnowledgeGraph.open()
ctx_str = g.get_context_for_binary(arch='ppc32', fmt='xcoff32')
# prepend ctx_str to the session prompt

ctx = BinaryContext.load_or_build('/path/to/target')
print(ctx.summary())
```

---

## Reading output

`get_context_for_binary()` returns a plain string. `get_recommendations_for_task()` returns a plain string. `get_gap_candidates()` returns a list of dicts:

| Field | Content |
|:---|:---|
| `module` | Module name as it appears in `capabilities.json` |
| `arch` | Canonical architecture string |
| `event_count` | Number of `AnalysisEvent` records that contributed |
| `avg_fp_rate` | Average false positive rate across those events |
| `root_causes` | Sorted list of distinct root_cause strings recorded |

`record_finding()` stores these fields on a Finding node:

| Field | Content |
|:---|:---|
| `cwe` | CWE identifier, e.g. `CWE-121` |
| `va` | Virtual address of the finding in the binary |
| `status` | `CONFIRMED`, `PLAUSIBLE`, `ELIMINATED` |
| `byte_verified` | `True` if bytes at va were checked against expected encoding |
| `disclosure_status` | `public` or `pre-disclosure` |
| `access_level` | `public` by default; set to `internal` to restrict visibility |

---

## See also

- [Binary Context](binary-context.md): session foundation that KnowledgeGraph context feeds into
- [Semantic Code Search](semantic-search.md): run after KnowledgeGraph selects candidates
- [SinkArgClassifier](sink-arg-classifier.md): classify before TaintTracker; record result with `add_run()`
- [Taint Analysis](taint-analysis.md): run on ARG_PROPAGATED / UNKNOWN sinks surfaced by the graph
- [FindingRegistry](registry.md): persistent finding storage that complements Finding nodes
