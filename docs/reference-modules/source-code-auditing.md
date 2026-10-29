<a id="source-dangerous-sink-detection"></a>
# Source Code Security Analysis

Inspect JavaScript, TypeScript, and Python repositories for dangerous operations, nearby guard conditions, and syntactic source-to-sink paths. The tools prioritize human review; they do not turn a pattern match into proof of exploitability.

---

## Why this exists

Large source trees make it difficult to decide which files deserve attention first. A reviewer can search for `eval`, `subprocess`, or `fetch`, but raw search results do not explain severity, nearby guards, or how request input might reach the operation.

`SourceSinkScanner` provides that first inventory. `SourceTaintTracker` then builds a repository call graph and traces selected sink hits toward request-input sources. `SourceAuditCompressor` groups files with similar security profiles so reviewers can choose representative and high-priority files without treating compression as permission to discard the remainder.

These are source-oriented counterparts to binary sink triage. They reuse the same discipline of separating a dangerous operation, input provenance, and a verified security conclusion.

---

## How scanning works

`SourceSinkScanner` applies language-specific sink patterns to source lines. Categories include code evaluation, subprocess execution, server-side request forgery candidates, path traversal, and unguarded internal endpoints. Each match receives a category, CWE, base severity, source location, and nearby context.

The guard check searches a bounded context window for environment-variable and conditional-gate patterns. A recognized guard lowers severity by one level. This is a textual heuristic, not AST proof that the guard dominates the operation or validates its input.

```text
source files
  -> sink-pattern matches
  -> nearby guard classification
  -> prioritized SinkHit objects
  -> optional call-graph taint tracing
  -> manual route, authorization, and data-flow verification
```

The approach works as triage because dangerous APIs and common guard idioms have recognizable spellings. It cannot establish every dynamic call, framework middleware rule, or cross-file transformation from those spellings alone.

---

## Scan a repository

```python
from ablation.analyzers.source_sink_scanner import SourceSinkScanner
from ablation.analyzers.source_ingestion import SourceContext

ctx = SourceContext.from_path('/path/to/repo')
scanner = SourceSinkScanner.from_context(ctx)
findings = scanner.scan()

print(SourceSinkScanner.report(findings, severity_filter='HIGH'))
critical = [f for f in findings if f.severity == 'CRITICAL' and not f.guarded]
for finding in critical:
    print(f'{finding.rel_path}:{finding.line}  {finding.category}  {finding.cwe}')
```

`scan()` returns `SinkHit` objects sorted by severity, path, and line. `report()` is a static method. `SinkHit.as_dict()` provides JSON-compatible output for agent or export workflows.

### Trace sources and prioritize review

```python
from ablation.analyzers.source_taint_tracker import SourceTaintTracker

tracker = SourceTaintTracker.from_context(ctx)
tracker.build()
paths = tracker.trace_all(findings)
print(tracker.report(paths, ctx))
```

A reported taint path shows syntactic source-to-sink connectivity. Route exposure, middleware authorization, type conversions, and framework behavior still require review.

`SourceAuditCompressor` supplies a different view: review ordering rather than a vulnerability path.

```python
from ablation.analyzers.source_audit_compressor import SourceAuditCompressor

compressor = SourceAuditCompressor.from_context(ctx)
buckets = compressor.compress()
print(compressor.report(buckets, show_files=True))
print(compressor.priority_reads(buckets))
```

Use the buckets to select representative and high-priority reads. Do not interpret omission from a priority list as evidence that a file is safe.

---

## Illustrative output

The following illustrates the sink report's meaning rather than output from a particular repository:

```text
[CRITICAL] code-eval  src/eval.ts:42  CWE-95  guarded=False
[MEDIUM]   code-eval  src/local_eval.ts:18  CWE-95  guarded=True
```

The second result is lower severity because a guard pattern was detected nearby. It is not proof that the environment is configured safely or that the guard cannot be bypassed.

---

## What this adds for the user

The three tools provide a graduated workflow from broad inventory to focused review. A user can begin with sink locations, add call-graph evidence where useful, and organize the remaining reading without deploying the target.

They remain separate, composable components rather than one universal source decompiler. New sink rules, framework-aware guards, or richer call-graph models can extend the appropriate layer. A future replacement must preserve the distinction between heuristic severity and verified reachability.

---

## False positives and limitations

- A dangerous API can appear in a string, test, example, or unreachable branch. A constant argument can also be harmless even when the operation is generally dangerous.
- Guard detection uses a bounded textual window. A guard on another line or in another file can be missed; a nearby but ineffective guard can produce an undeserved downgrade.
- Taint paths do not prove route exposure, missing authorization, or attacker control after framework and runtime transformations.
- Compression is a review-ordering aid and does not provide complete file-level safety coverage.
- Verify critical findings against the actual call site, input source, guards, deployment configuration, and runtime behavior where available.

---

## Reading findings

| `SinkHit` field | Content |
|:---|:---|
| `rel_path` | Source file path relative to the repository root |
| `line` | One-based source line number |
| `line_text` | Exact source line containing the match |
| `category` | Sink category such as `code-eval`, `subprocess`, `path-traversal`, or `ssrf` |
| `cwe` | CWE identifier associated with the sink rule |
| `severity` | Severity after guard reduction |
| `base_severity` | Severity before guard reduction |
| `guarded` | Whether a nearby guard pattern was detected |
| `description` | Human-readable explanation of the sink rule |

`path` holds the full `Path` object, while `rel_path` is normally used in reports. There are no `gated`, `file`, or `sink_def` fields on `SinkHit`; those names belonged to an outdated example.

---

## See also

- [Source Code Audit Workflow](../workflows/source-code-audit.md): repository ingestion, compression, prioritized reads, and finding closure
- [Sink Argument Classification](sink-arg-classifier.md): analogous binary sink triage
- [Unauthenticated Attack Surface](preauth-exposure.md): exposure and authorization review after sink discovery
