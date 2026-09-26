# Source Code Auditor

Audit any large codebase for security vulnerabilities. Entry point is `SourceAuditCompressor`. The remaining analyzers compose around it.

---

## SourceContext

**File:** `ablation/analyzers/source_ingestion.py`

The ingestion layer. SourceContext is the source analog of BinaryContext: builds a lightweight index over a local or remote git repository and provides the `read()` and `rel()` helpers that all downstream source analyzers consume.

### Build and load

```python
from ablation.analyzers.source_ingestion import SourceContext

# From an existing local clone
ctx = SourceContext.from_path("/tmp/authentik")
print(ctx.summary())

# Clone from remote (shallow)
ctx = SourceContext.from_git("https://github.com/goauthentik/authentik", "/tmp/authentik")
```

### What gets indexed

| Field | Description |
|---|---|
| `repo_root` | `Path` to the repository root |
| `all_files` | Sorted list of all source file `Path` objects (ts, tsx, js, py, rs, go, java, rb, php) |
| `route_files` | Subset identified as HTTP route handlers (framework-aware: Next.js, Express, Flask, FastAPI, Axum) |
| `summary()` | File count by language, route count |

### CLI

```bash
python3 -m ablation.analyzers.source_ingestion /tmp/authentik
python3 -m ablation.analyzers.source_ingestion --clone https://github.com/goauthentik/authentik /tmp/authentik
```

---

## SourceAuditCompressor

**File:** `ablation/analyzers/source_audit_compressor.py`

The core audit tool. Assigns every file a 5-bit security risk profile, groups files into profile buckets, and tells you exactly which files require individual reads versus which can be batch-cleared. Compresses a 2861-file TypeScript codebase to 72 reads (40x reduction) without dropping coverage.

### The 5-bit profile

Each file gets a profile integer (0-31) based on which security signals are present:

| Bit | Weight | Signal | Triggers on |
|---|---|---|---|
| 4 | 16 | `unsafe_render` | `unsafeHTML()`, `innerHTML=`, `dangerouslySetInnerHTML`, `eval()`, `new Function()` |
| 3 | 8 | `href_binding` | Dynamic `href=${...}` attribute binding (Lit/JSX) |
| 2 | 4 | `url_assign` | `window.location.assign()`, `window.open(var)`, `navigateToUrl()` |
| 1 | 2 | `user_data` | API object fields (`.name`, `.email`, `.body`) rendered in templates |
| 0 | 1 | `shared_module` | Reusable base class or shared utility (amplifies risk in other signals) |

### Audit action by profile range

| Profile range | Binary | Signals | Audit action |
|---|---|---|---|
| 16-31 | `1xxxx` | unsafe rendering | **Individual read** (every file) |
| 8-15 | `01xxx` | href binding (no unsafe render) | **Individual read** (every file) |
| 4-7 | `001xx` | URL assignment | **Spot-check** (read a sample) |
| 2-3 | `0001x` | user-data rendering only | **Spot-check** (read a sample) |
| 1 | `00001` | shared module, no sinks | **Batch** (one representative) |
| 0 | `00000` | no signals | **Batch-CLEAN** (one representative) |

### Usage

```python
from ablation.analyzers.source_ingestion import SourceContext
from ablation.analyzers.source_audit_compressor import SourceAuditCompressor

ctx = SourceContext.from_path("/tmp/authentik")
compressor = SourceAuditCompressor.from_context(ctx)
buckets = compressor.compress()

print(compressor.report(buckets))

# Files requiring individual reads (profiles >= 8)
for bucket in compressor.priority_reads(buckets):
    print(f"profile={bucket.profile_str}: {len(bucket.files)} files  [{', '.join(bucket.active_bits)}]")
    for fp in bucket.files:
        print(f"  {fp.rel_path}")

# Spot-check candidates (profiles 2–7)
for bucket in compressor.spot_checks(buckets):
    print(f"profile={bucket.profile_str}: {len(bucket.files)} files")

# Batch-CLEAN candidates (profile 0)
batch = compressor.batch_clean(buckets)
print(f"Batch-CLEAN: {len(batch)} files — read one representative")

# Estimated reads saved
ratio = compressor.compression_ratio(buckets)
print(f"Compression: {ratio:.1%} fewer reads")
```

### Filter by extension

```python
# TypeScript only
files = [f for f in ctx.all_files if f.suffix in {".ts", ".tsx"}]
compressor = SourceAuditCompressor(ctx)
buckets = compressor.compress(files=files)
```

### CLI

```bash
python3 -m ablation.analyzers.source_audit_compressor /tmp/authentik
python3 -m ablation.analyzers.source_audit_compressor /tmp/authentik --ext ts
python3 -m ablation.analyzers.source_audit_compressor /tmp/authentik --profile 8
python3 -m ablation.analyzers.source_audit_compressor /tmp/authentik --show-files
```

---

## SourceEntryClassifier

**File:** `ablation/analyzers/source_entry_classifier.py`

Classifies every HTTP route handler file by its authentication level. Run this before deep reading to build an attack surface map: which endpoints are exposed, which are user-gated, which are admin-only.

### Auth levels (weakest → strongest)

| Level | Constant | Meaning |
|---|---|---|
| `NONE` | `AUTH_NONE` | No authentication check found |
| `API_KEY` | `AUTH_API_KEY` | API key or Basic auth required |
| `SESSION` | `AUTH_SESSION` | User session (cookie or JWT) required |
| `INTERNAL` | `AUTH_INTERNAL` | Service-to-service HMAC / admin key |
| `ADMIN` | `AUTH_ADMIN` | Global admin credential |

### Usage

```python
from ablation.analyzers.source_ingestion import SourceContext
from ablation.analyzers.source_entry_classifier import SourceEntryClassifier

ctx = SourceContext.from_path("/tmp/langfuse")
clf = SourceEntryClassifier.from_context(ctx)
results = clf.classify()
print(clf.report(results))

# Unauthenticated endpoints — highest priority
unauth = [r for r in results if r.auth_level == "NONE"]
```

### CLI

```bash
python3 -m ablation.analyzers.source_entry_classifier /tmp/langfuse
python3 -m ablation.analyzers.source_entry_classifier /tmp/langfuse --level NONE
```

---

## SourceSinkScanner

**File:** `ablation/analyzers/source_sink_scanner.py`

Scans for dangerous sink patterns across a repository: code evaluation, subprocess execution, SSRF, path traversal, and unguarded internal endpoints. Each hit maps to a CWE and severity. A guard-condition detector identifies env-var or conditional gates around sinks and reduces HIGH → MEDIUM for gated findings (e.g., `vm.runInContext` gated by `LANGFUSE_CODE_EVAL_DISPATCHER=insecure-local`).

### Sink classes

| Sink class | CWE | Example patterns |
|---|---|---|
| Code eval | CWE-94 | `vm.runInContext`, `eval()`, `new Function()` |
| Subprocess | CWE-78 | `child_process.exec`, `subprocess.run`, `os.system` |
| SSRF | CWE-918 | `fetch(userInput)`, `axios.get(userParam)` |
| Path traversal | CWE-22 | `fs.readFile(userPath)`, `open(userInput)` |
| Unguarded endpoint | CWE-284 | Admin routes missing auth middleware |

### Usage

```python
from ablation.analyzers.source_sink_scanner import SourceSinkScanner

ctx = SourceContext.from_path("/tmp/langfuse")
scanner = SourceSinkScanner.from_context(ctx)
findings = scanner.scan()
print(scanner.report(findings))

highs = [f for f in findings if f.severity == "HIGH"]
```

### CLI

```bash
python3 -m ablation.analyzers.source_sink_scanner /tmp/langfuse
python3 -m ablation.analyzers.source_sink_scanner /tmp/langfuse --severity HIGH
```

---

## SourceIsolationChecker

**File:** `ablation/analyzers/source_isolation_checker.py`

Finds database queries (Prisma, Mongoose, SQLAlchemy, raw SQL) that fetch or mutate data without scoping to the authenticated tenant (`orgId`, `projectId`, `userId`). A missing tenant scope in a `findUnique` / `findMany` where clause is the highest-yield pattern class in multi-tenant SaaS because it directly enables IDOR and cross-tenant data leaks.

### Usage

```python
from ablation.analyzers.source_isolation_checker import SourceIsolationChecker

ctx = SourceContext.from_path("/tmp/langfuse")
checker = SourceIsolationChecker.from_context(ctx)
findings = checker.scan()
print(checker.report(findings))
```

### CLI

```bash
python3 -m ablation.analyzers.source_isolation_checker /tmp/langfuse
python3 -m ablation.analyzers.source_isolation_checker /tmp/langfuse --severity CONFIRMED
```

---

## SourceArchRiskScanner

**File:** `ablation/analyzers/source_arch_risk.py`

Detects "safe now, catastrophic later" architectural patterns: files where unsafe rendering
is co-located with a type-dispatch switch or string-based component selector. These are the
exact patterns developers extend by adding new cases, without realising each new case is a
new rendering path that may bypass shared sanitization.

The risk model: a file with only one signal category is low-risk. A file with both
`unsafe_render` and `type_dispatch` in the same context is high-risk regardless of whether
the current dispatch cases are safe, because future extension is the threat.

### Usage

```python
from ablation.analyzers.source_arch_risk import SourceArchRiskScanner

ctx = SourceContext.from_path("/tmp/authentik")
scanner = SourceArchRiskScanner.from_context(ctx)
findings = scanner.scan()
print(scanner.report(findings))
```

---

## SourceTaintTracker

**File:** `ablation/analyzers/source_taint_tracker.py`

Traces data flows from user-controlled sources (route parameters, query strings, request bodies) through a call graph to dangerous sinks. Produces `TaintPath` objects showing each `TaintHop` in the chain. Source-level analog of `TaintTracker` in binary RE.

### Usage

```python
from ablation.analyzers.source_sink_scanner import SourceSinkScanner
from ablation.analyzers.source_taint_tracker import SourceTaintTracker

ctx = SourceContext.from_path("/tmp/langfuse")

# SourceTaintTracker takes sink_hits from SourceSinkScanner as input
sink_hits = SourceSinkScanner.from_context(ctx).scan()
tracker = SourceTaintTracker.from_context(ctx)
paths = tracker.trace_all(sink_hits)
print(SourceTaintTracker.report(paths, ctx))

# Walk paths manually
for path in paths:
    print(f"{path.sink.rel_path}:{path.sink.line}  [{path.confidence}]")
    for hop in path.hops:
        print(f"  {hop.rel_path}:{hop.line}  {hop.func_name}()")
```

---

## Running a full source audit

All six analyzers compose cleanly. The standard sequence:

```python
from ablation.analyzers.source_ingestion import SourceContext
from ablation.analyzers.source_audit_compressor import SourceAuditCompressor
from ablation.analyzers.source_entry_classifier import SourceEntryClassifier
from ablation.analyzers.source_sink_scanner import SourceSinkScanner
from ablation.analyzers.source_isolation_checker import SourceIsolationChecker

ctx = SourceContext.from_path("/tmp/target")

# 1. Build ranked read list
buckets = SourceAuditCompressor.from_context(ctx).compress()

# 2. Map exposed entry points
entry_results = SourceEntryClassifier.from_context(ctx).classify()
unauth = [r for r in entry_results if r.auth_level == "NONE"]

# 3. Flag dangerous sinks
sink_findings = SourceSinkScanner.from_context(ctx).scan()

# 4. Find tenant isolation gaps
iso_findings = SourceIsolationChecker.from_context(ctx).scan()
```

For the full step-by-step workflow with a worked example, see [Source Code Audit Workflow](../workflows/source-code-audit.md).
