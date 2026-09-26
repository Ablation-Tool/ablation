# Source Code Audit Workflow

How to use Ablation's source analyzers to go from a git repository to confirmed,
disclosure-ready findings with minimal wasted reads.

**Time to read list:** under 30 seconds.  
**Time to first confirmed finding:** 30 to 60 minutes.

---

## Overview

```
repository (git clone or local path)
      |
      v
[SourceContext]            -- file index, language detection, route detection
      |
      v
[SourceEntryClassifier]    -- auth-level map of all HTTP entry points
      |
      v
[SourceSinkScanner]        -- dangerous sink hits across entire codebase
      |
      v
[SourceAuditCompressor]    -- 5-bit profile per file → ranked priority buckets
      |
      v
  read list                -- individual reads (profiles 16-31, 8-15)
                              spot checks (profiles 4-7, 2-3)
                              batch close (profiles 0-1)
      |
      v
[manual read]              -- verify the signal; trace it to data origin
      |
      v
  confirmed finding        -- full path: source → transform → sink
                           -- logged to targets/<vendor>/<target>_re.py
```

---

## Phase 1: Context and entry point map (< 5 seconds)

```python
from ablation.analyzers.source_ingestion import SourceContext
from ablation.analyzers.source_entry_classifier import SourceEntryClassifier

ctx = SourceContext.from_path("/tmp/authentik")
print(ctx.summary())
```

Check `summary()` first. It gives file count by language and the number of detected
route handlers. If route count is 0 on a web app, the entry classifier won't produce
useful output — the framework-detection patterns may need extending for that stack.

```python
clf = SourceEntryClassifier.from_context(ctx)
results = clf.classify()
print(clf.report(results))

# Unauthenticated routes first — highest priority
unauth = [r for r in results if r.auth_level == "NONE"]
for r in unauth:
    print(r.path, r.auth_level, r.note)
```

Unauthenticated routes are the highest-leverage starting point: any input reaching
a dangerous sink from an unauth route is a full-chain finding with no prerequisite
access. On authentik (Python/Django + TypeScript/Lit), the classifier maps REST
API endpoints to their `@permission_classes` decorators.

---

## Phase 2: Sink scan (< 10 seconds)

```python
from ablation.analyzers.source_sink_scanner import SourceSinkScanner

scanner = SourceSinkScanner.from_context(ctx)
findings = scanner.scan()
print(scanner.report(findings))

highs = [f for f in findings if f.severity == "HIGH"]
```

The sink scanner catches dangerous patterns — `eval`, `subprocess.run`, `os.popen`,
`innerHTML=`, SSRF-shaped `fetch(var)` — before you read a single file. Each hit
names the file and line. These become read candidates even when the compressor
assigns them a low-priority profile, since the sink scanner uses different signal
classes.

---

## Phase 3: Compress and rank (< 30 seconds)

```python
from ablation.analyzers.source_audit_compressor import SourceAuditCompressor

compressor = SourceAuditCompressor.from_context(ctx)
buckets = compressor.compress()
print(compressor.report(buckets))
```

**Authentik output (2861 TypeScript files):**

```
Source Audit Compressor — profile-based batch audit
======================================================================
Total files: 2861
Occupied profiles: 12 / 32
Estimated audit compression: 97.5% fewer reads

── INDIVIDUAL READ (unsafe rendering present) (7 files) ──────────────
  profile=10011 (19):  1 files  [unsafe_render | user_data | shared_module]
  profile=10010 (18):  1 files  [unsafe_render | user_data]
  profile=10001 (17):  2 files  [unsafe_render | shared_module]
  profile=10000 (16):  3 files  [unsafe_render]

── INDIVIDUAL READ (dynamic href binding) (64 files) ──────────────
  profile=01011 (11): 45 files  [href_binding | user_data | shared_module]
  profile=01001  (9): 12 files  [href_binding | shared_module]
  profile=01000  (8):  7 files  [href_binding]

── SPOT CHECK (user-data rendering) (212 files) ──────────────
  profile=00011  (3): 212 files  [user_data | shared_module]

── BATCH-CLEAN (no signals at all) (2790 files) ──────────────
  profile=00000  (0): 2790 files  [no signals]
```

Start with the highest-profile files. Profile 16+ (unsafe rendering) is the first
pass — these are the only files where a single line can produce a DOM XSS finding
without further chaining.

---

## Phase 4: Individual reads — profiles 8–31

Read every file in `compressor.priority_reads(buckets)`. For each file:

1. Find the signal that triggered the profile (the bit table in the module reference tells you what to search for).
2. Trace backwards: where does the value come from? Admin-configured? API-returned? User-controlled?
3. Check whether any sanitization sits between source and sink.

```python
for bucket in compressor.priority_reads(buckets):
    print(f"\nprofile={bucket.profile_str} — {bucket.audit_action}")
    for fp in bucket.files:
        print(f"  {fp.rel_path}")
```

**Worked example — authentik PromptStage.ts (profile 19)**

Profile 19 = `unsafe_render | user_data | shared_module`. Reading
`web/src/flow/stages/prompt/PromptStage.ts` found:

```typescript
// line 85 — AlertInfo/AlertWarning/AlertDanger types
${unsafeHTML(prompt.initialValue)}

// line 219 — Static type
return html`<p>${unsafeHTML(prompt.initialValue)}</p>`

// line 272 — help text in all prompt types
return html`<p class="pf-c-form__helper-text">${unsafeHTML(prompt.subText)}</p>`
```

No DOMPurify anywhere in the file. Reading the Python model
`authentik/stages/prompt/models.py:234`:

```python
if self.field_key in prompt_context:
    # We don't want to parse this as an expression since a user will
    # be able to control the input
    value = prompt_context[self.field_key]
```

`prompt_context[field_key]` returns user-controlled input from a prior stage when
field keys collide. Finding logged as `AUT-PROMPT-UNSAFE-HTML-1` (PLAUSIBLE LOW —
requires admin misconfiguration to chain two stages with the same field_key).

---

## Phase 5: Spot checks — profiles 2–7

```python
for bucket in compressor.spot_checks(buckets):
    print(f"profile={bucket.profile_str}: {len(bucket.files)} files")
```

Read 10% of the files in each spot-check bucket, spread across subsystems. You are
looking for a surprise: a file assigned a low profile because the dangerous signal
uses a non-standard API that the compressor patterns don't cover.

**Worked example — authentik profiles 2–3 (212 files)**

All 10 spot-check reads confirmed the same pattern: user data rendered as Lit text
nodes:

```typescript
html`${item.name}`             // text node — Lit auto-escapes
html`<span>${user.email}</span>` // text node — Lit auto-escapes
```

Lit's tagged template literal always HTML-escapes interpolations when they land in
text node position. BATCH-CLEAN declared after 10 reads.

---

## Phase 6: Batch close — profiles 0–1

```python
batch = compressor.batch_clean(buckets)
print(f"Batch candidates: {len(batch)} files")
```

Read one representative file from profile 0. Confirm it contains nothing but config,
type definitions, lifecycle hooks, or pure utility logic with no rendering. If so,
declare the entire profile 0 bucket BATCH-CLEAN.

On authentik, 2790 files batch-closed via 2 reads: `lifecycle/worker.py` (Django
process entrypoint, no rendering) and `useSyntheticTitle.ts` (React-query hook,
no rendering).

---

## Phase 7: Log findings to the RE module

All findings — confirmed, plausible, eliminated — go into the target RE module at
`targets/<vendor>/<target>_re.py`. Add each finding to the `FINDINGS` dict and
each reviewed file to `CLEAN` with a note on what signal was present and why it
was cleared.

The compressor pass metadata goes into a comment block at the top of the RE module:

```python
# RE STATUS: pass 5ax complete (TypeScript audit 100% — all 2861 TS files covered)
# Profile coverage:
#   16-19 (unsafe_render): individual reads — passes 5ar/5as
#   8-15 (href_binding): individual reads — passes 5as/5at
#   4-7 (url_assign): spot-checks — pass 5au (10 representatives)
#   2-3 (user_data): BATCH-CLEAN — pass 5av (10 representatives)
#   1 (shared_module): BATCH-CLEAN — pass 5aw (2 representatives)
#   0 (no signals): BATCH-CLEAN — pass 5ax (2 representatives)
```

Commit and push after completing each profile tier — don't wait until 100%:

```bash
git add -f targets/authentik/authentik_re.py
git commit -m "pass 5ax: TypeScript profile 0 BATCH-CLEAN; 100% complete"
env HOME=/home/cowboy GIT_LFS_SKIP_SMUDGE=1 git push origin main
```

---

## Worked example: authentik full audit summary

**Codebase:** goauthentik/authentik — Python (Django) + TypeScript (Lit) + Go

| Language | Files | Method |
|---|---|---|
| Python | 2151 | REST API, Django models, permission classes — passes 1–5 |
| TypeScript | 2861 | Profile-based compression — passes 5ar–5ax |
| Go | 80 | Individual reads — pass 5 |
| **Total** | **4942** | |

**Findings:**

| ID | Severity | Status | Summary |
|---|---|---|---|
| AUT-SESS-PICKLE-1 | HIGH | PLAUSIBLE | Pickle deserialization in Redis session backend |
| AUT-SAML-REFURI-1 | CRITICAL* | PLAUSIBLE | SAML Reference URI bypass (* if SAML bypass confirmed) |
| AUT-PROMPT-UNSAFE-HTML-1 | LOW | PLAUSIBLE | Admin-configured HTML in prompt stages via `unsafeHTML()`; user-controlled XSS via flow key reuse |
| AUT-LAUNCH-URL-1 | — | ELIMINATED | `window.open()` URL validated before call |

**Audit compression:** 4942 files → ~80 manual reads (98.4% reduction).

---

## Applying to any codebase

The workflow is language-agnostic. The compressor's bit definitions are TypeScript/JavaScript
oriented (Lit, React, JSX patterns), but SourceContext indexes Python, Go, Rust, Java,
Ruby, and PHP as well. For non-JS stacks:

- Use `SourceEntryClassifier` and `SourceSinkScanner` directly — they have Python, Rust, and Go patterns built in.
- Use `SourceIsolationChecker` for any Prisma, SQLAlchemy, or Mongoose codebase.
- Extend `_PAT_UNSAFE_RENDER` in `source_audit_compressor.py` for framework-specific unsafe APIs (e.g., Jinja2 `Markup()`, Django `mark_safe()`).

See [Source Analyzers](../module-reference/source-audit.md) for full API reference.
