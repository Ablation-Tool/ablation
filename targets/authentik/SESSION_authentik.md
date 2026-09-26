# Authentik Source RE Session

## Status: IN PROGRESS — 2026-09-26

## Target
- Repo: https://github.com/goauthentik/authentik
- Clone: /tmp/authentik
- Framework: Django + DRF, Go outposts, TypeScript frontend
- Purpose: solidify ablation Code Base Audit module/toolchain

## Completed

### Tool Run — SourceContext
- 4942 source files: 2861 ts/tsx, 1285 py, 570 go, 226 js
- 1023 route files (after adding DRF CBV patterns to source_ingestion.py)
- Package roots: monorepo with packages/ subdirs

### Tool Run — SourceEntryClassifier
- Auth surface: 47 NONE, 150 SESSION, 2 ADMIN, ~810 API_KEY
- AllowAny downgrade identified: FlowExecutorView (intentional), debug view, geoip API

### Tool Run — SourceSinkScanner
- 5 HIGH (all pickle.loads): sessions.py:86, models.py:187/188/190, backend.py:32
- 3 MEDIUM (Rust Command::new): hardcoded commands, not user-controlled

### Deep Reads — Python auth layer
- authentik/api/authentication.py: TokenAuthentication, IPCUser (/tmp/authentik-core-ipc.key)
- authentik/core/sessions.py: unsigned pickle session store (vs. Django's signed sessions)
- packages/django-dramatiq-postgres/models.py: ScheduleBase.send() pickle sinks
- packages/django-postgres-cache/backend.py: cache pickle sink
- authentik/flows/views/executor.py:106: FlowExecutorView AllowAny (intentional)

### Ablation Tool Improvements (committed as 2777c49)
- source_ingestion.py: added Django CBV class inheritance patterns to _ROUTE_CONTENT_SIGNALS
- source_entry_classifier.py: added 10+ DRF/Django auth patterns + AllowAny downgrade logic

## Confirmed Findings

| ID | Severity | Title |
|----|----------|-------|
| AUT-SESS-PICKLE-1 | HIGH | Unsigned pickle deserialization of session data (no HMAC) |
| AUT-TASK-PICKLE-1 | HIGH | Unsigned pickle deserialization of task queue arguments |
| AUT-CACHE-PICKLE-1 | MEDIUM | Unsigned pickle deserialization of PostgreSQL cache values |
| AUT-IPC-KEY-1 | MEDIUM | IPC superuser key stored in world-readable /tmp |
| AUT-FLOW-ALLOWANY-1 | INFO | FlowExecutorView AllowAny (intentional — login flow) |

### Pass 2 — Expression engine, blueprints, debug view, outpost WS (2026-09-26)
- lib/expression/evaluator.py:365 — exec() in policy evaluator: admin-only by design
  (ExpressionPolicyViewSet uses DEFAULT_PERMISSION_CLASSES [ObjectPermissions])
  Notable: `requests` in globals = SSRF primitive; `expr_create_jwt_raw` = arbitrary JWT claims
- blueprints/v1/common.py — BlueprintLoader(SafeLoader): YAML deser is safe; !File/!Env admin-gated
  (resolve() only called after check_blueprint_perms() passes)
- core/views/debug.py — ServerLogAPI AllowAny gated by `if settings.DEBUG:`; not exposed in prod
- policies/geoip/api.py — ISO3166View AllowAny is static country list; GeoIPPolicyViewSet is authed
- outposts/consumer.py — OutpostConsumer.connect() uses guardian get_objects_for_user + DenyConnection
- SourceIsolationChecker: 0 results — checker is Prisma/TS-specific, not applicable to Django ORM

## Clean (investigated, not exploitable)
- ServerLogAPI, ISO3166View, FlowExecutorView, Expression exec(), Blueprint !File/!Env, Outpost WS

## Pending
- SourceIsolationChecker: needs Python/Django ORM adapter module (toolchain gap)
- SourceTaintTracker: trace flow executor PLAN_CONTEXT_* to session storage
- Go outpost code: internal/outpost/ and cmd/ (LDAP injection? Go-specific patterns)
- Property mappings API: confirm admin-only gate (same exec() path as ExpressionPolicy)

## Commits
- 2777c49: source_ingestion.py + source_entry_classifier.py DRF pattern additions
- 3aaa666: initial RE module — pass 1 (3 pickle HIGH, IPC key MEDIUM)
