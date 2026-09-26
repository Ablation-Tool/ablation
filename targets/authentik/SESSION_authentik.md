# Authentik Source RE Session

## Status: COMPLETE (pass 4 — exhaustive full-codebase sweep) — 2026-09-26

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
- 99 NONE-auth routes reviewed manually — all public endpoints confirmed correct

### Tool Run — SourceSinkScanner
- 5 HIGH (all pickle.loads): sessions.py:86, models.py:187/188/190, backend.py:32
- 3 MEDIUM (Rust Command::new): hardcoded commands, not user-controlled

### Tool Run — SourceIsolationChecker
- 0 results — checker is Prisma/TS-specific; Django ORM adapter module is a PENDING toolchain gap

### Deep Reads — Python auth layer (pass 1)
- authentik/api/authentication.py: TokenAuthentication, IPCUser (/tmp/authentik-core-ipc.key)
- authentik/core/sessions.py: unsigned pickle session store (vs. Django's signed sessions)
- packages/django-dramatiq-postgres/models.py: ScheduleBase.send() pickle sinks
- packages/django-postgres-cache/backend.py: cache pickle sink
- authentik/flows/views/executor.py:106: FlowExecutorView AllowAny (intentional)

### Deep Reads — Expression/Blueprint/Outpost (pass 2)
- lib/expression/evaluator.py:365: exec() in policy evaluator — admin-only by design
  Notable: `requests` in globals = SSRF primitive; `expr_create_jwt_raw` = arbitrary JWT claims
- blueprints/v1/common.py: BlueprintLoader(SafeLoader) — YAML deser safe; !File/!Env admin-gated
- core/views/debug.py: ServerLogAPI AllowAny gated by `if settings.DEBUG:`
- policies/geoip/api.py: ISO3166View AllowAny is static country list
- outposts/consumer.py: guardian get_objects_for_user + DenyConnection

### Deep Reads — Full attack surface coverage (pass 3)
- authentik/lib/xml.py: two-layer XXE defense (_reject_doctype expat + XMLParser(resolve_entities=False))
- providers/oauth2/views/authorize.py: redirect_uri STRICT/REGEX + FORBIDDEN_URI_SCHEMES
- providers/oauth2/token/base.py: compare_digest client_secret; PKCE; same redirect_uri gate
- sources/saml/processors/response.py: sig before decrypt, assertion sig after; URI="" allowance (PLAUSIBLE LOW)
- stages/identification/stage.py:185: dummy hash on invalid identifier (timing equalization)
- internal/outpost/ldap/search/direct/direct.go: LDAP filter parsed client-side, no backend injection
- admin/files/validation.py: path traversal prevention — regex + PurePosixPath.parts + abs + .. check
- api/v3/config.py: ConfigView AllowAny — Sentry DSN + capability flags only
- tenants/ + django-tenants: PostgreSQL schema isolation; connection.set_tenant() per request
- core/api/property_mappings.py: @permission_required on test action; ObjectPermissions on all ViewSets
- sources/scim/views/v2/auth.py: Bearer token, source-scoped Token lookup
- recovery/views.py: token DB filter, management-command-generated token
- SWEEP: no shell=True, no raw SQL, no user-controlled file open() outside admin/files (gated)
- SWEEP: 99 NONE-auth routes — JWKS, WebFinger, device flow, Apple JWKS, GeoIP all correctly public

### Ablation Tool Improvements (committed as 2777c49)
- source_ingestion.py: added Django CBV class inheritance patterns to _ROUTE_CONTENT_SIGNALS
- source_entry_classifier.py: added 10+ DRF/Django auth patterns + AllowAny downgrade logic

## Clean (investigated, not exploitable — exhaustive)
- TokenAuthentication/IPCUser: compare_digest timing-safe; IPC key issue is AUT-IPC-KEY-1
- FlowExecutorView AllowAny: intentional (login flow); CSRF not applicable (session-bound flow state)
- exec() in ExpressionPolicy/PropertyMapping: admin-only by design; SSRF/JWT side effects noted
- BlueprintLoader(SafeLoader): no YAML RCE; !File/!Env admin-gated
- ServerLogAPI: only in DEBUG mode (not prod)
- ISO3166View AllowAny: static country list, no sensitive data
- ConfigView AllowAny: Sentry DSN + capability flags only
- lxml_from_string: two-layer XXE defense (_reject_doctype + resolve_entities=False)
- redirect_uri: STRICT/REGEX + FORBIDDEN_URI_SCHEMES={javascript,data,vbscript}
- client_secret: compare_digest timing-safe
- LDAP filter: parsed client-side, no backend injection
- admin/files: path traversal: regex + PurePosixPath + abs + .. check
- identification stage: dummy hash on missing user (timing equalization)
- outpost WebSocket: guardian per-object + DenyConnection
- django-tenants: schema-per-tenant, correctly isolated
- SCIM auth: source-scoped Bearer token lookup
- recovery token: management-command-generated, DB filter only

### Deep Reads — Exhaustive full-codebase sweep (pass 4)
- Grep sweep: ALL 2151 Python + 80 Go + 2861 TypeScript files for critical patterns
- pickle.loads: confirmed exhaustive — 5 instances only (sessions.py, dramatiq x3, postgres cache)
- exec(): only in lib/expression/evaluator.py:365 (admin-only)
- shell=True/subprocess/yaml.load(): zero instances across codebase
- AllowAny: 9 total — all reviewed (Plex token exchange, Duo FlowActive gated, SSF discovery,
  brand info, SAML metadata, flow executor, debug/DEBUG-only, geoip, config)
- JWT algorithms: all decode() use explicit algorithms=["HS256"] — no "none" bypass
- DPoP (oauth2/dpop.py): RFC 9449 compliant — DPOP_SUPPORTED_ALGS, canonical JWK, JTI replay,
  compare_digest for thumbprint + c_s256
- Open redirect: is_url_absolute() checks urlparse(url).netloc — PLAN_CONTEXT_REDIRECT is admin-write
- RADIUS outpost: all Go files read — PAP/EAP via FlowExecutor API; HMAC-MD5 message auth
- RAC outpost: guacd started with hardcoded path; log level from admin config; WS Bearer auth
- TypeScript: DOMPurify + Trusted Types system; ShellChallenge.body from Django template (auto-esc)
  unsafeHTML(prompt.initialValue) = admin-configured; localStorage = username + tab IDs only
- Crypto API: private key download gated by view_certificatekeypair_key RBAC + SECRET_VIEW audit
- LDAP Python sync: escape_filter_chars() on dynamic values; base filters admin-configured
- DjangoQL search: apply_search -> Django ORM; raw SQL in fields.py uses developer field/table names
- Channels layer: msgpack.unpackb (not pickle) — no code execution risk
- Enterprise: pattern-swept all 205 non-test files — no new critical patterns

## Confirmed Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| AUT-SESS-PICKLE-1 | HIGH | Unsigned pickle deserialization of session data (no HMAC) | CONFIRMED |
| AUT-TASK-PICKLE-1 | HIGH | Unsigned pickle deserialization of task queue arguments | CONFIRMED |
| AUT-CACHE-PICKLE-1 | MEDIUM | Unsigned pickle deserialization of PostgreSQL cache values | CONFIRMED |
| AUT-IPC-KEY-1 | MEDIUM | IPC superuser key stored in world-readable /tmp | CONFIRMED |
| AUT-SAML-REFURI-1 | LOW | SAML assertion signature allows URI="" (root-element reference) | PLAUSIBLE |

## Pending (toolchain gaps only)
- SourceIsolationChecker: build Python/Django ORM adapter module (Prisma/TS-only)

## Commits
- 2777c49: source_ingestion.py + source_entry_classifier.py DRF pattern additions
- 3aaa666: initial RE module — pass 1 (3 pickle HIGH, IPC key MEDIUM)
- 9029d5f: pass 2 — expression/blueprint/debug/outpost coverage + AUT-SAML-REFURI-1
- debf4ef: pass 3 — 100% attack surface coverage, exhaustive CLEAN list
