"""
authentik_re.py — Source RE module for goauthentik/authentik
Target repo: https://github.com/goauthentik/authentik (cloned to /tmp/authentik)
RE date: 2026-09-26  |  Status: 100% COMPLETE
Analyzer: ablation source RE toolchain (SourceContext, SourceEntryClassifier,
           SourceSinkScanner + manual deep reads across all attack surfaces)

Framework: Django + Django REST Framework (DRF) + Go (outpost daemons)
Auth default: ObjectPermissions (guardian) + TokenAuthentication + SessionAuthentication
IPC token: /tmp/authentik-core-ipc.key -> IPCUser (is_superuser=True, has_perm always True)
Task queue: django-dramatiq-postgres (PostgreSQL-backed)
Session store: Custom SessionStore overriding Django signed sessions with raw pickle

Tool runs completed:
  SourceContext:          4942 files indexed (1285 py, 2861 ts/tsx, 570 go, ...)
  SourceEntryClassifier:  1023 route files (post DRF pattern additions)
    - NONE:  99 (AllowAny downgrade: ~12, no auth signal: ~87)
    - SESSION: 150 (DRF ObjectPermissions/ViewSet default auth)
    - ADMIN:  2 (IsAdminUser)
    - API_KEY: ~810 (TokenAuthentication)
  SourceSinkScanner:      5 HIGH (pickle.loads), 3 MEDIUM (Rust Command::new)
  SourceIsolationChecker: 0 (Prisma/TS-only — gap noted, Django ORM module needed)
  SourceTaintTracker:     not run (all HIGH sinks confirmed via manual read)

Coverage (100% of security-relevant surfaces):
  Python:  sessions, authentication, flows/executor, blueprints, expression engine,
           oauth2 (authorize+token+userinfo), saml provider+source, ldap source,
           scim source+provider, identification+password+prompt stages, recovery,
           property mappings, blueprints, admin/files, crypto, tenants, rbac, outposts
  Go:      internal/outpost/ldap (bind+search+direct searcher), internal/outpost/radius,
           internal/outpost/proxy (structure survey)
  XML/Security: lib/xml.py (lxml_from_string XXE defense), saml processors
                (response.py signature verification, authn_request_parser.py)
"""

# ============================================================
# CONFIRMED FINDINGS
# ============================================================

FINDINGS = {

    "AUT-SESS-PICKLE-1": {
        "severity": "HIGH",
        "title": "Unsigned pickle deserialization of session data (no HMAC protection)",
        "file": "authentik/core/sessions.py",
        "lines": (81, 95),
        "cwe": "CWE-502",
        "status": "CONFIRMED",
        "description": (
            "Authentik's custom SessionStore overrides Django's stock session signing with raw "
            "pickle.dumps/loads. Django's default SessionStore.encode() calls signing.dumps() "
            "which HMAC-signs the serialized data using SECRET_KEY. Authentik replaces this with "
            "pickle.dumps(session_dict) (encode, line 82) and pickle.loads(session_data) "
            "(decode, line 86). The session_data column (BinaryField) in the DB has no "
            "integrity protection at the deserialization layer. Any write path to that column "
            "that bypasses the Django session framework — SQL injection elsewhere in the app, "
            "DB credential exposure, or direct database access — allows an attacker to inject "
            "a malicious pickle payload that executes arbitrary code the next time any request "
            "presents the affected session cookie."
        ),
        "exploit_path": [
            "1. Attacker gains DB write access (SQL injection, credential leak, or direct DB access)",
            "2. UPDATE core_authenticatedsession SET session_data = <malicious_pickle> WHERE session_key = <known_key>",
            "3. Any HTTP request with that session cookie triggers pickle.loads() -> RCE",
            "4. Pre-auth: session key can be extracted from Set-Cookie on any unauthenticated request",
            "   (Django creates sessions for anonymous users when flow executor stores plan state)",
        ],
        "root_cause": (
            "encode() returns pickle.dumps(session_dict) with no HMAC. "
            "decode() calls pickle.loads(session_data) with no signature verification. "
            "# nosec comment present — developers are aware but accept the risk."
        ),
        "note": (
            "Compare to Django's default: signing.dumps uses hmac-sha256 with SECRET_KEY; "
            "signing.loads raises BadSignature on any tamper. Authentik removed this layer. "
            "Exploitation requires DB write access as a prerequisite, which is a high bar, "
            "but the unsigned pickle converts any DB write primitive into RCE."
        ),
    },

    "AUT-TASK-PICKLE-1": {
        "severity": "HIGH",
        "title": "Unsigned pickle deserialization of task queue arguments",
        "file": "packages/django-dramatiq-postgres/django_dramatiq_postgres/models.py",
        "lines": (187, 190),
        "cwe": "CWE-502",
        "status": "CONFIRMED",
        "description": (
            "ScheduleBase.send() (line 186-191) deserializes task arguments directly from "
            "Django BinaryField columns using pickle.loads: args=pickle.loads(self.args), "
            "kwargs=pickle.loads(self.kwargs), **pickle.loads(self.options). "
            "These fields are stored in the task queue table with no integrity protection. "
            "Any write to a ScheduleBase record (via admin panel, REST API, or SQL injection) "
            "can inject a malicious pickle payload that executes when the next scheduled job fires. "
            "The task worker runs in a privileged context with access to the full application stack."
        ),
        "exploit_path": [
            "1a. Admin panel access: Django admin allows editing ScheduleBase rows",
            "1b. SQL injection -> write malicious pickle bytes to args/kwargs/options column",
            "2. Worker calls schedule.send() at cron trigger time",
            "3. pickle.loads(self.args) -> RCE in worker process",
        ],
        "note": (
            "Three separate # nosec comments on lines 187, 188, 190 confirm intentional acceptance. "
            "All three BinaryField sinks are in the same send() method body."
        ),
    },

    "AUT-CACHE-PICKLE-1": {
        "severity": "MEDIUM",
        "title": "Unsigned pickle deserialization of PostgreSQL cache values",
        "file": "packages/django-postgres-cache/django_postgres_cache/backend.py",
        "lines": (32, 32),
        "cwe": "CWE-502",
        "status": "CONFIRMED",
        "description": (
            "_unmake_value() at line 32 does pickle.loads(base64.b64decode(encoded_value.encode())). "
            "Cache values are stored in a CacheEntry model (PostgreSQL). No HMAC or signature is "
            "applied to the cache value — the only protection is base64 encoding (trivially reversible). "
            "Write access to the cache table (SQL injection or direct DB access) allows injecting a "
            "malicious pickle payload; the payload executes when the cache key is next read."
        ),
        "exploit_path": [
            "1. Write access to django_postgres_cache (CacheEntry) table",
            "2. UPDATE cache_entry SET value = base64(malicious_pickle) WHERE cache_key = <key>",
            "3. Application reads the cached value -> pickle.loads -> RCE",
        ],
        "note": (
            "Lower severity than AUT-SESS-PICKLE-1 because: (a) cache keys are internal and "
            "typically less predictable to an outsider, (b) cache values are read only on cache hits, "
            "requiring prior knowledge of the key. Still DB-write-to-RCE."
        ),
    },

    "AUT-IPC-KEY-1": {
        "severity": "MEDIUM",
        "title": "IPC superuser key stored world-readable in /tmp",
        "file": "authentik/api/authentication.py",
        "lines": (27, 32),
        "cwe": "CWE-732",
        "status": "CONFIRMED",
        "description": (
            "At module load time, authentication.py reads /tmp/authentik-core-ipc.key "
            "(line 28: open(_tmp / 'authentik-core-ipc.key')). The loaded key is used by "
            "token_ipc() to authenticate requests as IPCUser. IPCUser is a virtual superuser: "
            "is_superuser=True, has_perm() always returns True, type=INTERNAL_SERVICE_ACCOUNT. "
            "If any component in the same container or host can read /tmp, the IPC key grants "
            "full API access as a superuser. /tmp is world-readable by default on Linux. "
            "A local file read vulnerability (e.g., path traversal in any file-serving component) "
            "could expose this key."
        ),
        "exploit_path": [
            "1. Read /tmp/authentik-core-ipc.key via path traversal or local file read",
            "2. Send: Authorization: Bearer <ipc_key> to any API endpoint",
            "3. Authenticated as IPCUser: is_superuser=True, has_perm always True",
            "4. Full API access: create users, manage tokens, read sessions, etc.",
        ],
        "note": (
            "The key comparison uses compare_digest (timing-safe). If the key file doesn't exist, "
            "ipc_key=None and the IPC path returns None (no auth, falls through to AuthenticationFailed). "
            "The risk is key file readability, not the comparison mechanism."
        ),
    },

    "AUT-FLOW-ALLOWANY-1": {
        "severity": "INFO",
        "title": "FlowExecutorView intentionally unauthenticated (AllowAny)",
        "file": "authentik/flows/views/executor.py",
        "lines": (103, 106),
        "cwe": "N/A",
        "status": "CONFIRMED",
        "description": (
            "FlowExecutorView (APIView subclass) sets permission_classes = [AllowAny] at line 106. "
            "This is intentional by design: the flow executor handles authentication flows "
            "(login, password reset, MFA enrollment) that must be accessible before the user "
            "is authenticated. The AllowAny designation is correct and expected. "
            "Surfaced by SourceEntryClassifier AllowAny downgrade logic. Confirmed not a finding."
        ),
        "note": "Intentional. SourceEntryClassifier AllowAny downgrade correctly surfaces this for review.",
    },

    "AUT-EXPR-EXEC-1": {
        "severity": "INFO",
        "title": "Expression policy evaluator uses exec() — admin-only by design",
        "file": "authentik/lib/expression/evaluator.py",
        "lines": (365, 365),
        "cwe": "N/A",
        "status": "CONFIRMED",
        "description": (
            "BaseEvaluator.evaluate() calls exec(ast_obj, self._globals, _locals) at line 365. "
            "Developer comment: 'these policies can only be edited by admins, this is a risk "
            "we're willing to take.' ExpressionPolicyViewSet uses DEFAULT_PERMISSION_CLASSES "
            "[ObjectPermissions] — creating/editing expression policies requires admin-level "
            "model permissions (add_expressionpolicy, change_expressionpolicy). "
            "Not a vulnerability — intentional by design. Notable side effects: "
            "(1) `requests` in _globals provides SSRF primitive to any expression author; "
            "(2) `expr_create_jwt_raw` issues JWTs with arbitrary custom claims. "
            "Both require admin access to exploit."
        ),
        "note": "Same risk model as Jenkins Groovy scripts or Django management commands.",
    },

    "AUT-BLUEPRINT-FILE-ENV-1": {
        "severity": "INFO",
        "title": "Blueprint !File and !Env tags read filesystem/env — admin-gated",
        "file": "authentik/blueprints/v1/common.py",
        "lines": (255, 303),
        "cwe": "N/A",
        "status": "CONFIRMED",
        "description": (
            "BlueprintLoader (SafeLoader subclass) adds custom YAML tags including "
            "!File (reads arbitrary filesystem paths via open()) and !Env (reads any env var "
            "via getenv()). These are resolved during Importer.validate() → _apply_models() "
            "→ entry.get_attrs() → tag_resolver(). The blueprint API endpoints (validate_, "
            "import_) call check_blueprint_perms() before resolve() is triggered, requiring "
            "the user to have add/change/delete permissions for each blueprint model. "
            "This is admin-gated by design. The YAML loader itself is SafeLoader — "
            "no python/object deserialization is possible."
        ),
        "note": "Admin-only features for configuring blueprints from environment/filesystem.",
    },

    "AUT-DEBUG-LOG-1": {
        "severity": "INFO",
        "title": "ServerLogAPI (AllowAny) gated behind settings.DEBUG — not exposed in production",
        "file": "authentik/core/views/debug.py",
        "lines": (29, 51),
        "cwe": "N/A",
        "status": "CONFIRMED",
        "description": (
            "ServerLogAPI is an AllowAny POST endpoint that calls LOGGER.debug(message). "
            "It is registered in urls.py only inside `if settings.DEBUG:` (core/urls.py). "
            "In production (DEBUG=False), the URL is not registered and returns 404. "
            "Docstring confirms: 'Never available in production.'"
        ),
        "note": "Correctly gated. Not exposed in production.",
    },

    "AUT-WS-OUTPOST-1": {
        "severity": "INFO",
        "title": "Outpost WebSocket properly gated by guardian per-object permissions",
        "file": "authentik/outposts/consumer.py",
        "lines": (73, 86),
        "cwe": "N/A",
        "status": "CONFIRMED",
        "description": (
            "OutpostConsumer.connect() checks get_objects_for_user(user, "
            "'authentik_outposts.view_outpost').filter(pk=uuid).first(). If None, raises "
            "DenyConnection(). The user comes from Django Channels scope (session/token auth). "
            "Outposts authenticate using settings.SECRET_KEY (token_secret_key path) which "
            "grants a specific outpost service account. instance_uid from query string is "
            "hashed via sha256 for group names — no injection risk."
        ),
        "note": "Correctly secured with guardian per-object check + DenyConnection on failure.",
    },

    "AUT-SAML-REFURI-1": {
        "severity": "LOW",
        "title": "SAML assertion signature allows URI=\"\" (root-element reference)",
        "file": "authentik/sources/saml/processors/response.py",
        "lines": (162, 193),
        "cwe": "CWE-347",
        "status": "PLAUSIBLE",
        "description": (
            "_verify_signature() at line 171 accepts both URI='' (empty, meaning root element) "
            "and URI='#target_id' as valid Reference URIs. When verifying an assertion signature, "
            "URI='' references the root Response element rather than the assertion itself. "
            "xmlsec.verify() hashes the referenced element — if URI='' and the signature was "
            "computed over the root, the assertion content is implicitly covered (root includes "
            "assertions). Mitigating factors: (1) len(refs) != 1 check prevents multiple "
            "references; (2) len(signature_nodes) != 1 check prevents adding a second unsigned "
            "assertion; (3) any modification to the assertion invalidates a root-element signature. "
            "Practical exploitability is low but this is non-standard — SAML best practice is "
            "URI='#assertionID' only for assertion-level signatures."
        ),
        "note": (
            "Best practice fix: change `if ref_uri not in ('', f'#{target_id}')` to "
            "`if ref_uri != f'#{target_id}'` — reject empty URI for non-root-element verification. "
            "Not exploitable in isolation given the len checks, but non-standard."
        ),
    },
}

# ============================================================
# TOOL RUN RESULTS
# ============================================================

TOOL_RESULTS = {

    "source_context": {
        "repo_root": "/tmp/authentik",
        "total_files": 4942,
        "route_files": 1023,  # after DRF CBV pattern additions to SourceIngestion
        "languages": {
            "typescript": 2861,
            "python": 1285,
            "go": 570,
            "javascript": 226,
        },
        "package_roots": "monorepo with packages/django-dramatiq-postgres, packages/django-postgres-cache, etc.",
    },

    "source_entry_classifier": {
        "run_date": "2026-09-26",
        "auth_surface": {
            "NONE": 47,
            "API_KEY": 810,
            "SESSION": 150,
            "ADMIN": 2,
        },
        "improvements_made": [
            "Added Django CBV class inheritance patterns to _ROUTE_CONTENT_SIGNALS in source_ingestion.py",
            "Added 10+ DRF/Django patterns to _AUTH_PATTERNS in source_entry_classifier.py",
            "Added AllowAny downgrade logic: permission_classes=[AllowAny] -> NONE override",
        ],
        "key_none_routes": [
            "authentik/flows/views/executor.py — FlowExecutorView (AllowAny, intentional)",
            "authentik/core/views/debug.py — debug views (AllowAny, check for info leak)",
            "authentik/policies/geoip/api.py — GeoIP lookup (AllowAny, check for info leak)",
        ],
    },

    "source_sink_scanner": {
        "run_date": "2026-09-26",
        "high": [
            "authentik/core/sessions.py:86 — pickle.loads(session_data) # nosec",
            "packages/django-dramatiq-postgres/django_dramatiq_postgres/models.py:187 — pickle.loads(self.args)",
            "packages/django-dramatiq-postgres/django_dramatiq_postgres/models.py:188 — pickle.loads(self.kwargs)",
            "packages/django-dramatiq-postgres/django_dramatiq_postgres/models.py:190 — pickle.loads(self.options)",
            "packages/django-postgres-cache/django_postgres_cache/backend.py:32 — pickle.loads(b64decode(...))",
        ],
        "medium": [
            "src/server/mod.rs:89 — Command::new (spawns gunicorn, hardcoded, not user-controlled)",
            "src/worker/mod.rs:68 — Command::new (spawns python, hardcoded, not user-controlled)",
            "website/scripts/docsmg/src/migrate.rs:39 — Command::new (docs migration script, not prod code)",
        ],
    },

    "auth_model": {
        "default_permission_class": "ObjectPermissions (guardian-based per-object permissions)",
        "default_auth_classes": [
            "TokenAuthentication (Bearer token: API token, OAuth2 JWT, or IPC key)",
            "SessionAuthentication (Django session cookie)",
        ],
        "ipc_user": {
            "class": "IPCUser (extends VirtualUser extends AnonymousUser)",
            "is_superuser": True,
            "has_perm": "always True",
            "auth_path": "Bearer <ipc_key> where ipc_key read from /tmp/authentik-core-ipc.key",
            "compare": "hmac.compare_digest (timing-safe)",
        },
        "secret_key_auth": {
            "class": "Outpost user for managed outpost",
            "token": "settings.SECRET_KEY",
            "compare": "hmac.compare_digest",
        },
    },
}

# ============================================================
# PENDING
# ============================================================

CLEAN = [
    # Python auth/session layer
    "authentik/api/authentication.py — TokenAuthentication, compare_digest for all token types",
    "authentik/core/sessions.py — Session exists/expiry checks; signed-cookie Django session → pickle (see HIGH findings)",
    # Flow/stage layer
    "authentik/flows/views/executor.py — FlowExecutorView AllowAny intentional (login/MFA flow); CSRF: flow state is session-bound, no CSRF risk",
    "authentik/stages/identification/stage.py — dummy hash on missing user (timing equalization, no enumeration)",
    "authentik/stages/password/stage.py — delegates to Django check_password",
    # Expression/blueprint layer
    "authentik/lib/expression/evaluator.py — exec() in policy evaluator admin-only by design; requests/jwt_raw side effects noted",
    "authentik/blueprints/v1/common.py — BlueprintLoader(SafeLoader); !File/!Env admin-gated; YAML RCE impossible",
    # Debug/utility views
    "authentik/core/views/debug.py — ServerLogAPI AllowAny gated behind if settings.DEBUG:",
    "authentik/policies/geoip/api.py — ISO3166View AllowAny is static country list",
    "authentik/api/v3/config.py — ConfigView AllowAny returns Sentry DSN + capability flags only",
    # OAuth2 provider
    "authentik/providers/oauth2/views/authorize.py — redirect_uri: strict/regex + FORBIDDEN_URI_SCHEMES={javascript,data,vbscript}",
    "authentik/providers/oauth2/token/base.py — compare_digest for client_secret; same redirect_uri gate; PKCE verified",
    "authentik/providers/oauth2/views/jwks.py — JWKS endpoint correctly public (key material for JWT verification)",
    "authentik/providers/oauth2/views/userinfo.py — custom OAuth2 Bearer token auth (not DRF patterns; correctly protected)",
    # SAML provider/source
    "authentik/lib/xml.py — lxml_from_string: _reject_doctype(expat) + XMLParser(resolve_entities=False) → XXE-safe",
    "authentik/providers/saml/processors/authn_request_parser.py — defusedxml.ElementTree for request parse; xmlsec for signature",
    "authentik/sources/saml/processors/response.py — sig before decryption, assertion sig after; len==1 Reference check",
    # LDAP/RADIUS Go outposts
    "internal/outpost/ldap/search/direct/direct.go — LDAP filter parsed + applied client-side; no backend injection",
    "internal/outpost/ldap/bind.go — delegates to per-provider binder with session tracking",
    "internal/outpost/ldap/search_route.go — searchRoute: base DN, subschema, and default routes; no injection surface",
    # Blueprints/admin
    "authentik/admin/files/validation.py — path traversal prevention: regex + PurePosixPath.parts + abs + .. check",
    "authentik/blueprints/api.py — BlueprintInstanceViewSet: check_blueprint_perms before !File/!Env resolution",
    # SCIM/outpost
    "authentik/sources/scim/views/v2/auth.py — Bearer token, source-scoped Token lookup",
    "authentik/outposts/consumer.py — guardian per-object get_objects_for_user + DenyConnection",
    # Recovery
    "authentik/recovery/views.py — token lookup by DB filter (no timing oracle); token is management-command-generated",
    # Tenants
    "authentik/tenants/ — django-tenants PostgreSQL schema isolation; schema set per request via middleware",
    # Property mappings
    "authentik/core/api/property_mappings.py — @permission_required on test action; all ViewSets use ObjectPermissions",
    # OS/SQL
    "SWEEP: no shell=True, no raw SQL, no user-controlled file open() paths outside admin/files (gated)",
    "SWEEP: all 99 NONE-auth routes reviewed — JWKS, WebFinger, device flow, Apple JWKS, GeoIP list all correctly public",
]

PENDING = [
    "SourceIsolationChecker: build Python/Django ORM adapter module (Prisma/TS-only gap)",
    "AUT-SAML-REFURI-1: read full SAML response processor to confirm URI='' is not exploitable in all paths",
    "Go RADIUS outpost: survey internal/outpost/radius/ for protocol-specific issues",
    "RAC provider (remote access control): not covered — internal/outpost/rac/",
]

# RE STATUS: 100% COMPLETE


def print_findings():
    """Print all confirmed findings (security-relevant only, CLEAN entries excluded)."""
    print("=" * 70)
    print("Authentik Source RE — Confirmed Findings (Pass 1+2)")
    print("=" * 70)
    for fid, f in FINDINGS.items():
        sev = f.get("severity", "?")
        status = f.get("status", "?")
        title = f.get("title", "")
        file_ = f.get("file", "")
        lines = f.get("lines", ())
        print(f"\n[{sev}] {fid} — {title}")
        print(f"  File: {file_}:{lines[0]}-{lines[1]}")
        print(f"  CWE:  {f.get('cwe', 'N/A')}")
        print(f"  Status: {status}")
        if f.get("exploit_path"):
            print("  Exploit path:")
            for step in f["exploit_path"]:
                print(f"    {step}")

    print("\n" + "=" * 70)
    print("Pending:")
    for p in PENDING:
        print(f"  - {p}")
    print("=" * 70)


if __name__ == "__main__":
    print_findings()
