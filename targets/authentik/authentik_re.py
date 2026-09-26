"""
authentik_re.py — Source RE module for goauthentik/authentik
Target repo: https://github.com/goauthentik/authentik (cloned to /tmp/authentik)
RE date: 2026-09-26
Analyzer: ablation source RE toolchain (SourceContext, SourceEntryClassifier,
           SourceSinkScanner, SourceEntryClassifier with DRF patterns)

Framework: Django + Django REST Framework (DRF)
Auth default: ObjectPermissions (guardian) + TokenAuthentication + SessionAuthentication
IPC token: /tmp/authentik-core-ipc.key -> IPCUser (is_superuser=True, has_perm always True)
Task queue: django-dramatiq-postgres (PostgreSQL-backed)
Session store: Custom SessionStore overriding Django signed sessions with raw pickle

Tool runs completed:
  SourceContext:          4942 files indexed (1285 py, 2861 ts/tsx, 570 go, ...)
  SourceEntryClassifier:  1023 route files (post DRF pattern additions)
    - NONE:  47 (AllowAny downgrade: 12, no auth signal: 35)
    - SESSION: 150 (DRF ObjectPermissions/ViewSet default auth)
    - ADMIN:  2 (IsAdminUser)
    - API_KEY: ~810 (TokenAuthentication)
  SourceSinkScanner:      5 HIGH (pickle.loads), 3 MEDIUM (Rust Command::new)
  SourceIsolationChecker: pending (see TODO below)
  SourceTaintTracker:     pending (see TODO below)
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

PENDING = [
    "SourceIsolationChecker: run on all Python files — check for tenant/org boundary gaps",
    "SourceTaintTracker: trace user-controlled flow inputs to session storage (flow executor PLAN_CONTEXT_*)",
    "debug view (authentik/core/views/debug.py): verify not exposed in prod; check AllowAny info leak",
    "GeoIP API (authentik/policies/geoip/api.py): verify AllowAny is intentional; check for info leak",
    "Go outpost code: review internal/outpost/ and cmd/ (LDAP, RADIUS, proxy outposts)",
    "Expression engine (authentik/lib/expression/): check for Python eval/exec injection via policy expressions",
    "Blueprint import (authentik/blueprints/): check for YAML deserialization or template injection",
    "Outpost IPC (authentik/outposts/channels/): WebSocket IPC between outpost and core, review auth",
]


def print_findings():
    """Print all confirmed findings."""
    print("=" * 70)
    print("Authentik Source RE — Confirmed Findings")
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
