# API Reverse Engineering

**File:** `modules/api_re.py`

## Why this exists

Three gaps existed before this module:

1. **HTTP API discovery was session-scripted.** Path fuzzing, OpenAPI harvesting, parameter inference, and injection probing each required separate tools. `api_re.py` wraps all 30 phases into one `run_re()` call with structured findings output.

2. **OWASP API Top 10 coverage was incomplete.** BOLA/IDOR, mass assignment, broken function level authorization, excessive data exposure, JWT attacks (alg=none, weak secrets, algorithm confusion), NoSQL injection, business logic abuse, and webhook SSRF each required manual one-off scripts.

3. **Protocol-layer attack surface (gRPC, GraphQL, SOAP, JSON-RPC, OAuth2, WebSocket) was not enumerable from one place.** This module probes all of them in a single pass.

---

## Usage

```python
from modules.api_re import run_re

api = run_re('http://target:8080', depth='normal')
api = run_re('http://target:8080', depth='deep', focus='jwt')
api = run_re('http://target:8080', focus='oauth2')
```

Depth options: `quick` / `normal` / `deep`
Focus options: `injection`, `schema`, `jwt`, `auth`, `bola`, `oauth2`, `grpc`, `graphql`, `soap`, `biz`, `ssrf`, `creds`, `cors`, `nosql`, `bfla`, `pii`, `timing`, `evasion`, `websocket`, `shadow`

CLI: `python api_re.py http://target:port [--depth deep] [--focus jwt] [--output report.json]`

---

## 30 phases

| Phase | Function | OWASP Coverage |
|---|---|---|
| 1 | `detect_framework` | API9 Improper Inventory |
| 2 | `harvest_openapi` + `parse_openapi` | Schema |
| 2b | `discover_versions` | API9 |
| 3 | `fuzz_paths` | Discovery |
| 3b | `probe_graphql` | GraphQL introspection |
| 3c | `discover_hidden_params` | Hidden params via JS |
| 4 | `probe_param` | Injection (path traversal, SQLi, SSTI, SSRF, XXE, prototype pollution) |
| 4b | `probe_verb_tampering` | API5 BFLA |
| 4c | `probe_content_type_switch` | Content-type confusion |
| 4d | `probe_param_pollution` | HPP |
| 4e | `probe_mass_assignment` | API3 Mass Assignment |
| 4f | `probe_bola` | API1 BOLA/IDOR |
| 4g | `analyze_tokens_in_response` | API2 JWT: alg=none, weak secret, kid, jku/x5u SSRF |
| 5 | `extract_info_from_errors` | Error leakage, stack traces, path disclosure |
| 6 | `map_state_changes` | Side-effect detection |
| 7 | `probe_rate_limiting` | API4 Rate limit absence |
| 8 | `probe_oauth2` | OAuth2/OIDC: redirect_uri, default creds, JWKS |
| 9 | `probe_grpc` | gRPC server reflection |
| 10 | `probe_graphql_advanced` | Batching, alias flooding, depth bombing, field suggestion |
| 11 | `probe_rate_limit_bypass` | IP header spoofing, path variation |
| 12 | `probe_wsdl_soap` | WSDL discovery, XXE in SOAP body |
| 13 | `probe_jsonrpc` | JSON-RPC method enumeration, batching |
| 14 | `probe_business_logic` | Numeric boundary, privilege escalation |
| 15 | `probe_webhook_ssrf` | Webhook SSRF: cloud metadata |
| 16 | `probe_default_creds` | Default credentials, user enumeration |
| 17 | `probe_cors` | CORS misconfiguration |
| 18 | `probe_jwt_alg_confusion` | RS256→HS256 confusion |
| 19 | `probe_nosql_injection` | MongoDB operator injection |
| 20 | `probe_bfla` | Admin path access, privileged operations |
| 21 | `probe_excessive_data_exposure` | PII, secrets, bulk data |
| 22 | `probe_host_header_injection` | Host header reflection, reset link poisoning |
| 23 | `probe_timing_oracle` | Timing-based user enumeration |
| 24 | `probe_second_order_injection` | Stored XSS/SQLi/SSTI |
| 25 | `probe_null_byte_evasion` | Null byte injection, WAF bypass |
| 26 | `probe_oauth_dynamic_reg` | Dynamic client registration, token introspection |
| 27 | `probe_websocket` | WebSocket upgrade, SSE streams |
| 28 | `probe_pagination_traversal` | Bulk enumeration via pagination |
| 29 | `probe_shadow_versions` | Deprecated/shadow API versions |
| 30 | `probe_oauth_state_pkce` | OAuth state CSRF, PKCE downgrade |

Phases 17–30 run via `ThreadPoolExecutor(max_workers=6)` with per-phase stdout capture. Due to the global `redirect_stdout` lock, they serialize in practice, runtime for deep scans is additive, not parallel.

---

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_HTTP_BYTES` | 4 MB | All HTTP response bodies via `_safe_read()` streaming |
| `TIMEOUT` | 10 s | All `requests` calls |

---

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings.

- All HTTP responses capped at `_MAX_HTTP_BYTES` (4 MB) via `_safe_read()` streaming helper: no CWE-770.
- No bare `except:`. All handlers use `except Exception:` or more specific.
- No file reads. No lief. No subprocess.
- Network socket reads go through `requests` with `stream=True` and the cap enforced before `_content` is set.

| Finding | Severity | Location | Description |
|---|---|---|---|
| Serialized "parallel" phases | MEDIUM | `_run_phase_captured` (line 131) | `redirect_stdout` requires global lock; phases 17–30 serialize despite 6-worker executor |
| Double `r.json()` call | LOW | `probe_graphql_advanced` (line 1235/1238) | JSON parsed twice in batch detection check |

---

## How it works

Discovers API endpoints through documentation scraping, response reflection, and path enumeration. For each discovered endpoint, a suite of probes tests for BOLA, mass assignment, injection, authentication bypass, and information disclosure. Probes are generated from the endpoint's parameter schema and sent with crafted payloads. Responses are analyzed for status code anomalies, data leakage, and error message disclosure.

---

## Example output

```
[CRITICAL] BOLA   GET /api/v1/users/{id}/profile
  detail: id parameter accepts any integer; no ownership check
  evidence: GET /api/v1/users/1337/profile → 200 OK (authenticated as user 9999)

[HIGH] MASS_ASSIGN   POST /api/v1/users
  detail: role field accepted and persisted in user creation request
  evidence: {"name":"test","role":"admin"} → 201 Created
```

---

## False positives

Rate-limit and authentication findings from internal networks or behind authenticated sessions are not external attack surface. Confirm endpoint reachability from an unauthenticated external perspective. Mass-assignment findings require confirmation that the extra fields are actually persisted or acted on by the server.

---

## Pipeline position

**Before this module:** Network access to the target API and basic authentication credentials or an unauthenticated endpoint map.

**After this module:** Feed injection and auth bypass findings to `FindingRegistry`. Surface exposure findings feed `PreAuthExposure`.

---

## Reading output

`run_re(base_url)` (module-level function) returns an `APIMap` populated with discovered `Endpoint` objects:

| Attribute | Content |
|:---|:---|
| `base_url` | Base URL of the target API |
| `endpoints` | `List[Endpoint]` — each with `path`, `methods`, `params`, `responses` |
| `auth_required` | `True` if authentication signals were detected |
| `framework` | Detected framework string (e.g., `'express'`, `'flask'`), or `None` |
| `version` | Detected API version string, or `None` |
| `findings` | List of free-form finding notes from the analysis |

Each `Endpoint` has: `path: str`, `methods: list`, `params: dict`, `responses: dict`, `vuln_signals: list`.

---

## See also

- [NetworkAnalyze](network-analyze.md) — port and service discovery before API RE
- [PreAuthExposure](preauth-exposure.md) — find unauthenticated code paths in the backend binary
- [FindingRegistry](registry.md) — record confirmed API findings
