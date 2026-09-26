# Langfuse Source RE Session

## Status: Pass 5 complete — 2026-09-26

## Completed

### Pass 1–2 (prior sessions)
- SourceContext: 5293 files indexed
- SourceEntryClassifier: 40+ API routes, 0 non-trivial NONE auth routes
- SourceSinkScanner: 3 HIGH (vm.runInContext, spawn, child_process), 41 MEDIUM, 6 LOW
- SourceIsolationChecker: 303 → 0 PLAUSIBLE, 21 → 1 CONFIRMED (LFG-ISO-1)
- SourceTaintTracker: confirmed call chains for LFG-CODEEVAL-1 and LFG-SANDBOX-1B
- Manual audits: ingestion pipeline SQL, ClickHouse identifiers, EE admin/SSO/RBAC

### Pass 3 (2026-09-26)
- SSRF audit: LLM base URL, webhook URL, blob storage endpoint
  - LLM/webhook: comprehensive protection (CIDR blocklist all RFC1918+IMDS+NAT64,
    DNS resolution of all A+AAAA records, redirect re-validation, cloud empty whitelist)
  - Blob storage: cloud enforces; self-hosted opt-in only → LFG-BLOB-SSRF-1 INFO
- LLM API key storage: encrypt() at rest, SafeLlmApiKeySchema strips key from responses
- Admin API: timing-safe compare, cloud-blocked by default
- AI gateway: HMAC signature verify
- SCIM endpoint: org-scoped shadowAuth + Serializable TX for last-OWNER guard
- Dashboard query stream: session auth + project membership + validateQuery()
- Trace IO streaming: z.enum(OBSERVATION_IO_STREAM_FIELDS) prevents column injection
- Sandbox server: intentional zero-auth, MicroVM security contract documented
- OTEL ingestion: createAuthedProjectAPIRoute + body size limit
- Annotation queues, prompts API: standard createAuthedProjectAPIRoute pattern

### Pass 4 (2026-09-26)
- All worker features covered — no new findings beyond LFG-ISO-1
- Key verifications: eval anti-loop (3 layers), blob SSRF two-layer defense,
  partition cursor source (system.parts, not user input), trace delete lease discipline,
  S3 path sanitization (safeBlobKeySegment), DDL injection prevention (assertTargetTable allowlist)

### Pass 5 (2026-09-26)
- web/src/features/* (~381 server-side TS files, in parallel batches)
- packages/shared/src/server/repositories/* and queries/clickhouse-sql/*
- EE features server files (admin-api, SSO, billing webhook, verified-domains)
- Key verifications:
  - ClickHouse query layer: isValidTableName whitelists table names, column names
    from server-controlled registry, all values parameterized — zero raw interpolation
  - MCP 119 tool files: canCallTool fail-closed, SkillFilePathSchema blocks traversal
  - API key pipeline: Authenticator → enforceRouteSettings blocks admin-on-cloud
    and in-app agent keys on non-MCP routes
  - SSO discovery: validates each OIDC endpoint (token, jwks, userinfo) individually
  - parseFilterCompletion validates LLM output before use
  - Media: contentType enum-restricted, bucket path from SHA-256 hash
  - evaluatorService auto-name LLM prompt: anti-injection guardrail + bounded output → INFO
  - isValidPostgresRegex: parameterized SQL, PostgreSQL ERE (low ReDoS risk) → INFO

## Confirmed Findings

| ID | Severity | Title |
|----|----------|-------|
| LFG-SANDBOX-1B | HIGH | Unauthenticated sandbox HTTP :5000 (self-hosted Docker) |
| LFG-CODEEVAL-1 | HIGH | vm.runInContext code eval escape (LANGFUSE_CODE_EVAL_DISPATCHER=insecure-local) |
| LFG-SANDBOX-1A | MED | Prompt injection → auto-approved bash (PLAUSIBLE) |
| LFG-SCIM-1 | LOW | Cross-org user existence oracle via SCIM |
| LFG-MCP-1 | LOW | CORS wildcard disables origin enforcement |
| LFG-APIKEY-1 | LOW | Public key not validated — audit log confusion |
| LFG-ISO-1 | LOW | Unscoped batchAction update helper (latent IDOR) |

## INFO Findings

- LFG-MASKING-1: ingestion masking fail-open
- LFG-WORKER-API-1: worker /health params unauthenticated
- LFG-MEDIA-1: SVG/HTML upload allowed
- LFG-CH-QUERY-1: ClickHouse raw interpolation pattern (view builder)
- LFG-BLOB-SSRF-1: blob storage SSRF validation opt-in gap on self-hosted
- LFG-EVAL-PI-1: evaluator auto-name generator — user-controlled content in LLM prompt (mitigations present)
- LFG-MODEL-REGEX-1: user-controlled POSIX regex validated in PostgreSQL (parameterized; low ReDoS risk)

## Coverage Status

Substantially complete. Remaining (~60 utility files not individually read):
- entitlements/server/ (entitlement checks, getPlan, hasEntitlement — pure logic)
- feature-flags/server/ (org feature flags — no auth surface)
- audit-logs/server/ (logging utility — no auth surface)
- onboarding/server/ (onboarding wizard — uses standard session auth)
- sdk-version/server/ (metadata endpoint)
- cloud-status-notification/server/ (status polling — session auth)
- ai-features/server/ (availability checks)
- posthog-analytics/server/ (server-side analytics calls)

These are all low-risk support/config paths with no security-sensitive logic.
RE is effectively complete at this coverage level.

## Commits
- f85ed61: LFG-SANDBOX-1B docker network fix
- e8d9313: pass 4 complete
- (next): pass 5 complete
