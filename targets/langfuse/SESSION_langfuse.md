# Langfuse Source RE Session

## Status: Pass 3 complete — 2026-09-26

## Completed

### Pass 1–2 (prior sessions)
- SourceContext: 5293 files indexed
- SourceEntryClassifier: 40+ API routes, 0 non-trivial NONE auth routes
- SourceSinkScanner: 3 HIGH (vm.runInContext, spawn, child_process), 41 MEDIUM, 6 LOW
- SourceIsolationChecker: 303 → 0 PLAUSIBLE, 21 → 1 CONFIRMED (LFG-ISO-1)
- SourceTaintTracker: confirmed call chains for LFG-CODEEVAL-1 and LFG-SANDBOX-1B
- Manual audits: ingestion pipeline SQL, ClickHouse identifiers, EE admin/SSO/RBAC

### Pass 3 (this session, 2026-09-26)
- SSRF audit: LLM base URL, webhook URL, blob storage endpoint
  - LLM/webhook: comprehensive protection (CIDR blocklist all RFC1918+IMDS+NAT64,
    DNS resolution of all A+AAAA records, redirect re-validation, cloud empty whitelist)
  - Blob storage: cloud enforces; self-hosted opt-in only → LFG-BLOB-SSRF-1 INFO
- LLM API key storage: encrypt() at rest, SafeLlmApiKeySchema strips key from responses
- Admin API: timing-safe compare, cloud-blocked by default (NEXT_PUBLIC_LANGFUSE_CLOUD_REGION)
- AI gateway: HMAC signature verify (withGatewayResolveSignatureVerification)
- SCIM endpoint: org-scoped shadowAuth + Serializable TX for last-OWNER guard
- Dashboard query stream: session auth + project membership + validateQuery()
- Trace IO streaming: z.enum(OBSERVATION_IO_STREAM_FIELDS) prevents column injection
- Sandbox server: intentional zero-auth, MicroVM security contract documented
- OTEL ingestion: createAuthedProjectAPIRoute + body size limit
- Annotation queues: createAuthedProjectAPIRoute, all ops use auth.scope.projectId
- Prompts API: createAuthedProjectAPIRoute, scoped to auth.scope.projectId

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
- LFG-CH-QUERY-1: ClickHouse raw interpolation pattern
- LFG-BLOB-SSRF-1: blob storage SSRF validation opt-in gap on self-hosted

## Next

Codebase RE substantially complete. Areas not yet read in detail:
- Dataset management routes (standard CRUD, createAuthedProjectAPIRoute pattern)
- Score management (same pattern)
- Experiment queue internals
- packages/shared/src/server/repositories/* (Clickhouse read paths, reviewed for SQL injection; not for logic bugs)

If continuing: focus on dataset/experiment query injection surface and eval template
prompt injection (adversarial user prompts stored in LLM evaluator templates).
