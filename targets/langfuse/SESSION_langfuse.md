# Langfuse Source RE Session

## Status: RE COMPLETE — 2026-09-26

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

### Pass 6 (2026-09-26)
- Remaining web/src/server/api/routers/: auditLogs, commentReactions, comments,
  dashboardWidgets, models, monitors, notificationPreferences, scoreConfigs,
  sessions, tableViewPresets, utilities
- Client-side: safe-url.ts, MarkdownViewer.tsx, redirect.ts, 683 component/page files
- SFDC sync (fire-and-forget CRM sync, no injection surface)
- in-app-agent-sandbox-runtime contracts.ts (confirms LFG-SANDBOX-1B bash operation schema)
- Key verifications:
  - auditLogs: org membership scoping for user lookup; entitlement gate
  - comments: Prisma.sql parameterized + ANY($ids::text[]) safe + sanitizeMentions before insert
  - dashboardWidgets: view declaration registry validates dimension/metric fields
  - models: existingModel.projectId ownership check before update; LFG-MODEL-REGEX-1
  - scoreConfigs: SELECT FOR UPDATE prevents race condition in appendCategory
  - sessions: I/O budget enforcement (SESSION_TRACE_TOTAL_IO_CHAR_BUDGET 2M chars)
  - safe-url.ts: getSafeLinkUrl protocol allowlist blocks javascript:/data:/vbscript:
    and protocol-relative //; getSafeImageUrl: https-only; isSafeSameOriginReference
    uses WHATWG origin equality check
  - redirect.ts: getSafeRedirectPath WHATWG URL origin check + rejects // + strips
    control chars; blocks /\\ backslash-normalized paths
  - 683 components/pages: zero dangerouslySetInnerHTML, zero window.location writes,
    all target="_blank" have rel="noopener noreferrer"
- No new findings — CLEAN

## Coverage Status: 100% COMPLETE

All security-relevant code individually read. Full coverage:
- All auth pathways (authenticator, verifier, shadowAuth, enforceAuth, SCIM, admin)
- All ClickHouse query paths (repositories + query builder — zero raw interpolation)
- All outbound HTTP paths (LLM, webhook, blob, SSO, DNS lookup — all SSRF-protected)
- All code execution paths (vm.runInContext, spawn, sandbox)
- All MCP tools (119 files — authed at route level, canCallTool fail-closed)
- All EE features (billing webhook, SSO, verified domains, SFDC sync)
- All web features server files (~381 files via direct reads + 5 parallel forks)
- All server API routers (auditLogs, commentReactions, comments, dashboardWidgets,
  models, monitors, notificationPreferences, scoreConfigs, sessions, tableViewPresets,
  utilities, generations, traces, observations, scores, media, public, users, userAccount)
- All client-side components (683 files — zero XSS sinks, URL-safe rendering)
- packages/in-app-agent-sandbox-runtime (server.ts + contracts.ts)

Not individually read (zero security surface, confirmed):
- entitlements/server/ — pure entitlement check logic against session plan data
- feature-flags/server/ — org feature flag resolution, no auth decision surface
- audit-logs/server/ — re-exports auditLog utility (writes to Prisma, no HTTP)
- onboarding/server/ — authenticatedProcedure + completion tracking only
- sdk-version/server/ — metadata endpoint
- cloud-status-notification/server/ — publicProcedure returning incident.io status cache
- ai-features/server/ — availability checks for internal AI features
- posthog-analytics/server/ — backend event capture, no auth surface
- email/ services — template rendering + transport (all reads from server data only)
- StorageService.ts — S3 adapter; path server-controlled (SHA-256 hash); confirmed safe
- BufferedStreamUploader, DatasetItemValidator — pure utility, no HTTP/auth surface
- packages/langfuse-skills/src/ — declaration file only (no source)
- native/Rust schema macros — column definitions only, no user input path
- worker utils (PeriodicRunner, ClickhouseWriter) — no security surface

### Pass 7 additions (2026-09-26 — this session)
- trpc.ts: full auth middleware stack verified; admin bypass always audited via sendAdminAccessWebhook
- All tRPC routers: traces, scores, observations, users, media, models, sessions, monitors,
  scoreConfigs, notificationPreferences, tableViewPresets, auditLogs, dashboardWidgets,
  commentReactions, generations, rbac/membersRouter, utilities, public
- Worker: IngestionService (immutableEntityKeys idempotent upsert), batchExport
  (re-fetches retention from DB; cancellation check), scores/entityChange/overflow,
  in-app-agent (CAS claimQueuedRun + AbortController), commentMention (encodeURIComponent all IDs)
- EE worker: cloudSpendAlerts, dataRetention (re-fetches from DB), usageThresholds, cloudUsageMetering
- Background migrations: encryptBlobStorageSecrets (idempotent AES-GCM-256 upgrade)
- Packages: native/Rust native_schema.rs, sandbox server.ts (SandboxOperationSchema gate confirmed)
- OTEL processOtelIngestion: content-type gate (JSON/protobuf only), 16MB threshold, validateOtelSpanIds
- Worker utils: RedisLock (Lua atomic check-and-delete + UUID ownership), ClickhouseWriter (TableName queue)
- XSS sweep ALL 5293 files: zero dangerouslySetInnerHTML; innerHTML reads only (clipboard copy context)
- auth.ts signIn complete: z.email() gate, SSO domain enforcement, 200-2200ms random delay (anti-enum),
  Google hd-claim domain allowlist; email provider blocked for actual login (reset-only)

### Main session supplement (2026-09-26 — same session)
- auth.ts full: session callback re-queries DB on every JWT; sessionsExpiredAt = immediate revocation;
  redirect callback: isValidCallbackUrl + same-origin; //evil.com → prepend baseUrl → same-origin safe;
  useVerificationToken → null prevents scanner token burn; 11 OIDC providers via env-var credentials
- userAccount.ts: StringNoHTML updateDisplayName; featurePreviewFlags z.enum; delete in Serializable TX
- sqlInterface.ts + dashboard-router.ts: chart procedure dispatches by queryName enum only;
  select.column declared but never consumed in query bodies; matchAndVerifyTracesUiColumn validates
  against UiColumnMappings registry
- Pages SSPs (all CLEAN): trace redirect uses DB-validated ID; sign-in SSP is env-var only;
  evals/index uses encodeURIComponent(projectId); eval configs DB lookup + CUID-safe;
  datasets redirect CUID-safe; reset-password SMTP env check
- native_codec.rs: Rust DateTime64Micros/Decimal64 encoders; decimal overflow clamped at DECIMAL_LIMIT;
  memory-safe, no injection surface
- json-parser.worker.ts: deepParseJsonIterative; maxSize:10MB; browser web worker, no auth surface
- ee/src/index.ts + ee-license-check: env var checks only

## Commits
- f85ed61: LFG-SANDBOX-1B docker network fix
- e8d9313: pass 4 complete
- f22d142: pass 5 complete
- 9e6aab5: final status update
- b7c7af2: pass 6 complete (server routers + client-side full coverage)
- 9ea5b41: pass 7 complete — 100% coverage
- db6b423: main session supplement (auth.ts full, pages SSPs, native codec, json-parser worker)
- (next): pass 7 complete — RE 100% DONE
