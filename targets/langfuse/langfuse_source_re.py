"""
Langfuse source RE — pass 3 complete (2026-09-26)

Target  : langfuse/langfuse (open source LLM observability platform)
Repo    : https://github.com/langfuse/langfuse
Version : main branch, shallow clone 2026-09-26
Method  : 4-stage source RE via ablation source analyzers
          Stage 1: SourceContext (5293 files indexed)
          Stage 2: SourceEntryClassifier (40 API routes, 0 non-trivial NONE)
          Stage 3: SourceSinkScanner (3 HIGH, 41 MEDIUM, 6 LOW sinks)
          Stage 4: SourceIsolationChecker (1 CONFIRMED, 199 INFO)
          Stage 5: SourceTaintTracker (BFS backward from 3 HIGH sinks)
          Pass 3:  SSRF audit (LLM/webhook/blob), LLM key storage, admin routes,
                   AI gateway, SCIM, sandbox, dashboard query, IO streaming,
                   remaining route handlers, analytics integrations
Auditor : nicholas@nuclide-research.com

Findings summary (confirmed):
  LFG-SANDBOX-1B  HIGH  unauthenticated sandbox HTTP server (self-hosted)
  LFG-CODEEVAL-1  HIGH  vm.runInContext code eval escape (self-hosted)
  LFG-SCIM-1      LOW   cross-org user existence oracle
  LFG-MCP-1       LOW   CORS wildcard configuration footgun
  LFG-APIKEY-1    LOW   audit log confusion via mismatched public key
  LFG-ISO-1       LOW   unscoped batchAction update helper (latent IDOR)
  LFG-SANDBOX-1A  MED   prompt injection → auto-approved bash (PLAUSIBLE)

SSRF surface — pass 3 verdict: CLEAN (no new findings)
  LLM base URL:        validateLlmConnectionBaseURL → validateOutboundUrlHost →
                       CIDR blocklist (all RFC1918 + IMDS + NAT64) + DNS resolution
                       + redirect re-validation; cloud forces empty whitelist + HTTPS-only
  Webhook URL:         validateWebhookURL → same infrastructure, port 80/443 only
  Blob storage:        cloud enforces; self-hosted opt-in only (see LFG-BLOB-SSRF-1 INFO)
  LLM API key storage: encrypt() at rest, displaySecretKey truncated, never returned in API
  AI gateway:          HMAC signature verification (withGatewayResolveSignatureVerification)
  SCIM endpoint:       shadowAuth + org-scoped, Serializable TX for last-OWNER guard
  Sandbox server:      intentional zero-auth, security contract is microVM isolation

Run this module to reproduce the sweep and register confirmed findings:
    python3 targets/langfuse/langfuse_source_re.py --sweep /tmp/langfuse
    python3 targets/langfuse/langfuse_source_re.py --register
"""

import sys
from pathlib import Path

REPO_PATH = Path("/tmp/langfuse")

# ── confirmed findings ────────────────────────────────────────────────────────
#
# Status key: CONFIRMED | PLAUSIBLE | ELIMINATED | INFO
#
# Format mirrors binary RE findings: id, status, severity, cwe, title, description,
# file:line, deployment (cloud|self-hosted|all), notes.

FINDINGS = [
    {
        "id": "LFG-SANDBOX-1B",
        "status": "CONFIRMED",
        "severity": "HIGH",
        "cwe": "CWE-306",
        "title": "Unauthenticated sandbox HTTP server on Docker network (self-hosted)",
        "description": (
            "The in-app agent sandbox runtime listens on :5000 with no application-level "
            "authentication. POST /sandbox with operation=bash executes arbitrary shell via "
            "spawn('sh', ['-lc', command]). The Docker provider (self-hosted) connects directly "
            "to the container port with no auth token. Any process on the same Docker network "
            "gets unauthenticated RCE in the sandbox-server context."
        ),
        "file": "packages/in-app-agent-sandbox-runtime/src/server.ts",
        "line": 47,
        "deployment": "self-hosted",
        "attack_chain": (
            "SSRF from web container OR compromised sidecar on Docker network "
            "→ POST http://sandbox:5000/sandbox {operation:'bash', command:'id'} "
            "→ spawn('sh', ['-lc', 'id']) → arbitrary code in sandbox-server process"
        ),
        "notes": "Cloud deployment uses AWS Lambda MicroVMs; proxy token required. Self-hosted has no equivalent gate.",
    },
    {
        "id": "LFG-CODEEVAL-1",
        "status": "CONFIRMED",
        "severity": "HIGH",
        "cwe": "CWE-94",
        "title": "vm.runInContext code eval escape in insecure-local dispatcher (self-hosted)",
        "description": (
            "localCodeEvalDispatcher uses Node.js vm.runInContext to execute user-supplied "
            "TypeScript evaluator code. vm.runInContext is explicitly not a security sandbox "
            "(Node.js docs). Escape via prototype chain: {}.constructor.constructor('return process')(). "
            "Gated by LANGFUSE_CODE_EVAL_DISPATCHER=insecure-local or NODE_ENV=development. "
            "Self-hosted operators who set this env var expose worker RCE to any user who can "
            "create an evaluator."
        ),
        "file": "packages/shared/src/server/evals/localCodeEvalDispatcher.ts",
        "line": 52,
        "deployment": "self-hosted",
        "attack_chain": (
            "User creates evaluator with malicious TypeScript code "
            "→ LANGFUSE_CODE_EVAL_DISPATCHER=insecure-local set "
            "→ vm.runInContext executes user code in worker process "
            "→ prototype chain escape → process.env, file system, network access"
        ),
        "notes": "Production cloud uses AWS Lambda. Warning is logged. Gate is a single env var string comparison.",
    },
    {
        "id": "LFG-SANDBOX-1A",
        "status": "PLAUSIBLE",
        "severity": "MEDIUM",
        "cwe": "CWE-74",
        "title": "Prompt injection → auto-approved sandbox bash (cloud)",
        "description": (
            "The in-app agent bash tool is in IN_APP_AGENT_LOCAL_AUTO_APPROVED_TOOL_NAMES — "
            "no human confirmation gate. The LLM generates the bash command from user natural language "
            "and any Langfuse data it reads via MCP tools (traces, prompts, scores). Adversarial "
            "content in stored Langfuse data → prompt injection → arbitrary bash in microVM. "
            "egressNetworkConnectorArn is optional; unconfigured deployments have full outbound network."
        ),
        "file": "packages/shared/src/in-app-agent/server/mcpPolicy.ts",
        "line": 436,
        "deployment": "cloud",
        "attack_chain": (
            "Attacker stores malicious content in a Langfuse trace/prompt/score "
            "→ in-app agent reads it via MCP during a user session "
            "→ LLM instruction injection → bash tool called with attacker payload "
            "→ auto-approved, no human gate → executes in microVM sandbox"
        ),
        "notes": "Requires access to store data AND a user triggering the in-app agent. Severity conditional on microVM egress config.",
    },
    {
        "id": "LFG-SCIM-1",
        "status": "CONFIRMED",
        "severity": "LOW",
        "cwe": "CWE-200",
        "title": "Cross-org user existence oracle via SCIM GET /Users/{id}",
        "description": (
            "SCIM GET /Users/{id} fetches prisma.user.findUnique({ where: { id } }) globally "
            "before the org membership check. Two distinct 404 error messages: "
            "'User not found' (user doesn't exist) vs 'User not found in organization' "
            "(user exists but not in caller's org). Org-scoped SCIM caller can oracle whether "
            "any UUID belongs to a user in a different organization."
        ),
        "file": "web/src/pages/api/public/scim/Users/[id].ts",
        "line": 394,
        "deployment": "all",
        "attack_chain": (
            "Obtain valid org-scoped API key with admin-api entitlement "
            "→ enumerate UUIDs via GET /api/public/scim/Users/{uuid} "
            "→ 'User not found in organization' confirms UUID is a valid user in another org"
        ),
        "notes": "Requires org API key with admin-api entitlement. Impact: user enumeration across orgs.",
    },
    {
        "id": "LFG-MCP-1",
        "status": "CONFIRMED",
        "severity": "LOW",
        "cwe": "CWE-942",
        "title": "MCP CORS wildcard disables all origin enforcement",
        "description": (
            "LANGFUSE_MCP_ALLOWED_HOSTS=* bypasses the entire Host/Origin validation block "
            "in the MCP endpoint security handler. Any origin can issue MCP requests. "
            "Combined with an authenticated user's browser directed to a malicious page, "
            "this is a CSRF vector against all MCP write tools (createPrompt, deleteDataset, etc.)."
        ),
        "file": "web/src/features/mcp/server/security.ts",
        "line": 69,
        "deployment": "all",
        "attack_chain": (
            "Operator sets LANGFUSE_MCP_ALLOWED_HOSTS=* "
            "→ all Host/Origin checks skipped "
            "→ malicious page in authenticated user's browser "
            "→ cross-origin POST /api/public/mcp with user's session cookie "
            "→ MCP write tool executed on behalf of user"
        ),
        "notes": "Configuration footgun. Wildcard is intentional for self-hosted flexibility but eliminates origin security.",
    },
    {
        "id": "LFG-APIKEY-1",
        "status": "CONFIRMED",
        "severity": "LOW",
        "cwe": "CWE-287",
        "title": "Public key not validated against secret key — audit log confusion",
        "description": (
            "Basic auth looks up the API key by SHA256(secretKey), not by publicKey. "
            "If the submitted public key doesn't match the stored one, only logger.warn fires "
            "and authentication succeeds. Intentional for credential rotation but means audit "
            "logs may record a public key that doesn't belong to the authenticated credential. "
            "Not an authentication bypass — attacker still needs the valid secret key."
        ),
        "file": "web/src/features/public-api/server/apiAuth.ts",
        "line": 178,
        "deployment": "all",
        "attack_chain": (
            "Attacker obtains a valid secret key (e.g. via exposure) "
            "→ authenticates with anyPublicKey:validSecretKey "
            "→ audit logs record the fake publicKey "
            "→ confuses incident response; attacker activity attributed to wrong key"
        ),
        "notes": "Intentional design for rotation support. Impact: forensic/audit only.",
    },
    {
        "id": "LFG-ISO-1",
        "status": "CONFIRMED",
        "severity": "LOW",
        "cwe": "CWE-639",
        "title": "Unscoped batchAction update helper — IDOR precondition",
        "description": (
            "commitTraceDeleteBatchActionState() updates prisma.batchAction by id only "
            "with no projectId/orgId in the where clause. The function is a narrow helper "
            "that relies entirely on callers to validate ownership. No path from a public "
            "HTTP route currently calls it with an unvalidated ID, but any future caller "
            "that passes a user-controlled batchActionId without prior validation would "
            "allow cross-project batchAction state overwrites."
        ),
        "file": "worker/src/features/batchAction/processTraceDeleteBatchAction.ts",
        "line": 204,
        "deployment": "all",
        "attack_chain": (
            "Future code path passes user-supplied batchActionId "
            "→ commitTraceDeleteBatchActionState(batchActionId, state) "
            "→ prisma.batchAction.update({ where: { id: batchActionId } }) "
            "→ overwrites any project's batchAction status"
        ),
        "notes": (
            "Currently no exploitable path — BullMQ worker context only. "
            "Risk: architectural — unscoped helper is a latent IDOR if call graph expands. "
            "Fix: add projectId to the where clause."
        ),
    },
    # Eliminated
    {
        "id": "LFG-SHADOW-1",
        "status": "ELIMINATED",
        "severity": "N/A",
        "cwe": "CWE-863",
        "title": "Shadow auth context substitution (ELIMINATED)",
        "description": (
            "Both pipelines read org/project from the same DB key record. authCtx is only "
            "used for secondary restriction checks in ingestion, never for primary data selection. "
            "scope.projectId from legacy governs all data writes. No divergence possible."
        ),
        "file": "web/src/features/public-api/server/shadowAuth.ts",
        "line": 55,
        "deployment": "all",
        "notes": "Traced: ctx only used in authorizeIngestionBatch (shadow mode, returns success), never for data scoping.",
    },
]

# ── INFO findings ─────────────────────────────────────────────────────────────

INFO_FINDINGS = [
    {
        "id": "LFG-MASKING-1",
        "title": "Ingestion masking fail-open by default",
        "file": "packages/shared/src/server/ee/ingestionMasking/applyIngestionMasking.ts",
        "line": 210,
        "note": "LANGFUSE_INGESTION_MASKING_CALLBACK_FAIL_CLOSED defaults false. Availability→confidentiality path for EE compliance deployments.",
    },
    {
        "id": "LFG-WORKER-API-1",
        "title": "Worker /health /ready params unauthenticated",
        "file": "worker/src/app.ts",
        "line": 114,
        "note": "failIfEventPropagationStuck / failIfQueueConsumptionStuck exposed with no auth. Network-policy-only gate.",
    },
    {
        "id": "LFG-MEDIA-1",
        "title": "SVG/HTML upload allowed; XSS if same-origin media serving",
        "file": "web/src/pages/api/public/media/index.ts",
        "line": None,
        "note": "MediaContentType includes text/html and image/svg+xml. Default S3/GCS uses separate domain (safe). Self-hosted same-origin serving → stored XSS.",
    },
    {
        "id": "LFG-CH-QUERY-1",
        "title": "Fragile ClickHouse raw-interpolation pattern in view builder",
        "file": "packages/shared/src/server/",
        "line": None,
        "note": "queryBuilder uses raw string interpolation for column/table names from hardcoded view declarations. Safe now; injection surface if any view ever pulls a field from user-supplied config.",
    },
    {
        "id": "LFG-BLOB-SSRF-1",
        "title": "Blob storage endpoint SSRF validation opt-in on self-hosted",
        "file": "packages/shared/src/server/services/blobStorageEndpointValidation.ts",
        "line": 68,
        "note": (
            "isBlobStorageEndpointValidationEnabled() returns false when no whitelist env vars "
            "(LANGFUSE_BLOB_STORAGE_ENDPOINT_WHITELISTED_HOST/IPS/IP_SEGMENTS) are set on self-hosted. "
            "A self-hosted operator configuring a malicious or SSRF-reachable blob endpoint is not "
            "validated at save time. Cloud enforces strict whitelist (NEXT_PUBLIC_LANGFUSE_CLOUD_REGION). "
            "TODO comment in source: 'TODO(next major): enforce for self-hosted even with no allowlist'. "
            "Risk: self-hosted admin who is themselves the attacker, or misconfigured managed deployment."
        ),
    },
]


def print_findings():
    """Print all confirmed findings in RE module format."""
    print(f"Langfuse Source RE — Pass 3 Complete  ({len(FINDINGS)} findings, {len(INFO_FINDINGS)} INFO)")
    print("=" * 70)
    for f in FINDINGS:
        print(f"\n[{f['id']}] {f['status']} {f['severity']}  {f['cwe']}")
        print(f"  {f['title']}")
        print(f"  {f['file']}:{f['line'] or '?'}  [{f['deployment']}]")
        print(f"  {f['description'][:120]}...")
    print("\nINFO:")
    for f in INFO_FINDINGS:
        print(f"  [{f['id']}] {f['title']}")


# ── taint tracker confirmed paths ─────────────────────────────────────────────
#
# Produced by SourceTaintTracker.trace_all() against main branch 2026-09-26.
# Only LOW confidence because all HIGH sinks cross an async queue boundary
# (BullMQ Redis) or an inter-process HTTP boundary (sandbox :5000).
# Phase 1 regex tracker cannot auto-cross these — confirmed manually.
#
# LFG-CODEEVAL-1 confirmed chain (vm.runInContext lines 58 + 77):
#   evalJobCreatorQueueProcessor()  worker/src/queues/evalQueue.ts:102
#   → processObservationEval()      worker/src/features/evaluation/observationEval/observationEvalProcessor.ts:101
#   → executeCodeBasedEvaluation()  worker/src/features/evaluation/codeBased/executeCodeBasedEvaluation.ts:20
#   → runCodeBasedEvaluationDispatch()  packages/shared/src/server/evals/codeEvalExecution.ts:210
#   → dispatch()                    packages/shared/src/server/evals/localCodeEvalDispatcher.ts:25
#   → vm.runInContext()             line 58 / 77
#
# LFG-SANDBOX-1B confirmed zero paths (correct): sandbox runtime is a
# standalone HTTP server on :5000 — no function call path from the main app.
# Inter-process boundary: fetch("http://sandbox:5000/sandbox") from web container.
#
TAINT_PATHS = [
    {
        "sink_id": "LFG-CODEEVAL-1",
        "confidence": "LOW",  # queue-mediated path, not direct HTTP→sink
        "boundary": "BullMQ async queue (HTTP tRPC write → Redis → worker pickup)",
        "chain": [
            "worker/src/queues/evalQueue.ts:102  evalJobCreatorQueueProcessor [ENTRY]",
            "worker/src/features/evaluation/observationEval/observationEvalProcessor.ts:101  processObservationEval",
            "worker/src/features/evaluation/codeBased/executeCodeBasedEvaluation.ts:20  executeCodeBasedEvaluation",
            "packages/shared/src/server/evals/codeEvalExecution.ts:210  runCodeBasedEvaluationDispatch",
            "packages/shared/src/server/evals/localCodeEvalDispatcher.ts:25  dispatch",
            "packages/shared/src/server/evals/localCodeEvalDispatcher.ts:58  vm.runInContext [SINK]",
        ],
        "notes": "data enters chain as evaluator template code stored in DB by authenticated tRPC route; "
                 "vm.runInContext executes it in worker process when a trace triggers the eval rule",
    },
    {
        "sink_id": "LFG-SANDBOX-1B",
        "confidence": "BOUNDARY",  # inter-process — no function call path
        "boundary": "HTTP inter-process (web container → fetch :5000 → sandbox-server process)",
        "chain": [
            "web: POST /api/public/mcp or agent dispatch  [HTTP request origin]",
            "  → fetch('http://sandbox:5000/sandbox') with operation=bash  [IPC boundary]",
            "packages/in-app-agent-sandbox-runtime/src/server.ts:330  spawn('sh',['-lc',command]) [SINK]",
        ],
        "notes": "cross-process boundary; taint tracker confirms no in-process call path from web to sandbox",
    },
]


def run_sweep(repo_path: Path):
    """Re-run the source RE scanners against the repo and print results."""
    try:
        from ablation.analyzers.source_ingestion import SourceContext
        from ablation.analyzers.source_entry_classifier import SourceEntryClassifier
        from ablation.analyzers.source_sink_scanner import SourceSinkScanner
        from ablation.analyzers.source_isolation_checker import SourceIsolationChecker
        from ablation.analyzers.source_taint_tracker import SourceTaintTracker
    except ImportError:
        import os
        sys.path.insert(0, os.path.expanduser("~/ablation"))
        from ablation.analyzers.source_ingestion import SourceContext
        from ablation.analyzers.source_entry_classifier import SourceEntryClassifier
        from ablation.analyzers.source_sink_scanner import SourceSinkScanner
        from ablation.analyzers.source_isolation_checker import SourceIsolationChecker
        from ablation.analyzers.source_taint_tracker import SourceTaintTracker

    print(f"Building SourceContext for {repo_path} ...")
    ctx = SourceContext.from_path(repo_path)
    print(ctx.summary())
    print()

    print("── Entry Classifier ─────────────────────────────────")
    clf = SourceEntryClassifier.from_context(ctx)
    clf_results = clf.classify()
    none_routes = [r for r in clf_results if r.auth_level == "NONE" and not r.is_low_value]
    print(f"  Unauthenticated non-trivial routes: {len(none_routes)}")
    for r in none_routes[:10]:
        print(f"    {r.rel_path}")
    print()

    print("── Sink Scanner ─────────────────────────────────────")
    scanner = SourceSinkScanner.from_context(ctx)
    sink_hits = scanner.scan()
    highs = [h for h in sink_hits if h.severity in ("CRITICAL", "HIGH")]
    print(f"  HIGH/CRITICAL sinks: {len(highs)}")
    print(scanner.report(highs))
    print()

    print("── Isolation Checker ────────────────────────────────")
    checker = SourceIsolationChecker.from_context(ctx)
    iso_findings = checker.scan()
    confirmed = [f for f in iso_findings if f.severity == "CONFIRMED"]
    print(f"  CONFIRMED isolation failures: {len(confirmed)}")
    print(checker.report(confirmed))
    print()

    print("── Taint Tracker ────────────────────────────────────")
    tracker = SourceTaintTracker.from_context(ctx)
    tracker.build()
    cg = tracker.cg
    total_funcs = sum(len(v) for v in cg.func_defs.values())
    print(f"  Call graph: {total_funcs} functions, {sum(len(v) for v in cg.callees.values())} edges")
    high_sinks = [h for h in sink_hits if h.severity in ("CRITICAL", "HIGH")]
    taint_paths = tracker.trace_all(high_sinks)
    direct_high = [p for p in taint_paths if p.confidence in ("DIRECT", "HIGH")]
    print(f"  Taint paths: {len(taint_paths)} total  ({len(direct_high)} DIRECT/HIGH confidence)")
    if taint_paths:
        print(tracker.report(direct_high))


def register_findings():
    """Register confirmed findings into the Ablation finding registry."""
    from ablation.analyzers.finding_registry import FindingRegistry
    reg = FindingRegistry()

    confirmed = [f for f in FINDINGS if f["status"] == "CONFIRMED"]
    for f in confirmed:
        fid = reg.register(
            vendor="langfuse",
            product="langfuse",
            title=f["title"],
            description=f["description"],
            cwe_class=f["cwe"],
            severity=f["severity"],
            source="langfuse-source-re-2026-09-26",
        )
        print(f"Registered id={fid}: {f['id']} {f['title'][:60]}")

    reg.close()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Langfuse source RE")
    ap.add_argument("--sweep", metavar="REPO_PATH", help="Re-run scanners against repo")
    ap.add_argument("--register", action="store_true", help="Register confirmed findings into FindingRegistry")
    args = ap.parse_args()

    if args.sweep:
        run_sweep(Path(args.sweep))
    elif args.register:
        register_findings()
    else:
        print_findings()
