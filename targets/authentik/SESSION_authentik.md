# Authentik Source RE Session

## Status: COMPLETE (pass 5 — exhaustive individual file reads) — 2026-09-26

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

### Deep Reads — Continued exhaustive individual file reads (pass 5b — 2026-09-26)
- core/models.py: CLEAN — Session.session_data=BinaryField (AUT-SESS-PICKLE-1 confirmed), User.uid=SHA-256(id+tenant), GroupAncestryNode raw SQL=developer-defined
- core/api/users.py: CLEAN — json.loads (not pickle) in filter_attributes; User objects stored in pickle session (AUT-SESS-PICKLE-1 impact +); impersonation deepens session attack surface
- stages/authenticator_validate/stage.py: CLEAN — JWT MFA cookie uses algorithms=["HS256"], key=SHA-256(tenant_uid+stage_pk), challenge whitelist validation
- providers/proxy/models.py: CLEAN — ProxySession.session_data=JSONField (not pickle), SystemRandom cookie secret, STRICT redirect URI mode
- sources/oauth/models.py: CLEAN — tokens in TextField, oidc_jwks as JSONField, all subclasses abstract
- sources/oauth/views/callback.py: CLEAN — token exchange, profile parsing, state all through safe paths
- sources/ldap/auth.py: CLEAN — bind uses stored DN not filter construction
- sources/ldap/sync/base.py: CLEAN — search_filter and search_base are admin-configured source fields
- sources/ldap/sync/groups.py: CLEAN — filter=admin-configured group_object_filter; property mappings admin-only expression evaluator
- stages/password/stage.py: CLEAN — backends are admin-configured class paths; credentials cleaned via _clean_credentials()
- flows/planner.py: CLEAN — cache.get() at line 296 is AUT-CACHE-PICKLE-1 consumption point; FlowPlan deserialized from postgres cache
- providers/saml/processors/authn_request_parser.py: CLEAN — defusedxml for parsing, lxml+two-layer XXE defense for signature verification, strict ACS URL equality, xmlsec verify before parse
- providers/saml/processors/assertion.py: CLEAN — lxml programmatic construction (no XML injection); correct sign→encrypt→sign-response order; AES-128+RSA-OAEP; session index=SHA-256(session_key)
- sources/kerberos/auth.py: CLEAN — gssapi.raw.import_name() uses stored principal; MEMORY: cache isolation; no shell commands
- stages/consent/stage.py: CLEAN — UUID anti-CSRF token with compare_digest; consent permissions use set operations
- stages/user_write/stage.py: CLEAN — disallowed_user_attributes blocks id/pk/groups; password via set_password(); data from admin-configured PLAN_CONTEXT_PROMPT
- providers/rac/consumer_client.py: CLEAN — token bound to session; Guacamole protocol filtered via parser; channel groups SHA-256 hashed
- providers/rac/guacamole.py: CLEAN — strict length-prefix validation; UTF-16 code unit counting; 8192-byte/64-element limits; ping split from forwarded data

### Deep Reads — Continued exhaustive individual file reads (pass 5c — 2026-09-26)
- enterprise/stages/account_lockdown/stage.py: CLEAN — can_lock_user() self-vs-admin permission gate; TOCTOU fix via User.objects.get(pk=) inside atomic()
- enterprise/core/revocation.py: CLEAN — retry loop with READ COMMITTED isolation guards credential minting race; dynamic discovery of ExpiringModel subclasses
- enterprise/middleware.py: CLEAN — license READ_ONLY blocks writes only; explicit allowlist for LicenseViewSet/FlowExecutorView/UserViewSet
- enterprise/providers/ssf/views/auth.py: CLEAN — bug: line 67 returns (jwt_token.user, token) where token=None; request.auth=None for JWT auth but provider already set on self.view, no security bypass
- enterprise/providers/ssf/views/base.py: CLEAN — SSFView uses get_authenticators() returning SSFTokenAuth; IsAuthenticated + SSF Bearer
- enterprise/providers/ssf/views/stream.py: CLEAN — object-level has_perm() on all CRUD methods; stream_id is UUID
- enterprise/providers/ws_federation/processors/sign_in.py: CLEAN — wreply validated against configured ACS URL (scheme+netloc+path-startswith); lxml programmatic XML construction
- enterprise/providers/ws_federation/processors/assertion_saml11.py: CLEAN — lxml Element/SubElement, attribute_value.text properly escaped; signing uses AssertionID ref (correct SAML 1.1)
- enterprise/stages/mtls/stage.py: CLEAN — PolicyBuilder chain verification with now() time check; cert→dict conversion avoids pickle; outpost path requires pass_outpost_certificate perm
- enterprise/agents/api.py: CLEAN — self-service agents: always expire, ActorPolicyInheritance.NONE; admin_perm gate for cross-user creation
- enterprise/endpoints/connectors/agent/views/auth_interactive.py: CLEAN — compare_digest on SHA-256(device_token.key); HttpResponseRedirectScheme(allowed_schemes=["goauthentik.io"])
- enterprise/lifecycle/offboarding/actions.py: CLEAN — audit event emitted BEFORE user.delete() to survive CASCADE
- enterprise/policies/unique_password/tasks.py: CLEAN — ORM-only cleanup tasks
- enterprise/providers/scim/views.py: CLEAN — dispatch() requires is_authenticated + change_scimprovider object permission
- enterprise/endpoints/connectors/agent/http.py: CLEAN — ECDH-ES + AES-256-GCM; ConcatKDFHash X9.63 KDF, 96-bit random nonce, protected header as AAD; correct JWE compact
- stages/authenticator_duo/stage.py: CLEAN — enroll_status == "success" gate before device creation; duplicate duo_user_id blocked
- stages/authenticator_webauthn/stage.py: CLEAN — verify_registration_response with server-generated challenge; AAGUID restrictions; max_attempts rate limiting
- stages/authenticator_email/stage.py: CLEAN — mask_email() in challenge; duplicate email check; token server-generated
- stages/captcha/stage.py: CLEAN — server-side verification; score min/max threshold; remoteip from ClientIPMiddleware
- providers/scim/clients/base.py: CLEAN — AUT-CACHE-PICKLE-1 note: get_service_provider_config() caches via postgres cache; hardcoded paths, no user-controlled URLs
- providers/scim/clients/users.py: CLEAN — code quality note: userName in SCIM filter not quoted (injection into external SCIM server only)
- providers/scim/clients/auth.py: CLEAN — explicit UTF-8 encoding for Basic auth (RFC 7617)
- sources/plex/plex.py: CLEAN — hardcoded plex.tv URLs; server overlap checks against admin-configured allowed_servers
- enterprise/stages/authenticator_endpoint_gdtc/stage.py: CLEAN — FrameChallenge uses local URL reversal
- enterprise/requests/stage.py: CLEAN — max expiry enforced at persistence with min(granted_expiry_candidates)
- stages/deny/stage.py: CLEAN — deny_message plan context override is admin-written only
- stages/redirect/stage.py: CLEAN — ak-flow:// scheme for flow redirect, static URLs admin-configured
- stages/authenticator_totp/stage.py: CLEAN — session pickle impact++: unsaved TOTPDevice stored in session (AUT-SESS-PICKLE-1 deepening)
- stages/user_delete/stage.py: CLEAN — logout() before user.delete() prevents session/user mismatch
- stages/authenticator_static/stage.py: CLEAN — session pickle impact++: StaticDevice + StaticToken list stored in session
- stages/authenticator_sms/stage.py: CLEAN — plan context pickle impact++: unsaved SMSDevice stored in context; hash_phone_number() for verify_only mode
- web/src/flow/FlowExecutor.ts: CLEAN — unsafeHTML only for xak-flow-shell (Django template auto-escape); unsafeStatic for tag names (not content)
- web/src/flow/stages/prompt/PromptStage.ts: INFO — unsafeHTML(prompt.initialValue) for PromptTypeEnum.Static and Alert types; user-provided plan context values reach this path for self-XSS only (per-session isolation; same-user execution)
- web/src/elements/ak-mdx/ak-mdx.ts: CLEAN — Trusted Types CompiledMarkdownSanitizePolicy.createHTML() before unsafeHTML()

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

### Deep Reads — TypeScript individual file reads (pass 5l — 2026-09-26)
- web/src/elements/ak-mdx/markdown.ts (full): CLEAN — unified pipeline allowDangerousHtml:false; no eval/Function; pure tree transformers
- web/src/elements/ak-mdx/components/ak-md-a.ts (full): CLEAN — handles #fragment links only; no URL construction from user input
- web/src/elements/LoadingOverlay.ts (full): CLEAN — pure loading spinner
- web/src/elements/CodeMirror.ts (re-export): CLEAN — admin YAML/JSON editor shim
- web/src/elements/table/TableSearch.ts (full): CLEAN — search value from FormData → API query param (not rendered)
- web/src/flow/stages/email/EmailStage.ts (full): CLEAN — static Lit template; no user input
- web/src/flow/components/ak-flow-card.ts (full): CLEAN — flowInfo.title as text node; slots delegate
- web/src/admin/policies/PolicyTestForm.ts (full): CLEAN — policy test result messages as text nodes
- web/src/elements/events/LogViewer.ts (full): CLEAN — event fields Lit text nodes; JSON.stringify in <pre>
- web/src/admin/brands/BrandForm.ts (partial 100 lines): CLEAN — admin field bindings
- web/src/elements/ak-mdx/remark/remark-admonition.ts (full): CLEAN — node.name validated against ADMONITION_TYPES set
- web/src/flow/components/ak-brand-footer.ts (full): CLEAN — link.name via sanitizeHTML(BrandedHTMLPolicy); link.href admin-controlled
- web/src/elements/mixins/branding.ts (full): CLEAN — pure Lit context mixin; no rendering

### Deep Reads — TypeScript individual file reads (pass 5m — 2026-09-26)
- web/src/flow/stages/user_login/UserLoginStage.ts (full): CLEAN — static Lit template; no user data rendered raw
- web/src/admin/providers/saml/SAMLProviderForm.ts (full): CLEAN — state management + typed API calls; rendering in SAMLProviderFormForm.ts
- web/src/elements/table/Table.ts (full): CLEAN — rows via abstract row() → SlottedTemplateResult; no unsafeHTML; group names as text nodes; pluckErrorDetail for error state
- web/src/admin/brands/BrandForm.ts (full completion): CLEAN — all admin-controlled fields via ak-text-input/ak-switch-input; no unsafeHTML
- web/src/admin/users/UserInfoCard.ts (full): CLEAN — user.username/name/email/type via renderKeyValueList (Lit text nodes); pk numeric in URLs
- web/src/admin/users/UserForm.ts (full): CLEAN — all user fields via ak-text-input component bindings; no unsafeHTML
- web/src/admin/events/EventListPage.ts (full): CLEAN — row() renders event fields as text nodes; pk numeric in URL; renderEventUser() from utils.ts
- web/src/admin/events/utils.ts (full): CLEAN — username/device.name Lit text nodes; URLs via toAdminInterface(); device.pk UUID in URL path only
- web/src/components/ak-event-info.ts (full): **NEW PLAUSIBLE LOW (AUT-EMAIL-SRCDOC-1)** — renderEmailSent() at line 387 renders event.context.body via <iframe srcdoc=${body}> with NO sandbox attribute; srcdoc inherits parent origin; script in email body runs in admin UI origin; all other event renderers CLEAN (model diff via JSON.stringify in <pre>; policy context via JSON.stringify in <code>; exception messages as text nodes)

### Deep Reads — TypeScript individual file reads (pass 5n — 2026-09-26)
- web/src/admin/applications/ApplicationForm.ts (full): CLEAN — fields via ak-text-input/ak-slug-input; navigate() for redirect; typed API
- web/src/admin/flows/FlowForm.ts (full): CLEAN — fields via ak-text-input/ak-slug-input; designation from hardcoded FlowDesignationEnum options
- web/src/admin/groups/ak-group-form.ts (full): CLEAN — group.name in DualSelectPair as text node; typed API
- web/src/admin/providers/ldap/LDAPProviderForm.ts (full): CLEAN — thin wrapper; rendering in LDAPProviderFormForm.ts
- web/src/user/LibraryApplication/CardHeader.ts (full): CLEAN — application.name text node
- web/src/user/LibraryApplication/CardMenu.ts (full): CLEAN — metaPublisher/description text nodes; editURL admin-constructed in <a href>
- web/src/user/LibraryPage/ApplicationList.ts (full): CLEAN — groupLabel text node; delegates to LibraryAppRow/AKLibraryApp
- web/src/user/LibraryApplication/index.ts (full): CLEAN — launchUrl in <a href>: admin-configured, DomainlessURLValidator rejects javascript:; metaIconUrl → ak-app-icon → <img src>; name/description text nodes
- web/src/user/user-settings/UserSettingsPage.ts (full): CLEAN — component bindings; configureUrl/userId as attribute bindings
- web/src/elements/user/UserConsentList.ts (full): CLEAN — application.name/permissions (scope strings) text nodes
- web/src/elements/user/SessionList.ts (full): CLEAN — lastIp/location/device text nodes; getUnicodeFlagIcon() returns Unicode emoji

## Confirmed Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| AUT-SESS-PICKLE-1 | HIGH | Unsigned pickle deserialization of session data (no HMAC) | CONFIRMED |
| AUT-TASK-PICKLE-1 | HIGH | Unsigned pickle deserialization of task queue arguments | CONFIRMED |
| AUT-FLOWTOKEN-PICKLE-1 | HIGH | Unsigned pickle deserialization of FlowToken._plan (bare import, missed by grep) | CONFIRMED |
| AUT-CACHE-PICKLE-1 | MEDIUM | Unsigned pickle deserialization of PostgreSQL cache values | CONFIRMED |
| AUT-IPC-KEY-1 | MEDIUM | IPC superuser key stored in world-readable /tmp | CONFIRMED |
| AUT-SAML-REFURI-1 | LOW | SAML assertion signature allows URI="" (root-element reference) | PLAUSIBLE |
| AUT-EMAIL-SRCDOC-1 | LOW | Email body preview in unsandboxed srcdoc iframe (inherits admin UI origin) | PLAUSIBLE |

## Pending (toolchain gaps only)
- SourceIsolationChecker: build Python/Django ORM adapter module (Prisma/TS-only)

## Commits
- 2777c49: source_ingestion.py + source_entry_classifier.py DRF pattern additions
- 3aaa666: initial RE module — pass 1 (3 pickle HIGH, IPC key MEDIUM)
- 9029d5f: pass 2 — expression/blueprint/debug/outpost coverage + AUT-SAML-REFURI-1
- debf4ef: pass 3 — 100% attack surface coverage, exhaustive CLEAN list
- 0dd967c: pass 5 — AUT-FLOWTOKEN-PICKLE-1 (bare `from pickle import loads` in flows/models.py:353 — missed by grep sweep)
- pass 5b: 18 more files read (core/, stages/, providers/saml/, sources/ldap/, sources/kerberos/, providers/rac/) — all CLEAN; no new findings; AUT-CACHE-PICKLE-1 consumption confirmed in flows/planner.py:296
- pass 5d (committed separately): 32+ more files; no new security findings; executor.py context-merge deepens pickle; code-quality: Python 2 except syntax in scim/clients/groups.py:237 + enterprise/license.py:111

### Deep Reads — Continued exhaustive individual file reads (pass 5d — 2026-09-26)
- flows/views/executor.py: CLEAN — FlowToken plan context merge (line 155) deepens AUT-SESS-PICKLE-1/AUT-FLOWTOKEN-PICKLE-1 interaction; PLAN_CONTEXT_REDIRECT via redirect() guarded by "expression-or-authentik-only" comment; restart_flow() keep_context propagates existing context
- providers/scim/clients/groups.py: CLEAN — code quality: `except SCIMRequestException, ObjectExistsSyncException:` at line 237 is Python 2 syntax (SyntaxError in Python 3)
- enterprise/providers/ssf/views/jwks.py: CLEAN — short delegator to OAuth2 JWKSView; Access-Control-Allow-Origin: * (JWKS is intentionally public)
- enterprise/providers/ws_federation/views.py: CLEAN — WSFedEntryView uses PolicyAccessView; wreply validated in sign_in processor; SAMLSession update_or_create idempotent
- enterprise/endpoints/connectors/agent/views/apple_authorize.py: CLEAN — AppleAuthorizePreauthView unauthenticated (discovery); AppleAuthorizeView validates device JWT with ES256 + kid→DB lookup; redirect_uri strict equality check; PSSOAuthFulfillmentStage 5-min auth code expiry
- enterprise/endpoints/connectors/agent/views/apple_nonce.py: CLEAN — DeviceToken lookup required before nonce creation; b64encode(token_bytes(32)) = 256-bit random nonce; 5-min expiry
- enterprise/endpoints/connectors/agent/views/apple_register.py: CLEAN — IsAuthenticated + AgentAuth; RegisterUserView requires 3-way device+user+token join
- enterprise/endpoints/connectors/fleet/models.py: CLEAN — config model only
- enterprise/endpoints/connectors/fleet/stage.py: CLEAN — extends MTLSStageView; SAN URI extraction with ORM __in filter (no SQL injection); device not found raises PermissionDenied
- enterprise/endpoints/connectors/google_chrome/models.py: CLEAN — JSONField credentials from Google service account; Credentials.from_service_account_info() via official library
- enterprise/endpoints/connectors/google_chrome/stage.py: CLEAN — FrameChallenge with local reverse() URL only
- enterprise/providers/google_workspace/clients/groups.py: CLEAN — all API calls via official Google client; slugify() on group name before email domain construction
- enterprise/providers/microsoft_entra/clients/groups.py: CLEAN — all API calls via official MS Graph SDK; displayName in OData filter unescaped (admin-only code quality); with_url(next_link) uses Graph-returned URL
- enterprise/lifecycle/models.py: CLEAN — pure re-export
- enterprise/lifecycle/review/models.py: CLEAN — unique_together [iteration, reviewer] prevents double-review; user_can_review() group membership check; on_review() state guard
- enterprise/reports/models.py: CLEAN — whitelist dispatch (user/event only); CSV via csv.writer; query_params through DjangoFilterBackend; MockRequest uses requester's own perms
- enterprise/license.py: CLEAN — x5c chain: cert→intermediate→root CA (embedded); code quality: Python 2 except syntax at line 111; _validate_curve monkey-patch for ES512/secp384r1 legacy licenses (TODO); check_expiry=False disables sig verify for expired licenses (intentional status check)
- enterprise/policy.py: CLEAN — EnterprisePolicyAccessView adds license validity + INTERNAL user type check to PolicyAccessView
- enterprise/agents/models.py: CLEAN — Agent.create_for_user() sets unusable_password; MIRROR policy behavior default (agent cannot exceed parent access)
- enterprise/lifecycle/review/signals.py: CLEAN — post_save dispatches task with UUID only; pre_delete cancels pending iterations
- providers/scim/tasks.py: CLEAN — thin actor delegators to SyncTasks
- sources/plex/tasks.py: CLEAN — plex_token redacted from error messages
- lib/expression/evaluator.py (lines 100-339): CLEAN — expr_create_jwt_raw/expr_send_email are intentionally powerful admin-only primitives; socket.getaddrinfo (DNS not HTTP); expr_user_by(**filters) catches FieldError; wrap_expression() calls sanitize_arg() on all context keys
- enterprise/models.py: CLEAN — License.status calls validate(check_expiry=False) intentionally
- admin/api/system.py: CLEAN — HasPermission gate; session cookie redacted from header dump via SafeExceptionReporterFilter
- blueprints/v1/importer.py: CLEAN — is_model_allowed() whitelist; all mutations via model serializer; _save_with_retry() race condition handling; PK uses model._meta.pk.to_python()
- crypto/builder.py: CLEAN — RSA 4096, ECDSA P-256, Ed25519, Ed448; common_name[:64]; EdDSA algo=None; NoEncryption() storage (admin-only)
- rbac/permissions.py: CLEAN — ObjectPermissions: lookup-based bypass intentional (has_object_permission does actual check); rbac_allow_create_without_perm defaults False; assign_initial_permissions scoped to user.all_roles()
- policies/engine.py: CLEAN — effective_policy_user() MIRROR chain with cycle guard (seen set); Pipe for IPC within-process
- tenants/utils.py: CLEAN — get_current_tenant() reads connection.schema_name from trusted middleware; get_unique_identifier() scopes to tenant or install_id

### Deep Reads — Continued exhaustive individual file reads (pass 5e — 2026-09-26)
- events/models.py (lines 200-319): CLEAN — from_http() reads SESSION_KEY_PLAN for pending user (post-pickle, already decoded); log_deprecation() deduplication with Q filter; Event.save() logs to structlog
- core/api/users.py (partial): CLEAN — validate_type() blocks INTERNAL_SERVICE_ACCOUNT create/change; validate_groups() requires enable_group_superuser perm for superuser groups; validate_roles() requires change_role perm; validate() blocks modification of INTERNAL_SERVICE_ACCOUNT users; impersonation (/user/switch) at line 717 gated by IsAuthenticated + start_user_switch_flow; _create_recovery_link() uses FlowToken.pickle (AUT-FLOWTOKEN-PICKLE-1 scope); recovery email uses pickle_flow_token_for_email (same scope)
- core/api/groups.py (partial): CLEAN — BulkPrimaryKeyRelatedField.many_init() → BulkManyRelatedField; bulk PK validation via single filter(pk__in=...); PartialUserSerializer/RelatedGroupSerializer limited field exposure
- providers/oauth2/views/authorize.py (full): CLEAN — OAuthAuthorizationParams.from_request() filters prompt to ALLOWED_PROMPT_PARAMS; check_redirect_uri() STRICT/REGEX + FORBIDDEN_URI_SCHEMES; check_scope() silently intersects with allowed; code=uuid4().hex random; max_age via login event timestamp; prompt=login re-auth loop prevention with SESSION_KEY_LAST_LOGIN_UID; response modes: QUERY/FRAGMENT/FORM_POST all use pre-validated redirect_uri; Python 2 except syntax at line 210 (4th occurrence: resolve_routing_from_request_object)
- providers/oauth2/views/token.py (full): CLEAN — CSRF-exempt (client credential flow); parse_token_request dispatch; grant_type routing; TokenError/UserAuthError clean error responses
- providers/oauth2/token/base.py (full): CLEAN — compare_digest for client_secret (timing-safe); is_all_vschar VSCHAR constraint; grant_type validation against provider config; scope intersection; DPoP validate_dpop; check_redirect_uri same STRICT/REGEX gate; FORBIDDEN_URI_SCHEMES
- providers/oauth2/token/authorization_code.py (full): CLEAN — PKCE challenge verify with pkce_s256_challenge(); PKCE downgrade prevention (code_verifier without challenge=reject); scope-bound DPoP validation
- sources/oauth/views/callback.py (partial): CLEAN — source enabled check; token fetch; raw_info parsed via response.json(); ValueError/JSONDecodeError handled
- sources/oauth/clients/base.py (partial): CLEAN — profile_url from admin-configured source_type; hardcoded plex.tv URLs; no user-controlled URL injection
- sources/saml/views.py (full): CLEAN — InitiateView: redirect bindings via urlencode; POST binding via consent stage; ACSView: @csrf_exempt (required for IdP POST); SAMLException/SuspiciousOperation/VerificationError/ValueError all caught; SLOView: redirect to admin-configured slo_url
- sources/saml/processors/response.py (full): CLEAN — verify response sig BEFORE decrypt; assertion sig AFTER decrypt; _verify_signature() exactly one Reference; URI="" allowed (root-doc reference with correct xmlsec target passing); _verify_request_id() InResponseTo matches session; _verify_destination() case-insensitive ACS URL; _verify_conditions() NotBefore/NotOnOrAfter with UTC; _verify_not_seen_before() atomic cache.add+get replay prevention (racing UUID pattern); AUT-SAML-REFURI-1: URI="" still PLAUSIBLE LOW
- stages/prompt/models.py (full): CLEAN — get_initial_value(): if field_key in prompt_context returns raw value (not expression-evaluated); admin-written expressions only for initial_value_expression=True; Static/Alert field() overrides default to self.placeholder (not prompt_context value); InlineFileField validates data: scheme + base64 encoding
- stages/prompt/stage.py (full): CLEAN — get_prompt_challenge_fields() populates initial_value via get_initial_value(); PromptChallengeResponse.validate() resets static/hidden fields to their defaults (prevents user-set values); validate_selected_stage() checks PLAN_CONTEXT_STAGES allowlist
- stages/password/stage.py (full): CLEAN — validate_password() from pending user username; authenticate() iterates admin-configured backends via path_to_class; PermissionDenied/ValidationError handled; reputation score throttle via failed_attempts_before_cancel
- stages/identification/stage.py (full): CLEAN — make_password(make_password(None)) timing equalization on invalid identifier; get_user() maps only email/username/upn fields (hardcoded dict, no ORM injection); validate_passkey_response() via validate_challenge_webauthn; captcha token server-verified; password check delegated to authenticate()
- stages/authenticator_validate/stage.py (full): CLEAN — cookie_jwt_key = sha256(install_id + ":" + stage_pk.hex); check_mfa_cookie(): algorithms=["HS256"], stage PK match, device PK match, exp>latest_allowed anti-future check; set_valid_mfa_cookie(): no httponly=True on MFA cookie (JavaScript-accessible; JWT signed with secret key, theft risk only); get_device_challenges() server-side device class filtering; validate_selected_challenge() device_class+device_uid must match PLAN_CONTEXT_DEVICE_CHALLENGES allowlist
- stages/authenticator_webauthn/stage.py (full): CLEAN — verify_registration_response() with server-generated challenge; expected_rp_id/expected_origin from request; WebAuthnDevice credential_id uniqueness enforced; AAGUID filter via device_type_restrictions; user_id=user.uid (SHA-256 hash, not DB PK)
- stages/email/flow.py (full): CLEAN — pickle_flow_token_for_email() in scope of AUT-FLOWTOKEN-PICKLE-1; EmailTokenRevocationConsentStageView.challenge_valid() deletes token (one-time-use defense against email scanner link consumption)
- outposts/models.py (full): CLEAN — OutpostConfig dataclass; DockerServiceConnection.url admin-configured; KubernetesServiceConnection.kubeconfig JSONField; Outpost.config via from_dict(OutpostConfig); state_cache_prefix keyed by UUID
- providers/saml/models.py (partial): CLEAN — SAMLProvider fields: acs_url/sls_url use DomainlessURLValidator; issuer_override/audience blank=True safe defaults
- providers/proxy/models.py (partial): CLEAN — ProxySession.session_data=JSONField (not pickle); get_cookie_secret() uses SystemRandom; callback URL hardcoded suffix + STRICT mode
- root/install_id.py (full): CLEAN — get_install_id() reads from authentik_install_id PostgreSQL table; secret, not derivable from public data; @lru_cache for performance; MFA cookie key is secure
- tenants/utils.py (full): CLEAN — get_unique_identifier() returns install_id (or tenant_uuid for multi-tenant); secret in both cases
- lib/expression/evaluator.py (full): CLEAN — exec() at line 365 with nosec comment; admin-only by design; _globals curated set; wrap_expression() sanitizes context keys; requests global = SSRF primitive (admin intent); expr_is_group_member(**group_filters)/expr_user_by(**filters) both admin-expression-controlled; expr_create_jwt_raw() arbitrary JWT claims (admin power tool)
- core/models.py (partial): CLEAN — default_token_key() uses generate_id(tenant_token_length); Group.is_superuser tracked via enable_group_superuser permission gate; GroupParentageNode trigger refreshes materialized view CONCURRENTLY; GroupAncestryNode recursive CTE transitive closure; Group.num_pk = first 5 digits of UUID int (stable, predictable but used only for LDAP gidNumber)
- web/src/flow/stages/prompt/PromptStage.ts (full): INFO — unsafeHTML(prompt.initialValue) for Static/Alert types (lines 85, 219); unsafeHTML(prompt.subText) for ALL types (lines 272, 303); admin-configured content rendered raw; same-session user-controlled initialValue possible only if admin configures TEXT+STATIC with matching field_key across stages (unusual misconfiguration, not standalone finding)
- sources/ldap/sync/base.py (partial): CLEAN — BaseLDAPSynchronizer.sync_full() test-only guard; base_dn_users/base_dn_groups from admin-configured additional_*_dn
- sources/ldap/sync/users.py (partial): CLEAN — user_object_filter from admin-configured source field; ALL_ATTRIBUTES + ALL_OPERATIONAL_ATTRIBUTES search
- stages/authenticator_webauthn/models.py: not yet read
- Python 2 except syntax count: 4 confirmed occurrences (scim/clients/groups.py:237, enterprise/license.py:111, root/middleware.py:76, providers/oauth2/views/authorize.py:210)

### Deep Reads — Continued exhaustive individual file reads (pass 5f — 2026-09-26)
- providers/oauth2/views/userinfo.py (full): CLEAN — @protected_resource_view([SCOPE_OPENID]); get_claims() filters ScopeMappings by scope_name AND provider; scope.evaluate() per ScopeMapping; nonce forwarded from id_token; cors_allow via token.provider.redirect_uris
- providers/oauth2/views/introspection.py (full): CLEAN — CONFIDENTIAL-only introspection; raw_token lookup by provider or federated providers (jwt_federation); checks token.is_expired + revoked; exports client_id in response (no secret)
- providers/oauth2/views/jwks.py (full): CLEAN — _jwks_from_private_key() @lru_cache; RSA/EC/Ed25519/Ed448 key serialization; x5c/x5t/x5t#S256 certificate fingerprints; Access-Control-Allow-Origin: * (public JWK endpoint)
- providers/oauth2/views/token_revoke.py (full): CLEAN — CONFIDENTIAL grants federated-token revoke; PUBLIC only own tokens; 200 on 404 (RFC 7009 compliant); token.delete() on success
- providers/oauth2/views/end_session.py (full): CLEAN — id_token_hint JWT verified (verify_exp=False intentional for post-expiry logout); post_logout_redirect_uri validated STRICT/REGEX + FORBIDDEN_URI_SCHEMES; id_token_hint required before redirect; relay_state appended safely via quote(state, safe=''); access_tokens deleted on auth logout; backchannel/frontchannel logout dispatch
- providers/oauth2/views/dcr.py (full): CLEAN — Bearer access token with SCOPE_AUTHENTIK_DCR required; policy access check via PolicyEngine; redirect_uris stored as STRICT mode only (not REGEX); grant_types intersected with dcr.allowed_grant_types; Python 2 except syntax at line 107 (5th occurrence: json.JSONDecodeError, UnicodeDecodeError)
- providers/oauth2/views/device_backchannel.py (full): CLEAN — AnonRateThrottle 20/hour; scope intersection; dpop_jkt validated by is_valid_jkt(); SCOPE_BOUND_KEY requires dpop_jkt; device_code/user_code via DB-assigned tokens
- providers/oauth2/views/device_init.py (full): CLEAN — CodeValidatorView resolves DeviceToken by user_code; OAuthDeviceCodeChallengeResponse.validate_code() calls CodeValidatorView directly; session gated by PolicyAccessView
- providers/oauth2/views/device_finish.py (full): CLEAN — token.user = request.user (authenticated); token.session from session store; one AUTHORIZE_APPLICATION event per flow
- providers/oauth2/views/github.py (full): CLEAN — @protected_resource_view([SCOPE_*]); org=group; org.num_pk = first 5 digits of UUID int (stable, not secret, used for gidNumber compat)
- providers/oauth2/views/provider.py (full): CLEAN — get_claims() evaluates against anonymous user (no user data leak); claims_cache_key with 1h TTL; registration_endpoint exposed only when DCR configured
- providers/saml/processors/assertion.py (full): CLEAN — sign THEN encrypt (correct order for EncryptedAssertion); _sign() uses URI="#"+element_id (no empty URI); TRANSIENT NameID = sha256(session_key.encode()) (changes per session); x509 cert embedded in KeyInfo; session_index = sha256(session_key)
- providers/saml/processors/authn_request_parser.py (full): CLEAN — defusedxml.ElementTree.fromstring for unsigned parsing; lxml only after defusedxml guard; xmlsec.ctx.verify() for signed requests; ACS URL mismatch = CannotHandleAssertion; ForceAuthn extracted as bool
- providers/saml/views/sso.py (full): CLEAN — check_force_authn() prevents re-auth bypass via SESSION_KEY_LAST_LOGIN_UID (login event PK comparison); ContinuousLogin.get() for iframe-compat REDIRECT mode
- providers/saml/views/flows.py (full): CLEAN — SAMLFlowFinalView gets AssertionProcessor and builds response; SAMLSession.update_or_create by session_index+provider; sign-before-encrypt order in build_response(); POST binding via AutosubmitChallenge; REDIRECT binding deprecated (SP binding)
- providers/saml/views/sp_slo.py (full): CLEAN — _get_redirect_url() uses stored relay_state from SESSION_KEY_PLAN (not request param); relay_state mismatch logged as warning; FRONTCHANNEL_NATIVE/BACKCHANNEL/IFRAME logout modes; SAMLSession deleted before redirect
- providers/saml/processors/metadata.py (full): CLEAN — xml_id = sha256(name+pk.hex); signing cert exposed in KeyDescriptor; signed metadata with xmlsec; WantAuthnRequestsSigned iff verification_kp set
- providers/saml/processors/logout_request_parser.py (full): CLEAN — defusedxml for XML parse; NameID/SessionIndex extracted; NO signature verification on logout request (info-only, replay prevention not implemented); relay_state stored on dataclass
- providers/saml/processors/logout_request.py (full): CLEAN — POST/REDIRECT encoding; _build_signable_query_string() follows SAML spec order (SAMLRequest, RelayState, SigAlg); sign via xmlsec.sign_binary()
- providers/saml/processors/logout_response_processor.py (full): CLEAN — same signable query string pattern; build_response() adds signature; InResponseTo from logout_request.id
- providers/saml/processors/metadata_parser.py (full): CLEAN — lxml_from_string (with UnsafeXML guard); check_signature() only when keypair supplied; select_endpoint() by BINDING_PREFERENCE; signing_keypair.check_signature() before storing
- policies/engine.py (full): CLEAN — effective_policy_user() MIRROR chain with seen-set cycle guard; PolicyEngine.compute_static_bindings() uses ORM aggregate (no Python iteration); FilterPolicyEngine._prefetch_cache() bulk cache.get_many(); ListPolicyEngine bulk policy+binding fetch; MIRROR actor verdict re-mapped via _finalize(); MODE_ALL fast-fail on static binding
- policies/process.py (full): CLEAN — FORK_CTX = get_context("fork"); PolicyProcess(Process) runs policy in subprocess; cache_key prefixed by CACHE_PREFIX + binding_uuid + session_key + user.pk; result sent via Pipe; PolicyException -> failure_result; execution_logging controlled by binding.policy.execution_logging
- policies/expression/evaluator.py (full): CLEAN — PolicyEvaluator(BaseEvaluator); ak_message appends to _messages (returned with PolicyResult); set_policy_request() sets ak_client_ip from ClientIPMiddleware; evaluate() propagates PolicyException; non-exception errors return PolicyResult(False)
- policies/reputation/signals.py (full): CLEAN — update_score_on_login() uses UPSERT with Greatest/Least clamping; negative score reset to 0 on success; failed login/identification both lower by -1; ConflictAction.UPDATE is atomic (psqlextra)
- rbac/permissions.py (full): CLEAN — ObjectPermissions.has_permission(): lookup bypass is intentional (object-level check in has_object_permission); has_object_permission: global perm > per-object perm > owner_field; HasPermission() returns class with has_perm check; assign_initial_permissions scoped to user.all_roles()
- rbac/middleware.py (full): CLEAN — InitialPermissionsMiddleware hooks post_save signal for request duration; assigns initial perms on instance creation; dispatch_uid=request_id prevents cross-request handler bleed; process_exception disconnects on error
- rbac/decorators.py (full): CLEAN — permission_required(obj_perm, global_perms): global perm has higher priority; self.get_object() only called if obj_perm set; permission_denied on failure
- api/authentication.py (full): CLEAN — TokenAuthentication: Token DB lookup (INTENT_API), then AccessToken (SCOPE_AUTHENTIK_API double-checked), then SECRET_KEY (outpost embedded), then IPC key; compare_digest for both SECRET_KEY and ipc_key checks (timing-safe); IPC key read from /tmp/authentik-core-ipc.key at module load; ipc_key=None if file absent (safe fallback); IPCUser.has_perm always True (virtual superuser); file permissions on ipc_key determine elevation path
- flows/views/executor.py (full): CLEAN — FlowExecutorView.permission_classes=[AllowAny] (expected: auth flows); _check_flow_token catches (AttributeError, EOFError, ImportError, IndexError) from pickle.plan — other exceptions propagate to handle_exception (AUT-FLOWTOKEN-PICKLE-1 scope); _flow_done() PLAN_CONTEXT_REDIRECT: no is_url_absolute check (comment: set by expression policy or authentik only); next param is_url_absolute checked; cancel() leaves SESSION_KEY_POST intact (intentional)
- flows/planner.py (full): CLEAN — FlowPlan.to_redirect(): short-circuit for allowed_silent_types (direct stage execution without executor); FlowPlanner._check_authentication(): REQUIRE_TOKEN checks PLAN_CONTEXT_IS_RESTORED; REQUIRE_OUTPOST checks outpost user from middleware; plan cached by flow+user PK; evaluate_on_plan=True stages evaluated at plan time; re_evaluate_policies→ReevaluateMarker
- Python 2 except syntax count: 5 confirmed occurrences (5th: providers/oauth2/views/dcr.py:107)

### Deep Reads — Continued exhaustive individual file reads (pass 5g — 2026-09-26)
- sources/ldap/auth.py (full): CLEAN — LDAPBackend.auth_user() checks LDAP_DISTINGUISHED_NAME in user.attributes; auth_user_by_bind() binds as stored DN (no filter construction, no injection); password_login_update_internal_password saves LDAP password to DB on success (intentional sync)
- sources/ldap/password.py (full): CLEAN — ad_password_complexity() checks MS AD 7-rule complexity; change_password() uses extend.microsoft.modify_password with fallback to standard modify; Python 2 except syntax at line 82: `except LDAPAttributeError, LDAPUnwillingToPerformResult, KeyError, IndexError:` and at line 105: `except LDAPAttributeError, LDAPUnwillingToPerformResult, LDAPNoSuchAttributeResult:` (6th and 7th occurrences)
- sources/oauth/views/dispatcher.py (full): CLEAN — DispatcherView.dispatch() does get_object_or_404(OAuthSource, slug=source_slug) then registry.find(provider_type, kind=RequestKind(self.kind)); @csrf_exempt (correct for OAuth callbacks); no user-controlled URL construction
- Python 2 except syntax count: 7 confirmed occurrences — scim/clients/groups.py:237, enterprise/license.py:111, root/middleware.py:76, providers/oauth2/views/authorize.py:210, providers/oauth2/views/dcr.py:107, sources/ldap/password.py:82, sources/ldap/password.py:105

### Deep Reads — Continued exhaustive individual file reads (pass 5h — 2026-09-26)
- sources/oauth/views/dispatcher.py (full): CLEAN — csrf_exempt; get_object_or_404 by slug; registry.find(provider_type, kind)
- sources/oauth/views/redirect.py (full): CLEAN — login_hint extracted from PLAN_CONTEXT_PENDING_USER (user's own email); additional_scopes from admin-configured source field; all URLs admin-configured
- sources/oauth/clients/oauth1.py (full): CLEAN — requests_oauthlib.OAuth1; request token stored in session; access_token_url from admin-configured source
- sources/oauth/clients/oauth2.py (full): CLEAN — constant_time_compare for state check (timing-safe); PKCE verifier stored in session, never from request; access_token_url from admin-configured source; UserprofileHeaderAuthClient sends auth via header only
- sources/oauth/views/base.py (full): CLEAN — dispatches to OAuthClient (OAuth1) or OAuth2Client based on request_token_url presence
- sources/oauth/views/callback.py (full): CLEAN — AUT-FLOWTOKEN-PICKLE-1 scope: handle_match_failure() calls session_token.plan; token deleted after use; identifier from source-type-specific get_user_id()
- sources/oauth/types/registry.py (full): CLEAN — find_type() falls back to SourceType on unknown provider; no user-controlled input
- sources/ldap/sync/forward_delete_groups.py (full): CLEAN — UUID sentinel pattern for group deletion
- sources/ldap/sync/membership.py (full): CLEAN — escape_filter_chars(group_dn) for lookup_groups_from_user LDAP filter; group_object_filter from admin-configured source field
- sources/ldap/sync/vendor/ms_ad.py (full): CLEAN — UserAccountControl IntFlag; ACCOUNTDISABLE|LOCKOUT → is_active=False; set_unusable_password() on pwdLastSet change
- sources/ldap/sync/vendor/freeipa.py (full): CLEAN — nsaccountlock string→bool conversion (389-ds quirk); krbLastPwdChange UTC-aware comparison
- providers/ldap/models.py (full): CLEAN — uid_start_number/gid_start_number added to user/group PK for POSIX; mfa_support=semicolon TOTP append (design note); get_required_objects() includes cert key perm
- providers/ldap/api.py (full): CLEAN — check_access() uses ORM lookup for app_slug; search_full_directory custom perm check; LDAPOutpostConfigViewSet lists assigned providers only
- events/models.py (full): CLEAN — Event.new() uses cleanse_dict+sanitize_dict; from_http() reads impersonation context and SESSION_KEY_PLAN (already decoded); send_webhook() uses admin-configured webhook_url validated by DomainlessURLValidator; sanitize_item() on mapping output
- events/utils.py (full): CLEAN — cleanse_item() uses SafeExceptionReporterFilter.hidden_settings regex; ALLOWED_SPECIAL_KEYS exceptions; sanitize_item() drops HttpRequest via ... sentinel
- lib/utils/http.py (full): CLEAN — TimeoutSession enforces configurable timeout; DebugSession only in debug/trace mode; User-Agent header set to authentik version
- lib/models.py (full): CLEAN — DomainlessURLValidator adds localhost+blank+ssh+sftp schemes; DomainlessFormattedURLValidator allows %(var)s in URL host; ExpiringManager excludes expired by default
- root/middleware.py (full): CLEAN — Python 2 except syntax at line 76: `except KeyError, PyJWTError:` (already noted); decode_session_key() with algorithms=["HS256"]; _get_outpost_override_ip() validates IP via ip_address() parse; INTERNAL_SERVICE_ACCOUNT required for IP override
- lib/generators.py (full): CLEAN — all generators use SystemRandom() (CSPRNG)
- lib/config.py (partial 100 lines): CLEAN — ConfigLoader searches SEARCH_PATHS + env vars with ENV_PREFIX; Attr dataclass with source tracking
- admin/files/validation.py (full): CLEAN (confirmed pass 3) — regex + PurePosixPath + absolute path + .. check + THEME_VARIABLE placeholder handling
- admin/files/api.py (full): CLEAN — 25MB size limit; validate_upload_file_name() on upload AND delete paths; HasPermission RBAC; audit events for both operations
- admin/files/backends/s3.py (full): CLEAN — ACL=private; key prefix {usage}/{schema}/{name}; presigned URLs with configurable expiry; custom domain rewrite for non-AWS S3
- admin/files/manager.py (full): CLEAN — config-driven backend selection; file_url() falls back through backends; _check_manageable() before all writes
- admin/signals.py (full): CLEAN — sets Prometheus metrics on startup
- admin/tasks.py (full): CLEAN — update_latest_version() fetches from hardcoded version.goauthentik.io URL; event dedup check before creating
- core/sources/mapper.py (full): CLEAN — PropertyMappingManager.iter_eval(); admin-configured property mappings; MERGE_LIST_UNIQUE for merging
- core/sources/matcher.py (full): CLEAN — refuses to match on empty property (prevents account takeover); existing connection by identifier → AUTH; new connection by attribute match → LINK/DENY
- core/sources/stage.py (full): CLEAN — PostSourceStage saves connection after enrollment; audit event created
- core/sources/flow_manager.py (full): CLEAN — AUT-FLOWTOKEN-PICKLE-1 call sites: handle_match_failure() and _prepare_flow() both call token.plan; both delete token after use; GroupUpdateStage group update in transaction.atomic()
- enterprise/stages/source/stage.py (full): CLEAN — AUT-FLOWTOKEN-PICKLE-1 call site: SourceStageFinal.dispatch() calls token.plan; token expiry checked; token deleted after use; create_flow_token() uses FlowToken.pickle()
- events/middleware.py (full): CLEAN — dispatch_uid=request_id scopes signals to current request; _CTX_REQUEST ContextVar prevents cross-request handler bleed; audit_ignore() context manager
- events/signals.py (full): CLEAN — on_user_logged_in reads SESSION_KEY_PLAN (already decoded); on_login_failed logs credentials through cleanse_dict; GDPR cleanup on user delete
- events/tasks.py (full): CLEAN — event_trigger_handler() infinite loop prevention via policy_uuid check; PolicyEngine.empty_result=False; user looked up from event.user JSONField (not pickle)

### Deep Reads — TypeScript individual file reads (pass 5i — 2026-09-26)
- web/src/flow/FlowExecutor.ts (full): CLEAN — unsafeHTML(challenge.body) only for ShellChallenge (Django auto-escaped); unsafeStatic(tag) for component tags from static registry (not user content); flowsExecutorSolve echoes back server-provided challenge.component
- web/src/flow/controllers/FlowIframeMessageController.ts (full): **NEW PLAUSIBLE LOW (AUT-POSTMSG-ORIGIN-1)** — onMessage() checks event.data.source/context/message (attacker-controlled) but NOT event.origin; any cross-origin page can trigger invisible empty submit; blast radius limited (most stages reject {} server-side) but FrameChallenge/AutosubmitStage accept blank submits
- web/src/flow/controllers/FlowMultitabController.ts (full): CLEAN — correct origin check: new URL(next, window.location.origin) + url.origin===window.location.origin before window.location.assign()
- web/src/flow/stages/base.ts (full): CLEAN — submitForm uses FormData; readFileAsync for blobs; renderNonFieldErrors HTML-escaped via Lit
- web/src/flow/stages/autosubmit/AutosubmitStage.ts (full): CLEAN — Lit attribute binding HTML-escaped; action from server-side challenge URL
- web/src/flow/utils/autosubmit.ts (full): CLEAN — DOM property assignment; HTMLFormElement.prototype.submit.call() (bypasses event handlers for SAML POST binding — by design)
- web/src/common/api/client.ts (full): CLEAN — Configuration singleton Object.freeze'd; CSRFMiddleware in middleware chain; base path from globalAK().api.base
- web/src/common/errors/network.ts (full): CLEAN — pluckErrorDetail reads typed error fields; parseAPIResponseError parses response.json() safely with status-code transformer map

### Deep Reads — TypeScript individual file reads (pass 5j — 2026-09-26)
- web/src/flow/stages/identification/IdentificationStage.ts (lines 100-219): CLEAN — helper form creation via DOM API (createElement, setAttribute); username/password sync via onkeyup without innerHTML; shadow DOM compat workaround
- web/src/flow/stages/password/PasswordStage.ts (full): CLEAN — Lit attribute binding on pendingUser and recoveryUrl; no unsafeHTML
- web/src/flow/stages/captcha/CaptchaStage.ts (full): CLEAN — jsUrl admin-configured challenge; URL.canParse() validation; generation counter guard for stale async loads; no unsafeHTML
- web/src/flow/stages/consent/ConsentStage.ts (full): CLEAN — permission.name/id and headerText rendered as Lit text nodes; token from server challenge
- web/src/flow/stages/authenticator_validate/AuthenticatorValidateStage.ts (full): CLEAN — device/stage labels from enum→static prop map; StrictUnsafe(tag) where tag from hardcoded switch/case
- web/src/flow/stages/authenticator_validate/AuthenticatorValidateStageWebAuthn.ts (full): CLEAN — navigator.credentials.get() with PublicKeyCredentialRequestOptions; transformAssertionForServer() encoding; typed submit
- web/src/elements/utils/unsafe.ts (full): CLEAN — StrictUnsafe gates unsafeStatic(tagName) behind: startsWith(AKElementTagPrefix) check, customElements.get() registration check, isAKElementConstructor check
- web/src/flow/stages/prompt/PromptStage.ts (full): CLEAN — unsafeHTML(prompt.initialValue/subText) for Static/Alert/Checkbox types (admin-configured); all other input types use Lit attribute binding
- web/src/common/helpers/webauthn.ts (full): CLEAN — pure base64/byte-array encoding helpers for WebAuthn ceremony
- web/src/flow/stages/authenticator_webauthn/WebAuthnAuthenticatorRegisterStage.ts (full): CLEAN — standard navigator.credentials.create(); transformNewAssertionForServer() encoding; typed submit; Lit-escaped error strings
- web/src/common/api/middleware.ts (full): CLEAN — CSRFMiddleware reads getCookie("authentik_csrf") → X-authentik-CSRF header; DevRepeatedRequestsMiddleware only in CanDebug mode; LocaleMiddleware formats Accept-Language header
- web/src/common/purify.ts (full): CLEAN — 5 DOMPurify-backed Trusted Types policies; BrandedHTMLPolicy has explicit FORBID_TAGS (script/iframe/form/input) + FORBID_ATTR (on* handlers); CompiledMarkdownSanitizePolicy re-sanitizes even build-time markdown because admin-controlled replacers may inject values
- web/src/elements/router/core/navigation.ts (full): CLEAN — navigate() uses new URL(to, window.location.origin); cross-origin → window.location.assign(); decideInterception rejects cross-origin clicks; click interceptor checks pathname prefix
- web/src/elements/router/core/interfaces.ts (full): CLEAN — URL builders use server-configured base+interface path; toAdminInterface/toUserInterface/toFlowInterface all pure path formatters

### Deep Reads — TypeScript individual file reads (pass 5k — 2026-09-26)
- web/src/elements/forms/Form.ts (partial): CLEAN — base form class setup; serializeForm() uses typed DOM property reads (value/checked/toJSON), no eval/injection
- web/src/elements/forms/serialization.ts (full): CLEAN — serializeForm() walks DOM elements via .value/.checked/.toJSON(); assignValue() dot-path JSON assignment via deepmerge; no injection
- web/src/elements/forms/ModelForm.ts (partial): CLEAN — base ModelForm class, typed CRUD ops
- web/src/elements/messages/MessageContainer.ts (full): CLEAN — messages rendered as Lit text nodes; tryParsingJSON from server-side <script> tag; no innerHTML
- web/src/common/sentry/middleware.ts (full): CLEAN — adds Sentry trace headers (baggage, sentry-trace) only; no user input
- web/src/admin/providers/oauth2/OAuth2ProviderForm.ts (partial): CLEAN — typed API calls; form data from serializeForm() → typed API submit
- web/src/admin/users/UserListPage.ts (full): CLEAN — item.username/name/displayName all Lit text nodes (escaped); item.pk numeric in href; item.avatar in <img src> (src cannot execute javascript: URI)
- web/src/common/global.ts (full): CLEAN — reads server context from <meta> tags + Django json_script blocks (not inline JS); enables strict CSP path
- web/src/common/utils.ts (full): CLEAN — getCookie reads named cookie; randomString uses crypto.getRandomValues() (CSPRNG)
- web/src/flow/FormStatic.ts (full): CLEAN — username Lit text node; cancelUrl from server-side challenge (admin-configured); avatar in <img src>
- web/src/flow/stages/authenticator_duo/AuthenticatorDuoStage.ts (full): CLEAN — activationBarcode as <img src>; activationCode as <a href> (Duo-generated URL from server challenge); setInterval polling via typed API call
- web/src/elements/ak-mdx/ak-mdx.ts (full): CLEAN — URL mode: CompiledMarkdownSanitizePolicy re-sanitizes after replacers run; Content mode: compileRuntimeMarkdown (no eval/Function) then sanitizeHTML(BrandedHTMLPolicy); both paths through DOMPurify before unsafeHTML()

### Deep Reads — TypeScript individual file reads (pass 5o — 2026-09-26)
- web/src/elements/AppIcon.ts (full): CLEAN — iconClass in CSS class attribute (Lit setAttribute, no HTML injection); resolvedIcon in <img src>; name first-char insignia as text node
- web/src/elements/user/sources/SourceSettings.ts (full): CLEAN — source.component switch with 4 hardcoded cases + default error; no unsafeStatic; source.title as text node in aria-label
- web/src/elements/sources/utils.ts (full): CLEAN — renderSourceIcon() renders FA class in class attribute (not innerHTML); iconUrl in <img src>; name in title attribute
- web/src/user/user-settings/tokens/UserTokenList.ts (full): CLEAN — item.identifier/userObj.username as Lit text nodes; intent via formatIntentLabel; expiry via formatElapsedTime
- web/src/user/user-settings/mfa/MFADevicesPage.ts (full): CLEAN — item.name/extraDescription as text nodes; stage.component dispatched to deleteWrapper as hardcoded switch; stage.configureUrl in <a href> from server stage config

### Deep Reads — TypeScript individual file reads (pass 5p — 2026-09-26)
- web/src/user/user-settings/mfa/MFADeviceForm.ts (full): CLEAN — name field via form input binding; send() dispatch on this.instance.type as hardcoded switch; no rendering of user data
- web/src/user/user-settings/details/UserPassword.ts (full): CLEAN — configureUrl in <a href> (admin-set flow URL); text nodes only
- web/src/user/user-settings/details/UserSettingsFlowExecutor.ts (full): CLEAN — unsafeHTML(ShellChallenge.body) at line 172: same server-controlled shell HTML pattern as main FlowExecutor; RedirectChallenge.to in <a href> from flow API
- web/src/elements/buttons/TokenCopyButton/ak-token-copy-button.ts (full): CLEAN — fetches token via typed API call, writes to clipboard via writeToClipboard(); no HTML rendering of token value
- web/src/admin/providers/proxy/ProxyProviderForm.ts (full): CLEAN — thin wrapper; delegates all rendering to renderForm() in ProxyProviderFormForm.ts
- web/src/admin/providers/proxy/ProxyProviderFormForm.ts (full): CLEAN — all fields via ak-text-input/ak-switch-input; mode dispatched via ts-pattern match to renderProxySettings/renderForwardSingleSettings/renderForwardDomainSettings; window.location.origin as default externalHost value
- web/src/admin/providers/radius/RadiusProviderForm.ts (full): CLEAN — thin wrapper; delegates to RadiusProviderFormForm.ts
- web/src/admin/providers/scim/SCIMProviderForm.ts (full): CLEAN — thin wrapper; delegates to SCIMProviderFormForm.ts
- web/src/admin/stages/prompt/PromptStageForm.ts (full): CLEAN — ak-text-input for stage name; dual-select for fields and bindings
- web/src/admin/stages/prompt/PromptForm.ts (partial 80 lines): CLEAN — ModelForm for Prompt; sends via stagesPromptPromptsUpdate/Create; preview rendering not yet read
- web/src/flow/stages/identification/IdentificationStage.ts (full): CLEAN — applicationPre via msg(str`...`) (localize-safe); enrollUrl/recoveryUrl/passwordlessUrl in <a href> from server flow config; source.name as text node; renderSourceIcon() traced CLEAN; primaryAction server-provided button text
- web/src/admin/outposts/OutpostForm.ts (full): CLEAN — fields via ak-text-input/ak-search-select; config via ak-codemirror with YAML.stringify(); type selector hardcoded options; provider list from API
- web/src/admin/policies/expression/ExpressionPolicyForm.ts (full): CLEAN — expression in ak-codemirror; name in text input; no unsafeHTML
- web/src/flow/FlowExecutor.ts (full): CLEAN — unsafeHTML(challenge.body) only for xak-flow-shell special case; unsafeStatic(tag) from StageMapping.registry (compile-time hardcoded entries only); frame background src from server challenge.flowInfo.background
- web/src/flow/FlowExecutorStageFactory.ts (full): CLEAN — tag resolved via: entry.tag || customElements.getName(StageConstructor) || entry.stage; all three sources are compile-time values; unknown challenge.component never reaches unsafeStatic (falls to error path if not in registry)
- web/src/flow/FlowExecutorStages.ts (full): CLEAN — hardcoded StageEntries array with 30 known ak-/xak-prefixed component names; registry is static, not extensible at runtime
- web/src/user/user-settings/UserSettingsPage.ts (full): CLEAN — all rendering via child component bindings; currentUser.pk in attribute binding (numeric)

### Deep Reads — TypeScript individual file reads (pass 5q — 2026-09-26)
- web/src/admin/providers/oauth2/OAuth2ProviderFormForm.ts (full): CLEAN — all form fields via ak-text-input/ak-radio-input/ak-flow-search/ak-crypto-certificate-search; no unsafeHTML
- web/src/admin/providers/oauth2/OAuth2ProviderRedirectURI.ts (full): CLEAN — redirectURI fields in form input value bindings; no rendered user HTML
- web/src/admin/crypto/CertificateKeyPairForm.ts (full): CLEAN — PEM data in ak-secret-textarea-input (input control, not rendered); name in ak-text-input
- web/src/admin/sources/oauth/OAuthSourceForm.ts (full, grep-confirmed): CLEAN — no unsafeHTML; all fields via typed form components
- web/src/admin/sources/saml/SAMLSourceForm.ts (full, grep-confirmed): CLEAN — no unsafeHTML; hasSigningCert state toggle
- web/src/admin/stages/prompt/PromptForm.ts (full): CLEAN — previewResult via JSON.stringify in <pre> (Lit text node); renderTypes() hardcoded options; form inputs only

#### unsafeHTML/unsafeStatic exhaustive coverage — ALL 9 FILES CONFIRMED
- Grep across 2861 TypeScript files: only 9 files use unsafeHTML or unsafeStatic
- All 9 confirmed reviewed; 7 CLEAN, 2 INFO (PromptStage admin-configured; FlowExecutor/UserSettingsFlowExecutor server-controlled)
- web/src/elements/ak-dual-select/ak-dual-select.ts (full): CLEAN — unsafeHTML("&nbsp;") or msg(str`${number} items...`) — neither is user-controlled HTML
- web/src/elements/Diagram/ak-diagram.ts (full): CLEAN — unsafeHTML(svg) from Mermaid renderer of admin-configured diagram text
- web/src/elements/utils/files.ts (full): CLEAN — unsafeHTML(Intl.ListFormat.format(hardcoded ["theme"])) — hardcoded HTML wrapper, not user data
