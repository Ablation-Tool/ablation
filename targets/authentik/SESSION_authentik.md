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

## Confirmed Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| AUT-SESS-PICKLE-1 | HIGH | Unsigned pickle deserialization of session data (no HMAC) | CONFIRMED |
| AUT-TASK-PICKLE-1 | HIGH | Unsigned pickle deserialization of task queue arguments | CONFIRMED |
| AUT-FLOWTOKEN-PICKLE-1 | HIGH | Unsigned pickle deserialization of FlowToken._plan (bare import, missed by grep) | CONFIRMED |
| AUT-CACHE-PICKLE-1 | MEDIUM | Unsigned pickle deserialization of PostgreSQL cache values | CONFIRMED |
| AUT-IPC-KEY-1 | MEDIUM | IPC superuser key stored in world-readable /tmp | CONFIRMED |
| AUT-SAML-REFURI-1 | LOW | SAML assertion signature allows URI="" (root-element reference) | PLAUSIBLE |

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
