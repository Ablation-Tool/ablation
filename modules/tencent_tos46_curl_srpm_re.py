"""
TencentOS Server 4.6 curl RE Module
Source: curl-8.4.0-{15,16,17}.tl4.src.rpm
        /media/cowboy/research/tencentos/4.6/BaseOS-source/
Analysis date: 2026-09-04

PACKAGE HISTORY:
  curl-8.4.0-15.tl4  18 CVE patches (2023-2025)
  curl-8.4.0-16.tl4  +CVE-2026-5545 +CVE-2026-6429 (4 patches: 3 pre + main)
  curl-8.4.0-17.tl4  +CVE-2026-8924

BUILD PATCHES (non-CVE, 3): multilib, test3026, tests-warnings — informational only

NOTABLE PROVENANCE:
  CVE-2024-2398 (http2 push cleanup) — authored by zoedong@tencent.com (Tencent upstream contributor)
  CVE-2026-8924 — "Adapted-by: PkgAgent/deepseek-v4" in patch comment — AI-assisted downstream adaptation

SECURITY FINDINGS: TOS46-CURL-F01 through TOS46-CURL-F19
  F01 HIGH     CVE-2026-6429   cross-origin credential leak on redirect (origin-check rewrite)
  F02 HIGH     CVE-2025-14524  OAuth bearer not cleared on redirect to different origin
  F03 HIGH     CVE-2025-14017  LDAP TLS options applied via NULL handle (process-global)
  F04 MEDIUM   CVE-2026-5545   NTLM+NEGOTIATE connection reuse credential confusion
  F05 MEDIUM   CVE-2026-8924   PSL trailing-dot cookie bypass (AI-adapted patch)
  F06 MEDIUM   CVE-2025-15079  libssh: SSH_OPTIONS_GLOBAL_KNOWNHOSTS not set
  F07 MEDIUM   CVE-2025-15224  libssh: pubkey auth attempted without private key
  F08 MEDIUM   CVE-2025-14819  X.509 store cache key missing no_partialchain bit
  F09 MEDIUM   CVE-2024-11053  redirect + netrc credential handling flaws (two patches)
  F10 MEDIUM   CVE-2024-9681   HSTS subdomain match preferred over full host match
  F11 MEDIUM   CVE-2025-9086   cookie path "/" stripped to empty (Google Big Sleep)
  F12 LOW      CVE-2024-8096   GnuTLS OCSP stapling bypass — check-before-response logic
  F13 LOW      CVE-2024-7264   ASN.1 GTime2str() fractional-seconds off-by-one + OOB
  F14 LOW      CVE-2025-10966  wolfSSH backend removed (1174 lines, incomplete impl)
  F15 INFO     CVE-2023-46218  cookie PSL check missing lowercase normalization
  F16 INFO     CVE-2023-46219  temp file name reveals original filename in suffix
  F17 INFO     CVE-2024-2004   CURLOPT_PROTOCOLS_STR "-all" leaves default protocol set
  F18 INFO     CVE-2025-0167   netrc 'default' with no credentials matched anyway
  F19 INFO     CVE-2024-2398   HTTP/2 push promise cleanup refactor (Tencent upstream)
"""

# ──────────────────────────────────────────────────────────────────────────────
# F01 — cross-origin redirect credential leak (CVE-2026-6429)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F01_REDIRECT_CRED = {
    "finding_id": "TOS46-CURL-F01",
    "severity": "HIGH",
    "cve": "CVE-2026-6429",
    "title": (
        "curl Curl_follow() leaks username/password on cross-origin redirect: "
        "old port/scheme comparison replaced by Curl_url_same_origin(); "
        "proxy credentials also never cleared pre-patch"
    ),
    "description": (
        "lib/transfer.c Curl_follow() — redirect credential handling. "
        "\n"
        "Pre-patch logic: "
        "  Compared redirect target port and scheme to current connection. "
        "  Cleared auth only if port changed OR scheme protocol changed. "
        "  Did NOT clear proxy credentials at all. "
        "  Missed cases: different host same port, different path exposing auth. "
        "\n"
        "Post-patch logic (with 3 prerequisite patches): "
        "  1. pre1 (CVE-2026-6429-pre1): prevent HTTPS scheme push over non-SSL h2 "
        "  2. pre2 (CVE-2026-6429-pre2): add Curl_url_same_origin() to urlapi.c "
        "     — compares scheme + host + port "
        "     — handles port omission vs default port correctly "
        "  3. pre3 (CVE-2026-6429-pre3): refactor Curl_reset_userpwd() + Curl_reset_proxypwd() "
        "  4. main: replace old port/scheme check with Curl_url_same_origin() "
        "     — cross-origin OR no explicit username → reset credentials "
        "     — always reset proxy credentials "
        "\n"
        "Reported-by: Muhamad Arga Reksapati "
        "\n"
        "Attack scenario: "
        "  curl follows a 3xx redirect from https://trusted.example.com/ "
        "  to https://attacker.example.net/ (different host, same port/scheme) "
        "  Pre-patch: Authorization header forwarded to attacker.example.net "
        "  Post-patch: credentials cleared on host change "
        "\n"
        "Proxy credential disclosure: "
        "  Pre-patch: proxy credentials NEVER cleared on any redirect. "
        "  Any application using curl with a proxy and following redirects "
        "  leaked proxy credentials to all redirect destinations. "
        "\n"
        "Backport note: Curl_follow() in 8.4.0 differs from current; "
        "adapted from lib/http.c Curl_http_follow() to lib/transfer.c Curl_follow(). "
        "Uses char* URL instead of Curl_bufref_ptr, free() instead of curlx_free()."
    ),
    "affected_files": ["lib/transfer.c", "lib/url.c", "lib/transfer.h", "lib/urlapi.c", "lib/urlapi-int.h"],
    "reporter": "Muhamad Arga Reksapati",
}

# ──────────────────────────────────────────────────────────────────────────────
# F02 — OAuth bearer not cleared on redirect (CVE-2025-14524)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F02_BEARER_LEAK = {
    "finding_id": "TOS46-CURL-F02",
    "severity": "HIGH",
    "cve": "CVE-2025-14524",
    "title": (
        "CURLOPT_BEARER_TOKEN forwarded to cross-origin redirect targets — "
        "unlike all other credential types, bearer token cleared only when "
        "this_is_a_follow=true AND allow_auth_to_other_hosts=false"
    ),
    "description": (
        "lib/curl_sasl.c Curl_sasl_start() — SASL auth initiation. "
        "\n"
        "Pre-patch: "
        "  const char *oauth_bearer = data->set.str[STRING_BEARER]; "
        "  Bearer token always used, even on follow-redirect to different origin. "
        "\n"
        "Post-patch: "
        "  const char *oauth_bearer = "
        "    (!data->state.this_is_a_follow || data->set.allow_auth_to_other_hosts) ? "
        "    data->set.str[STRING_BEARER] : NULL; "
        "\n"
        "The this_is_a_follow flag is set in Curl_follow() when following a 3xx. "
        "Effect: OAuth bearer tokens were forwarded to every redirect destination "
        "unconditionally, regardless of whether the destination was the same origin. "
        "\n"
        "Protocols affected: any SASL-enabled protocol (SMTP, IMAP, POP3) "
        "and HTTP when using libcurl's OAuth support. "
        "\n"
        "Backport: applies to 8.4.0 without modification."
    ),
    "affected_files": ["lib/curl_sasl.c"],
    "reporter": None,
}

# ──────────────────────────────────────────────────────────────────────────────
# F03 — LDAP TLS options via NULL handle (CVE-2025-14017)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F03_LDAP_NULL = {
    "finding_id": "TOS46-CURL-F03",
    "severity": "HIGH",
    "cve": "CVE-2025-14017",
    "title": (
        "LDAP: ldap_set_option(NULL, ...) sets process-global TLS options before "
        "connection init — LDAP_OPT_NETWORK_TIMEOUT, LDAP_OPT_X_TLS_CACERTFILE, "
        "LDAP_OPT_X_TLS_REQUIRE_CERT applied globally to all libldap handles in process"
    ),
    "description": (
        "lib/ldap.c ldap_do() — LDAP connection setup. "
        "\n"
        "In libldap, passing NULL to ldap_set_option() sets the option globally "
        "(all future and existing connections in the same process). "
        "\n"
        "Pre-patch code flow: "
        "  ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, ...) — global "
        "  ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, ...) — global "
        "  [ssl path] ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, ...) — global CA "
        "  [ssl path] ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, ...) — global verify "
        "  [ssl path] server = ldap_init(...) — init AFTER setting options "
        "\n"
        "Post-patch: server = ldap_init() is called first, then all options "
        "use the connection handle (not NULL). "
        "\n"
        "Implication: "
        "  In a process using libcurl for multiple LDAP connections concurrently, "
        "  the TLS CA file and certificate verification mode are shared. "
        "  If one curl handle disables cert verification, ALL LDAP connections "
        "  in the process inherit the weakened setting. "
        "  Race condition if multiple threads establish LDAP connections simultaneously. "
        "\n"
        "Additional bug in pre-patch: "
        "  [ssl path] server = ldap_init() was called AFTER setting TLS options, "
        "  so the options were set on the global handle that no longer exists "
        "  after the per-handle init."
    ),
    "affected_files": ["lib/ldap.c"],
    "reporter": None,
}

# ──────────────────────────────────────────────────────────────────────────────
# F04 — NTLM+NEGOTIATE connection reuse (CVE-2026-5545)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F04_NTLM_NEGOTIATE = {
    "finding_id": "TOS46-CURL-F04",
    "severity": "MEDIUM",
    "cve": "CVE-2026-5545",
    "title": (
        "ConnectionExists() allows NTLM connection reuse when negotiate auth "
        "is in-progress on that connection — a credential-mismatched connection "
        "with active GSS negotiation can be repurposed for a different user"
    ),
    "description": (
        "lib/url.c ConnectionExists() — connection pool reuse check. "
        "\n"
        "Pre-patch: credential-mismatched NTLM connection eligible for reuse "
        "if http_ntlm_state == NTLMSTATE_NONE, regardless of negotiate state. "
        "\n"
        "Post-patch (with USE_SPNEGO): "
        "  if((check->http_ntlm_state == NTLMSTATE_NONE) "
        "     && (check->http_negotiate_state == GSS_AUTHNONE)) { "
        "      chosen = check; "
        "  } "
        "\n"
        "Without the fix: a connection that was partway through SPNEGO/Kerberos "
        "negotiation (http_negotiate_state != GSS_AUTHNONE) could be reused "
        "for a different user's request. The new user's request would inherit "
        "the partial auth state of the previous connection. "
        "\n"
        "Reported-by: Stefan Eissing "
        "\n"
        "Severity: requires shared connection pool (multi-user curl processes, "
        "proxy applications, or misconfigured thread-sharing of CURLM handles)."
    ),
    "affected_files": ["lib/url.c"],
    "reporter": "Stefan Eissing",
}

# ──────────────────────────────────────────────────────────────────────────────
# F05 — PSL trailing-dot bypass (CVE-2026-8924)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F05_PSL_TRAILINGDOT = {
    "finding_id": "TOS46-CURL-F05",
    "severity": "MEDIUM",
    "cve": "CVE-2026-8924",
    "title": (
        "Cookie PSL check bypassed for domains with trailing dots — "
        "psl_is_cookie_domain_acceptable(psl, 'foo.co.uk.', 'co.uk.') bypasses "
        "public suffix guard; fix: trim trailing dots before PSL lookup"
    ),
    "description": (
        "lib/cookie.c Curl_cookie_add() — PSL domain check. "
        "\n"
        "Pre-patch: Curl_strntolower(lcase, domain, dlen + 1) passed original "
        "domain with trailing dot to psl_is_cookie_domain_acceptable(). "
        "\n"
        "The PSL library does not normalize trailing dots. "
        "'co.uk.' is not in the PSL, so the check for setting a cookie "
        "on domain='co.uk.' would succeed — allowing a cookie scoped to "
        "a TLD+1 suffix in violation of RFC 6265. "
        "\n"
        "Post-patch: "
        "  dlen-- if domain[dlen-1] == '.' "
        "  clen-- if co->domain[clen-1] == '.' "
        "  Then pass trimmed lengths to Curl_strntolower "
        "\n"
        "Also fixes off-by-one: Curl_strntolower used dlen+1 (included NUL); "
        "post-patch uses dlen with explicit NUL termination. "
        "\n"
        "Notable: patch adapted by 'PkgAgent/deepseek-v4' for opencloudos-stream. "
        "TOS 4.6 is adapting patches via automated AI tooling. "
        "\n"
        "Reported-by: not listed in patch."
    ),
    "affected_files": ["lib/cookie.c"],
    "ai_adaptation_note": "Adapted-by: PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)",
}

# ──────────────────────────────────────────────────────────────────────────────
# F06 — SSH global knownhosts not set (CVE-2025-15079)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F06_SSH_KNOWNHOSTS = {
    "finding_id": "TOS46-CURL-F06",
    "severity": "MEDIUM",
    "cve": "CVE-2025-15079",
    "title": (
        "libssh backend: SSH_OPTIONS_GLOBAL_KNOWNHOSTS not set — curl only "
        "set SSH_OPTIONS_KNOWNHOSTS; libssh checks BOTH; mismatch allows "
        "global knownhosts to override per-session known-hosts file"
    ),
    "description": (
        "lib/vssh/libssh.c myssh_connect() — SSH session init. "
        "\n"
        "libssh has two separate knownhosts options: "
        "  SSH_OPTIONS_KNOWNHOSTS — per-session knownhosts file "
        "  SSH_OPTIONS_GLOBAL_KNOWNHOSTS — system-wide knownhosts file "
        "\n"
        "curl only set SSH_OPTIONS_KNOWNHOSTS. libssh checks both files. "
        "If the system global knownhosts (/etc/ssh/ssh_known_hosts) "
        "contained a different or conflicting entry for the target host, "
        "host key verification could use the wrong key or accept an "
        "unexpected host key. "
        "\n"
        "Post-patch: immediately after setting KNOWNHOSTS, also sets "
        "SSH_OPTIONS_GLOBAL_KNOWNHOSTS to the same file path, ensuring "
        "both options point to the user-specified file. "
        "\n"
        "Security window: narrow — requires a system that has a global "
        "known_hosts with conflicting entries for target hosts."
    ),
    "affected_files": ["lib/vssh/libssh.c"],
    "reporter": None,
}

# ──────────────────────────────────────────────────────────────────────────────
# F07 — SSH pubkey auth without key (CVE-2025-15224)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F07_SSH_PUBKEY_NOKEY = {
    "finding_id": "TOS46-CURL-F07",
    "severity": "MEDIUM",
    "cve": "CVE-2025-15224",
    "title": (
        "libssh: pubkey auth initiated when neither private key nor ssh-agent "
        "configured — curl would enter SSH_AUTH_PKEY_INIT state, attempt "
        "key auth, fail silently, and potentially skip to password auth"
    ),
    "description": (
        "lib/vssh/libssh.c myssh_statemach_act() — SSH auth state machine. "
        "\n"
        "Pre-patch: "
        "  if(sshc->auth_methods & SSH_AUTH_METHOD_PUBLICKEY) { "
        "    state(data, SSH_AUTH_PKEY_INIT); "
        "\n"
        "Post-patch: "
        "  if((sshc->auth_methods & SSH_AUTH_METHOD_PUBLICKEY) && "
        "    (data->set.str[STRING_SSH_PRIVATE_KEY] || "
        "     (data->set.ssh_auth_types & CURLSSH_AUTH_AGENT))) { "
        "\n"
        "Without the fix: curl would always attempt pubkey auth when the server "
        "advertised SSH_AUTH_METHOD_PUBLICKEY, even with no private key set "
        "and ssh-agent not configured. "
        "\n"
        "The useless auth attempt could: "
        "  - Consume an auth attempt (servers with MaxAuthTries) "
        "  - Log a failed auth event on the server "
        "  - Cause libssh to use an unintended default key from ~/.ssh/"
    ),
    "affected_files": ["lib/vssh/libssh.c"],
    "reporter": None,
}

# ──────────────────────────────────────────────────────────────────────────────
# F08 — X.509 store cache key missing no_partialchain (CVE-2025-14819)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F08_X509_CACHE = {
    "finding_id": "TOS46-CURL-F08",
    "severity": "MEDIUM",
    "cve": "CVE-2025-14819",
    "title": (
        "OpenSSL: shared X.509 store cache does not include no_partialchain "
        "in cache key — a connection with SSL_CTX_FLAG_NO_PARTIAL_CHAIN disabled "
        "can reuse a store built for a connection with it enabled, causing "
        "incorrect certificate chain acceptance/rejection"
    ),
    "description": (
        "lib/vtls/openssl.c — multi_ssl_backend_data cached X509_STORE management. "
        "\n"
        "struct multi_ssl_backend_data caches a shared X509_STORE. "
        "cached_x509_store_different() compares the cached store against the "
        "current connection's config to determine if a new store is needed. "
        "\n"
        "Pre-patch: compared only CAfile path. "
        "If two connections use the same CA file but different no_partialchain "
        "settings, the wrong cached store was returned. "
        "\n"
        "Post-patch: adds BIT(no_partialchain) to multi_ssl_backend_data. "
        "cached_x509_store_different() compares no_partialchain. "
        "set_cached_x509_store() saves no_partialchain with the cached store. "
        "\n"
        "Security implication: "
        "  Partial chain = an SSL chain that does not lead to a trusted root. "
        "  If no_partialchain=TRUE (strict), partial chains are rejected. "
        "  If a strict-mode connection cached the store, a lax-mode connection "
        "  could inherit the strict store — FALSE NEGATIVE (rejected valid chain). "
        "  Conversely: lax-mode cached store reused for strict — FALSE POSITIVE "
        "  (accepted partial chain that should be rejected)."
    ),
    "affected_files": ["lib/vtls/openssl.c"],
    "reporter": None,
}

# ──────────────────────────────────────────────────────────────────────────────
# F09 — redirect + netrc credential handling (CVE-2024-11053)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F09_NETRC_CREDS = {
    "finding_id": "TOS46-CURL-F09",
    "severity": "MEDIUM",
    "cve": "CVE-2024-11053",
    "title": (
        "Two-patch netrc/redirect credential fix: (1) redirect lost username but "
        "kept password when using URL credentials; (2) netrc parser accepted "
        "incomplete entries, wrong login/password order, ASCII control chars"
    ),
    "description": (
        "Patch 1 — lib/url.c, lib/transfer.c (Tobias Bora): "
        "  parseurlandfillconn() overwrote password from URL but not username "
        "  when CREDS_OPTION was set — result: request sent with option username "
        "  but URL-derived password (or vice versa). "
        "  Added CREDS_OPTION/CREDS_URL tracking to creds_from field. "
        "  Added test 998 and 999 to verify. "
        "\n"
        "Patch 2 — lib/netrc.c, lib/url.c (Harry Sintonen): "
        "  (a) netrc entry could match with login but no password — "
        "      parser now ensures password is set (blank if absent). "
        "  (b) Multiple login entries for same host — parser could pick "
        "      second entry if login/password appeared in reverse order "
        "      (password: before login: token). "
        "  (c) Netrc credentials with ASCII control codes not rejected — "
        "      HTTP protocol doesn't support control chars in headers; "
        "      a .netrc with embedded \\r or \\0 could inject into HTTP headers. "
        "  Tests 478, 479, 480 added to verify."
    ),
    "affected_files": ["lib/url.c", "lib/transfer.c", "lib/netrc.c"],
    "reporter": ["Tobias Bora (patch 1)", "Harry Sintonen (patch 2)"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F10 — HSTS match preference (CVE-2024-9681)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F10_HSTS_MATCH = {
    "finding_id": "TOS46-CURL-F10",
    "severity": "MEDIUM",
    "cve": "CVE-2024-9681",
    "title": (
        "HSTS Curl_hsts() prefers first-found subdomain match over "
        "a more specific full-host match — incorrect HSTS policy applied "
        "when HSTS list contains both exact hostname and wildcard entries"
    ),
    "description": (
        "lib/hsts.c Curl_hsts() — HSTS database lookup. "
        "\n"
        "Pre-patch: first subdomain match in the HSTS list was returned "
        "immediately. If the list contained: "
        "  *.example.com includeSubDomains expires=2027 "
        "  api.example.com includeSubDomains expires=2025 "
        "and api.example.com appeared after *.example.com in the list, "
        "the wildcard entry would be returned first — wrong expiry. "
        "\n"
        "Post-patch: "
        "  Full host match returned immediately (optimal result). "
        "  Longest subdomain tail match tracked in bestsub. "
        "  After full scan: if no full match, return bestsub. "
        "\n"
        "Impact: wrong HSTS maxage applied — either too long (keeps forcing "
        "HTTPS past expiry) or too short (drops HTTPS protection early)."
    ),
    "affected_files": ["lib/hsts.c"],
    "reporter": None,
}

# ──────────────────────────────────────────────────────────────────────────────
# F11 — cookie path "/" becomes empty (CVE-2025-9086)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F11_COOKIE_PATH = {
    "finding_id": "TOS46-CURL-F11",
    "severity": "MEDIUM",
    "cve": "CVE-2025-9086",
    "title": (
        "sanitize_cookie_path() strips trailing slash even when path is '/' — "
        "cookie with path='/' gets empty spath causing assertion failure or "
        "broad cookie matching; reported by Google Big Sleep"
    ),
    "description": (
        "lib/cookie.c sanitize_cookie_path() — cookie path normalization. "
        "\n"
        "Pre-patch: "
        "  if(len && new_path[len - 1] == '/') { "
        "    new_path[len - 1] = 0x0; "
        "  } "
        "For path='/', this truncates to empty string. "
        "\n"
        "Post-patch: "
        "  if(len > 1 && new_path[len - 1] == '/') "
        "Only strips trailing slash if len > 1, preserving '/' paths. "
        "\n"
        "Also in Curl_cookie_add(): "
        "  sep = strchr(clist->spath + 1, '/') — if spath is empty, "
        "  spath+1 is past end of string — UB. "
        "  Post-patch adds DEBUGASSERT(clist->spath[0]) and len guard. "
        "\n"
        "Reported-by: Google Big Sleep — Google's AI-powered security research. "
        "This is a second PSL/cookie path bug in the same release cycle, "
        "alongside CVE-2026-8924."
    ),
    "affected_files": ["lib/cookie.c"],
    "reporter": "Google Big Sleep",
}

# ──────────────────────────────────────────────────────────────────────────────
# F12 — GnuTLS OCSP stapling bypass (CVE-2024-8096)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F12_OCSP_BYPASS = {
    "finding_id": "TOS46-CURL-F12",
    "severity": "LOW",
    "cve": "CVE-2024-8096",
    "title": (
        "GnuTLS OCSP stapling: gnutls_ocsp_status_request_is_checked() == 0 "
        "does not distinguish 'check passed' from 'check not run' — "
        "curl accepted valid OCSP response as 'not checked' in some paths"
    ),
    "description": (
        "lib/vtls/gtls.c Curl_gtls_verifyserver() — post-handshake verification. "
        "\n"
        "Pre-patch: "
        "  if(config->verifystatus) { "
        "    if(gnutls_ocsp_status_request_is_checked(session, 0) == 0) { "
        "      // attempt to get and parse OCSP response "
        "\n"
        "gnutls_ocsp_status_request_is_checked() returns 0 on both: "
        "  - no OCSP staple present in handshake "
        "  - OCSP check was not performed "
        "  Returning 0 meant both 'no staple' and 'check ok' in some versions. "
        "\n"
        "Post-patch: unconditionally calls gnutls_ocsp_status_request_get() "
        "when verifystatus=true. GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE → fail. "
        "Parse and check the OCSP response directly. "
        "\n"
        "Also adds GNUTLS_NO_STATUS_REQUEST flag when verifystatus=false — "
        "disables the status_request TLS extension entirely, reducing "
        "unnecessary staple negotiation. "
        "\n"
        "Reported-by: Hiroki Kurosawa"
    ),
    "affected_files": ["lib/vtls/gtls.c"],
    "reporter": "Hiroki Kurosawa",
}

# ──────────────────────────────────────────────────────────────────────────────
# F13 — ASN.1 GTime2str parsing (CVE-2024-7264)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F13_ASN1_GTIME = {
    "finding_id": "TOS46-CURL-F13",
    "severity": "LOW",
    "cve": "CVE-2024-7264",
    "title": (
        "x509asn1 GTime2str(): off-by-one in fractional seconds count; "
        "CURLE_BAD_FUNCTION_ARGUMENT returned as const char* (pointer confusion); "
        "missing NUL in timezone 'GMT' case — two-patch fix"
    ),
    "description": (
        "lib/vtls/x509asn1.c GTime2str() — ASN.1 GeneralizedTime to string. "
        "\n"
        "Patch 1 bugs: "
        "  fracl = tzp - fracp - 1 — off by one (should be tzp - fracp) "
        "  if(tzp == fracp) return CURLE_BAD_FUNCTION_ARGUMENT — returns "
        "    an integer constant cast to const char*, not an error path "
        "  tzp = fracp++ then while(tzp < end ...) — tzp starts at wrong position "
        "  'Z' case: tzp='  GMT', end=tzp+4 — no NUL termination "
        "\n"
        "Patch 2 (follow-up fix): "
        "  Fixes fracl = tzp - fracp (not -1) "
        "  Fixes fracp++ before tzp=fracp "
        "  Fixes 'Z' case to use sep='  ' + tzp='GMT' + tzl=3 "
        "  Adds unit tests in tests/unit/unit1656.c "
        "\n"
        "Reported-by: Dov Murik "
        "\n"
        "Exploitability: GTime2str is called when displaying certificate "
        "validity dates (e.g., via CURLINFO_CERTINFO). A malformed "
        "ASN.1 date in a server certificate could cause curl to read "
        "past the end of the date field into adjacent DER structure."
    ),
    "affected_files": ["lib/vtls/x509asn1.c"],
    "reporter": "Dov Murik",
}

# ──────────────────────────────────────────────────────────────────────────────
# F14 — wolfSSH removal (CVE-2025-10966)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F14_WOLFSSH = {
    "finding_id": "TOS46-CURL-F14",
    "severity": "LOW",
    "cve": "CVE-2025-10966",
    "title": (
        "wolfSSH backend removed (1174 lines, lib/vssh/wolfssh.c) — "
        "incomplete implementation, no known users, no bug reports — "
        "dead code that carried unaudited attack surface"
    ),
    "description": (
        "lib/vssh/wolfssh.c — complete deletion (1174 lines). "
        "\n"
        "The wolfSSH backend was built in but incomplete relative to "
        "libssh2 and libssh backends. "
        "No bugs were ever filed against it. No enhancements requested. "
        "This indicates the backend was never used in production. "
        "\n"
        "Security argument for removal: "
        "  Incomplete implementations often have incomplete input validation. "
        "  Dead code accumulates technical debt without receiving CVE scrutiny. "
        "  The wolfSSH library itself has had its own CVEs; "
        "  integrating it added attack surface without corresponding value. "
        "\n"
        "backport: from https://github.com/curl/curl/commit/b011e3fcfb06d6c027859"
    ),
    "affected_files": ["lib/vssh/wolfssh.c (deleted)"],
    "lines_removed": 1174,
}

# ──────────────────────────────────────────────────────────────────────────────
# F15 — PSL lowercase normalization (CVE-2023-46218)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F15_PSL_LOWERCASE = {
    "finding_id": "TOS46-CURL-F15",
    "severity": "INFO",
    "cve": "CVE-2023-46218",
    "title": (
        "Cookie PSL check used mixed-case domain names — "
        "psl_is_cookie_domain_acceptable() is case-sensitive; "
        "EXAMPLE.COM not in PSL, bypassing the suffix block"
    ),
    "description": (
        "lib/cookie.c Curl_cookie_add() — PSL domain check. "
        "\n"
        "Pre-patch: domain names passed directly to PSL without lowercasing. "
        "PSL library is case-sensitive by design. "
        "'EXAMPLE.COM' != 'example.com' to the PSL, so the check would "
        "not find 'EXAMPLE.COM' as a suffix and would allow setting cookies "
        "on that 'domain'. "
        "\n"
        "Post-patch: Curl_strntolower() applied to both domain and co->domain "
        "before PSL check. Also adds size guard (< 256 bytes). "
        "\n"
        "Reported-by: Harry Sintonen"
    ),
    "affected_files": ["lib/cookie.c"],
    "reporter": "Harry Sintonen",
}

# ──────────────────────────────────────────────────────────────────────────────
# F16 — Temp file name info disclosure (CVE-2023-46219)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F16_TEMPFILE = {
    "finding_id": "TOS46-CURL-F16",
    "severity": "INFO",
    "cve": "CVE-2023-46219",
    "title": (
        "curl temporary file named '<original_file>.<random>.tmp' — "
        "original file path embedded in temp name; excessive length on long paths; "
        "fix: uses random-only name in same directory"
    ),
    "description": (
        "lib/fopen.c Curl_fopen() — safe file write via temp+rename. "
        "\n"
        "Pre-patch: tempstore = aprintf('%s.%s.tmp', filename, randsuffix) "
        "  If filename='/home/user/.secret_config/credentials.netrc', "
        "  temp file is '/home/user/.secret_config/credentials.netrc.XXXXXXXX.tmp' "
        "  Full path visible in directory listings, process tables, inotify events. "
        "\n"
        "Post-patch: new dirslash() extracts directory component of filename. "
        "  tempstore = aprintf('%s%s.tmp', dir, randbuf) "
        "  Random name only — 40 alnum chars + .tmp "
        "  Dir separator ensures correct directory placement. "
        "\n"
        "Reported-by: Maksymilian Arciemowicz"
    ),
    "affected_files": ["lib/fopen.c"],
    "reporter": "Maksymilian Arciemowicz",
}

# ──────────────────────────────────────────────────────────────────────────────
# F17 — CURLOPT_PROTOCOLS_STR "-all" bypass (CVE-2024-2004)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F17_PROTO_FILTER = {
    "finding_id": "TOS46-CURL-F17",
    "severity": "INFO",
    "cve": "CVE-2024-2004",
    "title": (
        "CURLOPT_PROTOCOLS_STR with '-all' fails to clear allowed protocols "
        "because *val=0 was set AFTER NULL-input check — default set remains; "
        "fix: initialize to 0 before NULL check"
    ),
    "description": (
        "lib/setopt.c protocol2num() — protocol string to bitmask. "
        "\n"
        "Pre-patch: "
        "  if(!str) return CURLE_BAD_FUNCTION_ARGUMENT; "
        "  /* ... */ "
        "  *val = 0; /* only reached if str is not NULL */ "
        "  do { /* parse each token */ } while ... "
        "\n"
        "Also: protocol2num() wrote to a local 'prot' variable, not directly "
        "to data->set.allowed_protocols. If the call succeeded, the local "
        "was assigned — but if '-all' produced a zero result and the function "
        "had early-exited the do-while, the zero was not written. "
        "\n"
        "Post-patch: "
        "  *val = 0; /* moved to top, before NULL check */ "
        "  protocol2num() now writes directly to data->set.allowed_protocols "
        "  and data->set.redir_protocols (no intermediate variable). "
        "\n"
        "Reported-by: Dan Fandrich"
    ),
    "affected_files": ["lib/setopt.c"],
    "reporter": "Dan Fandrich",
}

# ──────────────────────────────────────────────────────────────────────────────
# F18 — netrc 'default' empty match (CVE-2025-0167)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F18_NETRC_DEFAULT = {
    "finding_id": "TOS46-CURL-F18",
    "severity": "INFO",
    "cve": "CVE-2025-0167",
    "title": (
        "netrc 'default' entry with no login/password treated as successful match "
        "— curl would proceed with empty credentials rather than no-auth"
    ),
    "description": (
        "lib/netrc.c parsenetrc() — .netrc file parser. "
        "\n"
        "A .netrc file can contain: "
        "  machine specific.host login user password secret "
        "  default "
        "\n"
        "Pre-patch: 'default' with no login/password was a successful match "
        "(retcode=0 + our_login=NULL + password=NULL → blank password added). "
        "curl would send a request with empty username and empty password. "
        "\n"
        "Post-patch: if !login && !password after parsing, "
        "return NETRC_FILE_MISSING (no match). "
        "\n"
        "Reported-by: Yihang Zhou"
    ),
    "affected_files": ["lib/netrc.c"],
    "reporter": "Yihang Zhou",
}

# ──────────────────────────────────────────────────────────────────────────────
# F19 — HTTP/2 push cleanup (CVE-2024-2398, Tencent upstream)
# ──────────────────────────────────────────────────────────────────────────────

CURL_F19_H2_PUSH = {
    "finding_id": "TOS46-CURL-F19",
    "severity": "INFO",
    "cve": "CVE-2024-2398",
    "title": (
        "HTTP/2 push promise header cleanup refactor — duplicate free_push_headers() "
        "calls consolidated; realloc failure path leaked headers; "
        "authored by zoedong@tencent.com (Tencent upstream curl contributor)"
    ),
    "description": (
        "lib/http2.c — HTTP/2 push promise handling in nghttp2 callback. "
        "\n"
        "Pre-patch: push header cleanup duplicated in three places: "
        "  http2_data_done(), push_promise(), on_header() bailout. "
        "  on_header() used Curl_safefree() on push_headers before iterating — "
        "  so the inner free() calls used a freed pointer. "
        "  Also: in on_header() realloc failure path, "
        "    Curl_safefree(stream->push_headers) freed the array but not elements. "
        "\n"
        "Post-patch: free_push_headers() helper introduced — "
        "  frees each element, then Curl_safefree(stream->push_headers), "
        "  resets push_headers_used=0. Used in all three paths. "
        "\n"
        "In on_header() realloc path: switches from Curl_saferealloc to realloc "
        "so that on failure, the original pointer is preserved for free_push_headers() "
        "to clean up correctly (Curl_saferealloc nulls the pointer on failure). "
        "\n"
        "Author: zoedong@tencent.com — contributed upstream to curl. "
        "This Tencent fix appears in TOS 4.6 via the upstream inclusion path."
    ),
    "affected_files": ["lib/http2.c"],
    "tencent_author": "zoedong@tencent.com",
}

# ──────────────────────────────────────────────────────────────────────────────
# RELEASE DELTA TABLE
# ──────────────────────────────────────────────────────────────────────────────

RELEASE_DELTA = {
    "curl-8.4.0-15.tl4": {
        "cve_patches": 18,
        "new_cves": [
            "CVE-2023-46218", "CVE-2023-46219",
            "CVE-2024-2004", "CVE-2024-2398",
            "CVE-2024-7264 (2-patch)", "CVE-2024-8096",
            "CVE-2024-9681", "CVE-2024-11053 (2-patch)",
            "CVE-2025-0167", "CVE-2025-9086",
            "CVE-2025-10966", "CVE-2025-14017",
            "CVE-2025-14524", "CVE-2025-14819",
            "CVE-2025-15079", "CVE-2025-15224",
        ],
    },
    "curl-8.4.0-16.tl4": {
        "cve_patches": 4,
        "new_cves": ["CVE-2026-5545", "CVE-2026-6429 (4-patch: 3 pre + main)"],
    },
    "curl-8.4.0-17.tl4": {
        "cve_patches": 1,
        "new_cves": ["CVE-2026-8924"],
    },
    "total_cve_patches": 23,
    "unique_cves": 19,
    "cve_years": {
        "2023": 2,
        "2024": 8,
        "2025": 9,
        "2026": 3,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-CURL-F01": CURL_F01_REDIRECT_CRED,
    "TOS46-CURL-F02": CURL_F02_BEARER_LEAK,
    "TOS46-CURL-F03": CURL_F03_LDAP_NULL,
    "TOS46-CURL-F04": CURL_F04_NTLM_NEGOTIATE,
    "TOS46-CURL-F05": CURL_F05_PSL_TRAILINGDOT,
    "TOS46-CURL-F06": CURL_F06_SSH_KNOWNHOSTS,
    "TOS46-CURL-F07": CURL_F07_SSH_PUBKEY_NOKEY,
    "TOS46-CURL-F08": CURL_F08_X509_CACHE,
    "TOS46-CURL-F09": CURL_F09_NETRC_CREDS,
    "TOS46-CURL-F10": CURL_F10_HSTS_MATCH,
    "TOS46-CURL-F11": CURL_F11_COOKIE_PATH,
    "TOS46-CURL-F12": CURL_F12_OCSP_BYPASS,
    "TOS46-CURL-F13": CURL_F13_ASN1_GTIME,
    "TOS46-CURL-F14": CURL_F14_WOLFSSH,
    "TOS46-CURL-F15": CURL_F15_PSL_LOWERCASE,
    "TOS46-CURL-F16": CURL_F16_TEMPFILE,
    "TOS46-CURL-F17": CURL_F17_PROTO_FILTER,
    "TOS46-CURL-F18": CURL_F18_NETRC_DEFAULT,
    "TOS46-CURL-F19": CURL_F19_H2_PUSH,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "packages": ["curl-8.4.0-15.tl4", "curl-8.4.0-16.tl4", "curl-8.4.0-17.tl4"],
        "unique_cves": RELEASE_DELTA["unique_cves"],
        "tencent_upstream_author": "zoedong@tencent.com (CVE-2024-2398)",
        "ai_adapted_patch": "CVE-2026-8924 by PkgAgent/deepseek-v4",
        "findings": [
            {
                "id": k,
                "cve": v.get("cve"),
                "severity": v.get("severity"),
                "title": v.get("title", "")[:80],
            }
            for k, v in FINDINGS.items()
        ],
        "release_delta": RELEASE_DELTA,
    }, indent=2))
