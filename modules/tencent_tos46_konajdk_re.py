"""
TencentOS 4.6 — TencentKona JDK security patch RE.

Packages:
  java-8-konajdk-8.0.27-1.tl4    — TencentKona-8, based on OpenJDK 8u422+
  java-11-konajdk-11.0.32-1.tl4  — TencentKona-11
  java-17-konajdk-17.0.20-1.tl4  — TencentKona-17

Method: spec changelog CVE enumeration + patch file diff analysis.
3 CVE patches backported to all three JDK major versions simultaneously.

Context: TencentKona is Tencent's OpenJDK distribution with additional features
(TGCA/SM2 cipher support, G1GC improvements, NUMA-aware allocation). The JDK
packages ship with Tencent-backported security fixes before upstream GA releases.
"""

PACKAGES = {
    "java-8-konajdk": {
        "version": "8.0.27",
        "release": "1.tl4",
        "upstream_base": "TencentKona-8.0.9-322 (OpenJDK 8u322+)",
        "tarball": "TencentKona8.0.9.b1_jdk_linux-x86_64_8u322.tar.gz",
        "source": "https://github.com/Tencent/TencentKona-8",
        "cve_patches": 3,
    },
    "java-11-konajdk": {
        "version": "11.0.32",
        "release": "1.tl4",
        "upstream_base": "TencentKona-11.0.26",
        "source": "https://github.com/Tencent/TencentKona-11",
        "cve_patches": 3,
    },
    "java-17-konajdk": {
        "version": "17.0.20",
        "release": "1.tl4",
        "upstream_base": "TencentKona-17.0.14",
        "source": "https://github.com/Tencent/TencentKona-17",
        "cve_patches": 3,
    },
}

CVE_ANALYSES = {
    "CVE-2026-60589": {
        "jbs_id": "8382471",
        "severity": "HIGH",
        "component": "security-libs/javax.xml.crypto",
        "subsystem": "XML Digital Signatures (XMLDSig) — ResourceResolver URI scheme detection",
        "affects": ["java-8-konajdk", "java-11-konajdk", "java-17-konajdk"],
        "files_changed": [
            "jdk/src/share/classes/com/sun/org/apache/xml/internal/security/utils/resolver/ResourceResolverSpi.java",
            "jdk/src/share/classes/com/sun/org/apache/xml/internal/security/utils/resolver/implementations/ResolverDirectHTTP.java",
            "jdk/src/share/classes/com/sun/org/apache/xml/internal/security/utils/resolver/implementations/ResolverLocalFilesystem.java",
        ],
        "description": (
            "The XMLDSig URIDereferencer's engineCanResolveURI() methods in ResolverDirectHTTP and "
            "ResolverLocalFilesystem used simple String.startsWith() for URI scheme detection. "
            "This is incorrect for two reasons: "
            "(1) A relative URI with no scheme (e.g., 'http.example.com/path') satisfies "
            "    context.uriToResolve.startsWith('http:') only if the string literally begins with 'http:'. "
            "    But a URI like '//evil.com/path' (protocol-relative) or 'http%3A//evil.com/path' (encoded) "
            "    could be misrouted to the wrong resolver. "
            "(2) ResolverLocalFilesystem's old guard 'context.uriToResolve.startsWith(\"http:\")' was the "
            "    wrong exclusion rule — it excluded HTTP URIs from file resolution, but this was fragile "
            "    against mixed-case or encoded schemes. "
            "The fix adds a scheme(String uri) helper that parses the scheme character-by-character: "
            "scans for ':' before any of '/', '?', '#' (similar to java.net.URI::parse). "
            "Returns null if no scheme is found or if the first path character appears before ':'. "
            "Both resolvers now use scheme() instead of startsWith(), and handle null scheme "
            "(relative URI) separately from explicit scheme values."
        ),
        "attack_scenario": (
            "An attacker who can supply a crafted XML document to a Java application that validates "
            "XMLDSig signatures could construct a Reference element with a URI that tricks the resolver "
            "into dereferencing a resource from an unintended location. "
            "For example: a relative URI that the old code routes to ResolverDirectHTTP when it should "
            "not, causing an HTTP request to an attacker-controlled server (SSRF), or routing to "
            "ResolverLocalFilesystem when the URI is scheme-relative, enabling local file read "
            "during signature validation. "
            "Severity depends on the application's XMLDSig usage — requires attacker control over "
            "the Reference URI within a signed document."
        ),
        "scheme_helper": {
            "code": (
                "protected static final String scheme(String uri) { "
                "  if (uri == null) return null; "
                "  char[] uriChars = uri.toCharArray(); "
                "  for (int i = 0; i < uriChars.length; i++) { "
                "    if (uriChars[i] == '/' || uriChars[i] == '?' || uriChars[i] == '#') return null; "
                "    if (uriChars[i] == ':') return uri.substring(0, i); "
                "  } "
                "  return null; "
                "}"
            ),
            "note": (
                "Correctly handles: null URI → null, relative URI → null, "
                "'http://...' → 'http', 'file:...' → 'file', 'https:...' → 'https', "
                "'//host/path' → null (no scheme before first '/'). "
                "Returns null for no-scheme case, allowing callers to check the baseUri scheme instead."
            ),
        },
        "class": "incorrect-input-validation / SSRF / local-file-read",
    },

    "CVE-2026-61308": {
        "jbs_id": "8384708",
        "severity": "MEDIUM",
        "component": "core-libs/java.net",
        "subsystem": "HttpURLConnection — Proxy-Authorization header not stripped on redirect",
        "affects": ["java-8-konajdk", "java-11-konajdk", "java-17-konajdk"],
        "files_changed": [
            "jdk/src/share/classes/sun/net/www/http/HttpClient.java",
            "jdk/src/share/classes/sun/net/www/protocol/http/HttpURLConnection.java",
        ],
        "description": (
            "HttpURLConnection did not strip the Proxy-Authorization header when following "
            "HTTP redirects. When a connection using an authenticating HTTP proxy follows a "
            "redirect to a different host, the Proxy-Authorization header (containing base64-encoded "
            "proxy credentials) was forwarded in the redirected request. "
            "The destination server (different from the proxy) receives the proxy credentials, "
            "which are: (a) unnecessary — the destination is not the proxy, and "
            "(b) a credential leak — the destination can log or extract the proxy password. "
            "Three-part fix: "
            "(1) Added getHttpProxy() to HttpClient: returns the HttpClient's proxy if it is "
            "    of type Proxy.Type.HTTP, null otherwise. "
            "(2) Added 'Proxy lastProxy' field to HttpURLConnection. In followRedirect0(), "
            "    save lastProxy = http.getHttpProxy() before disconnecting. "
            "    In the redirect loop, if the new connection's proxy differs from lastProxy "
            "    (or there's no proxy), call requests.remove('Proxy-Authorization'). "
            "(3) HTTPS CONNECT tunnel fix: when the tunnel is established (CONNECT → 200 OK), "
            "    remove Proxy-Authorization from savedRequests — the saved requests are then "
            "    replayed inside the TLS tunnel where the proxy can't see them anyway. "
            "(4) Avoid HTTP_PROXY_AUTH handling during TUNNELING state "
            "    (tunnelState() != TunnelState.TUNNELING guard added)."
        ),
        "attack_scenario": (
            "Target: Java application that uses HttpURLConnection through an authenticating HTTP proxy "
            "and follows redirects. "
            "Attacker controls a redirect target (e.g., via a URL shortener or server-side redirect). "
            "Attacker's server receives the Proxy-Authorization header: "
            "'Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA=='. "
            "Attacker base64-decodes to extract proxy credentials (username:password). "
            "Credentials can then be used to authenticate to the enterprise proxy and intercept "
            "or MITM other users' corporate network traffic."
        ),
        "class": "information-disclosure / credential-leak",
    },

    "CVE-2026-70907": {
        "jbs_id": "8386205",
        "severity": "MEDIUM",
        "component": "security-libs/javax.net.ssl",
        "subsystem": "TLS 1.3 ServerHello — server may send a second HelloRetryRequest",
        "affects": ["java-8-konajdk", "java-11-konajdk", "java-17-konajdk"],
        "files_changed": [
            "jdk/src/share/classes/sun/security/ssl/ServerHandshakeContext.java",
            "jdk/src/share/classes/sun/security/ssl/ServerHello.java",
        ],
        "description": (
            "TLS 1.3 (RFC 8446 S4.1.4) explicitly states: a client receiving a second "
            "HelloRetryRequest in the same connection MUST abort with unexpected_message. "
            "The symmetric rule applies to the server: an RFC-compliant server MUST NOT send "
            "two HRRs in the same connection. "
            "The JDK TLS 1.3 server implementation lacked enforcement of this constraint. "
            "A TLS 1.3 server could, in theory, be made to emit a second HRR to a client "
            "that sent a second ClientHello (after a first HRR) with a different key_share group "
            "that the server still finds unsatisfactory. "
            "Fix: added 'boolean sentHRR' flag to ServerHandshakeContext. "
            "ServerHello.HelloRetryRequestMessage.produce() checks sentHRR at entry: "
            "if already set, throw fatal HANDSHAKE_FAILURE alert. "
            "After emitting the first HRR, set sentHRR = true."
        ),
        "attack_scenario": (
            "A malicious TLS 1.3 server (or MITM) could send repeated HelloRetryRequests to a client. "
            "From the server side: a client that supports multiple key_share groups could send a "
            "second ClientHello with a different group, attempting to force a second HRR negotiation. "
            "While RFC 8446 requires the CLIENT to abort, a server that complies with the spec "
            "closes the attack surface from the server side as well. "
            "Possible impact without the fix: "
            "(1) Key group downgrade via repeated HRR forcing selection of a weaker group, "
            "(2) Amplified handshake messages for DDoS, "
            "(3) Interoperability issues with strict RFC clients that abort on second HRR. "
            "With the fix, a second HRR attempt from any client triggers HANDSHAKE_FAILURE."
        ),
        "rfc_reference": "RFC 8446 §4.1.4 (HelloRetryRequest), §4.6.1 (server constraints)",
        "class": "tls-protocol-deviation / potential-cipher-downgrade",
    },
}

CROSS_VERSION_COVERAGE = {
    "note": "All 3 CVEs were patched simultaneously across JDK 8, 11, and 17.",
    "matrix": {
        "CVE-2026-60589": {"jdk8": True, "jdk11": True, "jdk17": True},
        "CVE-2026-61308": {"jdk8": True, "jdk11": True, "jdk17": True},
        "CVE-2026-70907": {"jdk8": True, "jdk11": True, "jdk17": True},
    },
    "backport_approach": (
        "All patches are structurally identical across JDK versions: same class paths "
        "(jdk/src/share/classes/), same field/method additions, same logic. "
        "JDK 8 uses the internal Apache XML Security shaded copy "
        "(com.sun.org.apache.xml.internal.security.*). "
        "JDK 11/17 use the modular javax.xml.crypto API paths. "
        "The proxy-auth and TLS patches are in common sun.net / sun.security paths, "
        "so the backport is a direct diff application."
    ),
    "prior_changelog_cves": {
        "context": "Prior release (also in spec changelog) fixed additional CVEs:",
        "jdk8_prior": [
            "CVE-2026-47057", "CVE-2026-47063", "CVE-2026-47058", "CVE-2026-60147",
            "CVE-2026-46968", "CVE-2026-47059", "CVE-2026-47027", "CVE-2026-47021",
            "CVE-2026-47010",
        ],
        "note": "Prior changelog CVEs not in this package's patch set — fixed by upstream base version bump.",
    },
}

KONAJDK_SPECIFICS = {
    "extensions_over_openjdk": [
        "TGCA (Tencent Group Certificate Authority) trust anchor integration",
        "SM2/SM3/SM4 cipher suite support (China national cryptographic standards)",
        "G1GC improvements for server workloads",
        "NUMA-aware memory allocation enhancements",
        "TencentKonaJDK vendor string in java.vendor system property",
    ],
    "security_relevance": (
        "SM2 support adds China national curve cipher suites to TLS. "
        "On TOS 4.6, HTTPS connections between Tencent microservices may use SM2-based "
        "cipher suites in addition to standard ECDHE/RSA suites. "
        "The SM2 implementation reuses the OpenSSL-derived stack analyzed in "
        "tencent_tos46_sm2_blob_re.py."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-60589",
        "title": "XMLDSig URIDereferencer: startsWith() scheme detection allows resource misrouting",
        "detail": (
            "ResolverDirectHTTP and ResolverLocalFilesystem used String.startsWith('http:'/'file:') "
            "for scheme classification. Protocol-relative ('//host/path') or edge-case URIs could be "
            "misrouted to wrong resolver. "
            "Fix: new scheme(String) helper parses URI char-by-char, finds ':' before path chars. "
            "Null return for relative URIs triggers baseUri scheme fallback. "
            "Affected: any Java app validating XMLDSig with attacker-controlled Reference URIs. "
            "Fixed in JDK 8.0.27 / 11.0.32 / 17.0.20 (TOS 4.6)."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "cve": "CVE-2026-61308",
        "title": "HttpURLConnection: Proxy-Authorization not stripped on HTTP redirect — credential leak",
        "detail": (
            "Proxy-Authorization header preserved through redirects to different host. "
            "Attacker-controlled redirect destination receives base64-encoded proxy credentials. "
            "Fix: HttpClient.getHttpProxy() added; lastProxy tracking in HttpURLConnection; "
            "header stripped when proxy changes or absent. Also: remove Proxy-Auth after CONNECT. "
            "Fixed in JDK 8.0.27 / 11.0.32 / 17.0.20 (TOS 4.6)."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "cve": "CVE-2026-70907",
        "title": "TLS 1.3 server: no guard against sending second HelloRetryRequest (RFC 8446 violation)",
        "detail": (
            "TLS 1.3 server could emit a second HRR in same connection, violating RFC 8446 §4.1.4. "
            "Risk: key group downgrade, handshake amplification, strict-client interoperability failure. "
            "Fix: sentHRR boolean in ServerHandshakeContext; second HRR attempt → fatal HANDSHAKE_FAILURE. "
            "Fixed in JDK 8.0.27 / 11.0.32 / 17.0.20 (TOS 4.6)."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "TencentKona JDK: SM2/SM3/SM4 cipher suites add national-standard TLS to TOS 4.6",
        "detail": (
            "TencentKona ships SM2 ECDH + SM3 HMAC + SM4 symmetric cipher suites for TLS. "
            "These suites are used in Tencent intra-datacenter communication on TOS 4.6. "
            "SM2 key exchange implementation analyzed in tencent_tos46_sm2_blob_re.py — "
            "OpenSSL-derived EVP stack with standard null-argument guards; no memory safety issues found."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 TencentKona JDK security patch RE")
    print()
    for pkg, info in PACKAGES.items():
        print(f"  {pkg}-{info['version']}-{info['release']}: {info['cve_patches']} CVE patches")
    print()
    print("CVE matrix (all 3 CVEs × all 3 JDK versions):")
    for cve, d in CVE_ANALYSES.items():
        print(f"  [{d['severity']:6s}] {cve} [{d['jbs_id']}]: {d['subsystem'][:60]}")
        print(f"            class: {d['class']}")
    print()
    for f in FINDINGS:
        cve = f"[{f['cve']}] " if f.get('cve') else ""
        print(f"  [{f['severity']:6s}] {f['id']}: {cve}{f['title'][:68]}")
