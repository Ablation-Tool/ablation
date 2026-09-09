"""
RouterOS 7.24.2 — libuhttp.so Binary RE (HTTP/1.1 + HTTP/2 Client/Server Library)
Target binary: /lib/libuhttp.so (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 171K
Source: routeros-7.24.2.npk → squashfs-root → /lib/libuhttp.so
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm -D C++ symbol demangling, string extraction,
        CVE mitigation fingerprinting, nghttp2 feature detection

CONSUMERS (binaries linking libuhttp.so):
  - /nova/bin/www      (WebFig HTTP/2 server — primary attack surface)
  - likely: tr069-client-7.24.2.npk (TR-069/CWMP over HTTP/1.1 or HTTP/2)
  - likely: user-manager package (captive portal HTTP frontend)
  All consumers inherit libuhttp.so's nghttp2 implementation and attack surface.

IMPORT SYMBOL SWEEP (nm -D):
  nghttp2_session_mem_recv   — HTTP/2 receive, stateful session parser (C callback)
  nghttp2_session_recv       — HTTP/2 receive (network-reading variant)
  nghttp2_session_mem_recv2  — HTTP/2 receive v2 API
  nghttp2_session_want_read  — session read-readiness check
  malloc / realloc           — heap allocation (nghttp2 internal use)
  memmove                    — present
  read / recvmsg             — I/O

  ABSENT: strcpy, strcat, sprintf, system, execve — no obvious C-string vulnerabilities
  in libuhttp.so's own code (nghttp2 is the risk surface, not the RouterOS wrapper).

C++ SYMBOL LANDSCAPE (demangled):
  HttpHeaders class:
    HttpHeaders::hasHeader(string const&)
    HttpHeaders::getHeader(string const&, string*)
    HttpHeaders::getHeader(string const&, unsigned long long*)
    HttpHeaders::getHeader(string const&, vector<string>*)
    HttpHeaders::addHeader(string const&, string const&, AllowDuplicates)
    HttpHeaders::removeHeader(string const&)
    HttpHeaders::parseHeaderLine(string const&)
    HttpHeaders::getAllFieldStrEv()

  HTTP Authentication:
    HttpAuthHeaderParser::readAuthParamValue()
    HttpAuthHeaderParser::readParamOrScheme()
    HttpAuthHeaderParser::next()
    HttpAuthHolder::parseHeader(string const&)
    HttpAuthMngr::processRcvdAuthHeadersERK(vector<string> const&)

  HTTP/2 implementation layer:
    Http2Impl::onStreamCloseCallback(nghttp2_session*, int, unsigned int, void*)
    Http2Impl::onDataChunkRecvCallback(nghttp2_session*, unsigned char, int,
                                       unsigned char const*, unsigned long, void*)
    Http2Impl::sendCallback(nghttp2_session*, unsigned char const*, unsigned long,
                            int, void*)
    Http2Impl::recvCallback(nghttp2_session*, unsigned char*, unsigned long, int, void*)
    Http2Impl::getNvList(vector<pair<string*,string*>>)
    Http2Impl::onFrameRecvCallback(nghttp2_session*, nghttp2_frame const*, void*)
    Http2Impl::onHeaderCallback(nghttp2_session*, nghttp2_frame const*,
                                unsigned char const*, unsigned long,
                                unsigned char const*, unsigned long,
                                unsigned char, void*)
    Http2Impl::performRequest(HttpClient*)
    Http2Impl::SessionSend(nghttp2_session*)
    Http2Impl::SessionReceive(nghttp2_session*)
    Http2Impl::terminateSession(nghttp2_session*)
    Http2Impl::setupCallbacks(nghttp2_session_callbacks*)
    Http2Impl::setupCallbacks(nghttp2_session_callbacks*)
    Http2Impl::cleanupSession(nghttp2_session*)

  HttpClient::onHttp2Data(int, unsigned int)

=== FINDING: MTIK-HTTP-F01 — nghttp2 EMBEDDED STATIC LIBRARY VERSION ===

IDENTIFICATION METHOD: Feature fingerprinting via exported symbol set + error strings.

CONFIRMED PRESENT:
  "Flooding was detected in this HTTP/2 session, and it must be closed"
    → CVE-2023-44487 (HTTP/2 Rapid Reset) mitigation — added in nghttp2 1.57.0

  "Too many CONTINUATION frames following a HEADER frame"
    → CVE-2024-28182 (HTTP/2 CONTINUATION Flood) mitigation — added in nghttp2 1.61.0

  "SETTINGS frame contained more than the maximum allowed entries"
    → SETTINGS flood protection — added in nghttp2 1.61.0 timeframe

  nghttp2_session_change_extpri_stream_priority
  nghttp2_extpri_parse_priority
  nghttp2_submit_priority_update
    → RFC 9218 EXTENSIBLE_PRIORITIES support — added in nghttp2 1.59.0

  nghttp2_session_mem_recv2
  nghttp2_session_mem_send2
    → v2 API variants — added in nghttp2 1.59.0

VERSION LOWER BOUND: >= 1.61.0 (CONTINUATION flood mitigation present)
VERSION UPPER BOUND: unknown without explicit version string

IMPLICATIONS:
  - CVE-2023-44487 (HTTP/2 Rapid Reset, CVSS 7.5): MITIGATED
  - CVE-2024-28182 (CONTINUATION Flood, CVSS 5.3): MITIGATED
  - Unknown CVEs introduced after 1.61.0: status unknown

  The library is statically compiled into libuhttp.so. No runtime patch path
  exists without a full firmware update. Any new nghttp2 CVE discovered against
  versions >= 1.61.0 would affect all RouterOS 7.x versions built before a patch.

STATUS: INFO — major known CVEs mitigated; monitor for post-1.61.0 nghttp2 CVEs.

=== FINDING: MTIK-HTTP-F02 — HTTP AUTH HEADER PARSING ATTACK SURFACE ===

LOCATION: HttpAuthHolder::parseHeader + HttpAuthMngr::processRcvdAuthHeadersERK
CONTEXT:
  Two-stage authentication header processing:
  1. HttpAuthHolder::parseHeader(string const&) — parses a single WWW-Authenticate
     or Authorization header field. Uses HttpAuthHeaderParser state machine with:
       - readParamOrScheme() — reads auth scheme name or parameter name
       - readAuthParamValue() — reads parameter value (quoted-string or token)
       - next() — advances the token cursor
  2. HttpAuthMngr::processRcvdAuthHeadersERK(vector<string> const&) — processes
     the full set of received auth headers, likely selecting the strongest supported
     scheme (Digest, Basic, Bearer).

ATTACK SURFACE:
  These functions parse attacker-controlled HTTP header values (if libuhttp.so is
  used as an HTTP CLIENT — i.e., TR-069 client receiving headers from a rogue ACS).
  If used as HTTP SERVER (WebFig), they parse client-supplied Authorization headers.

  RouterOS WebFig accepts Basic and Digest auth on the management interface.
  If HttpAuthHeaderParser has an off-by-one or state confusion bug in quoted-string
  parsing, a malformed Authorization header from a client could cause memory
  corruption in the WebFig process.

  TR-069 client: if the ACS server is compromised (or MITM'd), it controls the
  response headers including WWW-Authenticate. A malformed challenge response
  reaching readAuthParamValue() could corrupt the tr069-client process heap.

CANDIDATE SCENARIO:
  Craft an Authorization header with:
    (a) Deeply nested quoted-string values
    (b) Excessively long auth scheme name (> expected buffer)
    (c) Mixed case + special chars in parameter names
  Target: processRcvdAuthHeadersERK memory operations on the input vector.

STATUS: CANDIDATE — requires fuzzing of auth header parser against live WebFig.
  Recommended: ffuf against WebFig /login with crafted Authorization: headers.

=== FINDING: MTIK-HTTP-F03 — HTTP/2 UPGRADE AND ALPN NEGOTIATION ===

STRINGS OBSERVED:
  "HTTP/2 not supported in ALPN, close connection"
  "HTTP/2 not supported in ALPN"
  "HTTP/2 not supported in ALPN, Fallback to http/1.1"
  "PRI * HTTP/2.0"  — HTTP/2 connection preface (client-initiated upgrade without ALPN)

CONTEXT:
  libuhttp.so supports three HTTP/2 establishment paths:
  1. ALPN negotiation (TLS h2) — primary path on TLS connections
  2. HTTP/1.1 Upgrade: h2c header — plaintext HTTP/1.1 to HTTP/2 upgrade
  3. Connection preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" — direct H2

  The fallback path ("Fallback to http/1.1") means the library supports protocol
  downgrade. A downgrade attack from HTTP/2 to HTTP/1.1 could trigger HTTP/1.1-
  specific parsing paths (chunked transfer encoding, Content-Length handling) that
  have different security characteristics.

CHUNKED PARSING:
  Strings: "chunked error", "content-length", "transfer-encoding", "chunked"
  Both chunked and Content-Length are handled. CL-TE desync (HTTP request smuggling)
  requires a front-end proxy that disagrees with the backend on body length. If WebFig
  is fronted by a reverse proxy or load balancer in enterprise deployments, this
  attack surface exists.

OBSERVED HEADER HANDLING:
  "401 should contain www-authenticate header" — auth flow enforcement
  "timeout receiving headers" — header receive timeout (DoS mitigated)
  "Content-Length" in parsed form — standard CL handling

STATUS:
  HTTP/2 ALPN + downgrade path: INFORMATIONAL
  Chunked/CL desync: CANDIDATE if proxied (no proxy in default RouterOS config)
  Auth header parsing: see MTIK-HTTP-F02

=== FINDING: MTIK-HTTP-F04 — TR-069/CWMP CLIENT ATTACK SURFACE ===

CONTEXT:
  libuhttp.so is the HTTP client library for TR-069 (CWMP) — the remote management
  protocol used by ISPs to configure CPE (RouterOS acting as CPE). The TR-069 client
  connects OUT to an Auto-Configuration Server (ACS) controlled by the ISP.

  If the ACS URL is intercepted (DNS poisoning, BGP hijack, or ISP-side compromise),
  an attacker controls the HTTP response that the TR-069 client parses via libuhttp.so.

  Attack vectors from a rogue ACS response:
  1. Malformed HTTP/2 HEADERS frame → HPACK decoder bug
  2. Oversized HTTP/2 DATA frame → iov_len check in recv callback
  3. Crafted WWW-Authenticate header → HttpAuthHolder::parseHeader
  4. SOAP/XML body with crafted RPC → above libuhttp layer (tr069 parser)
  5. 302 redirect loop → resource exhaustion

  The RB5009UPr+S+ target (36.64.234.59) is on PT Telekomunikasi Indonesia (AS7713).
  If this device uses TR-069 for ISP management (common in SOHO/SMB deployment),
  the ACS URL may be configurable or injectable via DHCP option 43.

STATUS: CANDIDATE — requires confirmation that TR-069 is enabled on the target.
  Check via SNMP: cwmpACS* OIDs, or via RouterOS API if credentials obtained.

=== ATTACK SURFACE SUMMARY ===

  Tier 1 (network-reachable, pre-auth):
    HTTP/2 HEADERS flood via WebFig (mitigated in nghttp2 >= 1.61.0)
    HTTP/2 SETTINGS flood (mitigated)
    Auth header parsing in WebFig (unauthenticated client can send Authorization)

  Tier 2 (ISP-adjacent, requires network position):
    TR-069 rogue ACS → full HTTP response control → auth header + HPACK injection

  Tier 3 (post-auth or local):
    HTTP request smuggling (if proxied)

=== RECOMMENDED NEXT STEPS ===

  1. Fuzz WebFig Authorization: header field — target HttpAuthHolder::parseHeader
     with libFuzzer or Boofuzz against live WebFig endpoint (accessible via
     firewall bypass: sport=80/443 → dport=443).
  2. Confirm TR-069 client status via SNMP (cwmpACS MIB or tr069 package check).
  3. Identify exact nghttp2 version by comparing binary hash with known releases.
  4. Monitor nghttp2 CVE feed for post-1.61.0 disclosures.
"""

BINARY_PATH = "/lib/libuhttp.so"
VERSION = "7.24.2"

FINDINGS = [
    {
        "id": "MTIK-HTTP-F01",
        "severity": "INFO",
        "title": "Embedded nghttp2 >= 1.61.0 — major CVEs mitigated, version unknown above 1.61.0",
        "description": (
            "CVE-2023-44487 and CVE-2024-28182 both mitigated via embedded mitigation strings. "
            "RFC 9218 EXTENSIBLE_PRIORITIES present (>= 1.59.0). Post-1.61.0 CVEs unknown."
        ),
        "cve_status": "CVE-2023-44487: MITIGATED | CVE-2024-28182: MITIGATED",
    },
    {
        "id": "MTIK-HTTP-F02",
        "severity": "MEDIUM",
        "title": "HTTP auth header parser (HttpAuthHolder::parseHeader) — unverified bounds",
        "description": (
            "Two-stage auth header parser processes attacker-controlled WWW-Authenticate/"
            "Authorization values. readAuthParamValue() handles quoted-string tokens. "
            "No bounds check confirmed for token length. Fuzzing needed."
        ),
        "cve_status": "CANDIDATE — pending fuzz validation",
    },
    {
        "id": "MTIK-HTTP-F03",
        "severity": "LOW",
        "title": "HTTP/2 ALPN downgrade to HTTP/1.1 — CL-TE desync if proxied",
        "description": (
            "Library supports HTTP/2-to-HTTP/1.1 fallback. Chunked and Content-Length "
            "parsing both present. Request smuggling if fronted by proxy. No proxy "
            "in default RouterOS config."
        ),
        "cve_status": "INFO — default config not vulnerable",
    },
    {
        "id": "MTIK-HTTP-F04",
        "severity": "MEDIUM",
        "title": "TR-069 client HTTP response processing — rogue ACS can control parse input",
        "description": (
            "TR-069 client uses libuhttp.so for HTTP. A rogue ACS (via DNS poisoning, "
            "DHCP option 43, or ISP compromise) controls all HTTP response fields "
            "reaching auth header parser and HPACK decoder."
        ),
        "cve_status": "CANDIDATE — requires TR-069 enabled on target",
    },
]


def describe():
    print(f"RouterOS {VERSION} /lib/libuhttp.so — RE findings summary")
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
        print(f"           CVE status: {f['cve_status']}")


if __name__ == "__main__":
    describe()
