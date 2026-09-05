"""
TencentOS Server 4.6 AppStream Network Servers RE Module
Packages: bind-9.18.21-6.tl4, httpd-2.4.68-1.tl4, nginx-1.29.8-1.tl4.ap.1,
          squid-6.5-11.tl4, haproxy-2.6.19-5.tl4, vsftpd-3.0.5-6.tl4,
          dnsmasq-2.89-6.tl4
Source: /media/cowboy/research/tencentos/4.6/AppStream-source/
Method: rpm2cpio extraction + patch audit + spec changelog analysis
Analysis date: 2026-09-04

PKGAGENT ATTRIBUTION:
  Multiple patches across bind, squid, curl carry patch header:
  'PkgAgent/deepseek-v4' or 'PkgAgent/deepseek-v4-flash'
  This is Tencent's internal AI agent system that adapts upstream CVE patches
  to the OpenCloudOS/TencentOS build stream. This attribution appears ONLY in
  complex multi-file patches (bind CVE-2026-5946 5-part, squid CVE-2026-32748).

VERSION LADDERS:
  bind:     9.18.21-1.tl4 (Jan 2024) → 9.18.21-6.tl4 (Aug 2025)
  nginx:    1.29.6-1.tl4.ap.1 → 1.29.8-1.tl4.ap.1 (Sep 2025)
  squid:    6.5-7.tl4 → 6.5-11.tl4 (Sep 2025)
  haproxy:  2.6.19-1.tl4 → 2.6.19-5.tl4 (Sep 2025)
  dnsmasq:  2.89-1.tl4 → 2.89-6.tl4 (Aug 2025)

FINDINGS:
  TOS46-NET-F01 (HIGH/8.6)    dnsmasq NSEC bitmap infinite loop pre-auth DoS (CVE-2026-4890)
  TOS46-NET-F02 (HIGH/8.2)    nginx OCSP use-after-free (CVE-2026-40701)
  TOS46-NET-F03 (HIGH/7.8)    squid ICP v3 use-after-free (CVE-2026-32748)
  TOS46-NET-F04 (HIGH/7.5)    haproxy FCGI integer overflow (CVE-2026-55203)
  TOS46-NET-F05 (HIGH/7.3)    bind CHAOS class recursion amplification (CVE-2026-5946)
  TOS46-NET-F06 (INFO)        httpd 2.4.68: same 14-patch set as 2.4.66, no new delta
  TOS46-NET-F07 (INFO)        PkgAgent/deepseek-v4 AI-assisted patch attribution
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

NETWORK_SERVER_INVENTORY = {
    "bind": {
        "version": "9.18.21-6.tl4",
        "total_patches": 22,
        "notable_cves": [
            "CVE-2026-5946 (5-part)", "CVE-2026-11721 (2-part)", "CVE-2026-12617",
            "CVE-2024-11187", "CVE-2024-12705",
            "CVE-2023-50387", "CVE-2023-50868", "CVE-2023-5517", "CVE-2023-5679",
            "CVE-2023-3341", "CVE-2024-0760", "CVE-2024-1737", "CVE-2024-1975",
            "CVE-2024-4076",
        ],
        "pkgagent_in": ["CVE-2026-5946"],
    },
    "nginx": {
        "version": "1.29.8-1.tl4.ap.1",
        "patches": 5,
        "cves": ["CVE-2026-40701", "CVE-2026-42055", "CVE-2026-42533",
                 "CVE-2026-42945", "CVE-2026-9256"],
        "version_note": ".ap.1 suffix = Tencent additions on top of NGINX 1.29.8 OSS",
    },
    "squid": {
        "version": "6.5-11.tl4",
        "notable_cves_v11": ["CVE-2026-32748", "CVE-2026-33515"],
        "earlier_cves": ["CVE-2025-59362", "CVE-2025-62168"],
        "pkgagent_in": ["CVE-2026-32748"],
    },
    "haproxy": {
        "version": "2.6.19-5.tl4",
        "notable_cves_v5": ["CVE-2026-55203", "CVE-2026-55204"],
        "earlier_cves": ["CVE-2025-11230"],
    },
    "dnsmasq": {
        "version": "2.89-6.tl4",
        "notable_cves_v6": ["CVE-2026-4890", "CVE-2026-4891",
                             "CVE-2026-4892", "CVE-2026-4893", "CVE-2026-2291"],
    },
    "httpd": {
        "version": "2.4.68-1.tl4",
        "patch_count": 14,
        "note": "Same 14 patches as httpd-2.4.66-1.tl4; no new CVE patches in 2.4.68",
    },
    "vsftpd": {
        "version": "3.0.5-6.tl4",
        "patch_count": 66,
        "note": "Heavy Tencent patching; mostly feature/compat; needs dedicated binary RE",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-NET-F01: dnsmasq NSEC bitmap infinite loop (CVE-2026-4890)
# ──────────────────────────────────────────────────────────────────────────────

DNSMASQ_NSEC_INFINITE_LOOP_CVE_2026_4890 = {
    "finding_id": "TOS46-NET-F01",
    "severity": "HIGH",
    "cvss_v3": 8.6,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
    "cve": "CVE-2026-4890",
    "package": "dnsmasq-2.89-6.tl4 (fixed), 2.89-5.tl4 and earlier vulnerable",
    "title": (
        "dnsmasq DNSSEC NSEC bitmap parsing: bitmap advance uses p[1] instead of p[1]+2; "
        "attacker-controlled NSEC record with crafted bitmap length triggers infinite loop; "
        "pre-authentication DoS — exploitable before RRSIG validation"
    ),
    "description": (
        "dnsmasq's DNSSEC validation code in src/dnssec.c processes NSEC (Next Secure) "
        "records, which contain a 'Type Bit Maps' field. The bit map field format per "
        "RFC 4034 section 4.1.2 is: [window_block][bitmap_length][bitmap_data...] "
        "\n"
        "The advance pointer expression to move past each bitmap window block should be: "
        "  p += p[1] + 2   (2 bytes overhead: window_block + bitmap_length fields) "
        "\n"
        "The vulnerable code used: "
        "  p += p[1]       (missing the +2 for the overhead bytes) "
        "\n"
        "When an attacker sends a response (or crafts a UDP DNS response) with an NSEC "
        "record where bitmap_length == 0, the pointer never advances: p += 0 → infinite loop. "
        "When bitmap_length is carefully crafted, the pointer advances backwards into "
        "already-processed data. "
        "\n"
        "CRITICAL: this occurs in the NSEC bitmap parsing loop BEFORE RRSIG signature "
        "validation. Any DNS response containing an NSEC record triggers the parsing — "
        "an attacker controlling a forged DNS response (DNS cache poisoning, MitM, or "
        "a rogue authoritative server) can crash the dnsmasq process. "
        "\n"
        "Fix at two locations in dnssec.c (lines ~1296 and ~1455): "
        "  -   p += p[1];        "
        "  +   p += p[1] + 2;    "
    ),
    "attack_vector": (
        "DNS response injection → NSEC bitmap with length=0 → dnsmasq infinite loop. "
        "No authentication required. Network-accessible. "
        "Reachable from: local network, rogue upstream DNS, DNS cache poisoning, "
        "any network that can send UDP/53 responses to the dnsmasq host."
    ),
    "attack_chain": (
        "1. Identify TOS 4.6 host using dnsmasq (common in container/K8s environments). "
        "2. Craft UDP DNS response containing NSEC RR with bitmap_length=0. "
        "3. Trigger dnsmasq to resolve a name that returns the malformed NSEC. "
        "4. dnsmasq loops on NSEC parsing, consuming 100% CPU. "
        "5. All DNS resolution on the host fails — containers cannot resolve service names. "
        "6. Container orchestrator interprets health check failures as node failure → cascading. "
        "Severity amplified in Kubernetes nodes where dnsmasq serves cluster DNS."
    ),
    "references": [
        "CVE-2026-4890",
        "RFC 4034 section 4.1.2 (NSEC Type Bit Maps)",
        "dnsmasq-2.89-6.tl4 SRPM: dnsmasq-CVE-2026-4890.patch",
    ],
    "same_release_cves": {
        "CVE-2026-4891": "Added in same 2.89-6 release; DNSSEC RRSIG handling",
        "CVE-2026-4892": "Added in same 2.89-6 release; NSEC3 handling",
        "CVE-2026-4893": "Added in same 2.89-6 release; DNSSEC verification path",
        "CVE-2026-2291": "DNS-over-HTTPS (DoH) handling",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-NET-F02: nginx OCSP use-after-free (CVE-2026-40701)
# ──────────────────────────────────────────────────────────────────────────────

NGINX_OCSP_UAF_CVE_2026_40701 = {
    "finding_id": "TOS46-NET-F02",
    "severity": "HIGH",
    "cvss_v3": 8.2,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "cve": "CVE-2026-40701",
    "package": "nginx-1.29.8-1.tl4.ap.1 (fixed), 1.29.6 and earlier vulnerable",
    "title": (
        "nginx OCSP stapling: SSL connection close during in-progress resolver lookup "
        "frees ctx before resolver callback fires; use-after-free in SSL context "
        "→ information disclosure or crash"
    ),
    "description": (
        "nginx's OCSP stapling feature performs asynchronous DNS lookups to resolve OCSP "
        "responder hostnames. When ssl_stapling is enabled, nginx allocates an OCSP context "
        "(ngx_ssl_ocsp_t) and initiates a resolver lookup via ngx_resolve_name(). "
        "\n"
        "If the SSL connection is closed (e.g., client sends TCP RST or FIN) while the "
        "resolver lookup is still in progress: "
        "  1. Connection cleanup runs ngx_ssl_ocsp_cleanup(), freeing the OCSP context. "
        "  2. The asynchronous resolver callback fires later. "
        "  3. Callback accesses already-freed ctx → use-after-free. "
        "\n"
        "The use-after-free can yield: "
        "  - Memory disclosure: freed memory content read through the OCSP context. "
        "  - Crash: if freed memory has been reallocated and the callback overwrites. "
        "\n"
        "Fix adds: ctx->resolve pointer tracking. When SSL connection cleanup occurs, "
        "calls ngx_resolve_name_done(ctx->resolve) to cancel the pending resolver query "
        "BEFORE freeing the OCSP context. Also nulls ctx->resolve after cancellation."
    ),
    "preconditions": [
        "ssl_stapling on; (nginx config)",
        "TLS connection establishment + immediate close (no full handshake required)",
        "Timing window: connection close while DNS resolver lookup is in-flight",
    ],
    "additional_cves_nginx_1298": {
        "CVE-2026-42055": "nginx HTTP/2 stream handling memory corruption",
        "CVE-2026-42533": "nginx HTTP/3 QUIC path validation bypass",
        "CVE-2026-42945": "nginx ngx_http_proxy_module header handling OOB",
        "CVE-2026-9256": "nginx upstream keep-alive connection handling",
    },
    "references": [
        "CVE-2026-40701",
        "nginx-1.29.8-1.tl4.ap.1 SRPM: nginx-CVE-2026-40701.patch",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-NET-F03: squid ICP v3 use-after-free (CVE-2026-32748)
# ──────────────────────────────────────────────────────────────────────────────

SQUID_ICP_UAF_CVE_2026_32748 = {
    "finding_id": "TOS46-NET-F03",
    "severity": "HIGH",
    "cvss_v3": 7.8,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cve": "CVE-2026-32748",
    "package": "squid-6.5-11.tl4 (fixed), 6.5-10.tl4 and earlier vulnerable",
    "patch_author": "PkgAgent/deepseek-v4-flash (per patch header attribution)",
    "title": (
        "squid ICP v3 (Internet Cache Protocol): HttpRequest destroyed by ACLFilledChecklist "
        "while still referenced in icpGetRequest(); use-after-free in cache peering code"
    ),
    "description": (
        "squid's ICP (Internet Cache Protocol) implementation handles cache-peering queries "
        "between squid instances. In icp_v3.cc, icpHandleIcpV3() calls icpGetRequest() to "
        "create an HttpRequest object for ACL evaluation. An ACLFilledChecklist is then "
        "used for access control checking. "
        "\n"
        "When ACLFilledChecklist runs icpAccessAllowed(), it could trigger early destruction "
        "of the HttpRequest object via destructor chains before icpGetRequest() was done "
        "with it — a use-after-free. "
        "\n"
        "Fix: "
        "  1. Change icpGetRequest() return type to HttpRequestPointer (smart pointer with "
        "     ref counting) instead of raw HttpRequest*. "
        "  2. Move the icpAccessAllowed() call inside icpGetRequest() so the smart pointer "
        "     holds a reference for the duration of the ACL check. "
        "  3. Access control decision is made before releasing the pointer. "
        "\n"
        "Note: PkgAgent/deepseek-v4-flash attribution in patch header indicates this "
        "complex ICP v3 refactor was AI-assisted."
    ),
    "attack_vector": (
        "ICP protocol runs on UDP port 3130 by default. Any squid cache peer "
        "or network peer sending ICP v3 queries can trigger the use-after-free. "
        "In a cache hierarchy, a rogue cache peer can exploit this remotely."
    ),
    "references": [
        "CVE-2026-32748",
        "squid-6.5-11.tl4 SRPM: squid-CVE-2026-32748.patch",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-NET-F04: haproxy FCGI integer overflow (CVE-2026-55203)
# ──────────────────────────────────────────────────────────────────────────────

HAPROXY_FCGI_OVERFLOW_CVE_2026_55203 = {
    "finding_id": "TOS46-NET-F04",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2026-55203",
    "package": "haproxy-2.6.19-5.tl4 (fixed), 2.6.19-4.tl4 and earlier vulnerable",
    "title": (
        "haproxy mux_fcgi.c: uint16_t drl overflows to 0 when drl += drp "
        "wraps (drp=255 + drl=65535+1); infinite loop or OOB in FCGI multiplexer"
    ),
    "description": (
        "haproxy's FastCGI (FCGI) multiplexer mux_fcgi.c tracks data record lengths "
        "using two variables: "
        "  uint16_t drl  — data record length remaining "
        "  uint16_t drp  — data record padding "
        "\n"
        "The expression: drl += drp "
        "\n"
        "When drl is near uint16 max (65535) and drp is non-zero, this addition wraps "
        "around to a small value, causing the FCGI state machine to compute an "
        "incorrect data record length. This can cause: "
        "  - Infinite loop as the state machine loops waiting for data that never arrives "
        "  - OOB read/write if the wrapped length is used for buffer positioning "
        "\n"
        "Fix: widen both variables to uint32_t. "
        "  -   uint16_t drl, drp; "
        "  +   uint32_t drl, drp; "
        "\n"
        "Maximum FCGI data record length is bounded by the 65535 uint16_t maximum, "
        "so uint32_t is sufficient to prevent any overflow in practice."
    ),
    "attack_vector": (
        "Attacker controls backend FCGI application responses. Any FCGI response "
        "with carefully crafted padding values can trigger the overflow. "
        "If haproxy fronts PHP-FPM or similar FCGI backend, a compromised backend "
        "application can crash haproxy via this path."
    ),
    "references": ["CVE-2026-55203", "haproxy-2.6.19-5.tl4 SRPM: haproxy-CVE-2026-55203.patch"],
    "companion_cve": "CVE-2026-55204 (2nd FCGI mux fix, same 2.6.19-5 release)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-NET-F05: bind CHAOS class recursion (CVE-2026-5946)
# ──────────────────────────────────────────────────────────────────────────────

BIND_CHAOS_RECURSION_CVE_2026_5946 = {
    "finding_id": "TOS46-NET-F05",
    "severity": "HIGH",
    "cvss_v3": 7.3,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2026-5946",
    "package": "bind-9.18.21-6.tl4 (5-part fix), 9.18.21-5.tl4 and earlier vulnerable",
    "patch_author": "PkgAgent/deepseek-v4 (per patch header attribution in 5-part series)",
    "patch_files": [
        "bind-9.18.21-CVE-2026-5946-1of5.patch",
        "bind-9.18.21-CVE-2026-5946-2of5.patch",
        "bind-9.18.21-CVE-2026-5946-3of5.patch",
        "bind-9.18.21-CVE-2026-5946-4of5.patch",
        "bind-9.18.21-CVE-2026-5946-5of5.patch",
    ],
    "title": (
        "named allows recursive queries for non-IN (e.g., CHAOS) class RRs; "
        "CHAOS class recursion enables amplification via view-private queries "
        "being forwarded to public resolvers; 5-part fix disables non-IN recursion"
    ),
    "description": (
        "BIND named supports multiple DNS classes. The IN (Internet) class is the standard; "
        "CHAOS class (CH) contains special meta-records like version.bind and hostname.bind "
        "which expose server identity. "
        "\n"
        "Prior to CVE-2026-5946 fix, named would accept recursive query requests for "
        "non-IN class (e.g., ANY CHAOS) and forward them to upstream resolvers. Since "
        "CHAOS queries are typically handled only by the queried server's local zone, "
        "forwarding them to public resolvers could: "
        "  1. Leak internal CHAOS zone data (version.bind exposes BIND version to external). "
        "  2. Enable amplification attacks using CHAOS query forwarding. "
        "  3. Reveal internal nameserver identity via view-private CHAOS queries "
        "     routed through the public resolution path. "
        "\n"
        "Fix (5-part series): disables recursion for queries where class != IN. "
        "Non-IN queries are answered from local authoritative zones only; "
        "no recursion is attempted for CHAOS, HESIOD, or any non-IN class."
    ),
    "references": [
        "CVE-2026-5946",
        "bind-9.18.21-6.tl4 SRPM: bind-9.18.21-CVE-2026-5946-*of5.patch",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-NET-F06: httpd 2.4.68 no new patches
# ──────────────────────────────────────────────────────────────────────────────

HTTPD_NO_DELTA = {
    "finding_id": "TOS46-NET-F06",
    "severity": "INFO",
    "title": (
        "httpd-2.4.68-1.tl4 contains the same 14-patch set as httpd-2.4.66-1.tl4; "
        "version bump from 2.4.66 to 2.4.68 carries no new CVE patches on TOS 4.6 — "
        "upstream 2.4.68 security fixes are included via source update, not patches"
    ),
    "patches_unchanged": 14,
    "note": (
        "httpd's CVE coverage in 2.4.68 comes from the upstream version bump itself. "
        "Tencent does not add CVE backport patches on top; they track the upstream "
        "release branch. The 14 existing patches are Tencent customizations "
        "(hardening, OpenSSL compat, locale fixes) carried forward unchanged."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-NET-F07: PkgAgent/deepseek-v4 AI patch attribution
# ──────────────────────────────────────────────────────────────────────────────

PKGAGENT_DEEPSEEK_ATTRIBUTION = {
    "finding_id": "TOS46-NET-F07",
    "severity": "INFO",
    "title": (
        "PkgAgent/deepseek-v4 and PkgAgent/deepseek-v4-flash attribution found in "
        "multi-file CVE patch headers for bind (CVE-2026-5946) and squid (CVE-2026-32748); "
        "Tencent uses AI agent to adapt upstream CVE patches to TencentOS build stream"
    ),
    "observed_attributions": {
        "bind-CVE-2026-5946": "PkgAgent/deepseek-v4 (5-part series, most complex bind patch)",
        "squid-CVE-2026-32748": "PkgAgent/deepseek-v4-flash (ICP v3 refactor)",
        "curl-CVE-2026-6429": "PkgAgent/deepseek-v4 (in pre-patches)",
    },
    "pattern": (
        "Attribution appears only in complex multi-file patches that require non-trivial "
        "adaptation from upstream (e.g., adapting a 5-part series against 9.18.x to 9.18.21). "
        "Simple single-file backports do NOT carry PkgAgent attribution. "
        "\n"
        "This is significant: it means Tencent is deploying AI-generated CVE patches "
        "to production kernel/network services. The AI is adapting patches, not writing "
        "them from scratch — but any adaptation errors would go directly to production. "
        "\n"
        "Implication for RE: AI-adapted patches may contain subtle differences from "
        "upstream fixes (different line numbers, slightly different logic due to context "
        "mismatch). Patch validation is critical — the adaptation could be incomplete."
    ),
    "investigation_priority": (
        "Compare PkgAgent-attributed patches against upstream fixes to identify "
        "adaptation gaps. A mis-adapted patch might fix only the primary exploit path "
        "while leaving a secondary one open."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-NET-F01": DNSMASQ_NSEC_INFINITE_LOOP_CVE_2026_4890,
    "TOS46-NET-F02": NGINX_OCSP_UAF_CVE_2026_40701,
    "TOS46-NET-F03": SQUID_ICP_UAF_CVE_2026_32748,
    "TOS46-NET-F04": HAPROXY_FCGI_OVERFLOW_CVE_2026_55203,
    "TOS46-NET-F05": BIND_CHAOS_RECURSION_CVE_2026_5946,
    "TOS46-NET-F06": HTTPD_NO_DELTA,
    "TOS46-NET-F07": PKGAGENT_DEEPSEEK_ATTRIBUTION,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "packages": list(NETWORK_SERVER_INVENTORY.keys()),
        "pkgagent_attribution": ["bind CVE-2026-5946 (5-part)", "squid CVE-2026-32748", "curl CVE-2026-6429"],
        "pre_auth_dos": ["CVE-2026-4890 dnsmasq NSEC bitmap (before RRSIG validation)"],
        "findings": [{"id": k, "severity": v.get("severity", "?"), "cve": v.get("cve", "-")}
                     for k, v in FINDINGS.items()],
    }, indent=2))
