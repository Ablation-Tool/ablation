"""
TencentOS Server 4.6 gnutls RE Module
Source: gnutls-3.8.2-14.tl4 SRPM (3 releases: -11/-12/-14)
        /media/cowboy/research/tencentos/4.6/BaseOS-source/
Analysis date: 2026-09-04

PACKAGE: gnutls-3.8.2-14.tl4
  Upstream: GnuTLS 3.8.2
  Tencent releases: 11, 12, 14 (gap from 12→14 suggests -13 was internal/skipped)
  CVE patches: 14 total — 5 from 2024, 4 from 2025, 5 from 2026
  Non-CVE patches: hash-named upstream backports + ktls/pkcs11 fixes

NOTABLE EXTERNAL REPORTERS:
  CVE-2025-32988: OpenAI Security Research Team
  CVE-2025-32990: David Aitel (Immunity/NSO)
  CVE-2026-3833:  Oleh Konko (1seal.org) + Joshua Rogers (AISLE Research)
  CVE-2026-42011: Haruto Kimura (Stella)
  CVE-2026-42012: Oleh Konko (1seal.org)
  CVE-2026-42013: Haruto Kimura + Joshua Rogers (AISLE Research)
  CVE-2026-33846: Haruto Kimura + Oscar Reparaz + Zou Dikai

SECURITY FINDINGS: TOS46-TLS-F01 through TOS46-TLS-F12
  F01 HIGH    CVE-2026-33846  DTLS heap overwrite via fragment reassembly (3 missing checks)
  F02 MEDIUM  CVE-2025-6395   TLS 1.3 HRR+PSK NULL ptr deref (server-side pre-auth crash)
  F03 HIGH    CVE-2026-3833   x509 name constraint DNS comparison case-sensitive bypass
  F04 MEDIUM  CVE-2026-42012  URI SAN does not preclude CN fallback (RFC 6125 6.4.4 violation)
  F05 MEDIUM  CVE-2026-42013  Oversized SAN permits CN/DN fallback (RFC 6125 6.4.4 violation)
  F06 MEDIUM  CVE-2026-42011  Name constraint intersection skips empty permitted sets
  F07 MEDIUM  CVE-2025-32988  SAN othername double-free on ASN.1 write error (OpenAI reported)
  F08 LOW     CVE-2025-32989  SCT timestamp heap buffer overread (missing upper bound check)
  F09 LOW     CVE-2025-32990  certtool 1-byte heap write overrun in template parse (Aitel)
  F10 HIGH    CVE-2024-0553   RSA-PSK timing side-channel (known, backported)
  F11 MEDIUM  CVE-2024-28834  Minerva ECDSA nonce timing attack (known, backported)
  F12 INFO    CVE-2024-12243  Name constraints base rewrite (base for 2026 backports)

ATTACK CHAINS:
  CHAIN-1: pre-auth DTLS → heap overwrite → potential RCE on DTLS server
  CHAIN-2: TLS 1.3 HRR+PSK → NULL deref → pre-auth server crash
  CHAIN-3: rogue cert with excluded domain case variation → name constraint bypass
  CHAIN-4: cert with URI SAN + matching CN → CN-fallback hostname bypass
  CHAIN-5: RSA-PSK timing oracle → key recovery
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_PACKAGE = {
    "name": "gnutls",
    "version": "3.8.2",
    "release": "14.tl4",
    "tencent_releases": [11, 12, 14],
    "cve_count": 14,
    "cve_by_year": {"2024": 5, "2025": 4, "2026": 5},
    "source_srpm": "gnutls-3.8.2-14.tl4.src.rpm",
    "total_patches": 29,
    "key_affected_components": [
        "lib/buffers.c (DTLS reassembly)",
        "lib/handshake.c (TLS 1.3 HRR+PSK)",
        "lib/x509/name_constraints.c (name constraints)",
        "lib/x509/hostname-verify.c (SAN hostname check)",
        "lib/x509/email-verify.c (email SAN check)",
        "lib/x509/extensions.c (SAN othername)",
        "lib/x509/x509_ext.c (SCT parsing)",
        "src/certtool-cfg.c (certtool template)",
    ],
    "external_reporters": {
        "OpenAI Security Research Team": ["CVE-2025-32988"],
        "David Aitel": ["CVE-2025-32990"],
        "Oleh Konko (1seal.org)": ["CVE-2026-3833", "CVE-2026-42012"],
        "Joshua Rogers (AISLE Research Team)": ["CVE-2026-3833", "CVE-2026-42013"],
        "Haruto Kimura (Stella)": ["CVE-2026-42011", "CVE-2026-42013", "CVE-2026-33846"],
        "Oscar Reparaz": ["CVE-2026-33846"],
        "Zou Dikai": ["CVE-2026-33846"],
    },
    "impact_scope": (
        "gnutls is a widely-used TLS library. On TOS 4.6 it is used by: "
        "NetworkManager, libcurl, wget, cyrus-sasl, OpenLDAP clients, systemd's "
        "optional HTTPS fetcher, and any package linked against libgnutls.so.30. "
        "Library-level bugs affect all callers; no recompile required to trigger."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# F01 — CVE-2026-33846: DTLS heap overwrite via fragment reassembly
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2026_33846 = {
    "finding_id": "TOS46-TLS-F01",
    "cve": "CVE-2026-33846",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector_dos": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cvss_vector_rce": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
    "component": "lib/buffers.c merge_handshake_packet()",
    "patch_file": "gnutls-3.8.2-CVE-2026-33846.patch",
    "reporters": ["Haruto Kimura (Stella)", "Oscar Reparaz", "Zou Dikai"],
    "title": (
        "DTLS handshake fragment reassembly (merge_handshake_packet()): three missing "
        "boundary checks allow heap overwrite via crafted fragments — plus sequence "
        "number missing from reassembly slot lookup enables cross-message fragment merging"
    ),
    "description": (
        "DTLS allows handshake messages to be fragmented across multiple datagrams. "
        "merge_handshake_packet() merges incoming fragments into a reassembly buffer. "
        "\n"
        "Bug 1 — Cross-message fragment merging (sequence number not checked): "
        "  Pre-patch slot lookup: if (recv_buf[i].htype == hsk->htype) "
        "  Two different handshake messages of the same type (same htype) but "
        "  different sequence numbers merge into the same reassembly slot. "
        "  Fix: add '&& recv_buf[i].sequence == hsk->sequence' to lookup. "
        "\n"
        "Bug 2 — Inconsistent message_length across fragments: "
        "  No check that fragment's claimed message_length matches "
        "  the in-progress reassembly's recorded length. "
        "  A fragment with inflated message_length can cause subsequent fragments "
        "  to write into the heap beyond the allocated reassembly buffer. "
        "  Fix: if (hsk->length != recv_buf[pos].length) → reject fragment. "
        "\n"
        "Bug 3 — Impossible fragment extent (start_offset + data.length > length): "
        "  No validation that the fragment's claimed position doesn't exceed the "
        "  overall message length. Allows memcpy into out-of-bounds offset. "
        "  Fix: if (hsk->length < hsk->start_offset + hsk->data.length) → reject. "
        "\n"
        "Bug 4 — Write past data.max_length: "
        "  No check that hsk->length <= recv_buf[pos].data.max_length. "
        "  The reassembly buffer is allocated based on the first fragment's claim; "
        "  if a later fragment claims a larger message_length, memcpy writes past "
        "  the end of the allocated buffer. "
        "  Fix: if (hsk->length > recv_buf[pos].data.max_length) → reject. "
        "\n"
        "Combined exploitation: "
        "  1. Open DTLS connection (no authentication required for ClientHello phase) "
        "  2. Send first ClientHello fragment: htype=CH, sequence=0, "
        "     message_length=X, start_offset=0, data.length=small "
        "     (allocates reassembly buffer of size X) "
        "  3. Send second fragment: htype=CH, sequence=1 (DIFFERENT message), "
        "     message_length=X+heap_overflow_delta, start_offset=X-delta "
        "     (same htype, different sequence → pre-patch: merges into same slot!) "
        "     (controlled memcpy with attacker-chosen data past buffer end) "
        "\n"
        "Impact: heap overwrite in the TLS server process at DTLS receive time. "
        "Server process handles many clients — heap layout is predictable in some "
        "implementations. DoS (crash) confirmed; RCE depends on allocator and "
        "heap layout of the specific gnutls application. "
        "\n"
        "Affected: any DTLS server using gnutls (e.g., OpenConnect VPN, Exim4 "
        "with STARTTLS+gnutls, openconnect daemon on TOS 4.6)."
    ),
    "attack_vector": "Pre-authentication DTLS fragment",
    "references": [
        "CVE-2026-33846",
        "GNUTLS-SA-2026-04-29-1",
        "https://gitlab.com/gnutls/gnutls/-/issues/1816",
        "https://gitlab.com/gnutls/gnutls/-/issues/1838",
        "https://gitlab.com/gnutls/gnutls/-/issues/1839",
        "upstream commits: 9deffca5 + 65ab33fa + 092c65d0",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F02 — CVE-2025-6395: TLS 1.3 HRR+PSK NULL ptr deref
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2025_6395 = {
    "finding_id": "TOS46-TLS-F02",
    "cve": "CVE-2025-6395",
    "severity": "MEDIUM",
    "cvss_v3": 5.9,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "component": "lib/handshake.c set_auth_types() + lib/state.c reset_binders()",
    "patch_file": "gnutls-3.8.2-CVE-2025-6395.patch",
    "reporter": "Stefan Bühler",
    "title": (
        "TLS 1.3 HRR + PSK resumption: second ClientHello omitting PSK leaves "
        "HSK_PSK_SELECTED flag set while PSK binder info is cleared — NULL pointer "
        "dereference in server during set_auth_types()"
    ),
    "description": (
        "TLS 1.3 HelloRetryRequest (HRR) + PSK scenario: "
        "  1. Client sends ClientHello1 with PSK extension "
        "     (HSK_PSK_SELECTED flag set) "
        "  2. Server sends HelloRetryRequest "
        "  3. Client sends ClientHello2 WITHOUT PSK extension "
        "     (PSK binder info cleared, but HSK_PSK_SELECTED still set) "
        "\n"
        "In set_auth_types(), code checks HSK_PSK_SELECTED to determine KX type: "
        "  if (session->internals.hsk_flags & HSK_PSK_SELECTED) "
        "    kx = GNUTLS_KX_PSK; "
        "\n"
        "With HSK_PSK_SELECTED set but PSK binder cleared: "
        "  kx = GNUTLS_KX_PSK → _gnutls_map_kx_get_cred(session, kx, false) "
        "  → attempts to dereference PSK credential pointer → NULL dereference "
        "\n"
        "Fix (two parts): "
        "  1. reset_binders() now explicitly clears HSK_PSK_SELECTED "
        "  2. gnutls_kx_get() uses gnutls_auth_client_get_type(session) == GNUTLS_CRD_PSK "
        "     instead of the HSK_PSK_SELECTED flag (flag only valid during handshake) "
        "\n"
        "Trigger: any TLS 1.3 server with PSK/session resumption enabled, "
        "targeted with a crafted ClientHello1+HRR+ClientHello2-without-PSK sequence. "
        "Pre-authentication — the crash occurs during the server's second ClientHello "
        "processing before any credentials are verified. "
        "\n"
        "Impact: pre-auth server crash (DoS). Affected services: any application "
        "using gnutls for TLS 1.3 server operation with session tickets or PSK mode. "
        "On TOS 4.6: Exim with gnutls, openconnect daemon, any HTTPS server built "
        "against libgnutls."
    ),
    "trigger_condition": "TLS 1.3 server with session tickets (GNUTLS_SERVER + PSK/resumption)",
    "references": [
        "CVE-2025-6395",
        "reported by Stefan Bühler",
        "test: tests/tls13/hello_retry_request_psk.c",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F03 — CVE-2026-3833: x509 name constraint DNS case-sensitive bypass
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2026_3833 = {
    "finding_id": "TOS46-TLS-F03",
    "cve": "CVE-2026-3833",
    "severity": "HIGH",
    "cvss_v3": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "component": "lib/x509/name_constraints.c ends_with() / dnsname_matches() / email_matches()",
    "patch_file": "gnutls-3.8.2-CVE-2026-3833.patch",
    "reporters": ["Oleh Konko (security@1seal.org)", "Joshua Rogers (AISLE Research Team)"],
    "title": (
        "x509 name constraints: DNS name comparison uses memcmp() (case-sensitive) "
        "instead of c_strncasecmp() — RFC 5280 §7.2 requires case-insensitive DNS "
        "label comparison; excluded constraints bypassed with uppercase hostnames"
    ),
    "description": (
        "RFC 5280 §7.2: "
        "  'When comparing DNS names for equality, conforming implementations MUST "
        "  perform a case-insensitive exact match on the entire DNS name.' "
        "\n"
        "Pre-patch: ends_with() and dnsname_matches() use memcmp() for DNS label "
        "suffix comparison. For excluded name constraints: "
        "  - nameConstraints excludedSubtrees: dNSName 'evil.com' "
        "  - Certificate SAN dNSName: 'EVIL.COM' or 'Evil.Com' "
        "  - Pre-patch: memcmp('EVIL.COM', 'evil.com', ...) → NOT equal → NOT excluded "
        "  - Fix: c_strncasecmp('EVIL.COM', 'evil.com', ...) → equal → EXCLUDED "
        "\n"
        "Result: a CA with nameConstraints excluding 'evil.com' does NOT block "
        "a certificate with SAN 'EVIL.COM' — the constraint is effectively bypassed. "
        "\n"
        "Email SAN fix detail: "
        "  - RFC 5321: local-part of email is case-sensitive "
        "    (user@domain: 'User' != 'user') "
        "  - RFC 5280 §7.2: domain part is case-insensitive "
        "    (user@DOMAIN == user@domain) "
        "  - Fix preserves case-sensitive match for local-part only; "
        "    domain part uses c_strncasecmp "
        "\n"
        "Attack scenario: "
        "  1. Attacker obtains cert from CA that has nameConstraints for 'target.com' "
        "     (e.g., a corporate CA constrained to its own domain) "
        "  2. Attacker crafts/obtains cert with SAN 'TARGET.COM' or 'TARGET.COM' "
        "  3. Pre-patch: constraint 'target.com' does NOT match 'TARGET.COM' "
        "  4. Certificate passes name constraint validation → accepted "
        "  5. Attacker presents cert for TARGET.COM in a MITM scenario "
        "\n"
        "Most impactful in PKI environments using name-constrained sub-CAs "
        "(enterprise CAs, HPKP-era multi-CA deployments)."
    ),
    "references": [
        "CVE-2026-3833",
        "GNUTLS-SA-2026-04-29-5",
        "RFC 5280 §7.2 (DNS name comparison in name constraints)",
        "c-strcase.h: gnulib's case-insensitive comparison primitives",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F04 — CVE-2026-42012: URI SAN does not preclude CN fallback
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2026_42012 = {
    "finding_id": "TOS46-TLS-F04",
    "cve": "CVE-2026-42012",
    "severity": "MEDIUM",
    "cvss_v3": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N",
    "component": "lib/x509/hostname-verify.c gnutls_x509_crt_check_hostname2()",
    "patch_file": "gnutls-3.8.2-CVE-2026-42012.patch",
    "reporter": "Oleh Konko (security@1seal.org)",
    "title": (
        "gnutls_x509_crt_check_hostname2(): IS_SAN_SUPPORTED() macro does not include "
        "GNUTLS_SAN_URI — URI SAN in a certificate does not suppress CN (Common Name) "
        "fallback for hostname verification per RFC 6125 §6.4.4"
    ),
    "description": (
        "RFC 6125 §6.4.4: "
        "  'a client MUST NOT seek a match for a reference identifier of CN-ID "
        "   if the presented identifiers include a DNS-ID, SRV-ID, URI-ID, or "
        "   any application-specific identifier types supported by the client.' "
        "\n"
        "Pre-patch IS_SAN_SUPPORTED macro: "
        "  (san == GNUTLS_SAN_DNSNAME || san == GNUTLS_SAN_IPADDRESS) "
        "\n"
        "GNUTLS_SAN_URI was NOT in the set of 'supported' SAN types. Result: "
        "  - Certificate has only URI SAN (e.g., URN, LDAP URI) "
        "  - No DNSNAME SAN present "
        "  - CN fallback: check Common Name for hostname match "
        "  - Attacker cert with URI='urn:some:identifier' and CN='target.example.com' "
        "    passes DNS hostname verification for target.example.com "
        "\n"
        "Fix: add GNUTLS_SAN_URI to IS_SAN_SUPPORTED() macro. "
        "\n"
        "Attack scenario: "
        "  1. Attacker obtains cert signed by a legitimate CA with: "
        "     CN=victim.com, SAN=[URI=urn:attacker:id] (no dnsName SAN) "
        "     (CA may issue URI SANs for non-web purposes without checking CN) "
        "  2. Client application verifies certificate for victim.com: "
        "     - No dnsName SAN → IS_SAN_SUPPORTED() never set → CN fallback triggers "
        "     - CN=victim.com matches → ACCEPTED "
        "  3. TLS MITM for victim.com using the URI-SAN cert "
        "\n"
        "Impact: primarily affects TLS clients using gnutls for DNS hostname "
        "verification (curl with gnutls, wget, NetworkManager connections, LDAP "
        "clients). Not exploitable against clients that require dnsName SANs "
        "(modern browsers ignore CN for host validation)."
    ),
    "references": [
        "CVE-2026-42012",
        "GNUTLS-SA-2026-04-29-7",
        "RFC 6125 §6.4.4 (CN fallback suppression rule)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F05 — CVE-2026-42013: Oversized SAN permits CN/DN fallback
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2026_42013 = {
    "finding_id": "TOS46-TLS-F05",
    "cve": "CVE-2026-42013",
    "severity": "MEDIUM",
    "cvss_v3": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N",
    "component": "lib/x509/hostname-verify.c + lib/x509/email-verify.c",
    "patch_file": "gnutls-3.8.2-CVE-2026-42013.patch",
    "reporters": ["Haruto Kimura (Stella)", "Joshua Rogers (AISLE Research Team)"],
    "title": (
        "gnutls_x509_crt_check_hostname2() / gnutls_x509_crt_check_email(): "
        "oversized SAN (GNUTLS_E_SHORT_MEMORY_BUFFER) does not set fallback-suppression "
        "flags — certificate with oversized SAN followed by CN allows CN-fallback hostname bypass"
    ),
    "description": (
        "During SAN iteration in hostname/email verification, when "
        "gnutls_x509_crt_get_subject_alt_name() returns GNUTLS_E_SHORT_MEMORY_BUFFER "
        "(the SAN is too large for the output buffer), the code previously returned "
        "the error without setting the flags that suppress CN fallback: "
        "  - have_other_addresses (hostname check) "
        "  - found_rfc822name (email check) "
        "\n"
        "Pre-patch behavior: "
        "  1. Cert has oversized dnsName SAN (e.g., 65535-byte hostname) "
        "  2. gnutls_x509_crt_get_subject_alt_name() → GNUTLS_E_SHORT_MEMORY_BUFFER "
        "  3. have_other_addresses NOT set "
        "  4. Loop continues or exits with have_other_addresses=0 "
        "  5. CN fallback triggers: check Common Name "
        "  6. CN=victim.com → ACCEPTED "
        "\n"
        "Fix: when GNUTLS_E_SHORT_MEMORY_BUFFER is encountered, skip the oversized "
        "SAN (continue scanning) but SET the fallback-suppression flag: "
        "  have_other_addresses = 1; (hostname) "
        "  found_rfc822name = 1; (email) "
        "\n"
        "This correctly models: 'we saw a SAN of the relevant type, even though "
        "we couldn't read its value; per RFC 6125 CN fallback is therefore suppressed.' "
        "\n"
        "Attack: "
        "  Craft cert with: oversized dnsName SAN (>GNUTLS_MAX_X509_DN_SIZE) + CN=target.com "
        "  CA may sign it for 'internal URI use' or the attacker controls a sub-CA. "
        "  Any gnutls client performing hostname verification accepts it for target.com "
        "  via CN fallback."
    ),
    "references": [
        "CVE-2026-42013",
        "GNUTLS-SA-2026-04-27-8",
        "RFC 6125 §6.4.4",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F06 — CVE-2026-42011: Name constraint intersection skips empty permitted sets
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2026_42011 = {
    "finding_id": "TOS46-TLS-F06",
    "cve": "CVE-2026-42011",
    "severity": "MEDIUM",
    "cvss_v3": 4.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "component": "lib/x509/name_constraints.c name_constraints_node_list_intersect()",
    "patch_file": "gnutls-3.8.2-CVE-2026-42011.patch",
    "reporter": "Haruto Kimura (Stella)",
    "title": (
        "name_constraints_node_list_intersect(): 3-line guard returns early when "
        "either permitted set is empty — permitted constraints from downstream CAs "
        "ignored when prior CA chain only had excluded constraints"
    ),
    "description": (
        "When building the effective name constraint set across a certificate chain, "
        "permitted constraints are intersected at each level. The intersection function "
        "had: "
        "  if (permitted->size == 0 || permitted2->size == 0) return 0; "
        "\n"
        "This early return causes the function to skip intersection when the "
        "accumulated set is empty (no permitted constraints from prior CAs). "
        "\n"
        "Scenario: "
        "  - Root CA: only excluded name constraints (no permitted list) "
        "  - Sub-CA: permitted name constraints: { example.com } "
        "  - Pre-patch: permitted->size == 0 (from root CA) → return early "
        "    Sub-CA's permitted constraints never propagate "
        "    → effective permitted set remains empty "
        "    → name constraints check may allow any name "
        "\n"
        "Fix: remove the 3-line guard. Correct intersection semantics: "
        "  - empty ∩ non-empty2 → non-empty2 propagates "
        "  - non-empty ∩ empty2 → non-empty unchanged "
        "  - empty ∩ empty → remains empty "
        "\n"
        "This is a compound finding with CVE-2026-3833 — both are in the "
        "post-CVE-2024-12243 rewrite of name_constraints.c. Tencent backported "
        "all the name constraint fixes to gnutls-3.8.2."
    ),
    "references": [
        "CVE-2026-42011",
        "GNUTLS-SA-2026-04-29-6",
        "https://gitlab.com/gnutls/gnutls/-/issues/1824",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F07 — CVE-2025-32988: SAN othername double-free on ASN.1 error
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2025_32988 = {
    "finding_id": "TOS46-TLS-F07",
    "cve": "CVE-2025-32988",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H",
    "component": "lib/x509/extensions.c _gnutls_write_new_othername()",
    "patch_file": "gnutls-3.8.2-CVE-2025-32988.patch",
    "reporter": "OpenAI Security Research Team",
    "title": (
        "_gnutls_write_new_othername(): asn1_delete_structure(&ext) called on error "
        "but ext is caller-owned — double-free when caller also frees ext on the "
        "gnutls_x509_ext_export_subject_alt_names() error path"
    ),
    "description": (
        "_gnutls_write_new_othername() is called by "
        "gnutls_x509_ext_export_subject_alt_names() to serialize 'otherName' "
        "SAN extensions into an ASN.1 structure. "
        "\n"
        "The function received the ext ASN.1 node as a parameter (caller-allocated). "
        "On asn1_write_value() failures (two error paths), it called: "
        "  asn1_delete_structure(&ext); "
        "  return _gnutls_asn2err(result); "
        "\n"
        "But ext is owned by the CALLER. When _gnutls_write_new_othername() returns "
        "an error, the caller's gnutls_x509_ext_export_subject_alt_names() also "
        "frees ext in its cleanup path → double-free. "
        "\n"
        "Trigger: application builds a certificate with an otherName SAN that hits "
        "the asn1_write_value failure (invalid OID, malformed data, or ASN.1 structure "
        "pre-populated in incompatible state). "
        "\n"
        "Fix: remove the two asn1_delete_structure(&ext) calls from error paths in "
        "_gnutls_write_new_othername(). The caller is responsible for cleanup. "
        "\n"
        "Reporter: OpenAI Security Research Team — notable that OpenAI is actively "
        "auditing TLS library code."
    ),
    "trigger": "Certificate generation with otherName SAN + ASN.1 write failure",
    "references": [
        "CVE-2025-32988",
        "reporter: OpenAI Security Research Team",
        "gnutls commit 608829769cbc",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F08 — CVE-2025-32989: SCT timestamp heap buffer overread
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2025_32989 = {
    "finding_id": "TOS46-TLS-F08",
    "cve": "CVE-2025-32989",
    "severity": "LOW",
    "cvss_v3": 3.7,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "component": "lib/x509/x509_ext.c gnutls_x509_ext_ct_import_scts()",
    "patch_file": "gnutls-3.8.2-CVE-2025-32989.patch",
    "reporter": "Andrew Hamilton (oss-fuzz #42530513)",
    "title": (
        "gnutls_x509_ext_ct_import_scts(): missing upper-bound check on length field "
        "allows heap buffer overread when processing a malformed CT SCT extension"
    ),
    "description": (
        "In gnutls_x509_ext_ct_import_scts(), after parsing the SCT list: "
        "  length = _gnutls_read_uint16(scts_content.data); "
        "  if (length < 4) → reject "
        "\n"
        "The check validates that length is at least 4 (minimum valid SCT) "
        "but does NOT validate that length <= scts_content.size. "
        "\n"
        "With a crafted extension where the uint16 length field claims a value "
        "larger than the available data, subsequent reads access memory past the "
        "end of scts_content.data (heap buffer overread). "
        "\n"
        "Fix: add 'length > scts_content.size' to the rejection check: "
        "  if (length < 4 || length > scts_content.size) → reject "
        "\n"
        "Impact: CT (Certificate Transparency) SCT processing is triggered when "
        "parsing certificates with the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2). "
        "Any gnutls client that verifies CT-enabled certificates is at risk. "
        "Overread contents could leak heap data (ASLR bypass) if combined with a "
        "side-channel to observe the server's response."
    ),
    "references": [
        "CVE-2025-32989",
        "oss-fuzz issue: https://issues.oss-fuzz.com/issues/42530513",
        "gnutls commit 8e5ca951",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F09 — CVE-2025-32990: certtool 1-byte heap write overrun
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2025_32990 = {
    "finding_id": "TOS46-TLS-F09",
    "cve": "CVE-2025-32990",
    "severity": "LOW",
    "cvss_v3": 2.3,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L",
    "component": "src/certtool-cfg.c cfg_init() template parser",
    "patch_file": "gnutls-3.8.2-CVE-2025-32990.patch",
    "reporter": "David Aitel",
    "title": (
        "certtool template parser: malloc(MAX_ENTRIES * sizeof(char*)) without +1 "
        "for NUL terminator — writing exactly MAX_ENTRIES entries writes a NUL byte "
        "one byte past the allocation"
    ),
    "description": (
        "certtool-cfg.c template parser macro: "
        "  s_name = malloc(sizeof(char *) * MAX_ENTRIES); "
        "\n"
        "When parsing a template file with exactly MAX_ENTRIES occurrences of a "
        "key (e.g., MAX_ENTRIES other_name_utf8 lines), the code writes a NUL "
        "byte at index MAX_ENTRIES, one past the last valid slot. "
        "\n"
        "Fix: calloc(MAX_ENTRIES + 1, sizeof(char *)) "
        "\n"
        "Exploitability: certtool is an admin utility (not a network daemon). "
        "Requires crafted template file with exactly MAX_ENTRIES same-key entries. "
        "CVSS:LOW. Primary risk: crash or silent memory corruption when generating "
        "certificates from attacker-controlled template files. "
        "\n"
        "Reporter David Aitel is known for Immunity/NSO-adjacent research. "
        "The test template at tests/cert-tests/templates/template-too-many-othernames.tmpl "
        "uses organization='OpenAI' — an artifact of the cross-team fuzzing effort."
    ),
    "affected_surface": "certtool command-line utility (not libgnutls)",
    "references": [
        "CVE-2025-32990",
        "GNUTLS-SA-2025-07-07-3",
        "reporter: David Aitel",
        "gnutls commit 408bed40",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F10 — CVE-2024-0553: RSA-PSK timing side-channel (known)
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2024_0553 = {
    "finding_id": "TOS46-TLS-F10",
    "cve": "CVE-2024-0553",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "component": "lib/auth/rsa_psk.c RSA-PSK key exchange",
    "patch_file": "gnutls-3.8.2-CVE-2024-0553.patch",
    "title": (
        "RSA-PSK key exchange: timing side-channel in decryption error handling "
        "allows PKCS#1 v1.5 oracle via Bleichenbacher-style timing attack"
    ),
    "description": (
        "The RSA-PSK key exchange uses RSA PKCS#1 v1.5 for premaster secret "
        "decryption. The error handling on decryption failure returned different "
        "timing behavior depending on whether decryption succeeded or failed, "
        "enabling a Bleichenbacher oracle. "
        "\n"
        "Same class as CVE-2023-5981 (RSA-PSK timing). This is a follow-on backport. "
        "Impact: timing oracle against RSA-PSK mode allows decryption of captured "
        "pre-master secrets with ~millions of oracle queries."
    ),
    "references": ["CVE-2024-0553", "GNUTLS-SA-2024-01-09"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F11 — CVE-2024-28834: Minerva ECDSA nonce timing attack (known)
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2024_28834 = {
    "finding_id": "TOS46-TLS-F11",
    "cve": "CVE-2024-28834",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "component": "lib (libgcrypt ECDSA nonce generation)",
    "patch_file": "gnutls-3.8.2-CVE-2024-28834.patch",
    "title": (
        "Minerva timing attack: ECDSA nonce generation via libgcrypt vulnerable to "
        "cache-timing side-channel — partial nonce recovery leads to private key recovery"
    ),
    "description": (
        "Minerva is a class of timing attacks against ECDSA nonce generation that "
        "exploit bias in the scalar multiplication (dependent on nonce bit length). "
        "CVE-2024-28834 is the gnutls-specific Minerva variant, affecting ECDSA "
        "signatures through libgcrypt's nonce generation path. "
        "See also libgcrypt's CVE-2024-2236."
    ),
    "references": ["CVE-2024-28834", "Minerva attack paper (2019)", "libgcrypt CVE-2024-2236"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F12 — CVE-2024-12243: Name constraints base rewrite
# ──────────────────────────────────────────────────────────────────────────────

GNUTLS_CVE_2024_12243 = {
    "finding_id": "TOS46-TLS-F12",
    "cve": "CVE-2024-12243",
    "severity": "INFO",
    "component": "lib/x509/name_constraints.c",
    "patch_file": "gnutls-3.8.2-CVE-2024-12243.patch",
    "title": (
        "CVE-2024-12243: name constraints rewrite (base refactor for 2026 backports) — "
        "multiple name constraints processing correctness fixes; prerequisite for "
        "CVE-2026-3833/42011/42012/42013 backports to gnutls-3.8.2"
    ),
    "description": (
        "CVE-2024-12243 introduced a major rewrite of name_constraints.c in "
        "upstream GnuTLS 3.8.x. The 2026 CVE patches (3833, 42011, 42012, 42013) "
        "are backported ON TOP of this rewrite. Tencent's -14 release integrates "
        "all of them in sequence, creating a 5-layer patch stack on name_constraints.c. "
        "\n"
        "The rewrite itself fixes multiple RFC 5280 name constraints compliance bugs "
        "that allowed circumventing name-constrained sub-CA hierarchies."
    ),
    "references": ["CVE-2024-12243", "gnutls 3.8.x changelog"],
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = {
    "CHAIN-1": {
        "title": "Pre-auth DTLS → fragment heap overwrite → server memory corruption",
        "severity": "CRITICAL",
        "steps": [
            "1. Identify DTLS server using gnutls (openconnect daemon, DTLS-over-UDP services)",
            "2. Open DTLS connection (client role; no authentication needed yet)",
            "3. Send fragment A: htype=CH, sequence=0, length=512, start_offset=0, data=small",
            "4. Reassembly slot allocated with data.max_length=512",
            "5. Send fragment B: htype=CH, sequence=1 (SAME htype, different sequence!)",
            "   message_length=512+N, start_offset=512-delta (past buffer end)",
            "6. Pre-patch: sequence NOT checked → B merges into slot for A",
            "7. No max_length check → memcpy writes N controlled bytes past buffer end",
            "8. Adjacent heap metadata or TLS session state overwritten",
            "9. Subsequent DTLS record processing triggers controlled behavior",
            "10. Crash or RCE depending on what was overwritten",
        ],
        "chain_links": ["F01"],
        "prerequisites": "DTLS server with gnutls; pre-patch TOS 4.6; UDP access to server",
    },
    "CHAIN-2": {
        "title": "TLS 1.3 HRR+PSK NULL deref → pre-auth server crash",
        "severity": "MEDIUM",
        "steps": [
            "1. Target: TLS 1.3 server with session tickets or PSK (gnutls HTTPS/LDAPS)",
            "2. Send ClientHello1 with PSK extension (propose session resumption)",
            "3. Receive HelloRetryRequest (server requests key share change)",
            "4. Send ClientHello2 WITHOUT PSK extension",
            "5. Server: HSK_PSK_SELECTED still set, binder info cleared",
            "6. set_auth_types() dereferences PSK credential pointer → NULL deref → SIGABRT",
            "7. Server crashes; repeat to maintain DoS",
        ],
        "chain_links": ["F02"],
        "prerequisites": "TLS 1.3 server; session tickets or PSK mode enabled",
    },
    "CHAIN-3": {
        "title": "Name constraint bypass via case variation → domain impersonation",
        "severity": "HIGH",
        "steps": [
            "1. Target environment: PKI with name-constrained sub-CA or cross-certification",
            "2. Obtain cert from name-constrained CA with excluded domains",
            "3. Craft cert SAN with uppercase variant of excluded domain",
            "   e.g., nameConstraint excludes 'target.com', cert SAN = 'TARGET.COM'",
            "4. Pre-patch: memcmp('TARGET.COM', 'target.com') != 0 → NOT excluded",
            "5. Certificate passes name constraint validation",
            "6. TLS MITM presenting this cert to gnutls clients",
            "7. gnutls_x509_crt_check_hostname2() does case-insensitive dnsname check → PASSES",
            "8. Connection accepted to impersonated domain",
        ],
        "chain_links": ["F03"],
        "chain_with": ["F04", "F05"],
        "prerequisites": "Access to CA signing cert; MITM position or CA with lax issuance",
    },
    "CHAIN-4": {
        "title": "URI SAN + matching CN → CN-fallback TLS impersonation",
        "severity": "MEDIUM",
        "steps": [
            "1. Obtain cert from CA with: URI SAN only (no dnsName), CN=victim.com",
            "   (CA may issue URI SANs for non-web purposes without strict CN review)",
            "2. Client using gnutls verifies cert for victim.com",
            "3. gnutls_x509_crt_check_hostname2() scans SANs: URI type → IS_SAN_SUPPORTED() false",
            "4. have_other_addresses never set → CN fallback triggers",
            "5. CN=victim.com matches → certificate accepted",
            "6. MITM attack against gnutls-based clients",
        ],
        "chain_links": ["F04"],
        "prerequisites": "CA that issues URI SAN certs without restricting CN; MITM position",
    },
    "CHAIN-5": {
        "title": "RSA-PSK timing oracle → premaster secret recovery",
        "severity": "HIGH",
        "steps": [
            "1. Identify TLS server using RSA-PSK ciphersuite with gnutls",
            "2. Intercept or replay RSA-PSK ClientKeyExchange messages",
            "3. Submit ~1M modified ciphertexts observing server response timing",
            "4. Build Bleichenbacher oracle from timing differentials",
            "5. Recover RSA premaster secret → session key material",
            "6. Decrypt captured TLS sessions retroactively",
        ],
        "chain_links": ["F10"],
        "prerequisites": "Network visibility to TLS server + timing measurement capability",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# CVE INVENTORY BY YEAR
# ──────────────────────────────────────────────────────────────────────────────

CVE_INVENTORY = {
    "2024": {
        "CVE-2024-0553": {"finding": "TOS46-TLS-F10", "class": "timing-side-channel"},
        "CVE-2024-0567": {"finding": None, "class": "heap-double-free PKCS#12"},
        "CVE-2024-12243": {"finding": "TOS46-TLS-F12", "class": "name-constraints-rewrite"},
        "CVE-2024-28834": {"finding": "TOS46-TLS-F11", "class": "Minerva-ECDSA-timing"},
        "CVE-2024-28835": {"finding": None, "class": "PKCS#12-chain-verify-crash"},
    },
    "2025": {
        "CVE-2025-32988": {"finding": "TOS46-TLS-F07", "class": "double-free SAN othername"},
        "CVE-2025-32989": {"finding": "TOS46-TLS-F08", "class": "heap-overread SCT"},
        "CVE-2025-32990": {"finding": "TOS46-TLS-F09", "class": "1-byte heap overwrite certtool"},
        "CVE-2025-6395": {"finding": "TOS46-TLS-F02", "class": "NULL-deref TLS1.3 HRR+PSK"},
    },
    "2026": {
        "CVE-2026-33846": {"finding": "TOS46-TLS-F01", "class": "DTLS-heap-overwrite"},
        "CVE-2026-3833": {"finding": "TOS46-TLS-F03", "class": "name-constraint-case-bypass"},
        "CVE-2026-42011": {"finding": "TOS46-TLS-F06", "class": "name-constraint-intersection"},
        "CVE-2026-42012": {"finding": "TOS46-TLS-F04", "class": "URI-SAN-CN-fallback"},
        "CVE-2026-42013": {"finding": "TOS46-TLS-F05", "class": "oversized-SAN-CN-fallback"},
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-TLS-F01": GNUTLS_CVE_2026_33846,
    "TOS46-TLS-F02": GNUTLS_CVE_2025_6395,
    "TOS46-TLS-F03": GNUTLS_CVE_2026_3833,
    "TOS46-TLS-F04": GNUTLS_CVE_2026_42012,
    "TOS46-TLS-F05": GNUTLS_CVE_2026_42013,
    "TOS46-TLS-F06": GNUTLS_CVE_2026_42011,
    "TOS46-TLS-F07": GNUTLS_CVE_2025_32988,
    "TOS46-TLS-F08": GNUTLS_CVE_2025_32989,
    "TOS46-TLS-F09": GNUTLS_CVE_2025_32990,
    "TOS46-TLS-F10": GNUTLS_CVE_2024_0553,
    "TOS46-TLS-F11": GNUTLS_CVE_2024_28834,
    "TOS46-TLS-F12": GNUTLS_CVE_2024_12243,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "package": "gnutls-3.8.2-14.tl4",
        "tencent_releases": [11, 12, 14],
        "cve_count": 14,
        "cve_by_year": {"2024": 5, "2025": 4, "2026": 5},
        "attack_chains": list(ATTACK_CHAINS.keys()),
        "findings": [
            {
                "id": k,
                "severity": v.get("severity", "?"),
                "cvss": v.get("cvss_v3"),
                "cve": v.get("cve"),
                "component": v.get("component", "?"),
            }
            for k, v in FINDINGS.items()
        ],
    }, indent=2))
