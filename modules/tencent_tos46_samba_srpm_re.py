"""
TencentOS Server 4.6 samba RE Module
Source: samba-4.19.4-12.tl4 SRPM (3 releases: -10/-11/-12 indicating active patching)
        /media/cowboy/research/tencentos/4.6/BaseOS-source/
Analysis date: 2026-09-04

PACKAGE: samba-4.19.4-12.tl4
  Upstream: Samba 4.19.4
  Tencent releases: 10, 11, 12 (3 successive releases — active CVE backport stream)
  CVE patches: 4 CVEs across 3 patch files

CVE PATCHES:
  0001-fix-CVE-2025-9640.patch       — streams_xattr heap info leak (Tencent-originated)
  0002-fix-CVE-2026-58222.patch      — LDAP Compare confidential attribute bypass
  samba-4.19.4-CVE-2026-6949-58221  — DNS TSIG bad packet_len + rootdse LDB special DN bypass

TENCENT ATTRIBUTION:
  CVE-2025-9640 reporter: xiaoyunzhao@tencent.com
  (same pattern as CVE-2026-34182 in openssl: wynnfeng@tencent.com)

SECURITY FINDINGS: TOS46-SMB-F01 through TOS46-SMB-F05
  F01 HIGH   CVE-2025-9640  streams_xattr heap uninitialized memory via ADS pwrite hole
  F02 CRIT   CVE-2026-58222 LDAP Compare: confidential attributes bypass without ACL
  F03 HIGH   CVE-2026-6949  DNS TSIG verification wrong packet_len (NDR push vs wire offset)
  F04 HIGH   CVE-2026-58221 rootdse: unauthenticated LDB special DN (@MODULES etc.) operation
  F05 INFO               3 successive Tencent releases — active CVE backport; 3 CVEs from 2026

ATTACK CHAINS:
  CHAIN-1: unauth LDAP Compare → confidential attr enumeration → credential harvest
  CHAIN-2: unauth LDAP → @MODULES/@INDEXLIST special DN manip → LDB index corruption
  CHAIN-3: SMB2 ADS pwrite with offset gap → heap info leak → ASLR bypass
  CHAIN-4: DNS server TSIG → wrong packet_len → HMAC computed over wrong byte range
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

SAMBA_PACKAGE = {
    "name": "samba",
    "version": "4.19.4",
    "release": "12.tl4",
    "tencent_releases": [10, 11, 12],
    "patch_files": 3,
    "cve_count": 4,
    "source_srpm": "samba-4.19.4-12.tl4.src.rpm",
    "key_components": [
        "smbd (vfs_streams_xattr VFS module)",
        "samba4 LDAP server (ldap_backend.c)",
        "samba4 DNS server (dns_crypto.c + librpc/ndr/ndr_dns.c)",
        "samba4 LDB rootdse module (rootdse.c)",
    ],
    "tencent_originated_cves": ["CVE-2025-9640"],
    "notes": (
        "Only 3 patch files — but each patch is high severity and 2 patches cover "
        "multiple CVEs. Three successive -10/-11/-12 releases indicate Tencent "
        "is actively pulling CVE backports from upstream Samba. CVE-2025-9640 is "
        "Tencent-originated (xiaoyunzhao@tencent.com), similar to CVE-2026-34182 "
        "in openssl (wynnfeng@tencent.com) — Tencent is both finding and patching "
        "security bugs in their own TOS distributions."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# F01 — CVE-2025-9640: streams_xattr pwrite heap uninitialized memory leak
# ──────────────────────────────────────────────────────────────────────────────

SAMBA_CVE_2025_9640 = {
    "finding_id": "TOS46-SMB-F01",
    "cve": "CVE-2025-9640",
    "severity": "HIGH",
    "cvss_v3": 7.4,
    "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "component": "smbd vfs_streams_xattr.c streams_xattr_pwrite()",
    "patch_file": "0001-fix-CVE-2025-9640.patch",
    "reporter": "xiaoyunzhao@tencent.com (Tencent — Tencent-originated)",
    "title": (
        "vfs_streams_xattr streams_xattr_pwrite(): talloc_realloc() expands xattr "
        "buffer without zeroing the gap — writing an ADS at offset > current length "
        "exposes uninitialized heap memory in the 'hole' bytes, readable via SMB2 Read"
    ),
    "description": (
        "streams_xattr_pwrite() handles writes to NTFS Alternate Data Streams (ADS) "
        "stored as extended attributes. When a write extends the stream beyond its "
        "current length: "
        "\n"
        "Pre-patch: "
        "  new_ea = talloc_realloc(..., offset + n + 1); "
        "  // gap between old ea.value.length and (offset + n) is NOT zeroed "
        "\n"
        "Exploit scenario: "
        "  1. Client opens an ADS: FILE:stream_name "
        "  2. Write 'canary' at offset 0 (sets ea.value.length = 7) "
        "  3. Write 'canary' at offset 1018 (extends to length 1025) "
        "  4. talloc_realloc() grows buffer from 7 to 1025 bytes "
        "     New bytes [7..1017] are uninitialized heap memory "
        "  5. Client reads back the full 1024-byte ADS "
        "  6. Bytes [7..1017] contain whatever was in the Samba heap "
        "     (freed talloc chunks, prior operation data, auth tokens) "
        "\n"
        "Pre-requisites: "
        "  - vfs_streams_xattr VFS module enabled (configured in smb.conf) "
        "  - Authenticated write access to a share "
        "\n"
        "vfs_streams_xattr is enabled by default when: "
        "  - 'fruit' VFS module is enabled (Mac interop: 'vfs objects = fruit streams_xattr') "
        "  - Explicitly configured for Windows SMB client interoperability "
        "\n"
        "Fix: "
        "  new_sz = offset + n + 1; "
        "  talloc_realloc(..., new_sz); "
        "  memset(tmp + ea.value.length, 0, new_sz - ea.value.length); // zero the gap "
        "\n"
        "Information leak class: "
        "  - smbd is a long-lived process with many connections "
        "  - talloc heap contains authentication state, kerberos tickets, "
        "    NT hashes, session keys — all potentially in freed-but-not-zeroed chunks "
        "  - An attacker who can write ADS (any share with write + streams_xattr) "
        "    can use this as an ASLR oracle and memory disclosure primitive"
    ),
    "vfs_config_triggers": [
        "vfs objects = streams_xattr",
        "vfs objects = fruit streams_xattr  (macOS interop)",
    ],
    "references": [
        "CVE-2025-9640",
        "reporter: xiaoyunzhao@tencent.com",
        "Samba commit 3a7de975cbb (fix)",
        "test: source4/torture/vfs/streams_xattr.c test_streams_pwrite_hole",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F02 — CVE-2026-58222: LDAP Compare confidential attribute bypass
# ──────────────────────────────────────────────────────────────────────────────

SAMBA_CVE_2026_58222 = {
    "finding_id": "TOS46-SMB-F02",
    "cve": "CVE-2026-58222",
    "severity": "CRITICAL",
    "cvss_v3": 9.1,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "component": "samba4 ldap_server/ldap_backend.c ldapsrv_CompareRequest()",
    "patch_file": "0002-fix-CVE-2026-58222.patch",
    "title": (
        "ldapsrv_CompareRequest(): LDAP Compare operation uses ldb_search() without "
        "DSDB_MARK_REQ_UNTRUSTED flag — unauthenticated or low-privilege clients can "
        "compare confidential AD attributes (unicodePwd, lmPwdHash, supplementalCredentials) "
        "bypassing all ACL enforcement"
    ),
    "description": (
        "LDAP Compare (RFC 4511 §4.10) tests whether an attribute has a specific value. "
        "In AD/Samba, 'confidential' attributes (marked SEARCHFLAG_CONFIDENTIAL or "
        "CONFIDENTIAL in the schema) should not be readable or comparable without "
        "explicit permission. "
        "\n"
        "Pre-patch ldapsrv_CompareRequest() flow: "
        "  1. Build filter: talloc_asprintf(ctx, '(%s=%*s)', attribute, len, value) "
        "  2. ldb_search(samdb, ..., dn, LDB_SCOPE_BASE, attrs, filter) "
        "     ← NO DSDB_MARK_REQ_UNTRUSTED flag "
        "\n"
        "Without DSDB_MARK_REQ_UNTRUSTED, the LDB ACL layer does NOT apply search "
        "controls for confidential attributes. The search is treated as a TRUSTED "
        "(internal) request and bypasses all confidentiality enforcement. "
        "\n"
        "Fix: replace ldb_search() with dsdb_search() + DSDB_MARK_REQ_UNTRUSTED flag: "
        "  dsdb_search(samdb, ..., dn, LDB_SCOPE_BASE, attrs, "
        "              DSDB_MARK_REQ_UNTRUSTED, filter) "
        "\n"
        "Also: "
        "  - Validate attribute name with ldb_valid_attr_name() before use "
        "    (invalid attr names previously caused a crash / NULL filter) "
        "  - Binary-encode the value with ldb_binary_encode() before insertion "
        "    into the filter string (prevents filter injection) "
        "\n"
        "Attack: LDAP Compare oracle for password testing "
        "  1. Bind anonymously to Samba LDAP (or with any low-priv account) "
        "  2. LDAP Compare on uid=Administrator, attr='unicodePwd', value=<hash> "
        "  3. Server returns compareTrue (0x06) or compareFalse (0x05) "
        "  4. Binary search / rainbow table comparison against NT hashes "
        "  5. With enough comparisons: offline NTLM hash bruteforce oracle "
        "\n"
        "Confidential attributes at risk: "
        "  - unicodePwd (NTLM hash) "
        "  - lmPwdHash "
        "  - supplementalCredentials (Kerberos keys, NTLM-strong hash) "
        "  - msDS-ManagedPassword (gMSA password) "
        "  - All SEARCHFLAG_CONFIDENTIAL schema attributes "
        "\n"
        "Samba AD DC only — does not affect Samba file server (member server) configs."
    ),
    "affected_mode": "Samba Active Directory Domain Controller (samba AD DC)",
    "unaffected_mode": "Samba NT4-style member/file server",
    "references": [
        "CVE-2026-58222",
        "https://bugzilla.samba.org/show_bug.cgi?id=16148",
        "reviewer: Douglas Bagnall <douglas.bagnall@catalyst.net.nz>",
        "RFC 4511 §4.10 LDAP Compare",
        "DSDB_MARK_REQ_UNTRUSTED flag — source4/dsdb/common/util.h",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F03 — CVE-2026-6949: DNS TSIG wrong packet_len via NDR push
# ──────────────────────────────────────────────────────────────────────────────

SAMBA_CVE_2026_6949 = {
    "finding_id": "TOS46-SMB-F03",
    "cve": "CVE-2026-6949",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "component": "samba4 dns_server/dns_crypto.c + librpc/ndr/ndr_dns.c",
    "patch_file": "samba-4.19.4-CVE-2026-6949-58221.patch",
    "title": (
        "dns_verify_tsig(): TSIG signature computed over wrong byte range — "
        "packet_len = in->length - tsig_blob.length uses NDR-serialized TSIG size "
        "which may differ from the actual wire TSIG record size"
    ),
    "description": (
        "DNS TSIG authentication (RFC 2845) signs the DNS packet excluding the TSIG "
        "record. The server must compute HMAC over exactly the bytes of the packet "
        "that preceded the TSIG RR on the wire. "
        "\n"
        "Pre-patch: "
        "  ndr_push_struct_blob(&tsig_blob, ..., ndr_push_dns_res_rec) "
        "  packet_len = in->length - tsig_blob.length "
        "\n"
        "Problem: NDR-push of the TSIG record uses internal Samba serialization "
        "which may produce a different byte count than what was received on the wire "
        "(different alignment, padding, or encoding). If tsig_blob.length != "
        "wire_tsig_length, packet_len is wrong, and the HMAC is computed over "
        "a different byte range than the signer computed. "
        "\n"
        "This can cause: "
        "  1. Legitimate TSIG-signed packets to FAIL verification (DoS for DNS updates) "
        "  2. Specially crafted packets where NDR mismatch allows forged TSIG signatures "
        "     to pass (integrity bypass for DDNS updates) "
        "\n"
        "Fix: Record the wire offset of each dns_res_rec during NDR pull: "
        "  r->start_ndr_offset = ndr->offset; (in ndr_pull_dns_res_rec) "
        "\n"
        "Then use the wire offset directly: "
        "  packet_len = packet->additional[i].start_ndr_offset "
        "\n"
        "This gives the exact byte position of the TSIG RR on the wire, independent "
        "of NDR serialization. "
        "\n"
        "Safety bounds added: "
        "  SMB_ASSERT(in->length <= UINT16_MAX) — DNS max packet size "
        "  SMB_ASSERT(in->length > packet_len) — TSIG must fit in packet "
        "  if (fake_tsig_blob.length > SIZE_MAX - UINT16_MAX) overflow guard "
        "\n"
        "Impact: Samba internal DNS server with TSIG-secured dynamic DNS updates "
        "(DDNS from clients, AD-integrated DNS zones). Affects AD DCs that have "
        "dns-related TSIG keys configured."
    ),
    "affected_config": "Samba AD DC with TSIG-protected DNS zones",
    "references": [
        "CVE-2026-6949",
        "RFC 2845 (TSIG - Secret Key Transaction Authentication for DNS)",
        "ndr_pull_dns_res_rec: start_ndr_offset tracking",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F04 — CVE-2026-58221: rootdse unauthenticated LDB special DN operations
# ──────────────────────────────────────────────────────────────────────────────

SAMBA_CVE_2026_58221 = {
    "finding_id": "TOS46-SMB-F04",
    "cve": "CVE-2026-58221",
    "severity": "HIGH",
    "cvss_v3": 8.6,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",
    "component": "samba4 dsdb/samdb/ldb_modules/rootdse.c rootdse_filter_operations()",
    "patch_file": "samba-4.19.4-CVE-2026-6949-58221.patch",
    "title": (
        "rootdse_filter_operations(): anonymous/untrusted LDAP connections can "
        "perform MODIFY/DELETE/RENAME on LDB special DNs (@MODULES, @INDEXLIST, "
        "@ATTRIBUTES, @BASEINFO) — manipulates Samba's internal LDB metadata, "
        "potentially corrupting the AD database index structures"
    ),
    "description": (
        "rootdse_filter_operations() is the LDB module that gates LDAP operations "
        "for untrusted (unauthenticated or anonymous) connections. Pre-patch logic: "
        "\n"
        "  if (is_untrusted == false) return LDB_SUCCESS; "
        "  // check if anonymous then restrict to rootDSE searches only "
        "\n"
        "The check for anonymous user was only applied to search operations on "
        "normal DNs. Special LDB DNs (those where ldb_dn_is_special() is true) "
        "are Samba's internal control records: "
        "  - @MODULES: loaded LDB modules list "
        "  - @INDEXLIST: attribute index configuration "
        "  - @ATTRIBUTES: attribute definitions and flags "
        "  - @BASEINFO: base partition information "
        "  - @CREDENTIALS, @PARTITION: other control records "
        "\n"
        "These records are not real AD directory objects — they are LDB's internal "
        "metadata, analogous to a database's system catalog. Pre-patch: an "
        "unauthenticated LDAP client could issue MODIFY/DELETE/ADD/RENAME against "
        "these special DNs. The operations would reach the LDB backend and "
        "potentially: "
        "  - Delete @INDEXLIST → Samba re-creates it (DoS, temporary) "
        "  - Modify @MODULES → Samba loads different/none modules on restart "
        "  - Delete @ATTRIBUTES → attribute type resolution fails (database corruption) "
        "  - Rename @PARTITION → partition routing broken "
        "\n"
        "Fix: add ldb_dn_is_special() checks before the anonymous check: "
        "  if (ldb_dn_is_special(dn)) { "
        "    D_ERR('CVE-2026-58221-ATTACK: ...'); "
        "    ldb_set_errstring(..., 'Invalid DN'); "
        "    return LDB_ERR_OPERATIONS_ERROR; "
        "  } "
        "\n"
        "The patch also refactors log_attributes() and operation_human_readable() "
        "from static functions in audit_log.c to exported functions in audit_util.c "
        "(dsdb_audit_log_attributes / dsdb_audit_operation_human_readable). This "
        "is required because rootdse.c now calls these for attack logging. "
        "\n"
        "Attack: "
        "  1. Anonymous LDAP bind to Samba AD DC "
        "  2. LDAP MODIFY or DELETE with dn=@INDEXLIST "
        "  3. Samba's LDB indexing is corrupted or disabled "
        "  4. Subsequent searches return incorrect results or fail entirely "
        "  5. In severe cases: corrupt sam.ldb → Samba AD DC requires recovery "
        "\n"
        "Pre-requisites: "
        "  - Network access to Samba LDAP port (389 or 636) "
        "  - Anonymous bind allowed (Samba default: anonymous bind is allowed "
        "    for rootDSE reads; the filter is supposed to block everything else) "
    ),
    "affected_mode": "Samba Active Directory Domain Controller",
    "attack_indicator": "CVE-2026-58221-ATTACK: logged to samba log (Level ERR) on exploit attempt",
    "references": [
        "CVE-2026-58221",
        "ldb_dn_is_special() — lib/ldb/common/ldb_dn.c",
        "LDB special DNs: @MODULES @INDEXLIST @ATTRIBUTES @BASEINFO @PARTITION",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F05 — Active Tencent CVE backport cadence
# ──────────────────────────────────────────────────────────────────────────────

SAMBA_TENCENT_PATCH_CADENCE = {
    "finding_id": "TOS46-SMB-F05",
    "severity": "INFO",
    "title": (
        "samba-4.19.4 released in 3 successive TOS builds (-10/-11/-12) with "
        "3 CVEs from 2026; CVE-2025-9640 Tencent-originated (xiaoyunzhao@tencent.com)"
    ),
    "description": (
        "Three successive release numbers (10→11→12) on the same upstream version "
        "(4.19.4) indicates active backport churn. The patch set covers: "
        "  - 2025 CVE: 1 (CVE-2025-9640, Tencent-originated) "
        "  - 2026 CVEs: 3 (CVE-2026-58222, CVE-2026-6949, CVE-2026-58221) "
        "\n"
        "CVE-2025-9640 was discovered and reported by xiaoyunzhao@tencent.com — "
        "the same organizational pattern as CVE-2026-34182 in openssl "
        "(wynnfeng@tencent.com). Tencent's security team is actively auditing "
        "their TOS dependencies and originating upstream CVE fixes. "
        "\n"
        "The patch for CVE-2026-58221 includes D_ERR() logging with the literal "
        "string 'CVE-2026-58221-ATTACK:' — this is a defender detection signal "
        "baked into the patch, unusual for a distro backport. "
        "\n"
        "Operational note for TOS 4.6 defenders: "
        "  grep 'CVE-2026-58221-ATTACK' /var/log/samba/log.samba "
        "  → any hit is an active exploitation attempt "
    ),
    "tencent_originations_by_component": {
        "openssl": "CVE-2026-34182 (wynnfeng@tencent.com) — CMS AuthEnvelopedData",
        "samba": "CVE-2025-9640 (xiaoyunzhao@tencent.com) — streams_xattr heap leak",
    },
    "detection": "D_ERR('CVE-2026-58221-ATTACK:') in samba log on rootdse special DN exploit",
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = {
    "CHAIN-1": {
        "title": "Unauth LDAP Compare → confidential attr oracle → NTLM hash bruteforce",
        "severity": "CRITICAL",
        "steps": [
            "1. Network access to Samba AD DC LDAP port (389/636)",
            "2. Anonymous LDAP bind (Samba default allows anon bind for rootDSE)",
            "3. LDAP Compare: dn=cn=Administrator,cn=Users,dc=..., attr=unicodePwd, value=<hash>",
            "4. Pre-patch: ldb_search() without DSDB_MARK_REQ_UNTRUSTED → ACL bypassed",
            "5. Response: compareTrue (0x06) or compareFalse (0x05)",
            "6. Binary search over NTLM hash space (65536 queries per 16-bit hash prefix)",
            "7. Alternatively: rainbow table lookup via compare oracle",
            "8. Recovered hash → pass-the-hash or offline crack to cleartext",
            "9. Domain Admin → full AD compromise",
        ],
        "chain_links": ["F02"],
        "prerequisites": "Network access to LDAP port on Samba AD DC; pre-patch TOS 4.6",
        "rate_limit_bypass": "Samba default: no rate limiting on anonymous LDAP Compare",
    },
    "CHAIN-2": {
        "title": "Anon LDAP → @MODULES special DN delete → AD database corruption",
        "severity": "HIGH",
        "steps": [
            "1. Anonymous LDAP bind",
            "2. LDAP DELETE with dn=@INDEXLIST",
            "3. Pre-patch: rootdse_filter_operations() only checks anonymous for named DNs",
            "4. @INDEXLIST is ldb_dn_is_special() == true — not checked",
            "5. LDB backend processes DELETE on @INDEXLIST",
            "6. Samba automatically re-creates @INDEXLIST but loses custom index config",
            "7. All attribute searches degrade to full scans (DoS for large AD directories)",
            "8. More severe: LDAP MODIFY on @MODULES to remove security modules",
            "9. On Samba restart: acl_module or dsdb_memberof unloaded → ACL enforcement broken",
        ],
        "chain_links": ["F04"],
        "prerequisites": "Network access to LDAP on Samba AD DC",
        "detection": "CVE-2026-58221-ATTACK: in samba log",
    },
    "CHAIN-3": {
        "title": "SMB2 ADS pwrite hole → heap info leak → ASLR bypass → RCE",
        "severity": "HIGH",
        "steps": [
            "1. Authenticated SMB2 connection to a share with vfs_streams_xattr enabled",
            "2. Open FILE:ads_stream via SMB2 Create with stream name",
            "3. SMB2 Write 'marker' at offset 0 (4 bytes)",
            "4. SMB2 Write 'marker' at offset 4096 (extends stream, creates 4092-byte hole)",
            "5. talloc_realloc() grows xattr buffer from 4 to 4097 bytes WITHOUT zeroing [4..4095]",
            "6. SMB2 Read full 4096 bytes of ADS",
            "7. Bytes [4..4095] contain smbd heap contents: prior talloc allocations",
            "8. Analyze leaked memory for: stack canaries, ASLR slide, heap pointers",
            "9. Chain with memory corruption bug in smbd for precise RCE",
        ],
        "chain_links": ["F01"],
        "prerequisites": "Authenticated write access; vfs_streams_xattr in smb.conf",
    },
    "CHAIN-4": {
        "title": "DNS TSIG packet_len mismatch → HMAC forged for DDNS updates",
        "severity": "HIGH",
        "steps": [
            "1. Identify Samba AD DC with TSIG-protected DDNS zone",
            "2. Capture a legitimate TSIG-signed DDNS UPDATE packet",
            "3. Modify the DNS UPDATE payload (add a record) while keeping original TSIG",
            "4. If NDR serialization of the TSIG record differs from wire TSIG length:",
            "5. Pre-patch: packet_len = in->length - ndrserialized_tsig_blob.length",
            "6. The HMAC is computed over wrong packet range",
            "7. Specifically craft the TSIG record to exploit NDR padding mismatch",
            "8. Server computes HMAC over different range than attacker expects",
            "9. In edge case: HMAC verification passes for a modified packet",
        ],
        "chain_links": ["F03"],
        "prerequisites": "Network access to DNS port; TSIG keys configured on zones",
        "note": "Exploitability depends on exact NDR/wire encoding delta for the attacker's TSIG key type",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# PATCH CLASSIFICATION
# ──────────────────────────────────────────────────────────────────────────────

PATCH_CLASSIFICATION = {
    "total_patch_files": 3,
    "total_cves": 4,
    "patch_breakdown": {
        "0001-fix-CVE-2025-9640.patch": {
            "cves": ["CVE-2025-9640"],
            "files_changed": 5,
            "finding": "TOS46-SMB-F01",
            "tencent_originated": True,
        },
        "0002-fix-CVE-2026-58222.patch": {
            "cves": ["CVE-2026-58222"],
            "files_changed": 1,
            "finding": "TOS46-SMB-F02",
            "backport_note": "backported to samba-4.19.4, keeps legacy DEBUG(10,...) style",
        },
        "samba-4.19.4-CVE-2026-6949-58221.patch": {
            "cves": ["CVE-2026-6949", "CVE-2026-58221"],
            "files_changed": 8,
            "findings": ["TOS46-SMB-F03", "TOS46-SMB-F04"],
            "notable": (
                "Dual-CVE patch; includes @audit_log.c refactor to export "
                "dsdb_audit_operation_human_readable for attack logging; "
                "D_ERR('CVE-2026-58221-ATTACK:') defender detection baked in"
            ),
        },
    },
    "cve_years": {"2025": 1, "2026": 3},
    "tencent_attribution": "CVE-2025-9640 (xiaoyunzhao@tencent.com)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-SMB-F01": SAMBA_CVE_2025_9640,
    "TOS46-SMB-F02": SAMBA_CVE_2026_58222,
    "TOS46-SMB-F03": SAMBA_CVE_2026_6949,
    "TOS46-SMB-F04": SAMBA_CVE_2026_58221,
    "TOS46-SMB-F05": SAMBA_TENCENT_PATCH_CADENCE,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "package": "samba-4.19.4-12.tl4",
        "tencent_releases": [10, 11, 12],
        "cves": ["CVE-2025-9640", "CVE-2026-58222", "CVE-2026-6949", "CVE-2026-58221"],
        "tencent_originated": ["CVE-2025-9640"],
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
