"""
TencentOS 4.6 AppStream — bind-9.18.21-6.tl4 SRPM RE.

Source: tencent-re/4.6/AppStream-source/bind-9.18.21-6.tl4.src.rpm
Maintainer: Xin Cheng <denisecheng@tencent.com> (versions 3-4); PkgAgent Robot (versions 5-6)
Patch adapter: PkgAgent/deepseek-v4 (adapts upstream commits to opencloudos-stream base)

Release timeline (most recent first):
  9.18.21-6 (2026-07-27): CVE-2026-12617, CVE-2026-11721
  9.18.21-5 (2026-06-04): CVE-2026-5946 (5 patches — class confusion series)
  9.18.21-4 (2025-10-27): CVE-2025-8677, CVE-2025-40778, CVE-2025-40780
  9.18.21-3 (2025-05-23): CVE-2024-11187, CVE-2024-12705
  9.18.21-2 (2024-09-26): rebuild for loongarch
  9.18.21-1 (2024-08-19): upgrade from 9.18.18; CVE-2024-0760/1737/1975/4076
  9.18.18-5 (2024-02-28): CVE-2023-4408/5517/5679/6516/50387/50868 (KeyTrap)
  9.18.18-3 (2023-11-03): CVE-2023-3341/4236
"""

PACKAGE = {
    "name": "bind",
    "version": "9.18.21",
    "release": "6.tl4",
    "upstream": "ISC BIND 9 — https://www.isc.org/bind/",
    "license": "MPLv2.0",
    "maintainers": [
        "denisecheng@tencent.com (Xin Cheng)",
        "pkgagent@opencloudos.tech (PkgAgent Robot, deepseek-v4 adapter)",
    ],
    "patch_count_total": 17,
    "cve_count": "14 distinct CVE IDs across this SRPM",
    "base": "OpenCloudOS Stream 9.18.21-1",
    "tencent_delta": (
        "TOS 4.6 bind tracks OpenCloudOS base and applies security patches. "
        "The PkgAgent/deepseek-v4 tool adapts upstream ISC cherry-picks to the "
        "opencloudos-stream branch context. No Tencent-specific protocol changes."
    ),
}

# ── 2026 CVEs ──────────────────────────────────────────────────────────────

CVE_2026_5946 = {
    "id": "CVE-2026-5946",
    "title": "DNS class confusion: non-IN class requests reach IN-class-specific code paths",
    "fixed_in": "9.18.21-5.tl4",
    "fix_date": "2026-06-04",
    "patch_count": 5,
    "upstream_authors": ["Evan Hunt <each@isc.org>", "Mark Andrews <marka@isc.org>",
                         "Ondrej Sury <ondrej@isc.org>"],
    "bug_bounty_refs": [
        "YWH-PGM40640-70", "YWH-PGM40640-72", "YWH-PGM40640-73",
        "YWH-PGM40640-74", "YWH-PGM40640-75", "YWH-PGM40640-82",
        "YWH-PGM40640-83", "YWH-PGM40640-87", "YWH-PGM40640-88",
        "YWH-PGM40640-117",
    ],
    "upstream_issues": [
        "isc-projects/bind9#5777", "isc-projects/bind9#5778", "isc-projects/bind9#5779",
        "isc-projects/bind9#5780", "isc-projects/bind9#5781", "isc-projects/bind9#5782",
        "isc-projects/bind9#5783", "isc-projects/bind9#5797", "isc-projects/bind9#5798",
        "isc-projects/bind9#5853",
    ],
    "root_cause": (
        "BIND processes DNS requests for multiple RR classes (IN, CHAOS/CH, HS). "
        "A 'class-CHAOS view' (used for server identity queries like version.bind) "
        "is a non-IN view. The bug: CHAOS views could receive UPDATE and NOTIFY "
        "requests and enter code paths in lib/ns/update.c that assume IN-class zones. "
        "Specifically, get_current_rr() accepted a zoneclass parameter and set "
        "rdata->rdclass to zoneclass — allowing CHAOS class to propagate into "
        "IN-specific rdata handling (dns_rdata_tostruct for SRV, WKS). "
        "Additionally: the resolver could attempt recursive queries for non-IN classes, "
        "sending nameserver addresses of an unexpected format to recursive code. "
        "Class ANY and NONE (DNS meta-classes) could appear in QUESTION/ZONE sections "
        "of UPDATE/NOTIFY, reaching code that did not validate them."
    ),
    "five_patch_series": {
        "patch_1 — disable_recursion_non_in": (
            "configure_view() in bin/named/server.c: "
            "  view->recursion = (view->rdclass == dns_rdataclass_in && cfg_obj_asboolean(obj))\n"
            "Forces recursion=false for non-IN views unconditionally. "
            "Also: if rdclass != IN, sets recursionacl and recursiononacl to dns_acl_none() "
            "instead of reading allow-recursion/allow-recursion-on from config. "
            "lib/bind9/check.c: check_recursion() returns false immediately for non-IN class, "
            "and logs a warning if the operator explicitly set recursion=yes for a non-IN view."
        ),
        "patch_2 — disable_update_notify_non_in": (
            "lib/ns/client.c: ns__client_request() switch statement — two new guards:\n"
            "  case dns_opcode_update:\n"
            "    if (client->view->rdclass != dns_rdataclass_in) { error(DNS_R_NOTIMP); break; }\n"
            "  case dns_opcode_notify: same guard\n"
            "lib/ns/update.c:\n"
            "  get_current_rr() — removes zoneclass parameter; hardcodes rdata->rdclass = dns_rdataclass_in\n"
            "  send_update_event() / update_action() — INSIST(dns_zone_getclass(zone) == dns_rdataclass_in)\n"
            "  ssu_checkrr(): rdata.rdclass == IN guard before dns_rdata_tostruct(SRV)\n"
            "  replaces_p(): rdata.rdclass == IN guard before WKS comparison\n"
            "  update_class comparisons: zoneclass variable replaced with dns_rdataclass_in literal\n"
            "lib/dns/adb.c: INSIST → REQUIRE for rdtype A/AAAA check (convert assertion to error)"
        ),
        "patch_3 — validate_class_early": (
            "lib/ns/client.c: ns__client_request() switch on client->message->rdclass:\n"
            "  dns_rdataclass_reserved0 (0): DNS cookie path only; else NOTIMP/FORMERR\n"
            "  dns_rdataclass_in, _chaos, _hs: pass through\n"
            "  dns_rdataclass_none: allowed only if opcode == UPDATE; else FORMERR\n"
            "  dns_rdataclass_any: allowed only if message->tkey == 1 (TKEY negotiation); else FORMERR\n"
            "  default: any other class → NOTIMP\n"
            "This is a whitelist approach — unrecognized classes are rejected before any dispatch."
        ),
        "patch_4 — reject_metaclasses_update_notify": (
            "lib/dns/message.c: getquestions() — during wire parsing of QUESTION/ZONE section:\n"
            "  if ((opcode == UPDATE || opcode == NOTIFY) && "
            "(rdclass == NONE || rdclass == ANY)) → DNS_R_FORMERR\n"
            "Closes: YWH-PGM40640-72/82/83 (NONE class) and YWH-PGM40640-87/88/117 (ANY class). "
            "This fires at wire-parse time, before any higher-level dispatch."
        ),
        "patch_5 — skip_deny_answer_non_in": (
            "lib/dns/resolver.c: is_answeraddress_allowed() — additional guard:\n"
            "  if (rdataset->rdclass != dns_rdataclass_in) return true;\n"
            "deny-answer-address ACL matching skipped for non-IN answer addresses. "
            "Defense-in-depth for YWH-PGM40640-74."
        ),
    },
    "attack_model": (
        "A remote attacker sends a crafted DNS UPDATE or NOTIFY packet to a BIND server "
        "where a non-IN class view (e.g., CHAOS) is configured. Before the fix, the packet "
        "reaches IN-class-specific rdata handling code with non-IN class values. "
        "Impact depends on specific code path — could cause assertion failure (crash/DoS) "
        "or type confusion in rdata struct parsing. "
        "Requires: server has a non-IN class view configured (common for version.bind CHAOS)."
    ),
    "severity_assessment": "HIGH — remote DoS via assertion failure; class confusion depth suggests broader impact potential",
}

CVE_2026_12617 = {
    "id": "CVE-2026-12617",
    "title": "CNAME/DNAME assertion crash via concurrent queries and delayed negative answers",
    "fixed_in": "9.18.21-6.tl4",
    "fix_date": "2026-07-27",
    "patch_count": 1,
    "upstream_author": "Colin Vidal <colin@isc.org>",
    "affected_file": "lib/dns/resolver.c",
    "two_scenarios": {
        "scenario_dname": (
            "1. Client queries foo.test./DNAME and a.foo.test./A simultaneously.\n"
            "2. Auth server delays DNAME answer but immediately returns DNAME for A query.\n"
            "3. Resolver caches DNAME (foo.test. DNAME bar.test.), resolves a.bar.test./A.\n"
            "4. Auth server eventually responds NOERROR/NODATA (negative) for foo.test./DNAME.\n"
            "5. Resolver pulls previously cached DNAME (higher trust); ncache_adderesult() "
            "   sets DNS_R_UNCHANGED and maps to DNS_R_DNAME (BUG — should be ISC_R_SUCCESS).\n"
            "6. ns/query.c interprets DNS_R_DNAME as 'non-DNAME query got DNAME, follow chain'.\n"
            "7. query_dname() asserts qname is subdomain of DNAME owner. "
            "   Fails: qname (foo.test.) == owner (foo.test.) — equals but not subdomain.\n"
            "RESULT: named crashes (assertion failure)."
        ),
        "scenario_cname": (
            "1. Client queries cname.foo.test./CNAME and /A simultaneously.\n"
            "2. Auth answers A query with self-referential CNAME: cname.foo.test. CNAME cname.foo.test.\n"
            "3. Resolver caches it; sets result DNS_R_CNAME.\n"
            "4. Auth eventually answers CNAME query negatively.\n"
            "5. Resolver pulls cached self-referential CNAME; ncache_adderesult() maps to DNS_R_CNAME (BUG).\n"
            "6. query.c follows the CNAME chain; query_cname() adds rdataset to answer, restarts query.\n"
            "7. Restart retrieves same CNAME from cache (ISC_R_SUCCESS this time), calls "
            "   query_respond() which tries to add the rdataset to the message again.\n"
            "8. Fails: rdataset already in message; qctx->rdataset is NULL (ownership transferred).\n"
            "RESULT: named crashes (assertion failure)."
        ),
    },
    "bug_in_ncache_adderesult": (
        "Old code in ncache_adderesult(): when DNS_R_UNCHANGED (negative entry discarded "
        "in favor of higher-trust positive cache), returned ISC_R_SUCCESS with comment "
        "'XXXRTH There's a CNAME/DNAME problem here' — the TODO was real.\n"
        "The code failed to check whether the surviving positive rdataset was a CNAME/DNAME "
        "that needed chaining vs. the type being directly answered."
    ),
    "fix": (
        "New function fctx_setresult(fctx, rdataset):\n"
        "  if NEGATIVE(rdataset): return NCACHENXDOMAIN or NCACHENXRRSET\n"
        "  elif rdataset->type != fctx->type:\n"
        "    if type == CNAME: return DNS_R_CNAME\n"
        "    if type == DNAME: return DNS_R_DNAME\n"
        "  else: return ISC_R_SUCCESS\n"
        "Key invariant enforced: DNS_R_CNAME/DNAME only set when query type != rdataset type. "
        "When the cached positive rdataset IS the exact query type, returns ISC_R_SUCCESS. "
        "This prevents the assertion failures in query_dname() and query_respond()."
    ),
    "severity_assessment": "HIGH — remote crash (assertion failure) triggerable by a malicious auth server controlling CNAME/DNAME responses with timing",
}

CVE_2026_11721 = {
    "id": "CVE-2026-11721",
    "title": "DNSSEC wildcard cache poisoning via invalid RRSIG Labels field",
    "fixed_in": "9.18.21-6.tl4",
    "fix_date": "2026-07-27",
    "patch_count": 2,
    "upstream_author": "Mark Andrews <marka@isc.org>",
    "affected_files": [
        "lib/dns/dnssec.c",
        "lib/dns/rdata/generic/rrsig_46.c",
        "bin/dnssec/dnssec-signzone.c",
    ],
    "root_cause": (
        "RRSIG records contain a Labels field (RFC 4034 §3.1.3) indicating the number of "
        "labels in the original owner name (excluding root, excluding wildcard '*' if present). "
        "BIND's validator accepted RRSIG records where Labels < countlabels(signer_name). "
        "This is impossible for a legitimately signed record: the signer is always within "
        "the zone, and the signed name must be at or below the signer. "
        "When such an RRSIG covers a wildcard, the validator reconstructs a wildcard owner "
        "name using sig.labels — placing it ABOVE the signer's zone apex. "
        "The validator caches this forged wildcard as secure (high-trust). "
        "RFC 8198 (synth-from-dnssec / aggressive NSEC) then synthesizes answers for "
        "unrelated names using this cached wildcard, poisoning the cache for arbitrary queries."
    ),
    "attack_vector": (
        "An attacker who controls or can inject into a DNSSEC-signed zone presents a "
        "crafted RRSIG with Labels < countlabels(signer). The victim resolver accepts it, "
        "caches a wildcard at an impossible position (above zone apex), and serves "
        "synthesized answers for unrelated names based on the forged wildcard."
    ),
    "fix_patch_1": (
        "lib/dns/rdata/generic/rrsig_46.c — fromtext_rrsig() and fromwire_rrsig():\n"
        "  Both check: if (labels + 1) < dns_name_countlabels(signer_name) → RETTOK/RETERR\n"
        "  (labels+1 normalizes Labels field to include root label for comparison)\n"
        "RRSIG is now rejected at parse time — before reaching the validator.\n"
        "\n"
        "lib/dns/dnssec.c — dns_dnssec_verify():\n"
        "  siglabels = sig.labels + 1\n"
        "  if siglabels < countlabels(sig.signer) || siglabels > countlabels(name) → DNS_R_SIGINVALID\n"
        "Rejects malformed RRSIG during cryptographic verification as an additional gate."
    ),
    "fix_patch_2": (
        "bin/dnssec/dnssec-signzone.c — assignwork():\n"
        "  Added: if (!dns_name_issubdomain(name, gorigin)) { skip; }\n"
        "Prevents dnssec-signzone from signing records outside the zone's namespace. "
        "Guards against a related out-of-zone signing scenario."
    ),
    "severity_assessment": "HIGH — DNSSEC cache poisoning; synthesizes forged secure answers for arbitrary names",
}

# ── 2025 CVEs ──────────────────────────────────────────────────────────────

CVE_2025_SERIES = {
    "fixed_in": "9.18.21-4.tl4",
    "fix_date": "2025-10-27",
    "backport_author": "denisecheng@tencent.com (Xin Cheng)",
    "cve_2025_8677": {
        "id": "CVE-2025-8677",
        "title": "DNSSEC validator: missing val->failed=true on select_signing_key failure",
        "file": "lib/dns/validator.c",
        "fix": (
            "fetch_callback_dnskey(): when select_signing_key() returns non-ISC_R_SUCCESS, "
            "now sets val->failed = true before continuing. "
            "Prevents the validator from proceeding in a partially-initialized failure state."
        ),
    },
    "cve_2025_40778": {
        "id": "CVE-2025-40778",
        "title": "Resolver TCP retry handling and DNAME detection",
        "files": ["lib/dns/include/dns/message.h", "lib/dns/message.c", "lib/dns/resolver.c"],
        "fix": (
            "Adds dns_message_hasdname() helper and TCP retry logic to resolver.c. "
            "110-line patch to lib/dns/resolver.c. "
            "Corrects TCP query retry behavior when DNAME records are present in responses."
        ),
    },
    "cve_2025_40780": {
        "id": "CVE-2025-40780",
        "title": "ISC random number generator rewrite",
        "file": "lib/isc/random.c",
        "fix": (
            "Rewrites isc/random.c (172 → 44 lines). "
            "Simplifies the non-cryptographic RNG wrapper. "
            "Removes previous implementation with its potential weaknesses. "
            "Note: this is explicitly non-cryptographic RNG (for jitter/load-balancing, not keying)."
        ),
    },
}

# ── 2024 CVEs (notable) ────────────────────────────────────────────────────

CVE_2024_NOTABLE = {
    "cve_2024_1737": {
        "id": "CVE-2024-1737",
        "title": "DNSSEC: excessive CPU / memory via many RRSIGs per RRset",
        "patch_size_kb": 48,
        "fix": "Limits the number of RRSIG records the validator processes per RRset.",
    },
    "cve_2024_12705": {
        "id": "CVE-2024-12705",
        "title": "BIND resolver vulnerability (complex, 41KB patch)",
        "patch_size_kb": 41,
        "note": "Patch analyzed via header only — full root cause requires deeper resolver.c review.",
    },
    "cve_2024_0760": {
        "id": "CVE-2024-0760",
        "title": "TCP resource exhaustion via flood of DNS messages",
        "patch_size_kb": 32,
    },
    "cve_2024_1975": {
        "id": "CVE-2024-1975",
        "title": "SIG(0) resource exhaustion — CPU exhaustion via SIG(0) signed requests",
        "patch_size_kb": 14,
    },
}

# ── 2023 CVEs ──────────────────────────────────────────────────────────────

CVE_2023_NOTABLE = {
    "cve_2023_50387_50868": {
        "ids": ["CVE-2023-50387", "CVE-2023-50868"],
        "title": "KeyTrap — extreme CPU consumption in DNSSEC validator",
        "patch_size_kb": 19,
        "description": (
            "The most impactful DNSSEC DoS class: carefully crafted DNSSEC responses "
            "force the validator into pathological CPU consumption. CVE-2023-50387 is "
            "the broad KeyTrap (validator loops on crafted DNSKEY/RRSIG combinations); "
            "CVE-2023-50868 targets NSEC3 closest-encloser proof computation. "
            "Fixed in 9.18.18-4 (Feb 2024) for TOS 4.6."
        ),
    },
    "cve_2023_4408": {
        "id": "CVE-2023-4408",
        "title": "DNS message parsing excessive CPU load",
        "patch_size_kb": 27,
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-5946",
        "title": "DNS class confusion: CHAOS view UPDATE/NOTIFY reaches IN-class rdata code paths",
        "detail": (
            "BIND accepted UPDATE and NOTIFY requests on non-IN views (e.g., CHAOS/version.bind). "
            "In update.c, get_current_rr() set rdata->rdclass to zoneclass (CHAOS), then "
            "passed rdata to IN-only functions (dns_rdata_tostruct for SRV/WKS). "
            "Additionally, non-IN views could recurse, sending non-IP nameserver addresses "
            "to resolver code expecting IN-class address records. "
            "Fix: 5-patch series adds whitelist CLASS validation, forces recursion/UPDATE/NOTIFY "
            "off for non-IN views, and hardcodes dns_rdataclass_in in update code paths. "
            "Found via YWH bug bounty (10+ ticket IDs). Fixed 2026-06-04 in 9.18.21-5.tl4. "
            "Any TOS 4.6 system running 9.18.21-4 or earlier with CHAOS view configured is affected."
        ),
        "affected": "bind < 9.18.21-5.tl4 with non-IN class view configured",
        "fixed": "bind-9.18.21-5.tl4",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2026-12617",
        "title": "CNAME/DNAME assertion crash: concurrent queries + delayed negative answer",
        "detail": (
            "Two scenarios trigger assertion failures in named: "
            "(1) DNAME query + A query to same zone; auth delays DNAME, sends negative later — "
            "resolver maps DNS_R_UNCHANGED to DNS_R_DNAME incorrectly, "
            "query_dname() asserts qname is subdomain of DNAME owner (fails: qname == owner). "
            "(2) Self-referential CNAME + A concurrent queries — "
            "resolver maps cached CNAME to DNS_R_CNAME after negative answer, "
            "query_respond() tries to add already-present rdataset, assertion on NULL rdataset fails. "
            "Root cause: ncache_adderesult() had a 'XXXRTH CNAME/DNAME problem' TODO comment "
            "that was a real unfixed bug. "
            "Fix: fctx_setresult() correctly maps cached rdataset to result code. "
            "Requires: named acts as recursive resolver; attacker controls auth server responses. "
            "Fixed 2026-07-27 in 9.18.21-6.tl4."
        ),
        "affected": "bind < 9.18.21-6.tl4 (recursive resolver configuration)",
        "fixed": "bind-9.18.21-6.tl4",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2026-11721",
        "title": "DNSSEC wildcard cache poisoning via RRSIG with invalid Labels field",
        "detail": (
            "BIND accepted RRSIG records where Labels < countlabels(signer_name). "
            "Legitimate RRSIG invariant: signer is within the zone, Labels >= signer label count. "
            "Malicious RRSIG with Labels too small: validator reconstructs wildcard owner "
            "ABOVE the zone apex, caches it as DNSSEC-secure. "
            "RFC 8198 synth-from-dnssec then serves this forged wildcard for arbitrary names. "
            "Fix: reject at parse time (rrsig_46.c fromtext/fromwire) AND at verify time (dnssec.c). "
            "Also: dnssec-signzone fixed to not sign out-of-zone records. "
            "Requires: DNSSEC validation enabled; attacker can inject crafted RRSIG into resolver's view. "
            "Fixed 2026-07-27 in 9.18.21-6.tl4."
        ),
        "affected": "bind < 9.18.21-6.tl4 with DNSSEC validation enabled",
        "fixed": "bind-9.18.21-6.tl4",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "cve": "CVE-2023-50387 / CVE-2023-50868",
        "title": "KeyTrap: DNSSEC validator CPU exhaustion via crafted DNSKEY/RRSIG/NSEC3",
        "detail": (
            "KeyTrap (CVE-2023-50387): pathological validator behavior when processing "
            "crafted combinations of DNSKEY + RRSIG records — CPU exhaustion DoS. "
            "CVE-2023-50868: NSEC3 closest-encloser proof computation exhausts CPU. "
            "Industry-wide DNSSEC vulnerability class. Fixed in 9.18.18-4 (Feb 2024). "
            "All TOS 4.6 systems running 9.18.18-3 or earlier with DNSSEC validation were affected."
        ),
        "affected": "bind < 9.18.18-4.tl4",
        "fixed": "bind-9.18.18-4.tl4 (2024-02-28)",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "cves": ["CVE-2025-8677", "CVE-2025-40778", "CVE-2025-40780"],
        "title": "2025 patch series: validator failure state, TCP retry, RNG rewrite",
        "detail": (
            "CVE-2025-8677: validator.c missing val->failed=true on DNSKEY fetch key selection failure. "
            "CVE-2025-40778: resolver TCP retry logic + dns_message_hasdname() for DNAME handling. "
            "CVE-2025-40780: lib/isc/random.c rewritten (172→44 lines) — "
            "simplification of non-cryptographic RNG. "
            "Backported 2025-10-27 by denisecheng@tencent.com."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "PkgAgent/deepseek-v4: AI-assisted patch adaptation in TOS 4.6 security workflow",
        "detail": (
            "CVE-2026-5946 commit messages show: 'Adapted-by: PkgAgent/deepseek-v4 "
            "(modified to adapt to opencloudos-stream)'. "
            "TencentOS uses an AI model (deepseek-v4) to adapt upstream ISC cherry-picks "
            "to the OpenCloudOS branch. "
            "The adaptation is mechanical (context-conflict resolution) but introduces "
            "AI-generated code into security-critical patches. "
            "The adapted patches were reviewed (commits are signed, pushed via PkgAgent Robot). "
            "This is noteworthy as an emerging pattern in downstream security maintenance."
        ),
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "bind-9.18.21-6.tl4: active security maintenance through 2026-07-27",
        "detail": (
            "14 distinct CVE IDs fixed across 17 patches spanning 2023-2026. "
            "TOS 4.6 bind tracks ISC upstream security releases with 1-8 week lag. "
            "CVE-2026-5946 upstream fix: 2026-03 to 2026-06; TOS fix: 2026-06-04 (fast). "
            "CVE-2026-11721/12617 upstream: 2026-04 to 2026-06; TOS fix: 2026-07-27 (one month). "
            "No Tencent-specific protocol modifications — this is a clean security maintenance track."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 bind-9.18.21-6.tl4 AppStream RE")
    print()
    print(f"  Base: {PACKAGE['base']}")
    print(f"  CVEs patched: {PACKAGE['cve_count']}")
    print(f"  Patch adapter: PkgAgent/deepseek-v4 (AI-assisted adaptation)")
    print()
    print("2026 CVEs (critical):")
    print(f"  CVE-2026-5946  [{CVE_2026_5946['patch_count']} patches] {CVE_2026_5946['title'][:70]}")
    print(f"  CVE-2026-12617 [{CVE_2026_12617['patch_count']} patch ] {CVE_2026_12617['title'][:70]}")
    print(f"  CVE-2026-11721 [{CVE_2026_11721['patch_count']} patches] {CVE_2026_11721['title'][:70]}")
    print()
    print("2025 CVEs:")
    for k, v in CVE_2025_SERIES.items():
        if isinstance(v, dict) and 'id' in v:
            print(f"  {v['id']}: {v['title'][:70]}")
    print()
    print("Notable older CVEs:")
    for k, v in CVE_2024_NOTABLE.items():
        print(f"  {v['id']}: {v['title'][:70]}")
    print(f"  CVE-2023-50387/50868 (KeyTrap): {CVE_2023_NOTABLE['cve_2023_50387_50868']['title'][:50]}")
    print()
    for f in FINDINGS:
        sev = f['severity']
        cve = f.get('cve', f.get('cves', [''])[0] if isinstance(f.get('cves'), list) else '')
        label = f"{cve} " if cve else ""
        print(f"  [{sev:6s}] {f['id']}: {label}{f['title'][:64]}")
