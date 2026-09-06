"""
TencentOS 2.4 (TLinux 2) — bind-9.11.4-26.P2.tl2.19 SRPM RE.

Source from Drive: tencent-re/2.4/tlinux-srpms/bind-9.11.4-26.P2.tl2.19.src.rpm
Upstream: ISC BIND 9.11.4-P2 (RHEL 7 base)
Latest security revision: .19 (Nov 2025 — CVE-2025-40778)
RHEL 7 EoL: June 2024. TOS 2.4 independently maintains BIND 9.11 post-EoL.

This package covers the full 2018-2025 RHEL 7 BIND security backport history.
"""

PACKAGE = {
    "package": "bind-9.11.4-26.P2.tl2.19",
    "upstream": "ISC BIND 9.11.4-P2",
    "base": "RHEL 7 bind-9.11.4-26.P2",
    "license": "MPLv2.0",
    "maintainers": ["Petr Menšík <pemensik@redhat.com>", "Stepan Broz <sbroz@redhat.com>"],
    "tl2_tag_significance": (
        "RHEL 7 EoL was June 2024. Tencent continues shipping BIND 9.11.4 security patches "
        "on TOS 2.4 post-EoL, tracking ISC advisories independently. "
        ".19 revision released Nov 2025 — 17+ months past RHEL 7 EoL. "
        "Each .tl2.N revision is a Red Hat security errata backport, not a Tencent-authored fix."
    ),
}

# ── Recent CVEs (2024-2025) ──────────────────────────────────────────────────

CVE_2025_40778 = {
    "id": "CVE-2025-40778",
    "revision": ".19 (Nov 19 2025)",
    "author": "Diego Fronza <diego@isc.org>, Ondřej Surý <ondrej@isc.org> (ISC)",
    "title": "DNS COOKIE spoofing — dns_message_t lifetime and NS/address caching restrictions",
    "patch_series": "8 patches (140KB total)",
    "patches": {
        "1/8 Refactored dns_message_t for attach/detach semantics": (
            "dns_message_destroy() → dns_message_detach() throughout codebase. "
            "Attach/detach semantics allow shared references with proper refcount, "
            "preventing use-after-free when a message object has multiple owners."
        ),
        "2/8 Fix invalid dns_message state in resolver logic": (
            "Resolver held dns_message_t references incorrectly in error paths; "
            "message could be destroyed while resolver still used it."
        ),
        "3/8 Properly handling shared dns_message_t references": (
            "Ensures message state consistency across concurrent DNS query processing."
        ),
        "4/8 Tighten restrictions on caching NS RRsets in authority section": (
            "Restricts which NS RRsets can be cached from the authority section of responses. "
            "Prevents cache poisoning via spoofed authority section data."
        ),
        "5/8 Further restrict addresses cached via ADDITIONAL section": (
            "Tightens validation on addresses from the additional section of DNS responses. "
            "An attacker sending spoofed DNS responses could inject false A/AAAA records "
            "for out-of-bailiwick names via the additional section."
        ),
        "6/8 Retry lookups with unsigned DNAME over TCP": (
            "Forces TCP retry when DNAME response lacks DNSSEC signature. "
            "Prevents spoofed UDP DNAME responses from being accepted."
        ),
        "7/8 Restore dns_message_reset() before reuse": (
            "Fix message state corruption when message object is reused without reset."
        ),
        "8/8 Lock access to fctx->nqueries": (
            "Race condition in the query counter — fctx->nqueries accessed without lock "
            "in concurrent resolution paths."
        ),
    },
    "security_class": (
        "DNS spoofing / cache poisoning via COOKIE bypass and additional/authority section injection. "
        "BIND 9.11.4 is 2018-era code. The attach/detach refactor is a prerequisite for safe "
        "concurrent message processing — fixing latent use-after-free vulnerabilities in the resolver."
    ),
    "severity": "HIGH",
}

CVE_2024_11187 = {
    "id": "CVE-2024-11187",
    "revision": ".18 (Feb 17 2025)",
    "author": "Ondřej Surý <ondrej@isc.org> (ISC)",
    "title": "CPU exhaustion via large RDATA additional section processing",
    "root_cause": (
        "When answering a query, BIND processes each RDATA entry and adds data to the additional "
        "section (A/AAAA records for names referenced in MX/NS/SRV records). "
        "There was no limit on how many RDATA entries triggered additional lookups. "
        "A response with many names in RDATA (MX with 100+ entries, SRV with many targets) "
        "caused N×M database lookups for each client query — CPU exhaustion DoS. "
        "Also: ANY queries received additional data, making responses even larger."
    ),
    "fix": (
        "New constant: DNS_RDATASET_MAXADDITIONAL = 13 "
        "New function: dns_rdataset_additionaldata2(rdataset, add, arg, limit) "
        "  if rdataset.count > limit: return DNS_R_TOOMANYRECORDS (skip additional processing) "
        "Existing dns_rdataset_additionaldata() calls dns_rdataset_additionaldata2 with limit=0 (unlimited). "
        "query_addrdataset(): if NOADDITIONAL || qtype == ANY: return immediately (no additional). "
        "query_addadditional(): calls additionaldata2 with limit=DNS_RDATASET_MAXADDITIONAL."
    ),
    "severity": "HIGH — CPU exhaustion DoS",
}

CVE_2024_1737 = {
    "id": "CVE-2024-1737",
    "revision": ".17 (Aug 9 2024)",
    "author": "David Shea <dshea@redhat.com> (Red Hat)",
    "title": "CPU exhaustion via large RRSets and excessive RR types per name",
    "root_cause": (
        "Two related DoS vectors: "
        "(1) Unlimited RRs in an RRSet — RRSet storage is a linked list; walking it is O(n). "
        "    Adding a name with 10,000 RRs for the same type causes O(10000) traversals "
        "    for every lookup of that name. "
        "(2) Unlimited RR types per owner name — same issue for types list traversal. "
        "    A DNS zone with 200 different record types for one name causes O(200) list scans. "
        "Both vectors: remote attacker causes BIND to cache pathological RRSets, then "
        "triggers repeated queries for those names = sustained CPU exhaustion."
    ),
    "fix": (
        "Compile-time limits: "
        "  DNS_RDATASET_MAX_RECORDS (default configurable) — max RRs per RRSet "
        "  DNS_RBTDB_MAX_RTYPES = 100 — max RR types per owner name "
        "Priority type list: HTTPS, SVCB, SRV, PTR, NAPTR, DNSKEY, TXT placed at list head "
        "  (accessed first, not evicted when over limit). "
        "Eviction strategy: when over limit, mark new non-priority entries as ancient immediately "
        "  (gets evicted from cache ASAP rather than refusing to add)."
    ),
    "severity": "HIGH — sustained CPU exhaustion DoS via crafted DNS zone data",
}

CVE_2024_1975 = {
    "id": "CVE-2024-1975",
    "revision": ".17 (Aug 9 2024)",
    "author": "David Shea <dshea@redhat.com> (Red Hat)",
    "title": "SIG(0) support completely removed — CPU exhaustion via crafted SIG(0) records",
    "root_cause": (
        "SIG(0) is a DNSSEC-predecessor transaction signature mechanism (RFC 2535/2931). "
        "Processing a SIG(0)-signed message requires looking up and verifying the signer's key. "
        "A malicious sender can submit SIG(0)-signed requests with crafted keys that "
        "force expensive cryptographic operations in the resolver, causing CPU exhaustion. "
        "SIG(0) has essentially no real-world use; TSIG replaced it for transaction authentication."
    ),
    "fix": (
        "Complete removal of SIG(0) from named. "
        "dns_message_checksig() before: "
        "  if tsig: verify TSIG "
        "  elif sig0: look up signer key (via view), verify signature (80+ lines) "
        "dns_message_checksig() after: "
        "  if tsig: verify TSIG "
        "  (sig0 path entirely deleted — 80 lines removed from message.c) "
        "If a SIG(0) record is present: log debug message 'SIG(0) support was removed' and reject. "
        "Update-policy rules: SIG(0) key no longer valid for zone update authorization. "
        "Documentation updated: all references changed from 'TSIG or SIG(0)' to 'TSIG'."
    ),
    "note": "This is an atypical CVE fix — complete feature removal rather than a bug fix.",
    "severity": "HIGH — CPU exhaustion via SIG(0) crypto operations",
}

# ── Historic CVE summary (2018-2023) ─────────────────────────────────────────

HISTORIC_CVES = {
    "CVE-2023-50387+50868": {
        "rev": ".16 (Apr 2024)",
        "title": "KeyTrap DNSSEC validator CPU exhaustion — same as TOS 4.6 bind-9.18",
        "note": "Backported to 9.11 from 9.18 patch. See tencent_tos46_appstream_bind_re.py F4.",
    },
    "CVE-2023-4408": {
        "rev": ".16 (Apr 2024)",
        "size": "81KB",
        "title": "DNS message parsing crash — large patch for parser hardening",
    },
    "CVE-2023-3341": {
        "rev": ".15 (Sep 2023)",
        "title": "Control channel recursion — limit recursion in rndc protocol handler",
    },
    "CVE-2023-2828": {
        "rev": ".14 (Jul 2023)",
        "title": "Cache size enforcement — cache could grow beyond configured limit",
    },
    "CVE-2022-38177": {
        "rev": ".10 (Sep 2022)",
        "title": "ECDSA verify memory leak — dst_key_free not called on verify error",
    },
    "CVE-2022-38178": {
        "rev": ".10 (Sep 2022)",
        "title": "EdDSA verify memory leak — same pattern as CVE-2022-38177",
    },
    "CVE-2022-2795": {
        "rev": ".11 (Sep 2022)",
        "title": "Large delegation CPU exhaustion — excessive referral chain following",
    },
    "CVE-2021-25220": {
        "rev": ".12/.13 (Dec 2022)",
        "title": "Cache poisoning via forwarder — accepted records from forwarder outside bailiwick",
    },
    "CVE-2021-25215": {
        "rev": ".5 (Apr 2021)",
        "title": "DNAME assertion failure — crafted DNAME response causes named crash",
    },
    "CVE-2021-25214": {
        "rev": ".6 (May 2021)",
        "title": "IXFR truncation assertion — insufficient IXFR data causes assertion failure",
    },
    "CVE-2020-8625": {
        "rev": ".4 (Feb 2021)",
        "title": "SPNEGO off-by-one — ISC SPNEGO implementation buffer overflow in GSS-API handling",
    },
    "CVE-2020-8623": {
        "rev": ".1 (Aug 2020)",
        "title": "PKCS11 assertion failure on crafted PKCS#11 packet",
    },
    "CVE-2020-8622": {
        "rev": ".1 (Aug 2020)",
        "title": "TSIG verify assertion — invalid TSIG truncation assertion failure",
    },
    "CVE-2020-8616": {
        "rev": "23.P2 (May 2020)",
        "title": "NXNSAttack — forged NS referrals trigger amplified query storms",
    },
    "CVE-2020-8617": {
        "rev": "23.P2 (May 2020)",
        "title": "TSIG assertions in two-stage TSIG checks",
    },
    "CVE-2018-5743": {
        "rev": "base (2019)",
        "title": "TCP connection limit not enforced — exhaustion of file descriptors",
    },
    "CVE-2018-5745": {
        "rev": "base (2019)",
        "title": "Trust anchor management assertion failure — managed-keys database assertion",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2025-40778",
        "title": "DNS COOKIE spoofing via authority/additional section injection — 8-patch refactor",
        "detail": (
            "bind-9.11 RHEL 7 backport active 17+ months past RHEL 7 EoL. "
            "CVE-2025-40778: refactors dns_message_t attach/detach + tightens NS/address caching "
            "from authority and additional sections. Prevents spoofed UDP responses from poisoning "
            "the resolver cache via authority NS delegation or additional A/AAAA records. "
            "Patch series also fixes race on fctx->nqueries and DNAME TCP retry."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2024-1975",
        "title": "SIG(0) completely removed — eliminates CPU exhaustion vector",
        "detail": (
            "All SIG(0) processing (80+ lines in message.c) deleted. "
            "Queries with SIG(0) signatures now rejected. "
            "TSIG is the only transaction auth mechanism in bind-9.11.4-26.P2.tl2.17+. "
            "DNS UPDATE and nsupdate applications that used SIG(0) will fail — "
            "operators must migrate to TSIG."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2024-1737",
        "title": "RRSet and type-per-name DoS — compile-time limits and priority type list",
        "detail": (
            "DNS_RDATASET_MAX_RECORDS limits RRs per RRSet to prevent O(n) traversal DoS. "
            "DNS_RBTDB_MAX_RTYPES=100 limits record types per owner. "
            "Priority types (DNSKEY, HTTPS, SVCB, SRV, PTR, NAPTR, TXT) exempt from eviction. "
            "Attacker-controlled zone data or forged responses could exploit this via zone transfers."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "cve": "CVE-2024-11187",
        "title": "Additional section processing capped at 13 RDATA names — prevents CPU exhaustion",
        "detail": (
            "MX/NS/SRV responses with many names triggered N×M database lookups. "
            "DNS_RDATASET_MAXADDITIONAL=13: if response RDATA has >13 names, skip additional lookups. "
            "ANY queries always skipped for additional data. "
            "Fix is conservative but effective for real-world DNS data."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "TOS 2.4 BIND 9.11 receives security patches 17+ months past RHEL 7 EoL",
        "detail": (
            "RHEL 7 EoL was June 30, 2024. bind-9.11.4-26.P2.tl2.19 released Nov 2025. "
            "Tencent maintains independent RHEL 7 security backport program for TOS 2.4. "
            "Patches are Red Hat-authored and ISC-upstream — not Tencent-specific fixes. "
            "Downstream of Red Hat's Extended Support stream."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "25+ CVEs patched in bind-9.11.4 for TOS 2.4 — comprehensive backport history (2018-2025)",
        "detail": (
            "The tl2.19 SRPM contains 80+ patch files covering 25+ CVEs from 2018-2025. "
            "Key classes: CPU exhaustion DoS (NXNSAttack, KeyTrap, SIG(0), RDATA size), "
            "cache poisoning (CVE-2021-25220, CVE-2025-40778), memory safety (CVE-2022-38177/78), "
            "assertion failures (CVE-2021-25214/15). "
            "RHEL 7 / TOS 2.4 systems on old bind are exposed to the full 2018-2024 backlog."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 2.4 bind-9.11.4-26.P2.tl2.19 RE")
    print()
    print("RHEL 7 EoL: Jun 2024 — tl2.19 issued Nov 2025 (+17 months post-EoL)")
    print()
    for f in FINDINGS:
        cve = f.get('cve', '')
        label = f"{cve} " if cve else ""
        print(f"  [{f['severity']:6s}] {f['id']}: {label}{f['title'][:65]}")
    print()
    print("Historic CVE series (2018-2023):")
    for cve_id, info in HISTORIC_CVES.items():
        print(f"  {cve_id}: {info['title'][:65]}")
