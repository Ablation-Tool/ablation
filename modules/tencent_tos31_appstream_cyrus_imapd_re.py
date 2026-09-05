"""
TencentOS Server 3.1 AppStream cyrus-imapd RE Module
Source: /media/cowboy/research/tencentos/3.1/ SRPM hierarchy
Method: rpm2cpio SRPM extraction; patch file enumeration; spec changelog parsing
Analysis date: 2026-09-04

SRPM INVENTORY (TOS 3.1 sources):
  AppStream-srpms/cyrus-imapd-3.0.7-16.el8.src.rpm    upstream RHEL el8 (2018)
  AppStream-srpms/cyrus-imapd-3.0.7-16.tl3.src.rpm    Tencent rebuild
  AppStream-srpms/cyrus-imapd-3.0.7-19.el8.src.rpm    upstream RHEL el8 (2020)
  AppStream-srpms/cyrus-imapd-3.0.7-19.tl3.src.rpm    Tencent rebuild
  AppStream-srpms/cyrus-imapd-3.0.7-23.tl3.src.rpm    Tencent rebuild (CVE-2021-33582 patched)
  Updates-srpms/cyrus-imapd-3.0.7-23.tl3.src.rpm      (same, in Updates set)
  Updates-srpms/cyrus-imapd-3.0.7-24.tl3.src.rpm      functional fixes (Jun 2022)
  Updates-srpms/cyrus-imapd-3.0.7-26.tl3.src.rpm      test gating update (Jul 2024) <- LATEST

DIST TAG NOTE: All TOS 3.1 cyrus-imapd packages carry .tl3 dist tags.
Tencent maintains this package directly (unlike freeradius which uses RHEL AppStream modules).

KEY FINDING: cyrus-imapd 3.0.7 is the terminal version for TOS 3.1. RHEL 8 never
backported CVE-2024-34055 to 3.0.7. TOS 4.6 escaped by upgrading to 3.4.8.

COMPARISON:
  TOS 2.4:  2.4.17-15.tl2   IMAP 2.4.x branch; CVE-2024-34055 affects 3.0.x+ (different branch)
  TOS 3.1:  3.0.7-26.tl3    IMAP 3.0.x branch; CVE-2024-34055 OPEN (no RHEL 8 backport)
  TOS 4.6:  3.4.8-5.tl4     IMAP 3.4.x; upgraded Jun 2024 specifically for CVE-2024-34055

PATCH COVERAGE (-26.tl3 = terminal):
  CVE-2019-11356  PATCHED (cve_2019_11356.patch)
  CVE-2019-18928  PATCHED (CVE-2019-18928.patch)
  CVE-2019-19783  PATCHED (CVE-2019-19783.patch)
  CVE-2021-33582  PATCHED (3.0-CVE-2021-33582.patch, added in -23)
  CVE-2024-34055  OPEN    (heap overflow — no patch, RHEL 8 never backported, no update path)

FINDINGS SUMMARY:
  TOS31-CI-F01 (HIGH)    CVE-2024-34055 OPEN — heap overflow in IMAP FETCH, no 3.0.x backport
  TOS31-CI-F02 (INFO)    Last security CVE patched = CVE-2021-33582 (Sep 2021); -24/-25/-26 are functional
  TOS31-CI-F03 (INFO)    3.0.7-26 contains 3 new patches vs -23 (all functional, no CVEs)
  TOS31-CI-F04 (INFO)    TOS 4.6 upgraded to 3.4.8 specifically for CVE-2024-34055 (Tencent confirmed)
"""

# ──────────────────────────────────────────────────────────────────────────────
# PATCH COVERAGE ANALYSIS
# ──────────────────────────────────────────────────────────────────────────────

PATCH_SET_COMPARISON = {
    "patches_in_23_and_26": [
        "cyrus-imapd-cve_2019_11356.patch",
        "cyrus-imapd-CVE-2019-18928.patch",
        "cyrus-imapd-CVE-2019-19783.patch",
        "cyrus-imapd-3.0-CVE-2021-33582.patch",
        "cyrus-imapd-close_backup_fd_on_error.patch",
        "cyrus-imapd-close_backup_on_failure.patch",
        "cyrus-imapd-master_rename.patch",
        "cyrus-imapd-memory_leak_on_cleanup.patch",
        "cyrus-imapd-memory_leak_on_cleanup_2.patch",
        "cyrus-imapd-use_system_ciphers.patch",
    ],
    "patches_added_in_24_not_in_23": [
        "cyrus-squatter-assert-crash.patch",
        "cyrus-imapd-load-tombstones-for-cleanup.patch",
    ],
    "patches_added_in_25_26_not_in_24": [
        "cyrus-imapd-ptclient-canonification_across_multiple_domains.patch",
    ],
    "total_patches_in_26": 13,
    "cve_patches": 4,
    "last_cve_patch": "CVE-2021-33582 (added in -23, Sep 2021)",
    "new_patches_26_vs_23": {
        "cyrus-squatter-assert-crash.patch": (
            "NULL pointer guard in expand_mboxnames(): checks intname != NULL before "
            "calling mboxlist_mboxtree(). Fixes crash in squatter -r on malformed mailbox name. "
            "References: https://github.com/cyrusimap/cyrus-imapd/pull/3892 "
            "Not a CVE — crash only reachable by privileged squatter invocation."
        ),
        "cyrus-imapd-load-tombstones-for-cleanup.patch": (
            "cyr_expire.c: adds MBOXTREE_TOMBSTONES flag to mboxlist_usermboxtree() and "
            "mboxlist_allmbox() calls. Ensures tombstone mailboxes are included in expiry. "
            "References: commit 562ac9d7abd3b928315c7f0672d0f1a8995ca625 "
            "Functional correctness fix, no security impact."
        ),
        "cyrus-imapd-ptclient-canonification_across_multiple_domains.patch": (
            "ptclient/ldap.c: fixes logic inversion in domain canonification check. "
            "Changes strrchr(canon_id, '@') != NULL to == NULL. Enables correct LDAP "
            "domain enumeration when user has no @ in canon_id. "
            "References: RHEL-10710 "
            "Not a CVE — functional fix for multi-domain LDAP ptclient configurations."
        ),
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-CI-F01: CVE-2024-34055 OPEN
# ──────────────────────────────────────────────────────────────────────────────

CVE_2024_34055_TOS31 = {
    "finding_id": "TOS31-CI-F01",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2024-34055",
    "status": "OPEN",
    "title": (
        "CVE-2024-34055 (heap-based buffer overflow in IMAP FETCH handler) OPEN on "
        "TOS 3.1 cyrus-imapd 3.0.7-26.tl3 — no RHEL 8 backport exists; "
        "fix requires 3.4.7+; no update path in TOS 3.1"
    ),
    "disclosure_date": "2024-05-30",
    "affected_versions": (
        "Cyrus IMAP 3.0.x through 3.4.x before 3.4.7, 3.6.x before 3.6.4, "
        "3.8.x before 3.8.3. The 2.4.x branch is a separate attack surface "
        "and may not be affected."
    ),
    "component": "cyrus-imapd-3.0.7-26.tl3 (TOS 3.1 terminal version, Jul 2024)",
    "patch_status": (
        "No CVE-2024-34055 patch in the -26.tl3 SRPM patch set. "
        "The -26.tl3 changelog (Jul 2024): 'Update fmf plans and gating for c8s' — "
        "purely test infrastructure, not a security update. "
        "RHEL 8 / RHEL 8 StreamCentOS never backported CVE-2024-34055 to the 3.0.7 branch. "
        "The fix requires upgrading to 3.4.7+ (an API-breaking branch jump). "
        "TOS 3.1 has no mechanism to receive a 3.4.x package in the 3.0.x stream."
    ),
    "attack_surface": (
        "imapd listens on TCP 143 (IMAP) and TCP 993 (IMAPS). "
        "Attack requires authenticated IMAP session. "
        "Malicious IMAP FETCH command against a crafted message with deeply nested "
        "MIME structure triggers heap overflow in the fetch body handler. "
        "Impact: DoS (crash) or potential RCE in imapd process context."
    ),
    "attack_chain": (
        "Authenticated IMAP user → FETCH BODY[...] on crafted deep MIME message → "
        "heap overflow in cyrus-imapd 3.0.7 body structure handling → "
        "DoS or RCE in imapd daemon context → "
        "combined with TOS31-C01 PwnKit: imapd uid → local root"
    ),
    "tos_46_comparison": {
        "package": "cyrus-imapd-3.4.8-5.tl4",
        "changelog_entry": "upgrade to 3.4.8 to fix CVE-2024-34055 — 2024-06-26",
        "tencent_engineer": "Weiyao Feng <wynnfeng@tencent.com>",
        "status": "PATCHED — TOS 4.6 explicitly upgraded for this CVE",
    },
    "remediation": (
        "No patch available for TOS 3.1. Upgrade to TOS 4.6 (cyrus-imapd 3.4.8). "
        "Interim: restrict IMAP access to trusted/internal users only. "
        "Block unauthenticated IMAP from external networks."
    ),
    "references": ["CVE-2024-34055"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-CI-F02: Security update gap since Sep 2021
# ──────────────────────────────────────────────────────────────────────────────

CVE_COVERAGE_GAP_TOS31 = {
    "finding_id": "TOS31-CI-F02",
    "severity": "INFO",
    "title": (
        "Last security CVE patched in TOS 3.1 cyrus-imapd was CVE-2021-33582 (Sep 2021); "
        "counter revisions -24/-25/-26 contain only functional fixes; "
        "~3 year gap in CVE coverage (Sep 2021 → analysis date Sep 2026)"
    ),
    "changelog_analysis": {
        "3.0.7-23 (Sep 2021)": "CVE-2021-33582 PATCHED — Denial of service via IMAP/SIEVE",
        "3.0.7-24 (Jun 2022)": "Functional: squatter crash fix, network-online target wait, ctl_mboxlist null partition",
        "3.0.7-25 (Jun 2024)": "Functional: LDAP ptclient domain canonification (RHEL-10710)",
        "3.0.7-26 (Jul 2024)": "Infrastructure: fmf plans and gating for c8s",
    },
    "cve_history": {
        "CVE-2019-11356": "PATCHED (-16 baseline)",
        "CVE-2019-18928": "PATCHED (-17/-18 era)",
        "CVE-2019-19783": "PATCHED (-17/-18 era)",
        "CVE-2021-33582": "PATCHED (-23, Sep 2021)",
        "CVE-2024-34055": "OPEN — no path to fix in 3.0.7 branch",
    },
    "note": (
        "The counter jump from -23 to -26 (3 revisions) spans Jun 2022 to Jul 2024 "
        "with no CVE fixes. RHEL 8 upstream is at -26 (same). "
        "No unreleased CVE backport exists for 3.0.7 in RHEL 8."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-CI-F03: New functional patches in -26
# ──────────────────────────────────────────────────────────────────────────────

FUNCTIONAL_PATCHES_26 = {
    "finding_id": "TOS31-CI-F03",
    "severity": "INFO",
    "title": "cyrus-imapd 3.0.7-26.tl3 adds 3 functional patches vs -23: squatter crash, tombstones, LDAP domain",
    "patches_added_since_23": {
        "cyrus-squatter-assert-crash.patch": "NULL guard on intname in expand_mboxnames() — squatter -r crash on bad mailbox name",
        "cyrus-imapd-load-tombstones-for-cleanup.patch": "MBOXTREE_TOMBSTONES flag in cyr_expire — ensures deleted mailboxes are expired",
        "cyrus-imapd-ptclient-canonification_across_multiple_domains.patch": "Logic fix in ldap.c == NULL vs != NULL for multi-domain ptclient",
    },
    "security_relevance": "None — all three are functional/stability fixes with no exploitable path",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-CI-F04: TOS 4.6 explicitly fixed CVE-2024-34055
# ──────────────────────────────────────────────────────────────────────────────

TOS46_CVE_2024_34055_FIX = {
    "finding_id": "TOS31-CI-F04",
    "severity": "INFO",
    "title": (
        "TOS 4.6 upgraded cyrus-imapd from 3.4.4 → 3.4.8 explicitly for CVE-2024-34055; "
        "version-upgrade was the only fix path; confirms TOS 3.1 3.0.7 branch cannot receive the fix"
    ),
    "tos_46_package": "cyrus-imapd-3.4.8-5.tl4",
    "tos_46_changelog": {
        "3.4.8-1 (2024-06-26)": "upgrade to 3.4.8 to fix CVE-2024-34055 (Weiyao Feng, wynnfeng@tencent.com)",
        "3.4.8-2 (2024-08-16)": "rebuild for loongarch",
        "3.4.8-3 (2024-09-26)": "clarify package requirements",
        "3.4.8-4 (2024-12-23)": "rebuild for icu",
        "3.4.8-5 (2025-09-10)": "rebuild for icu",
    },
    "version_gap": {
        "TOS_3.1_terminal": "3.0.7-26.tl3 (Jul 2024)",
        "TOS_4.6_cvefixed": "3.4.8-1.tl4 (Jun 2024)",
    },
    "note": (
        "TOS 4.6 was already on 3.4.4 (from 3.4.x branch) before the CVE. "
        "The upgrade to 3.4.8 was a minor version bump within the same branch. "
        "TOS 3.1 would need a 3.0 → 3.4 branch jump — not feasible without breaking changes."
    ),
    "comparison": {
        "TOS_2.4 (2.4.17-15.tl2)": "Different branch (2.4.x); CVE-2024-34055 scope may differ",
        "TOS_3.1 (3.0.7-26.tl3)": "OPEN — 3.0.x branch, no backport, no update path",
        "TOS_4.6 (3.4.8-5.tl4)": "PATCHED — explicit upgrade for CVE-2024-34055",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS31-CI-F01": CVE_2024_34055_TOS31,
    "TOS31-CI-F02": CVE_COVERAGE_GAP_TOS31,
    "TOS31-CI-F03": FUNCTIONAL_PATCHES_26,
    "TOS31-CI-F04": TOS46_CVE_2024_34055_FIX,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "cyrus-imapd-3.0.7-26.tl3.src.rpm (TOS 3.1 Updates-srpms, terminal)",
        "method": "SRPM patch set enumeration + changelog analysis + cross-version comparison",
        "terminal_version": "3.0.7-26.tl3 (Jul 2024)",
        "last_cve_patched": "CVE-2021-33582 (Sep 2021)",
        "cve_2024_34055": "OPEN — no 3.0.x backport, no update path in TOS 3.1",
        "tos46_fix": "3.4.8-5.tl4 PATCHED (upgraded for CVE-2024-34055, Jun 2024)",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
