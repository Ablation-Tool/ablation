"""
TencentOS Server 3.1 SRPM Security Audit
Source: /media/cowboy/research/tencentos/3.1/TencentOS-srpms/ (and AppStream-srpms, Updates-srpms)
Method: rpm2cpio + cpio extraction; spec file changelog + patch list analysis
Analysis date: 2026-09-04

TOS 3.1 (RHEL 8 base, 5.4.119 TK4 kernel) repo structure:
  TencentOS-srpms/      — main OS packages (.tl3 release tag)
  TencentOS-AppStream-srpms/ — AppStream modules
  AppStream-srpms/      — additional AppStream
  TencentOS-testing-srpms/   — testing channel
  Updates-srpms/        — errata/update packages (overlapping with main srpms)

Key finding: TOS 3.x security packages are essentially pure RHEL 8 inheritance
with the .tl3 release counter appended. The openssh spec contains 68 patches —
all standard RHEL 8 patches, none Tencent-specific. openssl similarly.
The only Tencent-specific customization found: systemd-239 contains one patch
that enables libiptc (comment: "tencentos: we need libiptc as some users still
want it") and an upstream sync commit by victorzhong@tencent.com.

Patch coverage assessment: "highest-version" packages in the TOS 3.1 repo
represent the end-of-life state of each package for that series.
Earlier-version SRPMs in the same repo (e.g., openssh-8.0p1-4.tl3.1.src.rpm)
represent TOS 3.1 at earlier patch levels — systems not updated from TOS 3.1
launch would be missing all security patches applied between -4.tl3 and -13.tl3.

openssl 1.1.1 EOL (September 11, 2023): the highest openssl in the TOS 3.1 repo
is 1.1.1k-7.tl3, which includes fixes through July 2022. No newer versions exist
in TencentOS-srpms or Updates-srpms. TOS 3.1 systems running after Sep 2023
have shipped no openssl patches for 2+ years (12+ months post EOL by Sep 2026).
"""

PACKAGES_ANALYZED = {
    "openssh": {
        "versions": ["8.0p1-4.tl3.1", "8.0p1-4.tl3.2", "8.0p1-5.tl3", "8.0p1-13.tl3"],
        "highest": "8.0p1-13.tl3",
        "rhel_base": "8.0p1 (RHEL 8)",
        "patch_count": 68,
        "tencent_patches": 0,
        "cve_fix_level": "Through CVE-2021-41617 (Oct 2021); CVE-2020-14145 (Jun 2021)",
        "notes": (
            "Pure RHEL 8 patch set. 68 patches are all standard RHEL 8 openssh patches. "
            "Highest version -13.tl3 matches RHEL 8.5 security level (Oct 2021). "
            "TOS 3.x uses openssh 8.0p1 — different CVE surface from TOS 4.x 9.3p2."
        ),
    },
    "libssh": {
        "versions": ["0.9.0-4.tl3", "0.9.6-3.tl3"],
        "highest": "0.9.6-3.tl3",
        "rhel_base": "0.9.6 (RHEL 8)",
        "cve_fixes": [
            "CVE-2021-3634 heap buffer overflow — FIXED",
            "CVE-2020-16135 NULL ptr deref in sftpserver — FIXED",
            "CVE-2019-14889 — FIXED",
            "CVE-2020-1730 — FIXED",
        ],
        "missing_fixes": [
            "CVE-2023-48795 Terrapin — NOT FIXED (0.9.x series predates this class; fix in 0.10.6)",
        ],
        "notes": (
            "libssh 0.9.6 is the last of the 0.9.x series. "
            "Terrapin (CVE-2023-48795, Dec 2023) was fixed in 0.10.6 — not backported to 0.9.x. "
            "TOS 3.x libssh is actually better-patched within its series than TOS 4.x libssh: "
            "TOS 4.0-4.6 all ship 0.10.5 which was released Dec 2023, "
            "AFTER the Terrapin fix in 0.10.6 (Jan 2024) was available."
        ),
    },
    "openssl": {
        "versions": ["1.1.1c-15.tl3", "1.1.1k-7.tl3"],
        "highest": "1.1.1k-7.tl3",
        "rhel_base": "1.1.1k (RHEL 8)",
        "eol_date": "2023-09-11",
        "cve_fixes": [
            "CVE-2022-2097 AES OCB encrypt failure — FIXED",
            "CVE-2022-2068 c_rehash command injection — FIXED",
            "CVE-2022-1292 c_rehash command injection — FIXED",
            "CVE-2022-0778 infinite loop in BN_mod_sqrt — FIXED",
            "CVE-2021-3712 read buffer overrun ASN.1 strings — FIXED",
            "CVE-2021-3450 CA cert check bypass — FIXED",
            "CVE-2021-3449 NULL ptr deref signature_algorithms — FIXED",
            "CVE-2020-1971 EdiParty NULL ptr deref — FIXED",
        ],
        "notes": (
            "openssl 1.1.1k was released March 2021. The -7.tl3 backport includes fixes "
            "through approximately July 2022. openssl 1.1.1 series reached EOL on "
            "September 11, 2023. No newer openssl SRPMs exist in the TOS 3.1 repo "
            "(TencentOS-srpms, AppStream-srpms, or Updates-srpms). TOS 3.1 systems "
            "have shipped no openssl security patches since ~Jul 2022 (24+ months "
            "of upstream fixes missed; 24+ months running EOL software by Sep 2026)."
        ),
    },
    "sudo": {
        "versions": ["1.8.29-5.tl3", "1.8.29-8.tl3"],
        "highest": "1.8.29-8.tl3",
        "cve_fixes": [
            "CVE-2021-3156 Baron Samedit heap overflow — FIXED (Patch12)",
            "CVE-2021-23239 sudoedit dir existence race — FIXED (Patch13)",
            "CVE-2021-23240 sudoedit SELinux symlink — FIXED (Patches 14-18)",
            "CVE-2019-19232 attacker Runas ALL access — FIXED (Patch7)",
            "CVE-2019-18634 pwfeedback stack overflow — FIXED (Patch9)",
        ],
        "notes": "sudo 1.8.29-8 is well-patched. Baron Samedit confirmed fixed.",
    },
    "polkit": {
        "versions": ["0.115-11.tl3", "0.115-13.tl3.2"],
        "highest": "0.115-13.tl3.2",
        "cve_fixes": [
            "CVE-2021-4034 PwnKit local priv esc — FIXED (Patch13)",
            "CVE-2021-4115 file descriptor leak — FIXED (Patch14)",
            "CVE-2021-3560 auth bypass via dbus — FIXED (Patch12)",
            "CVE-2019-6133 PID reuse slow fork — FIXED (Patch6)",
            "CVE-2018-19788 high UID priv esc — FIXED (Patch5)",
        ],
        "notes": "polkit 0.115-13.tl3.2 includes all major CVEs through Feb 2022.",
    },
    "glibc": {
        "versions": ["2.28-101.tl3", "2.28-189.5.tl3"],
        "highest": "2.28-189.5.tl3",
        "patch_count": 667,
        "cve_fixes": [
            "CVE-2022-23218/CVE-2022-23219 sunrpc buffer overflow — FIXED",
            "CVE-2021-3999 getcwd buffer overflow — FIXED",
            "CVE-2021-33574 mq_notify pthread attr deep copy — FIXED",
            "CVE-2021-35942 wordexp positional param overflow — FIXED",
            "CVE-2021-27645 nscd netgroupcache double free — FIXED",
            "CVE-2019-9169 regexec buffer overread — FIXED",
            "CVE-2016-10228/CVE-2020-27618 iconv infinite loop — FIXED",
        ],
        "notes": "glibc 2.28-189.5 is heavily maintained with 667 patches — comprehensive coverage.",
    },
    "systemd": {
        "versions": ["239-30.tl3.1", "239-58.tl3.8"],
        "highest": "239-58.tl3.8",
        "patch_count": 770,
        "tencent_patches": 1,
        "tencent_patch_desc": "libiptc enabled (comment: 'tencentos: we need libiptc'); maintainer victorzhong@tencent.com",
        "cve_fixes": [
            "CVE-2020-1712 sd-bus use-after-free — FIXED (multiple patches)",
            "CVE-2018-15686 state deserialize out-of-bounds — FIXED",
            "CVE-2017-9445 resolved out-of-bounds write — FIXED",
        ],
        "notes": (
            "systemd-239-58.tl3.8 has exactly one Tencent-specific modification: "
            "libiptc enablement (iptables compatibility). All security patches are "
            "standard RHEL 8 backports. Latest changelog entry (Oct 26 2022) by "
            "Xun Zhong <victorzhong@tencent.com> at Tencent."
        ),
    },
}

FINDINGS = {
    "TOS31-SRPM-F01": {
        "title": (
            "openssl 1.1.1k-7 EOL Since September 2023; No Updates Available in TOS 3.1 Repo; "
            "TOS 3.1 Systems Shipping Unpatched EOL OpenSSL for 24+ Months (Sep 2026)"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-1104",
        "component": "openssl-1.1.1k-7.tl3 (highest in TOS 3.1 repo)",
        "description": (
            "openssl 1.1.1 reached end-of-life on September 11, 2023. "
            "The TOS 3.1 repository's highest openssl package is 1.1.1k-7.tl3, "
            "which includes CVE backports through approximately July 2022. "
            "\n"
            "No newer openssl packages exist in TencentOS-srpms, TencentOS-AppStream-srpms, "
            "or Updates-srpms for TOS 3.1. This means: "
            "\n"
            "(1) Zero openssl security patches have been applied to TOS 3.1 since ~July 2022. "
            "(2) The 1.1.1 series has been EOL (no upstream security fixes) since Sep 2023. "
            "(3) All CVEs disclosed in openssl after July 2022 are open on TOS 3.1 deployments. "
            "\n"
            "Known post-Jul-2022 openssl 1.1.1 CVEs not in TOS 3.1 repo: "
            "CVE-2023-0464 (chain verification DoS), CVE-2023-0465 (cert policy bypass), "
            "CVE-2022-4304 (RSA timing oracle), CVE-2022-4450 (double free), "
            "CVE-2023-0286 (GeneralName ASN.1 type confusion), and others. "
            "\n"
            "Any TOS 3.1 system that has not migrated to TOS 3.3+ (which bumps to openssl 1.1.1) "
            "or TOS 4.x (openssl 3.0.x) is running software with no vendor security support."
        ),
        "chain": (
            "TOS31-SRPM-F01: TOS 3.1 deployment (common in legacy cloud workloads) → "
            "openssl 1.1.1k with known CVEs (RSA timing oracle, ASN.1 confusion, etc.) → "
            "TLS MitM or service crash on affected code paths"
        ),
        "remediation": (
            "Migrate TOS 3.1 deployments to TOS 3.3 (which has more recent openssl) or "
            "TOS 4.x (which uses openssl 3.0.x). "
            "If TOS 3.1 must remain: apply openssl from a third-party source or "
            "manually backport critical CVE patches."
        ),
        "references": [
            "openssl 1.1.1 EOL: 2023-09-11",
            "CVE-2023-0286 (GeneralName type confusion)",
            "CVE-2022-4304 (RSA decryption timing oracle)",
        ],
    },
    "TOS31-SRPM-F02": {
        "title": (
            "TOS 3.1 Security Packages Are Pure RHEL 8 Snapshots; "
            "No Tencent-Proprietary CVE Patches in openssh, openssl, libssh, sudo, polkit; "
            "Security Posture is RHEL 8 Snapshot Quality — No Independent Patching"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": "CWE-1059",
        "component": "All security-critical SRPMs in TencentOS-srpms",
        "description": (
            "Analysis of 6 security-critical TOS 3.1 SRPMs confirms: "
            "\n"
            "openssh-8.0p1-13.tl3: 68 patches — all standard RHEL 8 patches (Patch100-Patch962). "
            "Zero Tencent-specific security patches. ".tl3' counter is the only TOS difference. "
            "\n"
            "openssl-1.1.1k-7.tl3: all patches are RHEL 8 backports. No Tencent additions. "
            "\n"
            "libssh-0.9.6-3.tl3: changelog is RHEL 8 maintainer entries. No Tencent entries. "
            "\n"
            "sudo/polkit/glibc: identical pattern — RHEL 8 inherited, counter renamed to .tl3. "
            "\n"
            "The sole Tencent-specific patch found: systemd-239-58.tl3.8 enables libiptc "
            "(one conditional block with comment 'tencentos: we need libiptc as some users "
            "still want it'). This is a feature addition, not a security patch. "
            "\n"
            "Implication: TOS 3.1's security posture for these packages is 100% determined "
            "by RHEL 8's patch cadence at the time Tencent froze the package version. "
            "Any CVE fixed by Red Hat after the freeze date is not applied to TOS 3.1."
        ),
        "notes": (
            "Contrast with TOS 3.x glibc (667 patches) and TOS 4.x systemd (255-20.tl4.ap.1) — "
            "some packages have more Tencent-specific work, but the security-critical "
            "crypto/auth stack shows no independent patching."
        ),
    },
    "TOS31-SRPM-F03": {
        "title": (
            "TOS 3.1 Repo Contains Multiple Versions Per Package; "
            "Earliest Versions (e.g., openssh-8.0p1-4.tl3.1) Miss All Security Updates "
            "Applied Between TOS 3.1 Launch and Repo Freeze"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-1104",
        "component": "TencentOS-srpms: multiple versions per package",
        "description": (
            "The TOS 3.1 SRPM repository contains multiple release-counter versions of each "
            "security-critical package (openssh: 4 versions spanning -4.tl3.1 to -13.tl3). "
            "\n"
            "A TOS 3.1 instance that has not been updated via dnf/yum since initial install "
            "would be running the launch-era package (-4.tl3.x), missing: "
            "  - CVE-2021-41617 openssh priv separation failure (Oct 2021) "
            "  - CVE-2020-14145 openssh algorithm negotiation info leak (Jun 2021) "
            "  - polkit PwnKit CVE-2021-4034 (Feb 2022) "
            "  - sudo Baron Samedit CVE-2021-3156 (Feb 2021) "
            "  - Multiple openssl CVEs between 1.1.1c-15 and 1.1.1k-7 "
            "\n"
            "This is a standard finding for unupdated systems but is notable because: "
            "Tencent does not operate a traditional CVE advisory system for TencentOS. "
            "Cloud instances not configured with auto-update may be silently unpatched."
        ),
        "references": [
            "CVE-2021-41617 (openssh)", "CVE-2021-3156 (sudo Baron Samedit)",
            "CVE-2021-4034 (polkit PwnKit)",
        ],
    },
}

VERSION_MATRIX_TOS31 = {
    "openssl":  {"version": "1.1.1k", "release": "7.tl3", "eol": "2023-09-11", "cve_level": "Jul 2022"},
    "openssh":  {"version": "8.0p1", "release": "13.tl3", "cve_level": "Oct 2021"},
    "libssh":   {"version": "0.9.6", "release": "3.tl3", "cve_level": "Nov 2021"},
    "sudo":     {"version": "1.8.29", "release": "8.tl3", "cve_level": "Dec 2021"},
    "polkit":   {"version": "0.115", "release": "13.tl3.2", "cve_level": "Feb 2022"},
    "glibc":    {"version": "2.28", "release": "189.5.tl3", "cve_level": "Feb 2022"},
    "systemd":  {"version": "239", "release": "58.tl3.8", "cve_level": "Sep 2022"},
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "TencentOS-srpms/ (TOS 3.1, RHEL 8 base)",
        "method": "rpm2cpio + cpio; spec file audit (changelog, patch list)",
        "packages_analyzed": list(PACKAGES_ANALYZED.keys()),
        "key_finding": "Zero Tencent-specific security patches in openssh/openssl/libssh; "
                       "openssl 1.1.1k EOL Sep 2023, no repo updates",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
