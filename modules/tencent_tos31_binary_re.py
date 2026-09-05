"""
TencentOS Server 3.1 Binary RE Module
Binaries: sshd (866KB), ssh-agent (333KB)
Source: openssh-server-8.0p1-13.tl3.x86_64.rpm (490KB, Google Drive)
        openssh-clients-8.0p1-13.tl3.x86_64.rpm (683KB, Google Drive)
Method: rpm2cpio extraction + string scan + upstream source cross-check
Analysis date: 2026-09-04

TOS 3.1 qcow2 images have corrupt ext4 journals (dirty, unrecoverable).
Binaries obtained directly from RPM packages on Google Drive.
Package timestamp in RPM headers: 2022-01-11.

Both CVE-2023-38408 and CVE-2023-48795 were disclosed in 2023 — after the
openssh-8.0p1-13.tl3 package was built (Jan 2022). TOS 3.1 received no openssh
security updates after -13 (confirmed: Updates-srpms/ contains no openssh package).

PKCS#11 WHITELIST CLARIFICATION:
  OpenSSH 8.0p1 (Dec 2019) included pkcs11_whitelist as part of the original
  PKCS#11 URI feature (openssh-8.0p1-pkcs11-uri.patch, RHEL 8 lineage).
  The compiled-in default is "/usr/lib*/*,/usr/local/lib*/*" — allowing any .so
  in system library directories. This is NOT the CVE-2023-38408 fix.
  The fix requires DEFAULT = empty (deny-all), which RHEL backported to
  openssh-8.0p1-25+ and upstream fixed in OpenSSH 9.3p2 (Aug 2023).
  TOS 3.1 at -13 ships the original allow-/usr/lib*/* default.

FINDINGS SUMMARY:
  TOS31-BIN-F01 (HIGH/7.3)    CVE-2023-38408 OPEN — default whitelist allows /usr/lib*/*
  TOS31-BIN-F02 (HIGH/7.3)    CVE-2023-48795 OPEN — no kex-strict strings in sshd
  TOS31-BIN-F03 (INFO)        Terminal package: no openssh updates after Jan 2022
  TOS31-BIN-F04 (INFO)        pkcs11_whitelist mechanism present (8.0p1 baseline feature,
                               not CVE fix — default is allow-all-in-/usr/lib*)
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-BIN-F01: CVE-2023-38408 PKCS#11 — OPEN
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_38408_TOS31 = {
    "finding_id": "TOS31-BIN-F01",
    "severity": "HIGH",
    "cvss_v3": 7.3,
    "status": "OPEN",
    "binary": "ssh-agent",
    "binary_size_bytes": 333504,
    "binary_build_date": "2022-01-11",
    "openssh_package": "openssh-8.0p1-13.tl3",
    "attack_vector": "ssh-agent forwarding + attacker-controlled PKCS#11 load request",
    "binary_evidence": {
        "pkcs11_whitelist_flag_present": True,
        "whitelist_usage_string": "[-P pkcs11_whitelist] [-t life] [command [arg ...]]",
        "rejection_message": 'refusing PKCS#11 provider "%.100s": not whitelisted',
        "compiled_default_whitelist": "/usr/lib*/*,/usr/local/lib*/*",
        "deny_all_default": False,
    },
    "exploit_path": (
        "Agent forwarding to compromised remote host. Remote attacker sends "
        "PKCS11_ADD_PROVIDER request with path matching /usr/lib64/*.so on victim "
        "machine. If a writable path under /usr/lib*/* exists or attacker can place "
        "a .so there, victim's ssh-agent loads attacker's library → code execution "
        "in ssh-agent process context."
    ),
    "cve_fix_requirement": (
        "CVE-2023-38408 fix = change default pkcs11_whitelist to empty (deny all). "
        "TOS 3.1's compiled-in default is '/usr/lib*/*,/usr/local/lib*/*' — "
        "not fixed. RHEL applied deny-all default in openssh-8.0p1-25+ (Jun 2024). "
        "TOS 3.1 terminal version is -13 (Jan 2022); no update channel for openssh. "
        "TOS 3.3 backported the fix in -25 (Aug 2024) with 'not whitelisted' wording."
    ),
    "comparison": {
        "pre_8.0p1 (unmitigated)": "no whitelist check at all — load any .so path",
        "8.0p1-13 (TOS 3.1)":     "whitelist defaults to /usr/lib*/* — OPEN (CVE exploitable via usr/lib paths)",
        "8.0p1-25 (TOS 3.3)":     "whitelist defaults to empty — PATCHED",
        "9.3p2 (TOS 4.0+)":       "permitted_providers, deny-all default — PATCHED",
    },
    "ref_srpm_module": "tencent_tos31_openssh_srpm_re.py",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-BIN-F02: CVE-2023-48795 Terrapin — OPEN
# ──────────────────────────────────────────────────────────────────────────────

CVE_2023_48795_TOS31 = {
    "finding_id": "TOS31-BIN-F02",
    "severity": "HIGH",
    "cvss_v3": 7.3,
    "status": "OPEN",
    "binary": "sshd",
    "binary_size_bytes": 866 * 1024,
    "binary_build_date": "2022-01-11",
    "openssh_package": "openssh-8.0p1-13.tl3",
    "binary_evidence": {
        "kex_strict_c_string": "ABSENT",
        "kex_strict_s_string": "ABSENT",
        "openssh_version_string": "OpenSSH_8.0p1",
    },
    "grep_result": "strings sshd | grep kex-strict → no output",
    "fix_requirement": (
        "Terrapin (CVE-2023-48795) fix = backport kex-strict extension strings "
        "kex-strict-c-v00@openssh.com and kex-strict-s-v00@openssh.com into "
        "OpenSSH. TOS 3.1 sshd binary (8.0p1-13.tl3) has neither string present. "
        "TOS 3.3 (8.0p1-25) has both backported. TOS 3.1 has no openssh update channel."
    ),
    "comparison": {
        "TOS_3.1 (8.0p1-13)": "OPEN — kex-strict strings absent",
        "TOS_3.3 (8.0p1-25)": "PATCHED — kex-strict strings confirmed at 0x54b16/0x54b62",
        "TOS_4.x (9.3+)":     "PATCHED — kex-strict at known offsets",
    },
    "attack_scenario": (
        "MitM attacker between SSH client and TOS 3.1 sshd. Attacker strips "
        "EXT_INFO message and manipulates sequence numbers during handshake. "
        "Enables bypass of integrity protections. High confidence exploitable — "
        "TOS 3.1 sshd has no kex-strict support at all; cannot negotiate safe mode."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-BIN-F03: Terminal openssh package — no update path
# ──────────────────────────────────────────────────────────────────────────────

TOS31_OPENSSH_TERMINAL = {
    "finding_id": "TOS31-BIN-F03",
    "severity": "INFO",
    "title": "openssh-8.0p1-13.tl3 is the terminal version for TOS 3.1",
    "package": "openssh-8.0p1-13.tl3",
    "package_build_date": "2022-01-11",
    "updates_channel_openssh": "ABSENT (verified: Updates-srpms/ has no openssh package)",
    "fix_availability": "None — no patched version published to TOS 3.1 update channel",
    "remediation": (
        "Upgrade to TOS 3.3 (openssh-8.0p1-25.tl3) or TOS 4.x. "
        "No in-place patch available for TOS 3.1 openssh. "
        "Workaround: disable agent forwarding (ForwardAgent no in ssh_config). "
        "For Terrapin: block SHA2 EtM MACs in server config (prevents downgrade vector)."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-BIN-F04: pkcs11_whitelist present but not the CVE fix
# ──────────────────────────────────────────────────────────────────────────────

PKCS11_WHITELIST_ANALYSIS = {
    "finding_id": "TOS31-BIN-F04",
    "severity": "INFO",
    "title": "pkcs11_whitelist in 8.0p1 is NOT the CVE-2023-38408 fix",
    "mechanism_origin": (
        "pkcs11_whitelist was introduced in OpenSSH 8.0p1 (Dec 2019) as part of "
        "the PKCS#11 URI feature (openssh-8.0p1-pkcs11-uri.patch). "
        "Upstream source: ssh-agent.c line 94 in 8.0p1 tarball: "
        "# define DEFAULT_PKCS11_WHITELIST '/usr/lib*/*,/usr/local/lib*/*'"
    ),
    "cve_fix_distinction": (
        "CVE-2023-38408 was disclosed July 2023. Fix = change default to empty "
        "(deny all untrusted providers). The 8.0p1 DEFAULT is allow-all-in-/usr/lib*. "
        "Having the mechanism ≠ having the fix. "
        "Correctly classifying this distinction avoids false-negative in CVE tracking."
    ),
    "binary_proof": {
        "compiled_default_string_found_in_binary": "/usr/lib*/*,/usr/local/lib*/*",
        "fix_indicator_for_comparison": "empty string OR explicit deny-all after -25 RHEL rebuild",
    },
    "implication_for_tos31_srpm_module": (
        "tencent_tos31_openssh_srpm_re.py incorrectly states pkcs11_whitelist ABSENT. "
        "Correction: mechanism is present in 8.0p1 baseline. "
        "CVE status remains OPEN — the correction is in the mechanism description, "
        "not in the vulnerability status."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

TOS31_BINARY_INVENTORY = {
    "source_method": "Google Drive RPM download + rpm2cpio extraction",
    "sshd": {
        "package": "openssh-server-8.0p1-13.tl3.x86_64.rpm",
        "gdrive_file_id": "1GKN7JTOTmOsBxu7jWqG6s9ZR8_9NfwhQ",
        "gdrive_file_size_bytes": 490 * 1024,
        "binary_path": "usr/sbin/sshd",
        "binary_size_bytes": 866 * 1024,
        "build_timestamp": "2022-01-11",
        "openssh_version": "OpenSSH_8.0p1",
        "kex_strict_present": False,
    },
    "ssh_agent": {
        "package": "openssh-clients-8.0p1-13.tl3.x86_64.rpm",
        "gdrive_file_id": "1paZK9kNfebfNoSeoI_fbmXCJX41WfyXq",
        "gdrive_file_size_bytes": 683188,
        "binary_path": "usr/bin/ssh-agent",
        "binary_size_bytes": 333504,
        "build_timestamp": "2022-01-11",
        "pkcs11_whitelist_present": True,
        "pkcs11_whitelist_default": "/usr/lib*/*,/usr/local/lib*/*",
        "deny_all_default": False,
    },
    "qcow2_status": (
        "All TOS 3.1 qcow2 images have corrupt ext4 dirty journals. "
        "mount -o ro,norecovery shows empty directories. "
        "e2fsck corrupts the qcow2 further (writes to read-only images). "
        "RPM extraction from Google Drive is the only viable binary source for TOS 3.1."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# CROSS-VERSION SUMMARY (sshd + ssh-agent)
# ──────────────────────────────────────────────────────────────────────────────

TOS31_CROSS_VERSION_POSITION = {
    "tos_version": "3.1",
    "openssh_package": "openssh-8.0p1-13.tl3",
    "base_upstream": "OpenSSH 8.0p1 (Dec 2019 release)",
    "package_build": "2022-01-11",
    "CVE_2023_38408": "OPEN — default whitelist /usr/lib*/* allows agent-forwarding RCE via usr/lib path",
    "CVE_2023_48795": "OPEN — no kex-strict strings in sshd binary",
    "update_channel": "NONE — terminal version -13; Updates-srpms has no openssh",
    "next_patched_version": "TOS 3.3 (openssh-8.0p1-25.tl3)",
    "comparison": {
        "TOS_2.4 (7.4p1-23)": "BOTH PATCHED (7.4p1 with backports, Jul 2026 ISO)",
        "TOS_3.1 (8.0p1-13)": "BOTH OPEN (Jan 2022 build, no update channel)",
        "TOS_3.3 (8.0p1-25)": "BOTH PATCHED",
        "TOS_4.0 (9.3p2-8)":  "BOTH PATCHED",
        "TOS_4.2+ (9.3+)":    "BOTH PATCHED",
    },
    "notable_pattern": (
        "TOS 2.4 (older) is PATCHED; TOS 3.1 (newer base) is OPEN. "
        "TOS 2.4 reached the fix via its active Jul 2026 ISO rebuild. "
        "TOS 3.1 is EoL with no update channel. Counter -13 represents Jan 2022 "
        "and no openssh package was ever published to Updates-srpms for TOS 3.1."
    ),
}
