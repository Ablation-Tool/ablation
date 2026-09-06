"""
TencentOS Server 4.6 BaseOS-Source SRPM RE Module
Sources: /media/cowboy/research/tencentos/4.6/BaseOS-source/
  libssh-0.10.5-{3,6,7,8}.tl4.src.rpm    (4 versions; -6 = TOS 4.6 ISO; -7 = qcow2 update)
  openssh-9.3p2-{15,16}.tl4.src.rpm       (2 versions; -15 = TOS 4.6 ISO; -16 = Jul 2026)
Method: rpm2cpio | cpio -idmv; patch file enumeration; spec changelog parsing
Analysis date: 2026-09-04

KEY FINDING — patch-counter model:
  Tencent does NOT advance upstream versions to get security fixes.
  Instead: freeze upstream version (libssh 0.10.5, openssh 9.3p2), accumulate CVE backports
  as release counter increments. The release counter IS the security patch ledger.
  SBOM version comparison alone (0.10.5 < 0.10.6) is insufficient and will produce
  false positives. Definitive check: enumerate *.patch files in the SRPM.

PATCH AGENT — DeepSeek V4:
  Patch file Subject headers contain:
    Adapted-by: PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)
  This attribution first observed in libssh -7 and openssh -16 SRPMs.
  Tencent delegates patch adaptation from upstream (OpenBSD/RHEL) to the TencentOS
  OpenCloudOS stream via an AI agent backed by DeepSeek V4.
  See TOS46-SRPM-F07 for security implications.

LIBSSH SRPM PATCH INVENTORY:
  -3.tl4:  (no CVE patches related to Terrapin)
  -6.tl4:  CVE-2023-48795.patch (Terrapin fix, added at -4 Aug 16 2024)
           CVE-2023-6004.patch
           CVE-2023-6918.patch
  -7.tl4:  + libssh-0.10.5-CVE-2026-0964.patch (SCP path traversal)
  -8.tl4:  + libssh-0.10.5-CVE-2026-59843-1.patch
           + libssh-0.10.5-CVE-2026-59843-2.patch (channel infinite loop)

OPENSSH SRPM PATCH INVENTORY:
  -15.tl4: openssh-9.6p1-CVE-2023-48795.patch (Terrapin)
           openssh-9.6p1-cve-2024-6387.patch (regreSSHion)
           [NO CVE-2025-26465.patch]
  -16.tl4: + openssh-9.3p2-CVE-2025-26465.patch
           + openssh-9.3p2-CVE-2026-35385.patch
           + openssh-9.3p2-CVE-2026-35414.patch
           Changelog: 'Wed Jul 29 2026 PkgAgent Robot — Fix CVE-2026-35414, CVE-2026-35385, CVE-2025-26465'
           Adapted-by: PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)

VERSION-TO-DEPLOYMENT MAP:
  libssh:
    0.10.5-3  TOS 4.0 (Mar 2024), TOS 4.2 (all 7 builds, May-Dec 2024)   Terrapin: OPEN
    0.10.5-6  TOS 4.6 ISO (Apr 2026)                                       Terrapin: FIXED
    0.10.5-7  TOS 4.6 qcow2 (update snapshot)                              +CVE-2026-0964: FIXED
    0.10.5-8  Update channel (future/post qcow2)                           +CVE-2026-59843: FIXED
  openssh:
    9.3p2-15  TOS 4.4 (Sep 2025), TOS 4.6 ISO (Apr 2026)                  CVE-2025-26465: OPEN
    9.3p2-16  Update channel (Jul 29 2026)                                 CVE-2025-26465: FIXED
"""

LIBSSH_SRPM_PATCH_INVENTORY = {
    "0.10.5-3.tl4": {
        "cve_patches": [],
        "terrapin_status": "OPEN",
        "deployments": ["TOS 4.0 (Mar 2024)", "TOS 4.2 (all 7 builds May-Dec 2024)"],
        "source_rpms": ["libssh-0.10.5-3.tl4.src.rpm"],
    },
    "0.10.5-6.tl4": {
        "cve_patches": [
            "CVE-2023-48795.patch",
            "CVE-2023-6004.patch",
            "CVE-2023-6918.patch",
        ],
        "terrapin_status": "FIXED",
        "terrapin_fix_added_at_counter": "-4",
        "terrapin_fix_date": "2026-08-16",
        "terrapin_fix_by": "OpenCloudOS RelEng",
        "deployments": ["TOS 4.4 (Sep 2025)", "TOS 4.6 ISO (Apr 9 2026)"],
        "source_rpms": ["libssh-0.10.5-6.tl4.src.rpm"],
    },
    "0.10.5-7.tl4": {
        "cve_patches": [
            "CVE-2023-48795.patch",
            "CVE-2023-6004.patch",
            "CVE-2023-6918.patch",
            "libssh-0.10.5-CVE-2026-0964.patch",
        ],
        "cve_2026_0964_status": "FIXED",
        "deployments": ["TOS 4.6 qcow2 update (post-Apr 2026)", "TENCENTOS_UPDATE_ID=6 in qcow2"],
        "source_rpms": ["libssh-0.10.5-7.tl4.src.rpm"],
        "adapted_by": "PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)",
    },
    "0.10.5-8.tl4": {
        "cve_patches": [
            "CVE-2023-48795.patch",
            "CVE-2023-6004.patch",
            "CVE-2023-6918.patch",
            "libssh-0.10.5-CVE-2026-0964.patch",
            "libssh-0.10.5-CVE-2026-59843-1.patch",
            "libssh-0.10.5-CVE-2026-59843-2.patch",
        ],
        "cve_2026_59843_status": "FIXED",
        "deployments": ["Update channel, post-Jul 2026 (not yet in qcow2)"],
        "source_rpms": ["libssh-0.10.5-8.tl4.src.rpm"],
    },
}

OPENSSH_SRPM_PATCH_INVENTORY = {
    "9.3p2-15.tl4": {
        "cve_patches": [
            "openssh-9.6p1-CVE-2023-48795.patch",
            "openssh-9.6p1-cve-2024-6387.patch",
        ],
        "cve_2025_26465_status": "OPEN",
        "deployments": ["TOS 4.4 (Sep 2025)", "TOS 4.6 ISO (Apr 9 2026)", "TOS 4.6 qcow2 (TENCENTOS_UPDATE_ID=6)"],
        "source_rpms": ["openssh-9.3p2-15.tl4.src.rpm"],
    },
    "9.3p2-16.tl4": {
        "cve_patches": [
            "openssh-9.6p1-CVE-2023-48795.patch",
            "openssh-9.6p1-cve-2024-6387.patch",
            "openssh-9.3p2-CVE-2025-26465.patch",
            "openssh-9.3p2-CVE-2026-35385.patch",
            "openssh-9.3p2-CVE-2026-35414.patch",
        ],
        "cve_2025_26465_status": "FIXED",
        "cve_2026_35385_status": "FIXED",
        "cve_2026_35414_status": "FIXED",
        "changelog_date": "2026-07-29",
        "changelog_entry": "Fix CVE-2026-35414, CVE-2026-35385, CVE-2025-26465",
        "adapted_by": "PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)",
        "deployments": ["Update channel, post-Jul 29 2026"],
        "source_rpms": ["openssh-9.3p2-16.tl4.src.rpm"],
    },
}

CVE_DETAILS = {
    "CVE-2023-48795": {
        "component": "libssh / openssh",
        "class": "Terrapin MitM — SSH handshake truncation",
        "fixed_libssh": "0.10.5-6 (TOS 4.4/4.6 ISO); NOT fixed in 0.10.5-3 (TOS 4.0/4.2)",
        "fixed_openssh": "present in -15 SRPM (openssh-9.6p1-CVE-2023-48795.patch)",
        "cvss": "5.9 / MEDIUM",
    },
    "CVE-2026-0964": {
        "component": "libssh",
        "class": "SCP path traversal — invalid paths accepted in ssh_scp_pull_request()",
        "patch_file": "libssh-0.10.5-CVE-2026-0964.patch",
        "fix_counter": "0.10.5-7",
        "vulnerable_in_tos": "TOS 4.6 ISO (libssh-0.10.5-6); qcow2 at -7 is FIXED",
        "description": (
            "scp.c ssh_scp_pull_request(): does not reject requests with null path, "
            "paths containing '/', or '.' / '..' components. "
            "Allows server to send malformed SCP pull request pointing outside intended directory. "
            "Fix: null check, '/' reject, and explicit '.' / '..' reject added to scp.c."
        ),
        "cvss": "4.8 / MEDIUM",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cvss_rationale": "Network-accessible (AV:N), MitM position or rogue server required (AC:H); limited to data client pulls via scp (C:L/I:L), no availability impact",
    },
    "CVE-2026-59843": {
        "component": "libssh",
        "class": "Channel write infinite loop (DoS)",
        "patch_files": [
            "libssh-0.10.5-CVE-2026-59843-1.patch",
            "libssh-0.10.5-CVE-2026-59843-2.patch",
        ],
        "fix_counter": "0.10.5-8",
        "vulnerable_in_tos": (
            "TOS 4.6 ISO (libssh-0.10.5-6) AND qcow2 update (libssh-0.10.5-7) — both open"
        ),
        "description": (
            "channel_write_common() enters an infinite loop when max_packet_size=0 is received "
            "from the remote. A server or MitM can trigger this by sending a channel open "
            "or configuration response with max_packet_size=0, causing the libssh client to "
            "loop forever and become unresponsive (process-level DoS). "
            "Two-patch fix: -1 adds the max_packet_size=0 guard; -2 handles related edge cases."
        ),
        "cvss": "5.9 / MEDIUM",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cvss_rationale": "MitM or rogue server required (AC:H); pure availability impact — infinite loop hangs libssh client process; no data exposure or integrity impact",
    },
    "CVE-2025-26465": {
        "component": "openssh",
        "class": "VerifyHostKeyDNS MitM — error code not propagated in key validation",
        "patch_file": "openssh-9.3p2-CVE-2025-26465.patch",
        "fix_counter": "9.3p2-16",
        "vulnerable_in_tos": "TOS 4.6 ISO (9.3p2-15) and qcow2 (9.3p2-15 confirmed at TENCENTOS_UPDATE_ID=6)",
        "description": (
            "Error codes not correctly set in krl.c, ssh-agent.c, ssh-sk-client.c, sshconnect2.c. "
            "Reported by Qualys Security Advisory team. "
            "When VerifyHostKeyDNS=yes is enabled and SSHFP DNS records exist, "
            "the client can accept a malicious host key due to an unchecked return code "
            "in the SSHFP validation path. "
            "Attack: attacker poisons SSHFP DNS or performs DNSSEC MitM → "
            "SSH client connects to attacker's server thinking it's the legitimate host."
        ),
        "cvss": "6.8 / MEDIUM",
        "adapted_by": "PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)",
    },
    "CVE-2026-35385": {
        "component": "openssh scp",
        "class": "scp fails to clear setuid/setgid bits when root downloads without -p",
        "patch_file": "openssh-9.3p2-CVE-2026-35385.patch",
        "fix_counter": "9.3p2-16",
        "vulnerable_in_tos": "TOS 4.6 ISO and qcow2 (both at 9.3p2-15)",
        "description": (
            "When scp downloads a file as root without the -p (preserve permissions) flag, "
            "it should strip setuid/setgid bits from the destination to prevent privilege "
            "escalation via downloaded files. "
            "Without the fix, 'mask |= 07000' is missing — setuid/setgid bits from the source "
            "are preserved in the destination even when root downloads without -p. "
            "Impact: root operator uses 'scp host:/setuid-binary .' — receives a setuid binary "
            "on the local filesystem that any local user can then execute for privilege escalation."
        ),
        "cvss": "6.3 / MEDIUM",
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N",
        "cvss_rationale": "Local vector (AV:L); requires root to scp without -p (PR:H, UI:R); setuid binary lands on filesystem → local users exploit for full local priv-esc (C:H/I:H); no availability impact",
        "adapted_by": "PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)",
    },
    "CVE-2026-35414": {
        "component": "openssh certificates",
        "class": "Empty certificate principals list accepted (fail-open authorization)",
        "patch_file": "openssh-9.3p2-CVE-2026-35414.patch",
        "fix_counter": "9.3p2-16",
        "vulnerable_in_tos": "TOS 4.6 ISO and qcow2 (both at 9.3p2-15)",
        "description": (
            "When an SSH certificate has an empty principals list (no subject restrictions), "
            "OpenSSH should reject it or treat it as invalid (fail-closed). "
            "The unfixed behavior: empty principal list passes authorization checks — "
            "a certificate with no principals restriction is accepted for any user. "
            "Impact: attacker obtains or crafts a certificate with empty principals → "
            "can authenticate as any user on any server that trusts the signing CA, "
            "bypassing per-user / per-host authorization controls enforced via principals."
        ),
        "cvss": "8.2 / HIGH",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "cvss_rationale": "Attacker needs valid certificate from a trusted CA (PR:L), must craft empty-principals cert (AC:H); scope changes (S:C) because compromise affects users/hosts across the CA trust domain; full auth bypass → C:H/I:H",
        "adapted_by": "PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)",
    },
}

FINDINGS = {
    "TOS46-SRPM-F01": {
        "title": (
            "libssh CVE-2023-48795 Terrapin Fix Absent at -3; Present at -6; "
            "TOS 4.0 and TOS 4.2 (All 7 Builds) Ship -3 = Vulnerable; "
            "TOS 4.4 and TOS 4.6 ISO Ship -6 = FIXED via CVE-2023-48795.patch in SRPM"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-354",
        "component": "libssh-0.10.5-3.tl4 (TOS 4.0, TOS 4.2) — OPEN",
        "description": (
            "SRPM patch file enumeration definitively resolves the libssh Terrapin status "
            "across TOS 4.x that version-number comparison could not. "
            "\n"
            "Methodology: rpm2cpio libssh-0.10.5-{3,6,7,8}.tl4.src.rpm | cpio -idmv; "
            "enumerate *.patch files; CVE-2023-48795.patch presence = fix applied. "
            "\n"
            "Result: "
            "  -3: NO CVE-2023-48795.patch — OPEN "
            "  -6: CVE-2023-48795.patch PRESENT — FIXED "
            "    Changelog: fixed at -4 (Aug 16 2024) by OpenCloudOS RelEng "
            "    The fix was applied 8 months after TOS 4.0 launched with -3 "
            "\n"
            "TOS 4.0 (Mar 2024): libssh-0.10.5-3 — OPEN "
            "TOS 4.2 (7 builds, May-Dec 2024): libssh-0.10.5-3 — OPEN across all builds "
            "TOS 4.4 (Sep 2025): libssh-0.10.5-6 — FIXED "
            "TOS 4.6 ISO (Apr 2026): libssh-0.10.5-6 — FIXED "
            "\n"
            "Downstream impact: all TOS 4.0 and 4.2 production deployments that have not "
            "applied updates to reach -6 remain vulnerable to Terrapin. The TOS 4.2 Dec 2024 "
            "ISO is the last confirmed -3 build in the corpus; -4 was released Aug 2024 "
            "but does not appear in available ISO SBOMs."
        ),
        "chain": (
            "TOS46-SRPM-F01: TOS 4.0 or 4.2 deployment (libssh-0.10.5-3) → "
            "git-over-SSH or automation SSH session → "
            "Terrapin MitM truncates negotiation → "
            "keystroke-timing countermeasures disabled → "
            "credential inference via timing side-channel"
        ),
        "references": [
            "CVE-2023-48795",
            "TOS40-F01 (tencent_tos40_container_re.py) — -3 vulnerable",
            "TOS42-F01 (tencent_tos42_iso_sbom_re.py) — -3 across 7 builds",
            "TOS46-C01 CORRECTION (tencent_tos46_components_re.py) — TOS 4.4/4.6 at -6 is FIXED",
        ],
    },
    "TOS46-SRPM-F02": {
        "title": (
            "CVE-2025-26465 openssh VerifyHostKeyDNS MitM CONFIRMED OPEN in TOS 4.6 ISO; "
            "openssh-9.3p2-15.tl4.src.rpm Has No CVE-2025-26465.patch; "
            "Fix Shipped at -16 (Jul 29 2026) — 17 Months After Disclosure"
        ),
        "severity": "MEDIUM",
        "cvss": "6.8",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cwe": "CWE-295",
        "component": "openssh-9.3p2-15.tl4 (TOS 4.6 ISO, qcow2 as of TENCENTOS_UPDATE_ID=6)",
        "description": (
            "CVE-2025-26465 (Qualys, Feb 2025): OpenSSH client accepts MitM connection when "
            "VerifyHostKeyDNS=yes and SSHFP records are present. "
            "The patch modifies sshconnect2.c and krl.c to propagate error codes that "
            "were previously ignored, closing the fail-open path. "
            "\n"
            "Confirmation method: "
            "  rpm2cpio openssh-9.3p2-15.tl4.src.rpm | cpio -idmv -> no CVE-2025-26465.patch "
            "  rpm2cpio openssh-9.3p2-16.tl4.src.rpm | cpio -idmv -> openssh-9.3p2-CVE-2025-26465.patch PRESENT "
            "\n"
            "Timeline: "
            "  Feb 2025: CVE-2025-26465 disclosed "
            "  Apr 9 2026 (TOS 4.6 ISO): still at -15, unfixed "
            "  Jul 29 2026: -16 released with fix + CVE-2026-35385 + CVE-2026-35414 "
            "\n"
            "Attack prerequisites: target's ~/.ssh/config or /etc/ssh/ssh_config sets "
            "VerifyHostKeyDNS=yes (non-default, but documented as 'yes' or 'ask' for "
            "DNSSEC-validating environments). "
            "Impact: attacker with DNS MitM or DNSSEC poisoning position redirects "
            "ssh client to attacker's server, collecting credentials."
        ),
        "chain": (
            "TOS46-SRPM-F02: SSH client with VerifyHostKeyDNS=yes → "
            "attacker poisons SSHFP DNS record or intercepts DNSSEC query → "
            "CVE-2025-26465 fail-open in SSHFP validation → "
            "client connects to attacker's server → "
            "private key usage / credential interception"
        ),
        "remediation": "Apply openssh-9.3p2-16.tl4 update. Interim: VerifyHostKeyDNS=no.",
        "references": [
            "CVE-2025-26465",
            "RHSA-2025:1677 (RHEL backport)",
            "TOS46-C02 update (tencent_tos46_components_re.py)",
        ],
    },
    "TOS46-SRPM-F03": {
        "title": (
            "NEW CVE-2026-0964: libssh SCP Path Traversal; "
            "ssh_scp_pull_request() Accepts Null, '/', '.', '..' Paths; "
            "OPEN in TOS 4.6 ISO (-6); FIXED in qcow2 Update (-7)"
        ),
        "severity": "MEDIUM",
        "cvss": "5.8",
        "cwe": "CWE-22",
        "component": "libssh-0.10.5-6.tl4 (TOS 4.6 ISO) — OPEN; libssh-0.10.5-7.tl4 (qcow2) — FIXED",
        "description": (
            "CVE-2026-0964: libssh scp.c ssh_scp_pull_request() does not validate the "
            "path supplied by the remote server. "
            "\n"
            "Unvalidated cases in unfixed versions: "
            "  - NULL path pointer (no null check) "
            "  - Paths containing '/' (allows absolute or traversal paths) "
            "  - Paths equal to '.' or '..' "
            "\n"
            "Impact: a malicious or compromised SCP server can send a pull request with "
            "a path like '../../etc/shadow' and the libssh client will attempt to open "
            "the traversed path, potentially writing attacker-controlled content outside "
            "the intended destination directory. "
            "\n"
            "Fix location: src/scp.c, ssh_scp_pull_request() "
            "  Add: null check, strchr('/')-based absolute-path reject, "
            "       strcmp('.')==0 and strcmp('..')==0 rejects "
            "\n"
            "TOS status: "
            "  -6 (TOS 4.6 ISO, Apr 2026): NO CVE-2026-0964.patch — OPEN "
            "  -7 (qcow2 update): libssh-0.10.5-CVE-2026-0964.patch PRESENT — FIXED "
            "  qcow2 at /mnt/qcow2 (TENCENTOS_UPDATE_ID=6) runs libssh-7.tl4 — FIXED "
            "\n"
            "TOS 4.6 installations using the Apr 2026 ISO and not applying updates "
            "remain vulnerable to this path traversal. The qcow2 represents a system "
            "that has applied the update."
        ),
        "chain": (
            "TOS46-SRPM-F03: TOS 4.6 ISO-installed system (libssh-0.10.5-6) → "
            "application performs SCP pull via libssh → "
            "attacker-controlled SCP server sends pull request with traversal path → "
            "libssh writes server content to arbitrary local path → "
            "file overwrite / injection outside intended directory"
        ),
        "references": ["CVE-2026-0964", "libssh-0.10.5-CVE-2026-0964.patch (in SRPM -7)"],
    },
    "TOS46-SRPM-F04": {
        "title": (
            "NEW CVE-2026-59843: libssh channel_write_common() Infinite Loop on max_packet_size=0; "
            "OPEN in TOS 4.6 ISO (-6) AND qcow2 Update (-7); "
            "FIXED Only at -8 — Not Yet in Any Known TOS Deployment"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-835",
        "component": (
            "libssh-0.10.5-6.tl4 (TOS 4.6 ISO) — OPEN; "
            "libssh-0.10.5-7.tl4 (qcow2) — OPEN; "
            "libssh-0.10.5-8.tl4 (update channel) — FIXED"
        ),
        "description": (
            "CVE-2026-59843: channel_write_common() in libssh enters an infinite loop "
            "when the remote sends a channel configuration response with max_packet_size=0. "
            "\n"
            "Root cause: the write loop uses max_packet_size to determine how many bytes "
            "to send per iteration. When max_packet_size=0, the per-iteration send size "
            "is zero, the loop progress check never advances, and the loop runs indefinitely. "
            "\n"
            "Two-patch fix: "
            "  CVE-2026-59843-1.patch: adds max_packet_size=0 guard at channel open response handling "
            "  CVE-2026-59843-2.patch: handles related edge cases in channel_write_common itself "
            "\n"
            "Attack scenarios: "
            "  - Attacker-controlled SSH server sends max_packet_size=0 on any channel open response "
            "  - MitM modifies channel open response in transit to set max_packet_size=0 "
            "  - Result: libssh client process spins indefinitely (DoS at process level) "
            "\n"
            "TOS status: "
            "  -6 (TOS 4.6 ISO): NO CVE-2026-59843 patches — OPEN "
            "  -7 (qcow2 update): NO CVE-2026-59843 patches — OPEN "
            "  -8 (future update): FIXED "
            "\n"
            "This is the most recently published unmitigated CVE in the libssh series "
            "across all TOS 4.x deployments with access to the SRPM corpus."
        ),
        "chain": (
            "TOS46-SRPM-F04: application using libssh connects to SSH server → "
            "server (attacker-controlled or MitM-modified) sends max_packet_size=0 → "
            "channel_write_common infinite loop → application process hangs → "
            "DoS of any libssh-dependent service; combined with watchdog restart: repeated crash loop"
        ),
        "references": [
            "CVE-2026-59843",
            "libssh-0.10.5-CVE-2026-59843-1.patch",
            "libssh-0.10.5-CVE-2026-59843-2.patch",
        ],
    },
    "TOS46-SRPM-F05": {
        "title": (
            "NEW CVE-2026-35385: openssh scp Fails to Clear setuid/setgid Bits for Root Download; "
            "'mask |= 07000' Missing — Root scp Without -p Preserves Special Bits on Destination; "
            "OPEN in TOS 4.6 ISO and qcow2 (-15); FIXED at -16 (Jul 2026)"
        ),
        "severity": "MEDIUM",
        "cvss": "6.3",
        "cwe": "CWE-732",
        "component": "openssh-9.3p2-15.tl4 (TOS 4.6 ISO and qcow2) — OPEN",
        "description": (
            "CVE-2026-35385: when the OpenSSH scp command is run as root WITHOUT the -p "
            "(preserve permissions) flag, it should strip setuid and setgid bits from "
            "downloaded files to prevent privilege escalation. "
            "\n"
            "Unfixed behavior: the mode mask used for destination file creation does not "
            "include '| 07000' — the octet that clears setuid/setgid bits. "
            "Result: a file with setuid bit (mode 4755) downloaded by root without -p "
            "retains its setuid bit at the destination. "
            "\n"
            "Fix: 'mask |= 07000' added to scp.c permission mask calculation "
            "(the same bit pattern cleared by chmod after a regular 'cp' would use). "
            "\n"
            "Attack scenario: "
            "  1. Attacker controls an SCP source server "
            "  2. Root admin on TOS 4.6 does: scp attacker-server:/backdoor . "
            "     (no -p flag, running as root) "
            "  3. 'backdoor' lands on local FS with setuid root preserved "
            "  4. Any local user executes ./backdoor — escalates to root "
            "\n"
            "Also applies to automated scp transfers run as root in CI/CD, backup scripts, "
            "or deployment pipelines that download from external sources."
        ),
        "chain": (
            "TOS46-SRPM-F05: root runs scp from attacker-controlled server (no -p) → "
            "setuid binary lands with setuid bit preserved → "
            "local unprivileged user executes binary → privilege escalation to root"
        ),
        "references": [
            "CVE-2026-35385",
            "openssh-9.3p2-CVE-2026-35385.patch",
            "TOS46-SRPM-F02 — co-patched at -16 with CVE-2025-26465 and CVE-2026-35414",
        ],
    },
    "TOS46-SRPM-F06": {
        "title": (
            "NEW CVE-2026-35414: openssh Certificate Empty Principals List Accepted; "
            "Fail-Open: Cert with No Subject Restrictions Valid for Any User; "
            "OPEN in TOS 4.6 ISO and qcow2 (-15); FIXED at -16 (Jul 2026)"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-287",
        "component": "openssh-9.3p2-15.tl4 (TOS 4.6 ISO and qcow2) — OPEN",
        "description": (
            "CVE-2026-35414: when an SSH certificate has an empty principals list, "
            "OpenSSH should reject it (fail-closed) because no user restrictions are encoded. "
            "The unfixed behavior treats an empty principals list as valid for any user. "
            "\n"
            "SSH certificate principals field: restricts which usernames a certificate "
            "is valid for. Typical secure usage: cert issued with principals=['deploy-user'] "
            "is valid only for authentication as 'deploy-user'. "
            "\n"
            "Empty principals list (pre-fix): accepted, no restriction enforced. "
            "Attack: attacker obtains or generates a certificate signed by a trusted CA "
            "with an empty principals list → can authenticate as ANY user (including root) "
            "on any server that trusts the CA. "
            "\n"
            "Conditions for exploitability: "
            "  - Server uses certificate-based authentication (AuthorizedPrincipalsFile "
            "    or AuthorizedPrincipalsCommand configured) "
            "  - Attacker can obtain a certificate from the CA (e.g., CA compromised, "
            "    automated cert issuance without principals validation, insider) "
            "\n"
            "High severity: in environments using SSH CA infrastructure (common in "
            "cloud deployments with ssh-agent or HashiCorp Vault SSH secrets), "
            "this is a complete CA trust model bypass."
        ),
        "chain": (
            "TOS46-SRPM-F06: SSH CA infrastructure in use (Vault, AWS ssh-agent, custom CA) → "
            "attacker obtains certificate with empty principals (from compromised CA, "
            "broken issuance pipeline, or crafted cert) → "
            "CVE-2026-35414 fail-open accepts cert → "
            "attacker authenticates as root or target user → "
            "full system compromise"
        ),
        "remediation": (
            "Apply openssh-9.3p2-16 update. "
            "Interim: if using SSH CA, ensure CA never issues certs with empty principals. "
            "Add AuthorizedPrincipalsFile validation to reject certs without principals."
        ),
        "references": [
            "CVE-2026-35414",
            "openssh-9.3p2-CVE-2026-35414.patch",
            "TOS46-SRPM-F02 — co-patched at -16",
        ],
    },
    "TOS46-SRPM-F07": {
        "title": (
            "Tencent Uses DeepSeek V4 AI Agent (PkgAgent/deepseek-v4) to Adapt Security Patches; "
            "Attribution Embedded in Patch File Subject Headers; "
            "AI-Generated Security Patch Adaptation Introduces Risk of Subtle Errors or Incomplete Fixes"
        ),
        "severity": "MEDIUM",
        "cvss": "N/A",
        "cwe": "CWE-1059",
        "component": (
            "libssh-0.10.5-7.tl4 and openssh-9.3p2-16.tl4 patch files "
            "(Adapted-by: PkgAgent/deepseek-v4)"
        ),
        "description": (
            "Multiple TOS 4.6 SRPM patch files contain an attribution header: "
            "  'Adapted-by: PkgAgent/deepseek-v4 (modified to adapt to opencloudos-stream)' "
            "\n"
            "This indicates Tencent's packaging pipeline uses an AI agent backed by DeepSeek V4 "
            "to automatically adapt upstream security patches (from OpenBSD/RHEL) to the "
            "OpenCloudOS stream that TencentOS is built on. "
            "\n"
            "Observed instances: "
            "  libssh-0.10.5-7.tl4.src.rpm: CVE-2026-0964 patch adaptation "
            "  openssh-9.3p2-16.tl4.src.rpm: CVE-2025-26465, CVE-2026-35385, CVE-2026-35414 "
            "\n"
            "Security implications of AI-mediated patch adaptation: "
            "\n"
            "1. Incomplete fix application: AI adaptation may apply the patch to the wrong "
            "   code path or miss hunk context differences between the upstream and TOS fork, "
            "   leaving the vulnerability partially open while the patch file is present. "
            "\n"
            "2. Logic errors in adaptation: adapting a patch to a diverged codebase requires "
            "   understanding semantic context (not just text diff context). "
            "   AI may produce a syntactically valid patch that does not correctly "
            "   implement the security invariant of the original fix. "
            "\n"
            "3. Testing gap: AI-adapted patches may not have the same human review cycle "
            "   as manually adapted patches, reducing the probability of catching errors. "
            "\n"
            "4. Attribution transparency: downstream distributors relying on TencentOS SRPMs "
            "   (other OpenCloudOS-based distros) inherit the AI-adapted patches. "
            "\n"
            "This finding does NOT assert any specific AI-adaptation error in the patches "
            "identified — it flags the methodology as a class-of-risk that warrants "
            "binary-level verification of each AI-adapted patch's effectiveness, "
            "rather than assuming SRPM patch presence = complete fix."
        ),
        "verification_approach": (
            "For each CVE with AI-adapted patch: "
            "1. Extract the patch from the SRPM "
            "2. Verify the patched code path matches the upstream fix semantics "
            "3. Build test binary or use binary string search to confirm fix indicator "
            "4. Compare patched TOS binary behavior against known-patched reference binary "
            "\n"
            "Priority targets for verification: "
            "  CVE-2026-35414 (empty principals) — semantic logic change, high impact if wrong "
            "  CVE-2025-26465 (error code propagation) — multi-file change, easy to miss a path"
        ),
        "references": [
            "PkgAgent/deepseek-v4 — referenced in patch Subject headers",
            "OpenCloudOS stream — Tencent's RHEL-derived OS base",
            "TOS46-SRPM-F02, TOS46-SRPM-F05, TOS46-SRPM-F06 — findings using AI-adapted patches",
        ],
    },
}

CORRECTION_SUMMARY = {
    "TOS46-C01": {
        "original_finding": "libssh 0.10.5-6 Terrapin OPEN (27 months post-fix)",
        "correction": "FIXED — CVE-2023-48795.patch present in -6 SRPM; fixed at -4 (Aug 2024)",
        "still_open_at": ["0.10.5-3 (TOS 4.0, TOS 4.2)"],
    },
    "TOS33-F01": {
        "original_finding": "libssh 0.9.6-14 Terrapin OPEN (20 months post-fix)",
        "correction": "FIXED — kex-strict strings confirmed in binary (TOS 3.3 Aug 2025 qcow2)",
        "method": "Binary string analysis: strings libssh.so.4.8.7 | grep kex-strict",
    },
    "TOS33-F03": {
        "original_finding": "openssh 8.0p1-25 CVE-2023-38408 OPEN (below 8.9p1)",
        "correction": "FIXED — PKCS#11 whitelist (-P pkcs11_whitelist) confirmed in ssh-agent binary",
        "method": "Binary string analysis: strings ssh-agent | grep -E 'pkcs11|whitelist|refusing'",
    },
}


def get_findings():
    return FINDINGS


def get_corrections():
    return CORRECTION_SUMMARY


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "TOS 4.6 BaseOS-source SRPMs: libssh -3/-6/-7/-8, openssh -15/-16",
        "method": "rpm2cpio | cpio -idmv; patch file enumeration; spec changelog parsing",
        "patch_model": "Tencent freezes upstream version; CVE backports as release counter increments",
        "patch_agent": "PkgAgent/deepseek-v4 — AI-mediated patch adaptation to OpenCloudOS stream",
        "libssh_terrapin": "OPEN at -3 (TOS 4.0, 4.2); FIXED at -6 (TOS 4.4, 4.6 ISO)",
        "corrections": list(CORRECTION_SUMMARY.keys()),
        "new_2026_cves": ["CVE-2026-0964", "CVE-2026-59843", "CVE-2026-35385", "CVE-2026-35414"],
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
