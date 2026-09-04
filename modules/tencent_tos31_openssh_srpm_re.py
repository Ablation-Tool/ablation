"""
TencentOS Server 3.1 openssh SRPM RE Module
Source: /media/cowboy/research/tencentos/3.1/TencentOS-srpms/openssh-8.0p1-13.tl3.src.rpm
Method: rpm2cpio | cpio -idmv; patch file enumeration; spec changelog parsing
Analysis date: 2026-09-04

TOS 3.1 openssh SRPM inventory in TencentOS-srpms/:
  openssh-8.0p1-4.tl3.1.src.rpm
  openssh-8.0p1-4.tl3.2.src.rpm
  openssh-8.0p1-5.tl3.src.rpm
  openssh-8.0p1-13.tl3.src.rpm   <- highest counter available

Updates-srpms/ contains NO openssh package — security updates for openssh
were never published to the TOS 3.1 update channel. The -13 SRPM in the
base TencentOS-srpms set is the terminal version for TOS 3.1.

COMPARISON WITH TOS 3.3:
  TOS 3.1 max: openssh-8.0p1-13.tl3    (changelog: Oct 26 2021)
  TOS 3.3 launch: openssh-8.0p1-24     (Jun 2024)
  TOS 3.3 latest: openssh-8.0p1-25     (Aug 2024 - Aug 2025)

  Between -13 (Oct 2021) and -24 (Jun 2024), 11 counter increments occurred.
  Those increments added (confirmed via TOS 3.3 binary analysis):
    - CVE-2023-38408 PKCS#11 whitelist fix (-P pkcs11_whitelist flag)
    - CVE-2023-48795 Terrapin fix (kex-strict extension strings)
  Both absent from -13.

KEY FINDING: TOS 3.1 openssh is genuinely vulnerable to CVE-2023-38408.
TOS 3.3 has the fix backported. TOS 3.1 does not.
"""

OPENSSH_SRPM_INVENTORY_TOS31 = {
    "openssh-8.0p1-4.tl3.1": {"date": "~2019", "notes": "minor rebuild"},
    "openssh-8.0p1-4.tl3.2": {"date": "~2019", "notes": "minor rebuild"},
    "openssh-8.0p1-5.tl3":   {"date": "~2020", "notes": "rebuild"},
    "openssh-8.0p1-13.tl3":  {
        "date": "2021-10-26",
        "changelog_by": "Dmitry Belyavskiy <dbelyavs@redhat.com>",
        "changelog_entry": "ClientAliveCountMax=0 disable the connection killing behaviour (#2015828)",
        "terminal_version": True,
        "cvs_2023_38408_patch": False,
        "cvs_2023_48795_patch": False,
        "pkcs11_whitelist": False,
    },
}

OPENSSH_PATCH_AUDIT_13 = {
    "patches_present": [
        "openssh-8.0p1-cve-2020-14145.patch",
        "openssh-8.7p1-upstream-cve-2021-41617.patch",
        "openssh-8.0p1-pkcs11-uri.patch",
    ],
    "cve_2023_38408_patch": "ABSENT",
    "cve_2023_48795_patch": "ABSENT",
    "pkcs11_whitelist_flag": "ABSENT (no '-P pkcs11_whitelist' in spec or patches)",
    "latest_cve_in_set": "CVE-2021-41617 (privilege escalation)",
    "updates_srpms_openssh": "ABSENT (no openssh in Updates-srpms for TOS 3.1)",
}

COUNTER_DELTA_TOS31_TO_TOS33 = {
    "TOS31_max": "8.0p1-13.tl3 (Oct 2021)",
    "TOS33_launch": "8.0p1-24 (Jun 2024)",
    "counter_delta": 11,
    "elapsed_months": "~32 months",
    "patches_added_in_delta_confirmed_by_TOS33_binary": [
        "CVE-2023-38408 PKCS#11 whitelist (strings: '-P pkcs11_whitelist', 'refusing PKCS#11 provider ... not whitelisted')",
        "CVE-2023-48795 Terrapin kex-strict (strings: 'kex-strict-s-v00@openssh.com')",
        "Other fixes in CVE and stability categories (OpenSSL API updates, FIPS changes, etc.)",
    ],
    "note": (
        "TOS 3.3's -24 counter is not the continuation of TOS 3.1's -13. "
        "The counter could represent a fresh packaging baseline (RHEL 8.x aligned) "
        "or accumulated patches from a different upstream track. "
        "The key empirical fact: -13 is the last available in TOS 3.1 and lacks both fixes; "
        "-24/-25 in TOS 3.3 has both fixes confirmed via binary string analysis."
    ),
}

FINDINGS = {
    "TOS31-OPENSSH-F01": {
        "title": (
            "TOS 3.1 openssh 8.0p1-13 (Terminal Version) Predates CVE-2023-38408; "
            "PKCS#11 Whitelist Mechanism Absent — ssh-agent Agent Forwarding RCE Open; "
            "No openssh Update Path in TOS 3.1 Update Channel"
        ),
        "severity": "HIGH",
        "cvss": "9.8",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-20",
        "component": "openssh-8.0p1-13.tl3 (TOS 3.1 terminal version, Oct 2021)",
        "description": (
            "CVE-2023-38408 (Qualys, July 2023): Remote code execution in ssh-agent "
            "via untrusted PKCS#11 provider loading. Fix requires the PKCS#11 provider "
            "allowlist (-P pkcs11_whitelist) introduced in OpenSSH 8.9p1. "
            "\n"
            "TOS 3.1 status: "
            "  openssh-8.0p1-13.tl3 is the highest counter SRPM in TencentOS-srpms. "
            "  Changelog date: October 26, 2021 — 21 months before CVE-2023-38408 disclosure. "
            "  Patch audit: no CVE-2023-38408.patch, no pkcs11_whitelist implementation. "
            "  Updates-srpms: no openssh package — no update path in TOS 3.1 update channel. "
            "\n"
            "Contrast with TOS 3.3: "
            "  openssh-8.0p1-24/-25 (Jun 2024 - Aug 2025) HAS the whitelist backported. "
            "  Binary strings confirmed: 'refusing PKCS#11 provider ... not whitelisted' "
            "  present in TOS 3.3 Aug 2025 qcow2 ssh-agent binary. "
            "\n"
            "Attack: victim on TOS 3.1 uses 'ssh -A' (agent forwarding) to connect through "
            "or to an attacker-controlled server. Agent protocol requests the client's "
            "ssh-agent to load a malicious PKCS#11 provider library (.so), resulting in "
            "arbitrary code execution in the ssh-agent process on the victim's TOS 3.1 host. "
            "\n"
            "All keys stored in the agent (typically all user SSH keys) are accessible to "
            "the attacker post-exploitation."
        ),
        "chain": (
            "TOS31-OPENSSH-F01: TOS 3.1 host with ssh -A (agent forwarding) enabled → "
            "user connects to attacker-controlled SSH server → "
            "CVE-2023-38408: agent forwarding RCE via PKCS#11 library load → "
            "code execution in ssh-agent on TOS 3.1 host → "
            "all agent-stored private keys exfiltrated → "
            "lateral movement to all accessible servers"
        ),
        "remediation": (
            "Upgrade to TOS 3.3 or TOS 4.x. "
            "Interim: disable agent forwarding globally (ForwardAgent=no in /etc/ssh/ssh_config). "
            "No package update available in TOS 3.1 update channel."
        ),
        "references": [
            "CVE-2023-38408",
            "Qualys advisory QVA-2023-001",
            "TOS33-F03 CORRECTION (tencent_tos33_iso_sbom_re.py) — TOS 3.3 has the fix backported",
            "openssh 8.9p1 release notes (PKCS#11 allowlist introduced)",
        ],
    },
    "TOS31-OPENSSH-F02": {
        "title": (
            "TOS 3.1 openssh 8.0p1-13 Also Predates Terrapin (CVE-2023-48795); "
            "No kex-strict Extension in SRPM Patch Set; "
            "Both Terrapin and Agent RCE Open in Terminal TOS 3.1 openssh"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-354",
        "component": "openssh-8.0p1-13.tl3 (TOS 3.1 terminal version, Oct 2021)",
        "description": (
            "CVE-2023-48795 (Terrapin, Dec 2023): SSH handshake truncation via MitM. "
            "The fix introduces kex-strict extension negotiation strings. "
            "\n"
            "TOS 3.1 -13 patch audit: no CVE-2023-48795 patch. "
            "Changelog: Oct 2021 — 26 months before Terrapin disclosure. "
            "\n"
            "Contrast with TOS 3.3 binary (confirmed): "
            "  'kex-strict-s-v00@openssh.com' present in sshd binary "
            "  Both client and server strict kex extension implemented "
            "\n"
            "TOS 3.1 sshd and ssh client: Terrapin fix ABSENT. "
            "Combined with TOS 3.1 libssh 0.9.6-3 also being Terrapin-unfixed "
            "(no CVE-2023-48795 patch and counter -3 vs TOS 3.3's -14 which has the fix), "
            "TOS 3.1 has the full Terrapin exposure on both the openssh and libssh surfaces."
        ),
        "references": [
            "CVE-2023-48795",
            "TOS33-F01 CORRECTION (tencent_tos33_iso_sbom_re.py) — TOS 3.3 -14 has binary-confirmed fix",
            "TOS31-OPENSSH-F01 — same -13 terminal version",
        ],
    },
    "TOS31-OPENSSH-F03": {
        "title": (
            "TOS 3.1 Update Channel Has No openssh Security Updates; "
            "Updates-srpms Contains 0 openssh Packages; "
            "Any TOS 3.1 Installation That Has Not Upgraded to TOS 3.3/4.x "
            "Remains on 8.0p1-13 (Oct 2021) With No Patch Path"
        ),
        "severity": "MEDIUM",
        "cvss": "0.0",
        "cwe": "CWE-1104",
        "component": "openssh (TOS 3.1 update channel)",
        "description": (
            "The TOS 3.1 update channel (Updates-srpms) contains no openssh package. "
            "This was confirmed by: "
            "  1. Direct search: ls Updates-srpms/ | grep openssh — no results "
            "  2. Google Drive search in the folder: title contains 'openssh' — no results "
            "\n"
            "The only available openssh for TOS 3.1 is the base TencentOS-srpms set "
            "at openssh-8.0p1-13.tl3 (Oct 2021). "
            "\n"
            "Implication: Tencent did not publish openssh security updates for TOS 3.1 "
            "after October 2021. TOS 3.1 installations are expected to upgrade to TOS 3.3 "
            "or TOS 4.x to receive CVE-2023-38408 and CVE-2023-48795 patches. "
            "\n"
            "Any TOS 3.1 instance still running in production with openssh (sshd + clients) "
            "is unpatched for both CVEs without a full OS upgrade. "
            "A dnf update on TOS 3.1 will NOT bring in a fixed openssh."
        ),
        "references": [
            "TOS31-OPENSSH-F01 (CVE-2023-38408 open)",
            "TOS31-OPENSSH-F02 (CVE-2023-48795 open)",
        ],
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "openssh-8.0p1-13.tl3.src.rpm (TOS 3.1 TencentOS-srpms, terminal version)",
        "method": "rpm2cpio | cpio; patch file enumeration; spec changelog parsing",
        "changelog_date": "2021-10-26",
        "cve_2023_38408": "OPEN — no patch, no whitelist mechanism",
        "cve_2023_48795": "OPEN — no patch, no kex-strict",
        "update_channel": "NO openssh updates in Updates-srpms",
        "contrast_tos33": "TOS 3.3 -24/-25 has both fixes backported (binary confirmed)",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
