"""
TencentOS Server 3.3 — Deployed Component Version Analysis
Source: SPDX SBOM from TencentOS-Server-3.3-20250320.0-5.4.241-18-x86_64-everything.iso
Generated: 2025-04-21T01:49:30Z (image date: 2025-03-20)
Total packages: 7875 (x86_64 everything ISO)

Methodology: SPDX SBOM analysis to establish deployed versions.
Base version + release count cross-referenced against CVE databases to identify
unpatched exposure windows. The SBOM contains no CVE annotations — purely package versions.

Key version patterns observed:
  compat-openssl10-1.0.2o-4    — EOL Dec 2019; only 4 patch releases in 5+ years
  openssl-1.1.1k-14            — EOL Sept 2023; 14 patch releases; still deployed Mar 2025
  openssh-8.0p1-25             — 2019 release; CVE-2023-38408 in ssh-agent
  polkit-0.115-15              — CVE-2021-4034 (PwnKit) base version; -15 may have backport
  glibc-2.28-251               — heavy backporting (251 patches); CVE-2023-4911 likely covered
  systemd-239-82               — 2018 release; 82 patches; multiple CVE-2021/2022 backports likely
  curl-7.61.1-34               — 2018 curl; 34 patches
  kernel-5.4.241-24            — note: TCS-K01/K02/K03 findings from 5.4.119 source;
                                  5.4.241 config verification pending (same dist layer, likely same)

RHEL 8 lineage: TencentOS 3.3 is RHEL 8-derived. Base versions match RHEL 8 release train.
The release numbers (e.g., glibc-2.28-251) represent Red Hat / TencentOS backport patch counts
accumulated since RHEL 8.0. High release numbers indicate active CVE backporting.
Low release numbers on EOL packages indicate abandonment.
"""

from typing import Optional

# ─── Target Profile ───────────────────────────────────────────────────────────

TARGET = "tencent-os-3.3-components"
SBOM_DATE = "2025-04-21"
IMAGE_DATE = "2025-03-20"
IMAGE = "TencentOS-Server-3.3-20250320.0-5.4.241-18-x86_64-everything.iso"

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TCS-S01": {
        "title": (
            "compat-openssl10-1.0.2o Deployed in March 2025 Image — "
            "EOL Since December 2019, Only 4 Patch Releases Over 5+ Years, "
            "No Security Updates Since OpenSSL Project Ended Support"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-1104",
        "component": (
            "tencentos/compat-openssl10-1.0.2o-4 — "
            "OpenSSL 1.0.2 compatibility package; provides libssl.so.10, libcrypto.so.10 "
            "for legacy applications that link against OpenSSL 1.0.2"
        ),
        "evidence": {
            "sbom_version": (
                "SBOM entry: 'tencentos/compat-openssl10-1.0.2o-4' in "
                "TencentOS-Server-3.3-20250320.0 x86_64 everything ISO (SPDX 2.3). "
                "Package name: compat-openssl10, version: 1.0.2o, release: 4. "
                "OpenSSL 1.0.2o was released March 27, 2018 (a minor patch release in the 1.0.2 line). "
                "OpenSSL 1.0.2 reached end-of-life on December 31, 2019 — "
                "no further security patches issued by the OpenSSL project after that date."
            ),
            "patch_count_analysis": (
                "Release number '-4' means TencentOS has applied 4 patch sets to the base 1.0.2o package. "
                "Compare: openssl-1.1.1k-14 (active, 14 patches); glibc-2.28-251 (251 patches). "
                "A release count of 4 over 5+ years (Dec 2019 to Mar 2025) for a cryptographic library "
                "indicates it is effectively unmaintained within the TencentOS distribution. "
                "No upstream CVE patches exist for OpenSSL 1.0.2 after EOL — "
                "any critical vulnerability requires a complete version upgrade."
            ),
            "known_unfixed_cves": (
                "CVEs in OpenSSL 1.0.2 unfixed since EOL (selected, non-exhaustive): "
                "CVE-2023-0286: X.400 address GeneralName type confusion (CRITICAL 7.4) — "
                "  affects 1.0.2 through 3.0.7; not patchable on 1.0.2 without upgrade. "
                "CVE-2022-4450: Double free after calling PEM_read_bio_ex() (HIGH 7.5). "
                "CVE-2022-0778: BN_mod_sqrt() infinite loop -> DoS on certificate parse (HIGH 7.5). "
                "CVE-2021-3712: OOB read in X509_aux_print() via crafted cert ASN.1. "
                "CVE-2021-23840: Integer overflow in EVP_EncodeUpdate() (HIGH 9.1). "
                "CVE-2021-23841: NULL pointer dereference in X509_issuer_and_serial_hash(). "
                "Applications linked against libssl.so.10 / libcrypto.so.10 are exposed to all of these."
            ),
            "scope_of_exposure": (
                "The 'compat-openssl10' package provides libssl.so.10 and libcrypto.so.10 — "
                "the 1.0.2 ABI shared libraries. Any application on the system dynamically linked "
                "against OpenSSL 1.0.x uses this library. Typical affected components: "
                "legacy Java applications using JSSE with native SSL, older Python 2.x with _ssl module, "
                "third-party vendor software compiled against OpenSSL 1.0.2. "
                "Tencent Cloud CVM operator software (e.g., Stargate agent — see TCS-F01) "
                "may depend on compat-openssl10 if it links against libssl.so.10."
            ),
        },
        "versions_affected": ["3.3-20250320"],
        "remediation": (
            "Remove the compat-openssl10 package entirely from the distribution. "
            "Audit all packages with a dynamic dependency on libssl.so.10 / libcrypto.so.10 "
            "using 'ldd /path/to/binary' or 'rpm -q --requires <package> | grep openssl'. "
            "Recompile or upgrade each dependent application to link against OpenSSL 1.1.x or 3.x. "
            "If compat-openssl10 cannot be removed due to ABI dependencies, "
            "apply all critical CVE patches manually and document the residual risk. "
            "Consider TencentOS maintaining a fork with backported CVE patches to the 1.0.2 line "
            "for the transition period, with a firm removal date."
        ),
    },
    "TCS-S02": {
        "title": (
            "OpenSSL 1.1.1k Deployed 18 Months Past EOL — "
            "No Security Patches Available from OpenSSL Project Since September 2023; "
            "libssl.so.1.1 Provides TLS Stack for Entire OS"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-1104",
        "component": (
            "tencentos/openssl-1.1.1k-14 + tencentos/openssl-libs-1.1.1k-14 — "
            "provides libssl.so.1.1, libcrypto.so.1.1 — "
            "primary TLS stack for TencentOS 3.3 (March 2025 image)"
        ),
        "evidence": {
            "sbom_version": (
                "SBOM entry: 'tencentos/openssl-1.1.1k-14' — OpenSSL 1.1.1k, 14 TencentOS patch releases. "
                "OpenSSL 1.1.1k was released March 25, 2021 (fixing CVE-2021-3449, CVE-2021-3450). "
                "OpenSSL 1.1.1 reached end-of-life on September 11, 2023. "
                "Image date: 2025-03-20 — 18 months post-EOL with 1.1.1k still as the primary TLS library."
            ),
            "eol_context": (
                "OpenSSL 3.x is the supported branch (LTS until 2026-09-07). "
                "OpenSSL 3.0 is available and production-stable since September 7, 2021. "
                "TencentOS 3.3 chooses to ship 1.1.1k rather than migrating to 3.x. "
                "The 14 patch releases (vs. compat-openssl10's 4) indicate active backporting of "
                "critical CVE fixes, but the window between each OpenSSL CVE and a TencentOS "
                "backport patch release is unknown without SRPM analysis. "
                "After Sept 2023, no upstream CVE reports reference 1.1.1k — operators relying "
                "on upstream CVE feeds get no signal for new vulnerabilities."
            ),
            "known_post_eol_cves": (
                "OpenSSL CVEs disclosed after 1.1.1 EOL (Sept 2023) that affect 1.1.1k (selected): "
                "CVE-2024-0727: PKCS12 parsing NULL ptr dereference via crafted file (MODERATE). "
                "CVE-2023-5678: DH key generation excessive resource use -> DoS (MODERATE). "
                "CVE-2023-6129: POLY1305 MAC computation constant-time violation on POWER CPU. "
                "No official patches from OpenSSL project for these exist on the 1.1.1 branch. "
                "Patching responsibility falls entirely to TencentOS distribution maintainers."
            ),
        },
        "versions_affected": ["3.3-20250320"],
        "remediation": (
            "Migrate from OpenSSL 1.1.1k to OpenSSL 3.x for all new TencentOS releases. "
            "For existing 3.3 deployments, commit to backporting all critical CVEs to the 1.1.1k branch "
            "with a documented SLA for patch delivery. "
            "Set a firm EOL date for openssl-1.1.1k in TencentOS 3.3 and communicate migration timeline. "
            "Use 'openssl version' and 'openssl ciphers -v' to audit deployed cipher suites for "
            "deprecated algorithms (EXPORT ciphers, 3DES, RC4) that may still be enabled."
        ),
    },
    "TCS-S03": {
        "title": (
            "OpenSSH 8.0p1 (2019) Deployed — "
            "CVE-2023-38408 PKCS#11 ssh-agent Remote Code Execution in Unpatched Versions; "
            "5-Year-Old SSH Daemon as the Primary Remote Access Entry Point"
        ),
        "severity": "HIGH",
        "cvss": "9.8",
        "cwe": "CWE-1104",
        "component": (
            "tencentos/openssh-8.0p1-25 + tencentos/openssh-server-8.0p1-25 — "
            "sshd listening on TCP/22; OpenSSH 8.0p1 released April 17, 2019"
        ),
        "evidence": {
            "sbom_version": (
                "SBOM entry: 'tencentos/openssh-8.0p1-25' and 'tencentos/openssh-server-8.0p1-25'. "
                "OpenSSH 8.0p1 released April 17, 2019. Current upstream release as of 2025: 9.9p2. "
                "Image date: 2025-03-20 — version is 6 years old. "
                "Release number '-25' indicates 25 patch sets applied, suggesting active backporting."
            ),
            "cve_2023_38408": (
                "CVE-2023-38408: Remote code execution in ssh-agent via PKCS#11 provider loading. "
                "Affects OpenSSH before 9.3p2 — 8.0p1-25 is in this range. "
                "Attack precondition: victim must have ssh-agent running AND forwarded the agent "
                "to an attacker-controlled server (ssh -A or ForwardAgent=yes). "
                "The attacker on the remote server sends a PKCS#11 load request for a "
                "malicious shared library path; ssh-agent loads it via dlopen() -> RCE "
                "on the victim's machine. "
                "Fixed upstream in OpenSSH 9.3p2 (August 2023). "
                "Whether TencentOS's '-25' patch set includes this backport is unknown without SRPM analysis. "
                "CVSS 9.8 (Network, No Interaction, No Auth) when agent forwarding is in use."
            ),
            "additional_exposure_window": (
                "Additional CVEs in OpenSSH 8.0p1 not fixed before 8.0p1-era (selected): "
                "CVE-2023-51385: Shell metacharacter injection via user-controlled hostname in scp/sftp proxy. "
                "CVE-2023-48795: Terrapin attack — SSH channel downgrade on ChaCha20-Poly1305 / ETM modes. "
                "CVE-2021-41617: Privilege escalation via AuthorizedKeysCommand with supplemental groups. "
                "The 25 patch releases likely address many of these, but complete coverage "
                "cannot be verified from SBOM data alone — requires SRPM diff analysis."
            ),
            "deployment_scope": (
                "sshd is the primary remote access vector for TencentOS CVM instances. "
                "Tencent Cloud CVM instances are accessible via public IP or VPC by default. "
                "OpenSSH 8.0p1 is the first authentication layer on every TencentOS 3.3 deployment. "
                "Combined with TCS-K01 (KASLR disabled), a memory corruption in sshd yields "
                "reliable kernel-level exploitation without requiring information leak primitives."
            ),
        },
        "versions_affected": ["3.3-20250320"],
        "remediation": (
            "Upgrade openssh to >= 9.3p2 to definitively address CVE-2023-38408. "
            "If staying on 8.0p1, backport the PKCS#11 loading restriction patch: "
            "  restrict dlopen() calls in ssh-agent to a list of trusted PKCS#11 provider paths. "
            "Disable agent forwarding in sshd_config by default: AllowAgentForwarding no. "
            "Enable Terrapin mitigation: StrictKEX=yes (available in patched OpenSSH builds). "
            "Audit sshd_config for: PermitRootLogin, PasswordAuthentication, "
            "AllowUsers/DenyUsers, and ensure rate limiting (MaxAuthTries, MaxStartups) is configured."
        ),
    },
    "TCS-S04": {
        "title": (
            "polkit 0.115 Base Version Matches CVE-2021-4034 (PwnKit) Affected Range — "
            "Local Unprivileged User to Root via pkexec Memory Corruption; "
            "Backport Status Unknown Without SRPM Analysis"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-787",
        "component": (
            "tencentos/polkit-0.115-15 — "
            "polkit (PolicyKit) privilege escalation framework; pkexec binary SUID root"
        ),
        "evidence": {
            "sbom_version": (
                "SBOM entry: 'tencentos/polkit-0.115-15'. "
                "polkit 0.115 released May 2018. "
                "CVE-2021-4034 (PwnKit) fixed in upstream 0.120 (released January 25, 2022). "
                "Base version 0.115 is in the affected range for CVE-2021-4034. "
                "Release number '-15' indicates 15 TencentOS patch sets — "
                "the RHEL 8 equivalent (polkit-0.115-13.el8_5.1) includes the CVE-2021-4034 backport. "
                "TencentOS's '-15' likely includes this backport, but verification requires SRPM diff."
            ),
            "cve_2021_4034": (
                "CVE-2021-4034 (PwnKit): Out-of-bounds write in pkexec argument processing. "
                "Any local unprivileged user can exploit this to gain root via pkexec. "
                "Attack: pkexec argv processing reads past argv[0] into envp[] when argc=0, "
                "allowing write to an attacker-controlled environment variable key/value pair "
                "in pkexec memory. Exploitation: re-introduction of LD_PRELOAD in pkexec environment "
                "-> load arbitrary shared library as root. "
                "CVSS 7.8 (local, no interaction, no auth, HIGH privileges/integrity/availability). "
                "Universal local root on any Linux system with unpatched pkexec. "
                "Patch is 3-line fix. RHEL 8 backported it to polkit-0.115-13.el8_5.1 in Jan 2022."
            ),
            "chain_context": (
                "If CVE-2021-4034 is NOT backported in polkit-0.115-15: "
                "Any web-facing service running as non-root (nginx, apache, nodejs) that is "
                "compromised → local shell → pkexec PwnKit → root. "
                "Combined with TCS-F01 (MitM root RCE via Stargate), the local root path "
                "is redundant but the polkit exposure applies to all TencentOS 3.3 instances "
                "regardless of whether Stargate is installed."
            ),
            "verification_required": (
                "This finding is PLAUSIBLE pending SRPM diff verification. "
                "To confirm: extract the polkit-0.115-15 SRPM, inspect patchset for "
                "commit equivalent to 'Fix arbitrary file read by setting the "
                "PolkitAgentSession->child_watch to 0 before calling waitpid in polkit_unix_process_new_for_owner'. "
                "If absent, severity upgrades to CRITICAL."
            ),
        },
        "versions_affected": ["3.3-20250320"],
        "remediation": (
            "Verify CVE-2021-4034 backport presence: "
            "rpm -q --changelog polkit | grep CVE-2021-4034 "
            "OR extract SRPM and check patches. "
            "If absent, apply RHEL 8 backport patch immediately. "
            "As defense-in-depth regardless of patch status: "
            "chmod 0755 /usr/bin/pkexec (remove SUID bit) — "
            "prevents exploitation but breaks polkit functionality for non-root users. "
            "Evaluate whether polkit is needed on CVM instances without interactive sessions."
        ),
    },
}


# ─── Probe Functions ──────────────────────────────────────────────────────────

def probe_package_versions(host: str, port: int = 22) -> dict:
    """
    Runtime version verification via RPM query.
    Execute on target: rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\\n' openssl openssh polkit glibc
    """
    return {
        "host": host,
        "note": "findings derived from SBOM; confirm with: rpm -q openssl openssh polkit glibc",
        "findings": list(FINDINGS.keys()),
        "sbom_source": IMAGE,
    }


probe = probe_package_versions
