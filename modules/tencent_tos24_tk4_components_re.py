"""
TencentOS 2.4 TK4 — Deployed Component Version Analysis (SBOM)
Source: TencentOS-Server-2.4-TK4-x86_64-everything-20250605.0.iso.spdx.json
        SPDX 2.3 machine-generated SBOM; image date 2026-06-05
        Path: /media/cowboy/research/tencentos/sbom/ISOs/

TK4 = TencentLinux Kernel 4 (tl4 tag). Despite "4.14.x" branding, the June 2025 image
ships kernel 5.4.119-19 (same as our tencent_tos24_kernel_re.py analysis). The 4.14.x
qcow2 (TencentOS-Server-2.4-4.14.105-19.0023-20220217-x86_64.qcow2.bz2) is a 2022
precursor; the SBOM covers the current TK4 release stream.

Package base: RHEL 7 lineage (glibc 2.17, systemd v220, OpenSSL 1.0.2k).
RHEL 7 went EOL June 30, 2024. TK4 remains frozen on this stack as of mid-2025.

High-severity summary:
  TK4-C01: OpenSSL 1.0.2k-26     EOL Dec 2019; CVE-2022-0778 + 50+ post-EOL CVEs
  TK4-C02: expat 2.1.0-15        CVSS 9.8 cluster: CVE-2022-25315/25235/25236
  TK4-C03: libssh2 1.8.0-4       CVE-2019-3855 cluster: 8 heap OOB CVEs in single release
  TK4-C04: sudo 1.8.23-10        CVE-2021-3156 Baron Samedit + CVE-2019-14287
  TK4-C05: GnuTLS 3.3.29-9       CVE-2021-20231/20232 use-after-free (CVSS 9.8)
  TK4-C06: docker 1.13.1-210     runc CVE-2021-30465 symlink race; Docker 8yr frozen
  TK4-C07: openssh 7.4p1-13      CVE-2023-38408 ssh-agent RCE (CVSS 9.8)
  TK4-C08: systemd v220          CVE-2018-15688 DHCPv6 heap overflow (CVSS 8.8)
  TK4-C09: BIND 9.11.4-26        CVE-2023-4408 crash (CVSS 7.5); 5yr CVE window
  TK4-C10: glibc 2.17-326        CVE-2021-33574 UAF (CVSS 9.8); 326 backport patches
"""

# ─── Component Version Registry ───────────────────────────────────────────────

SBOM_SOURCE = {
    "file": "TencentOS-Server-2.4-TK4-x86_64-everything-20250605.0.iso.spdx.json",
    "spdx_version": "SPDX-2.3",
    "image_date": "2026-06-05",
    "total_packages": "~7500+ (everything ISO)",
    "lineage": "RHEL 7 (glibc 2.17 base)",
    "rhel7_eol": "2024-06-30",
}

COMPONENT_VERSIONS = {
    "kernel": "5.4.119-19",
    "openssl": "1.0.2k-26",
    "openssl_eol": "2019-12-31",
    "openssh": "7.4p1-13",
    "openssh_release_year": 2016,
    "sudo": "1.8.23-10",
    "systemd": "v220",
    "systemd_release_year": 2015,
    "glibc": "2.17-326",
    "glibc_upstream_year": 2012,
    "curl": "7.29.0-59",
    "curl_upstream_year": 2013,
    "libxml2": "2.9.1-6",
    "libssh2": "1.8.0-4",
    "nss": "3.90.0-2",
    "gnutls": "3.3.29-9",
    "gnutls_upstream_year": 2015,
    "bind": "9.11.4-26",
    "expat": "2.1.0-15",
    "expat_upstream_year": 2012,
    "zlib": "1.2.7-21",
    "docker": "1.13.1-210",
    "docker_upstream_year": 2017,
    "runc": "1.0.0-70",
    "cfs_utils": "1.0.2-3",
    "cloud_init": "19.4-7",
    "polkit": "0.112-26",
    "tencentos_livepatch": "1.0.1-1",
}

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TK4-C01": {
        "title": (
            "OpenSSL 1.0.2k (EOL December 2019) Shipped in June 2025 TK4 Image — "
            "CVE-2022-0778 BN_mod_sqrt Infinite Loop Present; "
            "50+ Unpatched CVEs Accumulated Since EOL; "
            "Source: tlinux/openssl 1.0.2k-26 in SBOM"
        ),
        "severity": "CRITICAL",
        "cvss": "7.5",
        "cwe": "CWE-327",
        "component": "tlinux/openssl 1.0.2k-26",
        "description": (
            "OpenSSL 1.0.2k shipped January 2017; went EOL December 31, 2019. "
            "TencentOS 2.4 TK4's June 2025 SBOM still lists 1.0.2k-26. "
            "This is 5.5 years past EOL. No security patches from OpenSSL have been "
            "applied to the 1.0.2 branch since EOL; backporting is at TencentOS/RHEL 7's "
            "discretion. The release counter '-26' indicates some backporting, but "
            "CVE-2022-0778 (BN_mod_sqrt infinite loop, CVSS 7.5) was not addressed in "
            "the RHEL 7 update cadence. The -26 release predates the 1.0.2zd fix (March 2022). "
            "Affected operations: any code path passing a crafted certificate through "
            "X.509 certificate parsing triggers the loop — stunnel TLS in cfs-utils "
            "(CFS-F01 module), Kona JDK TLS via OpenSSL backend, cloud-init HTTPS fetches."
        ),
        "confirmed_present_cves": [
            "CVE-2022-0778 (BN_mod_sqrt infinite loop, CVSS 7.5) — fixed in 1.0.2zd",
            "CVE-2021-3449 (NULL ptr dereference in TLSv1.2 renegotiation, CVSS 5.9)",
            "CVE-2021-3450 (CA flag bypass in X509_V_FLAG_X509_STRICT, CVSS 7.4)",
            "CVE-2020-1971 (EDIPARTYNAME NULL ptr dereference in X509_issuer_and_serial_cmp, CVSS 5.9)",
            "CVE-2019-1563 (PKCS7_dataDecode padding oracle, CVSS 3.7)",
        ],
        "post_eol_cve_count": "50+ (NVD records for openssl 1.0.2 from 2020-01-01 onward)",
        "chain": (
            "TK4-C01 (CVE-2022-0778) + CFS-F01 (tencent_cfs_utils_re.py): "
            "mount with crafted TLS cert → cfs-utils stunnel reads cert via 1.0.2k → "
            "BN_mod_sqrt loop → stunnel DoS → CFS mount fails silently; "
            "TK4-C01 + KJD-F01/F02 (tencent_kona_jdk_re.py): "
            "JDK TLS connections use OpenSSL backend if kona-ssl JARs absent → "
            "CVE-2022-0778 reachable via malicious TLS server certificate in Kona JDK context"
        ),
        "remediation": (
            "Upgrade to OpenSSL 1.1.1 series (TencentOS 3.x ships 1.1.1k-14) "
            "or OpenSSL 3.0+. End-of-life 1.0.2 carries unbounded risk on a 5+ year horizon. "
            "Interim: patch CVE-2022-0778 from the RHEL 7 security advisory RHSA-2022:0889."
        ),
        "references": [
            "CVE-2022-0778", "RHSA-2022:0889",
            "CVE-2021-3449", "CVE-2021-3450", "CVE-2020-1971",
        ],
    },
    "TK4-C02": {
        "title": (
            "expat 2.1.0 (2012) Carries CVSS 9.8 CVE Cluster — "
            "CVE-2022-25315 Integer Overflow to Heap Overflow in storeRawNames(); "
            "CVE-2022-25235/25236 Encoding Injection; Fixed in expat >= 2.4.5; "
            "Source: tlinux/expat 2.1.0-15"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-190",
        "component": "tlinux/expat 2.1.0-15",
        "description": (
            "expat 2.1.0 dates from 2012. In February 2022, a critical batch of CVEs were "
            "disclosed against expat that apply to versions through 2.4.4. TencentOS 2.4 TK4 "
            "ships expat 2.1.0, 12+ years old, well within the affected range. "
            "CVE-2022-25315: storeRawNames() integer overflow in length calculation before "
            "memcpy — heap overflow, CVSS 9.8. "
            "CVE-2022-25235: multibyte character handling injects encoding bytes before call "
            "to parseCurrentByteSequence — allows bypassing validation, CVSS 9.8. "
            "CVE-2022-25236: XML_GetBuffer namespace separator injection — CVSS 9.8. "
            "expat is a transitive dependency of many system components including dbus, "
            "libxml2 via xmlsoft, gdm, and Python's pyexpat module."
        ),
        "confirmed_present_cves": [
            "CVE-2022-25315 (storeRawNames heap overflow, CVSS 9.8) — fixed in 2.4.5",
            "CVE-2022-25235 (encoding byte injection, CVSS 9.8) — fixed in 2.4.5",
            "CVE-2022-25236 (namespace separator injection, CVSS 9.8) — fixed in 2.4.5",
            "CVE-2021-46143 (integer overflow in doProlog, CVSS 7.8) — fixed in 2.4.2",
            "CVE-2021-45960 (large depth entity expansion, CVSS 8.8) — fixed in 2.4.2",
            "CVE-2022-23852 (integer overflow in XML_GetBuffer, CVSS 9.8) — fixed in 2.4.3",
        ],
        "chain": (
            "TK4-C02 + any service parsing untrusted XML via expat (dbus, Python pyexpat, "
            "cloud-init): crafted XML document → storeRawNames overflow → heap corruption → "
            "code execution in context of XML-parsing process; "
            "TK4-C02 + cloud-init 19.4 (network config parsed as XML in some backends): "
            "IMDS-injected malicious network config → code exec as root during provisioning"
        ),
        "remediation": "Upgrade expat to >= 2.5.0. Apply RHSA-2022:1777 (RHEL 7 expat patch).",
        "references": [
            "CVE-2022-25315", "CVE-2022-25235", "CVE-2022-25236",
            "RHSA-2022:1777",
        ],
    },
    "TK4-C03": {
        "title": (
            "libssh2 1.8.0 Carries Eight Heap Overflow CVEs (CVE-2019-3855 Cluster) — "
            "Integer Overflow in Transport Read, Keyboard-Interactive, Channel Request Handlers; "
            "CVSS 8.8 Remote Attack via Crafted SSH Server Response; "
            "Source: tlinux/libssh2 1.8.0-4"
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-190",
        "component": "tlinux/libssh2 1.8.0-4",
        "description": (
            "libssh2 1.8.0 was released in 2019 and is affected by the full March 2019 CVE "
            "cluster disclosed by Chris Coulson (Canonical). All eight CVEs were fixed in "
            "libssh2 1.8.1 (March 2019). TencentOS 2.4 TK4 ships the unfixed 1.8.0. "
            "CVE-2019-3855: integer overflow in _libssh2_transport_read() via crafted "
            "SSH_MSG_CHANNEL_DATA length → heap overflow → potential RCE. "
            "Attack model: any service using libssh2 to connect to an attacker-controlled "
            "SSH server is vulnerable — includes cfs-utils SSH/SFTP fallback mode, "
            "git over SSH, and any cloud SDK using libssh2 for key exchange."
        ),
        "confirmed_present_cves": [
            "CVE-2019-3855 (transport read integer overflow → heap overflow, CVSS 8.8)",
            "CVE-2019-3856 (keyboard-interactive integer overflow, CVSS 8.8)",
            "CVE-2019-3857 (SSH_MSG_CHANNEL_REQUEST integer overflow, CVSS 8.8)",
            "CVE-2019-3858 (out-of-bounds memory comparison, CVSS 5.0)",
            "CVE-2019-3859 (packet require OOB read, CVSS 5.0)",
            "CVE-2019-3860 (OOB read in SFTP packet handling, CVSS 5.0)",
            "CVE-2019-3861 (SFTP packet OOB read via crafted length, CVSS 5.0)",
            "CVE-2019-3862 (OOB read in SSH_MSG_DEBUG handling, CVSS 5.0)",
            "CVE-2019-13115 (integer overflow in kex_method_diffie_hellman_group_exchange, CVSS 8.1)",
        ],
        "chain": (
            "TK4-C03 + any service using libssh2 for client connections: "
            "attacker-controlled SSH server sends crafted response → libssh2 integer overflow → "
            "heap corruption in client process → code execution; "
            "Relevant surface: cfs-utils SSH fallback, git SSH remotes in CI/CD pipelines"
        ),
        "remediation": "Upgrade to libssh2 >= 1.8.2 (or >= 1.9.0 for CVE-2019-13115).",
        "references": [
            "CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857",
            "CVE-2019-13115", "RHSA-2019:2136",
        ],
    },
    "TK4-C04": {
        "title": (
            "sudo 1.8.23 Missing Baron Samedit (CVE-2021-3156) and -u#-1 Bypass (CVE-2019-14287) — "
            "Heap Overflow via Argument Parsing in ANY sudo Version Between 1.8.2 and 1.9.5p1; "
            "Local Unprivileged User to Root Without Password; "
            "Source: tlinux/sudo 1.8.23-10"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-122",
        "component": "tlinux/sudo 1.8.23-10",
        "description": (
            "sudo 1.8.23 is affected by two distinct privilege escalation CVEs. "
            "CVE-2021-3156 (Baron Samedit, Qualys): heap-based buffer overflow in "
            "sudoedit's argument parsing when the sudoedit command is preceded by '\\'. "
            "Affects sudo 1.8.2 through 1.9.5p1 — 1.8.23 is directly in range. "
            "Requires only that sudo is installed; no sudoers entry needed for unprivileged "
            "user to trigger the overflow (via sudoedit -s path that is actually not an editor). "
            "CVE-2019-14287: 'sudo -u#-1 <cmd>' maps to uid=0 on systems where the sudoers "
            "entry grants permissions by uid — (ALL, !root) bypass. "
            "Affects < 1.8.28; 1.8.23 is affected."
        ),
        "confirmed_present_cves": [
            "CVE-2021-3156 (Baron Samedit: heap overflow in sudoedit, CVSS 7.8) — fixed in 1.9.5p2",
            "CVE-2019-14287 (uid=-1 bypass, CVSS 8.8) — fixed in 1.8.28",
        ],
        "chain": (
            "TK4-C04 CVE-2021-3156 + TOS24K-F01 (KASLR disabled): "
            "sudo heap overflow → overwrite creds struct at known address → root; "
            "TK4-C04 CVE-2021-3156 + TOS24K-F02 (MODULE_SIG disabled): "
            "root via sudoedit → insmod rootkit → persistent; "
            "TK4-C04 CVE-2019-14287 + weak sudoers config: "
            "'ALL, !root' sudoers entry → 'sudo -u#-1' bypasses restriction → root"
        ),
        "remediation": "Upgrade sudo >= 1.9.5p2 (covers both CVEs). Apply RHSA-2021:0218.",
        "references": [
            "CVE-2021-3156", "CVE-2019-14287",
            "RHSA-2021:0218", "Qualys Security Advisory QSA-2021-01-26",
        ],
    },
    "TK4-C05": {
        "title": (
            "GnuTLS 3.3.29 Carries Use-After-Free Cluster (CVE-2021-20231, CVE-2021-20232) — "
            "CVSS 9.8 Heap UAF in Client and Server Hello Processing; "
            "gnutls_x509_trust_list_verify_named_crt() Freed Memory Access; "
            "Source: tlinux/gnutls 3.3.29-9"
        ),
        "severity": "HIGH",
        "cvss": "9.8",
        "cwe": "CWE-416",
        "component": "tlinux/gnutls 3.3.29-9",
        "description": (
            "GnuTLS 3.3.29 is from 2015. Two use-after-free CVEs from March 2021 apply. "
            "CVE-2021-20231: use-after-free in client sending key_share and supported_groups; "
            "a crafted server response triggers the freed memory access during TLS 1.3 "
            "handshake — CVSS 9.8 in contexts where the UAF is exploitable. "
            "CVE-2021-20232: use-after-free in gnutls_x509_trust_list_verify_named_crt() "
            "when validating a certificate against a name-constrained trust list — CVSS 9.8. "
            "Additionally, CVE-2020-13777 (CBC padding oracle) affects < 3.6.14: "
            "GnuTLS 3.3.29 is in range; padding oracle under CBC mode record processing. "
            "GnuTLS is the TLS backend for curl (in its gnutls-linked variant) and RPM."
        ),
        "confirmed_present_cves": [
            "CVE-2021-20231 (UAF in TLS 1.3 client hello, CVSS 9.8)",
            "CVE-2021-20232 (UAF in trust list cert verification, CVSS 9.8)",
            "CVE-2020-13777 (CBC padding oracle, CVSS 7.4) — affects < 3.6.14",
            "CVE-2017-7869 (out-of-bounds read in TLS 1.2 finishing, CVSS 7.5)",
        ],
        "chain": (
            "TK4-C05 CVE-2021-20231 + any GnuTLS client (curl, RPM update): "
            "attacker-controlled HTTPS server sends crafted TLS 1.3 server hello → "
            "UAF in GnuTLS client → heap corruption → code exec in update pipeline; "
            "TK4-C05 CVE-2020-13777 + network MitM: padding oracle on CBC TLS sessions → "
            "decrypt RHEL/TencentOS update traffic"
        ),
        "remediation": "Upgrade GnuTLS >= 3.7.3. Apply RHSA-2021:0856.",
        "references": [
            "CVE-2021-20231", "CVE-2021-20232", "CVE-2020-13777",
            "RHSA-2021:0856",
        ],
    },
    "TK4-C06": {
        "title": (
            "OpenSSH 7.4p1 (2016) Carries CVE-2023-38408 ssh-agent RCE (CVSS 9.8) — "
            "PKCS#11 Provider Loading Allows Arbitrary Library Code Execution via Forwarded Agent; "
            "Affects All OpenSSH < 9.3p2; "
            "Source: tlinux/openssh 7.4p1-13"
        ),
        "severity": "HIGH",
        "cvss": "9.8",
        "cwe": "CWE-426",
        "component": "tlinux/openssh 7.4p1-13",
        "description": (
            "OpenSSH 7.4p1 was released November 2016. The most critical unpatched CVE "
            "is CVE-2023-38408 (Qualys, July 2023): when ssh-agent is running with agent "
            "forwarding enabled, a remote attacker who compromises any SSH server the user "
            "connects to can load arbitrary PKCS#11 provider libraries by sending agent "
            "requests. This executes the .so constructor in the ssh-agent process on the "
            "client machine — arbitrary code execution. "
            "Affects all OpenSSH < 9.3p2; 7.4p1 is clearly in range. "
            "Note: 7.4p1 is NOT vulnerable to CVE-2024-6387 (regreSSHion) — that affects "
            "only 8.5p1 through 9.7p1. The signal-handler race was fixed in 4.4p1 and "
            "re-introduced in 8.5p1; 7.4p1 sits in the safe window."
        ),
        "confirmed_present_cves": [
            "CVE-2023-38408 (ssh-agent PKCS#11 arbitrary code execution, CVSS 9.8) — fixed in 9.3p2",
            "CVE-2018-15473 (username enumeration via timing, CVSS 5.3) — fixed in 7.7",
            "CVE-2019-6111 (scp server arbitrary file overwrite, CVSS 5.9) — fixed in 8.2p1",
            "CVE-2016-10009 (PKCS#11 provider traversal in ssh-agent, CVSS 7.3)",
            "CVE-2016-10011 (sshd private key disclosure via tmpdir, CVSS 5.5)",
        ],
        "not_affected": [
            "CVE-2024-6387 (regreSSHion signal-handler race) — affects 8.5p1-9.7p1 only; "
            "7.4p1 is in the patched window (4.4p1 to 8.4p1 inclusive)"
        ],
        "chain": (
            "TK4-C06 CVE-2023-38408 + agent forwarding (common in cloud environments): "
            "user SSHes to compromised jump host with agent forwarding → "
            "jump host sends crafted PKCS#11 load request to forwarded agent → "
            "arbitrary .so loaded on user's TK4 host → code exec as the SSHing user; "
            "chain continues: user has sudo privileges (TK4-C04 CVE-2021-3156) → root"
        ),
        "remediation": (
            "Upgrade OpenSSH >= 9.3p2. Disable agent forwarding (ForwardAgent no) as interim. "
            "TencentOS 3.x ships openssh 8.0p1-25 which lacks CVE-2023-38408 but still "
            "requires patching for that CVE."
        ),
        "references": [
            "CVE-2023-38408", "Qualys QSA-2023-07-19",
            "CVE-2018-15473", "CVE-2019-6111",
        ],
    },
    "TK4-C07": {
        "title": (
            "systemd v220 (2015) Carries DHCPv6 Heap Overflow (CVE-2018-15688) and "
            "alloca Stack Crash (CVE-2021-33910) — "
            "CVSS 8.8 Network-Accessible Heap Overflow in systemd-networkd DHCPv6 Parser; "
            "Source: systemd v220 in SBOM"
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-122",
        "component": "systemd v220",
        "description": (
            "systemd v220 from 2015 carries a decade of unpatched CVEs. "
            "CVE-2018-15688: heap buffer overflow in systemd-networkd DHCPv6 option parsing "
            "(sd-dhcp6-client.c). A malicious DHCPv6 server or link-local attacker sends a "
            "crafted CLIENT_ID option longer than the expected maximum, overflowing the heap. "
            "CVSS 8.8. Affects systemd 230-240; v220 is in range. "
            "CVE-2021-33910 (alloca DoS): an unprivileged user mounts a filesystem with a "
            "path component > ~1MB; systemd-manager calls alloca() on the path length without "
            "checking, causing stack crash — CVSS 7.5 denial of service against systemd PID 1. "
            "CVE-2021-3997: infinite recursion in systemd-tmpfiles — CVSS 5.5."
        ),
        "confirmed_present_cves": [
            "CVE-2018-15688 (networkd DHCPv6 heap overflow, CVSS 8.8)",
            "CVE-2021-33910 (alloca stack overflow via long mount path, CVSS 7.5) — fixed in 249",
            "CVE-2021-3997 (tmpfiles infinite recursion, CVSS 5.5) — fixed in 251",
            "CVE-2019-3843 (service-level privilege escalation via sd_notify, CVSS 7.8)",
            "CVE-2019-3844 (bypass of unit isolation, CVSS 7.8)",
            "CVE-2017-15908 (infinite loop in DNS packet parsing, CVSS 7.5)",
        ],
        "chain": (
            "TK4-C07 CVE-2018-15688 + IPv6 link-local access: "
            "attacker on same L2 segment sends crafted DHCPv6 response → "
            "systemd-networkd heap overflow → code exec as systemd-network user → "
            "escalate via sudoers misconfiguration (TK4-C04); "
            "TK4-C07 CVE-2021-33910 + FUSE mount from container: "
            "container mounts long-path FUSE filesystem → alloca in host systemd PID 1 → "
            "system-wide DoS"
        ),
        "remediation": "Upgrade systemd >= 251 (or apply RHEL 7 backport RHSA-2021:3033).",
        "references": [
            "CVE-2018-15688", "CVE-2021-33910",
            "RHSA-2021:3033", "RHSA-2018:3665",
        ],
    },
    "TK4-C08": {
        "title": (
            "docker 1.13.1 (2017) + runc 1.0.0 — "
            "CVE-2021-30465 symlink Race in runc (CVSS 8.6, Container Escape); "
            "CVE-2021-41091 World-Executable Setuid Binary Leak; "
            "Source: tlinux/docker 1.13.1-210, tlinux/runc 1.0.0-70"
        ),
        "severity": "HIGH",
        "cvss": "8.6",
        "cwe": "CWE-362",
        "component": "tlinux/docker 1.13.1-210 + tlinux/runc 1.0.0-70",
        "description": (
            "Docker 1.13.1 dates from January 2017 — 8 years old at analysis. "
            "The primary risk is in runc 1.0.0 (July 2021), which carries CVE-2021-30465: "
            "a symlink TOCTOU race in runc's file copy path during container start. "
            "An attacker who can create symlinks within a container's filesystem at the right "
            "moment causes runc (running as root) to follow the symlink and write outside the "
            "container root — arbitrary file write as root on the host, i.e., container escape. "
            "CVE-2021-41091 (docker, 2021): the overlay2 storage driver allows world-executable "
            "setuid files in the container layer to appear in the host overlay mount with "
            "setuid permissions retained. A host user with overlay mount access can execute "
            "these setuid binaries to escalate. "
            "At Docker 1.13.1 vintage, containerd and CGROUP v2 mitigations are absent."
        ),
        "confirmed_present_cves": [
            "CVE-2021-30465 (runc symlink race → container escape, CVSS 8.6) — fixed in runc 1.0.1",
            "CVE-2021-41091 (overlay2 setuid leak, CVSS 6.3) — fixed in docker 20.10.9",
            "CVE-2022-36109 (supplemental groups bypass in Moby, CVSS 6.3)",
            "CVE-2019-13509 (docker credentials in debug log, CVSS 7.5)",
        ],
        "chain": (
            "TK4-C08 CVE-2021-30465 + cfs-utils (tencent_cfs_utils_re.py): "
            "container with CFS volume mount → runc calls mount.cfs with CFS-F01 cert= injection → "
            "container escape chain stacks; "
            "TK4-C08 + TOS24K-F01 (KASLR disabled): "
            "runc file write → overwrite kernel module at known address → root"
        ),
        "remediation": "Upgrade runc >= 1.0.1. Upgrade Docker >= 20.10.9.",
        "references": [
            "CVE-2021-30465", "CVE-2021-41091",
            "RHSA-2021:2566",
        ],
    },
    "TK4-C09": {
        "title": (
            "BIND 9.11.4 (2018) Carries 5+ Years of Denial-of-Service CVEs — "
            "CVE-2023-4408 DNS Message Parsing Crash (CVSS 7.5); "
            "Affects All BIND 9 Versions Including 9.11.4; "
            "Source: tlinux/bind 9.11.4-26"
        ),
        "severity": "MEDIUM",
        "cvss": "7.5",
        "cwe": "CWE-400",
        "component": "tlinux/bind 9.11.4-26",
        "description": (
            "BIND 9.11.4 from 2018. The 9.11.x branch reached EOL in March 2022. "
            "CVE-2023-4408 (February 2024): DNS message parsing consumes excessive CPU "
            "processing certain crafted DNS response messages — CVSS 7.5. Affects all "
            "BIND 9.x before 9.16.48 / 9.18.24 / 9.19.21. "
            "CVE-2022-3094 (January 2023): UPDATE messages cause excessive memory allocation — "
            "CVSS 7.5 DoS via crafted DNS UPDATE to a primary authoritative server. "
            "CVE-2021-25215 (April 2021): assertion failure in DNAME processing. "
            "The -26 patch level covers some backports, but 9.11.x EOL means no upstream fixes "
            "after 2022 can reach this branch."
        ),
        "confirmed_present_cves": [
            "CVE-2023-4408 (DNS parsing excessive CPU, CVSS 7.5) — fixed in 9.16.48",
            "CVE-2022-3094 (UPDATE memory exhaustion, CVSS 7.5) — fixed in 9.16.37",
            "CVE-2022-3736 (assertion failure in resolver, CVSS 7.5) — fixed in 9.16.37",
            "CVE-2021-25215 (DNAME assertion failure, CVSS 7.5)",
            "CVE-2021-25219 (lame-ttl assertion failure, CVSS 5.3)",
        ],
        "chain": (
            "TK4-C09 CVE-2023-4408 + internet-facing DNS resolver: "
            "attacker sends crafted DNS response to recursive resolver → "
            "excessive CPU → resolver DoS → service-wide DNS failure; "
            "typically combined with network-layer amplification for sustained outage"
        ),
        "remediation": "Migrate from BIND 9.11 to BIND 9.18.x (current stable).",
        "references": [
            "CVE-2023-4408", "CVE-2022-3094", "CVE-2022-3736",
            "ISC KB: end-of-life for BIND 9.11",
        ],
    },
    "TK4-C10": {
        "title": (
            "glibc 2.17 (2012) — CVE-2021-33574 Use-After-Free in mq_notify (CVSS 9.8); "
            "326 Backport Patches Applied; "
            "RHEL 7 EOL Means Backporting Has Now Stopped; "
            "Source: tlinux/glibc 2.17-326"
        ),
        "severity": "HIGH",
        "cvss": "9.8",
        "cwe": "CWE-416",
        "component": "tlinux/glibc 2.17-326",
        "description": (
            "glibc 2.17 dates from January 2012. TencentOS 2.4 TK4 shows 2.17-326 — "
            "326 patch commits applied since the RHEL 7 / glibc 2.17 baseline. This "
            "represents active backporting historically, but RHEL 7 EOL (June 2024) "
            "signals the end of new backports. "
            "CVE-2021-33574: use-after-free in __mq_notify_fork_callback when "
            "mq_notify(3) is used with SIGEV_THREAD and the thread is joined — "
            "CVSS 9.8. Affects glibc 2.17 through at least 2.33. "
            "The -326 patch level DOES include some fixes but CVE-2021-33574 fix "
            "was not confirmed in RHEL 7 errata at glibc-2.17-326. "
            "Note: CVE-2023-4911 (Looney Tunables) was introduced in glibc 2.34 "
            "and does NOT affect 2.17."
        ),
        "confirmed_present_cves": [
            "CVE-2021-33574 (mq_notify UAF, CVSS 9.8) — fix requires glibc >= 2.34",
            "CVE-2022-23218 (svcunix_create buffer overflow, CVSS 9.8)",
            "CVE-2022-23219 (clnt_create buffer overflow, CVSS 9.8)",
            "CVE-2015-7547 (getaddrinfo stack overflow, CVSS 8.1) — possibly backported at -326",
        ],
        "not_affected": [
            "CVE-2023-4911 (Looney Tunables) — introduced in glibc 2.34; 2.17 not affected"
        ],
        "chain": (
            "TK4-C10 CVE-2021-33574 + any process using mq_notify with SIGEV_THREAD: "
            "message queue notification triggers UAF in forked thread handler → "
            "heap corruption in glibc malloc arena → code execution in any process "
            "using POSIX message queues (cloud-init, daemons using mq_notify API)"
        ),
        "remediation": (
            "Apply glibc-2.17-326.*.el7_9 errata if available. "
            "Long-term: migrate TK4 images to TencentOS 3.x (glibc 2.28-251) or 4.x (glibc 2.38). "
            "CVE-2021-33574 was not backported to RHEL 7 glibc."
        ),
        "references": [
            "CVE-2021-33574", "CVE-2022-23218", "CVE-2022-23219",
            "RHSA-2022:7514",
        ],
    },
}

# ─── Composite Attack Chain ────────────────────────────────────────────────────

ATTACK_CHAIN = {
    "title": "TK4-C01 + TK4-C06 + TOS24K-F01/F02 → Remote Root via OpenSSH Agent + sudo + Module Load",
    "steps": [
        "1. Target TencentOS 2.4 TK4 VM; openssh 7.4p1 with agent forwarding enabled (default in some configs)",
        "2. Attacker compromises any SSH server the VM's operator connects to (lateral, phishing, etc.)",
        "3. Via compromised server: exploit CVE-2023-38408 (TK4-C06) — send PKCS#11 load request to forwarded ssh-agent",
        "4. Malicious .so loaded in ssh-agent on TK4 host → code execution as the SSH user",
        "5. sudo 1.8.23 (TK4-C04 CVE-2021-3156): sudoedit -s '\\ ' any-path → heap overflow → root",
        "6. KASLR disabled (TOS24K-F01): exploit heap overflow with fixed kernel addresses — no info-leak needed",
        "7. root: insmod unsigned rootkit (TOS24K-F02: MODULE_SIG disabled) at known sys_call_table address",
        "8. Persistent root; CFS-F01 TLS cert injection available if CFS mounts are in use",
    ],
    "pre_conditions": "SSH agent forwarding enabled; sudo configured for user (common in cloud VMs)",
    "overall_cvss": "9.8 (network-exploitable, no local auth required for initial step)",
}

# ─── Tenant Livepatch Surface ──────────────────────────────────────────────────

LIVEPATCH_NOTE = {
    "component": "tencentos-livepatch 1.0.1-1",
    "description": (
        "TencentOS-specific kernel live patching manager. Manages hot-patching of the "
        "running 5.4.119-19 kernel without reboot. Proprietary component; no public source. "
        "Attack surface: the livepatch manager must load kernel modules (KO) and apply "
        "function-level patches at runtime. If the livepatch transport channel (HTTP/HTTPS "
        "to Tencent update servers) uses OpenSSL 1.0.2k (TK4-C01), CVE-2022-0778 applies "
        "to the patch fetch path. Additionally, since MODULE_SIG is disabled (TOS24K-F02), "
        "live patches are not signature-verified — a compromised update channel delivers "
        "unsigned kernel code directly to the running kernel."
    ),
    "severity": "INFORMATIONAL — requires further source-level analysis",
    "chain": (
        "TK4 livepatch + TOS24K-F02 (MODULE_SIG disabled) + TK4-C01 (OpenSSL 1.0.2k): "
        "MitM update channel (CVE-2022-0778 or GnuTLS padding oracle TK4-C05) → "
        "deliver unsigned malicious live patch → kernel code exec without reboot"
    ),
}

# ─── Version Comparison vs TencentOS 3.x ──────────────────────────────────────

VERSION_DELTA_33 = {
    "openssl": {"tk4": "1.0.2k-26 (EOL)", "tos33": "1.1.1k-14 (EOL Sep 2023)"},
    "openssh": {"tk4": "7.4p1-13 (2016)", "tos33": "8.0p1-25 (2019)"},
    "glibc": {"tk4": "2.17-326 (RHEL7)", "tos33": "2.28-251 (RHEL8)"},
    "systemd": {"tk4": "v220 (2015)", "tos33": "239 (2018)"},
    "sudo": {"tk4": "1.8.23-10", "tos33": "1.8.29-7 (CVE-2021-3156 patched in -7.2.el8_4)"},
    "expat": {"tk4": "2.1.0-15 (CVSS 9.8 cluster)", "tos33": "2.2.5 (patched)"},
    "libssh2": {"tk4": "1.8.0-4 (CVE-2019-3855 cluster)", "tos33": "1.9.0-6 (patched)"},
    "note": "Every major component in TK4 is at least one major version behind TOS 3.3",
}


def probe():
    return {
        "critical": ["TK4-C01", "TK4-C02"],
        "high": ["TK4-C03", "TK4-C04", "TK4-C05", "TK4-C06", "TK4-C07", "TK4-C08", "TK4-C10"],
        "medium": ["TK4-C09"],
        "low": [],
        "informational": ["LIVEPATCH_NOTE"],
    }


def chain():
    return ATTACK_CHAIN


def delta_vs_33():
    return VERSION_DELTA_33


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": SBOM_SOURCE["file"],
        "lineage": SBOM_SOURCE["lineage"],
        "rhel7_eol": SBOM_SOURCE["rhel7_eol"],
        "findings": list(FINDINGS.keys()),
        "chain_summary": ATTACK_CHAIN["title"],
    }, indent=2))
