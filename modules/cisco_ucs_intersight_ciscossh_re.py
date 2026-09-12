"""
Intersight Private Virtual Appliance -- CiscoSSH + remaining Intersight RE

Target:  intersight-appliance-installer-kvm-1.1.7-0.a-disk1.qcow2
Binary:  /usr/local/sbin/sshd (CSCO_CSM_CiscoSSH 1.19.92 / OpenSSH 10.2p1, not stripped)
Service: ciscosshd.service (ExecStart=/usr/local/sbin/sshd -f /etc/ssh/sshd_config)
Session: 37
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_intersight_ciscossh_re",
    "firmware": "intersight-appliance-installer-kvm-1.1.7-0.a-disk1.qcow2",
    "components": {
        "ciscosshd.service": (
            "Cisco-patched OpenSSH 10.2p1 (CSCO_CSM_CiscoSSH 1.19.92), "
            "launched with LD_LIBRARY_PATH=/opt/cisco/ssl/lib64:"
        ),
        "/etc/ssh/sshd_config": (
            "Active sshd config: PermitRootLogin no, DenyUsers root, "
            "restricted Ciphers/KEX/MACs, UsePAM yes, MaxAuthTries 4"
        ),
        "/usr/local/etc/ssh/sshd_config": (
            "CiscoSSH own config: only AuthorizedKeysFile + sftp subsystem active; "
            "all other options commented with PSB SEC-CRY-PRIM recommendations"
        ),
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 3, "LOW": 2},
    "cumulative_counts": {"CRITICAL": 57, "HIGH": 216, "MEDIUM": 213, "LOW": 188},
    "cumulative_total": 674,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "MEDIUM",
        "title": "ciscosshd Startup Deletes AlmaLinux Crypto Policy Drop-In (50-redhat.conf)",
        "component": "ciscosshd.service",
        "evidence": {
            "service_line": (
                "ExecStartPre=-/bin/ssh-keygen -A ; rm -f /etc/ssh/sshd_config.d/50-redhat.conf"
            ),
            "comment_in_service": (
                "'Note that if the openssh-server RPM is updated, it will restore the "
                "/etc/ssh/sshd_config.d/50-redhat.conf file, which will restore some "
                "cipher configs that CiscoSSH does not understand.'"
            ),
            "effect": (
                "50-redhat.conf enforces AlmaLinux system-wide crypto-policy "
                "(DEFAULT, FIPS, FUTURE) via drop-in. Deleting it at every startup "
                "permanently detaches CiscoSSH from the OS crypto-policy framework."
            ),
            "baseline_protection": (
                "The base /etc/ssh/sshd_config has its own Ciphers/MACs/KexAlgorithms "
                "restrictions, so the immediate cipher risk is mitigated. The concern "
                "is forward-looking: future system crypto-policy changes (e.g., switching "
                "to FIPS policy) will not propagate to ciscosshd."
            ),
        },
        "impact": (
            "CiscoSSH bypasses AlmaLinux's centralized crypto-policy enforcement by "
            "deleting the policy drop-in at every startup. If the system crypto-policy "
            "is later upgraded (e.g., to require post-quantum KEX, TLS 1.3-only, or "
            "exclude DH14-sha256), ciscosshd will silently continue using its own "
            "static cipher list. An admin who updates crypto-policy for compliance "
            "will not achieve the expected change for SSH."
        ),
        "remediation": (
            "Remove the rm -f /etc/ssh/sshd_config.d/50-redhat.conf from ExecStartPre. "
            "Update the Cisco SSH cipher list to be compatible with the system crypto-policy "
            "instead of working around it. "
            "Alternatively, use 'update-crypto-policies --set LEGACY' before starting "
            "if backwards-compat is genuinely required, but with explicit documentation."
        ),
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "CiscoSSH Ciphers Exclude chacha20-poly1305 and curve25519; NIST-Only KEX",
        "component": "/etc/ssh/sshd_config + /usr/local/etc/ssh/sshd_config",
        "evidence": {
            "active_ciphers": (
                "aes128-gcm@openssh.com,aes256-gcm@openssh.com,"
                "aes128-ctr,aes256-ctr,aes192-ctr"
            ),
            "active_kex": (
                "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                "diffie-hellman-group14-sha256,diffie-hellman-group16-sha512"
            ),
            "excluded": "chacha20-poly1305@openssh.com, curve25519-sha256, curve25519-sha256@libssh.org",
            "comment": (
                "CiscoSSH sshd_config comment: 'cipher configs that CiscoSSH "
                "does not understand' causes crash; solution is to remove "
                "the 50-redhat.conf drop-in rather than fix the cipher negotiation"
            ),
        },
        "impact": (
            "Curve25519 and chacha20-poly1305 are excluded from the KEX and cipher "
            "negotiation. Both are considered stronger modern alternatives to the "
            "allowed NIST EC curves, which carry NIST backdoor concerns. "
            "Clients that prefer Curve25519-based KEX will fall back to NIST ECDH. "
            "The exclusion appears to be driven by CiscoSSL FOM FIPS constraints "
            "(chacha20 and Curve25519 are not FIPS 140-2 approved) rather than "
            "security policy, but is undocumented in the service definition."
        ),
        "remediation": (
            "Document the FIPS rationale for the cipher/KEX exclusion. "
            "Verify whether Curve25519/chacha20 support can be added for "
            "non-FIPS mode deployments while keeping the FIPS restrictions "
            "for FIPS-required environments."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "CiscoSSH Loaded with CiscoSSL via LD_LIBRARY_PATH; lib dir Must Be Root-Controlled",
        "component": "ciscosshd.service",
        "evidence": {
            "service_env": "Environment=\"LD_LIBRARY_PATH=/opt/cisco/ssl/lib64:\"",
            "libraries": [
                "/opt/cisco/ssl/lib64/libssl.so.1.1",
                "/opt/cisco/ssl/lib64/libcrypto.so.1.1",
            ],
            "sshd_binary": (
                "CSCO_CSM_CiscoSSH 1.19.92, OpenSSH 10.2p1, ELF x86-64 PIE, not stripped, "
                "BuildID=ea5880a2895083be4a9a5a87b681018128a66ac4"
            ),
            "fips_symbols": [
                "FIPS_mode_set", "FIPS_cc_mode", "FIPS_cc_set",
                "FIPS_mode_initialized (string)",
            ],
        },
        "impact": (
            "sshd loads CiscoSSL (OpenSSL 1.1.1-based with FIPS FOM extensions) via "
            "LD_LIBRARY_PATH injection. If /opt/cisco/ssl/lib64/ is writable by any "
            "non-root user, a malicious shared library placed there will be loaded "
            "by the privileged sshd process. Additionally, CiscoSSL 1.1.1 is EOL "
            "(upstream support ended September 2023); any post-EOL OpenSSL 1.1.1 "
            "vulnerabilities are unpatched unless Cisco backports them."
        ),
        "remediation": (
            "Verify /opt/cisco/ssl/lib64/ is owned root:root, mode 0755 (no world write). "
            "Audit for CiscoSSL 1.1.1 CVEs since 2023-09-11. "
            "Plan migration to OpenSSL 3.x / CiscoSSL 3.x for long-term support."
        ),
    },
    {
        "id": "F4",
        "severity": "LOW",
        "title": "andro System Account in Shadow with Password Policy but nologin Shell",
        "component": "/etc/passwd + /etc/shadow",
        "evidence": {
            "passwd": "andro:x:1003:1002:Andromeda user:/home/andro:/sbin/nologin",
            "shadow": "andro:!!:20622:7:365:7:30::",
            "shadow_fields": (
                "min_age=7, max_age=365, warn=7, inactive=30"
            ),
            "purpose": "account name matches 'andromeda' subsystem but has no docs in init scripts",
        },
        "impact": (
            "The andro account exists with a shadow entry carrying a full password "
            "expiry policy (365-day max, 30-day inactive) despite using /sbin/nologin. "
            "The password policy is meaningless with a locked (!!) password and nologin shell. "
            "The account home /home/andro does not exist in the template disk. "
            "If another process creates a shell for this account or sets a password, "
            "the account can login without being noticed as a service account."
        ),
        "remediation": (
            "Document the andro account purpose. "
            "If it is a service account, verify it has no interactive login capability "
            "and that no other mechanism can set its password to a known value."
        ),
    },
    {
        "id": "F5",
        "severity": "LOW",
        "title": "PSB SEC-CRY-PRIM Cipher Recommendations Documented but Not Enforced",
        "component": "/usr/local/etc/ssh/sshd_config",
        "evidence": {
            "comment_in_config": (
                "# For PSB SEC-CRY-PRIM compliance, you should use a PSB recommended "
                "list of key types such as the one below\n"
                "# PubkeyAcceptedKeyTypes ecdsa-sha2-nistp256-cert-v01@openssh.com,...\n"
                "\n"
                "# SEC-CRY-PRIM-9 Approved Algorithms\n"
                "#   Ciphers aes128-ctr,...\n"
                "#   MACs hmac-sha2-256-etm@openssh.com,...\n"
                "#   KexAlgorithms ecdh-sha2-nistp256,..."
            ),
            "status": (
                "All SEC-CRY-PRIM-9 recommendations are commented out in "
                "CiscoSSH's own config; the active config is in /etc/ssh/sshd_config "
                "and partially overlaps but does not implement the full recommendation set"
            ),
        },
        "impact": (
            "Cisco's own PSB (Product Security Baseline) SEC-CRY-PRIM-9 cipher "
            "recommendations are present in the CiscoSSH default config as comments "
            "but are not enforced. The active config in /etc/ssh/sshd_config "
            "restricts ciphers differently (e.g., includes aes192-ctr which is not "
            "in the PSB list, excludes PubkeyAcceptedKeyTypes restrictions). "
            "This creates a compliance drift between Cisco's own documented baseline "
            "and the deployed configuration."
        ),
        "remediation": (
            "Uncomment and apply the SEC-CRY-PRIM-9 recommendations or document "
            "the deviation with a compensating control. Align /etc/ssh/sshd_config "
            "with the PSB baseline."
        ),
    },
]


def run_module():
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Firmware: {MODULE_SUMMARY['firmware']}")
    for component, desc in MODULE_SUMMARY["components"].items():
        print(f"  {component}: {desc}")
    counts = MODULE_SUMMARY["finding_counts"]
    print(
        f"Findings: {sum(counts.values())} "
        f"[{counts['CRITICAL']}C/{counts['HIGH']}H/"
        f"{counts['MEDIUM']}M/{counts['LOW']}L]"
    )
    cc = MODULE_SUMMARY["cumulative_counts"]
    print(
        f"Cumulative: {MODULE_SUMMARY['cumulative_total']} "
        f"[{cc['CRITICAL']}C+{cc['HIGH']}H+{cc['MEDIUM']}M+{cc['LOW']}L]"
    )
    print()
    for f in FINDINGS:
        sev = f["severity"]
        print(f"  {f['id']} [{sev}] {f['title']}")
        print(f"    Component: {f['component']}")
        print(f"    Impact: {f['impact'][:120]}...")
        print()


if __name__ == "__main__":
    run_module()
