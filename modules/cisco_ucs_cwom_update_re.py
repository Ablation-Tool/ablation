"""
Cisco UCS CWOM 3.16.0 Update Package RE

Target:  update64_package-3.16.0.iso
         Cisco Workload Optimization Manager (CWOM) 3.16.0 online update package
         Rebrand of IBM Turbonomic 8.18.0; Kubernetes + MariaDB + TimescaleDB
         Update scripts: turboupgrade.sh, turboload.sh, turboclientupgrade.sh
         Container images: cwom-8.18.0.tar, turbonomic-8.18.0.tar, t8c-operator-42.93.tar
Files:   turboupgrade.sh (251 lines): upgrade orchestrator with brand check, DB config, k8s apply
         turboload.sh (94 lines): container image loader via nerdctl
         turboclientupgrade.sh: client-side operator upgrade
         update_mariadb_conf.sh: MariaDB buffer pool + InnoDB config
         cwom.conf: cwomVersion="3.16.0"
         rpm9/: Rocky Linux 9 RPM packages (nerdctl, timescale, postgres, mariadb)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_cwom_update_re",
    "firmware": "update64_package-3.16.0.iso",
    "components": {
        "turboupgrade.sh": (
            "251-line upgrade orchestrator; "
            "brand gate: 'if [ Xcisco = Xcisco ]' (always true -- dead else branch); "
            "vmturbo MySQL root credential hardcoded via sed into K8s CR YAML; "
            "nerdctl downloaded from GitHub via sudo wget without integrity check; "
            "sudo chown -R turbo.turbo /opt/turbonomic; "
            "sudo yum localinstall -y --disablerepo '*' rpm9/*.rpm"
        ),
        "turboclientupgrade.sh": (
            "Client operator upgrade; "
            "sudo chown -R turbo.turbo /opt/turbonomic (second occurrence); "
            "missing closing quote: 'if [ -z \"$registry\"]' (syntax defect)"
        ),
        "cwom-8.18.0.tar / turbonomic-8.18.0.tar": (
            "Container images; IBM Turbonomic 8.18.0 rebrand; "
            "loaded via nerdctl into k8s.io namespace without manifest verification"
        ),
    },
    "finding_count": "6F [0C+3H+2M+1L]",
    "cumulative": "789 [76C+271H+248M+193L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "MySQL root password 'vmturbo' hardcoded in K8s CR YAML injection during upgrade",
        "description": (
            "turboupgrade.sh writes the MySQL root password directly into the "
            "Kubernetes Custom Resource YAML during upgrade via: "
            "\"sed -i '/prometheus-mysql-exporter:/,/prometheus/c\\\\  prometheus-mysql-exporter:\\\\n"
            "    enabled: false\\\\n\\\\    mysql:\\\\n\\\\      user: root\\\\n\\\\      pass: vmturbo"
            "\\\\n\\\\  prometheus:' ${chartsFile}\". "
            "chartsFile is charts_v1alpha1_xl_cr.yaml in the operator deploy directory. "
            "The password 'vmturbo' is the original IBM Turbonomic default MySQL credential. "
            "This same credential was documented in the CWOM 3.14.1 VMDK "
            "(vmturbo in Xl CR finding). "
            "After this sed replacement, the Prometheus MySQL exporter config "
            "contains the plaintext database root password in a Kubernetes resource. "
            "Any operator or service with CR read access can extract the database credential."
        ),
        "evidence": {
            "file": "turboupgrade.sh:134",
            "code": (
                "sed -i '/prometheus-mysql-exporter:/,/prometheus/c\\"
                "  prometheus-mysql-exporter:\\n"
                "    enabled: false\\n    mysql:\\n"
                "      user: root\\n      pass: vmturbo\\n"
                "  prometheus:' ${chartsFile}"
            ),
            "target_file": "charts_v1alpha1_xl_cr.yaml",
            "persists_from": "CWOM 3.14.1 vmturbo credential (unchanged between versions)",
        },
        "impact": (
            "Plaintext MySQL root password exposed in Kubernetes CR resource. "
            "Any principal with kubectl get/describe access to the CR retrieves the database credential. "
            "Database credential unchanged between 3.14.1 and 3.16.0."
        ),
        "remediation": "Store database credentials in a Kubernetes Secret. Do not hardcode in CR YAML.",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "nerdctl binary downloaded from GitHub without integrity verification",
        "description": (
            "turboupgrade.sh downloads and extracts nerdctl if the local copy is absent: "
            "'sudo -n wget -P /tmp "
            "https://github.com/containerd/nerdctl/releases/download/v2.0.2/"
            "nerdctl-2.0.2-linux-amd64.tar.gz' "
            "followed by 'sudo tar Cxzvvf /usr/local/bin /tmp/nerdctl-2.0.2-linux-amd64.tar.gz'. "
            "No checksum or signature verification is performed on the downloaded tarball. "
            "nerdctl is extracted directly to /usr/local/bin. "
            "A MITM or DNS poisoning attack during upgrade delivers a malicious binary "
            "to /usr/local/bin without detection. "
            "Separately, turboload.sh installs nerdctl from the ISO's rpm9/ directory "
            "(no network fetch required), but turboupgrade.sh falls back to the network "
            "download when the ISO copy is not found in the expected path."
        ),
        "evidence": {
            "file": "turboupgrade.sh:165-168",
            "code": (
                "sudo -n wget -P /tmp https://github.com/containerd/nerdctl/releases/download/"
                "v2.0.2/nerdctl-2.0.2-linux-amd64.tar.gz\n"
                "sudo tar Cxzvvf /usr/local/bin /tmp/nerdctl-2.0.2-linux-amd64.tar.gz"
            ),
            "no_verify": "No sha256sum, no gpg verify, no pinned hash before extraction",
        },
        "impact": (
            "MITM during upgrade installs attacker-controlled binary as nerdctl in /usr/local/bin. "
            "nerdctl is used for all container image loads; malicious nerdctl can intercept "
            "or modify container image loading."
        ),
        "remediation": "Verify download against a pinned SHA-256 hash before extraction. Prefer the on-ISO copy.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Recursive chown of /opt/turbonomic in two upgrade scripts",
        "description": (
            "turboupgrade.sh: 'sudo chown -R turbo.turbo /opt/turbonomic'. "
            "turboclientupgrade.sh: 'sudo chown -R turbo.turbo /opt/turbonomic'. "
            "Same finding as CWOM 3.14.1 VMDK module. "
            "/opt/turbonomic contains Kubernetes operator yamls, "
            "CRD definitions, migration scripts, and all deployed container configs. "
            "Recursive chown with sudo runs as root with no path validation. "
            "If a symlink attack is in place under /opt/turbonomic before the upgrade, "
            "chown follows the symlink to arbitrary filesystem paths. "
            "The chown is unconditional and runs before the upgrade validation steps."
        ),
        "evidence": {
            "turboupgrade.sh": "sudo chown -R turbo.turbo /opt/turbonomic (line ~58)",
            "turboclientupgrade.sh": "sudo chown -R turbo.turbo /opt/turbonomic (last line)",
        },
        "impact": (
            "Symlink attack during upgrade changes ownership of arbitrary files. "
            "Same unmitigated finding present in 3.14.1; not fixed in 3.16.0 update."
        ),
        "remediation": "Use explicit path list instead of recursive chown. Validate no symlinks escape the target directory before chown.",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "Always-true brand gate 'if [ Xcisco = Xcisco ]' exposes dead IBM Turbonomic code",
        "description": (
            "turboupgrade.sh uses 'if [ Xcisco = Xcisco ]' as the brand check "
            "in 6 separate conditional blocks. "
            "The comparison is between two identical string literals -- always evaluates true. "
            "The 'else' branch (IBM Turbonomic path) is dead code that never executes. "
            "A second gate 'if [ \"Xcisco\" != \"Xcisco\" ]' is always false, "
            "permanently suppressing IBM license operator installation. "
            "The original intent was likely 'if [ \"X$BRAND\" = \"Xcisco\" ]' "
            "or similar, using an environment variable. "
            "Dead IBM code paths reveal internal upgrade logic, IBM-specific registry URLs "
            "('icr.io/cpopen/turbonomic'), and the 8.18.0 IBM Turbonomic base version. "
            "The brand variable was stripped during the Cisco rebrand, "
            "leaving a permanently-true static comparison."
        ),
        "evidence": {
            "file": "turboupgrade.sh:3,30,49,79,140,218",
            "always_true": "if [ Xcisco = Xcisco ]",
            "always_false": "if [ \"Xcisco\" != \"Xcisco\" ]",
            "ibm_registry": "icr.io/cpopen/turbonomic (visible in dead else branch)",
        },
        "impact": (
            "IBM Turbonomic license operator never installed (always-false gate). "
            "Internal IBM registry and Turbonomic versioning exposed in shipping code. "
            "Confirms CWOM 3.16.0 is IBM Turbonomic 8.18.0 rebranded with incomplete brand variable removal."
        ),
        "remediation": "Replace static brand check with proper configuration variable or remove dead branches.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "RPM packages installed with --disablerepo '*' bypassing GPG key verification",
        "description": (
            "turboupgrade.sh installs TimescaleDB, PostgreSQL, and supporting RPMs with: "
            "'sudo yum localinstall -y --disablerepo \"*\" /mnt/iso/rpm9/*.rpm'. "
            "--disablerepo \"*\" disables all configured repositories including the GPG signing key repo. "
            "yum localinstall without a configured GPG key does not verify RPM signatures "
            "when no repo provides the signing key. "
            "An attacker who can modify the ISO (or the mounted /mnt/iso path before upgrade) "
            "delivers unsigned RPMs that install without verification. "
            "The RPMs include database engines and system utilities."
        ),
        "evidence": {
            "file": "turboupgrade.sh:169",
            "cmd": "sudo yum localinstall -y --disablerepo \"*\" /mnt/iso/rpm9/*.rpm",
            "packages": "timescale, postgres, mariadb components, nerdctl",
        },
        "impact": "Malicious RPMs from a tampered ISO install as trusted packages during upgrade.",
        "remediation": "Import and verify RPM signing keys before installation. Use --nogpgcheck only with explicit justification.",
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "turboclientupgrade.sh missing closing quote in conditional causes bash syntax error",
        "description": (
            "turboclientupgrade.sh line: "
            "'if [ -z \"$registry\"]' -- the closing bracket is not preceded by a space, "
            "and the double quote for $registry is not closed before the bracket. "
            "The correct syntax is 'if [ -z \"$registry\" ]'. "
            "bash parses this as 'if [ -z \"$registry]\"' (the ] is inside the string), "
            "which expands to testing whether the string '$registry]' is zero-length. "
            "This is always false (non-empty string), causing the conditional block "
            "to never execute -- the kubectl apply for the client operator runs unconditionally "
            "whether or not the registry variable is set. "
            "This is a scripting defect that alters intended control flow but does not "
            "by itself create a direct security impact."
        ),
        "evidence": {
            "file": "turboclientupgrade.sh:23",
            "defective": "if [ -z \"$registry\"]",
            "correct": "if [ -z \"$registry\" ]",
            "consequence": "Registry variable check never taken; kubectl apply runs unconditionally",
        },
        "impact": "Client operator deployed without registry substitution even when a private registry is configured.",
        "remediation": "Fix syntax: 'if [ -z \"$registry\" ]'. Validate all shell scripts with shellcheck.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
