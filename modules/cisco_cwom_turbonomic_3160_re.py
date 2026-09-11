"""
Cisco CWOM / Turbonomic 3.16.0 — delta RE module
Target: update64_package-3.16.0.iso
Source: /media/cowboy/research/Cisco-UCS/cwom/update64_package-3.16.0.iso
Mounted: scratchpad/cwom-3160-mnt/

This module documents findings NOVEL to 3.16.0 — not already covered by
cisco_cwom_turbonomic_818_re.py (CWOM-F1 through F5, extracted from 8.18.0 ISO).

Files analyzed:
  bin/configure_mariadb.sh   — MariaDB initial permissions setup
  bin/onlineUpgrade.sh       — CDN-based online upgrade path
  bin/externalize_mariadb.sh — GlusterFS→local MariaDB migration (no novel findings)
  bin/skupper-proxy/deploy-skupper-proxy.sh — Skupper proxy deploy (no novel findings)
  cwom-8.18.0.tar (OCI)      — t8c-operator 8.2.0 ClusterServiceVersion RBAC

Delta from 8.18.0 / prior analysis:
  - vmturbo credential confirmed AGAIN in configure_mariadb.sh (third independent location)
    with GRANT ALL ON *.* TO 'root'@'%' (any host, not just localhost)
  - onlineUpgrade.sh: unsigned CDN download → root exec (distinct from ISO-based CWOM-F3)
  - t8c-operator 8.2.0 ClusterRole wildcard expanded beyond CWOM-F5 scope
    (secrets, namespaces, full RBAC wildcard; cluster-admin equivalent escalation path)
"""

FIRMWARE = {
    "target":     "Cisco CWOM / Turbonomic 3.16.0",
    "file":       "update64_package-3.16.0.iso",
    "parent_module": "cisco_cwom_turbonomic_818_re.py",
    "findings":   ["CWOM3160-F1", "CWOM3160-F2", "CWOM3160-F3"],
}

# CWOM3160-F1: configure_mariadb.sh grants root@'%' with vmturbo during MariaDB setup
CWOM3160_F1 = {
    "id":       "CWOM3160-F1",
    "title":    "configure_mariadb.sh grants MariaDB root@'%' WITH GRANT OPTION using hardcoded "
                "'vmturbo' password — network-accessible MySQL root created at install time",
    "severity": "HIGH",
    "status":   "CONFIRMED — GRANT statement extracted directly from configure_mariadb.sh; "
                "runs unconditionally with retry loop (up to 5 attempts) during MariaDB setup",
    "cwe":      ["CWE-798 (Use of Hard-coded Credentials)", "CWE-284 (Improper Access Control)"],
    "file":     "bin/configure_mariadb.sh",
    "verbatim_grant": (
        "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'vmturbo' WITH GRANT OPTION; "
        "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY 'vmturbo' WITH GRANT OPTION; "
        "FLUSH PRIVILEGES;"
    ),
    "execution_context": {
        "mechanism":    "echo <SQL> | sudo /usr/bin/mysql -uroot",
        "retry_count":  5,
        "host_scope":   "'%' (any host on the network)",
        "privilege":    "ALL PRIVILEGES WITH GRANT OPTION (full MySQL admin)",
        "username":     "root",
        "password":     "vmturbo",
    },
    "delta_from_prior": {
        "CWOM-F1": "xl-backup.sh uses vmturbo in backup scripts (schema enumeration context); "
                   "this is the GRANT that creates the credential at install time, "
                   "and explicitly opens root@'%' (any host) not just root@localhost",
        "CWOM-F4": "turboupgrade.sh writes vmturbo into K8s CR YAML (upgrade context); "
                   "CWOM3160-F1 is the install-time setup that persists across upgrades",
    },
    "threat_model": "Default Turbonomic deployment exposes MariaDB port 3306 on the host; "
                    "attacker with network access to the appliance IP authenticates as "
                    "mysql root with password 'vmturbo' — full read/write/drop on all databases "
                    "including Turbonomic's operational schema (topology, credentials, targets)",
    "exploit_sketch": "mysql -h <turbo-ip> -uroot -pvmturbo -e 'show databases;'",
    "cvss_estimate":  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 CRITICAL (network reachable)",
    "note": "Third independent hardcoded vmturbo location in the codebase. "
            "Standalone finding — not a chain.",
}

# CWOM3160-F2: onlineUpgrade.sh downloads and executes unsigned tar from CDN
CWOM3160_F2 = {
    "id":       "CWOM3160-F2",
    "title":    "onlineUpgrade.sh downloads online-packages.tar from download.vmturbo.com via curl "
                "without hash or signature verification, then executes the extracted turboupgrade.sh "
                "as root",
    "severity": "HIGH",
    "status":   "CONFIRMED — full script extracted from bin/onlineUpgrade.sh; "
                "download URL and execution flow verified by direct grep",
    "cwe":      ["CWE-494 (Download of Code Without Integrity Check)", "CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)"],
    "file":     "bin/onlineUpgrade.sh",
    "execution_flow": [
        "pushd /mnt/iso/",
        "sudo curl -o /mnt/iso/online-packages.tar "
        "https://download.vmturbo.com/appliance/download/updates/${turboVersion}/online-packages.tar",
        "sudo tar -xvf online-packages.tar",
        "# tar extracts turboupgrade.sh (and turboclientupgrade.sh) into /mnt/iso/",
        "/mnt/iso/turboupgrade.sh    # executed as root — sourced from the downloaded tar",
    ],
    "missing_verification": [
        "No checksum comparison (no .sha256 / .md5 file fetched alongside the tar)",
        "No GPG signature verification",
        "No HMAC or any authenticated binding between version and expected digest",
    ],
    "proxy_support": "Script prompts for proxy host:port and passes --proxy to curl; "
                     "proxy MITM path: attacker controls proxy → intercepts TLS via trusted corp CA "
                     "→ serves malicious tar at the moment of upgrade",
    "attack_conditions": {
        "path_a": "Compromise download.vmturbo.com CDN or the S3/blob bucket it serves from",
        "path_b": "DNS poisoning of download.vmturbo.com → serve malicious tar over HTTPS "
                  "(requires valid TLS cert for that domain or CA-level MITM)",
        "path_c": "Enterprise MITM proxy with corp CA installed → intercept upgrade download",
        "impact":  "Arbitrary code execution as root on the Turbonomic appliance at upgrade time",
    },
    "delta_from_prior": {
        "CWOM-F3": "turboload.sh loads container images from LOCAL ISO without digest; "
                   "CWOM3160-F2 is a REMOTE CDN download path — attacker doesn't need ISO access, "
                   "only network position between appliance and download.vmturbo.com",
    },
}

# CWOM3160-F3: t8c-operator 8.2.0 ClusterRole has wildcard verbs on secrets, namespaces, full RBAC
CWOM3160_F3 = {
    "id":       "CWOM3160-F3",
    "title":    "t8c-operator 8.2.0 ClusterRole grants verbs: ['*'] on secrets, namespaces, "
                "clusterroles, clusterrolebindings, rolebindings, and roles — "
                "operator SA compromise equals cluster-admin",
    "severity": "HIGH",
    "status":   "CONFIRMED — ClusterServiceVersion permissions extracted from t8c-operator-8.2.0 "
                "CSV in cwom-8.18.0.tar OCI image layer; wildcard resource set verified",
    "cwe":      ["CWE-269 (Improper Privilege Management)", "CWE-732 (Incorrect Permission Assignment)"],
    "file":     "cwom-8.18.0.tar → t8c-operator-8.2.0.clusterserviceversion.yaml",
    "wildcard_resources": [
        "secrets",
        "pods",
        "persistentvolumeclaims",
        "services",
        "serviceaccounts",
        "deployments",
        "daemonsets",
        "replicasets",
        "namespaces",
        "clusterroles",
        "clusterrolebindings",
        "rolebindings",
        "roles",
        "jobs",
    ],
    "wildcard_verbs": ["*"],
    "escalation_path": {
        "step_1": "Compromise t8c-operator pod (via any vuln in operator code)",
        "step_2": "Use operator's SA token to create a ClusterRoleBinding: "
                  "kubectl create clusterrolebinding pwn --clusterrole=cluster-admin "
                  "--serviceaccount=turbonomic:t8c-operator",
        "step_3": "Full cluster-admin access — read all secrets (inc. kube API certs), "
                  "modify any namespace, escalate any SA",
    },
    "note": "Wildcards on `clusterroles` + `clusterrolebindings` + `rolebindings` + `roles` "
            "means the operator SA can self-escalate or grant arbitrary permissions — "
            "this is the critical distinction from over-permissioned workload SAs that "
            "lack RBAC write access.",
    "delta_from_prior": {
        "CWOM-F5": "CWOM-F5 covers Helm v2 Tiller legacy manifest binding tiller SA to cluster-admin; "
                   "CWOM3160-F3 is about t8c-operator itself (the ACTIVE operator SA, not legacy Tiller) "
                   "having wildcard access to RBAC resources — self-escalation without needing Tiller",
    },
}

FINDINGS = [CWOM3160_F1, CWOM3160_F2, CWOM3160_F3]
