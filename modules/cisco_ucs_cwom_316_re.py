"""
RE Module: Cisco UCS CWOM 3.16.0 Update Package (update64_package-3.16.0.iso)
IBM Turbonomic 8.18.0 rebrand, upgrade package (2025-11-07)
Target: Cisco Workload Optimization Manager on-premises appliance

Findings: 6F [0C+2H+3M+1L]
"""

FINDINGS = [
    {
        "id": "CWOM316-F1",
        "title": "vmturbo MySQL root password persists unfixed from 3.14.1 to 3.16.0",
        "severity": "HIGH",
        "component": "configure_mariadb.sh (bin.tar) / MariaDB 10.6.x",
        "evidence": [
            "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'vmturbo' WITH GRANT OPTION;",
            "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY 'vmturbo' WITH GRANT OPTION;",
            "FLUSH PRIVILEGES;",
        ],
        "detail": (
            "configure_mariadb.sh in the 3.16.0 bin.tar provisions the MariaDB root account "
            "with the hardcoded password 'vmturbo' and grants full privileges from both "
            "'%' (any host) and 'localhost'. This is the same credential shipped in CWOM "
            "3.14.1 (cisco_ucs_cwom_bintar_re.py F1). The credential has not changed across "
            "at least two major update cycles. The provision script runs in a retry loop "
            "('for i in `seq 1 5`') that re-applies the credential up to five times; "
            "a one-time rotated password would be reverted to 'vmturbo' on each upgrade. "
            "MariaDB is deployed alongside the Turbonomic application stack and holds all "
            "Turbonomic operational data. The '%' host mask means the credential is valid "
            "from any MariaDB client that can reach the database port."
        ),
        "impact": (
            "Full MariaDB root access from any reachable host. All Turbonomic operational "
            "data (workload, pricing, policy) accessible. Persists across upgrades from "
            "3.14.1 through 3.16.0."
        ),
        "remediation": "Generate a per-deployment random password during first provisioning and store it in a Kubernetes Secret. Do not re-apply a fixed credential on upgrade. Remove the '%' host grant; restrict to 'localhost' or a specific pod CIDR.",
        "references": ["CWOM 3.14.1 cisco_ucs_cwom_bintar_re.py F1", "vmturbo credential"],
    },
    {
        "id": "CWOM316-F2",
        "title": "PostgreSQL superuser with BYPASSRLS + REPLICATION + vmturbo password in new TimescaleDB integration",
        "severity": "HIGH",
        "component": "configure_timescaledb.sh (bin.tar) / TimescaleDB / PostgreSQL 15",
        "evidence": [
            "sudo -iu postgres psql -c \"ALTER ROLE postgres WITH PASSWORD 'vmturbo'\"",
            "sudo -iu postgres psql -c \"CREATE ROLE turbo WITH SUPERUSER CREATEDB CREATEROLE LOGIN REPLICATION BYPASSRLS PASSWORD 'vmturbo'\"",
        ],
        "detail": (
            "CWOM 3.16.0 introduces TimescaleDB as a new data store alongside MariaDB. "
            "configure_timescaledb.sh provisions two PostgreSQL accounts with the same "
            "'vmturbo' password: (1) the default 'postgres' superuser is assigned the "
            "'vmturbo' password, and (2) a new 'turbo' role is created with "
            "SUPERUSER CREATEDB CREATEROLE LOGIN REPLICATION BYPASSRLS. "
            "BYPASSRLS means the 'turbo' role bypasses all Row Level Security policies "
            "in PostgreSQL, defeating any fine-grained access controls on TimescaleDB tables. "
            "REPLICATION grants access to the streaming replication protocol and "
            "pg_basebackup, enabling full database exfiltration via replication stream. "
            "CREATEROLE allows the turbo role to create additional roles, including other "
            "superusers. All three accounts use the same hardcoded 'vmturbo' password "
            "as the MariaDB root credential."
        ),
        "impact": (
            "Full TimescaleDB / PostgreSQL access with BYPASSRLS (no RLS enforcement) "
            "and REPLICATION (full stream backup). New attack surface introduced in 3.16.0. "
            "Same 'vmturbo' password as MariaDB root provides single-credential access "
            "to both database backends."
        ),
        "remediation": "Generate per-deployment unique passwords for postgres and turbo roles. Remove BYPASSRLS and REPLICATION from the turbo role unless strictly required. Restrict CREATEROLE from application roles.",
        "references": ["TimescaleDB CWOM 3.16.0", "configure_timescaledb.sh", "PostgreSQL BYPASSRLS"],
    },
    {
        "id": "CWOM316-F3",
        "title": "t8c-operator ClusterServiceVersion v42.30.0 grants wildcard verbs across all core API groups",
        "severity": "MEDIUM",
        "component": "operator/bundle/42.30.0/t8c-certified.clusterserviceversion.yaml (operator.tar)",
        "evidence": [
            "resources: [pods, secrets, serviceaccounts, services] -> verbs: ['*']",
            "resources: [daemonsets, deployments, statefulsets, replicasets] -> verbs: ['*']",
            "resources: [rolebindings, roles] -> verbs: ['*']",
            "resources: [podsecuritypolicies, poddisruptionbudgets] -> verbs: ['*']",
            "resources: ['*'] apiGroups: [charts.helm.k8s.io] -> verbs: ['*']",
        ],
        "detail": (
            "The t8c-certified.clusterserviceversion.yaml (OLM bundle v42.30.0) grants the "
            "t8c-operator service account wildcard verbs ('*') over core Kubernetes resources "
            "including secrets, pods, serviceaccounts, deployments, statefulsets, "
            "rolebindings, and roles. The 'rolebindings + roles: *' rule means the operator "
            "can create or modify any ClusterRoleBinding in its namespace, enabling privilege "
            "escalation to cluster-admin via a self-referential binding. "
            "This finding carries over from CWOM 3.14.1 (cisco_ucs_cwom_vmdk_re.py) and "
            "persists through at least 8 minor operator versions (34.x through 42.30.0). "
            "Operator bundle 42.30.0 is the latest version shipped in the 3.16.0 ISO."
        ),
        "impact": (
            "Operator pod compromise enables RBAC escalation to cluster-admin via "
            "self-referential ClusterRoleBinding creation. Access to all secrets in namespace "
            "including TLS keys, MariaDB credentials, and service account tokens."
        ),
        "remediation": "Replace wildcard verbs with the minimum required list for each resource type. Separate the RBAC management permission from application deployment permissions. Audit operator RBAC at each version bump.",
        "references": ["t8c-certified.clusterserviceversion.yaml", "OLM bundle 42.30.0", "CWOM 3.14.1 RBAC escalation"],
    },
    {
        "id": "CWOM316-F4",
        "title": "Consul configured without ACL token in 3.16.0",
        "severity": "MEDIUM",
        "component": "configure_consul.sh / consul.hcl (bin.tar)",
        "evidence": [
            "SRC_CONSUL_CONFIG='/opt/local/etc/consul.hcl'",
            "sudo cp -f $SRC_CONSUL_CONFIG $DEST_CONSUL_CONFIG",
            "# no acl_master_token, no acl_default_policy=deny in configure script",
        ],
        "detail": (
            "configure_consul.sh copies /opt/local/etc/consul.hcl to the Consul config "
            "directory without configuring ACL tokens. The script contains no ACL-related "
            "configuration: no acl_master_token, no acl_default_policy, no acl_token "
            "in the setup. Consul in this configuration runs in legacy ACL mode or with "
            "ACLs disabled, making the service catalog, key/value store, and health check "
            "API accessible to any process on the appliance without authentication. "
            "This finding carries over from CWOM 3.14.1 (cisco_ucs_cwom_vmdk_re.py) and "
            "is not addressed in 3.16.0."
        ),
        "impact": (
            "Any process on the CWOM appliance can read and write the Consul key/value "
            "store, deregister services, and modify health check registrations. Service "
            "discovery poisoning without credentials."
        ),
        "remediation": "Enable Consul ACL system with a generated master token. Set acl_default_policy=deny in consul.hcl. Distribute per-service tokens via Vault or Kubernetes Secrets rather than a shared consul.hcl.",
        "references": ["configure_consul.sh 3.16.0", "CWOM 3.14.1 Consul no-ACL"],
    },
    {
        "id": "CWOM316-F5",
        "title": "tokenExchange.sh disables TLS verification with curl -k on token exchange operations",
        "severity": "MEDIUM",
        "component": "tokenExchange.sh / enable_saas_reporting.py (bin.tar)",
        "evidence": [
            "status=`curl -sS -k -m 10 -c $tmp ${ip}/api/v3/login --data-urlencode \"username=${username}\" --data-urlencode \"password=${password}\" -w \"%{http_code}\" -o /dev/null`",
            "token=$(curl -sS -k -m 10 -b $tmp -X POST ${ip}/api/v3/clients/networks/tokens)",
            "cookie=$(curl -k -s -v \"https://$ip/vmturbo/rest/login\" --data ...)",
        ],
        "detail": (
            "tokenExchange.sh performs API login and token retrieval with 'curl -k' "
            "(--insecure), disabling TLS certificate verification for all token operations. "
            "The script transmits username and password in the first curl call and retrieves "
            "a bearer token in the second. With -k, a MITM attacker on the appliance network "
            "can intercept both the credentials and the token. "
            "enable_saas_reporting.py similarly uses 'curl -k' for SaaS login operations. "
            "These scripts are used during initial configuration and appliance integration "
            "workflows, where full Turbonomic credentials are in play."
        ),
        "impact": (
            "Plaintext credential and token interception via MITM on the appliance network "
            "during tokenExchange and SaaS reporting configuration."
        ),
        "remediation": "Remove -k flag. Add --cacert pointing to the appliance's CA bundle or the Turbonomic self-signed cert, generated at install time. Do not disable certificate verification in production scripts.",
        "references": ["tokenExchange.sh 3.16.0", "enable_saas_reporting.py curl -k"],
    },
    {
        "id": "CWOM316-F6",
        "title": "Online upgrade downloads update tarball from vmturbo.com without integrity verification",
        "severity": "LOW",
        "component": "onlineUpgrade.sh (bin.tar)",
        "evidence": [
            "sudo curl -o /mnt/iso/online-packages.tar https://download.vmturbo.com/appliance/download/updates/${turboVersion}/online-packages.tar",
            "# no --cacert, no hash verification, no signature check on downloaded tarball",
        ],
        "detail": (
            "onlineUpgrade.sh downloads an update tarball from download.vmturbo.com using "
            "curl with system CAs (no -k) but performs no integrity check on the downloaded "
            "tarball before applying it. The URL path includes ${turboVersion} which is "
            "script-derived; there is no version pinning via a hash or signature. "
            "After download, the tarball is applied directly without any verification step. "
            "This means a CDN or DNS compromise targeting download.vmturbo.com would deliver "
            "a malicious update tarball that is applied without detection. "
            "The TLS channel protects against passive interception but not against "
            "server-side compromise or DNS hijack."
        ),
        "impact": (
            "Malicious online update package applied without detection if download.vmturbo.com "
            "CDN or DNS is compromised. All CWOM appliances using online upgrade are affected."
        ),
        "remediation": "Publish a SHA256 manifest alongside each update tarball. Verify the downloaded tarball hash before applying. Consider code-signing the update tarball and verifying the signature before execution.",
        "references": ["onlineUpgrade.sh 3.16.0", "download.vmturbo.com update pipeline"],
    },
]


def run():
    for f in FINDINGS:
        sev = f["severity"]
        print(f"[{sev}] {f['id']}: {f['title']}")
        for e in f["evidence"]:
            print(f"    {e!r}")
        print()


if __name__ == "__main__":
    run()
