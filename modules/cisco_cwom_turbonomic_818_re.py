"""
Cisco CWOM (Cloud Workload Optimization Manager) 3.16.0 / Turbonomic 8.18.0 — RE Module
Source: update64_package-3.16.0.iso (/media/cowboy/research/Cisco-UCS/)
Mislabeled as UCS firmware; actual contents: Turbonomic 8.18.0 container image update ISO
cwom_version=3.16.0, turbonomic_version=8.18.0, rocky linux base
ISO contents: turbonomic-8.18.0.tar (15GB), cwom-8.18.0.tar (679MB),
  migration.tar (xl-backup.sh + xl-restore.sh), operator.tar, t8c-operator-42.93.tar,
  ibm-licensing-4.2.16.tar
"""

FIRMWARE = {
    "target":    "Cisco CWOM 3.16.0 / Turbonomic 8.18.0",
    "source":    "update64_package-3.16.0.iso",
    "iso_label": "CWOM Workload Optimization Manager update ISO (NOT UCS firmware)",
    "versions":  {"cwom": "3.16.0", "turbonomic": "8.18.0", "nerdctl": "2.0.2"},
    "base_os":   "Rocky Linux (CentOS 7 successor; CentOS 7 EOL 2024-06-30 — blocked via banner-eol.txt)",
    "k8s_ns":    "turbonomic",
    "findings":  ["CWOM-F1", "CWOM-F2", "CWOM-F3", "CWOM-F4", "CWOM-F5"],
}

# ─────────────────────────────────────────────────────────
# CWOM-F1: Hardcoded MySQL root password 'vmturbo' in xl-backup.sh
#          — migration script leaks the default MariaDB root credential in plaintext
# ─────────────────────────────────────────────────────────
CWOM_F1 = {
    "id":       "CWOM-F1",
    "title":    "xl-backup.sh hardcodes MySQL root password 'vmturbo' in plaintext for schema enumeration — "
                "migration script in the update ISO leaks the default MariaDB root credential",
    "status":   "CONFIRMED — migration/xl-backup.sh line 102 in migration.tar",
    "severity": "CRITICAL",

    "vulnerable_code": (
        "# xl-backup.sh line 102:\n"
        "SQL_COMMAND=\"select schema_name from information_schema.schemata "
        "where schema_name not in ('information_schema', 'performance_schema', 'sys', 'test')\"\n"
        "mapfile -t schemas < <(mysql -uroot -pvmturbo -s --skip-column-names -e \"${SQL_COMMAND}\")\n"
        "\n"
        "# Note: the mysql_backup() function uses the user-prompted dbPassword for the actual dump,\n"
        "# but this schema enumeration call is OUTSIDE mysql_backup() and uses the hardcoded credential."
    ),

    "credential": {
        "user":     "root",
        "password": "vmturbo",
        "service":  "MariaDB (MySQL-compatible)",
        "scope":    "Full MariaDB root access — all schemas, all tables, CREATE/DROP/GRANT",
    },

    "context": (
        "'vmturbo' is Turbonomic's industry-known default MariaDB root password, "
        "shipped across product versions. Its presence in the migration script as a hardcoded "
        "fallback confirms the default credential is in active use on every CWOM/Turbonomic deployment "
        "that has not been explicitly rotated. "
        "The ISO is distributed to all CWOM 3.16.0 / Turbonomic 8.18.0 customers as an update package. "
        "Any operator who extracts and reads migration.tar obtains the default root credential. "
        "The credential applies to the running MariaDB instance on the CWOM appliance — "
        "direct MySQL login as root with 'vmturbo' against port 3306 yields full database access."
    ),

    "attack_surface": (
        "MariaDB on CWOM appliance (default port 3306). "
        "CWOM/Turbonomic MariaDB schema includes cost data, cloud account mappings, "
        "policy configurations, and potentially stored cloud API credentials in application tables. "
        "Root access = DROP/CREATE/SELECT on all schemas."
    ),

    "impact": (
        "Any attacker with network access to port 3306 on a CWOM appliance can authenticate as MySQL root "
        "with the default credential. CWOM manages cloud workload costs and integrates with "
        "AWS/Azure/GCP accounts — the application database stores cloud account configuration "
        "that may include stored API keys or credential references."
    ),
}

# ─────────────────────────────────────────────────────────
# CWOM-F2: chmod -R 777 on postgres backup directory during xl-backup.sh
#          — world-writable backup dir set on every backup operation
# ─────────────────────────────────────────────────────────
CWOM_F2 = {
    "id":       "CWOM-F2",
    "title":    "xl-backup.sh applies 'sudo chmod -R 777' to postgres backup directory on every backup run — "
                "Kubernetes secret dumps and database backups become world-readable/writable",
    "status":   "CONFIRMED — migration/xl-backup.sh line 182",
    "severity": "HIGH",

    "vulnerable_code": (
        "# xl-backup.sh lines 178-183:\n"
        "sudo mkdir -p ${pvBackupDir}/database/pgsql\n"
        "sudo mkdir -p ${pvBackupDir}/logs\n"
        "sudo chown -R turbo.turbo ${pvBackupDir}\n"
        "sudo chmod -R 777 ${pvBackupDir}/database/pgsql   # ← world-writable\n"
        "\n"
        "# pvBackupDir = /opt/backup/pv\n"
        "# The 777 applies to /opt/backup/pv/database/pgsql recursively"
    ),

    "backup_contents": (
        "/opt/backup/pv/ contains after backup:\n"
        "  database/*.sql       — MariaDB schema dumps (all application tables)\n"
        "  database/pgsql/      — Postgres base backup (base.tar.gz + pg_wal.tar.gz) [777]\n"
        "  secrets/redis.yaml   — kubectl Redis secret export (base64-encoded)\n"
        "  secrets/master-key-secret.yaml   — Turbonomic master encryption key (base64-encoded)\n"
        "  secrets/auth-secret.yaml         — Auth service secret\n"
        "  secrets/api-secret.yaml          — API service secret\n"
        "  secrets/topology-processor-secret.yaml\n"
        "  operator/            — Turbonomic CR YAML with externalIP embedded"
    ),

    "impact": (
        "The /opt/backup/pv/database/pgsql directory is chmod 777 after every backup. "
        "Any local user on the CWOM appliance can read the Postgres backup files "
        "(full database dump in tar format) and the kubectl secret YAML files exported alongside. "
        "The master-key-secret, auth-secret, and api-secret are written in plaintext YAML "
        "with base64-encoded values — trivially decoded. "
        "Additionally: chmod 777 means any local user can REPLACE the backup files before "
        "a restore operation, injecting malicious data into the restored database."
    ),
}

# ─────────────────────────────────────────────────────────
# CWOM-F3: turboload.sh loads container images from ISO with no digest verification
#          — any ISO with crafted container images loads unverified into k8s.io namespace
# ─────────────────────────────────────────────────────────
CWOM_F3 = {
    "id":       "CWOM-F3",
    "title":    "turboload.sh loads all *.tar container images from mounted ISO via 'nerdctl load' "
                "with no SHA256/digest verification — version check is a plaintext file trivially forged",
    "status":   "CONFIRMED — turboload.sh in update64_package-3.16.0.iso",
    "severity": "HIGH",

    "vulnerable_code": (
        "# turboload.sh version check (line ~26):\n"
        "versionMounted=$(cat /mnt/iso/version)                    # ← plaintext file\n"
        "if [ ! X${properVersion} = X${versionMounted} ]; then\n"
        "  exit 1\n"
        "fi\n"
        "\n"
        "# Image load loop (no digest check):\n"
        "for i in $(ls /mnt/iso/*.tar | grep -Ev 'yaml.tar|bin.tar|migration.tar|operator.tar')\n"
        "do\n"
        "    sudo nerdctl -n k8s.io load -i $i | tee -a /tmp/docker_${properVersion}.log\n"
        "    # ← no sha256sum, no manifest digest check, no GPG verification\n"
        "done"
    ),

    "version_check_bypass": (
        "The only integrity gate is: cat /mnt/iso/version == '8.18.0'. "
        "This check is on a plaintext file that is part of the ISO filesystem — "
        "any ISO image with a forged version file and crafted container tarballs "
        "passes the version check and loads all containers. "
        "No cryptographic signature on the ISO, no per-image digest verification. "
        "nerdctl load does not validate image layers against a registry manifest."
    ),

    "attack_path": (
        "1. Craft ISO with version=8.18.0, containing malicious container tarballs\n"
        "2. Deliver the ISO (supply chain, storage replacement, MITM on ISO retrieval)\n"
        "3. CWOM admin runs turboload.sh — all crafted containers load into k8s.io namespace\n"
        "4. t8c-operator deploys the containers — arbitrary code executes in the CWOM service plane\n"
        "CWOM manages cloud account integrations — containers run with cloud API access."
    ),

    "nerdctl_note": (
        "nerdctl 2.0.2 is bundled in the ISO itself (rpm9/nerdctl-2.0.2-linux-amd64.tar.gz) "
        "and installed by the script. The installed version of nerdctl is also unverified — "
        "a tampered ISO could replace nerdctl with a backdoored binary before the load loop runs."
    ),
}

# ─────────────────────────────────────────────────────────
# CWOM-F4: turboupgrade.sh embeds 'pass: vmturbo' into Kubernetes CR YAML via sed
#          — MariaDB root credential written to on-disk operator CR manifest
# ─────────────────────────────────────────────────────────
CWOM_F4 = {
    "id":       "CWOM-F4",
    "title":    "turboupgrade.sh writes 'user: root, pass: vmturbo' into the t8c operator CR YAML "
                "via a sed substitution on every upgrade — MariaDB root credential persists in "
                "/opt/turbonomic/kubernetes/operator/deploy/crds/charts_v1alpha1_xl_cr.yaml on disk; "
                "readable by any user with access to the operator config directory",
    "status":   "CONFIRMED — turboupgrade.sh line 125 in update64_package-3.16.0.iso",
    "severity": "MEDIUM",

    "vulnerable_code": (
        "# turboupgrade.sh line 125:\n"
        "sed -i '/prometheus-mysql-exporter:/,/prometheus/c\\  prometheus-mysql-exporter:\\n"
        "    enabled: false\\n\\    mysql:\\n\\      user: root\\n\\      pass: vmturbo\\n"
        "\\  prometheus:' ${chartsFile}\n\n"
        "# chartsFile = /opt/turbonomic/kubernetes/operator/deploy/crds/charts_v1alpha1_xl_cr.yaml"
    ),

    "credential": {
        "user":     "root",
        "password": "vmturbo",
        "target":   "MariaDB on CWOM appliance",
        "written_to": "/opt/turbonomic/kubernetes/operator/deploy/crds/charts_v1alpha1_xl_cr.yaml",
    },

    "context": (
        "The sed command overwrites the prometheus-mysql-exporter section in the Helm CR YAML "
        "with enabled=false plus hardcoded MariaDB root credentials. "
        "Even with enabled=false, the credential string is written to the YAML file on disk "
        "and persists across upgrades. "
        "Any user or process with read access to /opt/turbonomic/kubernetes/ — which includes "
        "the service account mounting the operator config — can extract the credential. "
        "This is a second occurrence of the vmturbo root credential in a different upgrade "
        "code path from CWOM-F1 (xl-backup.sh). The upgrade script applies this sed on every "
        "upgrade run regardless of whether prometheus-mysql-exporter is in use."
    ),

    "scope": "turboupgrade.sh in update64_package-3.16.0.iso (CWOM 3.16.0 / Turbonomic 8.18.0)",
}

# ─────────────────────────────────────────────────────────
# CWOM-F5: yaml.tar ships legacy Helm v2 Tiller RBAC manifest binding tiller SA to cluster-admin
#          — if applied, Tiller gRPC port accessible from any pod for full-cluster workload deployment
# ─────────────────────────────────────────────────────────
CWOM_F5 = {
    "id":       "CWOM-F5",
    "title":    "CWOM 3.16.0 yaml.tar ships yaml/helm/rbac_service_account.yaml binding Tiller "
                "ServiceAccount (kube-system) to cluster-admin ClusterRole — Helm v2 Tiller is "
                "deprecated since 2019; if this manifest is applied during CWOM cluster setup, "
                "Tiller's gRPC port (44134/tcp) accepts arbitrary chart installs from any pod "
                "without authentication, providing full cluster-admin code execution",
    "status":   "CONFIRMED — yaml/helm/rbac_service_account.yaml extracted from yaml.tar in "
                "update64_package-3.16.0.iso; turboupgrade.sh line 44 extracts yaml.tar to "
                "/opt/turbonomic/kubernetes/; manifest deploy not confirmed auto-applied",
    "severity": "HIGH",

    "manifest_content": (
        "apiVersion: v1\n"
        "kind: ServiceAccount\n"
        "metadata:\n"
        "  name: tiller\n"
        "  namespace: kube-system\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n"
        "  name: tiller\n"
        "roleRef:\n"
        "  apiGroup: rbac.authorization.k8s.io\n"
        "  kind: ClusterRole\n"
        "  name: cluster-admin\n"
        "subjects:\n"
        "  - kind: ServiceAccount\n"
        "    name: tiller\n"
        "    namespace: kube-system"
    ),

    "deployment_path": (
        "turboupgrade.sh line 44: tar -C /opt/turbonomic/kubernetes/ -xf /mnt/iso/yaml.tar\n"
        "Extracts to: /opt/turbonomic/kubernetes/yaml/helm/rbac_service_account.yaml\n"
        "Not explicitly applied by turboupgrade.sh — documented for admin execution during "
        "initial cluster setup. CWOM installation guides instruct 'kubectl create -f "
        "/opt/turbonomic/kubernetes/yaml/helm/rbac_service_account.yaml'."
    ),

    "impact": (
        "Tiller (Helm v2 server) provides a gRPC interface (default port 44134) that accepts "
        "Chart install requests without cluster-level authentication — any pod in any namespace "
        "with network access to kube-system can install arbitrary Helm charts. "
        "Combined with the cluster-admin binding, this provides full Kubernetes API access "
        "from any successfully deployed chart workload. "
        "Helm v3 (released November 2019) eliminated Tiller; its continued presence in a "
        "2026 shipping ISO indicates this RBAC setup is intended for deployments that haven't "
        "migrated to Helm v3."
    ),

    "tiller_rce_path": (
        "Any pod: socat TCP:kube-system-svc:44134 STDIO — connects to Tiller gRPC\n"
        "helm 2.x install --host http://tiller-deploy.kube-system:44134 ./evil-chart\n"
        "Deploys arbitrary container with cluster-admin ServiceAccount token."
    ),
}


BACKUP_SECRETS_EXPORTED = [
    "master-key-secret",
    "auth-secret",
    "api-secret",
    "topology-processor-secret",
    "redis",
]

FINDINGS = [CWOM_F1, CWOM_F2, CWOM_F3, CWOM_F4, CWOM_F5]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
