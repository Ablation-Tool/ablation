"""
Cisco Workload Optimization Manager (CWOM64) 3.14.1 — RE Module
Source: cwom64-opsmgr-3.14.1.ova (Workload Optimization Manager 3/ subdirectory)
        update64_package-3.16.0.iso (update ISO — structural reference)
OVF name: cisco-t8c-3.14.1-20250508211123000 (built 2025-05-08)

Technology: Turbonomic t8c platform (IBM OEM)
OVF OS designation: centos9_64Guest (actual: Rocky Linux 9.5 Blue Onyx)
Disk layout (LVM VG ibmturbo, 1.75TB virtual):
  root            100GB  XFS  — OS root filesystem
  usr_local_bin   100GB  XFS  — kubectl, nerdctl, calicoctl, skupper, pip
  var             301GB  XFS  — /var (kubelet, MariaDB base)
  var_lib_mysql   800GB  XFS  — MariaDB data directory (pre-populated base)
  var_lib_containerd 230GB XFS — containerd images / Kubernetes state
  data_turbonomic 256GB  XFS  — Turbonomic application data (empty in base OVA)
  tmp               4GB  XFS  — /tmp

Architecture: Single-node Kubernetes cluster with Turbonomic components.
Kubernetes not initialized in base OVA — cluster state populated at first boot.
"""

FIRMWARE = {
    "target":  "Cisco Workload Optimization Manager (CWOM64) / Turbonomic t8c",
    "version": "3.14.1 (t8c build, Turbonomic 8.18)",
    "source":  "cwom64-opsmgr-3.14.1.ova",
    "os":      "Rocky Linux 9.5 (Blue Onyx)",
    "lvm_vg":  "ibmturbo",
    "findings": ["CWOM-F1", "CWOM-F2", "CWOM-F3"],
}

# ─────────────────────────────────────────────────────────
# CWOM-F1: root and turbo accounts both use the well-known vmturbo default password
#          — SHA-512 hashes cracked to 'vmturbo' in single-pass wordlist check
# ─────────────────────────────────────────────────────────
CWOM_F1 = {
    "id":       "CWOM-F1",
    "title":    "CWOM64 3.14.1 root and turbo accounts deployed with identical default password 'vmturbo' — "
                "SHA-512 hashes cracked; both accounts share the legacy VMturbo default credential",
    "status":   "CONFIRMED — /etc/shadow from ibmturbo/root LV (Rocky Linux 9.5, SHA-512)",
    "severity": "CRITICAL",

    "password": "vmturbo",

    "shadow_entries": {
        "root":  "$6$abCocSUEMHOOX38a$ITWqbBk1kiIPA9bPAXvQ1Tu3.ffCtltVwcFiM8uOrIq/R.OIjmA6gWmjQaLZYfOa8ubGuY5eUrivKMZDmJnBl/",
        "turbo": "$6$Fx9UpxFaHeo.a7TC$2MDopykChtPzZkkZTxYty5N/EZNVhYo21eFkSjMIGDLqbJYb5V1/grRWHqH/X1.YLtn7CSG5vTOOfwyPmkuVM/",
    },

    "algorithm": "SHA-512 ($6$), identical plaintext 'vmturbo' for both accounts",

    "turbo_user": {
        "uid":   1000,
        "home":  "/opt/turbonomic",
        "shell": "/bin/bash",
        "note":  "Application service user. vmturbo is the original VMturbo-era default that persisted through Cisco's acquisition.",
    },

    "sshd_state": {
        "PasswordAuthentication": "default (yes, since not explicitly overridden in sshd_config.d/50-redhat.conf)",
        "PermitRootLogin":        "default (prohibit-password — root SSH requires pubkey, but console and su paths are open)",
        "note": "sshd_config contains all-commented defaults. 50-redhat.conf from distro does not restrict PasswordAuthentication.",
    },

    "analysis": (
        "'vmturbo' is the well-documented default credential for Cisco Workload Optimization Manager / "
        "IBM Turbonomic, published in official documentation and CVE disclosures. "
        "Both root and turbo carry the same SHA-512 hash of this password in the base OVA. "
        "Any deployment that has not changed the default credential (a non-trivial percentage "
        "of production deployments) is directly accessible: "
        "turbo@<host> with password vmturbo → full login → sudo su root (CWOM-F2). "
        "The turbo account's home /opt/turbonomic is the Turbonomic application base directory — "
        "login as turbo provides immediate access to application configuration, kubernetes credentials, "
        "and SSL certificates."
    ),
}

# ─────────────────────────────────────────────────────────
# CWOM-F2: turbo group has unrestricted NOPASSWD:ALL sudo
#          — turbo user login = immediate root without additional credential
# ─────────────────────────────────────────────────────────
CWOM_F2 = {
    "id":       "CWOM-F2",
    "title":    "CWOM64 sudoers grants '%turbo' group NOPASSWD:ALL — turbo user login "
                "provides unrestricted root access without password prompt",
    "status":   "CONFIRMED — /etc/sudoers.d/turbo from ibmturbo/root LV",
    "severity": "CRITICAL",

    "sudoers_file": "/etc/sudoers.d/turbo",

    "sudoers_rules": {
        "unrestricted": "%turbo        ALL=(ALL)       NOPASSWD: ALL",
        "kube_commands": "KUBE ALL = (ALL) NOPASSWD:/usr/bin/pip, /usr/sbin/visudo, "
                         "/usr/local/bin/kubectl, /usr/sbin/wipefs, /opt/local/bin/*, "
                         "/usr/sbin/vgremove, /usr/sbin/modprobe, /usr/sbin/setsebool, "
                         "/usr/local/bin/crictl, /usr/local/bin/nerdctl, /usr/local/bin/ctr",
        "Defaults": "Defaults:KUBE !requiretty",
    },

    "privilege_chain": (
        "vmturbo password → turbo login → %turbo group membership → "
        "sudo any command (NOPASSWD:ALL) → root"
    ),

    "kube_commands_impact": (
        "In addition to unrestricted sudo, the KUBE alias grants kubectl (full k8s API), "
        "nerdctl/crictl/ctr (container runtime management), vgremove (LVM volume group deletion), "
        "wipefs (filesystem/partition wipe), and modprobe (kernel module loading) — "
        "all without password. Post-initialization, kubectl access with the cluster-admin "
        "kubeconfig provides full Kubernetes API access including secret extraction."
    ),

    "analysis": (
        "The turbo user is both the application service account AND a member of the turbo group "
        "with unrestricted passwordless sudo. The design conflates the least-privilege service "
        "account role (run application processes) with a system administration role "
        "(manage Kubernetes, containers, storage). Any process running as turbo can escalate "
        "to root without authentication. Post-deployment, when the Kubernetes cluster is running, "
        "the combination of kubectl access + CWOM-F1's default credential represents "
        "full cluster compromise from a single stolen credential."
    ),
}

# ─────────────────────────────────────────────────────────
# CWOM-F3: Kubernetes operator RBAC binding uses cluster-admin ClusterRole for t8c-operator
# ─────────────────────────────────────────────────────────
CWOM_F3 = {
    "id":       "CWOM-F3",
    "title":    "CWOM64 t8c-operator ClusterRole can read all secrets AND create/modify ClusterRoleBindings "
                "— functional cluster-admin via RBAC escalation path",
    "status":   "CONFIRMED — operator/deploy/cluster_role.yaml and cluster_role_binding.yaml in ibmturbo/root LV",
    "severity": "HIGH",

    "binding": {
        "file":      "/opt/turbonomic/kubernetes/operator/deploy/cluster_role_binding.yaml",
        "subject":   "ServiceAccount t8c-operator (namespace: turbonomic)",
        "roleRef":   "ClusterRole: t8c-operator (custom role, not built-in cluster-admin)",
    },

    "critical_permissions_in_cluster_role": {
        "secrets_wildcard": "apiGroups: [''], resources: [secrets], verbs: ['*'] — read all secrets cluster-wide",
        "pods_exec":        "resources: [pods/exec], verbs: ['*'] — exec into any pod",
        "rbac_escalation":  "apiGroups: [rbac.authorization.k8s.io], resources: [clusterrolebindings, clusterroles, rolebindings], verbs: [create, patch, delete, update]",
        "serviceaccounts":  "resources: [serviceaccounts], verbs: ['*'] — create new SAs",
    },

    "escalation_path": (
        "t8c-operator SA → can create new ClusterRoleBinding → "
        "bind any SA (including newly-created) to cluster-admin → "
        "full cluster compromise"
    ),

    "analysis": (
        "The t8c-operator ClusterRole is not cluster-admin by name but is equivalent in practice. "
        "Any subject with permission to create ClusterRoleBindings can grant cluster-admin to itself. "
        "Additionally, wildcard secrets access cluster-wide means every credential in every namespace "
        "(database passwords, TLS keys, API tokens) is directly readable by the operator. "
        "pods/exec access means the operator can execute arbitrary commands in any running pod, "
        "bypassing container security policies. "
        "Combined with CWOM-F1 and CWOM-F2, full cluster compromise from the OVA default state "
        "requires: (1) authenticate as turbo with vmturbo, (2) access post-boot kubeconfig at "
        "/etc/kubernetes/admin.conf or /opt/turbonomic/.kube/config, (3) kubectl create clusterrolebinding."
    ),
}

# ─────────────────────────────────────────────────────────
# CWOM-F4: MariaDB root password hardcoded as 'vmturbo' in migration/xl-backup.sh
#          — database root credential exposed in update ISO migration scripts
# ─────────────────────────────────────────────────────────
CWOM_F4 = {
    "id":       "CWOM-F4",
    "title":    "CWOM64 migration script xl-backup.sh hardcodes MariaDB root password 'vmturbo' — "
                "'mysql -uroot -pvmturbo' in update64_package-3.16.0.iso migration/xl-backup.sh",
    "status":   "CONFIRMED — xl-backup.sh extracted from migration.tar in update64_package-3.16.0.iso",
    "severity": "CRITICAL",

    "password":     "vmturbo",
    "credential":   "MariaDB root user",

    "source": {
        "iso":     "update64_package-3.16.0.iso",
        "archive": "migration.tar",
        "file":    "migration/xl-backup.sh",
        "snippet": "mapfile -t schemas < <(mysql -uroot -pvmturbo -s --skip-column-names -e \"${SQL_COMMAND}\")",
    },

    "scope": (
        "The 'vmturbo' password is the default MariaDB root credential across all CWOM/Turbonomic "
        "deployments. Combined with CWOM-F1 (same password for Linux root and turbo), "
        "'vmturbo' is the single default credential spanning all three authentication boundaries: "
        "Linux OS (root), application service account (turbo), and database (MariaDB root). "
        "The MariaDB root account has unrestricted access to all databases including the "
        "Turbonomic application data (target topology, workload data, integrated service credentials)."
    ),

    "xl_backup_also_exposes": [
        "kubectl get secrets -n turbonomic redis → Redis authentication secret",
        "kubectl get secrets -n turbonomic master-key-secret → Turbonomic master encryption key",
        "kubectl get secrets -n turbonomic auth-secret → Authentication secrets",
    ],

    "analysis": (
        "The backup script uses the hardcoded credential for production database operations — "
        "not just initialization. Any operator running the official Cisco-provided backup procedure "
        "on an instance that has changed the MariaDB root password will fail. "
        "This creates pressure to KEEP the default password, as changing it breaks the official tooling "
        "unless the migration script is manually updated. "
        "The pattern across CWOM-F1 through CWOM-F4 shows that 'vmturbo' is an operational dependency "
        "embedded in the product's management toolchain, not just an install-time convenience."
    ),
}

FIRMWARE["findings"].append("CWOM-F4")

FINDINGS = [CWOM_F1, CWOM_F2, CWOM_F3, CWOM_F4]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
