"""
Cisco CWOM (IBM Turbonomic 3.16.0) Update ISO RE

Target:  update64_package-3.16.0.iso (16GB, ISO 9660)
         cwom64-opsmgr-3.14.1.ova (21GB, base image)
Product: Cisco Workload Optimization Manager 3.16.0 / IBM Turbonomic 8.18.0
OS:      CentOS 9 Stream, Kubernetes single-node cluster
Files:   turboload.sh, turboupgrade.sh, yaml.tar, bin.tar, my.cnf,
         migration/xl-backup.sh, migration/xl-restore.sh
Session: 37
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_cwom_iso_re",
    "firmware": "update64_package-3.16.0.iso + cwom64-opsmgr-3.14.1.ova",
    "components": {
        "turboload.sh": "ISO container image loader, runs during offline update",
        "turboupgrade.sh": "Full upgrade orchestrator; sources turbo.conf + cwom.conf",
        "yaml/registry/registry.yaml": (
            "Kubernetes container registry (registry:2) + proxy DaemonSet"
        ),
        "yaml/helm/rbac_service_account.yaml": "Helm v2 Tiller ClusterRoleBinding",
        "bin/configure_mariadb.sh": "MariaDB initialization without root password",
        "bin/libs.sh + my.cnf": "MariaDB configuration (log_bin_trust, no TLS)",
    },
    "finding_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 58, "HIGH": 218, "MEDIUM": 215, "LOW": 189},
    "cumulative_total": 680,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Unauthenticated Container Registry DaemonSet with hostPort 5000 Bypasses NetworkPolicy",
        "component": "yaml/registry/registry.yaml",
        "evidence": {
            "registry_controller": (
                "apiVersion: v1\n"
                "kind: ReplicationController\n"
                "  name: turbo-registry\n"
                "  labels:\n"
                "    zone: internal   # internal NetworkPolicy zone\n"
                "  containers:\n"
                "  - name: registry\n"
                "    image: registry:2\n"
                "    env:\n"
                "    - name: REGISTRY_HTTP_ADDR\n"
                "      value: :5000  # no TLS, no auth configured\n"
            ),
            "proxy_daemonset": (
                "kind: DaemonSet\n"
                "  name: turbo-registry-proxy\n"
                "  labels:\n"
                "    zone: internal\n"
                "  containers:\n"
                "  - name: turbo-registry-proxy\n"
                "    image: gcr.io/google_containers/kube-registry-proxy:0.4\n"
                "    ports:\n"
                "    - containerPort: 80\n"
                "      hostPort: 5000  # exposed on ALL cluster nodes"
            ),
            "network_policy": (
                "zone: internal receives traffic from dmz + internal pods. "
                "DaemonSet hostPort: 5000 is NOT governed by NetworkPolicy -- "
                "it exposes the port directly on the node's network interface."
            ),
        },
        "impact": (
            "The Turbonomic/CWOM container registry runs without authentication "
            "(no REGISTRY_AUTH env var, no TLS). A DaemonSet proxy exposes it on "
            "hostPort 5000 on every cluster node. Kubernetes NetworkPolicy does not "
            "govern hostPort traffic -- any host reachable on port 5000 can push "
            "arbitrary container images to the registry without credentials. "
            "Malicious images pushed to the registry would be available for "
            "deployment by the Turbonomic operator. Additionally, gcr.io/ "
            "google_containers/kube-registry-proxy:0.4 is a deprecated, "
            "unmaintained image (kube-registry-proxy was removed from GCR)."
        ),
        "remediation": (
            "Enable REGISTRY_AUTH with htpasswd. Add TLS via REGISTRY_HTTP_TLS_CERTIFICATE "
            "and REGISTRY_HTTP_TLS_KEY. Replace the DaemonSet hostPort with a "
            "Kubernetes Service to enforce NetworkPolicy. "
            "Replace gcr.io/google_containers/kube-registry-proxy:0.4 with a maintained image."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Helm v2 Tiller ClusterRoleBinding with cluster-admin Included in 3.16.0 Update",
        "component": "yaml/helm/rbac_service_account.yaml",
        "evidence": {
            "yaml": (
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
                "  kind: ClusterRole\n"
                "  name: cluster-admin  # full cluster admin\n"
                "subjects:\n"
                "  - kind: ServiceAccount\n"
                "    name: tiller\n"
                "    namespace: kube-system"
            ),
            "helm_v2_eol": "Helm v2 (Tiller) reached EOL November 2020; Helm v3 removes Tiller entirely",
            "turboupgrade_path": (
                "turboupgrade.sh: tar -C /opt/turbonomic/kubernetes/ -xf /mnt/iso/yaml.tar\n"
                "Extracts to /opt/turbonomic/kubernetes/yaml/helm/rbac_service_account.yaml"
            ),
        },
        "impact": (
            "The CWOM 3.16.0 update ISO ships a Helm v2 Tiller ClusterRoleBinding YAML "
            "granting cluster-admin to the tiller ServiceAccount in kube-system. "
            "Helm v2 Tiller listens on gRPC port 44134 by default with no authentication. "
            "If this YAML is applied and Tiller is running, any pod or host that can reach "
            "the Tiller gRPC endpoint can deploy, modify, or delete any Kubernetes resource "
            "in any namespace as cluster-admin. "
            "This YAML is extracted by turboupgrade.sh to the operator directory during every upgrade."
        ),
        "remediation": (
            "Remove yaml/helm/rbac_service_account.yaml from the update ISO. "
            "Migrate to Helm v3 (no Tiller). "
            "Audit whether tiller ClusterRoleBinding exists on deployed instances and remove it. "
            "Verify Tiller is not running: kubectl get pods -n kube-system | grep tiller"
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "ISO Container Images Loaded Without SHA256 Verification (turbonomic_sums.txt Unused)",
        "component": "turboload.sh",
        "evidence": {
            "sums_file_exists": (
                "turbonomic_sums.txt contains SHA256 checksums for all .tar files:\n"
                "  a2183299c97... bin.tar\n"
                "  d556f261ccae... turbonomic-8.18.0.tar\n"
                "  [12 entries total]"
            ),
            "turboload_no_verify": (
                "turboload.sh never reads turbonomic_sums.txt.\n"
                "Only check: version string match (cat /mnt/iso/version == '8.18.0').\n"
                "Then: `nerdctl load -i $i` for each .tar on /mnt/iso/ directly."
            ),
            "version_bypass": (
                "Creating /mnt/iso/version with content '8.18.0' passes the only check.\n"
                "No CA signature, no GPG check on the ISO itself."
            ),
        },
        "impact": (
            "An attacker with write access to the vSphere datastore, or the ability to "
            "mount a crafted ISO image on the CWOM VM, can replace container image tarballs "
            "with malicious versions. turboload.sh will load them as long as /mnt/iso/version "
            "contains '8.18.0'. The malicious images are then deployed by the Kubernetes "
            "operator on the next upgrade cycle. The turbonomic_sums.txt file on the ISO "
            "provides false assurance -- it is never referenced by the loading script."
        ),
        "remediation": (
            "Add sha256sum -c /mnt/iso/turbonomic_sums.txt before the image loading loop. "
            "Sign the turbonomic_sums.txt with a Cisco GPG key and verify the signature. "
            "Consider signing the ISO itself with Cisco's code signing infrastructure."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "MariaDB Initialized Without Root Password; No TLS; All-Interface Bind",
        "component": "bin/configure_mariadb.sh + my.cnf",
        "evidence": {
            "init_command": (
                "sudo mysql_install_db --defaults-file=$MY_CNF --user=mysql --basedir=\"/\"\n"
                "# No --password flag; initializes with empty root password by default"
            ),
            "my_cnf_issues": {
                "log_bin_trust_function_creators": "1  # stored procs without SUPER",
                "ssl": "not configured (no require_secure_transport)",
                "bind_address": "not set (listens on 0.0.0.0:3306 by default)",
                "general_log": "'OFF'  # reduced auditability",
            },
        },
        "impact": (
            "MariaDB is initialized via mysql_install_db without a root password, "
            "leaving the root account passwordless until a subsequent hardening step runs. "
            "If the hardening step fails or is skipped, MariaDB root is accessible without "
            "authentication to any host that can reach port 3306. "
            "log_bin_trust_function_creators=1 allows any MariaDB user with CREATE ROUTINE "
            "privilege to create stored functions/procedures without SUPER, "
            "enabling privilege escalation through stored routines. "
            "No SSL enforcement means database credentials and query data transit in cleartext "
            "on the cluster network."
        ),
        "remediation": (
            "Pass --password to mysql_install_db or run mysql_secure_installation immediately after. "
            "Add require_secure_transport=ON to my.cnf. "
            "Add bind-address=127.0.0.1 or the cluster-internal address. "
            "Set log_bin_trust_function_creators=0 unless specifically required by application code."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "Cisco OEM Branch Condition Always True (Xcisco = Xcisco); IBM Patch Path Dead",
        "component": "turboupgrade.sh",
        "evidence": {
            "code": (
                "# Rebranding\n"
                "if [ Xcisco = Xcisco ]  # always true\n"
                "then\n"
                "  chmod 755 /opt/local/etc/cwom.conf\n"
                "  source /opt/local/etc/cwom.conf\n"
                "  cp /mnt/iso/cwom.conf /opt/local/etc/.\n"
                "fi\n"
                "...\n"
                "if [ Xcisco = Xcisco ]  # all Cisco-specific paths always execute\n"
                "then\n"
                "  mv /opt/local/bin /opt/local/bin-${cwomVersion}\n"
                "  ...\n"
                "  newCwomVersion=3.16.0\n"
                "else\n"
                "  newTurboVersion='8.18.0'  # IBM path is dead code\n"
                "fi"
            ),
            "implication": (
                "In IBM Turbonomic baseline, this condition would be 'if [ Xcisco = X ]' "
                "evaluating false, executing the else branch. Cisco's OEM build hardcoded "
                "it as always-true, making the 'else' IBM path unreachable dead code."
            ),
        },
        "impact": (
            "The CWOM upgrade scripts permanently diverge from IBM's upstream Turbonomic "
            "upgrade path via a compile-time branching condition that is always true. "
            "Any upstream IBM security patch that modifies the 'else' branch will never "
            "execute on CWOM instances. Cisco must independently backport any IBM security "
            "fix that touches these conditional branches. The dead-code else branches "
            "are invisible to both IBM and Cisco QA if tests don't distinguish the builds."
        ),
        "remediation": (
            "Replace the literal string comparison with a proper environment variable "
            "(e.g., CISCO_OEM=true) and document the divergence from IBM upstream. "
            "Establish a formal process for evaluating IBM Turbonomic security patches "
            "against the always-true code paths."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "MariaDB wait_timeout=86400; 24-Hour Session Persistence",
        "component": "my.cnf",
        "evidence": {
            "config": "wait_timeout = 86400  # 24 hours",
            "default": "MySQL/MariaDB default wait_timeout = 28800 (8 hours)",
        },
        "impact": (
            "MariaDB sessions remain active for up to 24 hours without activity. "
            "Compromised application sessions (stolen connection handles, "
            "process injection into running services) remain valid for the full day. "
            "Combined with no SSL enforcement and all-interface bind, a long session "
            "lifetime extends the exploitation window for network-level credential capture."
        ),
        "remediation": (
            "Reduce wait_timeout to 3600 (1 hour) or less. "
            "Set interactive_timeout separately if interactive sessions need a different value."
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
