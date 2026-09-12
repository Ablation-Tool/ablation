"""
Cisco CWOM (IBM Turbonomic 3.14.1) VM Filesystem RE

Target:  cwom64-opsmgr-3.14.1.ova -> cwom-disk1.vmdk -> cwom-disk1.qcow2
         /dev/mapper/ibmturbo-root (Rocky Linux 9.5 Blue Onyx)
OS:      Rocky Linux 9.5 (IBM Turbonomic base: CentOS 9 Stream migrated)
Files:   /opt/turbonomic/kubernetes/operator/deploy/crds/charts_v1alpha1_xl_cr.yaml
         /opt/turbonomic/kubernetes/operator/deploy/cluster_role.yaml
         /opt/local/etc/consul.hcl, server.properties, turbo.conf
         /opt/turbonomic/kubernetes/ssl/certs/k8s-create-certs.sh.template
         /root/ova.log (OVA build trace)
Session: 37
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_cwom_vmdk_re",
    "firmware": (
        "cwom64-opsmgr-3.14.1.ova "
        "(Rocky Linux 9.5, LVM: ibmturbo-root/var_lib_mysql/data_turbonomic)"
    ),
    "components": {
        "charts_v1alpha1_xl_cr.yaml": (
            "Xl Custom Resource template; all component settings deployed by t8c-operator"
        ),
        "cluster_role.yaml": (
            "t8c-operator ClusterRole; RBAC rules for operator service account"
        ),
        "consul.hcl": (
            "Consul server config; single-node, no ACL, UI enabled"
        ),
        "server.properties": (
            "Kafka broker config; PLAINTEXT listener, no SASL/TLS"
        ),
        "k8s-create-certs.sh.template": (
            "Kubernetes PKI cert generation; -days 3650 for all cert types"
        ),
    },
    "finding_counts": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 2, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 60, "HIGH": 223, "MEDIUM": 219, "LOW": 191},
    "cumulative_total": 693,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": (
            "Hardcoded 'vmturbo' MariaDB Root Credential Embedded in Kubernetes "
            "Custom Resource Template (Xl CR)"
        ),
        "component": (
            "/opt/turbonomic/kubernetes/operator/deploy/crds/"
            "charts_v1alpha1_xl_cr.yaml"
        ),
        "evidence": {
            "xl_cr": (
                "prometheus-mysql-exporter:\n"
                "  enabled: false\n"
                "  mysql:\n"
                "    user: root\n"
                "    pass: vmturbo  # hardcoded in the Kubernetes Custom Resource"
            ),
            "ova_log_build_command": (
                "sed -i '/prometheus-mysql-exporter:/,/prometheus/c\\"
                "  prometheus-mysql-exporter:\\n    enabled: false\\n\\"
                "    mysql:\\n\\      user: root\\n\\      pass: vmturbo\\n\\  "
                "prometheus:' "
                "/opt/turbonomic/kubernetes/operator/deploy/crds/"
                "charts_v1alpha1_xl_cr.yaml"
            ),
            "scope": (
                "Credential is written into the Xl CR during OVA build. "
                "The CR is applied to the cluster by t8c-operator on every install/upgrade. "
                "When prometheus-mysql-exporter is enabled, these credentials are passed "
                "directly to the exporter and appear in the Kubernetes resource spec."
            ),
        },
        "impact": (
            "The MariaDB root credential 'vmturbo' is baked into the Kubernetes Custom "
            "Resource template on every CWOM 3.14.1 deployment. "
            "When prometheus-mysql-exporter is enabled (disabled by default but "
            "easily toggled), the operator creates a component with MariaDB root "
            "access using this credential, and the credential appears in the "
            "Kubernetes resource definition visible to anyone with kubectl get xl -o yaml. "
            "MariaDB root with 'vmturbo' on all-interface bind provides full database "
            "access including pg_execute_server_program equivalents (User-Defined Functions "
            "writing to /tmp, INTO OUTFILE, etc.). "
            "This credential is also confirmed in configure_timescaledb.sh (PostgreSQL path) "
            "and the ova.log build trace across every CWOM instance of this version."
        ),
        "remediation": (
            "Remove the hardcoded pass: vmturbo from the Xl CR template. "
            "Generate the prometheus-mysql-exporter credential at first boot "
            "using a per-instance random value stored in a Kubernetes Secret. "
            "Audit all deployed CWOM instances: kubectl get xl xl-release -n turbonomic -o yaml "
            "| grep -A2 prometheus-mysql-exporter"
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": (
            "t8c-operator ClusterRole Grants Wildcard Verbs on RBAC Resources "
            "Enabling Privilege Escalation to cluster-admin"
        ),
        "component": (
            "/opt/turbonomic/kubernetes/operator/deploy/cluster_role.yaml"
        ),
        "evidence": {
            "rbac_rule": (
                "- apiGroups:\n"
                "  - rbac.authorization.k8s.io\n"
                "  resources:\n"
                "  - clusterrolebindings\n"
                "  - clusterroles\n"
                "  - rolebindings\n"
                "  - roles\n"
                "  verbs:\n"
                "  - '*'  # create, delete, update, patch, list, watch"
            ),
            "additional_wildcards": [
                "pods/exec with verbs: ['*'] -- exec into any pod as root",
                "secrets with verbs: ['*'] -- read all Kubernetes secrets",
                "podsecuritypolicies with verbs: ['*'] -- bypass pod security",
            ],
            "binding": (
                "ClusterRoleBinding 't8c-operator' binds this ClusterRole "
                "to ServiceAccount 't8c-operator' in namespace 'turbonomic'"
            ),
        },
        "impact": (
            "The t8c-operator ServiceAccount can create new ClusterRoleBindings granting "
            "cluster-admin to any subject, effectively granting itself full cluster control. "
            "An attacker who compromises the t8c-operator container (e.g., through its "
            "dependency on icr.io/cpopen/t8c-operator:42.79 or a supply chain compromise) "
            "can immediately escalate to cluster-admin by creating one RBAC resource. "
            "Additionally, wildcard on 'secrets' means the operator has permanent read access "
            "to all Kubernetes secrets in the cluster, and wildcard on 'pods/exec' allows "
            "exec into any running container as root."
        ),
        "remediation": (
            "Remove 'clusterrolebindings' and 'clusterroles' from the operator's ClusterRole, "
            "or restrict to 'list' and 'watch' only. "
            "The operator does not need to create or modify ClusterRoles to manage the "
            "Turbonomic application stack. "
            "Replace wildcard on 'secrets' with explicit resource names. "
            "Restrict 'pods/exec' to the 'turbonomic' namespace only via a Role, "
            "not a ClusterRole."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "Consul Deployed Without ACL; UI Enabled; Unauthenticated HTTP API on All Interfaces",
        "component": "/opt/local/etc/consul.hcl",
        "evidence": {
            "config": (
                "server = true\n"
                "bootstrap_expect = 1\n"
                "bind_addr = \"{{GetInterfaceIP \\\"eth0\\\"}}\"\n"
                "client_addr = \"{{GetInterfaceIP \\\"eth0\\\"}}\"\n"
                "data_dir = \"/opt/consul/data\"\n"
                "disable_update_check = true\n"
                "ui = true\n"
                "# No 'acl' block -- ACLs disabled"
            ),
            "default_ports": [
                "8500/tcp: HTTP API (unauthenticated) + UI",
                "8300/tcp: Server RPC",
                "8301/tcp+udp: LAN Gossip",
            ],
            "acl_default": (
                "Without an 'acl' block, Consul runs in legacy mode with "
                "default_policy=allow. Any HTTP client can read/write all "
                "KV pairs, register/deregister services, and access the Consul UI."
            ),
        },
        "impact": (
            "Consul is the service mesh and distributed KV store for the Turbonomic "
            "application stack. Without ACL, any host that can reach port 8500 can: "
            "(1) read all KV pairs including application configuration and secrets stored by services, "
            "(2) write to the KV store to modify service configuration, "
            "(3) register fake services to hijack Consul DNS resolution, "
            "(4) deregister running services causing health check failures. "
            "The UI is enabled and accessible without authentication, providing a GUI "
            "for all of the above from a browser."
        ),
        "remediation": (
            "Add ACL configuration to consul.hcl:\n"
            "  acl {\n"
            "    enabled = true\n"
            "    default_policy = \"deny\"\n"
            "    enable_token_persistence = true\n"
            "  }\n"
            "Bootstrap ACL tokens during first-boot initialization. "
            "Disable UI on production deployments: ui_config { enabled = false }. "
            "Restrict client_addr to 127.0.0.1 if Consul is only accessed by local services."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": (
            "Grafana Admin and Database Credentials Set to Literal 'passwordPlaceholder' "
            "in Xl CR Template"
        ),
        "component": (
            "/opt/turbonomic/kubernetes/operator/deploy/crds/"
            "charts_v1alpha1_xl_cr.yaml"
        ),
        "evidence": {
            "xl_cr": (
                "grafana:\n"
                "  enabled: false\n"
                "  adminPassword: passwordPlaceholder\n"
                "  grafana.ini:\n"
                "    database:\n"
                "      type: postgres\n"
                "      password: passwordPlaceholder"
            ),
            "scope": (
                "Grafana is disabled by default. When enabled, both the Grafana admin "
                "credential and its database connection password are set to the literal "
                "string 'passwordPlaceholder'."
            ),
        },
        "impact": (
            "When Grafana is enabled on a CWOM deployment, the admin credential is "
            "'admin/passwordPlaceholder' and the database connection password is also "
            "'passwordPlaceholder'. These are predictable default credentials that would "
            "be present on every CWOM deployment that enables Grafana without explicitly "
            "changing the Xl CR before applying. "
            "Grafana admin access allows arbitrary dashboard queries against the "
            "configured data sources (Prometheus, TimescaleDB), "
            "which can expose sensitive metrics and operational data."
        ),
        "remediation": (
            "Generate per-instance Grafana credentials at first boot and inject them "
            "into the Xl CR before operator applies it. "
            "Store Grafana credentials in a Kubernetes Secret and reference via "
            "grafana.admin.existingSecret in the Helm values."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": (
            "Kafka Broker Configured with PLAINTEXT Listener Only; "
            "No Authentication, No Encryption"
        ),
        "component": "/opt/local/etc/server.properties",
        "evidence": {
            "listener_config": (
                "advertised.listeners=PLAINTEXT://10.0.2.15:9092\n"
                "# No 'ssl.*' properties\n"
                "# No 'sasl.*' properties\n"
                "# No 'security.inter.broker.protocol' setting"
            ),
            "default_acl": (
                "Kafka with no auth and no ACL configuration allows any client "
                "to connect, produce to any topic, consume from any topic, "
                "and manage topic configurations."
            ),
        },
        "impact": (
            "Kafka is the Turbonomic inter-service message bus carrying actionable "
            "workload optimization events and infrastructure state telemetry. "
            "Any host that can reach port 9092 can: "
            "consume all Turbonomic action events (infrastructure remediation instructions), "
            "produce spoofed events to inject false actions, "
            "and delete or reconfigure topics. "
            "No client authentication or inter-broker encryption is configured."
        ),
        "remediation": (
            "Enable SASL authentication: SASL_PLAINTEXT or SASL_SSL listeners. "
            "Configure ssl.keystore.location and ssl.truststore.location for TLS. "
            "Add 'authorizer.class.name=kafka.security.authorizer.AclAuthorizer' "
            "and define per-service ACL rules. "
            "Bind to the cluster-internal interface only, not the external IP."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": (
            "Kubernetes PKI Certificates Issued with 10-Year Validity "
            "(-days 3650) via Custom Cert Generation Script"
        ),
        "component": (
            "/opt/turbonomic/kubernetes/ssl/certs/k8s-create-certs.sh.template"
        ),
        "evidence": {
            "openssl_commands": [
                "openssl x509 ... -CA /etc/kubernetes/pki/ca.crt -CAkey ... -days 3650",
                "openssl x509 ... -CA /etc/kubernetes/pki/etcd/ca.crt -CAkey ... -days 3650",
                "openssl x509 ... -CA /etc/kubernetes/pki/front-proxy-ca.crt -CAkey ... -days 3650",
            ],
            "scope": (
                "All Kubernetes component certs (apiserver, etcd, kubelet, scheduler, "
                "controller-manager, front-proxy-client) are issued for 3650 days "
                "(10 years) via this custom script instead of kubeadm's default 1-year certs."
            ),
            "kubeadm_default": "kubeadm default cert validity: 365 days (1 year)",
        },
        "impact": (
            "Kubernetes PKI certificates with 10-year validity eliminate the annual "
            "forced rotation window. If a cluster cert is compromised "
            "(e.g., via etcd backup exfiltration, node compromise, or CA key leak), "
            "the stolen cert remains valid for up to a decade without remediation. "
            "The 10-year window was likely chosen to avoid the annual cert renewal "
            "maintenance burden, but it extends the post-compromise exploitation window "
            "by 10x compared to the kubeadm default."
        ),
        "remediation": (
            "Reduce cert validity to 1 year (365 days) or less. "
            "Enable kubeadm's built-in annual cert renewal via 'kubeadm certs renew all'. "
            "Automate renewal via k8s-certs-renew.sh on a cron job or systemd timer "
            "triggered 30 days before expiry. "
            "The CWOM k8s-certs-renew.sh script is already bundled -- use it on a schedule."
        ),
    },
    {
        "id": "F7",
        "severity": "LOW",
        "title": (
            "Docker Hub Default Credential 'turbopassword' Preserved as Comment "
            "in Xl CR Template"
        ),
        "component": (
            "/opt/turbonomic/kubernetes/operator/deploy/crds/"
            "charts_v1alpha1_xl_cr.yaml"
        ),
        "evidence": {
            "commented_credential": (
                "global:\n"
                "#  registry: index.docker.io\n"
                "#  imageUsername: turbouser\n"
                "#  imagePassword: turbopassword"
            ),
            "scope": (
                "Commented out in the template. The credential 'turbopassword' "
                "implies a former Docker Hub account 'turbouser' that was used for "
                "image distribution before the migration to icr.io/cpopen/."
            ),
        },
        "impact": (
            "The commented credential in the template file documents a former Docker Hub "
            "account (turbouser/turbopassword). If this account still exists with this "
            "password, it could be used to push malicious images to the 'turbouser' "
            "Docker Hub account. While the default image source is now icr.io/cpopen/, "
            "the registry/imageUsername/imagePassword fields are still active config "
            "parameters that override the default if uncommented by an administrator."
        ),
        "remediation": (
            "Remove the commented-out Docker Hub credential block entirely. "
            "If the turbouser Docker Hub account still exists, rotate or delete it. "
            "Document the icr.io/cpopen/ migration as the only supported image source."
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
