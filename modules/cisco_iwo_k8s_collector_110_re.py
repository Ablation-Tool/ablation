"""
Cisco IWO (Intersight Workload Optimizer) Kubernetes Collector 1.10.0 — RE Module
Source: iwo-k8s-collector-1.10.0.tgz (/media/cowboy/research/Cisco-UCS/)
Format: Helm chart (Chart.yaml version 1.10.0)
Images: intersight/pasadena:1.0.11-20250604055421206 (cloud connector)
        intersight/kubeturbo:8.15.2.1 (k8s collector)
"""

FIRMWARE = {
    "target":   "Cisco IWO Kubernetes Collector",
    "version":  "1.10.0",
    "source":   "iwo-k8s-collector-1.10.0.tgz",
    "type":     "Helm chart",
    "images": {
        "connector": "intersight/pasadena:1.0.11-20250604055421206",
        "collector": "intersight/kubeturbo:8.15.2.1",
    },
    "findings": ["IWO-F1"],
}

# ─────────────────────────────────────────────────────────
# IWO-F1: Default Helm values ship with roleName = "cluster-admin"
#         — iwo-user ServiceAccount gets full Kubernetes cluster-admin ClusterRole by default
# ─────────────────────────────────────────────────────────
IWO_F1 = {
    "id":       "IWO-F1",
    "title":    "iwo-k8s-collector Helm chart default values.yaml sets roleName='cluster-admin' — "
                "iwo-user ServiceAccount is bound to the built-in cluster-admin ClusterRole on install",
    "status":   "CONFIRMED — values.yaml:roleName and templates/serviceaccount.yaml ClusterRoleBinding in iwo-k8s-collector-1.10.0.tgz",
    "severity": "HIGH",

    "default_values": (
        "# values.yaml (shipped default):\n"
        "roleName: \"cluster-admin\"\n"
        "replicaCount: 2\n"
        "\n"
        "# templates/serviceaccount.yaml ClusterRoleBinding (always created):\n"
        "kind: ClusterRoleBinding\n"
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "metadata:\n"
        "  name: iwo-all-binding\n"
        "subjects:\n"
        "  - kind: ServiceAccount\n"
        "    name: iwo-user\n"
        "roleRef:\n"
        "  kind: ClusterRole\n"
        "  name: {{ .Values.roleName }}   # = cluster-admin when default\n"
        "  apiGroup: rbac.authorization.k8s.io"
    ),

    "role_options": (
        "The template supports three roleName values:\n"
        "  'cluster-admin'     — full built-in ClusterRole (default shipped)\n"
        "  'iwo-cluster-admin' — custom ClusterRole with node/pod/deployment write + read-only others\n"
        "  'iwo-cluster-reader' — read-only ClusterRole\n"
        "The default 'cluster-admin' is the most permissive option. "
        "The custom scoped roles (iwo-cluster-admin/iwo-cluster-reader) are provided "
        "as explicitly opt-in alternatives but are not the default."
    ),

    "attack_surface": (
        "The iwo-user ServiceAccount token is mounted into every collector pod "
        "(2 replicas by default, StatefulSet). The token provides full cluster-admin access:\n"
        "  - kubectl exec into any pod\n"
        "  - kubectl get secrets (all namespaces, all secrets)\n"
        "  - Create/delete RBAC, namespaces, ClusterRoles\n"
        "  - Access all Kubernetes API endpoints\n"
        "Attack path:\n"
        "  1. Gain code execution in any iwo-k8s-collector pod (via container escape, RCE in collector)\n"
        "  2. Read /var/run/secrets/kubernetes.io/serviceaccount/token\n"
        "  3. kubectl --token=<sa-token> get secrets -A → full cluster credential dump"
    ),

    "remediation": (
        "Install with --set roleName=iwo-cluster-reader (read-only monitoring) "
        "or roleName=iwo-cluster-admin (scoped admin) depending on the actions required. "
        "Do not use the default 'cluster-admin' in production. "
        "Reference: templates/serviceaccount.yaml defines the scoped ClusterRoles inline "
        "— they are available without any additional config."
    ),

    "connector_note": (
        "The pasadena (Intersight cloud connector) image is the same 'andromeda/an-apollo' "
        "package seen in UCS FI 6.0(2b)A install-connector.sh. "
        "Its compareVersion() '0.1.0' bypass (UCSM-F5) is relevant in the FI context "
        "but not directly exploitable via the IWO Helm chart install path."
    ),
}

FINDINGS = [IWO_F1]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
