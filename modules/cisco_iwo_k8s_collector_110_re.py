"""
Cisco IWO (Intersight Workload Optimizer) Kubernetes Collector 1.10.0 — RE Module
Source: iwo-k8s-collector-1.10.0.tgz (/media/cowboy/research/Cisco-UCS/)
Format: Helm chart (Chart.yaml, values.yaml, templates/)
"""

FIRMWARE = {
    "target":    "Cisco IWO Kubernetes Collector",
    "version":   "1.10.0",
    "source":    "iwo-k8s-collector-1.10.0.tgz",
    "chart_type": "Helm v3 StatefulSet",
    "containers": [
        "intersight/kubeturbo:8.15.2.1     — collector (kubeturbo)",
        "intersight/pasadena:1.0.11-20250604055421206 — connector (DC/IWO bridge)",
    ],
    "findings": ["IWO-F1"],
}

# ─────────────────────────────────────────────────────────
# IWO-F1: Default roleName is "cluster-admin" — Helm chart deploys with full cluster admin RBAC
# ─────────────────────────────────────────────────────────
IWO_F1 = {
    "id":       "IWO-F1",
    "title":    "IWO K8s collector Helm chart defaults roleName to 'cluster-admin' — "
                "ClusterRoleBinding grants iwo-user ServiceAccount full cluster-admin rights",
    "status":   "CONFIRMED — values.yaml and templates/serviceaccount.yaml",
    "severity": "HIGH",

    "values_yaml_default": "roleName: \"cluster-admin\"",

    "serviceaccount_template": {
        "binding": "ClusterRoleBinding iwo-all-binding → roleRef: name: {{ .Values.roleName }}",
        "subject": "ServiceAccount iwo-user (namespace: {{ .Release.Namespace }})",
        "note":    "The template conditionally creates ClusterRole definitions ONLY for "
                   "'iwo-cluster-reader' and 'iwo-cluster-admin' custom roles. "
                   "When roleName='cluster-admin' (the default), no ClusterRole is created — "
                   "the binding references the built-in cluster-admin role directly.",
    },

    "least_privilege_alternative": "roleName: iwo-cluster-reader",

    "analysis": (
        "The default Helm values bind the iwo-user ServiceAccount to the cluster-admin ClusterRole. "
        "cluster-admin is the highest privilege role in Kubernetes — it grants unrestricted access "
        "to all resources and namespaces. Any compromise of the kubeturbo or pasadena container "
        "(via container escape, image substitution, or exec) provides full cluster control: "
        "arbitrary pod creation, secret reads across all namespaces, and node manipulation. "
        "The chart defines a read-only alternative ('iwo-cluster-reader') that restricts "
        "to get/watch/list operations — the optimization use case only requires read access "
        "to compute resource metrics. A write-capable role ('iwo-cluster-admin') is also defined "
        "but still narrower than cluster-admin. The least-privilege path is to deploy with "
        "'--set roleName=iwo-cluster-reader' unless workload optimization actions are needed, "
        "in which case 'iwo-cluster-admin' is the appropriate scope."
    ),

    "security_context_note": (
        "The StatefulSet does include a non-root security context "
        "(runAsUser: 1000, runAsGroup: 3000, fsGroup: 2000) which limits intra-pod privilege. "
        "However, the ServiceAccount token mounted at /var/run/secrets/kubernetes.io/serviceaccount "
        "still carries the cluster-admin binding — a container compromise with access to "
        "that token gives full API server access regardless of the container's UID."
    ),
}

FINDINGS = [IWO_F1]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
