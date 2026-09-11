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
    "findings": ["IWO-F1", "IWO-F2", "IWO-F3"],
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

# ─────────────────────────────────────────────────────────
# IWO-F2: turboServer configured as plaintext HTTP in ConfigMap
#          All cluster topology data sent to topology-processor:8080 without TLS
# ─────────────────────────────────────────────────────────
IWO_F2 = {
    "id":       "IWO-F2",
    "title":    "IWO ConfigMap sets turboServer to cleartext HTTP (http://topology-processor:8080) "
                "— all cluster topology data transmitted unencrypted within the cluster network",
    "status":   "CONFIRMED — templates/configmap.yaml iwoServerVersion block",
    "severity": "MEDIUM",

    "configmap_value": '"turboServer": "http://topology-processor:8080"',

    "data_in_transit": (
        "The kubeturbo collector continuously sends pod resource usage, node specs, "
        "deployment metadata, and service endpoint data to topology-processor over HTTP. "
        "In a default Kubernetes cluster without NetworkPolicy restrictions, any pod "
        "in any namespace can establish a connection to topology-processor:8080 and "
        "receive or inject data. The proxy port (9004 on the pasadena container) uses "
        "a separate channel; the topology data path is unencrypted."
    ),

    "threat": (
        "In a compromised cluster or shared-tenant environment, an attacker with a pod in "
        "any namespace can sniff the kubeturbo → topology-processor channel to exfiltrate "
        "full cluster topology (node capacity, pod placements, resource limits). "
        "A malicious pod could also inject false topology data to cause IWO to make "
        "incorrect optimization decisions (VM migration, pod eviction, resource reservation)."
    ),
}

# ─────────────────────────────────────────────────────────
# IWO-F3: Container images pulled from public Docker Hub without digest pinning
#          intersight/pasadena and intersight/kubeturbo referenced by mutable tag only
# ─────────────────────────────────────────────────────────
IWO_F3 = {
    "id":       "IWO-F3",
    "title":    "IWO Helm chart pulls intersight/pasadena and intersight/kubeturbo from Docker Hub "
                "by mutable tag — no digest pinning; Docker Hub account compromise enables "
                "malicious image delivery to cluster-admin ServiceAccount",
    "status":   "CONFIRMED — values.yaml connectorImage.repository + collectorImage.repository",
    "severity": "LOW",

    "images": {
        "connector": "intersight/pasadena:1.0.11-20250604055421206 (pullPolicy: IfNotPresent)",
        "collector":  "intersight/kubeturbo:8.15.2.1 (pullPolicy: IfNotPresent)",
    },

    "note": (
        "IfNotPresent mitigates casual tag drift — the image is pulled only if not cached locally. "
        "But: (1) fresh deployments always pull, (2) image replacement on the registry after "
        "deletion of the local cache triggers a re-pull, (3) Kubernetes nodes with no cached "
        "copy pull on first scheduling. "
        "Combining a compromised Docker Hub account with the cluster-admin ServiceAccount binding "
        "(IWO-F1) means a malicious replacement image immediately has full cluster access. "
        "Fix: pin with @sha256:<digest> in the repository field, or mirror to a private registry."
    ),
}

FINDINGS = [IWO_F1, IWO_F2, IWO_F3]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
