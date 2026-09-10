"""
Cisco IWO (Intersight Workload Optimizer) Kubernetes Collector Helm Chart 1.10.0 — RE Module
Source: iwo-k8s-collector-1.10.0.tgz (Helm chart)
Package: iwo-k8s-collector v1.10.0 — intersight/kubeturbo:8.15.2.1 + intersight/pasadena:1.0.11
"""

FIRMWARE = {
    "target":    "Cisco IWO Kubernetes Collector",
    "version":   "1.10.0",
    "source":    "iwo-k8s-collector-1.10.0.tgz",
    "type":      "Helm chart — Kubernetes StatefulSet deployment",
    "images": {
        "collector": "intersight/kubeturbo:8.15.2.1",
        "connector": "intersight/pasadena:1.0.11-20250604055421206",
    },
    "findings":  ["IWO-F1", "IWO-F2"],
}

# ─────────────────────────────────────────────────────────
# IWO-F1 — Default roleName is Kubernetes built-in 'cluster-admin' — full cluster access
# ─────────────────────────────────────────────────────────
IWO_F1 = {
    "id":       "IWO-F1",
    "title":    "IWO k8s collector Helm chart defaults to Kubernetes built-in 'cluster-admin' role — "
                "unrestricted access to all cluster resources including secrets and credentials",
    "status":   "CONFIRMED — iwo-k8s-collector/values.yaml + templates/serviceaccount.yaml",
    "severity": "HIGH",

    "values_default": 'roleName: "cluster-admin"',

    "rbac_binding": (
        "ClusterRoleBinding 'iwo-all-binding' binds ServiceAccount 'iwo-user' to "
        "the roleName from values.yaml. Default roleName is the Kubernetes built-in "
        "'cluster-admin' ClusterRole, which grants access to ALL apiGroups, ALL resources, "
        "and ALL verbs — including read/write of Secrets, ConfigMaps, and ServiceAccountTokens."
    ),

    "least_privilege_options_available": {
        "iwo-cluster-reader":  "Read-only — get/watch/list on nodes/pods/deployments/services/etc.",
        "iwo-cluster-admin":   "Constrained write — specific resources only, no secrets access",
        "cluster-admin":       "BUILTIN — unrestricted (DEFAULT, active without configuration change)",
    },

    "default_replicacount": 2,

    "impact": (
        "Two cluster-admin pods running continuously in the target cluster. "
        "Any code execution in the kubeturbo or pasadena container — via supply chain attack, "
        "container escape, or image compromise — yields full Kubernetes cluster-admin access: "
        "read all Secrets (includes service account tokens, TLS certs, database credentials), "
        "create/delete any pod, access all namespaces, and bridge to cloud via the connector. "
        "Customer clusters connected to Intersight have a standing cluster-admin foothold "
        "unless explicitly overridden at deployment time."
    ),

    "relay_context": (
        "kubeturbo communicates cluster data to topology-processor:8080 (internal, HTTP, no TLS). "
        "pasadena relays to Intersight cloud via PROXY_PORT=9004. "
        "Data collected includes full workload inventory, resource utilization, and pod specs "
        "(which may reference Secret names). With cluster-admin, the collector can also "
        "read Secret values directly."
    ),
}

# ─────────────────────────────────────────────────────────
# IWO-F2 — Internal kubeturbo → topology-processor communication uses HTTP (no TLS)
# ─────────────────────────────────────────────────────────
IWO_F2 = {
    "id":       "IWO-F2",
    "title":    "kubeturbo relays cluster data to topology-processor:8080 over plaintext HTTP — "
                "any pod in the namespace can MITM or sniff the data stream",
    "status":   "CONFIRMED — iwo-k8s-collector/templates/configmap.yaml",
    "severity": "LOW",

    "configmap_entry": '"turboServer": "http://topology-processor:8080"',

    "analysis": (
        "The kubeturbo collector's --turboconfig configures the upstream server as "
        "http://topology-processor:8080. "
        "This is plaintext HTTP to a Kubernetes service within the same cluster. "
        "Any pod with network access to the topology-processor service can intercept "
        "the stream of cluster workload data being relayed to Intersight. "
        "The proxy path continues from topology-processor → pasadena container "
        "(PROXY_PORT=9004) → Intersight cloud, which may use TLS on the egress leg."
    ),

    "scope": (
        "In-cluster only — topology-processor:8080 is a cluster-internal service. "
        "The lack of TLS matters primarily if an attacker already has a pod in the cluster "
        "and wants to read workload inventory data without needing the kubeturbo credentials."
    ),
}

FINDINGS = [IWO_F1, IWO_F2]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
