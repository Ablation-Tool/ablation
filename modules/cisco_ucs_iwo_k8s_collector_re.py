"""
Cisco IWO (Intersight Workload Optimizer) K8s Collector 1.10.0 Helm Chart RE

Target:  iwo-k8s-collector-1.10.0.tgz
         Intersight Workload Optimizer Kubernetes Collector, appVersion 8.15.2.1
         Helm chart v1.10.0; deployer for IBM Turbonomic-derived kubeturbo agent in Kubernetes
         Components: iwo-k8s-collector (kubeturbo) + iwo-k8s-dc (pasadena/connector) containers
         Deployed as StatefulSet with ClusterRoleBinding to iwo-user ServiceAccount
Files:   Chart.yaml (appVersion=8.15.2.1, chart=1.10.0)
         values.yaml (default role, image sources, HA config, args)
         templates/sts.yaml (StatefulSet: 2 containers, securityContext, volumeMounts)
         templates/serviceaccount.yaml (ServiceAccount + conditional ClusterRole + ClusterRoleBinding)
         templates/configmap.yaml (iwo.config: turboServer, proxy, HANodeConfig)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_iwo_k8s_collector_re",
    "firmware": "iwo-k8s-collector-1.10.0.tgz",
    "components": {
        "values.yaml (roleName)": (
            "roleName: 'cluster-admin' (default); "
            "alternatives: 'iwo-cluster-reader', 'iwo-cluster-admin'; "
            "all three bind iwo-user ServiceAccount via ClusterRoleBinding iwo-all-binding"
        ),
        "values.yaml (images)": (
            "connectorImage: intersight/pasadena:1.0.11-20250604055421206 (docker.io, tag-pinned); "
            "collectorImage: intersight/kubeturbo:8.15.2.1 (docker.io, tag-pinned); "
            "no imagePullSecret required for docker.io public images"
        ),
        "templates/sts.yaml (securityContext)": (
            "pod securityContext: runAsUser=1000, runAsGroup=3000, fsGroup=2000; "
            "NO container-level securityContext on either container; "
            "resources: {} (empty -- no limits/requests on either container)"
        ),
        "templates/configmap.yaml (iwo.config)": (
            "turboServer: 'http://topology-processor:8080' (cleartext HTTP); "
            "proxy: 'http://localhost:9004' (cleartext HTTP from connector); "
            "PROXY_PORT env var: 9004"
        ),
    },
    "finding_count": "6F [0C+1H+3M+2L]",
    "cumulative": "819 [78C+282H+261M+197L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "roleName defaults to 'cluster-admin' in values.yaml; iwo-user ServiceAccount gets full cluster access",
        "description": (
            "values.yaml line: 'roleName: \"cluster-admin\"'. "
            "ClusterRoleBinding iwo-all-binding binds iwo-user to this role. "
            "cluster-admin is Kubernetes built-in superuser: full read/write access "
            "to every resource in every namespace including Secrets. "
            "The chart offers two least-privilege alternatives ('iwo-cluster-reader' and 'iwo-cluster-admin') "
            "with explicit ClusterRole definitions in serviceaccount.yaml, "
            "but the default is the maximally privileged option. "
            "An operator who deploys with 'helm install iwo-k8s-collector . --namespace iwo' "
            "without overriding roleName gets cluster-admin for the collector ServiceAccount. "
            "kubeturbo (intersight/kubeturbo container) has documented features including "
            "pod moves, resize, and deployment scaling -- "
            "but cluster-admin exceeds what those features require. "
            "Compromise of the kubeturbo container (e.g., via the docker.io supply chain) "
            "yields cluster-admin API access."
        ),
        "evidence": {
            "file": "values.yaml",
            "default": "roleName: \"cluster-admin\"",
            "binding": "ClusterRoleBinding iwo-all-binding -> roleRef.name: {{ .Values.roleName }}",
            "alternatives_in_chart": "iwo-cluster-reader (read-only) and iwo-cluster-admin (nodes/pods write)",
        },
        "impact": (
            "Default deploy grants the collector full read/write access to all Kubernetes resources. "
            "Secrets (database credentials, API keys, TLS certs) readable by the collector. "
            "Container compromise yields unauthenticated cluster-admin API access."
        ),
        "remediation": "Change default roleName to 'iwo-cluster-reader' or 'iwo-cluster-admin'. Document minimum required permissions.",
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "Container images pulled from docker.io by tag without digest pinning",
        "description": (
            "values.yaml: "
            "connectorImage.repository=intersight/pasadena; tag=1.0.11-20250604055421206; "
            "collectorImage.repository=intersight/kubeturbo; tag=8.15.2.1. "
            "Neither image specifies an 'image@sha256:...' digest override. "
            "pullPolicy=IfNotPresent means the images are pulled once and cached -- "
            "on first deployment, docker.io/intersight/pasadena:1.0.11-... and "
            "docker.io/intersight/kubeturbo:8.15.2.1 are fetched from Docker Hub. "
            "Tags are mutable: the Intersight Docker Hub account can push a new image "
            "under the same tag. "
            "No imagePullSecret is required (public images) -- "
            "any node with internet access pulls directly from docker.io. "
            "Clusters without internet access fail deployment silently "
            "if pre-pulled images are unavailable."
        ),
        "evidence": {
            "file": "values.yaml",
            "images": (
                "intersight/pasadena:1.0.11-20250604055421206 (docker.io, tag-only)\n"
                "intersight/kubeturbo:8.15.2.1 (docker.io, tag-only)"
            ),
            "no_digest": "No sha256 digest pin; no private registry override",
        },
        "impact": (
            "Tag mutation at Docker Hub delivers different code to nodes pulling the image after a push. "
            "Combined with cluster-admin ServiceAccount: supply chain compromise = cluster takeover."
        ),
        "remediation": "Pin both images by digest (image@sha256:...). Mirror to a private registry.",
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "No container-level securityContext on either container; no capability drops",
        "description": (
            "sts.yaml spec.securityContext applies at pod level: "
            "runAsUser=1000, runAsGroup=3000, fsGroup=2000. "
            "Neither the iwo-k8s-collector container nor the iwo-k8s-dc container "
            "has a container-level securityContext block. "
            "Missing: allowPrivilegeEscalation=false, capabilities.drop=[ALL], "
            "readOnlyRootFilesystem=true, seccompProfile. "
            "runAsUser=1000 prevents running as root but does not prevent: "
            "setuid binary exploitation, capability acquisition via ambient set, "
            "privilege escalation if the container image contains a setuid executable. "
            "iwo-k8s-dc (pasadena connector) runs without any restrictions; "
            "its purpose is to maintain a persistent connection to Intersight -- "
            "an unverified connection given MITM risks in the network."
        ),
        "evidence": {
            "file": "templates/sts.yaml",
            "pod_level": "securityContext: runAsUser: 1000; runAsGroup: 3000; fsGroup: 2000",
            "container_level": "absent for both containers (no allowPrivilegeEscalation, no drop ALL)",
        },
        "impact": "Container processes can acquire capabilities via setuid binaries or ambient set.",
        "remediation": "Add container securityContext with allowPrivilegeEscalation: false and capabilities.drop: [ALL].",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "turboServer and proxy use cleartext HTTP in configmap iwo.config",
        "description": (
            "configmap.yaml iwo.config: "
            "'\"proxy\": \"http://localhost:9004\"' (PROXY_PORT=9004 from iwo-k8s-dc env). "
            "'\"turboServer\": \"http://topology-processor:8080\"'. "
            "The collector communicates with the IWO server (topology-processor) over HTTP port 8080. "
            "topology-processor is an in-cluster IWO service; the connection is within the cluster network, "
            "but Kubernetes cluster networks are not encrypted by default (no mTLS without a service mesh). "
            "Data collected by kubeturbo (pod specs, resource usage, node state) "
            "travels over cleartext HTTP to the IWO server. "
            "The proxy at localhost:9004 (iwo-k8s-dc/pasadena connector) also uses HTTP -- "
            "the path from kubeturbo to Intersight goes: "
            "kubeturbo -> http://localhost:9004 (pasadena proxy) -> Intersight SaaS. "
            "The pasadena container handles TLS to Intersight but the intra-pod link is HTTP."
        ),
        "evidence": {
            "configmap": (
                '"proxy": "http://localhost:9004",\n'
                '"turboServer": "http://topology-processor:8080"'
            ),
            "env": "PROXY_PORT: 9004 on iwo-k8s-dc container",
        },
        "impact": (
            "In-cluster traffic (kubeturbo -> topology-processor) sent in cleartext HTTP. "
            "Intra-pod collector-to-proxy link also cleartext."
        ),
        "remediation": "Use HTTPS for turboServer URL. Configure pasadena to accept HTTPS on local proxy port.",
    },
    {
        "id": "F5",
        "severity": "LOW",
        "title": "resources: {} empty block; both containers run with no CPU or memory limits",
        "description": (
            "sts.yaml applies 'resources: {{ toYaml .Values.resources | indent 12 }}' "
            "and values.yaml sets 'resources: {}'. "
            "Both the iwo-k8s-collector and iwo-k8s-dc containers inherit the empty resource spec. "
            "With no limits, the containers can consume all available CPU and memory on a node. "
            "kubeturbo's function is cluster-wide resource optimization -- "
            "a collector that itself has no resource constraints is structurally inconsistent "
            "with its stated purpose. "
            "On resource-constrained nodes (edge deployments, small clusters), "
            "an unconstrained kubeturbo could starve workloads it is meant to optimize."
        ),
        "evidence": {
            "file": "values.yaml",
            "resources": "resources: {}",
            "sts_apply": "resources:\n{{ toYaml .Values.resources | indent 12 }}",
        },
        "impact": "Collector can exhaust node CPU/memory; no eviction threshold; OOMKiller-dependent.",
        "remediation": "Set resource requests and limits appropriate for cluster size.",
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "kubeturbo.io/controllable=false annotation exempts collector from IWO optimization",
        "description": (
            "values.yaml annotations: 'kubeturbo.io/controllable: \"false\"'. "
            "This annotation instructs IWO to exclude the collector pods from resource optimization. "
            "The StatefulSet pods marked kubeturbo.io/controllable=false will never be resized, "
            "moved, or throttled by IWO regardless of resource pressure. "
            "Combined with resources: {} (no limits), this creates a privileged unmanaged pod "
            "that IWO cannot reclaim or reschedule. "
            "In a multi-tenant cluster where IWO enforces resource policies, "
            "the collector is exempt from those policies while enforcing them on all other pods."
        ),
        "evidence": {
            "file": "values.yaml",
            "annotation": "kubeturbo.io/controllable: \"false\"",
        },
        "impact": "Collector runs indefinitely at unconstrained resource usage; cannot be reclaimed by IWO.",
        "remediation": "Either remove the annotation (allow IWO to manage the collector) or document the exception.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
