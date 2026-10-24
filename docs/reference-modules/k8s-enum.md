# Kubernetes Enumeration

**File:** `modules/k8s_enum.py`

## Why this exists

Kubernetes attack surface enumeration: exposed API server endpoints, RBAC misconfigurations, privileged pod detection, hostPath volume mounts, service account token exposure, and kubelet read-only port (10255) checks.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_FILE_BYTES` | 64 KB | procfs / kubepods cgroup file reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All procfs reads use `f.read_MAX_FILE_BYTES.splitlines()` including `_check_privileged_caps()` `/proc/self/status` L2801, fixed this session. HTTP/API responses use inline `resp.read4 * 1024 * 1024` cap (4 MB). All kubectl subprocess calls have `timeout=` on continuation lines. No lief.parse().

---

## How it works

`K8sEnumerator()` no constructor args: auto-detects token, CA cert, API server from environment. `enumerate_all()` runs `check_in_k8s()` first to confirm Kubernetes context, then runs RBAC, pod, secret, network policy, and admission controller checks. Escape vectors accumulate in `self.escape_vectors` as `{type, severity, description, exploit}` dicts. Other finding lists such as `clusteradmin_findings` and `privileged_pod_findings` use `{severity, ...resource-specific keys}`.

---

## Usage

```python
from modules.k8s_enum import K8sEnumerator

enumerator = K8sEnumerator()
enumerator.enumerate_all()

# escape_vectors: [{type, severity, description, exploit}]
for v in enumerator.escape_vectors:
    print(f"  [{v['severity']}] {v['type']}: {v['description'][:80]}")
    if v.get('exploit'):
        print(f"    exploit: {v['exploit'][:80]}")

# clusteradmin_findings: [{name, subject_kind, subject_name, subject_namespace, severity}]
for f in enumerator.clusteradmin_findings:
    print(f"  [{f['severity']}] cluster-admin: {f['subject_kind']} {f['subject_name']}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
K8sEnumerator.enumerate_all():
  in_k8s: True  namespace: default  api_server: https://10.96.0.1:443

escape_vectors:
  [HIGH] CLUSTERADMIN_BINDING: ClusterRoleBinding 'ci-pipeline' binds
         ServiceAccount default/ci-sa to cluster-admin
         exploit: kubectl --token=<tok> get secrets -A

privileged_pod_findings:
  [HIGH] pod: monitoring/prometheus — securityContext.privileged: true
```

---

## False positives

**`check_rbac_clusteradmin()` on CI/CD service accounts**: many CI/CD pipelines ArgoCD, Tekton, and Flux legitimately bind their service accounts to `cluster-admin` for deployment automation. Confirm whether the binding is intentional by checking the bound service account's namespace and workload name before escalating.

**`check_network_policies()` reports `NO_NETWORK_POLICY` per namespace**: a namespace without a NetworkPolicy allows all traffic by default. In single-tenant clusters or staging environments this is often intentional. The finding is accurate; intent must be verified separately.

---

## Pipeline position

Run `K8sEnumerator` from inside a pod after gaining container-level shell access. `check_in_k8s()` detects the service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`: if the token has RBAC access, full cluster enumeration proceeds automatically.

---

## Reading findings

`escape_vectors` shape: `{type, severity, description, exploit}`

Other finding lists `clusteradmin_findings`, `network_policy_findings`, and `privileged_pod_findings` have resource-specific keys plus `severity`. Read `enumerator.report()` for a formatted summary.

---

## See also

- [FindingRegistry](registry.md): record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md): chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md): port and service fingerprinting
