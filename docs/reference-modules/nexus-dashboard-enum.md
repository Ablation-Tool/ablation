# Nexus Dashboard Enumeration

**File:** `modules/nexus_dashboard_enum.py`

## Why this exists

Cisco Nexus Dashboard, NDI, NDFC, NDO, and Data Broker enumeration. Single-SSO architecture means one credential set reaches APIC + NDFC + NDO + Data Broker. Kafka anomaly export is unauthenticated by default, this module checks for that exposure.

Also covers adjacent DevOps/CI-CD infrastructure commonly co-located with Nexus Dashboard environments: Jenkins, GitLab, Tekton, ArgoCD, Flux GitOps, Crossplane, SonarQube, JFrog Artifactory, and Sonatype Nexus Repository. Probe functions: `probe_jenkins_exposure`, `probe_gitlab_exposure`, `probe_tekton_pipeline_exposure`, `probe_argocd_api`, `probe_flux_gitops_exposure`, `probe_crossplane_exposure`, `probe_sonarqube_exposure`, `probe_artifactory_nexus_registry`.

## Constructor

```python
from modules.nexus_dashboard_enum import probe_nexus_dashboard, enumerate_nexus_dashboard
result = probe_nexus_dashboard("10.0.0.1")
results = enumerate_nexus_dashboard(["10.0.0.1", "10.0.0.2"])
```

## FORGE audit

Gate: **PASSED**. All HTTP response bodies read with inline `r.read(4 * 1024 * 1024)` cap (4 MB). Socket recv bounded. No file reads. No lief.parse().

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.nexus_dashboard_enum import NexusDashboardEnumeration

results = NexusDashboardEnumeration.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
[HIGH]     UNAUTH_ACCESS     /api/v1/config/backup
  detail: unauthenticated GET returns full config including credentials
  evidence: HTTP 200, Content-Type: application/json, body: {"admin_pass": ...}

[MEDIUM]   INFO_DISCLOSURE   /status
  detail: version string exposed without authentication
  evidence: X-Version: FortiOS 7.2.1 build 1254
```

---

## False positives

Findings from internal management interfaces, development endpoints, and lab-only services are not real attack surface. Filter by comparing discovered endpoints against the product's documented management plane. Authentication-required findings are lower severity unless a pre-auth bypass is confirmed separately.

---

## Pipeline position

**Before this module:** Network reachability confirmation and credential acquisition. `BinaryContext` is not required; this module works from a live target or captured traffic.

**After this module:** Feed findings to `FindingRegistry.register()` and review with `LLMAnalyst` for chaining opportunities.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Category (e.g., `UNAUTH_ACCESS`, `INFO_DISCLOSURE`, `WEAK_CONFIG`) |
| `endpoint` | URI, port, or service address where the finding was observed |
| `detail` | What was found and why it matters |
| `evidence` | Response excerpt or protocol trace that confirms the finding |

---

## See also

- [FindingRegistry](registry.md) — record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md) — chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md) — port and service fingerprinting
