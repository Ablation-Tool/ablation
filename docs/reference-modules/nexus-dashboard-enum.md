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

Standalone probe functions `(host, port, timeout) → list` return `{severity, title, detail, host, port}` finding dicts. `probe_nexus_dashboard(host)` returns a plain data dict `{host, port, reachable, version, cred_result, unauth_data, auth_data, kafka_export_open, sso_impact}`. `enumerate_nexus_dashboard(hosts)` runs all probes across a list of hosts and returns a combined findings list.

---

## Usage

```python
from modules.nexus_dashboard_enum import (
    probe_nexus_dashboard,
    probe_nxapi_cli,
    probe_nexus_dashboard_api,
    enumerate_nexus_dashboard,
)

# Data dict probe
nd = probe_nexus_dashboard('10.0.0.1')
if nd['reachable']:
    print(f"  version: {nd['version']}  kafka: {nd['kafka_export_open']}")

# Findings list probes — [{severity, title, detail, host, port}]
for f in probe_nxapi_cli('10.0.0.1', port=80):
    print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
probe_nxapi_cli: 10.0.0.1:80

  [CRITICAL] NXAPI_CLI_UNAUTH: NX-API CLI executed without authentication
  [HIGH]     NXAPI_RUNNING_CONFIG_UNAUTH: running-config retrieved via NX-API without auth
  [HIGH]     NXAPI_BASH_EXEC_UNAUTH: bash command executed via NX-API without authentication
  [MEDIUM]   NXAPI_CLI_HTTP_CLEARTEXT: NX-API CLI accessible over HTTP (cleartext)
```

---

## False positives

**`probe_nxapi_cli()` on NX-API with management VRF restriction**: NX-API CLI may be accessible only from management VRF. A probe from the data plane may time out, producing no finding even when NX-API is misconfigured from the management plane. Confirm by sending the probe from a management-plane foothold.

---

## Pipeline position

Run `probe_nexus_dashboard()` after identifying a Cisco Nexus Dashboard management IP. Run `probe_nxapi_cli()` and `probe_nxapi_rest()` when NX-API ports (TCP/80, TCP/443) are confirmed open on a Cisco Nexus switch.

---

## Reading findings

Findings list probes return `{severity, title, detail, host, port}`:

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `title` | Finding code (e.g., `NXAPI_CLI_UNAUTH`, `NXAPI_RUNNING_CONFIG_UNAUTH`, `NXAPI_BASH_EXEC_UNAUTH`) |
| `detail` | What was found and why it matters |
| `host` | Target host |
| `port` | Target port |

---

## See also

- [FindingRegistry](registry.md): record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md): chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md): port and service fingerprinting
