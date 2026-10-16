# Nexus Dashboard Enumeration

**File:** `modules/nexus_dashboard_enum.py`

## Why this exists

Cisco Nexus Dashboard, NDI, NDFC, NDO, and Data Broker enumeration. Single-SSO architecture means one credential set reaches APIC + NDFC + NDO + Data Broker. Kafka anomaly export is unauthenticated by default — this module checks for that exposure.

Also covers adjacent DevOps/CI-CD infrastructure commonly co-located with Nexus Dashboard environments: Jenkins, GitLab, Tekton, ArgoCD, Flux GitOps, Crossplane, SonarQube, JFrog Artifactory, and Sonatype Nexus Repository. Probe functions: `probe_jenkins_exposure`, `probe_gitlab_exposure`, `probe_tekton_pipeline_exposure`, `probe_argocd_api`, `probe_flux_gitops_exposure`, `probe_crossplane_exposure`, `probe_sonarqube_exposure`, `probe_artifactory_nexus_registry`.

## Constructor

```python
from modules.nexus_dashboard_enum import probe_nexus_dashboard, enumerate_nexus_dashboard
result = probe_nexus_dashboard("10.0.0.1")
results = enumerate_nexus_dashboard(["10.0.0.1", "10.0.0.2"])
```

## FORGE audit

Gate: **PASSED**. All HTTP response bodies read with inline `r.read(4 * 1024 * 1024)` cap (4 MB). Socket recv bounded. No file reads. No lief.parse().
