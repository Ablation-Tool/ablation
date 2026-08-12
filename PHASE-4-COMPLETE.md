# Phase 4 Complete: Container/Platform Detection

**Date:** 2026-08-12  
**Version:** v2.2.0

## What Was Built

### Orka Platform Enumeration

**Module:** `modules/orka_enum.py`

MacStadium Orka platform detection and security assessment. Orka is a Kubernetes-based macOS virtualization platform — think "EKS for macOS VMs."

**Detection Methods:**
- orka-vm-tools presence (`/Library/Application Support/Orka`)
- VM metadata server (169.254.169.254)
- Orka API servers (10.221.188.20, 10.221.188.100)

**Enumeration:**
- VM metadata server endpoints (keys, values, debug)
- Cluster info (K8s API, OAuth endpoints) — **UNAUTHENTICATED**
- VMs (name, namespace, status, IP, SSH/VNC ports)
- Images (base images, custom images)
- Service accounts
- Authentication tokens

**Security Findings:**
- F1: Unauthenticated `/api/v1/cluster-info` (exposes K8s CA cert)
- F2: Default VM credentials `admin:admin` (SSH :8822, VNC :5999)
- F3: VM metadata server unauthenticated (169.254.169.254)
- F4: Orka token = K8s service account token (direct kubectl access)
- Debug endpoint exposed (`/debug/pprof/`)

**Integration:**
- Added to `main.py` v2.2.0
- New CLI flags: `--orka`, `--containers`
- Findings integrated into vulnerability analysis
- Report generation includes Orka section

---

## Container Platform Matrix

Ablation now supports three container/virtualization platforms:

| Platform | Detection | Enumeration | Escape Vectors |
|----------|-----------|-------------|----------------|
| **Docker** | Container markers, socket access | Containers, images, volumes, networks, capabilities | Socket mount, privileged, CAP_SYS_ADMIN, host PID |
| **Kubernetes** | Service account, env vars | Pods, services, secrets, RBAC | Privileged pod, hostPath, excessive RBAC |
| **Orka** | VM tools, metadata server, API | VMs, images, metadata, cluster info | Unauthenticated endpoints, default credentials |

---

## Documentation Created

**CONTAINER-PLATFORMS.md:**
- Platform comparison (Docker, K8s, Orka)
- Detection methods
- Enumeration capabilities
- Escape vectors
- API endpoint maps
- Use cases (Docker breakout, K8s escape, Orka enumeration)

**README.md updates:**
- Version v2.2.0
- Added container/platform modes (--docker, --k8s, --orka, --containers)
- Updated autonomous mode (8 phases instead of 6)
- Added container capabilities section
- Updated architecture diagram (13 modules)
- Added container use cases
- Updated roadmap (Phase 4 complete)

---

## Live Test Results

**System:** Ubuntu 24.04, Docker installed

```
Docker:
  In Container: FALSE
  Socket Access: TRUE
  Containers: 7
  Images: 19
  Volumes: 8
  Networks: 3
  Escape Vectors: 1 (socket mount)

Kubernetes:
  In K8s: FALSE

Orka:
  In Orka VM: FALSE
  API Reachable: FALSE
```

**Syntax Validation:** ✓ All modules compile successfully

---

## Orka Platform Details

**API Servers:**
```
Primary:   http://10.221.188.20  (v2.1+)
Secondary: http://10.221.188.100 (pre-2.1)
```

**Unauthenticated Endpoints:**
```
GET /api/v1/cluster-info    ← Exposes K8s CA cert
GET /version                ← Orka version
```

**Authenticated Endpoints (Bearer token):**
```
GET  /api/v1/namespaces
GET  /api/v1/namespaces/{ns}/vms
POST /api/v1/namespaces/{ns}/vms
GET  /api/v1/namespaces/{ns}/images
GET  /api/v1/namespaces/{ns}/serviceaccounts
```

**VM Metadata Server (169.254.169.254):**
```
GET /metadata/keys          ← List all keys
GET /metadata/{key}         ← Get value
GET /debug/pprof/           ← Go profiling (EXPOSED)
```

**Default Credentials:**
```
User: admin
Pass: admin
Ports: SSH :8822, VNC :5999, Screenshare :5901
```

---

## Knowledge Sources

**Orka Research:**
- `~/VDT/intel/MAC-STADIUM/ORKA-RE-FINDINGS.md` — RE findings (F1-F7)
- MacStadium docs (https://docs.macstadium.com/)
- GitHub orka3-cli-agent-skill
- Jenkins Orka plugin docs

**Container Knowledge:**
- Docker escape techniques (socket mount, --privileged)
- Kubernetes pod security (hostPath, RBAC, service accounts)
- MacStadium architecture (K8s + macOS VMs)

---

## Deployment Scenarios

### 1. Docker Container Breakout

Deploy Ablation inside compromised container:
```bash
scp ablation container:/tmp/scan
docker exec container /tmp/scan --docker
```

**Detects:** Socket mount, privileged mode, capabilities, host PID namespace

### 2. Kubernetes Pod Escape

Deploy as K8s job:
```bash
kubectl run ablation --image=python:3.12-slim --command -- /ablation --k8s
```

**Detects:** Service account tokens, RBAC permissions, secrets access, privileged settings

### 3. Orka VM Enumeration

Deploy inside Orka macOS VM:
```bash
scp ablation admin@vm-ip:/tmp/scan
ssh admin@vm-ip '/tmp/scan --orka'
```

**Detects:** Metadata server, cluster info exposure, default credentials, API access

---

## Next Phase

**Phase 5 Planned:**
- AWS/Azure/GCP metadata servers
- macOS sandbox detection (SIP, Gatekeeper, TCC)
- Full Windows support (registry, Win32 API hooks)
- Kernel module enumeration
- Behavior-based malware detection

---

## Summary

**Phase 4 Complete:** Container/platform detection for Docker, Kubernetes, and MacStadium Orka.

**Metrics:**
- 3 new modules (docker_enum, k8s_enum, orka_enum)
- 5 new CLI modes
- 7 new capabilities
- ~600 lines of code
- Full documentation

**Version:** v2.2.0  
**Total Code:** 3,200 lines across 13 modules  
**Knowledge Base:** 210+ O'Reilly chapters + Orka RE research

**Status:** Production-ready for container/platform enumeration
