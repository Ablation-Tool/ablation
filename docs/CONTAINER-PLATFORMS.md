# Ablation Container/Platform Support

## Supported Platforms

Ablation v2.2.0 enumerates three container/virtualization platforms:

### 1. Docker
**Module:** `modules/docker_enum.py`

**Detection:**
- Container presence (/.dockerenv, /proc/1/cgroup)
- Socket access (/var/run/docker.sock)
- Hostname analysis (12-char hex = container ID)

**Enumeration:**
- Containers (ID, name, image, status, ports)
- Images (repository, tag, size)
- Volumes (name, driver)
- Networks (ID, name, driver)
- Capabilities (CapEff from /proc/self/status)
- Mounts (/proc/self/mountinfo)

**Escape Vectors:**
- Docker socket mounted (CRITICAL)
- Privileged container (CRITICAL)
- Host PID namespace (HIGH)
- CAP_SYS_ADMIN capability (HIGH)

**CLI:**
```bash
./ablation --docker
```

---

### 2. Kubernetes
**Module:** `modules/k8s_enum.py`

**Detection:**
- Service account path (/var/run/secrets/kubernetes.io/serviceaccount)
- Environment variables (KUBERNETES_SERVICE_HOST)
- cgroup markers (kubepods)

**Enumeration:**
- Service account + namespace
- Token extraction
- Pods (name, namespace, status, IP)
- Services (name, type, cluster IP)
- Secrets (name, type) - if permitted
- ConfigMaps
- RBAC permissions (kubectl auth can-i)

**Escape Vectors:**
- Service account token available (HIGH)
- Privileged pod (CRITICAL)
- Dangerous hostPath mounts (CRITICAL)
- Excessive RBAC permissions (HIGH)

**CLI:**
```bash
./ablation --k8s
```

---

### 3. Orka Platform (MacStadium)
**Module:** `modules/orka_enum.py`

**Detection:**
- orka-vm-tools presence (/Library/Application Support/Orka)
- Metadata server (169.254.169.254)
- Orka API reachability (10.221.188.20, 10.221.188.100)

**Enumeration:**
- VM metadata server (keys, values, debug endpoints)
- Cluster info (K8s API, OAuth endpoints) - UNAUTHENTICATED
- VMs (name, namespace, status, IP, SSH/VNC ports)
- Images (base images, custom images)
- Service accounts
- Authentication tokens (~/.kube/config)

**Security Findings:**
- F1: Unauthenticated /api/v1/cluster-info (exposes K8s CA cert)
- F2: Default VM credentials admin:admin (SSH :8822, VNC :5999)
- F3: VM metadata server unauthenticated (169.254.169.254)
- F4: Orka token = K8s token (direct kubectl access)
- Debug endpoint exposed (/debug/pprof/)

**CLI:**
```bash
./ablation --orka
```

---

## Combined Analysis

Run all three platforms:
```bash
./ablation --containers
```

**Output:**
- Docker enumeration (if socket accessible or in container)
- Kubernetes enumeration (if in K8s pod)
- Orka enumeration (if in Orka VM or API reachable)

All findings integrated into vulnerability analysis.

---

## Architecture

```
Ablation Container Detection Flow:

1. Docker Check
   ├─ /.dockerenv exists? → IN_CONTAINER
   ├─ /proc/1/cgroup contains "docker"? → IN_CONTAINER
   └─ Socket accessible? → SOCKET_ACCESS

2. Kubernetes Check
   ├─ /var/run/secrets/kubernetes.io/serviceaccount? → IN_K8S
   ├─ KUBERNETES_SERVICE_HOST set? → IN_K8S
   └─ /proc/1/cgroup contains "kubepods"? → IN_K8S

3. Orka Check
   ├─ /Library/Application Support/Orka exists? → IN_ORKA_VM
   ├─ 169.254.169.254 responsive? → IN_ORKA_VM
   └─ Orka API reachable (10.221.188.20)? → ORKA_API_ACCESS
```

---

## Live Test Results

**Test System:** Ubuntu 24.04, Docker installed

```
Docker:
  Socket Access: TRUE
  Containers: 7 running
  Images: 19
  Volumes: 8
  Networks: 3

Kubernetes:
  In K8s: FALSE

Orka:
  In Orka VM: FALSE
  API Reachable: FALSE
```

---

## Orka Platform Details

**API Endpoints:**
```
Base: http://10.221.188.20 (v2.1+)
      http://10.221.188.100 (pre-2.1)

Unauthenticated:
  GET  /api/v1/cluster-info     ← FINDING F1
  GET  /version

Authenticated (Bearer token):
  GET  /api/v1/namespaces
  GET  /api/v1/namespaces/{ns}/vms
  POST /api/v1/namespaces/{ns}/vms  ← Deploy VM
  GET  /api/v1/namespaces/{ns}/images
  GET  /api/v1/namespaces/{ns}/serviceaccounts
```

**VM Metadata Server:**
```
Runs in every Orka VM: 169.254.169.254

Endpoints:
  GET /metadata/keys          ← List all keys
  GET /metadata/{key}         ← Get value
  GET /debug/pprof/           ← Go profiling (FINDING F3)

No authentication required.
```

**Default Credentials (FINDING F2):**
```
Every MacStadium base image:
  User: admin
  Pass: admin

Ports:
  SSH: 8822
  VNC: 5999
  Screenshare: 5901
```

---

## Use Cases

### 1. Docker Breakout
Deploy Ablation inside container:
```bash
scp ablation container:/tmp/scan
docker exec container /tmp/scan --docker
```

**Detects:**
- Privileged mode
- Mounted socket
- Host PID namespace
- Dangerous capabilities

### 2. K8s Pod Escape
Deploy as Kubernetes job:
```bash
kubectl run ablation --image=python:3.12-slim --command -- /ablation
```

**Detects:**
- Service account tokens
- RBAC permissions
- Accessible secrets
- Privileged pod settings

### 3. Orka VM Enumeration
Deploy inside Orka macOS VM:
```bash
scp ablation admin@vm-ip:/tmp/scan
ssh admin@vm-ip '/tmp/scan --orka'
```

**Detects:**
- Metadata server contents
- Cluster info exposure
- Default credentials
- API access from VM

---

## Version History

**v2.0.0:** Docker + Kubernetes support
**v2.1.0:** Container enumeration integrated into autonomous mode
**v2.2.0:** Orka platform support added

---

**Location:** `~/VDT/tools/ablation/`
**Modules:** docker_enum.py, k8s_enum.py, orka_enum.py
