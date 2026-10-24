# Docker / Container Enumeration

**File:** `modules/docker_enum.py`

## Why this exists

Docker API and container attack surface enumeration: exposed Docker sockets, container escape opportunities, privileged containers, mounted host paths, and credential material in environment variables.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_HTTP_BYTES` | 4 MB | Docker API HTTP response body |
| `_MAX_FILE_BYTES` | 64 KB | `/proc/1/cgroup` and procfs reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP reads use `resp.read_MAX_HTTP_BYTES`. Five procfs reads all capped with `f.read_MAX_FILE_BYTES` or `f.read_MAX_FILE_BYTES.splitlines()`: `/proc/1/cgroup` L112, L366, `/proc/self/status` in `check_privileged()` (L270) and `get_capabilities()` (L297), `/proc/self/mountinfo` in `get_mounts()` (L311). No lief.parse().

---

## How it works

`DockerEnumerator.enumerate_all()` runs in three paths based on environment: always runs `probe_docker_daemon_api()` TCP port 2375 unauthenticated API probe, then conditionally runs socket-based checks if `/var/run/docker.sock` is accessible, and container-escape checks if running inside a container. Returns a single dict with all results.

---

## Usage

```python
from modules.docker_enum import DockerEnumerator

enum = DockerEnumerator()
result = enum.enumerate_all()
# Keys: in_container, socket_access, privileged, containers, images,
#       volumes, networks, capabilities, mounts, escape_vectors,
#       daemon_api_findings, privileged_container_findings,
#       exposed_port_findings, env_secret_findings, image_layer_findings
print(f"In container: {result['in_container']}  Socket: {result['socket_access']}")
for f in result['daemon_api_findings'] + result['privileged_container_findings']:
    print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
DockerEnumerator.enumerate_all():
  in_container: True  socket_access: True

daemon_api_findings:
  [CRITICAL] Docker daemon API unauthenticated on TCP port
             TCP localhost:2375 responded without authentication. Version=24.0.5

privileged_container_findings:
  [HIGH] container nginx: CAP_SYS_ADMIN capability granted
```

---

## False positives

**`probe_docker_daemon_api()` fires on non-Docker HTTP services on port 2375**: a TCP response to `GET /version` on port 2375 does not guarantee Docker. Verify `Content-Type: application/json` and the presence of `Version` and `APIVersion` fields in the response before treating this as a confirmed Docker daemon.

---

## Pipeline position

Run `DockerEnumerator` after gaining shell access to a host or container. Use `daemon_api_findings` to identify escape primitives and `containers` + `images` for lateral movement target inventory.

---

## Reading findings

Finding dicts in the result's `*_findings` keys use `{severity, title, detail, host, port}`.

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `title` | Finding description such as `Docker daemon API unauthenticated on TCP port` |
| `detail` | What was found and why it matters |
| `host` | Target host where the finding was observed |
| `port` | Target port where the finding was observed |

---

## See also

- [Docker Inventory and Posture](docker-inventory-and-posture.md): `check_container_isolation()` for `/proc`-based escape surface
- [Cluster Management Exposure](cluster-management-exposure.md): combined Docker + Kubernetes management surface
