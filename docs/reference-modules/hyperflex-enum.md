# HyperFlex Enumeration

**File:** `modules/hyperflex_enum.py`

## Why this exists

Cisco HyperFlex attack surface enumeration: HX Connect REST API, iSCSI/NFS exposure, UCSM, APIC, stCtlVM cluster services. Checks for default credentials, unauthenticated API endpoints, and cluster node discovery.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP response bodies read with inline `r.read(4 * 1024 * 1024)` cap (4 MB). No file reads. No lief.parse().

---

## How it works

`HyperFlexEnumerator(host, timeout=8).enumerate_all()` runs six probes in sequence: `probe_hx_connect_api()` (HX Connect login surface), `probe_ucsm_api()` (UCSM XML API), `probe_apic_api()` (APIC REST API), `probe_iscsi_no_chap()` (iSCSI without CHAP), `probe_stctlvm_ssh()` (storage controller VM SSH), and `probe_cluster_discovery()` (cluster node enumeration). Returns a deduplicated `List[dict]`: all findings combined. Each finding uses `_finding()` returning `{severity, title, detail, host, port, evidence}`.

---

## Usage

```python
from modules.hyperflex_enum import HyperFlexEnumerator

enum = HyperFlexEnumerator('10.0.0.1', timeout=8)
findings = enum.enumerate_all()
# findings: [{severity, title, detail, host, port, evidence}]
for f in findings:
    print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
HyperFlexEnumerator.enumerate_all(): 10.0.0.1

  [CRITICAL] HX Connect default credentials accepted
             admin:admin login succeeded on HX Connect management interface
  [HIGH]     UCSM XML API accessible
             /nuova XMLl API returned aaaLogin without credential
  [HIGH]     iSCSI no-CHAP target accessible
             iSCSI target at 10.0.0.1:3260 accepted login without CHAP authentication
```

---

## False positives

**`probe_hx_connect_api()` default credential finding on locked-down HX Connect**: HyperFlex clusters in hardened configurations disable the web UI and return 403 or redirect to a corporate SSO. The finding fires only on a successful login response (HTTP 200 + token). A 403 or redirect is not a finding.

---

## Pipeline position

Run `HyperFlexEnumerator` after confirming a Cisco HyperFlex management IP via reverse DNS or certificate CN. Run `probe_iscsi_no_chap()` independently when storage traffic is visible on the network (TCP/3260).

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `title` | Finding name (e.g., `UCSM XML API accessible`, `iSCSI no-CHAP target accessible`) |
| `detail` | What was found and why it matters |
| `host` | Target host |
| `port` | Target port |
| `evidence` | Response excerpt confirming the finding |

---

## See also

- [FindingRegistry](registry.md): record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md): chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md): port and service fingerprinting
