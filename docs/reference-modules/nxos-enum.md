# NX-OS / ACI / VXLAN Enumeration

**File:** `modules/nxos_enum.py`

## Why this exists

Cisco NX-OS, ACI/APIC, DCNM, and VXLAN enumeration. Covers: TLS cert OU discriminator (dcnxos vs dcapic), APIC unauthenticated domain listing, APIC REST credential spray, full APIC MIT enumeration (tenants, EPGs, contracts, L3Out networks, VMM domains, audit log, firmware versions, endpoint tracker, out-of-band management), NX-API (port 443/8080), DCNM REST probing, NX-OS SSH banner grab and CLI command execution, VXLAN VTEP discovery, and Cobra SDK package disclosure.

## Key functions

- `classify_by_cert_ou(host)`: TLS cert OU discriminator (NXOS_SWITCH vs APIC_CONTROLLER)
- `probe_apic_unauthenticated(host)`: aaaListDomains without auth
- `apic_login(host, user, pwd)`: APIC-cookie token login
- `apic_enumerate(host, token)`: full MIT enumeration (30+ classes + subtree queries)
- `apic_get_contract_matrix(host, token)`: EPG-to-EPG contract provided/consumed mapping
- `apic_get_l3out_networks(host, token)`: L3Out external networks and BGP peers
- `apic_get_vmm_domains(host, token)`: VMM lateral movement surface (vCenter IPs/creds)
- `apic_get_audit_log(host, token)`: last 200 config change records
- `apic_get_endpoints(host, token)`: learned MAC/IP/EPG/physical-path endpoint table
- `apic_cobra_bulk_extract(host, token)`: Cobra SDK.whl package disclosure
- `probe_nxapi(host)`: NX-API JSON-RPC at /ins
- `probe_dcnm(host)`: DCNM REST at /rest/*
- `run_nxos_commands(host, user, pwd)`: SSH CLI batch execution
- `probe_vxlan_vteps(host)`: NVE peer and VNI enumeration
- `NXOSEnumerator(targets, creds).run()`: orchestrated multi-target scan

## Constructor

```python
from modules.nxos_enum import NXOSEnumerator
enum = NXOSEnumerator(
    targets=[{"ip": "10.0.0.1", "role": "apic"}],
    creds=[("admin", "admin"), ("admin", "cisco123")]
)
results = enum.run()
```

## FORGE audit

Gate: **PASSED**. Six None-dereference guards added (`if not data: return []` / `continue`) in `apic_get_fabric_nodes`, `apic_get_vmm_providers`, `apic_get_service_graphs`, `apic_get_tenants`, `apic_get_contracts`, `apic_get_out_of_band_mgmt`, these functions called `.get()` on the return value of `_apic_get()` which can return `None`. All urllib reads bounded at 4 MB. No file reads. No lief.parse().

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.nxos_enum import NXOSACIVXLANEnumeration

results = NXOSACIVXLANEnumeration.from_context(ctx).run()
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
