# NX-OS / ACI / VXLAN Enumeration

**File:** `modules/nxos_enum.py`

## Why this exists

Cisco NX-OS, ACI/APIC, DCNM, and VXLAN enumeration. Covers: TLS cert OU discriminator (dcnxos vs dcapic), APIC unauthenticated domain listing, APIC REST credential spray, full APIC MIT enumeration (tenants, EPGs, contracts, L3Out networks, VMM domains, audit log, firmware versions, endpoint tracker, out-of-band management), NX-API (port 443/8080), DCNM REST probing, NX-OS SSH banner grab and CLI command execution, VXLAN VTEP discovery, and Cobra SDK package disclosure.

## Key functions

- `classify_by_cert_ou(host)` — TLS cert OU discriminator (NXOS_SWITCH vs APIC_CONTROLLER)
- `probe_apic_unauthenticated(host)` — aaaListDomains without auth
- `apic_login(host, user, pwd)` — APIC-cookie token login
- `apic_enumerate(host, token)` — full MIT enumeration (30+ classes + subtree queries)
- `apic_get_contract_matrix(host, token)` — EPG-to-EPG contract provided/consumed mapping
- `apic_get_l3out_networks(host, token)` — L3Out external networks and BGP peers
- `apic_get_vmm_domains(host, token)` — VMM lateral movement surface (vCenter IPs/creds)
- `apic_get_audit_log(host, token)` — last 200 config change records
- `apic_get_endpoints(host, token)` — learned MAC/IP/EPG/physical-path endpoint table
- `apic_cobra_bulk_extract(host, token)` — Cobra SDK .whl package disclosure
- `probe_nxapi(host)` — NX-API JSON-RPC at /ins
- `probe_dcnm(host)` — DCNM REST at /rest/*
- `run_nxos_commands(host, user, pwd)` — SSH CLI batch execution
- `probe_vxlan_vteps(host)` — NVE peer and VNI enumeration
- `NXOSEnumerator(targets, creds).run()` — orchestrated multi-target scan

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

Gate: **PASSED**. Six None-dereference guards added (`if not data: return []` / `continue`) in `apic_get_fabric_nodes`, `apic_get_vmm_providers`, `apic_get_service_graphs`, `apic_get_tenants`, `apic_get_contracts`, `apic_get_out_of_band_mgmt` — these functions called `.get()` on the return value of `_apic_get()` which can return `None`. All urllib reads bounded at 4 MB. No file reads. No lief.parse().
