# NX-OS / ACI / VXLAN Enumeration

**File:** `modules/nxos_enum.py`

## Why this exists

Cisco NX-OS, ACI/APIC, DCNM, and VXLAN enumeration. Covers: TLS cert OU discriminator dcnxos vs dcapic, APIC unauthenticated domain listing, APIC REST credential spray, full APIC MIT enumeration tenants, EPGs, contracts, L3Out networks, VMM domains, audit log, firmware versions, endpoint tracker, out-of-band management, NX-API port 443/8080, DCNM REST probing, NX-OS SSH banner grab and CLI command execution, VXLAN VTEP discovery, and Cobra SDK package disclosure.

## Key functions

- `classify_by_cert_ou(host)`: TLS cert OU discriminator NXOS_SWITCH vs APIC_CONTROLLER
- `probe_apic_unauthenticated(host)`: aaaListDomains without auth
- `apic_loginhost, user, pwd`: APIC-cookie token login
- `apic_enumeratehost, token`: full MIT enumeration 30+ classes + subtree queries
- `apic_get_contract_matrixhost, token`: EPG-to-EPG contract provided/consumed mapping
- `apic_get_l3out_networkshost, token`: L3Out external networks and BGP peers
- `apic_get_vmm_domainshost, token`: VMM lateral movement surface (vCenter IPs/creds)
- `apic_get_audit_loghost, token`: last 200 config change records
- `apic_get_endpointshost, token`: learned MAC/IP/EPG/physical-path endpoint table
- `apic_cobra_bulk_extracthost, token`: Cobra SDK.whl package disclosure
- `probe_nxapi(host)`: NX-API JSON-RPC at /ins
- `probe_dcnm(host)`: DCNM REST at /rest/*
- `run_nxos_commandshost, user, pwd`: SSH CLI batch execution
- `probe_vxlan_vteps(host)`: NVE peer and VNI enumeration
- `NXOSEnumeratortargets, creds.run()`: orchestrated multi-target scan

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

`NXOSEnumerator(targets).run()` iterates target hosts: for each host it runs `classify_by_cert_ou()` OU-based device type discrimination from the TLS certificate, `probe_nxos_ports()` open port surface, and conditionally `probe_apic_unauthenticated()`, `probe_nxapi()`, `probe_dcnm()`, or `probe_vxlan_vteps()` based on device type and open ports. Standalone functions (`probe_apic_unauthenticated`, `probe_nxapi`, `probe_nxos_ports`) return plain dicts, not finding lists.

---

## Usage

```python
from modules.nxos_enum import (
    NXOSEnumerator,
    probe_apic_unauthenticated,
    probe_nxapi,
    probe_nxos_ports,
)

# Class-based multi-host scan
targets = [{'ip': '10.0.0.1', 'role': 'apic'}, {'ip': '10.0.0.2', 'role': 'nxos'}]
enumerator = NXOSEnumerator(targets)
result = enumerator.run()
# result keys: cert_classification, apic_unauthenticated, apic_credential_spray,
#              apic_full_enum, nxos_port_surface, nxapi_probe, dcnm_probe, vxlan_vtep_probe, summary

# Standalone: probe_apic_unauthenticated returns {host, reachable, aaa_domains, raw_domains_response}
apic = probe_apic_unauthenticated('10.0.0.1')
if apic['reachable']:
    print(f"AAA domains: {apic['aaa_domains']}")

# probe_nxapi returns {host, reachable, version, apis_accessible, error}
nxapi = probe_nxapi('10.0.0.2')
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
NXOSEnumerator.run():
  apic_unauthenticated: [{host: '10.0.0.1', reachable: True, aaa_domains: ['DefaultAuth', 'ldap']}]
  nxapi_probe: [{host: '10.0.0.2', reachable: True, version: '9.3(10)', apis_accessible: True}]

probe_nxos_ports:
  {host: '10.0.0.2', open_ports: {22: 'ssh', 443: 'https', 830: 'netconf'}}
```

---

## False positives

**`probe_apic_unauthenticated()` `aaa_domains` on non-APIC hosts**: the AAA domain list endpoint (`/api/aaaListDomains.json`) may be served by other Cisco web interfaces that share the same URL path. Verify `Content-Type: application/json` and the `imdata` key in the response before treating this as a confirmed APIC surface.

**`classify_by_cert_ou()` misclassification on self-signed certs**: a self-signed certificate with a generic OU (e.g., `Engineering`) will classify as `UNKNOWN` device type. In this case all probe types run APIC, NX-API, DCNM, which increases probe traffic.

---

## Pipeline position

Run `NXOSEnumerator` after port scanning identifies Cisco ACI/NX-OS management ports TCP/443, TCP/830, TCP/9443. Run `probe_apic_unauthenticated()` directly when targeting known APIC controllers.

---

## Reading findings

Standalone functions return plain data dicts not finding lists:

| Function | Return shape |
|:---|:---|
| `probe_apic_unauthenticated(host)` | `{host, reachable, aaa_domains: List[str], raw_domains_response}` |
| `probe_nxapi(host)` | `{host, reachable, version, apis_accessible, error}` |
| `probe_nxos_ports(host)` | `{host, open_ports: {port: service_name}}` |
| `probe_vxlan_vtepslocal_host` | `{host, vteps: List[str], error}` |

---

## See also

- [FindingRegistry](registry.md): record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md): chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md): port and service fingerprinting
