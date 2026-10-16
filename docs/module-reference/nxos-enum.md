# NX-OS / ACI / VXLAN Enumeration

**File:** `modules/nxos_enum.py`

## Why this exists

Cisco NX-OS, ACI/APIC, and VXLAN enumeration: NX-API REST/JSON-RPC exposure, APIC REST API unauthenticated access, VXLAN VTEP discovery, LLDP/CDP neighbor disclosure via NX-API, and default credential checks.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP response bodies read with inline `r.read(4 * 1024 * 1024)` cap (4 MB). No file reads. No lief.parse().
