# HyperFlex Enumeration

**File:** `modules/hyperflex_enum.py`

## Why this exists

Cisco HyperFlex attack surface enumeration: HX Connect REST API, iSCSI/NFS exposure, UCSM, APIC, stCtlVM cluster services. Checks for default credentials, unauthenticated API endpoints, and cluster node discovery.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP response bodies read with inline `r.read(4 * 1024 * 1024)` cap (4 MB). No file reads. No lief.parse().
