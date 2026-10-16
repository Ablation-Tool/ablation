# Nexus Dashboard Enumeration

**File:** `modules/nexus_dashboard_enum.py`

## Why this exists

Cisco Nexus Dashboard, NDI, NDFC, NDO, and Data Broker enumeration. Single-SSO architecture means one credential set reaches APIC + NDFC + NDO + Data Broker. Kafka anomaly export is unauthenticated by default — this module checks for that exposure.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP response bodies read with inline `r.read(4 * 1024 * 1024)` cap (4 MB). No file reads. No lief.parse().
