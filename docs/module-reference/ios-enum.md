# IOS / IOS-XE Enumeration

**File:** `modules/ios_enum.py`

## Why this exists

Cisco IOS and IOS-XE attack surface enumeration: SNMP community string brute-force, IOS HTTP server exposure, console/aux port detection, enable password strength assessment, telnet fallback detection, and Smart Install protocol probing.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All socket reads bounded: `recv(1024)` for service banners, `recv(4096)` for flush. HTTP response bodies read with inline `r.read(4 * 1024 * 1024)` cap (4 MB). No file reads. No lief.parse().
