# Nginx Enumeration

**File:** `modules/nginx_enum.py`

## Why this exists

Nginx attack surface enumeration with version-specific CVE coverage: CVE-2013-4547 (null byte URI bypass), CVE-2014-0133 (SPDY heap overflow), alias traversal misconfigurations, stub_status exposure, and TLS version negotiation testing. Socket-based probing for SNI, chunked encoding handling, and header injection vectors.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All socket reads bounded: `sock.recv(4096)` throughout. No file reads. No lief.parse().
