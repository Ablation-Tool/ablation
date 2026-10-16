# NetSniffer

**File:** `modules/net_sniffer.py`

## Why this exists

Raw network capture and credential extraction for post-compromise enumeration. Captures clear-text credentials from HTTP Basic, FTP, SMTP AUTH, MQTT CONNECT, and SIP REGISTER frames in a promiscuous-mode socket capture session.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. HTTP XML body reads bounded at `resp.read(65536)`. Socket reads bounded: `sock.recv(4 - len(connack))` (bounded by CONNACK length), `sock.recv(1024)` for banners. Two CWE-770 procfs reads fixed: `/proc/net/arp` and `/proc/net/route` changed from `readlines()` to `read(_MAX_PROC_BYTES).splitlines()`; `_MAX_PROC_BYTES=4MB` constant added. No lief.parse().
