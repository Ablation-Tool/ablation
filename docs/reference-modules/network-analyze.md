# Network Analysis

**File:** `modules/network_analyze.py`

## Why this exists

Network traffic analysis and active enumeration: PCAP parsing for credential extraction and protocol identification, TCP/UDP port scan with service fingerprinting, ICMP host discovery, and HTTP directory brute-force. Synthesized from *Violent Python*, *Black Hat Python 2e*, and *Hacking: The Art of Exploitation*.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PCAP_BYTES` | 512 MB | PCAP file read cap |
| `_MAX_HTTP_BYTES` | 4 MB | HTTP response body cap |
| `_MAX_PROC_BYTES` | 4 MB | `/proc/net/*` reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before PCAP `f.read()`; `_MAX_PCAP_BYTES=512MB`. HTTP reads capped at `_MAX_HTTP_BYTES=4MB`. Three CWE-770 procfs reads fixed: `/proc/net/dev`, `/proc/net/tcp`, `/proc/net/tcp6` changed from `readlines()` to `read(_MAX_PROC_BYTES).splitlines()`; `_MAX_PROC_BYTES=4MB` constant added. No lief.parse().
