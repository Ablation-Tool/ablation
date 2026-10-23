# NetSniffer

**File:** `modules/net_sniffer.py`

## Why this exists

Raw network capture and credential extraction for post-compromise enumeration. Captures clear-text credentials from HTTP Basic, FTP, SMTP AUTH, MQTT CONNECT, and SIP REGISTER frames in a promiscuous-mode socket capture session.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. HTTP XML body reads bounded at `resp.read(65536)`. Socket reads bounded: `sock.recv(4 - len(connack))` bounded by CONNACK length, `sock.recv(1024)` for banners. Two CWE-770 procfs reads fixed: `/proc/net/arp` and `/proc/net/route` changed from `readlines()` to `read_MAX_PROC_BYTES.splitlines()`; `_MAX_PROC_BYTES=4MB` constant added. No lief.parse().

---

## How it works

`RawSniffer(interface=None).sniff(duration=10.0)` opens a raw socket (`SOCK_RAW`) and captures for `duration` seconds. Returns `{packets: int, credentials: list, connections: list}`. `CredentialExtractor` inside the sniffer extracts HTTP Basic Auth, FTP `USER`/`PASS`, and Telnet sequence patterns from payload bytes. `MDNSDiscovery` and `SSDPDiscovery` listen for multicast announcements and return structured service inventory dicts. Requires root.

---

## Usage

```python
from modules.net_sniffer import RawSniffer, MDNSDiscovery, SSDPDiscovery

# Packet capture — requires root
sniffer = RawSniffer(interface='eth0')
result = sniffer.sniff(duration=30.0)
# result: {packets: int, credentials: list, connections: list}
print(f"Captured {result['packets']} packets")
for cred in result['credentials']:
    print(f"  credential: {cred}")

# mDNS service discovery
mdns = MDNSDiscovery()
services = mdns.discover(duration=10.0)

# SSDP UPnP discovery
ssdp = SSDPDiscovery()
devices = ssdp.discover()
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
RawSniffer.sniff(duration=30):
  packets: 847
  credentials: [{'type': 'HTTP_BASIC', 'host': '10.0.0.1', 'auth': 'admin:password123'}]
  connections: [('10.0.0.5', '10.0.0.1', 80), ('10.0.0.5', '10.0.0.2', 443)]
```

---

## False positives

**`RawSniffer` requires a promiscuous-mode interface**: on a switched network without port mirroring, the raw socket only sees broadcast/multicast traffic and traffic to/from the host. Credentials extracted belong to the local host's connections only; the sniffer does not see other hosts' traffic without a SPAN port or mirror.

**`CredentialExtractor` HTTP Basic Auth detection**: the extractor decodes base64 strings following `Authorization: Basic`. A false positive can occur if a non-auth base64 string happens to parse as UTF-8 text with a colon separator. Verify that the decoded string matches the `username:password` pattern.

---

## Pipeline position

Run `RawSniffer` after gaining root shell access on a network switch or router with traffic mirroring. Run `MDNSDiscovery` and `SSDPDiscovery` for passive internal network service inventory without generating scan traffic.

---

## Reading findings

`RawSniffer.sniff()` returns a plain data dict, not a findings list:

| Field | Content |
|:---|:---|
| `packets` | Total packets captured |
| `credentials` | List of extracted credential dicts |
| `connections` | List of `src_ip, dst_ip, dst_port` tuples |

---

## See also

- [FindingRegistry](registry.md): record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md): chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md): port and service fingerprinting
