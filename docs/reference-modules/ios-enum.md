# IOS / IOS-XE Enumeration

**File:** `modules/ios_enum.py`

## Why this exists

Cisco IOS and IOS-XE attack surface enumeration: SNMP community string brute-force, IOS HTTP server exposure, console/aux port detection, enable password strength assessment, telnet fallback detection, and Smart Install protocol probing.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All socket reads bounded: `recv(1024)` for service banners, `recv(4096)` for flush. HTTP response bodies read with inline `r.read4 * 1024 * 1024` cap (4 MB). No file reads. No lief.parse().

---

## How it works

`IOSEnumerator(host, timeout=8).run()` probes a Cisco IOS/IOS-XE device in sequence: `probe_telnet()` banner and IOS version without auth, `brute_snmp_communities()` common community strings, `probe_cdp_info()` neighbor table via SNMP, `probe_tftp_config()` TFTP config pull, and `probe_http_api()` REST API credential probe. Returns `{host, telnet, snmp, cdp_neighbors, tftp_config, http_api, parsed_config, findings}`. `findings` is a list of `{severity, title, detail}` dicts.

---

## Usage

```python
from modules.ios_enum import IOSEnumerator

enum = IOSEnumerator('10.0.0.1', timeout=8)
result = enum.run()
# result keys: host, telnet, snmp, cdp_neighbors, tftp_config, http_api, findings

# findings: [{severity, title, detail}]
for f in result['findings']:
    print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")

# cdp_neighbors shows adjacent Cisco devices
if result['cdp_neighbors'].get('neighbors'):
    print(f"CDP neighbors: {result['cdp_neighbors']['neighbors']}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
IOSEnumerator.run(): 10.0.0.1

findings:
  [MEDIUM] IOS Telnet Open — Version Exposed: Cisco IOS Software, Version 15.6(3)M
  [HIGH]   IOS SNMP Weak Community: public — sysDescr Cisco IOS ...

cdp_neighbors: [{'label': '10.0.0.2'}, {'label': '10.0.0.3'}]
```

---

## False positives

**`brute_snmp_communities()` with the `public` community string**: community string `public` is present on almost every unmodified Cisco device. The finding is accurate; escalation depends on whether SNMP v3 is also available. Cross-reference with the target's SNMP configuration to determine whether SNMP v1/v2c should have been disabled.

---

## Pipeline position

Run `IOSEnumerator` after confirming a Cisco IOS device via SSH banner or HTTPS certificate CN. Run standalone probes (`probe_cisco_aaa_bypass`, `probe_cisco_snmp_extended`) for targeted AAA/SNMP surface analysis.

---

## Reading findings

`IOSEnumerator.findings` shape: `{severity, title, detail}`

| Field | Content |
|:---|:---|
| `severity` | `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `title` | Short finding name (e.g., `IOS Telnet Open: Version Exposed`, `IOS SNMP Weak Community: public`) |
| `detail` | Detail string (version string, SNMP sysDescr excerpt, etc.) |

---

## See also

- [FindingRegistry](registry.md): record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md): chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md): port and service fingerprinting
