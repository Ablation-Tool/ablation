# C2 / Exfiltration Indicators

Probe a live host for active command-and-control channel signatures: Cobalt Strike default beacon responses, Meterpreter HTTP stager behavior, Empire and Metasploit default listener ports, and ransomware initial-access precursors exposed RDP, OWA, Fortinet VPN, Pulse VPN: using raw socket connections with no external tool dependencies.

---

## Why this exists

1. **Known C2 framework default configurations produce distinctive network fingerprints.** Cobalt Strike with an unmodified Malleable C2 profile responds to `GET /` with HTTP 200, no `Server` header, and `Content-Length: 0` or zero body bytes. Meterpreter HTTP stager responds HTTP 200 to any path, including random 4-character URIs that no legitimate service would handle. These patterns are not guaranteed: operators change them, but they appear frequently enough in engagements that probing them before manual analysis saves time.

2. **Well-known C2 framework default ports confirm compromise without service identification.** Port 50050 is the Cobalt Strike teamserver default. Port 8443 is the PowerShell Empire default. Port 55553 is the Metasploit default reverse handler. When any of these ports responds to a TCP connect on an internal host that has no business running these services, that response alone constitutes an indicator of compromise. The function probes all three in sequence.

3. **Ransomware operators use specific exposed services as initial access vectors.** RDP (`3389`), Outlook Web Access, Fortinet VPN (`/remote/login`), and Pulse VPN (`/dana-na/auth/url_default/welcome.cgi`) are the four most common initial access broker pivot points. Identifying these services: especially unpatched VPN appliances with publicly known vulnerabilities: maps the external attack surface before an active exploitation attempt is made.

---

## How it works

```mermaid
flowchart TD
    A(["detect_c2_beaconing_indicators(host, port=443)"]):::input --> B["_http_get(host, port, '/')\nRaw TCP socket + minimal HTTP/1.1 GET\nCapture up to 64KB response"]:::primary
    B:::primary --> C{"HTTP 200?"}:::neutral
    C:::neutral -->|"200, no Server header, Content-Length 0 or empty body"| D(["Finding: POTENTIAL_CS_BEACON (MEDIUM)\nCobalt Strike default Malleable C2 pattern"]):::output
    C:::neutral -->|else| E["E"]:::secondary
    E:::secondary --> F["_http_get(host, port, '/XXXX') · 4-char random URI"]:::tertiary
    F:::tertiary --> G{"200 with non-empty body?"}:::neutral
    G:::neutral -->|yes| H(["Finding: POTENTIAL_METERPRETER_STAGER (MEDIUM)\nMeterpreter stager responds 200 to any URI path"]):::output
    G:::neutral -->|no| I["I"]:::tertiary
    I:::tertiary --> J["_http_get(host, 80, '/api/v1/health')"]:::tertiary
    J:::tertiary --> K{"200, JSON body or Content-Type=application/json?"}:::neutral
    K:::neutral -->|yes| L(["Finding: UNENCRYPTED_API_C2_SURFACE (MEDIUM)\nJSON API on plaintext HTTP · unencrypted C2 channel indicator"]):::output
    K:::neutral -->|no| M["M"]:::tertiary
    M:::tertiary --> N["_tcp_open(host, 50050) · CS teamserver"]:::tertiary
    N:::tertiary --> O{"open?"}:::neutral
    O:::neutral -->|yes| P["Finding: KNOWN_C2_PORT_OPEN (HIGH) · Cobalt_Strike_teamserver"]:::tertiary
    N:::tertiary --> Q["_tcp_open(host, 8443) · Empire"]:::tertiary
    Q:::tertiary --> R{"open?"}:::neutral
    R:::neutral -->|yes| S(["Finding: KNOWN_C2_PORT_OPEN (HIGH) · Empire_C2_default"]):::output
    N:::tertiary --> T["_tcp_open(host, 55553) · Metasploit"]:::tertiary
    T:::tertiary --> U{"open?"}:::neutral
    U:::neutral -->|yes| V(["Finding: KNOWN_C2_PORT_OPEN (HIGH) · Metasploit_default_listener"]):::output
    P:::tertiary --> W(["List[{severity, title, detail, host, port}]"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#546e7a,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#00695c,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#546e7a,stroke-width:2px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#6a1b9a,stroke-width:2px
    linkStyle 8 stroke:#6a1b9a,stroke-width:2px
    linkStyle 9 stroke:#546e7a,stroke-width:2px
    linkStyle 10 stroke:#2e7d32,stroke-width:3px
    linkStyle 11 stroke:#6a1b9a,stroke-width:2px
    linkStyle 12 stroke:#6a1b9a,stroke-width:2px
    linkStyle 13 stroke:#546e7a,stroke-width:2px
    linkStyle 14 stroke:#6a1b9a,stroke-width:2px
    linkStyle 15 stroke:#6a1b9a,stroke-width:2px
    linkStyle 16 stroke:#546e7a,stroke-width:2px
    linkStyle 17 stroke:#2e7d32,stroke-width:3px
    linkStyle 18 stroke:#6a1b9a,stroke-width:2px
    linkStyle 19 stroke:#546e7a,stroke-width:2px
    linkStyle 20 stroke:#2e7d32,stroke-width:3px
    linkStyle 21 stroke:#2e7d32,stroke-width:3px
```

```mermaid
flowchart TD
    A(["check_ras_initial_access_patterns(host, port=443)"]):::input --> B["TCP connect port 3389 · RDP"]:::primary
    B:::primary --> C["TCP connect port 80/443 + GET /owa/ · OWA"]:::secondary
    C:::secondary --> D["GET /remote/login · Fortinet VPN login page"]:::tertiary
    D:::tertiary --> E["GET /dana-na/auth/url_default/welcome.cgi · Pulse VPN"]:::tertiary
    E:::tertiary --> F(["List[{severity, title, detail, host, port}] for each responsive service"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from modules.lateral_movement import (
    detect_c2_beaconing_indicators,
    check_ras_initial_access_patterns,
)

host = "10.10.10.5"

# C2 beacon check
c2_findings = detect_c2_beaconing_indicators(host, port=443, timeout=5.0)
for f in c2_findings:
    print(f"[{f['severity']:6}]  {f['title']}")
    print(f"         {f['detail']}")

# Also check HTTP (port 80)
c2_findings += detect_c2_beaconing_indicators(host, port=80)

# RaaS initial access precursors
ras_findings = check_ras_initial_access_patterns(host, timeout=5.0)
for f in ras_findings:
    print(f"[{f['severity']:6}]  {f['title']}  host={f['host']} port={f['port']}")

# Combine and sort by severity
all_findings = c2_findings + ras_findings
all_findings.sort(key=lambda f: {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}.get(f['severity'], 9))
for f in all_findings:
    print(f"  {f['severity']:6}  {f['title']}")
```

---

## Example output

```
[HIGH  ]  KNOWN_C2_PORT_OPEN
          host=10.10.10.5 port=50050 service=Cobalt_Strike_teamserver
          note=well_known_C2_framework_default_port_responding

[MEDIUM]  POTENTIAL_CS_BEACON
          host=10.10.10.5 port=443 status=200 server_header=absent
          content_length=0 note=Cobalt_Strike_default_beacon_response_pattern

[MEDIUM]  POTENTIAL_METERPRETER_STAGER
          host=10.10.10.5 port=443 uri=/aBcD status=200 body_len=204800
          note=Meterpreter_HTTP_stager_responds_200_to_random_URIs

[HIGH  ]  FORTINET_VPN_EXPOSED
          host=10.10.10.5 port=443 path=/remote/login
          note=Fortinet_SSL-VPN_login_page_responsive
```

---

## False positives

**`POTENTIAL_CS_BEACON` on misconfigured servers.** A legitimate web server with `ServerTokens Off` and no content on `/` produces the same `Server`-absent, zero-body 200 response as an unmodified Cobalt Strike profile. This finding is an indicator, not a confirmation. Follow up with SSL certificate inspection (`openssl s_client -connect host:port`): Cobalt Strike default certificates use self-signed RSA with a known subject string.

**`POTENTIAL_METERPRETER_STAGER` on wildcard handlers.** Any server with a catch-all route that returns 200 for unknown paths common in single-page apps and load balancers triggers this finding. The distinguishing factor for Meterpreter is binary body content containing PE headers or shellcode. The function does not inspect body content: treat this as low-confidence until the response body is analyzed.

**`KNOWN_C2_PORT_OPEN` on legitimate services.** Port 8443 runs TLS services on many production hosts Elasticsearch, Kubernetes API, Jenkins. `_tcp_open()` only checks whether the port accepts a TCP connection, it does not send any protocol-specific probe. Verify with `openssl s_client -connect host:8443 </dev/null` and check the certificate subject.

---

## Pipeline position

**Before this module:** This module targets live hosts. Obtain target IPs from `NetworkDiscovery.enumerate_all()`, the VDT `tiptoe` scan, or the engagement scope.

**After this module:** For `KNOWN_C2_PORT_OPEN` and `POTENTIAL_CS_BEACON` findings: extract any SSL certificate from the port for inspection, check for default Cobalt Strike watermark license hash embedded in profile or stage. For `FORTINET_VPN_EXPOSED` / RaaS precursors: check the firmware version against known CVEs and run the appropriate binary RE analysis with `BinaryContext.load_or_build()`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `HIGH` default C2 ports, VPN with CVE exposure / `MEDIUM` behavioral indicators / `INFO` informational surface |
| `title` | Short classification: `POTENTIAL_CS_BEACON`, `KNOWN_C2_PORT_OPEN`, `FORTINET_VPN_EXPOSED`, etc. |
| `detail` | Full probe result: host, port, path, status code, headers observed, explanatory note |
| `host` | Target IP |
| `port` | Port at which the indicator was detected |

---

## See also

- [System-Call Tracing](system-call-tracing.md): dynamic trace to confirm active beaconing from a compromised host
- [Binary Format and Platform Identification](binary-format-and-platform-identification.md): identify firmware on exposed VPN appliances
- [API Authentication and Token Checks](api-authentication-and-token-checks.md): binary RE for VPN authentication bypass
