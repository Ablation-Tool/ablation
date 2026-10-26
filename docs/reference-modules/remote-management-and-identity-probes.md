# Remote Management and Identity Probes

Probe SMB for null sessions and NTLM challenge-response exposure, test WinRM authentication surfaces, detect RDP service presence, enumerate WMI unauthenticated access, probe Active Directory LDAP for anonymous bind acceptance, and extract NTLM challenge tokens for offline cracking: via `modules/lateral_movement.py`.

---

## Why this exists

1. `probe_smb_null_session()` and `probe_smb_ntlm()` map the Windows lateral movement surface: null session testing SMBv1 empty credentials reveals legacy share and user enumeration access. `probe_smb_ntlm()` sends an SMB NTLM Negotiate request and captures the NTLM Challenge message: the 8-byte server challenge embedded in the Type 2 message is used with captured NTLMv2 hashes for offline relay or cracking attacks. NTLM challenge capture requires only a TCP connection to port 445, no credentials are needed.

2. `probe_winrm()` tests whether Windows Remote Management is accessible from the network: WinRM port 5985 HTTP, port 5986 HTTPS is the PowerShell remoting and `Invoke-Command` transport. `probe_winrm()` sends an HTTP OPTIONS request to the WinRM endpoint and checks for `WWW-Authenticate: Kerberos, NTLM` in the response headers: confirming that PowerShell remoting is enabled on the target and that NTLM-based authentication is accepted. Combined with captured NTLM hashes, this confirms pass-the-hash lateral movement is viable.

3. `probe_wmi_unauth()` tests WMI DCOM exposure: WMI over DCOM port 135 + dynamic RPC can be probed for `IWbemServices` interface availability via `enumerate_rpc_endpoints()`. WMI unauthenticated enumeration is prevented by modern Windows versions, but the probe confirms whether the endpoint mapper is accessible and whether WMI namespaces respond to anonymous bind attempts: a prerequisite for pass-the-hash WMI lateral movement.

---

## How it works

```mermaid
flowchart TD
    A(["probe_smb_null_session(host) → dict\n  TCP connect → 445\n  _build_smb_negotiate() → send\n  _build_smb_session_setup_null(uid=0) → send\n  Parse NT_STATUS 0x00 → null session ok\n  → {vulnerable: bool, dialect: str, os_version: str}"]):::input --> B["probe_smb_ntlm(host, port=445) → dict\n  TCP + SMB Negotiate + NTLMSSP_NEGOTIATE\n  Parse Type 2 (NTLM Challenge) response\n    target_name, challenge_bytes[8]\n    flags: NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY\n  → {ntlm_challenge: bytes, target_name, flags}"]:::primary
    B:::primary --> C["probe_winrm(host) → dict\n  HTTP OPTIONS http://host:5985/wsman\n  Check: WWW-Authenticate header\n    Kerberos → Kerberos auth available\n    NTLM → pass-the-hash viable\n  Check: Content-Type: application/soap+xml\n  → {winrm_enabled: bool, auth_methods: List[str]}"]:::secondary
    C:::secondary --> D(["probe_wmi_unauth(host) → dict\n  enumerate_rpc_endpoints() → DCOM/RPC surface\n    TCP 135 endpoint mapper query\n    Look for: IWbemServices UUID\n  probe_rdp(host) → dict\n    TCP connect 3389 + RDP TPKT header\n    Parse CredSSP / NLA negotiation response\n    → {rdp_enabled, nla_required: bool}"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from modules.lateral_movement import (
    NetworkDiscovery, CredentialHarvester  # containing class
)

# SMB null session and NTLM probe (via host object)
# Direct function access:
from modules.lateral_movement import (
    _build_smb_negotiate, _build_smb_session_setup_null
)

# Subnet discovery: scan_subnets populates nd.live_hosts {ip: {port: banner}}
nd = NetworkDiscovery()
nd.scan_subnets(['<target-subnet>/24'], ports=[445, 5985, 3389, 135])

for ip, ports in nd.live_hosts.items():
    print(f"  {ip}: open={sorted(ports.keys())}")
    # LateralMovementEnumerator(host, port=445) — each probe is a method
    if 445 in ports:
        lme = LateralMovementEnumerator(ip, port=445)
        smb = lme.probe_smb_null_session()
        # smb: {null_session, dialect, os, security_mode, shares, error}
        print(f"    SMB null_session={smb['null_session']}  dialect={smb.get('dialect')}")
    if 5985 in ports:
        lme = LateralMovementEnumerator(ip, port=5985)
        winrm = lme.probe_winrm()
        print(f"    WinRM: {winrm}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
probe_smb_null_session: <target-ip>:445

  null_session: True  dialect: NT LM 0.12  OS: Windows Server <version>

probe_smb_ntlm: <target-ip>:445

  NTLM Challenge: <challenge-bytes>  target: <domain>  (NTLMv2 relay/crack target)

probe_winrm: <target-ip>:5985

  WinRM enabled  auth_methods: [Kerberos, NTLM]  (pass-the-hash viable)

probe_rdp: <target-ip>:3389

  RDP enabled  NLA required: True  (requires valid credentials, no CredSSP bypass)
```

---

## False positives

**`probe_smb_null_session()` dialect negotiation**: Windows Server 2019 and later with SMBv1 disabled will reject the negotiate request. A failed null session probe may indicate SMBv1 is disabled rather than that null sessions are blocked. Test SMBv2 capabilities separately.

**`probe_winrm()` NTLM in `WWW-Authenticate`**: NTLM in the WinRM auth header does not mean pass-the-hash will succeed if Kerberos delegation is enforced and NTLM is restricted via Group Policy (`Network Security: LAN Manager Authentication Level = NTLMv2 only`). Confirm NTLM authentication policy before attempting relay attacks.

---

## Pipeline position

Run remote management probes during lateral movement planning after internal network discovery identifies live Windows hosts. NTLM challenge capture from SMB is the highest-priority finding; combine with captured hashes from `CredentialHarvester` for relay or cracking.

---

## Reading findings

Remote management probe functions return `List[{severity, title, detail, host, port}]`:

| Field | Content |
|:---|:---|
| `severity` | `HIGH` auth bypass or relay target / `MEDIUM` enabled service |
| `title` | Finding code for example `SMB_NULL_SESSION`, `SMB_NTLM_RELAY_TARGET`, `WINRM_ENABLED` |
| `detail` | Dialect, OS, NTLM challenge bytes, or auth method list |
| `host` | Target host IP |
| `port` | Protocol port for example `445` for SMB, `5985` for WinRM |

---

## See also

- [Credential Testing Helpers](credential-testing-helpers.md): SSH/FTP credential spray for Linux hosts
- [Credential/Token/Key Discovery](credential-token-key-discovery.md): filesystem credential enumeration for Windows targets via `CredentialHarvester`
