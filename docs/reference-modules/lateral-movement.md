# Lateral Movement

**File:** `modules/lateral_movement.py`

## Why this exists

Post-exploitation lateral movement: TCP connect scan, SSH credential spray, SMB/RDP pivot, credential harvesting from `/proc/pid/environ` and cmdline, and parallel host coverage. Synthesized from *Violent Python*, *Black Hat Python 2e*, and *Penetration Testing* (Weidman).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PROC_BYTES` | 4 MB | `/proc/pid/environ`, `/proc/pid/cmdline`, `/proc/net/arp`, `/proc/net/route` |
| `_MAX_SYSFS_BYTES` | 64 B | sysfs counter files |
| `_MAX_LOG_BYTES` | 64 MB | auth log reads |
| `_MAX_SSH_FILE_BYTES` | 1 MB | `~/.ssh/authorized_keys` and `known_hosts` reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. Four CWE-770 reads fixed this session: `/proc/net/arp` (L92) and `/proc/net/route` (L123) changed from `f.readlines()[1:]` to `f.read_MAX_PROC_BYTES.splitlines()[1:]`; `authorized_keys` (L4924) and `known_hosts` (L4974) changed from `for line in fh:` to `fh.read_MAX_SSH_FILE_BYTES.splitlines()`. `_MAX_SSH_FILE_BYTES=1MB` constant added. Socket banners bounded at `s.recv(256)`. No lief.parse(). No HTTP reads.

---

## How it works

`CloudMetadataProber().probe_all()` returns `self.results`: a dict with keys `aws_imdsv1`, `aws_imdsv2`, `aws_iam_creds`, `gcp_metadata`, `azure_imds`, `oci_imds`. `CredentialHarvester()` scans local files `~/.kube/config`, `~/.aws/credentials`, and environment variables and appends `{source, data, severity}` finding dicts. `LateralMovementEnumerator()` probes SMB null sessions and WMI unauthenticated access.

---

## Usage

```python
from modules.lateral_movement import CloudMetadataProber, CredentialHarvester

# Cloud metadata
prober = CloudMetadataProber()
result = prober.probe_all()
# result keys: aws_imdsv1, aws_imdsv2, aws_iam_creds, gcp_metadata, azure_imds, oci_imds
aws_creds = result.get('aws_iam_creds', {})
if aws_creds:
    print(f"  role: {aws_creds.get('role')}  json: {aws_creds.get('credentials_json', '')[:80]}")

# Credential harvester: findings shape {source, data, severity}
harvester = CredentialHarvester()
harvester.harvest_all()
for f in harvester.findings:
    print(f"  [{f['severity']}] {f['source']}: {str(f['data'])[:80]}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
CloudMetadataProber.probe_all():
  aws_iam_creds: {role: 'ec2-role', credentials_json: '{"AccessKeyId": "ASIA..."}'}
  gcp_metadata: {project_id: 'my-project', service_accounts: ['default@...iam.gserviceaccount.com']}
  azure_imds: {subscription_id: '...', client_id: '...'}

CredentialHarvester.findings:
  [MEDIUM] ~/.aws/credentials: {'profile': 'default', 'key': 'AKIA...'}
  [HIGH]   K8S_SA_TOKEN: eyJhbGciOiJSUzI1NiIsImtpZCI6...
```

---

## False positives

**`CloudMetadataProber.probe_all()` fires on non-cloud hosts with IMDS-like HTTP services**: any HTTP service on 169.254.169.254:80 will be probed. Corporate DHCP servers or virtual machine management agents sometimes listen on this address. Verify the response body structure matches the expected IMDS JSON format before treating as a confirmed cloud environment.

---

## Pipeline position

Run `CloudMetadataProber` immediately after gaining shell access to any host. A successful IMDS response establishes cloud credentials in seconds. Run `CredentialHarvester` to enumerate locally stored credentials before running privilege escalation.

---

## Reading findings

`CredentialHarvester.findings` shape: `{source, data, severity}`

`CloudMetadataProber.probe_all()` returns a plain data dict not a findings list:

| Key | Content |
|:---|:---|
| `aws_iam_creds` | `{role: str, credentials_json: str}` raw JSON string from IMDS |
| `gcp_metadata` | GCP instance metadata dict |
| `azure_imds` | Azure IMDS response dict |
| `aws_imdsv1` / `aws_imdsv2` | IMDSv1 and IMDSv2 probe results |

---

## See also

- [Credential Token Key Discovery](credential-token-key-discovery.md): full credential surface including IMDS keys
- [Internal Network Reconnaissance](internal-network-reconnaissance.md): cloud network pivot planning
