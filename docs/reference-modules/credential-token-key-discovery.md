# Credential/Token/Key Discovery

Enumerate SSH private keys and `known_hosts` entries from all user home directories, detect API token patterns in environment variables and configuration files, probe AWS/GCP/Azure/OCI instance metadata services for temporary credentials, and detect SSH key reuse across multiple targets: providing the complete credential surface from a compromised host position: via `modules/lateral_movement.py`.

---

## Why this exists

1. **`SSHKeyEnumerator` finds SSH keys across all user home directories in one pass**, it walks `/home/*/`, `/root/`, and `/var/lib/*/` looking for `id_rsa`, `id_ecdsa`, `id_ed25519`, and any file matching `.*_rsa$` private key naming patterns. For each key found, it parses the PEM header to determine algorithm and whether the key is passphrase-protected. Unencrypted private keys are immediately usable for lateral movement to any host in the corresponding `known_hosts` file.

2. **`APITokenDetector` scans environment variables and configuration files for API tokens and secrets**, it checks every environment variable whose name contains `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `APIKEY`, or `CREDENTIAL`, and additionally scans files in `/etc/`, `/opt/`, `~/.config/`, and common application configuration paths. Value entropy filtering ≥ 3.5 bits/character and length ≥ 20 characters reduces false positives from non-credential variable names.

3. **`detect_ssh_key_reuse()` cross-references SSH public keys across multiple hosts**, it collects all public keys from `~/.ssh/authorized_keys` files on the local host and known hosts from `~/.ssh/known_hosts`. If the same public key appears in `authorized_keys` files on multiple hosts, a single private key compromise provides access to all of them. This is the most common finding in enterprise environments where a shared deployment key is used for automation.

---

## How it works

```mermaid
flowchart TD
    A(["SSHKeyEnumerator(base_path='/home') → enumerator\n  Walk: /home/*/.ssh/, /root/.ssh/\n  Match: id_rsa, id_ecdsa, id_ed25519, *.pem\n  Per key file:\n    PEM header: -----BEGIN RSA PRIVATE KEY-----\n    ENCRYPTED in header → passphrase required\n    parse known_hosts: hash or plaintext hosts\n  → List[SSHKey{path, algo, encrypted, known_hosts}]"]):::input --> B["APITokenDetector:\n  scan_env_variables(os.environ) → List[dict]\n    Name filter: TOKEN|KEY|SECRET|PASSWORD|APIKEY\n    Value entropy ≥ 3.5 bits/char AND len ≥ 20\n    → [{name, value_snippet, entropy, source}]\n  scan_config_files(paths) → List[dict]\n    Regex: (api_key|token|password|secret)\s*[:=]\s*['\"](\\S+)['\"]\n    → [{file, key_name, value_snippet}]"]:::primary
    B:::primary --> C["CloudMetadataProber:\n  probe_all() → self.results dict:\n    aws_imdsv1: {status, keys}\n    aws_imdsv2: {status, token}\n    aws_iam_creds: {role, credentials_json}\n    gcp_metadata: {status, project_id, service_accounts, ...}\n    azure_imds: {status, subscription_id, ...}\n    oci_imds: {status, ...}\n  Private: _probe_aws(), _probe_gcp(), _probe_azure(), _probe_oci()"]:::secondary
    C:::secondary --> D(["detect_ssh_key_reuse(scan_path='/home') → list\n  Collect all authorized_keys public keys\n  Collect known_hosts (plaintext + hashed)\n  Cross-reference: same pubkey in N files\n  → [{pubkey_fingerprint, found_in: [path, ...], reuse_count}]"]):::output
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
    SSHKeyEnumerator, APITokenDetector, CloudMetadataProber,
    detect_ssh_key_reuse
)

# SSH key enumeration — enumerate_all() returns self; read .private_keys list
enum = SSHKeyEnumerator()
enum.enumerate_all()
for k in enum.private_keys:
    # key dict: {path, mode, world_readable, group_readable, encrypted, fingerprint, type}
    enc = 'ENCRYPTED' if k['encrypted'] else 'UNENCRYPTED'
    print(f"  {k['path']} ({k['type']}, {enc})  fingerprint={k['fingerprint']}")

# Cloud metadata — probe_all() returns self.results dict
cloud = CloudMetadataProber()
results = cloud.probe_all()
# keys: aws_imdsv1, aws_imdsv2, aws_iam_creds, gcp_metadata, azure_imds, oci_imds
for provider, data in results.items():
    if isinstance(data, dict) and data.get('status') != 'BLOCKED':
        print(f"  {provider}: {list(data.keys())[:3]}")

# Key reuse detection — returns [{severity, title, detail, host, port}]
for finding in detect_ssh_key_reuse('/home'):
    print(f"  [{finding['severity']}] {finding['title']}: {finding['detail'][:80]}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
SSHKeyEnumerator:

  /home/deploy/.ssh/id_rsa  RSA, UNENCRYPTED  → 12 known hosts
  /root/.ssh/id_ed25519     ED25519, ENCRYPTED

APITokenDetector:

  GITHUB_TOKEN=<token>  (env var, entropy=<score>)
  /home/user/.config/app/config.yaml: api_key=<token>

CloudMetadataProber:

  AWS: role=<iam-role>  AccessKeyId=<access-key-id>  (temporary STS credentials)

detect_ssh_key_reuse:

  REUSE: <key-fingerprint> in 4 authorized_keys files (shared deployment key)
```

---

## False positives

**`APITokenDetector` entropy-based filtering**: high-entropy strings that are not API tokens UUID values, base64-encoded non-credential data may pass the entropy threshold. Verify the context of each match: a `SESSION_KEY` that contains a random nonce is not a credential for an external service.

**`CloudMetadataProber` timeout behavior**: on hosts not running in a cloud environment, `169.254.169.254` is not routable and the probe will time out default: 2 seconds. A timeout is a reliable negative result; treat `None` return as "not a cloud instance" rather than an error.

---

## Pipeline position

Run credential and key discovery immediately after gaining shell access, before any active scanning. SSH key enumeration and cloud metadata credential recovery are passive reads that leave no network-observable evidence.

---

## Reading findings

Each enumerator returns a list of finding dicts with `{severity, title, detail, host, port}`:

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` |
| `title` | Finding name for example `SSH_KEY_UNENCRYPTED`, `API_TOKEN_EXPOSED`, `AWS_IAM_CREDS` |
| `detail` | File path, key type, token prefix, or IAM role name with context |
| `host` | Target host or `localhost` for local file findings |
| `port` | Service port or `0` for local findings |

`detect_ssh_key_reuse()` returns a list of `{fingerprint, files}` dicts identifying shared keys.

---

## See also

- [Credential Testing Helpers](credential-testing-helpers.md): using discovered credentials in SSH/FTP spray operations
- [Internal Network Reconnaissance](internal-network-reconnaissance.md): `CredentialHarvester` for `.netrc`, `.gitconfig`, and application credential files
