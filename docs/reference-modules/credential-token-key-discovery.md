# Credential/Token/Key Discovery

Enumerate SSH private keys and `known_hosts` entries from all user home directories, detect API token patterns in environment variables and configuration files, probe AWS/GCP/Azure/OCI instance metadata services for temporary credentials, and detect SSH key reuse across multiple targets — providing the complete credential surface from a compromised host position — via `modules/lateral_movement.py`.

---

## Why this exists

1. **`SSHKeyEnumerator` finds SSH keys across all user home directories in one pass** — it walks `/home/*/`, `/root/`, and `/var/lib/*/` looking for `id_rsa`, `id_ecdsa`, `id_ed25519`, and any file matching `.*_rsa$` private key naming patterns. For each key found, it parses the PEM header to determine algorithm and whether the key is passphrase-protected. Unencrypted private keys are immediately usable for lateral movement to any host in the corresponding `known_hosts` file.

2. **`APITokenDetector` scans environment variables and configuration files for API tokens and secrets** — it checks every environment variable whose name contains `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `APIKEY`, or `CREDENTIAL`, and additionally scans files in `/etc/`, `/opt/`, `~/.config/`, and common application configuration paths. Value entropy filtering (≥ 3.5 bits/character and length ≥ 20 characters) reduces false positives from non-credential variable names.

3. **`detect_ssh_key_reuse()` cross-references SSH public keys across multiple hosts** — it collects all public keys from `~/.ssh/authorized_keys` files on the local host and known hosts from `~/.ssh/known_hosts`. If the same public key appears in `authorized_keys` files on multiple hosts, a single private key compromise provides access to all of them. This is the most common finding in enterprise environments where a shared deployment key is used for automation.

---

## How it works

```mermaid
flowchart TD
    A["SSHKeyEnumerator(base_path='/home') → enumerator\n  Walk: /home/*/.ssh/, /root/.ssh/\n  Match: id_rsa, id_ecdsa, id_ed25519, *.pem\n  Per key file:\n    PEM header: -----BEGIN RSA PRIVATE KEY-----\n    ENCRYPTED in header → passphrase required\n    parse known_hosts: hash or plaintext hosts\n  → List[SSHKey{path, algo, encrypted, known_hosts}]"] --> B["APITokenDetector:\n  scan_env_variables(os.environ) → List[dict]\n    Name filter: TOKEN|KEY|SECRET|PASSWORD|APIKEY\n    Value entropy ≥ 3.5 bits/char AND len ≥ 20\n    → [{name, value_snippet, entropy, source}]\n  scan_config_files(paths) → List[dict]\n    Regex: (api_key|token|password|secret)\s*[:=]\s*['\"](\\S+)['\"]\n    → [{file, key_name, value_snippet}]"]
    B --> C["CloudMetadataProber:\n  probe_aws() → {role, AccessKeyId, SecretAccessKey, Token}\n    GET 169.254.169.254/latest/meta-data/iam/security-credentials/<role>\n  probe_gcp() → {service_accounts, project_id}\n    GET 169.254.169.254/computeMetadata/v1/ Metadata-Flavor:Google\n  probe_azure() → {subscription_id, resource_group, managed_identity_token}\n    GET 169.254.169.254/metadata/instance?api-version=2021-02-01\n  → highest-value credential by cloud provider"]
    C --> D["detect_ssh_key_reuse(scan_path='/home') → list\n  Collect all authorized_keys public keys\n  Collect known_hosts (plaintext + hashed)\n  Cross-reference: same pubkey in N files\n  → [{pubkey_fingerprint, found_in: [path, ...], reuse_count}]"]
```

---

## Usage

```python
from modules.lateral_movement import (
    SSHKeyEnumerator, APITokenDetector, CloudMetadataProber,
    detect_ssh_key_reuse
)

# SSH key enumeration
enum = SSHKeyEnumerator()
keys = enum.enumerate()
for k in keys:
    enc = 'ENCRYPTED' if k.encrypted else 'UNENCRYPTED'
    print(f"  {k.path} ({k.algo}, {enc}) → {len(k.known_hosts)} hosts")

# Cloud metadata credentials
cloud = CloudMetadataProber()
for probe_fn, name in [(cloud.probe_aws, 'AWS'), (cloud.probe_gcp, 'GCP')]:
    creds = probe_fn()
    if creds:
        print(f"  {name}: {list(creds.keys())[:3]}")

# Key reuse detection
reuse = detect_ssh_key_reuse('/home')
for r in reuse:
    if r['reuse_count'] > 1:
        print(f"  KEY REUSE: {r['pubkey_fingerprint']} in {r['reuse_count']} files")
```

---

## Example output

The following illustrates credential and key discovery output format.

```
SSHKeyEnumerator:

  /home/deploy/.ssh/id_rsa  RSA, UNENCRYPTED  → 12 known hosts
  /root/.ssh/id_ed25519     ED25519, ENCRYPTED

APITokenDetector:

  GITHUB_TOKEN=ghp_***  (env var, entropy=4.8)
  /home/user/.config/app/config.yaml: api_key=sk-***

CloudMetadataProber:

  AWS: role=ec2-deploy  AccessKeyId=ASIA...  (temporary STS credentials)

detect_ssh_key_reuse:

  REUSE: SHA256:Abc... in 4 authorized_keys files (shared deployment key)
```

---

## False positives

**`APITokenDetector` entropy-based filtering** — high-entropy strings that are not API tokens (UUID values, base64-encoded non-credential data) may pass the entropy threshold. Verify the context of each match — a `SESSION_KEY` that contains a random nonce is not a credential for an external service.

**`CloudMetadataProber` timeout behavior** — on hosts not running in a cloud environment, `169.254.169.254` is not routable and the probe will time out (default: 2 seconds). A timeout is a reliable negative result; treat `None` return as "not a cloud instance" rather than an error.

---

## Pipeline position

Run credential and key discovery immediately after gaining shell access, before any active scanning. SSH key enumeration and cloud metadata credential recovery are passive reads that leave no network-observable evidence.

---

## See also

- [Credential Testing Helpers](credential-testing-helpers.md) — using discovered credentials in SSH/FTP spray operations
- [Internal Network Reconnaissance](internal-network-reconnaissance.md) — `CredentialHarvester` for `.netrc`, `.gitconfig`, and application credential files
