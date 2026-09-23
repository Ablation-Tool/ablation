#!/usr/bin/env python3
"""
TLS Certificate Chain and Cipher Suite Analyzer
Synthesized from: Real-World Cryptography (David Wong), TLS Cryptography in Depth,
                  Serious Cryptography 2nd Ed (Aumasson), Post-Quantum Security for AI,
                  Applied Cryptography (Schneier 20th Ed)

Covers:
  - TLS certificate chain extraction + deep vulnerability detection
  - Version/cipher probing (TLS 1.0/1.1, RC4, 3DES, NULL, EXPORT, anon DH)
  - Certificate transparency anomaly detection (CT poison = honeypot signal per Insight #97)
  - HSTS / HPKP header detection
  - Quantum-vulnerability inventory (RSA/ECDSA -> Shor-vulnerable; ML-KEM/ML-DSA -> safe)
  - MacStadium-specific: idp.macstadium.com, api.macstadium.com, *.orka.macstadium.com

TLS 1.3 handshake facts (from Real-World Cryptography ch. 9):
  - Phase 1 (Key Exchange): ClientHello + ServerHello; ephemeral ECDHE/X25519
  - Phase 2 (Server Parameters): additional negotiation, encrypted
  - Phase 3 (Authentication): Certificate -> CertificateVerify -> Finished
  - HKDF (RFC 5869) derives handshake_secret -> app_traffic_secret; SHA-256/384
  - All key exchanges are ephemeral in TLS 1.3 -> forward secrecy guaranteed

Post-quantum threat model (from NIST FIPS 203/204/205):
  - Shor's algorithm: breaks RSA, ECDSA, ECDH in polynomial time on a quantum computer
  - Grover's algorithm: halves effective key length of symmetric ciphers (AES-128 -> 64-bit)
  - Quantum-safe replacements: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+)
"""

import hashlib
import json
import os
import re
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

# ── MacStadium target constants ───────────────────────────────────────────────
MACSTADIUM_HOSTS = [
    ('idp.macstadium.com',   443),
    ('api.macstadium.com',   443),
    ('orka.macstadium.com',  443),
]

# ── TLS weak cipher/protocol detection ───────────────────────────────────────

# TLS protocol versions deprecated by RFC 8996 (March 2021)
DEPRECATED_TLS_VERSIONS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'}

# Cipher patterns known to be cryptographically broken:
#   RC4  - stream cipher with statistical biases (RFC 7465)
#   3DES - SWEET32 birthday attack (CVE-2016-2183)
#   NULL - no encryption at all
#   EXPORT - 40/56-bit key export ciphers (FREAK, LOGJAM)
#   ANON/ADH/AECDH - anonymous DH, no server authentication (trivial MITM)
WEAK_CIPHER_PATTERN = re.compile(
    r'(?i)(RC4|3DES|DES_?EDE|NULL|EXPORT|ANON|ADH|AECDH|EXP_)'
)

# Key size thresholds grounded in NIST SP 800-131A Rev 2
RSA_MIN_BITS = 2048      # RSA < 2048 = WEAK; < 1024 = CRITICAL
EC_MIN_BITS  = 256       # ECDSA/ECDH < 256 = WEAK

# Signature algorithms considered broken or deprecated
WEAK_SIG_ALGORITHMS = {
    'md5WithRSAEncryption':  'MD5 (classically broken, trivial collision)',
    'sha1WithRSAEncryption': 'SHA-1 (SHAttered collision, CVE-2017-2905)',
    'sha1WithECDSA':         'SHA-1 with ECDSA (SHA-1 broken)',
    'dsaWithSHA1':           'DSA with SHA-1',
}

# Quantum-vulnerable key algorithms (Shor's algorithm)
QUANTUM_VULNERABLE_KEY_TYPES = {
    'rsaEncryption':       'RSA — Shor\'s algorithm factors modulus in polynomial time',
    'id-ecPublicKey':      'ECDSA/ECDH — Shor\'s algorithm solves ECDLP in polynomial time',
    'dhpublicnumber':      'Finite-field DH — Shor\'s algorithm applies',
    'dsaEncryption':       'DSA — Shor\'s algorithm breaks discrete log',
}

# NIST FIPS 203/204/205 (Aug 2024) quantum-safe algorithms
QUANTUM_SAFE_KEY_TYPES = {
    'id-alg-ml-kem':       'ML-KEM (Kyber) — FIPS 203; lattice-based KEM',
    'id-alg-ml-dsa':       'ML-DSA (Dilithium) — FIPS 204; lattice-based signatures',
    'id-alg-slh-dsa':      'SLH-DSA (SPHINCS+) — FIPS 205; hash-based signatures',
    'id-alg-falcon':       'Falcon (FN-DSA) — NIST alternate candidate',
}

# Certificate transparency: CT poison extension OID
CT_POISON_OID = '1.3.6.1.4.1.11129.2.4.3'  # Pre-certificate poison

# ── Weak cipher code registry ─────────────────────────────────────────────────

# Numeric cipher suite codes that are cryptographically broken or provide no
# server authentication. Used by detect_protocol_weaknesses() to label
# cipher suites selected from adversarial ClientHellos.
#
# Sources: RFC 5246 (TLS 1.2), RFC 4492 (ECDHE), RFC 2246 (TLS 1.0),
#          IANA TLS Cipher Suite Registry, Logjam (2015), FREAK (2015).
WEAK_CIPHER_CODES = {
    # NULL cipher suites — no encryption of any kind
    0x0000: 'TLS_NULL_WITH_NULL_NULL',
    0x0001: 'TLS_RSA_WITH_NULL_MD5',
    0x0002: 'TLS_RSA_WITH_NULL_SHA',
    0x000A: 'TLS_RSA_WITH_NULL_SHA256',
    # EXPORT ciphers — 40/56-bit key caps mandated by 1990s US export law
    # FREAK (CVE-2015-0204) and LOGJAM (CVE-2015-4000) exploit these.
    0x0003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    0x0006: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
    0x0008: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x000B: 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
    0x000E: 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x0011: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
    0x0014: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x0017: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
    0x0019: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
    0x0062: 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
    0x0063: 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
    # Anonymous DH/ECDH suites — no server authentication; trivial MITM
    0x0018: 'TLS_DH_anon_WITH_RC4_128_MD5',
    0x001B: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
    0x0034: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
    0x003A: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
    0x006C: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
    0x006D: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
    0xC015: 'TLS_ECDH_anon_WITH_NULL_SHA',
    0xC016: 'TLS_ECDH_anon_WITH_RC4_128_SHA',
    0xC017: 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
    0xC018: 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
    0xC019: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
    # SSLv2 CipherKind codes (0xFF00+ sentinel range for pre-TLS protocols)
    0xFF01: 'SSL_CK_RC4_128_WITH_MD5',
    0xFF02: 'SSL_CK_RC4_128_EXPORT40_WITH_MD5',
    0xFF03: 'SSL_CK_RC2_128_CBC_WITH_MD5',
    0xFF04: 'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5',
    0xFF05: 'SSL_CK_IDEA_128_CBC_WITH_MD5',
    0xFF06: 'SSL_CK_DES_64_CBC_WITH_MD5',
    0xFF07: 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5',
}

# RFC 2409 / RFC 3526 MODP group primes all embed the hex substring
# 'c90fdaa22168c234' derived from the fractional digits of pi.
# Any DH prime containing this marker is a known published group —
# meaning offline NFS pre-computation (Logjam 2015) has already been
# performed at academic/national scale for the 768-bit and 1024-bit groups.
_LOGJAM_PRIME_FINGERPRINTS = frozenset({
    'c90fdaa22168c234',   # pi-derived constant present in all RFC 2409/3526 MODP primes
})

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ssl_ctx_no_verify() -> ssl.SSLContext:
    """Create an SSL context that does not verify certificates.

    Required to analyze self-signed or expired certs without connection failure.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def _ssl_ctx_verify() -> ssl.SSLContext:
    """Create an SSL context using the system trust store."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx


def _http_get_headers(host: str, port: int = 443, path: str = '/', timeout: int = 5) -> dict:
    """Fetch HTTP headers from a TLS endpoint.

    Returns dict of header name -> value (lowercase keys).
    Returns {} on failure.
    """
    ctx = _ssl_ctx_no_verify()
    url = f'https://{host}:{port}{path}' if port != 443 else f'https://{host}{path}'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return {}


def _parse_cert_not_after(not_after_str: str) -> Optional[datetime]:
    """Parse cert notAfter string into UTC datetime."""
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%Y%m%d%H%M%SZ'):
        try:
            dt = datetime.strptime(not_after_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _cert_sha256(der_bytes: bytes) -> str:
    """SHA-256 fingerprint of a DER-encoded certificate."""
    return hashlib.sha256(der_bytes).hexdigest().upper()


def _extract_cert_key_info(cert_dict: dict) -> dict:
    """Extract key algorithm and size from ssl.getpeercert() dict."""
    spki = cert_dict.get('subjectPublicKeyInfo', {})
    return {
        'algorithm':  spki.get('algorithm', 'unknown'),
        'bits':       spki.get('bits', None),
    }


def _get_san_names(cert_dict: dict) -> list:
    """Extract Subject Alternative Names from cert dict."""
    sans = []
    for entry in cert_dict.get('subjectAltName', []):
        if isinstance(entry, tuple) and len(entry) == 2:
            sans.append(entry[1])
        elif isinstance(entry, str):
            sans.append(entry)
    return sans


# ── Core TLS analysis ─────────────────────────────────────────────────────────

class TLSAnalyzer:
    """
    TLS certificate chain and cipher suite analyzer.

    Grounded in:
      - Real-World Cryptography ch. 9 (TLS 1.3 handshake, X.509, web PKI)
      - TLS Cryptography in Depth (pub-key cryptography, DH, cipher suites)
      - Post-Quantum Security for AI ch. 1, 10 (Shor's algorithm, FIPS 203/204/205)
      - Applied Cryptography (Schneier): RSA, DH, discrete log intractability
    """

    def __init__(self):
        self.findings = []

    # ── Main analysis entry point ─────────────────────────────────────────────

    def analyze(self, host: str, port: int = 443, timeout: int = 8) -> dict:
        """Full TLS analysis for a host:port.

        Returns dict with cert chain info, cipher info, all findings.
        """
        result = {
            'host':              host,
            'port':              port,
            'tls_version':       None,
            'cipher':            None,
            'cert_chain':        [],
            'headers':           {},
            'findings':          [],
            'quantum_inventory': {},
            'hsts':              {},
            'http_redirect':     {},
            'dns_zone_transfer': {},
            'ocsp_stapling':     {},
            'error':             None,
        }

        # 1. Connect and get TLS session info
        tls_info = self._connect_tls(host, port, timeout)
        if tls_info.get('error'):
            result['error'] = tls_info['error']
            finding = {
                'type':     'TLS_CONNECT_ERROR',
                'severity': 'INFO',
                'host':     host,
                'port':     port,
                'detail':   tls_info['error'],
                'exploit':  '',
            }
            result['findings'].append(finding)
            self.findings.append(finding)
            return result

        result['tls_version'] = tls_info.get('version')
        result['cipher']      = tls_info.get('cipher')
        result['cert_chain']  = tls_info.get('cert_chain', [])

        # 2. TLS version check
        self._check_tls_version(host, port, tls_info, result)

        # 3. Cipher suite check
        self._check_cipher_suite(host, port, tls_info, result)

        # 4. Certificate chain vulnerability analysis
        for cert_info in tls_info.get('cert_chain', []):
            self._check_cert(host, port, cert_info, result)

        # 5. CT poison / honeypot detection
        self._check_ct_poison(host, port, tls_info, result)

        # 6. HSTS / HPKP headers
        headers = _http_get_headers(host, port, timeout=timeout)
        result['headers'] = headers
        self._check_security_headers(host, port, headers, result)

        # 7. Quantum inventory from cert key type
        result['quantum_inventory'] = self._quantum_inventory(tls_info)

        # 8. Protocol-level cryptographic weakness detection (Applied Cryptography)
        proto_findings = self.detect_protocol_weaknesses(host, port, timeout=timeout)
        result['findings'].extend(proto_findings)

        # 9. HSTS header (direct TLS socket probe)
        hsts_info = self.check_hsts_header(host, port)
        result['hsts'] = hsts_info
        f = hsts_info.get('finding')
        if f:
            result['findings'].append(f)

        # 10. HTTP-to-HTTPS redirect
        http_redirect = self.check_http_redirect(host)
        result['http_redirect'] = http_redirect
        f = http_redirect.get('finding')
        if f:
            result['findings'].append(f)

        # 11. DNS zone transfer (derive domain from host)
        dns_zt = self.check_dns_zone_transfer(host)
        result['dns_zone_transfer'] = dns_zt
        f = dns_zt.get('finding')
        if f:
            result['findings'].append(f)

        # 12. OCSP stapling probe
        ocsp_info = self.check_ocsp_stapling(host, port)
        result['ocsp_stapling'] = ocsp_info
        f = ocsp_info.get('finding')
        if f:
            result['findings'].append(f)

        # 13. Protocol downgrade (SSLv3 / TLS 1.0 / TLS 1.1)
        downgrade_findings = self.check_protocol_downgrade(host, port, timeout=timeout)
        result['findings'].extend(downgrade_findings)

        # 14. Cipher suite ordering / forward-secrecy probe
        cipher_order = self.check_cipher_suite_ordering(host, port, timeout=timeout)
        result['cipher_ordering'] = cipher_order
        if cipher_order.get('accepted_rsa_kex'):
            result['findings'].append({
                'type':     'NO_FORWARD_SECRECY_CIPHER_ACCEPTED',
                'severity': 'HIGH',
                'host':     host,
                'port':     port,
                'detail':   (
                    'Server accepts RSA key-exchange cipher suites (no forward secrecy). '
                    'RSA key exchange: client encrypts pre-master secret with server RSA public key. '
                    'If the server RSA private key is recovered (Heartbleed, server compromise, '
                    'compelled disclosure), ALL past sessions are retroactively decryptable. '
                    'DHE/ECDHE ephemeral key exchange is not present or not preferred.'
                ),
                'exploit':  (
                    f'openssl s_client -connect {host}:{port} -cipher "kRSA" '
                    f'2>/dev/null | grep "Cipher    :" ; '
                    f'# Capture traffic + recover RSA private key -> decrypt all sessions'
                ),
            })

        # 15. Certificate Transparency SCT check
        ct_findings = self.check_certificate_transparency(host, port)
        result['findings'].extend(ct_findings)

        # 16. RC4 / NULL / EXPORT cipher acceptance
        rne_findings = self.check_rc4_null_export(host, port)
        result['findings'].extend(rne_findings)

        # 17. TLS compression (CRIME attack, CVE-2012-4929)
        step17 = self.check_tls_compression(host, port)
        self.findings.extend(step17)

        # 18. Client certificate authentication bypass
        step18 = self.check_client_auth_bypass(host, port)
        self.findings.extend(step18)

        # 19. Session resumption abuse
        step19 = self.check_session_resumption_abuse(host, port)
        self.findings.extend(step19)

        # 20. BEAST vulnerability (TLS 1.0 + CBC)
        step20 = self.check_beast_vulnerability(host, port)
        self.findings.extend(step20)

        self.findings.extend(result['findings'])
        return result

    # ── TLS connection ────────────────────────────────────────────────────────

    def _connect_tls(self, host: str, port: int, timeout: int) -> dict:
        """Connect to host:port, return TLS session information.

        Uses CERT_NONE so self-signed / expired certs don't abort the probe.
        This mirrors the approach in Real-World Cryptography sec. 9.1.2:
        the client configuration determines what it will accept.
        """
        ctx = _ssl_ctx_no_verify()
        info = {
            'version': None, 'cipher': None, 'cipher_bits': None,
            'cert_chain': [], 'error': None,
        }

        try:
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    cipher_info = ssock.cipher()   # (name, protocol, bits)
                    info['version']     = ssock.version()
                    info['cipher']      = cipher_info[0] if cipher_info else None
                    info['cipher_bits'] = cipher_info[2] if cipher_info else None

                    # Primary cert (peer cert)
                    cert_der  = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()  # decoded, no sig verification

                    if cert_der and cert_dict:
                        primary = self._parse_cert(cert_der, cert_dict, position=0)
                        info['cert_chain'].append(primary)

        except ssl.SSLError as e:
            info['error'] = f'SSL_ERROR: {e}'
        except (socket.timeout, ConnectionRefusedError) as e:
            info['error'] = f'CONNECT_TIMEOUT: {e}'
        except OSError as e:
            info['error'] = f'NETWORK_ERROR: {e}'

        return info

    # ── Certificate parsing ───────────────────────────────────────────────────

    def _parse_cert(self, cert_der: bytes, cert_dict: dict, position: int) -> dict:
        """Build a normalized cert info dict from DER + decoded dict."""
        subject = dict(x[0] for x in cert_dict.get('subject', []) if x)
        issuer  = dict(x[0] for x in cert_dict.get('issuer',  []) if x)

        # Key info — ssl module exposes limited info; extract what we can
        key_info = _extract_cert_key_info(cert_dict)

        return {
            'position':        position,
            'sha256':          _cert_sha256(cert_der),
            'subject_cn':      subject.get('commonName', ''),
            'subject_org':     subject.get('organizationName', ''),
            'issuer_cn':       issuer.get('commonName', ''),
            'issuer_org':      issuer.get('organizationName', ''),
            'not_before':      cert_dict.get('notBefore'),
            'not_after':       cert_dict.get('notAfter'),
            'sans':            _get_san_names(cert_dict),
            'serial':          cert_dict.get('serialNumber'),
            'version':         cert_dict.get('version'),
            'sig_algorithm':   cert_dict.get('signatureAlgorithm', 'unknown'),
            'key_algorithm':   key_info.get('algorithm', 'unknown'),
            'key_bits':        key_info.get('bits'),
            'is_self_signed':  (subject == issuer),
            'raw_dict':        cert_dict,
        }

    # ── Vulnerability checks ──────────────────────────────────────────────────

    def _check_tls_version(self, host, port, tls_info, result):
        """Flag deprecated TLS/SSL versions.

        Per RFC 8996 (March 2021), TLS 1.0 and 1.1 are deprecated.
        TLS 1.2 is acceptable; TLS 1.3 is preferred.
        Real-World Cryptography sec. 9.3: TLS < 1.2 has known exploitable attacks
        (BEAST, POODLE, DROWN, Lucky13, Bleichenbacher98).
        """
        ver = tls_info.get('version', '')
        if not ver:
            return

        if ver in DEPRECATED_TLS_VERSIONS or any(d in ver for d in DEPRECATED_TLS_VERSIONS):
            sev = 'CRITICAL' if 'SSL' in ver or ver in ('TLSv1', 'TLSv1.0', 'TLSv1.1') else 'HIGH'
            finding = {
                'type':     'DEPRECATED_TLS_VERSION',
                'severity': sev,
                'host':     host,
                'port':     port,
                'detail':   f'Negotiated {ver} — deprecated by RFC 8996',
                'exploit':  (
                    f'TLS downgrade attack: force {ver} handshake. '
                    f'Known attacks: BEAST (TLS 1.0 CBC), POODLE (SSL 3.0), Lucky13 (CBC padding). '
                    f'testssl.sh {host}:{port} --protocols'
                ),
            }
            result['findings'].append(finding)

        elif ver == 'TLSv1.2':
            finding = {
                'type':     'TLS_1_2_ONLY',
                'severity': 'LOW',
                'host':     host,
                'port':     port,
                'detail':   'TLS 1.2 negotiated — acceptable but TLS 1.3 preferred',
                'exploit':  'No direct exploit; TLS 1.3 provides better forward secrecy and performance',
            }
            result['findings'].append(finding)

    def _check_cipher_suite(self, host, port, tls_info, result):
        """Detect weak cipher suites.

        RC4: statistical biases exploited by RC4 NOMORE (2015), RFC 7465 prohibits.
        3DES: SWEET32 birthday attack (64-bit block), CVE-2016-2183.
        NULL: no encryption (RFC 5246 appendix warns against).
        EXPORT: 40/56-bit keys broken by FREAK (2015) and LOGJAM (2015).
        ANON/ADH/AECDH: no server authentication, trivial MITM.
        """
        cipher = tls_info.get('cipher', '')
        bits   = tls_info.get('cipher_bits', 0) or 0

        if cipher and WEAK_CIPHER_PATTERN.search(cipher):
            matched = WEAK_CIPHER_PATTERN.search(cipher).group(1).upper()
            attack_map = {
                'RC4':    'RC4 NOMORE attack (2015) — recover plaintext from RC4 stream',
                '3DES':   'SWEET32 — birthday attack on 64-bit block cipher, CVE-2016-2183',
                'DES_EDE': 'Same as 3DES (SWEET32)',
                'NULL':   'No encryption — plaintext traffic, any passive observer reads data',
                'EXPORT':  'FREAK/LOGJAM — force server to export 40/56-bit keys, factor modulus',
                'ANON':   'Anonymous DH — no server auth, trivial MITM possible',
                'ADH':    'Anonymous DH — no server auth, trivial MITM possible',
                'AECDH':  'Anonymous ECDH — no server auth, trivial MITM possible',
            }
            attack = attack_map.get(matched, f'Known-broken cipher class: {matched}')
            finding = {
                'type':     'WEAK_CIPHER_SUITE',
                'severity': 'CRITICAL',
                'host':     host,
                'port':     port,
                'detail':   f'Cipher: {cipher} ({bits} bits) — {attack}',
                'exploit':  (
                    f'openssl s_client -connect {host}:{port} '
                    f'-cipher {cipher} 2>/dev/null | head -20'
                ),
            }
            result['findings'].append(finding)

        if bits and bits < 128:
            finding = {
                'type':     'WEAK_CIPHER_KEY_SIZE',
                'severity': 'CRITICAL',
                'host':     host,
                'port':     port,
                'detail':   f'Cipher key size {bits} bits — below 128-bit minimum',
                'exploit':  'Brute-force feasible with modern hardware at key sizes < 80 bits',
            }
            result['findings'].append(finding)

    def _check_cert(self, host, port, cert_info, result):
        """Full certificate vulnerability check.

        Checks (from Real-World Cryptography sec. 9.2.1 and X.509 analysis):
          1. Expiry (expired or >398 days = overlength)
          2. Self-signed (no CA validation possible)
          3. Weak RSA key (< 2048 bits) or weak EC key (< 256 bits)
          4. SHA-1 signature algorithm (SHAttered collision 2017)
          5. Wildcard misuse (*.example.com used for cross-scope domains)
          6. Missing SANs (deprecated CN-only matching per RFC 2818)
        """
        now  = datetime.now(timezone.utc)
        cn   = cert_info.get('subject_cn', '')
        pos  = cert_info.get('position', 0)

        # 1. Expiry
        not_after_str = cert_info.get('not_after')
        if not_after_str:
            exp_dt = _parse_cert_not_after(not_after_str)
            if exp_dt:
                if now > exp_dt:
                    delta_days = (now - exp_dt).days
                    finding = {
                        'type':     'CERT_EXPIRED',
                        'severity': 'HIGH',
                        'host':     host,
                        'port':     port,
                        'detail':   f'Certificate CN={cn!r} expired {delta_days} days ago ({not_after_str})',
                        'exploit':  (
                            'Expired cert breaks chain-of-trust for clients enforcing expiry. '
                            'Also: expired cert often == abandoned/compromised infrastructure.'
                        ),
                    }
                    result['findings'].append(finding)

                elif (exp_dt - now).days > 398:
                    # CA/Browser Forum Ballot SC31: max validity 398 days since Sep 2020
                    over_days = (exp_dt - now).days
                    finding = {
                        'type':     'CERT_OVERLENGTH_VALIDITY',
                        'severity': 'LOW',
                        'host':     host,
                        'port':     port,
                        'detail':   f'Certificate valid for {over_days} more days — exceeds 398-day CA/B Forum limit',
                        'exploit':  'Long-lived certs extend exposure window if private key is compromised.',
                    }
                    result['findings'].append(finding)

        # 2. Self-signed
        if cert_info.get('is_self_signed'):
            finding = {
                'type':     'CERT_SELF_SIGNED',
                'severity': 'HIGH',
                'host':     host,
                'port':     port,
                'detail':   f'Certificate CN={cn!r} is self-signed — no CA validation',
                'exploit':  (
                    'MITM attack trivial: attacker presents own self-signed cert, '
                    'client cannot distinguish from legitimate. '
                    'openssl s_client -connect {host}:{port} 2>&1 | grep "self signed"'
                ),
            }
            result['findings'].append(finding)

        # 3. Weak key size
        key_algo = cert_info.get('key_algorithm', '').lower()
        key_bits = cert_info.get('key_bits')

        if key_bits and 'rsa' in key_algo:
            if key_bits < 1024:
                finding = {
                    'type':     'CERT_WEAK_RSA_KEY_CRITICAL',
                    'severity': 'CRITICAL',
                    'host':     host,
                    'port':     port,
                    'detail':   f'RSA key only {key_bits} bits — factorable with current hardware (NIST deprecated < 2048)',
                    'exploit':  f'openssl s_client -connect {host}:{port} | openssl x509 -noout -modulus | wc -c',
                }
                result['findings'].append(finding)
            elif key_bits < RSA_MIN_BITS:
                finding = {
                    'type':     'CERT_WEAK_RSA_KEY',
                    'severity': 'HIGH',
                    'host':     host,
                    'port':     port,
                    'detail':   f'RSA key {key_bits} bits — below NIST SP 800-131A minimum of {RSA_MIN_BITS}',
                    'exploit':  f'Factor with Coppersmith / GNFS; use MSIEVE or CADO-NFS on 1024-bit keys.',
                }
                result['findings'].append(finding)

        if key_bits and ('ec' in key_algo or 'ecdsa' in key_algo):
            if key_bits < EC_MIN_BITS:
                finding = {
                    'type':     'CERT_WEAK_EC_KEY',
                    'severity': 'HIGH',
                    'host':     host,
                    'port':     port,
                    'detail':   f'EC key {key_bits} bits — below minimum {EC_MIN_BITS} bits; ECDLP attacks feasible',
                    'exploit':  'Baby-step giant-step or Pohlig-Hellman on weak curve orders.',
                }
                result['findings'].append(finding)

        # 4. SHA-1 signature (SHAttered: first SHA-1 collision Feb 2017)
        sig_alg = cert_info.get('sig_algorithm', '').lower()
        if 'sha1' in sig_alg or 'md5' in sig_alg:
            broken = 'SHA-1 (SHAttered collision 2017, CVE-2017-2905)' if 'sha1' in sig_alg else 'MD5 (trivially collided)'
            finding = {
                'type':     'CERT_WEAK_SIGNATURE',
                'severity': 'HIGH',
                'host':     host,
                'port':     port,
                'detail':   f'Certificate signed with {broken} — {cert_info.get("sig_algorithm")}',
                'exploit':  (
                    'SHA-1 collision allows forging a certificate with the same signature. '
                    'Attack complexity: practical with ~$75K GPU cluster (CWI/Google 2017).'
                ),
            }
            result['findings'].append(finding)

        # 5. Wildcard misuse
        # Wildcard cert is only valid for one level of subdomain (RFC 6125 sec. 6.4.3)
        # Misuse: *.example.com covering api.internal.example.com, or bare wildcard *.com
        sans = cert_info.get('sans', [])
        for san in sans:
            if san.startswith('*.'):
                domain = san[2:]
                # Bare wildcard (e.g. *.com) — highly dangerous
                if '.' not in domain:
                    finding = {
                        'type':     'CERT_WILDCARD_TOO_BROAD',
                        'severity': 'CRITICAL',
                        'host':     host,
                        'port':     port,
                        'detail':   f'SAN {san!r} — wildcard at TLD level covers any domain under .{domain}',
                        'exploit':  'Any subdomain of a TLD could be impersonated with this cert.',
                    }
                    result['findings'].append(finding)

                # Wildcard covering internal/production crossover
                if 'internal' in domain or 'corp' in domain:
                    finding = {
                        'type':     'CERT_WILDCARD_INTERNAL_SCOPE',
                        'severity': 'MEDIUM',
                        'host':     host,
                        'port':     port,
                        'detail':   f'Wildcard SAN {san!r} covers internal/corp domain — scope crossover risk',
                        'exploit':  'Compromised wildcard private key authenticates all internal hosts.',
                    }
                    result['findings'].append(finding)

        # 6. No SANs (CN-only — deprecated per RFC 2818)
        if not sans and pos == 0:
            finding = {
                'type':     'CERT_NO_SAN',
                'severity': 'MEDIUM',
                'host':     host,
                'port':     port,
                'detail':   f'Leaf cert CN={cn!r} has no Subject Alternative Names — CN-only matching deprecated (RFC 2818)',
                'exploit':  (
                    'Modern browsers reject CN-only certs. '
                    'CN-only matching allows homograph attacks on older clients.'
                ),
            }
            result['findings'].append(finding)

    def _check_ct_poison(self, host, port, tls_info, result):
        """Detect Certificate Transparency poison extension.

        CT poison (OID 1.3.6.1.4.1.11129.2.4.3) marks a pre-certificate submitted
        to CT logs but not yet finalized. Its presence in a live cert is anomalous.

        Per Insight #97 ( cert-distribution honeypot discriminator):
        cert I/N ratio >= 0.30 signals a honeypot fleet. CT anomalies compound
        this signal.
        """
        for cert_info in tls_info.get('cert_chain', []):
            raw = cert_info.get('raw_dict', {})
            extensions = raw.get('extensions', []) if isinstance(raw, dict) else []

            # Check for the CT poison OID in any form
            cert_str = str(raw)
            if CT_POISON_OID in cert_str or 'ctPoison' in cert_str:
                finding = {
                    'type':     'CT_POISON_EXTENSION',
                    'severity': 'HIGH',
                    'host':     host,
                    'port':     port,
                    'detail':   (
                        f'Certificate CN={cert_info.get("subject_cn")!r} contains CT poison extension '
                        f'(OID {CT_POISON_OID}). Pre-certificate in live service = honeypot signal.'
                    ),
                    'exploit':  'Cross-reference with cert I/N ratio check (Insight #97). Treat as honeypot candidate.',
                }
                result['findings'].append(finding)

            # Cert SHA256 anomaly: if we've seen this fingerprint from multiple operators,
            # it's likely a canary cert
            sha256 = cert_info.get('sha256', '')
            if sha256:
                # We can't check cross-corpus here without a DB; log the FP for external lookup
                finding = {
                    'type':     'CERT_FINGERPRINT',
                    'severity': 'INFO',
                    'host':     host,
                    'port':     port,
                    'detail':   f'SHA256: {sha256[:32]}... CN={cert_info.get("subject_cn")!r}',
                    'exploit':  'Cross-reference against VisorGraph cert-pivot for operator attribution.',
                }
                result['findings'].append(finding)

    def _check_security_headers(self, host, port, headers: dict, result):
        """Detect HSTS and HPKP response headers.

        From Real-World Cryptography sec. 9.3:
          HSTS (Strict-Transport-Security): instructs browser to use HTTPS only.
          HPKP (Public-Key-Pins): deprecated (RFC 7469 withdrawn); pins specific key hashes.

        Absence of HSTS = first HTTP connection is unprotected (downgrade risk).
        Presence of HPKP with short max-age = incomplete protection.
        """
        if 'strict-transport-security' not in headers:
            finding = {
                'type':     'MISSING_HSTS',
                'severity': 'MEDIUM',
                'host':     host,
                'port':     port,
                'detail':   'No Strict-Transport-Security header — first HTTP connection is unprotected',
                'exploit':  (
                    'SSLstrip: intercept first HTTP request, strip HTTPS redirect, '
                    'serve downgraded HTTP session. '
                    f'curl -sk -D - https://{host}/ | grep -i strict'
                ),
            }
            result['findings'].append(finding)
        else:
            hsts_val = headers['strict-transport-security']
            if 'includesubdomains' not in hsts_val.lower():
                finding = {
                    'type':     'HSTS_NO_SUBDOMAINS',
                    'severity': 'LOW',
                    'host':     host,
                    'port':     port,
                    'detail':   f'HSTS present but missing includeSubDomains: {hsts_val}',
                    'exploit':  'Subdomains remain SSLstrip-vulnerable.',
                }
                result['findings'].append(finding)

            # max-age < 1 year is weakly configured
            max_age_match = re.search(r'max-age=(\d+)', hsts_val)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # 1 year
                    finding = {
                        'type':     'HSTS_SHORT_MAX_AGE',
                        'severity': 'LOW',
                        'host':     host,
                        'port':     port,
                        'detail':   f'HSTS max-age={max_age}s — below recommended 31536000 (1 year)',
                        'exploit':  'Short max-age allows HSTS expiry and subsequent downgrade window.',
                    }
                    result['findings'].append(finding)

            finding = {
                'type':     'HSTS_PRESENT',
                'severity': 'INFO',
                'host':     host,
                'port':     port,
                'detail':   f'HSTS: {hsts_val}',
                'exploit':  '',
            }
            result['findings'].append(finding)

        if 'public-key-pins' in headers or 'public-key-pins-report-only' in headers:
            hpkp_key   = 'public-key-pins' if 'public-key-pins' in headers else 'public-key-pins-report-only'
            hpkp_val   = headers[hpkp_key]
            finding = {
                'type':     'HPKP_PRESENT',
                'severity': 'MEDIUM',
                'host':     host,
                'port':     port,
                'detail':   (
                    f'{hpkp_key}: {hpkp_val[:120]}. '
                    'HPKP deprecated (RFC 7469). Risk: key pinning disaster on cert rotation.'
                ),
                'exploit':  (
                    'HPKP can be weaponized: attacker injects malicious HPKP header via XSS, '
                    'pins their own key, causing DOS for legitimate cert renewal (HPKP Suicide).'
                ),
            }
            result['findings'].append(finding)

    # ── Quantum inventory ─────────────────────────────────────────────────────

    def _quantum_inventory(self, tls_info: dict) -> dict:
        """Classify the cert key algorithm for quantum vulnerability.

        Shor's algorithm (1994) breaks RSA and ECDSA in O(log^3 n) time
        on a large-enough quantum computer (NIST estimates: ~4000 logical qubits
        for 2048-bit RSA). As of NIST FIPS 203/204/205 (Aug 2024), replacements are:
          - ML-KEM (Kyber) for key encapsulation
          - ML-DSA (Dilithium) for digital signatures
          - SLH-DSA (SPHINCS+) for hash-based signature backup
        """
        inventory = {
            'vulnerable_algorithms': [],
            'safe_algorithms':       [],
            'migration_urgency':     'UNKNOWN',
            'recommended_migration': [],
        }

        for cert_info in tls_info.get('cert_chain', []):
            key_algo = cert_info.get('key_algorithm', '').lower()
            sig_algo = cert_info.get('sig_algorithm', '').lower()

            # Key algorithm quantum check
            for vuln_oid, reason in QUANTUM_VULNERABLE_KEY_TYPES.items():
                if vuln_oid.lower() in key_algo or key_algo in vuln_oid.lower():
                    inventory['vulnerable_algorithms'].append({
                        'context':    f'cert key CN={cert_info.get("subject_cn")!r}',
                        'algorithm':  cert_info.get('key_algorithm'),
                        'threat':     reason,
                        'fips_std':   'Shor\'s algorithm — polynomial time on quantum hardware',
                    })

            # Signature algorithm quantum check
            if 'rsa' in sig_algo or 'ecdsa' in sig_algo:
                inventory['vulnerable_algorithms'].append({
                    'context':    f'cert signature CN={cert_info.get("subject_cn")!r}',
                    'algorithm':  cert_info.get('sig_algorithm'),
                    'threat':     'Shor\'s algorithm breaks RSA/ECDSA signatures',
                    'fips_std':   'Replace with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)',
                })

        if inventory['vulnerable_algorithms']:
            inventory['migration_urgency']     = 'HIGH — NIST PQC migration required'
            inventory['recommended_migration'] = [
                'Key encapsulation: ML-KEM / CRYSTALS-Kyber (FIPS 203)',
                'Digital signatures: ML-DSA / CRYSTALS-Dilithium (FIPS 204)',
                'Backup signatures: SLH-DSA / SPHINCS+ (FIPS 205)',
                'Interim: hybrid RSA+Kyber or ECDSA+Dilithium for backward compat',
            ]

        return inventory

    # ── Raw TLS record helpers ────────────────────────────────────────────────

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
        """Read exactly n bytes from sock, blocking until complete or EOF."""
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _build_client_hello(self, session_id: bytes = b'',
                            cipher_codes: list = None) -> bytes:
        """Build a minimal raw TLS 1.2 ClientHello record.

        Constructs a valid ClientHello with the given cipher suite list and
        optional session ID (used to request session resumption).  No SNI or
        other extensions are included — this is intentional so the server's
        cipher-suite selection is driven purely by what we advertise.

        Wire format (RFC 5246 §7.4.1.2):
          TLS Record:  content_type(1) + version(2) + length(2)
          Handshake:   msg_type(1) + length(3)
          ClientHello: client_version(2) + random(32) + session_id + ciphers
                       + compression_methods + extensions
        """
        random_bytes = os.urandom(32)

        if cipher_codes is None:
            # Default: safe TLS 1.2 GCM suites used when no specific probe needed
            cipher_codes = [0xC02F, 0xC02B, 0x009C, 0x003C]

        cs_bytes = b''.join(struct.pack('!H', c) for c in cipher_codes)
        cs_field = struct.pack('!H', len(cs_bytes)) + cs_bytes

        sid_field  = bytes([len(session_id)]) + session_id
        comp_field = b'\x01\x00'          # 1 compression method: null (0x00)
        ext_field  = b'\x00\x00'          # extensions length = 0

        body = b'\x03\x03' + random_bytes + sid_field + cs_field + comp_field + ext_field

        # Handshake type 0x01 (ClientHello) + 3-byte length
        hs_len = struct.pack('!I', len(body))[1:]   # drop the high byte
        hs     = b'\x01' + hs_len + body

        # TLS record: content_type=0x16 (Handshake) + version 0x0301 + length
        return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

    def _raw_tls_connect(self, host: str, port: int, client_hello: bytes,
                         timeout: int = 4) -> list:
        """Send a raw ClientHello and collect TLS records from the server.

        Returns list of (content_type, payload_bytes) tuples.
        Stops collecting on Alert (0x15) record or connection close.
        Exceptions are swallowed — empty list returned on any failure.
        """
        records: list = []
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.sendall(client_hello)
                sock.settimeout(timeout)
                buf = b''
                while True:
                    try:
                        chunk = sock.recv(4096)
                    except Exception:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    # Parse all complete TLS records out of the buffer
                    while len(buf) >= 5:
                        ct     = buf[0]
                        length = struct.unpack('!H', buf[3:5])[0]
                        if len(buf) < 5 + length:
                            break   # wait for more data
                        records.append((ct, buf[5:5 + length]))
                        buf = buf[5 + length:]
                        if ct == 0x15:  # Alert — server done
                            return records
        except Exception:
            pass
        return records

    def _parse_server_hello(self, hs_payload: bytes) -> dict:
        """Extract key fields from a ServerHello handshake message payload.

        hs_payload is the TLS record body (starts with handshake type byte).
        Returns dict with 'session_id' (bytes), 'cipher_suite' (int or None),
        'compression' (int).
        """
        result = {'session_id': b'', 'cipher_suite': None, 'compression': 0}
        if not hs_payload or hs_payload[0] != 0x02:  # must be ServerHello
            return result
        if len(hs_payload) < 4:
            return result

        msg_len = struct.unpack('!I', b'\x00' + hs_payload[1:4])[0]
        body    = hs_payload[4:4 + msg_len]
        offset  = 0

        offset += 2   # client_version
        offset += 32  # server random

        if offset >= len(body):
            return result

        sid_len = body[offset]
        offset += 1
        result['session_id'] = body[offset:offset + sid_len]
        offset += sid_len

        if offset + 2 <= len(body):
            result['cipher_suite'] = struct.unpack('!H', body[offset:offset + 2])[0]
            offset += 2

        if offset < len(body):
            result['compression'] = body[offset]

        return result

    def _parse_server_key_exchange(self, records: list) -> dict:
        """Extract DH or ECDHE parameters from a ServerKeyExchange message.

        Iterates over handshake records looking for message type 0x0C.

        For DHE:   starts with p_len(2) + p; extracts prime p and its bit length.
        For ECDHE: starts with curve_type(1); named_curve(0x03) + curve_id(2).

        Returns dict with keys: type ('dh'/'ecdhe'/'unknown'), p_bits (int|None),
        p_hex (str|None), curve (str|None).
        """
        EC_NAMED_CURVES = {
            19: 'secp192r1',
            21: 'secp224r1',
            23: 'secp256r1',
            24: 'secp384r1',
            25: 'secp521r1',
            29: 'x25519',
            30: 'x448',
            26: 'brainpoolP256r1',
            27: 'brainpoolP384r1',
            28: 'brainpoolP512r1',
        }

        result = {'type': 'unknown', 'p_bits': None, 'p_hex': None, 'curve': None}

        for ct, data in records:
            if ct != 0x16:
                continue
            offset = 0
            while offset + 4 <= len(data):
                msg_type = data[offset]
                msg_len  = struct.unpack('!I', b'\x00' + data[offset + 1:offset + 4])[0]
                offset  += 4
                body     = data[offset:offset + msg_len]

                if msg_type == 0x0C:  # ServerKeyExchange
                    if len(body) < 3:
                        return result
                    if body[0] == 0x03:  # named_curve — ECDHE
                        result['type']  = 'ecdhe'
                        curve_id        = struct.unpack('!H', body[1:3])[0]
                        result['curve'] = EC_NAMED_CURVES.get(curve_id, f'unknown(0x{curve_id:04x})')
                    else:
                        # DHE: first 2 bytes = p_length
                        result['type'] = 'dh'
                        p_len = struct.unpack('!H', body[0:2])[0]
                        if len(body) >= 2 + p_len:
                            p_bytes         = body[2:2 + p_len]
                            result['p_bits'] = len(p_bytes) * 8
                            result['p_hex']  = p_bytes.hex()
                    return result

                offset += msg_len

        return result

    # ── Protocol-level cryptographic weakness detection ───────────────────────

    def detect_protocol_weaknesses(self, host: str, port: int,
                                   timeout: int = 6) -> list:
        """Probe for protocol-level cryptographic weaknesses.

        Derived from the Applied Cryptography (Schneier) threat model for
        stream-cipher, block-cipher, and key-exchange weaknesses:

          a. GCM nonce reuse via session resumption
             TLS 1.2 AES-GCM uses a 4-byte implicit IV (from key material) plus
             an 8-byte explicit IV sent per record.  Implementations commonly
             start the explicit IV counter at 0 for each new TLS session.  Under
             session resumption the same 128-bit key is reused; if the explicit IV
             counter also restarts at 0, the (key, nonce) pair repeats.  GCM nonce
             reuse yields: keystream cancellation, GHASH key recovery, and full
             authenticated-encryption break (Joux 2006; Nonce-Disrespecting
             Adversaries, USENIX 2016).

          b. Anonymous cipher suite acceptance
             ECDH_anon / DH_anon suites omit the Certificate message entirely.
             The server provides no authentication proof; any on-path attacker
             presents their own ephemeral key and transparently relays traffic.

          c. EXPORT cipher acceptance
             40/56-bit export keys are broken by FREAK (CVE-2015-0204, RSA-EXPORT)
             and LOGJAM (CVE-2015-4000, DHE-EXPORT) by offline factoring or DLP
             pre-computation within hours on commodity hardware.

          d. Long session ticket lifetime
             RFC 5077 session tickets encrypt the session state under a server-held
             key.  Ticket lifetime > 24 h means an attacker who later recovers that
             key (Heartbleed, key-rotation failure, server compromise) can decrypt
             all captured sessions within the lifetime window — eliminating forward
             secrecy for the entire traffic corpus.

        Returns a list of finding dicts (same schema as _check_* methods).
        """
        findings = []

        gcm_ciphers = [
            0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009E,  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        ]

        # ── a. GCM nonce reuse via session resumption ─────────────────────────
        try:
            ch1      = self._build_client_hello(session_id=b'', cipher_codes=gcm_ciphers)
            records1 = self._raw_tls_connect(host, port, ch1, timeout=timeout)

            session_id = b''
            for ct, data in records1:
                if ct == 0x16 and data and data[0] == 0x02:
                    sh         = self._parse_server_hello(data)
                    session_id = sh.get('session_id', b'')
                    break

            if session_id:
                ch2      = self._build_client_hello(session_id=session_id,
                                                    cipher_codes=gcm_ciphers)
                records2 = self._raw_tls_connect(host, port, ch2, timeout=timeout)

                resumed = False
                for ct, data in records2:
                    if ct == 0x16 and data and data[0] == 0x02:
                        sh2     = self._parse_server_hello(data)
                        resumed = (sh2.get('session_id') == session_id)
                        break

                if resumed:
                    findings.append({
                        'type':     'GCM_NONCE_REUSE_RISK',
                        'severity': 'CRITICAL',
                        'host':     host,
                        'port':     port,
                        'detail':   (
                            'Server accepted TLS 1.2 session resumption with a GCM cipher '
                            '(same session_id echoed in ServerHello). '
                            'TLS 1.2 GCM explicit IV counter restarts at 0 per connection. '
                            'If the implementation reuses the session key without re-randomizing '
                            'the IV, (key, nonce) pairs repeat — GCM nonce reuse breaks both '
                            'confidentiality and integrity; GHASH authentication key H is '
                            'recoverable from two ciphertexts encrypted under the same nonce.'
                        ),
                        'exploit':  (
                            'Capture two GCM records from resumed sessions sharing explicit IV=0. '
                            'XOR ciphertexts to cancel the keystream. '
                            'Recover H via polynomial roots over GF(2^128) (Joux 2006). '
                            'Ref: Nonce-Disrespecting Adversaries, USENIX Security 2016.'
                        ),
                    })
        except Exception:
            pass

        # ── b. Anonymous cipher suite acceptance ─────────────────────────────
        anon_codes = [
            0xC018,  # TLS_ECDH_anon_WITH_AES_128_CBC_SHA
            0xC019,  # TLS_ECDH_anon_WITH_AES_256_CBC_SHA
            0x0034,  # TLS_DH_anon_WITH_AES_128_CBC_SHA
            0x003A,  # TLS_DH_anon_WITH_AES_256_CBC_SHA
            0x001B,  # TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
            0x0018,  # TLS_DH_anon_WITH_RC4_128_MD5
        ]
        anon_set = set(anon_codes)

        try:
            ch_anon      = self._build_client_hello(session_id=b'', cipher_codes=anon_codes)
            records_anon = self._raw_tls_connect(host, port, ch_anon, timeout=timeout)

            for ct, data in records_anon:
                if ct == 0x16 and data and data[0] == 0x02:
                    sh = self._parse_server_hello(data)
                    cs = sh.get('cipher_suite')
                    if cs and cs in anon_set:
                        cs_name = WEAK_CIPHER_CODES.get(cs, f'0x{cs:04X}')
                        findings.append({
                            'type':     'ANON_CIPHER_ACCEPTED',
                            'severity': 'CRITICAL',
                            'host':     host,
                            'port':     port,
                            'detail':   (
                                f'Server selected anonymous cipher suite {cs_name} (0x{cs:04X}). '
                                f'No server authentication — attacker positions as MITM with zero '
                                f'cryptographic material required.'
                            ),
                            'exploit':  (
                                f'openssl s_client -connect {host}:{port} -cipher aNULL '
                                f'2>/dev/null | grep "Cipher    :"'
                            ),
                        })
                    break
        except Exception:
            pass

        # ── c. EXPORT cipher acceptance ───────────────────────────────────────
        export_codes = [
            0x0003,  # TLS_RSA_EXPORT_WITH_RC4_40_MD5       (RC4-40)
            0x0006,  # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            0x0008,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA    (DES-40)
            0x0062,  # TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
            0x0014,  # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x0011,  # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        ]
        export_set = set(export_codes)

        try:
            ch_exp      = self._build_client_hello(session_id=b'', cipher_codes=export_codes)
            records_exp = self._raw_tls_connect(host, port, ch_exp, timeout=timeout)

            for ct, data in records_exp:
                if ct == 0x16 and data and data[0] == 0x02:
                    sh = self._parse_server_hello(data)
                    cs = sh.get('cipher_suite')
                    if cs and cs in export_set:
                        cs_name = WEAK_CIPHER_CODES.get(cs, f'0x{cs:04X}')
                        findings.append({
                            'type':     'EXPORT_CIPHER_ACCEPTED',
                            'severity': 'CRITICAL',
                            'host':     host,
                            'port':     port,
                            'detail':   (
                                f'Server accepted EXPORT cipher {cs_name} (0x{cs:04X}). '
                                f'40/56-bit key cap is brute-forceable in hours on commodity '
                                f'hardware. FREAK attack vector (CVE-2015-0204): factor the '
                                f'512-bit RSA-EXPORT modulus offline, inject plaintext '
                                f'premaster secret into the handshake.'
                            ),
                            'exploit':  (
                                f'openssl s_client -connect {host}:{port} -cipher EXPORT '
                                f'2>/dev/null | grep "Cipher    :" ; '
                                f'# Then factor the ephemeral RSA-EXPORT key with MSIEVE'
                            ),
                        })
                    break
        except Exception:
            pass

        # ── d. Session ticket lifetime (via ssl module session object) ─────────
        # NewSessionTicket is sent after the full handshake completes; it is not
        # visible in a partial raw probe.  Python's ssl.SSLSession exposes the
        # ticket_lifetime_hint field that OpenSSL surfaces from the ticket message.
        try:
            ctx = _ssl_ctx_no_verify()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    session     = ssock.session
                    ticket_life = getattr(session, 'ticket_lifetime_hint', -1) if session else -1

            if ticket_life is not None and ticket_life > 86400:
                days = ticket_life // 86400
                findings.append({
                    'type':     'SESSION_TICKET_LONG_LIFETIME',
                    'severity': 'HIGH',
                    'host':     host,
                    'port':     port,
                    'detail':   (
                        f'NewSessionTicket lifetime_hint = {ticket_life}s ({days} day(s)) '
                        f'— exceeds 86400s (24h). Forward secrecy window is extended: any '
                        f'attacker who captures traffic and later recovers the ticket '
                        f'encryption key can retroactively decrypt all sessions issued '
                        f'within the lifetime window (RFC 5077 §5.6 warns against this).'
                    ),
                    'exploit':  (
                        'Recover ticket key via Heartbleed / server memory read / key rotation '
                        'failure. Decrypt any captured TLS session whose ticket was valid '
                        f'within {days} day(s) of capture time.'
                    ),
                })
            elif ticket_life is not None and 0 <= ticket_life <= 86400:
                findings.append({
                    'type':     'SESSION_TICKET_LIFETIME',
                    'severity': 'INFO',
                    'host':     host,
                    'port':     port,
                    'detail':   f'NewSessionTicket lifetime_hint = {ticket_life}s — within recommended range',
                    'exploit':  '',
                })
        except Exception:
            pass

        return findings

    # ── Hardening-failure detection (linux-hardening ch. 4/5/7) ──────────────

    def check_hsts_header(self, host: str, port: int = 443) -> dict:
        """Probe Strict-Transport-Security header over a direct TLS socket.

        From Linux Hardening in Hostile Networks ch. 5 (Web Servers):
          HSTS instructs browsers to use HTTPS exclusively. Without it, the
          first plaintext HTTP request is unprotected and an SSLstrip attacker
          can intercept credentials before HTTPS is ever established.

        Severity mapping (ch. 5 guidance + HAProxy example: max-age=15768000):
          - Missing header                   -> HIGH  (SSLstrip directly exploitable)
          - max-age < 31536000 (< 1 year)    -> MEDIUM (short protection window)
          - No includeSubDomains             -> LOW   (subdomains SSLstrip-vulnerable)

        Returns {'present': bool, 'max_age': int, 'include_subdomains': bool,
                 'finding': dict}
        """
        result: dict = {
            'present':           False,
            'max_age':           0,
            'include_subdomains': False,
            'finding':           {},
        }

        ctx = _ssl_ctx_no_verify()
        try:
            with socket.create_connection((host, port), timeout=6) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    req = f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
                    ssock.sendall(req.encode())
                    resp = b''
                    ssock.settimeout(4)
                    try:
                        while True:
                            chunk = ssock.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                            if b'\r\n\r\n' in resp:
                                break
                    except Exception:
                        pass
        except Exception:
            return result

        hsts_val = ''
        try:
            header_section = resp.split(b'\r\n\r\n')[0].decode('latin-1', errors='replace')
            for line in header_section.splitlines():
                if line.lower().startswith('strict-transport-security:'):
                    hsts_val = line.split(':', 1)[1].strip()
                    break
        except Exception:
            pass

        if not hsts_val:
            result['finding'] = {
                'type':     'HSTS_MISSING',
                'severity': 'HIGH',
                'host':     host,
                'port':     port,
                'detail':   (
                    'Strict-Transport-Security header absent — HTTPS downgrade possible. '
                    'SSLstrip intercepts first plaintext HTTP request before client can '
                    'upgrade to HTTPS (ch. 5: HSTS defeats downgrade attacks).'
                ),
                'exploit':  (
                    f'SSLstrip -l 8080; arpspoof -t <victim> <gw>; '
                    f'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to 8080. '
                    f'Verify: curl -sk -D - https://{host}/ | grep -i strict'
                ),
            }
            return result

        result['present'] = True

        max_age_match = re.search(r'max-age=(\d+)', hsts_val, re.I)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        result['max_age'] = max_age

        include_sub = 'includesubdomains' in hsts_val.lower()
        result['include_subdomains'] = include_sub

        if max_age < 31536000:
            result['finding'] = {
                'type':     'HSTS_SHORT_MAX_AGE',
                'severity': 'MEDIUM',
                'host':     host,
                'port':     port,
                'detail':   (
                    f'HSTS max-age={max_age}s — below 31536000 (1 year) minimum. '
                    f'Value: {hsts_val}'
                ),
                'exploit':  (
                    'Wait for HSTS TTL to expire, then SSLstrip-downgrade the next '
                    'unprotected connection within the expiry window.'
                ),
            }
        elif not include_sub:
            result['finding'] = {
                'type':     'HSTS_NO_SUBDOMAINS',
                'severity': 'LOW',
                'host':     host,
                'port':     port,
                'detail':   f'HSTS present but missing includeSubDomains: {hsts_val}',
                'exploit':  (
                    'Subdomains remain SSLstrip-vulnerable. '
                    'Cookie scope leakage: cookies set on apex domain readable via '
                    'subdomain MitM if HttpOnly and Secure not set.'
                ),
            }
        else:
            result['finding'] = {
                'type':     'HSTS_OK',
                'severity': 'INFO',
                'host':     host,
                'port':     port,
                'detail':   f'HSTS correctly configured: {hsts_val}',
                'exploit':  '',
            }

        return result

    def check_http_redirect(self, host: str, http_port: int = 80) -> dict:
        """Check whether HTTP port 80 issues a 301/302 redirect to HTTPS.

        From Linux Hardening ch. 5 (Web Servers):
          Apache: Redirect permanent / https://...
          Nginx:  return 301 https://$host$request_uri;
        Missing redirect leaves initial connection in cleartext — credentials
        and session tokens visible to any passive observer on the path.

        Returns {'redirects': bool, 'status_code': int, 'location': str,
                 'finding': dict}
        """
        result: dict = {
            'redirects':   False,
            'status_code': 0,
            'location':    '',
            'finding':     {},
        }

        try:
            with socket.create_connection((host, http_port), timeout=6) as sock:
                req = f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
                sock.sendall(req.encode())
                resp = b''
                sock.settimeout(4)
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                        if b'\r\n\r\n' in resp or len(resp) > 8192:
                            break
                except Exception:
                    pass
        except Exception:
            result['finding'] = {
                'type':     'HTTP_PORT_CLOSED',
                'severity': 'INFO',
                'host':     host,
                'port':     http_port,
                'detail':   f'Port {http_port} TCP unreachable — redirect status unknown',
                'exploit':  '',
            }
            return result

        status_code = 0
        location    = ''
        try:
            header_section = resp.split(b'\r\n\r\n')[0].decode('latin-1', errors='replace')
            lines = header_section.splitlines()
            if lines:
                m = re.match(r'HTTP/\S+\s+(\d+)', lines[0])
                if m:
                    status_code = int(m.group(1))
            for line in lines[1:]:
                if line.lower().startswith('location:'):
                    location = line.split(':', 1)[1].strip()
                    break
        except Exception:
            pass

        result['status_code'] = status_code
        result['location']    = location

        if status_code in (301, 302, 307, 308) and location.lower().startswith('https://'):
            result['redirects'] = True
            result['finding'] = {
                'type':     'HTTP_REDIRECT_PRESENT',
                'severity': 'INFO',
                'host':     host,
                'port':     http_port,
                'detail':   f'HTTP {status_code} redirect to HTTPS: {location}',
                'exploit':  '',
            }
        else:
            result['finding'] = {
                'type':     'HTTP_REDIRECT_MISSING',
                'severity': 'MEDIUM',
                'host':     host,
                'port':     http_port,
                'detail':   (
                    f'HTTP to HTTPS redirect missing (status={status_code}, '
                    f'location={location!r}). Cleartext HTTP exposed — credentials '
                    f'and session tokens visible to passive interception.'
                ),
                'exploit':  (
                    f'curl -v http://{host}/ 2>&1 | grep -E "< HTTP|[Ll]ocation" ; '
                    f'# confirm no redirect; then SSLstrip for live capture'
                ),
            }

        return result

    def check_dns_zone_transfer(self, host: str, domain: str = None) -> dict:
        """Probe for unauthenticated DNS zone transfer (AXFR) over TCP port 53.

        From Linux Hardening ch. 7 (DNS Security Fundamentals):
          BIND hardening: allow-transfer { <secondary_ip>; };
          Without IP restriction, any host can pull the full zone via AXFR,
          exposing every hostname and IP — full network topology.

        Wire format: DNS-over-TCP 2-byte length prefix + standard DNS message.
        AXFR query QTYPE = 252 (0xFC). A zone transfer response returning more
        than the initial SOA record means the transfer was permitted.

        Returns {'axfr_allowed': bool, 'record_count': int,
                 'records_sample': list, 'domain': str, 'finding': dict}
        """
        if domain is None:
            parts = host.split('.')
            domain = '.'.join(parts[1:]) if len(parts) > 2 else host

        result: dict = {
            'axfr_allowed':   False,
            'record_count':   0,
            'records_sample': [],
            'domain':         domain,
            'finding':        {},
        }

        def _encode_qname(name: str) -> bytes:
            buf = b''
            for label in name.rstrip('.').split('.'):
                enc = label.encode('ascii', errors='replace')
                buf += bytes([len(enc)]) + enc
            return buf + b'\x00'

        def _build_axfr_query(zone: str) -> bytes:
            txid    = b'\xAB\xCD'
            flags   = b'\x00\x00'   # standard query, recursion=0
            qdcount = b'\x00\x01'
            zeros   = b'\x00\x00\x00\x00\x00\x00'
            qname   = _encode_qname(zone)
            qtype   = b'\x00\xFC'   # AXFR = 252
            qclass  = b'\x00\x01'   # IN
            msg = txid + flags + qdcount + zeros + qname + qtype + qclass
            return struct.pack('!H', len(msg)) + msg

        try:
            with socket.create_connection((host, 53), timeout=6) as sock:
                sock.sendall(_build_axfr_query(domain))
                sock.settimeout(4)
                data = b''
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except Exception:
                    pass
        except Exception:
            result['finding'] = {
                'type':     'DNS_PORT_CLOSED',
                'severity': 'INFO',
                'host':     host,
                'port':     53,
                'detail':   f'TCP port 53 not reachable on {host}',
                'exploit':  '',
            }
            return result

        if len(data) < 2:
            result['finding'] = {
                'type':     'DNS_AXFR_NO_RESPONSE',
                'severity': 'INFO',
                'host':     host,
                'port':     53,
                'detail':   f'No response to AXFR query for {domain}',
                'exploit':  '',
            }
            return result

        # Parse DNS-over-TCP: each message has 2-byte length prefix
        record_names: list = []
        try:
            offset = 0
            while offset + 2 <= len(data):
                msg_len = struct.unpack('!H', data[offset:offset + 2])[0]
                offset += 2
                msg = data[offset:offset + msg_len]
                offset += msg_len

                if len(msg) < 12:
                    continue

                ancount = struct.unpack('!H', msg[6:8])[0]
                result['record_count'] += ancount

                # Skip question section to reach answers
                rr_off = 12
                qd = struct.unpack('!H', msg[4:6])[0]
                for _ in range(qd):
                    while rr_off < len(msg):
                        if msg[rr_off] & 0xC0 == 0xC0:
                            rr_off += 2
                            break
                        if msg[rr_off] == 0:
                            rr_off += 1
                            break
                        rr_off += msg[rr_off] + 1
                    rr_off += 4  # qtype + qclass

                # Sample a few answer RR types
                for _ in range(min(ancount, 5)):
                    if rr_off >= len(msg):
                        break
                    # skip name
                    while rr_off < len(msg):
                        if msg[rr_off] & 0xC0 == 0xC0:
                            rr_off += 2
                            break
                        if msg[rr_off] == 0:
                            rr_off += 1
                            break
                        rr_off += msg[rr_off] + 1
                    if rr_off + 10 <= len(msg):
                        rtype = struct.unpack('!H', msg[rr_off:rr_off + 2])[0]
                        rdlen = struct.unpack('!H', msg[rr_off + 8:rr_off + 10])[0]
                        record_names.append(f'rrtype={rtype}')
                        rr_off += 10 + rdlen
        except Exception:
            pass

        result['records_sample'] = record_names[:5]

        # AXFR returns zone records (SOA + entries + trailing SOA); > 1 = transfer succeeded
        if result['record_count'] > 1:
            result['axfr_allowed'] = True
            result['finding'] = {
                'type':     'DNS_ZONE_TRANSFER_PERMITTED',
                'severity': 'HIGH',
                'host':     host,
                'port':     53,
                'detail':   (
                    f'AXFR zone transfer permitted for {domain} — '
                    f'{result["record_count"]} record(s) returned. Full zone exposed: '
                    f'all hostnames and IPs enumerable without authentication. '
                    f'allow-transfer not restricted to secondary IP(s).'
                ),
                'exploit':  (
                    f'dig AXFR {domain} @{host} ; '
                    f'# Maps entire zone: all A/CNAME/MX/NS/PTR records returned'
                ),
            }
        else:
            result['finding'] = {
                'type':     'DNS_ZONE_TRANSFER_REFUSED',
                'severity': 'INFO',
                'host':     host,
                'port':     53,
                'detail':   (
                    f'AXFR refused or empty for {domain} '
                    f'(records={result["record_count"]}) — allow-transfer restricted'
                ),
                'exploit':  '',
            }

        return result

    def check_ocsp_stapling(self, host: str, port: int = 443) -> dict:
        """Probe for OCSP stapling via TLS_EXT_STATUS_REQUEST in ClientHello.

        From Linux Hardening ch. 5 + general TLS hardening best practice:
          Without OCSP stapling, clients must make a separate OCSP request to the
          CA on each TLS handshake. This leaks browsing behavior to the CA and adds
          latency. nginx directive: ssl_stapling on; ssl_stapling_verify on;

        Mechanism: include extension type 0x0012 (status_request) in ClientHello.
          A server with stapling configured echoes 0x0012 in its ServerHello extensions.

        Returns {'stapling_present': bool, 'finding': dict}
        """
        result: dict = {
            'stapling_present': False,
            'finding':          {},
        }

        # status_request extension: type=0x0012, data=status_type(1=OCSP)+responder_list_len(0)+ext_len(0)
        status_request_ext = (
            b'\x00\x12'   # extension type: status_request
            b'\x00\x05'   # extension data length
            b'\x01'        # status_type: OCSP
            b'\x00\x00'   # responder_id_list length: 0
            b'\x00\x00'   # request_extensions length: 0
        )

        # SNI extension for server compatibility
        try:
            sni_name = host.encode('ascii')
        except Exception:
            sni_name = b''

        if sni_name:
            sni_ext = (
                b'\x00\x00'                                         # type: server_name
                + struct.pack('!H', len(sni_name) + 5)              # ext data len
                + struct.pack('!H', len(sni_name) + 3)              # server_name_list len
                + b'\x00'                                            # name_type: host_name
                + struct.pack('!H', len(sni_name))                  # name len
                + sni_name
            )
        else:
            sni_ext = b''

        ext_data  = sni_ext + status_request_ext
        ext_field = struct.pack('!H', len(ext_data)) + ext_data

        # Build raw TLS 1.2 ClientHello with extensions
        random_bytes = b'\x00' * 32
        cipher_codes = [0xC02F, 0xC02B, 0x009C, 0x003C]
        cs_bytes     = b''.join(struct.pack('!H', c) for c in cipher_codes)
        cs_field     = struct.pack('!H', len(cs_bytes)) + cs_bytes
        sid_field    = b'\x00'
        comp_field   = b'\x01\x00'

        body = b'\x03\x03' + random_bytes + sid_field + cs_field + comp_field + ext_field
        hs_len = struct.pack('!I', len(body))[1:]
        hs     = b'\x01' + hs_len + body
        client_hello = b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

        records = self._raw_tls_connect(host, port, client_hello, timeout=6)

        # Check if ServerHello echoes extension type 0x0012 (status_request)
        stapling_present = False
        for ct, data in records:
            if ct != 0x16 or not data or data[0] != 0x02:
                continue

            if len(data) < 4:
                break

            msg_len = struct.unpack('!I', b'\x00' + data[1:4])[0]
            body    = data[4:4 + msg_len]
            off     = 0

            off += 2    # server_version
            off += 32   # server_random
            if off >= len(body):
                break

            sid_len = body[off]
            off    += 1 + sid_len
            off    += 2   # cipher_suite
            off    += 1   # compression_method

            if off + 2 > len(body):
                break

            ext_total = struct.unpack('!H', body[off:off + 2])[0]
            off      += 2
            ext_end   = off + ext_total

            while off + 4 <= ext_end and off + 4 <= len(body):
                ext_type = struct.unpack('!H', body[off:off + 2])[0]
                ext_len  = struct.unpack('!H', body[off + 2:off + 4])[0]
                if ext_type == 0x0012:
                    stapling_present = True
                    break
                off += 4 + ext_len
            break

        result['stapling_present'] = stapling_present

        if stapling_present:
            result['finding'] = {
                'type':     'OCSP_STAPLING_PRESENT',
                'severity': 'INFO',
                'host':     host,
                'port':     port,
                'detail':   (
                    'OCSP stapling configured — server includes revocation proof '
                    'in handshake (status_request extension echoed in ServerHello)'
                ),
                'exploit':  '',
            }
        else:
            result['finding'] = {
                'type':     'OCSP_STAPLING_MISSING',
                'severity': 'LOW',
                'host':     host,
                'port':     port,
                'detail':   (
                    'OCSP stapling not configured — clients perform separate OCSP '
                    'requests to CA, leaking browsing patterns and adding latency. '
                    'nginx fix: ssl_stapling on; ssl_stapling_verify on;'
                ),
                'exploit':  (
                    f'openssl s_client -connect {host}:{port} -status 2>/dev/null '
                    f'| grep -A 17 "OCSP response:"'
                ),
            }

        return result

    def check_protocol_downgrade(self, host: str, port: int = 443,
                                  timeout: int = 10) -> list:
        """Probe whether server accepts deprecated SSL/TLS protocol versions.

        SSLv3 + CBC = POODLE (CVE-2014-3566): padding oracle on CBC mode decryption.
        TLS 1.0 + CBC = BEAST (CVE-2011-3389): predictable IV chaining in CBC, allows
        chosen-plaintext recovery of blocks on a known-prefix boundary.
        TLS 1.1: no BEAST (fixed IV), but still deprecated per RFC 8996; missing AEAD.

        Returns list of finding dicts.
        """
        findings = []

        # SSLv3 — POODLE attack surface
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)  # type: ignore[attr-defined]
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    ver = ss.version()
                    if ver:
                        findings.append({
                            'type':     'SSLV3_ACCEPTED',
                            'severity': 'CRITICAL',
                            'host':     host,
                            'port':     port,
                            'detail':   (
                                f'Server accepts SSLv3 (negotiated: {ver}). '
                                'POODLE attack (CVE-2014-3566): CBC padding oracle in SSLv3 allows '
                                'byte-by-byte plaintext recovery. SSLv3 has no protection against '
                                'padding oracle because the MAC is computed before padding, making '
                                'malleability trivial. Retire SSLv3 immediately.'
                            ),
                            'exploit':  (
                                f'openssl s_client -connect {host}:{port} -ssl3 2>/dev/null '
                                f'| grep "Protocol  :" ; '
                                f'# POODLE: 256 requests/block average to recover one byte'
                            ),
                        })
        except AttributeError:
            pass  # ssl.PROTOCOL_SSLv3 unavailable in this Python build — SSLv3 not testable
        except Exception:
            pass  # connection refused, handshake failure — SSLv3 not accepted

        # TLS 1.0 — BEAST attack surface
        for ver_label, tls_ver in (('TLSv1', ssl.TLSVersion.TLSv1),
                                    ('TLSv1.1', ssl.TLSVersion.TLSv1_1)):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.maximum_version = tls_ver
                ctx.minimum_version = tls_ver
                with socket.create_connection((host, port), timeout=timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=host) as ss:
                        negotiated = ss.version()
                        if negotiated:
                            beast_note = (
                                ' BEAST attack (CVE-2011-3389): TLS 1.0 CBC uses the last '
                                'ciphertext block of the previous record as the IV for the next, '
                                'making the IV predictable. Allows chosen-plaintext recovery '
                                'against CBC cipher suites (e.g. AES-128-CBC, 3DES-CBC).'
                                if ver_label == 'TLSv1' else ''
                            )
                            findings.append({
                                'type':     f'{ver_label.upper().replace(".", "_")}_ACCEPTED',
                                'severity': 'HIGH',
                                'host':     host,
                                'port':     port,
                                'detail':   (
                                    f'Server accepts {ver_label} (negotiated: {negotiated}). '
                                    f'Deprecated per RFC 8996 (March 2021).{beast_note}'
                                ),
                                'exploit':  (
                                    f'openssl s_client -connect {host}:{port} '
                                    f'-tls1{"" if ver_label == "TLSv1" else "_1"} '
                                    f'2>/dev/null | grep "Protocol  :"'
                                ),
                            })
            except AttributeError:
                pass  # TLSVersion enum value unavailable in this Python build
            except Exception:
                pass  # handshake failed — version not accepted

        return findings

    def check_cipher_suite_ordering(self, host: str, port: int = 443,
                                     timeout: int = 10) -> dict:
        """Probe whether server accepts RSA key-exchange (non-forward-secrecy) ciphers.

        Forward secrecy: ECDHE and DHE generate ephemeral key pairs per session.
        Even if the server long-term private key is later recovered, past session
        keys cannot be derived — they existed only in memory during the handshake.

        RSA key exchange (non-FS): client generates pre-master secret and encrypts
        it with the server's RSA public key. The server decrypts it with its private
        key. If the private key is recovered at any future point, all past sessions
        encrypted under it are decryptable (Bleichenbacher 1998; ROBOT 2017).

        TLS 1.3 eliminates RSA key exchange entirely — this check targets TLS 1.2.

        Returns dict with keys: forward_secrecy (bool), accepted_rsa_kex (bool),
        ecdhe_accepted (bool), dhe_accepted (bool).
        """
        result = {
            'forward_secrecy':  False,
            'accepted_rsa_kex': False,
            'ecdhe_accepted':   False,
            'dhe_accepted':     False,
        }

        # Probe ECDHE cipher acceptance
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_ciphers('ECDHE+AESGCM:ECDHE+AES')
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cipher = ss.cipher()
                    if cipher and 'ECDHE' in cipher[0].upper():
                        result['ecdhe_accepted']  = True
                        result['forward_secrecy'] = True
        except Exception:
            pass

        # Probe DHE cipher acceptance
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_ciphers('DHE+AESGCM:DHE+AES:DHE+RSA')
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cipher = ss.cipher()
                    if cipher and ('DHE' in cipher[0].upper() and 'ECDHE' not in cipher[0].upper()):
                        result['dhe_accepted']    = True
                        result['forward_secrecy'] = True
        except Exception:
            pass

        # Probe RSA key-exchange cipher acceptance (non-FS)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            # Exclude ECDHE and DHE — force RSA key exchange
            ctx.set_ciphers('RSA+AES:RSA+3DES:!ECDHE:!DHE:!aNULL:!eNULL')
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cipher = ss.cipher()
                    if cipher:
                        name = cipher[0].upper()
                        # Confirm it is truly RSA kex (not ECDHE or DHE)
                        if 'ECDHE' not in name and 'DHE' not in name:
                            result['accepted_rsa_kex'] = True
        except Exception:
            pass

        return result

    def check_certificate_transparency(self, host: str, port: int = 443) -> list:
        """Check for Signed Certificate Timestamp (SCT) presence in the certificate.

        Certificate Transparency (RFC 6962) requires CAs to submit certificates to
        public append-only logs; browsers enforce CT via SCTs embedded in the cert
        (X.509 extension OID 1.3.6.1.4.1.11129.2.4.2), TLS extension (0x0012), or
        OCSP staple. Absence of any SCT means no public auditability of the cert.

        For honeypot discrimination: CT poison OID (1.3.6.1.4.1.11129.2.4.3) in a
        live serving cert indicates a pre-certificate — anomalous (Insight #97).

        Returns list of finding dicts.
        """
        findings = []
        # SCT list extension OID embedded in the end-entity certificate
        SCT_LIST_OID    = '1.3.6.1.4.1.11129.2.4.2'

        ctx = _ssl_ctx_no_verify()
        try:
            with socket.create_connection((host, port), timeout=8) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert_dict = ss.getpeercert()
                    cert_der  = ss.getpeercert(binary_form=True)
        except Exception:
            return findings

        if not cert_dict or not cert_der:
            return findings

        # Python's ssl.getpeercert() represents extensions inconsistently across
        # versions. Check the string representation of the raw dict for the OID
        # and also scan the DER bytes for the OID encoding.
        cert_str = str(cert_dict)
        has_sct  = SCT_LIST_OID in cert_str

        # DER byte scan fallback: OID 1.3.6.1.4.1.11129.2.4.2 encodes as
        # 06 0a 2b 06 01 04 01 d6 79 02 04 02
        SCT_OID_DER = bytes([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02])
        if not has_sct and cert_der and SCT_OID_DER in cert_der:
            has_sct = True

        if not has_sct:
            cn = ''
            try:
                subj = dict(x[0] for x in cert_dict.get('subject', []) if x)
                cn   = subj.get('commonName', '')
            except Exception:
                pass
            findings.append({
                'type':     'CT_SCT_MISSING',
                'severity': 'LOW',
                'host':     host,
                'port':     port,
                'detail':   (
                    f'No Signed Certificate Timestamp (SCT) found in certificate '
                    f'(CN={cn!r}). Certificate Transparency not enforced — cert was not '
                    f'submitted to a public CT log, or SCTs are delivered only via TLS '
                    f'extension / OCSP (not in the cert itself). Modern browsers require '
                    f'SCTs for certificates issued after April 2018.'
                ),
                'exploit':  (
                    f'openssl s_client -connect {host}:{port} 2>/dev/null '
                    f'| openssl x509 -noout -text | grep -A2 "Certificate Transparency"'
                ),
            })
        else:
            cn = ''
            try:
                subj = dict(x[0] for x in cert_dict.get('subject', []) if x)
                cn   = subj.get('commonName', '')
            except Exception:
                pass
            findings.append({
                'type':     'CT_SCT_PRESENT',
                'severity': 'INFO',
                'host':     host,
                'port':     port,
                'detail':   f'SCT extension present in certificate (CN={cn!r}) — CT enforced.',
                'exploit':  '',
            })

        return findings

    def check_rc4_null_export(self, host: str, port: int = 443) -> list:
        """Probe whether server accepts RC4, NULL, or EXPORT cipher suites.

        RC4 (RFC 7465 prohibits): stream cipher with known statistical biases.
        RC4 NOMORE (2015): 2^24 sessions under the same key leak enough ciphertext
        to recover 50 bytes of plaintext from a fixed-position secret (e.g. cookie).
        Invariant bytes: positions 0 and 1 are never 0, position 1 biased towards 0.

        NULL encryption: traffic is sent in plaintext. Any passive observer reads it.

        EXPORT ciphers: US export regulations (1990s) capped keys at 40/56 bits.
        FREAK (CVE-2015-0204): server unexpectedly offers EXPORT RSA even after
        handshake begins with strong cipher; client forced to 512-bit RSA key,
        factorable in ~7.5 hours. LOGJAM (CVE-2015-4000): same pattern for DHE-EXPORT.

        Returns list of finding dicts (CRITICAL for each accepted cipher class).
        """
        findings = []

        probe_map = [
            ('RC4',    'RC4',    'CRITICAL',
             'RC4 NOMORE (2015): statistical bias in RC4 keystream allows byte-by-byte '
             'plaintext recovery from repeated ciphertexts. RFC 7465 prohibits RC4.'),
            ('NULL',   'NULL',   'CRITICAL',
             'NULL encryption: no confidentiality protection. All traffic is plaintext.'),
            ('EXPORT',  'EXPORT', 'CRITICAL',
             'FREAK (CVE-2015-0204) / LOGJAM (CVE-2015-4000): 40/56-bit EXPORT keys '
             'are brute-forceable in hours. Server coerced to weak key; session decryptable.'),
        ]

        for cipher_str, label, severity, reason in probe_map:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.set_ciphers(cipher_str)
                with socket.create_connection((host, port), timeout=8) as s:
                    with ctx.wrap_socket(s, server_hostname=host) as ss:
                        cipher = ss.cipher()
                        if cipher:
                            findings.append({
                                'type':     f'{label}_CIPHER_ACCEPTED',
                                'severity': severity,
                                'host':     host,
                                'port':     port,
                                'detail':   (
                                    f'Server accepted {label} cipher suite: {cipher[0]} '
                                    f'({cipher[2]} bits). {reason}'
                                ),
                                'exploit':  (
                                    f'openssl s_client -connect {host}:{port} '
                                    f'-cipher "{cipher_str}" 2>/dev/null | grep "Cipher    :"'
                                ),
                            })
            except ssl.SSLError:
                pass  # cipher string rejected by local OpenSSL or not accepted by server
            except Exception:
                pass

        return findings

    def check_tls_compression(self, host: str, port: int) -> list:
        """Probe whether the server selects DEFLATE TLS compression.

        TLS compression (RFC 3749) is enabled when the server's ServerHello
        selects a non-NULL compression method.  CRIME (CVE-2012-4929) exploits
        length-based side-channel leakage: when attacker-controlled data is
        compressed together with a secret (e.g. session cookie), the compressed
        length reveals information about the secret's content through an
        adaptive chosen-plaintext attack.

        Mechanism: send ClientHello advertising DEFLATE (0x01) and NULL (0x00)
        compression methods.  Parse the ServerHello selected_compression_method
        byte; any value != 0x00 means compression is active.

        Returns list of finding dicts.
        """
        findings = []
        try:
            random_bytes = os.urandom(32)
            cipher_codes = [0xC02F, 0xC02B, 0x009C, 0x003C]
            cs_bytes  = b''.join(struct.pack('!H', c) for c in cipher_codes)
            cs_field  = struct.pack('!H', len(cs_bytes)) + cs_bytes
            sid_field = b'\x00'
            # Two compression methods: DEFLATE (0x01) and NULL (0x00)
            comp_field = b'\x02\x01\x00'
            ext_field  = b'\x00\x00'

            body   = b'\x03\x03' + random_bytes + sid_field + cs_field + comp_field + ext_field
            hs_len = struct.pack('!I', len(body))[1:]
            hs     = b'\x01' + hs_len + body
            client_hello = b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

            records = self._raw_tls_connect(host, port, client_hello, timeout=6)
            for ct, data in records:
                if ct == 0x16 and data and data[0] == 0x02:
                    sh = self._parse_server_hello(data)
                    compression = sh.get('compression', 0)
                    if compression != 0:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title':    'TLS compression enabled (CRIME attack, CVE-2012-4929)',
                            'detail':   (
                                f'ServerHello selected compression method 0x{compression:02x} '
                                f'(DEFLATE). TLS compression is exploitable via CRIME: an '
                                f'attacker who can inject chosen plaintext and observe ciphertext '
                                f'length can recover session secrets byte-by-byte. Disable TLS '
                                f'compression entirely (OpenSSL: SSL_OP_NO_COMPRESSION).'
                            ),
                            'host':     host,
                            'port':     port,
                        })
                    break
        except (ssl.SSLError, OSError):
            pass
        except Exception:
            pass
        return findings

    def check_client_auth_bypass(self, host: str, port: int) -> list:
        """Probe whether client certificate authentication is enforced.

        From ch. 6 (Client-Side TLS): when a server sends CertificateRequest
        during the handshake, the client must present a valid certificate.
        If the server completes the handshake without requiring a client cert,
        client authentication is not enforced (or is configured optional).

        Mechanism: attempt TLS handshake without presenting any client certificate.
        If the connection succeeds (no handshake failure), client auth is not
        enforced on this endpoint.

        Returns list of finding dicts.
        """
        findings = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            # Explicitly do NOT load any client certificate
            with socket.create_connection((host, port), timeout=8) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    ver = ss.version()
                    if ver:
                        findings.append({
                            'severity': 'MEDIUM',
                            'title':    'Client certificate authentication not enforced',
                            'detail':   (
                                f'TLS handshake completed ({ver}) without presenting a client '
                                f'certificate. If this endpoint advertises client authentication '
                                f'(CertificateRequest in ServerHello), the server accepted the '
                                f'connection anyway — client auth is either optional or absent. '
                                f'Endpoints requiring mutual TLS must reject handshakes with no '
                                f'client cert (ssl_verify_client required).'
                            ),
                            'host':     host,
                            'port':     port,
                        })
        except (ssl.SSLError, OSError):
            pass
        except Exception:
            pass
        return findings

    def check_session_resumption_abuse(self, host: str, port: int) -> list:
        """Probe TLS session resumption behavior.

        From ch. 6 (Session Resumption): the abbreviated handshake lets a client
        reuse a previously negotiated session by echoing the session ID from the
        ServerHello.  This avoids a full key exchange but raises security concerns:
          - Session resumption extends forward secrecy window (master secret reuse)
          - Session ticket extension (RFC 5077, type 0x0023) allows stateless
            resumption but requires server-held ticket encryption key

        Checks performed:
          1. Full handshake -> capture session ID -> second hello with same ID.
             If server echoes same ID in ServerHello = INFO (resumption supported).
          2. SessionTicket extension (0x0023) in ServerHello = INFO.
          3. Second hello with random (forged) session ID -> if server accepts = MEDIUM.

        Returns list of finding dicts.
        """
        findings  = []
        TLS_EXT_SESSION_TICKET = 0x0023

        gcm_ciphers = [0xC02F, 0xC02B, 0x009C, 0x003C]

        try:
            # First connection: capture real session ID
            ch1      = self._build_client_hello(session_id=b'', cipher_codes=gcm_ciphers)
            records1 = self._raw_tls_connect(host, port, ch1, timeout=6)

            session_id     = b''
            ticket_present = False

            for ct, data in records1:
                if ct != 0x16 or not data or data[0] != 0x02:
                    continue
                sh         = self._parse_server_hello(data)
                session_id = sh.get('session_id', b'')

                # Scan ServerHello extensions for SessionTicket (0x0023)
                # Extensions start after: 2(ver)+32(rand)+1+sid_len(sid)+2(cs)+1(comp)
                try:
                    msg_len = struct.unpack('!I', b'\x00' + data[1:4])[0]
                    body    = data[4:4 + msg_len]
                    off     = 2 + 32
                    if off < len(body):
                        sid_len = body[off]
                        off    += 1 + sid_len + 2 + 1  # sid + cipher + comp
                    if off + 2 <= len(body):
                        ext_total = struct.unpack('!H', body[off:off + 2])[0]
                        off      += 2
                        ext_end   = off + ext_total
                        while off + 4 <= ext_end and off + 4 <= len(body):
                            ext_type = struct.unpack('!H', body[off:off + 2])[0]
                            ext_len  = struct.unpack('!H', body[off + 2:off + 4])[0]
                            if ext_type == TLS_EXT_SESSION_TICKET:
                                ticket_present = True
                                break
                            off += 4 + ext_len
                except Exception:
                    pass
                break

            if ticket_present:
                findings.append({
                    'severity': 'INFO',
                    'title':    'TLS session ticket extension supported',
                    'detail':   (
                        'ServerHello includes TLS_EXT_SESSION_TICKET (0x0023, RFC 5077). '
                        'Stateless session resumption is enabled. The server-held ticket '
                        'encryption key is a single point of compromise: recovery allows '
                        'decryption of all sessions within the ticket lifetime window.'
                    ),
                    'host':     host,
                    'port':     port,
                })

            if session_id:
                # Second connection: request resumption with captured session ID
                ch2      = self._build_client_hello(session_id=session_id,
                                                    cipher_codes=gcm_ciphers)
                records2 = self._raw_tls_connect(host, port, ch2, timeout=6)

                for ct, data in records2:
                    if ct != 0x16 or not data or data[0] != 0x02:
                        continue
                    sh2     = self._parse_server_hello(data)
                    resumed = (sh2.get('session_id') == session_id)
                    if resumed:
                        findings.append({
                            'severity': 'INFO',
                            'title':    'Session resumption supported',
                            'detail':   (
                                f'Server echoed session_id in ServerHello (abbreviated handshake). '
                                f'Session ID length: {len(session_id)} bytes. Resumption reuses '
                                f'the master secret from the original session; forward secrecy '
                                f'is limited to the original handshake lifetime.'
                            ),
                            'host':     host,
                            'port':     port,
                        })
                    break

                # Third connection: forged (random) session ID — should be rejected
                forged_id = os.urandom(len(session_id) if session_id else 32)
                ch3       = self._build_client_hello(session_id=forged_id,
                                                     cipher_codes=gcm_ciphers)
                records3  = self._raw_tls_connect(host, port, ch3, timeout=6)

                for ct, data in records3:
                    if ct != 0x16 or not data or data[0] != 0x02:
                        continue
                    sh3          = self._parse_server_hello(data)
                    forged_match = (sh3.get('session_id') == forged_id)
                    if forged_match:
                        findings.append({
                            'severity': 'MEDIUM',
                            'title':    'Session resumption accepted forged session ID',
                            'detail':   (
                                'Server echoed a random (forged) session ID in its ServerHello. '
                                'This indicates the server is treating unknown session IDs as valid '
                                'for resumption, which may allow session fixation or state confusion '
                                'attacks. Session IDs should be validated against the server session '
                                'cache before resumption is granted.'
                            ),
                            'host':     host,
                            'port':     port,
                        })
                    break

        except (ssl.SSLError, OSError):
            pass
        except Exception:
            pass
        return findings

    def check_beast_vulnerability(self, host: str, port: int) -> list:
        """Probe for BEAST vulnerability: TLS 1.0 with CBC cipher.

        From ch. 6 (CBC IV issues): TLS 1.0 uses the last ciphertext block of
        the previous record as the IV for the next CBC record.  This makes the IV
        predictable to an observer, enabling a chosen-plaintext attack (BEAST,
        CVE-2011-3389) against CBC ciphers when the attacker can inject data
        adjacent to a known-position secret (e.g. HTTP session cookie).

        TLS 1.1+ fixed this by generating an explicit random IV per record.

        Returns MEDIUM finding if TLS 1.0 + CBC is negotiated.
        Returns INFO if TLS 1.1+ with CBC (IV fixed but CBC still suboptimal vs AEAD).
        Returns list of finding dicts.
        """
        findings = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    ver_str = ss.version() or ''
                    cipher  = ss.cipher()
                    cipher_name = (cipher[0] if cipher else '') or ''

            if 'CBC' in cipher_name.upper():
                if ver_str in ('TLSv1', 'TLSv1.0'):
                    findings.append({
                        'severity': 'MEDIUM',
                        'title':    'TLS 1.0 with CBC cipher (BEAST attack vector)',
                        'detail':   (
                            f'Negotiated {ver_str} with cipher {cipher_name}. '
                            'TLS 1.0 CBC uses the last ciphertext block of the previous '
                            'record as a predictable IV for the next (RFC 2246 sec. 6.2.3.2). '
                            'BEAST (CVE-2011-3389): attacker with network access and ability to '
                            'inject chosen plaintext can recover secrets byte-by-byte from a '
                            'known-position fixed value (e.g. HTTP cookie). '
                            'Mitigate: disable TLS 1.0 or prefer AEAD cipher suites (AES-GCM).'
                        ),
                        'host':     host,
                        'port':     port,
                    })
                else:
                    findings.append({
                        'severity': 'INFO',
                        'title':    f'{ver_str} with CBC cipher (BEAST not applicable)',
                        'detail':   (
                            f'Negotiated {ver_str} with cipher {cipher_name}. '
                            'TLS 1.1+ uses explicit per-record random IV for CBC, eliminating '
                            'the BEAST predictable-IV condition. CBC is still less preferred '
                            'than AEAD (AES-GCM) due to padding oracle and Lucky13 risks; '
                            'consider migrating to AES-128-GCM or ChaCha20-Poly1305.'
                        ),
                        'host':     host,
                        'port':     port,
                    })
        except (ssl.SSLError, OSError):
            pass
        except Exception:
            pass
        return findings

    def check_dh_params(self, host: str, port: int, timeout: int = 6) -> dict:
        """Extract and evaluate Diffie-Hellman parameters from ServerKeyExchange.

        Sends a ClientHello advertising DHE and ECDHE cipher suites, reads the
        raw TLS records, and parses the ServerKeyExchange message to extract key
        exchange parameters.  No openssl dependency — pure socket + struct.

        DH prime bit-length thresholds (NIST SP 800-131A Rev 2):
          < 1024 bits  — CRITICAL: NFS pre-computation practical at lab scale
          < 2048 bits  — HIGH: approaching factoring range with academic compute
          >= 2048 bits — OK

        Known Logjam primes (RFC 2409 / 3526 MODP groups):
          Identified by the pi-derived constant embedded in all MODP group primes.
          NFS pre-computation for the 768-bit and 1024-bit groups is estimated
          complete at national-scale compute (Logjam 2015 paper, §6).

        ECDHE named-curve classification:
          OK:   secp256r1, secp384r1, secp521r1, x25519, x448
          HIGH: secp192r1 (below 192-bit security floor)
          LOW:  brainpool variants (less-studied implementations, side-channel risk)

        Returns dict with findings list, kex_type, dh_p_bits, ecdhe_curve,
        logjam_prime flag, and raw p_hex prefix for external analysis.
        """
        result = {
            'host':         host,
            'port':         port,
            'kex_type':     'unknown',
            'dh_p_bits':    None,
            'dh_p_hex':     None,
            'ecdhe_curve':  None,
            'logjam_prime': False,
            'findings':     [],
        }

        dhe_ciphers = [
            0x0067,  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
            0x006B,  # TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
            0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256 (RSA fallback, no SKE)
        ]

        ch      = self._build_client_hello(session_id=b'', cipher_codes=dhe_ciphers)
        records = self._raw_tls_connect(host, port, ch, timeout=timeout)
        kex     = self._parse_server_key_exchange(records)

        result['kex_type']    = kex['type']
        result['dh_p_bits']   = kex.get('p_bits')
        result['dh_p_hex']    = (kex.get('p_hex') or '')[:64]  # first 32 bytes as hex
        result['ecdhe_curve'] = kex.get('curve')

        if kex['type'] == 'dh' and kex.get('p_bits') is not None:
            p_bits = kex['p_bits']
            p_hex  = (kex.get('p_hex') or '').lower()

            # Logjam prime detection: MODP group primes all contain the pi-constant
            result['logjam_prime'] = any(fp in p_hex for fp in _LOGJAM_PRIME_FINGERPRINTS)

            if p_bits < 1024:
                sev    = 'CRITICAL'
                detail = (
                    f'DH prime {p_bits} bits — below 1024-bit floor. '
                    f'Number Field Sieve pre-computation is practical at laboratory scale '
                    f'(Logjam 2015). Any connection using this prime is retroactively decryptable.'
                )
            elif p_bits < 2048:
                sev    = 'HIGH'
                detail = (
                    f'DH prime {p_bits} bits — below NIST SP 800-131A Rev 2 minimum of 2048 bits. '
                    f'Approaching practical NFS factoring range with well-resourced adversary.'
                )
            else:
                sev    = 'INFO'
                detail = f'DH prime {p_bits} bits — meets NIST SP 800-131A Rev 2 minimum of 2048 bits.'

            result['findings'].append({
                'type':     'DH_PRIME_SIZE',
                'severity': sev,
                'host':     host,
                'port':     port,
                'detail':   detail,
                'exploit':  (
                    f'testssl.sh --logjam {host}:{port} ; '
                    f'# Offline NFS against a {p_bits}-bit prime'
                ) if p_bits < 2048 else '',
            })

            if result['logjam_prime']:
                result['findings'].append({
                    'type':     'DH_LOGJAM_PRIME',
                    'severity': 'CRITICAL',
                    'host':     host,
                    'port':     port,
                    'detail':   (
                        f'DH prime matches a known RFC 2409 / RFC 3526 MODP group '
                        f'(pi-derived constant detected in prime hex). '
                        f'NFS pre-computation for the {p_bits}-bit MODP group is estimated '
                        f'complete at national-scale compute (Logjam 2015 §6). '
                        f'Passive decryption of any session using this prime is trivial for '
                        f'a sufficiently resourced adversary.'
                    ),
                    'exploit':  (
                        'Apply pre-computed NFS discrete-log table for this MODP group. '
                        'Recover ephemeral DH private key in seconds from the logged table. '
                        'Decrypt pre-master secret and derive all session keys. '
                        'Ref: Logjam: On the Viability of DLOG in the Wild, CCS 2015.'
                    ),
                })

        elif kex['type'] == 'ecdhe' and kex.get('curve'):
            curve       = kex['curve']
            safe_curves = {'secp256r1', 'secp384r1', 'secp521r1', 'x25519', 'x448'}
            weak_curves = {'secp192r1', 'secp224r1'}

            if curve in safe_curves:
                result['findings'].append({
                    'type':     'ECDHE_CURVE_OK',
                    'severity': 'INFO',
                    'host':     host,
                    'port':     port,
                    'detail':   f'ECDHE named curve {curve} — meets security requirements.',
                    'exploit':  '',
                })
            elif curve in weak_curves:
                result['findings'].append({
                    'type':     'ECDHE_CURVE_WEAK',
                    'severity': 'HIGH',
                    'host':     host,
                    'port':     port,
                    'detail':   (
                        f'ECDHE curve {curve} — below the 192-bit security floor. '
                        f'Pohlig-Hellman decomposition over small-order subgroups '
                        f'reduces ECDLP difficulty substantially.'
                    ),
                    'exploit':  (
                        f'openssl s_client -connect {host}:{port} -curves {curve} '
                        f'2>/dev/null | grep "Server Temp Key"'
                    ),
                })
            elif 'brainpool' in curve:
                result['findings'].append({
                    'type':     'ECDHE_BRAINPOOL_CURVE',
                    'severity': 'LOW',
                    'host':     host,
                    'port':     port,
                    'detail':   (
                        f'ECDHE curve {curve} — brainpool variant. Mathematically acceptable '
                        f'but less studied for side-channel resistance than NIST / Bernstein '
                        f'curves. Implementation correctness is not universally verified.'
                    ),
                    'exploit':  '',
                })
            else:
                result['findings'].append({
                    'type':     'ECDHE_CURVE_UNKNOWN',
                    'severity': 'MEDIUM',
                    'host':     host,
                    'port':     port,
                    'detail':   f'ECDHE curve {curve!r} — not in known-safe set; manual review required.',
                    'exploit':  '',
                })

        return result

    # ── MacStadium-specific ───────────────────────────────────────────────────

    def analyze_macstadium(self) -> list:
        """Analyze MacStadium TLS targets.

        Targets: idp.macstadium.com, api.macstadium.com, orka.macstadium.com
        Context: F-JWT finding — empty-secret HS256 JWT at idp.macstadium.com.
        TLS posture correlates with JWT security posture.
        """
        results = []
        for host, port in MACSTADIUM_HOSTS:
            result = self.analyze(host, port)
            result['target_label'] = f'MacStadium:{host}'
            results.append(result)
        return results

    # ── Bulk probing ──────────────────────────────────────────────────────────

    def analyze_hosts(self, targets: list) -> list:
        """Analyze a list of (host, port) or 'host:port' strings.

        Returns list of analysis results.
        """
        results = []
        for target in targets:
            if isinstance(target, str):
                if ':' in target:
                    h, _, p = target.rpartition(':')
                    host, port = h, int(p)
                else:
                    host, port = target, 443
            else:
                host, port = target[0], target[1]
            results.append(self.analyze(host, port))
        return results

    # ── Report ────────────────────────────────────────────────────────────────

    def report(self, results: list = None) -> str:
        """Generate a text report from analysis results."""
        findings = self.findings if results is None else []
        if results:
            for r in results:
                findings.extend(r.get('findings', []))

        lines = ['=' * 60, 'TLS CERTIFICATE AND CIPHER ANALYSIS', '=' * 60]
        crit  = [f for f in findings if f.get('severity') == 'CRITICAL']
        high  = [f for f in findings if f.get('severity') == 'HIGH']
        med   = [f for f in findings if f.get('severity') == 'MEDIUM']
        other = [f for f in findings if f.get('severity') not in ('CRITICAL', 'HIGH', 'MEDIUM')]

        lines.append(
            f'\nTotal findings: {len(findings)} '
            f'({len(crit)} CRITICAL, {len(high)} HIGH, {len(med)} MEDIUM, {len(other)} other)'
        )

        for f in crit + high + med + other:
            if f.get('severity') == 'INFO':
                continue
            lines.append(f'\n  [{f.get("severity","?")}] {f.get("type","")}')
            if f.get('host'):
                lines.append(f'  Target: {f["host"]}:{f.get("port", 443)}')
            lines.append(f'  {f.get("detail","")[:200]}')
            if f.get('exploit'):
                for el in f['exploit'].splitlines()[:3]:
                    lines.append(f'  EXPLOIT: {el[:120]}')

        return '\n'.join(lines)


# ── Cipher suite probe (multi-version) ───────────────────────────────────────

class CipherSuiteProber:
    """
    Active cipher suite enumeration.

    Attempts to negotiate each TLS version separately to detect support
    for deprecated versions. Python's ssl module does not expose
    forced-cipher negotiation directly for all suites, so this uses
    openssl s_client subprocess where available, falling back to
    ssl context probes.

    Key cipher classes per RFC 5246 / RFC 8446:
      - Forward-secure: ECDHE / DHE key exchange
      - Non-forward-secure: RSA key exchange (removed in TLS 1.3)
      - Authenticated encryption: AES-GCM, ChaCha20-Poly1305, AES-CCM
      - Broken: RC4, 3DES, NULL, EXPORT, ANON
    """

    def __init__(self, host: str, port: int = 443):
        self.host    = host
        self.port    = port
        self.results = {}

    def probe_version_support(self, timeout: int = 5) -> dict:
        """Test which TLS/SSL versions the server accepts.

        Returns dict: version_str -> supported (bool)
        """
        version_map = {
            'TLSv1':   ssl.PROTOCOL_TLS_CLIENT,
            'TLSv1.1': ssl.PROTOCOL_TLS_CLIENT,
            'TLSv1.2': ssl.PROTOCOL_TLS_CLIENT,
            'TLSv1.3': ssl.PROTOCOL_TLS_CLIENT,
        }

        supported = {}
        for ver_label in ('TLSv1.2', 'TLSv1.3'):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            try:
                if ver_label == 'TLSv1.2':
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                elif ver_label == 'TLSv1.3':
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

                with socket.create_connection((self.host, self.port), timeout=timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=self.host) as ss:
                        supported[ver_label] = ss.version()
            except Exception:
                supported[ver_label] = None

        # Try deprecated versions using minimum_version hack
        for ver_label, tls_ver in (('TLSv1', ssl.TLSVersion.TLSv1),
                                    ('TLSv1.1', ssl.TLSVersion.TLSv1_1)):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = tls_ver
                ctx.maximum_version = tls_ver
                with socket.create_connection((self.host, self.port), timeout=timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=self.host) as ss:
                        supported[ver_label] = ss.version()
            except AttributeError:
                supported[ver_label] = None  # Python version doesn't support this TLSVersion
            except Exception:
                supported[ver_label] = None

        self.results['version_support'] = supported
        return supported


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys

    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        print('Usage: tls_analyzer.py [host[:port] ...] [--macstadium]')
        print('       tls_analyzer.py idp.macstadium.com api.macstadium.com')
        print('       tls_analyzer.py --macstadium')
        sys.exit(0)

    analyzer = TLSAnalyzer()
    results  = []

    if '--macstadium' in args or not args:
        print('[*] Analyzing MacStadium TLS targets...')
        results = analyzer.analyze_macstadium()
    else:
        targets = [a for a in args if not a.startswith('--')]
        print(f'[*] Analyzing {len(targets)} host(s)...')
        results = analyzer.analyze_hosts(targets)

    # Print results
    for r in results:
        host  = r.get('host')
        port  = r.get('port')
        ver   = r.get('tls_version', 'N/A')
        ciph  = r.get('cipher', 'N/A')
        err   = r.get('error')

        print(f'\n{"=" * 50}')
        print(f'  {host}:{port}')
        print(f'  TLS Version: {ver}')
        print(f'  Cipher:      {ciph}')
        if err:
            print(f'  Error:       {err}')

        chain = r.get('cert_chain', [])
        if chain:
            c = chain[0]
            print(f'  Cert CN:     {c.get("subject_cn")}')
            print(f'  Issuer:      {c.get("issuer_cn")}')
            print(f'  Expires:     {c.get("not_after")}')
            print(f'  Self-Signed: {c.get("is_self_signed")}')
            print(f'  Key Alg:     {c.get("key_algorithm")} ({c.get("key_bits")} bits)')
            print(f'  Sig Alg:     {c.get("sig_algorithm")}')

        qi = r.get('quantum_inventory', {})
        vuln = qi.get('vulnerable_algorithms', [])
        if vuln:
            print(f'  Quantum-Vulnerable: {len(vuln)} algorithm(s)')
            for v in vuln[:2]:
                print(f'    {v.get("algorithm")} — {v.get("threat")[:60]}...')

        crit_f = [f for f in r.get('findings', []) if f.get('severity') in ('CRITICAL', 'HIGH')]
        if crit_f:
            print(f'  Findings ({len(crit_f)} CRIT/HIGH):')
            for f in crit_f[:5]:
                print(f'    [{f["severity"]}] {f["type"]}: {f["detail"][:80]}')

    print(analyzer.report(results))
    print(json.dumps({'summary': f'{len(results)} hosts analyzed'}, indent=2))
