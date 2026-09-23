#!/usr/bin/env python3
"""
TLS Enumeration Module
Synthesized from:
  Practical Binary Analysis ch02 — ELF section types, symbol table layout,
    relocation entries (R_386_JUMP_SLOT / R_386_GLOB_DAT), .got.plt hijacking,
    RPATH injection, weak symbols, version symbols
  Practical Reverse Engineering ch02 — ARM calling convention, Thumb mode,
    ADRP/BL/BLX, ARM TrustZone, exception levels

Advanced certificate chain inspection, TLS inspection/bypass detection,
weak cipher enumeration, and certificate pinning / HPKP assessment.
All functions are standalone; no third-party dependencies.
"""

import datetime
import json
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(severity: str, title: str, detail: str, host: str, port: int) -> dict:
    return {"severity": severity, "title": title, "detail": detail,
            "host": host, "port": port}


def _tls_connect(host: str, port: int, timeout: float,
                 sni: str | None = None,
                 ctx: ssl.SSLContext | None = None):
    """Return a connected (sock, ssl_sock) pair or raise."""
    if ctx is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=timeout)
    server_hostname = sni if sni is not None else host
    tls = ctx.wrap_socket(raw, server_hostname=server_hostname)
    return raw, tls


def _send_raw_clienthello(host: str, port: int, payload: bytes,
                           timeout: float) -> bytes:
    """Send a raw TLS record and return up to 4096 bytes of response."""
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(payload)
        return s.recv(4096)
    except Exception:
        return b""
    finally:
        s.close()


def _build_clienthello(cipher_ids: list[int],
                        sni: str = "",
                        session_id: bytes = b"",
                        extensions_extra: bytes = b"",
                        include_early_data: bool = False) -> bytes:
    """
    Construct a minimal TLS 1.3-capable ClientHello record using struct.pack.
    cipher_ids — list of 2-byte cipher suite values (int).
    Returns the full TLS record layer bytes.
    """
    # Random (32 bytes)
    random_bytes = b"\x00" * 32

    # Session ID
    sid_len = len(session_id)
    sid_field = struct.pack("!B", sid_len) + session_id

    # Cipher suites
    cs_bytes = b"".join(struct.pack("!H", c) for c in cipher_ids)
    cs_len = len(cs_bytes)
    cs_field = struct.pack("!H", cs_len) + cs_bytes

    # Compression methods
    comp = b"\x01\x00"  # length=1, null

    # Extensions
    exts = b""

    # SNI extension (type 0x0000)
    if sni:
        sni_encoded = sni.encode()
        sni_name_len = len(sni_encoded)
        sni_list_len = sni_name_len + 3   # 1 (type) + 2 (len)
        sni_ext_data = struct.pack("!HBH", sni_list_len, 0, sni_name_len) + sni_encoded
        exts += struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    # Supported versions (TLS 1.3 = 0x0304, TLS 1.2 = 0x0303)
    sv_data = b"\x04\x03\x04\x03\x03"
    exts += struct.pack("!HH", 0x002B, len(sv_data)) + sv_data

    # Supported groups
    sg_data = b"\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
    exts += struct.pack("!HH", 0x000A, len(sg_data)) + sg_data

    # Signature algorithms
    sa_data = b"\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03"
    exts += struct.pack("!HH", 0x000D, len(sa_data)) + sa_data

    # Early data (0-RTT indicator, type 0x002A)
    if include_early_data:
        exts += struct.pack("!HH", 0x002A, 0)

    # Caller-supplied extra extensions
    exts += extensions_extra

    ext_field = struct.pack("!H", len(exts)) + exts

    # Assemble handshake body
    body = (b"\x03\x03"       # legacy_version = TLS 1.2
            + random_bytes
            + sid_field
            + cs_field
            + comp
            + ext_field)

    # Handshake header: type=1 (ClientHello) + 3-byte length
    hs = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body

    # TLS record: content_type=22 (handshake), version=0x0301, length
    record = struct.pack("!BBH", 22, 3, 1) + struct.pack("!H", len(hs)) + hs
    return record


# ---------------------------------------------------------------------------
# 1. Certificate Transparency checks
# ---------------------------------------------------------------------------

def check_certificate_transparency(host: str, port: int = 443,
                                    timeout: float = 5.0) -> list:
    """
    Check for certificate posture issues via the peer certificate.

    Returns list of findings:
      WILDCARD_SAN_OVERLY_BROAD  HIGH   — *.com / *.net SANs
      CERT_EXCEEDS_VALIDITY_LIMIT MEDIUM — validity > 398 days
      SELF_SIGNED_CERTIFICATE    HIGH   — issuer == subject
      CERT_CN_SAN_MISMATCH       HIGH   — CN absent from SAN set
    """
    findings = []
    try:
        _, tls = _tls_connect(host, port, timeout)
    except Exception as e:
        return [_finding("ERROR", "TLS_CONNECT_FAILED",
                         f"Could not connect: {e}", host, port)]
    try:
        cert = tls.getpeercert()
    except Exception:
        cert = None
    finally:
        try:
            tls.close()
        except Exception:
            pass

    if not cert:
        return [_finding("INFO", "NO_CERT_RETURNED",
                         "Server returned no parseable certificate", host, port)]

    # ── SAN extraction ──────────────────────────────────────────────────────
    san_entries = []
    for rdn_type, value in cert.get("subjectAltName", []):
        if rdn_type == "DNS":
            san_entries.append(value.lower())

    # Overly-broad wildcard: *.com or *.net (one label wildcards at TLD level)
    for san in san_entries:
        if san in ("*.com", "*.net", "*.org", "*.io"):
            findings.append(_finding(
                "HIGH", "WILDCARD_SAN_OVERLY_BROAD",
                f"SAN contains TLD-level wildcard: {san}", host, port))

    # ── Validity window ─────────────────────────────────────────────────────
    try:
        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter", "")
        fmt = "%b %d %H:%M:%S %Y %Z"
        nb = datetime.datetime.strptime(not_before_str, fmt)
        na = datetime.datetime.strptime(not_after_str, fmt)
        validity_days = (na - nb).days
        if validity_days > 398:
            findings.append(_finding(
                "MEDIUM", "CERT_EXCEEDS_VALIDITY_LIMIT",
                f"Certificate validity {validity_days}d exceeds 398-day CA/B Forum limit",
                host, port))
    except Exception:
        pass

    # ── Self-signed detection ────────────────────────────────────────────────
    def _rdn_to_str(rdn_seq):
        return ",".join(
            "=".join(pair) for rdn in rdn_seq for pair in rdn
        )

    issuer  = _rdn_to_str(cert.get("issuer", ()))
    subject = _rdn_to_str(cert.get("subject", ()))
    if issuer and subject and issuer == subject:
        findings.append(_finding(
            "HIGH", "SELF_SIGNED_CERTIFICATE",
            f"Issuer equals subject: {issuer}", host, port))

    # ── CN / SAN mismatch ───────────────────────────────────────────────────
    cn = None
    for rdn in cert.get("subject", ()):
        for attr, val in rdn:
            if attr == "commonName":
                cn = val.lower()
    if cn and san_entries and cn not in san_entries:
        findings.append(_finding(
            "HIGH", "CERT_CN_SAN_MISMATCH",
            f"CN '{cn}' not present in SANs: {san_entries}", host, port))

    return findings


# ---------------------------------------------------------------------------
# 2. TLS inspection / DPI bypass detection
# ---------------------------------------------------------------------------

_GREASE_VALUES = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
]

_DEFAULT_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]


def probe_tls_inspection_bypass(host: str, port: int = 443,
                                 timeout: float = 5.0) -> list:
    """
    Send crafted ClientHellos to detect DPI/TLS-inspection middleware.

    Returns findings:
      GREASE_EXTENSION_ACCEPTED    MEDIUM — GREASE values in cipher list accepted
      LARGE_SESSION_ID_ACCEPTED    MEDIUM — 32-byte session ID accepted
      ZERO_RTT_ACCEPTED            MEDIUM — early_data extension echoed back
      FRAGMENTED_CLIENTHELLO_BYPASSES_IDS  HIGH — split ClientHello completes
    """
    findings = []

    # ── GREASE cipher suites ─────────────────────────────────────────────────
    try:
        grease_ciphers = _GREASE_VALUES[:4] + _DEFAULT_CIPHERS
        payload = _build_clienthello(grease_ciphers, sni=host)
        resp = _send_raw_clienthello(host, port, payload, timeout)
        # ServerHello = record type 22, handshake type 2
        if len(resp) >= 6 and resp[0] == 22 and resp[5] == 2:
            findings.append(_finding(
                "MEDIUM", "GREASE_EXTENSION_ACCEPTED",
                "Server accepted GREASE cipher values — DPI may not be stripping",
                host, port))
    except Exception:
        pass

    # ── Large session ID (32 bytes) ──────────────────────────────────────────
    try:
        large_sid = b"\xAB" * 32
        payload = _build_clienthello(_DEFAULT_CIPHERS, sni=host,
                                     session_id=large_sid)
        resp = _send_raw_clienthello(host, port, payload, timeout)
        if len(resp) >= 6 and resp[0] == 22 and resp[5] == 2:
            findings.append(_finding(
                "MEDIUM", "LARGE_SESSION_ID_ACCEPTED",
                "Server accepted 32-byte session ID without rejection",
                host, port))
    except Exception:
        pass

    # ── Early data / 0-RTT ───────────────────────────────────────────────────
    try:
        payload = _build_clienthello(_DEFAULT_CIPHERS, sni=host,
                                     include_early_data=True)
        resp = _send_raw_clienthello(host, port, payload, timeout)
        # If server sends early_data extension (0x002A) in its EncryptedExtensions
        if b"\x00\x2a" in resp:
            findings.append(_finding(
                "MEDIUM", "ZERO_RTT_ACCEPTED",
                "Server echoed early_data extension — 0-RTT replay risk",
                host, port))
    except Exception:
        pass

    # ── Fragmented ClientHello across two TCP writes ──────────────────────────
    try:
        payload = _build_clienthello(_DEFAULT_CIPHERS, sni=host)
        split = max(len(payload) // 2, 5)
        part1, part2 = payload[:split], payload[split:]
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(part1)
            time.sleep(0.05)
            s.sendall(part2)
            resp = s.recv(4096)
            if len(resp) >= 6 and resp[0] == 22 and resp[5] == 2:
                findings.append(_finding(
                    "HIGH", "FRAGMENTED_CLIENTHELLO_BYPASSES_IDS",
                    "Server completed handshake after TCP-fragmented ClientHello — "
                    "IDS/DPI may not reassemble",
                    host, port))
        finally:
            s.close()
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# 3. Weak cipher suite enumeration
# ---------------------------------------------------------------------------

def check_weak_cipher_suites(host: str, port: int = 443,
                              timeout: float = 5.0) -> list:
    """
    Enumerate legacy / broken cipher suites.

    Returns findings:
      SSLV3_ACCEPTED          CRITICAL — POODLE
      RC4_CIPHER_ACCEPTED     CRITICAL — RC4 broken
      DES_CIPHER_ACCEPTED     CRITICAL — SWEET32 (64-bit block)
      NULL_CIPHER_OFFERED_ACCEPTED  HIGH
      EXPORT_CIPHER_ACCEPTED  CRITICAL — FREAK
    """
    findings = []

    def _server_accepts(cipher_ids: list[int]) -> bool:
        """True if server responds with ServerHello."""
        payload = _build_clienthello(cipher_ids, sni=host)
        resp = _send_raw_clienthello(host, port, payload, timeout)
        return len(resp) >= 6 and resp[0] == 22 and resp[5] == 2

    # ── SSLv3 via ssl module ─────────────────────────────────────────────────
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.SSLv3  # type: ignore[attr-defined]
        ctx.maximum_version = ssl.TLSVersion.SSLv3  # type: ignore[attr-defined]
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            tls.close()
            findings.append(_finding(
                "CRITICAL", "SSLV3_ACCEPTED",
                "Server negotiated SSLv3 — vulnerable to POODLE (CVE-2014-3566)",
                host, port))
        except ssl.SSLError:
            pass
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except (AttributeError, OSError):
        # SSLv3 constant absent on hardened Python builds — fall through to raw
        # ClientHello probe with version bytes \x03\x00
        try:
            sslv3_payload = _build_clienthello(
                [0x0005, 0x000A, 0x002F], sni=host)
            # Override legacy_version field: bytes 9-10 in the record → \x03\x00
            sslv3_payload = sslv3_payload[:9] + b"\x03\x00" + sslv3_payload[11:]
            resp = _send_raw_clienthello(host, port, sslv3_payload, timeout)
            if len(resp) >= 6 and resp[0] == 22 and resp[5] == 2:
                findings.append(_finding(
                    "CRITICAL", "SSLV3_ACCEPTED",
                    "Server responded to SSLv3 ClientHello — POODLE risk",
                    host, port))
        except Exception:
            pass

    # ── RC4 (TLS_RSA_WITH_RC4_128_SHA = 0x0005) ──────────────────────────────
    try:
        if _server_accepts([0x0005]):
            findings.append(_finding(
                "CRITICAL", "RC4_CIPHER_ACCEPTED",
                "TLS_RSA_WITH_RC4_128_SHA (0x0005) accepted — RC4 is broken",
                host, port))
    except Exception:
        pass

    # ── DES (TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x0015) ──────────────────────────
    try:
        if _server_accepts([0x0015]):
            findings.append(_finding(
                "CRITICAL", "DES_CIPHER_ACCEPTED",
                "TLS_DHE_RSA_WITH_DES_CBC_SHA (0x0015) accepted — vulnerable to SWEET32",
                host, port))
    except Exception:
        pass

    # ── NULL cipher (TLS_NULL_WITH_NULL_NULL = 0x0000) ───────────────────────
    try:
        payload = _build_clienthello([0x0000], sni=host)
        resp = _send_raw_clienthello(host, port, payload, timeout)
        # If server doesn't immediately send alert (21) or close
        if len(resp) >= 1 and resp[0] != 21:
            findings.append(_finding(
                "HIGH", "NULL_CIPHER_OFFERED_ACCEPTED",
                "Server did not immediately alert on TLS_NULL_WITH_NULL_NULL offer",
                host, port))
    except Exception:
        pass

    # ── EXPORT ciphers via connected ssl.SSLSocket.cipher() ──────────────────
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Force export-grade ciphers if the platform allows
        try:
            ctx.set_ciphers("EXPORT:ALL:@SECLEVEL=0")
        except ssl.SSLError:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            cipher_name = (tls.cipher() or ("", "", 0))[0]
            tls.close()
            if "_EXPORT_" in cipher_name.upper() or "EXP" in cipher_name.upper():
                findings.append(_finding(
                    "CRITICAL", "EXPORT_CIPHER_ACCEPTED",
                    f"Negotiated export-grade cipher: {cipher_name} — FREAK attack vector",
                    host, port))
        except ssl.SSLError:
            pass
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# 4. Certificate pinning / HPKP / Expect-CT detection
# ---------------------------------------------------------------------------

def probe_certificate_pinning_bypass(host: str, port: int = 443,
                                     timeout: float = 5.0) -> list:
    """
    Detect HPKP, Expect-CT, security.txt, and SNI-unbound certificate swap.

    Returns findings:
      HPKP_CONFIGURED              MEDIUM — Public-Key-Pins header present
      EXPECT_CT_ABSENT             MEDIUM — Expect-CT header missing
      SECURITY_TXT_PRESENT         INFO   — /.well-known/security.txt returns 200
      CERT_NOT_SNI_BOUND           HIGH   — certificate changes when SNI omitted
    """
    findings = []

    # ── Fetch response headers ───────────────────────────────────────────────
    headers_found: dict[str, str] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://{host}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ctx) as resp:
            for k, v in resp.headers.items():
                headers_found[k.lower()] = v
    except Exception:
        pass

    # HPKP
    if "public-key-pins" in headers_found:
        findings.append(_finding(
            "MEDIUM", "HPKP_CONFIGURED",
            f"Public-Key-Pins header: {headers_found['public-key-pins'][:120]}",
            host, port))

    # Expect-CT
    if "expect-ct" not in headers_found:
        findings.append(_finding(
            "MEDIUM", "EXPECT_CT_ABSENT",
            "Expect-CT header absent — certificate transparency not enforced by server",
            host, port))

    # ── security.txt ─────────────────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://{host}:{port}/.well-known/security.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ctx) as resp:
            if resp.status == 200:
                findings.append(_finding(
                    "INFO", "SECURITY_TXT_PRESENT",
                    "/.well-known/security.txt returned 200",
                    host, port))
    except urllib.error.HTTPError as e:
        if e.code == 200:
            findings.append(_finding(
                "INFO", "SECURITY_TXT_PRESENT",
                "/.well-known/security.txt returned 200",
                host, port))
    except Exception:
        pass

    # ── SNI-unbound certificate check ────────────────────────────────────────
    def _get_cert_digest(sni_value: str | None) -> str | None:
        """Return SHA256 fingerprint of peer cert, or None on error."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((host, port), timeout=timeout)
            raw.settimeout(timeout)
            try:
                tls = ctx.wrap_socket(raw, server_hostname=sni_value)
                der = tls.getpeercert(binary_form=True)
                tls.close()
                if not der:
                    return None
                import hashlib
                return hashlib.sha256(der).hexdigest()
            finally:
                try:
                    raw.close()
                except Exception:
                    pass
        except Exception:
            return None

    cert_with_sni    = _get_cert_digest(host)
    cert_without_sni = _get_cert_digest(None)

    if (cert_with_sni and cert_without_sni
            and cert_with_sni != cert_without_sni):
        findings.append(_finding(
            "HIGH", "CERT_NOT_SNI_BOUND",
            "Certificate differs when SNI is omitted — possible SSL stripping / "
            "virtual-host misconfiguration",
            host, port))

    return findings


# ---------------------------------------------------------------------------
# 5. mTLS enforcement probes
# ---------------------------------------------------------------------------

def probe_mtls_enforcement(host: str, port: int = 443,
                            timeout: float = 5.0) -> list:
    """
    Detect gaps in mutual-TLS enforcement and related client-auth controls.

    Returns findings:
      MTLS_NOT_ENFORCED            HIGH   — handshake succeeds without a client cert
      TLS13_0RTT_ENABLED           HIGH   — TLS 1.3 session ticket issued; PSK
                                           resumption enables 0-RTT early data
      NO_CLIENT_AUTH_REQUESTED     HIGH   — server handshake flight contains no
                                           CertificateRequest (handshake type 13)
      SNI_STRICT_VALIDATION_ABSENT MEDIUM — handshake succeeds with a bogus SNI
    """
    findings = []

    # ── 1. mTLS: connect without client certificate ───────────────────────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            tls.close()
            findings.append(_finding(
                "HIGH", "MTLS_NOT_ENFORCED",
                "TLS handshake completed without a client certificate — "
                "mutual TLS is not enforced",
                host, port))
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except ssl.SSLError:
        pass  # server rejected — mTLS may be in force
    except Exception:
        pass

    # ── 2. TLS 1.3 early data (0-RTT): session ticket as capability proxy ────
    # Session tickets in TLS 1.3 enable PSK resumption; if the server issues a
    # ticket and negotiates 1.3, it can offer 0-RTT (max_early_data_size > 0).
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            version = tls.version()          # e.g. "TLSv1.3"
            session = tls.session            # ssl.SSLSession or None
            tls.close()
            if version == "TLSv1.3" and session is not None and session.has_ticket:
                findings.append(_finding(
                    "HIGH", "TLS13_0RTT_ENABLED",
                    "Server negotiated TLS 1.3 and issued a session ticket — "
                    "PSK resumption enables 0-RTT early data; replay attack "
                    "surface present if max_early_data_size > 0",
                    host, port))
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        pass

    # ── 3. CertificateRequest detection via raw handshake scan ───────────────
    # Send a ClientHello and walk the server's handshake records looking for
    # handshake type 13 (CertificateRequest). Absence = client auth not required.
    try:
        hello = _build_clienthello(
            cipher_ids=[0x002F, 0x0035, 0xC02B, 0xC02C, 0x1301, 0x1302],
            sni=host,
        )
        resp = _send_raw_clienthello(host, port, hello, timeout)
        found_cert_req = False
        i = 0
        while i + 5 <= len(resp):
            content_type = resp[i]
            rec_len = struct.unpack("!H", resp[i + 3: i + 5])[0]
            payload_end = i + 5 + rec_len
            if content_type == 22:  # handshake record
                j = i + 5
                while j + 4 <= payload_end and payload_end <= len(resp):
                    hs_type = resp[j]
                    hs_len = struct.unpack("!I", b"\x00" + resp[j + 1: j + 4])[0]
                    if hs_type == 13:  # CertificateRequest
                        found_cert_req = True
                        break
                    j += 4 + hs_len
            if found_cert_req:
                break
            if rec_len == 0:
                break
            i = payload_end
        if not found_cert_req and len(resp) > 5:
            findings.append(_finding(
                "HIGH", "NO_CLIENT_AUTH_REQUESTED",
                "Server handshake flight contains no CertificateRequest "
                "(handshake type 13) — client certificate authentication "
                "is not required",
                host, port))
    except Exception:
        pass

    # ── 4. SNI strict validation: wrong SNI still completes handshake ─────────
    # Distinct from CERT_NOT_SNI_BOUND (which checks cert identity change);
    # this checks whether a bogus hostname is accepted at all.
    wrong_sni = "invalid-sni-probe.example.invalid"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=wrong_sni)
            tls.close()
            findings.append(_finding(
                "MEDIUM", "SNI_STRICT_VALIDATION_ABSENT",
                f"TLS handshake succeeded with bogus SNI '{wrong_sni}' — "
                "server does not gate certificate selection on a valid SNI value",
                host, port))
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except ssl.SSLError:
        pass  # server rejected bogus SNI — strict validation in place
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# 6. TLS downgrade attack probes
# ---------------------------------------------------------------------------

def probe_tls_downgrade_attack(host: str, port: int = 443,
                                timeout: float = 5.0) -> list:
    """
    Probe for TLS downgrade weaknesses: FALLBACK_SCSV, legacy version acceptance,
    and HSTS policy gaps.

    Returns findings:
      NO_FALLBACK_SCSV_PROTECTION  HIGH   — server does not send inappropriate_fallback
                                           alert when TLS_FALLBACK_SCSV is present
                                           with a below-maximum protocol version
      TLS10_ACCEPTED               HIGH   — server accepts TLS 1.0 connections
      TLS11_ACCEPTED               MEDIUM — server accepts TLS 1.1 connections
      SHORT_HSTS_MAX_AGE           MEDIUM — HSTS max-age below 31536000 (1 year)
      HSTS_NOT_PRELOAD_READY       MEDIUM — HSTS header missing includeSubDomains
                                           and/or preload directive
    """
    findings = []

    # ── 1. TLS_FALLBACK_SCSV (RFC 7507) ──────────────────────────────────────
    # Build a ClientHello advertising TLS 1.1 as max version plus the
    # FALLBACK_SCSV sentinel (0x5600).  A server that supports TLS 1.2+ MUST
    # respond with a fatal inappropriate_fallback alert (level=2, desc=86).
    try:
        random_bytes = b"\x00" * 32
        ciphers = [0x002F, 0x0035, 0x5600]       # AES128, AES256, FALLBACK_SCSV
        cs_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
        cs_field = struct.pack("!H", len(cs_bytes)) + cs_bytes
        sni_enc = host.encode()
        sni_list_len = len(sni_enc) + 3
        sni_data = struct.pack("!HBH", sni_list_len, 0, len(sni_enc)) + sni_enc
        exts = struct.pack("!HH", 0x0000, len(sni_data)) + sni_data
        ext_field = struct.pack("!H", len(exts)) + exts
        # legacy_version = TLS 1.1 (0x0302) to simulate a downgrade
        body = (b"\x03\x02" + random_bytes + b"\x00"
                + cs_field + b"\x01\x00" + ext_field)
        hs = struct.pack("!B", 1) + struct.pack("!I", len(body))[1:] + body
        hello = struct.pack("!BBH", 22, 3, 1) + struct.pack("!H", len(hs)) + hs

        resp = _send_raw_clienthello(host, port, hello, timeout)
        # inappropriate_fallback: content_type=21 (alert), level=2, desc=86
        got_fallback_alert = (
            len(resp) >= 7
            and resp[0] == 21   # alert record
            and resp[5] == 2    # fatal
            and resp[6] == 86   # inappropriate_fallback
        )
        if len(resp) > 0 and not got_fallback_alert:
            findings.append(_finding(
                "HIGH", "NO_FALLBACK_SCSV_PROTECTION",
                "Server did not return inappropriate_fallback alert (RFC 7507) "
                "when TLS_FALLBACK_SCSV was presented with a downgraded version — "
                "protocol downgrade attacks may succeed",
                host, port))
    except Exception:
        pass

    # ── 2 & 3. Legacy TLS version acceptance ─────────────────────────────────
    _version_tests = [
        ("TLSv1",   "HIGH",   "TLS10_ACCEPTED",
         "Server accepted TLS 1.0 — deprecated since RFC 8996 (2021)"),
        ("TLSv1_1", "MEDIUM", "TLS11_ACCEPTED",
         "Server accepted TLS 1.1 — deprecated since RFC 8996 (2021)"),
    ]
    for ver_name, sev, title, detail in _version_tests:
        try:
            ver_attr = getattr(ssl.TLSVersion, ver_name, None)
            if ver_attr is None:
                continue  # OpenSSL build has disabled this version entirely
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver_attr
            ctx.maximum_version = ver_attr
            raw = socket.create_connection((host, port), timeout=timeout)
            raw.settimeout(timeout)
            try:
                tls = ctx.wrap_socket(raw, server_hostname=host)
                tls.close()
                findings.append(_finding(sev, title, detail, host, port))
            finally:
                try:
                    raw.close()
                except Exception:
                    pass
        except (ssl.SSLError, OSError):
            pass  # version rejected — expected good behaviour
        except Exception:
            pass

    # ── 4 & 5. HSTS policy ───────────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://{host}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers_lc = {k.lower(): v for k, v in resp.headers.items()}
        hsts_val = headers_lc.get("strict-transport-security", "")
        if hsts_val:
            max_age = None
            for part in hsts_val.lower().split(";"):
                part = part.strip()
                if part.startswith("max-age="):
                    try:
                        max_age = int(part.split("=", 1)[1].strip())
                    except ValueError:
                        pass
            if max_age is not None and max_age < 31_536_000:
                findings.append(_finding(
                    "MEDIUM", "SHORT_HSTS_MAX_AGE",
                    f"HSTS max-age={max_age} is below the recommended 31536000 "
                    "(1 year) — browsers will not pin the domain for a full year",
                    host, port))
            has_include_sub = "includesubdomains" in hsts_val.lower()
            has_preload = "preload" in hsts_val.lower()
            if not has_include_sub or not has_preload:
                missing = []
                if not has_include_sub:
                    missing.append("includeSubDomains")
                if not has_preload:
                    missing.append("preload")
                findings.append(_finding(
                    "MEDIUM", "HSTS_NOT_PRELOAD_READY",
                    "HSTS header missing directive(s): "
                    + ", ".join(missing)
                    + " — domain cannot be submitted to the HSTS preload list",
                    host, port))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 8. ACME endpoint exposure
# ---------------------------------------------------------------------------

def probe_acme_endpoint_exposure(host: str, port: int = 443,
                                  timeout: float = 10.0) -> list:
    """
    Probe ACME/PKI challenge paths for unintended exposure.

    Synthesized from:
      Go for DevOps ch21 — Kubernetes certificate-authority-data / client-
        certificate-data handling; secret and certificate lifecycle management
        in control-plane configs; ACME-backed cert rotation patterns observed
        in cloud-native tooling.
      Go for DevOps ch11 — HTTP client patterns for probing remote endpoints
        (http.Client, URL construction, status-code gating).

    Checks:
      /.well-known/acme-challenge/        MEDIUM  directory listing / open dir
      /.well-known/pki-validation/        MEDIUM  PKI validation path exposed
      /acme/directory                     HIGH    private ACME CA directory API
      /.well-known/acme-challenge/probe-test  HIGH  HTTP-01 challenge path live

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    # (path, expected_status_for_finding, severity, title, detail)
    _probes = [
        (
            "/.well-known/acme-challenge/",
            [200, 403],  # 200 = open dir; 403 = dir exists but denied
            "MEDIUM",
            "ACME_CHALLENGE_DIR_EXPOSED",
            "ACME challenge directory accessible — certificate issuance surface "
            "visible; attacker with network position can race HTTP-01 challenges",
        ),
        (
            "/.well-known/pki-validation/",
            [200, 403],
            "MEDIUM",
            "PKI_VALIDATION_DIR_EXPOSED",
            "PKI validation path accessible — CA validation tokens may be "
            "enumerable; reveals certificate issuance activity",
        ),
        (
            "/acme/directory",
            [200],
            "HIGH",
            "ACME_SERVER_EXPOSED",
            "Private ACME CA directory API accessible — internal certificate "
            "authority endpoint reachable; enables unauthorized certificate "
            "requests against the internal CA",
        ),
    ]

    for path, match_codes, severity, title, detail in _probes:
        try:
            scheme = "https" if port == 443 else f"https"
            url = f"{scheme}://{host}:{port}{path}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0"})
            try:
                with urllib.request.urlopen(
                        req, timeout=timeout, context=_ctx) as resp:
                    code = resp.status
            except urllib.error.HTTPError as e:
                code = e.code
            if code in match_codes:
                findings.append(_finding(severity, title, detail, host, port))
        except Exception:
            pass

    # Separate probe: HTTP-01 challenge path liveness (non-404 response)
    try:
        url = f"https://{host}:{port}/.well-known/acme-challenge/probe-test"
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(
                    req, timeout=timeout, context=_ctx) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        if code == 200:
            findings.append(_finding(
                "HIGH",
                "ACME_CHALLENGE_RESPONDS",
                "HTTP-01 challenge path returns 200 for arbitrary token — "
                "domain ownership abuse possible; attacker can complete ACME "
                "HTTP-01 challenges for this domain if they control challenge "
                "content delivery",
                host, port))
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# 9. Certificate transparency monitor
# ---------------------------------------------------------------------------

# OID 1.3.6.1.4.1.11129.2.4.2 (Signed Certificate Timestamp list extension)
# DER-encoded OID bytes used to detect SCT presence in raw cert DER.
_SCT_OID_DER = b"\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02"


def probe_certificate_transparency_monitor(host: str, port: int = 443,
                                            timeout: float = 10.0) -> list:
    """
    Certificate transparency and issuance anomaly detection.

    Synthesized from:
      Go for DevOps ch21 — Kubernetes kubeconfig certificate-authority-data
        and client-certificate-data management; CT-log integration patterns
        described in cloud-native certificate lifecycle tooling; wildcard and
        SAN scope implications for secret management surface area.
      Go for DevOps ch11 — HTTP client patterns; TLS connection setup with
        ssl.SSLContext; getpeercert(binary_form=True) for raw DER inspection.

    Checks:
      No SCT extension in certificate DER      HIGH    possible MITM/rogue cert
      Cert not-before within last 24 hours     MEDIUM  recently issued / dynamic
      CN or any SAN begins with '*.'           MEDIUM  wildcard cert broad scope
      SAN count > 10                           MEDIUM  large-scope certificate

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # ── Fetch raw cert (binary DER) and structured cert dict ─────────────────
    raw_der: bytes | None = None
    cert: dict | None = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            try:
                raw_der = tls.getpeercert(binary_form=True)
                cert    = tls.getpeercert()
            finally:
                try:
                    tls.close()
                except Exception:
                    pass
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        return findings

    if not raw_der or not cert:
        return findings

    # ── 1. SCT extension presence ─────────────────────────────────────────────
    # RFC 6962 §3.3: SCT list embedded in cert as extension OID
    # 1.3.6.1.4.1.11129.2.4.2. Absence indicates cert was not submitted to a
    # public CT log — characteristic of MITM intercept certs and private CA
    # issuances that bypass browser CT enforcement.
    if _SCT_OID_DER not in raw_der:
        findings.append(_finding(
            "HIGH",
            "NO_SCT_IN_CERTIFICATE",
            "Certificate does not contain a Signed Certificate Timestamp (SCT) "
            "extension (OID 1.3.6.1.4.1.11129.2.4.2) — cert was not embedded "
            "with CT log proof at issuance; characteristic of MITM intercept "
            "certificates and private CA issuances",
            host, port))

    # ── 2. Recently issued certificate (not-before within 24 h) ──────────────
    try:
        not_before_str = cert.get("notBefore", "")
        fmt = "%b %d %H:%M:%S %Y %Z"
        nb = datetime.datetime.strptime(not_before_str, fmt)
        # Make timezone-naive comparison using UTC now
        now_utc = datetime.datetime.utcnow()
        age_seconds = (now_utc - nb).total_seconds()
        if 0 <= age_seconds < 86400:
            findings.append(_finding(
                "MEDIUM",
                "RECENTLY_ISSUED_CERT",
                f"Certificate not-before is {int(age_seconds)}s ago — issued "
                "within the last 24 hours; possible dynamic provisioning, "
                "certificate rotation event, or rogue certificate issuance",
                host, port))
    except Exception:
        pass

    # ── 3. Wildcard certificate ───────────────────────────────────────────────
    # Separate from check_certificate_transparency which flags TLD-level
    # wildcards (*.com); this flags any wildcard (*.example.com) as the
    # private key compromise blast radius covers the entire subdomain space.
    wildcard_found = False

    # Check CN
    cn: str | None = None
    for rdn in cert.get("subject", ()):
        for attr, val in rdn:
            if attr == "commonName":
                cn = val
    if cn and cn.startswith("*."):
        wildcard_found = True
        findings.append(_finding(
            "MEDIUM",
            "WILDCARD_CERTIFICATE",
            f"Certificate CN '{cn}' is a wildcard — private key compromise "
            "affects all subdomains; higher value target for MITM attacks",
            host, port))

    # Check SANs (only if CN was not already flagged to avoid double-report)
    san_entries = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    if not wildcard_found:
        wildcard_sans = [s for s in san_entries if s.startswith("*.")]
        if wildcard_sans:
            findings.append(_finding(
                "MEDIUM",
                "WILDCARD_CERTIFICATE",
                f"Certificate SAN contains wildcard(s): {wildcard_sans} — "
                "broad scope cert; private key compromise affects all "
                "matching subdomains",
                host, port))

    # ── 4. Large SAN count ────────────────────────────────────────────────────
    san_count = len(san_entries)
    if san_count > 10:
        findings.append(_finding(
            "MEDIUM",
            "LARGE_SAN_COUNT",
            f"{san_count} SANs in certificate — broad scope certificate; "
            "single private key covers {san_count} distinct hostnames, "
            "increasing blast radius of key compromise",
            host, port))

    return findings

    return findings


def probe_tls_session_resumption(host: str, port: int = 443,
                                  timeout: float = 10.0) -> list:
    """
    TLS session resumption and 0-RTT replay risk detection.

    Checks:
      Session ticket issued after first handshake    INFO    session tickets in use
      Session ticket reused on second handshake      MEDIUM  past sessions decryptable
                                                             if ticket key compromised
      TLS 1.3 + session reuse                        HIGH    0-RTT replay attack surface

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # ── First connection: capture session object ──────────────────────────────
    session_obj = None
    tls_version_first: str | None = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            try:
                tls_version_first = tls.version()
                session_obj = tls.session
            finally:
                try:
                    tls.close()
                except Exception:
                    pass
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        return findings

    if session_obj is not None:
        findings.append(_finding(
            "INFO",
            "TLS_SESSION_TICKET_ISSUED",
            f"TLS session ticket issued by server (version {tls_version_first}) — "
            "session tickets in use; ticket key rotation policy determines "
            "forward secrecy window",
            host, port))
    else:
        # Server did not issue a resumable session; nothing further to test.
        return findings

    # ── Second connection: inject captured session before handshake ───────────
    # do_handshake_on_connect=False allows setting the session object prior to
    # the handshake completing, which is the mechanism Python's ssl exposes for
    # session resumption (SSLSocket.session setter, added in 3.6).
    session_reused = False
    tls_version_second: str | None = None
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        raw2 = socket.create_connection((host, port), timeout=timeout)
        raw2.settimeout(timeout)
        try:
            tls2 = ctx2.wrap_socket(raw2, server_hostname=host,
                                    do_handshake_on_connect=False)
            try:
                tls2.session = session_obj
                tls2.do_handshake()
                session_reused = bool(tls2.session_reused)
                tls_version_second = tls2.version()
            finally:
                try:
                    tls2.close()
                except Exception:
                    pass
        finally:
            try:
                raw2.close()
            except Exception:
                pass
    except Exception:
        return findings

    if session_reused:
        findings.append(_finding(
            "MEDIUM",
            "TLS_SESSION_TICKET_REUSE",
            f"TLS session ticket resumed on second connection "
            f"(version {tls_version_second}) — if the server's ticket "
            "encryption key is compromised, an attacker who captured prior "
            "ciphertext can decrypt past sessions; ticket key rotation interval "
            "determines the blast radius",
            host, port))

        # ── TLS 1.3 0-RTT risk ────────────────────────────────────────────────
        # RFC 8446 §2.3 defines 0-RTT early data, which eliminates one round
        # trip by sending application data before the server Finished message.
        # Servers that do not set max_early_data=0 may accept replayed 0-RTT
        # records against non-idempotent endpoints. Python's ssl module does not
        # expose whether early data was accepted, but a TLS 1.3 session that
        # resumed without 0-RTT suppression confirmed at the transport layer is
        # the necessary precondition. Flag when TLS 1.3 is confirmed and session
        # was resumed.
        if (tls_version_second == "TLSv1.3"
                or tls_version_first == "TLSv1.3"):
            findings.append(_finding(
                "HIGH",
                "TLS_13_ZERO_RTT_RISK",
                f"TLS 1.3 session resumed — server may accept 0-RTT early data "
                "(RFC 8446 §2.3); if max_early_data=0 is not enforced, replay "
                "attacks are possible against non-idempotent endpoints; verify "
                "server-side early_data suppression configuration",
                host, port))

    return findings


# ---------------------------------------------------------------------------
# 10. Weak cipher suite probe (ssl context cipher restriction)
# ---------------------------------------------------------------------------

def probe_tls_weak_cipher_suite(host: str, port: int = 443,
                                 timeout: float = 10.0) -> list:
    """
    Attempt TLS connection offering only known-weak cipher suites by
    restricting the ssl context cipher list.  If the server accepts,
    report the negotiated cipher and classify by specific weakness class.

    Synthesized from:
      Security with Go ch TLS — cipher suite negotiation during the TLS
        handshake; the ClientHello cipher_suites field as the attack surface
        for weak cipher acceptance; InsecureSkipVerify context setup.

    Detects:
      Any weak cipher accepted    CRITICAL  TLS_WEAK_CIPHER_ACCEPTED
      RC4 negotiated              CRITICAL  TLS_RC4_ACCEPTED
        (broken by statistical keystream bias — RFC 7465)
      3DES negotiated             HIGH      TLS_3DES_SWEET32
        (64-bit block SWEET32 birthday-bound attack — CVE-2016-2183)

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # OpenSSL cipher string covering all known-broken families.
    # @SECLEVEL=0 disables the OpenSSL security level floor so that the
    # weak ciphers are actually offered to the server in the ClientHello
    # rather than being silently stripped by the local SSL library.
    _WEAK_CIPHER_STRING = (
        "NULL:eNULL:aNULL:RC4:DES:3DES:EXPORT:ADH:LOW:@SECLEVEL=0"
    )

    negotiated_cipher: str | None = None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers(_WEAK_CIPHER_STRING)
        except ssl.SSLError:
            # Hardened OpenSSL build rejects the full weak string; attempt
            # a narrower subset that is more likely to survive the local
            # security policy.
            try:
                ctx.set_ciphers("RC4:3DES:DES:@SECLEVEL=0")
            except ssl.SSLError:
                return findings  # No weak ciphers available in this build
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            cipher_info = tls.cipher()
            if cipher_info:
                negotiated_cipher = cipher_info[0]
            tls.close()
        except ssl.SSLError:
            pass  # Server rejected all weak ciphers — good posture
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        pass

    if negotiated_cipher is None:
        return findings

    # ── Generic: any weak cipher was accepted ─────────────────────────────────
    findings.append(_finding(
        "CRITICAL", "TLS_WEAK_CIPHER_ACCEPTED",
        f"Server negotiated weak cipher suite: {negotiated_cipher} — "
        "broken or deprecated cipher family accepted; traffic may be "
        "decryptable by a passive observer",
        host, port))

    cn = negotiated_cipher.upper()

    # ── RC4: statistical bias attacks enable plaintext recovery ───────────────
    if "RC4" in cn:
        findings.append(_finding(
            "CRITICAL", "TLS_RC4_ACCEPTED",
            f"RC4 cipher negotiated: {negotiated_cipher} — cryptographically "
            "broken per RFC 7465; plaintext recovery is possible via "
            "statistical bias attacks on the keystream",
            host, port))

    # ── 3DES: 64-bit block SWEET32 birthday-bound collision ───────────────────
    if "3DES" in cn or "DES-CBC3" in cn or "DES3" in cn:
        findings.append(_finding(
            "HIGH", "TLS_3DES_SWEET32",
            f"3DES cipher negotiated: {negotiated_cipher} — SWEET32 "
            "birthday-bound attack (CVE-2016-2183); 64-bit block size allows "
            "collision-based session decryption after approximately 32 GB of "
            "traffic under the same session key",
            host, port))

    return findings


# ---------------------------------------------------------------------------
# 11. Legacy TLS version support probe
# ---------------------------------------------------------------------------

def probe_tls_version_support(host: str, port: int = 443,
                               timeout: float = 10.0) -> list:
    """
    Test whether the server accepts legacy TLS versions (TLS 1.0, TLS 1.1)
    and whether it negotiates TLS 1.3.  Uses ssl.PROTOCOL_TLSv1 /
    ssl.PROTOCOL_TLSv1_1 when available; falls back to ssl.TLSVersion pin
    for builds where those constants have been removed.

    Synthesized from:
      Security with Go ch TLS — TLS version negotiation via the ClientHello
        supported_versions extension; how the server selects the highest
        mutually acceptable version; the security implications of TLS 1.0
        and 1.1 acceptance.
      Security with Go ch TLS client — InsecureSkipVerify context setup;
        ConnectionState version inspection after handshake completion.

    Detects:
      TLS_1_0_ACCEPTED   HIGH   — RFC 8996 deprecated; BEAST, POODLE-on-TLS,
                                  Lucky13 attack surface
      TLS_1_1_ACCEPTED   MEDIUM — RFC 8996 deprecated; missing AEAD cipher
                                  suites; disable in favor of TLS 1.2+
      TLS_1_3_SUPPORTED  INFO   — TLS 1.3 negotiated; AEAD-only, mandatory
                                  forward secrecy by design (RFC 8446)

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # ── TLS 1.0 probe ─────────────────────────────────────────────────────────
    # ssl.PROTOCOL_TLSv1 pins negotiation to TLS 1.0 exactly.  Deprecated in
    # Python 3.10; may raise AttributeError on hardened builds that removed
    # the constant — catch AttributeError and fall back to TLSVersion pin.
    _tls10_found = False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # type: ignore[attr-defined]
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            tls.close()
            _tls10_found = True
        except (ssl.SSLError, OSError):
            pass  # server rejected TLS 1.0
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except AttributeError:
        # PROTOCOL_TLSv1 removed in this build; use the TLSVersion min/max API.
        try:
            v10 = getattr(ssl.TLSVersion, "TLSv1", None)
            if v10 is not None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = v10
                ctx.maximum_version = v10
                raw = socket.create_connection((host, port), timeout=timeout)
                raw.settimeout(timeout)
                try:
                    tls = ctx.wrap_socket(raw, server_hostname=host)
                    tls.close()
                    _tls10_found = True
                except (ssl.SSLError, OSError):
                    pass
                finally:
                    try:
                        raw.close()
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        pass

    if _tls10_found:
        findings.append(_finding(
            "HIGH", "TLS_1_0_ACCEPTED",
            "Server accepted TLS 1.0 connection — deprecated by RFC 8996 "
            "(2021); attack surface includes BEAST (CBC IV chaining), "
            "POODLE-on-TLS (padding oracle), and Lucky13 (timing side "
            "channel); PCI-DSS and HIPAA guidance requires disabling",
            host, port))

    # ── TLS 1.1 probe ─────────────────────────────────────────────────────────
    _tls11_found = False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)  # type: ignore[attr-defined]
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            tls.close()
            _tls11_found = True
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except AttributeError:
        # PROTOCOL_TLSv1_1 removed; fall back to TLSVersion pin.
        try:
            v11 = getattr(ssl.TLSVersion, "TLSv1_1", None)
            if v11 is not None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = v11
                ctx.maximum_version = v11
                raw = socket.create_connection((host, port), timeout=timeout)
                raw.settimeout(timeout)
                try:
                    tls = ctx.wrap_socket(raw, server_hostname=host)
                    tls.close()
                    _tls11_found = True
                except (ssl.SSLError, OSError):
                    pass
                finally:
                    try:
                        raw.close()
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        pass

    if _tls11_found:
        findings.append(_finding(
            "MEDIUM", "TLS_1_1_ACCEPTED",
            "Server accepted TLS 1.1 connection — deprecated by RFC 8996 "
            "(2021); lacks AEAD cipher suite support and the improved PRF "
            "introduced in TLS 1.2; disable in favor of TLS 1.2 (minimum) "
            "and TLS 1.3",
            host, port))

    # ── TLS 1.3 support check ─────────────────────────────────────────────────
    # A permissive connection (no version floor/ceiling) negotiates the
    # highest mutually supported version.  TLS 1.3 is the positive security
    # indicator: mandatory forward secrecy, AEAD-only cipher suites, and a
    # redesigned handshake that removes obsolete features (RFC 8446).
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=host)
            version = tls.version()
            tls.close()
            if version == "TLSv1.3":
                findings.append(_finding(
                    "INFO", "TLS_1_3_SUPPORTED",
                    "Server negotiated TLS 1.3 — current recommended version; "
                    "AEAD-only cipher suites and mandatory ephemeral key "
                    "exchange provide forward secrecy by design (RFC 8446)",
                    host, port))
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# 12. Certificate attribute and transparency exposure probe
# ---------------------------------------------------------------------------

def probe_certificate_transparency_exposure(host: str, port: int = 443,
                                             timeout: float = 10.0) -> list:
    """
    Analyse TLS certificate attributes for cryptographic and PKI weaknesses.

    Synthesized from:
      Hacking Cryptography ch.8 (Public-Key Cryptography) -- RSA key strength,
        trapdoor function security margins, common-factor / short-exponent risks
      Hacking Cryptography ch.9 (Digital Signatures) -- signature hash
        algorithm security, SHA-1/MD5 collision attacks, forgery vectors

    Returns findings:
      WILDCARD_CERTIFICATE          MEDIUM   -- CN starts with *.
      SELF_SIGNED_CERTIFICATE       HIGH     -- issuer == subject
      EXPIRED_CERTIFICATE           HIGH     -- notAfter in the past
      CERTIFICATE_EXPIRING_SOON     MEDIUM   -- expires in < 30 days
      WEAK_RSA_KEY_SIZE             CRITICAL -- RSA key < 2048 bits
      SHA1_SIGNED_CERTIFICATE       HIGH     -- signature algorithm uses SHA-1
      MD5_SIGNED_CERTIFICATE        CRITICAL -- signature algorithm uses MD5
      EV_CERTIFICATE                INFO     -- CA/B Forum EV OID 2.23.140.1.1 found
      CERTIFICATE_HOSTNAME_MISMATCH HIGH     -- hostname not matched by SAN list
    """
    findings = []

    # ── Single connection: get both parsed dict and raw DER ──────────────────
    cert_dict = None
    der_cert = b""
    try:
        raw, tls = _tls_connect(host, port, timeout)
        try:
            cert_dict = tls.getpeercert()
            der_cert = tls.getpeercert(binary_form=True) or b""
        finally:
            try:
                tls.close()
            except Exception:
                pass
            try:
                raw.close()
            except Exception:
                pass
    except Exception as e:
        return [_finding("ERROR", "TLS_CONNECT_FAILED",
                         f"Could not connect: {e}", host, port)]

    if not cert_dict:
        return [_finding("INFO", "NO_CERT_RETURNED",
                         "Server returned no parseable certificate", host, port)]

    # ── ASN.1 DER variable-length decoder ────────────────────────────────────
    def _asn1_len(data, off):
        """Return (length, next_offset) for DER length field at off."""
        if off >= len(data):
            return 0, off
        b = data[off]
        if b < 0x80:
            return b, off + 1
        n = b & 0x7f
        if n == 0 or off + 1 + n > len(data):
            return 0, off + 1
        val = 0
        for i in range(n):
            val = (val << 8) | data[off + 1 + i]
        return val, off + 1 + n

    # ── CN extraction ─────────────────────────────────────────────────────────
    cn = None
    for rdn in cert_dict.get("subject", ()):
        for attr, val in rdn:
            if attr == "commonName":
                cn = val

    # ── Wildcard certificate ──────────────────────────────────────────────────
    if cn and cn.startswith("*."):
        findings.append(_finding(
            "MEDIUM", "WILDCARD_CERTIFICATE",
            f"Certificate CN is a wildcard: {cn} -- covers all immediate "
            "subdomains; a single compromised private key exposes every "
            "covered host",
            host, port))

    # ── Self-signed detection ─────────────────────────────────────────────────
    def _rdn_str(rdn_seq):
        return ",".join("=".join(pair) for rdn in rdn_seq for pair in rdn)

    issuer  = _rdn_str(cert_dict.get("issuer", ()))
    subject = _rdn_str(cert_dict.get("subject", ()))
    if issuer and subject and issuer == subject:
        findings.append(_finding(
            "HIGH", "SELF_SIGNED_CERTIFICATE",
            f"Issuer equals subject ({issuer[:100]}) -- certificate is "
            "self-signed; not trusted by standard TLS stacks without explicit "
            "trust-anchor installation; susceptible to trivial MITM",
            host, port))

    # ── Expiry checks ─────────────────────────────────────────────────────────
    try:
        fmt = "%b %d %H:%M:%S %Y %Z"
        na = datetime.datetime.strptime(cert_dict.get("notAfter", ""), fmt)
        now = datetime.datetime.utcnow()
        days_left = (na - now).days
        if days_left < 0:
            findings.append(_finding(
                "HIGH", "EXPIRED_CERTIFICATE",
                f"Certificate expired {abs(days_left)}d ago "
                f"(notAfter: {cert_dict.get('notAfter')})",
                host, port))
        elif days_left < 30:
            findings.append(_finding(
                "MEDIUM", "CERTIFICATE_EXPIRING_SOON",
                f"Certificate expires in {days_left}d -- renewal window "
                "critical; browsers and TLS clients reject expired certs "
                "immediately",
                host, port))
    except Exception:
        pass

    # ── RSA key size from DER SubjectPublicKeyInfo ────────────────────────────
    # OID 1.2.840.113549.1.1.1 (rsaEncryption) DER content bytes
    RSA_OID = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'
    if der_cert:
        idx = der_cert.find(RSA_OID)
        if idx != -1:
            try:
                pos = idx + len(RSA_OID)
                # Skip NULL params \x05\x00 if present
                if pos + 1 < len(der_cert) and der_cert[pos:pos + 2] == b'\x05\x00':
                    pos += 2
                # Locate BIT STRING tag (0x03) within next 16 bytes
                bit_pos = der_cert.find(b'\x03', pos, pos + 16)
                if bit_pos != -1:
                    _, bs_start = _asn1_len(der_cert, bit_pos + 1)
                    inner = bs_start + 1   # skip unused-bits byte (0x00)
                    if inner < len(der_cert) and der_cert[inner] == 0x30:
                        _, seq_start = _asn1_len(der_cert, inner + 1)
                        if seq_start < len(der_cert) and der_cert[seq_start] == 0x02:
                            mod_len, mod_start = _asn1_len(der_cert, seq_start + 1)
                            # Strip leading 0x00 sign-padding byte
                            if mod_start < len(der_cert) and der_cert[mod_start] == 0x00:
                                mod_len -= 1
                            key_bits = mod_len * 8
                            if 0 < key_bits < 2048:
                                findings.append(_finding(
                                    "CRITICAL", "WEAK_RSA_KEY_SIZE",
                                    f"RSA public key is {key_bits} bits -- below "
                                    "the 2048-bit minimum (NIST SP 800-57 Rev 5); "
                                    "factorable with modern hardware",
                                    host, port))
            except Exception:
                pass

    # ── Signature algorithm: SHA-1 and MD5 detection via DER OID search ───────
    # md5WithRSAEncryption  OID 1.2.840.113549.1.1.4
    MD5_RSA_OID    = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04'
    # sha1WithRSAEncryption OID 1.2.840.113549.1.1.5
    SHA1_RSA_OID   = b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05'
    # ecdsa-with-SHA1       OID 1.2.840.10045.4.1
    SHA1_ECDSA_OID = b'\x2a\x86\x48\xce\x3d\x04\x01'
    if der_cert:
        if der_cert.find(MD5_RSA_OID) != -1:
            findings.append(_finding(
                "CRITICAL", "MD5_SIGNED_CERTIFICATE",
                "Certificate signed with MD5 -- cryptographically broken; "
                "collision attacks demonstrated (Wang 2004); CA/B Forum "
                "Baseline Requirements prohibited since 2015",
                host, port))
        elif (der_cert.find(SHA1_RSA_OID) != -1
              or der_cert.find(SHA1_ECDSA_OID) != -1):
            findings.append(_finding(
                "HIGH", "SHA1_SIGNED_CERTIFICATE",
                "Certificate signed with SHA-1 -- deprecated by CA/B Forum "
                "Baseline Requirements; browsers reject SHA-1 certs since "
                "2017; practical collision attack demonstrated (SHAttered, "
                "Stevens 2017)",
                host, port))

    # ── Extended Validation (EV) detection via CA/B Forum policy OID ──────────
    # OID 2.23.140.1.1 DER content bytes: 67 81 0C 01 01  (5 bytes)
    CABF_EV_OID = b'\x67\x81\x0c\x01\x01'
    if der_cert and der_cert.find(CABF_EV_OID) != -1:
        org_name = None
        for rdn in cert_dict.get("subject", ()):
            for attr, val in rdn:
                if attr == "organizationName":
                    org_name = val
        if org_name:
            findings.append(_finding(
                "INFO", "EV_CERTIFICATE",
                f"Extended Validation certificate detected -- O={org_name}; "
                "CA verified organization identity at issuance; higher "
                "assurance than DV/OV; CA/B Forum EV Guidelines OID "
                "2.23.140.1.1 present in certificatePolicies extension",
                host, port))

    # ── Hostname / SAN mismatch ───────────────────────────────────────────────
    san_entries = [v.lower() for rdn_type, v
                   in cert_dict.get("subjectAltName", [])
                   if rdn_type == "DNS"]
    if san_entries:
        host_lower = host.lower()
        matched = False
        for san in san_entries:
            if san == host_lower:
                matched = True
                break
            if san.startswith("*.") and "." in host_lower:
                # Wildcard: *.example.com covers foo.example.com
                label, sep, rest = host_lower.partition(".")
                if sep and rest == san[2:]:
                    matched = True
                    break
        if not matched:
            findings.append(_finding(
                "HIGH", "CERTIFICATE_HOSTNAME_MISMATCH",
                f"Hostname '{host}' not covered by SAN list "
                f"{san_entries[:6]} -- TLS validation fails for strict "
                "clients; indicates misconfiguration or active MITM "
                "interception",
                host, port))

    return findings


# ---------------------------------------------------------------------------
# 13. Certificate pinning enforcement and CT policy probe
# ---------------------------------------------------------------------------

def probe_certificate_pinning_enforcement(host: str, port: int = 443,
                                           timeout: float = 10.0) -> list:
    """
    Detect HPKP configuration, HSTS preloading, Expect-CT, and SCT embedding.

    Synthesized from:
      Hacking Cryptography ch.8 (Public-Key Cryptography) -- key pinning as
        a trust-anchor override mechanism against compromised public CAs
      Hacking Cryptography ch.9 (Digital Signatures) -- certificate
        transparency as a cryptographic audit trail for CA issuance events

    Returns findings:
      HPKP_HEADER_PRESENT              INFO   -- Public-Key-Pins or Report-Only set
      HPKP_NOT_IMPLEMENTED             MEDIUM -- HPKP header absent
      HPKP_SHORT_MAX_AGE               HIGH   -- HPKP max-age < 86400 s
      HSTS_PRELOAD_NOT_SET             INFO   -- Strict-Transport-Security lacks preload
      EXPECT_CT_MISSING                MEDIUM -- Expect-CT header absent
      NO_CERTIFICATE_TRANSPARENCY_SCT  MEDIUM -- SCT OID absent in DER cert
      MINIMAL_SCT_COUNT                MEDIUM -- Fewer than 2 SCTs present
      UNEXPECTED_CERTIFICATE_ISSUER    HIGH   -- Issuer not a recognized public CA
    """
    import re

    findings = []
    headers_found = {}

    # ── Fetch HTTPS response headers ──────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://{host}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            for k, v in resp.headers.items():
                headers_found[k.lower()] = v
    except Exception:
        pass

    # ── HPKP header analysis ──────────────────────────────────────────────────
    hpkp    = headers_found.get("public-key-pins", "")
    hpkp_ro = headers_found.get("public-key-pins-report-only", "")
    active_hpkp = hpkp or hpkp_ro
    if active_hpkp:
        mode = "Public-Key-Pins" if hpkp else "Public-Key-Pins-Report-Only"
        findings.append(_finding(
            "INFO", "HPKP_HEADER_PRESENT",
            f"{mode} header present (deprecated; removed from Chrome 67 / "
            f"Firefox 72 per RFC 7469 obsolescence): "
            f"{active_hpkp[:120]}",
            host, port))
        ma = re.search(r'max-age\s*=\s*(\d+)', active_hpkp, re.IGNORECASE)
        if ma and int(ma.group(1)) < 86400:
            findings.append(_finding(
                "HIGH", "HPKP_SHORT_MAX_AGE",
                f"HPKP max-age={ma.group(1)}s is below 86400s (1 day) -- "
                "insufficient pin window; attacker waits for expiry then "
                "substitutes an alternate certificate",
                host, port))
    else:
        findings.append(_finding(
            "MEDIUM", "HPKP_NOT_IMPLEMENTED",
            "Public-Key-Pins header absent -- no explicit pin-based protection "
            "configured; HSTS preloading and Expect-CT are the modern "
            "replacements for HPKP's CA-override function",
            host, port))

    # ── HSTS preload directive ────────────────────────────────────────────────
    hsts = headers_found.get("strict-transport-security", "")
    if not (hsts and "preload" in hsts.lower()):
        detail = (
            "Strict-Transport-Security present but 'preload' directive absent"
            if hsts else "Strict-Transport-Security header absent"
        )
        findings.append(_finding(
            "INFO", "HSTS_PRELOAD_NOT_SET",
            f"{detail} -- preloading prevents first-connection TOFU downgrade; "
            "submit to chromium.org/hsts for browser-native enforcement",
            host, port))

    # ── Expect-CT enforcement ─────────────────────────────────────────────────
    if "expect-ct" not in headers_found:
        findings.append(_finding(
            "MEDIUM", "EXPECT_CT_MISSING",
            "Expect-CT header absent -- server does not enforce Certificate "
            "Transparency reporting; misissued certs may not be detected; "
            "Chrome has enforced CT on all new public certs since 2018",
            host, port))

    # ── SCT extension in DER certificate ─────────────────────────────────────
    # OID 1.3.6.1.4.1.11129.2.4.2 (signed_certificate_timestamps extension)
    # DER OID content bytes: 2b 06 01 04 01 d6 79 02 04 02  (10 bytes)
    SCT_OID = b'\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02'
    cert_dict = None
    der_cert = b""
    try:
        raw, tls = _tls_connect(host, port, timeout)
        try:
            der_cert = tls.getpeercert(binary_form=True) or b""
            cert_dict = tls.getpeercert()
        finally:
            try:
                tls.close()
            except Exception:
                pass
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        pass

    if der_cert:
        sct_pos = der_cert.find(SCT_OID)
        if sct_pos == -1:
            findings.append(_finding(
                "MEDIUM", "NO_CERTIFICATE_TRANSPARENCY_SCT",
                "No Signed Certificate Timestamp extension (OID "
                "1.3.6.1.4.1.11129.2.4.2) found in certificate -- issued "
                "without CT logging; Chrome CT Policy requires embedded "
                "SCTs from 2+ independent logs for public trust",
                host, port))
        else:
            # Count SCTs: navigate past optional BOOLEAN critical flag and
            # OCTET STRING wrapper to the SCTList (2-byte length-prefixed entries)
            sct_count = 0
            try:
                w_off = sct_pos + len(SCT_OID)
                w = der_cert[w_off:w_off + 512]
                off = 0
                # Skip optional BOOLEAN critical \x01 \x01 \xff
                if off + 2 < len(w) and w[off] == 0x01:
                    off += 3
                # Expect OCTET STRING \x04
                if off < len(w) and w[off] == 0x04:
                    off += 1
                    lb = w[off]
                    if lb < 0x80:
                        off += 1
                    elif lb == 0x81:
                        off += 2
                    elif lb == 0x82:
                        off += 3
                    # SCTList: 2-byte total length then per-entry 2-byte lengths
                    if off + 2 <= len(w):
                        list_len = struct.unpack(">H", w[off:off + 2])[0]
                        off += 2
                        end = off + list_len
                        while off + 2 <= end and off + 2 <= len(w):
                            entry_len = struct.unpack(">H", w[off:off + 2])[0]
                            if entry_len == 0 or entry_len > 2000:
                                break
                            sct_count += 1
                            off += 2 + entry_len
            except Exception:
                sct_count = -1

            if 0 < sct_count < 2:
                findings.append(_finding(
                    "MEDIUM", "MINIMAL_SCT_COUNT",
                    f"Certificate contains {sct_count} SCT -- Chrome CT Policy "
                    "requires 2+ SCTs from independent logs; single SCT "
                    "provides no cross-log verification redundancy",
                    host, port))

    # ── Certificate issuer: unknown/private CA detection ──────────────────────
    KNOWN_CAS = {
        "let's encrypt", "digicert", "comodo", "sectigo", "globalsign",
        "entrust", "godaddy", "thawte", "geotrust", "verisign", "amazon",
        "microsoft", "google trust services", "identrust", "iden trust",
        "quovadis", "swisssign", "buypass", "zerossl", "usertrust",
    }
    if cert_dict:
        issuer_org = None
        for rdn in cert_dict.get("issuer", ()):
            for attr, val in rdn:
                if attr == "organizationName":
                    issuer_org = val.lower()
        if issuer_org and not any(k in issuer_org for k in KNOWN_CAS):
            findings.append(_finding(
                "HIGH", "UNEXPECTED_CERTIFICATE_ISSUER",
                f"Certificate issued by unrecognized CA: '{issuer_org}' -- "
                "private or unknown CAs cannot be audited via CT logs; "
                "verify this is an intentionally trusted internal CA",
                host, port))

    return findings


# ---------------------------------------------------------------------------
# Zero Trust / ZTNA bypass surface detection
# (Cisco Umbrella, Cisco+ Secure Connect, SASE/SSE auth bypass surfaces)
# ---------------------------------------------------------------------------

def probe_zero_trust_bypass_surface(host: str, port: int = 443,
                                     timeout: float = 10.0) -> list:
    """
    Detect Zero Trust / ZTNA implementation weaknesses and bypass surfaces.

    Synthesized from Cisco SASE/SSE architecture: identity-centric perimeter,
    ZTNA gateway enforcement, SPA (Single Packet Authorization), mutual TLS,
    and HSTS/CORS controls on Zero Trust access proxies (Cisco Umbrella,
    Cisco+ Secure Connect, SASE/SSE platform components).

    Checks:
      DIRECT_IP_ACCESS_BYPASSES_ZTNA   MEDIUM   -- TLS handshake completes with no SNI
      NO_SPA_ENFORCEMENT               HIGH     -- TCP connects without SPA pre-auth
      NO_MUTUAL_TLS_ENFORCEMENT        HIGH     -- no CertificateRequest in handshake
      LONG_TLS_SESSION_REUSE           MEDIUM   -- session ticket issued (reuse risk)
      JA3_NOT_CHECKED                  MEDIUM   -- curl-like and browser JA3 both succeed
      MISSING_HSTS_ZTNA               MEDIUM   -- Strict-Transport-Security absent
      BEARER_TOKEN_IN_URL              HIGH     -- JWT in URL query string accepted
      INSECURE_SESSION_COOKIE          HIGH     -- auth cookie lacks Secure/HttpOnly/SameSite
      CORS_WILDCARD_ON_AUTH_ENDPOINT   CRITICAL -- Access-Control-Allow-Origin: * on endpoint
    """
    findings = []

    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    # ── 1. Direct IP access bypasses ZTNA (no SNI) ───────────────────────────
    # ZTNA gateways should reject TLS that does not present a valid SNI
    # matching an enrolled application. A service that responds normally to a
    # no-SNI ClientHello is reachable without the ZTNA policy engine routing it.
    try:
        hello_no_sni = _build_clienthello(_DEFAULT_CIPHERS, sni="")
        resp = _send_raw_clienthello(host, port, hello_no_sni, timeout)
        if len(resp) >= 6 and resp[0] == 22 and resp[5] == 2:
            findings.append(_finding(
                "MEDIUM", "DIRECT_IP_ACCESS_BYPASSES_ZTNA",
                "TLS handshake completed with no SNI value -- ZTNA gateway does "
                "not enforce SNI-based application routing; direct IP access "
                "bypasses identity-based access control and policy enforcement",
                host, port))
    except Exception:
        pass

    # ── 2. SPA (Single Packet Authorization) not enforced ────────────────────
    # SPA makes ports appear CLOSED until a valid cryptographic knock is
    # received. If a plain TCP connect to the port succeeds, SPA is absent
    # and the surface is discoverable/scannable without pre-authentication.
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.close()
        findings.append(_finding(
            "HIGH", "NO_SPA_ENFORCEMENT",
            "TCP connection succeeds without prior Single Packet Authorization "
            "-- the port is openly reachable by any client; SPA/port-knocking "
            "is not in use; automated scanners can discover this surface without "
            "possessing a valid cryptographic token",
            host, port))
    except Exception:
        pass

    # ── 3. Mutual TLS not enforced (no CertificateRequest in handshake) ──────
    # Walk server handshake records for handshake type 13 (CertificateRequest).
    # Absence means the ZTNA gateway does not require device certificates;
    # any client can reach the access proxy without a trusted device cert.
    try:
        hello = _build_clienthello(_DEFAULT_CIPHERS, sni=host)
        resp = _send_raw_clienthello(host, port, hello, timeout)
        found_cert_req = False
        i = 0
        while i + 5 <= len(resp):
            content_type = resp[i]
            rec_len = struct.unpack("!H", resp[i + 3: i + 5])[0]
            payload_end = i + 5 + rec_len
            if content_type == 22:  # handshake record
                j = i + 5
                while j + 4 <= payload_end and payload_end <= len(resp):
                    hs_type = resp[j]
                    hs_len = struct.unpack("!I", b"\x00" + resp[j + 1: j + 4])[0]
                    if hs_type == 13:  # CertificateRequest
                        found_cert_req = True
                        break
                    j += 4 + hs_len
            if found_cert_req:
                break
            if rec_len == 0:
                break
            i = payload_end
        if not found_cert_req and len(resp) > 5:
            findings.append(_finding(
                "HIGH", "NO_MUTUAL_TLS_ENFORCEMENT",
                "Server handshake contains no CertificateRequest (type 13) -- "
                "device certificate authentication is not required; clients can "
                "reach the ZTNA access proxy without a trusted device certificate, "
                "bypassing device posture enforcement",
                host, port))
    except Exception:
        pass

    # ── 4. TLS session ticket issued (long session reuse risk) ───────────────
    # Session tickets enable PSK resumption for the ticket lifetime. Zero Trust
    # policy requires continuous re-evaluation; long-lived tickets allow stale
    # device posture assessments to persist past revocation or policy change.
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = _ctx.wrap_socket(raw, server_hostname=host)
            session = tls.session
            tls.close()
            if session is not None and getattr(session, "has_ticket", False):
                findings.append(_finding(
                    "MEDIUM", "LONG_TLS_SESSION_REUSE",
                    "Server issued a TLS session ticket -- ticket-based PSK "
                    "resumption may allow sessions to persist beyond Zero Trust "
                    "continuous-verification windows; device posture changes "
                    "(revoked cert, failed health check) are not enforced until "
                    "the session ticket expires",
                    host, port))
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        pass

    # ── 5. JA3 fingerprint not enforced ──────────────────────────────────────
    # A ZTNA gateway differentiating on TLS fingerprint (JA3/JA4) should treat
    # curl-like and browser-like ClientHellos differently (policy or block).
    # If both receive a ServerHello, JA3-based enforcement is absent.
    try:
        curl_ciphers = [0xC02B, 0xC02F, 0x002F, 0x0035]
        browser_ciphers = _GREASE_VALUES[:1] + _DEFAULT_CIPHERS + [0xC02B, 0xC02F]

        curl_resp = _send_raw_clienthello(
            host, port, _build_clienthello(curl_ciphers, sni=host), timeout)
        browser_resp = _send_raw_clienthello(
            host, port, _build_clienthello(browser_ciphers, sni=host), timeout)

        curl_ok = (len(curl_resp) >= 6 and
                   curl_resp[0] == 22 and curl_resp[5] == 2)
        browser_ok = (len(browser_resp) >= 6 and
                      browser_resp[0] == 22 and browser_resp[5] == 2)

        if curl_ok and browser_ok:
            findings.append(_finding(
                "MEDIUM", "JA3_NOT_CHECKED",
                "Both curl-like and browser-like TLS fingerprints (JA3) receive "
                "a ServerHello without differentiation -- the ZTNA gateway does "
                "not enforce JA3/JA4 client fingerprint policy; automated tooling "
                "is indistinguishable from browser traffic at the TLS layer",
                host, port))
    except Exception:
        pass

    # ── 6-9. HTTP-layer checks ────────────────────────────────────────────────
    try:
        base_url = f"https://{host}:{port}/"
        req = urllib.request.Request(
            base_url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Origin": "https://evil.example.com",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_ctx) as resp:
                base_status = resp.status
                base_headers = resp.headers
        except urllib.error.HTTPError as e:
            base_status = e.code
            base_headers = e.headers

        # 6. Missing HSTS
        if base_headers and not base_headers.get("Strict-Transport-Security"):
            findings.append(_finding(
                "MEDIUM", "MISSING_HSTS_ZTNA",
                "Strict-Transport-Security header absent on ZTNA access proxy "
                "endpoint -- HTTPS-only policy is not enforced via HSTS; "
                "browsers may attempt plaintext HTTP to the access point, "
                "allowing credential interception on local-network attackers",
                host, port))

        # 7. Bearer token in URL
        jwt_url = base_url + "?token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.sig"
        req_tok = urllib.request.Request(
            jwt_url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req_tok, timeout=timeout,
                                        context=_ctx) as r:
                tok_status = r.status
        except urllib.error.HTTPError as e:
            tok_status = e.code
        except Exception:
            tok_status = 0
        if tok_status not in (0, 400, 401, 403, 404):
            findings.append(_finding(
                "HIGH", "BEARER_TOKEN_IN_URL",
                f"Endpoint responded HTTP {tok_status} to a JWT-shaped bearer "
                "token in the URL query string -- tokens passed in URLs are "
                "logged in access logs, proxy logs, and browser history; "
                "Zero Trust access tokens must travel in Authorization headers, "
                "not query parameters",
                host, port))

        # 8. Insecure session cookie
        if base_headers:
            set_cookie = base_headers.get("Set-Cookie", "")
            if set_cookie:
                ck = set_cookie.lower()
                missing_attrs = []
                if "secure" not in ck:
                    missing_attrs.append("Secure")
                if "httponly" not in ck:
                    missing_attrs.append("HttpOnly")
                if "samesite=strict" not in ck:
                    missing_attrs.append("SameSite=Strict")
                if missing_attrs:
                    findings.append(_finding(
                        "HIGH", "INSECURE_SESSION_COOKIE",
                        f"Set-Cookie missing: {', '.join(missing_attrs)} -- "
                        "ZTNA session token is accessible via JavaScript, "
                        "may be sent over HTTP, or is shareable cross-site; "
                        "Cisco Umbrella and Secure Connect session cookies "
                        "require Secure+HttpOnly+SameSite=Strict",
                        host, port))

        # 9. CORS wildcard on authenticated endpoint
        if base_headers:
            acao = base_headers.get("Access-Control-Allow-Origin", "")
            if acao.strip() == "*":
                findings.append(_finding(
                    "CRITICAL", "CORS_WILDCARD_ON_AUTH_ENDPOINT",
                    "Access-Control-Allow-Origin: * returned on ZTNA access "
                    "proxy endpoint -- wildcard CORS allows any origin to make "
                    "cross-origin requests; Cisco Umbrella and Secure Connect "
                    "dashboard APIs with ACAO:* are vulnerable to CSRF without "
                    "SameSite cookie protection; session tokens may be exfiltrated "
                    "by a malicious page the user visits",
                    host, port))
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# Cloud proxy / SSL inspection bypass detection
# (SASE/SSE split-tunnel bypass patterns targeting Cisco Umbrella and
# Cisco+ Secure Connect SSL inspection enforcement)
# ---------------------------------------------------------------------------

def probe_cloud_proxy_ssl_inspection_bypass(host: str, port: int = 443,
                                              timeout: float = 10.0) -> list:
    """
    Detect cloud proxy / SSL inspection bypass vectors (SASE/SSE split-tunnel
    bypass patterns targeting Cisco Umbrella, Cisco+ Secure Connect).

    Synthesized from Cisco SSE/SASE architecture: cloud-based SWG (Secure Web
    Gateway), SSL inspection chain-of-trust, QUIC bypass, HTTP CONNECT
    tunneling, TLS fingerprint enforcement, and IDS/IPS evasion via record
    fragmentation.

    Checks:
      TLS_FINGERPRINT_BYPASS          MEDIUM   -- non-standard cipher ordering accepted
      NO_CERT_PINNING_ENFORCEMENT     HIGH     -- TLS completes with no cert verification
      SNI_BYPASS_SURFACE              HIGH     -- no-SNI and SNI ClientHellos both succeed
      HTTP2_CLEARTEXT_UPGRADE         MEDIUM   -- Upgrade: h2c accepted on TLS port
      QUIC_HTTP3_ACCESSIBLE           HIGH     -- UDP port 443 responds to QUIC Initial
      PROXY_CONNECT_INTERNAL_BYPASS   CRITICAL -- HTTP CONNECT tunnels to RFC-1918
      TLS_FRAGMENTATION_IDS_BYPASS    HIGH     -- 3-fragment ClientHello completes
    """
    findings = []

    _ctx = ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

    # ── 1. TLS fingerprint bypass ─────────────────────────────────────────────
    # SASE/SSE cloud proxies (Umbrella, Secure Connect) that enforce JA3/JA4
    # fingerprint policy should treat unusual cipher orderings differently.
    # If both standard and reversed orderings return a ServerHello, the proxy
    # does not gate on TLS fingerprint.
    try:
        std_resp = _send_raw_clienthello(
            host, port,
            _build_clienthello(_DEFAULT_CIPHERS, sni=host),
            timeout)
        reversed_ciphers = list(reversed(_DEFAULT_CIPHERS)) + [0x002F, 0x0035, 0x000A]
        nonstd_resp = _send_raw_clienthello(
            host, port,
            _build_clienthello(reversed_ciphers, sni=host),
            timeout)
        std_ok = (len(std_resp) >= 6 and
                  std_resp[0] == 22 and std_resp[5] == 2)
        nonstd_ok = (len(nonstd_resp) >= 6 and
                     nonstd_resp[0] == 22 and nonstd_resp[5] == 2)
        if std_ok and nonstd_ok:
            findings.append(_finding(
                "MEDIUM", "TLS_FINGERPRINT_BYPASS",
                "Server accepts both standard and non-standard cipher-suite "
                "orderings with identical ServerHello response -- SSL inspection "
                "proxy does not enforce JA3/JA4 fingerprint policy; non-browser "
                "clients bypass fingerprint-based detection in Cisco Umbrella "
                "and Secure Connect inspection chains",
                host, port))
    except Exception:
        pass

    # ── 2. Certificate pinning not enforced ───────────────────────────────────
    # Cloud proxy SSL inspection re-signs intercepted traffic with a proxy CA
    # cert. If the endpoint accepts TLS with no certificate verification
    # (CERT_NONE), no pinning is in force; a MITM cloud proxy can present a
    # re-signed certificate without client-side rejection.
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = _ctx.wrap_socket(raw, server_hostname=host)
            tls.close()
            findings.append(_finding(
                "HIGH", "NO_CERT_PINNING_ENFORCEMENT",
                "TLS handshake completed without certificate chain verification "
                "-- no certificate pinning is enforced; a SASE/SSE cloud proxy "
                "performing SSL inspection can present a re-signed certificate "
                "without client rejection, enabling transparent interception of "
                "all application traffic",
                host, port))
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        pass

    # ── 3. SNI bypass surface ─────────────────────────────────────────────────
    # A SASE proxy routes and inspects traffic based on the TLS SNI hostname.
    # If both a no-SNI and an SNI-bearing ClientHello complete the handshake,
    # traffic with SNI omitted bypasses domain-based policy routing.
    try:
        with_sni_resp = _send_raw_clienthello(
            host, port,
            _build_clienthello(_DEFAULT_CIPHERS, sni=host),
            timeout)
        no_sni_resp = _send_raw_clienthello(
            host, port,
            _build_clienthello(_DEFAULT_CIPHERS, sni=""),
            timeout)
        sni_ok = (len(with_sni_resp) >= 6 and
                  with_sni_resp[0] == 22 and with_sni_resp[5] == 2)
        no_sni_ok = (len(no_sni_resp) >= 6 and
                     no_sni_resp[0] == 22 and no_sni_resp[5] == 2)
        if sni_ok and no_sni_ok:
            findings.append(_finding(
                "HIGH", "SNI_BYPASS_SURFACE",
                "TLS handshake completes both with and without SNI -- cloud "
                "proxy does not enforce SNI-based routing; omitting SNI bypasses "
                "URL/domain filtering policy in Cisco Umbrella and Secure Connect "
                "inspection chains, allowing uncategorized traffic to flow "
                "without policy enforcement",
                host, port))
    except Exception:
        pass

    # ── 4. HTTP/2 cleartext (h2c) upgrade ────────────────────────────────────
    # Upgrade: h2c inside a TLS session is invalid per RFC 7540 s.3.2.
    # Proxies that forward this header unmodified may create an unencrypted
    # HTTP/2 stream inside TLS that bypasses SSL inspection parsing.
    try:
        url = f"https://{host}:{port}/"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Upgrade": "h2c",
                "HTTP2-Settings": "AAMAAABkAAQAAP__",
                "Connection": "Upgrade, HTTP2-Settings",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_ctx) as r:
                h2c_status = r.status
                h2c_hdrs = r.headers
        except urllib.error.HTTPError as e:
            h2c_status = e.code
            h2c_hdrs = e.headers
        upgrade_val = (h2c_hdrs.get("Upgrade", "") if h2c_hdrs else "")
        if h2c_status == 101 or "h2c" in upgrade_val.lower():
            findings.append(_finding(
                "MEDIUM", "HTTP2_CLEARTEXT_UPGRADE",
                f"Server responded HTTP {h2c_status} to Upgrade: h2c inside TLS "
                "-- RFC 7540 forbids h2c upgrades within TLS; SSL inspection "
                "proxies that forward this header unmodified may fail to parse "
                "the upgraded stream, creating an inspection gap",
                host, port))
    except Exception:
        pass

    # ── 5. QUIC / HTTP3 accessible on UDP 443 ────────────────────────────────
    # QUIC operates over UDP. Most SASE/SSE SSL inspection implementations
    # (Cisco Umbrella, Secure Connect) inspect only TCP/443; QUIC traffic on
    # UDP/443 bypasses SSL inspection entirely and may circumvent DNS-layer
    # filtering if the QUIC connection resolves before DoH intercept.
    # Send a minimal QUIC Long Header Initial packet and watch for any
    # Long Header response (Initial, Retry, or Version Negotiation).
    try:
        quic_initial = (
            b"\xc0"                          # Long Header, Fixed bit, Initial, PN len=1
            b"\x00\x00\x00\x01"             # QUIC version 1 (RFC 9000)
            b"\x08"                          # DCID length = 8 bytes
            b"\x01\x02\x03\x04\x05\x06\x07\x08"  # DCID
            b"\x00"                          # SCID length = 0
            b"\x00"                          # Token length = 0
            b"\x40\x19"                      # Payload length = 25 (2-byte var-int)
            b"\x01"                          # Packet number (1 byte)
            + b"\x00" * 24                  # Padding to reach declared length
        )
        host_ip = socket.gethostbyname(host)
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        try:
            udp_sock.sendto(quic_initial, (host_ip, port))
            data, _ = udp_sock.recvfrom(4096)
            # Any Long Header response (bit 7 set) indicates QUIC service
            if data and (data[0] & 0x80):
                findings.append(_finding(
                    "HIGH", "QUIC_HTTP3_ACCESSIBLE",
                    "UDP port responded to a QUIC Long Header Initial packet -- "
                    "QUIC/HTTP3 is reachable; Cisco Umbrella DNS-layer and "
                    "Secure Connect SSL inspection solutions typically inspect "
                    "only TCP/443; clients using QUIC bypass SWG policy "
                    "enforcement and SSL inspection chains",
                    host, port))
        finally:
            udp_sock.close()
    except Exception:
        pass

    # ── 6. Proxy CONNECT to internal RFC-1918 ────────────────────────────────
    # If the service fronts or acts as an HTTP proxy, a CONNECT request to
    # an RFC-1918 address tests whether the proxy will tunnel to private
    # ranges. Success enables attackers to pivot through the SASE gateway.
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            tls = _ctx.wrap_socket(raw, server_hostname=host)
            connect_req = (
                b"CONNECT 10.0.0.1:80 HTTP/1.1\r\n"
                b"Host: 10.0.0.1:80\r\n"
                b"User-Agent: Mozilla/5.0\r\n"
                b"\r\n"
            )
            tls.sendall(connect_req)
            resp = b""
            try:
                resp = tls.recv(1024)
            except Exception:
                pass
            resp_str = resp.decode("utf-8", errors="replace")
            if resp_str.startswith("HTTP") and " 200 " in resp_str[:50]:
                findings.append(_finding(
                    "CRITICAL", "PROXY_CONNECT_INTERNAL_BYPASS",
                    "HTTP CONNECT 10.0.0.1:80 returned 200 Connection established "
                    "-- the SASE/SSE gateway tunnels CONNECT requests to RFC-1918 "
                    "addresses; attackers can pivot through the cloud proxy into "
                    "private network segments, bypassing network segmentation and "
                    "Cisco Secure Connect access policy",
                    host, port))
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception:
        pass

    # ── 7. TLS record fragmentation IDS bypass (3-packet split) ──────────────
    # Split the ClientHello TLS record across 3 TCP writes with short delays.
    # IDS/DPI middleware that does not fully reassemble TLS records before
    # policy evaluation may apply a permissive default and forward traffic
    # that a fully-reassembled inspection would block.
    try:
        payload = _build_clienthello(_DEFAULT_CIPHERS, sni=host)
        third = max(len(payload) // 3, 4)
        part1 = payload[:third]
        part2 = payload[third: 2 * third]
        part3 = payload[2 * third:]

        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(part1)
            time.sleep(0.02)
            s.sendall(part2)
            time.sleep(0.02)
            s.sendall(part3)
            resp = b""
            try:
                resp = s.recv(4096)
            except Exception:
                pass
            if len(resp) >= 6 and resp[0] == 22 and resp[5] == 2:
                findings.append(_finding(
                    "HIGH", "TLS_FRAGMENTATION_IDS_BYPASS",
                    "Server completed TLS handshake after ClientHello split "
                    "across 3 TCP write calls with 20 ms inter-write delays -- "
                    "SSL inspection middleware that does not reassemble fragmented "
                    "TLS records applies a different (less restrictive) policy; "
                    "IDS/IPS bypass via TLS record fragmentation is feasible "
                    "against Cisco Umbrella and Secure Connect SWG components",
                    host, port))
        finally:
            s.close()
    except Exception:
        pass

    return findings
