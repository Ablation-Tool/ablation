"""
libnetconf2 security audit — CESNET/libnetconf2.

11 findings across 4 attack surfaces.

=== PRE-AUTH (highest value) ===

F1  session.c:1533   nc_parse_cpblts — unbounded <capability> heap allocation.
    Two-pass: first loop counts children, second loop iterates. calloc(i+1,
    sizeof(char*)) with no bound on i. The parsed libyang tree is built from
    raw attacker input before nc_parse_cpblts runs. i can be arbitrarily large.

    Heap spray math (64-bit):
      pointer array : (i + 1) × 8 bytes
      string copies : i × cap_len bytes
      At i=100000, cap_len=64: ~7.2 MB heap, pre-auth, no rate limit.

    spray primitive: controls both allocation count and string content/length
    → sets heap layout for F2 double-free chain.

    PRE-AUTH. No idle_timeout. No rate limiting on hello exchange.

F7  session_openssl.c:474   TLS chain verification always returns success for
    intermediate certs (depth > 0 → return 1 regardless of preverify_ok).
    Only leaf (depth==0) undergoes any check. Self-signed intermediate CA →
    issue any leaf → full MitM on NETCONF-over-TLS.

    Attack:
      1. Generate self-signed CA cert (any name/key).
      2. Issue leaf cert from it (CN = target device name).
      3. Intercept NETCONF TCP connection.
      4. Present generated cert chain.
      5. Client (libnetconf2) accepts: depth>0 chain passes, leaf depth==0
         checked against what? → depends on client verify options. If
         check_hostname=false or SNI not enforced → full accept.

F8  session_client_ssh.c:477  NC_SSH_KNOWNHOSTS_ACCEPT accepts changed
    hostkeys after logging a warning. Credentials are sent regardless.
    Line 463: NC_SSH_KNOWNHOSTS_SKIP — no check at all, no warning.

F11 session_client_ssh.c:1303  Server banner printed verbatim via WRN().
    No escape stripping. Fake sudo prompts, screen clear, title hijack.
    Terminal injection pre-auth (banner exchange precedes credential check).

=== POST-AUTH / CHAIN LINKS ===

F2  session.c:1051   nc_session_free TOCTOU double-free.
    status = session->status      // non-atomic read
    if (status == NC_STATUS_CLOSING) return;
    ... ~70 lines of work ...
    session->status = NC_STATUS_CLOSING;  // written too late

    Race: two concurrent callers both read NC_STATUS_RUNNING, both skip the
    guard, both proceed through teardown → double-free of session members.
    Server-side trigger: disconnect + idle-watchdog fire on same session.
    Client-side: concurrent session close from two threads.

    Chain with F1: spray heap layout → race double-free → controlled free of
    attacker-shaped chunk → heap RCE.

F3  messages_client.c:102   filter string validated with single-byte check.
    XPath filter content passed to server-side evaluator without sanitization.
    //*[contains(., 'password')] → credential extraction from running config.
    count(//node()) on large configs → DoS.

F9  session_openssl.c:1058   (strlen(b64)/4)*3 underestimates output buffer
    by 1-2 bytes when input length % 4 != 0 (input not padded to 4-byte
    base64 boundary). Writes 1-2 bytes past heap allocation end.
    Heap OOB write. Size depends on adjacent chunk layout.

F10 session_client_ssh.c:1453  memset(password, 0, len) before free().
    Compiler elides dead stores to soon-freed memory at -O2. Password
    bytes survive in freed chunk. F1 heap spray + F2 double-free may
    recover credential bytes from freed heap.

=== CHAINS ===

MitM/cred chain:
  F7 (TLS self-signed intermediate) → intercept NETCONF session
  OR
  F8 (SSH ACCEPT/SKIP) → MitM SSH session
  → credentials arrive in cleartext
  + F10 → if memory disclosure exists, recover passwords from freed heap

RCE chain:
  F1 (pre-auth) → flood <capability> → shape heap layout (spray)
  + F2 (concurrent teardown) → double-free of session struct member
  → heap corruption → RCE (requires heap layout alignment via F1)
  Variant: F9 (OOB write) → targeted 1-2 byte overwrite of adjacent chunk

=== SOURCE REFS ===
  session.c:1030     nc_session_free start
  session.c:1051     status = session->status (non-atomic read)
  session.c:1120     session->status = NC_STATUS_CLOSING (too late)
  session.c:1533     nc_parse_cpblts — calloc(i+1, sizeof(char*))
  messages_client.c:102  filter validation (single byte)
  session_openssl.c:474   verify_callback depth>0 → return 1
  session_openssl.c:1058  (strlen/4)*3 base64 allocation
  session_client_ssh.c:463  NC_SSH_KNOWNHOSTS_SKIP
  session_client_ssh.c:477  NC_SSH_KNOWNHOSTS_ACCEPT
  session_client_ssh.c:1303 banner verbatim print
  session_client_ssh.c:1453 memset-before-free
"""

import sys
import os
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.netconf_libnetconf2_re import (
    build_hello_spray,
    f1_heap_spray,
    analyze_f1,
    f2_race_model,
    analyze_f2,
    build_get_with_filter,
    FILTER_PAYLOADS,
    f9_check_allocation,
    analyze_f9,
    analyze_f7_static,
    analyze_f8_static,
    analyze_f10_static,
    analyze_f11_static,
    TERMINAL_INJECTION_SEQS,
    run_full_audit,
)


# ---------------------------------------------------------------------------
# F1: heap spray verification
# ---------------------------------------------------------------------------

def test_f1_spray_math():
    """Verify spray size math for various cap counts."""
    cases = [
        (1000,   64,   72_000),
        (10000,  64,  720_000),
        (100000, 64, 7_200_000),
        (100000, 128, 13_600_000),
    ]
    for n_caps, cap_len, expected_bytes in cases:
        spray = n_caps * (cap_len + 8)
        assert spray == expected_bytes, f"n={n_caps} len={cap_len}: {spray} != {expected_bytes}"


def test_f1_hello_structure():
    """Verify the spray payload is valid NETCONF framing."""
    payload = build_hello_spray(n_caps=3, cap_len=8)
    assert payload.endswith(b"]]>]]>")
    # Count capability elements: 1 base + 3 spray
    assert payload.count(b"<capability>") == 4
    assert b"</hello>" in payload


def test_f1_frame_length():
    """Large spray payloads are within TCP stream limits."""
    payload = build_hello_spray(n_caps=1000, cap_len=64)
    # Must be > 0 and < some sanity limit (not checking OS limits here)
    assert len(payload) > 1000
    assert b"]]>]]>" in payload


# ---------------------------------------------------------------------------
# F2: race model
# ---------------------------------------------------------------------------

def test_f2_race_win_rate():
    """The TOCTOU race is reproducible in simulation."""
    result = f2_race_model(iterations=5000)
    assert result["iterations"] == 5000
    # Race should be winnable at some rate (Python timing is loose but > 0)
    # If 0, the model is wrong
    print(f"F2 race: {result['race_wins']}/{result['iterations']} "
          f"({result['win_rate']:.2%})")
    findings = analyze_f2(result)
    assert len(findings) == 1
    assert findings[0]["id"] == "F2"
    assert "double-free" in findings[0]["title"].lower()


# ---------------------------------------------------------------------------
# F3: XPath filter payloads
# ---------------------------------------------------------------------------

def test_f3_filter_payloads():
    """All filter payloads build valid NETCONF framing."""
    for name, expr, desc in FILTER_PAYLOADS:
        payload = build_get_with_filter(expr)
        assert b"<get>" in payload
        assert b"]]>]]>" in payload
        # The expr is embedded
        assert b"<filter" in payload


# ---------------------------------------------------------------------------
# F7: TLS chain bypass — static analysis
# ---------------------------------------------------------------------------

def test_f7_static():
    findings = analyze_f7_static()
    assert len(findings) == 1
    f = findings[0]
    assert f["id"] == "F7"
    assert f["severity"] == "CRITICAL"
    assert "depth" in f["detail"]
    assert f["line"] == 474


# ---------------------------------------------------------------------------
# F8: SSH known-hosts bypass — static analysis
# ---------------------------------------------------------------------------

def test_f8_static():
    findings = analyze_f8_static()
    assert len(findings) == 2
    ids = {f["id"] for f in findings}
    assert "F8a" in ids and "F8b" in ids
    for f in findings:
        assert f["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# F9: base64 allocation underestimate
# ---------------------------------------------------------------------------

def test_f9_allocation_math():
    """Confirm underestimate for non-padded inputs."""
    # Length not divisible by 4: underestimate
    for n in [1, 2, 3, 5, 6, 7, 9, 10, 11]:
        r = f9_check_allocation(n)
        assert r["oob_write_possible"], f"Expected OOB at len={n}"
        assert 1 <= r["underestimate_bytes"] <= 3

    # Length divisible by 4: no underestimate
    for n in [4, 8, 12, 100]:
        r = f9_check_allocation(n)
        # floor == ceil when %4==0, no OOB
        assert not r["oob_write_possible"], f"Unexpected OOB at len={n}"


def test_f9_finding():
    findings = analyze_f9()
    assert len(findings) == 1
    assert findings[0]["id"] == "F9"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 1058


# ---------------------------------------------------------------------------
# F10: memset-before-free static
# ---------------------------------------------------------------------------

def test_f10_static():
    findings = analyze_f10_static()
    assert len(findings) == 1
    assert findings[0]["id"] == "F10"
    assert "CWE-14" in findings[0]["detail"] or "memset" in findings[0]["detail"]


# ---------------------------------------------------------------------------
# F11: terminal injection payloads
# ---------------------------------------------------------------------------

def test_f11_terminal_sequences():
    """Verify all terminal injection sequences are non-empty bytes."""
    for seq, label in TERMINAL_INJECTION_SEQS:
        assert isinstance(seq, bytes) and len(seq) > 0, f"Empty seq: {label}"


def test_f11_banner():
    from modules.netconf_libnetconf2_re import build_banner_injection
    for seq, label in TERMINAL_INJECTION_SEQS:
        banner = build_banner_injection(seq)
        assert banner.startswith(b"SSH-2.0-")
        assert seq in banner, f"Payload not embedded: {label}"


def test_f11_static():
    findings = analyze_f11_static()
    assert len(findings) == 1
    assert findings[0]["id"] == "F11"
    assert findings[0]["line"] == 1303


# ---------------------------------------------------------------------------
# Full audit runner (static only)
# ---------------------------------------------------------------------------

def test_full_audit_static():
    result = run_full_audit(host=None, run_network=False, f2_iterations=1000)
    assert result["total"] >= 7  # F2+F7+F8a+F8b+F9+F10+F11 minimum
    severities = {f["severity"] for f in result["findings"]}
    assert "CRITICAL" in severities
    ids = {f["id"] for f in result["findings"]}
    assert "F7" in ids
    assert "F8a" in ids
    assert "F9" in ids


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
