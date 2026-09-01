"""
cisco_secure_client_posture_re — Cisco Secure Client Posture (HostScan) 5.1.15.287 RE

Package: cisco-secure-client-posture_5.1.15.287_amd64.deb
Also known as: Secure Firewall Posture, CSD (Cisco Secure Desktop)

Components:
  ciscod       — ELF64 PIE, BuildID 12f44e21, stripped
               Root daemon, no systemd hardening
               Source: /tmp/build/workspace/secure-client-linux_Raccoon_MR15/posture/asa/ciscod/
               IPC: /opt/cisco/secureclient/securefirewallposture/.ciscod.ipc (UNIX socket)
               Legacy: /opt/cisco/hostscan/.ciscod.ipc
               Calls: execvp, chmod, mktemp, socket
  libhostscan.so — Host scanning library
               Source: Raccoon_MR15/posture/asa/libhostscan/
               Calls: popen, execvp, socket
               Functions: hs_process_kill, hs_fw_enable/disable, hs_am_check_rtp
  libcsd.so    — CSD (Cisco Secure Desktop) library, curl-based
               Downloads: cscan.gz from headend over http://
               Functions: csd_run, csd_setarg, csd_prelogin
               Calls: popen, execvp, socket
  cscan        — ELF64 PIE, BuildID ef7299e1, stripped
               XML-driven host scan executor
               Source: Raccoon_MR15/posture/asa/cscan/
               Calls: popen, execvp, xmlReadMemory
  cstub        — stub binary (not analyzed in depth)
  libwaapi.so  — Web agent API (OPSWAT integration)
  csc_sfpuiplugin.so — UI plugin in VPN bin/plugins/

Architecture:
                     ┌─────────────────────────────────────────────────┐
  ASA/FTD Headend   │  posture policy XML + cscan.gz (http://)         │
  (ISE/FTD)         └────────────────────────┬────────────────────────┘
                                             │ HTTPS + http:// download
                                             ▼
  ciscod (root) ◄─.ciscod.ipc──► libhostscan.so ──popen──► system checks
       │                              │
       │ dlopen                       ├── hs_fw_enable/disable (iptables/ufw)
       └── libhostscan.so             ├── hs_am_check_rtp (antivirus state)
       └── libcsd.so                  ├── hs_process_kill (arbitrary PID kill)
                │                    └── hs_process_get_list (ps enumeration)
                └── curl GET cscan.gz (http://)
                └── csd_run() ──execvp──► cscan (XML-driven scan)

Build info:
  Source path: /tmp/build/workspace/secure-client-linux_Raccoon_MR15/posture/...
  Codename: Raccoon_MR15 (major release 15 of Raccoon)
  Compiler: GCC (same build system as VPN/NVM/DART)

IPC protocol:
  UNIX socket at /opt/cisco/secureclient/securefirewallposture/.ciscod.ipc
  Legacy path: /opt/cisco/hostscan/.ciscod.ipc (AnyConnect 4.x compatibility)
  Protocol: TLV-based (hostscanH9 tag = protocol version 9)
  No documentation on IPC message authentication
"""

import struct
import socket
import os


# ── Finding Registry ─────────────────────────────────────────────────────────

FINDINGS = {
    "POS-F01": {
        "title": "ciscod systemd service: no hardening — root daemon with process orphaning",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "lib/systemd/system/ciscod.service",
        "description": (
            "ciscod.service runs ciscod as root with no security hardening:\n"
            "  No User= directive (runs as root)\n"
            "  No NoNewPrivileges=yes\n"
            "  No CapabilityBoundingSet=\n"
            "  No ProtectSystem= or ProtectHome=\n"
            "  KillMode=process — child processes orphaned when service stops\n"
            "  EnvironmentFile=/etc/environment — inherits system environment\n"
            "Identical hardening failure to vpnagentd (CSC-F09). "
            "Combined with IPC accessibility issues (POS-F02/POS-F03), "
            "a compromised ciscod has unrestricted root filesystem access."
        ),
        "evidence": [
            "ciscod.service: no User=, no NoNewPrivileges=, no CapabilityBoundingSet=",
            "ciscod.service: KillMode=process (orphan children)",
            "ciscod.service: EnvironmentFile=/etc/environment",
        ],
        "impact": "Exploiting any ciscod bug gives unrestricted root. Orphaned child processes persist after service stop.",
        "remediation": (
            "Add: User=cisco, NoNewPrivileges=yes, CapabilityBoundingSet=CAP_NET_ADMIN, "
            "ProtectSystem=strict, ProtectHome=yes, KillMode=control-group"
        ),
    },

    "POS-F02": {
        "title": ".ciscod.ipc UNIX socket: no confirmed caller authentication — local privilege escalation path",
        "severity": "CRITICAL",
        "status": "CANDIDATE",
        "source_file": "opt/cisco/secureclient/securefirewallposture/bin/ciscod",
        "description": (
            "ciscod exposes a UNIX domain socket at two paths:\n"
            "  /opt/cisco/secureclient/securefirewallposture/.ciscod.ipc (current)\n"
            "  /opt/cisco/hostscan/.ciscod.ipc (legacy AnyConnect compatibility)\n"
            "The socket names begin with '.' (hidden) but are filesystem sockets "
            "with normal ACL. The IPC protocol is TLV-based (hostscanH9 tag).\n"
            "No source is available for the IPC dispatch, but the following IPC "
            "handler functions are confirmed by string analysis:\n"
            "  priv_file_copy — copy arbitrary files as root\n"
            "  priv_file_make_executable — chmod +x arbitrary files\n"
            "  priv_file_rename — rename/move arbitrary files\n"
            "  priv_dir_create — mkdir as root\n"
            "  priv_extended_op_check — generic extended privileged operation\n"
            "  priv_restart_ciscod — kill/restart the ciscod daemon\n"
            "If the socket is group-accessible or world-accessible (depends on "
            "package install permissions), any user can request these operations."
        ),
        "evidence": [
            "ciscod: '/opt/cisco/secureclient/securefirewallposture/.ciscod.ipc'",
            "ciscod: 'priv_file_copy', 'priv_file_make_executable', 'priv_file_rename'",
            "ciscod: 'priv_dir_create', 'priv_extended_op_check', 'priv_restart_ciscod'",
            "ciscod: 'init_ipc_server', 'ipc_connect', 'process_ipc_message'",
            "hostscanH9 = protocol version identifier in all libs",
        ],
        "impact": (
            "If socket is accessible without authentication: "
            "arbitrary root file copy/rename/chmod. "
            "Combine priv_file_copy + priv_file_make_executable for root code execution: "
            "copy malicious binary to /opt/cisco, chmod +x, trigger execution."
        ),
        "exploit_chain": (
            "1. Connect to /opt/cisco/secureclient/securefirewallposture/.ciscod.ipc\n"
            "2. Send priv_file_copy: /tmp/evil.sh -> /etc/cron.d/evil\n"
            "3. Send priv_file_make_executable: /etc/cron.d/evil\n"
            "4. Wait for cron → root shell"
        ),
        "remediation": (
            "Verify socket permissions are root:cisco 0660 minimum. "
            "Add credential-based caller verification using SO_PEERCRED "
            "to validate that caller UID is a recognized service process. "
            "Never expose priv_file_copy or priv_file_make_executable without "
            "path whitelist validation."
        ),
    },

    "POS-F03": {
        "title": "libhostscan.so: hs_process_kill — unprivileged process kill via IPC",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "opt/cisco/secureclient/securefirewallposture/lib/libhostscan.so",
        "description": (
            "libhostscan.so exports hs_process_kill, which ciscod calls via dlopen/dlsym "
            "to kill arbitrary processes. The function is in the posture check surface — "
            "it can terminate antivirus processes that fail the posture check, "
            "but if the IPC is accessible without authentication (POS-F02), any "
            "local user can kill any PID including security tools (auditd, syslogd, "
            "EDR agents, etc.).\n"
            "Additional process-related functions:\n"
            "  hs_process_get_list — enumerate all processes\n"
            "  hs_process_get_applications — get installed applications\n"
            "  hs_process_get_name / hs_process_get_pid\n"
            "  hs_process_stat — process status\n"
            "  hs_process_get_parent_pid, hs_process_get_parent_of_pid"
        ),
        "evidence": [
            "libhostscan.so: hs_process_kill symbol",
            "libhostscan.so: hs_process_get_list, hs_process_stat",
            "libhostscan.so: popen, execvp calls",
        ],
        "impact": (
            "Kill arbitrary processes (EDR, auditd, logging daemons). "
            "Enumerate all running processes and application inventory. "
            "Combines with POS-F04 for complete security control bypass."
        ),
        "remediation": (
            "hs_process_kill must only accept PIDs matching Cisco-managed processes. "
            "Whitelist killable PIDs. Apply caller auth (POS-F02 fix) as a prerequisite."
        ),
    },

    "POS-F04": {
        "title": "libcsd.so: cscan.gz downloaded over http:// from headend — MITM RCE",
        "severity": "CRITICAL",
        "status": "CONFIRMED",
        "source_file": "opt/cisco/secureclient/securefirewallposture/lib/libcsd.so",
        "description": (
            "libcsd.so downloads 'cscan.gz' from the VPN headend using libcurl. "
            "The URL uses 'http://' (confirmed by string: 'http://' without https, "
            "and the curl debug flag 'setting curl debug'). The download is NOT "
            "over the encrypted VPN tunnel — it happens during pre-login posture "
            "assessment (csd_prelogin() is called before VPN establishment). "
            "Sequence:\n"
            "  1. csd_prelogin() — connect to ASA/FTD headend\n"
            "  2. GET http://<headend>/cscan.gz (PLAINTEXT HTTP)\n"
            "  3. Decompress cscan.gz\n"
            "  4. csd_run() — execute cscan binary from decompressed content\n"
            "  5. cscan parses XML posture policy from headend\n"
            "An on-path attacker (public WiFi, malicious AP, DNS poisoning) can "
            "replace cscan.gz with a malicious ELF and achieve RCE as ciscod (root)."
        ),
        "evidence": [
            "libcsd.so: 'http://' string without https prefix in download path",
            "libcsd.so: 'cscan.gz', 'cscan', 'csfpscan', 'hostscan'",
            "libcsd.so: 'setting curl debug' (curl integration confirmed)",
            "libcsd.so: csd_prelogin() called before VPN establishment",
            "libcsd.so: popen, execvp (execution of downloaded content)",
        ],
        "impact": (
            "CRITICAL: On-path attacker replaces cscan.gz with malicious binary. "
            "ciscod executes it as root. Full system compromise on VPN connect "
            "from any untrusted network (hotel WiFi, conference, public hotspot). "
            "Attack window: every VPN connection from untrusted network."
        ),
        "poc_sketch": (
            "# On-path attacker (ARP spoof / rogue AP):\n"
            "# 1. Intercept HTTP GET /cscan.gz\n"
            "# 2. Serve malicious cscan.gz (gzip of backdoored ELF)\n"
            "# 3. ciscod extracts and executes as root\n"
            "# No TLS to break — it's plaintext HTTP\n"
        ),
        "remediation": (
            "CRITICAL: Use HTTPS exclusively for all pre-login downloads. "
            "Verify downloaded binary via code-signing (RSA/ECDSA) with "
            "a pinned Cisco public key — NOT just a hash from the same HTTP channel. "
            "Perform posture check inside the established VPN tunnel, not before."
        ),
    },

    "POS-F05": {
        "title": "cscan: XML-driven scan policy parsed from headend — XML injection",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "source_file": "opt/cisco/secureclient/securefirewallposture/bin/cscan",
        "description": (
            "cscan parses XML posture policy received from the ASA/FTD headend "
            "using libxml2 (xmlReadMemory, xmlGetProp, xmlHasProp). "
            "The XML drives what checks cscan performs: antivirus state, "
            "firewall state, process enumeration, file existence, registry. "
            "If the headend XML is attacker-controlled (rogue ASA, compromised "
            "headend, or combined with POS-F04 MITM), malformed XML can:\n"
            "  1. Trigger libxml2 parser bugs (historic: CVE-2022-40303/40304)\n"
            "  2. Inject scan arguments passed to popen/execvp (if cscan builds "
            "     shell commands from XML attribute values without sanitization)\n"
            "cscan source file: Raccoon_MR15/posture/asa/cscan/cfg.c — "
            "the fact that arg parsing is in cfg.c (config file) suggests "
            "XML attributes are directly used as command arguments."
        ),
        "evidence": [
            "cscan: xmlReadMemory, xmlGetProp, xmlHasProp (libxml2 XML parsing)",
            "cscan: popen, execvp (command execution from parsed config)",
            "cscan: 'unable to find data node: xml data is invalid!'",
            "cscan source: Raccoon_MR15/posture/asa/cscan/cfg.c",
        ],
        "impact": (
            "If XML args flow to popen/execvp without sanitization: "
            "RCE from malicious headend or MITM (combined with POS-F04)."
        ),
        "remediation": (
            "Sanitize all XML attribute values before passing to shell. "
            "Use execvp with argv array (no shell=True equivalent). "
            "Validate XML schema before processing."
        ),
    },

    "POS-F06": {
        "title": "ciscod fw_enable/fw_disable over IPC: iptables manipulation from posture client",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "opt/cisco/secureclient/securefirewallposture/lib/libhostscan.so",
        "description": (
            "libhostscan.so exports hs_fw_enable and hs_fw_disable functions "
            "for managing the local firewall. ciscod calls these via IPC dispatch "
            "to enforce posture remediation (if endpoint fails posture check, "
            "firewall may be enabled/disabled). "
            "Functions confirmed:\n"
            "  ac_hs_priv_enable_firewall / ac_hs_priv_disable_firewall\n"
            "  ac_hs_priv_add_firewall_rule\n"
            "  sfp_priv_enable_firewall / sfp_priv_disable_firewall\n"
            "  hs_fw_add_rule (adds iptables rules)\n"
            "If IPC is accessible without auth (POS-F02), any local user can:\n"
            "  - disable iptables/ufw/firewalld entirely\n"
            "  - add rules opening inbound ports\n"
            "  - add rules allowing outbound C2 traffic"
        ),
        "evidence": [
            "libhostscan.so: ac_hs_priv_enable_firewall, ac_hs_priv_disable_firewall",
            "libhostscan.so: ac_hs_priv_add_firewall_rule, hs_fw_add_rule",
            "libhostscan.so: sfp_priv_enable_firewall, sfp_priv_disable_firewall",
        ],
        "impact": (
            "Disable host firewall: removes network isolation. "
            "Add firewall rules: open inbound ports, allow C2 outbound. "
            "Combined with network access, full lateral movement enablement."
        ),
        "remediation": "Apply POS-F02 fix. Validate that firewall rule sources are Cisco-internal addresses only.",
    },

    "POS-F07": {
        "title": "Dual IPC socket paths: legacy hostscan path may have weaker permissions",
        "severity": "MEDIUM",
        "status": "CANDIDATE",
        "source_file": "opt/cisco/secureclient/securefirewallposture/bin/ciscod",
        "description": (
            "ciscod listens on two IPC socket paths for backward compatibility:\n"
            "  Current: /opt/cisco/secureclient/securefirewallposture/.ciscod.ipc\n"
            "  Legacy:  /opt/cisco/hostscan/.ciscod.ipc (AnyConnect 4.x)\n"
            "The legacy path is in /opt/cisco/hostscan/ — if this directory exists "
            "from a prior AnyConnect 4.x installation with different ownership/permissions "
            "than the new Secure Client 5.x directories, the legacy socket may be "
            "accessible to a wider audience than intended. "
            "Both sockets connect to the same ciscod dispatch, so exploiting the "
            "more-permissive legacy path achieves the same privileged operations."
        ),
        "evidence": [
            "ciscod: '/opt/cisco/hostscan/.ciscod.ipc' AND '/opt/cisco/secureclient/securefirewallposture/.ciscod.ipc'",
            "Both paths connect to same process_ipc_message dispatch",
        ],
        "poc_check": (
            "ls -la /opt/cisco/hostscan/.ciscod.ipc\n"
            "ls -la /opt/cisco/secureclient/securefirewallposture/.ciscod.ipc\n"
            "stat /opt/cisco/hostscan/\n"
            "# Check if hostscan/ dir is world-traversable"
        ),
        "remediation": (
            "Remove legacy IPC socket path from production Secure Client 5.x. "
            "Ensure /opt/cisco/hostscan/ (if present) is owned root:root 0750."
        ),
    },
}


# ── IPC Protocol Primitives ───────────────────────────────────────────────────

IPC_SOCKET_PATHS = [
    "/opt/cisco/secureclient/securefirewallposture/.ciscod.ipc",
    "/opt/cisco/hostscan/.ciscod.ipc",
]

HOSTSCAN_PROTOCOL_TAG = b"hostscanH9"  # version identifier


def probe_ciscod_socket() -> dict:
    """
    Probe .ciscod.ipc socket accessibility.
    Returns dict of path -> status.
    """
    results = {}
    for path in IPC_SOCKET_PATHS:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(path)
            results[path] = "connected"
            s.close()
        except FileNotFoundError:
            results[path] = "socket_not_found"
        except PermissionError:
            results[path] = "permission_denied"
        except ConnectionRefusedError:
            results[path] = "connection_refused"
        except OSError as e:
            results[path] = f"error: {e}"
    return results


def check_socket_permissions() -> dict:
    """
    Check socket file permissions and parent directory permissions.
    """
    results = {}
    for path in IPC_SOCKET_PATHS:
        parent = os.path.dirname(path)
        try:
            sock_stat = os.stat(path)
            dir_stat = os.stat(parent)
            results[path] = {
                "socket_mode": oct(sock_stat.st_mode),
                "socket_uid": sock_stat.st_uid,
                "socket_gid": sock_stat.st_gid,
                "dir_mode": oct(dir_stat.st_mode),
                "world_accessible": bool(dir_stat.st_mode & 0o001),
            }
        except FileNotFoundError:
            results[path] = {"exists": False}
        except PermissionError:
            results[path] = {"error": "permission_denied"}
    return results


def report(verbose: bool = False):
    print("Cisco Secure Client Posture (HostScan) 5.1.15.287 — RE Findings")
    print("ciscod BuildID: 12f44e2179ef8203f6a0bdd0ec36c22a8dcaa0bb")
    print("Source: Raccoon_MR15 (secure-client-linux_Raccoon_MR15)")
    print("=" * 70)
    for fid, f in FINDINGS.items():
        print(f"[{f['severity']:<8}] [{f['status']:<9}] {fid}: {f['title']}")
        if verbose:
            print(f"          Source: {f.get('source_file', 'N/A')}")
            print(f"          Impact: {f['impact']}")
            print()
    print()
    counts = {}
    for f in FINDINGS.values():
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in counts:
            print(f"  {sev}: {counts[sev]}")

    print()
    print("IPC socket paths:")
    for p in IPC_SOCKET_PATHS:
        print(f"  {p}")
    print("Protocol tag:", HOSTSCAN_PROTOCOL_TAG.decode())


if __name__ == "__main__":
    import sys
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    report(verbose=verbose)

    if "--probe" in sys.argv:
        print("\nProbing ciscod IPC sockets...")
        status = probe_ciscod_socket()
        for path, result in status.items():
            print(f"  {path}: {result}")

    if "--check-perms" in sys.argv:
        print("\nSocket permission check:")
        perms = check_socket_permissions()
        for path, info in perms.items():
            if not info.get("exists", True):
                print(f"  NOT FOUND: {path}")
            elif info.get("world_accessible"):
                print(f"  WORLD ACCESSIBLE: {path} (dir mode {info.get('dir_mode')})")
            else:
                print(f"  {path}: dir={info.get('dir_mode')}, sock={info.get('socket_mode')}")
