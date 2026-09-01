"""
cisco_secure_client_dart_re — Cisco Secure Client DART 5.1.15.287 RE

DART = Diagnostics and Reporting Tool
Package: cisco-secure-client-dart_5.1.15.287_amd64.deb

Components:
  dartcli     — ELF64 PIE, BuildID ad042b1a, stripped
               Deps: libxml2, libpthread, libdl, libz, libsystemd, CiscoSSL
               Calls: execl, execvp, popen, fchmod, fchmodat
  darthelper  — ELF64 PIE, BuildID c1071a2d, stripped
               D-Bus system service: com.cisco.secureclient.dart.helper
               Deps: libpolkit-gobject-1 (polkit_authority_check_authorization_sync)
               GLib/GDBus IPC to desktop session
  dartui      — GTK3 GUI frontend (not analyzed, not in attack surface)

Architecture:
  dartcli <──IPC──> darthelper (D-Bus) ──polkit──> admin auth prompt
       |
       └── reads XML config files ──> execvp external commands as dart process
       └── collects files from filesystem ──> writes bundle zip

XML config surface:
  /opt/cisco/secureclient/dart/xml/config/DART.xml       — module-specific file list + commands
  /opt/cisco/secureclient/dart/xml/config/BaseConfig.xml — OS-wide commands (ps, df, sysctl, etc.)
  /opt/cisco/secureclient/dart/xml/config/AnyConnectConfig.xml — VPN config collection
  /opt/cisco/secureclient/dart/xml/config/ISEPosture.xml
  /opt/cisco/secureclient/dart/xml/config/NetworkVisibility.xml
  /opt/cisco/secureclient/dart/xml/config/Posture.xml

D-Bus policy (com.cisco.secureclient.dart.conf):
  context="default" → allow own + allow send_destination
  Any user can send messages to com.cisco.secureclient.dart.helper.

polkit action (com.cisco.secureclient.dart.collect):
  allow_inactive: no
  allow_active:   auth_admin_keep
  Requires admin credentials to generate bundle.
  BUT: if polkit check is bypassable or darthelper has pre-check operations, unprivileged.

Build info:
  PDB path prefix: /home/build/p4files/ngc/Raccoon/... (confirmed Raccoon codebase)
  Compiler: GCC 13.3.1 20240611 (Red Hat 13.3.1-2) — same as vpnagentd
  OpenSSL: CiscoSSL 1.1.1x (EOL 2023-09-11) via /opt/cisco/secureclient/lib/cfom.so
"""

import subprocess
import os
from pathlib import Path


# ── Finding Registry ─────────────────────────────────────────────────────────

FINDINGS = {
    "DART-F01": {
        "title": "darthelper D-Bus policy: context=default allows any user to send",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "usr/share/dbus-1/system.d/com.cisco.secureclient.dart.conf",
        "description": (
            "The D-Bus policy for com.cisco.secureclient.dart.helper uses "
            "context='default' (applies to all callers) and grants:\n"
            "  <allow own='com.cisco.secureclient.dart.helper'/>\n"
            "  <allow send_destination='com.cisco.secureclient.dart.helper'/>\n"
            "This means any unprivileged user can call darthelper's D-Bus methods. "
            "The polkit check (auth_admin_keep) gates the 'collect' action — but "
            "only if darthelper correctly invokes polkit_authority_check_authorization_sync "
            "before performing every sensitive operation. Any pre-check operation "
            "(method enumeration, introspection, parameter validation) runs without "
            "the auth gate and is fully accessible from an unprivileged session.\n"
            "Callers can also spam the auth prompt to frustrate legitimate admin operations."
        ),
        "evidence": [
            "com.cisco.secureclient.dart.conf: <policy context='default'>",
            "com.cisco.secureclient.dart.conf: <allow send_destination='com.cisco.secureclient.dart.helper'/>",
            "polkit action: allow_active=auth_admin_keep (admin password only, not user password)",
        ],
        "impact": (
            "Unprivileged user can interact with darthelper D-Bus service methods. "
            "Pre-polkit operations may disclose system information or trigger partial "
            "bundle collection. Auth prompt spamming as DoS."
        ),
        "remediation": (
            "Add per-user D-Bus policy: <policy user='root'> or restrict to a cisco group. "
            "Use context='mandatory' deny-first pattern; whitelist only necessary senders."
        ),
    },

    "DART-F02": {
        "title": "dartcli XML-driven external command execution: writable config = command injection",
        "severity": "CRITICAL",
        "status": "CANDIDATE",
        "source_file": "opt/cisco/secureclient/dart/xml/config/",
        "description": (
            "dartcli reads collection configuration from XML files and executes "
            "<use_extern_action> entries via execl/execvp. The execution path:\n"
            "  1. Parse DART.xml / BaseConfig.xml / module XMLs (libxml2)\n"
            "  2. For each <use_extern_action>: extract <path> and <args>\n"
            "  3. Execute: execvp(path + '/' + binary, args[])\n"
            "  4. Collect stdout to bundle\n"
            "The XML files are at /opt/cisco/secureclient/dart/xml/config/ "
            "which is installed by the cisco-secure-client-dart DEB package. "
            "If the package sets these files world-writable or group-writable, "
            "any local user can inject arbitrary commands executed by dartcli "
            "when bundle generation runs (with dartcli's privilege level).\n"
            "dartcli itself is not a setuid binary — it runs as the invoking user. "
            "However, darthelper (the polkit-authorized helper) may call dartcli "
            "after acquiring admin credentials, in which case dartcli runs with "
            "elevated privileges and XML injection executes as root."
        ),
        "evidence": [
            "dartcli: execl, execvp symbols present",
            "DART.xml: <use_extern_action><args>journalctl ...</args>",
            "BaseConfig.xml: <use_extern_action><path>/usr/sbin</path><args>sysctl -a</args>",
            "DARTENGINE_ERROR_EXTERN_ACTION_TIMEOUT: Binary executable took too long",
            "String 'cannot copy file' adjacent to execvp in dartcli binary",
        ],
        "impact": (
            "If XML config files are group/world-writable: "
            "arbitrary command injection when any user triggers bundle generation. "
            "If darthelper calls dartcli post-polkit-auth: root RCE."
        ),
        "poc_check": (
            "ls -la /opt/cisco/secureclient/dart/xml/config/\n"
            "# If writable:\n"
            "# Inject into DART.xml <use_extern_action>:\n"
            "# <path>/tmp</path>\n"
            "# <args>evil.sh</args>\n"
            "# Then trigger: dartcli --collect\n"
        ),
        "remediation": (
            "XML config files must be owned root:root 0644 (read-only to non-root). "
            "dartcli must validate XML file integrity (hash/signature) before parsing. "
            "Never execute user-writable path entries."
        ),
    },

    "DART-F03": {
        "title": "dartcli bundle collection: /proc/$PID enumeration as diagnostic data",
        "severity": "MEDIUM",
        "status": "CONFIRMED",
        "source_file": "opt/cisco/secureclient/dart/dartcli",
        "description": (
            "dartcli reads /proc/%d/exe and /proc/%d/stat for running processes "
            "as part of diagnostic collection. The format string '/proc/%d/exe' "
            "directly in the binary confirms process enumeration. Combined with "
            "the bundle collection of /etc/os-release, /etc/issue, /etc/machine-id, "
            "and /dev/disk/by-uuid, the DART bundle contains a complete system "
            "fingerprint — machine-id, all mounted devices, running process list, "
            "and VPN connection state.\n"
            "The bundle file output location: likely /tmp or home directory. "
            "If written to /tmp without O_EXCL, a symlink race allows overwriting "
            "arbitrary files."
        ),
        "evidence": [
            "dartcli strings: '/proc/%d/exe', '/proc/%d/stat'",
            "dartcli strings: '/etc/machine-id', '/dev/disk/by-uuid', '/etc/mtab'",
            "dartcli strings: '/etc/os-release', '/etc/issue'",
            "Bundle contains VPN profiles with server addresses and cert thumbprints",
        ],
        "impact": (
            "Sensitive system identification data (machine-id, disk UUIDs, process list) "
            "captured in DART bundle. If bundle output path has a race condition, "
            "arbitrary file overwrite."
        ),
        "bundle_sensitive_content": [
            "/etc/machine-id — permanent host identifier",
            "/dev/disk/by-uuid — storage fingerprint",
            "/etc/mtab — mounted filesystems",
            "VPN profiles (server IPs, cert data)",
            "journalctl output (last 24h DART/VPN logs)",
        ],
        "remediation": (
            "Use O_EXCL | O_CREAT for bundle output file creation. "
            "Document that DART bundles contain sensitive system identifiers. "
            "Require admin auth before reading /proc data."
        ),
    },

    "DART-F04": {
        "title": "CiscoSSL 1.1.1x (EOL) in dartcli — same EOL OpenSSL fork as vpnagentd",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "source_file": "opt/cisco/secureclient/lib/cfom.so",
        "description": (
            "dartcli links cfom.so (Cisco FIPS Object Module) which wraps CiscoSSL "
            "1.1.1x — the same EOL OpenSSL 1.1.1 fork present in vpnagentd. "
            "OpenSSL 1.1.1 reached end-of-life on 2023-09-11. "
            "dartcli uses TLS for certificate CRL fetching "
            "(crl3.digicert.com/DigiCertTrustedRootG4.crl) and CA cert retrieval. "
            "Any post-EOL OpenSSL 1.1.1 CVEs (including CVE-2022-0778 handled "
            "separately) affect dartcli's crypto operations."
        ),
        "evidence": [
            "dartcli: imports /opt/cisco/secureclient/lib/cfom.so",
            "libacciscossl.so: CiscoSSL 1.1.1x.7.2.568",
            "dartcli strings: http://crl3.digicert.com/DigiCertTrustedRootG4.crl",
            "OpenSSL 1.1.1 EOL: 2023-09-11",
        ],
        "impact": "All dartcli TLS operations inherit EOL OpenSSL 1.1.1 CVE exposure.",
        "remediation": "Upgrade CiscoSSL to OpenSSL 3.x fork or ship with system libssl.",
    },

    "DART-F05": {
        "title": "darthelper: fchmod on collected files — permission change attack surface",
        "severity": "MEDIUM",
        "status": "CANDIDATE",
        "source_file": "opt/cisco/secureclient/dart/dartcli",
        "description": (
            "dartcli uses fchmod and fchmodat on files during bundle collection. "
            "If the bundle assembly process changes file permissions to world-readable "
            "before archiving (to ensure dartcli can read root-owned log files), "
            "a TOCTOU race exists: "
            "1. dartcli calls fchmod(fd, 0644) on a root-owned sensitive file.\n"
            "2. Attacker opens the file before dartcli closes it.\n"
            "3. Attacker reads contents that should require root.\n"
            "The fchmod/fchmodat calls are confirmed by symbol table."
        ),
        "evidence": [
            "dartcli: fchmod, fchmodat symbols",
            "dartcli collects /opt/cisco/secureclient/lib/* (includes cert stores)",
            "Bundle collection requires reading root-owned VPN log files",
        ],
        "impact": "Potential read of root-owned VPN state files via fchmod TOCTOU.",
        "remediation": "Never chmod files before reading; use root-privileged reader, not chmod.",
    },
}


# ── XML Config Paths ──────────────────────────────────────────────────────────

XML_CONFIG_BASE = "/opt/cisco/secureclient/dart/xml/config/"

XML_CONFIGS = {
    "DART.xml": "Module-specific: DART logs + journalctl commands",
    "BaseConfig.xml": "OS-wide: ps, df, sysctl, mount, sw_vers, profiles",
    "AnyConnectConfig.xml": "VPN-specific: profiles, cert state, IPC logs",
    "ISEPosture.xml": "Posture logs",
    "NetworkVisibility.xml": "NVM logs",
    "Posture.xml": "Posture logs",
    "SecureClientConfig.xml": "Client config",
    "ZTA.xml": "Zero Trust Access config",
}

EXTERNAL_COMMANDS = {
    "linux": [
        ("journalctl", "-S -1d -t csc_dartui -t csc_dartcli -t csc_darthelper"),
        ("journalctl", "-o export -S -1d -t csc_dartui -t csc_dartcli -t csc_darthelper"),
        ("ps", "aux"),
        ("df", ""),
        ("mount", ""),
        ("uname", "-a"),
        ("hostname", ""),
        ("date", ""),
    ],
    "macos": [
        ("/usr/sbin/system_profiler", "SPHardwareDataType SPNetworkDataType ..."),
        ("/usr/bin/systemextensionsctl", "list"),
        ("/bin/ps", "aux"),
        ("/usr/sbin/sysctl", "-a"),
        ("/usr/sbin/pkgutil", "--regexp --pkg-info com.cisco.*"),
    ],
}

DBUS_SERVICE = "com.cisco.secureclient.dart.helper"
POLKIT_ACTION = "com.cisco.secureclient.dart.collect"
POLKIT_RESULT = "auth_admin_keep"


# ── Privilege Check ───────────────────────────────────────────────────────────

def check_xml_config_permissions() -> dict:
    """
    Check if DART XML config files are writable by non-root.
    Returns dict of path -> permission info.
    """
    results = {}
    for xml_file in XML_CONFIGS:
        path = os.path.join(XML_CONFIG_BASE, xml_file)
        try:
            st = os.stat(path)
            world_writable = bool(st.st_mode & 0o002)
            group_writable = bool(st.st_mode & 0o020)
            results[path] = {
                "mode": oct(st.st_mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "world_writable": world_writable,
                "group_writable": group_writable,
                "vulnerable": world_writable or (group_writable and os.getgid() == st.st_gid),
            }
        except FileNotFoundError:
            results[path] = {"exists": False}
        except PermissionError:
            results[path] = {"error": "permission_denied"}
    return results


def check_dbus_service_accessible() -> str:
    """
    Test if darthelper D-Bus service is reachable.
    """
    try:
        result = subprocess.run(
            ["dbus-send", "--system", "--print-reply",
             "--dest=com.cisco.secureclient.dart.helper",
             "/", "org.freedesktop.DBus.Introspectable.Introspect"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return "reachable"
        return f"error: {result.stderr.strip()}"
    except FileNotFoundError:
        return "dbus-send not available"
    except Exception as e:
        return f"exception: {e}"


# ── Bundle Analysis ───────────────────────────────────────────────────────────

BUNDLE_SENSITIVE_FILES = [
    "/opt/cisco/secureclient/profile/*.xml",
    "/opt/cisco/secureclient/log/*.txt",
    "/etc/machine-id",
    "/etc/mtab",
    "/dev/disk/by-uuid/*",
    "/proc/*/exe",
    "/proc/*/stat",
    "/var/run/vpnagentd.pid",
]


def report(verbose: bool = False):
    print("Cisco Secure Client DART 5.1.15.287 — RE Findings")
    print("dartcli BuildID: ad042b1aa54ee28d72ed7a98ff8b1e03138952cb")
    print("darthelper BuildID: c1071a2d6142221144793602f071308621fee2b3")
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
    print("D-Bus service:", DBUS_SERVICE)
    print("polkit action:", POLKIT_ACTION, "->", POLKIT_RESULT)
    print()
    print("XML configs (possible injection paths):")
    for f, desc in XML_CONFIGS.items():
        print(f"  {XML_CONFIG_BASE}{f}: {desc}")


if __name__ == "__main__":
    import sys
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    report(verbose=verbose)

    if "--check-perms" in sys.argv:
        print("\nXML config file permission check:")
        perms = check_xml_config_permissions()
        for path, info in perms.items():
            if not info.get("exists", True):
                print(f"  {path}: NOT FOUND")
            elif info.get("vulnerable"):
                print(f"  VULNERABLE: {path} {info.get('mode')}")
            else:
                print(f"  {path}: {info.get('mode', 'N/A')}")

    if "--check-dbus" in sys.argv:
        print("\nD-Bus service accessibility:")
        result = check_dbus_service_accessible()
        print(f"  {DBUS_SERVICE}: {result}")
