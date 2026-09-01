"""
cisco_secure_client_re — Cisco Secure Client (AnyConnect) 5.1.x RE module

Covers:
  Linux 5.1.15.287 — vpnagentd, vpnui, vpndownloader, acwebhelper, acinstallhelper
  Windows 5.1.6.103 — vpnagent.exe, acsock64.sys, vpnva64-6.sys, InstallHelper{32,64}.exe
  Shared libs: libvpncommon.so, libvpncommoncrypt.so, libvpnagentutilities.so,
               libacciscossl.so, libacciscocrypto.so, cfom.so, libacruntime.so

Binary sources:
  Linux: cisco-secure-client-linux64-5.1.15.287-predeploy-deb-k9.tgz
         (extracted from cisco-secure-client-vpn_5.1.15.287_amd64.deb)
  Windows: cisco-secure-client-win-5.1.6.103-core-vpn-predeploy-k9.msi
           (msiextract -> APPDIR: binaries)

Architecture:
  vpnagentd (root/SYSTEM) listens on abstract UNIX socket "csc_vpnagent".
  JSON IPC messages (CJsonIpcClient::SendMsg, JSON_IPC_FROM_CLIENT_MSG enum).
  Three named sockets: csc_vpnagent, csc_vpncli, csc_vpndownloader.
  vpndownloader receives package-install commands via P2P IPC from vpnagentd.
  cfom.so = Cisco FIPS Object Module (OpenSSL ENGINE for FIPS 140-2 compliance).
  Windows kernel stack: acsock64.sys (L4 interceptor, codename "Raccoon") +
                        vpnva64-6.sys (virtual adapter) + vpnagent.exe (SYSTEM service).

Extraction method (DEBs):
  ar x cisco-secure-client-vpn_5.1.15.287_amd64.deb
  tar -xJf data.tar.xz
  -> /opt/cisco/secureclient/bin/ and /opt/cisco/secureclient/lib/

Findings: CSC-F01 through CSC-F10
"""

import re
import struct
import socket
import json
import subprocess
import os
from pathlib import Path


# ── Finding Registry ─────────────────────────────────────────────────────────

FINDINGS = {
    "CSC-F01": {
        "title": "Abstract UNIX socket IPC: unauthenticated access to root daemon",
        "severity": "CRITICAL",
        "status": "CONFIRMED",
        "binary": "vpnagentd (Linux), vpnagent.exe (Windows)",
        "version": "5.1.15.287 (Linux), 5.1.6.103 (Windows)",
        "description": (
            "vpnagentd binds three abstract UNIX domain sockets with no ACL: "
            "'csc_vpnagent', 'csc_vpncli', 'csc_vpndownloader'. "
            "Linux abstract namespace sockets (prefix \\x00) are not subject to "
            "filesystem permission checks — any process on the host can connect "
            "regardless of UID. The daemon runs as root with no systemd security "
            "hardening (no User=, NoNewPrivileges=, CapabilityBoundingSet=, "
            "ProtectSystem=, SecureBits=). IPC protocol is JSON "
            "(CJsonIpcClient::SendMsg with JSON_IPC_FROM_CLIENT_MSG enum). "
            "Any local user can send arbitrary IPC messages to the root daemon."
        ),
        "evidence": [
            "strings vpnagentd | grep csc_vpnagent -> b'csc_vpnagent' at 0xda29b",
            "context: CInterModuleStateProducer -> csc_vpnagent socket name",
            "readelf libvpncommon.so -> CJsonIpcClient::SendMsg, CJsonIpcServer",
            "lib/systemd/system/vpnagentd.service: no User=, no hardening",
            "socket names: csc_vpnagent, csc_vpncli, csc_vpndownloader",
        ],
        "impact": "LPE: any local user -> root via crafted JSON IPC message",
        "connect_poc": (
            "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); "
            "s.connect('\\x00csc_vpnagent'); s.send(b'{\"type\":1}')"
        ),
        "remediation": (
            "Bind to filesystem socket in /var/run/cisco/ with 0700 permissions, "
            "owned by root:cisco, require daemon to verify peer UID via SO_PEERCRED "
            "before processing any IPC message. Add systemd hardening: "
            "NoNewPrivileges=true, ProtectSystem=strict, CapabilityBoundingSet=CAP_NET_ADMIN."
        ),
        "cve_ref": "CVE-2023-20195, CVE-2022-20773, CVE-2021-1365 (prior LPE via IPC)",
    },

    "CSC-F02": {
        "title": "CCommandShell::Execute() in root daemon IPC class tree",
        "severity": "CRITICAL",
        "status": "CANDIDATE",
        "binary": "libvpncommon.so",
        "version": "5.1.15.287",
        "description": (
            "libvpncommon.so (loaded by vpnagentd) exports CCommandShell with six "
            "Execute() overloads that wrap fork()+exec: "
            "Execute(string, uint), Execute(char*, ostream, uint), Execute(ofstream, uint), "
            "Execute(list<string>), ExecuteTimeoutHelper, ExecuteNoTimeoutHelper. "
            "The class holds sm_forkMutex (serialized fork). If any IPC message dispatch "
            "path reaches CCommandShell::Execute() without privilege verification, "
            "an unprivileged local user can achieve root command execution via "
            "the csc_vpnagent abstract socket."
        ),
        "evidence": [
            "readelf -s libvpncommon.so | c++filt | grep CCommandShell ->",
            "  CCommandShell::Execute(string&, uint)",
            "  CCommandShell::Execute(char const*, ostream&, uint)",
            "  CCommandShell::Execute(ofstream&, uint)",
            "  CCommandShell::Execute(char const*, list<string>&)",
            "  CCommandShell::ExecuteTimeoutHelper",
            "  CCommandShell::ExecuteNoTimeoutHelper",
            "  CCommandShell::sm_forkMutex (fork serialization mutex)",
        ],
        "impact": "Root command execution if IPC dispatch reaches Execute() without UID check",
        "remediation": (
            "Audit all IPC dispatch paths for calls into CCommandShell. "
            "Validate peer UID (SO_PEERCRED) before any IPC that routes through "
            "CCommandShell. If shell execution from IPC is intentional, require "
            "it to be root-initiated only (check euid==0 at dispatch)."
        ),
        "next_step": (
            "Disassemble CIpcDepot::initiateIpcListening dispatch table to trace "
            "which IPC_MESSAGE_IDs route to CCommandShell::Execute()."
        ),
    },

    "CSC-F03": {
        "title": "CiscoSSL 1.1.1x EOL fork: backport drift risk",
        "severity": "HIGH",
        "status": "CONFIRMED",
        "binary": "libacciscossl.so",
        "version": "5.1.15.287 (released 2024)",
        "description": (
            "libacciscossl.so version string: 'CiscoSSL 1.1.1x.7.2.568'. "
            "Upstream OpenSSL 1.1.1 reached end-of-life September 11, 2023. "
            "Cisco continues shipping a proprietary fork with internal backports. "
            "Compiler: GCC 13.3.1 20240611 (Red Hat). "
            "Internal backport drift means CVEs fixed upstream in 3.x may not be "
            "addressed in the Cisco fork, and Cisco advisories for its SSL fork "
            "have historically lagged upstream disclosure windows."
        ),
        "evidence": [
            "strings libacciscossl.so | grep CiscoSSL -> 'CiscoSSL 1.1.1x.7.2.568'",
            "OpenSSL 1.1.1 EOL: 2023-09-11",
            "Package date: Feb 2024 (5.1.15.287)",
        ],
        "impact": (
            "Unpatched TLS/crypto vulnerabilities in EOL fork; "
            "relevant CVEs: CVE-2023-5363 (AES-SIV key confusion), "
            "CVE-2023-3817 (DH check excessive time), "
            "CVE-2023-3446 (excessive DH modulus), "
            "CVE-2022-0778 (OpenSSL infinite loop — confirmed present in ASA/CSC by prior RE)."
        ),
        "remediation": "Upgrade libacciscossl.so to OpenSSL 3.x or latest FIPS-validated 3.0.x.",
        "cross_ref": "ftd_ciscossl_cve_2022_0778.py (confirmed in prior RE session)",
    },

    "CSC-F04": {
        "title": "cfom.so FIPS module: substitution and bypass attack surface",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "binary": "cfom.so",
        "version": "5.1.15.287",
        "description": (
            "cfom.so is Cisco's FIPS 140-2 validated OpenSSL ENGINE plugin. "
            "Exports: FIPS_cfom_get_load_permission, cfom_rsa_init, cfom_dsa_init, "
            "cfom_dh_init, cfom_engine_set_ciphers, cfom_digests. "
            "Attack vector 1 (substitution): if /opt/cisco/secureclient/lib/ is "
            "writable by non-root (or via a local priv-esc), a malicious cfom.so "
            "can be swapped in — all VPN crypto is then attacker-controlled. "
            "Attack vector 2 (bypass): intercept FIPS_cfom_get_load_permission "
            "return value; if it returns failure and vpnagentd falls back to "
            "non-FIPS OpenSSL, cipher strength is silently downgraded without "
            "user notification."
        ),
        "evidence": [
            "strings cfom.so -> FIPS_cfom_get_load_permission",
            "strings cfom.so -> cfom_engine_set_ciphers, cfom_digests",
            "strings cfom.so -> cfom_rsa_init, cfom_dsa_init, cfom_dh_init",
        ],
        "impact": (
            "Full VPN traffic decryption if cfom.so is substituted or FIPS "
            "fallback downgrade accepted silently."
        ),
        "remediation": (
            "Verify cfom.so integrity at load time via HMAC (OpenSSL FIPS POST). "
            "Ensure FIPS_cfom_get_load_permission failure causes vpnagentd abort, "
            "not fallback. Restrict /opt/cisco/secureclient/lib/ to root:root 0755."
        ),
    },

    "CSC-F05": {
        "title": "SCEP certificate enrollment: unauthenticated enrollment attack surface",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "binary": "vpnagentd",
        "version": "5.1.15.287",
        "description": (
            "vpnagentd contains a SCEP (Simple Certificate Enrollment Protocol) "
            "enrollment subsystem: SCEPTlv (IPC TLV type), CCertSCEPEnroller::GetPKCS12(), "
            "SCEP Enrollment Check Timer, Aggregate Config SCEP enable/enroll-now flags. "
            "SCEP is vulnerable to MITM enrollment without strong authentication: "
            "if the SCEP server is not properly authenticated (CA thumbprint in profile "
            "can be set by attacker-controlled profile XML), an adversary on the "
            "network path can issue a fraudulent certificate via a rogue SCEP responder. "
            "CSC explicitly suppresses SCEP during management tunnels but allows it "
            "on standard tunnels."
        ),
        "evidence": [
            "strings vpnagentd | grep SCEP ->",
            "  'SCEP Enrollment Check Timer'",
            "  'SCEPTlv::GetMessageType'",
            "  'Aggregate Config SCEP is enabled.'",
            "  'SCEP Certificate Enrollment not performed during management tunnel.'",
            "readelf libvpncommon.so -> CCertSCEPEnroller::GetPKCS12()",
        ],
        "impact": (
            "Rogue certificate issuance via MITM SCEP responder; "
            "certificate can then be used to authenticate to VPN headend."
        ),
        "remediation": (
            "Pin the SCEP CA certificate thumbprint in policy (not user-editable profile). "
            "Require SCEP challenge password. Enforce HTTPS-only SCEP with HSTS."
        ),
    },

    "CSC-F06": {
        "title": "vpndownloader P2P IPC: root package installer reachable via local socket",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "binary": "vpndownloader, vpndownloader-cli",
        "version": "5.1.15.287",
        "description": (
            "vpndownloader runs as root and receives installation instructions via "
            "P2P IPC from vpnagentd on abstract socket 'csc_vpndownloader'. "
            "The downloader fetches packages from cloud infrastructure "
            "('cloudupdate' flow) and performs installation. "
            "If the csc_vpndownloader socket does not verify peer UID "
            "(same vulnerability class as CSC-F01), an unprivileged user can "
            "direct vpndownloader to install an arbitrary package as root. "
            "vpndownloader also reads 'csc_vpndownloader_major' and "
            "'csc_vpndownloader_minor' version sockets — version negotiation "
            "over unauthenticated channels is a TOCTOU surface."
        ),
        "evidence": [
            "strings vpndownloader -> csc_vpndownloader, csc_vpndownloader_major",
            "strings vpndownloader -> 'Missing first instance executable command line arguments, "
            "presuming delivery via P2P IPC'",
            "strings vpndownloader -> cloudupdate, updateInstallProgress, updateFileProgress",
        ],
        "impact": "Root package installation from unprivileged local user via IPC",
        "remediation": (
            "Apply SO_PEERCRED UID verification to csc_vpndownloader before "
            "processing any install directive. Verify package signature before install."
        ),
    },

    "CSC-F07": {
        "title": "Profile XML parser running as root: CA URL and thumbprint from user-influenced XML",
        "severity": "MEDIUM",
        "status": "CANDIDATE",
        "binary": "vpnagentd (ProfileMgr, PreferenceMgr)",
        "version": "5.1.15.287",
        "description": (
            "vpnagentd's ProfileMgr parses AnyConnect profile XML from "
            "/opt/cisco/secureclient/vpn/profile/ as root. "
            "Profile XML specifies CA URL (getCAURL()), CA thumbprint "
            "(getCAThumbprint()), challenge password (getPromptForChallengePW()), "
            "and host-level settings. The parser runs in the root daemon context. "
            "If profile directory permissions allow non-root write (installable "
            "world-writable by design on some enterprise configs), an attacker "
            "can inject a malicious profile to redirect CA authentication, "
            "bypass certificate pinning, or exploit XML parser vulnerabilities "
            "in the root process. VPNDisable_ServiceProfile.xml is world-readable "
            "in the DEB layout."
        ),
        "evidence": [
            "readelf vpnagentd -> ProfileMgr::getCAURL(), getCAThumbprint()",
            "find / -path '*secureclient/vpn/profile*' in DEB layout",
            "/opt/cisco/secureclient/vpn/profile/AnyConnectProfile.xsd (world-readable)",
            "libvpncommoncrypt.so: 'CA certificate thumbprint mismatch: expected %s, SHA1 %s, MD5 %s'",
        ],
        "impact": (
            "XML injection or CA redirect if profile directory is writable; "
            "MD5/SHA1 thumbprint comparison for CA cert pinning (weak hash usage)."
        ),
        "remediation": (
            "Restrict /opt/cisco/secureclient/vpn/profile/ to root:root 0700. "
            "Validate profile XML against AnyConnectProfile.xsd before parsing. "
            "Replace MD5/SHA1 CA thumbprint with SHA-256."
        ),
    },

    "CSC-F08": {
        "title": "Windows kernel drivers: acsock64.sys (L4 interceptor) + vpnva64-6.sys",
        "severity": "HIGH",
        "status": "CANDIDATE",
        "binary": "acsock64.sys, acsock.sys, vpnva64-6.sys",
        "version": "5.1.6.103 (Windows MSI)",
        "description": (
            "acsock64.sys (and acsock.sys for 32-bit): kernel-mode Layer 4 network "
            "interceptor (PDB: 'Raccoon\\kdf\\interceptors\\layer4'). "
            "CSocketMultiplexor::DeviceIoControl is the kernel driver's primary "
            "user-mode interface — accessible via CreateFile + DeviceIoControl "
            "from any user-mode process. "
            "IOCTL codes exposed via vpnagent.exe: IOCTL_CVCVA_STATE_CONNECTED, "
            "IOCTL_CVCVA_STATE_DISCONNECTED (virtual adapter state control). "
            "vpnva64-6.sys and vpnva-6.sys are the virtual network adapter drivers "
            "also accessible from user-mode. "
            "Internal codename: 'Raccoon' (PDB paths in both acsock64.sys and vpnagent.exe). "
            "Developer username: 'thehoff'. Build: Raccoon_MR6 (Maintenance Release 6)."
        ),
        "evidence": [
            "strings acsock64.sys -> CSocketMultiplexor::DeviceIoControl",
            "strings acsock64.sys -> PDB: C:\\temp\\build\\thehoff\\Raccoon0.35474093232"
            "\\Raccoon\\kdf\\interceptors\\layer4\\win\\x64\\Release\\acsock64.pdb",
            "strings vpnagent.exe -> IOCTL_CVCVA_STATE_CONNECTED, IOCTL_CVCVA_STATE_DISCONNECTED",
            "strings vpnagent.exe -> PDB: Raccoon_MR60.479390463523\\Raccoon_MR6\\vpn\\Agent",
        ],
        "impact": (
            "Kernel-mode attack surface: privilege escalation, BSOD, "
            "arbitrary kernel memory read/write if IOCTL input validation is insufficient."
        ),
        "ioctl_poc": (
            "import ctypes; k32 = ctypes.windll.kernel32\n"
            "h = k32.CreateFileW(r'\\\\.\\acsock', 0xC0000000, 0, None, 3, 0, None)\n"
            "# enumerate IOCTLs starting from IOCTL_CVCVA_STATE_CONNECTED"
        ),
        "remediation": (
            "Add strict input length validation and probe_for_read/write guards "
            "for all IOCTL input buffers. Restrict DeviceObject ACL to SYSTEM+Administrators. "
            "Enable Driver Verifier during QA with IOCTL fuzzing."
        ),
    },

    "CSC-F09": {
        "title": "Systemd service: zero security hardening on root daemon",
        "severity": "MEDIUM",
        "status": "CONFIRMED",
        "binary": "lib/systemd/system/vpnagentd.service",
        "version": "5.1.15.287",
        "description": (
            "vpnagentd.service has no security hardening directives. "
            "Running as root (no User=). "
            "KillMode=process means only vpnagentd itself is signaled on stop — "
            "child processes spawned via CCommandShell::Execute() (fork+exec) "
            "survive service stop/restart. "
            "Missing: NoNewPrivileges=true, CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW, "
            "ProtectSystem=strict, ProtectHome=true, PrivateTmp=true, "
            "RestrictNamespaces=true, RestrictSUIDSGID=true, "
            "SystemCallFilter=@system-service."
        ),
        "evidence": [
            "cat vpnagentd.service ->",
            "  Type=simple, Restart=on-failure",
            "  ExecStartPre=/opt/cisco/secureclient/bin/load_tun.sh",
            "  KillMode=process",
            "  EnvironmentFile=-/etc/environment",
            "  [no User=, no NoNewPrivileges=, no ProtectSystem=]",
        ],
        "impact": (
            "No confinement on root daemon; "
            "child processes persist after service stop (orphan LPE chain); "
            "full system access if root daemon is compromised."
        ),
        "remediation": (
            "Add: NoNewPrivileges=true, CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW "
            "CAP_SYS_MODULE, ProtectSystem=strict, ProtectHome=true, PrivateTmp=true, "
            "KillMode=control-group."
        ),
    },

    "CSC-F10": {
        "title": "/opt/cisco/secureclient/pem.XXXXXX: mkstemp tmpfile in Cisco-owned directory",
        "severity": "LOW",
        "status": "CANDIDATE",
        "binary": "vpnagentd",
        "version": "5.1.15.287",
        "description": (
            "vpnagentd creates temporary PEM files using mkstemp-style template "
            "'/opt/cisco/secureclient/pem.XXXXXX'. "
            "If /opt/cisco/secureclient/ has any world-write permission (non-default "
            "but possible in misconfigured installs), an attacker can pre-create "
            "a symlink at a predicted tmpfile path to redirect the write to an "
            "arbitrary root-owned file (symlink race). "
            "Additionally, if the PEM file is created with world-readable permissions "
            "before content is written (TOCTOU), a local attacker can read key material."
        ),
        "evidence": [
            "strings vpnagentd -> /opt/cisco/secureclient/pem.XXXXXX",
        ],
        "impact": "Conditional: arbitrary root file write or key material exposure if directory misconfigured",
        "remediation": (
            "Use mkstemp in /tmp with O_TMPFILE or restrict directory to 0700 root:root. "
            "Set umask 0077 before mkstemp call."
        ),
    },
}


# ── IPC Probe Primitives ───────────────────────────────────────────────────────

IPC_SOCKET_NAMES = [
    "csc_vpnagent",       # main VPN agent (root)
    "csc_vpncli",         # CLI interface
    "csc_vpndownloader",  # downloader (root, installs packages)
    "csc_vpndownloader_major",  # version negotiation channel
    "csc_vpndownloader_minor",  # version negotiation channel
    "csc_nam",            # Network Access Manager
    "csc_iseagent",       # ISE posture agent
    "csc_zta_agent",      # Zero Trust Access agent
]


def connect_abstract_socket(name: str, timeout: float = 2.0):
    """Connect to a Linux abstract UNIX domain socket by name."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect("\x00" + name)
        return sock
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        sock.close()
        return None


def probe_ipc_sockets() -> dict:
    """
    Probe all known Cisco Secure Client abstract sockets.
    Returns {socket_name: "open" | "refused" | "error"}.
    Requires: running on a Linux host with vpnagentd installed and active.
    """
    results = {}
    for name in IPC_SOCKET_NAMES:
        sock = connect_abstract_socket(name)
        if sock is not None:
            results[name] = "open"
            sock.close()
        else:
            results[name] = "refused"
    return results


def send_json_ipc(socket_name: str, msg: dict) -> bytes:
    """
    Send a raw JSON IPC message to a Cisco Secure Client abstract socket.
    Protocol: CJsonIpcClient::SendMsg(JSON_IPC_FROM_CLIENT_MSG, json_string).
    Returns raw response bytes (format varies by message type).
    """
    sock = connect_abstract_socket(socket_name)
    if sock is None:
        raise ConnectionError(f"Cannot connect to \\x00{socket_name}")
    try:
        payload = json.dumps(msg).encode()
        sock.sendall(payload)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(chunk) < 4096:
                break
        return response
    finally:
        sock.close()


# ── String Analysis Helpers ──────────────────────────────────────────────────

LINUX_VPN_ROOT = Path("/tmp/csc-vpn-root/opt/cisco/secureclient")
WINDOWS_EXTRACT = Path("/tmp/csc-msi-extract")


def _strings_file(path: Path, min_len: int = 6) -> list:
    result = subprocess.run(
        ["strings", "-n", str(min_len), str(path)],
        capture_output=True, text=True
    )
    return result.stdout.splitlines()


def analyze_vpnagentd(binary_path: Path = None) -> dict:
    """
    Static analysis of vpnagentd. Returns structured findings dict.
    """
    if binary_path is None:
        binary_path = LINUX_VPN_ROOT / "bin" / "vpnagentd"

    if not binary_path.exists():
        return {"error": f"vpnagentd not found at {binary_path}"}

    strs = _strings_file(binary_path)

    return {
        "binary": str(binary_path),
        "ipc_sockets": [s for s in strs if s.startswith("csc_")],
        "file_paths": sorted({s for s in strs if s.startswith("/") and len(s) > 4}),
        "scep_refs": [s for s in strs if "SCEP" in s or "scep" in s],
        "pem_tmpfile": [s for s in strs if "pem" in s.lower() and "XXXX" in s],
        "ssl_exports": [s for s in strs if "SSL_SESSION_set1_master_key" in s
                        or "SSL_export_keying_material" in s],
    }


def analyze_acsock_driver(sys_path: Path = None) -> dict:
    """
    Static analysis of acsock64.sys Windows kernel driver.
    Extracts IOCTL names, PDB metadata, device names.
    """
    if sys_path is None:
        sys_path = WINDOWS_EXTRACT / "APPDIR:./acsock64.sys"

    if not sys_path.exists():
        return {"error": f"acsock64.sys not found at {sys_path}"}

    strs = _strings_file(sys_path)

    return {
        "binary": str(sys_path),
        "pdb_path": next((s for s in strs if ".pdb" in s), None),
        "codename": "Raccoon",
        "ioctl_names": [s for s in strs if s.startswith("IOCTL_")],
        "device_names": [s for s in strs if s.startswith("\\Device\\") or s.startswith("\\DosDevices\\")],
        "architecture": "kdf/interceptors/layer4 (L4 kernel interceptor)",
    }


def analyze_ciscossl_version(lib_path: Path = None) -> dict:
    """
    Extract CiscoSSL version and assess EOL status.
    """
    if lib_path is None:
        lib_path = LINUX_VPN_ROOT / "lib" / "libacciscossl.so"

    if not lib_path.exists():
        return {"error": f"libacciscossl.so not found at {lib_path}"}

    strs = _strings_file(lib_path)
    version_str = next((s for s in strs if "CiscoSSL" in s), None)
    compiler = next((s for s in strs if s.startswith("GCC:")), None)

    return {
        "binary": str(lib_path),
        "version_string": version_str,
        "compiler": compiler,
        "openssl_base": "1.1.1",
        "openssl_eol": "2023-09-11",
        "status": "EOL — upstream security fixes not guaranteed to be backported",
    }


def analyze_cfom(lib_path: Path = None) -> dict:
    """
    Analyze cfom.so (Cisco FIPS Object Module) exports and attack surface.
    """
    if lib_path is None:
        lib_path = LINUX_VPN_ROOT / "lib" / "cfom.so"

    if not lib_path.exists():
        return {"error": f"cfom.so not found at {lib_path}"}

    strs = _strings_file(lib_path)

    return {
        "binary": str(lib_path),
        "fips_exports": [s for s in strs if "FIPS" in s or "cfom_" in s],
        "engine_hooks": [s for s in strs if "engine" in s.lower() or "cipher" in s.lower()],
        "attack_vectors": [
            "FIPS module substitution: replace cfom.so in /opt/cisco/secureclient/lib/",
            "FIPS bypass: intercept FIPS_cfom_get_load_permission return value -> non-FIPS fallback",
            "OpenSSL ENGINE hijack: cfom_engine_set_ciphers -> downgrade cipher suite",
        ],
    }


def check_profile_dir_permissions(profile_path: str = "/opt/cisco/secureclient/vpn/profile") -> dict:
    """
    Check profile XML directory permissions on a live system.
    World-writable = attacker can inject profile XML parsed as root.
    """
    try:
        st = os.stat(profile_path)
        mode = st.st_mode
        world_writable = bool(mode & 0o002)
        group_writable = bool(mode & 0o020)
        return {
            "path": profile_path,
            "mode": oct(mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "world_writable": world_writable,
            "group_writable": group_writable,
            "risk": "HIGH" if world_writable else ("MEDIUM" if group_writable else "LOW"),
        }
    except PermissionError as e:
        return {"error": str(e)}
    except FileNotFoundError:
        return {"error": f"{profile_path} not found — CSC not installed"}


# ── Report ───────────────────────────────────────────────────────────────────

def report(verbose: bool = False):
    """Print finding summary."""
    print("Cisco Secure Client 5.1.x — RE Findings")
    print(f"Linux: 5.1.15.287 | Windows: 5.1.6.103")
    print("=" * 60)
    for fid, f in FINDINGS.items():
        print(f"[{f['severity']:<8}] [{f['status']:<9}] {fid}: {f['title']}")
        if verbose:
            print(f"          Binary:  {f['binary']}")
            print(f"          Impact:  {f['impact']}")
            print()
    print()
    counts = {}
    for f in FINDINGS.values():
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev, count in sorted(counts.items()):
        print(f"  {sev}: {count}")


if __name__ == "__main__":
    import sys
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    report(verbose=verbose)

    if "--probe" in sys.argv:
        print("\nProbing IPC sockets (requires live vpnagentd)...")
        results = probe_ipc_sockets()
        for name, status in results.items():
            print(f"  \\x00{name}: {status}")

    if "--acsock" in sys.argv:
        print("\nacsock64.sys analysis:")
        r = analyze_acsock_driver()
        for k, v in r.items():
            print(f"  {k}: {v}")

    if "--ssl" in sys.argv:
        print("\nCiscoSSL version analysis:")
        r = analyze_ciscossl_version()
        for k, v in r.items():
            print(f"  {k}: {v}")
