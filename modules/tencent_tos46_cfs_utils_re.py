"""
TencentOS 4.6 — cfs-utils 1.0.4 source RE.

Package: cfs-utils 1.0.4-5.tl4
License: MIT (Tencent)
Language: Python 3 (noarch)
Source: cfs-utils.tar.gz

Components:
  /sbin/mount.cfs      — mount helper (src/mount_cfs/__init__.py, 1671 lines)
  /sbin/cfs-watchdog   — mount watchdog (src/watchdog/__init__.py, 1083 lines)
  cfs-mount-watchdog.service — systemd unit

Role: Tencent CFS (Cloud File System) NFS mount utility. Mounts CFS volumes
(NFS v3/v4.0) with optional TLS encapsulation via stunnel. Used to connect
TOS 4.6 workloads to Tencent Cloud's managed NFS service.
"""

PACKAGE = {
    "name": "cfs-utils",
    "version": "1.0.4",
    "release": "5.tl4",
    "license": "MIT",
    "upstream_url": "https://cloud.tencent.com/product/cfs",
    "language": "Python 3",
    "build_arch": "noarch",
    "dependencies": ["nfs-utils", "stunnel >= 4.56", "openssl >= 1.0.2", "util-linux"],
    "install_paths": {
        "/sbin/mount.cfs": "mount helper (symlinked as mount.cfs type in fstab)",
        "/sbin/cfs-watchdog": "periodic mount liveness checker",
        "/etc/cfs/cfs-utils.conf": "configuration file (TLS port ranges, stunnel options)",
        "/var/log/cfs/": "log directory",
        "/var/run/cfs/": "state directory (stunnel configs, TLS port lock files, PID files)",
    },
}

ARCHITECTURE = {
    "mount_flow": (
        "1. mount -a → kernel calls /sbin/mount.cfs <fsname> <mountpoint> -o <options> "
        "2. mount.cfs parses fstab options (parse_options) "
        "3. If TLS: allocate loopback IP + port, write stunnel config, start stunnel subprocess "
        "4. Build NFS mount command: mount -t nfs[-4] <dns-or-ip>:/<path> <mountpoint> -o ... "
        "5. Run mount command via subprocess.Popen (list form, no shell) "
        "6. Post-mount: optimize_readahead_window to fix kernel NFS readahead to 15*rsize "
        "7. Start watchdog daemon if not running"
    ),
    "tls_path": (
        "TLS is implemented by routing NFS through an stunnel client process. "
        "stunnel listens on a loopback IP (127.0.0.x, allocated from a pool) on a "
        "configured port range (default: dynamic). stunnel connects to the CFS server "
        "on port 2050/tcp with TLS. The NFS client connects to stunnel's loopback address. "
        "TLS identity is provided by a client certificate (cert= fstab option). "
        "Loopback IP allocation uses a cross-process file lock: /var/run/cfs/.mount_tls_ip.lock "
        "to prevent race conditions during concurrent mounts."
    ),
    "notls_path": (
        "When 'notls' is in mount options: NFS mounts directly to the CFS server, "
        "bypassing stunnel. Plain NFS v3/v4.0 over TCP. No encryption."
    ),
    "stunnel_config": {
        "fips": "no",
        "client": "yes",
        "connect_port": 2050,
        "renegotiation": "no",
        "TIMEOUTbusy": 20,
        "TIMEOUTclose": 0,
        "socket_options": ["l:SO_REUSEADDR=yes", "a:SO_BINDTODEVICE=lo"],
        "foreground": "yes (quiet if stunnel >= 5.25)",
    },
}

SECURITY_ANALYSIS = {
    "subprocess_audit": {
        "shell_true_sites": 1,
        "location": "optimize_readahead_window() at line ~1562",
        "code": '"echo %s > %s" % (fixed_readahead_kb, read_ahead_kb_config_file)',
        "injection_risk": "NONE",
        "analysis": (
            "fixed_readahead_kb = int(15 * int(options['rsize']) / 1024) — double int() cast. "
            "read_ahead_kb_config_file = '/sys/class/bdi/%s:%s/read_ahead_kb' % (major, minor) "
            "where major, minor are from os.stat(mountpoint).st_dev (kernel device numbers). "
            "Both values are integer-typed; shell injection is not possible."
        ),
    },
    "all_other_subprocess_calls": "list form only (no shell=True); no injection surface",
    "parse_options_bug": {
        "location": "parse_options() at line ~223",
        "code": "k, v = o.split('=')",
        "bug": (
            "str.split('=') without maxsplit=1 raises ValueError if the value contains '='. "
            "Common case: base64-encoded certificate data or query strings in mount options. "
            "The 'cert' option is a file path (validated with os.path.isabs()), unlikely to "
            "contain '='. But custom options or a cert path with '=' causes mount failure. "
            "Fix: change to o.split('=', 1) (add maxsplit=1 argument)."
        ),
        "impact": "Mount failure (DoS on mount operation); not a security vulnerability",
        "severity": "INFO",
    },
    "hmac_import": {
        "observation": "import hmac at line 38 but no hmac.* calls anywhere in the 1671-line file.",
        "conclusion": "Dead import — leftover from a removed signing feature (possibly API request signing).",
    },
    "tls_verification": {
        "options": "'verify' fstab option controls stunnel verify level (1, 2, 3)",
        "ocsp": "'ocsp' and 'noocsp' options control OCSP stapling; mutually exclusive (enforced)",
        "notls": "'notls' disables TLS entirely — NFS traffic is plaintext",
        "cafile": "CA certificate for server verification configurable via 'cafile=' option",
        "risk": (
            "If 'notls' is used in production mounts, NFS traffic is unencrypted on the wire. "
            "An on-path attacker (same cloud region fabric) can read/modify NFS file operations. "
            "The default (when 'tls' is specified) uses stunnel with client certificate auth. "
            "Security depends on operator fstab configuration — not enforced by the binary."
        ),
    },
    "privilege_model": (
        "mount.cfs runs as root (invoked by mount). It writes to /var/run/cfs/ and /var/log/cfs/. "
        "It reads the cert file specified in mount options — attacker-controlled path if an "
        "unprivileged user can write fstab (requires root normally). "
        "The tool does not drop privileges before running stunnel or the NFS mount command. "
        "stunnel runs as root (child process of mount.cfs). "
        "There are no setuid/setgid bits; the tool's privilege is inherited from mount."
    ),
    "state_file_race": (
        "Multiple concurrent mounts use a cross-process file lock (MOUNT_TLS_IP_LOCK_FILE) "
        "to serialize TLS loopback IP allocation. The lock is an fcntl.flock() exclusive lock "
        "on /var/run/cfs/.mount_tls_ip.lock. "
        "Lock is held while scanning the state directory for existing port bindings, "
        "then released after the new socket is bound. Correct TOCTOU avoidance."
    ),
}

CERT_HANDLING = {
    "fstab_option": "cert=/absolute/path/to/client.pem",
    "validation": "os.path.isabs(options['cert']) checked before use — relative paths rejected",
    "usage": "cfs_config['cert'] = options['cert'] — path written directly to stunnel config file",
    "risk": (
        "cert option allows any absolute path. If the path points to a file that is not a PEM "
        "certificate, stunnel will fail to start (graceful failure). "
        "No path traversal beyond absolute path injection, and fstab is root-owned. "
        "Not exploitable without root access to fstab."
    ),
}

WATCHDOG_SUMMARY = {
    "file": "src/watchdog/__init__.py",
    "size_lines": 1083,
    "role": (
        "Periodically checks that all cfs mounts are still alive. "
        "Reads state files from /var/run/cfs/ to find active mounts. "
        "If a mount is dead, attempts remount (re-runs mount.cfs). "
        "Runs as a systemd service (cfs-mount-watchdog.service)."
    ),
    "security_note": (
        "Watchdog runs as root. State files in /var/run/cfs/ are root-owned. "
        "If /var/run/cfs/ is world-writable, a local attacker could inject fake "
        "state files to cause the watchdog to attempt arbitrary remounts. "
        "Expected permissions: 0700 or 0750, root-owned."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "parse_options(): split('=') without maxsplit=1 — mount failure on '=' in option value",
        "detail": (
            "Line ~223: k, v = o.split('='). If any mount option value contains '=', "
            "ValueError is raised and mount fails. Affects cert= paths with '=' characters "
            "or any future option with base64 values. "
            "Fix: o.split('=', 1). No security impact; DoS on mount only."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "shell=True subprocess in optimize_readahead_window() — not injectable (int-typed vars)",
        "detail": (
            "'echo %s > %s' % (int, kernel_bdi_path). Both vars are integer-typed or "
            "kernel-device-derived. No injection path from fstab options or user input. "
            "Only shell=True site in the codebase."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "hmac imported but not used — dead import, possible removed signing feature",
        "detail": (
            "import hmac at line 38. No hmac.new() or hmac.compare_digest() calls found "
            "in 1671-line mount_cfs source. Indicates a feature removal (API request signing). "
            "If CFS API keys were previously handled here, they are no longer present."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "notls mount option disables TLS — plaintext NFS if misconfigured in fstab",
        "detail": (
            "fstab entry with 'notls' option skips stunnel and mounts NFS directly. "
            "NFS traffic is cleartext over TCP. On-path attacker in same cloud fabric can "
            "read/modify file operations. Security is operator-configuration-dependent. "
            "Default recommended option requires 'tls' with cert=."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "CFS-specific fstab mount type with client certificate auth via stunnel",
        "detail": (
            "TLS path: stunnel client on 127.0.0.x:<port> → CFS server:2050/tcp. "
            "Client cert required (cert= fstab option). Loopback IP allocation uses "
            "cross-process fcntl.flock() for TOCTOU-safe concurrent mounts. "
            "Overall design is sound; no high-severity findings."
        ),
    },
]

if __name__ == '__main__':
    print(f"TOS 4.6 cfs-utils {PACKAGE['version']}-{PACKAGE['release']} source RE")
    print(f"  Python 3, noarch, MIT license")
    print(f"  Dependencies: {', '.join(PACKAGE['dependencies'])}")
    print()
    print("Architecture:")
    for line in ARCHITECTURE['mount_flow'].split('\n'):
        print(f"  {line.strip()}")
    print()
    print("Security analysis:")
    print(f"  subprocess: 1 shell=True site (read_ahead_kb, not injectable)")
    print(f"  parse_options: split('=') bug — mount failure on '=' in value")
    print(f"  HMAC: imported, not used")
    print(f"  TLS: stunnel w/ client cert; notls option bypasses TLS")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
