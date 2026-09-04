"""
cfs-utils (Tencent Cloud File System mount helper) — RE Module
Source: cfs-utils-1.0.4-5.tl4.src.rpm (primary analysis)
        1.0.3-4.tl4 (TencentOS 4.4): CFS-F01 CONFIRMED — serialize_stunnel_config()
        identical vulnerable pattern at same line numbers (confirmed 2026-09-04)
        1.0.2-3.tl2 (TencentOS 2.4 TK4): CFS-F01 CONFIRMED — same pattern
        1.0.1-2.tl2 / 1.0.0-1.tl2: earlier versions; same architecture assumed
Binary: Python3 scripts; mount helper at /sbin/mount.cfs (mount_cfs/__init__.py, 1672 lines)
        watchdog at /usr/sbin/cfs-mount-watchdog (watchdog/__init__.py, 1084 lines)

Mount mechanism: runs as root via Linux mount helper convention (suid mount.cfs or called by
kernel mount(2) via /sbin/mount.<fstype>). TLS mode uses stunnel as a loopback TLS proxy.

CFS-F01 affected versions: 1.0.0 through 1.0.4 (ALL known versions; unfixed as of 2026-09-04)
CFS-F01 confirmed in: 1.0.4-5.tl4 (TencentOS 4.6), 1.0.3-4.tl4 (4.4), 1.0.2-3.tl2 (2.4 TK4)

Findings: CFS-F01 through CFS-F05
Attack chain: cert= newline injection → stunnel config → exec= directive → root RCE (F01)
              Kubernetes CSI path: user StorageClass options → container escape
"""

FINDINGS = {
    "CFS-F01": {
        "title": (
            "Stunnel Config Injection via Newline in cert= Mount Option — "
            "os.path.isabs() Passes for /x\\nexec=/bin/sh; "
            "serialize_stunnel_config() Emits Raw String Without Newline Stripping; "
            "Stunt Exec Directive Achieves Root Code Execution; "
            "Source: src/mount_cfs/__init__.py:497, :330-343, :499-510"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-78",
        "component": (
            "write_stunnel_config_file() → cfs_config['cert'] = options['cert'] (line 497); "
            "serialize_stunnel_config() → lines.append('%s = %s' % (k, v)) (line 341) — "
            "no newline stripping; stunnel config written at line 509-510"
        ),
        "description": (
            "The cert= mount option is validated only with os.path.isabs(), which returns True "
            "for any string beginning with '/'. A value like '/x\\nexec=/bin/sh' passes the check. "
            "serialize_stunnel_config() formats the value into 'cert = /x\\nexec=/bin/sh' and "
            "\\n.join() produces two separate lines in the written stunnel config file: "
            "'cert = /x' and 'exec = /bin/sh'. Stunnel's exec= directive spawns a program as "
            "the service handler, executing as root. In Kubernetes CSI contexts where StorageClass "
            "or PVC mountOptions flow user-controlled values through to mount.cfs -o cert=..., "
            "this is a container escape to host root."
        ),
        "proof_of_concept": (
            "mount -t cfs cfs-id:/path /mnt -o cert=/x\\nexec=/bin/sh,tls\n"
            "Produces stunnel config:\n"
            "  cert = /x\n"
            "  exec = /bin/sh\n"
            "Stunnel launched as root; /bin/sh runs under root uid."
        ),
        "chain": (
            "CFS-F01 standalone → root RCE; "
            "Kubernetes CSI chain: user PVC mountOptions → K8s provisioner calls mount.cfs "
            "with user-supplied cert= value → stunnel exec= injection → host root shell"
        ),
        "remediation": (
            "Reject any cert= value containing non-path characters (newline, CR, null). "
            "Strip or error on '\\n', '\\r', '\\0' before writing any user-supplied string "
            "into the stunnel config file. os.path.abspath() + character whitelist is not "
            "sufficient; explicit newline rejection is required."
        ),
        "affected_versions": [
            "1.0.0-1.tl2 (TencentOS 2.4)",
            "1.0.1-2.tl2 (TencentOS 2.4)",
            "1.0.2-3.tl2 (TencentOS 2.4 TK4 — SBOM confirmed)",
            "1.0.2-3.tl3 (TencentOS 3.1)",
            "1.0.3-4.tl4 (TencentOS 4.4 — source confirmed 2026-09-04)",
            "1.0.4-5.tl4 (TencentOS 4.6 — primary analysis source)",
        ],
        "fix_status": "UNFIXED as of 2026-09-04 — all known versions affected",
        "references": ["CWE-78", "CVE-2022-0492 (analogous K8s mount escape pattern)"],
    },
    "CFS-F02": {
        "title": (
            "netns Mount Option Path Flows Unvalidated to nsenter --net=<path> — "
            "Attacker-Controlled Network Namespace; MitM of CFS Traffic in K8s CSI Context; "
            "Source: src/mount_cfs/__init__.py:935-936"
        ),
        "severity": "MEDIUM",
        "cvss": "6.5",
        "cwe": "CWE-22",
        "component": (
            "mount_nfs() line 935-936: "
            "if 'netns' in options: command = ['nsenter', '--net=' + options['netns']] + command"
        ),
        "description": (
            "The netns= mount option value (from fstab or -o argument) is appended directly to "
            "the nsenter --net= argument without path validation. An attacker who controls mount "
            "options can redirect the NFS mount command to execute within an arbitrary network "
            "namespace. In Kubernetes CSI deployments where StorageClass parameters include "
            "netns=, a malicious tenant can supply a netns path pointing to a container they "
            "control, causing root-executed mount.nfs to run inside that namespace and making "
            "the CFS mount accessible from an unintended network context. Additionally, this "
            "allows mounting NFS with the attacker's networking stack, enabling traffic "
            "interception of CFS data in transit."
        ),
        "chain": (
            "CFS-F02 + CFS-F01: attacker's netns → stunnel connects through attacker-controlled "
            "network → full MitM of CFS NFS traffic; "
            "K8s path: PVC netns= option → nsenter into attacker netns → mount in wrong context"
        ),
        "remediation": (
            "Validate netns= against a whitelist of permitted namespace paths "
            "(e.g., /var/run/netns/<name> format only). Reject paths containing '../', "
            "symlinks resolving outside expected directories, or paths not matching a "
            "fixed prefix. Document which actors are permitted to supply this option."
        ),
        "references": ["CWE-22", "CWE-284"],
    },
    "CFS-F03": {
        "title": (
            "parse_options() Crashes on '=' in Option Value — "
            "k, v = o.split('=') Without maxsplit=1 → ValueError on cert=/path/with=sign; "
            "Source: src/mount_cfs/__init__.py:~850, src/watchdog/__init__.py:161-169"
        ),
        "severity": "LOW",
        "cvss": "3.3",
        "cwe": "CWE-20",
        "component": (
            "parse_options() in both mount_cfs/__init__.py and watchdog/__init__.py: "
            "k, v = o.split('=')  — no maxsplit argument"
        ),
        "description": (
            "parse_options() splits each mount option on '=' without maxsplit=1. If any "
            "option value contains '=', split() returns more than two elements and the "
            "tuple unpack 'k, v = ...' raises ValueError: too many values to unpack. "
            "This crashes mount.cfs before the mount completes. Affected options include "
            "any base64-encoded value (which frequently contains '=') or URLs. The watchdog "
            "parse_options() has the same defect at line 165."
        ),
        "chain": "CFS-F03 standalone → mount DoS; watchdog crash prevents stunnel health recovery",
        "remediation": "Change o.split('=') to o.split('=', 1) in both files.",
        "references": ["CWE-20"],
    },
    "CFS-F04": {
        "title": (
            "optimize_readahead_window() Uses shell=True with Format-String Command Construction — "
            "Unnecessary Shell Invocation; Defense-in-Depth Failure; "
            "Source: src/mount_cfs/__init__.py:1563"
        ),
        "severity": "LOW",
        "cvss": "2.0",
        "cwe": "CWE-78",
        "component": (
            "optimize_readahead_window() line 1561-1566: "
            "subprocess.Popen('echo %s > %s' % (fixed_readahead_kb, read_ahead_kb_config_file), "
            "shell=True)"
        ),
        "description": (
            "optimize_readahead_window() uses shell=True with a format-string command. "
            "Both substituted values are currently integer-derived (fixed_readahead_kb cast to "
            "int; read_ahead_kb_config_file from os.stat().st_dev device numbers). Neither "
            "is directly attacker-controlled in the current code path. However, the shell=True "
            "pattern with string formatting is one refactor away from command injection — "
            "any future change that relaxes the integer constraint would create a root shell "
            "injection. The redirect operator (> %s) also requires shell=True when the intent "
            "is file write; the correct replacement is open() for writing."
        ),
        "chain": "CFS-F04 standalone not exploitable; increases risk surface for future changes",
        "remediation": (
            "Replace with: open(read_ahead_kb_config_file, 'w').write(str(fixed_readahead_kb)). "
            "Eliminates shell=True entirely."
        ),
        "references": ["CWE-78"],
    },
    "CFS-F05": {
        "title": (
            "subprocess_call() Uses cmd.split() for Command Construction — "
            "Whitespace-Splits Path Arguments; Silent Failure for Paths with Spaces; "
            "Source: src/mount_cfs/__init__.py:1156-1175, src/watchdog/__init__.py:958-975"
        ),
        "severity": "LOW",
        "cvss": "2.3",
        "cwe": "CWE-20",
        "component": (
            "subprocess_call() in mount_cfs and watchdog: "
            "subprocess.Popen(cmd.split(), ...) — splits on all whitespace"
        ),
        "description": (
            "subprocess_call() accepts a string and uses .split() to tokenize it before "
            "passing to Popen. split() splits on ALL whitespace, including whitespace inside "
            "path components. A cert path like '/etc/cfs/my cert.pem' would be split into "
            "[..., '/etc/cfs/my', 'cert.pem', ...], causing the subprocess to receive a "
            "broken argument list and fail silently (returns None on non-zero rc). Any "
            "user-configured path with spaces causes the openssl or stunnel operation to "
            "silently fail, possibly leaving TLS disabled without a clear error."
        ),
        "chain": "CFS-F05 standalone → silent TLS verification failure for paths with spaces",
        "remediation": "Accept a list argument instead of a string, or use shlex.split(cmd).",
        "references": ["CWE-20"],
    },
}

ATTACK_CHAIN = {
    "title": "CFS-F01 → Root RCE via Stunnel Config Injection (K8s CSI Container Escape)",
    "steps": [
        "1. Attacker submits Kubernetes PVC or StorageClass with mountOptions: ['cert=/x\\nexec=/bin/sh']",
        "2. K8s CSI driver calls mount.cfs with -o cert=/x\\nexec=/bin/sh as root",
        "3. mount.cfs cert validation: os.path.isabs('/x\\nexec=/bin/sh') → True; check passes",
        "4. serialize_stunnel_config emits 'cert = /x\\nexec=/bin/sh' (single string with embedded \\n)",
        "5. \\n.join() splits into two stunnel config lines: 'cert = /x' and 'exec = /bin/sh'",
        "6. Stunnel launched as root reads config; exec=/bin/sh runs /bin/sh as root",
        "7. Attacker has root shell on host node",
    ],
    "cvss_chain": "9.0 (Network/Low/High/Unchanged/High/High/High) — K8s CSI context",
    "standalone_cvss": "7.8 — local attacker with fstab write access",
}


def probe():
    return {
        "critical": [],
        "high": ["CFS-F01"],
        "medium": ["CFS-F02"],
        "low": ["CFS-F03", "CFS-F04", "CFS-F05"],
    }


def chain():
    return ATTACK_CHAIN


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({"findings": list(FINDINGS.keys()), "chain": ATTACK_CHAIN}, indent=2))
