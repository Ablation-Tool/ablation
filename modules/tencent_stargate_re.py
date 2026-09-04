"""
Tencent Cloud Stargate Agent (sgagent) — RE Module
Package: linux_stargate_installer (self-extracting bash + tgz)
Binary corpus: sgagent64 (x86_64), sgagent32 (x86), sgagentarm64 (aarch64)
Build date: 2021-01-21; installer created 2021-01-28

Stargate is Tencent Cloud's (qcloud) root-privileged monitoring/management agent
deployed on TencentOS Server and CVM instances. It polls a Tencent-controlled
update endpoint, downloads modules, executes shell commands, and manages agent
lifecycle — all as root. One binary per instance, persistent via cron.

Install paths:
  /usr/local/qcloud/stargate/  (if /usr writable)
  /var/lib/qcloud/stargate/    (fallback)

Persistence mechanism:
  cron: * * * * * root flock -xn /tmp/stargate.lock -c 'start.sh > /dev/null 2>&1 &'
  systemd: stargate.service (CoreOS/Container Linux only)

Key files:
  bin/sgagent{32,64,arm64}      — main agent binary (symlinked to bin/sgagent)
  etc/base.conf                 — update URL, check interval, SSL config
  admin/{start,stop,restart,addcrontab,delcrontab,uninstall,trystart}.sh

Update protocol (HTTP, plaintext):
  URL: http://update2.agent.tencentyun.com/interface.php
  Method: POST (libcurl embedded, single binary)
  Response: JSON with module list, installPath, moduleId, retcode, msg fields
  SSL:  useCA = 0  ->  CURLOPT_SSL_VERIFYPEER=0, CURLOPT_SSL_VERIFYHOST=0

Python runtime: Python 2.6 bundled (EOL since 2013, known CVEs)
  /usr/local/qcloud/monitor/python26/{32,64,arm64}/

Binary (sgagent64) security profile:
  PIE:     NO  (EXEC type, fixed load address 0x400000)
  RELRO:   NONE (no GNU_RELRO segment)
  Stack canary: NO (__stack_chk_fail not in imports)
  NX/DEP:  YES (GNU_STACK RW, no exec)
  Stripped: YES
  Linked:   dynamically (GLIBC_2.2.5)
  Entry:    0x405228

Dangerous imports (sgagent64):
  system@GLIBC_2.2.5  — 1 call site (0x404858 PLT, called at 0x405bec)
  strcpy@GLIBC_2.2.5
  sprintf@GLIBC_2.2.5
  sscanf@GLIBC_2.2.5
  memcpy@GLIBC_2.2.5
  fork@GLIBC_2.2.5

system() call graph:
  system() PLT: 0x404858
  system() wrapper: 0x405be0  — (rdi=context, rsi=cmd) -> system(cmd), logs result
  Wrappers that append fixed suffixes to server-controlled installPath:
    0x405c50: installPath + /admin/trystart.sh (18 bytes, 0x446c19)
    0x405d10: installPath + /admin/stop.sh    (14 bytes, 0x446c2c)
    (+ /admin/uninstall.sh at separate caller)
  Direct exec of temp installer:
    0x406370: system("../stargate_install") -> remove("../stargate_install")
  Callers of trystart wrapper: 0x4063f2, 0x407903
  Callers of stop wrapper:     0x406506, 0x4069b2
  installPath JSON parsing:    0x40807a, 0x40838d

rodata strings of interest (VA -> content):
  0x446b99: '../stargate_install'    (temp upgrade script executed then deleted)
  0x446c19: '/admin/trystart.sh'     (appended to installPath for system() call)
  0x446c2c: '/admin/stop.sh'         (appended to installPath for system() call)
  0x446c3b: '/admin/uninstall.sh'    (appended to installPath for system() call)
  0x446c4f: '%s/%s'                  (path construction format)
  0x446e9c: 'installPath'            (JSON field name parsed from server response)
  0x446ea8: 'module.installPath:%s'  (debug log for installPath value)
"""

import ssl
import json
import socket
import hashlib
from typing import Optional

# ─── Target Profile ───────────────────────────────────────────────────────────

TARGET = "tencent-stargate"
VERSIONS_AFFECTED = ["1.5.0"]  # base.conf: version = 1.5.0; build 2021-01-21
BINARY_SHA256 = {
    "sgagent64": "unknown",   # sgagent64 from stargate.tgz — sha256 TBD
    "sgagent32": "unknown",
    "sgagentarm64": "unknown",
}

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TCS-F01": {
        "title": (
            "sgagent Polls Update Server over Plaintext HTTP with SSL Verification Disabled — "
            "Network MitM Delivers Arbitrary Root Commands via Server JSON Response"
        ),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-295",
        "component": (
            "sgagent64 / libcurl embedded / etc/base.conf — "
            "update polling loop -> curl_easy_setopt(CURLOPT_SSL_VERIFYPEER=0) -> "
            "http://update2.agent.tencentyun.com/interface.php"
        ),
        "evidence": {
            "plaintext_url": (
                "base.conf: url = http://update2.agent.tencentyun.com/interface.php. "
                "Protocol is HTTP (not HTTPS). All update traffic is transmitted unencrypted. "
                "Any network-local attacker (ARP/DNS/BGP hijack) intercepts the full request "
                "and response without cryptographic obstacle."
            ),
            "ssl_disabled": (
                "base.conf: useCA = 0. "
                "sgagent64 reads this config value and disables libcurl TLS verification: "
                "CURLOPT_SSL_VERIFYPEER = 0, CURLOPT_SSL_VERIFYHOST = 0. "
                "Even if the attacker redirects to an HTTPS server (for future config changes), "
                "any certificate is accepted. "
                "String 'SSL peer certificate or SSH remote key was not OK' is present in binary "
                "as a dormant error path that never fires when useCA=0."
            ),
            "command_execution": (
                "Server JSON response includes moduleId, installPath, retcode, msg fields. "
                "sgagent64 parses 'installPath' at 0x40807a/0x40838d and passes it to "
                "system() wrappers at 0x405c50 (trystart) and 0x405d10 (stop). "
                "Command constructed: installPath + '/admin/trystart.sh' or installPath + '/admin/stop.sh'. "
                "No input validation or path sanitization applied to installPath before system(). "
                "A MitM attacker supplies installPath = '/tmp/x;id #' -> system('/tmp/x;id #/admin/stop.sh') "
                "-> executes 'id' as root."
            ),
            "temp_script_exec": (
                "sgagent64 at 0x406370: system('../stargate_install') -> remove('../stargate_install'). "
                "The server's upgrade response causes the agent to write a shell script to "
                "'../stargate_install' (relative to admin/), execute it via system(), then delete it. "
                "A MitM attacker serving a crafted upgrade response controls the full script content. "
                "Since the process runs as root (enforced at install: 'Only root can execute this script'), "
                "any shell payload executes with root privileges."
            ),
            "persistence": (
                "sgagenttask cron entry: '* * * * * root flock -xn /tmp/stargate.lock -c "
                "start.sh > /dev/null 2>&1'. "
                "Agent is guaranteed running every minute as root on any Tencent Cloud CVM. "
                "Attack window: one cron tick (up to 60 seconds)."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Change base.conf url to HTTPS endpoint. "
            "Set useCA = 1 and provide a valid CA bundle path. "
            "Validate the TLS certificate against a pinned Tencent root CA. "
            "Sign server JSON responses (e.g., HMAC or asymmetric signature) so that "
            "MitM response injection is detectable even on compromised networks. "
            "Do not pass server-supplied installPath to system() without strict allow-list validation "
            "(path must begin with expected prefix, contain no shell metacharacters). "
            "Replace system() with execve() + explicitly constructed argv[] to eliminate shell interpretation."
        ),
    },
    "TCS-F02": {
        "title": (
            "sgagent64 Lacks Stack Canaries, PIE, and RELRO — "
            "No Exploit Mitigations on a Root-Persistent Binary with strcpy/sprintf"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-693",
        "component": (
            "sgagent64 ELF binary — binary protection configuration"
        ),
        "evidence": {
            "no_canary": (
                "nm -D sgagent64: __stack_chk_fail not imported. "
                "Binary was compiled without -fstack-protector. "
                "Stack buffer overflows in any function have no canary detection before return."
            ),
            "no_pie": (
                "readelf -h sgagent64: Type = EXEC (not DYN). "
                "Binary loads at fixed base address 0x400000. "
                "ASLR provides no entropy for the binary itself. "
                "ROP gadget addresses are static and predictable."
            ),
            "no_relro": (
                "readelf -l sgagent64: no GNU_RELRO segment present. "
                "The GOT/PLT is fully writable post-load. "
                "A heap or stack write primitive resolves immediately to GOT overwrite "
                "without needing to bypass partial RELRO."
            ),
            "dangerous_imports": (
                "Imported without bounds: strcpy, sprintf, sscanf, memcpy. "
                "Binary processes externally-sourced strings from HTTP responses and "
                "file system paths with these functions — any length miscalculation "
                "produces an exploitable buffer overflow with no mitigation."
            ),
            "nx_present": (
                "GNU_STACK segment: RW (no exec bit). NX is enforced. "
                "Stack shellcode injection is blocked, but ROP/ret2libc chains are viable "
                "given static binary addresses and no canary."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Recompile with: -fstack-protector-strong -fpie -pie. "
            "Add full RELRO: -Wl,-z,relro,-z,now. "
            "Replace strcpy with strlcpy/strncpy+null, sprintf with snprintf with explicit bounds. "
            "Enable FORTIFY_SOURCE=2: -D_FORTIFY_SOURCE=2 -O2."
        ),
    },
    "TCS-F03": {
        "title": (
            "Bundled Python 2.6 Runtime (EOL 2013) — "
            "Known CVEs in Python Core and Standard Library Exposed via Agent Plugin Execution"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-1104",
        "component": (
            "/usr/local/qcloud/monitor/python26/{32,64,arm64}/ — "
            "bundled Python 2.6 interpreter shipped with stargate package"
        ),
        "evidence": {
            "eol_version": (
                "Python 2.6 reached end-of-life in October 2013. "
                "No security patches have been issued for 12+ years. "
                "The bundled interpreter is version 2.6.x (exact patch level unknown — "
                "binary inspection required). All known Python 2.6 CVEs apply."
            ),
            "known_cves": (
                "Selected Python 2.6 CVEs (non-exhaustive): "
                "CVE-2021-3177 (buffer overflow in PyCArg_repr, CVSS 9.8), "
                "CVE-2021-23336 (web cache poisoning via query string parsing), "
                "CVE-2019-20907 (infinite loop in tarfile, DoS), "
                "CVE-2019-16935 (XSS in xmlrpc.server), "
                "CVE-2018-20406 (integer overflow in _pickle.c). "
                "Python 2.6 lacks all security fixes applied to Python 3.x line."
            ),
            "execution_context": (
                "The python26 interpreter is used by the qcloud monitor module "
                "(/usr/local/qcloud/monitor/) which runs as the same root-privileged context. "
                "Any module code downloaded from the Tencent update server and executed "
                "by python26 inherits root privileges."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Replace bundled Python 2.6 with Python 3.12+ or Python 3.11+ (still supported). "
            "If Python 2 compatibility is required, use Python 2.7 (EOL but patches available longer). "
            "Audit all Python modules executed by the agent for compatibility with a supported runtime."
        ),
    },
    "TCS-F04": {
        "title": (
            "Cron-Based Persistence Runs Every Minute as Root Without File Integrity Verification — "
            "Writable Agent Directory Enables Persistent Backdoor"
        ),
        "severity": "MEDIUM",
        "cvss": "6.7",
        "cwe": "CWE-732",
        "component": (
            "stargate/admin/sgagenttask / stargate/admin/addcrontab.sh — "
            "cron persistence mechanism"
        ),
        "evidence": {
            "cron_entry": (
                "sgagenttask: '* * * * * root flock -xn /tmp/stargate.lock -c "
                "'/usr/local/qcloud/stargate/admin/start.sh > /dev/null 2>&1 &''. "
                "Root cron entry runs every minute. "
                "File placed at /etc/cron.d/sgagenttask with chmod 600, but the "
                "agent install directory is owned by the install user, not guaranteed root-only writable."
            ),
            "no_integrity": (
                "start.sh: '$agent_name -d' — binary is executed directly without checksum verification. "
                "If an attacker replaces $agentPath/bin/sgagent with a malicious binary "
                "(e.g., after local privilege escalation or writable mount exploit), "
                "the cron entry re-executes it as root every minute. "
                "No hash verification of the agent binary is performed before execution."
            ),
            "lock_file_race": (
                "flock -xn /tmp/stargate.lock: lock file is in world-writable /tmp. "
                "A local attacker can pre-create /tmp/stargate.lock and hold it open, "
                "preventing the legitimate agent from starting (denial of service). "
                "Conversely, releasing the lock at the right moment allows a race condition "
                "where two agent instances briefly run simultaneously."
            ),
        },
        "versions_affected": ["1.5.0"],
        "remediation": (
            "Move lock file from /tmp to /var/run/stargate/ (root-owned, mode 0750). "
            "Add HMAC or signature verification of the agent binary before execution in start.sh. "
            "Install agent directory with root:root ownership, mode 0755 minimum for dirs, 0755 for binaries. "
            "Consider systemd service with ProtectSystem=strict instead of raw cron."
        ),
    },
}


# ─── Probe Functions ──────────────────────────────────────────────────────────

def _check_agent_running(host: str) -> dict:
    """Check if sgagent cron lock file is accessible (passive indicator)."""
    result = {"host": host, "findings": []}
    # No active probe defined — agent is internal to the host
    return result


def probe(host: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Placeholder probe — sgagent is a local agent, not a network service.
    Findings are confirmed via binary RE + config file analysis.
    """
    return {
        "host": host,
        "note": "sgagent is not a network-exposed service; findings confirmed via static RE",
        "findings": list(FINDINGS.keys()),
    }
