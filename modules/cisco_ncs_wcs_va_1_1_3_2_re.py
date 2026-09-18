"""
Cisco NCS/WCS Virtual Appliance 1.1.3.2 RE Module
Target: wcs-va-1.1.3.2.qcow2 (6.4GB, converted from WCS-VA-1.1.3.2-large-disk1.vmdk)
Source: NCS-VA-1.1.3.2-large.ova (OVA contains WCS-VA-1.1.3.2-large-disk1.vmdk)

OVF product: Cisco Prime Network Control System Virtual Appliance 1.1.3.2
OS: Red Hat Enterprise Linux Server 5.4 (Tikanga), RHEL5 EOL since November 2020
Architecture: x86-64

LVM volume group: smosvg
  rootvol     1.9GB  /              (analyzed)
  optvol    293GB    /opt           (analyzed: /opt/system + /opt/oracle)
  varvol      1.9GB  /var           (analyzed)
  storeddatavol 9.8GB /storeddata   (analyzed: contains NCS.tar.gz to-install)
  localdiskvol 58.6GB /localdisk
  usrvol      6.8GB  /usr
  home         96MB  /home
  recvol       96MB  (recovery)
  altrootvol   96MB  (alternate root)
  tmpvol      1.9GB  /tmp
  swapvol    15.6GB  swap

Platform: Cisco ADE-OS (Application Deployment Engine OS)
ADE-OS also ships in: Cisco WSA (IronPort), ESA (IronPort), SMA (IronPort)
  The ADE-OS setuid chain and restricted shell are shared across all Cisco ADE appliances.

Relationship to prior modules:
  - /storeddata/ToInstall/NCS.tar.gz contains NetworkControlSystem-1.1.3.2-1.x86_64.rpm
    = same RPM analyzed in cisco_ncs_va_1_1_3_2_re.py, cisco_ncs_https_auth_re.py,
      cisco_ncs_cars_infrastructure_re.py, cisco_ncs_remoting_rce_re.py,
      cisco_ncs_webapp_re.py
    All NCS-RPM findings apply post-install on this VA.
  - This module documents ADE-OS layer findings not present in the RPM analysis.

Key files:
  /etc/shadow:          root:$1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX.
  /etc/sshd_config:     PasswordAuthentication yes; PermitRootLogin default (yes)
  /opt/system/bin/:     6 setuid root binaries (all 2011-03-25)
  /etc/init.d/install_apps: on-boot app installer with unquoted $app variable
  /etc/init.d/debugd:   ADE-OS debug daemon via FIFO /opt/system/etc/debugd-fifo
  /opt/system/bin/init_startupconfig.sh: dynamically creates setuid fdisk at /opt/system/bin/root_fdisk
  /opt/system/bin/writemem.sh: tmpfile /tmp/wrmem$$ predictable TOCTOU

Setuid root binaries (/opt/system/bin/, all root:root, 2011-03-25):
  firewall       rwsr-sr-x 34320B   (also setgid root)
  vsh-mergetree  rwsr-xr-x 36376B
  carssh         rwsr-xr-x 319912B  (VSH restricted shell -- primary user shell)
  root_netstat   rwsr-xr-x 4280B
  cars_udi_util  rwsr-xr-x 507080B
  setup          rwsr-sr-x 12480B   (also setgid root)

install_apps init script (chkconfig 2345 12 90):
  for i in `find /storeddata/ToInstall -type f`
  do
      app=`basename $i | awk -F. '{print $1}'`
      echo "Installing $app ... " > /dev/tty
      /opt/system/bin/carsInstallPkg $app SystemDefaultPkgRepos 2>&1
  done

  Injection path: filename with spaces/; in basename (before first dot) ->
  unquoted $app expands as shell words in carsInstallPkg call.

init_startupconfig.sh (runs at boot via carssh -f startup-commands):
  if [ ! -f /opt/system/bin/root_fdisk ] ; then
    /bin/cp -f /sbin/fdisk /opt/system/bin/root_fdisk
    /bin/chmod u+s /opt/system/bin/root_fdisk
  fi

writemem.sh TOCTOU:
  TMPFILE=/tmp/wrmem$$
  /opt/system/bin/carssh -s /opt/system/etc/carscli/default/main_tree.par -f $TMPFILE
  Race window between tmpfile creation and carssh read.

secureCopy.exp CLI args pattern:
  Usage: SecureBackupCopy [list|put|get] hostname username password destinationDir localLocation
  Password passed as CLI argument -> visible in /proc/*/cmdline
"""

METADATA = {
    "target": "wcs-va-1.1.3.2.qcow2",
    "ova_source": "NCS-VA-1.1.3.2-large.ova",
    "platform": "Cisco ADE-OS (Application Deployment Engine OS)",
    "os": "RHEL 5.4 (EOL 2020-11-30)",
    "ncs_version": "1.1.3.2",
    "root_hash": "$1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX.",
    "root_hash_algorithm": "MD5-crypt ($1$)",
    "root_hash_matches_ncs_rpm": True,
    "storeddata_package": "NCS.tar.gz (811MB, contains NetworkControlSystem-1.1.3.2-1.x86_64.rpm)",
    "setuid_binaries": [
        "firewall (rwsr-sr-x, 34320B, 2011)",
        "vsh-mergetree (rwsr-xr-x, 36376B, 2011)",
        "carssh (rwsr-xr-x, 319912B, 2011)",
        "root_netstat (rwsr-xr-x, 4280B, 2011)",
        "cars_udi_util (rwsr-xr-x, 507080B, 2011)",
        "setup (rwsr-sr-x, 12480B, 2011)",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "title": "WCS-VA and NCS-VA Share Identical Fleet-Wide Root Hash (MD5-crypt $1$2Ye/mXie$)",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1188",
        "description": (
            "The WCS-VA 1.1.3.2 root shadow hash is identical to the NCS-VA 1.1.3.2 hash "
            "documented in cisco_ncs_va_1_1_3_2_re.py F5. "
            "WCS-VA /etc/shadow root entry: $1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX. "
            "NCS-VA hash (from RPM analysis): $1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX. (identical) "
            "Same salt ($2Ye/mXie$), same hash, same algorithm (MD5-crypt $1$). "
            "This is the same password shipped in the RPM and the VA simultaneously. "
            "Impact: "
            "(1) Cross-product scope: any attacker who cracks or knows the NCS root password "
            "also has the WCS-VA root password. Both products share one fleet-wide root credential. "
            "(2) SSH reachability: sshd_config has PasswordAuthentication=yes (explicit) and "
            "PermitRootLogin is not set (RHEL5 sshd default = yes). SSH root login with "
            "password auth is active. "
            "(3) The NCS.tar.gz in /storeddata/ToInstall adds ftp-user:ftp-user (from "
            "cisco_ncs_va_1_1_3_2_re.py F6) on installation, extending the credential exposure. "
            "WCS and NCS are distinct products with separate install paths but share one root hash "
            "for all deployments of either product at version 1.1.3.2."
        ),
        "root_hash": "$1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX.",
        "hash_algorithm": "MD5-crypt ($1$)",
        "ssh_config": "PasswordAuthentication yes; PermitRootLogin yes (default)",
        "cross_product_match": "cisco_ncs_va_1_1_3_2_re.py F5",
        "impact": [
            "SSH root login with hardcoded fleet password to all WCS-VA and NCS-VA 1.1.3.2 deployments",
            "Same hash: crack once, compromise all WCS+NCS deployments of this version",
        ],
    },
    {
        "id": "F2",
        "title": "install_apps Boot Script Unquoted Shell Variable Allows Command Injection via Filename",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "description": (
            "/etc/init.d/install_apps (chkconfig 2345 12 90, runs early in every boot) iterates "
            "over files in /storeddata/ToInstall and installs each package: "
            "  for i in `find /storeddata/ToInstall -type f` "
            "  do "
            "      app=`basename $i | awk -F. '{print $1}'` "
            "      /opt/system/bin/carsInstallPkg $app SystemDefaultPkgRepos 2>&1 "
            "  done "
            "The $app variable is unquoted in the carsInstallPkg call and is derived from "
            "the filename's first field before the dot separator. "
            "Attack vector: create a file in /storeddata/ToInstall with a filename whose "
            "base name (before the first dot) contains shell metacharacters. "
            "Example: a file named 'foo; chmod u+s /bin/bash .tar' causes: "
            "    carsInstallPkg foo; chmod u+s /bin/bash  SystemDefaultPkgRepos "
            "to execute as a shell command at the next boot. "
            "Write access prerequisite: "
            "(1) After NCS is installed, the ftp-user:ftp-user account from "
            "    cisco_ncs_va_1_1_3_2_re.py F6 may have write access to /storeddata "
            "    depending on vsftpd chroot configuration. "
            "(2) Any local command execution primitive (from other NCS modules) that runs "
            "    as any user with /storeddata write permission chains here. "
            "Timing: the injection executes early (priority 12) in every boot cycle. "
            "The carsInstallPkg binary itself is not at risk from this path; the risk is "
            "the unquoted expansion before the binary is even called, which is interpreted "
            "by the shell (/bin/bash executing the init script as root)."
        ),
        "affected_script": "/etc/init.d/install_apps",
        "chkconfig": "2345 12 90",
        "injection_line": "/opt/system/bin/carsInstallPkg $app SystemDefaultPkgRepos 2>&1",
        "prerequisite": "write access to /storeddata/ToInstall",
        "triggers": "every boot in runlevels 2-5",
        "impact": [
            "Persistent root code execution at boot via malicious filename in /storeddata/ToInstall",
            "Chains with ftp-user:ftp-user write access if vsftpd allows /storeddata paths",
        ],
    },
    {
        "id": "F3",
        "title": "Six Setuid Root ADE-OS Binaries on RHEL5 EOL (Unpatched Since 2011)",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "description": (
            "Six /opt/system/bin/ binaries have setuid root permissions (all dated 2011-03-25): "
            "  firewall      rwsr-sr-x 34320B  (also setgid root) "
            "  vsh-mergetree rwsr-xr-x 36376B "
            "  carssh        rwsr-xr-x 319912B (VSH restricted shell, primary user shell) "
            "  root_netstat  rwsr-xr-x 4280B "
            "  cars_udi_util rwsr-xr-x 507080B "
            "  setup         rwsr-sr-x 12480B  (also setgid root) "
            "All binaries are stripped ELF64 built for GNU/Linux 2.4.0. "
            "Platform is RHEL5 (EOL 2020-11-30) with no patch path since at least 2013 "
            "(when Cisco ceased NCS updates). "
            "Primary risk: carssh is the ADE-OS restricted shell (Cisco VSH). "
            "Any VSH escape vulnerability gives root via setuid. "
            "Known VSH escape patterns on Cisco ADE-OS: "
            "(1) Shell metacharacter injection in VSH command parameters "
            "(2) tcpdump output redirect to root-writable path "
            "(3) Certain show/debug commands that call popen() with user-controlled args "
            "Secondary risks: "
            "setup (12480B) calls system(), execl(), /bin/bash, and /opt/system/bin/writemem.sh "
            "with setuid+setgid. Any argument injection or environment manipulation (PATH, LD_PRELOAD) "
            "on setup escalates to root. "
            "init_startupconfig.sh called at boot creates a SEVENTH setuid binary: "
            "  /bin/cp -f /sbin/fdisk /opt/system/bin/root_fdisk "
            "  /bin/chmod u+s /opt/system/bin/root_fdisk "
            "fdisk (root_fdisk) is then setuid root and accessible to non-root users. "
            "On RHEL5 with no mitigations (no ASLR enforcement, no stack canaries in these 2011 builds), "
            "memory corruption in any setuid binary is directly exploitable to root."
        ),
        "setuid_binaries": {
            "firewall": "rwsr-sr-x 34320B, iptables-restore wrapper, reads /opt/system/etc/fw/iptables",
            "vsh-mergetree": "rwsr-xr-x 36376B, merges VSH par files",
            "carssh": "rwsr-xr-x 319912B, VSH restricted shell (escape = root)",
            "root_netstat": "rwsr-xr-x 4280B, execve netstat -nlp hardcoded (safe wrapper)",
            "cars_udi_util": "rwsr-xr-x 507080B, stripped, unknown attack surface",
            "setup": "rwsr-sr-x 12480B, calls system()+execl()+/bin/bash",
        },
        "runtime_setuid": "root_fdisk (/bin/cp -f /sbin/fdisk + chmod u+s) created by init_startupconfig.sh",
        "impact": [
            "VSH escape in carssh -> root (via setuid)",
            "setup system()/execl() injection -> root+setgid (via setuid+setgid)",
            "cars_udi_util 507KB stripped binary - unknown attack surface",
            "RHEL5 EOL: no patches since 2013; no upstream security fixes available",
        ],
    },
    {
        "id": "F4",
        "title": "writemem.sh Predictable TOCTOU Tmpfile (/tmp/wrmem$$) with carssh -f Execution",
        "severity": "MEDIUM",
        "cvss": 6.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-377",
        "description": (
            "/opt/system/bin/writemem.sh is called from the setuid carssh context to save "
            "running configuration. It creates a predictable temporary file: "
            "  TMPFILE=/tmp/wrmem$$ "
            "  echo 'write memory' > $TMPFILE "
            "  /opt/system/bin/carssh -s /opt/system/etc/carscli/default/main_tree.par -f $TMPFILE "
            "  rm -f $TMPFILE "
            "The variable $$ is the shell's PID. On a single-user appliance, PIDs are predictable "
            "within a bounded range. "
            "TOCTOU attack path: "
            "(1) Attacker predicts the next PID that will be used when writemem.sh runs "
            "(2) Attacker pre-creates /tmp/wrmem<predicted_pid> as a symlink to a target file "
            "    (e.g., /etc/cron.d/backdoor, /etc/passwd) "
            "(3) When writemem.sh executes, 'echo write memory' dereferences the symlink and "
            "    writes 'write memory' to the target file "
            "(4) The write clobbers/appends to root-owned files "
            "The -f flag to carssh tells it to read commands from a file. Since carssh is "
            "setuid, the file it reads executes with root privileges in the VSH context. "
            "A pre-created symlink that points to an attacker-controlled file (not a root-owned "
            "target) allows the attacker to inject arbitrary VSH commands into the carssh execution "
            "with setuid root, potentially using VSH commands that exec() programs. "
            "Exploitability depends on VSH escape capability (see F3)."
        ),
        "affected_script": "/opt/system/bin/writemem.sh",
        "tmpfile_pattern": "/tmp/wrmem<pid>",
        "pid_predictability": "Sequential PIDs on single-task appliance = narrowly bounded prediction",
        "impact": [
            "Arbitrary file write via symlink at /tmp/wrmem<pid> -> clobber root-owned files",
            "VSH command injection via symlink -> setuid carssh executes injected commands",
        ],
    },
    {
        "id": "F5",
        "title": "ADE-OS secureCopy.exp SSH Password in Process Command Line",
        "severity": "LOW",
        "cvss": 3.9,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-214",
        "description": (
            "/opt/system/bin/secureCopy.exp is an Expect script used for ADE-OS backup "
            "file transfers. The script accepts SSH credentials as positional arguments: "
            "  Usage: SecureBackupCopy [list|put|get] hostname username password destinationDir localLocation "
            "The password is passed in clear text as $4 on the command line. During the SCP "
            "transfer, the process is visible in /proc/*/cmdline with the password as plaintext "
            "to any process that can read /proc (any local user or process). "
            "This follows the same pattern as before_backup.sh from the NCS RPM module "
            "(cisco_ncs_https_auth_re.py F4): DBPASSWD in CLI args, visible in /proc. "
            "secureCopy.exp passes the password to the SSH/SCP password prompt via Expect's "
            "send/expect mechanism ($pass variable) -- the password is never written to disk, "
            "but it's visible in the process table during the transfer window. "
            "Risk: any process with /proc read access (local code execution from any "
            "NCS vulnerability) can harvest SSH credentials from the backup process."
        ),
        "affected_script": "/opt/system/bin/secureCopy.exp",
        "password_position": "argv[4] (command-line argument, visible in /proc/*/cmdline)",
        "exposure_window": "Duration of SCP transfer (seconds to minutes)",
        "impact": [
            "/proc/*/cmdline readable by local processes -> SSH password exposure during backup",
            "Chains with any local code execution from NCS web/remoting vulnerabilities",
        ],
    },
]

SUMMARY = {
    "total":    5,
    "critical": 1,
    "high":     2,
    "medium":   1,
    "low":      1,
    "notes": (
        "F1 (root hash) is the highest-impact finding: confirms WCS-VA and NCS-VA share "
        "a fleet-wide MD5-crypt root password. One hash = root on all 1.1.3.2 NCS and WCS "
        "deployments. Combined with PasswordAuthentication=yes and default PermitRootLogin=yes, "
        "this is a direct SSH root login vector once the hash is cracked. "
        "F2 (install_apps injection) is the most novel finding: boot-time command injection "
        "via unquoted shell variable from filename. The injection runs as root at priority 12 "
        "(early boot) on every system start. "
        "F3 (setuid binaries) documents the ADE-OS attack surface shared across all Cisco "
        "IronPort-derived appliances (WSA, ESA, SMA). The 13-year-old unpatched carssh binary "
        "is the primary VSH escape target. "
        "All NCS RPM findings (cisco_ncs_va_1_1_3_2_re.py, cisco_ncs_https_auth_re.py, "
        "cisco_ncs_cars_infrastructure_re.py, cisco_ncs_remoting_rce_re.py, "
        "cisco_ncs_webapp_re.py) apply to this VA post-installation."
    ),
    "prior_modules": [
        "cisco_ncs_va_1_1_3_2_re.py",
        "cisco_ncs_https_auth_re.py",
        "cisco_ncs_cars_infrastructure_re.py",
        "cisco_ncs_remoting_rce_re.py",
        "cisco_ncs_webapp_re.py",
    ],
}
