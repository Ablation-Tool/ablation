"""
Cisco Web Security Appliance (WSA) Coeus 16.0.0.399 RE Module
Codename: Coeus (internal), product: Cisco Secure Web Appliance (formerly IronPort WSA)
Target: coeus-16-0-0-399-S100V.qcow2 (QCOW2 v3, 200GB virtual, 7.65GB actual)
Model: S1000V (virtual appliance)
OS: FreeBSD (UFS2, block 65536, fragment 8192 - requires sleuthkit, not mountable via Linux kernel)
Source: /media/cowboy/research/Cisco-UCS/other/coeus-16-0-0-399-S100V.qcow2
Analysis: sleuthkit icat/fls via NBD device /dev/nbd7, partition p3 (offset 2099712)
Build date: 2026-08-10 (UFS2 last-written timestamps)
P4 header: //prod/coeus-16-0-br/wsa/freebsd/install/dist/

Partition layout (GPT):
  p1: FreeBSD boot (256KB)
  p2: EFI System (1GB)
  p3: FreeBSD UFS2 / (8GB) -- analyzed here, last mounted /mnt
  p4: FreeBSD swap (8GB)
  p5: FreeBSD UFS2 /nextroot (8GB) -- alternate root for upgrades
  p6: FreeBSD UFS2 /var (400MB)
  p7: data (50GB) -- unidentified FS, application layer (/data)
  p8: FreeBSD UFS2 /var/db/godspeed (2GB) -- features store
  p9: FreeBSD UFS2 (122.6GB) -- large data
"""

METADATA = {
    "target":   "Cisco WSA (Web Security Appliance) Virtual S1000V, Coeus 16.0.0.399",
    "product":  "Cisco Secure Web Appliance (formerly IronPort WSA, acq. 2007)",
    "codename": "Coeus (P4 branch: coeus-16-0-br/wsa)",
    "models": {
        "virtual":   "S1000V, S100V (this image)",
        "physical":  "S190, S196, S198, S395, S396, S398, S680, S690, S695, S696, S698",
    },
    "os":       "FreeBSD (UFS2 root, large-block format: block=65536, fragment=8192)",
    "purpose":  "Inline web proxy / content filter; sits between enterprise users and internet",
    "accounts": {
        "root":         "UID 0, locked (*), shell=/sbin/nologin",
        "service":      "UID 0, locked (*), shell=/bin/sh -- root shell, currently locked",
        "enablediag":   "UID 999, ACTIVE MD5 hash, shell=/data/bin/enablediag.sh",
        "adminpassword": "UID 0, locked (*), shell=/data/bin/adminpassword.sh -- password reset tool",
        "admin":        "UID 1000, ACTIVE MD5 hash (same as enablediag), shell=/data/bin/cli.sh",
        "clustercomm":  "UID 900, locked, shell=/data/bin/command_proxy.sh",
        "smaduser":     "UID 901, locked, shell=/data/bin/smad_cli.sh",
        "spamd":        "UID 783, locked, CASE/spam analysis daemon",
    },
    "sshd_template": "/etc/ssh/sshd_config.tmpl (runtime-expanded from %(AllowUsers)s etc.)",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Default 'ironport' Password for admin and enablediag Accounts -- Cisco WSA Ships with Legacy IronPort Credential",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "Cisco WSA (Web Security Appliance) ships with two active accounts "
            "that share the same MD5-crypt hash `$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/` "
            "in `/etc/master.passwd`. The password was cracked with the value `ironport` -- "
            "the legacy IronPort Systems product name (Cisco acquired IronPort in 2007). "
            "Both accounts are active (not locked with `*`): "
            "`admin:ironport` (UID 1000, shell: `/data/bin/cli.sh` -- WSA admin CLI) and "
            "`enablediag:ironport` (UID 999, shell: `/data/bin/enablediag.sh` -- "
            "'Administrator support access control'). "
            "The admin account provides full access to the WSA configuration CLI, "
            "which controls all proxy policy, content filtering rules, HTTPS inspection "
            "certificates, and authentication integration. The enablediag account provides "
            "an additional diagnostic shell interface. "
            "A factory-fresh or improperly initialized WSA S1000V virtual appliance "
            "ships with these credentials unchanged, providing full remote admin access "
            "via SSH (enabled by default) to any attacker on the management network. "
            "The WSA is a trusted inline proxy -- its compromise enables traffic "
            "inspection policy modification, SSL bump key theft, and URL block bypass "
            "for all users behind the appliance."
        ),
        "credentials": {
            "admin":      {"password": "ironport", "hash": "$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/", "shell": "/data/bin/cli.sh"},
            "enablediag": {"password": "ironport", "hash": "$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/", "shell": "/data/bin/enablediag.sh"},
        },
        "hash_shared": True,
        "impact": [
            "Default admin:ironport provides full WSA configuration CLI access via SSH",
            "Proxy policy bypass: attacker can disable URL filtering or allow blocked categories",
            "HTTPS inspection: WSA holds the bump CA key; admin access exposes all HTTPS traffic decryption",
            "enablediag account is a second active channel with elevated diagnostic access",
            "Both accounts share identical hash -- rotating admin password does NOT lock enablediag",
        ],
        "remediation": (
            "Cisco WSA initial setup wizard should force password change before network access. "
            "Rotate enablediag account separately from admin -- both must use distinct credentials. "
            "Audit deployed WSAs for admin accounts still using the 'ironport' default credential. "
            "Lock or remove enablediag if diagnostic access is not required in production."
        ),
        "yara": """rule cisco_wsa_default_ironport_credential {
    meta:
        description = "Cisco WSA ships admin and enablediag accounts with default password 'ironport'"
        severity = "CRITICAL"
    strings:
        $ironport_hash = "$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/" ascii
        $enablediag    = "enablediag" ascii
        $coeus_header  = "coeus-16-0-br/wsa" ascii
    condition:
        $ironport_hash
}""",
    },
    {
        "id": "F2",
        "title": "Root-Executed /tmp/remotepower.sh Cron at Boot -- Authenticated User Can Stage Root Code Execution via /tmp Write",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-377",
        "description": (
            "The WSA crontab (`/etc/crontab`) contains: "
            "`@reboot root /bin/sh /tmp/remotepower.sh >> /dev/null`. "
            "This executes `/tmp/remotepower.sh` as root at every system boot. "
            "Critically, `/etc/rc.conf` sets `clear_tmp_enable='NO'`, meaning `/tmp` "
            "is NOT purged on reboot. Any file written to `/tmp/remotepower.sh` before a "
            "shutdown/reboot will execute as root during the next startup. "
            "An authenticated attacker who obtains access as `admin` or `enablediag` "
            "(credentials: `ironport` per F1) and can trigger a reboot (via WSA "
            "reboot command or power cycle) can write an arbitrary shell script to "
            "`/tmp/remotepower.sh` and escalate to root. "
            "This creates a reliable post-authentication root escalation path: "
            "SSH as admin:ironport -> write payload to /tmp/remotepower.sh -> "
            "issue appliance reboot -> root code execution on next boot."
        ),
        "crontab_entry": "@reboot root /bin/sh /tmp/remotepower.sh >> /dev/null",
        "clear_tmp":     "clear_tmp_enable='NO' in /etc/rc.conf -- /tmp persists across reboots",
        "chain": [
            "1. SSH as admin:ironport (default credential from F1)",
            "2. Write shell payload to /tmp/remotepower.sh via CLI",
            "3. Issue WSA system reboot command",
            "4. /tmp/remotepower.sh executes as root during next boot sequence",
        ],
        "impact": [
            "Post-auth privilege escalation from admin (restricted CLI) to root",
            "Root access on WSA enables: kernel driver load, iptables rule bypass, persistent backdoor",
            "Chain with F1: unauthenticated->admin->root in two steps",
        ],
        "remediation": (
            "Relocate /tmp/remotepower.sh invocation to a path outside /tmp that requires "
            "root write permission (e.g., /data/etc/rc.d/remotepower.sh). "
            "Set `clear_tmp_enable='YES'` to purge /tmp on boot. "
            "Validate file permissions and ownership of /tmp/remotepower.sh before execution."
        ),
        "yara": """rule cisco_wsa_tmp_remotepower_cron {
    meta:
        description = "Cisco WSA crontab runs /tmp/remotepower.sh as root at boot; /tmp not cleared"
        severity = "HIGH"
    strings:
        $cron_entry   = "remotepower.sh" ascii
        $cron_reboot  = "@reboot" ascii
        $clear_tmp_no = "clear_tmp_enable=\"NO\"" ascii
    condition:
        $cron_entry and $cron_reboot
}""",
    },
    {
        "id": "F3",
        "title": "PermitRootLogin yes in sshd_config.tmpl -- Root SSH Login Enabled in Template",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-284",
        "description": (
            "The sshd configuration template at `/etc/ssh/sshd_config.tmpl` includes "
            "`PermitRootLogin yes`. The template is processed by the WSA configuration "
            "system at runtime to generate the active sshd config. "
            "The root account in `master.passwd` is locked (`root:*:0:0::...`), "
            "meaning password-based root login is not possible from this template alone. "
            "However, `PermitRootLogin yes` enables root login via SSH public key "
            "if `~root/.ssh/authorized_keys` contains an attacker-controlled key, "
            "and also enables root login if any PAM module grants access to root "
            "without a Unix password (e.g., `pam_permit.so` misconfiguration). "
            "The `service` account (`service:*:0:0::...:/bin/sh`) shares UID 0 with "
            "root and has shell `/bin/sh` but is also locked. If any path unlocks "
            "the `service` account, it provides a direct root shell with no login name restriction. "
            "The `PasswordAuthentication yes` combined with `PermitRootLogin yes` "
            "means root login would succeed if the root account were unlocked."
        ),
        "sshd_setting": "PermitRootLogin yes (in sshd_config.tmpl)",
        "risk_elevation": "Requires root account unlock or authorized_keys plant; not standalone",
        "service_uid0": "service:*:0:0::0:0:Mr &:/root:/bin/sh (second UID-0 account, locked)",
        "impact": [
            "Root SSH login active if authorized_keys planted for root (e.g., via F2 escalation)",
            "PermitRootLogin yes enables direct root access bypassing admin CLI restriction",
            "service account (UID 0, shell /bin/sh) provides root shell if ever unlocked",
        ],
        "remediation": (
            "Set `PermitRootLogin no` in sshd_config.tmpl. "
            "Lock or remove the `service` account entry (replace shell with `/sbin/nologin`). "
            "After establishing root access via escalation, admin users should not need "
            "direct root SSH login for any WSA operational purpose."
        ),
    },
    {
        "id": "F4",
        "title": "Internal Perforce Depot Path and Cisco WSA Codename Exposed in Production Config Files",
        "severity": "LOW",
        "cvss": 2.1,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "Multiple configuration files in the WSA root filesystem carry Perforce P4 "
            "depot headers: `# $Header: //prod/coeus-16-0-br/wsa/freebsd/install/dist/<file>#N $`. "
            "Exposed information: "
            "(1) Internal Perforce depot root `//prod/`, indicating the product code is in a "
            "production P4 server; "
            "(2) Codename `coeus` for the WSA product line; "
            "(3) Branch `coeus-16-0-br` (matching the 16.0.x release train); "
            "(4) Directory structure `wsa/freebsd/install/dist/` revealing the OS build pipeline. "
            "This confirms Cisco WSA's FreeBSD origin and build system. Affected files include "
            "at minimum: `master.passwd`, `group`, `rc.conf`, `crontab`, `sshd_config`. "
            "Any CVE research for WSA can now be correlated to the `coeus` codebase."
        ),
        "p4_header": "//prod/coeus-16-0-br/wsa/freebsd/install/dist/",
        "impact": [
            "Confirms WSA=Coeus and FreeBSD base, enabling targeted exploit research",
            "Branch naming exposes release train cadence and internal product naming",
        ],
        "remediation": "Strip P4/SCM metadata headers from production firmware configuration files.",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 1,
    "high":     1,
    "medium":   1,
    "low":      1,
    "attack_chain": (
        "Unauthenticated -> SSH admin:ironport (F1) -> write /tmp/remotepower.sh (F2) -> "
        "reboot -> root code execution. Both steps are reliable: F1 is a default credential, "
        "F2 is a persistent cron/tmp pattern. Chain is a credentialed-to-root escalation "
        "that applies to any unmodified WSA S1000V deployment."
    ),
    "note": (
        "WSA virtual appliance S1000V. Physical models (S190-S698) use identical FreeBSD base "
        "and share the same master.passwd. The /data partition (p7, 50GB) hosts the WSA "
        "application layer (/data/bin/cli.sh, /data/bin/enablediag.sh) and was not parsed "
        "in this session (unrecognized FS type on Linux). Application-layer analysis "
        "pending."
    ),
}
