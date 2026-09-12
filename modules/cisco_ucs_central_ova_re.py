"""
Cisco UCS Central 1.5(1c) OVA RE

Target:  ucs-central.1.5.1c.ova -> ucs-central.1.5.1c-disk1.vmdk
         RHEL 5 64-bit (rhel5_64Guest), ext3 LVM (VolGroup00-LogVol00, 37.9GB)
Product: Cisco UCS Central 1.5(1c) -- centralized management for UCS domains
Files:   /opt/cisco/bin/vm-common.pl      (crypto, auth, setup logic)
         /opt/cisco/bin/vm-init.sh        (OVA post-deploy init)
         /opt/cisco/bin/vsh_perm          (admin account shell)
         /opt/cisco/bin/decryptpasswd.pl  (sharedSecret decrypt utility)
         /etc/sudoers                     (NOPASSWD rules)
         /etc/shadow                      (OS credentials)
         /usr/lib/libvmpam.so             (custom PAM module for SSH auth)
Session: 38
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_central_ova_re",
    "firmware": (
        "ucs-central.1.5.1c.ova "
        "(RHEL 5 64-bit, LVM ext3, productVersion=1.5(1c))"
    ),
    "components": {
        "/opt/cisco/bin/vm-common.pl": (
            "Central Perl library: crypto (AES-128), auth, setup, "
            "OVF/KS config handling; hardcoded encryption key"
        ),
        "/etc/sudoers": (
            "NOPASSWD:ALL for admin/root/samdme; "
            "ALL ALL=NOPASSWD:SUDO_CMNDS includes decryptpasswd.pl and '/bin/chown -R *'"
        ),
        "/opt/cisco/bin/vm-init.sh": (
            "OVA post-deployment init script; debug parameter enables "
            "serial telnet console and retains root account"
        ),
        "/opt/cisco/bin/vsh_perm": (
            "Admin account shell (bash script); sets umask 000 globally; "
            "delegates to /opt/cisco/core/sam/bin/ucssh"
        ),
        "/usr/lib/libvmpam.so": (
            "Custom PAM module for SSH auth; delegates to UCS Central mgmt service; "
            "built from /ramfs/buildsa/170226-115116-rev960-FCSc/core/sam/src/app/sam/vmpam/vm_auth.cc"
        ),
    },
    "finding_counts": {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 0},
    "cumulative_counts": {"CRITICAL": 64, "HIGH": 235, "MEDIUM": 226, "LOW": 192},
    "cumulative_total": 717,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": (
            "Hardcoded AES-128 Encryption Key 'theKeyForEncryptingTheSharedSecret' "
            "Used to Encrypt UCS Central sharedSecret in All Deployments"
        ),
        "component": "/opt/cisco/bin/vm-common.pl",
        "evidence": {
            "hardcoded_key": (
                "Line 462:\n"
                "  my $encKey = \"theKeyForEncryptingTheSharedSecret\";"
            ),
            "encrypt_function": (
                "sub encryptPass {\n"
                "    my $pass = shift;\n"
                "    my $encrypt_key = shift;\n"
                "    $pass =~ s/\"/\\\\\"/;\n"
                "    $pass =~ s/\\$/\\\\\\$/;\n"
                "    $encrypted = `$echo \"$pass\" | $openssl enc -e -k $encrypt_key -a -aes128`;\n"
                "}"
            ),
            "decrypt_function": (
                "sub decryptPass {\n"
                "    my $encrypted = shift;\n"
                "    $pass = `$echo \"$encrypted\" | $openssl enc -d -k $encKey -a -aes128`;\n"
                "}\n"
                "# $encKey is always 'theKeyForEncryptingTheSharedSecret'"
            ),
            "encryption_usage": (
                "Line 1775: $inputs{$secret} = encryptPass($pass, $encKey)\n"
                "Line 2072: $vpod::inputs{$field} = vpod::encryptPass(..., $encKey)\n"
                "Line 1688: decryptPass uses $encKey (module-level, not passed as argument)\n\n"
                "The $secret variable maps to the 'sharedSecret' key in sam.config. "
                "The sharedSecret authenticates all UCSM domain registrations to UCS Central."
            ),
            "decryption_command": (
                "To decrypt any UCS Central 1.5.x sharedSecret from sam.config:\n"
                "  echo '<sam.config sharedSecret value>' | "
                "openssl enc -d -k theKeyForEncryptingTheSharedSecret -a -aes128"
            ),
            "openssl_weakness": (
                "The '-k' flag to openssl enc derives the actual AES key using "
                "OpenSSL's legacy EVP_BytesToKey(MD5, 1 iteration). "
                "This is a weak KDF -- the static passphrase + MD5 derivation "
                "means the effective encryption strength is far below AES-128."
            ),
        },
        "impact": (
            "The sharedSecret is the credential used to authenticate UCS domain (UCSM) "
            "registrations to UCS Central. It is stored AES-128 encrypted in sam.config, "
            "but the encryption key is the literal string 'theKeyForEncryptingTheSharedSecret' "
            "hardcoded in vm-common.pl on every UCS Central deployment. "
            "Any attacker who can read sam.config (readable by samdme and admin, "
            "exfiltrated via backup, or accessed via a web UI path traversal) can decrypt "
            "the sharedSecret using a single openssl command. "
            "With the sharedSecret, an attacker can register a rogue UCSM domain to "
            "UCS Central, or impersonate UCS Central in domain-registration protocol exchanges. "
            "The weak KDF (EVP_BytesToKey MD5, 1 iteration) provides no meaningful "
            "additional protection beyond the passphrase."
        ),
        "remediation": (
            "Replace the hardcoded key with a per-instance randomly generated key "
            "stored in a root-only file (/etc/ucsc_master.key, 0400). "
            "Replace the openssl enc -k (weak KDF) invocation with a proper "
            "PBKDF2 or Argon2-based encryption scheme. "
            "Rotate the sharedSecret on all registered UCS domains for any "
            "deployment where sam.config has been accessible to non-root users "
            "or was included in backups."
        ),
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "title": (
            "Wildcard '/bin/chown -R *' in NOPASSWD Sudoers for ALL System Users "
            "Enables Arbitrary File Ownership Change to Any Path"
        ),
        "component": "/etc/sudoers",
        "evidence": {
            "sudoers_cmnds_alias": (
                "Cmnd_Alias SUDO_CMNDS = ..., /bin/chown -R *, ..."
            ),
            "all_users_rule": (
                "ALL ALL = NOPASSWD:SUDO_CMNDS\n\n"
                "This grants every user on the system passwordless sudo access to "
                "all commands in SUDO_CMNDS, including '/bin/chown -R *'."
            ),
            "exploitation": (
                "The sudoers wildcard '*' in '/bin/chown -R *' matches any argument "
                "after '-R '. Any local user can run:\n\n"
                "  sudo /bin/chown -R <username>: /etc/shadow\n"
                "  sudo /bin/chown -R <username>: /etc/sudoers\n"
                "  sudo /bin/chown -R <username>: /opt/cisco/bin/\n\n"
                "Once the attacker owns /etc/shadow or /etc/sudoers, they can write "
                "to it (even as an unprivileged user, owner write bit applies). "
                "Writing a new root entry to /etc/shadow or NOPASSWD:ALL for their "
                "user to sudoers provides immediate root."
            ),
            "also_affected": [
                "decryptpasswd.pl -- all users can decrypt sharedSecret (standalone finding)",
                "regenerate-certs.pl -- all users can regenerate TLS certificates",
                "update-secret.pl -- all users can update the sharedSecret",
                "/sbin/iptables and /sbin/ip6tables -- all users can modify firewall rules",
                "restore.sh -p * -- all users can initiate restore with arbitrary -p argument",
            ],
        },
        "impact": (
            "Any unprivileged local user (including application service accounts like samdme, "
            "postgres, or a web shell running as apache) can run 'sudo /bin/chown -R <user>: /etc/shadow' "
            "to take ownership of the shadow password file. "
            "After chowning, they can write a crafted root password hash to /etc/shadow "
            "and authenticate as root. "
            "The 'ALL ALL = NOPASSWD:SUDO_CMNDS' line applies to every account on the system; "
            "the comment '# dont modify following line' above it indicates this is a deliberate "
            "build-time configuration. "
            "Additional escalation paths exist via iptables (firewall rules), "
            "restore.sh (arbitrary restore path injection), and certificate regeneration."
        ),
        "remediation": (
            "Remove '/bin/chown -R *' from SUDO_CMNDS entirely. "
            "If chown access is required, restrict it to specific target paths: "
            "'/bin/chown -R samdme: /opt/cisco/', '/bin/chown -R postgres: /var/lib/pgsql/'. "
            "Replace 'ALL ALL = NOPASSWD:SUDO_CMNDS' with service-account-specific entries: "
            "only the accounts that need each command should have it, not ALL users. "
            "Audit the full SUDO_CMNDS list for additional wildcard injection vectors "
            "(restore.sh -p *, fileMgmt.sh delete * are also exploitable with wildcard -p or path args)."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": (
            "admin Account Has NOPASSWD:ALL Sudo and Empty Shadow Password -- "
            "Zero-Credential Root Escalation Path via CLI Login"
        ),
        "component": "/etc/shadow + /etc/sudoers",
        "evidence": {
            "shadow_entry": (
                "admin::17223:0:99999:7:::\n"
                "# Field 2 (encrypted password) is empty -- no password is set."
            ),
            "sudoers_admin": (
                "admin ALL = NOPASSWD:ALL\n"
                "# Unrestricted passwordless sudo for admin -- full root access."
            ),
            "admin_shell": (
                "admin shell: /opt/cisco/bin/vsh_perm\n"
                "vsh_perm delegates to /opt/cisco/core/sam/bin/ucssh (UCS management CLI).\n"
                "ucssh is the only restriction on the admin account's interactive sessions."
            ),
            "nopasswd_all_scope": (
                "admin ALL = NOPASSWD:ALL grants admin the ability to run any command as root "
                "via 'sudo <cmd>' without supplying a password. "
                "If an attacker reaches the admin CLI (via ucssh), they can execute "
                "'sudo /bin/bash' to break out of ucssh into a root shell."
            ),
        },
        "impact": (
            "The UCS Central admin account has no OS-level password set in the factory OVA image. "
            "The admin shell (vsh_perm -> ucssh) provides CLI access to UCS Central management. "
            "Once in the CLI, 'sudo /bin/bash' is available without a password (NOPASSWD:ALL). "
            "Any attacker with SSH access to the admin account (including through the factory-state "
            "empty password, or by exploiting the UCS Central web interface to execute OS commands) "
            "has a direct, one-step path to a root shell. "
            "The empty shadow password is the factory default before OVA first-boot configuration "
            "sets the admin password -- but ucssh's auth is handled by libvmpam.so, not the shadow file, "
            "so the shadow state may persist through deployment in some configurations."
        ),
        "remediation": (
            "Restrict admin's sudo to specific commands required for UCS Central operation: "
            "remove NOPASSWD:ALL and enumerate only the minimum privilege set. "
            "Set a placeholder admin shadow password at image build time: "
            "'echo -e \"changeme\\nchangeme\" | passwd --stdin admin'. "
            "Force mandatory admin password change on first OVA login. "
            "Verify that post-OVF-deploy first-boot correctly sets the admin shadow entry "
            "for all deployment paths."
        ),
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": (
            "ALL System Users Can Run 'sudo decryptpasswd.pl' Without Password -- "
            "Unrestricted UCS Central sharedSecret Decryption"
        ),
        "component": "/etc/sudoers + /opt/cisco/bin/decryptpasswd.pl",
        "evidence": {
            "sudoers_rule": (
                "Cmnd_Alias SUDO_CMNDS = ..., /opt/cisco/bin/decryptpasswd.pl, ...\n"
                "ALL ALL = NOPASSWD:SUDO_CMNDS"
            ),
            "decryptpasswd_pl": (
                "#!/usr/bin/perl\n"
                "use strict;\n"
                "require '/opt/cisco/bin/vm-common.pl';\n"
                "$vpod::inputs{$vpod::secret} = vpod::decryptPass(\n"
                "    vpod::getValFromSamConfig($vpod::secret));\n"
                "my $hashPass = $vpod::inputs{$vpod::secret};\n"
                "print \"$hashPass\";"
            ),
            "what_it_prints": (
                "decryptpasswd.pl reads the sharedSecret from sam.config, "
                "decrypts it using the hardcoded key (see F1), and prints the plaintext "
                "to stdout. Any user can run:\n\n"
                "  sudo /opt/cisco/bin/decryptpasswd.pl\n\n"
                "to retrieve the plaintext sharedSecret."
            ),
        },
        "impact": (
            "The sharedSecret is required to register a UCS domain (UCSM fabric interconnect) "
            "with UCS Central. Any local user or process (web server running as apache, "
            "backup agent, application code running as samdme) can retrieve the plaintext "
            "sharedSecret with one command. "
            "The sharedSecret is used in mutual authentication during domain registration; "
            "knowledge of it allows registration of unauthorized UCSM instances to UCS Central, "
            "or impersonation of UCS Central in inter-domain communication. "
            "Note: sudo update-secret.pl and sudo regenerate-certs.pl are also available to "
            "ALL users without password -- allowing any user to replace the sharedSecret or "
            "regenerate the TLS certificates used for UCS Central HTTPS."
        ),
        "remediation": (
            "Remove decryptpasswd.pl, update-secret.pl, and regenerate-certs.pl from SUDO_CMNDS. "
            "These operations should only be executable by root and admin, not by all system users. "
            "Add explicit user restrictions: 'admin ALL = NOPASSWD: /opt/cisco/bin/decryptpasswd.pl' "
            "instead of the broad ALL-users grant."
        ),
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "title": (
            "vm-init.sh 'debug' Parameter Enables Serial Telnet Console and "
            "Retains Root Account with Active Shadow Hash"
        ),
        "component": "/vm-init.sh",
        "evidence": {
            "debug_path": (
                "if [[ -n \"$flag\" && \"$flag\" == \"debug\" ]]; then\n"
                "    # Modify grub.conf to add serial console\n"
                "    sed -i 's/title Cisco UCS Central/serial --unit=0 --speed=19200\\n"
                "terminal --timeout=8 console serial\\ntitle Cisco UCS Central/' "
                "/boot/grub/grub.conf\n"
                "    sed -i 's/LogVol00/& console=tty0 console=ttyS0,19200n8/' "
                "/boot/grub/grub.conf\n"
                "    # Add agetty to inittab for serial login\n"
                "    echo 'S0:23:respawn:/sbin/agetty -h -L ttyS0 19200 vt100' >> /etc/inittab\n"
                "else\n"
                "    # Release build: disable root account\n"
                "    /usr/sbin/usermod -s /sbin/nologin root\n"
                "fi"
            ),
            "root_shadow_hash": (
                "In the OVA image (pre-deploy), root has an active SHA-512 hash:\n"
                "  root:$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/::0:99999:7:::\n"
                "In release builds, root is disabled by changing the shell to /sbin/nologin. "
                "In debug builds, root retains /bin/bash and the active hash."
            ),
            "chmod_777_tmp": (
                "# fix tmp permissions\n"
                "chmod 777 /tmp -R\n"
                "# Applied in BOTH debug and release builds"
            ),
            "deploy_trigger": (
                "vm-init.sh is executed once during OVA post-deployment. "
                "The flag argument comes from the VMware OVF environment or a "
                "Packer/CI build system invocation. "
                "A 'debug' build shipped to a customer retains the root account, "
                "serial telnet console, and active MD5-crypt root hash."
            ),
        },
        "impact": (
            "A UCS Central OVA built with the 'debug' parameter retains a fully active "
            "root account with the password hash '$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/' and "
            "adds a serial telnet console accessible on ttyS0 at 19200 baud. "
            "If a debug build is deployed in production (accidentally or through a supply chain "
            "substitution), the root account is accessible via serial console with no PAM "
            "restriction, and the MD5-crypt hash can be cracked offline. "
            "All builds (debug and release) also set '/tmp' and all its contents to 777 "
            "(chmod 777 /tmp -R), creating a world-writable directory tree that allows "
            "any local user to modify temporary files used by UCS Central processes."
        ),
        "remediation": (
            "Remove the 'debug' parameter from vm-init.sh entirely, or require it to be "
            "compiled out at build time rather than passed as a runtime argument. "
            "Lock the root account password in all builds: 'passwd -l root'. "
            "Replace 'chmod 777 /tmp -R' with 'chmod 1777 /tmp' (sticky bit, no recurse). "
            "Audit released OVA images to verify root shell is /sbin/nologin "
            "and no serial console entries exist in /etc/inittab."
        ),
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": (
            "vsh_perm Admin Shell Sets umask 000 Globally -- "
            "All Admin Session Files Are World-Writable"
        ),
        "component": "/opt/cisco/bin/vsh_perm",
        "evidence": {
            "umask_line": (
                "#The following line will make sure log file has permission 666 - CSCti44291\n"
                "umask 000"
            ),
            "scope": (
                "umask 000 is set in the admin account shell (vsh_perm) before any other "
                "commands. This affects the umask for the entire admin session and all "
                "child processes spawned from it (ucssh, sudo, any invoked scripts).\n\n"
                "With umask 000:\n"
                "- Files created by admin sessions: mode 666 (rw-rw-rw-)\n"
                "- Directories created by admin sessions: mode 777 (rwxrwxrwx)"
            ),
            "bug_reference": (
                "CSCti44291 -- Cisco internal bug reference cited in the comment. "
                "The fix makes log files group/world-readable (mode 666) to resolve a "
                "permission error, but sets umask 000 for the entire session rather "
                "than applying only to the specific log file."
            ),
        },
        "impact": (
            "Every file written by the admin account SSH session or its child processes "
            "is created with mode 666 (world-readable and world-writable). "
            "This includes temporary files written by sudo-invoked scripts, "
            "downloaded firmware images, configuration backups, and certificate files. "
            "A local attacker (running as any user, including samdme or postgres) "
            "can read or modify any file created during an admin session. "
            "If admin writes a temporary credential or certificate file, "
            "it is immediately world-readable without any additional action."
        ),
        "remediation": (
            "Replace 'umask 000' with a targeted fix for the specific log file that "
            "triggered CSCti44291: explicitly chmod the log file after creation "
            "rather than clearing the umask for the entire session. "
            "Use 'umask 022' or 'umask 027' in vsh_perm."
        ),
    },
]


def run_module():
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Firmware: {MODULE_SUMMARY['firmware']}")
    for component, desc in MODULE_SUMMARY["components"].items():
        print(f"  {component}: {desc}")
    counts = MODULE_SUMMARY["finding_counts"]
    print(
        f"Findings: {sum(counts.values())} "
        f"[{counts['CRITICAL']}C/{counts['HIGH']}H/"
        f"{counts['MEDIUM']}M/{counts['LOW']}L]"
    )
    cc = MODULE_SUMMARY["cumulative_counts"]
    print(
        f"Cumulative: {MODULE_SUMMARY['cumulative_total']} "
        f"[{cc['CRITICAL']}C+{cc['HIGH']}H+{cc['MEDIUM']}M+{cc['LOW']}L]"
    )
    print()
    for f in FINDINGS:
        sev = f["severity"]
        print(f"  {f['id']} [{sev}] {f['title']}")
        print(f"    Component: {f['component']}")
        print(f"    Impact: {f['impact'][:120]}...")
        print()


if __name__ == "__main__":
    run_module()
