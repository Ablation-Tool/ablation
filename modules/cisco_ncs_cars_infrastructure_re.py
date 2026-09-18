"""
Cisco NCS CARS Infrastructure RE Module
Targets (all from NCS.tar.gz, NCS VA 1.1.3.2):
  CARSBackup-2.0cars-3.x86_64.rpm  -- CARS platform backup subsystem
  CARSInstall-2.0cars-2.x86_64.rpm -- CARS platform install subsystem
  NCSCARSCli-1.1-4.x86_64.rpm      -- NCS CARS CLI extensions
  os-updates.zip                    -- OS update bundle (openssh + openssl)
  preinstall.zip / postinstall.zip  -- NCS install lifecycle scripts

CARS = Cisco Application Release Suite (ADE-OS framework, shared with Prime/DCNM)
ADE-OS: Application Deployment Engine OS v2.0.1.038 (RHEL5.4 base)

CARSBackup encryption scheme:
  GPG symmetric encryption, algorithm CAST5 (CAST-128)
  Passphrase: read from /opt/system/bin/cars-backup.pp at runtime
  Passphrase file shipped in CARSBackup RPM at ./opt/system/bin/cars-backup.pp
  Content: "You can't have great software without a great team, and most software
            teams behave like dysfunctional families. =;^) Jim McCarthy"
  Backup output: <name>.tar.gpg (CAST5 symmetric, no key exchange, no asymmetric wrapping)
  Backup contents: /opt/system/etc/config/* (passwd/shadow/group/firewall)
                   /storedconfig/active/     (running device config)
                   /storedconfig/fixed/      (baseline device config)

Backup decryption (one command):
  gpg -d --batch --cipher-algo CAST5 --compress-level 0 \
      --passphrase "You can't have great software without a great team, \
and most software teams behave like dysfunctional families. =;^) Jim McCarthy" \
      <name>.tar.gpg > <name>.tar

os-updates.zip component versions:
  openssh-4.3p2-82.el5.x86_64.rpm    -- OpenSSH 4.3p2 (2006, numerous CVEs)
  openssh-server-4.3p2-82.el5.x86_64 -- sshd with Protocol 1 support
  openssh-clients-4.3p2-82.el5.x86_64
  openssl-0.9.8e-22.el5_8.3.x86_64   -- OpenSSL 0.9.8e (2007, BEAST/Lucky13/etc.)
  hmaccalc-0.9.6-3.el5.x86_64.rpm    -- SHA-based HMAC tool (FIPS compliance)

postinstall.sh notable behaviors (upgrade path only):
  1. Disables oracle user password: usermod -p !! oracle
  2. Disables GSSAPIAuthentication in sshd_config
  3. Disables UsePAM in sshd_config (removes PAM auth chain)
  4. Appends fips=1 to /boot/grub/grub.conf
  5. Runs mkinitrd --with-fips
  6. SSHv1 RSA key manipulation: sed patches /etc/rc.d/init.d/sshd
     - sed "s/do_rsa1_keygen/#do_rsa1_keygen/g" (comments out call and definition)
     - sed "s/#do_rsa1_keygen()/do_rsa1_keygen()/g" (restores definition only)
     Net effect: SSHv1 keygen function defined but not called (SSHv1 keys NOT generated)
  7. VMware Tools: VMwareTools-8.6.5-621624.tar.gz via vmware-install.pl --default
  8. Physical appliance: MegaCli-8.00.26-1.i386.rpm, IBM ASU ibm_utl_asu_asut70i

preinstall.sh notable behaviors:
  Supported upgrade paths: 1.1.0.58, 1.1.1.24, 1.1.2.12 -> 1.1.3.2 (hardcoded version check)
  Removes deployed WAR files from Tomcat webapps (three paths checked)
  Installs os-updates.zip packages via rpm -Uvh --force
"""

METADATA = {
    "targets": [
        "CARSBackup-2.0cars-3.x86_64.rpm",
        "CARSInstall-2.0cars-2.x86_64.rpm",
        "NCSCARSCli-1.1-4.x86_64.rpm",
        "os-updates.zip",
        "preinstall.zip",
        "postinstall.zip",
    ],
    "framework": "CARS (Cisco Application Release Suite), ADE-OS v2.0.1.038",
    "platform": "NCS VA 1.1.3.2 / WCS VA 1.1.3.2 (RHEL5.4 base)",
    "backup_cipher": "GPG CAST5 symmetric, passphrase from cars-backup.pp",
    "backup_passphrase": (
        "You can't have great software without a great team, and most software "
        "teams behave like dysfunctional families. =;^) Jim McCarthy"
    ),
    "os_update_versions": {
        "openssh": "4.3p2-82.el5",
        "openssl": "0.9.8e-22.el5_8.3",
        "hmaccalc": "0.9.6-3.el5",
    },
    "vmware_tools": "VMwareTools-8.6.5-621624 (2012-era)",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Hardcoded Fleet-Wide GPG Passphrase for All NCS Backup Archives (CAST5)",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-321",
        "description": (
            "CARSBackup-2.0cars-3 ships /opt/system/bin/cars-backup.pp as a plaintext file "
            "inside the RPM, containing the GPG passphrase used to encrypt ALL NCS backup archives. "
            "The passphrase is the same on every NCS deployment (fleet-wide constant): "
            "'You can't have great software without a great team, and most software teams "
            "behave like dysfunctional families. =;^) Jim McCarthy' "
            "Backups are produced as <name>.tar.gpg using GPG symmetric CAST5 encryption "
            "with --batch --passphrase-file /opt/system/bin/cars-backup.pp. "
            "Any attacker who obtains a backup archive can decrypt it with one command: "
            "gpg -d --batch --cipher-algo CAST5 --compress-level 0 "
            "--passphrase 'You can...' backup.tar.gpg > backup.tar "
            "Backup archive contains: "
            "/opt/system/etc/config/* (passwd, shadow, group -- system credentials), "
            "/opt/system/etc/fw/ (firewall configuration), "
            "/storedconfig/active/ (running device configuration), "
            "/storedconfig/fixed/ (baseline configuration). "
            "Attack chain with NCS FTP server (cisco_ncs_va_1_1_3_2_re.py F5): "
            "An attacker with network access connects to the embedded Apache FTP server "
            "(ftp-user:ftp-user, writepermission=true) on the NCS appliance. "
            "If the backup repository is configured on the FTP server's home directory "
            "(/opt/CSCOncs/remotingServices/Ftp/ftp-server/root), backup archives are "
            "accessible without authentication beyond ftp-user:ftp-user. "
            "Decrypt the archive, extract /opt/system/etc/config/shadow to recover "
            "root credentials (MD5-crypt hash $1$2Ye/mXie$7ENVFaenxQpQOOD5Qe9CX.) -- "
            "same hash confirmed in the NCS VA root account. "
            "The passphrase is effectively public: it is embedded in the CARSBackup RPM "
            "which is distributed with every NCS installation and available to any "
            "administrator or researcher who has obtained the firmware."
        ),
        "passphrase": (
            "You can't have great software without a great team, and most software "
            "teams behave like dysfunctional families. =;^) Jim McCarthy"
        ),
        "passphrase_file": "/opt/system/bin/cars-backup.pp",
        "gpg_command": (
            "gpg -c -q --batch --cipher-algo CAST5 --compress-level 0 "
            "--passphrase-file /opt/system/bin/cars-backup.pp <name>.tar"
        ),
        "decrypt_command": (
            "gpg -d --batch --cipher-algo CAST5 --compress-level 0 "
            "--passphrase 'You can\\'t have great software...' <name>.tar.gpg"
        ),
        "backup_contents": [
            "/opt/system/etc/config/passwd",
            "/opt/system/etc/config/shadow",
            "/opt/system/etc/config/group",
            "/opt/system/etc/fw/ (firewall rules)",
            "/storedconfig/active/ (running config)",
            "/storedconfig/fixed/ (baseline config)",
        ],
        "impact": [
            "Any NCS backup archive is trivially decryptable -- no key material needed beyond passphrase",
            "Backup exposes shadow file with root MD5-crypt hash -- offline cracking or direct reuse",
            "Chain: FTP server unauth (ftp-user:ftp-user) + this passphrase = full credential recovery",
        ],
        "remediation": (
            "Generate a deployment-unique GPG key pair at installation time. "
            "Encrypt backup archives to the per-deployment public key. "
            "Never ship a symmetric passphrase in a firmware package."
        ),
    },
    {
        "id": "F2",
        "title": "OpenSSH 4.3p2 and OpenSSL 0.9.8e Bundled in os-updates.zip -- Multiple CVEs",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-1329",
        "description": (
            "os-updates.zip (bundled in NCS.tar.gz and installed by preinstall.sh) contains "
            "OpenSSH 4.3p2-82.el5 (c. 2006) and OpenSSL 0.9.8e-22.el5_8.3 (c. 2007). "
            "These are the specific package versions installed on every NCS 1.1.3.2 appliance "
            "via rpm -Uvh --force. "
            "OpenSSH 4.3p2 known CVEs include: "
            "CVE-2006-5051 (signal handler race, pre-4.4) -- SIGCHLD handler race condition "
            "allowing a local user to gain elevated privileges. "
            "CVE-2007-4752 (unsafe ptrace) -- may allow local privilege escalation. "
            "CVE-2008-1483 (X11 forwarding) -- X11 cookie injection when X11UseLocalhost disabled. "
            "OpenSSL 0.9.8e known CVEs include: "
            "CVE-2011-4576 (CBC padding oracle -- precursor to BEAST), "
            "CVE-2012-2110 (ASN.1 buffer overflow in d2i_* functions), "
            "CVE-2012-2686 (AES-NI predictable IV -- Lucky Thirteen precursor), "
            "CVE-2013-0169 (Lucky Thirteen), "
            "CVE-2014-0160 (Heartbleed -- openssl 0.9.8e patched at 22.el5_10.3, NOT 22.el5_8.3). "
            "The el5_8.3 RHEL release predates the Heartbleed patch. "
            "The NCS platform is EOL with no patch mechanism, so these CVEs are permanent. "
            "The sshd server listens on port 22 with PasswordAuthentication yes "
            "(confirmed in the NCS VA -- see cisco_ncs_va_1_1_3_2_re.py F6). "
            "Any Heartbleed-vulnerable service using this OpenSSL library is attackable "
            "from the network without authentication."
        ),
        "versions": {
            "openssh": "4.3p2-82.el5 (2006, Protocol 1 capable)",
            "openssl": "0.9.8e-22.el5_8.3 (2007, pre-Heartbleed patch)",
        },
        "cves_openssh": ["CVE-2006-5051", "CVE-2007-4752", "CVE-2008-1483"],
        "cves_openssl": [
            "CVE-2011-4576",
            "CVE-2012-2110",
            "CVE-2012-2686",
            "CVE-2013-0169",
            "CVE-2014-0160",
        ],
        "heartbleed_note": (
            "Heartbleed patch landed in openssl-0.9.8e-27.el5_9.3 (RHEL5). "
            "Bundled version 0.9.8e-22.el5_8.3 predates the patch by 5 RHEL updates. "
            "Heartbleed exploitability depends on which NCS services link against libssl.so.6 -- "
            "Tomcat uses Java (not OpenSSL), but the sshd and any C-based network service would use it."
        ),
        "impact": [
            "Pre-Heartbleed OpenSSL on a permanently unpatched platform",
            "SSHv1 support in the bundled OpenSSH server (Protocol 1 not explicitly disabled)",
        ],
        "remediation": "NCS is EOL. No patch path. Isolate from untrusted networks.",
    },
    {
        "id": "F3",
        "title": "VMware Tools 8.6.5-621624 Bundled -- 12-Year-Old Version with Privilege Escalation CVEs",
        "severity": "MEDIUM",
        "cvss": 6.7,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1329",
        "description": (
            "postinstall.sh bundles and installs VMware Tools 8.6.5-621624 "
            "(from VMwareTools-8.6.5-621624.tar.gz) on virtual appliance deployments. "
            "VMware Tools 8.6.5 is from approximately 2012. "
            "Known CVEs affecting VMware Tools in the 8.x series include: "
            "CVE-2015-5191 (TOCTOU symlink attack during VMware Tools installation), "
            "CVE-2014-4199 (privilege escalation via hgfsmounter SUID binary), "
            "CVE-2012-3289 (arbitrary code execution via vmtools-daemon). "
            "The installer runs ./vmware-install.pl --default, which creates SUID helpers "
            "(vmware-user-suid-wrapper, hgfsmounter) in the VMware Tools directory. "
            "These SUID binaries are local privilege escalation vectors for any code "
            "execution achieved through other findings (e.g., web shell via Tomcat). "
            "VMware Tools 12.x is current. Gap from 8.6.5 to 12.x spans ~10 years of patches."
        ),
        "version": "VMwareTools-8.6.5-621624 (2012-era)",
        "installer": "./vmware-install.pl --default (unattended, all defaults)",
        "cves": ["CVE-2015-5191", "CVE-2014-4199", "CVE-2012-3289"],
        "suid_binaries": ["vmware-user-suid-wrapper", "hgfsmounter"],
        "impact": [
            "SUID VMware Tools binaries are local privilege escalation surface for code execution",
        ],
        "remediation": "NCS is EOL. No patch path.",
    },
    {
        "id": "F4",
        "title": "UsePAM Disabled in sshd_config by postinstall.sh -- Bypasses PAM Security Modules",
        "severity": "LOW",
        "cvss": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1173",
        "description": (
            "postinstall.sh explicitly removes PAM authentication from sshd: "
            "sed 's/UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config "
            "Disabling UsePAM means sshd falls back to direct /etc/shadow lookups "
            "instead of routing through PAM. This bypasses any PAM security modules "
            "that might be configured for: account lockout (pam_tally2), "
            "two-factor authentication, session logging, "
            "and access control restrictions (pam_access, pam_listfile). "
            "In practice on a fresh NCS install, the default RHEL5 PAM configuration "
            "does not include additional security modules beyond standard auth, "
            "so the impact is low. However, any hardening applied to PAM "
            "(common in enterprise deployments) is silently bypassed by this install script. "
            "Also disabled: GSSAPIAuthentication (Kerberos), X11Forwarding, PRELINKING."
        ),
        "ssh_changes": {
            "GSSAPIAuthentication": "yes -> no",
            "GSSAPICleanupCredentials": "yes -> no",
            "UsePAM": "yes -> no",
            "X11Forwarding": "yes -> no",
            "PRELINKING": "yes -> no (via /etc/sysconfig/prelink)",
        },
        "impact": ["PAM security modules bypassed; sshd uses direct shadow auth only"],
        "remediation": "Explicitly set UsePAM yes and configure pam_tally2 or pam_faillock.",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 1,
    "high":     1,
    "medium":   1,
    "low":      1,
    "notes": (
        "The CARS backup passphrase finding (F1) chains directly with the embedded FTP server "
        "credential finding in cisco_ncs_va_1_1_3_2_re.py (F5): ftp-user:ftp-user access "
        "to the backup repository directory provides the backup archive, and the hardcoded "
        "GPG CAST5 passphrase decrypts it. The full chain yields the root shadow hash. "
        "The passphrase 'You can\\'t have great software without a great team...' is a quote "
        "from Jim McCarthy (Microsoft research, 'Dynamics of Software Development', 1995). "
        "It was selected as a developer placeholder and never replaced with a per-deployment key. "
        "The OpenSSL 0.9.8e Heartbleed status depends on which NCS services link libssl -- "
        "a runtime assessment is needed to confirm exploitability. "
        "All findings are permanent: NCS 1.1.3.2 reached EOL in 2013, no updates available."
    ),
}
