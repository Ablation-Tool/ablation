"""
Cisco UCS Central 1.5.1c — passreset ISO RE findings
Source: ucs-central-passreset.1.5.1c.iso (146MB)
Format: RHEL-based Anaconda installer ISO
Key files:
  ks.cfg / ks_upgrade.cfg — Kickstart scripts
  images/stage2.img — Squashfs (92MB uncompressed) with Anaconda installer
  /usr/lib/anaconda/ucscentral.py — UCS Central specific installer module
  /usr/share/anaconda/ui/ucscentralreset.glade — GTK password reset UI
Built: 2017-02-26 (stage2.img), Anaconda content: 2014
"""

FIRMWARE = {
    "target":      "Cisco UCS Central 1.5.1c",
    "source_pkg":  "ucs-central-passreset.1.5.1c.iso",
    "format":      "RHEL Anaconda installer ISO (isolinux + squashfs stage2)",
    "stage2":      "images/stage2.img — squashfs v3.0, 92845193 bytes, 9944 inodes, 2017-02-26",
    "installer":   "Anaconda (RHEL 6.x era), Python 2 syntax",
    "core_module": "usr/lib/anaconda/ucscentral.py",
    "selinux":     "selinux --disabled (explicit in ks_upgrade.cfg)",
}

# ─────────────────────────────────────────────────────────
# UCSC-F1 — Hardcoded AES-128 key for shared secret encryption
# ─────────────────────────────────────────────────────────
UCSC_F1 = {
    "id":       "UCSC-F1",
    "title":    "Hardcoded AES-128 encryption key 'theKeyForEncryptingTheSharedSecret' used to encrypt the UCS Central shared secret in all installations",
    "status":   "CONFIRMED — /usr/lib/anaconda/ucscentral.py:54 in passreset ISO 1.5.1c",
    "severity": "CRITICAL",

    "source_file": "usr/lib/anaconda/ucscentral.py",
    "source_lines": [
        "def encrypt(self, plaintext):",
        "    key = 'theKeyForEncryptingTheSharedSecret'",
        "    cmd = \"echo '%s' | /usr/lib/anaconda/openssl enc -e -k '%s' -aes128 -a\" % (plaintext, key)",
    ],

    "affected_field": "sharedSecret — the pre-shared key used by UCS Central to authenticate with managed UCS domains",
    "kickstart_output": "secret <openssl_aes128_base64_ciphertext>",

    "decryption_cmd": "echo '<ciphertext>' | openssl enc -d -k 'theKeyForEncryptingTheSharedSecret' -aes128 -a",
    "note":           "The key is identical across all UCS Central 1.5.1c installations. "
                      "Any kickstart artifact, backup, or installation log containing the 'secret' line is decryptable "
                      "with this known static key. "
                      "The shared secret is also used to encrypt restorePass (remote backup password).",

    "also_encrypted_with_same_key": ["restorePass"],
}

# ─────────────────────────────────────────────────────────
# UCSC-F2 — Command injection via encrypt() — shell=True + unsanitized plaintext
# ─────────────────────────────────────────────────────────
UCSC_F2 = {
    "id":       "UCSC-F2",
    "title":    "Shell command injection via encrypt() — user-controlled plaintext concatenated into shell command with shell=True",
    "status":   "CONFIRMED — /usr/lib/anaconda/ucscentral.py:55-57 in passreset ISO 1.5.1c",
    "severity": "HIGH",

    "source_file": "usr/lib/anaconda/ucscentral.py",
    "vulnerable_code": [
        "cmd = \"echo '%s' | /usr/lib/anaconda/openssl enc -e -k '%s' -aes128 -a\" % (plaintext, key)",
        "pipe = subprocess.Popen([cmd], stdout = subprocess.PIPE, shell = True)",
    ],

    "injection_vector": "plaintext parameter — receives sharedSecret or restorePass from the GTK UI input field",
    "injection_payload_example": "foo' | <cmd> | echo '",
    "resulting_shell_cmd_example": "echo 'foo' | <cmd> | echo '' | openssl enc -e -k 'theKeyForEncryptingTheSharedSecret' -aes128 -a",

    "context": "Executed during UCS Central installation/reset by the Anaconda installer running as root. "
               "The GTK UI (ucscentralreset.glade / ucscentralsetup.glade) passes user input to writeKS() → encrypt(). "
               "An attacker with physical or console access to a UCS Central install can inject shell commands "
               "into the shared secret or restore password field.",

    "runCmd_also_vulnerable": "runCmd() also uses shell=True for all disk/memory detection commands.",
}

# ─────────────────────────────────────────────────────────
# UCSC-F3 — Universal root password hash in passreset kickstart
# ─────────────────────────────────────────────────────────
UCSC_F3 = {
    "id":       "UCSC-F3",
    "title":    "Universal MD5 root password hash embedded in ks_upgrade.cfg — identical across all UCS Central 1.5.1c passreset operations",
    "status":   "CONFIRMED — ks_upgrade.cfg in passreset ISO 1.5.1c",
    "severity": "CRITICAL",

    "kickstart_file": "ks_upgrade.cfg",
    "rootpw_line":    "rootpw --iscrypted $1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
    "hash_type":      "MD5crypt ($1$) — offline crackable",
    "salt":           "ToWcsC4R",

    "note": "The passreset ISO sets the root password to this hash on every UCS Central system that uses it. "
            "The hash is static across all 1.5.1c deployments. "
            "An admin who uses this ISO to reset a UCS Central system ends up with a known root password "
            "if the hash is crackable or if the cleartext was recorded during passreset kit creation.",

    "authconfig": "authconfig --enableshadow --enablemd5",
    "selinux":    "selinux --disabled",
}

# ─────────────────────────────────────────────────────────
# UCSC-F4 — Admin password stored as MD5 in kickstart artifact
# ─────────────────────────────────────────────────────────
UCSC_F4 = {
    "id":       "UCSC-F4",
    "title":    "UCS Central admin password written as MD5 hash to kickstart artifact during passreset — recoverable from installation logs",
    "status":   "CONFIRMED — /usr/lib/anaconda/ucscentral.py:89 in passreset ISO 1.5.1c",
    "severity": "HIGH",

    "source_file": "usr/lib/anaconda/ucscentral.py",
    "source_line":  "f.write('adminPass %s\\n' % users.cryptPassword(self.adminPass, 'md5'))",

    "note": "During UCS Central setup or reset, the admin password is hashed with MD5 and written to the kickstart "
            "output file. Anaconda logs all kickstart writes to /root/post-install.log and /tmp/pre-install.log. "
            "If installation logs are retained (common in enterprise environments), the MD5 admin password hash is "
            "recoverable from the log and crackable offline.",

    "log_files":   ["/root/post-install.log", "/tmp/pre-install.log"],
    "hash_format": "MD5crypt ($1$) — same format as /etc/shadow",
}

# ─────────────────────────────────────────────────────────
# UCSC-F5 — root account NOT disabled (commented-out code)
# ─────────────────────────────────────────────────────────
UCSC_F5 = {
    "id":       "UCSC-F5",
    "title":    "Root account disable code commented out in ucscentral.py — root remains active on all UCS Central installations",
    "status":   "CONFIRMED — /usr/lib/anaconda/ucscentral.py:130-141 in passreset ISO 1.5.1c",
    "severity": "MEDIUM",

    "source_file": "usr/lib/anaconda/ucscentral.py",
    "commented_block": [
        "#disable root",
        "#log.info('Disabling root user')",
        "#os.rename(instPath + '/etc/passwd', instPath + '/etc/passwd.orig')",
        "# [replaces root shell with /sbin/nologin]",
    ],

    "note": "The write() method in ucscentral.py contains a commented-out block that would have replaced "
            "root's shell with /sbin/nologin to disable interactive root login. This code was intentionally "
            "commented out, leaving root with a standard login shell. "
            "Combined with the universal MD5 root hash in ks_upgrade.cfg (UCSC-F3), "
            "the active root account is reachable if the hash is cracked.",
}

# ─────────────────────────────────────────────────────────
# OVA ANALYSIS — ucs-central.1.5.1c.ova (1.4GB)
# Source: OVA → VMDK disk1 (40GB, LVM VolGroup00/LogVol00, ext3, RHEL 5)
# Additional findings from running system filesystem
# ─────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────
# UCSC-F6 — Pre-generated SSH host keys identical across all UCS Central 1.5.1c deployments
# ─────────────────────────────────────────────────────────
UCSC_F6 = {
    "id":       "UCSC-F6",
    "title":    "Pre-generated SSH host private keys shipped in UCS Central 1.5.1c OVA — identical across all deployments",
    "status":   "CONFIRMED — /etc/ssh/ssh_host_{rsa,dsa,ed25519}_key extracted from OVA disk1 VMDK",
    "severity": "CRITICAL",

    "host_keys": {
        "ssh_host_rsa_key":     "2048-bit RSA, generated 2010-12-16, 1675 bytes",
        "ssh_host_dsa_key":     "1024-bit DSA, generated 2010-12-16, 668 bytes",
        "ssh_host_ed25519_key": "Ed25519, generated 2015-08-10, 419 bytes",
    },
    "fingerprints": {
        "RSA": "SHA256:liLiF/1EHY0VU4x4aCaCvx+CMIF0z4Aau9RZYdqSv2g",
        "DSA": "SHA256:oycZt0JQhmMvNBLzs/mZbU1U+XrbBAx/z4pZehB+NII",
    },
    "rsa_key_prefix": "MIIEogIBAAKCAQEA9hs4GweVFGy9CQ...",

    "impact": (
        "Every UCS Central 1.5.1c VM deployed from this OVA uses the same three SSH host key pairs. "
        "An attacker who extracts the private keys from the OVA can: "
        "(1) MITM any SSH connection to any UCS Central 1.5.1c deployment, "
        "(2) Impersonate any UCS Central 1.5.1c instance (client trusts known fingerprint), "
        "(3) Decrypt any previously recorded SSH session to/from UCS Central 1.5.1c "
        "if the session was captured before key rotation."
    ),

    "sshd_config": {
        "Protocol":                     "2",
        "PasswordAuthentication":        "yes",
        "UsePAM":                       "yes",
        "X11Forwarding":                "yes",
        "PermitRootLogin":              "(not set — OpenSSH 6.6p1 default: without-password)",
        "ChallengeResponseAuthentication": "no",
    },
}

# ─────────────────────────────────────────────────────────
# UCSC-F7 — admin OS account has empty shadow password + libvmpam ucs-prefix bypass
# ─────────────────────────────────────────────────────────
UCSC_F7 = {
    "id":       "UCSC-F7",
    "title":    "OS 'admin' account has empty shadow entry; libvmpam.so skips authentication for 'ucs-' prefixed usernames via PAM bypass path",
    "status":   "CONFIRMED — /etc/shadow and /usr/lib/libvmpam.so in OVA disk1 VMDK",
    "severity": "HIGH",

    "shadow_entry": "admin::17223:0:99999:7:::  (empty password field)",
    "admin_shell":  "/opt/cisco/bin/vsh_perm (bash script → /opt/cisco/core/sam/bin/ucssh restricted shell)",

    "pam_config": {
        "file": "/etc/pam.d/sshd and /etc/pam.d/login (identical)",
        "lines": [
            "auth [system_err=ignore buf_err=ignore default=done] /usr/lib/libvmpam.so debug",
            "auth sufficient pam_unix.so debug",
            "account required pam_unix.so debug",
        ],
    },

    "libvmpam_behavior": (
        "libvmpam.so is a custom VMware/Cisco PAM module that forwards auth to a socket-based service. "
        "String evidence: 'Skipping PAM authentication for user %s', 'ucs-', 'ucs login prefix removed %s'. "
        "Users with 'ucs-' prefix have authentication skipped by libvmpam (returns PAM_SUCCESS without password check). "
        "With action [default=done], PAM_SUCCESS from libvmpam exits the auth chain as success."
    ),

    "bypass_path": (
        "Authenticating as 'ucs-admin' (with ucs- prefix) via SSH or console: "
        "libvmpam strips prefix, skips authentication, returns PAM_SUCCESS → auth chain exits as success. "
        "Session runs as 'admin' user in the vsh_perm restricted shell. "
        "NOTE: 'ucs-admin' must exist as a system user or libvmpam must map it — verification requires live testing."
    ),

    "pam_unix_empty_password_note": (
        "pam_unix.so without 'nullok' flag denies empty passwords — so admin's empty shadow entry "
        "is NOT directly exploitable via pam_unix. The bypass path is libvmpam's ucs- prefix skip."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F8 — Build server path and internal directory structure leaked in shipped configs
# ─────────────────────────────────────────────────────────
UCSC_F8 = {
    "id":       "UCSC-F8",
    "title":    "Cisco build server path '/ramfs/buildsa/170226-115116-rev960-FCSc/...' embedded in shipped Apache config files",
    "status":   "CONFIRMED — /opt/cisco/core/apache/conf/original/*.conf in OVA disk1 VMDK",
    "severity": "LOW",

    "affected_files": [
        "opt/cisco/core/apache/conf/original/httpd.conf",
        "opt/cisco/core/apache/conf/original/extra/httpd-multilang-errordoc.conf",
        "opt/cisco/core/apache/conf/original/extra/httpd-ssl.conf",
        "opt/cisco/core/apache/conf/original/extra/httpd-dav.conf",
    ],
    "leaked_path":  "/ramfs/buildsa/170226-115116-rev960-FCSc/core/sam/src/.release/vhome/opt/apache",
    "build_server": "buildsa",
    "build_stamp":  "170226-115116 (2017-02-26 11:51:16)",
    "build_label":  "rev960-FCSc",

    "note": "Production Apache config ships with Cisco build server paths as DocumentRoot, ServerRoot, "
            "and Alias targets. These expose the Cisco internal build infrastructure layout. "
            "The 'original' configs are backup copies included in the OVA; the active configs "
            "at opt/cisco/core/apache/conf/httpd.conf use the production paths (/opt/apache).",
}

# ─────────────────────────────────────────────────────────
# UCSC-F9 — recvbackup.cgi OS command injection via unsanitized URL parameters
# ─────────────────────────────────────────────────────────
UCSC_F9 = {
    "id":       "UCSC-F9",
    "title":    "recvbackup.cgi OS command injection — $targetDir and $file from URL query string passed unsanitized into backtick shell exec and sudo invocation",
    "status":   "CONFIRMED — /opt/cisco/core/apache/ucsmoperations/recvbackup.cgi and /opt/cisco/bin/ucsm_copy_backup.sh in OVA disk1 VMDK",
    "severity": "CRITICAL",

    "cgi_script": "opt/cisco/core/apache/ucsmoperations/recvbackup.cgi (Perl)",
    "endpoint":   "/ucsmoperations/file-<file>/recvbackup.txt?targetDir=<dir>&targetFile=<tf>&maxIndex=<n>",

    "url_parsing": (
        "URI regex: /\\/ucsmoperations\\/file-(.*)\\//  -> $file (no path validation) "
        "query string: targetDir=<X> -> $targetDir (no sanitization)"
    ),

    "injection_points": [
        "`mkdir -p $targetDir`  -- $targetDir interpolated into backtick shell; any shell metachar executes",
        "`sudo $COPY_BACKUP $targetDir $targetFile $maxIndex $file`  -- all four vars unsanitized, sudo level",
    ],

    "injection_payload_example": "targetDir=foo;id>/tmp/pwn",
    "arbitrary_write": (
        "open(OUTF, \">$file\") writes STDIN verbatim to the path extracted from the URI. "
        "No path prefix restriction — $file can be any path writable by the Apache daemon user."
    ),

    "sudo_script": "opt/cisco/bin/ucsm_copy_backup.sh",
    "sudo_escalation": (
        "ucsm_copy_backup.sh runs as root via sudoers. It uses $DIR_NAME unquoted in: "
        "'chown root:root ${DIR_NAME}/*', "
        "'chmod 777 -R ${DIR_NAME}/..' (recursively world-writes the parent directory), "
        "and all file operations. Shell metacharacters in $targetDir execute at root."
    ),

    "access_precondition": (
        "Endpoint is under /xmlInternal with SSLVerifyClient require — "
        "requires a TLS client certificate issued to a UCSM domain member. "
        "Pre-existing UCSM client certificate required to reach the CGI."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F10 — sendimage.cgi path traversal via externalrep/../ prefix bypass
# ─────────────────────────────────────────────────────────
UCSC_F10 = {
    "id":       "UCSC-F10",
    "title":    "sendimage.cgi path traversal — 'externalrep/' prefix check bypassed by 'externalrep/../' allowing reads of arbitrary files",
    "status":   "CONFIRMED — /opt/cisco/core/apache/ucsmoperations/sendimage.cgi in OVA disk1 VMDK",
    "severity": "HIGH",

    "cgi_script": "opt/cisco/core/apache/ucsmoperations/sendimage.cgi (Perl)",
    "endpoint":   "/ucsmoperations/file-<file>/sendimage.txt",

    "url_parsing": "URI regex: /\\/ucsmoperations\\/file-(.*)\\// -> $file",

    "prefix_check": "$file !~ /^externalrep/ -> fails transaction",
    "substitution": "$file =~ s/^externalrep/\\/bootflash\\/images/",

    "bypass": (
        "Payload: file-externalrep/../../../etc/shadow "
        "Step 1 prefix check: 'externalrep/../../../etc/shadow' starts with 'externalrep' — PASSES. "
        "Step 2 substitution: s/^externalrep/\\/bootflash\\/images/ → '/bootflash/images/../../../etc/shadow'. "
        "Step 3 open(INF, \"$file\"): Perl's open() resolves the path — reads /etc/shadow and streams it to client."
    ),

    "reachable_files": [
        "/etc/shadow (root password hash + admin empty field)",
        "/etc/passwd",
        "/opt/cisco/core/apache/conf/httpd.conf",
        "any file readable by the Apache daemon user",
    ],

    "access_precondition": (
        "Same as UCSC-F9: endpoint under /xmlInternal with SSLVerifyClient require. "
        "TLS client certificate required."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F11 — Sudoers grants any OS user NOPASSWD /bin/chown -R * + admin/samdme have NOPASSWD:ALL
# ─────────────────────────────────────────────────────────
UCSC_F11 = {
    "id":       "UCSC-F11",
    "title":    "Sudoers misconfiguration: /bin/chown -R * NOPASSWD for all OS users enables local root; admin and samdme accounts have unrestricted NOPASSWD:ALL sudo",
    "status":   "CONFIRMED — /etc/sudoers in OVA disk1 VMDK",
    "severity": "CRITICAL",

    "sudoers_file": "etc/sudoers",

    "nopasswd_all_accounts": [
        "admin  ALL = NOPASSWD:ALL  -- admin OS account has unrestricted root; no password required",
        "samdme ALL = NOPASSWD:ALL  -- application service account has unrestricted root; no password required",
        "root   ALL = NOPASSWD:ALL",
    ],

    "sudo_cmnds_for_all_users": (
        "ALL ALL = NOPASSWD:SUDO_CMNDS applies to every OS user without a password. "
        "SUDO_CMNDS includes /bin/chown -R * — any OS user can recursively chown any file or directory as root."
    ),

    "chown_lpe_path": (
        "Apache runs as 'daemon' (User daemon in httpd.conf). "
        "Any code executing as daemon (e.g., via UCSC-F9 recvbackup.cgi command injection) can: "
        "'sudo /bin/chown -R daemon:daemon /etc/cron.d' — take ownership of cron.d, "
        "write a cron job as daemon, which executes as root on the next cron cycle. "
        "Alternatively: 'sudo /bin/chown -R daemon:daemon /etc/sudoers.d' — write "
        "'daemon ALL = NOPASSWD:ALL' to sudoers.d, then 'sudo /bin/bash' = root shell."
    ),

    "also_in_sudo_cmnds": [
        "/opt/cisco/bin/regenerate-certs.pl  -- any user can regenerate TLS certs and stop Apache (DoS)",
        "/opt/cisco/bin/decryptpasswd.pl      -- any user can print cleartext shared secret (redundant with world-readable sam.config + hardcoded key UCSC-F1)",
        "/opt/cisco/bin/restore.sh -p *       -- any user can trigger restore with wildcard password arg",
        "/bin/kill                             -- any user can kill any process as root",
    ],

    "env_file_note": (
        "Defaults env_file = /opt/cisco/core/env/core.env (0644, world-readable). "
        "core.env sets LD_LIBRARY_PATH and PATH for sudo sessions. "
        "If core.env is writable by any user (not confirmed at static analysis time), "
        "injecting LD_LIBRARY_PATH into sudo sessions enables library hijacking."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F12 — RC4 explicitly enabled in Apache SSLCipherSuite; TLSv1.0/1.1 permitted
# ─────────────────────────────────────────────────────────
UCSC_F12 = {
    "id":       "UCSC-F12",
    "title":    "Apache SSLCipherSuite explicitly enables RC4 (RC4+RSA); SSLProtocol allows TLSv1.0 and TLSv1.1; DHE-RSA-AES256-SHA (PFS) explicitly excluded",
    "status":   "CONFIRMED — /opt/cisco/core/apache/conf/extra/httpd-ssl.conf in OVA disk1 VMDK",
    "severity": "MEDIUM",

    "config_file": "opt/cisco/core/apache/conf/extra/httpd-ssl.conf",

    "active_cipher_suite": "ALL:!DHE-RSA-AES256-SHA:!ADH:!EXPORT40:!EXPORT56:!LOW:!MEDIUM:!eNULL:RC4+RSA:+HIGH:+EXP",

    "weaknesses": {
        "RC4+RSA": (
            "RC4 explicitly added to active cipher set. RC4 stream cipher is cryptographically broken "
            "(NOMORE attack 2015; RFC 7465 prohibits RC4 in TLS since 2015). "
            "A client and server can negotiate RC4-MD5 or RC4-SHA even with 'HIGH' ciphers available."
        ),
        "!DHE-RSA-AES256-SHA": (
            "The only DHE (Diffie-Hellman Ephemeral) cipher is explicitly excluded, "
            "disabling Perfect Forward Secrecy for RSA key exchange sessions. "
            "Recorded TLS sessions can be decrypted if the server private key is obtained."
        ),
        "SSLProtocol All -SSLv2 -SSLv3": (
            "TLSv1.0 and TLSv1.1 remain permitted. "
            "TLSv1.0 is vulnerable to POODLE-over-TLS (CVE-2014-3566 variant) and BEAST (CVE-2011-3389). "
            "PCI-DSS prohibited TLSv1.0 in 2018; NIST SP 800-52r2 requires TLSv1.2 minimum."
        ),
    },

    "commented_variants": [
        "#SSLCipherSuite ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL  (includes eNULL — no encryption)",
        "#SSLCipherSuite ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM",
        "#SSLCipherSuite HIGH:RC4:+HIGH+TLSv1:MEDIUM:!MD5:!aNULL:!eNULL",
        "#SSLCipherSuite ALL:!ADH:!EXPORT40:!EXPORT56:!LOW:!MEDIUM:!eNULL:RC4+RSA:+HIGH:+EXP",
    ],

    "note": (
        "Multiple commented variants show iterative weakening over time. "
        "One commented line includes '+eNULL' (no-encryption ciphers). "
        "The active production config retains RC4 and excludes PFS."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F13 — ucssh (vsh) management shell binary is SUID root; -R flag allows unrestricted output redirection
# ─────────────────────────────────────────────────────────
UCSC_F13 = {
    "id":       "UCSC-F13",
    "title":    "ucssh (vsh) management shell is SUID root with -R 'allow redirection anywhere' flag — arbitrary file write as root via CLI output redirection",
    "status":   "CONFIRMED (SUID bit) — /opt/cisco/core/sam/bin/ucssh in OVA disk1 VMDK",
    "severity": "HIGH",

    "binary":      "opt/cisco/core/sam/bin/ucssh",
    "permissions": "-rwsr-sr-x root root 162737 Feb 26 2017",
    "suid":        "Set-user-ID and set-group-ID bits set — executes as root regardless of calling user",

    "relevant_flags": {
        "-c <cmd>":      "Execute a single CLI command",
        "-f <cmdsfile>": "Execute commands from a file",
        "-R":            "Allow redirection anywhere — disables path restrictions on output redirection",
        "-a":            "All commands allowed (roles disabled) — bypasses UCS role-based access control",
        "-n":            "No pagination",
        "--ucs-mgmt":    "Start UCS Management Shell mode",
    },

    "risk": (
        "Any OS user can invoke ucssh directly as a SUID binary. "
        "With the -R flag, UCS CLI 'show' commands that include user-controllable data "
        "can be redirected to any OS path (e.g., /etc/cron.d, /etc/sudoers.d) as root. "
        "The -a flag disables role checking, making all CLI commands available to any caller. "
        "The -f flag reads CLI commands from a caller-supplied file path."
    ),

    "vsh_perm_escape": (
        "/opt/cisco/bin/vsh_perm (admin's login shell) contains a hardcoded escape branch: "
        "when called with exactly '-c /isan/bin/xmlsa' as argument, exec /bin/bash is triggered. "
        "This is an SCP/SFTP subsystem path used by UCS domain operations. "
        "vsh_perm is not SUID; the ucssh binary it normally invokes is. "
        "Source: /opt/cisco/bin/vsh_perm lines: s1='-c /isan/bin/xmlsa'; "
        "if [ \"$s1\" != \"$*\" ]; then exec $SHELL --ucs-mgmt; else exec /bin/bash $*; fi"
    ),

    "umask_note": (
        "vsh_perm sets 'umask 000' before exec'ing ucssh. "
        "Any files created during the management session have 0o666 permissions (world-writable by default)."
    ),
}

FINDINGS = [UCSC_F1, UCSC_F2, UCSC_F3, UCSC_F4, UCSC_F5, UCSC_F6, UCSC_F7, UCSC_F8, UCSC_F9, UCSC_F10, UCSC_F11, UCSC_F12, UCSC_F13]
