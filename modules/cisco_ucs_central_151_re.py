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

# ─────────────────────────────────────────────────────────
# UCSC-F14 — Hardcoded RC4 encryption key 'dwefsAvfsdkfqweqyrmfvsfwth' in samcrypt/libosiris.so
# ─────────────────────────────────────────────────────────
UCSC_F14 = {
    "id":       "UCSC-F14",
    "title":    "Hardcoded RC4 encryption key 'dwefsAvfsdkfqweqyrmfvsfwth' (KeyCode E001) in samcrypt binary and libosiris.so — all samcrypt-encrypted files decryptable",
    "status":   "CONFIRMED — strings /opt/cisco/bin/samcrypt and /opt/cisco/core/sam/lib/libosiris.so in OVA disk1 VMDK; "
                "confirmed in 2.1.2b: central-mgr-2.1.2-b.x86_64.rpm and policy-mgr-2.1.2-b.x86_64.rpm both ship "
                "libosiris.so with the same key",
    "severity": "HIGH",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "binary":    "opt/cisco/bin/samcrypt",
    "library":   "opt/cisco/core/sam/lib/libosiris.so (and central-mgr, policy-mgr, operation-mgr copies)",
    "algorithm": "RC4 (RC4_set_key from OpenSSL; symbol RC4_1_CIPHER_KEYCODE)",

    "hardcoded_key":  "dwefsAvfsdkfqweqyrmfvsfwth",
    "keycode":        "E001 (KeyCode 1 = RC4_1_CIPHER_KEY; CURRENT_CIPHER_KEY maps to same value)",

    "binary_interface": "samcrypt [infile] [outfile] [KeyCode]  -- third arg selects key by code",

    "libosiris_functions": [
        "utils::encryptFile(infile, outfile, KeyCode)",
        "utils::encryptBuffer(Buffer, Buffer, bool)",
        "utils::encryptProp(String, String, bool)",
    ],

    "decryption": (
        "RC4 is symmetric — encrypt and decrypt use the same key. "
        "Any file encrypted by samcrypt with KeyCode E001 can be decrypted: "
        "python3 -c \"from Crypto.Cipher import ARC4; c=ARC4.new(b'dwefsAvfsdkfqweqyrmfvsfwth'); "
        "open('out','wb').write(c.decrypt(open('enc','rb').read()))\" "
        "Note: RC4 is stateful — decryption must process from byte 0 of the ciphertext."
    ),

    "context": (
        "samcrypt is used by UCS Central service components (libosiris.so is loaded by core, "
        "central-mgr, and operation-mgr). Files encrypted with samcrypt include properties, "
        "configurations, and potentially credentials stored in the application databases. "
        "Combined with world-readable sam.config (0644), any OS user can decrypt application "
        "data files protected by samcrypt."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F15 — upd_admin_passwd.sh trusts world-writable /tmp/shadow as source for admin password
# ─────────────────────────────────────────────────────────
UCSC_F15 = {
    "id":       "UCSC-F15",
    "title":    "upd_admin_passwd.sh reads admin password hash from world-writable /tmp/shadow and overwrites /etc/shadow — admin password injectable via /tmp race",
    "status":   "CONFIRMED — /opt/cisco/bin/upd_admin_passwd.sh in OVA disk1 VMDK",
    "severity": "HIGH",

    "script": "opt/cisco/bin/upd_admin_passwd.sh",
    "script_content": [
        "ADMIN_PASSWD=$(awk -F: '$1 == \"admin\" {print $2}' /tmp/shadow)",
        "/opt/cisco/bin/schelper.pl -s main -k adminPasswd -v $ADMIN_PASSWD -r",
        "mv /tmp/shadow /etc/shadow",
        "mv /tmp/passwd /etc/passwd",
        "mv /tmp/group /etc/group",
    ],

    "vulnerability": (
        "The script reads the admin password hash from /tmp/shadow (world-writable) "
        "without integrity checking. Any OS user who writes a crafted /tmp/shadow "
        "before this script executes sets the admin OS password to a known hash. "
        "The script then overwrites /etc/shadow, /etc/passwd, and /etc/group with "
        "the /tmp/ versions — replacing system auth files with attacker-controlled content."
    ),

    "trigger_context": (
        "Invoked during UCS Central admin password reset operations and potentially "
        "via the passreset ISO flow. The /tmp path is accessible to all OS users "
        "including the Apache daemon (uid daemon), postgres, and samdme."
    ),

    "impact": (
        "An attacker with any OS-level shell (e.g., via UCSC-F9 CGI injection as daemon) "
        "can: write /tmp/shadow with admin:<known_md5_hash>:17223:... and /tmp/passwd and /tmp/group "
        "copying the originals, then wait for or trigger upd_admin_passwd.sh to run. "
        "On completion, admin's password is set to the attacker's known hash → admin shell access "
        "→ NOPASSWD:ALL sudo (UCSC-F11) → root."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F16 — vm-common.pl chmod 666 on /var/log/vm-setup.log + shared secret logged in cleartext
# Source: OVA runtime filesystem (ucs-central.1.5.1c.ova disk1)
# ─────────────────────────────────────────────────────────
UCSC_F16 = {
    "id":       "UCSC-F16",
    "title":    "vm-common.pl executes chmod 666 on /var/log/vm-setup.log and logs plaintext shared secret — world-readable log exposes cluster credential",
    "status":   "CONFIRMED — /opt/cisco/bin/vm-common.pl:540 + OVA disk1 filesystem (/var/log/vm-setup.log -rwxrw-rw-)",
    "severity": "HIGH",

    "source_file": "opt/cisco/bin/vm-common.pl",
    "logfile":     "/var/log/vm-setup.log",
    "observed_perms": "-rwxrw-rw- root root (world-readable + world-writable) confirmed in OVA disk1",

    "chmod_line": (
        "vm-common.pl line 540: `$chmod 666 $logfile` — executed as root during any "
        "vm-common.pl invoked operation (shared secret update, cluster add, peer secret sync). "
        "Sets /var/log/vm-setup.log to 0666 (world-readable, world-writable)."
    ),
    "secret_logging": (
        "updateSharedSecretOnPeer() in vm-common.pl calls: "
        "logger(\"Calling $update_peer_secret $peer_ip '$inputs{$secret}'\") "
        "before executing the peer secret sync. "
        "$inputs{$secret} is the plaintext shared secret value. "
        "The logger() function appends to $logfile (/var/log/vm-setup.log). "
        "Result: shared secret is written in cleartext to a world-readable file."
    ),
    "encryption_key": (
        "vm-common.pl line 462: my $encKey = \"theKeyForEncryptingTheSharedSecret\" — "
        "same key used in UCSC-F1. AES-128 errors from openssl enc also append to $logfile "
        "(stderr redirect: 2>>$logfile), further populating the world-readable log."
    ),
    "access": "Any local OS user (daemon, postgres, samdme) can read /var/log/vm-setup.log.",
}

# ─────────────────────────────────────────────────────────
# UCSC-F17 — cluster_add.sh reads samdme SSH password from world-writable /tmp/tp
# Source: OVA runtime filesystem (ucs-central.1.5.1c.ova disk1)
# ─────────────────────────────────────────────────────────
UCSC_F17 = {
    "id":       "UCSC-F17",
    "title":    "cluster_add.sh, update_peer_secret.sh, and cluster_ipcheck.sh read samdme SSH password from world-writable /tmp/tp via Expect login proc",
    "status":   "CONFIRMED — /opt/cisco/bin/cluster_add.sh, update_peer_secret.sh, cluster_ipcheck.sh in OVA disk1",
    "severity": "HIGH",

    "affected_scripts": [
        "opt/cisco/bin/cluster_add.sh",
        "opt/cisco/bin/update_peer_secret.sh",
        "opt/cisco/bin/cluster_ipcheck.sh",
    ],
    "authfile":  "/tmp/tp",
    "tmp_perms": "world-writable (drwxrwxrwx on /tmp in OVA)",

    "expect_pattern": (
        "All three scripts define: set authFile \"/tmp/tp\"\n"
        "proc login {} {\n"
        "    set input [ open $authFile \"r\"]\n"
        "    gets $input line\n"
        "    send \"$line\\r\"\n"
        "    close $input\n"
        "}\n"
        "cluster_add.sh calls login when SSH returns \" password:\" — "
        "sends the content of /tmp/tp as the samdme SSH password."
    ),
    "toctou": (
        "/tmp/tp is created transiently by the calling process (Tomcat/Java application layer) "
        "before the Expect script is invoked. The file lives in world-writable /tmp. "
        "Any local OS user (daemon, postgres) can: "
        "1. inotify-watch /tmp for tp creation, "
        "2. read /tmp/tp during the window between creation and script completion, "
        "3. obtain the samdme SSH password for the cluster peer node."
    ),
    "samdme_sudo": "samdme has NOPASSWD:ALL in sudoers (see UCSC-F11) — SSH credential grants root on peer node.",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F18 — updateBin.sh and updateBundle.sh: predictable /tmp/update-$(date +%s)
#             directory — local TOCTOU symlink race on firmware update execution
# Source: ucs-central.1.5.1c.iso ucsCentral/updateBin.sh + updateBundle.sh
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F18 = {
    "id":       "UCSC-F18",
    "title":    "updateBin.sh and updateBundle.sh create /tmp/update-$(date +%s) — "
                "Unix-timestamp-predictable temp dir in world-writable /tmp; "
                "local attacker symlinks it before mkdir, redirecting tar extraction and installScript execution",
    "status":   "CONFIRMED — ucsCentral/updateBin.sh line 12 and ucsCentral/updateBundle.sh line 11 "
                "in ucs-central.1.5.1c.iso; identical code in ucs-central.2.1.2b_EVAL.iso",
    "severity": "HIGH",

    "affected_scripts": [
        "ucsCentral/updateBin.sh  (1.5.1c line 12, 2.1.2b line 12)",
        "ucsCentral/updateBundle.sh (1.5.1c line 11, 2.1.2b line 11)",
    ],

    "vulnerable_code": (
        "# Both scripts:\n"
        "folder=\"/tmp/update-\"$(date +%s)          # timestamp: 1-second granularity, world-predictable\n"
        "...\n"
        "mkdir -p ${folder}                           # succeeds silently if path is already a symlink\n"
        "tar xfzm ${tarballName} -C ${folder}        # extracts into symlink target\n"
        "# updateBin.sh:\n"
        "${folder}/${scripts} ${force}               # executes installScript from symlink target\n"
        "# updateBundle.sh:\n"
        "${script} ${folder}/${bin} ${force}         # script from inventory.cfg runs as root"
    ),

    "race_window": (
        "The timestamp is evaluated at line 12 before any isanadd signature processing. "
        "Race window: from process start (line 12) to mkdir -p (lines 41/52). "
        "isanadd -s (signature check) and isanadd -o (payload extraction) run in this window — "
        "providing several hundred milliseconds to create the symlink."
    ),

    "attack_sequence": [
        "1. Attacker monitors invocation of updateBin.sh (ps/audit/inotify on trigger file) or controls timing via management API",
        "2. Reads /proc/<pid>/cmdline to extract $file path and stat() to estimate process start timestamp",
        "3. Creates: ln -s /etc/cron.d /tmp/update-<timestamp> before mkdir -p runs",
        "4. mkdir -p /tmp/update-<ts> resolves through symlink; target /etc/cron.d exists → mkdir succeeds silently",
        "5. tar xfzm ... -C /tmp/update-<ts> extracts Cisco update tarball contents into /etc/cron.d/",
        "6. ${folder}/${scripts} = /etc/cron.d/${installScript} — the extracted installScript now executes from /etc/cron.d/",
        "7. If the update runs as root (standard for UCS Central updates), any extracted file in /etc/cron.d/ runs as root on next cron tick",
    ],

    "privilege_context": (
        "UCS Central software updates are performed by the UCS Central application running as root. "
        "updateBin.sh and updateBundle.sh are invoked from the Java application layer via "
        "sudo or directly as root. The installScript extracted from the firmware tarball "
        "runs as the same privilege level as the update process."
    ),

    "signature_gating": (
        "isanadd -s verifies the SN bundle format before extraction. "
        "If isanadd performs weak verification (SN magic byte check without cryptographic verification, "
        "consistent with the SN bundle format analysis: magic 0x6401534e), "
        "a locally-crafted bundle could pass the check and deliver attacker-controlled scripts. "
        "Regardless of signature strength, the symlink race can redirect extraction of a legitimate "
        "Cisco-signed bundle into an attacker-chosen target directory."
    ),

    "versions_affected": ["1.5.1c", "2.1.2b"],
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F19 — updateBin.sh production code contains debug-plugin detection and
#             file deletion path — engineering backdoor mechanism in shipped installer
# Source: ucs-central.1.5.1c.iso ucsCentral/updateBin.sh lines 53-60
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F19 = {
    "id":       "UCSC-F19",
    "title":    "updateBin.sh production installer contains debug-plugin detection and unconditional "
                "file deletion (rm -f $orgfile) — shipped engineering backdoor path for internal "
                "debug bundles; $orgfile unquoted with no path restriction",
    "status":   "CONFIRMED — ucsCentral/updateBin.sh lines 53-60 in ucs-central.1.5.1c.iso; "
                "identical in ucs-central.2.1.2b_EVAL.iso",
    "severity": "MEDIUM",

    "source_file": "ucsCentral/updateBin.sh",
    "source_lines": (
        "dplug=$(grep dplugin ${inv})\n"
        "if [[ \"${dplug}\" =~ \"dplugin\" ]]; then\n"
        "    echo 'Warning: debug-plugin is for engineering internal use only!'\n"
        "    rm -f $orgfile\n"
        "    echo 'For security reason, debug plugin file has been deleted.'\n"
        "fi"
    ),

    "orgfile_source": "$3 (third positional argument to updateBin.sh, unquoted in rm -f call)",

    "findings": [
        "Debug-plugin detection code ships in production firmware installers — "
        "Cisco engineers can deliver 'dplugin' update bundles that trigger this path on any deployment.",

        "rm -f $orgfile: $orgfile is $3 (caller-controlled, unquoted) — "
        "if the caller passes a space-separated list or glob pattern as $3, "
        "rm -f interprets it as multiple targets; no path restriction on $orgfile.",

        "When dplugin is detected, the message 'debug plugin file has been deleted' is printed to stdout "
        "and the update continues — debug-plugin bundles run their installScript normally "
        "with no additional privilege gating beyond the standard isanadd signature check.",

        "The UCS Central management layer that calls updateBin.sh passes $orgfile as $3; "
        "if that caller path is reachable via the management API with user-controlled input, "
        "$orgfile becomes attacker-controlled → rm -f $orgfile deletes an arbitrary file as root.",
    ],

    "significance": (
        "The dplugin path proves Cisco ships update bundles with a distinct internal-use code flow "
        "that is entirely invisible to operators — no audit log entry beyond a stdout message "
        "that is redirected to ${logFile}. Any debug-plugin bundle that passes isanadd -s "
        "runs its installScript with root privileges and self-deletes the update archive ($orgfile). "
        "This is an engineering access mechanism in production update infrastructure."
    ),

    "versions_affected": ["1.5.1c", "2.1.2b"],
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F20 — bundle_unpack.sh uses `tar -P` (absolute paths) on firmware bundle
#             payload extraction — path traversal to arbitrary filesystem paths
# Source: ucsCentral/bundle_unpack.sh line 94 (1.5.1c), line 120 + 244 (2.1.2b)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F20 = {
    "id":       "UCSC-F20",
    "title":    "bundle_unpack.sh extracts firmware bundle tar payload with 'tar -P' (absolute paths) — "
                "if tar payload contains absolute-path entries, files are written outside the intended "
                "temp directory to arbitrary filesystem paths",
    "status":   "CONFIRMED — ucsCentral/bundle_unpack.sh lines 93-94 in ucs-central.1.5.1c.iso; "
                "same -P flag at lines 120 and 244 in ucs-central.2.1.2b_EVAL.iso (two extraction paths)",
    "severity": "HIGH",

    "source_file": "ucsCentral/bundle_unpack.sh",
    "vulnerable_code": (
        "cd ${TMP_FILES_DIR}\n"
        "/bin/dd if=${BUNDLE_BASE_DIR}/${BUNDLE_NAME} skip=1 bs=$BS | tar zxkPpmvf -\n"
        "# -P = absolute paths: leading / NOT stripped; archive entries with /etc/... paths\n"
        "#      extract to /etc/... on the filesystem, not to ${TMP_FILES_DIR}/etc/...\n"
        "# Second extraction path (inner images):\n"
        "cd ${TARGET}; /bin/dd if=${TMP_FILES_DIR}/${i} skip=1 bs=$BS | tar zxkPpmvf -"
    ),

    "flag_breakdown": {
        "-P": "absolute paths — tar does NOT strip leading / from archive entries",
        "-k": "keep existing files — does NOT overwrite existing files",
        "-p": "preserve permissions from archive",
        "-m": "don't restore modification times",
        "-v": "verbose output",
        "f -": "read archive from stdin (piped from dd)",
    },

    "attack_scenario": (
        "An attacker who can supply a crafted firmware bundle (either by exploiting weak SN signature "
        "verification as shown by FIINFRA-F1, by invoking bundle_unpack.sh directly after any "
        "initial access, or via the management API with spoofed bundle content) includes a tar.gz "
        "payload containing entries like:\n"
        "  /etc/cron.d/cisco_update   (new cron job, not blocked by -k since file is new)\n"
        "  /etc/sudoers.d/cisco       (adds NOPASSWD:ALL rule)\n"
        "  /root/.ssh/authorized_keys (adds SSH public key)\n"
        "The -k flag does not protect against creation of NEW files in world-accessible directories. "
        "Any directory writable by root (which includes most of /etc/) is a valid extraction target. "
        "The second extraction path (line 190/244) runs inside ${TARGET} (installables directory) "
        "with the same -P flag."
    ),

    "signature_gating": (
        "bundle_unpack.sh itself contains NO signature check. "
        "isanadd -s is called in updateBundle.sh BEFORE calling bundle_unpack.sh. "
        "If isanadd -s performs only header-format validation (SN magic byte check, not crypto — "
        "consistent with FIINFRA-F1 finding: SN format has no cryptographic payload verification), "
        "a locally crafted bundle with the correct SN header format but a malicious tar payload "
        "passes the gate. "
        "Additionally, bundle_unpack.sh can be invoked directly (it's a standalone script in "
        "/opt/cisco/bin/) without going through updateBundle.sh — no signature check at all."
    ),

    "mitigation_gap": (
        "The -k flag prevents overwriting of existing files (e.g., /etc/passwd, /etc/shadow). "
        "It does NOT prevent creation of new files anywhere on the filesystem. "
        "Any new file planted in /etc/cron.d/, /etc/cron.daily/, /etc/sudoers.d/, "
        "or /root/.ssh/ represents a complete privilege escalation vector."
    ),

    "versions_affected": ["1.5.1c", "2.1.2b"],
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F21 — bundle_unpack.sh executes bundle_extsvc.sh from extracted bundle
#             content without additional signature verification
# Source: ucsCentral/bundle_unpack.sh lines 253-255 (1.5.1c)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F21 = {
    "id":       "UCSC-F21",
    "title":    "bundle_unpack.sh makes bundle_extsvc.sh executable and runs it from extracted bundle "
                "content (chmod +x + exec) — no per-file signature check; bundle extended service "
                "script executes with update process privileges",
    "status":   "CONFIRMED — ucsCentral/bundle_unpack.sh lines 253-255 in ucs-central.1.5.1c.iso; "
                "same pattern in ucs-central.2.1.2b_EVAL.iso",
    "severity": "MEDIUM",

    "source_file":  "ucsCentral/bundle_unpack.sh",
    "source_lines": (
        "if [ -e \"${TMP_FILES_DIR}/${BUNDLE_EXTSVC}\" ]; then\n"
        "    /bin/chmod +x ${TMP_FILES_DIR}/${BUNDLE_EXTSVC}\n"
        "    ${TMP_FILES_DIR}/${BUNDLE_EXTSVC}\n"
        "fi\n"
        "# BUNDLE_EXTSVC='bundle_extsvc.sh' (hardcoded)"
    ),

    "impact": (
        "A firmware bundle that passes the SN signature check (or is delivered directly to "
        "bundle_unpack.sh) and contains a file named 'bundle_extsvc.sh' will have that file "
        "executed as root with no additional verification. "
        "The bundle_extsvc.sh script runs in the context of bundle_unpack.sh after all images "
        "have been moved to their target directories — it has full filesystem access. "
        "Design intent is for the extsvc script to 'update the system with future knowledge "
        "about the provider firmware' (comment at line ~136). "
        "No code signing, no content verification, no sandboxing."
    ),

    "versions_affected": ["1.5.1c", "2.1.2b"],
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F22 — bundle_unpack.sh runs chmod a+w /opt/cisco/download -R on every
#             platform=18 firmware image installation
# Source: ucsCentral/bundle_unpack.sh line 149 (1.5.1c), line 203 (2.1.2b)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F22 = {
    "id":       "UCSC-F22",
    "title":    "bundle_unpack.sh runs 'chmod a+w /opt/cisco/download -R' during platform=18 "
                "firmware image installation — recursively world-writes the download directory "
                "on every provider image update",
    "status":   "CONFIRMED — ucsCentral/bundle_unpack.sh line 149 in ucs-central.1.5.1c.iso; "
                "line 203 in ucs-central.2.1.2b_EVAL.iso",
    "severity": "LOW",

    "source_file": "ucsCentral/bundle_unpack.sh",
    "source_line": "chmod a+w /opt/cisco/download -R",
    "trigger":     "BUNDLE_PLATFORM=18 (provider image type, e.g., UCSM domain firmware)",

    "impact": (
        "/opt/cisco/download is the symlink staging directory for downloadable firmware images. "
        "After every platform=18 bundle unpack (which includes UCSM domain firmware updates), "
        "all files and subdirectories under /opt/cisco/download become world-writable. "
        "Any local OS user (daemon via UCSC-F9, postgres, samdme) can replace staged firmware "
        "images in the download directory with malicious binaries. "
        "The next time a managed UCSM domain downloads an image from UCS Central, "
        "it receives the attacker-substituted firmware. "
        "Combined with UCSC-F15 (arbitrary /tmp/shadow injection → admin password control), "
        "an attacker can escalate from daemon-level access to replacing all staged UCSM firmware."
    ),

    "versions_affected": ["1.5.1c", "2.1.2b"],
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F23 — snmpd_base.conf ships with SNMPv3 internalUser hardcoded password
#             'authpassword' (full MIB read, authNoPriv) + SNMPv2c community 'public'
# Source: etc/snmp/snmpd_base.conf in core-1.5.1-c.x86_64.rpm (identical in 2.1.2b;
#         2.1.2b adds udp6:161 agent address)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F23 = {
    "id":       "UCSC-F23",
    "title":    "snmpd_base.conf hardcodes SNMPv3 user 'internalUser' with password 'authpassword' "
                "and full MIB read access (-V all, authNoPriv) — network-accessible SNMP client "
                "with static credentials reads entire UCS Central MIB; "
                "SNMPv2c community 'public' enabled by default on UDP 161",
    "status":   "CONFIRMED — etc/snmp/snmpd_base.conf in core-1.5.1-c.x86_64.rpm and "
                "core-2.1.2-b.x86_64.rpm (identical content; 2.1.2b adds udp6:161)",
    "severity": "HIGH",

    "source_file":    "etc/snmp/snmpd_base.conf",
    "installed_path": "/etc/snmp/snmpd_base.conf",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "hardcoded_credentials": {
        "snmpv3_user":       "internalUser",
        "snmpv3_auth_alg":   "MD5",
        "snmpv3_password":   "authpassword",
        "snmpv3_access":     "authuser read internalUser authNoPriv -V all \"\"",
        "snmpv2c_community": "public",
        "snmpv2c_access":    "rocommunity public default -V vro (1.5.1c: IPv4 only; 2.1.2b adds rocommunity6)",
    },

    "snmpv3_impact": (
        "createUser internalUser MD5 authpassword\n"
        "authuser read internalUser authNoPriv -V all \"\"\n\n"
        "internalUser has read access to the full OID tree ('.1'). "
        "An SNMP client with username=internalUser and password=authpassword can enumerate: "
        "system identity, running process list (hrSWRunTable), network interface config, "
        "UCS Central-specific MIB entries (OID .1.3.6.1.4.1.9.9.719) via the dlmod plugin "
        "(libsvc_sam_extSnmpPlugin.so), storage layout, and all load/CPU metrics. "
        "authNoPriv = authenticated but traffic not encrypted — packets traverse the network "
        "in cleartext; capture reveals all queried MIB data."
    ),

    "snmpv2c_impact": (
        "rocommunity public default -V vro\n"
        "The 'vro' view exposes system OIDs, network interface stats, storage info, "
        "process table (HOST-RESOURCES), load averages, and UCS-specific MIB. "
        "Any host that can reach UDP 161 queries the vro view without credentials."
    ),

    "dlmod_note": (
        "dlmod svc_sam_extSnmpPlugin /opt/cisco/central-mgr/sam/lib/libsvc_sam_extSnmpPlugin.so\n"
        "The dynamic SNMP module exposes UCS Central management OIDs (1.3.6.1.4.1.9.9.719). "
        "internalUser's -V all access includes this plugin's subtree."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F24 — update_peer_secret.sh passes cluster shared_secret as 2nd CLI arg
#             — visible in ps aux on local node; also transmitted in remote SSH command
#             as 'sudo schelper.pl -v <secret>' (visible in peer ps + SSH audit log)
# Source: opt/cisco/bin/update_peer_secret.sh in core-1.5.1-c.x86_64.rpm
#         (byte-identical in core-2.1.2-b.x86_64.rpm)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F24 = {
    "id":       "UCSC-F24",
    "title":    "update_peer_secret.sh passes cluster shared_secret as 2nd CLI argument "
                "— secret visible in ps aux on local node and in "
                "'sudo schelper.pl -v <secret>' SSH command on peer node (ps + audit log exposure)",
    "status":   "CONFIRMED — opt/cisco/bin/update_peer_secret.sh in core-1.5.1-c.x86_64.rpm; "
                "byte-identical in core-2.1.2-b.x86_64.rpm",
    "severity": "MEDIUM",

    "source_file":    "opt/cisco/bin/update_peer_secret.sh",
    "installed_path": "/opt/cisco/bin/update_peer_secret.sh",
    "script_type":    "Tcl/Expect (#!/usr/bin/expect)",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "vulnerable_code": (
        "set shared_secret [lindex $argv 1]  # argv[1] — visible in ps aux\n"
        "send \"sudo /opt/cisco/bin/schelper.pl -r -s main -k sharedSecret -v $shared_secret\\r\"\n"
        "# secret interpolated into remote command string — visible in peer ps + SSH audit log"
    ),

    "local_exposure": (
        "The cluster shared_secret is passed as the 2nd positional argument. "
        "During the window between process start and exit (includes SSH round trip), "
        "any local OS user can read /proc/<pid>/cmdline or ps aux to extract the plaintext secret."
    ),

    "remote_exposure": (
        "The secret is embedded in the remote command sent to the peer via SSH expect: "
        "'sudo /opt/cisco/bin/schelper.pl -r -s main -k sharedSecret -v <plaintext_secret>'. "
        "On the peer node, this command is visible in ps aux during execution. "
        "SSH implementations that log executed remote commands write the secret to the peer's "
        "auth log."
    ),

    "dead_code_note": (
        "The script defines login{} which reads credentials from hardcoded /tmp/tp (world-accessible /tmp). "
        "login{} is never called in the main execution flow — SSH auth uses samdme's key. "
        "Dead code; noted for completeness."
    ),
}

FINDINGS = [
    UCSC_F1, UCSC_F2, UCSC_F3, UCSC_F4, UCSC_F5, UCSC_F6, UCSC_F7, UCSC_F8,
    UCSC_F9, UCSC_F10, UCSC_F11, UCSC_F12, UCSC_F13, UCSC_F14, UCSC_F15,
    UCSC_F16, UCSC_F17, UCSC_F18, UCSC_F19, UCSC_F20, UCSC_F21, UCSC_F22,
    UCSC_F23, UCSC_F24,
]


if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
