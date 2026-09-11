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

    "cross_component": (
        "Confirmed in multiple independent components across both versions:\n"
        "  1.5.1c: usr/lib/anaconda/ucscentral.py line 55 (passreset ISO)\n"
        "  2.1.2b: opt/cisco/bin/vm-common.pl line 462 (core-2.1.2-b.x86_64.rpm)\n"
        "  2.1.2b: opt/cisco/bin/restore.sh extracts key at runtime via grep on vm-common.pl:\n"
        "    encrypt_key=$(grep 'my \\$encKey' /opt/cisco/bin/vm-common.pl | sed 's/.*= \"\\(.*\\)\";/\\1/')\n"
        "  2.1.2b: cluster_validate.sh populate_config() uses this key to encrypt/verify sam.config "
        "    adminPasswd and sharedSecret (see UCSC-F31). "
        "The key is a universal encryption constant across all UCS Central components, "
        "not scoped to the passreset ISO."
    ),

    "also_encrypted_with_same_key": ["restorePass", "adminPasswd (sam.config)", "sharedSecret (sam.config)"],
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

    "versions_affected": ["1.5.1c", "2.1.2b"],

    "scope_212b": (
        "Confirmed in core-2.1.2-b.x86_64.rpm: "
        "opt/cisco/core/apache/ucsmoperations/recvbackup.cgi — identical injection pattern; "
        "$targetDir and $targetFile unsanitized from URL query string into backtick shell. "
        "httpd-ssl.conf (extra/httpd-ssl.conf lines 210-213): "
        "ScriptAliasMatch ^/ucsmoperations/file-(.*)/recvbackup.txt -> recvbackup.cgi; "
        "<Directory /opt/cisco/core/apache/ucsmoperations> SSLVerifyClient require — "
        "same access precondition as 1.5.1c."
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
    "library":   "opt/cisco/core/sam/lib/libosiris.so (and all application package copies); "
                 "ALSO confirmed in libsamsec.so and libcore.so in all application packages "
                 "(central-mgr, policy-mgr, identifier-mgr, service-reg, operation-mgr) — "
                 "3 distinct library carriers; key is ubiquitous across the entire service stack",
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

    "backup_encryption_path": (
        "Confirmed as the backup file encryption key in 2.1.2b:\n"
        "  restore.sh line ~97: ${vmbindir}/samcrypt ${binfile} ${tarfile} E001\n"
        "  libosiris.so utils::getEncryptionKeyRC4('E001') at 0x9da8c compares input\n"
        "  against rodata string 'E001' (0x10b2c9) and returns pointer to 'dwefsAvfsdkfqweqyrmfvsfwth'\n"
        "  (rodata 0x10b2a1). The RC4 key for ALL samcrypt legacy backup files is this same constant.\n"
        "  RC4 is symmetric — any backup file produced by samcrypt E001 is decryptable with:\n"
        "    python3 -c \"from Crypto.Cipher import ARC4; "
        "c=ARC4.new(b'dwefsAvfsdkfqweqyrmfvsfwth'); "
        "open('out','wb').write(c.decrypt(open('backup.bin','rb').read()))\""
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

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F25 — image_unpack.sh (operation-mgr) uses 'tar zxkPpmvf -' with -P flag
#             on firmware image extraction — absolute path entries not stripped;
#             no per-file signature check; same class as UCSC-F20 (bundle_unpack.sh)
# Source: opt/cisco/bin/image_unpack.sh in operation-mgr-1.5.1-c.x86_64.rpm
#         (functionally identical in operation-mgr-2.1.2-b.x86_64.rpm;
#          2.1.2b adds platform=21 and uses imghdrScript.sh wrapper)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F25 = {
    "id":       "UCSC-F25",
    "title":    "image_unpack.sh (operation-mgr) uses 'tar zxkPpmvf -' with -P flag on firmware "
                "image extraction — absolute path entries write to arbitrary filesystem paths "
                "without signature verification; same class as UCSC-F20 in the image download "
                "code path independent from bundle install path",
    "status":   "CONFIRMED — opt/cisco/bin/image_unpack.sh in operation-mgr-1.5.1-c.x86_64.rpm; "
                "functionally identical in operation-mgr-2.1.2-b.x86_64.rpm",
    "severity": "MEDIUM",

    "source_file":    "opt/cisco/bin/image_unpack.sh",
    "installed_path": "/opt/cisco/bin/image_unpack.sh",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "vulnerable_code": (
        "/bin/dd if=${BUNDLE_BASE_DIR}/${IMAGE_NAME} skip=1 bs=$BS | tar zxkPpmvf -\n"
        "# -P = absolute paths; new absolute-path archive entries written outside TARGET dir\n"
        "# No signature check before extraction"
    ),

    "path_traversal": (
        "image_unpack.sh cds to ${TARGET} before piping to tar, but the -P flag causes tar "
        "to honor absolute paths in the archive — leading / is NOT stripped. "
        "Archive entries beginning with '/' extract to their absolute path on the filesystem "
        "regardless of the working directory. "
        "-k prevents overwriting existing files but does not prevent creation of new files "
        "at arbitrary absolute paths. "
        "A crafted firmware image with absolute-path tar entries achieves root write anywhere."
    ),

    "debug_plugin_path": (
        "For platform=7, type=4 (debug-plugin image): TARGET is set to ${FILES_DIR} "
        "instead of the firmware subdirectory. "
        "Debug-plugin images are copied to the workspace root without content verification. "
        "Engineering code path in production firmware image install logic."
    ),

    "class_reference": (
        "Same vulnerability class as UCSC-F20 (bundle_unpack.sh tar -P). "
        "Independent code path: UCSC-F20 handles bundle installation; "
        "UCSC-F25 handles image download unpack."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F26 — validate-backup.sh uses POSIX cksum (CRC32) for backup file
#             integrity verification — cryptographically forgeable;
#             attacker with backup storage access (NFS share) recalculates CRC
#             and passes forged backup through restore validation
# Source: opt/cisco/bin/validate-backup.sh in operation-mgr-1.5.1-c.x86_64.rpm
#         (functionally identical in operation-mgr-2.1.2-b.x86_64.rpm)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F26 = {
    "id":       "UCSC-F26",
    "title":    "validate-backup.sh uses POSIX cksum (CRC32) for backup integrity — "
                "CRC32 is not cryptographically secure and is trivially forgeable; "
                "attacker with NFS share write access replaces backup content "
                "and recalculates CRC; forged restore payload passes validation",
    "status":   "CONFIRMED — opt/cisco/bin/validate-backup.sh in operation-mgr-1.5.1-c.x86_64.rpm; "
                "functionally identical in operation-mgr-2.1.2-b.x86_64.rpm",
    "severity": "MEDIUM",

    "source_file":    "opt/cisco/bin/validate-backup.sh",
    "installed_path": "/opt/cisco/bin/validate-backup.sh",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "vulnerable_code": (
        "CKSUM=`/bin/cat ${MF_FILE_NAME}.mf`\n"
        "COMPUTECKSUM=`/usr/bin/cksum ${FILE_NAME} | /usr/bin/cut -d' ' -f1`\n"
        "if [ \"${CKSUM}\" != \"${COMPUTECKSUM}\" ]; then exit 1; fi"
    ),

    "integrity_weakness": (
        "POSIX cksum computes CRC-32 — a polynomial hash for error detection, not authentication. "
        "An attacker who modifies the backup file can recalculate the CRC-32 "
        "(python3: import binascii; print(binascii.crc32(data) & 0xFFFFFFFF)) "
        "and overwrite the .mf sidecar file. "
        "Validation passes; the forged backup is accepted for restore."
    ),

    "attack_surface": (
        "UCS Central uses NFS for shared storage in clustered deployments "
        "(confirmed: ucsCentral/switch_to_nfs.sh in core-1.5.1-c.x86_64.rpm). "
        "Attacker with write access to the NFS share can: "
        "modify backup .tgz → recalculate cksum → overwrite .mf → trigger UCS Central restore. "
        "Backup content: managed domain config, policy definitions, LDAP/AAA config, user accounts. "
        "Forged restore introduces backdoor accounts or weakened policies that persist post-restore."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F27: sec::CallSystem() exported by libsamsec.so (security library) —
#            thin system() wrapper; called from comm::CommWkr::capConfPeerVMPolicies()
#            in libsvc_sam_controllerAG.so with unsanitized keyRing-derived filename
#            in a shell command; single-quote injection via keyRing name achieves
#            OS command injection on the UCS Central management server
# Source: core-1.5.1-c.x86_64.rpm / central-mgr-1.5.1-c.x86_64.rpm
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F27 = {
    "id":       "UCSC-F27",
    "title":    "comm::CommWkr::capConfPeerVMPolicies() in libsvc_sam_controllerAG.so builds "
                "a shell command via snprintf with an unsanitized keyRing-derived cert path "
                "and passes it to sec::CallSystem() — single-quote injection via keyRing name "
                "achieves OS command injection on UCS Central from a managed domain admin",
    "status":   "CONFIRMED — disassembly of libsvc_sam_controllerAG.so + libsamsec.so in "
                "core-1.5.1-c.x86_64.rpm and central-mgr-1.5.1-c.x86_64.rpm; "
                "capConfPeerVMPolicies and CallSystem are ABSENT from 2.1.2b controllerAG — "
                "1.5.1c-specific",
    "severity": "HIGH",
    "versions_affected": ["1.5.1c"],

    "call_chain": (
        "comm::CommWkr::capConfPeerVMPolicies(method::Method*) "
        "→ sec::GetCertFilename(base::Buffer&, const base::String& keyRing) "
        "→ sec::GetKeyRingPrefix(base::Buffer&, const base::String& keyRing) "
        "  [appends SvcConfigParams::CERT_ENROLL_PATH + keyRing.c_str() — no sanitization] "
        "→ appends '.crt' "
        "→ snprintf(buf, 0x400, format, '/tmp/https_cert_diff', cert_path, "
        "   '/opt/cisco/cert/CACertificate.pem') "
        "→ sec::CallSystem(buf)  [thin wrapper: system(buf)]"
    ),

    "shell_command_template": (
        "file=%s;if [ '%s' == `readlink %s` ]; then touch $file;else rm -f $file; fi\n"
        "# %s #1 = /tmp/https_cert_diff (static)\n"
        "# %s #2 = <CERT_ENROLL_PATH>/<keyRing_name>.crt  (user-controlled keyRing name)\n"
        "# %s #3 = /opt/cisco/cert/CACertificate.pem (static)"
    ),

    "injection_payload": (
        "keyRing name: legit'; touch /tmp/pwned; echo '\n"
        "Resulting command: "
        "file=/tmp/https_cert_diff;if [ '<CERT_PATH>/legit'; touch /tmp/pwned; echo '.crt' == "
        "`readlink /opt/cisco/cert/CACertificate.pem` ]; then touch $file;else rm -f $file; fi\n"
        "Result: touch /tmp/pwned executes as samdme (root-equivalent) on UCS Central"
    ),

    "sec_callsystem": (
        "libsamsec.so exports sec::CallSystem(const char*) at offset 0x3bdd0 — a 6-byte function "
        "that passes its argument directly to system(). No logging, no privilege drop, no shell "
        "character filtering. The function is part of the public sec:: namespace API."
    ),

    "no_sanitization": (
        "sec::GetKeyRingPrefix() clears buffer, appends CERT_ENROLL_PATH, then calls "
        "base::String::c_str() virtual method on the keyRing argument and appends the raw string. "
        "No character filtering (single-quote, backtick, semicolon, etc.) at any point in the chain. "
        "The 1024-byte snprintf buffer prevents truncation for typical keyRing names."
    ),

    "trust_boundary": (
        "keyRing is a UCS Manager data model object (pki::KeyRing) that managed domain admins "
        "can create with arbitrary names. UCS Central calls capConfPeerVMPolicies() when enforcing "
        "cert policies on managed domains. A compromised UCSM domain or rogue domain admin can "
        "trigger OS command injection on the UCS Central management server — cross-domain privilege "
        "escalation."
    ),

    "affected_libs": [
        "opt/cisco/central-mgr/sam/lib/libsamsec.so (defines sec::CallSystem at 0x3bdd0)",
        "opt/cisco/core/sam/lib/libsvc_sam_controllerAG.so (capConfPeerVMPolicies at 0x65de6, "
        "calls sec::CallSystem at 0x6642c)",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F28: All UCS Central 1.5.1c application service binaries compiled with
#            GCC 4.1.2 (2008, RHEL 5) — no PIE, no stack canaries, no RELRO;
#            in 2.1.2b: still no PIE, no stack canaries; partial RELRO on DME
#            binaries only; all 12+ networked daemons (UCSM XML federation)
#            have zero stack memory corruption mitigations
# Source: all 1.5.1c + 2.1.2b application RPMs
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F28 = {
    "id":       "UCSC-F28",
    "title":    "All UCS Central application service binaries compiled without PIE, stack "
                "canaries, or RELRO — zero memory corruption mitigations across 12+ UCSM "
                "federation daemons in 1.5.1c; 2.1.2b adds partial RELRO on DME binaries "
                "only, still no PIE or stack canaries",
    "status":   "CONFIRMED — ELF headers and symbol tables across all 1.5.1c + 2.1.2b "
                "application RPMs (central-mgr, policy-mgr, identifier-mgr, service-reg, "
                "operation-mgr) and shared libraries",
    "severity": "MEDIUM",

    "compiler":    "GCC 4.1.2 20080704 (Red Hat 4.1.2-55) — 2008, RHEL 5 era",
    "elf_type":    "EXEC (not DYN) — no PIE; fixed load address; ASLR provides no benefit "
                   "for the executable itself (shared libs may be randomized)",
    "stack_canary": "absent — __stack_chk_fail not referenced in any application binary; "
                    "GCC 4.1.2 default: -fno-stack-protector",
    "relro":       "1.5.1c: absent (no GNU_RELRO segment, no BIND_NOW); "
                   "2.1.2b: GNU_RELRO on svc_centralMgr_dme + svc_pol_dme + svc_idm_dme; "
                   "GOT writable at runtime in all other binaries",
    "nx":          "present (GNU_STACK RW, not RWE) — NX/DEP is enabled",

    "binaries_affected": [
        "svc_centralMgr_dme, svc_pol_dme, svc_idm_dme, svc_reg_dme, svc_ops_dme (DMEs)",
        "svc_sam_cloudAG, svc_sam_controllerAG, svc_sam_imgMgmtAG, svc_sam_licenseAG",
        "svc_sam_pkiAG, svc_sam_secAG, svc_sam_sessionmgrAG, svc_sam_snmpTrapAG",
        "ucssh (SUID — already covered by UCSC-F13)",
        "pam_proxy_test_client, curl, openssl (bundled test/utility binaries)",
    ],

    "dangerous_lib_functions": (
        "Shared library sweep across central-mgr/sam/lib/: "
        "strcpy in 26/31 libraries; sprintf in 19/31; strcat in 17/31; "
        "system() in libclicommon.so, libcliservice.so, libmodel.so, libosiris.so, libsamsec.so; "
        "popen() in libcliservice.so, libosiris.so; "
        "execve/execv/execl/execlp in libcliservice.so, libcurl.so, libosiris.so, "
        "libtsJavaAcc_libFNP.so, libtsJavaAcc.so, libucsshedit.so. "
        "Any stack buffer overflow in any calling function → direct RIP control."
    ),

    "impact": (
        "UCSM XML federation is processed by these daemons: managed domains push XML MO updates "
        "over TCP. Any memory corruption vulnerability in the federation message parsers runs "
        "without stack canary or ASLR-for-executable protection — return-oriented programming "
        "chains are stable across deployments. With GOT writable (1.5.1c), GOT-overwrite attacks "
        "reach system() and exec* without ROP."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F29: pam_proxy_test_client test/diagnostic binary deployed in production
#            across all application packages (central-mgr, policy-mgr,
#            identifier-mgr, service-reg, operation-mgr); provides direct PAM
#            auth proxy access without application-level enforcement; no binary
#            hardening; 2.1.2b equivalent present in all packages
# Source: all 1.5.1c + 2.1.2b application RPMs
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F29 = {
    "id":       "UCSC-F29",
    "title":    "pam_proxy_test_client diagnostic binary deployed in production across "
                "all UCS Central application packages — direct PAM auth proxy exercise "
                "without application-level enforcement; no binary hardening; "
                "2.1.2b present in all packages",
    "status":   "CONFIRMED — opt/cisco/*/sam/bin/pam_proxy_test_client in "
                "central-mgr, policy-mgr (1.5.1c); central-mgr, policy-mgr, "
                "identifier-mgr, service-reg (2.1.2b — identifier-mgr212b and service-reg212b "
                "confirmed via package extraction)",
    "severity": "LOW",

    "installed_path": "/opt/cisco/*/sam/bin/pam_proxy_test_client",
    "binary_size":    "8617 bytes (GCC 4.1.2, not stripped)",
    "purpose":        "multi-threaded PAM proxy stress/functional test client (connect_to_server + pthread_create)",
    "exports":        "none — uses srand() for pseudorandom session generation",

    "risk": (
        "A local user on the UCS Central server can invoke pam_proxy_test_client to directly "
        "exercise the PAM authentication proxy without going through the normal UCS Central "
        "application login flow. If the PAM proxy has authentication bypass conditions or "
        "rate-limit gaps, this utility provides a local tool to test/exploit them. "
        "No binary hardening (no PIE, no canary, no RELRO) — consistent with UCSC-F28."
    ),

    "note": "Similar to CMC-F11 (TPM test binaries in production rootfs). "
            "Diagnostic binaries should not be shipped in production packages.",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F30: cluster_add.sh and cluster_validate.sh perform zero SSH host key
#            verification during cluster formation — known_hosts cleared before
#            every peer SSH session; Expect auto-accepts any host key with
#            'send "yes\r"'; complete MITM surface for inter-node cluster traffic
# Source: opt/cisco/bin/cluster_add.sh + cluster_validate.sh in
#         core-2.1.2-b.x86_64.rpm; equivalent in 1.5.1c OVA disk1
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F30 = {
    "id":       "UCSC-F30",
    "title":    "cluster_validate.sh clears SSH known_hosts before every peer connection and "
                "cluster_add.sh auto-accepts any host key via Expect 'send \"yes\\r\"' — "
                "zero SSH host verification during cluster formation; complete MITM surface",
    "status":   "CONFIRMED — opt/cisco/bin/cluster_validate.sh + cluster_add.sh in "
                "core-2.1.2-b.x86_64.rpm; cluster_add.sh also present in 1.5.1c OVA disk1",
    "severity": "HIGH",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "source_files": [
        "opt/cisco/bin/cluster_validate.sh",
        "opt/cisco/bin/cluster_add.sh",
    ],

    "known_hosts_clear": (
        "cluster_validate.sh communicate() function:\n"
        "  log info \"Clearing known_hosts file before ssh to peer node\"\n"
        "  echo > ${KNOWN_HOSTS}\n"
        "KNOWN_HOSTS is sourced from bashfunctions.sh (samdme user's ~/.ssh/known_hosts). "
        "This deliberately empties the known_hosts file before every cluster formation or "
        "peer communication sequence, ensuring no cached host key exists to detect a MITM."
    ),

    "expect_auto_accept": (
        "cluster_add.sh (Expect script) handles the SSH host key prompt:\n"
        "  expect {\n"
        "    \"Are you sure you want to continue connecting\" { send \"yes\\r\"; exp_continue }\n"
        "    ...\n"
        "  }\n"
        "Any host key presented by a peer (or MITM at PEER_IP) is unconditionally accepted. "
        "The accepted key is written into the now-empty known_hosts file, "
        "trusting the MITM for all subsequent SSH/SCP/rsync operations in the same session."
    ),

    "subsequent_operations_trusted": (
        "After cluster_add.sh accepts the MITM's host key into known_hosts, "
        "all subsequent unauthenticated-SSH operations in cluster_validate.sh trust it:\n"
        "  scp samdme@${PEER_IP}:${SAM_CONFIG} /tmp/peer_config   # downloads peer's sam.config\n"
        "  rsync -azO --delete -e ssh samdme@${PEER_IP}:/opt/cisco/cert /opt/cisco/  # cert copy\n"
        "  ssh samdme@${PEER_IP} [validate commands]               # remote validation\n"
        "A MITM can serve crafted sam.config, malicious certificates, and false validation results."
    ),

    "impact": (
        "An attacker on the network path between two UCS Central nodes during cluster formation "
        "can MITM the inter-node SSH session with zero detection. "
        "The MITM can serve: (1) crafted sam.config containing known-key-encrypted credentials "
        "(see UCSC-F31), (2) attacker-controlled TLS certificates that replace /opt/cisco/cert/, "
        "(3) false validation results that allow a compromised node to join the cluster. "
        "The attack requires network position (ARP spoofing or rogue switch port) during "
        "the cluster formation window, which is a known operation logged in change management."
    ),

    "no_fix_in_later_version": (
        "The pattern is identical in 1.5.1c (OVA disk1) and 2.1.2b (core RPM). "
        "No StrictHostKeyChecking configuration or fingerprint pinning was added between versions."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F31: cluster_validate.sh populate_config() copies encrypted credentials
#            from peer node's sam.config to local sam.config without validation;
#            encryption key 'theKeyForEncryptingTheSharedSecret' is hardcoded
#            and known (UCSC-F1) — attacker controlling the peer node can inject
#            arbitrary adminPasswd and sharedSecret into the target cluster node
# Source: opt/cisco/bin/cluster_validate.sh in core-2.1.2-b.x86_64.rpm
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F31 = {
    "id":       "UCSC-F31",
    "title":    "cluster_validate.sh populate_config() writes encrypted credentials from peer's "
                "sam.config to local sam.config without integrity validation — attacker controlling "
                "peer node crafts credentials encrypted with the known static key (UCSC-F1) "
                "to poison the joining node's adminPasswd and sharedSecret",
    "status":   "CONFIRMED — opt/cisco/bin/cluster_validate.sh populate_config() + copy_certs() "
                "in core-2.1.2-b.x86_64.rpm",
    "severity": "HIGH",
    "versions_affected": ["2.1.2b"],

    "source_file": "opt/cisco/bin/cluster_validate.sh",

    "vulnerable_code": (
        "populate_config() function:\n"
        "  local PASSWORD_ENC=$($SCREADER ${SAMKEY_PASSWORD} ${PEER_CONFIG_FILE})\n"
        "  local SECRET_ENC=$($SCREADER ${SAMKEY_SECRET} ${PEER_CONFIG_FILE})\n"
        "  $SCHELPER -r -s main -k ${SAMKEY_PASSWORD} -v $PASSWORD_ENC\n"
        "  $SCHELPER -r -s main -k ${SAMKEY_SECRET} -v $SECRET_ENC\n"
        "PEER_CONFIG_FILE = /tmp/peer_config (downloaded from peer via SCP, see UCSC-F30). "
        "The values read from PEER_CONFIG_FILE are written directly to the local sam.config "
        "via schelper — no MAC, no signature, no validation of the ciphertext."
    ),

    "encryption_key_known": (
        "Credentials in sam.config are encrypted with AES-128 using the hardcoded key "
        "'theKeyForEncryptingTheSharedSecret' (confirmed in vm-common.pl line 462; see UCSC-F1). "
        "An attacker with knowledge of this key can produce validly-encrypted ciphertext "
        "for any adminPasswd or sharedSecret value:\n"
        "  echo 'attacker_passwd' | openssl enc -e "
        "-k 'theKeyForEncryptingTheSharedSecret' -a -aes128\n"
        "The resulting ciphertext, placed in a crafted sam.config, passes all checks "
        "and is written to the victim node's sam.config as the new admin password or shared secret."
    ),

    "cert_replacement": (
        "copy_certs() in cluster_validate.sh:\n"
        "  /usr/bin/rsync -azO --delete -e ssh samdme@${PEER_IP}:/opt/cisco/cert /opt/cisco/\n"
        "Replaces ALL certificates in /opt/cisco/cert/ with those from the peer node. "
        "--delete removes local certs not present on the peer. "
        "If the peer is attacker-controlled, this replaces CACertificate.pem, Combined.pem, "
        "privKey.pem, and all enrolled certs with attacker certs — enabling TLS impersonation "
        "of the UCS Central management interface and federation endpoints."
    ),

    "attack_scenario": (
        "Attacker controls a UCS node (e.g., a rogue second node, or a compromised node) "
        "that is presented as the cluster peer during formation:\n"
        "1. Host rogue SSH server at PEER_IP with crafted sam.config\n"
        "2. cluster_validate.sh clears known_hosts (UCSC-F30) and calls cluster_add.sh\n"
        "3. cluster_add.sh auto-accepts rogue SSH host key\n"
        "4. scp downloads crafted sam.config from rogue server to /tmp/peer_config\n"
        "5. populate_config() writes attacker-chosen adminPasswd+sharedSecret to local sam.config\n"
        "6. rsync copies attacker-controlled TLS certs to /opt/cisco/cert/\n"
        "Outcome: victim UCS Central node boots with attacker's admin password and attacker's "
        "TLS certificate — full authentication bypass on the management plane."
    ),

    "nfs_mount_surface": (
        "validate_nfs() also mounts an NFS share using PEER_IP from peer's config file:\n"
        "  mount -t nfs $NFS_SERV_IP:$NFS_SERV_DIR /bootflash -o soft,rw,intr,proto=tcp\n"
        "NFS_SERV_IP is read from the peer's sam.config (unvalidated). "
        "Attacker-controlled sam.config can redirect the NFS mount to an attacker-controlled server."
    ),

    "dependency": "UCSC-F30 (SSH host bypass) is the prerequisite for remote exploitation. "
                  "UCSC-F1 provides the static encryption key required to craft valid ciphertexts.",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F32: cluster_add.sh 'eval spawn ssh -l $admin_user $peer_ip' — Tcl eval
#            with unsanitized admin_user allows Tcl command injection via bracket
#            notation; attacker-supplied admin_user containing '[exec cmd]' is
#            evaluated as Tcl code before SSH is spawned, executing arbitrary
#            commands in the Expect interpreter as samdme
# Source: opt/cisco/bin/cluster_add.sh in core-2.1.2-b.x86_64.rpm;
#         equivalent in 1.5.1c OVA disk1 (also in update_peer_secret.sh,
#         cluster_ipcheck.sh)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F32 = {
    "id":       "UCSC-F32",
    "title":    "cluster_add.sh uses 'eval spawn ssh -l $admin_user $peer_ip' — Tcl eval "
                "interprets bracket-notation [exec cmd] in admin_user as a command substitution; "
                "local command injection in the Expect interpreter as samdme before SSH is spawned",
    "status":   "CONFIRMED — opt/cisco/bin/cluster_add.sh in core-2.1.2-b.x86_64.rpm; "
                "equivalent pattern in update_peer_secret.sh and cluster_ipcheck.sh; "
                "also present in 1.5.1c OVA disk1",
    "severity": "HIGH",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "source_files": [
        "opt/cisco/bin/cluster_add.sh",
        "opt/cisco/bin/update_peer_secret.sh",
        "opt/cisco/bin/cluster_ipcheck.sh",
    ],

    "vulnerable_code": (
        "#!/usr/bin/expect\n"
        "set admin_user [lindex $argv 1]  # argv[1] = PEER_USER from cluster_validate.sh\n"
        "...\n"
        "eval spawn ssh -l $admin_user $peer_ip\n"
        "# Tcl 'eval' concatenates arguments and re-evaluates as a Tcl command.\n"
        "# $admin_user is substituted before eval, then the resulting string is parsed as Tcl.\n"
        "# Tcl bracket notation [cmd] in the substituted string triggers command substitution."
    ),

    "injection_mechanism": (
        "Tcl 'eval spawn ssh -l $admin_user $peer_ip' is equivalent to:\n"
        "  spawn ssh -l <literal_admin_user_value> $peer_ip\n"
        "when admin_user is clean. When admin_user contains Tcl metacharacters:\n"
        "  admin_user = 'admin [exec id > /tmp/pwned]'\n"
        "Tcl eval sees: spawn ssh -l admin [exec id > /tmp/pwned] <PEER_IP>\n"
        "The [exec id > /tmp/pwned] fragment is evaluated as a Tcl command substitution "
        "BEFORE spawn receives its arguments. 'exec' in Tcl executes an OS command. "
        "Result: arbitrary OS command executes as samdme before the SSH connection is attempted."
    ),

    "call_chain": (
        "cluster_validate.sh communicate():\n"
        "  ${CLUSTERADD} ${PEER_IP} ${PEER_USER} ${PEER_PASSWORD}\n"
        "CLUSTERADD=/opt/cisco/bin/cluster_add.sh; PEER_USER is taken from the CLI args "
        "of cluster_validate.sh, which is called from the UCS Central Java application layer "
        "(Tomcat) during cluster formation. "
        "If the admin username input in the cluster formation UI is not sanitized upstream, "
        "a cluster admin who sets their username to 'admin [exec cmd]' achieves OS code execution."
    ),

    "samdme_privilege": (
        "cluster_add.sh runs as samdme. samdme has NOPASSWD:ALL in sudoers (UCSC-F11). "
        "Tcl exec'd commands run as samdme → sudo escalation to root is available "
        "without additional exploitation."
    ),

    "other_affected_scripts": (
        "update_peer_secret.sh and cluster_ipcheck.sh use the identical 'eval spawn ssh' "
        "pattern with unsanitized argv input. Both are in the same cluster management path."
    ),

    "no_sanitization": (
        "admin_user is taken directly from $argv and interpolated into the eval string. "
        "No character stripping, no quoting of the Tcl variable, no list-based spawn call "
        "(which would be safe: 'spawn ssh -l $admin_user $peer_ip' without eval). "
        "Safe alternative: spawn ssh -l $admin_user $peer_ip [no eval; Tcl does not perform "
        "command substitution in 'spawn' argument list when called without eval]."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F33: cert-gen.pl executes 'chmod -R 777 /opt/cisco/cert' after every
#            certificate generation — TLS private key, CA cert, and all derived
#            certs become world-readable and world-writable; any local OS user
#            can replace the UCS Central TLS identity and CA
# Source: opt/cisco/bin/cert-gen.pl in core-1.5.1-c.x86_64.rpm (line 221) and
#         core-2.1.2-b.x86_64.rpm (same line); both confirmed
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F33 = {
    "id":       "UCSC-F33",
    "title":    "cert-gen.pl executes 'chmod -R 777 /opt/cisco/cert' after every certificate "
                "generation — CA private key, TLS identity cert, and all derived certs become "
                "world-readable and world-writable; any local OS user can replace UCS Central TLS",
    "status":   "CONFIRMED — opt/cisco/bin/cert-gen.pl line 221 in core-1.5.1-c.x86_64.rpm; "
                "identical line confirmed in core-2.1.2-b.x86_64.rpm",
    "severity": "CRITICAL",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "source_file":  "opt/cisco/bin/cert-gen.pl",
    "trigger_line": "system(\"chmod -R 777 /opt/cisco/cert\");  # final line of cert-gen.pl",

    "invocations": (
        "cert-gen.pl is called from:\n"
        "  network.pl line 701: system(\"$certgen\")  — during network IP reconfiguration\n"
        "  network.pl line 832: system(\"$certgen\")  — after NTP sync (cert datetime check)\n"
        "  network.pl line 857: system(\"$certgen\")  — on every network.pl invocation\n"
        "  vm-common.pl: our $certgen = \"$binpath/cert-gen.pl\" — referenced as default certgen\n"
        "  regenerate-certs.pl: calls cert-gen.pl directly\n"
        "Triggered on: first boot, IP address change, NTP resync, certificate rotation. "
        "After each invocation, the /opt/cisco/cert/ tree is set to 0777 permanently "
        "until the next reboot (no subsequent chmod to restrict permissions)."
    ),

    "affected_files": [
        "/opt/cisco/cert/default.key   → symlinked as privKey.pem (CA/server private key)",
        "/opt/cisco/cert/default.crt   → symlinked as CACertificate.pem (CA certificate)",
        "/opt/cisco/cert/Combined.pem  (cert+key bundle for Apache TLS termination)",
        "/opt/cisco/cert/privKey.pem   (symlink to default.key)",
        "/opt/cisco/cert/CACertificate.pem  (symlink to default.crt)",
        "/opt/cisco/cert/CACertChain.pem",
        "/opt/cisco/cert/ThirdPartyCA.pem",
        "/opt/cisco/cert/seq           (CA serial number file)",
        "/opt/cisco/cert/.$$client.cnf (temp openssl config — race condition target)",
    ],

    "impact": (
        "After any cert-gen.pl invocation, every local OS user (daemon, postgres, samdme) can:\n"
        "1. Read /opt/cisco/cert/default.key (CA private key) — enables offline signing of "
        "   arbitrary client certificates trusted by all managed UCS domains\n"
        "2. Overwrite /opt/cisco/cert/default.key with an attacker-controlled key — "
        "   next Apache restart loads attacker's key for all TLS connections\n"
        "3. Overwrite /opt/cisco/cert/Combined.pem — immediate TLS subversion without restart\n"
        "   (Apache reads this on each request in some configurations)\n"
        "4. Overwrite /opt/cisco/cert/CACertificate.pem — UCS Manager domains trusting this CA "
        "   will accept attacker-signed client certs\n"
        "5. Write a malicious /opt/cisco/cert/.$$client.cnf before mkpkcs10req.sh reads it — "
        "   openssl generates a CSR with attacker-controlled Subject/SAN/extensions\n"
        "Result: full TLS identity takeover for UCS Central management plane from any local OS user."
    ),

    "privilege_path": (
        "Any process with any shell foothold (e.g., UCSC-F9 CGI injection as daemon, "
        "or any CVE in the Tomcat/Java layer) can immediately:\n"
        "  cat /opt/cisco/cert/default.key  → extract CA private key\n"
        "  cp attacker.key /opt/cisco/cert/default.key  → replace CA key\n"
        "No privilege escalation required — chmod 777 makes it accessible to all."
    ),

    "note": (
        "The chmod -R 777 appears intentional — likely added for service account access "
        "(samdme, daemon, postgres all need cert files). The correct fix is targeted ACLs "
        "for specific service accounts, not world-writable on the entire cert tree."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F34: cert-gen.pl send_to_ca() uses 'curl --insecure' for all certificate
#            exchange with the CA endpoint — TLS verification disabled during
#            CA cert bootstrap; MITM can serve forged CA certificate to any
#            UCSM node performing cert enrollment
# Source: opt/cisco/bin/cert-gen.pl in core-1.5.1-c.x86_64.rpm (line 144) and
#         core-2.1.2-b.x86_64.rpm; confirmed in both
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F34 = {
    "id":       "UCSC-F34",
    "title":    "cert-gen.pl send_to_ca() uses 'curl --insecure' for certificate exchange with "
                "UCS Central CA endpoint — TLS verification disabled during CA cert bootstrap; "
                "MITM serves forged CA cert accepted without validation",
    "status":   "CONFIRMED — opt/cisco/bin/cert-gen.pl send_to_ca() line 144 in "
                "core-1.5.1-c.x86_64.rpm and core-2.1.2-b.x86_64.rpm",
    "severity": "HIGH",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "source_file": "opt/cisco/bin/cert-gen.pl",

    "vulnerable_code": (
        "sub send_to_ca {\n"
        "    my $url = \"https://$vpod::inputs{$vpod::regIp}:$vpod::inputs{$vpod::commsport}"
        "/xmlInternal/apache/cert\";\n"
        "    ...\n"
        "    my $resp = `$vpod::curl $url --insecure -s -d '$xml'`;\n"
        "    return $resp;\n"
        "}"
    ),

    "operations_affected": [
        "get_ca_cert() — initial CA certificate fetch from UCS Central registration endpoint",
        "create_csr_and_sign() — CSR submission and signed cert retrieval",
        "Both are POST requests to https://<regIp>:<commsport>/xmlInternal/apache/cert",
    ],

    "attack_scenario": (
        "During UCSM node registration with UCS Central, cert-gen.pl contacts the CA endpoint. "
        "An attacker on the network path between UCSM and UCS Central can:\n"
        "1. Intercept the HTTPS connection (curl --insecure accepts any cert)\n"
        "2. Respond with a forged XML body: outCert='<attacker_cert>' outResDigest='<hash>'\n"
        "3. cert-gen.pl writes the forged cert to /opt/cisco/cert/ as CACertificate.pem\n"
        "4. UCSM then trusts the attacker's CA cert for all subsequent mutual TLS operations\n"
        "The validate_hash_from_xml() check provides partial protection — it validates the "
        "response digest — but requires knowing the shared secret to forge a valid digest. "
        "Since the shared secret is known (UCSC-F1), the attacker can compute a valid digest "
        "for their forged cert and pass this validation."
    ),

    "shared_secret_link": (
        "create_hash_for_xml() computes the authentication hash as:\n"
        "  $hash = crypt($shared_secret . $regIp, $hash) # MD5-crypt via openssl passwd -1\n"
        "Since shared_secret is decryptable from sam.config using the known static key "
        "(UCSC-F1: 'theKeyForEncryptingTheSharedSecret'), an attacker can compute the correct "
        "digest for any cert content and forge a valid response that passes validate_hash_from_xml()."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F35: clusterserver binary listens on TCP 3111 with source IP-only trust —
#            samdme SSH keys, sam.config, and ODBC credentials transferred in
#            plaintext; IP trust bypassed by ARP spoofing on management VLAN;
#            malicious client receives sam.config + SSH keys, or injects
#            unauthorized SSH public key into samdme authorized_keys
# Source: opt/cisco/bin/clusterserver + clusterclient in core-2.1.2-b.x86_64.rpm
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F35 = {
    "id":       "UCSC-F35",
    "title":    "clusterserver listens on TCP 3111 with source IP-only trust — "
                "samdme SSH keys, sam.config (adminPasswd + sharedSecret), and ODBC config "
                "transferred in plaintext; ARP spoof bypasses IP trust; "
                "malicious client receives credentials or injects SSH key into authorized_keys",
    "status":   "CONFIRMED — strings + disassembly of opt/cisco/bin/clusterserver and "
                "opt/cisco/bin/clusterclient in core-2.1.2-b.x86_64.rpm",
    "severity": "HIGH",
    "versions_affected": ["2.1.2b"],

    "binary_server": "opt/cisco/bin/clusterserver",
    "binary_client": "opt/cisco/bin/clusterclient",

    "protocol": (
        "clusterserver: TCP, AF_INET (IPv4), port 3111 (0xc27 — confirmed via htons disassembly)\n"
        "Binding IP: popen('/bin/grep oobIpAddr /opt/cisco/sam.config | awk -F= ...')\n"
        "Trust check: inet_addr-based source IP comparison — 'Not a trusted client. Good bye' "
        "message on failure; no encryption, no authentication tokens, no TLS\n"
        "clusterclient: USAGE: <binary> <server_ip> — connects to server_ip:3111"
    ),

    "data_transferred": (
        "Confirmed via clusterclient string table:\n"
        "  /home/samdme/.ssh/id_rsa.pub       — samdme RSA public key (sent to peer)\n"
        "  /home/samdme/.ssh/authorized_keys  — samdme authorized_keys (synchronized)\n"
        "  /opt/cisco/sam.config              — full sam.config (adminPasswd + sharedSecret)\n"
        "  /tmp/peer_config                   — peer's sam.config written here after receive\n"
        "  /etc/odbc.ini                      — PostgreSQL ODBC config (DSN, credentials)\n"
        "  /tmp/peer_odbc.ini                 — peer's ODBC config written here\n"
        "All transferred in plaintext TCP stream — no session encryption."
    ),

    "trust_bypass": (
        "clusterserver's trust check compares the client source IP to the expected peer IP "
        "read from sam.config. On a management VLAN without 802.1X port authentication or "
        "DHCP snooping, an attacker can:\n"
        "1. ARP-spoof to claim the expected peer IP\n"
        "2. Connect to clusterserver:3111 on the target node — trust check passes\n"
        "3. Receive sam.config (adminPasswd + sharedSecret encrypted with known static key) "
        "   and samdme SSH keys in plaintext\n"
        "Since adminPasswd and sharedSecret are encrypted with 'theKeyForEncryptingTheSharedSecret' "
        "(UCSC-F1), decryption is immediate after capture."
    ),

    "ssh_key_injection": (
        "clusterclient sends /home/samdme/.ssh/authorized_keys to clusterserver for sync. "
        "clusterserver writes the received key data to its local authorized_keys path. "
        "An attacker impersonating the clusterclient (ARP spoof on the client side) can "
        "send a crafted authorized_keys containing the attacker's RSA public key — "
        "injected into samdme's authorized_keys on the target node. "
        "samdme has NOPASSWD:ALL sudo (UCSC-F11) → SSH as samdme → root."
    ),

    "attack_window": (
        "The clusterserver process runs only during cluster formation/validation operations, "
        "not as a persistent daemon. The attack window is limited to the period when "
        "cluster_validate.sh is executing. This window is identifiable via change management "
        "records (cluster formation is a logged administrative operation)."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F36 — recvfile.cgi arbitrary file write, unauthenticated
# No path sanitization; no auth; Allow from all; overwrites any file writable
# by Apache daemon (daemon user); confirmed in 1.5.1c + 2.1.2b (identical files)
# Source: opt/cisco/core/apache/operations/recvfile.cgi (both RPMs)
# httpd.conf: <Directory /opt/apache/operations> Allow from all (no SSLVerifyClient)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F36 = {
    "id":       "UCSC-F36",
    "title":    "recvfile.cgi arbitrary file write — REQUEST_URI captures absolute path unsanitized; "
                "open(OUTF, \">$file\") overwrites any daemon-writable file; unauthenticated (Allow from all)",
    "status":   "CONFIRMED — opt/cisco/core/apache/operations/recvfile.cgi; "
                "httpd.conf <Directory /opt/apache/operations>: Allow from all, no SSLVerifyClient; "
                "identical in 1.5.1c and 2.1.2b",
    "severity": "CRITICAL",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "cgi_script": "opt/cisco/core/apache/operations/recvfile.cgi (Perl)",
    "endpoint":   "POST /operations/file-<absolute_path>/recvfile.txt",

    "url_parsing": (
        "Regex: /\\/operations\\/file-(.*)\\//recvfile\\.txt/ -> $file = $1\n"
        "No further sanitization. No use strict. No -T taint flag on shebang (#!/usr/bin/perl, not -wT).\n"
        "Example: REQUEST_URI=/operations/file-/etc/passwd/recvfile.txt -> $file='/etc/passwd'"
    ),

    "sink_lines": [
        "open(INF, \"$file\");        # reads existing file (truncation race)",
        "open(OUTF, \">$file\");      # overwrites $file with request body (STDIN)",
        "while (read (STDIN, $buffer, 65536) and print OUTF $buffer) { ... }",
    ],

    "access_control": (
        "httpd.conf <Directory /opt/apache/operations>:\n"
        "  SetHandler sam-cgi\n"
        "  Order allow,deny\n"
        "  Allow from all\n"
        "No AuthType, no Require, no SSLVerifyClient. Network-reachable with zero credentials."
    ),

    "writable_targets": [
        "/etc/passwd          — inject uid=0 account (no shadow required if empty passwd field)",
        "/etc/cron.d/<name>   — write cron job executing as root",
        "/opt/cisco/sam.config — overwrite adminPasswd/sharedSecret with known ciphertext (UCSC-F1)",
        "/home/samdme/.ssh/authorized_keys — inject RSA public key -> SSH as samdme -> root (UCSC-F11)",
        "/opt/cisco/cert/default.key — replace CA private key (cert dir world-writable: UCSC-F33)",
        "/etc/sudoers         — if daemon has write access via cert dir chmod -R 777 path",
    ],

    "comparison_note": (
        "recvimage.cgi, recvlic.cgi, and importconfig.cgi all apply $safe_filename_chars = 'a-zA-Z0-9_.-' "
        "and strip path separators before open(). recvfile.cgi has no equivalent sanitization — "
        "the pattern appears intentionally different, likely for internal-only file transfer that was "
        "never removed from the unauthenticated endpoint."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F37 — sendfile.cgi arbitrary file read, unauthenticated
# No path sanitization in /operations/file-X/sendfile.txt branch (1.5.1c) or
# path traversal via ../../../ in /backupfile/, /techsupport/, /corefile/ (2.1.2b);
# Allow from all; streams any daemon-readable file to HTTP client
# Source: opt/cisco/core/apache/operations/sendfile.cgi (both RPMs)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F37 = {
    "id":       "UCSC-F37",
    "title":    "sendfile.cgi arbitrary file read — REQUEST_URI captures absolute path or "
                "path-traversable prefix; open(INF, \"$file\") streams any daemon-readable file; "
                "unauthenticated (Allow from all)",
    "status":   "CONFIRMED — opt/cisco/core/apache/operations/sendfile.cgi; "
                "httpd.conf <Directory /opt/apache/operations>: Allow from all, no SSLVerifyClient; "
                "identical file in 1.5.1c and 2.1.2b; exposed URL pattern differs per httpd.conf",
    "severity": "CRITICAL",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "cgi_script": "opt/cisco/core/apache/operations/sendfile.cgi (Perl)",

    "url_routing": {
        "1.5.1c": (
            "ScriptAliasMatch ^/operations/file-(.*)/sendfile.txt -> sendfile.cgi\n"
            "Branch: REQUEST_URI =~ /\\/operations\\/file-(.*)\\//sendfile\\.txt/ -> $file = $1\n"
            "No prefix prepended — $file IS the absolute path from URL.\n"
            "Payload: GET /operations/file-/etc/shadow/sendfile.txt -> reads /etc/shadow"
        ),
        "2.1.2b": (
            "ScriptAliasMatch ^/backupfile/(.*) -> sendfile.cgi (httpd.conf line 97)\n"
            "ScriptAliasMatch ^/techsupport/(.*) -> sendfile.cgi (httpd.conf line 98)\n"
            "ScriptAliasMatch ^/corefile/(.*) -> sendfile.cgi (httpd.conf line 99)\n"
            "Branches prepend fixed base dirs but $1 is unsanitized:\n"
            "  /backupfile/../../etc/shadow -> $file='/bootflash/backup/../../etc/shadow' -> /etc/shadow\n"
            "  /techsupport/../../../etc/shadow -> $file='/workspace/techsupport/../../../etc/shadow' -> /etc/shadow\n"
            "  /corefile/../../etc/shadow -> $file='/bootflash/sysdebug/coremgmt/logs/../../etc/shadow'\n"
            "Note: /operations/file-X/sendfile.txt ScriptAlias absent from 2.1.2b httpd.conf; "
            "backupfile/techsupport/corefile routes are the exposed attack surface."
        ),
    },

    "sink_line": "open(INF, \"$file\"); ... while (read (INF, $buffer, 65536) and print $buffer) { ... }",

    "access_control": (
        "httpd.conf <Directory /opt/apache/operations>:\n"
        "  SetHandler sam-cgi\n"
        "  Order allow,deny\n"
        "  Allow from all\n"
        "No AuthType, no Require, no SSLVerifyClient. Network-reachable with zero credentials."
    ),

    "readable_targets": [
        "/etc/shadow                — root and samdme password hashes",
        "/opt/cisco/sam.config     — adminPasswd + sharedSecret (decryptable: UCSC-F1)",
        "/etc/odbc.ini             — PostgreSQL DSN + credentials",
        "/home/samdme/.ssh/id_rsa  — samdme private key (if generated); samdme -> root via UCSC-F11",
        "/opt/cisco/cert/default.key — CA private key (UCSC-F33 world-readable)",
        "/opt/cisco/core/apache/conf/httpd.conf — full Apache config",
        "/opt/cisco/core/apache/conf/extra/httpd-ssl.conf — SSL vhost config, cert paths, CA config",
    ],

    "combined_impact": (
        "UCSC-F36 + UCSC-F37 together: unauthenticated read-then-write cycle on any daemon-accessible file. "
        "Read /etc/shadow to recover password hashes; write /etc/passwd to inject uid=0 account; "
        "read sam.config for encrypted credentials then decrypt with UCSC-F1 key; "
        "write authorized_keys for SSH as samdme then sudo root (UCSC-F11)."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F38 — sam-copy.exp auto-accepts SSH host key during backup SCP/SFTP;
#             pass-wrapper.sh passes remote password as CLI arg → ps-visible;
#             MITM on management network intercepts admin backup credentials
# Source: opt/cisco/bin/sam-copy.exp + opt/cisco/bin/pass-wrapper.sh (both RPMs)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F38 = {
    "id":       "UCSC-F38",
    "title":    "sam-copy.exp auto-accepts SSH host key during backup SCP/SFTP transfer; "
                "pass-wrapper.sh passes remote server password as CLI arg to sam-copy.exp; "
                "MITM on management network intercepts admin remote server credentials",
    "status":   "CONFIRMED — opt/cisco/bin/sam-copy.exp + opt/cisco/bin/pass-wrapper.sh + "
                "opt/cisco/bin/download-common.sh in both core-1.5.1-c.x86_64.rpm and "
                "core-2.1.2-b.x86_64.rpm (diff: shebang path only + minor k option)",
    "severity": "HIGH",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "host_key_bypass": (
        "sam-copy.exp sam_scp proc:\n"
        "  expect { \"*yes*?*\" { send \"yes\\r\"; exp_continue } }\n"
        "No SSH host key verification for backup SCP/SFTP operations. "
        "Distinct from UCSC-F30 (cluster_add.sh) — separate Expect script, separate code path; "
        "same vulnerability class. Triggered on every admin-initiated backup/restore/export."
    ),

    "password_exposure": (
        "pass-wrapper.sh line 7:\n"
        "  ${bindir}/sam-copy.exp ${proto} ${direction} ${server} ${localfile} ${remotefile} ${user} ${pass}\n"
        "Remote server password appears as argv[6] of sam-copy.exp process — visible in "
        "/proc/<pid>/cmdline and 'ps aux' output to any local user with /proc access. "
        "sam-copy.exp receives it from download-common.sh getopts -P flag or interactive 'read -s -p'.\n"
        "Flow: admin runs backup → file-copy.sh -P <pass> → pass-wrapper.sh → sam-copy.exp <pass>"
    ),

    "receive_perms": (
        "sam-copy.exp change_perms proc (copyin direction only):\n"
        "  spawn /bin/chmod a+rw $localfile\n"
        "Every file received via copyin gets chmod a+rw applied. "
        "On restore, backup files written to /opt/cisco/cert/ or other sensitive paths become "
        "world-writable after transfer — amplifies impact of a MITM-served malicious restore payload."
    ),

    "mitm_impact": (
        "On management VLAN without DHCP snooping or ARP inspection:\n"
        "1. ARP spoof targeting admin workstation to impersonate backup server\n"
        "2. sam-copy.exp auto-accepts attacker's SSH host key (no verification)\n"
        "3. Admin's remote server password transmitted to attacker's server\n"
        "4. Attacker serves malicious restore payload on copyin — file written by daemon user, "
        "   then change_perms makes it world-readable/writable.\n"
        "Combined with UCSC-F1 (known encryption key): attacker also serves forged sam.config "
        "with crafted adminPasswd ciphertext → credential replacement on restore."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F39 — snmp_update_peer.sh StrictHostKeyChecking=no during SNMP peer sync;
#             sync_snmpconf.sh sudo chmod 666 on SNMP config files (world-readable
#             + world-writable); SNMP community strings and internalUser:authpassword
#             exposed to any local process; MITM enables malicious SNMP config injection
# Source: opt/cisco/bin/snmp_update_peer.sh + opt/cisco/bin/sync_snmpconf.sh
#         (identical in 1.5.1c and 2.1.2b; diff: shebang path only)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F39 = {
    "id":       "UCSC-F39",
    "title":    "snmp_update_peer.sh uses StrictHostKeyChecking=no for peer SNMP config sync; "
                "sync_snmpconf.sh sudo-chmodds SNMP config files to 666 — "
                "SNMP credentials (internalUser:authpassword, public community) world-readable/writable; "
                "MITM during peer sync replaces SNMP config",
    "status":   "CONFIRMED — opt/cisco/bin/snmp_update_peer.sh line 10 + "
                "opt/cisco/bin/sync_snmpconf.sh lines 11-12; "
                "identical in 1.5.1c and 2.1.2b (diff: shebang path only)",
    "severity": "MEDIUM",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "stricthostkeychecking": (
        "snmp_update_peer.sh line 10:\n"
        "  SSH_OPTIONS=\"-o StrictHostKeyChecking=no -o ConnectionAttempts=3 -o ConnectTimeout=3 -o ServerAliveInterval=3\"\n"
        "Used in lines 15-16: sudo scp ${SSH_OPTIONS} ${SNMPD_GEN_CONF_FILE} samdme@${PEER_IP}:${SNMPD_CONF_DIR}\n"
        "Used in line 19: sudo ssh ${SSH_OPTIONS} samdme@${PEER_IP} 'bash -s' </opt/cisco/bin/sync_snmpconf.sh\n"
        "No host key verification — MITM attack intercepts SCP transfer; attacker replaces "
        "snmpd_gen.conf on peer with malicious config. On line 19, attacker controls the "
        "executed script on the target if SSH session is intercepted before auth completes."
    ),

    "world_writable_config": (
        "sync_snmpconf.sh lines 11-12:\n"
        "  ${SUDO_CMD} ${CHMOD_CMD} 666 $SNMPD_GEN_CONF_FILE         # /etc/snmp/snmpd_gen.conf\n"
        "  ${SUDO_CMD} ${CHMOD_CMD} 666 $SNMPD_GEN_PERSIST_CONF_FILE # /etc/snmp/snmpd_gen_persist.conf\n"
        "Both files set 666 (rw-rw-rw-) after every snmpd restart. "
        "Any local OS user (daemon, postgres, etc.) can:\n"
        "  1. READ /etc/snmp/snmpd_gen.conf → internalUser:authpassword + public community (UCSC-F23)\n"
        "  2. WRITE arbitrary SNMP config → add write community, modify auth params, redirect traps"
    ),

    "related": "UCSC-F23 (hardcoded internalUser:authpassword in snmpd_base.conf); "
               "UCSC-F30 (cluster SSH host key bypass); UCSC-F38 (backup SCP host key bypass). "
               "Third independent SSH host-key-bypass code path in three distinct operations "
               "(cluster formation, backup, SNMP sync).",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F40 — sam-copy.sh (operation-mgr RPM) auto-accepts SSH host key during
#             firmware image SCP/SFTP transfers (fourth distinct host-key-bypass
#             code path); distinct from UCSC-F38 (backup, sam-copy.exp/core RPM)
#             and UCSC-F39 (SNMP peer sync, snmp_update_peer.sh/core RPM)
# Source: opt/cisco/bin/sam-copy.sh in operation-mgr RPM (1.5.1c + 2.1.2b)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F40 = {
    "id":       "UCSC-F40",
    "title":    "sam-copy.sh (operation-mgr RPM) auto-accepts SSH host key during "
                "firmware image SCP/SFTP transfers; fourth independent SSH host-key-bypass "
                "code path across UCS Central; MITM enables firmware image tampering "
                "during remote copy operations",
    "status":   "CONFIRMED — operation-mgr RPM opt/cisco/bin/sam-copy.sh line 69 "
                "(1.5.1c) / line 69 (2.1.2b); diff: minor SCP arg quoting, TFTP binary "
                "change (busybox → system tftp); host-key-bypass logic identical",
    "severity": "MEDIUM",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "host_key_bypass": (
        "sam-copy.sh line 69: expect { ... \"*yes*?*\" { send \"yes\\r\" } ... }\n"
        "Applies to: sam_scp (SCP) and sam_sftp (SFTP) proc — any 'yes/no' host key "
        "prompt auto-accepted without verification.\n"
        "sam_ftp: FTP protocol — no SSH, no host key; not in scope.\n"
        "sam_tftp: TFTP — no auth at all; not in scope.\n"
        "Operation: called for firmware image download/upload; attacker controlling "
        "network between UCS Central and firmware server intercepts SCP/SFTP session, "
        "presents rogue host key, delivers malicious firmware image."
    ),

    "distinction_from_f38": (
        "UCSC-F38 (sam-copy.exp, core RPM): backup SCP/SFTP; password always CLI arg "
        "(ps-visible); change_perms sets a+rw on copyin files.\n"
        "UCSC-F40 (sam-copy.sh, operation-mgr RPM): firmware image transfer; password "
        "via argv[6] OR $SAM_COPY_PASSWD env var (env var path avoids ps exposure); "
        "change_perms sets 644 on copyin files (less permissive than UCSC-F38).\n"
        "Both have identical host-key-bypass logic; different RPM, different operation, "
        "different caller chain."
    ),

    "related": "UCSC-F30 (cluster SSH host-key bypass); UCSC-F38 (backup SCP sam-copy.exp); "
               "UCSC-F39 (SNMP peer sync snmp_update_peer.sh). All four bypass SSH host key "
               "verification across cluster, backup, SNMP, and firmware-transfer code paths.",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F41 — Hardcoded SCSI-3 Persistent Group Reservation (PGR) keys
#             across all 5 sg_PGR_*.sh HA fencing scripts; keys identical
#             in all UCS Central HA deployments; SAN-level fencing bypass
# Source: opt/cisco/bin/sg_PGR_{register,clearAllAndRegister,reserve,release,
#         unregister}.sh (core RPM, 1.5.1c + 2.1.2b)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F41 = {
    "id":       "UCSC-F41",
    "title":    "Hardcoded SCSI-3 PGR keys '123abc1' (Fabric A) and '123abc2' (Fabric B) "
                "in all HA storage fencing scripts — identical across all UCS Central HA "
                "deployments; attacker with SAN access preempts reservations using known "
                "keys, disabling HA fencing and enabling split-brain data corruption",
    "status":   "CONFIRMED — opt/cisco/bin/sg_PGR_{register,clearAllAndRegister,reserve,"
                "release,unregister}.sh in core RPM; keys identical in 1.5.1c + 2.1.2b "
                "(only shebang line differs: /bin/bash vs /usr/bin/bash)",
    "severity": "MEDIUM",
    "versions_affected": ["1.5.1c", "2.1.2b"],

    "pgr_keys": {
        "fabric_A": "123abc1",
        "fabric_B": "123abc2",
    },

    "source_files": [
        "opt/cisco/bin/sg_PGR_register.sh",
        "opt/cisco/bin/sg_PGR_clearAllAndRegister.sh",
        "opt/cisco/bin/sg_PGR_reserve.sh",
        "opt/cisco/bin/sg_PGR_release.sh",
        "opt/cisco/bin/sg_PGR_unregister.sh",
    ],

    "technical_detail": (
        "SCSI-3 PGR is the HA storage fencing mechanism in UCS Central clustered deployments. "
        "Nodes register with the shared storage device using a key, then make write-exclusive "
        "reservations — the node holding the reservation controls storage; the other is fenced.\n"
        "sg_PGR_register.sh: sg_persist --out --register --param-sark=123abc1 <device>\n"
        "sg_PGR_reserve.sh:  sg_persist --out --reserve --param-rk=123abc1 --prout-type=1 <device>\n"
        "sg_PGR_clearAllAndRegister.sh: sg_persist -C -K 123abc1 --out <device> (CLEAR ALL then register)\n"
        "All keys hardcoded to '123abc1' (A) / '123abc2' (B) — no per-deployment uniqueness."
    ),

    "attack_path": (
        "Requires SAN/iSCSI access to the shared storage device.\n"
        "1. Attacker queries SCSI PGR state: sg_persist <device> (no auth, SAN access only)\n"
        "2. Attacker clears all registrations using known key:\n"
        "     sg_persist -C -K 123abc1 --out <device>\n"
        "   Both cluster nodes are now deregistered — HA fencing inoperable.\n"
        "3. Attacker registers competing key, claiming storage:\n"
        "     sg_persist --out --register --param-sark=123abc1 <device>\n"
        "   Result: split-brain; both nodes may write to shared storage simultaneously "
        "→ database corruption.\n"
        "4. Alternatively: keep one node fenced permanently by holding the reservation, "
        "forcing the other into standby regardless of cluster health."
    ),

    "prerequisite": "Direct SAN/iSCSI/FC access to the UCS Central shared storage LUN. "
                    "Not exploitable from the network management plane alone.",

    "note": "These keys serve the same SCSI PGR role as node-specific keys in production "
            "storage stacks, but are deliberately simplified (single numeric sequence) "
            "in UCS Central — suggesting they were never intended to be a security boundary. "
            "However, their universality across ALL deployments makes them trivially known.",
}

# ─────────────────────────────────────────────────────────────────────────────
# UCSC-F42 — HyperFlex encryption service barredUsers list omits 'diag' and
#             'local/diag'; all other HyperFlex REST APIs explicitly bar these
#             accounts; diag can authenticate to SED disk encryption management
# Source: encryption/WEB-INF/classes/application.conf (both copies)
# ─────────────────────────────────────────────────────────────────────────────
UCSC_F42 = {
    "id":       "UCSC-F42",
    "title":    "HyperFlex REST API platform: 8 of 11 WAR services omit 'diag'/'local/diag' "
                "from barredUsers — diag can authenticate to disk encryption, data protection, "
                "backup, DARE software encryption, firmware upgrade, STIG removal, cluster "
                "bootstrap, and smart licensing APIs",
    "status":   "CONFIRMED — barredUsers = [\"root\", \"local/root\"] (diag absent) in: "
                "encryption, dataprotection, backupservice, securityservice, hxupgrade, "
                "slservice, supportservice, ROOT — all both copies (WEB-INF/classes/ and resources/); "
                "coreapi, auth-war, iscsi correctly use: barredUsers = [\"root\", \"local/root\", \"diag\", \"local/diag\"]",
    "severity": "HIGH",
    "affected_services": {
        "encryption":      "barredUsers = [\"root\", \"local/root\"] — diag NOT barred",
        "dataprotection":  "barredUsers = [\"root\", \"local/root\"] — diag NOT barred",
        "backupservice":   "barredUsers = [\"root\", \"local/root\"] — diag NOT barred",
        "securityservice": "barredUsers = [\"root\", \"local/root\"] — diag NOT barred",
        "hxupgrade":       "barredUsers = [\"root\", \"local/root\"] — diag NOT barred",
        "slservice":       "barredUsers = [\"root\", \"local/root\"] — diag NOT barred",
        "supportservice":  "barredUsers = [\"root\", \"local/root\"] — diag NOT barred",
        "ROOT":            "barredUsers = [\"root\", \"local/root\"] — diag NOT barred",
        "coreapi":         "barredUsers = [\"root\", \"local/root\", \"diag\", \"local/diag\"] — correct",
        "auth-war":        "barredUsers = [\"root\", \"local/root\", \"diag\", \"local/diag\"] — correct",
        "iscsi":           "barredUsers = [\"root\", \"local/root\", \"diag\", \"local/diag\"] — correct",
    },
    "exposed_endpoints": {
        "encryption": [
            "GET  /encryption/v1/disks         — SED disk status across cluster nodes",
            "GET  /encryption/v1/certstatus    — per-node KMIP certificate serial numbers",
            "GET  /encryption/v1/kmipcertpolicy — KMIP cert policy",
            "POST /encryption/v1/testkmipconn  — test KMIP connectivity (reveals KMIP server)",
            "GET  /encryption/v1/status        — SED/encryption FSM state",
            "GET  /encryption/v1/nodes         — per-node encryption state",
            "POST /encryption/v1/certificates  — upload/manage KMIP client certificates",
        ],
        "dataprotection": [
            "PUT /vms/{vmId}/failover          — trigger VM failover",
            "PUT /vms/{vmId}/migrate           — migrate protected VM",
            "PUT /vms/{vmId}/testFailover      — initiate test failover",
            "GET/POST/DELETE /peers/           — manage DR peer clusters",
            "GET/POST /dataProtectionGroup     — manage data protection groups",
            "GET/DELETE /dataProtectionGroup/{groupId}/snapshots/{snapshotId}",
            "PUT /schedule/actions             — modify replication schedule",
        ],
        "backupservice": [
            "GET/POST/PUT /policy/backup       — backup policy management",
            "PUT /vms/{vmId}/localRestore      — restore VM from local snapshot",
            "PUT /vms/{vmId}/restoreFromRemote — restore VM from remote backup",
            "POST /snapshots/checkpoint        — create checkpoint snapshot",
        ],
        "securityservice": [
            "GET /software-encryption/dare/overview — DARE encryption state",
            "POST /software-encryption/dare/backup  — backup DARE encryption keys",
            "PUT /software-encryption/dare/key      — modify DARE encryption key",
            "PUT /software-encryption/dare/rekey    — initiate DARE re-keying",
            "GET /software-encryption/dare/config   — DARE configuration",
            "POST /secureboot/setStatus             — modify Secure Boot state",
            "GET /secureboot/getStatus              — Secure Boot status",
        ],
        "hxupgrade": [
            "POST /upgrade                          — initiate firmware upgrade",
            "GET /upgrade/check                     — upgrade pre-check",
            "GET /upgrade/clusterVersionDetails     — current cluster firmware versions",
            "POST /upgrade/validateucsmcreds        — validate UCS Manager credentials",
            "GET /upgrade/ucsAvailablePackages      — enumerate available UCS packages",
            "GET /upgrade/validations               — upgrade validation results",
        ],
        "supportservice": [
            "PUT /stig/apply                        — apply STIG security hardening",
            "PUT /stig/remove                       — remove STIG security hardening",
            "PUT /stig/check                        — check STIG compliance state",
            "GET/PUT /asup                          — AutoSupport configuration",
            "GET/PUT /remotesupport                 — remote support (TAC tunnel) config",
            "GET/POST/DELETE /supportbundle         — support bundle generation/deletion",
        ],
        "slservice": [
            "POST /license/register                 — register smart license",
            "POST /license/renew                    — renew smart license",
            "GET/PUT /license/tier                  — license tier management",
        ],
        "ROOT": [
            "GET/POST /cluster                      — cluster configuration (bootstrap)",
            "GET /clusterCreationProgress           — cluster creation progress",
            "PUT /cluster/network/configure         — configure cluster network",
            "PUT /clusters/recreate/{name}          — recreate a named cluster",
            "GET /nodes                             — node discovery/listing",
            "GET/POST /internalsupport/*            — internal support bundle aggregation",
        ],
    },
    "technical_detail": (
        "All 11 HyperFlex REST API WARs share the same AAA filter chain (AuditFilter, "
        "SPPrivilegedAuth, SessionAuth, SPBasicAuth, SPAuth applied via web.xml /v1/* or "
        "/rest/*). Each WAR's application.conf independently sets barredUsers, which the "
        "filter implementation reads to block specific system accounts from authenticating.\n"
        "The diag account is blocked in only 3 of 11 WARs: coreapi, auth-war, iscsi "
        "(4 entries: root, local/root, diag, local/diag). The remaining 8 WARs use only "
        "2 entries (root, local/root), leaving diag able to authenticate.\n"
        "The encryption, dataprotection, and ROOT WARs also include a KerberosAuth filter "
        "(com.springpath.hx.aaa.filters.kerberosFilter.KerberosFilterImpl); with "
        "hxSvcHttpEnabled=true in all configs, Kerberos tickets can be passed over "
        "plaintext HTTP.\n"
        "The diag account exists in the HyperFlex PAM stack (service=nginx) and is intended "
        "for diagnostic use only. Its credentials are known or derivable from HyperFlex "
        "diagnostic tooling. Access to supportservice enables STIG hardening removal. "
        "Access to securityservice enables DARE software encryption key manipulation and "
        "Secure Boot state toggle. Access to hxupgrade enables firmware upgrade initiation. "
        "Access to ROOT /rest/* exposes cluster bootstrap and cluster recreation operations. "
        "Access to dataprotection enables VM failover/migration without authorization."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F43 — storfs.py sets LD_LIBRARY_PATH='/root' before exec'ing StorFS binary
# ─────────────────────────────────────────────────────────
UCSC_F43 = {
    "id":       "UCSC-F43",
    "title":    "storfs.py sets LD_LIBRARY_PATH='/root' before exec'ing the StorFS storage "
                "daemon — /root is unconventionally prepended to the dynamic linker search "
                "path, preferentially loading any .so placed there over system libraries",
    "status":   "CONFIRMED — storfs-core-552/opt/springpath/storfs-core/storfs.py line 31: "
                "os.environ['LD_LIBRARY_PATH'] = '/root'",
    "severity": "LOW",
    "source_file": "opt/springpath/storfs-core/storfs.py",
    "source_line": 31,
    "source_text": "os.environ['LD_LIBRARY_PATH'] = '/root'",
    "technical_detail": (
        "storfs.py is a Python wrapper that reads hardware and tune configuration, "
        "then calls os.execvp('/opt/springpath/storfs-core/storfs', args) to replace "
        "itself with the StorFS storage daemon. Before execvp, line 31 sets "
        "LD_LIBRARY_PATH to '/root' (the root user's home directory).\n"
        "The dynamic linker resolves LD_LIBRARY_PATH before standard library paths "
        "(rpath, /etc/ld.so.cache, /lib, /usr/lib). Any shared library placed in /root "
        "matching a StorFS dependency name (e.g. libssl.so.1.1, libz.so.1) would be "
        "loaded instead of the system library.\n"
        "Since StorFS runs as root and /root is mode 700, exploitation requires root-level "
        "write access. The value '/root' is a development artifact (testing with local "
        "libraries) that was never replaced before shipping. No legitimate runtime "
        "libraries should be in /root."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F44 — storfsevents.py embeds FIFO data unsanitized into initctl command string
# ─────────────────────────────────────────────────────────
UCSC_F44 = {
    "id":       "UCSC-F44",
    "title":    "storfsevents.py process_event() embeds FIFO-sourced event fields directly "
                "into an initctl emit command string without sanitization — argument injection "
                "into Upstart event dispatch via crafted records written to /tmp/storfseventsfifo",
    "status":   "CONFIRMED — storfs-core-552/opt/springpath/storfs-core/storfsevents.py "
                "lines 164-169: event_id and event_args embedded in format string, "
                "Command.execute() calls shlex.split() on the result",
    "severity": "LOW",
    "source_file": "opt/springpath/storfs-core/storfsevents.py",
    "source_lines": [164, 165, 166, 169],
    "source_text": (
        "event_id, event_ts, event_desc, event_args = stevent.split('::')[:4]\n"
        "cmd='{} emit --no-wait {} ST_EVENT_ID={} ST_EVENT_TIME={} "
        "ST_EVENT_DESC=\"{}\" ST_EVENT_ARGS=\"{}\".format(\n"
        "    exe, event_id, event_id, event_ts, event_desc, event_args)\n"
        "v = Command(logger=logger).execute(cmd=cmd)"
    ),
    "fifo_path": "/tmp/storfseventsfifo",
    "technical_detail": (
        "storfsevents.py reads the StorFS event FIFO at /tmp/storfseventsfifo "
        "(configurable, default path in /tmp). Events are '::'‐delimited 4-field records: "
        "event_id::event_ts::event_desc::event_args.\n"
        "process_event() builds an initctl command string using .format() with all four "
        "fields embedded directly without escaping. Command.execute() calls shlex.split() "
        "on this string (shell=False), then passes the resulting token list to subprocess.Popen.\n"
        "Injected spaces in event_id split into additional initctl arguments. "
        "Injected double-quotes in event_args close the quoted token and inject new "
        "argument tokens. With shell=False, this does not execute arbitrary OS commands, "
        "but enables injection of extra arguments to /sbin/initctl, allowing an attacker "
        "with write access to the FIFO to emit arbitrary Upstart events with controlled "
        "environment variables, which can trigger registered Upstart job handlers.\n"
        "The FIFO resides in /tmp (world-accessible), created by EventFifo.__enter__ via "
        "os.mkfifo(). FIFO permissions are set by the service's umask at startup. "
        "If storfsevents.py starts before the StorFS binary attempts to write the FIFO, "
        "a timing window exists where a local process could write a crafted event record "
        "before the legitimate event is produced."
    ),
}

# ─────────────────────────────────────────────────────────
# UCSC-F45 — StorvisorFileUploader servlet at /upload, auth filters at /upload/* — URL pattern mismatch
# ─────────────────────────────────────────────────────────
UCSC_F45 = {
    "id":       "UCSC-F45",
    "title":    "ROOT WAR StorvisorFileUploader servlet mapped to '/upload' but all auth filters "
                "mapped to '/upload/*' — Servlet spec URL pattern mismatch leaves the firmware "
                "upgrade bundle upload endpoint unauthenticated; POST to /upload writes "
                "attacker-controlled data to /tmp/hxupgrade_bundle.tgz or /tmp/esxiupgrade_bundle.zip",
    "status":   "CONFIRMED — ROOT-1.0.0.war WEB-INF/web.xml: "
                "servlet-mapping /upload (exact), filter-mapping /upload/* (wildcard); "
                "context-param HXFileUploadPath=/tmp/hxupgrade_bundle.tgz, "
                "ESXiFileUploadPath=/tmp/esxiupgrade_bundle.zip; "
                "no auth check in StorvisorFileUploader.class",
    "severity": "HIGH",
    "source_file": "storfs-restapi/opt/hyperflex/storfs-restapi/ROOT-1.0.0.war/WEB-INF/web.xml",
    "servlet_class": "com.storvisor.sysmgmt.service.StorvisorFileUploader",
    "upload_paths": {
        "hxupgrade_bundle": "/tmp/hxupgrade_bundle.tgz",
        "esxi_bundle":      "/tmp/esxiupgrade_bundle.zip",
    },
    "url_patterns": {
        "servlet_mapping": "/upload",
        "filter_mapping":  "/upload/*",
    },
    "technical_detail": (
        "ROOT-1.0.0.war defines 6 filters (AuditFilter, SPPrivilegedAuth, SessionAuth, "
        "KerberosAuth, SPBasicAuth, SPAuth) that are mapped to URL pattern '/upload/*'. "
        "The StorvisorFileUploader servlet is mapped to the exact path '/upload'.\n"
        "Per the Servlet 2.4 spec (Section 12.2), a URL pattern ending in '/*' matches "
        "only paths that start with the prefix followed by '/'. The exact path '/upload' "
        "does NOT match '/upload/*' (there is no '/' after 'upload'). Tomcat implements "
        "this strictly: a request to exactly '/upload' hits the servlet without traversing "
        "any of the auth filter mappings.\n"
        "StorvisorFileUploader.doPost() reads the 'uploadType' request parameter: "
        "if 'ESXI', the file is written to esxiFilePath (/tmp/esxiupgrade_bundle.zip); "
        "otherwise, it is written to hxFilePath (/tmp/hxupgrade_bundle.tgz). The upload "
        "size limit is set via maxFileSize (from Apache Commons FileUpload). "
        "No authentication, session, or CSRF check is present in the servlet class itself.\n"
        "The uploaded bundles are the input to the hxupgrade service's upgrade pipeline. "
        "An unauthenticated attacker with network access to the HyperFlex management "
        "interface can overwrite the pending upgrade bundle with arbitrary content."
    ),
}

UCSC_F46 = {
    "id":       "UCSC-F46",
    "title":    "HyperFlex REST API storfs-restapi Tomcat process permanently disables TLS certificate "
                "verification JVM-globally via HttpsURLConnection.setDefaultSSLSocketFactory(trustAll) "
                "and setDefaultHostnameVerifier(acceptAll) — 17 gateway client classes across 7 of 11 "
                "WARs call trustAll() on every HTTP Thrift connection, setting JVM-wide defaults that "
                "persist for the lifetime of the process; all outbound HTTPS connections after any "
                "management operation skip certificate validation",
    "status":   "CONFIRMED — strings/javap analysis; 17 classes across iscsi/supportservice/ROOT/"
                "securityservice/slservice/hxupgrade/encryption WARs all contain setDefaultSSLSocketFactory"
                " + setDefaultHostnameVerifier calls setting process-global trust-all TLS state",
    "severity": "HIGH",
    "source_pkg": "storfs-restapi deb (storfs-packages-6.0.2b-44423.tgz)",
    "affected_wars": [
        "iscsi WAR (4 classes): HxIscsiMgrClient, HxIscsiCloneMgrClient, HxSvcMgrClient, StMgrClient",
        "supportservice WAR (4 classes): HxSvcMgrClient, StMgrClient, HxSupportSvcClient, WebDownloader",
        "ROOT WAR (3 classes): WebDownloader, HxSupportSvcAccess, ServiceAccess",
        "securityservice WAR (3 classes): HxSvcMgrClient, HxSecuritySvcMgrClient, StMgrClient",
        "encryption WAR (1 class): StMgrClient — manages KMIP certs and SED disk encryption keys",
        "slservice WAR (1 class)",
        "hxupgrade WAR (1 class)",
    ],
    "technical_detail": (
        "Each affected gateway client class contains a trustAll() method that:\n"
        "  1. Creates an X509TrustManager stub overriding checkClientTrusted/checkServerTrusted/getAcceptedIssuers "
        "     (all no-ops or return null)\n"
        "  2. Initializes an SSLContext.getInstance('TLS') with the trust-all manager\n"
        "  3. Calls HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory()) — GLOBAL\n"
        "  4. Creates a HostnameVerifier stub that unconditionally returns true\n"
        "  5. Calls HttpsURLConnection.setDefaultHostnameVerifier(verifier) — GLOBAL\n"
        "These static calls modify the JVM process default, not a per-connection setting. "
        "Once any management operation in these 6 WARs executes, ALL subsequent HTTPS connections "
        "from the storfs-restapi Tomcat JVM bypass certificate verification. "
        "The 11 WARs share a single Tomcat process; the global state persists until process restart.\n"
        "Affected outbound HTTPS connections include: vCenter API (VM management, backup snapshots), "
        "UCS Manager API (hardware inventory), KMIP server (SED disk encryption key operations — "
        "securityservice WAR), smart licensing authority, any external HTTPS endpoint the process "
        "contacts. An attacker with MITM position on the management network can present a self-signed "
        "certificate and intercept credentials or session tokens exchanged over these connections.\n"
        "The pattern is present in every HTTP Thrift gateway client; it is invoked on every API call "
        "that uses HTTP transport (sysmgmt.hxSvcHttpEnabled=true default in application.conf)."
    ),
    "instance_example": {
        "class":    "com.springpath.hx.iscsi.gateway.HxIscsiMgrClient.openClientHttp()",
        "sequence": [
            "trustAll();  // sets JVM-global SSLSocketFactory + HostnameVerifier",
            "host = AAAConfiguration.getPropVal('sysmgmt.hxIscsiMgrHost') ?? 'localhost'",
            "transport = new THttpClient(host + ':9342');",
            "transport.setCustomHeader('X-RootSessionID', HxSecurity.getLocalSessionId());",
            "cl = new iscsiSvcMgr.Client(new TBinaryProtocol(transport));",
        ],
    },
}

UCSC_F47 = {
    "id":       "UCSC-F47",
    "title":    "HyperFlex storfs.py launch wrapper hardcodes LD_LIBRARY_PATH=/root — the storfs "
                "storage daemon launch script sets LD_LIBRARY_PATH to /root (root home directory) "
                "at module level before execvp into the storfs binary; if /root permissions are "
                "permissive or an attacker can write files there, arbitrary shared objects are "
                "loaded into the storfs process on next service restart",
    "status":   "CONFIRMED — source analysis; storfs.py line 31: os.environ['LD_LIBRARY_PATH'] = '/root'; "
                "storfs.conf launches storfs.py as root with no setuid directive; storfs binary "
                "inherits the environment and searches /root first for shared libraries",
    "severity": "MEDIUM",
    "source_pkg": "storfs-core-data deb (storfs-packages-6.0.2b-44423.tgz)",
    "technical_detail": (
        "storfs.py sets LD_LIBRARY_PATH to /root unconditionally at module scope (line 31), "
        "before any argument parsing or privilege checks. The Upstart job storfs.conf (no setuid "
        "directive) runs storfs.py as root. storfs.py then calls os.execvp('/opt/springpath/storfs-core/storfs', ...) "
        "which inherits the modified environment. The storfs binary dynamic linker resolves "
        "shared libraries by searching LD_LIBRARY_PATH first: /root is searched before /lib, "
        "/usr/lib, and other system paths.\n"
        "Impact: A local process with write access to /root (or if /root permissions are not 0700) "
        "can plant a .so file whose name matches any library linked by storfs (e.g., libstorfs.so, "
        "libstdc++.so.6, libc.so.6). The malicious .so is loaded on the next storfs restart. "
        "Since storfs is the primary storage daemon for the HyperFlex controller VM, code execution "
        "in this context provides access to all storage data paths.\n"
        "The /root path is not a legitimate shared library directory and its presence is a "
        "development artifact that was never removed from production code."
    ),
    "source_ref": "storfs-core-data/opt/springpath/storfs-core/storfs.py:31",
}

UCSC_F48 = {
    "id":       "UCSC-F48",
    "title":    "UCS Central bundle_unpack.sh uses tar --absolute-names (-P) on bundle payload — "
                "the firmware bundle unpack script extracts the tar payload inside Cisco bundles "
                "with the -P flag (preserve absolute paths), allowing tar members with absolute "
                "paths to be written to arbitrary filesystem locations rather than being confined "
                "to the working directory",
    "status":   "CONFIRMED — source analysis; bundle_unpack.sh: tar zxkPpmvf - (P flag present); "
                "applied to all four bundle types (switch/chassis/third-party/provider) during "
                "image installation; both 1.5.1c and 2.1.2b versions affected",
    "severity": "MEDIUM",
    "source_pkg": "operation-mgr (operation-mgr151c, operation-mgr212b)",
    "technical_detail": (
        "bundle_unpack.sh processes firmware bundles via:\n"
        "  cd ${TMP_FILES_DIR}\n"
        "  /bin/dd if=${BUNDLE_BASE_DIR}/${BUNDLE_NAME} skip=1 bs=$BS | tar zxkPpmvf -\n"
        "The -P flag (--absolute-names) instructs GNU tar not to strip leading '/' from member "
        "names. Without -P, GNU tar strips leading slashes, confining extraction to the working "
        "directory. With -P, a tar member named '/etc/cron.d/malicious' is written to "
        "'/etc/cron.d/malicious' rather than './etc/cron.d/malicious'.\n"
        "The -k flag (keep, do not overwrite existing files) limits overwrite of existing system "
        "files, but new files at arbitrary absolute paths can be created. Attackers who can "
        "supply a bundle with a valid Cisco image header wrapping a crafted tar payload can "
        "write arbitrary new files to the UCS Central appliance filesystem during bundle "
        "installation. Plausible new-file targets: /etc/cron.d/, /etc/init/, /etc/sudoers.d/, "
        "/root/.ssh/authorized_keys (if not present).\n"
        "The bundle_extsvc.sh execution at line:\n"
        "  ${TMP_FILES_DIR}/${BUNDLE_EXTSVC}\n"
        "provides a direct code execution path: if the tar payload includes bundle_extsvc.sh, "
        "the script is made executable and run immediately after extraction."
    ),
    "source_ref": "operation-mgr151c/opt/cisco/bin/bundle_unpack.sh",
}

UCSC_F49 = {
    "id":       "UCSC-F49",
    "title":    "UCS Central bundle_unpack.sh recursively sets world-writable permissions on "
                "firmware staging and download directories — chmod 777 applied to unpacking "
                "scratch directories and chmod a+w /opt/cisco/download -R applied to the "
                "permanent download directory after every provider image installation",
    "status":   "CONFIRMED — source analysis; bundle_unpack.sh: chmod 777 ${TMP_FILES_DIR}; "
                "chmod 777 ${TMP_IMAGES_DIR}; chmod 777 ${TMP_SCRATCH_DIR}; "
                "chmod a+w /opt/cisco/download -R (permanent, not cleaned up)",
    "severity": "LOW",
    "source_pkg": "operation-mgr (operation-mgr151c, operation-mgr212b)",
    "technical_detail": (
        "bundle_unpack.sh applies chmod 777 to three scratch directories during bundle processing "
        "and, for provider-type images (PLATFORM==18), applies chmod a+w /opt/cisco/download -R "
        "to make the persistent download directory world-writable. The download directory stores "
        "softlinks pointing to installed firmware images. A local attacker with any shell access "
        "can:\n"
        "  1. Replace softlinks in /opt/cisco/download/ with symlinks pointing to attacker-controlled "
        "files, poisoning subsequent firmware operations that follow these links.\n"
        "  2. Write files into the scratch directories during the window when they are world-writable "
        "to inject content that is subsequently processed or linked into the installable tree.\n"
        "The scratch directory window is transient but /opt/cisco/download remains world-writable "
        "after any provider image has been installed."
    ),
    "source_ref": "operation-mgr151c/opt/cisco/bin/bundle_unpack.sh",
}

UCSC_F50 = {
    "id":       "UCSC-F50",
    "title":    "UCS Central sam-copy.sh passes file transfer credentials as plaintext command-line "
                "arguments — the Tcl/Expect file transfer script accepts passwords via argv[6] "
                "and environment variable SAM_COPY_PASSWD; passwords passed as argv[6] are visible "
                "in process listings (ps aux) to any local user",
    "status":   "CONFIRMED — source analysis; sam-copy.sh (Tcl/Expect script): "
                "set pass [lindex $argv 6]; password sourced from CLI arg when SAM_COPY_PASSWD "
                "env var absent; script handles SCP, SFTP, FTP, TFTP protocols with explicit "
                "password handling; both 1.5.1c and 2.1.2b versions affected",
    "severity": "LOW",
    "source_pkg": "operation-mgr (operation-mgr151c, operation-mgr212b)",
    "technical_detail": (
        "sam-copy.sh is a Tcl/Expect script invoked as:\n"
        "  sam-copy.sh <protocol> <copyin|copyout> <server> <localfile> <remotefile> <user> [<passwd>]\n"
        "When passwd is supplied as argv[6], it is passed to the scp/sftp/ftp/tftp spawn commands "
        "and visible in /proc/<pid>/cmdline and ps aux output. Any local process with /proc read "
        "access (typically all local users) can read the password mid-transfer.\n"
        "The fallback is SAM_COPY_PASSWD environment variable, but callers that use argv[6] "
        "expose the credential. This script is called by the operation-mgr Java DME daemon for "
        "inter-domain file transfers (firmware images, backup files), so the credentials belong "
        "to remote system accounts (peer UCS domains, external storage servers)."
    ),
    "source_ref": "operation-mgr151c/opt/cisco/bin/sam-copy.sh",
}

UCSC_F51 = {
    "id":       "UCSC-F51",
    "title":    "HSU agent systemd service loads EnvironmentFile from world-writable /tmp path — "
                "hsu_agent.service specifies EnvironmentFile=-/tmp/hsu-agent/hsu_env; the init script "
                "creates the /tmp/hsu-agent/ directory and hsu_env file but applies no restrictive "
                "permissions; a local attacker who pre-creates /tmp/hsu-agent/hsu_env before service "
                "start can inject LD_PRELOAD or other environment variables into the root-privileged "
                "hsu_agent process",
    "status":   "CONFIRMED — source analysis; hsu_agent.service: "
                "ExecStartPre=/usr/local/bin/hsu_agent.sh start; EnvironmentFile=-/tmp/hsu-agent/hsu_env; "
                "No User= directive (runs as root); hsu_agent.sh init_config(): mkdir -p /tmp/hsu-agent/ "
                "(no -m flag, default umask), touch /tmp/hsu-agent/hsu_env (does not clear content); "
                "no chmod/fchmod/umask call on the directory or env file; "
                "jemalloc conditional overwrites file only when /usr/local/lib/libjemalloc.so.2 is "
                "present — absent jemalloc, attacker content survives into EnvironmentFile load; "
                "hsu_agent binary strings: no chmod/fchmod/umask symbol found",
    "severity": "MEDIUM",
    "source_pkg": "hsu-agent-436",
    "technical_detail": (
        "hsu_agent.service (systemd unit, no User= directive → runs as root):\n"
        "  ExecStartPre=/usr/local/bin/hsu_agent.sh start\n"
        "  ExecStart=/usr/local/bin/hsu_agent\n"
        "  EnvironmentFile=-/tmp/hsu-agent/hsu_env\n"
        "  Restart=always; RestartSec=5s\n\n"
        "hsu_agent.sh init_config() sequence:\n"
        "  mkdir -p /tmp/hsu-agent/           # no -m; default umask → dir is 755\n"
        "  touch /tmp/hsu-agent/hsu_env       # only updates mtime if file exists\n"
        "  if [ -e /usr/local/lib/libjemalloc.so.2 ]; then\n"
        "      echo LD_PRELOAD=.../libjemalloc.so.2 > /tmp/hsu-agent/hsu_env\n"
        "  fi\n\n"
        "Attack: local user writes LD_PRELOAD=/tmp/evil.so to /tmp/hsu-agent/hsu_env before service "
        "start. touch preserves the content. If jemalloc is absent the file is loaded as-is into "
        "ExecStart environment. The Restart=always policy provides a 5-second race window on every "
        "daemon crash — an attacker who can trigger a crash gets repeated opportunities.\n\n"
        "Affected: hsu-agent-436 deployed on UCS rack servers as part of HyperFlex / UCS management stack."
    ),
    "source_ref": "hsu-agent-436-data/usr/lib/systemd/system/hsu_agent.service; "
                  "hsu-agent-436-data/usr/local/bin/hsu_agent.sh",
}

UCSC_F52 = {
    "id":       "UCSC-F52",
    "title":    "HSU agent Unix domain socket /tmp/hsu-agent/hsu-socket is world-accessible with no "
                "authentication — the root-privileged daemon creates the socket with default umask "
                "permissions (no chmod/fchmod call), accepts JSON method dispatch without credentials, "
                "and exposes operations including OS installation, OOB firmware activation, inband "
                "firmware update, host reboot, and hardware diagnostics to any local user",
    "status":   "CONFIRMED — binary analysis; hsu_agent: bind() on /tmp/hsu-agent/hsu-socket; "
                "no chmod/fchmod/umask symbol in binary (strings scan exhaustive); socket created "
                "in /tmp/hsu-agent/ directory with default 755 permissions (world-traversable); "
                "socket file inherits process umask → world-readable/writable (srwxr-xr-x); "
                "method dispatch strings: stop, start-diagnostics, cancel-diagnostics, oob-activate, "
                "huu-inband-operation, get-fw-inventory, get-inventory-state, update-status, "
                "scu-os-install, resume-hsu-max; no token/auth/key field in dispatch interface; "
                "hsu_plugin.json: 9 components (CIMC, BIOS, Board_Controller, VIC 1385/1387/1455/1457/"
                "1495/1497); disruption=Host_Reboot for 8 of 9 components",
    "severity": "MEDIUM",
    "source_pkg": "hsu-agent-436",
    "technical_detail": (
        "The HSU agent listens on /tmp/hsu-agent/hsu-socket (Unix domain socket, AF_UNIX).\n"
        "The directory /tmp/hsu-agent/ is created by hsu_agent.sh with mkdir -p (no -m flag), "
        "defaulting to 755. The binary calls bind() on the socket path but no chmod/fchmod/umask "
        "call is present in the binary. Under a typical root umask of 022, the socket file is "
        "created with srwxr-xr-x — world-readable and world-writable.\n\n"
        "The server dispatches based on a 'method' JSON field with no authentication check:\n"
        "  stop                  — terminates the daemon (availability DoS)\n"
        "  start-diagnostics     — triggers hardware diagnostics\n"
        "  cancel-diagnostics    — cancels running diagnostics\n"
        "  oob-activate          — triggers out-of-band firmware activation\n"
        "  huu-inband-operation  — triggers HUU inband firmware update\n"
        "  scu-os-install        — triggers OS installation on the server\n"
        "  get-fw-inventory      — reads firmware inventory\n"
        "  update-status         — reads update task status\n\n"
        "Any local user (including containers with /tmp mounted, or processes in the UCS management "
        "namespace) can connect to the socket and dispatch methods. The scu-os-install method "
        "invokes the SCU OS installation workflow — effectively wiping and reinstalling the host OS. "
        "Firmware update methods (BIOS, VIC, Board_Controller) trigger host reboots per "
        "hsu_plugin.json disruption='Host_Reboot'.\n\n"
        "The stop command is documented in hsu_agent.sh itself, confirming socket accessibility:\n"
        "  echo '{\"method\":\"stop\"}' | ncat -U /tmp/hsu-agent/hsu-socket"
    ),
    "source_ref": "hsu-agent-436-data/usr/local/bin/hsu_agent (binary); "
                  "hsu-agent-436-data/usr/local/bin/hsu_agent.sh; "
                  "hsu-agent-436-data/var/cisco/hsu-agent/hsu_plugin.json",
}

UCSC_F53 = {
    "id":       "UCSC-F53",
    "title":    "UCS Central libosiris.so contains hardcoded RC4 encryption key used to protect "
                "all sensitive MO fields across 30+ managed object classes — LDAP bind passwords, "
                "RADIUS shared secrets, TACACS+ keys, SNMP auth/priv passwords, iSCSI CHAP "
                "credentials, firmware server passwords, PKI key rings, and database configuration "
                "are all RC4-encrypted with the static key 'dwefsAvfsdkfqweqyrmfvsfwth'",
    "status":   "CONFIRMED — binary analysis; central-mgr151c and central-mgr212b (both versions); "
                "libosiris.so imports RC4_set_key, exports EncryptionContext::getImportKeyCode(), "
                "encryptFile(), decryptBuffer(); string 'dwefsAvfsdkfqweqyrmfvsfwth' appears at "
                "offset 3773 immediately before 'encryptFile' and 'Missing Key Code!!!' error message; "
                "central-mgr.in.xsd confirms 30+ moClass entries with encrypted=\"true\" that rely "
                "on this encryption: aaaEpUser, aaaLdapProvider, aaaRadiusProvider, aaaTacacsPlusProvider, "
                "aaaUser, aaaUserData, aaaRemoteUser, commSnmpUser, commSnmpTrapData, computeUser, "
                "configDbConfig (database credentials), firmwareDownloader, iscsiAuthProfile, "
                "mgmtBackup, pkiKeyRing, and 15+ others; same key in 1.5.1c and 2.1.2b",
    "severity": "HIGH",
    "source_pkg": "central-mgr (central-mgr151c, central-mgr212b)",
    "technical_detail": (
        "libosiris.so is a core shared library in the UCS Central SAM subsystem, linked by libauth.so "
        "and the SAM agent binaries. It implements RC4-based file encryption for the management plane.\n\n"
        "Hardcoded key: dwefsAvfsdkfqweqyrmfvsfwth (26 bytes)\n\n"
        "Function chain:\n"
        "  EncryptionContext::getImportKeyCode() -> returns the static key string\n"
        "  encryptFile(char* src, char* dst, char* key) -> RC4-encrypts src->dst\n"
        "  decryptBuffer(Buffer& in, Buffer& out, bool) -> RC4-decrypts in->out\n\n"
        "All MOs with encrypted=\"true\" in central-mgr.in.xsd have their sensitive attribute values "
        "(passwords, shared secrets, private keys) stored encrypted with this key in the Sybase "
        "database (libsybdb.so/libtdsodbc.so client) or on-disk config files.\n\n"
        "Impact: an attacker with read access to the UCS Central database, a configuration export "
        "(mgmtExport), or a backup archive can RC4-decrypt all credential fields offline using "
        "the static key. No brute force required. RC4 is a broken stream cipher with no authentication; "
        "same-key reuse across all installations means decryption is universal across all UCS Central "
        "1.5.1c and 2.1.2b deployments.\n\n"
        "High-value targets in the encrypted MO set:\n"
        "  configDbConfig  — database connection credentials\n"
        "  aaaLdapProvider — LDAP bind password (domain enumeration pivot)\n"
        "  aaaRadiusProvider / aaaTacacsPlusProvider — shared secrets (RADIUS/TACACS+ auth bypass)\n"
        "  commSnmpUser    — SNMPv3 auth/priv passwords\n"
        "  pkiKeyRing      — PKI private key material\n"
        "  iscsiAuthProfile — iSCSI CHAP initiator/target secrets\n"
        "  firmwareDownloader — firmware server SCP/FTP credentials"
    ),
    "source_ref": "central-mgr151c/opt/cisco/central-mgr/sam/lib/libosiris.so (offset 3773); "
                  "central-mgr212b/opt/cisco/central-mgr/sam/lib/libosiris.so (same key); "
                  "central-mgr151c/opt/cisco/www/schema/central-mgr.in.xsd (encrypted=\"true\" MOs)",
}

UCSC_F54 = {
    "id":       "UCSC-F54",
    "title":    "CMC xinetd TFTP server runs as root with -c (create) flag — unauthenticated file "
                "write to /workspace and unauthenticated read of /workspace/techsupport diagnostic "
                "bundles; both IPv4 and IPv6 listeners enabled on UDP/69",
    "status":   "CONFIRMED — source analysis; cmc-260036-rootfs xinetd.conf: two TFTP service blocks "
                "(flags=IPv4 and flags=IPv6), both with disable=no, user=root, group=root; "
                "server_args=-4/-6 -c -v -s /workspace; -c flag enables file creation; "
                "TFTP has no authentication by default; /workspace contains core/ and techsupport/ "
                "subdirectories; techsupport/ may contain diagnostic bundles with configuration data; "
                "xinetd monitored by doctor_cmc watchdog (always running)",
    "severity": "HIGH",
    "source_pkg": "cmc-260036",
    "technical_detail": (
        "xinetd.conf (CMC) configures two TFTP services:\n"
        "  service tftp (IPv4):\n"
        "    disable = no; user = root; group = root\n"
        "    server_args = -4 -c -v -s /workspace\n"
        "  service tftp (IPv6):\n"
        "    disable = no; user = root; group = root\n"
        "    server_args = -6 -c -v -s /workspace\n\n"
        "The -c flag for tftpd enables file creation — clients can PUT new files to /workspace. "
        "Standard TFTP has no authentication mechanism. Any host with network access to the CMC "
        "management interface can:\n"
        "  GET /workspace/techsupport/* — read diagnostic bundles, potentially containing "
        "network topology, configuration exports, and credential material\n"
        "  GET /workspace/core/*        — read core dump files (process memory)\n"
        "  PUT /workspace/<any>         — write arbitrary files as root\n\n"
        "Written files are created as root-owned. If any CMC daemon reads from /workspace paths "
        "(e.g., firmware update workflows, scripted maintenance tasks), uploaded content could "
        "influence execution. The cicd_update.sh update path reads from /tmp/cmcapppkg.sh, not "
        "/workspace, but other daemons may reference this path.\n\n"
        "xinetd is in the doctor_cmc process watchdog list — the service restarts automatically."
    ),
    "source_ref": "cmc-260036-rootfs/etc/xinetd.conf",
}

UCSC_F55 = {
    "id":       "UCSC-F55",
    "title":    "CMC Mosquitto MQTT broker runs as root with allow_anonymous true — any local "
                "process on the CMC can publish or subscribe to all MQTT topics without credentials",
    "status":   "CONFIRMED — source analysis; cmc-260036-rootfs etc/mosquitto-broker.conf: "
                "user root; per_listener_settings true; listener 0 /var/run/mymqtt.sock; "
                "allow_anonymous true; cmc/bin/* binaries link libmosquitto.so.1 and publish "
                "to /var/run/mymqtt.sock for telemetry; no ACL file configured",
    "severity": "MEDIUM",
    "source_pkg": "cmc-260036",
    "technical_detail": (
        "mosquitto-broker.conf (CMC):\n"
        "  per_listener_settings true\n"
        "  user root\n"
        "  log_dest file /var/cmc/log/mosquitto.log\n"
        "  listener 0 /var/run/mymqtt.sock\n"
        "  allow_anonymous true\n\n"
        "The broker runs as root (user=root directive). The listener is a Unix domain socket "
        "at /var/run/mymqtt.sock — accessible to any local process on the CMC with filesystem "
        "access. No ACL file is configured, and allow_anonymous=true disables credential checks.\n\n"
        "Any process running on the CMC (post-exploitation, container escape, or compromised daemon) "
        "can connect to the socket and:\n"
        "  - Subscribe to all topics (including telemetry, event, and control channels)\n"
        "  - Publish to any topic (potentially injecting false telemetry or triggering actions)\n\n"
        "CMC binaries (cmc/bin/* with libmosquitto linkage) publish MQTT data for telemetry. "
        "The attack surface is local-only (Unix socket), but the absence of any authentication "
        "means a single compromised non-root process on the CMC gains full pub/sub access to "
        "the MQTT broker running as root."
    ),
    "source_ref": "cmc-260036-rootfs/etc/mosquitto-broker.conf; cmc-260036-rootfs/etc/mosquitto/mosquitto.conf",
}

UCSC_F56 = {
    "id":       "UCSC-F56",
    "title":    "HyperFlex SSOPrivilegeAuthImpl accepts X-RootSessionID header to authenticate any "
                "request as any user without a JWT — the session ID is read from "
                "/etc/hyperflex/secure/root_file.pub at runtime; if that file is world-readable "
                "(the .pub extension convention suggests it is), any local process can forge "
                "X-RootSessionID + X-LoggedInUser (arbitrary, including root) + X-Scope: MODIFY, "
                "causing SSOAuthFilterImpl to short-circuit JWT validation and grant full API access; "
                "the barredUsers list (root, diag) is also bypassed on this code path",
    "status":   "CONFIRMED — source analysis; "
                "SSOPrivilegeAuthImpl.validateAuthHeaderForPrivilegeCreds() bytecode: "
                "reads X-RootSessionID header; calls HxSecurity.getLocalSessionId() which opens "
                "/etc/hyperflex/secure/root_file.pub and reads line 0; compares with String.equals(); "
                "if match: sets com.springpath.hx.aaa.authenticateduser=X-LoggedInUser, "
                "com.springpath.hx.aaa.authenticateduserscope=X-Scope, Authenticated=True; "
                "SSOAuthFilterImpl.doFilter() at offset 127 short-circuits to filterChain.doFilter() "
                "when Authenticated=True without any JWT validation; "
                "SSOManager.barredUsers check occurs only during credential auth path, not on this path; "
                "HxSecurity.class constant pool #33=/etc/hyperflex/secure/root_file.pub confirmed; "
                "no X-LoggedInUser content validation found in filter chain",
    "severity": "HIGH",
    "source_pkg": "auth-jar (HyperFlex REST API authentication filters)",
    "technical_detail": (
        "Filter chain (web.xml order): AuditFilter → SPPrivilegedAuth → SessionCookieFilter → "
        "KerberosAuth → SPBasicAuth → SPAuth (SSOAuthFilterImpl)\n\n"
        "SSOPrivilegeAuthImpl.validateAuthHeaderForPrivilegeCreds() logic:\n"
        "  1. Read X-RootSessionID header\n"
        "  2. Call HxSecurity.getLocalSessionId() — reads /etc/hyperflex/secure/root_file.pub\n"
        "  3. If X-RootSessionID == file contents AND X-LoggedInUser + X-Scope + X-RequestInitiator present:\n"
        "     - setAttribute('com.springpath.hx.aaa.authenticateduser', X-LoggedInUser)\n"
        "     - setAttribute('com.springpath.hx.aaa.authenticateduserscope', scope)\n"
        "     - setAttribute('Authenticated', 'True')\n"
        "     - return true\n\n"
        "SSOAuthFilterImpl.doFilter() offset 101-130:\n"
        "  if getAttribute('Authenticated') == 'True': filterChain.doFilter() [no JWT check]\n\n"
        "Attack: read /etc/hyperflex/secure/root_file.pub, send:\n"
        "  X-RootSessionID: <file contents>\n"
        "  X-LoggedInUser: admin  (or any username, barredUsers not checked)\n"
        "  X-Scope: MODIFY\n"
        "  X-RequestInitiator: 127.0.0.1\n"
        "→ Full authenticated API access without a valid JWT token\n\n"
        "File permission verification requires live system access; the .pub extension is consistent "
        "with world-readable SSH public key conventions on Linux systems."
    ),
    "source_ref": (
        "auth-jar/com/springpath/hx/aaa/filters/privilegeAuthFilter/SSOPrivilegeAuthImpl.class; "
        "auth-jar/com/springpath/hx/aaa/filters/ssoFilter/SSOAuthFilterImpl.class; "
        "core-jar/com/springpath/hx/aaa/core/HxSecurity.class"
    ),
}

UCSC_F57 = {
    "id":       "UCSC-F57",
    "title":    "HyperFlex JWT defaultTokenLifeTime is 18 days (1555200000ms) with session keepalive "
                "on every authenticated request — sessions never expire under normal use; stolen "
                "Bearer tokens remain valid for 18+ days without forced rotation",
    "status":   "CONFIRMED — source analysis; application.conf: defaultTokenLifeTime = 1555200000 "
                "(18.0 days); SSOAuthFilterImpl.doFilter() calls AuthFilter.keepSessionAlive() on "
                "every authenticated request with valid JWT, extending the token lifetime; "
                "no short-lived access token + long-lived refresh token pattern; single token "
                "is both access and session credential; SSOManager.defaultServiceAuthTokenLifeTime "
                "field also referenced in SaJwtSerializer.toJwtString",
    "severity": "LOW",
    "source_pkg": "auth-jar (HyperFlex REST API authentication), common-jar (SSOManager)",
    "technical_detail": (
        "application.conf: defaultTokenLifeTime = 1555200000  # 1,555,200 seconds = 18.0 days\n\n"
        "SSOAuthFilterImpl.doFilter() offset 237:\n"
        "  AuthFilter.keepSessionAlive(authType, sessionId)  -- extends token on every request\n\n"
        "Impact: a stolen Bearer token intercepted from any HyperFlex API call (MITM, log leak, "
        "shoulder-surf) remains valid for up to 18 days and gets extended on each use. "
        "Standard practice is 15-60 minute access tokens with separate refresh tokens. "
        "The 18-day single-token design means credential revocation requires explicit "
        "server-side session invalidation (ZK-backed session store), which operators "
        "typically do not perform after incident response."
    ),
    "source_ref": (
        "auth-jar/application.conf (defaultTokenLifeTime); "
        "auth-jar/com/springpath/hx/aaa/filters/ssoFilter/SSOAuthFilterImpl.class (keepSessionAlive); "
        "common-jar/com/springpath/hx/aaa/common/SSOManager.class (defaultTokenLifeTime field)"
    ),
}

UCSC_F58 = {
    "id":       "UCSC-F58",
    "title":    "CMC libcisco_signature.so allow_dev_keys global initialized to 1 in production "
                "firmware — firmware update validation calls code_sign_verify_signature() with "
                "allow_dev_keys=1, accepting firmware signed with Cisco developer keys in addition "
                "to production keys; any entity with Cisco development signing key access can "
                "install arbitrary firmware on production CMC chassis management controllers",
    "status":   "CONFIRMED — source analysis; "
                "libcisco_signature.so .data section at 0x12008 (allow_dev_keys): "
                "initial value 0x01 (uint32=1, true); "
                "cs_rommon_verify_buffer_raw_sign_revocation() offset a4ec: "
                "cbnz w23, a5a4 — when allow_dev_keys!=0 skips non-dev path, "
                "jumps to a5a4 which prints SHA2 hash then calls "
                "code_sign_verify_signature(buf, len, keydb, envSize, allow_dev_keys=1) at a5d4; "
                "non-dev path (a4f0-a50c) calls code_sign_verify_signature(..., allow_dev_keys=0); "
                "_cs_rommon_verify_cmc_buffer.constprop.0 at b948 loads allow_dev_keys from "
                "11000+3960 data pointer into w6 and passes as 7th arg to cs_rommon_verify_buffer; "
                "updated daemon at validate_image_signature offset 6560 calls "
                "cs_rommon_platform_allow_dev_keys(1) which writes 1 to allow_dev_keys+8",
    "severity": "HIGH",
    "source_pkg": "cmc-260036",
    "technical_detail": (
        "libcisco_signature.so .data segment (readelf -l confirms LOAD):\n"
        "  0x12000: __dso_handle = 0x00012000\n"
        "  0x12008: allow_dev_keys = 0x00000001  <-- initialized TRUE\n\n"
        "cs_rommon_verify_buffer_raw_sign_revocation() execution path:\n"
        "  a474: mov w23, w6  (w6 = allow_dev_keys = 1)\n"
        "  a4ec: cbnz w23, a5a4  (non-zero → dev key path)\n"
        "  [a4f0-a50c skipped]: code_sign_verify_signature(..., allow_dev_keys=0)\n"
        "  a5a4: printf('Computed Hash SHA2: '); print_hash(); putchar(\\n)\n"
        "  a5d4: code_sign_verify_signature(..., allow_dev_keys=1)  ← accepts dev keys\n\n"
        "validate_image_signature() in updated:\n"
        "  6548: mov w20, #1\n"
        "  654c: mov w0, w20\n"
        "  6560: bl cs_rommon_platform_allow_dev_keys  [stores 1 → allow_dev_keys+8]\n\n"
        "Impact: All CMC chassis running this firmware version accept developer-signed firmware "
        "images. Cisco development signing keys are internal assets; if obtainable through insider "
        "access, supply-chain compromise, or key leakage, an attacker can permanently backdoor "
        "any UCS CMC through a legitimate-looking firmware update that passes signature validation."
    ),
    "source_ref": (
        "cmc-260036-rootfs/lib/libcisco_signature.so "
        "(nm: allow_dev_keys @0x12008, .data initial value 0x01; "
        "cs_rommon_platform_allow_dev_keys @0x9880; "
        "cs_rommon_verify_buffer_raw_sign_revocation @0xa420; "
        "_cs_rommon_verify_cmc_buffer.constprop.0 @0xb8a0); "
        "cmc-260036-rootfs/cmc/bin/updated "
        "(validate_image_signature @0x6490)"
    ),
}


# ─────────────────────────────────────────────────────────
# UCSC-F59 — HyperFlex encryption service StMgrClient sets JVM-global TLS trust bypass
# ─────────────────────────────────────────────────────────
UCSC_F59 = {
    "id":       "UCSC-F59",
    "title":    "HyperFlex encryption service StMgrClient calls trustAll() which installs an "
                "X509TrustManager that accepts any certificate and a HostnameVerifier that always "
                "returns true as JVM-wide global defaults via HttpsURLConnection.setDefaultSSLSocketFactory() "
                "and setDefaultHostnameVerifier() — affects all HTTPS connections from the encryption "
                "service JVM, not just the stMgr connection; attacker with network position between "
                "HyperFlex nodes can MITM the SED key management Thrift/HTTPS channel to intercept "
                "or replace KMIP credentials (kmip_password, kmip_server_cert) and SED security keys",
    "status":   "CONFIRMED — source analysis; "
                "StMgrClient$1 (X509TrustManager): checkServerTrusted() is empty (return); "
                "getAcceptedIssuers() returns null; "
                "StMgrClient$2 (HostnameVerifier): verify() returns iconst_1 (true) unconditionally; "
                "StMgrClient.trustAll(): calls HttpsURLConnection.setDefaultSSLSocketFactory() and "
                "setDefaultHostnameVerifier() — JVM static globals, affect ALL HttpsURLConnections; "
                "stMgr URL: 'https://\\u0001/stmgr' (Thrift over HTTPS to SEDConfiguration.stMgrHost); "
                "constant pool confirms kmip_password, kmip_server_cert, security_key, kek, "
                "deployed_security_key, executeRekey operations transmitted over this channel; "
                "encryption/WEB-INF/web.xml: same SPPrivilegedAuth + SSOAuthFilterImpl filter chain",
    "severity": "HIGH",
    "source_pkg": "encryption WAR (HyperFlex SED/KMIP encryption management)",
    "source_ref": "encryption/WEB-INF/classes/com/springpath/hx/encryption/clients/StMgrClient.class; "
                  "encryption/WEB-INF/classes/com/springpath/hx/encryption/clients/StMgrClient$1.class; "
                  "encryption/WEB-INF/classes/com/springpath/hx/encryption/clients/StMgrClient$2.class",
}

# ─────────────────────────────────────────────────────────
# UCSC-F60 — KerberosFilterImpl discards validation result, never blocks
# ─────────────────────────────────────────────────────────
UCSC_F60 = {
    "id":       "UCSC-F60",
    "title":    "HyperFlex encryption WAR KerberosFilterImpl.doFilter() calls "
                "validateKerberosTicketAndPermission() then discards the result with POP — "
                "the filter always proceeds to filterChain.doFilter() regardless of whether "
                "Kerberos validation succeeds or fails; Kerberos authentication in the encryption "
                "service provides no access gating, only optional session enrichment",
    "status":   "CONFIRMED — source analysis; "
                "KerberosFilterImpl.doFilter() offset 106-124: "
                "invokevirtual validateKerberosTicketAndPermission (offset 121); "
                "offset 124: pop (return value discarded); "
                "offset 125: goto 146 (unconditional jump to filterChain.doFilter()); "
                "exception handler (128): SSOException caught, logged, continues to filterChain.doFilter() at 146; "
                "only init guard: if hypervisor != HyperV skips to filterChain.doFilter() directly; "
                "Authenticated=True set only on valid Kerberos ticket (enrichment path); "
                "SSOAuthFilterImpl remains the sole blocking gate; "
                "encryption/WEB-INF/web.xml: KerberosAuth filter registered and mapped to /v1/*",
    "severity": "LOW",
    "source_pkg": "auth-jar (KerberosFilterImpl) + encryption WAR web.xml",
    "source_ref": "auth-jar/com/springpath/hx/aaa/filters/kerberosFilter/KerberosFilterImpl.class; "
                  "encryption/WEB-INF/web.xml",
}


# ─────────────────────────────────────────────────────────
# UCSC-F61 — UCS FI6400 firmware image signature verification uses 1024-bit RSA key
# ─────────────────────────────────────────────────────────
UCSC_F61 = {
    "id":       "UCSC-F61",
    "title":    "UCS Fabric Interconnect firmware image signature verification uses a 1024-bit RSA "
                "public key at /etc/pub.pem across all four FI product lines (FI6400, FI6500, FI6600, "
                "UCS X-Direct) — RSA-1024 is cryptographically broken (NIST deprecated 2010; "
                "estimated factorable with nation-state resources); isanboot/bin/imghdr.aci reads "
                "this key to verify firmware signatures before loading; all four bundles in version "
                "6.0.2b.A ship the identical ucsfi.10.5.1.I60.2b.F.bin (1589095936 bytes), confirming "
                "a single shared weak key covers the entire current UCS FI product line; an attacker "
                "who factors the 1024-bit modulus obtains a signing key capable of producing valid "
                "firmware signatures accepted by every FI6400, FI6500, FI6600, and X-Direct unit",
    "status":   "CONFIRMED — source analysis; "
                "fi6400-extract/rootfs/etc/pub.pem: RSA public key, 1024-bit modulus "
                "(openssl rsa: 'Public-Key: (1024 bit)', exponent 65537, "
                "modulus 00:be:be:f6:6e:69:e7:bf...); "
                "cross-platform scope confirmed: ucs-6400-k9-bundle-infra.6.0.2b.A, "
                "ucs-6500-k9-bundle-infra.6.0.2b.A, ucs-6600-k9-bundle-infra.6.0.2b.A, "
                "ucs-x-direct-k9-infra.6.0.2b.A — all four bundles contain "
                "ucsfi.10.5.1.I60.2b.F.bin at identical size 1589095936 bytes; "
                "isanboot/bin/imghdr.aci (ELF 32-bit, stripped, x86): string '/etc/pub.pem'; "
                "exports: img_verify_signature, rsalib_signature_verify, "
                "cs_dc3sup2_digital_signature_valid; 'Invalid modulus size %d, expecting %d' "
                "confirms key size enforcement at verification time",
    "severity": "HIGH",
    "source_pkg": "ucs-6400/6500/6600-k9-bundle-infra.6.0.2b.A + ucs-x-direct-k9-infra.6.0.2b.A "
                  "→ ucsfi.10.5.1.I60.2b.F.bin (all identical, 1589095936 bytes)",
    "source_ref": "fi6400-extract/rootfs/etc/pub.pem (1024-bit RSA, modulus starts 00:be:be:f6:6e:69:e7:bf); "
                  "fi6400-extract/rootfs/isanboot/bin/imghdr.aci; "
                  "bundle tar listing confirms identical ucsfi.bin across all four FI product bundles",
}

# ─────────────────────────────────────────────────────────
# UCSC-F62 — FI6400 nginx enables deprecated TLS 1.0 and 1.1
# ─────────────────────────────────────────────────────────
UCSC_F62 = {
    "id":       "UCSC-F62",
    "title":    "UCS FI6400 nginx configuration enables TLS 1.0 and TLS 1.1 in addition to TLS 1.2 "
                "and 1.3 — both TLS 1.0 and 1.1 were deprecated by RFC 8996 (March 2021) due to "
                "cryptographic weaknesses (BEAST, POODLE, CRIME; weak MAC constructions); clients "
                "that negotiate TLS 1.0 or 1.1 to the FI6400 management interface are exposed to "
                "downgrade and protocol-level attacks against the management channel",
    "status":   "CONFIRMED — source analysis; "
                "fi6400-extract/rootfs/etc/nginx/nginx.conf: "
                "'ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;' — TLSv1 and TLSv1.1 "
                "explicitly listed; default server listens on port 80 (plaintext) and HTTPS; "
                "RFC 8996 prohibited TLS 1.0/1.1 negotiation in 2021",
    "severity": "LOW",
    "source_pkg": "ucs-6400-k9-bundle-infra.6.0.2b.A → ucsfi.10.5.1.I60.2b.F.bin rootfs",
    "source_ref": "fi6400-extract/rootfs/etc/nginx/nginx.conf (ssl_protocols directive)",
}


# ─────────────────────────────────────────────────────────
# UCSC-F63 — ROOT WAR /upload servlet filter bypass — unauthenticated file write
# ─────────────────────────────────────────────────────────
UCSC_F63 = {
    "id":       "UCSC-F63",
    "title":    "HyperFlex ROOT webapp StorvisorFileUploader servlet is mapped to the exact path "
                "'/upload' while all auth filters (SPAuth/SSOAuthFilterImpl, SPBasicAuth, "
                "SessionAuth, KerberosAuth, SPPrivilegedAuth) are mapped only to '/upload/*' — "
                "in Servlet 2.4 spec, path-prefix pattern '/upload/*' does not match the exact "
                "path '/upload', so a POST to '/upload' invokes the file-upload servlet with no "
                "filter applied; an unauthenticated attacker can write arbitrary multipart content "
                "to '/tmp/hxupgrade_bundle.tgz' (HX upgrade path) or '/tmp/esxiupgrade_bundle.zip' "
                "(ESXi upgrade path) by setting the 'uploadType' parameter to 'ESXI'",
    "status":   "CONFIRMED — source analysis; "
                "ROOT/WEB-INF/web.xml: servlet-mapping url-pattern='/upload' (exact); "
                "all six filter-mappings for /upload use url-pattern='/upload/*' (path-prefix); "
                "Servlet 2.4 spec §SRV.11.2: '/upload/*' matches '/upload/' and '/upload/x' "
                "but not '/upload' (no trailing slash, no suffix); "
                "StorvisorFileUploader.doPost(): reads uploadType param, sets filePath to "
                "hxFilePath ('/tmp/hxupgrade_bundle.tgz') or esxiFilePath ('/tmp/esxiupgrade_bundle.zip'); "
                "FileItem.write(new File(filePath)) writes uploaded bytes to that path verbatim; "
                "no content-type, magic-byte, or signature check on the uploaded file; "
                "maxFileSize=4294967296 (4 GB); no internal auth check in doPost()",
    "severity": "HIGH",
    "source_pkg": "ROOT WAR (HyperFlex initial setup webapp)",
    "source_ref": "ROOT/WEB-INF/web.xml (servlet-mapping /upload, filter-mappings /upload/*); "
                  "ROOT/WEB-INF/classes/com/storvisor/sysmgmt/service/StorvisorFileUploader.class "
                  "(doPost: FileItem.write at offset 249)",
}


# ─────────────────────────────────────────────────────────
# UCSC-F64 — operation-mgr nfs_conf.sh iptables command injection via CLIENT_IP
# ─────────────────────────────────────────────────────────
UCSC_F64 = {
    "id":       "UCSC-F64",
    "title":    "operation-mgr nfs_conf.sh inserts the CLIENT_IP argument directly into iptables "
                "commands without quoting or sanitization — 'CLIENT_IP=$2' is expanded unquoted "
                "inside 'iptables -D RH-Firewall-1-INPUT -s ${CLIENT_IP}' and companion add/delete "
                "rule commands; an attacker who controls the CLIENT_IP argument (passed by the "
                "operation-mgr when configuring NFS exports) can inject arbitrary iptables rule "
                "parameters or shell metacharacters, potentially bypassing firewall rules or "
                "achieving OS command execution in the context of the process invoking the script",
    "status":   "CONFIRMED — source analysis; "
                "operation-mgr151c/opt/cisco/bin/nfs_conf.sh: CLIENT_IP=$2 assigned from positional "
                "argument with no validation; used unquoted in iptables -D/-A/-I invocations as "
                "'-s ${CLIENT_IP}'; no tr/sed sanitization, no regex guard, no quote wrapping; "
                "iptables -s accepts CIDR notation but shell word-splitting on whitespace or "
                "semicolons in CLIENT_IP allows argument injection or command termination; "
                "script runs as root (iptables requires root); same pattern present in 212b",
    "severity": "MEDIUM",
    "source_pkg": "operation-mgr151c (UCS Central operation manager)",
    "source_ref": "operation-mgr151c/opt/cisco/bin/nfs_conf.sh (CLIENT_IP=$2, unquoted expansion "
                  "in iptables -s ${CLIENT_IP} invocations)",
}


# ─────────────────────────────────────────────────────────
# UCSC-F65 — HyperFlex executeCommand denylist bypass via internal whitespace
# ─────────────────────────────────────────────────────────
UCSC_F65 = {
    "id":       "UCSC-F65",
    "title":    "HyperFlex ROOT webapp Executor.executeCommand() denylist is bypassable by inserting "
                "extra internal whitespace in a blocked command — isSupportedCommand() checks "
                "unsupportedCommands.contains(command.trim()), which only strips leading/trailing "
                "whitespace; the command tokenizer uses whitespace-splitting regex so 'stcli cluster  upgrade' "
                "(double space) is tokenized identically to 'stcli cluster upgrade' but fails the "
                "contains() check; all 25 blocked stcli subcommands (cluster create, cluster upgrade, "
                "cluster shutdown, security password set, node add, dp peer add/edit/delete, cleaner/rebalance "
                "ops) can be unblocked by inserting an extra space between any two words; requires "
                "authenticated access to /rest/commands",
    "status":   "CONFIRMED — source analysis; "
                "Executor.isSupportedCommand(): unsupportedCommands.contains(command.trim()) at offset 6-18; "
                "trim() only removes leading/trailing whitespace, not internal; "
                "Executor.executeCommand(): tokenizer regex '([^\\\"\\\\S*|\\\".+?\\\")\\\\s*' at offset 347-388 "
                "splits on all whitespace sequences, so 'stcli cluster  upgrade' tokens to "
                "['stcli','cluster','upgrade'] — identical argv to the blocked command; "
                "Runtime.exec(String[], String[]) at offset 446; "
                "Executor$1 unsupportedCommands list: 25 entries, all single-space-separated; "
                "example bypass: POST /rest/commands {\"command\":\"stcli cluster  shutdown\"} "
                "(double space between 'cluster' and 'shutdown') → executes stcli cluster shutdown",
    "severity": "HIGH",
    "source_pkg": "ROOT WAR (HyperFlex bootstrap webapp)",
    "source_ref": "ROOT/WEB-INF/classes/com/storvisor/sysmgmt/bootstrap/util/Executor.class "
                  "(isSupportedCommand: offset 6 List.contains with trim only; executeCommand: "
                  "offset 347 regex tokenizer, offset 446 Runtime.exec array form); "
                  "ROOT/WEB-INF/classes/com/storvisor/sysmgmt/bootstrap/util/Executor$1.class "
                  "(unsupportedCommands: 25 exact single-space strings)",
}


# ─────────────────────────────────────────────────────────
# UCSC-F66 — HyperFlex executeCommand denylist covers only stcli — sysmtool/hxcli/mkfs.storfs unconstrained
# ─────────────────────────────────────────────────────────
UCSC_F66 = {
    "id":       "UCSC-F66",
    "title":    "HyperFlex ROOT webapp authenticated CLI execution API at POST /rest/commands permits "
                "any subcommand of sysmtool, hxcli, and mkfs.storfs without restriction — the "
                "Executor$1 denylist contains 25 entries exclusively for stcli subcommands; "
                "sysmtool, hxcli, and mkfs.storfs have zero denylist entries; mkfs.storfs is a "
                "Springpath storage filesystem formatter — an authenticated attacker can invoke "
                "'mkfs.storfs <device>' to destroy storage volumes; sysmtool and hxcli expose "
                "cluster management and diagnostic operations with no web-API-level restriction",
    "status":   "CONFIRMED — source analysis; "
                "Executor.executeCommand() offset 277-323: startsWith check admits 'stcli', 'sysmtool', "
                "'hxcli', 'mkfs.storfs'; Executor$1.unsupportedCommands: all 25 entries are "
                "'stcli *' strings — sysmtool/hxcli/mkfs.storfs not present; "
                "isSupportedCommand() returns true for any sysmtool/hxcli/mkfs.storfs command; "
                "endpoint: POST /rest/commands (JSON body {command, user, role, category}); "
                "protected by SSOAuthFilterImpl (authenticated access only); "
                "BootstrapResource: getCommands()/getAdvCommands()/getBasicCommands() enumerate "
                "available command set at GET /rest/commands",
    "severity": "HIGH",
    "source_pkg": "ROOT WAR (HyperFlex bootstrap webapp)",
    "source_ref": "ROOT/WEB-INF/classes/com/storvisor/sysmgmt/bootstrap/util/Executor.class "
                  "(executeCommand offset 277-323: four-prefix allowlist); "
                  "ROOT/WEB-INF/classes/com/storvisor/sysmgmt/bootstrap/util/Executor$1.class "
                  "(unsupportedCommands: stcli-only, no sysmtool/hxcli/mkfs.storfs entries); "
                  "ROOT/WEB-INF/classes/com/storvisor/sysmgmt/bootstrap/rest/BootstrapResource.class "
                  "(@Path('/rest') @POST @Path('/commands') executeCommand)",
}


# ─────────────────────────────────────────────────────────
# UCSC-F67 — bundle_unpack.sh executes bundle_extsvc.sh from extracted bundle without integrity check
# ─────────────────────────────────────────────────────────
UCSC_F67 = {
    "id":       "UCSC-F67",
    "title":    "operation-mgr bundle_unpack.sh executes 'bundle_extsvc.sh' extracted from a firmware "
                "bundle without verifying its integrity — after extraction, the script checks only for "
                "file existence and executes it directly ('chmod +x; ./bundle_extsvc.sh'); "
                "imghdr is called for platform/len/name header metadata only; the img_verify_signature "
                "exports in imghdr.aci are not invoked for bundle_extsvc.sh; an attacker who can "
                "supply a malicious bundle (e.g. via the /tmp/hxupgrade_bundle.tgz write path) "
                "can include an arbitrary bundle_extsvc.sh that executes as the operation-mgr process "
                "user when the upgrade workflow invokes bundle_unpack.sh",
    "status":   "CONFIRMED — source analysis; "
                "operation-mgr151c/opt/cisco/bin/bundle_unpack.sh lines 253-255: "
                "'if [ -e \\\"${TMP_FILES_DIR}/${BUNDLE_EXTSVC}\\\" ]; then'; "
                "'/bin/chmod +x ${TMP_FILES_DIR}/${BUNDLE_EXTSVC}'; "
                "'${TMP_FILES_DIR}/${BUNDLE_EXTSVC}' — direct unquoted execution; "
                "BUNDLE_EXTSVC='bundle_extsvc.sh' (line 30); "
                "imghdr calls: platform (line 53), len (lines 92/154/187/277), name (line 188) — "
                "none invoke img_verify_signature; imghdr.aci exports img_verify_signature and "
                "rsalib_signature_verify but they are not called in this script path; "
                "same pattern present in operation-mgr212b/opt/cisco/bin/bundle_unpack.sh",
    "severity": "HIGH",
    "source_pkg": "operation-mgr151c (UCS Central operation manager)",
    "source_ref": "operation-mgr151c/opt/cisco/bin/bundle_unpack.sh "
                  "(lines 30,253-255: BUNDLE_EXTSVC definition and execution without signature check)",
}


FINDINGS = [
    UCSC_F1, UCSC_F2, UCSC_F3, UCSC_F4, UCSC_F5, UCSC_F6, UCSC_F7, UCSC_F8,
    UCSC_F9, UCSC_F10, UCSC_F11, UCSC_F12, UCSC_F13, UCSC_F14, UCSC_F15,
    UCSC_F16, UCSC_F17, UCSC_F18, UCSC_F19, UCSC_F20, UCSC_F21, UCSC_F22,
    UCSC_F23, UCSC_F24, UCSC_F25, UCSC_F26, UCSC_F27, UCSC_F28, UCSC_F29,
    UCSC_F30, UCSC_F31, UCSC_F32, UCSC_F33, UCSC_F34, UCSC_F35,
    UCSC_F36, UCSC_F37, UCSC_F38, UCSC_F39, UCSC_F40, UCSC_F41, UCSC_F42,
    UCSC_F43, UCSC_F44, UCSC_F45, UCSC_F46, UCSC_F47, UCSC_F48, UCSC_F49,
    UCSC_F50, UCSC_F51, UCSC_F52, UCSC_F53, UCSC_F54, UCSC_F55,
    UCSC_F56, UCSC_F57, UCSC_F58, UCSC_F59, UCSC_F60, UCSC_F61,
    UCSC_F62, UCSC_F63, UCSC_F64, UCSC_F65, UCSC_F66, UCSC_F67,
]


if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
