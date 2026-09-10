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

FINDINGS = [UCSC_F1, UCSC_F2, UCSC_F3, UCSC_F4, UCSC_F5]
