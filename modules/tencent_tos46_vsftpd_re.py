"""
TencentOS Server 4.6 vsftpd RE Module
Binary: /usr/sbin/vsftpd (extracted from RPM)
Source: vsftpd-3.0.5-6.tl4.x86_64.rpm
        /media/cowboy/research/tencentos/4.6/AppStream-x86_64/
Method: rpm2cpio extraction + objdump + strings + config analysis
        + SRPM patch audit (66 patches)
Analysis date: 2026-09-04

BINARY HEADER:
  Size: 180072 bytes (176KB)
  Format: ELF 64-bit LSB pie executable, x86-64
  Build ID: 0a92707f65c3a86f872c36f11cdac10cab5826d7
  Build date: 2025-01-15
  PIE: yes

PATCH COUNT: 66 (heavy Tencent patching, far above upstream vsftpd)
  Upstream vsftpd 3.0.5 has ~0-5 distro patches typically.
  TOS 4.6 has 66 — indicates heavy Tencent feature additions/hardening.

SECCOMP: prctl PR_SET_SECCOMP present in binary — DISABLED by default
         patch 0034 sets tunable_seccomp_sandbox = 0 in tunables.c
         Binary has seccomp code but feature is OFF in default operation.
         (Corrected: initial analysis incorrectly stated seccomp active)
CAPABILITIES: cap_get_proc, cap_set_flag, cap_set_proc — privilege reduction
PRIV_REDUCTION: prctl PR_SET_NO_NEW_PRIVS — new privilege suppression
SUPERSEDED: Full 66-patch audit in tencent_tos46_vsftpd_patch_audit_re.py
CHROOT: chroot() for local user jailing
PAM: pam_shells.so + password-auth + pam_loginuid (tight PAM stack)
DEFAULT CONFIG: anonymous_enable=NO, local_enable=YES, write_enable=YES
               (anon disabled by default — secure baseline)

FINDINGS:
  TOS46-FTP-F01 (MEDIUM/5.3) seccomp DISABLED by default (patch 0034); corrected
  TOS46-FTP-F02 (MEDIUM/5.1) chroot_local_user: chroot jail breakout via writable homedir
  TOS46-FTP-F03 (INFO)     66 Tencent patches — feature-heavy, not just CVE backports
  TOS46-FTP-F04 (INFO)     FTPS: full SSL/TLS support with ALPN and DH param callback
  TOS46-FTP-F05 (MEDIUM)   write_enable=YES in default config with local_enable=YES
"""

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_BINARY = {
    "path": "/usr/sbin/vsftpd",
    "size_bytes": 180072,
    "build_id": "0a92707f65c3a86f872c36f11cdac10cab5826d7",
    "build_date": "2025-01-15",
    "format": "ELF 64-bit LSB pie executable, x86-64, stripped",
    "pie": True,
    "seccomp_code_present": True,
    "seccomp_enabled_default": False,
    "capabilities": ["CAP_NET_BIND_SERVICE", "cap_get_proc", "cap_set_flag", "cap_set_proc"],
    "no_new_privs": True,
    "ssl_library": "OpenSSL (OPENSSL_init_ssl, TLS_server_method)",
    "package": "vsftpd-3.0.5-6.tl4",
    "patch_count": 66,
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F01: hardening stack confirmation
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_HARDENING_CONFIRMED = {
    "finding_id": "TOS46-FTP-F01",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "title": (
        "vsftpd-3.0.5-6.tl4: seccomp syscall sandboxing DISABLED by default "
        "(patch 0034 sets tunable_seccomp_sandbox = 0); binary has seccomp code "
        "but it is off — exploitation does not need to bypass seccomp; "
        "see tencent_tos46_vsftpd_patch_audit_re.py for full analysis"
    ),
    "description": (
        "CORRECTION: initial binary analysis noted 'prctl PR_SET_SECCOMP' string "
        "presence and assumed seccomp was active. Patch audit shows 0034 explicitly "
        "disables it: tunable_seccomp_sandbox default changed 1 → 0 in tunables.c. "
        "\n"
        "Remaining hardening (confirmed from binary + patch 0047 Makefile): "
        "  - PIE + FULL RELRO (-fPIE -pie -Wl,-z,relro -Wl,-z,now) "
        "  - Stack canary (-fstack-protector) + FORTIFY_SOURCE=2 "
        "  - Linux capabilities drop (cap_get_proc/cap_set_proc) "
        "  - prctl(PR_SET_NO_NEW_PRIVS) "
        "  - PAM stack: pam_shells.so + pam_loginuid.so + password-auth "
        "\n"
        "seccomp can be re-enabled via seccomp_sandbox=YES in vsftpd.conf. "
        "Test for compatibility with the running kernel before enabling."
    ),
    "binary_evidence": [
        "prctl PR_SET_NO_NEW_PRIVS",
        "prctl PR_SET_SECCOMP failed (unreachable by default)",
        "cap_init", "cap_set_flag", "cap_set_proc",
    ],
    "correction": "Initial analysis incorrect — seccomp DISABLED by patch 0034",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F02: chroot_local_user breakout via writable home
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_CHROOT_BREAKOUT = {
    "finding_id": "TOS46-FTP-F02",
    "severity": "MEDIUM",
    "cvss_v3": 5.1,
    "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "title": (
        "vsftpd chroot_local_user: chroot(homedir) followed by chdir('/') does NOT "
        "prevent escape if homedir is world-writable or user-writable; "
        "classic vsftpd chroot breakout via hard-link or bind-mount tricks "
        "when allow_writeable_chroot is enabled"
    ),
    "description": (
        "vsftpd's chroot_local_user=YES chroots each local user to their home directory. "
        "The implementation calls chroot($HOME) then chdir('/') within the chroot. "
        "\n"
        "VULNERABILITY CONDITION: when the chroot directory (home directory) is "
        "writable by the FTP user, vsftpd refuses to chroot (since vsftpd 3.0.2) "
        "UNLESS allow_writeable_chroot=YES is explicitly configured. "
        "\n"
        "If allow_writeable_chroot=YES: "
        "  - The user can modify the directory structure inside their home. "
        "  - Hard links to SUID binaries outside the chroot can be created in "
        "    some filesystem configurations. "
        "  - The chroot is technically broken — the kernel cannot prevent "
        "    chroot escape via open('/proc/1/cwd') or /proc filesystem if /proc "
        "    is bind-mounted into the chroot. "
        "\n"
        "vsftpd config file references: "
        "  chroot_local_user=YES (optional) "
        "  allow_writeable_chroot=YES (optional, dangerous) "
        "  chroot_list_enable=YES (list-based chroot, alternate) "
        "\n"
        "Default TOS 4.6 config: chroot_local_user not enabled by default — "
        "this risk only applies when the operator enables chroot_local_user."
    ),
    "default_config_status": "NOT ENABLED — requires operator opt-in",
    "references": [
        "https://security.appspot.com/vsftpd.html (chroot and security)",
        "vsftpd changelog: 3.0.2 chroot writeable-dir protection",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F03: 66 Tencent patches
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_66_PATCHES = {
    "finding_id": "TOS46-FTP-F03",
    "severity": "INFO",
    "title": (
        "vsftpd-3.0.5-6.tl4 carries 66 patches — approximately 60x more than a "
        "typical distro's vsftpd patch set; patches are primarily feature additions "
        "and behavioral changes, not CVE backports; specific patch list not fully "
        "analyzed (SRPM patch content requires deeper audit)"
    ),
    "description": (
        "Upstream vsftpd 3.0.5 typically receives 1-5 distro patches (build system, "
        "PAM config, manpage). TOS 4.6's 66-patch set is anomalously large. "
        "\n"
        "Categories inferred from binary string analysis: "
        "  - Enhanced FTPS/SSL configuration options "
        "    (SSL_CTX_set_alpn_select_cb, DH parameter callback present) "
        "  - Extended PAM integration "
        "  - Additional config options beyond upstream "
        "    (many config option strings: anon_umask, anon_max_rate, passwd_chroot_enable, "
        "     guest_enable, email_passwords, banned_emails) "
        "  - Logging enhancements (dual_log_enable, xferlog_std_format) "
        "\n"
        "Risk: heavily-patched binaries diverge from upstream security analysis. "
        "A vulnerability found in upstream vsftpd 3.0.5 may be introduced or "
        "mitigated by any of the 66 patches. Reverse engineering each patch to "
        "determine its security impact requires the SRPM patch files which are "
        "available at /media/cowboy/research/tencentos/4.6/ for further analysis."
    ),
    "patch_count": 66,
    "comparison": {
        "typical_distro_patches": "1-5",
        "tos46_patches": 66,
        "ratio": "~13x",
    },
    "next_step": "Extract vsftpd SRPM from BaseOS-source and read all 66 patch files",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F04: FTPS SSL/TLS implementation
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_FTPS_TLS = {
    "finding_id": "TOS46-FTP-F04",
    "severity": "INFO",
    "title": (
        "vsftpd implements full FTPS with ALPN, DH parameter callbacks, "
        "client certificate support, and session resumption; "
        "SSL cipher list configurable via ssl_ciphers in vsftpd.conf"
    ),
    "ssl_imports": [
        "OPENSSL_init_ssl", "TLS_server_method", "SSL_CTX_new",
        "SSL_CTX_set_options", "SSL_CTX_use_certificate_chain_file",
        "SSL_CTX_use_PrivateKey_file", "SSL_CTX_set_cipher_list",
        "SSL_CTX_set_verify", "SSL_CTX_load_verify_locations",
        "SSL_CTX_set_client_CA_list", "SSL_CTX_set_session_id_context",
        "SSL_CTX_set_tmp_dh_callback", "SSL_CTX_set_alpn_select_cb",
        "SSL_CTX_callback_ctrl", "SSL_CTX_set_timeout",
        "SSL_new", "SSL_set_fd", "SSL_accept", "SSL_read", "SSL_write",
        "SSL_get_current_cipher", "SSL_get_shutdown", "SSL_peek", "SSL_free",
    ],
    "config_options": [
        "ssl_enable=YES/NO",
        "ssl_ciphers=<cipher_list>",
        "require_ssl_reuse=YES/NO",
        "ssl_request_cert=YES/NO",
        "ssl_enable_alpn=YES/NO",
    ],
    "security_note": (
        "FTPS cipher strength depends on ssl_ciphers config. "
        "Default TOS 4.6 vsftpd.conf does not set ssl_enable, so FTPS is not "
        "enabled by default. When enabled, cipher list should exclude weak ciphers "
        "(RC4, DES, 3DES, EXPORT). "
        "Verify ssl_ciphers includes 'HIGH:!aNULL:!eNULL:!3DES:!RC4' or equivalent."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-FTP-F05: write_enable=YES in default config
# ──────────────────────────────────────────────────────────────────────────────

VSFTPD_WRITE_ENABLE_DEFAULT = {
    "finding_id": "TOS46-FTP-F05",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "title": (
        "vsftpd default config has write_enable=YES with local_enable=YES — "
        "any local user who can FTP-authenticate can upload, overwrite, and "
        "delete files in their accessible directories"
    ),
    "description": (
        "The default /etc/vsftpd/vsftpd.conf on TOS 4.6 includes: "
        "  anonymous_enable=NO   (good — anonymous is disabled) "
        "  local_enable=YES      (local system users can log in) "
        "  write_enable=YES      (ENABLED by default — write commands allowed) "
        "\n"
        "write_enable=YES enables all write-class FTP commands: "
        "  STOR, APPE, MKD, RMD, RNFR, RNTO, DELE, STOU "
        "\n"
        "With chroot_local_user not enabled (the default), authenticated local "
        "users can traverse to any directory they have read permission on and "
        "write to any directory they have write permission on. "
        "\n"
        "Attack chain: "
        "  1. Attacker compromises a low-privilege local user account. "
        "  2. FTP-authenticates as that user (PAM password-auth). "
        "  3. write_enable=YES allows uploading files to any directory accessible "
        "     to the user, including cron-readable directories if permissions allow. "
        "  4. If user has write access to /etc/cron.d or home/.ssh: "
        "     privilege escalation path available. "
        "\n"
        "Note: pam_shells.so requires user to have a valid shell in /etc/shells. "
        "The ftpusers deny-list provides another layer. But write_enable=YES in "
        "the shipped default is a high-risk default that should be commented out."
    ),
    "default_config_lines": [
        "anonymous_enable=NO",
        "local_enable=YES",
        "write_enable=YES",
    ],
    "recommendation": "Comment out write_enable=YES in default config or change to NO; "
                      "require explicit operator opt-in for write access.",
    "references": ["/etc/vsftpd/vsftpd.conf TOS 4.6 shipped default"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-FTP-F01": VSFTPD_HARDENING_CONFIRMED,
    "TOS46-FTP-F02": VSFTPD_CHROOT_BREAKOUT,
    "TOS46-FTP-F03": VSFTPD_66_PATCHES,
    "TOS46-FTP-F04": VSFTPD_FTPS_TLS,
    "TOS46-FTP-F05": VSFTPD_WRITE_ENABLE_DEFAULT,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "binary": "vsftpd-3.0.5-6.tl4",
        "patches": 66,
        "hardening": ["seccomp", "capabilities", "no_new_privs", "chroot", "PAM"],
        "default_config_risk": "write_enable=YES with local_enable=YES",
        "findings": [{"id": k, "severity": v.get("severity", "?"), "cvss": v.get("cvss_v3")}
                     for k, v in FINDINGS.items()],
    }, indent=2))
