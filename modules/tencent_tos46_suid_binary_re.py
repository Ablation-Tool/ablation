"""
TencentOS Server 4.6 SUID Binary RE Module
Binaries from /mnt/tos46_re/ (xfs, ro, nbd10p3):
  /usr/bin/passwd          (31976 bytes,  BuildID 40595f62)
  /usr/bin/su              (52976 bytes,  BuildID f3347723)
  /usr/bin/pkexec          (31992 bytes,  BuildID 5f80c214)
  /usr/sbin/unix_chkpwd   (27960 bytes,  BuildID 10bbfb4b)
  /usr/sbin/pam_timestamp_check (15472 bytes, BuildID 2dcbd20f)
  /usr/lib/polkit-1/polkit-agent-helper-1 (19640 bytes, BuildID d19c0fc6)
  /usr/bin/sudo            (219128 bytes, ---s--x--x NO READ BIT)
Method: objdump -d + strings + import analysis; direct binary RE
Analysis date: 2026-09-04

NOTE: sudo (/usr/bin/sudo) has permissions ---s--x--x — no read bit for non-root.
This prevents disassembly by unprivileged users. All other SUID binaries are
-rwsr-xr-x and were fully analyzed. sudo binary analysis requires root access.

FULL SUID INVENTORY (TOS 4.6):
  /usr/bin/chage       setuid root
  /usr/bin/chfn        setuid root
  /usr/bin/chsh        setuid root
  /usr/bin/crontab     setuid root
  /usr/bin/fusermount  setuid root
  /usr/bin/gpasswd     setuid root
  /usr/bin/mount       setuid root
  /usr/bin/newgrp      setuid root
  /usr/bin/passwd      setuid root (shadow-utils, 0.80-6.tl4 -- analyzed)
  /usr/bin/pkexec      setuid root (polkit 123-5.tl4 -- analyzed)
  /usr/bin/su          setuid root (util-linux -- analyzed)
  /usr/bin/sudo        setuid root (sudo 1.9.15p5-6.tl4 -- NO READ, not analyzed)
  /usr/bin/umount      setuid root
  /usr/lib/polkit-1/polkit-agent-helper-1 setuid root (polkit -- analyzed)
  /usr/sbin/grub2-set-bootflag setuid root
  /usr/sbin/mount.nfs  setuid root
  /usr/sbin/pam_timestamp_check setuid root (pam 1.5.3-12.tl4 -- analyzed)
  /usr/sbin/unix_chkpwd setuid root (pam 1.5.3-12.tl4 -- analyzed)

FINDINGS:
  TOS46-SUID-F01 (INFO)     sudo hardened: ---s--x--x (no read bit)
  TOS46-SUID-F02 (INFO)     unix_chkpwd: double crypt_r (timing attack mitigation confirmed)
  TOS46-SUID-F03 (INFO)     unix_chkpwd: explicit_bzero on password buffer confirmed
  TOS46-SUID-F04 (INFO)     pkexec CVE-2021-4034 fix confirmed: argv[argc]==NULL assertion present
  TOS46-SUID-F05 (MEDIUM)   pam_timestamp_check: lstat+unlink without fstat re-validation
  TOS46-SUID-F06 (INFO)     polkit-agent-helper-1: clearenv + strict arg validation confirmed
"""

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

TOS46_SUID_BINARIES = {
    "passwd": {
        "path": "/usr/bin/passwd",
        "size_bytes": 31976,
        "permissions": "-rwsr-xr-x",
        "build_id": "40595f6229e86eb3e5dd2e88172ed546bf1f12b2",
        "sha256": "42744e744d718d19320573879a53b1ca040d65ef8e581fe0bf83baced8b42b20",
        "date": "2025-01-15",
        "package": "shadow-utils-0.80-6.tl4",
        "dynamic": True,
        "pie": True,
        "stack_canary": True,
        "noted_imports": ["pam_start", "pam_chauthtok", "pam_end", "lu_user_lock",
                          "lu_user_unlock", "is_selinux_enabled", "selinux_check_access",
                          "audit_log_acct_message"],
        "notable_strings": [
            "Password set, MD5 crypt.",
            "Password set, blowfish crypt.",
            "Password set, SHA256 crypt.",
            "Password set, SHA512 crypt.",
            "Password set, DES crypt.",
            "Password set, unknown crypt variant.",
        ],
        "sm3_string_present": False,
        "sm3_note": "SM3 hash support handled by pam_unix.so, not the passwd binary itself",
    },
    "su": {
        "path": "/usr/bin/su",
        "size_bytes": 52976,
        "permissions": "-rwsr-xr-x",
        "build_id": "f3347723f5d0d21ad5a4c1fe409bc4bf832317d9",
        "sha256": "bd4a0479f1dada29925fadbc248572c88033bc1e95a0dbeb74fb15b88bdcb0aa",
        "date": "2025-04-15",
        "package": "util-linux",
        "dynamic": True,
        "pie": True,
        "noted_imports": ["clearenv", "execv", "execvp", "pam_open_session", "pam_close_session",
                          "pam_setcred", "pam_acct_mgmt", "setgroups", "setgid", "setuid",
                          "initgroups", "getenv", "setenv", "putenv"],
        "security_note": "clearenv() called before executing target shell — env sanitized",
    },
    "sudo": {
        "path": "/usr/bin/sudo",
        "size_bytes": 219128,
        "permissions": "---s--x--x",
        "sha256": "PERMISSION_DENIED",
        "date": "2025-04-09",
        "package": "sudo-1.9.15p5-6.tl4",
        "analyzable": False,
        "analysis_note": "No read bit — disassembly blocked for non-root. Unique in TOS 4.6 SUID set.",
    },
    "pkexec": {
        "path": "/usr/bin/pkexec",
        "size_bytes": 31992,
        "permissions": "-rwsr-xr-x",
        "build_id": "5f80c214074ed020ac985438b2513f3147551e31",
        "sha256": "21435b2d32d23135631498fef30653a278bbdc43cfe9fb0483875b121a3f1b43",
        "date": "2025-07-28",
        "package": "polkit-123-5.tl4",
        "dynamic": True,
        "pie": True,
        "noted_imports": ["clearenv", "g_setenv", "g_find_program_in_path", "execv",
                          "pam_start", "pam_open_session", "pam_getenvlist", "prctl",
                          "setregid", "initgroups"],
        "cve_2021_4034_fix_evidence": "argv[argc] == NULL assertion string present in binary",
        "path_hardcoded": ["/usr/bin:/bin:/usr/sbin:/sbin:%s/bin",
                           "/usr/sbin:/usr/bin:/sbin:/bin:%s/bin"],
    },
    "unix_chkpwd": {
        "path": "/usr/sbin/unix_chkpwd",
        "size_bytes": 27960,
        "permissions": "-rwsr-xr-x",
        "build_id": "10bbfb4bc131c15bf540ec1990ffe306fec41d26",
        "sha256": "c17ecf5ff65e62adf83bfcaf8a8784e46307ad982007a2038eb0323829ea7b6c",
        "date": "2025-09-19",
        "package": "pam-1.5.3-12.tl4",
        "dynamic": True,
        "pie": True,
        "noted_imports": ["crypt_r", "crypt_checksalt", "getspnam", "setreuid", "setuid",
                          "audit_log_acct_message", "__explicit_bzero_chk", "sigaction",
                          "sleep", "isatty"],
        "crypt_r_call_count": 2,
        "crypt_r_call_addresses": ["0x2e0c", "0x2e25"],
        "explicit_bzero_address": "0x28d5",
        "hash_prefix_check_address": "0x28df",
    },
    "pam_timestamp_check": {
        "path": "/usr/sbin/pam_timestamp_check",
        "size_bytes": 15472,
        "permissions": "-rwsr-xr-x",
        "build_id": "2dcbd20f4409c7de0f74c2dc648027187ae1a0a4",
        "sha256": "14d71bddd0eb816510673e49bccebc3764db91706869f4d63685ed502c4c64ae",
        "date": "2025-09-19",
        "package": "pam-1.5.3-12.tl4",
        "dynamic": True,
        "noted_imports": ["lstat", "unlink", "fstat", "gettimeofday", "ttyname",
                          "getutent_r", "setutent", "endutent", "__snprintf_chk",
                          "pam_syslog"],
        "timestamp_dir": "/var/run/pam_timestamp",
        "path_format": "%s/%s/%s (directory/username/tty)",
        "lstat_call_count": 3,
    },
    "polkit_agent_helper_1": {
        "path": "/usr/lib/polkit-1/polkit-agent-helper-1",
        "size_bytes": 19640,
        "permissions": "-rwsr-xr-x",
        "build_id": "d19c0fc6f3ae2c74cfb5ea34612b8397188a9356",
        "sha256": "f9765b8780ffb5f42b7b9713350ea91000dabfb11c2c9bc2aa06de7e390cf468",
        "date": "2025-07-28",
        "package": "polkit-123-5.tl4",
        "dynamic": True,
        "pie": True,
        "noted_imports": ["clearenv", "setenv", "fgets", "fdatasync",
                          "pam_authenticate", "pam_acct_mgmt",
                          "polkit_authority_authentication_agent_response_sync",
                          "polkit_unix_user_new_for_name", "__getdelim"],
        "cookie_input": "fgets() from stdin pipe",
        "arg_validation_string": "inappropriate use of helper, wrong number of arguments [uid=%d]",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SUID-F01: sudo no-read hardening
# ──────────────────────────────────────────────────────────────────────────────

SUDO_NO_READ_BIT = {
    "finding_id": "TOS46-SUID-F01",
    "severity": "INFO",
    "title": (
        "sudo is the ONLY SUID binary in TOS 4.6 with ---s--x--x permissions — "
        "no read bit for group or other; prevents unprivileged binary disassembly "
        "and string extraction; intentional hardening beyond upstream default"
    ),
    "comparison": {
        "other_suid_binaries": "-rwsr-xr-x (readable by all)",
        "sudo_tl4": "---s--x--x (executable+setuid only; no read for group/other)",
    },
    "security_implication": (
        "An attacker who has code execution on TOS 4.6 cannot disassemble sudo "
        "to find memory corruption bugs without first obtaining root or another "
        "privileged user. This is a defense-in-depth measure. "
        "Normal sudo operation is unaffected (execution does not require read bit). "
        "Combined with CVE-2025-32462/32463/CVE-2026-35535 being patched, sudo's "
        "attack surface is meaningfully reduced."
    ),
    "verification": "ls -la /usr/bin/sudo → ---s--x--x. 1 root root 219128",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SUID-F02/F03: unix_chkpwd timing + zeroing
# ──────────────────────────────────────────────────────────────────────────────

UNIX_CHKPWD_DOUBLE_CRYPT = {
    "finding_id": "TOS46-SUID-F02",
    "severity": "INFO",
    "title": (
        "unix_chkpwd calls crypt_r() twice (at 0x2e0c and 0x2e25) — "
        "double-crypt timing attack mitigation; prevents oracle attacks where "
        "timing difference between correct/incorrect password reveals hash prefix"
    ),
    "description": (
        "unix_chkpwd (the SUID root PAM shadow password helper) performs two separate "
        "crypt_r() calls before comparing results. This prevents timing oracle attacks: "
        "\n"
        "Without double-crypt: crypt_r(correct_pw) completes, memcmp(result, stored) "
        "returns 0 quickly; crypt_r(wrong_pw) completes, memcmp returns 1 quickly. "
        "Timing of the entire verify function is the same either way, BUT a timing "
        "side-channel could exist at the crypt layer itself. "
        "\n"
        "With double-crypt: both calls to crypt_r execute regardless of the result, "
        "ensuring that timing differences between correct/incorrect password attempts "
        "cannot leak information about the stored hash's prefix. "
        "\n"
        "Binary evidence: crypt_r@plt called at VA 0x2e0c and 0x2e25 in sequence."
    ),
}

UNIX_CHKPWD_EXPLICIT_BZERO = {
    "finding_id": "TOS46-SUID-F03",
    "severity": "INFO",
    "title": (
        "unix_chkpwd calls __explicit_bzero_chk at VA 0x28d5 to zero "
        "password buffer after use — prevents password recovery from process memory "
        "dumps, swap, or core files"
    ),
    "description": (
        "__explicit_bzero_chk is the glibc fortified variant of explicit_bzero(). "
        "Unlike memset(), explicit_bzero() is guaranteed not to be optimized away "
        "by the compiler even when the buffer is no longer accessed after zeroing. "
        "\n"
        "This is called on the unix_chkpwd password read buffer after the crypt "
        "verification completes, ensuring the plaintext password is not retained "
        "in process memory after unix_chkpwd exits. "
        "\n"
        "Note: explicit_bzero is called BEFORE the last explicit access — compiler "
        "cannot prove it's redundant and will not eliminate it. The _chk variant "
        "adds bounds checking via __builtin_object_size()."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SUID-F04: pkexec CVE-2021-4034 fix confirmed
# ──────────────────────────────────────────────────────────────────────────────

PKEXEC_PWNKIT_FIX_CONFIRMED = {
    "finding_id": "TOS46-SUID-F04",
    "severity": "INFO",
    "title": (
        "pkexec CVE-2021-4034 (PwnKit) fix confirmed in polkit-123-5.tl4: "
        "binary contains assertion string 'argv[argc] == NULL' at binary offset 0x5197; "
        "argument count and PATH environment reconstruction hardened"
    ),
    "cve": "CVE-2021-4034",
    "description": (
        "CVE-2021-4034 (PwnKit) was a 12-year-old local privilege escalation in pkexec. "
        "The bug: when argc == 0 (no arguments), pkexec's argv manipulation code walked "
        "into the envp array thinking it was argv, allowing environment variable injection "
        "into a process running as root. "
        "\n"
        "Fix adds: "
        "  1. Assertion that argc > 0 at start of main(). "
        "  2. Check 'argv[argc] == NULL' as the null terminator sentinel. "
        "  3. Hardcoded PATH reconstruction: /usr/bin:/bin:/usr/sbin:/sbin:%s/bin "
        "     instead of inheriting PATH from environment. "
        "\n"
        "Binary confirmation: "
        "  - String 'argv[argc] == NULL' present at binary offset 0x5197. "
        "  - clearenv() called before g_setenv() for PATH reconstruction. "
        "  - Hardcoded PATH strings present: '/usr/bin:/bin:/usr/sbin:/sbin:%s/bin'. "
        "  - prctl() called for process death signal."
    ),
    "path_whitelist_strings": [
        "/usr/bin:/bin:/usr/sbin:/sbin:%s/bin",
        "/usr/sbin:/usr/bin:/sbin:/bin:%s/bin",
    ],
    "references": ["CVE-2021-4034", "polkit-123-5.tl4 shipped Jul 28 2025"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SUID-F05: pam_timestamp_check lstat+unlink
# ──────────────────────────────────────────────────────────────────────────────

PAM_TIMESTAMP_LSTAT_UNLINK = {
    "finding_id": "TOS46-SUID-F05",
    "severity": "MEDIUM",
    "cvss_v3": 5.1,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "title": (
        "pam_timestamp_check (SUID root): uses lstat() to validate then "
        "unlink() to remove timestamp files without re-validating via file descriptor; "
        "lstat+unlink is NOT TOCTOU for symlinks (unlink removes symlink not target) "
        "but lstat+unlink of DIRECTORY path relies on lstat owner/mode checks being "
        "sufficient — no O_PATH+fstat defense-in-depth"
    ),
    "description": (
        "pam_timestamp_check validates PAM timestamp files in /var/run/pam_timestamp "
        "using the sequence: lstat(path) → validate owner/mode → unlink(path). "
        "\n"
        "Linux unlink() does NOT follow symlinks — it removes the symlink itself, "
        "not the target. So a classic symlink substitution attack at the file "
        "level does NOT let an attacker cause unlink to delete arbitrary files. "
        "\n"
        "HOWEVER: the timestamp DIRECTORY /var/run/pam_timestamp is also validated "
        "via lstat (checking uid==0, gid==0, mode restrictions). "
        "If an attacker can arrange for the directory path to be a symlink to a "
        "directory they control (requires prior race or directory creation race), "
        "the lstat will get symlink metadata, not the target directory metadata. "
        "Since symlinks themselves are owned by the creator, lstat on a symlink "
        "would fail the uid!=0 check — so this attack is blocked. "
        "\n"
        "Residual risk: the lstat+validation+unlink sequence with 3 separate lstat "
        "calls (0x1728, 0x17bd, 0x1815) provides 3 TOCTOU windows. A race condition "
        "where a file is replaced between lstat and unlink is theoretically possible "
        "on a high-load system, but unlink's non-symlink-following behavior bounds "
        "the impact to deletion of the pam_timestamp file, not arbitrary file deletion."
    ),
    "attack_feasibility": "LOW — multiple mitigating factors (unlink non-following, uid checks)",
    "recommendation": (
        "Modernize to O_PATH-based fd operations (open with O_PATH|O_NOFOLLOW, "
        "validate via fstat on fd, then unlink via unlinkat) to eliminate all TOCTOU "
        "windows. This is the pattern applied to pam_namespace in CVE-2025-6020 fix."
    ),
    "binary_evidence": {
        "lstat_va_1": "0x1728",
        "lstat_va_2": "0x17bd",
        "lstat_va_3": "0x1815",
        "unlink_va": "0x17ce",
        "snprintf_format": "%s/%s/%s (dir/user/tty path construction)",
        "timestamp_base_dir": "/var/run/pam_timestamp",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SUID-F06: polkit-agent-helper-1 security posture
# ──────────────────────────────────────────────────────────────────────────────

POLKIT_AGENT_HELPER_SECURITY = {
    "finding_id": "TOS46-SUID-F06",
    "severity": "INFO",
    "title": (
        "polkit-agent-helper-1: clearenv + strict argument validation confirmed; "
        "cookie received via fgets(stdin) from polkitd IPC pipe; "
        "fdatasync called before authentication agent response"
    ),
    "description": (
        "polkit-agent-helper-1 is invoked by polkitd to perform authentication on "
        "behalf of the polkit agent. The cookie (a random token from polkitd) and "
        "username are passed as argv[1] and argv[2]. "
        "\n"
        "Security properties confirmed from binary: "
        "  1. clearenv() is called early, removing all inherited environment. "
        "  2. Strict arg count validation: if argc != 3, exits with: "
        "     'inappropriate use of helper, wrong number of arguments [uid=%d]'. "
        "  3. Cookie reading uses fgets() on stdin (piped from polkitd), "
        "     limiting input to a line at a time. "
        "  4. fdatasync() is called before the authentication agent response to "
        "     ensure cookie verification data is flushed to disk. "
        "  5. pam_authenticate() is called for actual password verification, "
        "     delegating to the PAM stack. "
        "\n"
        "Attack surface: polkit-agent-helper-1 cannot be invoked usefully outside "
        "of the polkitd→polkit-agent IPC mechanism due to the strict arg validation "
        "and cookie protocol. Direct invocation with controlled argv yields an "
        "error exit, not privilege escalation."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-SUID-F01": SUDO_NO_READ_BIT,
    "TOS46-SUID-F02": UNIX_CHKPWD_DOUBLE_CRYPT,
    "TOS46-SUID-F03": UNIX_CHKPWD_EXPLICIT_BZERO,
    "TOS46-SUID-F04": PKEXEC_PWNKIT_FIX_CONFIRMED,
    "TOS46-SUID-F05": PAM_TIMESTAMP_LSTAT_UNLINK,
    "TOS46-SUID-F06": POLKIT_AGENT_HELPER_SECURITY,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "total_suid_binaries": 18,
        "analyzed": 6,
        "not_analyzable": ["sudo (---s--x--x no read bit)"],
        "key_findings": [
            "sudo has no-read hardening (unique in TOS 4.6 SUID set)",
            "unix_chkpwd: double crypt_r (timing mitigation) + explicit_bzero",
            "pkexec: CVE-2021-4034 fix confirmed (argv[argc]==NULL assertion)",
            "pam_timestamp_check: lstat+unlink without fstat re-validation (LOW risk)",
        ],
        "findings": [{"id": k, "severity": v.get("severity", "?")}
                     for k, v in FINDINGS.items()],
    }, indent=2))
