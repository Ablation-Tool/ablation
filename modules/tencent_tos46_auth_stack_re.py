"""
TencentOS Server 4.6 Authentication Stack RE Module
Packages: pam-1.5.3-12.tl4, sudo-1.9.15p5-5/6.tl4, polkit-123-5.tl4,
          shadow-utils-4.14.3-4/5.tl4, passwd-0.80-6.tl4
Source: /media/cowboy/research/tencentos/4.6/BaseOS-source/
Method: rpm2cpio extraction + patch audit + spec changelog analysis
        + binary analysis from /mnt/tos46_re/
Analysis date: 2026-09-04

SUID BINARY INVENTORY (from /mnt/tos46_re/):
  /usr/bin/passwd      setuid root (shadow-utils passwd)
  /usr/bin/su          setuid root (util-linux su)
  /usr/bin/chage       setuid root
  /usr/bin/gpasswd     setuid root
  /usr/bin/newgrp      setuid root
  /usr/bin/chfn        setuid root
  /usr/bin/chsh        setuid root
  /usr/bin/sudo        setuid root
  /usr/bin/pkexec      setuid root (polkit)
  /usr/sbin/unix_chkpwd setuid root (PAM shadow helper)
  /usr/sbin/pam_timestamp_check setuid root
  /usr/lib/polkit-1/polkit-agent-helper-1 setuid root

TENCENT-SPECIFIC ADDITIONS:
  - SM3 password hashing support added to PAM, shadow-utils (zoedong, gordonwwang @tencent.com)
    crypt prefix: $sm3$ — NOT present in upstream linux-pam or shadow-utils
  - pam_access: wynnfeng @tencent.com authored CVE-2024-10963 patch

VERSION LADDERS:
  pam:          1.5.3-1 (Aug 2023) → 1.5.3-12 (Sep 2025); 12 counters
  sudo:         1.9.15p5-5 → 1.9.15p5-6; 2 counters
  polkit:       123-5.tl4; single version analyzed
  shadow-utils: 4.14.3-4 → 4.14.3-5; 2 counters
  passwd:       0.80-6.tl4; no CVE patches

FINDINGS:
  TOS46-AUTH-F01 (HIGH/7.8)    pam_namespace: mount-ns race condition privesc (CVE-2025-6020)
  TOS46-AUTH-F02 (MEDIUM/6.3)  pam_access: hostname resolution bypass (CVE-2024-10963)
  TOS46-AUTH-F03 (MEDIUM/5.5)  pam_namespace: FIFO DoS in protect_dir (CVE-2024-22365)
  TOS46-AUTH-F04 (MEDIUM/5.3)  pam_unix: shadow helper always called (CVE-2024-10041)
  TOS46-AUTH-F05 (HIGH/8.8)    sudo: remote host bypass in privilege check (CVE-2025-32462)
  TOS46-AUTH-F06 (HIGH/7.8)    sudo: filesystem pivot via pivot.c removed (CVE-2025-32463)
  TOS46-AUTH-F07 (MEDIUM/6.1)  sudo: mailer gid not dropped before exec (CVE-2026-35535)
  TOS46-AUTH-F08 (MEDIUM/5.9)  polkit: nested .policy XML stack overflow crash (CVE-2025-7519)
  TOS46-AUTH-F09 (INFO)        SM3 password hashing in PAM + shadow-utils (Tencent extension)
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

AUTH_PACKAGE_INVENTORY = {
    "pam": {
        "version": "1.5.3-12.tl4",
        "patches": 35,
        "cve_patches": ["CVE-2024-22365", "CVE-2024-10963", "CVE-2024-10041",
                        "CVE-2025-6020 (3-part)"],
        "tencent_patches": ["add-sm3-support.patch"],
        "suid_binaries": ["/usr/sbin/unix_chkpwd", "/usr/sbin/pam_timestamp_check"],
        "changelog_first": "1.5.2-1 (May 2022)",
        "changelog_last": "1.5.3-12 (Sep 2025)",
    },
    "sudo": {
        "versions": ["1.9.15p5-5.tl4", "1.9.15p5-6.tl4"],
        "cve_patches": ["CVE-2025-32462", "CVE-2025-32463", "CVE-2026-35535 (v6 only)"],
        "suid_binaries": ["/usr/bin/sudo"],
    },
    "polkit": {
        "version": "123-5.tl4",
        "cve_patches": ["CVE-2025-7519"],
        "suid_binaries": ["/usr/bin/pkexec", "/usr/lib/polkit-1/polkit-agent-helper-1"],
    },
    "shadow_utils": {
        "versions": ["4.14.3-4.tl4", "4.14.3-5.tl4"],
        "tencent_patches": ["add-sm3-support.patch (gordonwwang@tencent.com, Jan 2024)"],
        "suid_binaries": ["/usr/bin/chage", "/usr/bin/gpasswd", "/usr/bin/newgrp",
                          "/usr/bin/chfn", "/usr/bin/chsh"],
    },
    "passwd": {
        "version": "0.80-6.tl4",
        "patches": ["passwd-0.80-manpage.patch", "passwd-0.80-S-output.patch"],
        "cve_patches": "NONE",
        "suid_binaries": ["/usr/bin/passwd"],
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F01: pam_namespace mount namespace race → privesc
# ──────────────────────────────────────────────────────────────────────────────

PAM_NAMESPACE_RACE_CVE_2025_6020 = {
    "finding_id": "TOS46-AUTH-F01",
    "severity": "HIGH",
    "cvss_v3": 7.8,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cve": "CVE-2025-6020",
    "package": "pam-1.5.3-11.tl4 (fixed in -11, present in -1 through -10)",
    "patch_author": "Olivier Bal-Petre <olivier.bal-petre@ssi.gouv.fr> / Dmitry V. Levin",
    "patch_size": "3 patches, 637 lines changed in pam_namespace.c",
    "title": (
        "pam_namespace protect_dir()/protect_mount() vulnerable to race conditions "
        "from out-of-mount-namespace access; multiple users colluding can escalate to root"
    ),
    "description": (
        "The existing protection in pam_namespace's protect_dir() and protect_mount() "
        "worked by bind-mounting directories on themselves. This works ONLY against "
        "attacks from processes in the SAME mount namespace. "
        "\n"
        "An attacker with out-of-mount-namespace access (or two colluding users) can "
        "exploit multiple race conditions in the path traversal to achieve privilege "
        "escalation to root. The attack targets symlinks placed in user-controlled "
        "directories that are traversed by pam_namespace's path-walking code. "
        "\n"
        "Fix: converted all function calls to operate on file descriptors instead of "
        "absolute paths (O_PATH-based secure_opendir), eliminating TOCTOU race conditions. "
        "secure_opendir() now validates ownership (root-owned, not world/group-writable) "
        "at each path segment using fstat() rather than stat(), preventing symlink substitution."
    ),
    "attack_chain": (
        "1. Configure or exploit a pam_namespace polydir entry that includes user-writable "
        "   path components. "
        "2. Create a symlink race: replace path components with symlinks pointing to "
        "   /etc/shadow or other privileged files between pam_namespace's stat() and open() calls. "
        "3. Out-of-mount-namespace process manipulates the path concurrently. "
        "4. pam_namespace follows the attacker's path, bind-mounting /etc/shadow onto "
        "   an attacker-controlled path or vice versa. "
        "5. Attacker reads/writes files with root permissions."
    ),
    "affected_versions": "pam-1.5.3-1 through -10.tl4 (all versions before Jun 2025 patch)",
    "remediation": "Upgrade to pam-1.5.3-11.tl4 or later. Ensure pam_namespace polynss entries use root-owned paths.",
    "references": [
        "CVE-2025-6020",
        "https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/pam/1.5.3-5ubuntu5.4/pam_1.5.3-5ubuntu5.4.debian.tar.xz",
        "pam changelog: 1.5.3-11.tl4 (Jun 26, 2025) — wynnfeng@tencent.com",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F02: pam_access hostname resolution bypass
# ──────────────────────────────────────────────────────────────────────────────

PAM_ACCESS_HOSTNAME_CVE_2024_10963 = {
    "finding_id": "TOS46-AUTH-F02",
    "severity": "MEDIUM",
    "cvss_v3": 6.3,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "cve": "CVE-2024-10963",
    "package": "pam-1.5.3-7.tl4 (fixed), present in earlier versions",
    "patch_author": "wynnfeng <wynnfeng@tencent.com> (patch authored by Tencent developer)",
    "title": (
        "pam_access: tokens resolved as hostnames without requiring FQDN — "
        "device names or PAM service names could be confused with hostnames; "
        "reworked hostname resolution logic"
    ),
    "description": (
        "pam_access resolved tokens as hostnames without requiring Fully-Qualified "
        "Host Names (FQHNs). A token that matched a device name, PAM service name, "
        "or other non-hostname token could be incorrectly resolved as a hostname, "
        "potentially granting or denying access based on a false hostname match. "
        "\n"
        "Fix adds: nodns option to prevent DNS hostname resolution, noaudit option "
        "for suppressing audit log entries, and updated documentation requiring FQHNs. "
        "\n"
        "Note: The pam-1.5.3-7.tl4 changelog shows 'Tencent developer (wynnfeng) "
        "authored the patch' — unusual, as most CVE patches come from upstream. "
        "This indicates Tencent maintains and contributes to PAM independently."
    ),
    "references": ["CVE-2024-10963", "https://github.com/linux-pam/linux-pam/pull/854"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F03: pam_namespace FIFO DoS
# ──────────────────────────────────────────────────────────────────────────────

PAM_NAMESPACE_FIFO_DOS_CVE_2024_22365 = {
    "finding_id": "TOS46-AUTH-F03",
    "severity": "MEDIUM",
    "cvss_v3": 5.5,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2024-22365",
    "package": "pam-1.5.3-4.tl4 (fixed, Jan 2024)",
    "title": (
        "pam_namespace protect_dir() does not pass O_DIRECTORY to openat(); "
        "FIFO placed by user in path causes pam_namespace to block indefinitely on login"
    ),
    "description": (
        "Without O_DIRECTORY, the path-crawling logic in protect_dir() allows a FIFO "
        "(named pipe) to be placed in a user-controlled directory component. When pam_namespace "
        "traverses the path via openat(), it blocks indefinitely waiting for the FIFO to be opened "
        "for reading/writing by another process. This prevents PAM from completing authentication, "
        "resulting in a denial of service for all logins using the affected namespace configuration. "
        "\n"
        "Fix: add O_DIRECTORY flag to openat() calls, causing them to fail with ENOTDIR if "
        "the path resolves to a non-directory (including FIFOs). The post-open S_ISDIR check "
        "becomes redundant and is removed."
    ),
    "attack_surface": "Any system using pam_namespace with user-writable path components",
    "references": ["CVE-2024-22365", "https://github.com/linux-pam/linux-pam/issues/707"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F04: pam_unix shadow helper always-run
# ──────────────────────────────────────────────────────────────────────────────

PAM_UNIX_SHADOW_CVE_2024_10041 = {
    "finding_id": "TOS46-AUTH-F04",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cve": "CVE-2024-10041",
    "package": "pam-1.5.3-8.tl4 (fixed, Dec 2024)",
    "title": (
        "pam_unix calls pam_modutil_getspnam() before helper; "
        "libnss_systemd synthesizes shadow entries for root → root login locked out on some configs"
    ),
    "description": (
        "When pam_unix.so verifies a password, it historically called getspnam() to obtain the "
        "shadow password file entry, using the unix_chkpwd helper only as a fallback. "
        "\n"
        "With libnss_systemd enabled in nsswitch.conf shadow line: if libnss_files fails to "
        "obtain root's shadow entry (e.g., when SELinux denies the read), NSS falls back to "
        "libnss_systemd which synthesizes a shadow entry for root with a locked-account marker. "
        "This locked synthesized entry causes pam_unix to deny root login even though "
        "/etc/shadow has valid credentials. "
        "\n"
        "Fix: for password verification, pam_unix now ALWAYS invokes the helper instead of "
        "attempting getspnam() first. The helper runs as root (setuid unix_chkpwd) and bypasses "
        "the NSS fallback problem."
    ),
    "affected_configs": "Systems with libnss_systemd enabled in nsswitch.conf shadow entry",
    "references": [
        "CVE-2024-10041",
        "https://github.com/linux-pam/linux-pam/pull/484",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2150155",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F05: sudo remote host bypass (CVE-2025-32462)
# ──────────────────────────────────────────────────────────────────────────────

SUDO_REMOTE_HOST_CVE_2025_32462 = {
    "finding_id": "TOS46-AUTH-F05",
    "severity": "HIGH",
    "cvss_v3": 8.8,
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    "cve": "CVE-2025-32462",
    "package": "sudo-1.9.15p5-5.tl4",
    "title": (
        "sudo allows non-list commands to specify a remote host via -h flag; "
        "host check bypassed in sudoers_check_common() for non-MODE_LIST contexts"
    ),
    "description": (
        "The -h (host) flag in sudo is documented to be valid only for 'sudo -l' (list mode). "
        "However, prior to the fix, sudoers_check_common() did not enforce that ctx->runas.host "
        "== ctx->user.host when the mode is NOT MODE_LIST|MODE_CHECK. "
        "\n"
        "An attacker could use 'sudo -h <different_host> <command>' to execute commands with "
        "a different effective host context, potentially bypassing sudoers host restrictions "
        "intended for multi-host environments with centralized sudoers configuration. "
        "\n"
        "Fix: added explicit check in sudoers_check_common() at the top of the function: "
        "if not list/check mode AND runas.host != user.host, reject with audit log."
    ),
    "references": ["CVE-2025-32462", "sudo changelog log_warningx SLOG_NO_STDERR|SLOG_AUDIT"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F06: sudo filesystem pivot (CVE-2025-32463)
# ──────────────────────────────────────────────────────────────────────────────

SUDO_PIVOT_CVE_2025_32463 = {
    "finding_id": "TOS46-AUTH-F06",
    "severity": "HIGH",
    "cvss_v3": 7.8,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cve": "CVE-2025-32463",
    "package": "sudo-1.9.15p5-5.tl4",
    "patch_impact": "pivot.c and pivot.h deleted (87 lines removed), Makefile rebuilt",
    "title": (
        "sudo pivot.c enabled filesystem pivot_root attacks during command lookup; "
        "deleted entirely in CVE fix; match_command.c, find_path.c, goodpath.c reworked"
    ),
    "description": (
        "sudo contained a pivot.c module (87 lines) that implemented filesystem pivot "
        "functionality. This code was used during command path resolution and could be "
        "exploited to pivot_root into an attacker-controlled filesystem, allowing "
        "command lookup to be redirected to attacker-supplied binaries. "
        "\n"
        "The fix deletes pivot.c and pivot.h entirely and rewrites the affected files: "
        "match_command.c (212 lines changed), find_path.c (20 lines), goodpath.c (17 lines), "
        "and editor.c (2 lines). The sudoers Makefile.in is rebuilt (730 lines changed). "
        "\n"
        "Impact: local attacker with sudo access to ANY command could potentially use the "
        "pivot mechanism to execute arbitrary code as root."
    ),
    "files_changed": [
        "plugins/sudoers/pivot.c DELETED",
        "plugins/sudoers/pivot.h DELETED",
        "plugins/sudoers/match_command.c (212 lines)",
        "plugins/sudoers/find_path.c",
        "plugins/sudoers/goodpath.c",
        "plugins/sudoers/Makefile.in (730 lines)",
    ],
    "references": ["CVE-2025-32463"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F07: sudo mailer gid not dropped (CVE-2026-35535)
# ──────────────────────────────────────────────────────────────────────────────

SUDO_MAILER_GID_CVE_2026_35535 = {
    "finding_id": "TOS46-AUTH-F07",
    "severity": "MEDIUM",
    "cvss_v3": 6.1,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
    "cve": "CVE-2026-35535",
    "package": "sudo-1.9.15p5-6.tl4 (fixed), sudo-1.9.15p5-5.tl4 (vulnerable)",
    "title": (
        "sudo exec_mailer() drops uid to mailuid but does not drop gid/groups before "
        "execve; mailer runs with root group membership if mailuid != root"
    ),
    "description": (
        "In sudo's exec_mailer() function (lib/eventlog/eventlog.c), when the configured "
        "mailuid is not root, the code called setuid(mailuid) to drop privileges. However, "
        "it did NOT call setgid() or setgroups() first. The mailer process was executed with "
        "the mail user's uid but retained root's group (gid 0) and supplementary groups. "
        "\n"
        "If the mailer binary (sendmail, postfix, etc.) depends on group membership for "
        "access control, or if group-writable files are accessible to root group, the mailer "
        "process could perform actions beyond what the mailuid account normally can. "
        "\n"
        "Fix: adds setgid(mailgid) and setgroups(1, &mailgid) calls BEFORE setuid(mailuid). "
        "Also adds eventlog_config.mailgid field and eventlog_set_mailuser() function. "
        "Error paths now use goto bad → _exit(127) instead of falling through."
    ),
    "fix_diff": (
        "eventlog.c: adds setgid(evl_conf->mailgid) + setgroups(1, &mailgid) before setuid; "
        "eventlog_conf.c: adds mailgid field; sudo_eventlog.h: mailgid + eventlog_set_mailuser()"
    ),
    "references": ["CVE-2026-35535"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F08: polkit nested .policy XML crash (CVE-2025-7519)
# ──────────────────────────────────────────────────────────────────────────────

POLKIT_XML_CRASH_CVE_2025_7519 = {
    "finding_id": "TOS46-AUTH-F08",
    "severity": "MEDIUM",
    "cvss_v3": 5.9,
    "cvss_vector": "AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2025-7519",
    "package": "polkit-123-5.tl4",
    "title": (
        "polkit _start() XML parser for .policy files lacks stack depth check; "
        "nested XML elements cause overflow leading to crash (DoS)"
    ),
    "description": (
        "polkitbackendactionpool.c's _start() expat XML callback for parsing .policy "
        "action files uses a stack (pd->stack_depth) to track XML element nesting. "
        "Prior to the fix, there was no bounds check on pd->stack_depth before accessing "
        "the stack, allowing a .policy file with deeply nested XML elements to cause "
        "a stack-based overflow, crashing polkitd. "
        "\n"
        "Any root or authorized user who can place a crafted .policy file in "
        "/usr/share/polkit-1/actions/ can crash polkitd, causing a denial of service "
        "for all applications that use polkit for privilege checking. "
        "\n"
        "Fix adds: if (pd->stack_depth < 0 || pd->stack_depth >= PARSER_MAX_DEPTH) → "
        "g_warning and goto error, before accessing the stack."
    ),
    "fix_lines": 6,
    "location": "src/polkitbackend/polkitbackendactionpool.c:739 (_start function)",
    "references": ["CVE-2025-7519", "polkit-123-5.tl4 SRPM fix-CVE-2025-7519.patch"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-AUTH-F09: SM3 password hashing (Tencent extension)
# ──────────────────────────────────────────────────────────────────────────────

SM3_PASSWORD_HASHING = {
    "finding_id": "TOS46-AUTH-F09",
    "severity": "INFO",
    "title": (
        "Tencent adds SM3 password hash support to PAM and shadow-utils; "
        "crypt prefix $sm3$; not present in upstream linux-pam or shadow-utils; "
        "pam_unix 'sm3' option and ENCRYPT_METHOD=SM3 in login.defs"
    ),
    "pam_patch": {
        "file": "add-sm3-support.patch",
        "author": "zoedong <zoedong@tencent.com>",
        "date": "2023-08-01",
        "changelog_entry": "1.5.2-2 (Feb 2023): Add sm3 support",
        "files_changed": [
            "modules/pam_unix/pam_unix.8",
            "modules/pam_unix/pam_unix.8.xml",
            "modules/pam_unix/passverify.c",
            "modules/pam_unix/support.c",
            "modules/pam_unix/support.h",
        ],
        "crypt_prefix": "$sm3$",
        "pam_option": "sm3",
        "usage": "password required pam_unix.so sm3",
    },
    "shadow_utils_patch": {
        "file": "add-sm3-support.patch",
        "author": "gordonwwang <gordonwwang@tencent.com>",
        "date": "2024-01-11",
        "files_changed": [
            "configure.ac (--with-sm3-crypt flag)",
            "etc/login.defs (ENCRYPT_METHOD=SM3)",
            "lib/encrypt.c",
            "lib/getdef.c",
            "lib/obscure.c",
            "lib/salt.c (SM3_CRYPT_SALT_PREFIX = '$sm3$')",
            "src/chgpasswd.c",
            "src/chpasswd.c",
            "src/newusers.c",
            "src/passwd.c",
        ],
        "crypt_prefix": "$sm3$",
        "login_defs_option": "ENCRYPT_METHOD SM3",
        "rounds_setting": "SM3_CRYPT_MIN_ROUNDS / SM3_CRYPT_MAX_ROUNDS",
    },
    "security_notes": (
        "SM3 is the Chinese national hash standard (GM/T 0004-2012). Its use for "
        "password hashing requires SM3 support in the system crypt(3) library (typically "
        "glibc with SM3 crypt variant). SM3 is not NIST-approved but is approved in "
        "China under OSCCA (Office of State Commercial Cryptography Administration). "
        "\n"
        "Security equivalent to SHA-256 for password hashing purposes. "
        "Attack surface: systems configured with ENCRYPT_METHOD=SM3 in login.defs will "
        "use SM3 for new passwords; existing SHA-512 hashes are not retroactively converted. "
        "\n"
        "Interoperability concern: SM3-hashed passwords ($sm3$ prefix) will fail "
        "authentication on any system where the SM3 crypt variant is not compiled in."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-AUTH-F01": PAM_NAMESPACE_RACE_CVE_2025_6020,
    "TOS46-AUTH-F02": PAM_ACCESS_HOSTNAME_CVE_2024_10963,
    "TOS46-AUTH-F03": PAM_NAMESPACE_FIFO_DOS_CVE_2024_22365,
    "TOS46-AUTH-F04": PAM_UNIX_SHADOW_CVE_2024_10041,
    "TOS46-AUTH-F05": SUDO_REMOTE_HOST_CVE_2025_32462,
    "TOS46-AUTH-F06": SUDO_PIVOT_CVE_2025_32463,
    "TOS46-AUTH-F07": SUDO_MAILER_GID_CVE_2026_35535,
    "TOS46-AUTH-F08": POLKIT_XML_CRASH_CVE_2025_7519,
    "TOS46-AUTH-F09": SM3_PASSWORD_HASHING,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "packages": list(AUTH_PACKAGE_INVENTORY.keys()),
        "suid_binary_count": 12,
        "tencent_specific_patches": ["add-sm3-support (PAM)", "add-sm3-support (shadow-utils)"],
        "highest_cvss": max(v.get("cvss_v3", 0) for v in FINDINGS.values() if isinstance(v.get("cvss_v3"), float)),
        "findings": [{"id": k, "severity": v.get("severity", "?"), "cve": v.get("cve", "-")}
                     for k, v in FINDINGS.items()],
    }, indent=2))
