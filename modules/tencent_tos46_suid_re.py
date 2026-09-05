"""
TencentOS 4.6 — SUID binary survey and reverse engineering module.

Source: /mnt/tos46_re (nbd10, TOS 4.6 kernel 6.6.119-51.3.tl4.x86_64)
Survey scope: all SUID binaries found via find -perm -4000

18 SUID binaries total:
  /usr/bin/chage        shadow-utils 4.14.3-5.tl4, -rwsr-xr-x, 82784B, stripped
  /usr/bin/chfn         shadow-utils 4.14.3-5.tl4, -rws--x--x, 28024B (execute-only)
  /usr/bin/chsh         shadow-utils 4.14.3-5.tl4, -rws--x--x, 23872B (execute-only)
  /usr/bin/crontab      cronie 1.6.1-6.tl4, -rwsr-xr-x, 57224B, stripped
  /usr/bin/fusermount   fuse 2.9.9-6.tl4, -rwsr-xr-x, 36272B, stripped
  /usr/bin/gpasswd      shadow-utils 4.14.3-5.tl4, -rwsr-xr-x, 73920B, stripped
  /usr/bin/mount        util-linux 2.39.1-13.tl4, -rwsr-xr-x, 44480B, stripped
  /usr/bin/newgrp       shadow-utils 4.14.3-5.tl4, -rwsr-xr-x, 33592B, stripped
  /usr/bin/passwd       pam 1.5.3-12.tl4, -rwsr-xr-x, 31976B, stripped
  /usr/bin/pkexec       polkit 0.117(?), -rwsr-xr-x, 31992B, stripped
  /usr/bin/su           util-linux 2.39.1-13.tl4, -rwsr-xr-x, 52976B, stripped
  /usr/bin/sudo         sudo (ver unknown), ---s--x--x, 219128B (execute-only)
  /usr/bin/umount       util-linux 2.39.1-13.tl4, -rwsr-xr-x, 36224B, stripped
  /usr/lib/polkit-1/polkit-agent-helper-1  polkit, -rwsr-xr-x, 19640B, stripped
  /usr/sbin/grub2-set-bootflag  grub2 (v2.12 script), -rwsr-xr-x, 15416B, stripped
  /usr/sbin/mount.nfs   nfs-utils 2.6.3-6.tl4, -rwsr-xr-x, 97128B, stripped
  /usr/sbin/pam_timestamp_check pam 1.5.3-12.tl4, -rwsr-xr-x, 15472B, stripped
  /usr/sbin/unix_chkpwd pam 1.5.3-12.tl4, -rwsr-xr-x, 27960B, stripped

TOS-specific package versions (all build with .tl4 suffix):
  shadow-utils: 4.14.3-5.tl4
  util-linux: 2.39.1-13.tl4
  cronie (crontab): 1.6.1-6.tl4
  fuse: 2.9.9-6.tl4
  nfs-utils: 2.6.3-6.tl4
  pam: 1.5.3-12.tl4

All binaries are x86-64, dynamically linked.
"""

METADATA = {
    "target": "TencentOS 4.6",
    "source": "nbd10 /mnt/tos46_re",
    "suid_binary_count": 18,
    "build_suffix": ".tl4",
    "all_stripped": True,
}

SUID_INVENTORY = {
    "/usr/bin/chage":     {"pkg": "shadow-utils", "ver": "4.14.3-5.tl4", "size": 82784,  "build_id": "c98b9dd5fcefaafcd771a27b16f4dbbd62552c40", "mode": "4755"},
    "/usr/bin/chfn":      {"pkg": "shadow-utils", "ver": "4.14.3-5.tl4", "size": 28024,  "mode": "4711"},
    "/usr/bin/chsh":      {"pkg": "shadow-utils", "ver": "4.14.3-5.tl4", "size": 23872,  "mode": "4711"},
    "/usr/bin/crontab":   {"pkg": "cronie",       "ver": "1.6.1-6.tl4",   "size": 57224,  "build_id": "d50ed4cb235f255e31675d3922b7dfa31e841078", "mode": "4755"},
    "/usr/bin/fusermount":{"pkg": "fuse",         "ver": "2.9.9-6.tl4",   "size": 36272,  "build_id": "783f9338789089995aa609b6000455c66a02a923", "mode": "4755"},
    "/usr/bin/gpasswd":   {"pkg": "shadow-utils", "ver": "4.14.3-5.tl4", "size": 73920,  "build_id": "5f084e011081fcbe373d7c2e4973c3a65d81a511", "mode": "4755"},
    "/usr/bin/mount":     {"pkg": "util-linux",   "ver": "2.39.1-13.tl4", "size": 44480,  "build_id": "04870dde6a402b73f1bcd4ba20b39a8ebc417f7e", "mode": "4755"},
    "/usr/bin/newgrp":    {"pkg": "shadow-utils", "ver": "4.14.3-5.tl4", "size": 33592,  "build_id": "6505c6307994c0c1d89d6320171d014e7f81d4d2", "mode": "4755"},
    "/usr/bin/passwd":    {"pkg": "pam",          "ver": "1.5.3-12.tl4",  "size": 31976,  "build_id": "40595f6229e86eb3e5dd2e88172ed546bf1f12b2", "mode": "4755"},
    "/usr/bin/pkexec":    {"pkg": "polkit",       "ver": "unknown",        "size": 31992,  "build_id": "5f80c214074ed020ac985438b2513f3147551e31", "mode": "4755"},
    "/usr/bin/su":        {"pkg": "util-linux",   "ver": "2.39.1-13.tl4", "size": 52976,  "build_id": "f3347723f5d0d21ad5a4c1fe409bc4bf832317d9", "mode": "4755"},
    "/usr/bin/sudo":      {"pkg": "sudo",         "ver": "unknown",        "size": 219128, "mode": "4111"},
    "/usr/bin/umount":    {"pkg": "util-linux",   "ver": "2.39.1-13.tl4", "size": 36224,  "build_id": "87a597594a0edf0f0b404b72f271fbdb4783a70b", "mode": "4755"},
    "/usr/lib/polkit-1/polkit-agent-helper-1": {"pkg": "polkit", "ver": "unknown", "size": 19640, "build_id": "d19c0fc6f3ae2c74cfb5ea34612b8397188a9356", "mode": "4755"},
    "/usr/sbin/grub2-set-bootflag": {"pkg": "grub2", "ver": "2.12", "size": 15416, "build_id": "0476d5dcb9f57f653b080cc12f4b0d32002913ee", "mode": "4755"},
    "/usr/sbin/mount.nfs": {"pkg": "nfs-utils", "ver": "2.6.3-6.tl4", "size": 97128, "build_id": "c9536ff746ce25ac0984568661212fb317a6b46e", "mode": "4755"},
    "/usr/sbin/pam_timestamp_check": {"pkg": "pam", "ver": "1.5.3-12.tl4", "size": 15472, "build_id": "2dcbd20f4409c7de0f74c2dc648027187ae1a0a4", "mode": "4755"},
    "/usr/sbin/unix_chkpwd": {"pkg": "pam", "ver": "1.5.3-12.tl4", "size": 27960, "build_id": "10bbfb4bc131c15bf540ec1990ffe306fec41d26", "mode": "4755"},
}

PKEXEC_ANALYSIS = {
    "binary": "/usr/bin/pkexec",
    "main_addr": "0x2b10",
    "entry_addr": "0x4330",
    "pwnkit_cve": "CVE-2021-4034",
    "pwnkit_patch_status": "PATCHED",
    "pwnkit_patch_evidence": (
        "At main+0x137 (VA 0x2c47): 'test r12d, r12d; jle 0x3e83' "
        "— r12d = argc (movsxd r12, edi at 0x2b6f). "
        "When argc <= 0, jumps to 0x3e83 (error path, likely exit). "
        "Patched versions of pkexec added this check to prevent the PwnKit exploit, "
        "which required invoking pkexec with argc=0 to trigger argv[n_args] == environ[0]."
    ),
    "pam_imports": ["pam_start", "pam_strerror", "pam_getenvlist"],
    "polkit_imports": [
        "polkit_unix_process_new_for_owner",
        "polkit_unix_process_get_pid",
        "polkit_authority_check_authorization_sync",
        "polkit_authorization_result_get_is_authorized",
    ],
    "argc_check_disasm": [
        "2b6f: movsxd r12, edi          ; r12 = argc",
        "2c47: test r12d, r12d          ; argc == 0?",
        "2c4a: jle 3e83                 ; argc <= 0 -> error exit (PwnKit patch)",
        "2c76: cmp r12d, 0x1            ; argc == 1?",
        "2c7a: je 3425                  ; argc == 1 -> show help/version",
    ],
}

GRUB_SET_BOOTFLAG_ANALYSIS = {
    "binary": "/usr/sbin/grub2-set-bootflag",
    "target_file": "/boot/grub2/grubenv",
    "version": "2.12",
    "imports": [
        "fopen64", "fread", "fwrite", "fclose", "ftruncate64", "fsync",
        "fdopen", "fileno", "flock", "fflush", "fstat64",
        "realpath", "rename", "unlink", "open64",
        "setegid", "getuid", "geteuid", "getrlimit64",
        "snprintf", "strncmp", "strcmp", "strstr", "memcmp", "memcpy",
    ],
    "security_notes": (
        "grub2-set-bootflag is SUID root solely to write /boot/grub2/grubenv. "
        "Uses realpath() to canonicalize the grubenv path before opening — "
        "mitigates simple symlink attacks on the path itself. "
        "Uses flock() for mutual exclusion ('Another invocation won race' error string). "
        "Uses atomic write: write to tmpfile, fsync, rename to /boot/grub2/grubenv. "
        "setegid import: drops group privilege after opening. "
        "getrlimit64: likely enforcing file size limits before write. "
        "The attack surface is narrow — argument is the boot flag name "
        "(from a fixed allowlist: 'boot_success' confirmed from strings). "
        "If flag name is not validated against an allowlist, the grubenv format "
        "parser may be exploitable — but the binary is small (15KB) and likely "
        "validates the flag name against a hardcoded set."
    ),
    "flag_seen": ["boot_success"],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "pkexec patched against PwnKit (CVE-2021-4034) — argc≤0 check at main+0x137",
        "detail": (
            "pkexec on TOS 4.6 is patched against CVE-2021-4034 (PwnKit, Jan 2022). "
            "The patch adds: at main VA 0x2c47, test r12d,r12d (r12=argc) + jle 0x3e83 (exit). "
            "When argc=0 (the PwnKit trigger condition), pkexec now exits immediately instead of "
            "executing environ[0] as the target binary. "
            "polkit version is not disclosed in strings, but the BuildID "
            "(5f80c214074ed020ac985438b2513f3147551e31) can be used to confirm the patch epoch."
        ),
        "cve": "CVE-2021-4034",
        "status": "PATCHED",
    },
    {
        "id": "F2",
        "severity": "MEDIUM",
        "title": "sudo binary is execute-only (mode ---s--x--x) — version and patch status unverifiable",
        "detail": (
            "sudo at /usr/bin/sudo has mode 4111 (---s--x--x): not readable by non-root. "
            "This prevents static analysis without root access on a live system. "
            "Binary size 219128 bytes is consistent with sudo 1.9.x or 1.8.x. "
            "Cannot determine version or CVE patch status from mode-4111 binary. "
            "Standard sudo vulnerabilities (CVE-2021-3156 Baron Samedit heap overflow, "
            "CVE-2023-22809 sudoedit bypass) would require direct version string extraction "
            "from a running sudo --version or from the RPM database. "
            "RPM database on the TOS filesystem would show the exact version; "
            "not analyzed in this session."
        ),
        "recommendation": "Check rpm -q sudo on live system or extract from TOS RPM database",
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "grub2-set-bootflag SUID root modifies /boot/grub2/grubenv — bootloader config write surface",
        "detail": (
            "grub2-set-bootflag requires SUID root to modify /boot/grub2/grubenv. "
            "The binary accepts a flag name argument (e.g. 'boot_success') and modifies the grubenv. "
            "Attack surface: the flag name argument flows into the grubenv editor. "
            "If the flag name is not restricted to a hardcoded allowlist, an attacker who can "
            "call grub2-set-bootflag with an arbitrary argument can corrupt /boot/grub2/grubenv "
            "by injecting grubenv format metacharacters (newlines, '='), potentially affecting "
            "boot behavior. "
            "flock()-based race mitigation is present ('Another invocation won race'). "
            "realpath() is called to canonicalize the grubenv path — standard symlink attack mitigated. "
            "However, a TOCTOU window exists between realpath() and fopen64(): if /boot/grub2/ "
            "is writable by an intermediate user and atomically replaced, a different file is modified."
        ),
        "flags_seen": ["boot_success"],
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "TOS-specific package versions — all SUID binaries carry .tl4 build suffix",
        "detail": (
            "All SUID binary packages carry TOS-specific build suffixes: "
            "shadow-utils: 4.14.3-5.tl4 (upstream: 4.14.x base), "
            "util-linux: 2.39.1-13.tl4 (upstream: 2.39.1 base), "
            "cronie: 1.6.1-6.tl4, "
            "fuse: 2.9.9-6.tl4, "
            "nfs-utils: 2.6.3-6.tl4, "
            "pam: 1.5.3-12.tl4. "
            "The high patch release numbers (5-13 TOS patches on top of upstream) indicate "
            "active TOS-specific patching. The SRPM changelogs would reveal what was patched. "
            "TOS 4.6 is based on TencentOS Server 4, which is a RHEL-compatible distribution. "
            "These versions broadly align with RHEL 9.x package versions with additional TOS patches."
        ),
    },
    {
        "id": "F5",
        "severity": "INFO",
        "title": "mount.nfs SUID root uses libtirpc for RPC — NFS mount attack surface",
        "detail": (
            "mount.nfs (nfs-utils 2.6.3-6.tl4, 97KB, SUID root) uses libtirpc.so.3 for ONC-RPC. "
            "Dynamically linked: any vulnerability in libtirpc (on the live system) is in scope. "
            "NFS-specific attack surface: 'requested NFS version or transport protocol not supported', "
            "'NFS version %ld is not supported', 'Failed to create RPC client', "
            "'rpc.statd is not running but is required for remote locking'. "
            "The binary is SUID root because NFS mount syscall requires CAP_SYS_ADMIN. "
            "Argument parsing (minorversion=, NFS version) is user-controlled and flows "
            "into RPC client creation — worth auditing for integer overflow in version field."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "PAM stack (pam 1.5.3-12.tl4): passwd, unix_chkpwd, pam_timestamp_check — auth path",
        "detail": (
            "Three PAM-related SUID binaries: "
            "passwd (31976B): changes user passwords, calls PAM. "
            "unix_chkpwd (27960B): shadow password verification helper — called by pam_unix.so. "
            "  Imports: getpwnam, getspnam, strcmp, setreuid, audit_open, openlog. "
            "  setreuid: drops privilege after getting shadow entry. "
            "pam_timestamp_check (15472B): checks PAM timestamp files (sudo-like grace period). "
            "All three are standard PAM infrastructure. pam 1.5.3-12.tl4 is a heavily-patched "
            "version — the changelog would reveal TOS-specific modifications."
        ),
    },
]

if __name__ == '__main__':
    print(f"TOS 4.6 SUID Survey — {len(SUID_INVENTORY)} binaries, {len(FINDINGS)} findings")
    for path, info in sorted(SUID_INVENTORY.items()):
        print(f"  {path}: {info['pkg']} {info['ver']} ({info['size']}B, mode={info['mode']})")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
