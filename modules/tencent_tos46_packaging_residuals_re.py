"""
TencentOS 4.6 — packaging residuals RE.

Low-signal packaging and configuration patches for: dbus, nfs-utils, postfix,
rpm, FreeRADIUS (additional), tagent v2.1.6 installer.

Sources: scratchpad/dbus_work/, nfs_work/, postfix_work/, rpm_work/, tagent_work/
"""

DBUS_PATCHES = {
    "package": "dbus-1.14.8",
    "tos_version": "TOS 4.6",
    "patches": {
        "0001-tools-Use-Python3-for-GetAllMatchRules.patch": {
            "description": "Port GetAllMatchRules helper tool from Python 2 to Python 3.",
            "class": "packaging",
        },
        "5000-mute-autolaunch-testcase.patch": {
            "description": (
                "Removes run-test.sh from the dbus test suite (name-test/Makefile.am). "
                "The autolaunch test can fail in constrained build environments "
                "(no D-Bus session bus). TOS-specific patch to make rpm builds pass."
            ),
            "author": "TOS packaging team",
            "class": "packaging",
            "tos_specific": True,
        },
    },
    "security_note": "No security-relevant patches in TOS dbus stack; upstream dbus-1.14.8 consumed as-is.",
}

NFS_PATCHES = {
    "package": "nfs-utils-2.6.3",
    "tos_version": "TOS 4.6",
    "patches": {
        "5000-nfs-utils-2.6.1-nfsidmap-warnmsg.patch": {
            "file": "utils/nfsidmap/nfsidmap.c",
            "author": "jackxjchen@tencent.com",
            "description": (
                "nfsidmap warning message updated: "
                "'Check /etc/request-key.conf' → 'Check /etc/request-key.d/id_resolver.conf'. "
                "The request-key config moved to a subdirectory in modern distributions; "
                "the old path confused administrators troubleshooting ID mapping failures."
            ),
            "class": "usability",
        },
        "backport_patches": [
            "nfs-utils-1.2.1-exp-subtree-warn-off.patch",
            "nfs-utils-1.2.1-statdpath-man.patch",
            "nfs-utils-2.3.1-systemd-gssproxy-restart.patch",
            "nfs-utils-2.3.3-man-tcpwrappers.patch",
            "nfs-utils-2.3.3-nfsconf-usegssproxy.patch",
            "nfs-utils-2.4.2-systemd-svcgssd.patch",
        ],
    },
    "security_note": "No security CVEs in TOS nfs-utils patch stack beyond upstream baseline.",
}

POSTFIX_PATCHES = {
    "package": "postfix-3.8.5",
    "tos_version": "TOS 4.6",
    "patches": {
        "postfix-3.6.2-glibc-234-build-fix.patch": {
            "file": "src/util/sys_defs.h",
            "description": (
                "Adds '#define HAS_CLOSEFROM' when glibc >= 2.34. "
                "glibc 2.34 introduced closefrom(2) as a C library function; "
                "postfix 3.6.x predated this and used its own implementation. "
                "Without the define, postfix's internal closefrom shadows glibc's, "
                "causing build failures on TOS 4.6 (glibc 2.38)."
            ),
            "class": "build-compat",
        },
        "other_patches": [
            "postfix-3.3.3-alternatives.patch — alternatives symlink setup",
            "postfix-3.4.0-files.patch — file layout adjustments",
            "postfix-3.4.4-chroot-example-fix.patch — chroot config example",
            "postfix-3.7.0-config.patch — TOS default config",
            "postfix-3.7.0-large-fs.patch — large filesystem support",
            "postfix-3.7.0-whitespace-name-fix.patch — config key whitespace",
        ],
    },
    "security_note": "No security CVEs in TOS postfix patch stack beyond upstream baseline.",
}

RPM_PATCHES = {
    "package": "rpm-4.18.2",
    "tos_version": "TOS 4.6",
    "patches": {
        "rpm-4.17.x-rpm_dbpath.patch": {
            "description": (
                "Changes default rpm database path: "
                "%_dbpath %{_var}/lib/rpm → %{_usr}/lib/sysimage/rpm. "
                "Follows Fedora/RHEL 9 standard for relocating the rpm database "
                "to /usr/lib/sysimage/rpm (writeable during build, read-only in container)."
            ),
            "class": "config",
        },
        "rpm-4.18.x-ldflags.patch": {
            "description": (
                "Exposes RPM_LD_FLAGS in the rpm build environment. "
                "Previously only RPM_OPT_FLAGS (CFLAGS) was exported; "
                "linker flags (hardening: -Wl,-z,now, -Wl,-z,relro) were not "
                "available to %build scriptlets. Enables consistent hardening across TOS packages."
            ),
            "class": "build-hardening",
        },
        "rpm-4.18.x-siteconfig.patch": {
            "description": "Sets CONFIG_SITE=${CONFIG_SITE:-NONE} in build pre-env.",
            "class": "build-compat",
        },
        "rpm-4.9.90-no-man-dirs.patch": {
            "description": "find-lang.sh regex fix: append /* to match man directory contents.",
            "class": "packaging",
        },
        "rpm-4.18.x-revert-pandoc-cond.patch": {
            "description": "Removes pandoc conditional around docs/man subdirectory (always build man pages).",
            "class": "packaging",
        },
    },
}

TAGENT_V216 = {
    "version": "2.1.6",
    "installer": "tagent-installer-v2.1.6-both.zip",
    "build_date": "2026-08-18",
    "architectures": ["x86_64", "aarch64"],
    "packages": {
        "tagent-tms-x86.zip": "14MB",
        "tagent-tms-arm.zip": "19MB",
    },
    "new_vs_prior_versions": {
        "kill_protect": {
            "mechanism": "Write 'add <binary>' to /proc/kill_protect/blacklist",
            "status_check": "Read /proc/sys/kernel/sig_kill_protect (1=enabled, 0=disabled)",
            "binaries_protected": ["tagentV1.0", "tagent"],
            "note": "Uses TOS kill_protect.ko procfs interface. Already documented in tencent_tos4x_kill_hooks_re.py.",
        },
        "del_protect": {
            "mechanism": "chattr +i /usr/local/tagent (immutable bit via ext4 ioctl)",
            "config_key": "delProtect = true in /usr/local/tagent/config.conf",
            "disable_path": "chattr -i -R /usr/local/tagent; sed -i 's/delProtect = true/delProtect = false/'",
            "note": "Prevents file deletion even by root without CAP_LINUX_IMMUTABLE removal.",
        },
        "version_gate": {
            "function": "is_over_2_0_4()",
            "logic": "version sort: if installed <= v2.0.3, skip kill_protect disable step (old version lacks it)",
            "note": "Backwards compatibility: old tagent had no self-protection, new does",
        },
        "cgroup_management": {
            "v1": "Creates /sys/fs/cgroup/memory/tagent and /sys/fs/cgroup/cpu/tagent for resource isolation",
            "v2": "Creates /sys/fs/cgroup/unified/tagent hierarchy",
            "installer_manages": True,
        },
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "MEDIUM",
        "package": "tagent-v2.1.6",
        "title": "del_protect uses chattr +i: root-level delete prevention via ext4 immutable bit",
        "detail": (
            "tagent installer sets chattr +i on /usr/local/tagent entire directory tree. "
            "Root cannot rm -rf the agent without first calling chattr -i. "
            "Incident response: removing a compromised tagent requires explicit chattr step. "
            "ARM64 architecture now supported (19MB package)."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "package": "rpm-4.18.2",
        "title": "RPM_LD_FLAGS now exported in TOS package builds — linker hardening reaches all packages",
        "detail": (
            "rpm-4.18.x-ldflags.patch exposes RPM_LD_FLAGS to all TOS package %build scripts. "
            "TOS default ldflags include -Wl,-z,now and -Wl,-z,relro (full RELRO). "
            "All packages rebuilt under TOS 4.6 rpm inherit these flags without explicit spec changes."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "package": "nfs-utils-2.6.3",
        "title": "nfsidmap error message updated to correct config path (jackxjchen@tencent.com)",
        "detail": (
            "TOS-specific patch by Tencent engineer. The old error pointed to /etc/request-key.conf "
            "which no longer exists on modern systems; new message points to "
            "/etc/request-key.d/id_resolver.conf."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "package": "postfix-3.8.5",
        "title": "postfix glibc 2.34 compat: HAS_CLOSEFROM detection prevents build failures",
        "detail": (
            "glibc 2.34+ has closefrom() in libc. Without the HAS_CLOSEFROM define, "
            "postfix's internal closefrom redeclaration collides with glibc's symbol. "
            "TOS 4.6 (glibc 2.38) requires this patch to build postfix."
        ),
    },
]

GOOGLE_DRIVE_INVENTORY = {
    "TencentOS-x86_64": {
        "folder_id": "1W5v3bFEbXWpARvTQueYIFW6CzaGwFw3v",
        "content": "TOS 3.1 x86_64 binary RPMs (modifiedTime 2022-11-30)",
        "coverage": "Covered by tencent_tos31_binary_re.py and related TOS 3.1 modules",
    },
    "TencentOS-AppStream-x86_64": {
        "folder_id": "1wFIJmgSpbYaoTjJ1X7HTsw7LoFOg0AFi",
        "content": "TOS 3.1 AppStream x86_64 binary RPMs (2022)",
        "coverage": "Covered by tencent_tos31_appstream_*.py modules",
    },
}

if __name__ == '__main__':
    print("TencentOS 4.6 packaging residuals RE")
    print()
    print("Packages documented:")
    for pkg in [DBUS_PATCHES, NFS_PATCHES, POSTFIX_PATCHES, RPM_PATCHES]:
        print(f"  {pkg['package']}: {len(pkg['patches'])} patches ({pkg.get('security_note', 'see above')[:50]})")
    print()
    print("tagent v2.1.6 new features:")
    for k, v in TAGENT_V216["new_vs_prior_versions"].items():
        print(f"  {k}: {str(v)[:60]}")
    print()
    print("Google Drive: TOS 3.1 material only — covered by prior modules")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:65]}")
