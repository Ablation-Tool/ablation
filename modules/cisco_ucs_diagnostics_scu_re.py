"""
Cisco UCS Diagnostics and SCU RE Module 1: SDU 7.1.4.260010 + SCU 7.1.7.260100/260200
ISOs: ucs-diag-7.1.4.260010.iso (377MB), ucs-scu-7.1.7.260100.iso (2.7GB), ucs-scu-7.1.7.260200.iso (2.7GB)
Components: initrd (63MB gzip) + rootfs.img (same 2018 squashfs) + container squashfs

7 findings: 0C/1H/3M/3L
Cumulative: 580 [54C+187H+176M+163L]
"""

# ============================================================
# TARGET OVERVIEW
# ============================================================

DIAG_SCU_TARGETS = {
    "diag": {
        "iso": "ucs-diag-7.1.4.260010.iso",
        "size_mb": 377,
        "version": "7.1.4.260010",
        "container_squashfs": "ucs-sdu-container-7.1.4.260010.squashfs",
        "manifest_features": {
            "UefiBoot": True, "LegacyBoot": True, "Diagnostics": True,
            "NonInteractiveSupport": True, "RedfishSupport": True,
            "UISupport": True, "F7Support": True, "RunTimeSupport": False,
        },
    },
    "scu_260100": {
        "iso": "ucs-scu-7.1.7.260100.iso",
        "size_mb": 2740,
        "version": "7.1.7.260100",
        "container_squashfs": "ucs-scu-container-7.1.7.260100.squashfs",
    },
    "scu_260200": {
        "iso": "ucs-scu-7.1.7.260200.iso",
        "size_mb": 2740,
        "version": "7.1.7.260200",
        "container_squashfs": "ucs-scu-container-7.1.7.260200.squashfs",
    },
}

ISO_BOOT_ARCHITECTURE = {
    "components": {
        "bzImage": "Linux kernel 5.14.0-427.13.1.el9_4.x86_64 (RHEL9/AlmaLinux 9.4, 2024)",
        "initrd": "gzip cpio archive, 63MB -- initial ramdisk; sets IMG_VERIFY=1",
        "rootfs.img": "squashfs, same 2018-03-09 binary as all M8 HUU ISOs",
        "container.squashfs": "platform-specific application environment",
    },
    "contrast_with_huu": (
        "HUU ISOs have NO separate bzImage or initrd at ISO root. "
        "HUU rootfs.img is the bootable environment itself (kernel embedded or loaded differently). "
        "Diag/SCU ISOs have a separate 5.14.0 kernel + 63MB initrd that SETS IMG_VERIFY=1. "
        "Same rootfs.img binary is used in both, but in HUU it runs without IMG_VERIFY set."
    ),
    "isolinux_cfg": {
        "ALLOWOPTIONS": "1",
        "SERIAL": "0 115200",
        "KERNEL": "/bzImage",
        "APPEND": "initrd=/initrd LABEL=Host-Server-Utility root=/dev/ram0",
    },
}

# ============================================================
# INITRD SECURITY CONFIGURATION
# ============================================================

INITRD_PROFILE = {
    "path": "etc/profile.d/hsu-profile.sh (inside initrd cpio)",
    "IMG_VERIFY": "1",
    "HSU_KERNEL_IMGVERIFY": "0",
    "DEBUG": "no",
    "img_verify_semantics": (
        "IMG_VERIFY=1 enables container verification via imgverify. "
        "HSU_KERNEL_IMGVERIFY=0 forces userspace openssl dgst path; "
        "hsu-set-verify-key (kernel keyring) never called for Diag/SCU. "
        "Verification uses PEM keys (openssl) not DER keys (kernel)."
    ),
    "hsu_keys_copies": (
        "initrd ships all 14 hsu-keys (DEV+REL, DER+PEM) as a THIRD COPY "
        "after rootfs.img/hsu-keys/ and container base.tar.gz/hsu-keys/"
    ),
}

ROOTFS_VERIFICATION_90_ROOTFS = {
    "script": "initrd:init.d/90-rootfs",
    "process": [
        "1. copy rootfs.img from ISO to /rootfs.img",
        "2. extract trailing 14-byte header (length + type)",
        "3. extract sig_size bytes as /rootfs.sig",
        "4. truncate signature from /rootfs.img",
        "5. hsu-verify-file /rootfs.img /rootfs.sig (uses hsu-verify-digest or openssl)",
    ],
    "key_fallback": {
        "try_rel_first": "hsu-verify-file with rootfs-rel-verify-key",
        "on_rel_fail_try_dev": "hsu-verify-file with rootfs-dev-verify-key",
        "on_dev_succeed": "sets run_mode=DEV, prints 'validated with dev key', CONTINUES BOOT",
        "on_dev_fail": "fatal: 'rootfs image validation with dev key failed'",
    },
    "dev_fallback_consequence": (
        "If rootfs.img is signed with the DEV private key (and REL key fails), "
        "boot continues in DEV mode. DEV mode enables additional getty terminals "
        "(tty5/tty6/tty7) per container init.sh. "
        "A malicious rootfs.img signed with a compromised DEV key boots without fatal."
    ),
}

# ============================================================
# SCU TOOL INVENTORY
# ============================================================

SCU_CONTENT = {
    "linux_os_drivers": {
        "directory": "drivers/",
        "os_variants": ["centos7u9", "oracle7u9", "oracle8u2/4/5/6/7/8", "oracle9u0", "oracle10u0"],
        "driver_types": ["kmod-enic (VIC NIC)", "kmod-fnic (FCoE HBA)"],
        "kernel_example": "kmod-enic-4.9.0.11-1160.61.oluek_5.15.0_3.60.5.1.x86_64.zip (Oracle UEK)",
    },
    "duu_linux": {
        "directory": "duu-linux/",
        "tools": ["get_machine_type.sh", "lsb_release", "ucs_duu"],
        "purpose": "Driver Update Utility for Linux OS in-band driver install",
    },
    "duu_windows": {
        "directory": "duu-windows/",
        "executables": {
            "DriverInstall.exe": "PE32+ x86-64 GUI; main Windows DUU executable",
            "CSADriverSetup_x64.exe": "x64 chipset/adapter driver setup",
            "CSADriverSetup.bat": "batch wrapper",
            "CSADriverChipset.bat": "chipset-specific batch (modified 2026-04-21)",
        },
        "runtime_dlls": {
            "mfc110d.dll": "Microsoft MFC 11.0 DEBUG build (debug suffix 'd'); built 2021-01-06",
            "msvcr110.dll": "Visual C++ 2012 runtime (msvcr110 = MSVC 11.0); built 2021-01-06",
            "cjson.dll": "cJSON library; built 2021-01-06",
            "7z.dll": "7-Zip library; built 2021-01-06",
        },
        "other": {
            "7z.exe": "PE32 (x86 32-bit) 7-Zip console binary; built 2021-01-06",
            "cacert.pem": "CA certificate bundle; used for TLS verification in Windows DUU",
            "autorun.inf": "Windows autorun descriptor (73 bytes)",
        },
    },
    "container_tools": {
        "winpe_squashfs": "tools/winpe.squashfs -- embedded WinPE squashfs in Linux container",
        "storcli": "tools/Linux/*/common_tools/LSI/7.0813/Utility/storcli64 + storcli2",
        "python": "3.13 (Flask/Werkzeug -- same as HUU container)",
    },
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "DIAG-F1",
        "severity": "HIGH",
        "title": "VERIFICATION_ASYMMETRY_HUU_VS_SCU_DIAG_SAME_ROOTFS_DIFFERENT_SECURITY",
        "detail": (
            "HUU ISOs and Diag/SCU ISOs share the identical rootfs.img binary (2018-03-09 squashfs, "
            "147549884 bytes). The rootfs.img's imgverify bypass (IMG_VERIFY not set -> exit 0) "
            "is active in HUU but inactive in SCU/Diag. "
            "Difference: SCU/Diag ship a separate 63MB initrd that exports IMG_VERIFY=1 in "
            "etc/profile.d/hsu-profile.sh. HUU has no such initrd; rootfs.img's own hsu-profile.sh "
            "does not set IMG_VERIFY. "
            "Consequence: identical rootfs.img binary has verification ENABLED in SCU/Diag "
            "and BYPASSED in HUU. All M8 HUU ISOs (C220M8, C245M8, XE130C M8, versions 4.3.6 through 6.0.2) "
            "never verify the container squashfs. The SCU/Diag verification can itself be bypassed "
            "by injecting IMG_VERIFY=0 via ALLOWOPTIONS 1 (isolinux.cfg; present in all ISOs). "
            "ALLOWOPTIONS 1 + SERIAL 0 115200 means boot console via CIMC KVM-over-IP or SoL "
            "is sufficient to disable verification in all ISO types."
        ),
    },
    {
        "id": "DIAG-F2",
        "severity": "MEDIUM",
        "title": "DEV_KEY_FALLBACK_IN_ROOTFS_VERIFICATION_CONTINUES_BOOT_IN_DEV_MODE",
        "detail": (
            "initrd 90-rootfs script implements a DEV key fallback for rootfs.img verification: "
            "try REL key; if fail, try DEV key; if DEV key SUCCEEDS: set run_mode=DEV, log warning, CONTINUE BOOT. "
            "Only if BOTH keys fail does verification produce a fatal error. "
            "DEV key success path: run_mode=DEV causes container init.sh to add "
            "getty terminals on tty5/tty6/tty7 (additional console access). "
            "The DEV public key (rootfs-dev-verify-key.pem, md5 4a68951576b7b145d2d457a5cf7c0bc2) "
            "is shipped in every production ISO (rootfs.img, base.tar.gz, initrd -- three copies). "
            "If the DEV private key is available (Cisco build infrastructure), "
            "an attacker can sign a modified rootfs.img that passes the DEV fallback "
            "and boots in DEV mode on every Diag/SCU-equipped server."
        ),
    },
    {
        "id": "DIAG-F3",
        "severity": "MEDIUM",
        "title": "HSU_KERNEL_IMGVERIFY_ALWAYS_0_IN_DIAG_SCU_OPENSSL_NOT_KERNEL_KEYRING",
        "detail": (
            "initrd hsu-profile.sh sets HSU_KERNEL_IMGVERIFY=0 unconditionally. "
            "This disables the kernel-level verification path (hsu-set-verify-key -> hsu-verify-digest). "
            "All firmware and rootfs verification in Diag/SCU ISOs uses: "
            "'openssl dgst -verify $pub_key_file -signature $sig_file $src_file'. "
            "The DER-encoded keys (container-*-verify-key.der, rootfs-*-verify-key.der) "
            "are present in the initrd's hsu-keys/ but never used (hsu-set-verify-key is not called). "
            "Userspace openssl verification is vulnerable to environment manipulation: "
            "a malicious IMGVERIFY_PUB_KEY_FILE path, altered PATH, or LD_PRELOAD targeting libssl "
            "could redirect verification to an attacker-controlled key. "
            "Kernel keyring verification (when it was the path) would be immune to most userspace attacks."
        ),
    },
    {
        "id": "DIAG-F4",
        "severity": "MEDIUM",
        "title": "HSU_VERIFICATION_KEYS_IN_THREE_LOCATIONS_ALL_IDENTICAL",
        "detail": (
            "All 14 hsu-keys (DEV+REL public keys, DER+PEM) appear in three separate locations: "
            "(1) rootfs.img: /hsu-keys/ (squashfs, read-only); "
            "(2) container base.tar.gz: ./hsu-keys/ (extracted to tmpfs overlay); "
            "(3) initrd: /hsu-keys/ (cpio ramdisk, read-only by process). "
            "IMGVERIFY_PUB_KEY_FILE and HSU_KERNEL_IMGVERIFY control which location is used. "
            "With HSU_KERNEL_IMGVERIFY=0, the PEM key from /hsu-keys/ is passed to openssl. "
            "The path is user-controlled (environment variable IMGVERIFY_PUB_KEY_FILE). "
            "If this variable is modified (e.g., via ALLOWOPTIONS 1 kernel cmdline -> environment), "
            "openssl will use an attacker-supplied key path for signature verification."
        ),
    },
    {
        "id": "DIAG-F5",
        "severity": "LOW",
        "title": "SCU_DUU_WINDOWS_SHIPS_MFC110D_DEBUG_DLL_AND_MSVC2012_RUNTIME",
        "detail": (
            "SCU DUU Windows package (duu-windows/) ships mfc110d.dll -- the DEBUG build "
            "of MFC 11.0 (Visual C++ 2012 MFC library). "
            "mfc110d.dll (file date 2021-01-06, 8.1MB) contains debug symbols, assertion checks, "
            "and additional debugging infrastructure not present in the release build. "
            "Debug MFC binaries in production can expose internal state through debug assertions. "
            "Co-shipped: msvcr110.dll (MSVC 2012 runtime, 2021-01-06), "
            "cjson.dll (cJSON, 2021-01-06), 7z.dll (7-Zip 2021-01-06). "
            "All DLL dates are 2021-01-06 (3+ years pre-shipping). "
            "DriverInstall.exe is PE32+ x86-64 (built 2026-04-21) while its dependency DLLs "
            "are 2021 builds -- dependency/build date mismatch."
        ),
    },
    {
        "id": "DIAG-F6",
        "severity": "LOW",
        "title": "SCU_CONTAINER_SHIPS_WINPE_SQUASHFS_AND_STORCLI_INSIDE_LINUX_SQUASHFS",
        "detail": (
            "SCU container squashfs (7.1.7.260100, 2.7GB) contains: "
            "'tools/winpe.squashfs' -- embedded WinPE (Windows PE) squashfs image inside a Linux squashfs. "
            "WinPE is used for Windows-based driver updates; the SCU boots WinPE via kexec or similar "
            "to run Windows driver installation in a bare-metal Linux boot context. "
            "Also: 'tools/Linux/*/common_tools/LSI/7.0813/Utility/storcli64' and 'storcli2' -- "
            "Broadcom/LSI RAID management CLIs. storcli with physical disk access runs as root "
            "in the HUU/SCU context; RAID controller management commands can modify disk topology "
            "or trigger controller firmware updates. "
            "OS driver variants: CentOS 7.4/7.6, RHEL 8.6, RHEL 9.4, Oracle Linux 7-10 UEK."
        ),
    },
    {
        "id": "DIAG-F7",
        "severity": "LOW",
        "title": "DIAG_SCU_KERNEL_5_14_WITH_2018_USERSPACE_ROOTFS_AND_REDUNDANT_KERNEL_GENERATION",
        "detail": (
            "Diag/SCU ISOs boot with kernel 5.14.0-427.13.1.el9_4.x86_64 (RHEL9/AlmaLinux 9.4, 2024) "
            "but use the 2018-03-09 rootfs.img squashfs for the userspace environment. "
            "Kernel version 5.14.0 is newer than the '4.18' label in the rootfs.img /etc/issue file. "
            "The rootfs.img contains userspace utilities (imgverify, hsu-verify-file, hsu-set-verify-key, "
            "sshd, init scripts) built and tested with kernel 4.18 semantics. "
            "Specifically: hsu-set-verify-key uses raw syscall to the kernel keyring (KEY_ADD_KEY = 250). "
            "The keyring syscall interface is stable across versions, but the 2018 binaries have never "
            "been validated against RHEL9 kernel security features (FSGSBASE, TSX control, etc.). "
            "The HUU ISOs using the same rootfs.img do NOT ship a separate bzImage, "
            "suggesting HUU boots a DIFFERENT kernel -- possibly embedded in the squashfs or EFI partition."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_diagnostics_scu_re",
    "isos": [
        "ucs-diag-7.1.4.260010.iso",
        "ucs-scu-7.1.7.260100.iso",
        "ucs-scu-7.1.7.260200.iso",
    ],
    "finding_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 3, "LOW": 3},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 187, "MEDIUM": 176, "LOW": 163},
    "cumulative_total": 580,
    "key_insight": (
        "SCU/Diag ISOs ENABLE verification (initrd IMG_VERIFY=1) while HUU ISOs BYPASS it "
        "(no initrd, IMG_VERIFY unset). Same rootfs.img binary in both. "
        "ALLOWOPTIONS 1 present in all ISOs; allows disabling verification via boot console. "
        "DEV key fallback in rootfs.img verification continues boot in DEV mode -- "
        "DEV key compromise sufficient to boot arbitrary rootfs without fatal on Diag/SCU."
    ),
}
