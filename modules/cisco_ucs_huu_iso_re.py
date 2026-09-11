"""
Cisco UCS HUU ISO RE Module 1: C220M8 Host Upgrade Utility 6.0.2.260143
ISO: ucs-c220m8-huu-6.0.2.260143.iso
Components: rootfs.img (HSU Linux 4.18 squashfs, 141MB) + container squashfs (894MB)
Platform: C220 M8 (codename: Mustang); OEM: Wistron; Emerald Rapids

8 findings: 0C/2H/2M/4L
Cumulative: 567 [54C+184H+172M+157L]
"""

# ============================================================
# TARGET
# ============================================================

HUU_TARGET = {
    "iso": "ucs-c220m8-huu-6.0.2.260143.iso",
    "hsu_version": "6.0.2.260143",
    "cimc_version": "6.0(2.260095)",
    "bios_version": "C220M8.6.0.2d.0.0527260454",
    "board_controller": "21.0",
    "platform": "C220 M8",
    "codename_internal": "Mustang",
    "oem": "Wistron",
    "cpu_gen": "emeraldrapids",
    "iso_components": {
        "rootfs.img": {"size_mb": 141, "format": "squashfs", "os": "HSU Linux 4.18", "built": "2018-03-09"},
        "container.squashfs": {"size_mb": 894, "format": "squashfs", "python": "3.13", "flask": True},
        "efi.img": {"size_mb": 47},
    },
    "hsu_keys_dir": "/hsu-keys/",
}

# ============================================================
# KEY INVENTORY
# ============================================================

HSU_KEY_INVENTORY = {
    "description": (
        "Both DEV and REL RSA-2048 public keys ship in every production HUU ISO. "
        "Keys present in rootfs.img AND base.tar.gz (16 files total: 8 PEM + 8 DER). "
        "All DEV keys across all roles (container/rootfs/tools) are identical. "
        "All REL keys across all roles (container/rootfs/tools) are identical. "
        "tools-verify-key.pem is identical to tools-rel-verify-key.pem."
    ),
    "dev_key_md5": "4a68951576b7b145d2d457a5cf7c0bc2",
    "rel_key_md5": "1fd3bddb4b88e0e879c4a11868153659",
    "key_algorithm": "RSA-2048",
    "files": [
        "container-dev-verify-key.pem", "container-dev-verify-key.der",
        "container-rel-verify-key.pem", "container-rel-verify-key.der",
        "rootfs-dev-verify-key.pem", "rootfs-dev-verify-key.der",
        "rootfs-rel-verify-key.pem", "rootfs-rel-verify-key.der",
        "tools-dev-verify-key.pem", "tools-dev-verify-key.der",
        "tools-rel-verify-key.pem", "tools-rel-verify-key.der",
        "tools-verify-key.pem", "tools-verify-key.der",
    ],
    "run_mode_file": "/opt/cisco/run_mode",
    "run_mode_values": ["DEV", "REL"],
}

# ============================================================
# VERIFICATION MECHANISM
# ============================================================

IMGVERIFY_SCRIPT = {
    "path": "/usr/sbin/imgverify",
    "type": "POSIX shell script",
    "guard": 'if [ "$IMG_VERIFY" != "1" ]; then exit 0; fi',
    "guard_semantics": "if IMG_VERIFY is not set to exactly '1', script exits 0 (success) with no verification",
    "kernel_path": "hsu-verify-digest -> hsu-set-verify-key (kernel keyring) when HSU_KERNEL_IMGVERIFY=1",
    "userspace_path": "openssl dgst -verify $pub_key_file -signature $sig_file $src_file",
    "signature_format": "HSU-Signature: trailing 30-byte header with checksum:sigsize, then RSA sig, then magic 'HSU-Signature'",
}

FTD_SCRIPT = {
    "path": "/usr/sbin/ftd",
    "purpose": "firmware transfer + decrypt; decrypt-file + imgverify wrapper",
    "guard": 'if [ "$IMG_VERIFY" -eq 1 ]; then decrypt-file ...; else cp $src_file $dst_file; exit 0; fi',
    "bypass_semantics": "if IMG_VERIFY not set, firmware file copied as-is (encrypted), no verification",
}

ISOLINUX_CFG = {
    "path": "isolinux/isolinux.cfg",
    "content": {
        "ALLOWOPTIONS": "1",
        "SERIAL": "0 115200",
        "DEFAULT": "Host-Server-Utility",
        "TIMEOUT": "50",
        "PROMPT": "0",
        "KERNEL": "/bzImage",
        "APPEND": "initrd=/initrd LABEL=Host-Server-Utility root=/dev/ram0",
    },
    "img_verify_in_append": False,
    "note": "APPEND line does not set IMG_VERIFY=1; container verification disabled on every standard HUU boot",
}

# ============================================================
# BOOT INIT CHAIN
# ============================================================

HSU_INIT = {
    "path": "/etc/init.d/hsu-init",
    "telnetd_conditions": [
        "if [ $CONFIG_SEC_UTILS_SIGN_MODE == 'dev' ]: telnetd started",
        "if ! is_cisco_server(): telnetd started (IPMI raw 0x36 0x4d 0x04 0x03 failure)",
    ],
    "is_cisco_server_cmd": "ipmitool raw 0x36 0x4d 0x04 0x03",
    "is_cisco_server_semantics": "IPMI OEM command checks USB-NIC support; failure -> non-Cisco server -> telnetd",
    "run_mode_key_selection": {
        "DEV": "hsu-keys/tools-dev-verify-key.pem (kernel: .der)",
        "REL": "hsu-keys/tools-rel-verify-key.pem (kernel: .der)",
    },
    "container_glob": "find ${ISO_MNTPATH} -name *squashfs",
    "container_glob_note": "first glob match is mounted and executed; no name pinning below squashfs extension",
}

CONTAINER_INIT = {
    "path": "/etc/init.sh",
    "wistron_todo": (
        "# WISTRON-TODO: Temporary fix to workaround the platform ID issue in Mustang. "
        "Revert it once the PID issue is resolved"
    ),
    "wistron_disclosure": "Wistron as OEM; 'Mustang' as C220 M8 internal codename; shipped in production init.sh",
    "usb_nic_addresses": {
        "huu_host": "169.254.0.18/16",
        "bmc": "169.254.0.17",
        "purpose": "tsa_ucs binary communicates with BMC via USB-NIC link-local",
    },
    "tsa_ucs_registers": {
        "r7": "HUUBOOTCOMPLETE flag sent to BMC",
        "r11": "HUU summary file download from BMC",
    },
    "insmod_error_suppression": (
        "insmod of display drivers (drm, ttm, ast, mgag200, drm_kms_helper) "
        "and fnic.ko.xz all redirect stderr to /dev/null 2>&1; "
        "module load failures are silently ignored"
    ),
    "kernel_modules_loaded": [
        "drm.ko.xz", "ttm.ko.xz", "drm_kms_helper.ko.xz", "drm_shmem_helper.ko.xz",
        "drm_ttm_helper.ko.xz", "drm_vram_helper.ko.xz", "ast.ko.xz", "mgag200.ko.xz",
        "gpu-sched.ko.xz", "drm_buddy.ko.xz", "drm_display_helper.ko.xz", "fnic.ko.xz",
    ],
    "hsu_agent_encrypted": "root/hsu.tgz.enc",
    "boot_modes": ["Redfish HUU", "NIHUU", "Configuration", "SduRedfish", "standard"],
    "redfish_agent_script": "hsu-redfish.py (chroot, Python 3.13, Flask/Werkzeug)",
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "HUU-F1",
        "severity": "HIGH",
        "title": "IMGVERIFY_BYPASS_IMG_VERIFY_NOT_SET_IN_KERNEL_CMDLINE",
        "detail": (
            "The HUU container signature verification is silently disabled on every standard HUU boot. "
            "The imgverify script (/usr/sbin/imgverify) checks: "
            "'if [ \"$IMG_VERIFY\" != \"1\" ]; then exit 0; fi' as its first action. "
            "If IMG_VERIFY is not set to '1', the script exits 0 (success) without verifying anything. "
            "The isolinux.cfg APPEND line is: "
            "'APPEND initrd=/initrd LABEL=Host-Server-Utility root=/dev/ram0' -- "
            "IMG_VERIFY=1 is NOT present. "
            "On every standard HUU boot, imgverify returns success without checking the container tarball. "
            "In hsu-init, the verification gate is: "
            "'if ! imgverify /tmp/*-container-*-base.tar.gz >> /tmp/imgverify.log 2>&1; then fatal ...; fi' -- "
            "this gate always passes when IMG_VERIFY is unset. "
            "A replaced container squashfs (containing modified init.sh, hsu-redfish.py, or firmware blobs) "
            "boots without any signature check. "
            "The ftd script has the same bypass: 'if [ \"$IMG_VERIFY\" -eq 1 ]; else cp src dst; exit 0; fi' -- "
            "firmware files copied without decryption or verification. "
            "HUU ISOs can be uploaded to the server via CIMC Redfish: "
            "POST /redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate. "
            "A malicious HUU ISO uploaded via Redfish (requires CIMC credentials) "
            "would execute arbitrary code in the host boot context without any verification gate."
        ),
    },
    {
        "id": "HUU-F2",
        "severity": "HIGH",
        "title": "DEV_VERIFICATION_KEYS_SHIPPED_IN_PRODUCTION_HUU_ISO",
        "detail": (
            "Both DEV and REL RSA-2048 public verification keys are present in every production HUU ISO. "
            "14 key files total (PEM + DER formats) appear in rootfs.img AND in the container base.tar.gz. "
            "All DEV keys (container/rootfs/tools roles) are identical: md5 4a68951576b7b145d2d457a5cf7c0bc2. "
            "All REL keys (container/rootfs/tools roles) are identical: md5 1fd3bddb4b88e0e879c4a11868153659. "
            "The run_mode file (/opt/cisco/run_mode) determines which key set is active. "
            "In DEV mode (run_mode=DEV), the DEV public key is installed into the kernel keyring "
            "via hsu-set-verify-key (makes a raw syscall to the Linux keyring). "
            "The DER-encoded DEV keys are also present, used directly by hsu-set-verify-key. "
            "Consequence: anyone with the HUU ISO can extract the DEV public key and determine the exact key "
            "that production units use in DEV boot mode. "
            "If the DEV private key is compromised (from Cisco's build infrastructure), "
            "an attacker can sign malicious firmware that passes all DEV-mode verification, "
            "including kernel-level hsu-verify-digest checks."
        ),
    },
    {
        "id": "HUU-F3",
        "severity": "MEDIUM",
        "title": "ALLOWOPTIONS_1_ISOLINUX_ARBITRARY_KERNEL_CMDLINE_INJECTION",
        "detail": (
            "The HUU ISO isolinux.cfg contains 'ALLOWOPTIONS 1', enabling any user with boot console "
            "access to modify kernel parameters before HUU starts. "
            "Full isolinux APPEND: 'APPEND initrd=/initrd LABEL=Host-Server-Utility root=/dev/ram0'. "
            "Using ALLOWOPTIONS, an attacker can inject: "
            "'IMG_VERIFY=1' to enable (or force-disable) verification checks; "
            "'init=/bin/sh' to boot to a root shell before hsu-init runs; "
            "'CONFIG_SEC_UTILS_SIGN_MODE=dev' to trigger DEV mode key selection and extra getty terminals; "
            "'console=ttyS0' to redirect console if physical access; "
            "Modified APPEND can also target TFTP boot or alternate root device. "
            "SERIAL 0 115200 is configured: console is available on COM1 at 115200 baud. "
            "This requires physical server console (KVM/iKVM), which is achievable through CIMC's "
            "Serial over LAN (SoL) or KVM-over-IP session."
        ),
    },
    {
        "id": "HUU-F4",
        "severity": "MEDIUM",
        "title": "HSU_LINUX_4_18_KERNEL_FROM_2018_IN_2026_PRODUCTION_HUU",
        "detail": (
            "rootfs.img (HSU Linux) squashfs was built on 2018-03-09, shipping kernel 4.18 "
            "in a 2026 HUU package (version 6.0.2.260143). "
            "Kernel 4.18 reached end-of-life in November 2018. "
            "Post-4.18 security additions missing: Spectre-v1 array index masking improvements, "
            "SWAPGS speculation barrier (CVE-2019-1125), TCP SACK panic (CVE-2019-11477), "
            "SegmentSmack (CVE-2018-5390), BleedingTooth (CVE-2020-12351), "
            "io_uring and eBPF attack surface absent (not backported). "
            "The container (base.tar.gz) runs Python 3.13 and Flask/Werkzeug -- "
            "a modern application stack on an 8-year-old unpatched kernel. "
            "The HUU attaches directly to server hardware (IPMI/IPKVM, USB-NIC to BMC, "
            "direct disk access for firmware flashing). "
            "A kernel exploit in the HUU context yields host-level hardware access before the OS boots."
        ),
    },
    {
        "id": "HUU-F5",
        "severity": "LOW",
        "title": "TELNETD_STARTS_ON_IPMI_CAPABILITY_CHECK_FAILURE",
        "detail": (
            "hsu-init starts telnetd when 'ipmitool raw 0x36 0x4d 0x04 0x03' fails: "
            "'if ! is_cisco_server; then echo Enabling telnetd; telnetd; fi'. "
            "The IPMI raw command checks USB-NIC support (OEM command 0x36/0x4d). "
            "On hardware where this IPMI OEM command is not supported (non-Cisco BMC, "
            "modified firmware, or ipmitool unavailable), the check fails -> telnetd starts. "
            "All shadow passwords are locked ('*') in rootfs.img, providing no authenticated login. "
            "However: if any account's password field is modified in the overlay (writable tmpfs), "
            "telnetd provides unauthenticated network access to the HUU Linux environment. "
            "Telnetd listens on all interfaces, including the USB-NIC at 169.254.0.18 "
            "which is reachable from the BMC network."
        ),
    },
    {
        "id": "HUU-F6",
        "severity": "LOW",
        "title": "X11FORWARDING_YES_ENABLED_IN_HUU_SSH_CONFIG",
        "detail": (
            "rootfs.img sshd_config has X11Forwarding uncommented and set to 'yes'. "
            "HUU Linux has no X11 display server; X11Forwarding provides no legitimate functionality. "
            "X11Forwarding with a malicious DISPLAY connection can abuse the X11 authentication "
            "and socket forwarding path. "
            "sshd_config_readonly variant uses '/var/run/ssh/ssh_host_ecdsa_key' (runtime ephemeral). "
            "Standard sshd_config uses '/etc/ssh/ssh_host_ecdsa_key' (squashfs, read-only). "
            "No RSA host key configured; ECDSA only. "
            "HostKey /etc/ssh/ssh_host_ecdsa_key is in the read-only squashfs: "
            "the same static host key ships in every HUU ISO with the same key material."
        ),
    },
    {
        "id": "HUU-F7",
        "severity": "LOW",
        "title": "WISTRON_TODO_OEM_AND_MUSTANG_CODENAME_IN_PRODUCTION_INIT_SH",
        "detail": (
            "init.sh in the container base.tar.gz contains: "
            "'# WISTRON-TODO: Temporary fix to workaround the platform ID issue in Mustang. "
            "Revert it once the PID issue is resolved'. "
            "Discloses: Wistron as the C220 M8 OEM manufacturer, and 'Mustang' as the C220 M8 "
            "internal platform codename. The TODO comment indicates an unresolved platform ID bug "
            "worked around in production code. "
            "USB-NIC communication hardcodes 169.254.0.18 (HUU host) and 169.254.0.17 (BMC) "
            "as link-local addresses for tsa_ucs BMC communication. "
            "tsa_ucs registers: r7=HUUBOOTCOMPLETE flag, r11=HUU summary download. "
            "The Wistron workaround applies when '/opt/cisco/cisco_server' file is absent: "
            "'cp /etc/enable_usb_nic_wistron.sh /etc/enable_usb_nic.sh' substitutes the NIC script."
        ),
    },
    {
        "id": "HUU-F8",
        "severity": "LOW",
        "title": "KERNEL_MODULE_INSMOD_FAILURES_SILENTLY_SUPPRESSED_IN_CONTAINER_INIT",
        "detail": (
            "init.sh loads 12 kernel modules (display drivers + fnic) with error suppression: "
            "'insmod <module> > /dev/null 2>&1'. "
            "Modules loaded: drm.ko.xz, ttm.ko.xz, drm_kms_helper.ko.xz, drm_shmem_helper.ko.xz, "
            "drm_ttm_helper.ko.xz, drm_vram_helper.ko.xz, ast.ko.xz, mgag200.ko.xz, "
            "gpu-sched.ko.xz, drm_buddy.ko.xz, drm_display_helper.ko.xz, fnic.ko.xz. "
            "rootfs.img kernel cmdline includes 'module.sig_enforce=1' (signature enforcement). "
            "These modules are loaded from the container squashfs, which has a different build "
            "provenance than the rootfs.img kernel. "
            "If module signatures do not match the running kernel's trusted key, insmod fails -- "
            "silently, due to error suppression. The init.sh continues regardless. "
            "There is no verification that graphics or HBA modules loaded successfully "
            "before the HUU agent starts. "
            "A replaced module (from F1 container bypass) would attempt to load; "
            "failure is suppressed and the rest of init continues."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_iso_re",
    "iso": "ucs-c220m8-huu-6.0.2.260143.iso",
    "findings": [f["id"] + " " + f["severity"] + ": " + f["title"] for f in FINDINGS],
    "finding_counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 2, "LOW": 4},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 184, "MEDIUM": 172, "LOW": 157},
    "cumulative_total": 567,
    "codenames_discovered": {
        "C220_M8": "Mustang",
    },
    "oem_disclosed": "Wistron (C220 M8 OEM)",
    "key_architecture": "DEV+REL RSA-2048 public keys shipped in every production ISO",
    "verification_bypass_root_cause": "IMG_VERIFY not set in isolinux.cfg APPEND -> imgverify exits 0 unconditionally",
}
