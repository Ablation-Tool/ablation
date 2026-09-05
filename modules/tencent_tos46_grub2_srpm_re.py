"""
TencentOS Server 4.6 grub2 RE Module
Source: grub2-2.12-20.tl4.ap.3.src.rpm
        /media/cowboy/research/tencentos/4.6/BaseOS-source/
Analysis date: 2026-09-04

PACKAGE: grub2-2.12-20.tl4.ap.3
  Upstream: grub2 2.12
  Tencent releases: -19.tl4.ap.1, -20.tl4.ap.3 (two release lines; ap.3 is current)
  Total patches: ~470 (large upstream patch backport set)
  CVE patches: 3 distinct CVEs (CVE-2024-1048 x2, CVE-2023-4001 rework)
  Security patches: 7 (including IBM Secure Boot for POWER, EFI secure-boot lockdown)

NOTABLE PATCHES:
  0249/0250: CVE-2024-1048 grub-set-bootflag SUID program temp file + resource limit abuse
  0262: CVE-2023-4001 rework — USB UUID collision grub.cfg override
  0150/0215/0395/0397: IBM POWER Secure Boot + EFI chainloader Secure Boot support

SECURITY FINDINGS: TOS46-GRB-F01 through TOS46-GRB-F04
  F01 MEDIUM  CVE-2024-1048 grub-set-bootflag SUID: temp file accumulation DoS + RLIMIT bypass
  F02 MEDIUM  CVE-2023-4001 rework: USB UUID collision grub.cfg override (initial fix broken)
  F03 INFO    IBM POWER Secure Boot lockdown integration (non-standard trust path)
  F04 INFO    EFI chainloader Secure Boot support (attack surface expansion)

ATTACK CHAINS:
  CHAIN-1: local user → grub-set-bootflag RLIMIT_FSIZE signals → /boot filesystem full → boot failure
  CHAIN-2: physical access → USB with matching UUID → grub loads attacker grub.cfg → Secure Boot bypass
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

GRUB2_PACKAGE = {
    "name": "grub2",
    "version": "2.12",
    "release": "20.tl4.ap.3",
    "total_patches": 470,
    "cve_patches": 3,
    "patch_breakdown": {
        "upstream_backports": "~460 (standard RHEL/Fedora grub2 patch set)",
        "cve_targeted": 3,
        "ibm_power_secureboot": 4,
        "efi_secureboot": 2,
    },
    "binary_install_location": "/boot/efi/EFI/tencentos/grubx64.efi",
    "key_suid_binaries": ["grub-set-bootflag (SUID root — CVE-2024-1048 target)"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F01 — CVE-2024-1048: grub-set-bootflag SUID temp file + resource limit abuse
# ──────────────────────────────────────────────────────────────────────────────

GRUB2_CVE_2024_1048 = {
    "finding_id": "TOS46-GRB-F01",
    "cve": "CVE-2024-1048",
    "severity": "MEDIUM",
    "cvss_v3": 3.3,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
    "component": "util/grub-set-bootflag.c (SUID root binary)",
    "patch_files": [
        "0249-grub-set-bootflag-Conservative-partial-fix-for-CVE-2.patch",
        "0250-grub-set-bootflag-More-complete-fix-for-CVE-2024-104.patch",
    ],
    "reporter": "Solar Designer <solar@openwall.com> (via CIQ/Rocky Linux work)",
    "title": (
        "grub-set-bootflag (SUID root): three resource-abuse vectors — "
        "(1) temp file accumulation via RLIMIT_FSIZE/SIGXFSZ to fill /boot; "
        "(2) RLIMIT_NPROC bypass via SUID root escalation; "
        "(3) umask inheritance allows setting grubenv permissions to 0"
    ),
    "description": (
        "grub-set-bootflag is a SUID root binary that writes grubenv variables "
        "(boot_success, boot_indeterminate). It was previously hardened against "
        "CVE-2019-14865 (grubenv truncation via symlink). This is a follow-on audit. "
        "\n"
        "Abuse 1 — Temp file accumulation (incomplete fix for CVE-2019-14865): "
        "  After the CVE-2019-14865 fix, grub-set-bootflag writes to a temp file "
        "  and renames it. If killed before rename, the temp file persists. "
        "  RLIMIT_FSIZE can be set to trigger SIGXFSZ reliably on file write. "
        "  Repeated invocations + SIGXFSZ kills accumulate temp files in /boot "
        "  (or root filesystem if /boot not separate), exhausting inodes. "
        "  Result: filesystem full → no new files → service disruption. "
        "\n"
        "Abuse 2 — RLIMIT_NPROC bypass: "
        "  grub-set-bootflag raises itself to root to 'protect' from signals. "
        "  As root, RLIMIT_NPROC limits no longer apply to the process. "
        "  A user with RLIMIT_NPROC=N can spawn N processes normally; "
        "  after one becomes root via set-bootflag, it no longer counts against N "
        "  → user can fork more processes than allowed. "
        "  If RLIMIT_AS was also set (e.g., in Apache's RLimitNPROC), "
        "  this bypasses the RAM usage limit via the extra forks. "
        "\n"
        "Abuse 3 — umask inheritance: "
        "  mkstemp() applies umask to temp file permissions. "
        "  mkstemp() always uses 0600 base, but 'umask 0600' → permissions = 0. "
        "  No read access to grubenv, but GRUB still boots (reads at UEFI time, "
        "  before filesystem permissions are enforced). Minor nuisance. "
        "\n"
        "Conservative fix (patch 0249): "
        "  Check RLIMIT_FSIZE before proceeding to block the SIGXFSZ vector. "
        "  Does NOT fix all temp file accumulation vectors (other kill signals). "
        "\n"
        "More complete fix (patch 0250): "
        "  Per-user fixed temp filename (.UID suffix instead of XXXXXX random). "
        "  flock() locking on the temp file to serialize concurrent invocations. "
        "  One leftover temp file per user remains possible (acknowledged). "
        "  Solar Designer notes the locking logic is 'hard to reason about' — "
        "  potential for future logic errors in the serialization scheme. "
        "\n"
        "Impact on TOS 4.6: any local user can DoS /boot filesystem. On servers "
        "with separate /boot (standard TOS partition layout), this isolates the "
        "damage to /boot exhaustion — severe if /boot fills and prevents kernel "
        "updates or emergency recovery."
    ),
    "affected_binary": "/sbin/grub2-set-bootflag (SUID root, installed by default)",
    "references": [
        "CVE-2024-1048",
        "reporter: Solar Designer <solar@openwall.com>",
        "Openwall CVE-2024-1048",
        "predecessor: CVE-2019-14865 (grubenv truncation)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F02 — CVE-2023-4001: USB UUID collision grub.cfg override (reworked fix)
# ──────────────────────────────────────────────────────────────────────────────

GRUB2_CVE_2023_4001 = {
    "finding_id": "TOS46-GRB-F02",
    "cve": "CVE-2023-4001",
    "severity": "MEDIUM",
    "cvss_v3": 6.8,
    "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "component": "grub-core/commands/search.c grub_search_fs_uuid()",
    "patch_file": "0262-cmd-search-Rework-of-CVE-2023-4001-fix.patch",
    "original_fix_author": "original CVE-2023-4001 fix (Red Hat)",
    "rework_author": "Nicolas Frayer <nfrayer@redhat.com>",
    "title": (
        "CVE-2023-4001 (rework): grub loads grub.cfg stub from USB drive when partition "
        "UUID matches the actual /boot partition UUID — original 'same-disk' fix broke "
        "RAID and multi-disk setups; rework uses USB device detection + UUID comparison"
    ),
    "description": (
        "CVE-2023-4001: grub's UUID-based search (search.c) can be tricked into loading "
        "a grub.cfg stub from a USB drive if the USB partition's UUID matches the target "
        "UUID. An attacker with physical access creates a USB drive with the same UUID "
        "as the victim's /boot partition. GRUB finds the USB first and loads an "
        "attacker-controlled grub.cfg → arbitrary boot configuration → Secure Boot bypass "
        "if shim was not verifying the grub.cfg. "
        "\n"
        "Original fix (before this patch): forced the grub.cfg stub to be on the same "
        "disk as grub itself. Problem: broke RAID machines (partitions appear under "
        "different device names) and any /boot-on-separate-disk setup. "
        "\n"
        "Reworked fix (this patch): "
        "  1. is_device_usb() — checks EFI device path for USB I/O protocol handle "
        "     using grub_efi_locate_handle(). If the device is USB, return true. "
        "  2. In grub_search_fs_uuid(): when a candidate device is found: "
        "     a. Check if it's a USB device "
        "     b. If USB: check if its UUID matches the current grub device UUID "
        "     c. If UUID matches AND device is USB → deny (UUID collision attack) "
        "     d. If UUID doesn't match OR not USB → proceed normally "
        "\n"
        "The rework only blocks USB devices with UUID collision; non-USB devices with "
        "same UUID are still allowed (for legitimate RAID/multi-path setups). "
        "\n"
        "Remaining attack surface: "
        "  - Thunderbolt/USB-C docks with Thunderbolt security disabled: "
        "    is_device_usb() uses GRUB_EFI_USB_IO_GUID. Thunderbolt devices may "
        "    appear differently in EFI device paths. "
        "  - NVMe/SATA external enclosures via eSATA: not detected as USB. "
        "  - grub_efi_locate_handle() may behave differently across UEFI firmware "
        "    implementations — vendor-specific firmware may present USB differently. "
        "\n"
        "Impact: physical access attack enabling Secure Boot bypass. "
        "Requires knowing the /boot partition UUID (obtainable by booting the system "
        "once normally or reading /etc/fstab from recovered data)."
    ),
    "physical_access_required": True,
    "bypass_condition": "shim is not verifying grub.cfg integrity (standard configuration)",
    "references": [
        "CVE-2023-4001",
        "original fix + rework by Nicolas Frayer <nfrayer@redhat.com>",
        "grub-core/commands/search.c grub_search_fs_uuid()",
        "GRUB_EFI_USB_IO_GUID detection",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F03 — IBM POWER Secure Boot lockdown integration (INFO)
# ──────────────────────────────────────────────────────────────────────────────

GRUB2_IBM_SECBOOT = {
    "finding_id": "TOS46-GRB-F03",
    "cve": None,
    "severity": "INFO",
    "component": "grub-core/kern/ieee1275/, grub-core/loader/",
    "patch_files": [
        "0150-ieee1275-enter-lockdown-based-on-ibm-secure-boot.patch",
        "0395-powerpc-ieee1275-Enter-lockdown-based-on-ibm-secure-.patch",
        "0397-powerpc-ieee1275-Read-the-db-and-dbx-secure-boot-var.patch",
    ],
    "title": (
        "TOS 4.6 grub2 includes IBM POWER Secure Boot lockdown support via "
        "IBM Open Firmware Secure Boot (OFSB) — non-standard trust chain for POWER hardware; "
        "grub reads db/dbx variables via IBM's proprietary secure-boot interface"
    ),
    "description": (
        "IBM POWER systems use OpenFirmware/IEEE 1275 instead of UEFI. "
        "IBM's Secure Boot implementation for POWER uses OFSB (Open Firmware Secure Boot) "
        "with different variable namespaces than standard UEFI db/dbx. "
        "\n"
        "Patches 0150/0395: enter grub lockdown mode based on IBM OFSB state "
        "  (ibm-secure-boot property in Open Firmware device tree). "
        "\n"
        "Patch 0397: read db/dbx secure-boot variables via IBM's interface "
        "  (different from UEFI's GetVariable(db)/GetVariable(dbx)). "
        "\n"
        "Security implication: Two different Secure Boot trust chains depending on platform: "
        "  - x86-64: standard UEFI → shim (with TOS SM2 extension) → grub2 "
        "  - POWER: IBM OFSB → grub2 (no shim layer) "
        "\n"
        "The POWER chain bypasses shim entirely, including TOS's SM2 addition. "
        "Whether this is intentional (POWER systems don't support shim's PE signing) "
        "or a gap depends on TOS deployment on POWER hardware."
    ),
    "references": [
        "0150-ieee1275-enter-lockdown-based-on-ibm-secure-boot.patch",
        "IBM OFSB documentation",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F04 — EFI chainloader Secure Boot support (INFO)
# ──────────────────────────────────────────────────────────────────────────────

GRUB2_EFI_CHAINLOADER = {
    "finding_id": "TOS46-GRB-F04",
    "cve": None,
    "severity": "INFO",
    "component": "grub-core/loader/ EFI chainloader",
    "patch_file": "0215-Add-secureboot-support-on-efi-chainloader.patch",
    "title": (
        "grub2 EFI chainloader: Secure Boot support patch allows grub to chainload "
        "other EFI binaries while passing Secure Boot state — expands chainload attack surface "
        "if chainloaded binary is not properly verified"
    ),
    "description": (
        "The EFI chainloader module allows grub2 to load and execute other EFI binaries "
        "(e.g., another bootloader, a network stack). The Secure Boot support patch "
        "ensures the chainloaded binary is verified against the standard db/dbx trust store "
        "before being handed control. "
        "\n"
        "Without this patch: grub chainloads without Secure Boot verification → attacker "
        "with grub console access (or grub.cfg control) can chainload an unsigned binary. "
        "\n"
        "With this patch: verification occurs, but the security depends on: "
        "  - The integrity of db (which on TOS 4.6 includes SM2 keys per shim F08) "
        "  - Whether the grub.cfg itself is protected (it is NOT signed by default) "
        "\n"
        "A compromised grub.cfg (via CVE-2023-4001 or direct modification) can "
        "set chainloader target to any binary, and if that binary has an SM2 signature "
        "from a trusted TOS CA, it passes Secure Boot verification."
    ),
    "references": [
        "0215-Add-secureboot-support-on-efi-chainloader.patch",
        "cross-reference: TOS46-SHM-F08 (SM2 Secure Boot extension)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = {
    "CHAIN-1": {
        "title": "Local user → grub-set-bootflag RLIMIT_FSIZE abuse → /boot DoS",
        "severity": "MEDIUM",
        "steps": [
            "1. Local user (any login with access to /sbin/grub2-set-bootflag)",
            "2. Set RLIMIT_FSIZE = 0 (or small value)",
            "3. Loop: exec grub2-set-bootflag boot_success in background",
            "4. RLIMIT_FSIZE triggers SIGXFSZ killing each instance after temp file created",
            "5. Temp files accumulate in /boot (or root filesystem)",
            "6. /boot fills (inode or block exhaustion)",
            "7. kernel update: rpm -Uvh fails (cannot write to /boot)",
            "8. Grub update: grub2-mkconfig fails",
            "9. Next reboot: grub loads last known good config (resilient but stale)",
        ],
        "prerequisites": "Local login access; pre-patch TOS 4.6",
        "chain_links": ["F01"],
    },
    "CHAIN-2": {
        "title": "Physical access → USB UUID clone → grub.cfg injection → Secure Boot bypass",
        "severity": "MEDIUM",
        "steps": [
            "1. Attacker obtains target system's /boot partition UUID",
            "   (e.g., boot from live USB and read /etc/fstab or blkid)",
            "2. Create USB drive with partition UUID matching /boot UUID",
            "3. Place attacker-controlled grub.cfg on USB's EFI partition",
            "4. Insert USB, reboot target system",
            "5. GRUB's UUID search finds USB partition first (pre-patch or partial fix)",
            "6. Loads attacker grub.cfg → set linux /boot/vmlinuz init=/bin/sh",
            "7. Or: chainload an SM2-signed malicious EFI binary (with TOS SM2 CA key)",
            "8. Secure Boot chain broken; attacker code runs",
        ],
        "physical_access": True,
        "prerequisites": "Physical access; knowledge of /boot UUID",
        "chain_links": ["F02"],
        "chain_with_shim": "TOS46-SHM-F08 (SM2 signing allows legitimate-looking chainload)",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-GRB-F01": GRUB2_CVE_2024_1048,
    "TOS46-GRB-F02": GRUB2_CVE_2023_4001,
    "TOS46-GRB-F03": GRUB2_IBM_SECBOOT,
    "TOS46-GRB-F04": GRUB2_EFI_CHAINLOADER,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "package": "grub2-2.12-20.tl4.ap.3",
        "total_patches": 470,
        "cve_patches": 3,
        "attack_chains": list(ATTACK_CHAINS.keys()),
        "findings": [
            {
                "id": k,
                "severity": v.get("severity", "?"),
                "cvss": v.get("cvss_v3"),
                "cve": v.get("cve"),
            }
            for k, v in FINDINGS.items()
        ],
    }, indent=2))
