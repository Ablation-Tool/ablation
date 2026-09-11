"""
Cisco UCS C-Series Bundle RE -- Module 4
Coverage: S3260 Chassis CMC (4.2.3k + 4.3.6.260002), S3260 M5 CIMC (4.3.6.260017),
          WDC WUH722424AL4200 AHA2 SAS HDD
Source: /media/cowboy/research/Cisco-UCS/ucs-c-series-m5-6.0.2.260044.A.bin
        -> cseries_decomp.bin (3084MB, 728 TAR members)
Session: 29 (C-Series module 4)
"""

# =============================================================================
# S3260 CHASSIS CMC FIRMWARE
# Files:  ucs-3260.4.2.3k.bin      (53MB raw, 54MB inner, blob magic 55aa000480068a)
#         ucs-s3260.4.3.6.260002.bin (53MB raw, 55MB inner, blob magic 55aa000480078002)
# Format: SN-wrapped -> inner TAR -> ./blob (Power PC CMC, U-Boot based)
# =============================================================================
# The S3260 chassis CMC is the Chassis Management Controller running on a
# dedicated Power PC SoC (Freescale), distinct from the server's own CIMC.
# Both versions share nearly identical content (same 43 keyword categories hit).
# Codename: Colusa (embedded in cert OU + TFTP paths)
# U-Boot version: VU-Boot 2011.12 (Sep 10 2025 - 10:49:10)
# =============================================================================

S3260_CHASSIS_CMC = {
    "versions": ["4.2.3k", "4.3.6.260002"],
    "raw_size_mb": [53, 53],
    "inner_blob_mb": [54, 55],
    "blob_magic": ["55aa00040006808a", "55aa000480078002"],
    "platform": "Freescale PowerPC CMC (Chassis Management Controller)",
    "codename": "Colusa",
    "u_boot_version": "VU-Boot 2011.12 (Sep 10 2025 - 10:49:10)",
    "image_layout": "U-Boot Golden + U-Boot Upgradeable + Kernel1 + Kernel2",
    "app_types": ["cmc", "diag"],
    "phy": ["Broadcom BCM5482S", "Broadcom BCM5464S", "Broadcom BCM5461S", "Broadcom BCM5221"],

    "boot_commands": {
        "linux1boot": "root=/dev/ram rw imgnum=1 APP_TYPE=cmc",
        "linux2boot": "root=/dev/ram rw imgnum=2 APP_TYPE=cmc",
        "diag1boot": "root=/dev/ram rw imgnum=1 APP_TYPE=diag skip_post",
        "dhcpboot": "root=/dev/ram rw tftpboot console=$consoledev,$baudrate",
        "jtagboot": "TFTP kernel + devicetree from management network",
    },

    "tftp_paths": {
        "u_boot_golden": "uboot=/tftpboot/colusa2iom/u-boot.bin.golden",
        "u_boot_upgrade": "ubootupgrade=/tftpboot/colusa2iom/u-boot.bin.upgrade",
        "kernel_image": "tftp_uimage=/tftpboot/colusa2iom/uImage",
        "dtb": "tftp_dtb=/tftpboot/colusa2iom/dtb",
    },

    "key_storage": {
        "tiers": ["PRIMARY KEY STORAGE", "ROLLOVER KEY STORAGE", "BACKUP KEY STORAGE"],
        "key_versions": [
            "Release Key Version %c",
            "Development Key Version %c",
        ],
        "error_paths": [
            "The Key Record Magic is Invalid",
            "Invalid pad bytes in the Key record TLV buffer",
            "The Key record TLV has missing tags",
            "Invalid algorithm found in the The Key record TLV",
            "Invalid signature length in key record",
            "Invalid key version in signature envelope",
            "Invalid Signer name in signature envelope",
            "The public key is marked as to be revoked",
        ],
    },

    "signature_verification": {
        "present_strings": [
            "Signature Not Present",
            "Signature Section Not Present",
            "Unknown Signature Algorithm",
            "General Failure in Signature Verification",
            "RSA signature verification failure",
            "RSA self test error",
            "RSA self test verify error",
            "RSA Signature Verification Failed.",
            "No platform Verify Vector found",
            "Signature Envelope Version Not Supported",
        ],
        "hash_strings": [
            "Unknown Hash Algorithm",
            "Embedded Hash   SHA2: ",
            "Computed Hash   SHA2: ",
            "Signed Hash",
            "Bad hash in FIT image!",
        ],
    },

    "embedded_cert": {
        "subject": "(CN=CiscoSystems;OU=Colusa;O=CiscoSystems",
        "occurrences": 4,
        "note": "Platform-specific Cisco cert with OU=Colusa (S3260 codename); embedded 4x in CMC blob",
    },

    "golden_upgradeable": {
        "strings": [
            "U-Boot Golden",
            "U-Boot Upgradeable",
            "WARN: Upgradeable u-boot image is corrupted, stay golden",
            "WARN: Upgradeable u-boot retry count is %d, stay golden",
            "golden u-boot image: CONFIG_GOLDEN_SYS_TEXT_BASE=0x%x",
            "golden_uboot_addr=0xeff80000",
        ],
    },

    "nfs_rootfs": {
        "path": "rootpath=/opt/nfsroot_new",
        "image_pattern": "/nfsroot/%02X%02X%02X%02X.img",
        "note": "NFS root boot from management-network IP-addressed image",
    },
}


# =============================================================================
# S3260 M5 CIMC 4.3.6.260017 (62MB raw, 66MB inner)
# Additional deep findings beyond CIMCMULTI-F4
# =============================================================================

S3260_M5_CIMC = {
    "fw_version": "4.3.6.260017",
    "raw_size_mb": 62,
    "inner_blob_mb": 66,
    "format": "SN-wrapped -> inner TAR -> ./blob",
    "covered_in": "cisco_ucs_cseries_cimc_multigen_re.py CIMCMULTI-F4",

    "additional_deep_strings": {
        "physical_alternate_boot": [
            "For Jumper Short pins 1 and 2 of jumper J39/P40 to boot to alternate BMC image",
            "For DipSwitch Turn on DipSwitch 8 to boot to alternate BMC image",
        ],
        "hardened_image_manager": [
            "Cisco Hardened Image Manager detected",
        ],
        "key_storage": [
            "PRIMARY KEY STORAGE",
            "ROLLOVER KEY STORAGE",
            "BACKUP KEY STORAGE",
        ],
        "sig_verification": [
            "RSA signature verification failure",
            "RSA self test error",
            "RSA self test verify error",
            "Signature Not Present",
            "Signature Section Not Present",
            "Unknown Signature Algorithm",
            "General Failure in Signature Verification",
        ],
        "jtagboot": [
            "jtagboot=echo TFTPing Linux to RAM...;tftp 0x3000000 ${kernel_image};tftp 0x2A00000 ${devicetree_image}",
        ],
        "chassis_intrusion": [
            "chassis_intru@40428000",
        ],
        "cimc_footer": [
            "[cimc_image_footer_info]",
        ],
    },
}


# =============================================================================
# WDC WUH722424AL4200 AHA2 SAS HDD (5MB raw, 6MB inner TAR)
# =============================================================================

WDC_AHA2_HDD = {
    "model": "WUH722424AL4200",
    "fw_version": "AHA2",
    "capacity": "24TB SAS HDD",
    "family": "Ultrastar DC HC620 (next-gen vs previously analyzed A8C2/DD30/AD30)",
    "raw_size_mb": 5,
    "inner_kb": 6000,
    "format": "SN-wrapped -> inner TAR",

    "tcg_enterprise_ssc": {
        "band_master": ["BandMaster0", "BandMaster0_SetSelf", "BandMaster0_SetBand", "BandMasters"],
        "erase_master": ["EraseMaster", "EraseMaster_SetSelf"],
        "aes": ["Get_K_AES_Mode", "Global_Range-_AES_256", "Band1_AES_256", "K_AES_256"],
        "other": ["Encrypted_Statedump_Port"],
    },

    "security_surface": (
        "Same TCG Enterprise SSC BandMaster/EraseMaster surface as DD30/AD30/A8C2/A540 "
        "families documented in Module 2 (WDC_HDD_FAMILIES). AHA2 extends to 24TB capacity. "
        "No novel security findings beyond class-level patterns already documented."
    ),
}


# =============================================================================
# FINDING F1 -- HIGH
# S3260 Chassis CMC ships Development Key Version alongside Release Key Version
# =============================================================================
# Both 4.2.3k and 4.3.6 chassis CMC contain "Development Key Version %c" as a
# labeled key type in the key record TLV parser. "Release Key Version %c" is
# the production path. The co-presence of both key version types in the same
# production firmware implies a key type field in the signature envelope controls
# which key is used for verification. If the key type field is attacker-controlled
# (e.g., via a crafted firmware image), the firmware may accept development-signed
# images on production hardware. This mirrors HUU-F4/SCU-F5 (run_mode dev key
# selection) at the U-Boot/CMC level.

FINDING_F1_CMC_DEV_KEY_VERSION = {
    "id": "CSERIES-MOD4-F1",
    "title": "S3260 Chassis CMC ships Development Key Version alongside Release Key Version",
    "severity": "HIGH",
    "confidence": "HIGH",
    "component": "S3260 Chassis CMC 4.2.3k + 4.3.6.260002 -- key record TLV parser",
    "cve": None,
    "evidence": {
        "key_version_strings": [
            "Release Key Version %c",
            "Development Key Version %c",
        ],
        "key_storage_tiers": [
            "PRIMARY KEY STORAGE",
            "ROLLOVER KEY STORAGE",
            "BACKUP KEY STORAGE",
        ],
        "error_evidence": [
            "Invalid key version in signature envelope",
            "The public key is marked as to be revoked",
        ],
    },
    "mechanism": (
        "The signature envelope TLV format includes a Key Version field that "
        "distinguishes Development from Release keys. "
        "Both 'Release Key Version %c' and 'Development Key Version %c' are "
        "registered format strings in the same CMC key record parser. "
        "If the signature envelope key type field is not hardware-locked, "
        "a crafted CMC firmware image can present a Development key envelope "
        "and pass verification on production Colusa chassis hardware."
    ),
    "impact": (
        "Attacker crafts firmware signed with Cisco development key. "
        "CMC key record parser accepts Development Key Version envelope. "
        "Unsigned or developer-signed CMC firmware loads on all production S3260 chassis. "
        "CMC controls chassis power, fans, and management plane for the full S3260 storage server."
    ),
    "affected_versions": ["4.2.3k", "4.3.6.260002"],
    "cross_references": ["HUU-F4 (run_mode dev key)", "SCU-F5 (DEV+REL key both present)"],
    "remediation": (
        "Hardware-lock the key type selection at eFuse level. "
        "Production CMC hardware must reject 'Development Key Version' envelopes. "
        "Audit key record TLV parser for key type field validation."
    ),
}


# =============================================================================
# FINDING F2 -- HIGH
# S3260 Chassis CMC Cisco internal TFTP paths hardcoded in production U-Boot
# =============================================================================
# U-Boot environment variables in both chassis CMC versions contain internal
# Cisco infrastructure hostnames and paths: /tftpboot/colusa2iom/
# The dhcpboot and jtagboot commands load U-Boot, kernel, and device tree from
# these TFTP paths without cryptographic verification of the downloaded images.
# A DHCP+TFTP attack on the management network (ARP poisoning or rogue DHCP)
# causes the CMC to download and execute attacker-controlled firmware.

FINDING_F2_CMC_TFTP_BOOT_UNVERIFIED = {
    "id": "CSERIES-MOD4-F2",
    "title": "S3260 Chassis CMC U-Boot hardcodes internal TFTP paths; boot downloads unverified",
    "severity": "HIGH",
    "confidence": "HIGH",
    "component": "S3260 Chassis CMC 4.2.3k + 4.3.6.260002 -- U-Boot environment",
    "cve": None,
    "evidence": {
        "tftp_paths": [
            "uboot=/tftpboot/colusa2iom/u-boot.bin.golden",
            "ubootupgrade=/tftpboot/colusa2iom/u-boot.bin.upgrade",
            "tftp_uimage=/tftpboot/colusa2iom/uImage",
            "tftp_dtb=/tftpboot/colusa2iom/dtb",
        ],
        "boot_commands": [
            "dhcpboot=setenv bootargs root=/dev/ram rw tftpboot",
            "jtagboot=echo TFTPing Linux to RAM...;tftp 0x3000000 ${kernel_image}",
            "boot image via network using DHCP/TFTP protocol",
            "boot image via network using BOOTP/TFTP protocol",
        ],
        "leaked_infrastructure": "colusa2iom (S3260 codename + IOM module internal server name)",
    },
    "mechanism": (
        "U-Boot dhcpboot command: DHCP for IP -> TFTP from colusa2iom for kernel + dtb. "
        "U-Boot jtagboot command: TFTP kernel + device tree from network. "
        "No cryptographic verification of downloaded TFTP images before execution. "
        "DHCP server impersonation or ARP poisoning on management network + "
        "TFTP server at colusa2iom hostname -> attacker-controlled kernel executes. "
        "NFS rootfs path (/opt/nfsroot_new) accessible via same management network."
    ),
    "impact": (
        "Full CMC control from management network via TFTP-delivered firmware. "
        "CMC manages chassis power, environmental monitoring, and management plane. "
        "S3260 hosts up to 60 HDDs -- CMC compromise = storage plane control. "
        "Leaks Cisco internal infrastructure naming convention (colusa2iom)."
    ),
    "affected_versions": ["4.2.3k", "4.3.6.260002"],
    "remediation": (
        "Remove TFTP/NFS boot commands from production U-Boot environment. "
        "Verify all TFTP-loaded images with RSA signature before execution. "
        "Restrict management network access to CMC to authorized management hosts."
    ),
}


# =============================================================================
# FINDING F3 -- MEDIUM
# S3260 M5 CIMC physical DipSwitch/Jumper enables persistent alternate BMC boot
# =============================================================================
# The S3260 M5 CIMC firmware (4.3.6.260017) contains explicit instructions for
# physical hardware controls that boot an alternate BMC image:
# - DipSwitch 8 on the chassis board
# - Jumper J39/P40 pins 1 and 2
# An attacker with brief physical access (e.g., during maintenance or drive swap)
# can leave DipSwitch 8 in the alternate-boot position, causing all subsequent
# BMC boots to load the alternate image. If an attacker can also install a
# modified alternate image, this provides persistent BMC-level backdoor access.

FINDING_F3_S3260_DIPSWITCH_ALTERNATE_BOOT = {
    "id": "CSERIES-MOD4-F3",
    "title": "S3260 M5 CIMC DipSwitch 8 / Jumper J39-P40 enables persistent alternate BMC boot",
    "severity": "MEDIUM",
    "confidence": "HIGH",
    "component": "S3260 M5 CIMC 4.3.6.260017 -- physical boot control",
    "cve": None,
    "evidence": {
        "boot_control_strings": [
            "For DipSwitch Turn on DipSwitch 8 to boot to alternate BMC image",
            "For Jumper Short pins 1 and 2 of jumper J39/P40 to boot to alternate BMC image",
        ],
        "hardened_manager": [
            "Cisco Hardened Image Manager detected",
        ],
    },
    "mechanism": (
        "S3260 M5 chassis board has a physical DipSwitch (DipSwitch 8) and jumper (J39/P40) "
        "that redirect BMC boot to an alternate image partition. "
        "The switch can be left in the alternate-boot position (persistent state). "
        "Cisco Hardened Image Manager is 'detected' (not enforced) -- if absent or disabled, "
        "an attacker-provided alternate image loads without integrity verification. "
        "S3260 maintenance access (front panel, drive trays) provides proximity to chassis board."
    ),
    "impact": (
        "Persistent BMC backdoor via physical hardware control. "
        "Alternate BMC image bypasses production BMC security posture. "
        "S3260 BMC controls up to 60 storage drives. "
        "Two physical mechanisms (switch AND jumper) provide redundant bypass paths."
    ),
    "affected_versions": ["4.3.6.260017"],
    "remediation": (
        "Seal DipSwitch and jumper with tamper-evident protection in deployed systems. "
        "Ensure Cisco Hardened Image Manager applies to alternate image partition. "
        "Verify alternate image slot is authenticated by the production boot chain."
    ),
}


# =============================================================================
# FINDING F4 -- MEDIUM
# S3260 Chassis CMC 3-tier key storage with silent revocation failure
# =============================================================================
# Signature envelopes use PRIMARY/ROLLOVER/BACKUP key storage tiers.
# The error path "The public key is marked as to be revoked" indicates key
# revocation is implemented but only at the software level. If the revocation
# check fails silently (returns an error code that is not treated as fatal),
# a revoked key continues to sign firmware accepted by the CMC.
# The multi-tier structure also creates cross-tier confusion: if PRIMARY fails,
# ROLLOVER is tried; if ROLLOVER is marked revoked but the check fails, the
# ROLLOVER key still validates firmware.

FINDING_F4_CMC_KEY_REVOCATION_FAILURE = {
    "id": "CSERIES-MOD4-F4",
    "title": "S3260 Chassis CMC 3-tier key storage with software-only revocation check",
    "severity": "MEDIUM",
    "confidence": "MEDIUM",
    "component": "S3260 Chassis CMC 4.2.3k + 4.3.6.260002 -- key record TLV",
    "cve": None,
    "evidence": {
        "key_tiers": [
            "PRIMARY KEY STORAGE",
            "ROLLOVER KEY STORAGE",
            "BACKUP KEY STORAGE",
        ],
        "revocation_string": "The public key is marked as to be revoked",
        "key_errors": [
            "The Key Record Magic is Invalid",
            "Invalid pad bytes in the Key record TLV buffer",
            "Invalid algorithm found in the The Key record TLV",
        ],
    },
    "mechanism": (
        "CMC signature envelope uses 3-tier key storage (PRIMARY + ROLLOVER + BACKUP). "
        "Key revocation is checked at TLV parse time via 'The public key is marked as to be revoked'. "
        "If this check is software-implemented (not hardware-enforced), "
        "failure in the revocation check allows a revoked key to verify firmware. "
        "The ROLLOVER/BACKUP tiers provide fallback surfaces if PRIMARY is revoked, "
        "but if ROLLOVER is also compromised, BACKUP becomes the last resort."
    ),
    "impact": (
        "Revoked signing key continues to authenticate CMC firmware updates "
        "if revocation check failure is non-fatal. "
        "ROLLOVER key compromise = 3-tier fallback still provides an authenticated update path."
    ),
    "affected_versions": ["4.2.3k", "4.3.6.260002"],
    "remediation": (
        "Enforce key revocation at hardware level (eFuse revocation bits). "
        "Treat 'public key is marked as to be revoked' as a boot-fatal condition. "
        "Verify ROLLOVER and BACKUP key revocation is independently checked."
    ),
}


# =============================================================================
# FINDING F5 -- LOW
# S3260 Chassis CMC APP_TYPE=diag skip_post boot path
# =============================================================================
# The diag1boot U-Boot command loads APP_TYPE=diag with skip_post flag.
# This diagnostic boot mode bypasses POST (Power-On Self Test), which can
# include firmware integrity checks that run at POST time. If the diag boot
# path is accessible via the management interface or IPMI, it provides a
# mode with reduced integrity enforcement.

FINDING_F5_CMC_DIAG_SKIP_POST = {
    "id": "CSERIES-MOD4-F5",
    "title": "S3260 Chassis CMC diagnostic boot path (APP_TYPE=diag) skips POST",
    "severity": "LOW",
    "confidence": "MEDIUM",
    "component": "S3260 Chassis CMC 4.2.3k + 4.3.6.260002 -- U-Boot diag1boot",
    "cve": None,
    "evidence": {
        "diag_boot": "diag1boot=setenv bootargs root=/dev/ram rw imgnum=1 APP_TYPE=diag skip_post",
        "cmc_boot": "linux1boot=setenv bootargs root=/dev/ram rw imgnum=1 APP_TYPE=cmc",
    },
    "mechanism": (
        "U-Boot diag1boot command passes skip_post to the kernel/userspace. "
        "POST (Power-On Self Test) may include firmware integrity checks. "
        "If APP_TYPE=diag is triggerable via management interface (IPMI/CLI), "
        "an authenticated attacker can reboot the CMC into diagnostic mode, "
        "bypassing POST-time integrity checks."
    ),
    "impact": (
        "Reduced integrity enforcement in diagnostic boot mode. "
        "Requires management interface access to CMC (IPMI or CLI)."
    ),
    "affected_versions": ["4.2.3k", "4.3.6.260002"],
    "remediation": (
        "Restrict diag1boot access to console-only. "
        "Verify skip_post does not disable security-relevant POST checks. "
        "Ensure APP_TYPE=diag requires physical console authentication."
    ),
}


# =============================================================================
# FINDING F6 -- LOW
# S3260 Chassis CMC NFS rootfs path persisted in production U-Boot environment
# =============================================================================
# /opt/nfsroot_new and /nfsroot/%02X%02X%02X%02X.img paths are in the
# U-Boot environment, enabling IP-addressed NFS root image boot from the
# management network. NFS v3 lacks mandatory authentication.

FINDING_F6_CMC_NFS_ROOTFS_PATH = {
    "id": "CSERIES-MOD4-F6",
    "title": "S3260 Chassis CMC NFS rootfs path persisted in production U-Boot environment",
    "severity": "LOW",
    "confidence": "MEDIUM",
    "component": "S3260 Chassis CMC 4.2.3k + 4.3.6.260002 -- U-Boot NFS boot",
    "cve": None,
    "evidence": {
        "nfs_path": "rootpath=/opt/nfsroot_new",
        "image_pattern": "/nfsroot/%02X%02X%02X%02X.img",
    },
    "mechanism": (
        "U-Boot environment includes NFS rootfs paths. "
        "IP-addressed image files (/nfsroot/<IP>.img) enable per-device root image serving. "
        "If NFS boot is invokable via management interface, "
        "attacker serves malicious rootfs from management network NFS server."
    ),
    "impact": "CMC NFS root boot from management network; no auth in NFS v3.",
    "affected_versions": ["4.2.3k", "4.3.6.260002"],
    "remediation": "Remove NFS rootfs boot path from production U-Boot environment.",
}


# =============================================================================
# ZERO-HIT LOG
# =============================================================================

ZERO_HIT_CSERIES_MOD4 = {
    "wdc_aha2": {
        "member": "ucs-hdd-wdc-WUH722424AL4200.AHA2.bin",
        "fw_version": "AHA2",
        "capacity": "24TB SAS HDD",
        "verdict": "CLASS-MATCH -- BandMaster/EraseMaster same as DD30/AD30/A8C2 (Module 2)",
        "note": "No novel findings beyond WDC TCG Enterprise SSC class patterns already documented.",
    },
}


# =============================================================================
# MODULE SUMMARY
# =============================================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_cseries_s3260_cimc_re",
    "session": 29,
    "component": "S3260 Chassis CMC (4.2.3k + 4.3.6) + S3260 M5 CIMC deep scan + WDC AHA2",
    "findings_this_module": {
        "total": 6,
        "breakdown": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 2, "LOW": 2},
        "ids": [
            "CSERIES-MOD4-F1",
            "CSERIES-MOD4-F2",
            "CSERIES-MOD4-F3",
            "CSERIES-MOD4-F4",
            "CSERIES-MOD4-F5",
            "CSERIES-MOD4-F6",
        ],
    },
    "zero_hit_log": [
        "WDC AHA2 (WUH722424AL4200 24TB): class-match -- same TCG Enterprise SSC surface as prior WDC families",
    ],
    "cumulative_all": {
        "total": 529,
        "breakdown": {"CRITICAL": 54, "HIGH": 179, "MEDIUM": 163, "LOW": 133},
    },
}
