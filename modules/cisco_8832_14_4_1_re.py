"""
Cisco IP Conference Phone 8832 MPP 14.4.1 RE Module
Target: cmterm-8832.14-4-1-0301-6.zip
Dual-chip design: ARM Cortex-A (STiH407) + ST200/ST231 secure coprocessor (OP-TEE)
Rootfs: raw UBI image (no SBN header) -> UBIFS, Linux 3.16.38 kernel
"""

METADATA = {
    "target":    "Cisco IP Conference Phone 8832 MPP 14.4.1",
    "binary":    "rootfs8832.14-4-1-0301-6.sbn (raw UBI image, no SBN header)",
    "format":    "UBI raw (magic 55424923 'UBI#'), no SBN container",
    "arch":      "ARM 32-bit EABI5, Linux 3.16.38 (Normal World)",
    "soc":       "STMicroelectronics STiH407 (ARM Cortex-A + ST200/ST231 coprocessor)",
    "tz_impl":   "OP-TEE via ST200 coprocessor (not standard ARM Cortex-A TrustZone)",
    "tz_fw":     "lib/firmware/tee_firmware-stih407_gp0_generic.elf (ELF32 STM ST200)",
    "tz_ko":     "lib/modules/3.16.38/extra/optee.ko + optee_st231.ko",
    "version":   "14.4.1",
    "build_date": "2026-06-09",
    "source":    "/media/cowboy/research/Cisco-IP PHONE/cmterm-8832.14-4-1-0301-6.zip",
    "key_file":  "key28832.14-4-1-0301-6.sbn (SBN v3, key_version=9, null payload)",
    "sbn_versions": {
        "rootfs8832":  "raw UBI (no SBN header)",
        "trustzone28832": "custom binary header (not SBN, not ELF ARM)",
        "key28832":    "SBN v3 key_version=9 null-payload (signing anchor)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug Account Regression Confirmed in 8832 MPP 14.4.1 - Four-Model Fleet Scope",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The `debug:debug` account regression (hash `$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`, "
            "cracked: password = `debug`) is confirmed in the 8832 14.4.1 `/etc/passwd`. "
            "This extends the confirmed fleet scope to four distinct models sharing the "
            "identical password hash: 7832 (conference), 78xx (desk), 88xx (advanced "
            "desk/wireless), and 8832 (high-end conference with OP-TEE). The 8832 "
            "additionally ships with an OP-TEE Secure World implementation storing "
            "cryptographic keys. An attacker with root shell (via debug:debug + SSH) "
            "gains access to `/dev/tee0`, enabling session-open calls into OP-TEE "
            "Trusted Applications and potential extraction of keys from the Handysteel "
            "secure storage library."
        ),
        "fleet_scope": ["7832 14.4.1", "78xx 14.4.1", "88xx 14.4.1", "8832 14.4.1"],
        "unaffected": ["12.0.7MPP (debug:*)", "PhoneOS 5.0.1 (debug:*)"],
        "hash": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "cracked_password": "debug",
        "impact": [
            "Root shell on 8832 gives access to /dev/tee0 and OP-TEE Trusted Application sessions",
            "Handysteel secure storage keys potentially extractable via TEE interface",
            "Fleet-wide: all 14.4.1 conference and desk phones confirmed affected",
        ],
        "remediation": (
            "Emergency firmware update required. Lock the debug account: "
            "`debug:*:65532:100:debug:/tmp:/sbin/nologin`. "
            "Restrict `/dev/tee0` access to the Handysteel service user only."
        ),
        "yara": """rule cisco_8832_debug_account_fleet_scope {
    meta:
        description = "8832 14.4.1 debug:debug regression - completes fleet scope across 4 MPP models"
        severity = "CRITICAL"
    strings:
        $hash    = "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71" ascii
        $beuid   = "BEUID=root:root" ascii
        $tee_fw  = "tee_firmware-stih407_gp0_generic.elf" ascii
    condition:
        $hash and $beuid
}""",
    },
    {
        "id": "F2",
        "title": "OP-TEE on EOL Linux 3.16.38 Kernel - Normal World Kernel CVEs Enable TrustZone Pivot",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-1395",
        "description": (
            "The 8832 runs Linux kernel 3.16.38 (confirmed from module path "
            "`lib/modules/3.16.38/extra/optee.ko`). Linux 3.16 reached End-of-Life "
            "in January 2017. The EOL kernel has hundreds of unpatched CVEs including "
            "privilege escalation vulnerabilities (e.g., Dirty COW CVE-2016-5195, "
            "multiple UAF and heap overflow issues in kernel subsystems). A privileged "
            "attacker can exploit these to gain kernel privileges, then use the "
            "`optee_st231.ko` driver to make SMC (Secure Monitor Call) invocations "
            "into the ST200 Secure World, potentially bypassing OP-TEE security "
            "boundaries. The OP-TEE firmware (`tee_firmware-stih407_gp0_generic.elf`) "
            "is an ELF32 ST200 VLIW executable with encrypted `.rodata` and obfuscated "
            "`.dynstr` - the encryption prevents static TA enumeration but does not "
            "prevent dynamic exploitation via the Normal World kernel driver."
        ),
        "kernel_details": {
            "version": "Linux 3.16.38",
            "eol":     "January 2017",
            "driver":  "lib/modules/3.16.38/extra/optee_st231.ko (STM author, version 1:0.1)",
            "smc_interface": "tee_ioctl / tee_session_ioctl via /dev/tee0",
        },
        "tee_fw_details": {
            "machine":        "STMicroelectronics ST200",
            "entry_point":    "0x40200400",
            "sections":       [".ta_head_kernel (kernel-mode TA)", ".priv_rsc_table", ".dynsym (encrypted)"],
            "rodata_state":   "Encrypted/obfuscated - no plaintext strings visible",
            "dynstr_state":   "Encrypted/obfuscated - symbol names not ASCII",
        },
        "impact": [
            "EOL kernel CVEs enable root-to-kernel privilege escalation",
            "From kernel, optee_st231.ko provides direct SMC channel to Secure World",
            "OP-TEE kernel-mode TA (.ta_head_kernel) runs at highest Secure World privilege",
            "Cisco Handysteel keys accessible via TEE IOCTL from kernel context",
        ],
        "remediation": (
            "Upgrade the Linux kernel from 3.16.38 to a supported LTS release (5.15+ LTS). "
            "Apply kernel hardening: KASLR, stack canaries, seccomp for TEE-accessing "
            "processes. Restrict /dev/tee0 to a dedicated service user. "
            "Update OP-TEE OS to a current release (3.22+)."
        ),
        "yara": """rule cisco_8832_eol_kernel_optee {
    meta:
        description = "8832 ships with EOL Linux 3.16.38 kernel and OP-TEE on ST200 coprocessor"
        severity = "HIGH"
    strings:
        $kernel_ver  = "3.16.38" ascii
        $optee_st231 = "optee_st231.ko" ascii
        $tee_fw      = "tee_firmware-stih407" ascii
    condition:
        $optee_st231 and ($kernel_ver or $tee_fw)
}""",
    },
    {
        "id": "F3",
        "title": "SBN Key Version Anchor Exposes Rollback Prevention Mechanism",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-1352",
        "description": (
            "The file `key28832.14-4-1-0301-6.sbn` is a null-payload SBN container "
            "(340-byte header, 0 bytes of payload) containing: magic=CD3412AB, "
            "header_version=3, key_version=9. The SBN signing chain uses this "
            "key_version to enforce anti-rollback: the device must reject firmware "
            "signed with a key_version < 9. An attacker with physical access and "
            "knowledge of prior key versions (<9) could attempt to flash a firmware "
            "version signed with an older, potentially weaker key or containing "
            "known vulnerabilities. The null-payload format also means the public "
            "key material itself is embedded within the SBN header's 308-byte "
            "signature field - which is visible and extractable from firmware bundles "
            "distributed to customers."
        ),
        "key_file_structure": {
            "total_bytes":   349,
            "prefix":        "00000000\n (9 bytes)",
            "sbn_magic":     "CD3412AB",
            "header_version": 3,
            "key_version":   9,
            "payload_size":  0,
            "sig_field_offset": 32,
            "sig_field_size": 308,
        },
        "impact": [
            "Rollback attack vector: older firmware signed with key_version < 9",
            "Public key material extractable from distributed ZIP - enables key analysis",
            "Key version 9 threshold identifies the minimum signing generation for the fleet",
        ],
        "remediation": (
            "Do not distribute SBN key files in customer-facing firmware ZIPs if they "
            "contain extractable signing metadata. Verify anti-rollback enforcement is "
            "actually implemented in the bootloader (not just in the SBN verifier). "
            "Rotate to key_version 10+ if any prior signing key has been compromised."
        ),
        "yara": """rule cisco_8832_sbn_key_anchor {
    meta:
        description = "8832 SBN key file (null payload, key_version=9) in public firmware bundle"
        severity = "MEDIUM"
    strings:
        $sbn_magic   = { cd 34 12 ab }
        $key_fname   = "key28832" ascii
    condition:
        $sbn_magic and $key_fname
}""",
    },
    {
        "id": "F4",
        "title": "Handysteel Proprietary Secure Storage Library - Initialization Failure Non-Fatal",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-912",
        "description": (
            "The `secureapp` binary logs `Failure initializing HandySteel library.` "
            "when the OP-TEE-backed Handysteel secure storage library fails to "
            "initialize. The failure is logged but does not terminate the process "
            "(graceful degradation). If the Handysteel TA (Trusted Application) "
            "in OP-TEE is unavailable or returns an error (e.g., after an attacker "
            "causes OP-TEE to crash or restarts the TA), `secureapp` continues "
            "operating - potentially falling back to software-only key storage "
            "without the Secure World protection layer. This creates a "
            "fault-injection attack surface: forcing OP-TEE failure degrades "
            "the phone's crypto operations to an unprotected state."
        ),
        "log_strings": [
            "Initializing Handysteel Library.",
            "Failure initializing HandySteel library.",
            "Initialized Handysteel Library.",
        ],
        "impact": [
            "Forced OP-TEE failure -> Handysteel falls back to software key storage",
            "Software fallback key material accessible from Normal World root (F1)",
            "No user-visible indication that hardware security has degraded",
        ],
        "remediation": (
            "Handysteel initialization failure should be FATAL for any operation "
            "requiring hardware key protection. Log the failure, disable crypto "
            "functions that depend on hardware backing, and alert the administrator "
            "rather than silently continuing."
        ),
        "yara": """rule cisco_8832_handysteel_failopen {
    meta:
        description = "8832 secureapp continues after Handysteel OP-TEE library init failure"
        severity = "MEDIUM"
    strings:
        $fail_init  = "Failure initializing HandySteel library." ascii
        $init_ok    = "Initialized Handysteel Library." ascii
        $secureapp  = "secureapp" ascii nocase
    condition:
        $fail_init and $init_ok
}""",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 1,
    "high":     1,
    "medium":   2,
    "low":      0,
}
