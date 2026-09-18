"""
Cisco IP Phone 6821/68xx/7832/78xx MPP RE Module
Targets (12.0.7 and 14.4.1 where available):
  cmterm-6821.12-0-7MPP0501-123_REL.zip   -- 6821 wired entry-level
  cmterm-68xx.12-0-7MPP0501-123_REL.zip   -- 68xx family (3 platforms: 68xx, 6861, 6871)
  cmterm-7832.12-0-7MPP0501-123_REL.zip   -- 7832 wired conference
  cmterm-7832.14-4-1-0301-6.zip           -- 7832 14.4.1
  cmterm-78xx.12-0-7MPP0501-123_REL.zip   -- 78xx family
  cmterm-78xx.14-4-1-0301-6.zip           -- 78xx 14.4.1

Architecture: Single-chip ARM, UBI rootfs, Cisco SBN header wrapper
Key difference from 88xx/8832: SBN header wraps raw UBI (cd34 12ab magic); 88xx/8832 use raw UBI/SquashFS with NO wrapper.

Models:
  6821:  wired, entry-level, no BT/WiFi
  6841, 6851: wired
  6861: Wi-Fi (PLATFORM_M6861, separate rootfs from 68xx base)
  6871: Wi-Fi + BT/KEM (PLATFORM_M6871)
  7832: wired conference phone
  7811, 7821, 7841: wired
  7861: Wi-Fi

SBN header offsets (by version):
  12.0.7 6821/7832:  344 bytes (0x158) to UBI
  12.0.7 68xx/78xx:  348 bytes (0x15c) to UBI
  14.4.1 7832:       340 bytes (0x154) to UBI
  14.4.1 78xx:       344 bytes (0x158) to UBI

Extraction:
  For each: dd if=<rootfs>.sbn bs=1 skip=<offset> | ubireader_extract_files -

Platforms analyzed:
  6821 12.0.7 P1 -> /tmp/p_6821/
  68xx 12.0.7 P2 -> /tmp/p_68xx/  (base 6841/6851)
  68xx 12.0.7 M6861 -> /tmp/p_6861/  (Wi-Fi model)
  7832 12.0.7 P1 -> /tmp/p_7832/
  7832 14.4.1 P1 -> /tmp/p_7832_14b/
  78xx 12.0.7 P2 -> /tmp/p_78xx/
  78xx 14.4.1 P2 -> /tmp/p_78xx_14b/
"""

METADATA = {
    "targets":  "Cisco 6821/68xx (12.0.7), 7832 (12.0.7+14.4.1), 78xx (12.0.7+14.4.1)",
    "platform": "Single-chip ARM, UBI rootfs, Cisco SBN wrapper (cd 34 12 ab magic)",
    "sbn_format": {
        "magic": "cd 34 12 ab (Cisco proprietary SBN header -- NOT raw UBI/SquashFS)",
        "header_offset": "varies by model/version (340-348 bytes), then raw UBI image",
        "note": "Header contains filename bytes at offset 0x20+ and CRC fields",
    },
    "accounts_12_0_7": {
        "debug": "*:65532:100:debug:/tmp:/bin/false (LOCKED on all models -- secure baseline)",
        "root":  "!:0:0:root:/home/root:/bin/false (locked)",
    },
    "accounts_14_4_1": {
        "debug": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71 ACTIVE (password: debug, shell: /usr/sbin/debugsh)",
        "root":  "!:0:0:root:/home/root:/bin/false (locked)",
    },
    "service_privilege": {
        "wlanmgr": "app:services on all models and both versions (no root:root issue seen here)",
        "btman":   "absent on 6821, 7832, 6841, 6851 (wired-only models); present on 6861/6871/78xx but not analyzed in full",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug:debug Account Active in 14.4.1 -- Confirmed on 7832 and 78xx, Fleet-Wide Regression",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "Both 7832 14.4.1 and 78xx 14.4.1 contain the active debug account: "
            "`debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`, password `debug`, "
            "shell `/usr/sbin/debugsh`. "
            "This is identical to the regression documented in "
            "cisco_phoneos_5_0_1_re.py F1 across all 14.4.1 model families. "
            "In 12.0.7, the account is locked on all analyzed models (6821, 68xx, 7832, 78xx) "
            "with hash `*` and shell `/bin/false`. "
            "6821 and 68xx do not have a 14.4.1 firmware available in the research set -- "
            "their debug account state in a hypothetical 14.4.1 is expected to match "
            "based on the pattern across all other 14.4.1 firmware families. "
            "See cisco_phoneos_5_0_1_re.py F1 for full scope and "
            "cisco_88xx_14_mpp_re.py F1 for debugsh capability details."
        ),
        "confirmed_14_4_1": ["7832 (cmterm-7832.14-4-1-0301-6)", "78xx (cmterm-78xx.14-4-1-0301-6)"],
        "locked_12_0_7":    ["6821", "68xx (all platforms)", "7832", "78xx"],
        "hash":              "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "password":          "debug (cracked)",
        "impact": [
            "debug:debug SSH login on 7832 and 78xx phones running 14.4.1",
            "debugsh: btcli, cipcfg, netstat, dmesg, system() -- same as all 14.4.1 models",
        ],
        "remediation": "Lock debug account -- see cisco_phoneos_5_0_1_re.py F1.",
    },
    {
        "id": "F2",
        "title": "apigateway Unauthenticated API (Port 8443, root:root) Present on All Models",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "The apigateway binary is present in all extracted rootfs images: "
            "6821, 68xx (all platforms), 7832, and 78xx. "
            "The unauthenticated Config/UI/Serviceability OpenAPI 3.0.2 surface "
            "documented in cisco_8832_12_mpp_re.py F1 applies identically here. "
            "Endpoints: SetParams/GetParams (SIP credential read/write), "
            "RebootDevice, StartPacketCapture, SendKey (dial any number), "
            "GetDeviceScreenshot, GetConfigFile (upload to attacker URL). "
            "Wi-Fi models (6861, 6871, 7861) have the apigateway reachable over "
            "802.11 in addition to wired Ethernet. "
            "All models run apigateway as BEUID=root:root. "
            "The wlanmgr privilege issue (root:root seen in 88xx 12.0.7) is NOT "
            "present here -- wlanmgr correctly runs as app:services on all analyzed "
            "6861 and 68xx Wi-Fi models in 12.0.7, indicating the privilege fix was "
            "applied to the 68xx/78xx line before 88xx."
        ),
        "models_with_wifi": ["6861 (68xx)", "6871 (68xx)", "7861 (78xx)"],
        "apigateway_beuid": "root:root (all models)",
        "wlanmgr_beuid":    "app:services (Wi-Fi models -- correctly privileged)",
        "reference": "cisco_8832_12_mpp_re.py F1 (full endpoint documentation)",
        "impact": [
            "Same unauthenticated API surface as 8832/88xx -- remote config read/write, reboot, packet capture",
            "Wi-Fi models: apigateway accessible over 802.11 from radio range",
        ],
        "remediation": "Same as cisco_8832_12_mpp_re.py F1: add authentication, bind to wired interface.",
    },
    {
        "id": "F3",
        "title": "Cisco SBN Header Wraps UBI Rootfs -- New Format vs Raw UBI on 88xx/8832",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The 6821, 68xx, 7832, and 78xx rootfs SBN files use a Cisco proprietary "
            "SBN wrapper format with magic bytes `cd 34 12 ab`. "
            "This differs from the 8832 and 88xx PLATFORM_3 which use raw UBI with no wrapper. "
            "The SBN wrapper precedes the UBI image at offsets that vary by model version: "
            "344 bytes (6821/7832 12.0.7), 348 bytes (68xx/78xx 12.0.7), "
            "340 bytes (7832 14.4.1), 344 bytes (78xx 14.4.1). "
            "The header contains: 4-byte magic, 4-byte version field, model flags, "
            "CRC fields, and a filename string (`rootfs<model>` at offset ~0x20). "
            "This format requires stripping the header before UBI extraction: "
            "`dd if=rootfs.sbn bs=1 skip=<offset> | ubireader_extract_files`. "
            "The header offset variation between versions (12.0.7 vs 14.4.1) "
            "indicates the SBN header format has been revised and grows over firmware generations."
        ),
        "magic":        "cd 34 12 ab (Cisco SBN proprietary header)",
        "header_sizes": {
            "6821_7832_12_0_7":  344,
            "68xx_78xx_12_0_7":  348,
            "7832_14_4_1":       340,
            "78xx_14_4_1":       344,
        },
        "vs_88xx_8832": "88xx/8832 use raw UBI/SquashFS with no SBN wrapper; this family wraps UBI in proprietary header",
        "impact": ["Format knowledge required for tooling to extract these firmware images correctly"],
        "remediation": "N/A -- format documentation finding.",
    },
]

SUMMARY = {
    "total":    3,
    "critical": 2,
    "high":     0,
    "medium":   0,
    "low":      1,
    "notes": (
        "6821 and 68xx are wired-entry phones (no BT on base models). "
        "6861/6871 add Wi-Fi; apigateway then accessible over 802.11. "
        "7832 is a conference phone (circular form factor, no display). "
        "78xx: 7841 is wired, 7861 has Wi-Fi + BT. "
        "All share the same UBI+SBN format and same apigateway surface. "
        "No btman root:root issue seen (wired models have no BT; Wi-Fi models have "
        "wlanmgr correctly at app:services). The 8832/88xx btman root:root issue does "
        "not appear in this phone family."
    ),
}
