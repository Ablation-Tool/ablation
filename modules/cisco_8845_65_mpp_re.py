"""
Cisco IP Phone 8845/8865 MPP RE Module -- Both 12.0.7 and 14.4.1
Targets:
  cmterm-8845_65.12-0-7MPP0201-66_REL.zip (built 2025-06-17)
  cmterm-8845_65.14-4-1-0401-1_REL.zip    (built 2026-07-07)
Models: 8845 (5MP camera), 8865 (5MP camera + KEM expansion)
Architecture: Single-chip ARM 32-bit, SquashFS rootfs
Source: /media/cowboy/research/Cisco-IP PHONE/

Key difference from 88xx family: single chip (no PLATFORM_2 or PLATFORM_3).
Hardware additions vs 88xx: 5MP built-in camera (pcam binary, libcamera_client.so).

SBN inventory (12.0.7):
  fbi8845_65.BEV-01-006P.sbn     -- first-stage bootloader
  kern8845_65.12-0-7MPP0201-66.sbn -- kernel
  rootfs8845_65.12-0-7MPP0201-66.sbn -- 62.2 MB SquashFS, 3237 inodes
  sb28845_65.BEV-01-020P.sbn     -- second-stage bootloader
  vc48845_65.12-0-7MPP0201-66.sbn -- VideoCore 4 firmware

SBN delta (14.4.1 vs 12.0.7):
  rootfs: 62.2 MB -> 73.8 MB (+11.5 MB, 1887 inodes)
  No m0patch, no preloader (unlike 88xx tri-chip)

Extraction:
  unsquashfs rootfs8845_65.12-0-7MPP0201-66.sbn -> /tmp/8845_12_p1
  unsquashfs rootfs8845_65.14-4-1-0401-1.sbn    -> /tmp/8845_14_p1
"""

METADATA = {
    "target":   "Cisco IP Phone 8845/8865 MPP Firmware (12.0.7 and 14.4.1)",
    "models":   "8845 (built-in 5MP camera), 8865 (5MP camera + KEM expansion)",
    "platform": "Single-chip ARM 32-bit, SquashFS",
    "camera":   "pcam binary + libcamera_client.so (8845/8865 only, not present in 88xx/8832)",
    "accounts_12_0_7": {
        "root":  "!:0:0:root:/home/root:/sbin/nologin (locked)",
        "debug": "*:65532:100:debug:/tmp:/bin/false (LOCKED -- secure baseline)",
    },
    "accounts_14_4_1": {
        "root":  "!:0:0:root:/home/root:/sbin/nologin (locked)",
        "debug": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71 ACTIVE -- password: debug; shell: /usr/sbin/debugsh",
    },
    "service_privilege_12_0_7": {
        "wlanmgr": "app:services -- FIXED in 12.0.7 (unlike 88xx 12.0.7 which had root:root)",
        "btman":   "root:root -- unfixed (#BEUID=app:services commented out)",
        "btrl":    "root:root -- unfixed (#BEUID=app:services commented out)",
    },
    "service_privilege_14_4_1": {
        "wlanmgr": "app:services -- FIXED (unchanged from 12.0.7)",
        "btman":   "root:root -- unfixed (unchanged from 12.0.7)",
        "btrl":    "root:root -- unfixed (unchanged from 12.0.7)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug:debug Account Active in 14.4.1 with debugsh Shell -- Same Regression as Fleet",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "8845_65 14.4.1 contains the fleet-wide debug account regression: "
            "`debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`, password `debug`, "
            "shell `/usr/sbin/debugsh`. "
            "In 12.0.7, the account is locked (`debug:*`, shell `/bin/false`). "
            "The regression was confirmed in the single extracted SquashFS rootfs. "
            "The debugsh shell binary is identical to the version documented in "
            "cisco_88xx_14_mpp_re.py F1: ncurses+readline, `system()`, "
            "`start_interactive_shell()`, `btcli`, `cipcfg`, `netstat`, `dmesg`. "
            "On 8845 and 8865, the debug shell combined with access to the camera "
            "API (`pcam`, `libcamera_client.so`) provides a potential path to "
            "access the built-in camera stream via the debug account. "
            "See cisco_phoneos_5_0_1_re.py F1 for fleet-wide scope and "
            "cisco_88xx_14_mpp_re.py F1 for debugsh capability details."
        ),
        "hash":          "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "password":      "debug (cracked)",
        "shell_12_0_7":  "/bin/false (locked)",
        "shell_14_4_1":  "/usr/sbin/debugsh (interactive debug shell)",
        "camera_risk":   "pcam + libcamera_client.so: debug shell + 5MP camera on 8845/8865",
        "impact": [
            "debug:debug SSH login on 8845/8865 14.4.1",
            "debugsh shell: btcli, cipcfg, netstat, system() access",
            "Camera access via pcam/libcamera_client.so from debug session",
        ],
        "remediation": "Lock debug account -- same as cisco_phoneos_5_0_1_re.py F1.",
    },
    {
        "id": "F2",
        "title": "btman and btrl Run as root:root Across Both 12.0.7 and 14.4.1 -- wlanmgr Already Fixed",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "description": (
            "Unlike the 88xx 12.0.7 (where wlanmgr was root:root), the 8845_65 12.0.7 "
            "already has `wlanmgr.sh` running as `BEUID=app:services` (not commented out). "
            "The wlanmgr privilege fix was applied earlier on the 8845_65 platform. "
            "However, `btman.sh` and `btrl.sh` retain `BEUID=root:root` with "
            "`#BEUID=app:services` commented out in both 12.0.7 and 14.4.1 -- "
            "no remediation applied across either version. "
            "On 8845 and 8865, btman manages Bluetooth pairing, RFCOMM, A2DP, and HFP "
            "for Bluetooth headset support. The phone's Bluetooth stack process running "
            "as root amplifies any Bluetooth protocol vulnerability to full device compromise. "
            "The 8845/8865 camera (pcam) could also be accessed from a root shell obtained "
            "via a btman exploit."
        ),
        "wlanmgr_12_0_7": "FIXED -- app:services (fixed earlier than 88xx 12.0.7)",
        "wlanmgr_14_4_1": "FIXED -- app:services (unchanged, maintained)",
        "btman_status":   "root:root in both 12.0.7 and 14.4.1",
        "btrl_status":    "root:root in both 12.0.7 and 14.4.1",
        "impact": [
            "btman root:root on 8845/8865: Bluetooth exploit -> root -> camera access",
            "btrl root:root: Bluetooth rate limiter runs with full root privileges",
        ],
        "remediation": "Apply the same fix as wlanmgr to btman.sh and btrl.sh on all 8845_65 versions.",
    },
    {
        "id": "F3",
        "title": "apigateway Unauthenticated API (Port 8443) Accessible over Wi-Fi on Camera-Equipped Phone",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "The apigateway unauthenticated API (root:root, port 8443, no auth in OpenAPI) "
            "is present in both 8845_65 12.0.7 and 14.4.1, identical to "
            "cisco_8832_12_mpp_re.py F1. "
            "The 8865 includes 802.11 Wi-Fi, making the apigateway reachable over "
            "the Wi-Fi interface (same impact amplification as 88xx 8861/8865). "
            "On the 8845 (wired-only), apigateway is reachable via LAN. "
            "The 8845/8865 specific impact: the `POST /api/Ui/v1/GetDeviceScreenshot` "
            "endpoint can capture the phone screen (which may show active call content, "
            "directory entries, or conference participant information) and upload it "
            "to an attacker-supplied URL. "
            "See cisco_8832_12_mpp_re.py F1 for full endpoint documentation."
        ),
        "reference": "cisco_8832_12_mpp_re.py F1 (full endpoint list), cisco_88xx_12_mpp_re.py F3 (Wi-Fi amplification)",
        "camera_note": "GetDeviceScreenshot endpoint can capture camera view via phone screen -- not direct camera API",
        "impact": [
            "Wi-Fi attack range on 8865: unauthenticated apigateway reachable over 802.11",
            "GetDeviceScreenshot: conference screen capture to attacker URL on camera-equipped phone",
            "All F1 impacts from cisco_8832_12_mpp_re.py apply here",
        ],
        "remediation": "Same as cisco_8832_12_mpp_re.py F1.",
    },
    {
        "id": "F4",
        "title": "pcam Camera Binary Not Stripped -- 5MP Camera Attack Surface with Full Symbol Table",
        "severity": "LOW",
        "cvss": 3.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The `pcam` binary (`/usr/bin/pcam`, ELF 32-bit ARM) and `libcamera_client.so` "
            "are present only in the 8845_65 family (not in 88xx, 8832, or 9xxx). "
            "The pcam binary is NOT stripped (confirmed from ELF header: "
            "`BuildID[sha1]=1c3df57468e4b220e6f1d7301dc56de3a0c83a98, not stripped`). "
            "An unstripped binary provides the full symbol table for security research, "
            "lowering the barrier for finding camera stream access issues, "
            "buffer overflows, or command injection in the camera pipeline. "
            "The actual camera stream protocol and authentication requirements "
            "could not be determined from strings analysis (no RTSP/HTTP/auth strings "
            "found in pcam strings), suggesting the protocol detail is in libcamera_client.so "
            "or communicated via D-Bus IPC. "
            "The combination of debug:debug active in 14.4.1 (F1) + pcam not stripped "
            "provides a research path: SSH as debug -> inspect pcam internals -> "
            "identify camera stream access."
        ),
        "binary":   "/usr/bin/pcam (not stripped)",
        "library":  "/usr/lib/libcamera_client.so",
        "models":   "8845 (5MP camera), 8865 (5MP camera + KEM)",
        "impact":   ["Unstripped binary aids camera pipeline security analysis", "debug:debug (14.4.1 F1) + pcam = live camera access research path"],
        "remediation": "Strip pcam and libcamera_client.so before production builds.",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 2,
    "high":     1,
    "medium":   0,
    "low":      1,
    "version_notes": {
        "12_0_7": "debug locked; wlanmgr fixed; btman/btrl root:root; apigateway unauthenticated; built 2025-06-17",
        "14_4_1": "debug:debug regression; debugsh shell; all other issues unchanged; built 2026-07-07",
    },
    "vs_88xx": (
        "8845_65 is a single-chip device; no m0patch Cortex-M0, no preloader, no PLATFORM_3. "
        "wlanmgr was fixed earlier in 8845_65 12.0.7 (app:services) vs 88xx 12.0.7 (root:root). "
        "Unique feature: 5MP built-in camera (pcam + libcamera_client.so, not stripped)."
    ),
}
