"""
Cisco IP Phone 88xx MPP 12.0.7 Tri-Chip RE Module
Target: cmterm-88xx.12-0-7MPP0501-123_REL.zip
Models: 8841, 8851, 8861, 8865 (and variants with Wi-Fi/Bluetooth)
Architecture: Tri-chip (PLATFORM_1, PLATFORM_2, PLATFORM_3), ARM 32-bit
Source: /media/cowboy/research/Cisco-IP PHONE/cmterm-88xx.12-0-7MPP0501-123_REL.zip
Version: 12.0.7 MPP (MPP0501-123)

Chip layout -- each phone boots exactly one PLATFORM:
  PLATFORM_1 (SquashFS, 61.7 MB): rootfs88xx -- primary ARM chip, Wi-Fi/BT models
  PLATFORM_2 (SquashFS, 60.2 MB): rootfs288xx -- secondary ARM chip (includes m0patch Cortex-M0)
  PLATFORM_3 (UBI, 81.5 MB):      rootfs388xx -- tertiary ARM chip, includes preloader

SBN inventory (firmware archive):
  rootfs88xx.12-0-7MPP0501-123.sbn        -- 61.7 MB, SquashFS v4.0 zlib
  rootfs288xx.12-0-7MPP0501-123.sbn       -- 60.2 MB, SquashFS v4.0 zlib
  rootfs388xx.12-0-7MPP0501-123.sbn       -- 81.5 MB, UBI image
  m0patch288xx.BE-01-001P.sbn             -- 15.4 KB, uImage Cortex-M0 patch
  preloader88xx.BE-01-008P.sbn            -- 40.8 KB, Bootastic v2.6.0.C-rc2
  kern88xx, kernel288xx, kernel388xx      -- per-platform kernels
  fbi88xx, boot1288xx                     -- first-stage bootloaders (P1, P2)
  sb288xx, sb2288xx, sb2388xx             -- second-stage bootloaders
  ssb288xx                                -- secondary secure boot (P2)
  vc488xx                                 -- VideoCore 4 firmware (P1)

Extraction:
  unsquashfs rootfs88xx -> /tmp/88xx_p1
  unsquashfs rootfs288xx -> /tmp/88xx_p2
  ubireader_extract_files rootfs388xx -> /tmp/88xx_p3/1698109867/rootfs/

Key delta vs cisco_8832_12_mpp_re.py:
  + Wi-Fi (wlanmgr, hostapd), Bluetooth (btman, btrl, btrl, obex-client, brcm_patchram_plus)
  + Cortex-M0 coprocessor (m0patch, 2016 build)
  + Preloader "non-secure loader" with UART fallback
  + apigateway (F1 from 8832 module) reachable over Wi-Fi on 8861/8865 models
  - No TrustZone/oemloader SBNs (present in 8832 only)
  - No key28832.sbn fleet key (8832 only)
"""

METADATA = {
    "target":    "Cisco IP Phone 88xx MPP Firmware 12.0.7 (MPP0501-123)",
    "models":    "8841, 8851, 8861, 8865 (Wi-Fi/BT variants: 8861, 8865)",
    "platform":  "Tri-chip: P1 SquashFS + P2 SquashFS + Cortex-M0 + P3 UBI + preloader",
    "arch":      "ARM 32-bit (all chips), plus ARM Cortex-M0 (m0patch)",
    "version":   "12.0.7 MPP; same build date as 8832 12.0.7 (2026-03-17)",
    "codename":  "bigeasy_mpp (from kernel.core_pattern in sysctl.conf)",
    "accounts": {
        "P1_P2": {
            "root":  "!:0:0:root:/home/root:/bin/false (locked)",
            "debug": "*:65532:100:debug:/tmp:/bin/false (LOCKED with * -- account never active)",
        },
        "P3_UBI": {
            "root":  "!:0:0:root:/home/root:/sbin/nologin (locked, hardened shell)",
            "debug": "!:65532:100:debug:/tmp:/bin/false (locked -- same as P1/P2)",
        },
    },
    "m0patch": {
        "file":    "m0patch288xx.BE-01-001P.sbn",
        "type":    "u-boot legacy uImage, ARM Cortex-M0, Firmware (Not compressed)",
        "build":   "2016-04-05T19:10:15Z (10 years before 12.0.7 release date 2026-03-17)",
        "size":    "14728 bytes",
        "load_ep": "0x62000000 / 0x62000000",
    },
    "preloader": {
        "file":    "preloader88xx.BE-01-008P.sbn",
        "version": "Bootastic v2.6.0.C-rc2",
        "type":    "non-secure loader (literal string in binary)",
        "ddr":     "mt41k256m16_630 (Micron DDR3, 256M x 16)",
        "size":    "40852 bytes",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Bluetooth Manager (btman, btrl) and Wi-Fi Manager (wlanmgr) Run as root on All Platforms -- BEUID=app:services Commented Out",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "description": (
            "Three network-facing services on the 88xx run as BEUID=root:root despite "
            "having the correct low-privilege setting commented out in their init scripts. "
            "In all three files (`btman.sh`, `btrl.sh`, `wlanmgr.sh`), the line "
            "`#BEUID=app:services` appears commented out immediately above `BEUID=root:root`. "
            "This pattern is consistent across all three extracted platforms (P1, P2, P3). "
            "The `app:services` user would be the correct reduced-privilege owner; "
            "the comment-out indicates a deliberate development-time override that was "
            "not reverted for production:\n\n"
            "1. btman (Bluetooth manager): Full Bluetooth stack process. Manages BT pairing, "
            "connection profiles, and Bluetooth call audio routing. Attack surface: "
            "Bluetooth L2CAP, RFCOMM, A2DP, HFP, OBEX. Running as root amplifies any "
            "Bluetooth stack vulnerability to full system compromise.\n\n"
            "2. btrl (Bluetooth rate limiter / resource manager): Companion to btman, "
            "also root:root. Handles bandwidth and connection limits for BT. "
            "Lower complexity than btman but root execution is still unwarranted.\n\n"
            "3. wlanmgr (Wi-Fi manager): Controls 802.11 interface via wpa_supplicant, "
            "manages hostapd for Wi-Fi AP mode (soft-AP), handles SSID scanning, "
            "credential management, and hostapd config generation "
            "(`wpa_passphrase = %s`, `/etc/wifi/hostapd_template.conf`). "
            "Root execution gives any Wi-Fi stack exploit full system access. "
            "The wlanmgr binary is NOT stripped (confirmed ELF -- not stripped), "
            "making function-level exploit development easier than against a stripped binary.\n\n"
            "These three services are unique to the 88xx family (not present in 8832, "
            "which has no Wi-Fi or Bluetooth). "
            "The 8861 and 8865 models include Wi-Fi and Bluetooth hardware; "
            "btman, btrl, and wlanmgr are active on these models."
        ),
        "affected_services": {
            "btman": {
                "binary":       "which btman (PATH-resolved)",
                "config_args":  "-d -s --ddb /usr/local/bt_devices.xml --dbt /usr/local/bt_config.xml",
                "beuid_actual": "root:root",
                "beuid_intent": "#BEUID=app:services (commented out in btman.sh)",
            },
            "btrl": {
                "binary":       "/usr/sbin/btrl",
                "beuid_actual": "root:root",
                "beuid_intent": "#BEUID=app:services (commented out in btrl.sh)",
            },
            "wlanmgr": {
                "binary":       "/usr/sbin/wlanmgr",
                "beuid_actual": "root:root",
                "beuid_intent": "#BEUID=app:services (commented out in wlanmgr.sh)",
                "stripped":     False,
            },
        },
        "platforms":  "P1 (rootfs88xx), P2 (rootfs288xx), P3 (rootfs388xx) -- all three",
        "impact": [
            "Bluetooth vulnerability in btman gives unauthenticated attacker (BT range) root code execution",
            "Wi-Fi stack vulnerability in wlanmgr gives 802.11 attacker root code execution",
            "wlanmgr manages hostapd AP mode credentials; root context = full Wi-Fi config control",
            "btrl + btman both root: Bluetooth rate limiting bypass + full BT stack control",
        ],
        "remediation": (
            "Uncomment `BEUID=app:services` and remove `BEUID=root:root` in btman.sh, btrl.sh, and wlanmgr.sh. "
            "Test that Bluetooth and Wi-Fi operations function correctly under `app:services` privileges. "
            "If specific capabilities are needed (e.g., CAP_NET_ADMIN for wlanmgr), "
            "grant them via `setpcaps` rather than retaining full root."
        ),
        "yara": """rule cisco_88xx_bt_wifi_root_privilege {
    meta:
        description = "Cisco 88xx btman/btrl/wlanmgr init scripts run as root with app:services commented out"
        severity = "HIGH"
    strings:
        $btman_root     = "BEUID=root:root" ascii
        $btman_comment  = "#BEUID=app:services" ascii
        $btman_daemon   = "DAEMON=`which btman`" ascii
    condition:
        $btman_root and $btman_comment and $btman_daemon
}""",
    },
    {
        "id": "F2",
        "title": "Preloader on PLATFORM_3 Identifies as 'non-secure loader' with UART Firmware Load Fallback",
        "severity": "HIGH",
        "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-494",
        "description": (
            "The `preloader88xx.BE-01-008P.sbn` (Bootastic v2.6.0.C-rc2) contains the "
            "literal string `non-secure loader`. This indicates PLATFORM_3's preloader "
            "does not enforce a secure boot chain and does not operate in TrustZone "
            "secure world (contrast with the encrypted TrustZone SBNs on the 8832). "
            "More critically, the preloader contains a UART fallback path: if the primary "
            "firmware image fails to load and the backup image also fails, the preloader "
            "falls back to UART reception of firmware: "
            "`, try load backup one` -> `, backup not exist, try UART`. "
            "A physical attacker with serial console access (ttyS / ttyAS, 115200 baud) "
            "can exploit this UART fallback to load arbitrary unsigned firmware during "
            "the preloader stage. The preloader runs before any OS-level security controls. "
            "No authentication or signature verification is described for the UART fallback path. "
            "This provides a physical code execution primitive for an attacker who can: "
            "(1) corrupt the primary and backup firmware images (e.g., via flash write tools), or "
            "(2) power cycle the device while triggering the fallback condition. "
            "The UART MMIO address for PLATFORM_3 is not documented in the preloader strings "
            "but is consistent with ttyS0 on earlier Cisco phone platforms."
        ),
        "file":         "preloader88xx.BE-01-008P.sbn",
        "version":      "Bootastic v2.6.0.C-rc2",
        "secure_boot":  "non-secure loader (self-described in binary)",
        "uart_fallback": ", backup not exist, try UART (literal string in preloader)",
        "ddr_config":   "mt41k256m16_630 (Micron DDR3, 256Mx16)",
        "impact": [
            "Physical attacker can load unsigned firmware via UART if primary+backup images corrupted",
            "No secure boot enforcement on PLATFORM_3: arbitrary preloader-stage code execution",
            "UART console accessible on the phone's debug header during preloader window",
        ],
        "remediation": (
            "Enforce secure boot on PLATFORM_3 preloader -- require RSA signature on all accepted firmware images. "
            "Remove or restrict the UART fallback path in production builds. "
            "Add hardware write protection to primary and backup firmware flash partitions "
            "to prevent corruption-triggered fallback."
        ),
    },
    {
        "id": "F3",
        "title": "apigateway Unauthenticated API on Port 8443 Extends to Wi-Fi Attack Surface on 8861/8865 Models",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "The apigateway binary (421 KB, port 8443, BEUID=root:root) is present on the "
            "88xx across all three platforms (P1, P2, P3). "
            "The unauthenticated Config/UI/Serviceability API surface is identical to the "
            "8832 12.0.7 finding (see cisco_8832_12_mpp_re.py F1): embedded OpenAPI 3.0.2 "
            "specs, no `security` sections, endpoints for SetParams/GetParams/SendKey/"
            "RebootDevice/StartPacketCapture/GetConfigFile all running as root. "
            "On the 88xx, this finding carries elevated impact for 8861 and 8865 models "
            "which include 802.11 Wi-Fi hardware managed by wlanmgr (see F1). "
            "The apigateway runs on port 8443 which is accessible over the Wi-Fi interface "
            "in addition to the wired Ethernet interface. An attacker within Wi-Fi radio range "
            "(not requiring wired LAN access) can reach the unauthenticated API. "
            "The 8841 and 8851 models are wired-only; the Wi-Fi amplification applies to "
            "8861 and 8865 only. "
            "All endpoint details from 8832 F1 apply: GetParams reads SIP credentials, "
            "SetParams writes config, SendKey dials numbers, StartPacketCapture captures audio, "
            "RebootDevice causes DoS."
        ),
        "wifi_models":  "8861, 8865 (Wi-Fi + BT); apigateway also reachable over 802.11",
        "wired_models": "8841, 8851 (wired-only; apigateway on LAN only)",
        "port":         8443,
        "beuid":        "root:root",
        "platforms":    "P1, P2, P3 (apigateway present on all three platforms)",
        "reference":    "cisco_8832_12_mpp_re.py F1 for full endpoint documentation",
        "impact": [
            "Wi-Fi attack range: unauthenticated apigateway reachable without wired LAN on 8861/8865",
            "SetParams/GetParams: SIP credential read/write over Wi-Fi",
            "SendKey: dial arbitrary numbers from within Wi-Fi range",
            "StartPacketCapture: capture phone audio via Wi-Fi control plane",
            "All operations run as root on all three extracted platforms",
        ],
        "remediation": (
            "Same as cisco_8832_12_mpp_re.py F1: add authentication to all apigateway endpoints. "
            "Additionally, bind apigateway to wired interface only (eth0) and "
            "explicitly block access on the Wi-Fi interface (wlan0) via iptables. "
            "Validate url/callbackUrl parameters against an allowlist."
        ),
    },
    {
        "id": "F4",
        "title": "m0patch Cortex-M0 Firmware Component Built 2016-04-05 -- 10-Year-Old Binary in 2026 Release",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-1329",
        "description": (
            "The `m0patch288xx.BE-01-001P.sbn` file is a u-boot legacy uImage for an "
            "ARM Cortex-M0 microcontroller (14728 bytes, load/entry 0x62000000). "
            "The uImage header timestamp is 2016-04-05T19:10:15Z. "
            "The parent firmware (`cmterm-88xx.12-0-7MPP0501-123_REL.zip`) was built "
            "2026-03-17 (confirmed from .loads comment) -- the m0patch is therefore "
            "approximately 10 years older than the rest of the firmware it ships with. "
            "The Cortex-M0 controls hardware peripherals at the low level: "
            "keypad matrix scanning, LED control, power management, and "
            "low-level audio/button hardware. "
            "A 10-year unmaintained binary controlling hardware peripherals represents: "
            "(1) no security patches applied since 2016; "
            "(2) potential for Cortex-M0 specific vulnerabilities that have been "
            "undisclosed since discovery post-2016 with no updates shipping; "
            "(3) firmware archaeology opportunity -- the 2016 build predates many "
            "modern security practices (stack cookies, ASLR, etc.). "
            "The uImage format itself (legacy u-boot) indicates this component "
            "predates the switch to more modern signing mechanisms used in the rest "
            "of the 88xx boot chain."
        ),
        "file":       "m0patch288xx.BE-01-001P.sbn",
        "built":      "2016-04-05T19:10:15Z",
        "size":       "14728 bytes (payload)",
        "load_addr":  "0x62000000",
        "arch":       "ARM Cortex-M0",
        "age_in_fw":  "10 years unmaintained (in 12.0.7 released 2026-03-17)",
        "impact": [
            "Unpatched Cortex-M0 firmware -- any post-2016 vulnerabilities not addressed",
            "Legacy uImage format: no modern signature verification on M0 patch delivery",
            "M0 controls keypad, LEDs, power management: bugs can disrupt device operation",
        ],
        "remediation": (
            "Update the m0patch binary to a current build with a modern signing/verification mechanism. "
            "Audit the Cortex-M0 firmware for any publicly known ARM Cortex-M0 specific "
            "vulnerabilities disclosed since 2016. "
            "Replace the legacy uImage packaging with a signed container matching the rest "
            "of the 88xx boot chain."
        ),
    },
    {
        "id": "F5",
        "title": "DECT SUOTA Plaintext HTTP Firmware Delivery (88xx -- Same as 8832 F4)",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "cwe": "CWE-494",
        "description": (
            "The 88xx carries the same SUOTA DECT plaintext HTTP firmware delivery mechanism "
            "as documented in cisco_8832_12_mpp_re.py F4. "
            "`suota_mgmt.cfg` contains `1;1;1;1;1.6;1;http://localhost/NG11_4.01_SUOTA`. "
            "On 88xx models with Wi-Fi (8861/8865), an attacker within Wi-Fi range "
            "can perform the MITM attack without wired LAN access. "
            "See cisco_8832_12_mpp_re.py F4 for full description."
        ),
        "config_path": "suota_mgmt.cfg: 1;1;1;1;1.6;1;http://localhost/NG11_4.01_SUOTA",
        "reference":   "cisco_8832_12_mpp_re.py F4",
        "impact":      ["Wi-Fi MITM substitution of DECT handset firmware on 8861/8865 models"],
        "remediation": "Same as cisco_8832_12_mpp_re.py F4: HTTPS + firmware signature verification.",
    },
    {
        "id": "F6",
        "title": "debug Account LOCKED Across All Three Platforms -- 12.0.7 Secure Baseline Confirmed",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-284",
        "description": (
            "The debug account is locked on all three extracted platforms in 88xx 12.0.7: "
            "P1 and P2 (SquashFS): `debug:*:65532:100:debug:/tmp:/bin/false` -- locked with `*` "
            "(account never had a password set). "
            "P3 (UBI): `debug:!:65532:100:debug:/tmp:/bin/false` -- locked with `!`. "
            "Both locking conventions (`*` and `!`) prevent authentication. "
            "P3 also uses `/sbin/nologin` for root (more restrictive than P1/P2 `/bin/false`). "
            "Cross-reference: cisco_8832_12_mpp_re.py F7 and cisco_phoneos_5_0_1_re.py F1 "
            "document the 14.4.1 regression where debug:debug is active. "
            "The 88xx 12.0.7 confirms secure baseline across all model variants in this version. "
            "Note: P3's codename is `bigeasy_mpp` from `kernel.core_pattern` in sysctl.conf "
            "(`/usr/bin/core.sh bigeasy_mpp %e.%s.%t.gz`)."
        ),
        "platform_states": {
            "P1_P2": "debug:*:65532:100:debug:/tmp:/bin/false (locked with *)",
            "P3":    "debug:!:65532:100:debug:/tmp:/bin/false (locked with !)",
        },
        "codename_leak": "bigeasy_mpp (from kernel.core_pattern in sysctl.conf)",
        "impact":        ["Baseline confirmation only; no active vulnerability in 12.0.7"],
        "remediation":   "None required. Lock debug in 14.4.1 -- see cisco_phoneos_5_0_1_re.py F1.",
    },
]

SUMMARY = {
    "total":    6,
    "critical": 1,
    "high":     2,
    "medium":   2,
    "low":      1,
    "architecture_notes": (
        "88xx is a tri-chip design: P1 and P2 are SquashFS ARM chips for different hardware variants "
        "(P2 adds Cortex-M0 coprocessor via m0patch). P3 is the UBI main chip with preloader. "
        "Each physical phone boots exactly one PLATFORM. The firmware archive contains all three. "
        "P3 uses a 'non-secure loader' preloader (Bootastic v2.6.0.C-rc2) that falls back to UART "
        "if primary+backup firmware images fail to load. "
        "P2's m0patch (ARM Cortex-M0, 14 KB, 2016-04-05) is 10 years unmaintained in this 2026 release. "
        "Bluetooth services btman/btrl and Wi-Fi service wlanmgr all run as root:root "
        "despite app:services being the intended privilege level (commented out in init scripts)."
    ),
    "wifi_models":      "8861, 8865 (Wi-Fi + BT); apigateway F3 elevated impact",
    "no_trustzone_sbn": "88xx lacks TrustZone/oemloader SBNs present in 8832; different secure boot chain",
}
