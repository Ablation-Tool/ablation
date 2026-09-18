"""
Cisco IP Phone 8832 MPP 14.4.1 RE Module (Delta from 12.0.7)
Target: cmterm-8832.14-4-1-0301-6.zip
Model: 8832 conference phone (dual-chip: primary 8832 + secondary 28832)
Architecture:
  PLATFORM_1 (primary 8832):   UBI rootfs (SIP stack, main application)
  PLATFORM_2 (secondary 28832): SquashFS rootfs (media/audio, DECT, Wi-Fi control)
                                 + key28832 (TrustZone RSA-2048 modulus)
                                 + trustzone.sbn (encrypted, 408916 bytes)
                                 + oemloader.sbn (encrypted, 1690968 bytes)
Source: /media/cowboy/research/Cisco-IP PHONE/cmterm-8832.14-4-1-0301-6.zip
Version: 14.4.1 MPP (0301-6); built 2026-06-09 (from rootfs28832 SquashFS creation timestamp)

Baseline: cisco_8832_12_mpp_re.py (12.0.7)
This module documents the delta between 12.0.7 and 14.4.1 for the 8832.
Secondary chip rootfs28832 extracted to /tmp/8832_14_rootfs.

Key changes from 12.0.7:
  REGRESSION:  debug account re-activated on secondary chip (rootfs28832)
  REGRESSION:  wlanmgr still root:root on secondary chip (88xx 14.4.1 fixed it; 8832 did NOT)
  NEW:         key28832 RSA-2048 modulus rotated; header shrank 353->349 bytes (offset 0x60->0x5c)
  PERSISTENT:  debugshd (174KB daemon, command execution framework) running root:root on secondary chip
  PERSISTENT:  Java/Volantis.jar media termination server running root:root on secondary chip
  PERSISTENT:  mic_mgr DECT wireless microphone manager running root:root on secondary chip
  PERSISTENT:  Nearly all secondary chip services run as root:root (no privilege separation)

Secondary chip (28832) unique services vs primary chip (8832):
  java.sh:             BEUID=root:root -- Volantis.jar media termination server (cip.sys.SystemManager)
  mic_mgr.sh:          BEUID=root:root -- DECT wireless microphone manager (cmbsmic_* API)
  debugshd.sh:         BEUID=root:root -- full debug daemon (debug_ui framework, execl/execv, source_command_file)
  debugsht.sh:         BEUID=root:root -- debug shell transport (IPC bridge to daisy_mgr)
  edge_gateway.sh:     BEUID=root:root -- HTTP/TLS gateway with Cisco Huron token auth
  wlanmgr.sh:          BEUID=root:root -- Wi-Fi manager (CP-8832 model-gated, runs on secondary chip)
  daisy_mgr.sh:        BEUID=root:root -- daisy chain expansion manager
  daisy_subordinate_run.sh: BEUID=root:root -- daisy chain subordinate
  xinetd.sh:           BEUID=root:root -- inetd superserver (SSH service present but DISABLED)
  dbus.sh:             #BEUID=app:services commented out; BEUID=root:root active

SBN delta (14.4.1 vs 12.0.7):
  key28832:      353 -> 349 bytes (payload offset 0x60 -> 0x5c; RSA-2048 modulus rotated)
  rootfs28832:   SquashFS 105.8 MB, 2073 inodes, built 2026-06-09
  trustzone.sbn: 408916 bytes (same size as 12.0.7)
  oemloader.sbn: 1690968 bytes (same size as 12.0.7)
"""

METADATA = {
    "target":    "Cisco IP Phone 8832 MPP Firmware 14.4.1 (0301-6)",
    "model":     "8832 conference phone (dual-chip architecture)",
    "built":     "2026-06-09 (rootfs28832 SquashFS creation timestamp)",
    "dual_chip": {
        "primary_8832":    "UBI rootfs -- SIP stack, main application (same architecture as 88xx)",
        "secondary_28832": "SquashFS rootfs -- media termination, DECT mics, Wi-Fi, debug daemons",
    },
    "accounts_secondary_14_4_1": {
        "debug": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71 ACTIVE -- password: debug; shell: /usr/sbin/debugsh",
        "root":  "!:0:0:root:/root:/sbin/nologin (locked)",
    },
    "key28832_delta": {
        "12_0_7": {
            "size":           353,
            "payload_offset": "0x60 (96 bytes)",
            "payload_sha256": "80267ab76c08664827ce0b059fe1947ca259c79a21cde07651b888c9b87b9238",
            "modulus_prefix": "9fb0a8a5b7f994d7235452910a12a04b...",
        },
        "14_4_1": {
            "size":           349,
            "payload_offset": "0x5c (92 bytes)",
            "payload_sha256": "f1ec71f2c96509de9f6c32bf67b575c6a337768e8b3106cf795dc349c7809d3f",
            "modulus_prefix": "5912e4ab288e68875d964cc8bfdd2a86...",
            "note":           "Modulus is completely different -- TrustZone signing key was rotated",
        },
    },
    "secondary_chip_privilege_14_4_1": {
        "wlanmgr":  "root:root -- NOT fixed (88xx 14.4.1 fixed wlanmgr; 8832 secondary chip did not)",
        "debugshd": "root:root -- 174KB debug daemon with command execution framework",
        "debugsht": "root:root -- debug transport bridge",
        "java":     "root:root -- Volantis.jar media termination server (cip.sys.SystemManager)",
        "mic_mgr":  "root:root -- DECT wireless microphone manager (cmbsmic_* API)",
        "edge_gateway": "root:root -- HTTP/TLS gateway (Huron auth tokens, ports 36217-36260 range)",
        "xinetd":   "root:root -- inetd superserver; sshd present but disable=yes",
        "dbus":     "root:root -- D-Bus daemon (#BEUID=app:services commented out)",
        "secureapp": "security:sec -- only correctly-privileged non-root service",
        "propertystore": "app:services -- correctly privileged",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug:debug Account Active in 14.4.1 on Secondary 28832 Chip -- Fleet-Wide Regression",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The secondary 28832 chip rootfs (rootfs28832, SquashFS 105.8 MB) contains "
            "the fleet-wide debug account regression: "
            "`debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`, password `debug`, "
            "shell `/usr/sbin/debugsh`. "
            "This is confirmed in the rootfs28832 14.4.1 `/etc/passwd` and `/etc/shadow`. "
            "The debugsh binary (18KB, stripped ARM ELF) is identical to the version "
            "documented in cisco_88xx_14_mpp_re.py F1 and cisco_88xx_12_mpp_re.py. "
            "In the 8832 context, the secondary chip runs the media termination stack "
            "(Java/Volantis), DECT wireless microphone manager (mic_mgr), and Wi-Fi (wlanmgr). "
            "A debug:debug login on the secondary chip grants access to all of these "
            "subsystems running as root. "
            "The secondary chip's debugshd daemon (174KB, root:root) also provides "
            "a socket-based debug command interface via `debug_ui_execute_command` "
            "and `debug_ui_source_command_file` -- running commands from a file path. "
            "See cisco_phoneos_5_0_1_re.py F1 for fleet-wide scope."
        ),
        "hash":          "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "password":      "debug (cracked)",
        "shell":         "/usr/sbin/debugsh (18KB, stripped ARM ELF)",
        "chip":          "secondary 28832 (confirmed); primary 8832 assumed same pattern",
        "secondary_chip_impact": [
            "debug:debug login on secondary chip with access to media/DECT/Wi-Fi subsystems",
            "debugshd socket interface: debug_ui_source_command_file = command file injection",
            "mic_mgr access from debug shell: start/stop DECT microphone media streams",
        ],
        "remediation": "Lock debug account -- same as cisco_phoneos_5_0_1_re.py F1.",
    },
    {
        "id": "F2",
        "title": "wlanmgr Still root:root on 8832 Secondary Chip in 14.4.1 -- 88xx Fixed, 8832 Did Not",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "description": (
            "The 8832 uses its secondary 28832 chip to manage Wi-Fi. "
            "The `wlanmgr.sh` on the secondary chip contains a model check "
            "(`getmodel` -> CP-8832 only), confirming the secondary chip owns Wi-Fi for the 8832. "
            "In 14.4.1, the secondary chip's `wlanmgr.sh` still sets `BEUID=root:root` "
            "with no commented-out `BEUID=app:services` line. "
            "This is a regression relative to the 88xx 14.4.1 delta documented in "
            "cisco_88xx_14_mpp_re.py F2, where wlanmgr was fixed to `app:services`. "
            "Cisco applied the wlanmgr privilege fix to the 88xx 14.4.1 firmware "
            "but did not apply the same fix to the 8832 secondary chip firmware. "
            "The impact is the same as documented in cisco_88xx_12_mpp_re.py F1: "
            "a Wi-Fi protocol vulnerability in wlanmgr directly yields root on the secondary chip, "
            "which also hosts the media/DECT/debug stack."
        ),
        "wlanmgr_88xx_14_4_1":  "FIXED (app:services) -- cisco_88xx_14_mpp_re.py F2",
        "wlanmgr_8832_14_4_1":  "UNFIXED (root:root) -- wlanmgr.sh has no #BEUID=app:services line",
        "model_gate":            "wlanmgr only starts if getmodel returns CP-8832 (secondary chip is 8832-specific)",
        "impact": [
            "Wi-Fi exploit on 8832 in 14.4.1 yields root on secondary chip",
            "Secondary chip root = access to media termination, DECT mic manager, debug daemon",
            "8832 missed the wlanmgr fix that was applied to all 88xx models in 14.4.1",
        ],
        "remediation": "Apply the same wlanmgr BEUID=app:services fix used in 88xx 14.4.1 to the 8832 secondary chip firmware.",
    },
    {
        "id": "F3",
        "title": "key28832 TrustZone RSA-2048 Modulus Rotated in 14.4.1 -- Boot Chain Trust Changed",
        "severity": "MEDIUM",
        "cvss": 4.4,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N",
        "cwe": "CWE-347",
        "description": (
            "The `key28832.sbn` file contains the RSA-2048 public key modulus used to "
            "verify TrustZone/oemloader SBN signatures on the secondary 28832 chip. "
            "Between 12.0.7 and 14.4.1, this modulus was completely replaced: "
            "the 12.0.7 257-byte payload SHA256 is "
            "`80267ab76c08664827ce0b059fe1947ca259c79a21cde07651b888c9b87b9238`, "
            "and the 14.4.1 payload SHA256 is "
            "`f1ec71f2c96509de9f6c32bf67b575c6a337768e8b3106cf795dc349c7809d3f`. "
            "The first 16 bytes of the modulus changed from "
            "`9fb0a8a5b7f994d7235452910a12a04b` (12.0.7) to "
            "`5912e4ab288e68875d964cc8bfdd2a86` (14.4.1) -- entirely different. "
            "The SBN header also shrank by 4 bytes: "
            "the payload starts at offset 0x60 (96 bytes) in 12.0.7 and "
            "offset 0x5c (92 bytes) in 14.4.1, with the total file size decreasing "
            "from 353 to 349 bytes. "
            "This is consistent with a deliberate key rotation between firmware generations. "
            "The rotation means any 12.0.7-signed trustzone.sbn or oemloader.sbn "
            "cannot be verified by a 14.4.1 device -- a backward-incompatible key change. "
            "The key modulus is NOT DER-encoded; it is a raw 256-byte big-endian integer "
            "with a leading 0x00 byte (total 257 bytes at the payload offset). "
            "See cisco_8832_12_mpp_re.py F5 for the 12.0.7 key format documentation."
        ),
        "key_12_0_7": {
            "size":           353,
            "payload_offset": "0x60 (96 bytes)",
            "sha256":         "80267ab76c08664827ce0b059fe1947ca259c79a21cde07651b888c9b87b9238",
            "modulus_prefix": "9fb0a8a5b7f994d7235452910a12a04b",
        },
        "key_14_4_1": {
            "size":           349,
            "payload_offset": "0x5c (92 bytes)",
            "sha256":         "f1ec71f2c96509de9f6c32bf67b575c6a337768e8b3106cf795dc349c7809d3f",
            "modulus_prefix": "5912e4ab288e68875d964cc8bfdd2a86",
        },
        "format":     "257 bytes: 0x00 prefix + 256-byte raw RSA-2048 modulus (not DER-encoded)",
        "impact": [
            "TrustZone signing authority changed between 12.0.7 and 14.4.1 -- breaks cross-version boot chain analysis",
            "12.0.7-signed encrypted SBNs rejected by 14.4.1 devices (key mismatch)",
            "Two distinct TrustZone key epochs now documented for the 8832 platform",
        ],
        "remediation": "N/A -- key rotation is expected security practice. Document both epochs for boot chain analysis.",
    },
    {
        "id": "F4",
        "title": "debugshd Root-Privileged Debug Daemon on Secondary Chip -- Command File Injection Surface",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "description": (
            "The secondary 28832 chip runs two debug daemons not present on other phone families: "
            "`debugshd` (174756 bytes) and `debugsht` (18220 bytes), both as `BEUID=root:root`. "
            "`debugshd` is a full debug framework daemon with: "
            "`debug_ui_register_command`, `debug_ui_execute_command`, `debug_ui_dump_commands_csv`, "
            "`debug_ui_source_command_file`, `debug_ui_parse_command_string`, "
            "and `debug_ui_cmd_debug_imgauth`. "
            "The `debug_ui_source_command_file` function reads and executes debug commands "
            "from a file path -- if any caller-controlled path reaches this function, "
            "it becomes a file-backed command injection vector. "
            "The binary uses `execl` and `execv` to spawn subprocesses, "
            "and exposes a Unix IPC socket (similar to the debugsh transport bus). "
            "`debugsht` is a smaller transport bridge: it creates IPC sockets, "
            "connects to `daisy_mgr`, and uses `execl` to run the debug shell. "
            "The `debug_ui_cmd_debug_imgauth` command is particularly notable: "
            "it provides a command to debug image authentication, "
            "potentially allowing inspection or bypass of image signature verification. "
            "Neither daemon existed in the primary chip (8832) rootfs or the 88xx family -- "
            "they are unique to the 28832 secondary chip."
        ),
        "debugshd": {
            "size":     174756,
            "notable_functions": [
                "debug_ui_source_command_file (execute commands from file)",
                "debug_ui_execute_command (execute command string)",
                "debug_ui_cmd_debug_imgauth (image authentication debug)",
                "execl, execv (subprocess execution)",
            ],
        },
        "debugsht": {
            "size":     18220,
            "role":     "IPC transport bridge between chips via daisy_mgr; execl to debug shell",
        },
        "models_affected": ["8832 only -- secondary 28832 chip firmware"],
        "impact": [
            "debugshd command execution framework as root on secondary chip",
            "debug_ui_source_command_file = potential file-backed command injection",
            "debug_ui_cmd_debug_imgauth = image authentication inspection/bypass surface",
            "Not present on 88xx/8845_65/6821/68xx/7832/78xx -- 8832-specific attack surface",
        ],
        "remediation": (
            "Apply BEUID=app:services to debugshd.sh and debugsht.sh. "
            "Disable or remove debug_ui_source_command_file in production builds. "
            "Disable debugshd and debugsht entirely in non-debug production firmware."
        ),
    },
    {
        "id": "F5",
        "title": "Secondary Chip Mass root:root Privilege -- Java/Volantis, mic_mgr, edge_gateway All Unconfined",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "description": (
            "The 8832 secondary chip (28832) runs a richer application stack than "
            "the secondary chips in the 88xx family. "
            "Nearly all of its services run as `BEUID=root:root` with no privilege separation: "
            "the Java media termination server (`/bin/java`, Volantis.jar, `cip.sys.SystemManager`), "
            "the DECT wireless microphone manager (`mic_mgr`, 84KB, `cmbsmic_*` API), "
            "the edge_gateway HTTP/TLS proxy (397KB, Huron token auth, ports 36217-36260), "
            "D-Bus manager (`dbus_manager`, `dbus.sh` with `#BEUID=app:services` commented out), "
            "xinetd inetd superserver (sshd present, disabled), "
            "the daisy chain management stack (`daisy_mgr`, `daisy_server`, `daisy_subordinate_run`), "
            "and NTP, network services, power management, and watchdog. "
            "Only two services use reduced privileges: "
            "`secureapp.sh` (`BEUID=security:sec`) and `propertystore.sh` (`BEUID=app:services`). "
            "The edge_gateway binary references `libfileauth.so` and "
            "HTTP authentication functions: `http_common_getEdgeBasicAuthUID`, "
            "`http_common_getEdgeAuthCookieUID`, `http_common_getHuronAccessTokenUID`, "
            "`http_common_getHuronHttpAuthorizationUIDHeader`. "
            "Running as root means any bug in the media stack, DECT protocol handling, "
            "HTTP gateway, or D-Bus message processing yields full device compromise "
            "on the secondary chip."
        ),
        "root_services_notable": {
            "java":         "Volantis.jar media termination server (JVM with JNI, UpgradeService class)",
            "mic_mgr":      "DECT wireless mic manager -- cmbsmic_start_media/stop_media/open_registration",
            "edge_gateway": "HTTP/TLS gateway with Huron token auth (ports 36217-36260 range)",
            "dbus":         "#BEUID=app:services commented out; root:root active",
            "xinetd":       "sshd managed but disabled; root if re-enabled",
            "daisy_mgr":    "daisy chain expansion device management",
        },
        "correctly_privileged": {
            "secureapp":    "security:sec",
            "propertystore": "app:services",
        },
        "vs_other_models": (
            "88xx secondary chip (P2) is a simpler SquashFS with fewer services. "
            "8832 secondary chip has Java JVM, DECT mic manager, edge_gateway, "
            "and dedicated debug daemon stack -- all running as root."
        ),
        "impact": [
            "Any memory corruption or command injection in edge_gateway, Java JNI, or DECT handler = root on secondary chip",
            "DECT protocol fuzzing against mic_mgr: cmbsmic_open_registration accepts wireless handset pairing",
            "edge_gateway HTTP parsing as root: HTTP exploit => full secondary chip compromise",
        ],
        "remediation": (
            "Apply privilege separation across all secondary chip services. "
            "The secureapp and propertystore examples show the fix is known -- extend to all services."
        ),
    },
]

SUMMARY = {
    "total":    5,
    "critical": 1,
    "high":     3,
    "medium":   1,
    "low":      0,
    "version_delta": (
        "14.4.1 vs 12.0.7: debug account regressed on secondary chip (CRITICAL); "
        "wlanmgr still root:root on secondary chip (88xx fixed it, 8832 did not); "
        "key28832 TrustZone modulus rotated (new key epoch); "
        "debugshd command execution daemon unique to secondary chip. "
        "Secondary chip mass root:root issue was present in 12.0.7 and unchanged in 14.4.1."
    ),
    "architecture_note": (
        "8832 secondary chip (28832) hosts a significantly richer stack than 88xx P2: "
        "Java JVM (Volantis.jar), DECT wireless mic manager, HTTP/TLS edge gateway, "
        "debug daemons, and daisy chain expansion management. "
        "All of these run as root -- the secondary chip has no meaningful privilege separation."
    ),
}
