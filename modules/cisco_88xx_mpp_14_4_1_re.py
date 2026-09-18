"""
Cisco MPP 88xx 14.4.1 RE Module
Target: cmterm-88xx.14-4-1-0301-6.zip (Cisco IP Phone 8845/8861/8865 family)
Format: Raw SquashFS v4.0 (magic hsqs), NOT SBN-wrapped (differs from 78xx/7832)
Three rootfs variants: rootfs88xx (70MB), rootfs288xx (72MB), rootfs388xx (78MB)
Build toolchain: GCC 4.6.1 MeeGo 2011 (ARM10TDMI) + Java foundation.jar (2012 JVM)
"""

METADATA = {
    "target":    "Cisco IP Phone 88xx MPP 14.4.1 (8845, 8861, 8865, etc.)",
    "binary":    "rootfs88xx.14-4-1-0301-6.sbn (raw SquashFS, not SBN container)",
    "format":    "Raw SquashFS v4.0 LE (magic 0x73717368 'hsqs'), no SBN header",
    "arch":      "ARM 32-bit EABI5, Linux 2.6.25 ABI",
    "toolchain": "GCC 4.6.1 20110627 (MeeGo 4.6.1-1), ARM10TDMI",
    "java_rt":   "foundation.jar (embedded partial Java SE, 2012 class timestamps)",
    "version":   "14.4.1 (sip88xx.14-4-1-0301-6)",
    "build_date": "2026-06-09",
    "source":    "/media/cowboy/research/Cisco-IP PHONE/cmterm-88xx.14-4-1-0301-6.zip",
    "webex_integration": "sparkd + edge_gateway (Cisco Webex Calling / 'Huron' cloud)",
    "bt_stack":  "BlueZ (bluetoothd, hcidump, obexd, ofonod, brcm_patchram_plus)",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug Account with Password debug Confirmed Across 88xx, 78xx, and 7832 MPP 14.4.1",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The debug account regression first identified in MPP 7832 14.4.1 is "
            "confirmed in 88xx 14.4.1 (`/etc/passwd` contains identical hash "
            "`$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`, cracked: `debug`). The same "
            "`debugshd.sh` init script starts `debugshd` as root on every boot. "
            "Combined, the MPP 14.4.1 regression is confirmed across: 7832 "
            "(conference), 78xx (desk), and 88xx (advanced desk / wireless), "
            "representing the entire MPP 14.4.1 fleet (released June 2026). "
            "PhoneOS 5.0.1 and MPP 12.0.7 are NOT affected (account is locked)."
        ),
        "affected_versions": ["7832 14.4.1", "78xx 14.4.1", "88xx 14.4.1"],
        "unaffected_versions": ["12.0.7MPP (debug:*)", "PhoneOS 5.0.1 (debug:*)"],
        "hash": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "cracked_password": "debug",
        "impact": [
            "Full root code execution on any MPP 14.4.1 phone when SSH is activated",
            "Fleet-wide scope: all MPP 14.4.1 models confirmed",
            "SSH is disabled by default but TAC commonly enables it for troubleshooting",
        ],
        "remediation": (
            "Lock the debug account in all 14.4.1 builds: "
            "`debug:*:65532:100:debug:/tmp:/sbin/nologin`. "
            "Release an emergency firmware update to 14.4.2 or later. "
            "File as regression vs. MPP 12.0.7 baseline."
        ),
        "yara": """rule cisco_mpp_14_4_1_debug_fleet_regression {
    meta:
        description = "MPP 14.4.1 debug:debug account regression - all 88xx/78xx/7832 affected"
        severity = "CRITICAL"
    strings:
        $hash = "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71" ascii
        $beuid = "BEUID=root:root" ascii
    condition:
        $hash and $beuid
}""",
    },
    {
        "id": "F2",
        "title": "FIPS Power-On Self Test Disabled by Default via CISCOSSL_FOM_DIAG=SKIP_POST",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-693",
        "description": (
            "The phone startup script `/etc/rc5.d/S92phone.sh` exports "
            "`CISCOSSL_FOM_DIAG=SKIP_POST` for the entire phone process tree "
            "UNLESS the file `/usr/local/etc/secFipsModeEnabled` exists. The "
            "`/usr/local/` directory is a writable mount point (empty in SquashFS). "
            "This means any factory-reset phone, any phone without FIPS provisioning, "
            "or any phone where an attacker (via F1) deletes the enablement file, "
            "will operate with the CiscoSSL FIPS Object Module (FOM) Power-On Self "
            "Test bypassed. FIPS POST validates the integrity of cryptographic "
            "modules before use; bypassing it means all TLS, SRTP, and "
            "PKI operations proceed without validation of the crypto implementation. "
            "The export propagates to all child processes including sshd, "
            "wpa_supplicant (802.1X), and the Webex edge_gateway."
        ),
        "trigger_code": [
            "if ! [ -f /usr/local/etc/secFipsModeEnabled ]",
            "then",
            "    export CISCOSSL_FOM_DIAG=SKIP_POST",
            "fi",
        ],
        "impact": [
            "FIPS 140-2/3 compliance void when secFipsModeEnabled absent",
            "Attacker with root (F1) can delete the file, triggering non-FIPS mode on reboot",
            "All crypto operations (TLS, SRTP, 802.1X) proceed without POST validation",
            "Affects factory-reset phones deployed without FIPS provisioning",
        ],
        "remediation": (
            "Default SHOULD be FIPS-enabled (not disabled). Invert the logic: "
            "apply SKIP_POST only when `secFipsModeDISABLED` file exists. "
            "Protect `/usr/local/etc/secFipsModeEnabled` via immutable flag "
            "or signed attestation. Log FIPS state change on reboot."
        ),
        "yara": """rule cisco_88xx_fips_skip_post_default {
    meta:
        description = "88xx startup skips FIPS POST unless secFipsModeEnabled file exists"
        severity = "HIGH"
    strings:
        $skip_post      = "CISCOSSL_FOM_DIAG=SKIP_POST" ascii
        $fips_enablement = "secFipsModeEnabled" ascii
    condition:
        all of them
}""",
    },
    {
        "id": "F3",
        "title": "Webex OAuth Access Token Accessible via D-Bus Signal Interception",
        "severity": "HIGH",
        "cvss": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-522",
        "description": (
            "The phone runs `sparkd` (Webex integration daemon) which obtains "
            "OAuth access tokens from `edge_gateway` via a D-Bus signal: "
            "`AccessTokenChanged signal received from EdgeGateway. token_length %u`. "
            "Both binaries use `libdbus-c++-1.so.0`. The access token is used "
            "to authenticate the phone to Cisco Webex infrastructure at "
            "`https://idbroker.webex.com`, `https://wdm-a.wbx2.com/wdm/api/v1`, "
            "`https://u2c-a.wbx2.com/u2c/api/v1`, and "
            "`https://activation.webex.com`. An attacker with root shell (F1) "
            "can attach a D-Bus monitor or ptrace `sparkd` to extract the "
            "access token and use it to impersonate the phone in Webex cloud. "
            "The token is stored in memory via `SynergyliteAccountStore`."
        ),
        "signal_path": "edge_gateway -> D-Bus AccessTokenChanged -> sparkd.wx2.Authorizer",
        "webex_endpoints": [
            "https://idbroker.webex.com",
            "https://identity.webex.com",
            "https://u2c-a.wbx2.com/u2c/api/v1",
            "https://wdm-a.wbx2.com/wdm/api/v1",
            "https://ds.ciscospark.com/v1/region",
            "https://activation.webex.com",
        ],
        "api_surface": "GET /api/v1/users/<uid>/devices HTTP/1.1 (device registration)",
        "impact": [
            "Webex access token allows phone impersonation in cloud infrastructure",
            "Token can be used to access call logs, voicemail, and meeting data",
            "Re-register the phone's device ID to attacker-controlled endpoint",
            "Combined with F1: network access -> root -> D-Bus monitor -> Webex token",
        ],
        "remediation": (
            "D-Bus socket for the Webex token channel should require a dedicated "
            "policy rule limiting subscribers to the sparkd UID. Do not pass "
            "bearer tokens via signal payloads visible to all D-Bus listeners "
            "on the session bus. Use a secure IPC channel (Unix socket with "
            "strict permissions) for token delivery."
        ),
        "yara": """rule cisco_88xx_webex_token_dbus_signal {
    meta:
        description = "88xx sparkd receives Webex OAuth token via D-Bus signal - extractable via root"
        severity = "HIGH"
    strings:
        $signal     = "AccessTokenChanged signal received from EdgeGateway" ascii
        $webex_url  = "https://idbroker.webex.com" ascii
        $dbus_cpp   = "libdbus-c++-1.so" ascii
    condition:
        $signal and $webex_url
}""",
    },
    {
        "id": "F4",
        "title": "Java MicroServlet HTTP Server Exposes Call and Config Endpoints on LAN",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-306",
        "description": (
            "The phone runs an embedded Java HTTP server using `Bigeasy.jar` "
            "(the `cip.http.MicroServletContainer` module) on top of a 2012 "
            "JVM (`foundation.jar`). The `MicroServletRegistry` maps named "
            "paths to servlet classes. Registered servlets confirmed via "
            "`targetManifest.xml` and `manifest.xml.bigeasy`: "
            "`/LineInfo` (cip.callagent.LineInfoServlet - active call lines), "
            "`/CallInfo` (cip.callagent.CallInfoServlet - call details), "
            "`/SettingsInfo` (cip.setg.SettingsInfoServlet), "
            "`/Monitor` (cip.srvlt.Monitor), "
            "`/Serviceability` (cip.webdiag.ServiceabilityServlet). "
            "The Serviceability servlet handles admin auth via "
            "`device.settings.config.vendorconfig.adminpassword` property "
            "(default: blank on factory reset). No CSRF is enforced on "
            "GET-based information endpoints. An attacker on the same VLAN "
            "can query `/LineInfo` and `/CallInfo` to enumerate active calls "
            "and SIP line registrations without credentials."
        ),
        "servlet_map": {
            "/LineInfo":       "cip.callagent.LineInfoServlet - SIP line registration info",
            "/CallInfo":       "cip.callagent.CallInfoServlet - active call metadata",
            "/SettingsInfo":   "cip.setg.SettingsInfoServlet - phone configuration",
            "/Monitor":        "cip.srvlt.Monitor - system monitoring",
            "/Serviceability": "cip.webdiag.ServiceabilityServlet - admin web UI",
        },
        "java_stack": {
            "container": "Bigeasy.jar (cip.http.MicroServletContainer)",
            "registry":  "MicroServletRegistry (Hashtable path -> class name)",
            "runtime":   "foundation.jar (partial Java SE 2012 runtime)",
            "ipc":       "libDBusJava-1.jar (D-Bus Java bindings)",
            "upload":    "commons-fileupload-1.5.jar (firmware/config upload)",
        },
        "impact": [
            "Call state enumeration (who is on a call, call duration) from VLAN",
            "SIP line registrations and server addresses readable via /LineInfo",
            "Admin config change via /Serviceability with default blank password",
            "2012 JVM: known JVM vulnerabilities in older runtimes (classloading, deserial)",
        ],
        "remediation": (
            "Restrict all MicroServlet endpoints to localhost or management VLAN. "
            "Enforce authentication on /LineInfo and /CallInfo. "
            "Replace the 2012 embedded JVM with a current Java ME embedded release. "
            "Change the factory default admin password from blank to a per-device "
            "random value generated at first boot."
        ),
        "yara": """rule cisco_88xx_microservlet_call_info {
    meta:
        description = "88xx Java MicroServlet exposes call info and config endpoints on LAN"
        severity = "HIGH"
    strings:
        $lineinfo   = "LineInfoServlet" ascii
        $callinfo   = "CallInfoServlet" ascii
        $microsvlt  = "MicroServletContainer" ascii
        $bigeasy    = "Bigeasy.jar" ascii nocase
    condition:
        $lineinfo or ($callinfo and $microsvlt)
}""",
    },
    {
        "id": "F5",
        "title": "hcidump Present - Bluetooth HCI Packet Capture Including Audio",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-284",
        "description": (
            "The 88xx ships with `hcidump` in `/usr/sbin/hcidump`, a Bluetooth "
            "HCI packet capture tool supporting `-w <file>` (save to file) and "
            "`-d <host>` (send to remote host). The phone has an active Bluetooth "
            "stack (BlueZ: bluetoothd, brcm_patchram_plus for Broadcom firmware "
            "loading, ofonod for telephony, obexd for OBEX profiles). Paired "
            "Bluetooth headsets communicate audio over HFP/HSP profiles. An "
            "attacker with root access (F1) can run `hcidump -w /tmp/bt.pcap` "
            "to capture all Bluetooth HCI traffic including the SCO audio "
            "streams for any paired headset call."
        ),
        "bt_binaries": [
            "/usr/sbin/hcidump (packet capture)",
            "/usr/sbin/hcidump -w file (save to file)",
            "/usr/sbin/bluetoothd (BlueZ daemon)",
            "/usr/sbin/brcm_patchram_plus (Broadcom BT firmware loader)",
            "/usr/sbin/ofonod (ofono telephony stack)",
            "/usr/sbin/obexd (OBEX profiles)",
            "/usr/sbin/bt-audio (audio routing)",
        ],
        "impact": [
            "BT headset audio captured from HCI layer without headset knowledge",
            "HCI dump includes all paired device addresses (persistent tracking)",
            "Combined with F1: SSH root -> hcidump -> headset call audio exfil",
        ],
        "remediation": (
            "Remove hcidump from production builds - it is a diagnostic tool "
            "with no runtime purpose on deployed phones. If retained for TAC use, "
            "gate execution behind a privilege check against a non-debug user."
        ),
        "yara": """rule cisco_88xx_hcidump_bt_capture {
    meta:
        description = "88xx ships with hcidump - BT HCI packet capture tool for audio intercept"
        severity = "MEDIUM"
    strings:
        $hcidump    = "/usr/sbin/hcidump" ascii
        $save_dump  = "--save-dump" ascii
        $wait_dump  = "--wait-dump" ascii
    condition:
        $hcidump and ($save_dump or $wait_dump)
}""",
    },
]

SUMMARY = {
    "total":    5,
    "critical": 1,
    "high":     3,
    "medium":   1,
    "low":      0,
}
