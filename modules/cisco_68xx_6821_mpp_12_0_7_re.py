"""
Cisco IP Phone 68xx/6821 MPP 12.0.7 RE Module
Targets:
  - cmterm-68xx.12-0-7MPP0501-123_REL.zip: 6851/6861/6871 family (SBN+UBI)
  - cmterm-6821.12-0-7MPP0501-123_REL.zip: 6821 entry-level desk phone (SBN+UBI)
Build: 2026-03-17 (68xx), format identical across models
Security baseline: debug account LOCKED in 12.0.7 (debug:*)
"""

METADATA = {
    "targets": {
        "68xx": {
            "binary":   "rootfs2.68xx.12-0-7MPP0501-123.sbn",
            "format":   "SBN container (CD3412AB, 340-byte header + 8-byte extension) -> UBI at offset 348",
            "build":    "2026-03-17 02:51:56",
            "version":  "12.0.7MPP0501-123",
        },
        "6821": {
            "binary":   "rootfs6821.12-0-7MPP0501-123.sbn",
            "format":   "SBN container (CD3412AB) -> UBI at offset 344",
            "version":  "12.0.7MPP0501-123",
            "extra":    "miniroot6821.12-0-7MPP0501-123.sbn (16MB SBN recovery rootfs)",
        },
    },
    "security_baseline": {
        "debug_account":  "LOCKED (debug:*:65532:100:debug:/tmp:/bin/false) - NOT vulnerable to debug:debug regression",
        "root_account":   "LOCKED (root:!)",
        "all_accounts":   "root, bin, daemon, sys, sync, security, image, debug, app, messagebus, dbus, nobody - all locked",
        "fips_bypass":    "NOT PRESENT - S92phone.sh does NOT export CISCOSSL_FOM_DIAG=SKIP_POST",
    },
    "shared_binaries": [
        "apigateway (REST API bridge to D-Bus services)",
        "cscep (SCEP certificate enrollment)",
        "cdp (Cisco Discovery Protocol - voice VLAN assignment)",
        "dbusmonitor (D-Bus real-time monitoring tool)",
        "dsettftp (TFTP-based device settings downloader)",
        "getmicdata (6821: raw microphone capture via libsecuremic.so)",
        "curl (HTTP client)",
        "crond (cron scheduler)",
    ],
    "source": "/media/cowboy/research/Cisco-IP PHONE/",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "CDP VLAN Assignment Accepts Layer-2 Forged Frames - Voice VLAN Manipulation",
        "severity": "MEDIUM",
        "cvss": 6.0,
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "cwe": "CWE-290",
        "description": (
            "The Cisco Discovery Protocol client (`/usr/sbin/cdp`) accepts VLAN "
            "assignment messages from the network and configures the phone's "
            "voice VLAN via `cpr_eth_set_voice_vlan`, `cpr_eth_set_access_vlan`, "
            "and `cpr_eth_config_pc_vvlan_access`. An `adminVlanOverrideState` "
            "flag controls whether the admin VLAN assignment overrides the "
            "provisioned value. CDP operates at Layer 2 with no authentication "
            "or message integrity protection. An attacker with access to the same "
            "Layer 2 segment (same switch, VLAN, or unmanaged hub) can forge CDP "
            "frames to send a modified voice VLAN assignment to the phone. "
            "If accepted, the phone moves its traffic to an attacker-controlled VLAN, "
            "enabling interception of SIP signaling and media streams. "
            "This attack is effective regardless of whether 802.1X port security is "
            "configured on the switch, as it operates within the phone's existing "
            "authorized VLAN before VLAN switching."
        ),
        "cdp_functions": {
            "cpr_eth_set_voice_vlan":          "Set phone voice VLAN from CDP advertisement",
            "cpr_eth_set_access_vlan":          "Set access VLAN",
            "cpr_eth_set_pc_vlan":              "Set PC-side VLAN (pass-through port)",
            "cpr_eth_config_pc_vvlan_access":   "Configure PC-side voice VLAN access mode",
            "adminVlanOverrideState":            "Admin VLAN override flag",
            "addVVlan":                          "Add voice VLAN to configuration",
        },
        "impact": [
            "Forged CDP voice VLAN = phone moves traffic to attacker-controlled VLAN",
            "SIP signaling and RTP media streams interceptable from attacker VLAN",
            "LLDP-MED also accepted - dual protocol VLAN manipulation surface",
            "Affects all wired Cisco IP phones using CDP for VLAN provisioning",
        ],
        "remediation": (
            "Configure Cisco switches to use CDP authentication (HMAC-SHA1) via "
            "`cdp authentication hmac-sha1-12 <key>`. This is disabled by default. "
            "Alternatively, pre-configure the voice VLAN statically on the switch "
            "port instead of relying on CDP negotiation. "
            "Disable CDP on user-facing ports where possible; use LLDP-MED as a "
            "more controlled alternative."
        ),
        "yara": """rule cisco_68xx_cdp_vlan_manipulation {
    meta:
        description = "Cisco 68xx/6821 CDP client accepts unauthenticated VLAN assignment from network"
        severity = "MEDIUM"
    strings:
        $set_voice_vlan = "cpr_eth_set_voice_vlan" ascii
        $admin_override = "adminVlanOverrideState" ascii
        $add_vvlan      = "addVVlan" ascii
    condition:
        $set_voice_vlan and $admin_override
}""",
    },
    {
        "id": "F2",
        "title": "apigateway REST API Exposes Call Control and Config on All 68xx/6821 Models",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-306",
        "description": (
            "The 68xx/6821 12.0.7 ships the same `apigateway` binary as PhoneOS 5.0.1 "
            "and MPP 14.4.1. The gateway bridges HTTP REST requests to D-Bus services "
            "via `libdbushelper.so` and `libdbus-c++-1.so.0`. Endpoints include "
            "`/api/Call/v1` (call control via `com.cisco.mpp.CallControlService`) and "
            "`/api/Config/v1` (phone configuration via `com.cisco.mpp.ConfigService`). "
            "The phone does NOT have the debug:debug regression in 12.0.7, so initial "
            "access requires valid admin credentials. However, with default blank admin "
            "credentials (factory reset), the apigateway provides unauthenticated "
            "call control from the same VLAN. The `dbusmonitor` binary allows real-time "
            "D-Bus traffic monitoring from an authenticated shell."
        ),
        "endpoints": {
            "/api/Call/v1":   "Call control (make, answer, hold, transfer)",
            "/api/Config/v1": "Phone configuration read/write",
        },
        "dbus_path":     "libdbushelper.so + libdbus-c++-1.so.0 (D-Bus C++ bridge)",
        "dbusmonitor":   "Usage: dbusmonitor [-m] - real-time D-Bus traffic monitor",
        "impact": [
            "Default blank admin password: unauthenticated call control from VLAN",
            "CUCM-provisioned phones may have non-blank passwords: requires credential discovery",
            "dbusmonitor: from authenticated shell, monitor all D-Bus signals (call events, config)",
        ],
        "remediation": (
            "Set a non-blank per-device admin password during CUCM provisioning. "
            "Bind apigateway to localhost or a management VLAN interface only. "
            "Remove dbusmonitor from production builds."
        ),
        "yara": """rule cisco_68xx_apigateway_rest_api {
    meta:
        description = "68xx/6821 12.0.7 ships apigateway REST API + dbusmonitor diagnostic tool"
        severity = "MEDIUM"
    strings:
        $apigateway  = "apigateway" ascii
        $dbusmonitor = "dbusmonitor" ascii
        $dbus_helper = "libdbushelper.so" ascii
    condition:
        $apigateway and $dbus_helper
}""",
    },
    {
        "id": "F3",
        "title": "dsettftp TFTP Device Settings Downloader - Provisioning Trust Boundary",
        "severity": "LOW",
        "cvss": 4.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-494",
        "description": (
            "The `dsettftp` binary downloads device settings via TFTP and validates "
            "them via `sec_validate_config_file` from `libfileauth.so`. The binary "
            "resolves TFTP server addresses from a resource file "
            "(`getTftpAddrByNameFromResFile`) and maintains a list of available TFTP "
            "servers (`tftpListAvail`). The `sec_is_server_secure` check implies "
            "a distinction between secure and non-secure TFTP sources - but the "
            "validation criteria are opaque without source. "
            "If `sec_validate_config_file` fails open (returns success on error), "
            "or if the TFTP server address is derived from an unauthenticated source "
            "(DHCP option 150, CDP, or previous TFTP config), an attacker can serve "
            "malicious device settings. The EMCC config override "
            "(`overrideEMCCConfig`) suggests extension mobility cross-cluster "
            "configuration is downloaded via this path."
        ),
        "interesting_functions": {
            "sec_validate_config_file":    "Validates downloaded config file (from libfileauth.so)",
            "sec_is_server_secure":        "Checks if TFTP server is on secure list",
            "getTftpAddrByNameFromResFile": "Resolves TFTP server address from a resource file",
            "overrideEMCCConfig":          "Override EMCC (Extension Mobility Cross Cluster) config",
            "tftpListAvail":               "List of available TFTP servers",
        },
        "impact": [
            "TFTP provisioning trust boundary: if server address is derived from DHCP/CDP, it's attacker-controllable",
            "EMCC config override: attacker TFTP can redirect extension mobility authentication",
            "sec_validate_config_file: if fail-open, malicious config accepted without validation",
        ],
        "remediation": (
            "Pre-provision the TFTP server address in CUCM rather than relying on DHCP option 150. "
            "Ensure sec_validate_config_file fails closed (reject config on validation error). "
            "Migrate from TFTP provisioning to secure HTTPS-based provisioning with certificate validation."
        ),
        "yara": """rule cisco_68xx_dsettftp_provisioning {
    meta:
        description = "68xx/6821 dsettftp downloads device settings via TFTP with server-side validation"
        severity = "LOW"
    strings:
        $dsettftp    = "dsettftp" ascii
        $sec_valid   = "sec_validate_config_file" ascii
        $tftp_avail  = "tftpListAvail" ascii
    condition:
        $sec_valid and $tftp_avail
}""",
    },
]

SUMMARY = {
    "total":    3,
    "critical": 0,
    "high":     0,
    "medium":   2,
    "low":      1,
    "note":     "68xx/6821 on 12.0.7MPP represent the secure baseline. debug account LOCKED. FIPS POST not bypassed.",
}
