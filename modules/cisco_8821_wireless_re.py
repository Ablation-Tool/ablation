"""
Cisco IP Phone 8821 Wireless RE Module
Target: cmterm-8821.11-0-6SR8-2_REL.zip
Format: Raw SquashFS v4.0 (magic hsqs), version 11.0.6SR8-2
OEM Platform: Spectralink (build path: slbuild/sl_he_mr1_mr4_sr8)
OS: Linux 3.0.31 (EOL October 2013), wpa_supplicant v2.1-devel (July 2013 source)
Build: Tue Aug 18 04:06:13 UTC 2026
"""

METADATA = {
    "target":       "Cisco IP Phone 8821 Wireless",
    "binary":       "rootfs8821.11-0-6SR8-2.sbn (raw SquashFS, 74MB)",
    "format":       "Raw SquashFS v4.0 LE (magic 0x73717368 'hsqs'), no SBN header",
    "arch":         "ARM 32-bit EABI5",
    "kernel":       "Linux 3.0.31 (EOL October 2013)",
    "version":      "11.0.6SR8-2 (sip8821.11-0-6SR8-2)",
    "build_date":   "2026-08-18 04:06:13 UTC",
    "oem_platform": "Spectralink (build user: slbuild, branch: sl_he_mr1_mr4_sr8)",
    "wpa_version":  "wpa_supplicant v2.1-devel Bcmver:79 (July 3, 2013 Git source)",
    "wireless_driver": "bcmdhd (Broadcom FullMAC, ap_scan=0)",
    "wireless_config": "/usr/local/wifi/wlan_profiles.xml",
    "source":       "/media/cowboy/research/Cisco-IP PHONE/cmterm-8821.11-0-6SR8-2_REL.zip",
    "other_binaries": {
        "wlanmgr":    "Spectralink Wi-Fi profile manager (RADIUS, EAP, 802.1X)",
        "btman":      "Broadcom BSA Bluetooth manager",
        "ppusb":      "USB peripheral manager",
        "ppusbnet":   "USB network adapter manager",
        "usbaudmgr":  "USB audio manager",
    },
    "vc4_binary": {
        "file":   "vc48821.11-0-6SR8-2.sbn",
        "size":   "3.8MB",
        "format": "Proprietary Broadcom codec binary (256-byte null prefix, then binary DSP code)",
        "note":   "Contains 'Why Does It Always Rain on Me?' - developer codec test string",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug Account with Password debug Present in Non-14.4.1 Firmware Branch - Scope Expansion",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The debug account regression (`debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`, "
            "password: `debug`) previously confirmed in MPP 14.4.1 (7832, 78xx, 88xx, 8832, 8845/8865) "
            "is ALSO present in the 8821 firmware version `11.0.6SR8-2`, which is a "
            "completely separate firmware branch (11.x vs 14.x). The 8821 build was "
            "compiled on August 18, 2026, confirming this is a current production build. "
            "The identical MD5-crypt hash (`$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`) across "
            "two independent firmware branches (14.x MPP and 11.x 8821) indicates the "
            "regression originates in a shared build-system component or common "
            "password database template used across all Cisco MPP phone product lines. "
            "The 8821 attack surface is uniquely dangerous: this is a wireless phone "
            "that connects to corporate 802.1X Wi-Fi, stores RADIUS secrets and client "
            "certificates locally, and is deployed in environments where roaming users "
            "carry the phone outside the physical security perimeter. Debug SSH access "
            "enables real-time interception of calls on the wireless handset."
        ),
        "fleet_scope_extended": [
            "7832 14.4.1 MPP", "78xx 14.4.1 MPP", "88xx 14.4.1 MPP",
            "8832 14.4.1 MPP", "8845/8865 14.4.1 MPP",
            "8821 11.0.6SR8-2 (DIFFERENT FIRMWARE BRANCH - extends scope)",
        ],
        "hash": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "cracked_password": "debug",
        "multi_branch_significance": (
            "Same hash across 14.x and 11.x branches = shared build artifact, "
            "not a 14.4.1-specific regression. All firmware branches sharing this "
            "build system component may be affected."
        ),
        "impact": [
            "Root shell on 8821 wireless phone via debug:debug + SSH",
            "Wireless phone leaves physical perimeter: attacker on same Wi-Fi = instant root",
            "Root reads RADIUS secret from /usr/local/wifi/wlan_profiles.xml (see F3)",
            "Root reads EAP client certificate from /usr/local/wifi/usercert/user.p12",
            "Multi-branch scope: audit all other Cisco MPP firmware branches for same hash",
        ],
        "remediation": (
            "Lock the debug account in ALL Cisco MPP firmware branches: "
            "`debug:*:65532:100:debug:/tmp:/sbin/nologin`. "
            "The cross-branch presence indicates a shared template or build variable "
            "that must be audited across the full MPP/Wireless/Conference phone build system. "
            "File CVE against the broader MPP phone debug account regression, "
            "not just 14.4.1."
        ),
        "yara": """rule cisco_8821_debug_account_cross_branch {
    meta:
        description = "8821 11.0.6SR8 has same debug:debug hash as 14.4.1 MPP - cross-branch regression"
        severity = "CRITICAL"
    strings:
        $hash   = "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71" ascii
        $wlanmgr = "wlanmgr" ascii
        $ssid   = "wlan_profiles.xml" ascii
    condition:
        $hash and ($wlanmgr or $ssid)
}""",
    },
    {
        "id": "F2",
        "title": "EOL Linux 3.0.31 Kernel + wpa_supplicant 2.1-devel (July 2013 Source) - KRACK Unpatched",
        "severity": "HIGH",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1395",
        "description": (
            "The 8821 runs Linux kernel 3.0.31 (EOL October 2013) and wpa_supplicant "
            "v2.1-devel compiled from a July 3, 2013 Git commit "
            "(`Githash:06aeff5f8f2ba6d116911a1e3507519c44ee5043`, Bcmver:79). "
            "The binary was recompiled August 18, 2026, but from 13-year-old source. "
            "wpa_supplicant 2.1 (2013) is vulnerable to KRACK (CVE-2017-13082 - Key "
            "Reinstallation Attacks): an attacker can force WPA2 nonce reuse in the "
            "4-way handshake, decrypting and potentially injecting arbitrary packets. "
            "The 8821's KRACK exposure is maximized because it's a mobile Wi-Fi phone: "
            "it roams between APs, triggering 4-way handshakes repeatedly, and may "
            "reconnect to networks in environments without controlled infrastructure. "
            "Linux 3.0.31 additionally has Dirty COW (CVE-2016-5195) and perf_event "
            "privilege escalation (CVE-2013-2094). The Broadcom bcmdhd FullMAC driver "
            "(ap_scan=0) delegates the 802.11 state machine to closed Broadcom firmware, "
            "preventing audit of any frame-parsing vulnerabilities."
        ),
        "wpa_supplicant_details": {
            "version_string": "wpa_supplicant v2.1-devel Bcmver:79",
            "git_version":    "July-03/2013",
            "git_hash":       "06aeff5f8f2ba6d116911a1e3507519c44ee5043",
            "built_from":     "wpa_supplicant-0.8.0.79 (Broadcom internal fork of 0.8.0)",
            "build_date":     "Aug 18 2026 at 04:02:21 (recompiled from 2013 source)",
            "build_host":     "/home/slbuild/sl_he_mr1_mr4_sr8/... (Spectralink CI)",
        },
        "unpatched_cves": [
            "CVE-2017-13082: KRACK - 4-way handshake key reinstallation (wpa_supplicant < 2.7)",
            "CVE-2015-4141: WPS OOB write (wpa_supplicant < 2.5)",
            "CVE-2015-4143: EAP-pwd invalid curve (wpa_supplicant < 2.5)",
            "CVE-2019-9494/9495/9496: Dragonblood SAE timing attacks (wpa_supplicant < 2.8)",
            "CVE-2016-5195: Dirty COW kernel privilege escalation (Linux < 4.8.3)",
        ],
        "driver_details": {
            "driver":    "bcmdhd (Broadcom FullMAC)",
            "ap_scan":   "0 (driver-controlled scan, wpa_supplicant passive)",
            "kernel":    "Linux 3.0.31",
            "ko_path":   "lib/modules/3.0.31/bcmdhd/",
            "driver_note": "FullMAC = entire 802.11 state machine in closed Broadcom firmware",
        },
        "krack_attack_scenario": (
            "Attacker on same VLAN or same SSID acts as rogue AP and forces 4-way handshake "
            "retransmission. 8821's KRACK-vulnerable wpa_supplicant reinstalls the PTK/GTK "
            "with a reset nonce. Attacker can then decrypt all traffic from the 8821, "
            "including SIP signaling over SRTP and HTTP provisioning traffic."
        ),
        "impact": [
            "KRACK: Wi-Fi traffic decryptable by adjacent network attacker",
            "Dirty COW + root-capable debug account: network-to-root escalation chain",
            "FullMAC Broadcom firmware: frame-parsing bugs unauditable and unfixable by Cisco",
            "Roaming phone: repeatedly performs 4-way handshakes, maximizing KRACK exposure",
        ],
        "remediation": (
            "Upgrade wpa_supplicant to a current release (2.10+) compiled from the 2024 "
            "source tree. Apply KRACK patches specifically: FT handshake nonce protection "
            "(wpa_supplicant patches from 2017-10-16). "
            "Upgrade the Linux kernel from 3.0.31 to a supported LTS (5.15+ LTS). "
            "Replace the Broadcom bcmdhd FullMAC driver with a cfg80211-based softmac "
            "driver if the wireless chipset supports it."
        ),
        "yara": """rule cisco_8821_krack_wpa_supplicant_2013 {
    meta:
        description = "8821 ships wpa_supplicant built from July 2013 source - KRACK unpatched"
        severity = "HIGH"
    strings:
        $gitver   = "Gitver:July-03/2013" ascii
        $bcmver   = "Bcmver:79" ascii
        $wpa21    = "wpa_supplicant v2.1-devel" ascii
        $slbuild  = "slbuild" ascii
    condition:
        $gitver or ($bcmver and $wpa21)
}""",
    },
    {
        "id": "F3",
        "title": "802.1X RADIUS Shared Secret and Client Certificate Stored Plaintext on Filesystem",
        "severity": "HIGH",
        "cvss": 7.6,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-312",
        "description": (
            "The 8821's wlanmgr stores 802.1X authentication credentials in "
            "`/usr/local/wifi/wlan_profiles.xml`. The XML profile format includes: "
            "`<auth_server_shared_secret>` (RADIUS shared secret in plaintext), "
            "`auth_server_addr` (RADIUS server IP), `auth_server_port`, and EAP method. "
            "Additionally, the EAP-TLS client certificate is stored at "
            "`/usr/local/wifi/usercert/user.p12` with its password in "
            "`/usr/local/wifi/usercert/usercert_passwd`. "
            "An attacker with root access (F1: debug:debug) can read the RADIUS shared "
            "secret and the PKCS#12 client certificate + password. The RADIUS shared "
            "secret can be used to: (1) forge RADIUS authentication for any MAC address "
            "on that RADIUS server, and (2) decrypt WPA-Enterprise RADIUS exchanges "
            "captured off the wire. The client certificate extraction allows impersonating "
            "the phone's identity on the 802.1X infrastructure."
        ),
        "credential_files": {
            "/usr/local/wifi/wlan_profiles.xml": "XML with SSID, auth method, RADIUS server, shared secret",
            "/usr/local/wifi/usercert/user.p12": "PKCS#12 EAP-TLS client certificate",
            "/usr/local/wifi/usercert/usercert_passwd": "Plaintext password for PKCS#12 file",
            "/usr/local/wifi/pac.*": "EAP-FAST PAC (Protected Access Credential)",
            "/usr/local/wifi/rootca/*": "Trusted CA certificates for RADIUS server validation",
        },
        "xml_credential_fields": [
            "<auth_server_shared_secret> - RADIUS shared secret in plaintext",
            "<auth_server_addr> - RADIUS server IP",
            "<auth_server_port> - RADIUS server port",
            "<auth> - EAP method (MSCHAPV2, GTC, TLS, PEAP, etc.)",
        ],
        "impact": [
            "RADIUS shared secret: forge auth for any device on the corporate RADIUS server",
            "RADIUS shared secret: decrypt WPA-Enterprise MS-MPPE-Key from pcap",
            "PKCS#12 cert + password: impersonate phone identity in 802.1X infrastructure",
            "PAC file: EAP-FAST protected access credential for tunnel-less EAP-FAST attacks",
            "Combined with F1: SSH as debug + read wlan_profiles.xml = instant RADIUS pivot",
        ],
        "remediation": (
            "Store the RADIUS shared secret in a hardware-protected keystore (TPM/secure element), "
            "not in a plaintext XML file. The PKCS#12 client certificate should be provisioned "
            "via SCEP at runtime, not stored persistently on flash. "
            "If persistent storage is unavoidable, encrypt with a key derived from "
            "device-unique hardware identity (SUDI) rather than a static password. "
            "Restrict /usr/local/wifi/ to read-only mounts where possible."
        ),
        "yara": """rule cisco_8821_radius_secret_plaintext {
    meta:
        description = "8821 RADIUS shared secret stored in plaintext XML on filesystem"
        severity = "HIGH"
    strings:
        $secret_field  = "auth_server_shared_secret" ascii
        $xml_fmt       = "<auth_server_shared_secret>" ascii
        $usercert_p12  = "usercert/user.p12" ascii
    condition:
        $secret_field or $usercert_p12
}""",
    },
    {
        "id": "F4",
        "title": "Factory Default Wi-Fi Profile Connects to Open SSID 'cisco' - Evil Twin Attack Surface",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-1390",
        "description": (
            "The factory default `/etc/wlan_profiles.xml` shipped with the 8821 "
            "contains a pre-configured Wi-Fi profile: "
            "`<ssid>cisco</ssid>` with `<auth>none</auth>` (open authentication). "
            "This profile is marked `<enable>yes</enable>` and `<locked>Local</locked>`. "
            "On factory reset or when profile provisioning fails, the phone "
            "falls back to this pre-populated profile and will automatically associate "
            "to any Wi-Fi network advertising the SSID `cisco` without any "
            "authentication. An attacker can deploy a rogue AP named `cisco` "
            "(trivially done with hostapd on any Linux system or a portable router). "
            "Once associated, the phone sends TFTP provisioning requests to the "
            "default gateway (Cisco Unified Communications Manager address), "
            "which the attacker controls. This enables: malicious firmware delivery, "
            "SIP credential exfiltration via rogue CUCM, and call interception."
        ),
        "default_profile": {
            "name":     "Profile 1",
            "ssid":     "cisco",
            "auth":     "none (open - no authentication)",
            "dhcp":     "yes",
            "enabled":  "yes",
            "locked":   "Local",
            "priority": "3 (highest priority among 4 profiles)",
        },
        "attack_scenario": [
            "Attacker deploys 'cisco' SSID open AP in hotel/conference room/hospital hallway",
            "8821 auto-associates (priority 3, auth=none, no user prompt)",
            "Phone sends TFTP provisioning request (default: CUCM IP from DHCP option 150)",
            "Attacker's rogue TFTP server delivers SEP<MAC>.cnf.xml with malicious SIP proxy",
            "All subsequent SIP calls route through attacker's server",
            "Or: deliver debug-enabled firmware via TFTP to persist root access",
        ],
        "impact": [
            "Auto-connect to any 'cisco' SSID without user interaction",
            "Rogue AP = full network man-in-the-middle for SIP/TFTP/HTTPS traffic",
            "Factory reset + rogue AP = SIP credential exfil and firmware implant",
            "Deployed in healthcare: rogue AP in hospital = full hospital PBX MITM",
        ],
        "remediation": (
            "Remove the default pre-populated 'cisco' open profile from the factory image. "
            "The default wlan_profiles.xml should have all profiles disabled with no SSID. "
            "Add a check: if auth=none, require explicit local admin confirmation. "
            "If locked=Local profiles survive factory reset, require admin approval "
            "before enabling any profile received via TFTP provisioning."
        ),
        "yara": """rule cisco_8821_default_open_cisco_ssid {
    meta:
        description = "8821 factory profile auto-connects to open SSID 'cisco' - evil twin attack"
        severity = "HIGH"
    strings:
        $ssid_cisco = "<ssid> cisco </ssid>" ascii
        $auth_none  = "<auth> none </auth>" ascii
        $profile_en = "<enable> yes </enable>" ascii
    condition:
        $ssid_cisco and $auth_none
}""",
    },
    {
        "id": "F5",
        "title": "EAP-MSCHAPv2 Supported - 802.1X Credentials Crackable Offline via Challenge-Response",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-916",
        "description": (
            "The 8821's wlanmgr supports EAP-MSCHAPv2 as a 802.1X authentication "
            "method (`<auth>MSCHAPV2</auth>` in wlan_profiles.xml, confirmed via "
            "wlanmgr strings `auth=MSCHAPV2`). EAP-MSCHAPv2 is cryptographically "
            "broken: the challenge-response exchange can be cracked offline with "
            "tools like `asleap` or `hashcat -m 5500` (NetNTLMv1) once captured "
            "from the air. An attacker who runs a rogue AP (see F4) or captures "
            "a 4-way EAPOL exchange via a deauth attack can crack the Active "
            "Directory username and password (NT hash) offline, recovering corporate "
            "domain credentials without any server-side interaction. "
            "Combined with F3 (RADIUS secret plaintext) and the KRACK vulnerability "
            "(F2), an attacker can capture the MSCHAPv2 exchange, crack it, and "
            "pivot to Active Directory with the phone user's corporate credentials."
        ),
        "eap_methods_supported": [
            "MSCHAPv2 (auth=MSCHAPV2) - challenge-response, crackable offline",
            "GTC (auth=GTC) - password in plaintext inside TLS tunnel",
            "EAP-AKA (SIM-based) - confirmed via wpa_supplicant strings",
            "CCKM (Cisco proprietary fast roaming) - Cisco-specific key management",
        ],
        "crack_methodology": (
            "Capture EAPOL frames (via rogue AP or deauth+capture). "
            "Extract NT-challenge-response. "
            "Run: `hashcat -m 5500 hash.txt /dev/shm/wordlist.txt`. "
            "Result: corporate AD password. "
            "Alternatively: `asleap -r capture.pcap -W wordlist.txt`."
        ),
        "impact": [
            "Captured 802.1X MSCHAPv2 exchange -> offline AD password crack",
            "Corporate AD credentials from phone = pivot to mail, VPN, EHR systems",
            "No server interaction required: purely passive attack once handshake captured",
        ],
        "remediation": (
            "Replace EAP-MSCHAPv2 with EAP-TLS (certificate-based) for 802.1X on all 8821 deployments. "
            "If MSCHAPv2 is required, enforce PEAP-MSCHAPv2 and validate the RADIUS server "
            "certificate to prevent rogue AP challenge injection. "
            "Require that PEAP inner authentication uses PEAP v0 with server cert "
            "pinned to the corporate RADIUS CA."
        ),
        "yara": """rule cisco_8821_mschapv2_802_1x {
    meta:
        description = "8821 supports EAP-MSCHAPv2 - 802.1X credentials crackable offline"
        severity = "MEDIUM"
    strings:
        $mschapv2 = "auth=MSCHAPV2" ascii
        $mschapv2_xml = "<auth>MSCHAPV2</auth>" ascii nocase
        $wlanmgr = "wlanmgr" ascii
    condition:
        $mschapv2 or $mschapv2_xml
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
