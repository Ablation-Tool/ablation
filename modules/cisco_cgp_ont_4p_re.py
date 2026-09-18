"""
Cisco CGP-ONT-4P GPON/XGS-PON Optical Network Terminal RE Module
Firmware: CGP-ONT-4P-1.1.3.18.tar (21MB POSIX tar)
Version: 1.1.3.18 -- Wed Oct 19 08:38:10 CST 2022
Hardware: N40-429
Build user: walkman/walkman (ODM origin)
Codename: luna (/proc/luna_watchdog/watchdog_flag in rc34)
Source: /media/cowboy/research/Cisco-Catalyst/CGP-ONT-4P-1.1.3.18.tar
Rootfs: SquashFS v4.0 xz-compressed, 17.7MB, 1709 inodes, BusyBox Linux
Mounted: /tmp/cgp_mnt

Architecture: MIPS (Realtek RTL867x SOC, per mib binary strings)
ODM: Chinese ODM (YueMe framework, Chinese comments in fwu.sh, walkman build user)
Chipset: Realtek RTL867x-ADSL platform
OMCI: Multi-vendor (ALU/Huawei/ZTE OLT compatibility via vendor-specific conf files)
Storage: UBIFS config partition (/var/config via ubi_Config); runtime /var from UBIFS

Init chain: BusyBox /etc/inittab -> rcS -> rc0..rc63 sequential
Key services: configd (MIB daemon), boa (HTTP), telnetd, cwmpClient (TR-069), wscd (WPS/UPnP)
Runtime credentials: /var/passwd (root, written by startup binary), /var/boaUser.passwd and
                     /var/boaSuper.passwd (web, written by boa/cwmpClient from MIB)
Web server: Boa 0.94, port 80/443, AngularJS front-end, SHA-256 client-side password hashing
"""

METADATA = {
    "target":    "Cisco CGP-ONT-4P GPON/XGS-PON Optical Network Terminal",
    "firmware":  "1.1.3.18 (Oct 19 2022)",
    "hardware":  "N40-429",
    "codename":  "luna (platform), YueMe framework (ODM)",
    "odm":       "Chinese ODM (walkman build user, YueMe framework, RTL867x Realtek SOC)",
    "os":        "BusyBox Linux, SquashFS v4.0 xz rootfs, UBIFS config",
    "omci_support": {
        "ALU":    "omci_ignore_mib_tbl_ALU.conf",
        "Huawei": "omci_ignore_mib_tbl_HUAWEI.conf",
        "ZTE":    "omci_ignore_mib_tbl_ZTE.conf",
    },
    "default_ssid": "Management",
    "web_auth":  "boa -> /var/boaUser.passwd + /var/boaSuper.passwd (populated from MIB at boot)",
    "telnet":    "telnetd -l /bin/login (startup binary), credentials from /var/passwd (root)",
    "tr069_port": 7547,
    "models_visible": ["GN2000-04G-2VTP", "4GE-POE-2POTS-CATV", "BVMGC10GRA"],
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Hardcoded Default WiFi PSK 'ciscoap1' in MIB Firmware Binary -- All Devices Share Identical Factory Credential",
        "severity": "HIGH",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The CGP-ONT-4P firmware ships with a hardcoded default WiFi pre-shared key "
            "'ciscoap1' embedded in the `mib` binary for the management SSID 'Management'. "
            "The string appears twice consecutively in the mib defaults block (one per radio band). "
            "Any CGP-ONT-4P at factory defaults accepts WiFi authentication with PSK 'ciscoap1' "
            "on the 'Management' SSID. Gaining WiFi access to the management network allows "
            "attack of the web management interface (boa, port 80/443), telnet (port 23), "
            "and TR-069 CWMP connection request listener. The PSK is identical across all "
            "devices shipping firmware 1.1.3.18 -- there is no per-device randomization. "
            "A single published PSK compromise affects every unmodified unit globally."
        ),
        "evidence": {
            "binary": "/bin/mib",
            "ssid":   "Management",
            "psk":    "ciscoap1",
            "occurrences": 2,
            "context": "Management / ciscoap1 / ciscoap1 (two radio bands, same key)",
        },
        "impact": [
            "WiFi PSK 'ciscoap1' grants management network access to any attacker in RF range",
            "No per-device PSK randomization -- single PSK applies to entire deployed fleet",
            "Management WiFi provides direct access to boa web UI, telnet, and TR-069 port",
            "Enables LAN-side attack chain: F1 -> F2 (telnet) or F1 -> F3 (CWMP)",
        ],
        "remediation": (
            "Generate per-device unique WiFi PSK during manufacturing (e.g., derived from "
            "device serial number + secret salt stored in secure OTP). "
            "Print device-specific PSK on label or provision via OMCI from the OLT. "
            "Disable the management SSID by default; enable only for initial setup."
        ),
        "yara": """rule cisco_cgp_ont_default_wifi_psk {
    meta:
        description = "CGP-ONT-4P ships with hardcoded WiFi PSK ciscoap1 for Management SSID"
        severity = "HIGH"
    strings:
        $psk  = "ciscoap1" ascii
        $ssid = "Management" ascii
        $mib  = "TELNET_ENABLE" ascii
    condition:
        $psk and $mib
}""",
    },
    {
        "id": "F2",
        "title": "Telnet Enabled by Default -- Plaintext Root Credentials Transmitted on Port 23",
        "severity": "HIGH",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-319",
        "description": (
            "The CGP-ONT-4P startup binary unconditionally launches "
            "`telnetd -l /bin/login&` on port 23. "
            "The TELNET_ENABLE MIB key confirms telnet is a configurable service, "
            "but the firmware ships with it enabled. Telnet transmits all credentials "
            "and session data in plaintext, allowing passive capture of the root "
            "password on any network segment with visibility to the management port. "
            "The startup binary writes root credentials to `/var/passwd` using the "
            "format `%s:%s:0:0:root:%s:%s` (populated from MIB at boot). "
            "Three SHA-256crypt hashes for accounts `cisco`, `user`, and `adsl` are "
            "embedded in the mib binary defaults section using empty salt "
            "(`$5$$` -- SHA-256crypt with zero salt bytes). "
            "Empty-salt hashes are identical across all CGP-ONT-4P devices: "
            "if any of these passwords is cracked, every device at factory defaults "
            "is compromised simultaneously. "
            "The firewall rule `iptables -A INPUT -p tcp --dport 23 -j REJECT` "
            "appears in startup but may only apply to the WAN-facing interface; "
            "telnetd is accessible from LAN and management WiFi (SSID 'Management')."
        ),
        "evidence": {
            "startup_binary": "/bin/startup",
            "command":        "telnetd -l /bin/login&",
            "passwd_format":  "%s:%s:0:0:root:%s:%s (written to /var/passwd from MIB)",
            "credential_hashes": {
                "cisco": "$5$$s77OjPdDyhyTHtlpjO0Cs6c3si7JbL6pgupDn4Xma95",
                "user":  "$5$$6JDIwyp2jJiMmCJtCYZ2X/HpKVH1zG.0taOulHevym3",
                "adsl":  "$5$$q0JYT4t3GCxdO.uSPW.PGQpwP4tF32Db5k8IdxSgua9",
            },
            "hash_type": "SHA-256crypt ($5$) with empty salt -- no per-device salt",
            "note": "Hashes not cracked via rockyou; passwords are not in common wordlists",
        },
        "impact": [
            "Telnet session capture yields plaintext root credentials",
            "Empty-salt SHA-256crypt hashes are deterministic -- identical across all devices",
            "Cracking any hash breaks the entire deployed fleet at factory defaults",
            "Port 23 accessible from LAN and management WiFi (ciscoap1 PSK from F1)",
        ],
        "remediation": (
            "Disable telnet by default; enable only via explicit operator configuration on the OLT. "
            "Replace telnet with SSH (dropbear is present in /bin/). "
            "Use per-device salted password hashes during manufacturing -- never embed "
            "zero-salt hashes in firmware images. "
            "Force credential change on first login."
        ),
        "yara": """rule cisco_cgp_ont_telnetd_empty_salt_hashes {
    meta:
        description = "CGP-ONT-4P starts telnetd and embeds empty-salt SHA-256crypt credential hashes"
        severity = "HIGH"
    strings:
        $telnetd    = "telnetd -l /bin/login" ascii
        $empty_salt = "$5$$" ascii
        $hash_cisco = "$5$$s77OjPdDyhyTHtlpjO0Cs6c3si7JbL6pgupDn4Xma95" ascii
    condition:
        $empty_salt or $hash_cisco
}""",
    },
    {
        "id": "F3",
        "title": "TR-069 CWMP Default Connection Request Password '12345670' Allows ACS Impersonation",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The CGP-ONT-4P mib binary embeds the TR-069 CWMP defaults block: "
            "ACS port 7547, ACS path `/tr069`, connection request password `12345670`. "
            "The CWMP connection request mechanism allows an ACS to authenticate to "
            "the CPE device and trigger immediate contact. "
            "With the default connection request password `12345670`, any attacker on "
            "the management network can send an authenticated HTTP connection request "
            "to the device's TR-069 connection request URL, forcing the ONT to immediately "
            "connect to an attacker-controlled ACS and receive arbitrary CWMP provisioning "
            "commands. CWMP commands can: change admin passwords, reconfigure WiFi, "
            "push firmware upgrades, and modify GPON parameters. "
            "This is a full device takeover path from the management network without "
            "requiring knowledge of the admin credential."
        ),
        "evidence": {
            "binary":      "/bin/mib",
            "acs_port":    7547,
            "acs_path":    "/tr069",
            "conreq_pass": "12345670",
            "mib_key":     "CWMP_CONREQ_PASSWORD (context: client/7547/tr069/12345670)",
        },
        "cwmp_attack": [
            "1. Identify ONT's LAN-side IP address",
            "2. Send HTTP GET http://<ONT-IP>:7547/tr069 with Authorization: Basic <base64(Cisco:12345670)>",
            "3. ONT connects to attacker ACS",
            "4. Send CWMP SetParameterValues to change admin credentials or upload malicious firmware",
        ],
        "impact": [
            "Full ONT configuration control via rogue ACS without admin password",
            "CWMP access allows firmware update to attacker-controlled image",
            "Password reset via CWMP bypasses web auth entirely",
        ],
        "remediation": (
            "Generate per-device CWMP connection request credentials during manufacturing "
            "or via OLT OMCI provisioning. "
            "Restrict TR-069 access to OLT-side management VLAN (not LAN/WiFi). "
            "Require mutual TLS for CWMP sessions."
        ),
        "yara": """rule cisco_cgp_ont_cwmp_default_password {
    meta:
        description = "CGP-ONT-4P embeds default CWMP connection request password 12345670"
        severity = "MEDIUM"
    strings:
        $cwmp_pass = "12345670" ascii
        $tr069_path = "/tr069" ascii
        $cwmp_client = "cwmpClient" ascii
    condition:
        $cwmp_pass and $tr069_path
}""",
    },
    {
        "id": "F4",
        "title": "UPnP simplecfgservice Exposes Unauthenticated RebootAP and ResetAP Actions",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "The file `/etc/simplecfgservice.xml` is a UPnP WPS service descriptor "
            "that exposes control actions with no authentication requirement. "
            "Exposed unauthenticated actions include: "
            "`GetDeviceInfo` (returns device information), "
            "`PutMessage` (sends WPS messages to the device), "
            "`GetAPSettings` / `SetAPSettings` / `DelAPSettings` (read/write WiFi AP config), "
            "`GetSTASettings` / `SetSTASettings` / `DelSTASettings` (read/write WiFi station config), "
            "`RebootAP` (triggers AP reboot), `ResetAP` (triggers AP factory reset), "
            "`RebootSTA` and `ResetSTA` (STA reboot/reset). "
            "The wscd binary implements this service and is launched by the init chain. "
            "The UPnP service is accessible from any host on the LAN/management network "
            "without authentication. `ResetAP` resets the ONT's wireless configuration "
            "to factory defaults, and combined with F1 (default PSK 'ciscoap1'), "
            "restores the known-PSK state on any modified device."
        ),
        "evidence": {
            "file":    "/etc/simplecfgservice.xml",
            "binary":  "/bin/wscd",
            "actions": [
                "GetDeviceInfo (out: device identity, unauthenticated)",
                "SetAPSettings (in: AP config, unauthenticated write)",
                "RebootAP (triggers reboot, unauthenticated)",
                "ResetAP (factory reset of AP config, unauthenticated)",
                "RebootSTA / ResetSTA (unauthenticated)",
            ],
            "protocol": "UPnP SOAP over HTTP, LAN-accessible",
        },
        "impact": [
            "ResetAP resets WiFi config to factory (restores ciscoap1 PSK on any hardened device)",
            "SetAPSettings enables WiFi reconfiguration without web admin credentials",
            "GetDeviceInfo leaks device identity to unauthenticated LAN hosts",
            "RebootAP/RebootSTA enable denial of service from LAN",
        ],
        "remediation": (
            "Require WPS PIN or web session authentication for all SetAP/ResetAP/Reboot actions. "
            "Disable UPnP WPS service unless explicitly enabled via OLT provisioning. "
            "Bind the wscd service to loopback or a specific management interface only."
        ),
        "yara": """rule cisco_cgp_ont_upnp_unauth_reboot_reset {
    meta:
        description = "CGP-ONT-4P UPnP simplecfgservice exposes unauthenticated RebootAP and ResetAP"
        severity = "MEDIUM"
    strings:
        $service   = "simplecfgservice" ascii
        $reboot_ap = "RebootAP" ascii
        $reset_ap  = "ResetAP" ascii
    condition:
        $reboot_ap and $reset_ap
}""",
    },
    {
        "id": "F5",
        "title": "genpem.sh Generates Per-Device SSL Cert Using Device MAC as CN -- Hardcoded Fallback Date Range",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-297",
        "description": (
            "The script `/etc/genpem.sh` (called from rc3 at boot) generates a self-signed "
            "RSA-2048 TLS certificate for the web management interface. "
            "The certificate CN is set to the device MAC address: "
            "`openssl ... -subj /CN=$MAC_ADDR/`. "
            "If the MAC address MIB value is null, the script uses hardcoded fallback dates: "
            "NotBefore `191008015429Z` (Oct 8 2019) and NotAfter `291007015429Z` (Oct 7 2029). "
            "Two findings: "
            "(1) Using the MAC address as the certificate CN enables passive network fingerprinting "
            "of CGP-ONT-4P devices by certificate CN observation on port 443. "
            "(2) The hardcoded fallback validity window (exactly 10 years from a fixed past date) "
            "produces identical certificates across any devices where MAC MIB resolution fails, "
            "allowing fingerprinting of incomplete provisioning states. "
            "Stored at `/config/ssl_key.pem` and `/config/ssl_cert.pem` (UBIFS config partition)."
        ),
        "evidence": {
            "script": "/etc/genpem.sh",
            "cn_source": "Device MAC address from MIB",
            "fallback_not_before": "191008015429Z (Oct 8 2019)",
            "fallback_not_after":  "291007015429Z (Oct 7 2029)",
            "key_storage": "/config/ssl_key.pem (UBIFS)",
            "cert_storage": "/config/ssl_cert.pem (UBIFS)",
        },
        "impact": [
            "MAC address in certificate CN fingerprints CGP-ONT-4P devices via TLS certificate scan",
            "Hardcoded fallback cert is identical across all units with failed MAC resolution",
            "Self-signed cert not trusted by browsers -- typical users click through the warning",
        ],
        "remediation": (
            "Use a domain name or OUI-randomized string as the certificate CN instead of the MAC. "
            "Provision TLS certificates from the OLT via OMCI or TR-069 rather than self-signing. "
            "Remove hardcoded fallback dates; fail securely (do not start HTTPS) if MAC is unavailable."
        ),
        "yara": """rule cisco_cgp_ont_mac_as_cert_cn {
    meta:
        description = "CGP-ONT-4P genpem.sh uses device MAC as SSL cert CN with hardcoded fallback dates"
        severity = "MEDIUM"
    strings:
        $genpem    = "genpem.sh" ascii
        $not_after = "291007015429Z" ascii
        $ssl_key   = "/config/ssl_key.pem" ascii
    condition:
        $not_after or $ssl_key
}""",
    },
    {
        "id": "F6",
        "title": "ODM Supply Chain Metadata Exposure -- Chinese ODM Origin Fully Visible in Firmware",
        "severity": "LOW",
        "cvss": 2.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "Multiple firmware artifacts expose the complete ODM supply chain: "
            "(1) POSIX tar metadata: build user `walkman` and group `walkman` on all files. "
            "(2) `fwu.sh` script: Chinese language comment "
            "`### 兼容回退以前版本，回退版本时检测版本号 ###` ('compatible with prior version downgrade; "
            "check version on downgrade'), YueMe framework references, `G3` hardware identifier. "
            "(3) `/proc/luna_watchdog/watchdog_flag` reference in rc34: platform codename `luna`. "
            "(4) Realtek RTL867x-ADSL chipset family confirmed in mib binary default SSID name. "
            "(5) OEM model identifiers: `GN2000-04G-2VTP`, board ref `74-124298-01`, "
            "SN prefix `BVMGC10GRA`, `CGSY5A000001`. "
            "This metadata enables supply-chain research: identifying the ODM, the chipset "
            "vendor SDK (Realtek RTL867x), and other Cisco-branded products sharing the "
            "same firmware base (other luna-platform ONTs from the same Chinese ODM)."
        ),
        "evidence": {
            "build_user": "walkman/walkman (POSIX tar metadata on all files)",
            "codename":   "luna (watchdog path /proc/luna_watchdog/watchdog_flag)",
            "framework":  "YueMe (fwu.sh reference)",
            "chipset":    "Realtek RTL867x-ADSL (mib binary SSID default RTL867x-ADSL)",
            "chinese_comment": "兼容回退以前版本，回退版本时检测版本号 (fwu.sh)",
            "oem_models": ["GN2000-04G-2VTP", "4GE-POE-2POTS-CATV", "BVMGC10GRA"],
            "board_ref":  "74-124298-01",
        },
        "impact": [
            "ODM identity enables cross-product vulnerability research across luna-platform devices",
            "Realtek RTL867x SDK vulnerabilities apply to any product sharing this base",
            "Supply chain visibility aids competitive intelligence and counterfeit detection research",
        ],
        "remediation": "Strip build metadata from release tarballs; remove YueMe/platform references from production scripts.",
    },
]

SUMMARY = {
    "total":    6,
    "critical": 0,
    "high":     2,
    "medium":   3,
    "low":      1,
    "note": (
        "F1 and F2 are the primary attack surface. F1 (ciscoap1 default WiFi PSK) provides "
        "LAN access to the management interface; F2 (telnet + empty-salt credential hashes) "
        "provides root access once on LAN. F3 (CWMP default password 12345670) enables "
        "full device configuration takeover from LAN without needing admin credentials. "
        "The empty-salt SHA-256crypt hashes in F2 (cisco/user/adsl) were not cracked via "
        "rockyou wordlist but are deterministic across all devices -- any future crack "
        "applies fleet-wide. The Realtek RTL867x SDK base suggests shared vulnerabilities "
        "with other ODM products on the luna platform."
    ),
}
