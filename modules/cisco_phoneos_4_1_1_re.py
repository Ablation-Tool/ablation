"""
Cisco PhoneOS 4.1.1 RE Module
Target: PHONEOS.4-1-1-0101-76.zip
Platform: Cisco 9800 series (6th generation) - 9841, 9851, 9811, 9861, 9871, 8875
Format: UBI image (raw, no SBN header) -> UBIFS
Arch: ARM 32-bit, TI DaVinci + EBR bootloader (same platform family as 8831)
Build: 2026-05-13
"""

METADATA = {
    "target":         "PHONEOS.4-1-1-0101-76",
    "version":        "PhoneOS 4.1.1-0101-76",
    "generation":     "6th generation Cisco IP Phone (9800 series)",
    "platforms": {
        "9841_51":    "rootfs-9841_51.4-1-1-0101-76.sbn (144MB raw UBI) - shared by 9841/9851",
        "9811":       "miniroot-9811.4-1-1-0101-76.sbn (20MB) + same kernel/rootfs as 9841_51",
        "9861":       "PHONEOS-9861.4-1-1-0101-76.pkg (267MB) - PKG format, not analyzed here",
        "9871":       "PHONEOS-9871.4-1-1-0101-76.pkg (270MB) - PKG format, not analyzed here",
        "8875":       "PHONEOS-8875.4-1-1-0101-76.loads + .pkg (212MB) - loads + PKG format",
    },
    "arch":           "ARM 32-bit, TI DaVinci + EBR/UBL bootloader",
    "rootfs_format":  "Raw UBI image (UBI# magic, no SBN wrapper), UBIFS filesystem",
    "build_date":     "2026-05-13",
    "source":         "/media/cowboy/research/Cisco-IP PHONE/PHONEOS.4-1-1-0101-76.zip",
    "deploy_modes": {
        "0": "unknown",
        "1": "onprem (CUCM)",
        "2": "edge (Webex Edge)",
        "3": "huron (Webex Calling)",
        "4": "mra (Mobile and Remote Access via Expressway)",
        "5": "mpp (3PCC/MPP - Third-Party Call Control) **DEFAULT ON FACTORY RESET**",
    },
    "notable_binaries": {
        "edge_gateway":       "Webex cloud registration - OAuth, SRP, identity.webex.com",
        "webexd":             "Webex client daemon (MPP mode)",
        "nfcmain":            "NFC authentication daemon (runs as root, ST25 NFC chip)",
        "spr_voip":           "Secure Provisioning/Registration VoIP module",
        "apigateway":         "REST API bridge to D-Bus (same as MPP 14.4.1, runs as root)",
        "te_service":         "ThousandEyes network monitoring agent (conditionally loaded)",
        "camera_service":     "Camera daemon (9841/9871 have integrated cameras)",
        "webs":               "Embedded web server",
        "xinetd":             "Super-daemon for additional services",
        "syssecurity_monitor": "System security monitoring daemon",
    },
    "libraries": {
        "libdataEncryption.so": "Credential encryption: sec_encrypt_appData/sec_decrypt_appData via TAMS",
        "libplatformapi.so":    "Platform API (provides TAMS interface)",
        "libdataEncryption_deps": ["libplatformapi.so", "libplatformAbstraction.so", "libssl.so.1.1", "libcrypto.so.1.1"],
    },
    "security_baseline": {
        "debug_account":    "LOCKED (debug:*) - NOT vulnerable to debug:debug regression",
        "selinux":          "ENFORCING (SELINUXTYPE=cisco) - SELinux active on all 9800 phones",
        "fips_bypass":      "NOT PRESENT - no CISCOSSL_FOM_DIAG=SKIP_POST in S92phone.sh",
        "tams":             "Hardware TAMS (TAM_HW_0) on 9841/9851; Software TAMS (TAM_SW_0) on 9811",
        "iptables":         "Firewall active by default (iptables.sh + ip6tables.sh in startup)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "libdataEncryption.so Contains 'This is seed of security key' - Potential TAMS Fallback Key",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-321",
        "description": (
            "The credential encryption library `libdataEncryption.so` exports "
            "`sec_get_security_key`, `sec_encrypt_data_with_key`, and `sec_decrypt_data_with_key`. "
            "The library dynamically loads TAMS functions at runtime via `dlopen` from "
            "`libplatformapi.so`: `tam_encrypt_appdata` and `tam_decrypt_appdata`. "
            "Under normal operation, encryption keys are hardware-backed via TAMS. "
            "HOWEVER: the library contains the printable string "
            "`This is seed of security key`. This string appears as a standalone "
            "printable literal adjacent to the `sec_get_security_key` function symbol. "
            "In embedded device encryption implementations, this pattern typically "
            "indicates one of two scenarios: "
            "(a) A TAMS-unavailable fallback key derivation path that uses this string "
            "as a PBKDF2/HKDF seed, producing a static fleet-wide AES key when TAMS "
            "cannot be reached (e.g., during boot, before tamd_mgmt is running, or on "
            "TAM_SW-only models like the 9811). "
            "(b) A development marker that was never removed from the production build. "
            "The `sec_get_encryption_key` function is called BEFORE `sec_get_security_key` "
            "in the exported symbol table - suggesting a two-phase key lookup: primary "
            "(TAMS) then fallback (seed-derived). "
            "The 9811 uses `TAM_SW_0` (software TAMS) rather than `TAM_HW_0` (hardware HSM). "
            "Software TAMS implementations are typically less tamper-resistant, making "
            "the 9811 variant particularly interesting for fallback key extraction."
        ),
        "evidence": {
            "string":    "'This is seed of security key' (printable, not demangled C++ symbol)",
            "adjacent":  "Located adjacent to sec_get_security_key in binary",
            "functions": [
                "sec_get_encryption_key (primary - TAMS HSM key)",
                "sec_get_security_key (secondary - possible seed-based fallback)",
                "sec_decrypt_data_with_key / sec_encrypt_data_with_key",
            ],
            "tams_calls":    "tam_encrypt_appdata, tam_decrypt_appdata (via dlopen libplatformapi.so)",
            "9811_tams":     "TAM_SW_0 (software TAMS) - lower tamper resistance than TAM_HW_0",
        },
        "impact": [
            "If seed string is used as TAMS-unavailable fallback: every 9800 device shares identical AES key",
            "Static fleet-wide key: offline decryption of all captured credential files once key is derived",
            "Credentials at risk: refreshtoken.txt, encrypted_name.txt, encrypted_pwd.txt (Webex OAuth + user creds)",
            "9811 (software TAMS) most accessible target for fallback key extraction via TAMS simulation",
        ],
        "credentials_at_risk": {
            "path":        "/usr/local/misc/gateway/",
            "files": [
                "refreshtoken.txt (Webex OAuth refresh token)",
                "encrypted_name.txt (username, 'encrypted')",
                "encrypted_pwd.txt (password, 'encrypted')",
                "username.txt (username in plaintext - no 'encrypted' prefix)",
                "cisdomain_name.txt (Cisco domain)",
                "sparkuc_domain_name.txt (Webex/Spark UC domain)",
            ],
        },
        "remediation": (
            "Audit the fallback key derivation path in `sec_get_security_key`. "
            "If `'This is seed of security key'` is a static fallback seed, replace it with "
            "a per-device unique value derived from the hardware serial number and burned "
            "into the TAMS during manufacturing. "
            "Ensure all credential files are encrypted ONLY via TAMS and that the "
            "`sec_decrypt_appData` path strictly fails closed (returns error) when TAMS is unavailable. "
            "Audit the 9811 TAM_SW_0 implementation for the fallback key derivation path."
        ),
        "yara": """rule cisco_phoneos_4_1_1_static_key_seed {
    meta:
        description = "PhoneOS 4.1.1 libdataEncryption.so contains potential static key seed string"
        severity = "HIGH"
    strings:
        $seed_string  = "This is seed of security key" ascii
        $enc_lib      = "libdataEncryption.so" ascii
        $sec_get_key  = "sec_get_security_key" ascii
    condition:
        $seed_string or ($sec_get_key and $enc_lib)
}""",
    },
    {
        "id": "F2",
        "title": "Factory-Reset Default Deploy Mode = MPP (Mode 5) Starts apigateway on All 9800 Phones",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-1188",
        "description": (
            "The `check_deploy_mode.sh` script defines 5 deploy modes (0-5). "
            "The `is_mpp_mode()` function reads `/usr/local/etc/deploymode.conf` to determine mode. "
            "If the file does NOT exist (factory reset, unconfigured phone), the script calls "
            "`/usr/bin/setdeploymode 5` - setting the phone to MODE_MPP (3PCC). "
            "Mode 5 (MPP) triggers `apigateway.sh start` in S92phone.sh. "
            "The apigateway process runs as `BEUID=root:root`. "
            "The REST API gateway exposes `/api/Call/v1` (call control) and "
            "`/api/Config/v1` (phone configuration) with no access control when "
            "admin credentials are blank (factory state). "
            "An attacker on the same VLAN as an unconfigured or factory-reset 9800 "
            "phone can make/receive calls, read the phone configuration, and "
            "enumerate active sessions via the REST API without credentials. "
            "In MPP mode, additionally `webexd`, `cdc_service`, `onboard_service`, "
            "`spr_voip`, and `crashmessage` also start, expanding the attack surface further."
        ),
        "trigger": {
            "condition":    "No /usr/local/etc/deploymode.conf (factory reset)",
            "action":       "setdeploymode 5 (MPP/3PCC mode)",
            "consequence":  "apigateway starts as root with blank admin credentials",
        },
        "mpp_mode_starts": [
            "apigateway (REST API bridge, root)",
            "webexd (Webex daemon)",
            "cdc_service (cloud device control)",
            "onboard_service (onboarding service)",
            "spr_voip (SIP registration)",
            "crashmessage (crash reporting)",
        ],
        "impact": [
            "Unconfigured 9800 phones on enterprise VLAN expose full REST call control",
            "apigateway runs as root: REST API -> D-Bus -> potential privilege escalation chain",
            "MPP mode starts Webex daemon: cloud registration begins immediately on first boot",
            "Attacker can intercept initial Webex/cloud registration from VLAN before IT team configures phone",
        ],
        "remediation": (
            "Change the default deploy mode to MODE_UNKNOWN (0) - require explicit provisioning "
            "before any service mode is set. Do not start apigateway until a valid CUCM/Webex "
            "provisioning step has completed and a non-blank admin password is set. "
            "Firewall the REST API port (typically 80/443 for phoneOS web) to management VLAN only."
        ),
        "yara": """rule cisco_phoneos_4_1_1_default_mpp_mode {
    meta:
        description = "PhoneOS 4.1.1 defaults to MPP mode on factory reset - apigateway starts without credentials"
        severity = "MEDIUM"
    strings:
        $mpp_flag     = "is_mpp_mode" ascii
        $setdeploy    = "setdeploymode" ascii
        $deploymode   = "deploymode.conf" ascii
    condition:
        all of them
}""",
    },
    {
        "id": "F3",
        "title": "NFC Daemon (nfcmain) Runs as Root - JSON Parsing of Untrusted NFC Payload via nlohmann::json",
        "severity": "MEDIUM",
        "cvss": 6.4,
        "cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-20",
        "description": (
            "The 9841/9851 includes an ST25 NFC chip (STMicroelectronics ST25 family). "
            "The `nfcmain` daemon (`BEUID=root:root`) reads NFC tags via `read_from_nfc_device` "
            "and parses the payload using `nlohmann::json` (a C++ JSON library). "
            "The parsed NFC message is exposed via D-Bus as `NFCServiceDbusMessageInterface_adaptor`. "
            "NFC tags within physical proximity (~10 cm) can send arbitrary JSON payloads "
            "to the `nfcmain` process. If the JSON parser or the D-Bus message handler "
            "contains a memory corruption bug (buffer overflow, use-after-free, or "
            "nlohmann::json exception not caught), an attacker with physical access to the "
            "phone can achieve root code execution via a crafted NFC tag. "
            "The attack requires only physical proximity - no credentials, no network. "
            "Conference room phones and lobby phones with public physical access are "
            "at highest risk. "
            "Note: `tam_get_certificate` and `tam_get_private_key` are called by `nfcmain` "
            "to retrieve the device identity from TAMS - a compromised nfcmain process "
            "can extract the device certificate and private key."
        ),
        "nfc_chip":     "STMicroelectronics ST25 (ST25Register.read_from_nfc_device)",
        "daemon":       "nfcmain (BEUID=root:root, D-Bus: NFCServiceDbusMessageInterface_adaptor)",
        "json_parser":  "nlohmann::json (C++ header-only JSON library)",
        "tams_access":  "tam_get_certificate + tam_get_private_key called from nfcmain",
        "impact": [
            "Root code execution via crafted NFC tag from physical proximity",
            "TAMS device cert + private key extractable if nfcmain is compromised",
            "D-Bus IPC surface: compromised nfcmain can send arbitrary D-Bus messages",
            "Conference room phones are accessible by visitors, contractors, and guests",
        ],
        "remediation": (
            "Run nfcmain as a dedicated low-privilege user (e.g., nfc:nfc) with SELinux policy "
            "restricting D-Bus access to NFC-specific interface only. "
            "Wrap the JSON parsing in a memory-safe boundary (buffer size limits, exception handling). "
            "Move TAMS certificate access to a separate privileged process; nfcmain should not "
            "have direct TAMS access. "
            "Add a UI confirmation step before processing NFC payloads that trigger authentication."
        ),
        "yara": """rule cisco_9841_nfcmain_root_json_parser {
    meta:
        description = "9841 NFC daemon runs as root and parses untrusted NFC JSON payload with nlohmann::json"
        severity = "MEDIUM"
    strings:
        $nfc_read = "get_message_from_nfc_device" ascii
        $st25     = "ST25Register" ascii
        $nfc_dbus = "NFCServiceDbusMessageInterface_adaptor" ascii
        $tam_cert = "tam_get_certificate" ascii
    condition:
        $nfc_read and $tam_cert
}""",
    },
    {
        "id": "F4",
        "title": "Webex OAuth Credentials Stored at Predictable Paths - refreshtoken.txt Accessible with Root",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-312",
        "description": (
            "The `edge_gateway` binary stores Webex OAuth credentials in TAMS-encrypted "
            "flat files under `/usr/local/misc/gateway/`. The encrypted files are decrypted "
            "at runtime via `sec_decrypt_appData` -> `tam_decrypt_appdata`. "
            "The files include `refreshtoken.txt` (Webex OAuth refresh token), "
            "`encrypted_name.txt` (username), and `encrypted_pwd.txt` (password). "
            "Additionally, `username.txt` (NOT prefixed with 'encrypted') is stored "
            "in the same directory, possibly in plaintext. "
            "While TAMS provides HSM-backed key protection against offline disk analysis, "
            "ANY process running as root (or with the TAMS appdata storage key) can call "
            "`sec_decrypt_appData` at runtime and retrieve plaintext credentials. "
            "With root access (physical or via any root-reachable vulnerability), "
            "an attacker can obtain a long-lived Webex OAuth refresh token for the device "
            "and use it to access Webex Calling, Webex Meetings, and Webex Messages "
            "on the phone's behalf - effectively hijacking the device's cloud identity. "
            "The refresh token grants persistent access until explicitly revoked in Webex Control Hub."
        ),
        "credential_files": {
            "/usr/local/misc/gateway/refreshtoken.txt":     "Webex OAuth refresh token (TAMS-encrypted)",
            "/usr/local/misc/gateway/encrypted_name.txt":   "Username (TAMS-encrypted)",
            "/usr/local/misc/gateway/encrypted_pwd.txt":    "Password (TAMS-encrypted)",
            "/usr/local/misc/gateway/username.txt":         "Username (possibly plaintext)",
        },
        "decryption_chain": [
            "sec_decrypt_appData (libdataEncryption.so) -> tam_decrypt_appdata -> libplatformapi.so -> TAMS HSM"
        ],
        "impact": [
            "Root shell -> runtime TAMS decryption -> plaintext Webex OAuth refresh token",
            "Refresh token grants persistent Webex Calling/Meetings/Messages access as the phone",
            "Enables passive eavesdropping: attacker can join Webex calls the phone is invited to",
            "Token remains valid until admin revokes in Webex Control Hub - no automatic expiry",
        ],
        "remediation": (
            "Restrict `/usr/local/misc/gateway/` to root:root 0600. "
            "Use SELinux to restrict TAMS appdata access to edge_gateway context only, "
            "preventing other root processes from calling sec_decrypt_appData on gateway storage. "
            "Store the refresh token with per-file TAMS binding (tie the TAMS key to the "
            "edge_gateway binary hash, not just to root access). "
            "Remove `username.txt` (plaintext) - use only the encrypted_name.txt variant."
        ),
        "yara": """rule cisco_9841_webex_oauth_credential_paths {
    meta:
        description = "9841 PhoneOS 4.1.1 edge_gateway stores Webex OAuth refresh token at predictable path"
        severity = "MEDIUM"
    strings:
        $refresh_tok = "/usr/local/misc/gateway/refreshtoken.txt" ascii
        $enc_name    = "/usr/local/misc/gateway/encrypted_name.txt" ascii
        $user_txt    = "/usr/local/misc/gateway/username.txt" ascii
        $sec_decrypt = "sec_decrypt_appData" ascii
    condition:
        ($refresh_tok and $enc_name) or $sec_decrypt
}""",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 0,
    "high":     1,
    "medium":   3,
    "low":      0,
    "positive_security_baseline": (
        "PhoneOS 4.1.1 is significantly more secure than MPP 14.4.1: "
        "SELinux enforcing, debug account locked, no FIPS POST bypass, "
        "hardware TAMS (9841/9851), iptables enabled by default. "
        "The 9800 series represents a major security architecture improvement "
        "over the 8800/7800 MPP lineup."
    ),
    "note": (
        "9861/9871/8875 PKG files not analyzed here (267-270MB each, likely Android-based). "
        "ThousandEyes agent loads conditionally - binary may be absent from this rootfs, "
        "provisioned separately via download or present in PKG variants."
    ),
}
