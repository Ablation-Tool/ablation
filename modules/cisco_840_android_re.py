"""
Cisco CP-840 Video Phone Android RE Module
Target: cmterm-840.1-11-2-2927-89938.zip
Format: Android OTA (A/B) + APK bundle, codename "mars" (build) / "Saturn" (attestation)
OS: Android 10 (API 29), QKQ1.210128.001, security patch 2023-02-05
OEM Platform: Spectralink (ALL system APKs are com.spectralink.*)
Source: /media/cowboy/research/Cisco-IP PHONE/
"""

METADATA = {
    "target":         "Cisco CP-840 Video Phone",
    "outer_zip":      "cmterm-840.1-11-2-2927-89938.zip",
    "loads_file":     "sip840-1.11.2.2927-89938.loads",
    "apk_bundle":     "sip840-apk_update-signed-1.11.2.2927.zip",
    "ota_bundle":     "sip840-ota_update-signed-1.11.0.2878.zip",
    "sig_file":       "sip840-apk_update-signed-1.11.2.2927.sig",
    "os":             "Android 10 (API 29), QKQ1.210128.001",
    "build_type":     "user/release-keys",
    "android_codename": "mars (OTA build) / Saturn (attestation cert identity)",
    "security_patch": "2023-02-05",
    "oem_platform":   "Spectralink (ALL system APKs under com.spectralink.*)",
    "attestation_pki": {
        "device_identity":   "CN=SaturnAttestation (fleet-shared per firmware version)",
        "attestation_ca":    "CN=Attestation CA, OU=UCTG, O=Cisco Systems Inc., L=Boulder, ST=CO, C=US",
        "ca_validity":       "2020-06-02 to 2047-10-19 (27 years)",
        "signature_algo":    "RSA-2048 (256 bytes in loads file binary prefix)",
    },
    "ota_signing": {
        "cert_cn":      "CN=Cisco UCTG, OU=UCTG, O=Cisco Systems Inc., L=San Jose, ST=CA, C=US",
        "validity":     "2020-03-19 to 2047-08-05 (27 years)",
        "key_size":     "RSA-2048",
    },
    "apk_count":     18,
    "apk_list": [
        "CiscoPhone-32.4.89938.apk (13.1MB)",
        "Webex-43.9.0.110.apk (379MB)",
        "WebAPI-26.1.88690-cisco.apk (3.4MB)",
        "DpcLite-26.1.88637-cisco.apk (2.0MB)",
        "SlnkDeviceSettings-30.0.89093-cisco.apk",
        "SlnkOTA-26.1.88715-cisco.apk",
        "SlnkDiagnostics-26.1.88646-cisco.apk",
        "SmartLauncher-26.1.88659-cisco.apk (kiosk launcher)",
    ],
    "source": "/media/cowboy/research/Cisco-IP PHONE/cmterm-840.1-11-2-2927-89938.zip",
}

LOADS_FORMAT = {
    "total_bytes": 1820,
    "sections": {
        "binary_prefix":  "bytes 0-430 (431 bytes): TLV identity block + RSA-2048 signature",
        "attestation_ca": "bytes 431-1377 (947 bytes): DER-encoded Attestation CA certificate",
        "ascii_config":   "bytes 1378-1819 (442 bytes): INI-style config block",
    },
    "prefix_tlv_structure": {
        "tag_01_len2": "format version: 0x0100",
        "tag_02_len2": "identifier/nonce: 0x0562",
        "tag_03_len122": "device identity block (nested TLV):",
        "tag_04_len20": "  subject: CN=SaturnAttestation",
        "tag_05_len8":  "  serial/UID: 12 39 82 10 98 32 18 44",
        "tag_06_len67": "  issuer: CC=US,ST=CO,L=Boulder,OU=UCTG,O=CiscoSystems,Inc.,CN=AttestationCA",
        "tag_07_len15": "flags/extensions block",
        "tag_0c_len256": "RSA-2048 signature (device attestation signature over identity block)",
        "tag_00_len24": "firmware version string: sip840-1.11.2.2927-89938",
        "tag_0f_len4":  "timestamp: 0x693c6977",
    },
    "ascii_config_keys": {
        "[CISCO-ID]":  "id_version = sip840-1.11.2.2927-89938",
        "[PLATFORM]":  "platform_version = sip840-ota_update-signed-1.11.0.2878.zip",
        "[APKBUNDLE]": "apkbundle_version = sip840-apk_update-signed-1.11.2.2927.zip",
        "[DIALER]":    "dialer_version = (empty)",
    },
    "sig_file": {
        "encoding": "base64",
        "decoded_bytes": 256,
        "decoded_first8": "4592e803e23d8f14",
        "interpretation": "RSA-2048 signature of APK bundle (separate from loads file prefix signature)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Spectralink OEM Platform - Cisco PSIRT Advisory Scope Gap for All System APKs",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cwe": "CWE-1357",
        "description": (
            "Every system APK in the CP-840 bundle (17 of 18 APKs) uses the "
            "`com.spectralink.*` base package namespace. The device is an OEM-built "
            "Spectralink product rebranded as Cisco CP-840. Platform components "
            "include: `SlnkHostnameVerifier.java` (custom TLS verifier), "
            "`SlnkWebAPI` (third-party app framework), `SlnkDeviceSettings`, "
            "`SlnkOTA`, `SlnkDiagnostics`, `SlnkPortManager`, `SlnkVQO`, and others. "
            "Cisco PSIRT publishes advisories for Cisco-authored code; vulnerabilities "
            "in Spectralink's platform components are outside Cisco's disclosure and "
            "patch pipeline. The OTA build metadata confirms: "
            "`post-build=Cisco/mars/840:10/QKQ1.210128.001/user/release-keys`, "
            "where `mars` is the Spectralink-derived Android device codename. "
            "Organizations applying Cisco security advisories for CP-840 will not "
            "receive coverage for vulnerabilities in the Spectralink platform layer."
        ),
        "spectralink_components": [
            "com.spectralink.slnkwebapi (WebAPI framework, READ_SIPDATA permissions)",
            "com.spectralink.devicepolicycontroller (EMM/DPC, WRITE_SECURE_SETTINGS)",
            "com.spectralink.preferenceui (device validation activity)",
            "com.spectralink.slnkcontentprovider (file access, config collection)",
            "com.spectralink.slnklogger (log collection)",
            "SlnkHostnameVerifier.java (custom TLS hostname verification)",
            "SlnkBarcode, SlnkDiagnostics, SlnkLog, SlnkOTA, SlnkPortManager",
        ],
        "android_build_details": {
            "post_build":      "Cisco/mars/840:10/QKQ1.210128.001/1.11.0.2878:user/release-keys",
            "codename_mars":   "Spectralink Android device codename",
            "codename_saturn": "Attestation cert identity (CN=SaturnAttestation)",
        },
        "impact": [
            "Spectralink platform CVEs not covered by Cisco PSIRT advisories",
            "No public disclosure channel for Spectralink-layer vulnerabilities in Cisco-branded device",
            "Supply chain risk: Cisco rebrands Spectralink security posture to enterprise buyers",
        ],
        "remediation": (
            "Cisco should publish a joint advisory process with Spectralink covering "
            "CP-840 Spectralink-platform vulnerabilities. Security advisories for CP-840 "
            "must enumerate the Spectralink platform version alongside the Cisco firmware version. "
            "Customers should treat CP-840 as a Spectralink Android device and subscribe to "
            "Spectralink security advisories in addition to Cisco PSIRT."
        ),
        "yara": """rule cisco_840_spectralink_platform {
    meta:
        description = "CP-840 APK bundle contains Spectralink OEM platform - outside Cisco PSIRT scope"
        severity = "HIGH"
    strings:
        $slnk_webapi = "com.spectralink.slnkwebapi" ascii
        $slnk_dpc    = "com.spectralink.devicepolicycontroller" ascii
        $slnk_hv     = "SlnkHostnameVerifier" ascii
        $mars        = "Cisco/mars/840" ascii
    condition:
        2 of them
}""",
    },
    {
        "id": "F2",
        "title": "Android 10 with 3-Year-Old Security Patches on Healthcare-Deployed Phone",
        "severity": "HIGH",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1395",
        "description": (
            "The CP-840 ships with Android 10 (API 29, QKQ1.210128.001) with a "
            "security patch level of `2023-02-05`. As of September 2026, this is "
            "more than three years behind the current Android security patch level. "
            "Android 10 itself reached end-of-life in Android security bulletin terms "
            "in September 2023. The unpatched CVE window (2023-02 to present) includes "
            "privilege escalation, remote code execution, and sandbox bypass "
            "vulnerabilities across Android framework, kernel, and MediaTek/Qualcomm "
            "components. The phone is marketed for and deployed in healthcare "
            "environments (confirmed by Imprivata SSO integration - `com.imprivata.imda`, "
            "`com.imprivata.locker`), where it processes SIP call credentials and may "
            "have access to electronic health record (EHR) systems via hospital Wi-Fi. "
            "Three years of unpatched Android CVEs on a healthcare endpoint is a "
            "patient data protection risk under HIPAA."
        ),
        "android_version_details": {
            "android_version":      "Android 10 (Q)",
            "api_level":            29,
            "build_id":             "QKQ1.210128.001",
            "security_patch_level": "2023-02-05",
            "patch_gap_months":     "~31 months (as of September 2026)",
            "ota_post_timestamp":   "1740079622 (2025-02-20)",
        },
        "healthcare_context": [
            "com.imprivata.imda (Imprivata Mobile Device Access - healthcare SSO)",
            "com.imprivata.locker (Imprivata Tap-and-Go badge authentication)",
            "com.imprivata.locker.staging (staging env integration)",
            "Imprivata is used in 1,900+ hospitals for EHR single sign-on",
        ],
        "impact": [
            "3+ years of Android CVEs unpatched on healthcare-deployed endpoint",
            "Imprivata SSO context: phone compromise may chain to EHR access",
            "HIPAA risk: unpatched endpoint with access to patient communication systems",
            "MediaTek/Qualcomm kernel CVEs (2023-2026) available for local privilege escalation",
        ],
        "remediation": (
            "Update Android security patch level to within 90 days of the current "
            "Android Security Bulletin. Upgrade from Android 10 to a supported "
            "Android LTS release (12 or 13) with active security patch backports. "
            "For healthcare deployments: apply Network Access Control (NAC) to "
            "restrict CP-840 VLAN access until patched."
        ),
        "yara": """rule cisco_840_android10_stale_patches {
    meta:
        description = "CP-840 runs Android 10 with security patches >3 years behind (2023-02-05)"
        severity = "HIGH"
    strings:
        $patch_level = "post-security-patch-level=2023-02-05" ascii
        $android10   = "Cisco/mars/840:10/" ascii
        $imprivata   = "com.imprivata.imda" ascii
    condition:
        $patch_level or ($android10 and $imprivata)
}""",
    },
    {
        "id": "F3",
        "title": "WebAPI Framework Exposes SIP Credentials to Third-Party Web Apps via Bound Service",
        "severity": "HIGH",
        "cvss": 8.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-284",
        "description": (
            "The Spectralink WebAPI framework (`WebAPI-26.1.88690-cisco.apk`, "
            "`com.spectralink.slnkwebapi`) defines two custom permissions: "
            "`cisco.permission.READ_SIPDATA` and `cisco.permission.WRITE_SIPDATA`. "
            "These permissions expose SIP credential read/write operations to any "
            "third-party app or web app running in the WebAPI sandbox "
            "(`ThirdPartyAppBoundService`). Additional exposed permissions include "
            "`cisco.permission.CALL_CONTROL` (place/answer/terminate calls), "
            "`cisco.permission.CRYPTO_REQUEST` (cryptographic operations), and "
            "`cisco.permission.THIRD_PARTY_APP_UPDATE` (trigger firmware updates). "
            "The WebAPI also registers `CryptographyRequestReceiver` - a broadcast "
            "receiver for cryptographic operations. In healthcare environments, SIP "
            "credentials provide access to the hospital PBX/UCM and can enumerate "
            "extension maps. An attacker who can load a malicious web app into the "
            "WebAPI framework (via DpcLite/EMM provisioning or a rogue TFTP profile) "
            "can call READ_SIPDATA to exfiltrate credentials without user interaction."
        ),
        "dangerous_permissions": {
            "cisco.permission.READ_SIPDATA":       "Read SIP account credentials from phone",
            "cisco.permission.WRITE_SIPDATA":      "Overwrite SIP credentials on phone",
            "cisco.permission.CALL_CONTROL":       "Place/answer/terminate calls silently",
            "cisco.permission.CRYPTO_REQUEST":     "Request cryptographic operations",
            "cisco.permission.THIRD_PARTY_APP_UPDATE": "Trigger firmware update via web app",
        },
        "key_components": {
            "ThirdPartyAppBoundService":  "Bound service interface for third-party web app access to phone API",
            "CryptographyRequestReceiver": "Broadcast receiver accepting crypto operation requests",
            "WebAPIJob":                  "Background job for WebAPI operations",
            "GetLocationUpdates":         "Location access from third-party web apps",
        },
        "attack_path": [
            "EMM/DpcLite provisions a rogue web app URL via MDM policy",
            "Web app running in WebAPI sandbox requests cisco.permission.READ_SIPDATA",
            "WebAPI grants permission: SIP credentials exfiltrated to attacker server",
            "CALL_CONTROL used for silent call interception or room audio capture",
        ],
        "impact": [
            "SIP credentials readable by any web app loaded via EMM provisioning",
            "Call control (make/answer silently) enables passive room surveillance",
            "THIRD_PARTY_APP_UPDATE allows web app to push firmware - supply chain pivot",
            "Healthcare context: SIP cred exfil + CUCM extension map enumeration",
        ],
        "remediation": (
            "Remove READ_SIPDATA and WRITE_SIPDATA from the third-party app permission API. "
            "Require explicit user confirmation (on-screen prompt + physical acknowledgment) "
            "for CALL_CONTROL and CRYPTO_REQUEST permissions. "
            "ThirdPartyAppBoundService should validate caller identity via signature "
            "verification, not just Android permission checks. "
            "THIRD_PARTY_APP_UPDATE should never be available to web app callers."
        ),
        "yara": """rule cisco_840_webapi_sip_credential_exposure {
    meta:
        description = "CP-840 WebAPI exposes READ_SIPDATA/WRITE_SIPDATA to third-party web apps"
        severity = "HIGH"
    strings:
        $read_sip    = "cisco.permission.READ_SIPDATA" ascii
        $write_sip   = "cisco.permission.WRITE_SIPDATA" ascii
        $third_party = "ThirdPartyAppBoundService" ascii
        $crypto_recv = "CryptographyRequestReceiver" ascii
    condition:
        ($read_sip and $write_sip) or ($third_party and $crypto_recv)
}""",
    },
    {
        "id": "F4",
        "title": "SlnkHostnameVerifier Custom TLS Verifier with Blindly Trust Code Path in CiscoPhone DEX",
        "severity": "HIGH",
        "cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-297",
        "description": (
            "The CiscoPhone APK (`CiscoPhone-32.4.89938.apk`) implements a custom TLS "
            "hostname verifier in `SlnkHostnameVerifier.java` (Spectralink-authored). "
            "The DEX code contains the string literal `Blindly trust any server "
            "certificate` alongside `checkServerTrusted HandyIron` (a custom "
            "X509TrustManager implementation) and `checkServerTrusted Android`. "
            "The presence of a named code path for blind certificate trust indicates "
            "a fallback or debug mode that bypasses certificate chain validation. "
            "Additionally, TVS (Trust Verification Service) validation has an explicit "
            "timeout path: `Timed out waiting for TVS response` - if the CUCM "
            "TVS server is unreachable, the fallback TLS behavior is unknown. "
            "The Cisco UCM TVS service validates endpoint certificates; a TVS timeout "
            "under network partition or DoS conditions could trigger the blind trust path. "
            "The `network_security_config.xml` also includes `user` as a trust anchor "
            "type, allowing user-installed CA certificates to be used for server validation."
        ),
        "tls_verifier_evidence": {
            "custom_verifier":           "SlnkHostnameVerifier.java (Spectralink-authored)",
            "blindly_trust_literal":     "Blindly trust any server certificate (in CiscoPhone DEX)",
            "checkServerTrusted_paths":  ["checkServerTrusted HandyIron", "checkServerTrusted Android"],
            "tvs_timeout_path":          "Timed out waiting for TVS response",
            "trust_anchor_types":        ["system", "user (user-installed CAs accepted)"],
        },
        "attack_scenario": (
            "On a hospital Wi-Fi network: attacker presents a self-signed cert for the "
            "SIP proxy / CUCM server. If the TVS server is unreachable (e.g., phone is "
            "on a guest VLAN, or TVS server is overloaded), and the blind trust fallback "
            "activates, the attacker can MITM SIP signaling and capture call content."
        ),
        "impact": [
            "TVS unavailability triggers potential blind certificate trust (SIP MITM)",
            "User-installed CA (via EMM/DpcLite) accepted as trust anchor for SIP TLS",
            "Custom hostname verifier may not enforce RFC 2818 hostname matching",
            "CiscoPhone processes SIP credentials over TLS - MITM exposes auth tokens",
        ],
        "remediation": (
            "Remove the blind certificate trust code path entirely; it should not exist "
            "in production firmware. TVS timeout must not silently degrade to unvalidated "
            "TLS; instead fail closed (refuse the connection). "
            "Replace `user` trust anchors in network_security_config.xml with "
            "`system`-only. Implement certificate pinning for SIP proxy connections. "
            "Audit SlnkHostnameVerifier.java against RFC 2818 hostname verification requirements."
        ),
        "yara": """rule cisco_840_blindly_trust_tls {
    meta:
        description = "CiscoPhone DEX contains blind certificate trust code path + custom TLS verifier"
        severity = "HIGH"
    strings:
        $blind_trust = "Blindly trust any server certificate" ascii
        $slnk_hv     = "SlnkHostnameVerifier" ascii
        $tvs_timeout = "Timed out waiting for TVS response" ascii
    condition:
        $blind_trust or ($slnk_hv and $tvs_timeout)
}""",
    },
    {
        "id": "F5",
        "title": "Fleet-Wide OTA Signing Key - Single 27-Year Certificate for All CP-840 Devices",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-321",
        "description": (
            "The CP-840 OTA update package contains a single fleet-wide signing "
            "certificate (`META-INF/com/android/otacert`): "
            "CN=Cisco UCTG, OU=UCTG, O=Cisco Systems Inc., L=San Jose, ST=CA, C=US. "
            "This RSA-2048 certificate is valid from 2020-03-19 to 2047-08-05 (27 years). "
            "All CP-840 OTA updates distributed to all deployed devices are signed "
            "with this single private key. There is no evidence of per-batch, per-region, "
            "or time-limited signing granularity. The same Cisco UCTG PKI umbrella also "
            "issues the Attestation CA certificate (valid 2020-06-02 to 2047-10-19). "
            "A Cisco UCTG private key compromise would allow an attacker to sign a "
            "malicious Android OTA update accepted as authentic by every CP-840 device, "
            "enabling supply chain compromise of the entire deployed fleet. "
            "The private key is not distributed in the firmware bundle (only the cert), "
            "but the 27-year validity with no rotation plan represents poor key lifecycle management."
        ),
        "ota_cert_details": {
            "cert_cn":        "CN=Cisco UCTG",
            "cert_ou":        "OU=UCTG",
            "cert_org":       "O=Cisco Systems, Inc.",
            "cert_location":  "L=San Jose, ST=CA, C=US",
            "valid_from":     "2020-03-19 00:12:11Z",
            "valid_to":       "2047-08-05 00:12:11Z",
            "validity_years": 27,
            "key_algo":       "RSA-2048",
            "embedded_in":    "META-INF/com/android/otacert in every OTA bundle",
        },
        "attestation_ca_details": {
            "ca_cn":          "CN=Attestation CA",
            "valid_from":     "2020-06-02 23:11:07Z",
            "valid_to":       "2047-10-19 23:11:07Z",
            "validity_years": 27,
            "key_algo":       "RSA-2048 (inferred from loads file prefix signature)",
            "embedded_in":    "sip840-1.11.2.2927-89938.loads, bytes 431-1377",
        },
        "same_pki_umbrella": "Both certs share OU=UCTG under Cisco Systems Inc. - same root trust anchor",
        "impact": [
            "UCTG private key compromise = sign malicious OTA for all CP-840 fleet",
            "27-year validity = no planned key rotation event in certificate lifecycle",
            "Attestation CA compromise = forge valid device identity for any CP-840",
            "No per-device or per-batch signing granularity limits blast radius",
        ],
        "remediation": (
            "Rotate OTA signing and Attestation CA certificates on a 3-5 year cycle. "
            "Implement per-batch OTA signing with HSM-protected keys. "
            "Provide a key revocation mechanism (e.g., OCSP stapling or CRL embedded "
            "in OTA payload) so compromised keys can be revoked before device update. "
            "Consider per-device attestation certificates (not fleet-wide) for the "
            "Attestation CA hierarchy."
        ),
        "yara": """rule cisco_840_fleet_ota_signing_cert {
    meta:
        description = "CP-840 OTA bundle uses fleet-wide 27-year Cisco UCTG signing certificate"
        severity = "MEDIUM"
    strings:
        $cisco_uctg  = "Cisco UCTG" ascii
        $uctg_ou     = "UCTG" ascii
        $validity_47 = "2047" ascii
    condition:
        $cisco_uctg and $validity_47
}""",
    },
    {
        "id": "F6",
        "title": "DpcLite EMM Controller Holds WRITE_SECURE_SETTINGS - Full Device Control via MDM",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-284",
        "description": (
            "The `DpcLite-26.1.88637-cisco.apk` (Spectralink Device Policy Controller) "
            "holds `android.permission.WRITE_SECURE_SETTINGS` - a privileged Android "
            "permission that allows writing to the secure settings table (settings.db). "
            "DpcLite is the Android EMM Device Administration app on the CP-840, "
            "registering `android.app.device_admin` and listening for "
            "`PROFILE_PROVISIONING_COMPLETE`, `DEVICE_ADMIN_ENABLED`, and "
            "`DEVICE_ADMIN_DISABLED` broadcasts. The EMM server has full device "
            "policy control: it can write to secure settings, configure Wi-Fi, "
            "install/remove apps, and change device policies. "
            "An attacker who compromises the EMM server (or performs a DNS/MITM "
            "attack on the EMM provisioning URL) has full control over every "
            "CP-840 enrolled in that EMM. In healthcare environments this means "
            "control over Imprivata SSO tokens and SIP call routing on all phones. "
            "The `UserModeService` component enables multi-user role switching, "
            "relevant in shared-device healthcare deployments."
        ),
        "dpc_permissions": {
            "android.permission.BIND_DEVICE_ADMIN":     "Register as device administrator",
            "android.permission.WRITE_SECURE_SETTINGS": "Write Android secure settings table",
            "android.permission.ACCESS_WIFI_STATE":     "Read Wi-Fi configuration",
            "android.permission.CHANGE_WIFI_STATE":     "Modify Wi-Fi configuration",
        },
        "dpc_receivers": [
            "AdminReceiver (device admin events)",
            "BootReceiver (start on boot)",
            "UpdatedDataReceiver (SAM data updates)",
            "UserModeReceiver (user role switching)",
        ],
        "impact": [
            "EMM server compromise = full policy control over all enrolled CP-840 devices",
            "WRITE_SECURE_SETTINGS: write to secure settings including network policy",
            "Healthcare fleet: EMM pivot targets Imprivata SSO + SIP credential policy",
            "Rogue MDM provisioning (DNS MITM of enrollment URL) = full fleet enrollment",
        ],
        "remediation": (
            "Enforce mutual TLS between DpcLite and the EMM server. "
            "Verify EMM server certificate against a pinned Cisco/Spectralink CA. "
            "Limit WRITE_SECURE_SETTINGS to settings that DpcLite actually requires; "
            "use Android's granular DPC permission model rather than broad WRITE_SECURE_SETTINGS. "
            "Require physical acknowledgment on the phone screen for EMM enrollment "
            "in healthcare deployments where Imprivata tokens are in scope."
        ),
        "yara": """rule cisco_840_dpclite_write_secure_settings {
    meta:
        description = "CP-840 DpcLite EMM holds WRITE_SECURE_SETTINGS - full device control via MDM"
        severity = "MEDIUM"
    strings:
        $dpc_pkg     = "com.cisco.devicepolicycontroller" ascii
        $write_sec   = "android.permission.WRITE_SECURE_SETTINGS" ascii
        $bind_admin  = "android.permission.BIND_DEVICE_ADMIN" ascii
    condition:
        $dpc_pkg and $write_sec
}""",
    },
]

SUMMARY = {
    "total":    6,
    "critical": 0,
    "high":     4,
    "medium":   2,
    "low":      0,
}
