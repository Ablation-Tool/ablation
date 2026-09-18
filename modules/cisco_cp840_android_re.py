"""
Cisco CP-840 Android IP Phone RE Module
Target: cmterm-840.1-11-2-2927-89938.zip
  - sip840-1.11.2.2927-89938.loads: manifest + SaturnAttestation X.509 signature
  - sip840-apk_update-signed-1.11.2.2927.zip: 18 APKs (386MB)
    - CiscoPhone-32.4.89938.apk (14MB): main SIP phone app + UnboundID LDAP SDK
    - WebAPI-26.1.88690-cisco.apk (3.4MB): embedded web management server
    - Webex-43.9.0.110.apk (398MB): full Webex app bundle
    - SlnkDeviceSettings, SlnkDiagnostics, SlnkOTA, PTT, SAFE + 10 others
  - sip840-ota_update-signed-1.11.0.2878.zip: Android OTA (1.53GB)
Source: /media/cowboy/research/Cisco-IP PHONE/cmterm-840.1-11-2-2927-89938.zip
Build: 2025-12-12
Vendor: Spectralink (ODM, com.spectralink.slnkwebapi; sold/rebranded as Cisco CP-840)
"""

METADATA = {
    "target":     "Cisco CP-840 Android IP Phone",
    "model":      "CP-840 and CP-840-S (non-display variant)",
    "firmware":   "1.11.2.2927-89938 (APK bundle), OTA base 1.11.0.2878",
    "build_date": "2025-12-12",
    "platform":   "Android (non-standard Cisco ROM); ARM64 (arm64-v8a native libs)",
    "odm_vendor": "Spectralink (com.spectralink namespace throughout; rebranded for Cisco)",
    "attestation": {
        "cert_cn":   "SaturnAttestation",
        "issuer_cn": "Attestation CA",
        "issuer_ou": "UCTG (Unified Communications Technology Group)",
        "issuer_l":  "Boulder, CO, USA",
        "issuer_o":  "Cisco Systems, Inc.",
        "valid":     "2020-06-02 to 2047-10-19",
        "usage":     "Signs loads manifest to authenticate firmware package origin",
    },
    "webapi_components": {
        "pkg":         "com.spectralink.slnkwebapi (WebAPI-26.1.88690-cisco.apk)",
        "endpoints":   ["/authenticate", "/CGI/Execute", "/Device_information",
                        "/Device_logs", "/deviceLogsAction", "/Bugreport/",
                        "/boolean/preferences/"],
        "auth_method": "RSA-encrypted password via /authenticate POST",
        "spp_path":    "/spp/ variant pages (Cisco Spectralink Push Protocol)",
    },
    "ciscoPhone_components": {
        "pkg":       "com.spectralink.CiscoPhone (CiscoPhone-32.4.89938.apk)",
        "axl_api":   "http://www.cisco.com/AXL/API/12.0 (CUCM Admin XML Layer)",
        "ldap_sdk":  "UnboundID LDAP SDK (full client, 16 property files bundled)",
        "imprivata": "Imprivata iMDA SDK (badge tap SSO: com.imprivata.imda)",
        "xsi":       "CiscoXsiCgiExecute.java (Cisco Extended XML Services Interface)",
    },
    "native_libs": ["libappcrypto.so", "libappssl.so", "libpjapi.so", "libh264.so"],
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Developer RSA Private Key in testkey.jks Shipped in Production WebAPI APK -- Password 'password', CN=Rakesh",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-321",
        "description": (
            "The `WebAPI-26.1.88690-cisco.apk` ships `assets/testkey.jks` -- a PKCS12 "
            "keystore with password `password` containing a `PrivateKeyEntry` for a "
            "self-signed certificate `CN=Rakesh, OU=OT, O=OT, L=OT, ST=OT, C=OT`. "
            "The alias `selfsigned`, created April 2, 2020, is an RSA-2048 key pair "
            "with certificate serial `5a0b6b2b`. The certificate expired March 28, 2021 "
            "(valid from Apr 2020 to Mar 2021) but the keystore is still present in the "
            "December 2025 production firmware. "
            "SHA-256 fingerprint: `68:C7:B0:D8:9F:5C:C8:4D:92:4D:DC:A2:C3:55:58:04:"
            "EA:EA:60:1A:99:E7:74:B9:AC:00:E9:9A:5D:3D:14:8D`. "
            "A second keystore, `assets/keystore.bks` (BouncyCastle BKS format, 2254 "
            "bytes), is also present. Its password could not be recovered with common "
            "wordlists during this analysis. "
            "The RSA private key in testkey.jks is distributed to every CP-840 firmware "
            "recipient. The developer identity `CN=Rakesh` is exposed, attributing the "
            "phone platform to a named Spectralink developer. The known-password keystore "
            "may be loaded by the WebAPI for TLS client cert auth or a signing operation."
        ),
        "keystore": {
            "file":        "assets/testkey.jks (in WebAPI APK)",
            "type":        "PKCS12",
            "password":    "password",
            "alias":       "selfsigned",
            "entry_type":  "PrivateKeyEntry (RSA-2048)",
            "subject":     "CN=Rakesh, OU=OT, O=OT, L=OT, ST=OT, C=OT",
            "valid_from":  "2020-04-02",
            "valid_until": "2021-03-28 (EXPIRED)",
            "sha256":      "68:C7:B0:D8:...:5D:3D:14:8D",
        },
        "impact": [
            "Any CP-840 firmware recipient can extract the RSA-2048 private key with trivial password",
            "Developer identity (CN=Rakesh) and Spectralink origin exposed to all firmware recipients",
            "Expired-but-present keystore may still be loaded at runtime if validity dates are not checked",
            "keystore.bks (second keystore) may contain additional key material pending password recovery",
        ],
        "remediation": (
            "Remove testkey.jks and keystore.bks from production APK assets before shipping. "
            "Test keystores must never be embedded in production builds. "
            "Rotate any TLS/signing credentials that may have been derived from or trust this key."
        ),
        "yara": """rule cisco_cp840_testkey_jks_private_key {
    meta:
        description = "Cisco CP-840 WebAPI APK ships testkey.jks private key with password 'password'"
        severity = "HIGH"
    strings:
        $testkey    = "testkey.jks" ascii
        $keystore   = "keystore.bks" ascii
        $webapi_pkg = "com.spectralink.slnkwebapi" ascii
    condition:
        $testkey and $webapi_pkg
}""",
    },
    {
        "id": "F2",
        "title": "Static CSP Nonce in Firmware Completely Defeats Content-Security-Policy on WebAPI Management Interface",
        "severity": "HIGH",
        "cvss": 7.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N",
        "cwe": "CWE-693",
        "description": (
            "The WebAPI management interface sets a `Content-Security-Policy` header with "
            "a nonce that is hardcoded in compiled firmware: "
            "`default-src 'self'; base-uri 'self'; object-src 'none'; "
            "script-src 'strict-dynamic' 'nonce-4AEemGb0xJptoIGFP3Nd' "
            "'unsafe-inline' http: https:;`. "
            "The nonce value `4AEemGb0xJptoIGFP3Nd` is also present verbatim in every "
            "HTML page (login.html, DeviceInfo.html, devicelogs.html, NetworkInfo.html, "
            "NetworkStats.html, registrationInfo.html, spp/* variants). "
            "A CSP nonce is designed to be a per-request random value that authorizes "
            "only inline scripts generated by the server for that specific request. "
            "A static nonce is effectively public knowledge for any party who reads the "
            "firmware or observes a single HTTP response, allowing an attacker to inject "
            "`<script nonce='4AEemGb0xJptoIGFP3Nd'>...</script>` in any XSS context "
            "and have the browser accept it as authorized. "
            "The policy additionally includes `'unsafe-inline'` as an explicit fallback, "
            "which browsers without nonce support accept unconditionally. "
            "The `/CGI/Execute` endpoint and device log routes are potential injection surfaces."
        ),
        "csp_header": (
            "default-src 'self'; base-uri 'self'; object-src 'none'; "
            "script-src 'strict-dynamic' 'nonce-4AEemGb0xJptoIGFP3Nd' "
            "'unsafe-inline' http: https:;"
        ),
        "static_nonce": "4AEemGb0xJptoIGFP3Nd",
        "affected_pages": [
            "login.html", "DeviceInfo.html", "devicelogs.html", "NetworkInfo.html",
            "NetworkStats.html", "registrationInfo.html", "spp/*",
        ],
        "impact": [
            "Static nonce = CSP nonce protection is zero; any XSS payload with nonce embedded executes",
            "Combined with 'unsafe-inline': old browsers without nonce support get no protection at all",
            "WebAPI exposes device serial, network info, call registration state, and device logs without re-auth after login",
        ],
        "remediation": (
            "Generate a cryptographically random nonce per HTTP response (minimum 128 bits, base64url). "
            "The nonce must be embedded in the CSP header AND the HTML `<script nonce=...>` "
            "in the same server-side render -- never from firmware-compiled static HTML. "
            "Remove `'unsafe-inline'` from the policy (it is ignored when a valid nonce "
            "is present, but its presence signals that the policy was designed without "
            "proper nonce handling)."
        ),
        "yara": """rule cisco_cp840_webapi_static_csp_nonce {
    meta:
        description = "CP-840 WebAPI ships static CSP nonce '4AEemGb0xJptoIGFP3Nd' in compiled firmware"
        severity = "HIGH"
    strings:
        $nonce_csp  = "'nonce-4AEemGb0xJptoIGFP3Nd'" ascii
        $nonce_html = "nonce=\\"4AEemGb0xJptoIGFP3Nd\\"" ascii
        $webapi     = "com.spectralink.slnkwebapi" ascii
    condition:
        ($nonce_csp or $nonce_html) and $webapi
}""",
    },
    {
        "id": "F3",
        "title": "Login Page Loads JSEncrypt from External CDN -- Enterprise Deployment Dependency on cdnjs.cloudflare.com",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-829",
        "description": (
            "The WebAPI `login.html` loads the JSEncrypt 3.1.0 library from an external "
            "CDN: `<script src='https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/"
            "3.1.0/jsencrypt.min.js' nonce='4AEemGb0xJptoIGFP3Nd'>`. "
            "JSEncrypt is used to RSA-encrypt the login password before POST submission: "
            "`rsaEncrypt.setPublicKey(publicKey); rsaEncrypt.encrypt(password)`. "
            "This creates two failure modes: "
            "(1) Enterprise VLAN isolation -- if the phone cannot reach cdnjs.cloudflare.com, "
            "the login form loads but JSEncrypt fails to initialize; "
            "the password field value is not encrypted before submission, "
            "potentially transmitting the plaintext password to the WebAPI server. "
            "(2) CDN supply chain -- a CDN-level compromise or TLS downgrade can "
            "replace the jsencrypt.min.js payload with a version that skips encryption, "
            "silently exfiltrating the admin password. "
            "The SameNonce CSP finding (F2) does not protect against CDN script injection "
            "because the CDN URL itself is implicitly trusted by the script-src policy."
        ),
        "cdn_url": "https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/3.1.0/jsencrypt.min.js",
        "login_js_snippet": (
            "let rsaEncrypt = new JSEncrypt(); "
            "rsaEncrypt.setPublicKey(publicKey); "
            "let encryptedPass = rsaEncrypt.encrypt(password); "
            "document.login.txtPassword.value = encryptedPass;"
        ),
        "impact": [
            "Network-isolated deployment: JSEncrypt fails to load, password may be submitted in cleartext",
            "CDN compromise can silently replace RSA encryption with plaintext passthrough",
            "Admin password is only as secure as the CDN chain of trust",
        ],
        "remediation": (
            "Bundle jsencrypt.min.js directly in the APK assets (alongside the existing "
            "login.css/login.js). The file is ~75KB and should not require an external fetch. "
            "This eliminates both the network dependency and the CDN supply chain risk."
        ),
        "yara": """rule cisco_cp840_webapi_cdn_jsencrypt {
    meta:
        description = "CP-840 WebAPI login page loads JSEncrypt from external CDN (cdnjs.cloudflare.com)"
        severity = "MEDIUM"
    strings:
        $cdn_jsencrypt = "cdnjs.cloudflare.com/ajax/libs/jsencrypt" ascii
        $rsa_encrypt   = "rsaEncrypt.encrypt(password)" ascii
    condition:
        $cdn_jsencrypt
}""",
    },
    {
        "id": "F4",
        "title": "Hardcoded CUCM Call Recording Feature Activation Codes in CiscoPhone APK",
        "severity": "MEDIUM",
        "cvss": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-798",
        "description": (
            "The `CiscoPhone-32.4.89938.apk` `classes.dex` contains hardcoded Feature "
            "Activation Code (FAC) assignments for Cisco Unified Communications Manager "
            "call recording: `use hardcoded Start Recording FAC=*44`, "
            "`use hardcoded Stop Recording FAC=*45`, "
            "`use hardcoded Pause Recording FAC=*48`, "
            "`use hardcoded Resume Recording FAC=*49`. "
            "CUCM admins typically configure FAC codes via the CUCM admin GUI, "
            "and the phone is expected to use the codes provisioned by CUCM via the "
            "phone configuration file. The presence of hardcoded fallback FACs means: "
            "(1) a user with the FAC codes (which appear in the DEX and are thus public) "
            "may be able to initiate call recording regardless of CUCM provisioned state, "
            "and (2) if the CUCM provisioned FAC codes are deleted or unset, the phone "
            "falls back to these hardcoded values without the admin's knowledge. "
            "Call recording activation on a multi-party call constitutes unauthorized "
            "interception depending on jurisdiction and deployment context."
        ),
        "hardcoded_facs": {
            "*44": "Start Recording",
            "*45": "Stop Recording",
            "*48": "Pause Recording",
            "*49": "Resume Recording",
        },
        "impact": [
            "User knowledge of hardcoded FACs allows initiating recording regardless of CUCM policy",
            "FAC code deletion in CUCM falls back silently to hardcoded values",
            "Unauthorized call recording may trigger wiretapping compliance exposure",
        ],
        "remediation": (
            "Remove hardcoded FAC fallbacks from the APK. FAC codes must be provisioned "
            "from the CUCM configuration file only. If no FAC is configured, the "
            "recording feature should be disabled, not silently activated with "
            "firmware-default codes."
        ),
        "yara": """rule cisco_cp840_hardcoded_recording_fac {
    meta:
        description = "CP-840 CiscoPhone APK contains hardcoded CUCM call recording FAC codes *44/*45/*48/*49"
        severity = "MEDIUM"
    strings:
        $fac_start  = "use hardcoded Start Recording FAC=*44" ascii
        $fac_stop   = "use hardcoded Stop Recording FAC=*45" ascii
        $fac_pause  = "use hardcoded Pause Recording FAC=*48" ascii
        $fac_resume = "use hardcoded Resume Recording FAC=*49" ascii
    condition:
        2 of them
}""",
    },
    {
        "id": "F5",
        "title": "Spectralink ODM Origin Disclosed -- 'com.spectralink' Namespace and CN=Rakesh Across All CP-840 APKs",
        "severity": "LOW",
        "cvss": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "All 17 Cisco-branded APKs in the CP-840 firmware use the `com.spectralink` "
            "Java package namespace (e.g., `com.spectralink.slnkwebapi`, "
            "`com.spectralink.phone`, `com.spectralink.preferenceui`). "
            "The WebAPI testkey.jks (F1) leaks a developer's personal name `CN=Rakesh`. "
            "Spectralink Corporation (now acquired by Honeywell) is the ODM vendor for "
            "the CP-840. This information exposes the full software supply chain: "
            "Cisco CP-840 = Spectralink hardware + Spectralink Android ROM + Cisco CUCM integration layer. "
            "Vulnerability research in Spectralink's products (CVEs, security advisories, "
            "firmware archives for other Spectralink models) directly maps to the CP-840 "
            "attack surface. The Webex APK (43.9.0.110, 398MB) is unmodified from "
            "Cisco Webex's standard Android release and is subject to its own CVE history."
        ),
        "odm_evidence": {
            "namespace":   "com.spectralink.* across all 17 APKs",
            "developer_id": "CN=Rakesh in testkey.jks certificate",
            "webex_version": "43.9.0.110 (standard Cisco Webex APK, unmodified)",
        },
        "impact": [
            "Spectralink vulnerability disclosures and firmware archives apply to CP-840",
            "Webex 43.9.0.110 CVE history applies to CP-840 deployments running this version",
        ],
        "remediation": "Informational. Strip developer identity artifacts from production builds.",
    },
]

SUMMARY = {
    "total":    5,
    "critical": 0,
    "high":     2,
    "medium":   2,
    "low":      1,
    "note": (
        "F1 (testkey.jks private key, password='password') and F2 (static CSP nonce) are the "
        "primary findings. Both are in the WebAPI web management interface. F2 means any "
        "XSS vector in the WebAPI (F1 through /CGI/Execute or device log rendering) "
        "would bypass CSP using the public nonce. F3 (CDN dependency) compounds F2 -- "
        "an on-path attacker can replace JSEncrypt from CDN, capturing admin password. "
        "The CP-840 is an Android device; its OTA (1.53GB base image) was not analyzed "
        "in this session. OTA analysis would reveal the base Android OS credentials "
        "and any persistent adb/root access."
    ),
}
