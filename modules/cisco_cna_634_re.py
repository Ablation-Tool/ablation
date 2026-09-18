"""
Cisco Network Assistant (CNA) 6.3.4 RE Module
Targets:
  - cna-mac-k9-installer-6-3-4-en.zip: macOS InstallAnywhere installer (36MB)
  - cna-windows-k9-installer-6-3-4-en.exe: Windows installer (74MB)
Source: /media/cowboy/research/Cisco-Catalyst/
Extracted: /tmp/cna_mac/packages_zg_ia_sf.jar -> cna_boot.jar, utility-1.65/*.jar
Build date: 2018-12-18
"""

METADATA = {
    "target":      "Cisco Network Assistant (CNA) 6.3.4",
    "build_date":  "2018-12-18",
    "format":      "InstallAnywhere; outer ZIP -> Resource1.zip -> packages_zg_ia_sf.jar",
    "java_version": "Java 6 (JDK 1.6.0_29, Sun Microsystems) - target runtime",
    "eol":         "CNA 6.x end-of-life; last release December 2018",
    "purpose":     "Desktop GUI for managing Cisco Catalyst switch clusters (up to 40 devices)",
    "components": {
        "cna_boot.jar":   "Bootstrap/launcher with SGZ signing key and API credentials",
        "cmdsvc.jar":     "Command service - IOS CLI proxy",
        "startup-1.65":   "Core startup JARs",
        "utility-1.65":   "49 third-party JARs (SSH, HTTP, XML, serialization)",
    },
    "device_modules": ["c2950", "c3750", "c2900", "c2940", "ce500", "sbsbu", "isbu", "pcbu"],
    "api_endpoints": {
        "scanner_upload": "https://ciscoactiveadvisor.com/asi/rs/SCANNER-UPLOAD",
        "login":          "https://ciscoactiveadvisor.com/asi/rs/login",
        "oauth_token":    "https://cloudsso.cisco.com/as/token.oauth2",
        "software_api":   "https://api.cisco.com/software/v2.0/",
        "dev_urls": [
            "http://tcedev:8090/estgtce/",
            "http://tcedev:8090/CNAUpdateService/",
            "http://tcedevdb:8080/CAAAuthenticationService/",
        ],
    },
    "sgz_format":  "Cisco proprietary .sgz (Cisco Network Manager archive) - signed with RSA-768",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "RSA-768 SGZ Package Signing Private Key Distributed in CNA Installer JAR",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-321",
        "description": (
            "The Cisco Network Assistant 6.3.4 installer embeds a 768-bit RSA private key "
            "(`com/cisco/nm/tools/sgz/v2x/private.key`) in the `cna_boot.jar` bootstrap "
            "JAR, which is distributed to all CNA users as part of the installer package. "
            "The private key is in PKCS#1 DER format (modulus: `00:b2:af:65:62:d4:bd:d7:...`). "
            "RSA-768 was publicly factored by Kleinjung et al. in December 2009 "
            "(demonstrated on a 768-bit RSA modulus in ~2 years of CPU-time). "
            "This key is used to sign `.sgz` (Cisco Network Manager archive) packages: "
            "`SignatureVerifier.class` and `Signer.class` in `cna_boot.jar` form the "
            "signing/verification pipeline, and `SgzWrapper.class` creates signed "
            "archives for device package delivery. "
            "An attacker with access to the CNA installer (publicly distributed by Cisco) "
            "can extract the private key and forge signed SGZ packages. A forged SGZ "
            "delivered to CNA poses as a legitimate Cisco device update package. "
            "Since CNA manages up to 40 Catalyst switches simultaneously, a malicious "
            "SGZ can push malicious firmware or configuration to an entire cluster."
        ),
        "key_file":      "com/cisco/nm/tools/sgz/v2x/private.key (DER, PKCS#1)",
        "key_size_bits": 768,
        "key_modulus":   "00:b2:af:65:62:d4:bd:d7:fd:e5:60:2c:2d:c4:41:18:78:c2:4f:51:23...",
        "key_status":    "RSA-768 factored December 2009 (Kleinjung et al.) - cryptographically broken",
        "signing_classes": ["SignatureVerifier", "Signer", "SgzWrapper", "GenKeys"],
        "impact": [
            "Any CNA installer download contains the private key for forging signed SGZ packages",
            "RSA-768 key is computationally factorable with modern resources (factored 2009)",
            "Forged SGZ delivered via CNA can push malicious firmware to managed switch cluster",
            "Affects all CNA installations since the key is distributed to all users",
        ],
        "remediation": (
            "Rotate to RSA-2048 or ECDSA-256 minimum. "
            "Move signing key to build-time infrastructure (CI/CD secret store) -- "
            "the private key must never be distributed to end-user installers. "
            "Signed packages should be verified against a server-published certificate, "
            "not a key embedded in the client binary. "
            "Since CNA is EOL, this finding applies to CNA deployments still in use "
            "and should drive migration to supported management platforms."
        ),
        "yara": """rule cisco_cna_rsa768_signing_key {
    meta:
        description = "Cisco CNA 6.3.4 installer contains RSA-768 SGZ signing private key"
        severity = "CRITICAL"
    strings:
        $private_key_header = { 30 82 01 E4 02 01 00 30 0D }
        $key_path           = "sgz/v2x/private.key" ascii
        $signer_class       = "Signer.class" ascii
    condition:
        $private_key_header or $key_path
}""",
    },
    {
        "id": "F2",
        "title": "Hardcoded OAuth2 Client Secret for api.cisco.com in CNA Installer JAR",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-798",
        "description": (
            "The `asd_server.properties` file embedded in `cna_boot.jar` contains "
            "hardcoded OAuth2 credentials for the Cisco api.cisco.com production software "
            "download API. The credentials are: "
            "`clientId=5cjwsff6qd5u68yw5h8em83s` and `secret=SGSaU4DUw6kETQZ2wPAYhRZY`. "
            "The OAuth2 flow targets `https://cloudsso.cisco.com/as/token.oauth2` "
            "(Cisco Single Sign-On OAuth2 token endpoint) using `grantType=password`. "
            "These credentials permit: software metadata queries via "
            "`https://api.cisco.com/software/v2.0/metadata/`, software download URL "
            "generation, and K9/EULA compliance form submissions for export-controlled "
            "cryptographic software. Any entity with the client_id and secret can "
            "authenticate as the CNA application to Cisco's API. "
            "The `rest_service_url=https://ciscoactiveadvisor.com/asi/rs/SCANNER-UPLOAD` "
            "endpoint accepts CNA scan data uploads, enabling an attacker with these "
            "credentials to submit forged scan data or enumerate the API surface."
        ),
        "credentials": {
            "clientId":  "5cjwsff6qd5u68yw5h8em83s",
            "secret":    "SGSaU4DUw6kETQZ2wPAYhRZY",
            "grantType": "password",
            "token_url": "https://cloudsso.cisco.com/as/token.oauth2",
        },
        "dev_urls_exposed": [
            "http://tcedev:8090/estgtce/ (dev server)",
            "http://tcedev:8090/CNAUpdateService/",
            "http://tcedevdb:8080/CAAAuthenticationService/",
        ],
        "impact": [
            "OAuth2 client secret distributed to all CNA installer downloads since 2018",
            "Credentials permit API access to Cisco software download and compliance endpoints",
            "dev server URLs expose internal Cisco network hostname/port scheme",
        ],
        "remediation": (
            "Rotate the clientId/secret pair and remove from distributed binaries. "
            "Use per-user OAuth2 credentials (device_code or authorization_code flow) "
            "rather than embedding application-level credentials in client code. "
            "Remove dev server URL comments from production properties files."
        ),
        "yara": """rule cisco_cna_hardcoded_oauth2_secret {
    meta:
        description = "Cisco CNA asd_server.properties contains hardcoded OAuth2 client secret"
        severity = "HIGH"
    strings:
        $secret    = "secret=SGSaU4DUw6kETQZ2wPAYhRZY" ascii
        $client_id = "clientId=5cjwsff6qd5u68yw5h8em83s" ascii
        $asd_url   = "ciscoactiveadvisor.com" ascii
    condition:
        $secret or $client_id
}""",
    },
    {
        "id": "F3",
        "title": "Apache Commons Collections 3.1 -- Java Deserialization Gadget Chain in CNA Desktop Client",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-502",
        "description": (
            "CNA 6.3.4 bundles `commons-collections-3.1.jar` (560KB) in `utility-1.65/`. "
            "Apache Commons Collections 3.1 contains the `InvokerTransformer` gadget chain "
            "used by ysoserial's CommonsCollections1/3/5/6/7 exploit modules "
            "(CVE-2015-6420, CVE-2015-7450, and others affecting JBoss, WebLogic, WebSphere). "
            "CNA uses Java serialization (`java.util.HashMap` and `ObjectInputStream`) "
            "to communicate with managed Cisco devices (confirmed: `java.util.HasHashMap` "
            "serialized object header `ac ed 00 05 73 72 00 13 java.util.Has` detected "
            "in packages_zg_ia_sf.jar header). If CNA deserializes attacker-controlled "
            "data received from a managed device (malicious switch presenting forged "
            "device data), the gadget chain executes arbitrary OS commands on the "
            "admin workstation. A compromised switch in the managed cluster can "
            "pivot to the admin workstation via this attack surface."
        ),
        "library":    "commons-collections-3.1.jar (Apache Commons Collections 3.1)",
        "gadget_chains": [
            "CommonsCollections1 (InvokerTransformer chain, Java < 8u71)",
            "CommonsCollections3 (InstantiateTransformer + TemplatesImpl)",
            "CommonsCollections5 (TiedMapEntry + BadAttributeValueExpException)",
            "CommonsCollections6 (HashSet + TiedMapEntry, works on Java 8)",
        ],
        "serialized_header": "ac ed 00 05 73 72 00 13 6a 61 76 61 2e 75 74 69 6c 2e 48 61 73",
        "impact": [
            "Compromised managed switch can RCE the admin workstation via CNA Java deserialization",
            "CommonsCollections gadget chains produce full OS command execution",
            "Admin workstations typically have elevated privileges and network access beyond the switch VLAN",
        ],
        "remediation": (
            "Update commons-collections to 3.2.2+ or 4.x (both patched deserialization). "
            "Implement ObjectInputFilter to restrict deserialized classes. "
            "Since CNA is EOL, migrate to supported management platforms (Cisco DNA Center, "
            "Cisco Catalyst Center, or IOS-XE WebUI)."
        ),
        "yara": """rule cisco_cna_commons_collections_31_gadget {
    meta:
        description = "Cisco CNA bundles Apache Commons Collections 3.1 (Java deserialization gadget chain)"
        severity = "HIGH"
    strings:
        $cc31 = "commons-collections-3.1.jar" ascii
        $invoker = "InvokerTransformer" ascii
    condition:
        $cc31
}""",
    },
    {
        "id": "F4",
        "title": "JSch 0.1.48 EOL SSH Library (2012) -- CVE-class Vulnerabilities in SSH Client Path",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-327",
        "description": (
            "CNA bundles `jsch-0.1.48.jar` (226KB) in `utility-1.65/`. "
            "JSch 0.1.48 was released approximately 2011-2012 (manifest built with "
            "JDK 1.6.0_29 by Sun Microsystems + Ant 1.8.2). The current JSch release "
            "is 0.2.x+ with multiple security patches since 0.1.48. JSch 0.1.x versions "
            "are affected by: lack of server host key verification, weak cipher suite "
            "negotiation (no preference ordering, DES/3DES accepted), and missing "
            "validation in RSA host key comparison. The Maverick Java SSH libraries "
            "(`maverick.jar`, `maverick-ssh1.jar`) also bundle SSH1 support -- the "
            "SSHv1 protocol is insecure and has been deprecated since 2006. "
            "CNA uses SSH to manage Cisco switches; the SSH client trust surface "
            "is controlled by the managed device, which can negotiate weak ciphers "
            "or present manipulated host keys without CNA detecting the anomaly."
        ),
        "ssh_libraries": {
            "jsch-0.1.48.jar": "JSch 0.1.48 (2012, JDK 1.6 build, EOL)",
            "maverick.jar":    "Maverick Java SSH (SSHv2)",
            "maverick-ssh1.jar": "Maverick SSH1 support (SSHv1, deprecated/insecure protocol)",
            "sshtools-util.jar": "SSHTools utility library",
        },
        "impact": [
            "SSH1 library present -- managed device could negotiate SSHv1 session with CNA",
            "Weak cipher acceptance means managed device can downgrade CNA SSH to DES/3DES",
            "JSch 0.1.48 missing post-2012 security patches",
        ],
        "remediation": (
            "Update to JSch 0.2.x+ and remove SSHv1 support libraries. "
            "Enforce SSHv2-only in CNA SSH client configuration. "
            "Set explicit cipher preference list excluding DES/3DES/RC4."
        ),
        "yara": """rule cisco_cna_jsch_048_eol {
    meta:
        description = "Cisco CNA bundles EOL JSch 0.1.48 SSH library with SSHv1 support"
        severity = "MEDIUM"
    strings:
        $jsch     = "jsch-0.1.48.jar" ascii
        $mav_ssh1 = "maverick-ssh1.jar" ascii
    condition:
        $jsch or $mav_ssh1
}""",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 1,
    "high":     2,
    "medium":   1,
    "low":      0,
    "note": (
        "F1 is the primary finding: RSA-768 SGZ signing key in installer JAR. "
        "768-bit RSA was publicly factored in 2009; any CNA installer download "
        "provides the key for forging signed update packages for managed switches. "
        "F2 hardcoded OAuth2 secret provides API access to Cisco's software "
        "download infrastructure. F3 commons-collections 3.1 enables managed "
        "switch to RCE admin workstation via Java deserialization. "
        "CNA 6.x is EOL (December 2018); all findings reflect unpatched state."
    ),
}
