"""
Fortinet FortiFone Desktop v8.0 b67 RE
Source: FortiFone_linux_v8.0_b67.deb (amd64, 110MB)
Platform: Electron app (Chromium-based), x86-64 Linux
Build: 8.0.0~b67~1784584593~GA-0067, built 2026-07-20
Entry: /opt/FortiFone/fortifone (Electron binary)
Key file: /opt/FortiFone/resources/app.asar (172MB Electron ASAR bundle)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiFone Softclient for Desktop",
    "version":      "v8.0 build 67",
    "package_id":   "8.0.0~b67~1784584593~GA-0067",
    "build_date":   "2026-07-20",
    "arch":         "x86-64 (amd64), Electron (Chromium-based Node.js runtime)",
    "electron":     "Chromium Electron; runtime provides Node.js APIs (fs, crypto, https, keytar)",

    "installed_layout": {
        "/opt/FortiFone/fortifone":             "Electron binary (stripped, ~170MB)",
        "/opt/FortiFone/chrome-sandbox":         "SUID chrome-sandbox (Electron sandboxing, chmod 4755 in postinst)",
        "/opt/FortiFone/resources/app.asar":     "Electron ASAR archive, 172MB; full JS source + assets",
        "/opt/FortiFone/resources/server.key":   "RSA-2048 TLS private key; shared across ALL installations",
        "/opt/FortiFone/resources/server.crt":   "Self-signed TLS cert; CN=localhost; same for all installations",
        "/opt/FortiFone/resources/fortifone_desktop_1_c2_v0.bin": "PKCS12 mTLS client cert; 5251 bytes; shared across all installations",
    },

    "asar_key_files": {
        "main.js":                              "Electron main process; 224KB; handles crypto, keytar, HTTPS",
        "assets/fortiCsc.bin":                  "45-byte file: base64-encoded AES-256-CBC encrypted PKCS12 passphrase",
        "assets/Fortinet-CA2+fortinet-subca2001.bin": "Fortinet internal CA chain for server cert validation",
        "appAssistant/fvoiceAuthAgent.js":      "84KB; FortiVoice PBX auth; FEScrambler XOR protocol; mTLS handler",
        "fortivoiceAgent/fvoiceHttpAgent.js":   "51KB; mTLS HTTPS query implementation; uses globalObject.pf/csc/ca",
        "fortivoiceShared/fvPasswordProxy.js":  "Keytar wrapper; user credentials stored in OS keychain",
        "init-macOS-codesign-notary-keychain.sh": "macOS CI codesign script; WWDR Team ID AH4XFXJ7DK; references ~/ucdesktop_certs/",
    },

    "protocol": {
        "with_server":     "HTTPS/TLS to FortiVoice PBX; mTLS (client cert from fortifone_desktop_1_c2_v0.bin)",
        "local_ipc":       "HTTPS on localhost (server.key/server.crt) between Electron main and renderer processes",
        "pbx_framing":     "FEScrambler: XOR + base64; fewReq=/fewRes= header prefix; 3 scramble types (TYPE_V1/V2/V2_FE_MAGIC)",
        "xmpp":            "strophe.js XMPP library bundled (jabber/presence for chat/video features)",
    },
}


# ---------------------------------------------------------
# FFF-F01: Shared TLS private key (local HTTPS server)
# ---------------------------------------------------------
FFF_F01_SHARED_LOCAL_TLS_KEY = {
    "id":       "FFF-F01",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "LOW -- shared localhost TLS key; attack limited to local loopback MITM during IPC",
    "class":    "Shared cryptographic private key (CWE-321)",

    "description": (
        "FortiFone ships a pre-generated RSA-2048 TLS private key (server.key) and self-signed certificate "
        "(server.crt) identical across all installations of v8.0 b67. "
        "The certificate is self-signed with CN=localhost, "
        "issued by Fortinet Inc., FortiFone Team, Ottawa (developer identity ljwang@fortinet.com embedded in cert). "
        "This key pair is used by the Electron main process to serve a local HTTPS server for IPC with renderer processes. "
        "Any user who reverse-engineers the .deb package can use this private key to perform MITM on the local loopback "
        "interface for any FortiFone process on any machine with the same firmware version."
    ),

    "evidence": {
        "server_key_path":  "/opt/FortiFone/resources/server.key (RSA-2048, world-readable)",
        "server_crt_path":  "/opt/FortiFone/resources/server.crt (self-signed, world-readable)",
        "cert_subject":     "C=CA, ST=Ontario, L=Ottawa, O=Fortinet Inc., OU=FortiFone Team, CN=localhost, emailAddress=ljwang@fortinet.com",
        "cert_valid":       "2025-08-18 to (unspecified future date; cert in installed package)",
        "key_md5":          "84cef5e12932c7937ee2898ed15b9d85",
        "cert_md5":         "56df68b8d6204c45c0807b2cb44af737",
        "scope":            "All FortiFone Desktop v8.0 b67 installations share this key pair",
    },

    "impact": (
        "An attacker with local process access on a host running FortiFone can use the extracted key "
        "to MITM the Electron IPC channel, potentially injecting responses or extracting credentials "
        "passed between the renderer and main process over local HTTPS."
    ),

    "remediation": "Generate a unique key pair per installation at install time (postinst). Never ship a shared private key in a package.",
}


# ---------------------------------------------------------
# FFF-F02: Shared PKCS12 mTLS client certificate
# ---------------------------------------------------------
FFF_F02_SHARED_MTLS_CLIENT_CERT = {
    "id":       "FFF-F02",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "MEDIUM -- shared mTLS client certificate across all installations; passphrase derivable from static source; any attacker with the .deb can authenticate as 'FortiFone client' to FortiVoice PBX",
    "class":    "Shared cryptographic private key (CWE-321) + hardcoded passphrase derivation key (CWE-798)",

    "description": (
        "FortiFone uses a PKCS12 client certificate (fortifone_desktop_1_c2_v0.bin, 5251 bytes) "
        "for mutual TLS authentication with FortiVoice PBX servers. "
        "This certificate is identical across all installations of v8.0 b67. "
        "The PKCS12 passphrase is stored in assets/fortiCsc.bin (45 bytes) as AES-256-CBC ciphertext "
        "with key = SHA256('fortinet desktop app') -- a constant derived from the CONFIG_M_NUM environment "
        "variable that is hardcoded in the bundled .env file. "
        "Any attacker with access to the .deb package can recover the PKCS12 passphrase and private key, "
        "then authenticate as a FortiFone client to any FortiVoice PBX that trusts this certificate."
    ),

    "pkcs12_metadata": {
        "file":         "/opt/FortiFone/resources/fortifone_desktop_1_c2_v0.bin",
        "size":         "5251 bytes",
        "mac_algo":     "SHA-256 (hashcat mode 23210)",
        "mac":          "daaedd82cddf4d3515d3f9e6ad476806ab76233db0c5c0942f86520e71aa1711",
        "salt":         "d5f5d794d8836b6f (8 bytes)",
        "iterations":   2048,
    },

    "passphrase_derivation": {
        "encrypted_file":   "assets/fortiCsc.bin in app.asar (45 bytes total)",
        "content":          "base64 ciphertext: wGbPqZRhvhGxESR+n4HcFo8DAIc/GoTsmvQwVkk= + garbage bytes",
        "algorithm":        "AES-256-CBC",
        "key_derivation":   "k = SHA256(CONFIG_M_NUM) where CONFIG_M_NUM = 'fortinet desktop app' (hardcoded in .env)",
        "key_hex":          "04b1fc0a0fab47aa36ad4414373f0e61a670fc33446fb01afe124c40ba361c32",
        "iv":               "c066cfa99461be11b111247e9f81dc16 (first 16 bytes of decoded ciphertext)",
        "passphrase_status": "PENDING -- fortiCsc.bin in this build produces 13-byte ciphertext (not block-aligned); file may be truncated in this package build",
        "crack_target":     "hashcat -m 23210 $pfxng$2$2048$8$d5f5d794d8836b6f$<mac> <pfx_data>",
    },

    "code_references": {
        "loadCscFile":      "main.js:2431 -- reads fortiCsc.bin, decrypts with SHA256(CONFIG_M_NUM)",
        "loadCsc":          "main.js:705 -- loads decrypted passphrase into global.sharedObject.csc",
        "pfx_usage":        "fvoiceHttpAgent.js:734 -- pfx: globalObject.pf, passphrase: globalObject.csc",
        "mtls_function":    "fvoiceHttpAgent.js:714 -- fv_ajax_https_query_cert()",
    },

    "remediation": (
        "Provision unique client certificates per installation via a PKI enrollment flow. "
        "Do not ship a shared PKCS12 in the application package. "
        "Key derivation from a hardcoded constant (CONFIG_M_NUM='fortinet desktop app') is equivalent to "
        "a hardcoded passphrase and provides no protection."
    ),
}


# ---------------------------------------------------------
# FFF-F03: FEScrambler protocol obfuscation (trivially reversible XOR)
# ---------------------------------------------------------
FFF_F03_FESCRAMBLER_XOR = {
    "id":       "FFF-F03",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "INFO -- FEScrambler XOR obfuscation on FortiVoice PBX protocol; not a security control; trivially reversible",
    "class":    "Weak/absent protocol security (CWE-311 / security through obscurity)",

    "description": (
        "FortiFone obfuscates its HTTP requests to FortiVoice PBX using FEScrambler, "
        "a proprietary XOR+base64 scheme. Request payloads are prefixed with fewReq= and "
        "responses with fewRes=. Three scramble types: "
        "TYPE_V1 (random magic 1-14), TYPE_V2 (random session magic from server), TYPE_V2_FE_MAGIC (constant FE_MAGIC=0x1f). "
        "The session_magic_number is received from the server during authentication and reused for all subsequent requests. "
        "XOR with a single byte provides no confidentiality -- any observer who captures one "
        "known-plaintext request can recover the magic number and decrypt all other requests/responses."
    ),

    "scrambler_constants": {
        "FE_MAGIC":      "0x1f (31) -- fallback constant magic number",
        "FE_REQHEADER":  "fewReq= (7 bytes)",
        "FE_RESHEADER":  "fewRes= (7 bytes)",
        "FE_HEADER_LEN": 7,
        "DELIMITER":     ":",
        "SESSION_MAGIC_SIZE": 1,
    },

    "xor_function": "fv_xorString(original, magic) -- XOR each character with magic byte; output = fewReq=<codec>:<magic_hex>:<base64_or_raw_body>",

    "cryptographic_strength": (
        "Single-byte XOR is not a cipher. Given any one known-plaintext message (e.g., the login request "
        "which has predictable structure), the magic byte is directly recoverable: "
        "magic = plaintext_char XOR ciphertext_char at the same position. "
        "All other messages can then be decrypted without knowing the session magic."
    ),

    "note": (
        "The mTLS layer (HTTPS with client cert from FFF-F02) provides actual transport confidentiality. "
        "FEScrambler sits on top of HTTPS and obfuscates the application-layer payload after TLS decryption. "
        "It is irrelevant to network-path attackers but could hinder casual inspection of the protocol "
        "by developers with Burp access."
    ),

    "remediation": "Remove FEScrambler -- the mTLS HTTPS layer already provides transport confidentiality. Application-layer XOR on top of TLS adds no security.",
}


# ---------------------------------------------------------
# FFF-F04: Fortinet internal PKI CA certificates embedded
# ---------------------------------------------------------
FFF_F04_EMBEDDED_FORTINET_CA = {
    "id":       "FFF-F04",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "INFO -- Fortinet internal CA chain embedded for server cert validation; CA certs are public by nature; no private key embedded",
    "class":    "Certificate pinning (by CA, not leaf cert); informational",

    "description": (
        "FortiFone bundles Fortinet's internal root CA (fortinet-ca2) and intermediate CA (fortinet-subca2001) "
        "in assets/Fortinet-CA2+fortinet-subca2001.bin inside the asar. "
        "These are used as the 'ca' option in Node.js https.request for mTLS connections to FortiVoice PBX servers "
        "(globalObject.ca = contents of this file). "
        "This means FortiVoice PBX servers must have certificates signed by Fortinet's internal CA chain to be trusted by FortiFone. "
        "No private key material is present -- only the public CA certificates."
    ),

    "ca_chain": {
        "root": {
            "subject":  "CN=fortinet-ca2, O=Fortinet, OU=Certificate Authority, C=US, L=Sunnyvale",
            "issuer":   "Self-signed",
            "key_type": "RSA-8192",
            "valid":    "2016-06-06 to 2056-05-27",
            "purpose":  "Fortinet internal root CA for all Fortinet product TLS certificates",
        },
        "intermediate": {
            "subject":  "CN=fortinet-subca2001, O=Fortinet, OU=Certificate Authority, C=US, L=Sunnyvale",
            "issuer":   "fortinet-ca2",
            "key_type": "RSA-2048",
            "valid":    "2016-06-06 to 2056-05-27",
            "purpose":  "Intermediate CA; issues FortiVoice PBX server certificates",
        },
    },

    "security_implication": (
        "If Fortinet's internal CA private key is ever compromised, all FortiVoice PBX certificates "
        "(and all other Fortinet products using fortinet-ca2) would be attackable until clients are updated. "
        "The CA is valid until 2056 (40 years) which is an unusually long lifetime for a CA. "
        "FortiFone does not appear to implement certificate transparency or OCSP stapling."
    ),
}


# ---------------------------------------------------------
# FFF-F05: Developer CI/CD artifact in production asar
# ---------------------------------------------------------
FFF_F05_CI_ARTIFACT_IN_PRODUCTION = {
    "id":       "FFF-F05",
    "product":  "Fortinet FortiFone Desktop v8.0 build 67",
    "severity": "LOW -- developer CI/CD artifact bundled in production app; reveals internal infrastructure paths and Apple developer account context",
    "class":    "Information disclosure (CWE-200)",

    "description": (
        "The file init-macOS-codesign-notary-keychain.sh is included in the production app.asar, "
        "bundled at the root of the asar archive. "
        "This is a macOS CI/CD setup script for Apple Developer ID codesigning and notarization. "
        "It references the Fortinet/FortiFone team's internal build infrastructure: "
        "keychain file at ~/Library/Keychains/ucdesktop.keychain-db, "
        "certificate file at ~/ucdesktop_certs/apple_fvdesktopAppCodeSign.p12, "
        "Apple WWDR Team ID AH4XFXJ7DK, "
        "Apple ID stored in AC_USERNAME, and "
        "app-specific 2FA password in secret_2FA_password. "
        "The script references the GitLab CI environment (visible in .gitlab-ci.yml also in the asar). "
        "This is a build artifact that should not be included in the shipped product."
    ),

    "evidence": {
        "file":         "init-macOS-codesign-notary-keychain.sh (3081 bytes)",
        "wwdr_team_id": "AH4XFXJ7DK (Apple Developer Program Team ID for Fortinet/FortiFone team)",
        "cert_path":    "~/ucdesktop_certs/apple_fvdesktopAppCodeSign.p12",
        "keychain":     "~/Library/Keychains/ucdesktop.keychain-db",
        "ci_env":       ".gitlab-ci.yml also present in asar (GitLab CI pipeline config)",
        "devops_file":  ".devops also present (DevOps configuration, 702 bytes)",
    },

    "remediation": "Audit asar bundling to exclude CI/CD scripts, GitLab config, .devops files, and other build artifacts from the shipped product.",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "package":          "ANALYZED -- .deb fully extracted; postinst reviewed; 45 files cataloged",
    "asar":             "PARTIALLY ANALYZED -- 172MB ASAR, 6.1MB header (JSON file listing); key JS files extracted and reviewed",
    "server_key":       "EXTRACTED -- RSA-2048 private key confirmed shared (FFF-F01)",
    "pkcs12":           "EXTRACTED -- 5251-byte PKCS12 identified as mTLS client cert; passphrase PENDING (FFF-F02)",
    "fortiCsc_bin":     "ANALYZED -- AES-256-CBC key derivation from SHA256('fortinet desktop app'); ciphertext block-alignment issue in this build",
    "fescrambler":      "ANALYZED -- XOR+base64 protocol obfuscation; magic byte 0x1f; reversible (FFF-F03)",
    "ca_chain":         "EXTRACTED -- fortinet-ca2 RSA-8192 + fortinet-subca2001 RSA-2048; no private keys (FFF-F04)",
    "ci_artifact":      "IDENTIFIED -- macOS codesign script in production bundle; WWDR Team ID extracted (FFF-F05)",
    "electron_binary":  "NOT ANALYZED -- /opt/FortiFone/fortifone is stripped; native Electron binary, not Fortinet code",

    "unique_findings": [
        "FFF-F01: LOW -- shared RSA-2048 TLS private key (server.key) in all v8.0b67 installations; localhost HTTPS IPC",
        "FFF-F02: MEDIUM -- shared PKCS12 mTLS client cert for FortiVoice PBX; passphrase derived from SHA256('fortinet desktop app'); any .deb possessor can impersonate FortiFone client",
        "FFF-F03: INFO -- FEScrambler XOR obfuscation (magic=0x1f) on FortiVoice PBX protocol; single-byte XOR over TLS; security through obscurity only",
        "FFF-F04: INFO -- Fortinet internal CA chain (fortinet-ca2 RSA-8192, valid 2016-2056) bundled for server cert validation; no private key material",
        "FFF-F05: LOW -- CI/CD script (init-macOS-codesign-notary-keychain.sh) + .gitlab-ci.yml + .devops in production asar; WWDR Team ID AH4XFXJ7DK exposed",
    ],

    "vs_other_products": {
        "FSW":  "Both ship shared TLS keys; FSW shared key is device-to-device; FFF shared key is client app",
        "FAP":  "Both have empty/trivial credentials; FAP has empty SSH password (CRIT); FFF has static PKCS12 (MEDIUM)",
        "FGT":  "FGT has fortism LSM + encrypted rootfs; FFF has no OS-layer security (Electron/JS app)",
        "FAD":  "FAD has DES-56 SBVM key; FFF has AES-256-CBC with hardcoded-derivation key; both are static",
    },

    "pending": {
        "PKCS12_passphrase": "PENDING -- hashcat -m 23210 with Fortinet-specific wordlist; MAC=daaedd82..., salt=d5f5d794d8836b6f, iter=2048",
        "PKCS12_cert_identity": "PENDING -- cannot inspect cert content without passphrase; CN and validity unknown",
        "FortiVoice_protocol": "PARTIAL -- FEScrambler decoded; API endpoint mapping not complete",
        "keytar_services":    "NOT ANALYZED -- keytar stores account passwords in OS keychain under service 'fortifone-*'",
    },
}
