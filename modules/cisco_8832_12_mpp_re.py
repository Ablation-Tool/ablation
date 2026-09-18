"""
Cisco IP Phone 8832 MPP 12.0.7 Dual-Chip RE Module
Target: cmterm-8832.12-0-7MPP0501-123_REL.zip
Architecture: Dual-chip (primary 8832 + secondary 28832), ARM 32-bit
Source: /media/cowboy/research/Cisco-IP PHONE/cmterm-8832.12-0-7MPP0501-123_REL.zip
Firmware version: 12.0.7 MPP (Multi-Platform Phone) -- MPP0501-123

Chip layout:
  PLATFORM_1 (8832)  -- main chip, raw UBI image, extracted with ubireader_extract_files
  PLATFORM_2 (28832) -- secondary chip, raw SquashFS, extracted with unsquashfs

SBN inventory:
  sip8832.12-0-7MPP0501-123.loads         -- manifest
  key28832.12-0-7MPP0501-123.sbn          -- 353 bytes, fleet TrustZone RSA-2048 pubkey
  trustzone28832.12-0-7MPP0501-123.sbn    -- 408 KB, encrypted magic 00000001 1de1 0000
  oemloader28832.12-0-7MPP0501-123.sbn    -- 1.69 MB, encrypted magic 00000001 1de1 0000
  rootfs8832.12-0-7MPP0501-123.sbn        -- 78 MB, raw UBI, no SBN header
  rootfs28832.12-0-7MPP0501-123.sbn       -- 90 MB, raw SquashFS v4.0, no SBN header

Extraction:
  ubireader_extract_files rootfs8832.*.sbn  -> /tmp/8832_12_rootfs/1351312398/rootfs/
  unsquashfs rootfs28832.*.sbn              -> /tmp/8832_28832_rootfs/

Build metadata (from netsd strings):
  GCC 11.3.0, glibc 2.35, kernel 5.10.149
  Build paths: xinxiao / slbuild
  Internal git: sqbu-github.cisco.com (Cisco enterprise GitHub)
"""

METADATA = {
    "target":    "Cisco IP Phone 8832 MPP Firmware 12.0.7 (MPP0501-123)",
    "platform":  "Dual-chip: 8832 (primary, UBI) + 28832 (secondary, SquashFS)",
    "arch":      "ARM 32-bit",
    "codename":  "Volantis (Cisco Webex collaboration stack, /usr/lib/Volantis.jar on primary chip)",
    "version":   "12.0.7 MPP -- 2022 release train; compare 14.4.1 for regression delta",
    "os": {
        "primary_8832":   "Linux 5.10.149, glibc 2.35, GCC 11.3.0",
        "secondary_28832": "Linux, base.cfg: Software Version 7.1.1(005)",
    },
    "accounts": {
        "primary_8832": {
            "root":    "!:0:0:root:/home/root:/bin/false (locked, shell /bin/false)",
            "debug":   "!:65532:100:debug:/tmp:/bin/false (LOCKED -- contrast with 14.4.1 regression F1 in cisco_phoneos_5_0_1_re.py)",
            "default": "!:65533:100:default user:/home/default:/bin/false (locked)",
            "app":     "app user, services group",
        },
        "secondary_28832": {
            "root":       "!:0:0:root:/root:/bin/sh (locked but shell /bin/sh, not /bin/false)",
            "messagebus": "x:42:64002:Linux User:/var/run/dbus:/bin/sh (UNUSUAL: /bin/sh shell)",
            "debug":      "NOT in /etc/shadow on secondary chip",
        },
    },
    "services_secondary_28832": [
        "secureapp (BEUID=security:sec)",
        "netsd (BEUID=root:root, libnetsd.so + libplatformapi.so)",
        "downd",
        "pae (BEUID=root:root)",
        "xinetd (SSH: disable=yes)",
        "webexd (BEUID=root:root, Webex cloud daemon)",
        "mphone",
        "apigateway (BEUID=root:root, port 8443, OpenAPI 3.0.2)",
        "nc_deamon (NOT netcat -- network config daemon, NOT STRIPPED)",
        "spr_voip",
        "cdc_service",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "title": "apigateway on Port 8443 Exposes Unauthenticated Config, UI, and Serviceability APIs Running as root",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "The 28832 secondary chip runs `/usr/sbin/apigateway` as BEUID=root:root on port 8443 "
            "(confirmed from `__FUNCTION__.8443` string in binary). "
            "The binary embeds three complete OpenAPI 3.0.2 specification documents as raw JSON. "
            "None of the three specs include a `security` section or reference any "
            "authentication scheme (no Bearer token, no API key, no Basic auth). "
            "The embedded API surface exposes the following unauthenticated endpoints:\n\n"
            "Config API (/api/Config/v1/):\n"
            "  POST GetParams  -- reads any config.xml / status.xml parameter by XML tag name;\n"
            "                     includes SIP registration state, call state, DNS, NTP, credentials\n"
            "  POST SetParams  -- writes arbitrary config parameters; can enable/disable web server,\n"
            "                     change SIP credentials, modify network settings\n"
            "  POST Subscribe  -- registers a callbackUrl for config change notifications (see F2)\n\n"
            "UI API (/api/Ui/v1/):\n"
            "  POST GetDeviceScreenshot -- captures phone screen and uploads to caller-supplied URL\n"
            "  GET  GetSoftKeys         -- retrieves current softkey layout\n"
            "  POST SendKey             -- simulates hardware key press: Linekey_1..16, Dialpad_0..9,\n"
            "                             VoiceMail, Speaker, HangUp, Transfer, Conference, Mute,\n"
            "                             Volume_Up/Down, HeadSet, Hold (full keypad control)\n\n"
            "Serviceability API (/api/Serviceability/v1/):\n"
            "  POST RebootDevice          -- cold boot of the device\n"
            "  POST WebexRebootDevice     -- Webex cloud-triggered reboot\n"
            "  POST StartPacketCapture    -- starts tcpdump (filter: ALL or MYIP)\n"
            "  POST StopPacketCapture     -- stops tcpdump\n"
            "  POST GetPacketCapture      -- uploads pcap to caller-supplied URL (see F2)\n"
            "  POST GenerateAndGetPRTFile -- generates PRT diagnostic file + uploads to URL\n"
            "  POST GetConfigFile         -- retrieves device config file + uploads to URL\n"
            "  POST GetStatusFile         -- retrieves status file + uploads to URL\n"
            "  POST TriggerSampleMetric   -- triggers metric message\n"
            "  POST Subscribe             -- registers callbackUrl for serviceability events\n\n"
            "The process runs as root:root with no privilege drop, so all API operations "
            "execute with full root context. The `caps` subcommand in apigateway.sh also "
            "grants post-start capabilities: CAP_DAC_OVERRIDE, CAP_NET_ADMIN, CAP_IPC_OWNER, "
            "CAP_SYS_NICE, which are redundant given root start but confirm the intended "
            "capability set. The combination of root execution + no auth in OpenAPI spec + "
            "port 8443 (distinct from miniweb on 443) provides a second unauthenticated "
            "admin surface on the secondary chip."
        ),
        "endpoints": {
            "Config":          ["GetParams", "SetParams", "Subscribe"],
            "Ui":              ["GetDeviceScreenshot", "GetSoftKeys", "SendKey"],
            "Serviceability":  [
                "RebootDevice", "WebexRebootDevice", "StartPacketCapture",
                "StopPacketCapture", "GetPacketCapture", "GenerateAndGetPRTFile",
                "GetConfigFile", "GetStatusFile", "TriggerSampleMetric",
                "UpdatePrtStatus", "ProblemReport", "Subscribe",
            ],
        },
        "port":    8443,
        "beuid":   "root:root",
        "contact": "phone-api-mpp@cisco.com (Cisco MPP DevNet, from embedded OpenAPI)",
        "impact": [
            "POST /api/Config/v1/SetParams: write SIP credentials, enable SSH, change network config",
            "POST /api/Config/v1/GetParams: read all config including SIP passwords and auth credentials",
            "POST /api/Ui/v1/SendKey: dial arbitrary numbers, answer/transfer/hang up active calls",
            "POST /api/Serviceability/v1/StartPacketCapture: capture phone traffic (SIP, RTP/audio)",
            "POST /api/Serviceability/v1/RebootDevice: denial of service via repeated reboot",
            "All operations run as root on secondary chip",
        ],
        "remediation": (
            "Add authentication to all apigateway endpoints. "
            "Bind to loopback (127.0.0.1) or use a Unix socket if the API is only consumed by "
            "local processes on the secondary chip. "
            "Apply SetParams parameter allowlist to prevent credential and network modification. "
            "Drop apigateway from root:root to a dedicated low-privilege user. "
            "Validate the `url`/`callbackUrl` parameters against an allowlist of trusted upload targets."
        ),
        "yara": """rule cisco_8832_apigateway_unauthenticated_api {
    meta:
        description = "Cisco 8832 apigateway embeds no-auth OpenAPI specs for config/UI/serviceability"
        severity = "CRITICAL"
    strings:
        $openapi    = "\\"openapi\\":\\"3.0.2\\"" ascii
        $setparams  = "/api/Config/v1/SetParams" ascii
        $sendkey    = "/api/Ui/v1/SendKey" ascii
        $reboot     = "/api/Serviceability/v1/RebootDevice" ascii
        $no_auth_1  = "phone-api-mpp@cisco.com" ascii
    condition:
        $openapi and ($setparams or $sendkey or $reboot) and $no_auth_1
}""",
    },
    {
        "id": "F2",
        "title": "SSRF and Device File Exfiltration via Attacker-Controlled URL Parameters in apigateway",
        "severity": "HIGH",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-918",
        "description": (
            "Seven apigateway endpoints accept an attacker-controlled `url` or `callbackUrl` "
            "parameter which the phone then connects to outbound. "
            "This creates two distinct primitives:\n\n"
            "1. File exfiltration: five Serviceability and UI endpoints accept a `url` field "
            "described as 'URL provided by server where file will be uploaded by Apigateway' "
            "with `uploadMethod` defaulting to POST. When called, the phone initiates an "
            "outbound HTTP POST to the provided URL, uploading the requested file:\n"
            "  - GetDeviceScreenshot: POST screenshot image to attacker URL\n"
            "  - GetPacketCapture: POST packet capture (.pcap) to attacker URL\n"
            "  - GenerateAndGetPRTFile: POST PRT diagnostic bundle to attacker URL\n"
            "  - GetConfigFile: POST device configuration file to attacker URL\n"
            "  - GetStatusFile: POST device status file to attacker URL\n\n"
            "2. SSRF via callbackUrl: Config/Subscribe and Serviceability/Subscribe accept a "
            "`callbackUrl` that the phone calls when config or serviceability events occur. "
            "An attacker registers their server as the callback target, receiving ongoing "
            "phone state updates (call state, registration changes, config changes). "
            "Both the direct upload and the callback mechanisms allow the phone to be used "
            "as a request originator for SSRF against internal network targets. "
            "Combined with F1 (no authentication), all of these are reachable without credentials."
        ),
        "upload_endpoints": {
            "GetDeviceScreenshot": "/api/Ui/v1/GetDeviceScreenshot -- url (required), uploadMethod (POST/PUT)",
            "GetPacketCapture":    "/api/Serviceability/v1/GetPacketCapture -- url (required), uploadMethod",
            "GenerateAndGetPRTFile": "/api/Serviceability/v1/GenerateAndGetPRTFile -- url (required), uploadMethod",
            "GetConfigFile":       "/api/Serviceability/v1/GetConfigFile -- url (required), uploadMethod",
            "GetStatusFile":       "/api/Serviceability/v1/GetStatusFile -- url (required), uploadMethod",
        },
        "callback_endpoints": {
            "Config/Subscribe":          "/api/Config/v1/Subscribe -- callbackUrl (required)",
            "Serviceability/Subscribe":  "/api/Serviceability/v1/Subscribe -- callbackUrl (required)",
        },
        "impact": [
            "Exfiltrate device config file: contains SIP server credentials, admin credentials",
            "Exfiltrate packet capture: contains SIP signaling (auth headers, call content)",
            "Exfiltrate PRT diagnostic bundle: syslog, call records, network config dump",
            "SSRF via callbackUrl: phone originates HTTP requests to internal targets",
            "All exfiltration requires no authentication (see F1)",
        ],
        "remediation": (
            "Validate `url` and `callbackUrl` parameters against an allowlist of trusted targets. "
            "Do not allow arbitrary URLs; restrict to provisioned CUCM/UCM server addresses. "
            "Add authentication to all apigateway endpoints before accepting URL parameters. "
            "Log all outbound upload requests with destination IP."
        ),
    },
    {
        "id": "F3",
        "title": "SSL_CTX_set_keylog_callback Compiled into webexd on Secondary Chip -- TLS Session Key Logging Capability Present",
        "severity": "HIGH",
        "cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-311",
        "description": (
            "The `webexd` binary on the secondary 28832 chip imports `SSL_CTX_set_keylog_callback` "
            "and defines an internal handler `SL_SSL_CTX_keylog_cb_func`. "
            "This OpenSSL function registers a callback invoked for every TLS master secret "
            "derived during a TLS handshake, producing NSS key log format output compatible "
            "with Wireshark's TLS decryption (SSLKEYLOGFILE format). "
            "The `apigateway` binary also imports `SSL_CTX_set_keylog_callback` and "
            "`SL_SSL_CTX_keylog_cb_func`, indicating the pattern is shared across "
            "multiple processes on the chip. "
            "If the key log callback is invoked (via a debug flag, environment variable, or "
            "D-Bus trigger), TLS master secrets for all Webex cloud connections would be "
            "written to disk or a pipe. webexd establishes connections to hardcoded Cisco "
            "cloud endpoints: `https://ds.ciscospark.com/v1/region`, "
            "`https://activation.webex.com`, `https://idbroker.webex.com`, "
            "`https://u2c-a.wbx2.com/u2c/api/v1`. "
            "These connections carry Webex access tokens, device activation credentials, "
            "and call signaling data. Exposure of TLS session keys for these connections "
            "would decrypt all Webex cloud traffic for the device."
        ),
        "affected_binaries": [
            "webexd (28832 rootfs: /usr/sbin/webexd)",
            "apigateway (28832 rootfs: /usr/sbin/apigateway)",
        ],
        "cloud_endpoints": [
            "https://ds.ciscospark.com/v1/region",
            "https://activation.webex.com",
            "https://idbroker.webex.com",
            "https://u2c-a.wbx2.com/u2c/api/v1",
        ],
        "impact": [
            "TLS session key logging for all Webex cloud connections if callback is triggered",
            "Decryption of Webex access tokens, device activation credentials, call signaling",
            "Debug keylog path could be triggered via D-Bus (webexd uses D-Bus IPC) or env var",
        ],
        "remediation": (
            "Audit webexd and apigateway for SSLKEYLOGFILE environment variable check and "
            "any debug flags that invoke SSL_CTX_set_keylog_callback. "
            "Remove keylog callback registration from production builds. "
            "Ensure the callback is not invocable via any IPC channel accessible from "
            "lower-privilege processes."
        ),
    },
    {
        "id": "F4",
        "title": "DECT SUOTA Firmware Updates Delivered via Plaintext HTTP on Primary Chip",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "cwe": "CWE-494",
        "description": (
            "The primary 8832 chip contains `/etc/miniweb/suota_mgmt.cfg` with content: "
            "`1;1;1;1;1.6;1;http://localhost/NG11_4.01_SUOTA`. "
            "This configures the DECT SUOTA (Software Update Over The Air) mechanism "
            "for handset firmware distribution via the 8832 base station. "
            "The URL scheme is plaintext HTTP (`http://localhost/`), meaning handset "
            "firmware is served without transport encryption. "
            "The DECT library (`libcmbs_host_lnx.so`) provides the SUOTA delivery mechanism "
            "and also exports `app_SrvPINCodeSet` (DECT PIN code management API). "
            "An attacker with network access to the phone's DECT air interface or to the "
            "LAN segment serving the firmware URL can perform a MITM substitution of the "
            "DECT handset firmware with a malicious image. "
            "If the firmware signature check is absent or bypassable, this provides a "
            "code execution path on paired DECT handsets (e.g., Cisco IP DECT 6825). "
            "The `localhost` base URL also implies the 8832 itself serves the firmware "
            "to handsets, making the 8832 a firmware distribution point for the DECT network."
        ),
        "config_path":   "/etc/miniweb/suota_mgmt.cfg",
        "config_value":  "1;1;1;1;1.6;1;http://localhost/NG11_4.01_SUOTA",
        "dect_library":  "libcmbs_host_lnx.so (DECT stack, SUOTA delivery, PIN code API)",
        "impact": [
            "Plaintext HTTP DECT handset firmware delivery -- susceptible to MITM substitution",
            "Compromised 8832 (via F1) becomes a malicious DECT firmware distribution point",
            "No transport-layer integrity for firmware served to paired handsets",
        ],
        "remediation": (
            "Change SUOTA URL to HTTPS with certificate pinning for the firmware server. "
            "Implement firmware signature verification on the handset before applying any update. "
            "Restrict SUOTA server to a provisioned, authenticated endpoint."
        ),
    },
    {
        "id": "F5",
        "title": "key28832.sbn Contains Unencoded Fleet-Wide TrustZone RSA-2048 Public Modulus",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-321",
        "description": (
            "The file `key28832.12-0-7MPP0501-123.sbn` (353 bytes total) contains "
            "a raw RSA-2048 public modulus without ASN.1 DER encoding. "
            "Layout: 96-byte header (filename at offset 0x41) + 257-byte payload. "
            "The payload is `0x00` prefix + 256-byte RSA-2048 modulus "
            "(SHA256: 80267ab76c08664827ce0b059fe1947ca259c79a21cde07651b888c9b87b9238). "
            "Shannon entropy: 7.18 bits/byte (high, consistent with an RSA public key modulus). "
            "The filename prefix `key28832` and packaging in a separate SBN file alongside "
            "the encrypted `trustzone28832` and `oemloader28832` SBNs indicate this is the "
            "fleet-wide verification key used by the TrustZone bootloader on the 28832 chip "
            "to authenticate signed firmware images. "
            "Publishing this key in a distributed firmware archive exposes the modulus to "
            "cryptographic analysis (factoring attempts, ROCA/Coppersmith-class weaknesses). "
            "The absence of ASN.1 DER encoding (raw modulus only, no OID, no public exponent "
            "field in the SBN payload) is a non-standard format that suggests custom parsing "
            "in the TrustZone boot code."
        ),
        "file":      "key28832.12-0-7MPP0501-123.sbn",
        "size":      353,
        "payload":   "257 bytes = 0x00 sign prefix + 256-byte RSA-2048 modulus",
        "sha256_payload": "80267ab76c08664827ce0b059fe1947ca259c79a21cde07651b888c9b87b9238",
        "entropy":   7.18,
        "encoding":  "raw modulus (NOT ASN.1 DER encoded -- no OID, no public exponent in payload)",
        "impact": [
            "Fleet-wide TrustZone verification key modulus is publicly distributed in firmware archive",
            "Factoring the modulus would break TrustZone secure boot across all 8832 units",
            "Non-standard raw encoding suggests custom TrustZone parsing; parser bugs possible",
        ],
        "remediation": (
            "Use per-device or per-batch keys rather than a fleet-wide key for TrustZone verification. "
            "Encode the public key in standard DER/PEM format to allow standard parser use. "
            "Verify the modulus is not vulnerable to ROCA (CVE-2017-15361) or similar "
            "factoring-class weaknesses before relying on it as a trust anchor."
        ),
    },
    {
        "id": "F6",
        "title": "Cisco Internal GitHub Enterprise URL Leaked in Production webexd Binary",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The `webexd` binary on the 28832 chip contains debug build paths embedded as "
            "strings in the `.rodata` / `.debug_str` section. "
            "Multiple paths reference Cisco's internal GitHub Enterprise instance: "
            "`sqbu-github.cisco.com/SL/` -- revealing the internal SCM hostname and "
            "the `SL/` organization. Specific repositories exposed: "
            "`sqbu-github.cisco.com/SL/nlohmann-json.git` and "
            "`sqbu-github.cisco.com/SL/boost.git`. "
            "Both include full commit hashes pinned in the build path: "
            "nlohmann-json at `36e5ecf66d89cce2329168be1805a1728c8ddd23`, "
            "boost at `d42431faf50f07a87e697653ba26d083c1e3136f`. "
            "The build path format `_build/git-worktrees/git@<host>/<org>/<repo>.git/<hash>/` "
            "reveals the Cisco internal CI/CD build system uses git worktrees keyed by "
            "commit hash. These paths provide the exact internal hostname, organization, "
            "repository names, and commit pins used by the Cisco collaboration phone build pipeline."
        ),
        "leaked_host":  "sqbu-github.cisco.com (Cisco internal GitHub Enterprise)",
        "leaked_org":   "SL/ (internal organization namespace)",
        "leaked_repos": [
            "sqbu-github.cisco.com/SL/nlohmann-json.git (commit 36e5ecf)",
            "sqbu-github.cisco.com/SL/boost.git (commit d42431f)",
        ],
        "build_path_format": "_build/git-worktrees/git@sqbu-github.cisco.com/SL/<repo>.git/<hash>/",
        "impact": [
            "Confirms Cisco internal SCM hostname for targeted phishing / VPN entry point research",
            "Exposes build system architecture: git-worktree per commit hash CI pattern",
            "Pinned commit hashes identify exact library versions enabling CVE correlation",
        ],
        "remediation": "Strip debug build paths from production firmware binaries during release build.",
    },
    {
        "id": "F7",
        "title": "debug Account LOCKED in 12.0.7 -- Confirms 14.4.1 debug:debug as Regression",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-284",
        "description": (
            "The primary 8832 chip (12.0.7) shows `debug:!:65532:100:debug:/tmp:/bin/false` "
            "in /etc/passwd -- the `!` prefix locks the account and `/bin/false` prevents shell access. "
            "The secondary 28832 chip (12.0.7) has no debug entry in /etc/shadow at all. "
            "This establishes 12.0.7 as the baseline where the debug account is securely locked "
            "across both chips. "
            "Cross-reference: `cisco_phoneos_5_0_1_re.py` F1 (CRITICAL) documents that "
            "MPP 14.4.1 (all 5 models: 7832, 78xx, 8832, 88xx, 8845_65) has an active "
            "`debug:debug` account (active hash, not locked). "
            "This module's 12.0.7 data confirms the 14.4.1 state is a regression -- the "
            "account was locked in 12.0.7 and was re-activated (with crackable password) "
            "in 14.4.1. There is no functional justification for re-enabling a debug account "
            "in a later production release."
        ),
        "version_12_0_7_primary":   "debug:!:65532:100:debug:/tmp:/bin/false (LOCKED + /bin/false)",
        "version_12_0_7_secondary": "debug absent from /etc/shadow",
        "version_14_4_1":           "debug:debug ACTIVE (see cisco_phoneos_5_0_1_re.py F1)",
        "impact": [
            "Baseline confirmation: 12.0.7 is secure, 14.4.1 regression introduced debug:debug",
            "Regression scope confirmed: all 5 models in 14.4.1 train are affected",
        ],
        "remediation": (
            "Lock the debug account in 14.4.1 by replacing the active hash with `!`. "
            "See cisco_phoneos_5_0_1_re.py F1 for full remediation guidance."
        ),
    },
]

SUMMARY = {
    "total":    7,
    "critical": 1,
    "high":     2,
    "medium":   3,
    "low":      1,
    "chip_notes": {
        "primary_8832": (
            "Main phone logic chip. UBI rootfs. Hosts Volantis.jar (Webex stack), "
            "libcmbs_host_lnx.so (DECT/SUOTA), debugshd.sh init (binary not in rootfs -- "
            "runtime-provisioned). debug account locked. Serial console on ttyAS0 115200."
        ),
        "secondary_28832": (
            "Secondary ARM chip handling Webex cloud, UI, and API gateway. SquashFS rootfs. "
            "root:/bin/sh (not /bin/false), messagebus:/bin/sh (unusual). "
            "SSH disabled in xinetd. No SUDI hardware key (primary uses libctame:RSA_SUDIKEY). "
            "Deploy mode hardcoded to 5 (MPP/3PCC) in S93phone.sh. "
            "apigateway on 8443 is the primary attack surface."
        ),
    },
    "opaque_sbns": (
        "trustzone28832 (408 KB) and oemloader28832 (1.69 MB) both carry magic "
        "`00 00 00 01 1d e1 00 00` and are encrypted/obfuscated -- binwalk finds no "
        "compressed signatures. These protect the TrustZone attestation and bootloader. "
        "Decryption requires key28832.sbn modulus context (see F5)."
    ),
}
