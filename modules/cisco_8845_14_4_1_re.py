"""
Cisco IP Phone 8845/8865 MPP 14.4.1 RE Module
Target: cmterm-8845_65.14-4-1-0401-1_REL.zip
Format: Raw SquashFS v4.0 (magic hsqs), 72MB
Build: Tue Jul 7 06:50:54 UTC 2026
Video phone: includes vc48845_65.14-4-1-0401-1.sbn (5MB Broadcom video codec binary)
"""

METADATA = {
    "target":       "Cisco IP Phone 8845/8865 MPP 14.4.1",
    "binary":       "rootfs8845_65.14-4-1-0401-1.sbn (raw SquashFS, 72MB)",
    "format":       "Raw SquashFS v4.0 LE (magic 0x73717368 'hsqs'), no SBN header",
    "arch":         "ARM 32-bit EABI5",
    "version":      "14.4.1 (sip8845_65.14-4-1-0401-1)",
    "build_date":   "2026-07-07 06:50:54 UTC",
    "source":       "/media/cowboy/research/Cisco-IP PHONE/cmterm-8845_65.14-4-1-0401-1_REL.zip",
    "zip_contents": {
        "fbi8845_65":  "Boot image (97KB)",
        "kern8845_65": "Kernel image (4MB)",
        "rootfs8845_65": "SquashFS rootfs (72MB) - THIS FILE",
        "sb28845_65":  "Stage 2 bootloader (425KB)",
        "vc48845_65":  "Broadcom video codec binary (5MB, format: proprietary DSP)",
    },
    "vc4_binary": {
        "file":     "vc48845_65.14-4-1-0401-1.sbn",
        "size":     "5.0MB",
        "format":   "Proprietary binary (256-byte null prefix, binary DSP code)",
        "strings":  "31316 printable strings, mostly DSP instruction patterns",
        "notable":  "'Why Does It Always Rain on Me?' embedded string (developer codec marker)",
        "shared":   "Same structure as vc48821 - likely same Broadcom codec vendor",
    },
    "media_libs": {
        "libOMX.brcm.audio_encoder.so": "Broadcom OpenMAX audio encoder",
        "libOMX.brcm.audio_decoder.so": "Broadcom OpenMAX audio decoder",
    },
    "unique_binaries": {
        "cscep":     "SCEP certificate enrollment client",
        "curl":      "HTTP client (TFTP/HTTP provisioning)",
        "cdp":       "Cisco Discovery Protocol",
        "dgetfile":  "File download helper",
        "dgetimage": "Firmware image downloader",
        "bsa_server": "Broadcom BSA Bluetooth server",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug Account with Password debug Confirmed in 8845/8865 - Fleet Scope Now Six Models",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The debug account regression (`debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`, "
            "password: `debug`) is confirmed in the 8845/8865 14.4.1 `/etc/passwd`. "
            "This extends the confirmed fleet scope to six models: "
            "7832, 78xx, 88xx, 8832, 8845/8865 (all MPP 14.4.1), plus 8821 11.0.6SR8-2 "
            "(separate firmware branch). The 8845 is a video endpoint with a camera; "
            "root access on the 8845 provides access to camera capture capabilities "
            "in addition to microphone. The `debugshd` daemon runs as root on every boot."
        ),
        "fleet_scope": [
            "7832 14.4.1 MPP", "78xx 14.4.1 MPP", "88xx 14.4.1 MPP",
            "8832 14.4.1 MPP", "8845/8865 14.4.1 MPP (this module)",
            "8821 11.0.6SR8-2 (separate branch, see cisco_8821_wireless_re.py)",
        ],
        "hash": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "cracked_password": "debug",
        "8845_specific_impact": [
            "8845 is a video phone: root = camera + microphone access",
            "Can capture video from conference room camera via root shell",
            "Combined with FIPS bypass (F2): all crypto operations unvalidated",
        ],
        "remediation": (
            "Lock the debug account: `debug:*:65532:100:debug:/tmp:/sbin/nologin`. "
            "Emergency firmware update required for all MPP 14.4.1 models."
        ),
        "yara": """rule cisco_8845_debug_account_video_phone {
    meta:
        description = "8845/8865 14.4.1 debug:debug regression - video phone with camera access"
        severity = "CRITICAL"
    strings:
        $hash    = "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71" ascii
        $beuid   = "BEUID=root:root" ascii
        $vc4     = "vc48845" ascii nocase
    condition:
        $hash and $beuid
}""",
    },
    {
        "id": "F2",
        "title": "FIPS POST Disabled by Default - CISCOSSL_FOM_DIAG=SKIP_POST in S92phone.sh",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-693",
        "description": (
            "The 8845/8865 startup script `/etc/rc5.d/S92phone.sh` exports "
            "`CISCOSSL_FOM_DIAG=SKIP_POST` unless `/usr/local/etc/secFipsModeEnabled` "
            "exists. This is the same FIPS POST bypass confirmed in the 88xx (see "
            "cisco_88xx_mpp_14_4_1_re.py F2). The pattern is now confirmed across "
            "the entire MPP 14.4.1 family: any phone that has not been explicitly "
            "provisioned for FIPS compliance skips the CiscoSSL power-on self-test "
            "for all cryptographic operations. For the 8845 this includes video "
            "call encryption (SRTP for video streams), SIP TLS, and HTTPS. "
            "Factory-reset phones or phones without CUCM FIPS provisioning export "
            "this variable, voiding FIPS compliance claims for the device."
        ),
        "trigger_code": [
            "if ! [ -f /usr/local/etc/secFipsModeEnabled ]",
            "then",
            "    export CISCOSSL_FOM_DIAG=SKIP_POST",
            "fi",
        ],
        "affected_models_confirmed": [
            "88xx 14.4.1 MPP (original finding)",
            "8845/8865 14.4.1 MPP (confirmed here)",
        ],
        "impact": [
            "FIPS compliance bypassed by default for all 8845/8865 deployments without explicit FIPS provisioning",
            "Video call encryption (SRTP) proceeds without POST validation of crypto module",
            "Attacker with root (F1) can delete secFipsModeEnabled, disabling FIPS on next reboot",
            "Any phone sold under FIPS compliance claims operates in non-FIPS mode unless explicitly configured",
        ],
        "remediation": (
            "Invert the logic: FIPS POST should run by default, disabled only when a "
            "`secFipsModeDISABLED` file is explicitly present. "
            "Harden the enablement file against deletion by the debug account."
        ),
        "yara": """rule cisco_8845_fips_skip_post_default {
    meta:
        description = "8845/8865 S92phone.sh skips FIPS POST unless secFipsModeEnabled - same as 88xx"
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
        "title": "CSCEP Client - SCEP Certificate Enrollment URL Poisonable via Rogue TFTP",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-295",
        "description": (
            "The 8845/8865 ships with `/usr/sbin/cscep`, a SCEP (Simple Certificate "
            "Enrollment Protocol) client for automated PKI certificate enrollment. "
            "CSCEP supports `-u <url>` for the SCEP server URL and accepts both "
            "HTTP and HTTPS (`ra_transport_http_str`, `ra_transport_https_str`). "
            "The SCEP server URL is provisioned via CUCM or TFTP configuration. "
            "If the TFTP provisioning server is poisonable (see F4 in "
            "cisco_mpp_phone_14_4_1_re.py: unauthenticated TFTP), an attacker can "
            "redirect the SCEP URL to a rogue CA. The phone would then enroll with "
            "the attacker's CA, receiving an attacker-signed certificate. "
            "This certificate is used for SIP TLS mutual authentication, "
            "allowing the attacker to impersonate the phone to CUCM or intercept "
            "the phone's authenticated calls."
        ),
        "cscep_operations": [
            "getca: Retrieve CA/RA certificate from SCEP server",
            "enroll: Enroll a new certificate (private key generated on device)",
            "-k <file>: Private key to enroll",
            "-l <file>: Write enrolled certificate to file",
            "-R: Resume interrupted enrollment",
            "-p <host:port>: HTTPS proxy support",
        ],
        "attack_chain": [
            "Attacker poisons TFTP provisioning (see 7832 F4/F5: unauthenticated TFTP)",
            "Rogue SEP<MAC>.cnf.xml delivers attacker SCEP server URL",
            "Phone runs cscep -u http://attacker.com/scep to getca/enroll",
            "Attacker's CA signs the phone's enrollment request",
            "Phone uses attacker-signed cert for SIP TLS - attacker can terminate the TLS",
        ],
        "impact": [
            "Rogue SCEP server = attacker-signed device certificate enrolled on phone",
            "Attacker-signed cert used for SIP TLS: attacker can MITM SIP calls",
            "SCEP runs over HTTP by default: enrollment exchange visible in plaintext",
            "getca operation retrieves CA cert without authentication - CA identity spoofable",
        ],
        "remediation": (
            "Enforce HTTPS (not HTTP) for all SCEP operations. "
            "Pin the SCEP CA certificate to a pre-installed Cisco CA cert. "
            "Authenticate the TFTP configuration source (see SUDI/secure provisioning). "
            "Replace SCEP with EST (RFC 7030) which mandates TLS with server cert validation."
        ),
        "yara": """rule cisco_8845_cscep_enrollment_client {
    meta:
        description = "8845/8865 includes SCEP enrollment client - TFTP poison -> rogue CA enrollment"
        severity = "MEDIUM"
    strings:
        $cscep_url  = "-u <url>" ascii
        $getcacert  = "getcacert_str" ascii
        $enroll     = "enroll" ascii
        $ra_http    = "ra_transport_http_str" ascii
    condition:
        $getcacert and $ra_http
}""",
    },
    {
        "id": "F4",
        "title": "vc4 Video Codec Binary is Closed-Source Broadcom DSP Firmware - Unauditable",
        "severity": "LOW",
        "cvss": 3.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1059",
        "description": (
            "The firmware bundle includes `vc48845_65.14-4-1-0401-1.sbn` (5MB), "
            "a proprietary Broadcom video codec binary. The binary begins with 256 "
            "null bytes followed by what appears to be binary DSP/VPU code. "
            "31,316 printable strings are present but are mostly DSP instruction "
            "patterns. The binary contains the string "
            "`Why Does It Always Rain on Me?` - a Travis song, likely an embedded "
            "codec test pattern or developer marker used for audio/video codec "
            "identification. The same binary structure appears in the 8821 "
            "(`vc48821.11-0-6SR8-2.sbn`), confirming a shared Broadcom codec vendor "
            "across the CP-8821 and 8845/8865 product lines. "
            "The binary cannot be disassembled or audited without Broadcom's codec "
            "documentation. Vulnerabilities in the video codec (e.g., malformed RTP "
            "H.264 stream parsing) are undetectable by static analysis."
        ),
        "vc4_binary_details": {
            "8845_file":    "vc48845_65.14-4-1-0401-1.sbn",
            "8845_size":    "5,056,404 bytes",
            "8821_file":    "vc48821.11-0-6SR8-2.sbn",
            "8821_size":    "3,972,080 bytes",
            "null_prefix":  "256 bytes (both files)",
            "format":       "Proprietary binary DSP/VPU code",
            "easter_egg":   "'Why Does It Always Rain on Me?' (Travis) - embedded test string",
            "auditable":    "No - no symbols, no readable structure, no format documentation",
        },
        "impact": [
            "Video codec vulnerabilities (H.264 RTP parsing) unauditable without Broadcom documentation",
            "Shared binary across 8821 and 8845/8865: single codec vendor vulnerability affects both",
            "Easter egg string confirms developer access to codec binary - possible Broadcom vendor engagement",
        ],
        "remediation": (
            "Request the codec source code or security audit from Broadcom under NDA. "
            "Implement sandboxing for the video codec (seccomp-bpf, separate process, "
            "restricted syscall set) to limit blast radius of codec exploitation. "
            "Fuzz the RTP H.264 input parsing with Cisco's internal fuzzing infrastructure."
        ),
        "yara": """rule cisco_845_broadcom_vc4_codec_firmware {
    meta:
        description = "8845/8821 Broadcom video codec binary - closed-source, unauditable DSP firmware"
        severity = "LOW"
    strings:
        $easter_egg = "Why Does It Always Rain on Me?" ascii
        $vc4_name   = "vc48845" ascii nocase
    condition:
        $easter_egg
}""",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 1,
    "high":     1,
    "medium":   1,
    "low":      1,
}
