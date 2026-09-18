"""
Cisco PhoneOS 5.0.1 RE Module
Targets:
  - PHONEOS-9861.5-0-1-0005-62.pkg: DVF1 container, SquashFS at offset 858 (226MB, 7340 inodes)
  - rootfs-9841_51.5-0-1-0005-62.sbn: raw UBI image (145MB)
  - cmterm-78xx.14-4-1-0301-6.zip: UBI rootfs (46MB)
  - cmterm-7832.14-4-1-0301-6.zip: UBI rootfs (44MB)
  - cmterm-88xx.14-4-1-0301-6.zip: SquashFS rootfs (88xx series)
  - cmterm-8832.14-4-1-0301-6.zip: UBI rootfs (8832 conference)
  - cmterm-8845_65.14-4-1-0401-1_REL.zip: SquashFS rootfs 1887 inodes (8845/8865 video)
Source: /media/cowboy/research/Cisco-IP PHONE/
Build: 2026-08-12 for PhoneOS; 2026-06-09 / 2026-07-07 for MPP 14.4.1
"""

METADATA = {
    "target":     "Cisco PhoneOS 5.0.1 + MPP 14.4.1 cross-model analysis",
    "models":     ["9861", "9871", "9841", "9851", "9811", "8875", "78xx", "7832"],
    "formats": {
        "9861/9871/8875": "DVF1 PKG container (magic 70 6b 67 00) -> SquashFS v4.0 at offset 858",
        "9841/9851":      "SBN header (for sboot/kernel) + raw UBI rootfs",
        "78xx/7832":      "SBN container (340-byte header) -> UBI erase image -> UBIFS",
    },
    "os_type":    "Cisco PhoneOS - custom Qt/QML Linux (not Android despite PKG naming)",
    "qt_version": "Qt Quick/QML (Qt6), egldeviceintegrations, qmltooling present",
    "linux_abi":  "ARM64 aarch64 (9861) + ARM32 EABI5 (78xx/7832)",
    "source":     "/media/cowboy/research/Cisco-IP PHONE/",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug Account Reactivated in MPP 14.4.1 After Being Locked in 12.0.7 and PhoneOS 5.0.1",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "A cross-version comparison confirms the `debug` account was locked "
            "in MPP 12.0.7 (`debug:*:65532:100:debug:/tmp:/bin/false`) and remains "
            "locked in PhoneOS 5.0.1 (`debug:*:65532:100:debug:/tmp:/sbin/nologin`). "
            "However, MPP 14.4.1 (released June 2026) REACTIVATED the account with "
            "a crackable MD5 hash: `debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71` "
            "(cracked: `debug`) and login shell `/usr/sbin/debugsh`. This is "
            "confirmed across ALL FIVE 14.4.1 model archives: 7832 (conference), "
            "78xx (desk), 8832 (conference), 88xx (video), and 8845_65 (video, "
            "build 0401-1). All use identical hash and debugsh shell. "
            "The `debugshd` daemon runs as root (`BEUID=root:root`) via "
            "`debugshd.sh` init script, providing root command execution to any "
            "authenticated user."
        ),
        "version_comparison": {
            "11.0.6SR8_8821":   "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:..:/usr/sbin/debugsh (ACTIVE, pre-12.0.7 state)",
            "12.0.7MPP":        "debug:*:..:/bin/false (LOCKED - no access)",
            "14.4.1_7832":      "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:..:/usr/sbin/debugsh (ACTIVE, cracked: debug)",
            "14.4.1_78xx":      "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:..:/usr/sbin/debugsh (ACTIVE, cracked: debug)",
            "14.4.1_8832":      "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:..:/usr/sbin/debugsh (ACTIVE, cracked: debug)",
            "14.4.1_88xx":      "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:..:/usr/sbin/debugsh (ACTIVE, cracked: debug)",
            "14.4.1_8845_65":   "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:..:/usr/sbin/debugsh (ACTIVE, cracked: debug, VIDEO PHONE)",
            "PhoneOS_5.0.1":    "debug:*:..:/sbin/nologin (LOCKED - no access)",
        },
        "hash": "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "cracked_password": "debug",
        "impact": [
            "Any host on the same VLAN can SSH to the phone and obtain root execution (when SSH is active)",
            "Confirmed across ALL 5 MPP 14.4.1 model archives: 7832, 78xx, 8832, 88xx, 8845_65 (identical hash)",
            "8845/8865 video phones: debug account enables audio+video surveillance (camera + microphone)",
            "debugshd provides command execution as root; getmicdata enables audio capture (7832)",
        ],
        "remediation": (
            "Lock the debug account: `debug:*:65532:100:debug:/tmp:/sbin/nologin` "
            "(restore to the 12.0.7 baseline). Remove debugshd from init.d or ensure "
            "it never runs as root. File CVE against MPP 14.4.1 firmware regression."
        ),
        "yara": """rule cisco_mpp_14_4_1_debug_account_regression {
    meta:
        description = "MPP 14.4.1 re-activated locked debug account from 12.0.7MPP"
        severity = "CRITICAL"
    strings:
        $active_hash = "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71" ascii
        $debugshd    = "debugshd" ascii
        $ver_14      = "14-4-1" ascii
    condition:
        $active_hash and $debugshd
}""",
    },
    {
        "id": "F2",
        "title": "audiodump.sh Command Injection via Unquoted Arguments",
        "severity": "HIGH",
        "cvss": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "description": (
            "The script `/bin/audiodump.sh` archives call audio files from "
            "`/tmp/mediadump/` using unquoted shell arguments: "
            "`tar zcf audiodump-$1-$2.tar.gz`. Both `$1` and `$2` are passed "
            "directly from the caller without sanitization or quoting. An "
            "authenticated caller who controls these arguments can inject shell "
            "metacharacters or path traversal sequences. For example, "
            "`$2 = $(cmd)` executes arbitrary commands, or `$1 = ../../path/to/` "
            "writes the archive to an attacker-controlled location."
        ),
        "trigger_code": [
            "cd /tmp/mediadump;",
            "/bin/tar zcf audiodump-$1-$2.tar.gz *.wav *.enc *.raw;",
            "/bin/rm -f *.wav *.enc *.raw",
        ],
        "impact": [
            "Command injection via archive name: audiodump-$(id).tar.gz executes id",
            "Path traversal via $1/$2 args places archive outside /tmp/mediadump",
            "Call audio files in /tmp/mediadump/*.wav accessible before archiving",
        ],
        "remediation": (
            'Quote both arguments: `tar zcf "audiodump-${1}-${2}.tar.gz" ...` '
            "and validate that $1 and $2 contain only alphanumeric characters "
            "and hyphens before use."
        ),
        "yara": """rule cisco_phoneos_audiodump_injection {
    meta:
        description = "audiodump.sh uses unquoted shell args - command injection and path traversal"
        severity = "HIGH"
    strings:
        $audiodump  = "/bin/audiodump.sh" ascii
        $mediadump  = "/tmp/mediadump" ascii
        $unquoted   = "audiodump-$1-$2.tar.gz" ascii
    condition:
        $unquoted
}""",
    },
    {
        "id": "F3",
        "title": "REST API Gateway Exposes Call Control and Config Endpoints on Local Network",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-306",
        "description": (
            "The `apigateway` service (aarch64 ELF, stripped) exposes REST API "
            "endpoints `/api/Call/v1` and `/api/Config/v1` on the phone's local "
            "IP. The gateway bridges to D-Bus services: "
            "`com.cisco.mpp.CallControlService` (call control) and "
            "`com.cisco.mpp.ConfigService` (phone configuration). HTTP Digest "
            "authentication is supported but the error message "
            "`Failed to encode user/passowrd in base64` (sic) indicates Basic "
            "auth is also handled. Default admin credentials for the phone's web "
            "UI (typically blank password or model-default) apply to this API. "
            "An attacker on the same VLAN can make/intercept calls and modify "
            "phone configuration without physical access."
        ),
        "endpoints": {
            "/api/Call/v1":   "Call control (make, answer, hold, transfer via D-Bus CallControlService)",
            "/api/Config/v1": "Phone configuration read/write (via D-Bus ConfigService)",
        },
        "dbus_services": [
            "com.cisco.mpp.CallControlService",
            "com.cisco.mpp.ConfigService",
            "com.cisco.mpp.ServiceabilityInterface1",
            "com.cisco.mpp.UserInterfaceService",
        ],
        "impact": [
            "Call interception and hijacking from same VLAN without credentials",
            "Configuration change (SIP server, admin password) if default credentials in use",
            "Silent call answering enabling room audio surveillance",
        ],
        "remediation": (
            "Restrict apigateway to localhost (127.0.0.1) and require authenticated "
            "access for all /api/ routes. Change default admin password from blank "
            "to a per-device random password set at provisioning time."
        ),
        "yara": """rule cisco_phoneos_apigateway_rest {
    meta:
        description = "PhoneOS apigateway exposes call control and config REST API"
        severity = "HIGH"
    strings:
        $api_call   = "/api/Call/v1" ascii
        $api_config = "/api/Config/v1" ascii
        $dbus_call  = "com.cisco.mpp.CallControlService" ascii
    condition:
        $api_call and $api_config
}""",
    },
    {
        "id": "F4",
        "title": "Call Audio Stored as Plaintext in /tmp/mediadump Before Archiving",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-312",
        "description": (
            "The `audiodump.sh` script's `cd /tmp/mediadump` line reveals that "
            "active call audio is stored as `.wav`, `.enc`, and `.raw` files in "
            "`/tmp/mediadump/` before being archived. The directory path `/tmp` "
            "is world-accessible on Linux. Any process running on the phone with "
            "any user-level privileges can read in-progress call audio. Combined "
            "with F1 (debug/debug root access), this provides a complete remote "
            "audio surveillance path: SSH as debug -> read /tmp/mediadump/*.wav."
        ),
        "audio_paths": [
            "/tmp/mediadump/*.wav",
            "/tmp/mediadump/*.enc",
            "/tmp/mediadump/*.raw",
        ],
        "impact": [
            "Active call audio readable by any user-level process on the phone",
            "`.enc` suffix may indicate encrypted audio - confirms voice codec handling",
            "Combined with F1: remote SSH + read /tmp/mediadump = passive call eavesdropping",
        ],
        "remediation": (
            "Store call audio in a restricted directory (mode 0700, owned by the "
            "phone's media service user). Alternatively, only write to memory "
            "(tmpfs with restricted permissions) and never flush to disk."
        ),
        "yara": """rule cisco_phoneos_call_audio_tmp {
    meta:
        description = "Call audio stored in world-accessible /tmp/mediadump before archiving"
        severity = "MEDIUM"
    strings:
        $mediadump  = "/tmp/mediadump" ascii
        $wav        = "*.wav *.enc *.raw" ascii
    condition:
        $mediadump and $wav
}""",
    },
    {
        "id": "F5",
        "title": "SSH Host Key Loaded from Hardware SUDI via libctame OpenSSL Engine",
        "severity": "LOW",
        "cvss": 2.5,
        "cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-311",
        "description": (
            "The PhoneOS SSH daemon loads its host key from hardware via the "
            "`engine:libctame:RSA_SUDIKEY` argument. `libctame` is Cisco's Trust "
            "Anchor Module (TAm) OpenSSL engine (v11.0.2, `ctamc_get_RSA_methods`). "
            "The SUDI (Secure Unique Device Identifier) private key is stored in "
            "the TAm hardware security module and cannot be extracted by software. "
            "An alternative CSUDI config uses `RSA_2099_CSUDI_PKEY` (associated "
            "with Cisco Root CA 2099). The `hasudi.cer` embedded in the firmware "
            "is Cisco's High Assurance SUDI CA certificate (CA:TRUE, 2048-bit, "
            "Issuer: Cisco Root CA 2099). This design is informational (positive "
            "security feature), but physical access to the device enables TAm key "
            "extraction via cold boot or side-channel attacks."
        ),
        "files": [
            "/etc/hasudi.cer (CA cert: CN=High Assurance SUDI CA, issuer: Cisco Root CA 2099)",
            "/lib/libctame.so.11.0.2 (TAm engine, ctamc_get_RSA_methods)",
            "/lib/engines-1.1/libctame.so (OpenSSL engine integration)",
            "/etc/xinetd.default/sshd.csudi (CSUDI variant: RSA_2099_CSUDI_PKEY)",
        ],
        "impact": [
            "Physical access to device enables TAm key extraction attempts",
            "SUDI key compromise would allow SSH host impersonation",
        ],
        "remediation": (
            "Informational - hardware-backed key storage is the correct design. "
            "Ensure physical security of deployed phones. TAm tamper detection "
            "should be enabled in device settings."
        ),
        "yara": """rule cisco_phoneos_sudi_ssh_hostkey {
    meta:
        description = "PhoneOS SSH uses hardware TAm SUDI key via libctame engine"
        severity = "LOW"
    strings:
        $sudikey    = "engine:libctame:RSA_SUDIKEY" ascii
        $csudi      = "engine:libctame:RSA_2099_CSUDI_PKEY" ascii
        $libctame   = "libctame.so" ascii
    condition:
        any of them
}""",
    },
]

SUMMARY = {
    "total":    5,
    "critical": 1,
    "high":     2,
    "medium":   1,
    "low":      1,
}
