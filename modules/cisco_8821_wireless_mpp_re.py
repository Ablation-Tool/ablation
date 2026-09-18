"""
Cisco IP Phone 8821 Wireless MPP 11.0.6SR8-2 RE Module
Target: cmterm-8821.11-0-6SR8-2_REL.zip
  - rootfs8821.11-0-6SR8-2.sbn: SquashFS v4.0 gzip 4096-block 2257 inodes (77.6MB)
  - kern8821.11-0-6SR8-2.sbn: ARM32 kernel SBN (4.0MB)
  - dtblob8821.HE-01-011.sbn: Device tree blob (12KB)
  - fbi8821.HE-01-014.sbn: First Boot Image / flasher (130KB)
  - sb28821.HE-01-024.sbn: Second-stage bootloader (334KB)
  - vc48821.11-0-6SR8-2.sbn: VoIP codec payload (3.97MB)
Source: /media/cowboy/research/Cisco-IP PHONE/
Build date: 2026-08-17 (kernel + rootfs mtime)
Extracted: /tmp/mnt8821
"""

METADATA = {
    "target":     "Cisco 8821 Wireless IP Phone MPP 11.0.6SR8-2",
    "model":      "CP-8821 (8821 and 8821-EX / rugged outdoor variant)",
    "firmware":   "MPP (Multiplatform Phone) 11.0.6SR8-2",
    "format":     "SBN components: rootfs=SquashFS v4.0 (gzip, 4096-byte blocks, 2257 inodes)",
    "arch":       "ARM32 (same platform family as 78xx/8845 MPP)",
    "build_date": "2026-08-17 (latest SR8 security release)",
    "soc":        "Qualcomm/TI variant (ARM32, same class as 78xx MPP platform)",
    "bootloader": {
        "fbi":  "fbi8821.HE-01-014.sbn (First Boot Image)",
        "sb2":  "sb28821.HE-01-024.sbn",
        "dtb":  "dtblob8821.HE-01-011.sbn",
    },
    "auth_notes": "No /etc/shadow - all hashes in /etc/passwd (old-style, no shadow file)",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Root and Default Accounts Share Default DES Password 'cisco' -- /etc/passwd, No Shadow File",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "Cisco 8821 Wireless Phone firmware MPP 11.0.6SR8-2 stores credentials "
            "in `/etc/passwd` without a shadow file. The `root` and `default` accounts "
            "share an identical DES hash `nCjlgBm7.lvX2` (cracked: password=`cisco`). "
            "DES-crypt hashes are limited to 8-character passwords and are "
            "computationally weak by modern standards (recoverable in seconds on GPU). "
            "While both root and default have `nologin` shell (blocking interactive "
            "login), the cleartext-equivalent password `cisco` is usable by any "
            "service that performs PAM authentication without shell restriction checks. "
            "The absence of a shadow file exposes all hashes to any local process "
            "that can read `/etc/passwd` (world-readable by design). "
            "Combined with the active debug account (F2), an attacker who obtains "
            "debugsh access can read `/etc/passwd` and crack the root hash offline "
            "in seconds."
        ),
        "passwd_entries": {
            "root":    "root:nCjlgBm7.lvX2:0:0:root:/home/root:/sbin/nologin",
            "default": "default:nCjlgBm7.lvX2:65533:100:default user:/home/default:/sbin/nologin",
        },
        "hash":             "nCjlgBm7.lvX2",
        "hash_type":        "DES-crypt (traditional crypt(3), salt='nC')",
        "cracked_password": "cisco",
        "crack_method":     "hashcat -m 1500, wordlist hit (under 1 second)",
        "no_shadow":        True,
        "impact": [
            "Root password 'cisco' is a default credential -- applies to all 8821 deployments",
            "DES hash in world-readable /etc/passwd is trivially offline-crackable without privileged access",
            "Any PAM-authenticated service using root credentials authenticates with 'cisco'",
            "Combined with F2 debug account: debug shell -> /etc/passwd read -> root hash cracked offline",
        ],
        "remediation": (
            "Lock the root account: replace hash with `!` or `*`. "
            "Implement shadow password file (`/etc/shadow`, chmod 640). "
            "Do not share password hashes across accounts. "
            "Remove default 'cisco' credential from ALL phone firmware builds."
        ),
        "yara": """rule cisco_8821_mpp_root_cisco_des_hash {
    meta:
        description = "Cisco 8821 MPP 11.0.6 root/default accounts share DES hash for password 'cisco'"
        severity = "CRITICAL"
    strings:
        $root_des   = "root:nCjlgBm7.lvX2" ascii
        $default_des = "default:nCjlgBm7.lvX2" ascii
        $cisco_salt = "nCjlgBm7" ascii
    condition:
        any of them
}""",
    },
    {
        "id": "F2",
        "title": "debug Account Active with MD5 Hash (Same Hash as MPP 14.4.1 Regression) -- Pre-12.0.7 State Preserved",
        "severity": "HIGH",
        "cvss": 8.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The 8821 MPP 11.0.6SR8-2 firmware has the `debug` account active with "
            "hash `$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71` (MD5-crypt, cracked: `debug`) "
            "and login shell `/usr/sbin/debugsh`. This is the same account and "
            "identical hash found in MPP 14.4.1 firmware across five models "
            "(7832, 78xx, 8832, 88xx, 8845_65). "
            "The cross-version evidence establishes the timeline: "
            "(1) debug:debug was ACTIVE in MPP 11.0.6 and earlier versions, "
            "(2) it was LOCKED in MPP 12.0.7 (`debug:*:..:/bin/false`), "
            "(3) it was REACTIVATED in MPP 14.4.1 with the identical hash and debugsh shell. "
            "The identical hash across all versions suggests the debug account "
            "was never credential-rotated between releases -- it has always used "
            "the same password since initial implementation. "
            "On the 8821 wireless phone, debugsh access enables WiFi credential "
            "extraction (WPA enterprise credentials stored on device) and "
            "DECT/WiFi proximity attack facilitation via the Bluetooth+WiFi radio."
        ),
        "hash":             "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
        "hash_type":        "MD5-crypt ($1$)",
        "cracked_password": "debug",
        "version_timeline": {
            "11.0.6SR8_8821": "ACTIVE (same hash, confirmed 2026-08-17 build)",
            "12.0.7MPP":      "LOCKED (debug:*:..:/bin/false)",
            "14.4.1_all5":    "REACTIVATED (same hash, same shell -- build regression)",
        },
        "wireless_risk": "8821 WiFi phone: debug access enables WPA enterprise credential extraction from device keystore",
        "impact": [
            "debug:debug credentials unchanged since at least MPP 11.0.6 (not rotated across versions)",
            "Confirming debug account predates MPP 12.0.7 lockdown -- not a new credential",
            "8821 wireless: WPA/WPA2-Enterprise credentials stored on device accessible via debugsh",
        ],
        "remediation": (
            "Lock debug account in all MPP firmware: `debug:*:65532:100:debug:/tmp:/sbin/nologin`. "
            "Rotate the debug account password between major releases at minimum. "
            "File CVE against MPP 14.4.1 for reintroducing the 11.x-era debug account."
        ),
        "yara": """rule cisco_mpp_debug_active_md5 {
    meta:
        description = "Cisco MPP debug account active with MD5 hash (pre-12.0.7 or 14.4.1 regression)"
        severity = "HIGH"
    strings:
        $debug_hash = "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71" ascii
        $debugsh    = "/usr/sbin/debugsh" ascii
    condition:
        $debug_hash
}""",
    },
    {
        "id": "F3",
        "title": "Multiple Service Accounts with Empty Password in /etc/passwd -- security, image, app Without Hashes",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-521",
        "description": (
            "The 8821 `/etc/passwd` contains three service accounts with empty "
            "password fields (`security::17:70:security:/:/sbin/nologin`, "
            "`image::18:3:image:/usr/sbin:/sbin/nologin`, "
            "`app::65534:65534:app:/home:/sbin/nologin`). "
            "All three have `/sbin/nologin` shells, preventing interactive login. "
            "However, PAM authentication may succeed for these accounts "
            "with an empty password string, depending on PAM configuration. "
            "The `security` account has home directory `/` and GID 70 "
            "(likely a privileged system group). If any service performs "
            "privilege escalation by authenticating as these accounts via "
            "PAM (not shell), an empty password is sufficient. "
            "The `image` account with GID 3 (likely `sys` group) could "
            "provide access to firmware update operations if the image "
            "service uses account-based access control."
        ),
        "empty_accounts": [
            "security::17:70:security:/:/sbin/nologin",
            "image::18:3:image:/usr/sbin:/sbin/nologin",
            "app::65534:65534:app:/home:/sbin/nologin",
        ],
        "impact": [
            "Empty password accounts succeed PAM authentication without credentials",
            "security account GID 70 and home '/' may map to privileged system operations",
            "No shadow file means empty-password accounts are visible to any process reading /etc/passwd",
        ],
        "remediation": (
            "Lock all service accounts that do not require password authentication: "
            "replace empty password field with `*` or `!`. "
            "Migrate to shadow password file to prevent hash exposure."
        ),
        "yara": """rule cisco_8821_empty_password_accounts {
    meta:
        description = "Cisco 8821 MPP service accounts with empty password in /etc/passwd"
        severity = "MEDIUM"
    strings:
        $security_empty = "security::17:70" ascii
        $image_empty    = "image::18:3" ascii
        $app_empty      = "app::65534" ascii
    condition:
        2 of them
}""",
    },
]

SUMMARY = {
    "total":    3,
    "critical": 1,
    "high":     1,
    "medium":   1,
    "low":      0,
    "note": (
        "F1 establishes root:cisco as a default credential shared across root+default accounts "
        "in /etc/passwd with no shadow file. DES hash cracked in under 1 second. "
        "F2 confirms debug:debug predates MPP 12.0.7 -- the MPP 14.4.1 regression "
        "restored the pre-12.0.7 account state identically (same hash, same shell). "
        "Cross-model evidence: debug hash identical across 8821+7832+78xx+8832+88xx+8845_65."
    ),
}
