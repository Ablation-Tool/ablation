"""
Cisco Catalyst Classic IOS, IOS-XE, and CGP-ONT RE Module
Targets:
  - c3560cx-universalk9-mz.152-7.E14.bin: Classic IOS 15.2(7)E14 for 3560CX (22.9MB, MIPS)
  - c2960l-universalk9-mz.152-7.E14.bin: Classic IOS 15.2(7)E14 for 2960L (same train)
  - cat9k_iosxe_npe.17.18.04.SPA.bin: IOS-XE 17.18.04 NPE for Cat9K (1.18GB, x86_64 Linux)
  - cat9k_iosxe.17.18.04.SPA.bin: IOS-XE 17.18.04 standard (1.18GB, x86_64 Linux)
  - CGP-ONT-4P-1.1.3.18.tar: Catalyst Passive Optical Network ONT (Linux 4.4.140 MIPS, 2022)
  - cat9k_iosxe.17.15.06.CSCwt88239.SPA.smu.bin: IOS-XE 17.15.06 bulk-patch SMU
  - cat9k_iosxe.17.15.06.CSCwv26786.SPA.smu.bin: IOS-XE 17.15.06 bulk-patch SMU
Source: /media/cowboy/research/Cisco-Catalyst/
"""

METADATA = {
    "targets": {
        "c3560cx_ios152": {
            "binary":    "c3560cx-universalk9-mz.152-7.E14.bin",
            "format":    "MZIP compressed IOS image (MZIP magic 0x4D5A4950)",
            "arch":      "MIPS32 (3560CX compact access switch)",
            "image_type": "universalk9 (K9 = export-controlled crypto)",
            "features":  "IP|LAYER_3|PLUS|SSH|3DES|MIN_DRAM_MEG=128",
            "version":   "15.2(7)E14 (fc6)",
            "lzma_payloads": [
                "offset 0xA8: 102MB decompressed (main IOS image)",
                "offset 0x111AAA0: 27MB decompressed (secondary subsystem)",
            ],
            "openssl":   "OpenSSL 1.0.1j 15 Oct 2014 (EOL January 2016)",
            "tar_includes": "info, dc_default_profiles.txt, html/ web management files",
            "cobalt_bootrom": "COBALT boot ROM at offset 0xCDAFD3",
        },
        "cat9k_npe_iosxe": {
            "binary":    "cat9k_iosxe_npe.17.18.04.SPA.bin",
            "format":    "IOS-XE SPA package (DEADBEEF markers, PKCS7/SHA-512 signed)",
            "arch":      "x86_64 Linux (Intel/AMD compatible processor on Cat9K)",
            "variant":   "NPE (No Payload Encryption - export-unrestricted)",
            "version":   "IOS-XE 17.18.04",
            "build_date": "2026-07-18 (initramfs + SquashFS both built 2026-07-18)",
            "signing":   "PKCS7-signedData with SHA-512 digest",
            "initramfs": {
                "format":   "gzip + CPIO newc at offset 0x9DEDCA",
                "filename": "initramfs.x86_64.cat9k.ramfs.cpio",
                "python":   "Python 3.12 (usr/lib64/python3.12)",
                "setools":  "SELinux tools (setools Python package)",
                "systemd":  "systemd-udevd, systemd-journald in init system",
            },
            "squashfs": {
                "offset":   "0x3FDF48B",
                "size":     "1,175,701,760 bytes (1.17GB, xz compressed)",
                "inodes":   "10 (container wrapper)",
                "built":    "2026-07-18 17:56:06",
            },
            "platform_codenames": [
                "discovery", "intrepid", "magic_carpet", "scorpion", "starfleet",
                "nikka", "bigbang", "farscape", "martian", "symphony",
            ],
        },
    },
}

METADATA["targets"]["cgp_ont"] = {
    "binary":     "CGP-ONT-4P-1.1.3.18.tar (fwu.sh + uImage + rootfs + md5.txt)",
    "device":     "Cisco CGP-ONT-4P (4-port Catalyst Passive Optical Network ONT - fiber terminal)",
    "arch":       "MIPS Linux 4.4.140 (EOL February 2022)",
    "version":    "1.1.3.18 (built 2022-10-19)",
    "hardware":   "N40-429 (Cisco hardware model)",
    "codename":   "luna (fwu.sh: 'luna firmware upgrade script')",
    "framework":  "YueMe (firmware update framework)",
    "rootfs":     "SquashFS 4.0 xz-compressed, 17.7MB, 1709 inodes",
    "web_server": "Boa (embedded web server, last upstream release 2005)",
    "services":   ["Boa web server (port 80)", "Samba (smb.conf)", "WPS (wscd.conf)", "dnsmasq", "Avahi?"],
    "init":       "Custom rc0-rc63 sequential init scripts",
}

METADATA["smu_patches"] = {
    "CSCwt88239": "cat9k_iosxe.17.15.06.CSCwt88239.SPA.smu.bin - bulk-patch SMU for IOS-XE 17.15.06",
    "CSCwv26786": "cat9k_iosxe.17.15.06.CSCwv26786.SPA.smu.bin - bulk-patch SMU for IOS-XE 17.15.06",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Classic IOS 15.2(7)E14 Ships OpenSSL 1.0.1j (EOL 2016) with RC4 and 3DES Cipher Suites",
        "severity": "HIGH",
        "cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-327",
        "description": (
            "The decompressed classic IOS 15.2(7)E14 image for the 3560CX and 2960L "
            "contains `OpenSSL 1.0.1j 15 Oct 2014` (confirmed in both AES and RC4 "
            "module strings). OpenSSL 1.0.1 reached End-of-Life in January 2016. "
            "The cipher suite list includes: `AECDH-RC4-SHA` (RC4 - broken), "
            "`ADH-DES-CBC3-SHA` (3DES - SWEET32 CVE-2016-2183), and "
            "`AECDH-DES-CBC3-SHA` (anonymous DH with 3DES). "
            "RC4 is cryptographically broken (CVE-2015-2808 Bar Mitzvah attack). "
            "3DES has a practical birthday attack at ~32GB data (CVE-2016-2183 SWEET32). "
            "OpenSSL 1.0.1j is also affected by FREAK (CVE-2015-0204), POODLE "
            "(CVE-2014-3566), and numerous other OpenSSL 1.0.x vulnerabilities. "
            "15.2(7)E14 is the current release for 3560CX/2960L, so this is "
            "the best available firmware for these platforms - there is no patch."
        ),
        "openssl_version":  "OpenSSL 1.0.1j 15 Oct 2014 (both RC4 and AES module strings confirmed)",
        "weak_cipher_suites": [
            "AECDH-RC4-SHA (RC4 - broken, CVE-2015-2808)",
            "ADH-DES-CBC3-SHA (anonymous DH + 3DES)",
            "AECDH-DES-CBC3-SHA (anonymous ECDH + 3DES, SWEET32)",
        ],
        "platforms":    "3560CX (c3560cx-universalk9) and 2960L (c2960l-universalk9)",
        "impact": [
            "RC4 cipher suite active on SSL/TLS connections to switch web management",
            "3DES SWEET32: 32GB of traffic enables plaintext recovery of SSH/TLS sessions",
            "OpenSSL 1.0.1j: FREAK, POODLE, and 8+ years of unpatched vulnerabilities",
            "No patch path: 15.2(7)E14 is last supported release for 3560CX/2960L",
        ],
        "remediation": (
            "Disable RC4 and 3DES cipher suites in IOS: "
            "`ip ssh version 2`, `no ip ssh rsa keypair-name rsa1024`, "
            "`ip ssh modulus-size 2048`. "
            "For HTTPS management: `ip http secure-ciphersuite aes-128-cbc-sha aes-256-cbc-sha`. "
            "Accept that OpenSSL 1.0.1j is a permanent vulnerability in this image - "
            "migrate to Cat9K or other platforms with current OpenSSL if SSH/TLS security matters."
        ),
        "yara": """rule cisco_ios152_openssl_1_0_1j_legacy_ciphers {
    meta:
        description = "Classic IOS 15.2 ships OpenSSL 1.0.1j (EOL 2016) with RC4/3DES cipher suites"
        severity = "HIGH"
    strings:
        $openssl_ver  = "OpenSSL 1.0.1j 15 Oct 2014" ascii
        $rc4_suite    = "AECDH-RC4-SHA" ascii
        $3des_suite   = "ADH-DES-CBC3-SHA" ascii
    condition:
        $openssl_ver and ($rc4_suite or $3des_suite)
}""",
    },
    {
        "id": "F2",
        "title": "Smart Install Enabled by Default on 3560CX/2960L - TCP/4786 Unauthenticated RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-306",
        "description": (
            "IOS 15.2(7)E14 for the 3560CX and 2960L includes the Smart Install "
            "client (`Smart Install`, `Smart Installer`, `vstack` present in binary). "
            "Smart Install allows automatic configuration and image download from a "
            "Smart Install Director. The client listens on TCP port 4786 and accepts "
            "configuration and firmware update commands WITHOUT AUTHENTICATION. "
            "CVE-2018-0171 (CVSS 9.8) allows an unauthenticated remote attacker to "
            "reload the device, execute arbitrary code, or cause a denial of service "
            "by sending a crafted Smart Install message to TCP/4786. "
            "Smart Install is ENABLED BY DEFAULT on access layer switches. "
            "The remediation (`no vstack`) must be explicitly configured - "
            "factory-default switches are immediately exploitable on network access. "
            "Additionally, Smart Install directors can push arbitrary IOS images "
            "to clients - a compromised director = compromised fleet."
        ),
        "cve":          "CVE-2018-0171 (CVSS 9.8)",
        "port":         "TCP/4786",
        "affected":     "c3560cx-universalk9-mz.152-7.E14 and c2960l-universalk9-mz.152-7.E14",
        "binary_strings": [
            "Smart Install (Smart Install client binary component)",
            "Smart Installer",
            "vstack (Smart Install protocol name in IOS CLI)",
            "vstack basic, vstack director (director mode indicators)",
        ],
        "impact": [
            "Factory-default 3560CX/2960L: unauthenticated RCE on TCP/4786 from any network segment",
            "Smart Install director can push arbitrary firmware to all client switches",
            "Configuration download: director can push any IOS configuration including new passwords",
            "Affects entire 2960/3560 fleet worldwide (millions of deployed devices)",
        ],
        "remediation": (
            "Immediately: `no vstack` in global configuration. "
            "Block TCP/4786 at perimeter and on management VLAN ACLs. "
            "Run `show vstack status` to verify Smart Install is disabled. "
            "If Smart Install functionality is needed, use Smart Install Director "
            "with access control lists restricting which directors are trusted."
        ),
        "yara": """rule cisco_ios152_smart_install_default_enabled {
    meta:
        description = "Classic IOS 15.2 ships Smart Install enabled by default - CVE-2018-0171 unauthenticated RCE on TCP/4786"
        severity = "CRITICAL"
    strings:
        $smart_install = "Smart Install" ascii
        $vstack        = "vstack" ascii
        $vstack_basic  = "vstack basic" ascii
    condition:
        $smart_install and $vstack
}""",
    },
    {
        "id": "F3",
        "title": "Classic IOS 15.2 Default RSA Key Size = 1024 Bits - Below NIST SP 800-131A Minimum",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-326",
        "description": (
            "The IOS 15.2(7)E14 binary contains the default RSA key generation command "
            "`crypto key generate rsa general-keys modulus 1024`. "
            "RSA-1024 was deprecated by NIST in SP 800-131A (January 2011) and is "
            "disallowed for new usage since January 2024 (NIST SP 800-131A Rev 2). "
            "When SSH is enabled on a factory-default 3560CX or 2960L, the switch "
            "generates a 1024-bit RSA key pair unless explicitly overridden with "
            "`crypto key generate rsa modulus 2048` (or higher). "
            "The 1024-bit key is also used for SSL/TLS on the HTTPS management interface. "
            "1024-bit RSA is considered broken for long-term confidentiality "
            "(within reach of well-resourced attackers). "
            "Additionally, the ACT2 secure element is present on 3560CX for key storage "
            "(ACT2_RSA_KEYPAIR_OBJECT in the binary), but the default 1024-bit generation "
            "predates ACT2 key size guidance."
        ),
        "default_command": "crypto key generate rsa general-keys modulus 1024",
        "impact": [
            "Factory-default SSH key size = 1024 bits (NIST-disallowed since January 2024)",
            "HTTPS management interface uses 1024-bit RSA key by default",
            "ACT2 secure element present but default key size still 1024",
            "SSH host key fingerprints may be cached in network management tools - rekey needed",
        ],
        "remediation": (
            "`crypto key generate rsa modulus 2048` (or 4096 for long-term use). "
            "`ip ssh version 2` to disable SSHv1. "
            "Use `ip ssh dh min size 2048` to enforce 2048-bit DH minimum for key exchange. "
            "Consider EC keys: `crypto key generate ec keysize 256 label ecdsa_key`."
        ),
        "yara": """rule cisco_ios152_rsa_1024_default {
    meta:
        description = "Classic IOS 15.2 defaults to RSA-1024 key generation (NIST-disallowed since 2024)"
        severity = "MEDIUM"
    strings:
        $rsa_1024 = "crypto key generate rsa general-keys modulus 1024" ascii
        $act2     = "ACT2_RSA_KEYPAIR_OBJECT" ascii
    condition:
        $rsa_1024
}""",
    },
    {
        "id": "F4",
        "title": "Cat9K IOS-XE 17.18.04 NPE Initramfs Exposes 10 Internal Platform Codenames",
        "severity": "LOW",
        "cvss": 2.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-1059",
        "description": (
            "The Cat9K IOS-XE 17.18.04 NPE initramfs (CPIO archive at offset 0x9DEDCA) "
            "contains platform-specific directory trees with per-platform SELinux policies, "
            "binos application configurations, and startup scripts. "
            "The `platform-specific/` directory contains subdirectories for 10 distinct "
            "hardware platforms, revealing their internal codenames: "
            "discovery, intrepid, magic_carpet, scorpion, starfleet, nikka, bigbang, "
            "farscape, martian, symphony. "
            "These codenames are Cisco-internal hardware platform identifiers for "
            "different Cat9K switch/controller models. The codename mapping "
            "(e.g., scorpion = C9500, starfleet = likely C9800 WLC) gives insight "
            "into Cisco's hardware roadmap and platform branching. "
            "SELinux policies are per-platform, meaning each codename has a distinct "
            "security enforcement posture configured at factory."
        ),
        "initramfs_structure": {
            "format":    "gzip + CPIO newc (initramfs.x86_64.cat9k.ramfs.cpio)",
            "offset":    "0x9DEDCA in cat9k_iosxe_npe.17.18.04.SPA.bin",
            "arch":      "x86_64",
            "built":     "2026-07-18 17:52:53",
        },
        "platform_codenames": [
            "discovery  - access layer switch (C9200/C9300 family?)",
            "intrepid   - C9300L or similar compact switch",
            "magic_carpet - unknown platform",
            "scorpion   - C9500 (high-performance core switch)",
            "starfleet  - C9800 WLC (Wireless LAN Controller)?",
            "nikka      - unknown platform",
            "bigbang    - unknown platform (suggests new-generation hardware)",
            "farscape   - unknown platform",
            "martian    - unknown platform",
            "symphony   - unknown platform",
        ],
        "user_accounts": {
            "root":          "locked (*)",
            "binos":         "restricted shell (bshell.sh) at /usr/binos/conf/",
            "guestshell":    "locked (!), activated via CLI (guestshell enable)",
            "qemu":          "QEMU virtualization user (KVM/IOx VMs)",
            "dockeruser":    "Docker user (UID 1000000, namespace-mapped)",
            "limiteduser":   "restricted access user",
        },
        "impact": [
            "Platform codenames reveal Cisco internal hardware portfolio structure",
            "Per-platform SELinux policies: different enforcement postures across Cat9K variants",
            "Docker UID namespace mapping: dockeruser UID 1000000 confirms user namespace isolation",
            "guestshell locked by default but activatable via CLI = Python execution on network device",
        ],
        "guestshell_risk": (
            "Any user with EXEC-mode CLI access and `guestshell enable` permission "
            "gains a persistent Linux container (CentOS-based) with: "
            "Python 3.x, network tools, full access to Cat9K management interfaces, "
            "and the ability to make outbound network connections from the switch. "
            "A single misconfigured `privilege 15` account = Python reverse shell from the switch."
        ),
        "remediation": (
            "Disable guestshell if not needed: `no guestshell enable` globally. "
            "Restrict `guestshell` command to privilege-15 only and audit its use. "
            "Disable IOx (Docker/KVM) if not needed: `no iox`. "
            "Apply RBAC to prevent non-privileged users from running Linux containers on the switch."
        ),
        "yara": """rule cisco_cat9k_npe_initramfs_platform_codenames {
    meta:
        description = "Cat9K IOS-XE NPE initramfs exposes 10 internal platform codenames in platform-specific/ tree"
        severity = "LOW"
    strings:
        $magic_carpet = "magic_carpet" ascii
        $starfleet    = "starfleet" ascii
        $bigbang      = "bigbang" ascii
        $farscape     = "farscape" ascii
        $initramfs    = "initramfs.x86_64.cat9k.ramfs.cpio" ascii
    condition:
        2 of them
}""",
    },
]

FINDINGS.append(
    {
        "id": "F5",
        "title": "CGP-ONT Boa Web Server Runs as root (User 0) on TCP/80 - EOL Web Server on Fiber ONT",
        "severity": "HIGH",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-269",
        "description": (
            "The Cisco CGP-ONT-4P (fiber access ONT, version 1.1.3.18) runs Boa web server "
            "configured as `User 0` (root) on port 80. The Boa project was abandoned in 2005 "
            "and has not received security updates for 20+ years. "
            "Boa running as root means any vulnerability in the web server "
            "(path traversal, buffer overflow, CGI injection) immediately yields a root shell. "
            "The device also runs Linux 4.4.140, which went EOL in February 2022. "
            "The CGP-ONT additionally includes Samba (SMB file sharing) and WPS daemon "
            "(wscd.conf), creating unusual attack surface for what should be a simple fiber terminal. "
            "Firmware integrity check uses only MD5 checksums stored in the same tar archive "
            "as the firmware - an attacker serving a malicious firmware bundle just needs to "
            "include a matching md5.txt to bypass all integrity checking (no digital signature). "
            "The internal codename is `luna`; the update framework is `YueMe`."
        ),
        "boa_config": {
            "port":    "80",
            "user":    "0 (root)",
            "version": "Boa (EOL 2005, ~20 years of unpatched vulnerabilities)",
        },
        "firmware_integrity": {
            "method":    "MD5 checksum comparison against bundled md5.txt",
            "signature": "NONE - no digital signature on firmware payload",
            "exploit":   "Serve attacker firmware + matching md5.txt = accepted as valid",
        },
        "additional_services": [
            "Samba (smb.conf): file sharing on a fiber ONT - unusual attack surface",
            "WPS daemon (wscd.conf): Wi-Fi Protected Setup potentially enabled",
            "dnsmasq: DNS/DHCP server",
        ],
        "linux_kernel": "4.4.140 (EOL February 2022 - critical CVEs unpatched including Dirty COW CVE-2016-5195)",
        "impact": [
            "Boa RCE (any known CVE) = immediate root shell on fiber ONT",
            "Firmware update MITM: attacker-served firmware passes MD5 integrity check",
            "EOL kernel: Dirty COW and post-2022 Linux 4.4 CVEs all unpatched",
            "Samba + Boa-as-root: multiple root-reachable network attack surfaces",
        ],
        "remediation": (
            "Replace Boa with a maintained web server (lighttpd, nginx). "
            "Run web server as non-root with capability-based port binding. "
            "Add digital signature (RSA-2048 or ECDSA-P256) to firmware update process. "
            "Update to a supported Linux kernel. Remove Samba if not needed."
        ),
        "yara": """rule cisco_cgp_ont_boa_root_no_sig_firmware {
    meta:
        description = "CGP-ONT Boa web server runs as root, firmware has MD5-only integrity (no signature)"
        severity = "HIGH"
    strings:
        $luna_fwu    = "luna firmware upgrade" ascii
        $boa_user0   = "User 0" ascii
        $yueme       = "YueMe" ascii
        $md5_only    = "md5.txt" ascii
    condition:
        $luna_fwu or ($boa_user0 and $md5_only)
}""",
    }
)

SUMMARY = {
    "total":    5,
    "critical": 1,
    "high":     2,
    "medium":   1,
    "low":      1,
    "note":     (
        "Classic IOS 15.2(7)E14 has permanent security debt (no patch path): "
        "Smart Install on TCP/4786 (F2 CRITICAL, CVE-2018-0171), "
        "OpenSSL 1.0.1j (F1 HIGH), RSA-1024 default (F3 MEDIUM). "
        "Cat9K IOS-XE 17.18.04 NPE is significantly more secure: "
        "PKCS7/SHA-512 signing, SELinux per platform, locked root, Docker/guestshell "
        "isolated but activatable via CLI (F4 LOW). "
        "cat9k_iosxe.17.18.04.SPA.bin (full K9 variant) not independently analyzed "
        "- expected to have same structure plus export-controlled crypto features."
    ),
}
