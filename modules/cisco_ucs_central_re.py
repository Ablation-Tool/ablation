"""
Cisco UCS Central RE Module 1: Versions 1.5.1c and 2.1.2b_EVAL
ISOs: ucs-central.1.5.1c.iso (1.1GB), ucs-central.1.5.1c.ova (1.4GB),
      ucs-central-passreset.1.5.1c.iso (146MB), ucs-central.2.1.2b_EVAL.iso (4.2GB)
Platform: UCS Central management appliance; manages multiple UCSM domains

7 findings: 0C/2H/2M/3L
Cumulative: 594 [54C+190H+180M+167L]
"""

# ============================================================
# TARGET
# ============================================================

UCSC_TARGET = {
    "platform": "UCS Central",
    "purpose": "Centralized management plane for multiple UCS Manager domains",
    "versions_surveyed": ["1.5.1c", "2.1.2b_EVAL"],
    "install_method": "kickstart-based RHEL/AlmaLinux installer ISO",
    "1.5.1c_os": "RHEL 5 (el5)",
    "2.1.2b_os": "AlmaLinux 9 (el9)",
    "upgrade_path": "RHEL5 -> AlmaLinux9 across 2 major versions",
}

# ============================================================
# CREDENTIAL ANALYSIS
# ============================================================

KICKSTART_CREDENTIALS = {
    "1.5.1c": {
        "file": "ks.cfg",
        "rootpw_hash": "$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
        "hash_algo": "MD5-crypt ($1$)",
        "hash_algo_note": "MD5-crypt is deprecated; crackable via hashcat/john on modern GPU in hours",
        "crack_attempt": "common Cisco defaults not matched; requires targeted wordlist/bruteforce",
        "selinux": "disabled",
        "firewall": "enabled, port 22/tcp only",
        "timezone": "America/Los_Angeles",
        "upgrade_ks": "ks_upgrade.cfg -- same rootpw hash; selinux disabled",
        "passreset_ks": "upgrade type; minimal config (no rootpw entry visible)",
    },
    "2.1.2b": {
        "file": "kickstart.cfg",
        "rootpw_hash": "$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
        "hash_algo": "bcrypt cost-10 ($2b$10$)",
        "cisco_user_hash": "$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
        "cisco_user_groups": "wheel",
        "root_cisco_identical": True,
        "hostname": "csl-almalinux9",
        "timezone": "America/New_York",
        "bootloader_append": "rhgb quiet crashkernel=auto",
    },
}

# ============================================================
# LEGACY SOFTWARE STACK (1.5.1c / RHEL 5)
# ============================================================

RHEL5_STACK = {
    "os_version": "RHEL 5 (el5), EOL March 2017",
    "kernel": "2.6.18-406.el5.x86_64 (RHEL5; kernel 2.6.18 original 2006)",
    "openssl": "0.9.8e-40.el5_11 (CVE-2014-0224/POODLE/DROWN-era; 2007 base)",
    "openssh": "6.6p1-2 (2014 release; CVE-2016-0777/0778 timing-based RSA info)",
    "glibc": "2.5-123.el5_11.1 (ancient)",
    "curl": "7.15.5-17.el5_9 (2006 era)",
    "postgresql": "8.4.20-1.el5_10 (PostgreSQL 8.4 EOL July 2014)",
    "nss": "3.18.0-6.el5_11",
    "selinux_state": "disabled in kickstart",
    "note": (
        "UCS Central 1.5.1c is still in Cisco's support matrix as of 2025. "
        "The entire OS stack is RHEL5-era (EOL 2017). "
        "OpenSSL 0.9.8e predates Heartbleed (CVE-2014-0160 fixed in 1.0.1g); "
        "0.9.8e is vulnerable to CVE-2014-0224 (CCS injection) and SSLv3 POODLE. "
        "The el5_11 patch level applies RHEL5 backports but the 0.9.8 series itself "
        "is fundamentally limited in modern TLS support."
    ),
}

ALMALINUX9_STACK = {
    "os_version": "AlmaLinux 9 (el9)",
    "libcrypto": "libcrypto.so.1.1 bundled in ucsCentral/ directory (OpenSSL 1.1.x)",
    "libsafelibc": "libsafelibc.so -- Cisco safe C library (memcpy_s, memcpy16_s, memcpy32_s)",
    "libosc": "libosc.so -- Cisco OSC (Orchestration/Service Controller) library",
    "upgrade": "significant security improvement from RHEL5 base",
}

# ============================================================
# BUILD ARTIFACTS LEAKED TO ISO
# ============================================================

BUILD_ARTIFACTS = {
    "2.1.2b": {
        "sign-rpm-out.log": "RPM signing timing log: 'Time taken: 0.8233715333333333 mins'",
        "sign-rpm-err.log": "RPM signing error log: present but empty (no errors)",
        "implication": (
            "Build system artifacts (rpm signing logs) included in production ISO. "
            "Confirms RPM signing process runs during ISO creation. "
            "Empty error log means all RPMs signed successfully. "
            "Timestamp format suggests Python-based build tooling."
        ),
    },
}

# ============================================================
# IMGHDR UTILITY (BOTH VERSIONS)
# ============================================================

IMGHDR_BINARY = {
    "1.5.1c": {
        "file": "ucsCentral/imghdr",
        "type": "ELF 32-bit LSB executable, Intel 80386",
        "kernel": "for GNU/Linux 2.4.17",
        "stripped": False,
        "debug_info": True,
        "capabilities": [
            "generate NX-OS image headers",
            "publickeygen -- generates RSA public keys",
            "privatekey -- private key operations",
            "img_version -- image version metadata",
        ],
        "copyright": "Copyright (c) 2002-2009 by Cisco Systems, Inc.",
        "format_string": "Cisco NX-OS(tm) %s, Software (%s), Version %s, RELEASE SOFTWARE",
        "note": "NX-OS image signing/header tool shipped with UCS Central; NOT stripped",
    },
    "2.1.2b": {
        "file": "ucsCentral/imghdr",
        "type": "ELF 32-bit LSB shared object, Intel 80386",
        "kernel": "for GNU/Linux 3.1.0",
        "stripped": False,
        "debug_info": True,
        "note": "Repackaged as shared object but still NOT stripped with debug info",
    },
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "UCSC-F1",
        "severity": "HIGH",
        "title": "HARDCODED_MD5CRYPT_ROOT_PASSWORD_IN_1_5_1c_PRODUCTION_KICKSTART",
        "detail": (
            "UCS Central 1.5.1c ks.cfg and ks_upgrade.cfg both contain: "
            "'rootpw --iscrypted $1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/'. "
            "Algorithm: MD5-crypt ($1$), deprecated for security. "
            "Every UCS Central 1.5.1c installation uses this hash as the initial root password. "
            "The hash is derivable by any party with access to the ISO. "
            "MD5-crypt is crackable at ~10M hashes/sec on a modern GPU. "
            "UCS Central 1.5.1c is still in Cisco's support matrix (not EOL as of 2025). "
            "A successful crack gives root access to the UCS Central management plane, "
            "which controls all UCSM domains it manages (service profiles, firmware policies, "
            "network/storage zoning, compute policies for potentially thousands of servers)."
        ),
    },
    {
        "id": "UCSC-F2",
        "severity": "HIGH",
        "title": "ROOT_AND_CISCO_WHEEL_USER_SHARE_IDENTICAL_BCRYPT_HASH_IN_2_1_2b_KICKSTART",
        "detail": (
            "UCS Central 2.1.2b kickstart.cfg assigns the same bcrypt hash to both root "
            "and the 'cisco' user: "
            "$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu. "
            "The 'cisco' user is in the 'wheel' group (sudo access). "
            "Two consequences: (1) cracking either account password gives immediate escalation path "
            "to both unprivileged and root access simultaneously; "
            "(2) password change policy that updates one account must update both independently, "
            "or they diverge. "
            "The hash is bcrypt cost-10 ($2b$10$) -- stronger than MD5-crypt but still "
            "extractable from the ISO and crackable offline at ~4k hashes/sec on a modern GPU. "
            "Internal hostname: 'csl-almalinux9' (hardcoded in kickstart network config). "
            "UCS Central 2.1.2b runs on AlmaLinux 9 -- significant security upgrade from 1.5.1c's RHEL5."
        ),
    },
    {
        "id": "UCSC-F3",
        "severity": "MEDIUM",
        "title": "UCS_CENTRAL_1_5_1c_RHEL5_EOL_STACK_OPENSSL_0_9_8e_POSTGRESQL_8_4_CURL_7_15",
        "detail": (
            "UCS Central 1.5.1c installs on RHEL 5 (EOL March 2017) with: "
            "kernel 2.6.18-406.el5 (original 2006 kernel series, RHEL5 backport patches), "
            "OpenSSL 0.9.8e-40.el5_11 (2007 base; vulnerable to CCS injection CVE-2014-0224, "
            "SSLv3 POODLE CVE-2014-3566; el5_11 backport does NOT upgrade to 1.x API), "
            "PostgreSQL 8.4.20-1 (EOL July 2014; no official security updates post-EOL), "
            "curl 7.15.5-17.el5_9 (2006 era curl), "
            "glibc 2.5-123.el5_11.1 (ancient). "
            "SELinux is disabled in kickstart: 'selinux --disabled'. "
            "UCS Central 1.5.1c is still in Cisco's support matrix; "
            "the underlying OS stack will not receive RHEL5 security updates (EoL)."
        ),
    },
    {
        "id": "UCSC-F4",
        "severity": "MEDIUM",
        "title": "BUILD_ARTIFACTS_SIGN_RPM_LOGS_PRESENT_ON_PRODUCTION_2_1_2b_ISO",
        "detail": (
            "UCS Central 2.1.2b_EVAL.iso contains two build system log files at ISO root: "
            "'sign-rpm-out.log' (content: 'Time taken: 0.8233715333333333 mins') and "
            "'sign-rpm-err.log' (present but empty). "
            "These are artifacts from the RPM signing step of the ISO build process. "
            "Leaked information: the RPM signing process runs as a timed step (Python floats), "
            "all RPMs signed without errors, and the build toolchain uses Python. "
            "The 'EVAL' suffix in the ISO name suggests this may be an evaluation/pre-release build "
            "where build artifact cleanup was incomplete. "
            "If a production ISO carries these artifacts, they confirm the internal build pipeline."
        ),
    },
    {
        "id": "UCSC-F5",
        "severity": "LOW",
        "title": "IMGHDR_NXOS_IMAGE_HEADER_TOOL_NOT_STRIPPED_WITH_DEBUG_INFO_IN_BOTH_VERSIONS",
        "detail": (
            "ucsCentral/imghdr -- Cisco NX-OS image header generation utility -- ships with "
            "full debug symbols and not stripped in both 1.5.1c and 2.1.2b. "
            "1.5.1c: ELF 32-bit LSB executable, for GNU/Linux 2.4.17, debug_info, not stripped. "
            "2.1.2b: ELF 32-bit LSB shared object, for GNU/Linux 3.1.0, debug_info, not stripped. "
            "imghdr generates Cisco NX-OS image headers with embedded version metadata, "
            "and performs publickeygen/privatekey operations for image signing. "
            "Its copyright: 'Copyright (c) 2002-2009 by Cisco Systems, Inc.' "
            "Full debug symbols in a key generation/image signing utility reveal internal structure, "
            "data layout, and cryptographic implementation details."
        ),
    },
    {
        "id": "UCSC-F6",
        "severity": "LOW",
        "title": "UCSC_1_5_1c_SELINUX_DISABLED_AND_KEY_SKIP_IN_PRODUCTION_KICKSTART",
        "detail": (
            "UCS Central 1.5.1c kickstart: 'selinux --disabled' and 'key --skip' (no product key). "
            "SELinux disabled means no MAC (Mandatory Access Control) on the management appliance. "
            "Any local process compromise (via the RHEL5-era stack) achieves full DAC-only security, "
            "no SELinux policy constraints on sensitive file access. "
            "key --skip bypasses RHEL product activation -- consistent with Cisco OEM licensing. "
            "Both ks.cfg and ks_upgrade.cfg carry these settings."
        ),
    },
    {
        "id": "UCSC-F7",
        "severity": "LOW",
        "title": "INTERNAL_HOSTNAME_CSL_ALMALINUX9_HARDCODED_IN_2_1_2b_NETWORK_CONFIG",
        "detail": (
            "UCS Central 2.1.2b kickstart network stanza: "
            "'network --hostname=csl-almalinux9 --onboot=yes --ipv6=auto --bootproto=dhcp'. "
            "'csl-almalinux9' is the production default hostname shipped to all 2.1.2b installations. "
            "'csl' prefix likely = Cisco CSL (Central Services Layer or Cisco Systems Ltd). "
            "Hardcoded default hostname in management appliance allows network fingerprinting: "
            "a DHCP lease or DNS entry for 'csl-almalinux9' is a UCS Central 2.1.2b instance. "
            "DHCP mode ('--bootproto=dhcp') and IPv6 auto ('--ipv6=auto') "
            "are also hardcoded defaults."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_central_re",
    "isos": [
        "ucs-central.1.5.1c.iso",
        "ucs-central-passreset.1.5.1c.iso",
        "ucs-central.2.1.2b_EVAL.iso",
    ],
    "finding_counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 2, "LOW": 3},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 190, "MEDIUM": 180, "LOW": 167},
    "cumulative_total": 594,
    "root_password_hashes": {
        "1.5.1c_md5crypt": "$1$ToWcsC4R$XaYfvve4hPK/EhCIEuXlE/",
        "2.1.2b_bcrypt10": "$2b$10$Nh35Lu0kG2DvtgQAaeRwzueRI.3zg3RgXoZcX3cdNKjw2pyldLlmu",
    },
    "key_insight": (
        "Both UCS Central versions ship hardcoded root password hashes in kickstart files. "
        "1.5.1c uses weak MD5-crypt on RHEL5 EoL stack. "
        "2.1.2b upgraded to AlmaLinux9 with bcrypt-10 but root and wheel-user share identical hash. "
        "Management plane access = multi-domain UCSM fabric control."
    ),
}
