"""
Cisco IP Conference Phone 8831 SIP RE Module
Target: cmterm-8831-sip.10-3-1SR7-2-NA.zip
Model: CP-8831 conference phone (single-chip, wired)
Architecture: TI OMAP-L138 ARM926EJ-S + C674x DSP, Linux 2.6.37+, EXT2 rootfs
Version: SIP 10.3.1SR7-2-NA; signed 2021-04-15
Source: /media/cowboy/research/Cisco-IP PHONE/

This is the legacy SIP firmware line (not MPP). Completely different stack from
the 88xx/8832/78xx MPP phones. Uses TI OMAP-L138 SoC (ARM + DSP), Linux 2.6.37+
kernel, EXT2 rootfs in a gzip-wrapped Cisco signed SBN format.

SBN format (DIFFERENT from MPP SBN formats):
  All 4 files share magic: 01 00 02 01 01 02 00 02
  Filename string at offset 0x180 (e.g. kern8831.10-3-1SR7-2-NA.sbn)
  Signed with placeholder CN=someSigner;OU=someOrgUnit;O=someOrg (not a real CA)
  Payload format varies per file:
    .loads:  manifest/metadata wrapped in SBN signature
    sboot:   second-stage bootloader in SBN
    kern:    uImage at 0x1bc (Linux 2.6.37+, ARM, uncompressed, load 0xC0008000)
    rootfs:  gzip-wrapped EXT2 filesystem at 0x1c0 (32MB, 8192 inodes)

Kernel details:
  uImage at 0x1bc: Linux-2.6.37+
  Built: 2020-07-29 (ih_time 0x5f219af4)
  Arch: ARM (ih_arch=2)
  Type: kernel (ih_type=2)
  Compression: none (ih_comp=0)
  Load/Entry: 0xC0008000 (standard ARM physical memory)
  Size: 1330492 bytes

Rootfs details:
  gzip stream at 0x1c0 (filename: rootfs.ext2)
  Decompressed: 33554432 bytes = 32 MB EXT2 filesystem
  EXT2: 8192 inodes, 32768 blocks of 1024 bytes
  Creation: 2021-04-15 12:31

Hardware (leaked from fixsshd debug info):
  SoC: TI OMAP-L138 (ARM926EJ-S 300MHz + TMS320C674x DSP)
  SDK: ti-dvsdk_omapl138-evm_04_03_00_06 (OE arago toolchain)
  GCC: 4.3.3 (arago ARM toolchain, ARM926EJ-S target)
  Build host: conli@[hostname] (dev-beignet-2014MR project)

JFFS2 partition:
  /dev/mtdblock12 (or /dev/mtdblock11 fallback) mounted to /usr/local at boot via S45Revo
  Persistent config lives on JFFS2: /usr/local/etc/, /usr/local/backtraces/, /usr/local/syslog
  SSH config (for xinetd) is in /usr/local/etc/sshd (written by fixsshd binary at runtime)

Extraction:
  python3 -c "import gzip,io; ... " to dump EXT2 from gzip at offset 0x1c0
  debugfs -R 'cat /etc/passwd' rootfs8831.ext2
"""

METADATA = {
    "target":      "Cisco IP Conference Phone 8831 SIP 10.3.1SR7-2-NA",
    "model":       "CP-8831 conference phone (wired, single-chip, legacy SIP firmware line)",
    "platform":    "TI OMAP-L138 (ARM926EJ-S + C674x DSP), Linux 2.6.37+, EXT2",
    "built":       "2021-04-15 (SBN signing date); kernel built 2020-07-29",
    "soc":         "TI OMAP-L138 -- ARM926EJ-S 300MHz + TMS320C674x DSP (revealed in fixsshd build paths)",
    "sbn_format": {
        "magic":   "01 00 02 01 01 02 00 02 (different from MPP formats -- no cd 34 12 ab)",
        "cert_cn": "CN=someSigner;OU=someOrgUnit;O=someOrg (placeholder cert, not a real CA)",
        "kernel":  "uImage at 0x1bc in kern SBN",
        "rootfs":  "gzip at 0x1c0 in rootfs SBN (decompresses to raw EXT2 image)",
    },
    "accounts": {
        "root":  "djy5v.K9zLem2 (DES-crypt, 13 chars, not locked -- password not confirmed)",
        "debug": "qeFvMkbKo65tk (DES-crypt, 13 chars, ACTIVE -- password: debug, shell: /usr/sbin/debugsh)",
    },
    "ssh_model": "SSH disabled in S45Revo startup (commented out); managed by fixsshd binary + xinetd; config in JFFS2 /usr/local/etc/sshd",
    "no_beuid_pattern": "8831 uses legacy startup model -- no BEUID=app:services/root:root pattern; services run as root implicitly",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "debug:debug Account Active (DES-crypt) with debugsh Shell -- Same Password as Fleet-Wide 14.4.1 Regression",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The 8831 SIP 10.3.1SR7-2 EXT2 rootfs contains an active debug account: "
            "`debug:qeFvMkbKo65tk` (DES-crypt format), password `debug`, "
            "shell `/usr/sbin/debugsh`. "
            "The password was confirmed by DES-crypt verification against the hash. "
            "The same password (`debug`) was found across all 14.4.1 MPP firmware families "
            "stored as MD5-crypt (`$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71`). "
            "The 8831 uses DES-crypt (13-character hash, `qe` salt) instead of MD5-crypt -- "
            "a different hash format but the same credential value. "
            "DES-crypt is significantly weaker than MD5-crypt: "
            "limited to 8-character passwords, single DES iteration, "
            "and brute-forceable at ~10^9 attempts/second on consumer hardware. "
            "The debugsh binary (162KB, ELF ARM) provides the same interactive debug shell "
            "documented in cisco_88xx_14_mpp_re.py F1 for the MPP 14.4.1 firmware. "
            "The 8831 debug account represents the same Cisco-wide debug credential pattern "
            "but predating the MPP 14.4.1 regression -- the debug:debug credential existed "
            "in the SIP firmware line well before the 14.4.1 MPP deployment."
        ),
        "hash":         "qeFvMkbKo65tk (DES-crypt, salt 'qe')",
        "password":     "debug (confirmed by DES-crypt verification)",
        "vs_mpp_14_4_1": "Same password 'debug', different hash format (DES-crypt vs MD5-crypt $1$)",
        "hash_weakness": "DES-crypt: 8-char max, single iteration, ~10^9/s GPU brute-force",
        "impact": [
            "SSH login as debug:debug if SSH is enabled on the phone",
            "debugsh shell provides btcli, cipcfg, netstat, system() access",
            "DES-crypt hash crackable significantly faster than MD5-crypt",
        ],
        "remediation": "Lock debug account with `!` hash and change shell to /bin/false or /sbin/nologin.",
    },
    {
        "id": "F2",
        "title": "root Account Has Active DES-crypt Hash -- Not Locked Despite Shell /sbin/nologin",
        "severity": "HIGH",
        "cvss": 7.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-521",
        "description": (
            "The root account has an active DES-crypt password hash `djy5v.K9zLem2` "
            "in /etc/shadow (shadow age 15732 days = approximately 2013-01-24). "
            "While the login shell is `/sbin/nologin`, the active hash means the password "
            "is set and potentially usable in contexts that bypass nologin "
            "(PAM su, sudo without requiretty, SUID application bugs). "
            "This contrasts with the MPP firmware families which lock root with `!` "
            "in both 12.0.7 and 14.4.1. "
            "The password was not recovered from a short candidate list; "
            "it may be a device-specific or model-specific value. "
            "DES-crypt passwords are limited to 8 characters and can be brute-forced "
            "at high speed on GPU hardware -- a full 8-character keyspace attack "
            "is feasible in hours to days."
        ),
        "hash":     "djy5v.K9zLem2 (DES-crypt, salt 'dj', age 15732 = ~2013-01-24)",
        "shell":    "/sbin/nologin (no direct login, but hash is active for PAM/su contexts)",
        "vs_mpp":   "MPP firmware locks root with ! -- 8831 SIP has an actual password set",
        "impact": [
            "Active root hash enables password crack attempts",
            "DES-crypt format: full 8-char brute-force feasible on GPU hardware",
            "If cracked: su/sudo escalation to root from any shell session",
        ],
        "remediation": "Replace DES-crypt hash with `!` or `*` to lock the root account unconditionally.",
    },
    {
        "id": "F3",
        "title": "fixsshd Binary Modifies JFFS2-Mounted SSH Config at Runtime via system() -- Writes Writable NAND",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-377",
        "description": (
            "The `fixsshd` binary (10608 bytes, ARM ELF, not stripped, compiled with GCC 4.3.3 2009) "
            "is an SSH configuration patcher. "
            "It reads `/usr/local/etc/sshd` (xinetd sshd config on JFFS2-mounted NAND partition), "
            "writes a modified version to `/tmp/sshd.tmp`, then uses `system()` "
            "to call `kill -SIGHUP <pidof xinetd>` to reload the configuration. "
            "The JFFS2 partition at `/dev/mtdblock12` (or `/dev/mtdblock11` fallback) "
            "is mounted at `/usr/local` by `S45Revo` during boot. "
            "This partition is writable: if an attacker can write to `/usr/local/etc/sshd` "
            "(via another vulnerability), they can modify the SSH service configuration "
            "persistently across reboots (JFFS2 is persistent on-NAND). "
            "The `fixsshd` binary leaks its build origin: "
            "`/home/conli/workspace/dev-beignet-2014MR/testapps/fixsshd/src/main.c` "
            "and the ODM toolchain `ti-dvsdk_omapl138-evm_04_03_00_06` (TI OMAP-L138 EVM SDK). "
            "The SSH configuration managed by fixsshd sets `server_args = /usr/sbin/sshd -i`, "
            "enabling SSH on demand via xinetd. "
            "SSH is commented out in the main `S45Revo` startup script, "
            "suggesting it is conditionally enabled based on device configuration."
        ),
        "binary":       "fixsshd (10608 bytes, ARM ELF, not stripped, GCC 4.3.3)",
        "ssh_config":   "/usr/local/etc/sshd on JFFS2 (/dev/mtdblock12) -- writable and persistent",
        "build_leak":   "/home/conli/workspace/dev-beignet-2014MR/testapps/fixsshd/src/main.c",
        "sdk_leak":     "ti-dvsdk_omapl138-evm_04_03_00_06 (TI OMAP-L138 EVM SDK -- confirms SoC)",
        "impact": [
            "JFFS2 config writable by any root process: persistent SSH config modification",
            "fixsshd uses system() with SIGHUP: insecure SSH reload mechanism",
            "Build path leaks: developer identity + TI OMAP-L138 SoC + ODM project name",
        ],
        "remediation": (
            "Make /usr/local/etc/sshd world-read-only or owned by root:root 0400. "
            "Replace system() + kill with direct xinetd reload API."
        ),
    },
    {
        "id": "F4",
        "title": "TI OMAP-L138 SoC + Linux 2.6.37+ EOL Kernel in Production 2021 -- fixsshd Build Path Leak",
        "severity": "LOW",
        "cvss": 3.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "Multiple information disclosures and an EOL kernel in production: "
            "(1) The fixsshd binary's debug symbols confirm the hardware SoC: "
            "TI OMAP-L138 (ARM926EJ-S ARM + TMS320C674x DSP), "
            "built with the TI OMAP-L138 EVM SDK (`ti-dvsdk_omapl138-evm_04_03_00_06`). "
            "The arago toolchain path `/OE/arago-tmp/work/armv5te-arago-linux-gnueabi/glibc-2.9-r37.4` "
            "reveals ARMv5TE target and glibc 2.9. "
            "Developer home directory leaked: `/home/conli/workspace/dev-beignet-2014MR/`. "
            "(2) The kernel image is `Linux-2.6.37+`, built 2020-07-29. "
            "Linux 2.6.37 reached end-of-life in 2011 (upstream support ended). "
            "This kernel was still being shipped in production 2021-signed firmware. "
            "Known vulnerabilities affecting 2.6.37: CVE-2016-5195 (Dirty COW, local root), "
            "multiple privilege escalation and memory disclosure issues. "
            "(3) The Cisco signed SBN wrapper uses a placeholder certificate "
            "`CN=someSigner;OU=someOrgUnit;O=someOrg` rather than a real Cisco CA -- "
            "the SBN signature provides structural integrity but not chain-of-trust verification "
            "against a real Cisco PKI root. "
            "(4) The `dsplinkk.ko` kernel module is loaded at boot for TI DSP Link "
            "(ARM-DSP communication), revealing the DSP co-processor usage for media processing."
        ),
        "soc":           "TI OMAP-L138 (ARM926EJ-S 300MHz + TMS320C674x DSP)",
        "kernel":        "Linux 2.6.37+ (EOL 2011, in production 2021)",
        "cve_exposure":  "CVE-2016-5195 Dirty COW (local root), multiple 2.6.37 privilege escalations",
        "gcc":           "4.3.3 (arago ARM toolchain, ARMv5TE, glibc 2.9)",
        "sbn_cert":      "CN=someSigner (placeholder -- not a real Cisco PKI cert)",
        "build_leak":    "conli@[host] /home/conli/workspace/dev-beignet-2014MR/",
        "impact": [
            "Linux 2.6.37+ EOL: Dirty COW (CVE-2016-5195) applicable if local shell access obtained",
            "SoC identification aids hardware security analysis and JTAG/UART attack planning",
            "Placeholder SBN cert: structural signature only, no chain-of-trust verification",
        ],
        "remediation": "Upgrade to supported Linux kernel. Replace placeholder SBN cert with Cisco PKI.",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 1,
    "high":     1,
    "medium":   1,
    "low":      1,
    "platform_note": (
        "8831 SIP is architecturally distinct from the MPP phone families: "
        "TI OMAP-L138 SoC (ARM926EJ-S + DSP), Linux 2.6.37+, EXT2 rootfs, "
        "gzip-wrapped in Cisco SBN signed format (placeholder cert). "
        "No apigateway (MPP-specific). No BEUID privilege model. "
        "Legacy SIP firmware from a different ODM team (beignet-2014MR project, conli developer). "
        "debug:debug credential predates the MPP 14.4.1 regression -- "
        "the same password was in the SIP line before being embedded in MPP 14.4.1."
    ),
    "format_note": (
        "SBN magic 01 00 02 01 01 02 00 02 with CN=someSigner placeholder cert. "
        "rootfs: gzip-wrapped EXT2 (32MB) at offset 0x1c0 in SBN. "
        "kern: uImage at offset 0x1bc in SBN. "
        "First filesystem format seen that is neither SquashFS nor UBI in this RE set."
    ),
}
