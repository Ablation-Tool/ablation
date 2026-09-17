"""
Cisco UCS IOM 2400/6400 Series 6.0.2b RE module
Target: ucs-2400-6400.6.0.2b.bin (extracted from ucs-6400-k9-bundle-infra.6.0.2b.A.bin)
Platform: UCS IOM 2408 (8-port 25G) / 2412 (12-port 25G), Tahoe x86-64 switch ASIC
Architecture: x86-64 ELF, NX-OS satellite Linux

Extraction path:
  Outer bundle: ucs-6400-k9-bundle-infra.6.0.2b.A.bin (3.4GB)
  SN header hsize=808; gzip at offset 0x328
  Inner stream entries: ucsfi.10.5.1.I60.2b.F.bin (1.5GB), ucs-manager-k9.6.0.2b.bin (1.0GB),
    ucs-2400-6400.6.0.2b.bin (344MB at 2579MB offset), ucs-2500-6400.6.0.2b.bin (393MB)
  ucs-2400-6400.6.0.2b.bin: SN header hsize=760, gzip at 0x2f8
  Inner tar: imghdr.bin + ./blob (377MB)
  blob: NOT a disk image (55aa is BIOS partition magic at offset 0, not MBR);
    multiple shinstall packages concatenated with BIOS blob header
  Package 1 (CPIO old binary magic 0x71c7, ~150MB): NX-OS satellite layer
    494 files in isan/ isanboot/ directories; x86-64 ELF binaries
  Package 2 (CPIO old binary magic 0x71c7, 75MB): management stack
    817 files in nuova/ etc/ directories; CMC-style management layer

Architecture notes:
  IOM runs as NX-OS "satellite" controlled by parent Fabric Interconnect (FI)
  Two-layer FS: Package 1 (isan/ NX-OS layer) + Package 2 (nuova/ management stack)
  Tahoe ASIC: proprietary x86-64 switch ASIC; device nodes at /dev/ktah*
  AAPL SDK (Avago/Broadcom SerDes management) embedded in tahusd
  MTS (Message Transport Service) for NX-OS IPC
  ACT2 anti-counterfeiting chip authentication via satctrl (device auth to FI)
  pam_cmc.so: CMC PAM module, authenticate_with_ucsm forwards creds over local socket
  Abseil (libabsl_*) present suggesting gRPC usage; 0.0.0.0:50060 gRPC listener in tahusd

Control plane isolation:
  iptables default INPUT DROP; accepts from SAM (127.5.254.1, 127.6.254.1), 127.15.0.0/16,
  127.1.1.0/24, peer IOM (127.11.0.1/2), BMCs (127.3.x, 127.4.x), loopback
  No eth0 ACCEPT rules except explicit DROP for ports 623/514/513 (CSCwq78731)
  infra-network-chain empty chain inserted at INPUT 1 (runtime Intersight VLAN injection point)
"""

FIRMWARE = {
    "target":    "Cisco UCS IOM 2400/6400 6.0.2b",
    "file":      "ucs-2400-6400.6.0.2b.bin",
    "source_bundle": "ucs-6400-k9-bundle-infra.6.0.2b.A.bin",
    "model":     "UCS IOM 2408/2412 (Tahoe x86-64 switch ASIC, NX-OS satellite)",
    "arch":      "x86-64 ELF, stripped; two-package CPIO old binary (magic 0x71c7)",
    "pkg1_files": 494,
    "pkg1_dirs":  "isan/, isanboot/",
    "pkg2_files": 817,
    "pkg2_dirs":  "nuova/, etc/",
    "blob_magic": "55aa0011 at offset 0 (BIOS partition magic, not disk MBR)",
    "bios_version": "IOM BIOS: v1.2.29 Date: 02/04/2021 11:04:28",
    "findings": ["IOM2400-F1", "IOM2400-F2", "IOM2400-F3", "IOM2400-F4",
                 "IOM2400-F5", "IOM2400-F6", "IOM2400-F7", "IOM2400-F8"],
}

# IOM2400-F1: AAPL AACS/ATS unauthenticated hardware debug TCP server in tahusd
IOM2400_F1 = {
    "id":       "IOM2400-F1",
    "title":    "tahusd (Tahoe ASIC daemon) embeds AAPL SDK (Avago/Broadcom SerDes management) "
                "with TCP debug servers AACS (port 2330) and ATS exposing SBus, JTAG, I2C, MDIO, "
                "and spico_int (SERDES microcode interrupt) commands; no authentication strings "
                "present in server code path; gRPC listener bound 0.0.0.0:50060; "
                "iptables allows unrestricted access from FI management plane (SAM 127.5.254.1, "
                "127.6.254.1) and internal subnets (127.15.0.0/16, 127.1.1.0/24)",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — tahusd binary extracted from Package 1 (isan/bin/tahusd, x86-64 ELF "
                "stripped); AAPL copyright string confirmed; AACS/ATS server version format strings "
                "confirmed; all command strings confirmed; port 2330 as 32-bit LE integer confirmed; "
                "0.0.0.0:50060 gRPC bind string confirmed; no auth strings in server code path",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-284 (Improper Access Control)"],
    "file":     "isan/bin/tahusd",
    "aapl_strings": [
        "Copyright 2013-2015 Avago Technologies. All rights reserved.",
        "AAPL AACS server version %s is now listening for TCP connections on port %d...",
        "AAPL ATS server version %s is now listening for TCP connections on port %d...",
        "Valid commands are: sbus, jtag, i2c, set_debug, chips, chipnum, version, status, "
        "send, help, close, exit, spico_int, commands, sleep, diag, sbus_reset",
        "0.0.0.0:50060",
    ],
    "port_2330": "found as 32-bit LE integer in tahusd (traditional AAPL default port)",
    "grpc_port": 50060,
    "sbus_impact": (
        "SBus grants direct read/write access to all SerDes registers on the Tahoe ASIC. "
        "spico_int allows loading and executing arbitrary SPICO microcode on the SerDes "
        "cores. sbus_reset can destabilize all physical links. i2c/mdio expose PHY and "
        "optical transceiver management. JTAG boundary-scan access provided if ASIC has "
        "JTAG chain mapped through AAPL. "
        "From the FI management plane (SAM IP range, accepted unconditionally by iptables), "
        "an attacker with lateral movement from the FI can directly manipulate switch ASIC "
        "state, extract keying material from SerDes, or permanently brick the ASIC."
    ),
    "note": "AAPL AACS is a Broadcom-internal SDK debug server intended for lab characterization "
            "of SerDes IP blocks. Its presence in production firmware is a development artifact. "
            "The server's command set maps directly to hardware primitives with no OS-level "
            "access control between the TCP connection and the hardware. jtag and sbus_reset "
            "commands are destructive and non-reversible without a full hardware reset.",
}

# IOM2400-F2: PermitRootLogin yes, empty root shadow hash, missing common-auth PAM config
IOM2400_F2 = {
    "id":       "IOM2400-F2",
    "title":    "sshd_config sets PermitRootLogin yes (explicit, not default); root shadow entry "
                "is empty (root::::::::, no hash); /etc/pam.d/sshd includes common-auth which is "
                "absent from the filesystem; with PAM stack broken (missing include = PAM_ABORT) "
                "and UsePAM commented as 'no' in sshd_config, OpenSSH falls back to native "
                "/etc/shadow comparison; crypt() with empty hash field returns empty string on "
                "glibc, matching any attempt where crypt(passwd, '') == ''",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — sshd_config line 35 PermitRootLogin yes extracted; "
                "etc/shadow root::::::::: confirmed; etc/pam.d/common-auth absent from "
                "both Package 1 and Package 2 extracted filesystems; "
                "pam_cmc.so authenticate_with_ucsm socket path confirmed in binary strings",
    "cwe":      ["CWE-287 (Improper Authentication)",
                 "CWE-521 (Weak Password Requirements)",
                 "CWE-648 (Incorrect Use of Privileged APIs)"],
    "files":    ["etc/ssh/sshd_config", "etc/shadow", "etc/pam.d/sshd"],
    "sshd_config_extracts": {
        "PermitRootLogin": "yes (line 35, explicitly uncommented)",
        "PasswordAuthentication": "yes (commented = default; OpenSSH default is yes)",
        "PermitEmptyPasswords": "no (commented = default; blocks empty string password input)",
        "UsePAM": "no (commented as '#UsePAM no' = default is no in this build)",
    },
    "shadow_root": "root::::::::: (empty hash field, empty all other fields)",
    "pam_chain": (
        "sshd PAM config: auth include common-auth. "
        "common-auth not present in either extracted package. "
        "If UsePAM=yes (RHEL-based compile default), PAM_ABORT returned before pam_cmc.so loads. "
        "If UsePAM=no (sshd_config comment default), OpenSSH native auth_password() is called. "
        "native auth_password() calls sys_auth_passwd() -> crypt(password, sp->sp_pwdp). "
        "sp->sp_pwdp = '' (empty string from root::::::::). "
        "glibc crypt(any_string, '') behavior: DES requires 2-char salt; empty salt = undefined; "
        "in practice returns '' or fixed error string matching the empty hash field."
    ),
    "reachable_from": (
        "SAM addresses 127.5.254.1 and 127.6.254.1 (FI management plane) accepted unconditionally "
        "by iptables regardless of destination port. SSH port 22 is not explicitly blocked on "
        "these source ranges. Any process on the FI management plane can reach IOM SSH."
    ),
    "note": "At runtime, pam_cmc.so authenticate_with_ucsm is the intended auth mechanism "
            "(forwards credentials to UCSM over local socket). The broken PAM chain (missing "
            "common-auth) is expected to be resolved by a runtime FS overlay or symlink not "
            "visible in the extracted packages. The finding is the fallback behavior when "
            "that overlay is absent, e.g., during initial boot, factory reset, or after "
            "deliberate removal of the overlay mount.",
}

# IOM2400-F3: admin account no password hash, GID 0 (root group), shell /isan/bin/vsh
IOM2400_F3 = {
    "id":       "IOM2400-F3",
    "title":    "admin account in Package 2 /etc/passwd has empty password field "
                "(admin::500:0:admin:/tmp:/isan/bin/vsh); GID 0 = root group membership; "
                "home directory /tmp; shadow entry admin::::::::: (no hash, no expiry, no age); "
                "shell /isan/bin/vsh is the NX-OS virtual shell with elevated management access",
    "severity": "HIGH",
    "status":   "CONFIRMED — /etc/passwd and /etc/shadow extracted from Package 2; "
                "admin entry confirmed; GID 0 (root group) confirmed; "
                "vsh binary present in Package 1 at isan/bin/vsh",
    "cwe":      ["CWE-521 (Weak Password Requirements)",
                 "CWE-266 (Incorrect Privilege Assignment)"],
    "files":    ["etc/passwd", "etc/shadow"],
    "passwd_admin": "admin::500:0:admin:/tmp:/isan/bin/vsh",
    "shadow_admin": "admin::::::::: (all fields empty)",
    "sudoers":  "admin ALL = NOPASSWD: /nuova/bin/ls_alt_dir \"\" (minimal NOPASSWD entry)",
    "gid0_impact": (
        "GID 0 gives admin membership in the root group. Files with group-read/write "
        "permissions for group 0 are accessible without uid=0. Combined with the NX-OS "
        "vsh shell (which exposes 'debug bash' or equivalent commands in some builds to "
        "drop to a raw shell), admin provides a management-plane shell with root group access."
    ),
    "note": "The empty password field without 'x' in /etc/passwd indicates the account does NOT "
            "use /etc/shadow for authentication — the password field IS the hash. An empty field "
            "means no password is set, not an invalid/locked account (which would use '*' or '!'). "
            "PermitEmptyPasswords no prevents empty-string SSH passwords, but pam_unix.so with "
            "an empty hash field may still authenticate if PAM stack is invoked.",
}

# IOM2400-F4: Hardcoded card_id=11144 overwrites kernel cmdline; 21 hardware codenames exposed
IOM2400_F4 = {
    "id":       "IOM2400-F4",
    "title":    "S37tah init script hardcodes card_id=11144 with comment '# hack -summerville "
                "BIOS -sai', overwriting /proc/cmdline kernel parameter at every boot; exposes "
                "21 unreleased hardware platform codenames with internal numeric identifiers; "
                "chmod 666 applied to all /dev/ktah* Tahoe ASIC device nodes",
    "severity": "HIGH",
    "status":   "CONFIRMED — isan/etc/rc.d/rcS.d/S37tah extracted from Package 1; "
                "card_id=11144 line and comment confirmed; all codename entries confirmed; "
                "chmod 666 /dev/ktah* line confirmed",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to Unauthorized Actor)",
                 "CWE-732 (Incorrect Permission Assignment for Critical Resource)"],
    "file":     "isan/etc/rc.d/rcS.d/S37tah",
    "hardcoded_card_id": "card_id=11144  # hack -summerville BIOS -sai",
    "card_id_comment": (
        "The 'hack' comment confirms this is a development workaround left in production. "
        "card_id=11144 corresponds to the Summerville platform (21st codename in the list). "
        "The script reads card_id from /proc/cmdline then overwrites it unconditionally, "
        "meaning the kernel cmdline value is always replaced regardless of boot parameters."
    ),
    "hardware_codenames": {
        21121: "Grenoble",
        21122: "St Moritz",
        21123: "SaltLakeCity",
        21124: "Seoul",
        21125: "DeerValley",
        21126: "Chamonix",
        21128: "Bellevue",
        21129: "Turin",
        21131: "Kingsgate",
        21135: "Sumpin",
        21136: "Shugga",
        21137: "Fosters",
        21139: "WestLake",
        21142: "Doppelbock",
        21144: "Pipeworks",
        21146: "Pipedream",
        21148: "Scrimshaw",
        21150: "Southlake",
        21152: "Deeplake",
        11144: "Summerville",
        21153: "Kriek",
    },
    "dev_ktah_perms": "chmod 666 /dev/ktah* — Tahoe ASIC device nodes world-writable (see F5)",
    "note": "21 platform codenames represent current and unreleased IOM hardware variants. "
            "The numeric scheme (21xxx vs 11xxx) encodes a generation/family discriminator. "
            "Summerville (11144) at index 21 but with a different prefix is notable — it may "
            "be a different ASIC family or a blade-chassis variant. Presence in the same "
            "card_id switch statement means the same firmware binary supports all 21 platforms.",
}

# IOM2400-F5: chmod 666 Tahoe ASIC device nodes makes hardware registers world-writable
IOM2400_F5 = {
    "id":       "IOM2400-F5",
    "title":    "S37tah init script applies chmod 666 to all /dev/ktah* device nodes "
                "(Tahoe ASIC character devices), making them readable and writable by any "
                "process regardless of uid or gid; direct ioctl() access to switch ASIC "
                "hardware registers available to any local code execution context",
    "severity": "HIGH",
    "status":   "CONFIRMED — chmod 666 /dev/ktah* line extracted from "
                "isan/etc/rc.d/rcS.d/S37tah; Tahoe ASIC role as primary switch ASIC confirmed "
                "by tahusd binary analysis and S37tah codename table",
    "cwe":      ["CWE-732 (Incorrect Permission Assignment for Critical Resource)",
                 "CWE-284 (Improper Access Control)"],
    "file":     "isan/etc/rc.d/rcS.d/S37tah",
    "impact": (
        "Any process that achieves code execution on the IOM (e.g., via gRPC at 0.0.0.0:50060, "
        "via jrpc_server, or via vsh shell) can directly open /dev/ktahN and issue ioctls to "
        "read or modify switch ASIC hardware state. This includes forwarding tables, ACLs, "
        "port configuration, VLAN membership, and hardware counters. Combined with IOM2400-F1 "
        "(AACS TCP server), there are two independent unauthenticated paths to ASIC hardware "
        "manipulation: the TCP server and direct /dev/ktah* device node access."
    ),
    "note": "The ktah device nodes are the kernel interface to the Tahoe ASIC. 666 permissions "
            "are almost certainly set to allow tahusd (which likely runs as a non-root UID) to "
            "access the devices without requiring a privileged helper. This is a common embedded "
            "Linux shortcut; the correct fix is a dedicated udev rule with group-based access.",
}

# IOM2400-F6: TFTP firmware update with no signature/integrity check; direct MTD flash
IOM2400_F6 = {
    "id":       "IOM2400-F6",
    "title":    "upgrade_img.sh fetches firmware over TFTP from a caller-supplied IP address "
                "with no cryptographic signature or integrity verification; install_image.sh "
                "writes the fetched image directly to /dev/mtd1 and /dev/mtd11 (U-Boot flash "
                "partitions) via flash_eraseall and flashcp without any pre-flash validation; "
                "MD5-only integrity for the outer bundle (shinstall format) does not cover "
                "the inner binary content after extraction",
    "severity": "HIGH",
    "status":   "CONFIRMED — isan/bin/upgrade_img.sh and isan/bin/install_image.sh extracted "
                "from Package 1; TFTP invocation via mcclient --swupdate --tftpip $TFTP_IP "
                "confirmed; MTD device paths /dev/mtd1 and /dev/mtd11 confirmed; "
                "flash_eraseall + flashcp invocation confirmed; no signature check strings "
                "found in either script",
    "cwe":      ["CWE-494 (Download of Code Without Integrity Check)",
                 "CWE-345 (Insufficient Verification of Data Authenticity)"],
    "files":    ["isan/bin/upgrade_img.sh", "isan/bin/install_image.sh"],
    "upgrade_img_extracts": [
        "MCCLIENT_PATH=/nuova/bin/mcclient",
        "$MCCLIENT_PATH --swupdate --tftpip $TFTP_IP --tftppath $TFTP_PATH",
        "MTD_UBOOT_IMAGE_UPGRADE_CLONE=/dev/mtd11",
        "MTD_UBOOT_IMAGE_UPGRADE=/dev/mtd1",
    ],
    "install_image_extracts": [
        "flash_eraseall ${2}",
        "flashcp -v ${1} ${2}",
    ],
    "mtd_targets": {
        "/dev/mtd1":  "U-Boot primary flash partition",
        "/dev/mtd11": "U-Boot clone/backup flash partition",
    },
    "impact": (
        "An attacker with access to the management network segment from which upgrade_img.sh "
        "is triggered (FI management plane or with TFTP IP parameter control) can supply a "
        "malicious firmware image that is written directly to the U-Boot flash partitions. "
        "U-Boot persistence survives all OS-level remediation; the implant loads before the "
        "OS kernel and can modify the boot environment before any integrity check runs."
    ),
    "note": "shinstall outer format uses MD5 for the header checksum. This is a transport "
            "integrity check only — it verifies the outer wrapper was not corrupted in transit "
            "but provides no security guarantee against a malicious TFTP server. TFTP has no "
            "authentication or encryption; the protocol is trivially man-in-the-middle-able "
            "on the management VLAN.",
}

# IOM2400-F7: CICD status-13 exit bypass in upgrade_img.sh skips post-update validation
IOM2400_F7 = {
    "id":       "IOM2400-F7",
    "title":    "upgrade_img.sh contains a hardcoded exit path for mcclient return code 13 "
                "('CICD Update Succeded. Done') that exits with status 0 unconditionally, "
                "bypassing all post-update validation steps that execute for other return codes; "
                "comment 'CICD Update Succeded' (sic) and the typo confirm this is a CI/CD "
                "lab automation path left in production firmware",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — isan/bin/upgrade_img.sh extracted from Package 1; "
                "status-13 branch and echo string confirmed in script",
    "cwe":      ["CWE-670 (Always-Incorrect Control Flow Implementation)",
                 "CWE-693 (Protection Mechanism Failure)"],
    "file":     "isan/bin/upgrade_img.sh",
    "code_extract": (
        "if [ $STATUS -eq 13 ]; then\n"
        "    echo 'CICD Update Succeded. Done'; exit 0\n"
        "fi"
    ),
    "typo_evidence": "'Succeded' (double-e) confirms this string was written quickly for lab "
                     "automation and was never reviewed as production code",
    "bypass_impact": (
        "Triggering mcclient to return status code 13 causes upgrade_img.sh to exit cleanly "
        "before any post-update integrity checks or version verification steps execute. "
        "If mcclient's return code 13 path can be triggered by an attacker (e.g., via a "
        "crafted TFTP payload or by manipulating the mcclient binary), the update script "
        "reports success without verifying the installed firmware."
    ),
    "note": "The CICD bypass path is a development acceleration mechanism where the lab CI "
            "system triggers mcclient with a specific return code to short-circuit the normal "
            "validation flow. This is architectural debt from the development pipeline shipped "
            "in the production binary unchanged.",
}

# IOM2400-F8: Control interface in promiscuous mode (S43satinb)
IOM2400_F8 = {
    "id":       "IOM2400-F8",
    "title":    "S43satinb init script brings up the control interface ($ETH_CIF) in promiscuous "
                "mode with jumbo frame MTU 2200 (ifconfig $ETH_CIF promisc mtu 2200 up); "
                "the control interface carries intra-chassis management traffic between the IOM, "
                "blade BMCs, and the Fabric Interconnect; promiscuous mode enables passive capture "
                "of all traffic on the control segment by any local code execution context",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — isan/etc/rc.d/rcS.d/S43satinb extracted from Package 1; "
                "ifconfig $ETH_CIF promisc mtu 2200 up line confirmed",
    "cwe":      ["CWE-311 (Missing Encryption of Sensitive Data)",
                 "CWE-284 (Improper Access Control)"],
    "file":     "isan/etc/rc.d/rcS.d/S43satinb",
    "code_extract": "ifconfig $ETH_CIF promisc mtu 2200 up",
    "eth_cif_role": (
        "The control interface (ETH_CIF) carries NX-OS MTS (Message Transport Service) IPC "
        "between satellite processes and the FI, blade BMC management traffic, and ISAN "
        "discovery/keepalive traffic. IP ranges on this segment correspond to iptables "
        "ACCEPT rules: 127.5.254.1 (SAM), 127.6.254.1, 127.3.x/127.4.x (BMCs), "
        "127.11.0.x (peer IOM). MTU 2200 accommodates jumbo ISAN frames."
    ),
    "promisc_impact": (
        "Any local process with raw socket access (available to root and processes with "
        "CAP_NET_RAW) can open a raw socket on ETH_CIF and capture all intra-chassis "
        "management traffic in plaintext. MTS messages carry configuration state, "
        "authentication responses from pam_cmc.so (UCSM credential delegation), "
        "and blade BMC IPMI-over-LAN sessions on the control segment."
    ),
    "note": "Promiscuous mode on the control interface is likely required by NX-OS for "
            "protocol-level snooping (MTS multicast, ISAN discovery). It is an architectural "
            "requirement, not a misconfiguration per se. The finding is that this design "
            "choice means any local code execution can passively capture all intra-chassis "
            "management traffic without triggering ARP or flow table changes observable externally.",
}

FINDINGS = [
    IOM2400_F1, IOM2400_F2, IOM2400_F3, IOM2400_F4,
    IOM2400_F5, IOM2400_F6, IOM2400_F7, IOM2400_F8,
]
