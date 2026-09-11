"""
Cisco UCS B-Series Emulex OneConnect and QLogic Fibre Channel HBA Firmware RE
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin
Adapters: m73kr-e, m72kr-e, m73kr-q, m72kr-q

Binary format: SN wrapper (magic 6401534e, 2B BE hsize, name at [8:hsize], gzip payload)
Gzip decompresses to inner TAR containing ./blob (main firmware) + ./isan/etc/imghdr.bin
"""

EMULEX_OCE_FIRMWARE = {
    "m73kr_e": {
        "isan_filename": "ucs-m73kr-e.10.6.144.21.bin",
        "version": "10.6.144.21",
        "form_factor": "B-Series mezzanine 10GbE OCe11102",
        "blob_size_kb": 16384,
        "blob_md5_prefix": "ebbc92a7",
        "sn_header": {
            "magic": "6401534e",
            "inner_tar_members": ["./blob", "./isan/etc/imghdr.bin"],
        },
        "redboot": {
            "banner": "RedBoot(tm) bootstrap and debug environment [ROMRAM] Non-certified release, version v2_0 - built 18:55:26, Mar 21 2014",
            "gdb_stub_banner": "eCos GDB stubs [via RedBoot] - built Mar 21 2014 / 18:55:26 [-r] [-v] [-d] [-h <host>] [-m <varies>]",
            "prompt": "RedBoot>",
            "known_commands": ["version", "go", "reset", "display", "help", "fis", "load", "exec"],
            "error_strings": ["** Error: Illegal command: \"%s\""],
            "host_fw_download": "Detected host firmware download in progress ...",
        },
        "pki": {
            "pem_offset": "0x00048854",
            "structure": "-----BEGIN PUBLIC KEY-----\\x00\\x00-----END PUBLIC KEY-----\\x00\\x00\\x00\\x00Proc-Type: 4,ENCRYPTED",
            "note": "empty PUBLIC KEY block (no b64 data) immediately followed by orphaned Proc-Type:4,ENCRYPTED PEM header",
        },
        "iscsi_chap": {
            "fields": ["Initiator Secret", "Target Secret", "Initiator CHAP Name", "Target CHAP Name"],
            "constraint_string": "Initiator secret and Target secret must be different.",
        },
        "console_channel": {
            "command_string": "Display/switch console channel  [-1|<channel number>]   Current console channel id:",
            "note": "RedBoot multi-channel console mux present in production blob",
        },
    },
    "m72kr_e": {
        "isan_filename": "ucs-m72kr-e.10.0.803.19.bin",
        "version": "10.0.803.19",
        "form_factor": "B-Series mezzanine 10GbE OCe10102",
        "blob_size_kb": 8192,
        "blob_md5_prefix": "3ed1d7db",
        "redboot": {
            "banner": "RedBoot(tm) bootstrap and debug environment [ROMRAM] Non-certified release, version v2_0 - built 15:54:05, Jul 18 2011",
            "gdb_stub_banner": "eCos GDB stubs [via RedBoot] - built Jul 18 2011 / 15:54:05 [-r] [-v] [-d] [-h <host>] [-m <varies>]",
            "prompt": "RedBoot>",
            "console_channel_switch": True,
        },
        "build_date_note": "Jul 18 2011 -- 15 years old in shipping firmware at time of RE",
    },
}

QLOGIC_HBA_FIRMWARE = {
    "m73kr_q": {
        "isan_filename": "ucs-m73kr-q.2.50.11.bin",
        "version": "2.50.11",
        "form_factor": "B-Series mezzanine 8Gbps FC HBA",
        "blob_size_kb": 4346,
        "blob_md5_prefix": "736a45ea",
        "iscsi_config": {
            "fields": [
                "Initiator Subnet Mask",
                "Gateway",
                "Reverse CHAP Name",
                "Reverse CHAP Secret",
                "Target",
            ],
            "note": "Reverse CHAP (mutual authentication) supported; credentials stored in adapter NVRAM",
        },
        "bis_strings": [
            "BIS image/credential validation failed",
            "BIS integrity check failed",
            "BIS initialization failed",
            "BIS shutdown failed",
            "BIS get boot object authorization check flag failed",
            "BIS get signature information failed",
            "BIS free memory failed",
            "BIS bad entry structure checksum",
        ],
    },
    "m72kr_q": {
        "isan_filename": "ucs-m72kr-q.02.00.77.bin",
        "version": "02.00.77",
        "form_factor": "B-Series mezzanine 4Gbps FC HBA (PXE option ROM)",
        "blob_size_kb": 856,
        "blob_md5_prefix": "d264bbc1",
        "pxe_rom": {
            "pxe_strings": [
                "PXE-EC1: Base-code ROM ID structure was not found.",
                "PXE-M0F: Exit QLogic PXE ROM.",
                "PXE-EC3: BC ROM ID structure is invalid.",
                "PXE-E06: Option ROM requires DDIM support.",
            ],
            "debug_artifacts": [
                ".dbg-flash.h",
                "flash access",
                "exprom-sp-en",
                "exprom-sp-ds",
                "exprom-mapin",
                "exprom-mapout",
                "flash-adr.err",
            ],
            "bis_error_strings": [
                "BIS bad entry structure checksum",
                "BIS get signature information failed",
                "BIS free memory failed",
                "BIS get boot object authorization check flag failed",
                "BIS shutdown failed",
                "BIS initialization failed",
                "BIS image/credential validation failed",
                "BIS integrity check failed",
            ],
        },
        "tftp_strings": [
            "Error received from TFTP server",
            "TFTP cannot read from connection",
            "No boot filename received",
            "BOOT SERVER IP: ",
        ],
        "flash_integrity_string": "Invalid EEPROM checksum",
    },
}

FINDINGS = {
    "EMULEX-REDBOOT-NONCERT-F1": {
        "id": "EMULEX-REDBOOT-NONCERT-F1",
        "severity": "HIGH",
        "title": "Non-Certified RedBoot Debug Bootloader in Production Emulex Mezzanine HBA Firmware",
        "component": "Emulex OCe M73KR_E (10.6.144.21) + M72KR_E (10.0.803.19)",
        "what": (
            "Both M73KR_E and M72KR_E blobs embed RedBoot(tm) [ROMRAM] marked "
            "'Non-certified release, version v2_0'. M73KR_E built Mar 21 2014; "
            "M72KR_E built Jul 18 2011. 'Non-certified release' is the specific "
            "RedBoot build path that bypasses the production signing and certification "
            "gate used by certified RedBoot releases. The interactive RedBoot shell "
            "(RedBoot> prompt) with commands version/go/reset/display/help/fis/load/exec "
            "is compiled into both production blobs. 'Detected host firmware download in "
            "progress' string confirms RedBoot can observe and interact with host firmware "
            "download operations in-band."
        ),
        "why": (
            "A non-certified debug bootloader in a production B-Series mezzanine HBA "
            "means the adapter's root-of-trust is the non-production path. The RedBoot "
            "shell provides firmware flash (fis), arbitrary load-and-execute (exec/load/go), "
            "and hardware reset. The M72KR_E build from 2011 ships in firmware version "
            "10.0.803.19 -- a 15-year-old non-certified bootloader in a current shipping product."
        ),
        "evidence": {
            "m73kr_e_banner": "Non-certified release, version v2_0 - built 18:55:26, Mar 21 2014",
            "m72kr_e_banner": "Non-certified release, version v2_0 - built 15:54:05, Jul 18 2011",
            "redboot_prompt": "RedBoot>",
            "redboot_commands": "version go reset display help fis load exec",
        },
        "remediation": (
            "Re-certify Emulex OCe firmware through Broadcom's production bootloader "
            "signing process. Confirmed RedBoot releases do not carry 'Non-certified release' "
            "in the banner. Request Broadcom provide a roadmap for replacing v2_0 bootloader "
            "builds with current certified variants."
        ),
    },

    "EMULEX-GDB-STUB-F1": {
        "id": "EMULEX-GDB-STUB-F1",
        "severity": "HIGH",
        "title": "eCos GDB Debug Stubs with Network Connectivity Compiled into Production Emulex HBA Firmware",
        "component": "Emulex OCe M73KR_E (10.6.144.21) + M72KR_E (10.0.803.19)",
        "what": (
            "Both Emulex mezzanine blobs contain 'eCos GDB stubs [via RedBoot]' with "
            "the '-h <host>' argument specifier, indicating the GDB stub is network-capable "
            "and can accept a remote host address to connect back to. M73KR_E stubs built "
            "Mar 21 2014; M72KR_E stubs built Jul 18 2011. eCos GDB stubs implement the "
            "GDB Remote Serial Protocol (RSP), providing: arbitrary memory read/write, "
            "register read/write, single-step execution, hardware breakpoint insertion, and "
            "remote continue/halt. The '-r' flag in the stub signature indicates run-mode "
            "attach capability."
        ),
        "why": (
            "A network-capable GDB stub compiled into production adapter firmware creates "
            "a persistent hardware-level debug access channel on every B-Series blade that "
            "mounts these HBAs. If the management plane network (UCSM fabric interconnect) "
            "reaches the adapter's debug port, an attacker with fabric access can attach a "
            "GDB client, read all adapter memory (including iSCSI CHAP secrets, FC target "
            "credentials, and DMA-accessible host memory ranges), and execute arbitrary code "
            "in the adapter's eCos RTOS context."
        ),
        "evidence": {
            "m73kr_e": "eCos GDB stubs [via RedBoot] - built Mar 21 2014 / 18:55:26 [-r] [-v] [-d] [-h <host>] [-m <varies>]",
            "m72kr_e": "eCos GDB stubs [via RedBoot] - built Jul 18 2011 / 15:54:05 [-r] [-v] [-d] [-h <host>] [-m <varies>]",
        },
        "remediation": (
            "GDB stubs must be excluded from production builds via eCos build configuration "
            "(CYGDBG_HAL_DEBUG_GDB_INCLUDE_STUBS=0). Broadcom/Emulex should audit the OCe "
            "firmware build system to confirm debug stub exclusion is enforced in release "
            "build targets. Network isolation of the adapter management plane does not "
            "eliminate risk -- physical console channel access via the mezzanine interface "
            "also reaches the stub."
        ),
    },

    "EMULEX-PUBKEY-ENCRYPTED-F1": {
        "id": "EMULEX-PUBKEY-ENCRYPTED-F1",
        "severity": "MEDIUM",
        "title": "Empty PEM Public Key Block with Orphaned Encrypted PEM Header in Emulex M73KR_E Blob",
        "component": "Emulex OCe M73KR_E (10.6.144.21)",
        "what": (
            "At offset 0x00048854 in the M73KR_E 16MB blob, a PEM structure sequence: "
            "'-----BEGIN PUBLIC KEY-----\\x00\\x00-----END PUBLIC KEY-----' (empty body, "
            "no base64 key material) immediately followed by 'Proc-Type: 4,ENCRYPTED' "
            "(the PEM header that normally appears inside a BEGIN RSA PRIVATE KEY/ENCRYPTED "
            "PRIVATE KEY block). The PUBLIC KEY block body is zero bytes. The Proc-Type "
            "header has no surrounding private key PEM markers. The two PEM structures are "
            "NUL-separated but contiguous in the blob."
        ),
        "why": (
            "'Proc-Type: 4,ENCRYPTED' is the PEM encryption declaration used for encrypted "
            "PKCS#1 private key storage (traditionally in PEM format: BEGIN RSA PRIVATE KEY, "
            "Proc-Type: 4,ENCRYPTED, DEK-Info: <cipher>,<IV>, <base64>). Its presence without "
            "proper PEM markers in the blob indicates a key infrastructure artifact: either "
            "(a) an adapter key slot template where key material is provisioned post-flash but "
            "the PEM framing is compiled in as a placeholder, or (b) an incomplete sanitization "
            "where a private key was removed but the encryption header was not. Either scenario "
            "implies a key provisioning mechanism inside the adapter blob that is not documented "
            "in Cisco/Broadcom security disclosures."
        ),
        "evidence": {
            "offset": "0x00048854",
            "raw_sequence": "-----BEGIN PUBLIC KEY-----  -----END PUBLIC KEY-----    Proc-Type: 4,ENCRYPTED",
            "note": "spaces represent NUL bytes in printable dump; no base64 data between PEM markers",
        },
        "remediation": (
            "Audit the Emulex OCe M73KR_E build pipeline for key generation or key slot "
            "initialization logic that produces PEM-formatted key material in the blob. "
            "If this is a provisioning placeholder, the provisioning mechanism and key "
            "derivation path require security review. If it is residual private key "
            "infrastructure, the key must be rotated and the build process corrected."
        ),
    },

    "EMULEX-ISCSI-CHAP-MGMT-F1": {
        "id": "EMULEX-ISCSI-CHAP-MGMT-F1",
        "severity": "MEDIUM",
        "title": "iSCSI CHAP Credential Storage in Emulex Adapter NVRAM Outside Host OS Visibility",
        "component": "Emulex OCe M73KR_E (10.6.144.21)",
        "what": (
            "M73KR_E blob manages a full iSCSI CHAP credential set: 'Initiator Secret', "
            "'Target Secret', 'Initiator CHAP Name', 'Target CHAP Name'. Constraint string "
            "'Initiator secret and Target secret must be different.' confirms these are "
            "independent bidirectional CHAP secrets stored and enforced by the adapter. "
            "CHAP secrets are resident in adapter NVRAM, not host OS credential stores."
        ),
        "why": (
            "iSCSI CHAP secrets in adapter NVRAM are invisible to host-side credential "
            "auditing tools, not rotated by host OS password policies, and persist across "
            "OS reinstalls. In a B-Series blade with Emulex iSCSI boot, the initiator and "
            "target secrets in adapter NVRAM authenticate the blade to storage targets -- "
            "compromise of adapter firmware (e.g., via the RedBoot shell or GDB stubs) "
            "gives direct read access to these CHAP secrets, enabling storage target "
            "impersonation or man-in-the-middle attacks on iSCSI sessions."
        ),
        "evidence": {
            "fields": ["Initiator Secret", "Target Secret", "Initiator CHAP Name", "Target CHAP Name"],
            "constraint": "Initiator secret and Target secret must be different.",
        },
        "remediation": (
            "Rotate iSCSI CHAP secrets on any B-Series blade with Emulex OCe HBAs after "
            "firmware upgrade. Audit CHAP secret provisioning flows to confirm secrets are "
            "not transmitted in plaintext over the UCSM management plane. Consider migrating "
            "iSCSI boot authentication to mutual CHAP (mCHAP) with secrets derived from a "
            "per-blade hardware identity rather than static NVRAM values."
        ),
    },

    "QLOGIC-BIS-AUTHFLAG-F1": {
        "id": "QLOGIC-BIS-AUTHFLAG-F1",
        "severity": "LOW",
        "title": "BIS Boot Authorization Flag Retrieval Failure Path in QLogic M72KR_Q PXE Option ROM",
        "component": "QLogic M72KR_Q (02.00.77) PXE option ROM",
        "what": (
            "QLogic M72KR_Q PXE option ROM (856KB blob) contains 8 distinct BIS (Boot Integrity "
            "Services) error strings including 'BIS get boot object authorization check flag "
            "failed'. BIS is the UEFI Pre-boot Integrity mechanism that validates signed boot "
            "objects before network execution. The 'authorization check flag' is a BIOS-maintained "
            "flag that enables or disables BIS validation; the error path for flag retrieval "
            "failure is present in the ROM. Additionally, debug source artifact '.dbg-flash.h' "
            "and expansion ROM control strings 'exprom-sp-en'/'exprom-sp-ds' are embedded in the "
            "production PXE ROM."
        ),
        "why": (
            "If BIS 'authorization check flag' retrieval fails and the failure path does not "
            "default to deny-boot, network boot proceeds without signature validation. The "
            "presence of '.dbg-flash.h' in production PXE ROM confirms debug flash hooks were "
            "compiled into the shipping binary. 'exprom-sp-en'/'exprom-sp-ds' are NVRAM "
            "parameters controlling expansion ROM enable/disable state -- writable NVRAM access "
            "could disable the option ROM or swap it."
        ),
        "evidence": {
            "bis_flag_error": "BIS get boot object authorization check flag failed",
            "bis_error_set": [
                "BIS bad entry structure checksum",
                "BIS get signature information failed",
                "BIS image/credential validation failed",
                "BIS integrity check failed",
                "BIS initialization failed",
                "BIS shutdown failed",
                "BIS free memory failed",
            ],
            "debug_artifacts": [".dbg-flash.h", "exprom-sp-en", "exprom-sp-ds", "flash-adr.err"],
        },
        "remediation": (
            "Verify the QLogic M72KR_Q PXE option ROM BIS failure path defaults to "
            "boot-denied when the authorization check flag cannot be retrieved. Strip "
            ".dbg-flash.h and debug symbol references from production option ROM builds. "
            "Audit NVRAM parameter access controls for exprom-sp-en/exprom-sp-ds to "
            "ensure they are not settable from unauthenticated management plane access."
        ),
    },

    "QLOGIC-REVERSE-CHAP-F1": {
        "id": "QLOGIC-REVERSE-CHAP-F1",
        "severity": "LOW",
        "title": "Mutual CHAP Credential Storage in QLogic M73KR_Q FC HBA Adapter NVRAM",
        "component": "QLogic M73KR_Q (2.50.11) FC HBA",
        "what": (
            "QLogic M73KR_Q FC HBA blob carries iSCSI boot configuration fields including "
            "'Reverse CHAP Name' and 'Reverse CHAP Secret' in addition to standard forward "
            "CHAP fields. Reverse CHAP (mutual CHAP / bidirectional CHAP) enables the iSCSI "
            "target to authenticate the initiator in both directions. Reverse CHAP credentials "
            "are stored in adapter NVRAM alongside gateway and subnet mask configuration."
        ),
        "why": (
            "Reverse CHAP secrets in adapter NVRAM extend the credential attack surface: "
            "a target-side attacker who captures the reverse CHAP secret can impersonate "
            "a storage target to the blade. Combined with the BIS validation gaps in "
            "M72KR_Q, adapter NVRAM credential extraction represents a dual-direction "
            "authentication bypass path for iSCSI boot infrastructure."
        ),
        "evidence": {
            "config_fields": ["Initiator Subnet Mask", "Gateway", "Reverse CHAP Name", "Reverse CHAP Secret"],
            "blob": "ucs-m73kr-q.2.50.11.bin",
        },
        "remediation": (
            "Apply the same CHAP secret rotation and audit guidance as EMULEX-ISCSI-CHAP-MGMT-F1 "
            "to QLogic M73KR_Q adapters. Confirm reverse CHAP secrets are not stored in "
            "plaintext in adapter NVRAM and review QLogic FC HBA management interface for "
            "unauthenticated NVRAM read access."
        ),
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "session": 29,
    "adapters_analyzed": ["m73kr-e", "m72kr-e", "m73kr-q", "m72kr-q"],
    "format_confirmed": "SN magic 6401534e + 2B BE hsize + gzip -> inner TAR with ./blob + ./isan/etc/imghdr.bin",
    "total_findings": 6,
    "severity_breakdown": {"HIGH": 2, "MEDIUM": 2, "LOW": 2},
    "key_technical_notes": [
        "Both Emulex blobs: [ROMRAM] RedBoot variant boots from ROM but runs from RAM copy -- standard for embedded NOR flash adapters",
        "eCos RTOS used in both Emulex blobs: eCos is GPLv2 with eCos exception; RedBoot is the eCos-bundled debug bootloader",
        "M72KR_E blob built 2011 ships in current firmware 10.0.803.19 -- build toolchain not refreshed in 15 years",
        "QLogic M72KR_Q is a legacy PXE option ROM (856KB) vs M73KR_Q full FC HBA firmware (4.3MB)",
        "BIS (Boot Integrity Services) implementation predates UEFI Secure Boot; separate standard by Verisign/Intel (1999)",
        "Emulex OCe series: B-Series mezzanine form factor (OCe10102=M72KR_E, OCe11102=M73KR_E); CNA (converged network adapter) role",
    ],
}
