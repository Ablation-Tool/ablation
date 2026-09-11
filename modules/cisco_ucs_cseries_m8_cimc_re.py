"""
Cisco UCS C-Series M8 CIMC (BMC) Firmware RE module
Target: Intel Rack M8 CIMC (covers C220 M8 + C240 M8)
Source: ucs-k9-bundle-c-series.6.0.2b.C.bin -> ucs-intel-rack-m8-k9-cimc.6.0.2.260044.bin

Platform codename: Godzilla (C-Series rack M8 BMC platform)
BMC SoC: ASPEED AST2600 (confirmed from bmc_last init script)
Firmware version: 6.0.2.260044

SN entry: cseries_decomp+2047086592 (hsize=764)
Content structure:
  outer TAR -> ./blob (168MB SPL binary) + ./isan/etc/imghdr.bin
  blob: Cisco SPL image (starts 55aa 0013 0024 8073)
    SPL header[272]: SPLImage-CSeriesM8 (top-level SPL image name)
    SPL header[537]: SPLImage-godzilla1 (Godzilla component)
    gzip stream at +513,736 (kernel image)
    SquashFS (gzip) at +31,003,392 (120.9 MB, 14,096 inodes, 1,112 fragments)

CIMC filesystem extracted from SquashFS (126,793,126 bytes):
  /etc/passwd, /etc/shadow -- hardcoded accounts
  /etc/M8_CT_DEV_PublicKey.bin, /etc/M8_BIOS_REL_PublicKey.bin, /etc/M8_DC_REL_PublicKey.bin
  /usr/local/lib/libcisco_signature.so -- firmware signing / dev key bypass library
  /etc/BIOS_Token_Master_Schema -- 177KB JSON, 304 BIOS tokens (all C-Series M8 platforms)
  /etc/img_features.json -- platform feature flags
  /etc/godzilla1/, /etc/godzilla2/ -- per-variant (C220 M8 / C240 M8) platform-init configs
  /etc/init.d/cpld_verification -- Godzilla FPGA/CPLD verification script
  /cisco/lib/kmip/ -- KMIP library directory (empty in squashfs -- loaded from eMMC)
  /nuova/bin/ -- CIMC management binaries: get_primary_image_version, bmc_huu_update, etc.
  inetd.conf -- jrpc_server on 127.0.0.1 (loopback Jolt JSON-RPC)

Also analyzed from C-Series bundle:
  C245 M8 CIMC: cseries_decomp+1481073152 (141MB) -- AMD rack CIMC
  C225 M8 CIMC: cseries_decomp+1914477568 (141MB) -- AMD rack CIMC

B-Series equivalents analyzed in:
  cisco_ucs_bseries_m5m6_xseries_m8_bios_re.py (B200M5, B200M6, B210M6, X210M8 BIOS)
  Prior CIMC modules: b480m5_cimc, b200m6_cimc, bxm6_x210m6_cimc, intel_blade_m8_cimc
"""

CIMC_INTEL_RACK_M8 = {
    "target":       "Intel Rack M8 CIMC (C220 M8 + C240 M8)",
    "sn_name":      "ucs-intel-rack-m8-k9-cimc.6.0.2.260044.bin",
    "fw_version":   "6.0.2.260044",
    "bmc_soc":      "ASPEED AST2600",
    "spl_images":   ["SPLImage-CSeriesM8", "SPLImage-godzilla1"],
    "squashfs": {
        "offset_in_spl":  31003392,
        "size_bytes":     126793126,
        "inodes":         14096,
        "compression":    "gzip",
        "block_size":     131072,
    },
    "platform_codename": "Godzilla",
    "fpga_firmware_files": [
        "Godzilla_MB_FPGA_RTISP.jam (JTAG-based FPGA runtime image)",
        "Godzilla_MB_FPGA_ISP.jam (JTAG-based FPGA in-system programming)",
    ],
}

CIMC_ACCOUNTS = {
    "root": {
        "uid": 0, "shell": "/bin/bash",
        "shadow_hash": "$1$QEW/pPLa$tyWug5NeZ9sMKrXO2McRj1",
        "hash_type": "MD5-crypt ($1$)",
    },
    "support": {
        "uid": 0, "shell": "/bin/dfu",
        "shadow_hash": "$1$3gsI8PqW$UIGRGO/h61v/8bJDlEIOy0",
        "hash_type": "MD5-crypt ($1$)",
    },
    "cli": {
        "uid": 0, "shell": "/usr/cli/pmcli",
        "shadow_hash": "$1$3gsI8PqW$UIGRGO/h61v/8bJDlEIOy0",  # IDENTICAL to support
        "hash_type": "MD5-crypt ($1$)",
    },
    "sol": {
        "uid": 0, "shell": "/usr/local/bin/solshell",
        "shadow_hash": "$1$3gsI8PqW$UIGRGO/h61v/8bJDlEIOy0",  # IDENTICAL
        "hash_type": "MD5-crypt ($1$)",
    },
    "nobody": {
        "uid": 2000, "shell": "/bin/dfu",
        "shadow_hash": "$1$3gsI8PqW$UIGRGO/h61v/8bJDlEIOy0",  # IDENTICAL
        "hash_type": "MD5-crypt ($1$)",
    },
}

CIMC_PUBLIC_KEYS = {
    "M8_CT_DEV_PublicKey.bin": {
        "path": "/etc/M8_CT_DEV_PublicKey.bin",
        "size_bytes": 1072,
        "purpose": "CIMC_CT developer key for M8_CIMC_DEV_Key_Install bypass path",
        "label": "CIMC_CT",
        "marker": "last 5 bytes = ee be ef ca fe (Cisco dev marker)",
        "header": "ae0425ab1234cd01",
    },
    "M8_BIOS_REL_PublicKey.bin": {
        "path": "/etc/M8_BIOS_REL_PublicKey.bin",
        "size_bytes": 1076,
        "purpose": "Production BIOS image release signature verification",
        "header": "ae0429ab1234cd01",
    },
    "M8_DC_REL_PublicKey.bin": {
        "path": "/etc/M8_DC_REL_PublicKey.bin",
        "size_bytes": 1092,
        "purpose": "M8 DC release key (data center variant signing)",
        "header": "ae0439ab1234cd01",
    },
}

LIBCISCO_SIGNATURE = {
    "path":    "/usr/local/lib/libcisco_signature.so",
    "size_bytes": 67260,
    "arch":    "ARM32 (machine=0x28)",
    "exports": [
        "cs_rommon_platform_allow_dev_keys",        # allow_dev_keys global setter
        "cs_rommon_platform_get_dev_image_load_status",
        "cs_rommon_verify_buffer_raw_sign_revocation",
        "cimc_create_board_dev_key_token",
        "cimc_verify_board_dev_key_token",
        "cs_rommon_verify_bios_file",
        "cs_rommon_verify_cimc_buffer",
        "cs_rommon_verify_psb_buffer",
    ],
    "allow_dev_keys_bss": True,  # global in .bss (zero-initialized = OFF by default)
    "allow_dev_keys_contrast": "B-Series CIMC had allow_dev_keys=0x01 in .data (ON by default); "
                               "C-Series M8 CIMC has it in .bss (OFF by default, settable via DEV token)",
    "dev_key_install_strings": [
        "----- Copy below signing info -----",
        "M8_CIMC_DEV_Key_Install",
        "----- Copy above signing info -----",
        "Paste signature here:",
    ],
}

IMG_FEATURES = {
    "path": "/etc/img_features.json",
    "content": {
        "SecureVIC": "yes",
        "RioBeach": "yes",
        "BayView": "yes",
        "CiscoVICPIDs": ["UCSC-P-V5D200G", "UCSC-P-V5Q50G", "UCSC-M-V5D200GV2", "UCSC-M-V5Q50GV2"],
        "ImmersionModeGodzilla": "yes",
        "ImmersionMode": "yes",
        "BMC_Images_Encryption_Enabled": "yes",
    },
}

BIOS_TOKEN_SCHEMA = {
    "path":         "/etc/BIOS_Token_Master_Schema",
    "size_bytes":   177574,
    "token_count":  304,  # all C-Series M8 platforms combined
    "first_token":  "UEFIBootMode",
    "note":         "Master schema for all C-Series M8 BIOS tokens; 304 vs 223 per-platform in BiosUpdate.json -- "
                    "master includes tokens for AMD and Intel variants simultaneously",
}

# --- FINDINGS ---

# CSERIES-CIMC-F1: Hardcoded root MD5-crypt hash universal across C220/C240 M8 deployments
CSERIES_CIMC_F1 = {
    "id":       "CSERIES-CIMC-F1",
    "title":    "C-Series M8 CIMC root account carries hardcoded MD5-crypt password hash "
                "$1$QEW/pPLa$tyWug5NeZ9sMKrXO2McRj1 in /etc/shadow; "
                "MD5-crypt ($1$) is computationally weak -- modern hardware cracks it in minutes; "
                "the same hash is present in every C220 M8 and C240 M8 deployment globally "
                "because the SquashFS is read-only and shipped from the firmware bundle; "
                "root account has /bin/bash shell and uid=0; "
                "an attacker with the cracked root password gains root shell on any CIMC in the fleet "
                "via SSH or serial console without needing further privilege escalation",
    "severity": "HIGH",
    "status":   "CONFIRMED -- /etc/shadow root entry confirmed in Intel Rack M8 CIMC SquashFS "
                "(cimc-6.0.2.260044, 126MB SquashFS, 14096 inodes)",
    "cwe":      ["CWE-259 (Use of Hard-coded Password)", "CWE-916 (Use of Password Hash with Insufficient Computational Effort)"],
    "hash":     "$1$QEW/pPLa$tyWug5NeZ9sMKrXO2McRj1",
    "hash_type": "MD5-crypt ($1$, 32-bit POSIX crypt)",
}

# CSERIES-CIMC-F2: Four service accounts share identical MD5-crypt hash
CSERIES_CIMC_F2 = {
    "id":       "CSERIES-CIMC-F2",
    "title":    "All four CIMC service accounts (support, cli, sol, nobody) share identical "
                "MD5-crypt password hash $1$3gsI8PqW$UIGRGO/h61v/8bJDlEIOy0 in /etc/shadow; "
                "cracking this single hash grants simultaneous access to all four accounts; "
                "all service accounts are uid=0 (effective root) -- support and nobody use /bin/dfu shell, "
                "cli uses /usr/cli/pmcli (CIMC CLI), sol uses /usr/local/bin/solshell (Serial Over LAN); "
                "an attacker with the cracked hash can launch CIMC CLI or establish a serial-over-LAN session "
                "on any C220/C240 M8 server in the fleet via SSH without knowing the admin-set CIMC password; "
                "this is a parallel root-equivalent access path to CSERIES-CIMC-F1 (root hash)",
    "severity": "HIGH",
    "status":   "CONFIRMED -- support/cli/sol/nobody all have identical hash in /etc/shadow",
    "cwe":      ["CWE-259 (Use of Hard-coded Password)", "CWE-260 (Password in Configuration File)"],
    "hash":     "$1$3gsI8PqW$UIGRGO/h61v/8bJDlEIOy0",
    "accounts": ["support", "cli", "sol", "nobody"],
}

# CSERIES-CIMC-F3: M8_CT_DEV_PublicKey.bin in production -- dev key bypass path active
CSERIES_CIMC_F3 = {
    "id":       "CSERIES-CIMC-F3",
    "title":    "M8_CT_DEV_PublicKey.bin (Cisco Test developer public key) is shipped in "
                "the production C-Series M8 CIMC filesystem at /etc/; "
                "the key ends with Cisco's known developer marker bytes 0xEE 0xBE 0xEF 0xCA 0xFE; "
                "the CIMC_CT label is embedded in the key blob; "
                "libcisco_signature.so exports M8_CIMC_DEV_Key_Install interaction ("
                "'Copy below signing info ... Paste signature here') and "
                "cs_rommon_platform_allow_dev_keys (allow_dev_keys global setter, .bss, default 0); "
                "cimc_create_board_dev_key_token and cimc_verify_board_dev_key_token are exported -- "
                "the complete dev key token flow is active in production; "
                "holder of the M8_CT private key can present a signed CIMC_DEV token, call "
                "cs_rommon_platform_allow_dev_keys(1), and install unsigned firmware on any C220/C240 M8; "
                "contrast with B-Series CIMC which had allow_dev_keys initialized to 0x01 in .data "
                "(always enabled at boot); C-Series M8 requires the token to be presented (higher bar) "
                "but the full dev bypass architecture remains present in production; "
                "three public keys in /etc/: CT_DEV (1072B), BIOS_REL (1076B), DC_REL (1092B) -- "
                "all use Cisco key header ae04XXab1234cd01 format",
    "severity": "HIGH",
    "status":   "CONFIRMED -- /etc/M8_CT_DEV_PublicKey.bin (1072 bytes) present in SquashFS; "
                "key ends eebeefcafe; libcisco_signature.so confirms M8_CIMC_DEV_Key_Install export",
    "cwe":      ["CWE-321 (Use of Hard-coded Cryptographic Key)", "CWE-693 (Protection Mechanism Failure)"],
    "comparison": "B-Series CIMC: allow_dev_keys=0x01 in .data (always-on dev bypass at boot); "
                  "C-Series M8 CIMC: allow_dev_keys in .bss (default=0, requires CIMC_CT token to set to 1)",
}

# CSERIES-CIMC-F4: BIOS_Token_Master_Schema in CIMC -- 304-token complete feature surface
CSERIES_CIMC_F4 = {
    "id":       "CSERIES-CIMC-F4",
    "title":    "BIOS_Token_Master_Schema (177KB JSON, 304 tokens) stored in C-Series M8 CIMC "
                "at /etc/BIOS_Token_Master_Schema; "
                "the schema includes UEFI variable GUIDs, UEFI variable names, byte offsets within "
                "NvConfig variables, allowed values, and GUI visibility flags for all C-Series M8 platforms; "
                "first token example: UEFIBootMode at CiscoUcsBiosTokenNvConfig offset 6, 1 byte; "
                "UEFI variable GUID C63D2441-107E-4241-905E-A5E9393631CF is exposed; "
                "the CIMC BIOS token interface allows CIMC to directly read and write UEFI NvConfig variables "
                "in BIOS flash without host OS involvement; "
                "304 tokens (master) vs 223 per-platform tokens in BiosUpdate.json -- the master includes "
                "AMD-specific and Intel-specific tokens in a single schema; "
                "BIOS security tokens (SecureBoot, SGX, TXT, TPM settings) are in the schema and "
                "writable via the CIMC BIOS token interface (JRPC/Redfish path)",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- /etc/BIOS_Token_Master_Schema 177574 bytes, 304-element Tokens array",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "token_count": 304,
    "uefi_variable_guid": "C63D2441-107E-4241-905E-A5E9393631CF",
}

# CSERIES-CIMC-F5: BMC_Images_Encryption_Enabled = yes but dev bypass path active
CSERIES_CIMC_F5 = {
    "id":       "CSERIES-CIMC-F5",
    "title":    "C-Series M8 CIMC img_features.json declares BMC_Images_Encryption_Enabled=yes "
                "and SecureVIC=yes (VIC secure firmware), but CSERIES-CIMC-F3 confirms the "
                "developer key bypass path (M8_CT_DEV_PublicKey.bin + M8_CIMC_DEV_Key_Install) "
                "is simultaneously present in the same production firmware; "
                "ImmersionMode=yes and ImmersionModeGodzilla=yes expose the liquid immersion cooling "
                "feature support and the Godzilla platform codename in plaintext in a world-readable file; "
                "CiscoVICPIDs list (UCSC-P-V5D200G, UCSC-P-V5Q50G, UCSC-M-V5D200GV2, UCSC-M-V5Q50GV2) "
                "enumerates all VIC 15400-series (V5) PIDs supported by this CIMC; "
                "jrpc_server bound to 127.0.0.1 only (loopback) in inetd.conf -- contrast with "
                "B480 M5 credfish (B480-M5-F2) which listened on TCP/4038 with 20-connection throttle only; "
                "Godzilla platform name exposed via: SPL image headers, FPGA firmware filenames "
                "(Godzilla_MB_FPGA_RTISP.jam, Godzilla_MB_FPGA_ISP.jam), "
                "img_features.json, and cpld_verification init script",
    "severity": "LOW",
    "status":   "CONFIRMED -- img_features.json content verified in SquashFS",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "cimc_pids":   ["UCSC-P-V5D200G (VIC 15420 2-port 100G QSFP28)", "UCSC-P-V5Q50G (VIC 15428 4-port 25G)"],
    "codename_exposures": ["SPLImage-godzilla1/godzilla2", "Godzilla_MB_FPGA_*.jam", "ImmersionModeGodzilla"],
}

FINDINGS = [CSERIES_CIMC_F1, CSERIES_CIMC_F2, CSERIES_CIMC_F3, CSERIES_CIMC_F4, CSERIES_CIMC_F5]

FIRMWARE = [CIMC_INTEL_RACK_M8]
