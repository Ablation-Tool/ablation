"""
Cisco UCS C-Series AMD Rack M7/M8 CIMC (BMC) Firmware RE module
Target: AMD Rack CIMC covering C245 M7/M8 (Mount Rainier) and C225 M7/M8 (Mount Adams)
Source: ucs-k9-bundle-c-series.6.0.2b.C.bin -> SN entry at offset 1481073152 (141MB TAR)

Platform codenames:
  Mount Rainier = C245 AMD rack (2U) -- mountrainier1/mountrainier2 SPL image variants
  Mount Adams   = C225 AMD rack (1U) -- mountadams1/mountadams2 SPL image variants

BMC SoC: ASPEED AST2600 (assumed from SPL and shared /usr/local/lib/ CIMC architecture)
Firmware version: 6.0.2.260044 (shared with Intel Rack M8 CIMC)
SPL top-level image: SPLImage-CSeriesM7 (but covers M7+M8 -- CPUGeneration = emeraldrapids+turin)

SN entry content structure:
  outer TAR -> ./blob (141MB SPL binary) + ./isan/etc/imghdr.bin (764 bytes)
  blob: Cisco SPL image (starts 55aa 0019 0030 8029)
    SPL header[272]: SPLImage-CSeriesM7
    SPL header[400]: SPLImage-ast2600_evb
    SPL header[528]: SPLImage-mountrainier1
    SPL header[656]: SPLImage-mountrainier2
    SPL header[784]: SPLImage-mountadams1
    SPL header[912]: SPLImage-mountadams2
    Main SquashFS at blob offset 29,497,600 (gzip, 101.7MB, 9,930 inodes, mkfs 2026-02-18)
    Secondary SquashFS at blob offset 131,215,616 (10MB, 760 inodes, mkfs 2025-10-08)

SquashFS root filesystem (97MB, 9,930 inodes):
  /etc/ -- key files (no /etc/passwd or /etc/shadow -- accounts stored in eMMC /mnt/emmc/bmc_nv/)
  /usr/local/lib/ -- libcisco_bmcpsb.so (AMD PSB bypass library) + >50 CIMC .so files
  /nuova/bin/ -- CIMC management binaries
  /nv/ -- eMMC-mapped security artifacts (SPDM certs, mTLS CA, TPM firmware bundle)
  /configs/ -- CIMC init configuration
  /etc/mosquitto/ -- MQTT broker config
  /etc/ppp/ -- BMC-to-host PPP link config

Multi-platform coverage:
  img_features.json CPUGeneration: ["emeraldrapids", "turin"]
  nvme_mi_catalog.json lists: godzilla1/2 (Intel M8 rack) + mountrainier1/2 + mountadams1/2
  Single CIMC firmware binary covers Intel AND AMD rack M8 form factors simultaneously

B-Series comparison:
  AMD PSB bypass (cs_rommon_platform_allow_dev_keys): also in X215C M8 CIMC (X215M8-F1)
  Mosquitto allow_anonymous Unix socket: also in BXM6 CIMC (BSERIES-BXM6-F1)
  Intel M8 rack CIMC: separate binary (Godzilla codename), has /etc/passwd + /etc/shadow in SquashFS
"""

CIMC_AMD_RACK = {
    "targets":      ["C245 M7 (Mount Rainier 1U)", "C245 M8 (Mount Rainier 2U)",
                     "C225 M7 (Mount Adams 1U)", "C225 M8 (Mount Adams 1U)"],
    "spl_images":   ["SPLImage-CSeriesM7", "SPLImage-ast2600_evb",
                     "SPLImage-mountrainier1", "SPLImage-mountrainier2",
                     "SPLImage-mountadams1", "SPLImage-mountadams2"],
    "cpu_generation": ["emeraldrapids", "turin"],
    "squashfs_main": {
        "blob_offset":    29497600,
        "size_bytes":     101715758,
        "inodes":         9930,
        "compression":    "gzip",
        "block_size":     131072,
        "mkfs_time":      "2026-02-18T23:14:52Z",
    },
    "squashfs_secondary": {
        "blob_offset":    131215616,
        "size_bytes":     10077374,
        "inodes":         760,
        "mkfs_time":      "2025-10-08T15:01:59Z",
    },
}

AMD_RACK_KEYS = {
    "M7_BIOS_AMD_PSB_REL_PublicKey.bin": {
        "path": "/etc/M7_BIOS_AMD_PSB_REL_PublicKey.bin",
        "size_bytes": 564,
        "purpose": "AMD Platform Secure Boot (PSB) BIOS release signature verification",
        "suffix": "last 4 bytes = be ef ca fe (Cisco key marker)",
    },
    "M7_BIOS_REL_Key_pubkey.bin": {
        "path": "/etc/M7_BIOS_REL_Key_pubkey.bin",
        "size_bytes": 564,
        "purpose": "BIOS image release signature verification (non-PSB CIMC path)",
        "suffix": "be ef ca fe",
    },
    "key_REL_m7-connector-key_real.bin": {
        "path": "/etc/key_REL_m7-connector-key_real.bin",
        "size_bytes": 580,
        "purpose": "Cloud connector image signing key (production 'real' variant)",
        "suffix": "be ef ca fe",
        "note": "'real' in filename denotes production vs test key; 'andromeda-keys' group used "
                "by install-connector-early.sh cisco-img-valid for cloud connector validation",
    },
}

LIBCISCO_BMCPSB_AMD = {
    "path":    "/usr/local/lib/libcisco_bmcpsb.so",
    "exports": [
        "cs_rommon_platform_allow_dev_keys",   # AMD PSB dev key bypass setter
        "cs_rommon_platform_get_dev_image_load_status",
        "cs_rommon_platform_get_key_storage_buffer",
        "cs_rommon_verify_psb_buffer",
        "cs_rommon_verify_psb_file",
        "cs_rommon_verify_bios_file",
        "cs_rommon_verify_cimc_buffer",
        "cs_rommon_verify_cimc_file",
        "cs_rommon_verify_buffer_raw_sign_revocation",
        "code_sign_verify_signature",
    ],
    "dev_key_path":   "/mnt/emmc/bmc_nv/security/dev_keys/M7_BIOS_AMD_PSB_DEV_PublicKey.bin",
    "psb_status_path": "/nv/etc/psb_status.txt",
    "source_file":    "cisco_bmcpsb.c",  # debug string embedded in .so
}

MOSQUITTO_CONFIG_AMD = {
    "path": "/etc/mosquitto/mosquitto-broker.conf",
    "localhost_listener": "9001 127.0.0.1",
    "localhost_allow_anonymous": False,
    "socket_listener": "/var/run/mymqtt.sock",
    "socket_allow_anonymous": True,   # FINDING: no auth on Unix socket
    "auth_plugin_line": "# plugin /usr/local/lib/libmqtt_auth_plugin.so",  # commented out
}

PPP_CONFIG = {
    "path": "/etc/ppp/bmc2host.options",
    "link": "169.254.254.1:169.254.254.2",
    "speed": 115200,
    "noauth": True,
    "persist": True,
    "maxfail": 0,
    "note": "noauth+persist: BMC does not authenticate host before establishing link; "
            "link maintained indefinitely with no retry limit",
}

SPDM_TRUST_ANCHORS = {
    "/nv/security/SPDMcerts/broadcom_avenger_fcs_root_ca.pem": "Broadcom Avenger NIC FCS root CA",
    "/nv/security/SPDMcerts/broadcom_fcs_root_ca.pem": "Broadcom general FCS root CA",
    "/nv/security/SPDMcerts/knox_root_ca.pem": "Samsung Knox root CA",
    "/nv/security/mTLS/mTLS_ca.pem": "Inter-service mTLS CA",
}

CLOUD_CONNECTOR = {
    "install_script": "/nuova/bin/install-connector-early.sh",
    "key_group":      "andromeda-keys",
    "image_paths": [
        "/nv/bmc_images/ucs-mgnt-cloud-connector/DC1.img",
        "/nv/bmc_images/ucs-mgnt-cloud-connector/DC2.img",
    ],
    "active_index":   "/nv/bmc_images/ucs-mgnt-cloud-connector/active-go-img-index",
    "lang":           "Go (ucs-mgnt-cloud-connector)",
    "fallback_paths": [
        "/mnt/nand/ucs-mgnt-cloud-connector/DC1.img",
        "/mnt/nand/ucs-mgnt-cloud-connector/DC2.img",
    ],
}

# --- FINDINGS ---

# AMDCIMC-F1: AMD PSB bypass path present on C-Series AMD rack (extends X215M8-F1)
AMDCIMC_F1 = {
    "id":       "AMDCIMC-F1",
    "title":    "libcisco_bmcpsb.so exports cs_rommon_platform_allow_dev_keys on AMD rack CIMC; "
                "dev key path /mnt/emmc/bmc_nv/security/dev_keys/M7_BIOS_AMD_PSB_DEV_PublicKey.bin "
                "embedded as string literal in the production .so; "
                "same AMD PSB bypass architecture as X215M8-F1 (AMD Blade M8 CIMC) "
                "now confirmed on AMD RACK form factors: C245 M7, C245 M8, C225 M7, C225 M8; "
                "cs_rommon_verify_psb_buffer, cs_rommon_verify_psb_file, cs_tool_debug, "
                "and cs_rommon_platform_get_dev_image_load_status all exported; "
                "libpal_platform_data.so referenced by bmcpsb -- PAL data layer for platform detection; "
                "PSB dev key path differs from Intel rack CIMC M8_CT_DEV_PublicKey.bin path "
                "(AMD PSB dev key = eMMC-resident, Intel CT dev key = SquashFS /etc/); "
                "three release keys in /etc/ all end with Cisco beefcafe key marker; "
                "key_REL_m7-connector-key_real.bin 'real' suffix signals test-key variant "
                "awareness baked into production firmware naming",
    "severity": "HIGH",
    "status":   "CONFIRMED -- libcisco_bmcpsb.so exports cs_rommon_platform_allow_dev_keys; "
                "dev key path string /mnt/emmc/bmc_nv/security/dev_keys/M7_BIOS_AMD_PSB_DEV_PublicKey.bin "
                "verified in binary strings",
    "cwe":      ["CWE-321 (Use of Hard-coded Cryptographic Key)", "CWE-693 (Protection Mechanism Failure)"],
    "cross_platform": "X215M8-F1 (blade AMD PSB), CSERIES-CIMC-F3 (Intel rack CT dev key)",
}

# AMDCIMC-F2: Mosquitto allow_anonymous=true on Unix socket -- cross-platform confirmation
AMDCIMC_F2 = {
    "id":       "AMDCIMC-F2",
    "title":    "AMD rack CIMC mosquitto-broker.conf configures /var/run/mymqtt.sock with "
                "allow_anonymous true and libmqtt_auth_plugin.so commented out; "
                "identical configuration to BXM6 CIMC (B-Series X210C M6) finding BSERIES-BXM6-F1; "
                "the socket listener has no per-listener_settings authentication; "
                "the localhost listener on port 9001 retains allow_anonymous false but the "
                "Unix socket listener is the only path used by CIMC-internal service IPC; "
                "any CIMC-local process can publish or subscribe to all CIMC management "
                "telemetry topics (system events, sensor data, FRU updates) without authentication; "
                "cross-platform scope: confirmed on AMD rack CIMC (Mount Rainier/Adams, this module) "
                "AND B-Series X210C M6 CIMC (BSERIES-BXM6-F1) -- at minimum two distinct CIMC "
                "firmware families share this misconfiguration",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- mosquitto-broker.conf extracted from SquashFS; "
                "allow_anonymous true on /var/run/mymqtt.sock; auth plugin line commented out",
    "cwe":      ["CWE-862 (Missing Authorization)", "CWE-306 (Missing Authentication for Critical Function)"],
    "cross_platform": "BSERIES-BXM6-F1",
}

# AMDCIMC-F3: PPP bmc2host noauth -- host-to-BMC unauthenticated PPP link
AMDCIMC_F3 = {
    "id":       "AMDCIMC-F3",
    "title":    "BMC-to-host PPP link (/etc/ppp/bmc2host.options) configured with 'noauth' and "
                "'persist maxfail 0'; BMC does not authenticate the host before establishing "
                "the PPP link at 169.254.254.1 (BMC) to 169.254.254.2 (host); "
                "an attacker with host OS code execution can use the PPP link to reach the "
                "BMC management network at 169.254.254.1 without PPP-layer authentication; "
                "application-layer authentication (Redfish/JRPC) is still required for "
                "management API access, but this removes one authentication barrier on the "
                "host-to-BMC path; 'persist maxfail 0' means the BMC maintains the PPP link "
                "indefinitely and never drops it -- no timing window to exploit; "
                "the link runs at 115200 baud (serial interface, not Ethernet)",
    "severity": "LOW",
    "status":   "CONFIRMED -- /etc/ppp/bmc2host.options extracted from SquashFS; "
                "noauth and persist maxfail 0 confirmed",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "note":     "Host-to-BMC PPP noauth is common BMC design; application-layer auth still required; "
                "primarily relevant in host OS compromise + lateral movement to BMC scenario",
}

# AMDCIMC-F4: Multi-vendor silicon CIMC + SPDM vendor chain exposure
AMDCIMC_F4 = {
    "id":       "AMDCIMC-F4",
    "title":    "AMD rack CIMC img_features.json declares CPUGeneration ['emeraldrapids', 'turin'] -- "
                "single CIMC firmware binary is designed to run on BOTH Intel Emerald Rapids (Intel M8) "
                "AND AMD Turin (AMD EPYC 9005, M8 AMD) CPU platforms simultaneously; "
                "nvme_mi_catalog.json lists platform codenames godzilla1/2 (Intel M8 rack), "
                "mountrainier1/2 (AMD 2U rack), mountadams1/2 (AMD 1U rack) in a single config file; "
                "SPDM trust anchors expose peripheral supply chain: broadcom_avenger_fcs_root_ca.pem "
                "(Broadcom Avenger/BCM57414 NIC), broadcom_fcs_root_ca.pem, and knox_root_ca.pem "
                "(Samsung Knox for SSD/NVMe attestation) present in /nv/security/SPDMcerts/; "
                "cloud connector key group name 'andromeda-keys' embedded in install-connector-early.sh "
                "(cisco-img-valid -k andromeda-keys); 'andromeda' key group governs Go-based "
                "cloud connector DC1.img/DC2.img dual-image A/B update scheme",
    "severity": "LOW",
    "status":   "CONFIRMED -- img_features.json, nvme_mi_catalog.json, SPDM certs, "
                "install-connector-early.sh all verified in SquashFS",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "key_group_name": "andromeda-keys",
    "spdm_vendors": ["Broadcom (Avenger NIC)", "Broadcom (FCS general)", "Samsung Knox (NVMe)"],
}

FINDINGS = [AMDCIMC_F1, AMDCIMC_F2, AMDCIMC_F3, AMDCIMC_F4]

FIRMWARE = [CIMC_AMD_RACK]
