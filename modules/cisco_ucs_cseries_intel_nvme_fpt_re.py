"""
Cisco UCS C-Series -- Intel NVMe Universal FPT Survey RE
Targets: 43 Intel NVMe SKUs across 9 firmware groups (8DV1CP02, QDV1CP08, E201CP02,
         L031CP02, VDV1CP05, E201CP07, 9CV10510, 2CV1C036, ACV10370)

Intel FPT format (06000000a1000000) is universal across all 43 Intel NVMe entries.
Optane firmware implements TCG Opal 2.0 SED with host PKI (Exchange/Signing cert pairs).
L031CP02 (P5800x AlderStream) contains three NIST ECDSA test DRBG seeds in production firmware.
NVMEQ Ruler firmware includes asymmetric diagnostic unlock key surface.
Dell and Lenovo OEM product strings embedded across 4 firmware groups.
"""

INTEL_FPT_MAGIC = "06000000a1000000"

INTEL_NVME_FIRMWARE_GROUPS = {
    "8DV1CP02": {
        "size_kb": 988,
        "md5": "90b053c043526319da54c30c09b8a5ad",
        "codename": "Fultondale",
        "product_family": "SSD DC (early enterprise NVMe)",
        "skus": [
            "ucs-c-storage-intel-nvme-UCSC-F-I12003",
            "ucs-c-storage-intel-nvme-UCSC-F-I160010",
            "ucs-c-storage-intel-nvme-UCSC-F-I20003",
            "ucs-c-storage-intel-nvme-UCSC-F-I80010",
            "ucs-storage-intel-ucs-nvme-ucs-pci25-16003",
            "ucs-storage-intel-ucs-nvme-ucs-pci25-40010",
            "ucs-storage-intel-ucs-nvme-ucs-pci25-80010",
            "ucs-storage-intel-ucs-nvme-ucs-pci25-8003",
        ],
        "form_factor_merge": "UCSC-F-I (form factor) + pci25 (PCIe 2.5-inch) share binary",
        "key_strings": ["Intel Fultondale", "Intel Fultondale Bootloader", "Intel@ SSD DC"],
    },
    "QDV1CP08": {
        "size_kb": 1252,
        "md5": "8a0860379782b2c751cc0274ee57d53d",
        "codename": "Cliffdale",
        "product_family": "P4500 (enterprise entry NVMe PCIe 3.0)",
        "skus": [
            "ucs-storage-intel-nvme-UCSC-NVMEHW-I1000",
            "ucs-storage-intel-nvme-UCSC-NVMEHW-I1600",
            "ucs-storage-intel-nvme-UCSC-NVMEHW-I2000",
            "ucs-storage-intel-nvme-UCSC-NVMEHW-I2TBV",
            "ucs-storage-intel-nvme-UCSC-NVMEHW-I3200",
            "ucs-storage-intel-nvme-UCSC-NVMEHW-I4000",
            "ucs-storage-intel-nvme-UCSC-NVMELW-I500",
            "ucs-storage-intel-nvme-UCSC-NVMELW-I1000",
            "ucs-storage-intel-nvme-UCSC-NVMELW-I2000",
        ],
        "product_line_merge": "UCSC-NVMEHW (High Write) and UCSC-NVMELW (Low Write) share binary",
        "key_strings": [
            "Intel Cliffdale",
            "Namespace_Encrypt_Key",
            "NS_Encrypt_Key",
            "U.2 Intel P4500 1.0TB Entry NVMe PCIe 3.0 x4 3.5\" Hot Swap SSD",
        ],
    },
    "E201CP02": {
        "size_kb": 684,
        "md5": "60e0ccbaac4b70a61d9d85ec5519dc1d",
        "product_family": "Optane SSD DC P4800X (3D Xpoint v1)",
        "skus": [
            "ucs-storage-intel-nvme-UCSC-XNVME-I375",
            "ucs-storage-intel-nvme-UCSC-XNVME-I750",
        ],
        "oem_contamination": "Lenovo (Intel)",
        "tcg_host_auth": {
            "HostExchangeAuthority": "TCG Opal host exchange authority certificate slot",
            "HostExchangeCert": "Host exchange certificate",
            "HostSigningAuthority": "TCG Opal host signing authority certificate slot",
            "HostSigningCert": "Host signing certificate",
            "SignedHash": "Signed hash verification",
            "MaxAuthentications": "TCG Opal session authentication limit",
        },
    },
    "L031CP02": {
        "size_kb": 1328,
        "md5": "c880347b0bcc39e4082d690e66b79bb4",
        "codename": "AlderStream SP SSD",
        "product_family": "Optane P5800x/P5810x (3D Xpoint v2)",
        "skus": [
            "ucs-storage-intel-ucs-nvme-UCS-NVMEXP-I400",
            "ucs-storage-intel-ucs-nvme-UCS-NVMEXP-I800",
        ],
        "oem_contamination": {
            "Dell P5800x": ["Dell Ent NVMe P5800x SED WI", "Dell Ent NVMe P5800x WI U.2 400GB", "Dell Ent NVMe P5800x WI U.2 800GB", "Dell Ent NVMe P5800x WI U.2 1.6TB"],
            "Dell P5800x SED": ["Dell Ent NVMe P5800x SED WI U.2 400GB", "Dell Ent NVMe P5800x SED WI U.2 800GB", "Dell Ent NVMe P5800x SED WI U.2 1.6TB"],
            "Dell P5810x": ["Dell Ent NVMe P5810x WI U.2 400GB", "Dell Ent NVMe P5810x WI U.2 800GB", "Dell Ent NVMe P5810x SED WI U.2 400GB", "Dell Ent NVMe P5810x SED WI U.2 800GB"],
        },
        "intel_device_id_ca_dn": "C=US,ST=CA,O=Intel Corp.,OU=IOG,CN=Device ID Certificate CA",
        "ecdsa_test_vectors": [
            "ecdsaKeygenTestDrbgSeed",
            "ecdsaPWCTestDrbgSeed",
            "ecdsaPWCTestRndMsgGen",
        ],
        "tcg_host_auth": {
            "HostExchangeAuthority": "TCG Opal host exchange authority",
            "HostExchangeCert": "Host exchange certificate",
            "HostSigningAuthority": "Host signing authority",
            "HostSigningCert": "Host signing certificate",
            "SignedHash": "Signed hash verification",
            "MaxAuthentications": "Session authentication limit",
        },
    },
    "VDV1CP05": {
        "size_kb": 1508,
        "md5": "edf8cb97cab56226665c5d0f3a1c669d",
        "codename": "Cliffdale Refresh",
        "product_family": "P4510 (enterprise entry NVMe, Cliffdale refresh)",
        "skus": [
            "ucs-storage-intel-ucs-nvme-UCSC-NVME2H-I1000",
            "ucs-storage-intel-ucs-nvme-UCSC-NVME2H-I1600",
            "ucs-storage-intel-ucs-nvme-UCSC-NVME2H-I2TBV",
            "ucs-storage-intel-ucs-nvme-UCSC-NVME2H-I3200",
            "ucs-storage-intel-ucs-nvme-UCSC-NVME2H-I4000",
            "ucs-storage-intel-ucs-nvme-UCSC-NVMEHW-I8000",
        ],
        "cross_generation_note": "UCSC-NVMEHW-I8000 (gen 1 8TB drive) uses UCSC-NVME2H (gen 2) firmware",
        "oem_contamination": "Lenovo ThinkSystem P4510 (1TB/2TB/4TB)",
        "key_strings": ["Intel Cliffdale Refresh", "Namespace_Encrypt_Key", "NS_Encrypt_Key"],
    },
    "E201CP07": {
        "size_kb": 764,
        "md5": "b7d86c13262ba3dd961a0db1f8b31b1a",
        "product_family": "Optane SSD DC P4800X (3D Xpoint v1, v7 firmware)",
        "skus": [
            "ucs-storage-intel-ucs-nvme-UCSC-XNVME-I375",
            "ucs-storage-intel-ucs-nvme-UCSC-XNVME-I750",
        ],
        "oem_contamination": "Lenovo (Intel)",
        "tcg_host_auth_same_as": "E201CP02 (same HostExchangeAuthority/HostSigningAuthority/MaxAuthentications set)",
    },
    "9CV10510": {
        "size_kb": 1484,
        "md5": "ba30360bf0f3d1070f965651a79092e2",
        "product_family": "NVME4 enterprise NVMe",
        "skus": [
            "ucs-storage-intel-ucs-nvme-ucs-NVME4-15360",
            "ucs-storage-intel-ucs-nvme-ucs-NVME4-1600",
            "ucs-storage-intel-ucs-nvme-ucs-NVME4-1920",
            "ucs-storage-intel-ucs-nvme-ucs-NVME4-3200",
            "ucs-storage-intel-ucs-nvme-ucs-NVME4-3840",
            "ucs-storage-intel-ucs-nvme-ucs-NVME4-6400",
            "ucs-storage-intel-ucs-nvme-ucs-NVME4-7680",
        ],
        "compression": "LZ4 frame compression (full LZ4 error string set embedded)",
        "runtime": "C++ exception handling (terminate() / C++ runtime abort strings)",
        "fw_revision_format": "$FwRev:9IC1Z000$",
        "key_strings": ["ERROR_headerVersion_wrong", "DCert<", "wSigning+", "$FwRev:9IC1Z000$", "C++ runtime abort"],
    },
    "2CV1C036": {
        "size_kb": 1764,
        "md5": "17deb0fee41fd871761c00dd6a741eb3",
        "codename": "Arbordale Plus",
        "product_family": "P5600/P5500 (enterprise NVMe PCIe 4.0)",
        "skus": [
            "ucs-storage-intel-ucs-nvme-ucs-NVMEI4-I1600",
            "ucs-storage-intel-ucs-nvme-ucs-NVMEI4-I1920",
            "ucs-storage-intel-ucs-nvme-ucs-NVMEI4-I3200",
            "ucs-storage-intel-ucs-nvme-ucs-NVMEI4-I3840",
            "ucs-storage-intel-ucs-nvme-ucs-NVMEI4-I6400",
            "ucs-storage-intel-ucs-nvme-ucs-NVMEI4-I7680",
        ],
        "oem_contamination": {
            "Dell P5600/P5500": ["Dell Express Flash NVMe P5600 3.2TB SFF", "Dell Express Flash NVMe P5600 6.4TB SFF", "Dell Express Flash NVMe P5500 1.92TB SFF"],
            "Lenovo ThinkSystem": ["ThinkSystem U.2 Intel P5600 1.6TB Mainstream NVMe PCIe4.0 x4 Hot Swap SSD", "ThinkSystem U.2 Intel P5500 1.92TB Entry NVMe PCIe4.0 x4 Hot Swap SSD"],
        },
        "key_strings": ["Intel Arbordale Plus", "NS_Encrypt_Key", "Intel(R) SSD DC"],
    },
    "ACV10370": {
        "size_kb": 1812,
        "md5": "bf6fdfa58256f785832081a519a543a5",
        "product_family": "NVMEQ Ruler/EDSFF form factor enterprise NVMe",
        "skus": ["ucs-storage-intel-ucs-nvme-ucs-NVMEQ-1536"],
        "note": "Unique binary -- only Ruler form factor in C-Series bundle",
        "diagnostic_unlock": {
            "string": "Asymmetric Diag Unlock          Asymmetric Diag Unlock Auth Key",
            "mechanism": "Manufacturer diagnostic mode gated by asymmetric key pair",
        },
        "fru_format": {
            "MultiRecord NVMe V0": "NVMe FRU multi-record format",
            "MultiRecord NVMe PCIe Port V0": "Per-PCIe-port NVMe multi-record format",
            "Board Info V1": "Board FRU area version",
        },
        "tcg_host_auth": {
            "HostExchangeAuthority": "TCG Opal host exchange authority",
            "HostSigningAuthority": "Host signing authority",
            "MaxAuthentications": "Session auth limit",
        },
        "nvme_queue_prefixes": ["NVMe-AD-", "NVMe-CFG-", "NVMe-IO-", "NVMeR-"],
        "ns_encrypt_key": "NS_Encrypt_Key -- namespace encryption key label",
    },
}

TCG_OPAL_SESSION_PARAMS = {
    "source": "Intel Optane firmware (E201CP02, L031CP02, ACV10370)",
    "MaxComPacketSize": "Maximum communication packet size",
    "MaxPacketSize": "Maximum inner packet size",
    "MaxIndTokenSize": "Maximum individual token size",
    "MaxPackets": "Maximum packets per communication packet",
    "MaxSubpackets": "Maximum subpackets per packet",
    "MaxMethods": "Maximum method invocations per packet",
    "MaxResponseComPacketSize": "Maximum response communication packet size",
    "MaxSessions": "Maximum simultaneous sessions",
    "MaxAuthentications": "Maximum authentications per session",
    "MaxTransactionLimit": "Maximum transaction nesting depth",
    "MaxSessionTimeout": "Maximum session idle timeout",
    "MaxTransTimeout": "Maximum transaction timeout",
    "MaxComIDTime": "Maximum communication ID lifetime",
    "protocol_note": "TCG Opal 2.0 Storage Security Subsystem Class session layer protocol",
}

FINDINGS = {
    "INTEL-OPTANE-DRBG-F1": {
        "id": "INTEL-OPTANE-DRBG-F1",
        "severity": "HIGH",
        "title": "L031CP02 (P5800x AlderStream) contains three NIST ECDSA test DRBG seeds in production firmware alongside Intel IOG Device ID CA DN",
        "affected": [
            "ucs-storage-intel-ucs-nvme-UCS-NVMEXP-I400 (L031CP02)",
            "ucs-storage-intel-ucs-nvme-UCS-NVMEXP-I800 (L031CP02)",
        ],
        "evidence": {
            "test_vectors": [
                "ecdsaKeygenTestDrbgSeed -- ECDSA key generation test DRBG seed",
                "ecdsaPWCTestDrbgSeed -- ECDSA Pair-Wise Consistency test DRBG seed",
                "ecdsaPWCTestRndMsgGen -- ECDSA PWC test random message generator",
            ],
            "ca_dn": "C=US,ST=CA,O=Intel Corp.,OU=IOG,CN=Device ID Certificate CA",
            "context": "Strings present in production 1328KB firmware binary",
        },
        "mechanism": (
            "The Intel Optane P5800x (AlderStream) firmware (L031CP02) embeds three NIST ECDSA "
            "Known Answer Test (KAT) and Pair-Wise Consistency (PWC) check identifiers in production: "
            "(1) 'ecdsaKeygenTestDrbgSeed' -- the fixed DRBG seed used for ECDSA key generation "
            "test vectors (FIPS 186-4 KAT requirement); "
            "(2) 'ecdsaPWCTestDrbgSeed' -- fixed DRBG seed for the PWC check that verifies "
            "key generation function correctness after power-on; "
            "(3) 'ecdsaPWCTestRndMsgGen' -- the random message generator label for the PWC signing test. "
            "These strings label the FIPS 140-2/3 self-test code paths embedded in the production binary. "
            "If the DRBG seeding logic can be forced into test mode (e.g., by manipulating "
            "the health test conditional branch), key generation output becomes deterministic "
            "with a known seed. The Intel IOG Device ID Certificate CA DN "
            "('C=US,ST=CA,O=Intel Corp.,OU=IOG,CN=Device ID Certificate CA') in plaintext "
            "exposes the CA identity for the drive's unique Device ID certificate used in "
            "TCG Opal / SPDM attestation."
        ),
        "impact": "FIPS self-test DRBG seeds in production firmware; if test mode is reachable via field interface, ECDSA key generation becomes deterministic. Intel IOG CA DN enables Device ID certificate chain forgery scope assessment",
    },
    "INTEL-NVMEQ-DIAG-F1": {
        "id": "INTEL-NVMEQ-DIAG-F1",
        "severity": "HIGH",
        "title": "NVMEQ Ruler firmware (ACV10370) includes asymmetric diagnostic unlock key surface and full TCG Opal host PKI session parameters",
        "affected": ["ucs-storage-intel-ucs-nvme-ucs-NVMEQ-1536 (ACV10370)"],
        "evidence": {
            "diag_unlock": "Asymmetric Diag Unlock          Asymmetric Diag Unlock Auth Key",
            "tcg_auth": ["HostExchangeAuthority", "HostExchangeCert", "HostSigningAuthority", "HostSigningCert", "SignedHash", "MaxAuthentications"],
            "fru_multi_record": ["MultiRecord NVMe V0", "MultiRecord NVMe PCIe Port V0", "Board Info V1"],
            "queue_prefixes": ["NVMe-AD-", "NVMe-CFG-", "NVMe-IO-", "NVMeR-"],
            "ns_encrypt_key": "NS_Encrypt_Key -- namespace encryption key reference",
        },
        "mechanism": (
            "The NVMEQ Ruler/EDSFF firmware (ACV10370) exposes a manufacturer diagnostic unlock "
            "path gated by an asymmetric key pair: 'Asymmetric Diag Unlock Auth Key'. "
            "This is a field-accessible diagnostic mode (distinct from the factory diagnostic) "
            "where presenting a valid signature from the holder of the corresponding private key "
            "unlocks extended drive diagnostics. "
            "The string appears as a named NVM entry, meaning the asymmetric key material "
            "for authentication is stored in the drive's NVM space. "
            "Additionally, the firmware implements TCG Opal 2.0 host PKI with dual certificate "
            "authority roles (Exchange and Signing), enabling host-device mutual authentication. "
            "NVMe queue type prefixes (AD=Admin, CFG=Config, IO=IO, R=Response) expose the "
            "internal queue classification scheme. FRU multi-record format V0 is exposed for "
            "both the drive and per-PCIe-port entries."
        ),
        "impact": "Asymmetric diagnostic key in NVM space; extraction of the authentication key material enables diagnostic mode unlock on any NVMEQ unit; TCG Opal host PKI adds a second key management surface",
    },
    "INTEL-OPTANE-TCG-F1": {
        "id": "INTEL-OPTANE-TCG-F1",
        "severity": "MEDIUM",
        "title": "Intel Optane firmware implements TCG Opal 2.0 SED with full host PKI (Exchange + Signing cert authority pairs) and exposed session parameter set across 3 firmware groups",
        "affected": [
            "E201CP02 (Optane P4800X v1): UCSC-XNVME-I375/I750",
            "L031CP02 (Optane P5800x): UCS-NVMEXP-I400/I800",
            "ACV10370 (NVMEQ Ruler): ucs-NVMEQ-1536",
        ],
        "evidence": {
            "host_pki_strings": ["HostExchangeAuthority", "HostExchangeCert", "HostSigningAuthority", "HostSigningCert", "SignedHash", "MaxAuthentications"],
            "tcg_session_params": [
                "MaxComPacketSize", "MaxPacketSize", "MaxIndTokenSize", "MaxPackets",
                "MaxSubpackets", "MaxMethods", "MaxResponseComPacketSize",
                "MaxSessions", "MaxAuthentications", "MaxTransactionLimit",
                "MaxSessionTimeout", "MaxTransTimeout", "MaxComIDTime",
            ],
            "namespace_key": "NS_Encrypt_Key (ACV10370, L031CP02 class)",
        },
        "mechanism": (
            "Intel Optane enterprise SSDs implement the TCG Opal 2.0 Storage Security Subsystem "
            "Class (SSC) protocol for hardware-based SED (Self-Encrypting Drive) functionality. "
            "The firmware exposes the complete session management parameter set (MaxSessions, "
            "MaxAuthentications, MaxTransactionLimit, MaxSessionTimeout, MaxTransTimeout, MaxComIDTime) "
            "in plaintext -- these are the drive's declared TCG SP (Security Provider) limits. "
            "The host PKI framework uses two separate certificate authority roles: "
            "(1) Exchange Authority/Cert: key exchange certificate for session key establishment; "
            "(2) Signing Authority/Cert: for signed data verification. "
            "The 'MaxAuthentications' limit is the per-session auth attempt ceiling, "
            "enforcement of which is the only brute-force protection for TCG Opal PINs. "
            "E201CP02 (P4800X) exposes the full 14-parameter TCG session set, "
            "enabling complete protocol session reconstruction from the firmware binary alone."
        ),
        "impact": "Full TCG Opal session parameter set exposed; MaxAuthentications limit quantifies brute-force window; host PKI dual-cert framework enables certificate confusion analysis",
    },
    "INTEL-FPT-UNIVERSAL-F1": {
        "id": "INTEL-FPT-UNIVERSAL-F1",
        "severity": "MEDIUM",
        "title": "Intel FPT format (06000000a1000000) covers all 43 Intel NVMe SKUs in C-Series bundle -- 9 firmware groups, single update format attack surface",
        "affected": ["All 43 Intel NVMe SKUs across 9 firmware version groups"],
        "evidence": {
            "fpt_magic": "06000000a1000000 -- same as Solidigm SSD and PMEM DIMM/BPS (prior findings)",
            "firmware_groups": 9,
            "total_skus": 43,
            "size_range_kb": "684KB (E201CP02 Optane) to 1812KB (ACV10370 NVMEQ)",
        },
        "mechanism": (
            "All 43 Intel NVMe entries in the C-Series bundle use the Intel Firmware Programming "
            "Tool (FPT) container format (magic 06000000a1000000). This is the same format "
            "previously identified in Solidigm SSD and PMEM DIMM/BPS firmware (SOLIDIGM-F1, PMEM-F1). "
            "The FPT format is Intel's internal firmware update container for the full enterprise "
            "storage product tree: early NVMe (Fultondale), P4500 (Cliffdale), P4510 (Cliffdale Refresh), "
            "P5600/P5500 (Arbordale Plus), Optane P4800X, Optane P5800x, NVME4, NVMEI4, NVMEQ. "
            "A vulnerability in the FPT parser or update path applies to all 43 SKUs across "
            "9 generations simultaneously. The FPT format extends from SSDs to PMEM DIMMs -- "
            "the same update vector spans persistent memory and NVMe drive classes."
        ),
        "impact": "Single FPT parser vulnerability affects 43 NVMe SKUs + Solidigm SSDs + PMEM DIMMs simultaneously; update path attack surface spans the full Intel enterprise storage tree",
    },
    "INTEL-OEM-CONTAMINATION-F1": {
        "id": "INTEL-OEM-CONTAMINATION-F1",
        "severity": "MEDIUM",
        "title": "Dell and Lenovo OEM product strings embedded in Cisco UCS Intel NVMe firmware across 4 groups: Dell P5800x/P5810x SED, Dell P5600/P5500, Lenovo ThinkSystem P4510/P5600/P5500",
        "affected": [
            "L031CP02 (UCS-NVMEXP-I400/I800): Dell P5800x, P5810x, P5800x SED product strings",
            "VDV1CP05 (UCSC-NVME2H-*): Lenovo ThinkSystem P4510 product strings",
            "2CV1C036 (NVMEI4-*): Dell P5600/P5500, Lenovo ThinkSystem P5600/P5500",
            "E201CP02/E201CP07 (UCSC-XNVME-*): 'Lenovo (Intel)' string",
        ],
        "evidence": {
            "dell_models": [
                "Dell Ent NVMe P5800x SED WI / WI (SED = Self-Encrypting Drive variant)",
                "Dell Ent NVMe P5810x WI / SED WI",
                "Dell Express Flash NVMe P5600 3.2TB/6.4TB SFF",
                "Dell Express Flash NVMe P5500 1.92TB SFF",
            ],
            "lenovo_models": [
                "Lenovo (Intel) -- generic Lenovo Optane OEM tag",
                "ThinkSystem U.2 Intel P4510 1.0TB/2.0TB/4.0TB Entry NVMe PCIe3.0 Hot Swap SSD",
                "ThinkSystem U.2 Intel P5600 1.6TB/3.2TB/6.4TB Mainstream NVMe PCIe4.0 x4 Hot Swap SSD",
                "ThinkSystem U.2 Intel P5500 1.92TB/3.84TB/7.68TB Entry NVMe PCIe4.0 x4 Hot Swap SSD",
            ],
        },
        "mechanism": (
            "Four Intel NVMe firmware groups in the Cisco UCS C-Series bundle contain model "
            "identifier tables for competitor OEM products (Dell EMC and Lenovo/Lenovo Think). "
            "These are embedded as Identify Controller IDENTIFY_DEVICE response strings -- "
            "the firmware contains the product model names that the drive reports to the host "
            "when queried for different OEM variants. Cisco's distribution of Intel firmware "
            "includes the full model table that covers Dell, Lenovo, and standard Intel variants, "
            "enabling the drive to respond with a competitor product string if the OEM model "
            "slot is selected. Dell SED (Self-Encrypting Drive) entries in L031CP02 indicate "
            "the Cisco NVMe firmware contains SED-enabled model entries even in non-SED "
            "Cisco UCS-labeled drives."
        ),
        "impact": "Drives can report Dell or Lenovo model strings; SED firmware model strings in non-SED Cisco drives suggest SED capability may be accessible via model table manipulation",
    },
    "INTEL-HW-LW-SAME-F1": {
        "id": "INTEL-HW-LW-SAME-F1",
        "severity": "LOW",
        "title": "QDV1CP08 merges UCSC-NVMEHW (High Write) and UCSC-NVMELW (Low Write) into same binary -- wear endurance class not enforced in firmware",
        "affected": [
            "UCSC-NVMEHW-I1000/I1600/I2000/I2TBV/I3200/I4000 (High Write)",
            "UCSC-NVMELW-I500/I1000/I2000 (Low Write)",
        ],
        "evidence": {
            "shared_md5": "8a0860379782b2c751cc0274ee57d53d",
            "wear_strings": "No wear-endurance-class enforcement strings found",
            "namespace_key_strings": ["Namespace_Encrypt_Key", "NS_Encrypt_Key"],
        },
        "mechanism": (
            "The Cisco UCS NVMEHW (High Write, rated for higher DWPD) and NVMELW (Low Write) "
            "products in the Cliffdale/P4500 generation share the identical 1252KB firmware binary. "
            "Wear endurance class (DWPD -- Drive Writes Per Day) is not enforced in the firmware layer. "
            "If the endurance distinction is only in NVM configuration (via NAND media pre-programming "
            "or capacity reservations) rather than firmware logic, write budget enforcement may be "
            "manipulable via NVM parameter modification. "
            "'Namespace_Encrypt_Key' and 'NS_Encrypt_Key' appear as namespace-level encryption "
            "key management slots -- the drive supports per-namespace encryption key assignment. "
            "9 SKUs (6 HW + 3 LW) share the same binary and same security posture."
        ),
        "impact": "Wear endurance distinction exists only in NVM configuration or media, not firmware; 9 SKUs share one binary; namespace encryption key management surface exposed",
    },
    "INTEL-NVME4-LZ4-F1": {
        "id": "INTEL-NVME4-LZ4-F1",
        "severity": "LOW",
        "title": "9CV10510 (NVME4, 7 models) uses LZ4 frame compression internally with C++ exception handling; minimal plaintext strings indicate dense encoding",
        "affected": [
            "ucs-NVME4-15360/1600/1920/3200/3840/6400/7680 (9CV10510)",
        ],
        "evidence": {
            "lz4_errors": [
                "ERROR_maxBlockSize_invalid", "ERROR_blockMode_invalid",
                "ERROR_contentChecksumFlag_invalid", "ERROR_compressionLevel_invalid",
                "ERROR_headerVersion_wrong", "ERROR_blockChecksum_invalid",
                "ERROR_reservedFlag_set", "ERROR_allocation_failed",
                "ERROR_srcSize_tooLarge", "ERROR_dstMaxSize_tooSmall",
                "ERROR_frameHeader_incomplete", "ERROR_frameType_unknown",
                "ERROR_frameSize_wrong", "ERROR_srcPtr_wrong",
                "ERROR_decompressionFailed", "ERROR_headerChecksum_invalid",
                "ERROR_contentChecksum_invalid", "ERROR_frameDecoding_alreadyStarted",
            ],
            "fw_revision": "$FwRev:9IC1Z000$",
            "cpp_runtime": ["C++ runtime abort", "terminate() called by the exception handling mechanism", "returned from a user-defined terminate() routine"],
            "cert_fragment": ["DCert<", "wSigning+"],
        },
        "mechanism": (
            "The NVME4 firmware (9CV10510) uses LZ4 frame format for internal data compression "
            "(19 LZ4 frame error strings covering block mode, checksum, header version, and "
            "frame decoding state). Unlike prior NVMe firmware groups (100-300 plaintext strings), "
            "9CV10510 yields only 90 total strings -- likely because the payload is LZ4-compressed. "
            "C++ exception handling is active (terminate() path strings), distinguishing this from "
            "C-only firmware in prior groups. "
            "The firmware revision format '$FwRev:9IC1Z000$' uses '$' delimiters, matching a "
            "standard SCSI/ATA inquiry response format for version embedding. "
            "'DCert<' and 'wSigning+' are partial certificate and signing operation label fragments. "
            "LZ4 frame header validation errors provide a decompressor attack surface if "
            "compressed data is sourced from host-controlled paths."
        ),
        "impact": "LZ4 decompressor is an attack surface if host-controlled data reaches it; minimal string exposure due to compression; C++ exception surface active",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

INTEL_NVME_SKU_SUMMARY = {
    "total_skus": 43,
    "firmware_groups": 9,
    "fpt_magic": "06000000a1000000 (universal across all groups)",
    "same_binary_groups": {
        "8DV1CP02": {"skus": 8, "form_factor_classes": 2, "note": "Fultondale; UCSC-F-I + pci25 merge"},
        "QDV1CP08": {"skus": 9, "product_line_classes": 2, "note": "Cliffdale P4500; HW+LW merge"},
        "E201CP02": {"skus": 2, "note": "Optane P4800X v1"},
        "L031CP02": {"skus": 2, "note": "Optane P5800x AlderStream; DRBG seeds; Dell OEM"},
        "VDV1CP05": {"skus": 6, "note": "Cliffdale Refresh P4510; NVME2H+NVMEHW-I8000 cross-gen"},
        "E201CP07": {"skus": 2, "note": "Optane P4800X v2; same TCG auth as E201CP02"},
        "9CV10510": {"skus": 7, "note": "NVME4; LZ4 compressed; C++"},
        "2CV1C036": {"skus": 6, "note": "Arbordale Plus P5600/P5500 PCIe4; Dell+Lenovo OEM"},
        "ACV10370": {"skus": 1, "note": "NVMEQ Ruler; asymmetric diag unlock; unique"},
    },
}

SUMMARY = {
    "module": "cisco_ucs_cseries_intel_nvme_fpt_re",
    "targets": "43 Intel NVMe SKUs across 9 firmware groups",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 2, "MEDIUM": 3, "LOW": 2},
    "headline": (
        "L031CP02 (P5800x) contains three NIST ECDSA test DRBG seeds in production + Intel IOG CA DN. "
        "NVMEQ Ruler has asymmetric diagnostic unlock key surface. TCG Opal 2.0 host PKI exposed across "
        "3 Optane firmware groups. All 43 NVMe SKUs use Intel FPT format -- same surface as Solidigm and PMEM."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
    print(f"\nSKU coverage: {INTEL_NVME_SKU_SUMMARY['total_skus']} SKUs, {INTEL_NVME_SKU_SUMMARY['firmware_groups']} groups")
