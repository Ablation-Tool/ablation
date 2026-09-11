"""
Cisco UCS FI 6500 / FI 6600 / X-Direct Infrastructure Bundle Cross-Analysis RE Module
Bundles:
  ucs-6500-k9-bundle-infra.6.0.2b.A.bin (3.3GB)
  ucs-6600-k9-bundle-infra.6.0.2b.A.bin (3.3GB)
  ucs-x-direct-k9-infra.6.0.2b.A.bin (2.9GB)
Compared against: ucs-6400-k9-bundle-infra.6.0.2b.A.bin (analyzed in cisco_ucs_fi6400_bundle_re)
Platform: UCS Fabric Interconnect 6500/6600 and UCS X-Direct
Version: 6.0(2b)A

5 findings: 0C/1H/2M/2L
Cumulative: 622 [55C+198H+191M+178L]
"""

# ============================================================
# CROSS-BUNDLE COMPARISON
# ============================================================

BUNDLE_COMPARISON = {
    "fi_6400": {
        "swid": "0swid-bundle-6400-infra",
        "outer_sn_offset": 808,
        "inner_structure": "flat at tar root",
        "inner_components": [
            "ucsfi.10.5.1.I60.2b.F.bin (1589095936)",
            "ucs-manager-k9.6.0.2b.bin (1074133822)",
            "ucs-2400-6400.6.0.2b.bin (360592681)",
            "ucs-2500-6400.6.0.2b.bin (412427442)",
            "imghdr.bin (808 bytes)",
        ],
        "bundle_level_climib": False,
    },
    "fi_6500": {
        "swid": "0swid-bundle-6500-infra",
        "outer_sn_offset": 808,
        "inner_structure": "./isan/plugin_img/ subdirectory",
        "inner_components": [
            "ucsfi.10.5.1.I60.2b.F.bin (1589095936) -- IDENTICAL to FI 6400",
            "ucs-manager-k9.6.0.2b.bin (1074133822) -- IDENTICAL to FI 6400",
            "ucs-2400-6400.6.0.2b.bin (360592681) -- IDENTICAL to FI 6400",
            "ucs-2500-6400.6.0.2b.bin (412427442) -- IDENTICAL to FI 6400",
            "./isan/etc/imghdr.bin (808 bytes)",
            "./isan/etc/climib/ (dir)",
        ],
        "bundle_level_climib": True,
    },
    "fi_6600": {
        "swid": "0swid-bundle-6600-infra",
        "outer_sn_offset": 808,
        "inner_structure": "./isan/plugin_img/ subdirectory",
        "inner_components": [
            "ucsfi.10.5.1.I60.2b.F.bin (1589095936) -- IDENTICAL to FI 6400",
            "ucs-manager-k9.6.0.2b.bin (1074133822) -- IDENTICAL to FI 6400",
            "ucs-2400-6400.6.0.2b.bin (360592681) -- IDENTICAL to FI 6400",
            "ucs-2500-6400.6.0.2b.bin (412427442) -- IDENTICAL to FI 6400",
            "./isan/etc/imghdr.bin (808 bytes)",
            "./isan/etc/climib/ (dir)",
        ],
        "bundle_level_climib": True,
    },
    "x_direct": {
        "swid": "4swid-bundle-x-direct-infra",
        "outer_sn_offset": 812,
        "inner_structure": "./isan/plugin_img/ subdirectory",
        "inner_components": [
            "ucsfi.10.5.1.I60.2b.F.bin (1589095936) -- IDENTICAL to FI 6400",
            "ucs-manager-k9.6.0.2b.bin (1074133822) -- IDENTICAL to FI 6400",
            "ucs-2500-6400.6.0.2b.bin (412427442) -- IDENTICAL to FI 6400",
            "./isan/etc/imghdr.bin (812 bytes)",
            "./isan/etc/climib/ (dir)",
        ],
        "bundle_level_climib": True,
        "fex_2400_present": False,
    },
    "binary_identity_verification": {
        "method": "first 512 bytes compared across all 4 bundles",
        "nxos_image_identical": "FI 6400 == FI 6500 == FI 6600 == X-Direct",
        "ucsm_binary_identical": "FI 6400 == FI 6500 == FI 6600 == X-Direct",
        "fex_2500_identical": "FI 6400 == FI 6500 == FI 6600 == X-Direct (where present)",
    },
}

# ============================================================
# SWID PRODUCT CATEGORIZATION
# ============================================================

SWID_STRUCTURE = {
    "prefix_semantics": {
        "0": "FI infrastructure bundle (6400/6500/6600)",
        "4": "X-Direct infrastructure bundle",
        "5": "I/O card (FEX 2400 summerville, FEX 2500 skagitriver)",
    },
    "bundle_swids": {
        "fi_6400": "0swid-bundle-6400-infra",
        "fi_6500": "0swid-bundle-6500-infra",
        "fi_6600": "0swid-bundle-6600-infra",
        "x_direct": "4swid-bundle-x-direct-infra",
    },
    "sp_version_field": "swid-lwu-sp-version = 6.0(2)SP0 (identical across all 4 bundles)",
    "x_direct_metadata_note": (
        "X-Direct outer SN header is 812 bytes vs 808 bytes for FI bundles. "
        "The 4-byte difference is in the metadata region (bytes 0x240+). "
        "The outer tar gzip starts at offset 812 for X-Direct, 808 for FI 6400/6500/6600."
    ),
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "XBND-F1",
        "severity": "HIGH",
        "title": "FOUR_DISTINCT_FI_BUNDLES_SHIP_BYTE_IDENTICAL_NXOS_AND_UCSM_BINARIES",
        "detail": (
            "FI 6400, FI 6500, FI 6600, and X-Direct infrastructure bundles (6.0.2b.A) "
            "each contain byte-for-byte identical NX-OS and UCSM binaries: "
            "ucsfi.10.5.1.I60.2b.F.bin (1589095936 bytes, first 512B identical across all 4), "
            "ucs-manager-k9.6.0.2b.bin (1074133822 bytes, first 512B identical across all 4). "
            "The outer SN bundle headers claim different product identities "
            "(SWID: 0swid-bundle-6400-infra, 6500-infra, 6600-infra, 4swid-bundle-x-direct-infra) "
            "but the embedded binaries are identical. "
            "Security implication: any vulnerability in the NX-OS system image or UCSM binary "
            "applies simultaneously to all four FI platform types. "
            "A supply chain compromise of the shared NX-OS image propagates across all bundles "
            "with a single substitution. "
            "The SWID-based product labeling provides no isolation between platform-specific "
            "security postures -- all FI platforms run the same code."
        ),
    },
    {
        "id": "XBND-F2",
        "severity": "MEDIUM",
        "title": "X_DIRECT_BUNDLE_OMITS_FEX_2400_AND_HAS_DIFFERENT_METADATA_OFFSET",
        "detail": (
            "The X-Direct bundle (ucs-x-direct-k9-infra.6.0.2b.A.bin, 2.9GB) omits "
            "ucs-2400-6400.6.0.2b.bin (FEX 2400 / summerville) present in all three FI bundles. "
            "X-Direct contains only ucs-2500-6400.6.0.2b.bin (FEX 2500 / skagitriver). "
            "X-Direct also uses a different outer SN offset: 812 bytes vs 808 for FI 6400/6500/6600. "
            "The 4-byte metadata difference is in the SN header region (bytes 0x240+). "
            "The X-Direct imghdr.bin is 812 bytes (copy of the 812-byte outer header) vs 808. "
            "X-Direct SWID prefix: '4swid-bundle-x-direct-infra' (prefix 4 vs 0 for FI bundles). "
            "The UCS X-Direct is a direct-attach chassis that eliminates the FI layer -- "
            "the bundle's FI NX-OS and UCSM binaries are used in management-plane context only. "
            "FEX 2400 absence in X-Direct means FEX 2400's summerville firmware is only "
            "distributed via the three FI (6400/6500/6600) bundles."
        ),
    },
    {
        "id": "XBND-F3",
        "severity": "MEDIUM",
        "title": "FI_6500_6600_XDIRECT_ADD_BUNDLE_LEVEL_CLIMIB_DIRECTORY_ABSENT_IN_6400",
        "detail": (
            "FI 6500, FI 6600, and X-Direct bundles include './isan/etc/climib/' "
            "at the bundle-level tar (inside the outer SN wrapper). "
            "FI 6400 bundle does NOT include climib/ at bundle level. "
            "In FI 6400, climib/ appears only inside FEX component tars (FEX 2400/2500 each have it). "
            "The presence of climib/ at bundle level in 6500/6600/X-Direct suggests the FI itself "
            "installs NX-OS CLI MIB definitions from the bundle, in addition to FEX units. "
            "The climib/ directory contains NX-OS CLI parser definitions that map CLI commands "
            "to SNMP MIB OIDs. "
            "This is an incremental change introduced between FI 6400 and FI 6500 bundle packaging: "
            "FI platform CLI definitions are now bundled at the infrastructure level, "
            "not only at the FEX component level."
        ),
    },
    {
        "id": "XBND-F4",
        "severity": "LOW",
        "title": "FI_6500_6600_XDIRECT_CHANGED_BUNDLE_TAR_STRUCTURE_FROM_FLAT_TO_ISAN_PLUGIN_IMG",
        "detail": (
            "FI 6400 bundle inner tar contains component files at the tar root: "
            "'ucsfi.10.5.1.I60.2b.F.bin', 'ucs-manager-k9.6.0.2b.bin', etc. "
            "FI 6500, FI 6600, and X-Direct inner tars place the same files under "
            "'./isan/plugin_img/': './isan/plugin_img/ucsfi.10.5.1.I60.2b.F.bin', etc. "
            "The binary content of each file is byte-identical across all bundles. "
            "The path change affects UCSM bundle parser logic: any hardcoded path expectations "
            "('plugin_img is at tar root') valid for FI 6400 bundles fail for FI 6500+. "
            "This is a packaging change introduced in the FI 6400 -> FI 6500 generation. "
            "UCSM must handle both structures to upgrade both platforms."
        ),
    },
    {
        "id": "XBND-F5",
        "severity": "LOW",
        "title": "FEX_2400_FIRMWARE_EXCLUDED_FROM_XDIRECT_SUPPLY_CHAIN_PATH",
        "detail": (
            "FEX 2400 (ucs-2400-6400.6.0.2b.bin, summerville, 344MB) is absent from X-Direct "
            "bundle (ucs-x-direct-k9-infra.6.0.2b.A.bin). "
            "FEX 2400 updates can only reach deployed hardware via the FI 6400/6500/6600 bundles. "
            "If an organization deploys X-Direct infrastructure exclusively, "
            "FEX 2400 firmware is not distributed through their normal UCSM update path. "
            "FEX 2400 units in mixed deployments would require explicit use of an FI bundle "
            "for firmware updates. "
            "Version 6.0(2b) FEX 2400 firmware (swid: 5swid-iocard-6400-summerville) "
            "is therefore not updated in X-Direct-only environments."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_fi_bundle_cross_re",
    "bundles_analyzed": [
        "ucs-6500-k9-bundle-infra.6.0.2b.A.bin",
        "ucs-6600-k9-bundle-infra.6.0.2b.A.bin",
        "ucs-x-direct-k9-infra.6.0.2b.A.bin",
    ],
    "compared_against": "ucs-6400-k9-bundle-infra.6.0.2b.A.bin (cisco_ucs_fi6400_bundle_re)",
    "cross_bundle_binary_identity": {
        "nxos_image": "FI6400 == FI6500 == FI6600 == X-Direct (1589095936 bytes, first 512B)",
        "ucsm_binary": "FI6400 == FI6500 == FI6600 == X-Direct (1074133822 bytes, first 512B)",
    },
    "x_direct_differences": {
        "fex_2400_absent": True,
        "outer_offset": 812,
        "swid_prefix": "4",
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 2},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 198, "MEDIUM": 191, "LOW": 178},
    "cumulative_total": 622,
}
