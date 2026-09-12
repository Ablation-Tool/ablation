"""
Cisco UCS ESU (Extended Service Unit) Firmware Bundle RE

Targets: esu-firmware-6.0.1.251006.tar.gz
         esu-firmware-6.0.2.260026.tar.gz
         esu-firmware-6.0.2.260034.tar.gz
         esu-firmware-6.0.2.260143.tar.gz
         UCS XE ESU firmware bundles for UCSXE-ECMC-10G platform
         Components: CMC, PSU (3 models), pdbFPGA, eCMCFPGA, MTS, slamlatch
Files:   Catalog.json (update manifest, md5sums, plugin dispatch)
         CMC/6.0.2.260036/chassisA.img (CMC firmware, 55AA boot magic)
         PSU/*.bin (*_unsigned.bin for all 3 PSU models)
         slamlatch/v*/tSHL-PP-APP-FW-*.upg (CUPG magic header)
         eCMCFPGA/, pdbFPGA/ (FPGA .spi images)
         MTS/*/image_*_official_key.bin
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_esu_firmware_re",
    "firmware": (
        "esu-firmware-6.0.1.251006.tar.gz / "
        "esu-firmware-6.0.2.260026.tar.gz / "
        "esu-firmware-6.0.2.260034.tar.gz / "
        "esu-firmware-6.0.2.260143.tar.gz"
    ),
    "components": {
        "Catalog.json": (
            "Update manifest; 8 firmware components; "
            "secure-copy: {enabled: false} on ALL components; "
            "integrity: md5sum only; "
            "no SHA-256, no RSA signature field, no downgrade protection"
        ),
        "PSU firmware (3 models)": (
            "QCS_UCSXE-PSU-2400W, MEG_UCSXE-PSU-2400W, MEG_UCSXE-PSU-2400WDC; "
            "all named *_combined_unsigned.bin; "
            "explicit absent signature in filename AND catalog"
        ),
        "CMC/6.0.2.260036/chassisA.img": (
            "55 AA magic (bootable image header); "
            "MD5 = 2b80736a5c0... (260143) vs bc64937116e... (260034); "
            "no signature field in catalog"
        ),
        "slamlatch .upg": (
            "CUPG magic header; proprietary Cisco update format; "
            "no visible crypto verification strings in binary"
        ),
        "MTS image": (
            "image_Aldrin3S_*_official_key.bin naming suggests key-signed; "
            "catalog shows MD5 as sole integrity check regardless"
        ),
    },
    "finding_count": "6F [0C+3H+3M+0L]",
    "cumulative": "759 [72C+255H+240M+192L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "Secure-copy transport disabled for all 8 ESU firmware components",
        "description": (
            "Catalog.json in all four ESU bundle versions specifies "
            "'secure-copy': {'enabled': false} for every firmware component: "
            "pdbFPGA, CMC, PSU (3 models), eCMCFPGA, MTS, slamlatch. "
            "The 'swupdate' OOB plugin is used for delivery; "
            "with secure-copy disabled, firmware binaries are transferred "
            "over unencrypted transport. "
            "An attacker with MITM position on the management network during "
            "an ESU update session can substitute any firmware component in transit "
            "with a malicious binary. "
            "The MD5 check in Catalog.json is read from the same Catalog.json "
            "that the attacker can also modify."
        ),
        "evidence": {
            "catalog_field": "secure-copy: {enabled: false} on all 8 components (6.0.1 through 6.0.2.260143)",
            "components": "pdbFPGA, CMC, PSU x3, eCMCFPGA, MTS, slamlatch",
        },
        "impact": (
            "MITM during ESU update delivers malicious firmware to CMC, PSU, or FPGA components "
            "on the UCSXE-ECMC-10G chassis. "
            "CMC compromise = chassis management control. "
            "PSU compromise = power delivery control and potential hardware damage."
        ),
        "remediation": "Enable secure-copy on firmware delivery. Verify firmware over authenticated TLS.",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "PSU firmware explicitly unsigned across all ESU versions",
        "description": (
            "All three PSU firmware files across all four ESU versions are named "
            "'*_combined_unsigned.bin': "
            "QCS_UCSXE-PSU-2400W_1.6.0.0_3.5.0.0_combined_unsigned.bin (6.0.2), "
            "MEG_UCSXE-PSU-2400W_4.0.2.0_4.0.0.0_combined_unsigned.bin, "
            "MEG_UCSXE-PSU-2400WDC_4.0.0.0_4.0.0.0_combined_unsigned.bin. "
            "In 6.0.1, PSU firmware was QCS_UCSXE-PSU-2400W_1.5.0.0_3.4.0.0_combined_unsigned.bin "
            "(same naming convention). "
            "The Catalog.json has no signature field for PSU components, "
            "only MD5 checksums. "
            "The PSU binary header (c7 71 54 00 ...) contains embedded product string "
            "'QCS_UCSXE-PSU-2400W_Pri_V1.6.0_26Nov2025.bin' with no crypto material. "
            "PSU firmware update via swupdate delivers an unsigned binary with no "
            "on-device signature verification."
        ),
        "evidence": {
            "filenames": (
                "esu-firmware-6.0.1.251006: QCS_UCSXE-PSU-2400W_1.5.0.0_3.4.0.0_combined_unsigned.bin; "
                "esu-firmware-6.0.2.*: same pattern, updated version number"
            ),
            "header_bytes": "c7 71 54 00 82 ff 80 81 ... (custom PSU format, no RSA field)",
            "catalog_integrity": "md5sum only, no signature field",
        },
        "impact": (
            "Malicious PSU firmware can be flashed without signature verification. "
            "PSU firmware controls power delivery, monitoring, and protection circuits. "
            "Malicious PSU firmware can induce hardware damage or persistent implant "
            "at the power supply level, surviving OS reinstallation."
        ),
        "remediation": (
            "Apply digital signatures to PSU firmware images before distribution. "
            "Implement on-device RSA signature verification before PSU firmware application."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "MD5-only integrity checking for CMC, FPGA, and MTS firmware updates",
        "description": (
            "Catalog.json uses md5sum as the sole integrity check for all firmware components: "
            "CMC chassisA.img, pdbFPGA .spi, eCMCFPGA .spi, MTS image, slamlatch .upg. "
            "MD5 is broken for collision resistance: "
            "identical-prefix collision attacks can produce two files with the same MD5. "
            "With secure-copy disabled (F1), an attacker can replace a firmware binary "
            "and compute a matching MD5 in the Catalog.json. "
            "The MTS component is named 'image_Aldrin3S_1.0.2.2_official_key.bin' "
            "suggesting an intended key-signing mechanism, "
            "but the catalog verifies only MD5."
        ),
        "evidence": {
            "catalog_fields": "md5sum present; no sha256, no sha512, no rsa_signature field",
            "mts_filename": "image_Aldrin3S_1.0.2.2_official_key.bin (name implies key, catalog uses MD5)",
            "cmc_md5_diff": (
                "CMC md5 changed between 6.0.2.260034 (bc64937116e...) and "
                "6.0.2.260143 (2b80736a5c0...) -- confirms live firmware updates"
            ),
        },
        "impact": (
            "MD5 collision allows substituting malicious CMC or FPGA firmware while "
            "passing the catalog integrity check. "
            "CMC compromise gives chassis management control."
        ),
        "remediation": "Replace MD5 with SHA-256 or SHA-512 in Catalog.json. Add RSA signatures for critical components.",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "slamlatch firmware uses proprietary CUPG format with no visible signature mechanism",
        "description": (
            "slamlatch/v25082018/tSHL-PP-APP-FW-v25082018.upg uses a proprietary 'CUPG' "
            "magic header format (bytes: 43 55 50 47 01 00 00 00 ...). "
            "Binary strings analysis yields no crypto-related strings (no RSA, SHA, cert, verify, key). "
            "The slamlatch appears to be firmware for a physical chassis latch mechanism. "
            "With only MD5 catalog integrity (F3) and no secure-copy (F1), "
            "the CUPG format provides no additional security. "
            "The CUPG format is not publicly documented."
        ),
        "evidence": {
            "header": "43 55 50 47 01 00 00 00 ff ff ff ff (CUPG magic)",
            "strings_output": "No crypto/signature strings found in binary",
        },
        "impact": (
            "Malicious slamlatch firmware can be delivered without verification. "
            "Physical chassis latch control compromised."
        ),
        "remediation": "Document CUPG format. Add RSA signature verification to slamlatch update path.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "CMC firmware update with bootable-image header (55 AA) and MD5-only integrity",
        "description": (
            "CMC/6.0.2.260036/chassisA.img has the 55 AA boot magic header "
            "followed by structured data (00 05 80 05 80 5f 01 00 ...). "
            "CMC is the Chassis Management Controller for the UCSXE-ECMC-10G. "
            "The 55 AA header indicates the image is bootable/executable by the CMC processor. "
            "Catalog.json verifies only MD5 with no digital signature for this image. "
            "chassisA.img changed between 6.0.2.260034 and 6.0.2.260143, "
            "confirming active development and frequent update paths."
        ),
        "evidence": {
            "header_hex": "55 aa 00 05 80 05 80 5f 01 00 00 00 (55 AA boot magic)",
            "catalog_integrity": "md5sum=2b80736a5c00b9c96a7a0c4f7c64e304 only",
            "update_history": "MD5 differs between 6.0.2.260034 and 6.0.2.260143",
        },
        "impact": (
            "A crafted chassisA.img with a matching MD5 collision or MITM-replaced binary "
            "achieves arbitrary code execution on the CMC processor with chassis management access."
        ),
        "remediation": "Add RSA signature verification for CMC firmware before execution.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "No firmware version downgrade protection in ESU catalog",
        "description": (
            "Catalog.json specifies 'packaged_version' for each component "
            "but contains no minimum version requirement, no version comparison policy, "
            "and no anti-rollback field. "
            "The swupdate plugin receives the firmware path and version from Catalog.json "
            "without on-device version-gate enforcement. "
            "An attacker who can deliver a crafted ESU tarball with an older vulnerable "
            "component version can downgrade the target component to a known-vulnerable state. "
            "PSU versions in ESU: 6.0.1 (1.5.0.0) vs 6.0.2 (1.6.0.0) -- "
            "downgrading via modified catalog is structurally possible."
        ),
        "evidence": {
            "catalog_field": "packaged_version present; no min_version or rollback_protection field",
            "version_example": "PSU 1.5.0.0 (6.0.1) vs 1.6.0.0 (6.0.2) -- rollback possible",
        },
        "impact": (
            "Rollback to vulnerable component firmware versions by delivering a "
            "modified catalog with an older packaged_version. "
            "Enables re-exploitation of patched vulnerabilities in PSU, FPGA, or CMC firmware."
        ),
        "remediation": "Add minimum version enforcement in the swupdate plugin. Implement secure anti-rollback counters in CMC and PSU.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
