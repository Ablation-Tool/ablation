"""
Cisco UCS B-Series M5/M6 and X210C M8 BIOS Capsule RE
Targets: B200 M5 BIOS 4.3.2g, B200 M6 BIOS 6.0.2a, B210 M6 (aka X210C M6) BIOS 6.0.2a,
         X210C M8 BIOS 6.0.2b
Source: ucs-k9-bundle-b-series.6.0.2b.B.bin

SN entry offsets in decompressed bundle (1163MB stream):
  B200 M5: decomp+613006336 (hsize=896, standard gzip -- NOT wbits=47)
  B200 M6: decomp+622008320 (hsize=876)
  B210 M6: decomp+632383488 (hsize=876)  [bundle SN name says b210, PKG internal name says X210M6]
  X210C M8: decomp+655498240 (hsize=868)

Decompression note: these SN entries use standard gzip (wbits=31 via zlib.decompress) NOT the
wbits=47 Cisco encoding used in B480M5/X410M7; gzip.decompress() fails because it tries to
iterate multi-stream and hits non-gzip data after the first stream end.

Extraction chain (B200 M5):
  SN+896 gzip -> TAR (blob + imghdr.bin) -> blob gzip -> TAR -> B200M5-BIOS-4-3-2g-0.cap
  -> [CISCO UCS BIOS CIMCPackage] header (ImageOffset=2048, ACM_SVN=2, KM/BPM=0)
  -> bzip2 payload -> LFBC SPI image (32MB, same format as B480M5)
  Signing cert: CN=CiscoSystems;OU=Presidio;O=CiscoSystems

Extraction chain (B200 M6 / B210 M6):
  SN+876 gzip -> TAR -> blob gzip -> TAR -> B200M6-BIOS-6-0-2a-0.pkg / X210M6-...-0.pkg
  -> [CISCO UCS BIOS CIMCPackage] (ImageOffset=2048, no SVN fields)
  -> gzip payload -> PAX tar (package.json, BiosUpdate.json v1, ImageFeatures.json,
                               BiosTokens.json 206 tokens, biosFiles/)
  Signing cert: CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems

Extraction chain (X210C M8):
  SN+868 gzip -> TAR -> blob gzip -> TAR -> X210M8-BIOS-6-0-2b-0.pkg
  -> [CISCO UCS BIOS CIMCPackage] (ImageOffset=8192)
  -> gzip payload (18MB) -> PAX tar -> BiosUpdate.json v3 + 64MB BIOS binary

GNR stepping qualification matrix (confirmed across 4 platforms, 2 generations):
  X-Series M7:  X210C (2S) = C06F1 (step 1)  |  X410C (4S) = C06F2 (step 2)
  X-Series M8:  X210C (2S) = A06D1 (step 1)  |  X410C (4S) = A06D2 (step 2)
  Cisco consistently qualifies an earlier GNR stepping for 2-socket platforms vs 4-socket.

Platform codename families:
  Presidio:        B-Series M5 (B200 M5, B480 M5) -- shared OU=Presidio PKI chain
  JalamaBeachMR1:  B-Series M6 (B200 M6) AND B-to-X transition (B210 M6 / X210C M6) -- OU=BIOS_IMG
  LajollaBeachMR4: X-Series M8 Intel (X210C M8, X410C M8) -- same codename, same 64MB flash layout
  LaJollaBeach:    X-Series M8 AMD (X215C M8) -- AMD variant of LajollaBeach family
"""

FIRMWARE_B200M5 = {
    "target":            "Cisco UCS B200 M5 BIOS 4.3.2g",
    "file":              "ucs-b200-m5-bios.B200M5.4.3.2g.0.0116260829.bin",
    "model":             "UCS B200 M5 (2-socket Intel Xeon Scalable, B-Series Blade)",
    "platform_codename": "Presidio",  # same PKI family as B480 M5
    "signing_cert_dn":   "CN=CiscoSystems;OU=Presidio;O=CiscoSystems",
    "build_account":     "cspgre / eng",
    "image_version":     "B200M5.4.3.2g.0.0116260829",
    "image_offset":      2048,
    "capsule_format":    "Cisco CIMCPackage + bzip2(LFBC SPI image) -- same as B480 M5",
    "acm_svn_authorized": 2,
    "km_svn":            0,
    "bpm_svn":           0,
    "spi_size_mb":       32,
    "bios_tokens":       False,  # LFBC format -- no PAX tar, no BiosTokens.json
    "findings":          ["B200M5BIOS-F1", "B200M5BIOS-F2"],
}

FIRMWARE_B200M6 = {
    "target":            "Cisco UCS B200 M6 BIOS 6.0.2a",
    "file":              "ucs-b200-m6-bios.B200M6.6.0.2a.0.0121260813.bin",
    "model":             "UCS B200 M6 (2-socket Intel Xeon Ice Lake-SP, B-Series Blade)",
    "platform_codename": "JalamaBeachMR1",  # B-Series M6 platform family
    "signing_cert_dn":   "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
    "build_account":     "cspgre / eng",
    "image_version":     "B200M6.6.0.2a.0.0121260813",
    "image_offset":      2048,
    "biosupdate_version": 1,
    "cisco_signed":      "Enabled",
    "cpu_id":            "606a6",  # Intel Xeon Ice Lake-SP (3rd Gen): family 6, model 0x6A, step 6
    "cpu_ids_array":     None,     # v1 format uses only CpuId, not CpuIds array
    "bios_token_count":  206,
    "bios_file":         "biosFiles/B200/M6/606a6/B200M6.6.0.2a.0.cap",
    "image_features":    "ImageFeatures.json (AdopterBUPIDs compatibility block list)",
    "boot_guard_svns":   "ABSENT",
    "findings":          ["JALAMABEACH-F1", "JALAMABEACH-F2", "JALAMABEACH-F3"],
}

FIRMWARE_B210M6 = {
    "target":            "Cisco UCS B210 M6 BIOS 6.0.2a (aka X210C M6)",
    "file":              "ucs-b210-m6-bios.X210M6.6.0.2a.0.0121260813.bin",
    "model":             "UCS B210 M6 / X210C M6 (2-socket Intel Xeon Ice Lake-SP)",
    "platform_codename": "JalamaBeachMR1",  # SHARED with B200 M6 -- same BIOS platform base
    "pkg_internal_name": "X210M6-BIOS-6-0-2a-0.pkg",  # bundle says B210, PKG says X210M6
    "signing_cert_dn":   "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
    "build_account":     "cspgre / eng",
    "image_version":     "X210M6.6.0.2a.0.0121260813",
    "image_offset":      2048,
    "biosupdate_version": 1,
    "cisco_signed":      "Enabled",
    "cpu_id":            "606a6",
    "bios_token_count":  206,
    "bios_file":         "biosFiles/X210/M6/606a6/X210M6.6.0.2a.0.cap",
    "bios_size_bytes":   10345266,  # vs B200M6: 10345235 -- 31-byte difference, not identical
    "boot_guard_svns":   "ABSENT",
    "findings":          ["JALAMABEACH-F1", "JALAMABEACH-F2"],  # same findings as B200M6
}

FIRMWARE_X210M8 = {
    "target":            "Cisco UCS X210C M8 BIOS 6.0.2b",
    "file":              "ucs-x210-m8-bios.X210M8.6.0.2b.0.0130261958.bin",
    "model":             "UCS X210C M8 (2-socket Intel Xeon GNR, X-Series Compute Node)",
    "platform_codename": "LajollaBeachMR4",  # SHARED with X410C M8 -- same codename, both 2S and 4S
    "signing_cert_dn":   "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
    "build_account":     "cspgre / eng",
    "image_version":     "X210M8.6.0.2b.0.0130261958",
    "image_offset":      8192,
    "biosupdate_version": 3,
    "cisco_signed":      "Enabled",
    "cpu_ids":           ["A06D1"],  # Intel GNR step 1 (vs X410C M8's A06D2 step 2)
    "bios_file":         "biosFiles/X210/M8/X210M8.6.0.2b.0.bin",
    "bios_size_mb":      64,
    "bios_token_count":  223,
    "boot_guard_svns":   "ABSENT",
    "fit4_offset":       38132640,   # identical to X410C M8 -- same flash layout
    "intelpda_offset":   17694720,   # identical to X410C M8
    "intelpda_size":     131072,
    "findings":          ["X210M8BIOS-F1", "X210M8BIOS-F2", "X410M8BIOS-F1"],  # F1 shared with X410M8
}

# --- FINDINGS ---

# B200M5BIOS-F1: B200 M5 shares Presidio PKI + Boot Guard SVN=0 with B480 M5
B200M5BIOS_F1 = {
    "id":       "B200M5BIOS-F1",
    "title":    "B200 M5 BIOS uses OU=Presidio signing certificate and identical Boot Guard "
                "ACM_SVN=2, KM_SVN=0, BPM_SVN=0 to B480 M5 (B480BIOS-F1); "
                "confirms Presidio PKI chain covers the entire B-Series M5 blade family "
                "(B200 M5 2-socket and B480 M5 4-socket); "
                "a single Cisco private key compromise (CN=CiscoSystems;OU=Presidio) affects "
                "all deployed Presidio-platform blades; Boot Guard provides no SVN revocation "
                "for either KM or BPM on any B-Series M5 system",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- B200M5-BIOS-4-3-2g-0.cap: ImageACM_SVN_Authorized=2, "
                "ImageKM_SVN=0, ImageBPM_SVN=0; same as B480M5.4.3.2g; same Presidio DN",
    "cwe":      ["CWE-757", "CWE-327"],
    "affected_platforms": ["B200 M5 (Presidio)", "B480 M5 (Presidio)"],
    "cert_dn":  "CN=CiscoSystems;OU=Presidio;O=CiscoSystems",
    "svns":     {"ACM_SVN_Authorized": 2, "KM_SVN": 0, "BPM_SVN": 0},
}

# B200M5BIOS-F2: B200 M5 LFBC format -- no BiosTokens.json, BIOS security config opaque
B200M5BIOS_F2 = {
    "id":       "B200M5BIOS-F2",
    "title":    "B200 M5 and B480 M5 BIOS use the older LFBC SPI image format (bzip2 payload) "
                "with no BiosUpdate.json, BiosTokens.json, or per-section signing metadata; "
                "all B-Series M5 BIOS security configuration (SGX defaults, TPM policy, "
                "Secure Boot defaults) is encoded inside the 32MB LFBC SPI image without "
                "a structured token manifest; the M6 generation (B200M6/X210M6) introduced "
                "PAX tar wrapping with BiosTokens.json (206 tokens) and BiosUpdate.json v1; "
                "the M5 BIOS has 9 UEFI firmware volumes (confirmed for B480 M5) containing "
                "AMI BIOS framework with LENOVO_SYSTEM_* GUIDs and SecurityStubDxe -- "
                "without the token manifest, customers have no structured view of factory defaults",
    "severity": "LOW",
    "status":   "CONFIRMED -- B200M5 blob decompresses to B200M5-BIOS-4-3-2g-0.cap (LFBC, 32MB); "
                "no PAX tar wrapper; BiosTokens.json first appears in B200M6 6.0.2a",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "format_transition": {
        "M5 (4.3.2g)": "CIMCPackage + bzip2 -> LFBC 32MB SPI (no token manifest)",
        "M6 (6.0.2a)": "CIMCPackage + gzip -> PAX tar -> BiosUpdate v1 + BiosTokens 206 tokens",
        "M7 (6.0.2a)": "CIMCPackage + gzip -> PAX tar -> BiosUpdate v2 + BiosTokens 218 tokens",
        "M8 (6.0.2b)": "CIMCPackage + gzip -> PAX tar -> BiosUpdate v3 (RSA-4096) + 223 tokens",
    },
}

# JALAMABEACH-F1: SGX open launch policy on Ice Lake-SP (B-Series M6 gen)
JALAMABEACH_F1 = {
    "id":       "JALAMABEACH-F1",
    "title":    "B200 M6 and B210 M6 (X210C M6) BIOS ship SGX Launch Enclave Write enabled "
                "(SgxLeWr=Enabled) with all four LE public key hash registers at zero; "
                "confirms SGX open launch policy spans ALL Intel Xeon UCS platforms: "
                "Ice Lake-SP (B200M6, B210M6), Sapphire Rapids (X210M7, X410M7), "
                "Granite Rapids (X210M8, X410M8); 206 security tokens on IceLake platform "
                "vs 218-223 on SPR/GNR -- SGX token set present on all but the baseline "
                "configuration is open launch policy across every generation",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- BiosTokens.json B200M6 6.0.2a: SgxLeWr=Enabled, "
                "SgxLePubKeyHash0/1/2/3=0, EnableSgx=Disabled; B210M6 identical",
    "cwe":      ["CWE-276 (Incorrect Default Permissions)"],
    "affected_generations": {
        "Ice Lake-SP (IceLake)":    "B200 M6 / B210 M6 (JalamaBeachMR1) -- 206 tokens",
        "Sapphire Rapids":          "X210C M7 / X410C M7 (KellerBeachMR2) -- 218 tokens",
        "Granite Rapids":           "X210C M8 / X410C M8 (LajollaBeachMR4) -- 223 tokens",
    },
    "sgx_tokens": {
        "SgxLeWr": "Enabled", "EnableSgx": "Disabled",
        "SgxLePubKeyHash0": "0", "SgxLePubKeyHash1": "0",
        "SgxLePubKeyHash2": "0", "SgxLePubKeyHash3": "0",
    },
}

# JALAMABEACH-F2: JalamaBeachMR1 shared across B200M6 and B210M6/X210M6 -- platform family disclosure
JALAMABEACH_F2 = {
    "id":       "JALAMABEACH-F2",
    "title":    "B200 M6 and B210 M6 use identical platform codename JalamaBeachMR1 and identical "
                "CpuId 606a6 (Intel Xeon Ice Lake-SP, CPUID family 6 model 0x6A step 6), "
                "confirming B200 M6 and B210 M6 share the same BIOS foundation; "
                "bundle SN entry for B210 M6 is 'ucs-b210-m6-bios' but internal PKG is "
                "'X210M6-BIOS-6-0-2a-0.pkg' with BIOS path biosFiles/X210/M6/ -- reveals "
                "Cisco internally treats the B210 M6 blade as an X210C M6 compute node "
                "(B-to-X branding transition at the M6 generation); "
                "BIOS binaries differ by 31 bytes (B200M6: 10345235 vs X210M6: 10345266) "
                "confirming minor per-SKU customization within the same platform codebase; "
                "Intel Ice Lake-SP pre-dates public availability of BiosTokens -- the M6 "
                "generation introduced structured token manifests to the Cisco BIOS update format",
    "severity": "LOW",
    "status":   "CONFIRMED -- package.json PackageName=JalamaBeachMR1 for both; "
                "CpuId=606a6 in both BiosUpdate.json; PKG name X210M6 in B210M6 bundle",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "cpu_decode": {
        "606a6": "Intel Xeon Ice Lake-SP (3rd Gen Xeon Scalable, Whitley platform, "
                 "CPUID: family=6, extended_model=6, base_model=0xA, step=6, display_model=0x6A)",
    },
    "b_to_x_transition": {
        "bundle_sn_name":  "ucs-b210-m6-bios",
        "pkg_internal":    "X210M6-BIOS-6-0-2a-0.pkg",
        "bios_path":       "biosFiles/X210/M6/606a6/",
        "note": "B210 M6 (B-Series) internally uses X210 naming -- B-Series being renamed/aliased "
                "to X-Series at the M6 generation",
    },
}

# JALAMABEACH-F3: AdopterBUPIDs in ImageFeatures.json -- internal component compatibility IDs exposed
JALAMABEACH_F3 = {
    "id":       "JALAMABEACH-F3",
    "title":    "B200 M6 BiosUpdate.json v1 references ImageFeatures.json via GenericFiles "
                "with RefName='UcsComponentBlockList'; ImageFeatures.json contains 'AdopterBUPIDs' "
                "listing 9 internal Cisco UCS component compatibility identifiers: "
                "DN3-HW-APL, DN3-HW-APL-U, DN3-HW-APL=, DN3-HW-APL-L, DN3-HW-APL-L-U, "
                "DN3-HW-APL-L=, DN3-HW-APL-XL, DN3-HW-APL-XL-U, DN3-HW-APL-XL=; "
                "these BUPID (Bundle Update Package ID) strings are internal UCSM identifiers "
                "for hardware block list enforcement -- exposed in every shipped BIOS package; "
                "GenericFiles/UcsComponentBlockList field is present only in M6 packages; "
                "ImageFeatures.json is absent from M5 (LFBC format) and M7/M8 (dropped field); "
                "the BUPID namespace 'DN3-HW-APL*' reveals internal Cisco UCS component "
                "classification taxonomy not publicly documented",
    "severity": "LOW",
    "status":   "CONFIRMED -- ImageFeatures.json from B200M6.6.0.2a PAX tar, RefName=UcsComponentBlockList; "
                "absent from B200M5 (LFBC), B200M6 v1 but present; absent from M7+ BiosUpdate v2",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "bupids": [
        "DN3-HW-APL", "DN3-HW-APL-U", "DN3-HW-APL=",
        "DN3-HW-APL-L", "DN3-HW-APL-L-U", "DN3-HW-APL-L=",
        "DN3-HW-APL-XL", "DN3-HW-APL-XL-U", "DN3-HW-APL-XL=",
    ],
    "md5sum": "d48d16691122e447deef1b2868dc392a",  # ImageFeatures.json MD5
}

# X210M8BIOS-F1: LajollaBeachMR4 shared between X210C M8 and X410C M8 -- 2S/4S same platform
X210M8BIOS_F1 = {
    "id":       "X210M8BIOS-F1",
    "title":    "X210C M8 and X410C M8 both use platform codename LajollaBeachMR4; "
                "identical BiosUpdate v3 flash layout: FIT4 at offset 38132640 (88 bytes), "
                "IntelPDA at offset 17694720 (128KB), 64MB raw SPI binary; "
                "same per-section RSA-4096 signatures covering FullImage, FD0, FIT4; "
                "identical token count (223) and same SGX/security token defaults; "
                "only differentiator: CpuId (X210C M8 = A06D1, X410C M8 = A06D2); "
                "the 2-socket and 4-socket M8 compute nodes are effectively the same BIOS "
                "platform with per-SKU CPU stepping qualification; "
                "LajollaBeach family spans all three M8 X-Series platforms: "
                "LajollaBeachMR4 (Intel X210/X410 M8) and LaJollaBeach (AMD X215 M8)",
    "severity": "LOW",
    "status":   "CONFIRMED -- package.json PackageName=LajollaBeachMR4 for both X210M8 and X410M8; "
                "FIT4/IntelPDA offsets identical in both BiosUpdate v3 JSON files",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "lajollabeach_full_family": {
        "LajollaBeachMR4 (X210C M8)": "A06D1 (GNR step 1, 2S)",
        "LajollaBeachMR4 (X410C M8)": "A06D2 (GNR step 2, 4S)",
        "LaJollaBeach    (X215C M8)": "A00F00 (AMD EPYC Genoa, 2S)",
    },
}

# X210M8BIOS-F2: GNR stepping qualification matrix -- 2S always one step behind 4S
X210M8BIOS_F2 = {
    "id":       "X210M8BIOS-F2",
    "title":    "Cross-generation Intel Granite Rapids (GNR) stepping qualification pattern: "
                "Cisco consistently pre-qualifies one GNR stepping earlier for 2-socket (X210) "
                "than 4-socket (X410) platforms; confirmed across two hardware generations "
                "and two different GNR silicon stepping series; "
                "implies separate validation programs per socket count and reveals Cisco received "
                "GNR silicon ahead of public availability; stepping delta may reflect "
                "4-socket platforms requiring validated multi-socket cache coherence "
                "while 2-socket validated on prior stepping",
    "severity": "LOW",
    "status":   "CONFIRMED -- BiosUpdate.json CpuIds from X210M7, X410M7, X210M8, X410M8",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "gnr_stepping_matrix": {
        "X-Series M7": {
            "X210C M7 (2S)": {"cpuid": "C06F1", "model": "0xCF", "step": 1},
            "X410C M7 (4S)": {"cpuid": "C06F2", "model": "0xCF", "step": 2},
        },
        "X-Series M8": {
            "X210C M8 (2S)": {"cpuid": "A06D1", "model": "0xAD", "step": 1},
            "X410C M8 (4S)": {"cpuid": "A06D2", "model": "0xAD", "step": 2},
        },
        "pattern": "2S platform: step N; 4S platform: step N+1 (both generations)",
    },
}

FINDINGS = [
    B200M5BIOS_F1, B200M5BIOS_F2,
    JALAMABEACH_F1, JALAMABEACH_F2, JALAMABEACH_F3,
    X210M8BIOS_F1, X210M8BIOS_F2,
]

PLATFORMS = [FIRMWARE_B200M5, FIRMWARE_B200M6, FIRMWARE_B210M6, FIRMWARE_X210M8]

# Cross-platform BIOS format evolution summary
BIOS_FORMAT_EVOLUTION = {
    "M5 (2024, 4.3.2g)": {
        "payload":    "bzip2 -> LFBC 32MB SPI (B480M5, B200M5)",
        "cert_ou":    "Presidio",
        "svn_fields": "Present in CIMCPackage header",
        "tokens":     "None (LFBC format)",
        "biosupdate": "None",
    },
    "M6 (2024, 6.0.2a)": {
        "payload":    "gzip -> PAX tar -> BiosUpdate v1 + 206 tokens (B200M6, B210M6/X210M6)",
        "cert_ou":    "BIOS_IMG",
        "svn_fields": "Absent",
        "tokens":     "206 (Ice Lake-SP)",
        "biosupdate": "v1 (MD5Sum, CpuId singular, GenericFiles/UcsComponentBlockList)",
    },
    "M7 (2026, 6.0.2a)": {
        "payload":    "gzip -> PAX tar -> BiosUpdate v2 + 218 tokens (X210M7, X410M7)",
        "cert_ou":    "BIOS_IMG",
        "svn_fields": "Present in CIMCPackage header",
        "tokens":     "218 (SPR/GNR dual qualification)",
        "biosupdate": "v2 (MD5Sum, CpuIds array, CiscoSignedBinary field)",
    },
    "M8 Intel (2026, 6.0.2b)": {
        "payload":    "gzip -> PAX tar -> BiosUpdate v3 + 223 tokens (X210M8, X410M8)",
        "cert_ou":    "BIOS_IMG",
        "svn_fields": "Absent",
        "tokens":     "223 (GNR only)",
        "biosupdate": "v3 (per-section RSA-4096, FullImage+FD0+FIT4+IntelPDA, 64MB .bin)",
    },
    "M8 AMD (2026, 6.0.2a)": {
        "payload":    "gzip -> PAX tar -> BiosUpdate v1 + 130 tokens (X215M8)",
        "cert_ou":    "BIOS_IMG",
        "svn_fields": "N/A (AMD)",
        "tokens":     "130 (AMD EPYC Genoa -- no SGX/TXT/TME tokens)",
        "biosupdate": "v1 (MD5Sum only, CiscoSignedBinary=DISABLED)",
    },
}
