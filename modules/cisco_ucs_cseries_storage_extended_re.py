"""
Cisco UCS C-Series Bundle RE -- Module 2
Coverage: WDC HDD/SSD families, Seagate NL-SAS and legacy, Micron SSD families,
          Intel NVMe/SATA, Solidigm, Emulex FC HBA, NVMe mswitch, SAS expanders,
          double-decker RAID -- all from C-Series bundle TAR members
Source: /media/cowboy/research/Cisco-UCS/ucs-c-series-m5-6.0.2.260044.A.bin (gzip at hsize=844)
        -> cseries_decomp.bin (3084MB, 728 TAR members)
Session: 29 (C-Series module 2)
"""

# =============================================================================
# WDC HDD FAMILIES -- DD30 / AD30 / A8C2 / D8C2 / A540 / A730 / A9M0 / A2W0
# =============================================================================

WDC_HDD_FAMILIES = {
    "families": [
        # DD30 -- WUH722018CL4205, WUH722012CL4205 -- high-capacity SAS HDD
        # Hits: Encrypt, TCG Enterprise, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth, Debug
        {"fw": "DD30", "models": ["WUH722018CL4205", "WUH722012CL4205"]},

        # AD30 -- WUH722020CL4200 through WUH722012CL4200 -- high-cap SAS HDD
        # Hits: Encrypt, TCG Enterprise, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth, Debug
        {"fw": "AD30", "models": ["WUH722020CL4200", "WUH722018CL4200", "WUH722016CL4200",
                                   "WUH722014CL4200", "WUH722012CL4200"]},

        # A8C2/D8C2 -- WUH721814AL4200, WUH721818AL4205, WUH721816AL4200
        # Hits: Encrypt, TCG Enterprise, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth, Debug
        {"fw": "A8C2/D8C2", "models": ["WUH721814AL4200", "WUH721818AL4205", "WUH721816AL4200"]},

        # A540 -- WDC-WUH722020BL4200 (OptiNAND) -- NOVEL: EraseMaster
        # Hits: Encrypt, EraseMaster, Auth, Debug
        {"fw": "A540", "models": ["WDC-WUH722020BL4200"]},

        # A730 -- WDC-WUH722222AL4200 (OptiNAND) -- NOVEL: EraseMaster
        # Hits: Encrypt, EraseMaster, Auth, Debug
        {"fw": "A730", "models": ["WDC-WUH722222AL4200"]},

        # A9M0 -- WUS721010AL4200 -- older SAS HDD, cert chain without Debug
        # Hits: Encrypt, TCG Enterprise, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        {"fw": "A9M0", "models": ["WUS721010AL4200"]},

        # VXCST9M0 -- WUS721010ALE600 -- legacy SAS, minimal TCG
        # Hits: TCG Enterprise only
        {"fw": "VXCST9M0", "models": ["WUS721010ALE600"]},

        # A2W0 -- WUH721414AL4200 -- cert chain variant
        # Hits: Encrypt, TCG Enterprise, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        {"fw": "A2W0", "models": ["WUH721414AL4200"]},
    ],
    "common_signal": "PresentCertificate + HashAndSign + ReEncrypt -- HGST-lineage TCG cert auth across all WDC SAS HDD families",
    "distinguisher": "A540/A730 OptiNAND adds EraseMaster; VXCST9M0 has only TCG Enterprise marker (pre-cert-chain firmware)",
    "note": "WDC SAS HDDs share TCG Enterprise SSC certificate auth with HGST (confirmed class-wide)",
}

# =============================================================================
# WDC SAS SSD -- D971 FAMILY
# =============================================================================

WDC_SAS_SSD_D971 = {
    "models": [
        # WUSTM3216/3240/3280ASS205, WUSTR1538/1596/1548/6432/6416/6480/6440ASS200/205
        "WUSTM3216ASS205", "WUSTM3280ASS205", "WUSTM3240ASS205",
        "WUSTR1538ASS205", "WUSTR1596ASS205", "WUSTR1548ASS205",
        "WUSTR6432ASS200", "WUSTR6416ASS200", "WUSTR6480ASS200",
        "WUSTR6440ASS200", "WUSTR1538ASS200", "WUSTR1519ASS200",
        "WUSTR1596ASS200", "WUSTR1548ASS200",
    ],
    "fw": "D971",
    "hits": ["Encrypt", "TCG Enterprise", "EraseMaster", "Certificate", "FUSE",
             "PresentCertificate", "HashAndSign", "ReEncrypt"],
    "deep_strings": {
        "FUSE": "FUSEIDS",  # fuse-locked feature ID bitmap, distinct from HGST HDD lineage
        "EraseMaster": ["EraseMaster", "EraseMaster_SetSelf"],
    },
    "note": "SAS SSDs add FUSEIDS (fuse-locked feature gate) absent in HGST/WDC HDD TCG variants",
    "vs_hdd": "HGST SAS HDDs have full cert chain but no FUSE string; D971 SAS SSDs have both",
}

# =============================================================================
# HGST SAS HDD -- ADDITIONAL FAMILIES (D40K / A3Z4 / A40K / A630 / D630 / A9GH / ADD5 / A320)
# =============================================================================

HGST_SAS_HDD_ADDITIONAL = {
    "families": [
        # D40K -- HUS726T6TAL4205, HUS726T4TALS205, HUS726T6TAL5200, HUS726T4TALS200
        # Hits: Encrypt, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        {"fw": "D40K", "models": ["HUS726T6TAL4205", "HUS726T4TALS205", "HUS726T6TAL5200", "HUS726T4TALS200"]},

        # A3Z4 -- HUH721010AL42C0, HUH721010AL52C0, HUH721008AL4200, HUH721010AL5200
        # Hits: Encrypt, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        {"fw": "A3Z4", "models": ["HUH721010AL42C0", "HUH721010AL52C0", "HUH721008AL4200", "HUH721010AL5200"]},

        # A40K -- HUS726T6TAL5200, HUS726T4TALS200, HUS726T6TAL4200 (5200/4200 dual-speed)
        # Hits: Encrypt, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        {"fw": "A40K", "models": ["HUS726T6TAL5200", "HUS726T4TALS200"]},

        # A630/D630 -- HUH721212AL4205, HUH721212AL4200
        # Hits: Encrypt, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        {"fw": "A630/D630", "models": ["HUH721212AL4205", "HUH721212AL4200"]},

        # A9GH -- HUS728T8TAL4200 -- older 12G SATA HDD
        # Hits: Encrypt, TCG Enterprise, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        {"fw": "A9GH", "models": ["HUS728T8TAL4200"]},

        # ADD5 -- HUS726020ALS210, HUS726040ALS210, HUS726060AL4210
        # Hits: Encrypt, EraseMaster (060 only), Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        {"fw": "ADD5", "models": ["HUS726020ALS210", "HUS726040ALS210", "HUS726060AL4210"]},

        # A320 -- HUS724020ALS640, HUS724030ALS640, HUS724040ALS640
        # Hits: Encrypt, HashAndSign, ReEncrypt, Auth (no PresentCertificate -- partial cert chain)
        {"fw": "A320", "models": ["HUS724020ALS640", "HUS724030ALS640", "HUS724040ALS640"]},

        # HUC101812CSS205 (DA01), HUC109060CSS600 (A730), HUC109090CSS600 (A730) -- legacy 10K SAS
        # DA01: Encrypt, Certificate, PresentCertificate, HashAndSign, ReEncrypt, Auth
        # A730/A730: no hits (older TCG pre-cert era)
        {"fw": "DA01", "models": ["HUC101812CSS205"]},
        {"fw": "A730-nohits", "models": ["HUC109060CSS600", "HUC109090CSS600"]},
    ],
    "note": "A320 family shows partial cert chain (HashAndSign + ReEncrypt but no PresentCertificate) -- may use symmetric key exchange instead of X.509 cert",
    "zero_hit_families": ["HUSTR D551", "HUSMR A17D", "HUSMM D17D"],
    "zero_hit_reason": "HGST SAS SSDs (HUSTR/HUSMR/HUSMM) do NOT implement TCG SED -- only HDDs in HGST C-Series fleet",
}

# =============================================================================
# HGST SATA -- LECST92X / LHCST92X (minimal TCG)
# =============================================================================

HGST_SATA_HDD = {
    "families": [
        # LHCST92X -- HUH721010ALE600, HUH721008ALE600
        # Hits: TCG Enterprise only (no cert chain -- SATA vs SAS firmware split)
        {"fw": "LHCST92X", "models": ["HUH721010ALE600", "HUH721008ALE600"]},
        # LECST92X -- HUH721212ALE600
        # Hits: TCG Enterprise only
        {"fw": "LECST92X", "models": ["HUH721212ALE600"]},
    ],
    "note": "HGST SATA variants have simpler TCG implementation vs SAS -- no cert chain, just TCG Enterprise marker",
    "contrast": "HGST SAS uses PresentCertificate authority auth; HGST SATA does not",
}

# =============================================================================
# SEAGATE NL-SAS / NL-SATA -- CK02 / CK03 / CK01 / CN02 / CE04 / CN04
# =============================================================================

SEAGATE_NL_FAMILIES = {
    "families": [
        {
            "fw": "CK02",
            "models": ["ST10000NM024B", "ST6000NM026B"],
            "type": "NL-SAS 10TB/6TB",
            "hits": ["password", "Decrypt", "Encrypt", "TCG Enterprise", "Certificate", "HSM",
                     "unlock", "Unlock", "SBP", "RSA_", "AES-", "PresentCertificate",
                     "HashAndSign", "ReEncrypt", "Auth"],
            "deep": {
                "HSM": "HSMRTTRIndicator",  # Seagate TCG command status flag, NOT external HSM
                "EraseMaster": ["EraseMaster", "EraseMaster_SetSelf"],
            },
            "note": "HSMRTTRIndicator is a Seagate TCG Enterprise SSC command status byte, not KMIP/external HSM reference",
        },
        {
            "fw": "CK03",
            "models": ["ST18000NM006J", "ST12000NM006J"],
            "type": "NL-SAS 18TB/12TB",
            "hits": ["password", "Decrypt", "Encrypt", "TCG Enterprise", "Certificate", "HSM",
                     "unlock", "Unlock", "SBP", "RSA_", "AES-", "PresentCertificate",
                     "HashAndSign", "ReEncrypt", "Auth"],
            "deep": {
                "HSM": "HSMRTTRIndicator",
                "EraseMaster": ["EraseMaster", "EraseMaster_SetSelf"],
            },
        },
        {
            "fw": "CK01",
            "models": ["ST12000NM009G", "ST10000NM011G"],
            "type": "NL-SAS 12TB/10TB",
            "hits": ["password", "Decrypt", "Encrypt", "TCG Enterprise", "EraseMaster", "Certificate",
                     "Signature", "unlock", "Unlock", "SBP", "RSA_", "AES-",
                     "PresentCertificate", "HashAndSign", "ReEncrypt"],
            "note": "Full cert chain + EraseMaster; NO HSMRTTRIndicator (CK02/CK03 specific)",
        },
        {
            "fw": "CN02",
            "models": ["ST4000NM019B"],
            "type": "NL-SAS 4TB",
            "hits": ["password", "Decrypt", "Encrypt", "TCG Enterprise", "EraseMaster", "Certificate",
                     "unlock", "Unlock", "SBP", "RSA_", "AES-", "PresentCertificate",
                     "HashAndSign", "ReEncrypt", "Auth"],
        },
        {
            "fw": "CE04",
            "models": ["ST6000NM027A"],
            "type": "NL-SAS 6TB older",
            "hits": ["password", "Password", "Encrypt", "TCG Enterprise", "unlock", "SBP", "RSA_", "AES-"],
            "note": "Older family -- no cert chain, simpler TCG",
        },
        {
            "fw": "CN04",
            "models": ["ST4000NM016A", "ST2000NM012A", "ST1000NM004A"],  # -2HZ130 / -2MP130 / -2MN130
            "type": "NL-SATA 4/2/1TB",
            "hits": ["password", "Password", "Encrypt", "TCG Enterprise", "unlock", "SBP", "RSA_", "AES-"],
            "note": "SATA NL -- same simple TCG as CE04, no cert chain",
        },
        {
            "fw": "CN04-SAS",
            "models": ["ST4000NM017A", "ST2000NM013A", "ST1000NM005A"],
            "type": "SAS NL 4/2/1TB",
            "hits": ["password", "Encrypt", "TCG Enterprise", "Signature", "unlock", "Unlock", "SBP", "RSA_", "AES-"],
            "note": "Adds Signature vs SATA CN04 variant",
        },
    ],
    "note": "EraseMaster confirmed in CK01/CK02/CK03/CN02 NL-SAS; absent in CE04/CN04 older generation",
}

# =============================================================================
# SEAGATE LEGACY SAS/SATA -- C007 / A005 / N004 / N0A6 / K0A6 / CN05 / CN06 / CT06 / CF04
# =============================================================================

SEAGATE_LEGACY_FAMILIES = {
    "minimal_tcg": {
        # C007: only unlock/Unlock strings -- partial/pre-auth TCG state machine
        "C007": ["ST1000NM0023", "ST2000NM0023", "ST3000NM0023", "ST4000NM0023"],
        # A005: unlock + Unlock + Debug -- slightly more feature-exposed
        "A005": ["ST600MM0006", "ST300MM0006", "ST900MM0006", "ST4000NM0063"],
        # 0003/000B: unlock + Debug -- very early TCG firmware
        "0003": ["ST1200MM0007"],
    },
    "mid_tcg": {
        # N004: password + unlock + RSA_ + Auth (older 10K SAS)
        "N004": ["ST300MP0005", "ST450MP0005", "ST600MP0005"],
        # N0A6/K0A6: EraseMaster + unlock (EraseMaster present, no cert chain)
        "N0A6": ["ST300MM0008", "ST600MM0008", "ST900MM0168", "ST1200MM0088", "ST1800MM0008"],
        "K0A6": ["ST1800MM0008", "ST600MM0008"],
        # CN05: SBP + RSA_ (matches B-Series CN05 pattern -- same family, C-Series bundle copy)
        "CN05": ["ST1000NM0045", "ST4000NM0025"],
        # CN06: EraseMaster + unlock
        "CN06": ["ST1000NX0453", "ST2000NX0433"],
        # CF04: Unlock + RSA_ + AES- + Auth (newer than N004)
        "CF04": ["ST600MP0026"],
        # K0E5: EraseMaster + SBP
        "K0E5": ["ST6000NM0014"],
    },
    "misconfigured_sbp": {
        # CT06: Misconfigured SBP confirmed in SATA NL
        "CT06": ["ST1000NX0423"],
        "note": "Misconfigured SBP code path survives in CT06 SATA NL -- same as B-Series SBP finding class",
    },
    "note": "Legacy C-Series Seagate variants cover same firmware lineage as B-Series -- C-Series bundle is a superset of B-Series drive FW",
}

# =============================================================================
# SEAGATE CE02 -- SAS SSD (Misconfigured SBP confirmed in C-Series)
# =============================================================================

SEAGATE_CE02_SAS_SSD = {
    "models": ["XS3200LE70114", "XS1600LE70114", "XS800LE70114",
               "XS3840SE70114", "XS1920SE70114", "XS960SE70114"],
    "fw": "CE02",
    "hits": ["password", "jtag", "decrypt", "Encrypt", "TCG Enterprise", "Signature",
             "Unlock", "SBP", "Misconfigured SBP", "RSA_", "AES-", "Auth"],
    "vs_ce05": "CE05 (same XS drive family) does NOT contain 'Misconfigured SBP' string -- CE02 -> CE05 remediated the code path",
    "note": "C-Series SAS SSDs carry the Misconfigured SBP finding in CE02 firmware; upgraded to CE05 closes it",
}

# =============================================================================
# MICRON SSD FAMILIES -- D4CS001 (SED) / D4CS000 / D3MC000 / D1MH / 5200 / 5100 / MB19 / 0157
# =============================================================================

MICRON_SSD_FAMILIES = {
    # D4CS001 -- SED variants -- MTFDDAK7T6TGA_SED, MTFDDAK3T8TGA_SED, MTFDDAK1T9TGA_SED, MTFDDAK960TGA_SED
    # Hits: jtag, JTAG, decrypt, Decrypt, encrypt, Encrypt, Certificate, signature, Signature,
    #       unlock, Unlock, PresentCertificate, HashAndSign, ReEncrypt, TPM (= GETPM substring)
    "D4CS001_SED": {
        "models": ["MTFDDAK7T6TGA_SED", "MTFDDAK3T8TGA_SED", "MTFDDAK1T9TGA_SED", "MTFDDAK960TGA_SED"],
        "note": "TPM hit = 'GETPM' substring match; same as D4CS000 -- not a meaningful TPM distinction",
        "deep": {"EraseMaster": "EraseMaster_SetSelf"},
    },

    # D4CS000 -- non-SED variants, 9 capacities
    # Hits: identical hit pattern to D4CS001 (JTAG + full cert chain + GETPM)
    "D4CS000": {
        "models": ["MTFDDAK1T6TGB", "MTFDDAK1T9TGB", "MTFDDAK960TGB", "MTFDDAK480TGB",
                   "MTFDDAV960TGA", "MTFDDAV480TGA", "MTFDDAV240TGA",
                   "MTFDDAK7T6TGA", "MTFDDAK3T8TGA", "MTFDDAK1T9TGA", "MTFDDAK960TGA",
                   "MTFDDAK480TGA", "MTFDDAK240TGA"],
        "note": "Same hit pattern as D4CS001 SED -- no security feature difference detected at string level",
    },

    # D3MC000 -- M6/M7 gen, NVMe + SATA variants
    # Hits: jtag, JTAG, decrypt, Decrypt, encrypt, Encrypt, Certificate, signature, Signature,
    #       unlock, Unlock, SBP, PresentCertificate, HashAndSign, ReEncrypt
    # Note: has SBP string (vs D4CS000 which does not), no GETPM
    "D3MC000": {
        "models": ["MTFDDAK1T9TDS_SED", "MTFDDAK3T8TDS_SED", "MTFDDAK960TDS_SED",
                   "MTFDDAK7T6TDS", "MTFDDAK3T8TDS", "MTFDDAK1T9TDS", "MTFDDAK960TDS",
                   "MTFDDAK480TDS", "MTFDDAK240TDS", "MTFDDAK120TDT", "MTFDDAK1T9TDT",
                   "MTFDDAK960TDT", "MTFDDAK480TDT", "MTFDDAK1T6TDT",
                   "MTFDDAV960TDS", "MTFDDAV240TDS", "MTFDDAV1T9TDS"],
        "note": "D3MC000 adds SBP string (Seagate bus parity monitoring cross-feature) absent in D4CS000/D4CS001",
    },

    # D1MH (5200 series) -- older SATA SSD with password + full cert chain + SBP
    "D1MH_5200": {
        "models": ["MTFDDAK7T6TDC", "MTFDDAK3T8TDC", "MTFDDAK1T9TDC", "MTFDDAK1T6TDN",
                   "MTFDDAK960TDC", "MTFDDAK480TDC", "MTFDDAK1T9TDN", "MTFDDAK960TDN",
                   "MTFDDAK480TDN", "MTFDDAK3T8TDC-sed", "MTFDDAK960TDC-sed"],
        "fw": ["D1MH031", "D1MH431", "D1MH831"],
        "hits": ["password", "jtag", "JTAG", "decrypt", "Decrypt", "encrypt", "Encrypt",
                 "Certificate", "signature", "Signature", "unlock", "Unlock", "SBP",
                 "PresentCertificate", "HashAndSign"],
        "note": "5200 series adds plaintext password string vs D4CS000 -- may indicate admin password gate",
    },

    # 5100 (D0MC/D0MH) -- earlier Micron SATA SSD
    "D0MH_5100": {
        "models": ["MTFDDAK7T6TBY", "MTFDDAK3T8TBY", "MTFDDAK1T9TBY", "MTFDDAK1T6TCC",
                   "MTFDDAK960TCB", "MTFDDAK480TCB", "MTFDDAK240TCB", "MTFDDAK120TCC",
                   "MTFDDAK3T8TBY_SED", "MTFDDAK960TBY_SED", "MTFDDAK960TCB_SED",
                   "MTFDDAK240TCB_SED", "MTFDDAV240TCB", "MTFDDAV960TCB",
                   "MTFDDAK7T6TBY", "MTFDDAK3T8TBY", "MTFDDAK1T9TBY"],
        "fw": ["D0MH077", "D0MH447", "D0MH847", "D0MC077", "D0MC447"],
        "hits": ["password", "jtag", "JTAG", "decrypt", "Decrypt", "encrypt", "Encrypt",
                 "Certificate", "signature", "Signature", "unlock", "Unlock", "SBP",
                 "PresentCertificate"],
        "note": "Same hit profile as D1MH_5200; both include SBP and password strings",
    },

    # MB19 (S650DC FIPS) -- EraseMaster only TCG variant
    "MB19_S650DC_FIPS": {
        "models": ["s650dc400fips", "s650dc800fips", "s650dc1600fips"],
        "hits": ["password", "Encrypt", "TCG Enterprise", "EraseMaster", "Signature"],
        "note": "FIPS 140 certified variant -- simpler TCG surface (no cert chain), EraseMaster present",
    },

    # 0157 (older SATA SSD) -- JTAG + fuse without cert chain
    "0157_older": {
        "models": ["mtfddak100mar", "mtfddak400mar"],
        "hits": ["JTAG", "Decrypt", "Encrypt", "fuse", "Debug"],
        "note": "Pre-cert-chain generation -- JTAG and fuse exposure without TCG cert auth layer",
    },
}

# =============================================================================
# INTEL NVME / SATA -- MULTIPLE FIRMWARE GENERATIONS
# =============================================================================

INTEL_NVME_SATA = {
    # L031CP02 -- NVMEXP-I800/I400 -- most complete auth surface
    # Hits: Encrypt, Certificate, Unlock, ADU, HostExchange, HostSigning, Auth
    # Deep: HostExchangeAuthority, HostExchangeCert, HostSigningAuthority, HostSigningCert
    "L031CP02": {
        "models": ["UCS-NVMEXP-I800", "UCS-NVMEXP-I400"],
        "deep": {
            "HostExchange": "HostExchangeAuthority / HostExchangeCert",
            "HostSigning": "HostSigningAuthority / HostSigningCert",
            "ADU": "*DISLOG_ADU_HARD",
        },
        "note": "HostExchangeAuthority + HostSigningAuthority are TCG Opal 2.0 Host Authority certificate slots; ADU diagnostic log may expose cert state",
    },

    # XCV1CS06 -- SATA SSD (SSDSC2KG) -- full cert chain
    # Hits: Encrypt, Certificate, Unlock, HostExchange, HostSigning, PresentCertificate, HashAndSign, ReEncrypt
    "XCV1CS06": {
        "models": ["SSDSC2KG019T8K", "SSDSC2KG960G8K", "SSDSC2KG480G8K",
                   "SSDSC2KB038T8K", "SSDSC2KB960G8K", "SSDSC2KB480G8K"],
        "deep": {
            "HostExchange": "HostExchangeAuthority / HostExchangeCert",
            "HostSigning": "HostSigningAuthority / HostSigningCert",
        },
        "note": "Intel SATA SSD with full PresentCertificate cert chain + Host Authority cert slots",
    },

    # 2CV1C036 -- NVMEI4 -- adds plaintext password alongside cert auth
    # Hits: password, Password, Encrypt, Unlock, HostExchange, HostSigning
    "2CV1C036": {
        "models": ["ucs-NVMEI4-I6400", "ucs-NVMEI4-I3200", "ucs-NVMEI4-I1600",
                   "ucs-NVMEI4-I7680", "ucs-NVMEI4-I3840", "ucs-NVMEI4-I1920"],
        "deep": {
            "HostExchange": "HostExchangeAuthority / HostExchangeCert",
            "HostSigning": "HostSigningAuthority / HostSigningCert",
            "password": "plaintext admin password gate alongside cert auth",
        },
        "note": "NVMEI4 adds password authentication alongside cert-based Host Authority -- dual-mode auth",
    },

    # ACV10370 -- ucs-NVMEQ-1536 -- partial auth surface
    # Hits: Encrypt, Unlock, ADU, HostExchange, HostSigning
    "ACV10370": {
        "models": ["ucs-NVMEQ-1536"],
        "deep": {
            "HostExchange": "HostExchangeAuthority / HostExchangeCert",
            "HostSigning": "HostSigningAuthority / HostSigningCert",
        },
    },

    # 9CV10510 / E201CP07/02 / QDV1CP08 / VDV1CP05 -- simpler generations
    "simple_auth": {
        "9CV10510": ["ucs-NVME4-*"],  # Encrypt + ADU only
        "E201CP07": ["UCSC-XNVME-I750", "UCSC-XNVME-I375"],  # HostExchange + HostSigning + Auth
        "E201CP02": ["UCSC-XNVME-I750", "UCSC-XNVME-I375"],  # HostExchange + HostSigning + Auth
        "QDV1CP08": ["UCSC-NVMEHW-I4000", "UCSC-NVMEHW-I2TBV", "UCSC-NVMEHW-I1000",
                     "UCSC-NVMEHW-I3200", "UCSC-NVMEHW-I2000", "UCSC-NVMEHW-I1600",
                     "UCSC-NVMELW-I2000", "UCSC-NVMELW-I1000", "UCSC-NVMELW-I500"],  # Encrypt + Auth
        "VDV1CP05": ["UCSC-NVME2H-I3200", "UCSC-NVME2H-I1600", "UCSC-NVMEHW-I8000",
                     "UCSC-NVME2H-I4000", "UCSC-NVME2H-I2TBV", "UCSC-NVME2H-I1000"],  # Encrypt + Auth
        "SCV1CS08": ["SSDSC2KG019T7K", "SSDSC2KG960G7K", "SSDSC2KG480G7K",
                     "SSDSC2KB038T7K", "SSDSC2KB960G7K", "SSDSC2KB480G7K"],  # Encrypt + Auth
    },

    # Zero-hit Intel families
    "zero_hit": {
        "8DV1CP02": "ucs-pci25-* and UCSC-F-I*",
        "CS01": "older SATA SSD (ssdsc2bb*/ssdsc2bx*)",
        "0374": "legacy SATA SSD (ssdsc2bb120g4, ssdsc2bb480g4)",
        "N201CS04": "older Intel SATA (ssdsc2bb*g7k)",
    },
}

# =============================================================================
# SOLIDIGM SATA/NVME
# =============================================================================

SOLIDIGM_FAMILIES = {
    # 7CV1CS05 -- SATA SSD (Solidigm = Intel spin-off, same FW base as Intel 7CV1CS05)
    # Hits: Encrypt, Unlock, Auth
    "7CV1CS05_SATA": {
        "models": ["SSDSC2KB480GZK", "SSDSC2KB960GZK", "SSDSC2KB038TZK", "SSDSC2KG038TZK",
                   "SSDSC2KG480GZK", "SSDSC2KG960GZK", "SSDSCKKB240GZK", "SSDSCKKB480GZK",
                   "SSDSC2KG019TZK"],
        "note": "Minimal Encrypt+Auth -- no cert chain in Solidigm/Intel SATA SATA generation",
    },
    # 9CV10510 -- NVMe (same gen as Intel 9CV10510)
    # Hits: Encrypt + ADU
    "9CV10510_NVME": {
        "models": ["UCS-NVB12T8O1P", "UCS-NVB6T4O1P", "UCS-NVB3T2O1P", "UCS-NVB1T6O1P",
                   "UCS-NVB15TO1V", "UCS-NVB7T6O1V", "UCS-NVB3T8O1V", "UCS-NVB1T9O1V"],
        "note": "ADU diagnostic log path present; Encrypt-only auth",
    },
}

# =============================================================================
# MICRON NVME (E3MF009 / E3MQ009 / E2CS007 / G1MU003) -- C-Series NVMe
# =============================================================================

MICRON_NVME_FAMILIES = {
    # E3MF009 / E3MQ009 -- UCS-NVB* (15TB/7.6TB/3.8TB/1.9TB/960GB variants)
    # Hits: Signature, auth, debug, Debug -- opaque binary, not extractable
    "E3MF009_E3MQ009": {
        "models": ["UCS-NVB15T3M2V9", "UCS-NVB7T6M2V9", "UCS-NVB3T8M2V9", "UCS-NVB1T9M2V9",
                   "UCS-NVB12T8M2P", "UCS-NVB6T4M2P", "UCS-NVB3T2M2P", "UCS-NVB1T6M2P",
                   "UCS-NVB15T3M2V", "UCS-NVB7T6M2V", "UCS-NVB3T8M2V", "UCS-NVB1T9M2V",
                   "UCS-NVB960M2V"],
        "note": "Same opaque binary pattern as B-Series Micron NVMe -- only high-level auth/signature strings visible",
    },
    # E2CS007 -- UCSB-NVMEM6, UCSX-NVM2, UCS-NVMEG4 families
    # Hits: Certificate, Signature, HashAndSign, Auth, debug, Debug
    "E2CS007": {
        "models": ["UCSB-NVMEM6-M800", "UCSB-NVMEM6-M6400", "UCSB-NVMEM6-M7600",
                   "UCSB-NVMEM6-M3800", "UCSB-NVMEM6-M1920", "UCSX-NVM2-400GB",
                   "UCS-NVM2-960GB", "UCS-NVMEG4-M6400", "UCS-NVMEG4-M3200",
                   "UCS-NVMEG4-M1600", "UCS-NVMEG4-M1536", "UCS-NVMEG4-M7680",
                   "UCS-NVMEG4-M3840", "UCS-NVMEG4-M1920", "UCS-NVMEG4-M960"],
        "note": "Certificate + HashAndSign present -- partial cert chain visibility in Micron E2CS007 NVMe",
    },
}

# =============================================================================
# EMULEX / BROADCOM FC HBA
# =============================================================================

EMULEX_FC_HBA = {
    "models": {
        "LPe35002": {"fw": "14.4.576.17", "size_kb": 1366},
        "LPe32002": {"fw": "14.4.576.17", "size_kb": 1214},
        "LPe31002": {"fw": "14.4.576.17", "size_kb": 1214},
        "LPe32000": {"fw": "14.2.455.11", "size_kb": 1204},
    },
    "hits": ["password", "decrypt", "encrypt", "Encrypt", "certificate", "Certificate",
             "signature", "Signature", "fuse", "unlock", "SHA-", "ECDSA", "auth", "Auth",
             "debug", "Debug"],
    "deep": {
        "ECDSA": ["ECDSA with SHA1", "ECDSA with SHA512", "ECDSA with SHA224"],
        "fuse": ["Serial Number from EFUSE:", "AVS and EFUSE Menu", "Display EFUSE Regs",
                 "lowlevel_option_display_efuse_regs", "lowlevel_efuse_menu", "taps_display_efuse"],
    },
    "note": "In-firmware AVS+EFUSE diagnostic menu with Display EFUSE Regs option. ECDSA-SHA1 signing variant is cryptographically weak.",
}

# =============================================================================
# NVME MSWITCH M6 (Broadcom PM8x00-based) -- OTP/EFUSE / KMSK / UDS
# =============================================================================

NVME_MSWITCH_M6 = {
    "models": {
        "mswitch-nvme-m6": "ucs-storage-nvme-mswitch-nvme-m6.3.70.0.4F-U2B2-U4B2-U6B2.bin",
        "mswitch-m6-hddext-1": "ucs-storage-nvme-mswitch-m6-hddext-1.3.70.0.4F-U2B2-U4B2-U6B2.bin",
        "mswitch-m6-hddext-2": "ucs-storage-nvme-mswitch-m6-hddext-2.3.70.0.4F-U2B2-U4B2-U6B2.bin",
        "mswitch-m6-hddext-3": "ucs-storage-nvme-mswitch-m6-hddext-3.3.70.0.4F-U2B2-U4B2-U6B2.bin",
    },
    "hits": ["jtag", "decrypt", "signature", "FUSE", "unlock", "Unlock", "debug", "Debug"],
    "deep": {
        "OTP_EFUSE": [
            "OTP_EFUSE: eFuse burning failed",
            "OTP_EFUSE: Trying to burn eFuse data from 1 to 0 at offset 0x%x",
            "OTP_EFUSE: Attestation is enabled, but no UDS data is specified",
            "OTP_EFUSE: Debug mode has to be 0 in the secure setting command",
            "OTP_EFUSE: Access not existed KMSK entry %d",
            "OTP_EFUSE: KMSK entries are not set sequentially 0x%x",
            "OTP_EFUSE: FW secure version %d is not sequential",
            "OTP_EFUSE: Invalid security mode %d",
            "ASSERT: Failed to set eFuse RO in shadow register",
        ],
        "VQ_OTP": ["VQPS_OTP_SNS_U1", "VQPS_OTP_SNS_U2", "VQPS_OTP_SNS_U3"],
    },
    "key_security_primitives": {
        "UDS": "Unique Device Secret for DICE attestation (error: 'no UDS data is specified' when not provisioned)",
        "KMSK": "Key Manifest Secret Key stored in OTP eFuse entries (can be accessed sequentially 0..N)",
        "FW_secure_version": "Anti-rollback fuse counter (non-sequential FW version rejected)",
        "Debug_mode": "Debug mode controlled by eFuse bit (must be 0 in secure mode)",
        "eFuse_burn_1to0": "OTP write operation -- burns 1->0; irreversible; error on reverse",
        "eFuse_RO_shadow": "Shadow register read-only enforcement after burn (ASSERT on failure)",
    },
    "note": "NVMe switch implements DICE-style attestation with OTP-backed KMSK and UDS. If UDS not provisioned at manufacture, attestation claim is void despite the infrastructure being present.",
}

# =============================================================================
# PM8533 NVME SWITCH (C480 / C240 / C220)
# =============================================================================

PM8533_NVME_SWITCH = {
    "models": {
        "C480-PM8533-F1": "ucs-c-storage-nvme-C480-PM8533-F1.01080058-000041A3.bin",
        "C480-PM8533-F2": "ucs-c-storage-nvme-C480-PM8533-F2.01080058-000042A3.bin",
        "C480-PM8533-F3": "ucs-c-storage-nvme-C480-PM8533-F3.01080058-000043A3.bin",
        "C480-PM8533-R": "ucs-c-storage-nvme-C480-PM8533-R.01080058-000044E3.bin",
        "C240-PM8533": "ucs-c-storage-nvme-C240-PM8533.1.8.0.58-24B3.bin",
        "C220-PM8533": "ucs-c-storage-nvme-C220-PM8533.1.8.0.58-22D9.bin",
    },
    "hits": ["fuse", "debug", "Debug"],
    "deep": {"fuse": "ccpm efuse dtm irq"},
    "note": "PM8533 (Microsemi NVMe switch) has only minimal fuse + debug strings -- distinct from mswitch Broadcom which has full OTP_EFUSE infrastructure",
}

# =============================================================================
# SAS EXPANDERS -- CUB / CUBR M6 / C460-M4 / C3260
# =============================================================================

SAS_EXPANDERS = {
    "CUB_M6": {
        "model": "ucs-storage-expander-cub-m6.65.16.09.00.bin",
        "hits": ["jtag", "JTAG", "signature", "Signature", "Unlock", "debug", "Debug"],
        "note": "CUB M6 (non-R) -- same Avago SPICO SerDes PHY JTAG as CUBR; not a security-relevant JTAG master",
    },
    "CUBR_M6": {
        "model": "ucs-storage-expander-cubr-m6.65.16.09.00.bin",
        "note": "Already documented in C-Series module 1 -- Avago SPICO SerDes JTAG confirmed non-security",
    },
    "C460_M4_SAS_EXPANDER": {
        "model": "ucs-c460-m4-sas-expander-main-fw.65.10.41.00.bin",
        "hits": ["signature", "Signature", "Unlock", "debug", "Debug"],
        "note": "No JTAG string -- older expander generation without JTAG master interface",
    },
    "C3260_SAS_EXPANDER": {
        "model": "ucs-c3260-sas-expander.04.08.01.B083.bin",
        "hits": ["JTAG", "debug"],
        "note": "C3260-specific SAS expander -- JTAG string present; context suggests SerDes PHY JTAG consistent with other expanders",
    },
}

# =============================================================================
# DOUBLE-DECKER RAID (C480 M5 -- ucs-storage-controller-double-decker-raid)
# =============================================================================

DOUBLE_DECKER_RAID = {
    "model": "ucs-storage-controller-double-decker-raid.29.00.1-0360.bin",
    "fw_version": "29.00.1-0360",
    "size_bytes": 4433069,
    "hits": ["password", "Password", "jtag", "JTAG", "decrypt", "Decrypt", "encrypt", "Encrypt",
             "secret key", "KM_", "NVRAM key", "signature", "Signature", "fuse", "FUSE"],
    "deep": {
        "KM_": [
            "KM_SetEKMStateEvents",
            "AKM_INITIAL_VALUE",
            "KM_KeyIdGet",
        ],
        "HSM": [
            "BootMsgHandleHSMClear",
            "HSM active,failing Config CfgDcmd %x",
            "HSM active,failing Pdset Dcmd for/to JBOD",
        ],
        "fuse": [
            "ASRKEfuseDebug",
            "EfuseReadSRKVal",
            "EfusecompressSRKData",
        ],
        "TPM": [
            "TPM_BindKey",
            "KM_USE_TPM_MASK",
            "bbu=%x, alarm=%x, nvram=%x, uart=%x, memory=%x, flash=%x, TPM=%x, expander=%x",
        ],
        "iButton": [
            "Incompatible secondary iButton detected!",
            "Incompatible secondary iButton present!",
            "Please insert the correct iButton and restart the system.",
        ],
        "secret_key": [
            "KM_DecryptNvramKeyBlob: Failed to hash secret key, retVal = 0x%X, status = %u",
            "KM_DecryptNvramKeyBlob: Failed to decrypt with secret key, retVal = 0x%X, status = %u",
            "KM_DecryptNvramKeyBlob: Failed to authenticate NVRAM key blob with secret key",
        ],
        "NVRAM_key": [
            "KM_KeyMgmtInit: Failed to decrypt NVRAM key blob with USER secret key",
            "KM_KeyMgmtInit: Failed to decrypt NVRAM key blob with FW secret key",
        ],
        "FUSE": [
            "FUSE_RANDOM_NUMBER_READ:: Trying to read from user index %d",
            "EFUSE_RANDOM_NUMBER_READ::The data reg contents at index = %d is = %x",
            "EFUSE_RANDOM_NUMBER_READ::Data Reg contents after the first read = 0x%x",
        ],
    },
    "note": "Complete Broadcom KM_ dual-key suite -- identical to C3K M4RAID and UCSB-RAID12G-M6. Also includes AKM_INITIAL_VALUE constant not seen in all variants. Extends confirmed KM_ attack surface to C480 M5 double-decker platform.",
}

# =============================================================================
# ZERO-HIT FAMILIES SURVEY
# =============================================================================

ZERO_HIT_C_SERIES_BATCH2 = {
    "storage": {
        "toshiba_sas_hdd": ["AL13SEB", "AL14SEB", "AL15SEB", "AL13SXB", "MG04SCA", "MG06SCA",
                            "MG08SDA", "MG09SCA", "MG10SDA", "MG11SCA"],
        "samsung_sata_ssd": ["JXTG2F3Q", "JXTC3F3Q", "HXT7DF3Q", "DM0V", "EM19", "8F3Q"],
        "wdc_nvme": ["NVMEM6-W*", "NVMW*"],
        "kioxia_nvme_sas": ["KPM6*", "KPM7*", "1YETE106"],
        "hgst_sas_ssd": ["HUSTR D551", "HUSMR A17D", "HUSMM D17D"],
        "hgst_nvme": ["KNCCD122"],
        "micron_nvme": ["G1MU003"],
    },
    "networking": {
        "qlogic_fc": ["QLE2772", "QLE2872", "QLE2742", "QLE2692",
                      "ql45611h", "ql41162hl", "ql41132horj", "ql41232hocu", "ql41212h", "ql45412h"],
        "intel_pcie_nic": ["id10gc", "iq10gf", "id40gf", "id10gf", "iq10gc", "n2xx-aipci01",
                           "pcie-xxx710da2", "pcie-x710ta4"],
        "qsfp_emulex_nic": ["ucsc-p-IQ10GC", "ucsc-p-I8Q25GF", "ucsc-p-I8D25GF",
                            "ucsc-p-IBD100GF", "ucsc-o-ID10GC", "ucsc-p-ID10GC",
                            "ucsc-p-M6DD100GF", "ucsc-p-M6CD100GF", "ucsc-o-ID25GF"],
        "mlom": ["ucsc-mlom-001"],
    },
    "gpu_accel": {
        "nvidia": ["H100-NVL", "H100-80G", "L4", "L40", "A16", "A30", "A100-80", "A100",
                   "A40", "A10", "T4", "V100-32GB", "V100-SXM2-32GB", "v100", "A100-80",
                   "RTX-6000", "RTX-8000", "P4", "P100-16gb", "P100-12gb", "P40", "M10", "M60"],
        "amd": ["v340"],
        "intel_flex": ["flex-140-Mezz"],
    },
    "controller_no_hits": {
        "9400-8i": "24.65.18.00",
        "9400-8e": "24.65.18.00",
        "9500-8e": "36.65.08.00",
        "m2-nvmeraid": "52.34.0-6415",
        "m2-hwraid-88SE92xx": "2.3.17.1014",
        "riobeach": "8.10.1.0-00065-00002",
        "ucsc-raid-m6hd": "52.34.0-6415",
        "double-decker-raid-cpld": "00188-1A6",
        "c3k-m4raid-cpld": "31137-033",
    },
    "brdprog": "All c220/c225/c240/c245/c480/c3260/c125/s3260 brdprog (10-12KB) -- no hits",
    "cimc_bios": "CIMC and BIOS blobs >10MB -- skipped in this scan (129-153MB CIMC, 8-24MB BIOS)",
    "pmemory": ["ucs-pmemory-dimm-fw.1.2.0.5446.bin", "ucs-pmemory-bps-dimm-fw.2.2.0.1553.bin"],
    "retimer": ["ucs-c240-m7-pt5161l-retimer.1.27.42.bin", "ucs-c220-m7-pt5161l-retimer.1.27.42.bin"],
    "pll": "ucs-avago_C480-PLL8764.4810B-4820B-4830B-4840B.bin (1KB)",
}

# =============================================================================
# FINDINGS
# =============================================================================

FINDINGS = [
    {
        "id": "MSWITCH-M6-KMSK-UDS-F1",
        "title": "NVMe M6 Switch OTP eFuse KMSK + UDS -- DICE attestation not enforced by default",
        "severity": "MEDIUM",
        "components": ["mswitch-nvme-m6", "mswitch-m6-hddext-1/2/3"],
        "fw_version": "3.70.0.4F-U2B2-U4B2-U6B2",
        "evidence": [
            "OTP_EFUSE: Attestation is enabled, but no UDS data is specified",
            "OTP_EFUSE: Access not existed KMSK entry %d",
            "OTP_EFUSE: KMSK entries are not set sequentially 0x%x",
            "OTP_EFUSE: FW secure version %d is not sequential",
            "OTP_EFUSE: Debug mode has to be 0 in the secure setting command",
            "ASSERT: Failed to set eFuse RO in shadow register",
            "OTP_EFUSE: Trying to burn eFuse data from 1 to 0 at offset 0x%x",
        ],
        "technical_detail": (
            "The Broadcom NVMe switch (mswitch-nvme-m6 and hddext variants) implements a DICE-like "
            "attestation architecture with OTP eFuse-backed Key Manifest Secret Key (KMSK) entries, "
            "Unique Device Secret (UDS) for attestation identity, and firmware secure version as an "
            "anti-rollback counter. "
            "The error string 'Attestation is enabled, but no UDS data is specified' indicates the "
            "attestation infrastructure is conditionally enabled and the UDS is a separate provisioning "
            "step. If UDS was not programmed at manufacture (OEM integration failure), the device "
            "participates in attestation chains without a valid device identity. "
            "KMSK entries are accessed by index (0..N) and must be programmed sequentially -- the "
            "'not set sequentially' error is a provisioning guard, not a runtime gate. "
            "Debug mode is eFuse-controlled and must be cleared for secure operation; if the eFuse "
            "was not burned, debug mode may be active in production units. "
            "The 'ASSERT: Failed to set eFuse RO in shadow register' indicates a failure mode where "
            "eFuse values are written but the shadow register read-only enforcement fails -- in that "
            "case the OTP values may be mutable in the shadow space until next power cycle. "
            "The NVMe switch is accessible via NVMe Management Interface (NVMe-MI) from the OS in "
            "some UCSC deployment configurations."
        ),
        "impact": "If UDS not provisioned: device attestation claims are void. If debug mode not eFuse-locked: debug interfaces accessible in production. Shadow register eFuse RO enforcement failure window: eFuse values writable until reboot.",
        "affected_platforms": ["C220-M7", "C240-M7", "X210C-M6", "X210C-M7"],
    },
    {
        "id": "DOUBLE-DECKER-RAID-KM-FULL-F2",
        "title": "Double-Decker RAID (C480 M5) carries complete Broadcom KM_ dual-key suite",
        "severity": "MEDIUM",
        "component": "ucs-storage-controller-double-decker-raid.29.00.1-0360.bin",
        "fw_version": "29.00.1-0360",
        "evidence": {
            "KM_dual_key": [
                "KM_KeyMgmtInit: Failed to decrypt NVRAM key blob with USER secret key",
                "KM_KeyMgmtInit: Failed to decrypt NVRAM key blob with FW secret key",
                "KM_DecryptNvramKeyBlob: Failed to authenticate NVRAM key blob with secret key",
            ],
            "EfuseReadSRKVal": "ASRKEfuseDebug / EfuseReadSRKVal / EfusecompressSRKData",
            "EFUSE_RANDOM_NUMBER_READ": [
                "FUSE_RANDOM_NUMBER_READ:: Trying to read from user index %d",
                "EFUSE_RANDOM_NUMBER_READ::The data reg contents at index = %d is = %x",
            ],
            "TPM_BindKey": ["TPM_BindKey", "KM_USE_TPM_MASK"],
            "iButton": [
                "Incompatible secondary iButton detected!",
                "Please insert the correct iButton and restart the system.",
            ],
            "HSM_DoS": [
                "BootMsgHandleHSMClear",
                "HSM active,failing Config CfgDcmd %x",
                "HSM active,failing Pdset Dcmd for/to JBOD",
            ],
            "AKM": "AKM_INITIAL_VALUE",
        },
        "technical_detail": (
            "The C480 M5 double-decker RAID controller firmware carries the complete Broadcom KM_ "
            "dual-key suite previously confirmed in C3K M4RAID, C3X60-R1GB, and UCSB-RAID12G-M6. "
            "All attack surfaces documented in C-Series module 1 apply identically: "
            "KM_DecryptNvramKeyBlob USER + FW key fallback, EfuseReadSRKVal Secure Root Key eFuse "
            "read, SRKEfuseDebug (here as ASRKEfuseDebug -- array/multiple SRK), indexed "
            "EFUSE_RANDOM_NUMBER_READ, TPM_BindKey + KM_USE_TPM_MASK, DS1361S iButton SHA-1 "
            "hardware token, and HSM active DoS (ALL config commands blocked when HSM is active; "
            "BootMsgHandleHSMClear clears it during boot sequence). "
            "AKM_INITIAL_VALUE (Adaptive Key Management initial value) is present here -- this "
            "constant was not seen in all prior variants and may indicate a distinct key derivation "
            "state machine initialization path on the double-decker platform."
        ),
        "impact": "KM_ suite attack surface extended to C480 M5 double-decker RAID. ASRKEfuseDebug (vs SRKEfuseDebug) suggests array of SRK values -- potentially more key material accessible via eFuse read interface.",
        "affected_platform": "UCSC-C480-M5",
    },
    {
        "id": "SEAGATE-NL-SAS-ERASEMASTER-F3",
        "title": "Seagate CK01/CK02/CK03/CN02 NL-SAS families expose EraseMaster authority",
        "severity": "LOW",
        "families": {
            "CK02": ["ST10000NM024B", "ST6000NM026B"],
            "CK03": ["ST18000NM006J", "ST12000NM006J"],
            "CK01": ["ST12000NM009G", "ST10000NM011G"],
            "CN02": ["ST4000NM019B"],
        },
        "evidence": {
            "strings": ["EraseMaster", "EraseMaster_SetSelf"],
            "CK02_CK03_also_has": "HSMRTTRIndicator -- TCG command status byte, not external HSM",
        },
        "technical_detail": (
            "EraseMaster and EraseMaster_SetSelf are TCG Enterprise SSC authority names. The "
            "EraseMaster authority can issue EraseAll and Erase band operations without BandMaster "
            "key material -- its purpose is authorized data destruction. If EraseMaster credentials "
            "are unset (factory default) or if a separate EraseMaster credential path exists that "
            "doesn't require the full BandMaster authentication, targeted data destruction is "
            "possible without full drive authentication. "
            "CK02/CK03 additionally contain 'HSMRTTRIndicator' -- this is a Seagate-specific TCG "
            "command status indicator (not a reference to an external HSM server). The scanner "
            "keyword 'HSM' matched this string; it is NOT the KMIP/external HSM context from "
            "MegaRAID EKMS. "
            "Coverage: 4 NL-SAS drive families, 6 total firmware images, capacities 4TB-18TB."
        ),
        "impact": "EraseMaster authority enables cryptographic erasure of all bands without BandMaster key. Applies to all datacenter-capacity NL-SAS drives in C-Series deployments.",
        "note": "CE04/CN04 (older NL families) do NOT have EraseMaster -- it was added in CK-generation firmware",
    },
    {
        "id": "WDC-OPTINAND-ERASEMASTER-FUSE-F4",
        "title": "WDC OptiNAND (A540/A730) EraseMaster; D971 SAS SSD adds FUSE gate",
        "severity": "LOW",
        "families": {
            "A540": ["WDC-WUH722020BL4200"],
            "A730": ["WDC-WUH722222AL4200"],
            "D971_SAS_SSD": [
                "WUSTM3216ASS205", "WUSTM3280ASS205", "WUSTM3240ASS205",
                "WUSTR1538ASS205", "WUSTR1596ASS205", "WUSTR1548ASS205",
                "WUSTR6432ASS200", "WUSTR6416ASS200", "WUSTR6480ASS200", "WUSTR6440ASS200",
                "WUSTR1538ASS200", "WUSTR1519ASS200", "WUSTR1596ASS200", "WUSTR1548ASS200",
            ],
        },
        "evidence": {
            "A540_A730": ["EraseMaster", "EraseMaster_SetSelf"],
            "D971": ["EraseMaster", "FUSEIDS"],
        },
        "technical_detail": (
            "WDC A540 and A730 (OptiNAND platform) SAS HDDs have EraseMaster + EraseMaster_SetSelf, "
            "consistent with the WDC/HGST TCG Enterprise SSC implementation. These are the newer "
            "WDC-branded (post-HGST) OptiNAND-architecture drives. "
            "The D971 SAS SSD family (WUSTM3/WUSTR enterprise SAS SSDs) additionally has FUSEIDS -- "
            "a fuse-locked feature identifier bitmap not seen in HGST/WDC HDD variants. FUSEIDS "
            "controls which features are activated at the firmware level via OTP fuse bits. If "
            "FUSEIDS can be queried from the OS level (via SCSI diagnostic commands or TCG session), "
            "it reveals the security configuration of the drive without authentication. "
            "Note: HGST SAS HDDs (HGST-lineage, non-WDC-branded) share the cert chain but do NOT "
            "have FUSEIDS -- this is a WDC SAS SSD-specific addition."
        ),
        "impact": "EraseMaster enables authorized data destruction. FUSEIDS in D971 SAS SSDs reveals drive security configuration (which features are fuse-enabled) to any initiator.",
        "affected_platforms": ["UCSC-C220-M7", "UCSC-C240-M7", "UCSC-C225-M8", "UCSC-C245-M8"],
    },
    {
        "id": "SEAGATE-CE02-MISCONFIGURED-SBP-CSERIES-F5",
        "title": "Seagate CE02 SAS SSD retains Misconfigured SBP code path; CE05 does not",
        "severity": "LOW",
        "families": {
            "CE02": ["XS3200LE70114", "XS1600LE70114", "XS800LE70114",
                     "XS3840SE70114", "XS1920SE70114", "XS960SE70114"],
            "CE05_no_hit": ["XS960SE70075", "XS6400LE70075", "XS3200LE70075",
                            "XS1600LE70075", "XS800LE70075", "XS7680SE70075",
                            "XS1920SE70075", "XS3840SE70075"],
        },
        "evidence": {
            "CE02_strings": ["Misconfigured SBP", "SBP", "jtag", "decrypt"],
            "CE05_strings": ["SBP only (no Misconfigured SBP)"],
        },
        "technical_detail": (
            "Seagate XS-series SAS SSDs on CE02 firmware carry 'Misconfigured SBP' -- the same "
            "Seagate SBP Fuse Bits misconfiguration path documented in B-Series surveys. "
            "CE05 firmware (same XS drive family, newer revision) removes this code path -- "
            "the string is absent in all CE05 variants. "
            "This confirms CE02 -> CE05 was a security-relevant firmware update that addressed "
            "the misconfigured SBP path. The CE02 firmware also retains 'jtag' and 'decrypt' "
            "strings that CE05 removes. "
            "C-Series deployments still running CE02 on XS SAS SSDs have the full B-Series "
            "SBP finding surface exposed."
        ),
        "impact": "CE02-based XS SAS SSDs in C-Series carry B-Series SBP misconfiguration finding. Upgrade path to CE05 closes this exposure.",
        "note": "CE05 versions: 70075 suffix; CE02 versions: 70114 suffix",
    },
    {
        "id": "EMULEX-FC-ECDSA-EFUSE-MENU-F6",
        "title": "Emulex FC HBA exposes in-firmware EFUSE read menu; ECDSA-SHA1 signing",
        "severity": "LOW",
        "models": ["LPe35002", "LPe32002", "LPe31002", "LPe32000"],
        "fw_versions": ["14.4.576.17", "14.2.455.11"],
        "evidence": {
            "ECDSA": ["ECDSA with SHA1", "ECDSA with SHA512", "ECDSA with SHA224"],
            "EFUSE_menu": [
                "AVS and EFUSE Menu",
                "Display EFUSE Regs",
                "lowlevel_option_display_efuse_regs",
                "lowlevel_efuse_menu",
                "taps_display_efuse",
                "Serial Number from EFUSE:",
            ],
        },
        "technical_detail": (
            "Emulex (Broadcom) FC HBAs carry an in-firmware diagnostic menu 'AVS and EFUSE Menu' "
            "with an option to 'Display EFUSE Regs'. The lowlevel functions "
            "'lowlevel_option_display_efuse_regs' and 'lowlevel_efuse_menu' suggest this is "
            "accessible via a management interface (LightPulse hbaapi, bfa IOCTL, or debug UART). "
            "If accessible from the host OS without HBA-level authentication, it exposes eFuse "
            "register contents including the device serial number from eFuse. "
            "ECDSA signing variants include SHA1 (LPe32000/older) and SHA512/SHA224 (LPe35002/newer). "
            "ECDSA-SHA1 is cryptographically deprecated -- SHA1 collision attacks apply to "
            "signature validation if the firmware secure boot path uses ECDSA-SHA1."
        ),
        "impact": "EFUSE register read menu: exposes device key material if accessible without auth. ECDSA-SHA1 on LPe32000 generation: SHA1 collision attacks applicable to secure boot signature validation.",
        "affected_platforms": ["UCSC-C220-M5/M6/M7", "UCSC-C240-M5/M6/M7", "S3260"],
    },
    {
        "id": "INTEL-NVME-HOST-AUTHORITY-ADU-F7",
        "title": "Intel NVMe/SATA HostExchangeAuthority + HostSigningAuthority cert slots with ADU diagnostic log",
        "severity": "LOW",
        "families": {
            "L031CP02": ["UCS-NVMEXP-I800", "UCS-NVMEXP-I400"],
            "XCV1CS06": ["SSDSC2KG019T8K", "SSDSC2KG960G8K", "SSDSC2KG480G8K",
                         "SSDSC2KB038T8K", "SSDSC2KB960G8K", "SSDSC2KB480G8K"],
            "ACV10370": ["ucs-NVMEQ-1536"],
            "2CV1C036": ["ucs-NVMEI4-I6400", "ucs-NVMEI4-I3200", "ucs-NVMEI4-I1600",
                         "ucs-NVMEI4-I7680", "ucs-NVMEI4-I3840", "ucs-NVMEI4-I1920"],
        },
        "evidence": {
            "cert_slots": [
                "HostExchangeAuthority",
                "HostExchangeCert",
                "HostSigningAuthority",
                "HostSigningCert",
            ],
            "ADU_log": "*DISLOG_ADU_HARD",
            "password_2CV1": "plaintext Password alongside cert auth (2CV1C036 only)",
        },
        "technical_detail": (
            "Intel NVMe and SATA SSD families store HostExchangeAuthority and HostSigningAuthority "
            "certificate slot names -- these are TCG Opal 2.0 Host Authority entities that authenticate "
            "the host to the drive for key exchange and signing operations. "
            "HostExchangeAuthority holds the certificate for the host's key exchange identity; "
            "HostSigningAuthority holds the signing certificate used to authorize TCG commands. "
            "The ADU diagnostic log path ('*DISLOG_ADU_HARD') captures hard errors from the "
            "Administrative Domain Unit. On error conditions, this log may expose certificate "
            "state or key exchange state without requiring authentication. "
            "The 2CV1C036 (NVMEI4) family adds plaintext Password authentication alongside the "
            "cert-based authority chain -- the password mode may bypass the full cert exchange "
            "if the Password Authority is not properly locked. "
            "Affected: L031CP02, XCV1CS06, ACV10370, 2CV1C036 -- spans NVMe and SATA form factors."
        ),
        "impact": "HostExchangeAuthority/HostSigningAuthority: TCG Opal host cert slots -- if not provisioned, host authentication is void. 2CV1C036 password mode: potential cert-bypass if Password Authority not locked. ADU log: may expose auth state on error.",
        "affected_platforms": ["UCSC-C220-M5/M6/M7", "UCSC-C240-M5/M6/M7", "UCSC-C480-M5"],
    },
    {
        "id": "CSERIES-STORAGE-SURVEY-COMPLETE-F8",
        "title": "C-Series storage TAR survey complete for all members <10MB",
        "severity": "LOW",
        "total_members": 728,
        "analyzed_under_10mb": "~690 members",
        "skipped_over_10mb": [
            "CIMC (63-153MB): c220-m5/m6/m7, c225-m6/m8, c240-m5/m6/m7, c245-m6/m8, c125, c480-m5, c3260-m5, s3260-m5",
            "BIOS (8-24MB): c220-m5/m6/m7/m8, c225-m6/m8, c240-m5/m6/m7/m8, c245-m6/m8, c125, c480-m5, s3260-m5",
        ],
        "notable_zero_hit_families": {
            "toshiba_sas_hdd": "ALL Toshiba AL-series and MG-series -- no TCG Enterprise in any generation",
            "samsung_sata_ssd": "JXTG2F3Q, JXTC3F3Q, HXT7DF3Q -- no hits; only 33F3Q/GXT51F3Q have minimal Password+Signature+Unlock",
            "hgst_sas_ssd": "HUSTR/HUSMR/HUSMM -- no TCG SED (HDD-only feature in HGST C-Series)",
            "kioxia": "KPM6/KPM7 NVMe and SAS -- no hits in any family",
            "nvidia_gpu": "All GPU firmware (H100/L4/L40/A-series/T4/V100/P-series) -- no hits",
            "qlogic_fc": "All QLE/QL-series -- no hits",
            "wdc_nvme": "NVMEM6-W*/NVMEW* -- no hits",
        },
        "next_step": "CIMC and BIOS blobs require dedicated scan with full file read (>10MB skip was by design); NC3220 VIC (435MB) requires streaming decomp",
    },
]

# =============================================================================
# MODULE SUMMARY
# =============================================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_cseries_storage_extended_re.py",
    "session": 29,
    "c_series_module": 2,
    "families_covered": [
        "WDC HDD: DD30, AD30, A8C2, D8C2, A540, A730, A9M0, VXCST9M0, A2W0",
        "WDC SAS SSD: D971 (14 drives)",
        "HGST SAS HDD: D40K, A3Z4, A40K, A630, D630, A9GH, ADD5, A320, DA01, A730",
        "HGST SATA HDD: LHCST92X, LECST92X",
        "Seagate NL-SAS/SATA: CK02, CK03, CK01, CN02, CE04, CN04",
        "Seagate legacy: C007, A005, N004, N0A6, K0A6, CN05, CN06, CT06, CF04, K0E5",
        "Seagate CE02 SAS SSD (6 drives)",
        "Micron SSD: D4CS001 SED, D4CS000, D3MC000, D1MH/5200, 5100, MB19, 0157",
        "Micron NVMe: E3MF009, E3MQ009, E2CS007",
        "Intel NVMe/SATA: L031CP02, XCV1CS06, 2CV1C036, ACV10370, 9CV10510, E201CP07/02, QDV1CP08, VDV1CP05, SCV1CS08",
        "Solidigm: 7CV1CS05 SATA, 9CV10510 NVMe",
        "Emulex FC HBA: LPe35002, LPe32002, LPe31002, LPe32000",
        "NVMe mswitch M6 (hddext-1/2/3 + nvme-m6)",
        "PM8533 NVMe switch (C480-F1/F2/F3/R, C240, C220)",
        "SAS expanders: CUB M6, CUBR M6, C460-M4, C3260",
        "Double-decker RAID controller",
    ],
    "findings": [f["id"] for f in FINDINGS],
    "finding_count": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 6},
    "cumulative_c_series": {"module_1": 6, "module_2": 8, "total_cseries": 14},
    "cumulative_all": {
        "before_this_module": 509,
        "this_module": 8,
        "total": 517,
        "breakdown": {"CRITICAL": 54, "HIGH": 177, "MEDIUM": 158, "LOW": 128},
    },
}
