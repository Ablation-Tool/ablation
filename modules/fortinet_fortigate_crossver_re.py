"""
Fortinet FortiGate Cross-Version Comparative RE
Sources analyzed:
  FGT_VM64_KVM-v7.0.9-build0444  (virtioa.qcow2, main RE source, full rootfs accessible)
  FGT_VM64_KVM-v7.4.12.M-build2902 (2026-05-04, x86-64, Linux 4.19.13, rootfs encrypted)
  FGT_VM64_KVM-v8.0.0.F-build0167  (2026-04-20, x86-64, Linux 6.12.32, rootfs encrypted)
  FGT_ARM64_KVM-v8.0.0.F-build0167 (2026-04-19, ARM64, rootfs encrypted)
Purpose: Track key persistence, fortism evolution, kernel progression across versions.
"""


# ---------------------------------------------------------
# Cross-version kernel progression
# ---------------------------------------------------------
KERNEL_PROGRESSION = {
    "FGT_7.0.9_x86-64":  "Linux 3.2.16 (2012 kernel, FULL ROOTFS ACCESSIBLE)",
    "FGT_7.4.12_x86-64": "Linux 4.19.13 (2019 LTS, built 2026-05-04, same kernel as FFW 8.0.0)",
    "FGT_8.0.0_x86-64":  "Linux 6.12.32 (2024 LTS, built 2026-04-20)",
    "FGT_8.0.0_ARM64":   "ARM64 boot image 17.5MB; kernel version not extracted from flatkc",
    "FFW_8.0.0_x86-64":  "Linux 4.19.13 (2019 LTS, same as FGT 7.4.12)",
    "FWB_8.0.6_x86-64":  "Linux 6.1.62 (2022 LTS, different branch from FGT 8.0.0)",

    "progression_note": (
        "FortiGate x86-64 jumped from Linux 3.2 (in v7.0) to 4.19 (in v7.4) to 6.12 (in v8.0). "
        "FortiFirewall 8.0.0 stayed on 4.19 -- same branch as FGT 7.4. "
        "FortiWeb 8.0.6 uses 6.1 LTS instead of 6.12 (FortiGate 8.0 uses 6.12 LTS). "
        "Kernel upgrade in FGT 8.0.0 adds: KASLR improvements, KPTI, SMEP/SMAP reliability, "
        "better ROP mitigations. FGT 7.4.12 with 4.19 lacks these."
    ),

    "attack_impact": {
        "FGT_7.4.12":  "Linux 4.19: no KASLR randomization improvements from 5.x; KPTI present but 4.19-era; fortism DoS (FGT-F16 via 0x9007) applies if copy_from_user behaves like FFW",
        "FGT_8.0.0":   "Linux 6.12: strongest mitigation baseline; KASLR improved; fortism DoS CONFIRMED (FGT-F16 rep stosq)",
        "FGT_7.0.9":   "Linux 3.2: NO KASLR, NO KPTI, NO SMEP/SMAP by default; oldest fortism (4001-4004 range)",
    },
}


# ---------------------------------------------------------
# Cross-version key scope -- fgt2.key RSA-2048
# ---------------------------------------------------------
FGT2_KEY_CROSS_VERSION = {
    "finding_ref":  "FGA-F01 (FortiGate ARM64 8.0.0 discovery)",
    "cross_scope":  "CONFIRMED cross-version, cross-architecture",

    "version_md5_map": {
        "FGT_ARM64_8.0.0":  "c8eaa255efceab1512356f46f90b57b5  (fgt2.key, RSA-2048)",
        "FGT_x86-64_7.4.12": "c8eaa255efceab1512356f46f90b57b5  (fgt2.key, RSA-2048) -- IDENTICAL",
    },

    "implication": (
        "The fgt2.key RSA-2048 private key is IDENTICAL between FortiGate x86-64 v7.4.12 and "
        "FortiGate ARM64 v8.0.0 (different versions, different architectures, different build dates). "
        "This proves the key is firmware-baked (not per-device generated) and has persisted unchanged "
        "across at least one major version boundary (7.4 -> 8.0) and across architectures (x86-64 -> ARM64). "
        "The fgt2.crt not_before date is 2016-11-30, establishing the key has been in continuous use "
        "since at least November 2016 -- a 9+ year window as of 2026."
    ),

    "cert_signing_chain": (
        "fgt2.crt is signed by fortinet-subca2001 (CN=fortinet-subca2001, RSA-2048, valid 2016-2036). "
        "fortinet-subca2001 is in turn signed by fortinet-ca2 root (RSA-8192, valid 2016-2056). "
        "The PKI chain is also embedded in FortiFone Desktop firmware (FFF-F04). "
        "All Fortinet products share the same internal CA hierarchy."
    ),

    "scope_unknown": [
        "FGT x86-64 v7.0.9 (2022): fgt2.key not extracted (separate build pipeline, older product era)",
        "FGT x86-64 v8.0.0 (2026): datafs not yet extracted for direct comparison",
    ],
}


# ---------------------------------------------------------
# Cross-version key scope -- fgt_512.key RSA-512
# ---------------------------------------------------------
FGT_512_KEY_CROSS_VERSION = {
    "finding_ref":  "FGA-F02 (FortiGate ARM64) and FEXT-F05 (FortiExtender)",

    "modulus_pool": {
        "modulus_A": {
            "prefix":    "00:cf:b8:21:07:4c:9a:df:d7:95:1f:8e:da:b0:22:",
            "products":  ["FGT_x86-64_7.4.12", "FortiExtender_511F_7.0.3"],
            "note":      "Same RSA-512 modulus across FGT x86-64 and FortiExtender -- x86-64 build pipeline shared key",
        },
        "modulus_B": {
            "prefix":    "00:b5:ed:84:33:93:8a:7d:00:44:b9:8b:73:aa:98:",
            "products":  ["FGT_ARM64_8.0.0"],
            "note":      "Different RSA-512 modulus -- ARM64 build pipeline uses separate 512-bit key",
        },
    },

    "structural_finding": (
        "Fortinet uses different RSA-512 keys per build pipeline (x86-64 vs ARM64), "
        "but the key is still shared across all devices built from the same pipeline. "
        "Modulus-A is used by both FGT x86-64 AND FortiExtender, suggesting these share "
        "a common build/signing infrastructure. "
        "ALL instances use RSA-512 which is cryptographically broken regardless of modulus uniqueness."
    ),

    "extracted_factors": {
        "note":       "Both private keys are in plaintext firmware; no factoring required. Factors extracted directly.",
        "modulus_A": {
            "n":  "0xcfb821074c9adfd7951f8edab0229d295bb714b118eca5f687995afd5dc0f2ddedb07e1c0ca300f6846d3d9b958f5ad5ae67d0610d335447ef6b49157d41d2ad",
            "p":  "107095045731422606421607340394827291322211240411133720933781117103784129141009",
            "q":  "101583971568060441777466531308110073456717166856706173952340766593938766839773",
        },
        "modulus_B": {
            "n":  "0xb5ed8433938a7d0044b98b73aa98e5f92747a8811361d1dc9d0da381c22900045bc0d21fdf4594b74de6b1fd879207ce7901730ea29f1de7568a45cf398199cf",
            "p":  "97636374099857130169741076853870851523592073731019969402232674075263464647081",
            "q":  "97589981580399376801631665110380745102239180441911007493594721563758635549367",
        },
    },
}


# ---------------------------------------------------------
# Cross-version fortism LSM: anon-mem-exec policy delta
# ---------------------------------------------------------
FORTISM_ANON_MEM_EXEC_DELTA = {
    "finding_ref": "FGA-F05 (ARM64 8.0.0 fortism_config analysis)",

    "version_comparison": {
        "FGT_ARM64_8.0.0": {
            "total_domains":      "35 unique + repeated (87 entries total)",
            "anon_mem_exec":      6,
            "anon_exec_domains":  ["PRECHROOT", "CMDBSVR", "MISC", "WAD", "IPS", "WEB_SVC"],
        },
        "FGT_x86-64_7.4.12": {
            "total_domains":      "66 domain-name entries",
            "anon_mem_exec":      35,
            "anon_exec_domains":  [
                "ALL_ACCESS", "AUTOD", "AZD", "CMDBSVR", "CONFSYNCHBD", "CONSOLE",
                "CW_ACD", "CW_STAD", "DDNSCD", "DHCPCD", "DHCPD", "DSL_HSM",
                "ELBCD", "FGFMD", "FORTICLDD", "GCPD", "HATALK", "INIT",
                "IPSHELPER", "LNKMTD", "MIGLOGD", "MISC", "MODEMD", "PPPOED",
                "SDN_COMMON", "SESSIONSYNC", "SNIFFERD", "SSLVPND", "TELEMETRYD",
                "UPDATED", "URLFILTER", "VNED", "WAAGENT", "WAD", "WEB_SVC",
            ],
        },
    },

    "regression_analysis": (
        "FortiGate x86-64 7.4.12 has 35 domains with anon-mem-exec enabled, "
        "including high-sensitivity domains: SSLVPND, INIT, CONSOLE, MIGLOGD, SNIFFERD. "
        "FortiGate ARM64 8.0.0 has only 6 anon-mem-exec domains -- a significant tightening. "
        "This suggests Fortinet added anon-mem-exec to minimize the exploit attack surface "
        "in the v8.0.0 ARM64 build. "
        "Impact: compromise of SSLVPND on FGT 7.4.12 allows shellcode execution from anon memory "
        "(CVE-2023-27997 sslvpnd exploit class); on FGT 8.0.0 ARM64, SSLVPND lacks anon-mem-exec "
        "(harder shellcode execution path)."
    ),

    "additional_domains_in_7412": (
        "v7.4.12 has new/different domains vs ARM64 8.0.0: "
        "ALL_ACCESS (unrestricted domain), AUTOD, CW_ACD, CW_STAD, DDNSCD, DHCPCD, DHCPD, "
        "DSL_HSM (DSL modem), ELBCD, IPSHELPER, LNKMTD, MODEMD, PPPOED, "
        "SDN_COMMON, SESSIONSYNC, TELEMETRYD, UPDATED, URLFILTER, VNED, WAAGENT. "
        "These represent hardware-specific and feature-specific daemons not present in the "
        "ARM64 KVM build (which targets virtual/generic hardware)."
    ),
}


# ---------------------------------------------------------
# Cross-version rootfs encryption format survey
# ---------------------------------------------------------
ROOTFS_ENCRYPTION_SURVEY = {
    "format_table": {
        "FGT_7.0.9_x86-64":  "CPIO (standard, unencrypted) -- full rootfs accessible",
        "FGT_7.4.12_x86-64": "Magic 0x654accb2... (custom, encrypted) -- NOT accessible",
        "FGT_8.0.0_x86-64":  "Magic 0x5b6758cb... (same as FAZ/FMG 8.0.0) -- NOT accessible",
        "FGT_ARM64_8.0.0":   "Magic unknown (different from x86-64 8.0.0) -- NOT accessible",
        "FFW_8.0.0_x86-64":  "Magic 0xa3ba56c6... (FFW-specific) -- NOT accessible",
        "FWB_8.0.6_x86-64":  "Magic 0x84fe53de... (FWB-specific) -- NOT accessible",
        "FAZ_8.0.0_x86-64":  "Magic 0x5b6758cb... (same as FGT 8.0.0) -- NOT accessible",
        "FMG_8.0.0_x86-64":  "Magic 0x5b6758cb... (same as FGT/FAZ 8.0.0) -- NOT accessible",
    },

    "encryption_introduction": (
        "FortiGate rootfs was unencrypted in v7.0.9 (CPIO). "
        "FortiGate x86-64 v7.4.12 (May 2026) uses custom encryption (0x654accb2 magic). "
        "FortiGate x86-64 v8.0.0 shares an encryption format with FAZ/FMG 8.0.0 (0x5b6758cb). "
        "Encryption was introduced BETWEEN v7.0.9 and v7.4.12 -- the exact introduction version "
        "(7.2.x or 7.4.x) is unknown without additional firmware samples. "
        "v7.4.12 and v8.0.0 use DIFFERENT encryption formats (different magic bytes), "
        "suggesting the encryption scheme changed between these minor versions."
    ),

    "analysis_ceiling": (
        "All FortiOS versions since ~7.2+ use encrypted rootfs, blocking static RE of "
        "init, sslvpnd, httpsd, wad, cmdbsvr, and all other userspace binaries. "
        "Access requires: (1) live system exploitation, (2) bootloader debug access, "
        "(3) TPM unsealing research (ARM64), or (4) earlier unencrypted firmware version."
    ),
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "FGT_7.4.12_x86-64": {
        "kernel":           "Linux 4.19.13 (same as FFW 8.0.0) -- NOT analyzed; version identified only",
        "rootfs_gz":        "BLOCKED (magic 0x654accb2, encrypted)",
        "datafs_tar_gz":    "EXTRACTED -- keys, fortism_config.json, standard data files",
        "fgt2_key":         "CONFIRMED IDENTICAL to ARM64 8.0.0 (MD5 c8eaa255efceab1512356f46f90b57b5)",
        "fgt_512_key":      "CONFIRMED same modulus-A as FortiExtender 511F (MD5 1158fa1e43c915520a051fe4bebf90d6)",
        "fortism_config":   "EXTRACTED -- 35 anon-mem-exec domains (vs 6 in ARM64 8.0.0) -- significantly more permissive",
        "fortism_ioctls":   "NOT ANALYZED -- rootfs encrypted, fortism.ko not accessible",
    },

    "FGT_ARM64_8.0.0": {
        "reference": "fortinet_fortigate_arm64_re.py -- primary ARM64 module",
    },

    "FGT_x86-64_8.0.0": {
        "reference": "fortinet_fortigate_re.py -- primary x86-64 8.0.0 module (ANALYSIS_STATUS section)",
    },

    "cross_version_findings": [
        "CROSSVER-F01: fgt2.key RSA-2048 is IDENTICAL across FGT 7.4.12 x86-64 and 8.0.0 ARM64 -- same private key, 9+ year window (cert 2016-present)",
        "CROSSVER-F02: fgt_512.key split by pipeline: modulus-A (FGT x86-64 + FortiExtender), modulus-B (FGT ARM64) -- both RSA-512 (broken)",
        "CROSSVER-F03: FGT 7.4.12 x86-64 has 35 anon-mem-exec domains vs 6 in ARM64 8.0.0 -- SSLVPND anon-exec present in 7.4.12 but not 8.0.0",
        "CROSSVER-F04: Rootfs encryption introduced between v7.0.9 (CPIO, accessible) and v7.4.12 (encrypted) -- blocks static RE of modern versions",
        "CROSSVER-F05: Kernel progression: 3.2 (7.0) -> 4.19 (7.4) -> 6.12 (8.0 x86-64); FFW 8.0.0 stayed on 4.19 (same branch as FGT 7.4)",
    ],

    "pending": {
        "fgt_7.4.12_fortism":  "BLOCKED -- rootfs encrypted; fortism.ko not accessible; ioctl changes vs 8.0.0 unknown",
        "encryption_point":    "Need v7.2.x or v7.3.x samples to pinpoint when encryption was introduced",
        "fgt2_key_7.0.9":     "Unknown -- 7.0.9 uses pre-encryption pipeline; different datafs format",
    },
}
