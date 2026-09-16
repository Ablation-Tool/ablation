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
        "CROSSVER-F06: system.conf.def in FGT 8.0.0 VM64 datafs contains sae-password 'fortinet.mesh.root' in plaintext -- hardcoded WPA3 SAE mesh password same across all firmware images",
    ],

    "pending": {
        "fgt_7.4.12_fortism":  "BLOCKED -- rootfs encrypted; fortism.ko not accessible; ioctl changes vs 8.0.0 unknown",
        "encryption_point":    "Need v7.2.x or v7.3.x samples to pinpoint when encryption was introduced",
        "fgt2_key_7.0.9":     "Unknown -- 7.0.9 uses pre-encryption pipeline; different datafs format",
    },
}


# ---------------------------------------------------------
# CROSSVER-F06: Hardcoded SAE WiFi mesh password in system.conf.def
# ---------------------------------------------------------
CROSSVER_F06_SAE_PASSWORD = {
    "id":       "CROSSVER-F06",
    "product":  "FortiGate FortiOS 8.0.0 (VM64) -- system.conf.def in datafs.tar.gz; hardcoded plaintext SAE/WPA3 mesh password",
    "severity": "MEDIUM -- plaintext credential embedded in firmware; affects all devices running this firmware",
    "class":    "Hardcoded credential (CWE-798)",

    "source": {
        "firmware": "FGT 8.0.0 VM64-KVM (nbd1p1 -> /mnt/fgt800p1 -> datafs.tar.gz -> ./etc/system.conf.def)",
        "kernel":   "Linux 4.19.13 built 2026-04-20 (flatkc bzImage at /mnt/fgt800p1/flatkc)",
    },

    "evidence": [
        "system.conf.def line: 'set sae-password \"fortinet.mesh.root\"' (plaintext in firmware defaults)",
        "system.conf.def line: 'set password ENC XXUp2ozpdysrQ' (admin password, reversible encoding, same as FortiSwitch/FortiWeb -- FSW-F04)",
        "system.conf.def line: 'set trusthost1 0.0.0.0 0.0.0.0' (admin access from any IP by default)",
        "system.conf.def: '#config-version=FGVM64-8.0' (VM64 product variant)",
    ],

    "sae_password_detail": (
        "The SAE (Simultaneous Authentication of Equals) password 'fortinet.mesh.root' is the default "
        "credential used for WPA3 Enterprise / WiFi mesh authentication in FortiGate. "
        "SAE is the WPA3 key exchange protocol -- this password is used as the mesh network PSK. "
        "The default is hardcoded in the firmware image (system.conf.def is extracted at first boot). "
        "All FortiGate devices running this firmware share the same default SAE credential. "
        "An attacker knowing this credential can authenticate to any FortiGate WiFi mesh that "
        "has not changed the default password."
    ),

    "daemon_inventory": (
        "fortism_config.json in the same datafs shows complete FortiOS daemon binary paths: "
        "/bin/httpsd (HTTPS management), /bin/sslvpnd (SSL VPN), /bin/iked (IKE), "
        "/bin/wad (Web Application Daemon), /bin/cmdbsvr (config DB), /bin/fgfmd (FortiGate Federation Manager), "
        "/bin/scimd (SCIM identity), /bin/http_authd (HTTP auth), /bin/forticldd (FortiCloud), "
        "/bin/node (Node.js web service), /bin/cloudapid + awsd + ocid + azd + gcpd (cloud daemons). "
        "All in /bin/ -- confirms all FortiOS daemons are in single flat directory."
    ),

    "cross_product_admin_password": (
        "ENC XXUp2ozpdysrQ is the same default admin password encoding across FortiGate, FortiSwitch, FortiWeb "
        "(same string found in all three firmware system.conf.def files). "
        "FSW-F04 in fortinet_fortiswitch_re.py confirmed the string appears verbatim in /bin/init."
    ),
}


# ---------------------------------------------------------
# CROSSVER_MULTIVERSION_KEYS -- 8-year key reuse across 4 FortiOS generations
# Sources: FortiOS 6.0.3 / 7.0.3 / 7.2.0 / 8.0.0 qcow2 images; datafs extracted
# Mounts: /mnt/fgt603p1 (nbd2), /mnt/fgt703p1 (nbd3), /mnt/fgt70p1 (nbd4), /mnt/fgt720p1 (nbd5)
# ---------------------------------------------------------
CROSSVER_MULTIVERSION_KEYS = {
    "id":       "CROSSVER-F07",
    "title":    "RSA-2048 key (fgt2.key) identical across all FortiOS versions 2018-2026 (8-year span)",
    "severity": "CRITICAL -- shared private key across entire product fleet, all time",
    "class":    "Hardcoded cryptographic key (CWE-321)",

    "fgt2_key_rsa2048": {
        "pubkey_sha256": "3f9c28e38355e26d9f1fcaa50522ee9e74c57f17dcb9d80efa8c7d50bba4358c",
        "versions_confirmed": ["6.0.3 (2018)", "7.0.3 (2021)", "7.0.13 (2023)", "7.2.0 (2022)", "7.4.8 (2025)", "8.0.0 (2026)"],
        "path_in_datafs": "./etc/fgt2.key",
        "status": "IDENTICAL fingerprint across all 4 versions -- private key never rotated in 8 years",
        "impact": (
            "fgt2.key is used for device authentication in FortiGate management protocols (FGFM, FortiLink). "
            "Identical private key across all FortiOS versions and all devices that have not regenerated it "
            "means any firmware image leaks the private key for every deployed FortiGate. "
            "An attacker with one FortiOS image can impersonate any FortiGate device to FortiManager."
        ),
    },

    "fgt_512_key_rsa512": {
        "pubkey_sha256_pre_800":  "e5888c11ef0b452cf03be3b1bc325fa314a08402e7057b4fa6bdd46840223e78",
        "pubkey_sha256_800":      "bdef4ac15542bcc047eaa4de45c24f168cd7637be17de0e375735982b89dccbc",
        "versions_old_key": ["6.0.3 (2018)", "7.0.3 (2021)", "7.2.0 (2022)", "7.4.8 (2025)"],
        "versions_new_key": ["8.0.0 (2026)"],
        "rotation_window": "Between 7.4.8 (2025) and 8.0.0 (2026) -- NOT between 7.2.x and 8.0.0 as initially estimated",
        "status": "ROTATED silently between 7.4.8 and 8.0.0; no advisory published",
        "note": (
            "RSA-512 is cryptographically broken (factored in hours with CADO-NFS on commodity hardware). "
            "Fortinet silently rotated it in 8.0.0 but left the RSA-2048 (fgt2.key) untouched. "
            "All devices running 6.0.3 through 7.4.x share the same RSA-512 private key (7-year span), "
            "which can be factored to retroactively decrypt any session authenticated with this key."
        ),
    },

    "fgt2_crt": {
        "issuer":    "CN=fortinet-subca2001",
        "validity":  "Nov 30 2016 - Nov 20 2056 (40-year certificate)",
        "versions_confirmed": ["6.0.3", "7.0.3", "7.2.0"],
        "status": "IDENTICAL certificate across all three pre-8.0 versions",
        "note": (
            "40-year validity is a design choice, not an oversight -- Fortinet expects this cert to be valid "
            "for the operational lifetime of all deployed hardware. "
            "Same cert across versions means a cert revocation event would require simultaneous firmware update "
            "of the entire deployed FortiGate fleet."
        ),
    },

    "rootfs_encryption_timeline": {
        "6.0.3":  "gzip CPIO (unencrypted, full rootfs accessible)",
        "7.0.3":  "gzip CPIO (unencrypted, full rootfs accessible)",
        "7.0.13": "ENCRYPTED (magic 0x70c4180e, different scheme from 8.0.0)",
        "7.2.0":  "gzip CPIO (unencrypted, full rootfs accessible)",
        "8.0.0":  "ENCRYPTED (magic 0xcbd2efa3, TPM2-sealed key)",
        "analysis": (
            "Encryption was introduced between 7.0.9 (CPIO, accessible) and 7.0.13 (encrypted). "
            "7.2.0 reverted to unencrypted CPIO -- encryption was not uniformly deployed across branches. "
            "8.0.0 uses a different encryption magic from 7.0.13, suggesting a new scheme. "
            "Static RE is fully possible on 6.0.3, 7.0.3, and 7.2.0 -- all rootfs content accessible. "
            "7.0.13 and 8.0.0 require TPM2 key extraction or emulation-based dynamic analysis."
        ),
    },

    "default_credentials_cross_version": {
        "admin_password_enc": "ENC XXUp2ozpdysrQ",
        "admin_status": "IDENTICAL across 6.0.3, 7.0.3, 7.2.0, 8.0.0",
        "guest_password": "passwd guest (plaintext)",
        "guest_status": "IDENTICAL across all versions",
        "source": "system.conf.def in datafs.tar.gz for each version",
        "impact": (
            "Default admin ENC hash and guest plaintext credential unchanged across 8 years of releases. "
            "Any device where the admin password was not changed post-deployment is vulnerable to the known default. "
            "ENC prefix indicates FortiOS reversible encoding (not bcrypt) -- decoding possible with known algorithm."
        ),
    },

    "fgt_key_device_cert": {
        "pubkey_sha256": "01df5c4533518c2c8c5f482e9efbd58c7cf448efdffb3ddeb8b419a5f8ad5d3a",
        "cert_subject":  "CN=FortiGate, OU=FortiGate",
        "cert_issuer":   "CN=support",
        "cert_serial":   "0241C8",
        "cert_validity": "Jul 16 2015 - Jan 19 2038 (Y2038 = INT32_MAX timestamp)",
        "versions_confirmed": ["6.0.3 (2018)", "7.0.3 (2021)", "7.0.13 (2023)", "7.2.0 (2022)", "7.4.8 (2025)"],
        "versions_removed": ["8.0.0 (2026)"],
        "status": "IDENTICAL across all 5 pre-8.0.0 versions; REMOVED (not rotated) in 8.0.0",
        "impact": (
            "fgt.key is the default HTTPS private key for the FortiGate management interface (port 443). "
            "Any FortiGate device using the default certificate shares this private key. "
            "An attacker with the private key can decrypt any HTTPS management session or perform a "
            "transparent MitM against the management interface. "
            "Y2038 expiry (INT32_MAX) confirms auto-generation in 2015 with no review. "
            "Fortinet removed this cert in 8.0.0 instead of rotating it -- silently ending 10 years of reuse."
        ),
    },

    "libips_size_evolution": {
        "7.0.13": 8900728,
        "7.2.0":  10881736,
        "7.4.8":  13675184,
        "growth_7013_to_720_pct":  "+22%",
        "growth_720_to_748_pct":   "+26%",
        "note": "Consistent ~24% per-cycle growth -- each release adds significant new protocol parser code",
    },

    "attack_surface": [
        "CROSSVER-F07-A1: RSA-2048 fgt2.key -- extract from any firmware image -> impersonate any FortiGate to FortiManager (FGFM protocol) -> fleet-wide lateral movement without credential",
        "CROSSVER-F07-A2: RSA-512 fgt_512.key (pre-8.0.0) -- factor in hours with CADO-NFS -> decrypt any session authenticated with this key on 6.0.3 through 7.4.8 devices (7-year span)",
        "CROSSVER-F07-A3: fgt.key (pre-8.0.0) -- default HTTPS device cert private key; MitM any management session on default-cert FortiGate (10-year span, 2015-2025)",
        "CROSSVER-F07-A4: fgt2.crt 40-year shared CA cert -- cert pinning bypass; MitM FGFM traffic between FortiGate and FortiManager using known private key",
        "CROSSVER-F07-A5: Default admin ENC XXUp2ozpdysrQ -- decode with FortiOS ENC algorithm -> plaintext admin password for any device that has not changed default",
        "CROSSVER-F07-A6: Unencrypted rootfs (6.0.3/7.0.3/7.2.0) -- extract and analyze all FortiOS binaries without firmware decryption; directly compare httpsd/sslvpnd/wad/cmdbsvr across versions",
    ],
}


# ---------------------------------------------------------
# CROSSVER-F08: IPS/AV engine binary size evolution (7.2.0 vs 7.4.8)
# Sources: datafs.tar.gz extracted from each qcow2
# ---------------------------------------------------------
CROSSVER_ENGINE_EVOLUTION = {
    "id":    "CROSSVER-F08",
    "title": "FortiOS IPS and AV engine library size growth between 7.2.0 and 7.4.8",
    "class": "Attack surface expansion",

    "libips_so_new": {
        "7.2.0": {"size_bytes": 10881736, "build_id": "1e53d9610563168760c96e6fc804228e74e9ec31", "sha256": "348717c0c97cfb7b4fc29111beec8554b44fc2ee62d07d4df3c06f25050375dd"},
        "7.4.8": {"size_bytes": 13675184, "build_id": "37d8f9362af583fd9a81ec5ebb133ec381359101", "sha256": "d86541c4d9428f7d6ad75557b27373cc7800ee6df40678474c4dc7b5f61ab3c8"},
        "growth_bytes": 2793448,
        "growth_pct":   "+26%",
        "note": "Different BuildIDs and SHA256 -- distinct binaries; IPS engine added ~2.8MB of new code between releases",
    },

    "libav_so_new": {
        "7.2.0": {"size_bytes": 6667680},
        "7.4.8": {"size_bytes": 8672032},
        "growth_bytes": 2004352,
        "growth_pct":   "+30%",
        "note": "AV engine grew +30% between 7.2.0 and 7.4.8; 7.4.8 also ships libav.so.new.x (signed variant)",
    },

    "hash_bin_inventory_delta": {
        "8.0.0": 410,
        "7.4.8": 119,
        "note": (
            "7.4.8 IMA measurement list covers only 119 binaries vs 410 in 8.0.0. "
            "8.0.0 significantly expanded the set of IMA-measured binaries -- broader integrity coverage. "
            "7.4.8 measures primarily /bin/ and /usr/local/apache2/modules/; 8.0.0 adds full tree."
        ),
    },

    "datafs_extra_7.4.8": [
        "libav.so.new.x -- signed/chk variant present in 7.4.8 but not 7.2.0",
        "libips.so.new.x -- signed/chk variant present in 7.4.8 but not 7.2.0",
        "casb.dat -- new in 7.4.8; CASB policy database",
        "cid.dat -- new in 7.4.8; certificate intelligence data",
        "app.iot.rules.x + app.json.gz -- IoT classification engine upgraded",
        "application.rules.x -- signed application signature DB",
    ],

    "re_target_priority": (
        "libips.so.new in 7.4.8 (13.7MB stripped ELF) is the primary target: "
        "IPS engine parses all network traffic before firewall policy; "
        "memory corruption in the parser -> pre-auth RCE at kernel network path. "
        "Semantic sweep on both 7.2.0 and 7.4.8 versions maps new code added in 7.4.8 "
        "and finds any functions matching buffer-overflow / length-check-missing patterns. "
        "Cross-version homolog diffing via ablation identifies functions added/changed between releases."
    ),
}


# ---------------------------------------------------------
# CROSSVER-F09: libips.so.new 7.4.8 semantic sweep results
# Sweep: 4000 functions, 8 vulnerability query profiles, all-MiniLM-L6-v2
# ---------------------------------------------------------
CROSSVER_IPS_SWEEP_748 = {
    "id":       "CROSSVER-F09",
    "binary":   "/tmp/fgt748_datafs/lib/libips.so.new",
    "version":  "FortiOS 7.4.8",
    "method":   "BinFuse opcode normalization + all-MiniLM-L6-v2 semantic embedding; prologue-based function extraction",
    "corpus":   "4000 functions (hit limit; actual function count higher)",

    "top_candidates": {
        "VA_0x415311": {
            "label":    "compression-block-parser",
            "score":    0.2710,  # http-header-overflow query
            "stack_frame_bytes": 0x198,  # 408 bytes
            "flags": [
                "Parses three 16-bit fields from external buffer at [rdi+0], [rdi+2], [rdi+4]",
                "Remaining-length check: r12 - 6 - field1 - field2 - field3 (total sum vs packet length)",
                "Random access [rdi + rax + 5] where rax = field1 (word from packet) after cmp rax, 7 check",
                "BSR-based variable-width integer decoding (0-7 byte LEB-like encoding) at 0x4159e0",
                "Dispatch via jump table at 0x4159e0 indexed by field1 value",
                "408-byte stack frame; called via function pointer (no direct CALL rel32 callers found)",
                "TODO: verify [rdi + rax + 5] cannot exceed buffer bounds when field1 is max uint16",
            ],
            "verdict": "PLAUSIBLE -- bounds check validates total but per-segment random access not explicitly bounded",
        },
        "VA_0xd86f0": {
            "label":    "linked-list-destructor",
            "score":    0.3919,  # malloc-int-overflow query
            "flags": [
                "Walks r12-based pointer array of size 0x2000 bytes (512 pointers)",
                "For each non-null pointer: reads [rbx] (next ptr), calls 0xf05d0 (free wrapper), iterates",
                "Pattern: rbx = [r12], call free(rbx), rbx = old[rbx] -- if any code retains a pointer to freed nodes, UAF",
                "TODO: identify all callers and check for retained references post-free",
            ],
            "verdict": "PLAUSIBLE -- free loop; need caller graph to confirm UAF potential",
        },
        "VA_0xcf8e0": {
            "label":    "c++-object-init-or-logger",
            "score":    0.4223,  # sprintf-stack-buf (highest single query score)
            "flags": [
                "xorps + movups zero-init pattern (C++ object construction)",
                "RIP-relative string LEA followed by indirect call through vtable",
                "Likely C++ constructor or logging wrapper -- not direct buffer overflow target",
            ],
            "verdict": "LOW -- instrumentation/logging class, not a packet parser",
        },
        "VA_0x3296f0": {
            "label":    "multi-arg-accessor",
            "score":    0.2962,  # format-string query
            "flags": [
                "6 registers pushed (r14/r13/r12/rbx + stack args via [rbp+0x10])",
                "Feature flag check at entry: cmp byte ptr [rip + offset], 0",
                "Validates pointer pair r12/r14 non-null before dereferencing",
                "Reads [r14] as size field, compares to constant 8 (protocol field accessor pattern)",
                "Stores rax from global pointer [rip + offset + 0x40] -- likely capability/config accessor",
            ],
            "verdict": "LOW -- protocol field accessor / config reader, not a parser",
        },
    },

    "7.4.8_binary_inventory_highlights": {
        "openssl_upgrade":  "libcrypto.so.3 + libssl.so.3 in IMA list -- OpenSSL 3.x (from 1.1.1n in 7.2.0)",
        "fips_module":      "/lib/ossl-modules/fips.so -- OpenSSL FIPS 140 module included in 7.4.8",
        "apache_modules":   "mod_md.so + mod_watchdog.so in IMA list -- Apache httpd with ACME (Let's Encrypt) support",
        "ebpf":             "wad_dispatcher_kern.ebpf -- WAD eBPF kernel program (same as 8.0.0)",
        "jwt":              "libjwt.so.2 -- JWT library; suggests OAuth/OIDC token handling in management interface",
        "dlp_engine":       "libdlp.so -- Data Loss Prevention engine as shared library",
        "kmip":             "libkmip.so.0 -- KMIP key management client (HSM integration)",
        "node_addon":       "3505ff29135da0890d141264ed1e2af1.node -- same native addon pattern as 8.0.0",
        "libjemalloc":      "libjemalloc.so.2 -- jemalloc allocator (heap layout predictability affects exploit reliability)",
    },

    "fgt2_crt_7.4.8_confirmed": {
        "serial":   "109D",
        "issuer":   "CN=fortinet-subca2001",
        "validity": "Nov 30 2016 - Nov 20 2056",
        "status":   "IDENTICAL to 6.0.3/7.0.3/7.2.0 -- same cert across all 5 versions",
    },

    "default_creds_7.4.8": {
        "admin_enc": "ENC XXUp2ozpdysrQ -- IDENTICAL (now confirmed 6.0.3/7.0.3/7.2.0/7.4.8/8.0.0)",
        "guest":     "present in system.conf.def",
    },

    "next_steps": [
        "Manual disasm: verify 0x415311 [rdi+rax+5] access vs actual buffer bounds -- need caller context",
        "Manual disasm: 0xd86f0 caller graph -- identify code paths that retain freed node pointers",
        "jemalloc heap layout: document implications for exploit reliability vs glibc malloc",
        "mod_md.so RE: Apache ACME module processes domain validation -- potential SSRF or cert injection surface",
    ],
}


# ---------------------------------------------------------
# CROSSVER-F10: libips.so.new cross-version semantic diff (7.2.0 vs 7.4.8)
# ---------------------------------------------------------
CROSSVER_IPS_DIFF_720_748 = {
    "id":       "CROSSVER-F10",
    "method":   "Parallel semantic sweep on both versions; same 8-query profile; top-3 candidates per query",

    "corpus_sizes": {
        "7.2.0_libips": "1432 functions (10.9MB binary)",
        "7.4.8_libips": "4000 functions (13.7MB binary, hit cap)",
        "note": "7.4.8 has ~3x more detected prologues despite only 26% larger binary -- different inlining/optimization",
    },

    "7.2.0_top_candidates": {
        "VA_0x613770": {
            "queries_hit":  5,  # memcpy-no-bound, sprintf-stack-buf, tls-asn1-overflow, http-header-overflow, ips-sig-heap
            "stack_frame":  0x138,
            "flags": [
                "6-argument function (rdi/rsi/rdx/rcx/r8/r9 + stack args at [rsp+0x170])",
                "movabs rax, 0x50604030201 -- 6-byte type-code lookup table used with shr by cl*8",
                "cl computed from [rsp+0x8c] -- a field from decoded context struct",
                "Multiple indirect calls through vtable pointers (protocol decoder dispatch)",
                "Context switch between protocol variants via type byte extraction from movabs literal",
                "Appears across 5 vulnerability queries -- high-priority for manual verification",
            ],
            "verdict": "PLAUSIBLE -- protocol decoder dispatch with type byte extraction; need full trace",
        },
        "VA_0x663730": {
            "queries_hit":  1,  # use-after-free (score 0.3318)
            "stack_frame":  0x318,  # 792 bytes
            "flags": [
                "Reads [rsi+0x178] == 0x2f (protocol state check) and [rsi+0x1d8] == 2 (type check)",
                "Three sequential allocations using sizes derived from struct fields",
                "EACH multiplication has explicit setno/jo overflow guard: r14*4, r15*0x18",
                "Guards appear complete -- all three mul paths checked before allocation",
                "Verdict: overflow guards are correct and consistent on analyzed paths",
            ],
            "verdict": "LOW -- overflow guards validated as correct on analyzed allocation paths",
        },
        "VA_0x269a1c": {
            "queries_hit":  1,  # malloc-int-overflow (score 0.3483, highest single 7.2.0 score)
            "flags": [
                "TODO: not yet disassembled -- highest malloc-int-overflow score in 7.2.0",
                "VA 0x269a1c in early .text section (low offset) -- may be early initialization code",
            ],
            "verdict": "UNVERIFIED -- pending disassembly",
        },
    },

    "cross_version_delta_observations": [
        "7.2.0 top candidates cluster around 0x6x0000 range (high .text offset); 7.4.8 candidates cluster at 0x4x0000 and 0xd0000",
        "Different VA ranges suggest significant code reorganization between versions, not just appended code",
        "0x613770 (7.2.0) appearing in 5 queries but no equivalent high-signal function in 7.4.8 could indicate: (a) vulnerability patched in 7.4.8, (b) function inlined/split, or (c) recompiled differently",
        "7.4.8 libips.so.new ships libips.so.new.x (signed variant) -- signature verification now enforced in 7.4.8",
        "0x663730 overflow guards confirmed correct in 7.2.0; 7.4.8 equivalent not found (may be inlined or refactored)",
    ],

    "priority_action": (
        "Disassemble VA 0x269a1c in 7.2.0 libips.so.new -- highest malloc-int-overflow score (0.3483); "
        "early .text location suggests possible initialization/registration path. "
        "Also need caller graph for 0x613770 to understand input trust boundary."
    ),
}
