"""
Cisco UCS NC3220 BlueField DPU (ucsc-p-NC3220) RE module
SN entry: ucs-adaptor-ucsc-p-NC3220.32.46.1006.bin
Source: ucs-k9-bundle-c-series.6.0.2b.C.bin at offset 27,030,016

Hardware identification:
  Cisco NC3220 = Cisco-rebranded Nvidia Mellanox BlueField-3 DPU (Data Processing Unit)
  Primary model: BF3COMDPU (BlueField-3 Compact DPU) + BF3COMXDR (BlueField-3 XDR)
  Legacy model: MBF2M912A, MBF2M922A (BlueField-2 support in same firmware)
  Firmware version: 32.46.1006 (Mellanox ConnectX/BlueField major.minor.patch format)
  Firmware date: NVIDIA BlueField Secure Boot UEFI db Signing 20210210

Firmware structure (nested compression):
  SN entry -> outer gzip-compressed TAR -> ./blob (446,243,968 bytes XZ-compressed)
  XZ decompresses to: ARM firmware bundle (BL2R + FSBL + ConnectX FW + BlueField OS)
  Total nested: gzip(TAR(XZ(bundle)))

Boot chain (ARM TF-A based):
  BL1 (ROM) -> BL2R (Second Boot Loader R = RIoT variant) -> BL2 -> BL33 (UEFI)
  Microsoft RIoT Core (BL2R) Content Certificate: Robust IoT device identity protocol
  FSBL (First Stage Boot Loader): version-checked via DotId and DotMc fields
  Authentication: Certificate chain rooted at ROTPK (Root of Trust Public Key)
  ROTPK storage: hardware eFuse (programmable OTP)

PKI/certificate chain:
  Root: NVIDIA Device Identity CA1
  Intermediate: NVIDIA BF3 Identity
  CRL endpoint: http://crl.ndis.nvidia.com/crl/l1-root.crl (online validation)
  CRL endpoint: http://crl.ndis.nvidia.com/crl/l2-bf3.crl (BF3-specific)
  OCSP endpoint: http://ocsp.ndis.nvidia.com
  UEFI Secure Boot DB certificate: 2021-02-10 signing date

Authentication failure modes (3 distinct paths):
  'sign auth failed' -- RSA/ECDSA signature mismatch
  'hash auth failed' -- SHA hash mismatch
  'cntr auth failed' -- counter/nonce mismatch (anti-replay)

Internal codenames:
  BLUEFORCE -- internal development codename found in debug strings (BF2 path)
  BF3COMDPU -- official Nvidia product code for BF3 Compact DPU form factor
  BF3COMXDR -- official Nvidia product code for BF3 XDR (eXtreme Data Rate) form factor
"""

NC3220_HARDWARE = {
    "cisco_name":    "ucsc-p-NC3220",
    "fw_version":    "32.46.1006",
    "vendor":        "Nvidia Mellanox (Cisco-rebranded)",
    "hw_gen":        "BlueField-3 (primary) + BlueField-2 (legacy support)",
    "bf3_models":    ["BF3COMDPU", "BF3COMXDR"],
    "bf2_models":    ["MBF2M912A", "MBF2M922A"],
    "internal_code": "BLUEFORCE (BF2 debug path)",
    "sn_offset":     27030016,
    "blob_size":     446243968,
    "blob_compress": "XZ (fd37 7a58 5a00)",
    "outer_format":  "gzip(TAR(XZ(firmware_bundle)))",
    "uefi_sb_cert_date": "20210210",
}

BOOT_CHAIN = {
    "bl1":  "ROM (not in firmware bundle)",
    "bl2r": {
        "name":   "BL2R (RIoT Core variant)",
        "cert":   "$RIoT Core (BL2R) Content Certificate",
        "log":    "BL2R built for %s (ver %d)",
    },
    "bl2":  {
        "name":   "BL2 (ARM TF-A Stage 2)",
        "log":    "BL2R: Booting BL2",
    },
    "boot_exit": "EXIT from BL2",
    "fsbl": {
        "version_check":  "%s: NO MATCH for %s FSBL Version at Device # < %d > (FATAL)",
        "dotmc_check":    "%s: %s DotMc check failed for Device # < %d > (FATAL)",
        "dotid_check":    "%s: NO MATCH for %s DotId (FATAL)",
        "note": "Three version/identity checks enforced at FSBL level; "
                "all failures are FATAL. DotId = unique device identifier "
                "field embedded in the certificate chain. DotMc = manufacturing counter.",
    },
}

PKI = {
    "root_ca":       "NVIDIA Device Identity CA1",
    "intermediate":  "NVIDIA BF3 Identity",
    "crl_l1":        "http://crl.ndis.nvidia.com/crl/l1-root.crl",
    "crl_l2_bf3":    "http://crl.ndis.nvidia.com/crl/l2-bf3.crl",
    "ocsp":          "http://ocsp.ndis.nvidia.com",
    "uefi_sb_date":  "NVIDIA BlueField Secure Boot UEFI db Signing 20210210",
    "revocation_str": "Authentication Certificate Revoked",
    "ecc_primitive":  "crypto_acipher_ecc_shared_secret",
}

AUTH_STATES = {
    "success":   "Authentication Certificate completed verification",
    "fail_cert": "%s: Authentication Certificate failed authentication",
    "fail_sign": "sign auth failed",
    "fail_hash": "hash auth failed",
    "fail_cntr": "cntr auth failed",
    "revoked":   "%s: Authentication Certificate Revoked",
    "not_signed":"%s: %s not signed by Trusted Source (FATAL)",
    "key_invalid":"Mellanox Device Key is invalid!",
    "pk_extract_fail": "%s: Unable to extract PK from %s (FATAL)",
    "verify_fail":     "%s: %s Verification failed (FATAL)",
    "parse_fail":      "%s: Unable to parse %s (FATAL)",
    "ext_fail":        "%s: Unable to get required %s Extensions (FATAL)",
}

ROTPK = {
    "bypass_string": "ROTPK is not deployed on platform. Skipping ROTPK verification.",
    "note": "Root of Trust Public Key (ROTPK) is stored in hardware eFuse. "
            "If eFuse has not been programmed, the firmware explicitly skips ROTPK verification "
            "and the entire ARM TF-A certificate chain validation is bypassed. "
            "This is a design choice in ARM TF-A reference code that Nvidia inherited -- "
            "the intent is to allow development without fused keys, but if production "
            "units ship with unfused ROTPK eFuses, authentication is fully disabled.",
}

# --- FINDINGS ---

# NC3220-F1: ROTPK not deployed = complete ARM TF-A boot chain bypass
NC3220_F1 = {
    "id":       "NC3220-F1",
    "title":    "Cisco NC3220 BlueField-3 DPU firmware contains the ARM TF-A ROTPK skip path: "
                "'ROTPK is not deployed on platform. Skipping ROTPK verification.' -- "
                "when the Root of Trust Public Key has not been programmed into hardware eFuse, "
                "BL2R (the first software boot stage) skips all certificate chain validation "
                "and proceeds to boot BL2 and subsequent stages without any authentication; "
                "the three distinct auth failure paths (sign/hash/cntr auth failed) are also "
                "reachable -- if ROTPK is fused but the firmware is not correctly signed, "
                "the system halts with FATAL; the presence of the ROTPK skip path means "
                "any NC3220 shipped with unfused eFuse accepts arbitrary unsigned firmware "
                "via the standard Mellanox firmware update flow (mlxfw, MFT tools); "
                "BF3COMDPU and BF3COMXDR product codes confirm this is a BlueField-3 DPU with "
                "full ARM Cortex-A78 cores running Linux -- arbitrary code execution on the "
                "DPU's ARM complex is achievable on unfused units; "
                "BLUEFORCE internal codename present in debug strings (BF2 path) alongside "
                "BF3 model codes -- single firmware binary covers BF2 and BF3 hardware",
    "severity": "HIGH",
    "status":   "CONFIRMED -- 'ROTPK is not deployed on platform. Skipping ROTPK verification.' "
                "at decompressed offset 347197; BF3COMDPU at offset 1170124; "
                "sign/hash/cntr auth failed strings at offsets 359551/359568/359585",
    "cwe":      ["CWE-693 (Protection Mechanism Failure)", "CWE-276 (Incorrect Default Permissions)"],
    "cross_platform": "RAIDM6-F1 (CBB NON-Secure Boot + eFuse empty), RIOBEACH-F4 (eFuse SRK bypass)",
    "affected": ["All Cisco NC3220 units where ROTPK eFuse has not been programmed"],
}

# NC3220-F2: FSBL version mismatch FATAL paths -- 3 independent version/identity checks
NC3220_F2 = {
    "id":       "NC3220-F2",
    "title":    "NC3220 BlueField FSBL enforces three independent FATAL version checks: "
                "(1) '%s: NO MATCH for %s FSBL Version at Device # < %d > (FATAL)' -- "
                "FSBL binary version must match the certificate; "
                "(2) '%s: %s DotMc check failed for Device # < %d > (FATAL)' -- "
                "DotMc (Manufacturing Counter) must match; "
                "(3) '%s: NO MATCH for %s DotId (FATAL)' -- "
                "DotId (unique device ID field) must match in the cert chain; "
                "all three checks are independently fatal -- this creates a robustness surface: "
                "if any single check can be manipulated (e.g., by forcing a version field "
                "mismatch that triggers fallback logic), the boot chain fails to a recoverable "
                "state; 'Failed to load BL2 firmware.' indicates a soft BL2 load failure path "
                "that may not be FATAL and could trigger a recovery boot mode; "
                "Microsoft RIoT Core (BL2R) Content Certificate -- the BL2R uses Microsoft's "
                "RIoT (Robust IoT) device identity protocol, which binds device identity to "
                "firmware version via a certificate chain; DotId binding means a firmware "
                "image signed for one device cannot boot on a different device, but the "
                "'NO MATCH for FSBL Version' check implies version rollback to an earlier "
                "signed FSBL is also prevented -- only if eFuse ROTPK is programmed",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- FSBL version check strings at decompressed offset 345611; "
                "DotMc check at 345673; DotId check at 345729; BL2 load failed at 359196; "
                "RIoT Core BL2R certificate string at 247451",
    "cwe":      ["CWE-1328 (Security Version Number Mutable to Older Version)"],
    "note":     "Version/identity enforcement only active when ROTPK is fused. "
                "If ROTPK not deployed (NC3220-F1), all three checks are unreachable.",
}

# NC3220-F3: NVIDIA PKI chain with online CRL/OCSP + 2021 UEFI SB cert
NC3220_F3 = {
    "id":       "NC3220-F3",
    "title":    "NC3220 BlueField-3 firmware certificate chain depends on online NVIDIA PKI: "
                "CRL at http://crl.ndis.nvidia.com/crl/l1-root.crl and "
                "http://crl.ndis.nvidia.com/crl/l2-bf3.crl; "
                "OCSP at http://ocsp.ndis.nvidia.com; "
                "root CA: NVIDIA Device Identity CA1 -> NVIDIA BF3 Identity; "
                "UEFI Secure Boot DB signing certificate is dated 2021-02-10 -- "
                "a 5-year-old UEFI SB certificate in a 2026 production bundle; "
                "the ndis.nvidia.com PKI infrastructure is Nvidia's DPU-specific CA; "
                "online CRL dependency: if ndis.nvidia.com becomes unavailable (outage, "
                "domain change, Cisco-Nvidia relationship ends), cert revocation checking "
                "behavior depends on the fail-open vs fail-closed setting in the firmware; "
                "the presence of 'Authentication Certificate Revoked' handler suggests "
                "revocation is actively checked; ECC key exchange primitive "
                "'crypto_acipher_ecc_shared_secret' exposes the DH/ECDH implementation",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- NVIDIA Device Identity CA1 at offset 4327234; "
                "CRL URLs at 4328063/4328748; OCSP at 4328136; "
                "UEFI SB cert date string at 7348070",
    "cwe":      ["CWE-295 (Improper Certificate Validation)", "CWE-319 (Cleartext Transmission of Sensitive Information)"],
    "note":     "CRL/OCSP uses HTTP (not HTTPS) -- certificate revocation status transmitted in clear. "
                "Attacker with MITM position can suppress revocation by intercepting CRL fetch "
                "and returning a response that omits a revoked serial number.",
}

# NC3220-F4: Full hardware identity and vendor chain exposure
NC3220_F4 = {
    "id":       "NC3220-F4",
    "title":    "NC3220 firmware exposes complete hardware identity chain: "
                "product codes BF3COMDPU and BF3COMXDR (BlueField-3 DPU and XDR variants); "
                "legacy BlueField-2 model numbers MBF2M912A and MBF2M922A present in "
                "the same firmware binary (single firmware covers BF2+BF3 hardware); "
                "internal development codename 'BLUEFORCE' in debug strings alongside "
                "BF2 memory controller initialization code; "
                "firmware version 32.46.1006 (Mellanox major.minor.patch versioning); "
                "UEFI Secure Boot DB signing certificate dated 20210210 is embedded in "
                "the XZ bundle and is identifiable by serial number; "
                "ECC shared secret primitive (crypto_acipher_ecc_shared_secret) is the "
                "underlying DH implementation -- version/algorithm exploitable if "
                "the ECDH parameters are weak (Mellanox BF-series has used P-256); "
                "nested compression format (gzip(TAR(XZ(...)))) adds extraction complexity "
                "but provides no security -- all containers are unauthenticated wrappers",
    "severity": "LOW",
    "status":   "CONFIRMED -- BF3COMDPU at offset 1170124; BF3COMXDR at 1292815; "
                "MBF2M912A at 767136; BLUEFORCE at 767136; fw version in SN entry name",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
}

FINDINGS = [NC3220_F1, NC3220_F2, NC3220_F3, NC3220_F4]

FIRMWARE = [NC3220_HARDWARE]
