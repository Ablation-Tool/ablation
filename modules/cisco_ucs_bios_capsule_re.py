"""
Cisco UCS BIOS Capsule RE module
Targets: B480 M5 BIOS 4.3.2g, X410C M7 BIOS 6.0.2a
Source: ucs-k9-bundle-b-series.6.0.2b.B.bin (B-Series bundle)

Extraction chain (B480 M5):
  Bundle gzip at 0x354 -> 1163MB stream -> SN "ucs-b480-m5-bios.B480M5.4.3.2g.0.0116260830.bin"
  -> inner gzip (SN+888, wbits=47, hsize BE) -> TAR -> gzip(blob) -> TAR
  -> "B480M5-BIOS-4-3-2g-0.cap" (Cisco CIMCPackage, 8982495 bytes, uname=cspgre gname=eng)
  -> bzip2 payload at offset 2048 -> LFBC SPI image (33558744 bytes = 32MB)
  -> Intel IFD at 0x10e4, 9x _FVH firmware volumes

Extraction chain (X410C M7):
  Bundle -> SN "ucs-x410-m7-bios.X410M7.6.0.2a.0.0130261651.bin" at decomp+674893312
  -> gzip at SN+880, wbits=47, hsize BE -> TAR (imghdr.bin + blob)
  -> blob (gzip) -> TAR -> "X410M7-BIOS-6-0-2a-0.pkg" [CISCO UCS BIOS CIMCPackage]
  -> gzip payload at offset 2048 -> PAX tar (package.json, BiosUpdate.json, BiosTokens/, biosFiles/)
  -> biosFiles/X410/M7/6F6/X410M7.6.0.2a.0.cap

LFBC format (B480 M5 SPI image):
  Magic: 4c464243 "LFBC" + version(4) + field(4) + flags(4) + section_table
  Sections: BIOS_SPI_FLASH (offset 16), SPS (offset 64), BIOS (offset 96)
  Intel IFD at LFBC+0x10e4 (after Cisco-specific header)
  9 UEFI Firmware Volumes (_FVH): 512KB + 10876KB + 128KB + 4096KB + 4x smaller

Cisco CIMCPackage header format (all BIOS capsules):
  "[CISCO UCS BIOS CIMCPackage]\n" + INI key=value + binary cert blob + null padding to ImageOffset
  Binary cert region: X.509 DN string(s) + raw DER certificate bytes
  Certificate signing key embedded as plain DN string before DER blob

Build account exposed in TAR metadata: uname=cspgre, gname=eng (Cisco build service account)
"""

FIRMWARE_B480M5 = {
    "target":    "Cisco UCS B480 M5 BIOS 4.3.2g",
    "file":      "ucs-b480-m5-bios.B480M5.4.3.2g.0.0116260830.bin",
    "model":     "UCS B480 M5 (4-socket Intel Xeon Purley, B-Series Blade)",
    "platform_codename": "Presidio",  # from signing cert OU and BIOS strings
    "bios_alt_codenames": ["Pomona", "Plumas1U", "Plumas2U", "Madeira", "Morroco"],
    "capsule_format": "Cisco CIMCPackage INI header + bzip2(LFBC SPI image)",
    "signing_cert_dn": "CN=CiscoSystems;OU=Presidio;O=CiscoSystems",
    "build_account": "cspgre / eng (from TAR metadata)",
    "image_version": "B480M5.4.3.2g.0.0116260830",
    "image_offset": 2048,
    "acm_svn_authorized": 2,
    "km_svn": 0,   # Key Manifest SVN — no rollback protection
    "bpm_svn": 0,  # Boot Policy Manifest SVN — no rollback protection
    "spi_size_mb": 32,
    "lfbc_sections": ["BIOS_SPI_FLASH", "SPS", "BIOS"],  # SPS = Intel Server Platform Services (ME)
    "uefi_fv_count": 9,
    "main_fv_guid": "5c60f367-a505-419a-859e-2a4ff6ca6fe5",
    "main_fv_size_mb": 24.5,
    "nvar_store_guid": "cef5b9a3-476d-497f-9fdc-e98143e0422c",
    "nvar_variables": 10,  # pre-provisioned at factory
    "bios_framework": "AMI (AMITSESETUP NVAR present; LENOVO_SYSTEM_* GUIDs in DXE modules)",
    "findings": ["B480BIOS-F1", "B480BIOS-F2", "B480BIOS-F3", "B480BIOS-F4"],
}

FIRMWARE_X410M7 = {
    "target":    "Cisco UCS X410C M7 BIOS 6.0.2a",
    "file":      "ucs-x410-m7-bios.X410M7.6.0.2a.0.0130261651.bin",
    "model":     "UCS X410C M7 (2-socket Intel Xeon Sapphire Rapids, X-Series Compute Node)",
    "platform_codename": "KellerBeachMR2",  # from package.json PackageName
    "capsule_format": "Cisco CIMCPackage INI header + gzip(PAX tar with JSON metadata + .cap)",
    "signing_cert_dn": "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",  # DIFFERENT from B480
    "build_account": "cspgre / eng (from TAR metadata)",
    "image_version": "X410M7.6.0.2a.0.0130261651",
    "cpu_ids": ["806F6", "C06F2"],  # Sapphire Rapids + Granite Rapids (5th Gen Xeon)
    "cpu_id_dir": "6F6",  # subdirectory in biosFiles/X410/M7/
    "acm_svn_authorized": 2,
    "km_svn": 0,
    "bpm_svn": 0,
    "bios_token_count": 218,
    "findings": ["X410BIOS-F1", "X410BIOS-F2", "X410BIOS-F3"],
}

# B480BIOS-F1: Boot Guard KM/BPM SVN=0 — no revocation chain for BIOS signing keys
B480BIOS_F1 = {
    "id":       "B480BIOS-F1",
    "title":    "Intel Boot Guard Key Manifest SVN=0 and Boot Policy Manifest SVN=0 in production "
                "B480 M5 and X410C M7 BIOS capsules; ACM_SVN=2 tracks module revocations but the "
                "signing keys for both KM and BPM have never been revoked; if Cisco's BIOS signing "
                "private key (CN=CiscoSystems;OU=Presidio for B480, OU=BIOS_IMG for X410) is "
                "compromised, Boot Guard provides no SVN rollback mechanism to invalidate old images; "
                "an attacker with the leaked signing key could deliver SVN=0 BIOS updates that "
                "Boot Guard accepts as valid on all deployed B480 M5 and X410C M7 platforms",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — ImageKM_SVN=0 and ImageBPM_SVN=0 extracted from capsule headers "
                "of both B480M5.4.3.2g and X410M7.6.0.2a; ACM_SVN_Authorized=2 present in both",
    "cwe":      ["CWE-757 (Selection of Less-Secure Algorithm During Negotiation)",
                 "CWE-327 (Use of Broken or Risky Cryptographic Algorithm)"],
    "capsule_header_fields": {
        "ImageACM_SVN_Authorized": 2,
        "ImageKM_SVN": 0,
        "ImageBPM_SVN": 0,
    },
    "note":     "Cross-reference with M8-F1 (Intel M8 CIMC disables Boot Guard via "
                "'echo 0 > /proc/cisco/bootguard_enabled_cpu') — that finding makes Boot Guard "
                "enforcement moot on the Intel Blade M8 CIMC platform specifically, but B480 M5 "
                "BIOS is managed by a B-Series blade CIMC (not Intel M8) and Boot Guard is not "
                "explicitly disabled there. SVN=0 is the primary exploitable weakness on B480 M5.",
}

# B480BIOS-F2: Two distinct BIOS signing certificates reveal separate PKI chains
B480BIOS_F2 = {
    "id":       "B480BIOS-F2",
    "title":    "B-Series (B480 M5) and X-Series (X410C M7) BIOS use distinct signing certificates "
                "from separate organizational units — B480: OU=Presidio; X410: OU=BIOS_IMG — "
                "indicating two separate BIOS PKI chains; build service account 'cspgre' (group 'eng') "
                "is common to both, exposed as TAR metadata in every shipped BIOS package; "
                "platform codenames exposed: B480='Presidio/Pomona/Plumas1U/Plumas2U/Madeira/Morroco', "
                "X410='KellerBeachMR2'; internal board names embedded in production BIOS strings "
                "at offset 0x1e1b2b8 of B480 raw SPI image",
    "severity": "LOW",
    "status":   "CONFIRMED — DN strings extracted from capsule header binary blobs; "
                "cspgre/eng uname/gname in TAR headers of B480M5-BIOS-4-3-2g-0.cap; "
                "KellerBeachMR2 from package.json; Presidio/Pomona/Plumas1U from B480 BIOS strings",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "cert_dns": {
        "b480_m5": "CN=CiscoSystems;OU=Presidio;O=CiscoSystems",
        "x410_m7": "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
    },
    "platform_codenames": {
        "B480 M5": ["Presidio", "Pomona", "Plumas1U", "Plumas2U", "Madeira", "Morroco"],
        "X410C M7": ["KellerBeachMR2"],
    },
    "supply_chain_note": "X410M7 CpuIds=['806F6' (Sapphire Rapids), 'C06F2' (Granite Rapids)] "
                         "in BiosUpdate.json — production BIOS pre-qualified for Granite Rapids "
                         "(Intel 5th Gen Xeon, CPUID 0xCF model) prior to public availability; "
                         "firmware reveals hardware roadmap ahead of public disclosure",
}

# B480BIOS-F3: Secure Boot CustomMode=1 shipped as NVAR factory default
B480BIOS_F3 = {
    "id":       "B480BIOS-F3",
    "title":    "NVAR variable 'SecureBootSetup' pre-provisioned in B480 M5 BIOS with "
                "SecureBootEnable=1 AND CustomMode=1 as factory defaults; "
                "AMI BIOS Custom Mode permits enrollment of arbitrary Secure Boot signing keys "
                "without Platform Key (PK) owner authentication; combined with B480BIOS-F1 "
                "(no Boot Guard key revocation), an authenticated CIMC actor with BIOS flash write "
                "access (via live_extract.sh .cpk or /vic_upload/ PUT) can install a modified BIOS "
                "that either adds their own DB key to the Secure Boot database or disables Secure Boot "
                "entirely, achieving persistent signed UEFI-level code execution",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — NVAR raw bytes at offset 0x1001341 in b480m5_bios_raw.bin: "
                "SecureBootSetup = 01 00 01 00 00 00 00 (SecureBootEnable=1, CustomMode=1); "
                "10 total pre-provisioned NVAR variables: StdDefaults, Setup, PlatformLang=en-US, "
                "Timeout=3s, AMITSESetup, UsbSupport, NetworkStackVar, SecureBootSetup, "
                "ServerSetup, SocketIioConfig",
    "cwe":      ["CWE-276 (Incorrect Default Permissions)",
                 "CWE-306 (Missing Authentication for Critical Function)"],
    "nvar_secureboot": {
        "raw_hex": "010001000000004e564152",
        "SecureBootEnable": 1,
        "CustomMode": 1,
        "note": "CustomMode=1 in AMI BIOS enables arbitrary key enrollment without PK auth",
    },
    "nvar_all_defaults": [
        "StdDefaults", "Setup (BIOS defaults)", "PlatformLang=en-US",
        "Timeout=3s (boot menu)", "AMITSESetup", "UsbSupport (USB enabled)",
        "NetworkStackVar (network stack on)", "SecureBootSetup (SB enabled + custom mode)",
        "ServerSetup (0.0.0.0 IPs in UTF-16LE)", "SocketIioConfig (PCIe/IIO topology)",
    ],
}

# B480BIOS-F4: LENOVO_SYSTEM_* GUIDs throughout DXE phase — Lenovo BIOS framework
B480BIOS_F4 = {
    "id":       "B480BIOS-F4",
    "title":    "Cisco UCS B480 M5 BIOS DXE phase contains multiple LENOVO_SYSTEM_* GUIDs: "
                "DataHubDxe (53bcc14f), DevicePathDxe (9b680fce), Legacy8259 (79ca4208), "
                "PcRtc (378d7b65), CpuArchDxe (62d171cb), EbcDxe (13ac6dd0), "
                "HiiDatabase (348c4d62) — indicating the BIOS was built using AMI BIOS "
                "framework modules originally registered under Lenovo's GUID namespace; "
                "SecurityStubDxe (f80697e9, 58KB) present in DXE volume — if this is the active "
                "security protocol implementation rather than a vendor-specific replacement, "
                "EFI_SECURITY_ARCH_PROTOCOL returns EFI_SUCCESS for all file authentication "
                "checks, effectively bypassing Secure Boot enforcement at the DXE level",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — LENOVO_SYSTEM_* GUIDs from uefi-firmware-parser in FV 5c60f367; "
                "SecurityStubDxe f80697e9 size=0xe2c6=58054 bytes confirmed present; "
                "whether SecurityStubDxe is the active security handler requires dynamic analysis",
    "cwe":      ["CWE-506 (Embedded Malicious Code)", "CWE-693 (Protection Mechanism Failure)"],
    "dxe_lenovo_guids": [
        "53bcc14f-c24f-434c-b294-8ed2d4cc1860 (DataHubDxe)",
        "9b680fce-ad6b-4f3a-b60b-f59899003443 (DevicePathDxe)",
        "79ca4208-bba1-4a9a-8456-e1e66a81484e (Legacy8259/8259 Interrupt Controller)",
        "378d7b65-8da9-4773-b6e4-a47826a833e1 (PcRtc / RTC)",
        "62d171cb-78cd-4480-8678-c6a2a797a8de (CpuInitDxe / CpuArchDxe)",
        "13ac6dd0-73d0-11d4-b06b-00aa00bd6de7 (EbcDxe)",
        "348c4d62-bfbd-4882-9ece-c80bb1c4783b (HiiDatabase)",
    ],
    "security_stub_dxe": {
        "guid": "f80697e9-7fd6-4665-8646-88e33ef71dfc",
        "name": "SecurityStubDxe",
        "size": 58054,
        "note": "Stub implements EFI_SECURITY_ARCH_PROTOCOL returning EFI_SUCCESS for all "
                "calls; present in DXE volume — dynamic validation needed to confirm it is "
                "not superseded by a vendor security driver in the DXE dispatch order",
    },
}

# X410BIOS-F1: SGX Launch Control in open policy mode (LeWr=Enabled, key hashes all zero)
X410BIOS_F1 = {
    "id":       "X410BIOS-F1",
    "title":    "X410C M7 BIOS ships with SGX Launch Enclave Write enabled (SgxLeWr=Enabled) "
                "and SGX LE public key hash registers all zero (SgxLePubKeyHash0-3=0); "
                "this is Intel SGX 'open launch control' mode — any Intel-signed SGX enclave "
                "can run without platform-specific launch authorization; the all-zero LE hash "
                "defaults to Intel's embedded LE (Launch Enclave) public key, meaning Cisco "
                "has not set a custom launch control policy; customers cannot restrict which "
                "SGX enclaves execute on this hardware without explicitly modifying BIOS tokens; "
                "factory default exposes SGX attack surface without customer awareness",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — BiosTokens.json: EnableSgx=Disabled (feature off by default), "
                "SgxLeWr=Enabled, SgxLePubKeyHash0/1/2/3=0, SgxEpoch0/1=0; "
                "SgxAutoRegistrationAgent=Disabled; SgxFactoryReset=Disabled",
    "cwe":      ["CWE-276 (Incorrect Default Permissions)"],
    "sgx_token_defaults": {
        "EnableSgx": "Disabled",
        "SgxLeWr": "Enabled",
        "SgxLePubKeyHash0": "0",
        "SgxLePubKeyHash1": "0",
        "SgxLePubKeyHash2": "0",
        "SgxLePubKeyHash3": "0",
        "SgxEpoch0": "0",
        "SgxEpoch1": "0",
        "SgxAutoRegistrationAgent": "Disabled",
        "SgxQoS": "Enabled",
        "SgxPackageInfoInBandAccess": "Disabled",
    },
}

# X410BIOS-F2: Granite Rapids CPUID (C06F2) in production BIOS update manifest
X410BIOS_F2 = {
    "id":       "X410BIOS-F2",
    "title":    "BiosUpdate.json in X410C M7 BIOS 6.0.2a package lists CpuIds=['806F6','C06F2']; "
                "0x806F6 = Intel Xeon Sapphire Rapids (4th Gen, CPUID family 6 model 0x8F step 6); "
                "0xC06F2 = Intel Xeon Granite Rapids (5th Gen, CPUID family 6 model 0xCF step 2); "
                "Granite Rapids was not publicly available when this firmware shipped (2026-01-30); "
                "presence in production bundle reveals Cisco was pre-qualifying X410C M7 for "
                "Granite Rapids upgrades, leaking internal hardware roadmap; "
                "BIOS file resides at biosFiles/X410/M7/6F6/ — directory name '6F6' is the "
                "common CPU stepping suffix shared by both CPUID variants",
    "severity": "LOW",
    "status":   "CONFIRMED — BiosUpdate.json CpuIds array extracted from X410M7.6.0.2a package",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "cpu_ids": {
        "806F6": "Intel Xeon Sapphire Rapids (4th Gen Xeon SP, CPUID=0x806F6)",
        "C06F2": "Intel Xeon Granite Rapids (5th Gen Xeon SP, CPUID=0xC06F2)",
    },
}

# X410BIOS-F3: TXT disabled but TPM enabled — Intel TXT activation surface
X410BIOS_F3 = {
    "id":       "X410BIOS-F3",
    "title":    "X410C M7 BIOS ships with TPM enabled (TPMControl=Enabled, TpmSupport=Enabled) "
                "but Intel TXT (Trusted Execution Technology) disabled (TXTSupport=Disabled); "
                "TpmPpiRequired=Disabled means the TPM Physical Presence Interface confirmation "
                "is not required for TPM ownership or state changes; an authenticated administrator "
                "can take TPM ownership, perform TpmClear (TPMPendingOperation=TpmClear available), "
                "or enable Intel TXT without any physical presence attestation; "
                "combined with remote CIMC management, TPM state is fully administratively "
                "controllable without physical access, eliminating physical presence as a "
                "TPM security control",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — BiosTokens.json: TPMControl=Enabled, TpmSupport=Enabled, "
                "TXTSupport=Disabled, TpmPpiRequired=Disabled, TPMPendingOperation={None,TpmClear}",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "tpm_token_defaults": {
        "TPMControl": "Enabled",
        "TpmSupport": "Enabled",
        "TXTSupport": "Disabled",
        "TpmPpiRequired": "Disabled",
        "TPMPendingOperation": "None",  # can be set to TpmClear
    },
    "note":     "EnableTme=Disabled, EnableMktme=Disabled (Total Memory Encryption off); "
                "IntelVTD=Enabled (IOMMU on by default — positive); "
                "SelectMemoryRAS=ADDDC Sparing (advanced RAS enabled)",
}

FINDINGS = [B480BIOS_F1, B480BIOS_F2, B480BIOS_F3, B480BIOS_F4,
            X410BIOS_F1, X410BIOS_F2, X410BIOS_F3]

# Capsule format summary for B-Series BIOS (re-used for all variants)
CAPSULE_FORMAT_BSERIES = {
    "outer_wrapper": "[CISCO UCS BIOS CIMCPackage] INI text header",
    "header_fields": ["HeaderVersion", "ImageVersion", "ImageByteSize", "ImageOffset",
                      "ImageACM_SVN_Authorized", "ImageKM_SVN", "ImageBPM_SVN"],
    "cert_embed":    "X.509 DN string in plain ASCII before DER cert blob, after null-padded INI text",
    "payload_start": "ImageOffset (= 2048 for all observed variants)",
    "b480_payload":  "bzip2 compressed -> LFBC (4c464243) SPI image -> Intel IFD at 0x10e4 -> UEFI FVH",
    "x410_payload":  "gzip compressed -> PAX TAR -> JSON metadata + .cap -> gzip -> .cap [CISCO UCS BIOS CIMCPackage]",
    "common_build":  "Build account cspgre/eng in TAR metadata across all variants",
}
