"""
Cisco UCS C-Series 6.0.2b — OpenBMC component RE
Target: ucs-k9-bundle-c-series.6.0.2b.C.bin (3.1GB)
SHA256: on-disk at /media/cowboy/research/Cisco-UCS/c-series-ucsm/

Structure:
  offset 0:     Cisco SN header (844 bytes; magic=6401534E, hsize=034C)
  offset 844:   gzip stream → main C-Series filesystem (extends to ~211MB compressed)
  offset 211469021+: 21 xz-compressed plugin streams (bare, no per-stream SN wrapper)

xz stream inventory (21 streams total):
  0:  PEM certificate bundle (3 Spanish CAs: ACCVRAIZ1 + 2x FNMT-RCM)
  1:  Raw PEM base64 fragment (cert continuation)
  2:  ARM32 ELF — sdbusplus + libgpiod D-Bus/GPIO service (armhf, missing section headers)
  3-5,7-12: ARM32 machine code (microcontroller-level firmware, no strings)
  6:  binary data
  13: bash shell help text fragment (embedded in firmware image)
  14: binary data
  15: C++ template library — dpu::utils::FruReader + dpu::utils::IpInfo parser
  16: ARM32 ELF — xyz.openbmc_project.inventory.host.BfFruInfo D-Bus service (armhf)
  17: binary data
  18: ARM32 ELF — xyz.openbmc_project.software.Activation D-Bus service (armhf)
  19-20: binary data

Key finding: Cisco C-Series CIMC runs OpenBMC with Cisco-specific D-Bus extensions.
All xz streams are bare (no per-stream integrity wrapper); protected only by outer SN MD5
(same BCSERIES-F1 vulnerability applies).

Bundle SN hash algorithm: UNKNOWN for bundle-level files; does NOT match the
MD5(zeroed_hash_field) formula confirmed on plugin .bin files.
"""

FIRMWARE = {
    "target":     "Cisco UCS C-Series Bundle 6.0.2b",
    "file":       "ucs-k9-bundle-c-series.6.0.2b.C.bin",
    "size_bytes": 3232358153,
    "sn_header": {
        "magic":       "6401534E",
        "hsize":       844,
        "hash_offset": "0x38",
        "hash_value":  "d874baf4b4081021b368ba0949aec522",
        "count":       7,
        "algorithm":   "UNKNOWN — bundle-level hash does not match MD5(zeroed) formula; "
                       "confirmed different from plugin-level algorithm",
    },
    "architecture": "OpenBMC on ARMv7-A hard-float (armhf); systemd + D-Bus",
    "findings":    ["CSERIES-F1", "CSERIES-F2", "CSERIES-F3", "CSERIES-F4"],
}

CSERIES_F1 = {
    "id":       "CSERIES-F1",
    "title":    "Cisco-specific OpenBMC extension BfFruInfo exposes hardware identifiers "
                "(baseMAC + baseGUID + description) via unauthenticated D-Bus property read",
    "severity": "MEDIUM",
    "status":   "CANDIDATE — interface confirmed by symbol extraction from xz stream 16 "
                "(ARM32 ELF, sdbusplus, missing section headers at 214604); D-Bus policy "
                "file for this interface not yet retrieved to verify access control",
    "cwe":      ["CWE-284 (Improper Access Control)", "CWE-200 (Information Exposure)"],
    "dbus_interface": {
        "service":    "xyz.openbmc_project.inventory.host.BfFruInfo",
        "namespace":  "sdbusplus::server::xyz::openbmc_project::inventory::host::BfFruInfo",
        "properties": {
            "baseGUID":    "hardware GUID of the base server blade/board",
            "description": "human-readable hardware description string",
            "baseMACB":    "base MAC address of the server (hardware network identifier)",
        },
        "cisco_extension": True,
        "mainline_openbmc": False,
        "property_accessors": [
            "_ZNK9sdbusplus6server3xyz15openbmc_project9inventory4host9BfFruInfo8baseGUIDB5cxx11Ev",
            "_ZNK9sdbusplus6server3xyz15openbmc_project9inventory4host9BfFruInfo11descriptionB5cxx11Ev",
            "_ZNK9sdbusplus6server3xyz15openbmc_project9inventory4host9BfFruInfo7baseMACB5cxx11Ev",
        ],
    },
    "threat_model": "Authenticated CIMC shell user or any process on D-Bus system bus "
                    "(if policy allows) reads baseMAC and baseGUID without elevated privileges; "
                    "hardware fingerprint → asset tracking / clone detection bypass",
    "exploit_sketch": "busctl --system get-property xyz.openbmc_project.inventory.host.BfFruInfo "
                      "/xyz/openbmc_project/inventory/host BfFruInfo baseMACB",
}

CSERIES_F2 = {
    "id":       "CSERIES-F2",
    "title":    "OpenBMC Software.Activation firmware update service on C-Series CIMC — "
                "requestedActivation property setter may allow CIMC shell user to trigger "
                "firmware activation without admin privilege check",
    "severity": "HIGH",
    "status":   "CANDIDATE — Activation + ActivationProgress D-Bus interfaces confirmed "
                "by symbol extraction from xz stream 18 (ARM32 ELF, sdbusplus + sd_event_loop); "
                "D-Bus policy authorization model not yet extracted from filesystem image",
    "cwe":      ["CWE-862 (Missing Authorization)", "CWE-285 (Improper Authorization)"],
    "dbus_interface": {
        "service":    "xyz.openbmc_project.Software.Activation",
        "interfaces": [
            "xyz.openbmc_project.Software.Activation",
            "xyz.openbmc_project.Software.ActivationProgress",
        ],
        "properties": {
            "activation":          "current activation state (Activations enum)",
            "requestedActivation": "setter triggers firmware update (RequestedActivations enum)",
            "progress":            "uint8 progress percentage",
        },
        "methods": {
            "requestedActivation setter": "calling with 'Active' enum value initiates firmware update",
        },
        "key_symbols": [
            "_ZN9sdbusplus6server3xyz15openbmc_project8software10Activation19requestedActivationENS_6common3xyz15openbmc_project8software10Activation20RequestedActivationsE",
            "_ZN9sdbusplus6server3xyz15openbmc_project8software18ActivationProgress8progressEhb",
        ],
    },
    "threat_model": "CIMC shell user with read-only role sets requestedActivation=Active "
                    "via D-Bus to trigger pending firmware update; standard OpenBMC does "
                    "NOT enforce role-based auth at D-Bus layer — auth is expected at "
                    "Redfish/REST layer only; CIMC shell bypasses Redfish layer entirely",
    "exploit_sketch": (
        "busctl --system set-property xyz.openbmc_project.Software.Activation "
        "/xyz/openbmc_project/software/<img-id> "
        "xyz.openbmc_project.Software.Activation requestedActivation s Active"
    ),
    "verification_needed": "Confirm D-Bus policy allows non-root busctl access to Activation service",
}

CSERIES_F3 = {
    "id":       "CSERIES-F3",
    "title":    "C-Series CIMC trust store embeds SHA-1-signed Spanish root CA (ACCVRAIZ1) "
                "— all 3 embedded CAs are Spanish government PKI; ACCVRAIZ1 uses deprecated "
                "sha1WithRSAEncryption signature algorithm",
    "severity": "LOW",
    "status":   "CONFIRMED — certificate bundle extracted from xz stream 0 (PEM format, "
                "3 certificates, all C=ES); ACCVRAIZ1 signature verified by openssl x509",
    "cwe":      ["CWE-326 (Inadequate Encryption Strength)", "CWE-295 (Improper Certificate Validation)"],
    "certificates": {
        "ACCVRAIZ1": {
            "issuer":    "CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES",
            "subject":   "CN=ACCVRAIZ1, OU=PKIACCV, O=ACCV, C=ES",
            "not_before": "2011-05-05",
            "not_after":  "2030-12-31",
            "sig_algo":  "sha1WithRSAEncryption",
            "key_algo":  "rsaEncryption (RSA-2048)",
            "risk":      "SHA-1 deprecated; SHAttered collision attack (2017) breaks SHA-1 "
                         "collision resistance; forged cert possible with ~$100K GPU compute",
        },
        "FNMT-RCM": {
            "issuer":    "C=ES, O=FNMT-RCM, OU=AC RAIZ FNMT-RCM",
            "sig_algo":  "sha256WithRSAEncryption",
            "not_after": "2030-01-01",
            "risk":      "LOW — SHA-256 signed, not deprecated",
        },
        "FNMT-RCM-SERVIDORES-SEGUROS": {
            "issuer":    "CN=AC RAIZ FNMT-RCM SERVIDORES SEGUROS, O=FNMT-RCM, C=ES",
            "sig_algo":  "ecdsa-with-SHA384",
            "not_after": "2043-12-20",
            "risk":      "NEGLIGIBLE — ECDSA/SHA-384",
        },
    },
    "notable": "ALL 3 CAs are Spanish government/agency CAs — suggests C-Series CIMC has "
               "a hard-coded dependency on Spanish PKI infrastructure for specific service "
               "authentication or firmware signature validation; not a general CA bundle",
    "attack_condition": "Attacker who can forge a SHA-1 certificate chain under ACCVRAIZ1 "
                        "and MITM CIMC's TLS connections (or supply fake firmware signed by "
                        "forged cert) could bypass certificate validation; requires significant "
                        "compute (~$100K) and specific conditions",
}

CSERIES_F4 = {
    "id":       "CSERIES-F4",
    "title":    "dpu::utils::FruReader parses raw hardware EEPROM byte arrays into "
                "IP configuration (std::list<IpInfo>) and typed values — C++ template "
                "parser with hardware-controlled input",
    "severity": "LOW",
    "status":   "CANDIDATE — FruReader<FruLocator> and IpInfo parser confirmed by C++ "
                "mangled name extraction from xz stream 15; binary is stripped with "
                "section headers removed; full code flow analysis requires disassembly",
    "cwe":      ["CWE-20 (Improper Input Validation)", "CWE-119 (Buffer Errors)"],
    "component": {
        "namespace":   "dpu::utils",
        "classes":     ["FruReader<FruLocator>", "IpInfo", "ValueType", "TimeResReadPolicy"],
        "key_function": "std::list<dpu::utils::IpInfo>(const std::vector<uint8_t>&) — "
                        "converts raw byte array from FRU EEPROM to IP config list",
        "binding_pattern": "std::bind(parser_fn, placeholder) — functional callbacks for parse steps",
        "temporal_types": "TimeResReadPolicy<unsigned long long, std::chrono::milliseconds> — "
                          "timed reads with millisecond resolution",
    },
    "threat_model": "Physical attacker modifies FRU EEPROM on a server blade or NIC; "
                    "CIMC reads EEPROM and passes raw bytes to FruReader parser; "
                    "malformed EEPROM data → parser crashes or corrupts dpu service heap",
    "attack_prerequisite": "Physical access to server or out-of-band EEPROM write capability",
}
