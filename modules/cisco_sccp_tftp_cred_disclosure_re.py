"""
Cisco SCCP Phone — TFTP config file cleartext credential disclosure
SEP<MAC>.cnf.xml served via unauthenticated TFTP, contains cleartext credentials
Finding: PHN-F17
Evidence source: Live deployment artifact from d.idc.ir mirror (7942G SCCP config)
"""

# ─────────────────────────────────────────────────────────
# PHN-F17 — SCCP TFTP Config Cleartext Credential Disclosure
# ─────────────────────────────────────────────────────────
PHN_F17 = {
    "id":       "PHN-F17",
    "title":    "SCCP TFTP Config Cleartext Credential Disclosure",
    "product":  "Cisco IP Phone SCCP (all 79xx/78xx models using CUCM/ISSABEL/FreePBX)",
    "severity": "HIGH",
    "class":    "Cleartext Credential Disclosure",

    "description": (
        "SCCP phones fetch their device configuration from a TFTP server at boot via "
        "SEP<MAC>.cnf.xml (CUCM) or similar. This file is served over unauthenticated UDP/69 "
        "TFTP and contains cleartext credentials: SSH admin password, SIP registration "
        "authentication passwords (authPassword) for each line, and phone admin password. "
        "Any host with TFTP access or a MITM position on the phone's VLAN obtains these credentials."
    ),

    "credential_fields_exposed": {
        "sshPassword":    "SSH admin password for the phone (cleartext)",
        "authPassword":   "SIP registration auth password per line (cleartext) — allows fake extension registration",
        "phonePassword":  "Phone admin/settings PIN",
        "sshUserId":      "SSH username (always 'admin' by default)",
        "processNodeName": "CUCM/PBX server IP address",
    },

    "evidence_from_live_deployment": {
        "source":      "SEPB8BEBF22C253.cnf.xml from d.idc.ir Iranian CUCM mirror",
        "mac_device":  "B8:BE:BF:22:C2:53 (Cisco 7942G)",
        "pbx_server":  "172.16.1.15 (ISSABEL PBX, CUCM name 'Hairless')",
        "pbx_tz":      "Iran Standard/Daylight Time",
        "credential_count": 3,
        "credential_types": ["SSH admin", "SIP line 102 auth", "SIP line 103 auth"],
        "ssh_enabled": True,
        "ssh_port":    22,
        "web_disabled": True,
        "telnet_level": 2,
        "note": (
            "Private network IP (RFC1918 172.16.x.x) — not directly reachable. "
            "Credentials documented as proof of cleartext disclosure pattern, not as active targets. "
            "SSH and telnet access enabled; web disabled."
        ),
    },

    "attack_vectors": [
        "MITM on phone VLAN during boot — intercept TFTP response, read/modify config",
        "Access to TFTP server — read SEP*.cnf.xml files for all enrolled phones",
        "ARP spoofing on phone VLAN — redirect TFTP requests to attacker-controlled server",
        "Network tap at phone/switch — capture TFTP UDP exchange passively",
    ],

    "remediation": {
        "encrypted_config": "Enable CUCM Encrypted Phone Configuration (EPC) — uses ITL/CTL to encrypt SEP*.cnf.xml",
        "note": (
            "CUCM provides Encrypted Phone Configuration as a feature. When enabled, the "
            "SEP*.cnf.xml is encrypted using the phone's ITL-derived key. TFTP interception "
            "yields ciphertext, not credentials. Most deployments leave this disabled. "
            "Requires CTL/ITL trust establishment first."
        ),
    },

    "comparison_to_jabber": {
        "JAB-F15": "Jabber Windows CcmCip.Host.CertLevel=0 also TFTP-provisioned, similarly exploitable",
        "note": "Both Jabber and SCCP phones receive security-critical configuration via unauthenticated TFTP",
    },
}

# ─────────────────────────────────────────────────────────
# SCCP config format architecture
# ─────────────────────────────────────────────────────────
SCCP_CONFIG_ARCHITECTURE = {
    "boot_sequence": [
        "1. Phone powers on, sends DHCP request",
        "2. DHCP option 150 returns TFTP server IP",
        "3. Phone fetches XMLDefault.cnf.xml via TFTP (no auth)",
        "4. Phone fetches SEP<MAC>.cnf.xml via TFTP (no auth)",
        "5. Config contains SSH password, SIP auth passwords in cleartext",
        "6. Phone registers with CUCM/PBX using credentials from config",
    ],
    "attack_window": "Step 3-4 — phone has no credentials to authenticate TFTP before config fetch",
    "tlv_role": (
        "CTL (Certificate Trust List) and ITL (Initial Trust List) files control code signing "
        "trust. They do NOT protect TFTP config confidentiality unless EPC is enabled. "
        "CTL/ITL empty (0 bytes) in this deployment — no secure mode active."
    ),
}
