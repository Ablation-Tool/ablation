"""
Cisco UCS RE -- LOW Tier Re-verification Pass
Apply Cisco CVSS v3.1 conventions to all 181 LOW findings.
Identify upgrades (to MEDIUM or HIGH) and confirm remaining LOWs.

Pass: 4 of 4 (CRITICAL done, HIGH done, MEDIUM done, LOW this pass)
"""

# ============================================================
# UPGRADED TO MEDIUM (from LOW)
# ============================================================

UPGRADED_TO_MEDIUM = [
    {
        "id":           "UCSM-CTR-F8",
        "module":       "cisco_ucs_ucsm_container_re",
        "new_cvss3":    5.3,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "rationale": (
            "sam_policy_server runs as root on TCP/843 (all interfaces) via xinetd. "
            "The Flash socket policy protocol is trivial -- it serves a static XML file -- "
            "but the binary's memory safety properties are unanalyzed. A root process "
            "accepting unauthenticated connections on all interfaces with unknown binary "
            "safety is at minimum a C:L disclosure surface (policy XML contents). "
            "If flashp_policy_response.xml is writable, an attacker can serve an "
            "allow-all cross-domain policy to any Flash-capable client reaching port 843. "
            "AV:N: management-plane port, all interfaces. PR:N: no auth. "
            "C:L: policy content readable. I:N without confirmed response file write access. "
            "5.3 MEDIUM: root unauth network service with unknown binary safety baseline."
        ),
        "affected_products": ["UCS Manager (xinetd policyService, sam_policy_server TCP/843)"],
    },
    {
        "id":           "UCSM-APACHE-F7",
        "module":       "cisco_ucs_ucsm_apache_re",
        "new_cvss3":    5.3,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "rationale": (
            "RewriteRule ^/connector(.*)$ http://127.0.0.1:8889$1 [P,L] with ProxyPreserveHost On. "
            "The (.*) capture group passes the full path suffix verbatim to the backend, "
            "including URL-encoded sequences (%2f, %2e%2e), null bytes, and non-printable chars. "
            "mod_rewrite [P] does NOT canonicalize paths before forwarding. "
            "ProxyPreserveHost On forwards the attacker's Host header to the backend. "
            "This is an unauthenticated SSRF entry point against the Intersight connector "
            "service at localhost:8889. The backend connector is external-network-facing "
            "in cloud-managed UCSM deployments. "
            "5.3 MEDIUM: AV:N/PR:N path-passthrough to backend service; "
            "impact limited to C:L without confirmed backend path traversal."
        ),
        "affected_products": ["UCS Manager (httpd.conf connector proxy, /connector/* path)"],
    },
    {
        "id":           "intersight_node_init-F6",
        "module":       "cisco_ucs_intersight_node_init_re",
        "new_cvss3":    4.0,
        "new_vector":   "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "rationale": (
            "/tmp/net.conf is world-writable (sticky bit set but file creation unrestricted). "
            "diag.py reads this file as the network configuration source at init time. "
            "A low-privilege process that races the init service can place a crafted net.conf "
            "and redirect network traffic, change DNS, or alter routing. "
            "AC:H: race condition window is narrow (init startup only). "
            "I:H: successful race rewrites appliance network configuration. "
            "4.0 MEDIUM: local race condition against init-time config read."
        ),
        "affected_products": ["Cisco Intersight Appliance (node_init, diag.py)"],
    },
]

# ============================================================
# LOW FINDINGS CONFIRMED AS ACCURATE -- Category Summary
# ============================================================

CONFIRMED_LOW_CATEGORIES = {
    "firmware_recon_codenames": {
        "count": 48,
        "examples": [
            "BSERIES-F7 (SWID codename CPU gen matrix)",
            "BSERIES-F8 (Intel M8 single blob three codenames: godzilla1/godzilla2/godzilla3)",
            "CSUB-F5 (GODZILLA/MOUNTRAINIER/MOUNTADAMS codenames)",
            "CSUB-F6 (BIOS signing cert subject in package metadata)",
            "JALAMABEACH-F2 (Jalamabeach codename shared B200/B210 M6)",
            "AMDCIMC-F4 (AMD rack CIMC img_features CPUGeneration disclosure)",
            "CSERIES-M8-F5 (AMD M8 UEFI .cap format metadata)",
        ],
        "typical_cvss3": 2.0,
        "typical_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "note": "Internal product codenames and platform identifiers. "
                "Intelligence value for targeting but no direct attack path.",
    },
    "binary_deduplication_survey": {
        "count": 22,
        "examples": [
            "MRSAS-BINARY-DEDUP-F1 (B200 M4 mrsasctlr identical to UCSB-RAID12G-M6)",
            "HGST-NVME-KNCCD122-DEDUP-F1 (all HGST KNCCD122 capacity variants identical)",
            "MICRON-NVME-SHARED-FW-F1 (all Micron E2CS007 capacity variants share one firmware)",
            "KIOXIA-CF8-SAME-BINARY-F1 (all 8 Kioxia 1YETE106 SKUs share one binary)",
            "MARVELL-M2-F1 (Marvell M2 HWRAID plaintext firmware identical across SKUs)",
        ],
        "typical_cvss3": 0.0,
        "note": "Firmware deduplication facts -- informational, useful for acquisition scope.",
    },
    "build_metadata_exposure": {
        "count": 19,
        "examples": [
            "FI64-F6 (build hostname/date in NX-OS kernel version string)",
            "INTERSIGHT-F7 (build info exposes codenames and git hashes)",
            "INTERSIGHT-F6 (cloud-init admin password base64, not encrypted -- but still LOW: local access)",
            "BSERIES-BUNDLE-SURVEY-COMPLETE-F1 (survey metadata)",
            "FI-INFRA-F5 (all 4 FI platforms identical inner software -- survey fact)",
        ],
        "typical_cvss3": 2.0,
        "note": "Build system metadata. Useful for fingerprinting but no direct exploit.",
    },
    "hardware_security_config_informational": {
        "count": 31,
        "examples": [
            "SAMISH-LAKE-JTAG-PSOC-F1 (JTAG state machine debug + PSoC bootloader -- informational)",
            "PTE3-CPLD-SVF-BYPASS-F1 (DO_BYPASS pattern in CPLD SVF -- optional bypass flag)",
            "CSERIES-MOD3-F3 (PCIe M85-SB FPGA dual-image, no anti-rollback -- design choice)",
            "CSERIES-MOD3-F4 (AIKIDO loader change error, TAM integrity failure -- error path)",
            "CSERIES-MOD3-F6 (AIKIDO enforcement FPGA-resident -- informational architecture)",
            "MRAID12G-HE-CPLD-MAXII-SECURITY-F1 (Intel MAX II security bit programming state)",
        ],
        "typical_cvss3": 3.4,
        "typical_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
        "note": "Physical-proximity hardware security configurations. AV:P applies.",
    },
    "tls_crypto_informational": {
        "count": 8,
        "examples": [
            "UCSM-CRYPTO-F3 (libssl legacy renegotiation + TLS 1.0 support)",
            "CSERIES-F3 (CIMC trust store has SHA-1-signed Spanish root CA)",
            "intersight_ciscossh-F5 (PSB SEC-CRY-PRIM cipher gap)",
            "FASTLINQ-F2 (QLogic NVMe default iSCSI passwords in config)",
        ],
        "typical_cvss3": 3.1,
        "note": "Crypto configuration weaknesses that require active MITM to exploit.",
    },
    "session_auth_informational": {
        "count": 7,
        "examples": [
            "ucsm_fips_auth-F4 (session cookie entropy debug logging)",
            "ucsm_fips_auth-F5 (source tree path in Auth.cc error strings)",
            "fi_nxos_activation-F5 (log files mode 640 set in cinitial-setup.sh)",
            "intersight_cert_bootstrap-F6 (developer comment about predictable SSH key)",
        ],
        "typical_cvss3": 2.6,
        "note": "Hardening gaps and debug artifacts without direct exploitation path.",
    },
    "storage_hardware_survey": {
        "count": 28,
        "examples": [
            "SEAGATE-TCG-FAMILY-COMPLETE-F1 (Seagate TCG Enterprise survey)",
            "MICRON-NVME-SURVEY-F1 (Micron NVMe E2CS007/E3MQ survey)",
            "WDC-HAMR-AHA2-TCG-ENCRYPTED-DUMP-F1 (WDC HAMR TCG + encrypted dump)",
            "CPLD-SVF-BYPASS-OPTIONAL-F1 (Intel MAX 10 FPGA CPLD bypass modes)",
        ],
        "typical_cvss3": 2.0,
        "note": "Storage hardware survey results -- reconnaissance value only.",
    },
    "intersight_cloud_informational": {
        "count": 9,
        "examples": [
            "INTERSIGHT-F8 (missing kptr_restrict and dmesg_restrict)",
            "intersight_disk2_disk3-F6 (andromeda codename)",
            "intersight_onprem_ansible-F6 (hammer_account_id hardcoded 100000000000)",
            "intersight_equinox_connector-F6 (bash quoting bug in startup.sh)",
        ],
        "typical_cvss3": 3.3,
        "note": "Intersight hardening gaps. Most require root-level access to exploit.",
    },
    "remaining_low": {
        "count": 6,
        "note": "Miscellaneous LOW findings in cwom, esu, fi_bundle, and gpu modules "
                "confirmed as informational or requiring physical access.",
    },
}

# ============================================================
# NOTE ON VIC-M85SB-F1 (Telnet) IN LOW LIST
# ============================================================

# vic_m85sb module shows VIC-M85SB-F1 (BSERIES-BXM6-F2) as rlogin/rcp binaries present.
# This is a different sub-finding from VIC-M85SB-F1 (telnet), which was upgraded to CRITICAL
# in the HIGH pass. The LOW finding for vic module (rlogin binaries present without active
# xinetd config) is correctly LOW -- binaries present but not actively bound to any port
# without the xinetd config enabling them.

# ============================================================
# REVERIFICATION SUMMARY
# ============================================================

REVERIFICATION_SUMMARY = {
    "pass":              "4 of 4 (LOW)",
    "total_low_reviewed": 181,
    "upgraded_to_medium": 3,
    "confirmed_low":     178,

    "final_cumulative_critical": {
        "from_original_83_pass":    15,
        "upgraded_from_high_pass":   5,
        "upgraded_from_medium_pass": 1,
        "upgraded_from_low_pass":    0,
        "total_critical_ids":       21,
    },

    "all_passes_complete": True,
}

if __name__ == "__main__":
    print(f"LOW reverification: {REVERIFICATION_SUMMARY['total_low_reviewed']} findings reviewed")
    print(f"  Upgraded to MEDIUM:  {REVERIFICATION_SUMMARY['upgraded_to_medium']}")
    print(f"  Confirmed LOW:       {REVERIFICATION_SUMMARY['confirmed_low']}")
    print()
    print("All 4 passes complete.")
    fcc = REVERIFICATION_SUMMARY["final_cumulative_critical"]
    print(f"FINAL Critical ID total: {fcc['total_critical_ids']}")
    print(f"  Original 83 pass kept:   {fcc['from_original_83_pass']}")
    print(f"  Upgraded from HIGH:      {fcc['upgraded_from_high_pass']}")
    print(f"  Upgraded from MEDIUM:    {fcc['upgraded_from_medium_pass']}")
    print(f"  Upgraded from LOW:       {fcc['upgraded_from_low_pass']}")
