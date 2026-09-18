"""
Cisco UCS RE -- LOW Tier Re-verification Pass (Thorough)
Apply Cisco CVSS v3.1 conventions to all 181 LOW findings.
Identify upgrades (to MEDIUM) and resolve extraction artifacts.

Pass: 4 of 4 (CRITICAL done, HIGH done, MEDIUM done, LOW this pass)

Cisco CVSS v3.1 conventions applied:
  AV:N  -- management-plane services, even on dedicated VLANs
  AV:L  -- requires local process or session on the host
  AV:P  -- requires physical proximity (storage diagnostic interfaces)
  PR:H  -- root/admin credentials required (Cisco admin = PR:H)
  PR:L  -- any authenticated standard user
  AC:H  -- race condition, MITM-in-path, or CDN/DNS compromise required
  UI:R  -- reboot or explicit admin action (e.g., triggering an upgrade)
"""

# ============================================================
# EXTRACTION ARTIFACT DECONFLICTS
# ============================================================
# These findings appeared in the LOW bucket from the extraction script
# but are rated MEDIUM in their source modules. They are NOT LOW.

EXTRACTION_ARTIFACTS = [
    {
        "id":          "HUU-F9",
        "module":      "cisco_ucs_huu_c220m8_602_re",
        "real_severity": "MEDIUM",
        "detail": (
            "remove_sign creates temp file at /tmp/<basename>.tmp (no PID suffix). "
            "Symlink race: attacker pre-creates /tmp/<basename>.tmp -> /etc/shadow (or any root-owned file). "
            "cp -p follows the symlink, overwriting the target with source content. "
            "remove_sign runs as root during HUU boot. "
            "Source module rates MEDIUM. Extraction script incorrectly placed in LOW bucket. "
            "Confirmed MEDIUM: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N = 4.7"
        ),
    },
    {
        "id":          "FI-INFRA-F2",
        "module":      "cisco_ucs_fi_infrastructure_re",
        "real_severity": "MEDIUM",
        "detail": (
            "FEX 2400 (Summerville) kernel boots with 'nokaslr' kernel parameter. "
            "KASLR disabled = fixed kernel base address = ROP gadgets at predictable offsets. "
            "Reduces post-exploitation difficulty once code execution is achieved. "
            "Source module rates MEDIUM. Extraction script incorrectly placed in LOW bucket. "
            "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.0 (exploit prerequisite: "
            "code exec already achieved; this lowers the exploitation bar, not creates it)."
        ),
    },
]

# ============================================================
# UPGRADED TO MEDIUM (from LOW) -- Full list, all passes combined
# ============================================================

UPGRADED_TO_MEDIUM = [
    # --- From initial pass (written before thorough re-verification) ---
    {
        "id":           "UCSM-CTR-F8",
        "module":       "cisco_ucs_ucsm_container_re",
        "new_cvss3":    5.3,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "rationale": (
            "sam_policy_server TCP/843 xinetd, user=root, all interfaces. "
            "Flash socket policy server -- trivially simple protocol (serve static XML), "
            "but root process accepting unauthenticated connections on all interfaces. "
            "Binary memory safety unanalyzed. If flashp_policy_response.xml is writable, "
            "attacker can serve allow-all policy. "
            "AV:N (all interfaces, management plane). PR:N. C:L (policy content readable). "
            "5.3 MEDIUM: root unauth network service, TCB not fully analyzed."
        ),
        "affected_products": ["UCS Manager (xinetd policyService TCP/843)"],
    },
    {
        "id":           "UCSM-APACHE-F7",
        "module":       "cisco_ucs_ucsm_apache_re",
        "new_cvss3":    5.3,
        "new_vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "rationale": (
            "RewriteRule ^/connector(.*)$ http://127.0.0.1:8889$1 [P,L]. "
            "Full path suffix passed verbatim to backend including %2f/%2e%2e/null. "
            "ProxyPreserveHost On forwards attacker Host header to connector service. "
            "mod_rewrite [P] does not canonicalize before forwarding. "
            "Unauthenticated SSRF entry point against Intersight connector at :8889. "
            "External-facing in cloud-managed UCSM deployments. "
            "5.3 MEDIUM: AV:N/PR:N, impact limited to C:L without confirmed backend path traversal."
        ),
        "affected_products": ["UCS Manager (httpd.conf /connector/* proxy)"],
    },
    {
        "id":           "intersight_node_init-F6",
        "module":       "cisco_ucs_intersight_node_init_re",
        "new_cvss3":    4.0,
        "new_vector":   "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "rationale": (
            "/tmp/net.conf is world-writable (sticky bit but unrestricted file creation). "
            "diag.py reads this as network config source at init time. "
            "Low-privilege process that races the init service can inject crafted net.conf, "
            "redirecting management network traffic, DNS, or routing. "
            "AC:H: narrow race window (init startup only). I:H: successful race rewrites "
            "appliance network configuration. Admin has NOPASSWD sudo ALL -- "
            "network config tamper = potential session hijack if credentials transit the link. "
            "4.0 MEDIUM: local race against init-time config read."
        ),
        "affected_products": ["Cisco Intersight Appliance (node_init, diag.py)"],
    },

    # --- Found in thorough re-verification pass ---
    {
        "id":           "fi_nxos_activation-F5",
        "module":       "cisco_ucs_fi_nxos_activation_re",
        "new_cvss3":    6.1,
        "new_vector":   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L",
        "rationale": (
            "cinitial-setup.sh: chmod 666 /var/sysmgr/sam_logs/svc_sam_controller.klog "
            "and chmod 666 /var/sysmgr/sam_logs/svc_sam_controller.log. "
            "Mode 666 = world-readable + world-writable. "
            "svc_sam_controller is the primary UCSM management plane event log. "
            "Any local process can: "
            "(1) Truncate or overwrite to erase audit history; "
            "(2) Inject fabricated log entries to confuse forensics or hide real events; "
            "(3) Corrupt log format to disable log analysis tooling. "
            "Applied at every container initialization -- permanent condition, not transient. "
            "AV:L: local process access required. AC:L: no race condition, always writable. "
            "PR:L: any user on the FI. I:H: destroys/fabricates management audit trail. "
            "A:L: log corruption/truncation impairs availability of audit data. "
            "6.1 MEDIUM: Cisco rates audit log tampering as I:H (integrity of management records)."
        ),
        "affected_products": ["UCS Manager FI (cinitial-setup.sh, all FI platforms)"],
    },
    {
        "id":           "fi_nxos_activation-F6",
        "module":       "cisco_ucs_fi_nxos_activation_re",
        "new_cvss3":    5.0,
        "new_vector":   "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L",
        "rationale": (
            "sp_upgrade_helper.sh (690 lines, runs as root): "
            "SP_RESTORE_IMAGE_CAT=/tmp/sp_restore_image.cat "
            "SP_DELETE_FILES_CAT=/tmp/sp_delete_files.cat "
            "Fixed filenames in world-writable /tmp, no mkstemp or O_EXCL. "
            "Pre-created sp_restore_image.cat controls which FI image files are restored "
            "during service pack installation -- potential substitution of malicious images. "
            "Pre-created sp_delete_files.cat controls which files are deleted -- "
            "potential removal of security controls during SP upgrade. "
            "Script runs as root; an attacker who wins the race manipulates FI state "
            "at the root level during an SP upgrade operation. "
            "AC:H: race window is narrow (pre-upgrade to script execution). "
            "UI:R: requires admin to trigger SP upgrade. "
            "5.0 MEDIUM: local root-executing race condition on upgrade-time catalog files."
        ),
        "affected_products": [
            "UCS Manager FI 6500/6600 X-Direct (sp_upgrade_helper.sh, all platforms with spm)"
        ],
    },
    {
        "id":           "CWOM316-F6",
        "module":       "cisco_ucs_cwom_316_re",
        "new_cvss3":    6.4,
        "new_vector":   "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H",
        "rationale": (
            "onlineUpgrade.sh downloads update tarball from download.vmturbo.com: "
            "sudo curl -o /mnt/iso/online-packages.tar "
            "https://download.vmturbo.com/appliance/download/updates/${turboVersion}/online-packages.tar "
            "No --cacert pin, no hash verification, no signature check on downloaded tarball. "
            "Tarball applied directly after download without any integrity step. "
            "TLS channel protects passive interception but not CDN compromise or DNS hijack. "
            "A CDN or DNS compromise targeting download.vmturbo.com delivers malicious update "
            "applied without detection across all CWOM appliances using online upgrade. "
            "AV:N: update fetched from internet (management network to CDN). "
            "AC:H: requires compromising download.vmturbo.com CDN or DNS. "
            "PR:H: admin must trigger online upgrade (Cisco convention: admin-level ops = PR:H). "
            "UI:R: explicit admin action to run onlineUpgrade.sh. "
            "C:H/I:H/A:H: malicious package = full appliance compromise. "
            "6.4 MEDIUM (AC:H + PR:H + UI:R limit the score despite high impact). "
            "Contrast: same class as ESU-F3 (MEDIUM) but with broader CDN attack surface."
        ),
        "affected_products": ["CWOM 3.16.0 (onlineUpgrade.sh, all online-upgrade deployments)"],
        "cve_class": "Update mechanism without integrity verification (supply chain).",
    },
]

# ============================================================
# CONFIRMED LOW -- Category Summary (complete, thorough pass)
# ============================================================

CONFIRMED_LOW_CATEGORIES = {
    "firmware_recon_codenames": {
        "count": 42,
        "examples": [
            "BSERIES-F7 (SWID codename CPU gen matrix)",
            "BSERIES-F8 (M8 single blob three codenames: godzilla1/2/3)",
            "CSUB-F5 (GODZILLA/MOUNTRAINIER/MOUNTADAMS in production binary)",
            "JALAMABEACH-F2 (Jalamabeach codename B200/B210 M6)",
            "AMDCIMC-F4 (AMD rack CIMC CPUGeneration=['emeraldrapids','turin'])",
            "CSERIES-M8-F5 (AMD M8 UEFI .cap format metadata)",
            "FI64-F6/F7 (build hostname/date in NX-OS kernel version string)",
            "CSERIES-M8-F2 (Intel GNR C220/C240 M8 BiosUpdate.json metadata)",
        ],
        "cvss3_range": "2.0 to 2.6",
        "typical_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 absolute ceiling; "
                          "most are informational with no network-accessible attack path = 0.0 to 2.0",
        "note": "Internal product codenames, platform identifiers, build metadata. "
                "Intelligence value for targeting but no direct exploitation path.",
    },
    "binary_deduplication_survey": {
        "count": 18,
        "examples": [
            "MRSAS-BINARY-DEDUP-F1 (B200 M4 mrsasctlr = UCSB-RAID12G-M6 -- identical)",
            "HGST-NVME-KNCCD122-DEDUP-F1 (all HGST NVMe capacity variants identical)",
            "MICRON-NVME-SHARED-FW-F1 (all Micron E2CS007 SKUs share one firmware)",
            "KIOXIA-CF8-SAME-BINARY-F1 (8 Kioxia 1YETE106 SKUs share one binary)",
        ],
        "cvss3_range": "0.0",
        "note": "Firmware deduplication survey data. No security impact; "
                "useful only for acquisition scope and CVE applicability mapping.",
    },
    "build_metadata_exposure": {
        "count": 14,
        "examples": [
            "INTERSIGHT-F7 (build-info.json exposes git hashes and codenames)",
            "UCSC-F5 (imghdr not stripped, debug symbols present)",
            "BSERIES-BUNDLE-SURVEY-COMPLETE-F1 (survey metadata -- 582 TAR members)",
            "FI-INFRA-F5 (all 4 FI platforms share identical inner software)",
        ],
        "cvss3_range": "2.0 to 2.6",
        "note": "Build system metadata and binary survey results. "
                "Useful for fingerprinting and reverse engineering but no direct attack.",
    },
    "hardware_security_config_informational": {
        "count": 27,
        "examples": [
            "SAMISH-LAKE-JTAG-PSOC-F1 (JTAG state machine debug + PSoC bootloader strings)",
            "PTE3-CPLD-SVF-BYPASS-F1 (DO_BYPASS pattern in CPLD SVF -- optional flag)",
            "CSERIES-MOD3-F3 (PCIe M85-SB FPGA dual-image, no anti-rollback)",
            "CSERIES-MOD3-F4 (AIKIDO loader change error -- TAM integrity failure path)",
            "CSERIES-MOD3-F6 (AIKIDO enforcement FPGA-resident -- design architecture note)",
            "MRAID12G-HE-CPLD-MAXII-SECURITY-F1 (Intel MAX II security bit state)",
            "B480BIOS-F2 (B/X BIOS use older LFBC SPI image format)",
            "BSERIES-BXM6-F2 (rlogin/rcp binaries present, no active xinetd config)",
        ],
        "cvss3_range": "2.0 to 3.4",
        "typical_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
        "note": "Physical-proximity or admin-access hardware security configs. "
                "Not remotely exploitable without other preconditions.",
    },
    "tls_crypto_informational": {
        "count": 7,
        "examples": [
            "UCSM-CRYPTO-F3 (libssl legacy renegotiation + TLS 1.0 support)",
            "CSERIES-F3 (CIMC trust store SHA-1-signed Spanish root CA)",
            "intersight_ciscossh-F5 (PSB SEC-CRY-PRIM cipher gap -- documented not enforced)",
            "FASTLINQ-F2 (QLogic NVMe iSCSI default password in config)",
        ],
        "cvss3_range": "2.6 to 3.7",
        "note": "Crypto configuration weaknesses. MITM-in-path required (AC:H) for exploitation. "
                "UCSM-CRYPTO-F3 in particular: TLS 1.0 support = 3.7 LOW (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N). "
                "Not upgraded -- AC:H means not straightforwardly exploitable without active MITM.",
    },
    "session_auth_debug_informational": {
        "count": 8,
        "examples": [
            "ucsm_fips_auth-F4 (session cookie entropy debug logging)",
            "ucsm_fips_auth-F5 (source tree path in Auth.cc error strings)",
            "intersight_cert_bootstrap-F6 (dev comment about predictable SSH key)",
            "fi_nxos_activation-F5 -- UPGRADED TO MEDIUM (see above)",
        ],
        "cvss3_range": "0.0 to 2.6",
        "note": "Hardening gaps and debug artifacts. "
                "Note: fi_nxos_activation-F5 was originally in this category but upgraded to MEDIUM.",
    },
    "storage_hardware_survey": {
        "count": 25,
        "examples": [
            "SEAGATE-TCG-FAMILY-COMPLETE-F1 (Seagate SAS HDD TCG Enterprise survey complete)",
            "MICRON-NVME-SURVEY-F1 (Micron NVMe E2CS007/E3MQ survey)",
            "WDC-HAMR-AHA2-TCG-ENCRYPTED-DUMP-F1 (WDC HAMR 24TB AHA2 + encrypted dump)",
            "CPLD-SVF-BYPASS-OPTIONAL-F1 (Intel MAX 10 FPGA CPLD bypass modes documented)",
            "HGST-NVME-KMCCP108-XTENSA-F1 (Xtensa ISA DebugExceptionVector in HGST NVMe)",
        ],
        "cvss3_range": "0.0 to 2.0",
        "note": "Storage hardware survey results -- reconnaissance value only. "
                "Physical access required for all diagnostic paths.",
    },
    "intersight_cloud_informational": {
        "count": 8,
        "examples": [
            "INTERSIGHT-F6 (cloud-init admin password base64 in KVM YAML -- file permissions unconfirmed)",
            "intersight_disk2_disk3-F6 (andromeda codename in firmware)",
            "intersight_onprem_ansible-F6 (hammer_account_id hardcoded '100000000000')",
            "intersight_equinox_connector-F6 (bash quoting bug in startup.sh -- no-exec consequence)",
            "INTERSIGHT-F8 (missing kptr_restrict and dmesg_restrict -- hardening gap)",
        ],
        "cvss3_range": "2.0 to 3.3",
        "note": "Intersight hardening gaps. kptr_restrict/dmesg_restrict absence is a post-exploitation "
                "aid, not independently exploitable. INTERSIGHT-F6 base64 stays LOW: "
                "/etc/my-appliance-config.yaml permissions unconfirmed; root-readable only = PR:H = 2.3 LOW.",
    },
    "cwom_vmdk_bintar_informational": {
        "count": 4,
        "examples": [
            "cwom_vmdk-F7 (Docker Hub 'turbopassword' commented-out credential in CR template)",
            "cwom_bintar-F6 (k8s-ip-change.sh UID 1000 hardcoded check -- UID != username)",
            "cwom_iso-F6 (MariaDB wait_timeout=86400 -- 24-hour session persistence)",
            "cwom_update-F6 (turboclientupgrade.sh missing closing quote -- syntax defect, "
                            "causes conditional to always false but no security path)",
        ],
        "cvss3_range": "0.0 to 2.6",
        "note": "cwom_vmdk-F7: commented credential -- if Docker Hub account turbouser still active "
                "with this password, image push is possible; LOW because commented and account unconfirmed active. "
                "cwom_update-F6: bash syntax error causes unconditional kubectl apply -- "
                "no attacker-controlled input in scope, LOW confirmed.",
    },
    "fi_infrastructure_fex_informational": {
        "count": 7,
        "examples": [
            "FI-INFRA-F3 (FEX consent token system strings -- token key extraction requires physical flash access)",
            "FI-INFRA-F4 (FEX FPGA RSU in-service reprogram -- conditional: diagpkg.sh network accessibility unconfirmed)",
            "FI-INFRA-F5 (all 4 FI platforms identical inner software -- survey fact)",
            "FI-INFRA-F6 (FI NX-OS kernel cmdline security parameters exposed)",
            "FI-INFRA-F7 (FEX production firmware contains debug scripts -- access path unconfirmed)",
            "FI-INFRA-F8 (FEX cert DN exposes Summerville codename)",
        ],
        "cvss3_range": "2.0 to 3.4",
        "conditional_upgrade_note": (
            "FI-INFRA-F4: if diagpkg.sh is confirmed triggerable via UCSM or FEX management "
            "interface without authentication, this becomes HIGH "
            "(AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N = 7.5). "
            "Requires confirmation of authenticated vs unauthenticated access to diagpkg.sh."
        ),
    },
    "cmc_standalone_informational": {
        "count": 3,
        "examples": [
            "CMC-F6 (Mosquitto Unix socket allow_anonymous true -- AV:L, Unix socket only, TCP 9020 commented out)",
            "UCSM-SAM-F8 (nuova-sim-mgmt-nsg boot fallback -- legacy path, /bootflash write needed)",
            "UCSC-F6 (SELinux disabled in UCS Central 1.5.1c -- hardening gap, no independent exploit)",
        ],
        "cvss3_range": "2.0 to 3.4",
        "note": "CMC-F6 stays LOW: Unix socket = AV:L; if the jrpc_server or quiet_proxy bridge this "
                "socket to the network, severity escalates to MEDIUM via the CMC-F3 chain. "
                "UCSC-F6 stays LOW: SELinux disabled reduces post-exploitation barriers but "
                "is not independently exploitable.",
    },
    "huu_remaining_informational": {
        "count": 8,
        "examples": [
            "huu_c220_250-F6 (Python 3.11 invoked as 'python' -- version lock gap)",
            "HCMD-F6 (nginx HTTP access logging disabled by default -- auditability gap)",
            "HUU-C480-F2 (C480 biosup/fwup are OpenSSL test utilities -- not production feature)",
            "HCMP-F4 (IMGVERIFY bypass persists 2+ years of CI builds)",
            "HCMP-F5 (XE130 C M8 HUU stripped catalog, different CIMC build)",
        ],
        "cvss3_range": "0.0 to 3.4",
        "note": "HCMP-F4: IMGVERIFY bypass (IMG_VERIFY=0) already captured at MEDIUM in the MEDIUM pass "
                "(imgverify bypass class). This HCMP-F4 is the cross-platform persistence note -- "
                "informational observation about the bug duration, not a new finding instance.",
    },
    "remaining_misc": {
        "count": 4,
        "examples": [
            "fi_nxos_backup-F6 (log passphrase = SHA512(KEY_VALUE) -- dependent on F1 KEY_VALUE compromise)",
            "esu_602-ESU-F4 (ESU tarball CMC component version mismatch -- survey fact)",
            "fi_bundle_cross-XBND-F4/F5 (bundle TAR structure change -- informational)",
        ],
        "cvss3_range": "0.0 to 2.6",
        "note": "fi_nxos_backup-F6: dependent finding (cross-subsystem impact from KEY_VALUE compromise "
                "already rated HIGH in fi_nxos_backup-F1/F2). No standalone score.",
    },
}

# ============================================================
# CONDITIONAL UPGRADE NOTE
# ============================================================

CONDITIONAL_UPGRADE_NOTES = [
    {
        "id":        "FI-INFRA-F4",
        "module":    "cisco_ucs_fi_infrastructure_re",
        "condition": "diagpkg.sh triggerable from UCSM or FEX management interface without auth",
        "if_confirmed_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N = 7.5 HIGH",
        "current":   "LOW -- pending confirmation of diagpkg.sh network accessibility",
        "note": (
            "FEX 2400 fpga_signed_nomcu_rsu.rpd with RSU (in-service FPGA reprogram) capability. "
            "diagpkg.sh in production firmware bundle triggers FPGA updates. "
            "RSU would inject a malicious FPGA bitstream without power cycle. "
            "If diagpkg.sh is network-accessible without auth: 7.5 HIGH. "
            "Currently unconfirmed -- diagpkg.sh access control not yet extracted from FEX firmware."
        ),
    },
    {
        "id":        "cwom_vmdk-F7",
        "module":    "cisco_ucs_cwom_vmdk_re",
        "condition": "turbouser Docker Hub account still active with password 'turbopassword'",
        "if_confirmed_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N = 7.1 HIGH",
        "current":   "LOW -- credential is commented-out in template; account activity unconfirmed",
        "note": (
            "charts_v1alpha1_xl_cr.yaml comment block includes: "
            "#imageUsername: turbouser, #imagePassword: turbopassword. "
            "If turbouser account is still active on Docker Hub with this password, "
            "an attacker can push malicious images to turbouser namespace. "
            "The registry/imageUsername/imagePassword fields in the CR spec are live -- "
            "an admin who uncomments this block would pull from the attacker-controlled namespace. "
            "Pending: Docker Hub account liveness check for turbouser."
        ),
    },
]

# ============================================================
# REVERIFICATION SUMMARY
# ============================================================

REVERIFICATION_SUMMARY = {
    "pass":                   "4 of 4 (LOW) -- thorough re-verification",
    "total_low_reviewed":     181,
    "upgraded_to_medium":     6,
    "extraction_artifacts":   2,
    "confirmed_low":          173,
    "conditional_upgrades":   2,

    "upgraded_to_medium_list": [
        "UCSM-CTR-F8 (sam_policy_server TCP/843 root unauth, 5.3)",
        "UCSM-APACHE-F7 (connector proxy path-passthrough SSRF, 5.3)",
        "intersight_node_init-F6 (world-writable /tmp/net.conf, 4.0)",
        "fi_nxos_activation-F5 (mode 666 UCSM SAM audit logs, 6.1)",
        "fi_nxos_activation-F6 (SP upgrade /tmp catalog race root, 5.0)",
        "CWOM316-F6 (online update no hash/sig verify, 6.4)",
    ],

    "extraction_artifact_list": [
        "HUU-F9 -- MEDIUM in source module (symlink race root overwrite, 4.7); wrongly extracted as LOW",
        "FI-INFRA-F2 -- MEDIUM in source module (NOKASLR on FEX kernel); wrongly extracted as LOW",
    ],

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
    print(f"LOW reverification (thorough): {REVERIFICATION_SUMMARY['total_low_reviewed']} findings reviewed")
    print(f"  Upgraded to MEDIUM:     {REVERIFICATION_SUMMARY['upgraded_to_medium']}")
    print(f"  Extraction artifacts:   {REVERIFICATION_SUMMARY['extraction_artifacts']} (already MEDIUM in source)")
    print(f"  Conditional upgrades:   {REVERIFICATION_SUMMARY['conditional_upgrades']} pending confirmation")
    print(f"  Confirmed LOW:          {REVERIFICATION_SUMMARY['confirmed_low']}")
    print()
    print("Upgrades:")
    for u in REVERIFICATION_SUMMARY["upgraded_to_medium_list"]:
        print(f"  {u}")
    print()
    print("Artifacts (wrongly extracted as LOW):")
    for a in REVERIFICATION_SUMMARY["extraction_artifact_list"]:
        print(f"  {a}")
    print()
    fcc = REVERIFICATION_SUMMARY["final_cumulative_critical"]
    print("All 4 passes complete.")
    print(f"FINAL Critical ID total: {fcc['total_critical_ids']}")
