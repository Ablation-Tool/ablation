"""
Fortinet FortiManager FMG_VM64_KVM 8.0.0 RE
Source: FMG_VM64_KVM-v8.0.0.F-build0105-FORTINET.qcow2
Build date: 2026-04-20 | kernel: Linux 6.12.32 (same build as FAZ 8.0.0)
Extraction path: QCOW2 -> virtioa.raw -> P1 (sector 8193, dd) -> /mnt/fmg-p1
Accessible layers: P1 boot partition (ext2), rootfs-ext.tar.xz
Encrypted layers: vmlinuz payload, rootfs.gz (same custom format as FAZ)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiManager VM64-KVM",
    "os":             "FortiOS 8.0.0.F",
    "build":          "0105",
    "build_date":     "2026-04-20",
    "kernel":         "Linux 6.12.32",
    "kernel_builder": "root@e2770389c733",
    "arch":           "x86-64",

    "image_structure": {
        "qcow2":      "FMG_VM64_KVM-v8.0.0.F-build0105-FORTINET.qcow2",
        "p1_offset":  "sector 8193 (4196352 bytes)",
        "p1_size":    "1GB (2097152 sectors)",
        "p1_files":   ["vmlinuz (5.2MB bzImage)", "rootfs.gz (encrypted)", "rootfs-ext.tar.xz (standard XZ, accessible)"],
    },

    "codebase_identity": {
        "python_app":   "IDENTICAL to FAZ 8.0.0 (md5 differs only in macros.py IMG_TYPE field)",
        "img_type":     "IMG_TYPE = 2 (PRODUCT_FMG); FAZ uses IMG_TYPE = 1 (PRODUCT_FAZ)",
        "rootfs_ext_size": "237MB (vs FAZ's 296MB -- smaller, no FAZ-specific log analytics)",
        "all_ai_code":  "Byte-for-byte identical: agent_views.py, faz_mcp/views.py, mcp.py, all agent_definitions",
    },
}


# ---------------------------------------------------------
# Cross-product findings: all FAZ-F01 through FAZ-F05 apply
# ---------------------------------------------------------

# NOTE: FMG and FAZ 8.0.0 share an identical Python application codebase.
# All findings documented in fortinet_fortianalyzer_re.py apply verbatim to FMG.
# This module records:
# 1. The shared-codebase confirmation
# 2. FMG-specific amplified impact for FAZ-F01
# 3. FMG-specific analysis status

CROSS_PRODUCT_CONFIRMED = {
    "applies_to_fmg": [
        "FAZ-F01: Redis global pub/sub cross-session tool call injection",
        "FAZ-F02: Cookie exposure via webmcpserver cmdline args",
        "FAZ-F03: SSRF via server_url in faz_mcp endpoints (DEBUG-gated)",
        "FAZ-F04: Local MCP server :11345 auth unknown",
        "FAZ-F05: Log search filter passthrough to C daemon",
    ],
    "does_not_apply_to_fmg": {
        "FAZ-F06": "SOAR TLS bypass -- macros.py CONFIG_SOAR=0 in FMG; SOAR connector code present but feature-flagged off",
        "FAZ-F07": "SOAR WEBHOOK SSRF -- same reason; SOAR disabled in FMG",
        "FAZ-F08": "SOAR Redis credential store -- same reason; SOAR disabled in FMG",
        "FAZ-F09": "Apache backend proxy and ClickHouse binary -- APPLIES to FMG (same apache2 config, same ClickHouse binary)",
    },
    "macros_diff": {
        "IMG_TYPE":       "1 (FAZ) vs 2 (FMG)",
        "CONFIG_PROD_NAME": "FortiAnalyzer-VM64-KVM vs FortiManager-VM64-KVM",
        "CONFIG_SOAR":    "1 (FAZ) vs 0 (FMG)",
        "CONFIG_SIEM":    "1 (FAZ) vs 0 (FMG)",
        "HAVE_UPD_WEBSPAM": "absent (FAZ) vs 1 (FMG)",
        "FAZ_S_DISABLED": "absent (FAZ) vs 0 (FMG -- for enabling FAZ service mode on FMG)",
        "FAZ_S_ENABLED":  "absent (FAZ) vs 1 (FMG)",
    },
    "verification":  "diff -rq of Python trees returns 2 files: _c2pygui.so (binary) and macros.py (above)",
    "reference":     "fortinet_fortianalyzer_re.py",
}


# ---------------------------------------------------------
# FMG-F01: FAZ-F01 with amplified FMG impact
# ---------------------------------------------------------
FMG_F01_REDIS_CROSS_SESSION_AMPLIFIED = {
    "id":       "FMG-F01",
    "product":  "Fortinet FortiManager 8.0.0",
    "severity": "MEDIUM-HIGH -- same as FAZ-F01 but affects managed FortiGate fleet",
    "base":     "FAZ-F01 (fortinet_fortianalyzer_re.py) -- identical code, amplified blast radius",

    "description": (
        "FAZ-F01 Redis global pub/sub injection applies to FMG. "
        "On FMG, the advanced toolsets (general_network_diagnostic, vpn_diagnostic, "
        "sdwan_diagnostic, routing_diagnostic, utilities) execute diagnostic commands "
        "on MANAGED FORTIGATE DEVICES via the MCP server at :11345. "
        "An authenticated user who can inject a tool call response into another user's "
        "agent session could influence operations that run diagnostics on the managed fleet."
    ),

    "amplified_surface": {
        "managed_devices": "FMG manages fleet of FortiGate devices",
        "agent_tools":     "device_diagnostics_agent has tools that run remote device diagnostics",
        "fmg_toolsets":    [
            "fmg://agents/toolsets/advanced/general_network_diagnostic",
            "fmg://agents/toolsets/advanced/vpn_diagnostic",
            "fmg://agents/toolsets/advanced/sdwan_diagnostic",
            "fmg://agents/toolsets/advanced/routing_diagnostic",
            "fmg://agents/toolsets/advanced/utilities",
        ],
        "cross_device_impact": (
            "stop_conversation still only stops the FMG Django session. "
            "Tool call injection could affect in-flight device operations if "
            "an agent is executing a multi-step diagnostic on a managed device."
        ),
    },
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "python_layer":  "COMPLETE -- identical to FAZ; see FAZ module for full findings",
    "vmlinuz":       {
        "status":  "BLOCKED -- payload encrypted",
        "version": "Linux 6.12.32 PREEMPT_DYNAMIC (built 2026-04-20 10:50:40 PDT); RO-rootFS",
        "builder": "root@e2770389c733 (different container from FAZ root@49192c769448, same day build)",
    },
    "rootfs_gz":     "BLOCKED -- custom encryption format (same as FAZ, magic 0x5b6758cb...)",
    "rootfs_ext":    "ACCESSIBLE (extracted, 247MB) -- Python app confirmed identical to FAZ via diff; SOAR connectors ABSENT",
    "syntax_ext":    "ACCESSIBLE -- same structure as FAZ (fmg_cmdb_syntax.json 611KB, etc.)",
    "webmcpserver":  "BLOCKED -- binary in encrypted rootfs.gz",
    "unique_findings": ["FMG-F01"],
    "faz_findings_that_apply": ["FAZ-F01", "FAZ-F02", "FAZ-F03", "FAZ-F04", "FAZ-F05", "FAZ-F09"],
}
