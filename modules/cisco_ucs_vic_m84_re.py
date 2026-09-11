"""
Cisco UCS VIC M84 5.4.2 RE module
Target: ucs-m84-vic.5.4.2.47.bin (19,833,555 bytes, from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Model: UCS VIC 1497 / M84
Architecture: MIPS 32-bit LE, BusyBox + uClibc
Firmware version: 5.4(2.47) — same version branch as M85

Extraction path:
  SN header (hsize=964, magic=6401534e)
  -> gzip at hsize+0
  -> tar (./blob at 19,966,445 bytes)
  -> blob contains gzip at blob+0x7c
  -> inner (55,465,328 bytes)
  -> CPIO "newc" at inner+0x54aa58 (892 entries)
  -> JFFS2 at inner+0x11c3b4
  -> SquashFS (hsqs LE) at inner+0x5ef850

ASIC: Bodega / Bodeguita (confirmed via load_rtdb.sh and rcS BODXXX markers)
M85 ASIC: Beverly
M83 ASIC: unknown Palo-family predecessor

Shadow date 14396 = 2009-06-16: root hash has not been rotated
since before the 5.x firmware branch was created.
"""

FIRMWARE = {
    "target":    "Cisco UCS VIC M84 5.4.2",
    "file":      "ucs-m84-vic.5.4.2.47.bin",
    "model":     "UCS VIC M84 (Bodega ASIC)",
    "arch":      "MIPS 32-bit LE, BusyBox + uClibc",
    "cpio_off":  "inner+0x54aa58 (892 entries)",
    "jffs2_off": "inner+0x11c3b4",
    "sqfs_off":  "inner+0x5ef850",
    "findings":  ["VIC-M84-F1", "VIC-M84-F2", "VIC-M84-F3", "VIC-M84-F4", "VIC-M84-F5"],
    "asic":      "Bodega / Bodeguita (Cisco internal codenames, confirmed in rcS 'BODXXX' markers)",
    "shared_with_m85": ["VIC-M84-F1 ≈ VIC-M85-F1 (telnet -l dbgsh)",
                        "VIC-M84-F2 ≈ VIC-M85-F2 (rlogin)",
                        "VIC-M84-F3 ≈ VIC-M85-F3 (nosec mode, same securechk)",
                        "VIC-M84-F5 ≈ VIC-M85-F6 (root DES hash)"],
}

# VIC-M84-F1: Telnet TCP/23 no-auth via BusyBox telnetd -l dbgsh
VIC_M84_F1 = {
    "id":       "VIC-M84-F1",
    "title":    "xinetd spawns BusyBox telnetd with -l dbgsh on TCP/23 — no authentication; "
                "identical to M85 VIC-M85-F1; cross-model confirmation on Bodega ASIC",
    "severity": "HIGH",
    "status":   "CONFIRMED — etc/xinetd.conf extracted from CPIO; server_args = -i -l dbgsh",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "verbatim_config": """
service telnet
{
    disable          = no
    flags            = REUSE IPv6
    socket_type      = stream
    wait             = no
    user             = root
    server           = /usr/sbin/telnetd
    server_args      = -i -l dbgsh
    log_on_failure  += USERID
}""",
}

# VIC-M84-F2: rlogin TCP/513
VIC_M84_F2 = {
    "id":       "VIC-M84-F2",
    "title":    "rlogin (TCP/513) enabled via in.rlogind in xinetd.conf — "
                "cleartext BSD trust protocol; cross-model confirmation on Bodega ASIC",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — etc/xinetd.conf; service login block, disable=no",
    "cwe":      ["CWE-319 (Cleartext Transmission of Sensitive Information)"],
}

# VIC-M84-F3: nosec mode — same mechanism as M85, boot hooks confirmed
VIC_M84_F3 = {
    "id":       "VIC-M84-F3",
    "title":    "nosec mode via /config/devel.cfg security=0 — same mechanism as M85; "
                "securechk replaces consolelogin, debugplugin, login with no-auth equivalents; "
                "early_rc/mid_rc/late_rc boot hooks on writable /config/ NAND partition",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — bin/securechk, etc/nosec/* extracted from CPIO",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-284 (Improper Access Control)"],
    "verbatim_securechk": """
#!/bin/sh
if grep -q '^security[ ]*=[ ]*0' /config/devel.cfg 2>/dev/null
then
    cd /bin
    rm consolelogin debugplugin login
    cd /etc/nosec
    mv consolelogin debugplugin login /bin
fi""",
    "boot_sequence": [
        "if [ -f /config/early_rc ]; then . /config/early_rc; fi",
        "securechk",
        "xinetd",
        "if [ -f /config/mid_rc ]; then . /config/mid_rc; fi",
        "launcher",
        "if [ -f /config/late_rc ]; then . /config/late_rc; fi",
    ],
    "bodega_asic_markers": "rcS contains 'BODXXX=false' and 'reset_genio # BODXXX - needed by "
                           "Bodeguita since RAM not cleared' — Bodega/Bodeguita is M84's ASIC "
                           "family (Beverly = M85, Palo-family = M83).",
}

# VIC-M84-F4: /config/mcp and /config/macd overrides with explicit banner warnings
VIC_M84_F4 = {
    "id":       "VIC-M84-F4",
    "title":    "/config/mcp and /config/macd binary overrides print explicit console banners "
                "when active — Cisco deliberately documents debug override is running; "
                "M84 mcp.sh/macd.sh print WARNING banner to /dev/console (unlike M83)",
    "severity": "HIGH",
    "status":   "CONFIRMED — bin/mcp.sh and bin/macd.sh extracted from CPIO",
    "cwe":      ["CWE-668 (Exposure of Resource to Wrong Sphere)"],
    "verbatim_macd_sh": """
#!/bin/sh
if [ -x /config/macd ]; then
    cat > /etc/macd_banner << EOF
=============================================================
=                          WARNING                          =
=        Running /config/macd instead of /bin/macd          =
=============================================================
EOF
    cat /etc/macd_banner > /dev/console
    exec /config/macd $*
fi
exec macd $*""",
    "verbatim_mcp_sh": """
#!/bin/sh
if [ -x /config/mcp ]; then
    cat > /etc/mcp_banner << EOF
=============================================================
=                          WARNING                          =
=        Running /config/mcp instead of /bin/mcp            =
=============================================================
EOF
    cat /etc/mcp_banner > /dev/console
    exec /config/mcp $*
fi
exec mcp $*""",
    "note": "M84's mcp.sh and macd.sh write a WARNING banner to /dev/console (local UART) "
            "when the debug override is active. The banner is not logged to syslog or OBFL, "
            "and is not visible over the network — only on physical UART. "
            "An attacker planting /config/mcp leaves no remotely-observable indicator.",
    "threat_model": "Install trojanized binary at /config/mcp or /config/macd on writable /config/ NAND. "
                    "Persistence across reboots. Banner visible only on local UART — no network log. "
                    "Trojanized MCP controls VNIC configuration, NetFlow, firmware updates, and "
                    "all platform management traffic between VIC and CIMC.",
}

# VIC-M84-F5: Root DES hash cross-model confirmation (Bodega = M84, Beverly = M85, M83 = older)
VIC_M84_F5 = {
    "id":       "VIC-M84-F5",
    "title":    "Root DES crypt hash lAV031WHrUqto CONFIRMED on Bodega ASIC (M84) — "
                "identical to M83 4.7.2 and M85 5.4.2; static credential across ALL known "
                "VIC ASIC families and firmware versions",
    "severity": "HIGH",
    "status":   "CONFIRMED — etc/shadow extracted from CPIO; root:lAV031WHrUqto:14396:0:99999:7:::",
    "cwe":      ["CWE-259 (Use of Hard-coded Password)"],
    "shadow_entry": "root:lAV031WHrUqto:14396:0:99999:7:::",
    "cross_model_matrix": {
        "M83 4.7.2 (Palo-family)":  "root:lAV031WHrUqto:14396:0:99999:7::: [CONFIRMED]",
        "M84 5.4.2 (Bodega)":       "root:lAV031WHrUqto:14396:0:99999:7::: [CONFIRMED]",
        "M85 5.4.2 (Beverly)":      "root:lAV031WHrUqto:14396:0:99999:7::: [CONFIRMED]",
        "dbgsh (all models)":       "dbgsh::14396:0:99999:7::: (empty password)",
    },
    "crack_surface": "DES-crypt at ~500M/s on RTX 3090; single crack covers all VIC models ever deployed",
    "load_rtdb_asic_probe": """
#!/bin/sh
asic=$(conf basename | awk '{ print $2 }')
if [[ ${asic} = Bodega ]]; then     # M84 path
    ...
elif [[ ${asic} = Beverly ]]; then  # M85 path
    ...
fi""",
}

FINDINGS = [VIC_M84_F1, VIC_M84_F2, VIC_M84_F3, VIC_M84_F4, VIC_M84_F5]
