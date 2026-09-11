"""
Cisco UCS VIC M85-SB (Sideband/Secondary) 5.4(2.47-48) RE module
Target: ucs-m85-sb-vic.5.4.2.47-48.bin (21,288,939 bytes, from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Version: 5.4.2.47-48 — combined version suffix suggesting dual-component or upgrade bridge image

Extraction path:
  SN header (hsize=976, magic=6401534e) — note: 12 bytes larger than M85/M84
  -> gzip at hsize+0
  -> tar (./blob at 21,701,260 bytes) — 1.2MB larger than M85's blob
  -> blob has non-standard SN-like header (0x1bc bytes) before gzip
  -> gzip at blob+0x1bc (FNAME="mpf244321", gzip FLG=0x08)
  -> inner2 (55,470,568 bytes, very close to M84's 55,465,328)
  -> CPIO "newc" at inner2+0x542934 (876 entries, vs M84's 892)

Dual-ASIC image: load_rtdb.sh contains BOTH Bodega (M84) and Beverly (M85) branches.
This image can run on either ASIC generation. It is likely the field-upgrade bridge
firmware used when replacing a Bodega-generation VIC with a Beverly-generation VIC
without a separate firmware image per hardware revision.

Build info:
  Version string: "5.4(2.47)" at blob+0x20
  Build tag: "cspgre-260131-13:37:32" at blob+0x160 (6 min after M85: 13:31:41)
  Same build day (2026-01-31) as M85 Beverly; built slightly later

Security posture: IDENTICAL to M84/M85. All findings confirmed.
  - Same xinetd.conf (telnet -l dbgsh)
  - Same securechk (M85-style: 3-file replacement, no iptables zeroing)
  - Same nosec/* (login, consolelogin, debugplugin)
  - Same mcp.sh/macd.sh with WARNING banners
  - Same root:lAV031WHrUqto:14396 shadow hash
  - Same BODXXX markers in rcS (Bodega ASIC runtime)
"""

FIRMWARE = {
    "target":    "Cisco UCS VIC M85-SB (Sideband/Secondary) 5.4(2.47-48)",
    "file":      "ucs-m85-sb-vic.5.4.2.47-48.bin",
    "model":     "UCS VIC M85-SB (dual-ASIC: Bodega + Beverly support)",
    "arch":      "MIPS 32-bit LE, BusyBox + uClibc",
    "cpio_off":  "inner2+0x542934 (876 entries) — different from M84's 0x54aa58 / M85's 0xffd000",
    "blob_header_note": "blob has 0x1bc bytes of pre-gzip header containing version string and "
                        "build timestamp; gzip fname='mpf244321'; requires wbits=47 (gzip auto-detect) "
                        "for decompression (zlib with manual deflate parse fails on stored block)",
    "findings":  ["VIC-M85SB-F1", "VIC-M85SB-F2", "VIC-M85SB-F3", "VIC-M85SB-F4", "VIC-M85SB-F5"],
    "asic_support": "Dual: Bodega (M84) + Beverly (M85), confirmed via load_rtdb.sh",
    "dual_asic_load_rtdb": """
asic=$(conf basename | awk '{ print $2 }')
if [[ ${asic} = Bodega ]]; then      # M84 ASIC path
    ...
elif [[ ${asic} = Beverly ]]; then   # M85 ASIC path
    ...
fi""",
}

# VIC-M85SB-F1: Telnet no-auth — confirmed on dual-ASIC image
VIC_M85SB_F1 = {
    "id":       "VIC-M85SB-F1",
    "title":    "Telnet TCP/23 no-auth via xinetd/BusyBox telnetd -l dbgsh confirmed on M85-SB "
                "dual-ASIC image; applies to both Bodega (M84) and Beverly (M85) targets "
                "that receive this upgrade bridge image",
    "severity": "HIGH",
    "status":   "CONFIRMED — etc/xinetd.conf extracted from CPIO at inner2+0x542934; "
                "server_args=-i -l dbgsh, disable=no",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "cross_model_coverage": "VIC-M85-F1 (Beverly) + VIC-M84-F1 (Bodega) both confirmed on this image",
}

# VIC-M85SB-F2: rlogin TCP/513
VIC_M85SB_F2 = {
    "id":       "VIC-M85SB-F2",
    "title":    "rlogin TCP/513 via in.rlogind — identical to M84/M85; confirmed on dual-ASIC image",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — etc/xinetd.conf; service login, disable=no, in.rlogind",
    "cwe":      ["CWE-319 (Cleartext Transmission of Sensitive Information)"],
}

# VIC-M85SB-F3: nosec mode
VIC_M85SB_F3 = {
    "id":       "VIC-M85SB-F3",
    "title":    "nosec mode via /config/devel.cfg security=0 — identical securechk (M85-style: "
                "3-file replacement, no iptables zeroing); early_rc/mid_rc/late_rc boot hooks; "
                "BODXXX=false in rcS confirms Bodega runtime; Beverly also supported via load_rtdb.sh",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — bin/securechk, etc/nosec/* extracted from CPIO",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "verbatim_securechk": """
#!/bin/sh
if grep -q '^security[ ]*=[ ]*0' /config/devel.cfg 2>/dev/null
then
    cd /bin
    rm consolelogin debugplugin login
    cd /etc/nosec
    mv consolelogin debugplugin login /bin
fi""",
}

# VIC-M85SB-F4: /config/mcp and /config/macd overrides
VIC_M85SB_F4 = {
    "id":       "VIC-M85SB-F4",
    "title":    "/config/mcp and /config/macd binary overrides with WARNING banners — identical to M84",
    "severity": "HIGH",
    "status":   "CONFIRMED — bin/mcp.sh and bin/macd.sh extracted from CPIO",
    "cwe":      ["CWE-668 (Exposure of Resource to Wrong Sphere)"],
}

# VIC-M85SB-F5: Root DES hash — now confirmed on M85-SB, completing cross-model/version matrix
VIC_M85SB_F5 = {
    "id":       "VIC-M85SB-F5",
    "title":    "Root DES hash lAV031WHrUqto confirmed on M85-SB — completes cross-model matrix: "
                "Palo-family (M83 4.7.2) + Bodega (M84 5.4.2) + Beverly (M85 5.4.2) + "
                "Dual-ASIC bridge (M85-SB 5.4.2.47-48); single crack covers all VIC firmware",
    "severity": "HIGH",
    "status":   "CONFIRMED — etc/shadow extracted from CPIO; "
                "root:lAV031WHrUqto:14396:0:99999:7:::",
    "cwe":      ["CWE-259 (Use of Hard-coded Password)"],
    "complete_cross_model_matrix": {
        "M83 4.7.2 (Palo-family)":       "lAV031WHrUqto [CONFIRMED]",
        "M84 5.4.2 (Bodega)":            "lAV031WHrUqto [CONFIRMED]",
        "M85 5.4.2 (Beverly)":           "lAV031WHrUqto [CONFIRMED]",
        "M85-SB 5.4.2.47-48 (dual)":    "lAV031WHrUqto [CONFIRMED]",
        "dbgsh (all)":                   "empty password [CONFIRMED]",
    },
    "note": "The M85-SB dual-ASIC image confirms the credential is in BOTH Bodega and Beverly "
            "runtime environments from a single image. The bridge/upgrade image is what ships "
            "in the B-Series bundle for field upgrade scenarios; its compromise covers all "
            "VIC variants a customer is likely to have in a mixed deployment.",
}

FINDINGS = [VIC_M85SB_F1, VIC_M85SB_F2, VIC_M85SB_F3, VIC_M85SB_F4, VIC_M85SB_F5]
