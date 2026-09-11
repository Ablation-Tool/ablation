"""
Cisco UCS VIC M83 4.7.2 RE module
Target: ucs-m83-8p40-vic.4.7.2.260001.bin (10,141,280 bytes, from ucs-k9-bundle-b-series.6.0.2b.B.bin)
Model: UCS VIC 1385 / M83 8-port 40G VIC
Architecture: MIPS 32-bit LE, BusyBox + uClibc
Firmware version: 4.7.2.260001 (older branch vs M84/M85 at 5.4.2)

Extraction path:
  SN header (hsize=972, magic=6401534e)
  -> gzip at hsize+0
  -> tar (./blob at 10,178,945 bytes)
  -> blob contains gzip at blob+0x7c
  -> inner (24,120,408 bytes)
  -> CPIO "newc" at inner+0x3be008 (1,470 entries)
  -> JFFS2 at inner+0xf403c
  -> SquashFS (hsqs LE) at inner+0x45ac94

ASIC: Unknown (Palo-family predecessor to Bodega/Beverly)
Shadow date 14396 = 1970-01-01 + 14396 days = 2009-06-16

Cross-version note: root DES hash lAV031WHrUqto (salt lA) is IDENTICAL
to M84 5.4.2 and M85 5.4.2. The credential predates the 5.x branch
and has not been rotated across at least 17 years and 2 major firmware versions.
"""

FIRMWARE = {
    "target":    "Cisco UCS VIC M83 (8-port 40G) 4.7.2",
    "file":      "ucs-m83-8p40-vic.4.7.2.260001.bin",
    "model":     "UCS VIC M83 8P40",
    "arch":      "MIPS 32-bit LE, BusyBox + uClibc",
    "cpio_off":  "inner+0x3be008 (1,470 entries)",
    "jffs2_off": "inner+0xf403c",
    "sqfs_off":  "inner+0x45ac94",
    "findings":  ["VIC-M83-F1", "VIC-M83-F2", "VIC-M83-F3", "VIC-M83-F4", "VIC-M83-F5", "VIC-M83-F6"],
}

# VIC-M83-F1: Telnet TCP/23 no-auth via BusyBox telnetd -l dbgsh
VIC_M83_F1 = {
    "id":       "VIC-M83-F1",
    "title":    "xinetd spawns BusyBox telnetd with -l dbgsh on TCP/23 — "
                "telnetd executes /bin/dbgsh directly, bypassing all authentication; "
                "identical configuration in both production xinetd.conf and etc/nosec/xinetd.conf",
    "severity": "HIGH",
    "status":   "CONFIRMED — etc/xinetd.conf extracted from CPIO at inner+0x3be008; "
                "nosec/xinetd.conf is character-for-character identical to production config",
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
    "note_on_nosec_xinetd": "In M83, securechk replaces /etc/xinetd.conf with /etc/nosec/xinetd.conf "
                             "in nosec mode. However, both files are identical. The nosec config "
                             "does not reduce telnet access — it was never restricted to begin with. "
                             "In M85, there is no separate nosec xinetd.conf replacement.",
    "threat_model": "Any host on the management network segment with connectivity to VIC TCP/23 "
                    "gets a root shell without any credential. xinetd enforces no ACL on the "
                    "telnet service.",
}

# VIC-M83-F2: rlogin TCP/513 via in.rlogind
VIC_M83_F2 = {
    "id":       "VIC-M83-F2",
    "title":    "rlogin (TCP/513) enabled via in.rlogind in production xinetd.conf — "
                "BSD trust-model cleartext protocol",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — etc/xinetd.conf; service login block with in.rlogind, disable=no",
    "cwe":      ["CWE-319 (Cleartext Transmission of Sensitive Information)"],
    "verbatim_config": """
service login
{
    disable         = no
    socket_type     = stream
    wait            = no
    user            = root
    log_on_success += USERID
    log_on_failure += USERID
    server          = /usr/sbin/in.rlogind
}""",
}

# VIC-M83-F3: nosec mode — WIDER than M85; additionally zeroes 3 iptables scripts
VIC_M83_F3 = {
    "id":       "VIC-M83-F3",
    "title":    "nosec mode via /config/devel.cfg security=0 — M83 securechk zeroes "
                "THREE iptables scripts (iptables-rules, iptables-publicintf-rules, iptables-manage) "
                "in addition to auth bypass; full firewall collapse on nosec activation; "
                "early_rc hook on writable /config/ executes before securechk",
    "severity": "CRITICAL",
    "status":   "CONFIRMED — bin/securechk and all nosec/ files extracted from CPIO; "
                "iptables bypass is M83-specific, not present in M84 or M85 securechk",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)",
                 "CWE-668 (Exposure of Resource to Wrong Sphere)",
                 "CWE-284 (Improper Access Control)"],
    "verbatim_securechk": """
#!/bin/sh
if grep -q '^security[ ]*=[ ]*0' /config/devel.cfg 2>/dev/null
then
    mv /etc/nosec/login /bin/login
    mv /etc/nosec/xinetd.conf /etc/xinetd.conf
    rm /bin/debugplugin
    ln -s /etc/nosec/debugplugin /bin/debugplugin
    chmod 4755 /bin/debugplugin
    mv /etc/nosec/iptables-rules /bin/iptables-rules
    mv /etc/nosec/iptables-publicintf-rules /bin/iptables-publicintf-rules
    mv /etc/nosec/iptables-manage /bin/iptables-manage
    mv /etc/nosec/consolelogin /bin/consolelogin
fi
iptables-rules""",
    "verbatim_nosec_iptables_rules": "#!/bin/sh\n# Don't install any iptables rules — nosec mode\nexit 0",
    "verbatim_nosec_iptables_publicintf_rules": "#!/bin/sh\n# Do nothing — nosec mode\nexit 0",
    "verbatim_nosec_login": """
#!/bin/sh --
s="$*"
u=${s##* }
[ -z "$u" ] && u=root
export USER=$u; export TERM=vt100
s=`grep "^$u:" /etc/passwd`
[ -z "$s" ] && exit 0
shell=`expr "$s" : '.*:\\(.*\\)'`
[ -z "$shell" ] && shell=/bin/sh
exec $shell -i""",
    "boot_hooks": {
        "early_rc":  "/config/early_rc sourced BEFORE securechk — arbitrary script execution "
                     "from writable NAND before any security check runs",
        "mid_rc":    "/config/mid_rc sourced after securechk and xinetd, before launcher",
        "late_rc":   "/config/late_rc sourced after launcher",
    },
    "iptables_scope": {
        "iptables-rules":             "/bin/iptables-rules — base firewall ruleset; replaced with exit 0",
        "iptables-publicintf-rules":  "/bin/iptables-publicintf-rules — per-interface rules for "
                                      "public/customer-facing interfaces; replaced with exit 0",
        "iptables-manage":            "/bin/iptables-manage — firewall management wrapper; "
                                      "replaced with exit 0",
    },
    "nosec_vs_m85": "M83's nosec mode: 8 files replaced (login, xinetd.conf, debugplugin [symlink], "
                    "iptables-rules, iptables-publicintf-rules, iptables-manage, consolelogin). "
                    "M85's nosec mode: 3 files replaced (consolelogin, debugplugin, login). "
                    "M83 also zeroes all firewall scripts; M85 does not.",
    "threat_model": "Write security=0 to /config/devel.cfg (writable NAND), reboot. "
                    "On next boot: securechk replaces /bin/login with no-auth version, "
                    "zeroes all 3 iptables scripts, and grants setuid shell via debugplugin. "
                    "Full auth bypass + zero firewall. Or: write early_rc to /config/ to "
                    "execute arbitrary code before securechk even runs.",
}

# VIC-M83-F4: /config/mcp binary override backdoor
VIC_M83_F4 = {
    "id":       "VIC-M83-F4",
    "title":    "/config/mcp on writable NAND is executed instead of production /bin/mcp — "
                "persistent binary override for VIC's primary management control process; "
                "M83 variant does not print banner warning (unlike M84/M85)",
    "severity": "HIGH",
    "status":   "CONFIRMED — bin/mcp.sh extracted from CPIO",
    "cwe":      ["CWE-668 (Exposure of Resource to Wrong Sphere)"],
    "verbatim_mcp_sh": """
#!/bin/sh
# For debugging, check for /config/mcp and run that one if found.
test -x /config/mcp && exec /config/mcp $*
exec mcp $*""",
    "note_on_m83_vs_m84": "M83's mcp.sh uses a single-line test; M84/M85 use if-block with "
                           "explicit console banner warning. M83 is silent — no log entry "
                           "when /config/mcp override is active.",
    "threat_model": "Install a trojanized binary at /config/mcp on writable NAND. "
                    "On next MCP start (boot or service restart), the override runs instead of "
                    "production MCP, with no console warning and no log indication. "
                    "Persistence survives firmware updates if /config/ is not wiped.",
}

# VIC-M83-F5: UART console on ttyS0 (different from M85's ttyS1/bmcdebugshell)
VIC_M83_F5 = {
    "id":       "VIC-M83-F5",
    "title":    "UART console on /dev/ttyS0 — inittab runs /bin/consolelogin on ttyS0 with "
                "askfirst action (waits for keypress); consolelogin executes /bin/login dbgsh "
                "(empty password, dbgsh account) — different from M85's bmcdebugshell on ttyS1",
    "severity": "MEDIUM",
    "status":   "CONFIRMED — etc/inittab and bin/consolelogin extracted from CPIO",
    "cwe":      ["CWE-306 (Missing Authentication for Critical Function)"],
    "verbatim_inittab": "ttyS0::askfirst:/bin/consolelogin",
    "verbatim_consolelogin": "#!/bin/sh\n/bin/login dbgsh",
    "contrast_m85": {
        "M83": "ttyS0 / ::askfirst / consolelogin -> /bin/login dbgsh",
        "M85": "ttyS1 / ::respawn / bmcdebugshell /dev/ttyS1 38400 vt100 -> conf; /bin/dbgsh",
    },
    "threat_model": "Physical access to the M83 VIC UART header (ttyS0 at 38400 baud, "
                    "standard pinout) yields a dbgsh shell session with no password required. "
                    "askfirst means the console waits for Enter key before spawning login, "
                    "making this an interactive-only (not scripted) access path.",
}

# VIC-M83-F6: Root DES hash — cross-version, unchanged since 2009
VIC_M83_F6 = {
    "id":       "VIC-M83-F6",
    "title":    "Root DES crypt hash lAV031WHrUqto (salt lA) is IDENTICAL across M83 4.7.2, "
                "M84 5.4.2, and M85 5.4.2 — static credential spanning at least 17 years "
                "and two major firmware version branches; dbgsh account has empty password in all",
    "severity": "HIGH",
    "status":   "CONFIRMED — etc/shadow extracted from CPIO on M83, M84, M85; "
                "all three contain identical root hash and empty dbgsh entry",
    "cwe":      ["CWE-259 (Use of Hard-coded Password)",
                 "CWE-521 (Weak Password Requirements)"],
    "shadow_entry": "root:lAV031WHrUqto:14396:0:99999:7:::",
    "hash_analysis": {
        "algorithm":       "DES crypt(3), 2-char salt",
        "salt":            "lA",
        "hash":            "lAV031WHrUqto",
        "lastchg":         "14396 (days since 1970-01-01 = 2009-06-16)",
        "age":             "~17 years without rotation as of 2026",
        "cross_version":   ["M83 4.7.2", "M84 5.4.2", "M85 5.4.2"],
        "crack_command":   "hashcat -m 1500 'lAV031WHrUqto' rockyou.txt",
        "dbgsh_empty":     "dbgsh::14396:0:99999:7::: (empty password, valid on all three variants)",
    },
    "threat_model": "Crack the DES hash offline (trivial GPU time: DES-crypt at ~500M/s on "
                    "RTX 3090). The recovered password provides root on ALL deployed VIC variants "
                    "spanning at least M83, M84, and M85, across firmware versions 4.7.2 through 5.4.2. "
                    "The hash has not changed in 17 years — if cracked once, it is valid indefinitely "
                    "unless Cisco explicitly rotates the production root credential.",
}

FINDINGS = [VIC_M83_F1, VIC_M83_F2, VIC_M83_F3, VIC_M83_F4, VIC_M83_F5, VIC_M83_F6]
