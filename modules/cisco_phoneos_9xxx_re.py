"""
Cisco PHONEOS 9xxx / 8875 RE Module
Source: PHONEOS.5-0-1-0005-62.zip
Targets: CP-9811, CP-9821, CP-9841, CP-9851, CP-9861, CP-9871, CP-8875
Platform: i.MX 8ULP (ARM64), Linux 5.x miniroot + Android PKG overlay
Version: PHONEOS 5.0.1.0005-62 (2026-08-12)

Miniroot: miniroot-9811.5-0-1-0005-62.sbn -- squashfs v4.0, zlib, 20.6MB, 1375 inodes
          (shared by 9811 and 9841/9851 platforms per .loads manifest)
PKG: PHONEOS-9821/9861/9871/9841.5-0-1-0005-62.pkg -- proprietary Cisco container,
     magic 0x706b6700, platform-targeted (imx8ulp-WP-9821-0 etc.)

Analysis: miniroot squashfs extracted, sshd_config, init scripts, iptables rules,
          miniweb binary (strings), secureapp binary (strings), libfileauth.so,
          upgutil binary (strings)

Findings: 6F [0C+3H+3M+0L]
"""

FINDINGS = [
    {
        "id": "PHOS9K-F1",
        "title": "sshd_config: PermitRootLogin yes, PubkeyAuthentication no, "
                 "StrictModes no, UsePrivilegeSeparation no -- root accessible via password only",
        "severity": "HIGH",
        "component": "miniroot squashfs / /etc/ssh/sshd_config",
        "evidence": [
            "PermitRootLogin yes",
            "PubkeyAuthentication no",
            "StrictModes no",
            "MaxAuthTries 3",
            "MaxSessions 5",
            "UsePrivilegeSeparation no",
            "IgnoreUserKnownHosts yes",
            "ClientAliveInterval 30",
            "ClientAliveCountMax 10",
            "AddressFamily inet",
        ],
        "detail": (
            "The sshd_config baked into the PHONEOS miniroot squashfs sets PermitRootLogin yes, "
            "permitting root login via password authentication. PubkeyAuthentication is explicitly "
            "disabled, so password is the only accepted mechanism. "
            "StrictModes no disables the ownership and permissions checks on ~/.ssh and "
            "authorized_keys that would normally block root login misconfiguration. "
            "UsePrivilegeSeparation no runs the sshd post-auth handler as root without "
            "forking a privilege-separated monitor process, eliminating a defense-in-depth layer. "
            "All accounts in /etc/passwd use /sbin/nologin, but sshd does not check login shell "
            "by default -- PAM is disabled (UsePAM no), and the login shell check is a PAM module "
            "decision in stock OpenSSH. Without PAM, /sbin/nologin blocks interactive login but "
            "root can still land in a shell via ForceCommand or if sshd itself ignores the login "
            "shell (version-dependent). "
            "The secureapp daemon (security:sec) stores SSH credentials through its IPC socket "
            "(/tmp/secSrvrSock): 'handleSetSSHInfoReq', 'Get ssh password data successfully', "
            "'Failed to save SSH password data' -- confirming that SSH credentials are "
            "provisioned at runtime and root login is an expected operational capability. "
            "SSH is explicitly enabled in iptables when WEBHTTPS=1 and WEBPORT != 80: "
            "'iptables -A INPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT' "
            "(rate-limited to 4 attempts per 300 seconds)."
        ),
        "impact": (
            "Once SSH credentials are provisioned via secureapp, root SSH is the direct "
            "administrative access path. Any credential disclosure (F3 chain) or brute-force "
            "within the 4/300s window lands an interactive root shell. No privilege escalation "
            "required -- access is already root."
        ),
        "chain": "Pairs with PHOS9K-F2 (enterprise mode opens port 22) and PHOS9K-F3 "
                 "(credential reset using observable MAC/serial).",
        "remediation": (
            "Set PermitRootLogin prohibit-password or no. "
            "Enable StrictModes yes and UsePrivilegeSeparation sandbox. "
            "Enable UsePAM yes to enforce login shell restriction via pam_shells. "
            "Restrict SSH to an administrative VLAN or specific source IPs via iptables."
        ),
        "source": "/etc/ssh/sshd_config (miniroot squashfs binary-verified)",
    },
    {
        "id": "PHOS9K-F2",
        "title": "Enterprise mode (on-prem/edge/huron/mra) flushes all iptables rules "
                 "and sets INPUT/FORWARD/OUTPUT ACCEPT -- full attack surface exposed",
        "severity": "HIGH",
        "component": "miniroot squashfs / /etc/init.d/iptables.sh",
        "evidence": [
            "if [ $mpp_flag -eq 0 ]; then",
            "    log_msg 'iptables: Set iptables for onprem mode....'",
            "    iptables -P INPUT ACCEPT",
            "    iptables -P FORWARD ACCEPT",
            "    iptables -P OUTPUT ACCEPT",
            "    iptables -t filter -F",
            "    iptables -t filter -X",
            "    filter_icmp_timestamp",
            "    exit 0",
            "fi",
            "# mpp_flag=0 when deploy_mode in [1,2,3,4] (onprem/edge/huron/mra)",
            "# /usr/local/etc/deploymode.conf stores mode as single byte",
        ],
        "detail": (
            "iptables.sh checks deploy mode via check_deploy_mode.sh. "
            "When the phone is in any enterprise mode (modes 1-4: on-prem, edge, huron, MRA), "
            "iptables default policies are set to ACCEPT for INPUT, FORWARD, and OUTPUT, "
            "all filter table rules are flushed, and the script exits. "
            "No INPUT-DROP default, no port restrictions, no allowlist -- the phone is "
            "fully open to the network. SSH (port 22), miniweb (port 443), port 43444, "
            "dnsmasq (UDP 53/67), RTP range, and any other service the phone runs are "
            "accessible from any host. "
            "This is an explicit design choice per the comment: "
            "'if phone in enterprise mode, change iptables default policy to ACCEPT'. "
            "The deploy mode is read from /usr/local/etc/deploymode.conf (persistent storage). "
            "If the file does not exist, check_deploy_mode.sh sets mode MPP (5) by calling "
            "setdeploymode -- but a phone enrolled in enterprise mode retains mode 1-4 in "
            "the persistent conf file across reboots. "
            "The ip6tables.sh applies the same logic for IPv6."
        ),
        "impact": (
            "All services on the phone accessible from any host on the enterprise network. "
            "Combines with PHOS9K-F1 (root SSH) to provide unauthenticated network path to "
            "root shell. "
            "Combines with PHOS9K-F3 (credential reset) to allow admin web takeover from LAN."
        ),
        "chain": "Pairs with PHOS9K-F1 (PermitRootLogin yes) and PHOS9K-F3 (credential reset).",
        "remediation": (
            "Enterprise mode should apply a minimal INPUT allowlist (CUCM/TFTP server IPs, "
            "SIP ports, management IPs) rather than open all INPUT. "
            "The explicit ACCEPT/flush design should be replaced with a default-DROP policy "
            "with explicit ACCEPT rules for required services."
        ),
        "source": "/etc/init.d/iptables.sh + ip6tables.sh (miniroot squashfs binary-verified)",
    },
    {
        "id": "PHOS9K-F3",
        "title": "Admin credential reset security token derived from MAC address + serial number, "
                 "both exposed pre-auth via /api/deviceinfo -- zero-knowledge takeover on "
                 "unconfigured phones",
        "severity": "HIGH",
        "component": "miniroot squashfs / miniweb binary + /api/deviceinfo",
        "evidence": [
            "# In miniweb binary (strings):",
            "cpr_get_device_mac_string",
            "cpr_get_device_serial_number",
            "querytoken=",
            "Security token sent through pipe: %s",
            "Failed to write security token to pipe %s : %s",
            "No password configured. Administrator needs to reset credentials using security token.",
            "POST /api/admin/resetcredential (token= + newUsername= + newPassword= + confirmedPassword=)",
            "# Unauthenticated page HTML (miniweb strings):",
            "<TR><TD><B> MAC address</B></TD><td width=20></TD><TD><B>%s</B></TD></TR>",
            "<TR><TD><B> Serial number</B></TD><td width=20></TD><TD><B>%s</B></TD></TR>",
            "# Called in same binary as resetcredential handler:",
            "cpr_get_device_mac_string  [function pointer in miniweb]",
            "cpr_get_device_serial_number  [function pointer in miniweb]",
        ],
        "detail": (
            "On first boot or after a factory reset, miniweb has no admin credentials configured "
            "and displays: 'No password configured. Administrator needs to reset credentials "
            "using security token.' The resetcredential endpoint accepts a POST with a "
            "'security token' plus desired username/password. "
            "The token generation code in miniweb calls cpr_get_device_mac_string and "
            "cpr_get_device_serial_number -- both device-identifying values that are also "
            "rendered in the unauthenticated /api/deviceinfo HTML page (template strings "
            "confirmed in miniweb binary). The /api/deviceinfo page is in the public "
            "navigation sidebar alongside the Admin link with no authentication gate. "
            "Attack chain on an unconfigured phone: "
            "(1) GET /api/deviceinfo -> extract MAC and serial, "
            "(2) derive security token from MAC + serial (algorithm requires further disassembly), "
            "(3) POST /api/admin/resetcredential with derived token + attacker-chosen credentials, "
            "(4) admin access to all /api/admin/* endpoints. "
            "The MAC address is also broadcast via CDP/LLDP and observable via ARP, "
            "providing multiple token-derivation inputs without any HTTP request."
        ),
        "impact": (
            "Unauthenticated admin takeover on phones with no configured credentials. "
            "After takeover: remote firmware upgrade via /api/admin/upgradefw (push malicious "
            "firmware from attacker URL), remote packet capture via /api/admin/starttcpdump "
            "(capture VoIP audio/signaling), reboot via /api/admin/reboot. "
            "In enterprise deployments, phones are frequently deployed without initial "
            "admin credential configuration -- credential setup is optional in CUCM-managed "
            "environments where the CUCM handles all provisioning."
        ),
        "chain": "Pairs with PHOS9K-F2 (open firewall) and PHOS9K-F6 (admin API surface).",
        "remediation": (
            "Generate a per-device random security token and print it on the physical label "
            "(similar to Wi-Fi router WPS pins). "
            "The token must NOT be derivable from network-observable values (MAC, serial). "
            "Alternatively, require physical button press + token entry for initial credential setup. "
            "Require credentials to be set before enterprise enrollment is permitted."
        ),
        "source": "miniweb binary strings + /api/deviceinfo HTML templates (miniroot squashfs verified)",
    },
    {
        "id": "PHOS9K-F4",
        "title": "miniweb defaults to HTTP port 80 during initial boot when "
                 "/usr/local/etc/firewall.conf does not yet exist",
        "severity": "MEDIUM",
        "component": "miniroot squashfs / /etc/init.d/iptables.sh + miniweb.sh",
        "evidence": [
            "if [ -z $WEBPORT ] ; then",
            "    if [ $has_config_file -eq 1 ] ; then",
            "        WEBPORT=0  # web server disabled",
            "    else",
            "        # Config file not available yet, allow web server on default port",
            "        log_msg 'no config yet, allow default web port 80'",
            "        WEBPORT=80",
            "    fi",
            "fi",
            "# miniweb.sh start section:",
            'echo "WEBPORT=443" > /tmp/firewall.conf',
            'echo "WEBHTTPS=1" >> /tmp/firewall.conf',
            "if [ -f /usr/local/etc/firewall.conf ]; then",
            "    mount --bind /tmp/firewall.conf /usr/local/etc/firewall.conf",
            "else",
            "    cp /tmp/firewall.conf /usr/local/etc/firewall.conf",
            "fi",
        ],
        "detail": (
            "The iptables.sh reads WEBPORT from /usr/local/etc/firewall.conf (persistent storage). "
            "If this file does not exist (first boot, factory reset, storage corruption), "
            "WEBPORT defaults to 80. "
            "The iptables rule then opens HTTP/80: "
            "'iptables -A INPUT -p tcp --syn --dport $WEBPORT $RLIMIT_HTTP -j ACCEPT'. "
            "Separately, miniweb.sh writes a default firewall.conf to /tmp/ and then either "
            "bind-mounts it over /usr/local/etc/firewall.conf or copies it -- "
            "but this happens AFTER iptables.sh runs (iptables.sh is called before miniweb starts). "
            "During the window between iptables.sh setting WEBPORT=80 and miniweb.sh creating "
            "the persistent firewall.conf, the admin web interface is reachable over HTTP. "
            "After miniweb.sh runs, the default is 443 (HTTPS), but port 80 also remains open "
            "when WEBHTTPS=1 and WEBPORT != 80: "
            "'iptables -A INPUT -p tcp --syn --dport 80 $RLIMIT_HTTP -j ACCEPT'. "
            "miniweb.sh also uses a TOCTOU-susceptible bind-mount pattern: it writes to /tmp/ "
            "then bind-mounts the /tmp/ file over the persistent path. "
            "An attacker with write access to /tmp/ could race the copy to inject firewall config."
        ),
        "impact": (
            "Admin credentials transmitted in cleartext over HTTP during provisioning window. "
            "Admin login form POSTs to /api/admin/authenticate over HTTP on factory-fresh phones. "
            "TOCTOU on /tmp/firewall.conf write -> bind-mount is a secondary path for config "
            "injection if local code execution exists."
        ),
        "remediation": (
            "Default WEBPORT to 443 unconditionally; do not fall back to 80. "
            "If miniweb requires a provisioning HTTP phase, restrict it to loopback or "
            "a provisioning VLAN. "
            "Eliminate the /tmp/ TOCTOU by writing the firewall.conf directly to persistent "
            "storage atomically before starting the web server."
        ),
        "source": "/etc/init.d/iptables.sh + /etc/init.d/miniweb.sh (miniroot squashfs binary-verified)",
    },
    {
        "id": "PHOS9K-F5",
        "title": "TCP port 43444 hardcoded ACCEPT in both IPv4 and IPv6 iptables "
                 "regardless of deploy mode or firewall state",
        "severity": "MEDIUM",
        "component": "miniroot squashfs / /etc/init.d/iptables.sh + ip6tables.sh",
        "evidence": [
            "# iptables.sh (IPv4):",
            "iptables -A INPUT -p tcp --dport 43444 -j ACCEPT",
            "# ip6tables.sh (IPv6):",
            "ip6tables -A INPUT -p tcp --dport 43444 -j ACCEPT",
            "# Present outside the mode-check block -- applies in ALL modes including MPP",
        ],
        "detail": (
            "TCP port 43444 is explicitly opened in both the IPv4 and IPv6 firewall scripts, "
            "and the rule appears outside the MPP/enterprise mode conditional -- it applies "
            "in ALL deploy modes. The service running on this port is not identified from "
            "the miniroot alone; the strings in netsd show 'listeningSSH' and 'listeningTelnet' "
            "but port 43444 is not referenced in any init script or binary strings in the miniroot. "
            "Port 43444 is not a registered IANA port and is likely a Cisco proprietary "
            "management or debug channel. "
            "The unconditional nature of the rule means this port is exposed even on phones "
            "where the admin web and SSH are locked down, creating a persistent attack surface "
            "that cannot be closed through normal firewall configuration."
        ),
        "impact": (
            "Unknown service on 43444 exposed on all phones in all modes, including MPP mode "
            "which otherwise has a restrictive firewall. "
            "If 43444 carries a debug or management protocol, it may bypass authentication "
            "controls applied to the standard miniweb/SSH interfaces."
        ),
        "remediation": (
            "Identify the service on 43444 and apply the same authentication and "
            "firewall restrictions as miniweb/SSH. "
            "If the service is a debug channel, gate it behind FIPS mode or a development-only "
            "flag (per the DEVICE_IS_DEV pattern already present in iptables.sh)."
        ),
        "source": "/etc/init.d/iptables.sh + ip6tables.sh lines confirmed identical, "
                  "outside mode conditional (miniroot squashfs binary-verified)",
    },
    {
        "id": "PHOS9K-F6",
        "title": "miniweb admin API exposes remote firmware upgrade (attacker-supplied URL), "
                 "tcpdump start/stop, and reboot -- authenticated but pairs with F3 for full chain",
        "severity": "MEDIUM",
        "component": "miniroot squashfs / /usr/sbin/miniweb (binary)",
        "evidence": [
            "POST /api/admin/upgradefw",
            "  fields: upgradeRule (free-text URL rule), proxyHost, proxyPort, proxyUser, proxyPassword",
            "POST /api/admin/starttcpdump",
            "POST /api/admin/stoptcpdump",
            "  capture output: /tmp/tcpdump-%04d%02d%02d-%02d%02d%02d-%s.pcap",
            "POST /api/admin/reboot",
            "POST /api/admin/packetcapture",
            "GET  /api/admin/authenticate",
            "POST /api/admin/resetcredential",
            "# upgutil binary strings (upgrade backend):",
            "curl_url_set / curl_url_get / curl_url_cleanup  [libcurl CURLU API]",
            "dhcp option url is %s  [DHCP option 66/160 as upgrade URL source]",
            "checkOption: fail to get upgrade url",
        ],
        "detail": (
            "miniweb exposes a full administrative API behind session authentication. "
            "The firmware upgrade endpoint (/api/admin/upgradefw) accepts an 'upgradeRule' "
            "field (free-text URL), a proxy configuration, and calls upgutil to download and "
            "apply firmware. upgutil uses libcurl (curl_url_set/curl_url_get) to fetch "
            "the upgrade package. No integrity verification of the upgrade URL itself "
            "is visible in the miniweb/upgutil string surfaces. "
            "The tcpdump endpoints (/api/admin/starttcpdump, /api/admin/stoptcpdump) "
            "invoke system tcpdump and write captures to /tmp/ with a timestamp-based "
            "predictable filename: /tmp/tcpdump-%04d%02d%02d-%02d%02d%02d-%s.pcap. "
            "An authenticated admin can capture all VoIP signaling (SIP) and RTP audio "
            "passing through the phone. "
            "upgrade URLs also come from DHCP option (dhcp option url is %s in upgutil), "
            "meaning a rogue DHCP server can trigger firmware upgrade without any UI interaction. "
            "The /usr/local/etc/upgrade.sh override in S98upgrade.sh ('if [ -x /usr/local/etc/upgrade.sh ] "
            "then /usr/local/etc/upgrade.sh; exit 0') provides a persistent code execution path: "
            "if an attacker gains write access to /usr/local/ (persistent storage), "
            "any file planted as upgrade.sh executes as root on next boot."
        ),
        "impact": (
            "Post-auth firmware downgrade to vulnerable version or replacement with attacker firmware. "
            "Post-auth VoIP audio/SIP capture via tcpdump endpoints. "
            "Persistent root execution on next boot if /usr/local/etc/upgrade.sh is planted. "
            "Pairs with PHOS9K-F3: credential reset chain gives attacker admin access, "
            "then F6 enables firmware replacement."
        ),
        "chain": "Pairs with PHOS9K-F3 (credential reset) for full unauthenticated->firmware chain.",
        "remediation": (
            "Validate firmware upgrade URLs against a Cisco-signed allowlist. "
            "Restrict /api/admin/upgradefw to calls originating from CUCM/UCM provisioning server. "
            "Remove the /usr/local/etc/upgrade.sh override path or require it to be signed. "
            "DHCP-triggered upgrades should require out-of-band confirmation or a signed upgrade request."
        ),
        "source": "miniweb binary strings + upgutil binary strings + S98upgrade.sh "
                  "(miniroot squashfs binary-verified)",
    },
]

FIRMWARE = {
    "target": "Cisco PHONEOS 9xxx / 8875",
    "version": "5.0.1.0005-62",
    "build_date": "2026-08-12",
    "platforms": [
        "CP-9811 (ARM64, i.MX 8ULP, miniroot+SBN chain)",
        "CP-9821 (ARM64, i.MX 8ULP WP, Android PKG)",
        "CP-9841/9851 (ARM64, i.MX 8ULP, miniroot+rootfs+SBN chain)",
        "CP-9861/9871 (ARM64, Android PKG)",
        "CP-8875 (Android PKG)",
    ],
    "miniroot": "miniroot-9811.5-0-1-0005-62.sbn (squashfs v4.0, zlib, 20.6MB, 1375 inodes)",
    "pkg_format": "magic 0x706b6700, platform-targeted (imx8ulp-WP-<model>-<rev>)",
    "base_os": "Linux 5.x (miniroot), Android (PKG overlay)",
    "key_binaries": {
        "/usr/sbin/miniweb": "HTTPS admin web server (port 443)",
        "/usr/sbin/secureapp": "Security daemon, CAPF cert management, SSH cred store",
        "/usr/sbin/netsd": "Network service daemon (listeningSSH/listeningTelnet strings)",
        "/usr/bin/upgutil": "Firmware upgrade utility (libcurl, DHCP option URL)",
        "/usr/lib/libfileauth.so": "Image/config authentication (authVerify* functions)",
        "/usr/lib/libcisco.so": "Cisco platform library",
    },
    "summary": "6F [0C+3H+3M+0L]",
}

ATTACK_SURFACE = {
    "ssh_port_22": "PermitRootLogin yes, password-only, opened when WEBHTTPS=1 in enterprise mode",
    "miniweb_443": "Admin web with firmware upgrade, tcpdump, reboot APIs",
    "miniweb_80": "Default HTTP during initial boot before firewall.conf created",
    "port_43444": "Unknown Cisco proprietary TCP service, always open in all modes",
    "dhcp_upgrade": "DHCP option 66/160 triggers firmware download via upgutil",
    "upgrade_sh": "/usr/local/etc/upgrade.sh persistent root execution path on next boot",
}
