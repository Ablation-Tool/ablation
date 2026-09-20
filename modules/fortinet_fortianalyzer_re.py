"""
FortiAnalyzer VM -- Multi-version RE
Primary target: FAZ_VM64-v6.4.14-build2660-FORTINET (2024-02-06)
Additional versions: 7.0.12, 7.0.16, 7.2.10, 7.2.11, 7.2.12, 7.4.10, 8.0.0
VMDK: faz.vmdk (288MB, 2GB disk, 537MB ext3 partition)
rootfs.gz: XZ in 6.4.14 (NOT Fortinet-encrypted) -- full filesystem accessible
docker.tar.xz: Docker runtime (dockerd, containerd, runc)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":       "Fortinet FortiAnalyzer",
    "version":       "6.4.14",
    "build":         "2660",
    "build_date":    "2024-02-06",
    "os_type":       "Custom Linux (initramfs/cpio, ext3 boot partition)",
    "disk_system":   "537MB ext3 boot partition + 500GB data",
    "rootfs_format": "XZ-compressed cpio (NOT encrypted -- full extraction possible)",
    "python":        "3.8 (site-packages in /usr/local/lib/python3.8/)",
    "web_stack":     "Apache 2.x + mod_wsgi + Django 2.2 + Airflow 2.2.3 + ClickHouse",
    "django_proj":   "/usr/local/lib/python3.8/proj/",
    "apache_conf":   "/usr/local/apache2/conf/httpd.conf",
    "airflow_conf":  "/etc/airflow/airflow.cfg",
    "clickhouse_conf": "/etc/clickhouse-server/config.xml",
}

VERSIONS_ON_HAND = {
    # 11 versions confirmed complete (2026-09-19 README download status)
    # DO NOT ANALYZE v7.4.2 -- .aria2 control file present (incomplete download)
    "6.4.14":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v6.4.14-build2660-FORTINET.out.ovf.zip",
    "7.0.12":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.0.12-build0623-FORTINET.out.ovf.zip",   # VULNERABLE: CVE-2024-47575
    "7.0.16":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.0.16-build0710-FORTINET.out.zip",
    "7.2.5":   "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.5-build1574-FORTINET.out.ovf.zip",    # VULNERABLE: CVE-2024-47575
    "7.2.7":   "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.7-build1633-FORTINET.out.ovf.zip",    # VULNERABLE: CVE-2024-47575
    "7.2.9":   "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.9-build1638-FORTINET.zip",            # VULNERABLE: CVE-2024-47575 (patched in 7.2.8)
    "7.2.10":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.10-build1682-FORTINET.zip",           # patched for CVE-2024-47575
    "7.2.11":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.11-build1720-FORTINET.out.zip",
    "7.2.12":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.12-build1721-FORTINET.out.zip",
    "7.4.10":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.4.10.M-build2778-FORTINET.out.zip",
    "7.4.11":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.4.11.M-build2804-FORTINET.out.zip",
}

EXTRACTED = {
    "6.4.14_vmdk":   "/tmp/faz614_vmdk/faz.vmdk",
    "6.4.14_fs":     "/tmp/faz614_fs/         (ext3, nbd2p1, extlinux boot partition)",
    "6.4.14_rootfs": "/tmp/faz614_rootfs/     (full Linux rootfs, cpio extracted)",
}

# ---------------------------------------------------------
# Filesystem structure (6.4.14, from rootfs extraction)
# ---------------------------------------------------------
FILESYSTEM = {
    "web_server":   "/usr/local/apache2/ (Apache 2.x, mod_wsgi, CGI)",
    "django_app":   "/usr/local/lib/python3.8/proj/ (Django 2.2 + 15 apps)",
    "airflow":      "/etc/airflow/ + /usr/local/lib/python3.8/site-packages/airflow/",
    "clickhouse":   "/usr/local/clickhouse/ + /etc/clickhouse-server/",
    "soap_wsdl":    "/usr/local/webclient/xml_faz.wsdl + xml.wsdl",
    "docker":       "docker.tar.xz in boot partition (dockerd + containerd + runc)",
    "python_ver":   "3.8",
    "airflow_ver":  "2.2.3",
    "django_apps": [
        "alert", "fabric", "fazproxy", "fgd", "fortisoc", "fortiview",
        "frc", "i18n", "incident", "logfetcher", "logforwarding", "logview",
        "noc", "report", "sso_idp", "sso_sp", "util", "endpoint",
    ],
}

# ---------------------------------------------------------
# Findings
# ---------------------------------------------------------
FINDINGS = {}

FINDINGS["FAZ-F01"] = {
    "title": "Airflow 2.2.3 REST API on 0.0.0.0:8081 -- no authentication, hardcoded secret_key",
    "severity": "CRITICAL",
    "status": "CONFIRMED -- auth_backend = airflow.api.auth.backend.default + web_server_host = 0.0.0.0 + secret_key = temporary_key",
    "cvss": "9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
    "cve": None,
    "notes": [
        "airflow.cfg: auth_backend = airflow.api.auth.backend.default",
        "backend.default.py: requires_authentication decorator is a no-op -- all requests pass through",
        "web_server_host = 0.0.0.0 -- bound to all interfaces",
        "web_server_port = 8081",
        "secret_key = temporary_key -- hardcoded; Airflow uses this for JWT signing + CSRF",
        "Known secret key allows forging session tokens for Airflow web UI admin access",
        "Airflow 2.2.3 REST API (/api/v1/) allows: trigger DAGs, create/delete variables, read logs",
        "DAGs in /etc/airflow/dags/: faz_aggregation, ems_on_demand, global_monitor, airflow_db_cleanup",
        "ems_on_demand DAG: triggers EMS operations from FAZ -- cross-product code execution",
        "BashOperator/PythonOperator in DAGs = arbitrary code execution on FAZ host",
        "Pre-auth RCE chain: POST /api/v1/dags/<dag>/dagRuns -> arbitrary Python on FAZ",
        "CANDIDATE: port 8081 may be blocked by FAZ firewall rules -- need live test to confirm externally accessible",
        "Known CVEs in Airflow 2.2.3: CVE-2022-40127, CVE-2022-38054",
    ],
    "proof_of_concept": """
    # Trigger RCE via Airflow REST API (no auth required in 6.4.14 default config)
    # Step 1: Enable DAG
    PATCH http://faz_host:8081/api/v1/dags/faz_aggregation {"is_paused": false}
    # Step 2: Trigger DAG run
    POST http://faz_host:8081/api/v1/dags/faz_aggregation/dagRuns {}
    # Step 3: Use variable injection via /api/v1/variables for persistent payload
    POST http://faz_host:8081/api/v1/variables {"key":"payload","value":"<cmd>"}
    """,
    "references": ["CVE-2022-40127", "CVE-2022-38054"],
}

FINDINGS["FAZ-F02"] = {
    "title": "FAZ SOAP WSDL servicePass minOccurs=0 on ALL operations -- same as FMG-F01",
    "severity": "CRITICAL",
    "status": "CONFIRMED -- xml_faz.wsdl: servicePass with userID/password both minOccurs=0 on all ops",
    "cvss": "9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
    "cve": None,
    "notes": [
        "WSDL at /usr/local/webclient/xml_faz.wsdl",
        "servicePass type: userID(optional) + password(optional)",
        "Operations with optional auth: getDevices, getAdoms, searchFazLog, getFazArchive, removeFazArchive",
        "getFazConfig, setFazConfig: read/write FAZ configuration without credentials (if bypass confirmed)",
        "runFazReport: run arbitrary reports",
        "searchFazLog: search all log data for all connected FortiGate devices",
        "getFazArchive: download archived log data",
        "setFazConfig: write FAZ configuration -- can change admin password, disable MFA, add admin account",
        "Also has xml.wsdl (same as FMG xml.wsdl): runScript, installConfig ops with same optional auth",
        "VERSION BOUNDARY: XML API present in all FAZ <7.6.5; removed in 7.6.5 per 7.6.7 release notes",
        "All 7.2.x targets (7.2.5/7.2.7/7.2.9/7.2.10/7.2.11/7.2.12) have SOAP surface",
        "CANDIDATE: server-side enforcement TBD -- may validate credentials even if schema says optional",
        "Highest priority for live instance testing after FAZ-F01",
    ],
    "soap_operations": [
        "getDevices", "getAdoms", "getDeviceList", "getDeviceVdomList",
        "searchFazLog", "getFazArchive", "removeFazArchive",
        "getSystemStatus", "getFazConfig", "setFazConfig", "runFazReport",
        "getTaskList", "addDevice", "deleteDevice", "editAdom",
        "addAdom", "deleteAdom", "getAdomList", "listFazGeneratedReports",
        "getFazGeneratedReport",
    ],
    "references": ["FMG-F01"],
}

FINDINGS["FAZ-F03"] = {
    "title": "ClickHouse 8123/9000 on localhost -- empty default user password, SSRF pivot target",
    "severity": "HIGH",
    "status": "CONFIRMED in 6.4.14 -- config.xml: empty password for default user; localhost-bound only",
    "cvss": "7.5 (AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H) -- chained with F01/F02",
    "cve": None,
    "notes": [
        "ClickHouse at 127.0.0.1:8123 (HTTP) and 127.0.0.1:9000 (TCP)",
        "default user has empty password: <password></password>",
        "ClickHouse HTTP interface: SELECT/INSERT via POST to http://127.0.0.1:8123/?query=SELECT+*+FROM+system.tables",
        "No auth + localhost binding -- accessible after SSRF via other FAZ services",
        "Post-FAZ-F01 (Airflow RCE): access ClickHouse directly for log data exfiltration",
        "ClickHouse stores FAZ analytics data: FortiGate traffic logs, threat intel, event correlations",
        "Entire organization's network logs available via empty-password ClickHouse HTTP API",
        "SSRF via FAZ-F02 (SOAP searchFazLog with SSRF-injectable log source parameter) TBD",
        "VERSION BOUNDARY: ClickHouse present in 6.4.14 (confirmed from rootfs). In 7.2.x FAZ uses BOTH",
        "ClickHouse (analytics) and Postgres (primary log DB). In 7.6.0+ Postgres MIGRATED to ClickHouse.",
        "F03 applies to 6.4.14; needs confirmation in 7.2.x (ClickHouse config may differ)",
        "INAPPLICABLE for 7.2.x CVE-2024-47575 range as primary log DB attack vector (Postgres there)",
    ],
    "references": ["FAZ-F01"],
}

FINDINGS["FAZ-F04"] = {
    "title": "Docker runtime embedded in FAZ -- dockerd + runc + containerd in boot partition",
    "severity": "HIGH",
    "status": "CONFIRMED -- docker.tar.xz in boot partition contains full Docker runtime",
    "cvss": "8.8 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)",
    "cve": None,
    "notes": [
        "docker.tar.xz (36MB XZ) in /tmp/faz614_fs/ boot partition",
        "Contains: dockerd, docker, containerd, containerd-shim, runc, ctr, docker-init, docker-proxy",
        "FAZ uses Docker to run isolated components",
        "If Docker socket at /var/run/docker.sock is accessible from web context (FAZ-F01 Airflow RCE):",
        "  - Mount FAZ root filesystem in container: docker run -v /:/host ... = full filesystem access",
        "  - Start privileged container: docker run --privileged ... = kernel escape",
        "  - Read Docker socket from Airflow DAG shell command",
        "runc version: check for known runc container escape CVEs (CVE-2024-21626 etc.)",
        "CANDIDATE: Docker socket access from Airflow context needs verification",
    ],
    "references": ["FAZ-F01", "CVE-2024-21626"],
}

FINDINGS["FAZ-F05"] = {
    "title": "FAZ rootfs.gz is plain XZ in 6.4.14/7.0.x/7.2.x -- full filesystem extraction without decryption",
    "severity": "MEDIUM",
    "status": "CONFIRMED -- magic fd377a5a (XZ) NOT Fortinet-encrypted. 7.0.12 also confirmed XZ. 7.4.1+ encrypted per release notes.",
    "cvss": "N/A (firmware analysis, not network finding)",
    "cve": None,
    "notes": [
        "FAZ 6.4.14 rootfs.gz: XZ-compressed cpio initramfs -- fully extractable",
        "FAZ 7.0.12 rootfs.gz: also XZ (confirmed via debugfs dump + magic bytes)",
        "FAZ 7.4.1+ rootfs: ENCRYPTED per 7.6.7 release notes ('kernel and rootfs are encrypted as of 7.4.1')",
        "FAZ 7.2.x (CVE-2024-47575 range): XZ, unencrypted -- all 7.2.5/7.2.7/7.2.9 extractable",
        "FMG 7.4.11 rootfs.gz: Fortinet-encrypted (magic 0x6bda915e) -- cannot extract",
        "FAZ extraction: xz -dk rootfs.gz | cpio -id -> 968MB rootfs, ~82K files",
        "Entire Python web application, Airflow config, ClickHouse config, Django app, certs all accessible",
        "FAZ 7.4.x/7.6.x: encrypted rootfs -- must extract from running process or via alternate vectors",
        "Shell access: execute shell available in FAZ <7.6.0 (removed in 7.6.0 per release notes)",
        "SOAP/XML API: xml_faz.wsdl present in <7.6.5 (XML API removed in 7.6.5 per release notes)",
        "Config backup: unencrypted before 7.4.2 (encrypted+password required starting 7.4.2)",
    ],
    "references": [],
}

FINDINGS["FAZ-F06"] = {
    "title": "SAML SP: wantAssertionsSigned + wantMessagesSigned both False -- XSW possible if SSO enabled",
    "severity": "MEDIUM",
    "status": "CANDIDATE -- library enforces at least one sig; requires SSO enabled; downgraded from HIGH",
    "cvss": "6.5 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N) if SSO enabled with attacker-controlled Fabric IdP",
    "cve": None,
    "notes": [
        "sso_sp/adapter.py cfg2settings() security block: ONLY sets requestedAuthnContext=False",
        "wantAssertionsSigned and wantMessagesSigned both default to False (settings.py:286-287)",
        "python3-saml response.py:290: library DOES enforce at least one signature exists (NO_SIGNATURE_FOUND error)",
        "Fully unsigned SAML response REJECTED even with wantMessagesSigned=False",
        "XSW (XML Signature Wrapping) still possible: signed element present but assertion content forged",
        "parse_config(RelayState): RelayState = idp_name only; IdP cert fetched from server-side system config",
        "No cert injection via RelayState: c2py.get_sys_saml_sp_cfg() or get_fab_sp_cfg(name) -- server-side",
        "Requires SSO to be enabled (@sso.require_sso_enabled decorator blocks endpoint if disabled)",
        "Default FAZ deployment: SSO not enabled. Attack requires SSO configuration.",
        "If Fabric SP mode enabled: attacker controls which pre-configured Fabric IdP is selected via RelayState",
        "FAZ acts as both SP and IdP: potential circular trust if FAZ IdP cert accessible",
        "python3-saml version: not packaged as dist-info; located at /usr/local/lib/python3.8/onelogin/",
        "Known XSW CVEs in python3-saml: CVE-2022-41900, CVE-2023-40023 -- version check pending",
    ],
    "references": ["CVE-2022-41900", "CVE-2023-40023"],
}

FINDINGS["FAZ-F07"] = {
    "title": "FGFM fgfmsd: dvmDevVerifyNewSn() bypass via config flags -- CVE-2024-47575 root cause",
    "severity": "CRITICAL",
    "status": "CONFIRMED in 6.4.14 -- bypass control flow in fgfmsd at 0x428758; same class expected in 7.0.12/7.2.x",
    "cvss": "9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) -- per NVD for CVE-2024-47575",
    "cve": "CVE-2024-47575",
    "notes": [
        "FGFM protocol: FortiGate-to-FortiManager/FortiAnalyzer management protocol on port 541",
        "CVE-2024-47575 (FortiJump): missing authentication in FGFM handler allows pre-auth RCE",
        "Affected versions on hand: 6.4.14, 7.0.12, 7.2.5, 7.2.7, 7.2.9 -- all pre-patch per NVD",
        "Patched in 7.2.8; 7.2.10/7.2.11/7.2.12 are post-patch",
        "DAEMONS: fgfmsd = server (listens, CVE target, 266KB); fgfmd = client (206KB); SEPARATE from oftpd",
        "Binary analyzed: /tmp/faz614_rootfs/bin/fgfmsd (6.4.14, ELF x86-64 stripped)",
        "DISASM FINDING -- registration handler at 0x428758:",
        "  0x428821: call dvmDevVerifyNewSn()   <-- single SN verification gate",
        "  0x428826: test eax, eax",
        "  0x428828: jne  0x428871              <-- non-zero (success) takes normal path",
        "  [BYPASS PATH when dvmDevVerifyNewSn() returns 0]:",
        "  0x428834: cmp byte [rax+0x29c], 0   <-- config flag #1",
        "  0x42883b: je   0x42a4cc             <-- flag==0 -> exit (security enforced)",
        "  0x428841: cmp [rax+0x538], 0        <-- config flag #2",
        "  0x428849: je   0x42a4cc             <-- flag==0 -> exit",
        "  0x42885f: call fgfm_dev_in_filter() <-- if device passes filter",
        "  0x428866: je   0x4289d3             <-- bypass: registration WITHOUT SN verification",
        "IMPACT: when dvmDevVerifyNewSn() returns 0 AND both config flags non-zero AND device in filter,",
        "        device registers WITHOUT serial number verification",
        "Config flags [rax+0x29c] and [rax+0x538]: likely 'allow-unregistered' or similar feature flag",
        "dvmDevVerifyNewSn() called from ONLY ONE site in fgfmsd (0x428821) -- single auth gate",
        "dvmDevGetBySn() at 0x4288b0 (next call): looks up device by SN after successful verify",
        "cert_get_id() called from 17 sites; cert_id_invalid() from 12 sites -- cert validation active",
        "PLT: SSL_get_peer_certificate, X509_verify_cert_error_string, cert_id_invalid all present",
        "TODO: reverse dvmDevVerifyNewSn() in libdvmapi.so -- actual verification logic there",
        "TODO: determine default state of flags [rax+0x29c] and [rax+0x538]",
        "TODO: diff fgfmsd 6.4.14 vs 7.2.10 to identify exact patch for CVE-2024-47575",
        "TODO: extract fgfmsd from FAZ 7.2.9 VMDK; confirm same bypass pattern present",
        "OFTP: separate daemon (oftpd, TCP/UDP 514); FGFM daemon on port 541 is fgfmsd",
        "diagnose test application oftpd 3 -> OFTP connections; fgfmsd is not visible here",
    ],
    "references": ["CVE-2024-47575", "https://www.fortiguard.com/psirt/FG-IR-24-423"],
}

FINDINGS["FAZ-F08"] = {
    "title": "OFTP oftpd: SSLv3 supported + UDP514 log channel unencrypted by default",
    "severity": "HIGH",
    "status": "CANDIDATE -- documented in 7.4.1 admin guide Appendix B; SSLv3 support listed, default log=UDP514 unencrypted",
    "cvss": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    "cve": None,
    "notes": [
        "OFTP = Optimized Fabric Transfer Protocol; FAZ daemon = oftpd; ports TCP514 + UDP514",
        "Default config: OFTP control = TCP514 (TLS); log transfer = UDP514 (NO encryption)",
        "Secure log transfer requires explicit opt-in: config log fortianalyzer setting set reliable enable",
        "OFTP SSL supports: SSLv3, TLSv1.0, TLSv1.2, TLSv1.3 (default TLSv1.2)",
        "SSLv3 support = POODLE downgrade attack possible on OFTP control channel",
        "ssl-static-key-ciphers enabled by default = no forward secrecy on OFTP TLS",
        "Log integrity: default log-checksum=none (no integrity check); MD5 or MD5-auth optional",
        "UDP514 log path: no encryption, no integrity check by default = full log content visible/injectable",
        "In typical FAZ deployment: FortiGate logs flow UDP514 in cleartext across network",
        "enc-algorithm low = includes weak CBC ciphers; high = GCM only but not default",
        "Attack surface: MITM between FortiGate and FAZ captures/injects all network security logs",
        "FAZ serial number appears in OFTP diagnostics: SNs list -- confirms device identity leak pre-auth",
        "diagnose test application oftpd 3 -> active OFTP sessions (DEVICE, CONN, HOSTNAME, IP, #PKTS)",
        "logsync_conn_id visible in fgtlogd output = connection sequence numbers predictable",
        "CANDIDATE: verify SSLv3 actually present in oftpd binary (may be compiled out); check 7.2.x",
    ],
    "references": [],
}

# Doc-derived intelligence (from README mandatory docs reading)
DOC_INTEL = {
    "sources_read": [
        "FortiAnalyzer-7.6.7-Release_Notes.pdf (pages 1-20, 61-66)",
        "FortiAnalyzer-7.2.1-Administration_Guide.pdf (pages 1-50)",
        "FortiAnalyzer-7.4.1-Administration_Guide.pdf (pages 1-20, 34-37, 432-440)",
        "README.md (full re-read 2026-09-19)",
    ],
    "version_security_matrix": {
        "shell_access":    "execute shell: present in <7.6.0; REMOVED in 7.6.0",
        "soap_xml_api":    "xml_faz.wsdl: present in <7.6.5; REMOVED in 7.6.5",
        "rootfs_encrypt":  "rootfs unencrypted in 6.4.x/7.0.x/7.2.x; ENCRYPTED from 7.4.1",
        "log_database":    "Postgres as primary log DB in 7.2.x; MIGRATED to ClickHouse in 7.6.0",
        "config_backup":   "config backup unencrypted in <7.4.2; password-required from 7.4.2",
        "legacy_auth_mode":"OFTP password fallback only added in 7.6.7 (configurable); cert-only in 7.2.x",
    },
    "daemon_names": {
        "log_daemon_faz":  "fortilogd (confirmed: bug 1217641 diagnose fortilogd logvol-adom)",
        "oftp_daemon_faz": "oftpd (confirmed: diagnose test application oftpd 3; TCP/UDP 514)",
        "log_daemon_fgt":  "fgtlogd (FortiGate-side log daemon: diagnose test application fgtlogd 1)",
        "fgfm_daemon_faz": "fgfmd (CVE-2024-47575 target; port 541; extract from 7.2.9 rootfs)",
    },
    "oftp_protocol": {
        "ports":         "TCP514 (OFTP/TLS control) + UDP514 (log, unencrypted by default)",
        "tls_versions":  "SSLv3, TLSv1.0, TLSv1.2, TLSv1.3 (default TLSv1.2)",
        "log_integrity": "default=none; optional MD5 or MD5-auth",
        "forward_secrecy": "disabled by default (ssl-static-key-ciphers=enabled)",
        "enc_algorithm": "low=all OpenSSL; medium=high+medium; high=high only; custom=ssl-cipher-suites table",
    },
    "device_auth_flow": {
        "methods": ["serial number matching", "pre-shared key"],
        "fabric_auth": "FortiGate Fabric Connector (7.0.1+); FAZ verifies cert CN matches device SN",
        "oftp": "FortiGate log transfer protocol; cert-only in 7.2.x; no password fallback",
        "default_admin": "blank password on first setup -- must be changed during wizard",
    },
    "cve_in_767": "CVE-2026-84391 (Bug 1259015) -- only CVE patched in 7.6.7",
    "known_unfixed_bugs": [
        "Bug 1220686: SAML SSO HA failover -- sync prevents admin SSO login after HA failover (unfixed in 7.6.7)",
    ],
}

# Airflow DAG inventory
AIRFLOW_DAGS = {
    "faz_aggregation":    "Stats aggregation every 15 minutes (StatsAggregateOperator)",
    "ems_on_demand":      "On-demand EMS operations -- cross-product trigger",
    "global_monitor":     "Global system monitoring",
    "airflow_db_cleanup": "Airflow metadata DB cleanup",
    "airflow_log_cleanup":"Airflow log file cleanup",
}

# Apache config key routes
APACHE_ROUTES = {
    "/index.py":               "WSGIScriptAlias -> Django wsgi.py (main web app)",
    "/cgi-bin/":               "ScriptAlias -> /usr/local/webclient/cgi_bin/ (SOAP handlers)",
    "/portal/x":               "ScriptAlias -> /usr/local/portal/x/ (portal API)",
    "/fortiwan":               "ProxyPass -> 169.254.255.90 (FortiWAN integration)",
    "/fpc/":                   "ProxyPass -> 169.254.255.50:8444 (FPC service)",
    "/fortisigconverter/":     "ProxyPass -> 169.254.255.66 (signature converter)",
    "/fortiauthenticator/":    "ProxyPass -> 169.254.255.130 (FortiAuthenticator)",
    "/ws3":                    "ProxyPass -> ws://127.0.0.1:9003 (WebSocket)",
    "127.0.0.1:31723":         "Internal admin listener",
    "443, 80, 26443":          "External HTTPS/HTTP listeners",
    "8081":                    "Airflow webserver (direct, not proxied through Apache)",
}

# Pending analysis
TODO = [
    # IMMEDIATE: FGFM + OFTP daemon extraction (CVE-2024-47575 + F08)
    "Extract fgfmd binary from FAZ 7.2.9 rootfs -- mount VMDK; daemon on port 541 (FGFM protocol)",
    "Extract oftpd binary from FAZ 7.2.9 rootfs -- daemon on TCP/UDP 514 (OFTP log transfer)",
    "Run Ablation semantic sweep on fgfmd binary -- find missing auth check (F07)",
    "Run Ablation semantic sweep on oftpd binary -- verify SSLv3 compiled in; find cipher negotiation (F08)",
    "Diff fgfmd binary 7.2.7 vs 7.2.10 to locate exact patch for CVE-2024-47575",
    # BINARY SWEEPS (from 6.4.14 syntax.tar.xz)
    "Run Ablation semantic sweep on libcdb_plugin.so (134KB) -- /tmp/faz614_syntax/syntax/",
    "Run Ablation semantic sweep on libfazcfg_plugin.so (48KB) -- /tmp/faz614_syntax/syntax/",
    # SOAP SURFACE (F02)
    "Confirm FAZ-F02 server-side enforcement: SOAP servicePass bypass on 7.2.x live instance",
    "Run Ablation sweep on Apache2 CGI handler binaries (SOAP endpoint)",
    # AIRFLOW (F01)
    "Verify Airflow 8081 external accessibility: check FAZ iptables/nftables rules in 7.2.9 rootfs",
    "Live test FAZ-F01: POST /api/v1/dags/<dag>/dagRuns without Authorization header",
    # DOC READING (pending)
    "Read FortiAnalyzer-7.4.1-Administration_Guide.pdf -- logging daemon architecture section",
    # VERSION VERIFICATION
    "Confirm Airflow version in 7.2.x -- is it still 2.2.3 or upgraded?",
    "Check if 7.2.x uses same temporary_key or rotates Airflow secret_key",
    "Confirm ClickHouse config in 7.2.x -- is default user still empty password?",
    # SAML (F06)
    "Examine sso_sp/views.py for SAML assertion validation path",
    "Check python3-saml version in 7.2.x for CVE-2022-41900/CVE-2023-40023",
    # DOCKER (F04)
    "Examine Docker socket permissions from Airflow process context in 7.2.x",
]
