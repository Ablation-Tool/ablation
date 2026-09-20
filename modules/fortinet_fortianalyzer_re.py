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
    "6.4.14": "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v6.4.14-build2660-FORTINET.out.ovf.zip",
    "7.0.12": "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.0.12-build0623-FORTINET.out.ovf.zip",
    "7.0.16": "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.0.16-build0710-FORTINET.out.zip",
    "7.2.10": "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.10-build1682-FORTINET.zip",
    "7.2.11": "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.11-build1720-FORTINET.out.zip",
    "7.2.12": "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.2.12-build1721-FORTINET.out.zip",
    "7.4.10": "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v7.4.10.M-build2778-FORTINET.out.zip",
    "8.0.0":  "/media/cowboy/research/Fortinet/FortiAnalyzer/FAZ_VM64-v8.0.0.F-build0105-FORTINET.out.zip",
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
    "status": "CONFIRMED -- config.xml: empty password for default user; localhost-bound only",
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
    "title": "FAZ rootfs.gz is plain XZ in 6.4.14 -- full filesystem extraction without decryption",
    "severity": "MEDIUM",
    "status": "CONFIRMED -- magic fd377a5a (XZ) NOT Fortinet-encrypted (contrast: FMG 7.4.11 uses 6bda915e)",
    "cvss": "N/A (firmware analysis, not network finding)",
    "cve": None,
    "notes": [
        "FAZ 6.4.14 rootfs.gz: XZ-compressed cpio initramfs -- fully extractable",
        "FMG 7.4.11 rootfs.gz: Fortinet-encrypted (magic 0x6bda915e) -- cannot extract",
        "FAZ extraction: xz -dk rootfs.gz | cpio -id -> 968MB rootfs, ~82K files",
        "Entire Python web application, Airflow config, ClickHouse config, Django app, certs all accessible",
        "Contrast: FMG 7.x encrypts rootfs; FAZ 6.4.x does NOT -- much larger analysis surface",
        "Need to verify if FAZ 7.x/8.0.0 also encrypts rootfs or continues XZ format",
    ],
    "references": [],
}

FINDINGS["FAZ-F06"] = {
    "title": "Django SSO/SAML SP implementation in FAZ -- potential auth bypass via SAML assertion manipulation",
    "severity": "HIGH",
    "status": "CANDIDATE -- sso_sp Django app present; SAML endpoint at /saml/ and /p/sso_sp/",
    "cvss": "9.1 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N) if SAML bypass confirmed",
    "cve": None,
    "notes": [
        "Django URL conf: path('saml/', sso_sp_views.saml_sp) -- SAML SP endpoint",
        "path('p/sso_sp/', include('sso_sp.urls')) -- SAML SP management",
        "path('p/sso_idp/', include('sso_idp.urls')) -- SAML IdP (FAZ acts as identity provider)",
        "FAZ acts as BOTH SP and IdP -- potential circular trust exploitation",
        "SAML assertion signing validation: check for CVE-2023-40023 pattern (XML signature wrapping)",
        "FAZ also has /p/forticloud_jsonrpc_login/ -- FortiCloud authentication path",
        "Python3.8 + older Django 2.2: check for known SAML library CVEs in python3-saml",
        "TODO: examine sso_sp/views.py for assertion validation logic",
    ],
    "references": ["CVE-2023-40023"],
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
    "Check FAZ 7.x rootfs.gz format -- does it encrypt like FMG 7.x or stay XZ?",
    "Examine sso_sp/views.py for SAML assertion validation (F06)",
    "Verify if Airflow 8081 is externally accessible or firewalled by FAZ netfilter",
    "Live test FAZ-F02: SOAP searchFazLog without servicePass",
    "Live test FAZ-F01: Airflow REST API /api/v1/dags without auth",
    "Compare xml_faz.wsdl across 6.4.14/7.x/8.0.0 to find when auth was added",
    "Run Ablation semantic sweep on Apache2 CGI handler binaries",
    "Check ClickHouse for FAZ log schema -- identify sensitive data stored",
    "Examine Docker socket permissions from Airflow process context",
    "Check if FAZ 7.2.x/7.4.x still uses temporary_key or rotates it",
    "FAZ 8.0.0: extract and check Airflow version + auth config",
]
