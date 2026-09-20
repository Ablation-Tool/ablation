"""
FortiManager VM -- Multi-version RE
Primary target: FMG_VM64-v7.4.11.M-build2804-FORTINET (build 2026-05-06)
Additional versions on hand: 6.4.14, 7.0.12-7.0.16, 7.4.2-7.4.10, 7.6.2-7.6.7, 8.0.0
VMDK: fmg.vmdk (302MB compressed, 4GB partition, 1 Linux ext2 partition)
Filesystem: custom Fortinet bootloader (extlinux), encrypted rootfs.gz + overlays
Available unencrypted: rootfs-ext.tar.xz (130MB XZ) + syntax.tar.xz (73MB XZ)
rootfs.gz: Fortinet-encrypted (magic 0x6bda915e -- not standard gzip/squashfs)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiManager",
    "version":      "7.4.11",
    "build":        "2804",
    "build_date":   "2026-05-06",
    "os_type":      "Custom Linux 2.6.x 64-bit (OVF reports other26xLinux64Guest)",
    "hardware":     "4 vCPU, 16GB RAM",
    "disk_system":  "4.3GB system partition (ext2, 1 partition)",
    "disk_data":    "500GB thin-provisioned data partition",
    "boot":         "extlinux + vmlinuz + rootfs.gz (encrypted) + overlays",
    "python":       "3.11 (site-packages in rootfs-ext.tar.xz)",
    "web_stack":    "Flask JSON-RPC (/api/v1) + SOAP WSDL + React SPA (webclient)",
    "path_overlay": "/usr/local/ (from rootfs-ext.tar.xz)",
}

VERSIONS_ON_HAND = {
    "6.4.14":  "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v6.4.14-build2660-FORTINET.out.ovf.zip",
    "7.0.12":  "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.0.12-build0623-FORTINET.out.ovf.zip",
    "7.0.13":  "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.0.13-build0653-FORTINET.zip",
    "7.0.14":  "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.0.14-build0681-FORTINET.zip",
    "7.0.15":  "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.0.15-build0697-FORTINET.zip",
    "7.0.16":  "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.0.16-build0710-FORTINET.zip",
    "7.4.2":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.4.2-build2397-FORTINET.out.ovf.zip",
    "7.4.6":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.4.6.M-build2588-FORTINET.zip",
    "7.4.7":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.4.7.M-build2685-FORTINET.out.zip",
    "7.4.8":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.4.8.M-build2744-FORTINET.out.zip",
    "7.4.9":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.4.9.M-build2776-FORTINET.out.zip",
    "7.4.10":  "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.4.10.M-build2778-FORTINET.out.zip",
    "7.4.11":  "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.4.11.M-build2804-FORTINET.zip",
    "7.6.2":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.6.2.F-build3415-FORTINET.zip",
    "7.6.3":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.6.3.F-build3492-FORTINET.out.zip",
    "7.6.4":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.6.4.F-build3579-FORTINET.out.zip",
    "7.6.5":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.6.5.M-build3653-FORTINET.out.zip",
    "7.6.6":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.6.6.M-build3654-FORTINET.out.zip",
    "7.6.7":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v7.6.7.M-build3737-FORTINET.zip",
    "8.0.0":   "/media/cowboy/research/Fortinet/FortiManager/FMG_VM64-v8.0.0.F-build0105-FORTINET.zip",
}

EXTRACTED = {
    "7.4.11_vmdk":       "/media/cowboy/research/Fortinet/FortiManager/fmg7411_vmdk/fmg.vmdk",
    "7.4.11_rootfs_ext": "/tmp/fmg7411_rootfs_ext/",
    "7.4.11_syntax":     "/tmp/fmg7411_syntax/ (not yet extracted)",
    "7.4.11_mounted":    "/tmp/fmg7411_fs/ (ext2 partition mounted on nbd0)",
}

# ---------------------------------------------------------
# Filesystem structure
# ---------------------------------------------------------
FILESYSTEM = {
    "boot_partition_layout": [
        "extlinux.conf  -- kernel= vmlinuz, initrd= /rootfs.gz",
        "vmlinuz        -- Linux kernel (4.5MB)",
        "rootfs.gz      -- Fortinet-encrypted rootfs (80MB, magic 0x6bda915e -- NOT standard gz)",
        "rootfs-ext.tar.xz -- unencrypted overlay (130MB XZ, /usr/local/)",
        "syntax.tar.xz  -- CLI syntax files (73MB XZ, /syntax/)",
    ],
    "rootfs_gz_status": "ENCRYPTED -- cannot extract without Fortinet decryption key",
    "overlay_contents": {
        "/usr/local/bin/":    ["ssh", "rclone (Go binary, stripped)"],
        "/usr/local/python/": ["sql-validator/", "sql_rewriter/", "sql_helper/"],
        "/usr/local/webclient/": ["index.html", "cgi_bin/", "static/js/*.chunk.js", "xml.wsdl", "xml_faz.wsdl"],
        "/usr/local/vsig/":   ["AV/IPS signature packages"],
        "/usr/local/lib/python3.11/site-packages/": ["airflow/ (2.10.5)", "flask/", "flask_jsonrpc/", "flask_appbuilder/"],
    },
}

# ---------------------------------------------------------
# Findings
# ---------------------------------------------------------
FINDINGS = {}

FINDINGS["FMG-F01"] = {
    "title": "SOAP API servicePass authentication is optional (minOccurs=0) on ALL operations including runScript",
    "severity": "CRITICAL",
    "status": "CONFIRMED -- xml.wsdl schema: servicePass minOccurs=0, userID minOccurs=0, password minOccurs=0",
    "cvss": "9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
    "cve": None,
    "notes": [
        "WSDL servicePass type: userID + password both minOccurs=0 (optional fields)",
        "servicePass itself is minOccurs=0 on ALL operations",
        "Operations affected: runScript, installConfig, createScript, deleteScript, getConfig, revertConfig",
        "runScript runs scripts on managed FortiGate devices -- if auth bypass confirmed, RCE on all managed devices",
        "installConfig pushes configs -- same impact as runScript",
        "WSDL endpoint: xml.wsdl (FortiManagerWSxml namespace)",
        "CANDIDATE: schema allows omitting auth; server-side enforcement TBD (rootfs.gz encrypted)",
        "Historical precedent: CVE-2024-47575 was missing auth on FGFM protocol (CVSS 9.8)",
        "Highest priority for live instance testing",
    ],
    "soap_endpoint": "/webclient/xml.wsdl (likely at https://fmg_host/webclient/xml.wsdl)",
    "proof_of_concept": """
    POST /webclient/cgi-bin/FortiManager SOAP request (schema inference):
    <soapenv:Envelope>
      <soapenv:Body>
        <tns:runScript>
          <!-- servicePass omitted entirely -->
          <name>test</name>
          <devId>target_device</devId>
        </tns:runScript>
      </soapenv:Body>
    </soapenv:Envelope>
    """,
    "references": ["CVE-2024-47575", "CVE-2023-25610"],
}

FINDINGS["FMG-F02"] = {
    "title": "Flask SQL rewriter app.py runs with debug=True -- Werkzeug debugger exposed",
    "severity": "HIGH",
    "status": "CONFIRMED -- app.run(host='0.0.0.0', debug=True) in sql_rewriter/app.py",
    "cvss": "9.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) if port accessible",
    "cve": None,
    "notes": [
        "File: /usr/local/python/sql_rewriter/app.py line: app.run(host='0.0.0.0', debug=True)",
        "Flask Werkzeug debug mode exposes interactive Python console at /__debugger__/",
        "Console allows arbitrary Python code execution when PIN is obtained or not required",
        "No authentication on the Flask JSON-RPC service itself",
        "Service bound to 0.0.0.0 -- all interfaces if run directly",
        "Endpoints: sqlrewriter.rewrite, sqlrewriter.fabricrewrite, sqlrewriter.logfields, sqlrewriter.echo",
        "Schema bug: minLength and maxLength both defined with key 'minLength' (second overrides first)",
        "CANDIDATE: debug=True only active in __main__ mode; production may use gunicorn (no debug)",
        "Port unknown -- rootfs.gz encrypted, startup scripts inaccessible",
        "If exposed via nginx proxy to external network, instant RCE",
    ],
    "references": ["CVE-2021-23336 (Flask Werkzeug debug)"],
}

FINDINGS["FMG-F03"] = {
    "title": "Apache Airflow 2.10.5 embedded -- full workflow automation platform with known CVEs",
    "severity": "HIGH",
    "status": "CONFIRMED -- airflow==2.10.5 in /usr/local/lib/python3.11/site-packages/airflow/",
    "cvss": "8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)",
    "cve": None,
    "notes": [
        "Airflow 2.10.5 full installation in FMG overlay filesystem",
        "Airflow provides DAG execution, web UI (Flask AppBuilder), REST API, secret management",
        "Airflow DAGs can execute arbitrary shell commands via BashOperator, PythonOperator",
        "Known Airflow CVEs in 2.10.x series: check for auth bypass, DAG manipulation, secret exfil",
        "If Airflow web UI is exposed (default port 8080), auth bypass = code exec on FMG host",
        "FMG manages all FortiGate firewalls -- host compromise = full network control",
        "Port: Airflow default 8080; actual port binding unknown (rootfs.gz encrypted)",
        "flask_appbuilder version: check for IDOR/auth bypass in admin panel",
        "CANDIDATE: need to determine if Airflow web UI is network-accessible",
    ],
    "references": ["CVE-2024-39863", "CVE-2024-45784", "CVE-2024-46909"],
}

FINDINGS["FMG-F04"] = {
    "title": "rclone binary in FMG overlay -- cloud sync tool may expose sensitive data to external storage",
    "severity": "MEDIUM",
    "status": "CONFIRMED -- /usr/local/bin/rclone (Go binary, stripped, ~50MB)",
    "cvss": "6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)",
    "cve": None,
    "notes": [
        "rclone is present in the FMG overlay: /usr/local/bin/rclone",
        "rclone supports sync to S3, GCS, Azure Blob, Dropbox, SFTP, WebDAV, etc.",
        "In FMG context, likely used for scheduled backup to cloud storage",
        "If rclone config is world-readable or accessible via FMG config API, cloud creds exposed",
        "rclone config file typically at ~/.config/rclone/rclone.conf",
        "rclone config stores cloud provider tokens/keys -- attacker can exfiltrate all backups",
        "InsecureSkipVerify equivalent exists in rclone TLS options",
        "CANDIDATE: need to find rclone config location and access control in FMG",
    ],
    "references": [],
}

FINDINGS["FMG-F05"] = {
    "title": "FMG SOAP runScript + createScript -- script injection path to all managed FortiGates",
    "severity": "CRITICAL",
    "status": "CONFIRMED -- WSDL defines runScript with name, devId, serialNumber, type parameters",
    "cvss": "9.9 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)",
    "cve": None,
    "notes": [
        "runScript executes named scripts on target FortiGate devices",
        "Script content set via createScript (also SOAP with no mandatory auth)",
        "Script type parameter: 'cli' runs FortiOS CLI commands, 'tcl' runs TCL scripts",
        "devId and serialNumber target specific devices -- can target all registered devices",
        "Chain: createScript (inject CLI payload) + runScript (execute on all managed FGTs)",
        "Result: full control of all FortiGate firewalls managed by compromised FMG",
        "getTCLRootFile operation -- potential path traversal in TCL script filename",
        "getFazArchive/removeFazArchive -- FortiAnalyzer archive access",
        "Chained with FMG-F01: if auth is optional, this is pre-auth mass firewall compromise",
    ],
    "references": ["FMG-F01"],
}

FINDINGS["FMG-F06"] = {
    "title": "FMG SOAP installConfig -- unauthenticated config push to all managed FortiGates",
    "severity": "CRITICAL",
    "status": "CONFIRMED -- installConfig in WSDL with servicePass minOccurs=0",
    "cvss": "9.9 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
    "cve": None,
    "notes": [
        "installConfig pushes configuration revisions to managed FortiGate devices",
        "Parameters: from (revision), to (target revision), adom, devId, serialNumber",
        "Can overwrite running config on all managed firewalls",
        "revertConfig -- revert to known-bad config (denial of service)",
        "importPolicy -- import policy packages",
        "Chained with FMG-F01: if auth optional, pre-auth mass config manipulation",
    ],
    "references": ["FMG-F01", "FMG-F05"],
}

# SOAP operations map
SOAP_OPERATIONS = {
    "auth": "servicePass (userID + password) -- ALL minOccurs=0",
    "script_ops":  ["createScript", "deleteScript", "getScript", "runScript", "getScriptLog", "getScriptLogSummary"],
    "config_ops":  ["getConfig", "getConfigRevisionHistory", "installConfig", "retrieveConfig", "revertConfig", "listRevisionId", "deleteConfigRev"],
    "device_ops":  ["addDevice", "deleteDevice", "getDevices", "getDeviceList", "getDeviceLicenseList", "getDeviceVdomList"],
    "adom_ops":    ["addAdom", "deleteAdom", "editAdom", "getAdoms", "getAdomList"],
    "group_ops":   ["addGroup", "deleteGroup", "editGroupMembership", "getGroups", "getGroupList"],
    "policy_ops":  ["importPolicy", "addPolicyPackage", "assignGlobalPolicy"],
    "faz_ops":     ["searchFazLog", "getFazArchive", "removeFazArchive", "getFazConfig", "setFazConfig", "listFazGeneratedReports", "getFazGeneratedReport", "runFazReport"],
    "misc":        ["getSystemStatus", "getInstlog", "getTaskList", "getTCLRootFile", "addWTP"],
}

# Flask JSON-RPC operations (no auth)
FLASK_JSONRPC_OPS = {
    "endpoint":          "/api/v1",
    "auth":              "None -- no authentication on Flask JSON-RPC service",
    "debug_mode":        True,  # app.run(debug=True)
    "bind":              "0.0.0.0",
    "methods": {
        "sqlrewriter.rewrite":       "Rewrite FAZ SQL query (max 64KB)",
        "sqlrewriter.fabricrewrite": "Rewrite Fabric SQL query (max 64KB)",
        "sqlrewriter.logfields":     "Get log fields for devtype/logtype",
        "sqlrewriter.echo":          "Echo name back (test/confirm service alive)",
        "sqlrewriter.notify":        "No-op notification",
    },
}

# Pending analysis
TODO = [
    "Live test FMG-F01: send runScript SOAP without servicePass -- confirm auth bypass",
    "Live test FMG-F02: check Flask JSON-RPC port; curl sqlrewriter.echo to confirm exposed",
    "Live test FMG-F03: check if Airflow web UI on port 8080 is accessible",
    "Extract older FMG version (6.4.14 or 7.0.x) to track when SOAP auth became optional",
    "Extract FMG 7.6.x/8.0.0 to check if SOAP auth was fixed in newer versions",
    "Compare FMG xml.wsdl across versions to identify auth changes",
    "Mount FMG 8.0.0 VMDK and extract overlay to check SOAP WSDL differences",
    "Run Ablation semantic sweep on rclone binary for embedded config paths",
    "Check FMG FAZ WSDL (xml_faz.wsdl) for same auth bypass pattern",
    "Investigate getTCLRootFile for path traversal in TCL filename parameter",
]
