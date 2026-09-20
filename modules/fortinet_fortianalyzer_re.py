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
        "PORT 8081 ACCESSIBILITY ANALYSIS (rootfs static analysis, 6.4.14):",
        "  Airflow config: web_server_host = 0.0.0.0 (binds ALL interfaces including external)",
        "  Apache listens: 443, 26443, 80, 127.0.0.1:80, 127.0.0.1:31723 -- NO 8081 proxy",
        "  Init scripts (/etc/init.d/): no iptables rules applied at startup",
        "  No static iptables rules in rootfs blocking port 8081",
        "  FAZ access control: trusted-hosts per admin account (not port-level firewall)",
        "  cmdbsvr: no 8081 or iptables strings -- no dynamic port blocking found",
        "  VERDICT: No evidence of firewall blocking 8081 in static analysis.",
        "           Port 8081 appears externally accessible by default (no blocking found).",
        "           Live confirmation required for final certainty.",
        "           Risk: network-level firewall (external to FAZ) may block 8081.",
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
    "title": "FAZ SOAP servicePass auth bypass -- omitted credentials return SOAP_OK without auth check",
    "severity": "CRITICAL",
    "status": "CONFIRMED SERVER-SIDE -- libfortimanagerwsmain.so disasm proves bypass: null servicePass returns SOAP_OK(0)",
    "cvss": "9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
    "cve": None,
    "notes": [
        "WSDL at /usr/local/webclient/xml_faz.wsdl",
        "servicePass type: userID(optional) + password(optional) -- minOccurs=0 on BOTH fields",
        "Operations with optional auth: getDevices, getAdoms, searchFazLog, getFazArchive, removeFazArchive",
        "getFazConfig, setFazConfig: read/write FAZ configuration without credentials",
        "runFazReport: run arbitrary reports",
        "searchFazLog: search all log data for all connected FortiGate devices",
        "getFazArchive: download archived log data",
        "setFazConfig: write FAZ configuration -- can change admin password, disable MFA, add admin account",
        "Also has xml.wsdl (same as FMG xml.wsdl): runScript, installConfig ops with same optional auth",
        "VERSION BOUNDARY: XML API present in all FAZ <7.6.5; removed in 7.6.5 per 7.6.7 release notes",
        "All 7.2.x targets (7.2.5/7.2.7/7.2.9/7.2.10/7.2.11/7.2.12) have SOAP surface",
        "",
        "=== SERVER-SIDE BYPASS CONFIRMED (libfortimanagerwsmain.so:0x11e800 region) ===",
        "SOAP handler lib: /lib/libfortimanagerwsmain.so (1.87MB, C++ gSOAP-generated)",
        "Auth check function (near 0x11e800) examines servicePass struct from request:",
        "  if servicePass pointer is null: xor r14d,r14d (=0=SOAP_OK) + log + return SOAP_OK",
        "  if servicePass.userID is null: same bypass path -- return SOAP_OK",
        "  if servicePass.password is null: same bypass path -- return SOAP_OK",
        "  if both userID and password non-null: calls auth_user(userID, password, 0, 0, IP, 'XML')",
        "    then fgt_login_check; on failure: sleep(3) + return error",
        "Bypass path: svc_fmglog_text('/log/event/fmgws/connection', ..., 'remote_host=\"%s\"', IP, 'XML')",
        "  logs the connection event (bypass IS logged to FAZ event log) then returns SOAP_OK",
        "  then jumps to 0x11f563: mov r14d(%eax=0), ret -- caller sees SOAP_OK (success)",
        "CONSEQUENCE: all SOAP operations execute as authenticated when servicePass is omitted or empty",
        "NOTE: bypass events appear in /log/event/fmgws/connection -- detectable in FAZ audit logs",
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
    "title": "FGFM fgfmsd: dvmDevVerifyNewSn() empty-SN bypass + config-flag fallback -- CVE-2024-47575 root cause",
    "severity": "CRITICAL",
    "status": "CONFIRMED in 6.4.14 -- root cause in libsecurityconsolemain.so 0x62db7 (empty-SN Gate 1) + fgfmsd config-flag path at 0x428834; same class expected in 7.0.12/7.2.x",
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
        "OFTP: separate daemon (oftpd, TCP/UDP 514); FGFM daemon on port 541 is fgfmsd",
        "diagnose test application oftpd 3 -> OFTP connections; fgfmsd is not visible here",
        "",
        "=== dvmDevVerifyNewSn() ROOT CAUSE ANALYSIS (libsecurityconsolemain.so 0x62db7) ===",
        "Library: /tmp/faz614_rootfs/lib/libsecurityconsolemain.so (606KB, ELF x86-64, nm-confirmed export)",
        "NOT in libdvmapi.so (IPC library); ALSO present in libcdb.so at 0x157383",
        "",
        "FINDING: dvmDevVerifyNewSn() is a DATABASE LOOKUP, not a cryptographic cert check",
        "  Pseudocode:",
        "    dvmDevVerifyNewSn(device_struct* rdi, new_sn* rsi) -> int:",
        "      # Gate 1: empty SN field = BYPASS (CRITICAL BUG)",
        "      0x62dcc: cmp byte [device_struct+0x60], 0  ; is existing SN field empty?",
        "      0x62ddc: je  0x62e7f                        ; if empty -> return 1 (SUCCESS, no check!)",
        "      # Gate 2: strcmp(device_struct->sn, new_sn)",
        "      0x62de2: lea rdi, [device_struct+0x60]",
        "      0x62de6: mov r12, rsi                       ; save new_sn",
        "      0x62de9: call strcmp()  [PLT 0x20340]       ; strcmp(current_sn, new_sn)",
        "      0x62df9: je  0x62e7f                        ; if equal -> return 1 (same SN, match)",
        "      # Gate 3: DB lookup -- only reached when SN differs",
        "      0x62e0c: call dvmDbFetchCreate()  [PLT 0x1f1f0]  ; init DB query context on stack",
        "      0x62e30: call dvmDbFetchAddFilter(ctx, 0, 0, device->field_0x10, 0, 5)  ; filter by device_id",
        "      0x62e54: call dvmDbFetchAddFilter(ctx, 3, new_sn, 0, 0, 5)              ; filter by new SN",
        "      0x62e62: result = dvmDbCount(ctx)  [PLT 0x1f4e0]  ; count (device_id, new_sn) rows",
        "      0x62e7c: setg al  ; return (result > 0) ? 1 : 0",
        "",
        "ROOT CAUSE (CVE-2024-47575): Gate 1 at 0x62dcc is the exploit path.",
        "  For a NEW device registration: device_struct->field_0x60 (SN field) = 0 (not yet populated)",
        "  dvmDevVerifyNewSn returns 1 (success) WITHOUT any database lookup or cert check",
        "  fgfmsd at 0x428828 (jne 0x428871) takes the normal path -- device registered as authenticated",
        "  An attacker with no cert/SN sends a registration request for a device not in the DB:",
        "    device_struct->sn_field is empty => instant return 1 => registered without verification",
        "",
        "SECONDARY BYPASS in fgfmsd (config-flag path): even when dvmDevVerifyNewSn returns 0,",
        "  config flags [rax+0x29c] and [rax+0x538] gate a fallback registration at 0x4289d3",
        "  These flags are likely 'unregistered-device' allowlist feature flags",
        "",
        "PATCH HYPOTHESIS: 7.2.8 patch likely adds SN validation BEFORE dvmDevVerifyNewSn call,",
        "  or removes the empty-SN early return at Gate 1, or validates cert chain separately",
        "",
        "=== CROSS-VERSION DIFF: 6.4.14 vs faz712 (vulnerable pre-patch build, ~7.2.5-7.2.7) ===",
        "Binary: /tmp/faz712_rootfs/bin/fgfmsd (279KB, Apr 3, 2024 -- pre-patch)",
        "Registration handler: fgfm_msgclt_run@@Base (symbol visible, dvmDevVerifyNewSn at 0x42a7c1)",
        "Pre-check IDENTICAL in both versions:",
        "  6.4.14: lea rax,[rbp+0x28] / cmp rax,[rbp+0x28] / je -> bypass if sentinel (empty list)",
        "  7.2.x:  lea rax,[rbp+0x28] / cmp [rbp+0x28],rax / je -> bypass if sentinel (same check)",
        "  6.4.14: call strcmp([rbp+0x1d8], r12) / je -> bypass if current SN == new SN",
        "  7.2.x:  call strcmp([rbp+0x1d8], r12) / je -> bypass (identical)",
        "Config flag offsets (struct grew 8 bytes between 6.4.14 and 7.2.x):",
        "  6.4.14: [rax+0x29c] flag1, [rax+0x538] flag2",
        "  7.2.x:  [rax+0x2a4] flag1, [rax+0x540] flag2  (each +8)",
        "Conclusion: bypass logic is structurally IDENTICAL; only struct layout changed",
        "",
        "=== CROSS-VERSION DIFF: 7.0.12 (VULNERABLE) vs 7.0.16 (PATCHED) -- 7.0.x branch ===",
        "Binaries extracted from unencrypted XZ cpio rootfs (7.2.x and above rootfs.gz are Fortinet-encrypted)",
        "  7.0.12: /tmp/faz7012_rootfs/bin/fgfmsd (279KB, Apr 3 2024, build0623) -- VULNERABLE",
        "  7.0.16: /tmp/faz7016_rootfs/bin/fgfmsd (295KB, Jan 29 2026, build0710) -- supposedly PATCHED",
        "  libsecurityconsolemain.so: 7.0.12=664KB, 7.0.16=680KB (16KB larger)",
        "",
        "KEY FINDING: Gate 1 bypass (empty-SN early return) is IDENTICAL in both 7.0.12 and 7.0.16:",
        "  7.0.12: 0x6d4f4: cmpb $0x0, 0x60(%rbx) -> je 0x6d5a7 (return 1 if empty-SN)",
        "  7.0.16: 0x708e6: cmpb $0x0, 0x60(%rbx) -> je 0x7098e (return 1 if empty-SN)",
        "  SAME BYPASS -- Gate 1 was NOT removed in the FAZ 7.0.16 patch",
        "",
        "fgfmsd pre-check (sentinel + strcmp) also IDENTICAL:",
        "  7.0.12: 0x42a794 lea/cmp sentinel / 0x42a7a7 strcmp / 0x42a7c1 dvmDevVerifyNewSn",
        "  7.0.16: 0x2e088 lea/cmp sentinel / 0x2e0a0 strcmp / 0x2e0bd dvmDevVerifyNewSn",
        "  Config flags: SAME offsets [rax+0x2a4] and [rax+0x540] in both 7.0.x versions",
        "",
        "NEW CODE in 7.0.16 fgfmsd (not in 7.0.12):",
        "  IP address comparison block BEFORE sentinel check (calls ip_addr46_cmp, txt_to_ip_addr46)",
        "  pm3_set_current_sid call at 0x2e061",
        "  vtable call *[rax+0x18] at 0x2e07c with rdi=[rbp+0x178] (SN) and esi=0x16",
        "  VTABLE CALL IDENTIFIED (2026-09-20):",
        "    Global ptr at GOT+0x47f80: svc_dvm_clt (R_X86_64_GLOB_DAT from libsvcclt.so)",
        "    libsvcclt.so defines svc_dvm_clt at 0x45970 (DATA symbol)",
        "    vtable[3] = function at libsvcclt.so:0x20fd8",
        "    Function: DVM RPC dispatch -- sends command 0x16 ('session' string at 0x33e2d)",
        "    Args: rdi = SN buffer (&rbp[0x178]), esi = 0x16 (command ID 22)",
        "    Body: init_dmsvc_ops, imul 0x38 for array index, vtable dispatch, pm3_get_current_sid, obj_put",
        "    Purpose: register/update DVM session state when client IP changes",
        "    NOT cert verification -- DVM session notification, non-blocking",
        "    Result discarded by caller -- NOT a security gate",
        "  stack canary added in dvmDevVerifyNewSn (hardening, not functional change to bypass)",
        "",
        "VTABLE CALL CONCLUSION: svc_dvm_clt->vtable[3](SN, 0x16) = DVM session registration.",
        "  Runs on IP-change path only (guarded by ip_addr46_cmp je bypass).",
        "  Return value discarded. Gate 1 bypass in dvmDevVerifyNewSn is NOT blocked by this call.",
        "",
        "CONFIG FLAGS [rax+0x2a4] and [rax+0x540] -- FINAL ANALYSIS:",
        "  Only compared (never written) in fgfmsd and all key libs (libdvmapi, libfgfmapi, libsecurityconsole, libfgfmssl)",
        "  Loaded via global ptr at fgfmsd:main+0x15f7 -> GOT 0x47f60 (different from svc_dvm_clt at 0x47f80)",
        "  Source: populated externally by PM3/CDB config daemon at startup (not inside fgfmsd binary)",
        "  Secondary bypass path: only reached when dvmDevVerifyNewSn returns 0 AND device has registered SN",
        "  Gate 1 (empty-SN early return) bypasses BEFORE reaching dvmDevVerifyNewSn -- config flags not evaluated",
        "  Default state: unknown; likely 0 (disabled) per security-by-default",
        "  Not load-bearing for the primary exploit (Gate 1 bypasses before these flags)",
        "",
        "PATCH ASSESSMENT: The Gate 1 bypass is NOT patched in FAZ 7.0.16.",
        "  Possible explanations:",
        "  1. CVE-2024-47575 patch was applied to FortiManager fgfmsd but NOT FortiAnalyzer fgfmsd",
        "  2. The TLS/cert layer prevents the exploit path before FGFM reaches dvmDevVerifyNewSn",
        "  3. FAZ post-registration capabilities are limited vs FortiManager (different impact)",
        "  4. Fortinet's patch targets a different code layer (netfilter, pre-auth cert check)",
        "  The bypass code in FAZ is structurally identical across all examined versions (6.4.14 through 7.0.16)",
        "",
        "7.2.10 rootfs.gz is Fortinet-encrypted -- cannot directly extract fgfmsd without decryption key",
        "  7.2.9 rootfs.gz is also encrypted (same format, magic b8bc 1c74)",
        "  Encryption introduced between faz712 build (Apr 2024) and 7.2.5 (Mar 2024) -- all 7.2.x VMDKs encrypted",
        "  Only 6.4.x, 7.0.x VMDKs have accessible (XZ cpio) rootfs",
        "",
        "TODO: confirm field_0x10 in device_struct is the device_id used in DB filter",
    ],
    "references": ["CVE-2024-47575", "https://www.fortiguard.com/psirt/FG-IR-24-423"],
}

FINDINGS["FAZ-F08"] = {
    "title": "OFTP oftpd: SSLv3 configurable (not default) + no-forward-secrecy by default + UDP514 cleartext",
    "severity": "HIGH",
    "status": "CONFIRMED -- libcommon_oftp.so disasm + libssl.so.1.1 symbols confirm SSLv3 built-in and configurable",
    "cvss": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    "cve": None,
    "notes": [
        "OFTP = Optimized Fabric Transfer Protocol; FAZ daemon = oftpd; ports TCP514 + UDP514",
        "Default config: OFTP control = TCP514 (TLS); log transfer = UDP514 (NO encryption)",
        "Secure log transfer requires explicit opt-in: config log fortianalyzer setting set reliable enable",
        "",
        "=== SSLv3 BINARY ANALYSIS (libcommon_oftp.so + libssl.so.1.1) ===",
        "libssl.so.1.1: Fortinet custom OpenSSL 1.1.1t (Feb 2023) with enable-ssl3 compiled in",
        "  nm -D libssl.so.1.1 confirms: SSLv3_method, SSLv3_client_method, SSLv3_server_method ALL exported",
        "OFTP_SSL_init in libcommon_oftp.so (0xdb56): stores ssl-proto enum in global, calls OPENSSL_init_ssl",
        "SSL context created with TLS_server_method or TLS_client_method (not SSLv3_method directly)",
        "SSL_CTX_set_options called based on oftp-ssl-proto config value (r14):",
        "  r14=2  (SSLv3): SSL_CTX_set_options(ctx, 0x00000000)  -> NO protocol exclusions -> SSLv3 negotiable!",
        "  r14=4  (TLS1.0): SSL_CTX_set_options(ctx, 0x02000000) -> SSL_OP_NO_SSLv3",
        "  r14=8  (TLS1.1): SSL_CTX_set_options(ctx, 0x06000000) -> SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1",
        "  r14=16 (TLS1.2): SSL_CTX_set_options(ctx, 0x16000000) -> NO_SSLv3 | NO_TLSv1 | NO_TLSv1_1 [DEFAULT]",
        "  r14=32 (TLS1.3): SSL_CTX_set_options(ctx, 0x1e000000) -> all below TLS1.3 disabled",
        "DEFAULT is TLSv1.2 (r14=16) -- SSLv3 NOT enabled by default",
        "SSLv3 IS available when admin sets ssl-min-proto-version to SSLv3 (r14=2 -> options=0 -> POODLE risk)",
        "FIPS mode: if enabled, SSL_CTX_ctrl(ctx, 0x7c, 0, 0x303) = set_max_proto_version(TLS1_2) -- forces TLS1.2 max",
        "",
        "=== CIPHER LIST ANALYSIS (oftp_cert_config_read in libcommon_oftp.so) ===",
        "RESOLVED: set_custom_sslctx_ciphers traced -- does NOT set cipher string, only sets SSL options",
        "  libsysapi.so:0x22577 set_custom_sslctx_ciphers logic:",
        "    calls get_sw_version helper (0x22019); if version present: SSL_CTX_set_options(ctx, 0x400000)",
        "    0x400000 = SSL_OP_CIPHER_SERVER_PREFERENCE only -- no cipher list restriction",
        "    returns 1 (success) on normal installed FAZ, 0 on bare/uninitialized",
        "  oftp_cert_config_read (libcommon_oftp.so:0xbd09) cipher selection:",
        "    if set_custom_sslctx_ciphers returns 1: skip cipher table, go to SSL_CTX_set_options(0x80000854)",
        "    if set_custom_sslctx_ciphers returns 0: select from cipher table at 0x16d60",
        "  Cipher table at libcommon_oftp.so:0x16d60 (8 entries, selection by config mode r15d):",
        "    [0] NULL",
        "    [1] ALL:-NULL:-aNULL:@STRENGTH  (weakest -- all ciphers including RC4/DES)",
        "    [2] HIGH:MEDIUM:-NULL:-aNULL:!SHA1:@STRENGTH  (MEDIUM included = 3DES SWEET32 risk)",
        "    [3] HIGH:-NULL:-aNULL:!SHA1:@STRENGTH  (HIGH only -- stricter)",
        "    [4] HIGH:MEDIUM:-NULL:-aNULL:!SHA1:@STRENGTH  (same as [2])",
        "    [5] DHE-RSA-AES128-SHA:...:ECDHE-ECDSA-AES256-GCM-SHA384:-DES:-RC4:-NULL:-MD5:-DSS:-aNULL:@STRENGTH",
        "    [6] ALL:-NULL:-aNULL:@STRENGTH:!RSA  (all, RSA kex excluded)",
        "    [7] HIGH:MEDIUM:-NULL:-aNULL:@STRENGTH:!SHA1:!RSA  (MEDIUM+no RSA kex)",
        "  DEFAULT PATH (normal install): set_custom_sslctx_ciphers=1 -> cipher table SKIPPED",
        "    OpenSSL 1.1.1 default cipher list used (includes 3DES = SWEET32 risk per CVE-2016-2183)",
        "    Server preference order enforced (SSL_OP_CIPHER_SERVER_PREFERENCE=0x400000)",
        "  Additional options set at 0xc490: SSL_CTX_set_options(ctx, 0x26000000)",
        "    0x02000000 = SSL_OP_NO_SSLv3, 0x04000000 = SSL_OP_NO_TLSv1, 0x20000000 = SSL_OP_NO_COMPRESSION",
        "  Additional options at 0xc571: SSL_CTX_set_options(ctx, 0x80000854) -- disable renegotiation+others",
        "  EC curve: P-256 (NID_X9_62_prime256v1=0x19f) via SSL_CTRL_SET_TMP_ECDH",
        "  CONCLUSION: default OFTP TLS config = OpenSSL 1.1.1 defaults + server-pref + TLS1.2 minimum",
        "    3DES available in OpenSSL defaults (SWEET32 risk for long-lived log sessions)",
        "    No explicit restriction to ECDHE/DHE unless admin configures ssl-cipher-suites custom mode",
        "",
        "=== NO FORWARD SECRECY (default) ===",
        "ssl-static-key-ciphers enabled by default = RSA key exchange possible = no forward secrecy",
        "Default cipher suite: OpenSSL 1.1.1 defaults (unfiltered) -- includes RSA kex (no FS) and 3DES",
        "Forward secrecy requires admin action: set ssl-static-key-ciphers disable",
        "",
        "=== UDP514 CLEARTEXT LOGS ===",
        "Default log path: UDP514 (no TLS, no integrity check) -- all FortiGate logs flow cleartext",
        "Log integrity: default log-checksum=none; MD5 or MD5-auth optional but not default",
        "Attack surface: MITM between FortiGate and FAZ captures and INJECTS into all network security logs",
        "",
        "FAZ serial number appears in OFTP diagnostics -- device identity leak pre-auth",
        "diagnose test application oftpd 3 -> active OFTP sessions (DEVICE, CONN, HOSTNAME, IP, #PKTS)",
        "logsync_conn_id visible in fgtlogd output = connection sequence numbers predictable",
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
    # DONE: libcdb_plugin.so (134KB) -- 5 functions, no dangerous sinks, all scores <0.37 -- clean
    # DONE: libfazcfg_plugin.so (48KB) -- 28 functions, no memcpy/system/exec in PLT, all snprintf bounded -- clean
    #   Candidates disassembled: _adom_name_to_oid_c (Redis key lookup, bounded snprintf, safe),
    #   faz_cdb_plugin_system_connectors (JSON parsing + strcmp chains, no sinks),
    #   faz_cdb_plugin_update_redis (41-byte wrapper, no dangerous calls)
    #   CONCLUSION: both libraries use safe string functions; no novel memory corruption or injection found
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
