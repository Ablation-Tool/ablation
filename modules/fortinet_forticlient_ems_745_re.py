"""
FortiClient EMS 7.4.5 -- Linux AMD64 OVA VM RE
Source: forticlientems_vm.7.4.5.2111.M.ova.zip (7.4G ZIP -> OVA -> VMDK)
VMDK: ems_ubuntu-24.04.vmdk (80GB thin-provisioned, Ubuntu LVM)
LV: ubuntu-vg/ubuntu-lv, mounted at /tmp/ems745_fs
Architecture: Ubuntu 24.04 + AMD64 (x86_64), same Django/Python stack as 8.0.0
Build date: 2025-12-11 (install log timestamp)
Key difference from 8.0.0: separate worker binaries per service (not monolithic emsworkers)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":    "Fortinet FortiClient EMS",
    "version":    "7.4.5.2111",
    "build_date": "2025-12-11",
    "package":    "OVA VM (ems_ubuntu-24.04.vmdk, 80GB LVM, Ubuntu 24.04)",
    "arch":       "Linux AMD64 (x86_64)",
    "stack": {
        "web_server": "Nginx",
        "wsgi":       "Django 4.x (Python 3.10)",
        "python":     "3.10 (env22_amd64 + env24_amd64 virtualenvs)",
        "db":         "PostgreSQL",
        "cache":      "Redis",
        "das":        "FCTDas (Go binary, AMD64, 25MB)",
        "workers":    "Per-service binaries (81MB each, Go, AMD64) -- see WORKER_BINARIES",
    },
    "binary_path": "/opt/forticlientems/bin/",
    "django_path": "/opt/forticlientems/fcm/",
    "nginx_conf":  "/etc/nginx/",
    "install_log": "/forticlientems-install-20251211061226.log",
}

WORKER_BINARIES = [
    # Each is a separate 81MB Go binary starting one service from RunWorker()
    "adconnector_linux_amd64",
    "addaemon_linux_amd64",
    "adevtsrv_linux_amd64",
    "adtask_linux_amd64",
    "chromebookworker_linux_amd64",
    "dbopworker_linux_amd64",
    "deployworker_linux_amd64",
    "ecsocksrv_linux_amd64",
    "emsdaemonsworker_linux_amd64",
    "emsworkers_linux_amd64",       # orchestrator
    "eventworker_linux_amd64",
    "forensicsworker_linux_amd64",
    "ftntdbimpworker_linux_amd64",
    "installerworker_linux_amd64",
    "kaworker_linux_amd64",
    "licenseso_linux_amd64",
    "monitorworker_linux_amd64",
    "probeworker_linux_amd64",
    "regworker_linux_amd64",        # registration -- pre-auth surface
    "sipworker_linux_amd64",
    "tagworker_linux_amd64",
    "taskworker_linux_amd64",
    "updateworker_linux_amd64",
    "upgradeworker_linux_amd64",
    "uploadworker_linux_amd64",     # file upload -- injection surface
    "ztnaworker_linux_amd64",
]

# ---------------------------------------------------------
# Architecture delta vs 8.0.0
# ---------------------------------------------------------
ARCH_DELTA = {
    "vs_800": {
        "binary_model": "7.4.5 uses per-service worker binaries; 8.0.0 merged into one emsworkers_linux_arm64",
        "arch": "7.4.5 = AMD64; 8.0.0 = ARM64",
        "no_ai_route": "7.4.5 has no /api/v1/ai/query or ai_controller.pyc (AI feature added in 8.0.0)",
        "jwt_arch": "7.4.5 jwt_secrets simpler (SASE only); 8.0.0 adds WEBSERVER_KID RS256 + CLOUD_CONTROLLER_KID",
        "scim": "7.4.5 SCIM server confirmed (authMiddleware + scim_api_key via symmetric_key())",
    }
}

# ---------------------------------------------------------
# Findings
# ---------------------------------------------------------
FINDINGS = {}

FINDINGS["EMS-745-F01"] = {
    "title": "addons.symmetric_key() exposed to all DB users -- same as EMS-800-F06",
    "severity": "HIGH",
    "status": "CONFIRMED -- jwt_secrets.pyc SQL identical pattern to 8.0.0: pgp_sym_encrypt/decrypt with symmetric_key()",
    "cvss": "8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
    "cve": None,
    "notes": [
        "addons.pgp_sym_decrypt(secret::bytea, addons.symmetric_key()) in jwt_secrets.pyc",
        "addons.pgp_sym_encrypt(%s, addons.symmetric_key()) for writes",
        "SASE controller JWT stored encrypted with symmetric_key()",
        "backupSymmetricKey symbol in regworker -- key backed up during site backup",
        "Callable: SELECT addons.symmetric_key(); by any DB user",
        "Same attack chain as EMS-800-F06",
    ],
    "references": ["EMS-800-F06"],
}

FINDINGS["EMS-745-F02"] = {
    "title": "InsecureIgnoreHostKey in scheduled SFTP backup -- same as EMS-800-F16",
    "severity": "HIGH",
    "status": "CONFIRMED -- InsecureIgnoreHostKey symbol in regworker_linux_amd64",
    "cvss": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    "cve": None,
    "notes": [
        "InsecureIgnoreHostKey: 1 occurrence in regworker_linux_amd64",
        "golang.org/x/crypto/ssh.InsecureIgnoreHostKey() -- accepts any SFTP server host key",
        "SFTP backup password extractable via F01 (symmetric_key())",
        "MITM intercepts backup password + full backup archive",
        "Same vulnerability as EMS-800-F16",
    ],
    "references": ["EMS-800-F16", "EMS-745-F01"],
}

FINDINGS["EMS-745-F03"] = {
    "title": "InsecureSkipVerify: 2 occurrences -- TLS certificate verification disabled",
    "severity": "HIGH",
    "status": "CONFIRMED -- InsecureSkipVerify symbol in regworker_linux_amd64 (2 occurrences)",
    "cvss": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)",
    "cve": None,
    "notes": [
        "InsecureSkipVerify=true disables TLS cert chain and hostname verification",
        "2 occurrences -- affects at least 2 separate TLS connections",
        "Not present in EMS-800 (zero occurrences in ARM64 emsworkers)",
        "Likely in LDAP TLS or FortiGate connection paths",
        "8.0.0 emsworkers showed 0 InsecureSkipVerify -- may have been fixed upstream",
        "CANDIDATE: need to identify which connections use InsecureSkipVerify",
    ],
    "references": [],
}

FINDINGS["EMS-745-F04"] = {
    "title": "impdb._Cfunc_memcpy + nids_tlv_decode_* + dlopen/dlsym: TLV parsing via dynamically loaded IPS engine",
    "severity": "HIGH",
    "status": "CONFIRMED -- pclntab name extraction reveals 95 impdb functions; VulnImpDB package uses CGo to parse TLV-encoded FortiGuard signature data",
    "cvss": "8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) -- pre-auth if via FortiGuard update channel",
    "cve": None,
    "notes": [
        "Package: fortinet.com/ems/service/impdb -- VulnImpDB (vulnerability/IPS signature database)",
        "_Cfunc_memcpy VA: 0x240a1e0 (confirmed via Go pclntab name extraction)",
        "_Cfunc_dlopen VA: 0x24097e0 -- IPS engine loaded at runtime from .so file",
        "_Cfunc_dlsym VA: 0x24098a0 -- symbols resolved dynamically from the .so",
        "_Cfunc_nids_tlv_decode_app_addrs: 0x240a2e0 -- decodes TLV-encoded app address data",
        "_Cfunc_nids_tlv_decode_attr_map: 0x240a540 -- decodes TLV attribute maps",
        "_Cfunc_nids_tlv_decode_attrs: 0x240a620 -- decodes TLV attribute arrays",
        "_Cfunc_nids_tlv_decode_metadata: 0x240a740 -- decodes TLV metadata structures",
        "_Cfunc_nids_tlv_decode_params: 0x240a900 -- decodes TLV parameter blocks",
        "VulnImpDB.Import (0x2405440): entry point for signature import",
        "VulnImpDB.unpackLinuxBin (0x2405940): unpacks Linux binary (the .so)",
        "VulnImpDB.loadVulnDB (0x2406240): loads the vulnerability DB from .so",
        "VulnImpDB.decrypt (0x2409280): decryption step before TLV parsing",
        "Attack surface: FortiGuard update delivers encrypted .sig file; EMS decrypts then parses TLV via C IPS engine",
        "memcpy in C IPS engine: if TLV length field is not bounds-checked, heap overflow possible",
        "Also: vendor/github.com/golang-fips/openssl/v2._Cfunc_dlopen (0x83e420) -- OpenSSL loaded via CGo",
        "fortinet.com/ems/service/emstasks._Cfunc_dlopen (0x222d160) -- second CGo dlopen in task service",
        "TODO: extract the .so from a running EMS instance or FortiGuard update package",
        "TODO: trace VulnImpDB.Import call to confirm TLV parsing without bounds check",
        "Ablation improvement: go_pclntab.py module written to fix stripped Go binary sweep accuracy",
    ],
    "references": ["EMS-800-F04"],
}

FINDINGS["EMS-745-F05"] = {
    "title": "Ems-Call-Type header present in auth_middleware -- potential auth bypass",
    "severity": "HIGH",
    "status": "CANDIDATE -- Ems-Call-Type present in 7.4.5 auth_middleware.pyc (same as 8.0.0)",
    "cvss": "8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) if bypass confirmed",
    "cve": None,
    "notes": [
        "Ems-Call-Type string confirmed in auth_middleware.pyc",
        "FortiSOAR connector sends Ems-Call-Type: 2 on tag operations",
        "If middleware grants special permissions based on this header, unauthenticated bypass possible",
        "allowed_callers list also present -- whitelist of callers that bypass normal auth",
        "TODO: decompile or bytecode-inspect auth_middleware to confirm bypass condition",
    ],
    "references": ["EMS-800 Ems-Call-Type finding"],
}

# Symbols of interest for further analysis
SYMBOLS_OF_INTEREST = {
    "regworker_linux_amd64": [
        "fortinet.com/ems/service.(*ChromebookService).RegisterRoutes",
        "fortinet.com/ems/service.(*ChromebookService).handleUserChecksum",
        "fortinet.com/ems/service.(*ChromebookService).handleUserProfile",
        "fortinet.com/ems/service.(*DbOpService).backupSymmetricKey",
        "fortinet.com/ems/service.(*DbOpService).backupExistingSite",
        "fortinet.com/ems/server.RunWorker.withTLS.func10",
        "fortinet.com/ems/internal/pb.UnimplementedRegisterServiceServer.Register",
    ],
    "FCTDas": {
        "size": "25MB (AMD64 Go binary)",
        "sha256": None,  # TODO
        "note": "Smaller than EMS-800 FCTDas; SQL injection path EMS-800-F03 needs re-verification in 7.4.5",
    }
}

# Binary hashes for tracking
BINARY_HASHES = {
    "regworker_linux_amd64": {
        "size_bytes": 84951040,  # 81MB
        "md5": None,   # TODO
        "sha256": "f4a6d61750a9f06080440587eb6fdaedfc3f902be553a44fb483e8e4a8a25cfd",
    },
    "FCTDas": {
        "size_bytes": 26214400,  # 25MB
        "sha256": None,  # TODO -- check vs EMS-800 FCTDas
    },
}

# Pending analysis tasks
TODO = [
    "Run Ablation semantic sweep on regworker_linux_amd64 (AMD64 -- sweep works better than ARM64)",
    "Disassemble regworker around _Cfunc_memcpy callsite (F04)",
    "Identify which connections use InsecureSkipVerify (F03)",
    "Decompile auth_middleware.pyc -- confirm Ems-Call-Type bypass condition (F05)",
    "Compare nginx config with 8.0.0 to check /ai/ route absence and other diffs",
    "SHA256 FCTDas and compare with EMS-800 FCTDas for diff",
    "Check if emsworkers_linux_amd64 runs all workers or is the registration worker",
    "Analyze uploadworker_linux_amd64 for subprocess injection (F14 equivalent)",
]
