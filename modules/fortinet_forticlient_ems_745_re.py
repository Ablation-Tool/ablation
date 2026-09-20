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
    "title": "adconnector LDAP TLS: InsecureSkipVerify=true + peer-supplied CA trust = full MITM bypass",
    "severity": "HIGH",
    "status": "CONFIRMED -- Full disassembly of adconnector_linux_amd64 getTLSConfigForLDAPS + verifyPeerCertificate (2026-09-20).",
    "cvss": "7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    "cve": None,
    "notes": [
        "=== PRIOR FINDING CORRECTION (2026-09-20) ===",
        "Original claim 'InsecureSkipVerify=true: 2 occurrences in regworker' was WRONG.",
        "Both regworker occurrences are Go stdlib artifacts:",
        "  0x2c9a0f7: stdlib error msg 'tls: either ServerName or InsecureSkipVerify must be specified'",
        "  0x33c2a20: tls.Config struct field name in Go reflect/type metadata",
        "NO InsecureSkipVerify=true assignment in regworker. LDAPAuthenticator.AuthUser (0x2506dc0) is SQL-backed, no live LDAP.",
        "",
        "=== gRPC INSECURE TRANSPORTS (regworker) ===",
        "Two internal gRPC connections use grpc/credentials/insecure.NewCredentials (no TLS):",
        "  1. fortinet.com/ems/service/ec/dispatcher.NewGrpcConnPool.WithInsecure.func1 (0x2495800)",
        "  2. fortinet.com/ems/service.(*KeepAliveService).getForensicsWorkerConnSafely.func1.WithInsecure.1 (0x2698f40)",
        "  startUnprotectedListener (0x27108c0) confirms server side listens without TLS",
        "  Severity: LOW-MEDIUM (likely localhost; no confirmed 0.0.0.0 binding)",
        "",
        "=== LDAP TLS BYPASS -- CONFIRMED HIGH (adconnector_linux_amd64) ===",
        "Binary: /opt/forticlientems/bin/adconnector_linux_amd64 (36MB, Go 1.20+, 35706 funcs)",
        "",
        "getTLSConfigForLDAPS (0xdcac20, 280 insns, 1344 bytes):",
        "  Builds tls.Config for all LDAPS connections in NewDefaultLdapConnPool.",
        "  0xdcb05a: call runtime.newobject  (allocate tls.Config)",
        "  0xdcb05f: mov byte ptr [rax + 0xa0], 1  <-- InsecureSkipVerify = true, UNCONDITIONAL",
        "  Offset 0xa0 in Go 1.20 tls.Config struct layout:",
        "    +0x00 Rand, +0x10 Time, +0x18 Certificates (slice), +0x30 NameToCertificate,",
        "    +0x38 GetCertificate, +0x40 GetClientCertificate, +0x48 GetConfigForClient,",
        "    +0x50 VerifyPeerCertificate (func), +0x58 VerifyConnection, +0x60 RootCAs,",
        "    +0x68 NextProtos (slice), +0x80 ServerName, +0x90 ClientAuth, +0x98 ClientCAs,",
        "    +0xa0 InsecureSkipVerify bool  <-- CONFIRMED this field",
        "  0xdcb05f sets InsecureSkipVerify=true on every tls.Config, regardless of admin config.",
        "  0xdcb0ab: mov qword ptr [rax + 0x50], rdx  -- stores VerifyPeerCertificate closure",
        "  0xdcb0c5: mov word ptr [rax + 0x108], 0x303  -- MinVersion = TLS 1.2",
        "",
        "  VerifyPeerCertificate closure struct (at 0xdcafcb):",
        "    [+0x00] = ptr to getTLSConfigForLDAPS.func1 (0xdcb160)",
        "    [+0x08] = ServerName ptr",
        "    [+0x10] = ServerName len",
        "    [+0x18] = cachedPTRResult (for reverse DNS)",
        "    [+0x20] = cert pool ptr (pre-loaded CA)",
        "    [+0x28] = checkCertHostname bool (from proto3 LDAPAuthSettings.CheckCertHostname)",
        "    [+0x30] = root CA pool (may be nil)",
        "",
        "getTLSConfigForLDAPS.func1 (0xdcb160, VerifyPeerCertificate callback):",
        "  0xdcb177: movzx r10d, byte ptr [rdx + 0x28]  -- loads checkCertHostname bool",
        "  Passes all closure fields to verifyPeerCertificate (0xdca0e0)",
        "",
        "verifyPeerCertificate (0xdca0e0, 386 insns) -- CRITICAL BYPASS PATH:",
        "  Iterates rawCerts from peer:",
        "    - Calls crypto/x509.ParseCertificate for each raw cert",
        "    - If cert.IsCA (field 0x361 != 0): AddCert to CA pool built from PEER-SUPPLIED certs",
        "    - Else: saves as leaf cert",
        "  Decision branch at 0xdca386-0xdca3a4:",
        "    0xdca386: movzx r9d, byte ptr [rsp + 0x1d8]  -- load checkCertHostname",
        "    0xdca392: jne 0xdca3a9  -- if true: do PTR/hostname lookup",
        "    0xdca394-0xdca3a4: if false: SKIP hostname check, jump to 0xdca4a6",
        "  Final path (checkCertHostname=false, proto3 default):",
        "    0xdca4ee: test r9b, r9b; je 0xdca55f  -- DNSName stays empty",
        "    0xdca599: call crypto/x509.(*Certificate).Verify",
        "      opts.DNSName = '' (no hostname check)",
        "      opts.Roots = CA pool built from PEER-PROVIDED certs (not system trust store)",
        "  RESULT: x509.Verify passes for any cert where:",
        "    - Peer sends a self-signed cert with CA bit set",
        "    - verifyPeerCertificate adds it to Roots pool",
        "    - Leaf cert verified against attacker-supplied CA -> SUCCESS",
        "  Full MITM possible with self-signed cert, no DNS name check, no chain validation.",
        "",
        "  checkCertHostname=true path:",
        "    PTR lookup performed; DNSName set to ServerName",
        "    opts.Roots still = peer-supplied CAs (not system store)",
        "    Self-signed cert with correct CN/SAN still bypasses (chain not validated against trusted roots)",
        "",
        "NewDefaultLdapConnPool (0xdcb200): calls getTLSConfigForLDAPS at 0xdcb560",
        "  0xdcb59d: mov qword ptr [rdx + 0x98], rax  -- stores tls.Config at pool struct +0x98",
        "(*DefaultLdapConnPool).getConn (0xdc82a0): LDAP connection factory",
        "  0xdc83fb: mov rsi, qword ptr [rcx + 0x98]  -- loads tls.Config from pool",
        "  0xdc8414: call ldap.DialTLS  -- LDAPS connection with InsecureSkipVerify=true",
        "  0xdc8377: call ldap.Dial  -- plain LDAP path (no TLS at all)",
        "  ldap.(*Conn).StartTLS (0x9a8800) also present -- affected if StartTLS used",
        "",
        "IMPACT:",
        "  Attacker on LAN between EMS and AD/LDAP server can MITM all LDAPS/StartTLS traffic.",
        "  Captured: LDAP bind credentials (AD service account password), full LDAP search results",
        "  (user enumeration, group membership, attribute data)",
        "  Default configuration (CheckCertHostname=false) = no certificate verification whatsoever.",
        "  Even with CheckCertHostname=true: self-signed cert with correct hostname bypasses.",
        "",
        "AFFECTED PROTOCOLS:",
        "  LDAPS (ldap.DialTLS): directly via getConn",
        "  StartTLS (ldap.(*Conn).StartTLS): upgrade from plain LDAP",
        "  Plain LDAP (ldap.Dial): no TLS at all (separate issue, existing behavior)",
    ],
    "references": ["EMS-745-F02 (InsecureIgnoreHostKey SFTP)", "go-ldap/ldap/v3 CheckCertHostname"],
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
        "",
        "=== libips.so ANALYSIS (2026-09-20) ===",
        "File: /opt/forticlientems/lib/libips.so (11,970,160 bytes, Feb 8 2023, ELF64 stripped)",
        "Loaded by: InitIpsLib (0x2410640 in regworker) -> _Cfunc_dlopen at 0x24106ad",
        "  0x241066e: lea rax, [rip + 0x831d44]  -> string VA 0x2c423b9 = '/opt/forticlientems/lib//libips.so'",
        "  0x24106ad: call _Cfunc_dlopen (RTLD_LAZY=1)",
        "vtable (resolved via ips_so_query_interface at 0xcd280):",
        "  36 entries at 0xaed2a0, each: {name_ptr, func_ptr}",
        "  Key entries:",
        "    [11] load_rule_file           -> 0xbd070  (TLV parser entry, 885 insns)",
        "    [ 1] init_engine              -> 0xb86a0",
        "    [21] get_metadata_count       -> 0x1926c0",
        "    [22] get_metadata_info        -> 0x192dc0",
        "    [ 6] begin_iterate_rule       -> 0x1a8b60",
        "    [ 9] get_next_app             -> 0x1b0bf0",
        "load_rule_file (0xbd070):",
        "  TLV parse loop at 0xbd266: movzx ebx, byte ptr [r12] -- reads tag byte",
        "  Tag dispatch: 0xff -> 0xbe553, 0x08 -> 0xbdcd7",
        "  Internal calls: 0x6c4aa0, 0x6c95a0, 0x16d790, 0x1a5e40, 0x1b2390, 0x2b1e50, 0x2b1f80",
        "  PLT calls (from load_rule_file): strcasecmp, strcmp, qsort, getpid",
        "  memcpy@GLIBC_2.14 confirmed as undefined in .dynsym (IFUNC or inlined as rep movsq)",
        "",
        "=== _Cfunc_memcpy CALLSITE ANALYSIS (2026-09-20) ===",
        "GetIpsMaps.func9 (0x24100e0, 51 insns) -- ONLY caller of _Cfunc_memcpy in impdb:",
        "  0x24100f2: mov rdx, qword ptr [rax]        ; dest ptr from closure[rax]",
        "  0x24100fa: mov rsi, qword ptr [rbx]        ; src ptr from closure[rbx]",
        "  0x2410102: movsxd r8, dword ptr [rcx]      ; size = sign_extend(int32 from C IPS engine)",
        "  NO bounds check between size read and memcpy call.",
        "  0x241014f: call _Cfunc_memcpy(dest, src, r8) -- unchecked",
        "  If C IPS engine returns oversized length from parsed signature data:",
        "    - Large int32 -> memcpy past end of dest Go buffer",
        "    - Negative int32 -> sign-extended to huge uint64 -> wild memcpy",
        "    -> Heap corruption in Go runtime heap",
        "",
        "load_rule_file internal functions (0x6c4aa0, 0x6c95a0): have array index bounds checks",
        "  0xbd523: cmp esi, dword ptr [r14+0x12c] -- validates TLV index before 0x6c4aa0 dispatch",
        "  These functions do NOT memcpy; they dispatch by index.",
        "  Actual memcpy surface: the C-to-Go data extraction in GetIpsMaps.func9",
        "",
        "ATTACK CHAIN (F04):",
        "  1. Attacker delivers malformed FortiGuard .sig update (encrypted; EMS decrypts via VulnImpDB.decrypt)",
        "  2. load_rule_file (libips.so) parses TLV and stores entries internally",
        "  3. GetIpsMaps iterates via get_next_app/get_next_group/get_metadata_info",
        "  4. For each entry, GetIpsMaps.func9 calls memcpy(go_buf, c_ptr, c_int32_size)",
        "  5. c_int32_size = TLV length field -- if oversized: heap overflow in Go process",
        "  Status: CANDIDATE for exploitation; requires TLV format knowledge to craft malformed .sig",
        "Ablation improvement: go_pclntab.py module written to fix stripped Go binary sweep accuracy",
    ],
    "references": ["EMS-800-F04"],
}

FINDINGS["EMS-745-F14"] = {
    "title": "uploadworker subprocess injection surface: ./osslsigncode relative path + /usr/bin/php + Wine",
    "severity": "MEDIUM",
    "status": "CONFIRMED surface -- full subprocess map extracted (2026-09-20). osslsigncode relative path is exploitable if CWD is attacker-writable. PHP injection CANDIDATE (args not fully traced).",
    "cvss": "6.5 (AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H) -- osslsigncode path; requires write to CWD",
    "cve": None,
    "notes": [
        "Binary: uploadworker_linux_amd64 (82MB, Go 1.20+, 82,793 pclntab funcs)",
        "64 os/exec functions present: Command, CommandContext, Cmd.Run, Cmd.Start, Cmd.Output, Cmd.CombinedOutput",
        "766 EMS service functions matching: upload/unzip/script/install/extract/pkg/package",
        "",
        "=== FINDING 1: ./osslsigncode RELATIVE PATH (MEDIUM) ===",
        "fortinet.com/ems/service/fctinstaller.signFile (0x2566180, 473 insns):",
        "  Caller: signWithCustomerCertificate (0x2565ba0)",
        "  Command: os/exec.Command('./osslsigncode', 'sign', '-pkcs12', <cert_path>, '-in', <installer_path>, '-out', <output_path>, '-h', 'sha256', '-ts', <timestamp_url>, '-pass', <password>)",
        "  'osslsigncode' string: VA 0x2c092da, len 14 = './osslsigncode'",
        "  Arg strings confirmed: 'sign' (VA 0x2bedfc5), '-pkcs12' (0x2bf967c), '-in' (0x2becfb0), '-out' (0x2bedfc9), '-h' (0x2bec102), 'sha256' (0x2bf4fed), '-ts' (0x2becfb3)",
        "  Log message at 0x2c60e9a: 'Running osslsigncode command: %s %s -pass ***'",
        "Bundled binary: /opt/forticlientems/bin/osslsigncode -- version 2.4 (string at 0x34c0)",
        "  Size: 292,520 bytes (ELF64, AMD64)",
        "  Linked against: GLIBC_2.33, GLIBC_2.14",
        "Relative path './osslsigncode' resolves against uploadworker CWD at exec time.",
        "  If CWD = /opt/forticlientems/bin/ (where real osslsigncode lives), relative path works normally.",
        "  If an attacker can write a file named 'osslsigncode' to the CWD before signFile is triggered:",
        "    -> Any uploaded installer triggers execution of attacker's binary as the osslsigncode user",
        "  CWD verification: uploadworker likely chdir()s to /opt/forticlientems/bin/ at startup.",
        "  Attack prerequisite: write access to CWD (requires prior auth or path traversal in upload).",
        "",
        "signWithCustomerCertificate (0x2565ba0):",
        "  Iterates installer file list (array at [rsp+0x120], iterated with rcx count)",
        "  For each installer file: calls AES decrypt for cert password -> signFile(filepath, cert, timestamp, password)",
        "  Cert path: filepath.Join('/opt/forticlientems/data/certs/TLS_RSA_W...', <cert_name>)",
        "  The installer file path comes from the iterated array -- source is the uploaded/downloaded installer list.",
        "",
        "=== FINDING 2: /usr/bin/php IN batchPCRERegexMatch (CANDIDATE) ===",
        "fortinet.com/ems/service/softinvproc/swmatch.batchPCRERegexMatch (0x26d8ec0, 446 insns):",
        "  Command: os/exec.Command('/usr/bin/php', <runtime_args>)",
        "  '/usr/bin/php' string: VA 0x2c04d6c, len 12",
        "  Args: from runtime slice [rsp+0xc0/0xc8/0x120] -- built from software inventory processing",
        "  Purpose: PCRE pattern matching on software inventory data using PHP's preg_match",
        "  If PHP script path or pattern args include user-supplied software name/version strings:",
        "    -> Possible PHP argument injection (not shell injection -- Go exec avoids shell)",
        "  Status: CANDIDATE -- PHP script path and arg construction not fully traced.",
        "",
        "=== FINDING 3: Wine execution of rpkg.exe (INFORMATIONAL) ===",
        "fortinet.com/ems/service/fctinstaller.runRpkgCmd (0x2541540, 450 insns):",
        "  Command 1: os/exec.Command('/opt/forticlientems/rpkg/rpkg', ...) -- static path, absolute",
        "  Command 2: os/exec.Command('/opt/forticlientems/rpkg/emswine32-10.9/bin/wine', '/opt/forticlientems/rpkg/rpkg.exe', '--debug', '--wine', <additional_args>)",
        "  Wine 10.9 bundled: /opt/forticlientems/rpkg/emswine32-10.9/bin/wine",
        "  Execution triggered by: installer type matching at 0x2541a64-0x2541a9e (checks 'DEB_ARAM' and 'RPM_ARAM' 7-byte strings)",
        "  Wine-hosted rpkg.exe processes Windows installer repackaging.",
        "  Absolute paths, not a relative path issue. Informational for attack surface mapping.",
        "",
        "=== FINDING 4: 7zz extraction (INFORMATIONAL) ===",
        "fortinet.com/ems/service/fctinstaller.extractEDRSourcePKGFile (0x2540e60):",
        "  Command: os/exec.Command('/opt/forticlientems/bin/7zz', 'e', '-o/opt/forticlientems/rpkg/edrSource/extracted_dmg', <source_pkg_path>)",
        "  Absolute path. Source pkg path from function arg (caller-determined).",
        "  Risk: if source_pkg_path can escape the extraction directory (-snl for symlinks in 7z), possible path traversal.",
    ],
    "references": ["EMS-800 installer worker analysis (if any)", "osslsigncode v2.4"],
}

FINDINGS["EMS-745-F05"] = {
    "title": "Ems-Call-Type header: NOT a bypass in EMS 7.4.5 -- logging only",
    "severity": "NONE",
    "status": "CLOSED -- NOT CONFIRMED. Full bytecode disassembly (2026-09-20) shows header is logging-only.",
    "cvss": None,
    "cve": None,
    "notes": [
        "=== FULL BYTECODE ANALYSIS COMPLETE (2026-09-20) ===",
        "Method: sudo PYTHONHOME=<ems_python_env> python3.10; marshal.loads(pyc[16:]); dis.dis()",
        "",
        "__call__ method (Django middleware entry point):",
        "  Line 19: SETUP_FINALLY",
        "  Line 20: self.check_request_authorization(request) -- unconditional call",
        "  Line 21: if Exception: ErrorHandler.process_exception(request, e); return",
        "  Line 24: self.get_response(request); return",
        "  NO Ems-Call-Type check in __call__. No branching on header. Header NOT VISIBLE here.",
        "",
        "check_request_authorization (static method):",
        "  Line 33 (offset 44-60): RequestHandler.api_log(request, params.get('Ems-Call-Type'))",
        "    -> POP_TOP: result discarded. LOGGING ONLY. No branch on header value.",
        "  Lines 35-61: auth checks proceed in order regardless of Ems-Call-Type value:",
        "    ems_setup path: api_def.security_schemes.get('ems_setup') -- SERVER-DEFINED, not client-injectable",
        "    jwt path: JwtAuth.contains_header check",
        "    cert_chain paths",
        "    session path: SessionAuth.check_session",
        "  Lines 62+: if security_schemes non-empty, none matched -> UnauthorizedError",
        "             if security_schemes empty -> return None (no auth configured for endpoint)",
        "",
        "VERDICT: Ems-Call-Type is a logging parameter only in EMS 7.4.5.",
        "  Client cannot inject it to bypass auth. Server-side api_def controls security_schemes.",
        "  Finding CLOSED as false positive for this version.",
        "  NOTE: EMS-800 finding may differ -- needs separate bytecode analysis on 8.0.0 pyc.",
    ],
    "references": ["EMS-800 Ems-Call-Type finding -- separate analysis needed for 8.0.0"],
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
        "pclntab_funcs": 82810,
        "go_version": "1.20+",
        "analyzed": "2026-09-20",
    },
    "adconnector_linux_amd64": {
        "size_bytes": 37748736,  # 36MB
        "md5": None,   # TODO
        "sha256": None,  # TODO
        "pclntab_funcs": 35706,
        "go_version": "1.20+",
        "analyzed": "2026-09-20",
        "key_findings": [
            "getTLSConfigForLDAPS (0xdcac20): InsecureSkipVerify=true UNCONDITIONAL at 0xdcb05f",
            "verifyPeerCertificate (0xdca0e0): peer-supplied CA trusted, DNSName='' by default",
            "ldap.DialTLS (0x9a7fc0), ldap.Dial (0x9a7dc0), (*Conn).StartTLS (0x9a8800)",
            "(*DefaultLdapConnPool).getConn (0xdc82a0): connection factory",
            "NewDefaultLdapConnPool (0xdcb200): calls getTLSConfigForLDAPS",
        ],
    },
    "uploadworker_linux_amd64": {
        "size_bytes": 86106624,  # 82MB
        "pclntab_funcs": 82793,
        "go_version": "1.20+",
        "analyzed": "2026-09-20",
        "key_findings": [
            "signFile (0x2566180): os/exec.Command('./osslsigncode', ...) -- RELATIVE PATH (CWD-dependent)",
            "bundled osslsigncode: /opt/forticlientems/bin/osslsigncode v2.4 (ELF64 AMD64, 292520 bytes)",
            "full sign command: ./osslsigncode sign -pkcs12 <cert> -in <file> -out <out> -h sha256 -ts <url> -pass ***",
            "batchPCRERegexMatch (0x26d8ec0): os/exec.Command('/usr/bin/php', <runtime_args>)",
            "runRpkgCmd (0x2541540): Wine 10.9 execution of rpkg.exe (absolute path)",
            "extractEDRSourcePKGFile (0x2540e60): 7zz extraction (absolute path)",
            "64 os/exec functions, 766 upload/install/pkg functions, 3783 EMS service functions",
        ],
    },
    "FCTDas": {
        "size_bytes": 26214400,  # 25MB
        "sha256": None,  # TODO -- check vs EMS-800 FCTDas
    },
}

# Pending analysis tasks
TODO = [
    # COMPLETED:
    # [DONE 2026-09-20] Ablation semantic sweep on regworker_linux_amd64:
    #   37774 non-stdlib functions encoded, 1758s, all-MiniLM-L6-v2
    #   Result: NO Fortinet functions above 0.5 threshold on any vulnerability query
    #   All hits were vendor library code (golang-jwt, pgproto3, AzureAD MSAL)
    #   Confirms: attack surface is already-identified findings; no new code-pattern vulns
    # [DONE 2026-09-20] F03: gRPC WithInsecure() confirmed; LDAPAuthenticator.AuthUser = SQL-backed (no live LDAP)
    # [DONE 2026-09-20] F05: Ems-Call-Type bypass -- CLOSED, logging only
    # [DONE 2026-09-20] adconnector_linux_amd64 LDAP TLS analysis:
    #   getTLSConfigForLDAPS (0xdcac20): InsecureSkipVerify=true at 0xdcb05f (unconditional)
    #   verifyPeerCertificate (0xdca0e0): with checkCertHostname=false (default):
    #     DNSName="" + Roots=peer-supplied CAs -> any self-signed cert passes
    #   F03 elevated to HIGH, status CONFIRMED

    # [DONE 2026-09-20] F04 libips.so path confirmed: /opt/forticlientems/lib/libips.so (11MB, Feb 2023)
    # [DONE 2026-09-20] F04 memcpy callsite confirmed: GetIpsMaps.func9 (0x24100e0), sole caller, no bounds check
    # [DONE 2026-09-20] uploadworker_linux_amd64 subprocess injection survey COMPLETE (F14):
    #   ./osslsigncode relative path (MEDIUM), /usr/bin/php in batchPCRERegexMatch (CANDIDATE),
    #   Wine execution (informational), 7zz extraction (informational)

    # ACTIVE:
    "Compare nginx config with 8.0.0 to check /ai/ route absence and other diffs",
    "SHA256 FCTDas and compare with EMS-800 FCTDas for diff",
    "Trace batchPCRERegexMatch PHP args to confirm user-controlled input (F14 CANDIDATE elevation)",
    "Verify uploadworker CWD at runtime to confirm osslsigncode ./relative path resolves (F14 exploitability gate)",
    "Extract IPS engine .so from running EMS instance or FortiGuard update for F04 TLV analysis",
    "Run Ablation semantic sweep on adconnector_linux_amd64 (35706 non-stdlib funcs) -- look for additional LDAP/AD vulns",
]
