"""
cisco_expressway_re.py — Cisco Expressway X12.5.4 static RE module

Target: Cisco Expressway (Tandberg VCS) X12.5.4 Release 1
  /media/cowboy/research/cisco-expressway-12-5.zip
  VMDK: s42700x12_5_4_v6.0_signed-disk1.vmdk (streamOptimized, 3.83GiB virtual)
  RE workspace: /media/cowboy/research/expressway-12-5-extract/

Product XML: TANDBERG Video Communication Server
  code=X, s42700, build=oak_v12.5.4_rc_1, date=2019-07-08

Partition layout (DOS MBR, /dev/nbd0):
  p1 (boot, ext3, 40M)    — bootloader
  p2 (3M)                 — grub/config
  p3 (extended, 3.8G)
  p5 (ext3, 969.6M) UUID=e5c9798a-1bc7-4314-958d-ee689d620320  — root A (primary)
  p6 (ext3, 969.6M)       — root B (alternate, empty in this image)
  p7 (969.6M)             — persistent data: c_mgmt, Docker images, option keys
  p8 (969.6M)             — persistent data B

Mount paths (p5 = primary root):
  /mnt/expressway/         — root FS
  /mnt/expressway-p7/      — persistent data

Web framework: PHP5 (libphp5.so), Apache httpd
  DocumentRoot: /share/web/public (on p5)
  Listen 80 (HTTP), 443 (HTTPS via ssl.conf)

Runtime paths:
  /share/web/public/       — PHP management UI (~100 .php files)
  /share/python/site-packages/ni/  — Python management connector (c_mgmt)
  /opt/c_mgmt/             — symlink to /share/python/site-packages/ni/managementconnector
  /opt/jabber/xcp/         — Jabber XCP (embedded presence/IM)
  /dtandberg/etc/openssl/  — OpenSSL config (Tandberg namespace)
  /tmp/request/            — IPC bridge: PHP writes, root daemons read

OpenSSL: libcrypto.so.1.0.0, libssl.so.1.0.0 (branch 1.0.x, EOL Jan 2020)
PHP: 5.x (EOL Dec 2018) — no security patches since version bump

c_mgmt internal REST API: http://127.0.0.1:4370/
  Observed endpoint: /configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_tempTargetOrgId
  c_mgmt service account: _c_mgmt:*:804:804:/tandberg/c_mgmt:/bin/false

xAPI interface (same as RoomOS):
  /opt/c_mgmt/xcommand/   — xCommand handlers
  /opt/c_mgmt/xstatus/    — xStatus handlers

FINDINGS:

EXP-F1: domain_management_helper SETUID ROOT — Argument Injection Surface [CRITICAL]
  Binary: /sbin/domain_management_helper
  Type: setuid, setgid ELF 64-bit LSB PIE, x86-64, NOT stripped
  Caller: PHP ntlm.php (running as nobody/_nobody via Apache)
  Invocation from ntlm.php:
    $username = escapeshellarg($_POST['username']);
    $password = escapeshellarg($_POST['password']);
    exec("/sbin/domain_management_helper join --username $username --password $password", $out);
  Binary behavior (from symbols + strings):
    check_uid()      — validates caller UID == _nobody (UID ~65534)
    check_args()     — validates argument structure (symbol: _Z10check_argsiPPc)
    On pass: execve("/bin/python", ["/bin/domain_management", verb, "--username", u, "--password", p], env)
    PYTHONPATH=/share/python/site-packages is set in environment
  Verbs accepted: "join", "leave"
  Attack surface:
    1. check_args() boundary — if length/character validation is weak, malformed args reach Python
    2. /bin/domain_management (Python) — if it shells out with unquoted args, secondary injection
    3. escapeshellarg() in PHP 5 does not escape newlines — multiline username/password may split args
  Note: Binary not stripped, full symbol table available for Ghidra/IDA analysis.

EXP-F2: Cert Checker SSRF — Attacker-Controlled Root TLS Connection [HIGH]
  Chain: zonecertchecker.php → /bin/checkcerts.sh → /sbin/request-checkcerts (root daemon)
         → python /share/python/site-packages/ni/certchecker/checker.pyc
  PHP code (zonecertchecker.php line 62-77):
    isValidAddress() validates vcs_e_hostname (FQDN/IP regex, max 255 chars)
    tls_verify — NO semantic validation, only escapeshellarg()
    shell_exec("/bin/checkcerts.sh vcse '$vcs_e_hostname' '$tls_verify'")
  checkcerts.sh writes hostname + tls_verify to /tmp/request/check-vcse-certificate
  Root daemon (request-checkcerts) reads:
    lines=($(cat /tmp/request/check-vcse-certificate))
    vcse_fqdn=${lines[0]}
    tls_verify_name=${lines[1]}
    python checker.pyc -c -w --vcse=${vcse_fqdn} --tlsverify=${tls_verify_name}
  Impact:
    1. SSRF: root process opens TLS connection to attacker-controlled host
    2. Argument injection into checker.pyc via unquoted ${tls_verify_name}
    3. checker.pyc receives arbitrary --tlsverify= value; depends on how Python script uses it
  Note: vcs_e_hostname is validated against isValidAddress() regex before shell call.
        tls_verify has no semantic validation — arbitrary content passed to root daemon.

EXP-F3: /tmp/request/ Race Condition — Symlink Attack [MEDIUM]
  Pattern: PHP writes command/parameters to /tmp/request/<name>, root daemon reads + executes
  Files observed:
    /tmp/request/check-vcse-certificate   — TLS cert check target
    /tmp/request/check-cucm-certificates  — CUCM cert check
    /tmp/request/tcpdump                  — tcpdump start/stop
    /tmp/request/system-backup            — backup trigger
    /tmp/request/system-restore           — restore trigger
    /tmp/request/cacrl-dnhash             — CA/CRL DN hash rebuild
    /tmp/request/backuprestore            — backup/restore config
    + 20+ additional request files
  Attack: If /tmp/ is writable by web user (nobody) and the daemon does not atomically
          check + read, a symlink placed between PHP write and daemon read can redirect
          the read to an attacker-controlled file, injecting arbitrary content into
          the root execution path.
  Note: PHP and root daemon both use non-atomic file operations (write then rm, read then rm).

EXP-F4: OpenSSL 1.0.x (EOL Jan 2020) — Full Historical CVE Exposure [HIGH]
  Libraries: /lib64/libcrypto.so.1.0.0, /lib64/libssl.so.1.0.0
  Branch: OpenSSL 1.0.x (EOL January 2020 for 1.0.2 LTS)
  Notable CVEs applicable post-build (2019-07-08):
    CVE-2019-1549  (OpenSSL 1.0.2s, padding oracle)
    CVE-2019-1563  (PKCS7 padding oracle, AES-CBC)
    CVE-2019-1552  (Windows path insecurity — not applicable on Linux)
    CVE-2020-1971  (NULL dereference in X509_issuer_and_serial_hash, DTLS)
    CVE-2021-3449  (NULL dereference in signature_algorithms, server-side crash)
    All 1.0.x CVEs disclosed after 2019-07-08 apply
  Attack surface: TLS management interface (port 443), B2BUA SIP TLS, TURN/STUN media

EXP-F5: PHP 5 EOL (Dec 2018) — Inherent Vulnerability Class [HIGH]
  Module: /apache2/modules/libphp5.so
  PHP 5.x EOL: December 2018 — no security patches after that date
  Expressway 12.5 build date: 2019-07-08 — shipped 7 months after PHP 5 EOL
  Impact:
    PHP 5 type juggling: "0e..." strings hash to 0 in == comparisons (magic hash bypass)
    PHP 5 object injection: unserialize() on user-controlled input may trigger gadget chains
    PHP 5 specific: multiple post-EOL CVEs in curl, PCRE, openssl extensions
  Expressway uses PHP extensively (100+ .php files in DocumentRoot)

EXP-F6: viewcert.php base64_decode Fingerprint — Type Confusion [LOW/MEDIUM]
  File: /share/web/public/viewcert.php lines 24-28
    if (isset($_GET['fingerprint']))
    {
        $fingerprint = base64_decode($_GET['fingerprint']);
        $use_fingerprint = true;
    }
  Then: if ($item->get_fingerprint() === $fingerprint)
  Behavior: base64_decode() in PHP returns a binary string. If get_fingerprint() returns
            hex or formatted fingerprint, the === comparison fails but no injection.
            However, if $fingerprint matches any internal binary comparison (type confusion
            via PHP string/bool), fingerprint matching can be bypassed.
  Attack: Supplying $_GET['fingerprint'] = base64("false") or malformed binary may
          corrupt the certificate display logic. Low direct impact, but reveals cert
          enumeration logic for multi-cert deployments.

EXP-F7: c_mgmt REST API Internal Exposure [MEDIUM]
  Endpoint: http://127.0.0.1:4370/configuration/...
  Service: Python management connector (_c_mgmt user, UID 804)
  Observed endpoint: /configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_tempTargetOrgId
    (accessed from fusionregistrationajax.php via rest_data_adapter)
  Cisco Hybrid Services (Fusion/Spark) configuration flows through this internal API
  Post-initial-access: any process running on the box can call 127.0.0.1:4370
  Docker components (p7): images/ directory suggests c_mgmt runs in containerized context
  Credential file (p7): 8.6c_mgmt.passwd — _c_mgmt service account entry

EXP-F8: ciphertest.php — OpenSSL Cipher String Injection [LOW]
  File: /share/web/public/ciphertest.php line 85
    $suites = escapeshellarg($cipherstring);
    $command = kOpensslBinary . "ciphers -V $suites";
  User supplies cipherstring → escapeshellarg() → openssl ciphers -V 'value'
  escapeshellarg() is correctly applied — not injectable at shell level.
  Residual: if kOpensslBinary includes path traversal or openssl binary is replaceable,
            attacker post-compromise can swap the binary. Documenting for completeness.

BINARY ARTIFACTS:
  /sbin/domain_management_helper  setuid ELF64 PIE, NOT stripped, gcc 7.3.0
    Symbols: check_uid(), check_args(), kAllowedUser="_nobody", kScript="/bin/domain_management"
             kInterpreter="/bin/python", kPythonPath="/share/python/site-packages"
  /sbin/request-backuprestore     bash (36913 bytes), backup/restore with openssl AES encryption
  /sbin/request-tcpdump           bash (1359 bytes), tcpdump on eth0/eth1
  /sbin/request-checkcerts        bash, reads check-vcse-certificate → Python checker.pyc
  /bin/checkcerts.sh              bash, IPC bridge for cert checking
  /share/python/site-packages/ni/certchecker/checker.pyc  compiled Python 2.x bytecode

APACHE ATTACK SURFACE:
  CGI-bin: printenv, printenv.vbs, printenv.wsf, test-cgi (debug only, no production CGI)
  Config includes:
    /etc/apache2/conf.d/*.conf
    /tandberg/etc/opt/apache2/conf.d/*.conf
    /tandberg/persistent/etc/opt/apache2/auth.d/*.conf  — auth config in persistent partition
  SSL config: /etc/apache2/ssl.conf
  MaxClients: 70 (prefork MPM)
  Bug 119002/120281 (CVE-2011-3192): MaxRanges none — Range header DOS mitigated

RELATED CVEs (later Expressway versions, same codebase lineage):
  CVE-2022-20754  Expressway command injection via API (X14.0.x)
  CVE-2022-20755  Expressway command injection via API (X14.0.x)
  CVE-2023-20105  Expressway privilege escalation
  CVE-2024-20252  Expressway CSRF → auth bypass chain (Critical)
  CVE-2024-20254  Expressway CSRF (Critical)
  CVE-2024-20255  Expressway CSRF (Critical)
  Note: X12.5.4 predates X14.0.x vulnerabilities but shares architectural patterns.
        The xAPI interface (/opt/c_mgmt/xcommand/) present in X12.5 is the attack
        surface class for CVE-2022-20754/20755 in later versions.
"""

# Expressway X12.5.4 binary fingerprints for version discrimination
EXPRESSWAY_BUILD_MARKERS = {
    "product_xml_code": "X",          # code element in product_info.xml
    "software_id": "s42700",          # VMDK filename prefix
    "build_revision": "oak_v12.5.4_rc_1",
    "build_date": "2019-07-08",
    "openssl_so": "libcrypto.so.1.0.0",  # EOL branch
    "php_so": "libphp5.so",              # EOL version
    "c_mgmt_passwd_uid": 804,
    "dmgr_helper_allowed_user": "_nobody",
}

# SETUID binary: domain_management_helper
DOMAIN_MGMT_HELPER = {
    "path": "/sbin/domain_management_helper",
    "type": "setuid ELF64 PIE x86-64 NOT_STRIPPED gcc-7.3.0",
    "check_uid_symbol": "_Z9check_uidv",
    "check_args_symbol": "_Z10check_argsiPPc",
    "kAllowedUser": "_nobody",
    "kScript": "/bin/domain_management",
    "kInterpreter": "/bin/python",
    "kPythonPath": "/share/python/site-packages",
    "verbs": ["join", "leave"],
    "exec_env": {"PYTHONPATH": "/share/python/site-packages"},
    "invocation": "exec(\"/sbin/domain_management_helper join --username $username --password $password\")",
    "php_file": "/share/web/public/ntlm.php",
    "php_line": 370,
}

# /tmp/request/ IPC bridge map
REQUEST_IPC_FILES = [
    "/tmp/request/check-vcse-certificate",
    "/tmp/request/check-cucm-certificates",
    "/tmp/request/check-cup-certificates",
    "/tmp/request/check-ucxn-certificates",
    "/tmp/request/tcpdump",
    "/tmp/request/system-backup",
    "/tmp/request/system-restore",
    "/tmp/request/cacrl-dnhash",
    "/tmp/request/backuprestore",
    "/tmp/request/b2bua-restart",
    "/tmp/request/servicestart",
    "/tmp/request/servicechange",
    "/tmp/request/trafficserverrestart",
    "/tmp/request/transcodermanagerrestart",
    "/tmp/request/smbconfreload",
    "/tmp/request/hybridservices",
    "/tmp/request/togglesymphony",
    "/tmp/request/snap",
    "/tmp/request/xconfdump",
    "/tmp/request/ntp-keygen",
]

# Cert checker chain (SSRF path)
CERT_CHECKER_CHAIN = {
    "php_file": "/share/web/public/zonecertchecker.php",
    "validated_param": "vcs_e_hostname",      # isValidAddress() + escapeshellarg()
    "unvalidated_param": "tls_verify",        # escapeshellarg() ONLY
    "shell_script": "/bin/checkcerts.sh",
    "ipc_file": "/tmp/request/check-vcse-certificate",
    "root_daemon": "/sbin/request-checkcerts",
    "python_checker": "/share/python/site-packages/ni/certchecker/checker.pyc",
    "root_exec": "python checker.pyc -c -w --vcse=${vcse_fqdn} --tlsverify=${tls_verify_name}",
    "unquoted_vars": ["vcse_fqdn", "tls_verify_name"],  # unquoted in root daemon
}

# c_mgmt internal REST API
C_MGMT_API = {
    "base_url": "http://127.0.0.1:4370/",
    "observed_path": "/configuration/cafe/cafeblobconfiguration/name/c_mgmt_system_tempTargetOrgId",
    "service_account": "_c_mgmt",
    "uid": 804,
    "home": "/tandberg/c_mgmt",
    "shell": "/bin/false",
    "passwd_file": "8.6c_mgmt.passwd",     # on p7 persistent partition
}

# isValidAddress() regex (from /share/web/lib/utils.php line 646)
VALID_ADDRESS_REGEX = r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])+(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$'
VALID_ADDRESS_MAX_LEN = 255

# Apache config key values
APACHE_CONFIG = {
    "server_root": "/apache2",
    "document_root": "/share/web/public",
    "php_module": "modules/libphp5.so",
    "max_clients": 70,
    "max_ranges": "none",    # CVE-2011-3192 mitigation
    "keepalive": True,
    "keepalive_timeout": 15,
    "pid_file": "/var/run/apache2.pid",
}
