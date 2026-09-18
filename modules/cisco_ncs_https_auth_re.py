"""
Cisco NCS HTTPS / Authentication Layer RE Module
Targets (all from NetworkControlSystem-1.1.3.2-1.x86_64.rpm):
  httpd/conf/ssl.crt/server.cer  -- fleet-wide TLS certificate (all NCS deployments)
  httpd/conf/ssl.crt/server.key  -- fleet-wide TLS private key (RSA-1024)
  httpd/ssl/backup/ssl.conf      -- Apache SSL configuration
  conf/jaas.config.radius2       -- RADIUS authentication config (hardcoded secret)
  bin/before_backup.sh           -- pre-backup script (chmod 666/777 issues)
  bin/getDatabaseParams.sh       -- DB password in process args

Certificate details (server.cer):
  Issuer/Subject: C=US, ST=Some-State, O=Cisco Systems
  Serial: 0x0 (serial number zero -- placeholder)
  Not Before: 2005-02-25 22:30:33 UTC (6 years before firmware release)
  Not After:  2032-07-13 22:30:33 UTC (27-year validity window)
  Key: RSA-1024

Private key fingerprint (server.key):
  Algorithm: RSA-1024
  Modulus MD5: b9819a5624fcc2581f32e0720561dff3
  Same key on every NCS 1.1.3.2 deployment (shipped in RPM)

Apache SSL configuration (ssl.conf):
  SSLProtocol: all -SSLv2  (SSLv3 + TLS 1.0 both enabled)
  SSLCipherSuite: ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM
    RC4 explicitly permitted (RC4+RSA), SSLv3 permitted (POODLE)
  Port: SSL_PORT (runtime substitution, default 443)

RADIUS JAAS configuration (jaas.config.radius2):
  Module: com.cisco.xmp.jaas.radius.RadiusLoginModule
  debug=true  (debug output on by default)
  JaasSecretKey="cisco"  (hardcoded RADIUS shared secret)
  server="11.11.11.11" port=1812  (placeholder dev address -- replaced at deploy time)

before_backup.sh world-writable directory issue:
  mkdir -p $SQL_DIR && chmod 777 $SQL_DIR  (world-writable SQL generation dir)
  chmod 666 $LOG_FILE  (world-readable backup log)
  getDatabaseParams.sh output captured in DBPASSWD env var, then:
  su - oracle -c "get_ddl_constraints.sh $DBPASSWD ..." (DB password in CLI arg -> /proc visible)
"""

METADATA = {
    "targets": [
        "httpd/conf/ssl.crt/server.cer",
        "httpd/conf/ssl.crt/server.key",
        "httpd/ssl/backup/ssl.conf",
        "conf/jaas.config.radius2",
        "bin/before_backup.sh",
        "bin/getDatabaseParams.sh",
    ],
    "tls_cert": {
        "subject": "C=US, ST=Some-State, O=Cisco Systems",
        "serial": "0x0",
        "not_before": "2005-02-25 22:30:33 UTC",
        "not_after": "2032-07-13 22:30:33 UTC",
        "key_type": "RSA-1024",
        "key_modulus_md5": "b9819a5624fcc2581f32e0720561dff3",
    },
    "ssl_config": {
        "protocol": "all -SSLv2 (SSLv3 + TLS 1.0 enabled)",
        "ciphers": "ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM",
        "rc4_permitted": True,
        "sslv3_permitted": True,
    },
    "radius_secret": "cisco",
    "radius_debug": True,
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Fleet-Wide RSA-1024 TLS Private Key Shipped in NCS RPM (2005, Serial 0)",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-321",
        "description": (
            "The NCS Apache HTTPS server ships a pre-generated RSA-1024 private key "
            "(httpd/conf/ssl.crt/server.key) and matching self-signed certificate "
            "(server.cer) inside the NetworkControlSystem RPM, which is distributed "
            "with every NCS 1.1.3.2 installation and extractable from NCS.tar.gz. "
            "The private key is identical on every NCS deployment (fleet-wide). "
            "Key modulus MD5: b9819a5624fcc2581f32e0720561dff3 "
            "Certificate details: "
            "Subject/Issuer: C=US, ST=Some-State, O=Cisco Systems (no hostname) "
            "Serial: 0x0 (zero -- developer placeholder, never replaced) "
            "Not Before: 2005-02-25 (generated 6 years before the 2011 NCS firmware) "
            "Not After: 2032-07-13 (27-year validity -- never expires in service lifetime) "
            "Impact: Any researcher or attacker who downloads the NCS firmware can extract "
            "this private key and perform a TLS MITM attack against any NCS HTTPS session "
            "(port 443/SSL_PORT). The attacker presents the real Cisco-branded certificate "
            "and decrypts all HTTPS traffic including administrator credentials, session tokens, "
            "device configuration, and WLAN infrastructure management commands. "
            "RSA-1024 was deprecated by NIST in 2013 (SP 800-131A) and is additionally "
            "factored in ~hours on modern hardware, further reducing the key strength. "
            "The same fleet-wide TLS key pattern has been observed in: "
            "Cisco Cat9K IOS-XE 17.18.04 (cisco_catalyst_9k_iosxe_17_18_04_re.py F1: fallback.key), "
            "Cisco CP-6901 (DSS fleet key), "
            "confirming a systemic pattern in Cisco embedded appliance firmware."
        ),
        "key_file": "httpd/conf/ssl.crt/server.key",
        "cert_file": "httpd/conf/ssl.crt/server.cer",
        "key_type": "RSA-1024",
        "cert_serial": "0x0",
        "cert_issued": "2005-02-25",
        "cert_expires": "2032-07-13",
        "key_modulus_md5": "b9819a5624fcc2581f32e0720561dff3",
        "impact": [
            "Extract private key: openssl rsa -in server.key -noout -modulus",
            "MITM any NCS HTTPS session to recover admin credentials and session tokens",
            "Fleet-wide: same key across all NCS 1.1.3.2 deployments",
        ],
        "remediation": (
            "Generate a per-deployment key pair during first-boot provisioning. "
            "Never ship a TLS private key in a firmware package."
        ),
    },
    {
        "id": "F2",
        "title": "SSLv3 Enabled with RC4 Cipher Suite on Pre-POODLE OpenSSL 0.9.8e",
        "severity": "HIGH",
        "cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-326",
        "description": (
            "The NCS Apache SSL configuration (httpd/ssl/backup/ssl.conf) enables: "
            "(1) SSLv3: directive 'SSLProtocol all -SSLv2' disables SSLv2 but leaves "
            "SSLv3 enabled. SSLv3 is vulnerable to POODLE (CVE-2014-3566), which allows "
            "a network attacker to recover plaintext from SSLv3-encrypted sessions via "
            "a chosen-boundary attack on CBC-mode padding. "
            "The underlying OpenSSL library is 0.9.8e (from os-updates.zip, session 47), "
            "which was patched for POODLE only in OpenSSL 0.9.8zc (2014). "
            "The bundled version 0.9.8e is permanently unpatched (EOL platform). "
            "(2) RC4 cipher permitted: cipher string 'RC4+RSA' is in the middle of "
            "SSLCipherSuite ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM "
            "This allows RC4-based cipher suites. RC4 has multiple statistical biases "
            "(CVE-2013-2566, CVE-2015-2808) that allow partial plaintext recovery "
            "of HTTP session cookies when ~2^30 RC4-encrypted sessions are captured. "
            "Both SSLv3 and RC4 are disabled in current TLS best practices "
            "(RFC 7465 prohibits RC4; RFC 7568 prohibits SSLv3). "
            "Attack path: network MITM (possible via F1 fleet-wide private key) + "
            "forced SSLv3 downgrade + POODLE = session cookie recovery."
        ),
        "ssl_protocol": "all -SSLv2 (SSLv3 and TLS 1.0 both allowed)",
        "cipher_suite": "ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM",
        "cves": ["CVE-2014-3566", "CVE-2013-2566", "CVE-2015-2808"],
        "impact": [
            "POODLE: SSLv3 downgrade + CBC padding oracle -> session cookie plaintext recovery",
            "RC4 biases: statistical attack on RC4 sessions given volume capture",
        ],
        "remediation": (
            "Set SSLProtocol TLSv1.2 (or TLSv1.3). "
            "Remove RC4 from cipher suite: !RC4. "
            "Platform is EOL -- no patch path."
        ),
    },
    {
        "id": "F3",
        "title": "RADIUS Shared Secret 'cisco' Hardcoded in jaas.config.radius2 with debug=true",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-321",
        "description": (
            "conf/jaas.config.radius2 ships with a hardcoded RADIUS shared secret: "
            "JaasSecretKey='cisco' "
            "Full JAAS config entry: "
            "RADIUS1 { "
            "  com.cisco.xmp.jaas.radius.RadiusLoginModule required debug=true "
            "  JaasSecretKey='cisco' "
            "  server='11.11.11.11' port='1812'; "
            "}; "
            "When NCS is configured to use RADIUS for administrator authentication, "
            "this default shared secret is used to authenticate the RADIUS Access-Request "
            "messages sent by NCS to the RADIUS server. "
            "Impact path: "
            "(1) If an administrator deploys NCS with RADIUS auth and does not change "
            "the shared secret, any attacker on the network between NCS and the RADIUS server "
            "can forge RADIUS Access-Accept responses and bypass authentication. "
            "(2) The shared secret is also used to protect User-Password attribute encryption "
            "(PAP mode) -- recovery of the secret allows offline decryption of PAP passwords "
            "from captured RADIUS traffic. "
            "debug=true means the RadiusLoginModule produces verbose debug output including "
            "authentication attempts. In a default configuration, JAAS debug output goes to "
            "stdout or the application log, potentially exposing usernames and partial "
            "authentication state in /opt/CSCOncs/logs/. "
            "The '11.11.11.11' server address is a placeholder -- this is replaced at deploy time. "
            "The shared secret 'cisco' is the default and may not be replaced."
        ),
        "config_file": "conf/jaas.config.radius2",
        "radius_secret": "cisco",
        "debug_mode": True,
        "impact": [
            "RADIUS auth bypass: forge Access-Accept with shared secret 'cisco' if not changed",
            "PAP password recovery: decrypt User-Password from captured RADIUS traffic",
            "debug=true: authentication attempts logged to application log (username exposure)",
        ],
        "remediation": (
            "Require per-deployment RADIUS shared secret configuration. "
            "Remove hardcoded default. Set debug=false in production JAAS config."
        ),
    },
    {
        "id": "F4",
        "title": "before_backup.sh chmod 777 SQL Dir, chmod 666 Log, DB Password in Process Args",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-732",
        "description": (
            "before_backup.sh (run as root before every NCS backup) has three security issues: "
            "(1) World-writable SQL directory: "
            "mkdir -p $SQL_DIR && chmod 777 $SQL_DIR "
            "where $SQL_DIR = /opt/CSCOncs/dbcleanup. "
            "Any local process can write to this directory during backup execution. "
            "The directory contains generated Oracle DDL SQL scripts executed by sqlplus. "
            "A race condition: attacker writes a malicious .sql file to $SQL_DIR between "
            "the mkdir and the sqlplus execution = arbitrary SQL execution as oracle user. "
            "(2) World-readable backup log: "
            "chmod 666 $LOG_FILE "
            "The backup log at /opt/CSCOncs/logs/dbCleanupBackup.log is world-readable, "
            "exposing database schema structure, query timing, and error messages. "
            "(3) DB password in process command line: "
            "getDatabaseParams.sh decrypts dbPasswd.pwd and outputs the plaintext wcsdba "
            "password. before_backup.sh captures it as DBPASSWD and passes it to: "
            "su - oracle -c 'get_ddl_constraints.sh $DBPASSWD $LOG_FILE $SQL_DIR' "
            "The password appears in /proc/*/cmdline while get_ddl_constraints.sh runs, "
            "visible to any process that can read /proc (i.e., any local process). "
            "Note: exploit requires local process execution. On a fresh NCS appliance "
            "the FTP server and potential web application vulnerabilities provide "
            "the local execution path."
        ),
        "affected_script": "bin/before_backup.sh",
        "world_writable_dir": "/opt/CSCOncs/dbcleanup (chmod 777)",
        "world_readable_log": "/opt/CSCOncs/logs/dbCleanupBackup.log (chmod 666)",
        "password_in_args": "wcsdba plaintext password passed via su -c CLI arg",
        "impact": [
            "chmod 777 SQL dir: race condition -> arbitrary SQL as oracle user during backup",
            "chmod 666 log: DB schema and query info world-readable",
            "wcsdba password in /proc/*/cmdline during backup execution",
        ],
        "remediation": (
            "Use a private temp directory (mktemp -d) with restricted permissions. "
            "Pass DB password via environment variable or temp file, not CLI arg. "
            "Set log permissions to 640 (owner only)."
        ),
    },
]

SUMMARY = {
    "total":    4,
    "critical": 1,
    "high":     2,
    "medium":   1,
    "low":      0,
    "notes": (
        "F1 (fleet-wide TLS key) and F2 (SSLv3+RC4) combine into a complete HTTPS MITM chain: "
        "extract server.key from RPM, perform TLS MITM on NCS HTTPS port, "
        "force SSLv3 downgrade for POODLE, recover admin session cookie. "
        "F1 follows the same pattern as Cat9K IOS-XE fallback.key (cisco_catalyst_9k_iosxe_17_18_04_re.py F1) "
        "and CP-6901 DSS fleet key (cisco_6901_sip_sccp_re.py F1) -- Cisco systemic issue. "
        "F3 (RADIUS 'cisco' secret) is exploitable only when the administrator configures "
        "RADIUS authentication and does not change the default. The hardcoded 11.11.11.11 "
        "address confirms this is a template that may be copied verbatim at deploy time. "
        "F4 (backup race + password in args) is a local privilege escalation aid once "
        "any code execution is achieved through the FTP server (ftp-user:ftp-user) or "
        "web application vulnerabilities."
    ),
}
