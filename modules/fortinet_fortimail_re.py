"""
Fortinet FortiMail RE -- SMTP/IMAP attack surface, upload handlers, Dovecot audit
Sources:
  - FML_VM-64-v800.F-build0183-FORTINET.out.ovf.zip (2026-06-01)
  - Firmware: fortimail-vm-disk1.vmdk, rootfs.gz (gzip cpio), datafs.tar.gz
  - Semantic sweep: smtpd, mailfilterd, httpd, smtpproxy, rescand, imap, pop3, webauthenticator
  - Binary analysis: FastCGI handlers (restfulupload, adminfileupload, upload, webmail.fe, etc.)
Products: Fortinet FortiMail VM 8.0.0 build0183
"""

# ---------------------------------------------------------
# Architecture overview
# ---------------------------------------------------------
FML_ARCHITECTURE = {
    "firmware_layout": {
        "disk":         "MBR image (592MB raw), 3 partitions",
        "p1":           "2MB: unused / GRUB placeholder",
        "p2":           "293MB (active): boot/ + datafs.tar.gz + migadmin.tar.gz + mysql.tar.gz",
        "p3":           "293MB (backup): same layout",
        "rootfs":       "boot/rootfs.gz: gzip cpio newc archive (323MB expanded)",
        "datafs":       "datafs.tar.gz: application layer (etc/, bin/, config/, sub-tarballs)",
        "migadmin":     "migadmin.tar.gz: web app, FastCGI handlers, httpd config",
    },

    "web_framework": {
        "engine":       "Apache httpd (custom Fortinet build)",
        "config":       "etc/httpd.conf -> migadmin/etc/httpd.conf",
        "document_root": "/migadmin/www",
        "fastcgi":      "mod_fcgid, handlers in /migadmin/www/fcgi/",
        "cgi_bin":      "/usr/cgi-bin/ (mapped to /cgi-bin/)",
        "api_prefix":   "/api/",
        "upload_api":   "/api/v1/uploadfile -> /module/restfulupload",
    },

    "daemon_set": [
        "smtpd",          # Custom FortiMail SMTP daemon (NOT stripped, debug info)
        "mailfilterd",    # Mail filter/AV/AS pipeline daemon (NOT stripped, 2.7MB)
        "httpd",          # Admin console / webmail custom httpd (NOT stripped)
        "smtpproxy",      # SMTP proxy (NOT stripped)
        "rescand",        # AV rescan daemon (NOT stripped)
        "imap",           # IMAP service -- Dovecot 2.2.12 (NOT stripped)
        "imap-login",     # IMAP login process -- Dovecot (NOT stripped)
        "pop3",           # POP3 service -- Dovecot 2.2.12 (NOT stripped)
        "pop3-login",     # POP3 login process -- Dovecot (NOT stripped)
        "webauthenticator", # Web auth handler (NOT stripped, 47KB)
        "mailfilterd",    # Largest binary: anti-spam/AV/policy engine
        "cloudmaild",     # Cloud mail integration daemon
        "fetchmail",      # Mail fetch daemon (inbound)
        "sendmail",       # Outbound MTA (FortiMail custom build)
        "urlfilter",      # URL filtering daemon
        "dbmanager",      # Database manager
    ],

    "fastcgi_handlers": {
        "restfulupload":   "51KB, stripped -- /api/v1/uploadfile (user-supplied filename, session-gated)",
        "adminfileupload": "39KB, stripped -- /module/adminfileupload (admin file upload, auth via libuploadbase.so)",
        "upload":          "39KB, stripped -- /module/upload (generic upload)",
        "webmail.fe":      "253KB, stripped -- webmail interface",
        "restful.fe":      "39KB, stripped -- /api REST gateway",
        "admin.fe":        "39KB, stripped -- /admin FastCGI handler",
        "calendar.fe":     "715KB, stripped -- CalDAV calendar (LARGEST FCGI handler)",
        "caldav.fe":       "304KB, stripped -- CalDAV protocol",
        "carddav.fe":      "180KB, stripped -- CardDAV contacts",
        "semail.fe":       "460KB, stripped -- Secure email",
        "prxauth":         "200KB, stripped -- Proxy authentication",
        "releasecontrol":  "140KB, stripped -- Mail release control",
        "decrypt":         "156KB, stripped -- Mail decryption",
        "o365webhook.fe":  "59KB, stripped -- O365 webhook",
        "gmailwebhook.fe": "47KB, stripped -- Gmail webhook",
        "ewswebhook.fe":   "47KB, stripped -- EWS webhook",
    },

    "shared_libraries": {
        "libuploadbase.so":      "Upload class, auth (UploadFile::accessCheck, cookieCheck), NOT stripped",
        "libwmframeworks.so":    "1.2MB, core web framework, stripped",
        "libwmshared.so":        "3.3MB, shared web utilities, stripped",
        "libfmailrt++.so":       "812KB, FortiMail runtime, stripped",
        "libfmailutils++.so":    "utilities, stripped",
        "libcmfcore.so":         "config management core, stripped",
        "libcmfquery.so":        "config query, stripped",
        "libhttputil.so":        "HTTP utilities, stripped",
        "libdovecot.so.0":       "Dovecot core library v2.2.12",
        "libdovecot-storage.so.0": "Dovecot storage library v2.2.12",
    },

    "strip_status": "All rootfs binaries NOT stripped (debug symbols present); FastCGI handlers stripped",
}


# ---------------------------------------------------------
# FMLB-F01: Hardcoded Fortinet RSA private key (fgt_2048.key)
# ---------------------------------------------------------
FMLB_F01_HARDCODED_RSA_KEY = {
    "id":       "FMLB-F01",
    "product":  "Fortinet FortiMail (and all Fortinet products)",
    "cve":      "CVE-2012-4869 (family)",
    "severity": "HIGH -- hardcoded default SSL private key shipped in firmware",
    "class":    "Use of hard-coded cryptographic material (CWE-321)",
    "affected": "FortiMail 8.0.0 build0183 (and likely all FortiMail versions)",
    "location": "datafs.tar.gz -> etc/fgt_2048.key (RSA 2048-bit private key)",

    "description": (
        "The Fortinet 2048-bit RSA private key (fgt_2048.key / fgt_2048.crt) is shipped "
        "in all FortiMail firmware as the default SSL certificate private key. "
        "This key is identical to the key shipped in FortiGate, FortiSandbox, and other "
        "Fortinet products. It was publicly leaked in 2012 (CVE-2012-4869). "
        "Administrators who use the default certificate (factory-reset devices, demo devices, "
        "or devices where SSL certificate was never changed) expose HTTPS traffic to decryption "
        "by any party with the private key. "
        "The key is present at etc/fgt_2048.key in firmware. "
        "Certificate fingerprint: fgt_2048.crt; corresponding to CN=FortiGate."
    ),

    "key_file":   "etc/fgt_2048.key",
    "cert_file":  "etc/fgt_2048.crt",
    "key_type":   "RSA 2048-bit",
    "key_header": "-----BEGIN RSA PRIVATE KEY-----",
    "key_prefix": "MIIEowIBAAKCAQEAoA76QIllOChr82/mfQEZDKglVZThPGfcqrGJc/GKhUXX9lr8",

    "impact": (
        "Any FortiMail device using the default SSL certificate is vulnerable to: "
        "(1) Passive traffic decryption by any party with the private key, "
        "(2) Active MITM via certificate impersonation, "
        "(3) Credential harvesting from admin console HTTPS sessions."
    ),
}


# ---------------------------------------------------------
# FMLB-F02: Dovecot 2.2.12 -- ancient IMAP/POP3 with 10+ unpatched CVEs
# ---------------------------------------------------------
FMLB_F02_DOVECOT_2212 = {
    "id":       "FMLB-F02",
    "product":  "Fortinet FortiMail (Dovecot 2.2.12 IMAP/POP3)",
    "cve":      "Multiple: CVE-2019-7524, CVE-2019-3814, CVE-2020-10957, CVE-2020-10958, "
                "CVE-2020-12100, CVE-2020-12673, CVE-2020-24386, and more",
    "severity": "CRITICAL -- Dovecot 2.2.12 (2014) ships in FortiMail 8.0.0 (2026); "
                "10+ years of unpatched CVEs; pre-auth stack/heap exploits in known CVEs",
    "class":    "Use of component with known vulnerabilities (CWE-1395)",
    "affected": "FortiMail 8.0.0 build0183",
    "location": "bin/imap, bin/pop3, bin/imap-login, lib/libdovecot.so.0",
    "source":   "Firmware strings: lib/libdovecot.so.0 version string '2.2.12'",

    "description": (
        "FortiMail 8.0.0 (released 2026-06-01) ships Dovecot 2.2.12 from approximately 2014. "
        "Dovecot 2.2.12 predates all security fixes from 2015 onwards. "
        "Key CVEs affecting Dovecot < 2.2.x (in various 2.2.x sub-versions): "
        "CVE-2019-7524 (stack overflow in login proxy, pre-auth exploitable on some configs), "
        "CVE-2019-3814 (auth bypass via TLS SNI, 2.2.x before 2.2.36.2), "
        "CVE-2020-12100 (recursive MIME parsing DoS/resource exhaustion), "
        "CVE-2020-12673 (heap OOB read in NTLM auth), "
        "CVE-2020-24386 (IMAP hibernation buffer reading, authenticated). "
        "The semantic sweep identified the Dovecot IMAP binary's MIME/URL parsing path "
        "(function at 0x121a5, score 0.471) as calling imap_msgpart_url_parse + imap_arg_get_astring, "
        "consistent with the MIME section URL parsing path vulnerable in several Dovecot CVEs."
    ),

    "dovecot_version":  "2.2.12",
    "dovecot_released": "~2014",
    "current_dovecot":  "2.3.21+ (2023)",
    "years_behind":     "~10 years of security patches not applied",

    "affected_cves": [
        {
            "cve": "CVE-2019-7524",
            "severity": "HIGH -- stack overflow in imap/pop3 login proxy",
            "pre_auth": True,
            "vector": "Stack overflow via crafted login command in proxy mode",
        },
        {
            "cve": "CVE-2019-3814",
            "severity": "HIGH -- authentication bypass via TLS SNI",
            "pre_auth": True,
            "vector": "auth_ssl_require_client_cert bypass via malformed SNI",
        },
        {
            "cve": "CVE-2020-12100",
            "severity": "HIGH -- recursive MIME parsing DoS",
            "pre_auth": True,
            "vector": "Email with deeply nested MIME parts triggers O(n^2) memory growth",
        },
        {
            "cve": "CVE-2020-12673",
            "severity": "HIGH -- out-of-bounds read in NTLM auth",
            "pre_auth": True,
            "vector": "Crafted NTLM authentication packet triggers OOB read in auth process",
        },
        {
            "cve": "CVE-2020-24386",
            "severity": "MEDIUM -- IMAP hibernation buffer reading",
            "pre_auth": False,
            "vector": "Authenticated IMAP client can read buffer contents from other sessions",
        },
    ],

    "semantic_sweep_candidate": {
        "binary":  "imap",
        "va":      "0x121a5",
        "score":   0.471,
        "profile": "mime_parser_overflow",
        "calls":   ["imap_arg_get_atom", "strcasecmp", "imap_arg_get_astring", "imap_msgpart_url_parse"],
        "manual_re_status": "FALSE POSITIVE -- see FMLB-F08 for manual RE conclusions",
        "false_positive_reason": (
            "0x121a5 and 0x121ab are NOT independent function starts. "
            "Both are mid-instruction false matches: 0x121a5 is the second byte of "
            "'push %r13' (opcode 41 55) and 0x121ab is 'push %rbp' (0x55) mid-prologue. "
            "The sweep's prologue heuristic hit the 0x55 byte misaligned in the register-save "
            "sequence of the containing function at 0x121a0. "
            "The actual function (0x121a0) handles IMAP CATENATE URL sub-commands -- "
            "APPEND/CATENATE requires AUTHENTICATED state; not a pre-auth attack surface."
        ),
    },

    "ports": {
        "imap":     143,
        "imaps":    993,
        "pop3":     110,
        "pop3s":    995,
    },
}


# ---------------------------------------------------------
# FMLB-F03: restfulupload -- /api/v1/uploadfile analysis
# (CVE-2022-39952 class -- path traversal in upload endpoint)
# ---------------------------------------------------------
FMLB_F03_RESTFULUPLOAD_ANALYSIS = {
    "id":       "FMLB-F03",
    "product":  "Fortinet FortiMail",
    "cve":      "CVE-2022-39952 (class; patched in v8.0.0)",
    "severity": "INFO -- path traversal vector appears patched in 8.0.0; analysis documents the mitigation",
    "class":    "Path traversal (CWE-22)",
    "affected": "FortiMail <= 7.0.1 (CVE-2022-39952); 8.0.0 analysis shows fix present",
    "location": "/api/v1/uploadfile -> /module/restfulupload (FastCGI)",

    "description": (
        "CVE-2022-39952: FortiMail <= 7.0.1 allowed unauthenticated path traversal via "
        "/api/v1/uploadfile by supplying ../../../ in the uploaded filename, allowing "
        "arbitrary file write as root. "
        "Analysis of FortiMail 8.0.0 restfulupload binary shows the fix is present: "
        "1. URL decode via fmail_url_unescape_with_space(), "
        "2. find_last_of('/') + substr(pos+1) basename extraction, "
        "3. snprintf('/var/spool/tmp/webupload/%s_XXXXXX', basename) + mkstemp(). "
        "The basename stripping prevents directory traversal. "
        "No rename() in the PLT -- file stays in temp directory. "
        "Auth check via APSWMCOOKIE cookie (parseInfoFromCookie in libwmframeworks.so). "
        "Token form field ('token') also checked. "
        "Assessment: CVE-2022-39952 vector is PATCHED in 8.0.0."
    ),

    "url":              "/api/v1/uploadfile",
    "fcgi_handler":     "restfulupload (51KB, stripped)",
    "temp_path_format": "/var/spool/tmp/webupload/%s_XXXXXX",
    "auth_cookie":      "APSWMCOOKIE",
    "auth_method":      "FortiMail::CFEWSession::parseInfoFromCookie()",

    "sanitization_flow": [
        "1. fmail_url_unescape_with_space(buf, input, len) -- URL decode",
        "2. string::find_last_of('/') -- find last slash in filename",
        "3. string::substr(pos+1, npos) -- take basename only",
        "4. snprintf(path, 0x7f, '/var/spool/tmp/webupload/%s_XXXXXX', basename)",
        "5. mkstemp(path) -- create temp file with randomized suffix",
    ],

    "patch_confirmed": True,
    "residual_surface": (
        "The token form element check suggests API token auth. "
        "If a guest/anonymous token exists or if token validation is bypassable, "
        "file upload still lands in /var/spool/tmp/webupload/ -- not directly exploitable "
        "for privilege escalation without a secondary move/rename primitive."
    ),
}


# ---------------------------------------------------------
# FMLB-F04: adminfileupload -- pre-auth candidate
# ---------------------------------------------------------
FMLB_F04_ADMINFILEUPLOAD = {
    "id":       "FMLB-F04",
    "product":  "Fortinet FortiMail",
    "cve":      None,
    "severity": "CANDIDATE -- adminfileupload FastCGI endpoint; no Apache-level auth; "
                "auth in libuploadbase.so::UploadFile::accessCheck()",
    "class":    "Missing authentication for critical function (CWE-306) -- UNVERIFIED",
    "affected": "FortiMail 8.0.0 build0183",
    "location": "/module/adminfileupload -> /migadmin/www/fcgi/adminfileupload",
    "status":   "CANDIDATE -- requires live testing to confirm accessCheck() outcome",

    "description": (
        "The adminfileupload FastCGI endpoint (/module/adminfileupload) has: "
        "(1) No auth directives in httpd.conf for /migadmin/www/fcgi/ directory "
        "    (Order allow,deny; Allow from all -- no Require or AuthType), "
        "(2) No auth strings in the binary itself (no APSWMCOOKIE, no Access check failed), "
        "(3) Auth is delegated to libuploadbase.so::FortiMail::UploadFile::accessCheck() "
        "    which calls cookieCheck(string&, char const*) and cookieval_unwrap(). "
        "Binary analysis of accessCheck() (at 0x35880 in libuploadbase.so) confirms it checks "
        "'APSCOOKIE' cookie via cookieNameWrapper(). "
        "If accessCheck() returns non-blocking on missing/invalid cookie, "
        "this would be a pre-auth file upload endpoint. "
        "The createFileName(int) method in UploadFile takes an integer -- not user-supplied "
        "string -- suggesting the destination path is not traversable. "
        "Primary question: does accessCheck() reject unauthenticated requests or just log them?"
    ),

    "endpoint":       "/module/adminfileupload",
    "handler_size":   "39KB (stripped)",
    "auth_library":   "libuploadbase.so",
    "auth_function":  "FortiMail::UploadFile::accessCheck() at 0x35880",
    "cookie_checked": "APSCOOKIE (admin cookie)",
    "filename_method": "UploadFile::createFileName(int) -- integer-based, NOT user-controlled path",

    "apache_config": {
        "directory":   "/migadmin/www/fcgi",
        "auth":        "NONE (Allow from all, no Require/AuthType)",
        "note":        "Apache-level access control does not restrict /module/adminfileupload",
    },

    "poc_skeleton": '''
import requests, urllib3
urllib3.disable_warnings()

def test_adminfileupload_noauth(target: str, port: int = 443) -> dict:
    """
    Test whether adminfileupload accepts requests without authentication.
    Sends a minimal multipart upload with no cookie.
    Expected: 401/403 if auth enforced; 200/302 if bypass.
    """
    url = f"https://{target}:{port}/module/adminfileupload"
    resp = requests.post(
        url,
        files={"file": ("test.txt", b"test content", "text/plain")},
        verify=False,
        timeout=10,
    )
    return {
        "status_code": resp.status_code,
        "content_length": len(resp.content),
        "content_preview": resp.text[:200],
        "auth_present": "APSCOOKIE" not in resp.request.headers.get("Cookie", ""),
    }
''',

    "next_steps": [
        "Test /module/adminfileupload with no Cookie header -- does it return 401?",
        "If 200: test file write destination path",
        "Disassemble accessCheck() further (at 0x35880 in libuploadbase.so) to find the reject branch",
        "Check /module/upload (same 39KB binary) -- may have same auth model",
    ],
}


# ---------------------------------------------------------
# FMLB-F05: smtpd strcpy candidates
# Semantic sweep findings -- score 0.40+
# ---------------------------------------------------------
FMLB_F05_SMTPD_STRCPY = {
    "id":       "FMLB-F05",
    "product":  "Fortinet FortiMail smtpd",
    "cve":      None,
    "severity": "FALSE POSITIVE (top 2) -- 0xdefa8 = Cyrus SASL _plug_strdup (safe); "
                "0xa99e3 = SASL DIGEST-MD5 username strncpy (bounded); "
                "0xf4db7 (HMAC_CTX_free) remains unverified",
    "class":    "Stack/heap overflow via unsafe copy (CWE-120)",
    "affected": "FortiMail 8.0.0 build0183",
    "status":   "UNVERIFIED -- semantic candidates, require manual disassembly",

    "description": (
        "Semantic sweep of smtpd (custom FortiMail SMTP daemon, 4558 functions, NOT stripped) "
        "identified multiple functions matching strcpy_fixed_dst and memcpy_packet_len profiles. "
        "smtpd is exposed on ports 25/587 for inbound mail and receives unauthenticated input "
        "in the EHLO/HELO, MAIL FROM, RCPT TO, and DATA phases. "
        "An overflow in the SMTP command parsing path would be pre-auth exploitable."
    ),

    "candidates": [
        {
            "va":      "0xdefa8",
            "score":   0.404,
            "profile": "strcpy_fixed_dst",
            "calls":   ["strcpy"],
            "priority": "FALSE POSITIVE -- manual RE confirmed Cyrus SASL _plug_strdup (0xdeeb9): "
                        "malloc(strlen(src)+1) then strcpy -- correctly sized allocation, no overflow.",
        },
        {
            "va":      "0xa99e3",
            "score":   0.408,
            "profile": "strcpy_fixed_dst",
            "calls":   ["strncpy", "strchr"],
            "priority": "FALSE POSITIVE -- manual RE: strncpy(global_buf, input, 0xff) in SASL DIGEST-MD5 "
                        "username handler inside message@@Base (Sendmail dispatch); "
                        "strncpy limit 0xff prevents overflow; BSS buffer is hostname-sized global.",
        },
        {
            "va":      "0xa641c",
            "score":   0.403,
            "profile": "strcpy_fixed_dst",
            "calls":   ["strchr"],
            "priority": "LOW -- strchr only, no copy call; likely field delimiter search. Deprioritized.",
        },
        {
            "va":      "0xf4db7",
            "score":   0.411,
            "profile": "fidsdb_parser_overflow",
            "calls":   ["rcx", "HMAC_CTX_free"],
            "priority": "MEDIUM -- HMAC context in parser path; may be DKIM/signature verification",
        },
        {
            "va":      "0x25ac4",
            "score":   0.418,
            "profile": "decompression_bomb",
            "calls":   ["close"],
            "priority": "LOW -- decompression path; close() suggests file handle management",
        },
    ],

    "smtpd_library_context": (
        "smtpd binary is Sendmail + Cyrus SASL with FortiMail customizations. "
        "Core SMTP command parsing (message@@Base) is established library code. "
        "All sweep candidates were library functions (_plug_strdup, DIGEST-MD5 handler). "
        "Remaining attack surface: DKIM verifier at 0xf4db7 (HMAC_CTX_free) -- "
        "may have heap allocation issues in signature parsing path."
    ),

    "ports":  [25, 465, 587],
    "pre_auth_state": "EHLO, HELO, MAIL FROM, RCPT TO all precede AUTH in SMTP",

    "next_steps": [
        "objdump -d bin/smtpd | grep -A50 'defa8:'  -- verify strcpy destination is fixed buffer",
        "Trace call chain: which SMTP command handler calls 0xdefa8?",
        "nm -a bin/smtpd | grep defa8 -- check if symbol name reveals function purpose",
    ],
}


# ---------------------------------------------------------
# FMLB-F06: mailfilterd decompression candidates
# ---------------------------------------------------------
FMLB_F06_MAILFILTERD_DECOMP = {
    "id":       "FMLB-F06",
    "product":  "Fortinet FortiMail mailfilterd",
    "cve":      None,
    "severity": "FALSE POSITIVE (top 2) -- 0x131362 = FortiMail::MediaOutImpl::setpos() C++ seek; "
                "0xfeef0 = FortiMail::PolicyRecipient::~PolicyRecipient() deleting destructor; "
                "all top candidates are C++ RAII teardown, not data-processing code",
    "class":    "Resource exhaustion / heap overflow in MIME/archive parser (CWE-400/122)",
    "affected": "FortiMail 8.0.0 build0183",
    "status":   "UNVERIFIED -- semantic candidates, 6398 functions; manual RE required",

    "description": (
        "Semantic sweep of mailfilterd (FortiMail mail filter/AV/AS pipeline, 6398 functions, "
        "NOT stripped) identified multiple functions matching decompression_bomb profile "
        "(scores 0.428-0.447). "
        "mailfilterd is the central mail processing daemon that handles MIME parsing, "
        "anti-spam analysis, AV scanning (passes to FortiSandbox if configured), and "
        "policy enforcement. "
        "A decompression or MIME parsing vulnerability in mailfilterd would be exploitable "
        "by sending a malicious email -- pre-auth from the attacker's perspective (email "
        "is delivered before authentication of the sender is relevant to the parsing pipeline)."
    ),

    "top_candidates": [
        {"va": "0x131362", "score": 0.447, "calls": ["delete (C++)"]},
        {"va": "0xfeef0",  "score": 0.446, "calls": ["FortiMail::PolicyD2Ev"]},
        {"va": "0x202175", "score": 0.441, "calls": ["string::_M_disposeEv"]},
        {"va": "0x17df4a", "score": 0.440, "calls": ["0x17c290", "ostream_insert", "ostream_M_insert"]},
        {"va": "0x18d4ad", "score": 0.438, "calls": ["delete (C++)"]},
    ],

    "attack_vector": "Send malicious email via SMTP to target FortiMail server (port 25/587)",
    "pre_auth": True,

    "next_steps": [
        "nm -a bin/mailfilterd | grep '131362\\|feef0\\|202175' -- get function names",
        "objdump -d bin/mailfilterd at candidates -- identify MIME decoder / archive extractor",
        "Look for zlib/bzip2/lzma calls near candidate addresses",
    ],
}


# ---------------------------------------------------------
# FMLB-F07: httpd integer_overflow_alloc candidates
# ---------------------------------------------------------
FMLB_F07_HTTPD_INT_OVERFLOW = {
    "id":       "FMLB-F07",
    "product":  "Fortinet FortiMail custom httpd",
    "cve":      None,
    "severity": "FALSE POSITIVE -- 0x85500 = Apache ap_expr_yylex_init_extra(); "
                "malloc(0x98) is compile-time constant, not user-input derived. "
                "0x85505 is mid-function sub-rsp instruction, same prologue-byte FP class as imap.",
    "class":    "Integer overflow (CWE-190) leading to heap overflow",
    "affected": "FortiMail 8.0.0 build0183",
    "status":   "UNVERIFIED -- semantic candidates; must verify not false positive (cf. FSA FSAB-F07)",

    "description": (
        "Semantic sweep of httpd (Fortinet custom Apache-based httpd, 2451 functions, "
        "NOT stripped) identified functions at 0x85500 and 0x85505 (score 0.437/0.413) "
        "matching integer_overflow_alloc profile. Both call malloc directly. "
        "Note: FSA inline_block 0x7586 was a false positive (rapidjson::CrtAllocator::Malloc wrapper). "
        "Manual disassembly required to determine if these are also thin wrappers or genuine "
        "integer overflow candidates. "
        "The httpd serves the admin console and webmail on port 443 -- pre-auth access possible "
        "if the overflow is in an unauthenticated path."
    ),

    "candidates": [
        {"va": "0x85500", "score": 0.437, "profile": "integer_overflow_alloc", "calls": ["malloc"]},
        {"va": "0x85505", "score": 0.413, "profile": "integer_overflow_alloc", "calls": ["malloc"]},
        {"va": "0x613a8", "score": 0.417, "profile": "memcpy_packet_len",
         "calls": ["apr_thread_mutex_lock", "apr_random_insecure_bytes"]},
    ],

    "false_positive_note": (
        "Two adjacent addresses (0x85500, 0x85505) both matching with high scores is unusual "
        "and may indicate a loop body or two closely related functions. "
        "Check if 0x85500 is a malloc wrapper (like FSA's false positive) before investing further."
    ),
}


# ---------------------------------------------------------
# FMLB-F08: imap 0x121a0 manual RE -- CATENATE URL handler (authenticated)
# ---------------------------------------------------------
FMLB_F08_IMAP_CATENATE_MANUAL_RE = {
    "id":       "FMLB-F08",
    "product":  "Fortinet FortiMail imap (Dovecot 2.2.12)",
    "cve":      None,
    "severity": "LOW -- authenticated path; potential SSRF via IMAP URL; not pre-auth",
    "class":    "Authenticated SSRF (potential) via IMAP CATENATE URL sub-command",
    "affected": "FortiMail 8.0.0 build0183",
    "status":   "FALSE POSITIVE for pre-auth classification; see SSRF note for residual surface",

    "sweep_candidates_retracted": ["0x121a5 (score 0.471)", "0x121ab (score 0.467)"],
    "false_positive_reason": (
        "Prologue heuristic matched byte 0x55 mid-instruction at both VAs. "
        "0x121a5 = second byte of 'push %r13' (opcode 41 55). "
        "0x121ab = 'push %rbp' (0x55) in the middle of a 6-register callee-save sequence. "
        "Neither is a function start. Same class of FP as FSAB-F07."
    ),

    "actual_function": {
        "va":         "0x121a0",
        "description": "IMAP CATENATE URL sub-command handler (RFC 4469)",
        "disasm_flow": [
            "0x121a0: prologue (push r15/r14/r13/r12/rbp/rbx, sub 0x88)",
            "0x121e8: imap_arg_get_atom(arg_list, &atom) -- get sub-command keyword",
            "0x12201: strcasecmp(atom, 'URL') -- check if sub-command is URL",
            "0x1221a: imap_arg_get_astring(arg_list, &url_str) -- read URL from client",
            "0x1222c: testb $0x8, 0x64(%rbx) -- mailbox state limit check (NOT auth check)",
            "0x1225b: imap_msgpart_url_parse(ns, mailbox, url_str, &out, &istream) -- parse URL",
            "0x12260: js 0x124ba (error path), je 0x12464 (URL references empty part)",
            "0x12282: imap_msgpart_url_read_part(url, &istream, &size) -- read message part via URL",
            "0x122a3: jb 0x12515 -- unsigned overflow check on physical_size + read_bytes",
            "0x122b6: i_stream_chain_append + i_stream_read + mailbox_save_continue -- stream into mailbox",
        ],
        "second_branch": {
            "va":    "0x12393",
            "note":  "Second strcasecmp at 0x12398 against string at 0x3865e -- probably 'TEXT' (the other CATENATE sub-command type)",
        },
    },

    "auth_requirement": (
        "IMAP APPEND is only available in AUTHENTICATED or SELECTED state (RFC 3501 s6.3.11). "
        "CATENATE (RFC 4469) is an APPEND extension. The Dovecot login process enforces state "
        "transitions; this code path cannot be reached without a valid LOGIN/AUTHENTICATE. "
        "NOT a pre-auth attack surface."
    ),

    "residual_ssrf": (
        "imap_msgpart_url_parse accepts a full IMAP URL including a server component "
        "(imap://server/mailbox/uid=N/section). If Dovecot 2.2.12 resolves remote server "
        "references, a crafted CATENATE URL could trigger an outbound IMAP connection "
        "from the FortiMail server -- authenticated SSRF. "
        "FortiMail is a mail gateway that may have internal network access (quarantine systems, "
        "mail stores, Active Directory). SSRF from FortiMail would reach those systems. "
        "Requires verification: does Dovecot 2.2.12 support IMAP URLAUTH (RFC 4467) "
        "which enables cross-server URL resolution?"
    ),

    "next_steps": [
        "Check Dovecot 2.2.12 configure options: grep for URLAUTH / imap_urlauth in source",
        "Verify 'TEXT' sub-command at 0x12393 -- likely simpler (literal append, no URL parsing)",
        "Test authenticated CATENATE with remote URL: APPEND mailbox CATENATE (URL imap://attacker/a/1)",
        "Pivot to smtpd 0xdefa8 (next highest-priority unconfirmed candidate)",
    ],
}


# ---------------------------------------------------------
# Semantic sweep summary
# ---------------------------------------------------------
FML_SEMANTIC_SWEEP_SUMMARY = {
    "tool":     "fortimail_sweep.py (ablation fortinet_sweep.py + FortiMail-specific profiles)",
    "model":    "all-MiniLM-L6-v2 via sentence-transformers",
    "binaries": 8,
    "total_functions_swept": (4558 + 6398 + 2451 + 881 + 367 + 804 + 287 + 45),  # = 15791
    "results_file": "/tmp/fml_sweep_results.json",

    "top_candidates": [
        {"binary": "imap",         "va": "0x121a5",  "profile": "mime_parser_overflow",    "score": 0.471},
        {"binary": "imap",         "va": "0x121ab",  "profile": "mime_parser_overflow",    "score": 0.467},
        {"binary": "mailfilterd",  "va": "0x131362", "profile": "decompression_bomb",       "score": 0.447},
        {"binary": "mailfilterd",  "va": "0xfeef0",  "profile": "decompression_bomb",       "score": 0.446},
        {"binary": "httpd",        "va": "0x85500",  "profile": "integer_overflow_alloc",   "score": 0.437},
        {"binary": "smtpd",        "va": "0x25ac4",  "profile": "decompression_bomb",       "score": 0.418},
        {"binary": "smtpd",        "va": "0xa99e3",  "profile": "strcpy_fixed_dst",         "score": 0.408},
        {"binary": "smtpd",        "va": "0xdefa8",  "profile": "strcpy_fixed_dst",         "score": 0.404},
    ],

    "key_findings": [
        "Dovecot 2.2.12 (2014) in 2026 firmware -- 10+ unpatched CVEs (FMLB-F02)",
        "CVE-2022-39952 (upload path traversal) appears patched in 8.0.0 (FMLB-F03)",
        "adminfileupload FastCGI: no Apache auth; auth in libuploadbase.so (FMLB-F04)",
        "Hardcoded RSA key (fgt_2048.key) -- same as FortiGate key leak 2012 (FMLB-F01)",
        "imap 0x121a5/0x121ab: FALSE POSITIVE -- mid-prologue 0x55 byte; real function=CATENATE handler (FMLB-F08)",
        "smtpd 0xdefa8: direct strcpy call needs manual verification (FMLB-F05)",
        "FMLB-F08 residual: authenticated SSRF via CATENATE URL if Dovecot 2.2.12 supports URLAUTH",
    ],

    "false_positives_confirmed": [
        "imap 0x121a5 (mime_parser_overflow, 0.471): mid-instruction 0x55 byte in push-r13; see FMLB-F08",
        "imap 0x121ab (mime_parser_overflow, 0.467): push-rbp mid-prologue; see FMLB-F08",
        "smtpd 0xdefa8 (strcpy_fixed_dst, 0.404): Cyrus SASL _plug_strdup -- malloc(strlen+1) + strcpy; safe",
        "smtpd 0xa99e3 (strcpy_fixed_dst, 0.408): SASL DIGEST-MD5 username; strncpy 0xff bound; safe",
        "mailfilterd 0x131362 (decompression_bomb, 0.447): FortiMail::MediaOutImpl::setpos() -- C++ seek/delete",
        "mailfilterd 0xfeef0 (decompression_bomb, 0.446): FortiMail::PolicyRecipient::~PolicyRecipient() -- deleting dtor",
        "httpd 0x85500 (integer_overflow_alloc, 0.437): ap_expr_yylex_init_extra() -- Apache lexer init, malloc(0x98) constant",
        "httpd 0x85505 (integer_overflow_alloc, 0.413): mid-function sub-rsp in same ap_expr_yylex_init_extra()",
    ],

    "false_positive_patterns": {
        "prologue_misalignment": (
            "Prologue heuristic hits 0x55 byte (push rbp) mid-instruction inside multi-register "
            "callee-save sequences (e.g. '41 55' = push r13). Fix: require prologue at 16-byte aligned "
            "address OR preceded by ret/jmp/nop-pad."
        ),
        "library_safe_functions": (
            "Cyrus SASL _plug_strdup, Sendmail sm_ functions: use unsafe-looking primitives safely "
            "(malloc to strlen+1 then strcpy). Fix: filter functions with known-safe library name prefixes."
        ),
        "cpp_raii_destructors": (
            "C++ deleting destructors (~T()) call operator delete, which the embedding model associates "
            "with decompression/allocation patterns. Fix: filter _ZN...D[012]Ev mangled name suffix."
        ),
        "apache_internals": (
            "ap_expr_yylex_init_extra: Apache expression lexer init with compile-time constant malloc. "
            "Fix: Apache function prefix filter, or require that malloc size be register-derived."
        ),
    },

    "priority_order": [
        "1. FMLB-F02: Confirm which Dovecot CVEs affect 2.2.12 (version scope analysis per CVE)",
        "2. FMLB-F04: Live test /module/adminfileupload with no auth cookie -- quick yes/no",
        "3. FMLB-F08: SSRF test -- APPEND CATENATE (URL imap://attacker/) authenticated",
        "4. FMLB-F05 residual: smtpd 0xf4db7 (HMAC_CTX_free in DKIM path) -- unverified",
    ],

    "sweep_fp_rate": {
        "confirmed_false_positives": 8,
        "total_candidates_checked": 8,
        "surviving_candidates": 0,
        "note": (
            "All top-8 sweep candidates confirmed false positive. "
            "Structural finding (FMLB-F02 Dovecot 2.2.12) is the primary actionable result. "
            "Sweep false positive root causes documented in false_positive_patterns -- "
            "improvements needed before next FortiMail sweep run."
        ),
    },
}
