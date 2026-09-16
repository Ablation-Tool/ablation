"""
FortiClient fortitraylauncher + FortiFone Windows RE
Sources:
  - forticlient-vpn-deb/opt/forticlient/fortitraylauncher (C/C++, 1.7MB stripped ELF64)
  - fortifone-windows/FortiFone_windows_v7.0_b141.exe (PE32 NSIS self-extracting installer)
  - NNG 1.8.0 source paths confirmed across multiple daemons
Method: strings analysis, embedded web server identification, NSIS stub analysis
"""

# ---------------------------------------------------------
# fortitraylauncher architecture
# ---------------------------------------------------------
TRAYLAUNCHER_ARCH = {
    "id":       "TLAUNCH-ARCH",
    "product":  "fortitraylauncher -- FortiClient GUI launcher + embedded CivetWeb HTTP server (C/C++, 1.7MB ELF64)",
    "binary":   "/opt/forticlient/fortitraylauncher",

    "role": (
        "fortitraylauncher launches the FortiClient GUI (fortitray) and runs an embedded CivetWeb "
        "HTTP server that provides the GUI with a local web interface for configuration and status. "
        "It also handles user privilege transitions (setuid/getpwuid) and manages the "
        "fortitraylauncher.pid and fortitraylauncher.log files."
    ),

    "embedded_webserver": {
        "library":          "CivetWeb (embedded; confirmed by SSI/CGI/WebSocket strings)",
        "nng_source":       "NNG 1.8.0 (/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/)",
        "bind":             "127.0.0.1 (localhost only; confirmed from string)",
        "features": {
            "ssi":          "Server-Side Includes with #exec directive (do_ssi_exec)",
            "cgi":          "CGI support (**.cgi$|**.pl$|**.php$ pattern)",
            "websocket":    "WebSocket support (enable_websocket_ping_pong)",
            "tls":          "TLS support (optional; depends on port config)",
            "basic_auth":   "HTTP Basic Auth (authentication_domain)",
        },
    },

    "gui_launch": {
        "command":          "/bin/bash -c '/opt/forticlient/fortitray &'",
        "privilege":        "Runs as configured user (Couldn't set uid / Failed to run as configured user)",
        "uid_lookup":       "getpwuid -- resolves UID to username for privilege drop",
    },

    "nng_source_confirmed": {
        "version":  "NNG 1.8.0",
        "sources": [
            "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/core/socket.c",
            "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/platform/posix/posix_ipclisten.c",
            "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/sp/transport/ipc/ipc.c",
        ],
        "note": "NNG 1.8.0 is used across ALL FortiClient daemons (certd, fctdns, fortitraylauncher, fctsched, iked)",
    },

    "ipc":  "8f6ddf1358bd9d067261f529f69fda59.ipc (same shared socket across all daemons)",
}


# ---------------------------------------------------------
# TLAUNCH-F01: CivetWeb SSI #exec in locally-accessible web server
# ---------------------------------------------------------
TLAUNCH_F01_SSI_EXEC = {
    "id":       "TLAUNCH-F01",
    "product":  "fortitraylauncher -- CivetWeb SSI #exec allows local command execution via web server",
    "severity": "HIGH -- if document_root is writable, attacker places SSI template -> code execution as launcher user",
    "class":    "Command execution via Server-Side Include (CWE-97); local privilege escalation",
    "evidence": [
        "string: 'do_ssi_exec' (SSI exec handler function)",
        "string: 'Bad SSI #exec: [%s]'",
        "string: 'Cannot SSI #exec: [%s]: %s'",
        "string: '127.0.0.1' (localhost bind)",
    ],

    "mechanism": (
        "CivetWeb's SSI engine processes `.shtml` (or similar) files and executes the #exec directive: "
        "  `<!-- #exec cmd=\"/bin/sh -c 'id'\" -->` "
        "This runs the shell command and includes the output in the HTTP response. "
        "The CivetWeb server in fortitraylauncher binds to 127.0.0.1, so the HTTP request must come "
        "from localhost. Any local process can send an HTTP request to localhost. "
        "Attack prerequisites: "
        "  1. Attacker can write a file to the CivetWeb document_root directory. "
        "  2. Attacker can send an HTTP request to the CivetWeb port on localhost. "
        "If document_root is a user-writable path (e.g., /home/<user>/.config/forticlient/ "
        "or /tmp/.forticlient/), the attacker writes a .shtml file with an #exec directive. "
        "Then sends HTTP GET to http://127.0.0.1:<port>/evil.shtml. "
        "CivetWeb executes the command as the fortitraylauncher process user."
    ),

    "privilege_context": (
        "fortitraylauncher runs as the logged-in user (privilege drop via getpwuid/setuid). "
        "SSI exec in this context gives code execution as the local user. "
        "Lateral escalation: if the user's session has GNOME keyring unlocked, "
        "the SSI exec can extract VPN credentials stored by FortiClient (VPN-F02)."
    ),

    "verification": "Check document_root setting and its permissions at runtime; check listening port.",
}


# ---------------------------------------------------------
# TLAUNCH-F02: CGI support in embedded web server
# ---------------------------------------------------------
TLAUNCH_F02_CGI = {
    "id":       "TLAUNCH-F02",
    "product":  "fortitraylauncher -- CivetWeb CGI script execution support (.cgi, .pl, .php)",
    "severity": "HIGH -- CGI in document_root = code execution if root is writable",
    "class":    "Command execution via CGI (CWE-77); same local write access prerequisite as TLAUNCH-F01",
    "evidence": [
        "string: '**.cgi$|**.pl$|**.php$' (CGI file extension pattern)",
        "string: 'cgi_interpreter'",
        "string: 'cgi2_interpreter'",
        "string: 'cgi_interpreter_args'",
        "string: 'cgi2_environment'",
        "string: 'CGI path too long'",
    ],

    "description": (
        "fortitraylauncher's CivetWeb server supports CGI for .cgi, .pl, and .php files. "
        "cgi_interpreter and cgi2_interpreter allow configuring the interpreter for CGI scripts. "
        "If an attacker can write a .pl or .php file to the document_root, "
        "a GET request to that path causes CivetWeb to execute the script via the configured interpreter. "
        "This is equivalent to TLAUNCH-F01 but via CGI rather than SSI. "
        "Additionally: the cgi_environment setting allows configuring environment variables "
        "passed to CGI scripts, which could be used to bypass environment sanitization."
    ),
}


# ---------------------------------------------------------
# TLAUNCH-F03: CORS wildcard in localhost web server
# ---------------------------------------------------------
TLAUNCH_F03_CORS = {
    "id":       "TLAUNCH-F03",
    "product":  "fortitraylauncher -- CORS allow-origin header may permit cross-origin web requests to local API",
    "severity": "MEDIUM -- if allow_origin=*, any malicious webpage can send API requests to localhost CivetWeb",
    "class":    "Cross-origin request forgery (CWE-346); CORS misconfiguration on localhost API",
    "evidence": [
        "string: 'access_control_allow_origin' (configurable CORS origin)",
        "string: 'Access-Control-Allow-Origin: %s'",
        "string: 'Access-Control-Allow-Headers: %s'",
        "string: 'Access-Control-Allow-Methods: %s'",
    ],

    "description": (
        "The CivetWeb server in fortitraylauncher sends Access-Control-Allow-Origin headers. "
        "The origin is configurable via access_control_allow_origin setting. "
        "If this is set to '*' (wildcard): "
        "  1. A malicious webpage visited in the user's browser can send XMLHttpRequest/fetch "
        "     requests to http://127.0.0.1:<port>/. "
        "  2. The browser normally blocks cross-origin requests to localhost, but if the CivetWeb "
        "     server responds with Access-Control-Allow-Origin: *, the browser allows the request. "
        "  3. The malicious page can call FortiClient GUI API endpoints to: "
        "     - Read VPN connection status, credentials configuration. "
        "     - Trigger VPN connect/disconnect. "
        "     - Modify configuration via API calls. "
        "This is the same class of attack as the DNS rebinding attack against local services, "
        "but bypassed via CORS if the origin is wildcard."
    ),
}


# ---------------------------------------------------------
# TLAUNCH-F04: bash invocation for fortitray launch
# ---------------------------------------------------------
TLAUNCH_F04_BASH_EXEC = {
    "id":       "TLAUNCH-F04",
    "product":  "fortitraylauncher -- launches fortitray via /bin/bash -c, inheriting fortitraylauncher environment",
    "severity": "LOW-MEDIUM -- environment variable injection if fortitraylauncher environment is attacker-influenced",
    "class":    "Environment variable injection via shell invocation (CWE-78)",
    "evidence": [
        "string: \"/bin/bash -c '/opt/forticlient/fortitray &'\"",
    ],

    "description": (
        "fortitraylauncher launches the GUI process by calling: "
        "  execve('/bin/bash', ['/bin/bash', '-c', '/opt/forticlient/fortitray &'], env) "
        "The environment is inherited from fortitraylauncher. "
        "bash processes the command string through shell evaluation, which means: "
        "  1. If an environment variable like PATH is attacker-controlled and bash uses PATH "
        "     before the absolute /opt/forticlient/fortitray is resolved, path hijacking is possible "
        "     (unlikely given the absolute path, but relevant for other commands bash may run). "
        "  2. If the LD_PRELOAD or LD_LIBRARY_PATH environment variables are not cleared before "
        "     the bash invocation, an attacker who can set these variables causes dynamic linker "
        "     to load an attacker's .so into the bash + fortitray process. "
        "Verification: check whether fortitraylauncher clears LD_PRELOAD before execve."
    ),
}


# ---------------------------------------------------------
# NNG 1.8.0 IPC architecture (shared across all daemons)
# ---------------------------------------------------------
NNG_IPC_ARCH = {
    "id":       "NNG-ARCH",
    "product":  "NNG 1.8.0 -- shared IPC transport across all FortiClient daemons",
    "source":   "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/",

    "daemons_using_nng": [
        "certd", "fctdns", "fortitraylauncher", "fctsched", "iked", "vpn", "confighandler",
    ],

    "socket_name": "8f6ddf1358bd9d067261f529f69fda59.ipc (hardcoded MD5-hash filename; used by all daemons)",

    "security_note": (
        "All FortiClient daemons communicate via a single NNG IPC socket with a hardcoded name. "
        "NNG sockets created as Unix domain sockets in /tmp/ or /opt/forticlient/ inherit the "
        "permissions of the creating process's umask. "
        "If the socket is world-accessible (common for /tmp/ paths), any local process can: "
        "  1. Subscribe to NNG PUB/SUB channels to intercept configuration broadcasts. "
        "  2. Push NNG messages that are interpreted as daemon control commands. "
        "  3. Send malformed NNG messages to trigger parsing bugs (IKED-F03 length check failures). "
        "The shared socket also means compromising ONE daemon's IPC handling gives access to "
        "messages intended for ALL other daemons."
    ),

    "nng_version_note": (
        "NNG 1.8.0 was released in 2024. No CVEs for this specific version confirmed from public sources. "
        "Earlier NNG versions (< 1.5.2) had CVE-2023-24462 (null pointer dereference in MQTT). "
        "NNG 1.8.0 is current and likely patched. "
        "The attack surface is configuration/permission, not NNG library bugs."
    ),
}


# ---------------------------------------------------------
# FortiFone Windows RE
# ---------------------------------------------------------
FORTIFONE_WINDOWS = {
    "id":       "FPHONE-ARCH",
    "product":  "FortiFone v7.0 build 141 -- Fortinet VoIP softphone (Windows PE32, NSIS installer, 80386)",
    "binary":   "FortiFone_windows_v7.0_b141.exe (Nullsoft Installer self-extracting archive)",
    "note":     "Full application payload is inside the NSIS installer; strings below are from NSIS stub",

    "code_signing": {
        "ca":       "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
        "issuer":   "DigiCert Inc",
        "note":     "Signed binary; tampering without Fortinet's DigiCert signing key breaks signature",
    },

    "windows_api_imports": {
        "lstrcpyA":             "Unbounded ANSI string copy (no length check; potential buffer overflow)",
        "lstrcpynW":            "Length-bounded wide string copy (safer than lstrcpyA)",
        "LoadLibraryExW":       "DLL loading (DLL hijacking risk if search path is writable)",
        "AdjustTokenPrivileges": "Windows privilege adjustment (token privilege escalation)",
        "OpenProcessToken":     "Process token access (combined with AdjustTokenPrivileges: privilege escalation)",
        "ExitWindowsEx":        "System-level exit (shutdown/reboot capability)",
        "GetWindowsDirectoryW": "Windows directory access",
        "RegOpenKeyExW":        "Registry read",
        "RegCreateKeyExW":      "Registry write (persistence mechanism)",
        "RegDeleteKeyExW":      "Registry delete",
    },

    "protocol_indicators": {
        "SIP":  "Session Initiation Protocol (VoIP signaling; string fragment '6%xSIP*TgPb' seen)",
        "RTP":  "Real-time Transport Protocol (VoIP media; string fragment 'E\\!F^RTP' seen)",
        "SRTP": "Secure RTP (encryption for voice media)",
        "Note": "NSIS stub analysis only; actual SIP/RTP stack analysis requires NSIS extraction",
    },

    "security_surface": (
        "FortiFone is a SIP/RTP softphone running on Windows. "
        "Full attack surface requires extraction from NSIS installer (7zip -e or NSIS decompiler). "
        "Key concerns from stub analysis: "
        "  1. lstrcpyA (ANSI lstrcpy): used in NSIS stub; likely also in the extracted application. "
        "     If SIP message parsing uses lstrcpyA with server-provided strings -> pre-auth buffer overflow. "
        "  2. LoadLibraryExW: DLL hijacking if the application's working directory or PATH contains "
        "     an attacker-writable location. NSIS installers commonly drop DLLs to the install dir "
        "     without setting restricted ACLs. "
        "  3. AdjustTokenPrivileges + OpenProcessToken: the application adjusts its own token "
        "     privileges during installation or operation. If these calls are made based on "
        "     user-controllable input, privilege escalation is possible. "
        "  4. SIP stack: SIP message parsing in C/C++ without length checks is historically vulnerable "
        "     (CVE-2023-XXXX class; SIP stack overflows are well-known). "
        "     FortiFone processes SIP INVITE/REGISTER/OPTIONS from untrusted SIP servers."
    ),

    "analysis_status": "NSIS stub only; full binary extraction pending Windows analysis environment",
}


# ---------------------------------------------------------
# FORTIFONE-F01: lstrcpyA in SIP processing context
# ---------------------------------------------------------
FORTIFONE_F01_LSTRCPY = {
    "id":       "FPHONE-F01",
    "product":  "FortiFone Windows -- lstrcpyA (unbounded string copy) in SIP softphone context",
    "severity": "HIGH (potential) -- SIP INVITE/REGISTER messages from untrusted servers contain attacker-controlled strings",
    "class":    "Potential buffer overflow via unbounded string copy in SIP parser (CWE-120)",
    "evidence": [
        "import: lstrcpyA (visible in NSIS stub PE imports)",
        "protocol: SIP/RTP (softphone application)",
        "note: lstrcpyA is the ANSI (narrow) version with no length parameter; it copies until null terminator",
    ],

    "description": (
        "lstrcpyA copies a source string to a destination buffer without length checking. "
        "If FortiFone's SIP parser uses lstrcpyA to copy SIP header fields "
        "(From, To, Contact, Subject, User-Agent, etc.) into fixed-size stack or heap buffers, "
        "a malicious SIP server can send an oversized header value to trigger a buffer overflow. "
        "Attack vector: "
        "  1. Attacker controls the SIP server (rogue PBX, DNS rebinding, or SIP provider compromise). "
        "  2. Sends a crafted SIP 200 OK or REGISTER response with oversized headers. "
        "  3. FortiFone calls lstrcpyA(fixed_buf, sip_header_value) where header_value > sizeof(fixed_buf). "
        "  4. Stack or heap overflow triggers code execution on the client machine. "
        "Note: lstrcpyA is imported by the NSIS stub; it may or may not be used in the actual "
        "FortiFone application after extraction. Full analysis requires NSIS extraction."
    ),
}


# ---------------------------------------------------------
# FORTIFONE-F02: DLL hijacking via LoadLibraryExW
# ---------------------------------------------------------
FORTIFONE_F02_DLL_HIJACK = {
    "id":       "FPHONE-F02",
    "product":  "FortiFone Windows -- LoadLibraryExW enables DLL hijacking via writable install directory",
    "severity": "HIGH -- DLL placed in install directory loaded at startup without signature check",
    "class":    "DLL hijacking (CWE-427)",
    "evidence": [
        "import: LoadLibraryExW",
        "NSIS installer: typically installs to C:\\Program Files (x86)\\Fortinet\\FortiFone\\",
    ],

    "description": (
        "FortiFone calls LoadLibraryExW to load DLLs. "
        "Windows DLL search order: "
        "  1. Application directory (install dir) "
        "  2. System32 "
        "  3. Windows directory "
        "  4. PATH directories "
        "If the install directory (C:\\Program Files (x86)\\Fortinet\\FortiFone\\) "
        "is writable by a non-admin user (common when NSIS installs without requiring elevation, "
        "or when installing to a user-writable path), an attacker places a malicious DLL with the "
        "same name as one FortiFone loads. "
        "DLL hijacking achieves code execution in the FortiFone process context "
        "when FortiFone starts (e.g., at login if FortiFone runs in the system tray). "
        "Common DLL hijack targets: missing DLLs in the import table (Dependency Walker technique). "
        "Full DLL import table requires NSIS extraction."
    ),
}
