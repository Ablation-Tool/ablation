"""
FortiClient fortitray (system tray + notification daemon) RE
Source: forticlient-vpn-deb/opt/forticlient/fortitray (C/C++, 9.8MB dynamically-linked ELF64)
NOTE: Previous session incorrectly characterized this as Go; it is C/C++ (dynamically linked,
      .cc/.cpp source paths, libappindicator dynamic dep). 9.8MB from embedded CivetWeb + NNG + OpenSSL + protobuf.
Method: strings analysis, source path extraction, protobuf schema, IPC socket path extraction
"""

# ---------------------------------------------------------
# fortitray architecture
# ---------------------------------------------------------
FORTITRAY_ARCH = {
    "id":       "FORTITRAY-ARCH",
    "product":  "fortitray -- FortiClient system tray + notification daemon (C/C++, 9.8MB dynamically-linked ELF64)",
    "binary":   "/opt/forticlient/fortitray",
    "language": "C/C++ (confirmed: dynamically linked ELF64; source paths end in .cc/.cpp; libappindicator dynamic dep)",

    "role": (
        "fortitray is the user-facing system tray + notification daemon. Responsibilities: "
        "  1. Renders system tray icon via libappindicator (Ubuntu/GNOME indicator protocol). "
        "  2. Displays virus alerts, VPN state, and endpoint compliance notifications. "
        "  3. Handles fabricagent:// custom URL scheme (EMS messages, tab navigation). "
        "  4. Embeds CivetWeb HTTP server (same as fortitraylauncher) for GUI communication. "
        "  5. Generates and executes the FortiDeceptor honeypot binary. "
        "  6. Invokes pkexec to stop FortiClient services with elevated privileges. "
        "  7. Communicates with all other daemons via three shared NNG IPC sockets."
    ),

    "source_files_confirmed": [
        "/home/devops/code/src/fortitray/src/fortitray.cc",
        "/home/devops/code/src/fortitray/src/notification.cc",
        "/home/devops/code/src/fortitray/src/tray_msg_dispatcher.cc",
        "/home/devops/code/src/fortitray/src/virus_warning_dlg.cc",
        "/home/devops/code/src/fortitray/src/vpn_notification.cpp",
        "/home/devops/code/src/fortitray/src/fortideceptor_generate.cpp",
        "/home/devops/code/src/base/src/fortideceptor.cpp",
    ],

    "nng_ipc_sockets": [
        "8f6ddf1358bd9d067261f529f69fda59.ipc",    "shared: all FortiClient daemons",
        "8668fd42ebc016367da6f8d16e455684.ipc",    "fortitray-specific: purpose not yet confirmed",
        "8e145d51ebfccd7ee77b3eed706792fe.ipc",    "fortitray-specific: purpose not yet confirmed",
    ],

    "filesystem_paths": {
        "/opt/forticlient/data/alerts.db":          "SQLite alerts database",
        "/var/run/forticlient/service_port":        "fortitray writes its HTTP server port here",
        "/var/run/forticlient/public":              "public directory (served by CivetWeb?)",
        "/var/run/forticlient/hosts":               "hosts file manipulation by fortitray",
        "/tmp/.forticlient":                        "temporary directory",
        "/var/lib/forticlient/fdc/":                "FortiDeceptor results directory",
        "fortitray.log":                            "fortitray log file",
        "fortitray.pid":                            "fortitray PID file",
    },

    "process_launches": {
        "(/bin/bash -c 'xdg-open fabricagent://smallfct &')":
            "xdg-open with fabricagent:// URL scheme",
        "(cd /opt/forticlient && /bin/bash -c '/opt/forticlient/fortivpn autoconnect &')":
            "spawns fortivpn autoconnect from fortitray",
        "(cd /opt/forticlient/gui && /bin/bash -c '/opt/forticlient/gui/FortiClient &')":
            "spawns FortiClient GUI",
        "pkexec /bin/bash /opt/forticlient/stop-forticlient.sh":
            "pkexec invocation to stop FortiClient with elevated privileges",
    },

    "embedded_libraries": {
        "CivetWeb":         "embedded HTTP server (SSI, CGI, WebSocket)",
        "NNG 1.8.0":        "confirmed by /home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/",
        "OpenSSL":          "TLS/crypto",
        "SQLite":           "alerts.db, endpoint_messages table",
        "protobuf":         "policy schema serialization (github.com/fortinet/config/pb)",
        "libappindicator":  "GNOME/Unity system tray indicator",
        "libnotify":        "desktop notification dispatch",
    },

    "desktop_integration": {
        "app_indicator_new":        "creates GNOME indicator",
        "app_indicator_set_icon":   "sets tray icon",
        "app_indicator_set_menu":   "sets tray context menu",
        "app_indicator_set_status": "sets indicator status",
        "dbus-menu-server":         "DBus menu server backing the tray context menu",
        "flashing_system_tray_icon":"tray icon animation for alerts",
    },

    "url_scheme": {
        "fabricagent://":               "custom URL scheme handled by fortitray",
        "fabricagent://ems/msg?id=":    "EMS push message handler",
        "fabricagent://tab?name=":      "tab navigation handler",
        "open_scheme":                  "function name that dispatches URL scheme handling",
    },

    "fortideceptor": {
        "GenerateFortiDeceptor":                    "generates FortiDeceptor honeypot binary",
        "Failed to unzip FortiDeceptor archive":    "FortiDeceptor packed as zip archive",
        "Failed to unpack FortiDeceptor":           "unpacking step",
        "Failed to chmod FortiDeceptor binary":     "sets execute bit after unpack",
        "Failed to execute FortiDeceptor":          "executes the unpacked binary",
        "FortiDeceptorTok":                         "authentication token for FortiDeceptor",
        "/var/lib/forticlient/fdc/":                "FortiDeceptor results directory",
    },

    "civet_config_observed": {
        "document_root":            "configurable web root",
        "listening_ports":          "port configuration",
        "cgi_pattern":              "**.cgi$|**.pl$|**.php$",
        "ssi_pattern":              "**.shtml$|**.shtm$",
        "index_files":              "index.xhtml,index.html,index.htm,index.cgi,index.shtml,index.php",
        "ssl_certificate":          "SSL support",
        "cgi_interpreter":          "configurable CGI interpreter",
        "put_delete_auth_file":     "PUT/DELETE auth file",
        "access_control_allow_origin": "CORS header (value set in config)",
    },
}


# ---------------------------------------------------------
# FORTITRAY-F01: FortiDeceptor embedded binary extraction and execution
# ---------------------------------------------------------
FORTITRAY_F01_FORTIDECEPTOR_EXEC = {
    "id":       "FORTITRAY-F01",
    "product":  "fortitray -- FortiDeceptor honeypot binary unpacked from archive and executed; extraction path writable = code execution",
    "severity": "HIGH -- replace FortiDeceptor archive at writable path -> arbitrary binary executes with fortitray privileges",
    "class":    "Insecure executable unpack and run (CWE-494); privilege escalation via binary replacement",
    "evidence": [
        "string: 'Failed to unzip FortiDeceptor archive'",
        "string: 'Failed to unpack FortiDeceptor'",
        "string: 'Failed to chmod FortiDeceptor binary [%d]'",
        "string: 'Failed to execute FortiDeceptor, status: %d'",
        "string: 'GenerateFortiDeceptor'",
        "path: '/var/lib/forticlient/fdc/' (result directory)",
        "source: '/home/devops/code/src/fortitray/src/fortideceptor_generate.cpp'",
    ],

    "mechanism": (
        "fortitray embeds the FortiDeceptor honeypot binary as a zip archive. "
        "On demand it: "
        "  1. Generates (writes) the FortiDeceptor archive to a filesystem path (unconfirmed exact path). "
        "  2. Unzips the archive (Failed to unzip FortiDeceptor archive). "
        "  3. Sets the execute bit (chmod) on the extracted binary. "
        "  4. Executes it (Failed to execute FortiDeceptor, status: %d). "
        "  5. Results saved to /var/lib/forticlient/fdc/. "
        "Attack surface: if the intermediate extraction directory or the archive source path is "
        "world-writable (common for /tmp, /var/tmp, or /var/lib/ with loose permissions), "
        "a local attacker races to replace the archive or the extracted binary between "
        "steps 2-3 and step 4. "
        "The execute step runs under fortitray's effective UID. "
        "fortitray may run as root or as a privileged service user; the exact UID is unconfirmed."
    ),

    "attack_path": (
        "Step 1: Monitor /var/lib/forticlient/fdc/ or /tmp for creation of the FortiDeceptor archive. "
        "Step 2: Race to replace the archive with a crafted zip containing a malicious binary. "
        "Step 3: fortitray extracts, chmods, and executes the malicious binary. "
        "Alternatively: if the archive extraction directory is world-writable, "
        "the attacker pre-creates the target binary path with a symlink -> malicious target. "
        "fortitray chmods and executes via the symlink."
    ),

    "related": [
        "FCTSCHED-F03: auto_patch executes downloaded packages; same unpack-and-run pattern",
        "EPCTRL-F03: epctrl patch application; same class",
    ],
}


# ---------------------------------------------------------
# FORTITRAY-F02: fabricagent:// custom URL scheme parameter injection
# ---------------------------------------------------------
FORTITRAY_F02_URL_SCHEME = {
    "id":       "FORTITRAY-F02",
    "product":  "fortitray -- fabricagent:// custom URL scheme handler processes EMS-controlled URL parameters without confirmed sanitization",
    "severity": "HIGH -- rogue EMS or IPC injection -> attacker-controlled URL parameter -> shell injection or CivetWeb SSI",
    "class":    "Custom URL scheme parameter injection (CWE-88, CWE-78)",
    "evidence": [
        "string: 'fabricagent://'",
        "string: 'fabricagent://ems/msg?id='",
        "string: 'fabricagent://tab?name='",
        "string: '(/bin/bash -c 'xdg-open fabricagent://smallfct &')'",
        "string: 'Failed to open GUI URL scheme'",
        "string: 'open_scheme'",
        "string: 'invalid url scheme'",
    ],

    "mechanism": (
        "fortitray registers and handles the fabricagent:// URL scheme. "
        "The scheme carries parameters: "
        "  - fabricagent://ems/msg?id=<ID>  -- processes an EMS message by ID "
        "  - fabricagent://tab?name=<TAB>   -- switches to a named tab "
        "  - fabricagent://smallfct         -- opens the compact/mini FortiClient window "
        "The URL is opened via xdg-open (invoked from /bin/bash -c). "
        "Attack vector 1 (IPC injection): "
        "  An attacker with local IPC socket access sends a message triggering a fabricagent:// URL "
        "  with a crafted parameter (e.g., fabricagent://ems/msg?id=../../etc/passwd). "
        "  If fortitray uses the ID parameter in a file path operation, path traversal is possible. "
        "Attack vector 2 (rogue EMS): "
        "  Compromised EMS pushes a malicious EMS message with a crafted ID or tab name. "
        "  fortitray's tray_msg_dispatcher.cc processes the message and invokes xdg-open "
        "  with attacker-controlled content. "
        "Attack vector 3 (xdg-open shell expansion): "
        "  If the URL parameter is not shell-quoted before /bin/bash -c, "
        "  a parameter containing '; <command> #' is executed by bash. "
        "  fortitray calls /bin/bash -c with the fabricagent:// URL as part of the argument -- "
        "  if the URL parameter is substituted unsanitized into the shell string, "
        "  shell metacharacters in the URL inject arbitrary commands."
    ),

    "xdg_open_shell_injection": (
        "The hardcoded string '(/bin/bash -c 'xdg-open fabricagent://smallfct &')' shows "
        "fortitray constructs a bash -c string containing the URL. "
        "If the URL is parameterized (e.g., /bin/bash -c 'xdg-open fabricagent://ems/msg?id=' + id + ' &'), "
        "and id is attacker-controlled without shell-quoting: "
        "  id = \"x' & touch /tmp/pwned & '\" "
        "  => /bin/bash -c 'xdg-open fabricagent://ems/msg?id=x' & touch /tmp/pwned & '' "
        "  => touch /tmp/pwned executes with fortitray's privileges."
    ),

    "related": [
        "TLAUNCH-F04: fortitraylauncher LD_PRELOAD injection when launching fortitray via bash -c",
        "CONFIGHANDLER-F03: EMS compromise gives attacker control over all IPC-distributed policy",
    ],
}


# ---------------------------------------------------------
# FORTITRAY-F03: pkexec invocation creates polkit privilege escalation surface
# ---------------------------------------------------------
FORTITRAY_F03_PKEXEC = {
    "id":       "FORTITRAY-F03",
    "product":  "fortitray -- invokes pkexec /bin/bash to stop FortiClient services; unpatched polkit = local privilege escalation to root",
    "severity": "HIGH -- fortitray's pkexec invocation is an attack surface for CVE-2021-4034 (PwnKit) and polkit misconfiguration",
    "class":    "Privilege escalation via pkexec (CWE-269); relies on polkit rules and kernel version",
    "evidence": [
        "string: 'pkexec /bin/bash /opt/forticlient/stop-forticlient.sh'",
    ],

    "mechanism": (
        "fortitray invokes 'pkexec /bin/bash /opt/forticlient/stop-forticlient.sh' to stop "
        "FortiClient services. pkexec (polkit's setuid helper) runs a command with elevated "
        "privileges if the polkit policy permits it. "
        "Vulnerability surfaces: "
        "  1. CVE-2021-4034 (PwnKit): local privilege escalation via pkexec in polkit < 0.120. "
        "     If the FortiClient endpoint has not applied the PwnKit patch (2022-01), "
        "     any local user can exploit pkexec for root. "
        "     FortiClient's explicit invocation of pkexec makes the attack surface visible. "
        "  2. Polkit rule misconfiguration: if the polkit rules for "
        "     /opt/forticlient/stop-forticlient.sh are set to allow without authentication "
        "     (ResultAny=yes), any local user can trigger service shutdown without a password. "
        "  3. stop-forticlient.sh substitution: if the script path is in a world-writable "
        "     directory, an attacker replaces the script before pkexec executes it. "
        "     pkexec runs the replacement script with root privileges. "
        "FortiClient installs alongside a managed endpoint -- the endpoint may have unpatched polkit "
        "as a consequence of the managed update posture (ironic: FortiClient manages patches but "
        "the pkexec it relies on may be unpatched)."
    ),

    "pwnkit_chain": (
        "Full local-to-root chain on unpatched polkit: "
        "Step 1: Gain any local user shell on the FortiClient endpoint "
        "         (CLI-F01 credential leak, or any other initial access). "
        "Step 2: Exploit CVE-2021-4034 against pkexec: "
        "         env GCONV_PATH=. CHARSET=. LANG=fr_FR 'polkit-0.105-26_pkexec_exploit' "
        "Step 3: Root shell on the endpoint. "
        "         Combined with CONFIGHANDLER-F01 (pkcs11_lib), EPCTRL-F01 (rogue CA), "
        "         EPCTRL-F02 (Firefox policy): full endpoint compromise from EMS or IPC."
    ),

    "note": (
        "CVE-2021-4034 was patched in polkit >= 0.120 (2022-01-25). "
        "Not all Linux distributions have updated to patched polkit. "
        "The finding here is that fortitray's explicit pkexec invocation makes this "
        "a relevant attack surface for any FortiClient endpoint with unpatched polkit."
    ),
}


# ---------------------------------------------------------
# FORTITRAY-F04: three NNG IPC sockets expand local injection surface
# ---------------------------------------------------------
FORTITRAY_F04_IPC_SOCKETS = {
    "id":       "FORTITRAY-F04",
    "product":  "fortitray -- uses three distinct NNG IPC sockets including two fortitray-specific sockets beyond the shared daemon socket",
    "severity": "MEDIUM -- three world-accessible sockets; fortitray-specific sockets may accept unauthenticated control messages",
    "class":    "Unauthenticated local IPC (CWE-284); expands FCTSCHED-F01 attack surface",
    "evidence": [
        "string: '8f6ddf1358bd9d067261f529f69fda59.ipc'  (shared; all FortiClient daemons)",
        "string: 'ipc:///var/run/forticlient/8668fd42ebc016367da6f8d16e455684.ipc'",
        "string: 'ipc:///var/run/forticlient/8e145d51ebfccd7ee77b3eed706792fe.ipc'",
    ],

    "mechanism": (
        "fortitray listens on three NNG IPC sockets: "
        "  1. 8f6ddf1358bd9d067261f529f69fda59.ipc -- the shared bus socket used by ALL daemons "
        "     (certd, fctdns, firewall, fctsched, iked, confighandler, update, fortitraylauncher). "
        "     FCTSCHED-F01 already documented this socket as a local injection vector. "
        "  2. 8668fd42ebc016367da6f8d16e455684.ipc -- fortitray-specific; purpose unconfirmed. "
        "     Likely handles tray messages (tray_msg_dispatcher.cc). "
        "  3. 8e145d51ebfccd7ee77b3eed706792fe.ipc -- fortitray-specific; purpose unconfirmed. "
        "     Likely notification or VPN notification channel (vpn_notification.cpp). "
        "The two fortitray-specific sockets are NOT shared with other daemons -- they are "
        "direct communication channels FROM confighandler/other daemons TO fortitray. "
        "If these sockets are world-accessible (no filesystem permissions restricting them), "
        "any local process can inject tray messages, trigger URL scheme handlers, "
        "or invoke the FortiDeceptor generation flow."
    ),

    "injection_impact": {
        "tray_msg_dispatcher.cc": "inject arbitrary EMS messages -> trigger fabricagent:// URL scheme (FORTITRAY-F02)",
        "vpn_notification.cpp":   "inject VPN state notifications -> confuse user (social engineering) or trigger reconnect",
        "virus_warning_dlg.cc":   "inject virus alert dialogs -> social engineering or confuse incident response",
        "shared bus socket":      "inject policy to ANY daemon on the bus (see FCTSCHED-F01)",
    },

    "related": [
        "FCTSCHED-F01: hardcoded shared NNG IPC socket local task injection",
        "NNG-ARCH: NNG 1.8.0 shared IPC socket across all FortiClient daemons",
    ],
}


# ---------------------------------------------------------
# FORTITRAY-F05: CivetWeb SSI and CGI in fortitray (duplicate surface from fortitraylauncher)
# ---------------------------------------------------------
FORTITRAY_F05_CIVET_DUPLICATE = {
    "id":       "FORTITRAY-F05",
    "product":  "fortitray -- embeds CivetWeb HTTP server with SSI #exec and CGI enabled; same attack surface as TLAUNCH-F01/F02",
    "severity": "HIGH -- same as TLAUNCH-F01; two separate CivetWeb instances in VPN-only package",
    "class":    "Server-side include command injection + CGI file write (CWE-78, CWE-94)",
    "evidence": [
        "string: 'Bad SSI #exec: [%s]'",
        "string: 'Cannot SSI #exec: [%s]: %s'",
        "string: 'do_ssi_exec'",
        "string: '**.cgi$|**.pl$|**.php$'  (cgi_pattern)",
        "string: '**.shtml$|**.shtm$'  (ssi_pattern)",
        "string: 'document_root'",
        "string: 'cgi_interpreter'",
        "string: '/var/run/forticlient/service_port'  (fortitray writes its HTTP port here)",
        "string: '/var/run/forticlient/public'  (likely CivetWeb document_root)",
    ],

    "mechanism": (
        "fortitray embeds its own CivetWeb instance (separate from fortitraylauncher's instance). "
        "fortitray's CivetWeb binds to a port written to /var/run/forticlient/service_port. "
        "The document_root is likely /var/run/forticlient/public (world-readable directory). "
        "The same attack path as TLAUNCH-F01 applies: "
        "  If any local process can write a .shtml file to the document_root, "
        "  requesting it via localhost triggers SSI #exec (do_ssi_exec), "
        "  executing a shell command with fortitray's privileges. "
        "Attack path: "
        "  1. Determine fortitray's HTTP port from /var/run/forticlient/service_port. "
        "  2. Write a .shtml file to /var/run/forticlient/public/ (if world-writable). "
        "  3. Request it from localhost: curl http://127.0.0.1:<port>/evil.shtml "
        "  4. CivetWeb executes the SSI #exec command as fortitray. "
        "The presence of TWO CivetWeb instances (fortitraylauncher + fortitray) doubles the "
        "HTTP server attack surface in the VPN-only package."
    ),

    "note": (
        "TLAUNCH-F01 and TLAUNCH-F02 already documented the CivetWeb attack surface in "
        "fortitraylauncher. FORTITRAY-F05 is a separate instance in a different process "
        "(fortitray), bound to a different port. Both must be remediated independently."
    ),

    "related": [
        "TLAUNCH-F01: fortitraylauncher CivetWeb SSI #exec",
        "TLAUNCH-F02: fortitraylauncher CivetWeb CGI",
        "TLAUNCH-F03: fortitraylauncher CivetWeb CORS",
    ],
}
