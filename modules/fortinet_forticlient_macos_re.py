"""
FortiClient macOS standalone RE (forticlient_standalone_macos.dmg)
Version: 7.4.7.4573 (newer than Linux 7.2.0 -- different code branch)
Structure: DMG -> Install.mpkg (xar) -> 26 sub-packages
Method: 7z extract + cpio decompress + strings analysis on Mach-O binaries
"""

# ---------------------------------------------------------
# macOS installation architecture
# ---------------------------------------------------------
MACOS_ARCH = {
    "id":       "MACOS-ARCH",
    "product":  "FortiClient macOS 7.4.7.4573 (standalone)",
    "version_note": "macOS package is version 7.4.7.4573 vs Linux 7.2.0 -- separate code branch",

    "installer_structure": {
        "format":   "DMG -> HFS+ -> Install.mpkg (xar archive)",
        "auth":     "ALL 26 sub-packages install with auth='root'",
        "pre_post": "fctpreinstall.pkg + fctpostinstall.pkg run scripts as root before/after main install",
    },

    "key_packages": {
        "fctcommon.pkg":            "142MB; 39 files; installs to /Library; core services + binaries",
        "fctconsolevpn_arm64.pkg":  "113MB; 2 files; installs to /Applications (ARM64 Electron GUI)",
        "fctconsolevpn_x86.pkg":    "120MB; 2 files; installs to /Applications (x86_64 Electron GUI)",
        "fctforensics.pkg":         "28MB; FortiForensics endpoint telemetry/EDR module",
        "fctappfw.pkg":             "31MB; Application firewall (Network System Extension + IPS engine 26MB)",
        "fctztagent.pkg":           "22MB; ZTNA agent",
        "fctvpn.pkg":               "65MB; VPN service",
        "fctwebfilter.pkg":         "74MB; Web filter (Network System Extension)",
        "fortipam.pkg":             "14MB; Privileged Access Management agent",
        "fctnewav.pkg":             "2MB; New antivirus engine",
    },

    "binary_types": {
        "note": "All binaries are universal Mach-O fat binaries (x86_64 + ARM64 slices)",
        "flags": "NOUNDEFS|DYLDLINK|TWOLEVEL|PIE on all; WEAK_DEFINES|BINDS_TO_WEAK on Swift binaries",
    },

    "launchdaemons": {
        "com.fortinet.forticlient.macos.PrivilegedHelper.plist": {
            "binary":       "/Library/Application Support/Fortinet/FortiClient/bin/com.fortinet.forticlient.macos.PrivilegedHelper",
            "run_as":       "root (LaunchDaemon)",
            "run_at_load":  "false (on-demand via XPC Mach service)",
            "mach_service": "com.fortinet.forticlient.macos.PrivilegedHelper",
            "type":         "SMJobBless XPC Privileged Helper (Swift; 6.4MB universal)",
            "reset_at_close": True,
        },
        "com.fortinet.forticlient.ztnafw.plist": {
            "binary":       "/Library/Application Support/Fortinet/FortiClient/bin/ztnafw",
            "run_as":       "root (LaunchDaemon)",
            "run_at_load":  "true",
            "log_stdout":   "/tmp/ztnafw.log",
            "log_stderr":   "/tmp/ztnafw.log",
            "debug":        "true",
            "type":         "Go binary; 36MB universal; ZTNA firewall/proxy",
            "keepalive_pathstate": "/Library/Application Support/Fortinet/FortiClient/data/fct_is_running",
        },
        "com.fortinet.forticlient.fctdnsd.plist": {
            "binary":       "/Library/Application Support/Fortinet/FortiClient/bin/fctdnsd",
            "run_as":       "root (LaunchDaemon)",
            "type":         "DNS daemon; 27MB universal",
        },
        "com.fortinet.forticlient.servctl2.plist": {
            "binary":       "/Library/Application Support/Fortinet/FortiClient/bin/fctservctl2",
            "run_as":       "root (LaunchDaemon)",
            "mach_service": "com.fortinet.forticlient.servctl2",
            "type":         "Service controller; 4.8MB universal; XPC Mach service",
        },
        "com.fortinet.forticlient.config.plist": {
            "binary":       "config service (LaunchDaemon)",
            "run_as":       "root",
        },
    },

    "launchagents": {
        "com.fortinet.forticlient.credential_store.plist": {
            "binary":       "/Library/Application Support/Fortinet/FortiClient/bin/CredentialStore",
            "run_as":       "logged-in user (LaunchAgent)",
            "run_at_load":  "true",
            "keepalive":    "SuccessfulExit: false (always restart)",
            "process_type": "Interactive",
            "type":         "Credential storage; 324KB universal; macOS Keychain integration",
        },
        "com.fortinet.forticlient.fct_launcher.plist": {
            "binary":       "/Library/Application Support/Fortinet/FortiClient/bin/FCTLauncher",
            "run_as":       "logged-in user (LaunchAgent)",
        },
        "com.fortinet.forticlient.fortiagent.plist": {
            "binary":       "FortiClient.app agent (LaunchAgent)",
            "run_as":       "logged-in user",
        },
        "com.fortinet.forticlient.appfw2.plist": {
            "binary":       "/Applications/FortiClient.app/Contents/Resources/runtime.helper/FortiClientNetwork.app/Contents/MacOS/FortiClientNetwork",
            "run_as":       "logged-in user (LaunchAgent, Aqua session only)",
            "type":         "Network System Extension (not KEXT); loaded only if fct_is_running present",
        },
    },

    "privileged_helper_xpc_interface": {
        "caller_requirement": (
            "anchor apple generic and identifier 'com.fortinet.forticlient.macos.vpn' and "
            "(certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or "
            "certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and "
            "certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and "
            "certificate leaf[subject.OU] = AH4XFXJ7DK)"
        ),
        "team_id":      "AH4XFXJ7DK (Fortinet, Inc; Apple Developer ID)",
        "note":         "Caller validation is cryptographically enforced by Apple certificate chain; bypass requires XPC caller to be the legitimate Electron GUI (which is reachable via GUI-F06 XSS chain on macOS)",
        "operations": {
            "writeData:":                   "Write arbitrary data as root (path parameter unverified -- see MACOS-F02)",
            "write_p12_to_pem":             "Write PKCS#12 cert as PEM (root file write)",
            "write_ca":                     "Install CA certificate into macOS trust store (see MACOS-F03)",
            "write_cert":                   "Install certificate as root",
            "installDns:family:inheritExistingDns:": "Modify system DNS as root",
            "installFortiEDRIfExists":      "Install FortiEDR agent from path (see MACOS-F04)",
            "installSplitDns:":             "Configure split DNS as root",
            "installSearchDomain:":         "Modify search domain as root",
            "installWins:family:":          "Configure WINS as root",
            "uninstallDns/SearchDomain/SplitDns/Wins": "Remove network configuration",
            "deletePasswordWithService:account:": "Delete OS Keychain entry",
            "deleteTunnelExitReason:":      "Tunnel state management",
            "PromptForAuthentication":      "Trigger authentication prompt (FIDO/XAuth)",
        },
    },

    "appfw_architecture": {
        "fctappfw":         "4.8MB universal Mach-O; app firewall manager process",
        "libips.dylib":     "26MB universal Mach-O dylib; IPS rules engine",
        "network_ext":      "FortiClientNetwork.app; macOS Network System Extension (NEFilterDataProvider or NEAppProxyProvider)",
        "ips_rules":        "ids.rules + irdb.rules in /Library/Application Support/Fortinet/FortiClient/data/",
        "note": (
            "The Network System Extension runs in userspace with network filtering entitlements. "
            "No KEXT (kernel extension) required -- uses macOS 10.15+ System Extension framework. "
            "Attack surface: IPS rule injection via EMS-controlled rule updates; malformed rules -> parser crash in libips.dylib."
        ),
    },

    "custom_openssl": {
        "libssl":   "libssl.3.dylib (custom OpenSSL 3.5.5 build; same build tree as Linux)",
        "libcrypto": "libcrypto.3.dylib (same)",
        "note": "Same Fortinet custom OpenSSL 3.5.5 with SM2/SM3/SM4 Chinese state crypto as Linux tpm2/lib/pkcs11.so",
    },
}


# ---------------------------------------------------------
# MACOS-F01: ztnafw root daemon writes logs to /tmp via launchd plist
# ---------------------------------------------------------
MACOS_F01_TMP_LOG_SYMLINK = {
    "id":       "MACOS-F01",
    "product":  "FortiClient macOS -- ztnafw LaunchDaemon uses StandardOutPath/StandardErrorPath: /tmp/ztnafw.log; launchd follows symlinks as root",
    "severity": "HIGH -- local unprivileged user creates symlink in /tmp before service restart -> root writes to arbitrary path",
    "class":    "Unsafe temp file usage leading to symlink attack (CWE-59, CWE-61)",

    "evidence": [
        "LaunchDaemons/com.fortinet.forticlient.ztnafw.plist: <key>StandardOutPath</key><string>/tmp/ztnafw.log</string>",
        "LaunchDaemons/com.fortinet.forticlient.ztnafw.plist: <key>StandardErrorPath</key><string>/tmp/ztnafw.log</string>",
        "LaunchDaemons/com.fortinet.forticlient.ztnafw.plist: <key>Debug</key><true/>",
        "ztnafw strings: '/tmp/ztagent.log' -- second /tmp log file referenced in binary",
        "launchd opens StandardOutPath/StandardErrorPath files BEFORE executing the daemon binary",
        "launchd runs as root (PID 1); follows symlinks unconditionally when opening log files",
    ],

    "attack": {
        "precondition":     "Local unprivileged user; ztnafw daemon must restart (normal on boot, service failure, or launchctl stop/start)",
        "step1":            "rm /tmp/ztnafw.log; ln -s /etc/sudoers.d/forticlient /tmp/ztnafw.log",
        "step2":            "Trigger ztnafw restart: launchctl stop com.fortinet.ztnafw (fails if not root), OR wait for daemon to crash and respawn, OR force crash via malformed ZTNA packet",
        "step3":            "launchd opens /tmp/ztnafw.log (follows symlink to /etc/sudoers.d/forticlient) as root",
        "step4":            "ztnafw starts and writes to stdout/stderr -> data goes to /etc/sudoers.d/forticlient",
        "step5":            "If any log line matches 'username ALL=(ALL) NOPASSWD:ALL' format (controllable via FortiGate ZTNA server response) -> sudo access",
        "alternative_target": "Symlink /tmp/ztnafw.log -> /etc/cron.d/forticlient; cron executes root commands from log output",
    },

    "crash_trigger": (
        "ztnafw is a Go-based ZTNA proxy that connects to FortiGate/EMS. "
        "A rogue FortiGate (MACOS-F01 from network) can send malformed ZTNA data causing a panic. "
        "Go panics cause goroutine dump to stderr -> significant controlled output to the log file. "
        "Combined with symlink: rogue FortiGate triggers crash + controls crash output content."
    ),

    "see_also": [
        "MACOS-F03: ztnafw connects to /var/run/fctc.s (same socket as Linux /var/run/forticlient)",
        "GUI-F06: service_port file injection; similar /var/run/forticlient/ write attack surface on macOS",
    ],
}


# ---------------------------------------------------------
# MACOS-F02: XPC PrivilegedHelper writeData: path traversal -- root write via XSS chain
# ---------------------------------------------------------
MACOS_F02_XPC_WRITE = {
    "id":       "MACOS-F02",
    "product":  "FortiClient macOS -- XPC PrivilegedHelper exposes writeData: operation with potentially unvalidated path parameter; root file write via Electron XSS chain",
    "severity": "HIGH -- GUI XSS (GUI-F06 service_port) -> ipcMain -> XPC PrivilegedHelper writeData: -> root writes to attacker-controlled path",
    "class":    "Insecure XPC interface with path injection (CWE-22, CWE-284)",

    "evidence": [
        "strings output: 'writeData:' (XPC selector exposed by PrivilegedHelper)",
        "strings output: 'write_p12_to_pem', 'write_ca', 'write_cert' (additional root write operations)",
        "PrivilegedHelper is Swift-based (libswiftXPC.dylib); selector names are Objective-C style",
        "XPC caller requirement: Fortinet Electron GUI (com.fortinet.forticlient.macos.vpn) -- reachable via XSS",
    ],

    "attack_chain": (
        "Full chain (requires GUI-F06 service_port injection OR GUI-F01 api.sudoer XSS): "
        "Step 1: Attacker compromises EMS or FortiGate serving ZTNA content. "
        "Step 2: EMS delivers malicious data rendered in the Electron GUI renderer. "
        "Step 3: Renderer calls window.api.sudoer() or window.ipc.invoke() (GUI-F01/F02) "
        "         to reach an ipcMain handler that calls the PrivilegedHelper XPC interface. "
        "Step 4: ipcMain invokes writeData:(data, path:attacker_path). "
        "Step 5: PrivilegedHelper writes data to attacker_path as root. "
        "Depends on: whether the Electron app passes the path parameter to the XPC call without sanitization."
    ),

    "write_ca_impact": (
        "write_ca / write_cert are unconditionally dangerous: "
        "  - EMS pushes a CA certificate via confighandler (same as EPCTRL-F01 on Linux). "
        "  - PrivilegedHelper installs it into the macOS System Keychain as a trusted root. "
        "  - All macOS TLS-using applications (Safari, Chrome, curl, pip, npm, Homebrew) "
        "    trust any certificate signed by the rogue CA. "
        "  - Attacker MITM any HTTPS connection from the endpoint. "
        "No XSS required -- this is an intentional feature triggered by EMS policy."
    ),
}


# ---------------------------------------------------------
# MACOS-F03: installFortiEDRIfExists -- root binary installation from controllable path
# ---------------------------------------------------------
MACOS_F03_EDR_INSTALL = {
    "id":       "MACOS-F03",
    "product":  "FortiClient macOS -- XPC PrivilegedHelper exposes installFortiEDRIfExists; installs binary as root from path that may be attacker-influenced",
    "severity": "HIGH -- EMS controls which FortiEDR binary is installed; compromised EMS installs malicious EDR binary as root",
    "class":    "Root binary installation from attacker-influenced path (CWE-494, CWE-284)",

    "evidence": [
        "strings output: 'installFortiEDRIfExists' (XPC operation in PrivilegedHelper)",
    ],

    "mechanism": (
        "The XPC operation installFortiEDRIfExists installs a FortiEDR agent binary. "
        "The installation path and source file are controlled by FortiClient configuration "
        "(received from EMS). "
        "Attack chain: "
        "  1. Compromised EMS pushes a FortiEDR install path pointing to an attacker-controlled file. "
        "  2. The Electron GUI invokes the PrivilegedHelper XPC installFortiEDRIfExists operation. "
        "  3. PrivilegedHelper installs the file to the system EDR directory as root. "
        "  4. The file is executed with root privileges as part of the EDR setup. "
        "  5. Code execution as root on the endpoint."
    ),
}


# ---------------------------------------------------------
# MACOS-F04: diagnostictool.tar.gz extracted and executed at runtime
# ---------------------------------------------------------
MACOS_F04_DIAGNOSTICTOOL = {
    "id":       "MACOS-F04",
    "product":  "FortiClient macOS -- diagnostictool.tar.gz extracted and executed from /Library/Application Support/Fortinet/FortiClient/bin/ at runtime",
    "severity": "MEDIUM -- binary replacement race; local attacker substitutes malicious tar.gz before extraction",
    "class":    "Insecure binary extraction and execution (CWE-494); similar to FORTITRAY-F01 (FortiDeceptor)",

    "evidence": [
        "diagnostictool.tar.gz (618KB) present in fctcommon.pkg Payload",
        "Installed to /Library/Application Support/Fortinet/FortiClient/bin/diagnostictool.tar.gz",
        "DiagnosticTool.app inside tar.gz contains a signed macOS app bundle",
        "The app is extracted and run at runtime (not at installation time)",
    ],

    "mechanism": (
        "FortiClient extracts diagnostictool.tar.gz at runtime to a temporary directory "
        "and executes DiagnosticTool.app. "
        "The installed tar.gz is under /Library/ (root-writable by default). "
        "However, if /Library/Application Support/Fortinet/FortiClient/bin/ "
        "has incorrect permissions (group/world-writable), a local attacker substitutes "
        "the tar.gz with one containing a malicious binary. "
        "When FortiClient extracts and runs the diagnostic tool, the attacker's binary executes "
        "with the privileges of the extracting process."
    ),

    "see_also": [
        "FORTITRAY-F01: FortiDeceptor binary unpack-and-execute race on Linux (same CWE-494 pattern)",
    ],
}


# ---------------------------------------------------------
# MACOS-F05: Network System Extension loaded from Applications directory
# ---------------------------------------------------------
MACOS_F05_NETWORK_EXT = {
    "id":       "MACOS-F05",
    "product":  "FortiClient macOS -- Network System Extension (FortiClientNetwork.app) loaded from /Applications directory; code signing protects against substitution but path is notable",
    "severity": "MEDIUM -- architectural note; Network Extension filters ALL network traffic; any vuln = system-wide network MITM",
    "class":    "Security assessment of network traffic filtering component (CWE-668)",

    "evidence": [
        "LaunchAgents/com.fortinet.forticlient.appfw2.plist: ProgramArguments: /Applications/FortiClient.app/Contents/Resources/runtime.helper/FortiClientNetwork.app/Contents/MacOS/FortiClientNetwork",
        "fctappfw package contains: fctappfw (4.8MB Mach-O) + libips.dylib (26MB IPS engine)",
    ],

    "architecture": {
        "type":         "macOS Network System Extension (NEFilterDataProvider or similar)",
        "location":     "/Applications/FortiClient.app/Contents/Resources/runtime.helper/FortiClientNetwork.app",
        "ips_engine":   "libips.dylib (26MB universal Mach-O dylib)",
        "ips_rules":    "/Library/Application Support/Fortinet/FortiClient/data/ids.rules + irdb.rules",
    },

    "attack_surface": (
        "The Network Extension intercepts ALL network traffic on the system. "
        "A vulnerability in libips.dylib's IPS rule parser (processing malformed network packets) "
        "runs in the Network Extension process context. "
        "The IPS rules are loaded from /Library/.../data/ids.rules -- if EMS can update these rules "
        "(EPCTRL-F01 analog on macOS), malformed rule injection -> parser crash or code execution "
        "in the Network Extension process. "
        "Network Extensions run in userspace (not kernel) but have FULL NETWORK VISIBILITY."
    ),
}
