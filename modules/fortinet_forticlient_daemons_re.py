"""
FortiClient Linux daemon internals RE
Sources (all from forticlient-vpn-deb/opt/forticlient/):
  - fctdns  (Go, 11.4MB) -- ZTNA DNS daemon
  - firewall (Go, 14.5MB) -- iptables/nftables manager
  - fctsched (C/C++, 10.2MB) -- task scheduler daemon
  - fortivpn (C/C++, 8.5MB) -- VPN-only package daemon
Method: gopclntab symbol extraction, strings analysis, Go function name enumeration
"""

# ---------------------------------------------------------
# fctdns architecture
# ---------------------------------------------------------
FCTDNS_ARCH = {
    "id":       "FCTDNS-ARCH",
    "product":  "fctdns -- FortiClient ZTNA DNS daemon (Go 1.23.2, 11.4MB stripped ELF64)",
    "binary":   "/opt/forticlient/fctdns",

    "services": {
        "main.NewDNSService":   "DNS proxy service (intercepts system DNS queries)",
        "main.NewHTTPService":  "HTTP proxy service (HTTPS interception via fake cert)",
        "main.NewSimpleService": "Simple DNS-to-IP resolver for ZTNA host entries",
    },

    "ipc": {
        "transport":    "mangos/NNG socket (same library as certd daemon)",
        "pattern":      "fctdns subscribes to configuration push from certd/central daemon",
        "implication":  "NNG socket is a shared IPC attack surface across all FortiClient daemons",
    },

    "grpc_clients": {
        "firewall.Firewall.SetupSimpleDNS":  "Requests firewall daemon to create DNS redirect rules",
        "firewall.Firewall.RefreshSimpleDNS": "Reloads DNS firewall rules after ZTNA policy update",
        "firewall.Firewall.SetupWebfilter":  "Pushes SAAS domain filter rules to firewall daemon",
        "firewall.Firewall.EditZtnaRule":    "EditAction enum -- add/remove/modify ZTNA interception rules",
        "firewall.Firewall.Quarantine":      "Action enum -- quarantine host via firewall",
    },

    "upstream_doh": {
        "hardcoded":    "mozilla.cloudflare-dns.com (Cloudflare DoH endpoint)",
        "server":       "Starting DoH server at %v (local DoH server for ZTNA queries)",
        "ca_lifecycle": "Failed to initialize CA / Failed to remove DoH CA",
    },

    "resolver_types": {
        "resolve.ResolverType":     "Custom resolver interface (1*map.bucket[resolve.ResolverType]resolve.Resolver)",
        "ztna.RequestAction":       "ZTNA request tracking (8*func(ztna.RequestAction) (*ztna.TrackerResponse, error))",
        "ztna.trackedEntry":        "*[8]*ztna.trackedEntry -- tracked entry pool (8-slot ring)",
        "dns.Handler":              "*[8]dns.Handler -- 8 handler slots (miekg/dns library)",
        "forticlient.SAASRule":     "*[8][]forticlient.SAASRule -- SAAS filter rules per domain",
    },

    "system_integration": {
        "libresolv.so.2":           "Linked against system resolver for non-ZTNA fallback",
        "FortiClient_ZTNA_DNS_CA":  "ZTNA DNS CA cert managed by fctdns (/opt/forticlient/FortiClient_ZTNA_DNS_CA.crt)",
        "hosts_config":             "Failed to open ZTNA hosts config: %v -- maintains ZTNA host entries",
        "host_delete":              "Deleted host entry %v (%v) -- dynamic ZTNA host table",
    },
}


# ---------------------------------------------------------
# FCTDNS-F01: fake certificate generation (ZTNA TLS inspection)
# ---------------------------------------------------------
FCTDNS_F01_FAKE_CERT = {
    "id":       "FCTDNS-F01",
    "product":  "fctdns -- transparent TLS inspection via fake certificate generation",
    "severity": "CRITICAL -- all HTTPS traffic to ZTNA-inspected domains is decryptable by CA key holder",
    "class":    "Authorized MITM (product feature); CA key exposure = full HTTPS session compromise",
    "evidence": [
        "string: 'Failed to create fake certificate: %v'",
        "string: 'FortiClient_ZTNA_DNS_CA.crt'",
        "string: 'Failed to initialize CA: %v'",
        "string: 'Failed to remove DoH CA: %v'",
        "string: 'Intercepted DNS request to server: %v'",
    ],

    "mechanism": (
        "fctdns implements transparent TLS inspection for ZTNA-protected domains: "
        "1. Intercepts DNS query for a ZTNA target domain. "
        "2. Returns a local IP (loopback or tunnel) so the TCP connection reaches fctdns/NewHTTPService. "
        "3. fctdns generates a fake TLS certificate for the target domain, signed by FortiClient_ZTNA_DNS_CA.crt. "
        "4. The CA is installed in the system trust store, so the fake cert is accepted by all applications. "
        "5. The real connection to the origin is proxied transparently. "
        "This is architecturally identical to corporate TLS inspection proxies (Squid+SslBump, Zscaler). "
        "The feature is intentional; the attack surface is the CA private key."
    ),

    "ca_key_location": (
        "The FortiClient_ZTNA_DNS_CA private key is generated locally on the endpoint. "
        "It is likely stored in /opt/forticlient/ or managed by the certd daemon. "
        "CERTD-F01 (software TPM fallback) and CERTD-F02 (no PCR binding) apply: "
        "if certd seals the CA key with software TPM fallback, the key may be on disk in plaintext "
        "or AES-128 encrypted with a static key extractable from the certd binary. "
        "CA key extraction -> forge certificates for ANY ZTNA-inspected domain -> "
        "decrypt all historical ZTNA TLS sessions captured via TPROXY (FIREWALL-F01)."
    ),

    "attack_scenarios": {
        "local_ca_key_theft": (
            "Local attacker (e.g., via fctsched IPC -- see FCTSCHED-F01) extracts the ZTNA DNS CA private key. "
            "Attacker can now forge certificates for any ZTNA domain, enabling offline decryption of "
            "any captured HTTPS session from the endpoint."
        ),
        "compromised_fortigate_push": (
            "Rogue FortiGate (CVE-2024-47575 / MITM) pushes ZTNA rules (firewall.Firewall.EditZtnaRule) "
            "that include arbitrary domains. fctdns then intercepts DNS and creates fake certs for those domains. "
            "All HTTPS traffic to the attacker-specified domains is transparently proxied through fctdns, "
            "decryptable by the rogue FortiGate."
        ),
    },
}


# ---------------------------------------------------------
# FCTDNS-F02: DNS interception -- all DNS queries captured
# ---------------------------------------------------------
FCTDNS_F02_DNS_INTERCEPT = {
    "id":       "FCTDNS-F02",
    "product":  "fctdns -- full DNS query interception before system resolver",
    "severity": "HIGH -- ZTNA rules pushed by FortiGate control which domains are intercepted",
    "class":    "Authorized DNS interception (product feature); rogue FortiGate = arbitrary domain capture",
    "evidence": [
        "string: 'Intercepted DNS request to server: %v'",
        "string: 'Deleted host entry %v (%v)'",
        "string: 'Failed to open ZTNA hosts config: %v'",
        "string: 'firewall.Firewall.EditZtnaRule' (EditAction enum)",
    ],

    "mechanism": (
        "fctdns registers as the system DNS resolver (likely via /etc/resolv.conf or NetworkManager). "
        "All DNS queries pass through fctdns before reaching libresolv.so.2. "
        "For ZTNA-listed domains: fctdns intercepts and returns a local proxy IP. "
        "For non-ZTNA domains: fctdns forwards to Cloudflare DoH (mozilla.cloudflare-dns.com). "
        "ZTNA rule updates arrive via gRPC from the firewall daemon "
        "(firewall.Firewall.EditZtnaRule with EditAction enum). "
        "A compromised FortiGate can push ZTNA rules that cause fctdns to intercept "
        "ANY domain, not just ZTNA-protected resources."
    ),

    "exfil_surface": (
        "DNS query logs at 'Intercepted DNS request to server: %v' reveal which ZTNA domains "
        "the endpoint is resolving, including internal application hostnames not meant to be public. "
        "An attacker with read access to fctdns logs (or the NNG socket) obtains a map of "
        "internal application infrastructure."
    ),
}


# ---------------------------------------------------------
# FCTDNS-F03: DoH upstream hardcoded -- organizational DNS policy bypass
# ---------------------------------------------------------
FCTDNS_F03_DOH_CLOUDFLARE = {
    "id":       "FCTDNS-F03",
    "product":  "fctdns -- hardcoded Cloudflare DoH bypasses organizational DNS policies",
    "severity": "MEDIUM -- DNS traffic exits to Cloudflare regardless of corporate DNS config",
    "class":    "DNS policy bypass (CWE-693); data exfiltration via DNS-over-HTTPS",
    "evidence": [
        "string: 'mozilla.cloudflare-dns.com' (hardcoded DoH upstream)",
        "string: 'Starting DoH server at %v'",
    ],

    "description": (
        "Non-ZTNA DNS queries are forwarded to Cloudflare DoH (mozilla.cloudflare-dns.com) "
        "over HTTPS regardless of the organization's DNS server configuration. "
        "This bypasses: "
        "  1. Corporate DNS servers that enforce split-horizon or internal zone resolution. "
        "  2. DNS-based security controls (RPZ, Cisco Umbrella, etc.). "
        "  3. DNS query logging at the corporate perimeter. "
        "An attacker who controls fctdns configuration can redirect the DoH upstream to an "
        "attacker-controlled server to capture all DNS queries from the endpoint."
    ),

    "second_order": (
        "fctdns also runs a LOCAL DoH server ('Starting DoH server at %v'). "
        "If this server binds to 0.0.0.0 rather than 127.0.0.1, it is reachable from the local network. "
        "Other hosts on the same network segment could query this DoH server and have their DNS "
        "intercepted by fctdns, expanding the MITM surface beyond the endpoint running FortiClient."
    ),
}


# ---------------------------------------------------------
# FCTDNS-F04: NNG IPC shared attack surface
# ---------------------------------------------------------
FCTDNS_F04_NNG_IPC = {
    "id":       "FCTDNS-F04",
    "product":  "fctdns -- mangos/NNG IPC socket shared with certd daemon",
    "severity": "MEDIUM -- same IPC transport used by certd; compromise of one daemon = config injection into another",
    "class":    "Insecure IPC (CWE-287); shared transport without per-daemon authentication",
    "evidence": [
        "gopclntab symbols include mangos NNG socket functions",
        "certd RE (CERTD-ARCH) confirmed NNG socket as the IPC transport",
    ],

    "description": (
        "Both fctdns and certd use the mangos/NNG library for IPC. "
        "If the NNG socket is a Unix domain socket in /tmp or /opt/forticlient/, "
        "any local process with access to the socket path can: "
        "  1. Inject ZTNA configuration updates (push fake ZTNA rules to fctdns). "
        "  2. Subscribe to configuration broadcasts and read decrypted policy data. "
        "  3. Send malformed NNG messages to trigger parsing bugs in the NNG handler. "
        "The NNG socket is the inter-daemon trust boundary; its permission bits "
        "determine the local privilege escalation surface."
    ),
}


# ---------------------------------------------------------
# firewall daemon architecture
# ---------------------------------------------------------
FIREWALL_ARCH = {
    "id":       "FIREWALL-ARCH",
    "product":  "firewall -- FortiClient iptables/nftables manager (Go 1.23.2, 14.5MB stripped ELF64)",
    "binary":   "/opt/forticlient/firewall",

    "main_functions": {
        "main.firewallLoop":    "Main event loop -- receives gRPC messages from other daemons",
        "main.handleMessage":   "Dispatches incoming gRPC messages to specific rule handlers",
        "main.initChains":      "Initializes iptables/nftables chains at startup",
        "main.CleanUpTable":    "Cleans up rules on shutdown",
        "main.flush":           "Flushes specific chain/table (firewall.Firewall.Flush.ChainType)",
        "main.reply":           "Sends gRPC reply to requesting daemon",
        "main.setupSocket":     "Sets up Unix/NNG socket for gRPC transport",
    },

    "rule_management": {
        "main.setupChain":      "Creates a specific iptables/nftables chain",
        "main.setupChainType":  "Sets chain type (FILTER/NAT/MANGLE/RAW)",
        "main.appendRules":     "Appends rules to a chain",
        "main.syncRulesByType": "Synchronizes rules by type (VPN/ZTNA/webfilter/DNS)",
        "main.buildChains":     "Builds full chain set from configuration",
        "main.buildCTable":     "Builds connection-tracking table",
        "main.buildDtable":     "Builds destination table",
    },

    "functional_handlers": {
        "main.setupVPN":        "Installs VPN routing and masquerade rules",
        "main.setupZTNA":       "Installs ZTNA TPROXY intercept rules",
        "main.setupSimpleDNS":  "Installs DNS redirect rules (UDP/53 -> fctdns)",
        "main.refreshSimpleDNS": "Reloads DNS redirect rules after fctdns policy update",
        "main.setupWebfilter":  "Installs SAAS/web filter rules",
        "main.setupDOH":        "Installs DoH server intercept rules",
        "main.editZTNARule":    "EditAction-driven ZTNA rule modification",
        "main.quarantine":      "Quarantine action -- blocks host at firewall level",
    },

    "nftables_ops": {
        "AddChain":     "nftables chain creation",
        "AddTable":     "nftables table creation",
        "AddFlowtable": "nftables flowtable (hardware offload) creation",
    },

    "conntrack_states": ["RELATED", "ESTABLISHED", "tls+tcp"],

    "iptables_flags": {
        "--tproxy-mark": "TPROXY transparent proxy mark (Linux kernel TPROXY target)",
        "--sport":       "Source port match",
        "--dport":       "Destination port match",
        "--state":       "Connection state match (conntrack)",
        "fct_nat":       "FortiClient NAT rule set identifier",
    },

    "proto":    "firewall.proto (gRPC schema shared with fctdns, certd, fctsched)",
}


# ---------------------------------------------------------
# FIREWALL-F01: TPROXY transparent proxy -- kernel-level traffic interception
# ---------------------------------------------------------
FIREWALL_F01_TPROXY = {
    "id":       "FIREWALL-F01",
    "product":  "firewall daemon -- TPROXY rules intercept all TCP/UDP traffic at kernel level",
    "severity": "HIGH -- if firewall daemon is compromised, attacker can redirect arbitrary traffic",
    "class":    "Authorized traffic interception (product feature); daemon compromise = network pivot",
    "evidence": [
        "string: '--tproxy-mark' (iptables TPROXY target flag)",
        "function: main.setupZTNA (installs TPROXY rules)",
        "function: main.editZTNARule (EditAction-driven rule modification)",
        "string: 'tls+tcp' (TLS-over-TCP transparent proxy rule)",
    ],

    "mechanism": (
        "The firewall daemon installs iptables TPROXY rules that redirect matching packets "
        "to a local socket WITHOUT changing the destination IP/port (transparent). "
        "This enables fctdns/NewHTTPService to receive TLS connections to arbitrary remote IPs "
        "while the connecting application sees the original destination address. "
        "TPROXY requires CAP_NET_ADMIN (the firewall daemon runs with elevated privileges). "
        "ZTNA rules pushed from FortiGate (via editZTNARule) control WHICH destinations are TPROXY'd."
    ),

    "attack_scenarios": {
        "rogue_ztna_rules": (
            "Compromised FortiGate sends EditZtnaRule with an arbitrary IP/CIDR. "
            "firewall daemon installs TPROXY rule for that range. "
            "All TCP traffic to that range from the endpoint is transparently redirected to fctdns. "
            "fctdns generates fake certificates and proxies the connections. "
            "Attacker sees all plaintext application-layer data."
        ),
        "firewall_daemon_exploit": (
            "If firewall daemon gRPC socket is accessible without authentication (see FIREWALL-F02), "
            "local attacker sends forged gRPC SetupZTNA message. "
            "Arbitrary TPROXY rules are installed, redirecting any TCP traffic to attacker-controlled socket. "
            "No sudo or root shell needed -- just access to the gRPC socket."
        ),
    },
}


# ---------------------------------------------------------
# FIREWALL-F02: gRPC socket authentication unknown
# ---------------------------------------------------------
FIREWALL_F02_GRPC_AUTH = {
    "id":       "FIREWALL-F02",
    "product":  "firewall daemon -- gRPC socket authentication posture not confirmed",
    "severity": "HIGH (if unauthenticated) -- any local process can install iptables/nftables rules",
    "class":    "Potential unauthenticated local IPC (CWE-287)",
    "evidence": [
        "function: main.setupSocket (socket setup)",
        "function: main.handleMessage (message dispatch with no visible auth check in gopclntab)",
        "functions: main.setupVPN, main.setupZTNA, main.quarantine (privileged operations)",
    ],

    "description": (
        "The firewall daemon accepts gRPC messages from fctdns, fctsched, and other daemons. "
        "The gRPC transport uses a Unix domain socket or NNG socket (main.setupSocket). "
        "The gopclntab does not reveal any 'authenticate' or 'verify_peer' functions. "
        "If the socket is world-readable (e.g., /tmp/.forticlient/*.sock), "
        "any local process with filesystem access can send gRPC messages to: "
        "  - main.quarantine: block any host at the firewall level. "
        "  - main.setupZTNA: install TPROXY rules redirecting traffic to arbitrary sockets. "
        "  - main.editZTNARule: modify ZTNA interception rules. "
        "Verification required: check socket path and permission bits at runtime."
    ),
}


# ---------------------------------------------------------
# FIREWALL-F03: nftables flowtable -- hardware offload bypass risk
# ---------------------------------------------------------
FIREWALL_F03_FLOWTABLE = {
    "id":       "FIREWALL-F03",
    "product":  "firewall daemon -- nftables flowtable can bypass per-packet inspection",
    "severity": "MEDIUM -- flowtable-offloaded flows bypass nftables rules on subsequent packets",
    "class":    "Firewall rule bypass via hardware offload (CWE-693)",
    "evidence": [
        "string: 'AddFlowtable' (nftables flowtable creation)",
        "function: main.buildChains (creates full rule set including flowtables)",
    ],

    "description": (
        "nftables flowtables accelerate established connections by offloading them to the kernel's "
        "fast path (software) or network hardware (hardware offload). "
        "Once a connection is added to a flowtable, subsequent packets bypass the nftables ruleset. "
        "If the firewall daemon adds ZTNA-inspected flows to a flowtable prematurely, "
        "TPROXY interception may be bypassed for the remaining packets of that connection. "
        "Exploitation: establish a connection that passes TPROXY inspection for the first packet, "
        "trigger flowtable offload, then send subsequent packets that bypass ZTNA inspection."
    ),
}


# ---------------------------------------------------------
# fctsched architecture
# ---------------------------------------------------------
FCTSCHED_ARCH = {
    "id":       "FCTSCHED-ARCH",
    "product":  "fctsched -- FortiClient task scheduler daemon (C/C++, 10.2MB stripped ELF64)",
    "binary":   "/opt/forticlient/fctsched",

    "managed_tasks": {
        "AVScheduledScan":      "Scheduled antivirus scan (antivirus.scheduled_scans)",
        "StartUpdateTask":      "FortiClient signature + software update ('*********Call StartUpdateTask*')",
        "StartVpnTask":         "VPN connection task ('*********Call StartVpnTask*')",
        "StopTask":             "Task termination ('**********Call StopTask*')",
    },

    "features": {
        "antivirus":            "AV engine integration (Attempting to scan %s)",
        "antirootkit":          "Rootkit detection component",
        "auto_patch":           "Automatic vulnerability patching (auto_patch/level config field)",
        "automatic_virus_submission": "Automatic sample upload to Fortinet cloud",
        "vulnerability_scan":   "Scheduled vulnerability scan (forticlient_configuration_t.vulnerability_scan_t)",
    },

    "ipc": {
        "socket_name":  "8f6ddf1358bd9d067261f529f69fda59.ipc (MD5-hash hardcoded Unix socket filename)",
        "protocol":     "Accepted pipe<%u> on socket<%u> from %s -- pipe-based IPC",
        "queue":        "Add Task Queue size : %zu -- task queue with size tracking",
        "break_loop":   "Break task queue loop -- orderly shutdown",
    },

    "config_schema":    "forticlient_configuration_t protobuf (embedded in binary)",
    "proto_ref":        "firewall.Firewall.RefreshSimpleDNS -- fctsched triggers DNS refresh post-update",
}


# ---------------------------------------------------------
# FCTSCHED-F01: hardcoded IPC socket name
# ---------------------------------------------------------
FCTSCHED_F01_IPC_SOCKET = {
    "id":       "FCTSCHED-F01",
    "product":  "fctsched -- hardcoded MD5-hash IPC socket enables local task injection",
    "severity": "HIGH -- if socket is world-accessible, local process can inject or intercept scheduled tasks",
    "class":    "Insecure IPC socket permissions (CWE-732)",
    "evidence": [
        "string: '8f6ddf1358bd9d067261f529f69fda59.ipc'",
        "string: 'Accepted pipe<%u> on socket<%u> from %s'",
    ],

    "description": (
        "fctsched uses a Unix domain socket with a hardcoded MD5-hash filename "
        "(8f6ddf1358bd9d067261f529f69fda59.ipc) for IPC with other daemons. "
        "The MD5-hash filename pattern suggests obfuscation rather than a session-unique name. "
        "If the socket is created in /tmp/.forticlient/ (same pattern as run_shell_script output, VPN-F01) "
        "with world-writable permissions: "
        "  1. Local attacker sends a 'StartUpdateTask' message -> triggers update with attacker-specified source. "
        "  2. Local attacker sends 'AVScheduledScan' with a specific path -> scan timing side-channel. "
        "  3. Local attacker reads 'automatic_virus_submission' messages -> learns which files FortiClient flags. "
        "Verification: ls -la /tmp/.forticlient/*.ipc at runtime to confirm permissions."
    ),
}


# ---------------------------------------------------------
# FCTSCHED-F02: automatic_virus_submission -- silent file upload
# ---------------------------------------------------------
FCTSCHED_F02_VIRUS_SUBMISSION = {
    "id":       "FCTSCHED-F02",
    "product":  "fctsched -- automatic_virus_submission uploads files to Fortinet cloud without explicit consent",
    "severity": "MEDIUM -- privacy concern; sensitive files may be exfiltrated to Fortinet",
    "class":    "Unauthorized data collection (CWE-359)",
    "evidence": [
        "string: 'automatic_virus_submission'",
        "string: 'automatic_virus_submission_t'",
        "protobuf field: forticlient_configuration_t.antivirus_t.automatic_virus_submission",
    ],

    "description": (
        "fctsched includes an 'automatic_virus_submission' feature that uploads suspicious files "
        "to Fortinet's FortiGuard cloud for analysis. "
        "The feature is part of the antivirus_t configuration block (protobuf). "
        "If enabled (default state not confirmed from static analysis): "
        "  1. Any file fctsched deems suspicious is uploaded to Fortinet servers. "
        "  2. This includes potentially sensitive documents (Word files, PDFs) that trigger heuristics. "
        "  3. In a corporate environment, this may violate data residency or confidentiality policies. "
        "The upload destination (URL) is not visible in static strings -- likely embedded in the AV engine."
    ),
}


# ---------------------------------------------------------
# FCTSCHED-F03: auto_patch -- automatic patching without user confirmation
# ---------------------------------------------------------
FCTSCHED_F03_AUTO_PATCH = {
    "id":       "FCTSCHED-F03",
    "product":  "fctsched -- auto_patch installs system patches via update task without user interaction",
    "severity": "HIGH -- MITM on update channel delivers malicious patches via trusted daemon",
    "class":    "Insecure update mechanism (CWE-494)",
    "evidence": [
        "string: 'auto_patch'",
        "string: 'autopatch'",
        "string: 'auto_patch/level'",
        "string: '*********Call StartUpdateTask*'",
        "protobuf: forticlient_configuration_t.vulnerability_scan_t.auto_patch_t",
    ],

    "description": (
        "fctsched manages automatic patch installation for system vulnerabilities detected by the "
        "vulnerability scanner. The 'auto_patch/level' field controls which severity level triggers "
        "automatic patching without user interaction. "
        "Attack vector: MITM on the update channel between fctsched and the update source. "
        "If TLS certificate validation is disabled or the update URL is HTTP: "
        "  1. Attacker intercepts the update request from StartUpdateTask. "
        "  2. Returns a malicious update package. "
        "  3. fctsched installs the package with daemon-level privileges. "
        "Combined with VPN-F01 (on_connect script): a rogue FortiGate can deliver a malicious "
        "update that persists after VPN disconnection via the auto-patch mechanism."
    ),
}


# ---------------------------------------------------------
# fortivpn architecture
# ---------------------------------------------------------
FORTIVPN_ARCH = {
    "id":       "FORTIVPN-ARCH",
    "product":  "fortivpn -- FortiClient VPN-only package daemon (C/C++, 8.5MB stripped ELF64)",
    "binary":   "/opt/forticlient/fortivpn",
    "note":     "VPN-only package variant; stripped-down subset of the full vpn binary (11.8MB)",

    "shared_components": {
        "openssl":          "Same OpenSSL version and cipher suite as vpn binary",
        "certificate_ops":  "Same X509/certificate validation code paths as vpn binary",
        "auth":             "Same authentication framework (auth-psk, auth-ecdsa, auth-dss, auth-gost)",
        "protobuf_schema":  "Shares forticlient_configuration_t sslvpn_t schema with vpn binary",
    },

    "vpn_only_features": {
        "autoconnect":      "auto-connect + autoconnect_only_when_offnet -- network-triggered VPN",
        "autoconnect_tunnel": "autoconnect_tunnel -- tunnel-mode auto-connect",
        "sslvpn_schema":    "forticlient_configuration_t.vpn_t.sslvpn_t (connection parameters)",
        "ipsec_schema":     "forticlient_configuration_t.vpn_t.ipsecvpn_t (IKE settings, xauth)",
    },

    "vuln_inheritance": (
        "fortivpn shares the same C/C++ codebase as vpn binary. "
        "VPN-F01 (run_shell_script/system() RCE) is present if on_connect script handling is included. "
        "VPN-F03 (unbounded sprintf/strcpy callers) likely present given shared codebase. "
        "VPN-F08 (X509 state machine at 0x495b20) may be present at a different VA. "
        "Static analysis of fortivpn confirms the same auth-* strings and certificate validation paths."
    ),
}


# ---------------------------------------------------------
# FORTIVPN-F01: autoconnect_only_when_offnet -- evil twin attack surface
# ---------------------------------------------------------
FORTIVPN_F01_AUTOCONNECT_OFFNET = {
    "id":       "FORTIVPN-F01",
    "product":  "fortivpn -- autoconnect_only_when_offnet enables automatic VPN triggering via network manipulation",
    "severity": "HIGH -- evil twin access point causes VPN to connect to rogue FortiGate",
    "class":    "Automatic connection to untrusted network (CWE-923)",
    "evidence": [
        "string: 'autoconnect_only_when_offnet'",
        "string: 'autoconnect_tunnel'",
        "string: '--auto-connect'",
        "protobuf: forticlient_configuration_t.vpn_t.sslvpn_t.options_t.auto_connect",
    ],

    "description": (
        "The 'autoconnect_only_when_offnet' feature triggers a VPN connection automatically "
        "when FortiClient detects the endpoint is 'off network' (not on the corporate LAN). "
        "Detection is likely based on DNS resolution of an internal hostname or a probe to "
        "a known internal IP. "
        "Attack vector: "
        "  1. Attacker deploys an evil twin access point near the target. "
        "  2. Evil twin responds to the 'off-net detection' probe (DNS or IP) as if on-net, "
        "     then switches to off-net response to trigger auto-connect. "
        "  3. fortivpn initiates VPN connection to the configured FortiGate server. "
        "  4. If FortiGate server certificate validation is bypassed (or HSTS is absent), "
        "     fortivpn connects to a rogue FortiGate. "
        "  5. Rogue FortiGate pushes on_connect script (VPN-F01) -> RCE on the endpoint."
    ),
}
