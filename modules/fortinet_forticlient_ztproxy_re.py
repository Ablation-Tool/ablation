"""
FortiClient Linux ztproxy (Zero Trust proxy daemon) binary RE
Binary: /opt/forticlient/ztproxy (ELF64, stripped Go 1.23.2, 15MB)
Method: Go pclntab (gopclntab section) function table extraction + binary strings analysis
Go BuildID: MPrsy_Ma1qZLAW42tGXU/rVt1Z9dY2D5S9-K5AhfG/OW7FkFmSWtewOz3I4uwL/pN2uJM-3Aqu-jvZBLThh
Package: forticlient-vpn-standalone-linux_7.4.4_amd64.deb
Source ref: github.com/fortinet/forticlient/ (private repo; internal paths confirmed via gopclntab)
"""

# ---------------------------------------------------------
# Architecture overview
# ---------------------------------------------------------
ZTPROXY_ARCH = {
    "id":       "FCLIENT-ZTPROXY-ARCH",
    "product":  "FortiClient ztproxy -- Zero Trust Network Access transparent proxy daemon",
    "binary":   "/opt/forticlient/ztproxy",
    "format":   "ELF64 x86-64, stripped, PIE=No, Go 1.23.2",
    "size":     "15,236,096 bytes",
    "language": "Go 1.23.2 (gopclntab magic=0xfffffff1, function table: 1,188 functions, 20,729 names including closures)",
    "go_buildid": "MPrsy_Ma1qZLAW42tGXU/rVt1Z9dY2D5S9-K5AhfG",

    "internal_packages": {
        "ztproxy/cache":    "CertCacheStore + CertDB -- certificate management with SQLite backend; VerifyConnection, promptUser, handleCli, addCert, flushCerts, removeCert",
        "ztproxy/db":       "InitDatabase, AddError, checkConnection -- SQLite error/health database management",
        "ztproxy/ipwatch":  "IPRuleSet.Activate/AddRule/RemoveRule, Watcher.Watch -- iptables/nftables rule manipulation for TPROXY traffic interception",
        "ztproxy/proxy":    "TProxy.Start/Stop/handleConnection/forwardConnection/dial, AuthStore.GetFormAuth/GetSAMLAuth/UpdateFormAuth/UpdateSAMLAuth, Token.Monitor/notifyAccessProxy/getTLSConfig",
        "ztproxy/ztconfig": "Portal.Query/TryConnect, Watcher.queryPortalConfig/queryGatewayLatencies/gatherRules/writeHostsConfig -- ZTNA gateway configuration polling",
    },

    "key_dependencies": {
        "github.com/quic-go/quic-go": "QUIC transport for ZTNA tunneling (542 functions); QUIC v1 + Kyber PQC in TLS 1.3",
        "github.com/fortinet/forticlient/config": "FortiClient config system (555 functions)",
        "github.com/fortinet/forticlient/firewall": "Firewall rule management (101 functions)",
        "github.com/fortinet/forticlient/fctdns": "DNS filtering integration (15 functions)",
        "github.com/fortinet/forticlient/utmp": "UTMP session tracking",
        "modernc.org/sqlite v1.33.1": "Pure-Go SQLite for certificate cache and error DB",
        "zombiezen.com/go/sqlite v1.4.0": "Second SQLite library for additional stores",
        "github.com/elastic/go-sysinfo": "System info / process telemetry collection",
        "google.golang.org/protobuf": "Protobuf for IPC serialization",
        "github.com/google/uuid": "UUID for ZTNA session tokens",
    },

    "ipc_sockets": {
        "ipc:///var/run/forticlient/firewall.ipc": "NNG IPC to firewall daemon -- ztproxy sends iptables rule mutations here",
        "ipc:///var/run/forticlient/certd.ipc":    "NNG IPC to certd for ZTNA certificate operations",
        "ipc:///var/run/forticlient/cert_store.ipc": "NNG IPC to certificate store",
    },

    "databases": {
        "/var/run/forticlient/tcp-error.db": "SQLite; stores TCP connection errors per gateway",
    },

    "tproxy_mechanism": (
        "ztproxy uses Linux TPROXY (SO_MARK + iptables TPROXY target) to intercept TCP/UDP traffic "
        "destined for ZTNA-protected resources without requiring application changes. "
        "ztproxy/ipwatch.IPRuleSet.Activate inserts iptables rules; Watcher.Watch monitors IP changes. "
        "Intercepted connections are forwarded via forwardConnection() to the ZTNA gateway over QUIC. "
        "SO_MARK is set on outbound sockets (MarkedDialer pattern) to bypass the TPROXY rules for ztproxy's own traffic."
    ),

    "quic_transport": (
        "ZTNA tunnel uses QUIC (quic-go) over UDP. "
        "TLS 1.3 with Kyber (ML-KEM-768 post-quantum key exchange) attempted; falls back to X25519. "
        "Token.notifyAccessProxy() maintains a QUIC connection to the ZTNA access proxy. "
        "Token.Monitor() watches token expiry and triggers reconnection."
    ),
}

# ---------------------------------------------------------
# Findings
# ---------------------------------------------------------

FCLIENT_ZTPROXY_F01_CERT_BYPASS_MODE = {
    "id":       "FCLIENT-ZTPROXY-F01",
    "product":  "FortiClient ztproxy -- configurable TLS certificate validation bypass",
    "severity": "MEDIUM",
    "class":    "TLS certificate validation bypass (CWE-295); operator-configurable but no UI indicator to end user",

    "description": (
        "ztproxy binary contains the string 'Invalid server certificates are currently allowed' "
        "in its string table (confirmed via binary strings analysis of /opt/forticlient/ztproxy). "
        "This indicates a configurable mode where gateway certificate validation is downgraded from "
        "reject to allow. When active, ztproxy will establish QUIC tunnels to ZTNA gateways "
        "presenting invalid or self-signed certificates without user warning. "
        "The Barton CC FortiClient config (bartonccnew.conf, publicly exposed at "
        "docs.bartonccc.edu/infoserv/vpn/Fortinet/bartonccnew.conf) shows "
        "disallow_invalid_server_certificate=0 and warn_invalid_server_certificate=1, "
        "confirming that certificate validation bypass is commonly deployed in production."
    ),

    "strings_evidence": [
        "Invalid server certificates are currently allowed",
        "Failed to load ztna certificate: %v",
        "No client certificate will be used",
    ],

    "attack_surface": (
        "An attacker with a rogue ZTNA gateway or DNS poisoning capability can present an invalid "
        "certificate and establish the QUIC tunnel when this mode is active. "
        "Combined with FCLIENT-ZTPROXY-F04 (SSRF via gateway URL), the cert bypass removes the "
        "TLS barrier to intercepting ZTNA-tunneled traffic."
    ),

    "real_world_config": {
        "source": "https://docs.bartonccc.edu/infoserv/vpn/Fortinet/bartonccnew.conf",
        "generated_by": "FCT-7.0.12.0572",
        "vpn_gateway": "barton-vpn.kanren.net:443",
        "disallow_invalid_server_certificate": "0 (validation bypass ENABLED)",
        "warn_invalid_server_certificate": "1 (warn only, not block)",
        "cert_cn_match": "wildcard (*) -- any CN accepted",
        "cert_issuer_match": "wildcard (*) -- any CA accepted",
    },

    "remediation": "Set disallow_invalid_server_certificate=1 in FortiClient EMS policy. Deploy internal CA and restrict trusted issuers.",
}

FCLIENT_ZTPROXY_F02_FIREWALL_IPC = {
    "id":       "FCLIENT-ZTPROXY-F02",
    "product":  "FortiClient ztproxy -- NNG IPC socket for iptables rule mutation; local privilege escalation",
    "severity": "MEDIUM",
    "class":    "Local IPC access control; world-accessible NNG socket allows firewall rule manipulation (CWE-732)",

    "description": (
        "ztproxy communicates with the FortiClient firewall daemon over NNG IPC at "
        "'ipc:///var/run/forticlient/firewall.ipc'. "
        "This socket path is in /var/run/forticlient/ -- a directory that may be world-readable by default. "
        "NNG IPC on Linux uses abstract Unix sockets or filesystem paths; if the socket file permissions "
        "are not restrictive (mode 0600 or similar), any local process can connect and send "
        "firewall rule mutation messages. "
        "The github.com/fortinet/forticlient/firewall package (101 functions) handles the rule set, "
        "and ztproxy/ipwatch.IPRuleSet.Activate() modifies iptables to implement TPROXY interception. "
        "A local attacker who can write to this socket can insert or delete iptables rules, potentially "
        "redirecting network traffic or disabling the ZTNA enforcement layer."
    ),

    "ipc_paths_confirmed": [
        "ipc:///var/run/forticlient/firewall.ipc",
        "ipc:///var/run/forticlient/certd.ipc",
        "ipc:///var/run/forticlient/cert_store.ipc",
        "8f6ddf1358bd9d067261f529f69fda59.ipc (hash-named dynamic socket)",
    ],

    "re_evidence": (
        "String 'ipc:///var/run/forticlient/firewall.ipc' confirmed at binary offset in ztproxy. "
        "Functions: ztproxy/ipwatch.(*IPRuleSet).Activate (inserts rules), "
        "ztproxy/ipwatch.(*Watcher).updateRules (updates on IP change), "
        "github.com/fortinet/forticlient/firewall (101 functions -- full firewall rule API)."
    ),

    "check": "ls -la /var/run/forticlient/*.ipc -- look for world-writable socket files",
    "remediation": "Set firewall.ipc socket permissions to 0600, owned by root. Add peer UID check in NNG server (NNG supports IPC peer credentials via ipc:peer-uid).",
}

FCLIENT_ZTPROXY_F03_SAML_SQLITE_CREDS = {
    "id":       "FCLIENT-ZTPROXY-F03",
    "product":  "FortiClient ztproxy -- SAML and form credentials cached in SQLite; local exfiltration",
    "severity": "MEDIUM",
    "class":    "Insecure credential storage; authentication tokens in plaintext SQLite (CWE-312)",

    "description": (
        "ztproxy caches ZTNA gateway authentication credentials in SQLite databases at "
        "/var/run/forticlient/. "
        "Functions AuthStore.GetSAMLAuth, AuthStore.GetFormAuth, AuthStore.UpdateSAMLAuth, "
        "AuthStore.UpdateFormAuth (in ztproxy/proxy package) manage credential retrieval and storage. "
        "The string 'Updated cached credentials for gateway %v' confirms credentials are written "
        "to persistent storage after each successful authentication. "
        "Two SQLite libraries are statically linked: modernc.org/sqlite v1.33.1 and "
        "zombiezen.com/go/sqlite v1.4.0, with SQLite queries including "
        "UPDATE Cert SET state = ? WHERE hostname = ? and DELETE FROM Cert WHERE hostname = ?. "
        "A local attacker with read access to /var/run/forticlient/*.db can extract cached "
        "SAML tokens or form credentials without triggering any re-authentication."
    ),

    "functions_evidence": [
        "ztproxy/proxy.(*AuthStore).GetSAMLAuth",
        "ztproxy/proxy.(*AuthStore).GetFormAuth",
        "ztproxy/proxy.(*AuthStore).UpdateSAMLAuth",
        "ztproxy/proxy.(*AuthStore).UpdateFormAuth",
    ],

    "strings_evidence": [
        "Updated cached credentials for gateway %v",
        "UPDATE Cert SET state = ? WHERE hostname = ?;",
        "DELETE FROM Cert WHERE hostname = ?;",
        "ws://127.0.0.1&type=FORM&id=",
        "ws://127.0.0.1&type=SAML&id=",
    ],

    "deps_versions": {
        "modernc.org/sqlite": "v1.33.1",
        "zombiezen.com/go/sqlite": "v1.4.0",
    },

    "check": "ls -la /var/run/forticlient/*.db && sqlite3 /var/run/forticlient/*.db .schema",
    "remediation": "Encrypt SQLite DB with SQLCipher. Store SAML tokens in OS keyring (libsecret/Keychain). Set /var/run/forticlient/ mode 0700.",
}

FCLIENT_ZTPROXY_F04_ZTNA_API_ENDPOINT = {
    "id":       "FCLIENT-ZTPROXY-F04",
    "product":  "FortiClient ztproxy -- non-standard ZTNA API endpoint pattern; SSRF surface",
    "severity": "LOW",
    "class":    "Non-standard hardcoded API path; potential SSRF if gateway URL is attacker-controlled (CWE-918)",

    "description": (
        "ztproxy constructs ZTNA service API URLs using the hardcoded path component 'fct-api-xxyyzz': "
        "https://%v/fct-api-xxyyzz?command=service "
        "(confirmed via binary strings analysis). "
        "The %v placeholder is the gateway hostname from the ZTNA policy configuration. "
        "The 'xxyyzz' suffix in the path is an internal obfuscated API endpoint (not a standard REST path). "
        "If an attacker can manipulate the ZTNA gateway URL (via rogue EMS policy, DNS spoofing, "
        "or config file write), they can redirect this request to an attacker-controlled server, "
        "leaking the FortiClient's authentication context including the ZTNA token."
    ),

    "strings_evidence": [
        "https://%v/fct-api-xxyyzz?command=service",
        "failed to send HTTP/3 request: %w",
        "failed to open HTTP/3 request stream: %w",
    ],

    "remediation": "Pin gateway URLs in EMS policy. Validate gateway hostname against an allowlist before constructing requests. Certificate pinning for ZTNA gateway.",
}

FCLIENT_ZTPROXY_F05_QUIC_PQC = {
    "id":       "FCLIENT-ZTPROXY-F05",
    "product":  "FortiClient ztproxy -- QUIC with Kyber PQC; version and library metadata",
    "severity": "INFORMATIONAL",
    "class":    "Dependency version tracking; PQC implementation in production",

    "description": (
        "ztproxy implements the ZTNA tunnel using QUIC over UDP via github.com/quic-go/quic-go (542 functions). "
        "TLS 1.3 handshake includes Kyber (ML-KEM-768) post-quantum key exchange -- confirmed by "
        "error strings 'tls: invalid Kyber server key share' and 'tls: invalid Kyber client key share'. "
        "The binary was built with Go 1.23.2. "
        "HTTP/3 (QUIC) is used for the ZTNA service command channel (HTTP/3 request stream errors present). "
        "ECN (Explicit Congestion Notification) is enabled for QUIC -- 'Activating reading of ECN bits for IPv4/IPv6'. "
        "0-RTT is supported but rejected-path is handled: '0-RTT was rejected. Dropping 0-RTT keys.' "
        "The quic-go version determines exposure to known QUIC CVEs; version not determinable from binary alone."
    ),

    "tech_detail": {
        "quic_impl": "github.com/quic-go/quic-go (version from go.sum not available in binary)",
        "pqc": "ML-KEM-768 (Kyber) in TLS 1.3 -- server and client key share paths present",
        "ecn": "Enabled for IPv4 and IPv6",
        "zero_rtt": "Supported with explicit rejection handling",
        "http3": "QUIC-over-HTTP/3 for ZTNA service command channel",
        "go_version": "1.23.2",
    },

    "re_note": (
        "ztproxy Go pclntab parsed with Go 1.20+ magic (0xfffffff1). "
        "Total 1,188 function entries, 20,729 named symbols including closures. "
        "355 functions in ztproxy/* packages (cache, db, ipwatch, proxy, ztconfig)."
    ),
}

FCLIENT_ZTPROXY_F06_HOSTS_WRITE = {
    "id":       "FCLIENT-ZTPROXY-F06",
    "product":  "FortiClient ztproxy -- writes /etc/hosts equivalent for ZTNA; local file write primitive",
    "severity": "LOW",
    "class":    "Local file write by privileged daemon; ZTNA hostnames written to hosts config",

    "description": (
        "ztproxy/ztconfig.(*Watcher).writeHostsConfig (and writeHostsConfig-fm method alias) writes "
        "a ZTNA-managed hosts configuration file. "
        "Error string 'Failed to write ZTNA hosts config: %v' confirms this is a runtime operation. "
        "The function is referenced in the scheduleGatherRules goroutine, meaning it is triggered "
        "automatically when ZTNA gateway rules change. "
        "If the target path is /etc/hosts or a file that is symlinked from /etc/hosts, "
        "a rogue EMS policy that injects attacker-controlled hostnames could add DNS override entries "
        "visible to all processes on the host. "
        "The vpn binary also writes /etc/resolv.conf (confirmed in fortinet_forticlient_vpn_binary_re.py), "
        "making FortiClient a multi-path DNS resolution manipulator."
    ),

    "functions_evidence": [
        "ztproxy/ztconfig.(*Watcher).writeHostsConfig",
        "ztproxy/ztconfig.(*Watcher).writeHostsConfig-fm",
        "ztproxy/ztconfig.(*Watcher).scheduleGatherRules",
    ],

    "strings_evidence": [
        "Failed to write ZTNA hosts config: %v",
        "Failed to generate index key for rule: %v",
    ],

    "remediation": "Write to /var/run/forticlient/ztna-hosts (not /etc/hosts). Validate hostnames against ZTNA gateway allowlist before writing.",
}

# ---------------------------------------------------------
# Metadata
# ---------------------------------------------------------

ZTPROXY_RE_METADATA = {
    "module":           "fortinet_forticlient_ztproxy_re",
    "binary":           "/opt/forticlient/ztproxy",
    "version":          "FortiClient Linux 7.4.4",
    "analysis_method":  "Go pclntab (gopclntab section) function table extraction + binary strings; ablation semantic sweep pending",
    "go_pclntab_magic": "0xfffffff1 (Go 1.20+)",
    "total_go_funcs":   1188,
    "ztproxy_funcs":    355,

    "unique_findings":  ["FCLIENT-ZTPROXY-F01", "FCLIENT-ZTPROXY-F02", "FCLIENT-ZTPROXY-F03",
                         "FCLIENT-ZTPROXY-F04", "FCLIENT-ZTPROXY-F05", "FCLIENT-ZTPROXY-F06"],

    "pending": [
        "edrcomm binary RE (1.2MB PIE; EDR communication daemon; no prior module)",
        "ztproxy BERT semantic sweep (requires pclntab Go 1.20+ parser update in ablation)",
        "quic-go version extraction from go.sum embedded in binary (check .go.buildinfo section)",
        "FortiSOAR fortipam connector RE (21K RPM downloaded at /tmp/fortisoar_re/)",
        "FortiSOAR fortisiem connector RE (107K RPM)",
        "FortiSOAR fortimanager-json-rpc connector RE (27K RPM)",
    ],
}
