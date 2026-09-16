"""
FortiClient Linux (standalone DEB) binary RE: epctrl (C++) + confighandler (Rust)
Sources:
  - extracted/forticlient-standalone-deb/opt/forticlient/epctrl (ELF64, x86-64, stripped C++)
  - extracted/forticlient-standalone-deb/opt/forticlient/confighandler (ELF64, x86-64, stripped Rust)
  - extracted/forticlient-standalone-deb/opt/forticlient/vpn (ELF64, x86-64, stripped C++)
  - extracted/forticlient-standalone-deb/opt/forticlient/iked (ELF64, x86-64, stripped)
Products: FortiClient (Linux standalone 7.x)
Method: binary strings analysis (semantic binary RE; no disassembly yet)
"""

# ---------------------------------------------------------
# FortiClient Linux binary architecture overview
# ---------------------------------------------------------
FORTICLIENT_LINUX_ARCH = {
    "id":       "FCLIENT-LINUX-ARCH",
    "product":  "FortiClient Linux standalone",
    "install_path": "/opt/forticlient/",

    "binary_map": {
        "epctrl":         "C++ EMS registration daemon; state machine; MSG_HEADER protocol; port 8013",
        "confighandler":  "Rust config+UI+auth service; WebSocket server; OIDC/SAML/TPM; SQLite config",
        "vpn":            "C SSL VPN client; EMS integration; /remote/logincheck; TLS extension (EMS info)",
        "certd":          "Certificate daemon (PIE ELF); client certificate management",
        "iked":           "IKE daemon; IPsec VPN key exchange",
        "fctsched":       "Scheduler daemon; policy enforcement timing",
        "forticlient-cli": "CLI interface binary",
        "legacy.so":      "Legacy compatibility library",
        "libcertd.so":    "Certificate library (shared object for certd/epctrl)",
        "tpm2/lib/pkcs11.so": "PKCS#11 TPM2 provider; used by confighandler for ZTNA key operations",
    },

    "ipc_mechanisms": {
        "shmget/shmat/shmdt": "System V shared memory between epctrl (C++) and confighandler (Rust)",
        "socketpair/pipe":    "Unix pipe pairs for local IPC",
        "abstract_socket":    "Linux abstract namespace Unix socket (no filesystem permissions)",
        "warp_websocket":     "confighandler exposes local WebSocket server for GUI communication",
    },
}


# ---------------------------------------------------------
# epctrl binary RE: EMS registration protocol (C++)
# ---------------------------------------------------------
FORTICLIENT_EPCTRL = {
    "id":       "FCLIENT-EPCTRL",
    "product":  "FortiClient epctrl -- EMS endpoint control daemon",
    "binary":   "/opt/forticlient/epctrl (ELF64 x86-64 stripped; 12MB, dynamically linked)",
    "language": "C++ (symbols: epctrl::StateMachine, epctrl::RegisterOptions, epctrl::DataDownloader)",
    "source":   "/home/devops/code/src/epctrl/src/ (state_machine.cpp, client.cpp, data_downloader.cpp, data_manager.cpp, data_uploader.cpp, message/keepalive.cpp)",
}

FCLIENT_EPCTRL_F01_UUID_GENERATION = {
    "id":       "FCLIENT-EPCTRL-F01",
    "product":  "FortiClient epctrl -- FCTUID random UUID generation",
    "severity": "INFORMATIONAL -- FCTUID is random UUID; no hardware binding; confirms spoofing is trivial",
    "class":    "Identity weakness; FCTUID from libuuid uuid_generate (RFC 4122 type 4 random)",

    "description": (
        "epctrl links against libuuid.so.1 and calls: "
        "  uuid_generate() -- generates random RFC 4122 UUID "
        "  uuid_unparse_upper() -- formats as uppercase hex string XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX. "
        "FCTUID (FortiClient Unique ID) is a randomly generated UUID, NOT derived from hardware. "
        "There is no hardware fingerprinting (TPM, CPU serial, MAC) used in FCTUID generation. "
        "Device identity for EMS is primarily the MAC address and /etc/machine-id "
        "(the latter used for registration key encryption, not FCTUID itself). "
        "Implication: any UUID-format string is a valid FCTUID. "
        "The CVE-2023-48788 Python PoC hardcodes FCTUID=CBE8FC122B1A46D18C3541E1A8EFF7BD "
        "as a placeholder -- confirmed correct: no hardware access needed to spoof a FortiClient agent."
    ),

    "machine_id_role": (
        "/etc/machine-id is used for 'machine password for encrypting registration key'. "
        "This is a separate mechanism from FCTUID -- it encrypts the registration key exchange, "
        "not the client identifier. "
        "An attacker spoofing a FortiClient REGISTER message does not need /etc/machine-id "
        "from the target machine; they only need a valid UUID format for FCTUID."
    ),

    "re_insight": (
        "Compare with CVE-2023-48788 EMS SQLi mechanics: the injection works because FcmDaemon "
        "trusts ANY FCTUID value from the network. Since FCTUID is random per installation, "
        "EMS cannot validate 'is this FCTUID from a legitimate device' -- it only checks format. "
        "Ablation semantic sweep: find uuid_generate callsite in epctrl; "
        "query: 'function calling uuid_generate then uuid_unparse_upper; stores result in FCTUID field'."
    ),
}

FCLIENT_EPCTRL_PROTOCOL = {
    "id":       "FCLIENT-EPCTRL-PROTO",
    "product":  "FortiClient epctrl -- EMS registration protocol headers (complete list)",

    "x_fcck_header_family": {
        "X-FCCK-PROBE: FCCINFO||SYSINFO||": "Initial probe message; contains device capabilities",
        "X-FCCK-PROBE-END":                 "End marker for probe message",
        "X-FCCK-REGISTER: ":                "Registration payload start (CVE-2023-48788 injection target)",
        "X-FCCK-REGISTER-END":              "Registration payload end marker",
        "X-FCCK-KA: ":                      "Keepalive message start",
        "X-FCCK-KA-END":                    "Keepalive message end",
        "X-FCCK-TAG: ":                     "Tag message start (ZTNA tags / endpoint tags)",
        "X-FCCK-TAG-END":                   "Tag message end",
    },

    "msg_header_fields": {
        "MSG_HEADER: ":    "Protocol frame header prefix",
        "SYSINFO=":        "System information field in SYSINFO block",
        "HOSTNAME":        "Device hostname",
        "fctver":          "FortiClient version string",
        "device_id":       "Device identifier (distinct from FCTUID)",
        "ip_address":      "Endpoint IP address",
        "mac_address":     "Primary MAC address",
        "macs":            "All MAC addresses (onnet_mac_addresses)",
        "KA_INTERVAL":     "Keepalive interval in response (detection primitive for CVE-2023-48788)",
    },

    "state_machine_states": {
        "Pre-Register":        "Initial state before first EMS contact",
        "Trying Register":     "Registration attempt in progress",
        "Already Registered":  "Registration complete",
        "Not Registered":      "Registration failed or not attempted",
        "Cloud Register":      "Cloud-based registration path (FortiCloud EMS)",
    },

    "port": "8013 (default; -p --port argument for CLI override)",

    "re_insight": (
        "The X-FCCK-* header family is the complete EMS communication protocol. "
        "X-FCCK-REGISTER carries the SYSINFO block that CVE-2023-48788 targets. "
        "X-FCCK-TAG carries ZTNA endpoint tags -- these are the ztnaemstag values "
        "that FortiPAM checks against (FPAM-VAULT-F01 cross-reference). "
        "An attacker who can construct valid X-FCCK-REGISTER and X-FCCK-TAG messages "
        "can register a spoofed device with arbitrary ZTNA tags, satisfying any ztnaemstag policy "
        "without a real device. MAC address in the REGISTER message is the main binding -- "
        "MAC address is easily spoofed on Linux."
    ),
}

FCLIENT_EPCTRL_F02_CERT_SERIAL = {
    "id":       "FCLIENT-EPCTRL-F02",
    "product":  "FortiClient epctrl -- EMS client certificate serial validation",
    "severity": "INFORMATIONAL -- cert_serial/ems_serial validation present; validates EMS cert CN",
    "class":    "Certificate validation; 'client certificate does not match the expected serial number'",

    "description": (
        "'client certificate does not match the expected serial number' string in epctrl. "
        "Fields: cert_serial, ems_serial. "
        "epctrl validates the EMS server's certificate serial matches the expected EMS serial. "
        "This prevents an attacker from intercepting EMS traffic by presenting a different cert. "
        "However: the CLIENT certificate (FortiClient -> EMS) uses the FCTUID-derived serial. "
        "If EMS (FcmDaemon on Windows) does not validate the client cert against a known-good list, "
        "then epctrl's client cert validation is one-sided. "
        "CVE-2024-47575 (FortiManager): fdssvrd accepts ANY client cert -- same pattern possible in EMS."
    ),

    "ablation_target": (
        "FcmDaemon.exe (Windows): does it call SSL_CTX_set_verify with SSL_VERIFY_PEER? "
        "If not, any FortiClient cert is accepted. "
        "Ablation semantic sweep for FcmDaemon: "
        "query: 'SSL context initialization; sets verify mode for client certificate validation'. "
        "Note: FcmDaemon.exe is a Windows PE -- requires Windows binary RE tools."
    ),
}


# ---------------------------------------------------------
# confighandler binary RE: Config + Auth + ZTNA (Rust)
# ---------------------------------------------------------
FORTICLIENT_CONFIGHANDLER = {
    "id":       "FCLIENT-CONFIGHANDLER",
    "product":  "FortiClient confighandler -- configuration and authentication service",
    "binary":   "/opt/forticlient/confighandler (ELF64 x86-64 stripped Rust; ~2x larger than epctrl)",
    "language": "Rust (tokio async runtime; warp WebSocket; hyper/reqwest HTTP; rustls TLS; rusqlite SQLite; serde protobuf)",
    "frameworks": "tokio, warp, hyper, reqwest, rustls, ring, x509-parser, openidconnect, jsonwebtoken, rusqlite, protobuf",
}

FCLIENT_CONFIGHANDLER_F01_ABSTRACT_SOCKET = {
    "id":       "FCLIENT-CONFIGHANDLER-F01",
    "product":  "FortiClient confighandler -- abstract namespace Unix socket (no filesystem permissions)",
    "severity": "MEDIUM -- abstract socket grants any local process access if no auth on the WebSocket",
    "class":    "Missing access control on local IPC surface (CWE-284)",

    "description": (
        "confighandler uses SocketAddrExt::as_abstract_name() -- Linux abstract namespace Unix sockets. "
        "Abstract namespace sockets have no filesystem path and NO filesystem permission enforcement. "
        "Any process on the same Linux host can connect to the abstract socket by name alone. "
        "confighandler exposes a warp WebSocket server on this socket for GUI communication. "
        "If the WebSocket server does not authenticate connecting clients: "
        "  - Any local process can send WebSocket messages to confighandler "
        "  - confighandler processes config commands (forticlient_configuration_t Protobuf) "
        "  - A malicious local process could: "
        "    (a) Extract stored VPN credentials from SQLite config "
        "    (b) Inject new VPN server configurations pointing to attacker-controlled host "
        "    (c) Trigger SAML/OIDC authentication flow and capture tokens "
        "Local privilege escalation: any user-space process to FortiClient-stored VPN credentials."
    ),

    "abstract_socket_name": "Not determined from strings (requires binary analysis or strace at runtime)",

    "re_insight": (
        "To find the abstract socket name: strace -e network confighandler at startup; "
        "look for bind(fd, {sa_family=AF_UNIX, sun_path=@'<name>'}) calls. "
        "The @-prefix in the path indicates abstract namespace. "
        "Ablation approach: run confighandler in controlled environment and monitor socket creation "
        "with ss -lnx or lsof -U. "
        "If the socket name is predictable (e.g., @forticlient_config), any local process can connect."
    ),
}

FCLIENT_CONFIGHANDLER_F02_TPM_ZTNA_CHAIN = {
    "id":       "FCLIENT-CONFIGHANDLER-F02",
    "product":  "FortiClient confighandler -- TPM ZTNA attestation chain",
    "severity": "INFORMATIONAL -- hardware attestation; bypassable on VM deployments (software TPM)",
    "class":    "ZTNA device attestation via TPM; Ed25519 signing; Protobuf message protocol",

    "attestation_chain": (
        "1. confighandler receives ZTNA attestation request (via WebSocket or shared memory). "
        "2. confighandler sends ZtnaSign Protobuf request to tpm2/lib/pkcs11.so (TPM2 provider). "
        "3. tpm2/lib/pkcs11.so talks to local TPM2 chip via kernel driver. "
        "4. Ed25519 key (ring::ec::curve25519::ed25519::signing::Ed25519KeyPair::sign) signs challenge. "
        "5. Sign response Protobuf (tpm::response::Sign) returned to confighandler. "
        "6. confighandler passes attestation result to epctrl via shared memory "
        "   (Shm::epctrl_auth_saml or Shm::epctrl_auth_user). "
        "7. epctrl includes X-FCCK-TAG with ZTNA attestation in EMS registration."
    ),

    "vm_bypass": (
        "On VM deployments (FortiGate VM64, AWS, Azure, GCP): "
        "  - Software TPM (Microsoft vTPM, QEMU TPM emulator) instead of hardware TPM. "
        "  - Software TPM does not provide hardware-backed key isolation. "
        "  - The private key material may be extractable from VM memory/disk. "
        "  - Implication: ZTNA hardware attestation is meaningless for VM-hosted endpoints "
        "    and for cloud-based FortiClient EMS deployments where VMs are the norm."
    ),

    "shared_memory_ipc": (
        "Shm::epctrl_auth_saml -- SAML assertion passed via System V shared memory. "
        "Shm::epctrl_auth_user -- user credentials passed via System V shared memory. "
        "System V shared memory (shmget/shmat) on Linux: "
        "  - Permissions controlled by shmget flags (typically 0600 for process-private). "
        "  - If permissions are too permissive (0644 or 0666), other local processes can read/write. "
        "  - SAML assertion in writable shared memory = SAML injection attack surface. "
        "Ablation: check shmget() flags in epctrl and confighandler at runtime via strace."
    ),

    "re_insight": (
        "The ZTNA attestation chain is the most sophisticated security feature in FortiClient Linux. "
        "Bypass vectors: "
        "1. VM/software TPM: key not hardware-bound; extractable from VM snapshot. "
        "2. Shared memory race: if confighandler writes SAML to SHM before SAML is validated, "
        "   and epctrl reads before validation completes, a race condition could allow assertion injection. "
        "3. EMS SQLi (CVE-2023-48788): if EMS server is compromised, ZTNA attestation is moot -- "
        "   the EMS server is the relying party. "
        "Ablation semantic sweep for confighandler: Rust symbols need demangling; "
        "query: 'async function sending ZtnaSign to TPM2; waiting for Sign response; writing to shared memory'. "
        "Rust binaries are more difficult to semantic-sweep due to inlining and monomorphization."
    ),
}

FCLIENT_CONFIGHANDLER_F03_OIDC = {
    "id":       "FCLIENT-CONFIGHANDLER-F03",
    "product":  "FortiClient confighandler -- OpenID Connect + JWT license validation",
    "severity": "INFORMATIONAL -- standard OIDC flow; JwkSet JWT verification present",
    "class":    "License validation via OAuth2/OIDC; JWT signature verification with JWKS",

    "description": (
        "LicenceClient::generate_auth_url() -- OAuth2/OIDC authorization URL generation. "
        "JwkSet::verify_jwt() -- JWT signature verification using JSON Web Key Set. "
        "openidconnect library -- full OIDC client implementation. "
        "FortiClient standalone (non-EMS) uses OIDC for license activation: "
        "  1. generate_auth_url -> browser redirect to Fortinet's OAuth2 authorization endpoint. "
        "  2. User authenticates with FortiCloud credentials. "
        "  3. OAuth2 code returned to local confighandler redirect URI (likely localhost). "
        "  4. Code exchanged for JWT license token. "
        "  5. JWT verified with Fortinet's JWKS endpoint. "
        "Attack surface: if the OAuth2 redirect URI is not validated, redirect to attacker-controlled URI "
        "  steals the authorization code. "
        "FortiClient likely uses a custom URI scheme (forticlient://) or localhost as redirect URI."
    ),

    "license_websocket_messages": {
        "LicenceRegister":  "WebSocket message type: trigger license registration flow",
        "LicenceSignout":   "WebSocket message type: sign out of license",
        "VulScanStop":      "WebSocket message type: stop vulnerability scan",
    },
}


# ---------------------------------------------------------
# vpn binary RE: SSL VPN client (C)
# ---------------------------------------------------------
FORTICLIENT_VPN = {
    "id":       "FCLIENT-VPN",
    "product":  "FortiClient vpn -- SSL VPN client daemon",
    "binary":   "/opt/forticlient/vpn (ELF64 x86-64 stripped; 12MB)",
    "language": "C (dynamically linked; glibc 2.6.32 minimum; likely includes OpenSSL)",
}

FCLIENT_VPN_EMS_TLS = {
    "id":       "FCLIENT-VPN-EMS-TLS",
    "product":  "FortiClient vpn -- EMS TLS extension (FSV_EMS_SN)",
    "severity": "INFORMATIONAL -- EMS serial in TLS extension; traces to CVE-2024-47575 parallel",
    "class":    "TLS extension carrying EMS identity claim in SSL VPN handshake",

    "description": (
        "vpn binary strings: "
        "  'FSV_EMS_SN' -- FortiClient SSL VPN EMS Serial Number TLS extension "
        "  'EMSSN_tenant' -- EMS tenant ID in TLS extension "
        "  'tls_construct_ctos_ems' -- constructs client TLS extension for EMS info "
        "  'tls_parse_ctos_ems' -- parses received EMS TLS extension "
        "  'tls_construct_stoc_ems' -- server-side EMS TLS extension construction. "
        "FortiClient SSL VPN sends EMS serial number in a custom TLS extension (ctos = client-to-server). "
        "The SSL VPN server (sslvpnd on FortiOS) uses this extension to associate VPN sessions "
        "with EMS device registrations -- enables EMS-controlled VPN access policy. "
        "If FSV_EMS_SN extension is not validated by sslvpnd against actual EMS records, "
        "an attacker could inject an arbitrary EMS serial in the TLS extension "
        "to impersonate an EMS-registered device and bypass VPN access restrictions."
    ),

    "re_insight": (
        "The FSV_EMS_SN TLS extension creates a parallel trust chain to the EMS registration: "
        "FortiOS sslvpnd must validate the EMS serial in the TLS extension against EMS registration data. "
        "If sslvpnd only checks that FSV_EMS_SN is present (not that it's valid), "
        "any client that adds this extension bypasses EMS-gated VPN access. "
        "Ablation semantic sweep for sslvpnd: "
        "query: 'function parsing TLS extension with FortiClient EMS serial; validates against registered device list'."
    ),
}


# ---------------------------------------------------------
# Systemic: FortiClient Linux trust boundary weaknesses
# ---------------------------------------------------------
FORTICLIENT_LINUX_SYSTEMIC = {
    "id":       "FCLIENT-LINUX-SYSTEMIC",
    "product":  "FortiClient Linux (standalone)",
    "severity": "HIGH -- multiple local attack surfaces; shared memory IPC; abstract socket; random FCTUID",

    "attack_surface_map": {
        "Network -> EMS (epctrl)":              "Port 8013 TCP/TLS; FCTUID spoofable; X-FCCK-REGISTER injectable",
        "Network -> SSL VPN (vpn)":             "Port 443 SSL VPN; FSV_EMS_SN TLS extension; EMS policy bypass",
        "Local -> confighandler (websocket)":   "Abstract namespace socket; no filesystem permissions; config extraction",
        "Local -> shared memory (SHM)":         "System V SHM between epctrl/confighandler; SAML/user auth IPC",
        "Local -> SQLite (rusqlite)":           "FortiClient config database; stores VPN credentials",
        "TPM -> ZTNA attestation":              "Ed25519 via TPM2/PKCS#11; bypassable on VM/software TPM",
    },

    "cross_cve_chain": (
        "CVE-2023-48788 (EMS SQLi SYSTEM RCE) + FortiClient Linux local: "
        "1. CVE-2023-48788 compromises EMS server (SYSTEM on Windows). "
        "2. Attacker controls EMS policy distribution. "
        "3. FortiClient Linux confighandler connects to EMS and accepts new configuration. "
        "4. Malicious configuration delivered via X-FCCK-* protocol -- potential RCE on endpoint. "
        "This chain runs the CVE upstream: FortiClient is the victim after EMS is compromised."
    ),
}
