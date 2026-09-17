"""
FortiClient Linux: iked (IKE daemon for IPsec VPN) binary RE
Sources:
  - extracted/forticlient-standalone-deb/opt/forticlient/iked (ELF64 x86-64 stripped C; 11.6MB)
Products: FortiClient Linux standalone 7.x
Method: binary strings analysis
"""

# ---------------------------------------------------------
# iked binary RE: IPsec IKEv2 daemon
# ---------------------------------------------------------
FORTICLIENT_IKED = {
    "id":       "FCLIENT-IKED",
    "product":  "FortiClient iked -- IKE (Internet Key Exchange) daemon for IPsec VPN",
    "binary":   "/opt/forticlient/iked (ELF64 x86-64 stripped; 11.6MB)",
    "language": "C (OpenSSL 3.5.5 bundled; NNG 1.8.0 for IPC; strongSwan or custom IKE stack)",
    "ipc_framework": "NNG (Nano Next Generation) 1.8.0 -- REQ/REP and PAIR protocols over IPC transport",

    "source_paths": {
        "/home/devops/code/.build/amd64/deb/src/nng/nng-1.8.0/src/": "NNG messaging library",
        "/home/devops/code/.build/amd64/deb/src/openssl/openssl-3.5.5/installed/": "OpenSSL 3.5.5 bundled",
    },
}

FCLIENT_IKED_F01_TSS2_TPM = {
    "id":       "FCLIENT-IKED-F01",
    "product":  "FortiClient iked -- TSS2 TPM key blobs for IKE private key (same dual-path as certd)",
    "severity": "HIGH -- on systems without TPM, IKE private key = PEM file on disk",
    "class":    "Cryptographic key exposure; TSS2/PEM dual-path (CWE-321); same class as FCLIENT-CERTD-F01",

    "description": (
        "iked binary contains two TSS2 PEM header strings: "
        "  '-----BEGIN TSS2 KEY BLOB-----' "
        "  '-----BEGIN TSS2 PRIVATE KEY-----'. "
        "TSS2 (TPM2 Software Stack) PEM format is the standard encoding for TPM2-backed private keys. "
        "iked uses the same pattern as certd (FCLIENT-CERTD-F01): "
        "  Hardware TPM present -> TSS2 key blob; key is hardware-bound and non-exportable. "
        "  No TPM (VM, container, old hardware) -> standard PEM private key stored on disk. "
        "The IKE private key is used for IKEv2 certificate-based authentication to the IPsec gateway. "
        "On VM endpoints (the majority of enterprise deployments): "
        "  1. IKE private key is a PEM file on disk. "
        "  2. An attacker with read access to the file extracts the IKE private key. "
        "  3. Attacker can impersonate the endpoint in IKEv2 AUTH exchanges with the gateway. "
        "  4. Combined with CVE-2023-48788 (EMS SQLi): "
        "     compromise EMS -> extract EMS-distributed client certificate -> "
        "     impersonate enrolled FortiClient on IPsec VPN."
    ),

    "re_insight": (
        "The same developer team wrote certd and iked -- both follow the TPM/PEM dual-path pattern. "
        "The PEM key location for iked is likely /etc/forticlient/ or /var/lib/forticlient/. "
        "Both TSS2 PEM formats exist: "
        "  TSS2 KEY BLOB: the full TPM key object (TCG TSS2 v2 format) "
        "  TSS2 PRIVATE KEY: the private key in TSS2 format. "
        "If iked generates the key at install time and stores it as a TSS2 PRIVATE KEY PEM, "
        "extracting the file from disk directly yields the private key without TPM involvement."
    ),
}

FCLIENT_IKED_F02_NNG_IPC = {
    "id":       "FCLIENT-IKED-F02",
    "product":  "FortiClient iked -- NNG IPC messaging (no authentication on IPC protocol)",
    "severity": "MEDIUM -- NNG IPC socket; NNG has no built-in auth; local process can send IPC messages",
    "class":    "Unauthenticated local IPC (CWE-284); NNG REQ/REP protocol",

    "description": (
        "iked uses NNG 1.8.0 for inter-process communication with other FortiClient daemons. "
        "NNG transports used: "
        "  posix_ipclisten.c -> IPC transport (Unix socket with NNG framing) "
        "  posix_tcplisten.c -> TCP listener (possibly for VPN gateway communication) "
        "  inproc.c -> in-process transport (within iked) "
        "  pair.c, req.c -> PAIR and REQ/REP protocols. "
        "NNG does not provide built-in authentication. "
        "If the NNG IPC socket permissions are not restricted (world-readable or forticlient-group), "
        "any local process that speaks the NNG wire protocol can send IPC messages to iked. "
        "Possible IPC messages to iked: initiate tunnel, change VPN configuration, "
        "request key material, trigger rekey. "
        "NNG IPC socket name: not determined from strings; requires strace at iked startup."
    ),

    "contrast_with_certd": (
        "certd (FCLIENT-CERTD-F02) uses raw Unix sockets with SO_PEERCRED PID validation. "
        "iked uses NNG which does not have a built-in credential mechanism. "
        "iked would need to implement application-layer authentication on top of NNG "
        "to protect its IPC from arbitrary local callers. "
        "If iked does not implement this, any local process can trigger VPN state changes."
    ),
}

FCLIENT_IKED_F03_XAUTH = {
    "id":       "FCLIENT-IKED-F03",
    "product":  "FortiClient iked -- XAUTH (IKEv1 extended authentication) support",
    "severity": "INFORMATIONAL -- XAUTH credentials transmitted in IKEv1; legacy protocol",
    "class":    "XAUTH password in IKEv1 SA (cleartext after decryption); legacy auth method",

    "description": (
        "iked Protobuf config includes: "
        "  forticlient_configuration_t.vpn_t.ipsecvpn_t.connections_t.connection_t.ike_settings_t.xauth_t "
        "XAUTH = IKEv1 Extended Authentication (RFC 3748 + IKEv1 Informational exchange). "
        "XAUTH sends username+password inside an IKE encrypted SA (not separately TLS-protected). "
        "The SA encryption is only as strong as the Phase 1 SA cipher + PSK. "
        "If PSK is weak (dictionary word, default credential): "
        "  attacker captures IKEv1 exchange, cracks PSK offline (Aggressive Mode PSK = hash exposed), "
        "  decrypts XAUTH exchange to extract plaintext username + password. "
        "Fortinet IPsec VPN gateways default to supporting both IKEv1 and IKEv2. "
        "Bad string: 'bad psk', 'bad psk identity' -- PSK validation error strings in iked."
    ),

    "aggressive_mode_psk": (
        "IKEv1 Aggressive Mode (used for remote access IPsec VPN): "
        "  the PSK hash is sent unencrypted in the first two messages. "
        "  This hash can be captured and cracked offline (dictionary attack). "
        "  FortiGate IPsec VPN with Aggressive Mode + XAUTH = two-stage credential capture: "
        "  1. Capture Aggressive Mode exchange -> offline PSK crack "
        "  2. Decrypt XAUTH exchange -> plaintext domain credentials "
        "PSK strings in iked: 'auth-psk', 'AuthPSK', 'aPSK' -- confirms PSK auth is implemented."
    ),
}

FCLIENT_IKED_ARCH = {
    "id":       "FCLIENT-IKED-ARCH",
    "product":  "FortiClient iked -- IPsec/IKEv2 architecture",

    "auth_methods": {
        "AuthPSK":  "Pre-shared key authentication (IKEv1 + IKEv2)",
        "AuthANY":  "Any authentication method (wildcard -- may be insecure if not restricted)",
        "cert":     "Certificate-based authentication (IKEv2 AUTH payload; uses iked private key)",
        "XAUTH":    "Extended authentication (IKEv1; username+password inside encrypted SA)",
        "HYBRID":   "Hybrid auth -- gateway has cert, client uses PSK+XAUTH (RSA_HYBRID string present)",
    },

    "vpn_config_fields": {
        "ike_settings_t.proposals_t":       "IKE proposal set (encryption + integrity + DH group)",
        "ike_settings_t.auth_data_t":       "Authentication credentials (PSK, cert path, XAUTH creds)",
        "ike_settings_t.xauth_t":           "XAUTH username/password configuration",
        "ipsec_settings_t.proposals_t":     "IPsec proposal set (ESP encryption + authentication)",
        "ipsec_settings_t.remote_networks_t": "Split tunnel remote networks",
    },

    "routing": (
        "'Added split tunnel route. %s' -- iked adds routing table entries for split tunnel. "
        "'Adding a route to FGT gateway. %s' -- iked adds route to FortiGate gateway. "
        "Route manipulation: if iked NNG IPC is unprotected, an attacker could trigger "
        "routing changes without VPN authentication."
    ),
}

FCLIENT_IKED_F04_PREAUTH_SURFACE = {
    "id":       "FCLIENT-IKED-F04",
    "product":  "FortiClient 8.0 iked -- pre-auth dangerous function surface (ELF x86-64, 13MB, PLT analysis)",
    "binary":   "/opt/forticlient/iked (FortiClient 8.0, 13,078,576 bytes, BuildID sha1:87a4658c)",
    "severity": "LOW -- all strcpy/sprintf callers analyzed; no attacker-injectable unbounded copies found",
    "class":    "Static dangerous-function inventory (PLT sweep); pre-auth packet receive surface",

    "plt_inventory": {
        "memcpy":   {"plt": "0x412a90", "got": "0x12240d8", "callers": 1941, "status": "NOT ANALYZED -- too many; focused analysis needed on IKE parser path"},
        "memmove":  {"plt": "0x412c20", "got": "0x12241a0", "callers": 277,  "status": "NOT ANALYZED"},
        "strncpy":  {"plt": "0x412bf0", "got": "0x1224188", "callers": 16,   "status": "NOT ANALYZED"},
        "strcpy":   {"plt": "0x413280", "got": "0x12244d0", "callers": 10,   "status": "ANALYZED -- all safe (see below)"},
        "strcat":   {"plt": "0x413a10", "got": "0x1224898", "callers": 2,    "status": "NOT ANALYZED"},
        "sprintf":  {"plt": "0x414440", "got": "0x1224db0", "callers": 3,    "status": "ANALYZED -- all safe (see below)"},
        "snprintf": {"plt": "0x413550", "got": "0x1224638", "callers": 27,   "status": "NOT ANALYZED"},
        "sscanf":   {"plt": "0x413080", "got": "0x12243d0", "callers": 27,   "status": "NOT ANALYZED"},
        "recv":     {"plt": "0x414210", "got": "0x1224c98", "callers": 15,   "status": "NOT ANALYZED"},
        "recvfrom": {"plt": "0x412f00", "got": "0x1224310", "callers": 5,    "status": "PARTIALLY ANALYZED (see below)"},
        "read":     {"plt": "0x413bd0", "got": "0x1224978", "callers": 34,   "status": "NOT ANALYZED"},
        "sprintf":  {"plt": "0x414440", "got": "0x1224db0", "callers": 3,    "status": "ANALYZED -- all safe"},
    },

    "sprintf_analysis": {
        "callers": ["0x685a49", "0x689996", "0x6ee91c"],
        "verdict": "SAFE -- all 3 callers use static RODATA format strings with integer or static-string args; no user-controlled format string",
        "detail": {
            "0x685a49": "esi=0xcdfbc7 (static fmt), rdi=rbp-0x50 (stack buf), edx=[rbp-0x78] (int)",
            "0x689996": "esi=0xce0fdf (static fmt), rdi=rbp-0x20 (stack buf), edx=[rbp-0x44] (int)",
            "0x6ee91c": "rsi=[rip+static] (fmt), rdx/rsi=[rip+static] (static string args), rdi=[rbp-0x60] (ptr)",
        },
    },

    "strcpy_analysis": {
        "callers": ["0x68d6db", "0x6a54bd", "0x6ee83e", "0x7a461e", "0x7f0ecf",
                    "0x7f2095", "0x7f20cd", "0x82d115", "0x976f53", "0x976f66"],
        "verdict": "SAFE -- all 10 callers are either strdup patterns or have size-checked destinations",
        "patterns": {
            "strdup_pattern":     ["0x7a461e", "0x7f0ecf", "0x7f2095", "0x82d115", "0x976f53", "0x976f66"],
            "strdup_detail":      "call strlen(src) -> malloc(len+1) -> strcpy(dest, src); dest always sized to src",
            "bounded_copy":       ["0x6a54bd"],
            "bounded_detail":     "Pre-check: if source_len >= remaining_space: skip strcpy and advance write_pos to end. Only calls strcpy when source_len < remaining_space (correct bounds check).",
            "malloc_sized_copy":  ["0x6ee83e"],
            "malloc_detail":      "malloc(strlen(src1) + strlen(src2) + 13) then strcpy(dest, src1) -- src1 is strictly shorter than malloc size; safe by construction",
            "unreadable":         ["0x68d6db", "0x7f20cd"],
            "unreadable_note":    "Context bytes decode as mid-instruction or data; likely in non-linear code path (e.g., exception handler or unreachable code)",
        },
    },

    "recvfrom_analysis": {
        "callers": ["0x4e44e9", "0x56dac8", "0x7a7821", "0xa842c8", "0xca0aad"],
        "characterized": {
            "0xca0aad": "malloc(0xffff) -> recvfrom(fd, buf, 0xffff, flags, addr, addrlen) -> realloc(buf, recv_result) -> return buf. Safe allocation pattern; no parse-driven memcpy from received data in this function.",
            "0x56dac8": "Structured UDP receive; buf from rbp-0x58 (caller-allocated); len from rbp-0x50; typical select-loop recv handler.",
            "0x7a7821": "DTLS receive path; fd from [rbx+0x38]; buf = r12 (caller-allocated); flags include MSG_PEEK variant (r13d from r14+0x100). DTLS packet dispatcher entry.",
        },
        "note": "Pre-auth memcpy surface in IKE_SA_INIT and DTLS ClientHello parser not traced; 1941 memcpy callers require focused path-tracing from recvfrom call site through packet dispatcher to memcpy callsites.",
    },

    "pending": "Trace IKE_SA_INIT dispatch path from 0x7a7821 (DTLS recvfrom) through packet type dispatch to payload parsers; identify memcpy calls that use length fields from the received packet without upper-bound checks.",
}
