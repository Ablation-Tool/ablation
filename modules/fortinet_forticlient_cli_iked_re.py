"""
FortiClient CLI + IKEv2 daemon (iked) RE
Sources (all from forticlient-vpn-deb/opt/forticlient/):
  - forticlient-cli (Go, 9.4MB) -- Cobra CLI command handler
  - iked (C/C++, 11.6MB) -- IKEv2/IPsec daemon; source at /home/devops/code/src/ikev2/iked/
Method: gopclntab symbol extraction, strings analysis, function prologue scan
"""

# ---------------------------------------------------------
# forticlient-cli architecture
# ---------------------------------------------------------
CLI_ARCH = {
    "id":       "CLI-ARCH",
    "product":  "forticlient-cli -- FortiClient Cobra CLI (Go 1.23.2, 9.4MB stripped ELF64)",
    "binary":   "/opt/forticlient/forticlient-cli",
    "framework": "github.com/spf13/cobra (Cobra CLI framework)",

    "top_level_commands": ["connect", "disconnect", "list", "show", "status",
                           "certificate", "update", "version", "register",
                           "completion (bash/zsh/fish/powershell)"],

    "vpn_subcommands": {
        "vpn connect <vpn_name>":                           "Connect to named VPN profile",
        "vpn connect <vpn_name> --user <u> --password":    "Connect with credentials",
        "vpn connect <vpn_name> --user <u> --password --save-password --always-up --auto-connect":
            "Connect with credential persistence + always-up + auto-connect",
        "vpn connect <vpn_name> -u <u> -p -s -w -a":      "Short-flag equivalent",
        "edit <vpn name>":                                  "Edit VPN profile",
        "view <vpn name>":                                  "View VPN profile",
    },

    "notable_flags": {
        "--save-password (-s)":  "Persist credentials across sessions",
        "--always-up (-w)":      "Keep VPN connected, auto-reconnect on drop",
        "--auto-connect (-a)":   "Auto-connect on network availability",
        "--password (-p)":       "Password flag (likely prompts interactively when no value given)",
        "--user (-u)":           "Username argument",
    },

    "ipc":  "Communicates with vpn daemon via protobuf IPC",
    "shell_completions": "Embedded bash/zsh/fish/PowerShell completion scripts",
}


# ---------------------------------------------------------
# CLI-F01: --save-password credential persistence
# ---------------------------------------------------------
CLI_F01_SAVE_PASSWORD = {
    "id":       "CLI-F01",
    "product":  "forticlient-cli -- --save-password flag persists credentials outside secure storage",
    "severity": "HIGH -- credentials may be accessible via shell history, process list, or IPC intercept",
    "class":    "Credential exposure via CLI arguments (CWE-214, CWE-312)",
    "evidence": [
        "string: 'vpn connect <vpn_name> --user=username --password --save-password --always-up --auto-connect'",
        "string: 'vpn connect <vpn_name> -u username -p -s -w -a'",
        "flags: --save-password (-s), --password (-p), --user (-u)",
    ],

    "description": (
        "forticlient-cli accepts VPN credentials via CLI flags: --user and --password. "
        "The --save-password flag persists credentials for future auto-connect use. "
        "Credential exposure paths: "
        "  1. Process list: if --password accepts the password as a flag value (not interactive prompt), "
        "     the password is visible in /proc/<pid>/cmdline and `ps aux` output. "
        "  2. Shell history: bash/zsh history stores the full command including credentials. "
        "     ~/.bash_history, ~/.zsh_history, /var/log/auth.log (sudo invocations). "
        "  3. IPC intercept: forticlient-cli sends credentials to the vpn daemon via the fctsched "
        "     IPC socket (8f6ddf1358bd9d067261f529f69fda59.ipc); see FCTSCHED-F01 for socket access. "
        "  4. --save-password stores credentials via GNOME keyring (VPN-F02); if keyring is unlocked "
        "     for another application, the stored credentials are readable."
    ),

    "note": (
        "The -p flag without a value likely triggers an interactive prompt (standard practice). "
        "If -p=<value> is accepted inline, the credential exposure via cmdline is confirmed. "
        "Verification: run `forticlient-cli vpn connect <name> -p=test 2>/dev/null` and check "
        "/proc/$(pgrep forticlient-cli)/cmdline."
    ),
}


# ---------------------------------------------------------
# CLI-F02: vpn_name passed to IPC without validation
# ---------------------------------------------------------
CLI_F02_VPN_NAME_IPC = {
    "id":       "CLI-F02",
    "product":  "forticlient-cli -- vpn_name argument passed to vpn daemon IPC without observed validation",
    "severity": "MEDIUM (potential IPC injection; requires IPC message format confirmation)",
    "class":    "Potential argument injection via IPC (CWE-88)",
    "evidence": [
        "string: 'vpn connect <vpn_name>'",
        "string: 'edit <vpn name>'",
        "IPC transport to vpn daemon via fctsched socket",
    ],

    "description": (
        "The <vpn_name> argument to `forticlient-cli vpn connect` is taken from user input "
        "and passed to the vpn daemon via IPC. "
        "If the vpn daemon uses the profile name in a database query without parameterization "
        "(SQLite is embedded in the binary -- SQLite strings present in iked and fctsched), "
        "the vpn_name could trigger SQLite injection. "
        "If the vpn daemon passes the profile name to a shell command (e.g., for nmcli integration "
        "as seen in VPN-F06), the vpn_name could inject shell metacharacters. "
        "Attack surface: local user with access to forticlient-cli can trigger injection "
        "into the privileged vpn daemon process."
    ),
}


# ---------------------------------------------------------
# iked architecture
# ---------------------------------------------------------
IKED_ARCH = {
    "id":       "IKED-ARCH",
    "product":  "iked -- FortiClient IKEv2/IPsec daemon (C/C++, 11.6MB stripped ELF64)",
    "binary":   "/opt/forticlient/iked",
    "source":   "/home/devops/code/src/ikev2/iked/ (C/C++ source tree)",
    "version":  "IKEv2 (RFC 7296) + IKEv2 fragmentation (RFC 7383) + Fortinet extensions",
    "network":  "Listens UDP 500 (IKEv2) + UDP 4500 (NAT-T)",
    "functions": 3734,

    "source_files_confirmed": [
        "/home/devops/code/src/ikev2/iked/ca.c",
        "/home/devops/code/src/ikev2/iked/crypto.c",
        "/home/devops/code/src/ikev2/iked/eap/crypto/crypto_openssl.c",
        "/home/devops/code/src/ikev2/iked/eap/crypto/tls_openssl.c",
        "/home/devops/code/src/ikev2/iked/eap/eap_peer/eap_ttls.c",
        "/home/devops/code/src/ikev2/iked/eap/fct_eap_peer.c",
        "/home/devops/code/src/ikev2/iked/fct/credential_manager.cpp",
        "/home/devops/code/src/ikev2/iked/fct/dns.cpp",
        "/home/devops/code/src/ikev2/iked/fct/fct_module.cpp",
        "/home/devops/code/src/ikev2/iked/fct/generate_conf.cpp",
        "/home/devops/code/src/ikev2/iked/fct/saml.cpp",
        "/home/devops/code/src/ikev2/iked/fct/user_input.cpp",
        "/home/devops/code/src/ikev2/iked/fct/vpn_options_cmd_args.cpp",
        "/home/devops/code/src/ikev2/iked/fct/vpn_options.cpp",
        "/home/devops/code/src/ikev2/iked/ikev2.c",
        "/home/devops/code/src/ikev2/iked/log.c",
    ],

    "key_functions": {
        "ikev2_recv":               "Top-level IKEv2 packet receive handler (pre-auth entry point)",
        "ikev2_resp_ike_sa_init":   "IKE_SA_INIT responder (processes unauthenticated initiator)",
        "ikev2_frags_reassemble":   "IKEv2 fragment reassembly (RFC 7383; pre-auth)",
        "ikev2_check_frag_oversize": "Fragment size validation (defensive check added by Fortinet)",
        "ikev2_pld_parse":          "IKEv2 payload parser (dispatches per payload type)",
        "ikev2_pld_payloads":       "Payload type dispatcher",
        "ikev2_pld_ke":             "Key Exchange payload parser",
        "ikev2_pld_sa":             "Security Association payload parser",
        "ikev2_pld_nonce":          "Nonce payload parser",
        "ikev2_pld_notify":         "Notify payload parser",
        "ikev2_pld_cert":           "Certificate payload parser",
        "ikev2_pld_certreq":        "Certificate Request payload parser",
        "ikev2_pld_ts":             "Traffic Selector payload parser",
        "ikev2_pld_ef":             "Encrypted-and-Fragmented payload handler",
        "ikev2_pld_attr":           "Attribute payload parser (XAUTH/CP config attributes)",
        "ikev2_pld_eap":            "EAP payload parser",
        "ikev2_ike_auth":           "IKE_AUTH processing (authenticated exchange)",
        "ikev2_auth_verify":        "Authentication verification",
        "ikev2_validate_pld":       "Payload validation",
        "ikev2_validate_ke":        "Key Exchange validation",
        "ikev2_validate_sa":        "SA proposal validation",
    },

    "fortinet_extensions": {
        "ikev2_add_forticlient_connect": "Proprietary FortiClient connection metadata payload",
        "ikev2_add_adc_emssn":           "ADC + EMS serial number extension payload",
        "ikev2_add_network_id":          "FortiClient network identity payload",
        "ikev2_ctl_fortitoken":          "FortiToken 2FA over IKEv2 control channel",
        "ikev2_ctl_saml_response":       "SAML assertion processing over IKEv2 control channel",
        "ikev2_ctl_reset_id":            "Identity reset via control channel",
    },

    "ipc": {
        "socket_name":  "8f6ddf1358bd9d067261f529f69fda59.ipc (same as fctsched)",
        "protocol":     "Accepted pipe<%u> on socket<%u> from %s",
        "functions":    "ikev2_getimsgdata -- inter-process message data extraction",
    },

    "eap_methods":  ["EAP-TLS", "EAP-TTLS", "EAP-MD5 (CHAP)", "EAP-MSCHAPv2"],
    "xauth":        True,
    "saml":         True,
    "nat_traversal": True,
}


# ---------------------------------------------------------
# IKED-F01: pre-auth IKEv2 fragment reassembly
# ---------------------------------------------------------
IKED_F01_FRAG_REASSEMBLE = {
    "id":       "IKED-F01",
    "product":  "iked -- IKEv2 fragment reassembly (RFC 7383) processes attacker data before authentication",
    "severity": "CRITICAL (potential pre-auth network-reachable memory corruption on UDP 500/4500)",
    "class":    "Pre-auth network-reachable memory corruption (CWE-122/125); requires disassembly to confirm",
    "evidence": [
        "string: 'ikev2_frags_reassemble' (function confirmed in binary)",
        "string: 'ikev2_check_frag_oversize' (explicit oversize check -- defensive addition)",
        "string: 'ikev2_pld_ef' (Encrypted-and-Fragmented payload handler; pre-auth path)",
        "network: UDP 500 + 4500 (IKEv2 standard ports; no authentication required for IKE_SA_INIT)",
    ],

    "mechanism": (
        "IKEv2 fragmentation (RFC 7383) allows IKE_SA_INIT messages to arrive as multiple fragments. "
        "Fragmentation is processed BEFORE authentication (the IKE_AUTH exchange has not happened yet). "
        "An attacker at UDP 500 or 4500 can send crafted fragment packets to any host running iked "
        "WITHOUT any credentials or prior IKE session. "
        "ikev2_frags_reassemble() allocates a reassembly buffer and copies fragments into it. "
        "ikev2_check_frag_oversize() was added to validate fragment sizes -- its existence implies "
        "Fortinet identified this as a risk. "
        "If ikev2_check_frag_oversize() has incomplete coverage (e.g., checks total size but not "
        "individual fragment offset + length arithmetic), a crafted sequence of fragments could trigger "
        "a heap buffer overflow in the reassembly buffer."
    ),

    "attack_vector": (
        "UDP (connectionless, no TCP handshake required). "
        "Source IP: spoofable (no connection state before IKE_SA_INIT). "
        "Port: 500 or 4500 (standard IKEv2 ports, must be open for IPsec VPN to function). "
        "Auth requirement: NONE for the fragment reassembly path. "
        "Impact if exploitable: remote code execution on the endpoint as the iked process user "
        "(likely root or a privileged user for kernel IPsec integration)."
    ),

    "disasm_confirmed": (
        "BERT semantic sweep completed: 3,734 functions encoded; all 5 query profiles run. "
        "EAP-TTLS cluster (0x5b6425, 0x5afdd5, 0x5af7c5, 0x5af455, 0x5b0c75) showed "
        "highest confidence (score 0.33), consistent with credential-handling functions. "
        ""
        "ikev2_frags_reassemble: confirmed at 0x5f1000 (>18KB function). "
        "  References to 'ikev2_frags_reassemble' string at offsets +0x442a, +0x4460, +0x45c1 "
        "  within the function confirm this is the reassembly function (self-logging). "
        "  Zero direct (e8) callers found -- function is invoked via function pointer (indirect call). "
        ""
        "ikev2_check_frag_oversize: confirmed at 0x462620. "
        "  Logic: computes total fragment size (calls 0x4406f0, 0x440720, 0x43fec0), "
        "  compares against threshold (0x208=520 or 0x4b4=1204 bytes depending on IKE version flag). "
        "  Returns: 0 if within limits, 1 if oversize+allowed, -1 if error path. "
        "  Called from exactly 3 sites: 0x45fe2a, 0x464643, 0x464b71. "
        ""
        "Critical gap: frags_reassemble invoked via function pointer means the 3 check sites "
        "do NOT necessarily cover all reassembly paths. Any code path that invokes the function "
        "pointer directly without calling check_frag_oversize first bypasses the size validation. "
        "Full CFG (control flow graph) analysis required to enumerate all indirect call sites. "
        "Verdict: PLAUSIBLE; full confirmation requires dynamic analysis or CFG reconstruction."
    ),

    "related": "CVE-2024-23113 (FortiOS SSL-VPN pre-auth format string); IKED-F01 is a different daemon but same pre-auth network attack surface pattern.",
}


# ---------------------------------------------------------
# IKED-F02: Fortinet proprietary IKEv2 extensions
# ---------------------------------------------------------
IKED_F02_PROPRIETARY_EXT = {
    "id":       "IKED-F02",
    "product":  "iked -- proprietary Fortinet IKEv2 payload types lack RFC validation",
    "severity": "HIGH -- non-standard payload parsing without protocol specification = weaker input validation",
    "class":    "Missing input validation on vendor-specific protocol extension (CWE-20)",
    "evidence": [
        "string: 'ikev2_add_forticlient_connect' (Fortinet proprietary IKEv2 payload)",
        "string: 'ikev2_add_adc_emssn' (ADC + EMS serial number payload)",
        "string: 'ikev2_add_network_id' (network identity payload)",
        "No RFC defines FortiClient proprietary payload types -- no interoperability test suite",
    ],

    "description": (
        "iked implements at least three Fortinet-proprietary IKEv2 payload types: "
        "  1. forticlient_connect: carries FortiClient metadata (version, license, EMS registration). "
        "  2. adc_emssn: carries ADC + EMS serial number for device posture. "
        "  3. network_id: carries network identity information. "
        "These payloads are processed by a FortiGate peer (server-side) or by the FortiClient "
        "iked daemon (client-side) when received from the peer. "
        "Proprietary payload parsers: "
        "  - Are not subject to RFC compliance requirements. "
        "  - Lack formal specification documents that define valid/invalid inputs. "
        "  - Are tested only against Fortinet's own implementation (no third-party interoperability). "
        "A malicious FortiGate (compromised or rogue; see CVE-2024-47575 / VPN-F01 chain) can send "
        "crafted proprietary payloads to trigger parsing bugs in iked on the client side. "
        "This is a post-authentication attack (FortiGate sends these during IKE_AUTH), but the "
        "authentication can be forged via a rogue FortiGate with a valid or stolen certificate."
    ),
}


# ---------------------------------------------------------
# IKED-F03: inter-process message length check failures
# ---------------------------------------------------------
IKED_F03_IMSG_LENGTH = {
    "id":       "IKED-F03",
    "product":  "iked -- ikev2_getimsgdata length check failure messages indicate known bounds concern",
    "severity": "MEDIUM -- local privilege escalation via malformed IPC message if socket is accessible",
    "class":    "IPC input validation (CWE-20); local attack surface via shared fctsched socket",
    "evidence": [
        "string: 'ikev2_getimsgdata: length too small for sh'",
        "string: 'ikev2_getimsgdata: length too small for type'",
        "string: 'ikev2_prfplus: key material too large'",
        "string: 'ikev2_prfplus: hash length mismatch'",
    ],

    "description": (
        "ikev2_getimsgdata() extracts typed data from inter-process messages (imsg). "
        "Two explicit length check failure messages are present in the binary: "
        "  - 'length too small for sh': the message does not contain enough data for a struct sockaddr_storage "
        "    (sh = sockaddr host). "
        "  - 'length too small for type': the message payload is shorter than the declared type size. "
        "These checks are in the ERROR path -- they represent what ikev2_getimsgdata() REJECTS. "
        "The concern: if the CHECK path has an off-by-one (checks >= instead of >), "
        "a message exactly at the boundary triggers the failure but still allows a read past the end. "
        "The fctsched IPC socket (8f6ddf1358bd9d067261f529f69fda59.ipc) is the transport; "
        "FCTSCHED-F01 socket access grants an attacker the ability to send malformed imsg packets. "
        "ikev2_prfplus bounds checks ('key material too large', 'hash length mismatch') indicate "
        "similar defensive checks in the cryptographic PRF+ key derivation path."
    ),
}


# ---------------------------------------------------------
# IKED-F04: SAML assertion processing over IKEv2 control channel
# ---------------------------------------------------------
IKED_F04_SAML_OVER_IKE = {
    "id":       "IKED-F04",
    "product":  "iked -- SAML assertion processing via IKEv2 control channel (fct/saml.cpp)",
    "severity": "HIGH -- SAML XML injection via IKEv2 if SAML parser is not hardened",
    "class":    "SAML injection / XML injection (CWE-91) in a network daemon context",
    "evidence": [
        "source: /home/devops/code/src/ikev2/iked/fct/saml.cpp",
        "string: 'ikev2_ctl_saml_response' (SAML response handler in IKE control channel)",
        "string: 'ikev2_ctl_fortitoken' (FortiToken 2FA via same control channel)",
    ],

    "description": (
        "iked processes SAML authentication assertions as part of the IKEv2 VPN login flow. "
        "Source file fct/saml.cpp contains the SAML response parser. "
        "ikev2_ctl_saml_response() receives a SAML assertion (XML blob) from the authentication "
        "flow and parses it to extract user identity, group membership, and role claims. "
        "SAML XML parsing in a C/C++ context (vs. high-level language with hardened XML parsers) "
        "introduces several risk surfaces: "
        "  1. XML injection: if the SAML assertion is not schema-validated before parsing, "
        "     crafted XML can inject additional assertion elements. "
        "  2. XXE (XML External Entity): if the XML parser allows DOCTYPE declarations, "
        "     SAML assertions from a compromised FortiGate can trigger XXE to read local files. "
        "  3. Signature bypass: if SAML signature verification is performed on the parsed DOM "
        "     rather than the raw bytes (the classic XML signature wrapping attack), "
        "     a rogue IdP can forge a valid assertion for any user. "
        "Combined with VPN-F01 (rogue FortiGate via CVE-2024-47575): "
        "rogue FortiGate -> sends forged SAML assertion via IKEv2 -> iked parses it -> "
        "attacker authenticates as any user without valid credentials."
    ),
}


# ---------------------------------------------------------
# IKED-F05: XAUTH + EAP-TTLS credential handling
# ---------------------------------------------------------
IKED_F05_EAPTTLS_XAUTH = {
    "id":       "IKED-F05",
    "product":  "iked -- EAP-TTLS + XAUTH credential handling in network-facing C/C++ code",
    "severity": "HIGH -- credential parsing bugs in network-facing code = pre-auth credential theft",
    "class":    "Credential handling in network-facing code (CWE-312, CWE-522)",
    "evidence": [
        "source: /home/devops/code/src/ikev2/iked/eap/eap_peer/eap_ttls.c",
        "source: /home/devops/code/src/ikev2/iked/fct/credential_manager.cpp",
        "string: 'autheap='",
        "string: 'EXPORTER_EAP_TLS_Key_Material'",
        "string: 'EXPORTER_EAP_TLS_Method-Id'",
    ],

    "description": (
        "iked implements EAP-TTLS client-side authentication for IKEv2 VPN. "
        "Source fct/credential_manager.cpp manages credential storage and retrieval. "
        "Source eap/eap_peer/eap_ttls.c implements the EAP-TTLS peer (client) protocol. "
        "EAP-TTLS establishes a TLS tunnel (outer) and then carries the inner authentication "
        "(username/password via PAP/MSCHAPV2). "
        "Attack surface: "
        "  1. The TLS outer tunnel is terminated by the FortiGate server. "
        "     A rogue FortiGate (CVE-2024-47575) can serve a TLS certificate the client accepts "
        "     (if certificate pinning is absent), then intercept the inner credentials. "
        "  2. The credential_manager.cpp reads credentials for EAP-TTLS use. "
        "     If credentials are stored in memory as cleartext (before EAP encryption), "
        "     a memory dump of the iked process exposes user passwords. "
        "  3. The EAP_TLS_EXPORTER key material is derived for session keying. "
        "     An error in the exporter label parsing (EXPORTER_EAP_TLS_Key_Material, "
        "     EXPORTER_EAP_TLS_Method-Id) could cause incorrect key derivation."
    ),
}
