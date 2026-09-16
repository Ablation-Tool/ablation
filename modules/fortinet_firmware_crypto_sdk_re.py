"""
FortiOS firmware encryption RE + API SDK + MCP server attack surface
Sources:
  - firmware-tools/: forticrack-bishopfox, forticrack_v8, noways-fortigate-crypto,
                     fgx (FortiGate Extraction Toolkit), randorisec-decrypt-rootfs
  - mcp-servers/: fortimanager-mcp (Python), fortimanager-code-mode-mcp (TypeScript)
  - forti-sdk-go/: Fortinet Go SDK (FortiOS, FortiManager, FortiAnalyzer)
  - terraform-provider-fortios/: Fortinet Terraform provider
  - ansible-collections/: fortimanager + fortios Ansible collections
  - pypi-packages/: fortigate_api-2.0.8, PyFortiAPI-0.3.0
  - connector-fortinet-fortindr-cloud/ (FortiNDR SOAR connector)
"""

# ---------------------------------------------------------
# FortiOS firmware encryption architecture
# ---------------------------------------------------------
FORTIOS_FIRMWARE_CRYPTO = {
    "id":       "FOS-FWCRYPT",
    "product":  "FortiOS firmware image -- two-layer encryption architecture",
    "sources": [
        "firmware-tools/fgx/fgx.py (end-to-end; 4 stages; FortiOS 7.6.x)",
        "firmware-tools/forticrack-bishopfox/forticrack.py (outer layer, known-plaintext attack)",
        "firmware-tools/forticrack_v8/forticrack_v8.py (v8.0.0 kernel; RSA XOR decode)",
        "firmware-tools/noways-fortigate-crypto/ (seed extraction + ChaCha20; miasm symbolic exec)",
        "firmware-tools/randorisec-decrypt-rootfs/ (ChaCha20/AES; crypto_ctx struct RE)",
    ],

    "stage_1_outer_layer": {
        "cipher":       "Custom XOR block cipher (NOT standard ChaCha20 or AES)",
        "block_size":   512,
        "key_length":   32,
        "key_charset":  "ASCII alphanumeric only (0-9, A-Z, a-z)",
        "key_recovery": "Known-plaintext attack using magic bytes at offset 12-16: b'\\xff\\x00\\xaa\\x55'",
        "known_plaintext_offset": 12,
        "magic_bytes":  b"\xff\x00\xaa\x55",
        "key_derivation": (
            "For block at offset i: "
            "key_byte[k] = prev_byte XOR (known_plaintext + key_offset) XOR ciphertext_byte "
            "where key_offset = (i + 16) % 32. "
            "Key bytes from the 16th through 48th ciphertext positions in a single block. "
            "Key is then rotated: key[16:] + key[:16]."
        ),
        "validation": (
            "Decrypted block passes validation if: "
            "  1. cleartext[12:16] == b'\\xff\\x00\\xaa\\x55' (known magic) "
            "  2. cleartext[16:46] is valid UTF-8 containing 'build' (version string)"
        ),
        "inner_format": "After outer decryption: ext3 filesystem containing flatkc (compressed kernel) + rootfs.gz",
    },

    "stage_3_kernel_rsa_key": {
        "description":  "RSA public key XOR-encoded in the FortiOS kernel binary",
        "rsa_enc_va":   "0xffffffff8179a1a0 (270 bytes DER, XOR-encoded; kernel 4.19.13 v8.0.0 build 0167)",
        "rsa_enc_len":  270,
        "xor_key_va":   "0xffffffff8179a2c0 (32-byte XOR key)",
        "decode": (
            "decrypted_rsa_der[i] = encrypted_rsa[i] XOR xor_key[i % 32] "
            "Result is a DER-encoded RSA public key (RFC 3279 RSAPublicKey format)."
        ),
        "note": (
            "The XOR encoding is NOT cryptographic protection -- it is obfuscation. "
            "The XOR key is stored in the same kernel image immediately after the encrypted blob. "
            "Any attacker with the kernel image can extract the RSA public key trivially. "
            "The RSA key is used for rootfs signature verification, not encryption."
        ),
    },

    "stage_4_rootfs": {
        "cipher":           "ChaCha20 (custom implementation; possibly modified) + AES-256 in some versions",
        "seed_location":    "fgt_verifier_pub_key (x86_64) / fgt_verify_initrd (aarch64) in kernel .init.text section",
        "seed_extraction":  "miasm symbolic execution: track sha256_update RSI argument; min(all_seeds) = seed address",
        "seed_length":      32,
        "key_derivation": (
            "SHA256 of rotated seed: "
            "  chacha20_key  = SHA256(seed[4:32] + seed[0:4])   (rotate left by 4 bytes) "
            "  chacha20_nonce= SHA256(seed[5:32] + seed[0:5])   (rotate left by 5 bytes) "
            "Only the first 12 bytes of chacha20_nonce are used (ChaCha20 nonce = 96 bits)."
        ),
        "crypto_ctx_layout": {
            "description": "Randorisec crypto_ctx ctypes struct embedded in kernel memory",
            "fields": {
                "padding":      "174 bytes",
                "null":         "1 byte",
                "nonce":        "8 bytes (uint64 little-endian)",
                "counter":      "8 bytes (uint64 little-endian)",
                "aes_key":      "32 bytes (AES-256 key; used in some firmware versions)",
                "rootfs_hash":  "32 bytes (expected SHA256 hash of decrypted rootfs)",
            },
            "note": (
                "The crypto_ctx struct is embedded in the kernel and populated at boot time. "
                "In versions using AES-256 (older) the aes_key field is used instead of ChaCha20. "
                "Newer FortiOS (7.x+) uses ChaCha20 exclusively."
            ),
        },
        "trailing_signature": "256 bytes; skipped before decryption (RSA signature of rootfs)",
    },

    "seed_extraction_methods": {
        "symbolic_execution": (
            "noways getrootfskey.py: miasm symbolic execution from fgt_verifier_pub_key entry point. "
            "Tracks sha256_update(ctx, data, len) calls; extracts data pointer (RSI/X1 register). "
            "Minimum data address across all sha256_update calls = seed address. "
            "Reads 32 bytes from that address in the binary's virtual address space."
        ),
        "disassembly_scan": (
            "randorisec approach: objdump -d --section=.init.text | egrep push.*rbp before rsa_parse_pub_key. "
            "Then miasm disassembly scan for MOV RSI, <immediate> instructions. "
            "min(all_immediate_values) = seed address."
        ),
        "fgx_stage3": (
            "fgx.py Stage 3: extract flatkc (flat compressed kernel) from outer layer. "
            "Find seed by pattern matching in the decompressed kernel."
        ),
    },

    "fgx_pipeline": {
        "description":      "fgx.py end-to-end FortiGate firmware extraction toolkit",
        "supported":        "FortiOS 7.6.x (aarch64 / x86_64)",
        "stage_1":          "Outer XOR block cipher decryption (FortiCrack algorithm)",
        "stage_2":          "ext3 filesystem extraction from decrypted image",
        "stage_3":          "Seed + RSA key extraction from flatkc (kernel crypto material)",
        "stage_4":          "rootfs.gz decryption via modified RC4/ChaCha20 stream cipher",
        "note": (
            "fgx.py describes stage 4 as 'modified RC4 stream cipher' -- not pure ChaCha20 or AES. "
            "This suggests FortiOS 7.6.x uses a different rootfs cipher than 7.x (ChaCha20). "
            "The XOR block cipher in Stage 1 is consistent across FortiCrack and forticrack_v8, "
            "suggesting the outer layer has NOT changed since FortiOS v8.0.0 (2019-era) through 7.6.x."
        ),
    },

    "security_implications": {
        "offline_firmware_decryption": (
            "Full end-to-end firmware decryption is possible for an attacker with: "
            "  1. A .out firmware image (available from Fortinet support portal). "
            "  2. Python + miasm + cryptography library. "
            "The outer layer key is recoverable via known-plaintext attack (magic bytes at fixed offset). "
            "The seed is recoverable via symbolic execution of a few hundred instructions."
        ),
        "rootfs_modification": (
            "After decrypting rootfs: the attacker has full read access to the FortiOS root filesystem. "
            "Any binary can be extracted, analyzed, or modified. "
            "Re-encryption to create a valid firmware image requires the RSA private key "
            "(NOT present; only the public key is in the firmware). "
            "However: Fortinet TFTP/USB boot modes may accept images without RSA signature validation "
            "in certain engineering or RMA modes -- not confirmed from open sources."
        ),
        "key_rotation": (
            "The seed changes per firmware version and per model line (FGT vs FFW etc). "
            "forticrack_v8 hardcodes segments for 'kernel 4.19.13 v8.0.0 build 0167, same for FGT and FFW'. "
            "This means all devices of the same model/version share the same rootfs encryption key. "
            "Once the seed is extracted for a version, ALL devices running that version are decryptable."
        ),
    },
}


# ---------------------------------------------------------
# FortiManager MCP servers (Python + TypeScript)
# ---------------------------------------------------------
FORTIMANAGER_MCP_SERVERS = {
    "id":       "FMG-MCP",
    "product":  "FortiManager MCP server -- AI-controlled network security management",
    "sources": [
        "mcp-servers/fortimanager-mcp (Python, MCP SDK, 590 tools, author: Jamie van der Pijll)",
        "mcp-servers/fortimanager-code-mode-mcp (TypeScript, MCP SDK, 2 tools, QuickJS WASM sandbox)",
    ],

    "fortimanager_mcp_python": {
        "tools":    "590 tools (full mode) or dynamic proxy (small context mode)",
        "mode":     "FMG_TOOL_MODE=full (load all 590) or dynamic (on-demand lookup)",
        "auth":     "FORTIMANAGER_API_TOKEN or FORTIMANAGER_USERNAME + FORTIMANAGER_PASSWORD",
        "ssl":      "FORTIMANAGER_VERIFY_SSL=false by default in example config",
        "transport": "HTTP (Docker/web) or stdio (Claude Desktop/LM Studio)",

        "tool_categories": {
            "ADOM":         "list_adoms(), get_adom_details(adom)",
            "Devices":      "list_devices(), get_device_details(), install_policy()",
            "Firewall":     "list_firewall_addresses(), create_firewall_address(), list_firewall_policies()",
            "Policies":     "list_policy_packages(), list_firewall_policies()",
            "Monitoring":   "get_system_status(), list_tasks()",
            "Discovery":    "find_fortimanager_tool(operation) -- dynamic tool search",
            "Advanced":     "execute_fortimanager_operation(tool, params) -- arbitrary JSON-RPC execution",
        },

        "attack_surface": (
            "An AI agent connected to this MCP server has 590 tools covering ALL FortiManager operations. "
            "This includes: install_policy() (pushes configs to ALL managed FortiGates), "
            "create_firewall_address() (adds objects), delete_* (removes policy objects). "
            "A prompt injection attack against the AI agent (via injected text in FortiManager objects) "
            "could cause the agent to call install_policy() or modify firewall rules silently."
        ),
    },

    "fortimanager_code_mode_mcp": {
        "tools":    "2 tools: search_fortimanager_tool + execute_fortimanager_code",
        "sandbox":  "QuickJS WASM (quickjs-emscripten v0.31.0) for JavaScript code execution",
        "pattern":  "Code Mode: AI writes JavaScript; QuickJS executes it against the FortiManager JSON-RPC API",
        "spec":     "API spec loaded from fmg-api-spec-{version}.json (generated from Fortinet FNDN HTML docs)",

        "attack_surface": (
            "The execute_fortimanager_code tool accepts arbitrary JavaScript from the AI and executes it "
            "in a QuickJS WASM sandbox. "
            "QuickJS-emscripten sandbox bypasses: WASM-based sandboxes have historically been escapable "
            "via prototype pollution, shared memory access, and WASM linear memory manipulation. "
            "A prompt injection -> AI generates malicious JavaScript -> QuickJS sandbox escape -> "
            "arbitrary code execution in the Node.js process (which has FortiManager API credentials)."
        ),
    },

    "env_security_risks": {
        "FORTIMANAGER_VERIFY_SSL_false": (
            "Default env.example sets FORTIMANAGER_VERIFY_SSL=false. "
            "If deployed in production with this setting, FortiManager API traffic is MITM-able. "
            "An attacker on the network path between MCP server and FortiManager can: "
            "  1. Intercept API calls and extract credentials. "
            "  2. Return forged responses to manipulate AI agent decisions. "
            "  3. Inject malicious FortiManager API responses that contain prompt injection payloads."
        ),
        "credentials_in_env": (
            "FORTIMANAGER_API_TOKEN or FORTIMANAGER_PASSWORD are stored in environment variables "
            "or .env file. These grant full administrative access to all managed FortiGate devices "
            "via the FortiManager cascade (FortiJump pattern: CVE-2024-47575)."
        ),
    },
}


# ---------------------------------------------------------
# FortiOS/FortiManager API SDK landscape
# ---------------------------------------------------------
FORTINET_SDK_LANDSCAPE = {
    "id":       "FSDK-MAP",
    "product":  "Fortinet API SDK ecosystem -- authentication patterns and attack surface",

    "forti_sdk_go": {
        "path":     "forti-sdk-go/",
        "packages": ["fortios", "fortimanager", "fortimanager2", "fortianalyzer"],
        "note":     "Go SDK for FortiOS CMDB/monitor API + FortiManager JSON-RPC + FortiAnalyzer APIs",
    },

    "terraform_provider_fortios": {
        "path":     "terraform-provider-fortios/",
        "note": (
            "Terraform provider for FortiOS and FortiManager. "
            "Provider credentials (FORTIOS_ACCESS_TOKEN or username/password) stored in Terraform state. "
            "Terraform state files commonly stored in cloud backends (S3, GCS, Azure Blob) -- "
            "if the state bucket is world-readable or the storage account is misconfigured, "
            "all FortiGate admin credentials are exposed in plaintext in the state file."
        ),
    },

    "ansible_collections": {
        "path":     "ansible-collections/fortimanager/ + fortios/",
        "note": (
            "Ansible collections for FortiManager and FortiOS. "
            "Credentials stored in Ansible vault (if encrypted) or plaintext inventory files. "
            "A common misconfiguration: plaintext passwords in ansible_password variables "
            "in inventory files committed to git repositories."
        ),
    },

    "pypi_fortigate_api": {
        "package":  "fortigate_api-2.0.8",
        "note": (
            "Python library for FortiGate CMDB API. "
            "Comprehensive object model: covers alertemail, antivirus, application, authentication, "
            "IPS, firewall policies, VPN, system config, etc. "
            "Authentication via session token or API key. "
            "TLS verification: library honors requests library verify= parameter; "
            "default is verify=True but many examples set verify=False for self-signed certs."
        ),
    },

    "n8n_fortisiem": {
        "package":  "n8n-nodes-fortisiem-0.3.1",
        "api_resources": [
            "Agent", "Case", "CmdbQuery", "Context", "Device", "DeviceMaintenance",
            "Discovery", "Event", "Health", "Incident", "LookupTable", "Organization",
            "Osquery", "Reputation", "Watchlist", "Worker",
        ],
        "note": (
            "n8n workflow automation node for FortiSIEM. "
            "Exposes FortiSIEM REST API operations for automation workflows. "
            "Authentication via FortiSiemApi.credentials.js (stores username + password in n8n vault). "
            "Osquery resource: allows running arbitrary osquery SQL against managed endpoints "
            "via FortiSIEM agent API -- high-value lateral movement vector if FortiSIEM is compromised."
        ),
    },

    "connector_fortindr": {
        "path":     "connector-fortinet-fortindr-cloud/fortinet-fortindr-cloud/",
        "files":    "connector.py, constants.py, operations.py",
        "note": (
            "FortiNDR Cloud SOAR connector (for FortiSOAR/XSOAR). "
            "FortiNDR Cloud is a cloud-based NDR that processes on-premises network telemetry. "
            "The connector provides operations for: query events, hunt, pcap retrieval. "
            "API key stored in SOAR credential store. "
            "FortiNDR API access -> query all network telemetry from the organization -> "
            "full visibility into internal network traffic including potential credential theft."
        ),
    },
}
