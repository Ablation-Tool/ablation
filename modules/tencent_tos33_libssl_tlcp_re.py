"""
TencentOS Server 3.3 libssl.so.1.1 TLCP Binary RE Module
Binary: libssl.so.1.1 (from TOS 3.3 qcow2 /usr/lib64/libssl.so.1.1)
        openssl-1.1.1w (or openssl-1.1.1k equivalent) + TencentOS TLCP patches
Source: /dev/nbd11 mount of TOS 3.3 qcow2
Method: ELF dynsym + string scan + capstone disassembly
Analysis date: 2026-09-04

TLCP (GM/T 0024-2014) is present in TOS 3.3 libssl — 14+ internal functions confirmed.
API is narrower than TOS 4.6 (only 3 exported methods vs 10+ in TOS 4.6).
The dual-certificate model (sign_cert + enc_cert) is also present in TOS 3.3
(confirmed by ssl_set_sign_enc_pkey in error string table).

FINDINGS SUMMARY:
  TOS33-LIBSSL-F01 (INFO)     TLCP full state machine present in TOS 3.3 (14 internal fns)
  TOS33-LIBSSL-F02 (INFO)     TLCP exported API: only TLCP_method/server/client (3 symbols)
  TOS33-LIBSSL-F03 (INFO)     Dual-cert model present: ssl_set_sign_enc_pkey confirmed
  TOS33-LIBSSL-F04 (INFO)     SM2-DHE and SM2-ECC key exchange paths both present
  TOS33-LIBSSL-F05 (MEDIUM/5.3) TLCP predates SSL_is_tlcp/enable API — hardcoded activation
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS33-LIBSSL-F01: Full TLCP state machine in TOS 3.3 libssl
# ──────────────────────────────────────────────────────────────────────────────

TLCP_INTERNAL_FUNCTIONS_TOS33 = {
    "source": "TOS 3.3 libssl.so.1.1 error string table (ERR_raise function names)",
    "string_table_offset_range": "0x79b72 - 0x79c5b",
    "error_offset_range": "0x76f98 - 0x76fe8",
    "functions_confirmed": [
        # From error string table (0x79b* range)
        "tlcp_choose_sigalg",
        "tlcp_construct_cke_sm2dhe",
        "tlcp_construct_cke_sm2ecc",
        "tlcp_construct_ske_sm2dhe",
        "tlcp_construct_ske_sm2ecc",
        "tlcp_derive",
        "tlcp_process_cke_sm2dhe",
        "tlcp_process_cke_sm2ecc",
        "tlcp_process_key_exchange",
        "tlcp_process_ske_sm2dhe",
        "tlcp_process_ske_sm2ecc",
        # From different error string cluster (0x76f98 range)
        "tlcp_construct_client_key_exchange",
        "tlcp_construct_server_key_exchange",
        "tlcp_process_client_key_exchange",
    ],
    "function_count": 14,
    "coverage": (
        "Full GM/T 0024-2014 handshake message construction and processing. "
        "Both SM2-DHE (ephemeral Diffie-Hellman with SM2) and SM2-ECC (static SM2 "
        "key encapsulation) key exchange paths are present. "
        "tlcp_choose_sigalg selects the signature algorithm for TLCP handshake. "
        "tlcp_derive computes the session keys after key exchange."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS33-LIBSSL-F02: Exported TLCP API — 3 method getters only
# ──────────────────────────────────────────────────────────────────────────────

TLCP_EXPORTED_SYMBOLS_TOS33 = {
    "total_exported_tlcp_symbols": 3,
    "symbols": {
        "TLCP_method": {
            "va": 0x23ff0,
            "stub_va": 0x23ec0,
            "disassembly": [
                "endbr64",
                "jmp 0x23ec0",      # thunk to impl
                # impl at 0x23ec0:
                "endbr64",
                "lea rax, [rip + 0x270155]",  # -> static ssl_method_st struct
                "ret",
            ],
            "returns": "ptr to static TLCP generic ssl_method_st",
        },
        "TLCP_server_method": {
            "va": 0x24000,
            "stub_va": 0x23ed0,
            "disassembly": ["endbr64", "jmp 0x23ed0"],
            "returns": "ptr to static TLCP server ssl_method_st",
        },
        "TLCP_client_method": {
            "va": 0x24010,
            "stub_va": 0x23ee0,
            "disassembly": ["endbr64", "jmp 0x23ee0"],
            "returns": "ptr to static TLCP client ssl_method_st",
        },
    },
    "absent_vs_tos46": [
        "SSL_is_tlcp",
        "SSL_CTX_enable_tlcp",
        "SSL_enable_tlcp",
        "SSL_get_sign_cert_tlcp",
        "SSL_get_enc_cert_tlcp",
        "SSL_set_sign_cert_tlcp",
        "SSL_set_enc_cert_tlcp",
    ],
    "implication": (
        "In TOS 3.3, TLCP activation requires explicitly using TLCP_method() at context creation. "
        "There is no SSL_CTX_enable_tlcp() to opt into TLCP within an existing TLS context. "
        "Runtime detection (SSL_is_tlcp) is also absent — code must track the method choice externally. "
        "TOS 4.6 adds the full enable/query API, making TLCP more composable with existing TLS code."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS33-LIBSSL-F03/F04: Dual-cert model and SM2 key exchange
# ──────────────────────────────────────────────────────────────────────────────

DUAL_CERT_MODEL_TOS33 = {
    "ssl_set_sign_enc_pkey": {
        "confirmed_by": "error string table at 0x7992a",
        "context_string": "ssl_set_sign_enc_pkey",
        "description": (
            "Sets both the signing key+cert and encryption key+cert for TLCP. "
            "In TOS 3.3, this is the primary API for loading dual certificates. "
            "Appears in the same error string cluster as SSL_set_wfd, SSL_shutdown — "
            "standard SSL API functions."
        ),
    },
    "sm2_key_exchange_modes": [
        {
            "mode": "SM2-DHE",
            "functions": ["tlcp_construct_cke_sm2dhe", "tlcp_construct_ske_sm2dhe",
                          "tlcp_process_cke_sm2dhe", "tlcp_process_ske_sm2dhe"],
            "description": (
                "Ephemeral SM2 Diffie-Hellman. Server generates ephemeral SM2 keypair "
                "per session (ServerKeyExchange), client verifies with enc_cert. "
                "Forward secrecy: session keys not derived from static private key."
            ),
        },
        {
            "mode": "SM2-ECC",
            "functions": ["tlcp_construct_cke_sm2ecc", "tlcp_construct_ske_sm2ecc",
                          "tlcp_process_cke_sm2ecc", "tlcp_process_ske_sm2ecc"],
            "description": (
                "Static SM2 key encapsulation. Client generates session key, encrypts "
                "with server's enc_cert public key (SM2 encrypt). No ephemeral keys. "
                "No forward secrecy — compromise of enc private key decrypts recorded sessions."
            ),
        },
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS33-LIBSSL-F05: Hardcoded TLCP activation — no runtime enable/disable
# ──────────────────────────────────────────────────────────────────────────────

TLCP_ACTIVATION_FINDING = {
    "finding_id": "TOS33-LIBSSL-F05",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "title": "TOS 3.3 TLCP activation is binary (method selection), no dynamic enable/disable",
    "detail": (
        "SSL_CTX_enable_tlcp() and SSL_enable_tlcp() do not exist in TOS 3.3 libssl. "
        "TLCP can only be activated by passing TLCP_method()/TLCP_server_method() to "
        "SSL_CTX_new(). There is no way to conditionally enable TLCP on an existing "
        "TLS context, and no SSL_is_tlcp() to test at runtime. "
        "This makes it harder to implement feature detection or fallback logic. "
        "Code calling SSL_CTX_enable_tlcp() (a TOS 4.6 API) would fail to link against "
        "TOS 3.3 libssl at compile time or fail at runtime with dlsym returning NULL."
    ),
    "attack_surface": (
        "No SSL_is_tlcp() means runtime checks against TLCP connections are impossible "
        "without the caller tracking method choice separately. "
        "Applications that accept both TLS and TLCP connections without careful method "
        "management could fail to apply TLCP-specific validation paths."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# CROSS-VERSION TLCP API EVOLUTION
# ──────────────────────────────────────────────────────────────────────────────

TLCP_API_EVOLUTION = {
    "TOS_3.3 libssl.so.1.1": {
        "exported_tlcp_symbols": 3,
        "internal_tlcp_functions": 14,
        "api_surface": ["TLCP_method", "TLCP_server_method", "TLCP_client_method"],
        "missing_api": ["SSL_is_tlcp", "SSL_CTX_enable_tlcp", "SSL_enable_tlcp",
                        "SSL_get_sign_cert_tlcp", "SSL_get_enc_cert_tlcp"],
    },
    "TOS_4.6 libssl.so.3": {
        "exported_tlcp_symbols": "10+",
        "api_surface": [
            "TLCP_method", "TLCP_server_method", "TLCP_client_method",
            "SSL_is_tlcp",           # checks ssl->method->type == 0x101
            "SSL_CTX_enable_tlcp",   # sets SSL_CTX*+0x680 = 1
            "SSL_enable_tlcp",       # sets SSL*+0x1dd8 = 1
            "SSL_get_sign_cert_tlcp",  # returns SSL*+0x390
            "SSL_get_enc_cert_tlcp",   # returns SSL*+0x398
        ],
        "tlcp_method_constant": 0x101,
        "dual_cert_offsets": {"sign": 0x390, "enc": 0x398},
        "enable_flags": {"ctx": 0x680, "ssl": 0x1dd8},
        "ref_module": "tencent_tos46_libssl_tlcp_binary_re.py",
    },
    "openssl_source_patch": "openssl-3.0.12-support-tlcp.patch (wynnfeng@tencent.com, 2024-04-15, ~600+ LOC)",
}

# ──────────────────────────────────────────────────────────────────────────────
# STRING TABLE SUMMARY
# ──────────────────────────────────────────────────────────────────────────────

TOS33_LIBSSL_TLCP_STRINGS = {
    # All TLCP-related strings confirmed present in libssl.so.1.1
    "sm2_and_tlcp_cipher_strings": {
        0x7347f: "SM4 cipher name string",
        0x756dc: "SM2 cipher or key name string",
    },
    "tlcp_function_error_strings": {
        0x76f98: "tlcp_construct_client_key_exchange",
        0x76fc0: "tlcp_construct_server_key_exchange",
        0x76fe8: "tlcp_process_client_key_exchange",
        0x79b72: "tlcp_choose_sigalg",
        0x79b85: "tlcp_construct_cke_sm2dhe",
        0x79b9f: "tlcp_construct_cke_sm2ecc",
        0x79bb9: "tlcp_construct_ske_sm2dhe",
        0x79bd3: "tlcp_construct_ske_sm2ecc",
        0x79bed: "tlcp_derive",
        0x79bf9: "tlcp_process_cke_sm2dhe",
        0x79c11: "tlcp_process_cke_sm2ecc",
        0x79c29: "tlcp_process_key_exchange",
        0x79c43: "tlcp_process_ske_sm2dhe",
        0x79c5b: "tlcp_process_ske_sm2ecc",
    },
    "exported_method_strings": {
        0x7381: "TLCP_method",
        0x738d: "TLCP_server_method",
        0x73a0: "TLCP_client_method",
    },
    "dual_cert_api_string": {
        0x7992a: "ssl_set_sign_enc_pkey (enc_cert context)",
    },
    "enc_cert_string": 0x7992a,
}
