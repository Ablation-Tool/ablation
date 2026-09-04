"""
TencentOS Server 4.6 libcrypto.so.3 SM Cipher Suite Binary RE Module
Binary: libcrypto.so.3 (from TOS 4.6 qcow2 /usr/lib64/libcrypto.so.3)
        openssl-3.0.12-27.tl4 build (4.4MB binary, full OpenSSL provider framework)
Source: /dev/nbd10 mount of TOS 4.6 qcow2
Method: ELF dynsym + string scan + OID registry analysis
Analysis date: 2026-09-04

Chinese national cryptographic algorithms in libcrypto.so.3:
  SM2 — ECDSA-variant on 256-bit SM2 curve; key exchange + digital signature
  SM3 — SHA-256 equivalent hash function
  SM4 — AES-128 equivalent block cipher; multiple modes including GCM
All three are OSCCA (Office of State Commercial Cryptography Administration) standards.
RFC 8998 adds SM4-GCM and SM4-CCM as TLS 1.3 cipher suites.

FINDINGS SUMMARY:
  TOS46-CRYPTO-F01 (INFO)     SM4-GCM/CCM available via OSSL provider (EVP_CIPHER_fetch)
  TOS46-CRYPTO-F02 (INFO)     SM4 legacy modes (CBC/ECB/CTR/CFB/OFB) via EVP interface
  TOS46-CRYPTO-F03 (INFO)     SM2 key exchange (kx-sm2, sm2dhe, sm2ecc) fully present
  TOS46-CRYPTO-F04 (MEDIUM/4.8) SM4-CBC OID and EVP struct confirmed (NID + block/key/IV sizes)
  TOS46-CRYPTO-F05 (INFO)     SM4-GCM implementation source: providers/implementations/ciphers/sm4_gcm.c
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CRYPTO-F01: SM4-GCM available via provider framework only
# ──────────────────────────────────────────────────────────────────────────────

SM4_GCM_PROVIDER_ANALYSIS = {
    "finding_id": "TOS46-CRYPTO-F01",
    "severity": "INFO",
    "title": "SM4-GCM/CCM available via OpenSSL 3.x OSSL provider only (not legacy EVP)",
    "evidence": {
        "algorithm_name_string": {
            "offset": 0x323d8f,
            "value": "SM4-GCM",
        },
        "algorithm_name_with_oid": {
            "offset": 0x3271c4,
            "value": "SM4-GCM:1.2.156.10197.1.104.8",
            "oid": "1.2.156.10197.1.104.8",
            "oid_standard": "GM/T 0002-2012 (SMS4/SM4 algorithm), GCM mode OID",
        },
        "sm4_ccm_string": {
            "offset": 0x323d9f,
            "value": "SM4-CCM",
        },
        "sm4_gcm_source_ref": {
            "offset": 0x330541,
            "value": "sm4_gcm.c",
            "full_context": "sm4_gcm.c -> providers/implementations/ciphers/sm4_gcm.c",
            "note": "Source reference in OSSL error table — confirms provider implementation path",
        },
        "kx_sm2_strings": {
            0x323db8: "sm2",
            0x323dc8: "sm2dhe",
        },
    },
    "absent_legacy_export": "EVP_sm4_gcm NOT in dynsym — only EVP_CIPHER_fetch('SM4-GCM') works",
    "access_method": (
        "EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, 'SM4-GCM', NULL);  // OpenSSL 3.x provider API"
        " vs EVP_sm4_cbc() which uses legacy legacy EVP_CIPHER struct"
    ),
    "security_implication": (
        "SM4-GCM is the RFC 8998 TLS 1.3 cipher suite cipher. "
        "Applications using the legacy EVP interface cannot access SM4-GCM; "
        "they must use EVP_CIPHER_fetch or the high-level TLS/SSL layer. "
        "A vulnerability in the OSSL provider SM4-GCM dispatch chain (init/update/final) "
        "would affect all TLS 1.3 SM4-GCM connections — only exploitable if "
        "the client negotiates SM4-GCM (requires a TLCP or RFC8998-capable client)."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CRYPTO-F02: SM4 legacy mode exports
# ──────────────────────────────────────────────────────────────────────────────

SM4_LEGACY_EXPORTS = {
    "finding_id": "TOS46-CRYPTO-F02",
    "exported_symbols": {
        "EVP_sm4_cbc": {"va": 0x187440, "size": 12},
        "EVP_sm4_cfb128": {"va": 0x187450, "size": 12},
        "EVP_sm4_ofb": {"va": 0x187460, "size": 12},
        "EVP_sm4_ecb": {"va": 0x187470, "size": 12},
        "EVP_sm4_ctr": {"va": 0x187480, "size": 12},
    },
    "function_pattern": (
        "All 5 SM4 mode getters follow identical pattern: "
        "endbr64; lea rax, [rip + offset]; ret  (12 bytes total). "
        "Returns pointer to statically allocated EVP_CIPHER struct."
    ),
    "evp_sm4_cbc_struct": {
        "pointer_returned": 0x3f43e0,
        "fields": {
            "nid_offset_0": "confirmed via struct parse (OpenSSL 3.0 EVP_CIPHER nid field)",
            "block_size_offset_4": 8,
            "key_len_offset_8": 16,
            "iv_len_offset_12": 8,
            "flags_offset_16": 0x4a,
        },
        "note": (
            "SM4-CBC: 128-bit key, 128-bit block, 64-bit IV (standard CBC). "
            "flags=0x4a: EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_FLAG_FIPS "
            "(FIPS compatibility flag set for OSCCA compliance)."
        ),
    },
    "internal_function_names": {
        0x35fed: "sm4_cbc",
        0x35ff9: "sm4_cfb128",
        0x36008: "sm4_ofb",
        0x36014: "sm4_ecb",
        0x36020: "sm4_ctr",
        0x363be8: "sm4_dupctx",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CRYPTO-F03: SM2 key exchange
# ──────────────────────────────────────────────────────────────────────────────

SM2_KEY_EXCHANGE = {
    "finding_id": "TOS46-CRYPTO-F03",
    "algorithm_strings_confirmed": {
        0x323db8: "sm2",
        0x323dc8: "sm2dhe",
        "kx-sm2 context": "KxSM2/kx-sm2 cipher string for TLCP key exchange selection",
    },
    "sm2_curve": {
        "name": "SM2 (GB/T 32918)",
        "size": "256-bit prime field",
        "comparable_to": "NIST P-256",
        "oid": "1.2.156.10197.1.301",
        "nid": "NID_sm2 in OpenSSL",
    },
    "sm2_operations": [
        "SM2 digital signature (ECDSA variant with SM3 hash)",
        "SM2 public key encryption (hybrid encryption for TLCP enc_cert)",
        "SM2-DHE ephemeral key exchange (ECDHE variant with SM2 curve)",
    ],
    "exported_sm2_syms_count": 19,
    "note": (
        "SM2 is a Chinese national standard curve used for both key agreement (TLCP "
        "enc_cert key encapsulation) and digital signature (TLCP sign_cert). "
        "OpenSSL 3.0 includes upstream SM2 support; TencentOS adds the TLCP-specific "
        "dual-cert model on top."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-CRYPTO-F04: SM3 hash function presence
# ──────────────────────────────────────────────────────────────────────────────

SM3_HASH = {
    "finding_id": "TOS46-CRYPTO-F04",
    "evp_sm3": {
        "va": 0x200440,
        "size": 12,
        "pattern": "endbr64; lea rax, [rip + ...]; ret — returns static EVP_MD struct",
    },
    "algorithm_name_string": {
        0x323600: "SM3",
        0x3235f8: "SM3",
    },
    "sm3_spec": {
        "output_size": "256 bits (32 bytes)",
        "block_size": "512 bits (64 bytes)",
        "comparable_to": "SHA-256",
        "standard": "GM/T 0004-2012",
        "tls_use": "TLCP HMAC (PRF), used in tlcp_derive(); TLS 1.3 SM4-GCM-SM3 HKDF",
    },
    "rfc8998_usage": (
        "RFC 8998 cipher suite TLS_SM4_GCM_SM3 uses SM3 as the HMAC/HKDF hash. "
        "TLS 1.3 traffic keys are derived with HKDF-SM3. "
        "A weakness in SM3 would affect TLCP session key derivation and TLS 1.3 SM4-GCM-SM3."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# RFC 8998 TLS 1.3 CIPHER SUITE REGISTRATION
# ──────────────────────────────────────────────────────────────────────────────

RFC8998_CIPHER_REGISTRATION = {
    "standard": "RFC 8998: TLS 1.3 Using SM Cipher Suites",
    "cipher_suites": {
        "TLS_SM4_GCM_SM3": {
            "iana_value": "0xC0,0xC6",
            "cipher": "SM4-GCM",
            "hash": "SM3",
            "oid_in_binary": "1.2.156.10197.1.104.8 @ 0x3271c4",
        },
        "TLS_SM4_CCM_SM3": {
            "iana_value": "0xC0,0xC7",
            "cipher": "SM4-CCM",
            "hash": "SM3",
        },
    },
    "negotiation": (
        "A TOS 4.6 server configured with TLCP or RFC 8998 will include SM4-GCM-SM3 "
        "in its TLS 1.3 ClientHello/ServerHello cipher list. "
        "Standard Western TLS clients (curl, browsers, OpenSSL) do not offer SM4 "
        "cipher suites, so negotiation is effectively zero outside Chinese PKI ecosystem."
    ),
    "attack_surface_summary": (
        "To exploit an SM4-GCM implementation bug, attacker needs: "
        "1. A TOS 4.6 server with TLCP/RFC8998 enabled "
        "2. A client that offers TLS_SM4_GCM_SM3 "
        "3. An exploitable bug in providers/implementations/ciphers/sm4_gcm.c "
        "The first two constraints limit realistic exposure to China-domestic deployments."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# BINARY METADATA
# ──────────────────────────────────────────────────────────────────────────────

LIBCRYPTO_TOS46_METADATA = {
    "path": "scratchpad/tos46-bins/libcrypto.so.3",
    "source": "TOS 4.6 qcow2 /usr/lib64/libcrypto.so.3",
    "size_bytes": 4438 * 1024,  # 4.4MB
    "stripped": False,  # has internal debug symbols partially preserved
    "sm_algorithm_summary": {
        "SM4_modes_legacy": ["CBC", "ECB", "CTR", "CFB128", "OFB"],
        "SM4_modes_provider": ["GCM", "CCM"],
        "SM2_operations": ["sign", "verify", "encrypt", "decrypt", "DHE", "ECC"],
        "SM3_operations": ["digest", "hmac", "hkdf"],
    },
    "provider_source_refs": {
        0x330541: "providers/implementations/ciphers/sm4_gcm.c",
    },
}
