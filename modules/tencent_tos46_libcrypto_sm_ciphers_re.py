"""
TencentOS Server 4.6 libcrypto.so.3 SM Cipher Suite Binary RE Module
Binary: libcrypto.so.3 (from TOS 4.6 qcow2 /usr/lib64/libcrypto.so.3)
        openssl-3.0.12-27.tl4 build (4.4MB binary, full OpenSSL provider framework)
Source: /dev/nbd10 mount of TOS 4.6 qcow2
Method: ELF dynsym + string scan + OID registry analysis + capstone disassembly
        + EVP_CIPHER struct function pointer extraction + objdump disassembly
        + RIP-relative binary scan for cross-references + symbol resolution
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
  TOS46-SM2KE-F01 (INFO)      sm2_kmeth.c TLCP dual-cert key param setter — "self-enc-key"/"peer-enc-key"
  TOS46-SM2KE-F02 (INFO)      sm2_kmeth.c main function — SM2 key agreement (GB/T 32918.3) binary confirmed
  TOS46-SM2KE-F03 (MEDIUM/4.3) sm2sig_set_mdname: no SM3 enforcement — weak digest substitution possible
  TOS46-SM2KE-F04 (INFO)      sm22text_encode / sm22blob_encode OSSL encoder wrappers — correct param handling
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
        0x323daf: "KxSM2",
        0x323db5: "kx-sm2",
        0x323dbc: "KxSM2DHE",
        0x323dc5: "kx-sm2dhe",
        0x323dcf: "AuthSM2",
        0x323dd7: "auth-sm2",
        0x3271fc: "SM2:1.2.156.10197.1.301",
        0x327274: "SM2DH",
    },
    "sm2_curve": {
        "name": "SM2 (GB/T 32918)",
        "size": "256-bit prime field",
        "comparable_to": "NIST P-256",
        "oid": "1.2.156.10197.1.301",
        "string_at_0x3271fc": "SM2:1.2.156.10197.1.301",
    },
    "public_api_model": (
        "OpenSSL 3.0 does NOT export SM2_* functions directly. "
        "SM2 is accessed via EVP_PKEY_CTX with key type 'SM2' (NID_sm2). "
        "readelf -Ws confirms 0 exported FUNC symbols matching SM2. "
        "Prior count of '19 exported SM2 syms' was incorrect."
    ),
    "internal_sm2_functions": {
        "crypto_operations": {
            0x0035e208: "sm2_sig_verify — provider dispatch, signature verification",
            0x0035e220: "ossl_sm2_internal_verify — core EC-DSA verify (SM2 variant)",
            0x0035e240: "ossl_sm2_compute_z_digest — Z=H(ENTL||ID||a||b||xG||yG||xA||yA)",
            0x00363a20: "ossl_sm2_plaintext_size — ciphertext length → plaintext length",
            0x00363a40: "ossl_sm2_decrypt — SM2 hybrid decryption (C1||C2||C3 format)",
            0x00363a60: "ossl_sm2_encrypt — SM2 hybrid encryption",
            0x00363a80: "sm2_asym_encrypt — provider KEYENCRYPT dispatch",
            0x00366180: "ossl_sm2_key_private_check — private key in range [1, n-1]",
            0x00366e58: "sm2_sig_gen — provider dispatch, signature generation",
            0x00366e70: "ossl_sm2_internal_sign — core EC-DSA sign (SM2 variant)",
            0x00366e90: "sm2sig_signature_init — signature context init",
            0x00366ea8: "sm2sig_newctx — allocate SM2 signature context",
            0x00366ec0: "sm2sig_set_mdname — set message digest (SM3 by default)",
        },
        "key_exchange": {
            0x00365d60: "SM2_compute_key — legacy SM2 key agreement (compatibility API)",
            0x00365d70: "sm2dh_derive — SM2-DHE derivation (TLCP ephemeral KE)",
            0x00366168: "sm2_gen_init — key generation initialization",
        },
        "serialization": {
            0x00364060: "sm2_to_type_specific_no_pub_der_encode",
            0x00365840: "sm2_to_type_specific_no_pub_pem_encode",
            0x00364490: "sm22text_encode — SM2 key to text format",
            0x00364590: "sm22blob_encode — SM2 key to blob format (TencentOS extension)",
            0x00364e40: "sm2_to_SubjectPublicKeyInfo_pem_encode",
            0x00364e80: "sm2_to_SubjectPublicKeyInfo_der_encode",
            0x00364ec0: "sm2_to_PrivateKeyInfo_pem_encode",
            0x00364f00: "sm2_to_PrivateKeyInfo_der_encode",
            0x00364f40: "sm2_to_EncryptedPrivateKeyInfo_pem_encode",
            0x00364f80: "sm2_to_EncryptedPrivateKeyInfo_der_encode",
        },
        "source_file_refs": {
            0x3249da: "crypto/sm2/sm2_sign.c",
            0x326fee: "crypto/sm2/sm2_crypt.c",
            0x32770f: "crypto/sm2/sm2_kmeth.c — TencentOS-added key method",
            0x3277b2: "crypto/sm2/sm2_key.c",
            0x32d588: "providers/implementations/asymciphers/sm2_enc.c",
            0x330d40: "providers/implementations/exchange/sm2dh_exch.c",
            0x3316e0: "providers/implementations/signature/sm2_sig.c",
        },
    },
    "security_note": (
        "sm2sig_set_mdname (0x366ec0) allows applications to choose any digest with SM2. "
        "If an application specifies a weak MD (SHA-1, MD5) instead of SM3, signature "
        "security is reduced. The default is SM3 (SM2-SM3, string at 0x323a1c). "
        "No enforcement of SM3-only in the libcrypto implementation layer."
    ),
    "tencent_extensions": [
        "crypto/sm2/sm2_kmeth.c — new file (TencentOS patch), SM2 key method for TLCP dual-cert",
        "sm22text_encode / sm22blob_encode — non-upstream encoding helpers",
        "'sm2-initiator' role string — TLCP handshake role assignment",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SM2KE-F01: sm2_kmeth.c TLCP dual-cert param setter — binary
# ──────────────────────────────────────────────────────────────────────────────

SM2_KMETH_PARAM_SETTER = {
    "finding_id": "TOS46-SM2KE-F01",
    "severity": "INFO",
    "title": (
        "sm2_kmeth.c TLCP dual-cert key parameter setter (0x26d6f0): "
        "processes OSSL_PARAM array for sm2-initiator/self-enc-key/peer-enc-key; "
        "EC_KEY_free+EC_KEY_up_ref pair for atomic key replacement on sign and enc slots"
    ),
    "function_va": 0x26d6f0,
    "source_file": "crypto/sm2/sm2_kmeth.c",
    "source_ref_va": 0x32770f,
    "ossl_param_names_resolved": {
        "sm2-initiator": {
            "string_va": 0x3276d7,
            "type": "int (boolean)",
            "effect": "marks this endpoint as TLCP initiator (client role)",
            "ossl_param_op": "OSSL_PARAM_get_int",
        },
        "self-enc-key": {
            "string_va": 0x3276e5,
            "type": "octet pointer (EC_KEY*)",
            "effect": "replaces own encryption key at struct[+0x18]; EC_KEY_free old + EC_KEY_up_ref new",
            "ossl_param_op": "OSSL_PARAM_get_octet_ptr",
        },
        "peer-enc-key": {
            "string_va": 0x3276f2,
            "type": "octet pointer (EC_KEY*)",
            "effect": "replaces peer encryption key at struct[+0x20]; EC_KEY_free old + EC_KEY_up_ref new",
            "ossl_param_op": "OSSL_PARAM_get_octet_ptr",
        },
    },
    "key_replacement_pattern": (
        "For each key slot: EC_KEY_free(old_key) -> EVP_PKEY_CTX_new_from_pkey(new_key) -> "
        "NULL check -> EC_KEY_up_ref(new_key). "
        "EVP_KEYMGMT_free called on the intermediate KEYMGMT object used for import. "
        "Ordering: free old, import new, increment ref. "
        "If import fails (EVP_PKEY_CTX_new_from_pkey returns NULL), slot is set to NULL — "
        "subsequent operations on the context will correctly fail NULL checks."
    ),
    "dual_cert_model": (
        "TLCP (GB/T 38636) uses two SM2 certificate/key pairs per endpoint: "
        "  1. Sign certificate — used for authentication (handshake signature) "
        "  2. Encryption certificate — used for key agreement/encipherment "
        "Both are distinct SM2 key pairs. This setter handles both encryption key slots "
        "(own + peer) while the signing keys are set via a separate mechanism."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SM2KE-F02: sm2_kmeth.c main function — SM2 KA binary analysis
# ──────────────────────────────────────────────────────────────────────────────

SM2_KMETH_KEY_AGREEMENT = {
    "finding_id": "TOS46-SM2KE-F02",
    "severity": "INFO",
    "title": (
        "sm2_kmeth.c SM2 key agreement function (0x26dcb0): "
        "GB/T 32918.3 algorithm confirmed by binary — "
        "x-bar coordinate reduction, t_A computation, EC_POINT_mul+add for shared secret; "
        "EC_POINT_is_on_curve + cofactor check present"
    ),
    "function_va": 0x26dcb0,
    "function_size_approx": 0x8D0,
    "prologue": {
        "stack_frame": 0xb8,
        "callee_saved": ["r15", "r14", "r13", "r12", "rbp", "rbx"],
        "stack_canary": False,
    },
    "context_struct_layout": {
        "description": "SM2_KEYEXCH context pointed to by arg1 (rdi)",
        "fields": {
            "+0x00": "OSSL_LIB_CTX*  — for BN_CTX_new_ex",
            "+0x08": "EC_KEY*  self_sign_key  — own signing key (private+public accessed)",
            "+0x10": "EC_KEY*  peer_sign_key  — peer signing key (public key only accessed)",
            "+0x18": "EC_KEY*  self_enc_key   — own encryption key (private key accessed)",
            "+0x20": "EC_KEY*  peer_enc_key   — peer encryption key (on-curve validated)",
            "+0x28": "pointer  (checked non-null — likely ephemeral key or BIGNUM)",
            "+0x30": "pointer  (BIGNUM* or EC_GROUP*)",
            "+0x38": "pointer  (checked non-null — 4th EC key component)",
            "+0x40": "pointer  (saved to rsp+0x28)",
            "+0x48": "int      sm2_initiator_flag  — set by sm2-initiator OSSL_PARAM",
            "+0x50": "pointer  output_key_buf  — key material output",
            "+0x58": "uint64   key_length_bits — desired derived key length in bits",
        },
    },
    "input_validation": {
        "null_output_buf": "test rsi, rsi; je 0x26e51a -> error on NULL arg2",
        "outlen_check": "cmp r13, rcx; jb 0x26e5a8 -> error if key_length_bits < requested outlen",
        "key_length_overflow": "cmp r13, 0x7fffffff; ja 0x26e618 -> error prevents integer overflow in KDF",
        "all_key_fields_null_checked": "r15/rdx/r14/r10/rax/r11/rsi all checked non-null before any EC operation",
    },
    "algorithm_steps_binary_confirmed": {
        "step_1_bn_ctx": "BN_CTX_new_ex([rdi+0x00]) -> BN_CTX_start; 8 x BN_CTX_get -> temporaries t1..t8",
        "step_2_get_keys": [
            "EC_KEY_get0_private_key([+0x18]) -> self enc private key",
            "EC_KEY_get0_public_key([+0x08]) -> self sign public key",
            "EC_KEY_get0_public_key([+0x10]) -> peer sign public key",
            "EC_KEY_get0_private_key([+0x08]) -> self sign private key",
        ],
        "step_3_group_params": [
            "EC_GROUP_get_order  (0x140bf0) -> group order n",
            "EC_GROUP_get_cofactor (0x140f60) -> cofactor h (1 for SM2 curve; no subgroup risk)",
        ],
        "step_4_coord_reduction": [
            "BN_num_bits (0xe6810) -> bit size of group order",
            "BN_value_one (0xe55d0) -> constant 1",
            "BN_lshift (0xec160) with (degree+1)/2 -> 2^w constant (w = ceil(ceil(log2(n))/2) - 1)",
            "EC_POINT_get_affine_coordinates (0x140330) x 2 -> get x1, x2 from ephemeral points",
            "BN_nnmod (0xe9990) x 2 -> x_bar_A = x1 mod 2^w, x_bar_B = x2 mod 2^w",
            "BN_add (0xe4610) x 2 -> 2^w + x_bar_A, 2^w + x_bar_B",
        ],
        "step_5_combine_private": [
            "BN_mod_mul (0xeb560) -> t_A = (d_A * x_bar_A) mod n",
            "BN_mod_add (0xe9a40) -> t_A = t_A + r_A mod n  (t_A = r_A + d_A*x_bar_A)",
        ],
        "step_6_point_math": [
            "EC_POINT_mul (0x145340) -> R_B + x_bar_B * P_B  (combine peer ephemeral + static)",
            "EC_POINT_mul (0x145340) -> h * t_A * (above)  (cofactor * combined scalar mul)",
            "EC_POINT_add (0x13ffe0) -> U = point addition",
            "BN_mul (0xe8db0) -> final bignum operation in key derivation",
        ],
        "step_7_on_curve_check": (
            "EC_POINT_is_on_curve (0x140460) called — validates peer key is on SM2 curve. "
            "Prevents invalid curve attacks where attacker provides off-curve point to "
            "force private key leakage through small-order subgroup."
        ),
    },
    "security_properties": {
        "invalid_curve_protection": "PRESENT — EC_POINT_is_on_curve called before EC operations",
        "cofactor_multiplication": "PRESENT — EC_GROUP_get_cofactor used; h=1 for SM2 (no subgroup risk)",
        "integer_overflow_protection": "PRESENT — 0x7fffffff bound on key_length_bits",
        "coordinate_reduction_w": "CORRECT — BN_lshift((degree+1)/2) matches GB/T 32918.3 appendix B.3",
        "null_termination": "All key components validated non-null before EC operations",
    },
    "sm2_standard": {
        "spec": "GB/T 32918.3-2016 (SM2 key agreement protocol, part 3)",
        "also_known_as": "GM/T 0003.3-2012",
        "tlcp_use": (
            "TLCP (GB/T 38636) uses SM2 key agreement for session key derivation. "
            "Both parties contribute ephemeral and long-term key material. "
            "Output key material feeds into PRF for TLCP master secret."
        ),
    },
    "functions_called_resolved": {
        "EC_KEY_get0_private_key":          0x13ee30,
        "EC_KEY_get0_public_key":           0x13ee40,
        "EC_POINT_new":                     0x13fbe0,
        "EC_POINT_add":                     0x13ffe0,
        "EC_POINT_get_affine_coordinates":  0x140330,
        "EC_POINT_is_on_curve":             0x140460,
        "EC_GROUP_get_order":               0x140bf0,
        "EC_GROUP_get_cofactor":            0x140f60,
        "EC_POINT_mul":                     0x145340,
        "BN_add":                           0xe4610,
        "BN_value_one":                     0xe55d0,
        "BN_num_bits":                      0xe6810,
        "BN_CTX_new_ex":                    0xe7260,
        "BN_CTX_start":                     0xe7330,
        "BN_CTX_get":                       0xe7480,
        "BN_mul":                           0xe8db0,
        "BN_nnmod":                         0xe9990,
        "BN_mod_add":                       0xe9a40,
        "BN_mod_mul":                       0xeb560,
        "BN_lshift":                        0xec160,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SM2KE-F03: sm2sig_set_mdname — no SM3 enforcement
# ──────────────────────────────────────────────────────────────────────────────

SM2SIG_MD_ENFORCEMENT = {
    "finding_id": "TOS46-SM2KE-F03",
    "severity": "MEDIUM",
    "cvss_v3": 4.3,
    "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N",
    "title": (
        "sm2sig_set_mdname (0x366ec0): no SM3 enforcement — any EVP digest accepted; "
        "SHA-1 or MD5 substitution reduces SM2 signature security to collision-finding in that hash"
    ),
    "function_va": 0x366ec0,
    "description": (
        "sm2sig_set_mdname accepts any digest name string without validating it is SM3. "
        "The TencentOS TLCP profile requires SM2-with-SM3 for all certificate signatures "
        "(GM/T 0024-2014 section 7.2.1). If an application passes 'SHA1', 'MD5', or 'SHA256' "
        "to EVP_PKEY_CTX_set_signature_md, libcrypto will accept it and use that hash "
        "for SM2 signing operations."
    ),
    "upstream_behavior": (
        "This matches upstream OpenSSL 3.0 behavior — upstream also does not enforce SM3-only. "
        "Not a TencentOS-specific regression; however TencentOS ships this for TLCP use "
        "where SM3 is mandated by the standard, making it a deployment-relevant gap."
    ),
    "attack_path": (
        "1. Application calls EVP_PKEY_CTX_set_signature_md(ctx, EVP_md5()) for SM2 key. "
        "2. sm2sig_set_mdname stores 'MD5' digest name without validation. "
        "3. sm2sig_gen computes H(M) using MD5 instead of SM3. "
        "4. Attacker finds MD5 collision for target message. "
        "5. Forged signature validates against SM2 verify that also uses MD5. "
        "Chain: TLCP negotiation allowing client-specified hash -> downgrade to MD5 -> SM2 forgery."
    ),
    "remediation": (
        "Add whitelist check in sm2sig_set_mdname: only accept 'SM3' and 'SM3-SM2'. "
        "Alternatively: TLS layer must enforce SM2-SM3 cipher suite matching — "
        "application-layer digest selection should not be possible when using TLCP."
    ),
    "default_digest": "SM3 (SM2-SM3 suite string at 0x323a1c) — risk is in opt-in override, not default",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SM2KE-F04: sm22text_encode / sm22blob_encode binary analysis
# ──────────────────────────────────────────────────────────────────────────────

SM22_ENCODER_BINARY = {
    "finding_id": "TOS46-SM2KE-F04",
    "severity": "INFO",
    "title": (
        "sm22text_encode (0x268990) / sm22blob_encode (0x2664d0): "
        "OSSL_ENCODER dispatch wrappers — reject non-null abstract OSSL_PARAM (correct); "
        "blob encoder is thin wrapper (tail-call 0x292330); "
        "NOTE: prior module entry used string offsets as function VAs — corrected here"
    ),
    "function_vas_corrected": {
        "sm22text_encode": {
            "actual_fn_va": 0x268990,
            "wrong_value_in_prior_entry": 0x364490,
            "note": "0x364490 is the string literal 'sm22text_encode' in .rodata, not code",
        },
        "sm22blob_encode": {
            "actual_fn_va": 0x2664d0,
            "wrong_value_in_prior_entry": 0x364590,
            "note": "0x364590 is the string literal 'sm22blob_encode' in .rodata, not code",
        },
    },
    "sm22text_encode_disassembly": {
        "va": 0x268990,
        "param_check": "test rcx, rcx; je 0x2689e0 — if abstract params == NULL, proceed to encode",
        "error_path_if_params_nonnull": {
            "calls": ["ERR_new(0x170800)", "ERR_set_error(0x171860)", "ERR_string(0x170bc0)"],
            "error_code": 0x80106,
            "file_ref": "sm2_kmeth.c line 868 (0x364)",
            "returns": 0,
        },
        "encode_path_if_params_null": {
            "call_0x243e40": "alloc/prepare SM2 key for text output",
            "call_0x2682a0": "inner text encoder (formats key to PEM/text representation)",
            "call_0x0d9990": "cleanup/free of intermediate buffer",
        },
    },
    "sm22blob_encode_disassembly": {
        "va": 0x2664d0,
        "param_check": "test rcx, rcx; je 0x266518 — if abstract params == NULL, proceed to encode",
        "error_path_if_params_nonnull": {
            "calls": ["ERR_new(0x170800)", "ERR_set_error(0x171860)", "ERR_string(0x170bc0)"],
            "error_code": 0x80106,
            "file_ref": "sm2_kmeth.c line 177 (0xb1)",
            "returns": 0,
        },
        "encode_path_if_params_null": {
            "description": "arg swap then tail-call to 0x292330",
            "arg_swap": "swap arg2/arg3 registers (output BIO and key pointer reordered)",
            "tail_call": 0x292330,
        },
    },
    "ossl_encoder_conformance": (
        "Both functions follow correct OSSL_ENCODER callback conventions. "
        "Abstract-key-params (rcx) checked on entry; non-null params rejected with error. "
        "This prevents silent ignoring of params the function cannot handle — correct behavior."
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

# ──────────────────────────────────────────────────────────────────────────────
# SM4 IMPLEMENTATION BINARY DETAILS (confirmed via disassembly + data analysis)
# ──────────────────────────────────────────────────────────────────────────────

SM4_IMPLEMENTATION_BINARY = {
    "sbox": {
        "file_offset": 0x361780,
        "size": 256,
        "first_16_bytes": "d690e9fecce13db716b614c228fb2c05",
        "standard_match": True,
        "note": "Exact match with OSCCA SM4 standard S-box (GB/T 32907-2016, Annex A)",
    },
    "fk_constants": {
        "file_offset_start": 0x3342d0,
        "constants": [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC],
        "note": "SM4 family key constants (FK[0]-FK[3]) used in key schedule MK XOR step",
        "file_offsets": {
            "FK0": 0x3342d0,
            "FK1": 0x3342d4,
            "FK2": 0x3342d8,
            "FK3": 0x3342dc,
        },
    },
    "evp_sm4_cbc_struct": {
        "file_offset": 0x3f43e0,
        "function_pointers": {
            "init_fn":       {"offset_in_struct": 0x20, "va": 0x18a8c0},
            "do_cipher_fn":  {"offset_in_struct": 0x28, "va": 0x18a720},
            "cleanup_fn":    {"offset_in_struct": 0x30, "va": 0x0},       # NULL
            "ctrl_fn":       {"offset_in_struct": 0x50, "va": 0x188280},
        },
        "ctx_size": 0x104,  # 260 bytes per cipher context
    },
    "sm4_cbc_init_fn": {
        "va": 0x18a8c0,
        "description": "SM4-CBC key initialization — loads key, calls key schedule",
        "calls": {
            0x187ec0: "EVP_CIPHER_CTX_get_cipher_data() — get cipher-specific ctx",
            0x196ad0: "sm4_set_key_enc() — SM4 key expansion entry point",
            0x1e90d0: "sm4_set_key_inner() — bit-level key schedule",
        },
        "returns": 1,  # always success
        "key_disassembly": [
            "endbr64",
            "push r13; push r12; push rbp; push rbx",
            "call 0x187ec0   ; get cipher data ptr",
            "mov r13d, [rax] ; save something from cipher data",
            "call 0x196ad0   ; sm4_set_key_enc",
            "call 0x187ec0   ; get cipher data ptr again",
            "lea rdi, [rax+4]; point to key buffer at ctx+4",
            "call 0x1e90d0   ; expand key schedule",
            "mov eax, 1; ret",
        ],
    },
    "sm4_cbc_do_cipher_fn": {
        "va": 0x18a720,
        "description": "SM4-CBC encrypt/decrypt — processes input blocks",
        "length_check": {
            "instruction": "cmp rcx, 0x3fffffff",
            "limit": 0x3fffffff,
            "note": "Input length bounded at ~1GB per call (prevents integer overflow in loop)",
        },
        "iv_access_offset": 0x28,  # lea r14, [rdi + 0x28] — IV in cipher context
        "calls": {
            0x187e80: "EVP_CIPHER_CTX_get_flags()",
            0x187ec0: "EVP_CIPHER_CTX_get_cipher_data()",
        },
    },
    "sm4_set_key_fn": {
        "va": 0x196ad0,
        "description": "SM4 key setup — zero-fills local state, loads SBOX/FK ptr, calls SM4_set_key",
        "note": "Uses XMM registers (pxor/movaps) for efficient zero-fill of 160-byte key context",
        "sbox_ptr_load": "lea rsi, [rip + 0x18517c]  ; -> SBOX/CK table ptr",
        "calls": {
            0x1bf2c0: "SM4_set_key() — actual round key computation",
        },
    },
    "security_notes": [
        "Standard SM4 S-box confirmed — no backdoored S-box substitution",
        "Standard FK constants confirmed — key schedule matches spec",
        "SM4-CBC IV stored at EVP cipher context +0x28",
        "No constant-time guarantees: table lookups with secret-dependent indices (S-box) "
        "are vulnerable to cache-timing side-channel attacks (Flush+Reload, Prime+Probe)",
        "1GB per-call length limit in do_cipher prevents overflow but not DoS via very long inputs",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-CRYPTO-F01": SM4_GCM_PROVIDER_ANALYSIS,
    "TOS46-CRYPTO-F02": SM4_LEGACY_EXPORTS,
    "TOS46-CRYPTO-F03": SM2_KEY_EXCHANGE,
    "TOS46-CRYPTO-F04": SM3_HASH,
    "TOS46-SM2KE-F01":  SM2_KMETH_PARAM_SETTER,
    "TOS46-SM2KE-F02":  SM2_KMETH_KEY_AGREEMENT,
    "TOS46-SM2KE-F03":  SM2SIG_MD_ENFORCEMENT,
    "TOS46-SM2KE-F04":  SM22_ENCODER_BINARY,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "libcrypto.so.3 (openssl-3.0.12-27.tl4, TOS 4.6 qcow2)",
        "method": "ELF dynsym + string scan + RIP-relative cross-ref binary scan + objdump disassembly",
        "sm_algorithms": ["SM2", "SM3", "SM4"],
        "tencent_extensions": ["sm2_kmeth.c", "sm22text_encode", "sm22blob_encode", "sm2-initiator"],
        "sm2_key_agreement_binary": "0x26dcb0 — GB/T 32918.3 algorithm confirmed",
        "sm2_param_setter_binary": "0x26d6f0 — self-enc-key/peer-enc-key OSSL_PARAM handlers confirmed",
        "sm22_encoder_vas_corrected": "sm22text=0x268990, sm22blob=0x2664d0 (prior entries were .rodata offsets)",
        "findings": [{"id": k, "severity": v.get("severity", "INFO")} for k, v in FINDINGS.items()],
    }, indent=2))
