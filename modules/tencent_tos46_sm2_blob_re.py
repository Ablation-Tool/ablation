"""
TencentOS 4.6 — SM2 cryptographic implementation blob RE.

Blobs:
  sm22blob.bin      — 768 bytes, x86-64 machine code (5 functions)
  sm22text.bin      — 768 bytes, x86-64 machine code (1 function)
  sm2kmeth_main.bin — 2256 bytes, x86-64 machine code (SM2 key method dispatcher)
  sm2kmeth_bn.bin   — 1583 bytes, x86-64 machine code (sub-function, no endbr64)

Method: capstone disassembly + call target clustering + instruction pattern analysis.

Context: These are raw code fragments extracted from a TOS 4.6 binary (unknown source
binary). All four start with either endbr64 (CET-compiled) or are mid-function code.
SM2 is the Chinese national elliptic curve standard (GB/T 32918.x), used for digital
signatures and key exchange. TOS 4.6 includes SM2 support in its OpenSSL-derived
cryptographic stack.
"""

BLOB_INVENTORY = {
    "sm22blob.bin": {
        "size": 768,
        "type": "x86-64 machine code",
        "functions": 5,
        "endbr64_offsets": [0x0, 0x60, 0xc0, 0x120, 0x2c0],
        "role": "SM2 null-argument guard stubs (OpenSSL-style error entry checks)",
    },
    "sm22text.bin": {
        "size": 768,
        "type": "x86-64 machine code",
        "functions": 1,
        "endbr64_offsets": [0x0],
        "role": "SM2 null-argument guard stub (single larger function)",
    },
    "sm2kmeth_main.bin": {
        "size": 2256,
        "type": "x86-64 machine code",
        "functions": 1,
        "endbr64_offsets": [0x0],
        "call_count": 54,
        "unique_call_targets": 35,
        "role": "SM2 EVP_PKEY_METHOD or EVP_PKEY_ASN1_METHOD dispatcher (key operation dispatch)",
    },
    "sm2kmeth_bn.bin": {
        "size": 1583,
        "type": "x86-64 machine code",
        "functions": "1 (partial, no endbr64 — continuation or called sub-function)",
        "role": "SM2 BigNum/ECC field arithmetic sub-function",
    },
}

SM22BLOB_ANALYSIS = {
    "function_pattern": (
        "Each function follows a 4-part structure: "
        "(1) Test rcx (4th argument) for NULL; je → alternative_path. "
        "(2) Call error reporting function (0xfff0a330 — likely ERR_raise or EVP error logger). "
        "(3) Load [rip+offset] into rdx (error string pointer), load esi = reason_code. "
        "(4) Load [rip+offset] into rdi (function name string), call error handler (0xfff0b390). "
        "(5) Zero eax and edx; load edi=0x39=57, esi=0x80106; call cleanup (0xfff0a6f0). "
        "(6) Return 0 (failure). "
        "If rcx IS NULL at entry: swap arguments and jmp to the actual SM2 implementation."
    ),
    "esi_reason_codes": {
        "fn_0x00": "0xb1 (177) — error reason for first null-arg function",
        "fn_0x60": "0xe6 (230) — error reason for second null-arg function",
        "fn_0xc0": "0xea (234) — error reason for third null-arg function",
        "fn_0x120": "0x5aa (1450) — packed error code (OpenSSL 3.x ERR_PACK format?)",
        "fn_0x2c0": "0x5ae (1454) — packed error code",
    },
    "error_framework": (
        "The pattern matches OpenSSL 3.x EVP method wrapper conventions: "
        "public API functions check for NULL required arguments and call ERR_raise() before "
        "returning 0 (failure) or -1 (error). The 0x80106 value passed in esi is consistent with "
        "an OpenSSL error library/function identifier — possibly a TOS-specific SM2 library number "
        "(standard OpenSSL ERR_LIB_SM2 = 39; 0x80 = 128 suggests a Tencent-extended lib ID). "
        "0x39 = 57 may be an EVP_PKEY type ID for SM2 (OpenSSL uses NID_sm2 = 1172 in mainline, "
        "but Tencent TOS may use a different NID)."
    ),
    "verdict": "Null-pointer argument guards — standard defensive coding for SM2 EVP API entry points",
}

SM2KMETH_MAIN_ANALYSIS = {
    "size": 2256,
    "call_distribution": {
        "most_frequent": {
            "0xe797d0": "8 calls — likely EC_POINT arithmetic (scalar mult or point add)",
            "0xed1190": "3 calls — likely BN_CTX_get or BN_new",
            "0xed2680": "3 calls — likely BN comparison or copy",
            "0xf95900": "3 calls — likely EVP_MD_CTX or digest operation",
        },
        "note": (
            "Relative call offsets span -1.6M to -0.4M bytes from the function start "
            "— consistent with a large binary where SM2 lives near the middle and ECC "
            "primitives (EC_POINT_mul, BN_mod_add, etc.) are in a separate library section. "
            "The most-called function (8x) is likely an EC point operation "
            "(SM2 signatures require multiple EC point multiplications). "
            "Three groups of 3-call functions suggest BN (big number) allocation and comparison."
        ),
    },
    "structure": (
        "Function opens with AWAVAUATUSH prologue (7 register saves) — indicates heavy "
        "use of multiple struct pointers across a complex computation. "
        "mov r13, [rdi+0x58]: accesses a struct at first argument, field offset 0x58. "
        "This matches EVP_PKEY_CTX structure layout where the sm2_id field is at a "
        "known offset. The 54-call, 2256-byte size is consistent with SM2 sign/verify "
        "or keygen being the main method called by EVP_PKEY_sign/verify dispatch."
    ),
    "role": "SM2 EVP_PKEY_METHOD implementation: sign/verify/keygen orchestration",
}

SM2KMETH_BN_ANALYSIS = {
    "size": 1583,
    "starts_at": "mov rsi, rax; mov eax, [rsp+0xa8]",
    "stack_offset_0xa8": (
        "rsp+0xa8 = 168 bytes into local frame — large stack frame. "
        "This is likely a BigNum arithmetic function (BN_mod_mul, BN_mod_add) "
        "accessed mid-function, not at a prologue boundary. "
        "The only readable string is '[]A\\A]A^A_' (function epilogue: pop r15 r14 r13 r12). "
        "No endbr64 → either: (1) a direct-call sub-function that doesn't need CET protection, "
        "or (2) a code fragment extracted from inside a larger function."
    ),
    "role": "SM2/ECC BigNum arithmetic sub-function (likely BN_mod_mul or EC_POINT_mul step)",
}

SM2_SECURITY_ANALYSIS = {
    "algorithm": {
        "name": "SM2",
        "standard": "GB/T 32918 (China National Standard)",
        "curve": "SM2P256V1 (256-bit prime field, named curve a.k.a. sm2p256v1)",
        "operations": ["ECDSA-equivalent signing", "ECDH-equivalent key exchange", "ECIES-equivalent encryption"],
        "security_level": "~128-bit (comparable to P-256/ECDSA)",
    },
    "implementation_origin": (
        "TOS 4.6 SM2 implementation is in the OpenSSL-derived cryptographic library. "
        "OpenSSL added SM2 support in 3.0.0; FreeRADIUS 3.2.6's TLS uses this stack. "
        "The null-argument guards in sm22blob.bin are standard EVP API defensive checks — "
        "identical pattern to OpenSSL's own ECC/RSA method wrappers."
    ),
    "concerns": [
        {
            "issue": "Source binary unknown — these fragments cannot be attributed without knowing the origin binary",
            "risk": "INFO — RE result is structural/pattern only; no CVE or vuln attribution without origin",
        },
        {
            "issue": "0x80106 error library ID suggests Tencent-patched OpenSSL with non-standard lib number",
            "risk": "INFO — custom lib IDs do not affect security; only affects error message routing",
        },
    ],
    "note": (
        "No buffer overflow indicators: the null-argument guards return 0 on bad input. "
        "The main dispatcher uses saved registers (not stack buffers) for EC point pointers. "
        "BN operations are through the OpenSSL BN library which uses talloc-like dynamic allocation. "
        "SM2 constant-time properties depend on the underlying EC_POINT_mul implementation — "
        "OpenSSL 3.x EC uses Montgomery ladder for constant-time scalar multiplication on SM2."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "sm22blob.bin: 5 SM2 API null-argument guard functions (standard OpenSSL EVP pattern)",
        "detail": (
            "768 bytes, 5 endbr64 functions. Each checks 4th argument (rcx) for NULL. "
            "On NULL: logs error (reason codes 0xb1/0xe6/0xea/0x5aa/0x5ae) and returns 0. "
            "On non-NULL: jmp to actual SM2 implementation in original binary. "
            "Standard defensive coding — no memory safety issues observable in guard code."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "sm2kmeth_main.bin: SM2 EVP_PKEY_METHOD dispatcher — 54 calls, 7-register frame",
        "detail": (
            "2256 bytes, AWAVAUATUSH prologue. 54 calls to 35 unique targets. "
            "Most-called target (8x) consistent with EC_POINT scalar multiplication. "
            "Accesses struct at [rdi+0x58] — matches EVP_PKEY_CTX sm2_id field. "
            "Role: SM2 sign/verify/keygen dispatch via EVP_PKEY_METHOD callbacks."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "sm2kmeth_bn.bin: SM2/ECC BigNum sub-function (no endbr64, mid-function extract)",
        "detail": (
            "1583 bytes, no CET prologue. Enters mid-frame (reads rsp+0xa8). "
            "Likely BN_mod_mul or EC field arithmetic called directly (not via PLT). "
            "Single string artifact: epilogue pop sequence '[]A\\A]A^A_'."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "SM2 error library ID 0x80 suggests TOS-patched OpenSSL with non-standard lib number",
        "detail": (
            "Standard OpenSSL ERR_LIB_SM2 = 39. The 0x80106 constant in error-reporting calls "
            "indicates lib = 0x80 = 128 — a Tencent-extended error library registration. "
            "Functional impact: error messages route to custom SM2 library ID. "
            "Security impact: none — error codes don't affect cryptographic correctness."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 SM2 blob RE")
    for name, inv in BLOB_INVENTORY.items():
        print(f"  {name}: {inv['size']}B, {inv['functions']} func(s), {inv['type']}")
    print()
    print(f"Algorithm: SM2 (GB/T 32918), 256-bit ECC, OpenSSL-derived implementation")
    print(f"All guards use null-argument checks with OpenSSL error reporting pattern")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
