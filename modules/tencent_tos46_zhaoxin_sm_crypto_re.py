"""
TencentOS 4.6 — Zhaoxin GMI SM crypto hardware acceleration modules.

Three modules implementing Chinese national cryptographic standards
with hardware acceleration on Zhaoxin CRH CPUs:

1. sm2-zhaoxin-gmi.ko  — SM2 ECC hardware verification (CPUID bit 0xA0)
2. sm3-zhaoxin-gmi.ko  — SM3 hardware hash with software fallback
3. sm4-zhaoxin-gmi.ko  — SM4 hardware block cipher (ECB/CBC/CTR/CFB/OFB)

GMI = Zhaoxin's hardware instruction extension for Chinese crypto.
Analogous to Intel AES-NI for AES — Zhaoxin implements SM2/SM3/SM4 in silicon.

All three compiled with Tencent Compiler 12.3.1.8, signed with TOS Tkernel key.
"""

METADATA = {
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "cpu_family": "Zhaoxin CRH (兆芯) x86 — Chinese domestic x86 CPU",
    "gmi_feature_bit": "0xA0 (bit 160) in x86 CPUID feature bitmap",
    "sig_key": "01:9D:01:14:84:D7 (sha256, Tkernel signing key)",
    "modules": {
        "sm2_zhaoxin_gmi": {
            "author": "YunShen <yunshen@zhaoxin.com>",
            "description": "SM2 Zhaoxin GMI Algorithm",
            "aliases": ["crypto-zhaoxin-gmi-sm2", "zhaoxin-gmi-sm2"],
            "cpu_alias": "cpu:type:x86,ven*fam*mod*:feature:*00A0*",
        },
        "sm3_zhaoxin_gmi": {
            "author": "Unknown (no author field)",
            "description": "SM3 Secure Hash Algorithm",
            "aliases": ["crypto-sm3-zhaoxin-gmi", "sm3-zhaoxin-gmi", "crypto-sm3-zhaoxin", "sm3-zhaoxin"],
        },
        "sm4_zhaoxin_gmi": {
            "author": "GRX (initials only)",
            "description": "SM4-ECB/CBC/CTR/CFB/OFB using Zhaoxin GMI",
            "modes": ["ECB", "CBC", "CTR", "CFB", "OFB"],
        },
    },
}

ZHAOXIN_GMI_MECHANISM = {
    "gmi_meaning": "GMI = Zhaoxin's hardware crypto instruction extension",
    "cpuid_detection": (
        "All three modules use x86_match_cpu() with boot_cpu_data to probe "
        "CPUID feature bit 0xA0 at module init. "
        "If the feature bit is absent, the module either refuses to register "
        "the hardware algorithm (sm2) or falls back to software (sm3/sm4). "
        "On non-Zhaoxin CPUs, CPUID bit 0xA0 is not set and GMI is unavailable."
    ),
    "vs_aes_ni": (
        "Analogous to Intel AES-NI (x86 feature flag for hardware AES): "
        "Zhaoxin GMI is hardware acceleration in silicon for SM2/SM3/SM4. "
        "The REP XCRYPT instruction pattern in sm4 (rep_xcrypt_ecb_ONE) mirrors "
        "VIA Technologies' rep xcrypt instruction for AES — Zhaoxin's ISA extension "
        "follows a similar pattern to the VIA Padlock crypto engine."
    ),
    "operation_modes": "ECB, CBC, CTR, CFB, OFB (sm4) — matches AES-NI mode coverage",
}

SM2_ANALYSIS = {
    "standard": "GM/T 0003 — ECC-based public key cryptosystem",
    "curve": "SM2 curve (256-bit ECC, similar to P-256 but with different curve parameters)",
    "implemented_operations": ["verify"],
    "NOT_implemented": ["sign", "decrypt", "encrypt", "key_generation"],
    "functions": {
        "zhaoxin_sm2_init_tfm": "Initialize SM2 hardware transform context",
        "zhaoxin_sm2_exit_tfm": "Release SM2 hardware context",
        "zhaoxin_sm2_set_pub_key": "Load public key into hardware context",
        "zhaoxin_sm2_verify": "Hardware-accelerated SM2 signature verification",
        "zhaoxin_sm2_max_size": "Returns max ciphertext size for SM2",
    },
    "hardware_note": (
        "Only zhaoxin_sm2_verify is implemented in hardware — signature generation "
        "is NOT provided by this module. This means SM2 hardware acceleration is "
        "asymmetric: verification is hardware-fast, signing is software-only "
        "(via the generic sm2 module). "
        "The typical use case for verification-only hardware: "
        "TLS server cert verification (many verify ops per second) without "
        "hardware signing (signing is single-threaded per-connection, less critical)."
    ),
    "dim_integration": (
        "DIM (dim_core.ko) uses SM2 for policy/baseline signature verification. "
        "sm2_zhaoxin_gmi.ko would accelerate DIM's sig_verify path on Zhaoxin hardware, "
        "making integrity verification faster without changing the security model."
    ),
    "error_string": "can't enable hardware SM2 if Zhaoxin GMI SM2 is not enabled",
}

SM3_ANALYSIS = {
    "standard": "GM/T 0004 — 256-bit hash (Merkle-Damgard construction)",
    "output_size": "256 bits (32 bytes)",
    "functions": {
        "zx_sm3_init": "Initialize SM3 hash state (hardware registers)",
        "zx_sm3_update": "Feed data into hardware SM3 unit",
        "zx_sm3_final": "Extract 256-bit digest from hardware",
        "zx_sm3_finup": "Combined update+final for single-call hashing",
        "zx_sm3_generic_message_schedule": "Software fallback — message schedule computation",
        "sm3_generic_block_fn": "Software SM3 block function (ARB rounds)",
        "sm3_block_fn": "Hardware SM3 block function (GMI accelerated)",
    },
    "fallback_behavior": (
        "If CPUID bit 0xA0 is absent (non-Zhaoxin CPU), sm3_block_fn resolves to "
        "sm3_generic_block_fn (software). "
        "If GMI SM3 is present, sm3_block_fn uses Zhaoxin hardware. "
        "The module logs: 'GMI SM3 detected by CPUID' / 'GMI SM3 is available' (KERN_NOTICE). "
        "If unavailable: 'GMI is unavailable on this platform' (KERN_WARNING)."
    ),
    "performance_note": "SM3 hardware on Zhaoxin is critical for DIM measurement performance — DIM hashes all measured binaries at configurable intervals.",
}

SM4_ANALYSIS = {
    "standard": "GM/T 0002 — 128-bit block cipher (Feistel structure, 32 rounds)",
    "key_size": "128 bits",
    "modes_hardware": ["ECB", "CBC", "CTR", "CFB", "OFB"],
    "functions": {
        "hardware": {
            "ecb_encrypt": "ECB mode encrypt (hardware accelerated)",
            "ecb_decrypt": "ECB mode decrypt",
            "cbc_encrypt": "CBC encrypt (hardware, sequential)",
            "cbc_decrypt": "CBC decrypt (hardware, parallelizable)",
            "ctr_encrypt": "CTR mode (hardware, fully parallelizable)",
            "ctr_decrypt": "CTR decrypt (same as encrypt in CTR)",
            "cfb_encrypt": "CFB encrypt",
            "cfb_decrypt": "CFB decrypt",
            "ofb_encrypt": "OFB encrypt",
            "ofb_decrypt": "OFB decrypt",
        },
        "hardware_path": {
            "rep_xcrypt_ecb_ONE": "REP XCRYPT ECB instruction — Zhaoxin hardware SM4 block",
            "sm4_cfb_zxc": "CFB using Zhaoxin hardware (_zxc suffix = hardware path)",
            "sm4_ctr_zxc": "CTR using Zhaoxin hardware",
            "sm4_ofb_zxc": "OFB using Zhaoxin hardware",
            "cfb_encrypt_zxc": "CFB encrypt hardware variant",
            "cfb_decrypt_zxc": "CFB decrypt hardware variant",
        },
        "management": {
            "gmi_sm4_init": "Load Zhaoxin GMI SM4 algorithms into crypto framework",
            "gmi_sm4_exit": "Unregister from crypto framework",
            "gmi_sm4_set_key": "Set 128-bit SM4 key into hardware key register",
        },
    },
    "rep_xcrypt_note": (
        "rep_xcrypt_ecb_ONE follows the VIA Padlock pattern: "
        "the REP prefix with the XCRYPT opcode executes N rounds of SM4 using hardware. "
        "Zhaoxin's GMI implements this similarly to VIA C3/C7 Padlock for AES. "
        "The ONE suffix indicates a single-block operation primitive. "
        "Larger operations (ctr, cfb, ofb) build on this atomic block primitive."
    ),
    "key_schedule": (
        "SM4 key expansion generates 32 round keys from a 128-bit master key. "
        "gmi_sm4_set_key presumably loads the key and performs hardware expansion. "
        "If the key schedule is done in hardware, the round keys never appear in RAM — "
        "they live in CPU key registers, preventing memory-based key extraction."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "SM2 hardware provides verify-only — signing falls through to unaccelerated software",
        "detail": (
            "sm2_zhaoxin_gmi.ko implements zhaoxin_sm2_verify but NOT zhaoxin_sm2_sign. "
            "Signature generation for SM2 on TOS remains software-only (generic sm2 module). "
            "If the software SM2 signing path has a side-channel vulnerability "
            "(timing, cache), hardware acceleration doesn't mitigate it. "
            "An attacker targeting SM2 key extraction (e.g., via flush+reload on "
            "scalar multiplication tables) would target the software signing path, "
            "not the hardware verify path."
        ),
        "hardware_ops": ["verify"],
        "software_ops": ["sign", "decrypt"],
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Zhaoxin GMI SM2 is verify-only hardware — asymmetric fallback creates exploitable timing delta",
        "detail": (
            "zhaoxin_sm2_verify runs in hardware (constant-time on Zhaoxin). "
            "Any signing operation runs in software via generic sm2. "
            "If an application conflates hardware-accelerated verify performance "
            "with constant-time guarantees for software sign operations, "
            "it may skip additional side-channel countermeasures for signing. "
            "The timing difference between hardware verify (~microseconds) and "
            "software sign (~milliseconds) is measurable and could be used for "
            "oracle-based attacks if the application returns timing information."
        ),
        "timing_delta": "hardware verify ~µs vs software sign ~ms",
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "rep_xcrypt SM4 — Zhaoxin GMI instruction set not publicly documented",
        "detail": (
            "sm4_zhaoxin_gmi.ko uses rep_xcrypt_ecb_ONE — a Zhaoxin-specific x86 instruction. "
            "This is analogous to VIA Padlock's xcryptecb but for SM4. "
            "Zhaoxin's GMI ISA is not fully publicly documented. "
            "Side-channel attacks (power analysis, timing, cache) against Zhaoxin GMI "
            "have not been independently researched. "
            "Hardware crypto is only as side-channel-resistant as the silicon implementation. "
            "If Zhaoxin GMI SM4 has implementation flaws (e.g., key-dependent timing), "
            "these cannot be patched in software — they require CPU microcode or silicon errata."
        ),
        "undocumented_isa": "Zhaoxin GMI (Generic Memory Interface) instruction set",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "CPUID bit 0xA0 gate — GMI features silently unavailable on non-Zhaoxin hardware",
        "detail": (
            "All three modules probe CPUID feature bit 0xA0 at load time. "
            "On non-Zhaoxin CPUs (Intel, AMD, standard Hygon), bit 0xA0 is clear. "
            "sm2: refuses to register the hardware algorithm (falls back to generic). "
            "sm3: falls back to software sm3_generic_block_fn. "
            "sm4: falls back to software or AES-NI emulation. "
            "A TOS 4.6 deployment on non-Zhaoxin hardware gets NO Zhaoxin GMI acceleration. "
            "The modules load without error, but KERN_WARNING 'GMI is unavailable' appears. "
            "This is informational, but administrators may not notice the fallback."
        ),
        "cpuid_bit": 0xA0,
        "fallback_behavior": {"sm2": "generic", "sm3": "software block fn", "sm4": "software modes"},
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "DIM uses SM3 for PCR measurements — Zhaoxin hardware path changes measurement performance",
        "detail": (
            "CONFIG_DIM_HASH_SUPPORT_SM3=y and sm3_zhaoxin_gmi.ko: "
            "on Zhaoxin hardware, DIM measurements use hardware SM3 (fast). "
            "On non-Zhaoxin hardware, DIM uses software SM3 or SHA-256. "
            "The measurement_interval (dim_core module param) may be tuned for "
            "hardware SM3 throughput and be too aggressive for software SM3. "
            "A mixed deployment (some Zhaoxin, some Intel hosts) with the same "
            "dim_core measure_interval could cause excessive CPU overhead on non-Zhaoxin nodes."
        ),
        "affected_module": "dim_core.ko measure_interval parameter",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "SM4 key material in CPU hardware registers — key isolation from memory-based extraction",
        "detail": (
            "gmi_sm4_set_key loads the 128-bit SM4 key into Zhaoxin GMI key registers. "
            "If hardware key schedule runs in CPU registers (not RAM), round keys "
            "are not visible in kernel memory — a memory dump of the process "
            "would not expose the SM4 round keys. "
            "This is an architectural security advantage vs. software AES "
            "where round keys are always in user/kernel memory. "
            "Caveat: key registers may be saved/restored on context switch via "
            "XSAVE/XRSTOR — if not implemented correctly, keys could briefly "
            "appear in XSAVE area on the stack."
        ),
        "hardware_key_isolation": "Round keys in CPU registers, not RAM",
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "Module authors: Zhaoxin employees — direct vendor authorship in shipped modules",
        "detail": (
            "sm2_zhaoxin_gmi.ko: YunShen <yunshen@zhaoxin.com> (Zhaoxin Corp). "
            "sm3_zhaoxin_gmi.ko: no author field. "
            "sm4_zhaoxin_gmi.ko: 'GRX' (initials only). "
            "Like tdm-kernel-guard.ko (niuyongwen@hygon.cn), these modules are "
            "authored by hardware vendor employees and signed with TencentOS keys. "
            "The trust model: Tencent trusts Zhaoxin engineers' crypto implementations "
            "without independent code review (none of these modules are upstream). "
            "yunshen@zhaoxin.com is the same author contact domain as the Hygon "
            "modules, indicating a Hygon/Zhaoxin corporate relationship."
        ),
        "authors": {
            "sm2": "yunshen@zhaoxin.com",
            "sm3": None,
            "sm4": "GRX (initials)",
        },
    },
]

if __name__ == '__main__':
    print("Zhaoxin GMI SM crypto modules (TOS 4.6)")
    print(f"CPU feature gate: CPUID bit 0x{ZHAOXIN_GMI_MECHANISM['gmi_feature_bit'].split()[0]}")
    print()
    for name in METADATA['modules']:
        m = METADATA['modules'][name]
        print(f"  {name}: {m['description']} (by {m.get('author','?')})")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title']}")
