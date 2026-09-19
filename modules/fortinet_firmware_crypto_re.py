"""
Fortinet FortiOS firmware encryption RE -- complete decryption chain
Sources:
  - firmware-tools/noways-fortigate-crypto/ (getrootfskey.py, decrypt_rootfs.c, chacha20.c)
  - firmware-tools/forticrack_v8/forticrack_v8.py (Bishop Fox FortiCrack v8 port)
  - firmware-tools/fgx/fgx.py (FortiGate Firmware Extraction Toolkit, FortiOS 7.6.x)
  - firmware-tools/forticrack-bishopfox/ (original Bishop Fox FortiCrack)
Products: Fortinet FortiOS (all FortiGate platforms, x86_64 and aarch64)
"""

# ---------------------------------------------------------
# FortiOS firmware encryption architecture
# ---------------------------------------------------------
FIRMWARE_ENCRYPTION_ARCHITECTURE = {
    "overview": (
        "FortiOS firmware images use a two-layer encryption scheme: "
        "(1) Outer layer: XOR block cipher on the .out firmware container. "
        "(2) Inner layer: rootfs.gz encrypted with a stream cipher (ChaCha20 in earlier versions; "
        "modified RC4 in FortiOS 7.6.x). "
        "The rootfs.gz decryption key is a 32-byte seed embedded in the flatkc kernel binary. "
        "The kernel also contains an XOR-encrypted RSA public key used to verify the rootfs.gz signature."
    ),

    "file_format_chain": {
        "firmware.out":    "Gzip-compressed container; inner payload is XOR-encrypted",
        "decrypted.img":   "ext3 filesystem image after Stage 1 decryption",
        "rootfs.gz":       "Encrypted rootfs; inside ext3",
        "flatkc":          "Compressed Linux kernel; inside ext3; contains decryption seed + RSA key",
        "datafs.tar.gz":   "Data filesystem; inside ext3; persistent storage structure",
    },

    "platform_differences": {
        "aarch64": "FortiOS 7.6.x; modified RC4 rootfs cipher; XOR-brute-force seed extraction",
        "x86_64":  "Earlier FortiOS; ChaCha20 rootfs cipher; miasm symbolic exec seed extraction",
        "flatkc":  "Flat kernel image; converted to ELF with vmlinux-to-elf for disassembly",
    },
}


# ---------------------------------------------------------
# FCRYPTO-F01: Stage 1 -- Outer XOR block cipher (known-plaintext attack)
# ---------------------------------------------------------
FCRYPTO_F01_OUTER_XOR = {
    "id":       "FCRYPTO-F01",
    "product":  "Fortinet FortiOS firmware (.out files)",
    "severity": "INFORMATIONAL -- outer cipher breakable via known-plaintext attack",
    "class":    "Weak outer encryption; 32-byte rolling XOR block cipher",
    "source":   "firmware-tools/forticrack_v8/forticrack_v8.py + firmware-tools/fgx/fgx.py",

    "cipher_description": (
        "The outer layer uses a 32-byte rolling XOR cipher applied to 512-byte blocks. "
        "Known-plaintext attack at block offset 48: "
        "  32 null bytes (0x00) at offset 48 within each block. "
        "Key derivation from known plaintext: "
        "  key_byte = previous_ciphertext_byte XOR (known_plaintext + key_offset) XOR ciphertext_byte "
        "  key_offset = (i + 16) mod 32 "
        "After derivation: halves of the 32-byte key are swapped (key[16:] + key[:16]). "
        "The key is an ASCII alphanumeric string (0-9, A-Z, a-z) -- "
        "32 bytes from the set [a-zA-Z0-9], no special chars."
    ),

    "key_validation": (
        "validate_key(): len == 32 AND all bytes are ASCII alphanumeric. "
        "This constraint means the keyspace is (62)^32 -- but the known-plaintext attack "
        "reduces this to a brute-force of individual key bytes."
    ),

    "decryption_algorithm": (
        "decrypt_block(ciphertext, key): "
        "  prev = 0xFF (initial previous byte) "
        "  For each byte i: ko = i mod 32 (key offset) "
        "    plaintext_byte = prev XOR (ciphertext_byte + ko) XOR key[ko] "
        "    prev = plaintext_byte. "
        "Output validated by checking known header magic at the start of the decrypted block."
    ),

    "re_insight": (
        "The outer cipher is weak by design or by mistake: "
        "the use of null plaintext at a fixed offset makes the known-plaintext attack trivial. "
        "Fortinet did not add randomized padding or protect against KPA. "
        "The key is a human-readable ASCII string -- suggests it may be a version-specific constant "
        "or derived from a hardware identifier. "
        "Ablation: run forticrack against available FortiOS .out firmware images to extract keys "
        "and build a key->version mapping."
    ),
}


# ---------------------------------------------------------
# FCRYPTO-F02: Stage 3 -- Kernel seed + RSA key extraction
# ---------------------------------------------------------
FCRYPTO_F02_KERNEL_SEED = {
    "id":       "FCRYPTO-F02",
    "product":  "Fortinet FortiOS kernel (flatkc)",
    "severity": "INFORMATIONAL -- kernel seed extraction enables rootfs decryption",
    "class":    "Firmware crypto material in kernel; extractable via static analysis",
    "source":   "firmware-tools/noways-fortigate-crypto/getrootfskey.py + firmware-tools/fgx/fgx.py",

    "seed_structure": {
        "size":     "32 bytes",
        "location": "Embedded in flatkc at a known virtual address; found via symbolic execution",
        "use":      "Input to key derivation for rootfs.gz decryption",
    },

    "extraction_method_aarch64": (
        "XOR brute-force search (fgx Stage 3 Method 1): "
        "Scan the entire kernel ELF for a 32-byte seed followed by a 270-byte XOR-encrypted RSA DER. "
        "RSA DER validation: first two decrypted bytes must be 0x30 0x82 (DER SEQUENCE marker). "
        "Decryption test: seed XOR repeated over the 270-byte RSA blob. "
        "This works because the RSA DER has a known structure and the XOR key is the seed itself."
    ),

    "extraction_method_x86_64": (
        "Miasm symbolic execution (fgx Stage 3 Method 2 + noways-fortigate-crypto getrootfskey.py): "
        "1. Locate fgt_verifier_pub_key / fgt_verify_initrd / fgt_verify_decrypt symbol via objdump. "
        "2. Disassemble the function with Miasm. "
        "3. Find sha256_update() call sites; extract argument (RSI) value at each call. "
        "4. The seed address is the minimum RSI value seen across sha256_update calls. "
        "5. Read 32 bytes from the binary at seed_address -> seed. "
        "The function uses ChaCha20 to decrypt the RSA key: "
        "  ChaCha20(key=sha256(seed[4:32]+seed[0:4]), nonce=sha256(seed[5:32]+seed[0:5])[4:])."
    ),

    "rsa_public_key": {
        "size":   "270-byte DER-encoded RSA public key",
        "use":    "Verifies PKCS#1v15 signature on rootfs.gz trailing 256 bytes",
        "note":   "XOR-encrypted with the 32-byte seed using repeating XOR (not ChaCha20)",
    },

    "noways_key_derivation": (
        "decrypt_rootfs.c (noways-fortigate-crypto): "
        "md1 = SHA-256(seed[4:32] + seed[0:4]) -- ChaCha20 key "
        "md2 = SHA-256(seed[5:32] + seed[0:5]) -- ChaCha20 nonce/IV. "
        "chacha20_init_context(ctx, md1, md2); chacha20_xor(ctx, rootfs_data, size). "
        "This uses a CUSTOM ChaCha20 variant (chacha20.c implements it from scratch). "
        "The nonce rotation: seed bytes rotated by 4 bytes for key, 5 bytes for nonce -- "
        "a custom key schedule, not standard ChaCha20 usage."
    ),
}


# ---------------------------------------------------------
# FCRYPTO-F03: Stage 4 -- Modified RC4 rootfs.gz decryption (FortiOS 7.6.x)
# ---------------------------------------------------------
FCRYPTO_F03_MODIFIED_RC4 = {
    "id":       "FCRYPTO-F03",
    "product":  "Fortinet FortiOS 7.6.x rootfs.gz",
    "severity": "INFORMATIONAL -- non-standard RC4 variant; weaker than AES but requires firmware-specific seed",
    "class":    "Custom stream cipher (modified RC4 with cross-rotated S-box and XOR constant 0xAA)",
    "source":   "firmware-tools/fgx/fgx.py (modified_rc4 function)",

    "cipher_implementation": {
        "ksa": "Standard RC4 KSA: S = 0..255; swap S[i] and S[j] where j = (j + S[i] + key[i & 0x1F]) & 0xFF",
        "prga": "MODIFIED -- cross-rotated S-box indices + multi-lookup output with XOR 0xAA",
        "key_size": "32 bytes (seed from kernel, Stage 3 output)",
    },

    "modified_prga_details": (
        "For each output byte at position pos: "
        "  i_val = (i_val + 1) & 0xFF "
        "  i_lo = (i_val & 0x1F) << 3; i_hi = (i_val >> 5) & 0x7 "
        "  j_val = (j_val + S[i_val]) & 0xFF "
        "  j_lo = (j_val & 0x1F) << 3; j_hi = (j_val >> 5) & 0x7 "
        "  i_rot = (i_lo | j_hi) & 0xFF  -- cross: i bits with j high bits "
        "  j_rot = (j_lo | i_hi) & 0xFF  -- cross: j bits with i high bits "
        "  t = (S[i_val] + S[j_val]) & 0xFF "
        "  u = (S[j_val] + j_val) & 0xFF "
        "  v1 = ((S[i_rot] + S[j_rot]) XOR 0xFFFFFFAA) & 0xFF  -- 0xAA constant "
        "  v2 = ((S[v1] + S[t]) XOR S[u] XOR ciphertext_byte) & 0xFF  -- output byte. "
        "The cross-rotation of indices (i bits mixed with j bits) creates non-linear feedback "
        "not present in standard RC4 -- better diffusion, harder to distinguish from random."
    ),

    "keep_j_variant": (
        "Some kernel builds compiled with different optimization do not reset j after KSA. "
        "PRGA starts with j from KSA's final value rather than j=0. "
        "fgx handles this with keep_j parameter and tries both variants."
    ),

    "cipher_mode_detection": {
        "FortiOS_7.4.x-earlier": "ChaCha20 (noways-fortigate-crypto approach; sha256 key derivation)",
        "FortiOS_7.6.x":         "Modified RC4 (fgx approach; standard KSA + modified PRGA)",
    },

    "re_insight": (
        "The shift from ChaCha20 to modified RC4 in FortiOS 7.6.x is unusual -- "
        "RC4 is generally considered weaker than ChaCha20. "
        "The 'modification' (cross-rotated indices + XOR 0xAA) may be Fortinet's attempt "
        "to produce a distinct cipher from standard RC4 while remaining fast. "
        "The 32-byte key from the kernel seed provides sufficient security IF the seed is secret -- "
        "but fgx demonstrates the seed is extractable from the kernel binary. "
        "Ablation: implement modified_rc4 in the ablation test suite and validate against "
        "a known FortiOS 7.6.x rootfs.gz; confirm decryption yields a valid GZ magic (0x8B1F)."
    ),
}


# ---------------------------------------------------------
# FCRYPTO-F04: FortiOS 7.6.x firmware layer crypto summary table
# ---------------------------------------------------------
FCRYPTO_F04_CRYPTO_SUMMARY = {
    "id":       "FCRYPTO-F04",
    "product":  "Fortinet FortiOS 7.6.x firmware",
    "severity": "INFORMATIONAL -- complete crypto chain documented",

    "layer_table": {
        "Layer 1 (outer firmware.out)": {
            "cipher":        "Rolling XOR, 32-byte key, 512-byte blocks",
            "key":           "ASCII alphanumeric 32-byte string (version-specific)",
            "key_recovery":  "Known-plaintext attack on null bytes at offset 48 per block",
            "tool":          "forticrack_v8.py, fgx Stage 1",
        },
        "Layer 2 (inner ext3 fs)": {
            "cipher":        "None (plaintext ext3 after Stage 1)",
            "tool":          "binwalk / manual ext3 mount",
        },
        "Layer 3 (flatkc kernel seed)": {
            "cipher":        "XOR (aarch64) or ChaCha20 (x86_64) encrypted RSA key in kernel",
            "key_recovery":  "XOR brute-force (aarch64) or miasm symbolic execution (x86_64)",
            "tool":          "fgx Stage 3, getrootfskey.py",
            "output":        "32-byte seed + RSA-2048 public key",
        },
        "Layer 4 (rootfs.gz)": {
            "cipher_7_6_x":  "Modified RC4 (cross-rotated PRGA, XOR 0xAA constant)",
            "cipher_earlier": "ChaCha20 (SHA-256 key derivation with 4/5-byte seed rotation)",
            "key":           "32-byte seed from Layer 3",
            "signature":     "PKCS#1v15 RSA-2048 trailing 256 bytes; verified with RSA public key from Layer 3",
            "tool":          "fgx Stage 4 (modified_rc4), decrypt_rootfs.c (ChaCha20)",
        },
    },

    "forticrack_v8_specifics": {
        "target_kernel": "FortiOS 8.0.0 build 0167 (kernel 4.19.13, same for FGT and FFW)",
        "hardcoded_segments": [
            "(0xffffffff80200000, 0x200000, 0x12fa000)",
            "(0xffffffff81600000, 0x1600000, 0xe5000)",
            "(0x0000000000000000, 0x1800000, 0x29000)",
            "(0xffffffff8170e000, 0x190e000, 0x12e000)",
        ],
        "rsa_enc_va":    "0xffffffff8179a1a0 (270 bytes DER, XOR-encoded with XOR_KEY_VA)",
        "xor_key_va":    "0xffffffff8179a2c0 (32-byte XOR key)",
        "note":          "These addresses are hardcoded for kernel 4.19.13 v8.0.0 build 0167 -- different firmware versions require re-extraction",
    },
}


# ---------------------------------------------------------
# Cross-layer analysis
# ---------------------------------------------------------
FORTIOS_FIRMWARE_SYSTEMIC = {
    "id":       "FCRYPTO-SYSTEMIC",
    "product":  "Fortinet FortiOS firmware (all versions)",
    "severity": "HIGH -- all encryption layers are breakable given access to the firmware binary",
    "class":    "Defense in depth failure: all encryption layers recoverable from the same binary",

    "pattern": (
        "The FortiOS firmware encryption scheme is self-contained: "
        "all cryptographic material needed to decrypt the firmware is present in the firmware binary itself. "
        "Layer 1 key: recoverable via KPA on the firmware .out file (no external secret). "
        "Layer 3 seed: embedded in the flatkc kernel (inside Layer 1 + Layer 2). "
        "Layer 4 key: derived from Layer 3 seed (inside Layer 3). "
        "The RSA public key only verifies the signature -- it does not prevent decryption. "
        "Implication: any attacker with a FortiOS .out firmware image can decrypt the rootfs "
        "and access all FortiOS binaries, including sslvpnd, httpsd, authd, and cmdbsrv "
        "which contain the hardcoded credentials, session handling, and hash implementations."
    ),

    "missing_security_property": (
        "Secure firmware encryption requires a hardware-bound secret not present in the binary. "
        "FortiOS's scheme uses an in-binary seed -- no TPM, no HSM, no device-unique secret. "
        "The seed is the same for all firmware images of the same version. "
        "This means firmware downloaded by any party is decryptable by anyone with the tools."
    ),

    "ablation_targets": [
        "sslvpnd: SSL VPN daemon; CVE-2024-21762 / CVE-2022-42475 overflow targets",
        "httpsd: Web admin + API daemon; CVE-2022-40684 auth bypass target",
        "authd: Authentication daemon; COATHANGER replacement target",
        "cmdbsrv: Config database daemon; BOLDMOVE direct read target",
        "sshd: SSH daemon; CVE-2016-1909 backdoor target",
        "miglogd: Log daemon; BOLDMOVE suppression target",
    ],
}


# =============================================================
# Universal OVF/qcow2 P1 plaintext architecture survey
# Date: 2026-09-18
# Tested: FGT 8.0.0, FFW 8.0.0, FMG 8.0.0, FAZ 8.0.0
# =============================================================

FORTINET_P1_ARCHITECTURE_SURVEY = {
    "id":        "FW-ARCH-01",
    "product":   "Fortinet firmware -- all VM variants",
    "severity":  "INFORMATIONAL -- architecture disclosure",
    "class":     "Plaintext Application Archive in VM Firmware -- product family split",

    "summary": (
        "All Fortinet VM firmware images follow one of two P1 partition architectures. "
        "The split correlates with product family (FortiOS-based vs FAZ/FMG-based). "
        "Both families have encrypted rootfs.gz (fortism LSM, entropy 7.997). "
        "The application layer exposure varies by family."
    ),

    "family_a_fortigate_based": {
        "products":       ["FortiGate", "FortiFirewall"],
        "versions_tested": ["FortiGate 8.0.0 VM64-KVM", "FortiFirewall 8.0.0 VM64-KVM"],
        "p1_label":        "FORTIOS (ext3, SYSLINUX/EXTLINUX boot)",
        "encrypted":       "rootfs.gz (entropy 7.997, non-gzip header, fortism LSM hook)",
        "plaintext":       "datafs.tar.gz -- ~20MB gzip archive",
        "datafs_contents": [
            "etc/fgt2.key (2048-bit RSA shared device key -- all devices same key)",
            "etc/fgt_512.key (512-bit RSA, signs PKCS7 .x integrity files -- trivially factorable)",
            "etc/fgt_512.crt (leaf cert, issued by fortinet-subca2003)",
            "etc/fortism_config.json (~211KB -- full fortism LSM MAC policy in JSONC)",
            "lib/libips.so.new (18.5MB ELF shared lib -- IPS engine, 335 dynamic syms)",
            "lib/libav.so.new (15.7MB ELF shared lib -- AV engine)",
            "etc/wad_ips.rules, ips/ips.rules (549KB plaintext IPS rules)",
            "etc/system.conf.def (29KB default system configuration)",
            "etc/ssh/moduli (592KB SSH DH moduli)",
        ],
        "os_layer_access": "BLOCKED (rootfs.gz encrypted; requires fortism kernel hook intercept)",
    },

    "family_b_faz_fmg_based": {
        "products":        ["FortiAnalyzer", "FortiManager"],
        "versions_tested": ["FortiAnalyzer 8.0.0 VM64-KVM", "FortiManager 8.0.0 VM64-KVM"],
        "p1_label":        "FORTI_BOOT_DEV (ext3)",
        "encrypted":       "rootfs.gz (entropy 7.997) + syntax.tar.xz (entropy 7.997)",
        "plaintext":       "rootfs-ext.tar.xz -- 236MB compressed, ~1.36GB uncompressed",
        "rootfs_ext_contents": [
            "usr/local/python/ -- full Python application source",
            "usr/local/python/sql_rewriter/ -- Flask JSON-RPC SQL rewriting service",
            "usr/local/python/sql-validator/ -- SQL parser",
            "usr/local/builtin_connectors/ -- SOAR connector pack (tar.gz inside XZ)",
            "builtin_connectors: AD, EMS, FOS, VSPHERE, FMQ, LOCALHOST, FEDR, FSA, FML, etc.",
        ],
        "os_layer_access": "BLOCKED but IRRELEVANT -- full application layer in plaintext",
    },

    "shared_key_confirmation": (
        "fgt2.key modulus prefix A75C115F690B67C32834D43FE1BD50DB301CE34F6A96... "
        "confirmed identical across FGT 7.4.12, FGT 8.0.0, FFW 8.0.0 (separate qcow2 images). "
        "Key is universal across FortiOS product family. See FGT-F27 for full scope."
    ),
}


# ===================================================================
# FortiAuthenticator architecture note (universality sweep result)
# Date: 2026-09-18
# ===================================================================

FAC_ARCHITECTURE = {
    "product":   "FortiAuthenticator-VM",
    "versions_tested": [
        "FAC_VM_KVM-v6-build1355 (July 2023, 99MB rootfs.gz, 4MB flatkc)",
        "FAC_VM-v8-build0099-FORTINET.out.ovf (April 2026, 132MB rootfs.gz, 6.1MB flatkc)",
    ],
    "family":    "FortiOS (A), minimal variant -- NO plaintext data archive",
    "p1_format": "ext2/ext3, SYSLINUX/EXTLINUX boot, 3-partition layout",
    "p1_files":  [
        "flatkc (4-6MB, compressed bzImage kernel)",
        "rootfs.gz (~100-132MB, encrypted -- non-gzip header, fortism LSM)",
        "*.sign files (512B PKCS7 detached sigs for each file)",
        "extlinux.conf (bootloader config, root=/dev/ram0, ramdisk_size=600000)",
    ],
    "p2_p3_format": "Uninitialized (all zeros, pre-provisioned for runtime use)",
    "plaintext_attack_surface": "NONE -- no datafs.tar.gz, no rootfs-ext.tar.xz",
    "encrypted_rootfs_entropy": "7.571 (KVM v6), 7.571 (OVF v8) -- encrypted",
    "notes": (
        "FortiAuthenticator uses the FortiOS boot chain (flatkc + fortism LSM) "
        "but does NOT include the datafs.tar.gz plaintext archive present in FGT/FFW. "
        "This means the shared private key attack (FGT-F27) does NOT apply here. "
        "rootfs.gz decryption still requires the QEMU GDB approach targeting fortism LSM hook. "
        "LDAP-related authentication logic likely inside encrypted rootfs."
    ),
}

FAC_UNIVERSALITY_RESULT = {
    "finding":   "FAC has no plaintext application layer -- least attack surface of all VM products",
    "implication": "FortiOS family without datafs.tar.gz = most protected VM image format Fortinet ships",
}
