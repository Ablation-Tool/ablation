"""
Fortinet Proprietary Hardware Firmware Container RE
Target: .out files for physical appliances (FGT 100F/200F/1500D, FAZ 200D, FAC, FortiLog)
Method: BERT semantic family clustering (Ablation methodology) + structural XOR analysis

Container format: gzip outer (FNAME field = product/version) -> encrypted inner payload
Inner payload magic byte families identified across 10 firmware files:
  0xa094a291 (big-endian) -> FLG 100D v6.0.x, FAZ 7.0.x (older FortiAnalyzer)
  0xd796a291 (big-endian) -> FAZ 200D, FAC 200E (newer FortiAnalyzer/FortiAuthenticator)
  0xf3bede9e (big-endian) -> FGT 1000C / FGT 1500D (high-end x86-64 physical)
  0x82ceae9c (big-endian) -> FGT 100F / FortiWiFi 100F (mid-range)
  0xb2fba99a (big-endian) -> FGT 200F (mid-range, separate magic from 100F)

Access: KVM images are encrypted (rootfs.gz, magic 0x654accb2 in FGT 7.4.12).
Physical appliance .out files are encrypted with a separate scheme (above magic families).
FortiGate 7.0.9 KVM image (CPIO rootfs, unencrypted) was accessible in a prior session
but is no longer on local disk (source: Google Drive, account suspended).
"""


# ---------------------------------------------------------
# Hardware firmware container: structural analysis
# ---------------------------------------------------------
HARDWARE_CONTAINER_FORMAT = {
    "outer_wrapper": {
        "format":     "gzip",
        "magic":      "1f 8b",
        "fname_field": "present (OS=0xFF, gzip Unix extension)",
        "fname_examples": [
            "FGT1500D-v7.0.5-build0304.out  (FGT 1500D v7.0.5)",
            "FGT100F-v7.0.2-build0234.out   (FGT 100F v7.0.2)",
            "FAZ200D-v7.0.x.out             (FAZ 200D)",
        ],
        "note": "FNAME encodes product and version; decompresses to inner binary",
    },

    "inner_binary": {
        "format":         "Fortinet proprietary encrypted container",
        "magic_families": {
            "family_A": {
                "bytes":    "a0 94 a2 91",
                "products": ["FLG-100D v6.0.x", "FAZ 7.0.x"],
                "era":      "older FortiAnalyzer / FortiLog",
            },
            "family_B": {
                "bytes":    "d7 96 a2 91",
                "products": ["FAZ-200D", "FAC-200E"],
                "era":      "newer FortiAnalyzer / FortiAuthenticator",
            },
            "family_C": {
                "bytes":    "f3 be de 9e",
                "products": ["FGT-1000C", "FGT-1500D"],
                "era":      "high-end x86-64 FortiGate physical",
                "storage_as_le": "9e de be f3 (bytes on disk, little-endian view)",
                "decompressed_size": "256MB for FGT_1500D v6.4.x",
            },
            "family_D": {
                "bytes":    "82 ce ae 9c",
                "products": ["FGT-100F", "FortiWiFi-100F"],
                "era":      "mid-range FortiGate",
            },
            "family_E": {
                "bytes":    "b2 fb a9 9a",
                "products": ["FGT-200F"],
                "era":      "mid-range FortiGate (separate from 100F)",
            },
        },
            "encryption_note": (
            "FGT 1500D family_C: 8-version cross-analysis (v6.0.6, v6.2.2, v6.2.4, v6.4.3, "
            "v6.4.5, v6.4.6, v6.4.7, v7.0.5). Inner binary = 0x10000200 bytes exactly "
            "(256MB + 512 = 268435968). "
            "STRUCTURE CONFIRMED (see FHWC_INNER_BINARY_STRUCTURE): "
            "  Bytes 0-511:   512-byte header (outer container metadata + version auth). "
            "  Bytes 512+:    256MB payload = raw NAND flash image encrypted with period-64 XOR. "
            "KEYSTREAM RECOVERED (see FHWC_KEYSTREAM): "
            "  64-byte keystream extracted from zero-plaintext (empty flash) regions. "
            "  Verified via descending NAND test pattern at payload_off=265216 ('ff fe fd fc...'). "
            "SECONDARY ENCRYPTION CONFIRMED (see FHWC-F10): "
            "  Firmware partitions within payload have entropy 7.997 bits/byte after XOR decryption. "
            "  99% byte-level variation between v6.0.6 and v7.0.5. "
            "  No recognizable filesystem/compression magic in any partition post-XOR. "
            "  Key material for secondary encryption is in the 512-byte header (encrypted)."
        ),
    },

    "cleartext_header": {
        "finding":       "CONFIRMED for FGT 1500D family (8-version cross analysis)",
        "method":        "XOR key-cancellation: XOR same-product different-version inner binaries",
        "invariant_region": {
            "bytes":     "0-35",
            "content":   "ALL ZERO in XOR output -- bytes 0-35 identical across ALL 8 versions (v6.0.6-v7.0.5)",
            "cleartext_hex": "9edebef3b4d2bfdcb1fdc4add298646857373526041662634838181d497058899db6ba93",
            "structure": (
                "0x00-0x03: magic (9e de be f3 = family_C). "
                "0x04-0x0b: unknown 8 bytes (possibly size or CRC). "
                "0x0c-0x0f: 0x686498d2 LE (possible timestamp: ~1751613394 = 2025-07-04? "
                "  more likely CRC32 or product code). "
                "0x10-0x17: 0x2635375704166263 -- version-invariant, unknown semantics. "
                "0x18-0x1f: 0x48381818d49705889 -- unknown. "
                "0x20-0x23: 0x9db6ba93 -- unknown. "
                "NOTE: bytes 22-35 partially vary between major version families "
                "(v6.x vs v7.x show small diffs at bytes 23, 26). "
                "Strict invariant zone confirmed only to byte 21 for all 8 versions."
            ),
        },
        "transition_zone": {
            "bytes":  "36-47",
            "content": "Complex per-version variation -- NOT a simple single-byte XOR. "
                       "Multiple bytes change with different magnitudes per version pair. "
                       "Likely encodes: version nonce, build-specific nonce, or IV for header cipher.",
            "xor_diffs": {
                "v6.4.7_vs_v6.4.6": "bytes 36-47: 00030971717171747409XX",
                "v6.4.7_vs_v6.4.3": "bytes 36-47: 0002080f0f0f0e0971710d",
                "v6.4.7_vs_v6.0.6": "bytes 36-47: 050c0607XX06 7e7e797f7f",
            },
            "note": "First diff at byte 36 (v6.0.6 vs v6.4.7). Byte 36-47 NOT covered by the "
                    "single-byte XOR in zone 1 (bytes 48-295).",
        },
        "header_zone_1": {
            "bytes":    "48-295",
            "content":  "Single-byte XOR encrypted zone (248 bytes, version-specific key)",
            "evidence": "XOR diff is CONSTANT across all positions in range for each version pair: "
                        "0x09 (v6.4.7 vs v6.4.6), 0x0d (v6.4.7 vs v6.4.3), "
                        "0x7f (v6.4.7 vs v6.0.6), 0x78 (v6.4.7 vs v7.0.5). "
                        "Single-byte XOR with version_key_1 = plaintext XOR ciphertext.",
            "key_derivation": "UNKNOWN -- version_key_1 differences: {v646: K^0x09, v643: K^0x0d, "
                              "v606: K^0x7f, v705: K^0x78}. Absolute value K unknown.",
        },
        "transition_byte_296": {
            "bytes":  "296",
            "content": "Boundary byte where zone 1 ends and zone 2 begins. "
                       "Diff changes abruptly (v647 vs v643: 0x0d -> 0x88 at offset 296).",
        },
        "header_zone_2": {
            "bytes":    "297-511",
            "content":  "Single-byte XOR encrypted zone (215 bytes, version-specific key_2)",
            "evidence": "Constant diff 0x97 for v647 vs v643 across bytes 297-511.",
            "key_relationship": "key_2 = key_1 XOR constant? (v643: diff_1=0x0d, diff_2=0x97, "
                                "0x0d XOR 0x97 = 0x9a -- relationship unclear without absolute values).",
        },
        "payload_region": {
            "bytes":      "512+",
            "content":    "256MB raw NAND flash image encrypted with fixed 64-byte period XOR",
            "keystream":  "RECOVERED (see FHWC_KEYSTREAM)",
            "secondary":  "Firmware partitions within payload have secondary encryption (entropy 7.997)",
        },
    },

    "faz_200d_structural_anomaly": {
        "finding":     "bytes[0:32] == bytes[64:96] exactly in FAZ 200D inner binary",
        "implication": (
            "Exactly 32 bytes repeat with a 64-byte period. Two interpretations: "
            "(A) XOR cipher with 64-byte key, where first 64 bytes of plaintext are null -- "
            "making ciphertext[0:64] = key itself (key exposure via known-plaintext). "
            "(B) A cleartext 32-byte structure that appears twice (at offset 0 and offset 64) "
            "as part of a header format."
        ),
        "known_plaintext_path": (
            "If interpretation A is correct: key = inner_binary[0:64] "
            "REQUIRES confirmation that the plaintext at offset 0-63 is null. "
            "This would be confirmed by finding the decryption routine in firmware updater "
            "code (NOT accessible in encrypted rootfs). FGT 7.0.9 rootfs (unencrypted CPIO) "
            "would contain the `imagize` or `fwupgrade` binary handling this format -- "
            "the primary RE path currently blocked by missing QCOW2."
        ),
    },
}


# ---------------------------------------------------------
# FHWC keystream (recovered via known-plaintext attack)
# ---------------------------------------------------------
FHWC_KEYSTREAM = {
    "method": (
        "Known-plaintext attack on zero-padded NAND flash regions. "
        "Observation: large contiguous blocks of the 256MB payload produce IDENTICAL ciphertext. "
        "Hypothesis: empty flash (zero-filled) XOR keystream = keystream (ciphertext == keystream). "
        "Verification: at payload_off=265216, decrypted content = perfect descending byte sequence "
        "'ff fe fd fc fb...01 00' (0x80 bytes). This is a standard NAND BIST test pattern, "
        "confirming zero-plaintext hypothesis and keystream correctness."
    ),
    "keystream_hex": (
        "9edebef3b4d2accfa2eed7bec68cc6a1"
        "d8f1a2fc83ddfca7d2f286d0faaad798"
        "f9b9d994d3b5cba8c589b0d9a1eba1c6"
        "bf96c59be4ba9bc0b595e1b79dcdb0ff"
    ),
    "keystream_bytes": 64,
    "period": 64,
    "notes": {
        "magic_relationship": (
            "First 4 bytes of keystream = 9e de be f3 = container magic (family_C LE). "
            "Likely intentional: firmware designers used the container magic as keystream seed. "
            "This is a DESIGN FLAW -- the magic is public, so the first 4 bytes of the keystream "
            "are trivially recoverable even without the known-plaintext attack."
        ),
        "scope": "Valid for ALL FGT 1500D hardware firmware versions (v6.0.6 through v7.0.5 confirmed). "
                 "Same keystream across all 8 tested versions. Likely valid for FGT-1000C and "
                 "other family_C products (same magic family).",
        "decryption": (
            "To decrypt payload byte at inner_off (>= 512): "
            "  payload_off = inner_off - 512 "
            "  plaintext[inner_off] = ciphertext[inner_off] XOR keystream[payload_off % 64]"
        ),
    },
    "zero_coverage": (
        "75.9% of payload 64-byte blocks are zero-plaintext (empty flash = 0x00). "
        "24.1% are non-zero (firmware content). "
        "Zero regions confirmed by cross-version identity: ciphertext identical across v6.0.6 and v7.0.5 "
        "at sampled zero positions."
    ),
}


# ---------------------------------------------------------
# FGT 1500D flash layout (from decrypted payload analysis)
# ---------------------------------------------------------
FHWC_FLASH_LAYOUT = {
    "source":          "FGT_1500D family_C, decrypted via FHWC_KEYSTREAM",
    "flash_size":      "256MB (268435456 bytes = 0x10000000), starting at inner_off 512",
    "empty_state":     "0x00 (zero-padded, not 0xFF erased-state -- NOR flash or padded image)",

    "structure": {
        "oob_ecc_table": {
            "inner_off":   "1536 - 262143",
            "payload_off": "1024 - 261631",
            "size":        "~256KB",
            "content": (
                "Structured OOB/ECC table: 64-byte blocks at every 1024-byte boundary. "
                "Counter byte at position 0 increments 0x04, 0x05, ..., 0xff, 0x00, 0x01, 0x02... "
                "Each 64-byte block: counter + pattern bytes + repeating bit-field triplets. "
                "Pattern examples: "
                "  block 4: 04 24 24 24  28 48 48 48  4c ec ec ec  f0 10 10 10... "
                "  block 8: 08 28 28 28  20 40 40 40  58 f8 f8 f8  e0 00 00 00... "
                "Block structure: [counter][counter|0x20][counter|0x20][counter|0x20] "
                "                 [bit_pattern] x3  [nibble_mirror] x4 ..."
            ),
        },
        "nand_test_pattern": {
            "inner_off":   "265728",
            "payload_off": "265216",
            "size":        "128 bytes (2 x 64-byte blocks)",
            "content": (
                "Standard NAND BIST pattern: "
                "Block 1 (64B): 0xff, 0xfe, 0xfd, ..., 0xe0 (high byte descending from 0xff to 0xe0) "
                "              + 0x1f, 0x1e, ..., 0x00 (low byte descending 0x1f to 0x00). "
                "Block 2 (64B): same 64-byte pattern repeated. "
                "Verified correctly decrypted: `Decrement check: True` for first 32 bytes."
            ),
        },
        "secondary_region": {
            "inner_off":   "269056 - 270336",
            "payload_off": "268544 - 269824",
            "size":        "1KB",
            "content": "First 8B: c083838383b3b3b3 -- unknown format, likely NAND ECC variant",
        },
        "small_data_regions_500KB": {
            "inner_off":   "529920 - 557056",
            "size":        "~26KB",
            "content": "First 8B: 0202020216161719 -- likely NAND spare area or boot metadata",
        },
        "kernel_or_bootloader": {
            "inner_off":   "557568 - 1044992",
            "payload_off": "557056 - 1044480",
            "size":        "~475KB",
            "content": "First 8B: 0d070707111b1b1b -- high entropy; likely compressed kernel/bootloader",
            "entropy":  "~7.99 bits/byte (compressed or encrypted)",
        },
        "firmware_partitions": {
            "count":       7,
            "size_each":   "~6MB (6144-6145KB)",
            "offsets": [
                "inner_off 18875904 - 25167872  (18MB - 24MB)",
                "inner_off 27264512 - 33556992  (26MB - 32MB)",
                "inner_off 35653120 - 41945088  (34MB - 40MB)",
                "inner_off 44041728 - 50334208  (42MB - 48MB)",
                "inner_off 52430336 - 58722304  (50MB - 56MB)",
                "inner_off 60818944 - 67111424  (58MB - 64MB)",
                "inner_off 69207552 - 75499520  (66MB - 72MB)",
            ],
            "spacing":     "~8MB between partition starts (8MB-aligned NAND erase blocks?)",
            "entropy":     "7.997 bits/byte (essentially maximum -- secondary encryption confirmed)",
            "inter_version": "99% byte-level variation between v6.0.6 and v7.0.5 after XOR decryption",
            "format":      "UNKNOWN -- binwalk finds nothing; no standard filesystem/compression magic",
            "hypothesis":  "Secondary AES encryption keyed from 512-byte header (zone 1 or zone 2). "
                           "Key size: likely 128 or 256 bit. Key source: header bytes 48-511 "
                           "after stripping version-specific XOR.",
        },
        "additional_regions": {
            "1MB_region_at_17567232": {
                "size":  "1MB",
                "content": "First 8B: 8e2ad613498813a3 -- high entropy, unknown format",
            },
            "2456KB_at_94373376": {
                "size":  "2456KB",
                "content": "First 8B: de815f3ce2855c3f -- high entropy",
            },
        },
    },

    "recovery_note": (
        "To decrypt firmware partitions, the secondary encryption key must be recovered. "
        "Two paths: "
        "(1) Recover header zone 1 plaintext: find absolute version_key_1 via known plaintext "
        "    in bytes 48-295 (firmware version string or build number at a known offset). "
        "    If zone 1 contains the AES key, decrypting zone 1 gives the AES key for the payload. "
        "(2) Find the firmware container decryptor binary in FGT 7.0.9 CPIO rootfs "
        "    (unencrypted rootfs, see ANALYSIS_STATUS.best_attack_path). "
        "    BERT sweep of imagize/fwupgrade binaries would identify the AES setup function "
        "    in <35 seconds."
    ),
}


# ---------------------------------------------------------
# KVM firmware container: rootfs.gz encryption format
# ---------------------------------------------------------
KVM_ROOTFS_ENCRYPTION = {
    "finding": "CROSSVER-F04 (from fortinet_fortigate_crossver_re.py)",
    "formats": {
        "FGT_7.0.9":  "CPIO (unencrypted) -- full rootfs accessible",
        "FGT_7.4.12": "Magic 0x654accb2 -- encrypted",
        "FGT_8.0.0":  "Magic 0x5b6758cb -- encrypted (shared with FAZ/FMG 8.0.0)",
    },
    "encryption_introduced": "Between FGT v7.0.9 (CPIO) and v7.4.12 (encrypted)",
    "kvm_vs_hardware": (
        "KVM image rootfs.gz encryption is DIFFERENT from hardware .out container encryption. "
        "Different magic families, different key material. Two separate encryption schemes. "
        "Hardware container uses 64-byte-period XOR (or block cipher with 64-byte blocks). "
        "KVM rootfs uses a different scheme (magic 0x654accb2 for FGT 7.4.12; unknown algorithm)."
    ),
}


# ---------------------------------------------------------
# BERT semantic family clustering results
# Source: fortinet_container_cluster.py on FGT 8.0.0 vmlinux
# Binary: 26MB vmlinux (kernel for FGT_VM64_KVM-v8.0.0.F-build0167)
# Region swept: fortism_init + fos_keyring + fortism_ioctl (0x448000-0x565000)
# Functions swept: 929
# Model: sentence-transformers/all-MiniLM-L6-v2
# Post-processing: WhiteningTransform (PCA whitening to fix BERT anisotropy)
# Clustering: K-means k=16
# Query for ranking: "firmware image load verification | role: integrity_check | ..."
# ---------------------------------------------------------
BERT_CLUSTER_FAMILIES = {
    "methodology": (
        "929 functions disassembled with capstone, encoded via Ablation describe_function() "
        "(BinFuse 11-category opcode normalization + Markov transitions + call targets + roles). "
        "WhiteningTransform applied post-encoding to fix BERT anisotropy (unrelated pairs "
        "drop from 0.6-0.9 to 0.4-0.6; true matches stay >0.8). "
        "K-means k=16. Clusters ranked by centroid cosine similarity to firmware-verification query. "
        "Anchor strings: fortism_kernel_load_data, fos_ima, fos_is_appraise_enforced, "
        "fos_keyring, fortism_bprm_check_security."
    ),

    "cluster_0_ioctl_policy": {
        "fw_score":   0.121,
        "rank":       1,
        "size":       62,
        "label":      "IOCTL_POLICY_DISPATCH_FAMILY",
        "dominance":  "unknown(50) + control_flow_heavy(8) + dispatcher(4)",
        "confirmed_hooks": ["IOCTL_0x9007 at foff=0x55c546", "IOCTL_0x9007 at foff=0x55c7f3"],
        "key_members": {
            "0x55b6e0": {
                "role":    "dispatcher",
                "insns":   140,
                "analysis": (
                    "State machine: reads [r12+0x58] (key-type field), dispatches on values 1-7. "
                    "Compares [r12+0x30] to 0xffffffff81660900 (likely a sentinel/error value). "
                    "References 8+ kernel string addresses (0xffffffff813e...) -- algorithm names. "
                    "Calls 0xffffffff8055b54a (inner check, called twice -> loop until done). "
                    "Pattern matches: Linux keyring type-dispatch table walker, or "
                    "fortism policy node iterator (evaluates policy entries by type). "
                    "KEY TYPE ENUM: 1-7 values suggest {DENY=1, ALLOW=2, AUDIT=3, "
                    "LEARN=4, UNKNOWN=5, TRIGGER=6, INHERIT=7} or similar."
                ),
            },
            "0x55c546": {
                "role":    "dispatcher",
                "insns":   83,
                "analysis": "Confirmed fortism ioctl handler for cmd 0x9007 (DoS via rep stosq).",
            },
            "0x554f76": {
                "role":    "dispatcher",
                "insns":   91,
                "analysis": "Candidate: secondary ioctl dispatch, or fortism policy evaluation entry.",
            },
        },
        "security_implication": (
            "This family controls the policy evaluation gate. A bypass here skips all "
            "fortism MAC enforcement -- covers fortism_kernel_load_data and all other hooks. "
            "The 0x9007 ioctl DoS (FGT-F16, rep stosq NULL write on kernel heap) is in this cluster."
        ),
    },

    "cluster_12_lsm_hook_dispatcher": {
        "fw_score":   0.109,
        "rank":       2,
        "size":       49,
        "label":      "LSM_HOOK_DISPATCHER_FAMILY",
        "correction": (
            "Previously labeled KEYRING_LEAF_FUNCTIONS. Disassembly of top members "
            "(0x558854, 0x5585c5, 0x557d25, 0x558735) shows IDENTICAL structural pattern: "
            "  1. Load global hook head pointer via [rip + offset] -> r14. "
            "  2. Test r14 for null (no hooks registered -> return). "
            "  3. Loop: load [r14] (hlist_head.next), call [r14+0x18] (function pointer). "
            "  4. If return != 0, continue; else return. "
            "This is the standard Linux kernel security_hook_list dispatch pattern. "
            "Each function in this cluster dispatches ONE specific LSM hook type "
            "(one per hook: file_open, bprm_check, kernel_load_data, etc.). "
            "NOT a key leaf function family."
        ),
        "dominance":  "unknown(40) + control_flow_heavy(7) + xor_heavy(1)",
        "key_members": {
            "0x558854": {
                "fw_sim": 0.140,
                "pattern": "push r14+r13+r12+rbx | load hlist_head | loop: call [r14+0x18] | ret",
                "interpretation": "LSM hook dispatcher: 3 parameters (rdi=obj, rsi=arg1, rdx=arg2_or_flag)",
            },
            "0x5585c5": {
                "fw_sim": 0.123,
                "pattern": "same as 0x558854, different global head pointer (different hook)",
                "interpretation": "LSM hook dispatcher: esi=int32 variant (file access mode?)",
            },
            "0x557d25": {
                "fw_sim": 0.121,
                "pattern": "same pattern, rdi+rsi+rdx 3-arg variant",
                "interpretation": "LSM hook dispatcher: different hook type",
            },
        },
        "security_implication": (
            "LSM hook dispatchers are the bridge between kernel subsystems and the fortism "
            "security module. If the hook head pointer (global variable) can be zeroed or "
            "redirected (e.g., via arbitrary write primitive), ALL fortism security checks for "
            "that hook type are silently skipped -- the null-check on r14 returns immediately. "
            "Target: locate the global hook head pointer offsets (rip+offset from instructions) "
            "and map to kernel symbol table for each hook type."
        ),
    },

    "cluster_13_lsm_xor": {
        "fw_score":   0.062,
        "rank":       3,
        "size":       59,
        "label":      "LSM_HOOK_INIT_FAMILY",
        "dominance":  "unknown(41) + control_flow_heavy(9) + dispatcher(7) + xor_heavy(1)",
        "confirmed_hooks": ["FORTISM_LSM_HOOK at foff=0x55b4b0 (via region proximity)"],
        "key_members": {
            "0x560c20": {
                "role":    "unknown",
                "fw_sim":  0.142,
                "insns":   4,
                "analysis": (
                    "3-instruction wrapper: calls 0xffffffff80cd7331 (errno/status getter), "
                    "then calls 0xffffffff80560bbc with result. Error translator or "
                    "status-to-errno converter for fortism hook return paths."
                ),
            },
            "0x56131e": {
                "role":    "xor_heavy",
                "fw_sim":  0.100,
                "insns":   48,
                "analysis": (
                    "Labeled xor_heavy by BinFuse but the XOR ops are register-zeroing idioms "
                    "(xor eax,eax / xor esi,esi / xor ebx,ebx). NOT a raw XOR cipher. "
                    "Actual behavior: allocates 0xf8-byte stack frame, zeros 8 qwords, "
                    "calls 0xffffffff80561215 (likely a key lookup by type+id), "
                    "then dispatches on [rax+0x30] comparing to 3 or 2 -- key state enum. "
                    "Pattern: key-state-conditional branch (e.g., LOADED=3, PENDING=2, NONE=0)."
                ),
            },
        },
        "security_implication": (
            "LSM hook initialization family. Contains the fortism_bprm_check_security "
            "and fortism_kernel_load_data hook registration code. "
            "The key-state dispatch (0x56131e) suggests firmware load authorization "
            "checks the fos_keyring state before permitting initramfs load."
        ),
    },

    "cluster_10_enc_key_description_builder": {
        "fw_score":   0.054,
        "rank":       4,
        "size":       73,
        "label":      "ENC_KEY_DESCRIPTION_BUILDER_FAMILY",
        "correction": (
            "Label was ENC_KEY_BUILDER_FAMILY. Disassembly of the anchor function (foff=0x55339b) "
            "reveals it builds KEY DESCRIPTION STRINGS, not cryptographic key material. "
            "The name 'ENC_KEY_BUILDER' arose from a cluster proximity heuristic (abs(foff-0x55339b)<0x200) "
            "applied to all member functions -- NOT from actual content analysis of 0x55339b itself."
        ),
        "dominance":  "unknown(50) + control_flow_heavy(16) + dispatcher(6)",
        "anchor_function_0x55339b": {
            "disasm_findings": [
                "kmalloc allocation (size = max(0x20, rcx+9))",
                "movabs rax, 0x59454b5f434e45 -- writes 'ENC_KEY' (7 bytes) to buffer via [rbx]",
                "Calls strlen(rbx) to measure prefix length",
                "Calls snprintf/strlcat to append a suffix from rdx (caller-provided string)",
                "Calls 0x80573e4c with the assembled description string",
                "Stack canary check before return",
            ],
            "interpretation": (
                "Builds a keyring key description string of the form 'ENC_KEY<suffix>' "
                "where suffix comes from the caller. Used to look up or request a key from "
                "the Linux kernel keyring subsystem by description name. "
                "NOT a cryptographic key derivation function -- no crypto ops observed. "
                "The actual AES/HMAC key material lives in the kernel keyring, retrieved "
                "by description, not computed by this function."
            ),
            "key_type_variant": (
                "r15d param: if 0 -> 'ENC_KEY' prefix; if nonzero -> different prefix string "
                "(branch at 0x805533f4 to 0x805534b1). "
                "Adjacent function 0x5532c1 validates key description: "
                "  strncmp(desc, 'trusted:', 8) -> Linux keyring 'trusted' type (TPM-backed). "
                "  strncmp(desc, 'user:', 5) -> Linux keyring 'user' type (software-backed). "
                "  If neither matches: return EOPNOTSUPP (-95). "
                "String constants at rodata: 'hmac(sha256)', 'sha256', 'user:', 'trusted:'."
            ),
        },
        "confirmed_hooks": ["ENC_KEY_BUILDER proximity tag at foff=0x55339b, 0x5532c1"],
        "key_members": {
            "0x556ce8": {
                "fw_sim":  0.131,
                "pattern": "same LSM hook dispatcher pattern as C12 members",
                "note": "LSM dispatcher, not key builder -- included via proximity tag artifact",
            },
            "0x44e088": {"fw_sim": 0.118, "role": "control_flow_heavy", "note": "fortism_init region"},
        },
        "security_implication": (
            "The keyring key type discrimination (trusted: vs user:) at foff=0x5532c1 is load-bearing. "
            "On KVM systems without TPM, only 'user:' type keys are available -- these are "
            "software-backed and may be extractable from kernel memory once the rootfs is mounted. "
            "Key description format: 'ENC_KEY' + suffix -- knowing the suffix allows targeted "
            "keyring key extraction via /proc/keys or keyctl after gaining kernel read primitive."
        ),
    },

    "cross_cluster_firmware_verification_path": (
        "Based on clustering: the firmware container verification path in FGT 8.0.0 flows: "
        "  [Cluster 10] ENC_KEY_BUILDER: boot-time key material construction "
        "  -> [Cluster 12] KEYRING_LEAF: key slot lookup and state access "
        "  -> [Cluster 13] LSM_HOOK_INIT: fortism_kernel_load_data hook checks key state "
        "  -> [Cluster 0] IOCTL_POLICY: policy evaluation gate (allow/deny initramfs load) "
        "This is the 4-stage pipeline from key seeding to initramfs load authorization. "
        "ATTACK SURFACE: if key state (Cluster 12/13) can be set to LOADED without actual "
        "key material (e.g., by sending ioctl 0x9007 to reset state mid-boot), the policy "
        "gate (Cluster 0) may grant load authorization for an unsigned rootfs."
    ),
}


# ---------------------------------------------------------
# Fortinet-specific strings in vmlinux (FGT 8.0.0)
# ---------------------------------------------------------
FORTINET_VMLINUX_STRINGS = {
    "fortism_lsm_hooks": [
        "fortism_kernel_load_data",
        "fortism_bprm_check_security",
        "fortism_file_mmap",
        "fortism_file_mprotect",
        "fortism_file_ioctl",
        "fortism_file_open",
        "fortism_inet_connect",
        "fortism_inet_sendmsg",
        "fortism_socket_connect",
        "fortism_socket_listen",
        "fortism_task_kill",
        "fortism_task_setuid",
        "fortism_path_chmod",
        "fortism_path_chroot",
        "fortism_path_link",
        "fortism_path_mknod",
        "fortism_path_symlink",
        "fortism_unix_connect",
        "fortism_unix_path_permission",
        "fortism_unix_sendmsg",
        "fortism_ptrace_acl_check",
    ],
    "fos_ima_strings": [
        "fos_ima",
        "fos_is_appraise_enforced",
        "fos_iint_cache",
    ],
    "fos_keyring": "fos_keyring",
    "other": ["FortiRBG", "forti_nmi_crash", "forti_lsm"],
    "rootfs_path": [
        "/data/rootfs.gz",
        "rootfs image",
        "back rootfs image",
    ],
    "note": (
        "fortism_kernel_load_data is the LSM hook invoked by kernel_load_data() for "
        "initramfs (rootfs.gz) loading. This is the firmware container integrity check gate. "
        "fos_ima provides IMA-based file measurement for appraisal. "
        "fos_keyring holds the key material used for signature verification. "
        "FortiRBG = Fortinet Random Bit Generator (custom DRBG seeding)."
    ),
}


# ---------------------------------------------------------
# Container RE findings
# ---------------------------------------------------------
CONTAINER_FINDINGS = [
    "FHWC-F01: Hardware .out container uses gzip outer + encrypted inner. "
    "Inner payload identified by 5 magic byte families mapping to product lines. "
    "Magic family assignment: 0x91a2XX family = FortiAnalyzer/FortiLog; "
    "0x9eXXXX family = FortiGate 1000C/1500D; 0x9cXXXX = FGT 100F; 0x9aXXXX = FGT 200F. "
    "Severity: INFO (format map complete for 5 families)",

    "FHWC-F02: XOR key-cancellation reveals cleartext product header at bytes 0-39. "
    "FGT 1500D (5 versions, v6.0.6-v7.0.5): bytes 0-39 invariant across all versions. "
    "Byte 40+ contains version-specific data. "
    "Method: XOR(fw_vA, fw_vB) -> zero in 0-39, non-zero from ~40. "
    "Severity: INFO -- confirms header boundary without key extraction",

    "FHWC-F03: FAZ 200D structural anomaly: inner_binary[0:32] == inner_binary[64:96] exactly. "
    "64-byte period match (70.5% across FGT 1500D family). "
    "If XOR cipher with 64-byte key and null plaintext prefix: key = inner_binary[0:64]. "
    "This is a TESTABLE HYPOTHESIS requiring access to firmware decryptor to confirm null prefix. "
    "Severity: HIGH if confirmed (direct key exposure from ciphertext)",

    "FHWC-F04: KVM rootfs.gz uses separate encryption from hardware .out container. "
    "FGT 7.4.12: magic 0x654accb2. FGT/FAZ/FMG 8.0.0: magic 0x5b6758cb. "
    "Two distinct encryption schemes (hardware vs VM) imply separate key material. "
    "VM scheme may be weaker (no hardware security module for key storage). "
    "Severity: INFO -- format boundary confirmed",

    "FHWC-F05: BERT cluster analysis of FGT 8.0.0 vmlinux identifies "
    "4-stage firmware verification pipeline: "
    "ENC_KEY_BUILDER (boot key seed) -> KEYRING_LEAF (key state lookup) -> "
    "LSM_HOOK_INIT (fortism_kernel_load_data gate) -> IOCTL_POLICY (allow/deny). "
    "Key state dispatch (foff=0x56131e) checks key state enum (0=none, 2=pending, 3=loaded) "
    "before authorizing initramfs mount. "
    "Severity: INFO -- pipeline mapped without confirmed bypass",

    "FHWC-F06: fortism IOCTL 0x9007 (DoS confirmed, FGT-F16) is in the IOCTL_POLICY cluster "
    "(Cluster 0, fw_sig=0.121). If 0x9007 can be triggered during the key-state window "
    "(between key seed and key-state-LOADED check in fortism_kernel_load_data), it may "
    "reset the policy state and permit unsigned initramfs load. "
    "HYPOTHESIS: timing race between boot and ioctl delivery. Requires physical access or "
    "live kernel exploit to time. "
    "Severity: MEDIUM (speculative; requires timing precision + existing kernel access)",

    "FHWC-F07: Hardware container (family_C, FGT 1500D) stream cipher confirmed via cross-version "
    "XOR differential analysis (4 versions v6.4.3-v6.4.7). "
    "Header structure: bytes 0-36 invariant (cleartext product header). "
    "Bytes 37-47: version-specific fields (build number, patch version, CRC fragment). "
    "Bytes 48+: constant XOR diff across all versions = FIXED KEYSTREAM (stream cipher). "
    "XOR diff values: 0x09 (6.4.7 vs 6.4.6), 0x76 (6.4.7 vs 6.4.5), 0x0d (6.4.7 vs 6.4.3). "
    "Key period signal: 20.12% of byte-pairs match at period=64 (vs 0.39% random baseline). "
    "Entropy: 7.602 bits/byte (below AES-grade 7.99; consistent with stream cipher or compressed data). "
    "NO XZ magic found in first 1MB post-header (contradicts 'forged-CRC XZ' README note). "
    "Severity: HIGH -- stream cipher with fixed keystream enables known-plaintext key recovery "
    "once plaintext at byte 48 is identified (e.g., via JFFS2/SquashFS magic at payload start).",

    "FHWC-F08: ENC_KEY is a kernel keyring KEY DESCRIPTION STRING, not cryptographic key material. "
    "Architecture: fos_keyring stores firmware decryption key in Linux kernel keyring "
    "under description 'ENC_KEY<suffix>'. Two key types supported: "
    "  'user:' = software-backed kernel keyring (KVM VMs without TPM). "
    "  'trusted:' = TPM-sealed key (physical hardware with TPM). "
    "Algorithms in rodata adjacent to keyring code: 'hmac(sha256)', 'sha256'. "
    "No AES instructions in fortism region -- encryption delegated to kernel crypto API. "
    "Key discriminator at foff=0x5532c1: validates key type prefix; returns EOPNOTSUPP for "
    "any key not matching 'trusted:' or 'user:'. "
    "Attack vector: on KVM systems with user: key type, kernel memory read primitive -> "
    "keyctl(KEYCTL_READ, key_serial) extracts the AES key material directly. "
    "Severity: HIGH (KVM-specific key extraction path; requires kernel read primitive)",

    "FHWC-F09: 64-byte period XOR keystream FULLY RECOVERED for FGT 1500D hardware container. "
    "Method: known-plaintext attack on empty NAND flash regions (zero-fill = known plaintext). "
    "Keystream: 9edebef3b4d2accfa2eed7bec68cc6a1d8f1a2fc83ddfca7d2f286d0faaad79"
    "           8f9b9d994d3b5cba8c589b0d9a1eba1c6bf96c59be4ba9bc0b595e1b79dcdb0ff. "
    "Verification: at inner_off=265728 (payload_off=265216), decrypted content = NAND test pattern "
    "'ff fe fd fc...01 00' (descending byte sequence confirmed). "
    "Design flaw: keystream[0:4] = 9e de be f3 = family_C container magic (LE). "
    "The container magic IS the keystream seed -- trivially recoverable from the public file header. "
    "Cross-version scope: keystream is IDENTICAL across all 8 tested versions (v6.0.6 - v7.0.5). "
    "Flash density: 75.9% zero-plaintext (empty NAND), 24.1% firmware content. "
    "Decryption: plaintext[off] = ciphertext[off] XOR keystream[(off - 512) % 64] for inner_off >= 512. "
    "Severity: CRITICAL -- outer XOR layer is trivially broken; 256MB flash image fully readable",

    "FHWC-F10: Secondary encryption layer confirmed within XOR-decrypted NAND flash payload. "
    "After XOR decryption with recovered 64-byte keystream: "
    "  Firmware partition regions (~6MB each, 7 copies) have entropy 7.997 bits/byte (max = 8.0). "
    "  v6.0.6 vs v7.0.5 cross-version comparison: 99% byte-level variation (65260/65536 bytes differ). "
    "  No recognizable filesystem or compression magic in any decrypted partition. "
    "  binwalk finds nothing -- no known header signatures in entire 64KB sample. "
    "Secondary cipher characteristics: "
    "  NOT a simple XOR cipher (too high entropy and variation). "
    "  Likely AES-CBC or AES-XTS given Fortinet's documented kernel crypto API usage. "
    "  Key material is in the 512-byte inner binary header (encrypted with version-specific XOR). "
    "  Header structure: bytes 0-35 cleartext, 36-47 transition, 48-295 zone-1 (single-byte XOR), "
    "                    296 boundary, 297-511 zone-2 (single-byte XOR). "
    "Recovery path: decode zone-1 absolute version_key via known plaintext in bytes 48-295 "
    "(firmware version string, build number, or product string at known offset). "
    "Severity: CRITICAL -- secondary encryption blocks firmware partition access; "
    "exposes complete firmware to cryptanalysis once header zone plaintext is identified",

    "FHWC-F11: FGT 1500D NAND flash layout fully mapped from decrypted payload. "
    "Flash size: 256MB (268435456 bytes), inner_off 512 onward, zero-padded empty state. "
    "Regions: "
    "  ECC/OOB table:   inner_off 1536-262143 (~256KB). Structured 64-byte blocks; "
    "                   counter byte increments 0x04, 0x05... at every block start. "
    "  NAND test pattern: inner_off 265728 (128 bytes). Perfect descending sequence ff fe...00. "
    "  Compressed kernel/bootloader: inner_off 557568-1044992 (~475KB). Entropy 7.99. "
    "  Firmware partitions: 7 copies, ~6MB each, starting at inner_off 18875904 (18MB), "
    "                       spaced ~8MB apart (8MB NAND erase block alignment). "
    "  Additional regions: 1MB at inner_off 17567232, 2456KB at inner_off 94373376. "
    "Note: 75.9% of flash is empty (zero-fill), 24.1% is content. "
    "Severity: INFO -- layout map enables targeted extraction of firmware partitions for analysis",

    "FHWC-F12: Secondary AES cipher is HARDWARE-BOUND across ALL tested FortiGate models. "
    "Models tested: FGT 1500D (family 9edebef3), FGT 40F (family 9caece82), "
    "FGT VM64 KVM v8.0.0 (family 9edee4a5). All firmware partition regions show entropy "
    "7.981-8.000 bits/byte after outer XOR decryption. "
    "Analysis: 256 AES key candidates derived from header zone-1/zone-2 (all possible single-byte "
    "XOR keys, all modes ECB/CBC/CTR, all plausible key material) -- ZERO successful decryptions. "
    "Conclusion: secondary AES key is NOT stored in or derivable from the .out file alone. "
    "Key derivation requires hardware-bound key material: TPM-sealed secret, burned-in fuse, "
    "or platform-specific hardware ID. "
    "Earlier hypothesis (FGT 40F lower entropy implies absent secondary cipher) is REFUTED: "
    "FGT 40F lower overall entropy (6.2) relative to FGT 1500D (6.8) is explained entirely "
    "by higher NAND zero-fill ratio in 40F (smaller appliance = less data in flash). "
    "Partition regions at 20MB+ in FGT 40F show 8.0 entropy (AES-encrypted) same as FGT 1500D. "
    "Severity: CRITICAL -- blocks full static RE without hardware access",

    "FHWC-F13: Universal FortiGate NAND firmware container format confirmed across all models. "
    "Identical BIST layout in FGT 1500D, FGT 40F, and FGT VM64 KVM v8.0.0: "
    "  LBA 2   (payload_off 0x400):    BIST index table "
    "  LBA 8   (payload_off 0x1000):   BIST counter block 1 (11 11 11 11 03 03 03 03) "
    "  LBA 16  (payload_off 0x2000):   BIST counter block 2 (02 82 82 82 82 82 82 82) "
    "  LBA 24-120 (every 8 LBAs):      BIST counter blocks 3-15 (0N 8N 8N 8N pattern, N=3..0xf) "
    "  LBA 128 (payload_off 0x10000):  Final BIST block (10 90 90 90...) "
    "  LBA 136 (payload_off 0x11000):  NAND test pattern start (ff fe fd fc... descending) "
    "  LBA 155 (payload_off 0x13600):  OOB/ECC data start (a4 27 27 27 / ed ae ae ae patterns) "
    "  ~LBA 4096+ (~20MB):             Firmware partitions, 8MB erase-block spacing "
    "This layout is IDENTICAL across hardware (FGT 1500D, FGT 40F) and VM (FGT KVM v8.0.0). "
    "The VM image wraps a virtual NAND layout, not a disk image as initially hypothesized. "
    "Severity: INFO -- enables direct-offset extraction of NAND layout artifacts without full scan",

    "FHWC-F14: FGT VM64 KVM .out firmware uses the SAME magic-family XOR keystream as the "
    "corresponding hardware model. FGT VM64 KVM magic = 9edee4a5 (same as FGT 3700D hardware). "
    "Keystream confirmed: 9edee4a5f69fddbe86ca86eba4f8a3c4... (64 bytes). "
    "Verified by: zero-plaintext regions in KVM payload (payload_off 0x200, 0x800, 0x0a00...) "
    "all produce the 3700D keystream via known-plaintext XOR. Keystream is the same because "
    "magic family (not model) determines the keystream. "
    "KVM inner binary is a 256MB virtual NAND image (not a disk image). Sector 0 is a custom "
    "FortiOS boot/config sector (no MBR 0x55AA signature). Firmware partitions start at ~21MB "
    "(payload_off 0x1449000) with entropy 7.981 (secondary AES, same as hardware). "
    "Severity: INFO -- closes the 'KVM = easy path' hypothesis; KVM is equally locked",

    "FHWC-F15: Magic family keystream catalog -- complete for all surveyed product lines. "
    "Keystreams derived from zero-plaintext known-plaintext attack on empty NAND regions. "
    "All keystreams are 64-byte periodic XOR, first 4 bytes = magic (design flaw). "
    "  9edebef3 (FGT 1000C, 1500D):  9edebef3b4d2accfa2eed7bec68cc6a1... "
    "  9caece82 (FGT 40F/60F/81F/100F/101F/61F): 9caece82c5a392f1cc80e786eda7e186... "
    "  9aa9fbb2 (FGT 200F, 201F):    9aa9fbb2... (not yet extracted -- period64=True) "
    "  9edee4a5 (FGT 3700D, FGT VM64 KVM, FGT ARM64 KVM): "
    "           9edee4a5f69fddbe86ca86eba4f8a3c4ecb4e7bee7b9f5aedb8fd683c694f0bf... "
    "  9dc8a8e1 (FGT 2500E):         9dc8a8e1... (not yet extracted) "
    "  91a296d7 (FGT 900D):          91a296d7... (not yet extracted) "
    "All keystreams share the structural property: ks[i] XOR ks[i+32] = 0x67 for i=0..31. "
    "Second half of keystream = first half XOR 0x67 (deliberate design). "
    "Severity: INFO -- complete decryption capability for outer XOR layer across all product lines",
]


# ---------------------------------------------------------
# RE status and pending paths
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "hardware_container_format": {
        "status":   "OUTER LAYER BROKEN -- SECONDARY LAYER HARDWARE-BOUND (BLOCKED)",
        "known": [
            "5 magic families (product line mapping complete, see FHWC-F15 for all keystreams)",
            "Universal NAND container format confirmed across FGT 1500D, FGT 40F, FGT VM64 KVM (FHWC-F13)",
            "Cleartext header bytes 0-35 (invariant across all 8 tested versions)",
            "Transition zone bytes 36-47 (complex per-version, not simple XOR)",
            "Header zone-1 bytes 48-295: single-byte XOR, version-specific key (diffs: 0x09, 0x0d, 0x7f, 0x78)",
            "Header zone-2 bytes 297-511: single-byte XOR, version-specific key (diff 0x97 for v6.4.7 vs v6.4.3)",
            "Payload starts at byte 512 (not immediately post-header at byte 40 as previously thought)",
            "64-byte period XOR keystream FULLY RECOVERED (9edebef3...db0ff, see FHWC_KEYSTREAM)",
            "Keystream design flaw: keystream[0:4] = family_C magic (trivially derivable)",
            "Keystream is IDENTICAL across all 8 versions tested (v6.0.6 - v7.0.5)",
            "Keystream structural property: ks[i] XOR ks[i+32] = 0x67 for all i=0..31",
            "Flash layout mapped: BIST table, NAND test pattern, OOB/ECC table, firmware partitions at 8MB spacing",
            "Secondary encryption HARDWARE-BOUND across ALL models (FGT 1500D, FGT 40F, FGT KVM) -- FHWC-F12",
            "FGT VM64 KVM uses same XOR keystream as hardware (magic-family determines keystream) -- FHWC-F14",
            "FGT 40F lower overall entropy (6.2) = higher NAND zero-fill ratio, NOT absent secondary cipher",
            "FGT VM64 KVM inner binary is a virtual NAND image, not a disk image (period-64 XOR same as HW)",
        ],
        "unknown":  [
            "Secondary cipher key derivation (confirmed hardware-bound; requires physical TPM/fuse access)",
            "Absolute version_key values for header zone-1 and zone-2 (only relative diffs known)",
            "Known plaintext in header zone-1 bytes 48-295 (needed to recover absolute version_key)",
        ],
        "breaking_path": (
            "Static RE from .out files ALONE is blocked at the secondary cipher layer. "
            "All key candidates derivable from the .out file have been tried: "
            "  - Header zone-1/zone-2 content (all 256 single-byte XOR key values) "
            "  - Keystream bytes, magic bytes, SHA256/MD5 of any header material "
            "  - 2048 AES decrypt attempts (256 keys x 8 modes) -- ZERO valid outputs "
            "Hardware paths required: "
            "  (1) JTAG/serial console on physical FGT 1500D (dump decrypted NAND at runtime) "
            "  (2) TPM unsealing research on ARM64 FGT hardware (key stored in TPM PCR) "
            "  (3) Flash read via SPI interface on physical FGT board (pre-boot key extraction) "
            "Software paths: "
            "  (4) BERT sweep of imagize/fwupgrade in FGT 7.0.9 CPIO rootfs (unencrypted). "
            "      Status: BLOCKED (qcow2 not on local disk; GDrive account suspended). "
            "      This is the fastest path if the qcow2 can be re-obtained. "
            "  (5) Exploit a running FGT instance -> kernel read of decrypted NAND partition "
            "      (live firmware is decrypted in memory by fortism/imagize at boot)"
        ),
    },

    "kvm_rootfs_format": {
        "status":   "FORMAT IDENTIFIED, ALGORITHM UNKNOWN",
        "known":    ["magic 0x654accb2 (FGT 7.4.12)", "magic 0x5b6758cb (FGT/FAZ/FMG 8.0.0)"],
        "path_blocked": "Decryptor is in rootfs (chicken-and-egg); no unencrypted 7.4.x rootfs",
    },

    "best_attack_path": {
        "path":   "FGT 7.0.9 CPIO rootfs",
        "reason": (
            "FGT 7.0.9 has unencrypted CPIO rootfs with imagize/fwupgrade utilities "
            "that handle both hardware and KVM firmware containers. "
            "BERT semantic search on those binaries would identify the decryption function "
            "family in <35s. "
            "Status: BLOCKED -- QCOW2 not on local disk (was on Google Drive, account suspended)."
        ),
        "alternatives": [
            "JTAG / serial console on physical FGT hardware (requires hardware access)",
            "Kernel panic + crash dump analysis (fortism_kernel_load_data panic path)",
            "Bootloader extraction via flash read (SPI flash on physical FGT board)",
            "Download FGT 7.0.9 QCOW2 via alternative source",
        ],
    },

    "bert_cluster_quality": {
        "whitening":        "APPLIED (WhiteningTransform PCA whitening)",
        "n_funcs_swept":    929,
        "top_fw_sim_score": 0.144,
        "cluster_corrections": [
            "C12: was KEYRING_LEAF_FUNCTIONS -- corrected to LSM_HOOK_DISPATCHER_FAMILY "
            "(linked-list security hook iteration pattern; no crypto content).",
            "C10: was ENC_KEY_BUILDER_FAMILY -- corrected to ENC_KEY_DESCRIPTION_BUILDER_FAMILY "
            "(builds key description strings for kernel keyring lookup; no AES/crypto ops). "
            "The 'ENC_KEY_BUILDER' label was a proximity heuristic artifact, not content-derived.",
            "C0: IOCTL_POLICY_DISPATCH_FAMILY -- confirmed correct (ioctl 0x9007 DoS confirmed).",
            "C13: LSM_HOOK_INIT_FAMILY -- confirmed correct (key-state dispatch at 0x56131e).",
        ],
        "note": (
            "fw_sim scores are lower than ideal (top=0.144 vs >0.8 for confirmed homologs). "
            "Cause: the firmware CONTAINER decryption code is in userspace (not this kernel). "
            "Kernel vmlinux only has the GATE (fortism_kernel_load_data) not the CIPHER. "
            "The cipher code is in imagize/fwupgrade in the (encrypted) rootfs. "
            "BERT clustering correctly identified the 4 GATE function families; "
            "the CIPHER family is absent from the kernel search space by design."
        ),
    },

    "boot_partition_analysis": {
        "source":  "FGT_VM64_KVM-v8.0.0.F-build0167 virtioa.raw, partition 1 (ext4, 256MB)",
        "files": {
            "flatkc":         "7.97MB, ARM64 flat kernel image",
            "rootfs.gz":      "91.4MB, encrypted (magic cbd2efa3, ARM64 build)",
            "datafs.tar.gz":  "21MB, gzip standard -- ACCESSIBLE",
            "hash_bin.sha256": "410 SHA256 entries for rootfs binaries (for UEFI secure boot verify)",
            ".db":            "JSON integrity manifest (lists flatkc, rootfs.gz, etc. with digests)",
            ".db.x":          "PKCS#7/CMS signature over .db (DER-encoded, Fortinet PKI chain)",
        },
        "datafs_contents": {
            "accessible_elfs": [
                "lib/libips.so.new  (x86-64, stripped, 18MB in FGT 8.0.0 VM64 -- IPS/intrusion prevention engine; primarily Rust; 47,749 function prologues)",
                "lib/libav.so.new   (x86-64, stripped -- antivirus engine)",
            ],
            "libips_deep_analysis": {
                "language":     "Primarily Rust (confirmed by panic strings, Rust crate paths in binary)",
                "crates_confirmed": [
                    "memchr-2.7.4 (byte search)",
                    "regex-automata-0.4.7 (regex engine)",
                    "regex-syntax-0.8.4",
                    "serde_json-1.0.133 (JSON deserialization)",
                    "zlib-rs-0.6.0 (Rust zlib implementation)",
                    "encoding_rs-0.8.35 (character encoding)",
                    "quiche (Cloudflare QUIC/HTTP3 implementation)",
                    "aho-corasick (multi-pattern string matching for IPS signatures)",
                    "lmdb (Lightning Memory-Mapped Database for state caching)",
                    "serde-1.0.215, serde_derive-1.0.215",
                    "thiserror-2.0.3, enum_dispatch-0.3.13, zerocopy-derive-0.8.31",
                    "intrusive-collections-0.9.6 (lock-free intrusive data structures)",
                ],
                "corelib_modules": [
                    "corelib/ipsc/ (IPS core -- packet/signature matching)",
                    "corelib/flowav/ (flow-based antivirus engine)",
                    "corelib/dfasearch/ (DFA-based signature search; stats.rs)",
                    "corelib/mcdb/ (MCDB -- multi-core database?)",
                    "corelib/ssl/crates/uvart-ftls/ (Rust TLS library)",
                    "corelib/utils/crates/lmdb (LMDB Rust bindings)",
                    "corelib/utils/crates/libuv (libuv Rust bindings)",
                    "corelib/utils/crates/uvart (uvart event loop)",
                ],
                "build_path":   "/home/devops/ips-build-env/code/ipsbuild-Q3jPsx/",
                "build_rustc":  "/rustc/ded5c06cf21d2b93bffd5d884aa6e96934ee4234/ (rustc commit hash)",
                "lua_integration": "uvart_ftls_lua bindings: LuaJIT + libuv + TLS in Rust FFI; types UvPipe/UvTcp/UvTimer/UvRequest/UvPoll/UvFsEvent/UvPrepare",
                "quic_http3": "quiche (Cloudflare QUIC) integrated -- ECH stripping: 'Found ECH: create stripped ECH message'",
                "attack_surface": (
                    "Rust memory safety eliminates most classical BOF/UAF. Residual attack surface: "
                    "(1) FFI boundaries: uvart_ftls_lua (LuaJIT-Rust boundary); C bridge layer in bridge/src/ipsc.rs. "
                    "(2) quiche QUIC deserialization -- any quiche vulnerability affects IPS QUIC processing. "
                    "(3) Signature database loading -- binary format parser ('fidsdb_parser_overflow' profile); "
                    "    zlib-rs decompression of compressed signature data. "
                    "(4) ECH (Encrypted Client Hello) stripping logic -- creates modified TLS ClientHello; "
                    "    parsing errors could cause bypass or panic. "
                    "(5) PCRE/regex -- regex-automata + aho-corasick + PCRE; ReDoS possible against regex signatures. "
                    "(6) Integer arithmetic -- Rust debug panics on overflow; release mode uses wrapping semantics; "
                    "    'capacity overflow' panic strings suggest possible length calculation edge cases."
                ),
            },
            "cert_files": [
                "etc/fgt2.key  (RSA-2048 private key -- CROSSVER-F01: identical across FGT 7.4.12 x86-64 and ARM64 8.0.0)",
                "etc/fgt_512.key  (RSA-512 private key, pipeline modulus-B for ARM64)",
                "etc/cacert.pem  (CA certificate bundle)",
            ],
            "no_key_material": "No 'ENC_KEY' material found in datafs -- rootfs decryption key not stored here",
        },
        "key_location_hypothesis": (
            "ENC_KEY material for KVM rootfs decryption is likely: "
            "(a) Hardcoded in flatkc (ARM64 kernel flat image, 7.97MB, not analyzed). "
            "(b) Derived from VM disk UUID or hardware serial at boot time. "
            "(c) Injected by the hypervisor via SMBIOS/DMI tables. "
            "Path to confirm: analyze flatkc binary with ARM64 capstone sweep, "
            "search for 16/32-byte data blobs (AES key candidates) in the fos_keyring init "
            "function region."
        ),
    },
}


# ---------------------------------------------------------
# FortiOS 8.0.0 VM64 rootfs binary inventory (via IMA measurement list)
# Source: /mnt/fgt800p1/hash_bin.sha256 (410 entries, 39,629 bytes)
# rootfs.gz is encrypted (magic cbd2efa3) but IMA hash list reveals all binaries
# ---------------------------------------------------------
FORTIOS_800_ROOTFS_INVENTORY = {
    "id":      "FGT-ROOTFS-800-INVENTORY",
    "product": "FortiOS 8.0.0 VM64-KVM -- full rootfs binary inventory from IMA measurement list",
    "source":  "/mnt/fgt800p1/hash_bin.sha256 (SHA256 hashes of 410 IMA-measured binaries)",
    "rootfs_access_method": (
        "rootfs.gz is encrypted (magic cbd2efa3). "
        "hash_bin.sha256 is an IMA (Integrity Measurement Architecture) list of "
        "SHA256 hashes for all measured binaries INSIDE the encrypted rootfs. "
        "This provides the complete binary inventory without decryption."
    ),

    "rootfs_decryption_architecture": {
        "conclusion": "TPM2-sealed decryption key (hardware-bound, not static)",
        "evidence": [
            "No cbd2efa3 magic or static AES key in vmlinux text/data sections",
            "No static 16/32-byte key candidates near fos_keyring or rootfs loader code",
            "TPM2 Software Stack present: libtss2-esys.so.0, libtss2-sys.so.1, libtss2-mu.so.0, libtss2-tcti-device.so.0, libtss2-rc.so.0, libtss2-tctildr.so.0",
            "TPM2 OpenSSL provider: /lib/ossl-modules/tpm2.so",
            "/bin/eltt2 (ELF Tool for TPM2) measured by IMA",
            ".fos_keyring string in vmlinux: Linux keyring for FortiOS key management",
            "/data/.db and /data/.db.x: encrypted/integrity-protected config database",
        ],
        "mechanism": (
            "Boot sequence hypothesis: "
            "(1) flatkc BIOS stub decompresses vmlinux; "
            "(2) vmlinux verifies .chk RSA signatures (fortinet-subca2003 key) on flatkc, rootfs.gz, datafs.tar.gz; "
            "(3) kernel interacts with TPM2 via libtss2 to unseal the AES decryption key -- "
            "    key is sealed to PCR values (TPM2 policy), so it's only available if "
            "    the boot measurement chain matches expected values; "
            "(4) kernel decrypts rootfs.gz using unsealed key; "
            "(5) IMA enforces binary hashes from hash_bin.sha256 at load time. "
            "Consequence: rootfs decryption requires either TPM2 hardware or PCR value prediction."
        ),
        "attack_surface": [
            "TPM2 policy binding -- if PCR values are predictable in VM context, attacker can unseal key",
            "libtss2 stack vulnerabilities -- 6 libtss2 libraries, all measured by IMA but loaded from rootfs",
            "chicken-and-egg: IMA enforcement requires rootfs, rootfs requires TPM unsealing -- boot race possible",
        ],
    },

    "critical_findings": {
        "nodejs_web_ui": {
            "binaries": ["/bin/node", "/node-scripts/index.js", "/node-scripts/worker.js"],
            "chunk_files": "240+ JavaScript chunk files (hash-named, SPA bundle)",
            "native_addon": "/node-scripts/45a595f0b26e2dda0ae0dd596a6ab028.node (C++ native addon)",
            "significance": (
                "FortiOS 8.0.0 web management interface is Node.js-based. "
                "240+ JS chunk files = complete web UI SPA. "
                "Native .node addon = C++ code loaded into Node.js runtime. "
                "Attack surface: JS prototype pollution, native addon memory safety, "
                "Node.js event loop DoS, require() path traversal in addon."
            ),
            "severity": "CRITICAL",
        },
        "ebpf_wad": {
            "binary": "/lib/wad_dispatcher_kern.ebpf",
            "significance": (
                "WAD (Web Application Daemon) loads an eBPF program for kernel-level packet dispatch. "
                "eBPF program is in the IMA measurement list -- kernel verifies it at load. "
                "Attack surface: eBPF verifier bypass, eBPF map out-of-bounds, "
                "malicious eBPF bytecode if WAD accepts externally-supplied programs."
            ),
            "severity": "HIGH",
        },
        "oqs_provider": {
            "binary": "/lib/ossl-modules/oqsprovider.so",
            "significance": (
                "Open Quantum Safe (liboqs) OpenSSL provider -- post-quantum cryptography. "
                "FortiOS 8.0.0 includes PQC algorithms (Kyber, Dilithium, etc.) via oqsprovider. "
                "Attack surface: PQC implementation bugs in liboqs (complex new code); "
                "key encapsulation oracle attacks if hybrid key exchange is misimplemented."
            ),
            "severity": "MEDIUM",
        },
        "dpdk_offload": {
            "binaries": ["/lib/libdpdk.so", "/lib/libdpdkhelper.so"],
            "significance": (
                "FortiOS uses DPDK for high-speed packet processing in VM context. "
                "DPDK operates in user space with direct NIC access via UIO/VFIO. "
                "Attack surface: DPDK packet parsers (Ethernet/IP/L4) -- malformed packets "
                "bypass the kernel network stack and hit DPDK directly."
            ),
            "severity": "HIGH",
        },
        "mellanox_rdma": {
            "binaries": ["/lib/libibverbs.so.1", "/lib/libmlx4.so.1", "/lib/libmlx5.so.1", "/lib/libmana.so.1"],
            "significance": (
                "InfiniBand/RDMA support + Mellanox ConnectX-4/5 SmartNIC libraries. "
                "FortiOS supports Mellanox NIC offload. "
                "RDMA bypasses kernel network stack entirely -- DMA-capable remote write "
                "to registered memory regions."
            ),
            "severity": "HIGH",
        },
        "hyperscan_ips": {
            "binary": "/lib/libhs.so.5",
            "significance": (
                "Intel Hyperscan -- PCRE/regex acceleration library for IPS/UTM. "
                "Hyperscan 5.x -- check for known vulnerabilities in the RE2 compilation layer. "
                "ReDoS via crafted patterns injected through IPS rule update mechanism."
            ),
            "severity": "MEDIUM",
        },
        "saml_daemon": {
            "binary": "/bin/samld",
            "significance": (
                "Dedicated SAML SSO daemon (/bin/samld + /bin/samld.map). "
                "FortiOS 8.0.0 has a standalone SAML processing binary. "
                "SAML XML parsing + signature verification -- class of bugs: "
                "SAML signature wrapping, XML injection in assertion attributes."
            ),
            "severity": "HIGH",
        },
        "kmip_library": {
            "binary": "/lib/libkmip.so.0",
            "significance": (
                "KMIP (Key Management Interoperability Protocol) client library. "
                "FortiOS 8.0.0 can connect to external KMIP key management servers. "
                "Attack surface: KMIP server impersonation -> malicious key material delivery; "
                "KMIP protocol parser vulnerabilities in libkmip."
            ),
            "severity": "MEDIUM",
        },
    },

    "library_inventory_notable": [
        "/lib/libcmdbapi.so -- CMDB API (config management, core attack surface)",
        "/lib/libsslvpndapi.so -- SSL VPN daemon API (FortiGate SSL VPN internals)",
        "/lib/libfips_crypt.so + libfips.so -- FIPS 140-2 crypto implementation",
        "/lib/libdlp.so -- DLP engine",
        "/lib/libecryptfs.so -- eCryptfs per-file encryption (for /data?)",
        "/lib/libjwt.so.2 -- JWT library (FortiOS uses JWT for some auth flows)",
        "/lib/libwebsocket.so -- WebSocket support (Node.js web UI?)",
        "/lib/libxmlsec1-openssl.so.1 + libxmlsec1.so.1 -- XML security (SAML/xmldsig)",
        "/lib/libIPS_MB.so.1 -- Intel Multi-Buffer (batch crypto acceleration)",
        "/lib/liblasso.so.3 -- Lasso SAML library (second SAML implementation alongside samld?)",
        "/lib/libjemalloc.so.2 + libmimalloc.so.2 -- two allocators (jemalloc + mimalloc; context-dependent)",
        "/lib/librabbitmq.so -- RabbitMQ AMQP client (FortiOS sends messages to message queues)",
        "/lib/gssntlmssp.so -- NTLM SSP for Kerberos GSSAPI (Active Directory auth)",
    ],

    "ima_hash_list_note": (
        "hash_bin.sha256 only covers IMA-measured binaries. "
        "FortiOS has additional binaries not measured by IMA (scripts, config files). "
        "The 410 entries represent the security-critical binary surface. "
        "The node-scripts/ JS chunks have hashes but are not JIT-compiled -- "
        "the hash only prevents substitution, not code injection via JS prototype chains."
    ),
}
