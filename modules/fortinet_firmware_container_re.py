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
            "All inner binaries have entropy consistent with encryption (>7.9 bits/byte). "
            "64-byte periodicity confirmed: 70.5% of 64-byte blocks match at the same "
            "position across versions -- consistent with XOR cipher with 64-byte key "
            "OR NAND flash page-alignment artifacts. Cannot distinguish without known plaintext."
        ),
    },

    "cleartext_header": {
        "finding":       "CONFIRMED for FGT 1500D family",
        "method":        "XOR key-cancellation: XOR two firmwares of same HW, different versions",
        "invariant_region": {
            "bytes":     "0-39",
            "content":   "ALL ZERO in the XOR output (key cancels; plaintext is identical)",
            "implication": (
                "Bytes 0-39 of the inner binary are identical across all versions of FGT 1500D "
                "(v6.0.6, v6.2.15, v6.4.13, v7.0.5, v7.2.x). This is either: "
                "(a) a fixed product header present in cleartext before the encrypted payload, "
                "(b) an encrypted header where the plaintext bytes 0-39 are the same for all "
                "versions (product ID / magic), or (c) padding/alignment. "
                "Most likely: fixed cleartext product header identifying the hardware model."
            ),
        },
        "variable_region": {
            "bytes":      "40+",
            "content":    "Non-zero XOR output; version-specific differences visible from byte ~40",
            "implication": (
                "The encrypted payload begins at approximately byte 40. Version-specific content "
                "(version number, build timestamp, rootfs hash) starts here."
            ),
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

    "cluster_12_keyring_leaf": {
        "fw_score":   0.109,
        "rank":       2,
        "size":       49,
        "label":      "KEYRING_LEAF_FUNCTIONS",
        "dominance":  "unknown(40) + control_flow_heavy(7) + xor_heavy(1)",
        "key_members": {
            "0x558854": {"fw_sim": 0.140, "role": "unknown", "note": "Top fw_sig; near fos_keyring"},
            "0x5585c5": {"fw_sim": 0.123, "role": "unknown", "note": "Short leaf, fos_keyring region"},
            "0x557d25": {"fw_sim": 0.121, "role": "unknown", "note": "Short leaf, fos_keyring region"},
        },
        "analysis": (
            "Dense cluster of short functions (mostly 'unknown' role = < 5 visible call targets). "
            "All in fos_keyring / fortism_ioctl region (0x557d25-0x558854). "
            "Likely: key slot getters/setters, key type predicates, key metadata accessors. "
            "One xor_heavy member -- could be a key mixing or XOR-MAC operation. "
            "These are the leaf functions called by the Cluster 0 dispatcher."
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

    "cluster_10_enc_key_builder": {
        "fw_score":   0.054,
        "rank":       4,
        "size":       73,
        "label":      "ENC_KEY_BUILDER_FAMILY",
        "dominance":  "unknown(50) + control_flow_heavy(16) + dispatcher(6)",
        "confirmed_hooks": ["ENC_KEY_BUILDER at foff=0x55339b (x2 within cluster)"],
        "key_members": {
            "0x556ce8": {"fw_sim": 0.131, "role": "unknown", "note": "near ENC_KEY_BUILDER"},
            "0x44e088": {"fw_sim": 0.118, "role": "control_flow_heavy", "note": "fortism_init region"},
        },
        "analysis": (
            "Key construction family centered on foff=0x55339b (ENC_KEY_BUILDER confirmed in "
            "prior session as the fos_keyring key material builder). "
            "control_flow_heavy dominance (16/73) suggests complex key validation paths: "
            "key length checks, algorithm validation, key slot availability tests. "
            "Functions in fortism_init region (0x44e088) = initialization path that seeds "
            "the key material at boot time before any filesystem mount."
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
]


# ---------------------------------------------------------
# RE status and pending paths
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "hardware_container_format": {
        "status":   "PARTIALLY MAPPED",
        "known":    ["5 magic families", "cleartext header 0-39", "64-byte period"],
        "unknown":  [
            "Encryption algorithm (XOR vs AES-ECB vs custom)",
            "Key derivation (hardware fuse? hard-coded? version-derived?)",
            "Header structure (product ID fields, checksum, signature offset)",
        ],
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
        "note": (
            "fw_sim scores are lower than ideal (top=0.144 vs >0.8 for confirmed homologs). "
            "Cause: the firmware CONTAINER decryption code is in userspace (not this kernel). "
            "Kernel vmlinux only has the GATE (fortism_kernel_load_data) not the CIPHER. "
            "The cipher code is in imagize/fwupgrade in the (encrypted) rootfs."
        ),
    },
}
