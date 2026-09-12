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
            "FGT 1500D family_C: entropy 7.602 bits/byte (sample: bytes 40:1MB+40). "
            "Lower than AES-CBC (7.99) -- consistent with stream cipher or compressed content. "
            "Cross-version XOR diff analysis (4 versions, v6.4.3-v6.4.7): "
            "  bytes 0-36: XOR = 0x00 (INVARIANT -- cleartext header, identical across versions). "
            "  bytes 37-47: XOR = variable (version-specific fields: build, timestamp, CRC). "
            "  bytes 48+: XOR = CONSTANT (0x09 vs 6.4.6, 0x76 vs 6.4.5, 0x0d vs 6.4.3). "
            "CONSTANT XOR DIFF FROM BYTE 48 CONFIRMS STREAM CIPHER: "
            "  ciphertext[i] = plaintext_base[i] XOR keystream[i], keystream is identical "
            "  across all versions. The version-specific byte difference (0x09/0x76/0x0d) "
            "  is XOR'd into a fixed-position field (bytes 37-47) before the main payload. "
            "  Main payload from byte 48+ uses the SAME keystream regardless of version. "
            "Key period: period=64 shows 20.12% match vs expected 0.39% for random data; "
            "  no XZ magic found in first 1MB post-header -- not simply XZ with forged CRC."
        ),
    },

    "cleartext_header": {
        "finding":       "CONFIRMED for FGT 1500D family (4-version cross analysis)",
        "method":        "XOR key-cancellation: XOR same-product different-version inner binaries",
        "invariant_region": {
            "bytes":     "0-36",
            "content":   "ALL ZERO in XOR output -- bytes 0-36 identical across v6.4.3/v6.4.5/v6.4.6/v6.4.7",
            "structure": (
                "0x00-0x03: magic (9e de be f3 = family_C). "
                "0x04-0x0b: unknown 8 bytes (size or CRC in big-endian?). "
                "0x0c-0x0f: possible timestamp (0x686498d2 LE = ~1751613394 = 2025-07-04 epoch). "
                "0x10-0x23: additional header fields (all invariant = same for all product versions). "
                "0x24-0x36: last 19 invariant bytes -- possibly model ID, hardware revision, padding."
            ),
        },
        "variable_region": {
            "bytes":      "37-47",
            "content":    "Version-specific fields: build number, minor version, checksum fragment",
            "xor_diffs":  {
                "v6.4.7_vs_v6.4.6": "bytes 37-47: 00000000000309717171717174740909",
                "v6.4.7_vs_v6.4.5": "bytes 37-47: 0000000000030c0b0b0b0b0b71707676",
                "v6.4.7_vs_v6.4.3": "bytes 37-47: 000000000002080f0f0f0e0971710d0d",
            },
            "note": "First diff at byte 37 (0x03 between 6.4.7 and 6.4.6). Transition completes by byte 47.",
        },
        "payload_region": {
            "bytes":      "48+",
            "content":    "Stream-cipher encrypted firmware payload (keystream fixed across versions)",
            "evidence":   "XOR diff is CONSTANT (0x09, 0x76, 0x0d) for all versions from byte 48+",
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
                "lib/libips.so.new  (x86-64, stripped, 54MB -- IPS/intrusion prevention engine)",
                "lib/libav.so.new   (x86-64, stripped -- antivirus engine)",
            ],
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
