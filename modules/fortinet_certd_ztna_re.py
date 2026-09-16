"""
FortiClient certd daemon + libcertd.so ZTNA key management RE
Binaries:
  - extracted/forticlient-standalone-deb/opt/forticlient/certd (ELF64 PIE, stripped, 11MB, Rust)
  - extracted/forticlient-standalone-deb/opt/forticlient/libcertd.so (ELF64 shared, NOT stripped, 23MB, C++)
Method: semantic BERT sweep (ablation), nm symbol enumeration, strings analysis, capstone disasm
"""

# ---------------------------------------------------------
# Architecture overview
# ---------------------------------------------------------
CERTD_ARCH = {
    "id":       "CERTD-ARCH",
    "product":  "FortiClient certd daemon + libcertd.so -- ZTNA key management architecture",

    "certd_binary": {
        "path":     "/opt/forticlient/certd",
        "type":     "ELF64 PIE executable, x86-64, stripped",
        "language": "Rust (confirmed: Rust-mangled symbols in .dynstr, /rustc/ path strings)",
        "size":     "11MB",
        "tss2":     "TSS2 FAPI + ESYS statically linked (Fapi_CreateSeal, Fapi_Unseal, Fapi_Provision as GLOBAL FUNC exports)",
        "crypto":   "OpenSSL statically linked (ossl_* symbols, EVP_PKEY_sign_init)",
        "ipc":      "NNG (nanomsg-next-gen) statically linked -- nni_* symbols",
    },

    "libcertd_so": {
        "path":     "/opt/forticlient/libcertd.so",
        "type":     "ELF64 shared object, x86-64, NOT stripped (debug_info present)",
        "language": "C++ with Google Protobuf (tpm_msg namespace)",
        "size":     "23MB",
        "role":     "PKCS#11 client library; C_Sign, C_SignInit, etc. delegate to certd via NNG IPC",
    },

    "ipc_architecture": {
        "transport":    "NNG IPC socket at /var/run/forticlientcertd.ipc",
        "protocol":     "Google Protobuf (tpm_msg::Request / tpm_msg::Response)",
        "strategy":     "NNG REQ/REP (IPC::RequestStrategy / IPC::ReplyStrategy)",
        "credential":   "NNG ipc:peer-pid / IPC::Conn::GetPeerPid + GetPeerUid",
        "ipc_fn":       "send_message(tpm_msg::Request const&, tpm_msg::Response&) in libcertd.so",
    },

    "source_paths": [
        "src/certd/src/server/handlers.rs",
        "src/certd/src/server/server.rs",
        "src/certd/src/server/tpm/tpm.rs",
        "src/certd/src/server/pkcs11/pkcs11.rs",
        "src/certd/src/main.rs",
        "src/tss2-fapi/api/Fapi_CreateSeal.c",
        "src/tss2-fapi/api/Fapi_Unseal.c",
        "src/tss2-fapi/api/Fapi_ExportKey.c",
        "src/tss2-fapi/api/Fapi_Provision.c",
    ],
}


# ---------------------------------------------------------
# ZTNA key management: signing operations
# ---------------------------------------------------------
CERTD_ZTNA_SIGN = {
    "id":       "CERTD-ZTNA-SIGN",
    "product":  "certd ZtnaSign handler -- ZTNA attestation signing flow",

    "ipc_message_type":  "tpm_msg::Request_ZtnaSign / tpm_msg::Response_ZtnaSign",
    "pkcs11_entry":      "C_Sign (0xc1a20 in libcertd.so) -> C_SignInit (0xc16d0)",
    "ztna_token_label":  "fct-ztna-token (14 bytes; PKCS#11 token label for ZTNA slot)",
    "ztna_key_label":    "fct-ztna-key (12 bytes; PKCS#11 key label for ZTNA private key)",

    "signing_modes": {
        "rsa_pkcs":     "RSA PKCS#1 v1.5 (Request_ZtnaSign.rsa_pkcs field)",
        "rsa_pkcs_pss": "RSA-PSS (Request_ZtnaSign.rsa_pkcs_pss field)",
    },

    "sign_flow": (
        "1. FortiClient calls C_SignInit / C_Sign via libcertd.so PKCS#11 interface. "
        "2. libcertd.so populates tpm_msg::Request with Request_ZtnaSign payload. "
        "3. send_message() serializes and sends via NNG IPC to certd at /var/run/forticlientcertd.ipc. "
        "4. certd ZtnaSign handler (src/certd/src/server/handlers.rs) receives the request. "
        "5. Handler verifies caller UID via IPC::Conn::GetPeerUid (rejects with 'Rejecting ZtnaSign request from'). "
        "6. certd calls Fapi_Unseal to retrieve the sealed ZTNA private key from TPM. "
        "7. certd performs RSA sign operation using the unsealed private key. "
        "8. certd returns signature in tpm_msg::Response_ZtnaSign. "
        "9. libcertd.so returns the signature to the PKCS#11 caller."
    ),

    "software_fallback_in_sign": (
        "If Fapi_Unseal fails (TPM error, PCR mismatch, TPM not present): "
        "  'as we failed to unseal corresponding encryptor' + 'Loading: <fallback>' "
        "certd falls back to loading the ZTNA private key from a software encryptor "
        "(plaintext-on-disk or encrypted-on-disk). "
        "In the fallback path, the ZTNA signature is produced by software using a disk-stored key. "
        "The zero-trust claim that the private key is hardware-bound is FALSE in this code path."
    ),
}

CERTD_ZTNA_KEY = {
    "id":       "CERTD-ZTNA-KEY",
    "product":  "certd ZTNA key provisioning -- TPM seal and software fallback",

    "fapi_key_path":    "/HS/SRK/fct-ztna-key (FAPI sealed object under Storage Hierarchy/SRK)",
    "fapi_profile":     "P_RSA2048SHA256 (RSA-2048 / SHA-256; ECDSA not used for ZTNA signing)",
    "fapi_object_type": "Sealed object (Fapi_CreateSeal) -- private key blob sealed in TPM",

    "provisioning_flow": (
        "1. certd calls Fapi_Provision to initialize TPM FAPI context. "
        "   FAPI config at /opt/forticlient/tpm2/etc/tpm2-tss/fapi-config.json. "
        "   Profile dir: /opt/forticlient/tpm2/etc/tpm2-tss/fapi-profiles/. "
        "2. certd generates an RSA-2048 key pair (OpenSSL EVP). "
        "3. certd calls Fapi_CreateSeal(ctx, path, 'P_RSA2048SHA256', size, policyPath, authValue, privkey_blob). "
        "   policyPath: determines PCR binding -- see CERTD-F01. "
        "4. FAPI seals the private key blob under the SRK with the specified policy. "
        "5. The public key is stored separately (pem_ext_public / ems_cert.crt path)."
    ),

    "fapi_provision_restart": (
        "On startup, certd checks TPM state: "
        "'Re-provisioned FAPI as TPM state may have been corrupted.' "
        "If the FAPI metadata store is inconsistent with the actual TPM state, "
        "certd re-provisions (calls Fapi_Provision again). "
        "This re-provisioning deletes existing sealed objects and creates new ones. "
        "Implication: a sufficiently corrupted TPM state forces re-provisioning, "
        "which creates a NEW ZTNA key, invalidating the old attestation."
    ),
}


# ---------------------------------------------------------
# CERTD-F01: Software fallback bypasses TPM hardware binding (CRITICAL)
# ---------------------------------------------------------
CERTD_F01_TPM_FALLBACK = {
    "id":       "CERTD-F01",
    "product":  "certd -- TPM FAPI failure triggers software encryptor fallback",
    "severity": "HIGH -- software fallback defeats ZTNA hardware binding guarantee",
    "class":    "Insecure fallback / trust downgrade (CWE-636)",
    "source":   "src/certd/src/server/tpm/tpm.rs (confirmed via string: 'src/certd/src/server/tpm/tpm.rs')",

    "trigger_strings": [
        "TPM FAPI operation failed. Falling back to software encryptor.",
        "as we failed to unseal corresponding encryptor",
        "/proc/tpm is not available",
    ],

    "description": (
        "certd maintains two encryptor backends for ZTNA key operations: "
        "  1. TPM encryptor: uses Fapi_CreateSeal / Fapi_Unseal to store/retrieve the private key in hardware. "
        "  2. Software encryptor: stores the private key in a disk file (encrypted or plaintext). "
        "When the TPM backend fails -- FAPI error, TPM not present (/proc/tpm unavailable), "
        "PCR mismatch after firmware update, or TPM state corruption -- "
        "certd falls back to the software encryptor WITHOUT notifying the user or ZTNA policy engine. "
        "The ZTNA challenge-response signature is still produced, but from a software key. "
        "The ZTNA gateway accepts the signature (it verifies cryptographic correctness, not hardware binding). "
        "Result: ZTNA attestation operates as if TPM hardware binding is active, but it is not."
    ),

    "attack_scenarios": {
        "tpm_corruption": (
            "Attacker with local root access corrupts the FAPI metadata store "
            "(/opt/forticlient/tpm2/user/). "
            "Next ZTNA operation fails -> falls back to software encryptor. "
            "Attacker reads the software private key from disk. "
            "Attacker can now sign ZTNA challenges from any machine without the TPM."
        ),
        "tpm_removal": (
            "On a VM or cloud instance, /proc/tpm may be absent or emulated. "
            "certd detects 'Failed to read /dev/tpm0' and falls back to software. "
            "VM snapshot + key extraction -> ZTNA credential stolen."
        ),
        "firmware_update": (
            "Firmware update changes PCR values (PCR[7] for Secure Boot, PCR[0] for firmware). "
            "If Fapi_CreateSeal bound to PCRs, Fapi_Unseal fails after firmware update. "
            "certd falls back to software encryptor to maintain connectivity. "
            "This is the EXPECTED fallback path in enterprise environments. "
            "Any ZTNA connectivity requirement enforced via fallback = no TPM enforcement."
        ),
    },

    "re_evidence": (
        "String at VA 0x72d6de: 'TPM FAPI operation failed. Falling back to software encryptor.' "
        "String at VA 0x72c9fd: 'Loaded:  as we failed to unseal corresponding encryptor' "
        "String at VA 0x72d7c0: 'Failed to unseal' "
        "String at VA 0x72d7c0: 'TPM is not initialized due to some error.' "
        "String at VA 0x72d7c0: '/proc/tpm is not available'"
    ),
}


# ---------------------------------------------------------
# CERTD-F02: PCR policy binding unknown (requires runtime confirmation)
# ---------------------------------------------------------
CERTD_F02_PCR_BINDING_UNKNOWN = {
    "id":       "CERTD-F02",
    "product":  "certd -- ZTNA key PCR binding status unconfirmed",
    "severity": "HIGH if no PCR binding; LOW if PCR binding is present",
    "class":    "Insufficient TPM policy enforcement (CWE-345) -- unconfirmed",
    "source":   "src/certd/src/server/tpm/tpm.rs",

    "description": (
        "Fapi_CreateSeal(ctx, path, type, size, policyPath, authValue, data): "
        "  policyPath: if NULL, the sealed object has no PCR authorization policy. "
        "              The sealed object can be unsealed in ANY boot state (no firmware attestation). "
        "  policyPath: if non-NULL (e.g., '/policy/pcr_policy'), unsealing requires matching PCR values. "
        "The FAPI profiles (P_RSA2048SHA256) define a system_pcrs field that specifies PCRs "
        "but this only determines which PCRs the profile KNOWS ABOUT, not which are enforced. "
        "The actual PCR policy binding is determined by the policyPath argument at Fapi_CreateSeal time. "
        "Binary analysis: the Rust code at src/certd/src/server/tpm/tpm.rs calls Fapi_CreateSeal "
        "via function pointer (dlopen/dlsym pattern) rather than direct call -- "
        "static analysis cannot extract the policyPath argument value without runtime observation. "
        "String analysis: no policy path string (e.g., '/policy/pcr_seal') found in certd. "
        "This STRONGLY SUGGESTS policyPath is NULL (no PCR binding)."
    ),

    "implications_if_no_pcr": (
        "If policyPath=NULL in Fapi_CreateSeal: "
        "  - The ZTNA private key can be unsealed from ANY boot state. "
        "  - No attestation of firmware, bootloader, or OS integrity. "
        "  - Any process on the host with certd access (matching UID) can trigger signing. "
        "  - Combined with CERTD-F01 (software fallback): ZTNA = CRYPTOGRAPHIC AUTHENTICATION ONLY; "
        "    no hardware-rooted zero trust enforcement."
    ),

    "fapi_profile_note": (
        "FAPI config at /opt/forticlient/tpm2/etc/tpm2-tss/fapi-config.json: "
        "  system_pcrs: list of PCRs in the system profile. "
        "The FAPI profile P_RSA2048SHA256 from FortiClient specifies all 24 PCRs for SHA256 "
        "(from earlier analysis of fapi-profiles/*.json). "
        "BUT: listing PCRs in the profile != binding the seal to those PCRs. "
        "PCR binding requires an explicit TPM2_PolicyPCR object passed as policyPath."
    ),

    "confirmation_method": (
        "Runtime confirmation via strace or GDB on certd: "
        "  strace -e trace=read,write -p <certd_pid> "
        "  Observe the policyPath argument in Fapi_CreateSeal during key provisioning. "
        "Alternatively: extract /opt/forticlient/tpm2/user/ FAPI metadata "
        "and check if the sealed object has an authPolicy set (non-empty = PCR binding)."
    ),
}


# ---------------------------------------------------------
# CERTD-F03: ExportKey IPC method exposes private key material
# ---------------------------------------------------------
CERTD_F03_EXPORT_KEY = {
    "id":       "CERTD-F03",
    "product":  "certd -- Request_ExportKey IPC method exports private key material from TPM",
    "severity": "HIGH -- private key export from hardware if auth bypass is found",
    "class":    "Improper access control on key export operation (CWE-284)",
    "source":   "src/certd/src/server/handlers.rs",

    "ipc_message":  "tpm_msg::Request_ExportKey / tpm_msg::Response_ExportKey",
    "tss2_function": "Fapi_ExportKey (0x12c380 in certd)",

    "description": (
        "The certd IPC protocol includes a tpm_msg::Request_ExportKey message type "
        "that invokes Fapi_ExportKey. "
        "Fapi_ExportKey exports the FAPI key object including: "
        "  - For sealed objects: the sealed private key blob (encrypted under SRK). "
        "  - For native keys: the public key only (FAPI does not export private material directly). "
        "The handler at handlers.rs checks caller UID: "
        "  'Rejecting export_key request from UID: permission denied' "
        "  'failed to export key from tpm:' "
        "  'Failed to export key' "
        "The UID allowlist is not visible in static analysis -- could be root-only or wider. "
        "If the UID check is bypassable (e.g., via IPC socket access from a privileged process), "
        "an attacker could extract the sealed ZTNA private key blob. "
        "Even without direct key extraction: Fapi_ExportKey for a sealed object returns "
        "the TPM2B_PUBLIC of the SRK + the encrypted key blob -- which can be imported on "
        "another TPM if the SRK has no duplication policy."
    ),

    "re_evidence": (
        "String: 'Rejecting export_key request from' (src/certd/src/server/handlers.rs) "
        "String: 'failed to export key from tpm:' "
        "String: 'Failed to export key' "
        "Symbol: Fapi_ExportKey at 0x12c380 in certd "
        "Symbol: _ZN11forticlient2pb3tpm8Response14set_export_key... (Rust Response handler) "
        "String: 'Exported key is null' (Fapi_ExportKey returns null for some key types)"
    ),
}


# ---------------------------------------------------------
# CERTD-F04: IPC socket world-accessible; UID check is the only auth
# ---------------------------------------------------------
CERTD_F04_IPC_AUTH = {
    "id":       "CERTD-F04",
    "product":  "certd -- IPC socket authentication relies solely on Unix peer UID",
    "severity": "MEDIUM -- depends on OS UID isolation; SETUID escalation eliminates barrier",
    "class":    "Insufficient authentication on sensitive IPC channel (CWE-306)",
    "source":   "src/certd/src/server/server.rs",

    "ipc_socket":   "/var/run/forticlientcertd.ipc",
    "auth_method":  "NNG ipc:peer-pid / IPC::Conn::GetPeerUid -- Unix socket credential",

    "description": (
        "certd listens on a Unix socket at /var/run/forticlientcertd.ipc. "
        "Authentication is performed by reading the peer UID from the socket credential "
        "(SO_PEERCRED / NNG ipc:peer-pid option). "
        "The ZtnaSign handler rejects callers that don't match the allowed UID: "
        "  'Rejecting ZtnaSign request from' "
        "The ExportKey handler similarly checks UID: "
        "  'Rejecting export_key request from UID: permission denied' "
        "The allowed UID(s) are not visible in static analysis. "
        "If only a specific process UID (e.g., forticlient VPN daemon) is allowed: "
        "  1. A local process running as that UID can call ZtnaSign. "
        "  2. A SETUID binary or UID escalation vulnerability allows an unprivileged "
        "     attacker to obtain the allowed UID and make arbitrary IPC calls to certd. "
        "  3. certd provides no session-level authentication (no challenge-response, no token). "
        "The IPC::Conn::GetPeerPid is also available (peer PID check), "
        "but it's unclear whether certd validates the PID against /proc/<pid>/exe."
    ),

    "re_evidence": (
        "IPC::Conn::GetPeerPid (0xc4130 in libcertd.so) "
        "IPC::Conn::GetPeerUid (0xc40b0 in libcertd.so) "
        "String: 'ipc:peer-pid' (NNG peer credential option name) "
        "String: 'Failed to fetch peer pid' "
        "String: 'Rejecting ZtnaSign request from' "
        "String: 'Rejecting export_key request from UID: permission denied'"
    ),
}


# ---------------------------------------------------------
# libcertd.so: ExportKey as a PKCS#11 escalation path
# ---------------------------------------------------------
LIBCERTD_EXPORT_KEY_PKCS11 = {
    "id":       "LIBCERTD-EXPORT-KEY",
    "product":  "libcertd.so -- PKCS#11 key export interface available to any caller",

    "description": (
        "libcertd.so exposes the full PKCS#11 interface: "
        "  C_Initialize, C_GetFunctionList, C_OpenSession, C_Login, "
        "  C_Sign, C_SignInit, C_GenerateKey, C_GenerateKeyPair, etc. "
        "The C_GetMechanismList / C_GetMechanismInfo functions expose the supported mechanism list. "
        "Any process that loads libcertd.so (via LD_PRELOAD or direct link) "
        "gets access to the full PKCS#11 interface to certd's TPM key store. "
        "The auth check in certd is based on peer UID, so a process running as the "
        "allowed UID that loads libcertd.so can: "
        "  1. C_FindObjects to list available key objects. "
        "  2. C_GetAttributeValue to read key attributes. "
        "  3. C_Sign to trigger signing with the ZTNA key without going through FortiClient. "
        "This makes libcertd.so an UNAUTHORIZED SIGNING ORACLE for any process with the allowed UID."
    ),

    "symbols_of_interest": {
        "C_Initialize":      "0xbebb0 -- initializes libcertd PKCS#11 interface to certd IPC",
        "C_GetFunctionList": "0xbebf0 -- returns the full PKCS#11 function pointer table",
        "C_FindObjectsInit": "0xc0d00 -- begins key search with attribute template",
        "C_FindObjects":     "0xc1160 -- returns matching key handles",
        "C_Sign":            "0xc1a20 -- triggers ZtnaSign via certd",
        "C_GetAttributeValue": "0xc0960 -- reads key attributes",
    },
}


# ---------------------------------------------------------
# Semantic sweep results
# ---------------------------------------------------------
CERTD_SEMANTIC_SWEEP = {
    "id":       "CERTD-BERT-SWEEP",
    "binary":   "/opt/forticlient/certd",
    "method":   "BERT semantic sweep (all-MiniLM-L6-v2) on 5000 function prologues",
    "queries":  9,
    "note":     "Low similarity scores (0.3-0.5) due to stripped binary with inline Rust immediates",

    "hot_zone": "VA 0x2050xx - 0x206xxx: TSS2 marshaling/unmarshaling functions (Tss2_MU_TPMU_SIGNATURE_Marshal etc.)",
    "ipc_dispatch_candidate": "0x205187 (score 0.496 for IPC_DISPATCH query; has call targets to 0x2050ad)",
    "tpm2_policy_candidate":  "0x205ba2 (score 0.312 for TPM2_POLICYPCR query)",

    "key_finding": (
        "The BERT sweep correctly identified the TSS2 marshaling layer in certd (0x205xxx region). "
        "The business logic (Rust ZtnaSign handler) was NOT in the first 5000 prologues -- "
        "it is in the higher address range (Rust code starts much later in the binary). "
        "The string 'fct-ztna' is inlined as immediate operands (movabs rax, 0x616e747a2d746366) "
        "rather than rodata references -- standard Rust/LLVM optimization for short strings -- "
        "defeating the RIP-relative cross-reference scan technique."
    ),
}
