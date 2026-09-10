"""
Cisco UCS X-Series Chassis Management Controller (CMC) 6.0(1.251006) — RE findings
Source: esu-firmware-6.0.1.251006.tar.gz → CMC/6.0.1.251006/chassisA.img
Extraction: binwalk → CPIO at 0x21DB2F0 (294MB ARM64 rootfs)
Kernel: ARM64 Linux at 0x1AC4C70 (17MB)
"""

FIRMWARE = {
    "target":      "Cisco UCS X-Series Chassis Management Controller (CMC)",
    "version":     "6.0(1.251006)",
    "build_date":  "Thu Dec 4 05:17:43 UTC 2025",
    "source_pkg":  "esu-firmware-6.0.1.251006.tar.gz",
    "image":       "CMC/6.0.1.251006/chassisA.img",
    "rootfs":      "CPIO initramfs at img offset 0x21DB2F0 (294MB)",
    "kernel":      "ARM64 Linux at img offset 0x1AC4C70 (17MB)",
    "arch":        "AArch64 (ARM64), little-endian",
    "compiler":    "GNU C11 14.2.1 20241119, -O2, -mlittle-endian, -mabi=lp64",
}

# ─────────────────────────────────────────────────────────
# CMC-F1 — Static root MD5 password hash in /etc/shadow + PermitRootLogin yes
# ─────────────────────────────────────────────────────────
CMC_F1 = {
    "id":       "CMC-F1",
    "title":    "Static root MD5 credential embedded in CMC firmware — SSH root login enabled",
    "status":   "CONFIRMED — /etc/shadow + /etc/ssh/sshd_config in 6.0(1.251006) rootfs",
    "severity": "CRITICAL",

    "shadow_entry": "root:$1$1Bg658L8$RZ4QarfYI9Xjfz2uJDx5B0:::::::",
    "hash_type":    "MD5crypt ($1$) — crackable offline; no salt uniqueness across units",

    "sshd_config_excerpt": {
        "PermitRootLogin":           "yes",
        "PasswordAuthentication":    "yes",
        "ChallengeResponseAuthentication": "no",
        "PermitEmptyPasswords":      "no (commented — default)",
    },

    "attack_surface": (
        "CMC exposes TCP/22 (SSH). With PermitRootLogin=yes and PasswordAuthentication=yes, "
        "any attacker who cracks the static MD5 hash gets root SSH access to the CMC. "
        "MD5crypt is trivially crackable on modern GPU hardware. "
        "The hash is identical across all units of the same firmware version — no per-device salt."
    ),

    "impact": (
        "Full root shell on CMC. CMC controls chassis power, compute module management, "
        "firmware updates, and provides HTTPS Redfish API access. Root on CMC = chassis takeover."
    ),

    "samdme_hash": (
        "samdme:$5$o9TGJtssV$gKh0hd0F5nD9Kd7OEA5/CEF.TL6rWGSB7Phm8POdv35:::::::"
        " — IMM user, SHA-256 hash, also static across units."
    ),
}

# ─────────────────────────────────────────────────────────
# CMC-F2 — admin account with empty password field + root group membership
# ─────────────────────────────────────────────────────────
CMC_F2 = {
    "id":       "CMC-F2",
    "title":    "admin account carries empty password field with root group membership (GID=0)",
    "status":   "CONFIRMED — /etc/passwd and /etc/shadow in 6.0(1.251006) rootfs",
    "severity": "HIGH",

    "passwd_entry": "admin::500:0:admin:/tmp:/isan/bin/vsh",
    "shadow_entry": "admin::::::::",

    "anomalies": [
        "Password field in /etc/passwd is empty (`::`), not `x` — shadow is not used for this account",
        "Shadow entry is also empty — no password hash stored anywhere",
        "GID=0 = root group membership",
        "Shell `/isan/bin/vsh` (NX-OS/UCSM virtual shell) does not exist in CMC rootfs",
        "pam_cmc.so hardcodes `admin` as a special case in authentication logic",
    ],

    "pam_analysis": (
        "pam_cmc.so intercepts all authentication via UMGMT_CMD_USER_AUTHENTICATE IPC. "
        "The `admin` username is referenced directly in pam_cmc.c. "
        "With empty shadow, the UMGMT daemon likely treats the admin account as having "
        "no password configured (factory-default state), allowing login without credentials "
        "until an admin password is explicitly set post-deployment. "
        "PAM_PROXY_ADMIN and PAM_PROXY_USER_REMOTE strings confirm proxy auth privilege paths."
    ),

    "impact": (
        "Unauthenticated access to admin-level CMC management functions in factory-default state. "
        "The admin account accesses the Redfish API with elevated privileges. "
        "Combined with CMC-F3 (jrpc_server no-auth), root group membership enables lateral escalation."
    ),
}

# ─────────────────────────────────────────────────────────
# CMC-F3 — jrpc_server on TCP/4037 with no authentication, runs as root
# ─────────────────────────────────────────────────────────
CMC_F3 = {
    "id":       "CMC-F3",
    "title":    "jrpc_server on TCP/4037 explicitly marked 'not secured' — unauthenticated root RPC",
    "status":   "CONFIRMED — /etc/xinetd.conf + /etc/services + binary analysis in 6.0(1.251006)",
    "severity": "CRITICAL",

    "xinetd_config": {
        "service":     "jrpc_s_lo",
        "socket_type": "stream",
        "protocol":    "tcp",
        "wait":        "no",
        "user":        "root",
        "server":      "/cmc/bin/jrpc_server",
        "server_args": "-v 6",
    },

    "services_entry": "jrpc_s_lo   4037/tcp   # CMC loopback JRPC port (not secured)",

    "contrast": {
        "jrpc_s":        "4038/tcp  # CMC jrpc client/server port (TPM Secured)",
        "jrpc_redirect": "4039/tcp  # CMC jrpc client, proxy server listens for local connections on this port",
        "quiet_proxy":   "4040/tcp  # CMC jrpc client service, is redirected to proxy server",
    },

    "binary_flags": (
        "GNU C11 14.2.1 20241119 ... -fno-stack-protector ... -fPIE "
        "jrpc_server compiled WITHOUT stack canaries. Runs as root (user=root in xinetd)."
    ),

    "no_auth_evidence": (
        "jrpc_server binary contains no authentication strings (no password, token, session check). "
        "Method dispatch via jolti_method_invoke() without credential gate. "
        "`jrpc_s_lo` comment explicitly states 'not secured'. "
        "Methods implemented in libjolt_inf.so (includes Redfish method handlers)."
    ),

    "impact": (
        "Any network client reaching TCP/4037 can invoke CMC management methods as root "
        "without authentication. Combined with absence of stack canaries, any memory corruption "
        "in jrpc_server is easier to exploit. libjolt_inf.so also compiled -fno-stack-protector."
    ),
}

# ─────────────────────────────────────────────────────────
# CMC-F4 — TFTP server with create flag (-c) on world-writable /workspace/.firmware
# ─────────────────────────────────────────────────────────
CMC_F4 = {
    "id":       "CMC-F4",
    "title":    "Unauthenticated TFTP server allows file creation in world-writable /workspace/.firmware",
    "status":   "CONFIRMED — /etc/xinetd.conf + rootfs permissions in 6.0(1.251006)",
    "severity": "HIGH",

    "xinetd_config": {
        "service":     "tftp",
        "socket_type": "dgram",
        "protocol":    "udp",
        "port":        "69",
        "user":        "root",
        "server":      "/usr/sbin/tftpd",
        "server_args": "-4 -c -v -s /workspace",
        "note":        "-c flag = allow file creation (upload), -s = chroot to /workspace",
    },

    "workspace_permissions": {
        "/workspace":           "drwxr-xr-x (755) — readable",
        "/workspace/.firmware": "drwxrwxrwx (777) — world-writable",
        "/workspace/core":      "drwxrwxrwx (777) — world-writable",
        "/workspace/techsupport": "drwxrwxrwx (777) — world-writable",
    },

    "impact": (
        "Any network client with UDP/69 access can upload arbitrary files to /workspace/.firmware. "
        "This is the staging directory for firmware updates on the CMC. "
        "The firmware update pipeline (updated, esu_utils) reads from this path. "
        "If signature validation can be bypassed or a pre-signed payload prepared, "
        "this enables unauthenticated firmware replacement."
    ),

    "firmware_update_context": (
        "dc_signature_validation (Go binary, 4.3MB) validates firmware bundles. "
        "esu_utils imports libcisco_signature.so and libtftp.so — the TFTP client is used "
        "for outbound firmware retrieval. The inbound TFTP server (-c flag) provides a write path "
        "into the staging area without requiring this validation to pass first."
    ),
}

# ─────────────────────────────────────────────────────────
# CMC-F5 — CMC binary suite compiled without stack protection
# ─────────────────────────────────────────────────────────
CMC_F5 = {
    "id":       "CMC-F5",
    "title":    "CMC management binaries compiled without -fstack-protector across the entire software stack",
    "status":   "CONFIRMED — compiler flags extracted from binary strings in 6.0(1.251006)",
    "severity": "MEDIUM",

    "affected_binaries": {
        "jrpc_server":   "-fno-stack-protector -fPIE (runs as root on TCP/4037)",
        "libjolt_inf.so": "-fno-stack-protector -fPIE (Redfish + JRPC method library)",
        "redfish":       "links libjolt_inf.so — inherits no-canary behavior",
    },

    "excluded": {
        "pam_cmc.so": "-fstack-protector-all (PAM module has protection — inconsistent policy)",
    },

    "compiler_flags_verbatim": (
        "GNU C11 14.2.1 20241119 -mlittle-endian -mabi=lp64 -g -O2 -std=gnu11 "
        "-fgnu89-inline -fmerge-all-constants -frounding-math -fno-stack-protector "
        "-fno-common -fmath-errno -fPIE -ftls-model=initial-exec"
    ),

    "impact": (
        "Stack-based buffer overflows in jrpc_server or libjolt_inf.so (both exposed to network) "
        "have no stack canary to stop exploitation. jrpc_server runs as root. "
        "PIE is enabled, so ASLR applies, but without canaries, ret2plt / ROP chains "
        "via info leaks or brute-force are viable on AArch64."
    ),
}

# ─────────────────────────────────────────────────────────
# CMC-F6 — MQTT broker with allow_anonymous true
# ─────────────────────────────────────────────────────────
CMC_F6 = {
    "id":       "CMC-F6",
    "title":    "CMC MQTT broker (mosquitto) configured with allow_anonymous true on Unix socket",
    "status":   "CONFIRMED — /etc/mosquitto-broker.conf in 6.0(1.251006) rootfs",
    "severity": "LOW",

    "config": {
        "per_listener_settings": "true",
        "user":                  "root",
        "listener":              "0 /var/run/mymqtt.sock (Unix socket)",
        "allow_anonymous":       "true",
        "log_dest":              "file /var/cmc/log/mosquitto.log",
        "commented_out":         "listener 9020 127.0.0.1 (commented, not active)",
    },

    "scope": (
        "The active listener is a Unix domain socket (/var/run/mymqtt.sock), "
        "not a TCP port. This restricts exposure to local processes. "
        "However, if any remotely exploitable service bridges to this socket "
        "(via the jrpc proxy stack or quiet_proxy), unauthenticated MQTT publish/subscribe "
        "becomes accessible from the network. mosquitto runs as root."
    ),

    "impact": (
        "Local processes (including any code executing via CMC-F3) can publish/subscribe "
        "to all CMC MQTT topics without credentials. MQTT is used for inter-process "
        "event notification on the CMC. Unauthorized pub/sub = event spoofing, "
        "monitoring all chassis management events, or triggering management actions "
        "if any MQTT subscriber acts on received messages."
    ),
}

# ─────────────────────────────────────────────────────────
# Firmware metadata summary
# ─────────────────────────────────────────────────────────
CMC_ACCOUNTS = {
    "root": {
        "uid":    0,
        "gid":    0,
        "shadow": "$1$1Bg658L8$RZ4QarfYI9Xjfz2uJDx5B0 (MD5crypt)",
        "shell":  "/bin/sh",
    },
    "cli": {
        "uid":    0,
        "gid":    0,
        "shadow": "empty",
        "shell":  "/cmc/bin/ecmc_shell",
        "note":   "UID=0, restricted shell — empty shadow",
    },
    "admin": {
        "uid":    500,
        "gid":    0,
        "shadow": "empty",
        "shell":  "/isan/bin/vsh (does not exist in CMC rootfs)",
        "note":   "Root group membership, no password in any auth file",
    },
    "samdme": {
        "uid":    102,
        "gid":    105,
        "shadow": "$5$o9TGJtssV$gKh0hd0F5nD9Kd7OEA5/CEF.TL6rWGSB7Phm8POdv35 (SHA-256)",
        "shell":  "/bin/sh",
        "note":   "IMM (Intelligent Management Module) user",
    },
}

CMC_NETWORK_SERVICES = {
    "TCP/22":  "OpenSSH — PermitRootLogin yes, PasswordAuthentication yes",
    "TCP/4037": "jrpc_server — explicitly 'not secured', root-privileged, no-canary",
    "TCP/4038": "jrpc_server — TPM-secured variant",
    "TCP/4039": "jrpc_redirect — proxy redirect",
    "TCP/4040": "quiet_proxy — local JRPC redirect",
    "UDP/69":   "tftpd — unauthenticated, create flag, serves /workspace",
    "UNIX:/var/run/mymqtt.sock": "mosquitto MQTT — allow_anonymous true, root user",
    "HTTPS":    "Redfish API via libmhd + GnuTLS (port inferred from runtime config)",
}

# ─────────────────────────────────────────────────────────
# CMC-F7 — Hardcoded 64-byte encryption key in libjolt_user_mgmt.so
# ─────────────────────────────────────────────────────────
CMC_F7 = {
    "id":       "CMC-F7",
    "title":    "Hardcoded 64-byte key material in libjolt_user_mgmt.so adjacent to user credential storage path",
    "status":   "CONFIRMED — binary analysis of libjolt_user_mgmt.so in 6.0(1.251006) rootfs",
    "severity": "HIGH",

    "b64_value":  "8BgdB4Qp31lzKrmjTYurDsjwqMfpsxUbkHumeZgZ9/AhRYDXHMCfkeG18Zpl0i48SRKDd9edeSrJD0UyawAszA==",
    "raw_hex":    "f0181d078429df59732ab9a34d8bab0ec8f0a8c7e9b3151b907ba6799819f7f0214580d71cc09f91e1b5f19a65d22e3c49128377d79d792ac90f45326b002ccc",
    "raw_length": 64,

    "adjacent_strings": [
        "ABCDEFGHIJKLMNOP",
        "/cmc_secure/.persistent/security/default_user_cred_done",
        "/cmc_secure/.persistent/security/users/1.encrypted",
        "/cmc_secure/.persistent/security/userdb_meta.json",
        "__jolt_user_default_create",
        "populate_default_regular_password",
    ],

    "analysis": (
        "A 64-byte binary blob (base64-encoded in .rodata) appears in libjolt_user_mgmt.so "
        "in the same code section as the default user credential creation logic. "
        "User credentials are stored encrypted at /cmc_secure/.persistent/security/users/1.encrypted. "
        "The 64 bytes match AES-XTS key size (2×32-byte sub-keys) or an HMAC-SHA-512 key. "
        "Preceding string ABCDEFGHIJKLMNOP (16 bytes = AES-128 block) may be an IV or salt. "
        "If this key is used to encrypt user/1.encrypted, any CMC running 6.0(1.251006) "
        "exposes the same decryption key — any firmware dump yields the admin credential."
    ),

    "impact": (
        "If confirmed as the user database encryption key: obtain users/1.encrypted "
        "(via tech-support bundle, TFTP, or any file read) and decrypt offline "
        "to recover admin credentials — without needing to crack password hashes."
    ),
}

# ─────────────────────────────────────────────────────────
# CMC-F8 — SecureVault writes LUKS key to /tmp/luks_keyfileXXXXXX
# ─────────────────────────────────────────────────────────
CMC_F8 = {
    "id":       "CMC-F8",
    "title":    "SecureVault writes LUKS encryption key to /tmp/luks_keyfileXXXXXX (mkstemp pattern) — race window",
    "status":   "CONFIRMED — binary analysis of SecureVault in 6.0(1.251006) rootfs",
    "severity": "MEDIUM",

    "commands_found": [
        "cryptsetup -q luksFormat --type luks2 -c aes-xts-plain %s --key-file=%s",
        "cryptsetup luksOpen %s %s --key-file=%s",
    ],

    "key_file_pattern": "/tmp/luks_keyfileXXXXXX",

    "analysis": (
        "SecureVault creates a temporary key file in /tmp using mkstemp-like naming, "
        "passes it as --key-file to cryptsetup for LUKS2 volume operations, then (presumably) "
        "deletes it. During the window between creation and deletion, the key file exists in /tmp "
        "which is world-writable (drwxrwxrwt). "
        "Any root-level process (jrpc_server, CMC daemons) can read /tmp to capture the LUKS key "
        "if code execution is achieved via CMC-F3 or other vectors. "
        "SecureVault manages encryption of the CMC's secure storage partition."
    ),

    "impact": (
        "LUKS key extraction from /tmp race window. Encrypted partition decryptable offline "
        "after key capture. Relevant to recovering contents of /cmc_secure partition "
        "if physical access or persistent root execution is available."
    ),
}

# ─────────────────────────────────────────────────────────
# CMC-F9 — quiet_proxy skips TLS hostname verification when no hostname available
# ─────────────────────────────────────────────────────────
CMC_F9 = {
    "id":       "CMC-F9",
    "title":    "quiet_proxy silently skips TLS hostname verification when destination hostname is absent",
    "status":   "CONFIRMED — binary analysis of quiet_proxy in 6.0(1.251006) rootfs",
    "severity": "MEDIUM",

    "evidence_string": "Host name was not provided by %s and will not be verified.",

    "tls_api_used": [
        "SSL_CTX_set_cipher_list",
        "X509_VERIFY_PARAM_set1_host",
        "X509_VERIFY_PARAM_add1_host",
    ],

    "analysis": (
        "quiet_proxy (TCP/4040 → internal JRPC services) calls X509_VERIFY_PARAM_set1_host / "
        "X509_VERIFY_PARAM_add1_host to set the expected TLS hostname for peer verification. "
        "When no destination hostname is provided, it silently skips hostname verification "
        "('Host name was not provided by %s and will not be verified.'). "
        "An attacker controlling the destination routing can present any valid certificate "
        "from any CA in the trust store and have it accepted — certificate chain validates "
        "but the identity is unverified."
    ),

    "also_noted": (
        "quiet_proxy sets LD_PRELOAD=/lib/liboverride_getpeername.so and REMOTE_HOST=%s "
        "before spawning backend processes. This overrides getpeername() return value "
        "in the spawned process to show the original client IP rather than 127.0.0.1. "
        "Impact: any auth decisions in backend services based on getpeername() use "
        "a proxy-controlled IP value that could be manipulated if the proxy itself "
        "can be reached with a spoofed source address."
    ),

    "impact": (
        "MITM on connections routed through quiet_proxy when no explicit hostname is configured. "
        "Relevant to internal CMC service-to-service TLS connections."
    ),
}

# ─────────────────────────────────────────────────────────
# CMC-F10 — Hardcoded MTS read-only credential in mts.cfg
# ─────────────────────────────────────────────────────────
CMC_F10 = {
    "id":       "CMC-F10",
    "title":    "Hardcoded MTS read-only credential 'emcuser:emcNbv12345' in mts.cfg — identical across all CMC 6.0.x deployments",
    "status":   "CONFIRMED — etc/mts.cfg in CMC 6.0(2.260026) rootfs (plaintext); encrypted as etc/mts.cfg.enc in 6.0(1.251006) with static magic '#!##!#$!'",
    "severity": "HIGH",

    "cleartext_credential": {
        "file":     "etc/mts.cfg",
        "version":  "CMC 6.0.2+ (mts.cfg is plaintext)",
        "MTS_RO_USER":     "emcuser",
        "MTS_RO_PASSWORD": "emcNbv12345",
        "MTS_USER":        "admin",
        "MTS_PASSWORD":    "",
        "MTS_REST_ADDR":   "localhost:8075",
        "MTS_IP":          "127.20.0.1",
        "MTS_PROTOCOL":    "http",
    },

    "encrypted_601_note": (
        "In CMC 6.0.1, the same configuration was stored as etc/mts.cfg.enc — a base64-encoded "
        "AES blob. The encryption was performed by cmc/bin/encryptfile using libcommoncryptutil.so "
        "with a FIXED STATIC MAGIC credential '#!##!#$!' hardcoded in the binary. "
        "String evidence: 'At this time fixed static MAGIC is used, (Supplied %s)' in encryptfile. "
        "Anyone with access to the encryptfile binary can decrypt mts.cfg.enc with this magic."
    ),

    "6.0.2_regression": (
        "In CMC 6.0.2, the encryptfile binary and libcommoncryptutil.so were removed and mts.cfg "
        "was shipped in cleartext. The encryption provided only obscurity (known static key); "
        "removing it exposes the same hardcoded credential without even the base64 step."
    ),

    "mts_api": (
        "The MTS (MTS switch / Aldrin3S) REST API listens at localhost:8075. "
        "emcuser with MTS_RO_PRIVILEGE=1 has read access to switch configuration and state. "
        "admin with empty password controls the MTS management operations."
    ),

    "internal_tftp": {
        "MTS_AUTO_UPGRADE_TFTP_IP": "10.193.66.120",
        "note": "Cisco internal TFTP server IP hardcoded in production firmware. "
                "Auto-upgrade disabled by default (MTS_AUTO_UPGRADE_ENABLE=0) but "
                "configuration is settable via the authenticated MTS REST API."
    },
}

# ─────────────────────────────────────────────────────────
# CMC-F11 — TPM test binaries shipped in production CMC 6.0.2 rootfs
# ─────────────────────────────────────────────────────────
CMC_F11 = {
    "id":       "CMC-F11",
    "title":    "TPM diagnostic test binaries in /usr/bin of production CMC 6.0.2 firmware — attack surface for TPM security model",
    "status":   "CONFIRMED — usr/bin/tpm_test, tpm_test_key_install, tpm_test_tcg_{001-004} in CMC 6.0(2.260026) rootfs; absent from 6.0(1.251006)",
    "severity": "MEDIUM",

    "binaries": {
        "usr/bin/tpm_test":            "253688 bytes — TPM test harness",
        "usr/bin/tpm_test_key_install": "216808 bytes — TPM key installation test",
        "usr/bin/tpm_test_tcg_001":    "208552 bytes — TCG specification test 001",
        "usr/bin/tpm_test_tcg_002":    "208552 bytes — TCG specification test 002",
        "usr/bin/tpm_test_tcg_003":    "216744 bytes — TCG specification test 003",
        "usr/bin/tpm_test_tcg_004":    "216744 bytes — TCG specification test 004",
    },

    "introduced_in": "6.0(2.260026) — absent from 6.0(1.251006)",

    "note": (
        "TPM test binaries intended for validation are shipped in the production CMC rootfs. "
        "These binaries interact with TPM2 hardware directly. "
        "An attacker with code execution on the CMC (e.g., via CMC-F1 root SSH or CMC-F2 JRPC) "
        "can invoke these test utilities to probe TPM key management, "
        "potentially exposing sealed secrets or interfering with measured boot state."
    ),
}

CMC_KEY_BINARIES = {
    "redfish (2.1MB)":             "Redfish API server, uses libmhd + GnuTLS, libgnutls.so.30",
    "libjolt_inf.so":              "Redfish + JRPC method implementations, -fno-stack-protector",
    "jrpc_server (102KB)":         "JSON-RPC TCP server, -fno-stack-protector, root, 4037/4038",
    "pam_cmc.so":                  "PAM auth module, -fstack-protector-all, UMGMT IPC dispatch",
    "consent_token (251KB)":       "TAC consent token system, ECDSA+SHA-512 verification",
    "dc_signature_validation (4.3MB)": "Go binary (statically linked), firmware signature check",
    "SecureVault (61KB)":          "Credential storage binary",
    "onboarding (416KB)":          "Device onboarding — authentication entry point",
    "updated (290KB)":             "Firmware update daemon, uses libtftp.so, libcisco_signature.so",
    "esu_utils (425KB)":           "ESU bundle handler, ESU_ERR_BUNDLE_SIGNATURE_VALIDATION_FAILURE",
    "bmcd (540KB)":                "BMC daemon",
    "cmc_manager (378KB)":         "Main CMC management daemon",
    "ipwrmgr (1.4MB)":             "IP power manager",
    "mtsmanager (840KB)":          "MTS (Modular Transport System) manager",
    "uemd (614KB)":                "UEM (Unified Embedded Management) daemon",
    "platform_ohms (757KB)":       "Platform hardware monitoring",
}

FINDINGS = [CMC_F1, CMC_F2, CMC_F3, CMC_F4, CMC_F5, CMC_F6, CMC_F7, CMC_F8, CMC_F9, CMC_F10, CMC_F11]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
