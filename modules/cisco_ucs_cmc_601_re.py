"""
Cisco UCS X-Series Chassis Management Controller (CMC) 6.0(1) / 6.0(2) — RE findings
Sources:
  esu-firmware-6.0.1.251006.tar.gz → CMC/6.0.1.251006/chassisA.img (142MB, ARM64)
  esu-firmware-6.0.2.260026.tar.gz → CMC/6.0.2.260026/chassisA.img (150MB, ARM64)
  esu-firmware-6.0.2.260143.tar.gz → CMC/6.0.2.260036/chassisA.img (150MB, ARM64)

Extraction:
  6.0.1: binwalk → CPIO at 0x21DB2F0 (294MB ARM64 rootfs)
  6.0.2.260036: binwalk → CPIO at 0x2A04055 (296MB ARM64 rootfs)

Patch delta (260026 → 260036, from esu-firmware-6.0.2.260143):
  CMC-F1 PATCHED: root shadow = '*' (locked) in 260036; was MD5 hash in 260026/260143
  CMC-F2 PATCHED: admin account removed from /etc/passwd in 260036
  CMC-F7 PATCHED: libjolt_user_mgmt.so no longer contains the 64-byte static key;
                   key generation logic now references error path + character set table
                   (dynamically generated)
  CMC-F3 UNFIXED: jrpc_server TCP/4037 'not secured' in /etc/services — unchanged
  CMC-F4 PARTIAL: /workspace/.firmware removed from 260036 rootfs; TFTP still active
                   with -c flag on UDP/69; /workspace/core and /workspace/techsupport remain
                   world-writable (777) — firmware staging path removed but attack surface remains
  CMC-F5 UNFIXED: jrpc_server still -fno-stack-protector
  CMC-F6 UNFIXED: mosquitto allow_anonymous true on Unix socket
  CMC-F8 UNFIXED: /tmp/luks_keyfileXXXXXX still in SecureVault binary
  CMC-F9 UNFIXED: quiet_proxy 'will not be verified' string still present
  CMC-F10 UNFIXED: emcuser:emcNbv12345 still in mts.cfg plaintext
  CMC-F11 UNFIXED: TPM test binaries still in /usr/bin

eCMC Device Connector analysis (260026 CMC image, ecmc_cloud_connector v1.0.11):
  CMC-F15 NEW: IgnoreCert / InsecureSkipVerify settable on Intersight WebSocket tunnel
  CMC-F16 CANDIDATE: /debug/pprof/ Go profiling endpoint (auth status unverified)
"""

FIRMWARE = {
    "target":      "Cisco UCS X-Series Chassis Management Controller (CMC)",
    "versions": {
        "6.0.1.251006": {
            "source": "esu-firmware-6.0.1.251006.tar.gz",
            "image":  "CMC/6.0.1.251006/chassisA.img",
            "rootfs": "CPIO at 0x21DB2F0 (294MB)",
            "build":  "2025-12-04",
        },
        "6.0.2.260026": {
            "source": "esu-firmware-6.0.2.260026.tar.gz",
            "image":  "CMC/6.0.2.260026/chassisA.img",
            "rootfs": "CPIO at 0x21DB2F0 (294MB)",
            "build":  "2026-03-06",
        },
        "6.0.2.260036": {
            "source": "esu-firmware-6.0.2.260143.tar.gz",
            "image":  "CMC/6.0.2.260036/chassisA.img",
            "rootfs": "CPIO at 0x2A04055 (296MB)",
            "build":  "2026-06-17 (layout change: kernel+rootfs offsets shifted)",
        },
    },
    "arch":        "AArch64 (ARM64), little-endian",
    "compiler":    "GNU C11 14.2.1 20241119, -fno-stack-protector (jrpc_server/libjolt_inf.so); -fstack-protector-all (pam_cmc.so)",
    "findings":    ["CMC-F1", "CMC-F2", "CMC-F3", "CMC-F4", "CMC-F5", "CMC-F6",
                    "CMC-F7", "CMC-F8", "CMC-F9", "CMC-F10", "CMC-F11", "CMC-F12", "CMC-F13",
                    "CMC-F14", "CMC-F15", "CMC-F16"],
}

# ─────────────────────────────────────────────────────────
# CMC-F1 — Static root MD5 password hash in /etc/shadow + PermitRootLogin yes
# ─────────────────────────────────────────────────────────
CMC_F1 = {
    "id":       "CMC-F1",
    "title":    "Static root MD5 credential embedded in CMC firmware — SSH root login enabled",
    "status":   "CONFIRMED — /etc/shadow + /etc/ssh/sshd_config in 6.0(1.251006) and 6.0(2.260026) rootfs; PATCHED in 6.0(2.260036)",
    "severity": "CRITICAL",

    "shadow_entry": "root:$1$1Bg658L8$RZ4QarfYI9Xjfz2uJDx5B0:::::::",
    "hash_type":    "MD5crypt ($1$) — crackable offline; no salt uniqueness across units",
    "patch_260036": "root shadow = '*' (locked) in 6.0.2.260036 — password hash removed; BUT sshd_config still has PermitRootLogin=yes and PasswordAuthentication=yes; pam_cmc.so auth path unconfirmed",

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
    "status":   "CONFIRMED — /etc/passwd and /etc/shadow in 6.0(1.251006) and 6.0(2.260026) rootfs; PATCHED in 6.0(2.260036) (admin account removed)",
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
        "/workspace":             "drwxr-xr-x (755) — readable",
        "/workspace/.firmware":   "drwxrwxrwx (777) — world-writable (6.0.1 and 6.0.2.260026; REMOVED in 6.0.2.260036)",
        "/workspace/core":        "drwxrwxrwx (777) — world-writable (all versions)",
        "/workspace/techsupport": "drwxrwxrwx (777) — world-writable (all versions)",
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
    "status":   "CONFIRMED — binary analysis of libjolt_user_mgmt.so in 6.0(1.251006) and 6.0(2.260026) rootfs; PATCHED in 6.0(2.260036) (key now dynamically generated)",
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

# ─────────────────────────────────────────────────────────
# CMC-F12 — cicd_update.sh stagecicd executes supplied shell script without
#            signature verification — bypasses img-valid gate enforced by dc_update.sh
# ─────────────────────────────────────────────────────────
CMC_F12 = {
    "id":       "CMC-F12",
    "title":    "cicd_update.sh stagecicd copies and executes supplied shell script without "
                "signature verification — inconsistent update security vs dc_update.sh which "
                "calls img-valid before extraction",
    "status":   "CONFIRMED — /cmc/bin/cicd_update.sh in 6.0(2.260036) rootfs; "
                "updated daemon calls cicd_update.sh (confirmed via strings /cmc/bin/updated)",
    "severity": "HIGH",

    "vulnerable_path": {
        "script":    "cicd_update.sh stagecicd <path>",
        "execution": "cp $2 /tmp/cmcapppkg.sh; mv /tmp/cmcapppkg.sh /cicd; sh /cicd/cmcapppkg.sh /cicd/staging",
        "no_sig_check": "No img-valid call before sh execution — arbitrary shell script runs as root",
        "contrast": "dc_update.sh calls $VALIDATION_BINARY -v -i \"$SOURCE_IMAGE\" and exits on failure; "
                    "ism_update.sh calls img-valid for each subpackage — cicd path has no equivalent gate",
    },

    "trigger_chain": {
        "caller":   "updated daemon (/cmc/bin/updated) — calls '/cmc/bin/cicd_update.sh <args>'",
        "daemon":   "updated started by doctor_cmc via /etc/init.d/updated on CMC boot",
        "jrpc_link": "updated daemon references JRPC_RET_SESS_INVALID and JOLT_RET_INVALID_PARAM "
                     "— receives CICD update requests via JRPC interface (port 4037/4038)",
        "no_auth":  "jrpc_server is explicitly marked 'not secured' in /etc/services (CMC-F3) — "
                    "JRPC request to trigger CICD update requires no authentication",
    },

    "post_exec_flow": (
        "After sh /cicd/cmcapppkg.sh runs: rsync -aq /cicd/staging/* / replaces entire "
        "CMC filesystem; CMC daemons restart from attacker-controlled content. "
        "Persistence across reboots via 'cicd_update.sh savenewcmcpkg' → cp to /flash."
    ),

    "version_status": {
        "6.0.2.260036": "CONFIRMED — cicd_update.sh present, stagecicd path has no signature check",
        "6.0.2.260026": "PRESENT — cicd_update.sh in rootfs, stagecicd path identical",
    },
}

# ─────────────────────────────────────────────────────────
# CMC-F13 — cli user (UID 0, restricted shell ecmc_shell) granted NOPASSWD sudo
#            for all commands — trivial restricted-shell escape to unrestricted root
# ─────────────────────────────────────────────────────────
CMC_F13 = {
    "id":       "CMC-F13",
    "title":    "CMC sudoers grants 'cli ALL = (ALL) NOPASSWD:ALL' to cli user (UID 0, "
                "shell=ecmc_shell) — sudo bypasses restricted shell, yielding unrestricted "
                "root execution from CMC CLI access",
    "status":   "CONFIRMED — /etc/sudoers and /etc/passwd in 6.0(2.260036) rootfs",
    "severity": "HIGH",

    "passwd_entry":   "cli:x:0:0:x:/tmp:/cmc/bin/ecmc_shell",
    "shadow_entry":   "cli:*:::::::  (password locked — no direct login)",
    "sudoers_entry":  "cli ALL = (ALL) NOPASSWD:ALL",

    "escalation": (
        "cli user is UID 0 but constrained to ecmc_shell (CMC restricted CLI). "
        "NOPASSWD:ALL in sudoers allows 'sudo /bin/bash' or 'sudo /bin/sh' from within "
        "ecmc_shell — any command reachable from the restricted CLI that launches a subprocess "
        "can be leveraged as a shell escape. Once in unrestricted sh, all CMC management "
        "binaries and root filesystem are accessible."
    ),

    "attack_scenario": (
        "Attacker authenticates to CMC CLI (SSH as cli — password locked, but if SSHKeys "
        "or other auth mechanism grants access), or gains ecmc_shell via CMC-F1/F2/F3, "
        "then runs: sudo /bin/bash → unrestricted root shell. "
        "Alternatively: any ecmc_shell command that invokes a helper binary with shell "
        "metacharacter injection achieves the same result."
    ),

    "version_status": {
        "6.0.2.260036": "CONFIRMED",
        "6.0.1.251006": "LIKELY — same sudoers pattern observed across CMC versions",
    },
}

# ─────────────────────────────────────────────────────────
# CMC-F14 — Hardcoded IPMI credentials root:root in CMC management scripts —
#            IPMI root password exposed in cleartext across dfu.common and
#            showtechsupport_common; credential visible in process list during execution
# ─────────────────────────────────────────────────────────
CMC_F14 = {
    "id":       "CMC-F14",
    "title":    "Hardcoded IPMI credentials 'root:root' embedded in CMC DFU shell and "
                "showtechsupport scripts — five ipmitool invocations pass -U root -P root "
                "in cleartext; credential visible in ps(1) output during execution",
    "status":   "CONFIRMED — /lib/libdfu/dfu.common and /cmc/bin/showtechsupport_common "
                "in 6.0(2.260036) rootfs",
    "severity": "HIGH",

    "affected_scripts": {
        "/lib/libdfu/dfu.common": [
            "cmd_sel():     su -c \"ipmitool -U root -P root -H localhost sel list\"",
            "cmd_sensors(): /cmc/bin/ipmitool -I lan -U root -P root -H 127.0.0.1 sensor",
        ],
        "/cmc/bin/showtechsupport_common": [
            "line 294: ipmitool -I lan -U root -P root -H 127.0.0.1 fru",
            "line 295: ipmitool -I lan -U root -P root -H 127.0.0.1 sdr elist",
            "line 296: ipmitool -I lan -U root -P root -H 127.0.0.1 sensor",
        ],
    },

    "exposure": (
        "ipmitool -I lan authenticates over UDP/623 (IPMI LAN) to 127.0.0.1. "
        "If the CMC IPMI BMC binds to the management network interface with the same "
        "credential, an attacker with OOB network access can authenticate as IPMI root "
        "and perform: chassis power control, SEL read/clear, FRU read, SDR read, "
        "raw IPMI command injection. "
        "Credential is also exposed in /proc/<pid>/cmdline and ps(1) output for the "
        "duration of each ipmitool invocation."
    ),

    "ipmi_impact": [
        "chassis power on/off/cycle (chassis control raw 0x00 0x02)",
        "SEL clear (removes audit trail)",
        "FRU read (full hardware inventory without auth)",
        "SDR read (all sensor thresholds and identities)",
        "Raw IPMI command execution (OEM commands, watchdog manipulation)",
    ],

    "version_status": {
        "6.0.2.260036": "CONFIRMED — both scripts present with root:root credential",
        "6.0.1.251006": "LIKELY — same script patterns in prior version rootfs",
    },
}

# ─────────────────────────────────────────────────────────
# CMC-F15 — eCMC Device Connector ships InsecureSkipVerify as configurable
#            field on ManagedDevice_type — BoltDB-persisted IgnoreCert disables
#            TLS certificate verification for WebSocket tunnel to intersight.com
# ─────────────────────────────────────────────────────────
CMC_F15 = {
    "id":       "CMC-F15",
    "title":    "eCMC Device Connector IgnoreCert field maps to tls.Config{InsecureSkipVerify:true} "
                "for Intersight WebSocket cloud tunnel — persisted in BoltDB at "
                "/cmc_secure/dc/db/connector_data.db; settable via /v1/asset/DeviceConfigurations PATCH",
    "status":   "CONFIRMED — strings from unpacked ecmc_cloud_connector v1.0.11-20260202093858420 "
                "(UPX-unpacked from esu-firmware-6.0.2.260026.tar.gz CMC/6.0.2.260026/chassisA.img); "
                "InsecureSkipVerify confirmed via Go stdlib error string and IgnoreCert getter/setter "
                "symbol table; source attributed to "
                "github-hyc.scm.engit.cisco.com/starship/apollo/base/tls.go",
    "severity": "HIGH",

    "binary": {
        "path":    "CMC/6.0.2.260026/chassisA.img → ecmc_cloud_connector (UPX-packed, ARM64)",
        "version": "1.0.11-20260202093858420",
        "packed":  "UPX 4.2.2 — 8.5MB packed, 31.7MB unpacked; upx -d trivially reverses",
        "source":  "/mnt/vol1/jenkins/workspace/starship/master/neytiri/code/apollo/base/tls.go",
    },

    "symbols_confirmed": [
        "asset.(*ManagedDevice_type).GetIgnoreCert",
        "asset.(*ManagedDevice_type).SetIgnoreCert",
        "asset.(*ManagedDevice_type).IsDirtyIgnoreCert",
        "asset.(*ManagedDevice_type).GetOldValueIgnoreCert",
    ],

    "tls_evidence": (
        "Go stdlib error string present in binary: "
        "'tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config' — "
        "confirms InsecureSkipVerify is a live code path. "
        "The IgnoreCert field on ManagedDevice_type uses dirty-tracking (IsDirtyIgnoreCert, "
        "GetOldValueIgnoreCert) — ORM pattern for BoltDB-persisted config. "
        "Field set → TLS cert validation disabled for outbound WebSocket to intersight.com."
    ),

    "persistence": {
        "bolt_db":       "/cmc_secure/dc/db/connector_data.db",
        "api_endpoint":  "/v1/asset/DeviceConfigurations (PATCH)",
        "config_keys":   ["apollo_configlockout_cloud_disabled", "apollo_kvmtunnelling_cloud_disabled"],
    },

    "cloud_tunnel": {
        "target":    "https://intersight.com (WebSocket)",
        "function":  "base.(*intersightDialer).proxyToCloud (starship/apollo internal)",
        "ca_cert":   "certs/hydrant-ca-1.pem (Cisco internal Intersight CA — 'hydrant' project)",
        "jira_ref":  "ISPLAT-15068 — ticket reference embedded adjacent to proxyToCloud function",
    },

    "local_http": (
        "eCMC Device Connector polls local Redfish API over HTTP (not HTTPS): "
        "http://127.0.0.1:9000/redfish/v1/Managers/CMC and "
        "http://127.0.0.1:9000/redfish/v1/Managers/CMC/EthernetInterfaces/Management — "
        "Redfish at port 9000 serves plaintext HTTP on loopback."
    ),

    "impact": (
        "If IgnoreCert is set to true (via /v1/asset/DeviceConfigurations API with admin credentials, "
        "or via direct BoltDB write — possible from CMC-F3 jrpc_server root RPC), "
        "the eCMC Device Connector will accept any TLS certificate from intersight.com. "
        "A network-positioned attacker can MITM the CMC-to-Intersight WebSocket tunnel, "
        "injecting firmware upgrade commands, modifying inventory data, or intercepting "
        "chassis configuration pushed from Intersight cloud management."
    ),

    "remediation": (
        "Cisco should: (1) remove IgnoreCert from the ManagedDevice_type API surface; "
        "(2) pin the Intersight CA cert (already present as hydrant-ca-1.pem) and disallow "
        "skip-verify mode; (3) protect BoltDB with filesystem permissions that prevent "
        "modification by non-eCMC processes."
    ),

    "tags": ["tls-bypass", "insecure-skip-verify", "cloud-tunnel", "boltdb", "intersight", "mitm", "cwe-295", "high"],
}

# ─────────────────────────────────────────────────────────
# CMC-F16 — eCMC Device Connector registers /debug/pprof/ Go profiling endpoint;
#            authentication status unverified from static analysis (live probe required)
# ─────────────────────────────────────────────────────────
CMC_F16 = {
    "id":       "CMC-F16",
    "title":    "eCMC Device Connector registers Go /debug/pprof/ profiling endpoint — "
                "authentication guard unverified from static analysis; if accessible, "
                "exposes goroutine dumps, heap profiles, and execution traces",
    "status":   "CANDIDATE — /debug/pprof/ string confirmed in binary; "
                "authentication wrapper not determinable via static analysis alone; "
                "live probe required to confirm unauthenticated access",
    "severity": "MEDIUM",

    "binary": {
        "path":    "CMC/6.0.2.260026/chassisA.img → ecmc_cloud_connector (UPX-packed, ARM64)",
        "version": "1.0.11-20260202093858420",
    },

    "endpoint": "/debug/pprof/",
    "framework": "gorilla/mux — *mux.Router, *mux.Route symbols confirmed in binary",

    "pprof_surface": [
        "/debug/pprof/goroutine — goroutine dump (reveals internal state, goroutine IDs, stack frames)",
        "/debug/pprof/heap — heap allocation profile",
        "/debug/pprof/profile — 30-second CPU profile",
        "/debug/pprof/trace — execution trace",
        "/debug/pprof/cmdline — process command line",
        "/debug/pprof/symbol — symbol table lookup",
    ],

    "risk": (
        "If /debug/pprof/ is exposed without authentication on the CMC management interface, "
        "an unauthenticated attacker on the management network can: read goroutine stacks "
        "(may contain session tokens, decrypted config values), enumerate heap contents "
        "(may contain BoltDB key-value pairs including IgnoreCert and API credentials), "
        "and fingerprint the exact Go runtime and build version."
    ),

    "verify_command": (
        "curl -s http://<CMC-MGMT-IP>:<ECMC-PORT>/debug/pprof/ "
        "— expect 200 with HTML pprof index if unauthenticated"
    ),

    "tags": ["pprof", "info-disclosure", "golang", "debug-endpoint", "cwe-200", "medium"],
}

FINDINGS = [CMC_F1, CMC_F2, CMC_F3, CMC_F4, CMC_F5, CMC_F6, CMC_F7, CMC_F8, CMC_F9, CMC_F10, CMC_F11,
            CMC_F12, CMC_F13, CMC_F14, CMC_F15, CMC_F16]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
