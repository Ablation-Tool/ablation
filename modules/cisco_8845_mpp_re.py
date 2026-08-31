"""
Cisco 8845 MPP IP Phone firmware reverse engineering module.
Firmware: sip8845_65.11-3-3MPP0103-381
Platform: ARM32 EABI5 (Broadcom SoC), Linux 2.6.25
Build path: /workspace/ip_sl/BLD-slm_mpp_1133_throttle_v2-git-d_2/ip_sl/
"""

FIRMWARE = {
    "model": "Cisco IP Phone 8845 MPP",
    "version": "65.11-3-3MPP0103-381",
    "rootfs_sbn": "rootfs8845_65.11-3-3MPP0103-381.sbn",
    "vc4_sbn": "vc48845_65.11-3-3MPP0103-381.sbn",
    "arch": "ARM32 EABI5",
    "kernel": "Linux 2.6.25",
    "libc": "glibc 2.13",
    "openssl": "1.1.x",
    "build_path": "/workspace/ip_sl/BLD-slm_mpp_1133_throttle_v2-git-d_2/ip_sl/",
}

# PHN-F01: libhstls.so BypassTruststore — TLS cert validation bypass during NTP-unsync window
PHN_F01_BYPASS_TRUSTSTORE = {
    "id": "PHN-F01",
    "title": "libhstls BypassTruststore certificate verification bypass (NTP window)",
    "binary": "libhstls.so (ARM32, Cisco 8845 MPP)",
    "build_id_sha1": "e83dee01bb6844dfd34afa47d8ad93b370859efd",
    "source_file": "ip_sl/infra/services/secd/secbase/security_lib/hstls/src/cert_verify.c",

    # Exported API that creates the bypass truststore
    "create_bypass_truststore_va": 0x55bc,
    "create_bypass_truststore_size": 148,

    # Bypass truststore vtable layout (16-byte heap object)
    "bypass_vtable": {
        "offset_0_get_name_fn": 0x54c4,   # returns "BypassTruststore" string
        "offset_4_lookup_fn":   0x551c,   # always returns NULL (no cert found)
        "offset_8_verify_fn":   0x556c,   # always returns 1 (success)
    },
    "bypass_name_string_va": 0x8cc4,  # "BypassTruststore"

    # hs_verify_callback: where bypass is triggered
    "hs_verify_callback_va": 0x7048,
    "hs_verify_callback_size": 1496,

    # Bypass path: 0x72fc–0x7334
    # Triggered when: BypassTruststore active AND stime files absent
    "bypass_branch_va": 0x72fc,
    "bypass_return_success_va": 0x7334,  # mov sl, #1 — return 1 (TLS success)

    # Sentinel files checked in hs_verify_callback
    "stime_user_path": "/tmp/.stime-by-user",  # created when user sets time manually
    "stime_ntp_path":  "/tmp/.stime-by-ntp",   # created when NTP sync succeeds

    # Trigger conditions (both must be true)
    # 1. Neither stime file exists (phone clock not synced)
    # 2. BypassTruststore is the active truststore for the connection

    # Log strings emitted when bypass fires (level 4)
    "log_hostname_disabled": "TLS - Hostname validation disabled",
    "log_cert_disabled":     "TLS - Certificate verification disabled",

    # Time-validity bypass log strings (before bypass branch at 0x72fc)
    "log_accept_expired":    "System time NOT synced so ACCEPT EXPIRED cert",
    "log_accept_future":     "System time NOT synced so ACCEPT NOT_YET_VALID cert",

    # Supporting functions
    "setopt_sec_ctx_va": 0x6a98,   # setopt(ctx, 0, val): [ctx+0x1c]; option 1: [ctx+0x18]; option 2: [ctx+0x14]; option 3: truststore
    "tls_set_truststore_va": 0x5874,  # installs a truststore into a security context
    "enable_platform_truststore_va": 0x6f78,

    # Security impact
    "impact": (
        "During the NTP-unsync window (phone boot before first NTP sync), "
        "any connection configured with a BypassTruststore will accept any "
        "TLS certificate regardless of CA chain or validity period. "
        "An attacker controlling the provisioning server or DNS can present "
        "an expired or self-signed cert and establish a trusted HTTPS connection "
        "to the phone during this window."
    ),

    # Comparison to Jabber Android
    "related": "JAB-F13 (Jabber Android libcpve.so disableFingerprintVerification — stronger bypass, no time-sync gate)",

    # Static analysis note
    "note": (
        "DTLS media fingerprint verification is NOT in rootfs ARM userspace. "
        "It runs on the VideoCore IV processor (vc4 SBN). "
        "VC4 ISA is Broadcom proprietary; no open disassembler available via capstone. "
        "libssl.so.1.1 provides DTLS handshake primitives; fingerprint checking would "
        "be in ms (media server, 1.2MB stripped ARM32) or libvcp.so.1.0.1, "
        "neither of which contains fingerprint strings — confirmed in vc4."
    ),
}

# PHN-SURFACE: Attack surface enumeration for 8845 MPP
PHN_SURFACE = {
    "tls_library":     "libhstls.so (Cisco 'Huron Secure TLS', OpenSSL wrapper)",
    "srtp_library":    "libsrtp.so",
    "dtls_provider":   "libssl.so.1.1 (OpenSSL 1.1.x)",
    "media_server":    "ms (ELF ARM32, 1.2MB stripped, /usr/sbin/ms)",
    "voice_codec":     "vc4 SBN (VideoCore IV — Broadcom proprietary ISA)",
    "capf_client":     "libcapf.so (CAPF certificate enrollment)",
    "cert_storage":    "libhuronTruststore.so",
    "scep_client":     "cscep (/usr/sbin/cscep)",
    "web_server":      "webs (/usr/sbin/webs — Mongoose-based)",
    "pae_daemon":      "pae (/usr/sbin/pae — 802.1X EAP/TLS)",
    "interesting_libs": [
        "libatls.so",       # ATLS (async TLS) for provisioning
        "libedge.so",       # Cisco Edge (cloud registration)
        "libsecureapi.so",  # secd IPC client
        "libSecurityDll.so", # Java MIDlet signing
        "libfips.so",       # FIPS 140-2 crypto module
        "libNativeKEMManager.so",  # Key encryption manager
    ],
}

# PHN-CHAIN: Provisioning attack chain using PHN-F01
PHN_CHAIN = {
    "entry_point": "NTP block or pre-NTP-sync window (phone boot)",
    "step_1": "Present expired/self-signed HTTPS cert to phone provisioning endpoint",
    "step_2": "Phone in NTP-unsync window + BypassTruststore active → TLS handshake succeeds",
    "step_3": "Attacker-controlled TFTP/HTTP provisioning server delivers malicious config",
    "step_4": "Config redirects CUCM/Expressway registration to attacker infrastructure",
    "impact": "Full call interception + credential harvest",
    "gate": "Window closes when /tmp/.stime-by-user or /tmp/.stime-by-ntp created",
    "note": "BypassTruststore use in provisioning path needs dynamic confirmation",
}
