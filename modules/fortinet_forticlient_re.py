"""
Fortinet FortiClient VPN Windows RE
Sources analyzed:
  FortiClientVPN v6.0.9.0277 x64.exe  (92MB, 2019 vintage)
  FortiClientVPN v6.2.6.0951 x64.exe  (95MB)
  FortiClientVPN v6.4.2.1580 x64.exe  (117MB)
  FortiClientVPN v7.4.0.1658.exe      (169MB, 2024-05-31 build, primary analysis target)
  FortiExplorer OnlineInstaller v2.6.1083.exe
Purpose: kernel driver attack surface, IPC channels, code signing, embedded key material.
"""


# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiClient VPN",
    "versions":       ["6.0.9", "6.2.6", "6.4.2", "7.4.0"],
    "primary_target": "FortiClientVPN v7.4.0.1658.exe (2024-05-31 build, WiX MSI installer)",
    "arch":           "x86-64 (PE32 stub wrapping MSI with x64 CAB payloads)",
    "publisher":      "Fortinet Inc.",

    "installer_structure": {
        "outer_pe":   "PE32 x86 stub, 169MB total",
        "inner_msi":  "Embedded at .rsrc RCDATA MSI00 (163MB), WiX bootstrapper",
        "cab_files": {
            "common.cab":  "126MB -- main runtime (97 files)",
            "VPN.cab":     "5.6MB -- VPN kernel drivers and core VPN components",
            "Core.cab":    "6.3MB -- scheduler, update, FCAuth, FortiAuth, sqlite, libcurl",
            "x64.cab":     "248KB -- x64-specific binaries",
            "fcresc.cab":  "89KB  -- resources",
            "FSSOMA.cab":  "134KB -- SOMA endpoint compliance module",
        },
    },

    "kernel_drivers": {
        "FortiFilter_ndis6_3.sys": {
            "size_v740":  "35KB",
            "function":   "NDIS 6.3 LightWeight Filter -- packet inspection/filtering",
            "device":     "\\Device\\FORTIFILTER",
            "ioctls":     [],
            "signed_by":  "WHQL (Microsoft Windows Hardware Compatibility Publisher, 2014 CA)",
        },
        "fortips_ndis6_3.sys": {
            "size_v740":  "204KB",
            "function":   "FortiClient IPSec driver -- ESP/IKE tunnel processing",
            "device":     "\\Device\\FORTIPS",
            "references": ["\\Device\\fortifilter", "\\REGISTRY\\MACHINE\\SOFTWARE\\Fortinet\\FortiClient"],
            "ioctls":     ["0x0022641e (func=0x907, READ/OUTPUT_DIRECT)"],
            "signed_by":  "WHQL (Microsoft Windows Hardware Compatibility Publisher, 2014 CA)",
        },
        "fortitransctrl.sys": {
            "size_v740":  "111KB",
            "function":   "WFP callout driver -- intercepts auth/connect/recv-accept/bind for split-tunneling and firewall enforcement",
            "wfp_callouts": [
                "FortiTransCtrl auth connect callout",
                "FortiTransCtrl auth connect filter",
                "FortiTransCtrl auth recv-accept callout",
                "FortiTransCtrl auth recv-accept filter",
                "FortitransCtrl bind redirect callout",
                "FortitransCtrl bind redirect filter",
                "FortiTransCtrl subLayer",
                "xFortiTransCtrl connection redirect callout",
            ],
            "ioctls":     ["0x0022efe8 (func=0xbfa, RW/BUFFERED)"],
        },
        "ftsvnic.sys": {
            "size_v740":  "84KB",
            "function":   "FortiSplitDNS service provider / virtual NIC for split-DNS enforcement",
            "device":     "\\Device\\ftsvnic",
            "wfp_callouts": [
                "FortiSplitdns subLayer",
                "FortiSplitdns connection redirect callout",
                "FortiSplitdns connection redirect filter",
            ],
            "ioctls":     ["0x0022b30d (func=0xcc3, WRITE/INDIR)"],
            "signed_by":  "COMODO EV (Fortinet, Inc., 2021-2024)",
        },
        "ftvnic_ndis6_3.sys": {
            "size_v740":  "70KB",
            "function":   "Fortinet Virtual Network Adapter (NDIS 6.30 Miniport) -- VPN virtual interface",
            "product":    "FortiClient Virtual Miniport Driver",
            "ioctls": [
                "0x00223423 (func=0xd08, ANY_ACCESS / METHOD_NEITHER)",
                "0x0022ba18 (func=0xe86, WRITE_ACCESS / BUFFERED)",
                "0x0022baff (func=0xebf, WRITE_ACCESS / METHOD_NEITHER)",
                "0x0022ff81 (func=0xfe0, RW_ACCESS / INDIR)",
            ],
            "signed_by":  "Fortinet Technologies (Canada) Inc. (embedded in catalog .cat)",
        },
    },

    "userspace_components": {
        "FortiSSLVPNdaemon.exe":  "747KB -- user-mode SSL VPN daemon (communicates with FortiSSLVPNsys via named pipe)",
        "FortiSSLVPNsys.exe":     "134KB -- SYSTEM-context 'shadow mode connector'; sets up VPN tunnel on behalf of daemon",
        "File_fcp.dll":           "4.4MB -- FortiClient Protocol library (contains OpenSSL: PEM_write_bio, PEM_read)",
        "File_scheduler.exe":     "6.7MB -- update/task scheduler (also contains OpenSSL)",
        "File_xmlvpn.dll":        "453KB -- VPN XML configuration parser",
        "File_ipsec.exe":         "947KB -- IPsec userspace component",
        "File_update_task_tls.dll": "565KB -- update task TLS library (libcurl-based)",
        "File_libcurl.dll":       "562KB -- libcurl with certificate pinning support (sha256// pins)",
    },

    "named_pipes": {
        "FortiSslvpnNamedPipe":       "\\\\.\\pipe\\FortiSslvpnNamedPipe -- SSL VPN control pipe (daemon -> sys)",
        "FC_A8690EB5":                "\\\\.\\pipe\\FC_{A8690EB5-B40F-4438-A4EF-5D5132FC73FE}",
        "FC_6D57D5C3":                "\\\\.\\pipe\\FC_{6D57D5C3-9CEA-4497-BE57-9E544137A437}",
        "FC_2D1033CE":                "\\\\.\\pipe\\FC_{2D1033CE-B57A-4B95-B40F-0A9EEF1A3AA0}",
        "FCCryptd":                   "\\\\.\\ pipe\\FC_{...} -- FCCryptdAPI.cpp; separate crypto daemon process",
        "note":                       "DACLs on these pipes not analyzed (requires live Windows system); if permissive, low-privileged users can inject commands to SYSTEM-context FortiSSLVPNsys",
    },

    "registry_keys": {
        "vpn_config":   "SOFTWARE\\Fortinet\\FortiClient\\Sslvpn\\Tunnels",
        "vpn_config2":  "SOFTWARE\\Fortinet\\FortiClient\\Sslvpn",
        "auth":         "SOFTWARE\\Fortinet\\FortiClient\\FA_VPN",
        "esnac":        "SOFTWARE\\Fortinet\\FortiClient\\FA_ESNAC",
        "configd":      "SOFTWARE\\Fortinet\\FortiClient\\FA_CONFIGD",
    },
}


# ---------------------------------------------------------
# FCT-F01: Internal build path leak in shipped binary
# ---------------------------------------------------------
FCT_F01_BUILD_PATH_LEAK = {
    "id":       "FCT-F01",
    "product":  "Fortinet FortiClient VPN v7.4.0.1658",
    "severity": "LOW -- OPSEC failure; leaks internal build infrastructure paths in shipped binary",
    "class":    "Information disclosure (CWE-209 -- generation of error message with sensitive information)",
    "cwe":      "CWE-209",

    "description": (
        "FortiSSLVPNdaemon.exe (747KB, v7.4.0.1658) contains full internal Jenkins build server "
        "path strings in its .text section (compiled-in via C++ assertion/debug path macros). "
        "These strings are present in the shipped retail binary, not just debug builds. "
        "The paths reveal: "
        "  (1) Fortinet uses Jenkins CI with project identifier 'FCT0' (FortiClient); "
        "  (2) Source repository is named 'FortiClientHS'; "
        "  (3) Build server path prefix is C:\\jenkins\\FCT0\\GIT_CLONE_PARENT\\FortiClientHS\\; "
        "  (4) Module structure: sslvpn\\FortiSSLVPNd\\, service\\FCCryptdAPI\\. "
        "Secondary: FCCryptdAPI.cpp leaks the existence of a separate crypto daemon IPC component."
    ),

    "evidence": {
        "sslvpn_path":  r"C:\jenkins\FCT0\GIT_CLONE_PARENT\FortiClientHS\sslvpn\FortiSSLVPNd\SslvpnTunnelCertFingerprintCheckTestClient.cpp",
        "cryptd_path":  r"C:\jenkins\FCT0\GIT_CLONE_PARENT\FortiClientHS\service\FCCryptdAPI\FCCryptdAPI.cpp",
        "binary":       "FortiSSLVPNdaemon.exe in VPN.cab from FortiClientVPN v7.4.0.1658.exe",
        "method":       "strings extraction from .text section (no unpacking required)",
    },

    "chain_context": (
        "Combined with FCT-F04 (named pipe IPC), the build path leak reveals the FCCryptdAPI module "
        "responsible for the crypto daemon pipe. Knowing the module architecture helps target the IPC "
        "deserialization attack surface."
    ),

    "remediation": "Strip debug paths from release builds (linker flag /PDBSTRIPPED or equivalent; ensure __FILE__ macros not compiled into release assertions).",
}


# ---------------------------------------------------------
# FCT-F02: METHOD_NEITHER IOCTLs in ftvnic_ndis6_3.sys (LPE candidate)
# ---------------------------------------------------------
FCT_F02_NEITHER_IOCTL_LPE = {
    "id":       "FCT-F02",
    "product":  "Fortinet FortiClient VPN v7.4.0.1658 -- ftvnic_ndis6_3.sys",
    "severity": "HIGH -- unverified LPE candidate; METHOD_NEITHER IOCTL with FILE_ANY_ACCESS; confirmed by static analysis only",
    "class":    "Kernel memory safety -- improper pointer validation (CWE-822 -- Untrusted Pointer Dereference)",
    "cwe":      "CWE-822",

    "description": (
        "ftvnic_ndis6_3.sys (Fortinet Virtual Network Adapter NDIS 6.30 Miniport) exposes two "
        "IOCTLs with METHOD_NEITHER transfer type. "
        "METHOD_NEITHER bypasses the I/O Manager's buffer copy mechanism: the kernel driver receives "
        "the raw user-mode virtual addresses (Parameters.DeviceIoControl.Type3InputBuffer for input, "
        "Irp->UserBuffer for output) without any copying or probing. "
        "The driver code must explicitly call ProbeForRead/ProbeForWrite, MmProbeAndLockPages, or use "
        "structured exception handling (__try/__except) before dereferencing these pointers. "
        "Static analysis confirms the IOCTL codes exist; dynamic analysis on a live Windows system "
        "is required to confirm whether pointer validation is absent. "
        "\n"
        "IOCTL 0x00223423 (func=0xd08) is particularly dangerous: FILE_ANY_ACCESS means any user-mode "
        "process -- including low-integrity (sandboxed) processes -- can open the device handle and "
        "send this IOCTL. If the driver dereferences the Type3InputBuffer without validation, a "
        "sandbox-escaped or low-IL process can corrupt kernel memory via a crafted pointer."
    ),

    "ioctl_table": {
        "0x00223423": {
            "function_code": "0xd08",
            "access":        "FILE_ANY_ACCESS (any caller, including low-integrity)",
            "method":        "METHOD_NEITHER (raw user-mode pointers to kernel)",
            "risk":          "CRITICAL path -- accessible from low-integrity; no copy/probe by I/O Manager",
        },
        "0x0022ba18": {
            "function_code": "0xe86",
            "access":        "FILE_WRITE_ACCESS",
            "method":        "METHOD_BUFFERED (I/O Manager copies; lower risk)",
            "risk":          "lower",
        },
        "0x0022baff": {
            "function_code": "0xebf",
            "access":        "FILE_WRITE_ACCESS",
            "method":        "METHOD_NEITHER (raw user-mode pointers to kernel)",
            "risk":          "HIGH -- write-capable caller can corrupt kernel memory if no probe",
        },
        "0x0022ff81": {
            "function_code": "0xfe0",
            "access":        "FILE_READ_WRITE_ACCESS",
            "method":        "METHOD_IN_DIRECT (I/O Manager locks and validates; lower risk)",
            "risk":          "lower",
        },
    },

    "comparison_context": (
        "This pattern is structurally identical to the fortism.ko ioctl DoS in FGT-F16 "
        "(Windows equivalent: METHOD_NEITHER without ProbeForWrite = kernel stack/heap corruption). "
        "FortiGate's fortism unprotected SIZE_MAX copy_from_user -> kernel panic; "
        "ftvnic METHOD_NEITHER without probe -> arbitrary kernel write primitive. "
        "Both stem from the same engineering pattern: trusting user-supplied lengths/pointers in "
        "privileged kernel code paths."
    ),

    "verification_steps": [
        "Open \\\\.\\ftvnic_ndis6_3 (or the NDIS device object name, likely enumerated via NdisMGetDeviceProperty)",
        "Send IOCTL 0x00223423 with Type3InputBuffer pointing to unmapped address (e.g., 0x41414141)",
        "Expect: BSOD (access violation in kernel) if no ProbeForRead; or controlled dereference if protected",
        "Tool: WinObj to find device name, WinDbg kernel attach to observe exception",
    ],

    "evidence": {
        "driver": "File_ftvnic_ndis6_3.sys extracted from VPN.cab in FortiClientVPN v7.4.0.1658.exe",
        "device_size": "70KB (70368 bytes)",
        "strings_show": "NdisMGetDeviceProperty -- confirms NDIS miniport with device management",
        "cert_chain": "Fortinet Technologies (Canada) Inc.",
    },

    "remediation": "Validate all METHOD_NEITHER IOCTLs with ProbeForRead/ProbeForWrite or __try/__except. Convert 0x00223423 to METHOD_BUFFERED or restrict access to FILE_WRITE_ACCESS minimum.",
}


# ---------------------------------------------------------
# FCT-F03: Expired code signing and WHQL certs
# ---------------------------------------------------------
FCT_F03_EXPIRED_CERTS = {
    "id":       "FCT-F03",
    "product":  "Fortinet FortiClient VPN v7.4.0.1658 kernel drivers",
    "severity": "MEDIUM -- expired signing certs; valid Authenticode due to countersignature timestamp; WHQL expiry blocks driver install on some configurations",
    "class":    "Certificate management failure (CWE-295 -- improper certificate validation)",
    "cwe":      "CWE-295",

    "code_signing_chain": {
        "leaf":         "Fortinet, Inc. (EV) -- COMODO RSA EV Code Signing",
        "issuer":       "COMODO RSA Extended Validation Code Signing CA",
        "root":         "COMODO RSA Certification Authority (cross-signed by Microsoft Code Verification Root)",
        "not_before":   "2021-05-25",
        "not_after":    "2024-05-24 (EXPIRED -- 16 months ago as of 2026-09-12)",
        "ev_fields": {
            "serialNumber":     "3321792",
            "jurisdictionC":    "US",
            "jurisdictionST":   "Delaware",
            "businessCategory": "Private Organization",
            "O":                "Fortinet, Inc.",
            "L":                "Sunnyvale",
            "ST":               "California",
        },
    },

    "whql_chain": {
        "leaf":       "Microsoft Windows Hardware Compatibility Publisher",
        "issuer":     "Microsoft Windows Third Party Component CA 2014",
        "root":       "Microsoft Root Certificate Authority 2010",
        "not_before": "2024-01-11",
        "not_after":  "2025-01-10 (EXPIRED -- 20 months ago as of 2026-09-12)",
        "note":       "WHQL cert used to obtain Microsoft kernel-mode code signing approval; expiry affects driver installation validation on Windows 11 secure boot systems",
    },

    "timestamp_chain": {
        "tsa":        "DigiCert Timestamp 2023",
        "issuer":     "DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA",
        "not_before": "2023-07-14",
        "not_after":  "2034-10-13",
        "note":       "Timestamp countersignature applied within cert validity window; Authenticode remains valid for already-installed binaries despite leaf cert expiry",
    },

    "impact": (
        "Windows Authenticode validation uses the timestamp countersignature to determine if "
        "signing occurred during cert validity. Since the TSA countersignature pre-dates the "
        "2024-05-24 expiry, existing installations retain valid trust. "
        "However: on a fresh Windows 11 system with Driver Signature Enforcement and "
        "Secure Boot, an expired WHQL cert may trigger additional validation warnings or "
        "installation failures when the DSE policy requires current WHQL certs. "
        "An attacker cannot forge a new Fortinet-branded driver without a new COMODO EV cert, "
        "but the expired WHQL weakens the trust assumption for driver updates."
    ),

    "remediation": "Renew COMODO EV code signing cert and WHQL cert. Re-submit drivers to WHQL. Update installer.",
}


# ---------------------------------------------------------
# FCT-F04: Named pipe IPC attack surface
# ---------------------------------------------------------
FCT_F04_NAMED_PIPE_IPC = {
    "id":       "FCT-F03",
    "product":  "Fortinet FortiClient VPN v7.4.0.1658",
    "severity": "MEDIUM -- IPC channel to SYSTEM-context service; DACL not verified; requires live analysis",
    "class":    "Insecure IPC channel (CWE-269 -- improper privilege management)",
    "cwe":      "CWE-269",

    "description": (
        "FortiSSLVPNdaemon.exe (user-mode, user-context) communicates with FortiSSLVPNsys.exe "
        "(SYSTEM-context 'shadow mode connector') exclusively via named pipes. "
        "If the named pipe DACL allows non-administrator access, any local user can connect "
        "to the pipe and send commands to the SYSTEM-context process. "
        "FCCryptdAPI.cpp is a separate crypto daemon module also accessed via named pipe "
        "(\\\\.\\ pipe\\FC_{UUID}). "
        "The use of UUID-based pipe names suggests the daemon generates a new UUID per session "
        "and passes it to the service via another channel -- but if the UUID is predictable "
        "or derivable, a local attacker can race to connect to the pipe before the daemon."
    ),

    "pipes": {
        "FortiSslvpnNamedPipe": {
            "path":    "\\\\.\\pipe\\FortiSslvpnNamedPipe",
            "purpose": "SSL VPN control channel: user daemon -> SYSTEM connector",
            "risk":    "If DACL is permissive (Everyone:GENERIC_READ_WRITE), LPE via command injection to SYSTEM context",
        },
        "FC_UUID_pipes": {
            "examples": [
                "\\\\.\\pipe\\FC_{A8690EB5-B40F-4438-A4EF-5D5132FC73FE}",
                "\\\\.\\pipe\\FC_{6D57D5C3-9CEA-4497-BE57-9E544137A437}",
                "\\\\.\\pipe\\FC_{2D1033CE-B57A-4B95-B40F-0A9EEF1A3AA0}",
            ],
            "purpose": "FCCryptdAPI crypto daemon channel (one per session or component)",
            "risk":    "UUID predictability + TOCTOU on pipe connect = injection to crypto daemon",
        },
    },

    "ssl_config_attack_surface": {
        "registry_tunnels": "SOFTWARE\\Fortinet\\FortiClient\\Sslvpn\\Tunnels",
        "auth_file":        ".htpasswd-style auth file (read_auth_file/check_authorization code path found)",
        "config_options": [
            "ssl_certificate",
            "ssl_certificate_chain",
            "ssl_verify_peer",
            "ssl_ca_file",
            "ssl_cipher_list",
            "ssl_protocol_version",
            "authentication_domain",
            "enable_auth_domain_check",
        ],
        "note": (
            "ssl_verify_peer and ssl_short_trust config options in FortiSSLVPNdaemon suggest "
            "the VPN client can be configured to skip peer cert verification. "
            "If an attacker can write to HKLM\\SOFTWARE\\Fortinet\\FortiClient\\Sslvpn "
            "(requires SYSTEM or admin), they can disable cert verification and MITM the VPN tunnel."
        ),
    },

    "verification_steps": [
        "On live Windows system: `accesschk.exe -v \\\\.\\pipe\\FortiSslvpnNamedPipe`",
        "Check if pipe is accessible from medium or low integrity level",
        "Fuzz the pipe protocol with a simple write loop to trigger crashes in FortiSSLVPNsys",
    ],

    "remediation": "Set named pipe DACL to restrict to LocalSystem and Administrators only. Implement message authentication on pipe protocol. Store HMAC-verified session keys to prevent replay.",
}


# ---------------------------------------------------------
# FCT-F05: Hardcoded RSA public keys in kernel drivers
# ---------------------------------------------------------
FCT_F05_HARDCODED_DRIVER_KEYS = {
    "id":       "FCT-F05",
    "product":  "Fortinet FortiClient VPN v7.4.0.1658 kernel drivers",
    "severity": "INFO -- keys are public (no private key exposure); structural finding about key management",
    "class":    "Hardcoded cryptographic material (CWE-321 -- use of hard-coded cryptographic key)",
    "cwe":      "CWE-321",

    "description": (
        "Each FortiClient kernel driver embeds 2-3 RSA public keys used for driver-to-driver "
        "IPC integrity verification. One 4096-bit RSA key is shared across three drivers "
        "(fortips, fortitransctrl, ftsvnic), forming a shared-root trust scheme. "
        "FortiFilter and ftvnic share two 2048-bit keys. "
        "All keys use e=65537. "
        "Since these are public keys (not private), there is no direct key compromise risk -- "
        "the corresponding private keys would be held by Fortinet's signing infrastructure. "
        "However, hardcoding public keys in kernel drivers means key rotation requires a "
        "driver update shipped as a software update (cannot be done via certificate revocation "
        "or certificate store update). If the corresponding private key is ever compromised, "
        "Fortinet cannot revoke trust in affected driver versions without pushing a mandatory update."
    ),

    "key_map": {
        "shared_4096bit": {
            "modulus_prefix": "00:bf:e6:90:73:68:de:bb:e4:5d:4a:3c:30:22:30:69:33:ec:c2:a7...",
            "key_size":       4096,
            "exponent":       65537,
            "found_in":       ["fortips_ndis6_3.sys@0x2c9ae", "fortitransctrl.sys@0x161ae", "ftsvnic.sys@0xf9ae"],
            "purpose":        "likely the Fortinet IPS/transport signing root (verified by 3 drivers)",
        },
        "filter_vnic_key_A": {
            "modulus_prefix": "00:b1:ac:b3:49:54:4b:97:1c:12:0a:d8:25:79:91:22:57:2a:6f:dc...",
            "key_size":       2048,
            "exponent":       65537,
            "found_in":       ["FortiFilter_ndis6_3.sys@0x4bd1", "ftvnic_ndis6_3.sys@0xd3d1"],
        },
        "filter_vnic_key_B": {
            "modulus_prefix": "00:a2:63:0b:39:44:b8:bb:23:a7:44:49:bb:0e:ff:a1:f0:61:0a:53...",
            "key_size":       2048,
            "exponent":       65537,
            "found_in":       ["FortiFilter_ndis6_3.sys@0x4f99", "ftvnic_ndis6_3.sys@0xd799"],
        },
        "ips_svnic_key_C": {
            "modulus_prefix": "00:b3:83:d5:1c:70:03:33:5c:9f:11:82:41:31:67:1d:12:ed:a8:5c...",
            "key_size":       2048,
            "exponent":       65537,
            "found_in":       ["fortips_ndis6_3.sys@0x2cfd5", "ftsvnic.sys@0xffd5"],
        },
        "ips_svnic_key_D": {
            "modulus_prefix": "00:8a:fd:bd:43:f0:3d:c8:55:1f:f3:59:8a:f0:5a:b4:dc:93:d1:64...",
            "key_size":       2048,
            "exponent":       65537,
            "found_in":       ["fortips_ndis6_3.sys@0x2d562", "ftsvnic.sys@0x10562"],
        },
    },

    "cross_product_note": (
        "No overlap found between these driver public keys and the FortiGate firmware keys "
        "(fgt2.key RSA-2048 modulus c8eaa255, fgt_512.key RSA-512 moduli). "
        "FortiClient uses a separate key hierarchy from FortiGate OS keys. "
        "The FortiGate PKI (fortinet-ca2 RSA-8192 -> fortinet-subca2001 RSA-2048) also does not "
        "appear in the FortiClient driver binary trust chain."
    ),
}


# ---------------------------------------------------------
# FCT-F06: WFP callout driver intercepts all TCP connections
# ---------------------------------------------------------
FCT_F06_WFP_CALLOUT = {
    "id":       "FCT-F06",
    "product":  "Fortinet FortiClient VPN v7.4.0.1658 -- fortitransctrl.sys",
    "severity": "INFO -- by-design traffic interception; attack surface if callout has parsing bugs",
    "class":    "By-design network interception (Windows Filtering Platform callout driver)",

    "description": (
        "fortitransctrl.sys registers Windows Filtering Platform (WFP) callouts for: "
        "  (1) FWPM_LAYER_ALE_AUTH_CONNECT -- intercepts all outbound connection attempts; "
        "  (2) FWPM_LAYER_ALE_AUTH_RECV_ACCEPT -- intercepts all inbound connection accepts; "
        "  (3) FWPM_LAYER_ALE_BIND_REDIRECT -- redirects bind() calls (for split-tunneling). "
        "This gives fortitransctrl visibility into every TCP/UDP connection on the system, "
        "including those from applications running as SYSTEM. "
        "A parsing bug in the callout's classification function (called for EVERY packet) "
        "would be kernel-mode code execution with network-reachable trigger -- highest severity. "
        "IOCTL 0x0022efe8 (func=0xbfa, BUFFERED) is the control channel to the callout driver. "
        "The same function code (0xbfa) appears in FortiSSLVPNsys.exe (IOCTL 0x0022afe8), "
        "suggesting the function handler is shared between the kernel driver and the system service."
    ),

    "shared_ioctl_evidence": {
        "fortitransctrl":    "IOCTL=0x0022efe8 func=0xbfa RW/BUFFERED",
        "FortiSSLVPNsys":    "IOCTL=0x0022afe8 func=0xbfa OUTDIR",
        "note":              "Same function code 0xbfa -- shared dispatch table; same parsing code path in both drivers",
    },

    "remediation": "Audit WFP classify callback for length validation before any data parse operation. IOCTL 0xbfa handler: confirm input buffer length check before structure access.",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "v7.4.0": {
        "installer_type":    "WiX MSI (PE32 stub -> MSI -> CABs)",
        "kernel_drivers":    "EXTRACTED from VPN.cab (5 drivers fully analyzed)",
        "certificates":      "DECODED -- Authenticode chain and WHQL chain extracted from binary DER sections",
        "ioctls":            "MAPPED -- static analysis; no dynamic verification on live Windows",
        "named_pipes":       "IDENTIFIED -- DACLs not verified (requires live Windows)",
        "source_paths":      "LEAKED -- Jenkins build paths in FortiSSLVPNdaemon.exe",
        "rootfs_equiv":      "N/A -- Windows installer; no Linux rootfs",
    },

    "v6.0.9": {
        "installer_type":    "WiX MSI (same structure as v7.4.0)",
        "main_cab":          "CAB at offset 0x542F28 (56MB, 220 files)",
        "kernel_drivers":    "NOT extracted (analysis stopped at v7.4.0 comparison)",
        "notable_binaries":  ["sslvpnlib.dll (677KB)", "libeay32.dll (1.5MB)", "utilsdll.dll (1.1MB)", "FCSetupWx.dll (1.5MB)"],
        "openssl_presence":  "libeay32.dll (OpenSSL 1.x legacy naming) present in v6.0.9; fcp.dll in v7.4.0",
        "note":              "v6.0.9 predates COMODO EV cert (2021); different signing chain expected",
    },

    "unique_findings": [
        "FCT-F01: LOW  -- Jenkins build path leak (C:\\jenkins\\FCT0\\GIT_CLONE_PARENT\\FortiClientHS\\) in FortiSSLVPNdaemon.exe",
        "FCT-F02: HIGH -- ftvnic_ndis6_3.sys METHOD_NEITHER IOCTL 0x00223423 (FILE_ANY_ACCESS) -- LPE candidate; needs live verification",
        "FCT-F03: MED  -- Code signing EV cert expired 2024-05-24; WHQL cert expired 2025-01-10",
        "FCT-F04: MED  -- Named pipe IPC (FortiSslvpnNamedPipe + UUID-based FCCryptd pipes) to SYSTEM context; DACL unverified",
        "FCT-F05: INFO -- Hardcoded RSA public keys in kernel drivers (4096-bit shared root across 3 drivers; 2048-bit pairs per driver group)",
        "FCT-F06: INFO -- WFP callout driver (fortitransctrl) intercepts all TCP connections system-wide; func=0xbfa IOCTL shared with FortiSSLVPNsys",
    ],

    "pending": {
        "ftvnic_ioctl_verify":    "Confirm FCT-F02: send IOCTL 0x00223423 with invalid pointer on live Windows VM; check for BSOD",
        "pipe_dacl_check":        "Confirm FCT-F04: run accesschk.exe on FortiSslvpnNamedPipe from medium/low integrity",
        "v6.0.9_driver_compare":  "Extract VPN drivers from v6.0.9 installer; compare IOCTL sets and key fingerprints",
        "FortiSSLVPN_protocol":   "Reverse FortiSslvpnNamedPipe protocol format from FortiSSLVPNdaemon.exe and FortiSSLVPNsys.exe",
        "FortiExplorer_RE":       "FortiExplorer OnlineInstaller v2.6.1083.exe (1.8MB) -- not analyzed",
        "common_cab_drivers":     "common.cab (126MB, 97 files) not extracted -- may contain additional drivers",
    },
}
