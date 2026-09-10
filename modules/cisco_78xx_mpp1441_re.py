"""
Cisco IP Phone 78xx MPP 14.4.1 — RE findings
Source: cmterm-78xx.14-4-1-0301-6.zip
Two hardware platforms (PLATFORM_1 / PLATFORM_2), both ARM32 TI Sitara/OMAP
Static analysis: SBN header strip, ubireader_extract_files, strings, readelf
"""

# ─────────────────────────────────────────────────────────
# Firmware identity
# ─────────────────────────────────────────────────────────
FIRMWARE = {
    "file":     "cmterm-78xx.14-4-1-0301-6.zip",
    "version":  "14.4.1 (0301-6) MPP",
    "built":    "2026-06-09 06:17:23 UTC",
    "type":     "MPP (Multiplatform Firmware — BroadWorks/third-party PBX target)",
    "base_os":  "Angstrom 2011.09 arm-arago-linux-gnueabi (TI Sitara/OMAP SoC)",
    "arch":     "ARM 32-bit LSB EABI5, dynamically linked, stripped",
    "libc":     "glibc 2.12.2 (ld-linux.so.3)",
}

# ─────────────────────────────────────────────────────────
# SBN container format (fully mapped)
# ─────────────────────────────────────────────────────────
SBN_FORMAT = {
    "magic":           "CD 34 12 AB (bytes 0-3)",
    "header_size":     "uint32 LE at bytes 4-7: 0x154=340 (PLATFORM_1) or 0x158=344 (PLATFORM_2 variants)",
    "reserved":        "bytes 8-11: always 0x00000000",
    "payload_size":    "uint32 LE at bytes 12-15: filesize - header_size",
    "filename_len":    "uint32 LE at bytes 0x34-0x37: strlen(filename)",
    "filename":        "null-terminated string starting at byte 0x38",
    "payload_offset":  "header_size (skip header_size bytes to reach raw content)",
    "payload_formats": {
        "kern*":   "U-Boot uImage (magic 27 05 19 56)",
        "rootfs*": "UBI image version 1 (magic 55 42 49 23)",
        "sboot*":  "U-Boot uImage (magic 27 05 19 56) or raw bootloader",
    },
    "extraction":      "dd if=<file>.sbn of=<out> bs=<header_size> skip=1",
    "header_variants": {
        "PLATFORM_1 (kern/rootfs/sboot)": 0x154,
        "PLATFORM_2 (kern2/rootfs2/sboot2)": {
            "rootfs2": 0x158,
            "sboot2":  0x158,
            "kern2":   0x154,
        },
    },
}

# ─────────────────────────────────────────────────────────
# Platform manifest (.loads)
# ─────────────────────────────────────────────────────────
LOADS_MANIFEST = {
    "file":       "sip78xx.14-4-1-0301-6.loads",
    "format":     "binary header + plaintext INI body (signature prepended before text)",
    "hwcompat":   "0x0000003F — 6 hardware revision bits",
    "swcompat":   "0x00000004",
    "PLATFORM_1": {
        "sboot":  "sboot78xx.14-4-1-0301-6.sbn  (373108 B)",
        "kern":   "kern78xx.14-4-1-0301-6.sbn   (3094444 B)",
        "rootfs": "rootfs78xx.14-4-1-0301-6.sbn (46661972 B)",
        "ebr_layout": "dual A/B slots: sboot@0x280000+0x5980000, kern@0x480000+0x5b80000, rootfs@0xe80000+0x6580000",
    },
    "PLATFORM_2": {
        "sboot":  "sboot2.78xx.14-4-1-0301-6.sbn  (734948 B)",
        "kern":   "kern2.78xx.14-4-1-0301-6.sbn   (2578356 B)",
        "rootfs": "rootfs2.78xx.14-4-1-0301-6.sbn (45351256 B)",
        "ebr_layout": "dual A/B slots: sboot@0x280000+0x5e80000, kern@0x480000+0x6080000, rootfs@0xe80000+0x6a80000",
    },
    "note": "Dual partition layout for A/B update. Both platforms share the same rootfs codebase.",
}

# ─────────────────────────────────────────────────────────
# Rootfs structure
# ─────────────────────────────────────────────────────────
ROOTFS = {
    "container":  "UBI v1 → UBIFS volume 'rootfs' (vol-id 0, name rootfs)",
    "extraction": "ubireader_extract_images <file>.ubi → img-*_vol-rootfs.ubifs; ubireader_extract_files <file>.ubifs",
    "filesystem": "Standard Linux rootfs: /bin /etc /lib /sbin /usr /var",
    "notable": {
        "/bin/java":              "ARM32 JVM — main phone application runs Java",
        "/usr/sbin/debugshd":     "Debug shell daemon (191KB ARM32 ELF, runs as root)",
        "/usr/sbin/debugsh":      "Debug shell client (15KB ARM32 ELF, links libupgapi.so)",
        "/usr/sbin/edge_gateway": "Webex cloud connectivity daemon (416KB ARM32 ELF, runs as root)",
        "/usr/sbin/cdp":          "Cisco Discovery Protocol daemon (215KB)",
        "/usr/sbin/downd":        "Firmware download daemon (43KB)",
        "/usr/sbin/dgetimage":    "Firmware image fetcher (47KB)",
        "/usr/sbin/secureapp":    "TLS policy enforcement (ARM32 ELF)",
        "/usr/sbin/curl":         "Embedded curl (179KB)",
    },
}

# ─────────────────────────────────────────────────────────
# Security library hashes — 14.4.1 MPP
# ─────────────────────────────────────────────────────────
SECURITY_LIB_SHA256 = {
    "libseccommon.so": {
        "sha256": "10ffea1ad2c379b8c6d042f196805540199a996dfaf6a22ce7ae0db91d871df4",
        "size":   43268,
        "note":   "Larger than MPP 11.3.3 (30812B) and UC 12.8.1 (~37K) — more handyiron features added",
    },
    "libsecurity.so": {
        "sha256": "233618126d35b031af95c3de1cad3651d90575a0ee92acdbe6116e0f1104f52d",
        "size":   69660,
        "note":   "Same size as UC 12.8.1 rootfs1 (69660B) — likely same binary",
    },
    "libssl.so.1.1": {
        "sha256":      "e6aa47ce530e807b672d2ffaf4a400435f4cb916e0ec0e7807c19c74960642ec",
        "size":        449376,
        "ssl_version": "CiscoSSL 1.1.1za.7.3.410",
        "note":        "Upgrade from 1.0.2o (UC 12.8.1) and 1.0.1c (MPP 11.3.3) — OpenSSL 1.1.1 base",
    },
    "libcrypto.so.1.1": {
        "sha256":      "56920eb47f8d4610e4eb382855d6cafbb774e472354fc74eeeaa3aa5e27dece8",
        "size":        2005040,
        "ssl_version": "CiscoSSL 1.1.1za.7.3.410",
    },
    "libatls.so": {
        "sha256": "891a94add2a60d3000c3dea8934b468d9004e15bf46d5f569c439c217184b69f",
        "size":   28064,
        "note":   "Cisco Application TLS wrapper — custom layer over libssl; exports tls_create_conn/tls_send/tls_recv",
    },
    "libhstls.so": {
        "sha256": "28bed232369dcb95c8daf00137ad5efe38c4320afe29a28b72102f5a99e2eacd",
        "size":   44280,
        "note":   "Second Cisco TLS variant — used alongside libatls.so",
    },
    "libfileauth.so": {
        "sha256": "df02a0ac81d959832e45763407a3349b012f36c76ee8d3d1116b16372f30f3be",
        "size":   26424,
        "note":   "File authentication: sec_pkey_encrypt_data, sec_validate_cert — firmware signature verification",
    },
    "libcisco.so": {
        "sha256": "24894cfadcc029594be8f1cfe657fea4e533af142662ec312f3d63650b6cae23",
        "size":   90312,
        "note":   "Generic Cisco utilities library; linked by edge_gateway and others",
    },
    "libedge.so": {
        "sha256": "39a351f7b4d5df6dca7ff790a7b0bf35499af91afcbf5956f06cfccb82be9fc3",
        "size":   51448,
        "note":   "Edge connectivity: edge_authorize, egdd_cucm_user_auth, egdd_getsipdigest; manages CUCM+Webex auth bridge",
    },
    "libsparkServer.so": {
        "sha256": "eab9f6629e32f17b5e1645b58121de252bfe00ed65a537cd458e58ba620e4c66",
        "size":   29956,
        "note":   "Webex/Spark cloud server communication",
    },
    "libhuronTruststore.so": {
        "sha256": "5a9c7c1b89fe79dc20d0f7222450c4f3b4922e0ffb6b4cc4235749b4ede24723",
        "size":   22364,
        "note":   "Manages trust anchors for Webex/Huron cloud: wdmService endpoint reference",
    },
    "libsip.so": {
        "sha256": "60716c3b8ff5d0d034993f5687965b4c23eb353015078f1488c7d0da134024d8",
        "size":   3987180,
        "note":   "Full SIP stack (3.8MB): sippmh_parse_authenticate, ccsip_common_util_generate_auth, egdd_getsipdigest",
    },
}

# ─────────────────────────────────────────────────────────
# Webex / Huron cloud integration (NEW in 14.x)
# ─────────────────────────────────────────────────────────
WEBEX_CLOUD_INTEGRATION = {
    "introduced": "14.x MPP — not present in 11.3.3 or UC 12.8.1 modules",
    "daemon":     "/usr/sbin/edge_gateway (416KB, ARM32, runs as root, capabilities: CAP_DAC_OVERRIDE+CAP_NET_ADMIN+CAP_IPC_OWNER+CAP_SYS_NICE)",
    "libraries":  ["libedge.so", "libEdgeNative.so", "libsparkServer.so", "libsparkDevice.so", "libspark.so", "libhuronTruststore.so", "libHuronContactService.so"],
    "hardcoded_endpoint": "https://wdm-a.wbx2.com/wdm/api/v1 (Webex Device Manager — primary device registration URL)",
    "additional_endpoints": {
        "uds":     "https://uds.<domain>/api/v1 (CUCM User Data Service — user auth query)",
        "minerva": "https://minerva.<domain> (Cisco cloud service, purpose TBD)",
    },
    "ipc":        "D-Bus: com.cisco.EdgeGatewayInterface1_adaptor._GetTokenStatus_stub",
    "token_mgmt": "tokenTTLInSec tracked; Huron access token stored and refreshed by edge_gateway",
    "trust_anchors": {
        "file":     "/etc/trust_store/gds_trustlist.pem (7114B)",
        "anchors": [
            "QuoVadis Root CA 2 (Bermuda, QuoVadis Limited)",
            "VeriSign Class 3 Public Primary Certification Authority - G5 (US, VeriSign)",
            "Cisco RXC-R2 (US, Cisco Systems) — Cisco private root CA",
            "Go Daddy Class 2 Certification Authority (The Go Daddy Group, Inc.)",
        ],
        "finding": (
            "gds_trustlist.pem (7KB) is the trust anchor set for all Webex/Huron cloud comms. "
            "It contains only 4 roots — including Cisco RXC-R2, a Cisco-controlled private CA. "
            "The phone explicitly trusts certs signed by Cisco's own PKI for device registration. "
            "Separate from the 656KB defaulttrustlist.pem used for general HTTPS."
        ),
    },
    "sip_digest_bridge": (
        "egdd_getsipdigest exported from libedge.so — edge_gateway is the runtime broker for "
        "SIP digest credentials. libsip.so queries the edge daemon rather than holding credentials "
        "directly. edge_gateway running as root with CAP_DAC_OVERRIDE is the single process "
        "holding both Webex OAuth tokens and SIP digest material simultaneously."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F14 — handyiron bypass (CONFIRMED in MPP 14.4.1)
# ─────────────────────────────────────────────────────────
PHN_F14 = {
    "id":     "PHN-F14",
    "status": "CONFIRMED in MPP 14.4.1",
    "strings_present": [
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - no certificate validation plugin available.",
        "SSL session setup Cert Verification - Accept Authenticator cert. without validation - any role is specified.",
    ],
    "location": "libseccommon.so (sha256: 10ffea1ad2c...)",
    "full_scope": [
        "78xx UC 12.5.1SR1-4 (PLATFORM_1 and PLATFORM_2)",
        "78xx UC 12.8.1 (both rootfs)",
        "8845-65 UC 12.8.1",
        "78xx MPP 11.3.3",
        "8845-65 MPP 11.3.3",
        "78xx MPP 14.4.1 (THIS MODULE)",
    ],
    "note": "Persistent across 4+ major firmware generations. libseccommon.so grows (30812→43268B) but bypass code not removed.",
}

# ─────────────────────────────────────────────────────────
# PHN-F15 — debug credential REGRESSION in MPP 14.4.1
# ─────────────────────────────────────────────────────────
PHN_F15_REGRESSION = {
    "id":     "PHN-F15",
    "status": "REGRESSION — re-enabled in MPP 14.4.1 after being disabled in MPP 11.3.3",

    "passwd_entry": "debug:$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71:65532:100:debug:/tmp:/usr/sbin/debugsh",
    "hash":    "$1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71",
    "format":  "MD5crypt ($1$)",
    "shell":   "/usr/sbin/debugsh (ACTIVE)",

    "regression_history": {
        "78xx UC 12.5.1SR1-4": "debug account ACTIVE (same hash)",
        "78xx UC 12.8.1":      "debug account ACTIVE (same hash)",
        "8845-65 UC 12.8.1":   "debug account ACTIVE (same hash)",
        "78xx MPP 11.3.3":     "debug account DISABLED (/bin/false, * hash) — remediation",
        "8845-65 MPP 11.3.3":  "debug account DISABLED (/bin/false, * hash) — remediation",
        "78xx MPP 14.4.1":     "debug account ACTIVE (same static hash returned) — REGRESSION",
    },

    "significance": (
        "The same static MD5 hash ($1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71) that is present "
        "in UC firmware has re-appeared in MPP 14.4.1 after being removed in 11.3.3. "
        "Cisco explicitly disabled it in MPP then re-enabled it — likely for Webex/cloud "
        "serviceability features added in 14.x. The hash is the same across all UC and "
        "14.4.1 MPP variants, indicating a shared static credential, not a per-device key."
    ),

    "debugshd": {
        "binary":   "/usr/sbin/debugshd (191KB ARM32, runs as root via start-stop-daemon --chuid root:root)",
        "ipc":      "Unix domain socket at /tmp/debugshd_sock (chmod 777)",
        "daemon":   "Started by /etc/init.d/debugshd.sh from S92phone.sh boot sequence",
        "serial":   "Also echoes to /dev/ttyS0 (serial UART at 115200)",
    },

    "debugsh_capabilities": {
        "binary":   "/usr/sbin/debugsh (15KB ARM32)",
        "links":    ["libupgapi.so", "libplatform.so", "libnetsd.so", "libcisco.so", "libedit.so (readline)"],
        "vuln":     "debugsh links libupgapi.so, granting authenticated debug users direct raw MTD/NAND write access (cprUpgFlashErase, cprNandWriteClose, mtd_erase, mtd_unlock) with no secondary authorization check",
        "mtd_functions": [
            "cprUpgFlashErase / cprUpgFlashErase2 — erase NAND partitions",
            "cprNandWriteClose — finalize NAND write",
            "cprUpgIsRunningBackupImage — check A/B partition state",
            "cprUpgGetModelNumber — device model",
            "mtd_read / mtd_erase / mtd_lock / mtd_unlock — raw MTD operations",
        ],
    },

    "sip_debug_credential_dump": {
        "command":  "debug auth (from SIP commands registered in /etc/sip.commands)",
        "effect":   "Dumps live SIP authentication state including digest credentials",
        "source":   "/etc/sip.commands + /etc/debugsh_apps = /usr/local/log.properties|/tmp/jvmTraceMgr",
        "note":     "debug fsm, debug sip-messages also available — captures full SIP REGISTER content",
    },
}

# ─────────────────────────────────────────────────────────
# PHN-F16 — CERT_ANY (CONFIRMED in MPP 14.4.1)
# ─────────────────────────────────────────────────────────
PHN_F16 = {
    "id":     "PHN-F16",
    "status": "CONFIRMED in MPP 14.4.1",
    "strings_present": [
        "CERT_ANY      : allow all unverified server certs",
        "HTTPS_ANY     : allow unverified HTTPS servers",
        "test option       : %sallow unverified srvr certs",
        "test option       : %sallow unverified HTTPS srvr",
    ],
    "location": "/usr/sbin/secureapp (ARM32 ELF, runs as root)",
    "full_scope": [
        "78xx UC 12.5.1SR1-4 rootfs2 (PLATFORM_2)",
        "78xx UC 12.8.1 (both rootfs)",
        "8845-65 UC 12.8.1",
        "78xx MPP 11.3.3",
        "8845-65 MPP 11.3.3",
        "78xx MPP 14.4.1 (THIS MODULE)",
    ],
    "note": "CERT_ANY and HTTPS_ANY modes allow complete TLS bypass. Persistent across all analyzed versions.",
}

# ─────────────────────────────────────────────────────────
# PHN-F17 — TLS cert validation bypass via oversized DER cert (edge_gateway)
# ─────────────────────────────────────────────────────────
PHN_F17 = {
    "id":      "PHN-F17",
    "title":   "TLS certificate validation bypass via oversized DER cert in edge_gateway Webex cloud path",
    "status":  "CONFIRMED — static analysis of libsecureapi.so + edge_gateway (78xx MPP 14.4.1)",
    "severity": "HIGH",

    "affected_binary": "/usr/sbin/edge_gateway (416KB ARM32, runs as root)",
    "affected_library": "libsecureapi.so (57KB ARM32) — sec_validate_cert (0xaa04), sec_validate_cert_der (0xa8e4)",

    "call_chain": (
        "edge_gateway:sub_0001cff4 calls SSL_CTX_set_cert_verify_callback(ctx, sub_0001cfb0, NULL). "
        "sub_0001cfb0 is the callback: X509_STORE_CTX_get0_cert(ctx) → sec_validate_cert(cert, 0x15) → return. "
        "No inversion. The callback returns sec_validate_cert's value directly to OpenSSL. "
        "OpenSSL cert_verify_callback convention: 1=accept, 0=reject."
    ),

    "sec_validate_cert_flow": {
        "step1": "i2d_X509(cert, NULL) — get DER size (r0)",
        "step2": "check: if (DER_size + 24) > 8192: return 1  [BUG: returns accept instead of reject]",
        "step3": "CRYPTO_malloc(DER_size) — allocate buffer",
        "step4": "i2d_X509(cert, &buf) — serialize to DER",
        "step5": "sec_validate_cert_der(buf, DER_size, mode=0x15) — dispatch to security daemon",
        "step6": "CRYPTO_free(buf); return sec_validate_cert_der result",
    },

    "sec_validate_cert_der_flow": {
        "0xa900": "if NULL ptr or len <= 0: dummySecPrint; return 1  [BUG: returns accept]",
        "0xa92c": "getSecReq() failure: dummySecPrint; return -1 (0xFFFFFFFF)  [BUG: non-zero = accept]",
        "0xa954": "if (len + 24) > 8192: dummySecPrint; freeSecReq; return 1  [BUG: returns accept]",
        "0xa9a0": "sendSecReq(req, 0x22, 0x78) — send to security daemon",
        "0xa9b8": "recvSecRep(req) — receive daemon verdict; r5 = verdict",
        "0xa9e4": "return r5  [only this path invokes the security daemon]",
    },

    "bug": (
        "All error paths in both sec_validate_cert and sec_validate_cert_der return non-zero (1 or -1). "
        "OpenSSL's SSL_CTX_set_cert_verify_callback interprets any non-zero return as 'cert accepted'. "
        "The intended behavior is that these paths return 0 (reject). "
        "The oversized-DER path (len + 24 > 8168) is the most reliably attacker-controlled trigger: "
        "a MITM attacker presenting a cert with padded X.509 extensions > 8168 bytes DER causes "
        "sec_validate_cert to return 1 without invoking sendSecReq/recvSecRep, bypassing all "
        "cert validation for edge_gateway's Webex cloud registration connection to wdm-a.wbx2.com."
    ),

    "exploit_condition": (
        "Attacker controls network path between phone and wdm-a.wbx2.com "
        "(local network MITM or upstream BGP hijack). "
        "Presents TLS cert with DER encoding > 8168 bytes (e.g., cert with 200+ SAN entries, "
        "large OID extension blobs, or padded custom extensions). "
        "Result: edge_gateway completes TLS handshake with attacker-controlled cert — "
        "Webex device registration and OAuth token exchange proceed against attacker server."
    ),

    "secondary_triggers": [
        "NULL X509* from X509_STORE_CTX_get0_cert (peer presented empty cert chain)",
        "i2d_X509 DER serialization failure (malformed internal OpenSSL cert object)",
        "getSecReq exhaustion (security daemon request pool full or daemon crashed) — returns -1 (accepted)",
    ],

    "plt_evidence": {
        "edge_gateway:0xa7b4":  "X509_STORE_CTX_get0_cert (PLT)",
        "edge_gateway:0xa964":  "SSL_CTX_set_cert_verify_callback (PLT)",
        "edge_gateway:0xab5c":  "sec_validate_cert (PLT → libsecureapi.so)",
        "libsecureapi:0xaa04":  "sec_validate_cert — confirmed entry VA, 316B",
        "libsecureapi:0xa8e4":  "sec_validate_cert_der — confirmed entry VA, 288B",
        "libsecureapi:plt_3":   "sec_validate_cert_der (PLT entry 0x2dfc — intra-SO PIC call)",
        "libsecureapi:plt_35":  "i2d_X509 (PLT 0x2f7c)",
        "libsecureapi:plt_72":  "sendSecReq (PLT 0x312c)",
        "libsecureapi:plt_115": "recvSecRep (PLT 0x333c)",
        "libsecureapi:plt_86":  "CRYPTO_malloc (PLT 0x31e0)",
        "libsecureapi:plt_140": "CRYPTO_free (PLT 0x3468)",
        "libsecureapi:plt_11":  "freeSecReq (PLT 0x2e5c)",
    },

    "impacted_connection": "Webex Device Manager (WDM) registration — wdm-a.wbx2.com (hardcoded in edge_gateway strings)",
    "trust_store_bypassed": "gds_trustlist.pem (4 CA roots including Cisco RXC-R2) — completely bypassed when DER > 8168B",
    "daemon_privileges":    "edge_gateway runs as root with CAP_DAC_OVERRIDE+CAP_NET_ADMIN+CAP_IPC_OWNER+CAP_SYS_NICE",
}

# ─────────────────────────────────────────────────────────
# Boot sequence and service map
# ─────────────────────────────────────────────────────────
BOOT_SEQUENCE = {
    "init":    "sysvinit, runlevel 5 default (/etc/inittab)",
    "rcS":     "S02banner → S03sysfs/udev → S10checkroot → S30ramdisk → S35mountall → S41networking → S99finish",
    "rc5.d":   {
        "S20syslog":   "syslog daemon",
        "S42crond":    "cron",
        "S49restart_mgr": "restart manager",
        "S90makedirs": "create /usr/local/* runtime dirs (chmod 0777)",
        "S91correct":  "unknown correction script",
        "S92phone.sh": "MAIN PHONE STARTUP: netsd → dnsmasq → ntp → downd → secureapp → pae → ewcl → pwrman → dman → vieo → ms → rlogcoll → metmand → edge_gateway → java (CVM) → healthd → debugshd → iptables",
    },
    "firewall": "iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP (ONLY rule — minimal filtering)",
    "ssh":      "sshd defined in /usr/local/xinetd/sshd but disable=yes; xinetd started (PID file /var/run/xinetd.pid)",
    "fips":     "FIPS mode gated by /usr/local/etc/secFipsModeEnabled (runtime flash); if absent CISCOSSL_FOM_DIAG=SKIP_POST set",
    "cvm":      "Java-based main phone application (/bin/java ARM32 JVM, started last)",
}

# ─────────────────────────────────────────────────────────
# Version comparison vs prior modules
# ─────────────────────────────────────────────────────────
VERSION_DELTA = {
    "CiscoSSL": {
        "MPP 11.3.3 (78xx)":  "CiscoSSL-1.0.1c.3.0-fips",
        "UC 12.8.1":           "CiscoSSL 1.0.2o.6.2.238-fips",
        "MPP 14.4.1":          "CiscoSSL 1.1.1za.7.3.410",
        "note":                "First time 1.1.1 base seen in 78xx firmware",
    },
    "libseccommon.so size": {
        "MPP 11.3.3":  "30812B",
        "UC 12.8.1":   "~37K",
        "MPP 14.4.1":  "43268B (growing — Webex features added)",
    },
    "new_in_14.4.1": [
        "edge_gateway daemon + full Webex/Huron cloud stack (libspark*.so, libHuron*.so)",
        "libatls.so + libhstls.so (dual custom TLS wrappers over OpenSSL 1.1.1)",
        "libfileauth.so (firmware signing verification library)",
        "D-Bus IPC between phone processes",
        "OAuth/access token management (tokenTTLInSec)",
        "GDS trust store for Webex cloud (gds_trustlist.pem — 4 CA roots)",
        "PHN-F15 debug credential regression",
    ],
}
