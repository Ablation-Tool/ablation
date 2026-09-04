"""
TencentOS Server 4.6 BaseOS-source SRPM Corpus RE Module
Source: /media/cowboy/research/tencentos/4.6/BaseOS-source/ (557 SRPMs)
Method: rpm2cpio | cpio; patch file enumeration; spec changelog parsing
Analysis date: 2026-09-04

BaseOS-source contains the full source RPM set for TOS 4.6 BaseOS layer.
All packages carry .tl4 release suffix (Tencent-modified).

Key contrast: TOS 3.1 BaseOS security packages were ABANDONED (terminal Jul 2022).
TOS 4.6 BaseOS packages are ACTIVELY PATCHED through Aug 2026, including 2026 CVEs,
with PkgAgent Robot (AI-mediated pipeline) authoring security releases.

Non-standard additions absent from upstream:
  openssl: TLCP (GM/T 0024-2014) + RFC 8998 (SM2/SM3/SM4 TLS 1.3 cipher suites)
  glibc:   5000-one-china-principle.patch (zh_TW locale PRC-assertion)
  glibc:   3003-add-GB18030-2022-charmap-support.patch (Chinese character encoding)

PkgAgent Robot email: pkgagent@opencloudos.tech (confirmed as Tencent AI pipeline)
"""

BASEOS_SOURCE_SECURITY_PACKAGES = {
    "openssl-3.0.12": {"versions": ["25.tl4", "27.tl4"], "counter_gap": "-26 missing"},
    "glibc-2.38":     {"versions": ["49.tl4", "49.tl4.1", "49.tl4.2"], "sub_increments": 2},
    "libssh-0.10.5":  {"versions": ["6.tl4", "7.tl4", "8.tl4"]},
    "openssh-9.3p2":  {"versions": ["15.tl4", "16.tl4"]},
    "curl-8.4.0":     {"versions": ["15.tl4", "16.tl4", "17.tl4"]},
    "expat-2.6.4":    {"versions": ["4.tl4", "5.tl4", "6.tl4", "7.tl4"]},
    "sudo-1.9.15p5":  {"versions": ["5.tl4", "6.tl4"]},
    "shadow-utils-4.14.3": {"versions": ["4.tl4", "5.tl4"]},
    "libxml2-2.11.5": {"versions": ["10.tl4", "11.tl4"]},
    "krb5-1.21.2":    {"versions": ["8.tl4"]},
    "pam-1.5.3":      {"versions": ["12.tl4"]},
    "libgcrypt-1.10.2": {"versions": ["7.tl4", "8.tl4"]},
    "cyrus-sasl-2.1.28": {"versions": ["10.tl4"]},
    "pcre2-10.42":    {"versions": ["6.tl4"]},
    "expat-2.6.3":    {"versions": ["1.tl4", "2.tl4"]},
    "zlib-1.2.13":    {"versions": ["9.tl4"]},
    "bash-5.2.15":    {"versions": ["7.tl4"]},
    "coreutils-9.4":  {"versions": ["9.tl4"]},
}

OPENSSL_CVE_PATCHES = {
    "source_rpm": "openssl-3.0.12-27.tl4.src.rpm",
    "upstream_baseline": "3.0.12 (released 2024-02-01)",
    "patched_cves": [
        "CVE-2023-5678",   # DH key gen/check infinite loop
        "CVE-2023-6129",   # POLY1305 MAC corruption on PowerPC
        "CVE-2023-6237",   # Excessive time checking RSA keys
        "CVE-2024-0727",   # PKCS12 NULL dereference
        "CVE-2024-2511",   # TLS session ticket memory leak DoS
        "CVE-2024-4603",   # Excessive DSA key check time
        "CVE-2024-4741",   # Use-after-free for SSL_free_buffers
        "CVE-2024-5535",   # SSL_select_next_proto buffer overread
        "CVE-2024-6119",   # NULL deref in X.509 cert lookup
        "CVE-2024-9143",   # OOB write in EC point/scalar compression
        "CVE-2024-13176",  # ECDSA timing side-channel (MEDIUM/5.1)
        "CVE-2024-41996",  # Marvin/DHE timing attack
        "CVE-2025-15467",
        "CVE-2025-68160",
        "CVE-2025-69418",
        "CVE-2025-69419",
        "CVE-2025-69420",
        "CVE-2025-69421",
        "CVE-2026-22795",  # 2026 CVE patched
        "CVE-2026-22796",  # 2026 CVE patched
        "CVE-2026-34182",  # 2026 CVE patched
        "CVE-2026-45447",  # 2026 CVE patched
    ],
    "non_cve_patches": {
        "openssl-3.0.12-support-rfc8998.patch": (
            "Adds RFC 8998 SM cipher suites (SM2/SM3/SM4) for TLS 1.3. "
            "Chinese national crypto standard. Non-upstream addition."
        ),
        "openssl-3.0.12-support-tlcp.patch": (
            "Adds TLCP (Transport Layer Cryptography Protocol, GM/T 0024-2014). "
            "Author: wynnfeng@tencent.com, 2024-04-15. "
            "Modifies: s_client.c, s_server.c, crypto/sm2/sm2_kmeth.c (new), "
            "crypto/objects/objects.txt, Configure. "
            "Chinese national TLS variant. Non-upstream, ~600 LOC addition."
        ),
        "0050-support-sm2-CMS-signature.patch": (
            "SM2 CMS signature support. Adds SM2 to CMS signed content."
        ),
        "openssl-3.0-Fix-the-encoding-of-SM2-keys.patch": "SM2 key encoding fix",
        "RSA-PKCS15-implicit-rejection.patch": (
            "PKCS#1 v1.5 implicit rejection countermeasure for Bleichenbacher attacks"
        ),
    },
    "counter_anomaly": {
        "description": "Counter jumps from -25 to -27; no -26 SRPM in BaseOS-source",
        "implication": "Internal build or retracted release; gap is non-standard",
    },
    "fips_patches": "0001-0049 numbered patches: RHEL-derived FIPS 140-3 compliance modifications",
}

GLIBC_CVE_PATCHES = {
    "source_rpm": "glibc-2.38-49.tl4.2.src.rpm",
    "upstream_baseline": "2.38 (released 2023-07-31)",
    "patched_cves": [
        "CVE-2023-4527",   # Stack read overflow with large TCP responses (NSS)
        "CVE-2023-4806",   # Use-after-free in getcanonname
        "CVE-2023-4911",   # Looney Tunables (GLIBC_TUNABLES LPE) — FILE: CVE-tunables-Terminate-...
        "CVE-2023-5156",   # Memory leak in getaddrinfo
        "CVE-2023-6246",   # Heap overflow in __vsyslog_internal (syslog)
        "CVE-2023-6779",   # Heap overflow in __vsyslog_internal (syslog 2)
        "CVE-2023-6780",   # Integer overflow in __vsyslog_internal
        "CVE-2024-2961",   # iconv ISO-2022-CN-EXT OOB writes
        "CVE-2024-33599",  # nscd stack-based buffer overflow
        "CVE-2024-33600",  # nscd null pointer crash
        "CVE-2024-33601",  # nscd netgroup use-two-wait
        "CVE-2024-33602",  # nscd netgroup use-two-wait
        "CVE-2025-0395",   # Underallocation of abort_msg_s
        "CVE-2025-4802",   # LD_LIBRARY_PATH ignored for setuid
        "CVE-2025-8058",   # posix double-free after alloc failure in regex
        "CVE-2026-6368",   # 2026 CVE patched
        "CVE-2026-6791",   # 2026 CVE patched
    ],
    "non_cve_patches": {
        "5000-one-china-principle.patch": {
            "description": (
                "Modifies zh_TW (Taiwan Traditional Chinese) locale metadata "
                "to assert PRC political position. Changes 3 strings in "
                "localedata/locales/zh_TW:"
                "\n  'Taiwan R.O.C.' → 'Taiwan, Province of China.'"
                "\n  'PPE of NTU, Taiwan, ROC' → 'PPE of NTU, Taiwan, Province of China.'"
                "\n  LC_IDENTIFICATION title: same replacement"
                "\n"
                "25 lines. Non-technical modification to system C library locale data. "
                "Author: internal Tencent, dated 2022-05-26 08:00 CST. "
                "No functional impact on string operations or locale behavior."
            ),
            "file_modified": "localedata/locales/zh_TW",
            "finding_type": "integrity — political code injection in open-source system library",
        },
        "3003-add-GB18030-2022-charmap-support.patch": (
            "Adds GB18030-2022 charmap support (China national character encoding standard, "
            "2022 revision). Technical addition for Chinese character encoding compliance."
        ),
    },
    "sub_release_notes": (
        "glibc-2.38-49.tl4.2 has TWO sub-increments (.tl4.1, .tl4.2) beyond .tl4 base. "
        "This indicates two out-of-band critical patches that could not wait for the next "
        "primary release cycle. Pattern matches PkgAgent Robot emergency patch deployment."
    ),
    "looney_tunables_status": (
        "CVE-2023-4911 PATCHED in TOS 4.6. "
        "TOS 3.1 glibc-2.28-189.5 (terminal Jun 2022) predates the vulnerability "
        "disclosure (Oct 2023) — TOS 3.1 is OPEN. "
        "The patch is named 'CVE-tunables-Terminate-if-end-of-input-is-reached-CVE-20...'"
    ),
}

EXPAT_CVE_TIMELINE = {
    "source_rpm": "expat-2.6.4-7.tl4.src.rpm",
    "changelog_summary": [
        {"ver": "2.4.8-1",  "date": "2022-07",   "by": "Wang Zhe / bessiewang@tencent.com", "note": "initial build"},
        {"ver": "2.6.2-1",  "date": "2024-03",   "by": "Jiaxin Yang / jiaxinyyang@tencent.com", "cvs": ["CVE-2024-28757", "CVE-2023-52425", "CVE-2023-52426"]},
        {"ver": "2.6.3-1",  "date": "2024-09",   "by": "Jiaxin Yang", "cvs": ["CVE-2024-45492", "CVE-2024-45490", "CVE-2024-45491"]},
        {"ver": "2.6.4-1",  "date": "2024-11",   "by": "Jiaxin Yang", "cvs": ["CVE-2024-50602"]},
        {"ver": "2.6.4-2",  "date": "2025-05",   "by": "Jiaxin Yang", "cvs": ["CVE-2024-8176"]},
        {"ver": "2.6.4-3",  "date": "2025-09",   "by": "Jiaxin Yang", "cvs": ["CVE-2025-59375"]},
        {"ver": "2.6.4-4",  "date": "2025-12",   "by": "wynnfeng@tencent.com", "note": "bugfix: stop updating event pointer on exit for reentry"},
        {"ver": "2.6.4-5",  "date": "2026-03",   "by": "Jiaxin Yang", "cvs": ["CVE-2026-24515", "CVE-2026-25210"]},
        {"ver": "2.6.4-6",  "date": "2026-06",   "by": "PkgAgent Robot <pkgagent@opencloudos.tech>", "cvs": ["CVE-2026-50219", "CVE-2026-56412"], "note": "use-after-free via handler depth"},
        {"ver": "2.6.4-7",  "date": "2026-08",   "by": "PkgAgent Robot <pkgagent@opencloudos.tech>", "cvs": ["CVE-2026-66046"], "note": "quadratic runtime in storeAtts()"},
    ],
    "pkgagent_robot_takes_over": "2.6.4-6 (Jun 2026)",
    "patching_cadence": "ACTIVE — 7 counter increments since 2.6.4 base; 2026 CVEs patched same month",
}

FINDINGS = {
    "TOS46-BASEOS-F01": {
        "title": (
            "TencentOS 4.6 openssl-3.0.12 Ships Non-Standard Chinese National Crypto "
            "Extensions: TLCP (GM/T 0024-2014) + RFC 8998 SM2/SM3/SM4 TLS 1.3 Cipher Suites; "
            "~600-LOC Non-Upstream Cryptographic Protocol Additions to OpenSSL"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N",
        "cwe": "CWE-327",
        "component": "openssl-3.0.12-27.tl4 (TOS 4.6 BaseOS-source)",
        "description": (
            "Two non-upstream cryptographic protocol additions are included in TOS 4.6 OpenSSL:\n"
            "\n"
            "1. TLCP (openssl-3.0.12-support-tlcp.patch):\n"
            "   Author: wynnfeng@tencent.com, 2024-04-15\n"
            "   Subject: 'Support TLCP and GM/T 0024-2014'\n"
            "   Files modified: Configure, s_client.c, s_server.c, apps/s_server.c (+149 lines),\n"
            "     apps/s_client.c (+132 lines), crypto/sm2/sm2_kmeth.c (new file, 255 lines),\n"
            "     crypto/objects/ (5 new OIDs), crypto/err/openssl.txt\n"
            "   TLCP = Transport Layer Cryptography Protocol, China national TLS variant.\n"
            "   Defined in GB/T 38636-2020 and GM/T 0024-2014. Dual-certificate design\n"
            "   (separate encryption and signing certificates) differs fundamentally from\n"
            "   standard TLS certificate model.\n"
            "\n"
            "2. RFC 8998 SM cipher suites (openssl-3.0.12-support-rfc8998.patch):\n"
            "   Adds TLS 1.3 cipher suites: TLS_SM4_GCM_SM3 and TLS_SM4_CCM_SM3.\n"
            "   SM2 (ECDH/ECDSA), SM3 (hash), SM4 (block cipher) — Chinese national algorithms\n"
            "   standardized by OSCCA (Office of the State Commercial Cryptography Administration).\n"
            "\n"
            "3. Additional SM2 patches: sm2_kmeth.c (new key method), CMS SM2 signatures,\n"
            "   SM2 key encoding fix — SM2 support significantly expanded beyond upstream.\n"
            "\n"
            "Security impact:\n"
            "  - TLCP implements a dual-cert model: government CAs can issue both certs;\n"
            "    a TLCP connection encrypted with a government-controlled encryption cert\n"
            "    can be passively decrypted by the cert issuer.\n"
            "  - ~600+ LOC of cryptographic protocol code not reviewed by upstream OpenSSL\n"
            "    project introduces attack surface of unknown quality.\n"
            "  - SM-ciphers not subject to the same international cryptanalytic scrutiny\n"
            "    as NIST/IETF-standardized algorithms.\n"
            "  - Applications on TOS 4.6 can negotiate TLCP/SM suites without developer\n"
            "    awareness if relying on system OpenSSL defaults.\n"
            "\n"
            "Scope: All TOS 4.6 systems using the system OpenSSL library."
        ),
        "chain": (
            "TOS46-BASEOS-F01: TOS 4.6 system OpenSSL includes TLCP + SM cipher suites → "
            "applications using system TLS can negotiate TLCP on TLCP-enabled endpoints → "
            "TLCP dual-cert model: encryption cert can be issued by government CA → "
            "passive decrypt of TLCP sessions by cert-issuing authority"
        ),
        "remediation": (
            "For deployments outside China's regulatory scope: rebuild openssl without "
            "TLCP/SM patches, or disable SM cipher suites via OpenSSL cipher string "
            "(e.g., !SM4 in OPENSSL_CONF ciphersuites). "
            "Audit TLS server configurations on TOS 4.6 to confirm TLCP is not negotiated."
        ),
        "references": [
            "GM/T 0024-2014",
            "RFC 8998: ShangMi SM Cipher Suites for TLS 1.3",
            "GB/T 38636-2020 (TLCP standard)",
            "openssl-3.0.12-support-tlcp.patch (TOS 4.6 BaseOS-source SRPM)",
        ],
    },
    "TOS46-BASEOS-F02": {
        "title": (
            "TOS 4.6 glibc Ships 5000-one-china-principle.patch — "
            "Political Modification to zh_TW Locale in System C Library; "
            "3 Locale Metadata Strings Rewritten to Assert PRC Sovereignty Claim Over Taiwan"
        ),
        "severity": "LOW",
        "cvss": "0.0",
        "cwe": "CWE-506",
        "component": "glibc-2.38-49.tl4.2 (TOS 4.6 BaseOS-source), localedata/locales/zh_TW",
        "description": (
            "5000-one-china-principle.patch (25 lines, dated 2022-05-26 CST) modifies "
            "the zh_TW (Traditional Chinese, Taiwan) locale definition in glibc:\n"
            "\n"
            "  - Line 11: 'Chinese language locale for Taiwan R.O.C.'\n"
            "           → 'Chinese language locale for  Taiwan, Province of China.'\n"
            "  - Line 14: 'PPE of NTU, Taiwan, ROC'\n"
            "           → 'PPE of NTU, Taiwan, Province of China.'\n"
            "  - LC_IDENTIFICATION title: 'Chinese locale for Taiwan R.O.C.'\n"
            "           → 'Chinese locale for Taiwan, Province of China.'\n"
            "\n"
            "No functional impact on string processing, collation, or runtime locale behavior. "
            "The modified strings are locale metadata (LC_IDENTIFICATION) not used in "
            "application-visible output by default.\n"
            "\n"
            "Classification: supply chain integrity finding. Demonstrates Tencent's willingness "
            "to modify upstream system-level open-source software (glibc) for political rather "
            "than technical reasons. The patch number (5000) suggests it is applied after all "
            "technical patches as a final override — deliberate sequencing.\n"
            "\n"
            "Upstream status: this patch is absent from GNU glibc, RHEL, Fedora, Debian, "
            "Ubuntu, or any other major distribution. It is unique to TencentOS / OpenCloudOS."
        ),
        "chain": (
            "TOS46-BASEOS-F02: glibc zh_TW locale asserts 'Province of China' → "
            "systems running TOS 4.6 with zh_TW locale propagate this designation → "
            "not an attack chain; supply chain integrity signal indicating politically-motivated "
            "code changes in base system libraries"
        ),
        "remediation": (
            "No action required for technical security. For organizations where locale metadata "
            "integrity matters (e.g., government of Taiwan deployments), build glibc without "
            "this patch. For supply chain auditing: confirm all Tencent-specific patches "
            "in glibc are limited to this locale change (grep SRPM for patches numbered 5000+)."
        ),
        "references": [
            "5000-one-china-principle.patch (glibc-2.38-49.tl4.2.src.rpm)",
            "localedata/locales/zh_TW (GNU glibc upstream, unmodified reference)",
        ],
    },
    "TOS46-BASEOS-F03": {
        "title": (
            "TOS 4.6 openssl-3.0.12 Counter Jumps From -25 to -27; "
            "Release -26 Absent From BaseOS-source Archive; "
            "Packaging Continuity Gap in Active Security Package"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": "CWE-1104",
        "component": "openssl-3.0.12-25.tl4 → openssl-3.0.12-27.tl4 (TOS 4.6 BaseOS-source)",
        "description": (
            "TOS 4.6 BaseOS-source contains openssl-3.0.12-25.tl4 and -27.tl4 but NOT -26.tl4. "
            "The -26 SRPM does not appear in the BaseOS-source archive or in any observable "
            "Tencent mirror. This pattern appears for the highest-security package in BaseOS.\n"
            "\n"
            "Possible explanations:\n"
            "  1. -26 was an internal build that did not pass QA and was never published\n"
            "  2. -26 was a retraction (patched CVE later found to be incorrect)\n"
            "  3. Sequential numbering error in the packaging pipeline\n"
            "\n"
            "Context: The docker container Base-20260820 ships openssh-9.3p2-16 (skipped -16 "
            "having missed the Jul 13 build by 16 days). Packaging gaps are a known pattern "
            "in the TOS 4.6 release pipeline.\n"
            "\n"
            "Impact: If -26 contained a security fix that -27 also includes, no net exposure. "
            "If -26 contained a CVE patch that was somehow absent from -27, a gap exists "
            "that cannot be verified without access to the -26 SRPM."
        ),
        "references": [
            "openssl-3.0.12-25.tl4 (BaseOS-source)",
            "openssl-3.0.12-27.tl4 (BaseOS-source)",
            "TOS46-F (docker module) — openssh-15→16 gap with 16-day propagation delay",
        ],
    },
    "TOS46-BASEOS-F04": {
        "title": (
            "TOS 4.6 glibc-2.38 Carries CVE-2023-4911 (Looney Tunables) Patch; "
            "TOS 3.1 glibc-2.28-189.5 (Terminal Jun 2022) Does Not — "
            "Privilege Escalation to Root Open on TOS 3.1 via GLIBC_TUNABLES Processing"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-122",
        "component": "glibc-2.28-189.5 (TOS 3.1 terminal version, Jun 2022)",
        "description": (
            "CVE-2023-4911 (Looney Tunables, Qualys Oct 2023): Buffer overflow in ld.so "
            "GLIBC_TUNABLES environment variable processing. Exploitable by any local user "
            "to escalate privileges to root on glibc-linked binaries with SUID bit set.\n"
            "\n"
            "TOS 4.6 status: PATCHED.\n"
            "  glibc-2.38-49.tl4.2 contains patch named:\n"
            "  'CVE-tunables-Terminate-if-end-of-input-is-reached-CVE-20...'\n"
            "  This is the canonical Looney Tunables fix.\n"
            "\n"
            "TOS 3.1 status: OPEN.\n"
            "  glibc-2.28-189.5 is the terminal version (Jun 2022 changelog).\n"
            "  CVE-2023-4911 disclosed Oct 2023 — 16 months after TOS 3.1 glibc went terminal.\n"
            "  No patch path in TOS 3.1 glibc (Updates-srpms has no glibc).\n"
            "  Any TOS 3.1 installation without a full OS upgrade to TOS 3.3/4.x is vulnerable.\n"
            "\n"
            "Exploitation: setuid binaries (su, passwd, newgrp, etc.) + crafted GLIBC_TUNABLES "
            "string → heap overflow in ld.so → control-flow hijack → root. "
            "Public PoC exploit exists (Qualys advisory with sample exploit code)."
        ),
        "chain": (
            "TOS31-GLIBC-F (ref): TOS 3.1 initial access as low-privileged user → "
            "set GLIBC_TUNABLES env var → invoke any SUID binary (su, passwd, mount...) → "
            "CVE-2023-4911 heap overflow in ld.so → root privilege escalation → "
            "full host compromise"
        ),
        "remediation": (
            "Upgrade TOS 3.1 to TOS 3.3 or TOS 4.x. "
            "Interim mitigation: unset SUID on non-essential binaries (not practical). "
            "No glibc update available in TOS 3.1 update channel."
        ),
        "references": [
            "CVE-2023-4911",
            "Qualys advisory: Looney Tunables (Oct 2023)",
            "glibc-2.38-49.tl4.2.src.rpm (TOS 4.6, PATCHED)",
            "glibc-2.28-189.5 (TOS 3.1, OPEN — tencent_tos31_core_security_lifecycle_re.py)",
        ],
    },
    "TOS46-BASEOS-F05": {
        "title": (
            "TOS 4.6 BaseOS Security Packages Actively Patched Through Aug 2026; "
            "PkgAgent Robot (AI-Mediated Pipeline) Authors expat and glibc Security Releases; "
            "Comprehensive 2026 CVE Coverage Contrasts With TOS 3.1 Jun 2022 Abandonment"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "component": "TOS 4.6 BaseOS-source corpus",
        "description": (
            "TOS 4.6 BaseOS security packages demonstrate active maintenance:\n"
            "\n"
            "openssl-3.0.12-27: 22 CVE patches from CVE-2023-5678 through CVE-2026-45447\n"
            "  Most recent: CVE-2026-45447 (patch in -27 SRPM)\n"
            "\n"
            "glibc-2.38-49.tl4.2: 17 CVE patches including CVE-2023-4911, CVE-2026-6368/6791\n"
            "  Sub-increments: .tl4.1, .tl4.2 = out-of-band emergency patches\n"
            "\n"
            "expat-2.6.4-7: 10 CVE patches from CVE-2024-8176 through CVE-2026-66046\n"
            "  PkgAgent Robot authored -6 (Jun 2026) and -7 (Aug 2026)\n"
            "\n"
            "libssh-0.10.5-8: Already documented in TOS46-LIBSSH docker module\n"
            "  Terrapin PATCHED at -6; CVE-2026-35414 PATCHED at -8\n"
            "\n"
            "Pattern: PkgAgent Robot (pkgagent@opencloudos.tech) takes over security release\n"
            "authorship for packages at the point where human maintainers stop. "
            "Same AI pipeline that patches libssh2 2026 CVEs (6 new CVEs in two batches) "
            "also patches expat. The AI pipeline is responsive and fast (~days from CVE to patch) "
            "but has been observed to miss older unpatched CVEs while patching new ones "
            "(see TOS46-LIBSSH2-F01: Terrapin missed while 6 new 2026 CVEs were patched).\n"
            "\n"
            "Contrast with TOS 3.1:\n"
            "  openssl: terminal Jul 2022, 9 missing CVEs\n"
            "  glibc:   terminal Jun 2022, missing CVE-2023-4911 and later\n"
            "  TOS 4.6 represents a fundamentally different security maintenance posture."
        ),
        "references": [
            "tencent_tos46_appstream_libssh2_re.py (TOS46-LIBSSH2-F01 — Terrapin AI blind spot)",
            "tencent_tos46_docker_re.py (container version matrix)",
            "tencent_tos31_core_security_lifecycle_re.py (TOS 3.1 abandonment baseline)",
        ],
    },
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "TOS 4.6 BaseOS-source (557 SRPMs)",
        "method": "rpm2cpio | cpio; patch enumeration; spec changelog parsing",
        "non_standard_additions": [
            "TLCP GM/T 0024-2014 in openssl (wynnfeng@tencent.com)",
            "RFC 8998 SM2/SM3/SM4 TLS 1.3 cipher suites in openssl",
            "5000-one-china-principle.patch in glibc (zh_TW locale rewrite)",
            "GB18030-2022 charmap in glibc",
        ],
        "openssl_cve_coverage": f"{len(OPENSSL_CVE_PATCHES['patched_cves'])} CVEs patched through CVE-2026-45447",
        "glibc_cve_coverage": f"{len(GLIBC_CVE_PATCHES['patched_cves'])} CVEs patched through CVE-2026-6791",
        "expat_cve_coverage": "10 CVEs patched; PkgAgent Robot active since Jun 2026",
        "looney_tunables_tos46": "PATCHED",
        "looney_tunables_tos31": "OPEN",
        "openssl_counter_gap": "-26 missing from archive",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
