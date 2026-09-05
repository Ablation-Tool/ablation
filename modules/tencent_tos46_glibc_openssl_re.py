"""
TencentOS 4.6 — glibc 2.38 + OpenSSL 3.0.12 patch stack RE.

Source: glibc46/ and ssl_work/ scratchpad directories.
Covers: CVE patches, architecture support (Sw64/LoongArch/Hygon),
Chinese national crypto (SM2/SM3/SM4/TLCP), locale modifications.
"""

METADATA = {
    "packages": {
        "glibc": "2.38-49.tl4.2",
        "openssl": "3.0.12-27.tl4",
    },
    "patch_count": {
        "glibc": "~200 patches (CVEs + arch support + locale)",
        "openssl": "~50 patches (FIPS + SM ciphers + TLCP + arch)",
    },
}

GLIBC_CVES = {
    "CVE-2026-0861": {
        "title": "memalign: alignment overflow check dropped by PTRDIFF_MAX change",
        "file": "malloc/malloc.c",
        "function": "_int_memalign",
        "reporter": "Igor Morgenstern, Aisle Research",
        "author": "Siddhesh Poyarekar",
        "description": (
            "A prior change capped valid allocation sizes to PTRDIFF_MAX. "
            "This change inadvertently dropped the separate alignment overflow check "
            "from _int_memalign() and _mid_memalign(). "
            "Without the check, posix_memalign/memalign/aligned_alloc with an alignment "
            "argument > PTRDIFF_MAX did not return EINVAL and instead proceeded with "
            "arithmetic that could overflow, leading to under-allocation and heap corruption."
        ),
        "fix": "Added 'alignment > PTRDIFF_MAX' check in _int_memalign; returns ENOMEM if true.",
        "vulnerable_commit": "9bf8e29ca136094f73f69f725f15c51facc97206",
        "class": "integer-overflow",
    },
    "CVE-2025-15281": {
        "bz": "33814",
        "title": "wordexp WRDE_REUSE: free of invalid pointer via wrong we_wordv update",
        "file": "posix/wordexp.c",
        "author": "Adhemerval Zanella (Linaro)",
        "description": (
            "When wordexp() is called with WRDE_REUSE flag on a previously used wordexp_t, "
            "the old we_wordv buffer is freed, but we_wordc retains its old value and "
            "we_wordv is updated at the wrong offset (position we_wordc into the new buffer, "
            "not position 0). "
            "A subsequent wordfree() then calls free() with a pointer that is offset from "
            "the actual allocation base by we_wordc * sizeof(char*), causing heap corruption "
            "or abort() from the allocator."
        ),
        "fix": "Reset we_wordv to base (position 0) and we_wordc to 0 before WRDE_REUSE processing.",
        "class": "invalid-free",
    },
    "CVE-2026-0915": {
        "title": "getnetbyaddr: net=0 causes uninitialized stack bytes in DNS query",
        "file": "resolv/nss_dns/dns-network.c",
        "function": "_nss_dns_getnetbyaddr_r",
        "author": "Carlos O'Donell (Red Hat)",
        "description": (
            "getnetbyaddr(0, AF_INET) hits a switch case with no default, leaving qbuf "
            "uninitialized (stack bytes). The DNS query is constructed from the uninitialized "
            "buffer and sent to the nameserver, leaking stack contents in the query name. "
            "Can be triggered by any application calling getnetbyaddr(0, AF_INET)."
        ),
        "fix": "Added default case: strcpy(qbuf, '0.0.0.0.in-addr.arpa');",
        "class": "info-disclosure",
        "observable": "Wireshark shows random QNAME before fix; '0.0.0.0.in-addr.arpa' after fix",
    },
    "CVE-2026-6368": {
        "bz": "34090",
        "title": "wordexp WRDE_APPEND: use-after-free via dangling we_wordv after realloc",
        "file": "posix/wordexp.c",
        "author": "Adhemerval Zanella (Linaro)",
        "description": (
            "wordexp() with WRDE_APPEND saved the wordexp_t at entry and restored it blindly "
            "(*pwordexp = old_word) on error. When WRDE_APPEND is set, w_addword may have "
            "called realloc on we_wordv during partial processing before the error. "
            "If realloc relocated the buffer, the saved we_wordv pointer is dangling. "
            "Restoring it causes use-after-free in the caller (e.g., wordfree), and the "
            "relocated buffer is leaked. "
            "Also: POSIX violation — WRDE_APPEND must not modify pwordexp->we_wordc/we_wordv on error."
        ),
        "fix": (
            "Duplicate we_wordv at entry when WRDE_APPEND is set so all realloc calls "
            "inside w_addword operate on the copy. "
            "Also fixed two error paths in '\"' and '\\'' cases that returned from "
            "w_addword failures without going through do_error (leaking the saved array)."
        ),
        "class": "use-after-free",
    },
    "CVE-2026-6791": {
        "bz": "34091",
        "title": "wordexp tilde expansion: stack overflow via strndupa with user-controlled length",
        "file": "posix/wordexp.c",
        "function": "parse_tilde",
        "author": "Adhemerval Zanella (Linaro)",
        "description": (
            "parse_tilde() used strndupa() to allocate a username from the wordexp input on "
            "the stack. Since the username length is derived from user-controlled input "
            "(the string after ~), a sufficiently long username triggers alloca() with "
            "a user-controlled size, causing stack overflow."
        ),
        "fix": "Replaced strndupa with scratch_buffer, reusing the buffer from the __getpwnam_r call.",
        "class": "stack-overflow",
    },
    "CVE-2025-4802": {
        "title": "ld.so: LD_LIBRARY_PATH honored in setuid/setgid context",
        "description": "ld.so debug environment variables not fully sanitized for setuid/setgid.",
        "class": "privilege-escalation",
    },
    "CVE-2025-8058": {
        "title": "posix: double-free after allocation failure in regex",
        "class": "double-free",
    },
    "CVE-2025-0395": {
        "title": "abort_msg_s: underallocation causes OOB write on abort",
        "file": "debug/",
        "class": "heap-overflow",
    },
}

GLIBC_ARCH_SUPPORT = {
    "Sw64": {
        "architecture": "Sunway (申威) — Chinese domestic CPU (Matrix 2000, SW-64 ISA)",
        "developer": "Sunway / NUDT (National University of Defense Technology)",
        "patch_count": "~24 patches",
        "patches": [
            "Sw64-Add-Sw64-entries-to-config.h.in.patch",
            "Sw64-Add-relocations-and-ELF-flags-to-elf.h.patch",
            "Sw64-ABI-Implementation.patch",
            "Sw64-Thread-Local-Storage-Support.patch",
            "Sw64-Generic-math.h-and-soft-fp-Routines.patch",
            "Sw64-Atomic-and-Locking-Implementation.patch",
            "Sw64-Linux-Syscall-Interface.patch",
            "Sw64-Linux-ABI.patch",
            "Sw64-Add-ABI-Lists.patch",
            "Sw64-Build-Infrastructure.patch",
            "Sw64-Integer-Operation-Support.patch",
            "Sw64-Memory-and-String-Implementation.patch",
            "Sw64-math-support.patch",
            "Sw64-float128-Implementation.patch",
            "Sw64-Add-get_rounding_mode.patch",
            "Sw64-Add-specific-math-difinitons.patch",
            "Sw64-Introduce-elf-initfini.h-and-ELF_INITFINI.patch",
            "Sw64-Type-definitions-for-nscd.patch",
            "Sw64-GCC-frame-description.patch",
            "Sw64-Update-libm-test-ulps.patch",
        ],
        "note": (
            "Full glibc port for Sunway/申威 ISA. Includes ABI, TLS, atomics, "
            "math, ELF relocation types, syscall interface, and float128. "
            "Sunway processors are used in Taihu Light (神威·太湖之光), the Chinese "
            "national supercomputer. TOS supporting Sw64 indicates Tencent targets "
            "Sunway-based deployment environments."
        ),
    },
    "LoongArch": {
        "architecture": "LoongArch (龙芯) — Loongson Chinese RISC ISA",
        "developer": "Loongson Technology Corporation",
        "patch_count": "~30 patches",
        "highlights": [
            "IFUNC implementations for: memcpy, memset, memcmp, memchr, memrchr, rawmemchr",
            "IFUNC for string ops: strchr, strcmp, strcpy, stpcpy, strncmp, strnlen, strrchr",
            "LSX/LASX (SIMD extension) support in IFUNC selectors",
            "TLS Descriptor support (TLSDESC for LoongArch)",
            "HWCAP support including LSPW from Linux 6.12",
            "LoongArch-specific thread pointer (thread_pointer.h)",
            "New LoongArch ELF relocation types 101-126",
            "dl_runtime_profiler with LSX/LASX optimization",
        ],
    },
    "Hygon_x86": {
        "architecture": "Hygon (兆芯/海光) — AMD Zen fork with Chinese JV license",
        "developer": "Hygon (THATIC joint venture)",
        "patches": [
            {
                "name": "x86-Add-new-architecture-type-for-Hygon-processors.patch",
                "description": "New vendor ID path for Hygon (CPUID family/model detection)",
            },
            {
                "name": "x86-Add-cache-information-support-for-Hygon-processors.patch",
                "description": "Cache topology detection for Hygon processor hierarchy",
            },
            {
                "name": "x86-Disable-AVX-Fast-Unaligned-Load-on-Hygon-1-2-3.patch",
                "description": "Hygon gen 1-3: disable AVX fast unaligned load (slower than scalar)",
            },
            {
                "name": "x86-Set-Prefer_No_AVX512-flag-for-hygon-platform.patch",
                "description": "Hygon: prefer EVEX paths over AVX512 (benchmarked as faster)",
            },
            {
                "name": "x86-Enable-Prefer_No_AVX512-for-Hygon-model-0x8.patch",
                "description": "Extend Prefer_No_AVX512 to Hygon model 0x8 (author: xiejiamei@hygon.cn)",
                "author": "xiejiamei@hygon.cn",
            },
            {
                "name": "x86-Enable-non-temporal-memset-for-Hygon-processors.patch",
                "description": "Enable non-temporal stores for memset on Hygon (like AMD Zen)",
            },
            {
                "name": "x86-Fix-for-cache-computation-on-Hygon-under-hypervisor.patch",
                "description": "Cache size fallback when running Hygon as VM guest",
            },
            {
                "name": "0002-x86-Lower-non-temporal-copy-threshold-for-Hygon.patch",
                "description": "Lower NT-store threshold for Hygon vs Intel default",
            },
        ],
    },
}

GLIBC_LOCALE_POLITICAL = {
    "patch": "5000-one-china-principle.patch",
    "file": "localedata/locales/zh_TW",
    "description": (
        "Modifies the zh_TW (Taiwan Chinese) locale to replace geopolitically "
        "sensitive language with Chinese government terminology."
    ),
    "changes": [
        {
            "before": "% Chinese language locale for Taiwan R.O.C.",
            "after": "% Chinese language locale for  Taiwan, Province of China.",
        },
        {
            "before": "% \tPPE of NTU, Taiwan, ROC",
            "after": "% \tPPE of NTU, Taiwan, Province of China.",
        },
        {
            "before": 'title      "Chinese locale for Taiwan R.O.C."',
            "after": 'title      "Chinese locale for Taiwan, Province of China."",',
        },
    ],
    "effect": (
        "Any system-level locale query returning zh_TW locale identification "
        "will return 'Province of China' instead of 'R.O.C.' or 'ROC'. "
        "Affects locale -a, locale -k LC_IDENTIFICATION, and any application "
        "that reads glibc locale identification strings."
    ),
    "note": "Patch number 5000 — TOS-local numbering. Not in upstream glibc.",
}

GLIBC_CN_CHARMAP = {
    "patch": "3003-add-GB18030-2022-charmap-support.patch",
    "standard": "GB18030-2022 (Chinese national standard character encoding, 2022 revision)",
    "description": (
        "Adds GB18030-2022 charmap to glibc. GB18030-2022 is the current Chinese national "
        "character encoding standard (mandatory for software sold in China). "
        "Adds ~8,000 additional CJK extension characters vs GB18030-2005."
    ),
}

OPENSSL_TOS_PATCHES = {
    "TLCP": {
        "patch": "openssl-3.0.12-support-tlcp.patch",
        "standard": "GM/T 0024-2014 (Transport Layer Cryptographic Protocol, Chinese TLS equivalent)",
        "author": "wynnfeng (Tencent/OpenCloudOS contributor)",
        "size": "Large multi-file patch",
        "description": (
            "Adds TLCP (Transport Layer Cryptographic Protocol) support to OpenSSL 3.0.12. "
            "TLCP is China's mandatory TLS-equivalent protocol using SM2/SM3/SM4 algorithms "
            "instead of RSA/SHA/AES. Required for compliance with Chinese financial and "
            "government security standards."
        ),
        "new_files": [
            "ssl/statem_tlcp/README.md — TLCP protocol overview",
            "ssl/statem_tlcp/tlcp_extensions.c — TLCP extension processing",
            "ssl/statem_tlcp/tlcp_extensions_clnt.c — Client-side TLCP extensions",
            "ssl/statem_tlcp/tlcp_extensions_cust.c — Custom TLCP extensions",
            "ssl/statem_tlcp/tlcp_extensions_srvr.c — Server-side TLCP extensions",
            "include/openssl/tlcp.h — TLCP public API (92 additions)",
            "providers/implementations/exchange/sm2dh_exch.c — SM2 DH key exchange (478 lines)",
            "providers/implementations/ciphers/cipher_sm4_gcm.c/h — SM4-GCM mode",
        ],
        "modified_files": [
            "ssl/ssl_lib.c — 293 additions: TLCP context initialization, cert loading",
            "ssl/ssl_rsa.c — 615 additions: TLCP cert/key management",
            "ssl/s3_lib.c — 149 additions: TLCP cipher suite definitions",
            "apps/s_client.c — 132 additions: TLCP client CLI flags",
            "apps/s_server.c — 149 additions: TLCP server CLI flags",
        ],
        "cipher_suites": [
            "ECC-SM4-SM3 — SM2 key exchange, SM4 encryption, SM3 MAC",
            "ECDHE-SM4-SM3 — SM2 ephemeral key exchange",
            "RSA-SM4-SM3 — RSA key exchange, SM4 encryption, SM3 MAC (transitional)",
            "RSA-SM4-SHA256 — RSA key exchange, SM4 encryption, SHA-256 MAC",
        ],
        "key_features": [
            "Dual-certificate model: signing cert + encryption cert (mandated by GM/T 0024)",
            "SM2 DH key exchange (sm2dh_exch.c)",
            "SM4-GCM AEAD mode",
            "New ALPN handling for TLCP negotiation",
        ],
    },
    "SM2_CMS": {
        "patch": "0050-support-sm2-CMS-signature.patch",
        "file": "crypto/cms/cms_sd.c",
        "author": "Huaxin Lu (luhuaxin1@huawei.com)",
        "description": (
            "cms_sd_asn1_ctrl() routes SM2 keys through the ECDSA/DSA signing path "
            "by adding 'EVP_PKEY_is_a(pkey, \"SM2\")' to the existing "
            "'DSA || EC' check. Enables CMS (Cryptographic Message Syntax) signed "
            "data with SM2 keys — required for Chinese email/document signing standards."
        ),
        "change": "One-line patch: add '|| EVP_PKEY_is_a(pkey, \"SM2\")' to DSA/EC branch",
    },
    "SM2_KEY_ENCODING": {
        "patch": "openssl-3.0-Fix-the-encoding-of-SM2-keys.patch",
        "description": "Fix ASN.1 encoding of SM2 public/private keys to match GB/T 35276.",
    },
    "FIPS": {
        "patch_range": "0040-0048",
        "patches": [
            "0040: Remove X9.31 padding from FIPS provider",
            "0041: Add explicit FIPS indicator for KBKDF key length",
            "0042: Add explicit FIPS indicator for HMAC key length",
            "0043: Set minimum PBKDF2 password length to 8 bytes",
            "0044: Disable SHAKE in RSA FIPS context",
            "0045: Add PSS salt length indicator",
            "0046: Clamp PSS salt length to MD length",
            "0047: RSA encapsulation in FIPS context",
        ],
        "note": "TOS ships with FIPS 140-3 compliance patches for OpenSSL — required for government deployments",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-6791",
        "package": "glibc-2.38",
        "title": "wordexp tilde expansion: stack overflow via user-controlled strndupa length",
        "detail": (
            "parse_tilde() in wordexp uses strndupa with user-controlled username length. "
            "Attacker-controlled wordexp input (~<long_username>) triggers alloca overflow. "
            "Reachable from any application using wordexp()."
        ),
        "fix": "strndupa → scratch_buffer",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2026-6368",
        "package": "glibc-2.38",
        "title": "wordexp WRDE_APPEND: use-after-free via dangling we_wordv after realloc",
        "detail": (
            "Error path restores saved wordexp_t struct with dangling we_wordv pointer "
            "(realloc moved the buffer). wordfree() on returned struct causes use-after-free."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2026-0861",
        "package": "glibc-2.38",
        "title": "memalign: alignment overflow check dropped — heap corruption on large alignment",
        "detail": (
            "_int_memalign() did not check alignment > PTRDIFF_MAX. "
            "Large alignment values overflow arithmetic in subsequent calculation, "
            "causing under-allocation and heap corruption."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "cve": "CVE-2026-0915",
        "package": "glibc-2.38",
        "title": "getnetbyaddr(0): uninitialized stack bytes in DNS query",
        "detail": (
            "net=0 in getnetbyaddr hits unhandled switch branch; qbuf remains uninitialized. "
            "DNS query name contains stack data from calling frame — information leak."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "cve": "CVE-2025-15281",
        "package": "glibc-2.38",
        "title": "wordexp WRDE_REUSE: free of wrong pointer (offset by we_wordc * sizeof ptr)",
        "detail": (
            "we_wordv updated at wrong offset after WRDE_REUSE free. "
            "wordfree() calls free with pointer = base + we_wordc * 8 → heap corruption."
        ),
    },
    {
        "id": "F6",
        "severity": "HIGH",
        "title": "glibc zh_TW locale: 'Taiwan R.O.C.' → 'Taiwan, Province of China.'",
        "detail": (
            "patch 5000-one-china-principle.patch modifies the zh_TW locale identification "
            "fields in localedata/locales/zh_TW. System-level locale queries return "
            "CCP-approved geopolitical terminology. Patch is TOS-local, not in upstream glibc."
        ),
        "class": "political-modification",
        "tos_specific": True,
    },
    {
        "id": "F7",
        "severity": "HIGH",
        "title": "OpenSSL: TLCP (GM/T 0024-2014) mandatory Chinese TLS protocol support",
        "detail": (
            "3,000+ line patch adding complete TLCP state machine to OpenSSL 3.0.12. "
            "New ssl/statem_tlcp/ directory with client/server/custom extension handlers. "
            "SM2 DH key exchange, SM4-GCM, dual-certificate model. "
            "TLCP is required for Chinese government/financial compliance — exposes "
            "SM2-based key exchange attack surface not present in standard OpenSSL."
        ),
        "class": "crypto-extension",
        "standard": "GM/T 0024-2014",
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "glibc: Sw64 (Sunway/申威) full CPU port — targets Chinese supercomputer hardware",
        "detail": (
            "24 patches implementing complete glibc ABI for Sunway 申威 ISA. "
            "Includes TLS, atomics, math, syscall interface, float128. "
            "Sunway processors power Taihu Light (神威·太湖之光). "
            "TOS targeting this architecture indicates Tencent cloud targets HPC/government workloads."
        ),
        "tos_specific": True,
    },
    {
        "id": "F9",
        "severity": "INFO",
        "title": "glibc: LoongArch IFUNC string ops with LSX/LASX SIMD — 30+ patches",
        "detail": (
            "Complete LoongArch glibc port with SIMD IFUNC for all major string operations. "
            "LSX (Loongson SIMD Extension, 128-bit) and LASX (256-bit) IFUNC selectors. "
            "TLS Descriptor support. ELF relocation types 101-126."
        ),
    },
    {
        "id": "F10",
        "severity": "INFO",
        "title": "glibc: 7 Hygon x86 tuning patches — model detection, cache, NT-memset, AVX512",
        "detail": (
            "Hygon model detection, cache topology, Prefer_No_AVX512 for models 0x7+0x8 "
            "(xiejiamei@hygon.cn), non-temporal memset enable, lower NT-copy threshold. "
            "Treats Hygon as distinct from AMD Zen despite shared microarchitecture."
        ),
    },
    {
        "id": "F11",
        "severity": "INFO",
        "title": "OpenSSL: SM2 CMS signature — routes SM2 keys through ECDSA signing path",
        "detail": (
            "Single-line patch in cms_sd_asn1_ctrl() enables SM2 keys in CMS SignedData. "
            "Enables Chinese document/email signing standard compliance. Author: Huawei."
        ),
    },
    {
        "id": "F12",
        "severity": "INFO",
        "title": "GB18030-2022 charmap: Chinese national standard encoding 2022 revision added",
        "detail": (
            "Adds GB18030-2022 (mandatory for software sold in China) with ~8,000 additional "
            "CJK extension characters vs GB18030-2005. Required for Chinese government compliance."
        ),
    },
]

if __name__ == '__main__':
    print(f"glibc-2.38 + OpenSSL-3.0.12 TOS 4.6 patch stack RE")
    print()
    print("CVE coverage:")
    for cve_id, cve in GLIBC_CVES.items():
        print(f"  {cve_id}: {cve['title'][:60]}")
    print()
    print("Architecture support:")
    for arch, info in GLIBC_ARCH_SUPPORT.items():
        print(f"  {arch}: {info.get('architecture', '')[:60]}")
    print()
    for f in FINDINGS:
        cve = f.get('cve', '')
        label = f"[{cve}]" if cve else "[INFO]"
        print(f"  [{f['severity']:6s}] {f['id']}: {label} {f['title'][:60]}")
