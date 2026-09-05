"""
TencentOS Server 4.6 shim RE Module
Source: shim-15.7-11.tl4.ap.3.src.rpm (latest of 3 TOS ap releases)
        /media/cowboy/research/tencentos/4.6/BaseOS-source/
Analysis date: 2026-09-04

PACKAGE: shim-15.7-11.tl4.ap.3
  Upstream: shim 15.7
  Tencent ap releases: ap.1, ap.2, ap.3 (3 iterative Tencent patches)
  Base patches: 12 backports from upstream + 2 Tencent-specific (SM2/ECDSA)
  Total patches: 14

CRITICAL CONTEXT:
  shim is the first-stage EFI bootloader in the Secure Boot chain. It runs
  in UEFI pre-boot with no ASLR, no stack canary, no RELRO, and predictable
  heap layout. Vulnerabilities in shim can break the entire Secure Boot
  trust chain from UEFI firmware to kernel. Exploitation requires ability to
  present a crafted EFI binary to the shim loader — attacker must have local
  physical access OR network access when HTTPBoot is enabled.

PATCH SET:
  backport-0001-CVE-2023-40546: mok: LogError() format string mismatch (INFO)
  backport-0002: overflow-checked arithmetic primitives (prerequisite)
  backport-0003-CVE-2023-40551: MZ header PE offset OOB read
  backport-0004: make read_header use checked arithmetic (prerequisite)
  backport-0005-CVE-2023-40550: SBAT section table OOB read
  backport-0006: noop/prerequisite
  backport-0007-CVE-2023-40549: Authenticode header OOB read
  backport-0008-CVE-2023-40548: SBAT section size integer overflow (32-bit)
  backport-0009: further CVE-2023-40546 class mitigations
  backport-0010-CVE-2023-40547: HTTPBoot Content-Length OOB write
  backport-0011: PE section alignment for mem attrs
  backport-0012-CVE-2026-45447: PKCS7_verify() BIO chain UAF (Tencent-authored)
  openssl-add-ecdsa-and-ec-support-for-shim: Enable EC/ECDSA
  shim-support-sm2-and-sm3-algorithm: SM2+SM3 Secure Boot support (Tencent)

KEY EXTERNAL REPORTERS:
  CVE-2023-40547: Bill Demirkapi (Microsoft Security Response Center)
  CVE-2023-40548/40549/40550/40551: gkirkpatrick@google.com (Google)
  CVE-2026-45447: Sinong Chen <costinchen@tencent.com> (Tencent) — self-reported

SECURITY FINDINGS: TOS46-SHM-F01 through TOS46-SHM-F08
  F01 CRITICAL CVE-2026-45447  PKCS7_verify() UAF: BIO_free_all() frees caller-owned indata
  F02 HIGH     CVE-2023-40547  HTTPBoot: Content-Length OOB write (alloc < receive buffer)
  F03 MEDIUM   CVE-2023-40548  SBAT size integer overflow on 32-bit (AllocatePool underalloc)
  F04 LOW      CVE-2023-40549  Authenticode header OOB read in verify_buffer_authenticode()
  F05 LOW      CVE-2023-40550  SBAT section table OOB read in verify_buffer_sbat()
  F06 LOW      CVE-2023-40551  MZ header PE offset OOB read in read_header()
  F07 INFO     CVE-2023-40546  LogError() format argument mismatch (CHAR16 *var vs *name)
  F08 CRITICAL SM2_SECBOOT    Tencent adds SM2+SM3 to Secure Boot trust chain (2430 lines)

ATTACK CHAINS:
  CHAIN-1: Local/network → crafted PKCS7 EFI binary → PKCS7_verify() UAF → Secure Boot bypass
  CHAIN-2: HTTPBoot enabled → crafted HTTP response → Content-Length OOB write → pre-boot RCE
  CHAIN-3: Tencent SM2 CA → sign arbitrary EFI binary → accepted by any TOS 4.6 shim
"""

# ──────────────────────────────────────────────────────────────────────────────
# PACKAGE INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

SHIM_PACKAGE = {
    "name": "shim",
    "version": "15.7",
    "release": "11.tl4.ap.3",
    "tencent_ap_releases": ["ap.1", "ap.2", "ap.3"],
    "total_patches": 14,
    "cve_patches": 7,
    "tencent_specific_patches": 2,
    "embedded_openssl": "1.0.x (Cryptlib shim fork)",
    "uefi_context": "pre-boot, no ASLR, no canary, no RELRO, predictable heap",
    "note": (
        "shim embeds its own OpenSSL fork (Cryptlib) — separate from system OpenSSL. "
        "Vulns in Cryptlib affect UEFI pre-boot with no mitigations. "
        "All 2023 CVEs (Rhytis set) patched in this release."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# F01 — CVE-2026-45447: PKCS7_verify() BIO chain UAF
# ──────────────────────────────────────────────────────────────────────────────

SHIM_CVE_2026_45447 = {
    "finding_id": "TOS46-SHM-F01",
    "cve": "CVE-2026-45447",
    "severity": "CRITICAL",
    "cvss_v3": 8.6,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "component": "Cryptlib/OpenSSL/crypto/pkcs7/pk7_smime.c PKCS7_verify()",
    "patch_file": "backport-0012-CVE-2026-45447-Fix-possible-use-after-free-in-OpenSS.patch",
    "tencent_authored": True,
    "author": "Sinong Chen <costinchen@tencent.com>",
    "reviewers": [
        "Eugene Syromiatnikov <esyr@openssl.org>",
        "Norbert Pocs <norbertp@openssl.org>",
    ],
    "title": (
        "PKCS7_verify() in shim's embedded Cryptlib: BIO_free_all(p7bio) frees the "
        "caller-supplied 'indata' BIO when tmpin==indata — use-after-free when caller "
        "subsequently accesses the freed BIO"
    ),
    "description": (
        "shim uses PKCS7_verify() from its embedded OpenSSL Cryptlib to verify "
        "Authenticode-style signatures on EFI binaries during Secure Boot. "
        "\n"
        "PKCS7_verify() accepts an 'indata' BIO (caller-allocated, caller-owned). "
        "Internally it may set: tmpin = indata "
        "Then on the cleanup/error path: "
        "  if (tmpin == indata) { "
        "      if (indata) BIO_pop(p7bio); "
        "  } "
        "  BIO_free_all(p7bio); "
        "\n"
        "BIO_free_all() frees the ENTIRE BIO chain starting at p7bio, including "
        "any BIO that p7bio is linked to. When p7bio was assembled from indata "
        "(tmpin == indata), BIO_pop() removes indata from the chain FIRST — but "
        "BIO_free_all() then walks the rest of the chain and may still reach and "
        "free the indata BIO depending on chain structure. "
        "\n"
        "More precisely: the BIO chain can be: p7bio → ... → indata "
        "BIO_pop(p7bio) removes the first element but the remaining chain "
        "still contains pointers to indata in complex chain topologies. "
        "BIO_free_all() then frees through the chain including indata. "
        "When the caller subsequently uses indata, it's a UAF. "
        "\n"
        "Fix: replace the single BIO_free_all(p7bio) with a loop that walks "
        "the chain one node at a time, stopping when it reaches indata: "
        "  while (p7bio != NULL && p7bio != indata) { "
        "      next = BIO_pop(p7bio); "
        "      BIO_free(p7bio); "
        "      p7bio = next; "
        "  } "
        "\n"
        "UEFI pre-boot context: no ASLR, no canary, no RELRO. Heap layout in shim's "
        "UEFI environment is deterministic across boots on the same hardware model. "
        "A crafted EFI binary that triggers the UAF can potentially write attacker- "
        "controlled data to a freed heap region, achieving arbitrary code execution "
        "in the UEFI pre-boot environment — full Secure Boot bypass. "
        "\n"
        "Trigger: local physical access (USB drive with crafted EFI binary) OR "
        "network access when PXE/HTTPBoot is used (attacker serves crafted binary). "
        "\n"
        "Tencent attribution: costinchen@tencent.com self-reported this CVE — "
        "Tencent's security team found a vulnerability in code that ONLY RUNS "
        "on systems using TOS (and derivatives). This may indicate internal audit "
        "of Secure Boot code, possibly prompted by the SM2 addition (F08)."
    ),
    "uefi_exploit_notes": {
        "no_aslr": "EFI image base is fixed (image-relative addresses are predictable)",
        "no_canary": "stack corruption not detected",
        "heap_layout": "UEFI AllocatePool() layout depends on boot order; deterministic on same hw",
        "crash_to_rce": "UAF in UEFI heap is higher-value than userspace UAF",
    },
    "references": [
        "CVE-2026-45447",
        "Cryptlib/OpenSSL/crypto/pkcs7/pk7_smime.c:260-443",
        "reporter/fix: Sinong Chen <costinchen@tencent.com>",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F02 — CVE-2023-40547: HTTPBoot Content-Length OOB write
# ──────────────────────────────────────────────────────────────────────────────

SHIM_CVE_2023_40547 = {
    "finding_id": "TOS46-SHM-F02",
    "cve": "CVE-2023-40547",
    "severity": "HIGH",
    "cvss_v3": 8.3,
    "component": "httpboot.c receive_http_response()",
    "patch_file": "backport-0010-CVE-2023-40547-avoid-incorrectly-trusting-HTTP-heade.patch",
    "reporter": "Bill Demirkapi, Microsoft Security Response Center",
    "title": (
        "HTTPBoot: shim allocates rx buffer using Content-Length header, but copies "
        "from rx_message.BodyLength — attacker-controlled Content-Length < BodyLength "
        "causes heap buffer overflow write"
    ),
    "description": (
        "When loading a binary via HTTPBoot (EFI HTTP Boot), shim calls "
        "receive_http_response() which: "
        "  1. Reads Content-Length from HTTP response header -> *buf_size "
        "  2. Allocates: *buffer = AllocatePool(*buf_size) "
        "  3. Copies: memcpy(*buffer, rx_message.Body, rx_message.BodyLength) "
        "\n"
        "Pre-patch: no check that rx_message.BodyLength <= *buf_size "
        "Attacker controls the HTTP response (MITM on the PXE/HTTP boot path). "
        "Content-Length: 16 (allocates 16-byte buffer) "
        "BodyLength: 16384 (copies 16384 bytes into 16-byte buffer) "
        "→ heap overflow of 16368 bytes in UEFI pre-boot environment "
        "\n"
        "Fix: add check: if (*buf_size < rx_message.BodyLength) → error "
        "\n"
        "Trigger condition: HTTPBoot must be enabled in UEFI firmware and "
        "shim must be loading a binary via HTTP. "
        "An attacker who can intercept or serve the HTTP response (DNS poisoning, "
        "MITM on the boot network, rogue DHCP server) can trigger this. "
        "\n"
        "Impact: heap overflow in UEFI pre-boot → code execution → Secure Boot bypass "
        "This is particularly dangerous in enterprise environments using PXE/HTTPBoot "
        "for server provisioning (TOS 4.6 is a server OS)."
    ),
    "trigger_condition": "HTTPBoot enabled; attacker can MITM boot network",
    "references": [
        "CVE-2023-40547",
        "httpboot.c:578-592",
        "reporter: Bill Demirkapi, Microsoft MSRC",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# F03 — CVE-2023-40548: SBAT section size integer overflow (32-bit)
# ──────────────────────────────────────────────────────────────────────────────

SHIM_CVE_2023_40548 = {
    "finding_id": "TOS46-SHM-F03",
    "cve": "CVE-2023-40548",
    "severity": "MEDIUM",
    "cvss_v3": 5.1,
    "component": "pe.c verify_sbat_section() + shim.c verify_buffer_sbat()",
    "patch_file": "backport-0008-CVE-2023-40548-Fix-integer-overflow-on-SBAT-section-.patch",
    "reporter": "gkirkpatrick@google.com",
    "title": (
        "verify_sbat_section(): SBATSize+1 integer overflow on 32-bit systems — "
        "SBATSize is size_t (32-bit: uint32), SBAT section header value is uint32_t; "
        "SBATSize=0xFFFFFFFF → SBATSize+1=0 → AllocatePool(0) → "
        "subsequent memcpy(sbat_data, SBATBase, SBATSize) writes 4GB into 0-byte alloc"
    ),
    "description": (
        "Pre-patch: sbat_size = SBATSize + 1; sbat_data = AllocatePool(sbat_size) "
        "\n"
        "On 32-bit EFI systems (still common in older server hardware/embedded): "
        "  SBATSize = 0xFFFFFFFF (max uint32) "
        "  SBATSize + 1 = 0x00000000 (overflow) "
        "  AllocatePool(0) → small/zero allocation "
        "  Subsequent code copies SBATSize bytes into sbat_data → massive OOB write "
        "\n"
        "Fix: checked_add(SBATSize, 1, &sbat_size) + verify section boundary. "
        "Also adds: section boundary check in verify_buffer_sbat(). "
        "\n"
        "Note: TOS 4.6 targets 64-bit servers; size_t is 64-bit so the overflow "
        "doesn't trigger. MEDIUM severity because it affects x86 32-bit EFI only."
    ),
    "affected_arches": ["i686 EFI", "ARM 32-bit EFI"],
    "references": ["CVE-2023-40548", "pe.c:895, shim.c:743"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F04 — CVE-2023-40549: Authenticode header OOB read
# ──────────────────────────────────────────────────────────────────────────────

SHIM_CVE_2023_40549 = {
    "finding_id": "TOS46-SHM-F04",
    "cve": "CVE-2023-40549",
    "severity": "LOW",
    "cvss_v3": 3.8,
    "component": "shim.c verify_buffer_authenticode()",
    "patch_file": "backport-0007-CVE-2023-40549-Authenticode-verify-that-the-signatur.patch",
    "reporter": "gkirkpatrick@google.com",
    "title": (
        "verify_buffer_authenticode(): signature header not bounds-checked against "
        "binary end — OOB read on page containing binary when header points out-of-bounds"
    ),
    "description": (
        "In verify_buffer_authenticode(), the code validates that actual signature "
        "DATA is within the binary, but does NOT validate that the WIN_CERTIFICATE "
        "header structure describing the signature is fully within bounds. "
        "A malformed binary with a WIN_CERTIFICATE header at the very end of the "
        "binary causes an OOB read of the struct fields past the binary end. "
        "\n"
        "Likely DoS only — OOB read in UEFI pre-boot. Possible information leak "
        "of adjacent UEFI memory if the page after the binary contains sensitive data. "
        "\n"
        "Fix: add bounds check that the signature header is within [data, data+datasize]."
    ),
    "references": ["CVE-2023-40549", "shim.c:627"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F05 — CVE-2023-40550: SBAT section table OOB read
# ──────────────────────────────────────────────────────────────────────────────

SHIM_CVE_2023_40550 = {
    "finding_id": "TOS46-SHM-F05",
    "cve": "CVE-2023-40550",
    "severity": "LOW",
    "cvss_v3": 3.8,
    "component": "shim.c verify_buffer_sbat()",
    "patch_file": "backport-0005-CVE-2023-40550-pe-Fix-an-out-of-bound-read-in-verify.patch",
    "reporter": "gkirkpatrick@google.com",
    "title": (
        "verify_buffer_sbat(): section table entry (.sbat name check) not bounds-checked "
        "— OOB read when section table entry is near the end of the binary"
    ),
    "description": (
        "verify_buffer_sbat() iterates section headers looking for '.sbat\\0\\0\\0'. "
        "The section table entries are bounds-checked for their DATA (SizeOfRawData + "
        "PointerToRawData checked), but NOT the section table ENTRIES themselves. "
        "A crafted section table with an entry that extends past the binary end "
        "causes OOB read when accessing the Name field for '.sbat\\0\\0\\0' comparison. "
        "\n"
        "Fix: add bounds check that each section table entry is within [data, data+datasize]."
    ),
    "references": ["CVE-2023-40550", "shim.c:709"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F06 — CVE-2023-40551: MZ header PE offset OOB read
# ──────────────────────────────────────────────────────────────────────────────

SHIM_CVE_2023_40551 = {
    "finding_id": "TOS46-SHM-F06",
    "cve": "CVE-2023-40551",
    "severity": "LOW",
    "cvss_v3": 3.8,
    "component": "pe.c read_header()",
    "patch_file": "backport-0003-CVE-2023-40551-pe-relocate-Fix-bounds-check-for-MZ-b.patch",
    "reporter": "gkirkpatrick@google.com",
    "title": (
        "read_header(): MZ (MS-DOS) header PE offset (e_lfanew) not bounds-checked "
        "— OOB read when e_lfanew points past binary end"
    ),
    "description": (
        "When an EFI binary has an MZ (MS-DOS) header at offset 0, shim reads the "
        "PE offset from e_lfanew (MZ header field at offset 0x3c). "
        "Pre-patch: e_lfanew used directly as pointer arithmetic without bounds check. "
        "Crafted binary with e_lfanew = 0xffffffff → OOB read past binary end. "
        "\n"
        "Fix: bounds check e_lfanew and all derived PE header pointers. "
        "Also reworked PE32/PE32+ detection logic to use checked arithmetic."
    ),
    "references": ["CVE-2023-40551", "pe.c:631"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F07 — CVE-2023-40546: LogError() format argument mismatch (INFO)
# ──────────────────────────────────────────────────────────────────────────────

SHIM_CVE_2023_40546 = {
    "finding_id": "TOS46-SHM-F07",
    "cve": "CVE-2023-40546",
    "severity": "INFO",
    "cvss_v3": 0.0,
    "component": "mok.c mirror_one_esl()",
    "patch_file": "backport-0001-CVE-2023-40546-mok-fix-LogError-invocation.patch",
    "title": (
        "mok.c mirror_one_esl(): LogError() called with 'var' (CHAR16 *buffer) "
        "instead of 'name' (CHAR16 *variable name) — wrong argument type; "
        "triggers fault on ARM where format mismatch causes dereference of wrong pointer"
    ),
    "description": (
        "Two LogError() calls in mirror_one_esl() pass 'var' (a buffer pointer that "
        "may be NULL on the error path) instead of 'name' (the variable name string). "
        "On ARM with strict type enforcement, this triggers a fault reading the "
        "wrong pointer. On x86-64, the argument is just a garbage pointer in the "
        "error message — no code execution risk. CVE assigned for ARM DoS scenario. "
        "\n"
        "Fix: replace 'var' with 'name' in both LogError() calls."
    ),
    "references": ["CVE-2023-40546", "mok.c:291-309"],
}

# ──────────────────────────────────────────────────────────────────────────────
# F08 — SM2+SM3 Tencent Secure Boot Extension
# ──────────────────────────────────────────────────────────────────────────────

SHIM_SM2_SECBOOT = {
    "finding_id": "TOS46-SHM-F08",
    "cve": None,
    "severity": "CRITICAL",
    "cvss_v3_strategic": 9.0,
    "component": "Cryptlib/OpenSSL/crypto/sm2/ + Cryptlib/Hash/CryptSm3.c + pe.c + shim.c",
    "patch_file": "shim-support-sm2-and-sm3-algorithm.patch",
    "author": "rpm-build (Tencent internal, 2023-10-10)",
    "companion": "openssl-add-ecdsa-and-ec-support-for-shim.patch",
    "lines_added": 2430,
    "files_modified": 48,
    "title": (
        "Tencent adds SM2+SM3 (Chinese national cryptographic standards) to shim's "
        "Secure Boot trust chain — any entity holding a trusted SM2 CA key can sign "
        "EFI binaries accepted by TOS 4.6 shim without Western PKI involvement"
    ),
    "description": (
        "SM2 is the Chinese national ECC standard (GB/T 32918); SM3 is the Chinese "
        "national hash standard (GB/T 32905), both mandated by OSCCA. "
        "\n"
        "This 2430-line patch (48 files) grafts SM2/SM3 support from OpenSSL 1.1.1 "
        "into shim's embedded OpenSSL 1.0.x Cryptlib fork. Key components: "
        "  - Cryptlib/Hash/CryptSm3.c: SM3 hash wrapper (Sm3Init/Update/Final/HashAll) "
        "  - Cryptlib/OpenSSL/crypto/sm2/: SM2 sign/verify/encrypt/decrypt + EVP pmethod "
        "  - Cryptlib/OpenSSL/crypto/sm3/: SM3 core implementation "
        "  - pe.c modifications: recognize SM2+SM3 (NID_SM2_with_SM3=964, "
        "    NID_sm3WithRSAEncryption=963) as valid Secure Boot signature algorithms "
        "  - MokManager.c: SM2 key enrollment via MOK management "
        "  - shim.c: SM2 certificate verification path added "
        "\n"
        "OID assignments (hardcoded): "
        "  NID_sm2 = 961 (1.2.156.10197.1.301) "
        "  NID_sm3 = 962 (1.2.156.10197.1.401) "
        "  NID_SM2_with_SM3 = 964 (1.2.156.10197.1.501) "
        "  NID_sm3WithRSAEncryption = 963 (1.2.156.10197.1.504) "
        "\n"
        "Build flag: ENABLE_SHIM_SM — SM2/SM3 enabled at build time in TOS shim. "
        "\n"
        "SM2_DEFAULT_USERID = '1234567812345678' (GM/T 0009-2012 default) "
        "This hardcoded user ID participates in the SM2 Z-value computation that "
        "prefixes all SM2 signatures. Any SM2 implementation using a different user ID "
        "will produce incompatible signatures — this is the interop default. "
        "\n"
        "STRATEGIC IMPLICATIONS: "
        "\n"
        "1. Expanded trust anchor: Any entity holding an SM2 CA key that is enrolled "
        "   in the MOK database (or in the TOS-distributed db) can sign EFI binaries "
        "   trusted by TOS 4.6 shim. This includes Tencent-controlled CAs used for "
        "   code signing, internal deployment, etc. The Chinese government-mandated "
        "   SM2 PKI infrastructure (OSCCA-approved CAs) is now a valid trust anchor "
        "   for the TOS 4.6 Secure Boot chain. "
        "\n"
        "2. Implementation quality: The SM2 code is ported from OpenSSL 1.1.1 into "
        "   OpenSSL 1.0.x. Several OpenSSL 1.0.x internal APIs are shimmed: "
        "   EVP_MD_CTX_new/free/reset, OPENSSL_zalloc, CRYPTO_clear_free, "
        "   EVP_PKEY_set_alias_type, EVP_MD_CTX_set_pkey_ctx, etc. "
        "   This is a non-trivial port; correctness depends on whether the API "
        "   semantics are faithfully reproduced. EVP_MD_CTX_reset() replaces "
        "   EVP_MD_CTX_cleanup() calls — the clear+free semantics differ. "
        "\n"
        "3. BN_copy() pre-null check removed: The patch removes a null-safety check "
        "   in bn_lib.c BN_copy(): 'if (!a || !b || !a->d || !b->d) return NULL' "
        "   This was needed to make EC operations work (EC internally calls BN_copy "
        "   on initialized structs). The removed check means NULL input to BN_copy() "
        "   now proceeds to a->top = b->top with NULL a->d → NULL deref in EC code "
        "   if called with uninitialized BIGNUM. "
        "\n"
        "4. CVE surface expansion: Adding ~2430 lines of crypto code to shim "
        "   (a ~70KB binary with no runtime mitigations) significantly expands the "
        "   attack surface for Secure Boot bypass. The SM2 implementation in OpenSSL "
        "   1.1.1 itself has had CVEs (CVE-2021-3711 SM2 decrypt, CVE-2021-3712 "
        "   ASN.1 string read) that may or may not be backported into this port."
    ),
    "bn_copy_regression": (
        "The SM2 patch removes the null-pointer guard in BN_copy(): "
        "  - Removed: if (!a || !b || !a->d || !b->d) return (NULL); "
        "  - Rationale: EC operations call BN_copy on structs initialized by bn_wexpand() "
        "    which sets d to a valid pointer, making the check redundant. "
        "  - Risk: any code path that calls BN_copy() with an uninitialized BIGNUM "
        "    (a->d == NULL) will crash instead of returning NULL and propagating error. "
        "  - In UEFI pre-boot, a crash is a Secure Boot bypass if the crash path "
        "    falls through to a boot-success state (unlikely but not impossible)."
    ),
    "sm2_known_cves": {
        "CVE-2021-3711": "SM2 decryption buffer overflow in OpenSSL 1.1.1k and earlier",
        "CVE-2021-3712": "ASN.1 string read overflow in OpenSSL 1.1.1l and earlier",
        "note": (
            "These CVEs affect the SM2 implementation from which this port is derived. "
            "Whether the TOS shim port inherited the vulnerable code paths requires "
            "deeper analysis of sm2_decrypt() and ASN.1 string handling."
        ),
    },
    "references": [
        "shim-support-sm2-and-sm3-algorithm.patch (2430 lines)",
        "GB/T 32918 (SM2 standard)",
        "GB/T 32905 (SM3 standard)",
        "GM/T 0009-2012 (SM2 user ID default)",
        "CVE-2021-3711 (SM2 decrypt buffer overflow, OpenSSL origin)",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = {
    "CHAIN-1": {
        "title": "Crafted PKCS7 EFI binary → UAF in shim → Secure Boot bypass",
        "severity": "CRITICAL",
        "steps": [
            "1. Craft EFI binary with malformed PKCS7 signature structure",
            "   that triggers the BIO chain UAF in PKCS7_verify()",
            "2. Arrange the BIO chain so BIO_free_all() walks into indata",
            "3. In UEFI pre-boot (no ASLR): predict freed heap region address",
            "4. Groom heap so freed indata slot overlaps with a shim control structure",
            "5. UAF write → overwrite function pointer or certificate acceptance flag",
            "6. shim proceeds to boot the crafted binary without valid signature",
            "7. Secure Boot chain is broken; attacker-controlled code runs pre-OS",
        ],
        "trigger": "Local USB or network (PXE/HTTPBoot), pre-auth",
        "chain_links": ["F01"],
    },
    "CHAIN-2": {
        "title": "HTTPBoot MITM → Content-Length manipulation → heap overflow → pre-boot RCE",
        "severity": "HIGH",
        "steps": [
            "1. Identify target server using PXE/HTTPBoot (standard TOS datacenter config)",
            "2. Position MITM on the boot network (rogue DHCP, DNS poisoning, ARP spoof)",
            "3. Intercept HTTP response carrying the EFI binary",
            "4. Replace Content-Length header with small value (e.g., 64)",
            "5. Send full-size EFI binary payload in HTTP body (e.g., 128KB)",
            "6. shim allocates 64-byte buffer, copies 128KB into it",
            "7. UEFI heap overflow with ~128KB of attacker data",
            "8. Overwrite adjacent heap objects → control flow hijack → Secure Boot bypass",
        ],
        "trigger": "Network access to boot network; HTTPBoot enabled",
        "chain_links": ["F02"],
    },
    "CHAIN-3": {
        "title": "SM2 CA key → sign arbitrary EFI binary → trusted by TOS 4.6 shim",
        "severity": "CRITICAL",
        "steps": [
            "1. Entity with SM2 CA key enrolled in TOS shim/MOK generates CSR",
            "2. Signs any EFI binary (including a custom kernel or bootloader) with SM2+SM3",
            "3. Presents signed binary to TOS 4.6 host at boot",
            "4. shim's SM2 verification path accepts the signature",
            "5. Unsigned (from the Western PKI perspective) binary boots successfully",
            "6. Secure Boot is technically intact but now accepts SM2 signatures",
            "   that Western auditors cannot verify or audit",
        ],
        "trigger": "Access to SM2 CA key trusted by the target system",
        "chain_links": ["F08"],
        "note": (
            "This is a trust architecture finding, not a code-execution bug. "
            "The 'attacker' is any entity holding a trusted SM2 CA key. "
            "On TOS 4.6 systems deployed in Chinese enterprise environments, "
            "OSCCA-approved CAs may be enrolled in the MOK database, "
            "making those CAs trusted signing authorities for the Secure Boot chain."
        ),
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-SHM-F01": SHIM_CVE_2026_45447,
    "TOS46-SHM-F02": SHIM_CVE_2023_40547,
    "TOS46-SHM-F03": SHIM_CVE_2023_40548,
    "TOS46-SHM-F04": SHIM_CVE_2023_40549,
    "TOS46-SHM-F05": SHIM_CVE_2023_40550,
    "TOS46-SHM-F06": SHIM_CVE_2023_40551,
    "TOS46-SHM-F07": SHIM_CVE_2023_40546,
    "TOS46-SHM-F08": SHIM_SM2_SECBOOT,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "package": "shim-15.7-11.tl4.ap.3",
        "tencent_ap_releases": 3,
        "total_patches": 14,
        "cve_patches": 7,
        "tencent_specific": 2,
        "attack_chains": list(ATTACK_CHAINS.keys()),
        "findings": [
            {
                "id": k,
                "severity": v.get("severity", "?"),
                "cvss": v.get("cvss_v3") or v.get("cvss_v3_strategic"),
                "cve": v.get("cve"),
                "tencent_authored": v.get("tencent_authored", False),
            }
            for k, v in FINDINGS.items()
        ],
    }, indent=2))
