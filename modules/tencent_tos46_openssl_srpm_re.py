"""
TencentOS Server 4.6 OpenSSL SRPM Full Patch Audit
SRPM: openssl-3.0.12-27.tl4.src.rpm
Patch count: 96 patches
Analysis date: 2026-09-04

Base version: OpenSSL 3.0.12 (RHEL 9 branched from 3.0.x LTS)
TOS version: 3.0.12-27.tl4

TENCENT-ORIGINATED CVE:
  CVE-2026-34182 — found by wynnfeng@tencent.com
  CMS AuthEnvelopedData non-AEAD cipher bypass + 1-byte tag forge

SM/TLCP INTEGRATION:
  openssl-3.0.12-support-tlcp.patch — TLCP protocol (SM2/SM3/SM4 based TLS)
  openssl-3.0.12-support-rfc8998.patch — RFC 8998 SM2 cipher suites for TLS 1.3
  openssl-3.0-Fix-the-encoding-of-SM2-keys.patch — SM2 key encoding fix
  0050-support-sm2-CMS-signature.patch — SM2 CMS signatures

FIPS:
  0008–0047 FIPS patches: FIPS_mode compat, kernel FIPS flag, HMAC embed,
  EC curve restrictions, RSA limits, FIPS key checks
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F01: CVE-2026-34182 (Tencent-originated)
# CMS AuthEnvelopedData non-AEAD cipher + 1-byte tag forge
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_CVE_2026_34182 = {
    "finding_id": "TOS46-SSL-F01",
    "cve": "CVE-2026-34182",
    "severity": "HIGH",
    "cvss_v3": 8.2,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "title": (
        "CVE-2026-34182: CMS AuthEnvelopedData accepts non-AEAD ciphers (auth bypass) "
        "and allows AEAD tag as small as 1 byte (256-guess forge); "
        "Tencent-originated (wynnfeng@tencent.com); patched in TOS 4.6"
    ),
    "description": (
        "CMS (Cryptographic Message Syntax) AuthEnvelopedData (RFC 5083) is supposed "
        "to encrypt AND authenticate a message using an AEAD cipher. Two bugs: "
        "\n"
        "BUG 1: Non-AEAD cipher accepted in AuthEnvelopedData. "
        "  ossl_cms_EncryptedContent_init_bio() did not reject non-AEAD ciphers. "
        "  If a forged CMS message specified AES-CBC (non-AEAD) as the cipher in "
        "  an AuthEnvelopedData structure, OpenSSL would decrypt without any MAC "
        "  check — authentication completely bypassed. Violates RFC 5083. "
        "  Fix: added 'else if (ec->taglen > 0)' branch that returns error for "
        "  non-AEAD ciphers. "
        "\n"
        "BUG 2: AEAD tag length not validated. "
        "  ec->taglen could be as small as 1 byte. With a 1-byte AES-GCM tag: "
        "  256 forged ciphertext attempts to find a valid MAC match. "
        "  RFC 5084 recommends ≥12 bytes for AES-GCM. "
        "  Fix: enforce ec->taglen >= 4 (lower bound; prevents brute-force with "
        "  sub-second feasibility at 4 bytes but significantly raises cost). "
        "\n"
        "Attack chain: "
        "  1. Attacker sends forged AuthEnvelopedData CMS message "
        "     with non-AEAD cipher → authentication silently skipped "
        "  2. OR: sends AuthEnvelopedData with AES-GCM and 1-byte tag "
        "     → ~256 requests to forge a valid authenticated message "
        "  3. Target application decrypts and accepts attacker-controlled content "
        "\n"
        "Attribution: Found by wynnfeng@tencent.com (Tencent security researcher). "
        "This is a Tencent-originated upstream OpenSSL CVE."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssl-3.0-CVE-2026-34182.patch",
    "tencent_originated": True,
    "reporter": "wynnfeng@tencent.com (Tencent)",
    "references": [
        "RFC 5083: CMS Authenticated-Enveloped-Data",
        "RFC 5084: AES-CCM and AES-GCM in CMS",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F02: CVE-2025-69418 — OCB AES-NI pointer advance bug
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_CVE_2025_69418 = {
    "finding_id": "TOS46-SSL-F02",
    "cve": "CVE-2025-69418",
    "severity": "HIGH",
    "cvss_v3": 8.2,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "title": (
        "CVE-2025-69418: AES-OCB fast path (AES-NI/HW) fails to advance in/out "
        "pointers after full-block processing; trailing bytes unencrypted/unauthenticated; "
        "CPU-dependent (only triggers with AES-NI hardware acceleration)"
    ),
    "description": (
        "ocb128.c CRYPTO_ocb128_encrypt() / _decrypt(): when the hardware-accelerated "
        "stream path (AES-NI or ARMv8 CE ctx->stream != NULL) processes full blocks, "
        "it calls ctx->stream(in, out, num_blocks, ...) but does NOT advance "
        "the in/out pointers afterward. "
        "\n"
        "Pre-patch code: "
        "  ctx->stream(in, out, num_blocks, ...)  /* hw accel */ "
        "  /* in and out still point to start of buffer */ "
        "  /* tail handling then processes in[0..tail-1] instead of */ "
        "  /* in[num_blocks*16..num_blocks*16+tail-1] */ "
        "\n"
        "Fix: adds 'processed_bytes = num_blocks * 16; in += processed_bytes; "
        "out += processed_bytes;' after ctx->stream() call. "
        "\n"
        "Effect: "
        "  Encryption: tail bytes of plaintext are NOT encrypted (left as-is). "
        "    The checksum (authentication tag) is computed over the beginning of "
        "    the buffer again — not the actual tail. Trailing plaintext leaks. "
        "  Decryption: the authentication tag is computed over wrong bytes — "
        "    forged trailing bytes pass authentication silently. "
        "\n"
        "Attack chain (decryption): "
        "  1. Attacker intercepts AES-OCB-encrypted message "
        "  2. Modifies trailing bytes (after num_blocks*16 boundary) "
        "  3. Receiver decrypts and validates — auth check passes despite tampered bytes "
        "  4. Application processes attacker-modified trailing content as authentic "
        "\n"
        "Scope: only affects AES-OCB. AES-GCM, AES-CCM, ChaCha20-Poly1305 unaffected. "
        "Only triggers when AES-NI hardware acceleration is active (virtually all "
        "modern x86_64 CPUs). Systems without AES-NI take the software path — unaffected."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssl-3.0-CVE-2025-69418.patch",
    "affected_cipher": "AES-OCB with AES-NI/ARMv8 CE hardware acceleration",
    "unaffected": ["AES-GCM", "AES-CCM", "ChaCha20-Poly1305", "software AES-OCB"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F03: CVE-2025-68160 — BIO_f_linebuffer heap overflow
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_CVE_2025_68160 = {
    "finding_id": "TOS46-SSL-F03",
    "cve": "CVE-2025-68160",
    "severity": "HIGH",
    "cvss_v3": 7.4,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
    "title": (
        "CVE-2025-68160: BIO_f_linebuffer heap buffer overflow when next BIO performs "
        "short writes; remaining data unconditionally copied to fixed-size obuf "
        "without bounds check"
    ),
    "description": (
        "bf_lbuf.c linebuffer_write(): when processing data that has no newline "
        "at the end (and therefore needs to be buffered), the code copied remaining "
        "bytes unconditionally to ctx->obuf: "
        "\n"
        "  memcpy(&(ctx->obuf[ctx->obuf_len]), in, inl);  /* no bounds check! */ "
        "  ctx->obuf_len += inl; "
        "\n"
        "If the next BIO performs short writes (returns less than asked), the "
        "unwritten remainder accumulates in obuf. obuf is fixed-size. Without a "
        "bounds check, inl bytes are copied to ctx->obuf even if "
        "(ctx->obuf_len + inl) > ctx->obuf_size → heap overflow. "
        "\n"
        "Fix: replaced unconditional memcpy with a loop that checks available space "
        "and flushes to next BIO when needed. "
        "\n"
        "Impact: heap overflow in BIO chain — potentially controllable write "
        "primitive for an attacker who can cause short writes in a chained BIO "
        "(e.g., network throttling, SSL write buffering under load)."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssl-3.0-CVE-2025-68160.patch",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F04: CVE-2025-15467 — CMS AEAD IV buffer overflow
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_CVE_2025_15467 = {
    "finding_id": "TOS46-SSL-F04",
    "cve": "CVE-2025-15467",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "title": (
        "CVE-2025-15467: CMS AEAD IV length not validated before copy to fixed-size "
        "stack buffer; ASN.1 message with IV longer than EVP_MAX_IV_LENGTH causes "
        "stack buffer overflow"
    ),
    "description": (
        "evp_lib.c evp_cipher_get_asn1_aead_params(): reads AEAD IV from ASN.1 type "
        "in two steps (original code): "
        "\n"
        "  i = ossl_asn1_type_get_octetstring_int(type, &tl, NULL, EVP_MAX_IV_LENGTH); "
        "  /* i = actual length; no overflow check */ "
        "  ossl_asn1_type_get_octetstring_int(type, &tl, iv, i);  /* copy */ "
        "\n"
        "Problem: EVP_MAX_IV_LENGTH is 16. A crafted ASN.1 CMS message can specify "
        "an IV longer than 16 bytes. The first call's second arg is EVP_MAX_IV_LENGTH "
        "(limits extraction), but the second call uses 'i' which could be the full "
        "advertised length. If `i > EVP_MAX_IV_LENGTH`: stack buffer overflow in `iv`. "
        "\n"
        "Fix: single call with combined get+store; added 'i > EVP_MAX_IV_LENGTH' check "
        "→ return -1 for oversized IV. "
        "\n"
        "Attack: send a CMS message with an AEAD IV field longer than 16 bytes → "
        "stack overflow in the CMS decryption path → potential RCE or DoS."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssl-3.0-CVE-2025-15467.patch",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F05: CVE-2026-45447 — PKCS7_verify use-after-free
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_CVE_2026_45447 = {
    "finding_id": "TOS46-SSL-F05",
    "cve": "CVE-2026-45447",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "title": (
        "CVE-2026-45447: use-after-free in PKCS7_verify() error path; "
        "BIO_pop(p7bio) then BIO_free_all(p7bio) — double-free / UAF in BIO chain"
    ),
    "description": (
        "pk7_smime.c PKCS7_verify() error path: "
        "\n"
        "  err: "
        "  if (tmpin == indata) { "
        "      if (indata) "
        "          BIO_pop(p7bio);   /* pops p7bio from chain */ "
        "  } "
        "  BIO_free_all(p7bio);   /* frees all nodes in chain including already-popped */ "
        "\n"
        "The BIO_pop() call unlinks p7bio from the chain. BIO_free_all() then traverses "
        "p7bio's next chain — but if p7bio's next is `indata` (which was not supposed "
        "to be freed), this double-frees `indata` or traverses past it into freed memory. "
        "\n"
        "In the tmpin != indata path, the logic is different and p7bio includes indata "
        "in its chain — BIO_free_all frees it correctly. But the asymmetry creates the UAF. "
        "\n"
        "Fix: manual chain teardown stopping at indata: "
        "  while (p7bio != NULL && p7bio != indata) { "
        "      next = BIO_pop(p7bio); "
        "      BIO_free(p7bio); "
        "      p7bio = next; "
        "  } "
        "\n"
        "Attack: crafted S/MIME message processed by PKCS7_verify() → UAF → "
        "heap corruption → potential RCE in mail clients, TLS session verification, "
        "or any application that calls PKCS7_verify() on untrusted input."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssl-3.0-CVE-2026-45447.patch",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F06: CVE-2026-22795+22796 — ASN.1 type confusion
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_CVE_2026_22795_22796 = {
    "finding_id": "TOS46-SSL-F06",
    "cves": ["CVE-2026-22795", "CVE-2026-22796"],
    "severity": "MEDIUM",
    "cvss_v3": 6.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "title": (
        "CVE-2026-22795/22796: ASN.1 type tag not validated before union access "
        "in PKCS12/PKCS7/s_client; type confusion in ASN1_TYPE value field "
        "can cause invalid pointer dereference; from LibreSSL audit"
    ),
    "description": (
        "Multiple sites in PKCS12 and PKCS7 parsing access ASN1_TYPE union fields "
        "without first verifying the type tag: "
        "\n"
        "p12_kiss.c: "
        "  attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName); "
        "  fname = attrib->value.bmpstring;  /* TYPE NOT CHECKED */ "
        "  /* If type != V_ASN1_BMPSTRING, bmpstring is garbage */ "
        "\n"
        "pk7_doit.c: "
        "  astype->value.octet_string  /* accessed without checking V_ASN1_OCTET_STRING */ "
        "\n"
        "s_client.c: "
        "  atyp = ASN1_generate_nconf(genstr, cnf); "
        "  /* atyp->type not checked to be V_ASN1_SEQUENCE */ "
        "\n"
        "A crafted PKCS12 file or PKCS7 message with wrong type tags in attribute "
        "fields causes the application to read union fields as the wrong type. "
        "The ASN1_TYPE union shares memory — reading bmpstring when type is actually "
        "integer reads the integer's value as a pointer to a BIGNUM, causing "
        "NULL dereference or memory corruption. "
        "\n"
        "Fix: added explicit type checks before each union field access. "
        "\n"
        "Found by auditing LibreSSL's fix (openbsd/src commit aa1f637d). "
        "Additional instances found by scanning for the same pattern."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssl-3.0-CVE-2026-22795-CVE-2026-22796.patch",
    "source": "LibreSSL audit (openbsd/src commit aa1f637d)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F07: CVE-2024-5535 — SSL_select_next_proto buffer overread
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_CVE_2024_5535 = {
    "finding_id": "TOS46-SSL-F07",
    "cve": "CVE-2024-5535",
    "severity": "HIGH",
    "cvss_v3": 9.1,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "title": (
        "CVE-2024-5535: SSL_select_next_proto NULL/empty client protocol list "
        "not validated; out-of-bounds read when called from NPN callback with "
        "unchecked application-supplied client list"
    ),
    "description": (
        "SSL_select_next_proto() receives a client protocol list from either "
        "ALPN callback (pre-validated by OpenSSL) or NPN callback (application-provided, "
        "NOT pre-validated). "
        "\n"
        "Pre-patch: the function assumed the client list was always valid. "
        "A NULL or empty list could cause out-of-bounds reads when the function "
        "iterated over the protocol list expecting length-prefixed entries. "
        "\n"
        "Fix: uses PACKET abstraction (PACKET_buf_init + PACKET_get_length_prefixed_1) "
        "which safely validates list format at each step. Returns OPENSSL_NPN_NO_OVERLAP "
        "on malformed input instead of reading past bounds. "
        "\n"
        "Impact: any application using NPN (Next Protocol Negotiation — deprecated "
        "but still present) with application-controlled client protocol lists. "
        "ALPN users are unaffected (the callback already validated the list). "
        "\n"
        "CVSS 9.1 is Confidentiality:H + Availability:H because OOB reads can "
        "disclose adjacent heap memory (C:H) and cause crashes (A:H)."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssl-3.0-CVE-2024-5535.patch",
    "affected_protocol": "NPN (Next Protocol Negotiation) — deprecated in TLS 1.3",
    "unaffected": "ALPN callback path (pre-validated by OpenSSL before callback)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F08: CVE-2024-0727 — PKCS12 NULL pointer dereference
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_CVE_2024_0727 = {
    "finding_id": "TOS46-SSL-F08",
    "cve": "CVE-2024-0727",
    "severity": "MEDIUM",
    "cvss_v3": 5.5,
    "cvss_vector": "AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
    "title": (
        "CVE-2024-0727: PKCS12 ContentInfo data field can be NULL even with valid type; "
        "NULL dereference in PKCS12_unpack_p7data, PKCS12_unpack_p7encdata, "
        "PKCS12_unpack_authsafes; crafted .p12 file causes crash"
    ),
    "description": (
        "PKCS12 structures contain PKCS7 ContentInfo fields. These fields are optional "
        "and the data pointer can be NULL even when the 'type' field is set to a valid "
        "value (e.g., NID_pkcs7_data). "
        "\n"
        "OpenSSL did not check for NULL data before dereferencing: "
        "  PKCS12_unpack_p7data(): ASN1_item_unpack(p7->d.data, ...) — d.data could be NULL "
        "  PKCS12_unpack_p7encdata(): p7->d.encrypted dereference — could be NULL "
        "  PKCS12_unpack_authsafes(): p12->authsafes->d.data — could be NULL "
        "\n"
        "Fix: explicit NULL checks with ERR_raise(PKCS12_R_DECODE_ERROR) before each "
        "dereference. "
        "\n"
        "Attack: maliciously crafted .p12 file → application opens it → NULL deref crash. "
        "Typical impact: DoS of applications that process certificate bundles "
        "(web servers loading cert chains, mail clients, TLS tools)."
    ),
    "patched_in_tos46": True,
    "patch_file": "openssl-3.0-CVE-2024-0727.patch",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F09: RSA PKCS#1 v1.5 implicit rejection (Marvin attack)
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_RSA_IMPLICIT_REJECTION = {
    "finding_id": "TOS46-SSL-F09",
    "severity": "HIGH",
    "related_cves": ["CVE-2020-25659", "CVE-2020-25657", "CVE-2023-0215"],
    "title": (
        "RSA PKCS#1 v1.5 implicit rejection mitigates Bleichenbacher/Marvin attacks: "
        "on padding failure, returns deterministic random message instead of error; "
        "caller cannot distinguish decryption failure from success via timing or value"
    ),
    "description": (
        "RSA-PKCS15-implicit-rejection.patch (Hubert Kario, Red Hat): "
        "\n"
        "PKCS#1 v1.5 RSA decryption traditionally returns an error code on padding "
        "failure. Attackers can use this as a Bleichenbacher oracle — sending "
        "many crafted ciphertexts and observing success/failure to progressively "
        "decrypt the original message. "
        "\n"
        "Implicit rejection: on padding failure, instead of returning an error, "
        "the function returns a deterministic random message generated from: "
        "  - The RSA private exponent (static secret) "
        "  - The ciphertext (so each request returns a different 'fake plaintext') "
        "\n"
        "The returned 'plaintext' is indistinguishable from a legitimate decryption "
        "to the attacker — no oracle signal. The message is generated using HMAC "
        "with the private key as HMAC key over the ciphertext. "
        "\n"
        "This approach is shared with Mozilla NSS, preventing cross-library oracle "
        "attacks where one library is used as a Bleichenbacher oracle against another. "
        "\n"
        "Impact: any application using RSA PKCS#1 v1.5 decryption (TLS RSA key exchange, "
        "S/MIME, PKCS7) is now protected against Bleichenbacher timing attacks "
        "without requiring application-level changes."
    ),
    "patch_file": "RSA-PKCS15-implicit-rejection.patch",
    "implementation": "HMAC(private_exponent, ciphertext) → deterministic 'fake plaintext'",
    "cross_library_compat": "Compatible with Mozilla NSS (same algorithm)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS46-SSL-F10: TLCP and RFC 8998 SM cipher suite integration
# ──────────────────────────────────────────────────────────────────────────────

OPENSSL_TLCP_SM = {
    "finding_id": "TOS46-SSL-F10",
    "severity": "INFO",
    "title": (
        "TOS 4.6 OpenSSL adds TLCP (Transport Layer Cryptography Protocol) and "
        "RFC 8998 SM2 cipher suites for TLS 1.3; Chinese national TLS equivalent "
        "using SM2/SM3/SM4; non-standard; not in upstream OpenSSL"
    ),
    "description": (
        "openssl-3.0.12-support-tlcp.patch: "
        "  TLCP is China's national TLS-equivalent protocol (GB/T 38636-2020). "
        "  Uses SM2 (key exchange/signatures) + SM3 (MAC/PRF) + SM4 (bulk cipher). "
        "  TLCP is NOT TLS — different handshake, different cipher negotiation. "
        "  Enabled by a new 'TLCP' protocol flag in OpenSSL 3.0.12-tl4. "
        "\n"
        "openssl-3.0.12-support-rfc8998.patch: "
        "  RFC 8998 defines TLS 1.3 cipher suites using SM algorithms: "
        "  - TLS_SM4_GCM_SM3: SM4 in GCM mode with SM3 as PRF "
        "  - TLS_SM4_CCM_SM3: SM4 in CCM mode with SM3 as PRF "
        "  These are standard TLS 1.3 extension cipher suites, unlike TLCP. "
        "\n"
        "openssl-3.0-Fix-the-encoding-of-SM2-keys.patch: "
        "  Corrects ASN.1 encoding of SM2 public keys for interoperability. "
        "\n"
        "0050-support-sm2-CMS-signature.patch: "
        "  SM2 signatures in CMS (Cryptographic Message Syntax) structures. "
        "  Enables SM2-signed S/MIME messages. "
        "\n"
        "Security assessment: "
        "  - TLCP is a Tencent/China-ecosystem TLS alternative. Not FIPS-approved. "
        "  - RFC 8998 cipher suites extend standard TLS 1.3 — negotiated only if "
        "    both sides advertise them "
        "  - SM4-GCM is believed cryptographically sound but less audited than AES-GCM "
        "  - TLCP protocol has had fewer public security reviews than TLS 1.3 "
        "  - If TLCP is enabled, it creates an additional protocol surface that "
        "    may have less mature tooling for detection and analysis"
    ),
    "tlcp_standard": "GB/T 38636-2020",
    "rfc": "RFC 8998 (SM Cipher Suites for TLS 1.3)",
    "cross_reference": "tencent_tos46_libssl_tlcp_binary_re.py",
}

# ──────────────────────────────────────────────────────────────────────────────
# ALL CVE PATCHES CATALOGUED
# ──────────────────────────────────────────────────────────────────────────────

CVE_PATCH_CATALOG = {
    "2026": [
        {"cve": "CVE-2026-22795", "patch": "openssl-3.0-CVE-2026-22795-CVE-2026-22796.patch", "finding": "TOS46-SSL-F06"},
        {"cve": "CVE-2026-22796", "patch": "openssl-3.0-CVE-2026-22795-CVE-2026-22796.patch", "finding": "TOS46-SSL-F06"},
        {"cve": "CVE-2026-34182", "patch": "openssl-3.0-CVE-2026-34182.patch", "finding": "TOS46-SSL-F01", "note": "Tencent-originated"},
        {"cve": "CVE-2026-45447", "patch": "openssl-3.0-CVE-2026-45447.patch", "finding": "TOS46-SSL-F05"},
    ],
    "2025": [
        {"cve": "CVE-2025-15467", "patch": "openssl-3.0-CVE-2025-15467.patch", "finding": "TOS46-SSL-F04"},
        {"cve": "CVE-2025-68160", "patch": "openssl-3.0-CVE-2025-68160.patch", "finding": "TOS46-SSL-F03"},
        {"cve": "CVE-2025-69418", "patch": "openssl-3.0-CVE-2025-69418.patch", "finding": "TOS46-SSL-F02"},
        {"cve": "CVE-2025-69419", "patch": "openssl-3.0-CVE-2025-69419.patch"},
        {"cve": "CVE-2025-69420", "patch": "openssl-3.0-CVE-2025-69420.patch"},
        {"cve": "CVE-2025-69421", "patch": "openssl-3.0-CVE-2025-69421.patch"},
    ],
    "2024": [
        {"cve": "CVE-2024-0727", "patch": "openssl-3.0-CVE-2024-0727.patch", "finding": "TOS46-SSL-F08"},
        {"cve": "CVE-2024-2511", "patch": "openssl-3.0-CVE-2024-2511.patch"},
        {"cve": "CVE-2024-4603", "patch": "openssl-3.0-CVE-2024-4603.patch"},
        {"cve": "CVE-2024-4741", "patch": "openssl-3.0-CVE-2024-4741.patch"},
        {"cve": "CVE-2024-5535", "patch": "openssl-3.0-CVE-2024-5535.patch", "finding": "TOS46-SSL-F07"},
        {"cve": "CVE-2024-6119", "patch": "openssl-3.0-CVE-2024-6119.patch"},
        {"cve": "CVE-2024-9143", "patch": "openssl-3.0-CVE-2024-9143.patch"},
        {"cve": "CVE-2024-13176", "patch": "openssl-3.0-CVE-2024-13176.patch"},
        {"cve": "CVE-2024-41996", "patch": "openssl-3.0-CVE-2024-41996.patch"},
    ],
    "2023": [
        {"cve": "CVE-2023-5678", "patch": "openssl-3.0-CVE-2023-5678.patch"},
        {"cve": "CVE-2023-6129", "patch": "openssl-3.0-CVE-2023-6129.patch"},
        {"cve": "CVE-2023-6237", "patch": "openssl-3.0-CVE-2023-6237.patch"},
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAINS
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = [
    {
        "chain_id": "TOS46-SSL-CHAIN-01",
        "title": "CMS AuthEnvelopedData authentication bypass (CVE-2026-34182)",
        "severity": "HIGH",
        "steps": [
            "1. Attacker sends crafted CMS AuthEnvelopedData with non-AEAD cipher (AES-CBC)",
            "2. OpenSSL decrypts without any authentication check",
            "3. Application receives and acts on attacker-controlled plaintext",
            "OR: Attacker specifies 1-byte AEAD tag",
            "4. 256 requests to find a valid authenticated forged message",
            "5. Forge arbitrary CMS content appearing to come from trusted sender",
        ],
        "prerequisites": ["Application processes untrusted CMS messages"],
        "patched": True,
    },
    {
        "chain_id": "TOS46-SSL-CHAIN-02",
        "title": "AES-OCB trailing byte authentication bypass (CVE-2025-69418)",
        "severity": "HIGH",
        "steps": [
            "1. Application uses AES-OCB encryption on x86_64 (AES-NI active)",
            "2. Attacker MITM intercepts encrypted message",
            "3. Modifies bytes in the 'tail' (after last complete block boundary)",
            "4. Authentication tag passes verification (computed over wrong bytes)",
            "5. Application decrypts and processes tampered trailing content",
        ],
        "prerequisites": ["AES-OCB cipher in use", "AES-NI hardware acceleration", "MITM position"],
        "patched": True,
    },
    {
        "chain_id": "TOS46-SSL-CHAIN-03",
        "title": "PKCS12/S-MIME processing crash chain (CVE-2024-0727 + CVE-2026-45447 + CVE-2026-22795)",
        "severity": "HIGH",
        "steps": [
            "1. Attacker creates malformed .p12 or S/MIME message",
            "2. CVE-2024-0727: NULL ContentInfo data → NULL deref in PKCS12_unpack → crash",
            "3. CVE-2026-45447: PKCS7_verify() UAF in BIO chain teardown → heap corruption",
            "4. CVE-2026-22795: wrong ASN.1 type tag → union type confusion → invalid read",
            "5. Target: any application processing certificate bundles or signed emails",
            "6. Worst case: heap corruption → RCE in email clients or web server TLS setup",
        ],
        "prerequisites": ["Application processes untrusted PKCS12 or PKCS7 data"],
        "patched": True,
    },
    {
        "chain_id": "TOS46-SSL-CHAIN-04",
        "title": "BIO linebuffer heap overflow via short write (CVE-2025-68160)",
        "severity": "HIGH",
        "steps": [
            "1. Application uses BIO_f_linebuffer in a BIO chain (common in logging/output)",
            "2. Attacker causes next BIO in chain to perform short writes (network throttle)",
            "3. Unconditional memcpy to fixed-size obuf beyond obuf_size",
            "4. Heap overflow → metadata corruption → potential RCE",
        ],
        "prerequisites": ["BIO_f_linebuffer in use", "ability to cause short writes"],
        "patched": True,
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS46-SSL-F01": OPENSSL_CVE_2026_34182,
    "TOS46-SSL-F02": OPENSSL_CVE_2025_69418,
    "TOS46-SSL-F03": OPENSSL_CVE_2025_68160,
    "TOS46-SSL-F04": OPENSSL_CVE_2025_15467,
    "TOS46-SSL-F05": OPENSSL_CVE_2026_45447,
    "TOS46-SSL-F06": OPENSSL_CVE_2026_22795_22796,
    "TOS46-SSL-F07": OPENSSL_CVE_2024_5535,
    "TOS46-SSL-F08": OPENSSL_CVE_2024_0727,
    "TOS46-SSL-F09": OPENSSL_RSA_IMPLICIT_REJECTION,
    "TOS46-SSL-F10": OPENSSL_TLCP_SM,
}


def get_findings():
    return FINDINGS


def get_attack_chains():
    return ATTACK_CHAINS


def get_cve_count():
    total = sum(len(v) for v in CVE_PATCH_CATALOG.values())
    return total


if __name__ == "__main__":
    import json
    cves = [entry["cve"] for year in CVE_PATCH_CATALOG.values() for entry in year]
    summary = {
        "package": "openssl-3.0.12-27.tl4",
        "base_version": "OpenSSL 3.0.12",
        "patches_audited": 96,
        "cves_patched": len(cves),
        "cve_list": cves,
        "tencent_originated_cves": ["CVE-2026-34182"],
        "sm_tlcp_features": ["TLCP", "RFC8998 TLS1.3 SM ciphers", "SM2-CMS"],
        "findings": [
            {
                "id": k,
                "severity": v.get("severity"),
                "cve": v.get("cve", v.get("cves")),
                "cvss": v.get("cvss_v3"),
            }
            for k, v in FINDINGS.items()
        ],
        "attack_chains": [c["chain_id"] for c in ATTACK_CHAINS],
    }
    print(json.dumps(summary, indent=2))
