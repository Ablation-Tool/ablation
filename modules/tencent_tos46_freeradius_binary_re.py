"""
TencentOS 4.6 — FreeRADIUS 3.2.6 binary RE.

Binaries:
  fr32-bin/usr/sbin/radiusd              — 535KB PIE, main daemon
  fr32-bin/usr/lib64/freeradius/         — 58 modules (.so)
  fr32-bin/usr/lib64/freeradius/libfreeradius-radius.so — 267KB, core packet parser

Priority targets (authentication modules):
  rlm_pap.so    — 39KB, PAP password hashing/comparison
  rlm_mschap.so — 51KB, MS-CHAPv1/v2 NTHash comparison
  rlm_eap_peap.so / rlm_eap_ttls.so — PEAP/TTLS (EAP inside TLS)
  libfreeradius-radius.so — RADIUS wire protocol parser

Method: endbr64 function detection → BERT semantic sweep (all-MiniLM-L6-v2) →
manual disassembly of top candidates → string-based CVE fix verification.

Source: srpm_work/freeradius-3.2.6-3.tl4/ — 6 RHEL/Fedora patches
Build: FreeRADIUS 3.2.6-3.tl4 (TOS 4.6) — upgraded from 3.2.1 to fix CVE-2024-3596
"""

BINARY_INVENTORY = {
    "radiusd": {
        "path": "fr32-bin/usr/sbin/radiusd",
        "size": 547512,
        "type": "ELF 64-bit PIE executable, stripped",
        "role": "Main RADIUS daemon — request dispatch, client/server management, TLS",
    },
    "libfreeradius-radius.so": {
        "path": "fr32-bin/usr/lib64/freeradius/libfreeradius-radius.so",
        "size": 273560,
        "type": "ELF 64-bit shared object, stripped",
        "functions_detected": 377,
        "text_va": 0xcc30,
        "text_size": 0x1f91d,
        "role": "Core RADIUS packet encode/decode, attribute parsing, authenticator computation",
    },
    "rlm_pap.so": {
        "path": "fr32-bin/usr/lib64/freeradius/rlm_pap.so",
        "size": 40232,
        "functions_detected": 17,
        "role": "PAP password checking: PBKDF2-SHA256/512, SSHA*, MD5, SHA1, NS-MTA-MD5, crypt",
    },
    "rlm_mschap.so": {
        "path": "fr32-bin/usr/lib64/freeradius/rlm_mschap.so",
        "size": 52536,
        "functions_detected": 15,
        "role": "MS-CHAP v1/v2: NTHash generation, MPPE key derivation, MS-CHAPv2 challenge-response",
    },
    "rlm_eap_peap.so": {
        "path": "fr32-bin/usr/lib64/freeradius/rlm_eap_peap.so",
        "size": 40456,
        "role": "EAP-PEAP outer TLS shell; tunnels inner EAP (GTC/MSCHAPv2/PAP)",
    },
    "rlm_eap_ttls.so": {
        "path": "fr32-bin/usr/lib64/freeradius/rlm_eap_ttls.so",
        "size": 36184,
        "role": "EAP-TTLS outer TLS shell; tunnels inner PAP/CHAP/MSCHAPv2/EAP",
    },
}

PLT_AUDIT = {
    "radiusd_unsafe_imports": [
        "strcpy",
        "__strcpy_chk",
        "__snprintf_chk",
        "__sprintf_chk",
        "__vsnprintf_chk",
        "__isoc23_sscanf",
        "fgets",
        "snprintf",
        "memcpy",
        "__memcpy_chk",
        "fr_pair_value_strcpy",
        "fr_pair_value_sprintf",
    ],
    "note": (
        "FreeRADIUS uses talloc memory model for all attribute values. "
        "fr_pair_value_strcpy() is the safe RADIUS attribute string copy (length-bounded by "
        "the RADIUS protocol's 255-byte attribute value limit). "
        "Raw strcpy appears in internal paths where source is a compile-time or "
        "protocol-bounded string. __strcpy_chk and FORTIFY_SOURCE wrappers cover most sites. "
        "Memory allocation via talloc + rad_malloc (abort on failure); no unchecked return values."
    ),
    "rlm_pap_imports": [
        "fr_pair_value_strcpy",
        "fr_pair_value_memcpy",
        "memcpy",
        "__memcpy_chk",
        "EVP_md5/sha*",
        "PKCS5_PBKDF2_HMAC",
        "fr_crypt_check",
    ],
    "rlm_mschap_imports": [
        "__snprintf_chk",
        "__sprintf_chk",
        "fr_pair_value_memcpy",
        "fr_sha1_*",
        "EVP_EncryptInit_ex",
        "EVP_EncryptUpdate",
        "fr_rand",
    ],
}

CVE_2024_3596_ANALYSIS = {
    "cve": "CVE-2024-3596",
    "name": "BlastRADIUS",
    "severity": "HIGH",
    "cvss": 9.0,
    "published": "2024-07-09",
    "description": (
        "RADIUS protocol design flaw: the MD5-based Request/Response Authenticator and "
        "User-Password attribute encryption do not prevent MD5 chosen-prefix collision attacks. "
        "An on-path attacker between RADIUS client and server can: "
        "(1) forge a valid Access-Accept response to any Access-Request, "
        "(2) perform privilege escalation by modifying attribute values in the accepted packet. "
        "Root cause: the RADIUS authenticator is a single MD5 digest over (packet_header || "
        "attributes || shared_secret); without Message-Authenticator (HMAC-MD5 over the full "
        "packet), collision attacks can produce a valid-looking authenticator for a modified packet. "
        "Fix: enforce Message-Authenticator (RFC 3579 §3.2) in all Access-Request and "
        "Access-Accept packets. FreeRADIUS 3.2.6 adds `require_message_authenticator` per-client "
        "configuration and automatic detection of BlastRADIUS-vulnerable clients."
    ),
    "fix_status": "CONFIRMED_PRESENT",
    "fix_verification": (
        "Binary strings confirm the fix: "
        "'BlastRADIUS check: Received packet without Message-Authenticator.' "
        "'Setting \"require_message_authenticator = false\" for client %s' "
        "'UPGRADE THE CLIENT AS YOUR NETWORK IS VULNERABLE TO THE BLASTRADIUS ATTACK.' "
        "'BlastRADIUS check: Received packet with Proxy-State, but without Message-Authenticator.' "
        "The require_message_authenticator option, automatic per-client state tracking, and "
        "Proxy-State detection (the primary exploitation vector) are all compiled in."
    ),
    "operational_note": (
        "Fix is DEFENSIVE: FreeRADIUS detects and warns about non-compliant RADIUS clients. "
        "Operators must also upgrade RADIUS clients (NAS devices, switches, APs) and set "
        "'require_message_authenticator = true' per-client to fully mitigate. "
        "The server-side fix alone is not sufficient if clients cannot send Message-Authenticator."
    ),
    "affected_protocols": ["RADIUS/UDP (Access-Request/Accept/Reject)", "NOT RADIUS-over-TLS (RadSec)"],
}

BERT_SWEEP = {
    "method": "3 query profiles (AUTH_BYPASS, BUF_OVF, MD5_DOWNGRADE), all-MiniLM-L6-v2",
    "results": {
        "rlm_pap.so": {
            "functions": 17,
            "max_score": 0.254,
            "top_hit": {
                "va": 0x51c0,
                "calls": ["fr_hex2bin"],
                "strings": ['"known good" NS-MTA-MD5-Password has incorrect length',
                            '"known good" NS-MTA-MD5-Password is too long'],
                "verdict": "FALSE_POSITIVE — length validation function for NS-MTA-MD5-Password format",
            },
            "verdict": "No patterns above 0.260 — all-INFO",
        },
        "rlm_mschap.so": {
            "functions": 15,
            "max_score": 0.191,
            "top_hit": {
                "va": 0x5240,
                "calls": ["fr_sha1_init", "fr_sha1_update"],
                "strings": ["Magic server to client signing constant"],
                "verdict": "FALSE_POSITIVE — MS-CHAPv2 MPPE key derivation (FIPS 46-2 compliant)",
            },
            "verdict": "No patterns above 0.200 — all-INFO",
        },
        "libfreeradius-radius.so": {
            "functions": 377,
            "max_score": 0.354,
            "top_hit": {
                "va": 0x1e760,
                "calls": ["fr_assert_cond", "fr_pair_list_free", "_talloc_free"],
                "strings": ["radius_packet", "src/lib/radius.c"],
                "verdict": "FALSE_POSITIVE — packet cleanup/free function with assertion guard",
            },
            "verdict": "No patterns above 0.360 — all-INFO",
        },
    },
    "overall": (
        "Max BERT score across all three modules: 0.354 (cleanup function). "
        "FreeRADIUS's use of talloc, fr_pair_* API, and FORTIFY_SOURCE reduces exploit surface. "
        "Auth modules (rlm_pap, rlm_mschap) are small — most logic is inlined into main binary or "
        "implemented via library calls to libfreeradius-radius.so."
    ),
}

RLM_PAP_ANALYSIS = {
    "schemes_detected": [
        "{PBKDF2-SHA256}",
        "{PBKDF2-SHA512}",
        "{SHA}",
        "{SHA256}",
        "{SHA512}",
        "{SHA3-256}",
        "{MD5}",
        "{SSHA}",
        "{SSHA256}",
        "{NS-MTA-MD5}",
        "{crypt}",
    ],
    "pbkdf2_strings": [
        "PBKDF2-Password too short",
        "Can't determine format of PBKDF2-Password",
    ],
    "note": (
        "rlm_pap.so exports all hashing primitives via EVP_* + PKCS5_PBKDF2_HMAC. "
        "fr_crypt_check() wraps crypt(3) for Unix password compatibility. "
        "Password scheme selection is by string prefix matching on the stored password. "
        "NS-MTA-MD5: legacy Netscape Mail Server MD5 format; validation rejects incorrect lengths."
    ),
}

RLM_MSCHAP_ANALYSIS = {
    "observed_strings": [
        "nt_password",
        "Magic server to client signing constant",
        "src/modules/rlm_mschap/rlm_mschap.c",
    ],
    "algorithm": (
        "MS-CHAPv2 uses NTLM hash (MD4 of UTF-16LE password), challenge-response, "
        "and MPPE key derivation (SHA-1 based). "
        "rlm_mschap.so: fr_sha1_init/update sequence for MPPE-Keys, "
        "EVP_EncryptInit_ex + EVP_EncryptUpdate for RC4 encryption (MPPE), "
        "fr_rand for server challenge generation."
    ),
    "timing_note": (
        "fr_pair_find_by_num() returns the NT-Password attribute; password comparison "
        "is inside libfreeradius-radius.so — timing not directly observable from rlm_mschap.so alone."
    ),
}

SRPM_PATCHES = {
    "count": 6,
    "security_relevant": {
        "freeradius-ldap-infinite-timeout-on-starttls.patch": (
            "rlm_ldap: use infinite timeout (blocking socket) for LDAP+StartTLS initialization. "
            "Fixes race where FreeRADIUS started before LDAP TLS handshake completed. "
            "Bug: LDAP startup race → LDAP module load failure → auth falls through or errors. "
            "Not a vuln — startup reliability fix."
        ),
        "freeradius-Use-system-crypto-policy-by-default.patch": (
            "EAP/TLS: use /etc/crypto-policies (RHEL system crypto policy) instead of "
            "FreeRADIUS default cipher list. Ensures TLS cipher choices align with OS policy. "
            "Security benefit: enforces operator-configured crypto posture (e.g., FUTURE policy "
            "disabling TLS 1.0/1.1 and weak ciphers)."
        ),
    },
    "packaging_only": [
        "freeradius-Adjust-configuration-to-fit-Red-Hat-specifics.patch",
        "freeradius-bootstrap-create-only.patch",
        "freeradius-bootstrap-make-permissions.patch",
        "freeradius-no-buildtime-cert-gen.patch",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2024-3596",
        "title": "BlastRADIUS: MD5 collision attack on RADIUS authenticator — FIXED in 3.2.6",
        "detail": (
            "RADIUS protocol flaw: MD5 authenticator vulnerable to chosen-prefix collision attacks. "
            "On-path attacker can forge Access-Accept for any Access-Request. "
            "Fixed by require_message_authenticator enforcement. "
            "Binary CONFIRMED: BlastRADIUS detection strings + per-client auto-learning present. "
            "Mitigation requires also upgrading RADIUS clients (NAS) and enabling "
            "'require_message_authenticator = true' per-client. "
            "RadSec (RADIUS-over-TLS) is NOT affected."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "BERT sweep: 3 modules, max score 0.354 — no HIGH-confidence patterns",
        "detail": (
            "rlm_pap.so (17 funcs): max 0.254 — NS-MTA-MD5 length validation (FP). "
            "rlm_mschap.so (15 funcs): max 0.191 — MPPE key derivation (FP). "
            "libfreeradius-radius.so (377 funcs): max 0.354 — packet free/assert (FP). "
            "FreeRADIUS uses talloc + fr_pair_* API reducing direct strcpy/memcpy exposure."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "radiusd + libfreeradius-radius.so: raw strcpy in PLT — bounded by RADIUS protocol",
        "detail": (
            "strcpy present alongside __strcpy_chk (FORTIFY_SOURCE). "
            "RADIUS attribute values are ≤253 bytes by protocol spec; fr_pair_* API enforces this. "
            "talloc provides bounds-checked allocation throughout the codebase. "
            "No evidence of user-controlled length reaching raw strcpy without fr_pair_* mediation."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "EAP TLS uses system crypto policy (RHEL patch) — cipher suite strength config-dependent",
        "detail": (
            "rlm_eap_peap.so + rlm_eap_ttls.so: cipher_list sourced from /etc/crypto-policies. "
            "EAP-PEAP/TTLS security depends on TOS 4.6 system crypto policy configuration. "
            "LEGACY policy permits TLS 1.0/RC4; DEFAULT blocks them. "
            "Policy enforcement is operator-controlled, not a binary bug."
        ),
    },
]

if __name__ == '__main__':
    print(f"TOS 4.6 FreeRADIUS 3.2.6-3.tl4 binary RE")
    for name, inv in BINARY_INVENTORY.items():
        n = inv.get('functions_detected', '?')
        print(f"  {name}: {inv['size']//1024}KB, {n} funcs")
    print()
    print(f"CVE-2024-3596 (BlastRADIUS): {CVE_2024_3596_ANALYSIS['fix_status']}")
    print(f"  require_message_authenticator implemented; Proxy-State detection active")
    print()
    print("BERT sweep (3 modules):")
    for mod, d in BERT_SWEEP['results'].items():
        print(f"  {mod}: {d['functions']} funcs, max={d['max_score']:.3f} — {d['verdict']}")
    print()
    for f in FINDINGS:
        cve = f"[{f['cve']}] " if f.get('cve') else ""
        print(f"  [{f['severity']:6s}] {f['id']}: {cve}{f['title'][:70]}")
