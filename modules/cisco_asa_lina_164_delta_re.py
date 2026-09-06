"""
Cisco ASA lina 9.16.4.42 — security delta RE vs 9.16.1
Binary: extracted from asa9-16-4-42-lfbff-k8.SPA → rootfs.img cpio → ./asa/bin/lina
BuildID: 75f31b955aeea2b0fd213ae1d3f899e711dbc9c0
ELF64 stripped PIE, identity-mapped LOAD segments (file offset == vaddr for .text/.rodata).
Compare baseline: 9.16.1 (BuildID confirmed separately; .text 0x00ff9000, 9.22 confirmed same base).
"""

MODULE_ID = "cisco_asa_lina_164_delta_re"
TARGET    = "Cisco ASA lina 9.16.4.42 x86-64"
BASE      = "Delta analysis vs 9.16.1 — security-relevant string additions"

# ELF load layout (9.16.4.42):
#   LOAD0: file 0x00000000  vaddr 0x00000000  sz 0x00c179e0
#   LOAD1: file 0x00c18000  vaddr 0x00c18000  sz 0x03056905  (.text)
#   LOAD2: file 0x03c6f000  vaddr 0x03c6f000  sz 0x0100b065  (.rodata)
#   LOAD3: file 0x04c7aae0  vaddr 0x04c7bae0  sz 0x011a6040  (.data/.bss)


# ── CVE timeline confirmed across corpus ──────────────────────────────────────
VERSION_MATRIX = {
    '9.14.2.14': {
        'build_id':   '65cd03...',
        'lina_size':  '95MB',
        'quic':       False,
        'msg_auth_enforced': False,
        'saml_token_reuse': False,
        'cve_20866_fix': False,
        'ciscossl': 'unknown (no version string found)',
    },
    '9.16.1': {
        'build_id':   'confirmed separately',
        'lina_size':  '94MB',
        'quic':       False,
        'msg_auth_enforced': False,
        'saml_token_reuse': False,
        'cve_20866_fix': False,
        'ciscossl': 'unknown (no CiscoSSL version string found in strings output)',
    },
    '9.16.4.42': {
        'build_id':   '75f31b955aeea2b0fd213ae1d3f899e711dbc9c0',
        'lina_size':  '98MB',
        'quic':       False,
        'msg_auth_enforced': False,
        'saml_token_reuse': True,
        'cve_20866_fix': True,
        'ciscossl': 'CiscoSSL 1.1.1t.7.3sp.242 / CiscoSSL FOM 7.3sp',
    },
    '9.22.2.32': {
        'build_id':   '88929a...',
        'lina_size':  '105MB',
        'quic':       True,
        'msg_auth_enforced': True,
        'saml_token_reuse': True,
        'cve_20866_fix': True,
        'ciscossl': 'CiscoSSL 1.1.1t.7.3sp.242 (same as 9.16.4)',
    },
}


# ── F01: CVE-2022-20866 RSA private key leak detection ───────────────────────
#
# CVE-2022-20866 (Cisco advisory cisco-sa-asaftd-rsa-key-Ugch2WcY):
#   ASA and FTD leaked RSA private key material via a hardware acceleration timing
#   side channel. The private key could be recovered from 'show version', platform
#   diagnostic output, or via network traffic analysis.
#
# Fix in 9.16.4 (new strings, absent in 9.16.1):
#   "(CVE-2022-20866) exposure status"           @ 0x04200070
#   "Keypair <%s> is invalid due to the %s RSA Private Key Leak Vulnerability
#    (CVE-2022-20866) and will be cleared in memory. Please remove this key."
#                                                 @ 0x0420014c
#   "%s RSA Private Key Leak Vulnerability (CVE-2022-20866)"
#   "Keypair <%s> is valid but may have been vulnerable to exposure in previous
#    versions..."
#   "Enable purgatory SSL cleanup"
#   "Disable purgatory SSL cleanup"
#   "Force clean SSL pointer"
#   "Purge cleanup for SSL %s %s:%B/%d to %B/%d for %s session"
#   "Purge cleanup timer start for SSL %s %s:%B/%d to %B/%d for %s session"
#   "purgatory SSL cleanup"
#
# Binary evidence (9.16.4):
#   At 0x0258ed12: display function iterates key list (0x100(%rbx) = next key ptr),
#   checks key type at 0x20(%r15) == 0x2 (RSA), loads key state bits at 0x70(%r15).
#   Calls 0x377d430 (console print) with CVE-2022-20866 exposure status strings.
#
# "Purgatory" mechanism:
#   A new "purgatory" SSL cleanup path delays teardown of SSL sessions associated
#   with a leaked key. Sessions in purgatory are held until the key is replaced.
#   Debug commands expose purgatory state (enable/disable/force clean).
#
# CVSS: 7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)
# Fixed in: 9.16.4.x, 9.14.4.x, 9.12.4.x (per Cisco advisory)
# Affected:  9.14.2.14, 9.16.1 (confirmed absent in this corpus)
#
FINDING_01_CVE_2022_20866 = {
    'id':     'F01',
    'cve':    'CVE-2022-20866',
    'title':  'RSA private key leak — detection and purgatory cleanup added in 9.16.4',
    'affected_in_corpus': ['9.14.2.14', '9.16.1'],
    'fixed_in_corpus':    ['9.16.4.42', '9.22.2.32'],
    'strings_added': [
        ('(CVE-2022-20866) exposure status',     0x04200070),
        ('Keypair <%s> is invalid due to...',     0x0420014c),
        ('purgatory SSL cleanup',                 0x03cd82bd),
    ],
    'key_iter_fn':     0x00258ece2,  # walks key list, checks type/state, logs CVE status
    'key_type_check':  0x00258ed74,  # cmpl $0x2, 0x20(%r15) → RSA check
    'key_state_read':  0x00258ed7b,  # movzwl 0x70(%r15), %edx → reads key exposure bits
    'linked_list_off': 0x100,        # offset to next key in linked list (+0x100 from key obj)
    'mechanism': (
        'purgatory: SSL sessions using an exposed key are held in purgatory queue '
        'until the key is replaced. Key replacement triggers deferred cleanup. '
        'Three new debug commands: Enable/Disable/Force clean purgatory SSL cleanup.'
    ),
}


# ── F02: SAML token reuse detection — added 9.16.4 ───────────────────────────
#
# 9.16.1: No SAML token reuse detection (absence confirmed by string search).
# 9.16.4: New strings:
#   "SAML Token Reuse"                           @ 0x041e3757
#   "SAML_TOKEN_REUSE"                           @ 0x041e3768
#   "SAML_TOKEN_WRONG_GROUP"                     @ 0x041e3790
#   "%s: SAML ac token reuse %s"                 @ 0x0441ac21
#   "%s: SAML ac token tunnel group expected %s, received %s"
#
# Context:
#   After SAML authentication succeeds, ASA issues an AC (AnyConnect) token
#   containing the authenticated identity. The token is subsequently presented
#   to establish VPN sessions.
#
#   9.16.4 adds a cache of used AC tokens. When a token is presented a second
#   time (reuse), the new SAML_TOKEN_REUSE path fires and rejects it.
#
# Scope of protection:
#   This detection catches AC token replay — the token issued AFTER a successful
#   SAML authentication. It does NOT add InResponseTo validation (the SAML
#   assertion itself still lacks this check in all versions through 9.22.2.32).
#
#   InResponseTo check status (confirmed by string absence):
#     9.14.2.14: ABSENT
#     9.16.1:    ABSENT
#     9.16.4.42: ABSENT
#     9.22.2.32: ABSENT
#
#   Result: the IdP-initiated (unsolicited) assertion replay attack documented
#   in SAML_REPLAY_SURFACE (cisco_asa_lina_re.py) remains viable across all
#   four versions. SAML_TOKEN_REUSE detection fires AFTER the assertion is
#   consumed — it prevents reuse of the resulting AC token, not the SAML assertion.
#
FINDING_02_SAML_TOKEN_REUSE = {
    'id':      'F02',
    'title':   'SAML AC token reuse detection — added 9.16.4; does not fix assertion replay',
    'added_in': '9.16.4',
    'absent_in': ['9.14.2.14', '9.16.1'],
    'strings': [
        ('SAML Token Reuse',       0x041e3757),
        ('SAML_TOKEN_REUSE',       0x041e3768),
        ('SAML_TOKEN_WRONG_GROUP', 0x041e3790),
        ('%s: SAML ac token reuse %s', 0x0441ac21),
    ],
    'protects_against': 'AC token reuse after successful SAML authentication',
    'does_not_protect': 'SAML assertion replay (no InResponseTo check in any version)',
    'inresponseto_status': {
        '9.14.2.14': 'ABSENT',
        '9.16.1':    'ABSENT',
        '9.16.4.42': 'ABSENT',
        '9.22.2.32': 'ABSENT',  # confirmed by string search
    },
    'attack_still_viable': (
        'IdP-initiated (unsolicited) SAML assertion replay to ASA ACS endpoint '
        'remains viable across all corpus versions. SAML assertion presented directly '
        'to /+CSCOE+/saml/sp/acs bypasses token reuse check — the token is only '
        'generated after assertion acceptance. The 5-minute NotOnOrAfter window '
        '(SAML_REPLAY_SURFACE.attack_window_sec = 300) is unchanged.'
    ),
}


# ── F03: SAML ACS "Vulnerable-case" labels — added 9.16.4 ────────────────────
#
# New strings in 9.16.4 (absent in 9.16.1):
#   "ACS_VULNERABLE_SAML"                        @ 0x041e3790
#   "ACS_VULNERABLE_NO_SAML"                     (confirmed in 9.22 too)
#   "Invalid or vunerable saml URL received"     @ 0x04169b1b  (note typo: "vunerable")
#   "Vunerable non saml URL received"            (note typo)
#   "Vulnerable-case: invalid tg(%s) on saml/sp/acs" @ 0x045030d0
#
# Binary evidence (9.16.4):
#   Function at 0x032555de handles SAML ACS URL validation.
#   At 0x032558a2: loads "Vulnerable-case: invalid tg(%s) on saml/sp/acs" string.
#   At 0x032558d0: `orw $0x1, 0x2b4(%rbx)` — sets error bit in session struct.
#   At 0x032558d8: `mov $0x2, %eax` — returns 2 (error code).
#   Returns 2 to caller; caller rejects the ACS request.
#
# Interpretation:
#   Cisco added explicit labels for "vulnerable case" code paths in the SAML ACS
#   handler — tunnel group name mismatch, invalid ACS URL, non-SAML URL hitting
#   the ACS endpoint. These paths were present but unlabeled in 9.16.1.
#   The labeling (and corresponding syslog IDs) allows defenders to detect
#   exploit attempts against the ACS endpoint.
#
#   The "vunerable" typo ("vunerable" instead of "vulnerable") appears in two
#   strings. These were added quickly without spell-check — consistent with
#   emergency-patch authorship.
#
# ACS_VULNERABLE_SAML vs ACS_VULNERABLE_NO_SAML:
#   ACS_VULNERABLE_SAML:    ACS endpoint reached WITH a SAML context but invalid tunnel group
#   ACS_VULNERABLE_NO_SAML: ACS endpoint reached WITHOUT a SAML context at all
#   (Both labels fire error paths, not success paths.)
#
FINDING_03_ACS_VULNERABLE_LABELS = {
    'id':       'F03',
    'title':    'SAML ACS "Vulnerable-case" labels and URL validation added 9.16.4',
    'added_in': '9.16.4',
    'strings': [
        ('ACS_VULNERABLE_SAML',              0x041e3790),
        ('Vulnerable-case: invalid tg...',   0x045030d0),
        ('Invalid or vunerable saml URL',    0x04169b1b),
    ],
    'fn_va':        0x032555de,  # SAML ACS URL validation handler
    'error_bit_write': 0x032558d0,  # orw $0x1, 0x2b4(%rbx)
    'return_error':    0x032558d8,  # mov $0x2, %eax → error
    'syslog_coverage': True,  # ACS_VULNERABLE_* are registered syslog message IDs
    'typo_in_strings': ['vunerable saml URL', 'Vunerable non saml URL'],
    'note': (
        'The "vunerable" typo in two strings suggests rapid development. '
        'Both ACS_VULNERABLE strings are registered as syslog message IDs — '
        'defenders should alert on these to detect exploit attempts against '
        '/+CSCOE+/saml/sp/acs.'
    ),
}


# ── F04: CiscoSSL version update ─────────────────────────────────────────────
#
# 9.16.4 introduces the CiscoSSL version string in the binary:
#   "CiscoSSL 1.1.1t.7.3sp.242"
#   "CiscoSSL FOM 7.3sp"
#
# 9.16.1 has no CiscoSSL version string in strings output.
# 9.22.2.32 also uses CiscoSSL 1.1.1t.7.3sp.242 (same version).
#
# OpenSSL 1.1.1t:
#   Released 2023-02-07. Fixes CVE-2023-0286 (X.400 address type confusion),
#   CVE-2022-4304 (RSA timing side channel — overlaps with CVE-2022-20866scope),
#   CVE-2022-4450 (double-free in PEM buffer), CVE-2023-0215 (use-after-free in
#   BIO_new_NDEF). All medium severity.
#
FINDING_04_CISCOSSL_UPDATE = {
    'id':     'F04',
    'title':  'CiscoSSL updated to 1.1.1t.7.3sp.242 in 9.16.4',
    'version_9164': 'CiscoSSL 1.1.1t.7.3sp.242 / FOM 7.3sp',
    'version_9161': 'unknown (no version string in binary)',
    'version_9220': 'CiscoSSL 1.1.1t.7.3sp.242 (same)',
    'openssl_cves_fixed_in_1_1_1t': [
        'CVE-2023-0286 — X.400 type confusion in GeneralName',
        'CVE-2022-4304 — RSA decryption timing oracle',
        'CVE-2022-4450 — double-free in PEM d2i_PKCS8_fp',
        'CVE-2023-0215 — UAF in BIO_new_NDEF',
    ],
    'note': '9.16.4 and 9.22 share the same CiscoSSL version — upstream OpenSSL was not updated between these releases.',
}


# ── F05: SAML Lua API evolution ───────────────────────────────────────────────
#
# Lua code embedded as string literals (compiled Lua bytecode with inline source
# preserved in binary as debug strings):
#
# 9.16.1:
#   "local uid, session = SAML_SP_CONSUME_ASSERTION(tgname, samlresp);"
#   (not commented; active Lua code path)
#
# 9.16.4:
#   "--local uid, session = SAML_SP_CONSUME_ASSERTION(tgname, samlresp);"
#   (Lua comment prefix "--"; same code but COMMENTED OUT in the embedded Lua)
#   "aaa["saml"]["cisco_group_policy"]"  (bracket notation, replacing 9.16.1 dotted)
#   "ACS_VULNERABLE_SAML" / "ACS_VULNERABLE_NO_SAML" in Lua context
#
# 9.22.2.32:
#   "SAML_SP_CONSUME_ASSERTION" (active, not commented)
#   "SAML_SP_PRODUCE_AUTHN_REQ" (new)
#   "SAML_SP_VALIDATE_RELAYSTATE_HASH" (new — RelayState HMAC binding)
#   blob = string.gsub(blob,"{{AC_SAML_TOKEN}}",saml_ac_v2_token); (token embedding)
#
# Observation:
#   The SAML_SP_CONSUME_ASSERTION Lua call was active in 9.16.1 and commented out
#   in 9.16.4, suggesting a security concern with the direct Lua API call. By 9.22.2.32
#   it is active again — possibly refactored with added validation (RelayState HMAC).
#   The notation change (aaa.saml. → aaa["saml"]["..."]) is cosmetic (both valid Lua).
#
FINDING_05_SAML_LUA_EVOLUTION = {
    'id':    'F05',
    'title': 'SAML Lua API: SAML_SP_CONSUME_ASSERTION commented out in 9.16.4, reinstated in 9.22',
    'version_9161': {
        'consume_assertion': 'ACTIVE (no leading --)',
        'notation':          'aaa.saml.cisco_group_policy',
    },
    'version_9164': {
        'consume_assertion': 'COMMENTED OUT (leading --)',
        'notation':          'aaa["saml"]["cisco_group_policy"]',
    },
    'version_9220': {
        'consume_assertion': 'ACTIVE',
        'new_fns':           ['SAML_SP_PRODUCE_AUTHN_REQ', 'SAML_SP_VALIDATE_RELAYSTATE_HASH'],
        'token_embedding':   'string.gsub(blob, "{{AC_SAML_TOKEN}}", saml_ac_v2_token)',
    },
    'note': (
        'The comment-out in 9.16.4 may reflect a period where the Lua SAML API '
        'was disabled pending the ACS vulnerability fixes (F03). By 9.22 it is '
        'reinstated with additional validation (RelayState HMAC). The actual '
        'Lua bytecode source may differ from the embedded string literals; '
        'the comments are likely in the Lua source template, not compiled bytecode.'
    ),
}


# ── F06: New UAUTH / session error strings ────────────────────────────────────
#
# New in 9.16.4 (absent in 9.16.1) — UAUTH session management:
#   "UAUTH: Session=0x%08x, User=%s, Assigned IP=%I, Failed adding entry."
#   "UAUTH: Session=0x%08x, User=%s, Assigned IP=%I, Failed removing entry - %s."
#   "UAUTH: Session=0x%08x, User=%s, Assigned IP=%I, Removing stale entry added %H ago."
#   "UAUTH: Session=0x%08x, User=%s, Assigned IP=%I, Failed updating entry - no entry."
#   (multiple variants for add/remove/update/filter operations)
#
# Also new in 9.16.4:
#   "DTLS_TUNNEL_HANDLE_ZERO" — DTLS tunnel handle zero error (NULL pointer guard)
#   "endpoint.anyconnect.session_token_security" — AnyConnect session token security
#   "EAP: Invalid tunnel-group for auth reply processing" — EAP tunnel group mismatch
#   "ACK injection failed when CH is received" — TLS Client Hello ACK injection tracking
#   "ACK injection succeeded when CH is received"
#   "Dropping the packet %s RST injected by snort after server hello is done flow:%p..."
#   "1201) Enable purgatory SSL cleanup"  — debug command table addition
#
FINDING_06_NEW_ERROR_PATHS = {
    'id':    'F06',
    'title': 'New UAUTH session error paths and DTLS/EAP guards in 9.16.4',
    'additions': [
        'UAUTH stale entry detection and cleanup strings (7 new variants)',
        'DTLS_TUNNEL_HANDLE_ZERO — NULL tunnel handle guard',
        'EAP: Invalid tunnel-group for auth reply — tunnel group mismatch in EAP',
        'ACK injection tracking strings (TLS CH ACK path)',
        'RST injection log (Snort RST after server hello)',
        'session_token_security AnyConnect attribute',
    ],
    'security_relevance': (
        'DTLS_TUNNEL_HANDLE_ZERO and UAUTH stale entry removal suggest bug fixes for '
        'NULL dereference and stale session entry conditions respectively. '
        'These were likely discovered in 9.16.1 deployments; the 9.16.4 fixes add '
        'error handling rather than ignoring the conditions silently.'
    ),
}


# ── Summary ───────────────────────────────────────────────────────────────────

FINDINGS = [
    FINDING_01_CVE_2022_20866,
    FINDING_02_SAML_TOKEN_REUSE,
    FINDING_03_ACS_VULNERABLE_LABELS,
    FINDING_04_CISCOSSL_UPDATE,
    FINDING_05_SAML_LUA_EVOLUTION,
    FINDING_06_NEW_ERROR_PATHS,
]

SECURITY_DELTA_SUMMARY = {
    '9.16.1_to_9.16.4': {
        'critical_fixes': ['CVE-2022-20866 RSA key leak detection + purgatory cleanup'],
        'mitigations_added': [
            'SAML AC token reuse detection (SAML_TOKEN_REUSE)',
            'ACS URL validation with Vulnerable-case labels',
            'UAUTH stale session cleanup',
            'DTLS NULL handle guard',
        ],
        'ssl_library': 'CiscoSSL 1.1.1t (updated from unknown version)',
        'attack_surface_unchanged': [
            'SAML assertion replay (no InResponseTo — all versions)',
            'OU= RADIUS Class attribute overflow (gp_obj+0x2b1)',
            'Message-Authenticator not enforced (2 refs → no enforcement)',
        ],
    },
}
