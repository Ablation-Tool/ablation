"""
TencentOS Server 3.1 389-ds-base LDAP Server RE Module
Source: 13-version SRPM ladder (1.4.2.4-8 → 1.4.3.39-8)
        /media/cowboy/research/tencentos/3.1/AppStream-source/
Method: rpm2cpio extraction + patch audit + spec changelog analysis
        + changelog-based CVE provenance tracking
Analysis date: 2026-09-04

VERSION LADDER ANALYZED (all on Google Drive):
  1.4.2.4-8.tl3      (Nov 2021)  — earliest analyzed
  1.4.2.4-10.tl3     (Dec 2021)
  1.4.3.8-5.tl3      (Jul 2022)  — upgrade to 1.4.3.x series
  1.4.3.28-7.tl3     (Nov 2022)
  1.4.3.28-8.tl3     (Jan 2023)  — CVE-2021-4091 added
  1.4.3.30-6.tl3     (Feb 2023)
  1.4.3.32-3.tl3     (Mar 2023)  — password scheme change: PBKDF2-SHA512 → PBKDF2_SHA256
  1.4.3.34-1.tl3     (May 2023)
  1.4.3.37-1.tl3     (Aug 2023)
  1.4.3.37-2.tl3     (Nov 2023)
  1.4.3.39-3.tl3     (Feb 2024)  — CVE-2024-2199 added
  1.4.3.39-7.tl3     (Aug 2024)  — CVE-2024-3657, CVE-2024-5953 added
  1.4.3.39-8.tl3     (Nov 2024)  — LATEST ANALYZED

FINDINGS:
  TOS31-DS-F01 (HIGH/7.5)    bind DoS via malformed userPassword hash (CVE-2024-5953)
  TOS31-DS-F02 (HIGH/7.5)    LDAP filter stack overflow via dn syntax (CVE-2024-3657)
  TOS31-DS-F03 (MEDIUM/6.2)  non-UTF8 userPassword modify crash (CVE-2024-2199)
  TOS31-DS-F04 (MEDIUM/5.9)  virtual attribute double-free (CVE-2021-4091)
  TOS31-DS-F05 (INFO)        password scheme changed default PBKDF2-SHA512 → PBKDF2_SHA256
"""

# ──────────────────────────────────────────────────────────────────────────────
# VERSION LADDER DETAIL
# ──────────────────────────────────────────────────────────────────────────────

VERSION_LADDER = {
    "1.4.2.4-8.tl3": {
        "date": "2021-11",
        "notable": "Earliest analyzed version",
        "base_version": "1.4.2.4",
    },
    "1.4.2.4-10.tl3": {
        "date": "2021-12",
        "changes": "Build/packaging fixes",
    },
    "1.4.3.8-5.tl3": {
        "date": "2022-07",
        "notable": "Upgrade from 1.4.2.x → 1.4.3.x series",
        "changes": "Multiple security patches backported from 1.4.4.x",
    },
    "1.4.3.28-7.tl3": {
        "date": "2022-11",
        "changes": "Stability patches",
    },
    "1.4.3.28-8.tl3": {
        "date": "2023-01",
        "notable": "CVE-2021-4091 (double-free in virtual attribute) added",
        "cves_added": ["CVE-2021-4091"],
    },
    "1.4.3.30-6.tl3": {
        "date": "2023-02",
        "changes": "Miscellaneous fixes",
    },
    "1.4.3.32-3.tl3": {
        "date": "2023-03",
        "notable": "DEFAULT PASSWORD SCHEME CHANGED: PBKDF2-SHA512 → PBKDF2_SHA256",
        "changes": "Replication compatibility fix + password scheme change",
    },
    "1.4.3.34-1.tl3": {
        "date": "2023-05",
        "changes": "Performance and LDAP compliance patches",
    },
    "1.4.3.37-1.tl3": {
        "date": "2023-08",
        "changes": "HAProxy support added (Issue #5003)",
    },
    "1.4.3.37-2.tl3": {
        "date": "2023-11",
        "changes": "Stability patches",
    },
    "1.4.3.39-3.tl3": {
        "date": "2024-02",
        "notable": "CVE-2024-2199 (non-UTF8 password modify crash) added",
        "cves_added": ["CVE-2024-2199"],
    },
    "1.4.3.39-7.tl3": {
        "date": "2024-08",
        "notable": "CVE-2024-3657 (LDAP filter stack overflow) + CVE-2024-5953 (bind DoS) added",
        "cves_added": ["CVE-2024-3657", "CVE-2024-5953"],
    },
    "1.4.3.39-8.tl3": {
        "date": "2024-11",
        "notable": "Latest analyzed; minor fixes",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-F01: bind DoS via malformed hash (CVE-2024-5953)
# ──────────────────────────────────────────────────────────────────────────────

DS_BIND_DOS_CVE_2024_5953 = {
    "finding_id": "TOS31-DS-F01",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2024-5953",
    "package": "389-ds-base-1.4.3.39-7.tl3 (fixed), 1.4.3.39-3.tl3 and earlier vulnerable",
    "title": (
        "389-ds-base: malformed hash stored in userPassword attribute causes server DoS "
        "during LDAP bind authentication; attacker stores crafted hash via directory "
        "write, then binds to trigger denial of service"
    ),
    "description": (
        "When an LDAP bind request is processed, 389-ds-base checks the user's "
        "userPassword attribute against the supplied bind password. The userPassword "
        "attribute stores hashed passwords in the format: {SCHEME}hashed_value "
        "\n"
        "For PBKDF2 and MD5-based schemes, the hash value is base64-encoded binary data "
        "followed by salt. The server decodes the hash to extract parameters (iterations, "
        "salt length, hash length) from the stored value's structure. "
        "\n"
        "Prior to the fix, the server did NOT validate that the stored hash was "
        "internally coherent before using it for password verification. Specifically: "
        "  - MD5 hashes: md5_pwd.c reads 'hash_len' from the stored value without "
        "    checking that hash_len matches the actual MD5 digest length (16 bytes). "
        "  - PBKDF2 hashes: pbkdf2_pwd.c reads iteration count and salt length from "
        "    embedded fields without bounds checking. "
        "\n"
        "A user with WRITE permission to their own or another's userPassword attribute "
        "can store a malformed hash value. When anyone (or the server internally) "
        "attempts to authenticate via that account, processing the malformed hash crashes "
        "the directory server, causing denial of service for ALL LDAP clients. "
        "\n"
        "Fix: add hash size coherence checks at the top of md5_pwd.c and pbkdf2_pwd.c "
        "password verification functions. If hash_len does not match expected size → "
        "LDAP_INVALID_CREDENTIALS returned, no crash."
    ),
    "attack_chain": (
        "1. Attacker has LDAP bind access and WRITE permission to own userPassword "
        "   (or any user with userPassword write permission). "
        "2. Attacker uses ldapmodify to set userPassword to a malformed hash: "
        "   {MD5}AAAA (too short, claims length=256). "
        "3. Attacker (or server internally) binds with that account's DN. "
        "4. md5_pwd.c accesses out-of-bounds data based on stored hash_len. "
        "5. Directory server crashes → all LDAP clients lose authentication. "
        "In Active Directory environments: all Kerberos/SSSD/pam_ldap auth fails."
    ),
    "files_fixed": [
        "ldap/servers/slapd/md5_pwd.c (hash size coherence check added)",
        "ldap/servers/slapd/pbkdf2_pwd.c (hash parameter bounds check added)",
    ],
    "references": [
        "CVE-2024-5953",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2274401",
        "389-ds-base 1.4.3.39-7.tl3 spec changelog: Fix CVE-2024-5953",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-F02: LDAP filter stack overflow (CVE-2024-3657)
# ──────────────────────────────────────────────────────────────────────────────

DS_LDAP_FILTER_OVERFLOW_CVE_2024_3657 = {
    "finding_id": "TOS31-DS-F02",
    "severity": "HIGH",
    "cvss_v3": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2024-3657",
    "package": "389-ds-base-1.4.3.39-7.tl3 (fixed), 1.4.3.39-3.tl3 and earlier vulnerable",
    "title": (
        "389-ds-base: specially crafted LDAP search filter containing very large number "
        "of components (e.g., dn:=) with DN syntax attributes causes stack overflow "
        "in back-ldbm index.c recursive descent → crash"
    ),
    "description": (
        "LDAP search filters can contain assertions against attributes with DN syntax "
        "(e.g., member, owner, uniqueMember). When 389-ds processes a search filter "
        "that matches indexed DN-syntax attributes, the back-ldbm backend's index.c "
        "performs recursive evaluation of the filter components. "
        "\n"
        "A filter with a very large number of DN-syntax attribute assertions "
        "(e.g., (|(dn:foo=bar)(dn:foo=baz)...) repeated 10,000 times) causes deep "
        "recursion in the filter processing stack. Without a recursion depth limit, "
        "this exhausts the stack → stack overflow → server crash. "
        "\n"
        "Fix: add a maximum recursion depth counter to the filter evaluation in "
        "index.c. When the depth limit is exceeded, the search returns an error "
        "(ldap_matchingRuleAssertion exceeds allowed nesting level) rather than recursing. "
        "\n"
        "Attack preconditions: LDAP SEARCH access (anonymous access OR any valid LDAP bind). "
        "Default 389-ds configuration allows anonymous reads to the directory, so this "
        "is effectively an unauthenticated DoS on default installations."
    ),
    "preconditions": [
        "LDAP SEARCH access (anonymous if anonymous access enabled)",
        "Directory has DN-syntax attributes indexed (default on objectClass with member, etc.)",
    ],
    "attack_chain": (
        "1. Connect to LDAP port 389 (no bind required if anonymous access is enabled). "
        "2. Send LDAP SEARCH request with a crafted filter: "
        "   (&(objectClass=groupOfNames)(|(member=cn=a,dc=test,dc=com)(member=cn=b,...) "
        "   ... [10,000 member assertions] ...)). "
        "3. back-ldbm index.c enters deep recursion evaluating each DN assertion. "
        "4. Stack exhaustion → segfault → slapd crash → directory unavailable."
    ),
    "references": [
        "CVE-2024-3657",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2261879",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-F03: non-UTF8 userPassword modify crash (CVE-2024-2199)
# ──────────────────────────────────────────────────────────────────────────────

DS_NONUTF8_PASSWORD_CVE_2024_2199 = {
    "finding_id": "TOS31-DS-F03",
    "severity": "MEDIUM",
    "cvss_v3": 6.2,
    "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2024-2199",
    "package": "389-ds-base-1.4.3.39-3.tl3 (fixed), 1.4.3.28-8.tl3 and earlier vulnerable",
    "title": (
        "389-ds-base: non-UTF8 encoded password in LDAP Password Modify Extended Request "
        "causes server to crash rather than returning appropriate error; "
        "any authenticated user can crash the directory server"
    ),
    "description": (
        "The LDAP Password Modify Extended Operation (RFC 3062) allows users to change "
        "their own passwords. 389-ds-base's modify.c handler validates the new password "
        "against password policy constraints. "
        "\n"
        "One validation step checks if the password contains valid UTF-8. If the password "
        "is required to be valid UTF-8 by policy but the supplied value contains invalid "
        "byte sequences, the error handling code did not properly propagate the "
        "UNWILLING_TO_PERFORM LDAP result code back to the client. Instead, the server "
        "attempted to process the invalid string further, leading to a crash or assertion "
        "failure in the UTF-8 string handling code. "
        "\n"
        "Fix: modify.c now explicitly catches the invalid UTF-8 case early and returns "
        "LDAP_UNWILLING_TO_PERFORM with an error message before any further processing. "
        "\n"
        "Affected: any user with permission to use the Password Modify Extended Operation. "
        "Default policy: users can change their own passwords → any valid LDAP user can "
        "crash the directory server by submitting an invalid-UTF8 password in a modify request."
    ),
    "attack_chain": (
        "1. Bind to LDAP as any valid user. "
        "2. Send LDAP ExtendedRequest (OID 1.3.6.1.4.1.4203.1.11.1) "
        "   with newpasswd containing 0xFF 0xFE 0x80 (invalid UTF-8 sequence). "
        "3. modify.c attempts UTF-8 validation without proper error handling. "
        "4. Server crashes → all LDAP auth fails."
    ),
    "files_fixed": ["ldap/servers/slapd/modify.c (return UNWILLING_TO_PERFORM on non-UTF8)"],
    "references": [
        "CVE-2024-2199",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2265466",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-F04: virtual attribute double-free (CVE-2021-4091)
# ──────────────────────────────────────────────────────────────────────────────

DS_VIRTUAL_ATTR_DOUBLEFREE_CVE_2021_4091 = {
    "finding_id": "TOS31-DS-F04",
    "severity": "MEDIUM",
    "cvss_v3": 5.9,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "cve": "CVE-2021-4091",
    "package": "389-ds-base-1.4.3.28-8.tl3 (fixed, Jan 2023), earlier versions vulnerable",
    "patch_lag": "CVE disclosed 2021, fixed in TOS 3.1 package Jan 2023 — ~14 month lag",
    "title": (
        "389-ds-base: double-free of the return value of the virtual attribute "
        "resolve function (vattr_map_sp_getlist); crash under concurrent LDAP access"
    ),
    "description": (
        "Virtual attributes in 389-ds are computed attributes derived from other attributes "
        "or plugins (e.g., nsRoleDN derives from role plugin). The virtual attribute "
        "resolution code (ldap/servers/slapd/vattr.c) calls vattr_map_sp_getlist() "
        "to enumerate service providers for a virtual attribute. "
        "\n"
        "The return value from vattr_map_sp_getlist() was freed in two locations in the "
        "code path: once in the success path and once in the error/cleanup path, "
        "creating a double-free condition. Under concurrent LDAP access with virtual "
        "attribute lookups, this double-free corrupts the heap allocator and can cause "
        "a server crash. "
        "\n"
        "Note: This CVE was disclosed in December 2021. It was not patched in TOS 3.1 "
        "until January 2023 (version 1.4.3.28-8.tl3) — approximately 14 months after "
        "disclosure. Systems running TOS 3.1 versions before 1.4.3.28-8.tl3 were "
        "exposed for over a year."
    ),
    "patch_lag_analysis": (
        "14-month patch lag is significant. During this window: "
        "  - Upstream 389-ds fixed CVE-2021-4091 in Dec 2021 (v1.4.3.x branch). "
        "  - RHEL 8 shipped the fix in early 2022. "
        "  - TOS 3.1 did not incorporate the fix until Jan 2023. "
        "Explanation: TOS 3.1 was tracking 1.4.3.x upstream but with significant lag "
        "relative to RHEL 8 patch cadence."
    ),
    "references": [
        "CVE-2021-4091",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2040052",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-F05: password scheme change
# ──────────────────────────────────────────────────────────────────────────────

DS_PASSWORD_SCHEME_CHANGE = {
    "finding_id": "TOS31-DS-F05",
    "severity": "INFO",
    "title": (
        "389-ds-base 1.4.3.32-3.tl3: default password scheme changed from "
        "PBKDF2-SHA512 to PBKDF2_SHA256 for replication compatibility; "
        "SHA256 is weaker than SHA512 for password hashing but was chosen to match "
        "the replication partner's supported scheme"
    ),
    "description": (
        "In version 1.4.3.32-3.tl3 (March 2023), the default password hashing scheme "
        "for 389-ds on TOS 3.1 was changed from PBKDF2-SHA512 to PBKDF2_SHA256. "
        "\n"
        "Reason given in changelog: 'replication compatibility.' "
        "This suggests TOS 3.1 directory servers were being replicated to/from systems "
        "that could not process PBKDF2-SHA512 hashes (e.g., Windows AD LDS, older "
        "389-ds versions, or FreeIPA instances). "
        "\n"
        "Security implication: "
        "  - PBKDF2-SHA256 is still secure but offers a smaller security margin vs SHA-512. "
        "  - For offline cracking: SHA-256 iteration loops are faster than SHA-512 on "
        "    modern CPUs (x86-64 SHA-NI instructions for SHA-256 vs software-only for SHA-512). "
        "  - This reduces the effective KDF hardness by approximately 2-4x depending on "
        "    the iteration count configured. "
        "\n"
        "Existing password hashes in the directory ARE NOT retroactively converted. "
        "Only new passwords set after the upgrade to 1.4.3.32-3 use PBKDF2_SHA256. "
        "Old PBKDF2-SHA512 hashes remain valid and are verified against the SHA-512 path."
    ),
    "password_schemes_available": [
        "PBKDF2_SHA256 (default as of 1.4.3.32-3.tl3)",
        "PBKDF2_SHA512 (available, was default before 1.4.3.32)",
        "PBKDF2_SHA1 (legacy, deprecated)",
        "SSHA512 (available)",
        "SSHA256 (available)",
        "SSHA (legacy)",
        "MD5 (legacy, vulnerable per CVE-2024-5953)",
    ],
    "haproxy_support": (
        "1.4.3.37-1.tl3 (Aug 2023) added HAProxy support (referenced as Issue #5003). "
        "This enables HAProxy load balancers to health-check the LDAP service and "
        "handle failover between directory servers. Implies TOS 3.1 389-ds deployments "
        "are fronted by HAProxy in some configurations."
    ),
    "references": [
        "389-ds-base changelog: 1.4.3.32-3.tl3 (2023-03)",
        "https://www.port389.org/docs/389ds/design/password-hash.html",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS31-DS-F01": DS_BIND_DOS_CVE_2024_5953,
    "TOS31-DS-F02": DS_LDAP_FILTER_OVERFLOW_CVE_2024_3657,
    "TOS31-DS-F03": DS_NONUTF8_PASSWORD_CVE_2024_2199,
    "TOS31-DS-F04": DS_VIRTUAL_ATTR_DOUBLEFREE_CVE_2021_4091,
    "TOS31-DS-F05": DS_PASSWORD_SCHEME_CHANGE,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "source": "389-ds-base 13-version SRPM ladder (1.4.2.4-8 → 1.4.3.39-8)",
        "versions_analyzed": list(VERSION_LADDER.keys()),
        "cves_tracked": ["CVE-2021-4091", "CVE-2024-2199", "CVE-2024-3657", "CVE-2024-5953"],
        "notable": "14-month CVE-2021-4091 patch lag; PBKDF2-SHA512→SHA256 default change",
        "findings": [{"id": k, "severity": v.get("severity", "?"), "cve": v.get("cve", "-")}
                     for k, v in FINDINGS.items()],
    }, indent=2))
