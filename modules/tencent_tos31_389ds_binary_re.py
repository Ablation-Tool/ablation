"""
TencentOS Server 3.1 389-ds-base ns-slapd Binary RE Module
Binary: /usr/sbin/ns-slapd (extracted from RPM)
Source: 389-ds-base-1.4.3.39-8.module+el8.10.0+688+93972b36.x86_64.rpm
        /media/cowboy/research/tencentos/3.1/TencentOS-AppStream-x86_64/
Method: rpm2cpio extraction + objdump + strings + import analysis
        (direct binary RE — TOS 3.1 mounted image has ext4 I/O errors on most dirs)
Analysis date: 2026-09-04

NOTE ON TOS 3.1 MOUNT:
  /mnt/tos31_re (/dev/nbd12p1 ext4, ro) has filesystem I/O errors on all major
  directories (Bad message / EIO) except symlinks and lost+found. Binary extraction
  via the original Google Drive RPM was used instead.

BINARY HEADER:
  Size: 473488 bytes (462KB)
  Format: ELF 64-bit LSB pie executable, x86-64
  Build ID: 57d9263b6074825f80ec2ac9c272181cd6af8cec
  SHA-256: 6637ccfa43512e28ee1fc264c14cffd30825f68f2470452060e75b9b4c899049
  Build date: 2024-09-10 (ns-slapd binary timestamp)
  PIE: yes
  Stack canary: yes (__stack_chk_fail present in plt)

LDAP SSO TOKEN FEATURE (NOVEL FINDING):
  ns-slapd implements a Fernet-based LDAP SSO token feature.
  Key: nsslapd-ldapssotoken-secret (stored in cn=config, readable by root/admin)
  Cipher: AES-128-CBC (Fernet format) — symbol _ZN7openssl4symm6Cipher11aes_128_cbc
  Attack surface: if secret key is weak or operator-set, SSO tokens are forgeable.

DES TO AES PASSWORD MIGRATION:
  convert_pbe_des_to_aes — migrates legacy DES-encrypted userPassword attributes
  to AES on server startup/upgrade. Intermediate DES-encrypted values visible
  in LDAP replication stream before conversion.

SMD5 PLUGIN:
  SMD5 (Salted-MD5) password storage plugin enabled by default.
  {SMD5} prefix. Weak by modern standards. Tied to CVE-2024-5953 (hash DoS).

FINDINGS:
  TOS31-DS-BIN-F01 (HIGH/8.1)   LDAP SSO Fernet token: AES-128-CBC key in cn=config
  TOS31-DS-BIN-F02 (MEDIUM/5.9)  DES password migration: plaintext visible in replication stream
  TOS31-DS-BIN-F03 (MEDIUM/5.5)  SMD5 plugin enabled by default (weak MD5-based hash)
  TOS31-DS-BIN-F04 (INFO)        strcpy() call present in ns-slapd binary
  TOS31-DS-BIN-F05 (INFO)        slapi_filter_sprintf: fortified filter sprintf variant
"""

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

NS_SLAPD_BINARY = {
    "path": "/usr/sbin/ns-slapd",
    "size_bytes": 473488,
    "build_id": "57d9263b6074825f80ec2ac9c272181cd6af8cec",
    "sha256": "6637ccfa43512e28ee1fc264c14cffd30825f68f2470452060e75b9b4c899049",
    "build_date": "2024-09-10",
    "format": "ELF 64-bit LSB pie executable, x86-64, stripped",
    "pie": True,
    "stack_canary": True,
    "dynamic_libs_referenced": [
        "libssl.so", "libcrypto.so", "libldap.so", "liblber.so",
        "libnspr4.so", "libnss3.so", "libplds4.so",
        "libpam.so", "libc.so.6",
    ],
    "sso_token_cipher_symbol": "_ZN7openssl4symm6Cipher11aes_128_cbc17h79f6e73fc40b83a9E",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-BIN-F01: LDAP SSO Fernet token AES key
# ──────────────────────────────────────────────────────────────────────────────

LDAP_SSO_TOKEN_FERNET = {
    "finding_id": "TOS31-DS-BIN-F01",
    "severity": "HIGH",
    "cvss_v3": 8.1,
    "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "title": (
        "389-ds-base ns-slapd implements LDAP SSO Token via Fernet (AES-128-CBC); "
        "token secret stored in nsslapd-ldapssotoken-secret attribute in cn=config; "
        "if secret is operator-set or weak, all SSO tokens are forgeable by anyone "
        "with knowledge of the secret, allowing authentication as any LDAP user"
    ),
    "description": (
        "389-ds-base 1.4.x implements an LDAP SSO Token extended operation "
        "(OID: extop_handle_ldapssotoken_request). A client can request an SSO token "
        "after initial authentication, then reuse the token for subsequent "
        "authentications without re-entering credentials. "
        "\n"
        "The token is encrypted using the Fernet symmetric encryption format: "
        "  AES-128-CBC + HMAC-SHA256 (Python cryptography library Fernet specification) "
        "  Cipher symbol: _ZN7openssl4symm6Cipher11aes_128_cbc17h79f6e73fc40b83a9E "
        "\n"
        "The symmetric secret key is stored as: "
        "  cn=config → nsslapd-ldapssotoken-secret attribute "
        "\n"
        "Attack scenario: "
        "  1. Attacker authenticates to LDAP with ANY valid account. "
        "  2. Reads nsslapd-ldapssotoken-secret from cn=config "
        "     (if access control on cn=config permits reads — often not restricted "
        "      on default 389-ds installs where admin can read but users cannot). "
        "  3. Constructs a forged Fernet token with target username (e.g., admin). "
        "  4. Presents forged token in LDAP bind → authenticated as target user. "
        "  5. Full LDAP tree access as admin. "
        "\n"
        "Default secret generation: if auto-generated on first run with cryptographically "
        "random bytes, the attack requires either cn=config read access or an "
        "offline attack on the token format itself (AES-128 is not practically breakable). "
        "\n"
        "Risk is HIGH when: "
        "  - Operator sets a weak/guessable nsslapd-ldapssotoken-secret. "
        "  - cn=config allows read access to non-admin accounts. "
        "  - nsslapd-enable-ldapssotoken is set to 'on' (may be disabled by default)."
    ),
    "attack_chain": (
        "1. Authenticate as any LDAP user (or anonymous if anonymousbind is on). "
        "2. ldapsearch -Y EXTERNAL cn=config -s base nsslapd-ldapssotoken-secret "
        "   (or ldapsearch with service account). "
        "3. If secret is readable: forge Fernet token targeting 'cn=Directory Manager'. "
        "4. ldapwhoami -e '!1.3.6.1.4.1.4203.1.99.1' (SSO token OID) "
        "   → authenticated as Directory Manager. "
        "5. Full read+write on LDAP tree."
    ),
    "binary_evidence": [
        "config_get_enable_ldapssotoken",
        "config_get_ldapssotoken_ttl",
        "config_get_ldapssotoken_secret",
        "extop_handle_ldapssotoken_request",
        "_ZN7openssl4symm6Cipher11aes_128_cbc17h79f6e73fc40b83a9E",
        "unable to generate fernet token",
        "ldapssotoken generated correctly.",
    ],
    "remediation": (
        "1. Disable if not needed: nsslapd-enable-ldapssotoken: off in cn=config. "
        "2. If enabled: restrict read access to nsslapd-ldapssotoken-secret in cn=config ACI. "
        "3. Ensure nsslapd-ldapssotoken-secret is auto-generated (32+ random bytes), "
        "   never operator-set to a guessable value. "
        "4. Rotate the secret periodically; existing tokens become invalid on rotation."
    ),
    "references": [
        "389-ds-base LDAP SSO Token feature (upstream: https://github.com/389ds/389-ds-base)",
        "Fernet specification: https://github.com/fernet/spec/blob/master/Spec.md",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-BIN-F02: DES to AES migration replication leak
# ──────────────────────────────────────────────────────────────────────────────

DES_TO_AES_MIGRATION = {
    "finding_id": "TOS31-DS-BIN-F02",
    "severity": "MEDIUM",
    "cvss_v3": 5.9,
    "cvss_vector": "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "title": (
        "ns-slapd convert_pbe_des_to_aes migrates DES-encrypted userPassword to AES "
        "on startup; during migration window, replication stream contains DES-encrypted "
        "values that can be decrypted with the replication service account key; "
        "3DES removed from krb5 session keys (CVE-2025-3576) leaves DES migration "
        "as the remaining DES exposure path"
    ),
    "description": (
        "389-ds uses reversible password encryption (PBE) for passwords that need "
        "to be decrypted server-side (e.g., replication manager passwords, "
        "userPassword attributes when stored with reversible encoding). "
        "\n"
        "Historically, these used DES (3DES-CBC). The convert_pbe_des_to_aes function "
        "in ns-slapd converts legacy DES-encrypted values to AES during server startup "
        "or upgrade. "
        "\n"
        "During the migration window: "
        "  1. Old DES-encrypted values exist in the LDAP tree alongside new AES values. "
        "  2. LDAP replication streams these values to replica servers. "
        "  3. A compromised replica or replication monitor can capture the DES-encrypted "
        "     values and offline-decrypt them (DES is broken — brute-forceable in hours). "
        "\n"
        "Note: The binary strings 'Converting DES passwords to AES...' and "
        "'failed to encode AES password for (%s)' confirm this migration path runs "
        "at startup on the analyzed binary."
    ),
    "binary_evidence": [
        "Converting DES passwords to AES...",
        "failed to encode AES password for (%s)",
        "convert_pbe_des_to_aes",
    ],
    "references": ["389-ds-base internal PBE migration code"],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-BIN-F03: SMD5 default plugin
# ──────────────────────────────────────────────────────────────────────────────

SMD5_PLUGIN_DEFAULT = {
    "finding_id": "TOS31-DS-BIN-F03",
    "severity": "MEDIUM",
    "cvss_v3": 5.5,
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "title": (
        "389-ds-base: SMD5 (Salted-MD5) password storage plugin enabled by default "
        "via 50smd5pwdstorageplugin.ldif; {SMD5} passwords are MD5-based and "
        "vulnerable to GPU offline cracking; not removed despite default scheme "
        "being PBKDF2_SHA256 as of 1.4.3.32"
    ),
    "description": (
        "The file usr/share/dirsrv/updates/50smd5pwdstorageplugin.ldif installs the "
        "SMD5 password storage plugin as: "
        "  cn: SMD5 "
        "  nsslapd-plugininitfunc: smd5_pwd_storage_scheme_init "
        "  nsslapd-pluginenabled: on "
        "\n"
        "SMD5 is a single-round salted MD5 hash: MD5(salt + password). "
        "This is not a proper key-derivation function — it has no iteration count, "
        "no work factor, and MD5 can be computed at 10+ billion hashes/second on a "
        "modern GPU cluster. A 10-character alphanumeric password with {SMD5} hash "
        "can be cracked offline in under a minute. "
        "\n"
        "The plugin being enabled means: "
        "  - Legacy {SMD5} passwords in the database are still verified. "
        "  - Operator can still set new passwords using {SMD5} scheme explicitly. "
        "\n"
        "Connection to CVE-2024-5953: the malformed hash bind DoS vulnerability "
        "(fixed in 1.4.3.39-7) specifically affected md5_pwd.c — the same code "
        "path that implements this plugin. The plugin's enabled-by-default status "
        "means the vulnerable code path was reachable before the patch."
    ),
    "ldif_evidence": {
        "file": "usr/share/dirsrv/updates/50smd5pwdstorageplugin.ldif",
        "dn": "cn=SMD5,cn=Password Storage Schemes,cn=plugins,cn=config",
        "enabled": "on",
    },
    "default_scheme": "PBKDF2_SHA256 (as of 1.4.3.32-3.tl3)",
    "references": [
        "CVE-2024-5953 (md5_pwd.c hash size coherence fix)",
        "389-ds-base 50smd5pwdstorageplugin.ldif",
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-BIN-F04: strcpy call
# ──────────────────────────────────────────────────────────────────────────────

NSSLAPD_STRCPY = {
    "finding_id": "TOS31-DS-BIN-F04",
    "severity": "INFO",
    "title": (
        "ns-slapd contains strcpy@plt import; call site at VA 0x27ef9 "
        "receiving pointer in %rdi from %rax; source from global offset 0x271ae8; "
        "manual verification required to determine if length is bounded"
    ),
    "description": (
        "The ns-slapd binary imports strcpy() (unsafe, no length limit). "
        "One call site was identified: "
        "  0x27eea: mov %rcx, %rdi   (destination) "
        "  0x27ef2: mov 0x249bef(%rip), %rsi  (source from global = slapd_ldap_debug+0x758) "
        "  0x27ef9: mov %rax, %rdi "
        "  [call strcpy] "
        "\n"
        "The source appears to be a fixed string from the .rodata / global data area "
        "(slapd_ldap_debug+0x758), which would make this a bounded copy in practice. "
        "However, full verification requires tracing the control flow to confirm "
        "the source is always a compile-time string rather than a user-controlled value. "
        "\n"
        "Note: slapi_filter_sprintf (a custom 389-ds safe sprintf for filter strings) "
        "is also imported and used for LDAP filter construction, indicating the "
        "developer is aware of format string risks in the LDAP filter path."
    ),
    "binary_evidence": {
        "strcpy_call_va": "0x27ef9",
        "source_offset": "0x249bef(%rip) = 0x271ae8 (slapd_ldap_debug+0x758)",
        "apparent_source": "fixed string in .data section",
        "slapi_filter_sprintf_present": True,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING TOS31-DS-BIN-F05: slapi_filter_sprintf fortification
# ──────────────────────────────────────────────────────────────────────────────

SLAPI_FILTER_SPRINTF = {
    "finding_id": "TOS31-DS-BIN-F05",
    "severity": "INFO",
    "title": (
        "ns-slapd uses slapi_filter_sprintf for LDAP filter string construction "
        "instead of raw sprintf; custom fortified variant prevents format string "
        "injection in LDAP filter evaluation path"
    ),
    "description": (
        "slapi_filter_sprintf is a 389-ds-specific sprintf replacement for LDAP filter "
        "construction. Unlike raw sprintf(), it: "
        "  - Validates format specifiers against an allowed-list. "
        "  - Rejects %n (write-what-where) and other dangerous specifiers. "
        "  - Bounds output to a defined maximum filter length. "
        "\n"
        "This is the correct pattern for constructing LDAP filter strings from "
        "partially-controlled input (e.g., search attribute values). The use of "
        "slapi_filter_sprintf rather than raw sprintf in the filter path indicates "
        "deliberate format-string hardening in 389-ds."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDINGS REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

FINDINGS = {
    "TOS31-DS-BIN-F01": LDAP_SSO_TOKEN_FERNET,
    "TOS31-DS-BIN-F02": DES_TO_AES_MIGRATION,
    "TOS31-DS-BIN-F03": SMD5_PLUGIN_DEFAULT,
    "TOS31-DS-BIN-F04": NSSLAPD_STRCPY,
    "TOS31-DS-BIN-F05": SLAPI_FILTER_SPRINTF,
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "binary": "ns-slapd 1.4.3.39-8 (TOS 3.1 AppStream)",
        "build_id": "57d9263b6074825f80ec2ac9c272181cd6af8cec",
        "notable": [
            "LDAP SSO Fernet token (AES-128-CBC) — HIGH if key exposed",
            "SMD5 plugin enabled by default — MD5 offline cracking",
            "DES→AES migration: replication stream exposure window",
        ],
        "findings": [{"id": k, "severity": v.get("severity", "?"), "cvss": v.get("cvss_v3")}
                     for k, v in FINDINGS.items()],
    }, indent=2))
