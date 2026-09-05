"""
TencentOS 4.6 — Samba 4.19.4 new CVE patch stack + systemd security patch RE.

Sources:
  scratchpad/samba_work/ — samba-4.19.4-*.tl4 patches
  scratchpad/systemd_work/ — systemd TOS 4.6 patches
"""

SAMBA_METADATA = {
    "package": "samba-4.19.4",
    "tos_version": "TOS 4.6",
    "patches": [
        "0001-fix-CVE-2025-9640.patch",
        "0002-fix-CVE-2026-58222.patch",
        "samba-4.19.4-CVE-2026-6949-58221.patch",
    ],
    "note": "Patches from scratchpad/samba_work/ supplement existing tencent_tos46_samba_srpm_re.py",
}

SAMBA_CVES = {
    "CVE-2025-9640": {
        "title": "vfs_streams_xattr pwrite: gap bytes from realloc not zeroed — info leak",
        "file": "source3/modules/vfs_streams_xattr.c",
        "function": "streams_xattr_pwrite",
        "author": "xiaoyunzhao@tencent.com",
        "description": (
            "streams_xattr_pwrite() stores file alternate data streams (NTFS ADS) as "
            "extended attributes. When a write extends the stream beyond its current "
            "length, the code calls talloc_realloc() to grow the buffer. "
            "The gap between the old end (ea.value.length) and the new allocation is "
            "NOT zeroed — it contains stale heap contents from the previous talloc chunk "
            "or other prior allocation. "
            "A client that writes to a sparse offset (offset >> current size) will see "
            "old heap data when it later reads back the stream's intermediate bytes."
        ),
        "vulnerable_code": "tmp = talloc_realloc(..., offset + n + 1);  /* gap not zeroed */",
        "fixed_code": "size_t new_sz = offset + n + 1;\ntmp = talloc_realloc(..., new_sz);\nmemset(tmp + ea.value.length, 0, new_sz - ea.value.length);",
        "class": "info-disclosure",
        "impact": "Stale heap data leaked to SMB clients reading alternate data streams at sparse offsets.",
    },
    "CVE-2026-58222": {
        "title": "LDAP CompareRequest: confidential attributes readable via compare oracle",
        "file": "source4/ldap_server/ldap_backend.c",
        "function": "ldapsrv_CompareRequest",
        "author": "Stefan Metzmacher <metze@samba.org>",
        "reviewer": "Douglas Bagnall",
        "bz": "16148",
        "description": (
            "The LDAP Compare operation checks if an attribute equals a value and returns "
            "compareTrue/compareFalse. ldapsrv_CompareRequest() did not apply ACL checks "
            "for confidential attribute access. "
            "An unprivileged LDAP client could call CompareRequest against any attribute "
            "(including userPassword, unicodePwd, supplementalCredentials) and learn whether "
            "a given value matches — a boolean oracle that leaks credential material "
            "through a binary-search attack. "
            "Additional issue: the filter was built as '(%s=%*s)' without validating "
            "req->attribute — an attribute name with special characters could inject "
            "into the ldb search filter."
        ),
        "vulnerable_code": 'filter = talloc_asprintf(local_ctx, "(%s=%*s)", req->attribute, (int)req->value.length, req->value.data);',
        "fixed_code": (
            "/* Validate attribute name */\n"
            "if (!ldb_valid_attr_name(req->attribute)) {\n"
            "    result = LDAP_INVALID_ATTRIBUTE_SYNTAX;\n"
            "    goto reply;\n"
            "}\n"
            "/* Encode value safely */\n"
            "value = ldb_binary_encode(local_ctx, req->value);\n"
            '/* Apply ACL checks like a search */\n'
            "/* acl_check against search filter on confidential attributes */"
        ),
        "class": "authorization-bypass",
        "impact": "Boolean oracle on any LDAP attribute including credential hashes — binary search recovers values.",
        "pre_auth": False,
        "requires": "Valid LDAP bind (any user)",
    },
    "CVE-2026-6949_58221": {
        "title": "Samba combined CVE patch (details in patch file)",
        "patch": "samba-4.19.4-CVE-2026-6949-58221.patch",
        "note": "Multi-CVE patch covering CVE-2026-6949 and CVE-2026-58221",
    },
}

SYSTEMD_PATCHES = {
    "package": "systemd",
    "tos_version": "TOS 4.6",
    "patches": {
        "PR_SET_MDWE_missing_args": {
            "file": "0001-core-exec-invoke-Fix-missing-arguments-for-PR_SET_ME.patch",
            "description": (
                "systemd's exec invoke path uses prctl(PR_SET_MDWE, ...) to enable "
                "Memory Deny Write Execute (MDWE) hardening for service units. "
                "The prctl() call was missing required arguments — "
                "Linux prctl with PR_SET_MDWE needs PR_MDWE_REFUSE_EXEC_GAIN as the "
                "second argument. Missing args cause prctl() to use garbage from the "
                "stack as flags, silently failing to enable MDWE protection or "
                "(worse) setting unexpected memory protection flags."
            ),
            "impact": "MDWE protection silently not enabled for service units requesting it.",
            "class": "hardening-bypass",
        },
        "wait_online": {
            "file": "0001-wait-online-by-default-not-all-interface-need-to-be-.patch",
            "description": (
                "systemd-networkd-wait-online: not all network interfaces need to be "
                "configured for the wait to complete. TOS default: wait-online completes "
                "when at least one interface is online rather than requiring all interfaces."
            ),
            "class": "config",
        },
        "ukify_genkey": {
            "file": "0001-ukify-raise-error-if-genkey-is-called-with-no-output.patch",
            "description": "ukify genkey: raise error if called with no output path (prevents silent key discard).",
            "class": "usability",
        },
        "killall_rootfs": {
            "file": "0003-shared-killall-correctly-warn-about-rootfs-daemon-s-.patch",
            "description": "killall: correct warning about rootfs daemons during shutdown.",
            "class": "correctness",
        },
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2026-58222",
        "package": "samba-4.19.4",
        "title": "LDAP CompareRequest: any-user boolean oracle on confidential attributes",
        "detail": (
            "Any authenticated LDAP user can call CompareRequest against userPassword "
            "or unicodePwd. Response (compareTrue/compareFalse) is a bit-level oracle. "
            "Binary search over character space recovers password in O(n * log(charset)) queries. "
            "No ACL check enforced before Samba 4.19.4 patched version."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2026-58222",
        "package": "samba-4.19.4",
        "title": "LDAP CompareRequest: attribute name injection into ldb filter",
        "detail": (
            "req->attribute inserted into ldb filter string without ldb_valid_attr_name() check. "
            "Attribute name '(uid=*)' or similar injects into the filter, "
            "potentially bypassing attribute scope or causing unexpected ldb behavior."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "cve": "CVE-2025-9640",
        "package": "samba-4.19.4",
        "title": "vfs_streams_xattr: stale heap data in gap bytes of sparse xattr stream writes",
        "detail": (
            "Sparse write to alternate data stream via SMB leaves heap data in gap bytes. "
            "Attacker writes to offset >> current length; subsequent read of intermediate "
            "bytes returns prior talloc heap contents."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "package": "systemd",
        "title": "PR_SET_MDWE missing args: MDWE service hardening silently not applied",
        "detail": (
            "prctl(PR_SET_MDWE, ...) called without required PR_MDWE_REFUSE_EXEC_GAIN argument. "
            "MemoryDenyWriteExecute=yes in service units silently no-ops. "
            "Services expecting MDWE protection receive none."
        ),
    },
]

if __name__ == '__main__':
    print("Samba 4.19.4 + systemd — TOS 4.6 new patches RE")
    print()
    print("Samba CVEs:")
    for cve_id, cve in SAMBA_CVES.items():
        print(f"  {cve_id}: {cve['title'][:65]}")
    print()
    print("systemd patches:")
    for k, v in SYSTEMD_PATCHES["patches"].items():
        print(f"  {k}: {v['description'][:60]}")
    print()
    for f in FINDINGS:
        cve = f"[{f.get('cve', '')}]" if f.get('cve') else "[INFO]"
        print(f"  [{f['severity']:6s}] {f['id']}: {cve} {f['title'][:60]}")
