"""
TencentOS 4.6 — Cyrus IMAP 3.4.8 patch stack RE.

Package: cyrus-imapd-3.4.8-5.tl4
Source: scratchpad/cyrus-46-re/
Patches: 5 TOS-specific patches (Patch3000-3004)

Context: TOS upgraded from cyrus-imapd 3.0.x (TOS 3.1) to 3.4.8 specifically for
CVE-2024-34055 (busylist DoS via crafted APPEND). TOS 3.1 RE is in
tencent_tos31_appstream_cyrus_imapd_re.py; this module covers the 3.4.8 TOS-specific
patch additions.

Notable: no new CVE patches in the TOS 4.6 stack beyond what 3.4.8 ships upstream.
The 5 patches are packaging and bug fixes.
"""

PACKAGE_METADATA = {
    "name": "cyrus-imapd",
    "version": "3.4.8",
    "release": "5.tl4",
    "tos_version": "TOS 4.6",
    "tos31_version": "3.0.x (prior; upgraded for CVE-2024-34055)",
    "spec": "scratchpad/cyrus-46-re/cyrus-imapd.spec",
}

TOS_PATCHES = {
    "Patch3000": {
        "file": "patch-cyrus-testsuite-timeout",
        "description": "Extend test suite timeout values for TOS build environment.",
        "class": "packaging",
        "security_relevant": False,
    },
    "Patch3001": {
        "file": "patch-cyrus-default-configs",
        "description": (
            "TOS default configuration values for cyrus-imapd. "
            "Adjusts default paths and service settings for TOS filesystem layout."
        ),
        "class": "config",
        "security_relevant": False,
    },
    "Patch3002": {
        "file": "patch-cyrus-rename-quota",
        "description": (
            "Renames 'quota' binary reference to 'cyr_quota' in cmd_reconstruct() "
            "in imap/imapd.c. The binary was renamed in 3.x upstream. "
            "Code: snprintf(buf, sizeof(buf), \"%s/quota\", SBIN_DIR) "
            "→ snprintf(buf, sizeof(buf), \"%s/cyr_quota\", SBIN_DIR). "
            "Prevents cmd_reconstruct from exec'ing the wrong binary name."
        ),
        "file_affected": "imap/imapd.c",
        "class": "correctness",
        "security_relevant": False,
    },
    "Patch3003": {
        "file": "patch-cyrus-perl-linking",
        "description": (
            "Perl linking fix for TOS build environment. Adjusts linker flags "
            "for Perl shared library linkage in cyrus-imapd Perl bindings."
        ),
        "class": "build-compat",
        "security_relevant": False,
    },
    "Patch3004": {
        "file": "patch-cyrus-squatter-assert-crash",
        "description": (
            "NULL dereference fix in squatter (search indexer). "
            "In imap/squatter.c:expand_mboxnames(), mboxname_from_external() can return "
            "NULL for an invalid or empty mailbox name. The original code passed the "
            "potentially-NULL intname directly to mboxlist_mboxtree(), causing a crash "
            "when squatter processed an invalid mailbox name with -r (recursive) flag. "
            "Fix: adds NULL check and empty-string check on intname before calling "
            "mboxlist_mboxtree(); prints an error to stderr instead of crashing. "
            "Vulnerable code: "
            "  char *intname = mboxname_from_external(mboxnames[i], &squat_namespace, NULL); "
            "  int flags = recursive_flag ? 0 : MBOXTREE_SKIP_CHILDREN; "
            "  mboxlist_mboxtree(intname, addmbox, sa, flags);   /* NULL deref if intname=NULL */ "
            "Fixed code adds: "
            "  if (!intname || *intname == '\\0') { fprintf(stderr, ...); } else { ... }"
        ),
        "file_affected": "imap/squatter.c",
        "function_affected": "expand_mboxnames",
        "class": "null-deref",
        "security_relevant": True,
        "severity": "LOW",
        "pre_auth": False,
        "local_only": True,
        "notes": (
            "squatter is typically run as a scheduled job with mailbox access. "
            "A user who can name their mailbox with special characters that cause "
            "mboxname_from_external() to return NULL can crash the squatter process. "
            "Denial of service against search indexing. Not exploitable for code exec."
        ),
    },
}

UPSTREAM_CVE_CONTEXT = {
    "CVE-2024-34055": {
        "title": "Cyrus IMAP busylist DoS via APPEND command",
        "reason_for_upgrade": (
            "TOS 3.1 ran Cyrus 3.0.x. CVE-2024-34055 requires 3.4.7+ to fix. "
            "TOS upgraded to 3.4.8 in TOS 4.6 specifically for this CVE. "
            "Documented in tencent_tos31_appstream_cyrus_imapd_re.py."
        ),
        "fixed_in": "3.4.7",
        "tos46_status": "FIXED (3.4.8 ships the fix)",
    },
}

CASSANDANE_PATCHES = {
    "description": (
        "Three additional patches in cyrus-46-re/ target the Cassandane test suite "
        "(cyrus-imapd's Perl-based integration test framework). These are test-only "
        "patches with no production binary impact."
    ),
    "patches": [
        "patch-cassandane-fix-annotator — fix annotation test",
        "patch-cassandane-no-syslog — suppress syslog in test output",
        "patch-cassandane-xapian-delve-path — fix xapian-delve path in tests",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "LOW",
        "title": "squatter NULL deref via invalid mailbox name — search indexer crash",
        "detail": (
            "mboxname_from_external() returns NULL for malformed mailbox names. "
            "squatter.c:expand_mboxnames() passed NULL to mboxlist_mboxtree() without check. "
            "User with access to create mailboxes can crash the squatter scheduled job. "
            "DoS against search indexing — no code execution. Fixed in Patch3004."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "cyr_quota rename: cmd_reconstruct exec'd wrong binary name pre-patch",
        "detail": (
            "cmd_reconstruct built path as SBIN_DIR/quota; upstream renamed to cyr_quota. "
            "On a system where 'quota' refers to the disk quota tool, cmd_reconstruct "
            "would exec the wrong binary. Patch3002 corrects to cyr_quota."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "TOS 4.6 Cyrus 3.4.8: no new CVE patches — upgrade from 3.0.x captures upstream fixes",
        "detail": (
            "5 TOS-specific patches are all non-CVE (packaging, config, bug fixes). "
            "Security improvement over TOS 3.1 comes from the 3.0.x→3.4.8 version jump "
            "itself (CVE-2024-34055 + other upstream 3.x security fixes). "
            "Tencent has NOT applied additional out-of-band CVE patches to 3.4.8 beyond "
            "what upstream ships."
        ),
    },
]

if __name__ == '__main__':
    print("Cyrus IMAP 3.4.8 TOS 4.6 patch stack RE")
    print(f"  version: {PACKAGE_METADATA['version']}-{PACKAGE_METADATA['release']}")
    print(f"  prior: {PACKAGE_METADATA['tos31_version']}")
    print()
    print("TOS patches:")
    for pid, patch in TOS_PATCHES.items():
        sec = " [SECURITY]" if patch['security_relevant'] else ""
        print(f"  {pid} ({patch['class']}){sec}: {patch['description'][:60]}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
