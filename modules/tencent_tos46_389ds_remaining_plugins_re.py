"""
TencentOS 4.6 — 389-ds remaining C plugin binary survey.

Covers 12 C plugins from ds_work/usr/lib64/dirsrv/plugins/:
  libpam-passthru-plugin.so  (41KB, 232 funcs) — PAM passthrough auth
  libsyntax-plugin.so        (122KB, 413 funcs) — LDAP attribute syntax validation
  libmemberof-plugin.so      (69KB, 418 funcs) — group membership plugin
  libdna-plugin.so           (69KB, 327 funcs) — distributed numeric ID assignment
  libretrocl-plugin.so       (53KB, 287 funcs) — retro changelog
  libcontentsync-plugin.so   (53KB, 361 funcs) — RFC 4533 content sync
  libautomember-plugin.so    (53KB, 274 funcs) — automated group membership
  libmanagedentries-plugin.so(49KB, 247 funcs) — managed entries
  liblinkedattrs-plugin.so   (49KB, 287 funcs) — linked attributes
  libcos-plugin.so           (49KB, 212 funcs) — class of service
  libroles-plugin.so         (45KB, 265 funcs) — RBAC roles
  libposix-winsync-plugin.so (86KB, 499 funcs) — POSIX Windows sync

Method: endbr64 function detection → BERT semantic sweep (all-MiniLM-L6-v2) →
3 query profiles (BUF_OVF, AUTH_BYPASS, INJECT) → manual disassembly of top
candidates where score > 0.40.

Build: 389-ds-base 1.4.3.39-8 (TOS 4.6)
"""

SWEEP_RESULTS = {
    "libpam-passthru-plugin.so": {
        "size": 41984, "valid_funcs": 38,
        "max_scores": {"BUF_OVF": 0.307, "AUTH_BYPASS": 0.434, "INJECT": 0.280},
        "top_hit": {"query": "AUTH_BYPASS", "score": 0.434, "va": 0x5dc0},
        "manual_investigation": True,
    },
    "libsyntax-plugin.so": {
        "size": 124928, "valid_funcs": 207,
        "max_scores": {"BUF_OVF": 0.370, "AUTH_BYPASS": 0.189, "INJECT": 0.348},
        "top_hit": {"query": "BUF_OVF", "score": 0.370, "va": 0x8100},
        "manual_investigation": True,
    },
    "libmemberof-plugin.so": {
        "size": 70656, "valid_funcs": 54,
        "max_scores": {"BUF_OVF": 0.277, "AUTH_BYPASS": 0.124, "INJECT": 0.211},
    },
    "libdna-plugin.so": {
        "size": 70656, "valid_funcs": 31,
        "max_scores": {"BUF_OVF": 0.249, "AUTH_BYPASS": 0.114, "INJECT": 0.188},
    },
    "libretrocl-plugin.so": {
        "size": 53248, "valid_funcs": 37,
        "max_scores": {"BUF_OVF": 0.295, "AUTH_BYPASS": 0.208, "INJECT": 0.216},
    },
    "libcontentsync-plugin.so": {
        "size": 53248, "valid_funcs": 61,
        "max_scores": {"BUF_OVF": 0.358, "AUTH_BYPASS": 0.272, "INJECT": 0.285},
    },
    "libautomember-plugin.so": {
        "size": 53248, "valid_funcs": 36,
        "max_scores": {"BUF_OVF": 0.259, "AUTH_BYPASS": 0.184, "INJECT": 0.239},
    },
    "libmanagedentries-plugin.so": {
        "size": 49152, "valid_funcs": 23,
        "max_scores": {"BUF_OVF": 0.203, "AUTH_BYPASS": 0.146, "INJECT": 0.201},
    },
    "liblinkedattrs-plugin.so": {
        "size": 49152, "valid_funcs": 33,
        "max_scores": {"BUF_OVF": 0.288, "AUTH_BYPASS": 0.126, "INJECT": 0.164},
    },
    "libcos-plugin.so": {
        "size": 49152, "valid_funcs": 28,
        "max_scores": {"BUF_OVF": 0.226, "AUTH_BYPASS": 0.154, "INJECT": 0.132},
    },
    "libroles-plugin.so": {
        "size": 45056, "valid_funcs": 33,
        "max_scores": {"BUF_OVF": 0.273, "AUTH_BYPASS": 0.158, "INJECT": 0.229},
    },
    "libposix-winsync-plugin.so": {
        "size": 87040, "valid_funcs": 81,
        "max_scores": {"BUF_OVF": 0.292, "AUTH_BYPASS": 0.160, "INJECT": 0.115},
    },
}

PAM_PASSTHRU_ANALYSIS = {
    "function_va": 0x5e70,
    "role": "pam_passthru_bindpreop — pre-bind hook for PAM authentication",
    "analysis": (
        "Top BERT hit 0x5dc0 was the stub cluster before 0x5e70. The actual bind pre-op "
        "function starts at 0x5e70. Analysis of 0x5e70: "
        "(1) Calls slapi_pblock_get(pb, 0x46=SLAPI_BIND_CREDENTIALS, &creds). "
        "    If this fails: logs 'pam_passthru_bindpreop - not handled (unable to re...)' "
        "    and returns 0 (SLAPI_PLUGIN_RETURN_STOP = proceed with normal bind). "
        "(2) Calls slapi_pblock_get(pb, 0x2f=SLAPI_BIND_METHOD, &method). "
        "    If succeeds: jumps to 0x5f20 (the actual PAM call path). "
        "The fallback to return 0 when pblock get fails is NOT a bypass — "
        "SLAPI_BIND_CREDENTIALS is set by the LDAP framework before any pre-op; "
        "failure means an internal SLAPD error, not a user-controllable condition. "
        "The plugin correctly requires both credentials and method to be available "
        "before intercepting the bind."
    ),
    "verdict": "NOT_VULNERABLE — fallback returns control to normal LDAP bind, not to success",
}

SYNTAX_PLUGIN_ANALYSIS = {
    "top_hit_va": 0x8100,
    "score": 0.370,
    "analysis": (
        "0x8100 is a cluster of 4-16 byte dispatch stubs (one per LDAP syntax type). "
        "Each stub sets a syntax constant (e.g., esi=2 for Binary, ecx/edx for others) "
        "and jumps to a shared validator at 0x70a0, 0x7150, etc. "
        "These are the 'alias' entry points for each syntax's matching rule dispatch. "
        "The actual validation logic at 0x70a0+ processes pre-parsed BerVal objects "
        "(not raw bytes). No buffer copy — validation operates on already-decoded values. "
        "String OID '1.3.6.1.4.1.1466.115.121.1.26' (IA5String) and "
        "'1.3.6.1.4.1.1466.115.121.1.5' (Binary) confirm syntax types. "
        "BUF_OVF BERT score 0.370 is a semantic match on 'validate' + byte operations, "
        "not actual overflow indicators."
    ),
    "verdict": "NOT_VULNERABLE — dispatch stubs; actual validation on BerVal, not raw bytes",
}

PLUGIN_ROLES = {
    "libdna-plugin.so": (
        "Distributed Numeric Assignment: allocates unique numeric values (e.g., uidNumber) "
        "across multi-master replicas. Uses a range-based allocation scheme to avoid conflicts. "
        "Security surface: LDAP bind to allocate DNA ranges from the distributed coordinator; "
        "configuration via nsDS5*, dnaType, dnaNextValue attributes."
    ),
    "libretrocl-plugin.so": (
        "Retro Changelog: maintains an RFC 2589-compatible changelog of all directory changes. "
        "Security surface: read access to cn=changelog requires explicit ACL; "
        "historical passwords may be stored in changelog entries (password change audit)."
    ),
    "libcontentsync-plugin.so": (
        "RFC 4533 Content Sync: implements the LDAP 'Sync' control for persistent search. "
        "Security surface: sync sessions require read access to the synced subtree; "
        "cookie-based session resumption handled by the plugin."
    ),
    "libautomember-plugin.so": (
        "Auto-member: automatically adds entries to groups based on configurable rules. "
        "Security surface: incorrect rule configuration could auto-add users to privileged groups."
    ),
    "libmanagedentries-plugin.so": (
        "Managed Entries: creates and maintains 'managed' entries when 'origin' entries "
        "are added/modified/deleted. Template-based entry creation in configurable subtrees."
    ),
    "liblinkedattrs-plugin.so": (
        "Linked Attributes: maintains bidirectional attribute links (e.g., manager/directReports). "
        "Security surface: write to one side of a link modifies the other side — "
        "requires correct ACL on both linked entries."
    ),
    "libcos-plugin.so": (
        "Class of Service: dynamically generates virtual attribute values from CoS templates. "
        "Security surface: CoS-generated values can override real attribute values "
        "depending on CoS priority and type (indirect vs. classic vs. pointer)."
    ),
    "libroles-plugin.so": (
        "RBAC Roles: implements nsRoleDN and nsSimpleRoleDefinition for role-based access. "
        "Security surface: role membership checked by ACL plugin for access decisions; "
        "role definitions must be properly protected from unauthorized modification."
    ),
    "libposix-winsync-plugin.so": (
        "POSIX Windows Sync: synchronizes POSIX attributes (uid/gid numbers) alongside "
        "Windows AD synchronization. POSIX UID/GID values sourced from AD attributes. "
        "Security surface: ID collision between synced and local POSIX users."
    ),
    "libmemberof-plugin.so": (
        "MemberOf: maintains the memberOf attribute on entries when they are added to or "
        "removed from groups. Ensures group membership is reflectable from the user side. "
        "Security surface: memberOf is set by the server, not by users — tampering requires "
        "write access to the group's member attribute."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "pam-passthru bind pre-op: fallback on pblock failure returns 0 (not a bypass)",
        "detail": (
            "pam_passthru_bindpreop @ 0x5e70: returns 0 when SLAPI_BIND_CREDENTIALS unavailable. "
            "In LDAP pre-op context, SLAPI_BIND_CREDENTIALS is set by framework (not user-controlled). "
            "Failure returns control to normal LDAP bind — not a bypass path."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "libsyntax-plugin.so: dispatch stubs only — BUF_OVF score 0.370 is semantic FP",
        "detail": (
            "0x8100 cluster: 4-16 byte stubs that set syntax constants and jump to shared validators. "
            "Validation operates on pre-parsed BerVal objects, not raw bytes. No buffer copy surface."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "12 C plugins swept: all BERT scores below 0.40 — no HIGH-confidence patterns",
        "detail": (
            "3-query BERT sweep (BUF_OVF, AUTH_BYPASS, INJECT) across 12 plugins. "
            "Max scores: libpam-passthru AUTH_BYPASS=0.434 (investigated, not bypass), "
            "libsyntax BUF_OVF=0.370 (investigated, FP), libcontentsync BUF_OVF=0.358. "
            "All remaining ≤0.295. No standalone findings."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "libretrocl: historical passwords potentially in changelog — access control dependency",
        "detail": (
            "Retro changelog entries for password modification operations may include "
            "previous userPassword values. cn=changelog ACL must restrict read access "
            "to directory admins only. Security is configuration-dependent, not a binary bug."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 389-ds remaining C plugins binary survey")
    print()
    print(f"{'Plugin':<36} {'Funcs':>6} {'BUF_OVF':>8} {'AUTH':>8} {'INJECT':>8}")
    for name, d in SWEEP_RESULTS.items():
        s = d['max_scores']
        marker = ' ← investigated' if d.get('manual_investigation') else ''
        print(f"  {name:<34} {d['valid_funcs']:>6} {s['BUF_OVF']:>8.3f} {s['AUTH_BYPASS']:>8.3f} {s['INJECT']:>8.3f}{marker}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
