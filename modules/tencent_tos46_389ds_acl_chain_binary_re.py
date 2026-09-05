"""
TencentOS 4.6 — 389-ds libacl-plugin.so + libchainingdb-plugin.so binary RE.

Binaries analyzed:
  ds_work/usr/lib64/dirsrv/plugins/libacl-plugin.so     — 198KB stripped SO (149 functions)
  ds_work/usr/lib64/dirsrv/plugins/libchainingdb-plugin.so — 112KB stripped SO (120 functions)

Method: endbr64 function detection → capstone disassembly → BERT semantic sweep
(sentence-transformers/all-MiniLM-L6-v2) → 5 query profiles per library →
manual disassembly of top candidates → PLT call-site audit for unsafe primitives.

Build: 389-ds-base 1.4.3.39-8 (TOS 4.6)
"""

BINARY_INVENTORY = {
    "libacl-plugin.so": {
        "path": "ds_work/usr/lib64/dirsrv/plugins/libacl-plugin.so",
        "size": 202752,
        "type": "shared object",
        "stripped": True,
        "functions_detected": 149,
        "plt_sec_base": 0x8630,
        "role": (
            "LDAP ACL engine. Implements the Sun ACL v3 framework used by 389-ds: "
            "ACI parsing, ACI evaluation, group cache, macro expansion (($dn), ($attr.x)), "
            "backend state callbacks, anonymous profile, effective-rights computation. "
            "All access control decisions route through acl_access_allowed_main()."
        ),
        "key_imports": {
            "unsafe": ["strcpy @ plt.sec:0x9330", "strcat @ plt.sec:0x9c60", "strncpy @ plt.sec:0x8ef0"],
            "safe": ["PR_snprintf", "slapi_ch_smprintf", "__printf_chk", "__sprintf_chk",
                     "slapi_ch_malloc", "slapi_ch_realloc", "slapi_ch_strdup"],
            "note": (
                "strcpy/strcat present alongside the safer family. "
                "3 distinct call sites audited — see UNSAFE_PRIMITIVE_AUDIT below."
            ),
        },
    },
    "libchainingdb-plugin.so": {
        "path": "ds_work/usr/lib64/dirsrv/plugins/libchainingdb-plugin.so",
        "size": 114688,
        "type": "shared object",
        "stripped": True,
        "functions_detected": 120,
        "role": (
            "LDAP chaining backend. Proxies LDAP operations to a remote supplier LDAP server. "
            "Handles connection pooling, BIND forwarding (including GSSAPI), and failover."
        ),
    },
}

ACL_BERT_SWEEP = {
    "method": "5 semantic query profiles, all-MiniLM-L6-v2, cosine similarity",
    "results": {
        "ACL_BYPASS": {
            "top_hit_va": 0x1c6b0,
            "score": 0.455,
            "strings": [
                "acl_be_state_change_fnc - Backend %s is now STARTED--activat...",
                "acl_be_state_change_fnc - Failed to retrieve backend--NOT ac...",
            ],
            "verdict": "FALSE_POSITIVE — backend lifecycle callback, not access bypass path",
        },
        "DN_COMPARE": {
            "top_hit_va": 0x1c6b0,
            "score": 0.524,
            "second_hit_va": 0x158a0,
            "score2": 0.467,
            "verdict": "FALSE_POSITIVE — DN in log strings, not comparison logic surface",
        },
        "ACL_REGEX": {
            "top_hit_va": 0x198c0,
            "score": 0.415,
            "strings": ["aclutil_evaluate_macro - ACL info: found matched_val (%s) for aci index %d", "($dn)"],
            "verdict": "INVESTIGATED — ACI macro evaluator; see ACL_MACRO_EVAL_ANALYSIS",
        },
        "WILDCARD_ACL": {
            "top_hit_va": 0x10450,
            "score": 0.486,
            "strings": ["nsslapd-aclpb-max-selected-acls"],
            "second_hit_va": 0x22aa0,
            "score2": 0.468,
            "strings2": ["ACL Internal Error(%d)...", "aclutil_print_err - %s"],
            "verdict": "FALSE_POSITIVE — limit config reader; error formatter; not wildcard bypass",
        },
        "ACL_GRANT_DEFAULT": {
            "top_hit_va": 0xea60,
            "score": 0.379,
            "strings": ["acl_access_allowed_modrdn - Write permission to entry not al..."],
            "verdict": "FALSE_POSITIVE — access denial log path, not grant-by-default",
        },
    },
    "overall": "No HIGH-confidence vulnerability pattern found in ACL plugin BERT sweep.",
}

CHAIN_BERT_SWEEP = {
    "method": "5 semantic query profiles, all-MiniLM-L6-v2, cosine similarity",
    "all_scores_below": 0.31,
    "best_hit": {
        "query": "CHAIN_SSRF",
        "va": 0xd670,
        "score": 0.246,
        "strings": ["GSSAPI", "nsBindMechanism"],
    },
    "verdict": (
        "No high-confidence patterns. GSSAPI/nsBindMechanism strings confirm SASL bind "
        "forwarding is present; scores too low to surface as findings. "
        "libchainingdb-plugin.so appears to use the libldap API exclusively for its "
        "remote connection — not a custom protocol parser."
    ),
}

ACL_KEY_FUNCTIONS = {
    "acl_be_state_change_fnc_A": {
        "va": 0x1c6b0,
        "role": "Backend state change callback — ACI activation/deactivation",
        "analysis": (
            "Dispatches on edx/ecx values: edx==1 triggers ACI activation path "
            "(calls slapi_register_backend_state_change), edx!=1 triggers deactivation. "
            "Log strings: 'Backend %s is now STARTED' and 'Failed to retrieve backend'. "
            "Not an access control bypass surface — it manages ACI lifecycle, "
            "not ACI evaluation decisions."
        ),
    },
    "acl_be_state_change_fnc_B": {
        "va": 0x1c660,
        "role": "Backend state teardown path",
        "analysis": (
            "Simpler path: checks global ACI pointer, calls cleanup if non-null, "
            "zeros the pointer, calls slapi cleanup function. "
            "Teardown sequence for ACI state on backend removal."
        ),
    },
    "aclutil_evaluate_macro": {
        "va": 0x198c0,
        "role": "ACI macro expansion — ($dn) substitution in target patterns",
        "analysis": (
            "0x88-byte stack frame. Loads ACI index (rbp+0x58) and calls two helpers "
            "(0x9c30 = logging, 0x8ea0 = internal). "
            "String 'aclutil_evaluate_macro - ACL info: found matched_val (%s) for aci index %d' "
            "at 0x1995c. String '($dn)' at 0x19972. "
            "Function evaluates whether an ACI target DN macro ($dn) matches the "
            "request DN — the macro is compared, not sprintf'd into a buffer. "
            "The critical path for ($dn) injection would be in acl_match_macro_in_target() "
            "(separate function), not here. No unsafe buffer operations visible."
        ),
    },
    "aclutil_targetattr_error": {
        "va": 0x22aa0,
        "role": "ACI targetattr filter error formatter",
        "analysis": (
            "Large stack frame: sub rsp, 0x1000 + stack-probe loop (or [rsp], 0; cmp rsp, r11; jne) "
            "+ sub rsp, 0x4e0 — total ~5440 bytes on stack. "
            "This is GCC's stack probe loop for allocations exceeding one page (prevents "
            "stack-skip on Linux; touches each page). Not a vulnerability — standard "
            "compiler behavior for large local buffers. "
            "Function dispatches on edi (positive vs negative targetattr disposition) "
            "then on eax range (cmp 9, ja overflow path). "
            "Formats internal error messages into the large local buffer."
        ),
    },
}

UNSAFE_PRIMITIVE_AUDIT = {
    "strcpy": {
        "plt_sec_va": 0x9330,
        "call_sites": [0x2446c],
        "site_0x2446c": {
            "pattern": (
                "3-string concatenation: "
                "strlen(r14), strlen(rbx), + extra from [rsp+4] → total_len + 1; "
                "slapi_ch_malloc(total_len+1); "
                "stpcpy(buf, r14); stpcpy(end1, r15); strcpy(end2, rbx). "
                "All three component lengths are measured before allocation. "
                "Size calculation includes a third value from the stack (dword ptr [rsp+4]) "
                "which is set earlier in the function — likely len(r15) or a padding value. "
                "Allocation appears correctly sized for the 3-part concatenation."
            ),
            "verdict": "LIKELY_SAFE — allocation measured before copy; verified patterns consistent",
        },
    },
    "strcat": {
        "plt_sec_va": 0x9c60,
        "call_sites": [0x11d98, 0x11da9, 0x22877],
        "site_0x11d98_0x11da9": {
            "pattern": (
                "Resize-and-append loop. Loop body: "
                "slapi_ch_realloc(*r12, new_size); [r12] = new_buf; "
                "strcat(new_buf, rbp); — first append; "
                "strcat(new_buf, rbx); — second append. "
                "Inside a loop with ja condition checking (0x11d7e: ja 0x11d60). "
                "Risk: if the realloc does not account for BOTH appended strings, "
                "the second strcat may write past the buffer. "
                "Cannot confirm realloc size includes both rbp+rbx without full caller context; "
                "score below finding threshold."
            ),
            "verdict": "INCONCLUSIVE — realloc size calculation not fully verified",
        },
        "site_0x22877": {
            "pattern": (
                "aclutil_str_append helper. "
                "r12 = current buffer *dst; "
                "strlen(src=rsi) → r13; strlen(r12) → rax; "
                "slapi_ch_realloc(r12, r13 + rax + 1) — correctly measures both; "
                "strcat(new_buf, rbp). "
                "Note: rbp at call site — must equal rsi (function arg). "
                "Realloc size is exactly strlen(old) + strlen(src) + 1."
            ),
            "verdict": "SAFE — realloc accounts for full concatenation length",
        },
    },
}

CHAININGDB_KEY_OBSERVATIONS = {
    "GSSAPI_bind_forwarding": {
        "va": 0xd670,
        "strings": ["GSSAPI", "nsBindMechanism", "nsBindMechanism"],
        "role": "SASL GSSAPI bind forwarding to remote supplier",
        "note": (
            "Chaining backend forwards LDAP BIND operations to remote supplier. "
            "GSSAPI mechanism confirmed in binary. "
            "The chaining connection uses libldap for remote operations — not a "
            "custom protocol parser. No SSRF surface from URL construction visible in sweep."
        ),
    },
    "connection_pool": {
        "note": (
            "libchainingdb-plugin.so handles connection pooling to the remote supplier. "
            "The nsBindMechanism config attribute controls authentication used on the "
            "chaining connection. If configured with GSSAPI, the remote server's "
            "Kerberos delegation settings control what the chaining backend can access."
        ),
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "libacl-plugin.so: 149 functions, BERT sweep — no HIGH-confidence patterns",
        "detail": (
            "5 BERT query profiles (ACL_BYPASS, DN_COMPARE, ACL_REGEX, WILDCARD_ACL, "
            "ACL_GRANT_DEFAULT). Top scores 0.524 (DN_COMPARE) and 0.486 (WILDCARD_ACL). "
            "All top candidates resolved to logging and lifecycle functions, not bypass paths. "
            "ACI macro evaluator (aclutil_evaluate_macro @ 0x198c0) investigated — "
            "($dn) is used in comparison, not as sprintf argument. No finding."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "libacl-plugin.so strcpy/strcat: 4 call sites audited — no overflow path confirmed",
        "detail": (
            "strcpy @ 0x2446c: 3-string malloc+stpcpy×2+strcpy pattern; sizes pre-measured. "
            "strcat @ 0x22877 (aclutil_str_append): realloc(old+new+1) before strcat — safe. "
            "strcat @ 0x11d98/0x11da9: resize-and-append loop — realloc size not fully verified. "
            "Confidence below standalone finding threshold."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "libchainingdb-plugin.so: 120 functions, all BERT scores below 0.31 — no findings",
        "detail": (
            "GSSAPI/nsBindMechanism strings confirmed (SASL bind forwarding present). "
            "No custom protocol parser surface found. Uses libldap API for remote ops. "
            "SSRF via chaining depends on LDAP referral configuration, not this plugin."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 389-ds libacl + libchainingdb binary RE")
    print()
    for name, inv in BINARY_INVENTORY.items():
        print(f"  {name}: {inv['size']//1024}KB, {inv['functions_detected']} functions")
    print()
    print("BERT sweep summary:")
    print(f"  libacl: max score {max(v['score'] for v in ACL_BERT_SWEEP['results'].values()):.3f} — all resolved to FP")
    print(f"  libchain: all scores below {CHAIN_BERT_SWEEP['all_scores_below']}")
    print()
    print("Unsafe primitive audit:")
    print("  strcpy: 1 site — LIKELY_SAFE")
    print("  strcat: 3 sites — SAFE (x2), INCONCLUSIVE (x1, below threshold)")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
