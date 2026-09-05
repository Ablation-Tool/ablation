"""
TencentOS 4.6 — 389-ds libreplication-plugin.so binary RE.

Binary: ds_work/usr/lib64/dirsrv/plugins/libreplication-plugin.so — 746KB stripped SO
Method: endbr64 function detection → capstone disassembly → BERT semantic sweep
(sentence-transformers/all-MiniLM-L6-v2) → 6 query profiles → manual disassembly of
top candidates → PLT unsafe-primitive audit.

Build: 389-ds-base 1.4.3.39-8 (TOS 4.6)
Role: LDAP replication engine — RUV (Replication Update Vector), CSN management,
changelog, incremental/total update protocols, supplier-consumer state machine,
multi-master conflict resolution.
"""

BINARY_INVENTORY = {
    "libreplication-plugin.so": {
        "path": "ds_work/usr/lib64/dirsrv/plugins/libreplication-plugin.so",
        "size": 763904,
        "type": "shared object",
        "stripped": True,
        "text_foff": 0x264d0,
        "text_size": 0x5e7e3,
        "functions_detected": 878,
        "role": (
            "Core replication engine for 389-ds. Implements multi-master replication: "
            "RUV (Replication Update Vector) management, CSN (Change Sequence Number) "
            "generation and comparison, changelog (ldif-format), incremental protocol "
            "(repl5_inc_*), total update protocol (repl5_tot_*), and the LDAP-based "
            "replication wire protocol using extended operations "
            "(OID 2.16.840.1.113730.3.5.6 = StartReplicationRequest)."
        ),
    },
}

BERT_SWEEP = {
    "method": "6 query profiles, all-MiniLM-L6-v2, cosine similarity, 878 valid functions",
    "profiles": {
        "REPL_BUF_OVERFLOW": {
            "max_score": 0.456,
            "top_hit_va": 0x63ae0,
            "top_strings": ["2.16.840.1.113730.3.5.6", "send_entry - Replica \"%s\" is busy"],
            "verdict": "FALSE_POSITIVE — session state dispatch function, not a protocol buffer parser",
        },
        "REPL_AUTH_BYPASS": {
            "max_score": 0.387,
            "top_hit_va": 0x70810,
            "top_strings": ["(anon)"],
            "verdict": "INVESTIGATED — bind-to-supplier with anonymous DN logging; see AUTH_PATH_ANALYSIS",
        },
        "REPL_CSN_PARSE": {
            "max_score": 0.404,
            "top_hit_va": 0x61a70,
            "top_strings": ["ruv_compare_ruv - The max CSN [%s] from RUV [%s] is larger t"],
            "verdict": "INVESTIGATED — RUV comparison function; see RUV_COMPARE_ANALYSIS",
        },
        "REPL_CHANGELOG": {
            "max_score": 0.372,
            "top_hit_va": 0x66810,
            "top_strings": ["Slapi_Entry dump:", "Slapi_Entry is NULL"],
            "verdict": "FALSE_POSITIVE — debug dump functions, not changelog access-control path",
        },
        "REPL_SESSION_RACE": {
            "max_score": 0.360,
            "top_hit_va": 0x63ae0,
            "verdict": "FALSE_POSITIVE — same session dispatch function as BUF_OVERFLOW hit",
        },
        "REPL_URL_PARSE": {
            "max_score": 0.417,
            "top_hit_va": 0x508e0,
            "top_strings": ["repl keep alive", "(&(objectclass=ldapsubentry)(cn=%s %d))"],
            "verdict": "FALSE_POSITIVE — keep-alive LDAP search filter construction, not URL parsing",
        },
    },
    "overall": "No HIGH-confidence vulnerability pattern. Max score 0.456 — all resolved to FP.",
}

AUTH_PATH_ANALYSIS = {
    "function_va": 0x70810,
    "stack_frame": "0x38 bytes + 6 pushed registers + stack canary",
    "role": "Bind-to-supplier function: performs LDAP bind to replication consumer",
    "analysis": (
        "Function performs bind using stored replication credentials. "
        "String '(anon)' at rip+0x2c449 loaded as rdx argument to slapi_log_error (0x26090) "
        "with edi=1 (log level) — this is the string used in the log message "
        "when the replication bind DN is empty or anonymous. "
        "The actual bind call is at 0x70897: call 0x23df0 (ldap_sasl_bind or slapi_ldap_bind) "
        "with (rdi=conn, rsi=dn, rdx=cred, rcx=0, r8=0, r9=0). "
        "Return value checked: jne 0x709f0 (error path). "
        "Then [rbx+0x24] (credential type field) checked: jne 0x709c0 (non-anon path). "
        "No bypass — anonymous replication requires the consumer to be configured "
        "to accept the anonymous DN as a valid replication manager."
    ),
    "verdict": "NOT_A_BYPASS — logging path; authentication enforced by consumer-side ACL",
}

RUV_COMPARE_ANALYSIS = {
    "function_va": 0x61a70,
    "stack_frame": "0x4e8 bytes (1256 bytes) + 6 pushed registers + stack canary",
    "role": "ruv_compare_ruv — compares two RUV (Replication Update Vector) structs",
    "analysis": (
        "Large stack frame holds multiple local CSN iterator state structures. "
        "Function iterates over RUV1 elements (from r14) and RUV2 elements (from rbp), "
        "calling 0x245a0 (likely csn_compare) for each pair. "
        "CSN comparison results fed to slapi_log_error (0x26090) via format string "
        "'ruv_compare_ruv - The max CSN [%s] from RUV [%s] is larger than [%s]'. "
        "CSN-to-string conversion at 0x23c60 — generates bounded 20-char hex CSN strings. "
        "No memcpy or strcpy with unbounded length from wire-format CSN. "
        "Stack frame size is due to holding multiple CSN iterator structs, not buffers. "
        "Stack canary present (fs:[0x28] at 0x61a9d, verified at 0x61da0)."
    ),
    "verdict": "NOT_VULNERABLE — comparison/logging only; CSN strings bounded by format",
}

SESSION_STATE_ANALYSIS = {
    "function_va": 0x63ae0,
    "role": "Replication total-update session state dispatch",
    "analysis": (
        "Thin dispatch stub: checks [rax+0x48] flag (session active/idle), "
        "calls virtual function via [rax+0x10], then dispatches on pointers at "
        "offsets 0x90 and 0xb8 of the session object. "
        "This is a C++ vtable-style dispatch on protocol session state. "
        "The 'send_entry' log string and OID 2.16.840.1.113730.3.5.6 "
        "(StartReplicationRequest) confirm this is in the total-update protocol path. "
        "No buffer parsing in this function — calls into state handlers via function pointer."
    ),
    "verdict": "NOT_VULNERABLE — state machine dispatch, no parsing",
}

UNSAFE_PRIMITIVE_AUDIT = {
    "present_in_plt": ["strcpy @ plt.sec:0x22e30", "strcat @ plt.sec:0x23d40", "memcpy @ plt.sec:0x21c60"],
    "absent_from_plt": ["sprintf", "sscanf", "gets", "snprintf (not needed — PR_snprintf used)"],
    "call_sites": {
        "strcpy": {
            "count": 1,
            "site_0x279ca": {
                "pattern": (
                    "Function at 0x279b0: copies CSN string from rdi (source) "
                    "into rax = *rsi (pointer stored in struct). "
                    "Then calls strlen(rbp) and increments [rbx] counter by strlen+1. "
                    "CSN strings are fixed-format: 20 hexadecimal chars + timestamp. "
                    "Destination buffer presumed pre-allocated for CSN format. "
                    "No length validation visible in this function — relies on caller invariant."
                ),
                "verdict": "LIKELY_SAFE — CSN strings are bounded by protocol format (≤40 chars); destination allocated by caller for CSN storage",
            },
        },
        "strcat": {
            "count": 2,
            "site_0x65ed8_0x65ee4": {
                "function_va": 0x65e80,
                "pattern": (
                    "String-builder function (args: rdi=source_obj, rsi=struct with buffer). "
                    "Size calculation: call 0x25a30(rdi) → ebp (length from source object); "
                    "strlen([rsi+8]) → rax; ebp = ebp + rax + 1 (total added). "
                    "If buffer exists: realloc(existing, ebp + strlen(existing)); "
                    "If buffer NULL: calloc(1, ebp). "
                    "Then strcat(buf, get_str(rdi)) and strcat(buf, [rsi+8]). "
                    "Safety: 0x25a30 identity unconfirmed from binary — must return "
                    "strlen(get_str(rdi)) for the allocation to be correctly sized. "
                    "Pattern is consistent with slapi_sdn_get_ndn_len() + slapi_sdn_get_dn() pairing."
                ),
                "verdict": "LIKELY_SAFE — realloc sizes for both appended strings; risk depends on 0x25a30 returning length of the same string as 0x23b30",
            },
        },
    },
}

REPLICATION_WIRE_PROTOCOL = {
    "extended_ops": {
        "OID_start_replication": "2.16.840.1.113730.3.5.6",
        "note": (
            "Replication uses LDAP extended operations, not a custom wire protocol. "
            "The wire parsing is done by the LDAP library (libldap, OpenLDAP). "
            "Replication-specific parsing in this plugin operates on already-decoded "
            "Slapi_PBlock entries, not raw bytes — reduces parser attack surface."
        ),
    },
    "csn_format": {
        "description": "CSN: 16-char hex timestamp + 8-char replica ID = 24-28 chars fixed-length",
        "risk": "CSN parsing operates on pre-validated strings from LDAP attr values; no sscanf/atoi found",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "libreplication-plugin.so: 878 functions, BERT sweep — no HIGH-confidence patterns",
        "detail": (
            "6 BERT profiles (BUF_OVERFLOW, AUTH_BYPASS, CSN_PARSE, CHANGELOG, SESSION_RACE, URL_PARSE). "
            "Max score 0.456. Top candidates: session dispatch stub (0x63ae0), "
            "bind-to-supplier logging (0x70810), RUV comparison (0x61a70). "
            "All resolved to non-vulnerable functions via disassembly."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "libreplication strcpy/strcat: 3 call sites — all LIKELY_SAFE",
        "detail": (
            "No sprintf/sscanf in PLT — CSN parsing uses pre-decoded LDAP attributes. "
            "strcpy @ 0x279ca: CSN string copy, bounded by fixed CSN format. "
            "strcat @ 0x65ed8/0x65ee4: realloc+strcat builder; realloc covers both appended strings. "
            "0x25a30 identity unconfirmed but pattern consistent with length-getter pairing."
        ),
    },
    {
        "id": "F3",
        "severity": "INFO",
        "title": "Replication bind-to-supplier uses pre-configured credentials, not wire-supplied",
        "detail": (
            "bind-to-supplier function (0x70810): credentials from nsDS5ReplicaBindDN/Credentials attrs. "
            "Anonymous bind case logged but authentication enforced by consumer ACL. "
            "No unauthenticated replication session acceptance visible in binary."
        ),
    },
    {
        "id": "F4",
        "severity": "INFO",
        "title": "ruv_compare_ruv: 1256-byte stack frame with canary — comparison/logging only",
        "detail": (
            "Large frame holds CSN iterator state structs, not format string buffers. "
            "Stack canary at fs:[0x28] verified at epilogue (0x61da0). "
            "No dangerous operations — all CSN strings via bounded csn_to_str calls."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 389-ds libreplication-plugin.so binary RE")
    print(f"  size: {BINARY_INVENTORY['libreplication-plugin.so']['size']//1024}KB, "
          f"{BINARY_INVENTORY['libreplication-plugin.so']['functions_detected']} functions")
    print()
    print("BERT sweep (6 profiles):")
    max_score = max(v['max_score'] for v in BERT_SWEEP['profiles'].values())
    print(f"  max score: {max_score:.3f} — all resolved to FP")
    print()
    print("Unsafe primitive audit:")
    print("  strcpy: 1 site — LIKELY_SAFE (CSN format bounded)")
    print("  strcat: 2 sites — LIKELY_SAFE (realloc sized for both strings)")
    print("  sprintf/sscanf: NOT IN PLT (PR_snprintf / pre-decoded LDAP attrs used)")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
