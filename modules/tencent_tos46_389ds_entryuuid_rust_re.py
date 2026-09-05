"""
TencentOS 4.6 — 389-ds libentryuuid-plugin.so + libentryuuid-syntax-plugin.so RE.

Binaries: ds_work/usr/lib64/dirsrv/plugins/libentryuuid-plugin.so (1.3MB Rust)
          ds_work/usr/lib64/dirsrv/plugins/libentryuuid-syntax-plugin.so (1.3MB Rust)

Both are Rust plugins using the Tencent-written `slapi_r_plugin` crate (same crate
as libpwdchan-plugin.so). Not in upstream 389-ds 1.4.x — TOS-exclusive.

Build: 389-ds-base 1.4.3.39-8 (TOS 4.6)
"""

BINARY_INVENTORY = {
    "libentryuuid-plugin.so": {
        "path": "ds_work/usr/lib64/dirsrv/plugins/libentryuuid-plugin.so",
        "size": 1327104,
        "type": "shared object (Rust)",
        "c_entry_points": 9,
        "role": (
            "Operational plugin: generates and manages the entryUUID operational attribute. "
            "Registers betxn_pre_add (generates UUID v4 on new entry creation) and "
            "betxn_pre_modify (validates UUID on modify). Implements a fixup task to "
            "backfill entryUUID on existing entries."
        ),
    },
    "libentryuuid-syntax-plugin.so": {
        "path": "ds_work/usr/lib64/dirsrv/plugins/libentryuuid-syntax-plugin.so",
        "size": 1327104,
        "type": "shared object (Rust)",
        "c_entry_points": 9,
        "role": (
            "Syntax plugin: validates and indexes the entryUUID attribute. "
            "Implements SlapiSyntaxPlugin1, SlapiOrdMr (ordering matching rule), "
            "and equality matching rule (eq_mr) for UUID-typed attributes."
        ),
    },
}

ENTRYUUID_PLUGIN_ARCHITECTURE = {
    "uuid_generation": {
        "function": "uuid::v4::new_v4",
        "description": (
            "Generates RFC 4122 version 4 random UUID on each betxn_pre_add hook. "
            "Uses the Rust `uuid` crate v4 generator, which calls getrandom(2) internally "
            "for cryptographic randomness. UUID stored as the LDAP operational attribute "
            "entryUUID (OID 1.3.6.1.1.16.4)."
        ),
        "crypto_random": "getrandom(2) via uuid crate — CSPRNG quality",
    },
    "c_entry_points": [
        "entryuuid_plugin_init",
        "entryuuid_fixup_cb",
        "entryuuid_plugin_betxn_pre_add (→ Rust: entryuuid::entryuuid_plugin_betxn_pre_add)",
        "entryuuid_plugin_betxn_pre_modify (→ Rust: entryuuid::entryuuid_plugin_betxn_pre_modify)",
        "entryuuid_plugin_start (→ Rust: EntryUuid::start)",
        "entryuuid_plugin_close (→ Rust: EntryUuid::close)",
        "entryuuid_plugin_task_handler (→ Rust: EntryUuid::task_handler)",
        "entryuuid_plugin_task_destructor",
        "entryuuid_fixup_mapfn",
    ],
    "key_rust_symbols": {
        "<entryuuid::EntryUuid as slapi_r_plugin::plugin::SlapiPlugin3>::betxn_pre_add": "UUID injection on add",
        "<entryuuid::EntryUuid as slapi_r_plugin::plugin::SlapiPlugin3>::task_validate": "Task input validation",
        "<entryuuid::EntryUuid as slapi_r_plugin::plugin::SlapiPlugin3>::task_be_dn_hint": "Task base DN hint",
        "<entryuuid::EntryUuid as slapi_r_plugin::plugin::SlapiPlugin3>::task_handler": "Fixup task body",
        "slapi_r_plugin::ber::TryFrom<&BerValRef> for uuid::Uuid": "Parse UUID from BerVal (LDAP attribute value)",
        "slapi_r_plugin::value::Value::from(&uuid::Uuid)": "Serialize UUID to LDAP value",
        "entryuuid::entryuuid_plugin_pwd_storage_encrypt_fn": "Password storage hook — likely stub/placeholder",
    },
    "notable": (
        "entryuuid_plugin_pwd_storage_encrypt_fn is registered, suggesting the plugin "
        "participates in the password storage chain. This may be a passthrough/no-op "
        "or may interact with the pwdchan plugin for password upgrade flows."
    ),
}

ENTRYUUID_SYNTAX_PLUGIN = {
    "c_entry_points": [
        "entryuuid_syntax_plugin_init",
        "entryuuid_syntax_plugin_eq_mr_init",
        "entryuuid_syntax_plugin_ord_mr_init",
        "entryuuid_syntax_plugin_syntax_validate (→ Rust: entryuuid_syntax::entryuuid_syntax_plugin_syntax_validate)",
        "entryuuid_syntax_plugin_mr_filter_ava",
        "entryuuid_syntax_plugin_eq_mr_filter_create",
        "entryuuid_syntax_plugin_eq_mr_indexer_create",
        "entryuuid_syntax_plugin_eq_mr_filter_sub",
        "entryuuid_syntax_plugin_eq_mr_filter_values2keys",
    ],
    "key_rust_symbols": {
        "<entryuuid_syntax::EntryUuidSyntax as slapi_r_plugin::syntax_plugin::SlapiSyntaxPlugin1>::syntax_validate": "Validates UUID format",
        "<entryuuid_syntax::EntryUuidSyntax as slapi_r_plugin::syntax_plugin::SlapiSyntaxPlugin1>::filter_ava_eq": "Equality filter for UUID",
        "<entryuuid_syntax::EntryUuidSyntax as slapi_r_plugin::syntax_plugin::SlapiOrdMr>::filter_ava_ord": "Ordering filter for UUID",
        "<entryuuid_syntax::EntryUuidSyntax as slapi_r_plugin::syntax_plugin::SlapiOrdMr>::filter_compare": "UUID comparison for ordering",
        "slapi_r_plugin::ber::TryFrom<&BerValRef> for uuid::Uuid": "Parse UUID from wire BerVal",
        "<entryuuid_syntax::EntryUuidSyntax as SlapiSyntaxPlugin1>::attr_supported_names": "Register UUID attribute syntax names",
        "<entryuuid_syntax::EntryUuidSyntax as SlapiSyntaxPlugin1>::eq_mr_supported_names": "Register equality MR names",
    },
    "note": (
        "UUID format validation implemented in Rust via TryFrom<&BerValRef> for uuid::Uuid. "
        "A malformed UUID attribute value will fail at the BerVal → uuid::Uuid conversion, "
        "returning Err without panicking (Result-based error handling confirmed in string evidence). "
        "No buffer overflow surface — UUID is a fixed 36-char string (8-4-4-4-12 hex format)."
    ),
}

SECURITY_ANALYSIS = {
    "memory_safety": "MEMORY_SAFE — Rust compilation prevents memory corruption",
    "uuid_quality": (
        "UUID v4 uses getrandom(2) via the uuid crate. On Linux, getrandom(2) is backed "
        "by the kernel CSPRNG (ChaCha20-based from 5.17+). UUID collision probability: "
        "negligible for all practical purposes (~1/(2^122) birthday bound)."
    ),
    "panic_risk": "Same as libpwdchan — unhandled panics abort slapd. Risk: LOW (Result<> paths confirmed)",
    "syntax_validation_as_input_gate": (
        "libentryuuid-syntax-plugin.so gates UUID-typed attribute values before they reach "
        "other plugin code. The Rust UUID parser will reject any non-conforming UUID string, "
        "providing a strict input validation boundary."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "INFO",
        "title": "entryuuid plugins: Tencent-authored Rust UUID plugins — memory-safe, TOS-exclusive",
        "detail": (
            "Two 1.3MB Rust plugins (same slapi_r_plugin crate as libpwdchan-plugin.so). "
            "libentryuuid-plugin.so: generates UUID v4 via getrandom(2) on betxn_pre_add. "
            "libentryuuid-syntax-plugin.so: validates UUID format, implements eq/ord matching rules. "
            "Not in upstream 389-ds 1.4.x — Tencent extension."
        ),
    },
    {
        "id": "F2",
        "severity": "INFO",
        "title": "entryuuid_plugin_pwd_storage_encrypt_fn present — entryuuid participates in password storage chain",
        "detail": (
            "The operational entryuuid plugin registers a password storage encrypt function. "
            "Role unclear from binary alone — likely a no-op passthrough or a hook to trigger "
            "password scheme upgrade alongside UUID backfill. Not a vulnerability."
        ),
    },
]

if __name__ == '__main__':
    print("TOS 4.6 389-ds entryuuid Rust plugins RE")
    for name, inv in BINARY_INVENTORY.items():
        print(f"  {name}: {inv['size']//1024}KB, {inv['c_entry_points']} C entry points")
    print()
    print("Memory safety: RUST — memory-safe by construction")
    print("UUID generation: uuid crate v4 → getrandom(2) → kernel CSPRNG")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:72]}")
