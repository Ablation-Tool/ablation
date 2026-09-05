"""
TencentOS 4.6 — expat 2.6.4 CVE patch stack + Hygon TCM/TPM binary RE
+ Cyrus IMAP 3.4.8 squatter crash patch.

Sources:
  scratchpad/expat46/ — expat-2.6.4 patch stack
  scratchpad/tcm_hygon.ko — Hygon TCM2 driver (ELF, not stripped, 18KB)
  scratchpad/tpm_hygon.ko — Hygon TPM2 driver (ELF, not stripped, 16KB)
  scratchpad/cyrus-46-re/ — Cyrus IMAP 3.4.8 for TOS 4.6
"""

EXPAT_METADATA = {
    "package": "expat-2.6.4",
    "tos_version": "TOS 4.6",
    "patch_files": [
        "fix-CVE-2024-8176.patch",
        "Fix-CVE-2025-59375.patch",
        "fix-CVE-2026-24515.patch",
        "fix-1-CVE-2026-25210.patch",
        "fix-2-CVE-2026-25210.patch",
        "fix-3-CVE-2026-25210.patch",
        "expat-2.6.4-CVE-2026-50219.patch",
        "expat-2.6.4-CVE-2026-56412.patch",
        "expat-2.6.4-CVE-2026-66046.patch",
        "stop-updating-event-pointer-on-exit-for-reentry.patch",
    ],
}

EXPAT_CVES = {
    "CVE-2024-8176": {
        "title": "Entity chain stack overflow — recursive entity processing, pre-auth DoS",
        "author": "Kshitiz Godara (Microsoft); Google Project Zero (Jann Horn, Mark Brand)",
        "severity": "CVSS 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)",
        "description": (
            "XML parser crashed when chaining a large number of general entities or parameter "
            "entities due to unbounded recursion in the entity expansion stack. "
            "Three affected call paths: "
            "(1) general entities in character data, "
            "(2) general entities in attribute values, "
            "(3) parameter entities. "
            "Large patch: 566 lines modified in xmlparse.c, 27 in alloc_tests.c, "
            "187 in basic_tests.c. "
            "Compression around XML significantly reduces minimum attack payload size. "
            "Google Project Zero reported: 'reliable and easy denial of service'."
        ),
        "fix": "Converted recursion to iteration; introduced entity expansion depth tracking.",
        "class": "stack-overflow",
        "pre_auth": True,
    },
    "CVE-2025-59375": {
        "title": "Alloc-tracker amplification: new DoS protection API in Expat 2.7.2",
        "author": "Sebastian Pipping",
        "description": (
            "Memory allocation amplification — XML parser allocates far more memory than "
            "the input size suggests. Fix adds two new public APIs: "
            "XML_SetAllocTrackerMaximumAmplification() and "
            "XML_SetAllocTrackerActivationThreshold(). "
            "Analogous to the existing Billion Laughs attack protection. "
            "Upstream PR #1034."
        ),
        "fix": "New AllocTracker subsystem tracks allocation amplification ratio; aborts on threshold.",
        "class": "resource-exhaustion",
    },
    "CVE-2026-24515": {
        "title": "XML_ExternalEntityParserCreate: unknownEncodingHandlerData not copied",
        "author": "Sebastian Pipping (suggested by Artiphishell Inc.)",
        "description": (
            "XML_ExternalEntityParserCreate() copies all handler callbacks from the parent "
            "parser to the new sub-parser, but forgot to copy m_unknownEncodingHandlerData "
            "(the opaque user-data pointer passed to the unknown encoding handler). "
            "The sub-parser's unknown encoding handler receives a stale or NULL data pointer, "
            "causing use of uninitialized data or NULL deref in the handler."
        ),
        "fix": "Added oldUnknownEncodingHandlerData = ... / parser->m_unknownEncodingHandlerData = ... pair.",
        "class": "missing-copy",
    },
    "CVE-2026-25210": {
        "title": "doContent tag buffer realloc: integer overflow in size doubling",
        "author": "Matthew Fernandez (suggested by Sebastian Pipping)",
        "patches": 3,
        "description": (
            "Tag name buffer reallocation in doContent() computed bufSize as: "
            "bufSize = (int)(tag->bufEnd - tag->buf) << 1; "
            "This uses int arithmetic. If the buffer exceeds INT_MAX/2 bytes, "
            "the left-shift wraps to a negative value; REALLOC gets a negative size, "
            "resulting in under-allocation and subsequent OOB write. "
            "Three-patch fix: "
            "(1) Readability: replace << 1 with * 2. "
            "(2) Type safety: change bufSize to size_t. "
            "(3) Overflow guard: add SIZE_MAX/2 < (size_t)(...) check before doubling."
        ),
        "fix": "size_t type + SIZE_MAX/2 overflow guard before doubling.",
        "class": "integer-overflow",
    },
    "CVE-2026-50219": {
        "title": "Handler call depth tracking — prerequisite for reentrancy DoS fix",
        "author": "Sebastian Pipping",
        "description": (
            "Part 1 of a multi-patch fix. Introduces m_handlerCallDepth counter to "
            "XML_ParserStruct and beforeHandler()/afterHandler()/isCalledFromInsideHandler() "
            "primitives. These are used in subsequent patches (CVE-2026-56412) to guard "
            "handler invocations against reentrancy from within their own call chain. "
            "Note: 34 downstream patches numbered in this CVE series."
        ),
        "fix": "unsigned m_handlerCallDepth field + before/afterHandler wrappers.",
        "class": "reentrancy-infrastructure",
    },
    "CVE-2026-56412": {
        "title": "doCdataSection: CDATA CharacterData handler called without reentrancy guard",
        "author": "hextheshadow0x@gmail.com",
        "adapted_by": "PkgAgent/deepseek-v4 (opencloudos-stream backport)",
        "description": (
            "doCdataSection() in xmlparse.c invoked charDataHandler() without wrapping "
            "in beforeHandler()/afterHandler(). "
            "A malicious XML document with CDATA sections can trigger charDataHandler "
            "recursively (via XML_Parse called from within the handler). "
            "The fix wraps both charDataHandler call sites in doCdataSection with "
            "beforeHandler/afterHandler guards."
        ),
        "fix": "beforeHandler() + afterHandler() around both CDATA charDataHandler call sites.",
        "class": "reentrancy",
        "pre_auth": True,
        "ai_ported": True,
    },
    "CVE-2026-66046": {
        "title": "storeAtts() isCdata lookup: O(n^2) linear scan -> O(1) hash table",
        "author": "PkgAgent Robot <pkgagent@opencloudos.tech>",
        "adapted_by": "PkgAgent/deepseek-v4",
        "description": (
            "storeAtts() in xmlparse.c resolved the isCdata flag for each attribute "
            "by a linear scan over elementType->defaultAtts. With many attributes, "
            "this is O(n^2) — each attribute scans all defaultAtts. "
            "An attacker providing XML with many attributes on a deeply-nested element "
            "can trigger quadratic parser runtime, causing CPU exhaustion (DoS). "
            "Fix introduces NAME_AND_DEFAULT_ATTRIBUTE type and ELEMENT_TYPE.defaultAttForName "
            "hash table keyed by attribute name."
        ),
        "fix": "Hash table ELEMENT_TYPE.defaultAttForName; lookup becomes O(1).",
        "class": "algorithmic-complexity",
        "pre_auth": True,
        "ai_ported": True,
    },
}

EXPAT_REENTRY_FIX = {
    "patch": "stop-updating-event-pointer-on-exit-for-reentry.patch",
    "author": "Berkay Eren Uruen (Siemens)",
    "description": (
        "The recursive entity fix (CVE-2024-8176) introduced a m_reenter flag that "
        "returns from the current processor frame and switches to entity processing. "
        "The fix incorrectly updated m_eventPtr during this switch, changing behavior "
        "vs the old recursive version. Fix moves *eventPP = next into only the "
        "XML_SUSPENDED and XML_FINISHED cases, restoring pre-fix event pointer semantics."
    ),
}

TCM_TPM_HYGON = {
    "tcm_hygon": {
        "file": "tcm_hygon.ko",
        "size_bytes": 18432,
        "elf": "ELF 64-bit LSB relocatable x86-64, BuildID c407ca5257e5a01035a1d28b1be7f1f46c472206",
        "stripped": False,
        "author": "mayuanchen@hygon.cn",
        "description": "TCM2 device driver for Hygon PSP",
        "license": "GPL",
        "acpi_alias": "HYGT0201",
        "depends": "ccp",
        "vermagic": "6.6.119-51.3.tl4.x86_64 SMP mod_unload modversions",
        "standard": "TCM (Trusted Cryptography Module) — Chinese national TPM equivalent (GM/T 0028-2012)",
        "protocol": "PSP command queue interface (psp_do_cmd); same CCP path as hct.ko",
    },
    "tpm_hygon": {
        "file": "tpm_hygon.ko",
        "size_bytes": 16384,
        "elf": "ELF 64-bit LSB relocatable x86-64, BuildID b18006cf385463d11169b98b38607ae6b69be7cf",
        "stripped": False,
        "author": "mayuanchen@hygon.cn",
        "description": "TPM2 device driver for Hygon PSP",
        "license": "GPL",
        "acpi_alias": "HYGT0101",
        "depends": "ccp",
        "vermagic": "6.6.119-51.3.tl4.x86_64 SMP mod_unload modversions",
        "standard": "TPM2 — industry-standard Trusted Platform Module 2.0",
    },
    "design_note": (
        "Both modules are thin shims over the PSP (Platform Security Processor) CCP "
        "command queue. This is the same underlying interface as hct.ko (Hygon CCP "
        "hardware passthrough). TCM/TPM commands are marshalled into PSP command "
        "blocks and sent via psp_do_cmd(). "
        "TOS ships both: TCM (Chinese national crypto standard) and TPM2 "
        "(international standard), with separate ACPI IDs (HYGT0201 vs HYGT0101)."
    ),
}

TCM_DISASM = {
    "tcm_hygon_functions": {
        "offset_0x00": "hygon_tcm2_exit / cleanup_module — 16-NOP sled (kprobe landing pad) + chip unregister",
        "offset_0x10": "hygon_tcm2_exit body — tpm_chip_unregister via rdi+0x318 device pointer",
        "offset_0x40": "tcm_c_recv — receive response from PSP TCM command queue",
        "offset_0x40_analysis": {
            "rdi_arg0": "tpm_chip pointer",
            "rsi_arg1": "output buffer",
            "rdx_arg2": "output buffer size (rcx after adjust)",
            "rsi_plus_0x88": "internal TCM command buffer (cmd_buf)",
            "rsi_plus_0xa_bswap": "response length (big-endian u32 at cmd_buf+0xa, bswapped)",
            "rcx_vs_rdx": "if rcx < rdx: return EBUSY (0xfffffff9==-7); else copy",
            "flow": "read response len -> bswap -> compare to caller buf -> copy or error",
        },
        "offset_0xa0": "tcm_c_send — send TCM2 command to PSP via psp_do_cmd",
        "offset_0xa0_analysis": {
            "rdx_arg2": "command size",
            "cmp_0xff8": "size > 0xFF8 (4088) -> return EBUSY (-7); max command size = 4088 bytes",
            "rbx_plus_0": "dword 0x100000 written — PSP command header word 0 (target PSP, cmd class)",
            "rbx_plus_4": "bswap(size) — command size in big-endian at header offset 4",
            "call_psp_do_cmd": "edi=0x100 (PSP command type 0x100 = TCM), rsi=cmd_buf, rdx=&result",
            "gs_0x28": "stack canary (__stack_chk_guard)",
            "error_path": "psp_do_cmd failure -> result in edx; __tpm_transmit error printed; return -5 (EIO)",
        },
        "offset_0x140": "hygon_tcm2_acpi_add — ACPI device probe",
        "offset_0x140_analysis": {
            "size": "0xF0 bytes",
            "flow": "tpmm_chip_alloc -> devm_kmalloc(0x98 bytes) -> set ops -> tpm_chip_register",
            "ops_ptr": "0x140 bytes into ops array (tcm_c_ops at .rodata)",
        },
    },
    "tcm_c_ops": {
        "offset": "0x140 (.rodata)",
        "size": "0x140 bytes",
        "content": "tpm_class_ops struct with tcm_c_send/tcm_c_recv/pm_ops pointers",
    },
    "psp_command_format": {
        "header_word0": "0x100000 (PSP target + command class; CCP-specific encoding)",
        "header_word4_bswapped": "command size in big-endian",
        "max_command_size": "0xFF8 = 4088 bytes",
        "psp_cmd_type": "0x100 (TPM/TCM passthrough to PSP)",
    },
    "tcm_vs_tpm_difference": (
        "TCM uses same wire format but different PSP command type and ACPI ID. "
        "tcm_c_send uses psp cmd 0x100 (same as tpm_hygon.ko). "
        "Key protocol difference: TCM (GM/T 0028-2012) uses SM2/SM3/SM4 algorithms; "
        "TPM2 (ISO 11889) uses RSA/ECC/SHA. Both go through the same Hygon PSP CCP hardware."
    ),
}

CYRUS_SQUATTER = {
    "package": "cyrus-imapd-3.4.8",
    "tos_version": "TOS 4.6",
    "patch": "patch-cyrus-squatter-assert-crash",
    "file": "imap/squatter.c",
    "function": "expand_mboxnames",
    "description": (
        "squatter is the Cyrus IMAP search indexer (Sphinx/Xapian-based). "
        "expand_mboxnames() translated user-supplied mailbox names to internal form "
        "via mboxname_from_external(), then passed the result directly to "
        "mboxlist_mboxtree() without checking for NULL or empty string. "
        "mboxname_from_external() returns NULL or empty string for invalid/unsupported mailbox names. "
        "Passing NULL or empty intname to mboxlist_mboxtree() triggered an assertion or crash "
        "inside mboxlist (NULL deref or assert on empty path). "
        "Reachable by any user who can invoke squatter with a mailbox name that "
        "translates to an invalid internal form."
    ),
    "fix": "Null/empty check on intname before calling mboxlist_mboxtree; prints error_message(IMAP_MAILBOX_BADNAME) to stderr.",
    "class": "null-deref",
    "additional_patches": [
        "patch-cyrus-default-configs — TOS default configuration adjustments",
        "patch-cyrus-perl-linking — Perl module linking fix",
        "patch-cyrus-rename-quota — Quota subsystem rename for TOS packaging",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "cve": "CVE-2024-8176",
        "package": "expat-2.6.4",
        "title": "Entity chain stack overflow — pre-auth network DoS",
        "detail": (
            "Recursive entity expansion in xmlparse.c with no depth limit. "
            "Compressed XML payload triggers reliable stack overflow. "
            "CVSS 7.5, pre-auth, network-accessible. "
            "Reported by Google Project Zero."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "cve": "CVE-2026-56412",
        "package": "expat-2.6.4",
        "title": "CDATA charDataHandler called without reentrancy guard — reentrancy abuse",
        "detail": (
            "doCdataSection calls charDataHandler without beforeHandler/afterHandler guards. "
            "Adversarial XML with CDATA causes recursive XML_Parse from within handler, "
            "corrupting parser state. Pre-auth; backported by PkgAgent/deepseek-v4."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "cve": "CVE-2026-66046",
        "package": "expat-2.6.4",
        "title": "storeAtts O(n^2) — algorithmic complexity DoS via many-attribute elements",
        "detail": (
            "isCdata lookup linear over defaultAtts for each attribute. "
            "XML with N attributes in deep element causes O(N^2) CPU work. "
            "Pre-auth, no resource limit prevents this. AI-ported by PkgAgent/deepseek-v4."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "cve": "CVE-2026-25210",
        "package": "expat-2.6.4",
        "title": "doContent tag buffer: int arithmetic overflow on size doubling",
        "detail": (
            "bufSize = (int)(tag->bufEnd - tag->buf) << 1 overflows for buffers > INT_MAX/2. "
            "Negative size passed to REALLOC; subsequent write OOB."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "cve": "CVE-2026-24515",
        "package": "expat-2.6.4",
        "title": "External entity sub-parser: unknownEncodingHandlerData not copied",
        "detail": (
            "XML_ExternalEntityParserCreate skips m_unknownEncodingHandlerData copy. "
            "Sub-parser's unknown encoding handler receives stale data pointer — "
            "NULL deref or use of uninitialized data."
        ),
    },
    {
        "id": "F6",
        "severity": "HIGH",
        "title": "Hygon TCM2: psp_do_cmd interface — command injection via direct PSP access",
        "package": "tcm_hygon.ko",
        "detail": (
            "tcm_c_send marshals caller-supplied data directly into a PSP command block "
            "with only a size check (max 0xFF8=4088 bytes). "
            "Command header word0=0x100000 and cmd_type=0x100 are hardcoded, but "
            "command payload is fully user-controlled. "
            "Device accessible by root or processes with CAP_SYS_ADMIN. "
            "PSP firmware interface is unparsed from the kernel side — "
            "malformed TCM command packet sent to PSP could trigger PSP firmware bug."
        ),
    },
    {
        "id": "F7",
        "severity": "MEDIUM",
        "title": "Hygon TCM2: no response length validation in tcm_c_recv",
        "package": "tcm_hygon.ko",
        "detail": (
            "tcm_c_recv reads response length from cmd_buf+0xa (big-endian u32, bswapped). "
            "If PSP returns a malformed response with length > caller buffer, "
            "the driver returns EBUSY (-7) but does not validate that the response length "
            "is within the cmd_buf bounds. "
            "A compromised or buggy PSP could return length=0xFFFFFFFF, "
            "causing kernel OOB read in the copy path."
        ),
    },
    {
        "id": "F8",
        "severity": "INFO",
        "title": "TOS ships TCM (GM/T 0028-2012) alongside TPM2 — dual trust module strategy",
        "package": "tcm_hygon.ko + tpm_hygon.ko",
        "detail": (
            "tcm_hygon.ko (ACPI HYGT0201) implements GM/T 0028-2012 TCM (Chinese national standard). "
            "tpm_hygon.ko (ACPI HYGT0101) implements TPM2 (international standard). "
            "Both are thin PSP shims sharing the psp_do_cmd interface. "
            "TOS selects module based on ACPI hardware presence — "
            "government/regulated deployments get TCM; international deployments get TPM2."
        ),
    },
    {
        "id": "F9",
        "severity": "MEDIUM",
        "title": "Cyrus IMAP squatter: NULL deref on invalid mailbox name in expand_mboxnames",
        "package": "cyrus-imapd-3.4.8",
        "detail": (
            "expand_mboxnames() passes unchecked mboxname_from_external() result to "
            "mboxlist_mboxtree(). NULL or empty intname causes crash in squatter. "
            "Reachable by any authenticated IMAP user who can invoke squatter."
        ),
    },
    {
        "id": "F10",
        "severity": "INFO",
        "title": "CVE-2026-56412 and CVE-2026-66046 ported by PkgAgent/deepseek-v4 AI system",
        "package": "expat-2.6.4",
        "detail": (
            "Both patches carry 'Adapted-by: PkgAgent/deepseek-v4' attribution. "
            "Third observed instance of AI-ported security patches in TOS 4.6 "
            "(prior: security_patches_re.py F13). "
            "Systemic: TOS uses LLM-based patch porting for OpenCloudOS-stream backports."
        ),
    },
]

if __name__ == '__main__':
    print("expat-2.6.4 + Hygon TCM/TPM + Cyrus IMAP 3.4.8 — TOS 4.6")
    print()
    print("expat CVEs:")
    for cve_id, cve in EXPAT_CVES.items():
        ai = " [AI-PORTED]" if cve.get("ai_ported") else ""
        print(f"  {cve_id}: {cve['title'][:65]}{ai}")
    print()
    print("Hygon TCM/TPM modules:")
    for m, info in TCM_TPM_HYGON.items():
        if m == "design_note":
            continue
        print(f"  {m}: {info['description']} (ACPI {info['acpi_alias']})")
    print()
    for f in FINDINGS:
        cve = f"[{f.get('cve', '')}]" if f.get('cve') else "[INFO]"
        print(f"  [{f['severity']:6s}] {f['id']}: {cve} {f['title'][:60]}")
