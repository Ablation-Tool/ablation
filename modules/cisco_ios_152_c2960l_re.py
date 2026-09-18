"""
Cisco Classic IOS 15.2(7)E14 RE Module
Target: c2960l-universalk9-mz.152-7.E14.bin (Catalyst 2960-L)
Format: MZIP self-extracting with LZMA payload at offset 0xC7E77A
Decompressed: 16,370,048 bytes (ELF MIPS, monolithic IOS executive)
"""

METADATA = {
    "target":   "Cisco IOS 15.2(7)E14 - Catalyst 2960-L",
    "binary":   "c2960l-universalk9-mz.152-7.E14.bin",
    "format":   "MZIP/LZMA compressed monolithic IOS executive",
    "arch":     "MIPS32 (big-endian)",
    "version":  "15.2(7)E14",
    "platform": "c2960l / lanlite",
    "size_raw": 16777216,
    "size_dec": 16370048,
    "extraction_offset": 0xC7E77A,
    "source":   "/media/cowboy/research/Cisco-Catalyst/c2960l-universalk9-mz.152-7.E14.bin",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "PnP HELLO Beacon Sent over Plaintext HTTP",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-319",
        "description": (
            "During Zero-Touch Provisioning, the device sends its PnP HELLO "
            "announcement to the PnP server over HTTP with no TLS: "
            "http://<pnpserver>:<port>/pnp/HELLO. An on-path attacker can "
            "intercept the HELLO, redirect provisioning to a rogue server, and "
            "deliver attacker-controlled startup configuration."
        ),
        "trigger_strings": [
            "http://%s:%d/pnp/HELLO",
            "PnP-NAPP-HTTP-SERVER (%d): enabling pnp http server %s",
            "PnP-NAPP-HTTP-SERVER (%d): enabling pnp https server %s",
        ],
        "impact": [
            "Full device takeover via malicious Day 0 config delivery",
            "Credential theft if admin credentials written to startup-config",
            "Persistent backdoor injected during provisioning",
        ],
        "remediation": (
            "Ensure pnp profile connect uses HTTPS transport exclusively. "
            "Validate PnP server identity with a trusted certificate before "
            "accepting any configuration."
        ),
        "yara": """rule cisco_pnp_http_hello {
    meta:
        description = "IOS PnP HELLO beacon uses HTTP not HTTPS"
        severity = "HIGH"
    strings:
        $hello = "http://%s:%d/pnp/HELLO" ascii
        $http_enable = "enabling pnp http server" ascii
    condition:
        any of them
}""",
    },
    {
        "id": "F2",
        "title": "PnP Trust Pool CA Bundle Downloaded over HTTP",
        "severity": "HIGH",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-830",
        "description": (
            "The device fetches its initial CA trust pool from "
            "http://pnptrustpool.<domain>/ca/trustpool/cabundle.p7b over HTTP "
            "with no prior trust anchor. An on-path attacker who intercepts "
            "this request can serve a malicious CA bundle, causing the device "
            "to trust attacker-controlled certificates for all subsequent TLS "
            "connections including HTTPS management."
        ),
        "trigger_strings": [
            "http://pnptrustpool.%s/ca/trustpool/cabundle.p7b",
        ],
        "impact": [
            "Attacker CA trusted for all subsequent device TLS verification",
            "HTTPS management sessions MITMable post-provisioning",
            "Code signing bypass if device uses trust pool for image verification",
        ],
        "remediation": (
            "Cisco hardcodes a default trustpool bundle in flash. Ensure "
            "pnp trustpool download is disabled or the download uses a "
            "pre-configured HTTPS endpoint with certificate pinning."
        ),
        "yara": """rule cisco_pnp_trustpool_http {
    meta:
        description = "IOS PnP trust pool download over HTTP - CA bundle MITM risk"
        severity = "HIGH"
    strings:
        $trustpool = "http://pnptrustpool." ascii
        $cabundle  = "cabundle.p7b" ascii
    condition:
        all of them
}""",
    },
    {
        "id": "F3",
        "title": "Hardcoded PnP Test Server Domain in Production Binary",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-798",
        "description": (
            "The production binary contains the hardcoded test PnP server "
            "hostname `pnpserver2.ejabberd.test` alongside `pnpserver.domain` "
            "and `pnpserver.`. These are internal CI/test infrastructure "
            "artifacts. If the DNS resolver returns a result for these names "
            "(e.g., via a wildcard .test domain capture or a DNS rebinding "
            "attack), the device may contact the wrong server during "
            "provisioning."
        ),
        "trigger_strings": [
            "pnpserver2.ejabberd.test",
            "pnpserver.domain",
            "pnpserver.",
        ],
        "impact": [
            "Internal build infrastructure hostname leaked",
            "DNS rebinding may redirect provisioning to attacker host",
            "Reveals use of ejabberd/XMPP as internal PnP transport",
        ],
        "remediation": (
            "Scrub all test/development hostnames from production builds. "
            "Apply a build-time linter that fails on .test / .local / .domain "
            "TLDs in non-test source trees."
        ),
        "yara": """rule cisco_pnp_test_domain_hardcoded {
    meta:
        description = "Production IOS binary contains test PnP server hostname"
        severity = "MEDIUM"
    strings:
        $test_domain = "pnpserver2.ejabberd.test" ascii
        $fake_domain  = "pnpserver.domain" ascii
    condition:
        any of them
}""",
    },
    {
        "id": "F4",
        "title": "Bluetooth SMP Passkey Handler Present in Wired Switch",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-338",
        "description": (
            "The IOS 15.2 image for the Catalyst 2960-L includes a complete "
            "Bluetooth Low Energy (BLE) Security Manager Protocol (SMP) "
            "stack including passkey generation (`se_smp_gen_passkey_handler`), "
            "Long-Term Key handling (`se_smp_ltk_req_for_pairing_handler`), "
            "pairing confirmation, and GATT. While the C2960L-STACK series "
            "supports Bluetooth Day 0 provisioning, devices without Bluetooth "
            "hardware still contain the full stack. The passkey generation "
            "quality and LTK randomness are not verifiable without symbol "
            "resolution, creating uncertainty about BLE pairing security."
        ),
        "trigger_strings": [
            "se_smp_gen_passkey_handler",
            "se_smp_ltk_req_for_pairing_handler",
            "se_smp_pairing_confirm_handler",
            "debug bluetooth all",
            "bluetooth_day0_registry",
            "debug bluetooth id_bnep",
        ],
        "impact": [
            "BLE management channel accessible to attackers in physical proximity",
            "Day 0 provisioning interceptable if passkey entropy is weak",
            "BNEP (Bluetooth Network Encapsulation) may expose IP-over-Bluetooth path",
        ],
        "remediation": (
            "Disable Bluetooth if not required: `no bluetooth` in global config. "
            "Audit se_smp_gen_passkey_handler for entropy source (should use "
            "hw RNG, not pseudo-random). Require explicit user confirmation "
            "for BLE pairing during Day 0 provisioning."
        ),
        "yara": """rule cisco_ios_ble_smp_stack {
    meta:
        description = "Classic IOS contains full BLE SMP passkey/LTK stack"
        severity = "MEDIUM"
    strings:
        $passkey_handler = "se_smp_gen_passkey_handler" ascii
        $ltk_handler     = "se_smp_ltk_req_for_pairing_handler" ascii
        $debug_bt        = "debug bluetooth all" ascii
        $bnep            = "debug bluetooth id_bnep" ascii
    condition:
        2 of them
}""",
    },
    {
        "id": "F5",
        "title": "NVRAM Bypass Hidden CLI Command",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-912",
        "description": (
            "The IOS binary contains a hidden `nvbypass` command: "
            "`%s %s nvbypass` with a description `bypass nvram for distilled "
            "config`. This command bypasses NVRAM reading during config load. "
            "An attacker with ROMMON or privileged CLI access can use this to "
            "boot the device without loading the startup-config, effectively "
            "bypassing password authentication when combined with a reload."
        ),
        "trigger_strings": [
            "%s %s nvbypass",
            "nvbypass",
            "bypass nvram for distilled config",
        ],
        "impact": [
            "Authentication bypass when combined with console/ROMMON access",
            "Startup-config suppression allows loading default unconfigured state",
        ],
        "remediation": (
            "Enable `service password-recovery disable` which prevents "
            "ROMMON access from bypassing authentication. Monitor console "
            "port access physically."
        ),
        "yara": """rule cisco_ios_nvbypass {
    meta:
        description = "IOS nvbypass command allows NVRAM config bypass"
        severity = "MEDIUM"
    strings:
        $nvbypass      = "nvbypass" ascii
        $bypass_desc   = "bypass nvram for distilled config" ascii
    condition:
        all of them
}""",
    },
    {
        "id": "F6",
        "title": "Internal Build Path Disclosure via Assert Strings",
        "severity": "LOW",
        "cvss": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-209",
        "description": (
            "Production assert macros embed full Cisco internal source paths: "
            "`../VIEW_ROOT/cisco.comp/<subsystem>/src/<file>`. Paths leak "
            "Cisco's internal monorepo structure including component names "
            "(xdr, cfc_cefmpls, sanet, beep, beep_sasl) and build root "
            "(`VIEW_ROOT`). This aids targeted fuzzing of specific subsystems."
        ),
        "trigger_strings": [
            "../VIEW_ROOT/cisco.comp/xdr/src/xdr_mcast.c",
            "../VIEW_ROOT/cisco.comp/cfc_cefmpls/adj/src/adj_macstring.c",
            "../VIEW_ROOT/cisco.comp/sanet/auth-mgr/features/auth_feature_critical_core.c",
            "../VIEW_ROOT/cisco.comp/beep/src/beepcore-c/ios/",
            "agg assert failure: %s: %s: %d",
        ],
        "impact": [
            "Internal source tree structure exposed to reverse engineers",
            "Facilitates targeted fuzzing of named subsystems",
        ],
        "remediation": (
            "Strip __FILE__ macros from production builds using "
            "-DNDEBUG or a build-time string scrubbing pass."
        ),
        "yara": """rule cisco_ios_build_path_disclosure {
    meta:
        description = "IOS production binary leaks internal Cisco build paths via asserts"
        severity = "LOW"
    strings:
        $viewroot  = "../VIEW_ROOT/cisco.comp/" ascii
        $xdr_src   = "xdr/src/xdr_mcast.c" ascii
        $sanet_src = "sanet/auth-mgr/features/" ascii
    condition:
        $viewroot and any of ($xdr_src, $sanet_src)
}""",
    },
]

SUMMARY = {
    "total":    6,
    "critical": 0,
    "high":     2,
    "medium":   3,
    "low":      1,
}
