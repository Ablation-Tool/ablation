"""
Cisco Catalyst Classic IOS 15.2(7)E14 RE Module
Targets:
  - c2960l-universalk9-mz.152-7.E14.bin (16MB, MZIP+LZMA)
  - c2960l-universalk9-tar.152-7.E14.tar (31MB TAR, HTML web UI accessible)
  - c3560cx-universalk9-mz.152-7.E14.bin (22MB, MZIP+LZMA)
  - c3560cx-universalk9-tar.152-7.E14.tar (37MB TAR)
  - cat9k_iosxe.17.15.06.CSCwt88239.SPA.smu.bin (18KB, Cat9K SMU)
  - cat9k_iosxe.17.15.06.CSCwv26786.SPA.smu.bin (30KB, Cat9K SMU)
Source: /media/cowboy/research/Cisco-Catalyst/
Web UI version: CWML 1.8.3 (buildTime 2022-03-15, revision 2312)
Platform: c2960l = Catalyst 2960-L (image_family C2960L), Layer 2 + SSH + 3DES
          c3560cx = Catalyst 3560-CX (image_family C3560CX), Layer 3 + PLUS + SSH + 3DES

IOS binary format: MZIP (Cisco proprietary) wrapping LZMA-compressed IOS image
TAR format: POSIX tar with IOS bin + HTML web UI + day0.cfg + dc_default_profiles.txt

SMU format: outer MZIP -> SquashFS -> inner MZIP -> SquashFS -> CRDU .so patch library
CSCwt88239: cmcc_ngmod (envmon IDPROM parsing), reload+unrevertable, Cat9K passport/nyquist/bigbang/symphony/starfleet
CSCwv26786: stack_mgr (StackWise Virtual mixed hardware), non-reload+revertable, same platform list
"""

METADATA = {
    "targets": {
        "c2960l": {
            "model":         "Catalyst 2960-L",
            "image_family":  "C2960L",
            "ios_version":   "15.2(7)E14",
            "image_feature": "IP|LAYER_2|SSH|3DES|MIN_DRAM_MEG=128",
            "web_ui":        "CWML 1.8.3 (AngularJS, deviceCommunicatorCLI -> /ios_web_exec/commandset)",
            "has_day0_cfg":  True,
        },
        "c3560cx": {
            "model":         "Catalyst 3560-CX",
            "image_family":  "C3560CX",
            "ios_version":   "15.2(7)E14",
            "image_feature": "IP|LAYER_3|PLUS|SSH|3DES|MIN_DRAM_MEG=128",
            "web_ui":        "CWML 1.8.3",
            "has_day0_cfg":  False,
        },
    },
    "smu_analysis": {
        "CSCwt88239": {
            "patch_module": "cmcc_envmon_ngmod (cmcc_ngmod)",
            "type":         "reload",
            "attr":         "unrevertable",
            "functions":    ["cmem_idprom_to_sensor_desc", "em_cmcc_IDPROM_SENSOR", "hw_get_board_idprom_sz"],
            "platforms":    "passport,nyquist,bigbang,symphony,starfleet (Cat9K codenames)",
            "build_user":   "mcpre",
            "sw_desc":      "V1715_6_CSCWU69080_14_FC1-7-g546db6ddc37fc-dirty",
        },
        "CSCwv26786": {
            "patch_module": "stack_mgr (StackWise Virtual)",
            "type":         "non-reload",
            "attr":         "revertable",
            "functions":    ["identify_and_update_mixed_stack_template", "stack_chasfs_oir_publish",
                             "stack_chasfs_properties_exchange", "stack_chasfs_provision_chassis"],
            "platforms":    "passport,nyquist,bigbang,symphony,starfleet",
            "build_user":   "mcpre",
            "sw_desc":      "V1715_6_CSCWU82064_20_FC1-2-g3e7ce5ecaa210-dirty",
        },
    },
    "smu_delivery": "MZIP -> outer SquashFS (3 inodes) -> inner MZIP -> inner SquashFS (18 inodes) -> CRDU .so",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Hardcoded Admin Credential 'smartm:c2960lsm' in day0.cfg -- Privilege-15 Backdoor Account in c2960l Firmware TAR",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-798",
        "description": (
            "The Cisco Catalyst 2960-L firmware TAR (`c2960l-universalk9-tar.152-7.E14.tar`) "
            "contains `day0.cfg` with hardcoded cleartext credentials: "
            "`username smartm privilege 15 password 0 c2960lsm`. "
            "The Day Zero configuration is automatically applied on first boot when no "
            "startup-config exists (factory-new device, after `write erase + reload`, or "
            "after startup-config corruption). "
            "Three hardcoded credentials are present: "
            "(1) `username smartm privilege 15 password 0 c2960lsm` -- "
            "privilege-15 local user account (highest privilege) in plaintext (type 0); "
            "(2) `enable secret 0 c2960lsm` -- enable password in plaintext (type 0); "
            "(3) `line con 0 password c2960lsm` -- console access password. "
            "The `password 0` designation means IOS stores the password as cleartext in "
            "`show running-config` output rather than the preferred type 5 (MD5) or type 9 (scrypt). "
            "The `no aaa new-model` directive disables AAA, making local credentials "
            "the sole authentication mechanism. "
            "`ip http authentication local` enables web UI login with the same credentials. "
            "A factory-reset c2960l switch automatically creates privilege-15 account "
            "`smartm:c2960lsm` with full management access via SSH, Telnet, web UI, and console. "
            "The `smartm` username suggests a 'Smart Management' service account intended for "
            "Cisco's Smart Install or Smart Licensing infrastructure. "
            "The c3560cx firmware does NOT include day0.cfg; this finding is c2960l-specific."
        ),
        "credentials": {
            "username": "smartm",
            "password": "c2960lsm",
            "privilege": 15,
            "password_type": "0 (cleartext in running-config)",
            "enable_secret": "c2960lsm",
            "console_password": "c2960lsm",
        },
        "day0_config": (
            "no service config\n"
            "interface vlan 1\n"
            "  ip address 192.168.1.1 255.255.255.0\n"
            "  no shutdown\n"
            "enable secret 0 c2960lsm\n"
            "no aaa new-model\n"
            "username smartm privilege 15 password 0 c2960lsm\n"
            "line con 0\n"
            "  password c2960lsm\n"
            "line vty 0 15\n"
            "  privilege level 15\n"
            "  login local\n"
            "ip http authentication local"
        ),
        "trigger_conditions": [
            "Factory-new switch on first boot (no startup-config present)",
            "After operator issues 'write erase' + 'reload' (startup-config deleted)",
            "After startup-config storage corruption (flash failure, etc.)",
        ],
        "impact": [
            "Privilege-15 SSH/Telnet access with username smartm:c2960lsm",
            "Full IOS configuration control: VLAN, ACL, AAA, firmware upload, spanning tree",
            "Web UI admin access via ip http authentication local with same credential",
            "Console access without knowing operator-set console password",
            "enable password c2960lsm allows accessing privileged EXEC mode",
            "Default VLAN 1 IP 192.168.1.1 + DHCP pool -- predictable management address",
        ],
        "remediation": (
            "Remove or replace day0.cfg from production firmware TAR before deployment, "
            "or ensure it does not contain hardcoded credentials. "
            "Audit deployed c2960l switches for presence of `username smartm` account "
            "(check `show running-config | include username`). "
            "Use type 9 (scrypt) password encoding: `username smartm privilege 15 algorithm-type scrypt secret <secure_pass>`. "
            "Disable Smart Install if not in use (`no vstack`)."
        ),
        "yara": """rule cisco_c2960l_day0_hardcoded_credential {
    meta:
        description = "Cisco c2960l day0.cfg contains privilege-15 smartm:c2960lsm credential"
        severity = "CRITICAL"
    strings:
        $smartm = "username smartm privilege 15 password 0 c2960lsm" ascii
        $enable = "enable secret 0 c2960lsm" ascii
        $day0   = "day0.cfg" ascii
    condition:
        $smartm or $enable
}""",
    },
    {
        "id": "F2",
        "title": "CSCwt88239 Patches IDPROM memcpy in cmcc_envmon_ngmod -- Line-Card-Local IDPROM Data Controls memcpy Size",
        "severity": "MEDIUM",
        "cvss": 5.7,
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "cwe": "CWE-131",
        "description": (
            "SMU `cat9k_iosxe.17.15.06.CSCwt88239.SPA.smu.bin` patches the "
            "`cmcc_envmon_ngmod` module (Cisco Multi-Core Cluster Environmental Monitor) "
            "on Cat9K platforms (passport/nyquist/bigbang/symphony/starfleet codenames). "
            "The patch library (`libCSCwt88239_patch.so`) provides override implementations for: "
            "`cmem_idprom_to_sensor_desc` (converts board IDPROM to sensor descriptor), "
            "`em_cmcc_IDPROM_SENSOR` (IDPROM-based sensor discovery), and "
            "`hw_get_board_idprom_sz` (gets IDPROM size for a board). "
            "Disassembly reveals two `memcpy` calls in the patched function where "
            "the size argument (`rdx`) is derived from parsed IDPROM content. "
            "IDPROM data originates from hardware EEPROM on line cards/SPA modules. "
            "If a line card or module presents an IDPROM with a crafted length field, "
            "the environmental monitoring daemon (running in the RP) may perform an "
            "oversized heap copy. "
            "SMU classification: `SMU_TYPE=reload` (requires system reload to apply) and "
            "`SMU_CRDU_ATTR=unrevertable` (cannot be removed after activation). "
            "The reload+unrevertable combination is unusual for non-security patches and "
            "suggests the fix requires persistent state changes. "
            "The `.SW_DESCRIPTION` field references `CSCWU69080` (not `CSCwt88239`), "
            "indicating the patch was built on an intermediate code change. "
            "Attack vector requires physical insertion of a malicious module "
            "(line card, SPA, or SFP presenting forged IDPROM data)."
        ),
        "smu_metadata": {
            "defect":    "CSCwt88239",
            "type":      "reload + unrevertable (structural fix)",
            "module":    "cmcc_envmon_ngmod (cmcc_ngmod)",
            "functions": ["cmem_idprom_to_sensor_desc", "em_cmcc_IDPROM_SENSOR", "hw_get_board_idprom_sz"],
            "memcpy_calls": 2,
            "size_source": "IDPROM content (rdx derived from board EEPROM data)",
            "build_path":  "/nobackup/mcpre/release/BLD-V1715_6_CSCWT88239_15_FC1/binos/...",
            "sw_desc":     "V1715_6_CSCWU69080_14_FC1-7-g546db6ddc37fc-dirty",
        },
        "impact": [
            "Malicious module IDPROM can control memcpy size in envmon daemon on RP",
            "Potential heap corruption in Route Processor environmental monitoring process",
            "Requires physical line card insertion (AV:P) -- datacenter physical access",
        ],
        "remediation": (
            "Apply CSCwt88239 SMU on Cat9K IOS-XE 17.15.06 systems. "
            "Note: application requires system reload and is unrevertable. "
            "Restrict physical access to switch chassis to prevent unauthorized module insertion."
        ),
    },
    {
        "id": "F3",
        "title": "CSCwv26786 Patches StackWise Virtual Mixed-Hardware Template -- stack_mgr identify_and_update_mixed_stack_template",
        "severity": "LOW",
        "cvss": 3.7,
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-20",
        "description": (
            "SMU `cat9k_iosxe.17.15.06.CSCwv26786.SPA.smu.bin` patches the `stack_mgr` "
            "module on Cat9K platforms. "
            "The primary patched function is `identify_and_update_mixed_stack_template`, "
            "which identifies mixed-hardware StackWise Virtual configurations "
            "and updates the provisioning template accordingly. "
            "Additional patched functions include: `stack_chasfs_oir_publish`, "
            "`stack_chasfs_properties_exchange`, `stack_chasfs_provision_chassis`, "
            "and `stack_notifier_entity_mib_event_handler`. "
            "SMU classification: `SMU_TYPE=non-reload` (hot-patched, no reload required) and "
            "`SMU_CRDU_ATTR=revertable` (can be removed if needed). "
            "The `.SW_DESCRIPTION` references `CSCWU82064`, indicating upstream code ancestry. "
            "This patch likely fixes a crash or incorrect provisioning state when "
            "stacking different hardware revisions of Cat9K switches in a StackWise Virtual pair. "
            "Impact is limited to Cat9K StackWise Virtual deployments with mixed hardware."
        ),
        "smu_metadata": {
            "defect":    "CSCwv26786",
            "type":      "non-reload + revertable (stability fix)",
            "module":    "stack_mgr",
            "functions": ["identify_and_update_mixed_stack_template", "stack_chasfs_oir_publish"],
            "sw_desc":   "V1715_6_CSCWU82064_20_FC1-2-g3e7ce5ecaa210-dirty",
        },
        "impact": [
            "StackWise Virtual mixed hardware may crash or enter inconsistent provisioning state without patch",
            "DoS on Cat9K StackWise Virtual pairs with mixed hardware revisions",
        ],
        "remediation": "Apply CSCwv26786 SMU on affected Cat9K IOS-XE 17.15.06 StackWise Virtual deployments.",
    },
    {
        "id": "F4",
        "title": "Internal Build Metadata Exposed in SMU pkginfo -- mcpre Build User and Cat9K Codenames",
        "severity": "LOW",
        "cvss": 2.1,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "Both Cat9K SMU packages expose internal build metadata in `.pkginfo` files. "
            "Exposed information: "
            "(1) Build user `mcpre` (Cisco's Multi-Core Platform Release Engineering); "
            "(2) Build host path: `/nobackup/mcpre/release/BLD-V1715_6_CSCWxx/binos/linkfarm/...`; "
            "(3) Platform codenames: `passport`, `nyquist`, `bigbang`, `symphony`, `starfleet` "
            "(all Catalyst 9K platform internal names); "
            "(4) `.SW_DESCRIPTION` fields reference intermediate CSC bug IDs "
            "(`CSCWU69080` in CSCwt88239, `CSCWU82064` in CSCwv26786) -- "
            "these are the upstream commits the patch was based on; "
            "(5) `.PKGUID` SHA1 hashes and build timestamps. "
            "The codename mapping enables cross-version vulnerability correlation: "
            "any finding in `bigbang` (Cat9300) applies to the same silicon in "
            "`passport` (Cat9200) and `symphony` (Cat9500) when the code path is shared."
        ),
        "evidence": {
            "build_user":  "mcpre",
            "build_path":  "/nobackup/mcpre/release/BLD-V1715_6_CSCWT88239_15_FC1/binos/...",
            "codenames":   ["passport", "nyquist", "bigbang", "symphony", "starfleet"],
            "upstream_csc": ["CSCWU69080 (CSCwt88239 base)", "CSCWU82064 (CSCwv26786 base)"],
            "pkg_uid":     "b8569dd13b0aa3fe9fb38206f5fe2dcaabb12d37 (CSCwt88239)",
        },
        "impact": [
            "Codename mapping aids cross-platform vulnerability applicability analysis",
            "Upstream CSC IDs expose prior unpatched defect history",
            "Build path structure reveals Cisco's internal release engineering tree layout",
        ],
        "remediation": "Strip build metadata fields (BuildPath, SW_DESCRIPTION upstream references) from released SMU pkginfo.",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 1,
    "high":     0,
    "medium":   1,
    "low":      2,
    "note": (
        "F1 is the primary finding: day0.cfg in c2960l TAR ships privilege-15 backdoor "
        "account `smartm:c2960lsm` in cleartext (type 0). "
        "Applied automatically on factory-new or factory-reset switches. "
        "c3560cx does not include day0.cfg; the c2960l is specifically targeted by Smart Install. "
        "F2 (CSCwt88239 IDPROM memcpy) requires physical line card insertion but patches "
        "a memcpy size derived from hardware EEPROM content -- unusual for a stability SMU. "
        "Cat9K codenames confirmed: passport=Cat9200, nyquist=?, bigbang=Cat9300, "
        "symphony=Cat9500, starfleet=Cat9600 (inferred from prior Cat9K RE sessions)."
    ),
}
