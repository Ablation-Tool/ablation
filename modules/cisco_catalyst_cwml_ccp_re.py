"""
Cisco Catalyst CWML (Cisco Configuration Professional for Catalyst) RE Module
Targets:
  - c2960c405-cwml.01_08_03.tar: CWML 1.8.3 for 2960C/2960S (AngularJS web management UI)
  - c2960l-cwml.01_08_03.tar: CWML 1.8.3 for 2960L (same codebase, different device profile)
Source: /media/cowboy/research/Cisco-Catalyst/
Extracted: /tmp/cwml_c2960c/ (c2960c405 archive)
"""

METADATA = {
    "targets": {
        "c2960c405_cwml": {
            "archive":   "c2960c405-cwml.01_08_03.tar",
            "version":   "CWML 1.8.3 (01_08_03)",
            "models":    ["Cisco Catalyst 2960C", "Cisco Catalyst 2960S", "Cisco Catalyst 2960"],
            "framework": "AngularJS (JavaScript SPA, runs in-browser connected to IOS HTTP server)",
            "delivery":  "Bundled in IOS image, served by IOS embedded HTTP server",
            "copyright": "Copyright (c) 2019 by Cisco Systems, Inc. + Inspur ICNT, Inc.",
        },
        "c2960l_cwml": {
            "archive":   "c2960l-cwml.01_08_03.tar",
            "version":   "CWML 1.8.3 (01_08_03)",
            "models":    ["Cisco Catalyst 2960L"],
            "framework": "AngularJS (same codebase as c2960c405)",
        },
    },
    "key_files": {
        "config.js":                  "Product branding config; dual Cisco + Inspur identity",
        "day0/wizard/dayzeroController.js": "Day-0 wizard; device type detection; inspurDevice toggle",
        "day0/wizard/StepCtrls/wifiCtrl.js": "WiFi setup; admin password stored as Base64",
        "day0/wizard/StepCtrls/summaryScreenCtrl.js": "CLI generation; transport input all option",
        "features/troubleShoot/troubleShootController.js": "CSRF token harvest; hidden_command POST",
        "day0/js/deviceCommunicator.js": "IOS command execution endpoint; COMMANDSET VERSION 1.0",
        "day0/wizard/helpController.js": "Inspur device detection; deviceOwner toggle",
    },
    "ios_command_endpoint": {
        "url":     "/ios_web_exec/commandset",
        "format":  "COMMANDSET VERSION=1.0; CMD <command>; END_OF_COMMANDSET",
        "auth":    "IOS HTTP basic auth + CSRF token from session",
        "priv15":  "/level/15/exec/-/ URL prefix for privilege-15 commands",
    },
    "inspur_models": ["S6650L", "S5960"],
    "inspur_copyright": "Copyright (c) 2019 by ICNT, Inc.",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "Inspur ODM Variant Code in Standard Cisco Catalyst 2960 Firmware -- S6650L/S5960 Detection and Chinese ICM Branding",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-912",
        "description": (
            "The CWML 1.8.3 web management UI bundled in standard Cisco Catalyst 2960C "
            "and 2960L firmware contains code paths for a Chinese ODM product variant. "
            "`config.js` declares dual product branding: "
            '`productName="Cisco Configuration Professional for Catalyst"` and '
            '`productNameInspur="Inspur Configuration Manager"` with '
            '`productNameInspurChinese="\\u6d6a\\u6f6e\\u667a\\u80fd\\u7ba1\\u7406\\u7cfb\\u7edf"` '
            "(simplified Chinese: Inspur Intelligent Management System). "
            "`dayzeroController.js` detects the Inspur variant by parsing `show version` "
            "output for model strings `S6650L` or `S5960`: "
            "`if(versionInfo.ShowVersion.name.indexOf('S6650L') != -1 || "
            "versionInfo.ShowVersion.name.indexOf('S5960') != -1){ "
            "$scope.ciscoDevice=false; $scope.inspurDevice=true; }`. "
            "`helpController.js` sets `$scope.deviceOwner='inspur'` for the same model "
            "strings. The ODM vendor Inspur (ICNT = Inspur Computer Networks Technology) "
            "is a Chinese state-affiliated enterprise. Standard Cisco firmware "
            "unconditionally ships this detection and branding code regardless of "
            "customer geography, providing a software attestation that Inspur hardware "
            "and Cisco hardware share the same CWML codebase."
        ),
        "evidence": {
            "config.js_branding": {
                "productNameInspur":        "Inspur Configuration Manager",
                "productNameInspurChinese": "浪潮智能管理系统",
                "copyRightInspur":          "Copyright (c) 2019 by ICNT, Inc.",
            },
            "dayzeroController.js": (
                "if(versionInfo.ShowVersion.name.indexOf('S6650L') != -1 || "
                "versionInfo.ShowVersion.name.indexOf('S5960') != -1){"
                "$scope.ciscoDevice=false; $scope.inspurDevice=true;}"
            ),
            "helpController.js": "$scope.deviceOwner='inspur'",
        },
        "inspur_models":     ["S6650L (Inspur S6650L Catalyst-class switch)", "S5960 (Inspur S5960 access switch)"],
        "inspur_vendor":     "ICNT (Inspur Computer Networks Technology Co., Ltd.) - Chinese state-affiliated ODM",
        "impact": [
            "Standard Cisco firmware ships Chinese ODM vendor code paths unconditionally",
            "Supply chain visibility: Inspur S6650L/S5960 share Cisco CWML codebase",
            "If Inspur hardware is deployed in restricted environments, the shared codebase creates SCRM (supply chain risk) exposure",
        ],
        "remediation": (
            "Cisco should publish documentation disclosing the Inspur ODM relationship "
            "and which product SKUs are sourced from ICNT. Customers in restricted "
            "environments should verify hardware provenance before deployment. "
            "Cisco should strip ODM detection code from standard Catalyst firmware "
            "or explicitly disclose the dual-vendor code path."
        ),
        "yara": """rule cisco_cwml_inspur_odm_variant {
    meta:
        description = "Cisco CWML firmware contains Inspur ODM variant code (S6650L/S5960 detection)"
        severity = "MEDIUM"
    strings:
        $inspur_mgr   = "Inspur Configuration Manager" ascii wide
        $inspur_cn    = "\\u6d6a\\u6f6e\\u667a\\u80fd" ascii
        $icnt_copy    = "Copyright (c) 2019 by ICNT" ascii
        $s6650l       = "S6650L" ascii
        $s5960        = "S5960" ascii
        $inspur_dev   = "inspurDevice=true" ascii
    condition:
        2 of them
}""",
    },
    {
        "id": "F2",
        "title": "WiFi Admin Password Stored as Base64 (atob) in Day-0 Wizard -- Reversible Encoding Used as Obfuscation",
        "severity": "LOW",
        "cvss": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-261",
        "description": (
            "The day-0 configuration wizard in CWML stores the WiFi admin password "
            "using Base64 encoding, which provides no security benefit. "
            "`day0/wizard/StepCtrls/wifiCtrl.js` line: "
            "`$scope.wzModel.wifi.adminPassword=atob(userData.user.password)`. "
            "The `atob()` JavaScript function is the standard base64 decoder -- "
            "the password is stored encoded on the server side and decoded "
            "client-side before use. Any attacker who obtains the stored user "
            "data (via IOS `show running-config`, config backup, or management "
            "API) recovers the plaintext password by base64-decoding the value. "
            "This is trivially reversible with `echo <encoded> | base64 -d` and "
            "does not constitute encryption."
        ),
        "evidence": {
            "file": "day0/wizard/StepCtrls/wifiCtrl.js",
            "code": "$scope.wzModel.wifi.adminPassword=atob(userData.user.password)",
        },
        "impact": [
            "WiFi admin password recoverable from any stored config backup or running-config export",
            "Base64 is not encryption; no key material is involved -- recovery requires no credentials",
        ],
        "remediation": (
            "Store WiFi admin credentials using a proper key derivation function "
            "or IOS native credential store (type 6 or type 9 passwords). "
            "Do not transmit or store passwords as Base64."
        ),
        "yara": """rule cisco_cwml_base64_password_storage {
    meta:
        description = "Cisco CWML day-0 wizard uses atob() Base64 for password storage"
        severity = "LOW"
    strings:
        $atob_pwd = "atob(userData.user.password)" ascii
    condition:
        $atob_pwd
}""",
    },
    {
        "id": "F3",
        "title": "Day-0 Wizard Generates IOS Config with Telnet Enabled -- transport input all Default in Wizard Output",
        "severity": "LOW",
        "cvss": 3.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-319",
        "description": (
            "The day-0 configuration wizard in CWML 1.8.3 generates IOS configuration "
            "that includes `transport input all` for VTY lines, enabling Telnet access "
            "in addition to SSH. `day0/wizard/StepCtrls/summaryScreenCtrl.js` "
            "includes `transport input all` in the generated CLI block, which "
            "is appended to the device configuration during wizard completion. "
            "Telnet transmits all authentication credentials and session data "
            "in cleartext. A switch configured via the CWML day-0 wizard will "
            "accept Telnet connections by default, creating a credential exposure "
            "risk on the management network."
        ),
        "evidence": {
            "file": "day0/wizard/StepCtrls/summaryScreenCtrl.js",
            "config_fragment": "transport input all",
            "context": "Generated in VTY line configuration block during wizard completion",
        },
        "impact": [
            "Switches configured via CWML day-0 accept Telnet by default",
            "Management credentials transmitted in cleartext over Telnet sessions",
            "Any host on the management VLAN can passively capture enable passwords and commands",
        ],
        "remediation": (
            "Change the CWML wizard default to `transport input ssh` only. "
            "Audit existing switches configured via CWML wizard for `transport input all` "
            "and restrict to SSH: `line vty 0 15 / transport input ssh`."
        ),
        "yara": """rule cisco_cwml_telnet_enabled_wizard {
    meta:
        description = "Cisco CWML wizard generates IOS config with transport input all (Telnet enabled)"
        severity = "LOW"
    strings:
        $transport_all = "transport input all" ascii
        $cwml_context  = "summaryScreen" ascii
    condition:
        all of them
}""",
    },
    {
        "id": "F4",
        "title": "CSRF Token-Gated hidden_command POST to /level/15/exec/- -- Authenticated IOS Command Execution via Diagnostic Endpoint",
        "severity": "LOW",
        "cvss": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-352",
        "description": (
            "The CWML troubleshoot module implements a diagnostic command execution "
            "path using a CSRF token extracted from an HTML page. "
            "`features/troubleShoot/troubleShootController.js` extracts a 40-character "
            "hex token (SHA1-sized) from the HTML response of the IOS HTTP server, "
            "then submits it as `hidden_command` in a POST to "
            "`/level/15/exec/-/diagnostic/start/test/basic`. "
            "The CSRF token is the sole access gate: any attacker who obtains the "
            "token via XSS, MITM, or session theft can execute arbitrary privilege-15 "
            "diagnostics. IOS privilege-15 commands include `show tech-support` "
            "(full device state dump) and `debug` commands that can affect forwarding "
            "plane performance. The `hidden_command` field name in the POST body "
            "is noteworthy: it implies the command is intentionally not surfaced "
            "in normal UI flows."
        ),
        "evidence": {
            "file":     "features/troubleShoot/troubleShootController.js",
            "endpoint": "/level/15/exec/-/diagnostic/start/test/basic",
            "method":   "POST with hidden_command field containing CSRF token",
            "token":    "40-char hex SHA1 extracted from HTML response body",
        },
        "impact": [
            "CSRF token theft enables privilege-15 IOS command execution without re-authentication",
            "show tech-support exposes full device configuration, routing tables, and ARP cache",
            "debug commands via hidden_command can degrade forwarding performance under load",
        ],
        "remediation": (
            "Add per-request CSRF tokens that are not reusable. "
            "Rate-limit the /level/15/exec/- endpoint. "
            "Require re-authentication for debug and diagnostic commands "
            "in addition to CSRF token verification."
        ),
        "yara": """rule cisco_cwml_hidden_command_csrf {
    meta:
        description = "Cisco CWML troubleshoot controller uses CSRF token for hidden_command diagnostic POST"
        severity = "LOW"
    strings:
        $hidden_cmd   = "hidden_command" ascii
        $level15      = "/level/15/exec/-/" ascii
        $csrf_extract = "troubleShoot" ascii
    condition:
        2 of them
}""",
    },
    {
        "id": "F5",
        "title": "IOS Command Execution Architecture via /ios_web_exec/commandset -- COMMANDSET Version 1.0 Protocol Documented in Client JS",
        "severity": "INFORMATIONAL",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The CWML client-side JavaScript (`day0/js/deviceCommunicator.js`) "
            "documents the IOS embedded HTTP server command execution protocol. "
            "The endpoint `CMD_HTTP_URL = '/ios_web_exec/commandset'` accepts "
            "POST requests with body format: `COMMANDSET VERSION=\\\"1.0\\\"; "
            "CMD <ios-command>; END_OF_COMMANDSET`. This is the primary mechanism "
            "CWML uses to execute IOS CLI commands from the browser-based management "
            "interface. The format strings reveal the COMMANDSET protocol version "
            "and delimiter structure. While this endpoint requires authentication "
            "(IOS HTTP basic auth), the protocol is fully documented in the "
            "client-side JS, eliminating any security-through-obscurity protection. "
            "Combined with the F4 hidden_command path and F3 Telnet-enabled config, "
            "the full command execution surface is visible to any analyst with "
            "access to the CWML tar archive."
        ),
        "evidence": {
            "file":          "day0/js/deviceCommunicator.js",
            "endpoint":      "/ios_web_exec/commandset",
            "protocol":      'COMMANDSET VERSION="1.0"; CMD <command>; END_OF_COMMANDSET',
            "priv15_prefix": "/level/15/exec/-/",
        },
        "impact": [
            "Full IOS CLI command execution protocol documented in client-side JS (no reverse engineering needed)",
            "Useful for building offline IOS management tools or exploit PoC against the embedded HTTP server",
        ],
        "remediation": (
            "This is an architectural documentation finding. Restricting access to "
            "the IOS HTTP server (disable HTTP: `no ip http server`, use HTTPS only: "
            "`ip http secure-server`) eliminates the attack surface entirely."
        ),
        "yara": """rule cisco_ios_commandset_protocol {
    meta:
        description = "Cisco CWML documents IOS /ios_web_exec/commandset protocol in client JS"
        severity = "INFORMATIONAL"
    strings:
        $cmd_url   = "/ios_web_exec/commandset" ascii
        $cmdset    = "COMMANDSET VERSION" ascii
        $end_cmd   = "END_OF_COMMANDSET" ascii
    condition:
        $cmd_url and $cmdset
}""",
    },
]

SUMMARY = {
    "total":         5,
    "critical":      0,
    "high":          0,
    "medium":        1,
    "low":           3,
    "informational": 1,
    "note": (
        "Primary finding is the Inspur ODM variant code (F1) embedded unconditionally "
        "in standard Cisco Catalyst 2960C/2960L firmware. Cisco ships S6650L/S5960 "
        "detection and Chinese ICM branding in every CWML 1.8.3 archive regardless "
        "of customer geography. F2-F5 are standard web management issues (Base64 "
        "password encoding, Telnet-enabling wizard, CSRF-gated command execution, "
        "command protocol disclosure)."
    ),
}
