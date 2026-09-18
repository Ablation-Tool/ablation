"""
Kenna Security Agent RE Module
Target: kenna-agent (Go binary, x86-64, statically linked, NOT stripped)
Version: v1.31.1 (Go runtime)
Source: /media/cowboy/research/Cisco-UCS/ (RPM package)
Extracted to: /tmp/kenna-agent-extract/usr/bin/kenna-agent
"""

METADATA = {
    "target":         "Kenna Security Agent",
    "binary":         "kenna-agent",
    "arch":           "x86-64 ELF, statically linked, NOT stripped (debug_info present)",
    "language":       "Go",
    "go_runtime":     "v1.31.1",
    "go_buildid":     "rtqiylHQA-E-RTi3Beko/5w7vk-pTYFbw4rSMwWtW/ug3e8Eyh25mWM5VBjjXX/_X0DObqbEi8YNCOMERII",
    "config_file":    "/etc/kenna-agent/kenna-agent.toml",
    "source":         "/media/cowboy/research/Cisco-UCS/",
    "integrations":   ["Nexpose", "Nessus", "AppScan Enterprise", "Tenable SecurityCenter",
                       "Checkmarx SAST", "Sonatype Nexus IQ"],
    "third_party":    ["Datadog APM (datadog-go tracer)", "msgpack"],
}

FINDINGS = [
    {
        "id": "F1",
        "title": "validate_ssl = false Maps Directly to InsecureSkipVerify in TLS Config",
        "severity": "HIGH",
        "cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-295",
        "description": (
            "The TOML config field `validate_ssl` tagged `toml:\"validate_ssl\"` "
            "is passed directly into Go's `tls.Config.InsecureSkipVerify`. The "
            "shipped default config template `/etc/kenna-agent/kenna-agent.toml` "
            "has this field commented out, but the example comments show "
            "`#validate_ssl = false`. A deployer who uncomments this line disables "
            "all TLS certificate validation for connections to scanner endpoints "
            "(Nexpose, AppScan, SecurityCenter, Checkmarx). The binary confirms "
            "the mapping: `toml:\"validate_ssl\"` and `InsecureSkipVerify` strings "
            "both present in the same TLS configuration path."
        ),
        "trigger_strings": [
            'toml:"validate_ssl"',
            "InsecureSkipVerify",
            "Notice, hostname verification disabled",
            "tls: either ServerName or InsecureSkipVerify must be specified",
        ],
        "config_evidence": {
            "file": "/etc/kenna-agent/kenna-agent.toml",
            "relevant_lines": [
                "[connector.example]",
                "#validate_ssl = false",
            ],
        },
        "impact": [
            "MITM of all scanner API traffic when validate_ssl=false",
            "Attacker serves malicious scan results; agent uploads poisoned findings to Kenna platform",
            "Scanner credentials (API keys, passwords) in request headers exposed to MITM",
        ],
        "remediation": (
            "Remove validate_ssl from default config entirely. Enforce certificate "
            "validation at the Go http.Transport level regardless of config value. "
            "If a self-signed cert is needed, accept a cert pinning path, not a "
            "global InsecureSkipVerify toggle."
        ),
        "yara": """rule kenna_agent_tls_skip_verify {
    meta:
        description = "Kenna agent validate_ssl=false maps to InsecureSkipVerify"
        severity = "HIGH"
    strings:
        $validate_ssl     = { 76 61 6c 69 64 61 74 65 5f 73 73 6c }  // "validate_ssl"
        $insecure_skip    = "InsecureSkipVerify" ascii
        $hostname_warn    = "Notice, hostname verification disabled" ascii
    condition:
        $insecure_skip and ($validate_ssl or $hostname_warn)
}""",
    },
    {
        "id": "F2",
        "title": "Zip and Tar Archive Extraction from Scanner Endpoints Without Path Sanitization",
        "severity": "HIGH",
        "cvss": 7.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-22",
        "description": (
            "The agent downloads zip and tar archives from scanner endpoints "
            "(Nexpose `GET /scans/%d/export/%d/status`, AppScan Enterprise "
            "`/CxRestAPI/reports/sastScan/%d`) and extracts them to a "
            "temp directory (`json:\"tempdir\"`, `os.TempDir`). The Go standard "
            "library emits `archive/zip.zipinsecurepath` and `tarinsecurepath` "
            "errors when archive entries contain `../` path components, but only "
            "if the `GODEBUG=zipinsecurepath=0` flag is set (default since Go "
            "1.20). If the agent was built with an older GODEBUG default, or if "
            "the scanner is compromised/spoofed, a crafted archive with "../" "
            "entries writes files outside the temp directory as the agent's "
            "runtime user. Combined with F1 (validate_ssl bypass), a MITM can "
            "serve a poisoned archive."
        ),
        "trigger_strings": [
            "archive/zip.zipinsecurepath",
            "tarinsecurepath",
            'json:"tempdir"',
            "Failed to create temp file",
            "Failed to remove temp file",
            "Copy to temporary file incomplete",
            "/scans/%d/export/%d/status",
            "/CxRestAPI/reports/sastScan/%d",
        ],
        "attack_chain": [
            "1. Deploy with validate_ssl=false (F1) or MITM scanner TLS",
            "2. Intercept GET /scans/<id>/export/<id>/status response",
            "3. Serve zip archive with ../../../etc/cron.d/backdoor entry",
            "4. Agent extracts archive; cron job lands outside tempdir as agent user",
        ],
        "impact": [
            "Arbitrary file write on agent host with agent process privileges",
            "If agent runs as root (common for vulnerability scanner integrations), full host compromise",
            "Persistent backdoor via cron or authorized_keys",
        ],
        "remediation": (
            "Explicitly reject archive entries with absolute paths or `..` components "
            "before extraction. Use `filepath.Clean` + confirm the resolved path "
            "starts with the intended temp directory. Set GODEBUG=zipinsecurepath=0 "
            "in the agent's launch environment."
        ),
        "yara": """rule kenna_agent_archive_path_traversal {
    meta:
        description = "Kenna agent downloads and extracts archives from scanner endpoints"
        severity = "HIGH"
    strings:
        $zip_path   = "archive/zip.zipinsecurepath" ascii
        $tar_path   = "tarinsecurepath" ascii
        $tempdir    = { 6a 73 6f 6e 3a 22 74 65 6d 70 64 69 72 22 }  // json:"tempdir"
        $scan_ep    = "/scans/%d/export/%d/status" ascii
    condition:
        ($zip_path or $tar_path) and ($tempdir or $scan_ep)
}""",
    },
    {
        "id": "F3",
        "title": "Datadog APM Tracer Embedded - DD_TRACE_AGENT_HOST Leaks Request Spans",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The agent embeds the Datadog APM tracer (`datadog.tracer.*` metrics, "
            "`DD_TRACE_ANALYTICS_ENABLED`, `DD_RUNTIME_METRICS_ENABLED`, "
            "`datadog.tracer.flush_bytes/traces/errors`). If `DD_TRACE_AGENT_HOST` "
            "is set (either in the environment or via a compromised config), all "
            "trace spans - which include HTTP request URLs, response codes, headers, "
            "and partial bodies - are sent to the specified host. An attacker who "
            "can control this environment variable (via a compromised orchestration "
            "layer or container escape) receives the agent's full API interaction log "
            "including scanner credentials in request headers."
        ),
        "trigger_strings": [
            "DD_TRACE_ANALYTICS_ENABLED",
            "DD_RUNTIME_METRICS_ENABLED",
            "datadog.tracer.flush_bytes",
            "datadog.tracer.flush_traces",
            "datadog.tracer.decode_error",
            "Stats channel full, disregarding span.",
            "payload queue full, dropping %d traces",
        ],
        "impact": [
            "Scanner API keys/credentials leaked to attacker-controlled Datadog agent",
            "Full request/response tracing data exfiltrated",
            "Internal scanner hostnames and scan data exposed",
        ],
        "remediation": (
            "Document the DD_TRACE_* environment variable attack surface. "
            "Restrict the agent's environment so DD_TRACE_AGENT_HOST cannot be "
            "overridden by untrusted processes. If APM is not required, build "
            "without the datadog-go tracer dependency."
        ),
        "yara": """rule kenna_agent_datadog_apm_embedded {
    meta:
        description = "Kenna agent embeds Datadog APM tracer - DD_TRACE env vars leak spans"
        severity = "MEDIUM"
    strings:
        $dd_trace   = "DD_TRACE_ANALYTICS_ENABLED" ascii
        $dd_runtime = "DD_RUNTIME_METRICS_ENABLED" ascii
        $flush_b    = "datadog.tracer.flush_bytes" ascii
        $trace_host = "DD_TRACE_AGENT_HOST" ascii nocase
    condition:
        2 of them
}""",
    },
    {
        "id": "F4",
        "title": "Kenna API Token Required but Config Template Ships Commented-Out",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-522",
        "description": (
            "The error string `'kenna' section missing required 'token'` means "
            "the agent fails at startup if the Kenna API token is absent. The "
            "default config template ships with `#token = \"abc123\"` commented out. "
            "A deployer who edits the config may leave the token in the file, "
            "which is a plaintext file at `/etc/kenna-agent/kenna-agent.toml` "
            "with broad read permissions. Additionally, the keyfile path "
            "`Expected the keyfile to contain a string of the form, "
            "AES256:<encryption key>` suggests AES256-encrypted keyfiles are "
            "supported but are not the default - the default stores the token "
            "in plaintext TOML."
        ),
        "trigger_strings": [
            "'kenna' section missing required 'token'",
            "Expected the keyfile to contain a string of the form, 'AES256:<encryption key>'",
            "Error sending logs to Kenna Security: %s",
        ],
        "impact": [
            "Kenna platform API token readable by any user with access to /etc/kenna-agent/",
            "Token allows submitting false vulnerability findings to Kenna platform",
        ],
        "remediation": (
            "Store the API token as an AES256-encrypted keyfile, not plaintext TOML. "
            "Set config file permissions to 0600 owned by the agent service user. "
            "Document the AES256 keyfile path option prominently."
        ),
        "yara": """rule kenna_agent_plaintext_token_config {
    meta:
        description = "Kenna agent expects API token in plaintext TOML config"
        severity = "MEDIUM"
    strings:
        $missing_token = "'kenna' section missing required 'token'" ascii
        $aes256_key    = "AES256:<encryption key>" ascii
        $config_file   = "/etc/kenna-agent/kenna-agent.toml" ascii
    condition:
        $missing_token and $config_file
}""",
    },
]

SUMMARY = {
    "total":    4,
    "critical": 0,
    "high":     2,
    "medium":   2,
    "low":      0,
}
