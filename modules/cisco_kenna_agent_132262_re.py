"""
Cisco Kenna Security Agent 1.3.2262 RE Module
Target: kenna-agent-1.3.2262-1.x86_64.rpm (8.0MB, RPM v3.0)
Extracted: /tmp/kenna/
  - /usr/bin/kenna-agent: Go binary (statically linked, debug_info, NOT stripped)
  - /etc/kenna-agent/kenna-agent.toml: TOML configuration template
  - /lib/systemd/system/kenna-agent.service: systemd unit
Source: /media/cowboy/research/Cisco-UCS/other/kenna-agent-1.3.2262-1.x86_64.rpm
"""

METADATA = {
    "target":      "Cisco Kenna Security Agent 1.3.2262",
    "purpose":     "Vulnerability scan data broker: pulls from enterprise scanners, uploads to Kenna Security SaaS",
    "binary":      "/usr/bin/kenna-agent (Go statically linked, 8MB, with debug_info, NOT stripped)",
    "go_build_id": "rtqiylHQA-E-RTi3Beko/5w7vk-pTYFbw4rSMwWtW/ug3e8Eyh25mWM5VBjjXX/_X0DObqbEi8YNCOMERII",
    "build_flags": "-ldflags=-X main.version=1.3.2262 -X main.sha1=3568912 -X config.DebugAllowed=false",
    "version_sha": "3568912",
    "systemd": {
        "type":           "simple",
        "user":           "DynamicUser=yes (transient UID)",
        "isolation":      "PrivateTmp=yes, PrivateDevices=yes",
        "restart":        "on-failure (60s delay)",
    },
    "connectors_supported": [
        "Nexpose", "Nessus", "AppScan Enterprise", "Checkmarx", "BlackDuck", "SecurityCenter",
    ],
    "api_endpoint":  "https://api.kennasecurity.com/",
    "user_agent":    "kenna-security-agent/1.3.2262 (https://www.kennasecurity.com/)",
    "telemetry":     "Datadog APM (DD_TRACE_ANALYTICS_ENABLED, DD_RUNTIME_METRICS_ENABLED)",
    "go_pkg":        "github.com/KennaSecurity/agent/internal/connector",
}

FINDINGS = [
    {
        "id": "F1",
        "title": "validate_ssl = false Option in Kenna Agent Scanner Connector Config -- TLS Verification Bypass for Scan Data Ingestion",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-295",
        "description": (
            "The Kenna Agent TOML configuration template explicitly documents "
            "`validate_ssl = false` as a supported option for scanner connector "
            "connections. The config comment states: "
            "`## Set this to false for self-signed certs`. "
            "When disabled, the agent accepts any TLS certificate presented by "
            "the configured scanner (Nexpose, Nessus, SecurityCenter, etc.) "
            "without verification. Vulnerability scan data ingested from a "
            "scanner with unverified TLS is susceptible to MITM injection: "
            "an on-path attacker can serve fabricated vulnerability findings "
            "that the Kenna agent uploads to the Kenna SaaS risk intelligence platform. "
            "Fabricated findings could inflate or deflate risk scores, "
            "causing the security team to deprioritize critical vulnerabilities "
            "or waste resources on non-existent issues. "
            "The option is presented without a security warning in the config template."
        ),
        "evidence": {
            "file":    "/etc/kenna-agent/kenna-agent.toml",
            "option":  "validate_ssl = false",
            "comment": "## Set this to false for self-signed certs",
        },
        "impact": [
            "MITM of scanner TLS connection allows injection of fabricated vulnerability data",
            "Kenna risk scores derived from injected scan data mislead security prioritization",
            "Operators who set validate_ssl=false for convenience (self-signed certs) expose production risk intelligence",
        ],
        "remediation": (
            "Add an explicit warning in the config template that validate_ssl=false "
            "is insecure in production. Implement a CA-file option for self-signed "
            "scanner certs instead of disabling verification entirely. "
            "Audit existing Kenna agent deployments for validate_ssl=false."
        ),
        "yara": """rule cisco_kenna_agent_ssl_bypass_config {
    meta:
        description = "Kenna agent config template supports validate_ssl=false for scanner connections"
        severity = "MEDIUM"
    strings:
        $ssl_bypass = "validate_ssl = false" ascii
        $kenna_api  = "api.kennasecurity.com" ascii
    condition:
        $ssl_bypass and $kenna_api
}""",
    },
    {
        "id": "F2",
        "title": "Datadog APM Telemetry Embedded in Kenna Agent Binary -- Third-Party APM Receives Runtime Metrics from Enterprise Networks",
        "severity": "LOW",
        "cvss": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-359",
        "description": (
            "The Kenna agent binary embeds the Datadog APM tracing library "
            "(`DD_TRACE_ANALYTICS_ENABLED`, `DD_RUNTIME_METRICS_ENABLED`, "
            "`datadog.tracer.flush_bytes`). If the agent is deployed with "
            "Datadog environment variables configured, the binary sends "
            "runtime performance metrics (goroutine counts, memory stats, "
            "GC cycles) and trace data to Datadog's SaaS platform. "
            "The agent runs inside enterprise networks processing vulnerability "
            "scan data. Any telemetry exfiltration path from enterprise networks "
            "to external SaaS (beyond the already-documented Kenna API upload) "
            "requires explicit review in high-security environments. "
            "Datadog telemetry is typically disabled unless configured via environment "
            "variables, but the compiled-in library expands the agent's external "
            "communication surface without documentation in the config template."
        ),
        "evidence": {
            "strings": [
                "DD_TRACE_ANALYTICS_ENABLED",
                "DD_RUNTIME_METRICS_ENABLED",
                "datadog.tracer.flush_bytes",
            ],
            "config_documented": False,
        },
        "impact": [
            "If DD_TRACE_ANALYTICS_ENABLED=true, agent sends trace data to Datadog from enterprise network",
            "Undisclosed third-party telemetry dependency (not documented in agent config template)",
            "Agent binary attack surface includes Datadog APM library codebase",
        ],
        "remediation": (
            "Document the Datadog APM dependency in the agent release notes. "
            "Ensure the systemd unit or deployment documentation specifies that "
            "Datadog telemetry is disabled by default. "
            "In air-gapped or high-security environments, block outbound connections "
            "to Datadog endpoints if the agent is deployed."
        ),
        "yara": """rule cisco_kenna_agent_datadog_telemetry {
    meta:
        description = "Kenna agent binary contains embedded Datadog APM telemetry library"
        severity = "LOW"
    strings:
        $dd_trace   = "DD_TRACE_ANALYTICS_ENABLED" ascii
        $dd_metrics = "DD_RUNTIME_METRICS_ENABLED" ascii
        $kenna_pkg  = "KennaSecurity/agent" ascii
    condition:
        $dd_trace and $kenna_pkg
}""",
    },
    {
        "id": "F3",
        "title": "Kenna Agent Binary Not Stripped -- Full Go Symbol Table and Debug Info in Production RPM",
        "severity": "LOW",
        "cvss": 2.5,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "The Kenna agent RPM ships `kenna-agent` as an unstripped Go binary "
            "with full debug information (`with debug_info, not stripped` per `file`). "
            "The binary contains: complete Go symbol table with all internal package "
            "paths (`github.com/KennaSecurity/agent/internal/connector`, "
            "`internal/config.DebugAllowed`), function names for all internal "
            "operations, type information for all connector types "
            "(Nessus, Nexpose, AppScan, Checkmarx, BlackDuck, SecurityCenter), "
            "and internal field names for credential structures "
            "(`connector.NessusClient`, `connector.stringSet`). "
            "This metadata accelerates reverse engineering and vulnerability "
            "discovery in the agent itself, and exposes internal connector "
            "implementation details that could aid in crafting malformed scanner "
            "response data to trigger protocol handling bugs."
        ),
        "evidence": {
            "binary":     "/usr/bin/kenna-agent",
            "file_output": "ELF 64-bit, statically linked, Go BuildID, with debug_info, not stripped",
            "symbols":    ["connector.NessusClient", "connector.stringSet", "connector.runResultsImpl"],
        },
        "impact": [
            "Full symbol table exposes internal connector architecture, accelerating vulnerability research",
            "Type names for credential structures visible without disassembly",
            "Build metadata (sha1=3568912, version=1.3.2262) enables version-specific exploit targeting",
        ],
        "remediation": "Strip the production binary: `strip /usr/bin/kenna-agent` or add `-ldflags=-s -w` to Go build.",
    },
]

SUMMARY = {
    "total":    3,
    "critical": 0,
    "high":     0,
    "medium":   1,
    "low":      2,
    "note": (
        "Primary concern is the validate_ssl=false option (F1) which can corrupt "
        "vulnerability scan data uploaded to Kenna SaaS if enabled with a MITM. "
        "Datadog APM (F2) and unstripped binary (F3) are informational surface-expansion "
        "findings. No authentication bypass or RCE found in agent binary."
    ),
}
