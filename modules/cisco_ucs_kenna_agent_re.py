"""
Cisco CVM (Vulnerability Management) kenna-agent 1.3.2262 RE

Target:  kenna-agent-1.3.2262-1.x86_64.rpm
         (Cisco Vulnerability Management, formerly Kenna Security)
Binary:  /usr/bin/kenna-agent (ELF64, Go 1.31.1, statically linked, not stripped)
Service: kenna-agent.service (DynamicUser=yes, PrivateTmp=yes, PrivateDevices=yes)
Config:  /etc/kenna-agent/kenna-agent.toml (0644 world-readable)
Session: 38
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_kenna_agent_re",
    "firmware": "kenna-agent-1.3.2262-1.x86_64.rpm (Cisco CVM / Kenna Security Agent)",
    "components": {
        "/usr/bin/kenna-agent": (
            "Go 1.31.1 static binary, not stripped; "
            "integrates with Nexpose, Nessus, AppScan Enterprise, Checkmarx; "
            "BuildID=rtqiylHQA-E-RTi3Beko/..."
        ),
        "/etc/kenna-agent/kenna-agent.toml": (
            "TOML config; stores Kenna API token and scanner credentials; "
            "0644 permissions (world-readable)"
        ),
        "/lib/systemd/system/kenna-agent.service": (
            "systemd unit; DynamicUser=yes, PrivateTmp=yes, PrivateDevices=yes"
        ),
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 2, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 61, "HIGH": 229, "MEDIUM": 223, "LOW": 192},
    "cumulative_total": 705,
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": (
            "Kenna API Token and Scanner Credentials Stored in World-Readable "
            "/etc/kenna-agent/kenna-agent.toml (0644)"
        ),
        "component": "/etc/kenna-agent/kenna-agent.toml",
        "evidence": {
            "file_permissions": "0644 (-rw-r--r--) as installed by RPM",
            "config_contents": (
                "[kenna]\n"
                "# Kenna Security API Token\n"
                "token = \"abc123\"   # <-- live token after deployment\n"
                "\n"
                "[connector.example]\n"
                "id = 111\n"
                "type = \"nexpose\"  # or nessus, appscan, checkmarx, etc.\n"
                "url = \"https://nexpose.example.com:5917\"\n"
                "username = \"user\"\n"
                "password = \"pass\"  # <-- plaintext unless keyfile configured\n"
                "validate_ssl = false"
            ),
            "optional_keyfile": (
                "The agent supports optional AES-256 encryption via a keyfile: "
                "'Expected the keyfile to contain a string of the form, "
                "AES256:<encryption key>'. "
                "The keyfile field is optional (toml:\"keyfile\") -- "
                "without it, credentials are stored in plaintext in the 0644 file."
            ),
            "scanners_supported": [
                "Nexpose (Rapid7) -- /api/3/ endpoints",
                "Nessus (Tenable) -- /scans/%d/export",
                "AppScan Enterprise (HCL) -- /ase/api/login",
                "Checkmarx SAST -- /CxRestAPI/sast/scans",
            ],
        },
        "impact": (
            "The kenna-agent TOML config is installed world-readable (0644). "
            "Any local user on a host running kenna-agent can read the Kenna API token "
            "and all configured scanner credentials (usernames, passwords, URLs). "
            "The Kenna API token provides access to the organization's full "
            "vulnerability dataset at api.kennasecurity.com, including asset exposure "
            "data, vulnerability findings, and risk scores. "
            "Scanner credentials (Nexpose, Nessus, AppScan, Checkmarx) allow "
            "an attacker to authenticate directly to the vulnerability scanners, "
            "access all scan data, launch scans, or modify scan configurations. "
            "The AES-256 keyfile mechanism is optional and not enforced by the RPM "
            "install -- the default is plaintext."
        ),
        "remediation": (
            "Change /etc/kenna-agent/kenna-agent.toml permissions to 0600 (readable only by root). "
            "Since the service uses DynamicUser=yes, configure "
            "ConfigurationDirectory=kenna-agent in the systemd unit to set "
            "correct permissions. "
            "Enforce use of the keyfile AES-256 encryption feature for all "
            "credential fields. "
            "Prefer using environment variables for secrets, injected via "
            "systemd EnvironmentFile= with restricted permissions."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": (
            "validate_ssl = false Config Option Disables TLS Certificate "
            "Verification for Scanner Connections"
        ),
        "component": "/etc/kenna-agent/kenna-agent.toml + /usr/bin/kenna-agent",
        "evidence": {
            "config_option": "validate_ssl = false  # Set this to false for self-signed certs",
            "go_binding": "InsecureSkipVerify bound to toml:\"validate_ssl\"",
            "log_string": "Skipping, non-secure endpoint",
            "tls_note": (
                "When validate_ssl = false, the Go TLS config sets "
                "InsecureSkipVerify = true, disabling all certificate chain "
                "and hostname validation for HTTPS connections to the configured scanner."
            ),
        },
        "impact": (
            "The kenna-agent is a security-critical process: it authenticates to "
            "vulnerability scanners and uploads all discovered vulnerability data "
            "to the Kenna Security API. "
            "With validate_ssl = false, an on-path attacker (LAN, ARP poisoning, "
            "DNS cache poisoning) can impersonate the vulnerability scanner "
            "to intercept authentication credentials. "
            "The attacker receives the scanner username and password in the "
            "authentication flow before the agent realizes the connection is "
            "not the real scanner. "
            "The documentation encourages this setting for 'self-signed certs', "
            "making it likely to be used in enterprise deployments with "
            "internal PKI that the agent does not trust."
        ),
        "remediation": (
            "Remove validate_ssl = false as a supported option or restrict it "
            "to a trust_ca_file option that specifies a custom CA bundle. "
            "The current design conflates 'I have a self-signed cert' with "
            "'disable all TLS validation', which provides no MITM protection. "
            "Document that validate_ssl = false is insecure and should only "
            "be used with network-layer mitigations in place."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": (
            "Go Static Binary Ships with Full Debug Info and Symbol Table "
            "(Not Stripped) -- Complete Internal API Surface Visible"
        ),
        "component": "/usr/bin/kenna-agent",
        "evidence": {
            "binary_info": (
                "ELF 64-bit LSB executable, x86-64, statically linked, "
                "Go BuildID=rtqiylHQA-E-RTi3Beko/5w7vk-pTYFbw4rSMwWtW/..., "
                "with debug_info, not stripped"
            ),
            "visible_symbols": [
                "github.com/KennaSecurity/agent/internal/secrets",
                "github.com/KennaSecurity/agent/internal/kennaapi",
                "github.com/KennaSecurity/agent/internal/connector",
                "*secrets.AESKey",
                "*secrets.SecretString",
                "*kennaapi.KennaClient",
                "startKennaConnectorRun",
            ],
            "api_endpoints_exposed": [
                "api.kennasecurity.com (hardcoded)",
                "/rest/token",
                "/connectors/%d",
                "/connectors/%d/run",
                "/connectors/%d/data_file",
                "/api/3/asset_groups",
                "/api/3/tags/%d/assets",
                "/scans/%d/export",
                "/ase/api/login",
                "/CxRestAPI/sast/scans",
                "/j_spring_security_check",
            ],
            "json_fields": [
                "client_secret", "shared_secret", "asc_xsrf_token",
                "datecreated", "lastupdated",
            ],
        },
        "impact": (
            "The kenna-agent binary ships with full Go debug information and the "
            "complete symbol table intact. "
            "This exposes the full internal package structure, all function names, "
            "all API endpoint strings, all JSON field names, and the secrets management "
            "implementation. "
            "A security researcher or attacker can enumerate the complete API surface "
            "without source code access, reconstruct the authentication flow for each "
            "supported scanner, and identify the AES key management implementation details. "
            "The complete list of supported scanner API endpoints is directly visible, "
            "enabling targeted vulnerability hunting against each scanner integration. "
            "The 'j_spring_security_check' endpoint exposes Spring Security-based "
            "authentication handling that is not documented in the public TOML config."
        ),
        "remediation": (
            "Strip the binary at build time: add '-ldflags \"-s -w\"' to the Go build command. "
            "-s removes the symbol table; -w removes DWARF debug information. "
            "This does not affect runtime behavior but significantly raises the bar "
            "for binary analysis."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": (
            "Kenna API Endpoint api.kennasecurity.com Hardcoded; "
            "No Proxy TLS Verification Documented for API Path"
        ),
        "component": "/usr/bin/kenna-agent",
        "evidence": {
            "hardcoded_endpoint": "api.kennasecurity.com (string in binary)",
            "http_proxy_support": (
                "HTTP_PROXY and http_proxy environment variables are supported "
                "by the Go runtime (visible in binary strings). "
                "No documentation of proxy certificate validation behavior "
                "for the Kenna API connection path."
            ),
            "no_user_config": (
                "The API endpoint cannot be changed via kenna-agent.toml. "
                "Any enterprise that needs to route through a TLS-inspecting proxy "
                "must configure the Go TLS trust store or use a CONNECT proxy."
            ),
        },
        "impact": (
            "Organizations using TLS-inspecting proxies (common in regulated industries) "
            "cannot properly configure the Kenna API connection without either "
            "(1) adding the proxy CA to the system trust store or "
            "(2) disabling TLS verification for the API path entirely. "
            "The hardcoded endpoint means there is no way to point the agent at "
            "an on-premises or private API server. "
            "If the api.kennasecurity.com domain were to be compromised, spoofed via DNS, "
            "or expired, all deployed agents would immediately stop functioning with no "
            "built-in fallback or configurable endpoint override."
        ),
        "remediation": (
            "Expose the Kenna API endpoint as a configurable option in kenna-agent.toml. "
            "Document proxy CA configuration for TLS-inspecting proxy environments. "
            "Consider supporting KENNA_API_URL as an environment variable override."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": (
            "Datadog APM Tracing Integration Sends Agent Hostname, "
            "Service Paths, and Trace Data to Configurable DD_AGENT_HOST"
        ),
        "component": "/usr/bin/kenna-agent",
        "evidence": {
            "dd_env_vars": [
                "DD_AGENT_HOST",
                "DD_TRACE_DEBUG",
                "DD_TRACE_RATE_LIMIT",
                "DD_TRACE_AGENT_PORT",
                "DD_TRACE_REPORT_HOSTNAME",
                "DD_TRACE_SOURCE_HOSTNAME",
                "DD_TRACE_STARTUP_LOGS",
                "DD_TAGS",
            ],
            "trace_data": (
                "Trace data includes: service name, hostname, API endpoints called, "
                "x-datadog-parent-id, x-datadog-origin, _sampling_priority_v1, "
                "http.status_code, span IDs, trace IDs. "
                "Format: http://%s/v0.4/traces -> DD_AGENT_HOST:DD_TRACE_AGENT_PORT"
            ),
            "default_endpoint": "localhost:8126 (Datadog agent default)",
        },
        "impact": (
            "When Datadog APM is configured, the kenna-agent sends detailed trace data "
            "for every operation including scanner connections, API calls to "
            "api.kennasecurity.com, and connector run events. "
            "Trace data includes internal API paths, HTTP status codes, and service names "
            "that reveal the internal structure of the agent's operations. "
            "If DD_AGENT_HOST is misconfigured to point to an attacker-controlled host, "
            "all trace data (including API call metadata) is sent there. "
            "In environments where the Datadog agent runs on a shared host, "
            "trace data from the kenna-agent is visible to any process "
            "that can read the Datadog agent's data."
        ),
        "remediation": (
            "Document what data is included in APM traces for security review. "
            "Ensure trace data does not include credential fragments or tokens. "
            "Restrict DD_AGENT_HOST to localhost or a known-safe Datadog agent IP. "
            "Consider making APM opt-in rather than opt-out."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": (
            "kenna-agent Go Binary Built with Go 1.31.1 -- "
            "Future CVE Surface from Go Runtime"
        ),
        "component": "/usr/bin/kenna-agent",
        "evidence": {
            "go_version": "v1.31.1 (from binary string 'version:v1.31.1')",
            "build_date": "2025-09-02 (from RPM file timestamps)",
            "static_binary": (
                "Statically linked -- all Go standard library code is embedded. "
                "Any Go runtime CVE requires a binary rebuild to patch; "
                "OS-level package updates do not affect a static binary."
            ),
        },
        "impact": (
            "The kenna-agent binary embeds the Go 1.31.1 runtime statically. "
            "Any future CVE in the Go standard library affecting net/http, "
            "crypto/tls, or archive/zip requires a rebuild and redeployment of the agent. "
            "Since the binary is static, users cannot patch runtime vulnerabilities "
            "via OS package manager updates (unlike dynamically linked binaries). "
            "This creates an operational dependency on Cisco/Kenna to publish "
            "a patched RPM in response to Go security advisories."
        ),
        "remediation": (
            "Publish a new RPM within 30 days of any high-severity Go security advisory. "
            "Maintain a Go version history in the release notes. "
            "Consider a dynamic build for the Go standard library components, "
            "or provide a mechanism for customers to rebuild the binary locally."
        ),
    },
]


def run_module():
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Firmware: {MODULE_SUMMARY['firmware']}")
    for component, desc in MODULE_SUMMARY["components"].items():
        print(f"  {component}: {desc}")
    counts = MODULE_SUMMARY["finding_counts"]
    print(
        f"Findings: {sum(counts.values())} "
        f"[{counts['CRITICAL']}C/{counts['HIGH']}H/"
        f"{counts['MEDIUM']}M/{counts['LOW']}L]"
    )
    cc = MODULE_SUMMARY["cumulative_counts"]
    print(
        f"Cumulative: {MODULE_SUMMARY['cumulative_total']} "
        f"[{cc['CRITICAL']}C+{cc['HIGH']}H+{cc['MEDIUM']}M+{cc['LOW']}L]"
    )
    print()
    for f in FINDINGS:
        sev = f["severity"]
        print(f"  {f['id']} [{sev}] {f['title']}")
        print(f"    Component: {f['component']}")
        print(f"    Impact: {f['impact'][:120]}...")
        print()


if __name__ == "__main__":
    run_module()
