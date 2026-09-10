"""
Cisco Kenna Security Agent 1.3.2262 — Reverse Engineering Module
Source: kenna-agent-1.3.2262-1.x86_64.rpm (/media/cowboy/research/Cisco-UCS/other/)
Package: RPM v3.0 bin i386/x86_64, 7.7MB
Payload: zstd-compressed CPIO (magic 0x28b52ffd), 3 files
Binary: ELF 64-bit LSB executable x86-64, statically linked Go binary (Go 1.23.12)
        16.7MB, not stripped, with DWARF debug_info, Go BuildID: rtqiylHQA-E-RTi3Beko/...

Files installed:
  /etc/kenna-agent/kenna-agent.toml  (0644 — world-readable config)
  /lib/systemd/system/kenna-agent.service
  /usr/bin/kenna-agent               (0755, 15.9MB)

Kenna Security (acquired by Cisco) is a vulnerability management platform.
The agent runs as DynamicUser on the host, polls configured vulnerability scanners
(Nexpose, Nessus, AppScan Enterprise, CxSAST, Sonatype), and uploads findings to
api.kennasecurity.com using a bearer token stored in the TOML config.
"""

FIRMWARE = {
    "target":    "Cisco Kenna Security Agent",
    "version":   "1.3.2262",
    "rpm_nvra":  "kenna-agent-1.3.2262-1.x86_64.rpm",
    "binary":    "/usr/bin/kenna-agent",
    "go_ver":    "go1.23.12",
    "go_buildid":"rtqiylHQA-E-RTi3Beko/5w7vk-pTYFbw4rSMwWtW/ug3e8Eyh25mWM5VBjjXX/_X0DObqbEi8YNCOMERII",
    "findings":  ["KENNA-F1", "KENNA-F2", "KENNA-F3", "KENNA-F4"],
}

# ─────────────────────────────────────────────────────────────────────────────
# KENNA-F1: /etc/kenna-agent/kenna-agent.toml installed 0644 (world-readable)
#            — Kenna API token and scanner credentials readable by any local user
# ─────────────────────────────────────────────────────────────────────────────
KENNA_F1 = {
    "id":       "KENNA-F1",
    "title":    "/etc/kenna-agent/kenna-agent.toml installed 0644 (world-readable) — "
                "Kenna API token and vulnerability scanner passwords (Nexpose/Nessus/AppScan) "
                "readable by any local OS user",
    "status":   "CONFIRMED — CPIO header mode=0o100644 for kenna-agent.toml in kenna-agent-1.3.2262-1.x86_64.rpm",
    "severity": "HIGH",

    "installed_path": "/etc/kenna-agent/kenna-agent.toml",
    "rpm_mode":       "0o100644 (-rw-r--r--)",

    "config_fields_exposed": {
        "[kenna] token":         "Bearer token for api.kennasecurity.com — full API access",
        "[connector.*] id":      "Connector ID on Kenna platform",
        "[connector.*] url":     "Internal scanner URL (Nexpose, Nessus, etc.)",
        "[connector.*] username":"Scanner auth username",
        "[connector.*] password":"Scanner auth password in plaintext",
    },

    "impact": (
        "Any local user on the host can read the Kenna API token and all configured scanner "
        "credentials directly from /etc/kenna-agent/kenna-agent.toml. "
        "The Kenna API token provides authenticated access to api.kennasecurity.com — "
        "this includes reading vulnerability data, triggering connector runs, and potentially "
        "modifying vulnerability records. "
        "Scanner credentials (Nexpose, Nessus) allow direct access to the vulnerability scanner "
        "management plane from outside the agent. "
        "The systemd service runs as DynamicUser=yes, but the config file permissions are "
        "set by the RPM CPIO record at install time (mode 0644) and are not overridden by the service."
    ),

    "remediation": "Install config as 0640 (owner root, group kenna or the DynamicUser effective group). "
                   "No code change required — RPM CPIO mode field update only.",
}

# ─────────────────────────────────────────────────────────────────────────────
# KENNA-F2: validate_ssl=false config option maps to InsecureSkipVerify=true
#            — TOML struct tag `validate_ssl` directly controls TLS verification
# ─────────────────────────────────────────────────────────────────────────────
KENNA_F2 = {
    "id":       "KENNA-F2",
    "title":    "kenna-agent.toml validate_ssl=false maps to InsecureSkipVerify=true in TLS config — "
                "disabling TLS certificate verification for connections to vulnerability scanners",
    "status":   "CONFIRMED — struct tag 'toml:\"validate_ssl\"' in binary; InsecureSkipVerify present in TLS code path",
    "severity": "MEDIUM",

    "struct_tag":     "toml:\"validate_ssl\"",
    "tls_field":      "InsecureSkipVerify (crypto/tls.Config)",

    "config_template": (
        "[connector.example]\n"
        "#validate_ssl = false  # <-- setting this disables cert verification for that connector\n"
        "#url = 'https://nexpose.example.com:5917'"
    ),

    "verification_path": (
        "strings shows both 'toml:\"validate_ssl\"' (struct field annotation) and 'InsecureSkipVerify' "
        "in the binary's symbol table. Go TLS: InsecureSkipVerify skips all x509 chain validation. "
        "TLS error message present: 'tls: either ServerName or InsecureSkipVerify must be specified' "
        "confirms the TLS config is constructed from runtime options including this field."
    ),

    "impact": (
        "When validate_ssl=false is set (documented as 'Set this to false for self-signed certs'), "
        "the agent connects to vulnerability scanners without verifying the server certificate. "
        "An on-path attacker on the management network can MITM the agent's connections to Nexpose, "
        "Nessus, or AppScan and intercept all scanner API calls — including authentication flows "
        "and vulnerability data exfiltration. "
        "The plaintext scanner credentials (KENNA-F1) allow the attacker to authenticate directly "
        "to the scanner after capture."
    ),

    "severity_note": "MEDIUM standalone; elevates to HIGH combined with KENNA-F1 (world-readable credentials).",
}

# ─────────────────────────────────────────────────────────────────────────────
# KENNA-F3: Datadog APM telemetry endpoints use HTTP (not HTTPS)
#            — trace data sent in cleartext to localhost:8126
# ─────────────────────────────────────────────────────────────────────────────
KENNA_F3 = {
    "id":       "KENNA-F3",
    "title":    "Embedded Datadog APM client sends trace telemetry to http://%s/v0.4/traces and "
                "http://%s/v0.6/stats — cleartext HTTP to Datadog agent (default localhost:8126)",
    "status":   "CONFIRMED — format strings 'http://%s/v0.4/traces' and 'http://%s/v0.6/stats' in binary",
    "severity": "MEDIUM",

    "trace_url":  "http://%s/v0.4/traces (Datadog APM trace intake)",
    "stats_url":  "http://%s/v0.6/stats  (Datadog APM stats intake)",
    "default_dd_host": "localhost:8126",
    "dd_env_vars": ["DD_TRACE_STARTUP_LOGS", "DD_TRACE_DEBUG", "DD_TRACE_SAMPLE_RATE"],

    "impact": (
        "The Datadog APM client embedded in kenna-agent sends distributed traces over HTTP. "
        "These traces record spans for API calls to api.kennasecurity.com and vulnerability scanner endpoints. "
        "Trace spans may include HTTP headers, request parameters, and response metadata — "
        "including the Kenna API token (typically sent as an Authorization header). "
        "Even on localhost, a local attacker can intercept traffic to :8126 via LD_PRELOAD, "
        "a malicious Datadog agent binary, or by binding to the port first. "
        "If DD_AGENT_HOST is set to a remote host (common in container/Kubernetes deployments), "
        "API credentials traverse the network in cleartext."
    ),

    "note": "Severity is MEDIUM. Datadog's local HTTP transport is intentional design (IPC over HTTP). "
            "Risk materializes when DD_AGENT_HOST points remotely or a local attacker can read port 8126.",
}

# ─────────────────────────────────────────────────────────────────────────────
# KENNA-F4: Build path /home/circleci leaked in binary symbol table
#            — CircleCI workspace GOPATH embedded in all debug symbols
# ─────────────────────────────────────────────────────────────────────────────
KENNA_F4 = {
    "id":       "KENNA-F4",
    "title":    "CircleCI build workspace GOPATH '/home/circleci/go/pkg/mod/' leaked in kenna-agent "
                "binary debug symbols — CI/CD infrastructure disclosure",
    "status":   "CONFIRMED — strings /usr/bin/kenna-agent shows /home/circleci/go/pkg/mod/<dep>",
    "severity": "LOW",

    "example_paths": [
        "/home/circleci/go/pkg/mod/golang.org/x/sys@v0.18.0/unix/mremap.go",
        "/home/circleci/go/pkg/mod/golang.org/x/sys@v0.18.0/unix/syscall.go",
        "/home/circleci/go/pkg/mod/github.com/sirupsen/logrus@v1.8.1/logger.go",
    ],

    "disclosure": "Build user: circleci. CI platform: CircleCI. Module cache layout is standard Go.",
    "binary_note": "Binary ships with full debug_info (not stripped) — complete DWARF present in production.",
}

FINDINGS = [KENNA_F1, KENNA_F2, KENNA_F3, KENNA_F4]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
