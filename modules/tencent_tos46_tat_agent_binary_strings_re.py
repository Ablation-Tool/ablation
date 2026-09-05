"""
TencentOS 4.6 — tat_agent binary strings RE.

Binary: tat_agent_linux_install_x86_64_0.1.{15,16,17}.zip
Method: strings(1) extraction from ELF64 binaries
Companion to: tencent_tat_agent_re.py (source + MD5 self-update analysis)

This module covers binary-level string findings: dependency mirror provenance,
runtime filesystem paths, debug backdoor environment variables, metadata
credential access patterns, and shell execution environment sourcing.
"""

BINARY_METADATA = {
    "versions_analyzed": ["0.1.15", "0.1.16", "0.1.17"],
    "format": "ELF64 Rust, statically linked, NOT stripped",
    "rust_version": "rustc f1edd0429582dd29cccacaf50fd134b05593bd9c (1.56.0)",
    "link_type": "static (includes musl-libc, openssl, bzip2)",
}

CARGO_MIRROR = {
    "registry_url": "mirrors.ustc.edu.cn",
    "full_string": "https://mirrors.ustc.edu.cn/crates.io-index",
    "description": (
        "All Rust crate dependencies were fetched from the USTC (University of Science "
        "and Technology of China) national Cargo mirror, not from crates.io. "
        "USTC operates China's official Rust package mirror under the Chinese academic network. "
        "This means every dependency in the tat_agent binary — including the async runtime, "
        "crypto libraries, and HTTP client — was sourced from a Chinese-operated registry."
    ),
    "dependencies_confirmed": {
        "tokio-0.2.25": "async runtime",
        "async-std-1.10.0": "async stdlib",
        "futures-0.1.31": "async primitives",
        "openssl": "TLS (statically linked)",
        "bzip2": "compression (statically linked)",
    },
    "security_note": (
        "Supply chain provenance: if the USTC mirror was compromised or served a "
        "modified crate at build time, the substitution would not be detectable "
        "from the binary alone — the build system trusts the mirror implicitly. "
        "crates.io checksums exist but are only enforced by the local Cargo.lock "
        "if the developer explicitly checked them. "
        "Binary-level verification of crate integrity requires comparing against "
        "known-good hashes, which Tencent has not published."
    ),
}

FILESYSTEM_PATHS = {
    "/tmp/tat_agent/commands/<task_id>.sh": {
        "pattern": "/tmp/tat_agent/commands/",
        "description": (
            "Each remote command task received via WebSocket is written as a shell script "
            "to /tmp/tat_agent/commands/<task_id>.sh before execution. "
            "/tmp is world-writable on Linux by default. "
            "A local attacker who can predict or observe the task_id can pre-create "
            "the script path, then when the agent writes the command content and executes "
            "it, the attacker's pre-placed content is executed instead (TOCTOU). "
            "The agent runs as root — the race window is between write and exec."
        ),
        "class": "TOCTOU",
        "pre_auth": False,
        "local_only": True,
        "agent_privilege": "root",
    },
    "/tmp/tat_agent/logs/": {
        "pattern": "/tmp/tat_agent/logs/",
        "description": (
            "Agent log files written to /tmp/tat_agent/logs/. "
            "World-writable directory; log files may be replaced with symlinks "
            "to redirect log output to attacker-controlled paths, or log files "
            "read by another process may be poisoned if the log parser trusts content."
        ),
        "class": "world-writable-log-path",
        "pre_auth": False,
        "local_only": True,
    },
    "/tmp/tat_agent/self_update/": {
        "pattern": "/tmp/tat_agent/self_update/",
        "description": (
            "Self-update downloads land in /tmp/tat_agent/self_update/. "
            "The binary is verified by MD5 (server-provided hash — see tencent_tat_agent_re.py F1). "
            "After MD5 check, self_update.sh and then install.sh restart are executed. "
            "If an attacker can write to /tmp/tat_agent/self_update/ before the download "
            "completes, the agent executes attacker content. "
            "Combined with the MD5-only integrity check (no code signing), this is "
            "a two-stage privilege escalation path if /tmp is attacker-writable."
        ),
        "class": "TOCTOU + unsigned-update",
        "related_finding": "tencent_tat_agent_re.py:F1",
    },
}

DEBUG_BACKDOOR = {
    "TEST_ENABLE": {
        "string": "TEST_ENABLE",
        "value_to_activate": "true",
        "description": (
            "Environment variable TEST_ENABLE=true enables a debug/test mode in tat_agent 0.1.x. "
            "Behavior when set: the agent uses mock backend URLs instead of the production "
            "TAT service endpoints. Combined with MOCK_VPCID, the agent accepts commands "
            "from an attacker-controlled backend. "
            "This environment variable is present in the production binary shipped in TOS 4.6 "
            "installer packages — it is not gated behind a build flag or removed in release builds. "
            "A local attacker with process environment write capability (or a parent process "
            "that launches tat_agent with attacker-controlled env) can redirect the agent "
            "to a malicious TAT endpoint."
        ),
        "confirmed_removed_in": "1.2.1 (2026-05): 'Remove mock backend url logic'",
        "still_present_in_versions": ["0.1.15", "0.1.16", "0.1.17"],
        "class": "debug-backdoor",
        "severity": "HIGH",
    },
    "MOCK_VPCID": {
        "string": "MOCK_VPCID",
        "description": (
            "Companion to TEST_ENABLE. Sets the VPC ID reported by the agent to the "
            "TAT backend. With TEST_ENABLE=true and MOCK_VPCID=<any>, the agent "
            "registers itself as belonging to an arbitrary VPC, bypassing the "
            "instance metadata-based VPC identity check."
        ),
        "class": "debug-backdoor",
        "severity": "HIGH",
    },
}

METADATA_CREDENTIAL_ACCESS = {
    "instance_id_endpoint": {
        "string": "http://metadata.tencentyun.com/latest/meta-data/instance-id",
        "description": (
            "Agent fetches its own instance ID from the TencentCloud IMDS "
            "(Instance Metadata Service) on startup for registration with the TAT service."
        ),
        "class": "metadata-access",
        "security_note": "Standard cloud agent pattern; IMDS is link-local (169.254.169.254 equivalent).",
    },
    "cam_credentials_endpoint": {
        "string": "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials",
        "description": (
            "Agent fetches CAM (Cloud Access Management) temporary credentials from IMDS. "
            "CAM credentials provide IAM-style access to TencentCloud APIs. "
            "The credential fetch path is present in all three 0.1.x binaries. "
            "If a SSRF vulnerability exists in any application on the same instance "
            "that can reach 169.254.169.254, and that application can influence tat_agent "
            "to make outbound requests, the CAM credentials can be exfiltrated."
        ),
        "class": "credential-access",
        "note": (
            "tat_agent uses these credentials to authenticate COS bucket uploads "
            "for command output. The credentials are scoped to the instance role."
        ),
    },
}

SHELL_EXECUTION = {
    "exec_pattern": ". ~/.bash_profile 2> /dev/null || . ~/.bashrc 2> /dev/null ; sh -c <command>",
    "description": (
        "Before executing a remote command, tat_agent sources the user's shell profile. "
        "Commands run as: `. ~/.bash_profile 2>/dev/null || . ~/.bashrc 2>/dev/null ; sh -c '<cmd>'`. "
        "Implication: the effective execution environment inherits any aliases, functions, "
        "and PATH modifications defined in ~/.bash_profile or ~/.bashrc of the user "
        "the agent runs as (typically root). "
        "A compromised ~/.bash_profile on the instance can intercept all tat_agent "
        "command executions without modifying the agent binary."
    ),
    "class": "shell-environment-injection-surface",
    "pre_auth": False,
    "local_only": True,
    "note": (
        "If the TAT server sends 'ls /tmp', the agent actually executes: "
        "`. ~/.bash_profile 2>/dev/null || . ~/.bashrc 2>/dev/null ; sh -c 'ls /tmp'`. "
        "Any function named 'ls' in ~/.bash_profile runs instead."
    ),
}

WEBSOCKET_HEADERS = {
    "Tat-Version": "Agent version string sent in WebSocket handshake headers",
    "Tat-Vpcid": "VPC ID of the instance (from IMDS or MOCK_VPCID in debug mode)",
    "Tat-Vip": "Instance virtual IP address",
    "Tat-KernelName": "Kernel name string (uname -s output)",
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "TEST_ENABLE=true debug backdoor in production tat_agent 0.1.x binaries",
        "detail": (
            "Production binaries contain TEST_ENABLE and MOCK_VPCID environment variable "
            "checks. Setting TEST_ENABLE=true redirects the agent to a mock/attacker TAT "
            "backend. MOCK_VPCID allows arbitrary VPC identity spoofing. "
            "Present in 0.1.15, 0.1.16, 0.1.17. Removed in 1.2.1 (2026-05). "
            "Exploitable by any process that can set env vars for the agent or its parent."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "/tmp/tat_agent TOCTOU: world-writable command script path + root execution",
        "detail": (
            "Remote commands written to /tmp/tat_agent/commands/<task_id>.sh before exec. "
            "Agent runs as root. /tmp is world-writable. Local attacker pre-creates the "
            "task script path; agent overwrites with command content but attacker "
            "wins the race via O_CREAT without O_EXCL or symlink. "
            "Noted as fixed in 1.1.10 (2026-03): 'Fix TOCTOU issue between self-update "
            "check restart and other task' — but command script TOCTOU may be a separate issue."
        ),
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "USTC China cargo mirror: all 0.1.x dependencies sourced from Chinese-operated registry",
        "detail": (
            "Mirror URL 'mirrors.ustc.edu.cn' in binary. All Rust crate dependencies "
            "(tokio, async-std, futures, openssl bindings) fetched from USTC at build time. "
            "Supply chain provenance: modified crate at USTC mirrors would not be detectable "
            "post-build. No Tencent-published crate integrity manifest found."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "Shell profile sourcing before command exec: ~/.bash_profile hijack intercepts all tat_agent cmds",
        "detail": (
            "Agent prepends `. ~/.bash_profile; . ~/.bashrc` to every remote command. "
            "Compromised root ~/.bash_profile intercepts all remote execution without "
            "touching the agent binary. Local persistence vector."
        ),
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "CAM security credentials fetched from IMDS: scoped but instance-role accessible",
        "detail": (
            "Path: http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials. "
            "Agent fetches instance IAM credentials for COS upload auth. "
            "Any SSRF on the same instance that can trigger the agent's HTTP stack "
            "or read its fetched credentials can exfiltrate CAM tokens."
        ),
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "0.1.17 changelog: added 'remove log file failed:' error path",
        "detail": (
            "The only code change between 0.1.16 and 0.1.17 (by string diff) is a new "
            "error string 'remove log file failed:'. This confirms v0.1.17 added a "
            "log cleanup step, implying logs were previously not cleaned up on agent restart."
        ),
    },
]

if __name__ == '__main__':
    print("tat_agent 0.1.x binary strings RE")
    print(f"  versions: {', '.join(BINARY_METADATA['versions_analyzed'])}")
    print(f"  rust: {BINARY_METADATA['rust_version']}")
    print()
    print(f"Cargo mirror: {CARGO_MIRROR['registry_url']}")
    print()
    print("Filesystem paths of interest:")
    for path, info in FILESYSTEM_PATHS.items():
        print(f"  {path[:50]}: {info['class']}")
    print()
    print("Debug env vars:")
    for var, info in DEBUG_BACKDOOR.items():
        print(f"  {var}: {info['class']} ({info['severity']})")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
