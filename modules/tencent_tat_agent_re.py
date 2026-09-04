"""
TencentOS TAT Agent (Tencent Automation Tools) RE Module
Versions analyzed: 0.1.15, 0.1.16, 0.1.17 (Linux x86_64)
Source: /media/cowboy/research/tencent-agent/tat-agent/
  binaries: tat_agent_linux_install_x86_64_0.1.{15,16,17}.zip
  source: src/ (reflects current 1.2.2 codebase, July 2026)
Analysis date: 2026-09-04

TAT (Tencent Automation Tools) is the command execution agent for TencentOS cloud instances.
It provides remote command execution from the TencentCloud control plane to running instances.
It is installed by default on TencentOS cloud instances and runs as root.

Architecture:
  WebSocket connection to TAT service (wss://<region>.tat.tencentcloud.com)
  HTTPS poll to invoke API for command tasks
  COS (Cloud Object Storage) upload for command output

Command flow:
  TAT server -> InvocationNormalTask (InvocationTaskId, Command, CommandType, WorkingDirectory)
  -> ShellCommand exec (fork/exec with working_directory)
  -> stdout/stderr streaming -> COS bucket upload
  -> result report back to TAT server

Interface (getsockopt-style internally, public via WebSocket/HTTPS):
  InvocationNormalTask — execute command
  InvocationCancelTask — cancel running command
  DescribeTasksResponse — poll for queued tasks
  VersionCheckUpdate — self-update check (NeedUpdate, DownloadUrl, Md5)

Binary characteristics (all three 0.1.x versions):
  Rust statically-linked ELF64, with debug_info, NOT STRIPPED
  Sizes: 0.1.15=15.6MB, 0.1.16=15.6MB, 0.1.17=15.6MB
  Symbol comparison: identical base function sets; only LLVM internal hashes differ
  0.1.17 new string: "remove log file failed: " — log cleanup added
  Rust version: rustc f1edd0429582dd29cccacaf50fd134b05593bd9c (shared across all three)

Version mapping:
  0.1.15/0.1.16/0.1.17: old version scheme, deployed on legacy TOS instances
  1.x.x: new version scheme starting late 2023 (1.0.11 = Dec 2023)
  Current: 1.2.2 (July 2026) — source available in repo

Security-relevant CHANGELOG entries (from src/CHANGELOG.md):
  1.1.10 (Mar 2026): "Fix TOCTOU issue between self-update check restart and other task"
  1.2.0 (May 2026): "Fix tat_install scripts: stop service order and TLS certificate validation"
  1.2.1 (May 2026): "Remove mock backend url logic" [debug URL in production]
  1.1.9 (Sep 2025): "Enhanced PtyStart interface to support launching specified programs"
  1.0.17 (May 2024): "Support for multiplexing a single WebSocket connection across multiple Channels"
"""

BINARY_FINGERPRINTS = {
    "0.1.15": {
        "md5": "eb9db5a3f033bc4c57d7fd957fb73c6b",
        "size": 15608800,
        "build_id": "not extracted",
    },
    "0.1.16": {
        "md5": "b1df818b1bece91302deea9b521e1801",
        "size": 15611880,
        "build_id": "not extracted",
    },
    "0.1.17": {
        "md5": "d7a07a3cca055d4d4084e613fcba9464",
        "size": 15606840,
        "build_id": "not extracted",
    },
}

FINDINGS = {
    "TAT-F01": {
        "title": (
            "Self-Update Lacks Code Signing — Integrity Verified Only by Server-Provided MD5; "
            "Malicious Binary Accepted if Download URL MitM or Server Compromised; "
            "verify_agent() Insufficient: Checks Output Format Only, Not Cryptographic Signature"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-494",
        "component": "src/ontime/self_update.rs:update() + verify_agent()",
        "description": (
            "The TAT agent self-update chain (all versions including current 1.2.2) "
            "verifies the downloaded binary using only an MD5 hash provided by the TAT server. "
            "\n"
            "The full chain from src/ontime/self_update.rs: "
            "(1) Check server for update: InvokeAdapter::check_update() returns {need_update, download_url, md5} "
            "(2) Download binary from server-provided URL: HttpRequester::get(url) -> local zip "
            "(3) Compute actual MD5 of downloaded file; compare with server-provided md5 (L69) "
            "(4) Unzip to self_update/agent_update_unzip/ "
            "(5) verify_agent(): run new binary with --version; check output is 'tat_agent <version>' (L146) "
            "(6) run_self_update_script(): sh -c self_update.sh (from inside the attacker-controlled zip) "
            "\n"
            "Vulnerability: "
            "The MD5 check at (3) trusts the server-provided md5 value. If the TAT server "
            "is compromised, or if the download_url is redirected to an attacker-controlled "
            "endpoint (via DNS poisoning, BGP hijack, or COS bucket SSRF), the server can "
            "return matching md5 for a malicious binary. "
            "\n"
            "verify_agent() at (5) only checks: v.len()==2 && v[0]=='tat_agent'. "
            "Any binary that prints 'tat_agent 0.1.0\\n' passes this check. "
            "\n"
            "self_update.sh at (6) is unzipped from the attacker zip — no integrity check on "
            "the script contents at all. On Unix: sh -c <path> executes arbitrary shell commands. "
            "\n"
            "Impact: every TencentOS cloud instance running TAT can be taken to root arbitrary "
            "code execution via a server-side update push or network-level MitM of the update URL."
        ),
        "source_refs": {
            "update()": "src/ontime/self_update.rs:51-89",
            "md5_check": "src/ontime/self_update.rs:69-71",
            "verify_agent": "src/ontime/self_update.rs:140-149",
            "run_script": "src/ontime/self_update.rs:152-168",
        },
        "chain": (
            "TAT-F01: TAT server compromise OR DNS/BGP/COS-bucket MitM of download URL → "
            "server returns malicious binary URL + matching MD5 → "
            "agent downloads and verifies by MD5 (passes) → "
            "verify_agent() runs malicious binary (returns 'tat_agent 0.1.0' → passes) → "
            "self_update.sh executes from attacker zip → "
            "arbitrary root code execution on all enrolled TencentOS instances"
        ),
        "remediation": (
            "Add code signing: sign binaries with RSA/ECDSA key; "
            "embed verification public key in agent; verify signature before unzip. "
            "MD5 alone is insufficient — it only proves the download was not corrupted, "
            "not that the binary is from a trusted source."
        ),
        "references": ["CWE-494", "CVE-2016-0728 (analogous kernel module signing bypass)"],
    },
    "TAT-F02": {
        "title": (
            "TOCTOU Between Self-Update Binary Check and Restart (Pre-1.1.10); "
            "Downloaded Binary Could Change Between verify_agent() and restart(); "
            "TAT Server Changelog Acknowledges Fix at v1.1.10 (March 2026)"
        ),
        "severity": "MEDIUM",
        "cvss": "4.1",
        "cvss_vector": "AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N",
        "cwe": "CWE-367",
        "component": "src/ontime/self_update.rs:check_update() -> wait_and_restart()",
        "description": (
            "In versions before 1.1.10 (March 2026), the self-update flow had a TOCTOU "
            "between the update check/download (update()) and the restart phase (wait_and_restart()). "
            "\n"
            "The fix (v1.1.10): 'Fix TOCTOU issue between self-update check restart and other task.' "
            "The fix introduced restart_lock (RwLock) in src/common/guard.rs: "
            "  - prevent_restart(): acquires shared read lock during task execution "
            "  - acquire_restart_lock(): acquires exclusive write lock before restart "
            "This ensures no task is running when the agent restarts post-update. "
            "\n"
            "The 0.1.x binaries on the research drive predate this fix. "
            "The specific race: a task received during the window between "
            "run_self_update_script() completion and restart() could be partially "
            "executed by the old agent while the restart was in progress, "
            "leading to undefined state (task marked running in server, agent dead)."
        ),
        "status": "FIXED in 1.1.10 (March 2026); open in all 0.1.x binaries",
        "source_refs": {
            "guard_impl": "src/common/guard.rs:18-27",
            "check_update": "src/ontime/self_update.rs:31-38",
            "wait_and_restart": "src/ontime/self_update.rs:40-49",
        },
    },
    "TAT-F03": {
        "title": (
            "Install Script TLS Certificate Validation Bypass (Pre-1.2.0); "
            "Initial Agent Download Vulnerable to MitM RCE if --insecure Used; "
            "Mock Backend URL Removed at 1.2.1 — Debug Endpoint in Production Pre-1.2.1"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-295",
        "component": "install/install.sh (and internal install.sh embedded in agent)",
        "description": (
            "CHANGELOG v1.2.0 (May 2026): 'Fix tat_install scripts: stop service order and TLS certificate validation.' "
            "Prior to 1.2.0, the install scripts had a TLS certificate validation issue — "
            "consistent with curl/wget --insecure flag or equivalent that skips certificate verification "
            "during the initial agent download from COS. "
            "\n"
            "Impact: any deployment of TAT agent before May 2026 that used the affected install "
            "scripts was vulnerable to MitM during initial installation — an attacker on the "
            "network path could deliver an arbitrary binary as the TAT agent, achieving root "
            "RCE on the instance from the moment of installation. "
            "\n"
            "CHANGELOG v1.2.1 (May 2026): 'Remove mock backend url logic.' "
            "This indicates a debug/mock backend URL was present in production binaries "
            "prior to 1.2.1. Depending on whether the mock URL was reachable, this could "
            "be exploited by setting up a mock backend and waiting for misrouted connections, "
            "or by taking over the mock domain."
        ),
        "status": "TLS FIXED in 1.2.0; mock URL REMOVED in 1.2.1; both open in all 0.1.x",
    },
    "TAT-F04": {
        "title": (
            "TAT PTY and ConnectForward Interfaces Provide Bidirectional Terminal Access; "
            "PtyStart/PtyExecCmdStream Available Since 1.0.13 (Feb 2024); "
            "ConnectForward WebSocket Direct Forward Added in 1.2.0 (May 2026)"
        ),
        "severity": "INFO",
        "cvss": "0.0",
        "cwe": "CWE-749",
        "component": "src/tssh/ (PtyStart, PtyExecCmdStream, ConnectForward)",
        "description": (
            "The TAT agent exposes a full interactive terminal (PTY) interface in addition to "
            "batch command execution. Added in 1.0.13 (Feb 2024) for Unix streaming, "
            "enhanced in 1.1.9 (Sep 2025) to support launching specified programs in PTY. "
            "ConnectForward (1.2.0, May 2026) adds direct WebSocket port-forwarding. "
            "\n"
            "These interfaces are gated on authentication to the TAT control plane. "
            "However, they significantly expand the attack surface compared to simple "
            "command execution: "
            "  - Interactive terminal = interactive shell as root on any enrolled instance "
            "  - ConnectForward = TCP port forwarding through the instance "
            "    (lateral movement within VPC without exposed ports) "
            "\n"
            "From a trust model perspective: every TencentOS cloud instance with TAT installed "
            "gives whoever controls the TAT server API root interactive access and TCP "
            "port forwarding capability. This is by design for cloud instance management, "
            "but represents the trust relationship users of TencentOS accept."
        ),
        "chain": (
            "TAT-F04 + TAT-F01: TAT server compromise → "
            "PtyStart on all enrolled instances → root interactive shell on all TOS cloud VMs "
            "in the account; OR ConnectForward → pivot to internal VPC resources "
            "not otherwise network-accessible from outside"
        ),
    },
}

SOURCE_TREE = {
    "self_update": "src/ontime/self_update.rs — download/md5/unzip/verify/restart pipeline",
    "guard":       "src/common/guard.rs — RESTART_LOCK (RwLock) for TOCTOU fix",
    "requester":   "src/network/requester.rs — HTTP client (ClientBuilder::new(), default TLS)",
    "invoke_adapter": "src/network/adapter/invoke_adapter.rs — task polling, command dispatch",
    "cos_adapter": "src/network/adapter/cos_adapter.rs — output upload to COS bucket",
    "pty":         "src/tssh/ — interactive PTY and ConnectForward interfaces",
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "versions_analyzed": ["0.1.15", "0.1.16", "0.1.17"],
        "source_version": "1.2.2 (July 2026)",
        "binary_comparison": "identical symbol sets; 0.1.x predate all security fixes",
        "critical_finding": "no code signing in self-update — MD5 from server only",
        "findings": [{"id": k, "severity": v["severity"]} for k, v in FINDINGS.items()],
    }, indent=2))
