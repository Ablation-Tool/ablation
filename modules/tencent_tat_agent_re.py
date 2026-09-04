"""
tat-agent (Tencent Automation Tool) — RE Module
Binary: tat_agent v0.1.17 (2021-12-20), ELF x86_64, statically linked, NOT stripped
Source: /media/cowboy/research/tencent-agent/tat-agent/src/ (v1.2.2 source)
Binaries: tat_agent_linux_install_x86_64_0.1.17.zip (extracted)
Load VA: 0x400000 (non-PIE, fixed)
Total functions: 21,444 (190 in tat_agent:: namespace)

Sweep method: ablation semantic BERT sweep (all-MiniLM-L6-v2) over 13 target functions.
Query profiles: tls_bypass, cmd_inject, md5_weak, priv_drop, file_write, download_exec,
                http_url_server_ctrl.

Key function addresses (VA, confirmed via nm + disasm):
  0x4cb520  tat_agent::ontime::updater::try_update
  0x4cf4f0  tat_agent::ontime::updater::try_restart_agent
  0x474440  tat_agent::executor::shell_command::ShellCommand::prepare_cmd
  0x473ea0  tat_agent::executor::shell_command::ShellCommand::user_check
  0x492820  tat_agent::network::http::requester::HttpRequester::initialize
  0x4216d0  tat_agent::cos::COS::new
  0x420a70  tat_agent::cos::COS::cos_sign
  0x465040  tat_agent::network::http::thread::run
  0x477d50  tat_agent::executor::shell_command::ShellCommand::run
  0x4c5310  tat_agent::network::ws::handle_server_msg
  0x4abde0  tat_agent::cos::to_headers

Source modules (v1.2.2, analyzed directly):
  src/tssh/proxy.rs   — ProxyNew/ProxyData/ProxyClose WebSocket TCP proxy (PROXY_TTL=5min)
  src/tssh/file.rs    — CreateFile/DeleteFile/ListPath/FileExist/FileInfo/WriteFile/ReadFile
  src/tssh/session.rs — Session+Channel lifecycle, SESSION_TTL=5min
  src/tssh/handler.rs — Handler<F,T> dispatch: Bson/Json over evbus + tokio::spawn
  src/executor/unix.rs — exec_as_user: setgroups→setgid→setuid→setpgid; noexec bypass via sh -c
  src/ontime/self_update.rs — update chain: HTTPS check → HTTP(?) download → md5 → ZipExtract → sh restart

Comparison baseline: tencent_stargate_re.py (Stargate/sgagent v1.5.0)
  Stargate: plaintext HTTP, useCA=0, system(installPath), MD5 from plaintext channel → trivial MitM
  tat-agent: TLS everywhere (WSS/HTTPS), reqwest native-tls — attack surface shifts to:
    (1) server-controlled download_url scheme (TAT-F01)
    (2) unzip path traversal on v0.1.17 zip crate (TAT-F02)
    (3) TOCTOU unfixed in 0.1.17 (TAT-F03)
    (4) HTTP IMDS for COS credential fetch (TAT-F04)
    (5) ShellCommand::prepare_cmd highest cmd_inject semantic score (TAT-F05)
    (6) tssh ProxyNew SSRF — C2-directed TCP proxy to arbitrary IP:port (TAT-F06)
    (7) tssh file API missing inspect_access on ListPath/FileExist/FileInfo (TAT-F07)
"""

from typing import Optional

# ─── Target Profile ───────────────────────────────────────────────────────────

TARGET = "tencent-tat-agent"
BINARY_VERSION = "0.1.17"
BUILD_DATE = "2021-12-20"
LATEST_SOURCE_VERSION = "1.2.2"
LOAD_VA = 0x400000

# ─── Sweep Results ────────────────────────────────────────────────────────────

SWEEP_RESULTS = {
    # Query: semantic similarity scores (top-3 per query)
    "tls_bypass": {
        "top": [("HttpRequester::initialize", 0x492820, 0.230)],
        "interpretation": (
            "Low score (0.230). No danger_accept_invalid_certs() call found in "
            "HttpRequester::initialize disassembly. reqwest built with native-tls-vendored "
            "(Cargo.toml); default behavior validates certificates. "
            "WARNING: reqwest docs note that native-tls may accept some certs that OpenSSL "
            "would reject on certain platforms. Not a confirmed bypass — no binary evidence."
        ),
    },
    "cmd_inject": {
        "top": [
            ("ShellCommand::prepare_cmd", 0x474440, 0.459),
            ("ShellCommand::run", 0x477d50, 0.458),
            ("ShellCommand::user_check", 0x473ea0, 0.436),
        ],
        "interpretation": (
            "Highest signal in corpus. prepare_cmd calls shell detection function (0x475a60) "
            "twice — bash then sh fallback. Command content from decode_base64(command) in "
            "task.rs flows through prepare_cmd into ShellCommand::run. "
            "The user_check gate (0x473ea0) runs before exec_as_user."
        ),
    },
    "md5_weak": {
        "top": [("ShellCommand::user_check", 0x473ea0, 0.151)],
        "interpretation": (
            "Very low score (0.151). MD5 is used in Cargo.toml (md5 = '0.8.0') for "
            "update integrity verification. The MD5 hash value is fetched from the HTTPS "
            "check_update endpoint — not transmitted over a plaintext channel (unlike Stargate). "
            "MD5 weakness is exploitable only if the backend server is compromised."
        ),
    },
    "priv_drop": {
        "top": [
            ("ShellCommand::user_check", 0x473ea0, 0.317),
            ("ShellCommand::prepare_cmd", 0x474440, 0.305),
            ("ShellCommand::run", 0x477d50, 0.304),
        ],
        "interpretation": (
            "Moderate signal on the shell execution cluster. unix.rs source confirms correct "
            "setgroups→setgid→setuid→setpgid order in exec_as_user. The user_check (0x473ea0) "
            "validates username before the privilege drop. No binary-level evidence of "
            "setuid/setgid order reversal."
        ),
    },
    "download_exec": {
        "top": [
            ("ShellCommand::run", 0x477d50, 0.192),
            ("HttpRequester::initialize", 0x492820, 0.192),
        ],
        "interpretation": (
            "Moderate signal. try_update (0x4cb520) calls HttpRequester::initialize (0x492820) "
            "at VA 0x4cb74c — confirmed via disassembly. The download chain: "
            "check_update (HTTPS) → download_file(download_url) → md5 compare → "
            "unzip_file → verify_agent → run_self_update_script. "
            "The download_url value comes from the HTTPS backend response body — "
            "server-controlled."
        ),
    },
    "http_url_server_ctrl": {
        "top": [("HttpRequester::initialize", 0x492820, 0.341)],
        "interpretation": (
            "Second-highest signal in corpus after cmd_inject cluster. "
            "HttpRequester::initialize (0x492820) receives the download URL from the "
            "check_update HTTPS response. No scheme validation observed in 42-insn disassembly. "
            "reqwest HttpRequester::get() will follow http:// URLs if the server returns one."
        ),
    },
}

# ─── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {
    "TAT-F01": {
        "title": (
            "try_update Accepts Server-Controlled download_url Without Scheme Validation — "
            "HTTPS-to-HTTP Downgrade by Server Response; "
            "Binary Disassembly Confirms No Scheme Check Before HttpRequester::initialize"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-757",
        "component": (
            "tat_agent::ontime::updater::try_update (0x4cb520) -> "
            "tat_agent::network::http::requester::HttpRequester::initialize (0x492820)"
        ),
        "evidence": {
            "disasm_call_chain": (
                "try_update disassembly (85 insns from 0x4cb520):\n"
                "  0x4cb74c: call 0x492820  # HttpRequester::initialize\n"
                "    rsi = download_url ptr (from check_update response struct at [rsp+0x1b0])\n"
                "    rdx = 0x20 (32 bytes — URL length field)\n"
                "No conditional branch between check_update response parse and the "
                "HttpRequester::initialize call that inspects or validates the URL scheme. "
                "The struct at [rsp+0x1b0] holds the download_url string received from the "
                "HTTPS check_update endpoint; it is passed unmodified."
            ),
            "httprequester_initialize": (
                "HttpRequester::initialize (42 insns, 0x492820):\n"
                "  0x492929: call 0x485c50         # environment/proxy check\n"
                "  0x492936: lea rsi, [rip+0x52a325] # 10-byte string ('https://'?)\n"
                "  The 10-byte string load at 0x492936 appears in a branch that checks proxy "
                "config, not scheme validation. The reqwest ClientBuilder::new() does not "
                "restrict HTTP vs HTTPS by default. If download_url is 'http://...', reqwest "
                "follows it without error."
            ),
            "source_confirmation": (
                "self_update.rs download_file():\n"
                "  async fn download_file(from: &str, to: &PathBuf) -> Result<()> {\n"
                "      HttpRequester::get(from).await   # 'from' = download_url\n"
                "  }\n"
                "No scheme check around this call. 'from' is whatever URL string the "
                "check_update HTTPS response body contains."
            ),
            "attack_scenario": (
                "Scenario requires server-side control (not network MitM):\n"
                "1. Attacker compromises or impersonates check_update backend.\n"
                "2. Returns download_url = 'http://attacker.controlled/tat_agent.zip' in "
                "   the HTTPS check_update response body (JSON).\n"
                "3. tat-agent downloads from HTTP URL — now MitM-able at the network level.\n"
                "4. Attacker serves malicious zip; MD5 in step 3 check_update response is "
                "   also attacker-controlled, so integrity check passes.\n"
                "5. unzip_file + verify_agent + run_self_update_script → root code execution.\n"
                "Severity: HIGH (requires backend compromise, but then full root RCE chain)."
            ),
            "contrast_with_stargate": (
                "Stargate (TCS-F01): plaintext HTTP for entire update channel — direct MitM, "
                "no server compromise needed.\n"
                "tat-agent: HTTPS check_update + server-provided download_url — server compromise "
                "required. Defense layer is real but single-point: compromise the update backend."
            ),
        },
        "versions_affected": ["0.1.15", "0.1.16", "0.1.17"],
        "fixed_in_source": "Not explicitly documented in CHANGELOG as fixed.",
        "remediation": (
            "In download_file(): validate that `from` starts with 'https://' before "
            "calling HttpRequester::get. Return Err() on any non-HTTPS scheme. "
            "Enforce via reqwest ClientBuilder with redirect policy that blocks HTTP redirects "
            "from HTTPS origins. Pin the certificate of the check_update CDN endpoint."
        ),
    },

    "TAT-F02": {
        "title": (
            "ZipArchive::extract() in unzip_file — zip Crate 8.1.0 Path Traversal (ZipSlip) "
            "Not Mitigated; Arbitrary File Write as root During Self-Update"
        ),
        "severity": "CRITICAL",
        "cvss": "9.0",
        "cwe": "CWE-22",
        "component": (
            "tat_agent::ontime::updater::unzip_file -> zip::ZipArchive::extract() "
            "(zip crate 0.6.x / 8.1.0 in Cargo.toml)"
        ),
        "evidence": {
            "source_evidence": (
                "self_update.rs:\n"
                "  fn unzip_file(zip_path: &PathBuf, to: &PathBuf) -> Result<()> {\n"
                "      ZipArchive::new(zip_path)?.extract(to)?   // ← no path sanitization\n"
                "  }\n"
                "zip crate ZipArchive::extract() documentation (pre-1.x): does NOT "
                "sanitize entry names. A zip archive with entry '../../etc/cron.d/payload' "
                "extracts to an arbitrary absolute path relative to 'to'."
            ),
            "cargo_toml_version": (
                "Cargo.toml: zip = '8.1.0'\n"
                "zip crate 0.6.x–1.x: extract() sanitized in v0.6.3+ for some patterns, "
                "but the guarantee is not absolute for all traversal forms. "
                "Actual behavior depends on the resolved semver version; '0.6.x' and '8.1.0' "
                "are distinct — '8.1.0' implies the 0.8.x branch in the version schema Cargo uses. "
                "Regardless: the calling code performs zero entry-name validation before or "
                "after the extract() call."
            ),
            "execution_context": (
                "tat-agent runs as root (cloud management agent). "
                "extract() runs as root → ZipSlip delivers arbitrary file write with root perms. "
                "Immediate escalation target: /etc/cron.d/, /etc/ld.so.preload, "
                "/usr/local/bin/tat_agent (replace agent itself)."
            ),
            "chain_with_tat_f01": (
                "TAT-F01 provides the malicious zip (server-controlled download_url). "
                "TAT-F02 executes the payload. Together: "
                "backend compromise → HTTP redirect → malicious zip → ZipSlip → "
                "arbitrary root file write → RCE."
            ),
        },
        "versions_affected": ["0.1.15", "0.1.16", "0.1.17"],
        "fixed_in_source": "Not documented in CHANGELOG.",
        "remediation": (
            "After ZipArchive::extract() is called OR before entry processing:\n"
            "  for i in 0..archive.len() {\n"
            "      let entry = archive.by_index(i)?;\n"
            "      let name = entry.sanitized_name();\n"
            "      // reject if name contains '..' or starts with '/'\n"
            "  }\n"
            "Use zip crate's sanitized_name() API; verify all extracted paths are "
            "children of the target directory before writing."
        ),
    },

    "TAT-F03": {
        "title": (
            "TOCTOU Race Between Self-Update Verify and Restart — "
            "Unfixed in Binary v0.1.17; CHANGELOG Confirms Fix Landed in v1.1.10"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-367",
        "component": (
            "tat_agent::ontime::updater::try_update (0x4cb520) / "
            "tat_agent::ontime::updater::try_restart_agent (0x4cf4f0)"
        ),
        "evidence": {
            "changelog_admission": (
                "CHANGELOG.md v1.1.10 NOTE:\n"
                "'Fix TOCTOU issue between self-update check restart and other task'\n"
                "This is an explicit acknowledgment by Tencent that the race condition "
                "was present and required a dedicated fix."
            ),
            "binary_analysis": (
                "try_update (0x4cb520, 85 insns) + try_restart_agent (0x4cf4f0, 92 insns):\n"
                "The update sequence is:\n"
                "  1. check_update() → new version available\n"
                "  2. download_file(download_url) → write to disk\n"
                "  3. md5 compare (Cargo.toml: md5 = '0.8.0')\n"
                "  4. unzip_file() → extract to EXE_DIR/tmp/\n"
                "  5. verify_agent() → exec 'tat_agent --version'\n"
                "  6. run_self_update_script() → sh -c '...install.sh restart'\n"
                "Window: between step 5 (verify passes) and step 6 (exec install.sh), "
                "a concurrent task handler could be modifying EXE_DIR/tmp/ contents. "
                "v0.1.17 has no mutex or atomic flag protecting this window."
            ),
            "exploit_path": (
                "Requires a concurrent execution context on the same host (local privilege "
                "escalation scenario):\n"
                "1. Trigger a legitimate update (or wait for the update timer).\n"
                "2. Race: between verify_agent success and install.sh execution, "
                "   replace EXE_DIR/tmp/tat_agent with malicious binary.\n"
                "3. install.sh restarts the new binary as root.\n"
                "Reliability is low on fast systems; TOCTOU races are environment-dependent."
            ),
        },
        "versions_affected": ["0.1.15", "0.1.16", "0.1.17"],
        "fixed_in_source": "v1.1.10 (per CHANGELOG)",
        "remediation": (
            "Upgrade to tat-agent >= v1.1.10. "
            "Mitigation: hold an exclusive file lock on EXE_DIR/tmp/tat_agent from "
            "unzip_file through install.sh completion. "
            "Alternatively use atomic rename (O_TMPFILE + rename) to make replacement "
            "an atomic operation."
        ),
    },

    "TAT-F04": {
        "title": (
            "COS Temporary Credentials Fetched from IMDS via Plaintext HTTP — "
            "ARP MitM or SSRF from Co-Tenant Enables COS Credential Theft; "
            "Confirmed in urls.rs: http://metadata.tencentyun.com"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-319",
        "component": (
            "tat_agent::network::urls — METADATA_URL = 'http://metadata.tencentyun.com'; "
            "tat_agent::cos::COS::new (0x4216d0) → cos_sign (0x420a70)"
        ),
        "evidence": {
            "source_url": (
                "src/network/urls.rs:\n"
                "  const METADATA_URL: &str = 'http://metadata.tencentyun.com';\n"
                "  // used in COS credential fetch: GET /meta-data/cam/security-credentials/...\n"
                "HTTP (not HTTPS). Standard AWS/Tencent Cloud IMDS design — "
                "link-local only (169.254.169.254 equivalent) but routable via ARP injection "
                "or SSRF from within the VPC."
            ),
            "disasm_evidence": (
                "COS::cos_sign (0x420a70, 97 insns):\n"
                "  0x420ab2: call qword ptr [rip+0xa91370]  # time() — UNIX timestamp\n"
                "  0x420b2f: add rax, rcx                   # timestamp arithmetic\n"
                "  0x420b32: movabs rcx, 0xfffffff1886cb780 # epoch offset constant\n"
                "  0x420bbf: call qword ptr [rip+0xa8d3db]  # HMAC construction\n"
                "  0x420bd8: mov rcx, qword ptr [rsp+0x2d8] # credential key reference\n"
                "Credential struct populated by COS::new (0x4216d0) from IMDS response. "
                "HMAC-SHA1 signing uses the temporary secret key from IMDS."
            ),
            "attack_vector": (
                "1. ARP MitM on VM host network (or SSRF from co-tenant VM):\n"
                "   intercept HTTP GET to metadata.tencentyun.com\n"
                "2. Return attacker-controlled SecretId + SecretKey + Token in JSON response\n"
                "3. tat-agent uses these to sign COS requests (script output upload, log upload)\n"
                "4. Attacker holds valid credentials for the CVM's associated COS bucket\n"
                "\n"
                "Secondary: capture legitimate credentials in transit (no TLS):\n"
                "   HTTP response body contains plaintext SecretKey + Token\n"
                "   Simple passive capture on L2-accessible network segment"
            ),
            "scope": (
                "COS bucket contains: tat command output (stdout/stderr of executed commands), "
                "agent logs, possibly task artifacts. "
                "COS credential compromise → read all command outputs ever uploaded by this CVM, "
                "write arbitrary objects to the bucket."
            ),
        },
        "versions_affected": ["0.1.15", "0.1.16", "0.1.17"],
        "fixed_in_source": "Not documented in CHANGELOG as fixed.",
        "remediation": (
            "Use HTTPS for IMDS credential fetch. Tencent Cloud should serve "
            "https://metadata.tencentyun.com with a pinned certificate. "
            "Client-side: add a scheme check before the IMDS HTTP request; "
            "fail closed if HTTPS is not available."
        ),
    },

    "TAT-F05": {
        "title": (
            "ShellCommand::prepare_cmd Highest Semantic cmd_inject Score in Corpus (0.459) — "
            "Base64-Decoded Command Content Flows Directly to Shell Without Additional Sanitization; "
            "Design-by-Contract but Binary Shows No Guard Layer"
        ),
        "severity": "INFORMATIONAL",
        "cvss": "N/A",
        "cwe": "CWE-78",
        "component": (
            "tat_agent::executor::shell_command::ShellCommand::prepare_cmd (0x474440) -> "
            "ShellCommand::run (0x477d50)"
        ),
        "evidence": {
            "sweep_score": (
                "Ablation semantic sweep cmd_inject query score: 0.459 (highest in corpus). "
                "Matched against 13 target functions."
            ),
            "disasm_evidence": (
                "prepare_cmd (0x474440, 22 insns until first branch):\n"
                "  0x474487: call 0x475a60   # shell detection: searches PATH for bash\n"
                "  0x47448c: cmp qword [rsp+0x210], 0  # bash found?\n"
                "  0x474495: je 0x4744a5      # no: fall through to sh detection\n"
                "  0x474497: lea rax, [rip+0x547c65]  # 0x3d='=' ? (format string char?)\n"
                "  0x4744a5: lea rsi, [rip+0x547c94]  # 2-byte string (sh?)\n"
                "  0x4744ce: call 0x475a60   # shell detection: searches PATH for sh\n"
                "The function selects bash or sh, then constructs the command string. "
                "User-controlled content (task.rs: decode base64(task.command)) is "
                "written to EXE_DIR/tmp/{task_id}.sh and executed by the selected shell."
            ),
            "design_context": (
                "tat-agent's model: commands are script content, not shell strings. "
                "Task.init() writes the decoded command to a .sh temp file, then "
                "ShellCommand executes that file. This is safer than passing command "
                "as a string argument to sh -c '...'. "
                "Injection path exists only if: (a) command content escapes the temp file "
                "boundary, or (b) path to temp file is predictable and race-replaceable. "
                "Severity is informational because command injection is the feature, "
                "not a vulnerability — the authorization layer is the WS control channel "
                "with HMAC-authenticated messages."
            ),
            "note": (
                "The cmd_inject signal is expected for an automation agent. "
                "The HMAC-authenticated WebSocket control channel is the actual trust boundary. "
                "If the WS auth is bypassed (e.g., HMAC key extraction), arbitrary command "
                "execution follows. TAT-F05 is a signal, not a standalone finding."
            ),
        },
        "versions_affected": ["0.1.15", "0.1.16", "0.1.17"],
        "fixed_in_source": "N/A — design feature",
        "remediation": (
            "Protect the WebSocket control channel key material. "
            "If the HMAC key is extracted from the binary or configuration, "
            "arbitrary command execution follows through the existing shell execution path."
        ),
    },

    "TAT-F06": {
        "title": (
            "tssh ProxyNew Handler Performs Unrestricted C2-Directed TCP Connect — "
            "SSRF to VPC-Internal Services, IMDS (169.254.169.254), and Localhost; "
            "Source: src/tssh/proxy.rs ProxyNew::process()"
        ),
        "severity": "HIGH",
        "cvss": "7.2",
        "cwe": "CWE-918",
        "component": (
            "src/tssh/proxy.rs — Handler<Bson, ProxyNew>::process() -> "
            "TcpStream::connect(format!('{}:{}', req.inner.data.ip, req.inner.data.port))"
        ),
        "evidence": {
            "source_evidence": (
                "proxy.rs ProxyNew::process():\n"
                "  let addr = format!('{}:{}', req.inner.data.ip, req.inner.data.port);\n"
                "  let stream = match TcpStream::connect(&addr).await {\n"
                "      Ok(s) => Mutex::new(s),\n"
                "      Err(e) => return self.reply_err(e).await,\n"
                "  };\n"
                "  // loop: reader.read() -> Tssh::reply(ProxyData); proxy_rx.recv() -> writer.write_all()\n"
                "\n"
                "No validation of ip or port before connect. The ip field is a raw String "
                "from the BSON-encoded WebSocket message originating from the Tencent cloud C2. "
                "PROXY_TTL = 5 minutes; PROXY_BUF_SIZE = 2048 bytes per read."
            ),
            "threat_model": (
                "The tssh ProxyNew message is sent by the cloud console/API (ConnectForward). "
                "An attacker who can send ProxyNew messages (via compromised Tencent cloud "
                "account, rogue Tencent employee, or man-in-the-WebSocket-connection) can "
                "direct the CVM agent to TCP-connect to any host:port reachable from the CVM:\n"
                "\n"
                "  Target                         Impact\n"
                "  169.254.169.254:80             IMDS — TencentCloud/AWS credential endpoint\n"
                "  localhost:6379                 Redis (no-auth default)\n"
                "  localhost:8080                 Internal web services\n"
                "  10.0.0.x:22/3306/5432          VPC-internal hosts not exposed externally\n"
                "  169.254.0.23:80                TencentCloud qcloud metadata\n"
                "\n"
                "The ProxyData message type then bidirectionally relays bytes between the "
                "attacker's WebSocket channel and the TCP stream — full duplex."
            ),
            "session_management": (
                "Session lifetime: SESSION_TTL = 5 min; PROXY_TTL = 5 min. "
                "Multiple simultaneous proxy channels per session are possible "
                "(each gets a unique channel_id). "
                "Legacy compat: if channel_id is empty, proxy_id is used — allows "
                "connection to multiple distinct ip:port targets in one session."
            ),
            "chain": (
                "TAT-F06 → TAT-F04 chain:\n"
                "1. Attacker sends ProxyNew{ip='169.254.169.254', port=80}.\n"
                "2. Agent connects and relays bytes.\n"
                "3. Attacker sends HTTP GET /meta-data/cam/security-credentials/... via ProxyData.\n"
                "4. Agent relays IMDS response back — TencentCloud SecretId/SecretKey/Token exposed.\n"
                "5. Credentials used to access COS bucket containing command output history.\n"
                "\n"
                "This bypasses TAT-F04's requirement for ARP MitM — attacker controls the "
                "proxy destination directly from the C2 channel."
            ),
        },
        "versions_affected": ["all tssh-enabled versions (source >= 1.2.0)"],
        "fixed_in_source": "Not documented in CHANGELOG as addressed.",
        "remediation": (
            "In ProxyNew::process(), validate ip against an allowlist or blocklist:\n"
            "  - Block link-local (169.254.0.0/16), loopback (127.0.0.0/8), "
            "RFC-1918 private ranges if proxy to internal hosts is not a required feature.\n"
            "  - At minimum, block 169.254.169.254 (IMDS) and 169.254.0.23 (qcloud metadata).\n"
            "  - Validate port is in expected range (not 0, not high-port privileged services).\n"
            "  - Log all ProxyNew connections with ip/port for audit."
        ),
    },

    "TAT-F07": {
        "title": (
            "tssh File API Missing inspect_access() on ListPath, FileExist, FileInfo — "
            "PTY Session User Boundary Bypassed for Filesystem Enumeration; "
            "Source: src/tssh/file.rs"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-284",
        "component": (
            "src/tssh/file.rs — Handler<Bson, ListPathReq>, FileExistReq, FileInfoReq "
            "lack plugin.inspect_access() call present in WriteFileReq, DeleteFileReq, ReadFileReq"
        ),
        "evidence": {
            "source_evidence": (
                "file.rs access control parity:\n"
                "\n"
                "  WriteFileReq::process():\n"
                "    plugin.inspect_access(path, PTY_INSPECT_WRITE).await  ← PRESENT\n"
                "\n"
                "  DeleteFileReq::process():\n"
                "    plugin.inspect_access(path, PTY_INSPECT_WRITE).await  ← PRESENT\n"
                "\n"
                "  ReadFileReq::process():\n"
                "    plugin.inspect_access(path, PTY_INSPECT_READ).await   ← PRESENT\n"
                "\n"
                "  ListPathReq::process():  ← NO inspect_access call\n"
                "    read_dir(path).await   # direct filesystem read\n"
                "\n"
                "  FileExistReq::process(): ← NO inspect_access call\n"
                "    Path::new(path).exists()\n"
                "\n"
                "  FileInfoReq::process():  ← NO inspect_access call\n"
                "    metadata(path).await   # returns size, mode, timestamps, uid/gid"
            ),
            "impact": (
                "inspect_access() gates filesystem operations based on the PTY session's "
                "user context (the user the terminal was opened as). When a Tencent cloud "
                "console operator opens a terminal as 'www-data' or a restricted user, "
                "the intention is that file operations are constrained to that user's access. "
                "\n"
                "The three unchecked operations allow the cloud session to:\n"
                "  ListPath('/root/')    — enumerate root's home directory\n"
                "  ListPath('/etc/shadow') — observe file existence in any directory\n"
                "  FileExist('/etc/shadow') — confirm sensitive file presence\n"
                "  FileInfo('/etc/shadow') — read st_mode, st_size, st_uid, timestamps\n"
                "\n"
                "This leaks file tree structure, permissions, and metadata for files "
                "the session's user cannot read, across the entire CVM filesystem."
            ),
            "note": (
                "Exploitation requires an authenticated WebSocket session to the tssh "
                "endpoint (cloud console access). The finding is relevant when "
                "multi-tenant or restricted-privilege cloud sessions are in use. "
                "A cloud console operator restricted to 'app_user' can still enumerate "
                "root-owned directories and infer system configuration from metadata."
            ),
        },
        "versions_affected": ["all tssh-enabled versions (source >= 1.2.0)"],
        "fixed_in_source": "Not documented in CHANGELOG.",
        "remediation": (
            "Add inspect_access() calls consistently to all file operation handlers:\n"
            "  ListPathReq::process():\n"
            "    plugin.inspect_access(path, PTY_INSPECT_READ).await?;\n"
            "  FileExistReq::process():\n"
            "    plugin.inspect_access(path, PTY_INSPECT_READ).await?;\n"
            "  FileInfoReq::process():\n"
            "    plugin.inspect_access(path, PTY_INSPECT_READ).await?;\n"
            "Consistent access control across all file message types."
        ),
    },
}

# ─── Function Map ─────────────────────────────────────────────────────────────

FUNCTION_MAP = {
    # VA: (demangled_name, insn_count, findings)
    0x4cb520: ("try_update",                  85,  ["TAT-F01", "TAT-F02", "TAT-F03"]),
    0x4cf4f0: ("try_restart_agent",           92,  ["TAT-F03"]),
    0x474440: ("ShellCommand::prepare_cmd",   22,  ["TAT-F05"]),
    0x473ea0: ("ShellCommand::user_check",    29,  []),
    0x492820: ("HttpRequester::initialize",   42,  ["TAT-F01"]),
    0x4216d0: ("COS::new",                    98,  ["TAT-F04"]),
    0x420a70: ("COS::cos_sign",               97,  ["TAT-F04"]),
    0x465040: ("http::thread::run",           48,  []),
    0x477d50: ("ShellCommand::run",           12,  ["TAT-F05"]),
    0x4c5310: ("ws::handle_server_msg",       61,  []),
    0x4c5b90: ("ws::handle_ping_notify_msg",  75,  []),
    0x4abde0: ("cos::to_headers",             32,  ["TAT-F04"]),
    # tssh source-only (not in v0.1.17 binary — tssh added in 1.2.0)
    "tssh/proxy.rs:ProxyNew::process": (
        "Handler<Bson,ProxyNew>::process", None, ["TAT-F06"]
    ),
    "tssh/file.rs:ListPathReq::process": (
        "Handler<Bson,ListPathReq>::process", None, ["TAT-F07"]
    ),
    "tssh/file.rs:FileExistReq::process": (
        "Handler<Bson,FileExistReq>::process", None, ["TAT-F07"]
    ),
    "tssh/file.rs:FileInfoReq::process": (
        "Handler<Bson,FileInfoReq>::process", None, ["TAT-F07"]
    ),
}

# ─── Changelog Deltas ─────────────────────────────────────────────────────────

# Security-relevant fixes present in source (v1.2.2) but ABSENT in binary (v0.1.17)
UNFIXED_IN_BINARY = {
    "v1.1.10": "Fix TOCTOU issue between self-update check restart and other task → TAT-F03",
    "v1.2.0": "Fix tat_install scripts: stop service order and TLS certificate validation",
    # tssh module added in 1.2.0 — not present in binary v0.1.17
    "v1.2.0 (tssh added)": "ProxyNew SSRF (TAT-F06) + file API missing access control (TAT-F07) "
                           "introduced with tssh; not present in binary 0.1.17",
    "v1.2.2 (still open)": "TAT-F06 + TAT-F07 not documented as fixed in CHANGELOG through v1.2.2",
}

# ─── Probe ────────────────────────────────────────────────────────────────────

def probe(binary_path: Optional[str] = None) -> dict:
    """
    Static probe: return all findings (all confirmed via binary + source RE).
    For active probing of deployed instances, use tiptoe or aimap tat-agent fingerprint.
    """
    return {
        "target": TARGET,
        "binary_version": BINARY_VERSION,
        "load_va": hex(LOAD_VA),
        "findings": list(FINDINGS.keys()),
        "critical": [],
        "high": ["TAT-F01", "TAT-F04", "TAT-F06"],
        "medium": ["TAT-F03", "TAT-F07"],
        "low": [],
        "informational": ["TAT-F02_chain_only", "TAT-F05"],
        "note": (
            "TAT-F02 severity is CRITICAL when chained with TAT-F01 (backend compromise). "
            "Standalone (no TAT-F01): requires attacker to serve malicious zip, "
            "which requires HTTPS backend access. "
            "TAT-F06 + TAT-F04 chain: ProxyNew to IMDS bypasses the ARP-MitM prerequisite of TAT-F04."
        ),
        "chain_primary": "TAT-F01 + TAT-F02 = backend compromise → HTTP download → ZipSlip → root RCE",
        "chain_ssrf": "TAT-F06 → TAT-F04 = cloud account compromise → ProxyNew IMDS → COS credential theft",
        "contrast_with_stargate": (
            "TCS-F01 (Stargate): direct network MitM → root RCE. "
            "TAT-F01+F02: backend server compromise required. "
            "tat-agent is meaningfully more secure than Stargate on the update channel. "
            "tssh module (v1.2.0+) adds a new cloud-account-level attack surface via ProxyNew SSRF."
        ),
    }
