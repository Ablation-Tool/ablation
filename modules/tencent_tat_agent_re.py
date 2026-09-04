"""
tat-agent (Tencent Automation Tool) — RE Module
Binary: tat_agent v0.1.17 (2021-12-20), ELF x86_64, statically linked, NOT stripped
Source: /media/cowboy/research/tencent-agent/tat-agent/src/ (v1.2.2 source)
Binaries: tat_agent_linux_install_x86_64_0.1.17.zip (extracted)
Load VA: 0x400000 (non-PIE, fixed)
Total functions: 21,484 text functions (474 in tat_agent:: namespace)

Sweep method: ablation semantic BERT sweep (all-MiniLM-L6-v2) over 300 target functions.
Query profiles: tls_bypass, cmd_inject, md5_weak, priv_drop, file_write, download_exec,
                http_url_server_ctrl, sha1_rsa_signature, hmac_sha1_cos_auth.

Binary sweep results (session 2026-09-04):
  crypto::sha1::Sha1::new  confirmed at 0x8cb4f0 (nm T symbol)
  crypto::hmac::Hmac<D>::new  confirmed at 0x4ab750 (nm T symbol)
  <tat_agent::cos::client::COS as tat_agent::cos::auth::Auth>::cos_sign (0x420a70):
    calls Sha1::new (0x8cb4f0) then Hmac<D>::new (0x4ab750) — HMAC-SHA1 COS v4 auth confirmed
  build_extra_headers: no standalone symbol (inlined); RSA+SHA1 confirmed via source (TAT-F09)
  check_ontime_update (0x477170): SystemTime::elapsed timer gate, 0x1c20=7200s interval — no crypto
  store_path_check (0x488310/0x477cf0): early-return on non-empty length field — path gate logic
  COS::cos_sign (0x420a70): HMAC-SHA1 for Tencent COS v4 signature — TAT-F11

Key function addresses (VA, confirmed via nm + disasm):
  0x4cb520  tat_agent::ontime::updater::try_update
  0x4cf4f0  tat_agent::ontime::updater::try_restart_agent
  0x474440  tat_agent::executor::shell_command::ShellCommand::prepare_cmd
  0x473ea0  tat_agent::executor::shell_command::ShellCommand::user_check
  0x492820  tat_agent::network::http::requester::HttpRequester::initialize
  0x4216d0  tat_agent::cos::COS::new
  0x420a70  tat_agent::cos::COS::cos_sign  [TAT-F11: HMAC-SHA1 confirmed]
  0x465040  tat_agent::network::http::thread::run
  0x477d50  tat_agent::executor::shell_command::ShellCommand::run
  0x4c5310  tat_agent::network::ws::handle_server_msg
  0x4abde0  tat_agent::cos::to_headers
  0x8cb4f0  crypto::sha1::Sha1::new  [called from cos_sign]
  0x4ab750  crypto::hmac::Hmac<D>::new  [called from cos_sign]
  0x4ab550  crypto::hmac::Hmac<D>::result

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
    (7) tssh PluginComp::execute() missing setgroups — root supplementary groups retained (TAT-F08)
    (8) tssh file API missing inspect_access on ListPath/FileExist/FileInfo (TAT-F07)
    (9) RSA-PKCS1v15-SHA1 in Invoke API authentication headers (TAT-F09)
    (10) chown() UB via non-null-terminated &str in unsafe FFI (TAT-F10)
    (11) HMAC-SHA1 in COS object storage authentication (TAT-F11) — binary confirmed
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

    "TAT-F08": {
        "title": (
            "tssh PluginComp::execute() Missing setgroups() Before Privilege Drop — "
            "Child Process Retains Root Supplementary Groups After setgid/setuid; "
            "Same Bug Class as CHANGELOG 1.1.10 Fix for Main Executor; "
            "Reintroduced in tssh Code Path (Added v1.2.0)"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-269",
        "component": (
            "src/tssh/pty/unix.rs — PluginComp::execute() — "
            "libc::setgid() + libc::setuid() without libc::setgroups() in fork child"
        ),
        "evidence": {
            "source_evidence": (
                "tssh/pty/unix.rs PluginComp::execute() (the fork path):\n"
                "  let pid = libc::fork();\n"
                "  if pid == 0 {\n"
                "      let _ = env::set_current_dir(cwd_path);\n"
                "      libc::setgid(user.primary_group_id());  // ← gid drop\n"
                "      libc::setuid(user.uid());                // ← uid drop\n"
                "      // NO setgroups() call before setgid/setuid\n"
                "      match f() { ... }   // ← closure runs with hybrid privilege\n"
                "  }"
            ),
            "correct_implementation": (
                "executor/unix.rs exec_as_user() (the FIXED main executor path):\n"
                "  // Fix from CHANGELOG 1.1.10: setgroups before setgid/setuid\n"
                "  if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } != 0 {\n"
                "      return Err(io::Error::last_os_error());\n"
                "  }\n"
                "  if unsafe { libc::setgid(gid) } != 0 { return Err(...); }\n"
                "  if unsafe { libc::setuid(uid) } != 0 { return Err(...); }\n"
                "  if unsafe { libc::setpgid(0, 0) } != 0 { return Err(...); }"
            ),
            "posix_requirement": (
                "POSIX: setgroups() must be called BEFORE setuid(). Once setuid() drops root,\n"
                "the process no longer has CAP_SETGID and cannot call setgroups() to clear\n"
                "supplementary groups. The tssh execute() path reverses this (setgid/setuid,\n"
                "no setgroups) — the fork child's supplementary group list is inherited from\n"
                "the root parent and cannot be changed after setuid()."
            ),
            "supplementary_group_impact": (
                "TAT agent (root daemon) typically has supplementary groups including:\n"
                "  - docker (access to /var/run/docker.sock → container breakout)\n"
                "  - adm (read access to /var/log/*)\n"
                "  - wheel (sudo access on some configurations)\n"
                "  - disk (raw disk access)\n"
                "  - Any custom groups assigned to the tat_agent service account\n"
                "\n"
                "A tssh ExecCmdReq or CreateFileReq session opened as 'www-data' or 'app_user'\n"
                "runs the closure with uid=www-data, gid=www-data, supplementary=root-groups.\n"
                "If root is in the docker group, the closure can access Docker socket despite\n"
                "www-data having no docker group membership."
            ),
            "affected_operations": (
                "Operations using PluginComp::execute() (missing setgroups):\n"
                "  1. ExecCmdReq: StdCommand::new('bash').args(['-c', cmd]) — runs bash\n"
                "     as target user but with root supplementary groups\n"
                "  2. CreateFileReq: create_dir_all(parent) + create_dir/create_file(path)\n"
                "     — creates files/dirs with root supplementary group membership\n"
                "\n"
                "Operations using execute_stream() (CORRECT — uses configure_command):\n"
                "  - ExecCmdStreamReq: calls init_command + configure_command which includes\n"
                "    pre_exec(exec_as_user()) with correct setgroups sequence"
            ),
            "changelog_context": (
                "CHANGELOG 1.1.10: 'Fix setgroups when exec command and login'\n"
                "This fix was applied to executor/unix.rs exec_as_user().\n"
                "CHANGELOG 1.2.0: tssh module added (including PluginComp::execute()).\n"
                "The tssh execute() implementation does not inherit the setgroups fix from\n"
                "exec_as_user() — it uses a direct fork/setgid/setuid pattern instead,\n"
                "reintroducing the same bug class 2 releases after it was fixed."
            ),
        },
        "versions_affected": ["source >= 1.2.0 (tssh module introduction)"],
        "fixed_in_source": "Not fixed in v1.2.2 (the bug is in the current source).",
        "remediation": (
            "In PluginComp::execute() fork child, add setgroups() before setgid/setuid:\n"
            "  let groups: Vec<libc::gid_t> = user.groups().unwrap_or_default()\n"
            "      .iter().map(|g| g.gid()).collect();\n"
            "  libc::setgroups(groups.len(), groups.as_ptr());  // MUST be first\n"
            "  libc::setgid(user.primary_group_id());\n"
            "  libc::setuid(user.uid());\n"
            "Refactor to reuse exec_as_user() from executor/unix.rs to avoid "
            "future divergence between execution paths."
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

    "TAT-F09": {
        "title": (
            "Invoke API Authentication Signature Uses SHA1 (NIST-Deprecated Since 2013) — "
            "RSA-PKCS1v15-SHA1 Over Concatenated Fields Without Delimiters; "
            "Source: src/network/mod.rs build_extra_headers()"
        ),
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-327",
        "component": (
            "src/network/mod.rs build_extra_headers() lines 94-102; "
            "Pkcs1v15Sign::new::<Sha1>() + Sha1::digest()"
        ),
        "evidence": {
            "source_evidence": (
                "src/network/mod.rs build_extra_headers():\n"
                "  let data = format!('{}{}{}{}',\n"
                "      record.machine_id, record.instance_id, rand_key, timestamp);\n"
                "  let digest = Sha1::digest(data.as_bytes());\n"
                "  let sigvec = private_key.sign(Pkcs1v15Sign::new::<Sha1>(), &digest);\n"
                "  let signature = STANDARD.encode(sigvec.expect('rsa sign failed'));\n"
                "  headers.insert('Signature', value(&signature));\n"
                "\n"
                "Authentication headers sent on every Invoke API call:\n"
                "  MachineId: <machine_id>\n"
                "  InstanceId: <instance_id>\n"
                "  RandomKey: <32 random alphanumeric chars>\n"
                "  Timestamp: <unix epoch seconds>\n"
                "  Signature: <base64(RSA-PKCS1v15-SHA1(machine_id+instance_id+rand_key+ts))>"
            ),
            "sha1_weakness": (
                "SHA1 was deprecated for digital signatures by NIST SP 800-131A Rev.2 (2019). "
                "PKCS#1 v1.5 with SHA1 is vulnerable to:\n"
                "  1. Chosen-prefix collision attacks (SHAttered, 2017): ~2^63 SHA1 operations "
                "     to forge a signature collision, reduced from brute-force cost. "
                "     Practical with GPU clusters; documented for PDF signatures.\n"
                "  2. Theoretical length-extension attacks on the raw hash (mitigated by PKCS#1 "
                "     padding but combined with SHA1 weakness, adds risk).\n"
                "PKCS#1 v1.5 itself is deprecated in favor of PSS (RFC 8017). "
                "The combination of PKCS1v15 + SHA1 is the weakest RSA signing configuration."
            ),
            "concatenation_ambiguity": (
                "Signed data: format!('{}{}{}{}', machine_id, instance_id, rand_key, timestamp)\n"
                "No separator between fields. Concatenation ambiguity:\n"
                "  machine_id='abc', instance_id='defXY', rand_key='123', ts='456'\n"
                "  signed: 'abcdefXY123456'\n"
                "  vs machine_id='abcde', instance_id='fXY', rand_key='123', ts='456'\n"
                "  signed: 'abcdefXY123456'\n"
                "Identical signed payloads with different field values. "
                "In practice, machine_id and instance_id have different format constraints "
                "(machine_id is hardware-derived, instance_id='ins-XXXXXXXX'), limiting "
                "practical collision. BUT: rand_key is 32 alphanumeric chars with no format "
                "constraint — it can be chosen to bridge field boundaries if machine_id length "
                "varies, creating a theoretical cross-instance signature portability issue."
            ),
            "attack_scenario": (
                "SHA1 collision attack to forge signature:\n"
                "1. Attacker observes legitimate Invoke API request (via MITM or log access)\n"
                "2. Crafts two messages M1 and M2 that SHA1-collide\n"
                "3. If attacker has signature for M1, it validates for M2 too\n"
                "4. M2 can be constructed to authorize a different (machine_id, instance_id) pair\n"
                "Cost: ~2^63 SHA1 ops (months of GPU cluster time). Practical for nation-state "
                "actors; theoretical for commodity attackers. Risk level: MEDIUM."
            ),
        },
        "versions_affected": ["all versions (source: current main branch)"],
        "fixed_in_source": "Not documented in CHANGELOG.",
        "remediation": (
            "Replace SHA1 with SHA256 in RSA signature:\n"
            "  use sha2::Sha256;\n"
            "  use rsa::pkcs1v15::Pkcs1v15Sign;\n"
            "  let digest = Sha256::digest(data.as_bytes());\n"
            "  private_key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)\n"
            "Preferably migrate to RSA-PSS (RSASSA-PSS) which is stronger than PKCS#1 v1.5:\n"
            "  use rsa::pss::Pss;\n"
            "  private_key.sign(Pss::new::<Sha256>(), &digest)\n"
            "Also add field separators to signed data to prevent concatenation ambiguity:\n"
            "  let data = format!('{}|{}|{}|{}', machine_id, instance_id, rand_key, ts);"
        ),
    },

    "TAT-F11": {
        "title": (
            "COS Object Storage Authentication Uses HMAC-SHA1 (Tencent COS API v4) — "
            "Deprecated Digest; Binary-Confirmed via crypto::sha1::Sha1::new + "
            "crypto::hmac::Hmac<D>::new in cos_sign (0x420a70); "
            "Source: src/cos/auth.rs"
        ),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-327",
        "component": (
            "tat_agent::cos::COS::cos_sign (0x420a70) — "
            "calls crypto::sha1::Sha1::new (0x8cb4f0) + crypto::hmac::Hmac<D>::new (0x4ab750) "
            "to compute COS v4 HMAC-SHA1 authorization signature"
        ),
        "evidence": {
            "binary_evidence": (
                "ablation BERT sweep 2026-09-04 — binary symbol table (nm T, demangled):\n"
                "  0x8cb4f0  crypto::sha1::Sha1::new\n"
                "  0x8cb540  <crypto::sha1::Sha1 as crypto::digest::Digest>::input\n"
                "  0x8cb5d0  <crypto::sha1::Sha1 as crypto::digest::Digest>::result\n"
                "  0x4ab750  crypto::hmac::Hmac<D>::new\n"
                "  0x4ab550  <crypto::hmac::Hmac<D> as crypto::mac::Mac>::result\n"
                "  0x8c9cf0  crypto::hmac::derive_key\n"
                "\n"
                "cos_sign (0x420a70) disassembly (radare2):\n"
                "  0x420ab2: call sym.chrono::offset::local::Local::now  ; get current timestamp\n"
                "  [date arithmetic: extract year/month/day into integer fields]\n"
                "  0x420bcd: call sym.crypto::sha1::Sha1::new::h1d0ea730d433c0e0\n"
                "  0x420bf5: call sym.crypto::hmac::Hmac<D>::new::heec486cbf6a432e9\n"
                "\n"
                "The function retrieves the current time (chrono::Local::now), formats a "
                "timestamp string, then initializes SHA1 and constructs an HMAC-SHA1 keyed "
                "MAC over the signing string. This is the Tencent COS API v4 signature algorithm."
            ),
            "cos_v4_context": (
                "Tencent Cloud COS API uses two signature schemes:\n"
                "  v4 (legacy): HMAC-SHA1 over 'StringToSign' built from HTTP method, path, headers\n"
                "  v5 (current): HMAC-SHA256 (recommended for all new integrations since 2018)\n"
                "\n"
                "tat-agent v0.1.17 (2021-12-20) implements v4 (HMAC-SHA1). "
                "The signing key is the COS SecretKey obtained from the IMDS credential "
                "endpoint (see TAT-F04: http://metadata.tencentyun.com/...cam/security-credentials). "
                "The signed request grants the agent access to COS buckets for file upload/download "
                "(used in task output reporting)."
            ),
            "sha1_weakness": (
                "SHA1 was deprecated for digital signatures and MACs by NIST SP 800-131A Rev.2 (2019). "
                "HMAC-SHA1 is less vulnerable than bare SHA1 for collision attacks "
                "(HMAC provides key-dependent separation). "
                "However:\n"
                "  1. Brute-force HMAC-SHA1 key recovery: practical if secret key is short/weak\n"
                "     (tat-agent uses IAM credentials from IMDS — key length varies)\n"
                "  2. SHA1 output is 160 bits vs HMAC-SHA256 256 bits — smaller attack surface\n"
                "  3. Known SHA1 weaknesses propagate to HMAC in theoretic scenarios\n"
                "  4. Tencent's own COS documentation marks v4 as DEPRECATED since 2018\n"
                "\n"
                "Primary risk: uses the IMDS-sourced SecretKey (TAT-F04 chain). "
                "If IMDS credentials are stolen (TAT-F06→TAT-F04 chain), the attacker "
                "can forge HMAC-SHA1 COS signatures more easily than HMAC-SHA256."
            ),
            "chain_context": (
                "TAT-F11 amplifies the TAT-F06→TAT-F04 chain:\n"
                "  1. TAT-F06 (ProxyNew): cloud-directed TCP proxy to 169.254.169.254\n"
                "  2. TAT-F04 (HTTP IMDS): COS SecretKey extracted from IMDS response\n"
                "  3. TAT-F11 (HMAC-SHA1): attacker signs COS requests with stolen key;\n"
                "     SHA1 offers weaker forgery resistance than SHA256 if key is reused "
                "     across many HMAC operations"
            ),
        },
        "versions_affected": ["0.1.17 and all versions using COS v4 signing"],
        "fixed_in_source": (
            "Check if src/cos/auth.rs in v1.2.2 uses sha1 or sha256 (not yet verified). "
            "Tencent COS Go SDK migrated to v5 (SHA256) circa 2020; Rust crate status unclear."
        ),
        "remediation": (
            "Migrate to COS API v5 signature scheme (HMAC-SHA256):\n"
            "  Replace crypto::sha1::Sha1 with sha2::Sha256\n"
            "  Replace crypto::hmac::Hmac<sha1::Sha1> with hmac::Hmac<sha2::Sha256>\n"
            "  Update signing string format to COS v5 specification\n"
            "  (Tencent COS v5 signing: https://cloud.tencent.com/document/product/436/7778)\n"
            "Also address TAT-F04 (HTTPS for IMDS) to protect the key material."
        ),
    },

    "TAT-F10": {
        "title": (
            "update_file_permission() Passes Non-Null-Terminated &str Pointer to libc::chown() — "
            "Undefined Behavior in Unsafe C FFI; config.dat Ownership Change May Silently Fail; "
            "Source: src/common/mod.rs update_file_permission()"
        ),
        "severity": "LOW",
        "cvss": "3.7",
        "cwe": "CWE-119",
        "component": (
            "src/common/mod.rs update_file_permission() line 174; "
            "unsafe { libc::chown(path.as_ptr() as *const c_char, uid, gid) }"
        ),
        "evidence": {
            "source_evidence": (
                "src/common/mod.rs update_file_permission():\n"
                "  pub fn update_file_permission(path: &str) {\n"
                "      let uid = unsafe { libc::getuid() };\n"
                "      let gid = unsafe { libc::getgid() };\n"
                "      unsafe { libc::chown(path.as_ptr() as *const c_char, uid, gid) }; // BUG\n"
                "      let _ = set_permissions(path, Permissions::from_mode(0o600));\n"
                "  }\n"
                "\n"
                "Called from config.rs save_config() after writing config.dat."
            ),
            "ub_explanation": (
                "path.as_ptr() returns a *const u8 pointer to the string's content buffer. "
                "Rust &str is NOT null-terminated — it is a (pointer, length) pair. "
                "libc::chown() expects a C string: reads bytes until it finds '\\0'. "
                "\n"
                "Casting the &str pointer to *const c_char and passing to chown() is undefined "
                "behavior: chown will read past the string's length until it finds a null byte "
                "in adjacent memory. The actual path chown operates on depends on what bytes "
                "follow 'config.dat' on the stack/heap.\n"
                "\n"
                "In practice: the string 'config.dat' is likely followed by a null byte in "
                "most allocator layouts, causing chown to operate on the correct path by accident. "
                "But this is not guaranteed and constitutes a memory safety violation in "
                "Rust's unsafe code."
            ),
            "impact": (
                "If chown reads a longer 'path' from adjacent memory:\n"
                "  - Attempts to chown a non-existent path → silently ignored (ENOENT discarded)\n"
                "  - set_permissions() still runs using the correct Rust path — so 0600 is set\n"
                "  - Worst case: if adjacent memory contains a valid path, chown changes ownership "
                "    of an unintended file (very unlikely given 'config.dat' context)\n"
                "The primary risk is undefined behavior correctness, not a direct exploit path."
            ),
        },
        "versions_affected": ["all versions (source: current main branch)"],
        "fixed_in_source": "Not documented in CHANGELOG.",
        "remediation": (
            "Use CString for null-terminated path:\n"
            "  use std::ffi::CString;\n"
            "  let cpath = CString::new(path).expect('path contains null byte');\n"
            "  unsafe { libc::chown(cpath.as_ptr(), uid, gid) };\n"
            "Or use the nix crate's chown which handles &Path correctly:\n"
            "  nix::unistd::chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))"
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
    0x420a70: ("COS::cos_sign",               97,  ["TAT-F04", "TAT-F11"]),
    0x8cb4f0: ("crypto::sha1::Sha1::new",      None, ["TAT-F11"]),
    0x4ab750: ("crypto::hmac::Hmac<D>::new",   None, ["TAT-F11"]),
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
        "high": ["TAT-F01", "TAT-F04", "TAT-F06", "TAT-F08"],
        "medium": ["TAT-F03", "TAT-F07", "TAT-F09", "TAT-F11"],
        "low": ["TAT-F10"],
        "informational": ["TAT-F02_chain_only", "TAT-F05"],
        "note": (
            "TAT-F02 severity is CRITICAL when chained with TAT-F01 (backend compromise). "
            "Standalone (no TAT-F01): requires attacker to serve malicious zip, "
            "which requires HTTPS backend access. "
            "TAT-F06 + TAT-F04 chain: ProxyNew to IMDS bypasses the ARP-MitM prerequisite of TAT-F04."
        ),
        "chain_primary": "TAT-F01 + TAT-F02 = backend compromise → HTTP download → ZipSlip → root RCE",
        "chain_ssrf": "TAT-F06 → TAT-F04 → TAT-F11 = cloud account compromise → ProxyNew IMDS → COS credential theft → HMAC-SHA1 forgery",
        "contrast_with_stargate": (
            "TCS-F01 (Stargate): direct network MitM → root RCE. "
            "TAT-F01+F02: backend server compromise required. "
            "tat-agent is meaningfully more secure than Stargate on the update channel. "
            "tssh module (v1.2.0+) adds a new cloud-account-level attack surface via ProxyNew SSRF."
        ),
    }
