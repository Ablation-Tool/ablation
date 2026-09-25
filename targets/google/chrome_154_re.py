"""
RE module: Google Chrome 154.0.8037.57 (stable) x86_64
Source RPM: google-chrome-stable_current_x86_64.rpm
Extracted: /tmp/chrome_rpm_extract/opt/google/chrome/

Binaries analyzed:
  chrome                         281MB  stripped PIE ELF x86-64  BuildID e9584a00bc04d469c5e087f8dc58635b044085c3
  chrome-sandbox                  15KB  SETUID stripped PIE ELF x86-64  BuildID 5eb057c0e97a89154ae4507a7ee337f25eb7a129
  libwidevinecdm.so               21MB  stripped ELF x86-64  BuildID 58252b02901d485c773ba48e56ee9677af82b76a (pending)
  liboptimization_guide_internal.so 24MB stripped ELF x86-64 (pending)

Version: 154.0.8037.57
Channel: stable (CHROME_VERSION_EXTRA: "stable")
Build: Sep 21 2026, Linker: LLD 24.0.0

Priority order for RE:
  1. chrome-sandbox  -- SUID setuid, 15KB, small attack surface, high CIA on sandbox escape
  2. chrome          -- 281MB main binary; Mojo IPC + WebRTC + V8 + media codec surface
  3. libwidevinecdm  -- DRM, typically obfuscated; CDM interface boundary
  4. liboptimization_guide_internal -- on-device ML model runner

chrome-sandbox attack surface (from PLT + strings):
  - getenv("SBX_CHROME_API_RQ"), getenv("SBX_CHROME_API_PRV"), getenv("SBX_D"),
    getenv("SBX_HELPER_PID"), getenv("SBX_PID_NS"), getenv("SBX_NET_NS")
  - strtol(getenv result) -> OOM score, pid
  - socketpair() -> bidirectional IPC with browser process
  - read() -> response parsing from browser via socketpair
  - execv(argv[1], ...) -> launch sandboxed binary
  - chroot() + chdir() -> filesystem jail
  - setresuid() + setresgid() -> privilege drop
  - prctl() -> seccomp/PR_SET_NO_NEW_PRIVS
  - syscall(SYS_clone, ...) -> pid/net namespace creation
  - openat64() -> fd-based path validation (TOCTOU window)
  - --get-api, --adjust-oom-score CLI modes besides normal exec mode

chrome main binary Mojo IPC surface (from strings):
  blink.mojom.*, media.mojom.*, network.mojom.*, viz.mojom.*,
  on_device_translation.mojom.*, extensions.mojom.*,
  media.mojom.WebrtcVideoPerfHistory, media.mojom.CdmS,
  TCP/TLS/RTP/SAVP, UDP/TLS/RTP/SAVP (WebRTC)
  vp8-no-clearlead, vp9-no-clearlead (media codec paths)
"""

# ============================================================
# TARGET METADATA
# ============================================================

PRODUCT = "chrome"
VERSION = "154.0.8037.57"
VENDOR = "google"
BUILD_DATE = "2026-09-21"

BINARIES = {
    "chrome": {
        "path": "/tmp/chrome_rpm_extract/opt/google/chrome/chrome",
        "size_mb": 281,
        "build_id": "e9584a00bc04d469c5e087f8dc58635b044085c3",
        "setuid": False,
        "priority": 2,
    },
    "chrome-sandbox": {
        "path": "/tmp/chrome_rpm_extract/opt/google/chrome/chrome-sandbox",
        "size_mb": 0.015,
        "build_id": "5eb057c0e97a89154ae4507a7ee337f25eb7a129",
        "setuid": True,
        "priority": 1,
        "note": "SUID helper for process sandboxing; principal target for sandbox escape",
    },
    "libwidevinecdm": {
        "path": "/tmp/chrome_rpm_extract/opt/google/chrome/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so",
        "size_mb": 21,
        "setuid": False,
        "priority": 3,
    },
    "liboptimization_guide_internal": {
        "path": "/tmp/chrome_rpm_extract/opt/google/chrome/liboptimization_guide_internal.so",
        "size_mb": 24,
        "setuid": False,
        "priority": 4,
    },
}

# ============================================================
# chrome-sandbox PLT TABLE
# ============================================================
# Built from: objdump -d chrome-sandbox | grep "@plt>"

SANDBOX_PLT = {
    0x3a80: "__cxa_finalize",
    0x3a90: "__snprintf_chk",
    0x3aa0: "open64",
    0x3ab0: "close",
    0x3ac0: "getuid",
    0x3ad0: "openat64",
    0x3ae0: "strlen",
    0x3af0: "write",
    0x3b00: "__fxstat64",
    0x3b10: "getenv",
    0x3b20: "__errno_location",
    0x3b30: "strtol",
    0x3b40: "__fprintf_chk",
    0x3b50: "setenv",
    0x3b60: "perror",
    0x3b70: "strcmp",
    0x3b80: "__printf_chk",
    0x3b90: "strtoul",
    0x3ba0: "geteuid",
    0x3bb0: "execv",
    0x3bc0: "socketpair",
    0x3bd0: "syscall",
    0x3be0: "shutdown",
    0x3bf0: "send",
    0x3c00: "read",
    0x3c10: "unsetenv",
    0x3c20: "strerror",
    0x3c30: "signal",
    0x3c40: "waitid",
    0x3c50: "_exit",
    0x3c70: "chdir",
    0x3c80: "chroot",
    0x3ca0: "prctl",
    0x3cb0: "getresgid",
    0x3cc0: "setresgid",
    0x3cd0: "getresuid",
    0x3ce0: "setresuid",
    0x3cf0: "free",
    0x3d00: "malloc",
    0x3d10: "__memcpy_chk",
    0x3d20: "fflush",
    0x3d30: "__vfprintf_chk",
    0x3d40: "__stack_chk_fail",
    0x3d50: "memset",
}

# ============================================================
# VULN PROFILES -- chrome-sandbox
# ============================================================
# Tailored for the SUID helper's specific call graph and attack surface.
# Run via SemanticSearcher on the 15KB binary.

SANDBOX_VULN_PROFILES = [
    ("sandbox_execv_argv_injection",
     "FUNC | calls: execv strcmp getenv | "
     "vuln: execv called with argv[1] from user-controlled command line before adequate validation; "
     "attacker passes malicious path or flag to escape sandbox"),

    ("sandbox_env_strtol_overflow",
     "FUNC | calls: getenv strtol strcmp | "
     "vuln: strtol or strtoul on getenv result without ERANGE/errno check, "
     "attacker-set env var causes integer overflow or sign-extension before syscall"),

    ("sandbox_socketpair_read_overflow",
     "FUNC | calls: read socketpair malloc __memcpy_chk | "
     "vuln: read() from socketpair into fixed-size stack or heap buffer without length cap; "
     "malicious browser process sends oversized IPC response to child"),

    ("sandbox_openat_toctou",
     "FUNC | calls: openat64 __fxstat64 open64 strtol | "
     "vuln: file opened for stat then reopened for use; TOCTOU window between fxstat64 and openat64 "
     "allows symlink substitution while SUID process validates path"),

    ("sandbox_prctl_bypass",
     "FUNC | calls: prctl getuid geteuid setresuid setresgid | "
     "vuln: prctl PR_SET_NO_NEW_PRIVS or seccomp BPF not set before dropping root; "
     "uid/gid mismatch allows re-escalation after setresuid"),

    ("sandbox_namespace_clone_race",
     "FUNC | calls: syscall socketpair waitid signal | "
     "vuln: pid_namespace or net_namespace clone via syscall; race between parent "
     "and child uid map setup allows unprivileged user to gain elevated capability in new namespace"),

    ("sandbox_chroot_escape",
     "FUNC | calls: chroot chdir _exit execv | "
     "vuln: chroot called without preceding chdir inside new root; "
     "missing chdir('/') allows FD-based chroot escape from sandboxed process"),
]

# ============================================================
# VULN PROFILES -- chrome main binary (281MB)
# ============================================================

CHROME_VULN_PROFILES = [
    ("mojo_ipc_type_confusion",
     "FUNC | calls: malloc memcpy free | "
     "vuln: Mojo IPC message deserialization casts buffer pointer to typed struct "
     "without size validation; attacker renderer sends malformed message to trigger "
     "type confusion in browser process"),

    ("media_codec_heap_overflow",
     "FUNC | calls: malloc memcpy realloc | "
     "vuln: VP8 VP9 or H264 decoder allocates output buffer from bitstream-derived "
     "dimensions without checking integer overflow before allocation; "
     "crafted video frame causes heap overflow"),

    ("webrtc_rtp_overflow",
     "FUNC | calls: recv recvfrom read memcpy malloc | "
     "vuln: RTP or RTCP packet parsing copies payload into fixed buffer using "
     "header-specified length without bounds check; network attacker sends oversized packet"),

    ("v8_heap_type_confusion",
     "FUNC | calls: malloc free realloc | "
     "vuln: V8 heap object type assumption without runtime tag check; "
     "JIT-compiled path casts HeapObject to concrete type bypassing map check"),

    ("sandbox_ipc_escape",
     "FUNC | calls: read write socketpair send syscall | "
     "vuln: browser process IPC handler processes message from renderer without "
     "privilege level validation; renderer can issue privileged operation via IPC "
     "to escape sandbox boundary"),

    ("url_parser_overflow",
     "FUNC | calls: malloc memcpy strlen realloc | "
     "vuln: URL component parsing allocates buffer from parsed length field "
     "without overflow guard; crafted scheme or host overflows GURL heap buffer"),

    ("gpu_command_oob",
     "FUNC | calls: memcpy malloc free | "
     "vuln: GPU command buffer handler reads command size from ring buffer "
     "without validating against remaining buffer space; causes OOB read or write in GPU process"),

    ("cdm_ipc_deser",
     "FUNC | calls: malloc memcpy free read | "
     "vuln: Content Decryption Module IPC deserializes key or sample data "
     "using attacker-supplied length; heap overflow in CDM process"),

    ("network_mojom_recv_overflow",
     "FUNC | calls: recv read malloc memcpy | "
     "vuln: network.mojom handler reads response body into buffer sized from "
     "Content-Length header without cap; attacker server sends body larger than header value"),
]

# ============================================================
# MANUAL ANALYSIS -- chrome-sandbox (0x2ed0 main, initial pass)
# ============================================================
#
# 7 real functions identified by prologue scan (LLD binary; push-rbp-only prologues,
# no classic push-rbp;mov-rbp-rsp frame setup). CorpusBuilder/SemanticSearcher not
# usable here -- binary has 3 exports and no symbol table; prologue scan finds 7 funcs.
#
# Function map:
#   0x2be0  validate_path_fd(socketpair_fd, path_fd)
#             open64 -> fxstat64 -> getuid -> close -> openat64 -> close
#             builds path via __snprintf_chk, validates owner == process uid
#   0x2d90  adjust_oom_score()
#             getenv(SBX_D) -> strtol -> getenv(SBX_HELPER_PID) -> strtol ->
#             __snprintf_chk(path) -> setenv -> perror
#             writes OOM score to /proc/<pid>/oom_score_adj
#   0x2ed0  main(argc, argv)
#             argc==2 + strcmp(argv[1],"--get-api") -> print API and exit
#             otherwise: call adjust_oom_score, check geteuid, socketpair,
#             syscall(SYS_clone, CLONE_NEWPID|CLONE_NEWNET|SIGCHLD) for namespace,
#             falls back to CLONE_NEWPID if EINVAL, then validates+execv
#             execv path at 0x35bd: execv(argv[n+1], &argv[n+1])
#               preceded by validate_path_fd(r12d, eax) at 0x35af
#   0x37a0  fatal(fmt, ...)
#             __vfprintf_chk -> strerror -> __fprintf_chk -> fflush -> _exit
#   0x3870  wait_for_child(child_pid, socket_fd)
#             signal(SIGALRM, fatal) -> waitid -> errno check -> _exit/write
#             prctl(PR_SET_DUMPABLE, 0) before final _exit
#   0x3930  (overlaps 0x3960) -- wrapper calling drop_privileges
#             write(fd, msg) -> _exit on failure before calling 0x3960
#   0x3960  drop_privileges()
#             prctl(PR_SET_DUMPABLE=4, 0) -> prctl(PR_GET_DUMPABLE=3, 0) verify
#             getresgid -> setresgid(gid,gid,gid) -> getresuid -> setresuid(uid,uid,uid)
#
# Automated scan results -- chrome-sandbox:
#   TaintTracker interprocedural:       0 findings (no getenv/read -> execv/syscall paths)
#   FormatStringScanner:                0 findings
#   HeapVulnScanner:                    3 MEDIUM off_by_one_alloc -- ALL FALSE POSITIVES
#     0x34b4: strlen -> malloc, but malloc arg is lea 0x9(%rax),%rdi (strlen+9 bytes)
#     scanner does not track LEA offset additions; attribution to _start/_csu also wrong
#
# TOCTOU observation (by-design, not an attack path):
#   validate_path_fd (0x2be0) opens path with open64, stats with fxstat64 (checks uid),
#   then reopens with openat64. execv (0x35c8) is called with the same argv[1] path string
#   after validate_path_fd returns. There is a TOCTOU window between fxstat64 and execv.
#   Attack requires controlling argv[1], which is supplied by the browser process.
#   Not exploitable via the renderer attack model (renderer does not set sandbox argv).
#
# ============================================================
# CONFIRMED FINDINGS
# ============================================================
# (empty -- no confirmed findings from chrome-sandbox sweep; proceed to chrome main binary)

# ============================================================
# SWEEP ENTRY POINTS
# ============================================================

def sweep_sandbox(top_k: int = 5):
    """
    Semantic sweep over chrome-sandbox SUID binary.
    Small binary (~15KB text), fast sweep.
    """
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.corpus_builder import CorpusBuilder
    from ablation.analyzers.semantic_search import SemanticSearcher

    binary = BINARIES["chrome-sandbox"]["path"]

    ctx = BinaryContext.load_or_build(binary)
    print(ctx.summary())
    if ctx.names_count():
        print(ctx.names_table())

    db_path = "~/.ablation/func_id.db"
    cb = CorpusBuilder(db_path)
    n = cb.build(binary, product="chrome-sandbox", version=VERSION)
    print(f"[*] CorpusBuilder: {n} functions indexed")

    searcher = SemanticSearcher(db_path)
    searcher.build_corpus()

    results = {}
    for name, query in SANDBOX_VULN_PROFILES:
        hits = searcher.query(query, top_k=top_k)
        results[name] = hits
        print(f"\n--- {name} ---")
        for r in hits:
            print(f"  {ctx.name(r.va)}  score={r.score:.4f}")

    return results, ctx


def sweep_chrome_main(top_k: int = 5):
    """
    Semantic sweep over the 281MB chrome main binary.
    Long runtime (~10-20min on CPU for CorpusBuilder).
    """
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.corpus_builder import CorpusBuilder
    from ablation.analyzers.semantic_search import SemanticSearcher

    binary = BINARIES["chrome"]["path"]

    print(f"[*] Loading BinaryContext for {binary} (281MB, first build may take 2-3 min)")
    ctx = BinaryContext.load_or_build(binary)
    print(ctx.summary())
    if ctx.names_count():
        print(ctx.names_table())

    db_path = "~/.ablation/func_id.db"
    print("[*] Building corpus (281MB, CPU-bound, may take 10-20 min)")
    cb = CorpusBuilder(db_path)
    n = cb.build(binary, product="chrome", version=VERSION)
    print(f"[*] CorpusBuilder: {n} functions indexed")

    searcher = SemanticSearcher(db_path)
    searcher.build_corpus()

    results = {}
    for name, query in CHROME_VULN_PROFILES:
        hits = searcher.query(query, top_k=top_k)
        results[name] = hits
        print(f"\n--- {name} ---")
        for r in hits:
            print(f"  {ctx.name(r.va)}  score={r.score:.4f}")

    return results, ctx


def taint_sandbox(ctx=None):
    """
    Interprocedural taint analysis on chrome-sandbox.
    Sources: read(), getenv() returns.
    Sinks: execv (arg0/arg1), syscall (various), strtol result fed to syscall.
    """
    from ablation.analyzers.taint_tracker_x86 import TaintTracker
    from ablation.analyzers.xref_graph import XRefGraph
    from ablation.analyzers.binary_context import BinaryContext

    binary = BINARIES["chrome-sandbox"]["path"]

    if ctx is None:
        ctx = BinaryContext.load_or_build(binary)

    xg = XRefGraph.from_path(binary).build()

    tt = TaintTracker(
        binary,
        xref=xg,
        custom_sinks={
            "execv": [0, 1],
            "syscall": [0, 1, 2],
            "strtol": [0],
            "setresuid": [0, 1, 2],
            "setresgid": [0, 1, 2],
            "chroot": [0],
        },
    )

    print("[*] Running interprocedural taint analysis on chrome-sandbox")
    findings = tt.run_interprocedural()

    for f in findings:
        print(f"  {f}")

    return findings


def format_string_scan_sandbox(ctx=None):
    """Scan chrome-sandbox for format string vulnerabilities."""
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.format_string_scanner import FormatStringScanner

    binary = BINARIES["chrome-sandbox"]["path"]
    if ctx is None:
        ctx = BinaryContext.load_or_build(binary)

    scanner = FormatStringScanner.from_context(ctx)
    findings = scanner.scan()
    print(scanner.report(findings))
    return findings


def heap_scan_sandbox(ctx=None):
    """Scan chrome-sandbox for heap integer overflow / UAF / double-free."""
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner

    binary = BINARIES["chrome-sandbox"]["path"]
    if ctx is None:
        ctx = BinaryContext.load_or_build(binary)

    scanner = HeapVulnScanner.from_context(ctx)
    findings = scanner.scan()
    print(scanner.report(findings))
    return findings
