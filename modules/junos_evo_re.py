"""
Junos EVO 23.4R2.14 — semantic BERT RE sweep results.

Targets: jdhcpd, aaasd, bbe-pfcp-proxyd, jdiameterd
Pre-auth memory corruption hunt. No canary, no RELRO on any target.

BERT sweep methodology: BinFuse 11-category normalization + Markov transitions
+ all-MiniLM-L6-v2 cosine query. Prologue scanner: push rbp / mov rbp,rsp.

Sweep results summary
─────────────────────
Binary         Functions  Top score  Protocol surface          Verdict
jdhcpd         885        0.72       Raw DHCP (PIE, 11.6MB)   EXHAUSTED — no confirmed bug
aaasd          2438       0.47       gRPC (PIE, 2.6MB)        NEGATIVE — framework-protected
jdiameterd     2591       0.33       Raw TCP/SCTP epoll        NEGATIVE — internal-bounded
bbe-pfcp-proxyd  —          —       PFCP UDP                  FINDING 11 pending dynamic

jdhcpd findings
───────────────
Option 43 sub-option 0x0a handler: 0x232b10
  rep movsb at 0x232d27-0x232d67. All 4 callers verified:
    0x36bde0, 0x36c290 — pass NULL (copy skipped)
    0x36f0e0, 0x36f46b (enc: 0x36f0e0) — 64-byte stack buffers, max copy 63 bytes. SAFE.
All 157 option handlers: pure pointer stores at parse stage. No pre-auth write primitive.
BERT top (0x294ef0, 0x294f30, 0x3a9c00): all stubs / global-init-flag wrappers.

aaasd findings
──────────────
283 PLT entries; all gRPC. Pre-auth surface = gRPC message parsing only.
BERT top 0x134770 (memcpy, 0.44): movsxd sign-extend on arg3, then jl guard.
  Potential: negative int32 length bypasses guard. UNCONFIRMED — callers pass
  structured attribute counts (×8 shift), not raw packet bytes. 7 callers analyzed.
0x100310: C++ sized-delete wrapper (_ZdlPvm, 0xa0). Dead end.
0x1863a0 cluster: same movsxd pattern, bounds-checked append. Same caller profile.

jdiameterd findings
───────────────────
500 PLT entries; NO gRPC. Raw socket I/O: accept/epoll_wait/epoll_ctl.
strcpy, strncpy, strcat, sprintf, memcpy all present as unguarded PLT symbols.
BERT sweep ran 8 query profiles, 2591 functions.

avp_parser cluster (0x16e9c0, 0x16e690, 0x16f250):
  Hash table AVP lookups. strlen + Knuth-hash on input key. memcpy size at
  [rbx+6] = schema entry field, NOT packet field. Dest is caller-provided arg.
  Verdict: SAFE — copy size from internal schema, not from network.

double memcpy 0xcbd30:
  Size = loop-counted internal array entries × 32. Second memcpy source =
  RIP-relative global constant. Neither size is user-controlled. SAFE.

0x152840: constant 0x144 bytes from global pointer. SAFE.

Key insight: jdiameterd uses an internal AVP schema registry (hash table at
0x1664c0). The parser looks up AVP types by key, retrieves pre-registered
length/type metadata, then copies. Length fields in network packets feed the
lookup (key selection), not the memcpy size. Clean separation — parser trusts
schema, not wire bytes, for copy sizes.

bbe-pfcp-proxyd: FINDING 11 — STATIC ANALYSIS COMPLETE, HYPOTHESIS REVISED
──────────────────────────────────────────────────────────────────────────
Binary: /home/cowboy/junos-evo-work/bbe-pfcp-proxyd (24.4R2-S3.5)
Extraction: QCOW2 → raw (qemu-img --force-share) → UFS44BSD mount → IZO extraction
IZO format: V2.0 Juniper proprietary — 119-byte shell wrapper, TOC bytes 119-0x6cd8,
  sequential zlib-compressed 16KB blocks from 0x6cd8 → ISO 9660 payload.

Security profile: PIE=no (base 0x200000), canary=no, RELRO=partial, NX=yes.
  11791 functions in .text (file 0x14f740, VA 0x350740, size 0x2d5f9c).

PFCP IE dispatch chain (session establishment path):
  decodeSessionEstReqPdrFarIes VA 0x46b530
    → type 1 (Create PDR): decode3GPPCreatePdrIe VA 0x46b680
      → type 2 (PDI): decode3GPPPdiIe VA 0x46d240
        dispatches types 0x14-0x17 (Source Interface, Network Instance, SDF Filter)
        and types 0x83 (Traffic Endpoint ID), 0x84 (→ 0x46ccd0)
        UE IP Address wire type 0x5d (93): SKIPPED in PDI dispatch (loop-advance path)
    → type 3 (Create FAR): handler VA 0x46bbe0
    → type 0x80 (Juniper proprietary): VA 0x468a20

UE IP Address processing (decodeCreateTrafficEndpointIe / getTfeIdFromRule):
  V4 handler: VA 0x468103 — "HAVE V4 UE IP ADDR ipPrefixFamily:%d,..."
  V6 handler: VA 0x4683ab — "HAVE V6 UE IP ADDR ipPrefixFamily:%d"
  Both in function at VA 0x467e30 (function prologue: 55 48 89 e5).

Counter check at VA 0x4736ad (in createCprPdrFar, function starts VA 0x473490):
  add r13d, 1       ; r13d initialized 0 at 0x473588 (xor r13d, r13d)
  cmp r13d, 5       ; exit when counter == 5
  je 0x473533       ; return from function
  mov eax, 1
  shl eax, cl       ; 1 << r13d = bitmask bit selector
  and eax, [rbp-0x40] ; AND with IP-family bitmask from IE content
  add eax, 0xffffffff ; -= 1 → jump table index
  cmp eax, 0xf      ; bounds check
  ja 0x4736ad       ; if > 15, skip (loop back to increment)
  jmp [rax*8 + 0x291528] ; dispatch on IP family

  Jump table 0x291528 (rax=0..15):
    [0]→0x4736e0 (IPv4, writes [rbx+0x136]=0x800)
    [1]→0x47370f (IPv6, writes [rbx+0x136]=0x86dd)
    [2]→0x4736ad (loop-back)
    [3]→0x47374a (flags/prefix check)
    [7]→0x473771 (PPPoE 0x8864)
    [15]→0x473798 (PPPoE variant)
    [4-6,8-14]→0x4736ad (loop-back, no-op)

HYPOTHESIS REVISION:
  Original: counter r13d counts IE instances, array[3] overflows at 4th IE.
  INCORRECT. Counter scans BITMASK BITS from [rbp-0x40] (IP family flags in
  one UE IP Address IE). All dispatch handlers write to FIXED struct offsets
  (rbx+0x11a, +0x11c, +0x136, +0x138, +0xe). No array indexed by r13d.

ACTUAL BEHAVIOR: The counter limits scanning to bits 0-4 of the IP family
  bitmask. A single UE IP Address IE with 5 IP family flags set triggers 5
  iterations; excess flags are silently ignored. This is proper bounds behavior,
  not a buffer overflow.

FINDING 11 STATUS: UNCONFIRMED (static). Original OOB hypothesis refuted by
  static analysis. The PFCP parser for UE IP Address IE appears bounded.
  Residual risk: logic-level truncation of PDR processing when >4 IP families
  present — needs dynamic confirmation to assess crash behavior.

BERT sweep: 185 batches × 64 functions at all-mpnet-base-v2. Top candidates
  verified as fixed-constant copies or internal-schema-bounded memcpy. No
  pre-auth write primitive found at BERT-visible layer (score threshold 0.55).
"""

# SWEEP PARAMETERS — used by sweep scripts referencing this module
TARGETS = {
    'jdhcpd': {
        'binary': '/usr/sbin/jdhcpd',
        'arch': 'x86_64',
        'size_mb': 11.6,
        'mitigations': {'pie': True, 'canary': False, 'relro': False},
        'bert_functions': 885,
        'bert_top_score': 0.72,
        'protocol': 'DHCP UDP 67/68',
        'status': 'EXHAUSTED',
        'confirmed_bugs': 0,
    },
    'aaasd': {
        'binary': '/usr/sbin/aaasd',
        'arch': 'x86_64',
        'size_mb': 2.6,
        'mitigations': {'pie': True, 'canary': False, 'relro': False},
        'bert_functions': 2438,
        'bert_top_score': 0.47,
        'protocol': 'gRPC (no raw sockets)',
        'status': 'NEGATIVE',
        'confirmed_bugs': 0,
    },
    'jdiameterd': {
        'binary': '/usr/sbin/jdiameterd',
        'arch': 'x86_64',
        'size_mb': 2.8,
        'mitigations': {'pie': True, 'canary': False, 'relro': False},
        'bert_functions': 2591,
        'bert_top_score': 0.33,
        'protocol': 'Diameter TCP/SCTP 3868',
        'status': 'NEGATIVE',
        'confirmed_bugs': 0,
    },
    'bbe-pfcp-proxyd': {
        'binary': '/usr/sbin/bbe-pfcp-proxyd',
        'arch': 'x86_64',
        'size_mb': 4.3,
        'mitigations': {'pie': False, 'canary': False, 'relro': 'partial', 'nx': True},
        'load_base': 0x200000,
        'text_va': 0x350740, 'text_file': 0x14f740, 'text_size': 0x2d5f9c,
        'bert_functions': 11791,
        'protocol': 'PFCP UDP 8805 (FreeBSD 15.0, ELF64)',
        'status': 'F11_UNCONFIRMED',
        'confirmed_bugs': 0,
        # Extraction: QCOW2 24.4R2-S3.5 → raw → UFS44BSD → IZO → ISO 9660
        # IZO: V2.0 format, 119-byte wrapper, TOC to 0x6cd8, zlib 16KB blocks
        # F11 original hypothesis (OOB write, r13d indexes 3-slot array): REFUTED.
        # Counter at 0x4736ad scans IP-family bitmask bits; writes go to FIXED
        # struct offsets. Not a buffer overflow. See docstring for full analysis.
        # BERT sweep: 185 batches all-mpnet-base-v2. No pre-auth write primitives.
        # Residual: dynamic test for logic-truncation DoS with >4 IP family flags.
    },
}

# BERT QUERIES — proven to work on jdhcpd; run these on any new Junos EVO target
QUERY_PROFILES = {
    'unsafe_memcpy': '{daemon} | calls: memcpy | vuln: memcpy called with length from packet field without bounds check',
    'strcpy_overflow': '{daemon} | calls: strcpy | vuln: strcpy from network packet value without length check',
    'sprintf_overflow': '{daemon} | calls: sprintf | vuln: sprintf formatting network data without size limit',
    'strncpy_trunc': '{daemon} | calls: strncpy | vuln: strncpy length derived from packet field, destination fixed buffer',
    'recv_overflow': '{daemon} | calls: recv,memcpy | vuln: data from recv/accept copied into fixed-size buffer without length validation',
    'int_overflow': '{daemon} | calls: malloc,memcpy | vuln: integer overflow before allocation, length from network',
    'double_free': '{daemon} | calls: free | vuln: double free in error path',
    'avp_parser': '{daemon}_AVP_PARSER | length field | user-controlled | overflow before memcpy or strcpy',
}

# FINDING 8 — CVE-2024-6387 (regreSSHion) — STATIC ANALYSIS COMPLETE
# ─────────────────────────────────────────────────────────────────────
# Binary: /usr/sbin/sshd from os-crypto-x86-64-20251216.9125daf_builder_bsd15_244
# Extraction: contents.izo (5.3MB) → IZO V2.0 first block 0x1d58 → 921 blocks →
#   15MB ISO 9660 → mounted → sshd (ELF64 x86-64 FreeBSD 15.0, not stripped, 3.3MB)
# Build: 2025-09-09 14:04:52 UTC, "SSHD release 25.4R20250909_1359_builder"
#   Juniper clang 15.0.7, source: src/crypto/openssh/sshd.c (Juniper fork)
#   NT_VERSION: 0x1500008 = FreeBSD 15.0.0
#
# CVE-2024-6387 analysis: grace_alarm_handler at VA 0x264f20
#   1. getpgid(0) / getpid() check — if process group leader, reset SIGALRM to IGN
#      and kill(0, SIGALRM) to propagate to group
#   2. ssh_remote_ipaddr / ssh_remote_port — load client addr/port into r14/rbx
#   3. call sshsigdie (0x2eac40) with file="sshd.c", func="grace_alarm_handler",
#      line=0x17f(383), fmt="Timeout before authentication for %s port %d", args
#
# sshsigdie disassembly (0x2eac40):
#   push %rbp / mov %rsp,%rbp
#   mov $0x1,%edi
#   call _exit@plt    <- ASYNC-SIGNAL-SAFE: _exit(1) directly, no syslog/fatal
#   ud2
#
# VERDICT: NOT VULNERABLE to CVE-2024-6387.
#   sshsigdie ignores all arguments and calls _exit(1). No syslog(), no heap ops,
#   no async-signal-unsafe functions in the signal handler path.
#   Juniper incorporated the regreSSHion fix (upstream: OpenSSH 9.8p1, July 2024).
#   Binary built Sept 2025 — post-fix. F8 hypothesis refuted.
#
# FINDING 8 STATUS: NEGATIVE (static). CVE-2024-6387 not present.

# CALIBRATION — score threshold learned from jdhcpd sweep
# Scores below 0.50 on this model consistently resolve to false positives.
# jdhcpd hits at 0.62-0.72 were stubs / safe callers.
# aaasd hits at 0.39-0.47 were C++/gRPC wrappers.
# jdiameterd hits at 0.27-0.33 were schema-sourced copies.
# Implication: for Junos EVO binaries, interesting candidates start above 0.55.
SCORE_THRESHOLD_INVESTIGATE = 0.50
SCORE_THRESHOLD_HIGH_CONFIDENCE = 0.65
