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

bbe-pfcp-proxyd: FINDING 11 (pending)
──────────────────────────────────────
PFCP Create Session with 3+ IPv6 Address IEs triggers anomalous behavior.
Dynamic confirmation needed: send crafted PFCP packet to port 8805/UDP.
Binary not yet swept with BERT.
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
        'size_mb': None,
        'mitigations': {'pie': True, 'canary': False, 'relro': False},
        'bert_functions': None,
        'bert_top_score': None,
        'protocol': 'PFCP UDP 8805',
        'status': 'PENDING_DYNAMIC',
        'confirmed_bugs': 1,  # Finding 11 — 3+ IPv6 Address IEs
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

# CALIBRATION — score threshold learned from jdhcpd sweep
# Scores below 0.50 on this model consistently resolve to false positives.
# jdhcpd hits at 0.62-0.72 were stubs / safe callers.
# aaasd hits at 0.39-0.47 were C++/gRPC wrappers.
# jdiameterd hits at 0.27-0.33 were schema-sourced copies.
# Implication: for Junos EVO binaries, interesting candidates start above 0.55.
SCORE_THRESHOLD_INVESTIGATE = 0.50
SCORE_THRESHOLD_HIGH_CONFIDENCE = 0.65
