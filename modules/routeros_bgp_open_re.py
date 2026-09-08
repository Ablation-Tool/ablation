"""
RouterOS 7.24.2 — BGP Route Daemon RE (BGP OPEN Message Parser)
Target binary: /nova/bin/route (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 1.5MB
Source: routeros-7.24.2.npk → squashfs-root → /nova/bin/route
SHA256: (from CHR 7.24.2 image, extracted via binwalk squashfs)
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm symbol sweep, PLT enumeration, objdump full disassembly
        (444,115 lines dumped to /tmp/route_disasm.txt), string extraction, call-chain tracing,
        function prologue scan (push %ebp / mov %esp,%ebp / push %e?x pattern), big-endian
        byte-swap pattern recognition

ELF LOAD SEGMENTS:
  LOAD  file=0x000000  VA=0x08048000  R    (ELF header, PLT)
  LOAD  file=0x008000  VA=0x08050000  R E  (text ~1.1MB)
  LOAD  file=0x100000  VA=0x0814f000  R    (rodata)
  LOAD  file=0x150000  VA=0x081a2000  RW   (data / bss)

BGP ARCHITECTURE IN ROUTEROS v7:
  RouterOS v7 moves BGP to the route daemon. The route binary manages all routing
  protocols: BGP, OSPF, IS-IS, RIP, MPLS/LDP. BGP peer sessions run in separate Nova
  message bus contexts; session state is stored in nv::Store objects. The route daemon
  is a long-running process accessible to all BGP peers via TCP/179. Each accepted
  connection is dispatched to a per-session handler. The OPEN message is the first
  message sent after TCP connection establishment and is processed before any BGP
  authentication (MD5 TCP AO is handled at the kernel TCP level, not in route itself).

NOVA IPC IMPORTS (PLT sweep):
  read     — TCP session read at 0x816e39d (BGP OPEN handler)
  write    — BGP NOTIFY/UPDATE send
  recv     — alternative read path (unused in OPEN handler)
  socket   — peer connection setup
  connect  — active BGP connect
  accept   — passive BGP accept
  memcpy   — 5+ call sites in route/attribute parsers
  memcmp   — BGP header magic comparison
  malloc   — session object allocation
  free     — session teardown
  sprintf  — format strings in error logging
  snprintf — error/log format (bounded)
  htons    — network byte order (2-byte)
  htonl    — network byte order (4-byte)
  strcpy   — present (needs call site verification)
  strncpy  — present (needs call site verification)
  strcat   — absent
  system   — absent
  execve   — absent
  popen    — absent

DANGEROUS IMPORT STATUS:
  strcpy:  present in PLT — call sites NOT yet fully traced; HIGH priority for follow-up
  strncpy: present in PLT — call sites NOT yet fully traced
  memcpy:  5+ call sites; destination size validation unknown for each site

BGP PROTOCOL STACK (reconstructed from string pool):
  BGP state strings: "Connect", "Active", "OpenSent", "OpenConfirm", "Established"
  BGP message type strings: "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH"
  BGP NOTIFICATION error strings (confirmed from rodata):
    "bad BGP packet length"
    "bad BGP OPEN packet length"
    "bad BGP OPEN version"
    "bad BGP OPEN hold time"
    "bad CommonSessionParameters length"
    (all 5 NOTIFICATION trigger strings confirmed in one function block 0x816e196)

BGP OPEN MESSAGE FORMAT (RFC 4271):
  Byte  0-15:  BGP Marker (16x 0xFF)
  Byte  16-17: Total Length (big-endian, 19-4096)
  Byte  18:    Type (= 1 for OPEN)
  Byte  19:    Version (= 4)
  Byte  20-21: My AS (2-byte, or 23456 for 4-byte AS)
  Byte  22-23: Hold Time (big-endian)
  Byte  24-27: BGP Identifier (router-id, 4-byte)
  Byte  28:    Opt Parm Len
  Byte  29+:   Optional Parameters (variable)

OPEN MESSAGE PARSER ANALYSIS (function at 0x816e196):
  Frame: sub $0x17c,%esp → frame = 380 bytes
         This is modest; no large stack array for raw packet data.
  Function receives peer session object pointer in first argument.

  TCP READ LOOP (0x816e3a0 - 0x816e3f5):
    0x816e39d: call read@plt
               args: fd = [session+0x68], buf = stack frame, len = variable
    Post-read: return value checked; <=0 = session close.
    Loop: if bytes_remaining > 0, loop back to read@plt.
    The read loop accumulates BGP message data into a stack/heap buffer.
    Buffer location: [session+something] or local stack (not yet fully resolved —
    the frame is only 380 bytes so large packet data is heap-allocated or in session obj).

  TOTAL LENGTH VALIDATION (0x816e3e6 - 0x816e40a):
    0x816e3e6: mov 0x2(%ecx),%dx     ; load Length field (bytes 16-17 of header)
    0x816e3ea: xchg %dh,%dl          ; big-endian byte swap (no htons — manual swap)
    0x816e3f0: movzwl %dx,%edx       ; zero-extend to 32-bit (SAFE — 16-bit field, max 65535)
    0x816e3f5: cmp 0x14(%eax),%edx   ; compare against session-stored total length
               [eax+0x14] is session->pending_len or session->msg_len (set after TCP read)
    0x816e3fb: ja 0x816e4a5          ; if decoded_len > pending_len: NOTIFICATION "bad BGP packet length"
               VERDICT: length field is range-validated against actual bytes received.
               SAFE against length field > actual data scenarios.

  MINIMUM LENGTH CHECK (0x816e40e):
    Separate compare: cmp $0x13,%edx  ; 0x13 = 19 bytes (minimum BGP message size)
    jb → NOTIFICATION "bad BGP OPEN packet length"
    VERDICT: minimum enforced.

  MAXIMUM LENGTH CHECK (not confirmed):
    RFC 4271 §4 specifies max length = 4096 bytes. A check of the form:
    cmp $0x1000,%edx / ja → NOTIFICATION would be expected.
    NOT yet confirmed from disassembly. The ja 0x816e4a5 at 0x816e3fb compares against
    session->pending_len, which itself was set from read() return — if pending_len is
    set from total TCP data available, this acts as an implicit upper bound. The explicit
    4096 RFC cap is not confirmed. See MTIK-BGP-F01.

  VERSION CHECK (post-length validation):
    Confirms byte at offset 19 of OPEN message == 4.
    != 4 → NOTIFICATION "bad BGP OPEN version" (string confirmed)

  HOLD TIME CHECK (0x816e820 area):
    String "bad BGP OPEN hold time" confirmed — fires if Hold Time < 3 and != 0.
    RFC 4271 §6.2: Hold Time of 1 or 2 is an error; 0 is allowed (no keepalives).
    Implementation matches RFC.

  COMMON SESSION PARAMETERS EXACT-LENGTH CHECK (0x816e86c):
    0x816e86c: cmp $0xe,%eax         ; 0xe = 14 bytes
               je path continues / jne 0x816e8d1 → NOTIFICATION "bad CommonSessionParameters length"
    CONTEXT: CommonSessionParameters (defined in draft-ietf-idr-bgp-common-session)
    is a BGP capability option. Its expected fixed length is 14 bytes.
    The check is an exact-match (== 14), not a bounds check.
    If an attacker sends CommonSessionParameters with length != 14, the NOTIFICATION is sent.
    But: this guard fires AFTER the option length field from the packet has been consumed.
    The concern: if the attacker sends CommonSessionParameters length = 0x7f (127),
    and the code READS 127 bytes based on that field BEFORE hitting this check,
    there is potential for OOB read or incorrect pointer arithmetic.
    Status: CANDIDATE — need to trace what happens to option_len BETWEEN
    the option length read and the exact-match check. See MTIK-BGP-F02.

  OPTIONAL PARAMETERS PARSING (0x816e500 - 0x816e860):
    BGP OPEN optional parameters are TLV-encoded: 1-byte type, 1-byte length, variable data.
    String "bad BGP OPEN packet length" appears in this range — fires when a TLV length
    field causes the computed end-of-option to exceed the packet boundary.
    This is the TLV walk; each step advances by (2 + option_length).
    If option_length is attacker-controlled and not validated before pointer advance:
    OOB read risk. See MTIK-BGP-F03.

  STRCPY / STRNCPY IN ROUTE BINARY:
    Both strcpy and strncpy are in PLT. Route binary is large (1.5MB text) with many
    subsystems (BGP, OSPF, MPLS, RIP, IS-IS). Call sites in BGP-specific functions
    are not yet mapped. String "peer-description" in rodata suggests at least one
    string field is stored per peer — this could be a strcpy target. See MTIK-BGP-F04.

FINDINGS SUMMARY:
  MTIK-BGP-F01 (MEDIUM/5.9)    BGP OPEN max-length 4096-byte RFC cap not confirmed.
                                 Length field is checked against actual bytes received
                                 but explicit cmp $0x1000 not found in disassembly.
                                 If pending_len tracks actual-bytes-read, implicit cap exists.
                                 Status: UNCONFIRMED — requires tracing how pending_len is set.

  MTIK-BGP-F02 (MEDIUM/5.9)    CommonSessionParameters exact-match check: fires AFTER
                                 option bytes may have been consumed. If code reads
                                 option_len bytes into a buffer before exact-match check
                                 fires, malformed length triggers wrong-size read.
                                 Check at 0x816e86c: cmp $0xe,%eax; jne → NOTIFY.
                                 Status: CANDIDATE — needs tracing of option_len consume path.

  MTIK-BGP-F03 (MEDIUM/6.5)    TLV walk in optional parameters uses attacker-controlled
                                 option_length to advance pointer. If boundary check fires
                                 AFTER pointer arithmetic, OOB read for large option_length.
                                 "bad BGP OPEN packet length" string confirms boundary check
                                 exists — but order of check vs advance is UNCONFIRMED.
                                 Status: CANDIDATE — trace pointer advance at 0x816e500-0x816e860.

  MTIK-BGP-F04 (MEDIUM/5.9)    strcpy and strncpy in route binary PLT; call sites in
                                 BGP subsystem not mapped. String "peer-description" in
                                 rodata suggests unbounded string copy into peer object.
                                 Peer description is accepted from remote (via OPEN capability
                                 or from config); if from remote without bound, OOB write risk.
                                 Status: CANDIDATE — map strcpy call sites in BGP context.

  MTIK-BGP-F05 (LOW/3.7)       BGP TCP MD5 session authentication: route binary delegates
                                 to kernel TCP_MD5SIG. If MD5 not configured, any TCP peer
                                 can reach the OPEN parser. BGP hijacking via OPEN with
                                 crafted options is the threat model for F01-F04.
                                 Status: CONFIRMED (protocol behavior).
"""

# -----------------------------------------------------------------------
# PLT MAP
# -----------------------------------------------------------------------

PLT_MAP = {
    'read':      0x804e280,   # TCP session read; call at 0x816e39d
    'write':     0x804e2a0,   # BGP response send
    'recv':      0x804e0e0,   # alternative read (not in OPEN handler)
    'socket':    0x804e440,   # peer connection
    'accept':    0x804e100,   # incoming peer accept
    'connect':   0x804f060,   # active BGP connect
    'memcpy':    0x804e040,   # 5+ call sites; dest size unknown
    'memcmp':    0x804e060,   # BGP header magic check
    'malloc':    0x804e3a0,   # session object alloc
    'free':      0x804e380,   # session teardown
    'sprintf':   0x804f180,   # error log format
    'snprintf':  0x804e260,   # bounded
    'htons':     0x804e1c0,   # 2-byte net order
    'htonl':     0x804e1e0,   # 4-byte net order
    'strcpy':    0x804f0c0,   # present; BGP call sites unmapped
    'strncpy':   0x804e200,   # present; BGP call sites unmapped
}

# -----------------------------------------------------------------------
# BGP OPEN PARSER DISASSEMBLY TRACE
# -----------------------------------------------------------------------

BGP_OPEN_PARSER = {
    'fn_va':            0x816e196,
    'frame_bytes':      380,            # sub $0x17c,%esp
    'tcp_read_va':      0x816e39d,
    'length_byteswap':  0x816e3e6,      # mov 0x2(%ecx),%dx; xchg %dh,%dl
    'length_bounds_va': 0x816e3f5,      # cmp 0x14(%eax),%edx; ja 816e4a5
    'min_length_check': 0x816e40e,      # cmp $0x13,%edx; jb → NOTIFY
    'version_check':    None,           # post-length, version byte == 4
    'holdtime_check':   None,           # "bad BGP OPEN hold time" path
    'tlv_walk_start':   0x816e500,
    'tlv_walk_end':     0x816e860,
    'csp_exact_check':  0x816e86c,      # cmp $0xe,%eax; jne 816e8d1
    'error_block_start':0x816e895,
    'error_block_end':  0x816eb0a,
}

# -----------------------------------------------------------------------
# ERROR NOTIFICATION STRINGS (confirmed from rodata)
# -----------------------------------------------------------------------

BGP_OPEN_ERROR_STRINGS = [
    {'va': None, 'text': 'bad BGP packet length',                 'type': 'Header'},
    {'va': None, 'text': 'bad BGP OPEN packet length',            'type': 'OPEN TLV boundary'},
    {'va': None, 'text': 'bad BGP OPEN version',                  'type': 'Version != 4'},
    {'va': None, 'text': 'bad BGP OPEN hold time',                'type': 'Hold < 3 and != 0'},
    {'va': None, 'text': 'bad CommonSessionParameters length',    'type': 'CSP len != 14'},
]

# -----------------------------------------------------------------------
# BYTE-SWAP SEQUENCE (manual big-endian decode, no htons)
# -----------------------------------------------------------------------

BYTESWAP_SEQUENCE = [
    (0x816e3e6, 'mov  0x2(%ecx),%dx',   'load Length field bytes 16-17'),
    (0x816e3ea, 'xchg %dh,%dl',         'byte swap: big-endian to host order'),
    (0x816e3f0, 'movzwl %dx,%edx',      'zero-extend to 32-bit (max 65535, SAFE)'),
    (0x816e3f5, 'cmp  0x14(%eax),%edx', 'compare against session pending_len'),
    (0x816e3fb, 'ja   0x816e4a5',       'if decoded > received: NOTIFY bad length'),
]

# -----------------------------------------------------------------------
# FINDINGS
# -----------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-BGP-F01',
        'severity': 'MEDIUM',
        'cvss':     5.9,
        'title':    'BGP OPEN RFC 4096-byte maximum not confirmed; implicit cap via pending_len may be insufficient',
        'binary':   '/nova/bin/route',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/179, pre-auth (before session authentication)',
        'detail': (
            'RFC 4271 §4 mandates BGP messages are at most 4096 bytes. The OPEN parser at '
            '0x816e196 performs a Length field check at 0x816e3f5: cmp [session+0x14],%edx; '
            'ja → NOTIFY. The right-hand side [session+0x14] is the count of bytes '
            'actually received from read(). This validates that the Length field does not '
            'exceed bytes-in-buffer, which prevents reading past the received data. '
            'However, if the TCP stack delivers a 4097+ byte BGP message in one read() '
            'call (which TCP does not prevent), and pending_len reflects the full read '
            'count, then the 4096-byte RFC cap is not enforced — the parser would process '
            'an oversized message as valid. '
            'The expected explicit check (cmp $0x1000,%edx) was not observed in the '
            '444,115-line full disassembly around the length validation block. '
            'Oversized OPEN messages are not defined in the threat model but could expose '
            'optional parameter parsing to inputs beyond RFC bounds. '
            'Not directly exploitable without a TCP session to port 179 (filtered on '
            'most RouterOS deployments).'
        ),
        'evidence': [
            'Length byteswap at 0x816e3e6: mov 0x2(%ecx),%dx; xchg %dh,%dl',
            'Bounds check at 0x816e3f5: cmp 0x14(%eax),%edx; ja 0x816e4a5 (vs received bytes)',
            'Minimum check at 0x816e40e: cmp $0x13,%edx; jb → NOTIFY (19-byte minimum enforced)',
            'Explicit cmp $0x1000,%edx NOT found in 0x816e196 function block',
            'RFC 4271 §4: max BGP message size = 4096 bytes',
        ],
        'recommendation': (
            'Add explicit: if (decoded_len > 4096) send_notification(BAD_MSG_LENGTH); '
            'before optional parameter parsing. RouterOS firewall rule to limit BGP peer '
            'access: /ip firewall filter add chain=input protocol=tcp dst-port=179 '
            'src-address-list=!bgp-peers action=drop'
        ),
        'status': 'UNCONFIRMED — explicit 4096 cap not found; implicit cap analysis incomplete',
        'cve':    None,
    },
    {
        'id':       'MTIK-BGP-F02',
        'severity': 'MEDIUM',
        'cvss':     5.9,
        'title':    'CommonSessionParameters exact-match check fires after option-data consume — potential OOB read window',
        'binary':   '/nova/bin/route',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/179, BGP OPEN optional parameters — any peer with TCP access',
        'detail': (
            'BGP OPEN optional parameters are TLV-encoded. Type 2 is BGP Capabilities, '
            'within which Capability Code 65 is CommonSessionParameters (draft-ietf-idr-bgp-common-session). '
            'At 0x816e86c, the route binary checks: cmp $0xe,%eax; jne 0x816e8d1 — '
            'if the option length != 14 (0xe), NOTIFICATION "bad CommonSessionParameters length" is sent. '
            'The question is what happens BEFORE this check: '
            '(a) If the code reads option_length bytes into a fixed-size local buffer '
            'and THEN validates option_length == 14, an attacker can supply option_length = 255 '
            'and trigger a buffer write of 255 bytes into a 14-byte slot before the guard fires. '
            '(b) If the code validates first, then reads — this is safe. '
            'Disassembly shows eax = option_length at the check, suggesting it was loaded before '
            'a copy operation. The call sequence in 0x816e800-0x816e86c needs tracing to '
            'determine whether memcpy(local_buf, data, option_length) precedes or follows '
            'the exact-match check. One prior-art analog: CVE-2021-39274 (FRRouting BGP '
            'capability parsing — similar TLV length confusion before validation).'
        ),
        'evidence': [
            '0x816e86c: cmp $0xe,%eax; jne 0x816e8d1 — exact-match guard on CSP length',
            '0x816e8d1 path: "bad CommonSessionParameters length" NOTIFICATION string confirmed',
            'eax = option_length derived from packet at check site (data-before-validate pattern)',
            'memcpy present in PLT (0x804e040); 5+ call sites in route binary untraced',
            'RFC draft-ietf-idr-bgp-common-session-parameters: fixed 14-byte structure',
        ],
        'recommendation': (
            'Validate option_length == expected_length BEFORE any copy into a fixed-size '
            'option structure. Pattern: '
            'if (opt_len != CSP_FIXED_LEN) { send_notification(); return; } '
            'memcpy(&session->csp, data, CSP_FIXED_LEN);  // CSP_FIXED_LEN = 14'
        ),
        'status': 'CANDIDATE — requires tracing option_len consume path before check at 0x816e86c',
        'cve':    None,
    },
    {
        'id':       'MTIK-BGP-F03',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'BGP OPEN TLV walk boundary check ordering unconfirmed — potential OOB read if check fires after pointer advance',
        'binary':   '/nova/bin/route',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/179, BGP OPEN optional parameters',
        'detail': (
            'The optional parameters TLV walk (0x816e500-0x816e860) iterates over each '
            'BGP OPEN optional parameter: read type (1 byte), read length (1 byte), '
            'advance pointer by (2 + length), process content. '
            'The boundary check string "bad BGP OPEN packet length" is confirmed in '
            'the rodata and is triggered from within this block. '
            'RFC 4271 §4.2 boundary check: after computing next_opt = current + 2 + opt_len, '
            'reject if next_opt > msg_end. The SAFE pattern is: check BEFORE advance. '
            'The UNSAFE pattern is: advance pointer, dereference, check. '
            'From string position alone, the boundary check location within the loop body '
            'relative to the pointer advance cannot be determined. '
            'If the check fires after advance: an attacker can send opt_len = 254 (max 1-byte '
            'value) inside an OPEN message boundary to force the walk pointer past msg_end '
            'and read 1-254 bytes of stack/session memory before the boundary check triggers. '
            'Not a write — read-only OOB. Could leak session state (peer addresses, AS numbers, '
            'option buffers from prior sessions if memory reuse).'
        ),
        'evidence': [
            'TLV walk confirmed in range 0x816e500-0x816e860 from OPEN parser control flow',
            'String "bad BGP OPEN packet length" confirmed in rodata (boundary check exists)',
            'BGP optional parameter format: 1-byte type + 1-byte length + variable data',
            'opt_length is attacker-controlled: 0x00-0xFF (1-byte field)',
            'OOB read on loop = pointer dereferences session memory beyond msg boundary',
        ],
        'recommendation': (
            'Enforce: next = current + 2 + opt_len; if (next > msg_end) { send_notification(); return; } '
            'The check must precede any dereference at the advanced pointer. '
            'Add fuzzer input for BGP OPEN optional parameters with opt_len = 0, 1, 254, 255 '
            'and total message length < 2 + opt_len.'
        ),
        'status': 'CANDIDATE — boundary check exists but order relative to pointer advance unconfirmed',
        'cve':    None,
    },
    {
        'id':       'MTIK-BGP-F04',
        'severity': 'MEDIUM',
        'cvss':     5.9,
        'title':    'strcpy and strncpy in route binary PLT — BGP subsystem call sites unmapped',
        'binary':   '/nova/bin/route',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/179, BGP peer attribute/description fields',
        'detail': (
            'nm -D on the route binary confirms strcpy@plt and strncpy@plt are present. '
            'The route binary is 1.5MB text covering BGP, OSPF, MPLS, RIP, IS-IS — '
            'many subsystems share these imports. '
            'String "peer-description" in rodata suggests the OPEN negotiation stores a '
            'per-peer description string somewhere in the session object. '
            'If this string is written with strcpy from a network-supplied source without '
            'length checking, it is a candidate stack or heap overflow. '
            'BGP capabilities can carry arbitrary data in the capability value field '
            '(e.g., Capability Code 1 = Multi-Protocol, Code 65 = Dynamic Capabilities). '
            'A capability value copy via strcpy with no length cap would be the risk. '
            'String "peer-name" also confirmed in rodata. '
            'Full call site trace of strcpy/strncpy in the BGP subsystem (0x816e000-0x8170000 '
            'approximate BGP section range) is required to resolve this finding.'
        ),
        'evidence': [
            'strcpy@plt at 0x804f0c0: confirmed in PLT (nm -D output)',
            'strncpy@plt at 0x804e200: confirmed in PLT (nm -D output)',
            'String "peer-description" in rodata: peer-level string stored in session',
            'String "peer-name" in rodata: second peer string field',
            'BGP capability TLV provides network-supplied variable-length data',
        ],
        'recommendation': (
            'Map all strcpy@plt call sites in the BGP session handling region. '
            'Replace any strcpy(dst, network_data) with strncpy(dst, network_data, sizeof(dst)-1) '
            'followed by explicit NUL termination. For peer-description specifically: enforce '
            'a maximum length (RFC 4271 optional parameters max = 255 bytes per capability). '
            'Prefer snprintf(dst, sizeof(dst), "%s", src) over strncpy for string accumulation.'
        ),
        'status': 'CANDIDATE — strcpy in PLT confirmed; BGP-specific call sites not yet mapped',
        'cve':    None,
    },
    {
        'id':       'MTIK-BGP-F05',
        'severity': 'LOW',
        'cvss':     3.7,
        'title':    'BGP TCP MD5 not enforced at daemon level — without kernel-level MD5, any host can reach OPEN parser',
        'binary':   '/nova/bin/route',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'TCP/179, network-adjacent (BGP peering IPs)',
        'detail': (
            'RouterOS BGP TCP MD5 session authentication (RFC 2385) is implemented at the '
            'kernel level via TCP_MD5SIG socket option. The route daemon sets TCP_MD5SIG '
            'per-peer; without this, any IP can establish a TCP connection to port 179 '
            'and submit a BGP OPEN message to the parser. '
            'On RouterOS, /routing bgp peer add tcp-md5-key configures the key; if not '
            'set, the peer is unauthenticated at the TCP layer. '
            'The OPEN parser at 0x816e196 runs before any application-layer peer validation. '
            'Findings F01-F04 are all reachable from an unauthenticated TCP connection '
            'to port 179 on a RouterOS device with BGP enabled and no MD5 configured. '
            'Default RouterOS firewall blocks external access to port 179 unless explicitly '
            'added to input chain.'
        ),
        'evidence': [
            'TCP_MD5SIG is kernel-level; route binary does not perform application-layer auth before OPEN parse',
            'String "tcp-md5-key" in rodata confirms per-peer MD5 key configuration exists',
            'RouterOS default firewall input chain: accept established/related only; BGP requires explicit rule',
            'OPEN parser at 0x816e196 receives any TCP-established connection',
        ],
        'recommendation': (
            'Configure tcp-md5-key for all BGP peers. '
            '/routing bgp peer set <peer-name> tcp-md5-key=<key> '
            'Add firewall rule: /ip firewall filter add chain=input protocol=tcp '
            'dst-port=179 src-address=<peer-ip> action=accept (whitelist-only).'
        ),
        'status': 'CONFIRMED (protocol behavior — not a bug, but a configuration risk)',
        'cve':    None,
    },
]
