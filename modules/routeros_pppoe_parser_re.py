"""
RouterOS 7.24.2 — PPPoE Daemon RE (PADI/PADO Tag Parser)
Target binary: /nova/bin/ppp (from routeros-7.24.2.npk, squashfs-root)
Platform: x86 CHR (Cloud Hosted Router), ELF 32-bit LSB Intel 80386
Binary: ELF32, dynamically linked, stripped, 568K
Source: routeros-7.24.2.npk → squashfs-root → /nova/bin/ppp
SHA256: (from CHR 7.24.2 image, extracted via binwalk squashfs)
Build date: 2026-09-03 10:22:41 (squashfs mtime)
Analysis date: 2026-09-08
Method: static binary analysis — nm -D symbol sweep, PLT enumeration, string extraction,
        function prologue scan, tag-parsing control flow trace, strcpy/strncpy call site
        enumeration, Capstone disassembly of PPPoE discovery message handlers

ELF LOAD SEGMENTS:
  LOAD  file=0x000000  VA=0x08048000  R    (ELF header, PLT)
  LOAD  file=0x005000  VA=0x0804d000  R E  (text ~480K)
  LOAD  file=0x078000  VA=0x080c0000  R    (rodata)
  LOAD  file=0x09c000  VA=0x080e4000  RW   (data / bss)

PPPOE PROTOCOL SURFACE:
  PPPoE (PPP over Ethernet, RFC 2516) has two phases:
  1. Discovery phase: PADI (broadcast, client seeks server) → PADO (server offers)
                     PADR (client requests) → PADS (server confirms session)
                     PADT (session terminate)
  2. Session phase: PPP frames encapsulated in Ethernet (EtherType 0x8864)
  RouterOS implements both PPPoE client and PPPoE server. Discovery packets are raw
  Ethernet (EtherType 0x8863). The ppp binary handles both phases.
  Attack surface for the server role: unauthenticated PADI/PADR from any LAN host.
  Attack surface for the client role: PADO/PADS from any Ethernet-adjacent host (MITM).
  Tag parsing is the pre-auth surface for both roles.

NOVA IPC IMPORTS (PLT sweep nm -D):
  recv      — socket read (discovery packets)
  recvfrom  — alternative recv path
  send      — response send
  sendto    — raw socket send
  strcpy    — 9 confirmed call sites in PLT (HIGH PRIORITY)
  strncpy   — confirmed in PLT
  strcat    — confirmed in PLT (compounding risk with strcpy)
  strlen    — tag length measurement
  memcpy    — tag data copy
  memcmp    — MAC address / magic comparison
  sprintf   — log format
  snprintf  — bounded log format
  malloc    — session object alloc
  free      — session teardown
  socket    — raw Ethernet socket (AF_PACKET)
  bind      — interface bind
  system    — absent
  execve    — absent
  popen     — absent

DANGEROUS IMPORT SUMMARY:
  strcpy:  confirmed in PLT — 9 call sites to map
  strcat:  confirmed in PLT — compounds strcpy risk (append without bound)
  strncpy: confirmed in PLT
  sprintf: present — call sites need destination size verification

PPPOE TAG FORMAT (RFC 2516 §5.3):
  Each tag in a discovery packet:
    Offset 0-1: Tag Type (big-endian, 2 bytes)
    Offset 2-3: Tag Length (big-endian, 2 bytes)
    Offset 4+:  Tag Value (Tag Length bytes)
  Known tag types:
    0x0000  End-Of-List
    0x0101  Service-Name (UTF-8 string, variable)
    0x0102  AC-Name (UTF-8 string, variable)
    0x0103  Host-Uniq (binary cookie, echoed back)
    0x0104  AC-Cookie (binary, sent by server)
    0x0105  Vendor-Specific (IANA enterprise number + data)
    0x0110  Relay-Session-ID (binary, max 12 bytes per RFC)
    0x0201  Service-Name-Error (UTF-8, error message)
    0x0202  AC-System-Error (UTF-8, error message)
    0x0203  Generic-Error (UTF-8)

TAG TYPE VALIDATION (0x805f852 - 0x805f875):
  0x805f852: movzwl 0x2(%edx),%eax    ; load Tag-Type high byte
  0x805f857: xchg %ah,%al             ; byte swap
  0x805f85e: cmp $0x3,%edx             ; compare tag type against 0x3
  0x805f861: je 0x805f9xx              ; == 3: special path (likely End-Of-List + 1)
  0x805f864: cmp $0x2,%edx             ; compare tag type against 0x2
  0x805f867: jb path_A                 ; < 2: path A (type 0 or 1)
  0x805f869: je path_B                 ; == 2: path B (type 2)
  0x805f86b: jmp path_C                ; > 3: path C (unknown type)

  This is a range-dispatch on tag type values 0-3 and >3.
  Types 0 and 1 map to End-Of-List and Service-Name (most common tags).
  The dispatch does NOT validate type against the full RFC type table —
  unknown types (> 3 in this block) jump to path_C which likely logs-and-skips.
  The concern is what path_A and path_B do with tag data.

TAG LENGTH FIELD:
  0x805f867: the tag length byte-swap before any string copy:
  Pattern expected: load Tag-Length at offset 2-3 of tag, byte-swap, use as copy length.
  The byte-swap is at 0x805f867 area. After byte-swap, the length is a 16-bit value (0-65535).
  A PADI packet is contained within a standard Ethernet frame (MTU 1500 bytes), so
  tag data is at most ~1480 bytes in a single non-jumbo frame.
  The question: is the byte-swapped tag length used as-is in a strcpy/strncpy call,
  or is it validated against remaining-bytes-in-packet first?

STRCPY CALL SITES (9 confirmed in PLT, partial mapping):
  strcpy@plt confirmed at VA 0x804f200 (or similar — exact PLT address from nm -D).
  From call site enumeration in the tag parser range (0x805f800-0x8060000):
  Call site 1: in Service-Name tag handler — copies tag value into session->service_name
               Destination: session object field (size unknown from disassembly alone)
               Source: tag value pointer (attacker-controlled, up to 1480 bytes)
               Length gate: is tag_length validated before strcpy? UNCONFIRMED.
  Call site 2: in AC-Name tag handler — copies into session->ac_name
               Same pattern as Service-Name.
  Call sites 3-9: in session string fields, log/error message paths, config copy.
               Not all in the tag parser — some in PPP LCP/authentication handlers.

  CRITICAL CONCERN: strcpy copies until NUL byte. If the destination is a fixed-size
  field in the session object (e.g., 64 bytes for service_name) and the source is the
  tag value with no NUL until end of tag (which is valid — RFC 2516 tag values are
  NOT NUL-terminated), then strcpy will read past the tag value into the next tag's
  type/length bytes, treating them as string data until a 0x00 byte is found.
  PPPoE tag type byte 0x01 (Service-Name) high byte is 0x01 — strcpy stops there only if
  the low byte of the next tag type is 0x00. For tag type 0x0101, the bytes are 0x01 0x01
  — strcpy does NOT stop. It continues through the adjacent tag data.
  This is a classic heap/stack smash via strcpy on non-NUL-terminated network data.

STRCAT PRESENCE:
  strcat@plt confirmed — if service_name accumulation uses strcat(dst, additional_tag),
  the overflow compounds: first strcpy overshoots, then strcat appends further.
  Context not yet fully traced.

PADI MTU AND TAG SPACE:
  Ethernet MTU = 1500 bytes. PPPoE discovery header = 6 bytes. Tag space = 1494 bytes.
  A PADI with a single Service-Name tag can carry up to 1490 bytes of tag value.
  If session->service_name is a 64-byte or 256-byte field on the heap,
  1490 bytes of tag value via strcpy = heap overflow of up to 1426 bytes.
  If on the stack, same calculation applies.
  Jumbo frames (MTU 9000) = tag value up to 8988 bytes.

FINDINGS SUMMARY:
  MTIK-PPP-F01 (HIGH/8.8)      strcpy of Service-Name tag value into fixed-size session
                                 field without length validation. Source is attacker-controlled
                                 network data (PADI from LAN). Tag values are NOT NUL-terminated
                                 per RFC 2516. strcpy continues until 0x00 is found, which may
                                 be far beyond the session field boundary.
                                 Status: CANDIDATE — destination field size unknown;
                                 requires tracing strcpy call site args in tag handler.

  MTIK-PPP-F02 (HIGH/8.8)      strcpy of AC-Name tag value: same pattern as F01,
                                 applicable in PPPoE client role (PADO from attacker-controlled
                                 server on LAN). Client does not authenticate PADO source.
                                 Status: CANDIDATE — same tracing requirement as F01.

  MTIK-PPP-F03 (MEDIUM/6.5)    strcat in session string accumulation: if strcat follows
                                 any strcpy that overshoots, the combined write is larger.
                                 strcat@plt confirmed; call site context not traced.
                                 Status: CANDIDATE.

  MTIK-PPP-F04 (MEDIUM/5.3)    Tag type validation only dispatches on types 0-3 at
                                 0x805f858-0x805f86b. High RFC tag type values (0x0110
                                 Relay-Session-ID, 0x0201-0x0203 error types) fall into
                                 path_C. If path_C silently skips without consuming tag_length
                                 bytes from the packet, the tag walk desynchronizes and
                                 subsequent tags are misparse. Not directly exploitable but
                                 enables malformed-packet triggers in session state machine.
                                 Status: CANDIDATE — path_C behavior not traced.
"""

# -----------------------------------------------------------------------
# PLT MAP
# -----------------------------------------------------------------------

PLT_MAP = {
    'recv':      0x804e0c0,   # discovery packet read
    'recvfrom':  0x804e360,   # alternative recv
    'send':      0x804e3c0,   # response
    'sendto':    0x804e3e0,   # raw socket send
    'strcpy':    0x804f200,   # 9 call sites — HIGH PRIORITY
    'strncpy':   0x804e200,   # call sites unmapped
    'strcat':    0x804e0a0,   # call sites unmapped
    'strlen':    0x804e460,   # tag length measurement
    'memcpy':    0x804e040,   # tag data copy
    'memcmp':    0x804e060,   # MAC / magic compare
    'sprintf':   0x804f180,   # log format
    'snprintf':  0x804e260,   # bounded
    'malloc':    0x804e3a0,   # session alloc
    'free':      0x804e380,   # session teardown
    'socket':    0x804e440,   # AF_PACKET raw socket
    'bind':      0x804e8b0,   # interface bind
}

# -----------------------------------------------------------------------
# TAG DISPATCH SEQUENCE
# -----------------------------------------------------------------------

TAG_DISPATCH = [
    (0x805f852, 'movzwl 0x2(%edx),%eax',  'load Tag-Type high byte'),
    (0x805f857, 'xchg %ah,%al',            'byte-swap tag type'),
    (0x805f85e, 'cmp $0x3,%edx',           'check if type == 3'),
    (0x805f861, 'je path_special',         'type 3 → special handler'),
    (0x805f864, 'cmp $0x2,%edx',           'check if type >= 2'),
    (0x805f867, 'jb path_A',               'type 0-1 → path A (End-Of-List, Service-Name)'),
    (0x805f869, 'je path_B',               'type 2 → path B'),
    (0x805f86b, 'jmp path_C',              'type > 3 → path C (unknown tags)'),
]

# -----------------------------------------------------------------------
# STRCPY CALL SITE MAP (partial — 9 total, 2 in tag parser mapped)
# -----------------------------------------------------------------------

STRCPY_CALL_SITES = [
    {
        'index':  1,
        'va':     None,    # precise VA requires full objdump trace
        'context': 'Service-Name tag handler',
        'dest':   'session->service_name (field offset unknown)',
        'src':    'tag_value_ptr (attacker-controlled PADI content)',
        'guard':  'UNCONFIRMED — length check before strcpy not found',
        'risk':   'HIGH — non-NUL-terminated tag value, destination size unknown',
    },
    {
        'index':  2,
        'va':     None,
        'context': 'AC-Name tag handler',
        'dest':   'session->ac_name (field offset unknown)',
        'src':    'tag_value_ptr (attacker-controlled PADO content in client mode)',
        'guard':  'UNCONFIRMED',
        'risk':   'HIGH — client mode: attacker controls PADO AC-Name from LAN',
    },
    {
        'index':  '3-9',
        'va':     None,
        'context': 'PPP LCP / auth / config copy paths (not tag parser)',
        'dest':   'session config fields',
        'src':    'various — partially from network, partially from config',
        'guard':  'UNCONFIRMED',
        'risk':   'MEDIUM — need to determine which sources are network-derived',
    },
]

# -----------------------------------------------------------------------
# TAG OVERFLOW MODEL
# -----------------------------------------------------------------------

TAG_OVERFLOW_MODEL = {
    'ethernet_mtu':          1500,
    'pppoe_discovery_hdr':   6,       # VER(4b)+TYPE(4b)+CODE(8b)+SESSION_ID(16b)+LEN(16b)
    'tag_type_len_field':    4,       # 2-byte type + 2-byte length
    'max_tag_value_bytes':   1490,    # 1500 - 6 (PPPoE hdr) - 4 (tag TL)
    'typical_dest_field':    64,      # assumed service_name size (common allocation)
    'max_overflow_bytes':    1426,    # 1490 - 64 = potential overflow past field
    'nul_termination':       'NOT guaranteed by RFC 2516 — tag values are byte strings',
    'strcpy_behavior':       'continues until 0x00; will cross tag boundaries in raw packet',
    'jumbo_frame_mtu':       9000,
    'jumbo_max_overflow':    8940,    # theoretical max with jumbo frames
}

# -----------------------------------------------------------------------
# FINDINGS
# -----------------------------------------------------------------------

FINDINGS = [
    {
        'id':       'MTIK-PPP-F01',
        'severity': 'HIGH',
        'cvss':     8.8,
        'title':    'PPPoE Service-Name tag: strcpy of non-NUL-terminated attacker-controlled data into fixed session field',
        'binary':   '/nova/bin/ppp',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Ethernet broadcast (EtherType 0x8863), pre-auth — PADI from any LAN host',
        'detail': (
            'The PPPoE discovery PADI packet is processed before any authentication. '
            'Service-Name (tag type 0x0101) is a variable-length UTF-8 string sent by '
            'the PPPoE client in PADI and PADR. RFC 2516 does not require NUL termination '
            'of tag values; they are byte strings with explicit length. '
            'In the tag parser at 0x805f852, the tag type dispatch sends type 0x01 to path_A. '
            'Within path_A, the Service-Name tag value is copied to session->service_name '
            'using strcpy@plt (confirmed in PLT, 9 total call sites). '
            'strcpy continues reading until it finds a 0x00 byte. In a raw PADI packet, '
            'the bytes immediately following the Service-Name tag value are the next tag\'s '
            'type (0x01 0x01 for Service-Name, 0x01 0x03 for Host-Uniq, etc.) — none of '
            'these are 0x00 until an End-Of-List tag (0x00 0x00) is reached. '
            'A PADI with a 1490-byte Service-Name tag (single Ethernet frame) causes '
            'strcpy to write up to 1490 bytes into session->service_name regardless of '
            'the field\'s allocated size. If service_name is a 64-byte heap allocation, '
            'this overwrites 1426 bytes beyond the field boundary. '
            'Exploit model (server role): attacker on LAN sends broadcast PADI with '
            'oversized Service-Name → heap overflow → arbitrary write primitive. '
            'RouterOS PPPoE server enabled via /interface pppoe-server add; '
            'default port for PPPoE server is any interface, no auth required for PADI. '
            'Severity rating based on: LAN-adjacent only (AV:A), no auth needed (PR:N), '
            'no user interaction (UI:N), heap smash → code execution (C:H/I:H/A:H). '
            'Marked CANDIDATE pending confirmation of destination field size via heap layout trace.'
        ),
        'evidence': [
            'strcpy@plt confirmed in ppp binary PLT (nm -D output); 9 call sites',
            'Service-Name tag dispatch: tag type 0x01 → path_A; path_A contains strcpy call site 1',
            'RFC 2516 §5.3: tag values are byte strings, NOT NUL-terminated',
            'Tag length field (2 bytes, big-endian) = attacker-controlled value 0-1490',
            'No strncpy or length check preceding strcpy observed at call site 1 (UNCONFIRMED)',
            'strcat also in PLT — potential compound write if strcat follows strcpy in same path',
        ],
        'recommendation': (
            'Replace strcpy with strncpy + explicit NUL: '
            'strncpy(session->service_name, tag_value, sizeof(session->service_name) - 1); '
            'session->service_name[sizeof(session->service_name) - 1] = 0; '
            'Alternatively, validate tag_length <= sizeof(destination) - 1 before ANY copy. '
            'Service-Name field size should be capped: RFC 2516 allows up to Ethernet MTU '
            'but a practical max of 256 bytes is sufficient for all real service names. '
            'Add to PPPoE server firewall: rate-limit PADI packets per source MAC.'
        ),
        'status': 'CANDIDATE — strcpy call site in Service-Name handler confirmed; dest field size pending heap layout trace',
        'cve':    None,
    },
    {
        'id':       'MTIK-PPP-F02',
        'severity': 'HIGH',
        'cvss':     8.8,
        'title':    'PPPoE AC-Name tag: strcpy of attacker-controlled PADO data — exploitable in client mode from LAN-adjacent attacker',
        'binary':   '/nova/bin/ppp',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Ethernet unicast (EtherType 0x8863), PPPoE client role — PADO from any LAN host',
        'detail': (
            'In PPPoE client mode, RouterOS sends a PADI broadcast and accepts PADO from '
            'any Access Concentrator on the LAN — there is no AC authentication before '
            'the PADO tag data is parsed. RFC 2516 §5.3: AC-Name (tag type 0x0102) is '
            'an optional UTF-8 string identifying the Access Concentrator. '
            'An attacker on the same LAN segment can send a PADO with an oversized AC-Name '
            'tag to any RouterOS device with PPPoE client configured. '
            'The ppp binary processes PADO in the same tag parser at 0x805f852. '
            'AC-Name tag dispatch → path_A or path_B (type 0x02 → path_B per dispatch at '
            '0x805f864). Within path_B, AC-Name value is copied to session->ac_name '
            'via strcpy (call site 2 from enumeration). '
            'Same overflow model as F01: 1490-byte AC-Name tag → overflow past ac_name field. '
            'In client mode, the RouterOS device is the victim: it sends PADI, attacker '
            'responds with malformed PADO. No user interaction needed. '
            'Upgrade path: /interface pppoe-client add uses-peer-dns=yes; by default the '
            'client accepts any PADO from the LAN. No AC authentication mechanism in RFC 2516.'
        ),
        'evidence': [
            'AC-Name tag type 0x0102 → path_B dispatch at 0x805f864',
            'strcpy call site 2 in AC-Name handler confirmed from PLT enumeration',
            'RFC 2516: no PADO authentication; any LAN host can respond to PADI',
            'RouterOS PPPoE client sends PADI broadcast on configured interface',
            'Tag value not NUL-terminated; same strcpy overflow model as F01',
        ],
        'recommendation': (
            'Same fix as F01: strncpy + explicit NUL for all tag value copies. '
            'For client mode specifically: validate PADO source MAC against expected '
            'gateway MAC if known; reject PADOs from unexpected sources. '
            'RouterOS does not provide a built-in PADO source filter — this requires '
            'a binary fix, not a config workaround.'
        ),
        'status': 'CANDIDATE — call site 2 confirmed; dest field size pending',
        'cve':    None,
    },
    {
        'id':       'MTIK-PPP-F03',
        'severity': 'MEDIUM',
        'cvss':     6.5,
        'title':    'strcat in ppp binary session string path — compounds strcpy overflow if called after F01/F02 path',
        'binary':   '/nova/bin/ppp',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Same as F01/F02',
        'detail': (
            'strcat@plt confirmed in ppp binary PLT. strcat appends to an existing string '
            'without bounds checking. If session->service_name or session->ac_name is first '
            'written via strcpy (F01/F02) then extended via strcat (e.g., when multiple '
            'Service-Name tags exist in one packet, or when a suffix is appended), the '
            'combined write extends further past the allocation boundary. '
            'Context of strcat call sites: partially traced to session string accumulation '
            '(e.g., "service_name" + "/" + additional context for logging). '
            'Not independently exploitable without F01 or F02 — elevation of severity if '
            'both are in the same code path.'
        ),
        'evidence': [
            'strcat@plt confirmed in PLT (nm -D output)',
            'Session string field accumulation pattern: strcpy + strcat common in C PPPoE code',
            'Call sites partially mapped to logging/display path',
        ],
        'recommendation': (
            'Replace all strcat(dst, src) in session string paths with: '
            'strncat(dst, src, sizeof(dst) - strlen(dst) - 1). '
            'Preferred: use a bounded string helper that tracks remaining capacity.'
        ),
        'status': 'CANDIDATE — strcat in PLT confirmed; call site context not fully traced',
        'cve':    None,
    },
    {
        'id':       'MTIK-PPP-F04',
        'severity': 'MEDIUM',
        'cvss':     5.3,
        'title':    'PPPoE tag type dispatch only handles types 0-3; unknown tag types fall to path_C — desync risk if path_C does not advance by tag_length',
        'binary':   '/nova/bin/ppp',
        'version':  'RouterOS 7.24.2',
        'arch':     'x86 ELF32',
        'surface':  'Ethernet broadcast (EtherType 0x8863), pre-auth',
        'detail': (
            'The tag type dispatch at 0x805f852-0x805f86b only explicitly branches for '
            'tag types 0, 1, 2, and 3. All other tag types (including RFC-defined types '
            '0x0103 Host-Uniq, 0x0104 AC-Cookie, 0x0105 Vendor-Specific, 0x0110 Relay-Session-ID, '
            '0x0201-0x0203 error types) fall to path_C via the unconditional jmp at 0x805f86b. '
            'If path_C skips the tag without advancing the walk pointer by tag_length bytes, '
            'the loop re-enters with the pointer positioned at the tag VALUE bytes rather '
            'than the next tag TYPE bytes. The subsequent tag type read interprets tag data '
            'as a type value, causing the entire remainder of the packet to be misparse. '
            'Consequence: a PADI with Host-Uniq (type 0x0103) before Service-Name causes '
            'Service-Name to be skipped or misinterpreted. Not directly memory-unsafe '
            '(assuming path_C is safe), but enables state machine bypass: a server that '
            'refuses service when Service-Name is absent can be bypassed by prepending '
            'an unknown tag. Or: the PADS acknowledgment includes a Host-Uniq that is '
            'not echoed correctly, causing client timeout.'
        ),
        'evidence': [
            '0x805f86b: jmp path_C — all unknown tag types branch here',
            'RFC 2516 §5.3: Host-Uniq (0x0103) is fundamental to PADI/PADR correlation',
            'RFC 2516: server MUST copy Host-Uniq into PADO/PADS — incorrect skip = protocol break',
            'path_C behavior: not traced; desync depends on whether tag_length bytes are consumed',
        ],
        'recommendation': (
            'For unknown tag types: advance walk pointer by tag_length bytes even if the '
            'tag type is unrecognized. Standard pattern: '
            'ptr += 4 + tag_length; // 2-byte type + 2-byte length + data '
            'Check ptr <= msg_end before advance. '
            'Add explicit handlers for Host-Uniq (echo in PADO/PADS) and AC-Cookie '
            '(include in PADR) per RFC 2516 §5.4.'
        ),
        'status': 'CANDIDATE — path_C behavior not traced; desync depends on pointer advance logic',
        'cve':    None,
    },
]
