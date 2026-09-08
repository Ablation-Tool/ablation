"""
RouterOS 7.24.2 — /nova/bin/net RE module
Binary: net (1.5MB, x86-32 ELF stripped, dynamically linked)
SHA path: ~/mikrotik-re/bins/net

PLT imports (security-relevant):
  strcpy@plt  : 0x8055650  — 21 call sites
  sprintf@plt : 0x8054cb0  — 8 call sites
  snprintf@plt: 0x8053bb0  — confirmed bounded paths
  socket@plt  : 0x8054dc0  — pre-ifreq strcpy setup
  getsockopt@plt: 0x80542f0
  ioctl@plt   : probable (netfilter/ebtables strings confirm)
  nv::message::operator[]  : 0x8054b80
  nv::messageC1            : 0x8054810 / 0x8054c60

Nova store paths:
  /nova/store/traffic-scripts
  /nova/store/net/arp
  /nova/store/net/switch-vlans
  /nova/store/net/ip-firewall

Kernel module paths:
  /lib/modules/ebtables
  /lib/modules/iptables (ip_tables, ip6_tables)
  modprobe present

Firewall strings:
  "bad packet mark"
  "next firewall rebuild:"
  "dstnat", "srcnat"

Tunnel strings:
  greip4-, gre-tunnel, greip6-, gre6-tunnel, ipip-tunnel, l2tp, sstp

strcat: confirmed (PLT present)
sscanf: confirmed (PLT present)
No stack canary (__stack_chk_fail absent from PLT)

----- FINDINGS SUMMARY -----
MTIK-NET-F01 HIGH   7.8  Nova message → strcpy into interface config struct (4-site cluster)
MTIK-NET-F02 HIGH   7.5  ifreq.ifr_name overflow — strcpy to 16-byte IFNAMSIZ dest from C++ string
MTIK-NET-F03 MEDIUM 6.5  Nova message → firewall struct strcpy via double-indirect pointer chain
MTIK-NET-F04 MEDIUM 6.5  HTTP header path → stack strcpy (HttpHeaders context, 0x80f2064)
MTIK-NET-F05 MEDIUM 5.9  Nova message data → sockaddr-adjacent stack strcpy (0x8081ceb)
MTIK-NET-F06 INFO   0.0  sprintf: 8 sites — rodata format, integer args — CLEAN
MTIK-NET-F07 INFO   0.0  strcpy rodata cluster (0x80c7dd1–0x80c801a) — 8 sites all CLEAN
"""

# ---------------------------------------------------------------------------
# Call site inventory
# ---------------------------------------------------------------------------

STRCPY_SITES = [
    # ---- Nova message → interface/config struct (CANDIDATE cluster) ----
    {
        'va':      0x80c7004,
        'dest':    'lea 0xa(%esi) — struct field +0x0a, esi = alloc from 80c4400',
        'source':  'nv::message field: mov 0x18(%eax),%eax; lea 0xc(%eax),%edx  (string.data())',
        'context': 'Nova IPC — interface config hydration (0x80c6f4b function)',
        'risk':    'CANDIDATE — Nova message source; no length gate before strcpy',
        'cond_flag': '0x50(%ebx)',
    },
    {
        'va':      0x80c7049,
        'dest':    'lea 0x2a(%esi) — struct field +0x2a',
        'source':  'nv::message field: same pointer chain through 0x44(%ebx)',
        'context': 'same function, second config field',
        'risk':    'CANDIDATE',
        'cond_flag': '0x55(%ebx)',
    },
    {
        'va':      0x80c708e,
        'dest':    'lea 0x4a(%esi)',
        'source':  'nv::message field through 0x48(%ebx)',
        'context': 'same function, third config field',
        'risk':    'CANDIDATE',
        'cond_flag': '0x56(%ebx)',
    },
    {
        'va':      0x80c70d3,
        'dest':    'lea 0x6a(%esi)',
        'source':  'nv::message field through 0x4c(%ebx)',
        'context': 'same function, fourth config field',
        'risk':    'CANDIDATE',
        'cond_flag': '0x57(%ebx)',
    },
    # ---- ifreq.ifr_name overflow sites ----
    {
        'va':      0x8173fb3,
        'dest':    'lea -0x68(%ebp),%esi — stack struct, zero-filled 0x50 bytes; used as struct ifreq',
        'source':  'mov (%ebx),%eax; add $0x4,%eax — C++ string data() from function arg',
        'context': 'after socket(AF_INET,SOCK_DGRAM,0); dest fed to getsockopt() as ifr_name',
        'risk':    'CANDIDATE — ifr_name = IFNAMSIZ (16 bytes); C++ string may exceed',
    },
    {
        'va':      0x8174136,
        'dest':    'lea -0x68(%ebp),%esi — same ifreq pattern',
        'source':  'push -0x7c(%ebp) — stack local, origin requires deeper trace',
        'context': 'second getsockopt path, same function region',
        'risk':    'CANDIDATE',
    },
    # ---- Nova message → firewall struct ----
    {
        'va':      0x80cf110,
        'dest':    'lea 0x24(%edi),%eax — firewall rule struct field +0x24',
        'source':  'mov 0x10(%eax),%eax; mov 0x14(%eax),%eax; add $0x4,%eax — double-indirect via Nova message object',
        'context': 'firewall rule construction; Nova message acquired at 0x80cf0e8 (call 8060108)',
        'risk':    'CANDIDATE — double-indirect through Nova data; no snprintf/strlcpy guard',
    },
    # ---- HTTP header → stack strcpy ----
    {
        'va':      0x80f2064,
        'dest':    'lea -0x6c(%ebp),%eax — stack buffer',
        'source':  'mov 0xc(%eax),%eax; add $0x4,%eax — C++ string data() via pointer chain from HttpHeaders struct',
        'context': 'HttpHeaders::HttpHeaderRawField handling; after IP family branch (cmp $0x2,%esi)',
        'risk':    'CANDIDATE — HTTP-layer input feeds C++ string that becomes strcpy source',
    },
    # ---- Nova message → sockaddr-adjacent stack ----
    {
        'va':      0x8081ceb,
        'dest':    'lea -0x28(%ebp),%eax — stack buffer near sockaddr_in (AF_INET context: movw $0x2,-0x5c(%ebp))',
        'source':  'mov 0x18(%edx),%eax; add $0xc,%eax — Nova message string data()',
        'context': 'socket address construction for routing/forwarding path',
        'risk':    'CANDIDATE',
    },
    # ---- Nova message → 0x80c819e ----
    {
        'va':      0x80c819e,
        'dest':    'lea 0x4(%edx),%eax — zero-filled heap buffer +4',
        'source':  'mov 0x18(%esi),%eax; add $0x4,%eax — C++ string offset, likely internal struct copy',
        'context': 'internal config struct clone; esi origin requires further trace',
        'risk':    'PLAUSIBLE — internal string relay; not directly user-controlled',
    },
    # ---- Rodata-sourced sites (CLEAN) ----
    {
        'va':      0x80c44c3,
        'dest':    'C++ string object (alloc via 80c4400)',
        'source':  'push $0x819af50 — rodata literal',
        'context': 'config node init',
        'risk':    'CLEAN — rodata source',
    },
    {
        'va':      0x80ce904,
        'dest':    'lea 0x24(%edx),%eax — allocated struct field',
        'source':  'push $0x819ba8c — rodata literal',
        'context': 'firewall/NAT table init',
        'risk':    'CLEAN — rodata source',
    },
    # Second cluster 0x80c7dd1–0x80c801a: 8 sites, all push $0x819bXXX rodata
    {
        'va':      0x80c7dd1,
        'dest':    'lea -0x6c(%ebp),%esi — stack struct',
        'source':  'push $0x819b064 — rodata literal (interface type string)',
        'context': 'ioctl ifreq builder, kernel interface name',
        'risk':    'CLEAN — rodata source',
    },
    {
        'va':      0x80c7e67,
        'dest':    'lea -0x6c(%ebp),%edx',
        'source':  'push $0x819c0fa — rodata',
        'risk':    'CLEAN',
    },
    {
        'va':      0x80c7ec2,
        'dest':    'lea -0x6c(%ebp),%edx',
        'source':  'push $0x819b011 or $0x819b016 (branch on cmp $0x7,%esi)',
        'risk':    'CLEAN — both branches are rodata',
    },
    {
        'va':      0x80c7f2e,
        'dest':    'lea -0x6c(%ebp),%edx',
        'source':  'push $0x819b069',
        'risk':    'CLEAN',
    },
    {
        'va':      0x80c7f61,
        'dest':    'lea -0x6c(%ebp),%edx',
        'source':  'push $0x819b072',
        'risk':    'CLEAN',
    },
    {
        'va':      0x80c7fa8,
        'dest':    'lea -0x6c(%ebp),%edx',
        'source':  'push $0x819b07b',
        'risk':    'CLEAN',
    },
    {
        'va':      0x80c7fe3,
        'dest':    'lea -0x6c(%ebp),%edx',
        'source':  'push $0x819b087',
        'risk':    'CLEAN',
    },
    {
        'va':      0x80c801a,
        'dest':    'lea -0x6c(%ebp),%edx',
        'source':  'push $0x819b087 (duplicate path)',
        'risk':    'CLEAN',
    },
]

NOVA_MESSAGE_PATTERN = {
    'description':  'C++ string.data() extraction from nv::message field',
    'sequence': [
        'call nv::message lookup (0x8054b80)',
        'test %eax,%eax; je <null_path>',
        'mov 0x18(%eax),%eax   — string size or data ptr field',
        'test %eax,%eax; je <null_path>',
        'lea 0xc(%eax),%edx    — +12 = C++ string inline buf or heap ptr',
        '... push %edx as strcpy source',
    ],
    'risk': 'Nova bus has no inter-daemon auth (MTIK-NOVA-F03); any registered daemon can '
            'inject messages; external input via winbox/webfig/l2tp reaches net through parser/www',
}

IFREQ_OVERFLOW_MODEL = {
    'IFNAMSIZ':          16,
    'dest_zero_fill':    0x50,  # 80 bytes, but ifr_name is first 16
    'ifr_name_offset':   0,     # start of struct ifreq
    'overflow_trigger':  'interface name > 15 chars in C++ string arg',
    'post_overflow':     'into ifr_ifru union — IP address, flags, or MTU fields on stack',
    'route_to_trigger':  'Nova config message with long interface name; no IFNAMSIZ check before strcpy',
}

SPRINTF_SITES = [
    # All 8 sites use rodata format strings with integer/counter args
    {'va': 0x8076ba4, 'format_va': 0x818f22c, 'arg': 'struct field int from 0xc4(%ebx)', 'risk': 'CLEAN'},
    {'va': 0x8076be1, 'format_va': 0x818f232, 'arg': 'counter edi',                       'risk': 'CLEAN'},
    {'va': 0x8079f8f, 'format_va': 'rodata',   'arg': 'integer',                           'risk': 'CLEAN'},
    {'va': 0x80945c7, 'format_va': 'rodata',   'arg': 'integer',                           'risk': 'CLEAN'},
    {'va': 0x80cea79, 'format_va': 'rodata',   'arg': 'integer',                           'risk': 'CLEAN'},
    {'va': 0x80e9efe, 'format_va': 'rodata',   'arg': 'integer',                           'risk': 'CLEAN'},
    {'va': 0x814dd54, 'format_va': 'rodata',   'arg': 'integer',                           'risk': 'CLEAN'},
    {'va': 0x8151cd5, 'format_va': 'rodata',   'arg': 'integer',                           'risk': 'CLEAN'},
]

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDINGS = [
    {
        'id':             'MTIK-NET-F01',
        'severity':       'HIGH',
        'cvss':           7.8,
        'title':          'Nova message → strcpy into interface config struct (4-site cluster)',
        'detail': (
            'Function at 0x80c6f4b hydrates an interface configuration struct from Nova IPC messages. '
            'Four strcpy calls at 0x80c7004, 0x80c7049, 0x80c708e, 0x80c70d3 copy Nova message string '
            'fields (via the standard nv::message string.data() chain: mov 0x18(%eax); lea 0xc(%eax)) '
            'into struct fields at fixed offsets (+0x0a, +0x2a, +0x4a, +0x6a) of a heap-allocated object. '
            'Each copy is gated on a boolean flag byte in the config struct (0x50, 0x55, 0x56, 0x57 offsets) '
            'but has no length check before strcpy. The receiving struct has no visible sentinel beyond its '
            'allocation size. Nova bus carries no inter-daemon authentication (MTIK-NOVA-F03); any input path '
            'that reaches the Nova bus with a long interface/config string will trigger this. '
            'Winbox and WebFig both write to Nova store paths under /nova/store/net/.'
        ),
        'evidence': {
            'site_1_va':     '0x80c7004',
            'site_4_va':     '0x80c70d3',
            'source_pattern': 'mov 0x18(%eax),%eax; test; lea 0xc(%eax),%edx; push %edx → strcpy',
            'dest_pattern':   'lea 0xa/2a/4a/6a(%esi),%eax; push %eax',
            'nova_call_va':   '0x80619de',
            'no_length_check': True,
        },
        'recommendation': (
            'Replace strcpy with strlcpy(dest, src, FIELD_MAX). Add an explicit length check against '
            'the target field width before any string copy from nv::message data. Enforce input length '
            'limits at the Nova store write path for /nova/store/net/ interface config keys.'
        ),
        'status': 'UNCONFIRMED — static analysis; requires dynamic tracing of Nova message source',
        'cve': None,
    },
    {
        'id':             'MTIK-NET-F02',
        'severity':       'HIGH',
        'cvss':           7.5,
        'title':          'strcpy into ifreq.ifr_name — IFNAMSIZ overflow (0x8173fb3, 0x8174136)',
        'detail': (
            'Two call sites in the getsockopt handler copy a C++ string into the ifr_name field '
            'of struct ifreq on the stack. '
            '0x8173fb3: dest = lea -0x68(%ebp),%esi (zero-filled 80 bytes); source = mov (%ebx),%eax; '
            'add $0x4,%eax (C++ string data() from function arg). After strcpy, the same stack buffer '
            'is passed to getsockopt(fd, SOL_SOCKET, SO_TYPE, buf, 0x80). '
            '0x8174136: identical pattern with source from -0x7c(%ebp) stack local. '
            'struct ifreq.ifr_name = IFNAMSIZ = 16 bytes. The stack frame holds ifr_ifru union '
            'fields immediately after ifr_name; overflow of >= 1 byte clobbers IP address / flags / MTU. '
            'RouterOS interface names can be configured to arbitrary lengths via Nova; no IFNAMSIZ '
            'enforcement was observed in this path before the strcpy.'
        ),
        'evidence': {
            'site_1_va':     '0x8173fb3',
            'site_2_va':     '0x8174136',
            'dest':          'lea -0x68(%ebp),%esi; rep stosd 20 dwords = 80 bytes',
            'dest_field':    'struct ifreq.ifr_name (offset 0, max 16 bytes)',
            'IFNAMSIZ':      16,
            'getsockopt_va': '0x80542f0',
            'socket_va':     '0x8054dc0',
            'frame_va':      '0x8173f74',
        },
        'recommendation': (
            'Replace strcpy with strlcpy(ifr.ifr_name, src.data(), IFNAMSIZ). '
            'Add a length check: if src.size() >= IFNAMSIZ, log and return error before socket ops. '
            'Enforce IFNAMSIZ at the config store layer so oversized names are rejected on write.'
        ),
        'status': 'UNCONFIRMED — requires trace of C++ string source to Nova/WebFig config layer',
        'cve': None,
    },
    {
        'id':             'MTIK-NET-F03',
        'severity':       'MEDIUM',
        'cvss':           6.5,
        'title':          'Nova message → firewall struct strcpy via double-indirect pointer (0x80cf110)',
        'detail': (
            'At 0x80cf110 a firewall rule struct field is populated by strcpy. '
            'Dest: lea 0x24(%edi) (struct field +0x24 in a firewall rule object). '
            'Source chain: Nova message obtained at 0x80cf0e8; then '
            'mov 0x10(%eax),%eax; mov 0x14(%eax),%eax; add $0x4,%eax — double-indirect dereference '
            'through the message object before extracting the string pointer. '
            'No intermediate length check. The path leads into the firewall rule builder '
            '(subsequent calls to 0x80cdff2, 0x80ce056, 0x80ce35c, 0x80cdeaa at 0x80cf134+). '
            'Firewall rules are mutable via WebFig REST API (/rest/ip/firewall/filter) and Winbox. '
        ),
        'evidence': {
            'va':            '0x80cf110',
            'dest':          'lea 0x24(%edi) — firewall rule struct field',
            'source_chain':  'mov 0x10(%eax)→0x14(%eax)+4 through Nova message at 0x80cf0e8',
            'nova_call_va':  '0x8060108',
            'follow_calls':  ['0x80cdff2', '0x80ce056', '0x80ce35c', '0x80cdeaa'],
        },
        'recommendation': (
            'Bound all firewall rule string fields at ingestion (WebFig/Winbox input layer). '
            'Replace strcpy with strlcpy(dest, src, FIELD_MAX) and define explicit FIELD_MAX '
            'for each rule struct string field. '
            'Add a length validation step in the Nova message handler before the double-indirect dereference.'
        ),
        'status': 'UNCONFIRMED',
        'cve': None,
    },
    {
        'id':             'MTIK-NET-F04',
        'severity':       'MEDIUM',
        'cvss':           6.5,
        'title':          'HTTP header → stack strcpy in HttpHeaders path (0x80f2064)',
        'detail': (
            'At 0x80f2064 inside an HttpHeaders::HttpHeaderRawField handler, a C++ string from the '
            'HTTP header parsing struct chain is copied to a stack buffer via strcpy. '
            'Dest: lea -0x6c(%ebp),%eax (stack buffer). '
            'Source: mov 0x4(%ebx),%eax; test; mov 0x1c(%eax),%edx (linked-list/node traversal); '
            'then mov 0xc(%eax),%eax; add $0x4,%eax = C++ string data() two pointer hops from arg. '
            'IP address family branch (cmp $0x2,%esi → AF_INET vs AF_INET6) precedes the strcpy. '
            'WebFig serves HTTP/REST traffic; a crafted HTTP header with an overlong value in the '
            'relevant field could reach this path. The stack has no canary.'
        ),
        'evidence': {
            'va':           '0x80f2064',
            'dest':         'lea -0x6c(%ebp) — stack buffer (frame context unconfirmed size)',
            'source_chain': 'mov 0x4(%ebx)→0x1c(%eax); mov 0xc(%eax)+4',
            'context':      'HttpHeaders::HttpHeaderRawField — symbol from demangled reloc',
            'af_branch_va': '0x80f2078',
            'no_canary':    True,
        },
        'recommendation': (
            'Enforce HTTP header value length limits before entering the header struct chain. '
            'Replace strcpy with strlcpy(buf, src, sizeof(buf)). '
            'Given the no-canary constraint, adding stack protectors at the compiler level is the '
            'highest-leverage hardening step for this binary.'
        ),
        'status': 'UNCONFIRMED — requires HTTP request fuzzing against WebFig REST endpoint',
        'cve': None,
    },
    {
        'id':             'MTIK-NET-F05',
        'severity':       'MEDIUM',
        'cvss':           5.9,
        'title':          'Nova message data → sockaddr-adjacent stack strcpy (0x8081ceb)',
        'detail': (
            'At 0x8081ceb a strcpy copies a Nova message string into a stack buffer at -0x28(%ebp). '
            'Context: the surrounding code builds a sockaddr_in structure '
            '(movw $0x2,-0x5c(%ebp) for AF_INET; address and port fields at -0x4a and -0x46(%ebp)). '
            'Source: mov 0x18(%edx),%eax; add $0xc,%eax — standard C++ string.data() from Nova message. '
            'Dest at -0x28(%ebp) is 36 bytes above the sockaddr (-0x5c+36 = -0x28); overrun walks toward '
            'saved registers and return address. Frame setup not fully confirmed; stack canary absent.'
        ),
        'evidence': {
            'va':           '0x8081ceb',
            'dest':         '-0x28(%ebp) — near sockaddr_in at -0x5c(%ebp)',
            'source':       'Nova message string.data() via 0x18(%edx)+0xc',
            'sa_family_va': '0x8081d07',
            'sa_addr_va':   '0x8081cfc',
        },
        'recommendation': (
            'Use strlcpy with an explicit bound. Validate string length at the Nova message '
            'consumption point before sockaddr construction. '
            'Routing/forwarding state should be validated at config-write time, not at runtime copy.'
        ),
        'status': 'UNCONFIRMED',
        'cve': None,
    },
    {
        'id':             'MTIK-NET-F06',
        'severity':       'INFO',
        'cvss':           0.0,
        'title':          'sprintf: 8 sites — rodata format strings, integer args — CLEAN',
        'detail': (
            '8 sprintf call sites at 0x8076ba4, 0x8076be1, 0x8079f8f, 0x80945c7, 0x80cea79, '
            '0x80e9efe, 0x814dd54, 0x8151cd5. '
            'All confirmed: format string = rodata literal (push $0x818f22c etc.), '
            'argument = integer/counter from struct field or loop variable. '
            'No %s format specifiers with attacker-controlled strings observed. CLEAN.'
        ),
        'evidence': {'site_count': 8, 'format_source': 'rodata', 'arg_type': 'integer'},
        'recommendation': 'No action required. Monitor for future additions that introduce %s with uncontrolled data.',
        'status': 'CLEAN',
        'cve': None,
    },
    {
        'id':             'MTIK-NET-F07',
        'severity':       'INFO',
        'cvss':           0.0,
        'title':          'strcpy rodata cluster 0x80c7dd1–0x80c801a — 8 sites CLEAN',
        'detail': (
            '8 strcpy call sites in the 0x80c7dd1–0x80c801a range. '
            'All sources are push $0x819bXXX or $0x819cXXX immediates — rodata literals. '
            'Destinations are stack buffers zero-filled before copy (rep stosd patterns). '
            'These populate struct ifreq / ioctl struct ifr_name fields with kernel interface '
            'type strings ("ip_tables", "ip6_tables", "ebtables" etc.) for modprobe / ioctl calls. '
            'Source is compile-time constant → no overflow risk. CLEAN.'
        ),
        'evidence': {
            'site_range':   '0x80c7dd1–0x80c801a',
            'site_count':   8,
            'source_type':  'rodata immediate push',
            'example_src':  '0x819b064 (interface type string)',
        },
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
]
